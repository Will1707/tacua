// SPDX-License-Identifier: Apache-2.0

import type {
  BackendManagedHostController,
  BackendManagedHostControllerOptions,
} from "./BackendManagedHostController";

const MAXIMUM_REMEMBERED_LAUNCHES = 128;
const MAXIMUM_PENDING_LAUNCHES = 32;

export type BackendManagedHostAppState =
  | "active"
  | "background"
  | "inactive"
  | "unknown"
  | "extension";

export type BackendManagedHostLifecycleOperation =
  | "install_listeners"
  | "initial_refresh"
  | "get_initial_url"
  | "deliver_launch_url"
  | "foreground_retry";

/** Privacy-safe lifecycle failure projection. The source error and launch URL never cross here. */
export type BackendManagedHostLifecycleError = Readonly<{
  operation: BackendManagedHostLifecycleOperation;
  category: "host_lifecycle_rejected";
}>;

export type BackendManagedHostLifecycleAdapterOptions =
  BackendManagedHostControllerOptions &
    Readonly<{
      onError?: (error: BackendManagedHostLifecycleError) => void;
    }>;

/**
 * Platform seam used by the React Native factory and dependency-free tests. Subscriptions must
 * return idempotent removers. Incoming URLs are treated as one-time authority and never emitted.
 */
export type BackendManagedHostLifecyclePrimitives = Readonly<{
  getInitialURL: () => Promise<string | null>;
  getCurrentAppState: () => BackendManagedHostAppState;
  subscribeIncomingURL: (listener: (url: string) => void) => () => void;
  subscribeAppState: (
    listener: (state: BackendManagedHostAppState) => void,
  ) => () => void;
}>;

export type BackendManagedHostLifecycleAdapter = Readonly<{
  /** The existing finite-state controller. Launch URLs and launch codes are never projected. */
  controller: BackendManagedHostController;
  /** Resolves after initial discovery and initial-URL delivery, or rejects with a safe error. */
  ready: Promise<void>;
  /** Removes host/native listeners and disposes the owned controller. Idempotent and non-throwing. */
  dispose: () => void;
}>;

export class BackendManagedHostLifecycleAdapterError extends Error {
  readonly operation: BackendManagedHostLifecycleOperation;
  readonly category = "host_lifecycle_rejected" as const;

  constructor(operation: BackendManagedHostLifecycleOperation) {
    super(`Backend-managed host lifecycle operation failed: ${operation}`);
    this.name = "BackendManagedHostLifecycleAdapterError";
    this.operation = operation;
  }
}

type LifecycleOnlyOptions = Readonly<{
  onError?: (error: BackendManagedHostLifecycleError) => void;
}>;

class InternalLifecycleFailure {
  readonly operation: BackendManagedHostLifecycleOperation;

  constructor(operation: BackendManagedHostLifecycleOperation) {
    this.operation = operation;
  }
}

class InternalLifecycleDisposed {}

/** Pure seam used by the public React Native factory and Node tests. */
export function createBackendManagedHostLifecycleAdapterForPrimitives(
  controller: BackendManagedHostController,
  primitives: BackendManagedHostLifecyclePrimitives,
  options: LifecycleOnlyOptions = {},
): BackendManagedHostLifecycleAdapter {
  let disposed = false;
  let initialRefreshCompleted = false;
  let removeIncomingURL: (() => void) | null = null;
  let removeAppState: (() => void) | null = null;
  let previousAppState: BackendManagedHostAppState;
  let foregroundGeneration = 0;
  let foregroundProcessedGeneration = 0;
  let foregroundScheduled = false;

  const attemptedLaunches = new Set<string>();
  const attemptedLaunchOrder: string[] = [];
  const pendingLaunches = new Set<string>();

  const report = (error: BackendManagedHostLifecycleAdapterError): void => {
    if (!options.onError) return;
    try {
      options.onError(
        Object.freeze({
          operation: error.operation,
          category: error.category,
        }),
      );
    } catch {
      // A host error observer cannot interrupt lifecycle ordering or surface private input.
    }
  };

  const projectFailure = (
    error: unknown,
    fallback: BackendManagedHostLifecycleOperation,
  ): BackendManagedHostLifecycleAdapterError =>
    new BackendManagedHostLifecycleAdapterError(
      error instanceof InternalLifecycleFailure
        ? error.operation
        : fallback,
    );

  const runStep = async <Result>(
    operation: BackendManagedHostLifecycleOperation,
    task: () => Result | Promise<Result>,
  ): Promise<Result> => {
    try {
      const result = await task();
      if (disposed) throw new InternalLifecycleDisposed();
      return result;
    } catch (error) {
      if (error instanceof InternalLifecycleDisposed || disposed) {
        throw new InternalLifecycleDisposed();
      }
      // Never retain or chain a platform/native error: it can contain a launch URL or secret.
      throw new InternalLifecycleFailure(operation);
    }
  };

  let beginStartup: () => void = () => {
    throw new Error("Lifecycle startup gate was not initialized");
  };
  const startupGate = new Promise<void>((resolve) => {
    beginStartup = resolve;
  });

  let deliveryTail: Promise<void>;

  const rememberAttempt = (fingerprint: string): void => {
    if (attemptedLaunches.has(fingerprint)) return;
    attemptedLaunches.add(fingerprint);
    attemptedLaunchOrder.push(fingerprint);
    if (attemptedLaunchOrder.length <= MAXIMUM_REMEMBERED_LAUNCHES) return;
    const expired = attemptedLaunchOrder.shift();
    if (expired !== undefined) attemptedLaunches.delete(expired);
  };

  const prepareLaunchOnce = async (launchURL: string): Promise<void> => {
    const fingerprint = fingerprintLaunchURL(launchURL);
    pendingLaunches.delete(fingerprint);
    if (attemptedLaunches.has(fingerprint)) return;
    rememberAttempt(fingerprint);
    if (!initialRefreshCompleted) {
      await runStep("initial_refresh", () => controller.refresh());
      initialRefreshCompleted = true;
    }
    await runStep("deliver_launch_url", () =>
      controller.prepareLaunch(launchURL),
    );
  };

  const observe = (
    execution: Promise<void>,
    fallback: BackendManagedHostLifecycleOperation,
  ): Promise<void> => {
    const projected = execution.catch((error: unknown) => {
      if (error instanceof InternalLifecycleDisposed) return;
      const safeError = projectFailure(error, fallback);
      report(safeError);
      throw safeError;
    });
    // `ready` and callback-driven operations remain safe when a host intentionally ignores them.
    void projected.catch(() => undefined);
    return projected;
  };

  const startupExecution = startupGate.then(async () => {
    if (disposed) return;
    await runStep("initial_refresh", () => controller.refresh());
    initialRefreshCompleted = true;
    const initialURL = await runStep(
      "get_initial_url",
      primitives.getInitialURL,
    );
    if (initialURL === null) return;
    if (typeof initialURL !== "string" || initialURL.length === 0) {
      throw new InternalLifecycleFailure("get_initial_url");
    }
    await prepareLaunchOnce(initialURL);
  });
  const ready = observe(startupExecution, "initial_refresh");
  deliveryTail = ready.then(
    () => undefined,
    () => undefined,
  );

  const schedule = (
    operation: BackendManagedHostLifecycleOperation,
    task: () => Promise<void>,
  ): Promise<void> => {
    const execution = deliveryTail.then(async () => {
      if (disposed) return;
      await task();
    });
    const projected = observe(execution, operation);
    deliveryTail = projected.then(
      () => undefined,
      () => undefined,
    );
    return projected;
  };

  const queueIncomingURL = (launchURL: string): void => {
    if (disposed) return;
    if (typeof launchURL !== "string" || launchURL.length === 0) {
      report(
        new BackendManagedHostLifecycleAdapterError("deliver_launch_url"),
      );
      return;
    }
    const fingerprint = fingerprintLaunchURL(launchURL);
    if (
      attemptedLaunches.has(fingerprint) ||
      pendingLaunches.has(fingerprint)
    ) {
      return;
    }
    if (pendingLaunches.size >= MAXIMUM_PENDING_LAUNCHES) {
      report(
        new BackendManagedHostLifecycleAdapterError("deliver_launch_url"),
      );
      return;
    }
    pendingLaunches.add(fingerprint);
    void schedule("deliver_launch_url", async () => {
      await prepareLaunchOnce(launchURL);
    });
  };

  const scheduleForeground = (): void => {
    if (disposed || foregroundScheduled) return;
    foregroundScheduled = true;
    const execution = schedule("foreground_retry", async () => {
      while (!disposed && foregroundProcessedGeneration < foregroundGeneration) {
        const targetGeneration = foregroundGeneration;
        try {
          await runStep("foreground_retry", () =>
            controller.notifyForeground(),
          );
        } finally {
          foregroundProcessedGeneration = targetGeneration;
        }
      }
    });
    void execution
      .finally(() => {
        foregroundScheduled = false;
        if (
          !disposed &&
          foregroundProcessedGeneration < foregroundGeneration
        ) {
          scheduleForeground();
        }
      })
      .catch(() => undefined);
  };

  const handleAppState = (nextState: BackendManagedHostAppState): void => {
    if (disposed) return;
    const shouldNotify =
      nextState === "active" &&
      (previousAppState === "inactive" ||
        previousAppState === "background");
    previousAppState = nextState;
    if (!shouldNotify) return;
    foregroundGeneration += 1;
    scheduleForeground();
  };

  try {
    previousAppState = primitives.getCurrentAppState();
    removeIncomingURL = primitives.subscribeIncomingURL(queueIncomingURL);
    if (typeof removeIncomingURL !== "function") {
      throw new InternalLifecycleFailure("install_listeners");
    }
    removeAppState = primitives.subscribeAppState(handleAppState);
    if (typeof removeAppState !== "function") {
      throw new InternalLifecycleFailure("install_listeners");
    }
  } catch (error) {
    disposed = true;
    beginStartup();
    safelyRemove(removeIncomingURL);
    safelyRemove(removeAppState);
    safelyDispose(controller);
    const safeError = projectFailure(error, "install_listeners");
    report(safeError);
    throw safeError;
  }

  beginStartup();

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    const incomingURLRemoval = removeIncomingURL;
    const appStateRemoval = removeAppState;
    removeIncomingURL = null;
    removeAppState = null;
    safelyRemove(incomingURLRemoval);
    safelyRemove(appStateRemoval);
    pendingLaunches.clear();
    attemptedLaunches.clear();
    attemptedLaunchOrder.length = 0;
    safelyDispose(controller);
  };

  return Object.freeze({ controller, ready, dispose });
}

function safelyRemove(remover: (() => void) | null): void {
  if (!remover) return;
  try {
    remover();
  } catch {
    // Removal is best-effort; the disposed gate also makes already-queued callbacks inert.
  }
}

function safelyDispose(controller: BackendManagedHostController): void {
  try {
    controller.dispose();
  } catch {
    // The public adapter owns teardown and keeps it idempotent/non-throwing for host callbacks.
  }
}

/**
 * A bounded, non-authoritative fingerprint prevents retaining one-time launch URLs for dedupe.
 * A collision can only fail closed by suppressing a launch; native code remains authoritative.
 */
function fingerprintLaunchURL(value: string): string {
  let first = 0x811c9dc5;
  let second = 0x9e3779b9;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    first = Math.imul(first ^ code, 0x01000193) >>> 0;
    second = Math.imul(second ^ code, 0x85ebca6b) >>> 0;
    second = ((second << 13) | (second >>> 19)) >>> 0;
  }
  return `${value.length.toString(36)}:${first.toString(36)}:${second.toString(36)}`;
}
