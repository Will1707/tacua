// SPDX-License-Identifier: Apache-2.0

import type {
  BackendManagedHostController,
  BackendManagedHostControllerOptions,
} from "./BackendManagedHostController";

const MAXIMUM_REMEMBERED_LAUNCHES = 128;
const MAXIMUM_PENDING_LAUNCHES = 32;
const DEFAULT_INITIAL_URL_TIMEOUT_MILLISECONDS = 1_500;
const MAXIMUM_INITIAL_URL_TIMEOUT_MILLISECONDS = 10_000;

export type BackendManagedHostAppState =
  | "active"
  | "background"
  | "inactive"
  | "unknown"
  | "extension";

export type BackendManagedHostLifecycleOperation =
  | "install_listeners"
  | "initial_refresh"
  | "drain_native_launch_urls"
  | "get_initial_url"
  | "deliver_launch_url"
  | "prepare_launch"
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
  /**
   * Applies the exact build-pinned native launch parser. Unrelated app URLs return false and must
   * never be logged, retained, or forwarded to the backend-managed controller.
   */
  isBackendLaunchURL: (url: string) => boolean;
  /** Atomically removes URLs from the process-local native inbox. Values must never be logged. */
  drainPendingLaunchURLs: () => readonly string[];
  /** Content-free native signal; the callback drains the inbox synchronously. */
  subscribePendingLaunchURL: (listener: () => void) => () => void;
  /** Dependency-free test seam. Invalid values use the production default. */
  initialURLTimeoutMilliseconds?: number;
  getCurrentAppState: () => BackendManagedHostAppState;
  subscribeIncomingURL: (listener: (url: string) => void) => () => void;
  subscribeAppState: (
    listener: (state: BackendManagedHostAppState) => void,
  ) => () => void;
}>;

export type BackendManagedHostLifecycleAdapter = Readonly<{
  /** The existing finite-state controller. Launch URLs and launch codes are never projected. */
  controller: BackendManagedHostController;
  /** Resolves after initial discovery and launch-inbox delivery, or rejects with a safe error. */
  ready: Promise<void>;
  /**
   * After `ready` rejects during initial refresh, joins at most one additional refresh shared with
   * blocked launch delivery, then repeats startup discovery. The method has no launch input or
   * output and returns one sticky safe result to every caller.
   */
  retryStartup: () => Promise<void>;
  /**
   * Delivers a URL obtained from a host-owned linking seam into the same private, serialized,
   * deduplicated queue used by React Native Linking. The value is never returned or projected.
   */
  deliverLaunchURL: (launchURL: string) => void;
  /** Compatibility teardown for hosts that do not install a replacement owner. */
  dispose: () => void;
  /**
   * Attempts every owned teardown and returns one sticky confirmation result. Retained callbacks
   * are inert after disposal even when exclusive listener/native-authority cleanup is uncertain.
   */
  disposeWithConfirmation: () => boolean;
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

type StartupDiscoveryCollector = {
  firstFailure: BackendManagedHostLifecycleAdapterError | null;
  readonly pending: Set<Promise<void>>;
};

/** Pure seam used by the public React Native factory and Node tests. */
export function createBackendManagedHostLifecycleAdapterForPrimitives(
  controller: BackendManagedHostController,
  primitives: BackendManagedHostLifecyclePrimitives,
  options: LifecycleOnlyOptions = {},
): BackendManagedHostLifecycleAdapter {
  let disposed = false;
  let initialRefreshCompleted = false;
  let removePendingLaunchURL: (() => void) | null = null;
  let removeIncomingURL: (() => void) | null = null;
  let removeAppState: (() => void) | null = null;
  let previousAppState: BackendManagedHostAppState;
  let foregroundGeneration = 0;
  let foregroundProcessedGeneration = 0;
  let foregroundScheduled = false;

  const attemptedLaunches = new Set<string>();
  const attemptedLaunchOrder: string[] = [];
  const pendingLaunches = new Map<string, Promise<void>>();
  let startupDiscoveryCollector: StartupDiscoveryCollector | null = null;

  const throwIfDisposed = (): void => {
    if (disposed) throw new InternalLifecycleDisposed();
  };

  const report = (error: BackendManagedHostLifecycleAdapterError): void => {
    // Listener installation marks the adapter disposed before publishing its constructor failure.
    // Every later operation is silent once teardown has fenced the lifecycle boundary.
    if (disposed && error.operation !== "install_listeners") return;
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
      throwIfDisposed();
      const result = await task();
      throwIfDisposed();
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

  let initialRefreshRetryExecution: Promise<void> | null = null;
  const retryInitialRefresh = (): Promise<void> => {
    if (initialRefreshCompleted) return Promise.resolve();
    if (initialRefreshRetryExecution) return initialRefreshRetryExecution;

    const execution = runStep("initial_refresh", () =>
      controller.refresh(),
    ).then(() => {
      throwIfDisposed();
      initialRefreshCompleted = true;
    });
    // Unlike general callback observation, a disposed retry must stay rejected so a queued launch
    // cannot continue into preparation after teardown. Every other failure is projected once here
    // and the same safe promise is shared by queued delivery and the public startup retry.
    const projected = execution.catch((error: unknown) => {
      if (error instanceof InternalLifecycleDisposed) throw error;
      if (disposed) throw new InternalLifecycleDisposed();
      if (error instanceof BackendManagedHostLifecycleAdapterError) throw error;
      const safeError = projectFailure(error, "initial_refresh");
      report(safeError);
      throw safeError;
    });
    void projected.catch(() => undefined);
    initialRefreshRetryExecution = projected;
    return initialRefreshRetryExecution;
  };

  const prepareLaunchOnce = async (launchURL: string): Promise<void> => {
    const fingerprint = fingerprintLaunchURL(launchURL);
    if (attemptedLaunches.has(fingerprint)) return;
    if (!initialRefreshCompleted) {
      await retryInitialRefresh();
    }
    // Disposal can run in the microtask between refresh completion and this continuation. Fence it
    // before retaining the fingerprint or invoking the controller with private launch authority.
    throwIfDisposed();
    // A discovery failure is not a launch delivery attempt. Remember only after discovery has
    // recovered so the retained native inbox or another accepted source can safely retry it.
    rememberAttempt(fingerprint);
    await runStep("prepare_launch", () =>
      controller.prepareLaunch(launchURL),
    );
  };

  const observe = (
    execution: Promise<void>,
    fallback: BackendManagedHostLifecycleOperation,
  ): Promise<void> => {
    const projected = execution.catch((error: unknown) => {
      if (error instanceof InternalLifecycleDisposed || disposed) return;
      // Nested queue work has already been projected and reported at its originating operation.
      if (error instanceof BackendManagedHostLifecycleAdapterError) throw error;
      const safeError = projectFailure(error, fallback);
      report(safeError);
      throw safeError;
    });
    // `ready` and callback-driven operations remain safe when a host intentionally ignores them.
    void projected.catch(() => undefined);
    return projected;
  };

  const refreshExecution = startupGate.then(async () => {
    if (disposed) return;
    await runStep("initial_refresh", () => controller.refresh());
    throwIfDisposed();
    initialRefreshCompleted = true;
  });
  // URL delivery waits only for controller discovery. A stuck React Native initial-URL promise
  // can no longer block the native inbox or any already-installed host/linking source.
  deliveryTail = refreshExecution.then(
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

  const trackStartupDiscoveryDelivery = (
    delivery: Promise<void>,
  ): Promise<void> => {
    const collector = startupDiscoveryCollector;
    if (!collector || collector.pending.has(delivery)) return delivery;
    collector.pending.add(delivery);
    void delivery.then(
      () => {
        collector.pending.delete(delivery);
      },
      (error: unknown) => {
        collector.pending.delete(delivery);
        const safeError =
          error instanceof BackendManagedHostLifecycleAdapterError
            ? error
            : new BackendManagedHostLifecycleAdapterError(
                "deliver_launch_url",
              );
        if (!(error instanceof BackendManagedHostLifecycleAdapterError)) {
          report(safeError);
        }
        collector.firstFailure ??= safeError;
      },
    );
    return delivery;
  };

  const seedStartupDiscoveryCollector = (): void => {
    // Seed only bounded promise values: launch URLs and fingerprints stay outside the collector.
    // The Set makes repeated seeding harmless when recovery reuses the same collector.
    for (const delivery of pendingLaunches.values()) {
      trackStartupDiscoveryDelivery(delivery);
    }
  };

  const enqueueIncomingURL = (launchURL: string): Promise<void> | null => {
    if (disposed) return null;
    if (typeof launchURL !== "string" || launchURL.length === 0) {
      report(
        new BackendManagedHostLifecycleAdapterError("deliver_launch_url"),
      );
      return null;
    }
    let isBackendLaunchURL: boolean;
    try {
      isBackendLaunchURL = primitives.isBackendLaunchURL(launchURL);
    } catch {
      report(
        new BackendManagedHostLifecycleAdapterError("deliver_launch_url"),
      );
      return null;
    }
    // A native matcher may synchronously trigger host teardown. Do not fingerprint or retain the
    // launch after that reentrant disposal, regardless of the matcher's return value.
    if (disposed) return null;
    if (isBackendLaunchURL === false) return null;
    if (isBackendLaunchURL !== true) {
      report(
        new BackendManagedHostLifecycleAdapterError("deliver_launch_url"),
      );
      return null;
    }
    const fingerprint = fingerprintLaunchURL(launchURL);
    if (attemptedLaunches.has(fingerprint)) return null;
    const existing = pendingLaunches.get(fingerprint);
    if (existing) return trackStartupDiscoveryDelivery(existing);
    if (
      pendingLaunches.size >= MAXIMUM_PENDING_LAUNCHES ||
      (startupDiscoveryCollector?.pending.size ?? 0) >=
        MAXIMUM_PENDING_LAUNCHES
    ) {
      report(
        new BackendManagedHostLifecycleAdapterError("deliver_launch_url"),
      );
      return null;
    }
    const execution = schedule("deliver_launch_url", async () => {
      await prepareLaunchOnce(launchURL);
    });
    pendingLaunches.set(fingerprint, execution);
    void execution
      .finally(() => {
        if (pendingLaunches.get(fingerprint) === execution) {
          pendingLaunches.delete(fingerprint);
        }
      })
      .catch(() => undefined);
    return trackStartupDiscoveryDelivery(execution);
  };

  const queueIncomingURL = (launchURL: string): void => {
    void enqueueIncomingURL(launchURL)?.catch(() => undefined);
  };

  const drainNativeLaunchInbox = (): readonly Promise<void>[] => {
    // The native inbox is the authoritative cold-launch owner. Keep its value retained until
    // discovery can accept delivery; an early signal or foreground transition must not consume it
    // behind a refresh failure.
    if (disposed || !initialRefreshCompleted) return [];
    let launchURLs: readonly string[];
    try {
      launchURLs = primitives.drainPendingLaunchURLs();
      if (
        !Array.isArray(launchURLs) ||
        launchURLs.length > MAXIMUM_PENDING_LAUNCHES ||
        launchURLs.some(
          (launchURL) =>
            typeof launchURL !== "string" || launchURL.length === 0,
        )
      ) {
        throw new InternalLifecycleFailure("drain_native_launch_urls");
      }
    } catch (error) {
      if (disposed) return [];
      report(projectFailure(error, "drain_native_launch_urls"));
      return [];
    }

    const deliveries: Promise<void>[] = [];
    for (const launchURL of launchURLs) {
      const delivery = enqueueIncomingURL(launchURL);
      if (delivery) deliveries.push(delivery);
    }
    return deliveries;
  };

  const handlePendingNativeLaunch = (): void => {
    for (const delivery of drainNativeLaunchInbox()) {
      void delivery.catch(() => undefined);
    }
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
          // Cover a URL callback that races the foreground transition. Any work enters the same
          // queue after this foreground task, so the task never waits on itself.
          handlePendingNativeLaunch();
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
    if (nextState === "active") handlePendingNativeLaunch();
    const shouldNotify =
      nextState === "active" &&
      (previousAppState === "inactive" ||
        previousAppState === "background");
    previousAppState = nextState;
    if (!shouldNotify) return;
    foregroundGeneration += 1;
    scheduleForeground();
  };

  const discoverStartupLaunches = async (
    existingCollector?: StartupDiscoveryCollector,
  ): Promise<void> => {
    if (disposed) return;
    const discoveryCollector =
      existingCollector ??
      ({
        firstFailure: null,
        pending: new Set<Promise<void>>(),
      } satisfies StartupDiscoveryCollector);
    startupDiscoveryCollector = discoveryCollector;
    // A callback accepted during initial refresh is already queued when discovery opens. Adopt its
    // promise so `ready` cannot lose its safe preparation result through the normalized queue tail.
    seedStartupDiscoveryCollector();
    let initialURL: string | null = null;
    try {
      // Native delivery remains immediate while the bounded Linking fallback is pending. Every
      // accepted delivery in that discovery window is registered in the bounded collector below.
      drainNativeLaunchInbox();
      try {
        initialURL = await runStep("get_initial_url", () =>
          getInitialURLWithTimeout(primitives),
        );
        // `runStep` checks its own await, but disposal can still run before this caller resumes.
        throwIfDisposed();
      } catch (error) {
        if (error instanceof InternalLifecycleDisposed || disposed) throw error;
        // The validated native inbox is authoritative. React Native Linking is a compatibility
        // source, so a rejected or timed-out initial lookup is reported but cannot hide an already
        // prepared native launch behind a rejected `ready` promise.
        report(projectFailure(error, "get_initial_url"));
      }
      if (initialURL !== null) {
        if (typeof initialURL !== "string" || initialURL.length === 0) {
          report(
            new BackendManagedHostLifecycleAdapterError("get_initial_url"),
          );
          initialURL = null;
        }
      }
      if (initialURL !== null) {
        enqueueIncomingURL(initialURL);
      }
    } finally {
      // Close the discovery window synchronously after the initial lookup. Later signals are warm
      // callback work; signals that raced the lookup are fenced by this exact promise snapshot.
      startupDiscoveryCollector = null;
    }
    await Promise.all(
      [...discoveryCollector.pending].map((delivery) =>
        delivery.catch(() => undefined),
      ),
    );
    if (discoveryCollector.firstFailure) {
      throw discoveryCollector.firstFailure;
    }
  };

  const startupExecution = refreshExecution.then(() =>
    discoverStartupLaunches(),
  );
  const ready = observe(startupExecution, "initial_refresh");

  let retryStartupExecution: Promise<void> | null = null;
  const retryStartup = (): Promise<void> => {
    if (retryStartupExecution) return retryStartupExecution;

    const execution = ready.then(
      () => undefined,
      async (error: unknown) => {
        if (disposed) return;
        // Launch preparation is deliberately one-shot. Only a failed initial discovery refresh
        // admits the startup retry; every other ready rejection retains its existing safe result.
        if (
          !(
            error instanceof BackendManagedHostLifecycleAdapterError &&
            error.operation === "initial_refresh"
          )
        ) {
          throw error;
        }

        const discoveryCollector: StartupDiscoveryCollector = {
          firstFailure: null,
          pending: new Set<Promise<void>>(),
        };
        // Open the collector before scheduling refresh so a callback accepted while refresh is in
        // flight is fenced too. Discovery still runs after the serialized task: awaiting a URL
        // delivery from inside that task would make the lifecycle tail wait on itself.
        startupDiscoveryCollector = discoveryCollector;
        // A delivery accepted just before this public retry may already own the one shared refresh.
        // Seed only its bounded promise so normalized queue ordering cannot erase a safe failure;
        // launch URLs and fingerprints remain outside the collector.
        seedStartupDiscoveryCollector();
        try {
          await schedule("initial_refresh", async () => {
            if (initialRefreshCompleted) return;
            await retryInitialRefresh();
          });
          if (disposed) return;
          await discoverStartupLaunches(discoveryCollector);
        } finally {
          if (startupDiscoveryCollector === discoveryCollector) {
            startupDiscoveryCollector = null;
          }
        }
      },
    );
    retryStartupExecution = observe(execution, "initial_refresh");
    return retryStartupExecution;
  };

  try {
    previousAppState = primitives.getCurrentAppState();
    removePendingLaunchURL =
      primitives.subscribePendingLaunchURL(handlePendingNativeLaunch);
    if (typeof removePendingLaunchURL !== "function") {
      throw new InternalLifecycleFailure("install_listeners");
    }
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
    safelyRemove(removePendingLaunchURL);
    safelyRemove(removeIncomingURL);
    safelyRemove(removeAppState);
    safelyDispose(controller);
    const safeError = projectFailure(error, "install_listeners");
    report(safeError);
    throw safeError;
  }

  beginStartup();

  let disposalConfirmed: boolean | null = null;
  let disposalReentered = false;
  const disposeWithConfirmation = (): boolean => {
    if (disposed) {
      if (disposalConfirmed === null) disposalReentered = true;
      return disposalConfirmed ?? false;
    }
    disposed = true;
    const pendingLaunchURLRemoval = removePendingLaunchURL;
    const incomingURLRemoval = removeIncomingURL;
    const appStateRemoval = removeAppState;
    removePendingLaunchURL = null;
    removeIncomingURL = null;
    removeAppState = null;
    const pendingLaunchURLRemoved = safelyRemove(pendingLaunchURLRemoval);
    const incomingURLRemoved = safelyRemove(incomingURLRemoval);
    const appStateRemoved = safelyRemove(appStateRemoval);
    pendingLaunches.clear();
    attemptedLaunches.clear();
    attemptedLaunchOrder.length = 0;
    const controllerDisposed = safelyDispose(controller);
    disposalConfirmed =
      pendingLaunchURLRemoved &&
      incomingURLRemoved &&
      appStateRemoved &&
      controllerDisposed &&
      !disposalReentered;
    return disposalConfirmed;
  };
  const dispose = (): void => {
    void disposeWithConfirmation();
  };

  return Object.freeze({
    controller,
    ready,
    retryStartup,
    deliverLaunchURL: queueIncomingURL,
    dispose,
    disposeWithConfirmation,
  });
}

function getInitialURLWithTimeout(
  primitives: BackendManagedHostLifecyclePrimitives,
): Promise<string | null> {
  const configuredTimeout = primitives.initialURLTimeoutMilliseconds;
  const timeoutMilliseconds =
    typeof configuredTimeout === "number" &&
    Number.isFinite(configuredTimeout) &&
    Number.isInteger(configuredTimeout) &&
    configuredTimeout > 0 &&
    configuredTimeout <= MAXIMUM_INITIAL_URL_TIMEOUT_MILLISECONDS
      ? configuredTimeout
      : DEFAULT_INITIAL_URL_TIMEOUT_MILLISECONDS;

  return new Promise<string | null>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new InternalLifecycleFailure("get_initial_url"));
    }, timeoutMilliseconds);

    let initialURL: Promise<string | null>;
    try {
      // Invoke the primitive before yielding. A native drain can queue teardown, and a deferred
      // invocation must not begin a new initial-URL read after that teardown has run.
      initialURL = Promise.resolve(primitives.getInitialURL());
    } catch {
      settled = true;
      clearTimeout(timer);
      reject(new InternalLifecycleFailure("get_initial_url"));
      return;
    }

    void initialURL.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new InternalLifecycleFailure("get_initial_url"));
      },
    );
  });
}

function safelyRemove(remover: (() => void) | null): boolean {
  if (!remover) return true;
  try {
    remover();
    return true;
  } catch {
    // The disposed gate makes retained callbacks inert; false prevents a replacement owner.
    return false;
  }
}

function safelyDispose(controller: BackendManagedHostController): boolean {
  try {
    return controller.disposeWithConfirmation() === true;
  } catch {
    // Teardown remains non-throwing while its caller receives an exact failure confirmation.
    return false;
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
