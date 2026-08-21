// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import type {
  BackendManagedHostController,
  BackendManagedHostSnapshot,
} from "../src/BackendManagedHostController.ts";
import {
  BackendManagedHostLifecycleAdapterError,
  createBackendManagedHostLifecycleAdapterForPrimitives,
  type BackendManagedHostAppState,
  type BackendManagedHostLifecycleError,
  type BackendManagedHostLifecyclePrimitives,
} from "../src/BackendManagedHostLifecycleAdapter.ts";

const LAUNCH_CODE = "launch-code-must-not-cross-the-adapter-boundary";
const LAUNCH_URL = `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`;
const ORDINARY_APP_URL = "kuzaba://test-mode/plain-cold-launch";

type ControllerHarnessOptions = Readonly<{
  refresh?: () => Promise<void>;
  prepareLaunch?: (url: string) => Promise<void>;
  notifyForeground?: () => Promise<void>;
  dispose?: () => boolean;
}>;

function createControllerHarness(options: ControllerHarnessOptions = {}) {
  const calls: string[] = [];
  const preparedURLs: string[] = [];
  let disposeCount = 0;
  const emptySnapshot = Object.freeze({}) as BackendManagedHostSnapshot;
  const noOp = async () => undefined;
  const disposeWithConfirmation = (): boolean => {
    calls.push("dispose-controller");
    disposeCount += 1;
    return options.dispose?.() ?? true;
  };

  const controller: BackendManagedHostController = {
    getSnapshot: () => emptySnapshot,
    subscribe: () => () => undefined,
    refresh: async () => {
      calls.push("refresh");
      await options.refresh?.();
    },
    prepareLaunch: async (url) => {
      calls.push("prepare-launch");
      preparedURLs.push(url);
      await options.prepareLaunch?.(url);
    },
    respondToLaunchConsent: noOp,
    exchangeApprovedLaunch: noOp,
    recoverStartPlan: noOp,
    recoverResumePlan: noOp,
    abandonStart: noOp,
    resetPreparedResume: noOp,
    startPlannedCapture: noOp,
    resumePlannedCapture: noOp,
    stopCapture: noOp,
    keepVerifiedPartial: noOp,
    admitAndDrain: noOp,
    notifyForeground: async () => {
      calls.push("notify-foreground");
      await options.notifyForeground?.();
    },
    requestAuthenticatedReset: noOp,
    cancelAuthenticatedReset: noOp,
    confirmAuthenticatedReset: noOp,
    dispose: () => {
      void disposeWithConfirmation();
    },
    disposeWithConfirmation,
  };

  return {
    controller,
    calls,
    preparedURLs,
    disposeCount: () => disposeCount,
  };
}

type LifecycleHarnessOptions = Readonly<{
  initialURL?: string | null;
  initialNativeURLs?: readonly string[];
  isBackendLaunchURL?: (url: string) => boolean;
  currentState?: BackendManagedHostAppState;
  emitURLWhileSubscribing?: string;
  emitNativeSignalWhileSubscribing?: boolean;
  getInitialURL?: () => Promise<string | null>;
  drainPendingLaunchURLs?: () => readonly string[];
  initialURLTimeoutMilliseconds?: number;
  subscribeAppState?: (
    listener: (state: BackendManagedHostAppState) => void,
  ) => () => void;
  onPendingNativeLaunchRemoval?: () => void;
  failPendingNativeLaunchRemoval?: boolean;
  failIncomingURLRemoval?: boolean;
  failAppStateRemoval?: boolean;
}>;

function createLifecycleHarness(options: LifecycleHarnessOptions = {}) {
  const calls: string[] = [];
  const incomingURLListeners = new Set<(url: string) => void>();
  const pendingNativeLaunchListeners = new Set<() => void>();
  const appStateListeners = new Set<
    (state: BackendManagedHostAppState) => void
  >();
  let incomingURLRemovalCount = 0;
  let pendingNativeLaunchRemovalCount = 0;
  let appStateRemovalCount = 0;
  let pendingNativeURLs = [...(options.initialNativeURLs ?? [])];

  const primitives: BackendManagedHostLifecyclePrimitives = {
    getInitialURL: async () => {
      calls.push("get-initial-url");
      if (options.getInitialURL) return options.getInitialURL();
      return options.initialURL ?? null;
    },
    isBackendLaunchURL: (url) =>
      options.isBackendLaunchURL?.(url) ?? url.startsWith("tacua-test://"),
    drainPendingLaunchURLs: () => {
      calls.push("drain-native-launch-urls");
      if (options.drainPendingLaunchURLs) {
        return options.drainPendingLaunchURLs();
      }
      const drained = pendingNativeURLs;
      pendingNativeURLs = [];
      return drained;
    },
    subscribePendingLaunchURL: (listener) => {
      calls.push("subscribe-native-launch");
      pendingNativeLaunchListeners.add(listener);
      if (options.emitNativeSignalWhileSubscribing) listener();
      return () => {
        calls.push("remove-native-launch");
        pendingNativeLaunchRemovalCount += 1;
        pendingNativeLaunchListeners.delete(listener);
        options.onPendingNativeLaunchRemoval?.();
        if (options.failPendingNativeLaunchRemoval) {
          throw new Error(`private native-launch removal ${LAUNCH_URL}`);
        }
      };
    },
    ...(options.initialURLTimeoutMilliseconds === undefined
      ? {}
      : {
          initialURLTimeoutMilliseconds:
            options.initialURLTimeoutMilliseconds,
        }),
    getCurrentAppState: () => {
      calls.push("get-current-state");
      return options.currentState ?? "active";
    },
    subscribeIncomingURL: (listener) => {
      calls.push("subscribe-url");
      incomingURLListeners.add(listener);
      if (options.emitURLWhileSubscribing !== undefined) {
        listener(options.emitURLWhileSubscribing);
      }
      return () => {
        calls.push("remove-url");
        incomingURLRemovalCount += 1;
        incomingURLListeners.delete(listener);
        if (options.failIncomingURLRemoval) {
          throw new Error(`private incoming-URL removal ${LAUNCH_URL}`);
        }
      };
    },
    subscribeAppState: (listener) => {
      calls.push("subscribe-app-state");
      if (options.subscribeAppState) {
        return options.subscribeAppState(listener);
      }
      appStateListeners.add(listener);
      return () => {
        calls.push("remove-app-state");
        appStateRemovalCount += 1;
        appStateListeners.delete(listener);
        if (options.failAppStateRemoval) {
          throw new Error(`private app-state removal ${LAUNCH_URL}`);
        }
      };
    },
  };

  return {
    primitives,
    calls,
    emitURL(url: string) {
      for (const listener of incomingURLListeners) listener(url);
    },
    enqueueNativeURL(url: string, signal = true) {
      pendingNativeURLs.push(url);
      if (signal) {
        for (const listener of pendingNativeLaunchListeners) listener();
      }
    },
    emitAppState(state: BackendManagedHostAppState) {
      for (const listener of appStateListeners) listener(state);
    },
    incomingURLListenerCount: () => incomingURLListeners.size,
    pendingNativeLaunchListenerCount: () =>
      pendingNativeLaunchListeners.size,
    appStateListenerCount: () => appStateListeners.size,
    incomingURLRemovalCount: () => incomingURLRemovalCount,
    pendingNativeLaunchRemovalCount: () =>
      pendingNativeLaunchRemovalCount,
    appStateRemovalCount: () => appStateRemovalCount,
  };
}

function deferred() {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((fulfill) => {
    resolve = fulfill;
  });
  return { promise, resolve };
}

function deferredValue<Value>() {
  let resolve: (value: Value) => void = () => undefined;
  const promise = new Promise<Value>((fulfill) => {
    resolve = fulfill;
  });
  return { promise, resolve };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("Timed out waiting for lifecycle adapter work");
}

test("startup installs listeners, refreshes, and privately delivers the initial URL", async () => {
  const trace: string[] = [];
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      trace.push("refresh");
    },
    prepareLaunch: async () => {
      trace.push("prepare-launch");
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    initialURL: LAUNCH_URL,
    getInitialURL: async () => {
      trace.push("get-initial-url");
      return LAUNCH_URL;
    },
  });

  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );
  assert.equal(lifecycleHarness.pendingNativeLaunchListenerCount(), 1);
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 1);
  assert.equal(lifecycleHarness.appStateListenerCount(), 1);

  await adapter.ready;
  assert.deepEqual(trace, ["refresh", "get-initial-url", "prepare-launch"]);
  assert.equal(adapter.controller, controllerHarness.controller);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);

  adapter.dispose();
});

test("startup retry recovers a native-only cold-launch inbox after refresh rejection", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) {
        throw new Error(`private initial discovery ${LAUNCH_URL}`);
      }
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    currentState: "active",
    initialNativeURLs: [LAUNCH_URL],
    initialURL: null,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(
    adapter.ready,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "initial_refresh",
  );
  assert.equal(
    lifecycleHarness.calls.includes("drain-native-launch-urls"),
    false,
  );
  assert.deepEqual(controllerHarness.preparedURLs, []);

  await adapter.retryStartup();

  assert.equal(refreshCount, 2);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    1,
  );
  assert.equal(
    lifecycleHarness.calls.filter((call) => call === "get-initial-url")
      .length,
    1,
  );
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(
    controllerHarness.calls.filter((call) => call === "prepare-launch")
      .length,
    1,
  );
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(lifecycleHarness.pendingNativeLaunchListenerCount(), 1);
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 1);
  assert.equal(lifecycleHarness.appStateListenerCount(), 1);
  adapter.dispose();
});

test("a failed initial refresh has one coalesced startup retry across duplicate active sources", async () => {
  const releaseRecoveryRefresh = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) {
        throw new Error(`private initial discovery ${LAUNCH_URL}`);
      }
      await releaseRecoveryRefresh.promise;
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    currentState: "active",
    initialNativeURLs: [LAUNCH_URL],
    initialURL: LAUNCH_URL,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(
    adapter.ready,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "initial_refresh",
  );
  assert.equal(
    lifecycleHarness.calls.includes("drain-native-launch-urls"),
    false,
  );

  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  await waitFor(() => refreshCount === 2);

  // Router and React Native event duplicates race the retained native cold-launch inbox.
  adapter.deliverLaunchURL(LAUNCH_URL);
  lifecycleHarness.emitURL(LAUNCH_URL);
  assert.deepEqual(controllerHarness.preparedURLs, []);

  releaseRecoveryRefresh.resolve();
  await recovery;
  assert.equal(adapter.retryStartup(), recovery);
  await adapter.retryStartup();

  assert.equal(refreshCount, 2);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    1,
  );
  assert.equal(
    lifecycleHarness.calls.filter((call) => call === "get-initial-url")
      .length,
    1,
  );
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(lifecycleHarness.pendingNativeLaunchListenerCount(), 1);
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 1);
  assert.equal(lifecycleHarness.appStateListenerCount(), 1);
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("sequential duplicate callbacks share the one failed refresh retry", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      throw new Error(`private refresh ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({ initialURL: null });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  lifecycleHarness.emitURL(LAUNCH_URL);
  await waitFor(() => errors.length === 2);

  // Let the first rejected delivery leave the pending map before replaying the exact source.
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  lifecycleHarness.emitURL(LAUNCH_URL);
  adapter.deliverLaunchURL(LAUNCH_URL);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  await assert.rejects(
    recovery,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "initial_refresh" &&
      !String(error).includes(LAUNCH_CODE),
  );
  assert.equal(adapter.retryStartup(), recovery);

  assert.equal(refreshCount, 2);
  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("startup retry fences a callback accepted during its scheduled refresh", async () => {
  const releaseRetryRefresh = deferred();
  const releasePreparation = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) {
        throw new Error(`private initial refresh ${LAUNCH_URL}`);
      }
      await releaseRetryRefresh.promise;
    },
    prepareLaunch: async () => {
      await releasePreparation.promise;
      throw new Error(`private preparation ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({ initialURL: null });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  const recovery = adapter.retryStartup();
  await waitFor(() => refreshCount === 2);

  // This callback is accepted after recovery starts but cannot run until its refresh task exits.
  lifecycleHarness.emitURL(LAUNCH_URL);
  assert.deepEqual(controllerHarness.preparedURLs, []);
  releaseRetryRefresh.resolve();
  await waitFor(() => controllerHarness.preparedURLs.length === 1);

  let recoverySettled = false;
  void recovery
    .finally(() => {
      recoverySettled = true;
    })
    .catch(() => undefined);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(recoverySettled, false);

  releasePreparation.resolve();
  await assert.rejects(
    recovery,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "prepare_launch" &&
      !String(error).includes(LAUNCH_CODE),
  );
  assert.equal(recoverySettled, true);
  assert.equal(refreshCount, 2);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    1,
  );
  assert.equal(
    lifecycleHarness.calls.filter((call) => call === "get-initial-url")
      .length,
    1,
  );
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
    {
      operation: "prepare_launch",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("startup retry adopts a callback already driving the shared refresh", async () => {
  const releaseRetryRefresh = deferred();
  const releasePreparation = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) {
        throw new Error(`private initial refresh ${LAUNCH_URL}`);
      }
      await releaseRetryRefresh.promise;
    },
    prepareLaunch: async () => {
      await releasePreparation.promise;
      throw new Error(`private preparation ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({ initialURL: null });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  lifecycleHarness.emitURL(LAUNCH_URL);
  await waitFor(() => refreshCount === 2);

  // The callback owns the shared retry before the public boundary opens its collector.
  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  let recoverySettled = false;
  void recovery
    .finally(() => {
      recoverySettled = true;
    })
    .catch(() => undefined);

  releaseRetryRefresh.resolve();
  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(recoverySettled, false);

  releasePreparation.resolve();
  await assert.rejects(
    recovery,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "prepare_launch" &&
      !String(error).includes(LAUNCH_CODE),
  );
  assert.equal(recoverySettled, true);
  assert.equal(refreshCount, 2);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    1,
  );
  assert.equal(
    lifecycleHarness.calls.filter((call) => call === "get-initial-url")
      .length,
    1,
  );
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
    {
      operation: "prepare_launch",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("ready adopts a callback accepted during its initial refresh", async () => {
  const releaseInitialRefresh = deferred();
  const releasePreparation = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      await releaseInitialRefresh.promise;
    },
    prepareLaunch: async () => {
      await releasePreparation.promise;
      throw new Error(`private preparation ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({ initialURL: null });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await waitFor(() => refreshCount === 1);
  lifecycleHarness.emitURL(LAUNCH_URL);
  assert.deepEqual(controllerHarness.preparedURLs, []);

  let readySettled = false;
  void adapter.ready
    .finally(() => {
      readySettled = true;
    })
    .catch(() => undefined);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(readySettled, false);

  releaseInitialRefresh.resolve();
  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(readySettled, false);

  releasePreparation.resolve();
  let readyError: unknown;
  await assert.rejects(adapter.ready, (error: unknown) => {
    readyError = error;
    return (
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "prepare_launch" &&
      !String(error).includes(LAUNCH_CODE)
    );
  });
  assert.equal(readySettled, true);

  // A non-refresh startup failure is sticky and never replays discovery or launch preparation.
  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  await assert.rejects(recovery, (error: unknown) => error === readyError);
  assert.equal(refreshCount, 1);
  assert.deepEqual(controllerHarness.calls, ["refresh", "prepare-launch"]);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    1,
  );
  assert.equal(
    lifecycleHarness.calls.filter((call) => call === "get-initial-url")
      .length,
    1,
  );
  assert.deepEqual(errors, [
    {
      operation: "prepare_launch",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("ready fences a native signal that races the bounded initial URL lookup", async () => {
  const initialURL = deferredValue<string | null>();
  const releasePreparation = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness({
    prepareLaunch: async () => {
      await releasePreparation.promise;
      throw new Error(`private preparation ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    getInitialURL: () => initialURL.promise,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await waitFor(() => lifecycleHarness.calls.includes("get-initial-url"));
  lifecycleHarness.enqueueNativeURL(LAUNCH_URL);
  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  initialURL.resolve(null);

  let readySettled = false;
  void adapter.ready
    .finally(() => {
      readySettled = true;
    })
    .catch(() => undefined);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(readySettled, false);

  releasePreparation.resolve();
  await assert.rejects(
    adapter.ready,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "prepare_launch" &&
      !String(error).includes(LAUNCH_CODE),
  );
  assert.equal(readySettled, true);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.deepEqual(errors, [
    {
      operation: "prepare_launch",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("startup discovery bounds concurrent work without capping sequential native delivery", async () => {
  const initialURL = deferredValue<string | null>();
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    getInitialURL: () => initialURL.promise,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await waitFor(() => lifecycleHarness.calls.includes("get-initial-url"));
  const launchURLs = Array.from(
    { length: 33 },
    (_, index) => `${LAUNCH_URL}&sequence=${index}`,
  );
  for (const [index, launchURL] of launchURLs.entries()) {
    lifecycleHarness.enqueueNativeURL(launchURL);
    await waitFor(() => controllerHarness.preparedURLs.length === index + 1);
  }

  initialURL.resolve(null);
  await adapter.ready;

  assert.deepEqual(controllerHarness.preparedURLs, launchURLs);
  assert.deepEqual(errors, []);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    34,
  );
  adapter.dispose();
});

test("disposal fences a native delivery collected during initial URL lookup", async () => {
  const initialURL = deferredValue<string | null>();
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    getInitialURL: () => initialURL.promise,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await waitFor(() => lifecycleHarness.calls.includes("get-initial-url"));
  lifecycleHarness.enqueueNativeURL(LAUNCH_URL);
  assert.equal(adapter.disposeWithConfirmation(), true);
  initialURL.resolve(null);
  await adapter.ready;
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, []);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    2,
  );
  assert.equal(lifecycleHarness.pendingNativeLaunchListenerCount(), 0);
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 0);
  assert.equal(lifecycleHarness.appStateListenerCount(), 0);
});

test("startup recovery fences a native signal that races its initial URL lookup", async () => {
  const initialURL = deferredValue<string | null>();
  const releasePreparation = deferred();
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) throw new Error("private initial refresh");
    },
    prepareLaunch: () => releasePreparation.promise,
  });
  const lifecycleHarness = createLifecycleHarness({
    getInitialURL: () => initialURL.promise,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );

  await assert.rejects(adapter.ready);
  const recovery = adapter.retryStartup();
  await waitFor(() => lifecycleHarness.calls.includes("get-initial-url"));
  lifecycleHarness.enqueueNativeURL(LAUNCH_URL);
  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  initialURL.resolve(null);

  let recoverySettled = false;
  void recovery.then(() => {
    recoverySettled = true;
  });
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(recoverySettled, false);

  releasePreparation.resolve();
  await recovery;
  assert.equal(recoverySettled, true);
  assert.equal(refreshCount, 2);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  adapter.dispose();
});

test("an early native signal retains its cold launch until startup recovery", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) {
        throw new Error(`private discovery failure ${LAUNCH_URL}`);
      }
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    currentState: "active",
    initialNativeURLs: [LAUNCH_URL],
    initialURL: null,
    emitNativeSignalWhileSubscribing: true,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  assert.equal(
    lifecycleHarness.calls.includes("drain-native-launch-urls"),
    false,
  );
  const recovery = adapter.retryStartup();
  await recovery;

  assert.equal(refreshCount, 2);
  assert.equal(
    lifecycleHarness.calls.filter(
      (call) => call === "drain-native-launch-urls",
    ).length,
    1,
  );
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  assert.equal(lifecycleHarness.pendingNativeLaunchListenerCount(), 1);
  adapter.dispose();
});

test("startup retry failure is sticky, bounded, and contains no launch authority", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      throw new Error(`private refresh ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    initialNativeURLs: [LAUNCH_URL],
    initialURL: LAUNCH_URL,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  const recovery = adapter.retryStartup();
  await assert.rejects(
    recovery,
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "initial_refresh" &&
      !String(error).includes(LAUNCH_CODE),
  );
  assert.equal(adapter.retryStartup(), recovery);
  await assert.rejects(adapter.retryStartup());

  assert.equal(refreshCount, 2);
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(errors.every(Object.isFrozen), true);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("disposal during startup retry fences discovery and launch delivery", async () => {
  const releaseRecoveryRefresh = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  let refreshCount = 0;
  const controllerHarness = createControllerHarness({
    refresh: async () => {
      refreshCount += 1;
      if (refreshCount === 1) throw new Error(`private ${LAUNCH_URL}`);
      await releaseRecoveryRefresh.promise;
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    initialNativeURLs: [LAUNCH_URL],
    initialURL: LAUNCH_URL,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  const recovery = adapter.retryStartup();
  await waitFor(() => refreshCount === 2);
  assert.equal(adapter.disposeWithConfirmation(), true);
  releaseRecoveryRefresh.resolve();
  await recovery;

  assert.equal(adapter.retryStartup(), recovery);
  assert.equal(
    lifecycleHarness.calls.includes("drain-native-launch-urls"),
    false,
  );
  assert.equal(lifecycleHarness.calls.includes("get-initial-url"), false);
  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(controllerHarness.calls, [
    "refresh",
    "refresh",
    "dispose-controller",
  ]);
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
});

test("queued disposal fences a callback-owned retry before launch preparation", async () => {
  const releaseRetryRefresh = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  const events: string[] = [];
  let refreshCount = 0;
  let controllerDisposed = false;
  const controllerHarness = createControllerHarness();
  const disposeController = (): boolean => {
    controllerDisposed = true;
    events.push("dispose-controller");
    return true;
  };
  const controller: BackendManagedHostController = {
    ...controllerHarness.controller,
    refresh: () => {
      refreshCount += 1;
      events.push(`refresh-${refreshCount}`);
      return refreshCount === 1
        ? Promise.reject(new Error(`private refresh ${LAUNCH_URL}`))
        : releaseRetryRefresh.promise;
    },
    prepareLaunch: async () => {
      events.push(
        controllerDisposed ? "prepare-after-dispose" : "prepare-launch",
      );
    },
    dispose: () => {
      void disposeController();
    },
    disposeWithConfirmation: disposeController,
  };
  const lifecycleHarness = createLifecycleHarness({ initialURL: null });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await assert.rejects(adapter.ready);
  lifecycleHarness.emitURL(LAUNCH_URL);
  await waitFor(() => refreshCount === 2);

  // Resolving queues runStep's continuation first; disposal then runs before the retry projection
  // and launch-delivery continuation can mark discovery complete or retain launch authority.
  releaseRetryRefresh.resolve();
  queueMicrotask(() => adapter.dispose());
  for (let turn = 0; turn < 3; turn += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  await recovery;
  assert.equal(adapter.disposeWithConfirmation(), true);
  assert.deepEqual(events, ["refresh-1", "refresh-2", "dispose-controller"]);
  assert.deepEqual(errors, [
    {
      operation: "initial_refresh",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
});

test("queued disposal suppresses a classified initial refresh failure", async () => {
  let rejectInitialRefresh: (error: unknown) => void = () => undefined;
  const initialRefresh = new Promise<void>((_resolve, reject) => {
    rejectInitialRefresh = reject;
  });
  const errors: BackendManagedHostLifecycleError[] = [];
  const events: string[] = [];
  const controllerHarness = createControllerHarness();
  const disposeController = (): boolean => {
    events.push("dispose-controller");
    return true;
  };
  const controller: BackendManagedHostController = {
    ...controllerHarness.controller,
    refresh: () => {
      events.push("refresh");
      return initialRefresh;
    },
    dispose: () => {
      void disposeController();
    },
    disposeWithConfirmation: disposeController,
  };
  const lifecycleHarness = createLifecycleHarness({ initialURL: null });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );
  await waitFor(() => events.includes("refresh"));

  // runStep classifies this rejection before the next microtask disposes the adapter. Public
  // observation must still honor the current disposal fence instead of reporting a late failure.
  rejectInitialRefresh(new Error(`private refresh ${LAUNCH_URL}`));
  queueMicrotask(() => adapter.dispose());
  await adapter.ready;

  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  await recovery;
  assert.equal(adapter.disposeWithConfirmation(), true);
  assert.deepEqual(events, ["refresh", "dispose-controller"]);
  assert.deepEqual(errors, []);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
});

test("queued disposal fences initial URL validation and reporting", async () => {
  const initialURL = deferredValue<string | null>();
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    getInitialURL: () => initialURL.promise,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );
  await waitFor(() => lifecycleHarness.calls.includes("get-initial-url"));

  // The runtime-invalid fallback result reaches runStep first. Nested microtasks then dispose before
  // discovery resumes to validate it, so no post-teardown error or delivery may be published.
  initialURL.resolve(42 as unknown as string | null);
  queueMicrotask(() => queueMicrotask(() => adapter.dispose()));
  await adapter.ready;

  const recovery = adapter.retryStartup();
  assert.equal(adapter.retryStartup(), recovery);
  await recovery;
  assert.equal(adapter.disposeWithConfirmation(), true);
  assert.deepEqual(controllerHarness.calls, ["refresh", "dispose-controller"]);
  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, []);
  assert.equal(
    lifecycleHarness.calls.filter((call) => call === "get-initial-url")
      .length,
    1,
  );
});

test("a native drain cannot defer initial URL invocation past disposal", async () => {
  const events: string[] = [];
  const errors: BackendManagedHostLifecycleError[] = [];
  let controllerDisposed = false;
  let adapter:
    | ReturnType<typeof createBackendManagedHostLifecycleAdapterForPrimitives>
    | null = null;
  const controllerHarness = createControllerHarness({
    dispose: () => {
      controllerDisposed = true;
      events.push("dispose-controller");
      return true;
    },
  });
  const lifecycleHarness = createLifecycleHarness({
    drainPendingLaunchURLs: () => {
      events.push("drain-native-launch-urls");
      queueMicrotask(() => {
        events.push("dispose-adapter");
        adapter?.dispose();
      });
      return [];
    },
    getInitialURL: async () => {
      events.push(
        controllerDisposed
          ? "get-initial-url-after-dispose"
          : "get-initial-url",
      );
      return null;
    },
  });
  adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await adapter.ready;

  assert.equal(adapter.disposeWithConfirmation(), true);
  assert.deepEqual(events, [
    "drain-native-launch-urls",
    "get-initial-url",
    "dispose-adapter",
    "dispose-controller",
  ]);
  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, []);
});

test("startup retry preserves non-refresh ready failures without replay", async () => {
  const controllerHarness = createControllerHarness({
    prepareLaunch: async () => {
      throw new Error(`private preparation ${LAUNCH_URL}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness({ initialURL: LAUNCH_URL });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );

  let readyError: unknown;
  await assert.rejects(adapter.ready, (error: unknown) => {
    readyError = error;
    return (
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "prepare_launch"
    );
  });
  const recovery = adapter.retryStartup();
  await assert.rejects(recovery, (error: unknown) => error === readyError);
  assert.equal(adapter.retryStartup(), recovery);
  assert.deepEqual(controllerHarness.calls, ["refresh", "prepare-launch"]);
  adapter.dispose();
});

test("startup and event duplicates cause one exact launch delivery", async () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    initialURL: LAUNCH_URL,
    initialNativeURLs: [LAUNCH_URL],
    emitNativeSignalWhileSubscribing: true,
    emitURLWhileSubscribing: LAUNCH_URL,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );

  await adapter.ready;
  lifecycleHarness.emitURL(LAUNCH_URL);
  lifecycleHarness.emitURL(LAUNCH_URL);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);

  const secondURL = `${LAUNCH_URL}-different`;
  lifecycleHarness.emitURL(secondURL);
  await waitFor(() => controllerHarness.preparedURLs.length === 2);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL, secondURL]);
  adapter.dispose();
});

test("ordinary host-app initial and event URLs never enter the Tacua launch queue", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    initialURL: ORDINARY_APP_URL,
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await adapter.ready;
  lifecycleHarness.emitURL(ORDINARY_APP_URL);
  adapter.deliverLaunchURL(ORDINARY_APP_URL);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, []);

  lifecycleHarness.emitURL(LAUNCH_URL);
  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  adapter.dispose();
});

test("a launch matcher failure is content-safe and fails closed", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    initialURL: LAUNCH_URL,
    isBackendLaunchURL: () => {
      throw new Error(`private matcher failure ${LAUNCH_URL}`);
    },
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await adapter.ready;
  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, [
    {
      operation: "deliver_launch_url",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("native cold-launch inbox delivers before a stuck initial URL lookup times out", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    initialNativeURLs: [LAUNCH_URL],
    initialURLTimeoutMilliseconds: 10,
    getInitialURL: () => new Promise<string | null>(() => undefined),
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  await adapter.ready;
  assert.deepEqual(errors, [
    {
      operation: "get_initial_url",
      category: "host_lifecycle_rejected",
    },
  ]);
  adapter.dispose();
});

test("content-free native signal drains a warm launch into the shared queue", async () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness();
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );
  await adapter.ready;

  lifecycleHarness.enqueueNativeURL(LAUNCH_URL);
  lifecycleHarness.emitURL(LAUNCH_URL);
  adapter.deliverLaunchURL(LAUNCH_URL);
  await waitFor(() => controllerHarness.preparedURLs.length === 1);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  adapter.dispose();
});

test("foreground drains a retained native URL even when its signal was missed", async () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness();
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );
  await adapter.ready;

  lifecycleHarness.enqueueNativeURL(LAUNCH_URL, false);
  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  await waitFor(
    () =>
      controllerHarness.preparedURLs.length === 1 &&
      controllerHarness.calls.includes("notify-foreground"),
  );
  assert.deepEqual(controllerHarness.calls.slice(-2), [
    "prepare-launch",
    "notify-foreground",
  ]);
  adapter.dispose();
});

test("native inbox failures are content-safe and do not block fallback discovery", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    drainPendingLaunchURLs: () => {
      throw new Error(`private ${LAUNCH_URL}`);
    },
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await adapter.ready;
  assert.deepEqual(errors, [
    {
      operation: "drain_native_launch_urls",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("host-owned linking seams enter the adapter's existing private dedupe queue", async () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({ initialURL: LAUNCH_URL });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );

  adapter.deliverLaunchURL(LAUNCH_URL);
  lifecycleHarness.emitURL(LAUNCH_URL);
  await adapter.ready;

  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(adapter.deliverLaunchURL(LAUNCH_URL), undefined);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);

  const secondURL = `${LAUNCH_URL}-host-source`;
  adapter.deliverLaunchURL(secondURL);
  lifecycleHarness.emitURL(secondURL);
  await waitFor(() => controllerHarness.preparedURLs.length === 2);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL, secondURL]);

  adapter.dispose();
  adapter.deliverLaunchURL(`${LAUNCH_URL}-after-dispose`);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(controllerHarness.preparedURLs.length, 2);
});

test("incoming URLs and foreground work serialize behind initial discovery", async () => {
  const releaseRefresh = deferred();
  const controllerHarness = createControllerHarness({
    refresh: () => releaseRefresh.promise,
  });
  const lifecycleHarness = createLifecycleHarness();
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );

  lifecycleHarness.emitURL(LAUNCH_URL);
  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  await waitFor(() => controllerHarness.calls.includes("refresh"));
  assert.deepEqual(controllerHarness.calls, ["refresh"]);

  releaseRefresh.resolve();
  await adapter.ready;
  await waitFor(
    () =>
      controllerHarness.calls.filter(
        (call) => call === "notify-foreground",
      ).length === 1,
  );
  assert.deepEqual(controllerHarness.calls, [
    "refresh",
    "prepare-launch",
    "notify-foreground",
  ]);
  adapter.dispose();
});

test("foreground bursts coalesce while preserving a transition during native work", async () => {
  const releaseFirstForeground = deferred();
  let foregroundCalls = 0;
  const controllerHarness = createControllerHarness({
    notifyForeground: async () => {
      foregroundCalls += 1;
      if (foregroundCalls === 1) await releaseFirstForeground.promise;
    },
  });
  const lifecycleHarness = createLifecycleHarness();
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );
  await adapter.ready;

  lifecycleHarness.emitAppState("active");
  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  lifecycleHarness.emitAppState("active");
  await waitFor(() => foregroundCalls === 1);

  lifecycleHarness.emitAppState("inactive");
  lifecycleHarness.emitAppState("active");
  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  releaseFirstForeground.resolve();
  await waitFor(() => foregroundCalls === 2);
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  assert.equal(foregroundCalls, 2);
  adapter.dispose();
});

test("dispose is idempotent and prevents startup, queued, and later callback work", async () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness();
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );

  lifecycleHarness.emitURL(LAUNCH_URL);
  assert.equal(adapter.disposeWithConfirmation(), true);
  assert.equal(adapter.disposeWithConfirmation(), true);
  await adapter.ready;
  lifecycleHarness.emitURL(`${LAUNCH_URL}-after-dispose`);
  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  assert.deepEqual(controllerHarness.calls, ["dispose-controller"]);
  assert.equal(controllerHarness.disposeCount(), 1);
  assert.equal(lifecycleHarness.pendingNativeLaunchRemovalCount(), 1);
  assert.equal(lifecycleHarness.incomingURLRemovalCount(), 1);
  assert.equal(lifecycleHarness.appStateRemovalCount(), 1);
  assert.equal(lifecycleHarness.pendingNativeLaunchListenerCount(), 0);
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 0);
  assert.equal(lifecycleHarness.appStateListenerCount(), 0);
});

test("reentrant disposal makes the outer confirmation sticky false", async () => {
  const controllerHarness = createControllerHarness();
  let adapter:
    | ReturnType<typeof createBackendManagedHostLifecycleAdapterForPrimitives>
    | null = null;
  let reentrantResult: boolean | null = null;
  const lifecycleHarness = createLifecycleHarness({
    onPendingNativeLaunchRemoval: () => {
      reentrantResult = adapter?.disposeWithConfirmation() ?? null;
    },
  });
  adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
  );
  await adapter.ready;

  assert.equal(adapter.disposeWithConfirmation(), false);
  assert.equal(reentrantResult, false);
  assert.equal(adapter.disposeWithConfirmation(), false);
  assert.equal(lifecycleHarness.pendingNativeLaunchRemovalCount(), 1);
  assert.equal(lifecycleHarness.incomingURLRemovalCount(), 1);
  assert.equal(lifecycleHarness.appStateRemovalCount(), 1);
  assert.equal(controllerHarness.disposeCount(), 1);
});

for (const failure of [
  "pending native launch removal",
  "incoming URL removal",
  "app state removal",
  "controller rejection",
  "controller throw",
] as const) {
  test(`dispose returns one sticky false result after ${failure} while attempting every teardown`, async () => {
    const controllerHarness = createControllerHarness({
      ...(failure === "controller rejection"
        ? { dispose: () => false }
        : failure === "controller throw"
          ? {
              dispose: () => {
                throw new Error(`private controller teardown ${LAUNCH_URL}`);
              },
            }
          : {}),
    });
    const lifecycleHarness = createLifecycleHarness({
      failPendingNativeLaunchRemoval:
        failure === "pending native launch removal",
      failIncomingURLRemoval: failure === "incoming URL removal",
      failAppStateRemoval: failure === "app state removal",
    });
    const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
      controllerHarness.controller,
      lifecycleHarness.primitives,
    );
    await adapter.ready;

    assert.equal(adapter.disposeWithConfirmation(), false);
    assert.equal(adapter.disposeWithConfirmation(), false);
    assert.equal(lifecycleHarness.pendingNativeLaunchRemovalCount(), 1);
    assert.equal(lifecycleHarness.incomingURLRemovalCount(), 1);
    assert.equal(lifecycleHarness.appStateRemovalCount(), 1);
    assert.equal(controllerHarness.disposeCount(), 1);
    assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);
  });
}

test("dispose during initial refresh fences initial URL lookup and delivery", async () => {
  const releaseRefresh = deferred();
  const errors: BackendManagedHostLifecycleError[] = [];
  let initialURLReads = 0;
  const controllerHarness = createControllerHarness({
    refresh: () => releaseRefresh.promise,
  });
  const lifecycleHarness = createLifecycleHarness({
    initialURL: LAUNCH_URL,
    getInitialURL: async () => {
      initialURLReads += 1;
      return LAUNCH_URL;
    },
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );
  await waitFor(() => controllerHarness.calls.includes("refresh"));

  adapter.dispose();
  releaseRefresh.resolve();
  await adapter.ready;
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  assert.equal(initialURLReads, 0);
  assert.deepEqual(controllerHarness.preparedURLs, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(controllerHarness.calls, [
    "refresh",
    "dispose-controller",
  ]);
});

for (const failure of [
  {
    name: "initial refresh",
    operation: "initial_refresh",
    lifecycle: {},
    controller: {
      refresh: async () => {
        throw new Error(`private ${LAUNCH_CODE}`);
      },
    },
  },
  {
    name: "launch preparation",
    operation: "prepare_launch",
    lifecycle: { initialURL: LAUNCH_URL },
    controller: {
      prepareLaunch: async () => {
        throw new Error(`private ${LAUNCH_URL}`);
      },
    },
  },
] as const) {
  test(`${failure.name} errors are bounded and never expose launch authority`, async () => {
    const errors: BackendManagedHostLifecycleError[] = [];
    const controllerHarness = createControllerHarness(failure.controller);
    const lifecycleHarness = createLifecycleHarness(failure.lifecycle);
    const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
      controllerHarness.controller,
      lifecycleHarness.primitives,
      {
        onError: (error) => {
          errors.push(error);
          throw new Error("observer failure must be isolated");
        },
      },
    );

    await assert.rejects(
      adapter.ready,
      (error: unknown) =>
        error instanceof BackendManagedHostLifecycleAdapterError &&
        error.operation === failure.operation &&
        !String(error).includes(LAUNCH_CODE),
    );
    assert.deepEqual(errors, [
      {
        operation: failure.operation,
        category: "host_lifecycle_rejected",
      },
    ]);
    assert.equal(Object.isFrozen(errors[0]), true);
    assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);

    if (failure.operation === "prepare_launch") {
      lifecycleHarness.emitURL(LAUNCH_URL);
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      assert.equal(controllerHarness.preparedURLs.length, 1);
    }
    adapter.dispose();
  });
}

test("initial URL lookup rejection is safely reported as a fallback miss", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    getInitialURL: async () => {
      throw new Error(`private ${LAUNCH_CODE}`);
    },
  });
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );

  await adapter.ready;
  assert.deepEqual(errors, [
    {
      operation: "get_initial_url",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  adapter.dispose();
});

test("listener installation failure cleans up and throws only a safe error", () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    subscribeAppState: () => {
      throw new Error(`subscription failure ${LAUNCH_CODE}`);
    },
  });
  const errors: BackendManagedHostLifecycleError[] = [];

  assert.throws(
    () =>
      createBackendManagedHostLifecycleAdapterForPrimitives(
        controllerHarness.controller,
        lifecycleHarness.primitives,
        { onError: (error) => errors.push(error) },
      ),
    (error: unknown) =>
      error instanceof BackendManagedHostLifecycleAdapterError &&
      error.operation === "install_listeners" &&
      !String(error).includes(LAUNCH_CODE),
  );
  assert.equal(controllerHarness.disposeCount(), 1);
  assert.equal(lifecycleHarness.pendingNativeLaunchRemovalCount(), 1);
  assert.equal(lifecycleHarness.incomingURLRemovalCount(), 1);
  assert.deepEqual(errors, [
    {
      operation: "install_listeners",
      category: "host_lifecycle_rejected",
    },
  ]);
});

test("callback-driven foreground errors are bounded and consumed", async () => {
  const errors: BackendManagedHostLifecycleError[] = [];
  const controllerHarness = createControllerHarness({
    notifyForeground: async () => {
      throw new Error(`private foreground failure ${LAUNCH_CODE}`);
    },
  });
  const lifecycleHarness = createLifecycleHarness();
  const adapter = createBackendManagedHostLifecycleAdapterForPrimitives(
    controllerHarness.controller,
    lifecycleHarness.primitives,
    { onError: (error) => errors.push(error) },
  );
  await adapter.ready;

  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  await waitFor(() => errors.length === 1);
  assert.deepEqual(errors, [
    {
      operation: "foreground_retry",
      category: "host_lifecycle_rejected",
    },
  ]);
  assert.equal(JSON.stringify(errors).includes(LAUNCH_CODE), false);
  adapter.dispose();
});
