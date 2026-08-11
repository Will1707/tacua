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

type ControllerHarnessOptions = Readonly<{
  refresh?: () => Promise<void>;
  prepareLaunch?: (url: string) => Promise<void>;
  notifyForeground?: () => Promise<void>;
  dispose?: () => void;
}>;

function createControllerHarness(options: ControllerHarnessOptions = {}) {
  const calls: string[] = [];
  const preparedURLs: string[] = [];
  let disposeCount = 0;
  const emptySnapshot = Object.freeze({}) as BackendManagedHostSnapshot;
  const noOp = async () => undefined;

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
      calls.push("dispose-controller");
      disposeCount += 1;
      options.dispose?.();
    },
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
  currentState?: BackendManagedHostAppState;
  emitURLWhileSubscribing?: string;
  getInitialURL?: () => Promise<string | null>;
  subscribeAppState?: (
    listener: (state: BackendManagedHostAppState) => void,
  ) => () => void;
}>;

function createLifecycleHarness(options: LifecycleHarnessOptions = {}) {
  const calls: string[] = [];
  const incomingURLListeners = new Set<(url: string) => void>();
  const appStateListeners = new Set<
    (state: BackendManagedHostAppState) => void
  >();
  let incomingURLRemovalCount = 0;
  let appStateRemovalCount = 0;

  const primitives: BackendManagedHostLifecyclePrimitives = {
    getInitialURL: async () => {
      calls.push("get-initial-url");
      if (options.getInitialURL) return options.getInitialURL();
      return options.initialURL ?? null;
    },
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
      };
    },
  };

  return {
    primitives,
    calls,
    emitURL(url: string) {
      for (const listener of incomingURLListeners) listener(url);
    },
    emitAppState(state: BackendManagedHostAppState) {
      for (const listener of appStateListeners) listener(state);
    },
    incomingURLListenerCount: () => incomingURLListeners.size,
    appStateListenerCount: () => appStateListeners.size,
    incomingURLRemovalCount: () => incomingURLRemovalCount,
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
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 1);
  assert.equal(lifecycleHarness.appStateListenerCount(), 1);

  await adapter.ready;
  assert.deepEqual(trace, ["refresh", "get-initial-url", "prepare-launch"]);
  assert.equal(adapter.controller, controllerHarness.controller);
  assert.deepEqual(controllerHarness.preparedURLs, [LAUNCH_URL]);
  assert.equal(JSON.stringify(adapter).includes(LAUNCH_CODE), false);

  adapter.dispose();
});

test("startup and event duplicates cause one exact launch delivery", async () => {
  const controllerHarness = createControllerHarness();
  const lifecycleHarness = createLifecycleHarness({
    initialURL: LAUNCH_URL,
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
  adapter.dispose();
  adapter.dispose();
  await adapter.ready;
  lifecycleHarness.emitURL(`${LAUNCH_URL}-after-dispose`);
  lifecycleHarness.emitAppState("background");
  lifecycleHarness.emitAppState("active");
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  assert.deepEqual(controllerHarness.calls, ["dispose-controller"]);
  assert.equal(controllerHarness.disposeCount(), 1);
  assert.equal(lifecycleHarness.incomingURLRemovalCount(), 1);
  assert.equal(lifecycleHarness.appStateRemovalCount(), 1);
  assert.equal(lifecycleHarness.incomingURLListenerCount(), 0);
  assert.equal(lifecycleHarness.appStateListenerCount(), 0);
});

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
    name: "initial URL lookup",
    operation: "get_initial_url",
    lifecycle: {
      getInitialURL: async () => {
        throw new Error(`private ${LAUNCH_CODE}`);
      },
    },
    controller: {},
  },
  {
    name: "launch delivery",
    operation: "deliver_launch_url",
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

    if (failure.operation === "deliver_launch_url") {
      lifecycleHarness.emitURL(LAUNCH_URL);
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      assert.equal(controllerHarness.preparedURLs.length, 1);
    }
    adapter.dispose();
  });
}

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
