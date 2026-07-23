// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  BackendManagedHostControllerError,
  createBackendManagedHostControllerForPrimitives,
  type BackendManagedHostPrimitives,
} from "../src/BackendManagedHostController.ts";
import type {
  BackendQueueStatus,
  BackendResumeRecoveryStatus,
  BackendStartRecoveryStatus,
  CaptureStartOptions,
  CaptureStatus,
  RecoverableSession,
  ResumedCaptureSessionPlan,
  StartedCaptureSessionPlan,
} from "../src/TacuaCaptureSpikeModule.ts";

const LOCAL_SESSION_ID = "local_controller_001";
const REMOTE_SESSION_ID = "session_controller_001";
const LAUNCH_CODE = "a".repeat(32);

function captureOptions(
  localSessionId = LOCAL_SESSION_ID,
): CaptureStartOptions {
  return {
    sessionId: localSessionId,
    segmentDurationSeconds: 10,
    organizationId: "org_controller",
    projectId: "project_controller",
    buildId: "build_controller",
    handoffId: REMOTE_SESSION_ID,
    handoffTokenIdentifier: "credential_controller",
    expiresAt: "2099-07-23T12:00:00Z",
    rawMediaExpiresAt: "2099-08-23T12:00:00Z",
    consentVersion: "tacua-local-capture-consent-v1",
    expectedApplicationId: "com.example.controller",
    expectedBuildNumber: "1",
  };
}

function captureStatus(
  state: string,
  recording: boolean,
  localSessionId: string | undefined = recording
    ? LOCAL_SESSION_ID
    : undefined,
  segmentCount = 0,
): CaptureStatus {
  return {
    sessionId: localSessionId,
    state,
    segmentCount,
    gapCount: 0,
    markerCount: 0,
    errorCodes: [],
    recorderAvailable: true,
    recorderRecording: recording,
    maximumDurationSeconds: 1_800,
    automaticStopHostUptimeSeconds: null,
    stopReason: null,
    microphoneSamplesObserved: recording ? 1 : 0,
    appAudioSamplesObserved: 0,
    appAudioAvailable: true,
    appAudioAppendAttemptsObserved: 0,
    droppedAppAudioAppendAttempts: 0,
    appAudioAppendAccountingComplete: true,
    appAudioAppendAccountingVersion: 1,
    appAudioAppendReservedThroughIndex: 0,
    appAudioAppendUnknownRanges: [],
    diagnosticEventCount: 0,
    diagnosticContainsCollectionGap: false,
  };
}

function readyQueue(
  localSessionId = LOCAL_SESSION_ID,
  remoteSessionId = REMOTE_SESSION_ID,
  operationCount = 0,
): BackendQueueStatus {
  return {
    exists: true,
    localSessionId,
    remoteSessionId,
    credentialCapability: "active",
    credentialAvailability: "available",
    operationCount,
    resumeRequirement: {
      kind: "none",
      reason: "ready",
      canConsumeApprovedLaunch: false,
      expectedSessionState: null,
      expectedCompletionId: null,
    },
  };
}

function resumeQueue(
  localSessionId = LOCAL_SESSION_ID,
  remoteSessionId = REMOTE_SESSION_ID,
): BackendQueueStatus {
  return {
    ...readyQueue(localSessionId, remoteSessionId),
    credentialAvailability: "missing",
    resumeRequirement: {
      kind: "resume_session",
      reason: "credential_missing",
      canConsumeApprovedLaunch: true,
      expectedSessionState: "receiving",
      expectedCompletionId: null,
    },
  };
}

function noStartRecovery(
  localSessionId = LOCAL_SESSION_ID,
): BackendStartRecoveryStatus {
  return {
    localSessionId,
    state: "queue_committed",
    requiresFreshReviewerLaunch: false,
    remoteSessionMayExist: true,
    canRecoverWithoutLaunch: false,
    canAbandonLocally: false,
    resumeRequired: false,
    transportConfigurationMatchesBuild: true,
    credentialCapability: "active",
    credentialAvailability: "available",
  };
}

function noResumeRecovery(
  localSessionId = LOCAL_SESSION_ID,
): BackendResumeRecoveryStatus {
  return {
    localSessionId,
    state: "queue_committed",
    remoteCredentialMayExist: true,
    queueUsable: true,
    canRecoverWithoutLaunch: false,
    canResetPreparedCredential: false,
    requiresReconciliation: false,
  };
}

function startedPlan(
  localSessionId = LOCAL_SESSION_ID,
): StartedCaptureSessionPlan {
  const options = captureOptions(localSessionId);
  return {
    localSessionId,
    captureOptions: options,
    backendSession: {
      localSessionId,
      remoteSessionId: REMOTE_SESSION_ID,
    } as StartedCaptureSessionPlan["backendSession"],
  };
}

function resumedPlan(
  localSessionId = LOCAL_SESSION_ID,
): ResumedCaptureSessionPlan {
  return {
    localSessionId,
    captureOptions: captureOptions(localSessionId),
    backendSession: {
      localSessionId,
      remoteSessionId: REMOTE_SESSION_ID,
      backendSessionState: "receiving",
    } as ResumedCaptureSessionPlan["backendSession"],
  };
}

type TestHarness = ReturnType<typeof createHarness>;

function createHarness() {
  const calls: string[] = [];
  const queues = new Map<string, BackendQueueStatus>();
  const startRecovery = new Map<string, BackendStartRecoveryStatus>();
  const resumeRecovery = new Map<string, BackendResumeRecoveryStatus>();
  let recoverable: RecoverableSession[] = [];
  let status = captureStatus("idle", false);
  let preparedExpectedSessionId: string | null = null;
  let processFailureCount = 0;
  let deleteCount = 0;

  const sdk: BackendManagedHostPrimitives = {
    prepareBackendLaunch: () => {
      calls.push("prepare");
      return {
        consentRequestId: "consent_controller",
        requiredConsentVersion: "tacua-local-capture-consent-v1",
        expectedSessionId: preparedExpectedSessionId,
      };
    },
    confirmBackendLaunchConsent: (requestId, granted) => {
      calls.push(`confirm:${requestId}:${String(granted)}`);
      return { approvedLaunchId: "approved_controller" };
    },
    cancelBackendLaunch: (requestId) => {
      calls.push(`cancel:${requestId}`);
    },
    createCaptureSessionPlan: async () => {
      calls.push("create-plan");
      return startedPlan();
    },
    resumeCaptureSessionPlan: async ({ localSessionId }) => {
      calls.push(`resume-plan:${localSessionId}`);
      return resumedPlan(localSessionId);
    },
    recoverStartedCaptureSessionPlan: async ({ localSessionId }) => {
      calls.push(`recover-start:${localSessionId}`);
      return startedPlan(localSessionId);
    },
    recoverResumedCaptureSessionPlan: async ({ localSessionId }) => {
      calls.push(`recover-resume:${localSessionId}`);
      return resumedPlan(localSessionId);
    },
    listBackendSessions: async () => {
      calls.push("list-backend");
      return [...queues].map(([localSessionId, queue]) => ({
        localSessionId,
        hasCommittedQueue: queue.exists,
        hasStartRecovery: false,
      }));
    },
    getBackendQueueStatus: async (localSessionId) => {
      calls.push(`queue:${localSessionId}`);
      return queues.get(localSessionId) ?? {
        exists: false,
        localSessionId,
      };
    },
    getBackendStartRecoveryStatus: async (localSessionId) => {
      calls.push(`start-recovery:${localSessionId}`);
      return startRecovery.get(localSessionId) ?? noStartRecovery(localSessionId);
    },
    getBackendResumeRecoveryStatus: async (localSessionId) => {
      calls.push(`resume-recovery:${localSessionId}`);
      return (
        resumeRecovery.get(localSessionId) ?? noResumeRecovery(localSessionId)
      );
    },
    abandonBackendStart: async (localSessionId, acknowledged) => {
      calls.push(`abandon-start:${localSessionId}:${String(acknowledged)}`);
    },
    resetPreparedBackendResume: async (localSessionId) => {
      calls.push(`reset-resume:${localSessionId}`);
    },
    getStatus: () => status,
    listRecoverableSessions: async () => {
      calls.push("list-recoverable");
      return recoverable;
    },
    start: async (options) => {
      calls.push(`start:${options.sessionId}`);
      status = captureStatus("recording", true, options.sessionId);
      return status;
    },
    resume: async (options) => {
      calls.push(`resume:${options.sessionId}`);
      status = captureStatus("recording", true, options.sessionId, 2);
      return status;
    },
    stop: async () => {
      calls.push("stop");
      status = captureStatus("completed", false, LOCAL_SESSION_ID, 2);
      recoverable = [
        {
          sessionId: LOCAL_SESSION_ID,
          state: "completed",
          segmentCount: 2,
          partialFileCount: 0,
        },
      ];
      return status;
    },
    markPartialReadyForUpload: async (options) => {
      calls.push(`keep-partial:${options.sessionId}`);
      const kept: RecoverableSession = {
        sessionId: options.sessionId,
        state: "partial_ready_for_upload",
        segmentCount: 2,
        partialFileCount: 0,
      };
      recoverable = [kept];
      return kept;
    },
    admitFinalizedCapture: async (localSessionId) => {
      calls.push(`admit:${localSessionId}`);
      queues.set(localSessionId, readyQueue(localSessionId, REMOTE_SESSION_ID, 3));
      return {
        localSessionId,
        remoteSessionId: REMOTE_SESSION_ID,
      } as Awaited<ReturnType<BackendManagedHostPrimitives["admitFinalizedCapture"]>>;
    },
    processAdmittedCapture: async ({ localSessionId }) => {
      calls.push(`process:${localSessionId}`);
      if (processFailureCount > 0) {
        processFailureCount -= 1;
        throw Object.assign(new Error("private transport detail"), {
          code: "ERR_TACUA_TEST_RETRY",
        });
      }
      return {
        localSessionId,
        remoteSessionId: REMOTE_SESSION_ID,
        payloadCleanupState: "payloads_removed",
        uploadsConnected: true,
        completionConnected: true,
      } as Awaited<ReturnType<BackendManagedHostPrimitives["processAdmittedCapture"]>>;
    },
    deleteBackendSession: async ({ localSessionId }) => {
      calls.push(`delete:${localSessionId}`);
      deleteCount += 1;
      return {
        localSessionId,
        remoteDataDeleted: true,
        localSessionRetired: true,
        credentialRemoved: true,
      } as Awaited<ReturnType<BackendManagedHostPrimitives["deleteBackendSession"]>>;
    },
  };

  return {
    sdk,
    calls,
    queues,
    startRecovery,
    resumeRecovery,
    setRecoverable(value: readonly RecoverableSession[]) {
      recoverable = [...value];
    },
    setPreparedExpectedSessionId(value: string | null) {
      preparedExpectedSessionId = value;
    },
    failProcessing(attempts: number) {
      processFailureCount = attempts;
    },
    deleteCount: () => deleteCount,
  };
}

async function approveAndExchangeStart(harness: TestHarness) {
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );
  await controller.prepareLaunch(
    `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`,
  );
  await controller.respondToLaunchConsent(true);
  await controller.exchangeApprovedLaunch();
  return controller;
}

test("START keeps launch authority native and exposes a bounded plan workflow", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );
  const launchURL = `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`;

  await controller.prepareLaunch(launchURL);
  const consent = controller.getSnapshot();
  assert.equal(consent.phase.kind, "awaiting_launch_consent");
  assert.equal(Object.isFrozen(consent), true);
  assert.equal(Object.isFrozen(consent.actions), true);
  assert.equal(JSON.stringify(consent).includes(LAUNCH_CODE), false);
  assert.equal(JSON.stringify(consent).includes("consent_controller"), false);

  await controller.respondToLaunchConsent(true);
  assert.equal(controller.getSnapshot().phase.kind, "launch_approved");
  assert.equal(
    JSON.stringify(controller.getSnapshot()).includes("approved_controller"),
    false,
  );

  await controller.exchangeApprovedLaunch();
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "plan_ready",
    localSessionId: LOCAL_SESSION_ID,
    source: "start",
    nextAction: "start_capture",
    recoverableState: null,
    verifiedSegmentCount: 0,
  });

  await controller.startPlannedCapture();
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "capturing",
    localSessionId: LOCAL_SESSION_ID,
    mode: "started",
  });
  assert.deepEqual(
    harness.calls.filter((call) =>
      ["prepare", "create-plan", `start:${LOCAL_SESSION_ID}`].includes(call),
    ),
    ["prepare", "create-plan", `start:${LOCAL_SESSION_ID}`],
  );
});

test("a failed consent confirmation clears volatile state and permits a fresh link", async () => {
  const harness = createHarness();
  const sdk: BackendManagedHostPrimitives = {
    ...harness.sdk,
    confirmBackendLaunchConsent: () => {
      throw Object.assign(new Error("private consent failure"), {
        code: "PRIVATE_SECRET_VALUE",
      });
    },
  };
  const controller = createBackendManagedHostControllerForPrimitives(sdk);
  const link = `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`;

  await controller.prepareLaunch(link);
  await assert.rejects(controller.respondToLaunchConsent(true));
  assert.deepEqual(controller.getSnapshot().phase, { kind: "idle" });
  assert.equal(controller.getSnapshot().lastError?.nativeCode, null);
  assert.equal(harness.calls.includes("cancel:consent_controller"), true);

  await controller.prepareLaunch(link);
  assert.equal(
    controller.getSnapshot().phase.kind,
    "awaiting_launch_consent",
  );
});

test("an unknown launch exchange is one-shot and enters reconciliation", async () => {
  const harness = createHarness();
  const sdk: BackendManagedHostPrimitives = {
    ...harness.sdk,
    createCaptureSessionPlan: async () => {
      throw Object.assign(new Error("private exchange outcome"), {
        code: "ERR_TACUA_TEST_EXCHANGE_UNKNOWN",
      });
    },
  };
  const controller = createBackendManagedHostControllerForPrimitives(sdk);

  await controller.prepareLaunch(
    `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`,
  );
  await controller.respondToLaunchConsent(true);
  await assert.rejects(controller.exchangeApprovedLaunch());
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "blocked",
    reason: "operator_reconciliation_required",
    localSessionId: null,
  });
  assert.equal(
    controller.getSnapshot().lastError?.nativeCode,
    "ERR_TACUA_TEST_EXCHANGE_UNKNOWN",
  );
  assert.equal(harness.calls.includes("cancel:approved_controller"), true);
  await assert.rejects(
    controller.exchangeApprovedLaunch(),
    (error: unknown) =>
      error instanceof BackendManagedHostControllerError &&
      error.category === "invalid_state",
  );
});

test("a thrown start outcome still exposes a recording session that can be stopped", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  const sdk: BackendManagedHostPrimitives = {
    ...harness.sdk,
    start: async (options) => {
      await harness.sdk.start(options);
      throw new Error("bridge reply lost after native start");
    },
  };
  const controller = createBackendManagedHostControllerForPrimitives(sdk);
  await controller.prepareLaunch(
    `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`,
  );
  await controller.respondToLaunchConsent(true);
  await controller.exchangeApprovedLaunch();

  await assert.rejects(controller.startPlannedCapture());
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "capturing",
    localSessionId: LOCAL_SESSION_ID,
    mode: "started",
  });
  assert.equal(controller.getSnapshot().recorder.recording, true);
  assert.equal(
    controller.getSnapshot().actions.some(
      (action) => action.kind === "stop_capture",
    ),
    true,
  );
});

test("mutations are serialized across asynchronous native discovery", async () => {
  const harness = createHarness();
  let releaseDiscovery: (() => void) | null = null;
  const originalList = harness.sdk.listBackendSessions;
  const sdk: BackendManagedHostPrimitives = {
    ...harness.sdk,
    listBackendSessions: async () => {
      harness.calls.push("discovery-enter");
      await new Promise<void>((resolve) => {
        releaseDiscovery = resolve;
      });
      return originalList();
    },
  };
  const controller = createBackendManagedHostControllerForPrimitives(sdk);

  const refresh = controller.refresh();
  const prepare = controller.prepareLaunch(
    `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`,
  );
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(harness.calls.includes("prepare"), false);
  assert.notEqual(releaseDiscovery, null);
  releaseDiscovery?.();
  await Promise.all([refresh, prepare]);
  assert.equal(harness.calls.includes("prepare"), true);
});

test("RESUME refuses an ambiguous remote-session match before consent", async () => {
  const harness = createHarness();
  harness.setPreparedExpectedSessionId(REMOTE_SESSION_ID);
  harness.queues.set("local_controller_a", readyQueue("local_controller_a"));
  harness.queues.set("local_controller_b", readyQueue("local_controller_b"));
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );

  await assert.rejects(
    controller.prepareLaunch(
      `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}&session_id=${REMOTE_SESSION_ID}`,
    ),
    (error: unknown) =>
      error instanceof BackendManagedHostControllerError &&
      error.category === "ambiguous_resume_target",
  );
  assert.equal(
    harness.calls.includes("cancel:consent_controller"),
    true,
  );
  assert.equal(controller.getSnapshot().phase.kind, "idle");
  assert.equal(
    controller.getSnapshot().lastError?.category,
    "ambiguous_resume_target",
  );
});

test("RESUME can keep a verified partial, admit it, and drain native transport", async () => {
  const harness = createHarness();
  harness.setPreparedExpectedSessionId(REMOTE_SESSION_ID);
  harness.queues.set(LOCAL_SESSION_ID, resumeQueue());
  harness.setRecoverable([
    {
      sessionId: LOCAL_SESSION_ID,
      state: "recoverable_partial",
      segmentCount: 2,
      partialFileCount: 0,
    },
  ]);
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );

  await controller.prepareLaunch(
    `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}&session_id=${REMOTE_SESSION_ID}`,
  );
  await controller.respondToLaunchConsent(true);
  await controller.exchangeApprovedLaunch();
  assert.equal(
    controller.getSnapshot().phase.kind === "plan_ready"
      ? controller.getSnapshot().phase.nextAction
      : null,
    "resume_capture",
  );

  // Simulate the committed rotation making the queue usable before local finalization.
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  await controller.keepVerifiedPartial();
  assert.equal(controller.getSnapshot().phase.kind, "stopped");
  await controller.admitAndDrain();
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "complete",
    localSessionId: LOCAL_SESSION_ID,
    result: "uploaded",
  });
  assert.deepEqual(
    harness.calls.filter((call) =>
      call.startsWith("keep-partial:") ||
      call.startsWith("admit:") ||
      call.startsWith("process:"),
    ),
    [
      `keep-partial:${LOCAL_SESSION_ID}`,
      `admit:${LOCAL_SESSION_ID}`,
      `process:${LOCAL_SESSION_ID}`,
    ],
  );
});

test("foreground notification retries only a durably admitted native drain", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  const controller = await approveAndExchangeStart(harness);
  await controller.startPlannedCapture();
  await controller.stopCapture();
  harness.failProcessing(1);

  await assert.rejects(controller.admitAndDrain());
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "upload_retry",
    localSessionId: LOCAL_SESSION_ID,
  });
  assert.deepEqual(controller.getSnapshot().lastError, {
    operation: "admit_and_drain",
    category: "native_rejected",
    nativeCode: "ERR_TACUA_TEST_RETRY",
  });

  await controller.notifyForeground();
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "complete",
    localSessionId: LOCAL_SESSION_ID,
    result: "uploaded",
  });
  assert.equal(
    harness.calls.filter((call) => call === `admit:${LOCAL_SESSION_ID}`).length,
    1,
  );
  assert.equal(
    harness.calls.filter((call) => call === `process:${LOCAL_SESSION_ID}`).length,
    2,
  );
});

test("foreground notification discovers admitted work after controller relaunch", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue(LOCAL_SESSION_ID, REMOTE_SESSION_ID, 3));
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );

  await controller.notifyForeground();
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "complete",
    localSessionId: LOCAL_SESSION_ID,
    result: "uploaded",
  });
  assert.equal(harness.calls.includes(`admit:${LOCAL_SESSION_ID}`), false);
  assert.equal(harness.calls.includes(`process:${LOCAL_SESSION_ID}`), true);
});

test("a stopped verified partial remains explicit before admission", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  const partialStop = captureStatus(
    "recoverable_partial",
    false,
    LOCAL_SESSION_ID,
    2,
  );
  const sdk: BackendManagedHostPrimitives = {
    ...harness.sdk,
    stop: async () => partialStop,
  };
  const controller = createBackendManagedHostControllerForPrimitives(sdk);
  await controller.prepareLaunch(
    `tacua-test://tacua/start?launch_code=${LAUNCH_CODE}`,
  );
  await controller.respondToLaunchConsent(true);
  await controller.exchangeApprovedLaunch();
  await controller.startPlannedCapture();
  await controller.stopCapture();

  const actionKinds = controller
    .getSnapshot()
    .actions.map((action) => action.kind);
  assert.equal(actionKinds.includes("keep_verified_partial"), true);
  assert.equal(actionKinds.includes("admit_and_drain"), false);
  await controller.keepVerifiedPartial();
  assert.equal(
    controller.getSnapshot().phase.kind === "stopped"
      ? controller.getSnapshot().phase.captureState
      : null,
    "partial_ready_for_upload",
  );
});

test("authenticated reset requires an explicit second confirmation", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );

  await assert.rejects(controller.confirmAuthenticatedReset());
  await controller.requestAuthenticatedReset(LOCAL_SESSION_ID);
  assert.equal(harness.deleteCount(), 0);
  assert.equal(
    controller.getSnapshot().phase.kind,
    "awaiting_authenticated_reset_confirmation",
  );
  await controller.cancelAuthenticatedReset();
  assert.equal(harness.deleteCount(), 0);

  await controller.requestAuthenticatedReset(LOCAL_SESSION_ID);
  await controller.confirmAuthenticatedReset();
  assert.equal(harness.deleteCount(), 1);
  assert.deepEqual(controller.getSnapshot().phase, {
    kind: "complete",
    localSessionId: LOCAL_SESSION_ID,
    result: "reset",
  });
});

test("recovery actions distinguish recoverable receipts from unknown outcomes", async () => {
  const harness = createHarness();
  harness.queues.set(LOCAL_SESSION_ID, readyQueue());
  harness.startRecovery.set(LOCAL_SESSION_ID, {
    ...noStartRecovery(),
    state: "receipt_validated_queue_commit_pending",
    canRecoverWithoutLaunch: true,
  });
  harness.resumeRecovery.set(LOCAL_SESSION_ID, {
    localSessionId: LOCAL_SESSION_ID,
    state: "exchange_outcome_unknown",
    remoteCredentialMayExist: true,
    queueUsable: false,
    canRecoverWithoutLaunch: false,
    canResetPreparedCredential: false,
    requiresReconciliation: true,
  });
  const controller = createBackendManagedHostControllerForPrimitives(
    harness.sdk,
  );

  await controller.refresh();
  const actionKinds = controller
    .getSnapshot()
    .sessions[0]?.actions.map((action) => action.kind);
  assert.equal(actionKinds?.includes("recover_start_plan"), true);
  assert.equal(
    actionKinds?.includes("operator_reconciliation_required"),
    true,
  );
  await assert.rejects(
    controller.resetPreparedResume(LOCAL_SESSION_ID),
    (error: unknown) =>
      error instanceof BackendManagedHostControllerError &&
      error.category === "reconciliation_required",
  );
});

test("validated START and RESUME receipt journals restore native capture plans", async () => {
  const startHarness = createHarness();
  startHarness.startRecovery.set(LOCAL_SESSION_ID, {
    ...noStartRecovery(),
    state: "receipt_validated_queue_commit_pending",
    canRecoverWithoutLaunch: true,
  });
  const startController = createBackendManagedHostControllerForPrimitives(
    startHarness.sdk,
  );
  await startController.recoverStartPlan(LOCAL_SESSION_ID);
  assert.deepEqual(startController.getSnapshot().phase, {
    kind: "plan_ready",
    localSessionId: LOCAL_SESSION_ID,
    source: "recovered_start",
    nextAction: "start_capture",
    recoverableState: null,
    verifiedSegmentCount: 0,
  });

  const resumeHarness = createHarness();
  resumeHarness.resumeRecovery.set(LOCAL_SESSION_ID, {
    localSessionId: LOCAL_SESSION_ID,
    state: "receipt_validated_queue_commit_pending",
    remoteCredentialMayExist: true,
    queueUsable: false,
    canRecoverWithoutLaunch: true,
    canResetPreparedCredential: false,
    requiresReconciliation: false,
  });
  resumeHarness.setRecoverable([
    {
      sessionId: LOCAL_SESSION_ID,
      state: "recoverable_partial",
      segmentCount: 1,
      partialFileCount: 0,
    },
  ]);
  const resumeController = createBackendManagedHostControllerForPrimitives(
    resumeHarness.sdk,
  );
  await resumeController.recoverResumePlan(LOCAL_SESSION_ID);
  assert.deepEqual(resumeController.getSnapshot().phase, {
    kind: "plan_ready",
    localSessionId: LOCAL_SESSION_ID,
    source: "recovered_resume",
    nextAction: "resume_capture",
    recoverableState: "recoverable_partial",
    verifiedSegmentCount: 1,
  });
});
