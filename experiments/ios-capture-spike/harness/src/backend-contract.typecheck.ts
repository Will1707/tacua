// SPDX-License-Identifier: Apache-2.0

import * as TacuaCapture from "@tacua/mobile-sdk";

const buildIdentity: TacuaCapture.BackendBuildIdentity = {
  protocol_version: "tacua.sdk-backend@1.0.0",
  message_type: "build_identity",
  build_id: "build_fixture",
  platform: "ios",
  bundle_identifier: "org.example.tacua",
  native_version: "1.0.0",
  native_build: "1",
  build_variant: "development",
  distribution: "local",
  react_native_version: "0.85.3",
  transport_configuration_digest: `sha256:${"a".repeat(64)}`,
  expo: {
    sdk_version: "56.0.0",
    runtime_version: "1.0.0",
    update_id: null,
    update_channel: null,
  },
  source: {
    git_revision: "abcdef0",
    working_tree_dirty: false,
  },
  created_at: "2026-07-21T09:57:00Z",
  build_identity_digest: `sha256:${"b".repeat(64)}`,
};

const scope: TacuaCapture.BackendCaptureScope = {
  protocol_version: "tacua.sdk-backend@1.0.0",
  message_type: "capture_scope",
  organization_id: "org_fixture",
  project_id: "project_fixture",
  application_id: "application_fixture",
  build_id: buildIdentity.build_id,
  build_identity_digest: buildIdentity.build_identity_digest,
  capture_scope: "app_only",
  consent: {
    policy_version: "tacua-local-capture-consent-v1",
    screen_recording: "granted",
    microphone: "granted",
    diagnostics: "granted",
    raw_media_upload: "granted",
    granted_at: "2026-07-21T09:56:00Z",
  },
  retention: {
    policy_version: "tacua-retention-v1",
    raw_media_days: 30,
    derived_data_days: 90,
  },
  scope_digest: `sha256:${"c".repeat(64)}`,
};

const startOptions: TacuaCapture.BackendStartSessionOptions = {
  approvedLaunchId: "approved_fixture",
  localSessionId: "local_fixture",
  buildIdentity,
  scope,
  requestedAt: "2026-07-21T09:57:00Z",
};

const resumeOptions: TacuaCapture.BackendResumeSessionOptions = {
  approvedLaunchId: "approved_resume_fixture",
  localSessionId: "local_fixture",
  buildIdentity,
  scope,
  requestedAt: "2026-07-21T10:57:00Z",
};

const createPlanOptions: TacuaCapture.CreateCaptureSessionPlanOptions = {
  approvedLaunchId: "approved_fixture",
  segmentDurationSeconds: 10,
};

const createPlanCannotChooseIdentity: TacuaCapture.CreateCaptureSessionPlanOptions =
  {
    ...createPlanOptions,
    // @ts-expect-error Build identity is generated and validated by native code.
    buildIdentity,
  };

const resumePlanOptions: TacuaCapture.ResumeCaptureSessionPlanOptions = {
  approvedLaunchId: "approved_resume_fixture",
  localSessionId: "local_fixture",
  segmentDurationSeconds: 10,
};

const resumePlanCannotChooseScope: TacuaCapture.ResumeCaptureSessionPlanOptions =
  {
    ...resumePlanOptions,
    // @ts-expect-error Scope is loaded from the durable native queue.
    scope,
  };

const resumeOptionsCannotChooseSessionState: TacuaCapture.BackendResumeSessionOptions =
  {
    ...resumeOptions,
    // @ts-expect-error RESUME state is derived from the committed queue, not host input.
    expectedSessionState: "receiving",
  };

const resumeOptionsCannotChooseCredential: TacuaCapture.BackendResumeSessionOptions =
  {
    ...resumeOptions,
    // @ts-expect-error The previous credential is derived from the committed queue.
    previousCredentialId: "credential_host_must_not_choose",
  };

const deletionOptionsCannotChooseReason: TacuaCapture.BackendDeleteSessionOptions =
  {
    localSessionId: "local_fixture",
    // @ts-expect-error V1 deletion is always the fixed user_requested operation.
    deletionReason: "operator_requested",
  };

const resumeRecoveryStates: Record<
  TacuaCapture.BackendResumeRecoveryStatus["state"],
  true
> = {
  none: true,
  credential_prepared: true,
  credential_prepared_reset_pending: true,
  exchange_outcome_unknown: true,
  receipt_validated_queue_commit_pending: true,
  queue_conflict_requires_reconciliation: true,
  queue_committed: true,
};

const noResumeReasons: Record<
  Extract<
    TacuaCapture.BackendResumeRequirement,
    { readonly kind: "none" }
  >["reason"],
  true
> = {
  ready: true,
  credential_temporarily_unavailable: true,
  credential_unavailable: true,
  terminal_deletion: true,
};

const resumableReasons: Record<
  Extract<
    TacuaCapture.BackendResumeRequirement,
    { readonly kind: "resume_session" }
  >["reason"],
  true
> = {
  credential_missing: true,
  credential_expired_or_clock_invalid: true,
  transport_binding_missing: true,
};

const blockedResumeReasons: Record<
  Extract<
    TacuaCapture.BackendResumeRequirement,
    { readonly kind: "blocked" }
  >["reason"],
  true
> = {
  transport_configuration_changed: true,
  no_remote_session: true,
  invalid_completion_binding: true,
  launch_recovery_required: true,
};

const recoveryStates: Record<
  TacuaCapture.BackendStartRecoveryStatus["state"],
  true
> = {
  none: true,
  credential_prepared: true,
  exchange_outcome_unknown: true,
  receipt_validated_queue_commit_pending: true,
  credential_prepared_reset_pending: true,
  exchange_outcome_unknown_reset_pending: true,
  queue_committed: true,
};

export async function typecheckBackendContract(): Promise<void> {
  const transport: TacuaCapture.BackendTransportConfiguration =
    TacuaCapture.getBackendTransportConfiguration();
  const queueSchemaVersion: 4 = transport.queueSchemaVersion;
  const sdkProfileContractVersion: "tacua.sdk-profile@1.0.0" =
    transport.sdkProfileContractVersion;
  const sdkProfileDigest: string = transport.sdkProfileDigest;
  const discovered: readonly TacuaCapture.BackendSessionDiscoveryRecord[] =
    await TacuaCapture.listBackendSessions();
  for (const record of discovered) {
    const discoveredQueue: TacuaCapture.BackendQueueStatus =
      await TacuaCapture.getBackendQueueStatus(record.localSessionId);
    const discoveredStartRecovery: TacuaCapture.BackendStartRecoveryStatus =
      await TacuaCapture.getBackendStartRecoveryStatus(record.localSessionId);
    void discoveredQueue;
    void discoveredStartRecovery;
  }

  const pending: TacuaCapture.BackendLaunchConsentRequest =
    TacuaCapture.prepareBackendLaunch(
      "tacua-fixture://tacua/start?launch_code=opaque",
    );
  const expectedLaunchSession: string | null = pending.expectedSessionId;
  void expectedLaunchSession;
  const approved: TacuaCapture.ApprovedBackendLaunch =
    TacuaCapture.confirmBackendLaunchConsent(pending.consentRequestId, true);
  TacuaCapture.cancelBackendLaunch(approved.approvedLaunchId);

  const startedPlan: TacuaCapture.StartedCaptureSessionPlan =
    await TacuaCapture.createCaptureSessionPlan(createPlanOptions);
  const started: TacuaCapture.BackendStartedSession =
    startedPlan.backendSession;
  const generatedStartOptions: TacuaCapture.CaptureStartOptions =
    startedPlan.captureOptions;
  const surfacedLocalSessionId: string = startedPlan.localSessionId;
  const activeCapability: "active" = started.credentialCapability;
  const startedCredentialAvailability:
    | Exclude<
        NonNullable<TacuaCapture.BackendQueueStatus["credentialAvailability"]>,
        "not_applicable"
      > = started.credentialAvailability;
  const receivingState: "receiving" = started.backendSessionState;
  const captureStarted: false = started.captureStarted;
  const uploadsConnected: false = started.uploadsConnected;
  const completionConnected: false = started.completionConnected;

  const resumedPlan: TacuaCapture.ResumedCaptureSessionPlan =
    await TacuaCapture.resumeCaptureSessionPlan(resumePlanOptions);
  const resumed: TacuaCapture.BackendResumedSession =
    resumedPlan.backendSession;
  const resumedCredentialAvailability:
    | Exclude<
        NonNullable<TacuaCapture.BackendQueueStatus["credentialAvailability"]>,
        "not_applicable"
      > = resumed.credentialAvailability;
  const pendingRevokedCredentialRemovalCount: number =
    resumed.pendingRevokedCredentialRemovalCount;
  const resumedCaptureStarted: false = resumed.captureStarted;
  const resumedUploadsConnected: false = resumed.uploadsConnected;
  const resumedCompletionConnected: false = resumed.completionConnected;
  switch (resumed.backendSessionState) {
    case "receiving": {
      const capability: "active" = resumed.credentialCapability;
      const replayCompletionId: null = resumed.replayCompletionId;
      void capability;
      void replayCompletionId;
      break;
    }
    case "completed": {
      const capability: "completion_replay_or_delete_only" =
        resumed.credentialCapability;
      const replayCompletionId: string = resumed.replayCompletionId;
      void capability;
      void replayCompletionId;
      break;
    }
    default: {
      const exhaustive: never = resumed;
      void exhaustive;
    }
  }

  if (resumedPlan.captureOptions === null) {
    // Completed RESUME authority deliberately cannot restart ReplayKit.
    return;
  }
  const generatedResumeOptions: TacuaCapture.CaptureStartOptions =
    resumedPlan.captureOptions;

  const resumeRecovery: TacuaCapture.BackendResumeRecoveryStatus =
    await TacuaCapture.getBackendResumeRecoveryStatus(resumed.localSessionId);
  const resumeRecoveryStateIsKnown: true =
    resumeRecoveryStates[resumeRecovery.state];
  if (resumeRecovery.state === "exchange_outcome_unknown") {
    const remoteCredentialMayExist: true =
      resumeRecovery.remoteCredentialMayExist;
    const queueUsable: false = resumeRecovery.queueUsable;
    const canRecoverWithoutLaunch: false =
      resumeRecovery.canRecoverWithoutLaunch;
    const canResetPreparedCredential: false =
      resumeRecovery.canResetPreparedCredential;
    const requiresReconciliation: true =
      resumeRecovery.requiresReconciliation;
    void remoteCredentialMayExist;
    void queueUsable;
    void canRecoverWithoutLaunch;
    void canResetPreparedCredential;
    void requiresReconciliation;
  }
  if (resumeRecovery.state === "queue_conflict_requires_reconciliation") {
    const queueUsable: false = resumeRecovery.queueUsable;
    const canRecoverWithoutLaunch: false =
      resumeRecovery.canRecoverWithoutLaunch;
    const requiresReconciliation: true =
      resumeRecovery.requiresReconciliation;
    void queueUsable;
    void canRecoverWithoutLaunch;
    void requiresReconciliation;
  }
  const recoveredResume: TacuaCapture.BackendResumedSession =
    await TacuaCapture.recoverBackendResume(resumed.localSessionId);
  const recoveredResumePlan: TacuaCapture.ResumedCaptureSessionPlan =
    await TacuaCapture.recoverResumedCaptureSessionPlan({
      localSessionId: resumed.localSessionId,
      segmentDurationSeconds: generatedResumeOptions.segmentDurationSeconds,
    });
  await TacuaCapture.resetPreparedBackendResume(resumed.localSessionId);

  const recovery: TacuaCapture.BackendStartRecoveryStatus =
    await TacuaCapture.getBackendStartRecoveryStatus(started.localSessionId);
  const recoveryStateIsKnown: true = recoveryStates[recovery.state];
  const nullableResume: boolean | null = recovery.resumeRequired;
  const nullableTransportMatch: boolean | null =
    recovery.transportConfigurationMatchesBuild;
  const nullableRecoveryCapability:
    | NonNullable<TacuaCapture.BackendQueueStatus["credentialCapability"]>
    | null = recovery.credentialCapability;
  const nullableCredentialAvailability:
    | NonNullable<TacuaCapture.BackendQueueStatus["credentialAvailability"]>
    | null = recovery.credentialAvailability;
  const recoveryFlags: readonly boolean[] = [
    recovery.requiresFreshReviewerLaunch,
    recovery.remoteSessionMayExist,
    recovery.canRecoverWithoutLaunch,
    recovery.canAbandonLocally,
  ];

  const recovered: TacuaCapture.BackendStartedSession =
    await TacuaCapture.recoverBackendStart(started.localSessionId);
  const recoveredStartPlan: TacuaCapture.StartedCaptureSessionPlan =
    await TacuaCapture.recoverStartedCaptureSessionPlan({
      localSessionId: started.localSessionId,
      segmentDurationSeconds: generatedStartOptions.segmentDurationSeconds,
    });
  await TacuaCapture.abandonBackendStart(recovered.localSessionId, true);

  // Explicitly named advanced surfaces remain available only for legacy migration tooling.
  const advancedStarted: TacuaCapture.BackendStartedSession =
    await TacuaCapture.advancedStartBackendSession(startOptions);
  const advancedResumed: TacuaCapture.BackendResumedSession =
    await TacuaCapture.advancedResumeBackendSession(resumeOptions);

  const queue: TacuaCapture.BackendQueueStatus =
    await TacuaCapture.getBackendQueueStatus(started.localSessionId);
  const queueExists: boolean = queue.exists;
  const resumeRequired: boolean | undefined = queue.resumeRequired;
  const transportMatches: boolean | undefined =
    queue.transportConfigurationMatchesBuild;
  const resumeRequirement: TacuaCapture.BackendResumeRequirement | undefined =
    queue.resumeRequirement;
  if (resumeRequirement) {
    switch (resumeRequirement.kind) {
      case "none": {
        const cannotConsume: false = resumeRequirement.canConsumeApprovedLaunch;
        const expectedState: null = resumeRequirement.expectedSessionState;
        const expectedCompletionId: null =
          resumeRequirement.expectedCompletionId;
        const reasonIsKnown: true = noResumeReasons[resumeRequirement.reason];
        void cannotConsume;
        void expectedState;
        void expectedCompletionId;
        void reasonIsKnown;
        break;
      }
      case "resume_session": {
        const canConsume: true = resumeRequirement.canConsumeApprovedLaunch;
        const reasonIsKnown: true = resumableReasons[resumeRequirement.reason];
        if (resumeRequirement.expectedSessionState === "receiving") {
          const expectedCompletionId: null =
            resumeRequirement.expectedCompletionId;
          void expectedCompletionId;
        } else {
          const expectedState: "completed" =
            resumeRequirement.expectedSessionState;
          const expectedCompletionId: string =
            resumeRequirement.expectedCompletionId;
          void expectedState;
          void expectedCompletionId;
        }
        void canConsume;
        void reasonIsKnown;
        break;
      }
      case "blocked": {
        const cannotConsume: false = resumeRequirement.canConsumeApprovedLaunch;
        const expectedState: null = resumeRequirement.expectedSessionState;
        const expectedCompletionId: null =
          resumeRequirement.expectedCompletionId;
        const reasonIsKnown: true =
          blockedResumeReasons[resumeRequirement.reason];
        void cannotConsume;
        void expectedState;
        void expectedCompletionId;
        void reasonIsKnown;
        break;
      }
      default: {
        const exhaustive: never = resumeRequirement;
        void exhaustive;
      }
    }
  }

  const admission: TacuaCapture.BackendCaptureAdmission =
    await TacuaCapture.admitFinalizedCapture(started.localSessionId);
  const migratedAdmission: TacuaCapture.BackendCaptureAdmission =
    await TacuaCapture.advancedAdmitFinalizedCapture({
      localSessionId: started.localSessionId,
      buildIdentity,
      scope,
    });

  const deleted: TacuaCapture.BackendDeletedSession =
    await TacuaCapture.deleteBackendSession({
      localSessionId: started.localSessionId,
    });
  const deletionId: "deletion_user_requested_000001" = deleted.deletionId;
  const deletionReason: "user_requested" = deleted.deletionReason;
  const remoteDataDeleted: true = deleted.remoteDataDeleted;
  const localSessionRetired: true = deleted.localSessionRetired;
  const credentialRemoved: true = deleted.credentialRemoved;

  const eventMap: TacuaCapture.CaptureEventMap = {} as TacuaCapture.CaptureEventMap;
  const stateEvent: TacuaCapture.CaptureStatus = eventMap.onState;
  const diagnosticEventCount: number = stateEvent.diagnosticEventCount;
  const diagnosticContainsCollectionGap: boolean =
    stateEvent.diagnosticContainsCollectionGap;
  const routeReceipt: TacuaCapture.DiagnosticEventReceipt =
    await TacuaCapture.recordRouteTransition({
      fromRoute: "/projects/{project_id}",
      toRoute: "/projects/{project_id}/review",
      trigger: "user",
    });
  const interactionReceipt: TacuaCapture.DiagnosticEventReceipt =
    await TacuaCapture.recordUserInteraction({
      action: "tap",
      target: "review_submit",
    });
  const runtimeReceipt: TacuaCapture.DiagnosticEventReceipt =
    await TacuaCapture.recordRuntimeError({
      errorClass: "ui_render",
      sanitizedMessage: "The review view could not render.",
      stackTraceDigest: `sha256:${"d".repeat(64)}`,
      handled: true,
    });
  const networkReceipt: TacuaCapture.DiagnosticEventReceipt =
    await TacuaCapture.recordNetworkRequestCompleted({
      method: "POST",
      host: "api.example.test",
      pathTemplate: "/reviews/{review_id}",
      statusCode: 503,
      durationMilliseconds: 250,
      traceId: "e".repeat(32),
    });
  const customReceipt: TacuaCapture.DiagnosticEventReceipt =
    await TacuaCapture.recordCustomState({
      providerId: "navigation_snapshot",
      collectionStatus: "available",
      snapshotDigest: `sha256:${"f".repeat(64)}`,
    });
  await TacuaCapture.recordCustomState({
    providerId: "navigation_snapshot",
    collectionStatus: "unavailable",
  });
  // @ts-expect-error Available custom state must truthfully provide a digest.
  const invalidAvailableCustomState: TacuaCapture.DiagnosticCustomStateOptions = {
    providerId: "navigation_snapshot",
    collectionStatus: "available",
    snapshotDigest: undefined,
  };

  void queueSchemaVersion;
  void sdkProfileContractVersion;
  void sdkProfileDigest;
  void activeCapability;
  void startedCredentialAvailability;
  void receivingState;
  void captureStarted;
  void uploadsConnected;
  void completionConnected;
  void resumedCredentialAvailability;
  void pendingRevokedCredentialRemovalCount;
  void resumedCaptureStarted;
  void resumedUploadsConnected;
  void resumedCompletionConnected;
  void resumeRecoveryStateIsKnown;
  void recoveredResume;
  void recoveredResumePlan;
  void recoveredStartPlan;
  void advancedStarted;
  void advancedResumed;
  void createPlanCannotChooseIdentity;
  void resumePlanCannotChooseScope;
  void generatedStartOptions;
  void generatedResumeOptions;
  void surfacedLocalSessionId;
  void resumeOptionsCannotChooseSessionState;
  void resumeOptionsCannotChooseCredential;
  void deletionOptionsCannotChooseReason;
  void recoveryStateIsKnown;
  void nullableResume;
  void nullableTransportMatch;
  void nullableRecoveryCapability;
  void nullableCredentialAvailability;
  void recoveryFlags;
  void queueExists;
  void resumeRequired;
  void transportMatches;
  void resumeRequirement;
  void admission;
  void migratedAdmission;
  void deletionId;
  void deletionReason;
  void remoteDataDeleted;
  void localSessionRetired;
  void credentialRemoved;
  void stateEvent;
  void diagnosticEventCount;
  void diagnosticContainsCollectionGap;
  void routeReceipt;
  void interactionReceipt;
  void runtimeReceipt;
  void networkReceipt;
  void customReceipt;
  void invalidAvailableCustomState;
}
