// SPDX-License-Identifier: Apache-2.0

import * as TacuaCapture from "@tacua/ios-capture-spike";

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
  const queueSchemaVersion: 3 = transport.queueSchemaVersion;

  const pending: TacuaCapture.BackendLaunchConsentRequest =
    TacuaCapture.prepareBackendLaunch(
      "tacua-fixture://tacua/start?launch_code=opaque",
    );
  const approved: TacuaCapture.ApprovedBackendLaunch =
    TacuaCapture.confirmBackendLaunchConsent(pending.consentRequestId, true);
  TacuaCapture.cancelBackendLaunch(approved.approvedLaunchId);

  const started: TacuaCapture.BackendStartedSession =
    await TacuaCapture.startBackendSession(startOptions);
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

  const resumed: TacuaCapture.BackendResumedSession =
    await TacuaCapture.resumeBackendSession(resumeOptions);
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
  await TacuaCapture.abandonBackendStart(recovered.localSessionId, true);

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

  const eventMap: TacuaCapture.CaptureEventMap = {} as TacuaCapture.CaptureEventMap;
  const stateEvent: TacuaCapture.CaptureStatus = eventMap.onState;

  void queueSchemaVersion;
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
  void resumeOptionsCannotChooseSessionState;
  void resumeOptionsCannotChooseCredential;
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
  void stateEvent;
}
