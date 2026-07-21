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

  const eventMap: TacuaCapture.CaptureEventMap = {} as TacuaCapture.CaptureEventMap;
  const stateEvent: TacuaCapture.CaptureStatus = eventMap.onState;

  void queueSchemaVersion;
  void activeCapability;
  void startedCredentialAvailability;
  void receivingState;
  void captureStarted;
  void uploadsConnected;
  void completionConnected;
  void recoveryStateIsKnown;
  void nullableResume;
  void nullableTransportMatch;
  void nullableRecoveryCapability;
  void nullableCredentialAvailability;
  void recoveryFlags;
  void queueExists;
  void resumeRequired;
  void transportMatches;
  void stateEvent;
}
