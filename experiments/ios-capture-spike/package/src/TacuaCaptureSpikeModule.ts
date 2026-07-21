// SPDX-License-Identifier: Apache-2.0

import { requireNativeModule } from "expo";
import { type EventSubscription } from "expo-modules-core";

type CaptureCapabilities = {
  readonly platform: "ios";
  readonly api: "ReplayKit.startCapture";
  readonly available: boolean;
  readonly microphoneSupported: boolean;
  readonly microphonePermission:
    | "granted"
    | "denied"
    | "undetermined"
    | "unknown";
  readonly designPointDurationSeconds: number;
  readonly maximumDurationSeconds: number;
  readonly startWatchdogSeconds: number;
  readonly stopWatchdogSeconds: number;
  readonly writerFinalizationWatchdogSeconds: number;
  readonly microphoneStartupWatchdogSeconds: number;
  readonly requiredConsentVersion: "tacua-local-capture-consent-v1";
  readonly handoffTrust: "structural_only";
  readonly schemaVersion: number;
  readonly testFaultInjectionCompiled?: true;
  readonly testFaultPlan?: string | null;
  readonly testFaultLeaseConsumed?: boolean;
};

type CaptureStatus = {
  readonly sessionId?: string;
  readonly state: string;
  readonly segmentCount: number;
  readonly gapCount: number;
  readonly markerCount: number;
  readonly errorCodes: readonly string[];
  readonly latestMediaPTSSeconds?: number | null;
  readonly recorderAvailable: boolean;
  readonly recorderRecording: boolean;
  readonly maximumDurationSeconds: number;
  readonly automaticStopHostUptimeSeconds: number | null;
  readonly stopReason: string | null;
  readonly microphoneSamplesObserved: number;
  readonly appAudioSamplesObserved: number;
  readonly appAudioAvailable: boolean;
  readonly testFaultPlan?: string | null;
};

type CaptureStartOptions = {
  readonly sessionId: string;
  readonly segmentDurationSeconds: number;
  readonly organizationId: string;
  readonly projectId: string;
  readonly buildId: string;
  readonly handoffId: string;
  readonly handoffTokenIdentifier?: string;
  readonly expiresAt: string;
  readonly consentVersion: "tacua-local-capture-consent-v1";
  readonly expectedApplicationId: string;
  readonly expectedBuildNumber: string;
};

type CaptureRecoveryOptions = Omit<
  CaptureStartOptions,
  "segmentDurationSeconds"
>;

type RecoverableSession = {
  readonly sessionId: string;
  readonly state: string;
  readonly segmentCount: number;
  readonly gapCount?: number;
  readonly partialFileCount: number;
  readonly recoveredSegmentCount?: number;
  readonly createdAt?: string;
  readonly resumeCount?: number;
};

type CaptureMarker = {
  readonly id: string;
  readonly label: string;
  readonly hostUptimeSeconds: number;
  readonly latestMediaPTSSeconds?: number | null;
};

type CaptureSegmentEvent = {
  readonly index: number;
  readonly fileName: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly durationSeconds: number;
  readonly heldVideoSamples?: number;
};

type CaptureGapEvent = {
  readonly id: string;
  readonly reason: string;
  readonly openedHostUptimeSeconds?: number;
  readonly closedHostUptimeSeconds?: number | null;
};

type CaptureErrorEvent = {
  readonly code: string;
  readonly reason: string;
};

type BackendTransportConfiguration = {
  readonly backendOrigin: string;
  readonly transportConfigurationDigest: string;
  readonly transportPolicyVersion: "tacua.sdk-transport@1.0.0";
  readonly protocolVersion: "tacua.sdk-backend@1.0.0";
  readonly queueSchemaVersion: 3;
  readonly credentialStorage: "ios_keychain_when_unlocked_this_device_only";
  readonly launchCodePersistence: "transient_only";
  readonly redirectPolicy: "reject_all";
  readonly launchURLTemplate: string;
};

type BackendLaunchConsentRequest = {
  readonly consentRequestId: string;
  readonly requiredConsentVersion: "tacua-local-capture-consent-v1";
};

type ApprovedBackendLaunch = {
  readonly approvedLaunchId: string;
};

type BackendBuildIdentity = {
  readonly protocol_version: "tacua.sdk-backend@1.0.0";
  readonly message_type: "build_identity";
  readonly build_id: string;
  readonly platform: "ios";
  readonly bundle_identifier: string;
  readonly native_version: string;
  readonly native_build: string;
  readonly build_variant: "development" | "preview";
  readonly distribution: "local" | "internal" | "testflight";
  readonly react_native_version: string;
  readonly transport_configuration_digest: string;
  readonly expo: {
    readonly sdk_version: string;
    readonly runtime_version: string;
    readonly update_id: string | null;
    readonly update_channel: string | null;
  } | null;
  readonly source: {
    readonly git_revision: string;
    readonly working_tree_dirty: boolean;
  };
  readonly created_at: string;
  readonly build_identity_digest: string;
};

type BackendCaptureScope = {
  readonly protocol_version: "tacua.sdk-backend@1.0.0";
  readonly message_type: "capture_scope";
  readonly organization_id: string;
  readonly project_id: string;
  readonly application_id: string;
  readonly build_id: string;
  readonly build_identity_digest: string;
  readonly capture_scope: "app_only";
  readonly consent: {
    readonly policy_version: string;
    readonly screen_recording: "granted";
    readonly microphone: "granted";
    readonly diagnostics: "granted";
    readonly raw_media_upload: "granted";
    readonly granted_at: string;
  };
  readonly retention: {
    readonly policy_version: string;
    readonly raw_media_days: number;
    readonly derived_data_days: number;
  };
  readonly scope_digest: string;
};

type BackendStartSessionOptions = {
  readonly approvedLaunchId: string;
  readonly localSessionId: string;
  readonly buildIdentity: BackendBuildIdentity;
  readonly scope: BackendCaptureScope;
  readonly requestedAt: string;
};

type BackendStartSessionNativeOptions = {
  readonly approvedLaunchId: string;
  readonly localSessionId: string;
  readonly buildIdentityJson: string;
  readonly scopeJson: string;
  readonly requestedAt: string;
};

type BackendStartedSession = {
  readonly localSessionId: string;
  readonly remoteSessionId: string;
  readonly scopeDigest: string;
  readonly credentialId: string;
  readonly credentialExpiresAt: string;
  readonly credentialCapability: "active";
  readonly credentialAvailability:
    | "available"
    | "missing"
    | "temporarily_unavailable"
    | "unavailable";
  readonly queueSchemaVersion: 3;
  readonly resumeRequired: boolean;
  readonly backendSessionState: "receiving";
  readonly captureStarted: false;
  readonly uploadsConnected: false;
  readonly completionConnected: false;
};

type BackendStartRecoveryStatus = {
  readonly localSessionId: string;
  readonly state:
    | "none"
    | "credential_prepared"
    | "exchange_outcome_unknown"
    | "receipt_validated_queue_commit_pending"
    | "credential_prepared_reset_pending"
    | "exchange_outcome_unknown_reset_pending"
    | "queue_committed";
  readonly requiresFreshReviewerLaunch: boolean;
  readonly remoteSessionMayExist: boolean;
  readonly canRecoverWithoutLaunch: boolean;
  readonly canAbandonLocally: boolean;
  readonly resumeRequired: boolean | null;
  readonly transportConfigurationMatchesBuild: boolean | null;
  /** Recorded backend authority, not standalone proof that transport is currently usable. */
  readonly credentialCapability:
    | "requires_exchange"
    | "requires_transport_rebind"
    | "active"
    | "completion_replay_or_delete_only"
    | "deletion_replay_only"
    | null;
  readonly credentialAvailability:
    | "available"
    | "missing"
    | "temporarily_unavailable"
    | "unavailable"
    | "not_applicable"
    | null;
};

type BackendQueueStatus = {
  readonly exists: boolean;
  readonly localSessionId: string;
  readonly remoteSessionId?: string | null;
  readonly scopeDigest?: string | null;
  readonly currentCredentialId?: string | null;
  readonly currentCredentialExpiresAt?: string | null;
  /** Recorded backend authority; gate sends on this together with resumeRequired. */
  readonly credentialCapability?:
    | "requires_exchange"
    | "requires_transport_rebind"
    | "active"
    | "completion_replay_or_delete_only"
    | "deletion_replay_only";
  readonly credentialAvailability?:
    | "available"
    | "missing"
    | "temporarily_unavailable"
    | "unavailable"
    | "not_applicable";
  readonly credentialTimeValid?: boolean;
  readonly resumeRequired?: boolean;
  readonly transportConfigurationMatchesBuild?: boolean;
  readonly operationCount?: number;
  readonly queuedOperationCount?: number;
  readonly storedResponseCount?: number;
  readonly boundLocalPayloadCount?: number;
  readonly legacyUnboundPayloadCount?: number;
  readonly pendingRevokedCredentialRemovalCount?: number;
  readonly payloadCleanupState?: "none" | "tombstone_written" | "payloads_removed";
  readonly credentialCleanupState?: "none" | "tombstone_written" | "credential_removed";
  readonly completionCleanupAuthorized?: boolean;
  readonly deletionCleanupAuthorized?: boolean;
  readonly schemaVersion?: 3;
};

type CaptureEventMap = {
  onState: CaptureStatus;
  onSegment: CaptureSegmentEvent;
  onGap: CaptureGapEvent;
  onMarker: CaptureMarker;
  onError: CaptureErrorEvent;
};

type NativeTacuaCaptureSpikeModule = {
  getCapabilities: () => CaptureCapabilities;
  getBackendTransportConfiguration: () => BackendTransportConfiguration;
  getBackendQueueStatus: (localSessionId: string) => Promise<BackendQueueStatus>;
  prepareBackendLaunch: (launchURL: string) => BackendLaunchConsentRequest;
  confirmBackendLaunchConsent: (
    consentRequestId: string,
    granted: boolean,
  ) => ApprovedBackendLaunch;
  cancelBackendLaunch: (requestId: string) => void;
  startBackendSession: (
    options: BackendStartSessionNativeOptions,
  ) => Promise<BackendStartedSession>;
  getBackendStartRecoveryStatus: (
    localSessionId: string,
  ) => Promise<BackendStartRecoveryStatus>;
  recoverBackendStart: (
    localSessionId: string,
  ) => Promise<BackendStartedSession>;
  abandonBackendStart: (
    localSessionId: string,
    acknowledgeRemoteSessionMayExist: boolean,
  ) => Promise<void>;
  getStatus: () => CaptureStatus;
  start: (options: CaptureStartOptions) => Promise<CaptureStatus>;
  resume: (options: CaptureStartOptions) => Promise<CaptureStatus>;
  stop: () => Promise<CaptureStatus>;
  mark: (label: string) => Promise<CaptureMarker>;
  listRecoverableSessions: () => Promise<readonly RecoverableSession[]>;
  markPartialReadyForUpload: (
    options: CaptureRecoveryOptions,
  ) => Promise<RecoverableSession>;
  deleteSession: (options: CaptureRecoveryOptions) => Promise<void>;
  addListener: <K extends keyof CaptureEventMap>(
    eventName: K,
    listener: (event: CaptureEventMap[K]) => void,
  ) => EventSubscription;
};

export type {
  ApprovedBackendLaunch,
  BackendBuildIdentity,
  BackendCaptureScope,
  BackendLaunchConsentRequest,
  BackendQueueStatus,
  BackendStartedSession,
  BackendStartRecoveryStatus,
  BackendStartSessionOptions,
  BackendTransportConfiguration,
  CaptureCapabilities,
  CaptureErrorEvent,
  CaptureEventMap,
  CaptureGapEvent,
  CaptureMarker,
  CaptureRecoveryOptions,
  CaptureSegmentEvent,
  CaptureStartOptions,
  CaptureStatus,
  RecoverableSession,
};

export const TacuaCaptureSpikeModule =
  requireNativeModule<NativeTacuaCaptureSpikeModule>("TacuaCaptureSpikeModule");
