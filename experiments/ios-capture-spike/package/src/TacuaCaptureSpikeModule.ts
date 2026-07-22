// SPDX-License-Identifier: Apache-2.0

import { requireNativeModule } from "expo";
import { type EventSubscription } from "expo-modules-core";

type CaptureCapabilities = {
  readonly platform: "ios";
  readonly api: "ReplayKit.startCapture";
  readonly available: boolean;
  /** True only when the native binary carries the complete fail-closed QA build profile. */
  readonly qaBuildEnabled: boolean;
  /** True only for the exact DEBUG-only repository acceptance harness. */
  readonly localHarnessRetentionBypassEnabled: boolean;
  readonly buildVariant: "development" | "preview" | null;
  readonly distribution: "local" | "internal" | "testflight" | null;
  readonly unavailableReason:
    | "replaykit_unavailable"
    | "capture_not_enabled"
    | "invalid_capture_flag"
    | "invalid_build_variant"
    | "invalid_distribution"
    | "unsupported_build_distribution"
    | "development_build_requires_debug"
    | "invalid_qa_build_configuration"
    | "inconsistent_qa_build_configuration"
    | "backend_origin_missing"
    | "backend_origin_invalid"
    | "backend_origin_insecure"
    | "loopback_requires_debug_build"
    | "launch_scheme_invalid"
    | "sdk_profile_missing"
    | "sdk_profile_invalid"
    | "sdk_profile_build_mismatch"
    | null;
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
  readonly schemaVersion: 4;
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
  /** Every AVAssetWriter app-audio append decision made by this logical run. */
  readonly appAudioAppendAttemptsObserved: number;
  readonly droppedAppAudioAppendAttempts: number;
  /** False after interruption/recovery because an uncommitted writer tail cannot be inferred. */
  readonly appAudioAppendAccountingComplete: boolean;
  /** Legacy schema-3 recovery reports 0; fresh schema-4 capture reports 1. */
  readonly appAudioAppendAccountingVersion: 0 | 1;
  /** Inclusive high-watermark durably reserved before an app-audio index is issued. */
  readonly appAudioAppendReservedThroughIndex: number;
  /** Crash-reserved ranges skipped on recovery; their prior append outcomes are unknowable. */
  readonly appAudioAppendUnknownRanges: readonly AppAudioAppendUnknownRange[];
  readonly diagnosticEventCount: number;
  readonly diagnosticContainsCollectionGap: boolean;
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
  /** Immutable server START deadline; RESUME never extends this value. */
  readonly rawMediaExpiresAt: string;
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
  /** Immutable stored deadline required to resume the same local capture. */
  readonly rawMediaExpiresAt?: string | null;
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

type DiagnosticEventReceipt = {
  /** Native-generated privacy-safe event identifier. */
  readonly eventId: string;
  /** Native journal sequence, starting at one. */
  readonly sequence: number;
  /** Monotonic uptime sampled by the native SDK, never caller supplied wall time. */
  readonly monotonicMilliseconds: number;
};

type DiagnosticRouteTrigger = "user" | "system" | "deep_link" | "unknown";

type DiagnosticInteractionAction =
  | "tap"
  | "long_press"
  | "text_input"
  | "swipe"
  | "submit"
  | "other";

type DiagnosticNetworkMethod =
  | "DELETE"
  | "GET"
  | "HEAD"
  | "OPTIONS"
  | "PATCH"
  | "POST"
  | "PUT";

type DiagnosticRouteTransitionOptions = {
  readonly fromRoute?: string | null;
  readonly toRoute: string;
  readonly trigger: DiagnosticRouteTrigger;
};

type DiagnosticUserInteractionOptions = {
  readonly action: DiagnosticInteractionAction;
  /** Stable component/test identifier. Never pass rendered text or a user-entered value. */
  readonly target: string;
};

type DiagnosticRuntimeErrorOptions = {
  readonly errorClass: string;
  /** A pre-sanitized, bounded message. Do not pass secrets or user content. */
  readonly sanitizedMessage: string;
  /** Content digest only; raw stack traces are outside the V1 privacy boundary. */
  readonly stackTraceDigest?: string | null;
  readonly handled: boolean;
};

type DiagnosticNetworkCompletionOptions = {
  readonly method: DiagnosticNetworkMethod;
  readonly host: string;
  /** A route template such as `/projects/{project_id}`, never a raw URL or query string. */
  readonly pathTemplate: string;
  readonly statusCode: number;
  readonly durationMilliseconds: number;
  readonly traceId?: string | null;
};

type DiagnosticCustomStateOptions =
  | {
      readonly providerId: string;
      readonly collectionStatus: "available";
      /** Content digest only; the SDK intentionally has no raw-state API. */
      readonly snapshotDigest: string;
    }
  | {
      readonly providerId: string;
      readonly collectionStatus: "unavailable";
      readonly snapshotDigest?: never;
    };

type CaptureSegmentEvent = {
  readonly index: number;
  readonly fileName: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly durationSeconds: number;
  readonly heldVideoSamples?: number;
  readonly appAudioAppendAttemptStartIndex: number | null;
  readonly appAudioAppendAttempts: number | null;
  readonly droppedAppAudioSamples: number;
  readonly appAudioAppendDrops: readonly AppAudioAppendDrop[];
};

type AppAudioAppendDropCause =
  | "sample_data_not_ready"
  | "writer_finished"
  | "writer_not_writing"
  | "timestamp_invalid"
  | "input_backpressure"
  | "append_rejected";

type AppAudioAppendDrop = {
  readonly attemptIndex: number;
  readonly cause: AppAudioAppendDropCause;
};

type AppAudioAppendUnknownRange = {
  readonly startIndex: number;
  readonly endIndex: number;
  readonly reason: "process_recovery_reservation";
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
  readonly sdkProfileContractVersion: "tacua.sdk-profile@1.0.0";
  readonly sdkProfileDigest: string;
  readonly queueSchemaVersion: 4;
  readonly credentialStorage: "ios_keychain_when_unlocked_this_device_only";
  readonly launchCodePersistence: "transient_only";
  readonly redirectPolicy: "reject_all";
  readonly launchURLTemplate: string;
};

type BackendLaunchConsentRequest = {
  readonly consentRequestId: string;
  readonly requiredConsentVersion: "tacua-local-capture-consent-v1";
  /** Exact remote RESUME target from the trusted reviewer link; null for START. */
  readonly expectedSessionId: string | null;
};

type ApprovedBackendLaunch = {
  readonly approvedLaunchId: string;
};

/** Primary START input. All protocol identity/scope/handoff fields are native-generated. */
type CreateCaptureSessionPlanOptions = {
  readonly approvedLaunchId: string;
  readonly segmentDurationSeconds: number;
};

/** Primary RESUME input. Build and scope are loaded from the durable native queue. */
type ResumeCaptureSessionPlanOptions = {
  readonly approvedLaunchId: string;
  readonly localSessionId: string;
  readonly segmentDurationSeconds: number;
};

type RecoverCaptureSessionPlanOptions = {
  readonly localSessionId: string;
  readonly segmentDurationSeconds: number;
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

type BackendResumeSessionOptions = {
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

type BackendResumeSessionNativeOptions = {
  readonly approvedLaunchId: string;
  readonly localSessionId: string;
  readonly buildIdentityJson: string;
  readonly scopeJson: string;
  readonly requestedAt: string;
};

type BackendAdmitFinalizedCaptureOptions = {
  readonly localSessionId: string;
  /** Required together only for a queue migrated from an SDK predating durable artifacts. */
  readonly buildIdentity?: BackendBuildIdentity;
  /** Required together only for a queue migrated from an SDK predating durable artifacts. */
  readonly scope?: BackendCaptureScope;
};

type BackendAdmitFinalizedCaptureNativeOptions = {
  readonly localSessionId: string;
  readonly buildIdentityJson?: string;
  readonly scopeJson?: string;
};

type BackendCaptureAdmission = {
  readonly localSessionId: string;
  readonly remoteSessionId: string;
  readonly admissionDigest: string;
  readonly diagnosticEnvelopeDigest: string;
  readonly segmentCount: number;
  readonly diagnosticCount: 1;
  readonly admittedOperationCount: number;
  readonly alreadyAdmitted: boolean;
  /** Admission is a durable local boundary; dispatch and completion remain explicit. */
  readonly uploadsConnected: false;
  readonly completionConnected: false;
};

type BackendProcessAdmittedCaptureOptions = {
  readonly localSessionId: string;
};

type BackendProcessedCapture = {
  readonly localSessionId: string;
  readonly remoteSessionId: string;
  readonly completionId: string;
  readonly segmentReceiptCount: number;
  readonly diagnosticReceiptCount: number;
  readonly payloadCleanupState: "payloads_removed";
  readonly alreadyCompleted: boolean;
  readonly uploadsConnected: true;
  readonly completionConnected: true;
};

type BackendDeleteSessionOptions = {
  readonly localSessionId: string;
};

/** Returned only after the authenticated backend tombstone and every local cleanup step are durable. */
type BackendDeletedSession = {
  readonly localSessionId: string;
  readonly deletionId: "deletion_user_requested_000001";
  readonly tombstoneDigest: string;
  readonly deletionReason: "user_requested";
  readonly alreadyDeleted: boolean;
  readonly remoteDataDeleted: true;
  readonly localSessionRetired: true;
  readonly credentialRemoved: true;
};

type BackendStartedSession = {
  readonly localSessionId: string;
  readonly remoteSessionId: string;
  readonly scopeDigest: string;
  readonly credentialId: string;
  readonly credentialExpiresAt: string;
  readonly rawMediaExpiresAt: string;
  readonly credentialCapability: "active";
  readonly credentialAvailability:
    | "available"
    | "missing"
    | "temporarily_unavailable"
    | "unavailable";
  readonly queueSchemaVersion: 4;
  readonly resumeRequired: boolean;
  readonly backendSessionState: "receiving";
  readonly captureStarted: false;
  readonly uploadsConnected: false;
  readonly completionConnected: false;
};

/** Returned only after the START receipt and durable queue commit have completed. */
type StartedCaptureSessionPlan = {
  /** Retained by the host before ReplayKit starts, so capture-start errors remain recoverable. */
  readonly localSessionId: string;
  readonly backendSession: BackendStartedSession;
  readonly captureOptions: CaptureStartOptions;
};

type BackendResumedSessionBase = {
  readonly localSessionId: string;
  readonly remoteSessionId: string;
  readonly scopeDigest: string;
  readonly credentialId: string;
  readonly credentialExpiresAt: string;
  readonly rawMediaExpiresAt: string;
  readonly credentialAvailability:
    | "available"
    | "missing"
    | "temporarily_unavailable"
    | "unavailable";
  readonly queueSchemaVersion: 4;
  readonly resumeRequired: boolean;
  readonly pendingRevokedCredentialRemovalCount: number;
  /** Resume rotates backend authority; it does not start or reconnect capture transport. */
  readonly captureStarted: false;
  readonly uploadsConnected: false;
  readonly completionConnected: false;
};

type BackendResumedReceivingSession = BackendResumedSessionBase & {
  readonly backendSessionState: "receiving";
  readonly credentialCapability: "active";
  readonly replayCompletionId: null;
};

type BackendResumedCompletedSession = BackendResumedSessionBase & {
  readonly backendSessionState: "completed";
  readonly credentialCapability: "completion_replay_or_delete_only";
  readonly replayCompletionId: string;
};

type BackendResumedSession =
  | BackendResumedReceivingSession
  | BackendResumedCompletedSession;

/** Returned only after RESUME credential rotation is durably committed. */
type ResumedCaptureSessionPlan =
  | {
      readonly localSessionId: string;
      readonly backendSession: BackendResumedReceivingSession;
      readonly captureOptions: CaptureStartOptions;
    }
  | {
      readonly localSessionId: string;
      readonly backendSession: BackendResumedCompletedSession;
      /** A completed session has replay/delete authority and must not restart ReplayKit. */
      readonly captureOptions: null;
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

type BackendResumeRecoveryStatus =
  | {
      readonly localSessionId: string;
      readonly state: "none";
      readonly remoteCredentialMayExist: false;
      readonly queueUsable: false;
      readonly canRecoverWithoutLaunch: false;
      readonly canResetPreparedCredential: false;
      readonly requiresReconciliation: false;
    }
  | {
      readonly localSessionId: string;
      readonly state:
        | "credential_prepared"
        | "credential_prepared_reset_pending";
      readonly remoteCredentialMayExist: false;
      readonly queueUsable: false;
      readonly canRecoverWithoutLaunch: false;
      readonly canResetPreparedCredential: true;
      readonly requiresReconciliation: false;
    }
  | {
      readonly localSessionId: string;
      readonly state: "exchange_outcome_unknown";
      /** The backend may have revoked the queued credential and accepted the candidate. */
      readonly remoteCredentialMayExist: true;
      /** The committed queue is quarantined until the exchange is reconciled. */
      readonly queueUsable: false;
      readonly canRecoverWithoutLaunch: false;
      /** Unknown network outcomes can never be cleared by a local reset. */
      readonly canResetPreparedCredential: false;
      readonly requiresReconciliation: true;
    }
  | {
      readonly localSessionId: string;
      readonly state: "receipt_validated_queue_commit_pending";
      readonly remoteCredentialMayExist: true;
      readonly queueUsable: false;
      readonly canRecoverWithoutLaunch: true;
      readonly canResetPreparedCredential: false;
      readonly requiresReconciliation: false;
    }
  | {
      readonly localSessionId: string;
      readonly state: "queue_committed";
      /** Whether this queue still names a remotely issued credential authority. */
      readonly remoteCredentialMayExist: boolean;
      /** True only when the committed credential/configuration/time checks permit transport. */
      readonly queueUsable: boolean;
      readonly canRecoverWithoutLaunch: false;
      readonly canResetPreparedCredential: false;
      readonly requiresReconciliation: false;
    }
  | {
      readonly localSessionId: string;
      readonly state: "queue_conflict_requires_reconciliation";
      readonly remoteCredentialMayExist: true;
      readonly queueUsable: false;
      readonly canRecoverWithoutLaunch: false;
      readonly canResetPreparedCredential: false;
      readonly requiresReconciliation: true;
    };

type BackendResumeRequirement =
  | {
      readonly kind: "none";
      readonly reason:
        | "ready"
        | "credential_temporarily_unavailable"
        | "credential_unavailable"
        | "terminal_deletion";
      readonly canConsumeApprovedLaunch: false;
      readonly expectedSessionState: null;
      readonly expectedCompletionId: null;
    }
  | ({
      readonly kind: "resume_session";
      readonly reason:
        | "credential_missing"
        | "credential_expired_or_clock_invalid"
        | "transport_binding_missing";
      readonly canConsumeApprovedLaunch: true;
    } & (
      | {
          readonly expectedSessionState: "receiving";
          readonly expectedCompletionId: null;
        }
      | {
          readonly expectedSessionState: "completed";
          readonly expectedCompletionId: string;
        }
    ))
  | {
      readonly kind: "blocked";
      readonly reason:
        | "transport_configuration_changed"
        | "no_remote_session"
        | "invalid_completion_binding"
        | "launch_recovery_required";
      readonly canConsumeApprovedLaunch: false;
      readonly expectedSessionState: null;
      readonly expectedCompletionId: null;
    };

type BackendQueueStatus = {
  readonly exists: boolean;
  readonly localSessionId: string;
  readonly remoteSessionId?: string | null;
  readonly scopeDigest?: string | null;
  readonly sessionArtifactsAvailable?: boolean;
  readonly currentCredentialId?: string | null;
  readonly currentCredentialExpiresAt?: string | null;
  /** Recorded backend authority; gate sends on this together with resumeRequirement. */
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
  readonly resumeRequirement?: BackendResumeRequirement;
  /** @deprecated Use `resumeRequirement.kind === "resume_session"`. */
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
  readonly schemaVersion?: 4;
};

/**
 * Crash-discovery snapshot for a native-generated START identifier. Presence flags are advisory;
 * reload queue/start-recovery status before choosing an action.
 */
type BackendSessionDiscoveryRecord = {
  readonly localSessionId: string;
  readonly hasCommittedQueue: boolean;
  readonly hasStartRecovery: boolean;
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
  listBackendSessions: () => Promise<readonly BackendSessionDiscoveryRecord[]>;
  prepareBackendLaunch: (launchURL: string) => BackendLaunchConsentRequest;
  confirmBackendLaunchConsent: (
    consentRequestId: string,
    granted: boolean,
  ) => ApprovedBackendLaunch;
  cancelBackendLaunch: (requestId: string) => void;
  createCaptureSessionPlan: (
    options: CreateCaptureSessionPlanOptions,
  ) => Promise<StartedCaptureSessionPlan>;
  resumeCaptureSessionPlan: (
    options: ResumeCaptureSessionPlanOptions,
  ) => Promise<ResumedCaptureSessionPlan>;
  recoverStartedCaptureSessionPlan: (
    options: RecoverCaptureSessionPlanOptions,
  ) => Promise<StartedCaptureSessionPlan>;
  recoverResumedCaptureSessionPlan: (
    options: RecoverCaptureSessionPlanOptions,
  ) => Promise<ResumedCaptureSessionPlan>;
  /** Advanced migration/testing surface; normal hosts use createCaptureSessionPlan. */
  startBackendSession: (
    options: BackendStartSessionNativeOptions,
  ) => Promise<BackendStartedSession>;
  resumeBackendSession: (
    options: BackendResumeSessionNativeOptions,
  ) => Promise<BackendResumedSession>;
  admitFinalizedCapture: (
    options: BackendAdmitFinalizedCaptureNativeOptions,
  ) => Promise<BackendCaptureAdmission>;
  processAdmittedCapture: (
    options: BackendProcessAdmittedCaptureOptions,
  ) => Promise<BackendProcessedCapture>;
  deleteBackendSession: (
    options: BackendDeleteSessionOptions,
  ) => Promise<BackendDeletedSession>;
  getBackendResumeRecoveryStatus: (
    localSessionId: string,
  ) => Promise<BackendResumeRecoveryStatus>;
  recoverBackendResume: (
    localSessionId: string,
  ) => Promise<BackendResumedSession>;
  resetPreparedBackendResume: (localSessionId: string) => Promise<void>;
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
  recordRouteTransition: (
    options: DiagnosticRouteTransitionOptions,
  ) => Promise<DiagnosticEventReceipt>;
  recordUserInteraction: (
    options: DiagnosticUserInteractionOptions,
  ) => Promise<DiagnosticEventReceipt>;
  recordRuntimeError: (
    options: DiagnosticRuntimeErrorOptions,
  ) => Promise<DiagnosticEventReceipt>;
  recordNetworkRequestCompleted: (
    options: DiagnosticNetworkCompletionOptions,
  ) => Promise<DiagnosticEventReceipt>;
  recordCustomState: (
    options: DiagnosticCustomStateOptions,
  ) => Promise<DiagnosticEventReceipt>;
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
  BackendAdmitFinalizedCaptureOptions,
  BackendBuildIdentity,
  BackendCaptureAdmission,
  BackendCaptureScope,
  BackendDeletedSession,
  BackendDeleteSessionOptions,
  BackendLaunchConsentRequest,
  BackendQueueStatus,
  BackendSessionDiscoveryRecord,
  BackendProcessAdmittedCaptureOptions,
  BackendProcessedCapture,
  BackendResumedSession,
  BackendResumeRecoveryStatus,
  BackendResumeRequirement,
  BackendResumeSessionOptions,
  BackendStartedSession,
  BackendStartRecoveryStatus,
  BackendStartSessionOptions,
  BackendTransportConfiguration,
  AppAudioAppendDrop,
  AppAudioAppendDropCause,
  AppAudioAppendUnknownRange,
  CaptureCapabilities,
  CaptureErrorEvent,
  CaptureEventMap,
  CaptureGapEvent,
  CaptureMarker,
  CaptureRecoveryOptions,
  CaptureSegmentEvent,
  CaptureStartOptions,
  CaptureStatus,
  CreateCaptureSessionPlanOptions,
  DiagnosticCustomStateOptions,
  DiagnosticEventReceipt,
  DiagnosticInteractionAction,
  DiagnosticNetworkCompletionOptions,
  DiagnosticNetworkMethod,
  DiagnosticRouteTransitionOptions,
  DiagnosticRouteTrigger,
  DiagnosticRuntimeErrorOptions,
  DiagnosticUserInteractionOptions,
  RecoverableSession,
  RecoverCaptureSessionPlanOptions,
  ResumedCaptureSessionPlan,
  ResumeCaptureSessionPlanOptions,
  StartedCaptureSessionPlan,
};

export const TacuaCaptureSpikeModule =
  requireNativeModule<NativeTacuaCaptureSpikeModule>("TacuaCaptureSpikeModule");
