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
  readonly queueSchemaVersion: 2;
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

type BackendQueueStatus = {
  readonly exists: boolean;
  readonly localSessionId: string;
  readonly remoteSessionId?: string | null;
  readonly scopeDigest?: string | null;
  readonly currentCredentialId?: string | null;
  readonly currentCredentialExpiresAt?: string | null;
  readonly credentialCapability?:
    | "requires_exchange"
    | "active"
    | "completion_replay_or_delete_only"
    | "deletion_replay_only";
  readonly credentialTimeValid?: boolean;
  readonly resumeRequired?: boolean;
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
  readonly schemaVersion?: 2;
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
  BackendLaunchConsentRequest,
  BackendQueueStatus,
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
