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

type CaptureEventMap = {
  onState: CaptureStatus;
  onSegment: CaptureSegmentEvent;
  onGap: CaptureGapEvent;
  onMarker: CaptureMarker;
  onError: CaptureErrorEvent;
};

type NativeTacuaCaptureSpikeModule = {
  getCapabilities: () => CaptureCapabilities;
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
