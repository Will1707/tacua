// SPDX-License-Identifier: Apache-2.0

import {
  TacuaCaptureSpikeModule,
  type ApprovedBackendLaunch,
  type BackendLaunchConsentRequest,
  type BackendQueueStatus,
  type BackendTransportConfiguration,
  type CaptureCapabilities,
  type CaptureErrorEvent,
  type CaptureEventMap,
  type CaptureGapEvent,
  type CaptureMarker,
  type CaptureRecoveryOptions,
  type CaptureSegmentEvent,
  type CaptureStartOptions,
  type CaptureStatus,
  type RecoverableSession,
} from "./TacuaCaptureSpikeModule";
import { type EventSubscription } from "expo-modules-core";

export type {
  ApprovedBackendLaunch,
  BackendLaunchConsentRequest,
  BackendQueueStatus,
  BackendTransportConfiguration,
  CaptureCapabilities,
  CaptureErrorEvent,
  CaptureGapEvent,
  CaptureMarker,
  CaptureRecoveryOptions,
  CaptureSegmentEvent,
  CaptureStartOptions,
  CaptureStatus,
  RecoverableSession,
};

export function getCapabilities(): CaptureCapabilities {
  return TacuaCaptureSpikeModule.getCapabilities();
}

export function getBackendTransportConfiguration(): BackendTransportConfiguration {
  return TacuaCaptureSpikeModule.getBackendTransportConfiguration();
}

export function getBackendQueueStatus(
  localSessionId: string,
): Promise<BackendQueueStatus> {
  return TacuaCaptureSpikeModule.getBackendQueueStatus(localSessionId);
}

export function prepareBackendLaunch(
  launchURL: string,
): BackendLaunchConsentRequest {
  return TacuaCaptureSpikeModule.prepareBackendLaunch(launchURL);
}

export function confirmBackendLaunchConsent(
  consentRequestId: string,
  granted: boolean,
): ApprovedBackendLaunch {
  return TacuaCaptureSpikeModule.confirmBackendLaunchConsent(
    consentRequestId,
    granted,
  );
}

export function cancelBackendLaunch(requestId: string): void {
  TacuaCaptureSpikeModule.cancelBackendLaunch(requestId);
}

export function getStatus(): CaptureStatus {
  return TacuaCaptureSpikeModule.getStatus();
}

export function start(options: CaptureStartOptions): Promise<CaptureStatus> {
  return TacuaCaptureSpikeModule.start(options);
}

export function resume(options: CaptureStartOptions): Promise<CaptureStatus> {
  return TacuaCaptureSpikeModule.resume(options);
}

export function stop(): Promise<CaptureStatus> {
  return TacuaCaptureSpikeModule.stop();
}

export function mark(label: string): Promise<CaptureMarker> {
  return TacuaCaptureSpikeModule.mark(label);
}

export function listRecoverableSessions(): Promise<
  readonly RecoverableSession[]
> {
  return TacuaCaptureSpikeModule.listRecoverableSessions();
}

export function markPartialReadyForUpload(
  options: CaptureRecoveryOptions,
): Promise<RecoverableSession> {
  return TacuaCaptureSpikeModule.markPartialReadyForUpload(options);
}

export function deleteSession(options: CaptureRecoveryOptions): Promise<void> {
  return TacuaCaptureSpikeModule.deleteSession(options);
}

export function subscribe<K extends keyof CaptureEventMap>(
  eventName: K,
  listener: (event: CaptureEventMap[K]) => void,
): EventSubscription {
  return TacuaCaptureSpikeModule.addListener(eventName, listener);
}
