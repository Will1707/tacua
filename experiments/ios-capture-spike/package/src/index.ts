// SPDX-License-Identifier: Apache-2.0

import {
  TacuaCaptureSpikeModule,
  type ApprovedBackendLaunch,
  type BackendBuildIdentity,
  type BackendCaptureScope,
  type BackendLaunchConsentRequest,
  type BackendQueueStatus,
  type BackendResumedSession,
  type BackendResumeRecoveryStatus,
  type BackendResumeRequirement,
  type BackendResumeSessionOptions,
  type BackendStartedSession,
  type BackendStartRecoveryStatus,
  type BackendStartSessionOptions,
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
  BackendBuildIdentity,
  BackendCaptureScope,
  BackendLaunchConsentRequest,
  BackendQueueStatus,
  BackendResumedSession,
  BackendResumeRecoveryStatus,
  BackendResumeRequirement,
  BackendResumeSessionOptions,
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

export function startBackendSession(
  options: BackendStartSessionOptions,
): Promise<BackendStartedSession> {
  return TacuaCaptureSpikeModule.startBackendSession({
    approvedLaunchId: options.approvedLaunchId,
    localSessionId: options.localSessionId,
    buildIdentityJson: JSON.stringify(options.buildIdentity),
    scopeJson: JSON.stringify(options.scope),
    requestedAt: options.requestedAt,
  });
}

export function resumeBackendSession(
  options: BackendResumeSessionOptions,
): Promise<BackendResumedSession> {
  return TacuaCaptureSpikeModule.resumeBackendSession({
    approvedLaunchId: options.approvedLaunchId,
    localSessionId: options.localSessionId,
    buildIdentityJson: JSON.stringify(options.buildIdentity),
    scopeJson: JSON.stringify(options.scope),
    requestedAt: options.requestedAt,
  });
}

export function getBackendResumeRecoveryStatus(
  localSessionId: string,
): Promise<BackendResumeRecoveryStatus> {
  return TacuaCaptureSpikeModule.getBackendResumeRecoveryStatus(localSessionId);
}

/** Finishes a validated receipt/queue commit after a crash without consuming a launch code. */
export function recoverBackendResume(
  localSessionId: string,
): Promise<BackendResumedSession> {
  return TacuaCaptureSpikeModule.recoverBackendResume(localSessionId);
}

export function resetPreparedBackendResume(
  localSessionId: string,
): Promise<void> {
  return TacuaCaptureSpikeModule.resetPreparedBackendResume(localSessionId);
}

export function getBackendStartRecoveryStatus(
  localSessionId: string,
): Promise<BackendStartRecoveryStatus> {
  return TacuaCaptureSpikeModule.getBackendStartRecoveryStatus(localSessionId);
}

export function recoverBackendStart(
  localSessionId: string,
): Promise<BackendStartedSession> {
  return TacuaCaptureSpikeModule.recoverBackendStart(localSessionId);
}

export function abandonBackendStart(
  localSessionId: string,
  acknowledgeRemoteSessionMayExist: boolean,
): Promise<void> {
  return TacuaCaptureSpikeModule.abandonBackendStart(
    localSessionId,
    acknowledgeRemoteSessionMayExist,
  );
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
