// SPDX-License-Identifier: Apache-2.0

import {
  TacuaCaptureSpikeModule,
  type AppAudioAppendDrop,
  type AppAudioAppendDropCause,
  type AppAudioAppendUnknownRange,
  type ApprovedBackendLaunch,
  type BackendAdmitFinalizedCaptureOptions,
  type BackendBuildIdentity,
  type BackendCaptureAdmission,
  type BackendCaptureScope,
  type BackendDeletedSession,
  type BackendDeleteSessionOptions,
  type BackendLaunchConsentRequest,
  type BackendQueueStatus,
  type BackendSessionDiscoveryRecord,
  type BackendProcessAdmittedCaptureOptions,
  type BackendProcessedCapture,
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
  type CreateCaptureSessionPlanOptions,
  type DiagnosticCustomStateOptions,
  type DiagnosticEventReceipt,
  type DiagnosticInteractionAction,
  type DiagnosticNetworkCompletionOptions,
  type DiagnosticNetworkMethod,
  type DiagnosticRouteTransitionOptions,
  type DiagnosticRouteTrigger,
  type DiagnosticRuntimeErrorOptions,
  type DiagnosticUserInteractionOptions,
  type RecoverableSession,
  type RecoverCaptureSessionPlanOptions,
  type ResumedCaptureSessionPlan,
  type ResumeCaptureSessionPlanOptions,
  type StartedCaptureSessionPlan,
} from "./TacuaCaptureSpikeModule";
import { type EventSubscription } from "expo-modules-core";
import {
  createBackendManagedHostControllerForPrimitives,
  type BackendManagedHostAction,
  type BackendManagedHostController,
  type BackendManagedHostControllerOptions,
  type BackendManagedHostError,
  type BackendManagedHostErrorCategory,
  type BackendManagedHostMutation,
  type BackendManagedHostPhase,
  type BackendManagedHostSnapshot,
  type BackendManagedLaunchKind,
  type BackendManagedPlanNextAction,
  type BackendManagedQueueRequirement,
  type BackendManagedRecorderSnapshot,
  type BackendManagedSessionSummary,
} from "./BackendManagedHostController";

export type {
  AppAudioAppendDrop,
  AppAudioAppendDropCause,
  AppAudioAppendUnknownRange,
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
  BackendManagedHostAction,
  BackendManagedHostController,
  BackendManagedHostControllerOptions,
  BackendManagedHostError,
  BackendManagedHostErrorCategory,
  BackendManagedHostMutation,
  BackendManagedHostPhase,
  BackendManagedHostSnapshot,
  BackendManagedLaunchKind,
  BackendManagedPlanNextAction,
  BackendManagedQueueRequirement,
  BackendManagedRecorderSnapshot,
  BackendManagedSessionSummary,
};

/**
 * Creates the dependency-light orchestration boundary for a backend-managed Expo QA host.
 * Network requests, launch codes, bearer credentials, and backend origins stay native.
 * Capture-plan fields are held privately and never projected into controller snapshots.
 */
export function createBackendManagedHostController(
  options: BackendManagedHostControllerOptions = {},
): BackendManagedHostController {
  return createBackendManagedHostControllerForPrimitives(
    {
      prepareBackendLaunch,
      confirmBackendLaunchConsent,
      cancelBackendLaunch,
      createCaptureSessionPlan,
      resumeCaptureSessionPlan,
      recoverStartedCaptureSessionPlan,
      recoverResumedCaptureSessionPlan,
      listBackendSessions,
      getBackendQueueStatus,
      getBackendStartRecoveryStatus,
      getBackendResumeRecoveryStatus,
      abandonBackendStart,
      resetPreparedBackendResume,
      getStatus,
      listRecoverableSessions,
      start,
      resume,
      stop,
      markPartialReadyForUpload,
      admitFinalizedCapture,
      processAdmittedCapture,
      deleteBackendSession,
    },
    options,
  );
}

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

/**
 * Discovers durable native START identifiers after relaunch. For every returned identifier, read
 * queue and START-recovery status before resuming, recovering, uploading, or deleting.
 */
export function listBackendSessions(): Promise<
  readonly BackendSessionDiscoveryRecord[]
> {
  return TacuaCaptureSpikeModule.listBackendSessions();
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

/**
 * Commits backend START before returning. The host should retain `localSessionId`, then pass the
 * returned `captureOptions` to `start`; ReplayKit has not started when this promise resolves.
 */
export function createCaptureSessionPlan(
  options: CreateCaptureSessionPlanOptions,
): Promise<StartedCaptureSessionPlan> {
  return TacuaCaptureSpikeModule.createCaptureSessionPlan(options);
}

/** Rotates backend authority using the queue-owned build/scope and returns updated capture fields. */
export function resumeCaptureSessionPlan(
  options: ResumeCaptureSessionPlanOptions,
): Promise<ResumedCaptureSessionPlan> {
  return TacuaCaptureSpikeModule.resumeCaptureSessionPlan(options);
}

/** Finishes a crash-interrupted START receipt commit without consuming another launch code. */
export function recoverStartedCaptureSessionPlan(
  options: RecoverCaptureSessionPlanOptions,
): Promise<StartedCaptureSessionPlan> {
  return TacuaCaptureSpikeModule.recoverStartedCaptureSessionPlan(options);
}

/** Finishes a crash-interrupted RESUME receipt commit without consuming another launch code. */
export function recoverResumedCaptureSessionPlan(
  options: RecoverCaptureSessionPlanOptions,
): Promise<ResumedCaptureSessionPlan> {
  return TacuaCaptureSpikeModule.recoverResumedCaptureSessionPlan(options);
}

/** @advanced Legacy migration/testing only; normal hosts use `createCaptureSessionPlan`. */
export function advancedStartBackendSession(
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

/** @advanced Legacy migration/testing only; normal hosts use `resumeCaptureSessionPlan`. */
export function advancedResumeBackendSession(
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

/**
 * Verifies a stopped local capture, materializes its sanitized diagnostic, and atomically admits
 * immutable segment/diagnostic requests to the durable queue. This performs no network I/O.
 */
export function admitFinalizedCapture(
  localSessionId: string,
): Promise<BackendCaptureAdmission> {
  return TacuaCaptureSpikeModule.admitFinalizedCapture({ localSessionId });
}

/** @advanced Backfills build/scope for a queue migrated from an older SDK. */
export function advancedAdmitFinalizedCapture(
  options: BackendAdmitFinalizedCaptureOptions,
): Promise<BackendCaptureAdmission> {
  const buildIdentityJson = options.buildIdentity
    ? JSON.stringify(options.buildIdentity)
    : null;
  const scopeJson = options.scope ? JSON.stringify(options.scope) : null;
  return TacuaCaptureSpikeModule.admitFinalizedCapture({
    localSessionId: options.localSessionId,
    ...(buildIdentityJson === null ? {} : { buildIdentityJson }),
    ...(scopeJson === null ? {} : { scopeJson }),
  });
}

/**
 * Drives every admitted upload, session completion, receipt commit, and receipt-authorized local
 * payload cleanup. It is safe to call again after interruption; unknown outcomes replay the exact
 * durable request.
 */
export function processAdmittedCapture(
  options: BackendProcessAdmittedCaptureOptions,
): Promise<BackendProcessedCapture> {
  return TacuaCaptureSpikeModule.processAdmittedCapture(options);
}

/**
 * Authenticates a fixed `user_requested` deletion, durably stores the backend tombstone, retires
 * the entire local capture directory, removes its Keychain credential, and finally retires the
 * sensitive transport queue. Interrupted calls retry the exact durable deletion request.
 */
export function deleteBackendSession(
  options: BackendDeleteSessionOptions,
): Promise<BackendDeletedSession> {
  return TacuaCaptureSpikeModule.deleteBackendSession(options);
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

export function recordRouteTransition(
  options: DiagnosticRouteTransitionOptions,
): Promise<DiagnosticEventReceipt> {
  return TacuaCaptureSpikeModule.recordRouteTransition(options);
}

export function recordUserInteraction(
  options: DiagnosticUserInteractionOptions,
): Promise<DiagnosticEventReceipt> {
  return TacuaCaptureSpikeModule.recordUserInteraction(options);
}

export function recordRuntimeError(
  options: DiagnosticRuntimeErrorOptions,
): Promise<DiagnosticEventReceipt> {
  return TacuaCaptureSpikeModule.recordRuntimeError(options);
}

export function recordNetworkRequestCompleted(
  options: DiagnosticNetworkCompletionOptions,
): Promise<DiagnosticEventReceipt> {
  return TacuaCaptureSpikeModule.recordNetworkRequestCompleted(options);
}

export function recordCustomState(
  options: DiagnosticCustomStateOptions,
): Promise<DiagnosticEventReceipt> {
  return TacuaCaptureSpikeModule.recordCustomState(options);
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
