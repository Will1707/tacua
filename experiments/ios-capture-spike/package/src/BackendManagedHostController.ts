// SPDX-License-Identifier: Apache-2.0

import type {
  ApprovedBackendLaunch,
  BackendCaptureAdmission,
  BackendDeletedSession,
  BackendLaunchConsentRequest,
  BackendProcessedCapture,
  BackendQueueStatus,
  BackendResumeRecoveryStatus,
  BackendSessionDiscoveryRecord,
  BackendStartRecoveryStatus,
  CaptureRecoveryOptions,
  CaptureStartOptions,
  CaptureStatus,
  RecoverableSession,
  ResumedCaptureSessionPlan,
  StartedCaptureSessionPlan,
} from "./TacuaCaptureSpikeModule";

const MINIMUM_SEGMENT_DURATION_SECONDS = 2;
const MAXIMUM_SEGMENT_DURATION_SECONDS = 60;
const DEFAULT_SEGMENT_DURATION_SECONDS = 10;
const DEFAULT_MAXIMUM_DISCOVERED_SESSIONS = 64;
const ABSOLUTE_MAXIMUM_DISCOVERED_SESSIONS = 128;
const MAXIMUM_PROJECTED_ERROR_CODES = 64;

const RESUMABLE_CAPTURE_STATES = new Set([
  "prepared",
  "recording",
  "stopping",
  "recoverable_partial",
  "partial",
  "failed_no_verified_segments",
  "stop_failed_capture_active",
  "start_cleanup_pending",
]);

const ADMISSIBLE_CAPTURE_STATES = new Set([
  "completed",
  "partial_ready_for_upload",
]);

export type BackendManagedHostMutation =
  | "refresh"
  | "reconcile_native_lifecycle"
  | "prepare_launch"
  | "respond_to_consent"
  | "exchange_launch"
  | "recover_start_plan"
  | "recover_resume_plan"
  | "abandon_start"
  | "reset_prepared_resume"
  | "start_capture"
  | "resume_capture"
  | "stop_capture"
  | "keep_partial"
  | "admit_and_drain"
  | "foreground_retry"
  | "request_reset"
  | "cancel_reset"
  | "confirm_reset";

export type BackendManagedHostErrorCategory =
  | "invalid_input"
  | "invalid_state"
  | "session_not_found"
  | "ambiguous_resume_target"
  | "session_limit_exceeded"
  | "reconciliation_required"
  | "native_rejected";

export type BackendManagedHostError = Readonly<{
  operation: BackendManagedHostMutation;
  category: BackendManagedHostErrorCategory;
  /** A bounded native error code when one is safely available; never an error message. */
  nativeCode: string | null;
}>;

export type BackendManagedLaunchKind = "start" | "resume";

export type BackendManagedPlanNextAction =
  | "start_capture"
  | "resume_capture"
  | "admit_and_drain"
  | "none";

export type BackendManagedHostPhase =
  | Readonly<{ kind: "idle" }>
  | Readonly<{
      kind: "awaiting_launch_consent";
      launchKind: BackendManagedLaunchKind;
      requiredConsentVersion: "tacua-local-capture-consent-v1";
      expectedRemoteSessionId: string | null;
      matchedLocalSessionId: string | null;
    }>
  | Readonly<{
      kind: "launch_approved";
      launchKind: BackendManagedLaunchKind;
      expectedRemoteSessionId: string | null;
      matchedLocalSessionId: string | null;
    }>
  | Readonly<{
      kind: "plan_ready";
      localSessionId: string;
      source: "start" | "resume" | "recovered_start" | "recovered_resume";
      nextAction: BackendManagedPlanNextAction;
      recoverableState: string | null;
      verifiedSegmentCount: number;
    }>
  | Readonly<{
      kind: "capturing";
      localSessionId: string;
      mode: "started" | "resumed";
    }>
  | Readonly<{
      kind: "stopped";
      localSessionId: string;
      captureState: string;
      verifiedSegmentCount: number;
    }>
  | Readonly<{
      kind: "upload_retry";
      localSessionId: string;
    }>
  | Readonly<{
      kind: "awaiting_authenticated_reset_confirmation";
      localSessionId: string;
    }>
  | Readonly<{
      kind: "complete";
      localSessionId: string;
      result: "uploaded" | "reset";
    }>
  | Readonly<{
      kind: "blocked";
      reason:
        | "unsupported_capture_state"
        | "resume_launch_required"
        | "operator_reconciliation_required"
        | "missing_capture_authority";
      localSessionId: string | null;
    }>;

export type BackendManagedHostAction =
  | Readonly<{ kind: "refresh" }>
  | Readonly<{ kind: "prepare_launch" }>
  | Readonly<{ kind: "approve_launch" }>
  | Readonly<{ kind: "decline_launch" }>
  | Readonly<{ kind: "exchange_launch" }>
  | Readonly<{ kind: "start_planned_capture"; localSessionId: string }>
  | Readonly<{ kind: "resume_planned_capture"; localSessionId: string }>
  | Readonly<{ kind: "stop_capture"; localSessionId: string }>
  | Readonly<{ kind: "keep_verified_partial"; localSessionId: string }>
  | Readonly<{ kind: "admit_and_drain"; localSessionId: string }>
  | Readonly<{ kind: "recover_start_plan"; localSessionId: string }>
  | Readonly<{ kind: "recover_resume_plan"; localSessionId: string }>
  | Readonly<{ kind: "abandon_start"; localSessionId: string }>
  | Readonly<{ kind: "reset_prepared_resume"; localSessionId: string }>
  | Readonly<{ kind: "request_resume_launch"; localSessionId: string }>
  | Readonly<{ kind: "request_authenticated_reset"; localSessionId: string }>
  | Readonly<{ kind: "confirm_authenticated_reset"; localSessionId: string }>
  | Readonly<{ kind: "cancel_authenticated_reset"; localSessionId: string }>
  | Readonly<{
      kind: "operator_reconciliation_required";
      localSessionId: string;
    }>;

export type BackendManagedQueueRequirement =
  | "ready"
  | "resume_session"
  | "blocked"
  | "temporarily_unavailable"
  | "unavailable"
  | "terminal_deletion"
  | "unknown";

export type BackendManagedSessionSummary = Readonly<{
  localSessionId: string;
  remoteSessionId: string | null;
  captureState: string | null;
  verifiedSegmentCount: number;
  startRecoveryState: BackendStartRecoveryStatus["state"];
  resumeRecoveryState: BackendResumeRecoveryStatus["state"];
  queueExists: boolean;
  queueRequirement: BackendManagedQueueRequirement;
  admittedOperationCount: number;
  actions: readonly BackendManagedHostAction[];
}>;

export type BackendManagedRecorderSnapshot = Readonly<{
  state: string;
  localSessionId: string | null;
  recording: boolean;
  /** Bounded count of allowlisted public SDK codes; native error reasons are never retained. */
  errorCodeCount: number;
  /** Latest bounded public SDK error code, or null when native supplied no safe code. */
  latestErrorCode: string | null;
}>;

export type BackendManagedHostSnapshot = Readonly<{
  revision: number;
  phase: BackendManagedHostPhase;
  mutation: BackendManagedHostMutation | null;
  recorder: BackendManagedRecorderSnapshot;
  sessions: readonly BackendManagedSessionSummary[];
  actions: readonly BackendManagedHostAction[];
  lastError: BackendManagedHostError | null;
}>;

export type BackendManagedHostControllerOptions = Readonly<{
  segmentDurationSeconds?: number;
  maximumDiscoveredSessions?: number;
}>;

/**
 * Narrow adapter over the existing SDK. It deliberately contains no generic request primitive,
 * bearer credential, backend origin, fetch function, or caller-built capture authority.
 * Existing native plan APIs do return validated CaptureStartOptions; the controller keeps that
 * object private and never projects it into a snapshot.
 */
export type BackendManagedHostPrimitives = Readonly<{
  /**
   * Installs native onState/onError wake-up signals. Event payloads deliberately stop at this
   * boundary: reconciliation reads an authoritative status and never retains native error reasons.
   */
  subscribeCaptureLifecycle: (listeners: {
    readonly onState: () => void;
    readonly onError: () => void;
  }) => () => void;
  prepareBackendLaunch: (launchURL: string) => BackendLaunchConsentRequest;
  confirmBackendLaunchConsent: (
    consentRequestId: string,
    granted: boolean,
  ) => ApprovedBackendLaunch;
  cancelBackendLaunch: (requestId: string) => void;
  createCaptureSessionPlan: (options: {
    readonly approvedLaunchId: string;
    readonly segmentDurationSeconds: number;
  }) => Promise<StartedCaptureSessionPlan>;
  resumeCaptureSessionPlan: (options: {
    readonly approvedLaunchId: string;
    readonly localSessionId: string;
    readonly segmentDurationSeconds: number;
  }) => Promise<ResumedCaptureSessionPlan>;
  recoverStartedCaptureSessionPlan: (options: {
    readonly localSessionId: string;
    readonly segmentDurationSeconds: number;
  }) => Promise<StartedCaptureSessionPlan>;
  recoverResumedCaptureSessionPlan: (options: {
    readonly localSessionId: string;
    readonly segmentDurationSeconds: number;
  }) => Promise<ResumedCaptureSessionPlan>;
  listBackendSessions: () => Promise<readonly BackendSessionDiscoveryRecord[]>;
  getBackendQueueStatus: (
    localSessionId: string,
  ) => Promise<BackendQueueStatus>;
  getBackendStartRecoveryStatus: (
    localSessionId: string,
  ) => Promise<BackendStartRecoveryStatus>;
  getBackendResumeRecoveryStatus: (
    localSessionId: string,
  ) => Promise<BackendResumeRecoveryStatus>;
  abandonBackendStart: (
    localSessionId: string,
    acknowledgeRemoteSessionMayExist: boolean,
  ) => Promise<void>;
  resetPreparedBackendResume: (localSessionId: string) => Promise<void>;
  getStatus: () => CaptureStatus;
  listRecoverableSessions: () => Promise<readonly RecoverableSession[]>;
  start: (options: CaptureStartOptions) => Promise<CaptureStatus>;
  resume: (options: CaptureStartOptions) => Promise<CaptureStatus>;
  stop: () => Promise<CaptureStatus>;
  markPartialReadyForUpload: (
    options: CaptureRecoveryOptions,
  ) => Promise<RecoverableSession>;
  admitFinalizedCapture: (
    localSessionId: string,
  ) => Promise<BackendCaptureAdmission>;
  processAdmittedCapture: (options: {
    readonly localSessionId: string;
  }) => Promise<BackendProcessedCapture>;
  deleteBackendSession: (options: {
    readonly localSessionId: string;
  }) => Promise<BackendDeletedSession>;
}>;

export type BackendManagedHostController = Readonly<{
  getSnapshot: () => BackendManagedHostSnapshot;
  subscribe: (
    listener: (snapshot: BackendManagedHostSnapshot) => void,
  ) => () => void;
  refresh: () => Promise<void>;
  prepareLaunch: (launchURL: string) => Promise<void>;
  respondToLaunchConsent: (granted: boolean) => Promise<void>;
  exchangeApprovedLaunch: (segmentDurationSeconds?: number) => Promise<void>;
  recoverStartPlan: (
    localSessionId: string,
    segmentDurationSeconds?: number,
  ) => Promise<void>;
  recoverResumePlan: (
    localSessionId: string,
    segmentDurationSeconds?: number,
  ) => Promise<void>;
  abandonStart: (
    localSessionId: string,
    acknowledgeRemoteSessionMayExist: boolean,
  ) => Promise<void>;
  resetPreparedResume: (localSessionId: string) => Promise<void>;
  startPlannedCapture: () => Promise<void>;
  resumePlannedCapture: () => Promise<void>;
  stopCapture: () => Promise<void>;
  keepVerifiedPartial: () => Promise<void>;
  admitAndDrain: (localSessionId?: string) => Promise<void>;
  notifyForeground: () => Promise<void>;
  requestAuthenticatedReset: (localSessionId: string) => Promise<void>;
  cancelAuthenticatedReset: () => Promise<void>;
  confirmAuthenticatedReset: () => Promise<void>;
  dispose: () => void;
}>;

type PendingConsent = Readonly<{
  consentRequestId: string;
  launchKind: BackendManagedLaunchKind;
  expectedRemoteSessionId: string | null;
  matchedLocalSessionId: string | null;
}>;

type ApprovedLaunch = Readonly<{
  approvedLaunchId: string;
  launchKind: BackendManagedLaunchKind;
  expectedRemoteSessionId: string | null;
  matchedLocalSessionId: string | null;
}>;

type InstalledPlan = Readonly<{
  localSessionId: string;
  captureOptions: CaptureStartOptions | null;
}>;

type ResetRequest = Readonly<{
  localSessionId: string;
  priorPhase: BackendManagedHostPhase;
}>;

export class BackendManagedHostControllerError extends Error {
  readonly category: BackendManagedHostErrorCategory;

  constructor(category: BackendManagedHostErrorCategory, message: string) {
    super(message);
    this.name = "BackendManagedHostControllerError";
    this.category = category;
  }
}

/** Pure controller seam used by the public SDK factory and dependency-free unit tests. */
export function createBackendManagedHostControllerForPrimitives(
  primitives: BackendManagedHostPrimitives,
  options: BackendManagedHostControllerOptions = {},
): BackendManagedHostController {
  return new Controller(primitives, options);
}

class Controller implements BackendManagedHostController {
  private readonly primitives: BackendManagedHostPrimitives;
  private readonly segmentDurationSeconds: number;
  private readonly maximumDiscoveredSessions: number;
  private readonly listeners = new Set<
    (snapshot: BackendManagedHostSnapshot) => void
  >();
  private removeCaptureLifecycleListeners: (() => void) | null = null;
  private mutationTail: Promise<void> = Promise.resolve();
  private lifecycleSignalGeneration = 0;
  private lifecycleReconciliationScheduled = false;
  private lifecycleSubscriptionReady = false;
  private disposed = false;
  private pendingConsent: PendingConsent | null = null;
  private approvedLaunch: ApprovedLaunch | null = null;
  private installedPlan: InstalledPlan | null = null;
  private activeCaptureSessionId: string | null = null;
  private pendingDrainSessionId: string | null = null;
  private resetRequest: ResetRequest | null = null;
  private snapshot: BackendManagedHostSnapshot;

  constructor(
    primitives: BackendManagedHostPrimitives,
    options: BackendManagedHostControllerOptions,
  ) {
    this.primitives = primitives;
    this.segmentDurationSeconds = validateSegmentDuration(
      options.segmentDurationSeconds ?? DEFAULT_SEGMENT_DURATION_SECONDS,
    );
    this.maximumDiscoveredSessions = validateMaximumSessions(
      options.maximumDiscoveredSessions ??
        DEFAULT_MAXIMUM_DISCOVERED_SESSIONS,
    );
    const recorder = projectRecorder(primitives.getStatus());
    this.activeCaptureSessionId = recorder.recording
      ? recorder.localSessionId
      : null;
    const phase: BackendManagedHostPhase = recorder.recording
      ? recorder.localSessionId
        ? {
            kind: "capturing",
            localSessionId: recorder.localSessionId,
            mode: "resumed",
          }
        : {
            kind: "blocked",
            reason: "operator_reconciliation_required",
            localSessionId: null,
          }
      : { kind: "idle" };
    this.snapshot = {
      revision: 0,
      phase,
      mutation: null,
      recorder,
      sessions: [],
      actions: [],
      lastError: null,
    };
    this.snapshot = this.withActions(this.snapshot);
    let removeCaptureLifecycleListeners: (() => void) | null = null;
    try {
      removeCaptureLifecycleListeners =
        this.primitives.subscribeCaptureLifecycle({
          onState: this.handleCaptureLifecycleSignal,
          onError: this.handleCaptureLifecycleSignal,
        });
      if (typeof removeCaptureLifecycleListeners !== "function") {
        throw controllerError(
          "native_rejected",
          "Native lifecycle subscription did not return a remover",
        );
      }
    } catch (error) {
      // A synchronously fired callback is held behind lifecycleSubscriptionReady, so a failed
      // constructor cannot leave reconciliation work running on an unreachable controller.
      this.disposed = true;
      throw error;
    }
    this.removeCaptureLifecycleListeners = removeCaptureLifecycleListeners;
    this.lifecycleSubscriptionReady = true;
    if (this.lifecycleSignalGeneration > 0) {
      this.scheduleLifecycleReconciliation();
    }
  }

  getSnapshot = (): BackendManagedHostSnapshot => this.snapshot;

  subscribe = (
    listener: (snapshot: BackendManagedHostSnapshot) => void,
  ): (() => void) => {
    this.assertNotDisposed();
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  refresh = (): Promise<void> =>
    this.run("refresh", async () => {
      await this.refreshInternal();
    });

  prepareLaunch = (launchURL: string): Promise<void> =>
    this.run("prepare_launch", async () => {
      if (typeof launchURL !== "string" || launchURL.length === 0) {
        throw controllerError("invalid_input", "A launch URL is required");
      }
      if (this.pendingConsent || this.approvedLaunch) {
        throw controllerError(
          "invalid_state",
          "A launch is already awaiting a decision",
        );
      }
      if (
        this.snapshot.recorder.recording ||
        this.snapshot.phase.kind ===
          "awaiting_authenticated_reset_confirmation" ||
        this.snapshot.phase.kind === "launch_approved" ||
        this.snapshot.phase.kind === "awaiting_launch_consent"
      ) {
        throw controllerError(
          "invalid_state",
          "The current host state cannot accept another launch",
        );
      }

      const prepared = this.primitives.prepareBackendLaunch(launchURL);
      let matchedLocalSessionId: string | null = null;
      try {
        if (
          prepared.expectedSessionId === null &&
          !["idle", "complete", "blocked"].includes(
            this.snapshot.phase.kind,
          )
        ) {
          throw controllerError(
            "invalid_state",
            "A new START cannot replace unfinished session work",
          );
        }
        if (prepared.expectedSessionId !== null) {
          matchedLocalSessionId = await this.matchResumeTarget(
            prepared.expectedSessionId,
          );
        }
      } catch (error) {
        this.primitives.cancelBackendLaunch(prepared.consentRequestId);
        throw error;
      }

      const launchKind: BackendManagedLaunchKind =
        prepared.expectedSessionId === null ? "start" : "resume";
      this.pendingConsent = {
        consentRequestId: prepared.consentRequestId,
        launchKind,
        expectedRemoteSessionId: prepared.expectedSessionId,
        matchedLocalSessionId,
      };
      this.setPhase({
        kind: "awaiting_launch_consent",
        launchKind,
        requiredConsentVersion: prepared.requiredConsentVersion,
        expectedRemoteSessionId: prepared.expectedSessionId,
        matchedLocalSessionId,
      });
    });

  respondToLaunchConsent = (granted: boolean): Promise<void> =>
    this.run("respond_to_consent", async () => {
      const pending = this.pendingConsent;
      if (!pending) {
        throw controllerError(
          "invalid_state",
          "No launch is awaiting consent",
        );
      }
      this.pendingConsent = null;
      if (granted !== true) {
        this.primitives.cancelBackendLaunch(pending.consentRequestId);
        this.setPhase({ kind: "idle" });
        return;
      }

      let approved: ApprovedBackendLaunch;
      try {
        approved = this.primitives.confirmBackendLaunchConsent(
          pending.consentRequestId,
          true,
        );
      } catch (error) {
        // The native gate is volatile. Preparing another link replaces any orphaned approved
        // handle, but cancel the known request first and return the host to a retryable state.
        this.primitives.cancelBackendLaunch(pending.consentRequestId);
        this.setPhase({ kind: "idle" });
        throw error;
      }
      this.approvedLaunch = {
        approvedLaunchId: approved.approvedLaunchId,
        launchKind: pending.launchKind,
        expectedRemoteSessionId: pending.expectedRemoteSessionId,
        matchedLocalSessionId: pending.matchedLocalSessionId,
      };
      this.setPhase({
        kind: "launch_approved",
        launchKind: pending.launchKind,
        expectedRemoteSessionId: pending.expectedRemoteSessionId,
        matchedLocalSessionId: pending.matchedLocalSessionId,
      });
    });

  exchangeApprovedLaunch = (
    segmentDurationSeconds = this.segmentDurationSeconds,
  ): Promise<void> =>
    this.run("exchange_launch", async () => {
      const duration = validateSegmentDuration(segmentDurationSeconds);
      const approved = this.approvedLaunch;
      if (!approved) {
        throw controllerError(
          "invalid_state",
          "No approved launch is available",
        );
      }
      if (this.primitives.getStatus().recorderRecording) {
        throw controllerError(
          "invalid_state",
          "A backend launch cannot be exchanged while capture is recording",
        );
      }

      // One-shot native handles are never reused after an attempted exchange. Native code decides
      // whether the underlying launch code was consumed; JS always requires a fresh link on error.
      this.approvedLaunch = null;
      try {
        if (approved.launchKind === "start") {
          const plan = await this.primitives.createCaptureSessionPlan({
            approvedLaunchId: approved.approvedLaunchId,
            segmentDurationSeconds: duration,
          });
          await this.installStartedPlan(plan, "start");
          return;
        }

        const expectedRemoteSessionId = approved.expectedRemoteSessionId;
        const localSessionId = approved.matchedLocalSessionId;
        if (!expectedRemoteSessionId || !localSessionId) {
          throw controllerError(
            "invalid_state",
            "A resume launch has no exact target",
          );
        }
        const rematched = await this.matchResumeTarget(expectedRemoteSessionId);
        if (rematched !== localSessionId) {
          throw controllerError(
            "ambiguous_resume_target",
            "The resume target changed before exchange",
          );
        }
        const queue = await this.primitives.getBackendQueueStatus(localSessionId);
        if (
          queue.resumeRequirement?.kind !== "resume_session" ||
          queue.resumeRequirement.canConsumeApprovedLaunch !== true
        ) {
          throw controllerError(
            "invalid_state",
            "The queue cannot consume a resume launch",
          );
        }
        const plan = await this.primitives.resumeCaptureSessionPlan({
          approvedLaunchId: approved.approvedLaunchId,
          localSessionId,
          segmentDurationSeconds: duration,
        });
        await this.installResumedPlan(plan, "resume");
      } catch (error) {
        this.primitives.cancelBackendLaunch(approved.approvedLaunchId);
        this.setPhase({
          kind: "blocked",
          reason: "operator_reconciliation_required",
          localSessionId: approved.matchedLocalSessionId,
        });
        throw error;
      }
    });

  recoverStartPlan = (
    localSessionId: string,
    segmentDurationSeconds = this.segmentDurationSeconds,
  ): Promise<void> =>
    this.run("recover_start_plan", async () => {
      const duration = validateSegmentDuration(segmentDurationSeconds);
      const status = await this.primitives.getBackendStartRecoveryStatus(
        localSessionId,
      );
      if (!status.canRecoverWithoutLaunch) {
        throw controllerError(
          status.remoteSessionMayExist
            ? "reconciliation_required"
            : "invalid_state",
          "START cannot be recovered without a launch",
        );
      }
      const plan = await this.primitives.recoverStartedCaptureSessionPlan({
        localSessionId,
        segmentDurationSeconds: duration,
      });
      if (plan.localSessionId !== localSessionId) {
        throw controllerError(
          "native_rejected",
          "Recovered START returned a different local session",
        );
      }
      await this.installStartedPlan(plan, "recovered_start");
    });

  recoverResumePlan = (
    localSessionId: string,
    segmentDurationSeconds = this.segmentDurationSeconds,
  ): Promise<void> =>
    this.run("recover_resume_plan", async () => {
      const duration = validateSegmentDuration(segmentDurationSeconds);
      const status = await this.primitives.getBackendResumeRecoveryStatus(
        localSessionId,
      );
      if (!status.canRecoverWithoutLaunch) {
        throw controllerError(
          status.requiresReconciliation
            ? "reconciliation_required"
            : "invalid_state",
          "RESUME cannot be recovered without a launch",
        );
      }
      const plan = await this.primitives.recoverResumedCaptureSessionPlan({
        localSessionId,
        segmentDurationSeconds: duration,
      });
      if (plan.localSessionId !== localSessionId) {
        throw controllerError(
          "native_rejected",
          "Recovered RESUME returned a different local session",
        );
      }
      await this.installResumedPlan(plan, "recovered_resume");
    });

  abandonStart = (
    localSessionId: string,
    acknowledgeRemoteSessionMayExist: boolean,
  ): Promise<void> =>
    this.run("abandon_start", async () => {
      const status = await this.primitives.getBackendStartRecoveryStatus(
        localSessionId,
      );
      if (!status.canAbandonLocally) {
        throw controllerError(
          status.remoteSessionMayExist
            ? "reconciliation_required"
            : "invalid_state",
          "START cannot be abandoned locally",
        );
      }
      if (
        status.remoteSessionMayExist &&
        status.state !== "exchange_outcome_unknown_reset_pending" &&
        acknowledgeRemoteSessionMayExist !== true
      ) {
        throw controllerError(
          "invalid_input",
          "Unknown remote START outcomes require acknowledgement",
        );
      }
      await this.primitives.abandonBackendStart(
        localSessionId,
        acknowledgeRemoteSessionMayExist,
      );
      await this.refreshInternal();
    });

  resetPreparedResume = (localSessionId: string): Promise<void> =>
    this.run("reset_prepared_resume", async () => {
      const status = await this.primitives.getBackendResumeRecoveryStatus(
        localSessionId,
      );
      if (!status.canResetPreparedCredential) {
        throw controllerError(
          status.requiresReconciliation
            ? "reconciliation_required"
            : "invalid_state",
          "RESUME cannot be reset locally",
        );
      }
      await this.primitives.resetPreparedBackendResume(localSessionId);
      await this.refreshInternal();
    });

  startPlannedCapture = (): Promise<void> =>
    this.run("start_capture", async () => {
      const phase = this.snapshot.phase;
      const plan = this.installedPlan;
      if (
        phase.kind !== "plan_ready" ||
        phase.nextAction !== "start_capture" ||
        !plan?.captureOptions
      ) {
        throw controllerError(
          "invalid_state",
          "No START capture plan is ready",
        );
      }
      let status: CaptureStatus;
      try {
        status = await this.primitives.start(plan.captureOptions);
        assertRecordingStatus(status, plan.localSessionId);
      } catch (error) {
        this.reconcileCaptureMutationFailure("started", plan.localSessionId);
        throw error;
      }
      this.activeCaptureSessionId = plan.localSessionId;
      this.updateRecorder(status);
      this.setPhase({
        kind: "capturing",
        localSessionId: plan.localSessionId,
        mode: "started",
      });
    });

  resumePlannedCapture = (): Promise<void> =>
    this.run("resume_capture", async () => {
      const phase = this.snapshot.phase;
      const plan = this.installedPlan;
      if (
        phase.kind !== "plan_ready" ||
        phase.nextAction !== "resume_capture" ||
        !plan?.captureOptions
      ) {
        throw controllerError(
          "invalid_state",
          "No RESUME capture plan is ready",
        );
      }
      let status: CaptureStatus;
      try {
        status = await this.primitives.resume(plan.captureOptions);
        assertRecordingStatus(status, plan.localSessionId);
      } catch (error) {
        this.reconcileCaptureMutationFailure("resumed", plan.localSessionId);
        throw error;
      }
      this.activeCaptureSessionId = plan.localSessionId;
      this.updateRecorder(status);
      this.setPhase({
        kind: "capturing",
        localSessionId: plan.localSessionId,
        mode: "resumed",
      });
    });

  stopCapture = (): Promise<void> =>
    this.run("stop_capture", async () => {
      const current = this.primitives.getStatus();
      const localSessionId =
        this.activeCaptureSessionId ?? current.sessionId ?? null;
      if (!localSessionId) {
        throw controllerError("invalid_state", "No capture is recording");
      }
      if (current.recorderRecording !== true) {
        this.activeCaptureSessionId = null;
        this.updateRecorder(current);
        this.setPhase({
          kind: "stopped",
          localSessionId,
          captureState: current.state,
          verifiedSegmentCount: current.segmentCount,
        });
        return;
      }
      const terminal = await this.primitives.stop();
      if (terminal.recorderRecording) {
        throw controllerError(
          "native_rejected",
          "Capture remained active after stop",
        );
      }
      if (terminal.sessionId && terminal.sessionId !== localSessionId) {
        throw controllerError(
          "native_rejected",
          "Stop returned a different local session",
        );
      }
      this.activeCaptureSessionId = null;
      this.updateRecorder(terminal);
      this.setPhase({
        kind: "stopped",
        localSessionId,
        captureState: terminal.state,
        verifiedSegmentCount: terminal.segmentCount,
      });
    });

  keepVerifiedPartial = (): Promise<void> =>
    this.run("keep_partial", async () => {
      const phase = this.snapshot.phase;
      const plan = this.installedPlan;
      const isAuthorizedPartial =
        (phase.kind === "plan_ready" &&
          phase.nextAction === "resume_capture" &&
          phase.verifiedSegmentCount > 0) ||
        (phase.kind === "stopped" &&
          !ADMISSIBLE_CAPTURE_STATES.has(phase.captureState) &&
          phase.verifiedSegmentCount > 0);
      if (
        !isAuthorizedPartial ||
        !plan?.captureOptions
      ) {
        throw controllerError(
          "invalid_state",
          "No verified partial with current authority is ready",
        );
      }
      const kept = await this.primitives.markPartialReadyForUpload(
        plan.captureOptions,
      );
      if (kept.sessionId !== plan.localSessionId) {
        throw controllerError(
          "native_rejected",
          "Partial finalization returned a different local session",
        );
      }
      this.setPhase({
        kind: "stopped",
        localSessionId: plan.localSessionId,
        captureState: kept.state,
        verifiedSegmentCount: kept.segmentCount,
      });
    });

  admitAndDrain = (localSessionId?: string): Promise<void> =>
    this.run("admit_and_drain", async () => {
      if (this.primitives.getStatus().recorderRecording) {
        throw controllerError(
          "invalid_state",
          "Stopped-capture transport cannot start while capture is recording",
        );
      }
      const resolved = localSessionId ?? phaseLocalSessionId(this.snapshot.phase);
      if (!resolved) {
        throw controllerError(
          "invalid_state",
          "No stopped session is selected",
        );
      }
      await this.admitAndDrainInternal(resolved);
    });

  notifyForeground = (): Promise<void> =>
    this.run("foreground_retry", async () => {
      if (this.primitives.getStatus().recorderRecording) {
        await this.refreshInternal();
        return;
      }
      if (this.pendingDrainSessionId) {
        await this.drainInternal(this.pendingDrainSessionId);
        return;
      }

      const sessions = await this.discoverSessions();
      this.replaceSessionsAndRecorder(sessions);
      const admitted = sessions.filter(
        (session) =>
          session.queueExists &&
          session.queueRequirement === "ready" &&
          session.admittedOperationCount > 0,
      );
      for (const session of admitted) {
        this.pendingDrainSessionId = session.localSessionId;
        await this.drainInternal(session.localSessionId);
      }
    });

  requestAuthenticatedReset = (localSessionId: string): Promise<void> =>
    this.run("request_reset", async () => {
      if (this.resetRequest) {
        throw controllerError(
          "invalid_state",
          "A reset is already awaiting confirmation",
        );
      }
      if (this.primitives.getStatus().recorderRecording) {
        throw controllerError(
          "invalid_state",
          "Authenticated reset cannot begin while capture is recording",
        );
      }
      const queue = await this.primitives.getBackendQueueStatus(localSessionId);
      if (!queue.exists || queue.localSessionId !== localSessionId) {
        throw controllerError(
          "session_not_found",
          "Authenticated reset requires a durable backend queue",
        );
      }
      this.resetRequest = {
        localSessionId,
        priorPhase: this.snapshot.phase,
      };
      this.setPhase({
        kind: "awaiting_authenticated_reset_confirmation",
        localSessionId,
      });
    });

  cancelAuthenticatedReset = (): Promise<void> =>
    this.run("cancel_reset", async () => {
      const request = this.resetRequest;
      if (!request) {
        throw controllerError(
          "invalid_state",
          "No authenticated reset is awaiting confirmation",
        );
      }
      this.resetRequest = null;
      this.setPhase(request.priorPhase);
    });

  confirmAuthenticatedReset = (): Promise<void> =>
    this.run("confirm_reset", async () => {
      const request = this.resetRequest;
      if (!request) {
        throw controllerError(
          "invalid_state",
          "No authenticated reset is awaiting confirmation",
        );
      }
      // Clear the volatile confirmation before native network/storage work. A failed or unknown
      // outcome must be requested again and is replayed exactly by the native deletion journal.
      this.resetRequest = null;
      this.setPhase(request.priorPhase);
      const deleted = await this.primitives.deleteBackendSession({
        localSessionId: request.localSessionId,
      });
      if (
        deleted.localSessionId !== request.localSessionId ||
        deleted.remoteDataDeleted !== true ||
        deleted.localSessionRetired !== true ||
        deleted.credentialRemoved !== true
      ) {
        throw controllerError(
          "native_rejected",
          "Authenticated reset did not durably finish",
        );
      }
      if (this.installedPlan?.localSessionId === request.localSessionId) {
        this.installedPlan = null;
      }
      if (this.pendingDrainSessionId === request.localSessionId) {
        this.pendingDrainSessionId = null;
      }
      if (this.activeCaptureSessionId === request.localSessionId) {
        this.activeCaptureSessionId = null;
      }
      this.setPhase({
        kind: "complete",
        localSessionId: request.localSessionId,
        result: "reset",
      });
    });

  dispose = (): void => {
    if (this.disposed) return;
    this.disposed = true;
    const removeCaptureLifecycleListeners =
      this.removeCaptureLifecycleListeners;
    this.removeCaptureLifecycleListeners = null;
    if (removeCaptureLifecycleListeners) {
      try {
        removeCaptureLifecycleListeners();
      } catch {
        // Listener removal is best-effort during teardown. The disposed gate also ignores any
        // callback already queued by the native event emitter.
      }
    }
    if (this.pendingConsent) {
      this.primitives.cancelBackendLaunch(this.pendingConsent.consentRequestId);
    }
    if (this.approvedLaunch) {
      this.primitives.cancelBackendLaunch(this.approvedLaunch.approvedLaunchId);
    }
    this.pendingConsent = null;
    this.approvedLaunch = null;
    this.listeners.clear();
  };

  private readonly handleCaptureLifecycleSignal = (): void => {
    if (this.disposed) return;
    this.lifecycleSignalGeneration += 1;
    if (!this.lifecycleSubscriptionReady) return;
    this.scheduleLifecycleReconciliation();
  };

  private scheduleLifecycleReconciliation(): void {
    if (this.disposed || this.lifecycleReconciliationScheduled) return;
    this.lifecycleReconciliationScheduled = true;
    let reconciledThroughGeneration = 0;
    const reconciliation = this.run(
      "reconcile_native_lifecycle",
      async () => {
        const targetGeneration = this.lifecycleSignalGeneration;
        try {
          // Reconcile the recorder first so an unrelated queue-discovery failure cannot leave an
          // auto-stopped or errored ReplayKit session projected as actively recording.
          this.replaceRecorder(this.primitives.getStatus());
          await this.refreshInternal();
        } finally {
          // A failed reconciliation is surfaced through the controller's bounded error projection.
          // Do not spin on the same signal, but preserve a signal that arrived during the attempt.
          reconciledThroughGeneration = targetGeneration;
        }
      },
    );
    void reconciliation
      .catch(() => {
        // Native lifecycle callbacks cannot return a promise to Expo. `run` already publishes the
        // privacy-safe controller error, so consume the internal rejection here.
      })
      .finally(() => {
        this.lifecycleReconciliationScheduled = false;
        if (
          !this.disposed &&
          this.lifecycleSignalGeneration > reconciledThroughGeneration
        ) {
          this.scheduleLifecycleReconciliation();
        }
      });
  }

  private run(
    operation: BackendManagedHostMutation,
    task: () => Promise<void>,
  ): Promise<void> {
    const result = this.mutationTail.then(async () => {
      this.assertNotDisposed();
      this.patchSnapshot({ mutation: operation, lastError: null });
      try {
        await task();
      } catch (error) {
        this.patchSnapshot({ lastError: projectError(operation, error) });
        throw error;
      } finally {
        this.patchSnapshot({ mutation: null });
      }
    });
    this.mutationTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async refreshInternal(): Promise<void> {
    const sessions = await this.discoverSessions();
    this.replaceSessionsAndRecorder(sessions);
  }

  private replaceSessionsAndRecorder(
    sessions: readonly BackendManagedSessionSummary[],
  ): void {
    const recorderStatus = this.primitives.getStatus();
    this.replaceRecorder(recorderStatus, sessions);
  }

  private replaceRecorder(
    recorderStatus: CaptureStatus,
    sessions?: readonly BackendManagedSessionSummary[],
  ): void {
    const recorder = projectRecorder(recorderStatus);
    let phase = this.snapshot.phase;
    if (recorder.recording && recorder.localSessionId) {
      this.activeCaptureSessionId = recorder.localSessionId;
      const expectedLocalSessionId = phaseLocalSessionId(phase);
      if (
        expectedLocalSessionId !== null &&
        expectedLocalSessionId !== recorder.localSessionId
      ) {
        phase = {
          kind: "blocked",
          reason: "operator_reconciliation_required",
          localSessionId: expectedLocalSessionId,
        };
      } else if (phase.kind !== "capturing") {
        phase = {
          kind: "capturing",
          localSessionId: recorder.localSessionId,
          mode: "resumed",
        };
      }
    } else if (recorder.recording) {
      this.activeCaptureSessionId = null;
      phase = {
        kind: "blocked",
        reason: "operator_reconciliation_required",
        localSessionId: phaseLocalSessionId(phase),
      };
    } else {
      if (
        phase.kind === "capturing" &&
        recorder.localSessionId !== null &&
        recorder.localSessionId !== phase.localSessionId
      ) {
        phase = {
          kind: "blocked",
          reason: "operator_reconciliation_required",
          localSessionId: phase.localSessionId,
        };
      } else if (
        phase.kind === "capturing" ||
        (phase.kind === "stopped" &&
          recorder.localSessionId === phase.localSessionId)
      ) {
        phase = {
          kind: "stopped",
          localSessionId: phase.localSessionId,
          captureState: recorder.state,
          verifiedSegmentCount: recorderStatus.segmentCount,
        };
      }
      this.activeCaptureSessionId = null;
    }
    this.patchSnapshot({
      ...(sessions === undefined ? {} : { sessions }),
      recorder,
      phase,
    });
  }

  private async discoverSessions(): Promise<
    readonly BackendManagedSessionSummary[]
  > {
    const [records, recoverable] = await Promise.all([
      this.primitives.listBackendSessions(),
      this.primitives.listRecoverableSessions(),
    ]);
    const localCaptureById = new Map(
      recoverable.map((session) => [session.sessionId, session]),
    );
    const ids = new Set<string>();
    for (const record of records) ids.add(record.localSessionId);
    for (const session of recoverable) ids.add(session.sessionId);
    if (ids.size > this.maximumDiscoveredSessions) {
      throw controllerError(
        "session_limit_exceeded",
        "The bounded discovery limit was exceeded",
      );
    }

    const summaries: BackendManagedSessionSummary[] = [];
    for (const localSessionId of [...ids].sort()) {
      const start = await this.primitives.getBackendStartRecoveryStatus(
        localSessionId,
      );
      const resume = await this.primitives.getBackendResumeRecoveryStatus(
        localSessionId,
      );
      const recoveryBlocksQueue =
        !["none", "queue_committed"].includes(start.state) ||
        !["none", "queue_committed"].includes(resume.state);
      const queue = recoveryBlocksQueue
        ? emptyQueue(localSessionId)
        : await this.primitives.getBackendQueueStatus(localSessionId);
      const capture = localCaptureById.get(localSessionId) ?? null;
      summaries.push(
        projectSessionSummary(localSessionId, capture, queue, start, resume),
      );
    }
    return summaries;
  }

  private async matchResumeTarget(expectedRemoteSessionId: string): Promise<string> {
    const records = await this.primitives.listBackendSessions();
    if (records.length > this.maximumDiscoveredSessions) {
      throw controllerError(
        "session_limit_exceeded",
        "The bounded discovery limit was exceeded",
      );
    }
    const matches: string[] = [];
    for (const localSessionId of new Set(
      records.map((record) => record.localSessionId),
    )) {
      const queue = await this.primitives.getBackendQueueStatus(localSessionId);
      if (
        queue.exists &&
        queue.localSessionId === localSessionId &&
        queue.remoteSessionId === expectedRemoteSessionId
      ) {
        matches.push(localSessionId);
      }
    }
    if (matches.length === 0) {
      throw controllerError(
        "session_not_found",
        "No local queue matches the resume target",
      );
    }
    if (matches.length !== 1) {
      throw controllerError(
        "ambiguous_resume_target",
        "More than one local queue matches the resume target",
      );
    }
    // The cardinality checks above prove this element exists. Keep the
    // assertion at the array boundary so consumers enabling
    // `noUncheckedIndexedAccess` do not inherit `undefined` in the SDK source.
    return matches[0]!;
  }

  private async installStartedPlan(
    plan: StartedCaptureSessionPlan,
    source: "start" | "recovered_start",
  ): Promise<void> {
    if (
      plan.localSessionId !== plan.backendSession.localSessionId ||
      plan.localSessionId !== plan.captureOptions.sessionId
    ) {
      throw controllerError(
        "native_rejected",
        "START plan identifiers do not agree",
      );
    }
    await this.projectInstalledPlan(plan.localSessionId, source, true);
    this.installedPlan = {
      localSessionId: plan.localSessionId,
      captureOptions: plan.captureOptions,
    };
  }

  private async installResumedPlan(
    plan: ResumedCaptureSessionPlan,
    source: "resume" | "recovered_resume",
  ): Promise<void> {
    if (plan.localSessionId !== plan.backendSession.localSessionId) {
      throw controllerError(
        "native_rejected",
        "RESUME plan identifiers do not agree",
      );
    }
    if (
      plan.captureOptions &&
      plan.captureOptions.sessionId !== plan.localSessionId
    ) {
      throw controllerError(
        "native_rejected",
        "RESUME capture options name a different session",
      );
    }
    await this.projectInstalledPlan(
      plan.localSessionId,
      source,
      plan.captureOptions !== null,
    );
    this.installedPlan = {
      localSessionId: plan.localSessionId,
      captureOptions: plan.captureOptions,
    };
  }

  private async projectInstalledPlan(
    localSessionId: string,
    source: "start" | "resume" | "recovered_start" | "recovered_resume",
    hasCaptureOptions: boolean,
  ): Promise<void> {
    const recoverable = await this.primitives.listRecoverableSessions();
    if (recoverable.length > this.maximumDiscoveredSessions) {
      throw controllerError(
        "session_limit_exceeded",
        "The bounded recovery limit was exceeded",
      );
    }
    const capture = recoverable.find(
      (candidate) => candidate.sessionId === localSessionId,
    );
    let nextAction: BackendManagedPlanNextAction;
    if (!hasCaptureOptions) {
      nextAction = "admit_and_drain";
    } else if (!capture) {
      nextAction = "start_capture";
    } else if (ADMISSIBLE_CAPTURE_STATES.has(capture.state)) {
      nextAction = "admit_and_drain";
    } else if (RESUMABLE_CAPTURE_STATES.has(capture.state)) {
      nextAction = "resume_capture";
    } else {
      nextAction = "none";
    }
    this.setPhase({
      kind: "plan_ready",
      localSessionId,
      source,
      nextAction,
      recoverableState: capture?.state ?? null,
      verifiedSegmentCount: capture?.segmentCount ?? 0,
    });
    if (nextAction === "none") {
      this.setPhase({
        kind: "blocked",
        reason: "unsupported_capture_state",
        localSessionId,
      });
    }
  }

  private async admitAndDrainInternal(localSessionId: string): Promise<void> {
    const start = await this.primitives.getBackendStartRecoveryStatus(
      localSessionId,
    );
    const resume = await this.primitives.getBackendResumeRecoveryStatus(
      localSessionId,
    );
    if (
      !["none", "queue_committed"].includes(start.state) ||
      !["none", "queue_committed"].includes(resume.state)
    ) {
      throw controllerError(
        resume.requiresReconciliation || start.remoteSessionMayExist
          ? "reconciliation_required"
          : "invalid_state",
        "Lifecycle recovery must finish before admission",
      );
    }
    const queue = await this.primitives.getBackendQueueStatus(localSessionId);
    if (!queue.exists || queue.localSessionId !== localSessionId) {
      throw controllerError(
        "session_not_found",
        "Admission requires a durable backend queue",
      );
    }
    if (
      queue.resumeRequirement?.kind !== "none" ||
      queue.resumeRequirement.reason !== "ready"
    ) {
      throw controllerError(
        queue.resumeRequirement?.kind === "blocked"
          ? "reconciliation_required"
          : "invalid_state",
        "Queue authority is not ready for stopped-capture transport",
      );
    }
    const hasAdmittedOperations = admittedOperationCount(queue) > 0;
    if (!hasAdmittedOperations) {
      const recoverable = await this.primitives.listRecoverableSessions();
      const capture = recoverable.find(
        (candidate) => candidate.sessionId === localSessionId,
      );
      if (!capture || !ADMISSIBLE_CAPTURE_STATES.has(capture.state)) {
        throw controllerError(
          "invalid_state",
          "Only explicitly finalized capture can be admitted",
        );
      }
      const admission = await this.primitives.admitFinalizedCapture(
        localSessionId,
      );
      if (admission.localSessionId !== localSessionId) {
        throw controllerError(
          "native_rejected",
          "Admission returned a different local session",
        );
      }
    }
    this.pendingDrainSessionId = localSessionId;
    await this.drainInternal(localSessionId);
  }

  private async drainInternal(localSessionId: string): Promise<void> {
    try {
      const processed = await this.primitives.processAdmittedCapture({
        localSessionId,
      });
      if (
        processed.localSessionId !== localSessionId ||
        processed.payloadCleanupState !== "payloads_removed" ||
        processed.uploadsConnected !== true ||
        processed.completionConnected !== true
      ) {
        throw controllerError(
          "native_rejected",
          "Upload drain did not durably finish",
        );
      }
      this.pendingDrainSessionId = null;
      if (this.installedPlan?.localSessionId === localSessionId) {
        this.installedPlan = null;
      }
      this.setPhase({
        kind: "complete",
        localSessionId,
        result: "uploaded",
      });
    } catch (error) {
      this.pendingDrainSessionId = localSessionId;
      this.setPhase({ kind: "upload_retry", localSessionId });
      throw error;
    }
  }

  private updateRecorder(status: CaptureStatus): void {
    this.patchSnapshot({ recorder: projectRecorder(status) });
  }

  private reconcileCaptureMutationFailure(
    mode: "started" | "resumed",
    plannedLocalSessionId: string,
  ): void {
    try {
      const current = this.primitives.getStatus();
      this.updateRecorder(current);
      if (current.recorderRecording && current.sessionId) {
        this.activeCaptureSessionId = current.sessionId;
        if (current.sessionId !== plannedLocalSessionId) {
          this.setPhase({
            kind: "blocked",
            reason: "operator_reconciliation_required",
            localSessionId: plannedLocalSessionId,
          });
          return;
        }
        this.setPhase({
          kind: "capturing",
          localSessionId: current.sessionId,
          mode,
        });
        return;
      }
      this.activeCaptureSessionId = null;
    } catch {
      // Preserve the original mutation error; the next explicit refresh asks native code again.
    }
    this.setPhase({
      kind: "blocked",
      reason: "operator_reconciliation_required",
      localSessionId: plannedLocalSessionId,
    });
  }

  private setPhase(phase: BackendManagedHostPhase): void {
    this.patchSnapshot({ phase });
  }

  private patchSnapshot(
    patch: Partial<
      Pick<
        BackendManagedHostSnapshot,
        "phase" | "mutation" | "recorder" | "sessions" | "lastError"
      >
    >,
  ): void {
    const next: BackendManagedHostSnapshot = {
      ...this.snapshot,
      ...patch,
      revision: this.snapshot.revision + 1,
      actions: [],
    };
    this.snapshot = this.withActions(next);
    for (const listener of this.listeners) {
      try {
        listener(this.snapshot);
      } catch {
        // A rendering subscriber must not break native lifecycle serialization.
      }
    }
  }

  private withActions(
    snapshot: BackendManagedHostSnapshot,
  ): BackendManagedHostSnapshot {
    if (snapshot.mutation !== null) {
      return freezeSnapshot({ ...snapshot, actions: [] });
    }
    const actions: BackendManagedHostAction[] = [{ kind: "refresh" }];
    if (
      snapshot.recorder.recording &&
      snapshot.recorder.localSessionId !== null &&
      snapshot.phase.kind !== "capturing"
    ) {
      actions.push({
        kind: "stop_capture",
        localSessionId: snapshot.recorder.localSessionId,
      });
    }
    if (
      !snapshot.recorder.recording &&
      ![
        "awaiting_launch_consent",
        "launch_approved",
        "plan_ready",
        "awaiting_authenticated_reset_confirmation",
      ].includes(snapshot.phase.kind)
    ) {
      actions.push({ kind: "prepare_launch" });
    }
    switch (snapshot.phase.kind) {
      case "awaiting_launch_consent":
        actions.push({ kind: "approve_launch" }, { kind: "decline_launch" });
        break;
      case "launch_approved":
        actions.push({ kind: "exchange_launch" });
        break;
      case "plan_ready":
        if (snapshot.phase.nextAction === "start_capture") {
          actions.push({
            kind: "start_planned_capture",
            localSessionId: snapshot.phase.localSessionId,
          });
        } else if (snapshot.phase.nextAction === "resume_capture") {
          actions.push({
            kind: "resume_planned_capture",
            localSessionId: snapshot.phase.localSessionId,
          });
          if (snapshot.phase.verifiedSegmentCount > 0) {
            actions.push({
              kind: "keep_verified_partial",
              localSessionId: snapshot.phase.localSessionId,
            });
          }
        } else if (snapshot.phase.nextAction === "admit_and_drain") {
          actions.push({
            kind: "admit_and_drain",
            localSessionId: snapshot.phase.localSessionId,
          });
        }
        break;
      case "capturing":
        actions.push({
          kind: "stop_capture",
          localSessionId: snapshot.phase.localSessionId,
        });
        break;
      case "stopped":
        if (
          !ADMISSIBLE_CAPTURE_STATES.has(snapshot.phase.captureState) &&
          snapshot.phase.verifiedSegmentCount > 0 &&
          this.installedPlan?.localSessionId === snapshot.phase.localSessionId &&
          this.installedPlan.captureOptions !== null
        ) {
          actions.push({
            kind: "keep_verified_partial",
            localSessionId: snapshot.phase.localSessionId,
          });
          break;
        }
        if (ADMISSIBLE_CAPTURE_STATES.has(snapshot.phase.captureState)) {
          actions.push({
            kind: "admit_and_drain",
            localSessionId: snapshot.phase.localSessionId,
          });
        }
        break;
      case "upload_retry":
        actions.push({
          kind: "admit_and_drain",
          localSessionId: snapshot.phase.localSessionId,
        });
        break;
      case "awaiting_authenticated_reset_confirmation":
        actions.push(
          {
            kind: "confirm_authenticated_reset",
            localSessionId: snapshot.phase.localSessionId,
          },
          {
            kind: "cancel_authenticated_reset",
            localSessionId: snapshot.phase.localSessionId,
          },
        );
        break;
      default:
        break;
    }
    if (
      ["idle", "stopped", "upload_retry", "complete", "blocked"].includes(
        snapshot.phase.kind,
      )
    ) {
      for (const session of snapshot.sessions) {
        for (const action of session.actions) {
          if (
            !actions.some(
              (candidate) =>
                candidate.kind === action.kind &&
                ("localSessionId" in candidate
                  ? candidate.localSessionId
                  : null) ===
                  ("localSessionId" in action ? action.localSessionId : null),
            )
          ) {
            actions.push(action);
          }
        }
      }
    }
    return freezeSnapshot({ ...snapshot, actions });
  }

  private assertNotDisposed(): void {
    if (this.disposed) {
      throw controllerError("invalid_state", "Controller is disposed");
    }
  }
}

function projectSessionSummary(
  localSessionId: string,
  capture: RecoverableSession | null,
  queue: BackendQueueStatus,
  start: BackendStartRecoveryStatus,
  resume: BackendResumeRecoveryStatus,
): BackendManagedSessionSummary {
  const actions: BackendManagedHostAction[] = [];
  if (start.canRecoverWithoutLaunch) {
    actions.push({ kind: "recover_start_plan", localSessionId });
  } else if (start.canAbandonLocally) {
    actions.push({ kind: "abandon_start", localSessionId });
  }
  if (resume.canRecoverWithoutLaunch) {
    actions.push({ kind: "recover_resume_plan", localSessionId });
  } else if (resume.canResetPreparedCredential) {
    actions.push({ kind: "reset_prepared_resume", localSessionId });
  } else if (resume.requiresReconciliation) {
    actions.push({ kind: "operator_reconciliation_required", localSessionId });
  }
  if (queue.resumeRequirement?.kind === "resume_session") {
    actions.push({ kind: "request_resume_launch", localSessionId });
  }
  if (
    queue.resumeRequirement?.kind === "none" &&
    queue.resumeRequirement.reason === "ready" &&
    (admittedOperationCount(queue) > 0 ||
      (capture !== null && ADMISSIBLE_CAPTURE_STATES.has(capture.state)))
  ) {
    actions.push({ kind: "admit_and_drain", localSessionId });
  }
  if (queue.exists) {
    actions.push({ kind: "request_authenticated_reset", localSessionId });
  }
  return {
    localSessionId,
    remoteSessionId: queue.remoteSessionId ?? null,
    captureState: capture?.state ?? null,
    verifiedSegmentCount: capture?.segmentCount ?? 0,
    startRecoveryState: start.state,
    resumeRecoveryState: resume.state,
    queueExists: queue.exists,
    queueRequirement: projectQueueRequirement(queue),
    admittedOperationCount: admittedOperationCount(queue),
    actions,
  };
}

function projectQueueRequirement(
  queue: BackendQueueStatus,
): BackendManagedQueueRequirement {
  const requirement = queue.resumeRequirement;
  if (!requirement) return "unknown";
  if (requirement.kind === "resume_session") return "resume_session";
  if (requirement.kind === "blocked") return "blocked";
  switch (requirement.reason) {
    case "ready":
      return "ready";
    case "credential_temporarily_unavailable":
      return "temporarily_unavailable";
    case "credential_unavailable":
      return "unavailable";
    case "terminal_deletion":
      return "terminal_deletion";
  }
}

function admittedOperationCount(queue: BackendQueueStatus): number {
  return Math.max(
    0,
    ...[
      queue.operationCount,
      queue.queuedOperationCount,
      queue.storedResponseCount,
    ].filter(
      (value): value is number =>
        typeof value === "number" && Number.isInteger(value) && value >= 0,
    ),
  );
}

function emptyQueue(localSessionId: string): BackendQueueStatus {
  return { exists: false, localSessionId };
}

function projectRecorder(status: CaptureStatus): BackendManagedRecorderSnapshot {
  const safeErrorCodes = (
    Array.isArray(status.errorCodes) ? status.errorCodes : []
  )
    .filter(isSafeNativeErrorCode)
    .slice(-MAXIMUM_PROJECTED_ERROR_CODES);
  return {
    state: status.state,
    localSessionId: status.sessionId ?? null,
    recording: status.recorderRecording,
    errorCodeCount: safeErrorCodes.length,
    latestErrorCode: safeErrorCodes.at(-1) ?? null,
  };
}

function assertRecordingStatus(
  status: CaptureStatus,
  localSessionId: string,
): void {
  if (
    status.recorderRecording !== true ||
    status.sessionId !== localSessionId
  ) {
    throw controllerError(
      "native_rejected",
      "Native capture did not enter the expected recording state",
    );
  }
}

function validateSegmentDuration(value: number): number {
  if (
    !Number.isInteger(value) ||
    value < MINIMUM_SEGMENT_DURATION_SECONDS ||
    value > MAXIMUM_SEGMENT_DURATION_SECONDS
  ) {
    throw controllerError(
      "invalid_input",
      "Segment duration must be an integer from 2 through 60 seconds",
    );
  }
  return value;
}

function validateMaximumSessions(value: number): number {
  if (
    !Number.isInteger(value) ||
    value < 1 ||
    value > ABSOLUTE_MAXIMUM_DISCOVERED_SESSIONS
  ) {
    throw controllerError(
      "invalid_input",
      "Session discovery limit is outside the supported bound",
    );
  }
  return value;
}

function phaseLocalSessionId(phase: BackendManagedHostPhase): string | null {
  return "localSessionId" in phase ? phase.localSessionId : null;
}

function controllerError(
  category: BackendManagedHostErrorCategory,
  message: string,
): BackendManagedHostControllerError {
  return new BackendManagedHostControllerError(category, message);
}

function projectError(
  operation: BackendManagedHostMutation,
  error: unknown,
): BackendManagedHostError {
  const category =
    error instanceof BackendManagedHostControllerError
      ? error.category
      : "native_rejected";
  let nativeCode: string | null = null;
  if (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string" &&
    isSafeNativeErrorCode(error.code)
  ) {
    nativeCode = error.code;
  }
  return { operation, category, nativeCode };
}

function isSafeNativeErrorCode(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^ERR_TACUA_[A-Z0-9_]{1,85}$/u.test(value)
  );
}

function freezeSnapshot(
  snapshot: BackendManagedHostSnapshot,
): BackendManagedHostSnapshot {
  const sessions = Object.freeze(
    snapshot.sessions.map((session) =>
      Object.freeze({
        ...session,
        actions: Object.freeze(
          session.actions.map((action) => Object.freeze({ ...action })),
        ),
      }),
    ),
  );
  const actions = Object.freeze(
    snapshot.actions.map((action) => Object.freeze({ ...action })),
  );
  return Object.freeze({
    ...snapshot,
    phase: Object.freeze({ ...snapshot.phase }),
    recorder: Object.freeze({ ...snapshot.recorder }),
    sessions,
    actions,
    lastError:
      snapshot.lastError === null
        ? null
        : Object.freeze({ ...snapshot.lastError }),
  });
}
