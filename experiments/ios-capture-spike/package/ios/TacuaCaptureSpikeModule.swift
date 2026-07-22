// SPDX-License-Identifier: Apache-2.0

import AVFAudio
import ExpoModulesCore
import Foundation
import ReplayKit

public final class TacuaCaptureSpikeModule: Module {
  private var session: TacuaCaptureSession?
  private var lastTerminalStatus: [String: Any]?
  private let sessionLock = NSLock()
  private let launchConsentGate = TacuaLaunchConsentGate()
  private let backendCoordinatorLock = NSLock()
  private struct BackendLifecycleContext {
    let start: TacuaSDKStartLifecycleCoordinator
    let resume: TacuaSDKResumeLifecycleCoordinator
    let queueStore: TacuaTransportQueueFileStore
    let startJournalStore: TacuaSDKStartJournalFileStore
    let retention: TacuaSDKLocalRetentionCoordinator
    let admission: TacuaCaptureAdmissionCoordinator
    let upload: TacuaCaptureUploadCoordinator
    let deletion: TacuaCaptureDeletionCoordinator
  }
  private var backendLifecycleContext: BackendLifecycleContext?

  public func definition() -> ModuleDefinition {
    Name("TacuaCaptureSpikeModule")

    Events("onState", "onSegment", "onGap", "onMarker", "onError")

    Function("getCapabilities") { () -> [String: Any] in
      let recorder = RPScreenRecorder.shared()
      let buildGate = Self.captureBuildGate()
      let localHarnessRetentionBypassEnabled = Self.localHarnessRetentionDecision()
        .bypassesBackendRetention
      var result: [String: Any] = [
        "platform": "ios",
        "api": "ReplayKit.startCapture",
        "available": recorder.isAvailable && buildGate.configuration != nil,
        "qaBuildEnabled": buildGate.configuration != nil,
        "localHarnessRetentionBypassEnabled": localHarnessRetentionBypassEnabled,
        "buildVariant": buildGate.configuration?.buildVariant ?? NSNull(),
        "distribution": buildGate.configuration?.distribution ?? NSNull(),
        "unavailableReason": !recorder.isAvailable
          ? "replaykit_unavailable"
          : ((buildGate.unavailableReason as Any?) ?? NSNull()),
        "microphoneSupported": true,
        "microphonePermission": Self.microphonePermissionValue(),
        "designPointDurationSeconds": TacuaCapturePolicy.maximumDurationSeconds,
        "maximumDurationSeconds": TacuaCapturePolicy.maximumDurationSeconds,
        "startWatchdogSeconds": TacuaCapturePolicy.startWatchdogSeconds,
        "stopWatchdogSeconds": TacuaCapturePolicy.stopWatchdogSeconds,
        "writerFinalizationWatchdogSeconds": TacuaCapturePolicy.writerFinalizationWatchdogSeconds,
        "microphoneStartupWatchdogSeconds": TacuaCapturePolicy.microphoneStartupWatchdogSeconds,
        "requiredConsentVersion": TacuaCapturePolicy.requiredConsentVersion,
        "handoffTrust": "structural_only",
        "schemaVersion": 4,
      ]
#if TACUA_CAPTURE_FAULT_INJECTION
      result["testFaultInjectionCompiled"] = true
      result["testFaultPlan"] = TacuaCaptureFaultRuntime.configuredProcessPlan()?.rawValue
        ?? NSNull()
      result["testFaultLeaseConsumed"] = TacuaCaptureFaultRuntime.processLeaseWasClaimed
#endif
      return result
    }

    Function("getBackendTransportConfiguration") { () throws -> [String: Any] in
      let configuration = try TacuaBackendConfiguration.fromBuildConfiguration()
      let launchConfiguration = try TacuaLaunchLinkConfiguration.fromBuildConfiguration()
      let profile = try TacuaSDKBuildProfile.fromBuildConfiguration()
      return [
        "backendOrigin": configuration.normalizedOrigin,
        "transportConfigurationDigest": configuration.configurationDigest,
        "transportPolicyVersion": TacuaBackendConfiguration.policyVersion,
        "protocolVersion": TacuaSDKBackendProtocol.version,
        "sdkProfileContractVersion": TacuaSDKBuildProfile.contractVersion,
        "sdkProfileDigest": profile.profileDigest,
        "queueSchemaVersion": TacuaTransportQueueV3.schemaVersion,
        "credentialStorage": "ios_keychain_when_unlocked_this_device_only",
        "launchCodePersistence": "transient_only",
        "redirectPolicy": "reject_all",
        "launchURLTemplate": "\(launchConfiguration.scheme)://tacua/start?launch_code=<opaque>",
      ]
    }

    Function("prepareBackendLaunch") { (launchURL: String) throws -> [String: Any] in
      // Parsing never accepts an origin: the network origin is independently build-pinned.
      _ = try TacuaBackendConfiguration.fromBuildConfiguration()
      let launchConfiguration = try TacuaLaunchLinkConfiguration.fromBuildConfiguration()
      let pending = try self.launchConsentGate.prepare(
        rawURL: launchURL,
        configuration: launchConfiguration
      )
      return [
        "consentRequestId": pending.consentRequestID,
        "requiredConsentVersion": pending.requiredConsentVersion,
        "expectedSessionId": pending.expectedSessionID ?? NSNull(),
      ]
    }

    Function("confirmBackendLaunchConsent") {
      (consentRequestID: String, granted: Bool) throws -> [String: Any] in
      let approvedLaunchID = try self.launchConsentGate.confirm(
        consentRequestID: consentRequestID,
        granted: granted
      )
      return ["approvedLaunchId": approvedLaunchID]
    }

    Function("cancelBackendLaunch") { (requestID: String) in
      self.launchConsentGate.cancel(consentRequestID: requestID)
    }

    AsyncFunction("createCaptureSessionPlan") {
      (options: TacuaCreateCaptureSessionPlanNativeOptions, promise: Promise) in
      do {
        let coordinator = try self.hostIntegrationCoordinator()
        Task {
          do {
            let plan = try await coordinator.start(
              approvedLaunchID: options.approvedLaunchId,
              segmentDurationSeconds: options.segmentDurationSeconds
            )
            promise.resolve(Self.startedCapturePlanValue(plan))
          } catch {
            Self.rejectHostStart(promise, error: error)
          }
        }
      } catch {
        Self.rejectHostStart(promise, error: error)
      }
    }

    AsyncFunction("resumeCaptureSessionPlan") {
      (options: TacuaResumeCaptureSessionPlanNativeOptions, promise: Promise) in
      do {
        try self.allowLocalRetentionServerReconciliation(options.localSessionId)
        let coordinator = try self.hostIntegrationCoordinator()
        Task {
          do {
            let plan = try await coordinator.resume(
              approvedLaunchID: options.approvedLaunchId,
              localSessionID: options.localSessionId,
              segmentDurationSeconds: options.segmentDurationSeconds
            )
            try self.backendLifecycleCoordinators().retention.requireActive(
              localSessionID: options.localSessionId
            )
            promise.resolve(Self.resumedCapturePlanValue(plan))
          } catch {
            Self.rejectHostResume(promise, error: error)
          }
        }
      } catch {
        Self.rejectHostResume(promise, error: error)
      }
    }

    AsyncFunction("recoverStartedCaptureSessionPlan") {
      (options: TacuaRecoverCaptureSessionPlanNativeOptions, promise: Promise) in
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: options.localSessionId
        )
        let plan = try self.hostIntegrationCoordinator().recoverStart(
          localSessionID: options.localSessionId,
          segmentDurationSeconds: options.segmentDurationSeconds
        )
        promise.resolve(Self.startedCapturePlanValue(plan))
      } catch {
        Self.rejectHostStart(promise, error: error)
      }
    }

    AsyncFunction("recoverResumedCaptureSessionPlan") {
      (options: TacuaRecoverCaptureSessionPlanNativeOptions, promise: Promise) in
      do {
        try self.allowLocalRetentionServerReconciliation(options.localSessionId)
        let plan = try self.hostIntegrationCoordinator().recoverResume(
          localSessionID: options.localSessionId,
          segmentDurationSeconds: options.segmentDurationSeconds
        )
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: options.localSessionId
        )
        promise.resolve(Self.resumedCapturePlanValue(plan))
      } catch {
        Self.rejectHostResume(promise, error: error)
      }
    }

    // Advanced migration/testing primitive. Normal host code uses createCaptureSessionPlan.
    AsyncFunction("startBackendSession") {
      (options: TacuaBackendStartSessionNativeOptions, promise: Promise) in
      do {
        let coordinator = try self.startLifecycleCoordinator()
        let input = TacuaSDKStartSessionInput(
          approvedLaunchID: options.approvedLaunchId,
          localSessionID: options.localSessionId,
          buildIdentityJSON: Data(options.buildIdentityJson.utf8),
          scopeJSON: Data(options.scopeJson.utf8),
          requestedAt: options.requestedAt
        )
        Task {
          do {
            let started = try await coordinator.start(input)
            promise.resolve(Self.backendStartedSessionValue(started))
          } catch {
            Self.rejectBackendStart(promise, error: error)
          }
        }
      } catch {
        Self.rejectBackendStart(promise, error: error)
      }
    }

    AsyncFunction("getBackendStartRecoveryStatus") {
      (localSessionID: String, promise: Promise) in
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: localSessionID
        )
        let status = try self.startLifecycleCoordinator().recoveryStatus(
          localSessionID: localSessionID
        )
        promise.resolve(Self.backendStartRecoveryStatusValue(status))
      } catch {
        Self.rejectBackendStart(promise, error: error)
      }
    }

    // Advanced migration/testing primitive for a legacy queue without durable artifacts.
    AsyncFunction("resumeBackendSession") {
      (options: TacuaBackendResumeSessionNativeOptions, promise: Promise) in
      do {
        try self.allowLocalRetentionServerReconciliation(options.localSessionId)
        let coordinator = try self.resumeLifecycleCoordinator()
        let input = TacuaSDKResumeSessionInput(
          approvedLaunchID: options.approvedLaunchId,
          localSessionID: options.localSessionId,
          buildIdentityJSON: Data(options.buildIdentityJson.utf8),
          scopeJSON: Data(options.scopeJson.utf8),
          requestedAt: options.requestedAt
        )
        Task {
          do {
            let resumed = try await coordinator.resume(input)
            try self.backendLifecycleCoordinators().retention.requireActive(
              localSessionID: options.localSessionId
            )
            promise.resolve(Self.backendResumedSessionValue(resumed))
          } catch {
            Self.rejectBackendResume(promise, error: error)
          }
        }
      } catch {
        Self.rejectBackendResume(promise, error: error)
      }
    }

    AsyncFunction("getBackendResumeRecoveryStatus") {
      (localSessionID: String, promise: Promise) in
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: localSessionID
        )
        let status = try self.resumeLifecycleCoordinator().recoveryStatus(
          localSessionID: localSessionID
        )
        promise.resolve(Self.backendResumeRecoveryStatusValue(status))
      } catch {
        Self.rejectBackendResume(promise, error: error)
      }
    }

    AsyncFunction("admitFinalizedCapture") {
      (options: TacuaBackendAdmitFinalizedCaptureNativeOptions, promise: Promise) in
      guard self.currentSession() == nil else {
        Self.rejectCaptureAdmission(promise, error: TacuaCaptureAdmissionError.captureNotFinalized)
        return
      }
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: options.localSessionId
        )
        let admitted = try TacuaCaptureSession.withExclusiveRecoveryAccess {
          try self.backendLifecycleCoordinators().admission.admit(
            TacuaCaptureAdmissionInput(
              localSessionID: options.localSessionId,
              buildIdentityJSON: options.buildIdentityJson.map { Data($0.utf8) },
              scopeJSON: options.scopeJson.map { Data($0.utf8) }
            )
          )
        }
        promise.resolve(Self.captureAdmissionValue(admitted))
      } catch {
        Self.rejectCaptureAdmission(promise, error: error)
      }
    }

    AsyncFunction("processAdmittedCapture") {
      (options: TacuaBackendProcessAdmittedCaptureNativeOptions, promise: Promise) in
      guard self.currentSession() == nil else {
        Self.rejectCaptureUpload(promise, error: TacuaCaptureUploadError.alreadyInProgress)
        return
      }
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: options.localSessionId
        )
        let recoveryLease = try TacuaCaptureSession.acquireExclusiveRecoveryLease()
        let coordinator = try self.backendLifecycleCoordinators().upload
        Task {
          defer { recoveryLease.release() }
          do {
            let result = try await coordinator.drive(localSessionID: options.localSessionId)
            promise.resolve(Self.captureUploadValue(result))
          } catch {
            Self.rejectCaptureUpload(promise, error: error)
          }
        }
      } catch {
        Self.rejectCaptureUpload(promise, error: error)
      }
    }

    AsyncFunction("deleteBackendSession") {
      (options: TacuaBackendDeleteSessionNativeOptions, promise: Promise) in
      guard self.currentSession() == nil else {
        Self.rejectCaptureDeletion(promise, error: TacuaCaptureDeletionError.alreadyInProgress)
        return
      }
      do {
        try self.allowLocalRetentionServerReconciliation(options.localSessionId)
        // Serialize whole-directory retirement with recording, recovery, and local-only deletion.
        // The deletion coordinator separately holds the backend lifecycle lease across network I/O.
        let recoveryLease = try TacuaCaptureSession.acquireExclusiveRecoveryLease()
        let coordinator = try self.backendLifecycleCoordinators().deletion
        Task {
          defer { recoveryLease.release() }
          do {
            let result = try await coordinator.delete(localSessionID: options.localSessionId)
            promise.resolve(Self.captureDeletionValue(result))
          } catch {
            Self.rejectCaptureDeletion(promise, error: error)
          }
        }
      } catch {
        Self.rejectCaptureDeletion(promise, error: error)
      }
    }

    AsyncFunction("recoverBackendResume") { (localSessionID: String, promise: Promise) in
      do {
        try self.allowLocalRetentionServerReconciliation(localSessionID)
        let resumed = try self.resumeLifecycleCoordinator().recover(
          localSessionID: localSessionID
        )
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: localSessionID
        )
        promise.resolve(Self.backendResumedSessionValue(resumed))
      } catch {
        Self.rejectBackendResume(promise, error: error)
      }
    }

    AsyncFunction("resetPreparedBackendResume") {
      (localSessionID: String, promise: Promise) in
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: localSessionID
        )
        try self.resumeLifecycleCoordinator().resetPrepared(
          localSessionID: localSessionID
        )
        promise.resolve()
      } catch {
        Self.rejectBackendResume(promise, error: error)
      }
    }

    AsyncFunction("recoverBackendStart") { (localSessionID: String, promise: Promise) in
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: localSessionID
        )
        let started = try self.startLifecycleCoordinator().recover(
          localSessionID: localSessionID
        )
        promise.resolve(Self.backendStartedSessionValue(started))
      } catch {
        Self.rejectBackendStart(promise, error: error)
      }
    }

    AsyncFunction("abandonBackendStart") {
      (localSessionID: String, acknowledgeRemoteSessionMayExist: Bool, promise: Promise) in
      do {
        try self.backendLifecycleCoordinators().retention.requireActive(
          localSessionID: localSessionID
        )
        try self.startLifecycleCoordinator().abandon(
          localSessionID: localSessionID,
          acknowledgeRemoteSessionMayExist: acknowledgeRemoteSessionMayExist
        )
        promise.resolve()
      } catch {
        Self.rejectBackendStart(promise, error: error)
      }
    }

    AsyncFunction("getBackendQueueStatus") { (localSessionID: String, promise: Promise) in
      do {
        let retired: Bool
        do {
          retired = try self.backendLifecycleCoordinators().retention
            .enforce(localSessionID: localSessionID) == .retired
        } catch TacuaSDKLocalRetentionError.authoritativeTimeUnavailable,
          TacuaSDKLocalRetentionError.clockRollbackDetected
        {
          // Status is secret-free reconciliation metadata. Transport and raw-capture entry points
          // remain blocked until RESUME installs a current-boot server anchor.
          retired = false
        }
        if retired {
          promise.resolve([
            "exists": false,
            "localSessionId": localSessionID,
          ])
          return
        }
        guard let status = try self.startLifecycleCoordinator().queueStatus(
          localSessionID: localSessionID
        ) else {
          promise.resolve([
            "exists": false,
            "localSessionId": localSessionID,
          ])
          return
        }
        promise.resolve([
          "exists": true,
          "localSessionId": status.localSessionID,
          "remoteSessionId": status.remoteSessionID ?? NSNull(),
          "scopeDigest": status.scopeDigest ?? NSNull(),
          "sessionArtifactsAvailable": status.sessionArtifactsAvailable,
          "currentCredentialId": status.currentCredentialID ?? NSNull(),
          "currentCredentialExpiresAt": status.currentCredentialExpiresAt ?? NSNull(),
          "credentialCapability": status.credentialCapability.rawValue,
          "credentialAvailability": status.credentialAvailability.rawValue,
          "credentialTimeValid": status.credentialTimeValid,
          "resumeRequired": status.resumeRequired,
          "resumeRequirement": Self.backendResumeRequirementValue(
            status.resumeRequirement
          ),
          "transportConfigurationMatchesBuild": status.transportConfigurationMatchesBuild,
          "operationCount": status.operationCount,
          "queuedOperationCount": status.queuedOperationCount,
          "storedResponseCount": status.storedResponseCount,
          "boundLocalPayloadCount": status.boundLocalPayloadCount,
          "legacyUnboundPayloadCount": status.legacyUnboundPayloadCount,
          "pendingRevokedCredentialRemovalCount": status.pendingRevokedCredentialRemovalCount,
          "payloadCleanupState": status.payloadCleanupState.rawValue,
          "credentialCleanupState": status.credentialCleanupState.rawValue,
          "completionCleanupAuthorized": status.completionCleanupAuthorized,
          "deletionCleanupAuthorized": status.deletionCleanupAuthorized,
          "schemaVersion": status.schemaVersion,
        ])
      } catch {
        promise.reject(
          "ERR_TACUA_BACKEND_QUEUE_STATUS",
          "Tacua could not read the local backend transport queue."
        )
      }
    }

    AsyncFunction("listBackendSessions") { (promise: Promise) in
      do {
        let lifecycle = try self.backendLifecycleCoordinators()
        _ = try lifecycle.retention.sweep()
        let records = try TacuaSDKBackendSessionDiscoveryCoordinator(
          queueStore: lifecycle.queueStore,
          startJournalStore: lifecycle.startJournalStore
        ).list()
        promise.resolve(records.map { record -> [String: Any] in
          [
            "localSessionId": record.localSessionID,
            "hasCommittedQueue": record.hasCommittedQueue,
            "hasStartRecovery": record.hasStartRecovery,
          ]
        })
      } catch {
        promise.reject(
          "ERR_TACUA_BACKEND_SESSION_DISCOVERY",
          "Tacua could not discover durable backend sessions."
        )
      }
    }

    Function("getStatus") { () -> [String: Any] in
      if let session = self.currentSession() {
        return session.status()
      }
      if let terminalStatus = self.terminalStatus() {
        return terminalStatus
      }
      let recorder = RPScreenRecorder.shared()
      let processCleanupPending = TacuaCaptureSession.hasProcessRecorderOwnership
      let qaBuildEnabled = Self.captureBuildGate().configuration != nil
      return [
        "state": processCleanupPending ? "process_cleanup_pending" : "idle",
        "segmentCount": 0,
        "gapCount": 0,
        "markerCount": 0,
        "errorCodes": [],
        "recorderAvailable": recorder.isAvailable && qaBuildEnabled,
        "recorderRecording": recorder.isRecording,
        "maximumDurationSeconds": TacuaCapturePolicy.maximumDurationSeconds,
        "automaticStopHostUptimeSeconds": NSNull(),
        "stopReason": NSNull(),
        "microphoneSamplesObserved": 0,
        "appAudioSamplesObserved": 0,
        "appAudioAvailable": false,
        "diagnosticEventCount": 0,
        "diagnosticContainsCollectionGap": false,
      ]
    }

    AsyncFunction("start") { (options: TacuaCaptureStartOptions, promise: Promise) in
      self.startSession(options: options, resuming: false, promise: promise)
    }.runOnQueue(.main)

    AsyncFunction("resume") { (options: TacuaCaptureStartOptions, promise: Promise) in
      self.startSession(options: options, resuming: true, promise: promise)
    }.runOnQueue(.main)

    AsyncFunction("stop") { (promise: Promise) in
      guard let session = self.currentSession() else {
        Self.reject(promise, error: TacuaCaptureSpikeError.noCaptureRunning)
        return
      }
      session.stop { result in
        switch result {
        case .success(let snapshot): promise.resolve(snapshot)
        case .failure(let error): Self.reject(promise, error: error)
        }
      }
    }.runOnQueue(.main)

    AsyncFunction("mark") { (label: String, promise: Promise) in
      guard let session = self.currentSession() else {
        Self.reject(promise, error: TacuaCaptureSpikeError.noCaptureRunning)
        return
      }
      session.mark(label: label) { result in
        switch result {
        case .success(let marker): promise.resolve(marker)
        case .failure(let error): Self.reject(promise, error: error)
        }
      }
    }

    AsyncFunction("recordRouteTransition") {
      (options: TacuaDiagnosticRouteTransitionOptions, promise: Promise) in
      guard let trigger = TacuaDiagnosticRouteTrigger(rawValue: options.trigger) else {
        Self.reject(promise, error: TacuaCaptureSpikeError.diagnosticInvalid)
        return
      }
      self.recordDiagnosticEvent(
        .routeTransition(
          fromRoute: options.fromRoute,
          toRoute: options.toRoute,
          trigger: trigger
        ),
        promise: promise
      )
    }

    AsyncFunction("recordUserInteraction") {
      (options: TacuaDiagnosticUserInteractionOptions, promise: Promise) in
      guard let action = TacuaDiagnosticInteractionAction(rawValue: options.action) else {
        Self.reject(promise, error: TacuaCaptureSpikeError.diagnosticInvalid)
        return
      }
      self.recordDiagnosticEvent(
        .userInteraction(action: action, target: options.target),
        promise: promise
      )
    }

    AsyncFunction("recordRuntimeError") {
      (options: TacuaDiagnosticRuntimeErrorOptions, promise: Promise) in
      self.recordDiagnosticEvent(
        .runtimeError(
          errorClass: options.errorClass,
          sanitizedMessage: options.sanitizedMessage,
          stackTraceDigest: options.stackTraceDigest,
          handled: options.handled
        ),
        promise: promise
      )
    }

    AsyncFunction("recordNetworkRequestCompleted") {
      (options: TacuaDiagnosticNetworkCompletionOptions, promise: Promise) in
      guard let method = TacuaDiagnosticNetworkMethod(rawValue: options.method) else {
        Self.reject(promise, error: TacuaCaptureSpikeError.diagnosticInvalid)
        return
      }
      self.recordDiagnosticEvent(
        .networkRequestCompleted(
          method: method,
          host: options.host,
          pathTemplate: options.pathTemplate,
          statusCode: Int64(options.statusCode),
          durationMilliseconds: Int64(options.durationMilliseconds),
          traceID: options.traceId
        ),
        promise: promise
      )
    }

    AsyncFunction("recordCustomState") {
      (options: TacuaDiagnosticCustomStateOptions, promise: Promise) in
      guard let status = TacuaDiagnosticCollectionStatus(rawValue: options.collectionStatus) else {
        Self.reject(promise, error: TacuaCaptureSpikeError.diagnosticInvalid)
        return
      }
      self.recordDiagnosticEvent(
        .customState(
          providerID: options.providerId,
          snapshotDigest: options.snapshotDigest,
          collectionStatus: status
        ),
        promise: promise
      )
    }

    AsyncFunction("listRecoverableSessions") { (promise: Promise) in
      guard self.currentSession() == nil else {
        Self.reject(promise, error: TacuaCaptureSpikeError.captureAlreadyRunning)
        return
      }
      do {
        if !Self.localHarnessRetentionDecision().bypassesBackendRetention {
          _ = try self.backendLifecycleCoordinators().retention.sweep()
        }
        promise.resolve(
          try TacuaCaptureSession.withExclusiveRecoveryAccess {
            try TacuaCaptureSession.listRecoverableSessions()
          }
        )
      } catch {
        Self.reject(
          promise,
          error: error,
          fallback: TacuaCaptureSpikeError.recoveryIO("Tacua could not list local recovery sessions.")
        )
      }
    }

    AsyncFunction("markPartialReadyForUpload") {
      (options: TacuaCaptureRecoveryOptions, promise: Promise) in
      guard self.currentSession() == nil else {
        Self.reject(promise, error: TacuaCaptureSpikeError.captureAlreadyRunning)
        return
      }
      do {
        if !Self.localHarnessRetentionDecision().bypassesBackendRetention {
          try self.backendLifecycleCoordinators().retention.requireActive(
            localSessionID: options.sessionId
          )
        }
        promise.resolve(
          try TacuaCaptureSession.withExclusiveRecoveryAccess {
            try TacuaCaptureSession.markPartialReadyForUpload(options: options)
          }
        )
      } catch {
        Self.reject(
          promise,
          error: error,
          fallback: TacuaCaptureSpikeError.recoveryIO(
            "Tacua could not prepare the verified partial session."
          )
        )
      }
    }

    AsyncFunction("deleteSession") { (options: TacuaCaptureRecoveryOptions, promise: Promise) in
      if self.currentSession() != nil {
        Self.reject(promise, error: TacuaCaptureSpikeError.captureAlreadyRunning)
        return
      }
      do {
        if !Self.localHarnessRetentionDecision().bypassesBackendRetention {
          if try self.backendLifecycleCoordinators().retention.enforce(
            localSessionID: options.sessionId
          ) == .retired {
            promise.resolve()
            return
          }
        }
        try TacuaCaptureSession.withExclusiveRecoveryAccess {
          try TacuaCaptureSession.deleteSession(options: options)
        }
        promise.resolve()
      } catch {
        Self.reject(
          promise,
          error: error,
          fallback: TacuaCaptureSpikeError.recoveryIO("Tacua could not delete the local session.")
        )
      }
    }

    OnDestroy {
      self.takeSession()?.cancelForModuleDestruction()
    }
  }

  private func recordDiagnosticEvent(
    _ event: TacuaDiagnosticJournalEvent,
    promise: Promise
  ) {
    guard let session = currentSession() else {
      Self.reject(promise, error: TacuaCaptureSpikeError.noCaptureRunning)
      return
    }
    session.recordDiagnostic(event) { result in
      switch result {
      case .success(let receipt): promise.resolve(receipt)
      case .failure(let error): Self.reject(promise, error: error)
      }
    }
  }

  private func startSession(
    options: TacuaCaptureStartOptions,
    resuming: Bool,
    promise: Promise
  ) {
    guard Self.captureBuildGate().configuration != nil else {
      Self.reject(promise, error: TacuaCaptureSpikeError.captureDisabledForBuild)
      return
    }
    guard currentSession() == nil else {
      Self.reject(promise, error: TacuaCaptureSpikeError.captureAlreadyRunning)
      return
    }

    do {
      let retentionDecision = Self.localHarnessRetentionDecision()
      let rawMediaStopHostUptimeSeconds: Double
      switch retentionDecision {
      case .backendEnforced:
        let retention = try backendLifecycleCoordinators().retention.enforce(
          localSessionID: options.sessionId
        )
        guard case .active(let rawMediaExpiresAt, let stopUptimeMilliseconds) = retention,
          rawMediaExpiresAt == options.rawMediaExpiresAt
        else { throw TacuaSDKLocalRetentionError.expired }
        rawMediaStopHostUptimeSeconds = Double(stopUptimeMilliseconds) / 1_000
      case .localHarness(let stopUptimeSeconds):
        rawMediaStopHostUptimeSeconds = stopUptimeSeconds
      }
      let session = try TacuaCaptureSession(
        options: options,
        resuming: resuming,
        rawMediaStopHostUptimeSeconds: rawMediaStopHostUptimeSeconds,
        eventSink: { [weak self] name, payload in
          DispatchQueue.main.async {
            self?.sendEvent(name, payload)
          }
        },
        terminalSink: { [weak self] completedSession, snapshot in
          self?.rememberTerminalStatus(snapshot)
          self?.clearSession(ifMatching: completedSession)
          guard let self, !retentionDecision.bypassesBackendRetention else { return }
          DispatchQueue.global(qos: .utility).async {
            _ = try? self.backendLifecycleCoordinators().retention.enforce(
              localSessionID: completedSession.sessionId
            )
          }
        }
      )
      installSession(session)
      session.start { result in
        switch result {
        case .success(let snapshot):
          promise.resolve(snapshot)
        case .failure(let error):
          let retainedCleanupErrors = [
            TacuaCaptureSpikeError.captureStartCancelled.code,
            TacuaCaptureSpikeError.startTimeout.code,
          ]
          if !retainedCleanupErrors.contains(error.tacuaStableCode) {
            self.clearSession(ifMatching: session)
          }
          Self.reject(promise, error: error)
        }
      }
    } catch {
      Self.reject(
        promise,
        error: error,
        fallback: TacuaCaptureSpikeError.storageIO("Tacua could not prepare local capture storage.")
      )
    }
  }

  private func currentSession() -> TacuaCaptureSession? {
    sessionLock.lock()
    defer { sessionLock.unlock() }
    return session
  }

  private func installSession(_ newSession: TacuaCaptureSession) {
    sessionLock.lock()
    session = newSession
    lastTerminalStatus = nil
    sessionLock.unlock()
  }

  private func clearSession(ifMatching expected: TacuaCaptureSession) {
    sessionLock.lock()
    if let current = session, current === expected {
      session = nil
    }
    sessionLock.unlock()
  }

  private func takeSession() -> TacuaCaptureSession? {
    sessionLock.lock()
    defer { sessionLock.unlock() }
    let current = session
    session = nil
    return current
  }

  private func terminalStatus() -> [String: Any]? {
    sessionLock.lock()
    defer { sessionLock.unlock() }
    return lastTerminalStatus
  }

  private func rememberTerminalStatus(_ snapshot: [String: Any]) {
    sessionLock.lock()
    lastTerminalStatus = snapshot
    sessionLock.unlock()
  }

  private static func reject(
    _ promise: Promise,
    error: Error,
    fallback: TacuaCaptureSpikeError = .recoveryIO("Tacua reported an internal capture failure.")
  ) {
    let publicError = (error as? TacuaCaptureSpikeError) ?? fallback
    promise.reject(publicError.code, publicError.message)
  }

  private static func captureBuildGate() -> (
    configuration: TacuaQABuildConfiguration?, unavailableReason: String?
  ) {
    let qaBuild: TacuaQABuildConfiguration
    do {
      qaBuild = try TacuaQABuildConfiguration.fromBuildConfiguration()
    } catch let error as TacuaQABuildConfigurationError {
      let reason: String
      switch error {
      case .captureNotEnabled: reason = "capture_not_enabled"
      case .invalidCaptureFlag: reason = "invalid_capture_flag"
      case .invalidBuildVariant: reason = "invalid_build_variant"
      case .invalidDistribution: reason = "invalid_distribution"
      case .unsupportedBuildPair: reason = "unsupported_build_distribution"
      case .developmentBuildRequiresDebug: reason = "development_build_requires_debug"
      }
      return (nil, reason)
    } catch {
      return (nil, "invalid_qa_build_configuration")
    }
    do {
      let backend = try TacuaBackendConfiguration.fromBuildConfiguration()
      _ = try TacuaLaunchLinkConfiguration.fromBuildConfiguration()
      guard backend.qaBuildConfiguration == qaBuild else {
        return (nil, "inconsistent_qa_build_configuration")
      }
      _ = try TacuaSDKBuildProfile.fromBuildConfiguration()
      return (qaBuild, nil)
    } catch let error as TacuaBackendConfigurationError {
      switch error {
      case .missingBuildConfiguration: return (nil, "backend_origin_missing")
      case .invalidOrigin: return (nil, "backend_origin_invalid")
      case .insecureOrigin: return (nil, "backend_origin_insecure")
      case .loopbackDevelopmentOnly: return (nil, "loopback_requires_debug_build")
      case .invalidPathSegment, .buildIdentityMismatch:
        return (nil, "invalid_qa_build_configuration")
      }
    } catch let error as TacuaSDKBuildProfileError {
      switch error {
      case .missingBuildConfiguration: return (nil, "sdk_profile_missing")
      case .installedBuildMismatch: return (nil, "sdk_profile_build_mismatch")
      case .invalidProfile, .profileDigestMismatch, .transportConfigurationMismatch,
        .invalidConsentTimestamp:
        return (nil, "sdk_profile_invalid")
      }
    } catch {
      return (nil, "launch_scheme_invalid")
    }
  }

  private static func localHarnessRetentionDecision() -> TacuaLocalHarnessRetentionDecision {
    let decision = TacuaLocalHarnessPolicy.retentionDecision()
    guard decision.bypassesBackendRetention,
      let configuration = captureBuildGate().configuration,
      configuration.buildVariant == "development",
      configuration.distribution == "local"
    else { return .backendEnforced }
    return decision
  }

  private func startLifecycleCoordinator() throws -> TacuaSDKStartLifecycleCoordinator {
    try backendLifecycleCoordinators().start
  }

  /// RESUME and authenticated deletion are the only network paths allowed to proceed when a
  /// reboot invalidates the persisted monotonic anchor. They either install fresh server time or
  /// retire the session; callers re-run retention enforcement before receiving usable results.
  private func allowLocalRetentionServerReconciliation(_ localSessionID: String) throws {
    do {
      try backendLifecycleCoordinators().retention.requireActive(
        localSessionID: localSessionID
      )
    } catch TacuaSDKLocalRetentionError.authoritativeTimeUnavailable,
      TacuaSDKLocalRetentionError.clockRollbackDetected
    {
      return
    }
  }

  private func resumeLifecycleCoordinator() throws -> TacuaSDKResumeLifecycleCoordinator {
    try backendLifecycleCoordinators().resume
  }

  private func hostIntegrationCoordinator() throws -> TacuaSDKHostIntegrationCoordinator {
    let lifecycle = try backendLifecycleCoordinators()
    let profile: TacuaSDKBuildProfile
    do { profile = try TacuaSDKBuildProfile.fromBuildConfiguration() }
    catch { throw TacuaSDKHostIntegrationError.sealedBuildProfileInvalid }
    return TacuaSDKHostIntegrationCoordinator(
      profile: profile,
      startService: lifecycle.start,
      resumeService: lifecycle.resume,
      artifactStore: lifecycle.queueStore
    )
  }

  private func backendLifecycleCoordinators() throws -> BackendLifecycleContext {
    backendCoordinatorLock.lock()
    defer { backendCoordinatorLock.unlock() }
    if let backendLifecycleContext { return backendLifecycleContext }
    let configuration = try TacuaBackendConfiguration.fromBuildConfiguration()
    let credentialStore = TacuaKeychainCredentialStore()
    let credentialFactory = TacuaCredentialFactory(store: credentialStore)
    let queueStore = try TacuaTransportQueueFileStore.applicationSupportStore()
    let startJournalStore = try TacuaSDKStartJournalFileStore.applicationSupportStore()
    let resumeJournalStore = try TacuaSDKResumeJournalFileStore.applicationSupportStore()
    let exchanger = TacuaSDKBackendClient(
      configuration: configuration,
      credentialStore: credentialStore
    )
    let captureRoot = try TacuaCaptureAdmissionCoordinator.applicationSupportCaptureRoot()
    let retention = TacuaSDKLocalRetentionCoordinator(
      captureRootDirectory: captureRoot,
      queueStore: queueStore,
      startJournalStore: startJournalStore,
      resumeJournalStore: resumeJournalStore,
      credentialStore: credentialStore
    )
    let start = TacuaSDKStartLifecycleCoordinator(
      configuration: configuration,
      consentGate: launchConsentGate,
      credentialFactory: credentialFactory,
      exchanger: exchanger,
      queueStore: queueStore,
      journalStore: startJournalStore,
      resumeRecoveryInspector: resumeJournalStore,
      retentionChecker: retention
    )
    let resume = TacuaSDKResumeLifecycleCoordinator(
      configuration: configuration,
      consentGate: launchConsentGate,
      credentialFactory: credentialFactory,
      exchanger: exchanger,
      queueStore: queueStore,
      startJournalStore: startJournalStore,
      journalStore: resumeJournalStore,
      retentionChecker: retention
    )
    let admission = TacuaCaptureAdmissionCoordinator(
      configuration: configuration,
      captureRootDirectory: captureRoot,
      queueStore: queueStore,
      lifecycleGate: startJournalStore,
      resumeRecoveryInspector: resumeJournalStore,
      retentionChecker: retention
    )
    let upload = TacuaCaptureUploadCoordinator(
      configuration: configuration,
      captureRootDirectory: captureRoot,
      queueStore: queueStore,
      lifecycleGate: startJournalStore,
      resumeRecoveryInspector: resumeJournalStore,
      sender: exchanger,
      retentionChecker: retention
    )
    let deletion = TacuaCaptureDeletionCoordinator(
      configuration: configuration,
      captureRootDirectory: captureRoot,
      queueStore: queueStore,
      lifecycleGate: startJournalStore,
      resumeRecoveryInspector: resumeJournalStore,
      sender: exchanger,
      credentialStore: credentialStore
    )
    let context = BackendLifecycleContext(
      start: start,
      resume: resume,
      queueStore: queueStore,
      startJournalStore: startJournalStore,
      retention: retention,
      admission: admission,
      upload: upload,
      deletion: deletion
    )
    backendLifecycleContext = context
    return context
  }

  private static func backendStartedSessionValue(
    _ started: TacuaSDKStartedSession
  ) -> [String: Any] {
    [
      "localSessionId": started.localSessionID,
      "remoteSessionId": started.remoteSessionID,
      "scopeDigest": started.scopeDigest,
      "credentialId": started.credentialID,
      "credentialExpiresAt": started.credentialExpiresAt,
      "rawMediaExpiresAt": started.rawMediaExpiresAt,
      "credentialCapability": started.credentialCapability.rawValue,
      "credentialAvailability": started.credentialAvailability.rawValue,
      "queueSchemaVersion": started.queueSchemaVersion,
      "resumeRequired": started.resumeRequired,
      "backendSessionState": "receiving",
      "captureStarted": false,
      "uploadsConnected": false,
      "completionConnected": false,
    ]
  }

  private static func startedCapturePlanValue(
    _ plan: TacuaSDKHostStartedCapturePlan
  ) -> [String: Any] {
    [
      "localSessionId": plan.captureOptions.sessionID,
      "backendSession": backendStartedSessionValue(plan.backendSession),
      "captureOptions": captureStartOptionsValue(plan.captureOptions),
    ]
  }

  private static func backendStartRecoveryStatusValue(
    _ status: TacuaSDKStartRecoveryStatus
  ) -> [String: Any] {
    let resumeRequired: Any = status.resumeRequired.map { $0 as Any } ?? NSNull()
    let transportConfigurationMatchesBuild: Any = status.transportConfigurationMatchesBuild
      .map { $0 as Any } ?? NSNull()
    let credentialCapability: Any = status.credentialCapability?.rawValue ?? NSNull()
    let credentialAvailability: Any = status.credentialAvailability?.rawValue ?? NSNull()
    return [
      "localSessionId": status.localSessionID,
      "state": status.state.rawValue,
      "requiresFreshReviewerLaunch": status.requiresFreshReviewerLaunch,
      "remoteSessionMayExist": status.remoteSessionMayExist,
      "canRecoverWithoutLaunch": status.canRecoverWithoutLaunch,
      "canAbandonLocally": status.canAbandonLocally,
      "resumeRequired": resumeRequired,
      "transportConfigurationMatchesBuild": transportConfigurationMatchesBuild,
      "credentialCapability": credentialCapability,
      "credentialAvailability": credentialAvailability,
    ]
  }

  private static func backendResumedSessionValue(
    _ resumed: TacuaSDKResumedSession
  ) -> [String: Any] {
    [
      "localSessionId": resumed.localSessionID,
      "remoteSessionId": resumed.remoteSessionID,
      "scopeDigest": resumed.scopeDigest,
      "credentialId": resumed.credentialID,
      "credentialExpiresAt": resumed.credentialExpiresAt,
      "rawMediaExpiresAt": resumed.rawMediaExpiresAt,
      "backendSessionState": resumed.backendSessionState.rawValue,
      "credentialCapability": resumed.credentialCapability.rawValue,
      "replayCompletionId": resumed.replayCompletionID ?? NSNull(),
      "credentialAvailability": resumed.credentialAvailability.rawValue,
      "queueSchemaVersion": resumed.queueSchemaVersion,
      "pendingRevokedCredentialRemovalCount":
        resumed.pendingRevokedCredentialRemovalCount,
      "resumeRequired": resumed.resumeRequired,
      "captureStarted": false,
      "uploadsConnected": false,
      "completionConnected": false,
    ]
  }

  private static func resumedCapturePlanValue(
    _ plan: TacuaSDKHostResumedCapturePlan
  ) -> [String: Any] {
    let captureOptions: Any = plan.captureOptions.map(captureStartOptionsValue) ?? NSNull()
    return [
      "localSessionId": plan.backendSession.localSessionID,
      "backendSession": backendResumedSessionValue(plan.backendSession),
      "captureOptions": captureOptions,
    ]
  }

  private static func captureStartOptionsValue(
    _ options: TacuaSDKHostCaptureStartOptions
  ) -> [String: Any] {
    [
      "sessionId": options.sessionID,
      "segmentDurationSeconds": options.segmentDurationSeconds,
      "organizationId": options.organizationID,
      "projectId": options.projectID,
      "buildId": options.buildID,
      "handoffId": options.handoffID,
      "handoffTokenIdentifier": options.handoffTokenIdentifier,
      "expiresAt": options.expiresAt,
      "rawMediaExpiresAt": options.rawMediaExpiresAt,
      "consentVersion": options.consentVersion,
      "expectedApplicationId": options.expectedApplicationID,
      "expectedBuildNumber": options.expectedBuildNumber,
    ]
  }

  private static func backendResumeRecoveryStatusValue(
    _ status: TacuaSDKResumeRecoveryStatus
  ) -> [String: Any] {
    [
      "localSessionId": status.localSessionID,
      "state": status.state.rawValue,
      "remoteCredentialMayExist": status.remoteCredentialMayExist,
      "queueUsable": status.queueUsable,
      "canRecoverWithoutLaunch": status.canRecoverWithoutLaunch,
      "canResetPreparedCredential": status.canResetPreparedCredential,
      "requiresReconciliation": status.requiresReconciliation,
    ]
  }

  private static func captureAdmissionValue(
    _ admitted: TacuaCaptureAdmissionResult
  ) -> [String: Any] {
    [
      "localSessionId": admitted.localSessionID,
      "remoteSessionId": admitted.remoteSessionID,
      "admissionDigest": admitted.admissionDigest,
      "diagnosticEnvelopeDigest": admitted.diagnosticEnvelopeDigest,
      "segmentCount": admitted.segmentCount,
      "diagnosticCount": 1,
      "admittedOperationCount": admitted.admittedOperationCount,
      "alreadyAdmitted": admitted.alreadyAdmitted,
      "uploadsConnected": false,
      "completionConnected": false,
    ]
  }

  private static func captureUploadValue(
    _ result: TacuaCaptureUploadResult
  ) -> [String: Any] {
    [
      "localSessionId": result.localSessionID,
      "remoteSessionId": result.remoteSessionID,
      "completionId": result.completionID,
      "segmentReceiptCount": result.segmentReceiptCount,
      "diagnosticReceiptCount": result.diagnosticReceiptCount,
      "payloadCleanupState": result.payloadCleanupState.rawValue,
      "alreadyCompleted": result.alreadyCompleted,
      "uploadsConnected": true,
      "completionConnected": true,
    ]
  }

  private static func captureDeletionValue(
    _ result: TacuaCaptureDeletionResult
  ) -> [String: Any] {
    [
      "localSessionId": result.localSessionID,
      "deletionId": result.deletionID,
      "tombstoneDigest": result.tombstoneDigest,
      "deletionReason": "user_requested",
      "alreadyDeleted": result.alreadyDeleted,
      "remoteDataDeleted": true,
      "localSessionRetired": true,
      "credentialRemoved": true,
    ]
  }

  private static func backendResumeRequirementValue(
    _ requirement: TacuaSDKResumeRequirement
  ) -> [String: Any] {
    [
      "kind": requirement.kind.rawValue,
      "reason": requirement.reason.rawValue,
      "canConsumeApprovedLaunch": requirement.canConsumeApprovedLaunch,
      "expectedSessionState": requirement.expectedSessionState ?? NSNull(),
      "expectedCompletionId": requirement.expectedCompletionID ?? NSNull(),
    ]
  }

  private static func rejectBackendStart(_ promise: Promise, error: Error) {
    let publicError = (error as? TacuaSDKStartLifecycleError) ?? .persistenceFailure
    promise.reject(publicError.code, publicError.message)
  }

  private static func rejectHostStart(_ promise: Promise, error: Error) {
    if let publicError = error as? TacuaSDKHostIntegrationError {
      promise.reject(publicError.code, publicError.message)
      return
    }
    rejectBackendStart(promise, error: error)
  }

  private static func rejectBackendResume(_ promise: Promise, error: Error) {
    let publicError = (error as? TacuaSDKResumeLifecycleError) ?? .persistenceFailure
    promise.reject(publicError.code, publicError.message)
  }

  private static func rejectHostResume(_ promise: Promise, error: Error) {
    if let publicError = error as? TacuaSDKHostIntegrationError {
      promise.reject(publicError.code, publicError.message)
      return
    }
    rejectBackendResume(promise, error: error)
  }

  private static func rejectCaptureAdmission(_ promise: Promise, error: Error) {
    let publicError = (error as? TacuaCaptureAdmissionError) ?? .persistenceFailure
    promise.reject(publicError.code, publicError.message)
  }

  private static func rejectCaptureUpload(_ promise: Promise, error: Error) {
    let publicError = (error as? TacuaCaptureUploadError) ?? .persistenceFailure
    promise.reject(publicError.code, publicError.message)
  }

  private static func rejectCaptureDeletion(_ promise: Promise, error: Error) {
    let publicError = (error as? TacuaCaptureDeletionError) ?? .persistenceFailure
    promise.reject(publicError.code, publicError.message)
  }

  private static func microphonePermissionValue() -> String {
    switch AVAudioApplication.shared.recordPermission {
    case .granted: return "granted"
    case .denied: return "denied"
    case .undetermined: return "undetermined"
    @unknown default: return "unknown"
    }
  }
}
