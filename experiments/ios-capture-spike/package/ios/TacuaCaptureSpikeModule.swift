// SPDX-License-Identifier: Apache-2.0

import AVFAudio
import ExpoModulesCore
import Foundation
import ReplayKit

public final class TacuaCaptureSpikeModule: Module {
  private var session: TacuaCaptureSession?
  private var lastTerminalStatus: [String: Any]?
  private let sessionLock = NSLock()

  public func definition() -> ModuleDefinition {
    Name("TacuaCaptureSpikeModule")

    Events("onState", "onSegment", "onGap", "onMarker", "onError")

    Function("getCapabilities") { () -> [String: Any] in
      let recorder = RPScreenRecorder.shared()
      var result: [String: Any] = [
        "platform": "ios",
        "api": "ReplayKit.startCapture",
        "available": recorder.isAvailable,
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
        "schemaVersion": 2,
      ]
#if TACUA_CAPTURE_FAULT_INJECTION
      result["testFaultInjectionCompiled"] = true
      result["testFaultPlan"] = TacuaCaptureFaultRuntime.configuredProcessPlan()?.rawValue
        ?? NSNull()
      result["testFaultLeaseConsumed"] = TacuaCaptureFaultRuntime.processLeaseWasClaimed
#endif
      return result
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
      return [
        "state": processCleanupPending ? "process_cleanup_pending" : "idle",
        "segmentCount": 0,
        "gapCount": 0,
        "markerCount": 0,
        "errorCodes": [],
        "recorderAvailable": recorder.isAvailable,
        "recorderRecording": recorder.isRecording,
        "maximumDurationSeconds": TacuaCapturePolicy.maximumDurationSeconds,
        "automaticStopHostUptimeSeconds": NSNull(),
        "stopReason": NSNull(),
        "microphoneSamplesObserved": 0,
        "appAudioSamplesObserved": 0,
        "appAudioAvailable": false,
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

    AsyncFunction("listRecoverableSessions") { (promise: Promise) in
      guard self.currentSession() == nil else {
        Self.reject(promise, error: TacuaCaptureSpikeError.captureAlreadyRunning)
        return
      }
      do {
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

  private func startSession(
    options: TacuaCaptureStartOptions,
    resuming: Bool,
    promise: Promise
  ) {
    guard currentSession() == nil else {
      Self.reject(promise, error: TacuaCaptureSpikeError.captureAlreadyRunning)
      return
    }

    do {
      let session = try TacuaCaptureSession(
        options: options,
        resuming: resuming,
        eventSink: { [weak self] name, payload in
          DispatchQueue.main.async {
            self?.sendEvent(name, payload)
          }
        },
        terminalSink: { [weak self] completedSession, snapshot in
          self?.rememberTerminalStatus(snapshot)
          self?.clearSession(ifMatching: completedSession)
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

  private static func microphonePermissionValue() -> String {
    switch AVAudioApplication.shared.recordPermission {
    case .granted: return "granted"
    case .denied: return "denied"
    case .undetermined: return "undetermined"
    @unknown default: return "unknown"
    }
  }
}
