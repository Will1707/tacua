// SPDX-License-Identifier: Apache-2.0

import AVFAudio
import CoreMedia
import CryptoKit
import Foundation
import ReplayKit
import UIKit

final class TacuaCaptureSession {
  final class ExclusiveRecoveryLease {
    private let lock = NSLock()
    private var releaseClosure: (() -> Void)?

    fileprivate init(release: @escaping () -> Void) {
      releaseClosure = release
    }

    func release() {
      lock.lock()
      let closure = releaseClosure
      releaseClosure = nil
      lock.unlock()
      closure?()
    }

    deinit { release() }
  }

  typealias EventSink = (_ name: String, _ payload: [String: Any]) -> Void
  typealias TerminalSink = (_ session: TacuaCaptureSession, _ payload: [String: Any]) -> Void
  typealias StopCompletion = (Result<[String: Any], Error>) -> Void

  private static let resumableStates: Set<String> = [
    "prepared",
    "recording",
    "stopping",
    "recoverable_partial",
    "partial",
    "failed_no_verified_segments",
    "stop_failed_capture_active",
    "start_cleanup_pending",
  ]
  private static let recorderOwnershipLock = NSLock()
  private static var activeRecorderOwnershipToken: UUID?
  private static let captureGapOverflowID = "tacua-capture-gap-overflow"

  let sessionId: String

  private let segmentDurationSeconds: Double
  private let recorder = RPScreenRecorder.shared()
  private let queue = DispatchQueue(label: "dev.tacua.capture-spike.session", qos: .userInitiated)
  private let finalizationGroup = DispatchGroup()
  private let eventSink: EventSink
  private let terminalSink: TerminalSink
  private let directory: URL
  private let manifestURL: URL
  private let recorderOwnershipToken: UUID
  private var diagnosticJournal: TacuaDiagnosticJournal?
  private var diagnosticEventCount = 0
  private var diagnosticContainsCollectionGap = false
  private var diagnosticAppState = TacuaDiagnosticAppState.unknown

  private var manifest: CaptureManifest
  private var durationBudgetSeconds = TacuaCapturePolicy.maximumDurationSeconds
  private var durationStopReason = "maximum_duration"
  private let rawMediaStopHostUptimeSeconds: Double
  private var writer: SegmentWriter?
  private var nextSegmentIndex = 0
  private var latestVideoPTS: CMTime?
  private var latestVideoHostUptimeSeconds: Double?
  private var latestMicrophonePTS: CMTime?
  private var latestMicrophoneHostUptimeSeconds: Double?
  private var isStopping = false
  private var stopFinalizationStarted = false
  private var didCompleteStop = false
  private var terminalSnapshot: [String: Any]?
  private var stopCompletions: [StopCompletion] = []
  private var pendingStartCompletion: ((Result<[String: Any], Error>) -> Void)?
  private var recorderStartIssued = false
  private var recorderStartCompletionResolved = false
  private var recorderOwnershipReleased = false
  private var manifestPersistenceFailed = false
  private var stopAttempt = 0
  private var stopAttemptGeneration = 0
  private var stopAttemptSuppressedRecorderCall = false
  private var bypassInjectedStopBehavior = false
  private var realStopGeneration: Int?
  private var stopMustRepeatAfterStartResolution = false
  private var moduleDestructionRequested = false
  private var observers: [NSObjectProtocol] = []
  private var backgroundGapId: String?
  private var pendingResumeGapId: String?
  private var foregroundReturnHostUptimeSeconds: Double?
  private var microphoneNeedsValidation = true
  private var startWatchdog: DispatchWorkItem?
  private var stopWatchdog: DispatchWorkItem?
  private var durationWorkItem: DispatchWorkItem?
  private var microphoneWatchdog: DispatchWorkItem?
  private var destructionRetryWorkItem: DispatchWorkItem?
  private var idleTimerOverrideActive = false
  private var idleTimerWasDisabledBeforeCapture = false

  private var acceptsCaptureSamples: Bool {
    manifest.state == "recording" || manifest.state == "stop_failed_capture_active"
  }
#if TACUA_CAPTURE_FAULT_INJECTION
  private let faultInjection: TacuaCaptureFaultLease?
  private var faultStopInvocationCount = 0
#endif

  init(
    options: TacuaCaptureStartOptions,
    resuming: Bool = false,
    rawMediaStopHostUptimeSeconds: Double,
    eventSink: @escaping EventSink,
    terminalSink: @escaping TerminalSink
  ) throws {
    guard Self.isValidSessionId(options.sessionId) else {
      throw TacuaCaptureSpikeError.invalidSessionId
    }
    guard (2...60).contains(options.segmentDurationSeconds) else {
      throw TacuaCaptureSpikeError.invalidSegmentDuration
    }
    let handoff = Self.handoff(from: options)
    try Self.validateCandidateHandoff(handoff)
    guard Self.protocolDate(options.rawMediaExpiresAt) != nil else {
      throw TacuaCaptureSpikeError.retentionAuthorityInvalid
    }
    let retentionNowUptime = ProcessInfo.processInfo.systemUptime
    guard rawMediaStopHostUptimeSeconds.isFinite,
      rawMediaStopHostUptimeSeconds > retentionNowUptime
    else { throw TacuaCaptureSpikeError.retentionExpired }
    self.rawMediaStopHostUptimeSeconds = rawMediaStopHostUptimeSeconds
    let retentionBudget = rawMediaStopHostUptimeSeconds - retentionNowUptime

    let ownershipToken = UUID()
    guard Self.claimRecorderOwnership(ownershipToken) else {
      throw TacuaCaptureSpikeError.captureAlreadyRunning
    }
    var initializationCompleted = false
    defer {
      if !initializationCompleted {
        Self.releaseRecorderOwnership(ownershipToken)
      }
    }
    recorderOwnershipToken = ownershipToken

#if TACUA_CAPTURE_FAULT_INJECTION
    faultInjection = TacuaCaptureFaultRuntime.claimProcessLease()
#endif

    sessionId = options.sessionId
    segmentDurationSeconds = options.segmentDurationSeconds
    self.eventSink = eventSink
    self.terminalSink = terminalSink

    let root = try Self.storageRoot(create: true)
#if TACUA_CAPTURE_FAULT_INJECTION
    if faultInjection?.shouldFailPreparationStorageCheck == true {
      throw TacuaCaptureSpikeError.insufficientStorage
    }
#endif
    guard Self.hasMinimumFreeStorage(at: root) else {
      throw TacuaCaptureSpikeError.insufficientStorage
    }
    directory = root.appendingPathComponent(options.sessionId, isDirectory: true)
    manifestURL = directory.appendingPathComponent("manifest.json")

    let fileManager = FileManager.default
    if resuming {
      guard fileManager.fileExists(atPath: directory.path) else {
        throw TacuaCaptureSpikeError.sessionNotRecoverable
      }
      let data: Data
      do {
        data = try Data(contentsOf: manifestURL)
        manifest = try JSONDecoder().decode(CaptureManifest.self, from: data)
      } catch {
        throw TacuaCaptureSpikeError.recoveryIO(
          "The stored capture manifest could not be read for recovery."
        )
      }
      try Self.validateStoredSessionId(manifest: manifest, expected: options.sessionId)
      try Self.validateStoredIdentity(manifest: manifest, handoff: handoff)
      guard manifest.rawMediaExpiresAt == options.rawMediaExpiresAt else {
        throw TacuaCaptureSpikeError.retentionAuthorityInvalid
      }
      guard manifest.gaps.count <= TacuaCapturePolicy.maximumManifestGaps,
        manifest.markers.count <= TacuaCapturePolicy.maximumManifestMarkers,
        Set(manifest.gaps.map(\.id)).count == manifest.gaps.count,
        Set(manifest.markers.map(\.id)).count == manifest.markers.count
      else {
        throw TacuaCaptureSpikeError.recoveryIO(
          "The stored capture manifest exceeds its bounded marker or gap limit."
        )
      }
      guard TacuaCapturePolicy.canResumeStoredSession(
        schemaVersion: manifest.schemaVersion,
        storedBootSessionID: manifest.bootSessionId,
        currentBootSessionID: TacuaSystemMonotonicClock().bootSessionID
      ) else { throw TacuaCaptureSpikeError.sessionNotRecoverable }
      guard Self.resumableStates.contains(manifest.state) else {
        throw TacuaCaptureSpikeError.sessionNotRecoverable
      }
      _ = Self.reconcileFinalizedSegments(in: directory, manifest: &manifest)
      let recordedDuration = manifest.segments.reduce(0) { $0 + max(0, $1.durationSeconds) }
      guard recordedDuration < TacuaCapturePolicy.maximumDurationSeconds else {
        throw TacuaCaptureSpikeError.sessionNotRecoverable
      }
      durationBudgetSeconds = TacuaCapturePolicy.maximumDurationSeconds - recordedDuration
      if retentionBudget < durationBudgetSeconds {
        durationBudgetSeconds = retentionBudget
        durationStopReason = "raw_media_retention_expired"
      }
      nextSegmentIndex = (manifest.segments.map(\.index).max() ?? -1) + 1
      if let lastPTS = manifest.segments.last?.lastMediaPTSSeconds {
        latestVideoPTS = CMTime(seconds: lastPTS, preferredTimescale: 1_000_000_000)
      }
      manifest.handoffTokenIdentifier = handoff.handoffTokenIdentifier
      manifest.expiresAt = handoff.expiresAt
      manifest.state = "prepared"
      manifest.stoppedHostUptimeSeconds = nil
      manifest.stopReason = nil
      manifest.resumeCount = (manifest.resumeCount ?? 0) + 1
      manifest.lastResumedAt = Self.iso8601(Date())
      let resumeGap = CaptureGap(
        id: UUID().uuidString,
        reason: "process_resume",
        openedHostUptimeSeconds: ProcessInfo.processInfo.systemUptime,
        closedHostUptimeSeconds: nil,
        priorMediaPTSSeconds: latestVideoPTS.map(CMTimeGetSeconds),
        nextMediaPTSSeconds: nil
      )
      let boundedResumeGap = Self.appendBoundedGap(resumeGap, to: &manifest)
      pendingResumeGapId = boundedResumeGap.id
      try persistManifest()
    } else {
      let bootSessionID = TacuaSystemMonotonicClock().bootSessionID
      guard !bootSessionID.isEmpty else {
        throw TacuaCaptureSpikeError.storageIO(
          "Tacua could not establish a durable boot identity for capture timing."
        )
      }
      if fileManager.fileExists(atPath: directory.path) {
        throw TacuaCaptureSpikeError.writerCreation("The requested capture session already exists.")
      }
      try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
      try Self.protectAndExcludeFromBackup(directory)

      manifest = CaptureManifest(
        schemaVersion: 3,
        bootSessionId: bootSessionID,
        sessionId: options.sessionId,
        organizationId: options.organizationId,
        projectId: options.projectId,
        buildId: options.buildId,
        handoffId: options.handoffId,
        handoffTokenIdentifier: options.handoffTokenIdentifier,
        expiresAt: options.expiresAt,
        rawMediaExpiresAt: options.rawMediaExpiresAt,
        consentVersion: options.consentVersion,
        expectedApplicationId: options.expectedApplicationId,
        expectedBuildNumber: options.expectedBuildNumber,
        createdAt: Self.iso8601(Date()),
        segmentDurationSeconds: options.segmentDurationSeconds,
        maximumDurationSeconds: TacuaCapturePolicy.maximumDurationSeconds,
        state: "prepared",
        startedAt: nil,
        automaticStopAt: nil,
        startedHostUptimeSeconds: nil,
        automaticStopHostUptimeSeconds: nil,
        stoppedHostUptimeSeconds: nil,
        stopReason: nil,
        resumeCount: 0,
        lastResumedAt: nil,
        segments: [],
        gaps: [],
        markers: [],
        calibrations: [],
        errorCodes: [],
        droppedBeforeFirstVideo: ["appAudio": 0, "microphone": 0],
        droppedDuringBackground: ["appAudio": 0, "microphone": 0],
        microphoneSamplesObserved: 0,
        appAudioSamplesObserved: 0
      )
      try persistManifest()
    }
    guard let bootSessionID = manifest.bootSessionId else {
      throw TacuaCaptureSpikeError.storageIO(
        "Tacua could not bind the diagnostic journal to the capture boot identity."
      )
    }
    do {
      let journal = try TacuaDiagnosticJournal(
        rootDirectory: TacuaDiagnosticJournal.rootDirectory(sessionDirectory: directory),
        localSessionID: options.sessionId,
        bootSessionID: bootSessionID,
        // Two runtime-envelope slots are reserved for the terminal summary and an explicit
        // projection-overflow signal.
        maximumEvents: TacuaCapturePolicy.maximumDiagnosticJournalEvents
      )
      let diagnosticSnapshot = try journal.snapshot()
      diagnosticJournal = journal
      diagnosticEventCount = diagnosticSnapshot.entries.count
      diagnosticContainsCollectionGap = diagnosticSnapshot.containsCollectionGap
      diagnosticAppState = diagnosticSnapshot.entries.reversed().compactMap { entry in
        if case .event(.appStateChanged(_, let toState)) = entry.event { return toState }
        return nil
      }.first ?? .unknown
    } catch {
      throw resuming
        ? TacuaCaptureSpikeError.recoveryIO(
          "The stored diagnostic journal failed its recovery integrity checks."
        )
        : TacuaCaptureSpikeError.storageIO(
          "Tacua could not create the private diagnostic journal."
        )
    }
    initializationCompleted = true
  }

  deinit {
    startWatchdog?.cancel()
    stopWatchdog?.cancel()
    durationWorkItem?.cancel()
    microphoneWatchdog?.cancel()
    destructionRetryWorkItem?.cancel()
    removeLifecycleObservers()
    if !recorderOwnershipReleased {
      Self.releaseRecorderOwnership(recorderOwnershipToken)
    }
  }

  func start(completion: @escaping (Result<[String: Any], Error>) -> Void) {
    queue.async { [self] in
      guard pendingStartCompletion == nil, manifest.state == "prepared" else {
        completion(.failure(TacuaCaptureSpikeError.captureAlreadyRunning))
        return
      }
      pendingStartCompletion = completion
      guard recorder.isAvailable else {
        completeStartFailureOnQueue(TacuaCaptureSpikeError.captureUnavailable)
        return
      }
      scheduleStartWatchdogOnQueue()
      DispatchQueue.main.async { [self] in
        AVAudioApplication.requestRecordPermission { [weak self] granted in
          guard let self else { return }
          self.queue.async {
            guard self.pendingStartCompletion != nil else { return }
            guard granted else {
              self.completeStartFailureOnQueue(TacuaCaptureSpikeError.microphonePermissionDenied)
              return
            }
            DispatchQueue.main.async { [self] in
              self.beginRecorderStartOnMain()
            }
          }
        }
      }
    }
  }

  func stop(completion: @escaping StopCompletion) {
    requestStop(reason: "manual", completion: completion)
  }

  func cancelForModuleDestruction() {
    queue.async { [self] in
      moduleDestructionRequested = true
      if let completion = pendingStartCompletion {
        pendingStartCompletion = nil
        if !recorderStartIssued {
          startWatchdog?.cancel()
          startWatchdog = nil
        }
        completion(.failure(TacuaCaptureSpikeError.moduleDestroyed))
      }
      recordError(
        TacuaCaptureSpikeError.moduleDestroyed.code,
        gapReason: "module_destroyed"
      )
      bypassInjectedStopBehavior = true
      if isStopping,
        stopAttemptSuppressedRecorderCall,
        !stopFinalizationStarted,
        !didCompleteStop
      {
        // A QA timeout can deliberately omit ReplayKit's callback without ever
        // issuing stopCapture. Invalidate that attempt so module teardown always
        // has a live cleanup owner and makes a real bounded stop request.
        stopAttemptGeneration += 1
        stopWatchdog?.cancel()
        stopWatchdog = nil
        stopAttemptSuppressedRecorderCall = false
        isStopping = false
      }
      requestStopOnQueue(reason: "module_destroyed")
    }
  }

  func mark(label: String, completion: @escaping (Result<[String: Any], Error>) -> Void) {
    queue.async { [self] in
      guard label.range(of: "^[A-Za-z0-9._-]{1,80}$", options: .regularExpression) != nil else {
        completion(.failure(TacuaCaptureSpikeError.invalidMarkerLabel))
        return
      }
      guard manifest.state == "recording", !isStopping else {
        completion(.failure(TacuaCaptureSpikeError.noCaptureRunning))
        return
      }
      guard manifest.markers.count < TacuaCapturePolicy.maximumManifestMarkers else {
        completion(.failure(TacuaCaptureSpikeError.markerLimitReached))
        return
      }
      let marker = CaptureMarker(
        id: UUID().uuidString,
        label: label,
        hostUptimeSeconds: ProcessInfo.processInfo.systemUptime,
        latestMediaPTSSeconds: latestVideoPTS.map(CMTimeGetSeconds)
      )
      manifest.markers.append(marker)
      appendSystemDiagnosticBestEffort(.issueMark(
        markerID: Self.stableDiagnosticIdentifier(prefix: "m", source: marker.id),
        kind: .manual
      ))
      persistManifestAndReport()
      let payload: [String: Any] = [
        "id": marker.id,
        "label": marker.label,
        "hostUptimeSeconds": marker.hostUptimeSeconds,
        "latestMediaPTSSeconds": jsonValue(marker.latestMediaPTSSeconds),
      ]
      eventSink("onMarker", payload)
      completion(.success(payload))
    }
  }

  func recordDiagnostic(
    _ event: TacuaDiagnosticJournalEvent,
    completion: @escaping (Result<[String: Any], Error>) -> Void
  ) {
    queue.async { [self] in
      guard manifest.state == "recording", !isStopping else {
        completion(.failure(TacuaCaptureSpikeError.noCaptureRunning))
        return
      }
      guard let diagnosticJournal else {
        completion(.failure(TacuaCaptureSpikeError.diagnosticUnavailable))
        return
      }
      do {
        let entry = try diagnosticJournal.append(event)
        if entry.sequence > Int64(diagnosticEventCount + 1) {
          diagnosticContainsCollectionGap = true
        }
        diagnosticEventCount = max(diagnosticEventCount, Int(entry.sequence))
        completion(.success(Self.diagnosticReceipt(entry)))
      } catch {
        completion(.failure(Self.captureDiagnosticError(error)))
      }
    }
  }

  func status() -> [String: Any] {
    queue.sync { snapshot() }
  }

  static func listRecoverableSessions() throws -> [[String: Any]] {
    let root = try storageRoot(create: false)
    guard FileManager.default.fileExists(atPath: root.path) else { return [] }
    let directories = try FileManager.default.contentsOfDirectory(
      at: root,
      includingPropertiesForKeys: [.isDirectoryKey],
      options: [.skipsHiddenFiles]
    )

    return directories.compactMap { directory in
      guard (try? directory.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
        return nil
      }
      let manifestURL = directory.appendingPathComponent("manifest.json")
      guard let data = try? Data(contentsOf: manifestURL),
        var manifest = try? JSONDecoder().decode(CaptureManifest.self, from: data)
      else {
        return [
          "sessionId": directory.lastPathComponent,
          "state": "manifest_unreadable",
          "segmentCount": 0,
          "partialFileCount": partialFileCount(in: directory),
        ]
      }
      let recoveredSegmentCount = reconcileFinalizedSegments(in: directory, manifest: &manifest)
      markInterruptedStateIfNeeded(manifest: &manifest)
      try? persist(manifest: manifest, to: manifestURL)
      return recoverySnapshot(
        manifest: manifest,
        directory: directory,
        recoveredSegmentCount: recoveredSegmentCount
      )
    }.sorted { left, right in
      (left["createdAt"] as? String ?? "") < (right["createdAt"] as? String ?? "")
    }
  }

  static func markPartialReadyForUpload(options: TacuaCaptureRecoveryOptions) throws -> [String: Any] {
    guard isValidSessionId(options.sessionId) else {
      throw TacuaCaptureSpikeError.invalidSessionId
    }
    let handoff = handoff(from: options)
    try validateCandidateHandoff(handoff)
    let root = try storageRoot(create: false)
    let directory = root.appendingPathComponent(options.sessionId, isDirectory: true)
    let manifestURL = directory.appendingPathComponent("manifest.json")
    var manifest = try readManifest(at: manifestURL)
    try validateStoredSessionId(manifest: manifest, expected: options.sessionId)
    try validateStoredIdentity(manifest: manifest, handoff: handoff)
    let recovered = reconcileFinalizedSegments(in: directory, manifest: &manifest)
    markInterruptedStateIfNeeded(manifest: &manifest)
    guard !manifest.segments.isEmpty else {
      throw TacuaCaptureSpikeError.sessionHasNoVerifiedSegments
    }
    guard manifest.state != "completed" else {
      throw TacuaCaptureSpikeError.sessionNotRecoverable
    }
    manifest.handoffTokenIdentifier = handoff.handoffTokenIdentifier
    manifest.expiresAt = handoff.expiresAt
    manifest.state = "partial_ready_for_upload"
    try persist(manifest: manifest, to: manifestURL)
    return recoverySnapshot(
      manifest: manifest,
      directory: directory,
      recoveredSegmentCount: recovered
    )
  }

  static func deleteSession(options: TacuaCaptureRecoveryOptions) throws {
    guard isValidSessionId(options.sessionId) else {
      throw TacuaCaptureSpikeError.invalidSessionId
    }
    let handoff = handoff(from: options)
    try validateDeletionScope(handoff)
    let root = try storageRoot(create: false)
    let target = root.appendingPathComponent(options.sessionId, isDirectory: true)
    guard target.deletingLastPathComponent().standardizedFileURL == root.standardizedFileURL else {
      throw TacuaCaptureSpikeError.invalidSessionId
    }
    guard FileManager.default.fileExists(atPath: target.path) else { return }
    let manifest = try readManifest(at: target.appendingPathComponent("manifest.json"))
    try validateStoredSessionId(manifest: manifest, expected: options.sessionId)
    try validateStoredDeletionIdentity(manifest: manifest, handoff: handoff)
    try FileManager.default.removeItem(at: target)
  }

  private func beginRecorderStartOnMain() {
    let shouldStart = queue.sync { () -> Bool in
      guard pendingStartCompletion != nil, manifest.state == "prepared" else { return false }
      recorderStartIssued = true
      return true
    }
    guard shouldStart else { return }

    activateIdleTimerOverrideOnMain()
    recorder.isMicrophoneEnabled = true
    recorder.startCapture(
      handler: { [weak self] sampleBuffer, sampleType, error in
        guard let self else { return }
        let uptime = ProcessInfo.processInfo.systemUptime
        self.queue.async {
          if error != nil {
            self.failAndStopOnQueue(
              error: TacuaCaptureSpikeError.captureHandlerFailed,
              gapReason: "capture_handler_error"
            )
            return
          }
          guard !self.isStopping else { return }
          self.process(sampleBuffer, type: sampleType, hostUptimeSeconds: uptime)
        }
      },
      // ReplayKit owns this completion until the start attempt resolves. Keep
      // the session alive through that point so a module teardown cannot drop
      // the only cleanup owner just before a late successful start callback.
      completionHandler: { [self] error in
        self.queue.async {
          self.recorderStartCompletionResolved = true
          self.startWatchdog?.cancel()
          self.startWatchdog = nil
          guard self.pendingStartCompletion != nil else {
            if error == nil {
              if !self.isStopping {
                self.isStopping = true
                self.manifest.state = "stopping"
                self.manifest.stopReason = "late_start_cleanup"
                self.persistManifestAndReport()
                self.emitState()
              }
              if self.stopWatchdog != nil || self.realStopGeneration != nil {
                self.stopMustRepeatAfterStartResolution = true
              } else {
                self.stopAttempt = 0
                self.issueStopAttemptOnQueue()
              }
            } else if self.isStopping {
              if self.stopWatchdog == nil, self.realStopGeneration == nil {
                self.finalizeAfterRecorderStopOnQueue()
              }
            } else {
              self.releaseRecorderOwnershipIfSafeOnQueue()
            }
            return
          }
          if let error {
            self.completeStartFailureOnQueue(
              TacuaCaptureSpikeError.captureStartFailed(error.tacuaStableCode)
            )
            return
          }

          self.startWatchdog?.cancel()
          self.startWatchdog = nil
          let startCompletion = self.pendingStartCompletion
          self.pendingStartCompletion = nil
          let now = Date()
          let uptime = ProcessInfo.processInfo.systemUptime
          let remainingRetention = max(0, self.rawMediaStopHostUptimeSeconds - uptime)
          if remainingRetention < self.durationBudgetSeconds {
            self.durationBudgetSeconds = remainingRetention
            self.durationStopReason = "raw_media_retention_expired"
          }
          self.manifest.state = "recording"
          if self.manifest.startedAt == nil {
            self.manifest.startedAt = Self.iso8601(now)
          }
          self.manifest.startedHostUptimeSeconds =
            TacuaCapturePolicy.preservedSessionStartHostUptime(
              existing: self.manifest.startedHostUptimeSeconds,
              resumeCandidate: uptime
            )
          self.manifest.automaticStopAt = Self.iso8601(
            now.addingTimeInterval(self.durationBudgetSeconds)
          )
          self.manifest.automaticStopHostUptimeSeconds = uptime + self.durationBudgetSeconds
          self.installLifecycleObservers()
          self.transitionDiagnosticAppState(to: .active)
          self.scheduleDurationStopOnQueue()
          self.scheduleMicrophoneWatchdogOnQueue()
          self.persistManifestAndReport()
          let snapshot = self.snapshot()
          self.emitState()
          startCompletion?(.success(snapshot))
        }
      }
    )
  }

  private func completeStartFailureOnQueue(_ error: TacuaCaptureSpikeError) {
    guard let completion = pendingStartCompletion else { return }
    pendingStartCompletion = nil
    startWatchdog?.cancel()
    startWatchdog = nil
    let unresolvedRecorderStart = recorderStartIssued && !recorderStartCompletionResolved
    appendErrorCode(error.code)
    manifest.state = unresolvedRecorderStart ? "start_cleanup_pending" : "start_failed"
    if unresolvedRecorderStart {
      isStopping = true
      stopAttempt = 0
      manifest.stopReason = "start_timeout_cleanup"
    }
    persistManifestAndReport()
    emitState()
    restoreIdleTimerOverride()
    releaseRecorderOwnershipIfSafeOnQueue()
    completion(.failure(error))
    if unresolvedRecorderStart {
      issueStopAttemptOnQueue()
    }
  }

  private func scheduleStartWatchdogOnQueue() {
    startWatchdog?.cancel()
    let workItem = DispatchWorkItem { [self] in
      startWatchdog = nil
      if pendingStartCompletion != nil {
        completeStartFailureOnQueue(TacuaCaptureSpikeError.startTimeout)
      } else if recorderStartIssued, !recorderStartCompletionResolved, isStopping {
        recordError(
          TacuaCaptureSpikeError.startTimeout.code,
          gapReason: "start_capture_timeout"
        )
        manifest.state = "start_cleanup_pending"
        persistManifestAndReport()
        emitState()
        if stopWatchdog == nil, realStopGeneration == nil {
          stopAttempt = 0
          issueStopAttemptOnQueue()
        }
      }
    }
    startWatchdog = workItem
    queue.asyncAfter(
      deadline: .now() + TacuaCapturePolicy.startWatchdogSeconds,
      execute: workItem
    )
  }

  private func requestStop(reason: String, completion: StopCompletion?) {
    queue.async { [self] in
      if let terminalSnapshot {
        completion?(.success(terminalSnapshot))
        return
      }
      if let completion { stopCompletions.append(completion) }
      requestStopOnQueue(reason: reason)
    }
  }

  private func requestStopOnQueue(reason: String) {
    guard !didCompleteStop else { return }
    if isStopping {
      if realStopGeneration != nil, stopWatchdog == nil {
        // A real ReplayKit stop call crossed its watchdog but has not returned.
        // Do not overlap another stopCapture call with it. Keep ownership until
        // its callback arrives, and keep explicit callers bounded meanwhile.
        rejectStopCompletionsOnQueue(TacuaCaptureSpikeError.stopTimeout)
        if moduleDestructionRequested {
          scheduleDestructionStopRetryOnQueue()
        }
        return
      }
      if manifest.state == "start_cleanup_pending",
        stopWatchdog == nil,
        realStopGeneration == nil,
        !stopFinalizationStarted
      {
        stopAttempt = 0
        issueStopAttemptOnQueue()
      }
      return
    }

    let shouldFinalizeWithoutRecorder = manifest.state == "prepared" && !recorderStartIssued

    if let startCompletion = pendingStartCompletion {
      pendingStartCompletion = nil
      if !recorderStartIssued {
        startWatchdog?.cancel()
        startWatchdog = nil
      }
      startCompletion(
        .failure(TacuaCaptureSpikeError.captureStartCancelled)
      )
    }

    isStopping = true
    stopAttempt = 0
    durationWorkItem?.cancel()
    durationWorkItem = nil
    microphoneWatchdog?.cancel()
    microphoneWatchdog = nil
    let waitingForStartResolution = recorderStartIssued && !recorderStartCompletionResolved
    manifest.state = waitingForStartResolution ? "start_cleanup_pending" : "stopping"
    manifest.stopReason = reason
    persistManifestAndReport()
    emitState()
    if shouldFinalizeWithoutRecorder {
      finalizeAfterRecorderStopOnQueue()
    } else if waitingForStartResolution, !moduleDestructionRequested {
      // The start completion will issue the first serialized live stop. The
      // existing start watchdog remains the bounded fallback if ReplayKit omits it.
      return
    } else {
      issueStopAttemptOnQueue()
    }
  }

  private func issueStopAttemptOnQueue() {
    guard isStopping, !stopFinalizationStarted, !didCompleteStop else { return }
    guard stopWatchdog == nil, realStopGeneration == nil else { return }
    stopAttempt += 1
    stopAttemptGeneration += 1
#if TACUA_CAPTURE_FAULT_INJECTION
    faultStopInvocationCount += 1
    let faultInvocation = faultStopInvocationCount
    let injectedStopBehavior = bypassInjectedStopBehavior
      ? TacuaCaptureInjectedStopBehavior.none
      : faultInjection?.stopBehavior(attempt: faultInvocation) ?? .none
    stopAttemptSuppressedRecorderCall = injectedStopBehavior != .none
#else
    stopAttemptSuppressedRecorderCall = false
#endif
    let generation = stopAttemptGeneration
    if !stopAttemptSuppressedRecorderCall {
      realStopGeneration = generation
    }
    scheduleStopWatchdogOnQueue(generation: generation)
    DispatchQueue.main.async { [self] in
#if TACUA_CAPTURE_FAULT_INJECTION
      switch injectedStopBehavior {
      case .timeout:
        // The real recorder remains active. The production watchdog observes
        // that state and drives retry/preservation exactly as it would if
        // ReplayKit omitted its callback.
        return
      case .failure:
        let recorderStillRecording = recorder.isRecording
        queue.async {
          self.handleStopAttemptResultOnQueue(
            generation: generation,
            recorderStillRecording: recorderStillRecording,
            error: TacuaCaptureSpikeError.captureStopFailed
          )
        }
        return
      case .none:
        break
      }
#endif
      let shouldInvokeLiveStop = queue.sync {
        realStopGeneration == generation
          && isStopping
          && !stopFinalizationStarted
          && !didCompleteStop
      }
      guard shouldInvokeLiveStop else { return }
      recorder.stopCapture { [self] error in
        let recorderStillRecording = recorder.isRecording
        queue.async {
          if self.realStopGeneration == generation {
            self.realStopGeneration = nil
          }
          self.handleStopAttemptResultOnQueue(
            generation: generation,
            recorderStillRecording: recorderStillRecording,
            error: error
          )
        }
      }
    }
  }

  private func scheduleStopWatchdogOnQueue(generation: Int) {
    stopWatchdog?.cancel()
    let workItem = DispatchWorkItem { [self] in
      guard generation == stopAttemptGeneration,
        isStopping,
        !stopFinalizationStarted,
        !didCompleteStop
      else { return }
      DispatchQueue.main.async { [self] in
        let recorderStillRecording = recorder.isRecording
        queue.async {
          guard generation == self.stopAttemptGeneration,
            self.isStopping,
            !self.stopFinalizationStarted,
            !self.didCompleteStop
          else { return }
          self.recordError(
            TacuaCaptureSpikeError.stopTimeout.code,
            gapReason: "stop_capture_timeout"
          )
          if self.realStopGeneration == generation {
            // The watchdog bounds the caller, not ReplayKit's ownership of its
            // in-flight callback. Retain the generation and process lease so a
            // retry cannot overlap the live stopCapture call. A late callback
            // will resume the serialized coordinator.
            self.stopWatchdog?.cancel()
            self.stopWatchdog = nil
            self.manifest.state = self.recorderStartIssued
              && !self.recorderStartCompletionResolved
              ? "start_cleanup_pending"
              : "stopping"
            self.persistManifestAndReport()
            self.emitState()
            self.rejectStopCompletionsOnQueue(TacuaCaptureSpikeError.stopTimeout)
            if self.moduleDestructionRequested {
              self.scheduleDestructionStopRetryOnQueue()
            }
            return
          }
          self.handleStopAttemptResultOnQueue(
            generation: generation,
            recorderStillRecording: recorderStillRecording,
            error: nil
          )
        }
      }
    }
    stopWatchdog = workItem
    queue.asyncAfter(
      deadline: .now() + TacuaCapturePolicy.stopWatchdogSeconds,
      execute: workItem
    )
  }

  private func handleStopAttemptResultOnQueue(
    generation: Int,
    recorderStillRecording: Bool,
    error: Error?
  ) {
    guard generation == stopAttemptGeneration,
      isStopping,
      !stopFinalizationStarted,
      !didCompleteStop
    else { return }
    stopAttemptSuppressedRecorderCall = false
    stopWatchdog?.cancel()
    stopWatchdog = nil
    if error != nil {
      recordError(
        TacuaCaptureSpikeError.captureStopFailed.code,
        gapReason: "stop_capture_error"
      )
    }
    if stopMustRepeatAfterStartResolution {
      stopMustRepeatAfterStartResolution = false
      stopAttempt = 0
      issueStopAttemptOnQueue()
      return
    }

    switch TacuaCapturePolicy.stopTimeoutDisposition(
      recorderStillRecording: recorderStillRecording,
      attempt: stopAttempt
    ) {
    case .finalizeStopped:
      finalizeAfterRecorderStopOnQueue()
    case .retry:
      issueStopAttemptOnQueue()
    case .preserveActiveSession:
      preserveActiveStopFailureOnQueue()
    }
  }

  private func preserveActiveStopFailureOnQueue() {
    stopWatchdog?.cancel()
    stopWatchdog = nil
    realStopGeneration = nil
    if moduleDestructionRequested {
      manifest.state = "stopping"
      persistManifestAndReport()
      emitState()
      scheduleDestructionStopRetryOnQueue()
      return
    }
    if recorderStartIssued, !recorderStartCompletionResolved {
      manifest.state = "start_cleanup_pending"
      persistManifestAndReport()
      emitState()
      let completions = stopCompletions
      stopCompletions.removeAll()
      for completion in completions {
        completion(.failure(TacuaCaptureSpikeError.stopTimeout))
      }
      return
    }
    isStopping = false
    manifest.state = "stop_failed_capture_active"
    persistManifestAndReport()
    emitState()
    rejectStopCompletionsOnQueue(TacuaCaptureSpikeError.stopTimeout)
  }

  private func rejectStopCompletionsOnQueue(_ error: TacuaCaptureSpikeError) {
    let completions = stopCompletions
    stopCompletions.removeAll()
    for completion in completions {
      completion(.failure(error))
    }
  }

  private func scheduleDestructionStopRetryOnQueue() {
    destructionRetryWorkItem?.cancel()
    let workItem = DispatchWorkItem { [self] in
      guard moduleDestructionRequested,
        isStopping,
        !stopFinalizationStarted,
        !didCompleteStop
      else { return }
      destructionRetryWorkItem = nil
      if realStopGeneration != nil {
        // Keep this cleanup owner alive while ReplayKit still owns a timed-out
        // real callback. Retrying here would create overlapping live calls.
        scheduleDestructionStopRetryOnQueue()
        return
      }
      stopAttempt = 0
      issueStopAttemptOnQueue()
    }
    destructionRetryWorkItem = workItem
    queue.asyncAfter(deadline: .now() + 5, execute: workItem)
  }

  private func finalizeAfterRecorderStopOnQueue() {
    guard !stopFinalizationStarted else { return }
    if recorderStartIssued, !recorderStartCompletionResolved {
      manifest.state = "start_cleanup_pending"
      persistManifestAndReport()
      emitState()
      let completions = stopCompletions
      stopCompletions.removeAll()
      for completion in completions {
        completion(.failure(TacuaCaptureSpikeError.startCleanupPending))
      }
      if moduleDestructionRequested {
        scheduleDestructionStopRetryOnQueue()
      }
      return
    }
    stopFinalizationStarted = true
    destructionRetryWorkItem?.cancel()
    destructionRetryWorkItem = nil
    stopWatchdog?.cancel()
    stopWatchdog = nil
    finishCurrentSegment()
    finalizationGroup.notify(queue: queue) { [self] in
      finishStopOnQueue()
    }
  }

  private func scheduleDurationStopOnQueue() {
    durationWorkItem?.cancel()
    let workItem = DispatchWorkItem { [self] in
      guard manifest.state == "recording", !isStopping else { return }
      requestStopOnQueue(reason: durationStopReason)
    }
    durationWorkItem = workItem
    queue.asyncAfter(deadline: .now() + durationBudgetSeconds, execute: workItem)
  }

  private func scheduleMicrophoneWatchdogOnQueue() {
    microphoneWatchdog?.cancel()
    microphoneNeedsValidation = true
    let workItem = DispatchWorkItem { [self] in
      guard manifest.state == "recording", microphoneNeedsValidation, !isStopping else { return }
      failAndStopOnQueue(
        error: TacuaCaptureSpikeError.microphoneSamplesMissing,
        gapReason: "microphone_samples_missing"
      )
    }
    microphoneWatchdog = workItem
    queue.asyncAfter(
      deadline: .now() + TacuaCapturePolicy.microphoneStartupWatchdogSeconds,
      execute: workItem
    )
  }

  private func process(
    _ sampleBuffer: CMSampleBuffer,
    type: RPSampleBufferType,
    hostUptimeSeconds: Double
  ) {
    guard acceptsCaptureSamples, !isStopping else { return }
    if !TacuaCapturePolicy.shouldAdmitCaptureSample(
      backgroundGapOpen: backgroundGapId != nil,
      foregroundSignalObserved: foregroundReturnHostUptimeSeconds != nil
    ) {
      var dropped = manifest.droppedDuringBackground ?? [:]
      switch type {
      case .video: dropped["video", default: 0] += 1
      case .audioApp: dropped["appAudio", default: 0] += 1
      case .audioMic: dropped["microphone", default: 0] += 1
      @unknown default: break
      }
      manifest.droppedDuringBackground = dropped
      return
    }
    if TacuaCapturePolicy.hasReachedDeadline(
      hostUptimeSeconds: hostUptimeSeconds,
      deadlineHostUptimeSeconds: manifest.automaticStopHostUptimeSeconds
    ) {
      requestStopOnQueue(reason: durationStopReason)
      return
    }

    let incomingPTS = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
    let incomingPTSSeconds = CMTimeGetSeconds(incomingPTS)
    if type == .video, (!incomingPTS.isValid || !incomingPTSSeconds.isFinite) {
      failAndStopOnQueue(
        error: TacuaCaptureSpikeError.writerCreation("ReplayKit emitted an invalid video timestamp."),
        gapReason: "video_timestamp_invalid"
      )
      return
    }

    let returningFromBackground = type == .video
      && foregroundReturnHostUptimeSeconds != nil
      && backgroundGapId != nil
    let hasVideoClockDiscontinuity: Bool
    if type == .video,
      !returningFromBackground,
      let priorPTS = latestVideoPTS,
      let priorHostUptimeSeconds = latestVideoHostUptimeSeconds,
      TacuaCapturePolicy.videoClockHasDiscontinuity(
        priorMediaPTSSeconds: CMTimeGetSeconds(priorPTS),
        currentMediaPTSSeconds: incomingPTSSeconds,
        priorHostUptimeSeconds: priorHostUptimeSeconds,
        currentHostUptimeSeconds: hostUptimeSeconds
      )
    {
      hasVideoClockDiscontinuity = true
      finishCurrentSegment()
      openGap(reason: "video_pts_discontinuity", priorMediaPTS: priorPTS, nextMediaPTS: incomingPTS)
      latestMicrophonePTS = nil
      latestMicrophoneHostUptimeSeconds = nil
      scheduleMicrophoneWatchdogOnQueue()
    } else {
      hasVideoClockDiscontinuity = false
    }

    if type == .video, let writer, !writer.isCompatible(withVideoSample: sampleBuffer) {
      finishCurrentSegment()
    }
    if backgroundGapId == nil, !hasVideoClockDiscontinuity, let writer {
      let rotationPlan = TacuaCapturePolicy.segmentRotationPlan(
        startedAtPTSSeconds: CMTimeGetSeconds(writer.startedAtPTS),
        incomingPTSSeconds: incomingPTSSeconds,
        segmentDurationSeconds: segmentDurationSeconds
      )
      let boundaries: [Double]
      switch rotationPlan {
      case .none:
        boundaries = []
      case .boundaries(let plannedBoundaries):
        boundaries = plannedBoundaries
      case .excessive:
        failAndStopOnQueue(
          error: TacuaCaptureSpikeError.rotationLimitExceeded,
          gapReason: "segment_rotation_limit_exceeded"
        )
        return
      }
      for boundarySeconds in boundaries {
        let boundaryPTS = CMTime(
          seconds: boundarySeconds,
          preferredTimescale: 1_000_000_000
        )
        let openingVideoSample = type == .video
          && CMTimeCompare(incomingPTS, boundaryPTS) == 0
          ? sampleBuffer
          : nil
        do {
          try rotateCurrentSegment(
            at: boundaryPTS,
            hostUptimeSeconds: hostUptimeSeconds,
            openingVideoSample: openingVideoSample
          )
        } catch {
          failAndStopOnQueue(error: error, gapReason: "segment_rotation_failed")
          return
        }
      }
    }

    if type == .video {
      let pts = incomingPTS
      let mediaSeconds = incomingPTSSeconds
      if foregroundReturnHostUptimeSeconds != nil, backgroundGapId != nil {
        closeBackgroundGap(nextMediaPTS: pts, closedHostUptimeSeconds: hostUptimeSeconds)
        foregroundReturnHostUptimeSeconds = nil
        latestMicrophonePTS = nil
        latestMicrophoneHostUptimeSeconds = nil
        scheduleMicrophoneWatchdogOnQueue()
      }
      if let id = pendingResumeGapId {
        closeGap(id: id, nextMediaPTS: pts, closedHostUptimeSeconds: hostUptimeSeconds)
        pendingResumeGapId = nil
      }
      if !microphoneNeedsValidation,
        TacuaCapturePolicy.microphoneStreamHasStalled(
          latestVideoPTSSeconds: mediaSeconds,
          latestVideoHostUptimeSeconds: hostUptimeSeconds,
          latestMicrophonePTSSeconds: latestMicrophonePTS.map(CMTimeGetSeconds),
          latestMicrophoneHostUptimeSeconds: latestMicrophoneHostUptimeSeconds
        )
      {
        failAndStopOnQueue(
          error: TacuaCaptureSpikeError.microphoneSamplesMissing,
          gapReason: "microphone_stream_stalled"
        )
        return
      }
      latestVideoPTS = pts
      latestVideoHostUptimeSeconds = hostUptimeSeconds

      if writer == nil {
        do {
          try startWriter(
            firstVideoSample: sampleBuffer,
            hostUptimeSeconds: hostUptimeSeconds,
            appendFirstVideoAsHeldFrame: false
          )
        } catch {
          failAndStopOnQueue(
            error: error,
            gapReason: "writer_creation_failed"
          )
          return
        }
      }
    } else if writer == nil {
      let key = type == .audioMic ? "microphone" : "appAudio"
      if backgroundGapId != nil {
        var dropped = manifest.droppedDuringBackground ?? [:]
        dropped[key, default: 0] += 1
        manifest.droppedDuringBackground = dropped
      } else {
        manifest.droppedBeforeFirstVideo[key, default: 0] += 1
      }
      return
    }

    guard let writer else { return }
    let appended = writer.append(sampleBuffer, type: type, hostUptimeSeconds: hostUptimeSeconds)
    if appended {
      switch type {
      case .audioMic:
        manifest.microphoneSamplesObserved = (manifest.microphoneSamplesObserved ?? 0) + 1
        latestMicrophonePTS = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        latestMicrophoneHostUptimeSeconds = hostUptimeSeconds
        microphoneNeedsValidation = false
        microphoneWatchdog?.cancel()
        microphoneWatchdog = nil
      case .audioApp:
        manifest.appAudioSamplesObserved = (manifest.appAudioSamplesObserved ?? 0) + 1
      case .video:
        break
      @unknown default:
        break
      }
    } else if let fatalError = writer.fatalError {
      failAndStopOnQueue(error: fatalError, gapReason: "writer_append_failed")
    }
  }

  private func failAndStopOnQueue(error: Error, gapReason: String) {
    recordError(error.tacuaStableCode, gapReason: gapReason)
    requestStopOnQueue(reason: gapReason)
  }

  private func startWriter(
    firstVideoSample: CMSampleBuffer,
    hostUptimeSeconds: Double,
    appendFirstVideoAsHeldFrame: Bool
  ) throws {
#if TACUA_CAPTURE_FAULT_INJECTION
    if faultInjection?.shouldFailWriterStorageCheck(segmentIndex: nextSegmentIndex) == true {
      throw TacuaCaptureSpikeError.insufficientStorage
    }
#endif
    guard Self.hasMinimumFreeStorage(at: directory) else {
      throw TacuaCaptureSpikeError.insufficientStorage
    }
    let nextWriter = try SegmentWriter(
      index: nextSegmentIndex,
      directory: directory,
      firstVideoSample: firstVideoSample,
      hostUptimeSeconds: hostUptimeSeconds
    )
#if TACUA_CAPTURE_FAULT_INJECTION
    nextWriter.configureFaultInjection(
      faultInjection?.finishBehavior(segmentIndex: nextSegmentIndex) ?? .none
    )
#endif
    writer = nextWriter
    nextSegmentIndex += 1
    let mediaSeconds = CMTimeGetSeconds(CMSampleBufferGetPresentationTimeStamp(firstVideoSample))
    manifest.calibrations.append(
      CaptureCalibration(
        hostUptimeSeconds: hostUptimeSeconds,
        mediaPTSSeconds: mediaSeconds,
        hostMinusMediaSeconds: hostUptimeSeconds - mediaSeconds
      )
    )
    if appendFirstVideoAsHeldFrame,
      !nextWriter.appendHeldVideoFrame(
        firstVideoSample,
        hostUptimeSeconds: hostUptimeSeconds
      )
    {
      throw nextWriter.fatalError ?? TacuaCaptureSpikeError.writerFailed(
        "The next segment rejected its opening held video frame."
      )
    }
  }

  private func rotateCurrentSegment(
    at boundaryPTS: CMTime,
    hostUptimeSeconds: Double,
    openingVideoSample: CMSampleBuffer?
  ) throws {
    guard let currentWriter = writer else { return }
    let closingFrame = try currentWriter.makeHeldVideoSample(at: boundaryPTS)
    let heldOpeningFrame = openingVideoSample == nil
      ? try currentWriter.makeHeldVideoSample(at: boundaryPTS)
      : nil
    guard currentWriter.appendHeldVideoFrame(
      closingFrame,
      hostUptimeSeconds: hostUptimeSeconds
    ) else {
      throw currentWriter.fatalError ?? TacuaCaptureSpikeError.writerFailed(
        "The current segment rejected its boundary held video frame."
      )
    }
    finishCurrentSegment(extendVideoToLatestPTS: false)
    let openingFrame: CMSampleBuffer
    let appendOpeningAsHeldFrame: Bool
    if let openingVideoSample {
      openingFrame = openingVideoSample
      appendOpeningAsHeldFrame = false
    } else if let heldOpeningFrame {
      openingFrame = heldOpeningFrame
      appendOpeningAsHeldFrame = true
    } else {
      throw TacuaCaptureSpikeError.writerFailed(
        "The next segment could not retain its boundary video frame."
      )
    }
    try startWriter(
      firstVideoSample: openingFrame,
      hostUptimeSeconds: hostUptimeSeconds,
      appendFirstVideoAsHeldFrame: appendOpeningAsHeldFrame
    )
  }

  private func finishCurrentSegment(extendVideoToLatestPTS: Bool = true) {
    guard let writer else { return }
    if extendVideoToLatestPTS {
      do {
        try writer.extendVideoToLatestPTS(
          hostUptimeSeconds: ProcessInfo.processInfo.systemUptime
        )
      } catch {
        recordError(error.tacuaStableCode, gapReason: "video_tail_extension_failed")
      }
    }
    self.writer = nil
    finalizationGroup.enter()
    writer.finish { [self] result in
      queue.async {
#if TACUA_CAPTURE_FAULT_INJECTION
        var shouldRequestInjectedWriterStop = false
#endif
        switch result {
        case .success(let segment):
          self.manifest.segments.append(segment)
          self.manifest.segments.sort { $0.index < $1.index }
#if TACUA_CAPTURE_FAULT_INJECTION
          shouldRequestInjectedWriterStop =
            self.faultInjection?.shouldRequestStop(
              afterCommittedSegmentIndex: segment.index
            ) == true
#endif
          self.eventSink(
            "onSegment",
            [
              "index": segment.index,
              "fileName": segment.fileName,
              "sha256": segment.sha256,
              "byteLength": segment.byteLength,
              "durationSeconds": segment.durationSeconds,
              "heldVideoSamples": segment.heldVideoSamples ?? 0,
            ]
          )
        case .failure(let error):
          self.recordError(error.tacuaStableCode, gapReason: "segment_finalization_failed")
          if self.manifest.state == "recording", !self.isStopping {
            self.requestStopOnQueue(reason: "segment_finalization_failed")
          }
        }
        self.persistManifestAndReport()
        self.finalizationGroup.leave()
#if TACUA_CAPTURE_FAULT_INJECTION
        if shouldRequestInjectedWriterStop,
          !self.isStopping,
          self.writer?.index == 1
        {
          // This trigger is native and session-scoped so a JS remount cannot
          // miss it or issue a duplicate Stop. Requiring the index-1 writer
          // avoids treating a lifecycle-finalized segment 0 as fault evidence.
          self.requestStopOnQueue(reason: "qa_writer_fault_after_segment_0")
        }
#endif
      }
    }
  }

  private func finishStopOnQueue() {
    guard !didCompleteStop else { return }
    didCompleteStop = true
    removeLifecycleObservers()
    durationWorkItem?.cancel()
    microphoneWatchdog?.cancel()
    restoreIdleTimerOverride()
    closeBackgroundGap(
      nextMediaPTS: nil,
      closedHostUptimeSeconds: ProcessInfo.processInfo.systemUptime
    )
    if !manifest.segments.isEmpty, (manifest.microphoneSamplesObserved ?? 0) == 0 {
      recordError(
        TacuaCaptureSpikeError.microphoneSamplesMissing.code,
        gapReason: "microphone_samples_missing"
      )
    }
    if manifest.segments.isEmpty {
      appendErrorCode("ERR_TACUA_CAPTURE_NO_VERIFIED_SEGMENTS")
    }
    manifest.stoppedHostUptimeSeconds = ProcessInfo.processInfo.systemUptime
    manifest.state = TacuaCapturePolicy.terminalState(
      segmentCount: manifest.segments.count,
      gapCount: manifest.gaps.count,
      errorCount: manifest.errorCodes.count,
      microphoneSamplesObserved: manifest.microphoneSamplesObserved ?? 0
    )
    persistManifestAndReport()
    let result = snapshot()
    terminalSnapshot = result
    // Publish the final manifest before another session or recovery operation
    // can acquire the process token and touch capture storage.
    releaseRecorderOwnershipIfSafeOnQueue()
    emitState()
    terminalSink(self, result)
    let completions = stopCompletions
    stopCompletions.removeAll()
    for completion in completions {
      completion(.success(result))
    }
  }

  private func activateIdleTimerOverrideOnMain() {
    dispatchPrecondition(condition: .onQueue(.main))
    guard !idleTimerOverrideActive else { return }
    idleTimerWasDisabledBeforeCapture = UIApplication.shared.isIdleTimerDisabled
    idleTimerOverrideActive = true
    UIApplication.shared.isIdleTimerDisabled = true
  }

  private func restoreIdleTimerOverride() {
    DispatchQueue.main.async { [self] in
      guard idleTimerOverrideActive else { return }
      UIApplication.shared.isIdleTimerDisabled = idleTimerWasDisabledBeforeCapture
      idleTimerOverrideActive = false
    }
  }

  private func recordError(_ code: String, gapReason: String) {
    appendErrorCode(code)
    if !manifest.gaps.contains(where: { $0.reason == gapReason && $0.closedHostUptimeSeconds == nil }) {
      openGap(reason: gapReason, priorMediaPTS: latestVideoPTS, nextMediaPTS: nil)
    }
    eventSink("onError", ["code": code, "reason": gapReason])
    persistManifestAndReport()
  }

  private func appendErrorCode(_ code: String) {
    if !manifest.errorCodes.contains(code) {
      manifest.errorCodes.append(code)
    }
  }

  private func openGap(reason: String, priorMediaPTS: CMTime?, nextMediaPTS: CMTime?) {
    let now = ProcessInfo.processInfo.systemUptime
    let gap = CaptureGap(
      id: UUID().uuidString,
      reason: reason,
      openedHostUptimeSeconds: now,
      closedHostUptimeSeconds: nextMediaPTS == nil ? nil : now,
      priorMediaPTSSeconds: priorMediaPTS.map(CMTimeGetSeconds),
      nextMediaPTSSeconds: nextMediaPTS.map(CMTimeGetSeconds)
    )
    let bounded = Self.appendBoundedGap(gap, to: &manifest)
    if bounded.inserted {
      appendSystemDiagnosticBestEffort(.captureGap(
        gapID: Self.stableDiagnosticIdentifier(prefix: "g", source: bounded.id),
        affectedStreams: Self.diagnosticAffectedStreams(reason: bounded.reason)
      ))
    }
    eventSink(
      "onGap",
      [
        "id": bounded.id,
        "reason": bounded.reason,
        "openedHostUptimeSeconds": bounded.openedHostUptimeSeconds,
        "closedHostUptimeSeconds": jsonValue(bounded.closedHostUptimeSeconds),
      ]
    )
  }

  @discardableResult
  private func appendSystemDiagnosticBestEffort(_ event: TacuaDiagnosticStoredEvent) -> Bool {
    guard let diagnosticJournal else { return false }
    do {
      let entry = try diagnosticJournal.appendSystemEvent(event)
      if entry.sequence > Int64(diagnosticEventCount + 1) {
        diagnosticContainsCollectionGap = true
      }
      diagnosticEventCount = max(diagnosticEventCount, Int(entry.sequence))
      if case .collectionGap = entry.event { diagnosticContainsCollectionGap = true }
      return true
    } catch {
      let code = Self.captureDiagnosticError(error).code
      appendErrorCode(code)
      eventSink("onError", ["code": code, "reason": "diagnostic_journal_unavailable"])
      return false
    }
  }

  private func transitionDiagnosticAppState(to nextState: TacuaDiagnosticAppState) {
    let previous = diagnosticAppState
    guard previous != nextState else { return }
    guard appendSystemDiagnosticBestEffort(.event(.appStateChanged(
      fromState: previous,
      toState: nextState
    ))) else { return }
    diagnosticAppState = nextState
  }

  private static func diagnosticReceipt(_ entry: TacuaDiagnosticSnapshotEntry) -> [String: Any] {
    [
      "eventId": entry.eventID,
      "sequence": entry.sequence,
      "monotonicMilliseconds": entry.monotonicMilliseconds,
    ]
  }

  private static func captureDiagnosticError(_ error: Error) -> TacuaCaptureSpikeError {
    guard let error = error as? TacuaDiagnosticJournalError else {
      return .diagnosticUnavailable
    }
    switch error {
    case .invalidEvent, .invalidIdentity:
      return .diagnosticInvalid
    case .privacyViolation:
      return .diagnosticPrivacyViolation
    case .eventLimitReached:
      return .diagnosticEventLimitReached
    case .identityMismatch, .invalidJournal, .persistenceFailure:
      return .diagnosticUnavailable
    }
  }

  private static func stableDiagnosticIdentifier(prefix: String, source: String) -> String {
    let digest = SHA256.hash(data: Data(source.utf8)).map {
      String(format: "%02x", $0)
    }.joined()
    let available = max(1, 64 - prefix.utf8.count - 1)
    return "\(prefix)_\(digest.prefix(available))"
  }

  private static func diagnosticAffectedStreams(
    reason: String
  ) -> [TacuaDiagnosticAffectedStream] {
    if reason.contains("diagnostic") { return [.diagnostics] }
    if reason.contains("audio") || reason.contains("microphone") {
      return [.appAudio, .microphone]
    }
    if reason.contains("permission") { return [.microphone] }
    return [.appAudio, .appVideo, .microphone]
  }

  private func installLifecycleObservers() {
    guard observers.isEmpty else { return }
    let center = NotificationCenter.default
    observers.append(
      center.addObserver(
        forName: UIApplication.willResignActiveNotification,
        object: nil,
        queue: nil
      ) { [weak self] _ in
        self?.queue.async { self?.transitionDiagnosticAppState(to: .inactive) }
      }
    )
    observers.append(
      center.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil) {
        [weak self] _ in
        self?.queue.async {
          guard let self else { return }
          self.transitionDiagnosticAppState(to: .background)
          // A foreground notification is only an admission signal until the
          // next background transition. Clear it even when a gap is already open.
          self.foregroundReturnHostUptimeSeconds = nil
          self.microphoneWatchdog?.cancel()
          self.microphoneWatchdog = nil
          self.microphoneNeedsValidation = true
          guard self.acceptsCaptureSamples, self.backgroundGapId == nil else { return }
          let gap = CaptureGap(
            id: UUID().uuidString,
            reason: "app_backgrounded",
            openedHostUptimeSeconds: ProcessInfo.processInfo.systemUptime,
            closedHostUptimeSeconds: nil,
            priorMediaPTSSeconds: self.latestVideoPTS.map(CMTimeGetSeconds),
            nextMediaPTSSeconds: nil
          )
          let bounded = Self.appendBoundedGap(gap, to: &self.manifest)
          self.backgroundGapId = bounded.id
          if bounded.inserted {
            self.appendSystemDiagnosticBestEffort(.captureGap(
              gapID: Self.stableDiagnosticIdentifier(prefix: "g", source: bounded.id),
              affectedStreams: [.appAudio, .appVideo, .microphone]
            ))
          }
          self.finishCurrentSegment()
          self.persistManifestAndReport()
          self.eventSink("onGap", ["id": bounded.id, "reason": bounded.reason])
        }
      }
    )
    observers.append(
      center.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) {
        [weak self] _ in
        self?.queue.async {
          guard let self, self.backgroundGapId != nil, self.acceptsCaptureSamples else {
            return
          }
          self.transitionDiagnosticAppState(to: .inactive)
          self.foregroundReturnHostUptimeSeconds = ProcessInfo.processInfo.systemUptime
          self.scheduleMicrophoneWatchdogOnQueue()
        }
      }
    )
    observers.append(
      center.addObserver(
        forName: UIApplication.didBecomeActiveNotification,
        object: nil,
        queue: nil
      ) { [weak self] _ in
        self?.queue.async { self?.transitionDiagnosticAppState(to: .active) }
      }
    )
  }

  private func closeBackgroundGap(nextMediaPTS: CMTime?, closedHostUptimeSeconds: Double) {
    guard let id = backgroundGapId else { return }
    closeGap(id: id, nextMediaPTS: nextMediaPTS, closedHostUptimeSeconds: closedHostUptimeSeconds)
    backgroundGapId = nil
  }

  private func closeGap(id: String, nextMediaPTS: CMTime?, closedHostUptimeSeconds: Double) {
    guard let index = manifest.gaps.firstIndex(where: { $0.id == id }) else { return }
    manifest.gaps[index].closedHostUptimeSeconds = closedHostUptimeSeconds
    manifest.gaps[index].nextMediaPTSSeconds = nextMediaPTS.map(CMTimeGetSeconds)
    persistManifestAndReport()
  }

  /// Keeps the persisted capture artifact admissible under the runtime's 2,048-gap cap. The
  /// final slot is a durable overflow sentinel; later interruptions extend it without creating
  /// unbounded manifest or diagnostic records.
  private static func appendBoundedGap(
    _ proposed: CaptureGap,
    to manifest: inout CaptureManifest
  ) -> (id: String, reason: String, openedHostUptimeSeconds: Double,
    closedHostUptimeSeconds: Double?, inserted: Bool)
  {
    let limit = TacuaCapturePolicy.maximumManifestGaps
    precondition(limit >= 2)
    let overflowIndex = manifest.gaps.firstIndex(where: { $0.id == captureGapOverflowID })
    guard let disposition = TacuaCapturePolicy.captureGapInsertionDisposition(
      existingCount: manifest.gaps.count,
      overflowSentinelPresent: overflowIndex != nil
    ) else { preconditionFailure("Capture manifest gap count exceeded its hard limit") }
    if disposition == .append {
      manifest.gaps.append(proposed)
      return (
        proposed.id, proposed.reason, proposed.openedHostUptimeSeconds,
        proposed.closedHostUptimeSeconds, true
      )
    }

    if disposition == .coalesceIntoOverflowSentinel, let overflowIndex {
      let priorClosed = manifest.gaps[overflowIndex].closedHostUptimeSeconds
        ?? manifest.gaps[overflowIndex].openedHostUptimeSeconds
      let proposedClosed = proposed.closedHostUptimeSeconds ?? proposed.openedHostUptimeSeconds
      manifest.gaps[overflowIndex].closedHostUptimeSeconds = max(priorClosed, proposedClosed)
      if let next = proposed.nextMediaPTSSeconds {
        manifest.gaps[overflowIndex].nextMediaPTSSeconds = next
      }
      let overflow = manifest.gaps[overflowIndex]
      return (
        overflow.id, overflow.reason, overflow.openedHostUptimeSeconds,
        overflow.closedHostUptimeSeconds, false
      )
    }

    let replaced: CaptureGap?
    if disposition == .replaceLastWithOverflowSentinel {
      replaced = manifest.gaps.removeLast()
    } else {
      replaced = nil
    }
    let opened = min(replaced?.openedHostUptimeSeconds ?? proposed.openedHostUptimeSeconds,
      proposed.openedHostUptimeSeconds)
    let closedCandidates = [
      replaced?.closedHostUptimeSeconds,
      proposed.closedHostUptimeSeconds,
      proposed.openedHostUptimeSeconds,
    ].compactMap { $0 }
    let overflow = CaptureGap(
      id: captureGapOverflowID,
      reason: "capture_gap_overflow",
      openedHostUptimeSeconds: opened,
      closedHostUptimeSeconds: closedCandidates.max(),
      priorMediaPTSSeconds: replaced?.priorMediaPTSSeconds ?? proposed.priorMediaPTSSeconds,
      nextMediaPTSSeconds: proposed.nextMediaPTSSeconds ?? replaced?.nextMediaPTSSeconds
    )
    manifest.gaps.append(overflow)
    return (
      overflow.id, overflow.reason, overflow.openedHostUptimeSeconds,
      overflow.closedHostUptimeSeconds, true
    )
  }

  private func removeLifecycleObservers() {
    let tokens = observers
    observers.removeAll()
    for token in tokens {
      NotificationCenter.default.removeObserver(token)
    }
  }

  private static func claimRecorderOwnership(_ token: UUID) -> Bool {
    recorderOwnershipLock.lock()
    defer { recorderOwnershipLock.unlock() }
    guard activeRecorderOwnershipToken == nil else { return false }
    activeRecorderOwnershipToken = token
    return true
  }

  private static func releaseRecorderOwnership(_ token: UUID) {
    recorderOwnershipLock.lock()
    defer { recorderOwnershipLock.unlock() }
    if activeRecorderOwnershipToken == token {
      activeRecorderOwnershipToken = nil
    }
  }

  static var hasProcessRecorderOwnership: Bool {
    recorderOwnershipLock.lock()
    defer { recorderOwnershipLock.unlock() }
    return activeRecorderOwnershipToken != nil
  }

  static func withExclusiveRecoveryAccess<T>(_ operation: () throws -> T) throws -> T {
    let lease = try acquireExclusiveRecoveryLease()
    defer { lease.release() }
    return try operation()
  }

  static func acquireExclusiveRecoveryLease() throws -> ExclusiveRecoveryLease {
    let token = UUID()
    guard claimRecorderOwnership(token) else {
      throw TacuaCaptureSpikeError.captureAlreadyRunning
    }
    return ExclusiveRecoveryLease {
      releaseRecorderOwnership(token)
    }
  }

  private func releaseRecorderOwnershipIfSafeOnQueue() {
    guard !recorderOwnershipReleased else { return }
    guard didCompleteStop || manifest.state == "start_failed" else { return }
    guard !recorderStartIssued || recorderStartCompletionResolved else { return }
    Self.releaseRecorderOwnership(recorderOwnershipToken)
    recorderOwnershipReleased = true
  }

  private func snapshot() -> [String: Any] {
    var result: [String: Any] = [
      "sessionId": manifest.sessionId,
      "state": manifest.state,
      "segmentCount": manifest.segments.count,
      "gapCount": manifest.gaps.count,
      "markerCount": manifest.markers.count,
      "errorCodes": manifest.errorCodes,
      "latestMediaPTSSeconds": jsonValue(latestVideoPTS.map(CMTimeGetSeconds)),
      "recorderAvailable": recorder.isAvailable,
      "recorderRecording": recorder.isRecording,
      "maximumDurationSeconds": manifest.maximumDurationSeconds
        ?? TacuaCapturePolicy.maximumDurationSeconds,
      "automaticStopHostUptimeSeconds": jsonValue(manifest.automaticStopHostUptimeSeconds),
      "stopReason": jsonValue(manifest.stopReason),
      "microphoneSamplesObserved": manifest.microphoneSamplesObserved ?? 0,
      "appAudioSamplesObserved": manifest.appAudioSamplesObserved ?? 0,
      "appAudioAvailable": (manifest.appAudioSamplesObserved ?? 0) > 0,
      "diagnosticEventCount": diagnosticEventCount,
      "diagnosticContainsCollectionGap": diagnosticContainsCollectionGap,
    ]
#if TACUA_CAPTURE_FAULT_INJECTION
    result["testFaultPlan"] = faultInjection?.plan.rawValue ?? NSNull()
#endif
    return result
  }

  private func emitState() {
    eventSink("onState", snapshot())
  }

  private func jsonValue<T>(_ value: T?) -> Any {
    if let value { return value }
    return NSNull()
  }

  private func persistManifestAndReport() {
    do {
      try persistManifest()
    } catch {
      let code = TacuaCaptureSpikeError.storageIO(
        "Tacua could not persist the capture manifest."
      ).code
      appendErrorCode(code)
      eventSink("onError", ["code": code, "reason": "manifest_persist_failed"])
      guard !manifestPersistenceFailed else { return }
      manifestPersistenceFailed = true
      if manifest.state == "recording", !isStopping {
        requestStopOnQueue(reason: "manifest_persist_failed")
      }
    }
  }

  private func persistManifest() throws {
    try Self.persist(manifest: manifest, to: manifestURL)
  }

  private static func handoff(from options: TacuaCaptureStartOptions) -> CandidateHandoffEnvelope {
    CandidateHandoffEnvelope(
      organizationId: options.organizationId,
      projectId: options.projectId,
      buildId: options.buildId,
      handoffId: options.handoffId,
      handoffTokenIdentifier: options.handoffTokenIdentifier,
      expiresAt: options.expiresAt,
      consentVersion: options.consentVersion,
      expectedApplicationId: options.expectedApplicationId,
      expectedBuildNumber: options.expectedBuildNumber
    )
  }

  private static func protocolDate(_ value: String) -> Date? {
    guard value.utf8.count == 20,
      value.range(
        of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
        options: .regularExpression
      ) != nil
    else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: value)
  }

  private static func handoff(from options: TacuaCaptureRecoveryOptions) -> CandidateHandoffEnvelope {
    CandidateHandoffEnvelope(
      organizationId: options.organizationId,
      projectId: options.projectId,
      buildId: options.buildId,
      handoffId: options.handoffId,
      handoffTokenIdentifier: options.handoffTokenIdentifier,
      expiresAt: options.expiresAt,
      consentVersion: options.consentVersion,
      expectedApplicationId: options.expectedApplicationId,
      expectedBuildNumber: options.expectedBuildNumber
    )
  }

  private static func validateCandidateHandoff(_ handoff: CandidateHandoffEnvelope) throws {
    do {
      _ = try handoff.validate(
        now: Date(),
        actualApplicationId: Bundle.main.bundleIdentifier,
        actualBuildNumber: actualBuildNumber()
      )
    } catch let error as CandidateHandoffValidationError {
      switch error {
      case .invalidField(let field): throw TacuaCaptureSpikeError.invalidHandoffField(field)
      case .expired: throw TacuaCaptureSpikeError.handoffExpired
      case .applicationMismatch: throw TacuaCaptureSpikeError.handoffApplicationMismatch
      case .buildMismatch: throw TacuaCaptureSpikeError.handoffBuildMismatch
      case .unsupportedConsentVersion: throw TacuaCaptureSpikeError.unsupportedConsentVersion
      }
    }
  }

  private static func validateStoredIdentity(
    manifest: CaptureManifest,
    handoff: CandidateHandoffEnvelope
  ) throws {
    guard manifest.organizationId == handoff.organizationId,
      manifest.projectId == handoff.projectId,
      manifest.buildId == handoff.buildId,
      manifest.handoffId == handoff.handoffId,
      manifest.consentVersion == handoff.consentVersion,
      manifest.expectedApplicationId == handoff.expectedApplicationId,
      manifest.expectedBuildNumber == handoff.expectedBuildNumber
    else {
      throw TacuaCaptureSpikeError.handoffManifestMismatch
    }
  }

  private static func validateDeletionScope(_ handoff: CandidateHandoffEnvelope) throws {
    do {
      try handoff.validateDeletionScope(actualApplicationId: Bundle.main.bundleIdentifier)
    } catch let error as CandidateHandoffValidationError {
      switch error {
      case .invalidField(let field): throw TacuaCaptureSpikeError.invalidHandoffField(field)
      case .applicationMismatch: throw TacuaCaptureSpikeError.handoffApplicationMismatch
      case .expired, .buildMismatch, .unsupportedConsentVersion:
        throw TacuaCaptureSpikeError.handoffManifestMismatch
      }
    }
  }

  private static func validateStoredSessionId(manifest: CaptureManifest, expected: String) throws {
    guard manifest.sessionId == expected else {
      throw TacuaCaptureSpikeError.handoffManifestMismatch
    }
  }

  private static func validateStoredDeletionIdentity(
    manifest: CaptureManifest,
    handoff: CandidateHandoffEnvelope
  ) throws {
    guard manifest.organizationId == handoff.organizationId,
      manifest.projectId == handoff.projectId,
      manifest.handoffId == handoff.handoffId,
      manifest.expectedApplicationId == handoff.expectedApplicationId
    else {
      throw TacuaCaptureSpikeError.handoffManifestMismatch
    }
  }

  private static func actualBuildNumber() -> String? {
    let value = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")
    if let value = value as? String { return value }
    if let value = value as? NSNumber { return value.stringValue }
    return nil
  }

  private static func readManifest(at url: URL) throws -> CaptureManifest {
    do {
      let data = try Data(contentsOf: url)
      return try JSONDecoder().decode(CaptureManifest.self, from: data)
    } catch {
      throw TacuaCaptureSpikeError.recoveryIO("The stored capture manifest could not be read.")
    }
  }

  private static func markInterruptedStateIfNeeded(manifest: inout CaptureManifest) {
    let interruptedState = [
      "prepared",
      "recording",
      "stopping",
      "stop_failed_capture_active",
      "start_cleanup_pending",
    ].contains(manifest.state)
    guard interruptedState else { return }
    let code = "ERR_TACUA_CAPTURE_INTERRUPTED"
    if !manifest.errorCodes.contains(code) {
      manifest.errorCodes.append(code)
    }
    manifest.state = manifest.segments.isEmpty
      ? "failed_no_verified_segments"
      : "recoverable_partial"
  }

  private static func recoverySnapshot(
    manifest: CaptureManifest,
    directory: URL,
    recoveredSegmentCount: Int
  ) -> [String: Any] {
    [
      "sessionId": manifest.sessionId,
      "state": manifest.state,
      "segmentCount": manifest.segments.count,
      "gapCount": manifest.gaps.count,
      "partialFileCount": partialFileCount(in: directory),
      "recoveredSegmentCount": recoveredSegmentCount,
      "createdAt": manifest.createdAt,
      "resumeCount": manifest.resumeCount ?? 0,
    ]
  }

  private static func storageRoot(create: Bool) throws -> URL {
    let applicationSupport = try FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: create
    )
    let root = applicationSupport.appendingPathComponent("TacuaCaptureSpike", isDirectory: true)
    if create, !FileManager.default.fileExists(atPath: root.path) {
      try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
      try protectAndExcludeFromBackup(root)
    }
    return root
  }

  private static func protectAndExcludeFromBackup(_ url: URL) throws {
    try FileManager.default.setAttributes(
      [.protectionKey: FileProtectionType.completeUnlessOpen],
      ofItemAtPath: url.path
    )
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var mutableURL = url
    try mutableURL.setResourceValues(values)
  }

  private static func hasMinimumFreeStorage(at url: URL) -> Bool {
    let values = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
    return TacuaCapturePolicy.hasSufficientStorage(
      availableBytes: values?.volumeAvailableCapacityForImportantUsage
    )
  }

  private static func isValidSessionId(_ value: String) -> Bool {
    value.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil
  }

  private static func partialFileCount(in directory: URL) -> Int {
    let files = (try? FileManager.default.contentsOfDirectory(
      at: directory,
      includingPropertiesForKeys: nil,
      options: [.skipsHiddenFiles]
    )) ?? []
    return files.filter { $0.lastPathComponent.hasSuffix(".partial.mov") }.count
  }

  private static func reconcileFinalizedSegments(
    in directory: URL,
    manifest: inout CaptureManifest
  ) -> Int {
    let files = (try? FileManager.default.contentsOfDirectory(
      at: directory,
      includingPropertiesForKeys: nil,
      options: [.skipsHiddenFiles]
    )) ?? []
    var recovered = 0

    for sidecarURL in files where sidecarURL.lastPathComponent.hasSuffix(".segment.json") {
      guard let data = try? Data(contentsOf: sidecarURL),
        let segment = try? JSONDecoder().decode(CaptureSegment.self, from: data),
        segment.fileName.range(of: "^segment-[0-9]{6}\\.mov$", options: .regularExpression) != nil,
        !manifest.segments.contains(where: { $0.index == segment.index })
      else { continue }

      let finalURL = directory.appendingPathComponent(segment.fileName)
      let expectedSidecarURL = finalURL
        .deletingPathExtension()
        .appendingPathExtension("segment.json")
      let partialURL = finalURL
        .deletingPathExtension()
        .appendingPathExtension("partial.mov")
      guard sidecarURL.standardizedFileURL == expectedSidecarURL.standardizedFileURL,
        finalURL.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL,
        partialURL.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL
      else { continue }

      let finalExists = FileManager.default.fileExists(atPath: finalURL.path)
      let partialExists = FileManager.default.fileExists(atPath: partialURL.path)
      guard let source = TacuaCapturePolicy.recoverySource(
        finalExists: finalExists,
        partialExists: partialExists
      ) else { continue }
      let mediaURL = source == .finalized ? finalURL : partialURL
      guard let attributes = try? FileManager.default.attributesOfItem(atPath: mediaURL.path),
        (attributes[.size] as? NSNumber)?.int64Value == segment.byteLength,
        (try? sha256(url: mediaURL)) == segment.sha256
      else { continue }

      if source == .verifiedPartial {
        do {
          try FileManager.default.moveItem(at: partialURL, to: finalURL)
          try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUnlessOpen],
            ofItemAtPath: finalURL.path
          )
        } catch {
          continue
        }
      }
      manifest.segments.append(segment)
      recovered += 1
    }

    manifest.segments.sort { $0.index < $1.index }
    return recovered
  }

  private static func persist(manifest: CaptureManifest, to url: URL) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(manifest)
    try data.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
  }

  private static func sha256(url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hasher = SHA256()
    while true {
      let data = try handle.read(upToCount: 1_048_576) ?? Data()
      if data.isEmpty { break }
      hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
  }

  private static func iso8601(_ date: Date) -> String {
    ISO8601DateFormatter().string(from: date)
  }
}
