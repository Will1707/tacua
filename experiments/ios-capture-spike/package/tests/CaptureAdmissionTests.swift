// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Darwin
import Foundation

private enum CaptureAdmissionTestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  guard condition() else { throw CaptureAdmissionTestFailure.assertion(message) }
}

private final class AdmissionTestLease: TacuaSDKStartLifecycleLease {
  private(set) var released = false
  private let onRelease: () -> Void
  init(onRelease: @escaping () -> Void = {}) { self.onRelease = onRelease }
  func release() {
    guard !released else { return }
    released = true
    onRelease()
  }
}

private final class AdmissionTestLifecycleGate: TacuaCaptureAdmissionLifecycleGating {
  var startRecovery = false
  private(set) var leaseCount = 0
  private(set) var activeLeaseCount = 0

  func acquireLifecycleLease(localSessionID: String) throws -> TacuaSDKStartLifecycleLease {
    leaseCount += 1
    activeLeaseCount += 1
    return AdmissionTestLease { [weak self] in self?.activeLeaseCount -= 1 }
  }

  func hasStartRecovery(localSessionID: String) throws -> Bool { startRecovery }
}

private final class AdmissionTestResumeInspector: TacuaSDKResumeRecoveryInspecting {
  var resumeRecovery = false
  func hasRecovery(localSessionID: String) throws -> Bool { resumeRecovery }
}

private enum AdmissionTestRetentionError: Error { case expired }

private final class AdmissionTestRetentionChecker: TacuaSDKLocalRetentionChecking {
  private let lifecycleGate: AdmissionTestLifecycleGate
  var failOnCheck: Int?
  var retireOnCheck: Int?
  var stopUptimeMilliseconds: Int64 = 3_600_000
  private(set) var checkCount = 0
  private(set) var stopQueryCount = 0

  init(lifecycleGate: AdmissionTestLifecycleGate) {
    self.lifecycleGate = lifecycleGate
  }

  func requireActiveHoldingLifecycleLease(localSessionID: String) throws {
    guard lifecycleGate.activeLeaseCount == 1 else {
      throw CaptureAdmissionTestFailure.assertion(
        "Retention check ran outside the existing lifecycle lease"
      )
    }
    checkCount += 1
    if checkCount == retireOnCheck { throw TacuaSDKLocalRetentionError.expired }
    if checkCount == failOnCheck { throw AdmissionTestRetentionError.expired }
  }

  func activeStopUptimeMillisecondsHoldingLifecycleLease(
    localSessionID: String
  ) throws -> Int64 {
    guard lifecycleGate.activeLeaseCount == 1 else {
      throw CaptureAdmissionTestFailure.assertion(
        "Retention stop query ran outside the existing lifecycle lease"
      )
    }
    stopQueryCount += 1
    return stopUptimeMilliseconds
  }
}

private final class AdmissionTestQueueStore: TacuaCaptureAdmissionQueueStoring,
  TacuaCaptureUploadQueueStoring
{
  var queue: TacuaTransportQueueV3?
  var compareAndSwapCount = 0
  var installThenThrow = false
  private(set) var cleanupCount = 0

  init(queue: TacuaTransportQueueV3?) { self.queue = queue }

  func load(localSessionID: String) throws -> TacuaTransportQueueV3? {
    guard queue?.localSessionID == localSessionID else { return nil }
    return queue
  }

  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws {
    compareAndSwapCount += 1
    guard queue == expected else { throw TacuaTransportQueueFileStoreError.stateConflict }
    queue = replacement
    if installThenThrow {
      installThenThrow = false
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
  }

  func recoverPayloadCleanup(
    localSessionID: String,
    sessionDirectory: URL
  ) throws -> TacuaTransportQueueV3? {
    guard var candidate = queue, candidate.localSessionID == localSessionID else { return nil }
    let persistence = AdmissionTestCleanupPersistence(store: self)
    let retirer = try TacuaScopedSessionRetirer(sessionDirectory: sessionDirectory)
    try TacuaTransportCleanup.retireAuthorizedSession(
      queue: &candidate,
      persistence: persistence,
      retirer: retirer
    )
    queue = candidate
    cleanupCount += 1
    return candidate
  }
}

private final class AdmissionTestCleanupPersistence: TacuaTransportQueuePersisting {
  private unowned let store: AdmissionTestQueueStore
  init(store: AdmissionTestQueueStore) { self.store = store }
  func persist(_ queue: TacuaTransportQueueV3) throws { store.queue = queue }
}

private final class AdmissionTestSender: TacuaSDKBackendOperationSending {
  typealias Handler = (TacuaPreparedBackendRequest) throws -> TacuaValidatedBackendReceipt
  private let lock = NSLock()
  private let handler: Handler
  var suspendUntilCancelled = false
  var ignoreCancellation = false
  var suspensionNanoseconds: UInt64 = 60_000_000_000
  private(set) var callCount = 0
  private var requests: [TacuaPreparedBackendRequest] = []

  init(handler: @escaping Handler) { self.handler = handler }

  func send(
    _ request: TacuaPreparedBackendRequest,
    transportCredentialID: String
  ) async throws -> TacuaValidatedBackendReceipt {
    try await execute(request)
  }

  func uploadSegment(
    _ request: TacuaPreparedBackendRequest,
    fileURL: URL,
    sessionDirectory: URL,
    transportCredentialID: String
  ) async throws -> TacuaValidatedBackendReceipt {
    try await execute(request)
  }

  func observedCallCount() -> Int {
    lock.lock(); defer { lock.unlock() }
    return callCount
  }

  func observedRequests() -> [TacuaPreparedBackendRequest] {
    lock.lock(); defer { lock.unlock() }
    return requests
  }

  private func execute(
    _ request: TacuaPreparedBackendRequest
  ) async throws -> TacuaValidatedBackendReceipt {
    let shouldSuspend = recordCall(request)
    if shouldSuspend {
      if ignoreCancellation {
        await withCheckedContinuation { continuation in
          DispatchQueue.global().asyncAfter(
            deadline: .now() + .nanoseconds(Int(suspensionNanoseconds))
          ) {
            continuation.resume()
          }
        }
      } else {
        try await Task.sleep(nanoseconds: suspensionNanoseconds)
      }
    }
    return try handler(request)
  }

  private func recordCall(_ request: TacuaPreparedBackendRequest) -> Bool {
    lock.lock()
    callCount += 1
    requests.append(request)
    let shouldSuspend = suspendUntilCancelled
    lock.unlock()
    return shouldSuspend
  }
}

private final class AdmissionTestDirectorySynchronizer {
  private(set) var callCount = 0
  var failNext = false

  func synchronize(_ descriptor: Int32) -> Bool {
    callCount += 1
    if failNext {
      failNext = false
      return false
    }
    return fsync(descriptor) == 0
  }
}

private struct AdmissionTestClock: TacuaMonotonicClock {
  let uptimeMilliseconds: Int64
  let bootSessionID: String
}

private final class AdmissionDiagnosticClock {
  var value: Int64
  init(_ value: Int64) { self.value = value }
}

private struct AdmissionTestSegment: Codable {
  let index: Int
  let fileName: String
  let sha256: String
  let byteLength: Int64
  let firstMediaPTSSeconds: Double
  let lastMediaPTSSeconds: Double
  let firstHostUptimeSeconds: Double
  let lastHostUptimeSeconds: Double
  let durationSeconds: Double
  let videoSamples: Int
  let heldVideoSamples: Int?
  let appAudioSamples: Int
  let microphoneSamples: Int
  let droppedVideoSamples: Int
  let droppedAppAudioSamples: Int
  let droppedMicrophoneSamples: Int
}

private struct AdmissionHarness {
  let root: URL
  let localSessionID: String
  let configuration: TacuaBackendConfiguration
  let buildData: Data
  let scopeData: Data
  let clock: AdmissionTestClock
  let gate: AdmissionTestLifecycleGate
  let resume: AdmissionTestResumeInspector
  let queues: AdmissionTestQueueStore
  let directorySynchronizer: AdmissionTestDirectorySynchronizer
  let coordinator: TacuaCaptureAdmissionCoordinator

  var input: TacuaCaptureAdmissionInput {
    TacuaCaptureAdmissionInput(
      localSessionID: localSessionID,
      buildIdentityJSON: buildData,
      scopeJSON: scopeData
    )
  }
}

@main
enum CaptureAdmissionTests {
  static func main() async throws {
    guard CommandLine.arguments.count == 2 else {
      throw CaptureAdmissionTestFailure.assertion("Expected protocol fixture directory")
    }
    let fixtures = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try admitsExactlyOnceAndSanitizes(fixtures)
    try admitsCompleteSchema4AppAudioAccounting(fixtures)
    try rejectsMalformedSchema4AppAudioAccounting(fixtures)
    try incompleteSchema4AccountingAllowsOnlyExplicitMissingRanges(fixtures)
    try durableQueueAdmitsWithoutHostArtifacts(fixtures)
    try legacyQueueRequiresExplicitArtifacts(fixtures)
    try durableQueueRejectsHostArtifactSubstitution(fixtures)
    try sameBootResumeAnchorMapsHistoricalCapture(fixtures)
    try rejectsCaptureBeforeBackendSession(fixtures)
    try journalDiagnosticsProjectAndBindSource(fixtures)
    try fullJournalStillAdmitsLateManifestSignalsDeterministically(fixtures)
    try legacyFullTornJournalStillRecovers(fixtures)
    try repeatedJournalRecoveryGapsStayBounded(fixtures)
    try ambiguousCASConfirmsExactInstall(fixtures)
    try recoversVisibleButUnconfirmedMaterialization(fixtures)
    try acceptsLegitimatelyReboundAdmission(fixtures)
    try recoveryGateRunsBeforeMaterialization(fixtures)
    try rejectsSidecarSymlink(fixtures)
    try rejectsMissingRetentionAuthority(fixtures)
    try rejectsLegacyBootlessManifest(fixtures)
    try requiresExplicitPartialRecoveryChoice(fixtures)
    try conflictingStableIDDoesNotMaterialize(fixtures)
    try extraAdmissionOperationDoesNotMaterialize(fixtures)
    try await uploadCoordinatorDrivesCompletionAndCleanup(fixtures)
    try await uploadRechecksRetentionBetweenNetworkOperations(fixtures)
    try await uploadCancelsAtRetentionDeadlineWithoutAwaitingLateSender(fixtures)
    try await uploadAtRetentionBoundaryStartsNoRequest(fixtures)
    try await uploadRetentionCleanupFailureKeepsRetryJournal(fixtures)
    try await uploadCancellationKeepsUnknownOutcomeAndLease(fixtures)
    try await fileBackedUploadRelaunchReplaysExactUnknownAndCompletes(fixtures)
    print("Capture admission tests passed")
  }

  private static func admitsCompleteSchema4AppAudioAccounting(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "schema4_audio_valid")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try rewriteCaptureAsSchema4(harness)
    let result = try harness.coordinator.admit(harness.input)
    try require(!result.alreadyAdmitted, "Valid schema-4 accounting was not freshly admitted")
    try require(result.segmentCount == 1, "Valid schema-4 accounting lost its segment")
    let admissionURL = harness.root
      .appendingPathComponent(harness.localSessionID, isDirectory: true)
      .appendingPathComponent(TacuaCaptureAdmissionCoordinator.admissionFileName)
    let admission = try TacuaCanonicalJSON.parse(Data(contentsOf: admissionURL))
    let accounting = try required(
      admission.objectValue?["capture_manifest_seed"]?.objectValue?["app_audio_accounting"]?
        .objectValue,
      "Schema-4 accounting was not persisted in the runtime manifest seed"
    )
    try require(accounting["version"]?.integerValue == 1, "Wrong runtime accounting version")
    try require(accounting["complete"]?.boolValue == true, "Complete accounting was downgraded")
    try require(
      accounting["append_attempts"]?.integerValue == 600
        && accounting["reserved_through_index"]?.integerValue == 600,
      "Runtime accounting totals drifted from the verified sidecar"
    )
    let segments = try required(accounting["segments"]?.arrayValue, "Accounting segments missing")
    let projected = try segments[0].requiringObject(keys: [
      "append_attempts", "appended_samples", "attempt_start_index", "drops", "segment_id",
      "sequence",
    ])
    try require(
      projected["segment_id"]?.stringValue == "segment_000000"
        && projected["sequence"]?.integerValue == 0
        && projected["attempt_start_index"]?.integerValue == 1,
      "Runtime accounting did not bind the verified runtime segment"
    )
    let drop = try required(projected["drops"]?.arrayValue?.first?.objectValue, "Exact drop missing")
    try require(
      drop["attempt_index"]?.integerValue == 300
        && drop["cause"]?.stringValue == "input_backpressure",
      "Exact drop index or cause was not persisted downstream"
    )
    try require(
      accounting["unknown_ranges"]?.arrayValue == [],
      "Complete accounting fabricated an unknown range"
    )
  }

  private static func rejectsMalformedSchema4AppAudioAccounting(_ fixtures: URL) throws {
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "missing_fields",
      segmentMutation: { segment in
      segment.removeValue(forKey: "appAudioAppendDrops")
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "noncontiguous",
      segmentMutation: { segment in
        segment["appAudioAppendAttemptStartIndex"] = 2
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "duplicate",
      segmentMutation: { segment in
        segment["appAudioSamples"] = 598
        segment["droppedAppAudioSamples"] = 2
        segment["appAudioAppendDrops"] = [
          ["attemptIndex": 300, "cause": "input_backpressure"],
          ["attemptIndex": 300, "cause": "append_rejected"],
        ]
      },
      manifestMutation: { manifest in
        manifest["appAudioSamplesObserved"] = 598
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "missing_drop",
      segmentMutation: { segment in
        segment["appAudioAppendDrops"] = []
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "drop_count",
      segmentMutation: { segment in
        segment["droppedAppAudioSamples"] = 2
        segment["appAudioSamples"] = 598
      },
      manifestMutation: { manifest in
        manifest["appAudioSamplesObserved"] = 598
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "invalid_cause",
      segmentMutation: { segment in
        segment["appAudioAppendDrops"] = [[
          "attemptIndex": 300,
          "cause": "private_writer_detail",
        ]]
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "manifest_attempt_total",
      manifestMutation: { manifest in
        manifest["appAudioAppendAttemptsObserved"] = 599
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "manifest_appended_total",
      manifestMutation: { manifest in
        manifest["appAudioSamplesObserved"] = 598
      }
    )
  }

  private static func incompleteSchema4AccountingAllowsOnlyExplicitMissingRanges(
    _ fixtures: URL
  ) throws {
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "completed_incomplete",
      segmentMutation: { segment in
        segment["appAudioAppendAttemptStartIndex"] = 2
      },
      manifestMutation: { manifest in
        manifest["appAudioAppendAccountingComplete"] = false
        manifest["appAudioAppendReservedThroughIndex"] = 601
        manifest["appAudioAppendUnknownRanges"] = [[
          "startIndex": 1,
          "endIndex": 1,
          "reason": "process_recovery_reservation",
        ]]
      }
    )

    let harness = try makeHarness(fixtures: fixtures, suffix: "schema4_audio_incomplete")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try rewriteCaptureAsSchema4(
      harness,
      segmentMutation: { segment in
        segment["appAudioAppendAttemptStartIndex"] = 2
      },
      manifestMutation: { manifest in
        manifest["state"] = "partial_ready_for_upload"
        manifest["appAudioAppendAccountingComplete"] = false
        manifest["appAudioAppendReservedThroughIndex"] = 601
        manifest["appAudioAppendUnknownRanges"] = [[
          "startIndex": 1,
          "endIndex": 1,
          "reason": "process_recovery_reservation",
        ]]
      }
    )
    let result = try harness.coordinator.admit(harness.input)
    try require(
      !result.alreadyAdmitted,
      "Explicit incomplete accounting could not preserve uploadable debugging evidence"
    )
    let admissionURL = harness.root
      .appendingPathComponent(harness.localSessionID, isDirectory: true)
      .appendingPathComponent("backend-admission-v1.json")
    let admission = try TacuaCanonicalJSON.parse(Data(contentsOf: admissionURL))
    let admissionObject = try required(admission.objectValue, "Admission object missing")
    let seed = try required(
      admissionObject["capture_manifest_seed"]?.objectValue,
      "Admission manifest seed missing"
    )
    let projectedGaps = seed["gaps"]?.arrayValue ?? []
    try require(
      projectedGaps.contains(where: {
        $0.objectValue?["reason"]?.stringValue == "process_terminated"
      }),
      "Incomplete accounting had no backend-visible process-termination gap"
    )
    let accounting = try required(
      seed["app_audio_accounting"]?.objectValue,
      "Incomplete exact accounting was not persisted downstream"
    )
    try require(accounting["complete"]?.boolValue == false, "Incomplete history claimed complete")
    try require(
      accounting["append_attempts"]?.integerValue == 600
        && accounting["reserved_through_index"]?.integerValue == 601,
      "Incomplete accounting totals drifted"
    )
    let unknown = try required(
      accounting["unknown_ranges"]?.arrayValue?.first?.objectValue,
      "Explicit recovery range was lost"
    )
    try require(
      unknown["start_index"]?.integerValue == 1
        && unknown["end_index"]?.integerValue == 1
        && unknown["reason"]?.stringValue == "process_recovery_reservation",
      "Explicit recovery range changed during admission"
    )

    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "incomplete_overlap",
      segmentMutation: { segment in
        segment["appAudioAppendAttemptStartIndex"] = 1
      },
      manifestMutation: { manifest in
        manifest["state"] = "partial_ready_for_upload"
        manifest["appAudioAppendAccountingComplete"] = false
        manifest["appAudioAppendAttemptsObserved"] = 599
        manifest["appAudioAppendReservedThroughIndex"] = 600
        manifest["appAudioAppendUnknownRanges"] = []
      }
    )
    try expectSchema4AccountingRejection(
      fixtures,
      suffix: "incomplete_without_unknown_range",
      manifestMutation: { manifest in
        manifest["state"] = "partial_ready_for_upload"
        manifest["appAudioAppendAccountingComplete"] = false
        manifest["appAudioAppendUnknownRanges"] = []
      }
    )
  }

  private static func sameBootResumeAnchorMapsHistoricalCapture(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "resume_anchor")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var resumedQueue = try required(harness.queues.queue, "Missing pre-RESUME queue")
    try resumedQueue.applyExchange(
      remoteSessionID: "session_synthetic",
      scopeDigest: try scopeDigest(harness.scopeData),
      credentialID: "credential_resumed",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:05:00Z",
      previousCredentialID: "credential_synthetic",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: AdmissionTestClock(
        uptimeMilliseconds: 1_160_000,
        bootSessionID: harness.clock.bootSessionID
      )
    )
    harness.queues.queue = resumedQueue
    let admitted = try harness.coordinator.admit(harness.input)
    try require(!admitted.alreadyAdmitted, "Fresh post-RESUME admission was treated as old")
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let artifact = try TacuaCanonicalJSON.parse(
      Data(contentsOf: session.appendingPathComponent(
        TacuaCaptureAdmissionCoordinator.admissionFileName
      ))
    )
    let seed = try required(
      artifact.objectValue?["capture_manifest_seed"]?.objectValue,
      "Post-RESUME manifest seed missing"
    )
    try require(
      seed["started_at"]?.stringValue == "2026-07-21T09:58:20Z",
      "Historical capture start was not mapped backward from the same-boot RESUME anchor"
    )
    try require(
      seed["ended_at"]?.stringValue == "2026-07-21T09:59:20Z",
      "Historical capture end was not mapped backward from the same-boot RESUME anchor"
    )
  }

  private static func rejectsCaptureBeforeBackendSession(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "before_session")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var queue = try required(harness.queues.queue, "Pre-session queue missing")
    queue.sessionRetentionAuthority = TacuaSessionRetentionAuthority(
      sessionReceivedAt: "2026-07-21T09:59:00Z",
      rawMediaExpiresAt: "2026-08-20T09:59:00Z",
      derivedDataExpiresAt: "2026-08-20T09:59:00Z"
    )
    try queue.validate()
    harness.queues.queue = queue

    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Capture predating START was admitted")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .captureClockUnavailable, "Wrong pre-session chronology error")
    }
    try require(harness.queues.compareAndSwapCount == 0, "Pre-session capture mutated queue")
  }

  private static func admitsExactlyOnceAndSanitizes(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "success")
    defer { try? FileManager.default.removeItem(at: harness.root) }

    let first = try harness.coordinator.admit(harness.input)
    try require(!first.alreadyAdmitted, "First admission was reported as a retry")
    try require(first.segmentCount == 1, "Admission lost the verified segment")
    try require(first.admittedOperationCount == 2, "Admission did not add segment + diagnostic")
    try require(harness.queues.compareAndSwapCount == 1, "Admission used more than one queue CAS")
    let queue = try required(harness.queues.queue, "Admission lost its queue")
    try require(
      queue.operations.map(\.operationID) == [
        "upload_segment_000000", "upload_diagnostic_000001",
      ],
      "Admission did not use stable dense operation IDs"
    )
    try require(
      queue.operations.allSatisfy({ $0.state == .prepared }),
      "Admission did not leave requests in the known-unsent state"
    )
    for operation in queue.operations {
      _ = try TacuaSDKBackendProtocol.validateRequest(operation.canonicalRequest)
    }

    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let diagnosticData = try Data(
      contentsOf: session.appendingPathComponent(
        TacuaCaptureAdmissionCoordinator.diagnosticFileName
      )
    )
    let diagnostic = try TacuaCanonicalJSON.parse(diagnosticData)
    let envelope = try diagnostic.requiringObject(keys: [
      "build_id", "build_identity_digest", "collection_gaps", "contract_version",
      "envelope_digest", "envelope_id", "envelope_version", "events", "evidence",
      "media_type", "organization_id", "project_id", "redaction", "sequence_range",
      "session_id",
    ])
    let events = try required(envelope["events"]?.arrayValue, "Diagnostic events missing")
    try require(events.count == 3, "Admission lost sanitized manifest diagnostics")
    let eventTypes = try events.map { value in
      try value.requiringObject(keys: [
        "data", "elapsed_ms", "event_id", "event_type", "evidence_refs", "occurred_at",
        "sequence", "source",
      ])["event_type"]?.stringValue
    }
    try require(
      eventTypes == ["capture_gap", "issue_mark", "custom_state"],
      "Manifest diagnostic projection was not chronological"
    )
    let event = try events[2].requiringObject(keys: [
      "data", "elapsed_ms", "event_id", "event_type", "evidence_refs", "occurred_at",
      "sequence", "source",
    ])
    let eventData = try required(event["data"]?.objectValue, "Diagnostic event data missing")
    try require(event["event_type"]?.stringValue == "custom_state", "Diagnostic was not custom_state")
    try require(eventData["provider_id"]?.stringValue == "capture_summary", "Wrong provider")
    let diagnosticText = try required(String(data: diagnosticData, encoding: .utf8), "Invalid UTF-8")
    try require(!diagnosticText.contains("PRIVATE_MARKER_LABEL"), "Marker label leaked")
    try require(!diagnosticText.contains("PRIVATE_ERROR_DETAIL"), "Error detail leaked")
    try require(!diagnosticText.contains("handoff_private"), "Handoff identifier leaked")

    let admissionData = try Data(
      contentsOf: session.appendingPathComponent(
        TacuaCaptureAdmissionCoordinator.admissionFileName
      )
    )
    let admissionText = try required(String(data: admissionData, encoding: .utf8), "Invalid admission")
    try require(!admissionText.contains("PRIVATE_MARKER_LABEL"), "Admission leaked marker label")
    try require(!admissionText.contains("PRIVATE_ERROR_DETAIL"), "Admission leaked error detail")
    try require(!admissionText.contains("handoff_private"), "Admission leaked handoff identity")
    try require(admissionText.contains("session_received_at"), "Retention origin was not durable")
    try require(admissionText.contains("server_time_anchor"), "Server time anchor was not durable")
    let admission = try TacuaCanonicalJSON.parse(admissionData)
    let captureSeed = try required(
      admission.objectValue?["capture_manifest_seed"]?.objectValue,
      "Capture manifest seed missing"
    )
    let summary = try required(
      admission.objectValue?["capture_summary"]?.objectValue,
      "Capture summary missing"
    )
    try require(
      summary["app_audio_accounting_complete"]?.boolValue == false,
      "Schema-3 count-only audio was falsely labeled exact and complete"
    )
    try require(
      captureSeed["app_audio_accounting"] == .null,
      "Schema-3 count-only audio was falsely projected as exact accounting"
    )
    let captureGaps = captureSeed["gaps"]?.arrayValue ?? []
    try require(
      captureGaps.contains(where: {
        $0.objectValue?["reason"]?.stringValue == "unknown"
          && $0.objectValue?["affected_streams"]?.arrayValue?
            .compactMap(\.stringValue) == ["app_audio"]
      }),
      "Schema-3 count-only accounting had no explicit backend-visible uncertainty gap"
    )

    let second = try harness.coordinator.admit(harness.input)
    try require(second.alreadyAdmitted, "Exact retry was not idempotent")
    try require(second.admissionDigest == first.admissionDigest, "Retry changed admission digest")
    try require(harness.queues.compareAndSwapCount == 1, "Exact retry performed another CAS")

    var rotated = try required(harness.queues.queue, "Missing queue before rotation")
    try rotated.applyExchange(
      remoteSessionID: "session_synthetic",
      scopeDigest: try scopeDigest(harness.scopeData),
      credentialID: "credential_rotated",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:05:00Z",
      previousCredentialID: "credential_synthetic",
      capability: .active,
      issuedAt: "2026-07-21T10:01:00Z",
      clock: AdmissionTestClock(
        uptimeMilliseconds: 1_240_000,
        bootSessionID: harness.clock.bootSessionID
      )
    )
    harness.queues.queue = rotated
    let afterRotation = try harness.coordinator.admit(harness.input)
    try require(afterRotation.alreadyAdmitted, "Exact older-credential admission was rejected")
    try require(harness.queues.compareAndSwapCount == 1, "Rotation retry mutated the queue")
  }

  private static func durableQueueAdmitsWithoutHostArtifacts(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "durable_artifacts")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let admitted = try harness.coordinator.admit(TacuaCaptureAdmissionInput(
      localSessionID: harness.localSessionID,
      buildIdentityJSON: nil,
      scopeJSON: nil
    ))
    try require(
      admitted.segmentCount == 1 && !admitted.alreadyAdmitted,
      "Admission did not derive current artifacts from the durable queue"
    )
  }

  private static func legacyQueueRequiresExplicitArtifacts(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "legacy_artifacts")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var legacy = try required(harness.queues.queue, "Legacy fixture queue missing")
    legacy.buildIdentityJSON = nil
    legacy.captureScopeJSON = nil
    try legacy.validate()
    harness.queues.queue = legacy
    do {
      _ = try harness.coordinator.admit(TacuaCaptureAdmissionInput(
        localSessionID: harness.localSessionID,
        buildIdentityJSON: nil,
        scopeJSON: nil
      ))
      throw CaptureAdmissionTestFailure.assertion("Legacy queue invented session artifacts")
    } catch let error as CaptureAdmissionTestFailure {
      throw error
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .invalidInput, "Legacy omission surfaced the wrong error")
    }
    let admitted = try harness.coordinator.admit(harness.input)
    try require(
      admitted.segmentCount == 1,
      "Explicit validated artifacts could not admit a legacy queue"
    )
  }

  private static func durableQueueRejectsHostArtifactSubstitution(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "artifact_substitution")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    guard case .object(var scope) = try TacuaCanonicalJSON.parse(harness.scopeData),
      case .object(var consent)? = scope["consent"]
    else { throw CaptureAdmissionTestFailure.assertion("Scope fixture is malformed") }
    consent["granted_at"] = .string("2026-07-21T09:58:00Z")
    scope["consent"] = .object(consent)
    scope["scope_digest"] = .string(
      try TacuaCanonicalJSON.digest(.object(scope), omittingRootField: "scope_digest")
    )
    let substitutedScope = try TacuaCanonicalJSON.data(.object(scope))
    do {
      _ = try harness.coordinator.admit(TacuaCaptureAdmissionInput(
        localSessionID: harness.localSessionID,
        buildIdentityJSON: harness.buildData,
        scopeJSON: substitutedScope
      ))
      throw CaptureAdmissionTestFailure.assertion("Admission accepted host artifact substitution")
    } catch let error as CaptureAdmissionTestFailure {
      throw error
    } catch let error as TacuaCaptureAdmissionError {
      try require(
        error == .captureIdentityMismatch,
        "Host artifact substitution surfaced the wrong error"
      )
    }
    let admission = harness.root
      .appendingPathComponent(harness.localSessionID, isDirectory: true)
      .appendingPathComponent(TacuaCaptureAdmissionCoordinator.admissionFileName)
    try require(
      !FileManager.default.fileExists(atPath: admission.path),
      "Rejected host substitution materialized an admission artifact"
    )
  }

  private static func journalDiagnosticsProjectAndBindSource(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "journal_projection")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let diagnosticClock = AdmissionDiagnosticClock(1_061_000)
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: TacuaDiagnosticJournal.rootDirectory(sessionDirectory: session),
      localSessionID: harness.localSessionID,
      bootSessionID: harness.clock.bootSessionID,
      maximumEvents: TacuaCapturePolicy.maximumDiagnosticJournalEvents,
      monotonicClock: { diagnosticClock.value }
    )
    _ = try journal.append(.routeTransition(
      fromRoute: "/projects/{project_id}",
      toRoute: "/projects/{project_id}/review",
      trigger: .user
    ))
    diagnosticClock.value = 1_062_000
    _ = try journal.append(.userInteraction(action: .tap, target: "review.submit"))
    diagnosticClock.value = 1_063_000
    _ = try journal.append(.runtimeError(
      errorClass: "ui.render",
      sanitizedMessage: "The review view could not render.",
      stackTraceDigest: "sha256:" + String(repeating: "a", count: 64),
      handled: true
    ))
    diagnosticClock.value = 1_064_000
    _ = try journal.append(.networkRequestCompleted(
      method: .post,
      host: "api.example.test",
      pathTemplate: "/reviews/{review_id}",
      statusCode: 503,
      durationMilliseconds: 250,
      traceID: String(repeating: "b", count: 32)
    ))
    diagnosticClock.value = 1_065_000
    _ = try journal.append(.appStateChanged(fromState: .active, toState: .inactive))
    diagnosticClock.value = 1_066_000
    _ = try journal.append(.customState(
      providerID: "navigation_snapshot",
      snapshotDigest: "sha256:" + String(repeating: "c", count: 64),
      collectionStatus: .available
    ))
    diagnosticClock.value = 1_080_000
    _ = try journal.appendSystemEvent(.captureGap(
      gapID: stableTestIdentifier(prefix: "g", source: "LOCAL-GAP-PRIVATE"),
      affectedStreams: [.appAudio, .appVideo, .microphone]
    ))
    diagnosticClock.value = 1_090_000
    _ = try journal.appendSystemEvent(.issueMark(
      markerID: stableTestIdentifier(prefix: "m", source: "LOCAL-MARKER-PRIVATE"),
      kind: .manual
    ))

    let sourceURL = journal.fileURL
    let handle = try FileHandle(forWritingTo: sourceURL)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("{".utf8))
    try handle.synchronize()
    try handle.close()

    let result = try harness.coordinator.admit(harness.input)
    try require(result.admittedOperationCount == 2, "Journal changed the upload operation count")
    let queue = try required(harness.queues.queue, "Journal admission lost its queue")
    let diagnosticOperation = try required(
      queue.operations.first(where: { $0.kind == .diagnostic }),
      "Journal admission lost the diagnostic operation"
    )
    let bindings = try required(
      diagnosticOperation.localPayloadBindings,
      "Journal admission lost payload bindings"
    )
    try require(
      bindings.map(\.role) == [.diagnosticEnvelope, .diagnosticSourceJournal],
      "Journal source was not bound after the upload envelope"
    )
    try require(
      bindings[1].relativePath
        == "diagnostics/\(harness.localSessionID).diagnostics-v1.jsonl",
      "Journal source binding used the wrong path"
    )

    let envelope = try TacuaCanonicalJSON.parse(Data(contentsOf: session.appendingPathComponent(
      TacuaCaptureAdmissionCoordinator.diagnosticFileName
    )))
    let events = try required(envelope.objectValue?["events"]?.arrayValue, "Events missing")
    try require(events.count == 10, "Journal projection or terminal summary event was lost")
    let eventObjects = try events.map { try $0.requiringObject(keys: [
      "data", "elapsed_ms", "event_id", "event_type", "evidence_refs", "occurred_at",
      "sequence", "source",
    ]) }
    try require(
      eventObjects.map { $0["sequence"]?.integerValue }
        == Array(1...10).map(Int64.init),
      "Projected diagnostic sequence was not dense"
    )
    let elapsed = eventObjects.compactMap { $0["elapsed_ms"]?.integerValue }
    try require(elapsed == elapsed.sorted(), "Projected diagnostics were not chronological")
    try require(
      eventObjects.last?["event_type"]?.stringValue == "custom_state",
      "Capture summary was not terminal"
    )
    let types = eventObjects.compactMap { $0["event_type"]?.stringValue }
    for requiredType in [
      "route_transition", "user_interaction", "runtime_error",
      "network_request_completed", "app_state_changed", "issue_mark", "capture_gap",
    ] {
      try require(types.contains(requiredType), "Journal projection lost \(requiredType)")
    }
    let collectionGaps = try required(
      envelope.objectValue?["collection_gaps"]?.arrayValue,
      "Collection gaps missing"
    )
    try require(collectionGaps.count == 1, "Torn journal tail was not made explicit")
    let customStateProviders = eventObjects.compactMap { event -> String? in
      guard event["event_type"]?.stringValue == "custom_state" else { return nil }
      return event["data"]?.objectValue?["provider_id"]?.stringValue
    }
    try require(
      customStateProviders.contains("diagnostic_journal_recovery"),
      "Torn journal recovery was not represented as unavailable custom state"
    )
    try assertDiagnosticCaptureGapsBindManifest(harness: harness, envelope: envelope)
    let envelopeText = try required(
      String(data: try TacuaCanonicalJSON.data(envelope), encoding: .utf8),
      "Envelope was not UTF-8"
    )
    try require(!envelopeText.contains("LOCAL-MARKER-PRIVATE"), "Raw marker ID leaked")
    try require(!envelopeText.contains("LOCAL-GAP-PRIVATE"), "Raw gap ID leaked")
    _ = try TacuaSDKBackendProtocol.validateRequest(diagnosticOperation.canonicalRequest)
  }

  private static func fullJournalStillAdmitsLateManifestSignalsDeterministically(
    _ fixtures: URL
  ) throws {
    let first = try makeHarness(fixtures: fixtures, suffix: "full_journal")
    let second = try makeHarness(fixtures: fixtures, suffix: "full_journal")
    defer {
      try? FileManager.default.removeItem(at: first.root)
      try? FileManager.default.removeItem(at: second.root)
    }
    for harness in [first, second] {
      let session = harness.root.appendingPathComponent(
        harness.localSessionID,
        isDirectory: true
      )
      try writeSyntheticJournal(
        session: session,
        localSessionID: harness.localSessionID,
        bootSessionID: harness.clock.bootSessionID,
        eventCount: TacuaCapturePolicy.maximumDiagnosticJournalEvents
      )
      _ = try harness.coordinator.admit(harness.input)
    }

    let firstData = try diagnosticEnvelopeData(first)
    let secondData = try diagnosticEnvelopeData(second)
    try require(firstData == secondData, "A full-journal projection was not deterministic")
    let envelope = try TacuaCanonicalJSON.parse(firstData)
    let events = try required(envelope.objectValue?["events"]?.arrayValue, "Events missing")
    try require(
      events.count <= TacuaDiagnosticJournal.maximumEvents,
      "A 9,998-entry journal plus late manifest signals exceeded 10,000 events"
    )
    let eventObjects = try events.map { try $0.requiringObject(keys: [
      "data", "elapsed_ms", "event_id", "event_type", "evidence_refs", "occurred_at",
      "sequence", "source",
    ]) }
    let types = eventObjects.compactMap { $0["event_type"]?.stringValue }
    try require(types.contains("issue_mark"), "Late manual marker was discarded")
    try require(types.contains("capture_gap"), "Late capture gap was discarded")
    let providers = eventObjects.compactMap { event -> String? in
      guard event["event_type"]?.stringValue == "custom_state" else { return nil }
      return event["data"]?.objectValue?["provider_id"]?.stringValue
    }
    try require(
      providers.contains("diagnostic_projection_overflow"),
      "Full-journal projection omitted diagnostics without an explicit event"
    )
    try require(
      providers.last == "capture_summary",
      "The terminal capture summary was not preserved after overflow"
    )
    let collectionGaps = try required(
      envelope.objectValue?["collection_gaps"]?.arrayValue,
      "Collection gaps missing"
    )
    let overflowGaps = collectionGaps.compactMap { gap -> [String: TacuaJSONValue]? in
      guard let object = gap.objectValue, object["reason"]?.stringValue == "buffer_overflow"
      else { return nil }
      return object
    }
    try require(overflowGaps.count == 1, "Projection overflow did not emit one bounded gap")
    let retainedBeforeSignals = events.count - 2
    let expectedOmitted = TacuaCapturePolicy.maximumDiagnosticJournalEvents + 2
      - retainedBeforeSignals
    try require(
      overflowGaps[0]["detail"]?.stringValue?.contains(
        "omitted \(expectedOmitted) diagnostic events"
      ) == true,
      "Projection overflow did not expose the exact omitted count"
    )
    try assertDiagnosticCaptureGapsBindManifest(harness: first, envelope: envelope)
  }

  private static func repeatedJournalRecoveryGapsStayBounded(_ fixtures: URL) throws {
    let harness = try makeHarness(
      fixtures: fixtures,
      suffix: "bounded_recovery_gaps",
      projectedCollectionGapLimit: 3
    )
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: TacuaDiagnosticJournal.rootDirectory(sessionDirectory: session),
      localSessionID: harness.localSessionID,
      bootSessionID: harness.clock.bootSessionID,
      maximumEvents: TacuaCapturePolicy.maximumDiagnosticJournalEvents,
      monotonicClock: { 1_070_000 }
    )
    for _ in 0..<5 {
      _ = try journal.appendSystemEvent(.collectionGap(.incompleteFinalRecord))
    }
    _ = try harness.coordinator.admit(harness.input)
    let envelope = try TacuaCanonicalJSON.parse(diagnosticEnvelopeData(harness))
    let gaps = try required(
      envelope.objectValue?["collection_gaps"]?.arrayValue,
      "Collection gaps missing"
    )
    try require(gaps.count == 3, "Repeated recovery exceeded the injected collection-gap cap")
    let finalGap = try required(gaps.last?.objectValue, "Overflow collection gap missing")
    try require(finalGap["reason"]?.stringValue == "buffer_overflow", "Overflow was not explicit")
    try require(
      finalGap["detail"]?.stringValue?.contains("3 additional collection-gap records") == true,
      "Overflow did not report the exact omitted recovery-gap count"
    )
    let events = try required(envelope.objectValue?["events"]?.arrayValue, "Events missing")
    let syntheticCaptureGaps = events.compactMap { event -> String? in
      guard let object = event.objectValue,
        object["event_type"]?.stringValue == "capture_gap"
      else { return nil }
      return object["data"]?.objectValue?["gap_id"]?.stringValue
    }
    try require(syntheticCaptureGaps.count == 1, "Recovery manufactured capture-gap events")
    try assertDiagnosticCaptureGapsBindManifest(harness: harness, envelope: envelope)
  }

  private static func legacyFullTornJournalStillRecovers(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "legacy_full_torn")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    try writeSyntheticJournal(
      session: session,
      localSessionID: harness.localSessionID,
      bootSessionID: harness.clock.bootSessionID,
      eventCount: 9_999,
      tornTail: true
    )
    _ = try harness.coordinator.admit(harness.input)
    let envelope = try TacuaCanonicalJSON.parse(diagnosticEnvelopeData(harness))
    let events = try required(envelope.objectValue?["events"]?.arrayValue, "Events missing")
    try require(events.count <= 10_000, "Legacy torn recovery exceeded the runtime event cap")
    let providers = events.compactMap { event -> String? in
      guard let object = event.objectValue,
        object["event_type"]?.stringValue == "custom_state"
      else { return nil }
      return object["data"]?.objectValue?["provider_id"]?.stringValue
    }
    try require(
      providers.contains("diagnostic_journal_recovery"),
      "Legacy 9,999-entry torn journal did not preserve the recovery signal"
    )
    try require(
      providers.contains("diagnostic_projection_overflow"),
      "Legacy 9,999-entry torn journal did not expose projection overflow"
    )
    try assertDiagnosticCaptureGapsBindManifest(harness: harness, envelope: envelope)
  }

  private static func stableTestIdentifier(prefix: String, source: String) -> String {
    let digest = SHA256.hash(data: Data(source.utf8)).map {
      String(format: "%02x", $0)
    }.joined()
    return "\(prefix)_\(digest.prefix(64 - prefix.utf8.count - 1))"
  }

  private static func ambiguousCASConfirmsExactInstall(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "ambiguous")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    harness.queues.installThenThrow = true
    let result = try harness.coordinator.admit(harness.input)
    try require(result.alreadyAdmitted, "Install-then-throw was not confirmed by exact reload")
    try require(harness.queues.compareAndSwapCount == 1, "Ambiguous install retried queue CAS")
    try require(harness.queues.queue?.operations.count == 2, "Ambiguous install lost operations")
  }

  private static func recoversVisibleButUnconfirmedMaterialization(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "materialization_fsync")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    harness.directorySynchronizer.failNext = true
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Admission ignored directory fsync failure")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .persistenceFailure, "Wrong materialization fsync error")
    }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    try require(
      FileManager.default.fileExists(
        atPath: session.appendingPathComponent(
          TacuaCaptureAdmissionCoordinator.diagnosticFileName
        ).path
      ),
      "Test did not exercise a visible final name before fsync failure"
    )
    try require(harness.queues.compareAndSwapCount == 0, "Unconfirmed name reached queue CAS")

    let recovered = try harness.coordinator.admit(harness.input)
    try require(!recovered.alreadyAdmitted, "Materialization recovery skipped initial queue CAS")
    try require(harness.directorySynchronizer.callCount == 3, "Retry did not re-fsync exact name")
    try require(harness.queues.compareAndSwapCount == 1, "Materialization recovery CAS count wrong")
  }

  private static func acceptsLegitimatelyReboundAdmission(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "rebound")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)
    var queue = try required(harness.queues.queue, "Rebind queue missing")
    let rotatedClock = AdmissionTestClock(
      uptimeMilliseconds: 1_240_000,
      bootSessionID: harness.clock.bootSessionID
    )
    try queue.applyExchange(
      remoteSessionID: "session_synthetic",
      scopeDigest: try scopeDigest(harness.scopeData),
      credentialID: "credential_rebound",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:05:00Z",
      previousCredentialID: "credential_synthetic",
      capability: .active,
      issuedAt: "2026-07-21T10:01:00Z",
      clock: rotatedClock
    )
    let requestedAt = try queue.timestampForNewOperation(clock: rotatedClock)
    for operation in queue.operations where operation.kind == .segment || operation.kind == .diagnostic {
      try queue.rebindPreparedOperation(
        operationID: operation.operationID,
        replacement: try reboundRequest(
          operation,
          credentialID: "credential_rebound",
          requestedAt: requestedAt
        ),
        clock: rotatedClock
      )
    }
    harness.queues.queue = queue

    let retried = try harness.coordinator.admit(harness.input)
    try require(retried.alreadyAdmitted, "Semantic rebind broke admission idempotency")
    try require(harness.queues.compareAndSwapCount == 1, "Rebound retry performed queue CAS")
  }

  private static func recoveryGateRunsBeforeMaterialization(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "gate")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    harness.resume.resumeRecovery = true
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Admission bypassed RESUME recovery")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .resumeRecoveryRequired, "Wrong recovery gate error")
    }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    try require(
      !FileManager.default.fileExists(
        atPath: session.appendingPathComponent(
          TacuaCaptureAdmissionCoordinator.admissionFileName
        ).path
      ),
      "Recovery-gated admission materialized an artifact"
    )
    try require(harness.queues.compareAndSwapCount == 0, "Recovery-gated admission mutated queue")
  }

  private static func rejectsSidecarSymlink(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "symlink")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let sidecar = session.appendingPathComponent("segment-000000.segment.json")
    let target = session.appendingPathComponent("sidecar-target.json")
    try FileManager.default.moveItem(at: sidecar, to: target)
    try FileManager.default.createSymbolicLink(at: sidecar, withDestinationURL: target)
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Admission followed a sidecar symlink")
    } catch let error as TacuaCaptureAdmissionError {
      try require(
        error == .unsafeCaptureStorage || error == .captureArtifactMismatch,
        "Sidecar symlink surfaced an unrelated error"
      )
    }
    try require(harness.queues.compareAndSwapCount == 0, "Symlink admission mutated queue")
  }

  private static func rejectsMissingRetentionAuthority(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "legacy")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var queue = try TacuaTransportQueueV3(localSessionID: harness.localSessionID)
    try queue.applyRecoveredStart(
      remoteSessionID: "session_synthetic",
      scopeDigest: try scopeDigest(harness.scopeData),
      credentialID: "credential_synthetic",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      timeAnchor: TacuaServerTimeAnchor(
        issuedAt: "2026-07-21T09:57:01Z",
        issuedEpochMilliseconds: try required(
          TacuaProtocolTimestamp.parseMilliseconds("2026-07-21T09:57:01Z"),
          "Invalid test timestamp"
        ),
        uptimeMillisecondsAtIssue: 1_000_000,
        bootSessionID: harness.clock.bootSessionID,
        minimumEpochMilliseconds: try required(
          TacuaProtocolTimestamp.parseMilliseconds("2026-07-21T09:57:01Z"),
          "Invalid test timestamp"
        )
      )
    )
    harness.queues.queue = queue
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Legacy queue guessed retention authority")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .retentionAuthorityMissing, "Wrong legacy retention error")
    }
  }

  private static func rejectsLegacyBootlessManifest(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "legacy_manifest")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try mutateManifest(harness) { manifest in
      manifest["schemaVersion"] = 2
      manifest.removeValue(forKey: "bootSessionId")
    }
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Bootless schema-2 capture was admitted")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .captureClockUnavailable, "Wrong legacy capture clock error")
    }
    try require(harness.queues.compareAndSwapCount == 0, "Legacy capture mutated queue")
  }

  private static func requiresExplicitPartialRecoveryChoice(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "partial_choice")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try mutateManifest(harness) { $0["state"] = "partial" }
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Raw partial capture bypassed recovery choice")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .captureNotFinalized, "Wrong raw-partial error")
    }
    try require(harness.queues.compareAndSwapCount == 0, "Raw partial capture mutated queue")
  }

  private static func conflictingStableIDDoesNotMaterialize(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "id_conflict")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var queue = try required(harness.queues.queue, "Conflict queue missing")
    let requestedAt = try queue.timestampForNewOperation(clock: harness.clock)
    let differentDigest = "sha256:" + String(repeating: "a", count: 64)
    let differentSidecar = "sha256:" + String(repeating: "b", count: 64)
    let request = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_segment_000000",
      sessionID: "session_synthetic",
      scopeDigest: try scopeDigest(harness.scopeData),
      credentialID: "credential_synthetic",
      sequence: 0,
      segmentID: "segment_conflict",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: 1,
        contentDigest: differentDigest,
        sidecarDigest: differentSidecar
      ),
      requestedAt: requestedAt
    )
    try queue.enqueueNewOperation(
      kind: .segment,
      operationID: request.operationID,
      requestCredentialID: request.credentialID,
      request: try TacuaCanonicalJSON.parse(request.canonicalData),
      requestDigest: request.requestDigest,
      localPayloadBindings: [
        TacuaLocalPayloadBinding(
          role: .segmentMedia,
          relativePath: "different.mov",
          contentDigest: differentDigest
        ),
        TacuaLocalPayloadBinding(
          role: .segmentSidecar,
          relativePath: "different.segment.json",
          contentDigest: differentSidecar
        ),
      ],
      clock: harness.clock
    )
    harness.queues.queue = queue
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("Conflicting stable upload ID was admitted")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .admissionConflict, "Wrong stable-ID conflict error")
    }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    try require(
      !FileManager.default.fileExists(
        atPath: session.appendingPathComponent(
          TacuaCaptureAdmissionCoordinator.admissionFileName
        ).path
      ),
      "Known stable-ID conflict materialized an admission artifact"
    )
    try require(harness.queues.compareAndSwapCount == 0, "Conflict performed queue CAS")
  }

  private static func extraAdmissionOperationDoesNotMaterialize(_ fixtures: URL) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "extra_operation")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var queue = try required(harness.queues.queue, "Extra-operation queue missing")
    let contentDigest = "sha256:" + String(repeating: "c", count: 64)
    let sidecarDigest = "sha256:" + String(repeating: "d", count: 64)
    let request = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_segment_000999",
      sessionID: "session_synthetic",
      scopeDigest: try scopeDigest(harness.scopeData),
      credentialID: "credential_synthetic",
      sequence: 999,
      segmentID: "segment_000999",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: 1,
        contentDigest: contentDigest,
        sidecarDigest: sidecarDigest
      ),
      requestedAt: try queue.timestampForNewOperation(clock: harness.clock)
    )
    try queue.enqueueNewOperation(
      kind: .segment,
      operationID: request.operationID,
      requestCredentialID: request.credentialID,
      request: try TacuaCanonicalJSON.parse(request.canonicalData),
      requestDigest: request.requestDigest,
      localPayloadBindings: [
        TacuaLocalPayloadBinding(
          role: .segmentMedia,
          relativePath: "extra.mov",
          contentDigest: contentDigest
        ),
        TacuaLocalPayloadBinding(
          role: .segmentSidecar,
          relativePath: "extra.segment.json",
          contentDigest: sidecarDigest
        ),
      ],
      clock: harness.clock
    )
    harness.queues.queue = queue

    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion("A different admission namespace was accepted")
    } catch let error as TacuaCaptureAdmissionError {
      try require(error == .admissionConflict, "Wrong extra-operation conflict error")
    }
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    try require(
      !FileManager.default.fileExists(
        atPath: session.appendingPathComponent(
          TacuaCaptureAdmissionCoordinator.admissionFileName
        ).path
      ),
      "Extra admission operation allowed artifact materialization"
    )
    try require(harness.queues.compareAndSwapCount == 0, "Extra operation performed queue CAS")
  }

  private static func uploadCoordinatorDrivesCompletionAndCleanup(
    _ fixtures: URL
  ) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_success")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try rewriteCaptureAsSchema4(harness)
    _ = try harness.coordinator.admit(harness.input)
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let staging = session.appendingPathComponent(".tacua-upload-staging", isDirectory: true)
    try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
    let orphan = staging.appendingPathComponent(
      "upload-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.snapshot"
    )
    try Data("crash-left-private-media".utf8).write(to: orphan)
    let sender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let coordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      clock: harness.clock
    )
    let result: TacuaCaptureUploadResult
    do { result = try await coordinator.drive(localSessionID: harness.localSessionID) }
    catch {
      throw CaptureAdmissionTestFailure.assertion(
        "Upload drive failed after \(sender.observedCallCount()) sends: \(error)"
      )
    }
    try require(result.payloadCleanupState == .payloadsRemoved, "Upload did not finish cleanup")
    try require(result.segmentReceiptCount == 1, "Segment receipt was not committed")
    try require(result.diagnosticReceiptCount == 1, "Diagnostic receipt was not committed")
    try require(!result.alreadyCompleted, "First completed drive was reported as an old retry")
    try require(sender.observedCallCount() == 3, "Drive did not send segment, diagnostic, completion")
    let completionRequest = try required(
      sender.observedRequests().first(where: { $0.kind == .completion }),
      "Drive did not retain its completion request"
    )
    let completion = try TacuaCanonicalJSON.parse(completionRequest.canonicalData)
    let persistedAccounting = try required(
      completion.objectValue?["capture_manifest"]?.objectValue?["app_audio_accounting"]?
        .objectValue,
      "Completion manifest lost exact schema-4 accounting"
    )
    let persistedDrop = try required(
      persistedAccounting["segments"]?.arrayValue?.first?.objectValue?["drops"]?
        .arrayValue?.first?.objectValue,
      "Completion manifest lost the exact app-audio drop"
    )
    try require(
      persistedDrop["attempt_index"]?.integerValue == 300
        && persistedDrop["cause"]?.stringValue == "input_backpressure",
      "Completion request changed exact app-audio accounting"
    )
    let queue = try required(harness.queues.queue, "Upload drive lost its queue")
    try require(
      queue.completionCleanupAuthority?.completionID == "completion_capture_000001",
      "Validated completion receipt did not install cleanup authority"
    )
    try require(
      queue.operations.allSatisfy({ $0.state == .responseStored }),
      "Upload drive left a non-terminal network operation"
    )
    for name in [
      "segment-000000.mov", "segment-000000.segment.json",
      TacuaCaptureAdmissionCoordinator.diagnosticFileName,
    ] {
      try require(
        !FileManager.default.fileExists(atPath: session.appendingPathComponent(name).path),
        "Receipt-authorized cleanup retained \(name)"
      )
    }
    try require(
      !FileManager.default.fileExists(atPath: orphan.path),
      "Receipt-authorized cleanup retained a crash-left upload snapshot"
    )
    try require(
      !FileManager.default.fileExists(atPath: staging.path),
      "Receipt-authorized cleanup retained the emptied upload staging directory"
    )
    try require(
      !FileManager.default.fileExists(atPath: session.path),
      "Receipt-authorized cleanup retained the local capture session"
    )
    try require(harness.gate.activeLeaseCount == 0, "Drive leaked its lifecycle lease")

    let repeated = try await coordinator.drive(localSessionID: harness.localSessionID)
    try require(repeated.alreadyCompleted, "Completed retry was not idempotent")
    try require(sender.observedCallCount() == 3, "Completed retry performed network I/O")
  }

  private static func uploadCancellationKeepsUnknownOutcomeAndLease(
    _ fixtures: URL
  ) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_cancel")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)
    let sender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    sender.suspendUntilCancelled = true
    let coordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      clock: harness.clock
    )
    let task = Task {
      try await coordinator.drive(localSessionID: harness.localSessionID)
    }
    for _ in 0..<500 where sender.observedCallCount() == 0 {
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    try require(sender.observedCallCount() == 1, "Cancellation test never entered transport")
    try require(harness.gate.activeLeaseCount == 1, "Drive released its lease during network I/O")
    let inFlight = try required(harness.queues.queue, "Cancellation test lost queue")
    try require(
      inFlight.operations.first?.state == .outcomeUnknown,
      "Network I/O began before the unknown-outcome journal was durable"
    )
    task.cancel()
    do {
      _ = try await task.value
      throw CaptureAdmissionTestFailure.assertion("Cancelled upload unexpectedly completed")
    } catch let error as TacuaCaptureUploadError {
      try require(error == .transportOutcomeUnknown, "Cancellation surfaced the wrong recovery state")
    }
    try require(harness.gate.activeLeaseCount == 0, "Cancellation leaked the lifecycle lease")
    try require(
      harness.queues.queue?.operations.first?.state == .outcomeUnknown,
      "Cancellation rewound an outcome-unknown operation to prepared"
    )

    let recoverySender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let recovery = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: recoverySender,
      clock: harness.clock
    )
    let result = try await recovery.drive(localSessionID: harness.localSessionID)
    try require(result.payloadCleanupState == .payloadsRemoved, "Exact cancellation replay failed")
  }

  private static func fileBackedUploadRelaunchReplaysExactUnknownAndCompletes(
    _ fixtures: URL
  ) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_file_relaunch")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)

    let queueRoot = harness.root.appendingPathComponent("transport-queues", isDirectory: true)
    let initialStore = try TacuaTransportQueueFileStore(rootDirectory: queueRoot)
    try initialStore.persistInitial(
      try required(harness.queues.queue, "File-backed relaunch test lost admitted queue")
    )

    let firstGate = AdmissionTestLifecycleGate()
    let firstResumeInspector = AdmissionTestResumeInspector()
    let suspendedSender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    suspendedSender.suspendUntilCancelled = true
    let firstCoordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: initialStore,
      lifecycleGate: firstGate,
      resumeRecoveryInspector: firstResumeInspector,
      sender: suspendedSender,
      clock: harness.clock
    )
    let firstDrive = Task {
      try await firstCoordinator.drive(localSessionID: harness.localSessionID)
    }
    for _ in 0..<500 where suspendedSender.observedCallCount() == 0 {
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    try require(
      suspendedSender.observedCallCount() == 1,
      "File-backed relaunch test never entered transport"
    )
    let originalRequest = try required(
      suspendedSender.observedRequests().first,
      "File-backed relaunch test did not retain its attempted request"
    )
    let durableUnknown = try required(
      initialStore.load(localSessionID: harness.localSessionID),
      "File-backed queue vanished during the first upload attempt"
    )
    let durableOperation = try required(
      durableUnknown.operations.first(where: { $0.operationID == originalRequest.operationID }),
      "File-backed queue did not contain the attempted operation"
    )
    try require(
      durableOperation.state == .outcomeUnknown,
      "File-backed queue did not persist outcome-unknown before transport"
    )
    try require(
      durableOperation.canonicalRequest == originalRequest.canonicalData
        && durableOperation.requestDigest == originalRequest.requestDigest,
      "File-backed queue changed the attempted request"
    )

    firstDrive.cancel()
    do {
      _ = try await firstDrive.value
      throw CaptureAdmissionTestFailure.assertion(
        "Cancelled file-backed upload unexpectedly completed"
      )
    } catch let error as TacuaCaptureUploadError {
      try require(
        error == .transportOutcomeUnknown,
        "Cancelled file-backed upload surfaced the wrong recovery state"
      )
    }
    try require(firstGate.activeLeaseCount == 0, "Cancelled file-backed upload leaked its lease")

    let relaunchedStore = try TacuaTransportQueueFileStore(rootDirectory: queueRoot)
    let relaunchedQueue = try required(
      relaunchedStore.load(localSessionID: harness.localSessionID),
      "Relaunch could not reopen the durable upload queue"
    )
    let relaunchedOperation = try required(
      relaunchedQueue.operations.first(where: { $0.operationID == originalRequest.operationID }),
      "Relaunch lost the exact attempted operation"
    )
    try require(
      relaunchedOperation.state == .outcomeUnknown
        && relaunchedOperation.canonicalRequest == originalRequest.canonicalData
        && relaunchedOperation.requestDigest == originalRequest.requestDigest,
      "Relaunch did not recover the exact outcome-unknown request"
    )

    let recoverySender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let recoveryGate = AdmissionTestLifecycleGate()
    let recovery = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: relaunchedStore,
      lifecycleGate: recoveryGate,
      resumeRecoveryInspector: AdmissionTestResumeInspector(),
      sender: recoverySender,
      clock: harness.clock
    )
    let result = try await recovery.drive(localSessionID: harness.localSessionID)
    let replayedRequest = try required(
      recoverySender.observedRequests().first,
      "Relaunch did not replay the interrupted request"
    )
    try require(
      replayedRequest.canonicalData == originalRequest.canonicalData
        && replayedRequest.requestDigest == originalRequest.requestDigest,
      "Relaunch rewrote the interrupted request"
    )
    try require(
      recoverySender.observedCallCount() == 3,
      "Relaunch did not replay segment, diagnostic, and completion exactly once"
    )
    try require(
      result.payloadCleanupState == .payloadsRemoved && !result.alreadyCompleted,
      "Relaunch did not finish receipt-authorized cleanup"
    )
    try require(recoveryGate.activeLeaseCount == 0, "Recovered upload leaked its lease")
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    try require(
      !FileManager.default.fileExists(atPath: session.path),
      "Recovered upload retained the local capture directory"
    )

    let terminalStore = try TacuaTransportQueueFileStore(rootDirectory: queueRoot)
    let terminalQueue = try required(
      terminalStore.load(localSessionID: harness.localSessionID),
      "Terminal upload queue did not survive process relaunch"
    )
    try require(
      terminalQueue.payloadCleanupState == .payloadsRemoved
        && terminalQueue.completionCleanupAuthority?.completionID
          == "completion_capture_000001"
        && terminalQueue.operations.allSatisfy({ $0.state == .responseStored }),
      "Terminal file-backed queue did not preserve completion authority"
    )

    let retrySender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let retryGate = AdmissionTestLifecycleGate()
    let retryCoordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: terminalStore,
      lifecycleGate: retryGate,
      resumeRecoveryInspector: AdmissionTestResumeInspector(),
      sender: retrySender,
      clock: harness.clock
    )
    let repeated = try await retryCoordinator.drive(localSessionID: harness.localSessionID)
    try require(repeated.alreadyCompleted, "Terminal relaunch was not idempotent")
    try require(retrySender.observedCallCount() == 0, "Terminal relaunch performed network I/O")
    try require(retryGate.activeLeaseCount == 0, "Terminal relaunch leaked its lease")
  }

  private static func uploadRechecksRetentionBetweenNetworkOperations(
    _ fixtures: URL
  ) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_retention_boundary")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)
    let sender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let retention = AdmissionTestRetentionChecker(lifecycleGate: harness.gate)
    // The coordinator checks once after acquiring the lease and immediately before each drive
    // step. Expire on the first check after a completed network operation.
    retention.failOnCheck = 3
    let coordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      retentionChecker: retention,
      clock: harness.clock
    )

    do {
      _ = try await coordinator.drive(localSessionID: harness.localSessionID)
      throw CaptureAdmissionTestFailure.assertion(
        "Upload continued after the retention boundary"
      )
    } catch AdmissionTestRetentionError.expired {}
    try require(sender.observedCallCount() == 1, "Expiry allowed another raw-data operation")
    try require(retention.checkCount == 3, "Upload did not recheck retention after transport")
    try require(harness.gate.activeLeaseCount == 0, "Expiry leaked the lifecycle lease")
  }

  private static func uploadCancelsAtRetentionDeadlineWithoutAwaitingLateSender(
    _ fixtures: URL
  ) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_inflight_expiry")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)
    let sender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    sender.suspendUntilCancelled = true
    sender.ignoreCancellation = true
    sender.suspensionNanoseconds = 500_000_000
    let retention = AdmissionTestRetentionChecker(lifecycleGate: harness.gate)
    retention.stopUptimeMilliseconds = harness.clock.uptimeMilliseconds + 20
    retention.retireOnCheck = 3
    let coordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      retentionChecker: retention,
      clock: harness.clock
    )

    let startedAt = Date()
    do {
      _ = try await coordinator.drive(localSessionID: harness.localSessionID)
      throw CaptureAdmissionTestFailure.assertion("In-flight expiry returned success")
    } catch let error as TacuaCaptureUploadError {
      try require(error == .retentionExpired, "In-flight expiry surfaced the wrong error")
    }
    try require(
      Date().timeIntervalSince(startedAt) < 0.35,
      "Upload waited for a sender that ignored cancellation"
    )
    try require(sender.observedCallCount() == 1, "In-flight expiry did not enter transport once")
    try require(retention.stopQueryCount == 1, "Upload did not use one immutable stop uptime")
    try require(retention.checkCount == 3, "Post-timeout retention enforcement did not run")
    try require(harness.gate.activeLeaseCount == 0, "In-flight expiry leaked lifecycle lease")
    try await Task.sleep(nanoseconds: 600_000_000)
    try require(
      harness.queues.queue?.operations.first?.state == .outcomeUnknown,
      "A late sender receipt committed after the retention race was settled"
    )
  }

  private static func uploadAtRetentionBoundaryStartsNoRequest(_ fixtures: URL) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_at_expiry")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)
    let sender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let retention = AdmissionTestRetentionChecker(lifecycleGate: harness.gate)
    retention.stopUptimeMilliseconds = harness.clock.uptimeMilliseconds
    retention.retireOnCheck = 3
    let coordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      retentionChecker: retention,
      clock: harness.clock
    )

    do {
      _ = try await coordinator.drive(localSessionID: harness.localSessionID)
      throw CaptureAdmissionTestFailure.assertion("At-boundary upload returned success")
    } catch let error as TacuaCaptureUploadError {
      try require(error == .retentionExpired, "At-boundary upload surfaced the wrong error")
    }
    try require(sender.observedCallCount() == 0, "At-boundary upload started network I/O")
    try require(
      harness.queues.queue?.operations.first?.state == .outcomeUnknown,
      "At-boundary refusal rewound its durable conservative state"
    )
    try require(retention.checkCount == 3, "At-boundary cleanup enforcement did not run")
    try require(harness.gate.activeLeaseCount == 0, "At-boundary expiry leaked lifecycle lease")
  }

  private static func uploadRetentionCleanupFailureKeepsRetryJournal(
    _ fixtures: URL
  ) async throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "upload_cleanup_retry")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    _ = try harness.coordinator.admit(harness.input)
    let sender = AdmissionTestSender { request in
      try validatedReceipt(for: request, fixtures: fixtures)
    }
    let retention = AdmissionTestRetentionChecker(lifecycleGate: harness.gate)
    retention.stopUptimeMilliseconds = harness.clock.uptimeMilliseconds
    retention.failOnCheck = 3
    let coordinator = TacuaCaptureUploadCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.root,
      queueStore: harness.queues,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      retentionChecker: retention,
      clock: harness.clock
    )

    do {
      _ = try await coordinator.drive(localSessionID: harness.localSessionID)
      throw CaptureAdmissionTestFailure.assertion("Cleanup-failure upload returned success")
    } catch let error as TacuaCaptureUploadError {
      try require(
        error == .retentionCleanupPending,
        "Retention cleanup failure was reported as successful expiry"
      )
    }
    try require(sender.observedCallCount() == 0, "Cleanup-failure case started network I/O")
    try require(
      harness.queues.queue?.operations.first?.state == .outcomeUnknown,
      "Cleanup failure removed or rewound its durable retry journal"
    )
    try require(harness.gate.activeLeaseCount == 0, "Cleanup failure leaked lifecycle lease")
  }

  private static func validatedReceipt(
    for request: TacuaPreparedBackendRequest,
    fixtures: URL
  ) throws -> TacuaValidatedBackendReceipt {
    let requestValue = try TacuaCanonicalJSON.parse(request.canonicalData)
    guard case .object(let root) = requestValue else {
      throw CaptureAdmissionTestFailure.assertion("Upload request was not an object")
    }
    let response: TacuaJSONValue
    switch request.kind {
    case .segment:
      guard case .object(let transport)? = root["transport"],
        case .object(var object) = try fixture(fixtures, "segment-upload-receipt"),
        case .object(var runtime)? = object["runtime_receipt"]
      else { throw CaptureAdmissionTestFailure.assertion("Invalid segment response fixture") }
      for field in [
        "upload_id", "session_id", "scope_digest", "credential_id", "sequence",
        "segment_id", "sidecar_digest",
      ] { object[field] = root[field] }
      object["intent_digest"] = root["intent_digest"]
      object["content_type"] = transport["content_type"]
      object["transport_digest"] = transport["content_digest"]
      runtime["segment_id"] = root["segment_id"]
      runtime["size_bytes"] = transport["size_bytes"]
      runtime["content_digest"] = transport["content_digest"]
      runtime["received_at"] = .string("2026-07-21T10:02:00Z")
      runtime["receipt_digest"] = .string(try TacuaCanonicalJSON.digest(
        .object(runtime), omittingRootField: "receipt_digest"
      ))
      object["runtime_receipt"] = .object(runtime)
      object["segment_receipt_digest"] = .string(try TacuaCanonicalJSON.digest(
        .object(object), omittingRootField: "segment_receipt_digest"
      ))
      response = .object(object)
    case .diagnostic:
      guard case .object(let envelope)? = root["envelope"],
        case .object(let transport)? = root["transport"],
        case .object(var object) = try fixture(fixtures, "diagnostic-upload-receipt")
      else { throw CaptureAdmissionTestFailure.assertion("Invalid diagnostic response fixture") }
      for field in ["upload_id", "session_id", "scope_digest", "credential_id"] {
        object[field] = root[field]
      }
      object["request_digest"] = root["request_digest"]
      object["envelope_digest"] = envelope["envelope_digest"]
      object["envelope_id"] = envelope["envelope_id"]
      object["size_bytes"] = transport["size_bytes"]
      object["transport_digest"] = transport["content_digest"]
      object["received_at"] = .string("2026-07-21T10:02:04Z")
      object["diagnostic_receipt_digest"] = .string(try TacuaCanonicalJSON.digest(
        .object(object), omittingRootField: "diagnostic_receipt_digest"
      ))
      response = .object(object)
    case .completion:
      guard case .object(let manifest)? = root["capture_manifest"],
        case .array(let segmentReceipts)? = root["segment_receipts"],
        case .array(let diagnosticReceipts)? = root["diagnostic_receipts"],
        case .object(var object) = try fixture(fixtures, "completion-receipt"),
        case .object(var credential)? = object["credential"],
        case .object(var cleanup)? = object["local_cleanup"],
        case .object(var job)? = object["processing_job"],
        case .object(var inputs)? = job["inputs"]
      else { throw CaptureAdmissionTestFailure.assertion("Invalid completion response fixture") }
      for field in ["completion_id", "session_id", "scope_digest"] { object[field] = root[field] }
      object["request_digest"] = root["request_digest"]
      object["accepted_at"] = .string("2026-07-21T10:02:06Z")
      credential["credential_id"] = root["credential_id"]
      credential["replay_completion_id"] = root["completion_id"]
      object["credential"] = .object(credential)
      let segmentDigests = try segmentReceipts.map { receipt -> TacuaJSONValue in
        guard let digest = receipt.objectValue?["segment_receipt_digest"] else {
          throw CaptureAdmissionTestFailure.assertion("Segment receipt digest missing")
        }
        return digest
      }
      let diagnosticDigests = try diagnosticReceipts.map { receipt -> TacuaJSONValue in
        guard let digest = receipt.objectValue?["diagnostic_receipt_digest"] else {
          throw CaptureAdmissionTestFailure.assertion("Diagnostic receipt digest missing")
        }
        return digest
      }
      cleanup["manifest_digest"] = manifest["manifest_digest"]
      cleanup["segment_receipt_digests"] = .array(segmentDigests)
      cleanup["diagnostic_receipt_digests"] = .array(diagnosticDigests)
      object["local_cleanup"] = .object(cleanup)
      job["build_id"] = manifest["build_id"]
      job["build_identity_digest"] = manifest["build_identity_digest"]
      job["organization_id"] = manifest["organization_id"]
      job["project_id"] = manifest["project_id"]
      job["session_id"] = root["session_id"]
      job["requested_at"] = .string("2026-07-21T10:02:06Z")
      inputs["capture_manifest_digest"] = manifest["manifest_digest"]
      inputs["diagnostic_envelope_digests"] = .array(try diagnosticReceipts.map { receipt in
        guard let digest = receipt.objectValue?["envelope_digest"] else {
          throw CaptureAdmissionTestFailure.assertion("Envelope digest missing")
        }
        return digest
      })
      job["inputs"] = .object(inputs)
      job["job_digest"] = .string(try TacuaCanonicalJSON.digest(
        .object(job), omittingRootField: "job_digest"
      ))
      object["processing_job"] = .object(job)
      object["completion_receipt_digest"] = .string(try TacuaCanonicalJSON.digest(
        .object(object), omittingRootField: "completion_receipt_digest"
      ))
      response = .object(object)
    case .deletion:
      throw CaptureAdmissionTestFailure.assertion("Upload coordinator sent deletion")
    }
    let data = try TacuaCanonicalJSON.data(response)
    return try TacuaSDKBackendProtocol.validateResponse(
      data,
      forCanonicalRequest: request.canonicalData
    )
  }

  private static func fixture(_ root: URL, _ name: String) throws -> TacuaJSONValue {
    let data = try Data(contentsOf: root.appendingPathComponent("\(name).json"))
    return try TacuaCanonicalJSON.parse(data)
  }

  private static func makeHarness(
    fixtures: URL,
    suffix: String,
    projectedDiagnosticEventLimit: Int = TacuaDiagnosticJournal.maximumEvents,
    projectedDiagnosticEventByteLimit: Int = TacuaCaptureAdmissionCoordinator
      .maximumProjectedDiagnosticEventBytes,
    projectedCollectionGapLimit: Int = TacuaCaptureAdmissionCoordinator
      .maximumProjectedCollectionGaps
  ) throws -> AdmissionHarness {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-capture-admission-\(suffix)-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let localSessionID = "local_admission_\(suffix)"
      .replacingOccurrences(of: "-", with: "_")
    let session = root.appendingPathComponent(localSessionID, isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: false)
    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.tacua.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let buildData = try Data(contentsOf: fixtures.appendingPathComponent("build-identity.json"))
    let scopeData = try Data(contentsOf: fixtures.appendingPathComponent("capture-scope.json"))
    let clock = AdmissionTestClock(
      uptimeMilliseconds: 1_180_000,
      bootSessionID: "boot_capture_admission"
    )
    var queue = try TacuaTransportQueueV3(localSessionID: localSessionID)
    let receivedAt = "2026-07-21T09:57:01Z"
    let receivedMilliseconds = try required(
      TacuaProtocolTimestamp.parseMilliseconds(receivedAt),
      "Invalid fixture time"
    )
    try queue.applyRecoveredStart(
      remoteSessionID: "session_synthetic",
      scopeDigest: try scopeDigest(scopeData),
      credentialID: "credential_synthetic",
      transportConfigurationDigest: configuration.configurationDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      timeAnchor: TacuaServerTimeAnchor(
        issuedAt: receivedAt,
        issuedEpochMilliseconds: receivedMilliseconds,
        uptimeMillisecondsAtIssue: 1_000_000,
        bootSessionID: clock.bootSessionID,
        minimumEpochMilliseconds: receivedMilliseconds
      ),
      sessionRetentionAuthority: TacuaSessionRetentionAuthority(
        sessionReceivedAt: receivedAt,
        rawMediaExpiresAt: "2026-08-20T09:57:01Z",
        derivedDataExpiresAt: "2026-08-20T09:57:01Z"
      ),
      sessionArtifacts: try TacuaDurableSessionArtifacts.canonicalizing(
        buildIdentityJSON: buildData,
        scopeJSON: scopeData
      )
    )
    try writeCapture(session: session, localSessionID: localSessionID)
    let gate = AdmissionTestLifecycleGate()
    let resume = AdmissionTestResumeInspector()
    let queues = AdmissionTestQueueStore(queue: queue)
    let directorySynchronizer = AdmissionTestDirectorySynchronizer()
    let coordinator = TacuaCaptureAdmissionCoordinator(
      configuration: configuration,
      captureRootDirectory: root,
      queueStore: queues,
      lifecycleGate: gate,
      resumeRecoveryInspector: resume,
      clock: clock,
      directorySynchronizer: directorySynchronizer.synchronize,
      projectedDiagnosticEventLimit: projectedDiagnosticEventLimit,
      projectedDiagnosticEventByteLimit: projectedDiagnosticEventByteLimit,
      projectedCollectionGapLimit: projectedCollectionGapLimit
    )
    return AdmissionHarness(
      root: root,
      localSessionID: localSessionID,
      configuration: configuration,
      buildData: buildData,
      scopeData: scopeData,
      clock: clock,
      gate: gate,
      resume: resume,
      queues: queues,
      directorySynchronizer: directorySynchronizer,
      coordinator: coordinator
    )
  }

  private static func writeCapture(session: URL, localSessionID: String) throws {
    let media = Data((0..<2_048).map { UInt8($0 % 251) })
    let mediaHash = SHA256.hash(data: media).map { String(format: "%02x", $0) }.joined()
    let segment = AdmissionTestSegment(
      index: 0,
      fileName: "segment-000000.mov",
      sha256: mediaHash,
      byteLength: Int64(media.count),
      firstMediaPTSSeconds: 0,
      lastMediaPTSSeconds: 60,
      firstHostUptimeSeconds: 1_060,
      lastHostUptimeSeconds: 1_120,
      durationSeconds: 60,
      videoSamples: 120,
      heldVideoSamples: 1,
      appAudioSamples: 600,
      microphoneSamples: 600,
      droppedVideoSamples: 0,
      droppedAppAudioSamples: 0,
      droppedMicrophoneSamples: 0
    )
    let sidecarData = try JSONEncoder().encode(segment)
    let segmentObject = try JSONSerialization.jsonObject(with: sidecarData)
    let manifest: [String: Any] = [
      "schemaVersion": 3,
      "bootSessionId": "boot_capture_admission",
      "sessionId": localSessionID,
      "organizationId": "org_synthetic",
      "projectId": "project_synthetic",
      "buildId": "build_synthetic",
      "handoffId": "handoff_private",
      "handoffTokenIdentifier": "handoff_private_token",
      "expiresAt": "2026-07-22T10:00:00Z",
      "consentVersion": "tacua-local-capture-consent-v1",
      "expectedApplicationId": "dev.tacua.synthetic",
      "expectedBuildNumber": "42",
      "createdAt": "2026-07-21T09:58:00Z",
      "segmentDurationSeconds": 60,
      "maximumDurationSeconds": 1_800,
      "state": "completed",
      "startedAt": "2026-07-21T09:58:01Z",
      "automaticStopAt": NSNull(),
      "startedHostUptimeSeconds": 1_060,
      "automaticStopHostUptimeSeconds": NSNull(),
      "stoppedHostUptimeSeconds": 1_120,
      "stopReason": "user",
      "resumeCount": 0,
      "lastResumedAt": NSNull(),
      "segments": [segmentObject],
      "gaps": [[
        "id": "LOCAL-GAP-PRIVATE",
        "reason": "app_backgrounded",
        "openedHostUptimeSeconds": 1_080,
        "closedHostUptimeSeconds": 1_081,
        "priorMediaPTSSeconds": 20,
        "nextMediaPTSSeconds": 21,
      ]],
      "markers": [[
        "id": "LOCAL-MARKER-PRIVATE",
        "label": "PRIVATE_MARKER_LABEL",
        "hostUptimeSeconds": 1_090,
        "latestMediaPTSSeconds": 30,
      ]],
      "calibrations": [],
      "errorCodes": ["PRIVATE_ERROR_DETAIL"],
      "droppedBeforeFirstVideo": ["appAudio": 0, "microphone": 0],
      "droppedDuringBackground": ["appAudio": 0, "microphone": 0],
      "microphoneSamplesObserved": 600,
      "appAudioSamplesObserved": 600,
    ]
    try media.write(to: session.appendingPathComponent("segment-000000.mov"))
    try sidecarData.write(to: session.appendingPathComponent("segment-000000.segment.json"))
    try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys]).write(
      to: session.appendingPathComponent("manifest.json")
    )
  }

  private static func diagnosticEnvelopeData(_ harness: AdmissionHarness) throws -> Data {
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    return try Data(contentsOf: session.appendingPathComponent(
      TacuaCaptureAdmissionCoordinator.diagnosticFileName
    ))
  }

  private static func assertDiagnosticCaptureGapsBindManifest(
    harness: AdmissionHarness,
    envelope: TacuaJSONValue
  ) throws {
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let admission = try TacuaCanonicalJSON.parse(Data(contentsOf: session.appendingPathComponent(
      TacuaCaptureAdmissionCoordinator.admissionFileName
    )))
    let seed = try required(
      admission.objectValue?["capture_manifest_seed"]?.objectValue,
      "Capture manifest seed missing"
    )
    let manifestGaps = try required(seed["gaps"]?.arrayValue, "Manifest gaps missing")
    let manifestGapIDs = Set(manifestGaps.compactMap { $0.objectValue?["gap_id"]?.stringValue })
    let events = try required(envelope.objectValue?["events"]?.arrayValue, "Events missing")
    let diagnosticGapIDs = Set(events.compactMap { event -> String? in
      guard let object = event.objectValue,
        object["event_type"]?.stringValue == "capture_gap"
      else { return nil }
      return object["data"]?.objectValue?["gap_id"]?.stringValue
    })
    try require(
      diagnosticGapIDs.isSubset(of: manifestGapIDs),
      "Diagnostic capture_gap referenced a gap outside the capture manifest"
    )
  }

  /// Generates a valid full chain in linear time. Calling append 9,998 times would repeatedly
  /// verify the complete prefix and turn this boundary regression into quadratic test work.
  private static func writeSyntheticJournal(
    session: URL,
    localSessionID: String,
    bootSessionID: String,
    eventCount: Int,
    tornTail: Bool = false
  ) throws {
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: TacuaDiagnosticJournal.rootDirectory(sessionDirectory: session),
      localSessionID: localSessionID,
      bootSessionID: bootSessionID,
      maximumEvents: TacuaDiagnosticJournal.maximumEvents,
      monotonicClock: { 1_061_000 }
    )
    let headerData = try Data(contentsOf: journal.fileURL)
    guard let newline = headerData.firstIndex(of: 0x0A) else {
      throw CaptureAdmissionTestFailure.assertion("Synthetic journal header missing")
    }
    let headerLine = Data(headerData[..<newline])
    let header = try TacuaCanonicalJSON.parse(headerLine)
    var priorDigest = try required(
      header.objectValue?["chain_digest"]?.stringValue,
      "Synthetic journal header digest missing"
    )
    var output = headerData
    let storedEvent = TacuaJSONValue.object([
      "from_state": .string("active"),
      "to_state": .string("inactive"),
      "type": .string("app_state_changed"),
    ])
    for sequence in 1...eventCount {
      let sequenceValue = Int64(sequence)
      let eventSeed = TacuaJSONValue.object([
        "boot_session_id": .string(bootSessionID),
        "event": storedEvent,
        "local_session_id": .string(localSessionID),
        "previous_chain_digest": .string(priorDigest),
        "sequence": .integer(sequenceValue),
      ])
      let eventDigest = try TacuaCanonicalJSON.digest(eventSeed)
      let eventID = "event_" + String(eventDigest.dropFirst("sha256:".count).prefix(58))
      let unhashed = TacuaJSONValue.object([
        "boot_session_id": .string(bootSessionID),
        "event": storedEvent,
        "event_id": .string(eventID),
        "local_session_id": .string(localSessionID),
        "monotonic_milliseconds": .integer(1_061_000),
        "previous_chain_digest": .string(priorDigest),
        "record_kind": .string("event"),
        "schema_version": .integer(TacuaDiagnosticJournal.schemaVersion),
        "sequence": .integer(sequenceValue),
      ])
      let chainDigest = try TacuaCanonicalJSON.digest(unhashed)
      guard case .object(var record) = unhashed else {
        throw CaptureAdmissionTestFailure.assertion("Synthetic record was not an object")
      }
      record["chain_digest"] = .string(chainDigest)
      output.append(try TacuaCanonicalJSON.data(.object(record)))
      output.append(0x0A)
      priorDigest = chainDigest
    }
    if tornTail { output.append(contentsOf: Data("{".utf8)) }
    let handle = try FileHandle(forWritingTo: journal.fileURL)
    try handle.truncate(atOffset: 0)
    try handle.write(contentsOf: output)
    try handle.synchronize()
    try handle.close()
  }

  private static func scopeDigest(_ data: Data) throws -> String {
    let scope = try TacuaCanonicalJSON.parse(data)
    return try required(scope.objectValue?["scope_digest"]?.stringValue, "Scope digest missing")
  }

  private static func reboundRequest(
    _ operation: TacuaQueuedOperation,
    credentialID: String,
    requestedAt: String
  ) throws -> TacuaPreparedBackendRequest {
    let value = try TacuaCanonicalJSON.parse(operation.canonicalRequest)
    guard case .object(var object) = value else {
      throw CaptureAdmissionTestFailure.assertion("Queued request was not an object")
    }
    let digestField = operation.kind == .segment ? "intent_digest" : "request_digest"
    object["credential_id"] = .string(credentialID)
    object["requested_at"] = .string(requestedAt)
    object.removeValue(forKey: digestField)
    let digest = try TacuaCanonicalJSON.digest(.object(object), omittingRootField: digestField)
    object[digestField] = .string(digest)
    return TacuaPreparedBackendRequest(
      kind: operation.kind,
      operationID: operation.operationID,
      credentialID: credentialID,
      canonicalData: try TacuaCanonicalJSON.data(.object(object)),
      requestDigest: digest
    )
  }

  private static func mutateManifest(
    _ harness: AdmissionHarness,
    _ mutation: (inout [String: Any]) -> Void
  ) throws {
    let url = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
      .appendingPathComponent("manifest.json")
    let data = try Data(contentsOf: url)
    guard var manifest = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw CaptureAdmissionTestFailure.assertion("Test manifest was not an object")
    }
    mutation(&manifest)
    try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys]).write(to: url)
  }

  private static func rewriteCaptureAsSchema4(
    _ harness: AdmissionHarness,
    segmentMutation: (inout [String: Any]) -> Void = { _ in },
    manifestMutation: (inout [String: Any]) -> Void = { _ in }
  ) throws {
    let session = harness.root.appendingPathComponent(harness.localSessionID, isDirectory: true)
    let sidecarURL = session.appendingPathComponent("segment-000000.segment.json")
    let sidecarData = try Data(contentsOf: sidecarURL)
    guard var segment = try JSONSerialization.jsonObject(with: sidecarData) as? [String: Any]
    else {
      throw CaptureAdmissionTestFailure.assertion("Test segment sidecar was not an object")
    }
    segment["appAudioSamples"] = 599
    segment["droppedAppAudioSamples"] = 1
    segment["appAudioAppendAttemptStartIndex"] = 1
    segment["appAudioAppendAttempts"] = 600
    segment["appAudioAppendDrops"] = [[
      "attemptIndex": 300,
      "cause": "input_backpressure",
    ]]
    segmentMutation(&segment)
    try JSONSerialization.data(withJSONObject: segment, options: [.sortedKeys]).write(
      to: sidecarURL
    )

    let manifestURL = session.appendingPathComponent("manifest.json")
    let manifestData = try Data(contentsOf: manifestURL)
    guard var manifest = try JSONSerialization.jsonObject(with: manifestData) as? [String: Any]
    else {
      throw CaptureAdmissionTestFailure.assertion("Test manifest was not an object")
    }
    manifest["schemaVersion"] = 4
    manifest["appAudioAppendAccountingVersion"] = 1
    manifest["appAudioAppendAccountingComplete"] = true
    manifest["appAudioAppendAttemptsObserved"] = 600
    manifest["appAudioAppendReservedThroughIndex"] = 600
    manifest["appAudioAppendUnknownRanges"] = []
    manifest["appAudioSamplesObserved"] = 599
    manifest["segments"] = [segment]
    manifestMutation(&manifest)
    try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys]).write(
      to: manifestURL
    )
  }

  private static func expectSchema4AccountingRejection(
    _ fixtures: URL,
    suffix: String,
    segmentMutation: (inout [String: Any]) -> Void = { _ in },
    manifestMutation: (inout [String: Any]) -> Void = { _ in }
  ) throws {
    let harness = try makeHarness(fixtures: fixtures, suffix: "schema4_audio_\(suffix)")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try rewriteCaptureAsSchema4(
      harness,
      segmentMutation: segmentMutation,
      manifestMutation: manifestMutation
    )
    do {
      _ = try harness.coordinator.admit(harness.input)
      throw CaptureAdmissionTestFailure.assertion(
        "Malformed schema-4 app-audio accounting \(suffix) was admitted"
      )
    } catch let error as TacuaCaptureAdmissionError {
      try require(
        error == .captureArtifactMismatch,
        "Malformed schema-4 app-audio accounting \(suffix) surfaced \(error)"
      )
    }
    try require(
      harness.queues.compareAndSwapCount == 0,
      "Rejected schema-4 app-audio accounting \(suffix) mutated the queue"
    )
  }

  private static func required<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw CaptureAdmissionTestFailure.assertion(message) }
    return value
  }
}
