// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaCaptureGapInsertionDisposition: Equatable {
  case append
  case appendOverflowSentinel
  case coalesceIntoOverflowSentinel
  case replaceLastWithOverflowSentinel
}

enum TacuaCapturePolicy {
  static let maximumDurationSeconds: Double = 1_800
  /// Admission timestamps are persisted after ReplayKit stop and writer-finalization callbacks.
  /// The 30-minute media budget therefore needs the two 15-second watchdog envelopes plus one
  /// second of conservative millisecond rounding/dispatch tolerance.
  static let maximumAdmissionDurationMilliseconds: Int64 = 1_831_000
  /// The runtime envelope has 10,000 slots. Capture reserves one terminal-summary slot and one
  /// projection-overflow slot so a late manifest marker or gap can never make admission fail.
  static let maximumDiagnosticJournalEvents = 9_998
  static let maximumManifestGaps = 2_048
  static let maximumManifestMarkers = 2_048
  static let minimumFreeStorageBytes: Int64 = 256 * 1_024 * 1_024
  static let maximumCatchUpSegmentRotations = 60
  static let minimumSegmentBoundaryToleranceSeconds: Double = 1e-9
  static let startWatchdogSeconds: Double = 60
  static let stopWatchdogSeconds: Double = 15
  static let writerFinalizationWatchdogSeconds: Double = 15
  static let microphoneStartupWatchdogSeconds: Double = 8
  static let microphoneGapToleranceSeconds: Double = 3
  static let videoClockDiscontinuityToleranceSeconds: Double = 0.5
  static let requiredConsentVersion = "tacua-local-capture-consent-v1"

  static func isAdmissionDurationValid(_ durationMilliseconds: Int64) -> Bool {
    (0...maximumAdmissionDurationMilliseconds).contains(durationMilliseconds)
  }

  static func captureGapInsertionDisposition(
    existingCount: Int,
    overflowSentinelPresent: Bool
  ) -> TacuaCaptureGapInsertionDisposition? {
    guard existingCount >= 0, existingCount <= maximumManifestGaps else { return nil }
    if overflowSentinelPresent { return .coalesceIntoOverflowSentinel }
    if existingCount < maximumManifestGaps - 1 { return .append }
    if existingCount == maximumManifestGaps - 1 { return .appendOverflowSentinel }
    return .replaceLastWithOverflowSentinel
  }

  static func terminalState(
    segmentCount: Int,
    gapCount: Int,
    errorCount: Int,
    microphoneSamplesObserved: Int
  ) -> String {
    guard segmentCount > 0 else { return "failed_no_verified_segments" }
    guard microphoneSamplesObserved > 0 else { return "partial" }
    return gapCount == 0 && errorCount == 0 ? "completed" : "partial"
  }

  static func hasReachedDeadline(hostUptimeSeconds: Double, deadlineHostUptimeSeconds: Double?) -> Bool {
    guard let deadlineHostUptimeSeconds else { return false }
    return hostUptimeSeconds >= deadlineHostUptimeSeconds
  }

  /// A process resume starts a new ReplayKit lease, not a new logical QA session. Every segment
  /// and gap remains relative to the first capture origin, so the resume callback may fill a
  /// missing origin but must never replace an existing one.
  static func preservedSessionStartHostUptime(
    existing: Double?,
    resumeCandidate: Double
  ) -> Double {
    existing ?? resumeCandidate
  }

  /// Persisted host-uptime values are meaningful only on the boot that produced them. Legacy
  /// schema-2 sessions remain available to the explicit recovery/finalization APIs, but must not
  /// restart ReplayKit because they have no durable boot identity to prove that chronology.
  static func canResumeStoredSession(
    schemaVersion: Int,
    storedBootSessionID: String?,
    currentBootSessionID: String
  ) -> Bool {
    (schemaVersion == 3 || schemaVersion == 4)
      && !currentBootSessionID.isEmpty
      && storedBootSessionID == currentBootSessionID
  }

  static func hasSufficientStorage(
    availableBytes: Int64?,
    requiredBytes: Int64 = minimumFreeStorageBytes
  ) -> Bool {
    guard let availableBytes, requiredBytes >= 0 else { return false }
    return availableBytes >= requiredBytes
  }

  static func shouldAdmitCaptureSample(
    backgroundGapOpen: Bool,
    foregroundSignalObserved: Bool
  ) -> Bool {
    !backgroundGapOpen || foregroundSignalObserved
  }

  static func microphoneStreamHasStalled(
    latestVideoPTSSeconds: Double,
    latestVideoHostUptimeSeconds: Double,
    latestMicrophonePTSSeconds: Double?,
    latestMicrophoneHostUptimeSeconds: Double?
  ) -> Bool {
    guard let latestMicrophonePTSSeconds, let latestMicrophoneHostUptimeSeconds else {
      return false
    }
    return latestVideoPTSSeconds - latestMicrophonePTSSeconds > microphoneGapToleranceSeconds
      && latestVideoHostUptimeSeconds - latestMicrophoneHostUptimeSeconds > microphoneGapToleranceSeconds
  }

  static func videoClockHasDiscontinuity(
    priorMediaPTSSeconds: Double,
    currentMediaPTSSeconds: Double,
    priorHostUptimeSeconds: Double,
    currentHostUptimeSeconds: Double
  ) -> Bool {
    let mediaDelta = currentMediaPTSSeconds - priorMediaPTSSeconds
    let hostDelta = currentHostUptimeSeconds - priorHostUptimeSeconds
    guard mediaDelta.isFinite, hostDelta.isFinite, mediaDelta >= 0, hostDelta >= 0 else {
      return true
    }
    return abs(mediaDelta - hostDelta) > videoClockDiscontinuityToleranceSeconds
  }

  static func segmentRotationBoundary(
    startedAtPTSSeconds: Double,
    incomingPTSSeconds: Double,
    segmentDurationSeconds: Double
  ) -> Double? {
    segmentRotationBoundaries(
      startedAtPTSSeconds: startedAtPTSSeconds,
      incomingPTSSeconds: incomingPTSSeconds,
      segmentDurationSeconds: segmentDurationSeconds
    ).first
  }

  static func segmentRotationBoundaries(
    startedAtPTSSeconds: Double,
    incomingPTSSeconds: Double,
    segmentDurationSeconds: Double
  ) -> [Double] {
    guard case .boundaries(let boundaries) = segmentRotationPlan(
      startedAtPTSSeconds: startedAtPTSSeconds,
      incomingPTSSeconds: incomingPTSSeconds,
      segmentDurationSeconds: segmentDurationSeconds
    ) else { return [] }
    return boundaries
  }

  static func segmentRotationPlan(
    startedAtPTSSeconds: Double,
    incomingPTSSeconds: Double,
    segmentDurationSeconds: Double,
    maximumBoundaryCount: Int = maximumCatchUpSegmentRotations
  ) -> SegmentRotationPlan {
    guard startedAtPTSSeconds.isFinite,
      incomingPTSSeconds.isFinite,
      segmentDurationSeconds.isFinite,
      segmentDurationSeconds > 0,
      maximumBoundaryCount > 0
    else { return .none }

    let elapsedSeconds = incomingPTSSeconds - startedAtPTSSeconds
    let magnitude = [
      1,
      abs(startedAtPTSSeconds),
      abs(incomingPTSSeconds),
      abs(segmentDurationSeconds),
    ].max() ?? 1
    let toleranceSeconds = max(
      minimumSegmentBoundaryToleranceSeconds,
      magnitude * Double.ulpOfOne * 8
    )
    guard elapsedSeconds + toleranceSeconds >= segmentDurationSeconds else {
      return .none
    }

    let rawBoundaryCount = elapsedSeconds / segmentDurationSeconds
    let nearestBoundaryCount = rawBoundaryCount.rounded()
    let nearestElapsedSeconds = nearestBoundaryCount * segmentDurationSeconds
    let normalizedBoundaryCount = abs(elapsedSeconds - nearestElapsedSeconds) <= toleranceSeconds
      ? nearestBoundaryCount
      : rawBoundaryCount.rounded(.down)
    guard normalizedBoundaryCount.isFinite, normalizedBoundaryCount > 0 else {
      return .none
    }
    guard normalizedBoundaryCount <= Double(maximumBoundaryCount) else {
      return .excessive
    }

    let boundaries: [Double] = (1...Int(normalizedBoundaryCount)).compactMap { index -> Double? in
      let boundary = startedAtPTSSeconds + Double(index) * segmentDurationSeconds
      guard boundary.isFinite, boundary <= incomingPTSSeconds + toleranceSeconds else { return nil }
      // A tolerance-admitted exact boundary may be a fraction later than the
      // incoming Double. Clamp it so the next writer never starts after the
      // sample that triggered rotation.
      return min(boundary, incomingPTSSeconds)
    }
    return boundaries.isEmpty ? .none : .boundaries(boundaries)
  }

  static func recoverySource(finalExists: Bool, partialExists: Bool) -> RecoverySource? {
    if finalExists { return .finalized }
    if partialExists { return .verifiedPartial }
    return nil
  }

  static func stopTimeoutDisposition(
    recorderStillRecording: Bool,
    attempt: Int,
    maximumAttempts: Int = 2
  ) -> StopTimeoutDisposition {
    guard recorderStillRecording else { return .finalizeStopped }
    return attempt < maximumAttempts ? .retry : .preserveActiveSession
  }
}

enum SegmentRotationPlan: Equatable {
  case none
  case boundaries([Double])
  case excessive
}

enum RecoverySource: Equatable {
  case finalized
  case verifiedPartial
}

enum StopTimeoutDisposition: Equatable {
  case finalizeStopped
  case retry
  case preserveActiveSession
}

struct CandidateHandoffEnvelope {
  let organizationId: String
  let projectId: String
  let buildId: String
  let handoffId: String
  let handoffTokenIdentifier: String?
  let expiresAt: String
  let consentVersion: String
  let expectedApplicationId: String
  let expectedBuildNumber: String
}

enum CandidateHandoffValidationError: Error, Equatable {
  case invalidField(String)
  case expired
  case applicationMismatch
  case buildMismatch
  case unsupportedConsentVersion
}

extension CandidateHandoffEnvelope {
  func validate(
    now: Date,
    actualApplicationId: String?,
    actualBuildNumber: String?
  ) throws -> Date {
    let requiredIdentifiers: [(String, String)] = [
      ("organizationId", organizationId),
      ("projectId", projectId),
      ("buildId", buildId),
      ("handoffId", handoffId),
      ("expectedBuildNumber", expectedBuildNumber),
    ]
    for (field, value) in requiredIdentifiers where !Self.isValidIdentifier(value) {
      throw CandidateHandoffValidationError.invalidField(field)
    }
    if let handoffTokenIdentifier, !Self.isValidIdentifier(handoffTokenIdentifier) {
      throw CandidateHandoffValidationError.invalidField("handoffTokenIdentifier")
    }
    guard Self.isValidApplicationId(expectedApplicationId) else {
      throw CandidateHandoffValidationError.invalidField("expectedApplicationId")
    }
    guard consentVersion == TacuaCapturePolicy.requiredConsentVersion else {
      throw CandidateHandoffValidationError.unsupportedConsentVersion
    }
    guard let expiration = Self.parseISO8601(expiresAt) else {
      throw CandidateHandoffValidationError.invalidField("expiresAt")
    }
    guard expiration > now else {
      throw CandidateHandoffValidationError.expired
    }
    guard actualApplicationId == expectedApplicationId else {
      throw CandidateHandoffValidationError.applicationMismatch
    }
    guard actualBuildNumber == expectedBuildNumber else {
      throw CandidateHandoffValidationError.buildMismatch
    }
    return expiration
  }

  /// Authorizes local erasure without depending on a handoff's freshness or the
  /// build which originally created the data. Erasure must remain possible after
  /// expiration, consent-contract changes, and app upgrades.
  func validateDeletionScope(actualApplicationId: String?) throws {
    let requiredIdentifiers: [(String, String)] = [
      ("organizationId", organizationId),
      ("projectId", projectId),
      ("handoffId", handoffId),
    ]
    for (field, value) in requiredIdentifiers where !Self.isValidIdentifier(value) {
      throw CandidateHandoffValidationError.invalidField(field)
    }
    guard Self.isValidApplicationId(expectedApplicationId) else {
      throw CandidateHandoffValidationError.invalidField("expectedApplicationId")
    }
    guard actualApplicationId == expectedApplicationId else {
      throw CandidateHandoffValidationError.applicationMismatch
    }
  }

  private static func isValidIdentifier(_ value: String) -> Bool {
    value.range(
      of: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
      options: .regularExpression
    ) != nil
  }

  private static func isValidApplicationId(_ value: String) -> Bool {
    guard value.count <= 255 else { return false }
    return value.range(
      of: "^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)+$",
      options: .regularExpression
    ) != nil
  }

  private static func parseISO8601(_ value: String) -> Date? {
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = fractional.date(from: value) { return date }
    return ISO8601DateFormatter().date(from: value)
  }
}
