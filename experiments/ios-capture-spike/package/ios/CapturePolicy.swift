// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaCapturePolicy {
  static let maximumDurationSeconds: Double = 1_800
  static let startWatchdogSeconds: Double = 60
  static let stopWatchdogSeconds: Double = 15
  static let writerFinalizationWatchdogSeconds: Double = 15
  static let microphoneStartupWatchdogSeconds: Double = 8
  static let microphoneGapToleranceSeconds: Double = 3
  static let requiredConsentVersion = "tacua-local-capture-consent-v1"

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
