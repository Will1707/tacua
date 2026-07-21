// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum TestFailure: Error {
  case assertion(String)
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw TestFailure.assertion(message) }
}

private func expectValidationError(
  _ expected: CandidateHandoffValidationError,
  operation: () throws -> Void
) throws {
  do {
    try operation()
    throw TestFailure.assertion("Expected \(expected), but validation succeeded")
  } catch let error as CandidateHandoffValidationError {
    try expect(error == expected, "Expected \(expected), received \(error)")
  }
}

@main
enum CapturePolicyTests {
  static func main() throws {
    try terminalClassification()
    try deadlineAndMicrophoneContinuity()
    try videoClockContinuity()
    try segmentRotation()
    try crashWindowRecoverySource()
    try candidateHandoffValidation()
    try deletionAuthorizationAndStopSafety()
    print("Tacua capture core policy tests passed")
  }

  private static func videoClockContinuity() throws {
    try expect(
      !TacuaCapturePolicy.videoClockHasDiscontinuity(
        priorMediaPTSSeconds: 10,
        currentMediaPTSSeconds: 16,
        priorHostUptimeSeconds: 110,
        currentHostUptimeSeconds: 116
      ),
      "A static-screen interval advancing equally in media and host clocks is continuous"
    )
    try expect(
      TacuaCapturePolicy.videoClockHasDiscontinuity(
        priorMediaPTSSeconds: 10,
        currentMediaPTSSeconds: 16,
        priorHostUptimeSeconds: 110,
        currentHostUptimeSeconds: 111
      ),
      "A media jump not corroborated by the host clock must create a gap"
    )
    try expect(
      TacuaCapturePolicy.videoClockHasDiscontinuity(
        priorMediaPTSSeconds: 16,
        currentMediaPTSSeconds: 15,
        priorHostUptimeSeconds: 110,
        currentHostUptimeSeconds: 111
      ),
      "A regressing media clock must create a gap"
    )
  }

  private static func segmentRotation() throws {
    try expect(
      TacuaCapturePolicy.segmentRotationBoundary(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 109.999,
        segmentDurationSeconds: 10
      ) == nil,
      "A segment must not rotate before its configured media duration"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundary(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 110,
        segmentDurationSeconds: 10
      ) == 110,
      "The rotation boundary must be inclusive and anchored to the segment start"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundary(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 125,
        segmentDurationSeconds: 10
      ) == 110,
      "A late sample must not stretch the previous segment beyond its boundary"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundary(
        startedAtPTSSeconds: .nan,
        incomingPTSSeconds: 110,
        segmentDurationSeconds: 10
      ) == nil,
      "Invalid clocks must never create a synthetic boundary"
    )
  }

  private static func terminalClassification() throws {
    try expect(
      TacuaCapturePolicy.terminalState(
        segmentCount: 0,
        gapCount: 0,
        errorCount: 0,
        microphoneSamplesObserved: 0
      ) == "failed_no_verified_segments",
      "A session without verified segments must fail"
    )
    try expect(
      TacuaCapturePolicy.terminalState(
        segmentCount: 1,
        gapCount: 0,
        errorCount: 0,
        microphoneSamplesObserved: 0
      ) == "partial",
      "A video-only session must not complete"
    )
    try expect(
      TacuaCapturePolicy.terminalState(
        segmentCount: 1,
        gapCount: 0,
        errorCount: 0,
        microphoneSamplesObserved: 10
      ) == "completed",
      "Verified video plus microphone samples may complete"
    )
    try expect(
      TacuaCapturePolicy.terminalState(
        segmentCount: 1,
        gapCount: 1,
        errorCount: 0,
        microphoneSamplesObserved: 10
      ) == "partial",
      "A gapped session must remain partial"
    )
  }

  private static func deadlineAndMicrophoneContinuity() throws {
    try expect(
      !TacuaCapturePolicy.hasReachedDeadline(
        hostUptimeSeconds: 99.9,
        deadlineHostUptimeSeconds: 100
      ),
      "A session must not stop before its monotonic deadline"
    )
    try expect(
      TacuaCapturePolicy.hasReachedDeadline(
        hostUptimeSeconds: 100,
        deadlineHostUptimeSeconds: 100
      ),
      "The monotonic deadline must be inclusive"
    )
    try expect(
      TacuaCapturePolicy.microphoneStreamHasStalled(
        latestVideoPTSSeconds: 20,
        latestVideoHostUptimeSeconds: 120,
        latestMicrophonePTSSeconds: 16,
        latestMicrophoneHostUptimeSeconds: 116
      ),
      "A microphone stream behind in both clocks must be treated as stalled"
    )
    try expect(
      !TacuaCapturePolicy.microphoneStreamHasStalled(
        latestVideoPTSSeconds: 20,
        latestVideoHostUptimeSeconds: 120,
        latestMicrophonePTSSeconds: 16,
        latestMicrophoneHostUptimeSeconds: 119
      ),
      "Delivery reordering in only one clock must not create a false stall"
    )
  }

  private static func crashWindowRecoverySource() throws {
    try expect(
      TacuaCapturePolicy.recoverySource(finalExists: true, partialExists: true) == .finalized,
      "A final media file must take precedence"
    )
    try expect(
      TacuaCapturePolicy.recoverySource(finalExists: false, partialExists: true) == .verifiedPartial,
      "A sidecar-verified partial must be eligible for atomic promotion"
    )
    try expect(
      TacuaCapturePolicy.recoverySource(finalExists: false, partialExists: false) == nil,
      "Missing media must never be invented"
    )
  }

  private static func candidateHandoffValidation() throws {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let valid = CandidateHandoffEnvelope(
      organizationId: "org_local",
      projectId: "project.sample-mobile-app",
      buildId: "build-31",
      handoffId: "handoff-001",
      handoffTokenIdentifier: "token-id-001",
      expiresAt: "2027-01-15T08:01:00.000Z",
      consentVersion: TacuaCapturePolicy.requiredConsentVersion,
      expectedApplicationId: "com.example.samplemobileapp.tacuaspike",
      expectedBuildNumber: "31"
    )
    _ = try valid.validate(
      now: now,
      actualApplicationId: "com.example.samplemobileapp.tacuaspike",
      actualBuildNumber: "31"
    )

    let expired = CandidateHandoffEnvelope(
      organizationId: valid.organizationId,
      projectId: valid.projectId,
      buildId: valid.buildId,
      handoffId: valid.handoffId,
      handoffTokenIdentifier: valid.handoffTokenIdentifier,
      expiresAt: "2026-01-01T00:00:00Z",
      consentVersion: valid.consentVersion,
      expectedApplicationId: valid.expectedApplicationId,
      expectedBuildNumber: valid.expectedBuildNumber
    )
    try expectValidationError(.expired) {
      _ = try expired.validate(
        now: now,
        actualApplicationId: valid.expectedApplicationId,
        actualBuildNumber: valid.expectedBuildNumber
      )
    }
    try expectValidationError(.applicationMismatch) {
      _ = try valid.validate(
        now: now,
        actualApplicationId: "com.example.other",
        actualBuildNumber: valid.expectedBuildNumber
      )
    }
    try expectValidationError(.buildMismatch) {
      _ = try valid.validate(
        now: now,
        actualApplicationId: valid.expectedApplicationId,
        actualBuildNumber: "32"
      )
    }

    let unsupportedConsent = CandidateHandoffEnvelope(
      organizationId: valid.organizationId,
      projectId: valid.projectId,
      buildId: valid.buildId,
      handoffId: valid.handoffId,
      handoffTokenIdentifier: valid.handoffTokenIdentifier,
      expiresAt: valid.expiresAt,
      consentVersion: "unknown-consent",
      expectedApplicationId: valid.expectedApplicationId,
      expectedBuildNumber: valid.expectedBuildNumber
    )
    try expectValidationError(.unsupportedConsentVersion) {
      _ = try unsupportedConsent.validate(
        now: now,
        actualApplicationId: valid.expectedApplicationId,
        actualBuildNumber: valid.expectedBuildNumber
      )
    }
  }

  private static func deletionAuthorizationAndStopSafety() throws {
    let expiredOldBuild = CandidateHandoffEnvelope(
      organizationId: "org_local",
      projectId: "project.sample-mobile-app",
      buildId: "old-build",
      handoffId: "handoff-001",
      handoffTokenIdentifier: nil,
      expiresAt: "2020-01-01T00:00:00Z",
      consentVersion: "retired-consent-contract",
      expectedApplicationId: "com.example.samplemobileapp.tacuaspike",
      expectedBuildNumber: "1"
    )
    try expiredOldBuild.validateDeletionScope(
      actualApplicationId: "com.example.samplemobileapp.tacuaspike"
    )
    try expectValidationError(.applicationMismatch) {
      try expiredOldBuild.validateDeletionScope(actualApplicationId: "com.example.other")
    }

    try expect(
      TacuaCapturePolicy.stopTimeoutDisposition(
        recorderStillRecording: false,
        attempt: 1
      ) == .finalizeStopped,
      "A missing callback may finalize only after ReplayKit reports capture stopped"
    )
    try expect(
      TacuaCapturePolicy.stopTimeoutDisposition(
        recorderStillRecording: true,
        attempt: 1
      ) == .retry,
      "The first timed-out stop must retry while ReplayKit remains active"
    )
    try expect(
      TacuaCapturePolicy.stopTimeoutDisposition(
        recorderStillRecording: true,
        attempt: 2
      ) == .preserveActiveSession,
      "A still-active recorder must remain attached to a nonterminal session"
    )
  }
}
