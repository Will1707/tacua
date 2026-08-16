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
    try boundedArtifactCapacity()
    try terminalClassification()
    try admissionDurationEnvelope()
    try storageAndLifecycleAdmission()
    try sessionOriginSurvivesResume()
    try deadlineAndMicrophoneContinuity()
    try videoClockContinuity()
    try retainedReplayKitVideoFrameSequence()
    try retainedMarkerSegmentIndexesSurviveRecovery()
    try issueMarkerPersistenceResolution()
    try segmentRotation()
    try crashWindowRecoverySource()
    try candidateHandoffValidation()
    try deletionAuthorizationAndStopSafety()
    print("Tacua capture core policy tests passed")
  }

  private static func admissionDurationEnvelope() throws {
    try expect(
      TacuaCapturePolicy.isAdmissionDurationValid(1_831_000),
      "The exact ReplayKit stop/finalization envelope was rejected"
    )
    try expect(
      !TacuaCapturePolicy.isAdmissionDurationValid(1_831_001),
      "A capture beyond the bounded stop/finalization envelope was admitted"
    )
  }

  private static func boundedArtifactCapacity() throws {
    try expect(
      TacuaCapturePolicy.maximumDiagnosticJournalEvents == 9_998,
      "The journal must reserve one summary slot and one overflow-signal slot"
    )
    try expect(
      TacuaCapturePolicy.maximumManifestGaps == 2_048,
      "The persisted capture gap cap drifted from the runtime contract"
    )
    try expect(
      TacuaCapturePolicy.maximumManifestMarkers == 2_048,
      "The persisted capture marker cap drifted from the runtime contract"
    )
    try expect(
      TacuaCapturePolicy.maximumProcessableIssueMarks == 12,
      "The native issue-mark cap drifted from the processor contract"
    )
    try expect(
      TacuaCapturePolicy.retainedMarkerPTSProvenance == "retained_replaykit_append_v1",
      "The retained-frame marker provenance drifted from the admission contract"
    )
    try expect(
      TacuaCapturePolicy.canAppendProcessableIssueMark(existingCount: 11),
      "The final processor-supported issue-mark slot was rejected"
    )
    try expect(
      !TacuaCapturePolicy.canAppendProcessableIssueMark(existingCount: 12),
      "Native capture allowed a marker that would make the processor reject the capture"
    )
    let manifestMarkerIDs = (0..<11).map { "m_\($0)" }
    try expect(
      TacuaCapturePolicy.processableIssueMarkCount(
        manifestMarkerIDs: manifestMarkerIDs,
        journalMarkerIDs: manifestMarkerIDs + ["m_journal_only"]
      ) == 12,
      "A recovered journal-only marker was omitted from the native capacity projection"
    )
    try expect(
      !TacuaCapturePolicy.canAppendProcessableIssueMark(existingCount:
        TacuaCapturePolicy.processableIssueMarkCount(
          manifestMarkerIDs: manifestMarkerIDs,
          journalMarkerIDs: manifestMarkerIDs + ["m_journal_only"]
        ) ?? -1
      ),
      "Recovery reopened a thirteenth processor issue-mark slot"
    )
    try expect(
      TacuaCapturePolicy.processableIssueMarkCount(
        manifestMarkerIDs: ["m_manifest_only"],
        journalMarkerIDs: ["m_journal", "m_journal"]
      ) == 3,
      "Duplicate journal records were undercounted relative to admission"
    )
    try expect(
      TacuaCapturePolicy.processableIssueMarkCount(
        manifestMarkerIDs: ["m_collision", "m_collision"],
        journalMarkerIDs: []
      ) == nil,
      "Colliding manifest marker identifiers were accepted during recovery"
    )
    try expect(
      TacuaCapturePolicy.captureGapInsertionDisposition(
        existingCount: 2_046,
        overflowSentinelPresent: false
      ) == .append,
      "Ordinary gaps stopped before the reserved overflow slot"
    )
    try expect(
      TacuaCapturePolicy.captureGapInsertionDisposition(
        existingCount: 2_047,
        overflowSentinelPresent: false
      ) == .appendOverflowSentinel,
      "The final gap slot was not converted to an explicit overflow signal"
    )
    try expect(
      TacuaCapturePolicy.captureGapInsertionDisposition(
        existingCount: 2_048,
        overflowSentinelPresent: true
      ) == .coalesceIntoOverflowSentinel,
      "Later gaps did not coalesce into the bounded overflow signal"
    )
    try expect(
      TacuaCapturePolicy.captureGapInsertionDisposition(
        existingCount: 2_048,
        overflowSentinelPresent: false
      ) == .replaceLastWithOverflowSentinel,
      "A legacy full manifest could not migrate to bounded coalescing"
    )
    try expect(
      TacuaCapturePolicy.captureGapInsertionDisposition(
        existingCount: 2_049,
        overflowSentinelPresent: false
      ) == nil,
      "An already-invalid gap collection was accepted"
    )
  }

  private static func issueMarkerPersistenceResolution() throws {
    var events: [String] = []
    let durable = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .durable,
      confirmPublishedManifest: { events.append("confirm"); return false },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .unpublished },
      confirmPublishedRollback: { events.append("confirm_rollback"); return false }
    )
    try expect(durable == .committed, "A durable marker was not committed")
    try expect(events.isEmpty, "A durable marker performed unnecessary recovery work")

    events = []
    let unpublished = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .unpublished,
      confirmPublishedManifest: { events.append("confirm"); return false },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .unpublished },
      confirmPublishedRollback: { events.append("confirm_rollback"); return false }
    )
    try expect(unpublished == .rejected, "An unpublished marker was not rejected")
    try expect(events == ["remove"], "An unpublished marker was not rolled back in memory first")

    events = []
    let confirmed = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .publishedUnconfirmed,
      confirmPublishedManifest: { events.append("confirm"); return true },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .unpublished },
      confirmPublishedRollback: { events.append("confirm_rollback"); return false }
    )
    try expect(confirmed == .committed, "A confirmed marker publication was not committed")
    try expect(events == ["confirm"], "Confirmation performed unrelated rollback work")

    events = []
    let rolledBack = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .publishedUnconfirmed,
      confirmPublishedManifest: { events.append("confirm"); return false },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .publishedUnconfirmed },
      confirmPublishedRollback: { events.append("confirm_rollback"); return true }
    )
    try expect(rolledBack == .rejected, "A confirmed marker rollback was not rejected cleanly")
    try expect(
      events == ["confirm", "remove", "rollback", "confirm_rollback"],
      "The ambiguous marker rollback did not preserve safe ordering"
    )

    events = []
    let durablyRolledBack = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .publishedUnconfirmed,
      confirmPublishedManifest: { events.append("confirm"); return false },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .durable },
      confirmPublishedRollback: { events.append("confirm_rollback"); return false }
    )
    try expect(
      durablyRolledBack == .rejected,
      "A durably replaced marker manifest was not rejected cleanly"
    )
    try expect(
      events == ["confirm", "remove", "rollback"],
      "A durable rollback performed an unnecessary confirmation"
    )

    events = []
    let unknown = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .publishedUnconfirmed,
      confirmPublishedManifest: { events.append("confirm"); return false },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .unpublished },
      confirmPublishedRollback: { events.append("confirm_rollback"); return true }
    )
    try expect(unknown == .outcomeUnknown, "An ambiguous marker result claimed ordinary failure")
    try expect(
      events == ["confirm", "remove", "rollback"],
      "The outcome-unknown path performed an invalid confirmation"
    )

    events = []
    let unconfirmedRollback = TacuaCapturePolicy.resolveIssueMarkerPersistence(
      initialAttempt: .publishedUnconfirmed,
      confirmPublishedManifest: { events.append("confirm"); return false },
      removeMarker: { events.append("remove") },
      persistMarkerFreeManifest: { events.append("rollback"); return .publishedUnconfirmed },
      confirmPublishedRollback: { events.append("confirm_rollback"); return false }
    )
    try expect(
      unconfirmedRollback == .outcomeUnknown,
      "An unconfirmed marker-free rollback claimed an ordinary failure"
    )
    try expect(
      events == ["confirm", "remove", "rollback", "confirm_rollback"],
      "The failed rollback confirmation did not preserve safe ordering"
    )
  }

  private static func retainedMarkerSegmentIndexesSurviveRecovery() throws {
    try expect(
      TacuaCapturePolicy.nextSegmentIndexForRecovery(
        committedSegmentIndexes: [],
        retainedMarkerSegmentIndexes: []
      ) == 0,
      "A new session did not start with segment zero"
    )
    try expect(
      TacuaCapturePolicy.nextSegmentIndexForRecovery(
        committedSegmentIndexes: [0],
        retainedMarkerSegmentIndexes: [1]
      ) == 2,
      "Recovery reused the failed writer index retained by a marker"
    )
    try expect(
      TacuaCapturePolicy.nextSegmentIndexForRecovery(
        committedSegmentIndexes: [0, 2],
        retainedMarkerSegmentIndexes: [1]
      ) == 3,
      "Recovery did not advance past the complete reserved index set"
    )
    try expect(
      TacuaCapturePolicy.nextSegmentIndexForRecovery(
        committedSegmentIndexes: [-1],
        retainedMarkerSegmentIndexes: []
      ) == nil,
      "Recovery accepted a negative committed segment index"
    )
    try expect(
      TacuaCapturePolicy.nextSegmentIndexForRecovery(
        committedSegmentIndexes: [],
        retainedMarkerSegmentIndexes: [TacuaCapturePolicy.maximumSegmentIndex]
      ) == nil,
      "Recovery reused an exhausted retained-marker segment index"
    )
  }

  private static func sessionOriginSurvivesResume() throws {
    try expect(
      TacuaCapturePolicy.preservedSessionStartHostUptime(
        existing: 1_060,
        resumeCandidate: 1_600
      ) == 1_060,
      "Same-boot resume replaced the original session host-uptime origin"
    )
    try expect(
      TacuaCapturePolicy.preservedSessionStartHostUptime(
        existing: nil,
        resumeCandidate: 1_060
      ) == 1_060,
      "First capture start did not establish the session host-uptime origin"
    )
    try expect(
      TacuaCapturePolicy.canResumeStoredSession(
        schemaVersion: 3,
        storedBootSessionID: "boot_current",
        currentBootSessionID: "boot_current"
      ),
      "Schema-3 capture from the current boot was not resumable"
    )
    try expect(
      TacuaCapturePolicy.canResumeStoredSession(
        schemaVersion: 4,
        storedBootSessionID: "boot_current",
        currentBootSessionID: "boot_current"
      ),
      "Schema-4 capture from the current boot was not resumable"
    )
    try expect(
      !TacuaCapturePolicy.canResumeStoredSession(
        schemaVersion: 2,
        storedBootSessionID: nil,
        currentBootSessionID: "boot_current"
      ),
      "Bootless schema-2 capture was allowed to restart ReplayKit"
    )
    try expect(
      !TacuaCapturePolicy.canResumeStoredSession(
        schemaVersion: 3,
        storedBootSessionID: "boot_previous",
        currentBootSessionID: "boot_current"
      ),
      "Cross-boot schema-3 capture was allowed to restart ReplayKit"
    )
  }

  private static func storageAndLifecycleAdmission() throws {
    try expect(
      !TacuaCapturePolicy.hasSufficientStorage(availableBytes: nil),
      "Unavailable storage capacity must fail closed"
    )
    try expect(
      !TacuaCapturePolicy.hasSufficientStorage(
        availableBytes: TacuaCapturePolicy.minimumFreeStorageBytes - 1
      ),
      "One byte below the storage threshold must be rejected"
    )
    try expect(
      TacuaCapturePolicy.hasSufficientStorage(
        availableBytes: TacuaCapturePolicy.minimumFreeStorageBytes
      ),
      "The exact storage threshold must be admitted"
    )
    try expect(
      !TacuaCapturePolicy.shouldAdmitCaptureSample(
        backgroundGapOpen: true,
        foregroundSignalObserved: false
      ),
      "Samples must be rejected while a background gap remains open"
    )
    try expect(
      TacuaCapturePolicy.shouldAdmitCaptureSample(
        backgroundGapOpen: true,
        foregroundSignalObserved: true
      ),
      "A foreground lifecycle signal must reopen sample admission"
    )
    try expect(
      TacuaCapturePolicy.shouldAdmitCaptureSample(
        backgroundGapOpen: false,
        foregroundSignalObserved: false
      ),
      "Samples outside a background gap must be admitted"
    )
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

  private static func retainedReplayKitVideoFrameSequence() throws {
    var sequence = TacuaRetainedReplayKitVideoFrameClock()
    try expect(sequence.value == 0, "The retained-video sequence must start at zero")
    try expect(
      sequence.latestPTSSeconds == nil,
      "The marker clock must be unavailable before the first retained ReplayKit video frame"
    )
    try expect(sequence.latestSegmentIndex == nil, "The marker segment must start unavailable")
    sequence.recordReplayKitAppend(ptsSeconds: 10, segmentIndex: 0, wasAppended: false)
    try expect(
      sequence.value == 0,
      "An observed video callback rejected by the writer advanced the retained-video sequence"
    )
    try expect(
      sequence.latestPTSSeconds == nil,
      "An observed video callback rejected by the writer became the marker media clock"
    )

    sequence.recordReplayKitAppend(ptsSeconds: 11, segmentIndex: 0, wasAppended: true)
    try expect(
      sequence.value == 1,
      "The first successfully appended ReplayKit video frame did not advance the sequence"
    )
    try expect(
      sequence.latestPTSSeconds == 11,
      "The marker media clock did not select the first retained ReplayKit frame"
    )
    try expect(
      sequence.latestSegmentIndex == 0,
      "The marker clock did not retain the writer segment that accepted its frame"
    )

    sequence.recordReplayKitAppend(ptsSeconds: 12, segmentIndex: 1, wasAppended: false)
    try expect(
      sequence.value == 1,
      "A later dropped ReplayKit video frame changed the retained-video sequence"
    )
    try expect(
      sequence.latestPTSSeconds == 11 && sequence.latestSegmentIndex == 0,
      "A later dropped ReplayKit video frame replaced retained marker provenance"
    )

    sequence.recordReplayKitAppend(ptsSeconds: 13, segmentIndex: 1, wasAppended: true)
    try expect(
      sequence.value == 2,
      "A later successfully appended ReplayKit video frame did not advance the sequence exactly once"
    )
    try expect(
      sequence.latestPTSSeconds == 13 && sequence.latestSegmentIndex == 1,
      "The marker media provenance did not advance to the later retained ReplayKit frame"
    )

    sequence.recordReplayKitAppend(ptsSeconds: .nan, segmentIndex: 2, wasAppended: true)
    try expect(
      sequence.value == 2
        && sequence.latestPTSSeconds == 13
        && sequence.latestSegmentIndex == 1,
      "An invalid video timestamp changed retained-frame marker state"
    )
    sequence.recordReplayKitAppend(ptsSeconds: 14, segmentIndex: -1, wasAppended: true)
    try expect(
      sequence.value == 2
        && sequence.latestPTSSeconds == 13
        && sequence.latestSegmentIndex == 1,
      "An invalid writer segment changed retained-frame marker state"
    )
  }

  private static func segmentRotation() throws {
    try expect(
      TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
        boundaryPTSSeconds: 10,
        callbackPTSSeconds: 15,
        callbackHostUptimeSeconds: 115
      ) == 110,
      "A sparse ReplayKit callback did not project its synthetic boundary onto the host clock"
    )
    try expect(
      [10.0, 20.0, 30.0].compactMap {
        TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
          boundaryPTSSeconds: $0,
          callbackPTSSeconds: 35,
          callbackHostUptimeSeconds: 135
        )
      } == [110, 120, 130],
      "Catch-up rotation did not preserve monotonic media-to-host boundary spacing"
    )
    try expect(
      TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
        boundaryPTSSeconds: 15,
        callbackPTSSeconds: 15,
        callbackHostUptimeSeconds: 115
      ) == 115,
      "An exact ReplayKit boundary changed its real callback host time"
    )
    try expect(
      TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
        boundaryPTSSeconds: 16,
        callbackPTSSeconds: 15,
        callbackHostUptimeSeconds: 115
      ) == nil,
      "A boundary after its real callback received a fabricated host time"
    )
    try expect(
      TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
        boundaryPTSSeconds: 10,
        callbackPTSSeconds: 15,
        callbackHostUptimeSeconds: 115,
        minimumHostUptimeSeconds: 110.001
      ) == nil,
      "A boundary regressing behind the active writer host clock was accepted"
    )
    try expect(
      TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
        boundaryPTSSeconds: .nan,
        callbackPTSSeconds: 15,
        callbackHostUptimeSeconds: 115
      ) == nil,
      "A non-finite boundary received a fabricated host time"
    )
    try expect(
      TacuaCapturePolicy.segmentBoundaryHostUptimeSeconds(
        boundaryPTSSeconds: 0,
        callbackPTSSeconds: 20,
        callbackHostUptimeSeconds: 10
      ) == nil,
      "A boundary before host-clock origin received a negative host time"
    )
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
    try expect(
      TacuaCapturePolicy.segmentRotationBoundaries(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 125,
        segmentDurationSeconds: 10
      ) == [110, 120],
      "A late sample must return every elapsed segment boundary"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundaries(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 130,
        segmentDurationSeconds: 10
      ) == [110, 120, 130],
      "An exact incoming boundary must be included"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundaries(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 99,
        segmentDurationSeconds: 10
      ).isEmpty,
      "A regressing incoming clock must not create boundaries"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundaries(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: 130,
        segmentDurationSeconds: 0
      ).isEmpty,
      "A non-positive segment duration must not create boundaries"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationBoundaries(
        startedAtPTSSeconds: 100,
        incomingPTSSeconds: .infinity,
        segmentDurationSeconds: 10
      ).isEmpty,
      "Invalid incoming clocks must not create boundaries"
    )
    for timescale in [30.0, 600.0, 44_100.0] {
      let startedAt = 1.0 / timescale
      let incoming = (1.0 + 2.0 * timescale) / timescale
      try expect(
        TacuaCapturePolicy.segmentRotationBoundaries(
          startedAtPTSSeconds: startedAt,
          incomingPTSSeconds: incoming,
          segmentDurationSeconds: 2
        ).count == 1,
        "An exact two-second media boundary at timescale \(Int(timescale)) must survive Double conversion"
      )
    }
    try expect(
      TacuaCapturePolicy.segmentRotationPlan(
        startedAtPTSSeconds: 0,
        incomingPTSSeconds: Double(TacuaCapturePolicy.maximumCatchUpSegmentRotations + 1) * 2,
        segmentDurationSeconds: 2
      ) == .excessive,
      "A single callback must not allocate an unbounded number of catch-up writers"
    )
    try expect(
      TacuaCapturePolicy.segmentRotationPlan(
        startedAtPTSSeconds: 0,
        incomingPTSSeconds: Double(TacuaCapturePolicy.maximumCatchUpSegmentRotations) * 2,
        segmentDurationSeconds: 2
      ) != .excessive,
      "The bounded catch-up limit itself must remain admissible"
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
