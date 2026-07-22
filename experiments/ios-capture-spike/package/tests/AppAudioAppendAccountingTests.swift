// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum TestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw TestFailure.assertion(message) }
}

private func segment(
  index: Int,
  start: Int?,
  attempts: Int?,
  appended: Int,
  dropped: Int,
  drops: [TacuaAppAudioAppendDrop]?
) -> TacuaAppAudioSegmentAccounting {
  TacuaAppAudioSegmentAccounting(
    segmentIndex: index,
    attemptStartIndex: start,
    attemptCount: attempts,
    appendedCount: appended,
    droppedCount: dropped,
    drops: drops
  )
}

private func expectError(
  _ expected: TacuaAppAudioAppendAccountingError,
  _ operation: () throws -> Void
) throws {
  do {
    try operation()
    throw TestFailure.assertion("Expected \(expected), but validation succeeded")
  } catch let error as TacuaAppAudioAppendAccountingError {
    try require(error == expected, "Expected \(expected), received \(error)")
  }
}

@main
enum AppAudioAppendAccountingTests {
  static func main() throws {
    try exactIndexesSpanSegmentsAndCauses()
    try missingDuplicateAndMismatchedDropsFailClosed()
    try resumeDerivesTheNextRunWideIndex()
    try crashReservedRangesPreventIndexReuse()
    try recoveryInfersLeadingInternalAndTailReservedHoles()
    try malformedUnknownRangesFailClosed()
    try exactDropBoundPassesAndOverflowFails()
    try legacyCountsRemainRecoverableButNotExact()
    print("Tacua app-audio append-accounting tests passed")
  }

  private static func exactDropBoundPassesAndOverflowFails() throws {
    let exactDrops = (1...TacuaAppAudioAppendAccounting.maximumTrackedDrops).map {
      TacuaAppAudioAppendDrop(attemptIndex: $0, cause: .inputBackpressure)
    }
    let exact = segment(
      index: 0,
      start: 1,
      attempts: exactDrops.count,
      appended: 0,
      dropped: exactDrops.count,
      drops: exactDrops
    )
    let coverage = try TacuaAppAudioAppendAccounting.validatedCoverage(
      for: [exact],
      unknownRanges: []
    )
    try require(
      coverage.droppedCount == TacuaAppAudioAppendAccounting.maximumTrackedDrops,
      "The exact tracked-drop bound did not remain valid"
    )

    let overflowDrops = exactDrops + [TacuaAppAudioAppendDrop(
      attemptIndex: exactDrops.count + 1,
      cause: .appendRejected
    )]
    try expectError(.dropLimitExceeded) {
      _ = try TacuaAppAudioAppendAccounting.validatedCoverage(
        for: [segment(
          index: 0,
          start: 1,
          attempts: overflowDrops.count,
          appended: 0,
          dropped: overflowDrops.count,
          drops: overflowDrops
        )],
        unknownRanges: []
      )
    }
  }

  private static func exactIndexesSpanSegmentsAndCauses() throws {
    let segments = [
      segment(
        index: 0,
        start: 1,
        attempts: 4,
        appended: 3,
        dropped: 1,
        drops: [TacuaAppAudioAppendDrop(attemptIndex: 2, cause: .inputBackpressure)]
      ),
      segment(index: 1, start: 5, attempts: 0, appended: 0, dropped: 0, drops: []),
      segment(
        index: 2,
        start: 5,
        attempts: 3,
        appended: 2,
        dropped: 1,
        drops: [TacuaAppAudioAppendDrop(attemptIndex: 7, cause: .appendRejected)]
      ),
    ]
    let next = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: segments)
    try require(
      next == 8,
      "The next run-wide index did not cross segment and zero-attempt boundaries"
    )
  }

  private static func missingDuplicateAndMismatchedDropsFailClosed() throws {
    try expectError(.legacyFieldsMissing) {
      _ = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: [
        segment(index: 0, start: nil, attempts: nil, appended: 2, dropped: 1, drops: nil),
      ])
    }
    try expectError(.dropCountMismatch) {
      _ = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: [
        segment(index: 0, start: 1, attempts: 2, appended: 1, dropped: 1, drops: []),
      ])
    }
    try expectError(.invalidDropIndex) {
      _ = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: [
        segment(
          index: 0,
          start: 1,
          attempts: 3,
          appended: 1,
          dropped: 2,
          drops: [
            TacuaAppAudioAppendDrop(attemptIndex: 2, cause: .writerNotWriting),
            TacuaAppAudioAppendDrop(attemptIndex: 2, cause: .writerFinished),
          ]
        ),
      ])
    }
    try expectError(.nonContiguousAttemptRange) {
      _ = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: [
        segment(index: 0, start: 2, attempts: 1, appended: 1, dropped: 0, drops: []),
      ])
    }
  }

  private static func resumeDerivesTheNextRunWideIndex() throws {
    let persisted = [
      segment(index: 4, start: 4, attempts: 2, appended: 2, dropped: 0, drops: []),
      segment(
        index: 3,
        start: 1,
        attempts: 3,
        appended: 2,
        dropped: 1,
        drops: [TacuaAppAudioAppendDrop(attemptIndex: 1, cause: .sampleDataNotReady)]
      ),
    ]
    let next = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: persisted)
    try require(
      next == 6,
      "Resume did not derive the next index from sorted committed segment ranges"
    )
  }

  private static func crashReservedRangesPreventIndexReuse() throws {
    let committed = [
      segment(index: 0, start: 1, attempts: 3, appended: 3, dropped: 0, drops: []),
      segment(index: 1, start: 4_097, attempts: 2, appended: 2, dropped: 0, drops: []),
    ]
    let coverage = try TacuaAppAudioAppendAccounting.validatedCoverage(
      for: committed,
      unknownRanges: [TacuaAppAudioAppendUnknownRange(startIndex: 4, endIndex: 4_096)]
    )
    try require(coverage.nextIndex == 4_099, "Recovery reused a crash-reserved index")
    try require(coverage.actualAttemptCount == 5, "Reserved indexes were counted as attempts")
    try require(coverage.appendedCount == 5, "Known appended samples drifted")
  }

  private static func recoveryInfersLeadingInternalAndTailReservedHoles() throws {
    let missingMiddleSegment = [
      segment(index: 0, start: 1, attempts: 3, appended: 3, dropped: 0, drops: []),
      // Segment 1 finalized asynchronously but was lost before its sidecar committed. Segment 2
      // survived with the next crash-reserved lease, so recovery must preserve the internal hole.
      segment(index: 2, start: 4_097, attempts: 2, appended: 2, dropped: 0, drops: []),
    ]
    let inferred = try TacuaAppAudioAppendAccounting.reconciledRecoveryUnknownRanges(
      for: missingMiddleSegment,
      existingUnknownRanges: [],
      reservedThrough: 8_192
    )
    try require(
      inferred == [
        TacuaAppAudioAppendUnknownRange(startIndex: 4, endIndex: 4_096),
        TacuaAppAudioAppendUnknownRange(startIndex: 4_099, endIndex: 8_192),
      ],
      "Recovery did not infer both the missing committed segment and reserved writer tail"
    )
    let coverage = try TacuaAppAudioAppendAccounting.validatedCoverage(
      for: missingMiddleSegment,
      unknownRanges: inferred
    )
    try require(coverage.nextIndex == 8_193, "Recovery could reuse an inferred reserved hole")
    try require(coverage.actualAttemptCount == 5, "Unknown reservations became append attempts")

    let onlyLaterSegment = [
      segment(index: 1, start: 4_097, attempts: 1, appended: 1, dropped: 0, drops: []),
    ]
    let leading = try TacuaAppAudioAppendAccounting.reconciledRecoveryUnknownRanges(
      for: onlyLaterSegment,
      existingUnknownRanges: [],
      reservedThrough: 4_097
    )
    try require(
      leading == [TacuaAppAudioAppendUnknownRange(startIndex: 1, endIndex: 4_096)],
      "Recovery did not infer a leading reserved hole before the first surviving segment"
    )
  }

  private static func malformedUnknownRangesFailClosed() throws {
    let committed = [
      segment(index: 0, start: 1, attempts: 3, appended: 3, dropped: 0, drops: []),
      segment(index: 1, start: 6, attempts: 1, appended: 1, dropped: 0, drops: []),
    ]
    try expectError(.nonContiguousAttemptRange) {
      _ = try TacuaAppAudioAppendAccounting.validatedCoverage(
        for: committed,
        unknownRanges: [TacuaAppAudioAppendUnknownRange(startIndex: 4, endIndex: 4)]
      )
    }
    try expectError(.invalidUnknownRange) {
      _ = try TacuaAppAudioAppendAccounting.validatedCoverage(
        for: [segment(index: 0, start: 2, attempts: 1, appended: 1, dropped: 0, drops: [])],
        unknownRanges: [TacuaAppAudioAppendUnknownRange(
          startIndex: 1,
          endIndex: 1,
          reason: "invented"
        )]
      )
    }
  }

  private static func legacyCountsRemainRecoverableButNotExact() throws {
    let legacy = [
      segment(index: 0, start: nil, attempts: nil, appended: 4, dropped: 1, drops: nil),
      segment(index: 1, start: nil, attempts: nil, appended: 2, dropped: 0, drops: nil),
    ]
    let next = try TacuaAppAudioAppendAccounting.legacyNextAttemptIndex(for: legacy)
    try require(
      next == 8,
      "Schema-3 count recovery did not derive a collision-free next index"
    )
    try expectError(.legacyFieldsMissing) {
      _ = try TacuaAppAudioAppendAccounting.validatedNextAttemptIndex(for: legacy)
    }
  }
}
