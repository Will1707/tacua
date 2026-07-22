// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaAppAudioAppendDropCause: String, Codable, CaseIterable {
  case sampleDataNotReady = "sample_data_not_ready"
  case writerFinished = "writer_finished"
  case writerNotWriting = "writer_not_writing"
  case timestampInvalid = "timestamp_invalid"
  case inputBackpressure = "input_backpressure"
  case appendRejected = "append_rejected"
}

struct TacuaAppAudioAppendDrop: Codable, Equatable {
  let attemptIndex: Int
  let cause: String

  init(attemptIndex: Int, cause: TacuaAppAudioAppendDropCause) {
    self.attemptIndex = attemptIndex
    self.cause = cause.rawValue
  }
}

struct TacuaAppAudioAppendUnknownRange: Codable, Equatable {
  static let processRecoveryReason = "process_recovery_reservation"

  let startIndex: Int
  let endIndex: Int
  let reason: String

  init(startIndex: Int, endIndex: Int, reason: String = processRecoveryReason) {
    self.startIndex = startIndex
    self.endIndex = endIndex
    self.reason = reason
  }
}

struct TacuaAppAudioSegmentAccounting: Equatable {
  let segmentIndex: Int
  let attemptStartIndex: Int?
  let attemptCount: Int?
  let appendedCount: Int
  let droppedCount: Int
  let drops: [TacuaAppAudioAppendDrop]?
}

enum TacuaAppAudioAppendAccountingError: Error, Equatable {
  case legacyFieldsMissing
  case invalidSegmentIndex
  case invalidCount
  case attemptLimitExceeded
  case dropLimitExceeded
  case nonContiguousAttemptRange
  case dropCountMismatch
  case invalidDropCause
  case invalidDropIndex
  case duplicateDropIndex
  case invalidUnknownRange
  case unknownRangeLimitExceeded
}

struct TacuaAppAudioAppendCoverage: Equatable {
  let nextIndex: Int
  let actualAttemptCount: Int
  let appendedCount: Int
  let droppedCount: Int
}

enum TacuaAppAudioAppendAccounting {
  static let version = 1
  /// Bounds manifest growth while remaining far above the accepted 0.2% physical gate.
  static let maximumTrackedDrops = 2_048
  /// A defensive upper bound for a 30-minute ReplayKit session, not a performance target.
  static let maximumAttempts = 10_000_000
  /// Persisting one lease per callback would impose tens of thousands of synchronous writes.
  /// A bounded lease keeps crash durability practical without silently reusing an issued index.
  static let reservationSize = 4_096
  static let maximumUnknownRanges = 2_048

  static func validatedNextAttemptIndex(
    for segments: [TacuaAppAudioSegmentAccounting]
  ) throws -> Int {
    try validatedCoverage(for: segments, unknownRanges: []).nextIndex
  }

  static func validatedCoverage(
    for segments: [TacuaAppAudioSegmentAccounting],
    unknownRanges: [TacuaAppAudioAppendUnknownRange]
  ) throws -> TacuaAppAudioAppendCoverage {
    let sorted = segments.sorted { left, right in left.segmentIndex < right.segmentIndex }
    guard Set(sorted.map(\.segmentIndex)).count == sorted.count,
      sorted.allSatisfy({ $0.segmentIndex >= 0 })
    else { throw TacuaAppAudioAppendAccountingError.invalidSegmentIndex }

    guard unknownRanges.count <= maximumUnknownRanges else {
      throw TacuaAppAudioAppendAccountingError.unknownRangeLimitExceeded
    }
    let sortedUnknownRanges = unknownRanges.sorted { left, right in
      if left.startIndex == right.startIndex { return left.endIndex < right.endIndex }
      return left.startIndex < right.startIndex
    }

    var nextAttemptIndex = 1
    var actualAttemptCount = 0
    var appendedCount = 0
    var totalDrops = 0
    var seenDropIndexes: Set<Int> = []
    var unknownOffset = 0

    func consumeUnknownRanges(beforeOrAt limit: Int) throws {
      while unknownOffset < sortedUnknownRanges.count {
        let range = sortedUnknownRanges[unknownOffset]
        guard range.startIndex == nextAttemptIndex else {
          if range.startIndex < nextAttemptIndex {
            throw TacuaAppAudioAppendAccountingError.invalidUnknownRange
          }
          return
        }
        guard range.reason == TacuaAppAudioAppendUnknownRange.processRecoveryReason,
          range.endIndex >= range.startIndex,
          range.endIndex <= maximumAttempts,
          range.endIndex < limit
        else {
          if range.startIndex == limit {
            return
          }
          throw TacuaAppAudioAppendAccountingError.invalidUnknownRange
        }
        nextAttemptIndex = range.endIndex + 1
        unknownOffset += 1
      }
    }

    for segment in sorted {
      guard let start = segment.attemptStartIndex,
        let attempts = segment.attemptCount,
        let drops = segment.drops
      else { throw TacuaAppAudioAppendAccountingError.legacyFieldsMissing }
      guard attempts >= 0, segment.appendedCount >= 0, segment.droppedCount >= 0,
        segment.droppedCount <= maximumAttempts,
        segment.appendedCount <= maximumAttempts - segment.droppedCount,
        segment.appendedCount + segment.droppedCount == attempts
      else { throw TacuaAppAudioAppendAccountingError.invalidCount }
      try consumeUnknownRanges(beforeOrAt: start)
      guard start == nextAttemptIndex else {
        throw TacuaAppAudioAppendAccountingError.nonContiguousAttemptRange
      }
      guard attempts <= maximumAttempts - (nextAttemptIndex - 1) else {
        throw TacuaAppAudioAppendAccountingError.attemptLimitExceeded
      }
      let endExclusive = nextAttemptIndex + attempts
      guard drops.count == segment.droppedCount else {
        throw TacuaAppAudioAppendAccountingError.dropCountMismatch
      }
      var previousIndex = 0
      for drop in drops {
        guard TacuaAppAudioAppendDropCause(rawValue: drop.cause) != nil else {
          throw TacuaAppAudioAppendAccountingError.invalidDropCause
        }
        guard drop.attemptIndex >= start,
          drop.attemptIndex < endExclusive,
          drop.attemptIndex > previousIndex
        else { throw TacuaAppAudioAppendAccountingError.invalidDropIndex }
        guard seenDropIndexes.insert(drop.attemptIndex).inserted else {
          throw TacuaAppAudioAppendAccountingError.duplicateDropIndex
        }
        previousIndex = drop.attemptIndex
      }
      guard totalDrops <= maximumTrackedDrops - drops.count else {
        throw TacuaAppAudioAppendAccountingError.dropLimitExceeded
      }
      totalDrops += drops.count
      actualAttemptCount += attempts
      appendedCount += segment.appendedCount
      nextAttemptIndex = endExclusive
    }
    try consumeUnknownRanges(beforeOrAt: maximumAttempts + 1)
    guard unknownOffset == sortedUnknownRanges.count else {
      throw TacuaAppAudioAppendAccountingError.invalidUnknownRange
    }
    return TacuaAppAudioAppendCoverage(
      nextIndex: nextAttemptIndex,
      actualAttemptCount: actualAttemptCount,
      appendedCount: appendedCount,
      droppedCount: totalDrops
    )
  }

  /// Reconstructs every reserved-but-uncommitted hole from the surviving schema-4 sidecars.
  /// Existing ranges are treated only as corroboration: recovery canonicalizes the full leading,
  /// internal, and tail gaps before the ordinary exact-coverage validator runs.
  static func reconciledRecoveryUnknownRanges(
    for segments: [TacuaAppAudioSegmentAccounting],
    existingUnknownRanges: [TacuaAppAudioAppendUnknownRange],
    reservedThrough: Int
  ) throws -> [TacuaAppAudioAppendUnknownRange] {
    guard reservedThrough >= 0, reservedThrough <= maximumAttempts else {
      throw TacuaAppAudioAppendAccountingError.attemptLimitExceeded
    }
    let sorted = segments.sorted { left, right in left.segmentIndex < right.segmentIndex }
    guard Set(sorted.map(\.segmentIndex)).count == sorted.count,
      sorted.allSatisfy({ $0.segmentIndex >= 0 })
    else { throw TacuaAppAudioAppendAccountingError.invalidSegmentIndex }

    guard existingUnknownRanges.count <= maximumUnknownRanges else {
      throw TacuaAppAudioAppendAccountingError.unknownRangeLimitExceeded
    }
    let orderedExisting = existingUnknownRanges.sorted { left, right in
      if left.startIndex == right.startIndex { return left.endIndex < right.endIndex }
      return left.startIndex < right.startIndex
    }
    var priorExistingEnd = 0
    for range in orderedExisting {
      guard range.reason == TacuaAppAudioAppendUnknownRange.processRecoveryReason,
        range.startIndex >= 1,
        range.endIndex >= range.startIndex,
        range.endIndex <= maximumAttempts,
        range.startIndex > priorExistingEnd
      else { throw TacuaAppAudioAppendAccountingError.invalidUnknownRange }
      priorExistingEnd = range.endIndex
    }

    var nextIndex = 1
    var inferred: [TacuaAppAudioAppendUnknownRange] = []
    for segment in sorted {
      guard let start = segment.attemptStartIndex,
        let attempts = segment.attemptCount,
        segment.drops != nil
      else { throw TacuaAppAudioAppendAccountingError.legacyFieldsMissing }
      guard start >= nextIndex, attempts >= 0 else {
        throw TacuaAppAudioAppendAccountingError.nonContiguousAttemptRange
      }
      guard start <= maximumAttempts,
        attempts <= maximumAttempts - (start - 1)
      else { throw TacuaAppAudioAppendAccountingError.attemptLimitExceeded }
      if start > nextIndex {
        guard inferred.count < maximumUnknownRanges else {
          throw TacuaAppAudioAppendAccountingError.unknownRangeLimitExceeded
        }
        inferred.append(TacuaAppAudioAppendUnknownRange(
          startIndex: nextIndex,
          endIndex: start - 1
        ))
      }
      nextIndex = start + attempts
    }
    guard reservedThrough >= nextIndex - 1 else {
      throw TacuaAppAudioAppendAccountingError.attemptLimitExceeded
    }
    if reservedThrough >= nextIndex {
      guard inferred.count < maximumUnknownRanges else {
        throw TacuaAppAudioAppendAccountingError.unknownRangeLimitExceeded
      }
      inferred.append(TacuaAppAudioAppendUnknownRange(
        startIndex: nextIndex,
        endIndex: reservedThrough
      ))
    }

    // Previously persisted unknown ranges may be partial after a crash between reservation and
    // manifest replacement, but they may never claim an index occupied by a surviving segment.
    for existing in orderedExisting {
      guard inferred.contains(where: {
        $0.startIndex <= existing.startIndex && existing.endIndex <= $0.endIndex
      }) else { throw TacuaAppAudioAppendAccountingError.invalidUnknownRange }
    }
    _ = try validatedCoverage(for: sorted, unknownRanges: inferred)
    return inferred
  }

  /// Schema-3 sidecars have counts but no exact drop indexes. Recovery may continue at a unique
  /// index, but the resulting run remains ineligible for app-audio acceptance evidence.
  static func legacyNextAttemptIndex(
    for segments: [TacuaAppAudioSegmentAccounting]
  ) throws -> Int {
    let sorted = segments.sorted { left, right in left.segmentIndex < right.segmentIndex }
    guard Set(sorted.map(\.segmentIndex)).count == sorted.count,
      sorted.allSatisfy({ $0.segmentIndex >= 0 })
    else { throw TacuaAppAudioAppendAccountingError.invalidSegmentIndex }
    var attempts = 0
    for segment in sorted {
      guard segment.appendedCount >= 0, segment.droppedCount >= 0,
        segment.appendedCount <= maximumAttempts - attempts,
        segment.droppedCount <= maximumAttempts - attempts - segment.appendedCount
      else { throw TacuaAppAudioAppendAccountingError.invalidCount }
      attempts += segment.appendedCount + segment.droppedCount
    }
    return attempts + 1
  }
}
