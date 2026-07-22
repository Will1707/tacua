// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

/// A deliberately small first-party diagnostic vocabulary. Callers provide semantic labels and
/// templates, never event identifiers, clocks, headers, query strings, request bodies, or UI
/// values. The journal assigns chronology and identity inside the native SDK.
enum TacuaDiagnosticJournalEvent: Equatable {
  case routeTransition(
    fromRoute: String?,
    toRoute: String,
    trigger: TacuaDiagnosticRouteTrigger
  )
  case userInteraction(action: TacuaDiagnosticInteractionAction, target: String)
  case runtimeError(
    errorClass: String,
    sanitizedMessage: String,
    stackTraceDigest: String?,
    handled: Bool
  )
  case networkRequestCompleted(
    method: TacuaDiagnosticNetworkMethod,
    host: String,
    pathTemplate: String,
    statusCode: Int64,
    durationMilliseconds: Int64,
    traceID: String?
  )
  case appStateChanged(fromState: TacuaDiagnosticAppState, toState: TacuaDiagnosticAppState)
  case customState(
    providerID: String,
    snapshotDigest: String?,
    collectionStatus: TacuaDiagnosticCollectionStatus
  )
}

enum TacuaDiagnosticRouteTrigger: String, CaseIterable, Equatable {
  case deepLink = "deep_link"
  case system
  case unknown
  case user
}

enum TacuaDiagnosticInteractionAction: String, CaseIterable, Equatable {
  case longPress = "long_press"
  case other
  case submit
  case swipe
  case tap
  case textInput = "text_input"
}

enum TacuaDiagnosticNetworkMethod: String, CaseIterable, Equatable {
  case delete = "DELETE"
  case get = "GET"
  case head = "HEAD"
  case options = "OPTIONS"
  case patch = "PATCH"
  case post = "POST"
  case put = "PUT"
}

enum TacuaDiagnosticAppState: String, CaseIterable, Equatable {
  case active
  case background
  case inactive
  case unknown
}

enum TacuaDiagnosticCollectionStatus: String, CaseIterable, Equatable {
  case available
  case unavailable
}

enum TacuaDiagnosticIssueMarkKind: String, Equatable {
  case manual
  case spoken
}

enum TacuaDiagnosticAffectedStream: String, CaseIterable, Equatable {
  case appAudio = "app_audio"
  case appVideo = "app_video"
  case diagnostics
  case microphone
}

enum TacuaDiagnosticCollectionGapReason: String, Equatable {
  case incompleteFinalRecord = "incomplete_final_record"
}

/// Internal gap records use the same hash chain and sequence as normal events. They cannot be
/// submitted by an SDK consumer and therefore unambiguously mean the journal recovered a torn
/// final append.
enum TacuaDiagnosticStoredEvent: Equatable {
  case event(TacuaDiagnosticJournalEvent)
  case issueMark(markerID: String, kind: TacuaDiagnosticIssueMarkKind)
  case captureGap(gapID: String, affectedStreams: [TacuaDiagnosticAffectedStream])
  case collectionGap(TacuaDiagnosticCollectionGapReason)
}

struct TacuaDiagnosticSnapshotEntry: Equatable {
  let sequence: Int64
  let eventID: String
  let monotonicMilliseconds: Int64
  let event: TacuaDiagnosticStoredEvent
}

/// Immutable deterministic projection intended to become the event portion of a diagnostic
/// envelope. It excludes file-system framing while retaining native chronology and the terminal
/// hash-chain digest.
struct TacuaDiagnosticSnapshot: Equatable {
  static let schemaVersion: Int64 = 1

  let localSessionID: String
  let bootSessionID: String
  let entries: [TacuaDiagnosticSnapshotEntry]
  let terminalChainDigest: String

  var containsCollectionGap: Bool {
    entries.contains { entry in
      if case .collectionGap = entry.event { return true }
      return false
    }
  }

  func encoded() throws -> Data {
    let projected = try entries.map { entry in
      TacuaJSONValue.object([
        "event": try TacuaDiagnosticJournal.encode(event: entry.event),
        "event_id": .string(entry.eventID),
        "monotonic_milliseconds": .integer(entry.monotonicMilliseconds),
        "sequence": .integer(entry.sequence),
      ])
    }
    return try TacuaCanonicalJSON.data(.object([
      "boot_session_id": .string(bootSessionID),
      "contains_collection_gap": .bool(containsCollectionGap),
      "event_count": .integer(Int64(entries.count)),
      "events": .array(projected),
      "local_session_id": .string(localSessionID),
      "schema_version": .integer(Self.schemaVersion),
      "terminal_chain_digest": .string(terminalChainDigest),
    ]))
  }
}

struct TacuaDiagnosticJournalArtifact: Equatable {
  let snapshot: TacuaDiagnosticSnapshot
  let data: Data
  let contentDigest: String
}

enum TacuaDiagnosticJournalError: Error, Equatable {
  case eventLimitReached
  case identityMismatch
  case invalidEvent
  case invalidIdentity
  case invalidJournal
  case persistenceFailure
  case privacyViolation
}

/// Append-only, no-follow, private diagnostic storage for one capture session and one OS boot.
/// Each canonical JSON line commits to the preceding line. Only a non-newline-terminated final
/// record may be discarded after a crash; recovery immediately writes a durable collection gap.
final class TacuaDiagnosticJournal {
  static let schemaVersion: Int64 = 1
  static let maximumEvents = 10_000
  static let maximumRecordBytes = 4 * 1_024
  static let maximumJournalBytes = 48 * 1_024 * 1_024
  static let directoryName = "diagnostics"

  private struct JournalState {
    let entries: [TacuaDiagnosticSnapshotEntry]
    let terminalChainDigest: String
    let monotonicMilliseconds: Int64
    let validByteCount: Int64
    let hasIncompleteFinalRecord: Bool
    let data: Data
  }

  private let rootDirectory: URL
  private let localSessionID: String
  private let bootSessionID: String
  private let fileName: String
  private let eventLimit: Int
  private let monotonicClock: () -> Int64
  private let fileSynchronizer: (Int32) -> Bool
  private let directorySynchronizer: (Int32) -> Bool

  init(
    rootDirectory: URL,
    localSessionID: String,
    bootSessionID: String,
    createIfMissing: Bool = true,
    maximumEvents: Int = TacuaDiagnosticJournal.maximumEvents,
    monotonicClock: @escaping () -> Int64 = {
      Int64((ProcessInfo.processInfo.systemUptime * 1_000).rounded(.down))
    },
    fileSynchronizer: @escaping (Int32) -> Bool = { fsync($0) == 0 },
    directorySynchronizer: @escaping (Int32) -> Bool = { fsync($0) == 0 }
  ) throws {
    guard rootDirectory.isFileURL,
      Self.validLocalSessionID(localSessionID),
      Self.validBootSessionID(bootSessionID),
      (1...Self.maximumEvents).contains(maximumEvents)
    else { throw TacuaDiagnosticJournalError.invalidIdentity }

    self.rootDirectory = rootDirectory.standardizedFileURL
    self.localSessionID = localSessionID
    self.bootSessionID = bootSessionID
    self.fileName = "\(localSessionID).diagnostics-v1.jsonl"
    self.eventLimit = maximumEvents
    self.monotonicClock = monotonicClock
    self.fileSynchronizer = fileSynchronizer
    self.directorySynchronizer = directorySynchronizer

    try prepareRootDirectory(createIfMissing: createIfMissing)
    try withLockedJournal(createIfMissing: createIfMissing) { descriptor, rootDescriptor, created in
      var metadata = stat()
      guard fstat(descriptor, &metadata) == 0 else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
      if metadata.st_size == 0 {
        try hardenJournalFile(descriptor: descriptor)
        try writeInitialHeader(descriptor: descriptor)
        guard directorySynchronizer(rootDescriptor) else {
          throw TacuaDiagnosticJournalError.persistenceFailure
        }
        return
      }
      guard !created, (metadata.st_mode & 0o777) == (S_IRUSR | S_IWUSR) else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
      try verifyJournalFileProtection(descriptor: descriptor)
      _ = try recoverIfNeeded(descriptor: descriptor)
    }
  }

  /// Appends one validated event. A successful return means the complete record was fsynced.
  /// When fsync reports failure the method returns `persistenceFailure` and makes no durability
  /// claim, even if the bytes happen to remain visible in the current process.
  @discardableResult
  func append(_ event: TacuaDiagnosticJournalEvent) throws -> TacuaDiagnosticSnapshotEntry {
    try Self.validate(event: event)
    return try appendValidated(.event(event))
  }

  /// Native capture lifecycle code may add issue/gap facts, but the JS bridge never receives this
  /// entry point. IDs and affected-stream sets remain closed and privacy-validated here.
  @discardableResult
  func appendSystemEvent(_ event: TacuaDiagnosticStoredEvent) throws
    -> TacuaDiagnosticSnapshotEntry
  {
    try Self.validate(storedEvent: event)
    return try appendValidated(event)
  }

  private func appendValidated(_ event: TacuaDiagnosticStoredEvent) throws
    -> TacuaDiagnosticSnapshotEntry
  {
    return try withLockedJournal(createIfMissing: false) { descriptor, _, _ in
      let state = try recoverIfNeeded(descriptor: descriptor)
      guard state.entries.count < eventLimit else {
        throw TacuaDiagnosticJournalError.eventLimitReached
      }
      let sequence = Int64(state.entries.count + 1)
      let observed = monotonicClock()
      guard observed >= 0 else { throw TacuaDiagnosticJournalError.invalidJournal }
      let monotonic = max(observed, state.monotonicMilliseconds)
      return try appendStoredEvent(
        event,
        sequence: sequence,
        monotonicMilliseconds: monotonic,
        previousChainDigest: state.terminalChainDigest,
        descriptor: descriptor
      )
    }
  }

  /// Returns a deterministic, integrity-checked projection. If the previous process left a torn
  /// final append, this call first truncates that tail and durably records a collection gap.
  func snapshot() throws -> TacuaDiagnosticSnapshot {
    try withLockedJournal(createIfMissing: false) { descriptor, _, _ in
      let state = try recoverIfNeeded(descriptor: descriptor)
      return TacuaDiagnosticSnapshot(
        localSessionID: localSessionID,
        bootSessionID: bootSessionID,
        entries: state.entries,
        terminalChainDigest: state.terminalChainDigest
      )
    }
  }

  func artifact() throws -> TacuaDiagnosticJournalArtifact {
    try withLockedJournal(createIfMissing: false) { descriptor, _, _ in
      let state = try recoverIfNeeded(descriptor: descriptor)
      let snapshot = TacuaDiagnosticSnapshot(
        localSessionID: localSessionID,
        bootSessionID: bootSessionID,
        entries: state.entries,
        terminalChainDigest: state.terminalChainDigest
      )
      return TacuaDiagnosticJournalArtifact(
        snapshot: snapshot,
        data: state.data,
        contentDigest: TacuaCanonicalJSON.digest(data: state.data)
      )
    }
  }

  var fileURL: URL {
    rootDirectory.appendingPathComponent(fileName).standardizedFileURL
  }

  static func relativePath(localSessionID: String) throws -> String {
    guard validLocalSessionID(localSessionID) else {
      throw TacuaDiagnosticJournalError.invalidIdentity
    }
    return "\(directoryName)/\(localSessionID).diagnostics-v1.jsonl"
  }

  static func rootDirectory(sessionDirectory: URL) -> URL {
    sessionDirectory.appendingPathComponent(directoryName, isDirectory: true)
  }

  private func recoverIfNeeded(descriptor: Int32) throws -> JournalState {
    let state = try readState(descriptor: descriptor)
    guard state.hasIncompleteFinalRecord else { return state }
    guard state.entries.count < Self.maximumEvents else {
      // New appends honor the configured reserve, but an older clean prefix may already contain
      // 9,999 events. Recovery may use the runtime's final hard slot so that torn-tail loss is
      // made explicit and the admission projection can deterministically shed routine events.
      throw TacuaDiagnosticJournalError.eventLimitReached
    }
    guard ftruncate(descriptor, state.validByteCount) == 0,
      fileSynchronizer(descriptor)
    else { throw TacuaDiagnosticJournalError.persistenceFailure }

    let observed = monotonicClock()
    guard observed >= 0 else { throw TacuaDiagnosticJournalError.invalidJournal }
    _ = try appendStoredEvent(
      .collectionGap(.incompleteFinalRecord),
      sequence: Int64(state.entries.count + 1),
      monotonicMilliseconds: max(observed, state.monotonicMilliseconds),
      previousChainDigest: state.terminalChainDigest,
      descriptor: descriptor
    )
    return try readState(descriptor: descriptor)
  }

  private func appendStoredEvent(
    _ event: TacuaDiagnosticStoredEvent,
    sequence: Int64,
    monotonicMilliseconds: Int64,
    previousChainDigest: String,
    descriptor: Int32
  ) throws -> TacuaDiagnosticSnapshotEntry {
    let eventValue = try Self.encode(event: event)
    let eventID = try Self.eventID(
      event: eventValue,
      sequence: sequence,
      previousChainDigest: previousChainDigest,
      localSessionID: localSessionID,
      bootSessionID: bootSessionID
    )
    let unhashed = TacuaJSONValue.object([
      "boot_session_id": .string(bootSessionID),
      "event": eventValue,
      "event_id": .string(eventID),
      "local_session_id": .string(localSessionID),
      "monotonic_milliseconds": .integer(monotonicMilliseconds),
      "previous_chain_digest": .string(previousChainDigest),
      "record_kind": .string("event"),
      "schema_version": .integer(Self.schemaVersion),
      "sequence": .integer(sequence),
    ])
    let chainDigest = try TacuaCanonicalJSON.digest(unhashed)
    guard case .object(var record) = unhashed else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
    record["chain_digest"] = .string(chainDigest)
    var line = try TacuaCanonicalJSON.data(.object(record))
    guard line.count <= Self.maximumRecordBytes else {
      throw TacuaDiagnosticJournalError.invalidEvent
    }
    line.append(0x0A)
    try writeAll(line, descriptor: descriptor)
    guard fileSynchronizer(descriptor) else {
      throw TacuaDiagnosticJournalError.persistenceFailure
    }
    return TacuaDiagnosticSnapshotEntry(
      sequence: sequence,
      eventID: eventID,
      monotonicMilliseconds: monotonicMilliseconds,
      event: event
    )
  }

  private func writeInitialHeader(descriptor: Int32) throws {
    let unhashed = TacuaJSONValue.object([
      "boot_session_id": .string(bootSessionID),
      "local_session_id": .string(localSessionID),
      "record_kind": .string("header"),
      "schema_version": .integer(Self.schemaVersion),
    ])
    let digest = try TacuaCanonicalJSON.digest(unhashed)
    guard case .object(var header) = unhashed else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
    header["chain_digest"] = .string(digest)
    var line = try TacuaCanonicalJSON.data(.object(header))
    line.append(0x0A)
    try writeAll(line, descriptor: descriptor)
    guard fileSynchronizer(descriptor) else {
      throw TacuaDiagnosticJournalError.persistenceFailure
    }
  }

  private func readState(descriptor: Int32) throws -> JournalState {
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_nlink == 1,
      (metadata.st_mode & 0o777) == (S_IRUSR | S_IWUSR),
      metadata.st_size > 0,
      metadata.st_size <= Self.maximumJournalBytes,
      lseek(descriptor, 0, SEEK_SET) == 0
    else { throw TacuaDiagnosticJournalError.invalidJournal }

    var data = Data()
    data.reserveCapacity(Int(metadata.st_size))
    var buffer = [UInt8](repeating: 0, count: 32 * 1_024)
    while true {
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      if count < 0, errno == EINTR { continue }
      guard count >= 0 else { throw TacuaDiagnosticJournalError.invalidJournal }
      if count == 0 { break }
      data.append(buffer, count: count)
      guard data.count <= Self.maximumJournalBytes else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
    }
    guard data.count == metadata.st_size else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }

    var lines: [Data] = []
    var start = data.startIndex
    while let newline = data[start...].firstIndex(of: 0x0A) {
      let line = Data(data[start..<newline])
      guard !line.isEmpty, line.count <= Self.maximumRecordBytes else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
      lines.append(line)
      start = data.index(after: newline)
    }
    let tail = Data(data[start..<data.endIndex])
    guard lines.count >= 1, lines.count <= Self.maximumEvents + 1 else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
    if !tail.isEmpty {
      guard tail.count <= Self.maximumRecordBytes, tail.first == 0x7B else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
    }

    let header = try Self.decodeCanonicalLine(lines[0])
    let headerObject = try header.requiringObject(keys: [
      "boot_session_id", "chain_digest", "local_session_id", "record_kind", "schema_version",
    ])
    guard headerObject["schema_version"]?.integerValue == Self.schemaVersion,
      headerObject["record_kind"]?.stringValue == "header",
      let storedLocalSessionID = headerObject["local_session_id"]?.stringValue,
      let storedBootSessionID = headerObject["boot_session_id"]?.stringValue,
      let headerDigest = headerObject["chain_digest"]?.stringValue,
      Self.validDigest(headerDigest),
      try TacuaCanonicalJSON.digest(header, omittingRootField: "chain_digest") == headerDigest
    else { throw TacuaDiagnosticJournalError.invalidJournal }
    guard storedLocalSessionID == localSessionID, storedBootSessionID == bootSessionID else {
      throw TacuaDiagnosticJournalError.identityMismatch
    }

    var entries: [TacuaDiagnosticSnapshotEntry] = []
    var terminalDigest = headerDigest
    var previousMonotonic: Int64 = 0
    for (offset, line) in lines.dropFirst().enumerated() {
      let value = try Self.decodeCanonicalLine(line)
      let object = try value.requiringObject(keys: [
        "boot_session_id", "chain_digest", "event", "event_id", "local_session_id",
        "monotonic_milliseconds", "previous_chain_digest", "record_kind", "schema_version",
        "sequence",
      ])
      let expectedSequence = Int64(offset + 1)
      guard object["schema_version"]?.integerValue == Self.schemaVersion,
        object["record_kind"]?.stringValue == "event",
        object["local_session_id"]?.stringValue == localSessionID,
        object["boot_session_id"]?.stringValue == bootSessionID,
        object["sequence"]?.integerValue == expectedSequence,
        object["previous_chain_digest"]?.stringValue == terminalDigest,
        let monotonic = object["monotonic_milliseconds"]?.integerValue,
        monotonic >= 0,
        monotonic >= previousMonotonic,
        let eventValue = object["event"],
        let eventID = object["event_id"]?.stringValue,
        let chainDigest = object["chain_digest"]?.stringValue,
        Self.validDigest(chainDigest),
        try TacuaCanonicalJSON.digest(value, omittingRootField: "chain_digest") == chainDigest,
        try Self.eventID(
          event: eventValue,
          sequence: expectedSequence,
          previousChainDigest: terminalDigest,
          localSessionID: localSessionID,
          bootSessionID: bootSessionID
        ) == eventID
      else { throw TacuaDiagnosticJournalError.invalidJournal }
      let event = try Self.decode(event: eventValue)
      entries.append(TacuaDiagnosticSnapshotEntry(
        sequence: expectedSequence,
        eventID: eventID,
        monotonicMilliseconds: monotonic,
        event: event
      ))
      terminalDigest = chainDigest
      previousMonotonic = monotonic
    }
    return JournalState(
      entries: entries,
      terminalChainDigest: terminalDigest,
      monotonicMilliseconds: previousMonotonic,
      validByteCount: Int64(start),
      hasIncompleteFinalRecord: !tail.isEmpty,
      data: data
    )
  }

  private static func decodeCanonicalLine(_ data: Data) throws -> TacuaJSONValue {
    do {
      let value = try TacuaCanonicalJSON.parse(data, maximumBytes: maximumRecordBytes)
      guard try TacuaCanonicalJSON.data(value) == data else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
      return value
    } catch let error as TacuaDiagnosticJournalError {
      throw error
    } catch {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
  }

  fileprivate static func encode(event: TacuaDiagnosticStoredEvent) throws -> TacuaJSONValue {
    switch event {
    case .event(let event):
      try validate(event: event)
      switch event {
      case .routeTransition(let fromRoute, let toRoute, let trigger):
        return .object([
          "from_route": fromRoute.map(TacuaJSONValue.string) ?? .null,
          "to_route": .string(toRoute),
          "trigger": .string(trigger.rawValue),
          "type": .string("route_transition"),
        ])
      case .userInteraction(let action, let target):
        return .object([
          "action": .string(action.rawValue),
          "target": .string(target),
          "type": .string("user_interaction"),
        ])
      case .runtimeError(let errorClass, let sanitizedMessage, let stackDigest, let handled):
        return .object([
          "error_class": .string(errorClass),
          "handled": .bool(handled),
          "sanitized_message": .string(sanitizedMessage),
          "stack_trace_digest": stackDigest.map(TacuaJSONValue.string) ?? .null,
          "type": .string("runtime_error"),
        ])
      case .networkRequestCompleted(
        let method, let host, let pathTemplate, let statusCode, let duration, let traceID
      ):
        return .object([
          "duration_milliseconds": .integer(duration),
          "host": .string(host),
          "method": .string(method.rawValue),
          "path_template": .string(pathTemplate),
          "status_code": .integer(statusCode),
          "trace_id": traceID.map(TacuaJSONValue.string) ?? .null,
          "type": .string("network_request_completed"),
        ])
      case .appStateChanged(let fromState, let toState):
        return .object([
          "from_state": .string(fromState.rawValue),
          "to_state": .string(toState.rawValue),
          "type": .string("app_state_changed"),
        ])
      case .customState(let providerID, let snapshotDigest, let collectionStatus):
        return .object([
          "collection_status": .string(collectionStatus.rawValue),
          "provider_id": .string(providerID),
          "snapshot_digest": snapshotDigest.map(TacuaJSONValue.string) ?? .null,
          "type": .string("custom_state"),
        ])
      }
    case .issueMark(let markerID, let kind):
      return .object([
        "kind": .string(kind.rawValue),
        "marker_id": .string(markerID),
        "type": .string("issue_mark"),
      ])
    case .captureGap(let gapID, let affectedStreams):
      return .object([
        "affected_streams": .array(affectedStreams.map { .string($0.rawValue) }),
        "gap_id": .string(gapID),
        "type": .string("capture_gap"),
      ])
    case .collectionGap(let reason):
      return .object([
        "reason": .string(reason.rawValue),
        "type": .string("collection_gap"),
      ])
    }
  }

  private static func decode(event value: TacuaJSONValue) throws -> TacuaDiagnosticStoredEvent {
    guard let type = value.objectValue?["type"]?.stringValue else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
    do {
      let stored: TacuaDiagnosticStoredEvent
      switch type {
      case "route_transition":
        let object = try value.requiringObject(keys: [
          "from_route", "to_route", "trigger", "type",
        ])
        guard let trigger = TacuaDiagnosticRouteTrigger(
          rawValue: try requiredString(object["trigger"])
        ) else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .event(.routeTransition(
          fromRoute: try nullableString(object["from_route"]),
          toRoute: try requiredString(object["to_route"]),
          trigger: trigger
        ))
      case "user_interaction":
        let object = try value.requiringObject(keys: ["action", "target", "type"])
        guard let action = TacuaDiagnosticInteractionAction(
          rawValue: try requiredString(object["action"])
        ) else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .event(.userInteraction(
          action: action,
          target: try requiredString(object["target"])
        ))
      case "runtime_error":
        let object = try value.requiringObject(keys: [
          "error_class", "handled", "sanitized_message", "stack_trace_digest", "type",
        ])
        guard let handled = object["handled"]?.boolValue else {
          throw TacuaDiagnosticJournalError.invalidJournal
        }
        stored = .event(.runtimeError(
          errorClass: try requiredString(object["error_class"]),
          sanitizedMessage: try requiredString(object["sanitized_message"]),
          stackTraceDigest: try nullableString(object["stack_trace_digest"]),
          handled: handled
        ))
      case "network_request_completed":
        let object = try value.requiringObject(keys: [
          "duration_milliseconds", "host", "method", "path_template", "status_code",
          "trace_id", "type",
        ])
        guard let method = TacuaDiagnosticNetworkMethod(
          rawValue: try requiredString(object["method"])
        ), let status = object["status_code"]?.integerValue,
          let duration = object["duration_milliseconds"]?.integerValue
        else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .event(.networkRequestCompleted(
          method: method,
          host: try requiredString(object["host"]),
          pathTemplate: try requiredString(object["path_template"]),
          statusCode: status,
          durationMilliseconds: duration,
          traceID: try nullableString(object["trace_id"])
        ))
      case "app_state_changed":
        let object = try value.requiringObject(keys: ["from_state", "to_state", "type"])
        guard let fromState = TacuaDiagnosticAppState(
          rawValue: try requiredString(object["from_state"])
        ), let toState = TacuaDiagnosticAppState(
          rawValue: try requiredString(object["to_state"])
        ) else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .event(.appStateChanged(fromState: fromState, toState: toState))
      case "custom_state":
        let object = try value.requiringObject(keys: [
          "collection_status", "provider_id", "snapshot_digest", "type",
        ])
        guard let status = TacuaDiagnosticCollectionStatus(
          rawValue: try requiredString(object["collection_status"])
        ) else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .event(.customState(
          providerID: try requiredString(object["provider_id"]),
          snapshotDigest: try nullableString(object["snapshot_digest"]),
          collectionStatus: status
        ))
      case "issue_mark":
        let object = try value.requiringObject(keys: ["kind", "marker_id", "type"])
        guard let kind = TacuaDiagnosticIssueMarkKind(
          rawValue: try requiredString(object["kind"])
        ) else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .issueMark(
          markerID: try requiredString(object["marker_id"]),
          kind: kind
        )
      case "capture_gap":
        let object = try value.requiringObject(keys: [
          "affected_streams", "gap_id", "type",
        ])
        guard let streamValues = object["affected_streams"]?.arrayValue else {
          throw TacuaDiagnosticJournalError.invalidJournal
        }
        let streams = try streamValues.map { value -> TacuaDiagnosticAffectedStream in
          guard let raw = value.stringValue,
            let stream = TacuaDiagnosticAffectedStream(rawValue: raw)
          else { throw TacuaDiagnosticJournalError.invalidJournal }
          return stream
        }
        stored = .captureGap(
          gapID: try requiredString(object["gap_id"]),
          affectedStreams: streams
        )
      case "collection_gap":
        let object = try value.requiringObject(keys: ["reason", "type"])
        guard let reason = TacuaDiagnosticCollectionGapReason(
          rawValue: try requiredString(object["reason"])
        ) else { throw TacuaDiagnosticJournalError.invalidJournal }
        stored = .collectionGap(reason)
      default:
        throw TacuaDiagnosticJournalError.invalidJournal
      }
      try validate(storedEvent: stored)
      return stored
    } catch is TacuaJSONError {
      throw TacuaDiagnosticJournalError.invalidJournal
    } catch TacuaDiagnosticJournalError.privacyViolation {
      throw TacuaDiagnosticJournalError.invalidJournal
    } catch TacuaDiagnosticJournalError.invalidEvent {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
  }

  private static func requiredString(_ value: TacuaJSONValue?) throws -> String {
    guard let value = value?.stringValue else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
    return value
  }

  private static func nullableString(_ value: TacuaJSONValue?) throws -> String? {
    guard let value else { throw TacuaDiagnosticJournalError.invalidJournal }
    switch value {
    case .null: return nil
    case .string(let string): return string
    default: throw TacuaDiagnosticJournalError.invalidJournal
    }
  }

  fileprivate static func validate(event: TacuaDiagnosticJournalEvent) throws {
    switch event {
    case .routeTransition(let fromRoute, let toRoute, _):
      guard fromRoute.map(validPathTemplate) ?? true, validPathTemplate(toRoute) else {
        throw TacuaDiagnosticJournalError.invalidEvent
      }
      try rejectSensitive([fromRoute, toRoute].compactMap { $0 })
    case .userInteraction(_, let target):
      guard validSemanticIdentifier(target, maximumBytes: 64) else {
        throw TacuaDiagnosticJournalError.invalidEvent
      }
      try rejectSensitive([target])
    case .runtimeError(let errorClass, let sanitizedMessage, let stackDigest, _):
      guard validDomain(errorClass), validSanitizedSummary(sanitizedMessage),
        stackDigest.map(validDigest) ?? true
      else { throw TacuaDiagnosticJournalError.invalidEvent }
      try rejectSensitive([errorClass, sanitizedMessage])
    case .networkRequestCompleted(
      _, let host, let pathTemplate, let statusCode, let duration, let traceID
    ):
      guard validHost(host), validPathTemplate(pathTemplate),
        (100...599).contains(statusCode),
        (0...1_800_000).contains(duration),
        traceID.map(validTraceID) ?? true
      else { throw TacuaDiagnosticJournalError.invalidEvent }
      try rejectSensitive([host, pathTemplate])
    case .appStateChanged:
      break
    case .customState(let providerID, let snapshotDigest, let collectionStatus):
      guard validProtocolIdentifier(providerID),
        snapshotDigest.map(validDigest) ?? true,
        (collectionStatus == .available) == (snapshotDigest != nil)
      else { throw TacuaDiagnosticJournalError.invalidEvent }
      try rejectSensitive([providerID])
    }
  }

  private static func validate(storedEvent: TacuaDiagnosticStoredEvent) throws {
    switch storedEvent {
    case .event(let event):
      try validate(event: event)
    case .issueMark(let markerID, _):
      guard validSemanticIdentifier(markerID, maximumBytes: 64) else {
        throw TacuaDiagnosticJournalError.invalidEvent
      }
    case .captureGap(let gapID, let affectedStreams):
      let raw = affectedStreams.map(\.rawValue)
      guard validSemanticIdentifier(gapID, maximumBytes: 64),
        (1...4).contains(raw.count),
        Set(raw).count == raw.count,
        raw == raw.sorted()
      else { throw TacuaDiagnosticJournalError.invalidEvent }
    case .collectionGap:
      break
    }
  }

  private static func rejectSensitive(_ values: [String]) throws {
    guard !values.contains(where: containsSensitiveMaterial) else {
      throw TacuaDiagnosticJournalError.privacyViolation
    }
  }

  private static func containsSensitiveMaterial(_ value: String) -> Bool {
    let lower = value.lowercased()
    let compact = lower.unicodeScalars.filter(CharacterSet.alphanumerics.contains)
      .map(String.init).joined()
    let forbidden = [
      "password", "passwd", "secret", "token", "apikey", "accesstoken", "refreshtoken",
      "authtoken", "authorization", "bearertoken", "cookie", "credential",
      "privatekey", "clientsecret",
    ]
    if forbidden.contains(where: compact.contains) { return true }
    if lower.contains("bearer ") || lower.contains("-----begin ") || lower.contains("sk-")
      || lower.contains("ghp_") || lower.contains("xoxb-") || lower.contains("xoxp-")
      || lower.contains("://") || lower.contains("@") || lower.contains("?")
    { return true }
    if value.range(
      of: "[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
      options: .regularExpression
    ) != nil { return true }
    if value.range(
      of: "(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9_+/=-]{24,}",
      options: .regularExpression
    ) != nil { return true }
    return false
  }

  private static func validLocalSessionID(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 64
      && value.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil
  }

  private static func validBootSessionID(_ value: String) -> Bool {
    !value.isEmpty && value != "unavailable" && value.utf8.count <= 255
      && value.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x21 && $0.value <= 0x7E })
  }

  private static func validSemanticIdentifier(_ value: String, maximumBytes: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= maximumBytes
      && value.range(of: "^[a-z][a-z0-9_.-]*$", options: .regularExpression) != nil
  }

  private static func validDomain(_ value: String) -> Bool {
    value.utf8.count <= 128 && validSemanticIdentifier(value, maximumBytes: 128)
  }

  private static func validProtocolIdentifier(_ value: String) -> Bool {
    (3...64).contains(value.utf8.count)
      && value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validHost(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 253, value == value.lowercased(),
      value.unicodeScalars.allSatisfy({ $0.isASCII })
    else { return false }
    return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
      guard !label.isEmpty, label.utf8.count <= 63,
        label.range(of: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", options: .regularExpression)
          != nil
      else { return false }
      return true
    }
  }

  private static func validPathTemplate(_ value: String) -> Bool {
    guard value.utf8.count <= 256, value.unicodeScalars.allSatisfy({ $0.isASCII }),
      value.first == "/", !value.contains("?"), !value.contains("#"), !value.contains("//")
    else { return false }
    if value == "/" { return true }
    let components = value.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
    return components.allSatisfy { component in
      let part = String(component)
      return part.range(
        of: "^[a-z][a-z0-9._~-]{0,31}$|^\\{[a-z][a-z0-9_]{0,31}\\}$",
        options: .regularExpression
      ) != nil
    }
  }

  private static func validSanitizedSummary(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 160,
      Data(value.precomposedStringWithCanonicalMapping.utf8) == Data(value.utf8)
    else { return false }
    return value.unicodeScalars.allSatisfy { scalar in
      scalar.value >= 0x20 && scalar.value != 0x7F
    }
  }

  private static func validDigest(_ value: String) -> Bool {
    value.utf8.count == 71
      && value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func validTraceID(_ value: String) -> Bool {
    value.utf8.count == 32 && value != String(repeating: "0", count: 32)
      && value.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil
  }

  private static func eventID(
    event: TacuaJSONValue,
    sequence: Int64,
    previousChainDigest: String,
    localSessionID: String,
    bootSessionID: String
  ) throws -> String {
    let seed = TacuaJSONValue.object([
      "boot_session_id": .string(bootSessionID),
      "event": event,
      "local_session_id": .string(localSessionID),
      "previous_chain_digest": .string(previousChainDigest),
      "sequence": .integer(sequence),
    ])
    let fullDigest = try TacuaCanonicalJSON.digest(seed).dropFirst("sha256:".count)
    // Fifty-eight hex characters preserve 232 digest bits while keeping the complete identifier
    // at the frozen 64-byte runtime limit. Sequence plus the chain detect replay/reordering too.
    return "event_" + String(fullDigest.prefix(58))
  }

  private func prepareRootDirectory(createIfMissing: Bool) throws {
    var missing: [URL] = []
    var cursor = rootDirectory
    while true {
      var metadata = stat()
      if lstat(cursor.path, &metadata) == 0 {
        guard (metadata.st_mode & S_IFMT) == S_IFDIR else {
          throw TacuaDiagnosticJournalError.invalidJournal
        }
        break
      }
      guard errno == ENOENT, createIfMissing else {
        throw TacuaDiagnosticJournalError.invalidJournal
      }
      missing.append(cursor)
      let parent = cursor.deletingLastPathComponent()
      guard parent != cursor else { throw TacuaDiagnosticJournalError.invalidJournal }
      cursor = parent
    }
    for directory in missing.reversed() {
      guard mkdir(directory.path, S_IRWXU) == 0 || errno == EEXIST else {
        throw TacuaDiagnosticJournalError.persistenceFailure
      }
      try syncParent(of: directory)
    }
    let descriptor = open(rootDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw TacuaDiagnosticJournalError.invalidJournal }
    defer { close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFDIR,
      fchmod(descriptor, S_IRWXU) == 0
    else { throw TacuaDiagnosticJournalError.persistenceFailure }
    do {
      try FileManager.default.setAttributes(
        [
          .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
          .posixPermissions: 0o700,
        ],
        ofItemAtPath: rootDirectory.path
      )
      let attributes = try FileManager.default.attributesOfItem(atPath: rootDirectory.path)
      guard attributes[.protectionKey] as? FileProtectionType
        == .completeUntilFirstUserAuthentication,
        directorySynchronizer(descriptor)
      else { throw TacuaDiagnosticJournalError.persistenceFailure }
    } catch let error as TacuaDiagnosticJournalError {
      throw error
    } catch {
      throw TacuaDiagnosticJournalError.persistenceFailure
    }
  }

  private func hardenJournalFile(descriptor: Int32) throws {
    guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 else {
      throw TacuaDiagnosticJournalError.persistenceFailure
    }
    do {
      try FileManager.default.setAttributes(
        [
          .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
          .posixPermissions: 0o600,
        ],
        ofItemAtPath: fileURL.path
      )
      try verifyJournalFileProtection(descriptor: descriptor)
    } catch let error as TacuaDiagnosticJournalError {
      throw error
    } catch {
      throw TacuaDiagnosticJournalError.persistenceFailure
    }
  }

  private func verifyJournalFileProtection(descriptor: Int32) throws {
    var opened = stat()
    var named = stat()
    let attributes: [FileAttributeKey: Any]
    do { attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path) }
    catch { throw TacuaDiagnosticJournalError.invalidJournal }
    guard fstat(descriptor, &opened) == 0,
      lstat(fileURL.path, &named) == 0,
      (opened.st_mode & S_IFMT) == S_IFREG,
      (named.st_mode & S_IFMT) == S_IFREG,
      opened.st_dev == named.st_dev,
      opened.st_ino == named.st_ino,
      (opened.st_mode & 0o777) == (S_IRUSR | S_IWUSR),
      attributes[.protectionKey] as? FileProtectionType
        == .completeUntilFirstUserAuthentication
    else { throw TacuaDiagnosticJournalError.invalidJournal }
  }

  private func syncParent(of directory: URL) throws {
    let parent = directory.deletingLastPathComponent()
    let descriptor = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw TacuaDiagnosticJournalError.persistenceFailure }
    defer { close(descriptor) }
    guard directorySynchronizer(descriptor) else {
      throw TacuaDiagnosticJournalError.persistenceFailure
    }
  }

  private func withLockedJournal<T>(
    createIfMissing: Bool,
    _ body: (Int32, Int32, Bool) throws -> T
  ) throws -> T {
    let rootDescriptor = open(
      rootDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard rootDescriptor >= 0 else { throw TacuaDiagnosticJournalError.invalidJournal }
    defer { close(rootDescriptor) }

    var created = false
    var descriptor: Int32 = -1
    if createIfMissing {
      descriptor = openat(
        rootDescriptor,
        fileName,
        O_RDWR | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        S_IRUSR | S_IWUSR
      )
      if descriptor >= 0 {
        created = true
      } else if errno == EEXIST {
        descriptor = openat(
          rootDescriptor,
          fileName,
          O_RDWR | O_APPEND | O_NOFOLLOW | O_CLOEXEC
        )
      }
    } else {
      descriptor = openat(
        rootDescriptor,
        fileName,
        O_RDWR | O_APPEND | O_NOFOLLOW | O_CLOEXEC
      )
    }
    guard descriptor >= 0 else { throw TacuaDiagnosticJournalError.invalidJournal }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else {
      throw TacuaDiagnosticJournalError.invalidJournal
    }
    defer { _ = flock(descriptor, LOCK_UN) }

    var opened = stat()
    var named = stat()
    guard fstat(descriptor, &opened) == 0,
      fstatat(rootDescriptor, fileName, &named, AT_SYMLINK_NOFOLLOW) == 0,
      (opened.st_mode & S_IFMT) == S_IFREG,
      (named.st_mode & S_IFMT) == S_IFREG,
      opened.st_nlink == 1,
      named.st_nlink == 1,
      opened.st_dev == named.st_dev,
      opened.st_ino == named.st_ino
    else { throw TacuaDiagnosticJournalError.invalidJournal }
    return try body(descriptor, rootDescriptor, created)
  }

  private func writeAll(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { bytes in
      guard let base = bytes.baseAddress else {
        throw TacuaDiagnosticJournalError.persistenceFailure
      }
      var offset = 0
      while offset < data.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw TacuaDiagnosticJournalError.persistenceFailure }
        offset += count
      }
    }
  }
}
