// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

private enum DiagnosticJournalTestFailure: Error {
  case assertion(String)
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func increment() -> Int {
    lock.lock()
    defer { lock.unlock() }
    value += 1
    return value
  }
}

private final class LockedErrors: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [Error] = []

  func append(_ error: Error) {
    lock.lock()
    storage.append(error)
    lock.unlock()
  }

  var values: [Error] {
    lock.lock()
    defer { lock.unlock() }
    return storage
  }
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw DiagnosticJournalTestFailure.assertion(message) }
}

private func requireJournalError(
  _ expected: TacuaDiagnosticJournalError,
  _ body: () throws -> Void
) throws {
  do {
    try body()
    throw DiagnosticJournalTestFailure.assertion("Expected \(expected)")
  } catch let error as TacuaDiagnosticJournalError {
    try require(error == expected, "Wrong journal error: \(error), expected \(expected)")
  }
}

@main
enum DiagnosticJournalTests {
  static func main() throws {
    try allSupportedEventsRoundTripCanonically()
    try privacyAndFieldValidationRejectBeforePersistence()
    try malformedNoncanonicalAndDuplicateRecordsFailClosed()
    try symlinkHardLinkAndPermissionAttacksFailClosed()
    try tornFinalAppendCreatesExactlyOneGap()
    try interiorMutationDeletionAndReorderingAreDetected()
    try persistenceFailuresAreReported()
    try eventCapIsEnforced()
    try concurrentWritersReceiveOneNativeSequence()
    try bootAndSessionIdentityCannotBeRebound()
    print("Tacua diagnostic-journal tests passed")
  }

  private static func allSupportedEventsRoundTripCanonically() throws {
    let harness = try makeHarness("all_events")
    defer { removeHarness(harness.parent) }
    var clock: Int64 = 1_000
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: "local_diagnostics_001",
      bootSessionID: "boot_diagnostics_001",
      monotonicClock: {
        defer { clock += 7 }
        return clock
      }
    )
    let digest = "sha256:" + String(repeating: "b", count: 64)
    let trace = String(repeating: "a", count: 32)
    let events: [TacuaDiagnosticJournalEvent] = [
      .routeTransition(fromRoute: nil, toRoute: "/home", trigger: .deepLink),
      .routeTransition(
        fromRoute: "/home", toRoute: "/items/{item_id}", trigger: .user
      ),
      .userInteraction(action: .tap, target: "save_button"),
      .userInteraction(action: .longPress, target: "card_menu"),
      .runtimeError(
        errorClass: "react.native",
        sanitizedMessage: "Render failed before decoding",
        stackTraceDigest: digest,
        handled: true
      ),
      .networkRequestCompleted(
        method: .post,
        host: "api.example.com",
        pathTemplate: "/vone/items/{item_id}",
        statusCode: 422,
        durationMilliseconds: 913,
        traceID: trace
      ),
      .appStateChanged(fromState: .active, toState: .background),
      .appStateChanged(fromState: .background, toState: .active),
      .customState(
        providerID: "feature_mode",
        snapshotDigest: digest,
        collectionStatus: .available
      ),
    ]
    var returned: [TacuaDiagnosticSnapshotEntry] = []
    for event in events {
      do {
        returned.append(try journal.append(event))
      } catch {
        throw DiagnosticJournalTestFailure.assertion("Valid event \(event) failed: \(error)")
      }
    }
    returned.append(try journal.appendSystemEvent(
      .issueMark(markerID: "marker_manual_001", kind: .manual)
    ))
    returned.append(try journal.appendSystemEvent(.captureGap(
      gapID: "gap_capture_001",
      affectedStreams: [.appAudio, .appVideo, .diagnostics, .microphone]
    )))
    try require(
      returned.map(\.sequence) == Array(1...Int64(returned.count)),
      "Native journal sequence was not contiguous"
    )
    try require(Set(returned.map(\.eventID)).count == returned.count, "Event IDs collided")
    try require(
      returned.allSatisfy {
        $0.eventID.range(of: "^event_[a-f0-9]{58}$", options: .regularExpression) != nil
      },
      "Event IDs were not native deterministic identifiers"
    )

    let snapshot = try journal.snapshot()
    try require(snapshot.entries == returned, "Snapshot changed recorded events")
    try require(!snapshot.containsCollectionGap, "Healthy journal reported a gap")
    let artifact = try journal.artifact()
    try require(artifact.snapshot == snapshot, "Artifact snapshot diverged")
    try require(
      artifact.contentDigest == TacuaCanonicalJSON.digest(data: artifact.data),
      "Artifact digest did not bind the frozen journal bytes"
    )
    let encoded = try snapshot.encoded()
    let parsed = try TacuaCanonicalJSON.parse(encoded)
    let reencoded = try TacuaCanonicalJSON.data(parsed)
    try require(
      reencoded == encoded,
      "Snapshot projection was not canonical JSON"
    )
    let reopened = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: "local_diagnostics_001",
      bootSessionID: "boot_diagnostics_001",
      monotonicClock: { 900 }
    )
    let next = try reopened.append(.userInteraction(action: .other, target: "nav_back"))
    try require(next.sequence == Int64(returned.count + 1), "Resume restarted the sequence")
    try require(
      next.monotonicMilliseconds >= returned.last!.monotonicMilliseconds,
      "A lower observed uptime rewound native chronology"
    )
    let rootMode = try mode(harness.root)
    let fileMode = try mode(journal.fileURL)
    try require(rootMode == 0o700, "Journal directory is not private")
    try require(fileMode == 0o600, "Journal file is not private")
  }

  private static func privacyAndFieldValidationRejectBeforePersistence() throws {
    let harness = try makeHarness("privacy")
    defer { removeHarness(harness.parent) }
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: "local_privacy_001",
      bootSessionID: "boot_privacy_001",
      monotonicClock: { 50 }
    )
    let baseline = try Data(contentsOf: journal.fileURL)
    let sensitiveEvents: [TacuaDiagnosticJournalEvent] = [
      .customState(
        providerID: "api_token",
        snapshotDigest: "sha256:" + String(repeating: "a", count: 64),
        collectionStatus: .available
      ),
      .customState(
        providerID: "client_secret",
        snapshotDigest: nil,
        collectionStatus: .unavailable
      ),
      .userInteraction(action: .tap, target: "password_field"),
      .runtimeError(
        errorClass: "network.error",
        sanitizedMessage: "Authorization: Bearer abcdef",
        stackTraceDigest: nil,
        handled: true
      ),
      .routeTransition(fromRoute: nil, toRoute: "/reset/password", trigger: .user),
      .networkRequestCompleted(
        method: .get,
        host: "api.example.com",
        pathTemplate: "/items/{item_id}?access=one",
        statusCode: 200,
        durationMilliseconds: 3,
        traceID: nil
      ),
    ]
    for event in sensitiveEvents {
      do {
        try journal.append(event)
        throw DiagnosticJournalTestFailure.assertion("Sensitive event was accepted: \(event)")
      } catch TacuaDiagnosticJournalError.privacyViolation {
        continue
      } catch TacuaDiagnosticJournalError.invalidEvent {
        // Query strings are structurally invalid before the privacy scanner runs.
        continue
      }
    }
    let afterSensitive = try Data(contentsOf: journal.fileURL)
    try require(afterSensitive == baseline, "Rejected sensitive text reached the journal")
    let persistedText = String(decoding: afterSensitive, as: UTF8.self).lowercased()
    for forbidden in ["password", "bearer", "sk-proj", "api_token", "authorization"] {
      try require(!persistedText.contains(forbidden), "Journal persisted \(forbidden)")
    }

    let decomposed = "Cafe\u{301} failed"
    let invalidEvents: [TacuaDiagnosticJournalEvent] = [
      .routeTransition(fromRoute: nil, toRoute: "/items/123", trigger: .user),
      .routeTransition(fromRoute: nil, toRoute: "home", trigger: .unknown),
      .userInteraction(action: .tap, target: "SaveButton"),
      .runtimeError(
        errorClass: "react.native",
        sanitizedMessage: decomposed,
        stackTraceDigest: nil,
        handled: false
      ),
      .runtimeError(
        errorClass: "react.native",
        sanitizedMessage: "Render failed",
        stackTraceDigest: "sha256:ABC",
        handled: false
      ),
      .networkRequestCompleted(
        method: .get,
        host: "API.Example.com",
        pathTemplate: "/health",
        statusCode: 200,
        durationMilliseconds: 4,
        traceID: nil
      ),
      .networkRequestCompleted(
        method: .get,
        host: "api.example.com",
        pathTemplate: "/health",
        statusCode: 99,
        durationMilliseconds: 4,
        traceID: nil
      ),
      .networkRequestCompleted(
        method: .get,
        host: "api.example.com",
        pathTemplate: "/health",
        statusCode: 200,
        durationMilliseconds: -1,
        traceID: String(repeating: "0", count: 32)
      ),
      .networkRequestCompleted(
        method: .get,
        host: "api.example.com",
        pathTemplate: "/health",
        statusCode: 200,
        durationMilliseconds: 1_800_001,
        traceID: nil
      ),
      .customState(
        providerID: "provider.with.dot",
        snapshotDigest: nil,
        collectionStatus: .unavailable
      ),
      .customState(
        providerID: "mode",
        snapshotDigest: nil,
        collectionStatus: .available
      ),
    ]
    for event in invalidEvents {
      try requireJournalError(.invalidEvent) { try journal.append(event) }
    }
    let afterInvalid = try Data(contentsOf: journal.fileURL)
    try require(afterInvalid == baseline, "Invalid typed fields changed the journal")
  }

  private static func malformedNoncanonicalAndDuplicateRecordsFailClosed() throws {
    try withOneEventJournal("noncanonical") { root, session, boot, file in
      var lines = try readLines(file)
      lines[1].insert(0x20, at: lines[1].index(after: lines[1].startIndex))
      try rewrite(lines: lines, to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
    try withOneEventJournal("duplicate") { root, session, boot, file in
      var lines = try readLines(file)
      guard let text = String(data: lines[1], encoding: .utf8) else {
        throw DiagnosticJournalTestFailure.assertion("Missing event text")
      }
      let duplicate = text.replacingOccurrences(
        of: "\"sequence\":1",
        with: "\"sequence\":1,\"sequence\":1"
      )
      try require(duplicate != text, "Duplicate-key fixture did not mutate")
      lines[1] = Data(duplicate.utf8)
      try rewrite(lines: lines, to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
    try withOneEventJournal("malformed") { root, session, boot, file in
      try rawAppend(Data("{\"record_kind\":\n".utf8), to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
    try withOneEventJournal("garbage_tail") { root, session, boot, file in
      try rawAppend(Data("not-json".utf8), to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
  }

  private static func symlinkHardLinkAndPermissionAttacksFailClosed() throws {
    let symlinkParent = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-diagnostic-symlink-\(UUID().uuidString)", isDirectory: true
    )
    defer { removeHarness(symlinkParent) }
    let target = symlinkParent.appendingPathComponent("target", isDirectory: true)
    let linkedRoot = symlinkParent.appendingPathComponent("journal-link", isDirectory: true)
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: linkedRoot, withDestinationURL: target)
    try requireJournalError(.invalidJournal) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: linkedRoot,
        localSessionID: "local_symlink_001",
        bootSessionID: "boot_symlink_001"
      )
    }

    let fileLinkHarness = try makeHarness("file_symlink")
    defer { removeHarness(fileLinkHarness.parent) }
    try FileManager.default.createDirectory(
      at: fileLinkHarness.root,
      withIntermediateDirectories: true
    )
    guard chmod(fileLinkHarness.root.path, 0o700) == 0 else { throw POSIXError(.EIO) }
    let outside = fileLinkHarness.parent.appendingPathComponent("outside")
    try Data("do not touch".utf8).write(to: outside)
    let linkedFile = fileLinkHarness.root.appendingPathComponent(
      "local_filelink_001.diagnostics-v1.jsonl"
    )
    try FileManager.default.createSymbolicLink(at: linkedFile, withDestinationURL: outside)
    try requireJournalError(.invalidJournal) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: fileLinkHarness.root,
        localSessionID: "local_filelink_001",
        bootSessionID: "boot_filelink_001"
      )
    }
    let outsideData = try Data(contentsOf: outside)
    try require(
      String(decoding: outsideData, as: UTF8.self) == "do not touch",
      "Symlink target was changed"
    )

    try withOneEventJournal("permissions") { root, session, boot, file in
      guard chmod(file.path, 0o644) == 0 else { throw POSIXError(.EIO) }
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }

    try withOneEventJournal("hardlink") { root, session, boot, file in
      let alias = file.deletingLastPathComponent().appendingPathComponent("alias")
      guard Darwin.link(file.path, alias.path) == 0 else { throw POSIXError(.EIO) }
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
  }

  private static func tornFinalAppendCreatesExactlyOneGap() throws {
    let harness = try makeHarness("truncation")
    defer { removeHarness(harness.parent) }
    let session = "local_truncation_001"
    let boot = "boot_truncation_001"
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: session,
      bootSessionID: boot,
      monotonicClock: { 200 }
    )
    _ = try journal.append(.appStateChanged(fromState: .unknown, toState: .active))
    try rawAppend(Data("{\"record_kind\":\"event\",\"sequence\"".utf8), to: journal.fileURL)

    let recovered = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: session,
      bootSessionID: boot,
      monotonicClock: { 220 }
    )
    let snapshot = try recovered.snapshot()
    try require(snapshot.entries.count == 2, "Recovery did not replace torn tail with one gap")
    try require(snapshot.containsCollectionGap, "Torn append did not surface a collection gap")
    guard case .collectionGap(.incompleteFinalRecord) = snapshot.entries[1].event else {
      throw DiagnosticJournalTestFailure.assertion("Wrong recovered gap shape")
    }
    let bytes = try Data(contentsOf: recovered.fileURL)
    try require(bytes.last == 0x0A, "Recovered journal is not newline framed")
    try require(
      !String(decoding: bytes, as: UTF8.self).contains("\"sequence\"\n"),
      "Torn tail remained visible"
    )

    let reopened = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: session,
      bootSessionID: boot,
      monotonicClock: { 230 }
    )
    let reopenedSnapshot = try reopened.snapshot()
    try require(reopenedSnapshot.entries.count == 2, "A clean reopen duplicated the collection gap")
  }

  private static func interiorMutationDeletionAndReorderingAreDetected() throws {
    try withTwoEventJournal("mutation") { root, session, boot, file in
      var lines = try readLines(file)
      guard let text = String(data: lines[1], encoding: .utf8) else {
        throw DiagnosticJournalTestFailure.assertion("Missing event line")
      }
      let mutated = text.replacingOccurrences(of: "save_button", with: "gave_button")
      try require(mutated != text, "Mutation fixture did not change")
      lines[1] = Data(mutated.utf8)
      try rewrite(lines: lines, to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
    try withTwoEventJournal("deletion") { root, session, boot, file in
      var lines = try readLines(file)
      lines.remove(at: 1)
      try rewrite(lines: lines, to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
    try withTwoEventJournal("reordering") { root, session, boot, file in
      var lines = try readLines(file)
      lines.swapAt(1, 2)
      try rewrite(lines: lines, to: file)
      try requireJournalError(.invalidJournal) {
        _ = try TacuaDiagnosticJournal(
          rootDirectory: root,
          localSessionID: session,
          bootSessionID: boot
        )
      }
    }
  }

  private static func persistenceFailuresAreReported() throws {
    let harness = try makeHarness("fsync")
    defer { removeHarness(harness.parent) }
    let syncCalls = LockedCounter()
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: "local_fsync_001",
      bootSessionID: "boot_fsync_001",
      monotonicClock: { 1 },
      fileSynchronizer: { descriptor in
        if syncCalls.increment() == 2 { return false }
        return fsync(descriptor) == 0
      }
    )
    try requireJournalError(.persistenceFailure) {
      try journal.append(.appStateChanged(fromState: .unknown, toState: .active))
    }

    let directoryParent = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-diagnostic-dirfsync-\(UUID().uuidString)", isDirectory: true
    )
    defer { removeHarness(directoryParent) }
    try FileManager.default.createDirectory(at: directoryParent, withIntermediateDirectories: true)
    try requireJournalError(.persistenceFailure) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: directoryParent.appendingPathComponent("diagnostics", isDirectory: true),
        localSessionID: "local_dirfsync_001",
        bootSessionID: "boot_dirfsync_001",
        directorySynchronizer: { _ in false }
      )
    }
  }

  private static func eventCapIsEnforced() throws {
    try require(TacuaDiagnosticJournal.maximumEvents == 10_000, "Production cap changed")
    let harness = try makeHarness("cap")
    defer { removeHarness(harness.parent) }
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: "local_cap_001",
      bootSessionID: "boot_cap_001",
      maximumEvents: 2,
      monotonicClock: { 5 }
    )
    _ = try journal.append(.appStateChanged(fromState: .unknown, toState: .active))
    _ = try journal.append(.appStateChanged(fromState: .active, toState: .inactive))
    try requireJournalError(.eventLimitReached) {
      try journal.append(.appStateChanged(fromState: .inactive, toState: .background))
    }
    let cappedSnapshot = try journal.snapshot()
    try require(cappedSnapshot.entries.count == 2, "Cap rejection changed journal")
    try requireJournalError(.invalidIdentity) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: harness.root,
        localSessionID: "local_cap_other_001",
        bootSessionID: "boot_cap_001",
        maximumEvents: 10_001
      )
    }
  }

  private static func concurrentWritersReceiveOneNativeSequence() throws {
    let harness = try makeHarness("concurrency")
    defer { removeHarness(harness.parent) }
    let session = "local_concurrency_001"
    let boot = "boot_concurrency_001"
    let journals = try (0..<8).map { _ in
      try TacuaDiagnosticJournal(
        rootDirectory: harness.root,
        localSessionID: session,
        bootSessionID: boot,
        monotonicClock: { 900 }
      )
    }
    let errors = LockedErrors()
    let group = DispatchGroup()
    let queue = DispatchQueue(label: "dev.tacua.diagnostic-tests", attributes: .concurrent)
    for index in 0..<120 {
      group.enter()
      queue.async {
        defer { group.leave() }
        do {
          let digest = "sha256:" + String(repeating: index.isMultiple(of: 2) ? "a" : "b", count: 64)
          _ = try journals[index % journals.count].append(.customState(
            providerID: "worker_state",
            snapshotDigest: digest,
            collectionStatus: .available
          ))
        } catch {
          errors.append(error)
        }
      }
    }
    group.wait()
    try require(errors.values.isEmpty, "Concurrent append failed: \(errors.values)")
    let snapshot = try journals[0].snapshot()
    try require(snapshot.entries.count == 120, "Concurrent events were lost")
    try require(
      snapshot.entries.map(\.sequence) == Array(1...120).map(Int64.init),
      "Concurrent sequence was not contiguous"
    )
    try require(Set(snapshot.entries.map(\.eventID)).count == 120, "Concurrent IDs collided")
    try require(
      snapshot.entries.map(\.monotonicMilliseconds) == Array(repeating: 900, count: 120),
      "Journal accepted caller chronology or rewound native time"
    )
  }

  private static func bootAndSessionIdentityCannotBeRebound() throws {
    let harness = try makeHarness("identity")
    defer { removeHarness(harness.parent) }
    let original = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: "local_identity_001",
      bootSessionID: "boot_identity_001"
    )
    _ = try original.append(.appStateChanged(fromState: .unknown, toState: .active))
    try requireJournalError(.identityMismatch) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: harness.root,
        localSessionID: "local_identity_001",
        bootSessionID: "boot_identity_other_001"
      )
    }

    let copied = harness.root.appendingPathComponent(
      "local_identity_copy_001.diagnostics-v1.jsonl"
    )
    try copyPrivate(from: original.fileURL, to: copied)
    try requireJournalError(.identityMismatch) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: harness.root,
        localSessionID: "local_identity_copy_001",
        bootSessionID: "boot_identity_001"
      )
    }
    try requireJournalError(.invalidIdentity) {
      _ = try TacuaDiagnosticJournal(
        rootDirectory: harness.root,
        localSessionID: "../escape",
        bootSessionID: "boot_identity_001"
      )
    }
  }

  private static func withOneEventJournal(
    _ suffix: String,
    _ body: (URL, String, String, URL) throws -> Void
  ) throws {
    let harness = try makeHarness(suffix)
    defer { removeHarness(harness.parent) }
    let session = "local_\(suffix)_001"
    let boot = "boot_\(suffix)_001"
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: session,
      bootSessionID: boot,
      monotonicClock: { 10 }
    )
    _ = try journal.append(.userInteraction(action: .tap, target: "save_button"))
    try body(harness.root, session, boot, journal.fileURL)
  }

  private static func withTwoEventJournal(
    _ suffix: String,
    _ body: (URL, String, String, URL) throws -> Void
  ) throws {
    let harness = try makeHarness(suffix)
    defer { removeHarness(harness.parent) }
    let session = "local_\(suffix)_001"
    let boot = "boot_\(suffix)_001"
    let journal = try TacuaDiagnosticJournal(
      rootDirectory: harness.root,
      localSessionID: session,
      bootSessionID: boot,
      monotonicClock: { 10 }
    )
    _ = try journal.append(.userInteraction(action: .tap, target: "save_button"))
    _ = try journal.append(.appStateChanged(fromState: .active, toState: .background))
    try body(harness.root, session, boot, journal.fileURL)
  }

  private static func makeHarness(_ suffix: String) throws -> (parent: URL, root: URL) {
    let parent = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-diagnostic-\(suffix)-\(UUID().uuidString)", isDirectory: true
    )
    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
    return (parent, parent.appendingPathComponent("diagnostics", isDirectory: true))
  }

  private static func removeHarness(_ url: URL) {
    try? FileManager.default.removeItem(at: url)
  }

  private static func mode(_ url: URL) throws -> mode_t {
    var metadata = stat()
    guard lstat(url.path, &metadata) == 0 else { throw POSIXError(.ENOENT) }
    return metadata.st_mode & 0o777
  }

  private static func readLines(_ url: URL) throws -> [Data] {
    let data = try Data(contentsOf: url)
    let bytes = [UInt8](data)
    return bytes.split(separator: UInt8(0x0A), omittingEmptySubsequences: true).map {
      Data($0)
    }
  }

  private static func rewrite(lines: [Data], to url: URL) throws {
    var data = Data()
    for line in lines {
      data.append(line)
      data.append(0x0A)
    }
    try rewrite(data, to: url)
  }

  private static func rewrite(_ data: Data, to url: URL) throws {
    let descriptor = open(url.path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    try writeAll(data, descriptor: descriptor)
    guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0, fsync(descriptor) == 0 else {
      throw POSIXError(.EIO)
    }
  }

  private static func rawAppend(_ data: Data, to url: URL) throws {
    let descriptor = open(url.path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    try writeAll(data, descriptor: descriptor)
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
  }

  private static func copyPrivate(from source: URL, to destination: URL) throws {
    let data = try Data(contentsOf: source)
    let descriptor = open(
      destination.path,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    try writeAll(data, descriptor: descriptor)
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
    try FileManager.default.setAttributes(
      [
        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        .posixPermissions: 0o600,
      ],
      ofItemAtPath: destination.path
    )
  }

  private static func writeAll(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { bytes in
      guard let base = bytes.baseAddress else { throw POSIXError(.EIO) }
      var offset = 0
      while offset < data.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw POSIXError(.EIO) }
        offset += count
      }
    }
  }
}
