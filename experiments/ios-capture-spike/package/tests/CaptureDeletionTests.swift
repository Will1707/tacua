// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum DeletionTestFailure: Error { case assertion(String), injectedFailure }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw DeletionTestFailure.assertion(message) }
}

private func required<T>(_ value: T?, _ message: String) throws -> T {
  guard let value else { throw DeletionTestFailure.assertion(message) }
  return value
}

private final class DeletionTestClock: TacuaMonotonicClock {
  var uptimeMilliseconds: Int64 = 200_000
  var bootSessionID = "boot_deletion_tests"
}

private final class DeletionTestCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  var removals: [String] = []
  var failRemoval = false

  func store(secret: Data, credentialID: String) throws { values[credentialID] = secret }
  func read(credentialID: String) throws -> Data {
    guard let value = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return value
  }
  func remove(credentialID: String) throws {
    if failRemoval { throw DeletionTestFailure.injectedFailure }
    removals.append(credentialID)
    values.removeValue(forKey: credentialID)
  }
}

private final class DeletionTestLease: TacuaSDKStartLifecycleLease {
  private let releaseBody: () -> Void
  private var released = false
  init(_ releaseBody: @escaping () -> Void) { self.releaseBody = releaseBody }
  func release() {
    guard !released else { return }
    released = true
    releaseBody()
  }
}

private final class DeletionTestLifecycleGate: TacuaCaptureAdmissionLifecycleGating {
  var startRecovery = false
  private let lock = NSLock()
  private(set) var activeLeaseCount = 0

  func acquireLifecycleLease(localSessionID: String) throws -> TacuaSDKStartLifecycleLease {
    lock.lock()
    activeLeaseCount += 1
    lock.unlock()
    return DeletionTestLease { [weak self] in
      self?.lock.lock()
      self?.activeLeaseCount -= 1
      self?.lock.unlock()
    }
  }

  func hasStartRecovery(localSessionID: String) throws -> Bool { startRecovery }
}

private final class DeletionTestResumeInspector: TacuaSDKResumeRecoveryInspecting {
  var resumeRecovery = false
  func hasRecovery(localSessionID: String) throws -> Bool { resumeRecovery }
}

private final class DeletionTestSender: TacuaSDKBackendOperationSending {
  enum Behavior { case success, forgedAuthority, suspended }
  var behavior: Behavior
  var onSend: ((TacuaPreparedBackendRequest) throws -> Void)?
  private let lock = NSLock()
  private var requests: [TacuaPreparedBackendRequest] = []

  init(behavior: Behavior = .success) { self.behavior = behavior }

  func observedRequests() -> [TacuaPreparedBackendRequest] {
    lock.lock()
    defer { lock.unlock() }
    return requests
  }

  private func record(_ request: TacuaPreparedBackendRequest) {
    lock.lock()
    requests.append(request)
    lock.unlock()
  }

  func send(
    _ request: TacuaPreparedBackendRequest,
    transportCredentialID: String
  ) async throws -> TacuaValidatedBackendReceipt {
    record(request)
    try onSend?(request)
    if behavior == .suspended {
      try await Task.sleep(nanoseconds: 60_000_000_000)
    }
    let receipt = try deletionReceipt(for: request)
    guard behavior == .forgedAuthority else { return receipt }
    return TacuaValidatedBackendReceipt(
      operationKind: receipt.operationKind,
      operationID: receipt.operationID,
      responseDigest: receipt.responseDigest,
      canonicalResponse: receipt.canonicalResponse,
      receivedTimestamp: receipt.receivedTimestamp,
      authoritativeTimestamp: receipt.authoritativeTimestamp,
      remoteSessionID: receipt.remoteSessionID,
      scopeDigest: receipt.scopeDigest,
      credentialTransition: receipt.credentialTransition,
      completionCleanupAuthority: receipt.completionCleanupAuthority,
      deletionCleanupAuthority: TacuaDeletionCleanupAuthority(
        deletionID: receipt.operationID,
        tombstoneDigest: "sha256:" + String(repeating: "f", count: 64),
        credentialID: request.credentialID
      )
    )
  }

  func uploadSegment(
    _ request: TacuaPreparedBackendRequest,
    fileURL: URL,
    sessionDirectory: URL,
    transportCredentialID: String
  ) async throws -> TacuaValidatedBackendReceipt {
    throw DeletionTestFailure.assertion("Deletion coordinator attempted a segment upload")
  }
}

private final class DeletionFaultingStore: TacuaCaptureDeletionQueueStoring {
  let base: TacuaTransportQueueFileStore
  var installThenThrowCAS = false
  var finalizeThenThrow = false

  init(base: TacuaTransportQueueFileStore) { self.base = base }
  func load(localSessionID: String) throws -> TacuaTransportQueueV3? {
    try base.load(localSessionID: localSessionID)
  }
  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws {
    try base.compareAndSwap(expected: expected, replacement: replacement)
    if installThenThrowCAS {
      installThenThrowCAS = false
      throw DeletionTestFailure.injectedFailure
    }
  }
  func recoverPayloadCleanup(
    localSessionID: String,
    sessionDirectory: URL
  ) throws -> TacuaTransportQueueV3? {
    try base.recoverPayloadCleanup(
      localSessionID: localSessionID,
      sessionDirectory: sessionDirectory
    )
  }
  func recoverCredentialCleanup(
    localSessionID: String,
    credentialStore: TacuaCredentialStoring
  ) throws -> TacuaTransportQueueV3? {
    try base.recoverCredentialCleanup(
      localSessionID: localSessionID,
      credentialStore: credentialStore
    )
  }
  func deletionFinalization(localSessionID: String) throws
    -> TacuaDeletionFinalizationMarker?
  {
    try base.deletionFinalization(localSessionID: localSessionID)
  }
  func finalizeDeletion(localSessionID: String) throws -> TacuaDeletionFinalizationMarker {
    let marker = try base.finalizeDeletion(localSessionID: localSessionID)
    if finalizeThenThrow {
      finalizeThenThrow = false
      throw DeletionTestFailure.injectedFailure
    }
    return marker
  }
}

private struct DeletionHarness {
  let root: URL
  let captureRoot: URL
  let queueStore: TacuaTransportQueueFileStore
  let configuration: TacuaBackendConfiguration
  let credentials: DeletionTestCredentialStore
  let gate: DeletionTestLifecycleGate
  let resume: DeletionTestResumeInspector
  let clock: DeletionTestClock
  let localSessionID: String
  let credentialID: String
}

@main
enum CaptureDeletionTests {
  static func main() async throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try await activeDeletionRetiresEverythingAndIsIdempotent()
    try await cancellationKeepsExactUnknownRequest()
    try await completionRestrictedQueueCanDelete(fixtureRoot)
    try await forgedAuthorityCannotAuthorizeCleanup()
    try await CASAndFinalizationAmbiguitiesRecover()
    try await recoveryGatesAndConflictsAreExplicit()
    print("Tacua capture deletion tests passed")
  }

  private static func activeDeletionRetiresEverythingAndIsIdempotent() async throws {
    let harness = try makeHarness("active")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedUnexpectedSessionFiles(harness)
    let sender = DeletionTestSender()
    sender.onSend = { request in
      let durable = try required(
        harness.queueStore.load(localSessionID: harness.localSessionID),
        "Deletion queue vanished before network I/O"
      )
      let operation = try required(
        durable.operations.first(where: { $0.operationID == request.operationID }),
        "Deletion request was not journaled before network I/O"
      )
      try require(operation.state == .outcomeUnknown, "Network began before unknown-state CAS")
      try require(
        operation.canonicalRequest == request.canonicalData,
        "Network did not send the exact durable deletion request"
      )
      try require(harness.gate.activeLeaseCount == 1, "Lifecycle lease was not held during I/O")
    }
    let coordinator = makeCoordinator(harness, sender: sender, store: harness.queueStore)
    let result = try await coordinator.delete(localSessionID: harness.localSessionID)
    try require(!result.alreadyDeleted, "First deletion was reported as a retry")
    try require(
      result.deletionID == TacuaCaptureDeletionCoordinator.stableUserRequestedDeletionID,
      "Deletion did not use its stable operation ID"
    )
    let request = try required(sender.observedRequests().first, "Deletion did not reach sender")
    let root = try required(
      try TacuaCanonicalJSON.parse(request.canonicalData).objectValue,
      "Deletion request was not an object"
    )
    try require(root["reason"]?.stringValue == "user_requested", "Wrong deletion reason")
    try require(root["target"]?.stringValue == "session_all_data", "Wrong deletion target")
    let session = harness.captureRoot.appendingPathComponent(harness.localSessionID)
    try require(!FileManager.default.fileExists(atPath: session.path), "Session directory survived")
    try require(
      FileManager.default.fileExists(
        atPath: harness.root.appendingPathComponent("outside-preserved.txt").path
      ),
      "Whole-session retirement followed an external symlink"
    )
    let removedQueue = try harness.queueStore.load(localSessionID: harness.localSessionID)
    try require(
      removedQueue == nil,
      "Sensitive queue survived completed local cleanup"
    )
    try require(harness.credentials.values.isEmpty, "Deletion credential survived")
    try require(harness.gate.activeLeaseCount == 0, "Deletion leaked lifecycle lease")

    let repeated = try await coordinator.delete(localSessionID: harness.localSessionID)
    try require(repeated.alreadyDeleted, "Finalization marker did not make retry idempotent")
    try require(sender.observedRequests().count == 1, "Idempotent retry repeated network I/O")
  }

  private static func cancellationKeepsExactUnknownRequest() async throws {
    let harness = try makeHarness("cancel")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedUnexpectedSessionFiles(harness)
    let suspended = DeletionTestSender(behavior: .suspended)
    let coordinator = makeCoordinator(harness, sender: suspended, store: harness.queueStore)
    let task = Task { try await coordinator.delete(localSessionID: harness.localSessionID) }
    for _ in 0..<1_000 where suspended.observedRequests().isEmpty {
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    let first = try required(suspended.observedRequests().first, "Deletion never entered I/O")
    let inFlight = try required(
      harness.queueStore.load(localSessionID: harness.localSessionID),
      "Cancelled deletion lost its queue"
    )
    try require(
      inFlight.operations.first(where: { $0.kind == .deletion })?.state == .outcomeUnknown,
      "Cancellation test did not durably enter outcome-unknown"
    )
    task.cancel()
    do {
      _ = try await task.value
      throw DeletionTestFailure.assertion("Cancelled deletion unexpectedly succeeded")
    } catch let error as TacuaCaptureDeletionError {
      try require(error == .transportOutcomeUnknown, "Cancellation surfaced wrong error")
    }
    let recoverySender = DeletionTestSender()
    let recovered = try await makeCoordinator(
      harness,
      sender: recoverySender,
      store: harness.queueStore
    ).delete(localSessionID: harness.localSessionID)
    try require(!recovered.alreadyDeleted, "Exact recovery was reported as an old deletion")
    let replay = try required(recoverySender.observedRequests().first, "Unknown request not replayed")
    try require(replay.canonicalData == first.canonicalData, "Unknown deletion bytes were rewritten")
    try require(replay.requestDigest == first.requestDigest, "Unknown deletion digest was rewritten")
  }

  private static func completionRestrictedQueueCanDelete(_ fixtureRoot: URL) async throws {
    let harness = try makeHarness("completion-restricted", persistInitialQueue: false)
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let completionData = try canonicalFixture(fixtureRoot, "completion-request")
    let completionRoot = try required(
      try TacuaCanonicalJSON.parse(completionData).objectValue,
      "Completion fixture is invalid"
    )
    let oldCredential = try required(
      completionRoot["credential_id"]?.stringValue,
      "Completion fixture has no credential"
    )
    let remoteSessionID = try required(
      completionRoot["session_id"]?.stringValue,
      "Completion fixture has no session"
    )
    let scopeDigest = try required(
      completionRoot["scope_digest"]?.stringValue,
      "Completion fixture has no scope"
    )
    let completionID = try required(
      completionRoot["completion_id"]?.stringValue,
      "Completion fixture has no ID"
    )
    let requestDigest = try required(
      completionRoot["request_digest"]?.stringValue,
      "Completion fixture has no digest"
    )
    var queue = try TacuaTransportQueueV3(localSessionID: harness.localSessionID)
    try queue.applyExchange(
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialID: oldCredential,
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-21T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: DeletionTestClock()
    )
    try queue.enqueueNewOperation(
      kind: .completion,
      operationID: completionID,
      requestCredentialID: oldCredential,
      request: try TacuaCanonicalJSON.parse(completionData),
      requestDigest: requestDigest,
      clock: harness.clock
    )
    _ = try queue.beginAttempt(
      operationID: completionID,
      expectedTransportConfigurationDigest: harness.configuration.configurationDigest,
      clock: harness.clock
    )
    let newCredential = "credential_delete_resumed_001"
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:01:00Z",
      clock: harness.clock
    )
    try queue.applyRecoveredResume(
      expectedCurrentCredentialID: oldCredential,
      newCredentialID: newCredential,
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-21T10:01:00Z",
      capability: .completionReplayOrDeleteOnly,
      replayCompletionID: completionID,
      timeAnchor: anchor
    )
    try harness.queueStore.persistInitial(queue)
    harness.credentials.values[newCredential] = Data(repeating: 0x44, count: 32)
    try seedUnexpectedSessionFiles(harness)
    let sender = DeletionTestSender()
    let result = try await makeCoordinator(
      harness,
      sender: sender,
      store: harness.queueStore
    ).delete(localSessionID: harness.localSessionID)
    try require(!result.alreadyDeleted, "Completion-restricted deletion did not execute")
    let request = try required(sender.observedRequests().first, "Deletion was not sent")
    try require(
      request.credentialID == newCredential,
      "Completion-restricted deletion used the historical completion credential"
    )
  }

  private static func forgedAuthorityCannotAuthorizeCleanup() async throws {
    let harness = try makeHarness("forged")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedUnexpectedSessionFiles(harness)
    let sender = DeletionTestSender(behavior: .forgedAuthority)
    do {
      _ = try await makeCoordinator(
        harness,
        sender: sender,
        store: harness.queueStore
      ).delete(localSessionID: harness.localSessionID)
      throw DeletionTestFailure.assertion("Forged cleanup authority was accepted")
    } catch let error as TacuaCaptureDeletionError {
      try require(error == .receiptCommitPending, "Forged receipt surfaced wrong error")
    }
    let session = harness.captureRoot.appendingPathComponent(harness.localSessionID)
    try require(FileManager.default.fileExists(atPath: session.path), "Forged receipt deleted local data")
    try require(
      harness.credentials.values[harness.credentialID] != nil,
      "Forged receipt removed credential"
    )
    let queue = try required(
      harness.queueStore.load(localSessionID: harness.localSessionID),
      "Forged receipt removed queue"
    )
    try require(queue.deletionCleanupAuthority == nil, "Forged authority became durable")
  }

  private static func CASAndFinalizationAmbiguitiesRecover() async throws {
    let harness = try makeHarness("ambiguities")
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedUnexpectedSessionFiles(harness)
    let faulting = DeletionFaultingStore(base: harness.queueStore)
    faulting.installThenThrowCAS = true
    faulting.finalizeThenThrow = true
    let sender = DeletionTestSender()
    do {
      _ = try await makeCoordinator(
        harness,
        sender: sender,
        store: faulting
      ).delete(localSessionID: harness.localSessionID)
      throw DeletionTestFailure.assertion("Finalization ambiguity reported success")
    } catch let error as TacuaCaptureDeletionError {
      try require(error == .finalizationPending, "Finalization ambiguity surfaced wrong error")
    }
    try require(sender.observedRequests().count == 1, "CAS ambiguity duplicated network I/O")
    let removedQueue = try harness.queueStore.load(localSessionID: harness.localSessionID)
    try require(
      removedQueue == nil,
      "Finalize-then-throw retained sensitive queue"
    )
    let recovered = try await makeCoordinator(
      harness,
      sender: sender,
      store: faulting
    ).delete(localSessionID: harness.localSessionID)
    try require(recovered.alreadyDeleted, "Finalization proof did not recover ambiguity")
    try require(sender.observedRequests().count == 1, "Finalization recovery repeated deletion")
  }

  private static func recoveryGatesAndConflictsAreExplicit() async throws {
    let resumeHarness = try makeHarness("resume-gate")
    defer { try? FileManager.default.removeItem(at: resumeHarness.root) }
    resumeHarness.resume.resumeRecovery = true
    do {
      _ = try await makeCoordinator(
        resumeHarness,
        sender: DeletionTestSender(),
        store: resumeHarness.queueStore
      ).delete(localSessionID: resumeHarness.localSessionID)
      throw DeletionTestFailure.assertion("RESUME recovery gate was ignored")
    } catch let error as TacuaCaptureDeletionError {
      try require(error == .resumeRecoveryRequired, "RESUME gate surfaced wrong error")
    }

    let conflictHarness = try makeHarness("conflict")
    defer { try? FileManager.default.removeItem(at: conflictHarness.root) }
    var queue = try required(
      conflictHarness.queueStore.load(localSessionID: conflictHarness.localSessionID),
      "Conflict queue missing"
    )
    let requestedAt = try queue.timestampForNewOperation(clock: conflictHarness.clock)
    let request = try TacuaSDKBackendRequests.deletion(
      deletionID: "deletion_operator_001",
      sessionID: try required(queue.remoteSessionID, "Conflict remote session missing"),
      scopeDigest: try required(queue.scopeDigest, "Conflict scope missing"),
      credentialID: try required(queue.currentCredentialID, "Conflict credential missing"),
      reason: "operator_requested",
      requestedAt: requestedAt
    )
    let expected = queue
    try queue.enqueueNewOperation(
      kind: .deletion,
      operationID: request.operationID,
      requestCredentialID: request.credentialID,
      request: try TacuaCanonicalJSON.parse(request.canonicalData),
      requestDigest: request.requestDigest,
      clock: conflictHarness.clock
    )
    try conflictHarness.queueStore.compareAndSwap(expected: expected, replacement: queue)
    do {
      _ = try await makeCoordinator(
        conflictHarness,
        sender: DeletionTestSender(),
        store: conflictHarness.queueStore
      ).delete(localSessionID: conflictHarness.localSessionID)
      throw DeletionTestFailure.assertion("Conflicting operator deletion was guessed through")
    } catch let error as TacuaCaptureDeletionError {
      try require(error == .reconciliationRequired, "Conflict surfaced wrong error")
    }
  }

  private static func makeHarness(
    _ suffix: String,
    persistInitialQueue: Bool = true
  ) throws -> DeletionHarness {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-deletion-\(suffix)-\(UUID().uuidString)",
      isDirectory: true
    )
    let captureRoot = root.appendingPathComponent("captures", isDirectory: true)
    let queueRoot = root.appendingPathComponent("queues", isDirectory: true)
    try FileManager.default.createDirectory(at: captureRoot, withIntermediateDirectories: true)
    let store = try TacuaTransportQueueFileStore(rootDirectory: queueRoot)
    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.tacua.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let localSessionID = "session_delete_\(suffix.replacingOccurrences(of: "-", with: "_"))"
    let credentialID = "credential_delete_\(suffix.replacingOccurrences(of: "-", with: "_"))"
    let credentials = DeletionTestCredentialStore()
    credentials.values[credentialID] = Data(repeating: 0x33, count: 32)
    let clock = DeletionTestClock()
    if persistInitialQueue {
      var queue = try TacuaTransportQueueV3(localSessionID: localSessionID)
      try queue.applyExchange(
        remoteSessionID: "remote_delete_\(suffix.replacingOccurrences(of: "-", with: "_"))",
        scopeDigest: "sha256:" + String(repeating: "a", count: 64),
        credentialID: credentialID,
        transportConfigurationDigest: configuration.configurationDigest,
        expiresAt: "2026-08-21T10:00:00Z",
        capability: .active,
        issuedAt: "2026-07-21T10:00:00Z",
        clock: DeletionTestClock()
      )
      try store.persistInitial(queue)
    }
    return DeletionHarness(
      root: root,
      captureRoot: captureRoot,
      queueStore: store,
      configuration: configuration,
      credentials: credentials,
      gate: DeletionTestLifecycleGate(),
      resume: DeletionTestResumeInspector(),
      clock: clock,
      localSessionID: localSessionID,
      credentialID: credentialID
    )
  }

  private static func makeCoordinator(
    _ harness: DeletionHarness,
    sender: DeletionTestSender,
    store: TacuaCaptureDeletionQueueStoring
  ) -> TacuaCaptureDeletionCoordinator {
    TacuaCaptureDeletionCoordinator(
      configuration: harness.configuration,
      captureRootDirectory: harness.captureRoot,
      queueStore: store,
      lifecycleGate: harness.gate,
      resumeRecoveryInspector: harness.resume,
      sender: sender,
      credentialStore: harness.credentials,
      clock: harness.clock
    )
  }

  private static func seedUnexpectedSessionFiles(_ harness: DeletionHarness) throws {
    let session = harness.captureRoot.appendingPathComponent(
      harness.localSessionID,
      isDirectory: true
    )
    let diagnostics = session.appendingPathComponent("diagnostics", isDirectory: true)
    try FileManager.default.createDirectory(at: diagnostics, withIntermediateDirectories: true)
    for relative in [
      "manifest.json", "backend-admission-v1.json", "unexpected.partial",
      "diagnostics/\(harness.localSessionID).diagnostics-v1.jsonl",
    ] {
      try Data("corrupt-\(relative)".utf8).write(to: session.appendingPathComponent(relative))
    }
    let protected = session.appendingPathComponent("protected.partial")
    try Data("protected".utf8).write(to: protected)
    try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: protected.path)
    let outside = harness.root.appendingPathComponent("outside-preserved.txt")
    try Data("outside".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(
      at: session.appendingPathComponent("outside-link"),
      withDestinationURL: outside
    )
  }
}

private func canonicalFixture(_ root: URL, _ name: String) throws -> Data {
  let raw = try Data(contentsOf: root.appendingPathComponent("\(name).json"))
  return try TacuaCanonicalJSON.data(TacuaCanonicalJSON.parse(raw))
}

private func deletionReceipt(
  for request: TacuaPreparedBackendRequest
) throws -> TacuaValidatedBackendReceipt {
  let root = try required(
    try TacuaCanonicalJSON.parse(request.canonicalData).objectValue,
    "Deletion request is not an object"
  )
  let deletionID = try required(root["deletion_id"]?.stringValue, "Missing deletion ID")
  let sessionID = try required(root["session_id"]?.stringValue, "Missing session ID")
  let scopeDigest = try required(root["scope_digest"]?.stringValue, "Missing scope")
  let credentialID = try required(root["credential_id"]?.stringValue, "Missing credential")
  let requestDigest = try required(root["request_digest"]?.stringValue, "Missing digest")
  let requestedAt = try required(root["requested_at"]?.stringValue, "Missing timestamp")
  let requestedEpoch = try required(
    TacuaProtocolTimestamp.parseMilliseconds(requestedAt),
    "Invalid request timestamp"
  )
  let acceptedAt = TacuaProtocolTimestamp.format(milliseconds: requestedEpoch + 1_000)
  let deletedAt = TacuaProtocolTimestamp.format(milliseconds: requestedEpoch + 2_000)
  let expiresAt = TacuaProtocolTimestamp.format(
    milliseconds: requestedEpoch + 2_000 + 29 * 24 * 60 * 60 * 1_000
  )
  var response: [String: TacuaJSONValue] = [
    "protocol_version": .string(TacuaSDKBackendProtocol.version),
    "message_type": .string("deletion_tombstone"),
    "deletion_id": .string(deletionID),
    "deletion_request_digest": .string(requestDigest),
    "session_id": .string(sessionID),
    "scope_digest": .string(scopeDigest),
    "credential": .object([
      "credential_id": .string(credentialID),
      "state": .string("deletion_replay_only"),
      "replay_deletion_id": .string(deletionID),
      "verifier_retained_until": .string(expiresAt),
    ]),
    "session_access": .object([
      "uploads": .string("revoked"),
      "completion": .string("revoked"),
      "processing": .string("revoked"),
      "evidence": .string("revoked"),
    ]),
    "erasure": .object([
      "raw_media": .string("deleted"),
      "diagnostics": .string("deleted"),
      "derived_data": .string("deleted"),
      "session_metadata": .string("deleted_except_tombstone_and_replay_verifier"),
      "erased_object_count": .integer(4),
    ]),
    "local_credential_cleanup": .string("authorized_after_durable_tombstone"),
    "accepted_at": .string(acceptedAt),
    "deleted_at": .string(deletedAt),
    "tombstone_expires_at": .string(expiresAt),
    "tombstone_digest": .string("sha256:" + String(repeating: "0", count: 64)),
  ]
  response["tombstone_digest"] = .string(
    try TacuaCanonicalJSON.digest(.object(response), omittingRootField: "tombstone_digest")
  )
  let data = try TacuaCanonicalJSON.data(.object(response))
  return try TacuaSDKBackendProtocol.validateResponse(
    data,
    forCanonicalRequest: request.canonicalData
  )
}
