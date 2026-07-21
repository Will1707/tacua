// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum QueueTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw QueueTestFailure.assertion(message) }
}

private func expectQueueError(
  _ expected: TacuaTransportQueueError,
  _ operation: () throws -> Void
) throws {
  do {
    try operation()
    throw QueueTestFailure.assertion("Expected \(expected)")
  } catch let error as TacuaTransportQueueError {
    try require(error == expected, "Expected \(expected), received \(error)")
  }
}

private struct TestClock: TacuaMonotonicClock {
  let uptimeMilliseconds: Int64
  let bootSessionID: String
}

private final class MemoryPersistence: TacuaTransportQueuePersisting {
  var snapshots: [TacuaTransportQueueV2] = []
  func persist(_ queue: TacuaTransportQueueV2) throws { snapshots.append(queue) }
}

private final class MemoryPayloadRemover: TacuaLocalPayloadRemoving {
  var removed: [String] = []
  func removePayload(atRelativePath path: String) throws { removed.append(path) }
}

private final class MemoryCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  var removals: [String] = []

  func store(secret: Data, credentialID: String) throws { values[credentialID] = secret }
  func read(credentialID: String) throws -> Data {
    guard let value = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return value
  }
  func remove(credentialID: String) throws {
    removals.append(credentialID)
    values.removeValue(forKey: credentialID)
  }
}

private let digestA = "sha256:" + String(repeating: "a", count: 64)
private let digestB = "sha256:" + String(repeating: "b", count: 64)
private let digestC = "sha256:" + String(repeating: "c", count: 64)

@main
enum TransportQueueTests {
  static func main() throws {
    try migrationDropsLegacyGrantAuthority()
    try queueNeverPersistsSecretsOrLaunchCodes()
    try timeAnchorSurvivesRestartAndRejectsReboot()
    try exactRetryKeepsHistoricalBodyCredentialAfterRotation()
    try completedCredentialsCannotRestartUploads()
    try completionAloneAuthorizesCrashSafePayloadCleanup()
    try deletionAloneAuthorizesCredentialRemoval()
    print("Tacua transport queue tests passed")
  }

  private static func makeActiveQueue() throws -> TacuaTransportQueueV2 {
    var queue = try TacuaTransportQueueV2(
      localSessionID: "session_local_001",
      localPayloadPaths: ["segments/000.mov", "diagnostics/events.json"]
    )
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_first",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_001")
    )
    return queue
  }

  private static func request(
    messageType: String,
    idField: String,
    id: String,
    credentialID: String,
    digestField: String
  ) throws -> (TacuaJSONValue, String) {
    let unsigned = TacuaJSONValue.object([
      "protocol_version": .string("tacua.sdk-backend@1.0.0"),
      "message_type": .string(messageType),
      idField: .string(id),
      "credential_id": .string(credentialID),
      digestField: .string(""),
    ])
    let digest = try TacuaCanonicalJSON.digest(unsigned, omittingRootField: digestField)
    guard case .object(var object) = unsigned else { fatalError() }
    object[digestField] = .string(digest)
    return (.object(object), digest)
  }

  private static func enqueue(
    _ kind: TacuaQueuedOperationKind,
    id: String,
    credentialID: String,
    queue: inout TacuaTransportQueueV2,
    clock: TestClock = TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_001")
  ) throws {
    let message: String
    let idField: String
    let digestField: String
    switch kind {
    case .segment:
      message = "segment_upload_intent"; idField = "upload_id"; digestField = "intent_digest"
    case .diagnostic:
      message = "diagnostic_upload_request"; idField = "upload_id"; digestField = "request_digest"
    case .completion:
      message = "completion_request"; idField = "completion_id"; digestField = "request_digest"
    case .deletion:
      message = "deletion_request"; idField = "deletion_id"; digestField = "request_digest"
    }
    let (body, digest) = try request(
      messageType: message,
      idField: idField,
      id: id,
      credentialID: credentialID,
      digestField: digestField
    )
    try queue.enqueueNewOperation(
      kind: kind,
      operationID: id,
      requestCredentialID: credentialID,
      request: body,
      requestDigest: digest,
      clock: clock
    )
  }

  private static func migrationDropsLegacyGrantAuthority() throws {
    let legacy = Data(#"{"schemaVersion":1,"localSessionId":"session_local_001","remoteSessionId":"session_remote_001","organizationId":"org_local","projectId":"project_local","buildId":"build_local","grantIdentifier":"grant_old","grantExpiresAt":"2027-01-01T00:00:00Z","items":[{"objectId":"segment_001","objectKind":"segment","segmentIndex":0,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","byteLength":42,"state":"queued","attemptCount":0,"nextAttemptAt":null,"lastErrorCode":null,"receipt":null}]}"#.utf8)
    let queue = try TacuaTransportQueueV2.decodeOrMigrate(legacy)
    try require(queue.schemaVersion == 2, "Migration must emit queue schema v2")
    try require(queue.credentialCapability == .requiresExchange, "A legacy grant is not a V1 credential")
    try require(queue.currentCredentialID == nil && queue.remoteSessionID == nil, "Legacy remote authority must be discarded")
    try require(queue.localPayloadPaths == ["legacy/segment_001"], "Local payload inventory must survive migration")
  }

  private static func queueNeverPersistsSecretsOrLaunchCodes() throws {
    let queue = try makeActiveQueue()
    let encoded = try queue.encoded()
    let text = String(decoding: encoded, as: UTF8.self).lowercased()
    try require(!text.contains("launch_code"), "Launch codes must be transient")
    try require(!text.contains("authorization"), "Authorization must not enter the queue")
    try require(!text.contains("\"secret\""), "Keychain secret fields must not enter the queue")
    _ = try TacuaTransportQueueV2.decodeOrMigrate(encoded)
  }

  private static func timeAnchorSurvivesRestartAndRejectsReboot() throws {
    let queue = try makeActiveQueue()
    let restarted = TestClock(uptimeMilliseconds: 105_000, bootSessionID: "boot_001")
    let restartedTimestamp = try queue.timestampForNewOperation(clock: restarted)
    try require(
      restartedTimestamp == "2026-07-21T10:00:05Z",
      "A process restart on the same boot must retain the persisted monotonic anchor"
    )
    try expectQueueError(.resumeRequired) {
      _ = try queue.timestampForNewOperation(
        clock: TestClock(uptimeMilliseconds: 5_000, bootSessionID: "boot_002")
      )
    }
    try expectQueueError(.resumeRequired) {
      _ = try queue.timestampForNewOperation(
        clock: TestClock(uptimeMilliseconds: 99_999, bootSessionID: "boot_001")
      )
    }
  }

  private static func exactRetryKeepsHistoricalBodyCredentialAfterRotation() throws {
    var queue = try makeActiveQueue()
    try enqueue(.segment, id: "upload_segment_001", credentialID: "credential_first", queue: &queue)
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_second",
      capability: .active,
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
    )
    let attempt = try queue.attempt(operationID: "upload_segment_001")
    try require(attempt.immutableRequestCredentialID == "credential_first", "Rotation must not rewrite protocol truth")
    try require(attempt.transportCredentialID == "credential_second", "Exact recovery authenticates with the current credential")
    let body = try TacuaCanonicalJSON.parse(attempt.canonicalRequest)
    try require(body.objectValue?["credential_id"]?.stringValue == "credential_first", "Historical request bytes must remain exact")
  }

  private static func completedCredentialsCannotRestartUploads() throws {
    var queue = try makeActiveQueue()
    try enqueue(.completion, id: "completion_001", credentialID: "credential_first", queue: &queue)
    let response = try TacuaCanonicalJSON.data(.object(["ok": .bool(true)]))
    try queue.storeResponse(operationID: "completion_001", canonicalResponse: response, responseDigest: digestB)
    try queue.authorizeCompletionCleanup(
      TacuaCompletionCleanupAuthority(
        completionID: "completion_001",
        completionReceiptDigest: digestB,
        manifestDigest: digestC,
        segmentReceiptDigests: [],
        diagnosticReceiptDigests: []
      )
    )
    try expectQueueError(.operationNotAllowed) {
      try enqueue(.segment, id: "upload_late", credentialID: "credential_first", queue: &queue)
    }
  }

  private static func completionAloneAuthorizesCrashSafePayloadCleanup() throws {
    var queue = try makeActiveQueue()
    let persistence = MemoryPersistence()
    let remover = MemoryPayloadRemover()
    try expectQueueError(.cleanupNotAuthorized) {
      try TacuaTransportCleanup.removeAuthorizedPayloads(
        queue: &queue, persistence: persistence, remover: remover
      )
    }
    try enqueue(.completion, id: "completion_001", credentialID: "credential_first", queue: &queue)
    let response = try TacuaCanonicalJSON.data(.object(["receipt": .string("durable")]))
    try queue.storeResponse(operationID: "completion_001", canonicalResponse: response, responseDigest: digestB)
    try queue.authorizeCompletionCleanup(
      TacuaCompletionCleanupAuthority(
        completionID: "completion_001",
        completionReceiptDigest: digestB,
        manifestDigest: digestC,
        segmentReceiptDigests: [digestA],
        diagnosticReceiptDigests: [digestB]
      )
    )
    try TacuaTransportCleanup.removeAuthorizedPayloads(
      queue: &queue, persistence: persistence, remover: remover
    )
    try require(persistence.snapshots.first?.payloadCleanupState == .tombstoneWritten, "Cleanup tombstone must be durable before deletion")
    try require(remover.removed == queue.localPayloadPaths, "Every payload must be removed")
    try require(queue.payloadCleanupState == .payloadsRemoved, "Cleanup must finish durably")
    try require(queue.currentCredentialID == "credential_first", "Completion must retain the deletion credential")

    var recovered = persistence.snapshots[0]
    let retryPersistence = MemoryPersistence()
    let retryRemover = MemoryPayloadRemover()
    try TacuaTransportCleanup.removeAuthorizedPayloads(
      queue: &recovered, persistence: retryPersistence, remover: retryRemover
    )
    try require(retryRemover.removed == recovered.localPayloadPaths, "A tombstoned crash must resume idempotent removal")
  }

  private static func deletionAloneAuthorizesCredentialRemoval() throws {
    var queue = try makeActiveQueue()
    try enqueue(.deletion, id: "deletion_001", credentialID: "credential_first", queue: &queue)
    let response = try TacuaCanonicalJSON.data(.object(["tombstone": .string("durable")]))
    try queue.storeResponse(operationID: "deletion_001", canonicalResponse: response, responseDigest: digestC)
    let persistence = MemoryPersistence()
    let credentials = MemoryCredentialStore()
    credentials.values["credential_first"] = Data(repeating: 7, count: 32)
    try expectQueueError(.deletionNotAuthorized) {
      try TacuaTransportCleanup.removeAuthorizedCredential(
        queue: &queue, persistence: persistence, credentialStore: credentials
      )
    }
    try queue.authorizeDeletionCleanup(
      TacuaDeletionCleanupAuthority(
        deletionID: "deletion_001", tombstoneDigest: digestC, credentialID: "credential_first"
      )
    )
    try TacuaTransportCleanup.removeAuthorizedCredential(
      queue: &queue, persistence: persistence, credentialStore: credentials
    )
    try require(persistence.snapshots.first?.credentialCleanupState == .tombstoneWritten, "Credential tombstone must precede Keychain removal")
    try require(credentials.removals == ["credential_first"], "Deletion must remove only the bound credential")
    try require(queue.currentCredentialID == nil && queue.credentialCleanupState == .credentialRemoved, "Credential cleanup must finish durably")
    _ = try queue.encoded()
  }
}
