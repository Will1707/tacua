// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum QueueTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw QueueTestFailure.assertion(message) }
}

private func requireValue<T>(_ value: T?, _ message: String) throws -> T {
  guard let value else { throw QueueTestFailure.assertion(message) }
  return value
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

private func expectAnyFailure(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw QueueTestFailure.assertion("Expected failure")
  } catch is QueueTestFailure {
    throw QueueTestFailure.assertion("Expected failure")
  } catch {
    return
  }
}

private struct TestClock: TacuaMonotonicClock {
  let uptimeMilliseconds: Int64
  let bootSessionID: String
}

private final class MemoryPersistence: TacuaTransportQueuePersisting {
  var snapshots: [TacuaTransportQueueV3] = []
  func persist(_ queue: TacuaTransportQueueV3) throws { snapshots.append(queue) }
}

private final class MemoryPayloadRemover: TacuaLocalPayloadRemoving {
  var removed: [TacuaLocalPayloadBinding] = []
  func removePayload(_ binding: TacuaLocalPayloadBinding) throws { removed.append(binding) }
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
private let transportDigest = "sha256:" + String(repeating: "d", count: 64)

@main
enum TransportQueueTests {
  static func main() throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try migrationDropsLegacyGrantAuthority()
    try migrationFromV2RequiresCurrentTransportRebind()
    try migrationFromV2DropsUnavailableBootAnchor()
    try migrationFromV2BackfillsStoredResponseArtifactDigest(fixtureRoot)
    try migrationFromV2PreservesFullyCleanedDeletion(fixtureRoot)
    try queueNeverPersistsSecretsOrLaunchCodes()
    try strictIdentifierAndSensitiveKeyBounds()
    try persistedDecodeBoundsCollectionsAndStrings()
    try timeAnchorSurvivesRestartAndRejectsReboot()
    try expiredCredentialsRequireResumeAtHalfOpenBoundary()
    try exactRetryKeepsHistoricalBodyCredentialAfterRotation()
    try sameIdentifierRotationIsRejected()
    try rotationRemovalIsJournaledBeforeKeychainMutation()
    try completedCredentialsCannotRestartUploads()
    try responseStorageFailsClosed()
    try completionAloneAuthorizesCrashSafePayloadCleanup(fixtureRoot)
    try completionReplaySurvivesAnotherCredentialRotation(fixtureRoot)
    try cleanupRejectsUnboundMissingAndAliasedPayloads(fixtureRoot)
    try deletionAloneAuthorizesCredentialRemoval(fixtureRoot)
    print("Tacua transport queue tests passed")
  }

  private static func makeActiveQueue() throws -> TacuaTransportQueueV3 {
    var queue = try TacuaTransportQueueV3(
      localSessionID: "session_local_001",
      localPayloadPaths: ["segments/000.mov", "diagnostics/events.json"]
    )
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_first",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
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
    queue: inout TacuaTransportQueueV3,
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
    let queue = try TacuaTransportQueueV3.decodeOrMigrate(legacy)
    try require(queue.schemaVersion == 3, "Migration must emit queue schema v3")
    try require(queue.credentialCapability == .requiresExchange, "A legacy grant is not a V1 credential")
    try require(queue.currentCredentialID == nil && queue.remoteSessionID == nil, "Legacy remote authority must be discarded")
    try require(queue.localPayloadPaths == ["legacy/segment_001"], "Local payload inventory must survive migration")
  }

  private static func migrationFromV2RequiresCurrentTransportRebind() throws {
    var source = try makeActiveQueue()
    try enqueue(
      .diagnostic,
      id: "upload_migrated_001",
      credentialID: "credential_first",
      queue: &source
    )
    guard var v2Object = try JSONSerialization.jsonObject(
      with: source.encoded()
    ) as? [String: Any] else {
      throw QueueTestFailure.assertion("Could not construct a queue-v2 fixture")
    }
    v2Object["schemaVersion"] = 2
    v2Object.removeValue(forKey: "transportConfigurationDigest")
    let v2 = try JSONSerialization.data(withJSONObject: v2Object, options: [.sortedKeys])

    var migrated = try TacuaTransportQueueV3.decodeOrMigrate(v2)
    try require(migrated.schemaVersion == 3, "V2 migration must emit queue schema v3")
    try require(
      migrated.credentialCapability == .requiresTransportRebind,
      "V2 transport authority must require a build-pinned rebind"
    )
    try require(
      migrated.transportConfigurationDigest == nil,
      "V2 migration must not invent a transport configuration digest"
    )
    try expectQueueError(.resumeRequired) {
      _ = try migrated.timestampForNewOperation(
        clock: TestClock(uptimeMilliseconds: 102_000, bootSessionID: "boot_001")
      )
    }
    try expectQueueError(.transportConfigurationMismatch) {
      _ = try migrated.attempt(
        operationID: "upload_migrated_001",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 102_000, bootSessionID: "boot_001")
      )
    }

    try migrated.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_rebound",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T11:00:00Z",
      previousCredentialID: "credential_first",
      capability: .active,
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
    )
    let attempt = try migrated.attempt(
      operationID: "upload_migrated_001",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_001")
    )
    try require(
      attempt.immutableRequestCredentialID == "credential_first"
        && attempt.transportCredentialID == "credential_rebound",
      "Current-digest rebind must resume exact sends without rewriting request authority"
    )
  }

  private static func migrationFromV2DropsUnavailableBootAnchor() throws {
    let source = try makeActiveQueue()
    guard var v2Object = try JSONSerialization.jsonObject(
      with: source.encoded()
    ) as? [String: Any],
      var timeAnchor = v2Object["timeAnchor"] as? [String: Any]
    else {
      throw QueueTestFailure.assertion("Could not construct boot-anchor queue-v2 fixture")
    }
    v2Object["schemaVersion"] = 2
    v2Object.removeValue(forKey: "transportConfigurationDigest")
    timeAnchor["bootSessionID"] = "unavailable"
    v2Object["timeAnchor"] = timeAnchor
    let v2 = try JSONSerialization.data(withJSONObject: v2Object, options: [.sortedKeys])

    var migrated = try TacuaTransportQueueV3.decodeOrMigrate(v2)
    try require(
      migrated.credentialCapability == .requiresTransportRebind && migrated.timeAnchor == nil,
      "V2 unavailable boot sentinel must migrate to an anchorless transport rebind"
    )
    try migrated.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_rebound",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T11:00:00Z",
      previousCredentialID: "credential_first",
      capability: .active,
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_002")
    )
    try require(
      migrated.timeAnchor?.bootSessionID == "boot_002",
      "A current rebind must replace the discarded legacy boot anchor"
    )
  }

  private static func migrationFromV2BackfillsStoredResponseArtifactDigest(
    _ root: URL
  ) throws {
    let source = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )
    let expectedArtifactDigests = Dictionary(
      uniqueKeysWithValues: try source.operations.map { operation in
        (
          operation.operationID,
          try requireValue(
            operation.responseArtifactDigest,
            "Response fixture did not establish an artifact digest"
          )
        )
      }
    )
    guard var v2Object = try JSONSerialization.jsonObject(
      with: source.encoded()
    ) as? [String: Any],
      var operations = v2Object["operations"] as? [[String: Any]],
      !operations.isEmpty
    else {
      throw QueueTestFailure.assertion("Could not construct response-stored queue-v2 fixture")
    }
    for index in operations.indices {
      operations[index].removeValue(forKey: "responseArtifactDigest")
    }
    v2Object["operations"] = operations
    v2Object["schemaVersion"] = 2
    v2Object.removeValue(forKey: "transportConfigurationDigest")
    let v2 = try JSONSerialization.data(withJSONObject: v2Object, options: [.sortedKeys])

    let migrated = try TacuaTransportQueueV3.decodeOrMigrate(v2)
    try require(
      Dictionary(uniqueKeysWithValues: migrated.operations.compactMap { operation in
        operation.responseArtifactDigest.map { (operation.operationID, $0) }
      }) == expectedArtifactDigests,
      "V2 migration did not independently backfill stored protocol artifact evidence"
    )
    try require(
      migrated.credentialCapability == .requiresTransportRebind,
      "Completion-authorized V2 queue bypassed the transport rebind"
    )
    let cleanupBindings = try migrated.authorizedLocalPayloadBindings()
    try require(
      !cleanupBindings.isEmpty,
      "Completion V2 migration discarded local cleanup authority"
    )
  }

  private static func migrationFromV2PreservesFullyCleanedDeletion(
    _ root: URL
  ) throws {
    let source = try fixtureQueue(
      root,
      requestName: "deletion-request",
      kind: .deletion,
      operationID: "deletion_synthetic",
      responseName: "deletion-tombstone"
    )

    func v2Bytes(_ queue: TacuaTransportQueueV3) throws -> Data {
      guard var object = try JSONSerialization.jsonObject(
        with: queue.encoded()
      ) as? [String: Any] else {
        throw QueueTestFailure.assertion("Could not construct deletion queue-v2 fixture")
      }
      object["schemaVersion"] = 2
      object.removeValue(forKey: "transportConfigurationDigest")
      return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    var cleanupPendingSource = source
    cleanupPendingSource.credentialCleanupState = .tombstoneWritten
    var cleanupPending = try TacuaTransportQueueV3.decodeOrMigrate(
      v2Bytes(cleanupPendingSource)
    )
    try require(cleanupPending.schemaVersion == 3, "Cleanup-pending V2 deletion did not migrate")
    try require(
      cleanupPending.credentialCapability == .deletionReplayOnly,
      "Cleanup-pending V2 deletion was converted into an impossible credential rebind"
    )
    try require(
      cleanupPending.credentialCleanupState == .tombstoneWritten
        && cleanupPending.currentCredentialID == "credential_receiving_resume",
      "V2 migration discarded pending local credential cleanup"
    )
    try require(
      cleanupPending.transportConfigurationDigest == nil,
      "V2 migration invented transport binding for cleanup-pending deletion"
    )
    try expectQueueError(.transportConfigurationMismatch) {
      _ = try cleanupPending.attempt(
        operationID: "deletion_synthetic",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_fixture")
      )
    }
    let pendingPersistence = MemoryPersistence()
    let pendingCredentials = MemoryCredentialStore()
    pendingCredentials.values["credential_receiving_resume"] = Data(repeating: 7, count: 32)
    try TacuaTransportCleanup.removeAuthorizedCredential(
      queue: &cleanupPending,
      persistence: pendingPersistence,
      credentialStore: pendingCredentials
    )
    try require(
      cleanupPending.credentialCleanupState == .credentialRemoved
        && cleanupPending.currentCredentialID == nil,
      "Migrated V2 deletion could not finish its local credential cleanup"
    )
    _ = try cleanupPending.encoded()

    var cleanedSource = source
    let cleanupPersistence = MemoryPersistence()
    let cleanupCredentials = MemoryCredentialStore()
    cleanupCredentials.values["credential_receiving_resume"] = Data(repeating: 7, count: 32)
    try TacuaTransportCleanup.removeAuthorizedCredential(
      queue: &cleanedSource,
      persistence: cleanupPersistence,
      credentialStore: cleanupCredentials
    )
    let cleaned = try TacuaTransportQueueV3.decodeOrMigrate(v2Bytes(cleanedSource))
    try require(cleaned.schemaVersion == 3, "Credential-removed V2 deletion did not migrate")
    try require(
      cleaned.credentialCapability == .deletionReplayOnly,
      "Credential-removed V2 deletion was converted into an impossible rebind"
    )
    try require(
      cleaned.credentialCleanupState == .credentialRemoved
        && cleaned.currentCredentialID == nil,
      "V2 migration resurrected cleaned credential authority"
    )
    try require(
      cleaned.transportConfigurationDigest == nil,
      "V2 migration invented transport binding for terminal cleanup state"
    )
    try expectQueueError(.missingCredential) {
      _ = try cleaned.attempt(
        operationID: "deletion_synthetic",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_fixture")
      )
    }
  }

  private static func queueNeverPersistsSecretsOrLaunchCodes() throws {
    let queue = try makeActiveQueue()
    let encoded = try queue.encoded()
    let text = String(decoding: encoded, as: UTF8.self).lowercased()
    try require(!text.contains("launch_code"), "Launch codes must be transient")
    try require(!text.contains("authorization"), "Authorization must not enter the queue")
    try require(!text.contains("\"secret\""), "Keychain secret fields must not enter the queue")
    _ = try TacuaTransportQueueV3.decodeOrMigrate(encoded)
  }

  private static func strictIdentifierAndSensitiveKeyBounds() throws {
    try expectQueueError(.invalidQueue) {
      _ = try TacuaTransportQueueV3(localSessionID: "a" + String(repeating: "b", count: 64))
    }
    var queue = try makeActiveQueue()
    let unsafeRequest = TacuaJSONValue.object([
      "protocol_version": .string("tacua.sdk-backend@1.0.0"),
      "message_type": .string("diagnostic_upload_request"),
      "upload_id": .string("upload_unsafe"),
      "credential_id": .string("credential_first"),
      "client_secret": .string("must_not_persist"),
      "request_digest": .string(""),
    ])
    let digest = try TacuaCanonicalJSON.digest(
      unsafeRequest, omittingRootField: "request_digest"
    )
    guard case .object(var object) = unsafeRequest else { fatalError() }
    object["request_digest"] = .string(digest)
    try expectQueueError(.prohibitedPersistedMaterial) {
      try queue.enqueueNewOperation(
        kind: .diagnostic,
        operationID: "upload_unsafe",
        requestCredentialID: "credential_first",
        request: .object(object),
        requestDigest: digest,
        clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_001")
      )
    }
  }

  private static func persistedDecodeBoundsCollectionsAndStrings() throws {
    let tooManyPaths = (0...TacuaTransportQueueV3.maximumLocalPayloadPaths).map {
      "segments/\($0).mov"
    }
    try expectQueueError(.invalidQueue) {
      _ = try TacuaTransportQueueV3(
        localSessionID: "session_too_many_paths",
        localPayloadPaths: tooManyPaths
      )
    }

    let legacyItems: [[String: Any]] = (0...4_097).map {
      ["objectId": "segment_\($0)", "objectKind": "segment"]
    }
    let oversizedLegacy = try JSONSerialization.data(
      withJSONObject: [
        "schemaVersion": 1,
        "localSessionId": "session_legacy_bounded",
        "items": legacyItems,
      ],
      options: [.sortedKeys]
    )
    try expectQueueError(.invalidQueue) {
      _ = try TacuaTransportQueueV3.decodeOrMigrate(oversizedLegacy)
    }

    let queue = try makeActiveQueue()
    guard var object = try JSONSerialization.jsonObject(
      with: queue.encoded()
    ) as? [String: Any] else {
      throw QueueTestFailure.assertion("Could not construct bounded queue fixture")
    }
    object["remoteSessionID"] = "s" + String(repeating: "x", count: 64)
    let oversizedIdentifier = try JSONSerialization.data(
      withJSONObject: object,
      options: [.sortedKeys]
    )
    try expectQueueError(.invalidQueue) {
      _ = try TacuaTransportQueueV3.decodeOrMigrate(oversizedIdentifier)
    }
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
    try expectQueueError(.resumeRequired) {
      _ = try queue.timestampForNewOperation(
        clock: TestClock(uptimeMilliseconds: 105_000, bootSessionID: "unavailable")
      )
    }
    try expectQueueError(.invalidTimeAnchor) {
      _ = try TacuaServerTimeAnchor.establish(
        issuedAt: "2026-07-21T10:00:00Z",
        clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "")
      )
    }
    try expectQueueError(.invalidTimeAnchor) {
      _ = try TacuaServerTimeAnchor.establish(
        issuedAt: "2026-07-21T10:00:00Z",
        clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "unavailable")
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
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      previousCredentialID: "credential_first",
      capability: .active,
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
    )
    let attempt = try queue.attempt(
      operationID: "upload_segment_001",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_001")
    )
    try require(attempt.immutableRequestCredentialID == "credential_first", "Rotation must not rewrite protocol truth")
    try require(attempt.transportCredentialID == "credential_second", "Exact recovery authenticates with the current credential")
    let body = try TacuaCanonicalJSON.parse(attempt.canonicalRequest)
    try require(body.objectValue?["credential_id"]?.stringValue == "credential_first", "Historical request bytes must remain exact")
  }

  private static func expiredCredentialsRequireResumeAtHalfOpenBoundary() throws {
    var queue = try TacuaTransportQueueV3(localSessionID: "session_expiry_001")
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_short",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-07-21T10:00:02Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_expiry")
    )
    try enqueue(
      .diagnostic,
      id: "upload_before_expiry",
      credentialID: "credential_short",
      queue: &queue,
      clock: TestClock(uptimeMilliseconds: 101_999, bootSessionID: "boot_expiry")
    )
    try expectQueueError(.resumeRequired) {
      _ = try queue.attempt(
        operationID: "upload_before_expiry",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 102_000, bootSessionID: "boot_expiry")
      )
    }
    try expectQueueError(.resumeRequired) {
      try enqueue(
        .diagnostic,
        id: "upload_at_expiry",
        credentialID: "credential_short",
        queue: &queue,
        clock: TestClock(uptimeMilliseconds: 102_000, bootSessionID: "boot_expiry")
      )
    }
  }

  private static func sameIdentifierRotationIsRejected() throws {
    var queue = try makeActiveQueue()
    try expectQueueError(.invalidQueue) {
      try queue.applyExchange(
        remoteSessionID: "session_remote_001",
        scopeDigest: digestA,
        credentialID: "credential_first",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:00:00Z",
        previousCredentialID: "credential_first",
        capability: .active,
        issuedAt: "2026-07-21T10:05:00Z",
        clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
      )
    }
  }

  private static func rotationRemovalIsJournaledBeforeKeychainMutation() throws {
    var queue = try makeActiveQueue()
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_second",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      previousCredentialID: "credential_first",
      capability: .active,
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
    )
    let persistence = MemoryPersistence()
    let credentials = MemoryCredentialStore()
    credentials.values["credential_first"] = Data(repeating: 1, count: 32)
    credentials.values["credential_second"] = Data(repeating: 2, count: 32)
    try TacuaTransportCleanup.removePendingRevokedCredentials(
      queue: &queue,
      persistence: persistence,
      credentialStore: credentials
    )
    try require(
      persistence.snapshots.first?.pendingRevokedCredentialRemovals == ["credential_first"],
      "Revoked credential cleanup journal must be durable before Keychain removal"
    )
    try require(credentials.values["credential_first"] == nil, "Revoked secret must be removed")
    try require(credentials.values["credential_second"] != nil, "Current secret must remain")
    try require(queue.pendingRevokedCredentialRemovals.isEmpty, "Removal journal must drain durably")
  }

  private static func completedCredentialsCannotRestartUploads() throws {
    var queue = try makeActiveQueue()
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: digestA,
      credentialID: "credential_completed",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      previousCredentialID: "credential_first",
      capability: .completionReplayOrDeleteOnly,
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
    )
    try expectQueueError(.operationNotAllowed) {
      try enqueue(.segment, id: "upload_late", credentialID: "credential_completed", queue: &queue)
    }
  }

  private static func responseStorageFailsClosed() throws {
    var queue = try makeActiveQueue()
    try enqueue(.diagnostic, id: "upload_diagnostic_001", credentialID: "credential_first", queue: &queue)
    let canonical = try TacuaCanonicalJSON.data(.object(["ok": .bool(true)]))
    try expectQueueError(.responseConflict) {
      try queue.storeResponse(
        operationID: "upload_diagnostic_001", canonicalResponse: canonical,
        responseDigest: digestB
      )
    }
    var nonCanonical = canonical
    nonCanonical.append(0x0A)
    try expectQueueError(.responseConflict) {
      try queue.storeResponse(
        operationID: "upload_diagnostic_001", canonicalResponse: nonCanonical,
        responseDigest: TacuaCanonicalJSON.digest(data: nonCanonical)
      )
    }
  }

  private static func completionAloneAuthorizesCrashSafePayloadCleanup(_ root: URL) throws {
    var queue = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )
    let persistence = MemoryPersistence()
    let remover = MemoryPayloadRemover()
    let authorizedBindings = try queue.authorizedLocalPayloadBindings()
    try TacuaTransportCleanup.removeAuthorizedPayloads(
      queue: &queue, persistence: persistence, remover: remover
    )
    try require(persistence.snapshots.first?.payloadCleanupState == .tombstoneWritten, "Cleanup tombstone must be durable before deletion")
    try require(remover.removed == authorizedBindings, "Only receipt-bound payloads may be removed")
    try require(
      !remover.removed.map(\.relativePath).contains("legacy/unbound-must-survive.bin"),
      "Legacy queue inventory must never grant deletion authority"
    )
    try require(queue.payloadCleanupState == .payloadsRemoved, "Cleanup must finish durably")
    try require(queue.currentCredentialID == "credential_receiving_resume", "Completion must retain the deletion credential")

    var recovered = persistence.snapshots[0]
    let retryPersistence = MemoryPersistence()
    let retryRemover = MemoryPayloadRemover()
    let recoveredBindings = try recovered.authorizedLocalPayloadBindings()
    try TacuaTransportCleanup.removeAuthorizedPayloads(
      queue: &recovered, persistence: retryPersistence, remover: retryRemover
    )
    try require(retryRemover.removed == recoveredBindings, "A tombstoned crash must resume idempotent removal")
  }

  private static func deletionAloneAuthorizesCredentialRemoval(_ root: URL) throws {
    var queue = try fixtureQueue(
      root,
      requestName: "deletion-request",
      kind: .deletion,
      operationID: "deletion_synthetic",
      responseName: "deletion-tombstone"
    )
    let persistence = MemoryPersistence()
    let credentials = MemoryCredentialStore()
    credentials.values["credential_receiving_resume"] = Data(repeating: 7, count: 32)
    try TacuaTransportCleanup.removeAuthorizedCredential(
      queue: &queue, persistence: persistence, credentialStore: credentials
    )
    try require(persistence.snapshots.first?.credentialCleanupState == .tombstoneWritten, "Credential tombstone must precede Keychain removal")
    try require(credentials.removals == ["credential_receiving_resume"], "Deletion must remove only the bound credential")
    try require(queue.currentCredentialID == nil && queue.credentialCleanupState == .credentialRemoved, "Credential cleanup must finish durably")
    _ = try queue.encoded()
  }

  private static func completionReplaySurvivesAnotherCredentialRotation(_ root: URL) throws {
    var queue = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )
    try queue.applyExchange(
      remoteSessionID: "session_synthetic",
      scopeDigest: "sha256:112e576cdc6e5baac76cd40b0b2f49182e573039e7107a1eaf0605ff99f67f50",
      credentialID: "credential_replay_current",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-21T10:00:00Z",
      previousCredentialID: "credential_receiving_resume",
      capability: .completionReplayOrDeleteOnly,
      issuedAt: "2026-07-21T10:03:00Z",
      clock: TestClock(uptimeMilliseconds: 280_000, bootSessionID: "boot_fixture")
    )
    let response = try canonicalFixture(root, "completion-receipt")
    let request = try canonicalFixture(root, "completion-request")
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      response, forCanonicalRequest: request
    )
    // The immutable B receipt expiry is validated from B's ledger entry, not C's expiry.
    try queue.storeValidatedReceipt(receipt)
    let attempt = try queue.attempt(
      operationID: "completion_synthetic",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 281_000, bootSessionID: "boot_fixture")
    )
    try require(
      attempt.immutableRequestCredentialID == "credential_receiving_resume",
      "Completion replay must preserve credential B in the body"
    )
    try require(
      attempt.transportCredentialID == "credential_replay_current",
      "Completion replay must authenticate with credential C"
    )
  }

  private static func cleanupRejectsUnboundMissingAndAliasedPayloads(_ root: URL) throws {
    let completed = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )

    var missing = completed
    let segmentIndex = missing.operations.firstIndex(where: { $0.kind == .segment })!
    missing.operations[segmentIndex] = replacingBindings(
      missing.operations[segmentIndex], with: nil
    )
    try expectAnyFailure { _ = try missing.authorizedLocalPayloadBindings() }

    var aliased = completed
    let diagnosticIndex = aliased.operations.firstIndex(where: { $0.kind == .diagnostic })!
    let diagnostic = aliased.operations[diagnosticIndex]
    let diagnosticBinding = diagnostic.localPayloadBindings!.first!
    aliased.operations[diagnosticIndex] = replacingBindings(
      diagnostic,
      with: [TacuaLocalPayloadBinding(
        role: diagnosticBinding.role,
        relativePath: "segments/000.mov",
        contentDigest: diagnosticBinding.contentDigest
      )]
    )
    try expectAnyFailure { _ = try aliased.authorizedLocalPayloadBindings() }

    var missingReceipt = completed
    missingReceipt.operations.removeAll(where: { $0.kind == .diagnostic })
    try expectAnyFailure { _ = try missingReceipt.authorizedLocalPayloadBindings() }

    var extra = completed
    let segment = extra.operations[segmentIndex]
    var extraBindings = segment.localPayloadBindings!
    extraBindings.append(TacuaLocalPayloadBinding(
      role: .diagnosticEnvelope,
      relativePath: "arbitrary/unbound.json",
      contentDigest: digestC
    ))
    extra.operations[segmentIndex] = replacingBindings(segment, with: extraBindings)
    try expectAnyFailure { _ = try extra.authorizedLocalPayloadBindings() }
  }

  private static func replacingBindings(
    _ operation: TacuaQueuedOperation,
    with bindings: [TacuaLocalPayloadBinding]?
  ) -> TacuaQueuedOperation {
    TacuaQueuedOperation(
      kind: operation.kind,
      operationID: operation.operationID,
      requestCredentialID: operation.requestCredentialID,
      requestDigest: operation.requestDigest,
      canonicalRequest: operation.canonicalRequest,
      localPayloadPath: operation.localPayloadPath,
      localPayloadBindings: bindings,
      state: operation.state,
      canonicalResponse: operation.canonicalResponse,
      responseDigest: operation.responseDigest,
      responseArtifactDigest: operation.responseArtifactDigest
    )
  }

  private static func canonicalFixture(_ root: URL, _ name: String) throws -> Data {
    let data = try Data(contentsOf: root.appendingPathComponent("\(name).json"))
    return try TacuaCanonicalJSON.data(try TacuaCanonicalJSON.parse(data))
  }

  private static func fixtureQueue(
    _ root: URL,
    requestName: String,
    kind: TacuaQueuedOperationKind,
    operationID: String,
    responseName: String
  ) throws -> TacuaTransportQueueV3 {
    let requestData = try canonicalFixture(root, requestName)
    let requestValue = try TacuaCanonicalJSON.parse(requestData)
    guard case .object(let request) = requestValue,
      let credentialID = request["credential_id"]?.stringValue,
      let sessionID = request["session_id"]?.stringValue,
      let scopeDigest = request["scope_digest"]?.stringValue,
      let requestDigest = request[kind == .segment ? "intent_digest" : "request_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid fixture request") }
    var queue = try TacuaTransportQueueV3(
      localSessionID: "session_local_fixture",
      localPayloadPaths: ["legacy/unbound-must-survive.bin"]
    )
    if kind == .completion {
      try queue.applyExchange(
        remoteSessionID: sessionID,
        scopeDigest: scopeDigest,
        credentialID: "credential_synthetic",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:00:00Z",
        capability: .active,
        issuedAt: "2026-07-21T10:00:00Z",
        clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_fixture")
      )
      try enqueueFixtureUpload(
        root,
        requestName: "segment-upload-intent",
        responseName: "segment-upload-receipt",
        kind: .segment,
        bindings: [
          TacuaLocalPayloadBinding(
            role: .segmentMedia,
            relativePath: "segments/000.mov",
            contentDigest: "sha256:" + String(repeating: "3", count: 64)
          ),
          TacuaLocalPayloadBinding(
            role: .segmentSidecar,
            relativePath: "segments/000.sidecar.json",
            contentDigest: "sha256:" + String(repeating: "4", count: 64)
          ),
        ],
        queue: &queue,
        clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_fixture")
      )
      try queue.applyExchange(
        remoteSessionID: sessionID,
        scopeDigest: scopeDigest,
        credentialID: credentialID,
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:00:00Z",
        previousCredentialID: "credential_synthetic",
        capability: .active,
        issuedAt: "2026-07-21T10:01:00Z",
        clock: TestClock(uptimeMilliseconds: 160_000, bootSessionID: "boot_fixture")
      )
      try enqueueFixtureUpload(
        root,
        requestName: "diagnostic-upload-request",
        responseName: "diagnostic-upload-receipt",
        kind: .diagnostic,
        bindings: [
          TacuaLocalPayloadBinding(
            role: .diagnosticEnvelope,
            relativePath: "diagnostics/events.json",
            contentDigest: "sha256:6f395bf765e73eac49e90ff444ce8965ce31b452a683f26e03e8554497e4efbf"
          )
        ],
        queue: &queue,
        clock: TestClock(uptimeMilliseconds: 163_000, bootSessionID: "boot_fixture")
      )
    } else {
    try queue.applyExchange(
      remoteSessionID: sessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_fixture")
    )
    }
    try queue.enqueueNewOperation(
      kind: kind,
      operationID: operationID,
      requestCredentialID: credentialID,
      request: requestValue,
      requestDigest: requestDigest,
      clock: TestClock(
        uptimeMilliseconds: kind == .completion ? 165_000 : 101_000,
        bootSessionID: "boot_fixture"
      )
    )
    let responseData = try canonicalFixture(root, responseName)
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      responseData,
      forCanonicalRequest: requestData
    )
    try queue.storeValidatedReceipt(receipt)
    return queue
  }

  private static func enqueueFixtureUpload(
    _ root: URL,
    requestName: String,
    responseName: String,
    kind: TacuaQueuedOperationKind,
    bindings: [TacuaLocalPayloadBinding],
    queue: inout TacuaTransportQueueV3,
    clock: TestClock
  ) throws {
    let requestData = try canonicalFixture(root, requestName)
    let requestValue = try TacuaCanonicalJSON.parse(requestData)
    guard let request = requestValue.objectValue,
      let credentialID = request["credential_id"]?.stringValue,
      let operationID = request["upload_id"]?.stringValue,
      let digest = request[kind == .segment ? "intent_digest" : "request_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid fixture upload request") }
    try queue.enqueueNewOperation(
      kind: kind,
      operationID: operationID,
      requestCredentialID: credentialID,
      request: requestValue,
      requestDigest: digest,
      localPayloadBindings: bindings,
      clock: clock
    )
    let responseData = try canonicalFixture(root, responseName)
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      responseData, forCanonicalRequest: requestData
    )
    try queue.storeValidatedReceipt(receipt)
  }
}
