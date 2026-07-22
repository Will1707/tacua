// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum QueueTestFailure: Error { case assertion(String) }
private enum InjectedRemovalError: Error { case failed }

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
  var failAtRemoval: Int?
  func removePayload(_ binding: TacuaLocalPayloadBinding) throws {
    if failAtRemoval == removed.count { throw InjectedRemovalError.failed }
    removed.append(binding)
  }
}

private final class MemorySessionRetirer: TacuaLocalSessionRetiring {
  var callCount = 0
  var shouldFail = false
  func retireSession() throws {
    callCount += 1
    if shouldFail { throw InjectedRemovalError.failed }
  }
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
    try migrationFromV3DistrustsPreparedDispatchClaims()
    try migrationFromV2DropsUnavailableBootAnchor()
    try migrationFromV2BackfillsStoredResponseArtifactDigest(fixtureRoot)
    try migrationFromV2PreservesFullyCleanedDeletion(fixtureRoot)
    try durableSessionArtifactBindingIsClosed(fixtureRoot)
    try queueNeverPersistsSecretsOrLaunchCodes()
    try strictIdentifierAndSensitiveKeyBounds()
    try persistedDecodeBoundsCollectionsAndStrings()
    try timeAnchorSurvivesRestartAndRejectsReboot()
    try expiredCredentialsRequireResumeAtHalfOpenBoundary()
    try exactRetryKeepsHistoricalBodyCredentialAfterRotation()
    try exactReplayReceiptReanchorsAfterReboot(fixtureRoot)
    try exactSegmentReceiptOlderThanResumeAnchorStillCommits(fixtureRoot)
    try completedResumeAuthorizesOnlyExactUnknownCompletion(fixtureRoot)
    try credentialRotationRebindsOnlyKnownOrProvenUnsentRequests(fixtureRoot)
    try recoveredReceivingResumePreservesImmutableQueue()
    try recoveredResumeRejectsAuthoritativeTimeRegression()
    try recoveredCompletedResumeRequiresExactAuthority(fixtureRoot)
    try recoveredResumeRejectsStaleAndConflictingBindings()
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
    try require(queue.schemaVersion == 4, "Migration must emit queue schema v4")
    try require(queue.credentialCapability == .requiresExchange, "A legacy grant is not a V1 credential")
    try require(queue.currentCredentialID == nil && queue.remoteSessionID == nil, "Legacy remote authority must be discarded")
    try require(queue.localPayloadPaths == ["legacy/segment_001"], "Local payload inventory must survive migration")
  }

  private static func durableSessionArtifactBindingIsClosed(_ fixtureRoot: URL) throws {
    let buildData = try Data(
      contentsOf: fixtureRoot.appendingPathComponent("build-identity.json")
    )
    let scopeData = try Data(
      contentsOf: fixtureRoot.appendingPathComponent("capture-scope.json")
    )
    let artifacts = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: buildData,
      scopeJSON: scopeData
    )
    var queue = try TacuaTransportQueueV3(localSessionID: "session_artifacts_001")
    try queue.applyRecoveredStart(
      remoteSessionID: "session_remote_artifacts_001",
      scopeDigest: artifacts.scopeDigest,
      credentialID: "credential_artifacts_001",
      transportConfigurationDigest: artifacts.transportConfigurationDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      timeAnchor: try TacuaServerTimeAnchor.establish(
        issuedAt: "2026-07-21T10:00:00Z",
        clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_artifacts_001")
      ),
      sessionArtifacts: artifacts
    )
    let roundTrip = try TacuaTransportQueueV3.decodeOrMigrate(queue.encoded())
    let roundTripArtifacts = try requireValue(
      roundTrip.durableSessionArtifacts(),
      "Queue round-trip lost durable session artifacts"
    )
    try require(
      roundTripArtifacts == artifacts,
      "Queue round-trip changed canonical session artifacts"
    )
    let persisted = String(decoding: try queue.encoded(), as: UTF8.self).lowercased()
    try require(
      !persisted.contains("launch_code") && !persisted.contains("\"secret\""),
      "Public session-artifact retention persisted transient authority"
    )

    guard var legacyObject = try JSONSerialization.jsonObject(
      with: queue.encoded()
    ) as? [String: Any] else {
      throw QueueTestFailure.assertion("Could not construct artifact migration fixture")
    }
    legacyObject["schemaVersion"] = 3
    legacyObject.removeValue(forKey: "buildIdentityJSON")
    legacyObject.removeValue(forKey: "captureScopeJSON")
    let legacyData = try JSONSerialization.data(
      withJSONObject: legacyObject,
      options: [.sortedKeys]
    )
    var migrated = try TacuaTransportQueueV3.decodeOrMigrate(legacyData)
    try require(
      !migrated.hasDurableSessionArtifacts,
      "Legacy queue migration invented build/scope artifacts"
    )
    try migrated.bindDurableSessionArtifacts(artifacts)
    try migrated.bindDurableSessionArtifacts(artifacts)
    try require(
      migrated.hasDurableSessionArtifacts,
      "Exact artifact backfill was not idempotent"
    )

    guard case .object(var changedScope) = artifacts.scope,
      case .object(var consent)? = changedScope["consent"]
    else { throw QueueTestFailure.assertion("Scope fixture is malformed") }
    consent["granted_at"] = .string("2026-07-21T09:58:00Z")
    changedScope["consent"] = .object(consent)
    changedScope["scope_digest"] = .string(
      try TacuaCanonicalJSON.digest(
        .object(changedScope),
        omittingRootField: "scope_digest"
      )
    )
    let substituted = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: artifacts.buildIdentityJSON,
      scopeJSON: TacuaCanonicalJSON.data(.object(changedScope))
    )
    try expectQueueError(.operationConflict) {
      try migrated.bindDurableSessionArtifacts(substituted)
    }
    let retainedArtifacts = try migrated.durableSessionArtifacts()
    try require(
      retainedArtifacts == artifacts,
      "Rejected artifact substitution partially mutated the queue"
    )

    guard var tampered = try JSONSerialization.jsonObject(
      with: queue.encoded()
    ) as? [String: Any] else {
      throw QueueTestFailure.assertion("Could not construct artifact tamper fixture")
    }
    tampered["captureScopeJSON"] = "{}"
    try expectAnyFailure {
      _ = try TacuaTransportQueueV3.decodeOrMigrate(
        JSONSerialization.data(withJSONObject: tampered, options: [.sortedKeys])
      )
    }
    tampered["captureScopeJSON"] = NSNull()
    try expectAnyFailure {
      _ = try TacuaTransportQueueV3.decodeOrMigrate(
        JSONSerialization.data(withJSONObject: tampered, options: [.sortedKeys])
      )
    }
    tampered["captureScopeJSON"] = String(decoding: artifacts.scopeJSON, as: UTF8.self)
    tampered["buildIdentityJSON"] = String(
      repeating: "x",
      count: TacuaDurableSessionArtifacts.maximumArtifactBytes + 1
    )
    try expectAnyFailure {
      _ = try TacuaTransportQueueV3.decodeOrMigrate(
        JSONSerialization.data(withJSONObject: tampered, options: [.sortedKeys])
      )
    }
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
    try require(migrated.schemaVersion == 4, "V2 migration must emit queue schema v4")
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
      _ = try migrated.outcomeUnknownAttempt(
        operationID: "upload_migrated_001",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 102_000, bootSessionID: "boot_001")
      )
    }

    let recoveredAnchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:05:00Z",
      clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_001")
    )
    try migrated.applyRecoveredResume(
      expectedCurrentCredentialID: "credential_first",
      newCredentialID: "credential_rebound",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T11:00:00Z",
      capability: .active,
      replayCompletionID: nil,
      timeAnchor: recoveredAnchor
    )
    try require(
      migrated.transportConfigurationDigest == transportDigest
        && migrated.timeAnchor == recoveredAnchor,
      "A recovered V2 resume must bind the current transport and preserve its exact anchor"
    )
    let attempt = try migrated.outcomeUnknownAttempt(
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

  private static func migrationFromV3DistrustsPreparedDispatchClaims() throws {
    var source = try makeActiveQueue()
    try enqueue(
      .diagnostic,
      id: "upload_migrated_prepared",
      credentialID: "credential_first",
      queue: &source
    )
    try enqueue(
      .diagnostic,
      id: "upload_migrated_unknown",
      credentialID: "credential_first",
      queue: &source
    )
    _ = try source.beginAttempt(
      operationID: "upload_migrated_unknown",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 102_000, bootSessionID: "boot_001")
    )
    let v4RoundTrip = try TacuaTransportQueueV3.decodeOrMigrate(source.encoded())
    try require(
      v4RoundTrip.operations.first(where: { $0.operationID == "upload_migrated_prepared" })?
        .state == .prepared,
      "Queue v4 must preserve a durably journaled prepared claim"
    )

    guard var v3Object = try JSONSerialization.jsonObject(
      with: source.encoded()
    ) as? [String: Any] else {
      throw QueueTestFailure.assertion("Could not construct a queue-v3 migration fixture")
    }
    v3Object["schemaVersion"] = 3
    let v3 = try JSONSerialization.data(withJSONObject: v3Object, options: [.sortedKeys])
    let migrated = try TacuaTransportQueueV3.decodeOrMigrate(v3)
    try require(migrated.schemaVersion == 4, "V3 migration must emit queue schema v4")
    try require(
      migrated.operations.allSatisfy({ $0.state == .outcomeUnknown }),
      "V3 had no pre-network journal and cannot prove any operation was unsent"
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
    try require(cleanupPending.schemaVersion == 4, "Cleanup-pending V2 deletion did not migrate")
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
      _ = try cleanupPending.storedResponseReplayAttempt(
        operationID: "deletion_synthetic",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_fixture")
      )
    }
    let pendingPersistence = MemoryPersistence()
    let pendingCredentials = MemoryCredentialStore()
    pendingCredentials.values["credential_receiving_resume"] = Data(repeating: 7, count: 32)
    try TacuaTransportCleanup.retireAuthorizedSession(
      queue: &cleanupPending,
      persistence: pendingPersistence,
      retirer: MemorySessionRetirer()
    )
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
    // This fixture represents a queue written by a pre-v4 build which had already removed the
    // credential before whole-session retirement became mandatory. Migration must preserve that
    // terminal fact without using the legacy order for any new cleanup.
    cleanedSource.credentialCleanupState = .credentialRemoved
    cleanedSource.currentCredentialID = nil
    cleanedSource.currentCredentialExpiresAt = nil
    let cleaned = try TacuaTransportQueueV3.decodeOrMigrate(v2Bytes(cleanedSource))
    try require(cleaned.schemaVersion == 4, "Credential-removed V2 deletion did not migrate")
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
      _ = try cleaned.storedResponseReplayAttempt(
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
    _ = try queue.beginAttempt(
      operationID: "upload_segment_001",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_001")
    )
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
    let attempt = try queue.outcomeUnknownAttempt(
      operationID: "upload_segment_001",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_001")
    )
    try require(attempt.immutableRequestCredentialID == "credential_first", "Rotation must not rewrite protocol truth")
    try require(attempt.transportCredentialID == "credential_second", "Exact recovery authenticates with the current credential")
    let body = try TacuaCanonicalJSON.parse(attempt.canonicalRequest)
    try require(body.objectValue?["credential_id"]?.stringValue == "credential_first", "Historical request bytes must remain exact")
  }

  private static func exactReplayReceiptReanchorsAfterReboot(_ root: URL) throws {
    let requestData = try canonicalFixture(root, "segment-upload-intent")
    let responseData = try canonicalFixture(root, "segment-upload-receipt")
    let requestValue = try TacuaCanonicalJSON.parse(requestData)
    guard let request = requestValue.objectValue,
      let sessionID = request["session_id"]?.stringValue,
      let scopeDigest = request["scope_digest"]?.stringValue,
      let credentialID = request["credential_id"]?.stringValue,
      let operationID = request["upload_id"]?.stringValue,
      let requestDigest = request["intent_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid segment fixture") }
    var queue = try TacuaTransportQueueV3(localSessionID: "session_reboot_replay")
    try queue.applyExchange(
      remoteSessionID: sessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_before_replay")
    )
    try queue.enqueueNewOperation(
      kind: .segment,
      operationID: operationID,
      requestCredentialID: credentialID,
      request: requestValue,
      requestDigest: requestDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_before_replay")
    )
    _ = try queue.beginAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_before_replay")
    )
    queue = try TacuaTransportQueueV3.decodeOrMigrate(queue.encoded())
    let rebootClock = TestClock(uptimeMilliseconds: 5_000, bootSessionID: "boot_after_replay")
    _ = try queue.outcomeUnknownAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: rebootClock
    )
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      responseData,
      forCanonicalRequest: requestData
    )
    try queue.storeValidatedReceipt(receipt)
    try queue.observeAuthoritativeReceiptTimestamp(receipt.authoritativeTimestamp, clock: rebootClock)
    try queue.validate()
    try require(
      queue.timeAnchor?.bootSessionID == rebootClock.bootSessionID
        && queue.timeAnchor?.minimumEpochMilliseconds
          == TacuaProtocolTimestamp.parseMilliseconds(receipt.authoritativeTimestamp),
      "A validated exact-replay receipt must safely establish the current boot anchor"
    )
    try require(
      queue.operations.first(where: { $0.operationID == operationID })?.state == .responseStored,
      "The exact-replay receipt must become durable after reboot"
    )
    let establishedAnchor = queue.timeAnchor
    try queue.observeAuthoritativeReceiptTimestamp(
      "2026-07-21T09:59:59Z",
      clock: rebootClock
    )
    try require(
      queue.timeAnchor == establishedAnchor,
      "An older exact receipt must not rewind an established time anchor"
    )
  }

  private static func exactSegmentReceiptOlderThanResumeAnchorStillCommits(
    _ root: URL
  ) throws {
    let requestData = try canonicalFixture(root, "segment-upload-intent")
    let responseData = try canonicalFixture(root, "segment-upload-receipt")
    let requestValue = try TacuaCanonicalJSON.parse(requestData)
    guard let request = requestValue.objectValue,
      let sessionID = request["session_id"]?.stringValue,
      let scopeDigest = request["scope_digest"]?.stringValue,
      let credentialID = request["credential_id"]?.stringValue,
      let operationID = request["upload_id"]?.stringValue,
      let requestDigest = request["intent_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid segment fixture") }
    var queue = try TacuaTransportQueueV3(localSessionID: "session_segment_post_resume")
    try queue.applyExchange(
      remoteSessionID: sessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_segment_old")
    )
    try queue.enqueueNewOperation(
      kind: .segment,
      operationID: operationID,
      requestCredentialID: credentialID,
      request: requestValue,
      requestDigest: requestDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_segment_old")
    )
    _ = try queue.beginAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_segment_old")
    )
    let resumeAnchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:10:00Z",
      clock: TestClock(uptimeMilliseconds: 10_000, bootSessionID: "boot_segment_new")
    )
    try queue.applyRecoveredResume(
      expectedCurrentCredentialID: credentialID,
      newCredentialID: "credential_segment_resumed",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:10:00Z",
      capability: .active,
      replayCompletionID: nil,
      timeAnchor: resumeAnchor
    )
    _ = try queue.outcomeUnknownAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 11_000, bootSessionID: "boot_segment_new")
    )
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      responseData,
      forCanonicalRequest: requestData
    )
    try queue.storeValidatedReceipt(receipt)
    try queue.observeAuthoritativeReceiptTimestamp(
      receipt.authoritativeTimestamp,
      clock: TestClock(uptimeMilliseconds: 11_000, bootSessionID: "boot_segment_new")
    )
    try require(queue.timeAnchor == resumeAnchor, "An old segment receipt rewound RESUME time")
    try require(
      queue.operations.first(where: { $0.operationID == operationID })?.state == .responseStored,
      "An old exact segment receipt did not commit after RESUME"
    )
  }

  private static func completedResumeAuthorizesOnlyExactUnknownCompletion(
    _ root: URL
  ) throws {
    let segmentRequest = try canonicalFixture(root, "segment-upload-intent")
    let segmentRoot = try TacuaCanonicalJSON.parse(segmentRequest).objectValue
    guard let sessionID = segmentRoot?["session_id"]?.stringValue,
      let scopeDigest = segmentRoot?["scope_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid segment fixture") }
    var preparedQueue = try TacuaTransportQueueV3(localSessionID: "session_completion_replay")
    try preparedQueue.applyExchange(
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
      queue: &preparedQueue,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_fixture")
    )
    try preparedQueue.applyExchange(
      remoteSessionID: sessionID,
      scopeDigest: scopeDigest,
      credentialID: "credential_receiving_resume",
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
      queue: &preparedQueue,
      clock: TestClock(uptimeMilliseconds: 163_000, bootSessionID: "boot_fixture")
    )
    let completionRequest = try canonicalFixture(root, "completion-request")
    let completionValue = try TacuaCanonicalJSON.parse(completionRequest)
    guard let completionRoot = completionValue.objectValue,
      let completionID = completionRoot["completion_id"]?.stringValue,
      let completionCredential = completionRoot["credential_id"]?.stringValue,
      let completionDigest = completionRoot["request_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid completion fixture") }
    try preparedQueue.enqueueNewOperation(
      kind: .completion,
      operationID: completionID,
      requestCredentialID: completionCredential,
      request: completionValue,
      requestDigest: completionDigest,
      clock: TestClock(uptimeMilliseconds: 165_000, bootSessionID: "boot_fixture")
    )
    let completedAnchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:10:00Z",
      clock: TestClock(uptimeMilliseconds: 10_000, bootSessionID: "boot_completed")
    )
    try expectQueueError(.cleanupNotAuthorized) {
      var candidate = preparedQueue
      try candidate.applyRecoveredResume(
        expectedCurrentCredentialID: completionCredential,
        newCredentialID: "credential_completed_prepared",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:10:00Z",
        capability: .completionReplayOrDeleteOnly,
        replayCompletionID: completionID,
        timeAnchor: completedAnchor
      )
    }

    var queue = preparedQueue
    _ = try queue.beginAttempt(
      operationID: completionID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 165_000, bootSessionID: "boot_fixture")
    )
    try expectQueueError(.cleanupNotAuthorized) {
      var candidate = queue
      try candidate.applyRecoveredResume(
        expectedCurrentCredentialID: completionCredential,
        newCredentialID: "credential_completed_mismatch",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:10:00Z",
        capability: .completionReplayOrDeleteOnly,
        replayCompletionID: "completion_wrong",
        timeAnchor: completedAnchor
      )
    }
    try expectQueueError(.cleanupNotAuthorized) {
      var candidate = queue
      try enqueue(
        .completion,
        id: "completion_extra",
        credentialID: completionCredential,
        queue: &candidate,
        clock: TestClock(uptimeMilliseconds: 166_000, bootSessionID: "boot_fixture")
      )
      _ = try candidate.beginAttempt(
        operationID: "completion_extra",
        expectedTransportConfigurationDigest: transportDigest,
        clock: TestClock(uptimeMilliseconds: 166_000, bootSessionID: "boot_fixture")
      )
      try candidate.applyRecoveredResume(
        expectedCurrentCredentialID: completionCredential,
        newCredentialID: "credential_completed_multiple",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:10:00Z",
        capability: .completionReplayOrDeleteOnly,
        replayCompletionID: completionID,
        timeAnchor: completedAnchor
      )
    }

    try queue.applyRecoveredResume(
      expectedCurrentCredentialID: completionCredential,
      newCredentialID: "credential_completed_resume",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-20T10:10:00Z",
      capability: .completionReplayOrDeleteOnly,
      replayCompletionID: completionID,
      timeAnchor: completedAnchor
    )
    queue = try TacuaTransportQueueV3.decodeOrMigrate(queue.encoded())
    try require(
      queue.pendingCompletionReplayID == completionID
        && queue.completionCleanupAuthority == nil,
      "Completed RESUME did not durably authorize only the exact pending completion replay"
    )
    let replay = try queue.outcomeUnknownAttempt(
      operationID: completionID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 11_000, bootSessionID: "boot_completed")
    )
    try require(
      replay.canonicalRequest == completionRequest
        && replay.transportCredentialID == "credential_completed_resume",
      "Completed RESUME did not return the exact historical completion body"
    )
    let completionReceiptData = try canonicalFixture(root, "completion-receipt")
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      completionReceiptData,
      forCanonicalRequest: completionRequest
    )
    try queue.storeValidatedReceipt(receipt)
    try queue.observeAuthoritativeReceiptTimestamp(
      receipt.authoritativeTimestamp,
      clock: TestClock(uptimeMilliseconds: 11_000, bootSessionID: "boot_completed")
    )
    try require(queue.timeAnchor == completedAnchor, "Old completion receipt rewound RESUME time")
    try require(
      queue.pendingCompletionReplayID == nil
        && queue.completionCleanupAuthority?.completionID == completionID,
      "Validated replay receipt did not replace pending replay authority with cleanup authority"
    )
  }

  private static func credentialRotationRebindsOnlyKnownOrProvenUnsentRequests(
    _ root: URL
  ) throws {
    let requestData = try canonicalFixture(root, "segment-upload-intent")
    let requestValue = try TacuaCanonicalJSON.parse(requestData)
    guard let request = requestValue.objectValue,
      let sessionID = request["session_id"]?.stringValue,
      let scopeDigest = request["scope_digest"]?.stringValue,
      let credentialID = request["credential_id"]?.stringValue,
      let operationID = request["upload_id"]?.stringValue,
      let requestDigest = request["intent_digest"]?.stringValue
    else { throw QueueTestFailure.assertion("Invalid segment fixture") }

    func queueWithPreparedOperation() throws -> TacuaTransportQueueV3 {
      var queue = try TacuaTransportQueueV3(localSessionID: "session_rebind_001")
      try queue.applyExchange(
        remoteSessionID: sessionID,
        scopeDigest: scopeDigest,
        credentialID: credentialID,
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-20T10:00:00Z",
        capability: .active,
        issuedAt: "2026-07-21T10:00:00Z",
        clock: TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_rebind")
      )
      try queue.enqueueNewOperation(
        kind: .segment,
        operationID: operationID,
        requestCredentialID: credentialID,
        request: requestValue,
        requestDigest: requestDigest,
        clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_rebind")
      )
      return queue
    }

    func rotate(_ queue: inout TacuaTransportQueueV3) throws {
      try queue.applyExchange(
        remoteSessionID: sessionID,
        scopeDigest: scopeDigest,
        credentialID: "credential_rebound",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:00:00Z",
        previousCredentialID: credentialID,
        capability: .active,
        issuedAt: "2026-07-21T10:05:00Z",
        clock: TestClock(uptimeMilliseconds: 400_000, bootSessionID: "boot_rebind")
      )
    }

    func replacement(
      mutating mutation: ((inout [String: TacuaJSONValue]) -> Void)? = nil
    ) throws -> TacuaPreparedBackendRequest {
      var object = request
      object["credential_id"] = .string("credential_rebound")
      object["requested_at"] = .string("2026-07-21T10:05:01Z")
      object.removeValue(forKey: "intent_digest")
      mutation?(&object)
      let digest = try TacuaCanonicalJSON.digest(.object(object))
      object["intent_digest"] = .string(digest)
      return TacuaPreparedBackendRequest(
        kind: .segment,
        operationID: operationID,
        credentialID: "credential_rebound",
        canonicalData: try TacuaCanonicalJSON.data(.object(object)),
        requestDigest: digest
      )
    }

    var knownUnsent = try queueWithPreparedOperation()
    try rotate(&knownUnsent)
    try knownUnsent.rebindPreparedOperation(
      operationID: operationID,
      replacement: replacement(),
      clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_rebind")
    )
    try require(
      knownUnsent.operations[0].state == .prepared
        && knownUnsent.operations[0].requestCredentialID == "credential_rebound",
      "A durably unsent request did not rebind to the rotated credential"
    )

    var unknown = try queueWithPreparedOperation()
    _ = try unknown.beginAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_rebind")
    )
    try rotate(&unknown)
    let proof = TacuaValidatedBackendError(
      statusCode: 403,
      code: .operationNotAuthorized,
      reconciliationOutcome: .historicalOperationNotFound,
      operationKind: .segment,
      remoteSessionID: sessionID,
      operationID: operationID,
      requestDigest: requestDigest,
      requestCredentialID: credentialID,
      authenticatedCredentialID: "credential_rebound"
    )
    let baseline = unknown
    let mismatchedProof = TacuaValidatedBackendError(
      statusCode: proof.statusCode,
      code: proof.code,
      reconciliationOutcome: proof.reconciliationOutcome,
      operationKind: proof.operationKind,
      remoteSessionID: proof.remoteSessionID,
      operationID: proof.operationID,
      requestDigest: digestB,
      requestCredentialID: proof.requestCredentialID,
      authenticatedCredentialID: proof.authenticatedCredentialID
    )
    try expectQueueError(.operationConflict) {
      try unknown.rebindProvenMissingHistoricalOperation(
        operationID: operationID,
        replacement: replacement(),
        proof: mismatchedProof,
        clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_rebind")
      )
    }
    try require(unknown == baseline, "A mismatched backend proof rewrote an unknown request")
    try expectQueueError(.operationConflict) {
      try unknown.rebindProvenMissingHistoricalOperation(
        operationID: operationID,
        replacement: replacement(mutating: {
          $0["segment_id"] = .string("segment_other")
        }),
        proof: proof,
        clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_rebind")
      )
    }
    try require(unknown == baseline, "A semantic request change bypassed reconciliation")
    try unknown.rebindProvenMissingHistoricalOperation(
      operationID: operationID,
      replacement: replacement(),
      proof: proof,
      clock: TestClock(uptimeMilliseconds: 401_000, bootSessionID: "boot_rebind")
    )
    try require(
      unknown.operations[0].state == .prepared
        && unknown.operations[0].requestCredentialID == "credential_rebound",
      "A request-bound historical miss did not permit safe rebinding"
    )
  }

  private static func recoveredReceivingResumePreservesImmutableQueue() throws {
    var queue = try makeActiveQueue()
    queue.sessionRetentionAuthority = TacuaSessionRetentionAuthority(
      sessionReceivedAt: "2026-07-21T10:00:00Z",
      rawMediaExpiresAt: "2026-08-20T10:00:00Z",
      derivedDataExpiresAt: "2027-07-21T10:00:00Z"
    )
    try enqueue(
      .diagnostic,
      id: "upload_resume_immutable",
      credentialID: "credential_first",
      queue: &queue
    )
    _ = try queue.beginAttempt(
      operationID: "upload_resume_immutable",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 101_000, bootSessionID: "boot_001")
    )
    let originalOperations = queue.operations
    let originalPayloadPaths = queue.localPayloadPaths
    let originalRetentionAuthority = queue.sessionRetentionAuthority
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:06:00Z",
      clock: TestClock(uptimeMilliseconds: 460_000, bootSessionID: "boot_resume")
    )

    try queue.applyRecoveredResume(
      expectedCurrentCredentialID: "credential_first",
      newCredentialID: "credential_recovered",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-21T10:06:00Z",
      capability: .active,
      replayCompletionID: nil,
      timeAnchor: anchor
    )

    try require(queue.currentCredentialID == "credential_recovered", "Recovered resume did not install the validated credential")
    try require(queue.credentialCapability == .active, "Receiving resume did not preserve active authority")
    try require(queue.timeAnchor == anchor, "Recovery re-anchored the persisted server-time receipt")
    try require(queue.operations == originalOperations, "Resume rewrote immutable queued operations")
    try require(queue.localPayloadPaths == originalPayloadPaths, "Resume rewrote local payload inventory")
    try require(
      queue.sessionRetentionAuthority == originalRetentionAuthority,
      "Resume moved the immutable START retention deadlines"
    )
    try require(
      queue.pendingRevokedCredentialRemovals == ["credential_first"],
      "Resume did not durably journal the revoked credential"
    )

    let recovered = try TacuaTransportQueueV3.decodeOrMigrate(queue.encoded())
    try require(
      recovered.pendingRevokedCredentialRemovals == ["credential_first"]
        && recovered.timeAnchor == anchor,
      "Encoded recovery lost credential cleanup or anchor state"
    )
    let attempt = try recovered.outcomeUnknownAttempt(
      operationID: "upload_resume_immutable",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(uptimeMilliseconds: 461_000, bootSessionID: "boot_resume")
    )
    try require(
      attempt.immutableRequestCredentialID == "credential_first"
        && attempt.transportCredentialID == "credential_recovered",
      "Recovered resume did not separate immutable request authority from current transport"
    )
    try require(
      attempt.canonicalRequest == originalOperations[0].canonicalRequest,
      "Recovered resume changed canonical request bytes"
    )
  }

  private static func recoveredResumeRejectsAuthoritativeTimeRegression() throws {
    var queue = try makeActiveQueue()
    try queue.advanceTimeAnchor(
      authoritativeServerTimestamp: "2026-07-21T10:10:00Z",
      clock: TestClock(uptimeMilliseconds: 200_000, bootSessionID: "boot_001")
    )
    let baseline = queue
    let regressed = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:09:59Z",
      clock: TestClock(uptimeMilliseconds: 1_000, bootSessionID: "boot_resume_new")
    )
    try expectQueueError(.invalidTimeAnchor) {
      try queue.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_first",
        newCredentialID: "credential_regressed",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:09:59Z",
        capability: .active,
        replayCompletionID: nil,
        timeAnchor: regressed
      )
    }
    try require(queue == baseline, "Rejected time regression mutated the durable queue")
  }

  private static func recoveredCompletedResumeRequiresExactAuthority(_ root: URL) throws {
    let completed = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )
    let originalOperations = completed.operations
    let originalAuthority = try requireValue(
      completed.completionCleanupAuthority,
      "Completed fixture did not establish cleanup authority"
    )
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:03:00Z",
      clock: TestClock(uptimeMilliseconds: 280_000, bootSessionID: "boot_completed_resume")
    )

    var wrongCompletion = completed
    try expectQueueError(.cleanupNotAuthorized) {
      try wrongCompletion.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_receiving_resume",
        newCredentialID: "credential_wrong_completion",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:03:00Z",
        capability: .completionReplayOrDeleteOnly,
        replayCompletionID: "completion_other",
        timeAnchor: anchor
      )
    }
    try require(wrongCompletion == completed, "Rejected completion binding mutated the queue")

    var uploadReenabled = completed
    try expectQueueError(.operationNotAllowed) {
      try uploadReenabled.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_receiving_resume",
        newCredentialID: "credential_upload_reenabled",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:03:00Z",
        capability: .active,
        replayCompletionID: nil,
        timeAnchor: anchor
      )
    }
    try require(uploadReenabled == completed, "Completed resume restored receiving authority")

    var queue = completed
    try queue.applyRecoveredResume(
      expectedCurrentCredentialID: "credential_receiving_resume",
      newCredentialID: "credential_completed_recovered",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-21T10:03:00Z",
      capability: .completionReplayOrDeleteOnly,
      replayCompletionID: "completion_synthetic",
      timeAnchor: anchor
    )
    try require(
      queue.credentialCapability == .completionReplayOrDeleteOnly,
      "Completed resume restored upload authority"
    )
    try require(
      queue.completionCleanupAuthority == originalAuthority,
      "Completed resume changed exact cleanup authority"
    )
    try require(queue.operations == originalOperations, "Completed resume rewrote durable operations")
    try require(
      queue.pendingRevokedCredentialRemovals.contains("credential_receiving_resume"),
      "Completed resume did not journal its prior credential"
    )
    let attempt = try queue.storedResponseReplayAttempt(
      operationID: "completion_synthetic",
      expectedTransportConfigurationDigest: transportDigest,
      clock: TestClock(
        uptimeMilliseconds: 281_000,
        bootSessionID: "boot_completed_resume"
      )
    )
    try require(
      attempt.immutableRequestCredentialID == "credential_receiving_resume"
        && attempt.transportCredentialID == "credential_completed_recovered",
      "Completed replay did not retain its historical request credential"
    )
    try expectQueueError(.operationNotAllowed) {
      try enqueue(
        .segment,
        id: "upload_after_completed_resume",
        credentialID: "credential_completed_recovered",
        queue: &queue,
        clock: TestClock(
          uptimeMilliseconds: 281_000,
          bootSessionID: "boot_completed_resume"
        )
      )
    }
  }

  private static func recoveredResumeRejectsStaleAndConflictingBindings() throws {
    let queue = try makeActiveQueue()
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:06:00Z",
      clock: TestClock(uptimeMilliseconds: 460_000, bootSessionID: "boot_resume_errors")
    )

    var stale = queue
    try expectQueueError(.credentialMismatch) {
      try stale.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_stale",
        newCredentialID: "credential_new",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:06:00Z",
        capability: .active,
        replayCompletionID: nil,
        timeAnchor: anchor
      )
    }
    try require(stale == queue, "A stale resume baseline mutated the queue")

    var transportChanged = queue
    try expectQueueError(.transportConfigurationMismatch) {
      try transportChanged.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_first",
        newCredentialID: "credential_new",
        transportConfigurationDigest: digestB,
        expiresAt: "2026-08-21T10:06:00Z",
        capability: .active,
        replayCompletionID: nil,
        timeAnchor: anchor
      )
    }
    try require(transportChanged == queue, "A transport-origin change mutated the queue")

    var unprovedCompletion = queue
    try expectQueueError(.cleanupNotAuthorized) {
      try unprovedCompletion.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_first",
        newCredentialID: "credential_new",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:06:00Z",
        capability: .completionReplayOrDeleteOnly,
        replayCompletionID: "completion_unproved",
        timeAnchor: anchor
      )
    }
    try require(unprovedCompletion == queue, "Unproved completion authority mutated the queue")

    var activeWithCompletion = queue
    try expectQueueError(.operationNotAllowed) {
      try activeWithCompletion.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_first",
        newCredentialID: "credential_new",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:06:00Z",
        capability: .active,
        replayCompletionID: "completion_unexpected",
        timeAnchor: anchor
      )
    }
    try require(activeWithCompletion == queue, "An active resume with completion binding mutated the queue")

    var rotated = queue
    try rotated.applyRecoveredResume(
      expectedCurrentCredentialID: "credential_first",
      newCredentialID: "credential_second",
      transportConfigurationDigest: transportDigest,
      expiresAt: "2026-08-21T10:06:00Z",
      capability: .active,
      replayCompletionID: nil,
      timeAnchor: anchor
    )
    let rotatedBaseline = rotated
    let laterAnchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T10:07:00Z",
      clock: TestClock(uptimeMilliseconds: 520_000, bootSessionID: "boot_resume_errors")
    )
    try expectQueueError(.credentialMismatch) {
      try rotated.applyRecoveredResume(
        expectedCurrentCredentialID: "credential_second",
        newCredentialID: "credential_first",
        transportConfigurationDigest: transportDigest,
        expiresAt: "2026-08-21T10:07:00Z",
        capability: .active,
        replayCompletionID: nil,
        timeAnchor: laterAnchor
      )
    }
    try require(rotated == rotatedBaseline, "A reused historical credential mutated the queue")
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
      _ = try queue.beginAttempt(
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
    var syncFailureQueue = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )
    let failurePersistence = MemoryPersistence()
    let failureRetirer = MemorySessionRetirer()
    failureRetirer.shouldFail = true
    try expectAnyFailure {
      try TacuaTransportCleanup.retireAuthorizedSession(
        queue: &syncFailureQueue,
        persistence: failurePersistence,
        retirer: failureRetirer
      )
    }
    try require(
      syncFailureQueue.payloadCleanupState == .tombstoneWritten
        && failurePersistence.snapshots.last?.payloadCleanupState == .tombstoneWritten,
      "A removal/directory-sync failure must never advance the queue to payloadsRemoved"
    )

    var queue = try fixtureQueue(
      root,
      requestName: "completion-request",
      kind: .completion,
      operationID: "completion_synthetic",
      responseName: "completion-receipt"
    )
    let persistence = MemoryPersistence()
    let retirer = MemorySessionRetirer()
    try TacuaTransportCleanup.retireAuthorizedSession(
      queue: &queue, persistence: persistence, retirer: retirer
    )
    try require(persistence.snapshots.first?.payloadCleanupState == .tombstoneWritten, "Cleanup tombstone must be durable before deletion")
    try require(retirer.callCount == 1, "Receipt-authorized session retirement did not run")
    try require(queue.payloadCleanupState == .payloadsRemoved, "Cleanup must finish durably")
    try require(queue.currentCredentialID == "credential_receiving_resume", "Completion must retain the deletion credential")

    var recovered = persistence.snapshots[0]
    let retryPersistence = MemoryPersistence()
    let retryRetirer = MemorySessionRetirer()
    try TacuaTransportCleanup.retireAuthorizedSession(
      queue: &recovered, persistence: retryPersistence, retirer: retryRetirer
    )
    try require(retryRetirer.callCount == 1, "A tombstoned crash must resume retirement")
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
    try TacuaTransportCleanup.retireAuthorizedSession(
      queue: &queue,
      persistence: persistence,
      retirer: MemorySessionRetirer()
    )
    try TacuaTransportCleanup.removeAuthorizedCredential(
      queue: &queue, persistence: persistence, credentialStore: credentials
    )
    try require(
      persistence.snapshots.contains(where: {
        $0.credentialCleanupState == .tombstoneWritten
          && $0.currentCredentialID == "credential_receiving_resume"
      }),
      "Credential tombstone must precede Keychain removal"
    )
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
    let attempt = try queue.storedResponseReplayAttempt(
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
    _ = try queue.beginAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
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
    _ = try queue.beginAttempt(
      operationID: operationID,
      expectedTransportConfigurationDigest: transportDigest,
      clock: clock
    )
    let responseData = try canonicalFixture(root, responseName)
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      responseData, forCanonicalRequest: requestData
    )
    try queue.storeValidatedReceipt(receipt)
  }
}
