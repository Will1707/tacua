// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum StoreTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw StoreTestFailure.assertion(message) }
}

private func expectFailure(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw StoreTestFailure.assertion("Expected failure")
  } catch is StoreTestFailure {
    throw StoreTestFailure.assertion("Expected failure")
  } catch {
    return
  }
}

private struct StoreClock: TacuaMonotonicClock {
  let uptimeMilliseconds: Int64
  let bootSessionID: String
}

private let storeTransportDigest = "sha256:" + String(repeating: "d", count: 64)

private final class StoreCredentialStore: TacuaCredentialStoring {
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

@main
enum TransportQueueFileStoreTests {
  static func main() throws {
    let temporary = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-queue-store-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let store = try TacuaTransportQueueFileStore(rootDirectory: temporary)
    try atomicallyPersistsAndLoads(store, root: temporary)
    try compareAndSwapRejectsStaleSnapshots(store)
    try rewritesLegacyQueueAfterMigration(store)
    try startupRecoveryDrainsRevokedCredentialJournal(store)
    try payloadRemovalIsStrictlySessionScoped(temporary)
    print("Tacua transport queue file-store tests passed")
  }

  private static func atomicallyPersistsAndLoads(
    _ store: TacuaTransportQueueFileStore,
    root: URL
  ) throws {
    var queue = try TacuaTransportQueueV3(localSessionID: "session_store_001")
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: "sha256:" + String(repeating: "a", count: 64),
      credentialID: "credential_store_001",
      transportConfigurationDigest: storeTransportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: StoreClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_store")
    )
    try store.persistInitial(queue)
    try store.persistInitial(queue)
    var conflicting = try TacuaTransportQueueV3(localSessionID: "session_store_001")
    try conflicting.applyExchange(
      remoteSessionID: "session_remote_conflict",
      scopeDigest: "sha256:" + String(repeating: "b", count: 64),
      credentialID: "credential_store_conflict",
      transportConfigurationDigest: "sha256:" + String(repeating: "c", count: 64),
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: StoreClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_store")
    )
    try expectFailure { try store.persistInitial(conflicting) }
    let loaded = try store.load(localSessionID: "session_store_001")
    try require(loaded == queue, "Atomic queue round-trip must preserve exact state")
    let bytes = try Data(contentsOf: store.queueURL(localSessionID: "session_store_001"))
    let text = String(decoding: bytes, as: UTF8.self).lowercased()
    try require(!text.contains("secret"), "Queue file must never persist secret material")
    let rootMode = ((try FileManager.default.attributesOfItem(atPath: root.path))[
      .posixPermissions
    ] as? NSNumber)?.intValue ?? -1
    let queueMode = ((try FileManager.default.attributesOfItem(
      atPath: store.queueURL(localSessionID: queue.localSessionID).path
    ))[.posixPermissions] as? NSNumber)?.intValue ?? -1
    try require(rootMode & 0o777 == 0o700, "Queue directory permissions are not private")
    try require(queueMode & 0o777 == 0o600, "Queue file permissions are not private")

    try FileManager.default.setAttributes(
      [.posixPermissions: 0o777], ofItemAtPath: root.path
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o666],
      ofItemAtPath: store.queueURL(localSessionID: queue.localSessionID).path
    )
    let repairingStore = try TacuaTransportQueueFileStore(rootDirectory: root)
    _ = try repairingStore.load(localSessionID: queue.localSessionID)
    let repairedRootMode = ((try FileManager.default.attributesOfItem(atPath: root.path))[
      .posixPermissions
    ] as? NSNumber)?.intValue ?? -1
    let repairedQueueMode = ((try FileManager.default.attributesOfItem(
      atPath: repairingStore.queueURL(localSessionID: queue.localSessionID).path
    ))[.posixPermissions] as? NSNumber)?.intValue ?? -1
    try require(repairedRootMode & 0o777 == 0o700, "Existing queue root was not hardened")
    try require(repairedQueueMode & 0o777 == 0o600, "Existing queue file was not hardened")

    let orphan = root.appendingPathComponent(
      ".\(queue.localSessionID).queue-v3.\(String(repeating: "a", count: 32)).tmp"
    )
    try Data("interrupted-write".utf8).write(to: orphan)
    _ = try repairingStore.load(localSessionID: queue.localSessionID)
    try require(
      !FileManager.default.fileExists(atPath: orphan.path),
      "Session-locked queue recovery retained an interrupted temp file"
    )
  }

  private static func compareAndSwapRejectsStaleSnapshots(
    _ store: TacuaTransportQueueFileStore
  ) throws {
    let original = try requireValue(
      store.load(localSessionID: "session_store_001"),
      "CAS fixture queue is missing"
    )
    var replacement = original
    replacement.localPayloadPaths.append("segments/new.mov")
    try replacement.validate()
    try store.compareAndSwap(expected: original, replacement: replacement)
    try store.compareAndSwap(expected: original, replacement: replacement)

    var staleReplacement = original
    staleReplacement.localPayloadPaths.append("segments/stale.mov")
    do {
      try store.compareAndSwap(expected: original, replacement: staleReplacement)
      throw StoreTestFailure.assertion("Stale queue snapshot overwrote newer state")
    } catch let error as TacuaTransportQueueFileStoreError {
      try require(error == .stateConflict, "Stale CAS surfaced the wrong conflict")
    }
    let current = try store.load(localSessionID: original.localSessionID)
    try require(current == replacement, "Failed stale CAS changed the current queue")

    try store.remove(localSessionID: original.localSessionID)
    try store.remove(localSessionID: original.localSessionID)
    let removed = try store.load(localSessionID: original.localSessionID)
    try require(removed == nil, "Idempotent queue removal retained durable state")
  }

  private static func rewritesLegacyQueueAfterMigration(_ store: TacuaTransportQueueFileStore) throws {
    let legacy = Data(#"{"schemaVersion":1,"localSessionId":"session_legacy_001","remoteSessionId":"session_remote_001","organizationId":"org_local","projectId":"project_local","buildId":"build_local","grantIdentifier":"grant_old","grantExpiresAt":"2027-01-01T00:00:00Z","items":[{"objectId":"segment_001","objectKind":"segment","segmentIndex":0,"contentDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","byteLength":42,"state":"queued","attemptCount":0,"nextAttemptAt":null,"lastErrorCode":null,"receipt":null}]}"#.utf8)
    let url = try store.queueURL(localSessionID: "session_legacy_001")
    try legacy.write(to: url, options: .atomic)
    let migrated = try store.load(localSessionID: "session_legacy_001")
    try require(migrated?.schemaVersion == 3, "Store load must migrate queue v1 to v3")
    try require(migrated?.credentialCapability == .requiresExchange, "Migration must discard legacy authority")
    let rewritten = try Data(contentsOf: url)
    let object = try JSONSerialization.jsonObject(with: rewritten) as? [String: Any]
    try require(object?["schemaVersion"] as? Int == 3, "Migration must be persisted atomically")
  }

  private static func payloadRemovalIsStrictlySessionScoped(_ root: URL) throws {
    let session = root.appendingPathComponent("capture", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
    let payload = session.appendingPathComponent("segment.mov")
    let payloadData = Data("payload".utf8)
    try payloadData.write(to: payload)
    let remover = try TacuaScopedPayloadRemover(sessionDirectory: session)
    let binding = TacuaLocalPayloadBinding(
      role: .segmentMedia,
      relativePath: "segment.mov",
      contentDigest: TacuaCanonicalJSON.digest(data: payloadData)
    )
    try remover.removePayload(binding)
    try require(!FileManager.default.fileExists(atPath: payload.path), "Authorized payload file must be removed")
    try remover.removePayload(binding)
    try expectFailure {
      try remover.removePayload(TacuaLocalPayloadBinding(
        role: .segmentMedia,
        relativePath: "../outside",
        contentDigest: binding.contentDigest
      ))
    }

    let directory = session.appendingPathComponent("nested", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try expectFailure {
      try remover.removePayload(TacuaLocalPayloadBinding(
        role: .segmentMedia,
        relativePath: "nested",
        contentDigest: binding.contentDigest
      ))
    }

    let wrongDigestFile = session.appendingPathComponent("wrong.mov")
    try payloadData.write(to: wrongDigestFile)
    try expectFailure {
      try remover.removePayload(TacuaLocalPayloadBinding(
        role: .segmentMedia,
        relativePath: "wrong.mov",
        contentDigest: "sha256:" + String(repeating: "0", count: 64)
      ))
    }
    try require(
      FileManager.default.fileExists(atPath: wrongDigestFile.path),
      "A digest mismatch must preserve the file"
    )

    let symlink = session.appendingPathComponent("alias.mov")
    try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: wrongDigestFile)
    try expectFailure {
      try remover.removePayload(TacuaLocalPayloadBinding(
        role: .segmentMedia,
        relativePath: "alias.mov",
        contentDigest: binding.contentDigest
      ))
    }
    try require(
      FileManager.default.fileExists(atPath: wrongDigestFile.path),
      "A symlink must never redirect cleanup"
    )
    let hardlink = session.appendingPathComponent("hardlink.mov")
    try FileManager.default.linkItem(at: wrongDigestFile, to: hardlink)
    try expectFailure {
      try remover.removePayload(TacuaLocalPayloadBinding(
        role: .segmentMedia,
        relativePath: "hardlink.mov",
        contentDigest: binding.contentDigest
      ))
    }
  }

  private static func startupRecoveryDrainsRevokedCredentialJournal(
    _ store: TacuaTransportQueueFileStore
  ) throws {
    var queue = try TacuaTransportQueueV3(localSessionID: "session_recovery_001")
    let scope = "sha256:" + String(repeating: "a", count: 64)
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: scope,
      credentialID: "credential_old",
      transportConfigurationDigest: storeTransportDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: StoreClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_recovery")
    )
    try queue.applyExchange(
      remoteSessionID: "session_remote_001",
      scopeDigest: scope,
      credentialID: "credential_new",
      transportConfigurationDigest: storeTransportDigest,
      expiresAt: "2026-08-20T11:00:00Z",
      previousCredentialID: "credential_old",
      capability: .active,
      issuedAt: "2026-07-21T10:01:00Z",
      clock: StoreClock(uptimeMilliseconds: 160_000, bootSessionID: "boot_recovery")
    )
    try store.persist(queue)
    let credentials = StoreCredentialStore()
    credentials.values["credential_old"] = Data(repeating: 1, count: 32)
    credentials.values["credential_new"] = Data(repeating: 2, count: 32)
    let recovered = try store.recoverCredentialCleanup(
      localSessionID: queue.localSessionID,
      credentialStore: credentials
    )
    try require(
      recovered?.pendingRevokedCredentialRemovals.isEmpty == true,
      "Startup recovery must durably drain the revocation journal"
    )
    try require(credentials.removals == ["credential_old"], "Recovery must remove only A")
    try require(credentials.values["credential_new"] != nil, "Recovery must retain current B")
  }

  private static func requireValue<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw StoreTestFailure.assertion(message) }
    return value
  }
}
