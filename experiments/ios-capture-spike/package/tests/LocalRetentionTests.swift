// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

private enum LocalRetentionTestFailure: Error { case assertion(String), injected }

private func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
  if try !condition() { throw LocalRetentionTestFailure.assertion(message) }
}

private func expectCleanupFailure(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw LocalRetentionTestFailure.assertion("Expected retention cleanup failure")
  } catch LocalRetentionTestFailure.assertion {
    throw LocalRetentionTestFailure.assertion("Expected retention cleanup failure")
  } catch TacuaSDKLocalRetentionError.cleanupIncomplete {}
}

private final class RetentionWallClock: TacuaAuthoritativeWallClock {
  var value: Int64
  init(_ value: Int64) { self.value = value }
  func nowMilliseconds() throws -> Int64 { value }
}

private final class RetentionMonotonicClock: TacuaMonotonicClock {
  var uptimeMilliseconds: Int64 = 1_000
  var bootSessionID = "boot_local_retention_tests"
}

private final class RetentionCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  var removals: [String] = []
  var failuresRemaining = 0

  func store(secret: Data, credentialID: String) throws { values[credentialID] = secret }
  func read(credentialID: String) throws -> Data {
    guard let value = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return value
  }
  func remove(credentialID: String) throws {
    if failuresRemaining > 0 {
      failuresRemaining -= 1
      throw LocalRetentionTestFailure.injected
    }
    removals.append(credentialID)
    values.removeValue(forKey: credentialID)
  }
}

private struct AlwaysFailingRetentionRetirer: TacuaLocalSessionRetiring {
  func retireSession() throws { throw LocalRetentionTestFailure.injected }
}

private struct RetentionHarness {
  let root: URL
  let captureRoot: URL
  let queueStore: TacuaTransportQueueFileStore
  let startStore: TacuaSDKStartJournalFileStore
  let resumeStore: TacuaSDKResumeJournalFileStore
  let credentials: RetentionCredentialStore
  let wallClock: RetentionWallClock
  let monotonicClock: RetentionMonotonicClock
  let localSessionID: String
  let credentialID: String
}

@main
enum LocalRetentionTests {
  private static let receivedAt = "2026-07-01T00:00:00Z"
  private static let rawExpiresAt = "2026-07-31T00:00:00Z"
  private static let derivedExpiresAt = "2026-10-01T00:00:00Z"

  static func main() throws {
    try beforeAtAndAfterUseHalfOpenDeadline()
    try relaunchSweepDrainsDiscoveryAndHiddenRetirement()
    try relaunchSweepDiscoversCorruptOrphanResumeJournal()
    try relaunchSweepContinuesAfterPerSessionCleanupFailure()
    try partialSessionRetirementRecoversFromCrashWindow()
    try corruptAndMissingAuthorityRetireFailClosed()
    try serverAnchorDefeatsWallRollbackAndRebootBlocksAccess()
    try conflictingQueueAndJournalAuthoritiesRetireFailClosed()
    try holdingLifecycleLeaseEntryPointDoesNotReacquire()
    try unavailableCleanupBlocksThenRecoversIdempotently()
    try journalsCredentialsPayloadsAndQueueDrainTogether()
    try resumeRotationCannotExtendRawDeadline()
    print("Tacua local retention tests passed")
  }

  private static func beforeAtAndAfterUseHalfOpenDeadline() throws {
    let deadline = try milliseconds(rawExpiresAt)
    let before = try makeHarness("before", now: deadline - 1)
    defer { try? FileManager.default.removeItem(at: before.root) }
    try seedQueueAndCapture(before)
    let beforeResult = try coordinator(before).enforce(localSessionID: before.localSessionID)
    try require(
      beforeResult == .active(
        rawMediaExpiresAt: rawExpiresAt,
        stopUptimeMilliseconds: before.monotonicClock.uptimeMilliseconds + 1
      ),
      "One millisecond before expiry was not active"
    )
    try require(try queueExists(before), "Before-expiry queue was retired")
    try require(captureExists(before), "Before-expiry capture was retired")

    for (suffix, now) in [("at", deadline), ("after", deadline + 1)] {
      let harness = try makeHarness(suffix, now: now)
      defer { try? FileManager.default.removeItem(at: harness.root) }
      try seedQueueAndCapture(harness)
      try require(
        try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .retired,
        "At/after-expiry session was not retired"
      )
      try require(!(try queueExists(harness)), "Expired queue survived")
      try require(!captureExists(harness), "Expired capture tree survived")
      try require(harness.credentials.values.isEmpty, "Expired Keychain authority survived")
    }
  }

  private static func relaunchSweepDrainsDiscoveryAndHiddenRetirement() throws {
    let harness = try makeHarness("relaunch", now: try milliseconds(rawExpiresAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedQueueAndCapture(harness)
    let live = sessionDirectory(harness)
    let hidden = harness.captureRoot.appendingPathComponent(
      ".tacua-retiring-\(harness.localSessionID)",
      isDirectory: true
    )
    try FileManager.default.moveItem(at: live, to: hidden)

    let relaunched = coordinator(harness)
    try require(
      try relaunched.sweep() == [harness.localSessionID],
      "Relaunch sweep did not drain the hidden retirement name"
    )
    let records = try TacuaSDKBackendSessionDiscoveryCoordinator(
      queueStore: harness.queueStore,
      startJournalStore: harness.startStore
    ).list()
    try require(records.isEmpty, "Expired session remained discoverable")
    try require(try relaunched.sweep().isEmpty, "Completed sweep was not idempotent")
  }

  private static func partialSessionRetirementRecoversFromCrashWindow() throws {
    let harness = try makeHarness("rename_crash", now: try milliseconds(rawExpiresAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedQueueAndCapture(harness)
    var syncCalls = 0
    let first = coordinator(harness) { directory in
      try TacuaScopedSessionRetirer(
        sessionDirectory: directory,
        directorySynchronizer: { descriptor in
          syncCalls += 1
          if syncCalls == 1 { return false }
          return fsync(descriptor) == 0
        }
      )
    }
    try expectCleanupFailure {
      _ = try first.enforce(localSessionID: harness.localSessionID)
    }
    try require(try queueExists(harness), "Crash-window cleanup removed its retry journal")
    try require(
      FileManager.default.fileExists(
        atPath: harness.captureRoot.appendingPathComponent(
          ".tacua-retiring-\(harness.localSessionID)"
        ).path
      ),
      "Crash-window cleanup lost the hidden retirement tree"
    )
    try require(
      try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .retired,
      "Relaunch did not finish partial retirement"
    )
  }

  private static func relaunchSweepContinuesAfterPerSessionCleanupFailure() throws {
    let harness = try makeHarness("a_cleanup_failure", now: try milliseconds(rawExpiresAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let laterSessionID = "local_retention_z_cleanup_success"
    let laterCredentialID = "credential_retention_z_cleanup_success"
    try seedQueueAndCapture(harness)
    try seedQueueAndCapture(
      harness,
      localSessionID: laterSessionID,
      credentialID: laterCredentialID
    )
    let retention = coordinator(harness) { directory in
      if directory.lastPathComponent == harness.localSessionID {
        return AlwaysFailingRetentionRetirer()
      }
      return try TacuaScopedSessionRetirer(sessionDirectory: directory)
    }

    try expectCleanupFailure { _ = try retention.sweep() }
    try require(
      try queueExists(harness, localSessionID: harness.localSessionID),
      "Failed session lost its durable cleanup retry journal"
    )
    try require(
      !captureExists(harness, localSessionID: laterSessionID),
      "Earlier cleanup failure starved a later expired capture"
    )
    try require(
      !(try queueExists(harness, localSessionID: laterSessionID)),
      "Earlier cleanup failure starved a later expired queue"
    )
    try require(
      harness.credentials.values[laterCredentialID] == nil,
      "Earlier cleanup failure starved later credential retirement"
    )
  }

  private static func relaunchSweepDiscoversCorruptOrphanResumeJournal() throws {
    let harness = try makeHarness("orphan_resume", now: try milliseconds(receivedAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let resumeURL = try harness.resumeStore.journalURL(
      localSessionID: harness.localSessionID
    )
    try Data("corrupt-orphan-resume".utf8).write(to: resumeURL)

    try require(
      try coordinator(harness).sweep() == [harness.localSessionID],
      "Relaunch sweep did not discover and retire a corrupt orphan RESUME journal"
    )
    try require(
      !FileManager.default.fileExists(atPath: resumeURL.path),
      "Corrupt orphan RESUME journal survived retirement"
    )
  }

  private static func corruptAndMissingAuthorityRetireFailClosed() throws {
    let missing = try makeHarness("missing_authority", now: try milliseconds(receivedAt))
    defer { try? FileManager.default.removeItem(at: missing.root) }
    try seedQueueAndCapture(missing, retentionAuthority: nil)
    try require(
      try coordinator(missing).enforce(localSessionID: missing.localSessionID) == .retired,
      "Missing START retention authority retained raw data"
    )

    let corrupt = try makeHarness("corrupt_queue", now: try milliseconds(receivedAt))
    defer { try? FileManager.default.removeItem(at: corrupt.root) }
    try seedQueueAndCapture(corrupt)
    try Data("not-a-queue".utf8).write(
      to: try corrupt.queueStore.queueURL(localSessionID: corrupt.localSessionID)
    )
    try require(
      try coordinator(corrupt).enforce(localSessionID: corrupt.localSessionID) == .retired,
      "Corrupt queue retained raw data without trustworthy authority"
    )
    try require(!captureExists(corrupt), "Corrupt-queue capture tree survived")
    try require(!(try queueExists(corrupt)), "Corrupt queue bytes survived")
  }

  private static func unavailableCleanupBlocksThenRecoversIdempotently() throws {
    let harness = try makeHarness("unavailable", now: try milliseconds(rawExpiresAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedQueueAndCapture(harness)
    let protected = sessionDirectory(harness).appendingPathComponent("protected.partial")
    try Data("protected".utf8).write(to: protected)
    try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: protected.path)
    harness.credentials.failuresRemaining = 1

    try expectCleanupFailure {
      _ = try coordinator(harness).enforce(localSessionID: harness.localSessionID)
    }
    try require(!captureExists(harness), "Raw files survived while Keychain was unavailable")
    try require(try queueExists(harness), "Unavailable Keychain lost the retry authority")
    try require(
      try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .retired,
      "Retry did not finish cleanup after protected storage became available"
    )
    try require(
      try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .unmanaged,
      "Already-retired session was not idempotent"
    )
  }

  private static func serverAnchorDefeatsWallRollbackAndRebootBlocksAccess() throws {
    let received = try milliseconds(receivedAt)
    let deadline = try milliseconds(rawExpiresAt)
    let rollback = try makeHarness("rollback", now: received - 86_400_000)
    defer { try? FileManager.default.removeItem(at: rollback.root) }
    try seedQueueAndCapture(rollback)
    rollback.monotonicClock.uptimeMilliseconds += deadline - received
    try require(
      try coordinator(rollback).enforce(localSessionID: rollback.localSessionID) == .retired,
      "Wall-clock rollback silently extended the server raw-media deadline"
    )

    let rebootExpired = try makeHarness("reboot_expired", now: deadline + 1)
    defer { try? FileManager.default.removeItem(at: rebootExpired.root) }
    try seedQueueAndCapture(rebootExpired)
    rebootExpired.monotonicClock.bootSessionID = "boot_after_deadline"
    try require(
      try coordinator(rebootExpired).enforce(
        localSessionID: rebootExpired.localSessionID
      ) == .retired,
      "Cross-boot sweep did not delete at a valid wall observation after the deadline"
    )

    let reboot = try makeHarness("reboot_before", now: received + 1_000)
    defer { try? FileManager.default.removeItem(at: reboot.root) }
    try seedQueueAndCapture(reboot)
    reboot.monotonicClock.bootSessionID = "boot_before_deadline"
    do {
      _ = try coordinator(reboot).enforce(localSessionID: reboot.localSessionID)
      throw LocalRetentionTestFailure.assertion("Pre-deadline reboot trusted mutable wall time")
    } catch TacuaSDKLocalRetentionError.authoritativeTimeUnavailable {}
    try require(try queueExists(reboot), "Unreconciled reboot destroyed its server authority")
    try require(captureExists(reboot), "Unreconciled reboot guessed destructive expiry")

    let obviousRollback = try makeHarness("obvious_rollback", now: received - 1)
    defer { try? FileManager.default.removeItem(at: obviousRollback.root) }
    try seedQueueAndCapture(obviousRollback)
    obviousRollback.monotonicClock.bootSessionID = "boot_obvious_rollback"
    do {
      _ = try coordinator(obviousRollback).enforce(
        localSessionID: obviousRollback.localSessionID
      )
      throw LocalRetentionTestFailure.assertion("Persisted server floor did not catch rollback")
    } catch TacuaSDKLocalRetentionError.clockRollbackDetected {}
  }

  private static func conflictingQueueAndJournalAuthoritiesRetireFailClosed() throws {
    let harness = try makeHarness("authority_conflict", now: try milliseconds(receivedAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedQueueAndCapture(harness)
    let startSecret = Data(repeating: 0x55, count: TacuaKeychainCredentialStore.secretLength)
    let startCredential = "credential_authority_conflict"
    harness.credentials.values[startCredential] = startSecret
    let conflictingAuthority = TacuaSessionRetentionAuthority(
      sessionReceivedAt: receivedAt,
      rawMediaExpiresAt: "2026-07-30T00:00:00Z",
      derivedDataExpiresAt: derivedExpiresAt
    )
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: receivedAt,
      clock: harness.monotonicClock
    )
    let journal = try TacuaSDKStartJournal(
      localSessionID: harness.localSessionID,
      exchangeID: "exchange_authority_conflict",
      credentialID: startCredential,
      credentialOwnershipDigest: TacuaCredentialFactory.ownershipDigest(for: startSecret),
      transportConfigurationDigest: "sha256:" + String(repeating: "a", count: 64),
      createdAt: receivedAt,
      state: .receiptValidatedQueueCommitPending,
      validatedReceipt: TacuaSDKStartReceiptRecovery(
        remoteSessionID: "session_retention_remote",
        scopeDigest: "sha256:" + String(repeating: "b", count: 64),
        credentialExpiresAt: "2026-08-01T00:00:00Z",
        timeAnchor: anchor,
        sessionRetentionAuthority: conflictingAuthority
      )
    )
    try harness.startStore.create(journal)

    try require(
      try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .retired,
      "Conflicting queue/START-journal deadlines were silently selected"
    )
    try require(!captureExists(harness), "Authority conflict retained raw data")
    try require(!(try queueExists(harness)), "Authority conflict retained queue artifacts")
  }

  private static func holdingLifecycleLeaseEntryPointDoesNotReacquire() throws {
    let harness = try makeHarness("held_lease", now: try milliseconds(receivedAt) + 1_000)
    defer { try? FileManager.default.removeItem(at: harness.root) }
    try seedQueueAndCapture(harness)
    let lease = try harness.startStore.acquireLifecycleLease(
      localSessionID: harness.localSessionID
    )
    defer { lease.release() }

    try coordinator(harness).requireActiveHoldingLifecycleLease(
      localSessionID: harness.localSessionID
    )
    try require(try queueExists(harness), "Held-lease guard unexpectedly retired active state")
  }

  private static func journalsCredentialsPayloadsAndQueueDrainTogether() throws {
    let harness = try makeHarness("journals", now: try milliseconds(rawExpiresAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    let queue = try seedQueueAndCapture(harness)
    let startCredential = "credential_retention_start"
    let startSecret = Data(repeating: 0x52, count: TacuaKeychainCredentialStore.secretLength)
    harness.credentials.values[startCredential] = startSecret
    let startJournal = try TacuaSDKStartJournal(
      localSessionID: harness.localSessionID,
      exchangeID: "exchange_retention_start",
      credentialID: startCredential,
      credentialOwnershipDigest: TacuaCredentialFactory.ownershipDigest(for: startSecret),
      transportConfigurationDigest: "sha256:" + String(repeating: "a", count: 64),
      createdAt: receivedAt,
      state: .credentialPrepared
    )
    try harness.startStore.create(startJournal)

    let replacementCredential = "credential_retention_replacement"
    let replacementSecret = Data(
      repeating: 0x53,
      count: TacuaKeychainCredentialStore.secretLength
    )
    harness.credentials.values[replacementCredential] = replacementSecret
    let resumeJournal = try TacuaSDKResumeJournal(
      localSessionID: harness.localSessionID,
      baseQueueDigest: TacuaCanonicalJSON.digest(data: try queue.encoded()),
      previousCredentialID: harness.credentialID,
      remoteSessionID: "session_retention_remote",
      scopeDigest: "sha256:" + String(repeating: "b", count: 64),
      expectedSessionState: .receiving,
      expectedCompletionID: nil,
      transportConfigurationDigest: "sha256:" + String(repeating: "a", count: 64),
      exchangeID: "exchange_retention_resume",
      newCredentialID: replacementCredential,
      newCredentialOwnershipDigest: TacuaCredentialFactory.ownershipDigest(
        for: replacementSecret
      ),
      createdAt: receivedAt,
      state: .credentialPrepared
    )
    try harness.resumeStore.create(resumeJournal)

    try require(
      try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .retired,
      "Expired journal-bearing session was not retired"
    )
    try require(harness.credentials.values.isEmpty, "Lifecycle credentials survived retention")
    try require(
      try harness.startStore.load(localSessionID: harness.localSessionID) == nil,
      "START journal survived retention"
    )
    try require(
      try harness.resumeStore.load(localSessionID: harness.localSessionID) == nil,
      "RESUME journal survived retention"
    )
  }

  private static func resumeRotationCannotExtendRawDeadline() throws {
    let harness = try makeHarness("resume_immutable", now: try milliseconds(rawExpiresAt))
    defer { try? FileManager.default.removeItem(at: harness.root) }
    var queue = try seedQueueAndCapture(harness)
    let original = queue.sessionRetentionAuthority
    try queue.applyExchange(
      remoteSessionID: "session_retention_remote",
      scopeDigest: "sha256:" + String(repeating: "b", count: 64),
      credentialID: "credential_retention_rotated",
      transportConfigurationDigest: "sha256:" + String(repeating: "a", count: 64),
      expiresAt: "2027-08-01T00:00:00Z",
      previousCredentialID: harness.credentialID,
      capability: .active,
      issuedAt: "2026-07-02T00:00:00Z",
      clock: harness.monotonicClock
    )
    try require(
      queue.sessionRetentionAuthority == original,
      "RESUME credential rotation changed the START raw-media deadline"
    )
    try harness.queueStore.persist(queue)
    try require(
      try coordinator(harness).enforce(localSessionID: harness.localSessionID) == .retired,
      "Later RESUME credential expiry extended raw-media retention"
    )
  }

  @discardableResult
  private static func seedQueueAndCapture(
    _ harness: RetentionHarness,
    localSessionID explicitLocalSessionID: String? = nil,
    credentialID explicitCredentialID: String? = nil,
    retentionAuthority: TacuaSessionRetentionAuthority? = TacuaSessionRetentionAuthority(
      sessionReceivedAt: receivedAt,
      rawMediaExpiresAt: rawExpiresAt,
      derivedDataExpiresAt: derivedExpiresAt
    )
  ) throws -> TacuaTransportQueueV3 {
    let localSessionID = explicitLocalSessionID ?? harness.localSessionID
    let credentialID = explicitCredentialID ?? harness.credentialID
    var queue = try TacuaTransportQueueV3(localSessionID: localSessionID)
    try queue.applyExchange(
      remoteSessionID: "session_retention_remote",
      scopeDigest: "sha256:" + String(repeating: "b", count: 64),
      credentialID: credentialID,
      transportConfigurationDigest: "sha256:" + String(repeating: "a", count: 64),
      expiresAt: "2026-08-01T00:00:00Z",
      capability: .active,
      issuedAt: receivedAt,
      clock: harness.monotonicClock
    )
    queue.sessionRetentionAuthority = retentionAuthority
    try queue.validate()
    try harness.queueStore.persistInitial(queue)
    harness.credentials.values[credentialID] = Data(
      repeating: 0x51,
      count: TacuaKeychainCredentialStore.secretLength
    )
    let session = sessionDirectory(harness, localSessionID: localSessionID)
    try FileManager.default.createDirectory(
      at: session.appendingPathComponent("segments", isDirectory: true),
      withIntermediateDirectories: true
    )
    try FileManager.default.createDirectory(
      at: session.appendingPathComponent(".tacua-upload-staging", isDirectory: true),
      withIntermediateDirectories: true
    )
    try Data("raw-media".utf8).write(
      to: session.appendingPathComponent("segments/000.mov")
    )
    try Data("queued-payload".utf8).write(
      to: session.appendingPathComponent(".tacua-upload-staging/upload-queued.snapshot")
    )
    try Data("manifest".utf8).write(to: session.appendingPathComponent("manifest.json"))
    return queue
  }

  private static func makeHarness(_ suffix: String, now: Int64) throws -> RetentionHarness {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-local-retention-\(suffix)-\(UUID().uuidString)")
      .resolvingSymlinksInPath()
    let capture = root.appendingPathComponent("captures", isDirectory: true)
    try FileManager.default.createDirectory(at: capture, withIntermediateDirectories: true)
    return RetentionHarness(
      root: root,
      captureRoot: capture,
      queueStore: try TacuaTransportQueueFileStore(
        rootDirectory: root.appendingPathComponent("queues", isDirectory: true)
      ),
      startStore: try TacuaSDKStartJournalFileStore(
        rootDirectory: root.appendingPathComponent("start", isDirectory: true)
      ),
      resumeStore: try TacuaSDKResumeJournalFileStore(
        rootDirectory: root.appendingPathComponent("resume", isDirectory: true)
      ),
      credentials: RetentionCredentialStore(),
      wallClock: RetentionWallClock(now),
      monotonicClock: RetentionMonotonicClock(),
      localSessionID: "local_retention_\(suffix)",
      credentialID: "credential_retention_\(suffix)"
    )
  }

  private static func coordinator(
    _ harness: RetentionHarness,
    retirerFactory: @escaping (URL) throws -> TacuaLocalSessionRetiring = {
      try TacuaScopedSessionRetirer(sessionDirectory: $0)
    }
  ) -> TacuaSDKLocalRetentionCoordinator {
    TacuaSDKLocalRetentionCoordinator(
      captureRootDirectory: harness.captureRoot,
      queueStore: harness.queueStore,
      startJournalStore: harness.startStore,
      resumeJournalStore: harness.resumeStore,
      credentialStore: harness.credentials,
      wallClock: harness.wallClock,
      monotonicClock: harness.monotonicClock,
      retirerFactory: retirerFactory
    )
  }

  private static func sessionDirectory(
    _ harness: RetentionHarness,
    localSessionID: String? = nil
  ) -> URL {
    harness.captureRoot.appendingPathComponent(
      localSessionID ?? harness.localSessionID,
      isDirectory: true
    )
  }

  private static func captureExists(
    _ harness: RetentionHarness,
    localSessionID: String? = nil
  ) -> Bool {
    let identifier = localSessionID ?? harness.localSessionID
    return FileManager.default.fileExists(
      atPath: sessionDirectory(harness, localSessionID: identifier).path
    )
      || FileManager.default.fileExists(
        atPath: harness.captureRoot.appendingPathComponent(
          ".tacua-retiring-\(identifier)"
        ).path
      )
  }

  private static func queueExists(
    _ harness: RetentionHarness,
    localSessionID: String? = nil
  ) throws -> Bool {
    FileManager.default.fileExists(
      atPath: try harness.queueStore.queueURL(
        localSessionID: localSessionID ?? harness.localSessionID
      ).path
    )
  }

  private static func milliseconds(_ timestamp: String) throws -> Int64 {
    guard let value = TacuaProtocolTimestamp.parseMilliseconds(timestamp) else {
      throw LocalRetentionTestFailure.assertion("Invalid test timestamp")
    }
    return value
  }
}
