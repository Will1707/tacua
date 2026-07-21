// SPDX-License-Identifier: Apache-2.0

import Foundation
import Security

private enum LifecycleTestFailure: Error {
  case assertion(String)
  case forcedTransportFailure
  case forcedQueueFailure
  case forcedCredentialFailure
  case forcedJournalFailure
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw LifecycleTestFailure.assertion(message) }
}

private final class TestCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  var removals: [String] = []
  var failNextRemove = false
  var installThenThrowNextStore = false
  var failNextReadWithKeychainStatus: Int32?
  var pauseNextStore: TestPause?
  let events: TestEvents

  init(events: TestEvents = TestEvents()) { self.events = events }

  func store(secret: Data, credentialID: String) throws {
    events.values.append("credential_store")
    if let pause = pauseNextStore {
      pauseNextStore = nil
      pause.pause()
    }
    guard values[credentialID] == nil else {
      throw TacuaCredentialStoreError.duplicateCredential
    }
    values[credentialID] = secret
    if installThenThrowNextStore {
      installThenThrowNextStore = false
      throw LifecycleTestFailure.forcedCredentialFailure
    }
  }

  func read(credentialID: String) throws -> Data {
    if let status = failNextReadWithKeychainStatus {
      failNextReadWithKeychainStatus = nil
      throw TacuaCredentialStoreError.keychainFailure(status)
    }
    guard let value = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return value
  }

  func remove(credentialID: String) throws {
    events.values.append("credential_remove")
    if failNextRemove {
      failNextRemove = false
      throw LifecycleTestFailure.forcedCredentialFailure
    }
    removals.append(credentialID)
    values.removeValue(forKey: credentialID)
  }
}

private final class TestEvents { var values: [String] = [] }

private final class TestAsyncSignal: @unchecked Sendable {
  private let lock = NSLock()
  private var pendingSignals = 0
  private var waiters: [UUID: CheckedContinuation<Bool, Never>] = [:]

  func signal() {
    lock.lock()
    if let (id, continuation) = waiters.first {
      waiters.removeValue(forKey: id)
      lock.unlock()
      continuation.resume(returning: true)
    } else {
      pendingSignals += 1
      lock.unlock()
    }
  }

  func wait(timeoutSeconds: Double = 2) async -> Bool {
    await withCheckedContinuation { continuation in
      lock.lock()
      if pendingSignals > 0 {
        pendingSignals -= 1
        lock.unlock()
        continuation.resume(returning: true)
        return
      }
      let id = UUID()
      waiters[id] = continuation
      lock.unlock()
      DispatchQueue.global().asyncAfter(deadline: .now() + timeoutSeconds) { [weak self] in
        guard let self else { return }
        self.lock.lock()
        let timedOut = self.waiters.removeValue(forKey: id)
        self.lock.unlock()
        timedOut?.resume(returning: false)
      }
    }
  }
}

private final class TestLifecycleLease: TacuaSDKStartLifecycleLease {
  private let lock = NSLock()
  private var releaseAction: (() -> Void)?

  init(releaseAction: @escaping () -> Void) { self.releaseAction = releaseAction }

  func release() {
    lock.lock()
    let action = releaseAction
    releaseAction = nil
    lock.unlock()
    action?()
  }

  deinit { release() }
}

private final class TestPause: @unchecked Sendable {
  private let lock = NSLock()
  private let releaseSemaphore = DispatchSemaphore(value: 0)
  private var reached = false
  private var reachedContinuation: CheckedContinuation<Void, Never>?

  func pause() {
    lock.lock()
    reached = true
    let continuation = reachedContinuation
    reachedContinuation = nil
    lock.unlock()
    continuation?.resume()
    releaseSemaphore.wait()
  }

  func waitUntilPaused() async {
    await withCheckedContinuation { continuation in
      lock.lock()
      if reached {
        lock.unlock()
        continuation.resume()
      } else {
        reachedContinuation = continuation
        lock.unlock()
      }
    }
  }

  func resume() { releaseSemaphore.signal() }
}

private struct TestRandom: TacuaSecureRandomGenerating {
  let bytesValue: Data
  func bytes(count: Int) throws -> Data { bytesValue }
}

private final class TestQueueStore: TacuaSDKStartQueueStoring {
  var queues: [String: TacuaTransportQueueV3] = [:]
  var failNextPersist = false
  var installThenThrowNextPersist = false
  var persistAttempts = 0
  let events: TestEvents
  private let lock = NSLock()

  init(events: TestEvents = TestEvents()) { self.events = events }

  func load(localSessionID: String) throws -> TacuaTransportQueueV3? {
    lock.lock()
    defer { lock.unlock() }
    return queues[localSessionID]
  }

  func persist(_ queue: TacuaTransportQueueV3) throws {
    lock.lock()
    defer { lock.unlock() }
    try persistLocked(queue)
  }

  func persistInitial(_ queue: TacuaTransportQueueV3) throws {
    lock.lock()
    defer { lock.unlock() }
    if let existing = queues[queue.localSessionID], existing != queue {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    try persistLocked(queue)
  }

  func recoverCredentialCleanup(
    localSessionID: String,
    credentialStore: TacuaCredentialStoring
  ) throws -> TacuaTransportQueueV3? {
    guard var queue = try load(localSessionID: localSessionID) else { return nil }
    try TacuaTransportCleanup.removePendingRevokedCredentials(
      queue: &queue,
      persistence: self,
      credentialStore: credentialStore
    )
    if queue.credentialCleanupState == .tombstoneWritten {
      try TacuaTransportCleanup.removeAuthorizedCredential(
        queue: &queue,
        persistence: self,
        credentialStore: credentialStore
      )
    }
    return queue
  }

  private func persistLocked(_ queue: TacuaTransportQueueV3) throws {
    persistAttempts += 1
    events.values.append("queue_persist")
    if installThenThrowNextPersist {
      installThenThrowNextPersist = false
      queues[queue.localSessionID] = queue
      throw LifecycleTestFailure.forcedQueueFailure
    }
    if failNextPersist {
      failNextPersist = false
      throw LifecycleTestFailure.forcedQueueFailure
    }
    queues[queue.localSessionID] = queue
  }
}

private final class TestJournalStore: TacuaSDKStartJournalPersisting {
  var journals: [String: TacuaSDKStartJournal] = [:]
  var persistedBytes: [Data] = []
  let events: TestEvents
  private let lock = NSLock()
  private let lifecycleCondition = NSCondition()
  private var lifecycleLeases = Set<String>()
  let lifecycleWaiterReached = TestAsyncSignal()
  private var pauseAfterMissingLoad: (() -> Void)?
  var failNextLoad = false
  var failNextRemove = false
  var removeThenThrowNext = false
  var failNextConfirmAbsent = false
  var pauseBeforeNextRemove: TestPause?

  init(events: TestEvents = TestEvents()) { self.events = events }

  func acquireLifecycleLease(localSessionID: String) throws
    -> TacuaSDKStartLifecycleLease
  {
    lifecycleCondition.lock()
    while lifecycleLeases.contains(localSessionID) {
      lifecycleWaiterReached.signal()
      lifecycleCondition.wait()
    }
    lifecycleLeases.insert(localSessionID)
    lifecycleCondition.unlock()
    return TestLifecycleLease { [weak self] in
      guard let self else { return }
      self.lifecycleCondition.lock()
      self.lifecycleLeases.remove(localSessionID)
      self.lifecycleCondition.broadcast()
      self.lifecycleCondition.unlock()
    }
  }

  func load(localSessionID: String) throws -> TacuaSDKStartJournal? {
    lock.lock()
    if failNextLoad {
      failNextLoad = false
      lock.unlock()
      throw LifecycleTestFailure.forcedJournalFailure
    }
    let journal = journals[localSessionID]
    let pause = journal == nil ? pauseAfterMissingLoad : nil
    if pause != nil { pauseAfterMissingLoad = nil }
    lock.unlock()
    pause?()
    return journal
  }

  func pauseAfterNextMissingLoad(_ pause: @escaping () -> Void) {
    lock.lock()
    pauseAfterMissingLoad = pause
    lock.unlock()
  }

  func create(_ journal: TacuaSDKStartJournal) throws {
    lock.lock()
    defer { lock.unlock() }
    guard journals[journal.localSessionID] == nil else {
      throw TacuaSDKStartJournalError.ownershipConflict
    }
    try record(journal)
  }

  func createWhileQueueAbsent(
    _ journal: TacuaSDKStartJournal,
    assertQueueAbsent: () throws -> Void
  ) throws {
    lock.lock()
    defer { lock.unlock() }
    try assertQueueAbsent()
    guard journals[journal.localSessionID] == nil else {
      throw TacuaSDKStartJournalError.ownershipConflict
    }
    try record(journal)
  }

  func compareAndSwap(
    expected: TacuaSDKStartJournal,
    replacement: TacuaSDKStartJournal
  ) throws {
    lock.lock()
    defer { lock.unlock() }
    guard expected.localSessionID == replacement.localSessionID,
      expected.exchangeID == replacement.exchangeID,
      expected.credentialID == replacement.credentialID,
      expected.credentialOwnershipDigest == replacement.credentialOwnershipDigest,
      expected.transportConfigurationDigest == replacement.transportConfigurationDigest,
      journals[expected.localSessionID] == expected
    else { throw TacuaSDKStartJournalError.stateConflict }
    try record(replacement)
  }

  func remove(expected: TacuaSDKStartJournal) throws {
    if let pause = pauseBeforeNextRemove {
      pauseBeforeNextRemove = nil
      pause.pause()
    }
    lock.lock()
    defer { lock.unlock() }
    if removeThenThrowNext {
      removeThenThrowNext = false
      guard journals[expected.localSessionID] == expected else {
        throw TacuaSDKStartJournalError.stateConflict
      }
      events.values.append("journal_remove_\(expected.state.rawValue)")
      journals.removeValue(forKey: expected.localSessionID)
      throw LifecycleTestFailure.forcedJournalFailure
    }
    if failNextRemove {
      failNextRemove = false
      throw LifecycleTestFailure.forcedJournalFailure
    }
    guard journals[expected.localSessionID] == expected else {
      throw TacuaSDKStartJournalError.stateConflict
    }
    events.values.append("journal_remove_\(expected.state.rawValue)")
    journals.removeValue(forKey: expected.localSessionID)
  }

  func confirmAbsent(expected: TacuaSDKStartJournal) throws {
    lock.lock()
    defer { lock.unlock() }
    if failNextConfirmAbsent {
      failNextConfirmAbsent = false
      throw LifecycleTestFailure.forcedJournalFailure
    }
    guard journals[expected.localSessionID] == nil else {
      throw TacuaSDKStartJournalError.stateConflict
    }
    events.values.append("journal_absence_confirmed")
  }

  private func record(_ journal: TacuaSDKStartJournal) throws {
    events.values.append("journal_\(journal.state.rawValue)")
    journals[journal.localSessionID] = journal
    persistedBytes.append(try journal.encoded())
  }
}

private final class TestClock: TacuaMonotonicClock {
  var uptimeMilliseconds: Int64
  var bootSessionID: String

  init(uptimeMilliseconds: Int64, bootSessionID: String) {
    self.uptimeMilliseconds = uptimeMilliseconds
    self.bootSessionID = bootSessionID
  }
}

private final class TestExchanger: TacuaSDKLaunchExchanging {
  var shouldFail = false
  var requests: [TacuaTransientLaunchRequest] = []
  var responseCount = 0

  func exchange(_ request: TacuaTransientLaunchRequest) async throws
    -> TacuaValidatedBackendReceipt
  {
    requests.append(request)
    if shouldFail { throw LifecycleTestFailure.forcedTransportFailure }
    responseCount += 1
    let requestValue = try TacuaCanonicalJSON.parse(request.canonicalData)
    guard let root = requestValue.objectValue,
      let scope = root["scope"],
      let requestDigest = root["request_digest"]?.stringValue,
      let credential = root["credential"]?.objectValue,
      let credentialID = credential["credential_id"]?.stringValue,
      let exchangeID = root["exchange_id"]?.stringValue
    else { throw LifecycleTestFailure.assertion("Malformed request reached exchanger") }
    var response: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("launch_exchange_receipt"),
      "exchange_kind": .string("start_session"),
      "exchange_id": .string(exchangeID),
      "request_digest": .string(requestDigest),
      "session_id": .string(String(format: "session_remote_%03d", responseCount)),
      "session_state": .string("receiving"),
      "scope": scope,
      "credential": .object([
        "credential_id": .string(credentialID),
        "authentication_scheme": .string("Bearer"),
        "state": .string("active"),
        "replay_completion_id": .null,
        "expires_at": .string("2026-08-20T10:00:00Z"),
      ]),
      "previous_credential_revocation": .null,
      "received_at": .string("2026-07-21T09:57:01Z"),
      "issued_at": .string("2026-07-21T09:57:01Z"),
    ]
    response["exchange_receipt_digest"] = .string(
      try TacuaCanonicalJSON.digest(.object(response))
    )
    let data = try TacuaCanonicalJSON.data(.object(response))
    return try TacuaSDKBackendProtocol.validateResponse(
      data,
      forCanonicalRequest: request.canonicalData
    )
  }
}

private struct Harness {
  let configuration: TacuaBackendConfiguration
  let gate: TacuaLaunchConsentGate
  let credentials: TestCredentialStore
  let queues: TestQueueStore
  let journals: TestJournalStore
  let exchanger: TestExchanger
  let clock: TestClock
  let coordinator: TacuaSDKStartLifecycleCoordinator
  let build: Data
  let scope: Data
}

@main
enum SDKStartLifecycleTests {
  static func main() async throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try await successfulStartConsumesOnceAndCommitsSafeQueue(fixtureRoot)
    try await preflightFailureDoesNotConsumeOrCreateCredential(fixtureRoot)
    try await lostJournalOwnershipCannotOrphanCredential(fixtureRoot)
    try await duplicateCredentialFailurePreservesExistingItem(fixtureRoot)
    try await failedCredentialStoreCannotOrphanInstalledItem(fixtureRoot)
    try duplicateCredentialCrashRecoveryPreservesExistingItem(fixtureRoot)
    try await invalidApprovedHandleRemovesUnusedCredential(fixtureRoot)
    try await unknownExchangeRequiresExplicitAcknowledgedReset(fixtureRoot)
    try await credentialPreparedResetCanResumeAfterCleanupFailure(fixtureRoot)
    try await resetVerificationReadFailureCannotReportSuccess(fixtureRoot)
    try await journalCleanupMustBeConfirmedBeforeSessionRelease(fixtureRoot)
    try await queueStatusWaitsUntilReceiptJournalIsRemoved(fixtureRoot)
    try await ambiguousJournalUnlinkCanBeDurablyConfirmed(fixtureRoot)
    try await validatedReceiptRecoversWithOriginalTimeAnchor(fixtureRoot)
    try await validatedReceiptRecoverySurvivesMissingCredentialAndBuildChange(fixtureRoot)
    try await rebootedRecoveryRequiresResumeWithoutExtendingTime(fixtureRoot)
    try await installThenThrowQueueRecoveryRepersistsBeforeJournalDeletion(fixtureRoot)
    try await stalePreflightCannotReacquireOwnershipAfterCommittedQueue(fixtureRoot)
    try await recoveryStatusReflectsReceiptRecoverability(fixtureRoot)
    try await committedQueueStatusReflectsUsableAuthority(fixtureRoot)
    try coexistingQueueAndJournalMustMatch(fixtureRoot)
    try journalFileStoreEnforcesExclusiveOwnershipAndCAS()
    print("Tacua SDK START lifecycle tests passed")
  }

  private static func successfulStartConsumesOnceAndCommitsSafeQueue(
    _ root: URL
  ) async throws {
    let events = TestEvents()
    let harness = try makeHarness(root, events: events)
    let approved = try approve(harness.gate, code: String(repeating: "A", count: 43))
    let started = try await harness.coordinator.start(
      input(harness, approved: approved, localSessionID: "local_success_001")
    )
    try require(started.remoteSessionID == "session_remote_001", "Remote session was not bound")
    try require(started.credentialCapability == .active, "START credential must be active")
    try require(started.credentialAvailability == .available, "START credential is unavailable")
    try require(started.queueSchemaVersion == 3, "START did not expose queue schema v3")
    try require(!started.resumeRequired, "Fresh START unexpectedly requires resume")
    let queue = try requireValue(
      harness.queues.queues["local_success_001"], "Committed queue is missing"
    )
    try require(queue.operations.isEmpty, "START must not claim uploads are queued")
    try require(
      queue.transportConfigurationDigest == harness.configuration.configurationDigest,
      "START queue was not bound to the current transport configuration"
    )
    try require(harness.journals.journals.isEmpty, "Committed journal was not removed")
    try require(
      events.values.prefix(2).elementsEqual([
        "journal_credential_prepared", "credential_store",
      ]),
      "Non-secret journal must be durable before the Keychain write"
    )
    let queueText = String(decoding: try queue.encoded(), as: UTF8.self).lowercased()
    try require(!queueText.contains("launch_code"), "Queue persisted a launch-code key")
    try require(!queueText.contains("secret"), "Queue persisted secret material")
    try require(harness.exchanger.requests.count == 1, "START must exchange exactly once")
    do {
      _ = try harness.gate.withApprovedLaunchCode(approvedLaunchID: approved) { $0 }
      throw LifecycleTestFailure.assertion("Approved launch handle was reusable")
    } catch let error as LifecycleTestFailure {
      throw error
    } catch {}
  }

  private static func preflightFailureDoesNotConsumeOrCreateCredential(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root, origin: "https://other.example")
    let code = String(repeating: "B", count: 43)
    let approved = try approve(harness.gate, code: code)
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_preflight_001")
      )
      throw LifecycleTestFailure.assertion("Transport-mismatched build passed preflight")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .invalidInput, "Preflight surfaced the wrong error")
    }
    try require(harness.credentials.values.isEmpty, "Preflight failure created a credential")
    try require(harness.journals.journals.isEmpty, "Preflight failure created a journal")
    let retained = try harness.gate.withApprovedLaunchCode(approvedLaunchID: approved) { $0 }
    try require(retained == code, "Preflight failure consumed the approved launch code")
  }

  private static func lostJournalOwnershipCannotOrphanCredential(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    let pause = TestPause()
    harness.credentials.pauseNextStore = pause
    let code = String(repeating: "P", count: 43)
    let approved = try approve(harness.gate, code: code)
    let localSessionID = "local_keychain_race_001"
    let startTask = Task.detached {
      try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: localSessionID)
      )
    }
    await pause.waitUntilPaused()
    let resetCoordinator = statusCoordinator(
      harness, configuration: harness.configuration
    )
    let resetTask = Task.detached {
      try resetCoordinator.abandon(
        localSessionID: localSessionID,
        acknowledgeRemoteSessionMayExist: false
      )
    }
    guard await harness.journals.lifecycleWaiterReached.wait() else {
      pause.resume()
      _ = try? await startTask.value
      throw LifecycleTestFailure.assertion("Concurrent reset did not contend on lifecycle lease")
    }
    pause.resume()
    let started = try await startTask.value
    do {
      try await resetTask.value
      throw LifecycleTestFailure.assertion("Reset overtook a live START lifecycle")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .queueAlreadyCommitted, "Serialized reset surfaced the wrong result")
    }
    try require(
      harness.credentials.values[started.credentialID] != nil,
      "Serialized START lost its current credential"
    )
    try require(
      harness.queues.queues[localSessionID]?.currentCredentialID == started.credentialID,
      "Serialized START did not commit its credential to the queue"
    )
    try require(harness.journals.journals.isEmpty, "Serialized START retained its journal")
    try require(harness.exchanger.requests.count == 1, "Serialized START did not exchange once")
  }

  private static func duplicateCredentialFailurePreservesExistingItem(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    let collidingID = "credential_00000000000000000000000000000002"
    let existing = Data(repeating: 0xA5, count: TacuaKeychainCredentialStore.secretLength)
    harness.credentials.values[collidingID] = existing
    let code = String(repeating: "Q", count: 43)
    let approved = try approve(harness.gate, code: code)
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_duplicate_keychain_001")
      )
      throw LifecycleTestFailure.assertion("Duplicate Keychain item was overwritten")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .credentialPreparationFailed,
        "Duplicate Keychain item surfaced the wrong preparation error"
      )
    }
    try require(
      harness.credentials.values[collidingID] == existing,
      "Duplicate-add cleanup removed a credential owned outside this START"
    )
    try require(
      !harness.credentials.removals.contains(collidingID),
      "Duplicate-add cleanup attempted to delete the existing credential"
    )
    try require(harness.journals.journals.isEmpty, "Duplicate-add journal was retained")
    let retained = try harness.gate.withApprovedLaunchCode(
      approvedLaunchID: approved
    ) { $0 }
    try require(retained == code, "Duplicate-add failure consumed reviewer consent")
  }

  private static func duplicateCredentialCrashRecoveryPreservesExistingItem(
    _ root: URL
  ) throws {
    let harness = try makeHarness(root)
    let localSessionID = "local_duplicate_crash_001"
    let credentialID = "credential_duplicate_crash_001"
    let attemptedSecret = Data(repeating: 0x53, count: 32)
    let existingSecret = Data(repeating: 0xA5, count: 32)
    harness.credentials.values[credentialID] = existingSecret
    harness.journals.journals[localSessionID] = try TacuaSDKStartJournal(
      localSessionID: localSessionID,
      exchangeID: "exchange_duplicate_crash_001",
      credentialID: credentialID,
      credentialOwnershipDigest: TacuaCredentialFactory.ownershipDigest(
        for: attemptedSecret
      ),
      transportConfigurationDigest: harness.configuration.configurationDigest,
      createdAt: "2026-07-21T09:57:00Z",
      state: .credentialPrepared
    )

    try harness.coordinator.abandon(
      localSessionID: localSessionID,
      acknowledgeRemoteSessionMayExist: false
    )
    try require(
      harness.credentials.values[credentialID] == existingSecret,
      "Crash recovery removed a pre-existing duplicate Keychain item"
    )
    try require(
      !harness.credentials.removals.contains(credentialID),
      "Crash recovery attempted to delete a verifier mismatch"
    )
    try require(
      harness.journals.journals[localSessionID] == nil,
      "Verifier mismatch retained a cleanup-only START journal"
    )
  }

  private static func failedCredentialStoreCannotOrphanInstalledItem(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.credentials.installThenThrowNextStore = true
    let approved = try approve(harness.gate, code: String(repeating: "O", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_store_ambiguous_001")
      )
      throw LifecycleTestFailure.assertion("Install-then-throw credential store reported success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .credentialPreparationFailed,
        "Install-then-throw credential store surfaced the wrong error"
      )
    }
    try require(
      harness.credentials.values.isEmpty,
      "Install-then-throw credential store orphaned an owned item"
    )
    try require(
      harness.credentials.removals.count == 1,
      "Install-then-throw cleanup did not remove the verifier match"
    )
    try require(
      harness.journals.journals.isEmpty,
      "Install-then-throw cleanup retained its START journal"
    )
  }

  private static func invalidApprovedHandleRemovesUnusedCredential(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    do {
      _ = try await harness.coordinator.start(
        input(
          harness,
          approved: "approved_missing",
          localSessionID: "local_bad_handle_001"
        )
      )
      throw LifecycleTestFailure.assertion("Missing approved handle was accepted")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .launchRequestRejected, "Wrong missing-handle error")
    }
    try require(harness.credentials.values.isEmpty, "Unused credential survived request failure")
    try require(harness.credentials.removals.count == 1, "Unused credential was not removed")
    try require(harness.journals.journals.isEmpty, "Unused credential journal survived cleanup")
  }

  private static func credentialPreparedResetCanResumeAfterCleanupFailure(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.credentials.failNextRemove = true
    do {
      _ = try await harness.coordinator.start(
        input(
          harness,
          approved: "approved_missing",
          localSessionID: "local_reset_prepared_001"
        )
      )
      throw LifecycleTestFailure.assertion("Failed credential cleanup reported START success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .credentialCleanupRequired,
        "Prepared credential cleanup failure surfaced the wrong error"
      )
    }
    let journal = try requireValue(
      harness.journals.journals["local_reset_prepared_001"],
      "Prepared reset ownership was not durable"
    )
    try require(
      journal.state == .credentialPreparedResetPending,
      "Prepared reset did not claim cleanup with CAS"
    )
    let status = try harness.coordinator.recoveryStatus(
      localSessionID: journal.localSessionID
    )
    try require(
      status.state == .credentialPreparedResetPending,
      "Prepared reset-pending state was not externally visible"
    )
    try require(status.requiresFreshReviewerLaunch, "Prepared reset lost launch requirements")
    try require(status.canAbandonLocally, "Prepared reset cleanup was not retryable")
    try harness.coordinator.abandon(
      localSessionID: journal.localSessionID,
      acknowledgeRemoteSessionMayExist: false
    )
    try require(harness.credentials.values.isEmpty, "Prepared reset retry retained credential")
    try require(harness.journals.journals.isEmpty, "Prepared reset retry retained journal")
  }

  private static func unknownExchangeRequiresExplicitAcknowledgedReset(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.exchanger.shouldFail = true
    let code = String(repeating: "C", count: 43)
    let approved = try approve(harness.gate, code: code)
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_unknown_001")
      )
      throw LifecycleTestFailure.assertion("Failed transport reported START success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .exchangeOutcomeUnknown, "Transport ambiguity was mislabeled")
    }
    let journal = try requireValue(
      harness.journals.journals["local_unknown_001"], "Unknown outcome journal missing"
    )
    try require(journal.state == .exchangeOutcomeUnknown, "Unknown state was not durable")
    try require(
      harness.credentials.values[journal.credentialID] != nil,
      "Potentially accepted credential was removed"
    )
    let status = try harness.coordinator.recoveryStatus(localSessionID: "local_unknown_001")
    try require(status.requiresFreshReviewerLaunch, "Unknown outcome must require a fresh launch")
    try require(status.remoteSessionMayExist, "Unknown outcome hid possible remote state")
    try require(!status.canRecoverWithoutLaunch, "Unknown outcome claimed remote recovery")
    try require(status.resumeRequired == nil, "Unknown outcome asserted credential usability")
    try require(
      status.transportConfigurationMatchesBuild == true,
      "Unknown outcome lost its build-pinned transport identity"
    )

    let replacementCode = String(repeating: "R", count: 43)
    let replacementApproved = try approve(harness.gate, code: replacementCode)
    do {
      _ = try await harness.coordinator.start(
        input(
          harness,
          approved: replacementApproved,
          localSessionID: "local_unknown_001"
        )
      )
      throw LifecycleTestFailure.assertion("Existing recovery state allowed another START")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .recoveryActionRequired(.exchangeOutcomeUnknown),
        "Existing recovery state surfaced the wrong error"
      )
    }
    let retainedReplacement = try harness.gate.withApprovedLaunchCode(
      approvedLaunchID: replacementApproved
    ) { $0 }
    try require(
      retainedReplacement == replacementCode,
      "Recovery precondition consumed a fresh approved launch"
    )

    do {
      try harness.coordinator.abandon(
        localSessionID: "local_unknown_001",
        acknowledgeRemoteSessionMayExist: false
      )
      throw LifecycleTestFailure.assertion("Unknown outcome reset lacked acknowledgement")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .resetAcknowledgementRequired, "Wrong reset guard")
    }
    harness.credentials.failNextRemove = true
    do {
      try harness.coordinator.abandon(
        localSessionID: "local_unknown_001",
        acknowledgeRemoteSessionMayExist: true
      )
      throw LifecycleTestFailure.assertion("Failed credential reset reported success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .credentialCleanupRequired, "Reset cleanup failure was hidden")
    }
    let resetPending = try requireValue(
      harness.journals.journals["local_unknown_001"], "Reset ownership was not durable"
    )
    try require(
      resetPending.state == .exchangeOutcomeUnknownResetPending,
      "Unknown reset did not retain exclusive cleanup ownership"
    )
    let resetStatus = try harness.coordinator.recoveryStatus(
      localSessionID: "local_unknown_001"
    )
    try require(
      resetStatus.state == .exchangeOutcomeUnknownResetPending,
      "Recovery status hid the reset-pending state"
    )
    try require(resetStatus.canAbandonLocally, "Reset-pending cleanup was not retryable")
    try harness.coordinator.abandon(
      localSessionID: "local_unknown_001",
      acknowledgeRemoteSessionMayExist: false
    )
    try require(harness.credentials.values.isEmpty, "Acknowledged reset retained credential")
    try require(harness.journals.journals.isEmpty, "Acknowledged reset retained journal")
    let durableText = harness.journals.persistedBytes
      .map { String(decoding: $0, as: UTF8.self).lowercased() }.joined()
    try require(!durableText.contains(code.lowercased()), "Journal persisted the launch code")
    try require(!durableText.contains("secret"), "Journal persisted a secret key")
  }

  private static func resetVerificationReadFailureCannotReportSuccess(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.exchanger.shouldFail = true
    let approved = try approve(harness.gate, code: String(repeating: "V", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_reset_verify_001")
      )
      throw LifecycleTestFailure.assertion("Ambiguous START unexpectedly succeeded")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .exchangeOutcomeUnknown, "Reset fixture failed too early")
    }
    harness.journals.failNextRemove = true
    harness.journals.failNextConfirmAbsent = true
    do {
      try harness.coordinator.abandon(
        localSessionID: "local_reset_verify_001",
        acknowledgeRemoteSessionMayExist: true
      )
      throw LifecycleTestFailure.assertion(
        "A failed journal verification read was mistaken for successful reset"
      )
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .credentialCleanupRequired, "Reset read failure was hidden")
    }
    let pending = try requireValue(
      harness.journals.journals["local_reset_verify_001"],
      "Reset-pending journal disappeared after failed verification"
    )
    try require(
      pending.state == .exchangeOutcomeUnknownResetPending,
      "Reset did not retain durable cleanup ownership"
    )
    try harness.coordinator.abandon(
      localSessionID: "local_reset_verify_001",
      acknowledgeRemoteSessionMayExist: true
    )
    try require(harness.journals.journals.isEmpty, "Reset retry retained its journal")
  }

  private static func journalCleanupMustBeConfirmedBeforeSessionRelease(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.journals.failNextRemove = true
    let approved = try approve(harness.gate, code: String(repeating: "L", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_cleanup_gate_001")
      )
      throw LifecycleTestFailure.assertion("START released a session with a live journal")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .journalCleanupRequired,
        "Unconfirmed journal cleanup surfaced the wrong recovery error"
      )
    }
    try require(
      harness.queues.queues["local_cleanup_gate_001"] != nil
        && harness.journals.journals["local_cleanup_gate_001"] != nil,
      "Cleanup failure did not retain matching durable recovery state"
    )
    do {
      _ = try harness.coordinator.queueStatus(localSessionID: "local_cleanup_gate_001")
      throw LifecycleTestFailure.assertion(
        "Queue status exposed authority before receipt-journal recovery"
      )
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .journalCleanupRequired,
        "Unreleased queue status surfaced the wrong recovery error"
      )
    }

    _ = try harness.coordinator.recover(localSessionID: "local_cleanup_gate_001")
    try require(harness.journals.journals.isEmpty, "Recovery retained the redundant journal")
  }

  private static func queueStatusWaitsUntilReceiptJournalIsRemoved(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    let pause = TestPause()
    harness.journals.pauseBeforeNextRemove = pause
    let localSessionID = "local_queue_status_lease_001"
    let approved = try approve(harness.gate, code: String(repeating: "J", count: 43))
    let startTask = Task.detached {
      try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: localSessionID)
      )
    }
    await pause.waitUntilPaused()
    try require(
      harness.queues.queues[localSessionID] != nil
        && harness.journals.journals[localSessionID] != nil,
      "Queue-status race fixture did not pause in the publication window"
    )

    let reader = statusCoordinator(harness, configuration: harness.configuration)
    let statusTask = Task.detached { try reader.queueStatus(localSessionID: localSessionID) }
    guard await harness.journals.lifecycleWaiterReached.wait() else {
      pause.resume()
      _ = try? await startTask.value
      throw LifecycleTestFailure.assertion(
        "Queue status did not contend on the START lifecycle lease"
      )
    }

    pause.resume()
    let started = try await startTask.value
    let status = try requireValue(
      try await statusTask.value,
      "Queue status lost the released START queue"
    )
    try require(
      status.remoteSessionID == started.remoteSessionID
        && status.credentialCapability == .active
        && status.credentialAvailability == .available
        && !status.resumeRequired,
      "Queue status did not expose the exact released START authority"
    )
    try require(
      harness.journals.journals[localSessionID] == nil,
      "Queue status returned before receipt-journal removal"
    )
  }

  private static func ambiguousJournalUnlinkCanBeDurablyConfirmed(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.journals.removeThenThrowNext = true
    let approved = try approve(harness.gate, code: String(repeating: "M", count: 43))
    _ = try await harness.coordinator.start(
      input(harness, approved: approved, localSessionID: "local_unlink_confirm_001")
    )
    try require(
      harness.journals.events.values.contains("journal_absence_confirmed"),
      "Ambiguous unlink was not durably confirmed"
    )
    try require(harness.journals.journals.isEmpty, "Confirmed unlink retained a journal")
  }

  private static func validatedReceiptRecoversWithOriginalTimeAnchor(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.queues.failNextPersist = true
    let approved = try approve(harness.gate, code: String(repeating: "D", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_recover_001")
      )
      throw LifecycleTestFailure.assertion("Failed queue commit reported success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .receiptCommitPending, "Validated receipt was not recoverable")
    }
    let pending = try requireValue(
      harness.journals.journals["local_recover_001"], "Receipt journal missing"
    )
    try require(
      pending.validatedReceipt?.timeAnchor.uptimeMillisecondsAtIssue == 100_000,
      "Receipt journal did not retain the observation-time anchor"
    )
    harness.clock.uptimeMilliseconds = 3_700_000
    let recovered = try harness.coordinator.recover(localSessionID: "local_recover_001")
    try require(recovered.remoteSessionID == "session_remote_001", "Recovery changed session")
    let queue = try requireValue(
      harness.queues.queues["local_recover_001"], "Recovered queue missing"
    )
    let delayedTimestamp = try queue.timestampForNewOperation(clock: harness.clock)
    try require(
      delayedTimestamp == "2026-07-21T10:57:01Z",
      "Delayed recovery re-anchored the receipt timestamp"
    )
  }

  private static func rebootedRecoveryRequiresResumeWithoutExtendingTime(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.queues.failNextPersist = true
    let approved = try approve(harness.gate, code: String(repeating: "E", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_reboot_001")
      )
      throw LifecycleTestFailure.assertion("Failed queue commit reported success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .receiptCommitPending, "Receipt did not reach recovery state")
    }
    harness.clock.bootSessionID = "boot_after_reboot"
    harness.clock.uptimeMilliseconds = 5_000
    _ = try harness.coordinator.recover(localSessionID: "local_reboot_001")
    let queue = try requireValue(
      harness.queues.queues["local_reboot_001"], "Reboot recovery queue missing"
    )
    do {
      _ = try queue.timestampForNewOperation(clock: harness.clock)
      throw LifecycleTestFailure.assertion("Rebooted recovery extended credential time")
    } catch let error as TacuaTransportQueueError {
      try require(error == .resumeRequired, "Reboot must force a fresh resume exchange")
    }
  }

  private static func validatedReceiptRecoverySurvivesMissingCredentialAndBuildChange(
    _ root: URL
  ) async throws {
    let missingCredentialHarness = try makeHarness(root)
    missingCredentialHarness.queues.failNextPersist = true
    let missingApproved = try approve(
      missingCredentialHarness.gate,
      code: String(repeating: "N", count: 43)
    )
    do {
      _ = try await missingCredentialHarness.coordinator.start(
        input(
          missingCredentialHarness,
          approved: missingApproved,
          localSessionID: "local_receipt_no_keychain_001"
        )
      )
      throw LifecycleTestFailure.assertion("Missing-Keychain fixture unexpectedly committed")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .receiptCommitPending, "Missing-Keychain fixture failed too early")
    }
    let missingJournal = try requireValue(
      missingCredentialHarness.journals.journals["local_receipt_no_keychain_001"],
      "Missing-Keychain receipt journal disappeared"
    )
    missingCredentialHarness.credentials.values.removeValue(forKey: missingJournal.credentialID)
    let missingRecovered = try missingCredentialHarness.coordinator.recover(
      localSessionID: missingJournal.localSessionID
    )
    try require(
      missingRecovered.resumeRequired
        && missingCredentialHarness.journals.journals[missingJournal.localSessionID] == nil,
      "Validated receipt did not become a resume-required queue without Keychain material"
    )

    let changedBuildHarness = try makeHarness(root)
    changedBuildHarness.queues.failNextPersist = true
    let changedApproved = try approve(
      changedBuildHarness.gate,
      code: String(repeating: "O", count: 43)
    )
    do {
      _ = try await changedBuildHarness.coordinator.start(
        input(
          changedBuildHarness,
          approved: changedApproved,
          localSessionID: "local_receipt_old_build_001"
        )
      )
      throw LifecycleTestFailure.assertion("Changed-build fixture unexpectedly committed")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .receiptCommitPending, "Changed-build fixture failed too early")
    }
    let oldDigest = changedBuildHarness.configuration.configurationDigest
    let changedConfiguration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://other.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let recovered = try statusCoordinator(
      changedBuildHarness,
      configuration: changedConfiguration
    ).recover(localSessionID: "local_receipt_old_build_001")
    try require(recovered.resumeRequired, "Old-build receipt bypassed transport rebind")
    try require(
      changedBuildHarness.queues.queues[recovered.localSessionID]?
        .transportConfigurationDigest == oldDigest,
      "Receipt recovery rewrote its original build-pinned transport provenance"
    )
    try require(
      changedBuildHarness.journals.journals[recovered.localSessionID] == nil,
      "Changed-build recovery retained the receipt journal"
    )
  }

  private static func installThenThrowQueueRecoveryRepersistsBeforeJournalDeletion(
    _ root: URL
  ) async throws {
    let events = TestEvents()
    let harness = try makeHarness(root, events: events)
    harness.queues.installThenThrowNextPersist = true
    let approved = try approve(harness.gate, code: String(repeating: "F", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_install_throw_001")
      )
      throw LifecycleTestFailure.assertion("Install-then-throw queue commit reported success")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .receiptCommitPending, "Queue install ambiguity was mislabeled")
    }
    try require(
      harness.queues.queues["local_install_throw_001"] != nil,
      "Install-then-throw did not leave the candidate queue"
    )
    try require(
      harness.journals.journals["local_install_throw_001"]?.state
        == .receiptValidatedQueueCommitPending,
      "Install-then-throw discarded receipt recovery evidence"
    )

    let attemptsBeforeRecovery = harness.queues.persistAttempts
    events.values.removeAll()
    let recovered = try harness.coordinator.recover(
      localSessionID: "local_install_throw_001"
    )
    try require(recovered.queueSchemaVersion == 3, "Recovered queue did not expose schema v3")
    try require(
      harness.queues.persistAttempts == attemptsBeforeRecovery + 1,
      "Recovery trusted an ambiguously installed queue without re-persisting it"
    )
    try require(
      events.values == [
        "queue_persist",
        "journal_remove_receipt_validated_queue_commit_pending",
      ],
      "Recovery removed the journal before confirming the queue persist"
    )
    try require(harness.journals.journals.isEmpty, "Recovered journal was not removed")
  }

  private static func stalePreflightCannotReacquireOwnershipAfterCommittedQueue(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    let competingGate = TacuaLaunchConsentGate()
    let competingCredentials = TestCredentialStore()
    let competingExchanger = TestExchanger()
    var competingCounter = 101
    let competingFactory = TacuaCredentialFactory(
      store: competingCredentials,
      random: TestRandom(bytesValue: Data(repeating: 0x71, count: 32)),
      uuid: {
        defer { competingCounter += 1 }
        return UUID(
          uuidString: String(
            format: "00000000-0000-0000-0000-%012d", competingCounter
          )
        )!
      }
    )
    let competingCoordinator = TacuaSDKStartLifecycleCoordinator(
      configuration: harness.configuration,
      consentGate: competingGate,
      credentialFactory: competingFactory,
      exchanger: competingExchanger,
      queueStore: harness.queues,
      journalStore: harness.journals,
      clock: harness.clock
    )
    let competingApproved = try approve(
      competingGate, code: String(repeating: "G", count: 43)
    )
    let competingInput = TacuaSDKStartSessionInput(
      approvedLaunchID: competingApproved,
      localSessionID: "local_ownership_race_001",
      buildIdentityJSON: harness.build,
      scopeJSON: harness.scope,
      requestedAt: "2026-07-21T09:57:00Z"
    )

    let preflightPause = TestPause()
    harness.journals.pauseAfterNextMissingLoad {
      preflightPause.pause()
    }
    let competingStart = Task.detached {
      try await competingCoordinator.start(competingInput)
    }
    await preflightPause.waitUntilPaused()

    let winningApproved = try approve(
      harness.gate, code: String(repeating: "H", count: 43)
    )
    let laterStart = Task.detached {
      try await harness.coordinator.start(
        input(
          harness,
          approved: winningApproved,
          localSessionID: "local_ownership_race_001"
        )
      )
    }
    guard await harness.journals.lifecycleWaiterReached.wait() else {
      preflightPause.resume()
      _ = try? await competingStart.value
      throw LifecycleTestFailure.assertion("Second START did not contend on lifecycle lease")
    }
    preflightPause.resume()
    let winner = try await competingStart.value
    do {
      _ = try await laterStart.value
      throw LifecycleTestFailure.assertion(
        "A stale START reacquired ownership after another process committed the queue"
      )
    } catch let error as LifecycleTestFailure {
      throw error
    } catch is TacuaSDKStartLifecycleError {
      // Any lifecycle refusal is acceptable here; it must happen before a second exchange.
    }
    try require(
      competingExchanger.requests.count == 1 && harness.exchanger.requests.isEmpty,
      "Lifecycle lease admitted more than one START exchange"
    )
    let committed = try requireValue(
      harness.queues.queues["local_ownership_race_001"],
      "Winning queue disappeared during stale-owner rejection"
    )
    try require(
      committed.currentCredentialID == winner.credentialID,
      "Stale START overwrote the winning queue"
    )
  }

  private static func recoveryStatusReflectsReceiptRecoverability(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    harness.queues.failNextPersist = true
    let approved = try approve(harness.gate, code: String(repeating: "I", count: 43))
    do {
      _ = try await harness.coordinator.start(
        input(harness, approved: approved, localSessionID: "local_status_receipt_001")
      )
      throw LifecycleTestFailure.assertion("Receipt-status fixture unexpectedly committed")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .receiptCommitPending, "Receipt-status fixture failed too early")
    }
    let recoverable = try harness.coordinator.recoveryStatus(
      localSessionID: "local_status_receipt_001"
    )
    try require(
      recoverable.state == .receiptValidatedQueueCommitPending
        && recoverable.canRecoverWithoutLaunch,
      "Usable validated receipt did not advertise local recovery"
    )
    try require(
      recoverable.resumeRequired == false
        && recoverable.transportConfigurationMatchesBuild == true,
      "Usable validated receipt reported incorrect resume/configuration status"
    )

    let mismatchedConfiguration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://other.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let mismatchedCoordinator = statusCoordinator(
      harness, configuration: mismatchedConfiguration
    )
    let mismatched = try mismatchedCoordinator.recoveryStatus(
      localSessionID: "local_status_receipt_001"
    )
    try require(
      mismatched.canRecoverWithoutLaunch && mismatched.resumeRequired == true,
      "Transport-mismatched receipt did not preserve structural queue recovery"
    )
    try require(
      mismatched.requiresFreshReviewerLaunch,
      "Transport-mismatched receipt hid the need for a fresh reviewer launch"
    )
    try require(
      mismatched.transportConfigurationMatchesBuild == false,
      "Transport-mismatched receipt hid its build mismatch"
    )

    let journal = try requireValue(
      harness.journals.journals["local_status_receipt_001"],
      "Receipt-status journal disappeared"
    )
    harness.credentials.values.removeValue(forKey: journal.credentialID)
    let missingCredential = try harness.coordinator.recoveryStatus(
      localSessionID: journal.localSessionID
    )
    try require(
      missingCredential.canRecoverWithoutLaunch && missingCredential.resumeRequired == true,
      "Receipt without its Keychain credential did not preserve structural queue recovery"
    )
    try require(
      missingCredential.requiresFreshReviewerLaunch,
      "Receipt without its credential hid the need for a fresh reviewer launch"
    )
    try require(
      missingCredential.transportConfigurationMatchesBuild == true,
      "Missing credential was confused with a transport mismatch"
    )
  }

  private static func committedQueueStatusReflectsUsableAuthority(
    _ root: URL
  ) async throws {
    let harness = try makeHarness(root)
    let approved = try approve(harness.gate, code: String(repeating: "J", count: 43))
    let started = try await harness.coordinator.start(
      input(harness, approved: approved, localSessionID: "local_status_queue_001")
    )
    let usable = try harness.coordinator.recoveryStatus(
      localSessionID: "local_status_queue_001"
    )
    try require(
      usable.canRecoverWithoutLaunch && usable.resumeRequired == false,
      "Usable committed queue did not advertise local recovery"
    )
    try require(
      usable.transportConfigurationMatchesBuild == true,
      "Usable committed queue lost its build binding"
    )

    let mismatchedConfiguration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://other.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let mismatched = try statusCoordinator(
      harness, configuration: mismatchedConfiguration
    ).recoveryStatus(localSessionID: "local_status_queue_001")
    try require(
      mismatched.canRecoverWithoutLaunch && mismatched.resumeRequired == true,
      "Transport-mismatched committed queue hid structural START recovery"
    )
    try require(
      mismatched.requiresFreshReviewerLaunch,
      "Transport-mismatched queue hid the need for a fresh reviewer launch"
    )
    try require(
      mismatched.transportConfigurationMatchesBuild == false,
      "Committed queue hid its transport mismatch"
    )

    harness.credentials.values.removeValue(forKey: started.credentialID)
    let missingCredential = try harness.coordinator.recoveryStatus(
      localSessionID: "local_status_queue_001"
    )
    try require(
      missingCredential.canRecoverWithoutLaunch && missingCredential.resumeRequired == true,
      "Committed queue without its Keychain credential hid structural recovery"
    )
    try require(
      missingCredential.requiresFreshReviewerLaunch,
      "Queue without its credential hid the need for a fresh reviewer launch"
    )
    try require(
      missingCredential.transportConfigurationMatchesBuild == true,
      "Missing queue credential was confused with a transport mismatch"
    )
    try require(
      missingCredential.credentialAvailability == .missing,
      "Missing queue credential did not expose explicit availability"
    )

    harness.credentials.values[started.credentialID] = Data(repeating: 3, count: 32)
    harness.credentials.failNextReadWithKeychainStatus = errSecInteractionNotAllowed
    let lockedCredential = try harness.coordinator.recoveryStatus(
      localSessionID: "local_status_queue_001"
    )
    try require(
      lockedCredential.credentialAvailability == .temporarilyUnavailable
        && lockedCredential.resumeRequired == false
        && !lockedCredential.requiresFreshReviewerLaunch,
      "Temporary device-lock Keychain unavailability requested a destructive re-launch"
    )

    var terminal = try TacuaTransportQueueV3(localSessionID: "local_status_terminal_001")
    try terminal.applyExchange(
      remoteSessionID: "session_status_terminal_001",
      scopeDigest: "sha256:" + String(repeating: "a", count: 64),
      credentialID: "credential_status_terminal_001",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T09:57:01Z",
      clock: harness.clock
    )
    terminal.credentialCapability = .completionReplayOrDeleteOnly
    try terminal.validate()
    harness.credentials.values["credential_status_terminal_001"] = Data(repeating: 3, count: 32)
    harness.queues.queues[terminal.localSessionID] = terminal
    let terminalStatus = try harness.coordinator.recoveryStatus(
      localSessionID: terminal.localSessionID
    )
    try require(
      !terminalStatus.canRecoverWithoutLaunch && terminalStatus.resumeRequired == false,
      "Completion-restricted queue confused terminal authority with a required resume"
    )
    try require(
      !terminalStatus.requiresFreshReviewerLaunch,
      "Completion-restricted queue requested an unnecessary reviewer launch"
    )
    try require(
      terminalStatus.transportConfigurationMatchesBuild == true,
      "Terminal queue lost its valid transport provenance"
    )
    try require(
      terminalStatus.credentialCapability == .completionReplayOrDeleteOnly,
      "Terminal queue status hid its restricted credential capability"
    )

    var rebind = try TacuaTransportQueueV3(localSessionID: "local_status_rebind_001")
    try rebind.applyExchange(
      remoteSessionID: "session_status_rebind_001",
      scopeDigest: "sha256:" + String(repeating: "b", count: 64),
      credentialID: "credential_status_rebind_001",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T09:57:01Z",
      clock: harness.clock
    )
    rebind.credentialCapability = .requiresTransportRebind
    rebind.transportConfigurationDigest = nil
    try rebind.validate()
    harness.credentials.values["credential_status_rebind_001"] = Data(repeating: 4, count: 32)
    harness.queues.queues[rebind.localSessionID] = rebind
    let rebindStatus = try harness.coordinator.recoveryStatus(
      localSessionID: rebind.localSessionID
    )
    try require(
      !rebindStatus.canRecoverWithoutLaunch && rebindStatus.resumeRequired == true,
      "Transport-rebind queue overclaimed local START recovery"
    )
    try require(
      rebindStatus.requiresFreshReviewerLaunch,
      "Transport-rebind queue hid the need for a fresh reviewer launch"
    )
    try require(
      rebindStatus.transportConfigurationMatchesBuild == false,
      "Transport-rebind queue claimed a current build binding"
    )
  }

  private static func coexistingQueueAndJournalMustMatch(_ root: URL) throws {
    let harness = try makeHarness(root)
    var queue = try TacuaTransportQueueV3(localSessionID: "local_mismatch_001")
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: "2026-07-21T09:57:01Z", clock: harness.clock
    )
    try queue.applyRecoveredStart(
      remoteSessionID: "session_queue_001",
      scopeDigest: "sha256:" + String(repeating: "a", count: 64),
      credentialID: "credential_queue_001",
      transportConfigurationDigest: harness.configuration.configurationDigest,
      expiresAt: "2026-08-20T10:00:00Z",
      timeAnchor: anchor
    )
    harness.queues.queues[queue.localSessionID] = queue
    harness.journals.journals[queue.localSessionID] = try TacuaSDKStartJournal(
      localSessionID: queue.localSessionID,
      exchangeID: "exchange_mismatch_001",
      credentialID: "credential_other_001",
      credentialOwnershipDigest: "sha256:" + String(repeating: "e", count: 64),
      transportConfigurationDigest: harness.configuration.configurationDigest,
      createdAt: "2026-07-21T09:57:00Z",
      state: .receiptValidatedQueueCommitPending,
      validatedReceipt: TacuaSDKStartReceiptRecovery(
        remoteSessionID: "session_other_001",
        scopeDigest: "sha256:" + String(repeating: "b", count: 64),
        credentialExpiresAt: "2026-08-20T10:00:00Z",
        timeAnchor: anchor
      )
    )
    do {
      _ = try harness.coordinator.recoveryStatus(localSessionID: queue.localSessionID)
      throw LifecycleTestFailure.assertion("Mismatched journal was hidden by committed queue")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(error == .recoveryStateMismatch, "Wrong queue/journal mismatch error")
    }
  }

  private static func journalFileStoreEnforcesExclusiveOwnershipAndCAS() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-start-journal-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try TacuaSDKStartJournalFileStore(rootDirectory: root)
    let rootAttributes = try FileManager.default.attributesOfItem(atPath: root.path)
    let rootMode = (rootAttributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
    try require(rootMode & 0o777 == 0o700, "Journal directory permissions are not private")

    let orphanSessionID = "local_file_orphan_001"
    let orphan = root.appendingPathComponent(
      ".\(orphanSessionID).start-v1.\(String(repeating: "b", count: 32)).tmp"
    )
    try Data("interrupted-journal".utf8).write(to: orphan)
    _ = try store.load(localSessionID: orphanSessionID)
    try require(
      !FileManager.default.fileExists(atPath: orphan.path),
      "Session-locked journal recovery retained an interrupted temp file"
    )

    let blocked = try TacuaSDKStartJournal(
      localSessionID: "local_file_blocked_001",
      exchangeID: "exchange_file_blocked_001",
      credentialID: "credential_file_blocked_001",
      credentialOwnershipDigest: "sha256:" + String(repeating: "e", count: 64),
      transportConfigurationDigest: "sha256:" + String(repeating: "c", count: 64),
      createdAt: "2026-07-21T09:56:00Z",
      state: .credentialPrepared
    )
    do {
      try store.createWhileQueueAbsent(blocked) {
        throw LifecycleTestFailure.forcedQueueFailure
      }
      throw LifecycleTestFailure.assertion("Queue-aware create ignored a committed queue")
    } catch LifecycleTestFailure.forcedQueueFailure {}
    let blockedJournal = try store.load(localSessionID: blocked.localSessionID)
    try require(
      blockedJournal == nil,
      "Queue-aware create installed a journal after its absence check failed"
    )

    let journal = try TacuaSDKStartJournal(
      localSessionID: "local_file_001",
      exchangeID: "exchange_file_001",
      credentialID: "credential_file_001",
      credentialOwnershipDigest: "sha256:" + String(repeating: "f", count: 64),
      transportConfigurationDigest: "sha256:" + String(repeating: "d", count: 64),
      createdAt: "2026-07-21T09:57:00Z",
      state: .credentialPrepared
    )
    try store.createWhileQueueAbsent(journal) {}
    let journalAttributes = try FileManager.default.attributesOfItem(
      atPath: store.journalURL(localSessionID: journal.localSessionID).path
    )
    let journalMode = (journalAttributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
    try require(journalMode & 0o777 == 0o600, "Journal file permissions are not private")
    do {
      try store.create(journal)
      throw LifecycleTestFailure.assertion("Exclusive journal creation admitted two owners")
    } catch let error as TacuaSDKStartJournalError {
      try require(error == .ownershipConflict, "Duplicate create surfaced the wrong conflict")
    }

    let attempted = try journal.advancing(to: .exchangeOutcomeUnknown)
    try store.compareAndSwap(expected: journal, replacement: attempted)
    do {
      try store.compareAndSwap(expected: journal, replacement: attempted)
      throw LifecycleTestFailure.assertion("Stale journal CAS replaced newer state")
    } catch let error as TacuaSDKStartJournalError {
      try require(error == .stateConflict, "Stale CAS surfaced the wrong conflict")
    }
    do {
      try store.remove(expected: journal)
      throw LifecycleTestFailure.assertion("Stale owner removed newer journal state")
    } catch let error as TacuaSDKStartJournalError {
      try require(error == .stateConflict, "Stale remove surfaced the wrong conflict")
    }

    let resetPending = try attempted.advancing(to: .exchangeOutcomeUnknownResetPending)
    try store.compareAndSwap(expected: attempted, replacement: resetPending)
    let loaded = try store.load(localSessionID: journal.localSessionID)
    try require(loaded == resetPending, "Journal CAS round-trip changed reset ownership")
    let bytes = try Data(contentsOf: store.journalURL(localSessionID: journal.localSessionID))
    let decoded = try TacuaSDKStartJournal.decode(bytes)
    try require(decoded == resetPending, "Journal was not canonical")
    let text = String(decoding: bytes, as: UTF8.self).lowercased()
    try require(!text.contains("launch_code"), "Journal file contains launch-code key")
    try require(!text.contains("secret"), "Journal file contains secret key")
    try store.remove(expected: resetPending)
    let removed = try store.load(localSessionID: journal.localSessionID)
    try require(
      removed == nil,
      "Expected-owner removal retained the journal"
    )
  }

  private static func makeHarness(
    _ root: URL,
    origin: String = "https://qa.tacua.example",
    events: TestEvents = TestEvents()
  ) throws -> Harness {
    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: origin,
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let gate = TacuaLaunchConsentGate()
    let credentials = TestCredentialStore(events: events)
    let queues = TestQueueStore(events: events)
    let journals = TestJournalStore(events: events)
    let exchanger = TestExchanger()
    let clock = TestClock(uptimeMilliseconds: 100_000, bootSessionID: "boot_initial")
    var counter = 1
    let factory = TacuaCredentialFactory(
      store: credentials,
      random: TestRandom(bytesValue: Data(repeating: 0x53, count: 32)),
      uuid: {
        defer { counter += 1 }
        return UUID(
          uuidString: String(format: "00000000-0000-0000-0000-%012d", counter)
        )!
      }
    )
    let coordinator = TacuaSDKStartLifecycleCoordinator(
      configuration: configuration,
      consentGate: gate,
      credentialFactory: factory,
      exchanger: exchanger,
      queueStore: queues,
      journalStore: journals,
      clock: clock
    )
    return Harness(
      configuration: configuration,
      gate: gate,
      credentials: credentials,
      queues: queues,
      journals: journals,
      exchanger: exchanger,
      clock: clock,
      coordinator: coordinator,
      build: try Data(contentsOf: root.appendingPathComponent("build-identity.json")),
      scope: try Data(contentsOf: root.appendingPathComponent("capture-scope.json"))
    )
  }

  private static func statusCoordinator(
    _ harness: Harness,
    configuration: TacuaBackendConfiguration
  ) -> TacuaSDKStartLifecycleCoordinator {
    TacuaSDKStartLifecycleCoordinator(
      configuration: configuration,
      consentGate: harness.gate,
      credentialFactory: TacuaCredentialFactory(store: harness.credentials),
      exchanger: harness.exchanger,
      queueStore: harness.queues,
      journalStore: harness.journals,
      clock: harness.clock
    )
  }

  private static func approve(_ gate: TacuaLaunchConsentGate, code: String) throws -> String {
    let pending = try gate.prepare(
      rawURL: "configured-target-scheme://tacua/start?launch_code=\(code)",
      configuration: try TacuaLaunchLinkConfiguration(
        buildConfiguredScheme: "configured-target-scheme"
      )
    )
    return try gate.confirm(consentRequestID: pending.consentRequestID, granted: true)
  }

  private static func input(
    _ harness: Harness,
    approved: String,
    localSessionID: String
  ) -> TacuaSDKStartSessionInput {
    TacuaSDKStartSessionInput(
      approvedLaunchID: approved,
      localSessionID: localSessionID,
      buildIdentityJSON: harness.build,
      scopeJSON: harness.scope,
      requestedAt: "2026-07-21T09:57:00Z"
    )
  }

  private static func requireValue<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw LifecycleTestFailure.assertion(message) }
    return value
  }
}
