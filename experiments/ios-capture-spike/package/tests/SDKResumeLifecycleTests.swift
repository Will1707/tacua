// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum ResumeLifecycleTestFailure: Error {
  case assertion(String)
  case forcedCredentialFailure
  case forcedJournalFailure
  case forcedQueueFailure
  case forcedTransportFailure
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw ResumeLifecycleTestFailure.assertion(message) }
}

private func requireValue<T>(_ value: T?, _ message: String) throws -> T {
  guard let value else { throw ResumeLifecycleTestFailure.assertion(message) }
  return value
}

private final class ResumeTestCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  var stores: [String] = []
  var removals: [String] = []

  func store(secret: Data, credentialID: String) throws {
    stores.append(credentialID)
    guard values[credentialID] == nil else {
      throw TacuaCredentialStoreError.duplicateCredential
    }
    values[credentialID] = secret
  }

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

private struct ResumeTestRandom: TacuaSecureRandomGenerating {
  let value: Data

  func bytes(count: Int) throws -> Data {
    guard value.count == count else {
      throw TacuaCredentialStoreError.invalidSecretLength
    }
    return value
  }
}

private final class ResumeTestClock: TacuaMonotonicClock {
  var uptimeMilliseconds: Int64
  var bootSessionID: String

  init(uptimeMilliseconds: Int64, bootSessionID: String) {
    self.uptimeMilliseconds = uptimeMilliseconds
    self.bootSessionID = bootSessionID
  }
}

private final class ResumeTestLifecycleLease: TacuaSDKStartLifecycleLease {
  func release() {}
}

private final class ResumeTestStartJournalStore: TacuaSDKStartJournalPersisting {
  var journals: [String: TacuaSDKStartJournal] = [:]

  func acquireLifecycleLease(localSessionID: String) throws
    -> TacuaSDKStartLifecycleLease
  {
    ResumeTestLifecycleLease()
  }

  func load(localSessionID: String) throws -> TacuaSDKStartJournal? {
    journals[localSessionID]
  }

  func create(_ journal: TacuaSDKStartJournal) throws {
    guard journals[journal.localSessionID] == nil else {
      throw TacuaSDKStartJournalError.ownershipConflict
    }
    journals[journal.localSessionID] = journal
  }

  func createWhileQueueAbsent(
    _ journal: TacuaSDKStartJournal,
    assertQueueAbsent: () throws -> Void
  ) throws {
    try assertQueueAbsent()
    try create(journal)
  }

  func compareAndSwap(
    expected: TacuaSDKStartJournal,
    replacement: TacuaSDKStartJournal
  ) throws {
    guard journals[expected.localSessionID] == expected else {
      throw TacuaSDKStartJournalError.stateConflict
    }
    journals[expected.localSessionID] = replacement
  }

  func remove(expected: TacuaSDKStartJournal) throws {
    guard journals[expected.localSessionID] == expected else {
      throw TacuaSDKStartJournalError.stateConflict
    }
    journals.removeValue(forKey: expected.localSessionID)
  }

  func confirmAbsent(expected: TacuaSDKStartJournal) throws {
    guard journals[expected.localSessionID] == nil else {
      throw TacuaSDKStartJournalError.stateConflict
    }
  }
}

private final class ResumeTestQueueStore: TacuaSDKResumeQueueStoring {
  var queues: [String: TacuaTransportQueueV3] = [:]
  var compareAndSwapAttempts = 0
  var installThenThrowAttempts = Set<Int>()
  var failAttempts = Set<Int>()
  var events: [String] = []

  func load(localSessionID: String) throws -> TacuaTransportQueueV3? {
    queues[localSessionID]
  }

  func persist(_ queue: TacuaTransportQueueV3) throws {
    events.append("queue_persist")
    queues[queue.localSessionID] = queue
  }

  func persistInitial(_ queue: TacuaTransportQueueV3) throws {
    if let existing = queues[queue.localSessionID], existing != queue {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    try persist(queue)
  }

  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws {
    compareAndSwapAttempts += 1
    let attempt = compareAndSwapAttempts
    guard queues[expected.localSessionID] == expected else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    if installThenThrowAttempts.remove(attempt) != nil {
      queues[replacement.localSessionID] = replacement
      events.append("queue_cas_install_then_throw_\(attempt)")
      throw ResumeLifecycleTestFailure.forcedQueueFailure
    }
    if failAttempts.remove(attempt) != nil {
      events.append("queue_cas_fail_\(attempt)")
      throw ResumeLifecycleTestFailure.forcedQueueFailure
    }
    queues[replacement.localSessionID] = replacement
    events.append("queue_cas_success_\(attempt)")
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
}

private final class ResumeTestJournalStore: TacuaSDKResumeJournalPersisting,
  TacuaSDKResumeRecoveryInspecting
{
  var journals: [String: TacuaSDKResumeJournal] = [:]
  var events: [String] = []
  var installThenThrowReceiptCAS = false
  var failReceiptIdempotentCAS = false
  var failNextRemove = false
  var failNextConfirmAbsent = false

  func load(localSessionID: String) throws -> TacuaSDKResumeJournal? {
    journals[localSessionID]
  }

  func hasRecovery(localSessionID: String) throws -> Bool {
    journals[localSessionID] != nil
  }

  func create(_ journal: TacuaSDKResumeJournal) throws {
    guard journals[journal.localSessionID] == nil else {
      throw TacuaSDKResumeJournalError.ownershipConflict
    }
    journals[journal.localSessionID] = journal
    events.append("resume_journal_\(journal.state.rawValue)")
  }

  func createWhileBaseQueueMatches(
    _ journal: TacuaSDKResumeJournal,
    assertBaseQueueMatches: () throws -> Void
  ) throws {
    try assertBaseQueueMatches()
    try create(journal)
  }

  func compareAndSwap(
    expected: TacuaSDKResumeJournal,
    replacement: TacuaSDKResumeJournal
  ) throws {
    guard journals[expected.localSessionID] == expected else {
      throw TacuaSDKResumeJournalError.stateConflict
    }
    if installThenThrowReceiptCAS,
      expected.state == .exchangeOutcomeUnknown,
      replacement.state == .receiptValidatedQueueCommitPending
    {
      installThenThrowReceiptCAS = false
      journals[replacement.localSessionID] = replacement
      events.append("resume_journal_receipt_install_then_throw")
      throw ResumeLifecycleTestFailure.forcedJournalFailure
    }
    if failReceiptIdempotentCAS,
      expected.state == .receiptValidatedQueueCommitPending,
      replacement == expected
    {
      failReceiptIdempotentCAS = false
      events.append("resume_journal_receipt_retry_fail")
      throw ResumeLifecycleTestFailure.forcedJournalFailure
    }
    journals[replacement.localSessionID] = replacement
    events.append("resume_journal_\(replacement.state.rawValue)")
  }

  func remove(expected: TacuaSDKResumeJournal) throws {
    if failNextRemove {
      failNextRemove = false
      events.append("resume_journal_remove_fail")
      throw ResumeLifecycleTestFailure.forcedJournalFailure
    }
    guard journals[expected.localSessionID] == expected else {
      throw TacuaSDKResumeJournalError.stateConflict
    }
    journals.removeValue(forKey: expected.localSessionID)
    events.append("resume_journal_remove")
  }

  func confirmAbsent(expected: TacuaSDKResumeJournal) throws {
    if failNextConfirmAbsent {
      failNextConfirmAbsent = false
      events.append("resume_journal_confirm_absent_fail")
      throw ResumeLifecycleTestFailure.forcedJournalFailure
    }
    guard journals[expected.localSessionID] == nil else {
      throw TacuaSDKResumeJournalError.stateConflict
    }
    events.append("resume_journal_confirm_absent")
  }
}

private final class ResumeTestExchanger: TacuaSDKLaunchExchanging {
  var shouldFail = false
  var issuedAt = "2026-07-21T10:06:00Z"
  var receivedAt: String?
  var expiresAt = "2026-08-21T10:06:00Z"
  var requests: [TacuaTransientLaunchRequest] = []

  func exchange(_ request: TacuaTransientLaunchRequest) async throws
    -> TacuaValidatedBackendReceipt
  {
    requests.append(request)
    if shouldFail { throw ResumeLifecycleTestFailure.forcedTransportFailure }
    let requestValue = try TacuaCanonicalJSON.parse(request.canonicalData)
    guard let root = requestValue.objectValue,
      let exchangeID = root["exchange_id"]?.stringValue,
      let requestDigest = root["request_digest"]?.stringValue,
      let remoteSessionID = root["expected_session_id"]?.stringValue,
      let expectedState = root["expected_session_state"]?.stringValue,
      let previousCredentialID = root["previous_credential_id"]?.stringValue,
      let credential = root["credential"]?.objectValue,
      let credentialID = credential["credential_id"]?.stringValue,
      let scope = root["scope"]
    else {
      throw ResumeLifecycleTestFailure.assertion("Malformed RESUME request reached exchanger")
    }
    let expectedCompletionID: TacuaJSONValue = root["expected_completion_id"] ?? .null
    let credentialState = expectedState == "receiving"
      ? "active" : "completion_replay_or_delete_only"
    var response: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("launch_exchange_receipt"),
      "exchange_kind": .string("resume_session"),
      "exchange_id": .string(exchangeID),
      "request_digest": .string(requestDigest),
      "session_id": .string(remoteSessionID),
      "session_state": .string(expectedState),
      "scope": scope,
      "credential": .object([
        "credential_id": .string(credentialID),
        "authentication_scheme": .string("Bearer"),
        "state": .string(credentialState),
        "replay_completion_id": expectedCompletionID,
        "expires_at": .string(expiresAt),
      ]),
      "previous_credential_revocation": .object([
        "credential_id": .string(previousCredentialID),
        "state": .string("revoked"),
        "revoked_at": .string(issuedAt),
      ]),
      "received_at": .string(receivedAt ?? issuedAt),
      "issued_at": .string(issuedAt),
    ]
    response["exchange_receipt_digest"] = .string(
      try TacuaCanonicalJSON.digest(.object(response))
    )
    let responseData = try TacuaCanonicalJSON.data(.object(response))
    return try TacuaSDKBackendProtocol.validateResponse(
      responseData,
      forCanonicalRequest: request.canonicalData
    )
  }
}

private struct ResumeLifecycleHarness {
  let configuration: TacuaBackendConfiguration
  let gate: TacuaLaunchConsentGate
  let credentials: ResumeTestCredentialStore
  let queues: ResumeTestQueueStore
  let startJournals: ResumeTestStartJournalStore
  let resumeJournals: ResumeTestJournalStore
  let exchanger: ResumeTestExchanger
  let clock: ResumeTestClock
  let credentialFactory: TacuaCredentialFactory
  let coordinator: TacuaSDKResumeLifecycleCoordinator
  let build: Data
  let scope: Data
}

private func makeResumeHarness(
  _ fixtureRoot: URL,
  uuidValues: [UUID] = [
    UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
    UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
  ]
) throws -> ResumeLifecycleHarness {
  let configuration = try TacuaBackendConfiguration(
    buildConfiguredOrigin: "https://qa.tacua.example",
    allowInsecureLoopback: false,
    debugBuild: false
  )
  let gate = TacuaLaunchConsentGate()
  let credentials = ResumeTestCredentialStore()
  let queues = ResumeTestQueueStore()
  let startJournals = ResumeTestStartJournalStore()
  let resumeJournals = ResumeTestJournalStore()
  let exchanger = ResumeTestExchanger()
  let clock = ResumeTestClock(
    uptimeMilliseconds: 220_000,
    bootSessionID: "boot_resume_lifecycle"
  )
  var uuidIndex = 0
  let credentialFactory = TacuaCredentialFactory(
    store: credentials,
    random: ResumeTestRandom(value: Data(repeating: 0x52, count: 32)),
    uuid: {
      let value = uuidValues[min(uuidIndex, uuidValues.count - 1)]
      uuidIndex += 1
      return value
    }
  )
  let coordinator = TacuaSDKResumeLifecycleCoordinator(
    configuration: configuration,
    consentGate: gate,
    credentialFactory: credentialFactory,
    exchanger: exchanger,
    queueStore: queues,
    startJournalStore: startJournals,
    journalStore: resumeJournals,
    clock: clock
  )
  return ResumeLifecycleHarness(
    configuration: configuration,
    gate: gate,
    credentials: credentials,
    queues: queues,
    startJournals: startJournals,
    resumeJournals: resumeJournals,
    exchanger: exchanger,
    clock: clock,
    credentialFactory: credentialFactory,
    coordinator: coordinator,
    build: try Data(contentsOf: fixtureRoot.appendingPathComponent("build-identity.json")),
    scope: try Data(contentsOf: fixtureRoot.appendingPathComponent("capture-scope.json"))
  )
}

private func approveResumeLaunch(
  _ gate: TacuaLaunchConsentGate,
  code: String
) throws -> String {
  let pending = try gate.prepare(
    rawURL: "configured-target-scheme://tacua/start?launch_code=\(code)",
    configuration: try TacuaLaunchLinkConfiguration(
      buildConfiguredScheme: "configured-target-scheme"
    )
  )
  return try gate.confirm(consentRequestID: pending.consentRequestID, granted: true)
}

private func resumeInput(
  _ harness: ResumeLifecycleHarness,
  approved: String,
  localSessionID: String,
  scope: Data? = nil,
  requestedAt: String = "2026-07-21T10:05:00Z"
) -> TacuaSDKResumeSessionInput {
  TacuaSDKResumeSessionInput(
    approvedLaunchID: approved,
    localSessionID: localSessionID,
    buildIdentityJSON: harness.build,
    scopeJSON: scope ?? harness.scope,
    requestedAt: requestedAt
  )
}

private func startInput(
  _ harness: ResumeLifecycleHarness,
  approved: String,
  localSessionID: String
) -> TacuaSDKStartSessionInput {
  TacuaSDKStartSessionInput(
    approvedLaunchID: approved,
    localSessionID: localSessionID,
    buildIdentityJSON: harness.build,
    scopeJSON: harness.scope,
    requestedAt: "2026-07-21T10:05:00Z"
  )
}

private func retainedLaunchCode(
  _ gate: TacuaLaunchConsentGate,
  approved: String
) throws -> String {
  try gate.withApprovedLaunchCode(approvedLaunchID: approved) { $0 }
}

private func fixtureValue(_ root: URL, _ name: String) throws -> TacuaJSONValue {
  try TacuaCanonicalJSON.parse(
    Data(contentsOf: root.appendingPathComponent("\(name).json"))
  )
}

private func canonicalFixture(_ root: URL, _ name: String) throws -> Data {
  try TacuaCanonicalJSON.data(fixtureValue(root, name))
}

private func fixtureScopeDigest(_ harness: ResumeLifecycleHarness) throws -> String {
  let value = try TacuaCanonicalJSON.parse(harness.scope)
  return try requireValue(
    value.objectValue?["scope_digest"]?.stringValue,
    "Fixture scope digest is missing"
  )
}

private func makeReceivingBaseQueue(
  _ harness: ResumeLifecycleHarness,
  localSessionID: String,
  currentCredentialID: String = "credential_previous_receiving",
  transportConfigurationDigest: String? = nil,
  expiresAt: String = "2026-07-21T10:01:00Z",
  installCurrentCredential: Bool = true,
  issuedAt: String = "2026-07-21T10:00:00Z"
) throws -> TacuaTransportQueueV3 {
  var queue = try TacuaTransportQueueV3(localSessionID: localSessionID)
  try queue.applyExchange(
    remoteSessionID: "session_remote_receiving",
    scopeDigest: try fixtureScopeDigest(harness),
    credentialID: currentCredentialID,
    transportConfigurationDigest:
      transportConfigurationDigest ?? harness.configuration.configurationDigest,
    expiresAt: expiresAt,
    capability: .active,
    issuedAt: issuedAt,
    clock: ResumeTestClock(
      uptimeMilliseconds: 100_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  if installCurrentCredential {
    harness.credentials.values[currentCredentialID] = Data(repeating: 0x41, count: 32)
  }
  harness.queues.queues[localSessionID] = queue
  return queue
}

private func enqueueFixtureUpload(
  _ root: URL,
  requestName: String,
  responseName: String,
  kind: TacuaQueuedOperationKind,
  bindings: [TacuaLocalPayloadBinding],
  queue: inout TacuaTransportQueueV3,
  clock: ResumeTestClock
) throws {
  let requestData = try canonicalFixture(root, requestName)
  let requestValue = try TacuaCanonicalJSON.parse(requestData)
  guard let request = requestValue.objectValue,
    let credentialID = request["credential_id"]?.stringValue,
    let operationID = request["upload_id"]?.stringValue,
    let digest = request[kind == .segment ? "intent_digest" : "request_digest"]?.stringValue
  else {
    throw ResumeLifecycleTestFailure.assertion("Invalid fixture upload request")
  }
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
    responseData,
    forCanonicalRequest: requestData
  )
  try queue.storeValidatedReceipt(receipt)
}

private func makeCompletedBaseQueue(
  _ harness: ResumeLifecycleHarness,
  fixtureRoot: URL,
  localSessionID: String
) throws -> TacuaTransportQueueV3 {
  let completionRequestData = try canonicalFixture(fixtureRoot, "completion-request")
  let completionRequestValue = try TacuaCanonicalJSON.parse(completionRequestData)
  guard let request = completionRequestValue.objectValue,
    let credentialID = request["credential_id"]?.stringValue,
    let sessionID = request["session_id"]?.stringValue,
    let scopeDigest = request["scope_digest"]?.stringValue,
    let completionID = request["completion_id"]?.stringValue,
    let requestDigest = request["request_digest"]?.stringValue
  else {
    throw ResumeLifecycleTestFailure.assertion("Invalid completion fixture")
  }
  var queue = try TacuaTransportQueueV3(
    localSessionID: localSessionID,
    localPayloadPaths: ["legacy/unbound-must-survive.bin"]
  )
  try queue.applyExchange(
    remoteSessionID: sessionID,
    scopeDigest: scopeDigest,
    credentialID: "credential_synthetic",
    transportConfigurationDigest: harness.configuration.configurationDigest,
    expiresAt: "2026-08-20T10:00:00Z",
    capability: .active,
    issuedAt: "2026-07-21T10:00:00Z",
    clock: ResumeTestClock(
      uptimeMilliseconds: 100_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  try enqueueFixtureUpload(
    fixtureRoot,
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
    clock: ResumeTestClock(
      uptimeMilliseconds: 101_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  try queue.applyExchange(
    remoteSessionID: sessionID,
    scopeDigest: scopeDigest,
    credentialID: credentialID,
    transportConfigurationDigest: harness.configuration.configurationDigest,
    expiresAt: "2026-08-20T10:00:00Z",
    previousCredentialID: "credential_synthetic",
    capability: .active,
    issuedAt: "2026-07-21T10:01:00Z",
    clock: ResumeTestClock(
      uptimeMilliseconds: 160_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  try enqueueFixtureUpload(
    fixtureRoot,
    requestName: "diagnostic-upload-request",
    responseName: "diagnostic-upload-receipt",
    kind: .diagnostic,
    bindings: [
      TacuaLocalPayloadBinding(
        role: .diagnosticEnvelope,
        relativePath: "diagnostics/events.json",
        contentDigest:
          "sha256:6f395bf765e73eac49e90ff444ce8965ce31b452a683f26e03e8554497e4efbf"
      )
    ],
    queue: &queue,
    clock: ResumeTestClock(
      uptimeMilliseconds: 163_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  try queue.enqueueNewOperation(
    kind: .completion,
    operationID: completionID,
    requestCredentialID: credentialID,
    request: completionRequestValue,
    requestDigest: requestDigest,
    clock: ResumeTestClock(
      uptimeMilliseconds: 165_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  let completionResponse = try canonicalFixture(fixtureRoot, "completion-receipt")
  let receipt = try TacuaSDKBackendProtocol.validateResponse(
    completionResponse,
    forCanonicalRequest: completionRequestData
  )
  try queue.storeValidatedReceipt(receipt)
  harness.queues.queues[localSessionID] = queue
  return queue
}

private func makeDeletionBaseQueue(
  _ harness: ResumeLifecycleHarness,
  fixtureRoot: URL,
  localSessionID: String
) throws -> TacuaTransportQueueV3 {
  let requestData = try canonicalFixture(fixtureRoot, "deletion-request")
  let requestValue = try TacuaCanonicalJSON.parse(requestData)
  guard let request = requestValue.objectValue,
    let credentialID = request["credential_id"]?.stringValue,
    let sessionID = request["session_id"]?.stringValue,
    let scopeDigest = request["scope_digest"]?.stringValue,
    let deletionID = request["deletion_id"]?.stringValue,
    let requestDigest = request["request_digest"]?.stringValue
  else {
    throw ResumeLifecycleTestFailure.assertion("Invalid deletion fixture")
  }
  var queue = try TacuaTransportQueueV3(localSessionID: localSessionID)
  try queue.applyExchange(
    remoteSessionID: sessionID,
    scopeDigest: scopeDigest,
    credentialID: credentialID,
    transportConfigurationDigest: harness.configuration.configurationDigest,
    expiresAt: "2026-08-20T10:00:00Z",
    capability: .active,
    issuedAt: "2026-07-21T10:00:00Z",
    clock: ResumeTestClock(
      uptimeMilliseconds: 100_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  try queue.enqueueNewOperation(
    kind: .deletion,
    operationID: deletionID,
    requestCredentialID: credentialID,
    request: requestValue,
    requestDigest: requestDigest,
    clock: ResumeTestClock(
      uptimeMilliseconds: 101_000,
      bootSessionID: harness.clock.bootSessionID
    )
  )
  let responseData = try canonicalFixture(fixtureRoot, "deletion-tombstone")
  let receipt = try TacuaSDKBackendProtocol.validateResponse(
    responseData,
    forCanonicalRequest: requestData
  )
  try queue.storeValidatedReceipt(receipt)
  harness.queues.queues[localSessionID] = queue
  return queue
}

private func manualPreparedJournal(
  harness: ResumeLifecycleHarness,
  queue: TacuaTransportQueueV3,
  newCredentialID: String,
  newSecret: Data
) throws -> TacuaSDKResumeJournal {
  try TacuaSDKResumeJournal(
    localSessionID: queue.localSessionID,
    baseQueueDigest: TacuaCanonicalJSON.digest(data: try queue.encoded()),
    previousCredentialID: try requireValue(
      queue.currentCredentialID,
      "Manual journal base credential is missing"
    ),
    remoteSessionID: try requireValue(
      queue.remoteSessionID,
      "Manual journal remote session is missing"
    ),
    scopeDigest: try requireValue(queue.scopeDigest, "Manual journal scope is missing"),
    expectedSessionState: .receiving,
    expectedCompletionID: nil,
    transportConfigurationDigest: harness.configuration.configurationDigest,
    exchangeID: "exchange_manual_resume",
    newCredentialID: newCredentialID,
    newCredentialOwnershipDigest: TacuaCredentialFactory.ownershipDigest(for: newSecret),
    createdAt: "2026-07-21T10:05:00Z",
    state: .credentialPrepared
  )
}

@main
enum SDKResumeLifecycleTests {
  static func main() async throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try await receivingResumeCommitsAndCleansRevokedCredential(fixtureRoot)
    try await completedResumePreservesExactAuthority(fixtureRoot)
    try await preConsentRejectionsRetainLaunch(fixtureRoot)
    try await deterministicFailuresCleanPreparedCredentialBeforeNetwork(fixtureRoot)
    try await networkFailureQuarantinesBothCredentials(fixtureRoot)
    try preparedResetSurvivesBaseQueueMutation(fixtureRoot)
    try await receiptCASAmbiguityRecoversWithoutLaunch(fixtureRoot)
    try await installedResultRecoversWithoutLaunch(fixtureRoot)
    try await journalCleanupGatesQueueUntilRecovery(fixtureRoot)
    try await anchorRegressionRemainsOutcomeUnknown(fixtureRoot)
    try await receiptReceivedBeforeBaseFloorIsQuarantined(fixtureRoot)
    try await migratedV2BindingResumesSuccessfully(fixtureRoot)
    try await nearLimitV2ResumeReservesReceiptAnchorGrowth(fixtureRoot)
    try await startAndQueueStatusAreCrossGated(fixtureRoot)
    print("Tacua SDK RESUME lifecycle tests passed")
  }
}

private extension SDKResumeLifecycleTests {
  static func receivingResumeCommitsAndCleansRevokedCredential(
    _ fixtureRoot: URL
  ) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_receiving_001"
    let previousCredentialID = "credential_previous_receiving"
    _ = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: previousCredentialID
    )
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "A", count: 43)
    )

    let resumed = try await harness.coordinator.resume(
      resumeInput(harness, approved: approved, localSessionID: localSessionID)
    )

    try require(resumed.backendSessionState == .receiving, "Receiving state was not restored")
    try require(resumed.credentialCapability == .active, "Receiving authority is not active")
    try require(resumed.replayCompletionID == nil, "Receiving resume gained completion authority")
    try require(resumed.credentialAvailability == .available, "New credential is unavailable")
    try require(!resumed.resumeRequired, "Freshly resumed queue still requires RESUME")
    try require(
      resumed.pendingRevokedCredentialRemovalCount == 0,
      "Revoked credential cleanup did not drain"
    )
    let queue = try requireValue(
      harness.queues.queues[localSessionID],
      "Receiving result queue is missing"
    )
    try require(queue.currentCredentialID == resumed.credentialID, "Result queue kept credential A")
    try require(
      queue.transportConfigurationDigest == harness.configuration.configurationDigest,
      "Result queue lost its transport binding"
    )
    try require(
      harness.credentials.values[previousCredentialID] == nil,
      "Revoked credential A survived durable queue commit"
    )
    try require(
      harness.credentials.values[resumed.credentialID] != nil,
      "Current credential B was removed during cleanup"
    )
    try require(
      harness.credentials.removals.contains(previousCredentialID),
      "Queue-owned cleanup never attempted credential A"
    )
    try require(harness.resumeJournals.journals.isEmpty, "Successful RESUME retained a journal")
    try require(harness.exchanger.requests.count == 1, "Receiving RESUME exchanged more than once")
  }

  static func completedResumePreservesExactAuthority(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_completed_001"
    let base = try makeCompletedBaseQueue(
      harness,
      fixtureRoot: fixtureRoot,
      localSessionID: localSessionID
    )
    let originalOperations = base.operations
    let originalAuthority = try requireValue(
      base.completionCleanupAuthority,
      "Completed fixture has no cleanup authority"
    )
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "B", count: 43)
    )

    let resumed = try await harness.coordinator.resume(
      resumeInput(harness, approved: approved, localSessionID: localSessionID)
    )

    try require(resumed.backendSessionState == .completed, "Completed state became receiving")
    try require(
      resumed.credentialCapability == .completionReplayOrDeleteOnly,
      "Completed RESUME restored upload authority"
    )
    try require(
      resumed.replayCompletionID == originalAuthority.completionID,
      "Completed RESUME changed the exact completion binding"
    )
    let result = try requireValue(
      harness.queues.queues[localSessionID],
      "Completed result queue is missing"
    )
    try require(
      result.completionCleanupAuthority == originalAuthority,
      "Completed RESUME rewrote cleanup authority"
    )
    try require(result.operations == originalOperations, "Completed RESUME rewrote operation history")
    let request = try TacuaCanonicalJSON.parse(
      try requireValue(harness.exchanger.requests.first, "Completed RESUME was not sent")
        .canonicalData
    )
    try require(
      request.objectValue?["expected_session_state"]?.stringValue == "completed",
      "Completed launch did not request completed authority"
    )
    try require(
      request.objectValue?["expected_completion_id"]?.stringValue
        == originalAuthority.completionID,
      "Completed launch omitted its exact replay completion ID"
    )
    try require(
      result.currentCredentialID == resumed.credentialID,
      "Completed result did not install credential B"
    )
    try require(harness.resumeJournals.journals.isEmpty, "Completed RESUME retained a journal")
  }

  static func preConsentRejectionsRetainLaunch(_ fixtureRoot: URL) async throws {
    let invalidScopeHarness = try makeResumeHarness(fixtureRoot)
    let invalidScopeSession = "local_resume_bad_scope_001"
    _ = try makeReceivingBaseQueue(
      invalidScopeHarness,
      localSessionID: invalidScopeSession,
      installCurrentCredential: false
    )
    let invalidScopeCode = String(repeating: "C", count: 43)
    let invalidScopeApproval = try approveResumeLaunch(
      invalidScopeHarness.gate,
      code: invalidScopeCode
    )
    do {
      _ = try await invalidScopeHarness.coordinator.resume(
        resumeInput(
          invalidScopeHarness,
          approved: invalidScopeApproval,
          localSessionID: invalidScopeSession,
          scope: Data("{}".utf8)
        )
      )
      throw ResumeLifecycleTestFailure.assertion("Invalid scope reached credential preparation")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .invalidInput, "Invalid scope surfaced the wrong error")
    }
    let retainedInvalidScope = try retainedLaunchCode(
      invalidScopeHarness.gate,
      approved: invalidScopeApproval
    )
    try require(
      retainedInvalidScope == invalidScopeCode,
      "Invalid scope consumed reviewer consent"
    )
    try require(invalidScopeHarness.credentials.values.isEmpty, "Invalid scope created credential B")
    try require(invalidScopeHarness.credentials.stores.isEmpty, "Invalid scope prepared credential B")
    try require(invalidScopeHarness.resumeJournals.journals.isEmpty, "Invalid scope created a journal")
    try require(invalidScopeHarness.exchanger.requests.isEmpty, "Invalid scope reached the network")

    let readyHarness = try makeResumeHarness(fixtureRoot)
    let readySession = "local_resume_ready_001"
    _ = try makeReceivingBaseQueue(
      readyHarness,
      localSessionID: readySession,
      expiresAt: "2026-08-21T10:00:00Z"
    )
    let readyCode = String(repeating: "D", count: 43)
    let readyApproval = try approveResumeLaunch(readyHarness.gate, code: readyCode)
    do {
      _ = try await readyHarness.coordinator.resume(
        resumeInput(readyHarness, approved: readyApproval, localSessionID: readySession)
      )
      throw ResumeLifecycleTestFailure.assertion("Ready queue consumed a RESUME launch")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .resumeNotAuthorized(.ready),
        "Ready queue surfaced the wrong refusal"
      )
    }
    let retainedReady = try retainedLaunchCode(readyHarness.gate, approved: readyApproval)
    try require(
      retainedReady == readyCode,
      "Ready queue consumed reviewer consent"
    )
    try require(readyHarness.exchanger.requests.isEmpty, "Ready queue reached the network")
    try require(readyHarness.credentials.stores.isEmpty, "Ready queue prepared credential B")
    try require(readyHarness.resumeJournals.journals.isEmpty, "Ready queue created a journal")

    let changedConfigurationHarness = try makeResumeHarness(fixtureRoot)
    let changedConfigurationSession = "local_resume_config_001"
    let otherConfiguration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://other.tacua.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    _ = try makeReceivingBaseQueue(
      changedConfigurationHarness,
      localSessionID: changedConfigurationSession,
      transportConfigurationDigest: otherConfiguration.configurationDigest,
      installCurrentCredential: false
    )
    let configCode = String(repeating: "E", count: 43)
    let configApproval = try approveResumeLaunch(
      changedConfigurationHarness.gate,
      code: configCode
    )
    do {
      _ = try await changedConfigurationHarness.coordinator.resume(
        resumeInput(
          changedConfigurationHarness,
          approved: configApproval,
          localSessionID: changedConfigurationSession
        )
      )
      throw ResumeLifecycleTestFailure.assertion("Changed transport consumed RESUME consent")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .resumeNotAuthorized(.transportConfigurationChanged),
        "Changed transport surfaced the wrong refusal"
      )
    }
    let retainedConfiguration = try retainedLaunchCode(
      changedConfigurationHarness.gate,
      approved: configApproval
    )
    try require(
      retainedConfiguration == configCode,
      "Changed transport consumed reviewer consent"
    )
    try require(
      changedConfigurationHarness.exchanger.requests.isEmpty,
      "Changed transport reached the network"
    )
    try require(
      changedConfigurationHarness.credentials.stores.isEmpty,
      "Changed transport prepared credential B"
    )
    try require(
      changedConfigurationHarness.resumeJournals.journals.isEmpty,
      "Changed transport created a journal"
    )

    let deletionHarness = try makeResumeHarness(fixtureRoot)
    let deletionSession = "local_resume_deleted_001"
    _ = try makeDeletionBaseQueue(
      deletionHarness,
      fixtureRoot: fixtureRoot,
      localSessionID: deletionSession
    )
    let deletionCode = String(repeating: "F", count: 43)
    let deletionApproval = try approveResumeLaunch(deletionHarness.gate, code: deletionCode)
    do {
      _ = try await deletionHarness.coordinator.resume(
        resumeInput(
          deletionHarness,
          approved: deletionApproval,
          localSessionID: deletionSession
        )
      )
      throw ResumeLifecycleTestFailure.assertion("Deleted queue consumed RESUME consent")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .resumeNotAuthorized(.terminalDeletion),
        "Deleted queue surfaced the wrong refusal"
      )
    }
    let retainedDeletion = try retainedLaunchCode(
      deletionHarness.gate,
      approved: deletionApproval
    )
    try require(
      retainedDeletion == deletionCode,
      "Deleted queue consumed reviewer consent"
    )
    try require(deletionHarness.exchanger.requests.isEmpty, "Deleted queue reached the network")
    try require(deletionHarness.credentials.stores.isEmpty, "Deleted queue prepared credential B")
    try require(deletionHarness.resumeJournals.journals.isEmpty, "Deleted queue created a journal")
  }

  static func deterministicFailuresCleanPreparedCredentialBeforeNetwork(
    _ fixtureRoot: URL
  ) async throws {
    let invalidClockHarness = try makeResumeHarness(fixtureRoot)
    let invalidClockSession = "local_resume_invalid_clock_001"
    let oldCredentialID = "credential_invalid_clock_old"
    _ = try makeReceivingBaseQueue(
      invalidClockHarness,
      localSessionID: invalidClockSession,
      currentCredentialID: oldCredentialID,
      expiresAt: "2026-08-21T10:00:00Z"
    )
    invalidClockHarness.clock.bootSessionID = "unavailable"
    let invalidClockCode = String(repeating: "G", count: 43)
    let invalidClockApproval = try approveResumeLaunch(
      invalidClockHarness.gate,
      code: invalidClockCode
    )
    do {
      _ = try await invalidClockHarness.coordinator.resume(
        resumeInput(
          invalidClockHarness,
          approved: invalidClockApproval,
          localSessionID: invalidClockSession
        )
      )
      throw ResumeLifecycleTestFailure.assertion("Invalid clock reached the network")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .invalidInput, "Invalid clock surfaced the wrong error")
    }
    try require(
      Set(invalidClockHarness.credentials.values.keys) == Set([oldCredentialID]),
      "Invalid clock did not remove only owned credential B"
    )
    try require(
      invalidClockHarness.credentials.removals.count == 1,
      "Invalid clock did not clean its prepared credential"
    )
    try require(
      invalidClockHarness.resumeJournals.journals.isEmpty,
      "Invalid clock retained its prepared journal"
    )
    try require(invalidClockHarness.exchanger.requests.isEmpty, "Invalid clock sent a request")
    let retainedInvalidClock = try retainedLaunchCode(
      invalidClockHarness.gate,
      approved: invalidClockApproval
    )
    try require(
      retainedInvalidClock == invalidClockCode,
      "Invalid clock consumed reviewer consent"
    )

    let historicalCredentialUUID = UUID(
      uuidString: "00000000-0000-0000-0000-000000000099"
    )!
    let historicalCredentialID =
      "credential_00000000000000000000000000000099"
    let collisionHarness = try makeResumeHarness(
      fixtureRoot,
      uuidValues: [
        UUID(uuidString: "00000000-0000-0000-0000-000000000098")!,
        historicalCredentialUUID,
      ]
    )
    let collisionSession = "local_resume_history_collision_001"
    let currentCredentialID = "credential_history_current"
    var collisionQueue = try TacuaTransportQueueV3(localSessionID: collisionSession)
    try collisionQueue.applyExchange(
      remoteSessionID: "session_history_collision",
      scopeDigest: try fixtureScopeDigest(collisionHarness),
      credentialID: historicalCredentialID,
      transportConfigurationDigest: collisionHarness.configuration.configurationDigest,
      expiresAt: "2026-07-21T10:00:00Z",
      capability: .active,
      issuedAt: "2026-07-21T09:59:00Z",
      clock: ResumeTestClock(
        uptimeMilliseconds: 40_000,
        bootSessionID: collisionHarness.clock.bootSessionID
      )
    )
    try collisionQueue.applyExchange(
      remoteSessionID: "session_history_collision",
      scopeDigest: try fixtureScopeDigest(collisionHarness),
      credentialID: currentCredentialID,
      transportConfigurationDigest: collisionHarness.configuration.configurationDigest,
      expiresAt: "2026-07-21T10:01:00Z",
      previousCredentialID: historicalCredentialID,
      capability: .active,
      issuedAt: "2026-07-21T10:00:00Z",
      clock: ResumeTestClock(
        uptimeMilliseconds: 100_000,
        bootSessionID: collisionHarness.clock.bootSessionID
      )
    )
    collisionHarness.credentials.values[currentCredentialID] = Data(repeating: 0x43, count: 32)
    collisionHarness.queues.queues[collisionSession] = collisionQueue
    let collisionCode = String(repeating: "H", count: 43)
    let collisionApproval = try approveResumeLaunch(
      collisionHarness.gate,
      code: collisionCode
    )
    do {
      _ = try await collisionHarness.coordinator.resume(
        resumeInput(
          collisionHarness,
          approved: collisionApproval,
          localSessionID: collisionSession
        )
      )
      throw ResumeLifecycleTestFailure.assertion("Historical credential collision was accepted")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .invalidInput, "Historical collision surfaced the wrong error")
    }
    try require(
      collisionHarness.credentials.values[historicalCredentialID] == nil,
      "Historical collision retained owned credential B"
    )
    try require(
      collisionHarness.credentials.values[currentCredentialID] != nil,
      "Historical collision removed current credential A"
    )
    try require(
      collisionHarness.credentials.removals == [historicalCredentialID],
      "Historical collision cleanup removed the wrong credential"
    )
    try require(
      collisionHarness.resumeJournals.journals.isEmpty,
      "Historical collision retained its prepared journal"
    )
    try require(collisionHarness.exchanger.requests.isEmpty, "Historical collision reached network")
    let retainedCollision = try retainedLaunchCode(
      collisionHarness.gate,
      approved: collisionApproval
    )
    try require(
      retainedCollision == collisionCode,
      "Historical collision consumed reviewer consent"
    )
  }
}

private extension SDKResumeLifecycleTests {
  static func networkFailureQuarantinesBothCredentials(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_network_unknown_001"
    let previousCredentialID = "credential_network_old"
    let base = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: previousCredentialID
    )
    harness.exchanger.shouldFail = true
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "I", count: 43)
    )

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(harness, approved: approved, localSessionID: localSessionID)
      )
      throw ResumeLifecycleTestFailure.assertion("Network failure reported RESUME success")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .exchangeOutcomeUnknown, "Network failure was not quarantined")
    }

    let journal = try requireValue(
      harness.resumeJournals.journals[localSessionID],
      "Network failure lost its recovery journal"
    )
    try require(
      journal.state == .exchangeOutcomeUnknown && journal.requestDigest != nil,
      "Network intent was not durable before exchange"
    )
    try require(
      harness.credentials.values[previousCredentialID] != nil,
      "Outcome-unknown cleanup removed credential A"
    )
    try require(
      harness.credentials.values[journal.newCredentialID] != nil,
      "Outcome-unknown cleanup removed credential B"
    )
    try require(
      harness.queues.queues[localSessionID] == base,
      "Outcome-unknown exchange changed the durable queue"
    )
    let status = try harness.coordinator.recoveryStatus(localSessionID: localSessionID)
    try require(
      status.state == .exchangeOutcomeUnknown
        && status.remoteCredentialMayExist
        && !status.queueUsable
        && status.requiresReconciliation
        && !status.canResetPreparedCredential,
      "Outcome-unknown status did not quarantine both credential possibilities"
    )
    do {
      try harness.coordinator.resetPrepared(localSessionID: localSessionID)
      throw ResumeLifecycleTestFailure.assertion("Outcome-unknown journal was locally reset")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .preparedResetOnly, "Blocked reset surfaced the wrong error")
    }
    try require(
      harness.resumeJournals.journals[localSessionID] == journal,
      "Blocked reset changed outcome-unknown evidence"
    )
  }

  static func preparedResetSurvivesBaseQueueMutation(_ fixtureRoot: URL) throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_prepared_mutation_001"
    let base = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: "credential_prepared_old"
    )
    let newCredentialID = "credential_prepared_owned"
    let newSecret = Data(repeating: 0x72, count: 32)
    harness.credentials.values[newCredentialID] = newSecret
    let journal = try manualPreparedJournal(
      harness: harness,
      queue: base,
      newCredentialID: newCredentialID,
      newSecret: newSecret
    )
    harness.resumeJournals.journals[localSessionID] = journal

    var mutated = base
    mutated.localPayloadPaths.append("mutated/after-preparation.bin")
    try mutated.validate()
    harness.queues.queues[localSessionID] = mutated

    try harness.coordinator.resetPrepared(localSessionID: localSessionID)

    try require(
      harness.queues.queues[localSessionID] == mutated,
      "Prepared reset rewrote a concurrently mutated base queue"
    )
    try require(
      harness.credentials.values[newCredentialID] == nil,
      "Prepared reset retained its owned credential"
    )
    try require(
      harness.credentials.removals.contains(newCredentialID),
      "Prepared reset did not remove credential B"
    )
    try require(
      harness.resumeJournals.journals[localSessionID] == nil,
      "Prepared reset retained its journal after queue mutation"
    )
  }

  static func receiptCASAmbiguityRecoversWithoutLaunch(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_receipt_cas_001"
    let previousCredentialID = "credential_receipt_cas_old"
    _ = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: previousCredentialID
    )
    harness.resumeJournals.installThenThrowReceiptCAS = true
    harness.resumeJournals.failReceiptIdempotentCAS = true
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "J", count: 43)
    )

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(harness, approved: approved, localSessionID: localSessionID)
      )
      throw ResumeLifecycleTestFailure.assertion("Receipt CAS ambiguity reported success")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .exchangeOutcomeUnknown,
        "Receipt CAS ambiguity surfaced the wrong conservative error"
      )
    }
    let receiptJournal = try requireValue(
      harness.resumeJournals.journals[localSessionID],
      "Ambiguously installed receipt journal disappeared"
    )
    try require(
      receiptJournal.state == .receiptValidatedQueueCommitPending,
      "Installed receipt was not discoverable after CAS ambiguity"
    )
    let status = try harness.coordinator.recoveryStatus(localSessionID: localSessionID)
    try require(
      status.state == .receiptValidatedQueueCommitPending && status.canRecoverWithoutLaunch,
      "Installed receipt did not advertise no-launch recovery"
    )
    let exchangeCount = harness.exchanger.requests.count

    let recovered = try harness.coordinator.recover(localSessionID: localSessionID)

    try require(
      harness.exchanger.requests.count == exchangeCount,
      "Receipt recovery performed a second network exchange"
    )
    try require(
      recovered.credentialID == receiptJournal.newCredentialID,
      "Receipt recovery committed the wrong credential"
    )
    try require(
      harness.credentials.values[previousCredentialID] == nil,
      "Receipt recovery did not clean credential A"
    )
    try require(harness.resumeJournals.journals.isEmpty, "Receipt recovery retained a journal")
  }

  static func installedResultRecoversWithoutLaunch(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_install_throw_001"
    _ = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: "credential_install_throw_old"
    )
    harness.queues.installThenThrowAttempts = [1]
    harness.queues.failAttempts = [2]
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "K", count: 43)
    )

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(harness, approved: approved, localSessionID: localSessionID)
      )
      throw ResumeLifecycleTestFailure.assertion("Install-then-throw queue reported success")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .receiptCommitPending,
        "Install-then-throw result surfaced the wrong error"
      )
    }
    let journal = try requireValue(
      harness.resumeJournals.journals[localSessionID],
      "Install-then-throw lost its receipt journal"
    )
    let installed = try requireValue(
      harness.queues.queues[localSessionID],
      "Install-then-throw did not leave the result queue"
    )
    try require(
      journal.state == .receiptValidatedQueueCommitPending,
      "Install-then-throw lost validated receipt state"
    )
    let installedDigest = TacuaCanonicalJSON.digest(data: try installed.encoded())
    try require(
      installedDigest == journal.validatedReceipt?.resultQueueDigest,
      "Installed queue did not match the durable result digest"
    )
    try require(
      harness.queues.compareAndSwapAttempts == 2,
      "Initial ambiguity did not retry the installed result"
    )
    let exchangeCount = harness.exchanger.requests.count

    let recovered = try harness.coordinator.recover(localSessionID: localSessionID)

    try require(
      harness.queues.compareAndSwapAttempts == 3,
      "Recovery trusted an ambiguously installed result without re-persisting"
    )
    try require(
      harness.queues.events.contains("queue_cas_success_3"),
      "Recovery did not confirm the installed result queue"
    )
    try require(
      harness.exchanger.requests.count == exchangeCount,
      "Installed-result recovery consumed another launch"
    )
    try require(
      recovered.credentialID == journal.newCredentialID,
      "Installed-result recovery returned the wrong credential"
    )
    try require(harness.resumeJournals.journals.isEmpty, "Installed-result journal survived")
  }

  static func journalCleanupGatesQueueUntilRecovery(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_cleanup_gate_001"
    _ = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: "credential_cleanup_gate_old"
    )
    harness.resumeJournals.failNextRemove = true
    harness.resumeJournals.failNextConfirmAbsent = true
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "L", count: 43)
    )

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(harness, approved: approved, localSessionID: localSessionID)
      )
      throw ResumeLifecycleTestFailure.assertion("Unconfirmed journal cleanup released queue")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .journalCleanupRequired,
        "Unconfirmed journal cleanup surfaced the wrong error"
      )
    }
    let journal = try requireValue(
      harness.resumeJournals.journals[localSessionID],
      "Cleanup failure did not retain its journal gate"
    )
    let committed = try requireValue(
      harness.queues.queues[localSessionID],
      "Cleanup failure lost its committed result queue"
    )
    let committedDigest = TacuaCanonicalJSON.digest(data: try committed.encoded())
    try require(
      committedDigest == journal.validatedReceipt?.resultQueueDigest,
      "Cleanup gate did not describe the committed queue"
    )
    let status = try harness.coordinator.recoveryStatus(localSessionID: localSessionID)
    try require(
      status.state == .receiptValidatedQueueCommitPending
        && !status.queueUsable
        && status.canRecoverWithoutLaunch,
      "Journal cleanup failure exposed the result queue too early"
    )

    let recovered = try harness.coordinator.recover(localSessionID: localSessionID)

    try require(recovered.credentialID == journal.newCredentialID, "Cleanup recovery changed result")
    try require(harness.resumeJournals.journals.isEmpty, "Cleanup recovery retained the gate")
  }

  static func anchorRegressionRemainsOutcomeUnknown(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_anchor_regression_001"
    let base = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: "credential_anchor_old",
      expiresAt: "2026-08-21T10:05:00Z",
      installCurrentCredential: false,
      issuedAt: "2026-07-21T10:05:00Z"
    )
    harness.exchanger.issuedAt = "2026-07-21T10:04:00Z"
    harness.exchanger.expiresAt = "2026-08-21T10:04:00Z"
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "M", count: 43)
    )

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(
          harness,
          approved: approved,
          localSessionID: localSessionID,
          requestedAt: "2026-07-21T10:06:00Z"
        )
      )
      throw ResumeLifecycleTestFailure.assertion("Regressed server anchor was committed")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .exchangeOutcomeUnknown, "Anchor regression was not quarantined")
    }
    let journal = try requireValue(
      harness.resumeJournals.journals[localSessionID],
      "Anchor regression lost outcome evidence"
    )
    try require(
      journal.state == .exchangeOutcomeUnknown && journal.validatedReceipt == nil,
      "Anchor regression manufactured validated recovery"
    )
    try require(
      harness.queues.queues[localSessionID] == base,
      "Anchor regression changed the durable queue"
    )
    try require(
      harness.credentials.values[journal.newCredentialID] != nil,
      "Anchor regression removed possible remote credential B"
    )
    do {
      try harness.coordinator.resetPrepared(localSessionID: localSessionID)
      throw ResumeLifecycleTestFailure.assertion("Anchor-regressed outcome was locally reset")
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .preparedResetOnly, "Anchor reset refusal surfaced the wrong error")
    }
  }

  static func receiptReceivedBeforeBaseFloorIsQuarantined(
    _ fixtureRoot: URL
  ) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_received_floor_001"
    var base = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: "credential_received_floor_old",
      expiresAt: "2026-08-21T10:00:00Z",
      installCurrentCredential: false
    )
    try base.advanceTimeAnchor(
      authoritativeServerTimestamp: "2026-07-21T10:05:00Z",
      clock: harness.clock
    )
    harness.queues.queues[localSessionID] = base
    // This response is otherwise valid and is re-sealed by the exchanger. Its issued_at advances
    // authority, but received_at predates the queue's independently established 10:05 floor.
    harness.exchanger.receivedAt = "2026-07-21T10:04:59Z"
    harness.exchanger.issuedAt = "2026-07-21T10:06:00Z"
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "Q", count: 43)
    )

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(harness, approved: approved, localSessionID: localSessionID)
      )
      throw ResumeLifecycleTestFailure.assertion(
        "Receipt received before base authority floor was committed"
      )
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(
        error == .exchangeOutcomeUnknown,
        "Pre-floor received_at was not conservatively quarantined"
      )
    }

    let journal = try requireValue(
      harness.resumeJournals.journals[localSessionID],
      "Pre-floor receipt lost its outcome-unknown journal"
    )
    try require(
      journal.state == .exchangeOutcomeUnknown && journal.validatedReceipt == nil,
      "Pre-floor receipt manufactured validated recovery authority"
    )
    try require(
      harness.credentials.values[journal.newCredentialID] != nil,
      "Pre-floor receipt quarantine removed credential B"
    )
    try require(
      harness.queues.queues[localSessionID] == base,
      "Pre-floor receipt changed the durable queue"
    )
    try require(
      harness.exchanger.requests.count == 1,
      "Pre-floor receipt test did not exercise one network exchange"
    )
  }

  static func migratedV2BindingResumesSuccessfully(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_v2_rebind_001"
    let previousCredentialID = "credential_v2_unbound_old"
    var migrated = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: previousCredentialID,
      expiresAt: "2026-08-21T10:00:00Z"
    )
    migrated.transportConfigurationDigest = nil
    migrated.credentialCapability = .requiresTransportRebind
    try migrated.validate()
    harness.queues.queues[localSessionID] = migrated
    let approved = try approveResumeLaunch(
      harness.gate,
      code: String(repeating: "N", count: 43)
    )

    let resumed = try await harness.coordinator.resume(
      resumeInput(harness, approved: approved, localSessionID: localSessionID)
    )

    try require(resumed.backendSessionState == .receiving, "V2 rebind changed session state")
    try require(resumed.credentialCapability == .active, "V2 rebind remained transport-blocked")
    let rebound = try requireValue(
      harness.queues.queues[localSessionID],
      "V2 rebind did not commit a queue"
    )
    try require(
      rebound.transportConfigurationDigest == harness.configuration.configurationDigest,
      "V2 nil transport binding was not pinned by RESUME"
    )
    try require(
      rebound.currentCredentialID == resumed.credentialID,
      "V2 rebind kept credential A"
    )
    try require(
      harness.credentials.values[previousCredentialID] == nil,
      "V2 rebind did not clean revoked credential A"
    )
    try require(harness.resumeJournals.journals.isEmpty, "V2 rebind retained a journal")
  }

  static func nearLimitV2ResumeReservesReceiptAnchorGrowth(
    _ fixtureRoot: URL
  ) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_v2_anchor_reserve_001"
    let previousCredentialID = "credential_v2_reserve_old"
    let generatedCredentialID = "credential_00000000000000000000000000000002"
    let requestedAt = "2026-07-21T10:05:00Z"
    let maximumBytes = TacuaTransportQueueV3.maximumEncodedBytes
    let requiredGrowthReserve = 56

    func queue(paddingByteCount: Int) throws -> TacuaTransportQueueV3 {
      var value = try TacuaTransportQueueV3(localSessionID: localSessionID)
      try value.applyExchange(
        remoteSessionID: "session_v2_anchor_reserve",
        scopeDigest: try fixtureScopeDigest(harness),
        credentialID: previousCredentialID,
        transportConfigurationDigest: harness.configuration.configurationDigest,
        expiresAt: "2026-08-21T10:00:00Z",
        capability: .active,
        issuedAt: "2026-07-21T10:00:00Z",
        clock: ResumeTestClock(
          uptimeMilliseconds: 100_000,
          bootSessionID: harness.clock.bootSessionID
        )
      )
      func request(paddingByteCount: Int) throws -> (Data, String) {
        var object: [String: TacuaJSONValue] = [
          "padding": .string(String(repeating: "p", count: paddingByteCount)),
          "request_digest": .string("sha256:" + String(repeating: "0", count: 64)),
        ]
        let digest = try TacuaCanonicalJSON.digest(
          .object(object),
          omittingRootField: "request_digest"
        )
        object["request_digest"] = .string(digest)
        return (try TacuaCanonicalJSON.data(.object(object)), digest)
      }
      func operation(
        index: Int,
        canonicalRequest: Data,
        requestDigest: String
      ) -> TacuaQueuedOperation {
        TacuaQueuedOperation(
          kind: .diagnostic,
          operationID: String(format: "upload_v2_anchor_reserve_%02d", index),
          requestCredentialID: previousCredentialID,
          requestDigest: requestDigest,
          canonicalRequest: canonicalRequest,
          localPayloadPath: nil,
          localPayloadBindings: nil,
          state: .queued,
          canonicalResponse: nil,
          responseDigest: nil,
          responseArtifactDigest: nil
        )
      }
      // Canonical queue artifacts are individually capped at 4 MiB. Seven shared 3 MB requests
      // provide most of the bulk; only the eighth request changes during boundary calibration.
      let fixedRequestCount = 7
      let fixedPaddingBytes = 3_000_000
      let variablePaddingBytes = paddingByteCount - fixedRequestCount * fixedPaddingBytes
      guard variablePaddingBytes > 0 else {
        throw ResumeLifecycleTestFailure.assertion("Reserve fixture padding is too small")
      }
      let fixed = try request(paddingByteCount: fixedPaddingBytes)
      var operations = (0..<fixedRequestCount).map {
        operation(index: $0, canonicalRequest: fixed.0, requestDigest: fixed.1)
      }
      let variable = try request(paddingByteCount: variablePaddingBytes)
      operations.append(
        operation(
          index: fixedRequestCount,
          canonicalRequest: variable.0,
          requestDigest: variable.1
        )
      )
      value.operations = operations
      value.transportConfigurationDigest = nil
      value.credentialCapability = .requiresTransportRebind
      try value.validate()
      return value
    }

    func oldSyntheticSize(_ base: TacuaTransportQueueV3) throws -> Int {
      let requestedEpoch = try requireValue(
        TacuaProtocolTimestamp.parseMilliseconds(requestedAt),
        "Reserve fixture timestamp is invalid"
      )
      let issueEpoch = max(
        base.timeAnchor?.minimumEpochMilliseconds ?? requestedEpoch,
        requestedEpoch
      )
      let anchor = try TacuaServerTimeAnchor.establish(
        issuedAt: TacuaProtocolTimestamp.format(milliseconds: issueEpoch),
        clock: harness.clock
      )
      var candidate = base
      try candidate.applyRecoveredResume(
        expectedCurrentCredentialID: previousCredentialID,
        newCredentialID: generatedCredentialID,
        transportConfigurationDigest: harness.configuration.configurationDigest,
        expiresAt: TacuaProtocolTimestamp.format(
          milliseconds: issueEpoch + 31_536_000_000
        ),
        capability: .active,
        replayCompletionID: nil,
        timeAnchor: anchor
      )
      return try candidate.encoded().count
    }

    // Queue Data is base64 in the durable JSON, so three padding bytes change the encoded queue
    // by four bytes. Calibrate once toward the middle of the final 56-byte window.
    let seedPaddingBytes = 25_000_000
    let seedSize = try oldSyntheticSize(queue(paddingByteCount: seedPaddingBytes))
    let targetSize = maximumBytes - 28
    let calibratedPaddingBytes = seedPaddingBytes + ((targetSize - seedSize) * 3 / 4)
    let base = try queue(paddingByteCount: calibratedPaddingBytes)
    let oldSyntheticEncodingSize = try oldSyntheticSize(base)
    try require(
      oldSyntheticEncodingSize <= maximumBytes,
      "Old dry-run encoding no longer fits the queue limit"
    )
    try require(
      oldSyntheticEncodingSize > maximumBytes - requiredGrowthReserve,
      "Near-limit fixture accidentally leaves the 56-byte receipt-anchor reserve"
    )
    try require(
      base.transportConfigurationDigest == nil
        && base.credentialCapability == .requiresTransportRebind,
      "Near-limit fixture is not a migrated V2 nil-binding queue"
    )
    harness.credentials.values[previousCredentialID] = Data(repeating: 0x31, count: 32)
    harness.queues.queues[localSessionID] = base
    let launchCode = String(repeating: "P", count: 43)
    let approved = try approveResumeLaunch(harness.gate, code: launchCode)

    do {
      _ = try await harness.coordinator.resume(
        resumeInput(
          harness,
          approved: approved,
          localSessionID: localSessionID,
          requestedAt: requestedAt
        )
      )
      throw ResumeLifecycleTestFailure.assertion(
        "Near-limit V2 queue reached a receipt that may outgrow durable storage"
      )
    } catch let error as TacuaSDKResumeLifecycleError {
      try require(error == .invalidInput, "Growth-reserve refusal surfaced the wrong error")
    }

    try require(
      harness.exchanger.requests.isEmpty,
      "Growth-reserve refusal reached the network"
    )
    let retained = try retainedLaunchCode(harness.gate, approved: approved)
    try require(retained == launchCode, "Growth-reserve refusal consumed reviewer consent")
    try require(
      harness.credentials.values[previousCredentialID] != nil,
      "Growth-reserve cleanup removed credential A"
    )
    try require(
      harness.credentials.values[generatedCredentialID] == nil,
      "Growth-reserve cleanup retained prepared credential B"
    )
    try require(
      harness.credentials.stores == [generatedCredentialID]
        && harness.credentials.removals == [generatedCredentialID],
      "Growth-reserve cleanup did not remove exactly its owned credential B"
    )
    try require(
      harness.resumeJournals.journals[localSessionID] == nil,
      "Growth-reserve cleanup retained its prepared journal"
    )
    try require(
      harness.queues.queues[localSessionID] == base,
      "Growth-reserve refusal changed the V2 base queue"
    )
  }

  static func startAndQueueStatusAreCrossGated(_ fixtureRoot: URL) async throws {
    let harness = try makeResumeHarness(fixtureRoot)
    let localSessionID = "local_resume_cross_gate_001"
    let base = try makeReceivingBaseQueue(
      harness,
      localSessionID: localSessionID,
      currentCredentialID: "credential_cross_gate_old"
    )
    let newCredentialID = "credential_cross_gate_new"
    let newSecret = Data(repeating: 0x61, count: 32)
    harness.credentials.values[newCredentialID] = newSecret
    let prepared = try manualPreparedJournal(
      harness: harness,
      queue: base,
      newCredentialID: newCredentialID,
      newSecret: newSecret
    )
    let uncertain = try prepared.advancing(
      to: .exchangeOutcomeUnknown,
      requestDigest: "sha256:" + String(repeating: "a", count: 64)
    )
    harness.resumeJournals.journals[localSessionID] = uncertain
    let startCoordinator = TacuaSDKStartLifecycleCoordinator(
      configuration: harness.configuration,
      consentGate: harness.gate,
      credentialFactory: harness.credentialFactory,
      exchanger: harness.exchanger,
      queueStore: harness.queues,
      journalStore: harness.startJournals,
      resumeRecoveryInspector: harness.resumeJournals,
      clock: harness.clock
    )
    let code = String(repeating: "O", count: 43)
    let approved = try approveResumeLaunch(harness.gate, code: code)

    do {
      _ = try await startCoordinator.start(
        startInput(harness, approved: approved, localSessionID: localSessionID)
      )
      throw ResumeLifecycleTestFailure.assertion("START bypassed a RESUME journal")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .resumeRecoveryActionRequired,
        "START cross-gate surfaced the wrong error"
      )
    }
    let retainedStart = try retainedLaunchCode(harness.gate, approved: approved)
    try require(
      retainedStart == code,
      "START cross-gate consumed reviewer consent"
    )
    do {
      _ = try startCoordinator.queueStatus(localSessionID: localSessionID)
      throw ResumeLifecycleTestFailure.assertion("Queue status exposed quarantined authority")
    } catch let error as TacuaSDKStartLifecycleError {
      try require(
        error == .resumeRecoveryActionRequired,
        "Queue cross-gate surfaced the wrong error"
      )
    }
    try require(
      harness.resumeJournals.journals[localSessionID] == uncertain,
      "START/queue cross-gating changed RESUME evidence"
    )
    try require(harness.exchanger.requests.isEmpty, "Cross-gated START reached the network")
  }
}
