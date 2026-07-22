// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

enum TacuaSDKResumeJournalError: Error, Equatable {
  case invalidJournal
  case invalidSessionID
  case ownershipConflict
  case stateConflict
}

enum TacuaSDKResumeExpectedSessionState: String, Equatable {
  case receiving
  case completed
}

enum TacuaSDKResumeJournalState: String, Equatable {
  /// Resume identifiers and the ownership verifier are durable, but the new Keychain item or
  /// transient launch request may not exist yet. This is the only state that may be abandoned.
  case credentialPrepared = "credential_prepared"
  /// The exact request digest was durable before network I/O. The backend may have atomically
  /// revoked the previous credential and installed the new one, so this state is non-abandonable.
  case exchangeOutcomeUnknown = "exchange_outcome_unknown"
  /// A receipt was independently validated. The exact resulting queue digest is durable, but the
  /// queue CAS may have installed either the base or result when a filesystem error was reported.
  case receiptValidatedQueueCommitPending = "receipt_validated_queue_commit_pending"
  /// Reset won the only safe abandon transition, before any network intent became durable.
  case credentialPreparedResetPending = "credential_prepared_reset_pending"
}

struct TacuaSDKResumeReceiptRecovery: Equatable {
  let credentialCapability: TacuaTransportCredentialCapability
  let replayCompletionID: String?
  let credentialExpiresAt: String
  let responseDigest: String
  let resultQueueDigest: String
  /// The exact anchor established from the validated receipt. Recovery must not re-anchor an old
  /// server timestamp to a later uptime or boot session.
  let timeAnchor: TacuaServerTimeAnchor
}

struct TacuaSDKResumeJournal: Equatable {
  static let schemaVersion: Int64 = 2
  private static let legacySchemaVersion: Int64 = 1
  static let maximumEncodedBytes = 2 * 1_024 * 1_024

  let localSessionID: String
  let baseQueueDigest: String
  let previousCredentialID: String
  let remoteSessionID: String
  let scopeDigest: String
  let expectedSessionState: TacuaSDKResumeExpectedSessionState
  let expectedCompletionID: String?
  let transportConfigurationDigest: String
  /// Canonical public artifacts required to reproduce a migrated-queue backfill after a crash.
  /// Credential material and the transient launch request are intentionally absent.
  let buildIdentityJSON: String?
  let captureScopeJSON: String?
  let exchangeID: String
  let newCredentialID: String
  let newCredentialOwnershipDigest: String
  let createdAt: String
  let state: TacuaSDKResumeJournalState
  let requestDigest: String?
  let validatedReceipt: TacuaSDKResumeReceiptRecovery?

  init(
    localSessionID: String,
    baseQueueDigest: String,
    previousCredentialID: String,
    remoteSessionID: String,
    scopeDigest: String,
    expectedSessionState: TacuaSDKResumeExpectedSessionState,
    expectedCompletionID: String?,
    transportConfigurationDigest: String,
    buildIdentityJSON: String? = nil,
    captureScopeJSON: String? = nil,
    exchangeID: String,
    newCredentialID: String,
    newCredentialOwnershipDigest: String,
    createdAt: String,
    state: TacuaSDKResumeJournalState,
    requestDigest: String? = nil,
    validatedReceipt: TacuaSDKResumeReceiptRecovery? = nil
  ) throws {
    self.localSessionID = localSessionID
    self.baseQueueDigest = baseQueueDigest
    self.previousCredentialID = previousCredentialID
    self.remoteSessionID = remoteSessionID
    self.scopeDigest = scopeDigest
    self.expectedSessionState = expectedSessionState
    self.expectedCompletionID = expectedCompletionID
    self.transportConfigurationDigest = transportConfigurationDigest
    self.buildIdentityJSON = buildIdentityJSON
    self.captureScopeJSON = captureScopeJSON
    self.exchangeID = exchangeID
    self.newCredentialID = newCredentialID
    self.newCredentialOwnershipDigest = newCredentialOwnershipDigest
    self.createdAt = createdAt
    self.state = state
    self.requestDigest = requestDigest
    self.validatedReceipt = validatedReceipt
    try validate()
  }

  func advancing(
    to nextState: TacuaSDKResumeJournalState,
    requestDigest suppliedRequestDigest: String? = nil,
    validatedReceipt suppliedReceipt: TacuaSDKResumeReceiptRecovery? = nil
  ) throws -> TacuaSDKResumeJournal {
    let nextRequestDigest: String?
    let nextReceipt: TacuaSDKResumeReceiptRecovery?
    switch (state, nextState) {
    case (.credentialPrepared, .exchangeOutcomeUnknown):
      guard let suppliedRequestDigest else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      nextRequestDigest = suppliedRequestDigest
      nextReceipt = nil
    case (.exchangeOutcomeUnknown, .receiptValidatedQueueCommitPending):
      guard let requestDigest, let suppliedReceipt else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      nextRequestDigest = requestDigest
      nextReceipt = suppliedReceipt
    case (.receiptValidatedQueueCommitPending, .receiptValidatedQueueCommitPending):
      nextRequestDigest = requestDigest
      nextReceipt = suppliedReceipt ?? validatedReceipt
    case (.credentialPrepared, .credentialPreparedResetPending),
      (.credentialPreparedResetPending, .credentialPreparedResetPending):
      nextRequestDigest = nil
      nextReceipt = nil
    default:
      // In particular, exchangeOutcomeUnknown has no reset/abandon transition. Deleting the new
      // credential here could destroy the backend's only current credential after response loss.
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    return try replacing(
      state: nextState,
      requestDigest: nextRequestDigest,
      validatedReceipt: nextReceipt
    )
  }

  func encoded() throws -> Data {
    try validate()
    let receiptValue: TacuaJSONValue
    if let validatedReceipt {
      receiptValue = .object([
        "credential_capability": .string(validatedReceipt.credentialCapability.rawValue),
        "credential_expires_at": .string(validatedReceipt.credentialExpiresAt),
        "replay_completion_id": validatedReceipt.replayCompletionID.map(TacuaJSONValue.string)
          ?? .null,
        "response_digest": .string(validatedReceipt.responseDigest),
        "result_queue_digest": .string(validatedReceipt.resultQueueDigest),
        "time_anchor": .object([
          "boot_session_id": .string(validatedReceipt.timeAnchor.bootSessionID),
          "issued_at": .string(validatedReceipt.timeAnchor.issuedAt),
          "issued_epoch_milliseconds": .integer(
            validatedReceipt.timeAnchor.issuedEpochMilliseconds
          ),
          "minimum_epoch_milliseconds": .integer(
            validatedReceipt.timeAnchor.minimumEpochMilliseconds
          ),
          "uptime_milliseconds_at_issue": .integer(
            validatedReceipt.timeAnchor.uptimeMillisecondsAtIssue
          ),
        ]),
      ])
    } else {
      receiptValue = .null
    }
    let data = try TacuaCanonicalJSON.data(.object([
      "base_queue_digest": .string(baseQueueDigest),
      "build_identity_json": buildIdentityJSON.map(TacuaJSONValue.string) ?? .null,
      "capture_scope_json": captureScopeJSON.map(TacuaJSONValue.string) ?? .null,
      "created_at": .string(createdAt),
      "exchange_id": .string(exchangeID),
      "expected_completion_id": expectedCompletionID.map(TacuaJSONValue.string) ?? .null,
      "expected_session_state": .string(expectedSessionState.rawValue),
      "local_session_id": .string(localSessionID),
      "new_credential_id": .string(newCredentialID),
      "new_credential_ownership_digest": .string(newCredentialOwnershipDigest),
      "previous_credential_id": .string(previousCredentialID),
      "remote_session_id": .string(remoteSessionID),
      "request_digest": requestDigest.map(TacuaJSONValue.string) ?? .null,
      "schema_version": .integer(Self.schemaVersion),
      "scope_digest": .string(scopeDigest),
      "state": .string(state.rawValue),
      "transport_configuration_digest": .string(transportConfigurationDigest),
      "validated_receipt": receiptValue,
    ]))
    guard data.count <= Self.maximumEncodedBytes else {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    return data
  }

  static func decode(_ data: Data) throws -> TacuaSDKResumeJournal {
    do {
      guard !data.isEmpty, data.count <= maximumEncodedBytes else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      let value = try TacuaCanonicalJSON.parse(data, maximumBytes: maximumEncodedBytes)
      guard try TacuaCanonicalJSON.data(value) == data else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      guard let schema = value.objectValue?["schema_version"]?.integerValue,
        schema == schemaVersion || schema == legacySchemaVersion
      else { throw TacuaSDKResumeJournalError.invalidJournal }
      let root = try value.requiringObject(keys: schema == schemaVersion ? [
        "base_queue_digest", "build_identity_json", "capture_scope_json", "created_at",
        "exchange_id", "expected_completion_id", "expected_session_state", "local_session_id",
        "new_credential_id", "new_credential_ownership_digest", "previous_credential_id",
        "remote_session_id", "request_digest", "schema_version", "scope_digest", "state",
        "transport_configuration_digest", "validated_receipt",
      ] : [
        "base_queue_digest", "created_at", "exchange_id", "expected_completion_id",
        "expected_session_state", "local_session_id", "new_credential_id",
        "new_credential_ownership_digest", "previous_credential_id", "remote_session_id",
        "request_digest", "schema_version", "scope_digest", "state",
        "transport_configuration_digest", "validated_receipt",
      ])
      guard
        let localSessionID = root["local_session_id"]?.stringValue,
        let baseQueueDigest = root["base_queue_digest"]?.stringValue,
        let previousCredentialID = root["previous_credential_id"]?.stringValue,
        let remoteSessionID = root["remote_session_id"]?.stringValue,
        let scopeDigest = root["scope_digest"]?.stringValue,
        let rawExpectedState = root["expected_session_state"]?.stringValue,
        let expectedSessionState = TacuaSDKResumeExpectedSessionState(rawValue: rawExpectedState),
        let expectedCompletionValue = root["expected_completion_id"],
        let transportConfigurationDigest = root["transport_configuration_digest"]?.stringValue,
        let exchangeID = root["exchange_id"]?.stringValue,
        let newCredentialID = root["new_credential_id"]?.stringValue,
        let newCredentialOwnershipDigest = root["new_credential_ownership_digest"]?.stringValue,
        let createdAt = root["created_at"]?.stringValue,
        let rawState = root["state"]?.stringValue,
        let state = TacuaSDKResumeJournalState(rawValue: rawState),
        let requestDigestValue = root["request_digest"],
        let receiptValue = root["validated_receipt"]
      else { throw TacuaSDKResumeJournalError.invalidJournal }

      let buildIdentityJSON: String?
      let captureScopeJSON: String?
      if schema == schemaVersion {
        guard let buildValue = root["build_identity_json"],
          let scopeValue = root["capture_scope_json"]
        else { throw TacuaSDKResumeJournalError.invalidJournal }
        buildIdentityJSON = try nullableString(buildValue)
        captureScopeJSON = try nullableString(scopeValue)
      } else {
        buildIdentityJSON = nil
        captureScopeJSON = nil
      }

      let expectedCompletionID = try nullableString(expectedCompletionValue)
      let requestDigest = try nullableString(requestDigestValue)
      let validatedReceipt: TacuaSDKResumeReceiptRecovery?
      switch receiptValue {
      case .null:
        validatedReceipt = nil
      case .object:
        let receipt = try receiptValue.requiringObject(keys: [
          "credential_capability", "credential_expires_at", "replay_completion_id",
          "response_digest", "result_queue_digest", "time_anchor",
        ])
        guard let rawCapability = receipt["credential_capability"]?.stringValue,
          let capability = TacuaTransportCredentialCapability(rawValue: rawCapability),
          let replayValue = receipt["replay_completion_id"],
          let expiresAt = receipt["credential_expires_at"]?.stringValue,
          let responseDigest = receipt["response_digest"]?.stringValue,
          let resultQueueDigest = receipt["result_queue_digest"]?.stringValue,
          let anchorValue = receipt["time_anchor"]
        else { throw TacuaSDKResumeJournalError.invalidJournal }
        let anchor = try anchorValue.requiringObject(keys: [
          "boot_session_id", "issued_at", "issued_epoch_milliseconds",
          "minimum_epoch_milliseconds", "uptime_milliseconds_at_issue",
        ])
        guard let bootSessionID = anchor["boot_session_id"]?.stringValue,
          let issuedAt = anchor["issued_at"]?.stringValue,
          let issuedEpochMilliseconds = anchor["issued_epoch_milliseconds"]?.integerValue,
          let minimumEpochMilliseconds = anchor["minimum_epoch_milliseconds"]?.integerValue,
          let uptimeMillisecondsAtIssue = anchor["uptime_milliseconds_at_issue"]?.integerValue
        else { throw TacuaSDKResumeJournalError.invalidJournal }
        validatedReceipt = TacuaSDKResumeReceiptRecovery(
          credentialCapability: capability,
          replayCompletionID: try nullableString(replayValue),
          credentialExpiresAt: expiresAt,
          responseDigest: responseDigest,
          resultQueueDigest: resultQueueDigest,
          timeAnchor: TacuaServerTimeAnchor(
            issuedAt: issuedAt,
            issuedEpochMilliseconds: issuedEpochMilliseconds,
            uptimeMillisecondsAtIssue: uptimeMillisecondsAtIssue,
            bootSessionID: bootSessionID,
            minimumEpochMilliseconds: minimumEpochMilliseconds
          )
        )
      default:
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      return try TacuaSDKResumeJournal(
        localSessionID: localSessionID,
        baseQueueDigest: baseQueueDigest,
        previousCredentialID: previousCredentialID,
        remoteSessionID: remoteSessionID,
        scopeDigest: scopeDigest,
        expectedSessionState: expectedSessionState,
        expectedCompletionID: expectedCompletionID,
        transportConfigurationDigest: transportConfigurationDigest,
        buildIdentityJSON: buildIdentityJSON,
        captureScopeJSON: captureScopeJSON,
        exchangeID: exchangeID,
        newCredentialID: newCredentialID,
        newCredentialOwnershipDigest: newCredentialOwnershipDigest,
        createdAt: createdAt,
        state: state,
        requestDigest: requestDigest,
        validatedReceipt: validatedReceipt
      )
    } catch let error as TacuaSDKResumeJournalError {
      throw error
    } catch {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
  }

  fileprivate func permitsReplacement(_ replacement: TacuaSDKResumeJournal) -> Bool {
    guard sameExchangeIdentity(as: replacement) else { return false }
    if self == replacement { return true }
    return (try? advancing(
      to: replacement.state,
      requestDigest: replacement.requestDigest,
      validatedReceipt: replacement.validatedReceipt
    )) == replacement
  }

  private func replacing(
    state: TacuaSDKResumeJournalState,
    requestDigest: String?,
    validatedReceipt: TacuaSDKResumeReceiptRecovery?
  ) throws -> TacuaSDKResumeJournal {
    try TacuaSDKResumeJournal(
      localSessionID: localSessionID,
      baseQueueDigest: baseQueueDigest,
      previousCredentialID: previousCredentialID,
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      expectedSessionState: expectedSessionState,
      expectedCompletionID: expectedCompletionID,
      transportConfigurationDigest: transportConfigurationDigest,
      buildIdentityJSON: buildIdentityJSON,
      captureScopeJSON: captureScopeJSON,
      exchangeID: exchangeID,
      newCredentialID: newCredentialID,
      newCredentialOwnershipDigest: newCredentialOwnershipDigest,
      createdAt: createdAt,
      state: state,
      requestDigest: requestDigest,
      validatedReceipt: validatedReceipt
    )
  }

  private func sameExchangeIdentity(as other: TacuaSDKResumeJournal) -> Bool {
    localSessionID == other.localSessionID
      && baseQueueDigest == other.baseQueueDigest
      && previousCredentialID == other.previousCredentialID
      && remoteSessionID == other.remoteSessionID
      && scopeDigest == other.scopeDigest
      && expectedSessionState == other.expectedSessionState
      && expectedCompletionID == other.expectedCompletionID
      && transportConfigurationDigest == other.transportConfigurationDigest
      && buildIdentityJSON == other.buildIdentityJSON
      && captureScopeJSON == other.captureScopeJSON
      && exchangeID == other.exchangeID
      && newCredentialID == other.newCredentialID
      && newCredentialOwnershipDigest == other.newCredentialOwnershipDigest
      && createdAt == other.createdAt
  }

  private func validate() throws {
    guard Self.validIdentifier(localSessionID), Self.validDigest(baseQueueDigest),
      Self.validIdentifier(previousCredentialID), Self.validIdentifier(remoteSessionID),
      Self.validDigest(scopeDigest), Self.validDigest(transportConfigurationDigest),
      Self.validIdentifier(exchangeID), Self.validIdentifier(newCredentialID),
      previousCredentialID != newCredentialID,
      Self.validDigest(newCredentialOwnershipDigest), Self.timestampMilliseconds(createdAt) != nil,
      requestDigest.map(Self.validDigest) ?? true
    else { throw TacuaSDKResumeJournalError.invalidJournal }
    let artifacts: TacuaDurableSessionArtifacts?
    switch (buildIdentityJSON, captureScopeJSON) {
    case (nil, nil):
      artifacts = nil
    case (.some(let build), .some(let scope)):
      do {
        artifacts = try TacuaDurableSessionArtifacts.exactCanonical(
          buildIdentityJSON: build,
          scopeJSON: scope
        )
      } catch {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      guard artifacts?.scopeDigest == scopeDigest,
        artifacts?.transportConfigurationDigest == transportConfigurationDigest
      else { throw TacuaSDKResumeJournalError.invalidJournal }
    default:
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    switch expectedSessionState {
    case .receiving:
      guard expectedCompletionID == nil else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
    case .completed:
      guard expectedCompletionID.map(Self.validIdentifier) == true else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
    }
    switch state {
    case .credentialPrepared, .credentialPreparedResetPending:
      guard requestDigest == nil, validatedReceipt == nil else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
    case .exchangeOutcomeUnknown:
      guard requestDigest != nil, validatedReceipt == nil else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
    case .receiptValidatedQueueCommitPending:
      guard requestDigest != nil, let validatedReceipt else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      try validate(receipt: validatedReceipt)
    }
  }

  func durableSessionArtifacts() throws -> TacuaDurableSessionArtifacts? {
    guard let buildIdentityJSON, let captureScopeJSON else {
      guard self.buildIdentityJSON == nil, self.captureScopeJSON == nil else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      return nil
    }
    do {
      return try TacuaDurableSessionArtifacts.exactCanonical(
        buildIdentityJSON: buildIdentityJSON,
        scopeJSON: captureScopeJSON
      )
    } catch {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
  }

  private func validate(receipt: TacuaSDKResumeReceiptRecovery) throws {
    guard Self.timestampMilliseconds(receipt.credentialExpiresAt) != nil,
      Self.validDigest(receipt.responseDigest), Self.validDigest(receipt.resultQueueDigest),
      receipt.resultQueueDigest != baseQueueDigest,
      let issuedEpoch = Self.timestampMilliseconds(receipt.timeAnchor.issuedAt),
      receipt.timeAnchor.issuedEpochMilliseconds == issuedEpoch,
      receipt.timeAnchor.uptimeMillisecondsAtIssue >= 0,
      Self.validBootSessionID(receipt.timeAnchor.bootSessionID),
      // A receipt recovery journal stores the original anchor. Advancing this floor belongs to the
      // queue only after commit and must never be manufactured during recovery.
      receipt.timeAnchor.minimumEpochMilliseconds == issuedEpoch,
      let expiryEpoch = Self.timestampMilliseconds(receipt.credentialExpiresAt),
      expiryEpoch > issuedEpoch
    else { throw TacuaSDKResumeJournalError.invalidJournal }
    switch expectedSessionState {
    case .receiving:
      guard receipt.credentialCapability == .active, receipt.replayCompletionID == nil else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
    case .completed:
      guard receipt.credentialCapability == .completionReplayOrDeleteOnly,
        receipt.replayCompletionID == expectedCompletionID
      else { throw TacuaSDKResumeJournalError.invalidJournal }
    }
  }

  private static func nullableString(_ value: TacuaJSONValue) throws -> String? {
    switch value {
    case .null: return nil
    case .string(let string): return string
    default: throw TacuaSDKResumeJournalError.invalidJournal
    }
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.utf8.count <= 64
      && value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    value.utf8.count == 71
      && value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func validBootSessionID(_ value: String) -> Bool {
    !value.isEmpty && value != "unavailable" && value.utf8.count <= 255
  }

  private static func timestampMilliseconds(_ value: String) -> Int64? {
    guard value.utf8.count == 20,
      value.range(
        of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
        options: .regularExpression
      ) != nil
    else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    guard let date = formatter.date(from: value) else { return nil }
    return Int64((date.timeIntervalSince1970 * 1_000).rounded())
  }
}

protocol TacuaSDKResumeJournalPersisting {
  func load(localSessionID: String) throws -> TacuaSDKResumeJournal?
  func create(_ journal: TacuaSDKResumeJournal) throws
  func createWhileBaseQueueMatches(
    _ journal: TacuaSDKResumeJournal,
    assertBaseQueueMatches: () throws -> Void
  ) throws
  func compareAndSwap(
    expected: TacuaSDKResumeJournal,
    replacement: TacuaSDKResumeJournal
  ) throws
  func remove(expected: TacuaSDKResumeJournal) throws
  func confirmAbsent(expected: TacuaSDKResumeJournal) throws
}

final class TacuaSDKResumeJournalFileStore: TacuaSDKResumeJournalPersisting,
  TacuaSDKResumeRecoveryInspecting
{
  private let rootDirectory: URL
  private let fileManager: FileManager

  init(rootDirectory: URL, fileManager: FileManager = .default) throws {
    guard rootDirectory.isFileURL else { throw TacuaSDKResumeJournalError.invalidSessionID }
    self.rootDirectory = rootDirectory.standardizedFileURL
    self.fileManager = fileManager
    try prepareRootDirectory()
  }

  static func applicationSupportStore(fileManager: FileManager = .default) throws
    -> TacuaSDKResumeJournalFileStore
  {
    guard let applicationSupport = fileManager.urls(
      for: .applicationSupportDirectory, in: .userDomainMask
    ).first else { throw TacuaSDKResumeJournalError.invalidJournal }
    return try TacuaSDKResumeJournalFileStore(
      rootDirectory: applicationSupport
        .appendingPathComponent("TacuaTransport", isDirectory: true)
        .appendingPathComponent("resume-journals", isDirectory: true),
      fileManager: fileManager
    )
  }

  func load(localSessionID: String) throws -> TacuaSDKResumeJournal? {
    try withSessionLock(localSessionID: localSessionID) {
      try loadLocked(localSessionID: localSessionID)
    }
  }

  func hasRecovery(localSessionID: String) throws -> Bool {
    try load(localSessionID: localSessionID) != nil
  }

  /// Bounded exact-name discovery for relaunch retention. Content and inode safety are validated
  /// by `load`; deliberately returning a syntactically valid corrupt name lets the retention
  /// coordinator fail closed and unlink that exact leaf instead of letting malformed bytes hide.
  func listLocalSessionIDs() throws -> [String] {
    let suffix = ".resume-v1.json"
    var enumerationError: Error?
    guard let enumerator = fileManager.enumerator(
      at: rootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants],
      errorHandler: { _, error in
        enumerationError = error
        return false
      }
    ) else { throw TacuaSDKResumeJournalError.invalidJournal }
    var scannedEntryCount = 0
    var localSessionIDs = Set<String>()
    while let value = enumerator.nextObject() {
      guard let entry = value as? URL else { throw TacuaSDKResumeJournalError.invalidJournal }
      scannedEntryCount += 1
      guard scannedEntryCount <= 4_096 else { throw TacuaSDKResumeJournalError.invalidJournal }
      let name = entry.lastPathComponent
      guard name.hasSuffix(suffix) else { continue }
      let localSessionID = String(name.dropLast(suffix.count))
      guard Self.validLocalSessionID(localSessionID) else { continue }
      localSessionIDs.insert(localSessionID)
    }
    if enumerationError != nil { throw TacuaSDKResumeJournalError.invalidJournal }
    return localSessionIDs.sorted()
  }

  func create(_ journal: TacuaSDKResumeJournal) throws {
    try withSessionLock(localSessionID: journal.localSessionID) {
      try createLocked(journal)
    }
  }

  func createWhileBaseQueueMatches(
    _ journal: TacuaSDKResumeJournal,
    assertBaseQueueMatches: () throws -> Void
  ) throws {
    try withSessionLock(localSessionID: journal.localSessionID) {
      try assertBaseQueueMatches()
      try createLocked(journal)
    }
  }

  func compareAndSwap(
    expected: TacuaSDKResumeJournal,
    replacement: TacuaSDKResumeJournal
  ) throws {
    guard expected.permitsReplacement(replacement) else {
      throw TacuaSDKResumeJournalError.stateConflict
    }
    try withSessionLock(localSessionID: expected.localSessionID) {
      let current = try loadLocked(localSessionID: expected.localSessionID)
      // If rename installed the exact replacement before fsync reported failure, rewriting that
      // same value is a durability confirmation. A third state always remains a hard conflict.
      guard current == expected || current == replacement else {
        throw TacuaSDKResumeJournalError.stateConflict
      }
      try persistLocked(replacement)
    }
  }

  func remove(expected: TacuaSDKResumeJournal) throws {
    try withSessionLock(localSessionID: expected.localSessionID) {
      guard try loadLocked(localSessionID: expected.localSessionID) == expected else {
        throw TacuaSDKResumeJournalError.stateConflict
      }
      let url = try journalURL(localSessionID: expected.localSessionID)
      guard unlink(url.path) == 0 else {
        throw TacuaSDKResumeJournalError.stateConflict
      }
      try syncDirectory()
    }
  }

  /// Retention cleanup owns the shared lifecycle lease and uses this exact-name unlink when a
  /// journal is corrupt and therefore cannot participate in the ordinary value-CAS removal.
  func retire(localSessionID: String) throws {
    try withSessionLock(localSessionID: localSessionID) {
      let url = try journalURL(localSessionID: localSessionID)
      let result = unlink(url.path)
      guard result == 0 || errno == ENOENT else {
        throw TacuaSDKResumeJournalError.stateConflict
      }
      try syncDirectory()
    }
  }

  func confirmAbsent(expected: TacuaSDKResumeJournal) throws {
    try withSessionLock(localSessionID: expected.localSessionID) {
      guard try loadLocked(localSessionID: expected.localSessionID) == nil else {
        // Never remove a different journal that acquired this session name after an ambiguous
        // unlink. Absence is returned only after the parent directory is durably synchronized.
        throw TacuaSDKResumeJournalError.stateConflict
      }
      try syncDirectory()
    }
  }

  func journalURL(localSessionID: String) throws -> URL {
    guard Self.validLocalSessionID(localSessionID) else {
      throw TacuaSDKResumeJournalError.invalidSessionID
    }
    let url = rootDirectory.appendingPathComponent("\(localSessionID).resume-v1.json")
      .standardizedFileURL
    guard url.deletingLastPathComponent() == rootDirectory else {
      throw TacuaSDKResumeJournalError.invalidSessionID
    }
    return url
  }

  private func loadLocked(localSessionID: String) throws -> TacuaSDKResumeJournal? {
    let url = try journalURL(localSessionID: localSessionID)
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if descriptor < 0 {
      if errno == ENOENT { return nil }
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    defer { close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_nlink == 1,
      metadata.st_size > 0,
      metadata.st_size <= TacuaSDKResumeJournal.maximumEncodedBytes
    else { throw TacuaSDKResumeJournalError.invalidJournal }
    try hardenAndSyncFile(url, descriptor: descriptor)
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    let data = try handle.readToEnd() ?? Data()
    guard data.count == metadata.st_size else {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    let journal = try TacuaSDKResumeJournal.decode(data)
    guard journal.localSessionID == localSessionID else {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    return journal
  }

  private func createLocked(_ journal: TacuaSDKResumeJournal) throws {
    let url = try journalURL(localSessionID: journal.localSessionID)
    let stagedURL = try stage(journal.encoded(), localSessionID: journal.localSessionID)
    defer { _ = unlink(stagedURL.path) }
    // The staged inode is complete, 0600, protected, and fsynced. A same-filesystem hard-link is
    // an atomic no-replace publication, unlike rename which could overwrite another owner.
    guard Darwin.link(stagedURL.path, url.path) == 0 else {
      if errno == EEXIST { throw TacuaSDKResumeJournalError.ownershipConflict }
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    guard unlink(stagedURL.path) == 0 || errno == ENOENT else {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    try syncDirectory()
  }

  private func persistLocked(_ journal: TacuaSDKResumeJournal) throws {
    let url = try journalURL(localSessionID: journal.localSessionID)
    let stagedURL = try stage(journal.encoded(), localSessionID: journal.localSessionID)
    defer { _ = unlink(stagedURL.path) }
    guard Darwin.rename(stagedURL.path, url.path) == 0 else {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    try syncDirectory()
  }

  private func prepareRootDirectory() throws {
    var missing: [URL] = []
    var cursor = rootDirectory
    while true {
      var metadata = stat()
      if lstat(cursor.path, &metadata) == 0 {
        guard (metadata.st_mode & S_IFMT) == S_IFDIR else {
          throw TacuaSDKResumeJournalError.invalidJournal
        }
        break
      }
      guard errno == ENOENT else { throw TacuaSDKResumeJournalError.invalidJournal }
      missing.append(cursor)
      let parent = cursor.deletingLastPathComponent()
      guard parent != cursor else { throw TacuaSDKResumeJournalError.invalidJournal }
      cursor = parent
    }
    for created in missing.reversed() {
      if mkdir(created.path, S_IRWXU) != 0, errno != EEXIST {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      try hardenAndSyncDirectory(created)
      try syncDirectory(at: created.deletingLastPathComponent())
    }
    try hardenAndSyncDirectory(rootDirectory)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var directory = rootDirectory
    try directory.setResourceValues(values)
    try syncDirectory()
    try syncDirectory(at: rootDirectory.deletingLastPathComponent())
  }

  private func withSessionLock<T>(
    localSessionID: String,
    _ body: () throws -> T
  ) throws -> T {
    _ = try journalURL(localSessionID: localSessionID)
    let lockURL = rootDirectory.appendingPathComponent(".\(localSessionID).lock")
      .standardizedFileURL
    guard lockURL.deletingLastPathComponent() == rootDirectory else {
      throw TacuaSDKResumeJournalError.invalidSessionID
    }
    let descriptor = open(
      lockURL.path,
      O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw TacuaSDKResumeJournalError.invalidJournal }
    defer { close(descriptor) }
    try hardenAndSyncFile(lockURL, descriptor: descriptor)
    try syncDirectory()
    guard flock(descriptor, LOCK_EX) == 0 else {
      throw TacuaSDKResumeJournalError.invalidJournal
    }
    defer { _ = flock(descriptor, LOCK_UN) }
    try scavengeTemps(localSessionID: localSessionID)
    return try body()
  }

  private func scavengeTemps(localSessionID: String) throws {
    let prefix = ".\(localSessionID).resume-v1."
    let entries = try fileManager.contentsOfDirectory(
      at: rootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants]
    )
    var removed = false
    for entry in entries {
      let name = entry.lastPathComponent
      guard name.hasPrefix(prefix), name.hasSuffix(".tmp"),
        name.utf8.count == prefix.utf8.count + 32 + 4
      else { continue }
      let start = name.index(name.startIndex, offsetBy: prefix.count)
      let end = name.index(name.endIndex, offsetBy: -4)
      let token = String(name[start..<end])
      guard token.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
        continue
      }
      var metadata = stat()
      guard lstat(entry.path, &metadata) == 0 else {
        if errno == ENOENT { continue }
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      guard (metadata.st_mode & S_IFMT) == S_IFREG, metadata.st_nlink == 1 else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      guard unlink(entry.path) == 0 || errno == ENOENT else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      removed = true
    }
    if removed { try syncDirectory() }
  }

  private func stage(_ data: Data, localSessionID: String) throws -> URL {
    for _ in 0..<8 {
      let suffix = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
      let url = rootDirectory
        .appendingPathComponent(".\(localSessionID).resume-v1.\(suffix).tmp")
        .standardizedFileURL
      guard url.deletingLastPathComponent() == rootDirectory else {
        throw TacuaSDKResumeJournalError.invalidSessionID
      }
      let descriptor = open(
        url.path,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        S_IRUSR | S_IWUSR
      )
      if descriptor < 0 {
        if errno == EEXIST { continue }
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      do {
        try write(data, descriptor: descriptor)
        try hardenAndSyncFile(url, descriptor: descriptor)
        _ = close(descriptor)
        return url
      } catch {
        _ = close(descriptor)
        _ = unlink(url.path)
        throw error
      }
    }
    throw TacuaSDKResumeJournalError.invalidJournal
  }

  private func write(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { buffer in
      guard let baseAddress = buffer.baseAddress else {
        throw TacuaSDKResumeJournalError.invalidJournal
      }
      var offset = 0
      while offset < data.count {
        let count = Darwin.write(
          descriptor,
          baseAddress.advanced(by: offset),
          data.count - offset
        )
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw POSIXError(.EIO) }
        offset += count
      }
    }
  }

  private func hardenAndSyncFile(_ url: URL, descriptor: Int32) throws {
    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
      (opened.st_mode & S_IFMT) == S_IFREG,
      fchmod(descriptor, S_IRUSR | S_IWUSR) == 0
    else { throw TacuaSDKResumeJournalError.invalidJournal }
    try fileManager.setAttributes(
      [
        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        .posixPermissions: 0o600,
      ],
      ofItemAtPath: url.path
    )
    var pathMetadata = stat()
    var hardened = stat()
    let attributes = try fileManager.attributesOfItem(atPath: url.path)
    guard lstat(url.path, &pathMetadata) == 0,
      (pathMetadata.st_mode & S_IFMT) == S_IFREG,
      pathMetadata.st_dev == opened.st_dev,
      pathMetadata.st_ino == opened.st_ino,
      fstat(descriptor, &hardened) == 0,
      hardened.st_dev == opened.st_dev,
      hardened.st_ino == opened.st_ino,
      hardened.st_nlink >= 1,
      (hardened.st_mode & mode_t(0o777)) == mode_t(0o600),
      attributes[.protectionKey] as? FileProtectionType
        == .completeUntilFirstUserAuthentication,
      fsync(descriptor) == 0
    else { throw TacuaSDKResumeJournalError.invalidJournal }
  }

  private func hardenAndSyncDirectory(_ url: URL) throws {
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw TacuaSDKResumeJournalError.invalidJournal }
    defer { close(descriptor) }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
      (opened.st_mode & S_IFMT) == S_IFDIR,
      fchmod(descriptor, mode_t(0o700)) == 0
    else { throw TacuaSDKResumeJournalError.invalidJournal }
    try fileManager.setAttributes(
      [
        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        .posixPermissions: 0o700,
      ],
      ofItemAtPath: url.path
    )
    var pathMetadata = stat()
    var hardened = stat()
    let attributes = try fileManager.attributesOfItem(atPath: url.path)
    guard lstat(url.path, &pathMetadata) == 0,
      (pathMetadata.st_mode & S_IFMT) == S_IFDIR,
      pathMetadata.st_dev == opened.st_dev,
      pathMetadata.st_ino == opened.st_ino,
      fstat(descriptor, &hardened) == 0,
      hardened.st_dev == opened.st_dev,
      hardened.st_ino == opened.st_ino,
      (hardened.st_mode & mode_t(0o777)) == mode_t(0o700),
      attributes[.protectionKey] as? FileProtectionType
        == .completeUntilFirstUserAuthentication,
      fsync(descriptor) == 0
    else { throw TacuaSDKResumeJournalError.invalidJournal }
  }

  private func syncDirectory() throws {
    try syncDirectory(at: rootDirectory)
  }

  private func syncDirectory(at directory: URL) throws {
    let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
  }

  private static func validLocalSessionID(_ value: String) -> Bool {
    value.utf8.count <= 64
      && value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }
}
