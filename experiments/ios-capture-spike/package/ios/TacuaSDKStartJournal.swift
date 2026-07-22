// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

enum TacuaSDKStartJournalError: Error, Equatable {
  case invalidJournal
  case invalidSessionID
  case ownershipConflict
  case stateConflict
}

enum TacuaSDKStartJournalState: String, Equatable {
  /// The identifiers and ownership verifier are durable, but the Keychain write or request
  /// construction may not have completed. Cleanup removes only an exact verifier match.
  case credentialPrepared = "credential_prepared"
  /// The intent to send was durable before network I/O. A missing response cannot prove whether
  /// the backend accepted the exchange, so this state is never described as remotely recoverable.
  case exchangeOutcomeUnknown = "exchange_outcome_unknown"
  /// A response was independently validated and the fields required to reconstruct queue state
  /// are durable, but the queue commit may not have completed.
  case receiptValidatedQueueCommitPending = "receipt_validated_queue_commit_pending"
  /// Reset owns credential cleanup after winning a CAS from the pre-network state.
  case credentialPreparedResetPending = "credential_prepared_reset_pending"
  /// Reset owns credential cleanup after explicit acknowledgement of an ambiguous exchange.
  case exchangeOutcomeUnknownResetPending = "exchange_outcome_unknown_reset_pending"
}

struct TacuaSDKStartReceiptRecovery: Equatable {
  let remoteSessionID: String
  let scopeDigest: String
  let credentialExpiresAt: String
  let timeAnchor: TacuaServerTimeAnchor
  let sessionRetentionAuthority: TacuaSessionRetentionAuthority?

  init(
    remoteSessionID: String,
    scopeDigest: String,
    credentialExpiresAt: String,
    timeAnchor: TacuaServerTimeAnchor,
    sessionRetentionAuthority: TacuaSessionRetentionAuthority? = nil
  ) {
    self.remoteSessionID = remoteSessionID
    self.scopeDigest = scopeDigest
    self.credentialExpiresAt = credentialExpiresAt
    self.timeAnchor = timeAnchor
    self.sessionRetentionAuthority = sessionRetentionAuthority
  }
}

struct TacuaSDKStartJournal: Equatable {
  static let schemaVersion: Int64 = 2
  private static let legacySchemaVersion: Int64 = 1
  static let maximumEncodedBytes = 2 * 1_024 * 1_024

  let localSessionID: String
  let exchangeID: String
  let credentialID: String
  let credentialOwnershipDigest: String
  let transportConfigurationDigest: String
  /// Canonical public artifacts only. Legacy schema-1 journals decode as nil/nil; no launch code,
  /// transient request, or credential secret is ever accepted by this structure.
  let buildIdentityJSON: String?
  let captureScopeJSON: String?
  let createdAt: String
  let state: TacuaSDKStartJournalState
  let validatedReceipt: TacuaSDKStartReceiptRecovery?

  init(
    localSessionID: String,
    exchangeID: String,
    credentialID: String,
    credentialOwnershipDigest: String,
    transportConfigurationDigest: String,
    buildIdentityJSON: String? = nil,
    captureScopeJSON: String? = nil,
    createdAt: String,
    state: TacuaSDKStartJournalState,
    validatedReceipt: TacuaSDKStartReceiptRecovery? = nil
  ) throws {
    self.localSessionID = localSessionID
    self.exchangeID = exchangeID
    self.credentialID = credentialID
    self.credentialOwnershipDigest = credentialOwnershipDigest
    self.transportConfigurationDigest = transportConfigurationDigest
    self.buildIdentityJSON = buildIdentityJSON
    self.captureScopeJSON = captureScopeJSON
    self.createdAt = createdAt
    self.state = state
    self.validatedReceipt = validatedReceipt
    try validate()
  }

  func advancing(
    to state: TacuaSDKStartJournalState,
    validatedReceipt: TacuaSDKStartReceiptRecovery? = nil
  ) throws -> TacuaSDKStartJournal {
    switch (self.state, state) {
    case (.credentialPrepared, .exchangeOutcomeUnknown),
      (.exchangeOutcomeUnknown, .receiptValidatedQueueCommitPending),
      (.receiptValidatedQueueCommitPending, .receiptValidatedQueueCommitPending),
      (.credentialPrepared, .credentialPreparedResetPending),
      (.credentialPreparedResetPending, .credentialPreparedResetPending),
      (.exchangeOutcomeUnknown, .exchangeOutcomeUnknownResetPending),
      (.exchangeOutcomeUnknownResetPending, .exchangeOutcomeUnknownResetPending):
      break
    default:
      throw TacuaSDKStartJournalError.invalidJournal
    }
    return try TacuaSDKStartJournal(
      localSessionID: localSessionID,
      exchangeID: exchangeID,
      credentialID: credentialID,
      credentialOwnershipDigest: credentialOwnershipDigest,
      transportConfigurationDigest: transportConfigurationDigest,
      buildIdentityJSON: buildIdentityJSON,
      captureScopeJSON: captureScopeJSON,
      createdAt: createdAt,
      state: state,
      validatedReceipt: validatedReceipt
    )
  }

  func encoded() throws -> Data {
    try validate()
    let receipt: TacuaJSONValue
    if let validatedReceipt {
      let retention: TacuaJSONValue
      if let authority = validatedReceipt.sessionRetentionAuthority {
        retention = .object([
          "derived_data_expires_at": .string(authority.derivedDataExpiresAt),
          "raw_media_expires_at": .string(authority.rawMediaExpiresAt),
          "session_received_at": .string(authority.sessionReceivedAt),
        ])
      } else {
        // Backward-compatible recovery for a journal written before START retention was retained.
        // Its resulting queue remains usable only for exact replay/deletion, not completion.
        retention = .null
      }
      receipt = .object([
        "credential_expires_at": .string(validatedReceipt.credentialExpiresAt),
        "remote_session_id": .string(validatedReceipt.remoteSessionID),
        "session_retention_authority": retention,
        "scope_digest": .string(validatedReceipt.scopeDigest),
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
      receipt = .null
    }
    let data = try TacuaCanonicalJSON.data(.object([
      "created_at": .string(createdAt),
      "build_identity_json": buildIdentityJSON.map(TacuaJSONValue.string) ?? .null,
      "capture_scope_json": captureScopeJSON.map(TacuaJSONValue.string) ?? .null,
      "credential_id": .string(credentialID),
      "credential_ownership_digest": .string(credentialOwnershipDigest),
      "exchange_id": .string(exchangeID),
      "local_session_id": .string(localSessionID),
      "schema_version": .integer(Self.schemaVersion),
      "state": .string(state.rawValue),
      "transport_configuration_digest": .string(transportConfigurationDigest),
      "validated_receipt": receipt,
    ]))
    guard data.count <= Self.maximumEncodedBytes else {
      throw TacuaSDKStartJournalError.invalidJournal
    }
    return data
  }

  static func decode(_ data: Data) throws -> TacuaSDKStartJournal {
    let value = try TacuaCanonicalJSON.parse(data, maximumBytes: maximumEncodedBytes)
    guard try TacuaCanonicalJSON.data(value) == data else {
      throw TacuaSDKStartJournalError.invalidJournal
    }
    guard let schema = value.objectValue?["schema_version"]?.integerValue,
      schema == schemaVersion || schema == legacySchemaVersion
    else { throw TacuaSDKStartJournalError.invalidJournal }
    let root = try value.requiringObject(keys: schema == schemaVersion ? [
      "build_identity_json", "capture_scope_json", "created_at", "credential_id",
      "credential_ownership_digest", "exchange_id", "local_session_id", "schema_version",
      "state", "transport_configuration_digest", "validated_receipt",
    ] : [
      "created_at", "credential_id", "credential_ownership_digest", "exchange_id",
      "local_session_id", "schema_version", "state", "transport_configuration_digest",
      "validated_receipt",
    ])
    guard
      let localSessionID = root["local_session_id"]?.stringValue,
      let exchangeID = root["exchange_id"]?.stringValue,
      let credentialID = root["credential_id"]?.stringValue,
      let credentialOwnershipDigest = root["credential_ownership_digest"]?.stringValue,
      let createdAt = root["created_at"]?.stringValue,
      let rawState = root["state"]?.stringValue,
      let state = TacuaSDKStartJournalState(rawValue: rawState),
      let transportConfigurationDigest = root["transport_configuration_digest"]?.stringValue,
      let receiptValue = root["validated_receipt"]
    else { throw TacuaSDKStartJournalError.invalidJournal }
    let buildIdentityJSON: String?
    let captureScopeJSON: String?
    if schema == schemaVersion {
      guard let buildValue = root["build_identity_json"],
        let scopeValue = root["capture_scope_json"]
      else { throw TacuaSDKStartJournalError.invalidJournal }
      buildIdentityJSON = try nullableString(buildValue)
      captureScopeJSON = try nullableString(scopeValue)
    } else {
      buildIdentityJSON = nil
      captureScopeJSON = nil
    }
    let receipt: TacuaSDKStartReceiptRecovery?
    switch receiptValue {
    case .null:
      receipt = nil
    case .object:
      let hasRetentionAuthority = receiptValue.objectValue?["session_retention_authority"] != nil
      let object = try receiptValue.requiringObject(keys: hasRetentionAuthority ? [
        "credential_expires_at", "remote_session_id", "session_retention_authority",
        "scope_digest", "time_anchor",
      ] : [
        "credential_expires_at", "remote_session_id", "scope_digest", "time_anchor",
      ])
      guard let remoteSessionID = object["remote_session_id"]?.stringValue,
        let scopeDigest = object["scope_digest"]?.stringValue,
        let expiresAt = object["credential_expires_at"]?.stringValue,
        let anchorValue = object["time_anchor"]
      else { throw TacuaSDKStartJournalError.invalidJournal }
      let anchor = try anchorValue.requiringObject(keys: [
        "boot_session_id", "issued_at", "issued_epoch_milliseconds",
        "minimum_epoch_milliseconds", "uptime_milliseconds_at_issue",
      ])
      guard let bootSessionID = anchor["boot_session_id"]?.stringValue,
        let issuedAt = anchor["issued_at"]?.stringValue,
        let issuedEpochMilliseconds = anchor["issued_epoch_milliseconds"]?.integerValue,
        let minimumEpochMilliseconds = anchor["minimum_epoch_milliseconds"]?.integerValue,
        let uptimeMillisecondsAtIssue = anchor["uptime_milliseconds_at_issue"]?.integerValue
      else { throw TacuaSDKStartJournalError.invalidJournal }
      let retentionAuthority: TacuaSessionRetentionAuthority?
      if let retentionValue = object["session_retention_authority"] {
        switch retentionValue {
        case .null:
          retentionAuthority = nil
        case .object:
          let retention = try retentionValue.requiringObject(keys: [
            "derived_data_expires_at", "raw_media_expires_at", "session_received_at",
          ])
          guard let receivedAt = retention["session_received_at"]?.stringValue,
            let rawExpiresAt = retention["raw_media_expires_at"]?.stringValue,
            let derivedExpiresAt = retention["derived_data_expires_at"]?.stringValue
          else { throw TacuaSDKStartJournalError.invalidJournal }
          retentionAuthority = TacuaSessionRetentionAuthority(
            sessionReceivedAt: receivedAt,
            rawMediaExpiresAt: rawExpiresAt,
            derivedDataExpiresAt: derivedExpiresAt
          )
        default:
          throw TacuaSDKStartJournalError.invalidJournal
        }
      } else {
        retentionAuthority = nil
      }
      receipt = TacuaSDKStartReceiptRecovery(
        remoteSessionID: remoteSessionID,
        scopeDigest: scopeDigest,
        credentialExpiresAt: expiresAt,
        timeAnchor: TacuaServerTimeAnchor(
          issuedAt: issuedAt,
          issuedEpochMilliseconds: issuedEpochMilliseconds,
          uptimeMillisecondsAtIssue: uptimeMillisecondsAtIssue,
          bootSessionID: bootSessionID,
          minimumEpochMilliseconds: minimumEpochMilliseconds
        ),
        sessionRetentionAuthority: retentionAuthority
      )
    default:
      throw TacuaSDKStartJournalError.invalidJournal
    }
    return try TacuaSDKStartJournal(
      localSessionID: localSessionID,
      exchangeID: exchangeID,
      credentialID: credentialID,
      credentialOwnershipDigest: credentialOwnershipDigest,
      transportConfigurationDigest: transportConfigurationDigest,
      buildIdentityJSON: buildIdentityJSON,
      captureScopeJSON: captureScopeJSON,
      createdAt: createdAt,
      state: state,
      validatedReceipt: receipt
    )
  }

  private func validate() throws {
    guard Self.validIdentifier(localSessionID), Self.validIdentifier(exchangeID),
      Self.validIdentifier(credentialID), Self.validDigest(credentialOwnershipDigest),
      Self.validDigest(transportConfigurationDigest),
      Self.validTimestamp(createdAt)
    else { throw TacuaSDKStartJournalError.invalidJournal }
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
        throw TacuaSDKStartJournalError.invalidJournal
      }
      guard artifacts?.transportConfigurationDigest == transportConfigurationDigest else {
        throw TacuaSDKStartJournalError.invalidJournal
      }
    default:
      throw TacuaSDKStartJournalError.invalidJournal
    }
    switch state {
    case .credentialPrepared, .exchangeOutcomeUnknown,
      .credentialPreparedResetPending, .exchangeOutcomeUnknownResetPending:
      guard validatedReceipt == nil else { throw TacuaSDKStartJournalError.invalidJournal }
    case .receiptValidatedQueueCommitPending:
      guard let receipt = validatedReceipt,
        Self.validIdentifier(receipt.remoteSessionID),
        Self.validDigest(receipt.scopeDigest),
        Self.validTimestamp(receipt.credentialExpiresAt),
        Self.validTimestamp(receipt.timeAnchor.issuedAt),
        receipt.credentialExpiresAt > receipt.timeAnchor.issuedAt,
        let issuedEpoch = Self.timestampMilliseconds(receipt.timeAnchor.issuedAt),
        receipt.timeAnchor.issuedEpochMilliseconds == issuedEpoch,
        receipt.timeAnchor.uptimeMillisecondsAtIssue >= 0,
        !receipt.timeAnchor.bootSessionID.isEmpty,
        receipt.timeAnchor.bootSessionID.utf8.count <= 255,
        receipt.timeAnchor.minimumEpochMilliseconds >= issuedEpoch
      else { throw TacuaSDKStartJournalError.invalidJournal }
      if let artifacts, artifacts.scopeDigest != receipt.scopeDigest {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      do {
        try receipt.sessionRetentionAuthority?.validate()
      } catch {
        throw TacuaSDKStartJournalError.invalidJournal
      }
    }
  }

  func durableSessionArtifacts() throws -> TacuaDurableSessionArtifacts? {
    guard let buildIdentityJSON, let captureScopeJSON else {
      guard self.buildIdentityJSON == nil, self.captureScopeJSON == nil else {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      return nil
    }
    do {
      return try TacuaDurableSessionArtifacts.exactCanonical(
        buildIdentityJSON: buildIdentityJSON,
        scopeJSON: captureScopeJSON
      )
    } catch {
      throw TacuaSDKStartJournalError.invalidJournal
    }
  }

  private static func nullableString(_ value: TacuaJSONValue) throws -> String? {
    switch value {
    case .null: return nil
    case .string(let value): return value
    default: throw TacuaSDKStartJournalError.invalidJournal
    }
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func validTimestamp(_ value: String) -> Bool {
    timestampMilliseconds(value) != nil
  }

  private static func timestampMilliseconds(_ value: String) -> Int64? {
    guard value.range(
      of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
      options: .regularExpression
    ) != nil else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    guard let date = formatter.date(from: value) else { return nil }
    return Int64((date.timeIntervalSince1970 * 1_000).rounded())
  }
}

protocol TacuaSDKStartJournalPersisting {
  func acquireLifecycleLease(localSessionID: String) throws -> TacuaSDKStartLifecycleLease
  func load(localSessionID: String) throws -> TacuaSDKStartJournal?
  func create(_ journal: TacuaSDKStartJournal) throws
  func createWhileQueueAbsent(
    _ journal: TacuaSDKStartJournal,
    assertQueueAbsent: () throws -> Void
  ) throws
  func compareAndSwap(
    expected: TacuaSDKStartJournal,
    replacement: TacuaSDKStartJournal
  ) throws
  func remove(expected: TacuaSDKStartJournal) throws
  /// Confirms an earlier ambiguous unlink without ever deleting a journal.
  /// A different or still-present journal is a conflict; absence is reported
  /// only after the parent directory has been fsynced successfully.
  func confirmAbsent(expected: TacuaSDKStartJournal) throws
}

protocol TacuaSDKStartLifecycleLease: AnyObject {
  func release()
}

private final class TacuaSDKStartLifecycleFileLease: TacuaSDKStartLifecycleLease {
  private let lock = NSLock()
  private var descriptor: Int32?

  init(descriptor: Int32) { self.descriptor = descriptor }

  func release() {
    lock.lock()
    guard let descriptor else {
      lock.unlock()
      return
    }
    self.descriptor = nil
    lock.unlock()
    _ = flock(descriptor, LOCK_UN)
    _ = close(descriptor)
  }

  deinit { release() }
}

final class TacuaSDKStartJournalFileStore: TacuaSDKStartJournalPersisting {
  private let rootDirectory: URL
  private let fileManager: FileManager

  init(rootDirectory: URL, fileManager: FileManager = .default) throws {
    guard rootDirectory.isFileURL else { throw TacuaSDKStartJournalError.invalidSessionID }
    self.rootDirectory = rootDirectory.standardizedFileURL
    self.fileManager = fileManager
    try prepareRootDirectory()
  }

  static func applicationSupportStore(fileManager: FileManager = .default) throws
    -> TacuaSDKStartJournalFileStore
  {
    guard let applicationSupport = fileManager.urls(
      for: .applicationSupportDirectory, in: .userDomainMask
    ).first else { throw TacuaSDKStartJournalError.invalidJournal }
    return try TacuaSDKStartJournalFileStore(
      rootDirectory: applicationSupport
        .appendingPathComponent("TacuaTransport", isDirectory: true)
        .appendingPathComponent("start-journals", isDirectory: true),
      fileManager: fileManager
    )
  }

  func acquireLifecycleLease(localSessionID: String) throws
    -> TacuaSDKStartLifecycleLease
  {
    _ = try journalURL(localSessionID: localSessionID)
    let lockURL = rootDirectory.appendingPathComponent(".\(localSessionID).lifecycle.lock")
      .standardizedFileURL
    guard lockURL.deletingLastPathComponent() == rootDirectory else {
      throw TacuaSDKStartJournalError.invalidSessionID
    }
    let descriptor = open(
      lockURL.path,
      O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw TacuaSDKStartJournalError.invalidJournal }
    do {
      try hardenAndSyncFile(lockURL, descriptor: descriptor)
      try syncDirectory()
      guard flock(descriptor, LOCK_EX) == 0 else {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      return TacuaSDKStartLifecycleFileLease(descriptor: descriptor)
    } catch {
      _ = close(descriptor)
      throw error
    }
  }

  func load(localSessionID: String) throws -> TacuaSDKStartJournal? {
    try withSessionLock(localSessionID: localSessionID, exclusive: true) {
      try loadUnlocked(localSessionID: localSessionID)
    }
  }

  /// Returns only identifiers backed by a no-follow, single-link regular START journal. This is a
  /// discovery snapshot; the authoritative recovery state must be loaded under the lifecycle
  /// lease before the host chooses an action.
  func listLocalSessionIDs() throws -> [String] {
    let suffix = ".start-v1.json"
    var enumerationError: Error?
    guard let enumerator = fileManager.enumerator(
      at: rootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants],
      errorHandler: { _, error in
        enumerationError = error
        return false
      }
    ) else { throw TacuaSDKStartJournalError.invalidJournal }
    var scannedEntryCount = 0
    var localSessionIDs: [String] = []
    while let value = enumerator.nextObject() {
      guard let entry = value as? URL else { throw TacuaSDKStartJournalError.invalidJournal }
      scannedEntryCount += 1
      guard scannedEntryCount <= 4_096 else { throw TacuaSDKStartJournalError.invalidJournal }
      let name = entry.lastPathComponent
      guard name.hasSuffix(suffix) else { continue }
      let localSessionID = String(name.dropLast(suffix.count))
      guard localSessionID.range(
        of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression
      ) != nil else { continue }
      var metadata = stat()
      guard lstat(entry.path, &metadata) == 0 else {
        if errno == ENOENT { continue }
        throw TacuaSDKStartJournalError.invalidJournal
      }
      guard
        (metadata.st_mode & S_IFMT) == S_IFREG,
        metadata.st_nlink == 1
      else { throw TacuaSDKStartJournalError.invalidJournal }
      localSessionIDs.append(localSessionID)
    }
    if enumerationError != nil { throw TacuaSDKStartJournalError.invalidJournal }
    return localSessionIDs.sorted()
  }

  func create(_ journal: TacuaSDKStartJournal) throws {
    try withSessionLock(localSessionID: journal.localSessionID, exclusive: true) {
      try createLocked(journal)
    }
  }

  func createWhileQueueAbsent(
    _ journal: TacuaSDKStartJournal,
    assertQueueAbsent: () throws -> Void
  ) throws {
    try withSessionLock(localSessionID: journal.localSessionID, exclusive: true) {
      // Queue commit is fsynced before this same session lock removes the
      // winning journal. A stale creator therefore sees either the journal
      // or the durable queue, never a false empty state.
      try assertQueueAbsent()
      try createLocked(journal)
    }
  }

  func compareAndSwap(
    expected: TacuaSDKStartJournal,
    replacement: TacuaSDKStartJournal
  ) throws {
    guard expected.localSessionID == replacement.localSessionID,
      expected.exchangeID == replacement.exchangeID,
      expected.credentialID == replacement.credentialID,
      expected.credentialOwnershipDigest == replacement.credentialOwnershipDigest,
      expected.transportConfigurationDigest == replacement.transportConfigurationDigest,
      expected.buildIdentityJSON == replacement.buildIdentityJSON,
      expected.captureScopeJSON == replacement.captureScopeJSON
    else { throw TacuaSDKStartJournalError.stateConflict }
    try withSessionLock(localSessionID: expected.localSessionID, exclusive: true) {
      guard try loadUnlocked(localSessionID: expected.localSessionID) == expected else {
        throw TacuaSDKStartJournalError.stateConflict
      }
      try persistLocked(replacement)
    }
  }

  func remove(expected: TacuaSDKStartJournal) throws {
    try withSessionLock(localSessionID: expected.localSessionID, exclusive: true) {
      guard try loadUnlocked(localSessionID: expected.localSessionID) == expected else {
        throw TacuaSDKStartJournalError.stateConflict
      }
      let url = try journalURL(localSessionID: expected.localSessionID)
      guard unlink(url.path) == 0 else {
        throw TacuaSDKStartJournalError.stateConflict
      }
      try syncDirectory()
    }
  }

  /// Retention cleanup owns the per-session lifecycle lease and may need to retire an unreadable
  /// journal. Unlinking the exact bounded name is safe even when its contents cannot be trusted.
  func retire(localSessionID: String) throws {
    try withSessionLock(localSessionID: localSessionID, exclusive: true) {
      let url = try journalURL(localSessionID: localSessionID)
      let result = unlink(url.path)
      guard result == 0 || errno == ENOENT else {
        throw TacuaSDKStartJournalError.stateConflict
      }
      try syncDirectory()
    }
  }

  func confirmAbsent(expected: TacuaSDKStartJournal) throws {
    try withSessionLock(localSessionID: expected.localSessionID, exclusive: true) {
      guard try loadUnlocked(localSessionID: expected.localSessionID) == nil else {
        // In particular, never remove a newer journal that acquired the same
        // local session after an earlier unlink became ambiguous.
        throw TacuaSDKStartJournalError.stateConflict
      }
      try syncDirectory()
    }
  }

  private func loadUnlocked(localSessionID: String) throws -> TacuaSDKStartJournal? {
    let url = try journalURL(localSessionID: localSessionID)
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    if descriptor < 0 {
      if errno == ENOENT { return nil }
      throw TacuaSDKStartJournalError.invalidJournal
    }
    defer { close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_size > 0,
      metadata.st_size <= TacuaSDKStartJournal.maximumEncodedBytes
    else { throw TacuaSDKStartJournalError.invalidJournal }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    let data = try handle.readToEnd() ?? Data()
    guard data.count == metadata.st_size else { throw TacuaSDKStartJournalError.invalidJournal }
    let journal = try TacuaSDKStartJournal.decode(data)
    guard journal.localSessionID == localSessionID else {
      throw TacuaSDKStartJournalError.invalidJournal
    }
    try hardenAndSyncFile(url, descriptor: descriptor)
    return journal
  }

  private func persistLocked(_ journal: TacuaSDKStartJournal) throws {
    let url = try journalURL(localSessionID: journal.localSessionID)
    let data = try journal.encoded()
    let stagedURL = try stageJournal(data, localSessionID: journal.localSessionID)
    defer { _ = unlink(stagedURL.path) }
    guard Darwin.rename(stagedURL.path, url.path) == 0 else {
      throw TacuaSDKStartJournalError.invalidJournal
    }
    try syncDirectory()
  }

  private func createLocked(_ journal: TacuaSDKStartJournal) throws {
    let url = try journalURL(localSessionID: journal.localSessionID)
    let data = try journal.encoded()
    let stagedURL = try stageJournal(data, localSessionID: journal.localSessionID)
    defer { _ = unlink(stagedURL.path) }

    // A hard-link is an atomic no-replace install on the same filesystem. The
    // staged inode is already complete, protected, and fsynced, so the final
    // path can never expose a partial journal even if this process crashes.
    guard Darwin.link(stagedURL.path, url.path) == 0 else {
      if errno == EEXIST { throw TacuaSDKStartJournalError.ownershipConflict }
      throw TacuaSDKStartJournalError.invalidJournal
    }
    guard unlink(stagedURL.path) == 0 || errno == ENOENT else {
      throw TacuaSDKStartJournalError.invalidJournal
    }
    try syncDirectory()
  }

  func journalURL(localSessionID: String) throws -> URL {
    guard localSessionID.range(
      of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression
    ) != nil else { throw TacuaSDKStartJournalError.invalidSessionID }
    let url = rootDirectory.appendingPathComponent("\(localSessionID).start-v1.json")
      .standardizedFileURL
    guard url.deletingLastPathComponent() == rootDirectory else {
      throw TacuaSDKStartJournalError.invalidSessionID
    }
    return url
  }

  private func prepareRootDirectory() throws {
    var missing: [URL] = []
    var cursor = rootDirectory
    while !fileManager.fileExists(atPath: cursor.path) {
      missing.append(cursor)
      let parent = cursor.deletingLastPathComponent()
      guard parent != cursor else { throw TacuaSDKStartJournalError.invalidJournal }
      cursor = parent
    }
    for created in missing.reversed() {
      // Create each component privately from its first observable inode. FileManager's
      // intermediate creation can otherwise expose the process umask before attributes repair.
      if mkdir(created.path, S_IRWXU) != 0, errno != EEXIST {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      try hardenAndSyncDirectory(created)
      try syncDirectory(at: created.deletingLastPathComponent())
    }
    // Harden the root even when it predates this SDK version or another
    // process created it before crashing in the middle of initialization.
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
    exclusive: Bool,
    _ body: () throws -> T
  ) throws -> T {
    _ = try journalURL(localSessionID: localSessionID)
    let lockURL = rootDirectory.appendingPathComponent(".\(localSessionID).lock")
      .standardizedFileURL
    guard lockURL.deletingLastPathComponent() == rootDirectory else {
      throw TacuaSDKStartJournalError.invalidSessionID
    }
    let descriptor = open(
      lockURL.path,
      O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw TacuaSDKStartJournalError.invalidJournal }
    defer { close(descriptor) }
    try hardenAndSyncFile(lockURL, descriptor: descriptor)
    // Persist a newly created lock entry before relying on its inode for
    // cross-process exclusion. Existing lock files are harmlessly rechecked.
    try syncDirectory()
    guard flock(descriptor, exclusive ? LOCK_EX : LOCK_SH) == 0 else {
      throw TacuaSDKStartJournalError.invalidJournal
    }
    defer { flock(descriptor, LOCK_UN) }
    if exclusive { try scavengeJournalTemps(localSessionID: localSessionID) }
    return try body()
  }

  private func scavengeJournalTemps(localSessionID: String) throws {
    let prefix = ".\(localSessionID).start-v1."
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
        throw TacuaSDKStartJournalError.invalidJournal
      }
      guard (metadata.st_mode & S_IFMT) == S_IFREG else {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      guard unlink(entry.path) == 0 || errno == ENOENT else {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      removed = true
    }
    if removed { try syncDirectory() }
  }

  private func write(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { buffer in
      guard let base = buffer.baseAddress else {
        throw TacuaSDKStartJournalError.invalidJournal
      }
      var offset = 0
      while offset < data.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
        guard count > 0 else { throw POSIXError(.EIO) }
        offset += count
      }
    }
  }

  private func stageJournal(_ data: Data, localSessionID: String) throws -> URL {
    for _ in 0..<8 {
      let suffix = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
      let url = rootDirectory
        .appendingPathComponent(".\(localSessionID).start-v1.\(suffix).tmp")
        .standardizedFileURL
      guard url.deletingLastPathComponent() == rootDirectory else {
        throw TacuaSDKStartJournalError.invalidSessionID
      }
      let descriptor = open(
        url.path,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        S_IRUSR | S_IWUSR
      )
      if descriptor < 0 {
        if errno == EEXIST { continue }
        throw TacuaSDKStartJournalError.invalidJournal
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
    throw TacuaSDKStartJournalError.invalidJournal
  }

  private func hardenAndSyncFile(_ url: URL, descriptor: Int32) throws {
    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
      (opened.st_mode & S_IFMT) == S_IFREG,
      fchmod(descriptor, S_IRUSR | S_IWUSR) == 0
    else { throw TacuaSDKStartJournalError.invalidJournal }
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
      (hardened.st_mode & mode_t(0o777)) == mode_t(0o600),
      attributes[.protectionKey] as? FileProtectionType
        == .completeUntilFirstUserAuthentication,
      fsync(descriptor) == 0
    else { throw TacuaSDKStartJournalError.invalidJournal }
  }

  private func hardenAndSyncDirectory(_ url: URL) throws {
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw TacuaSDKStartJournalError.invalidJournal }
    defer { close(descriptor) }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
      (opened.st_mode & S_IFMT) == S_IFDIR,
      fchmod(descriptor, mode_t(0o700)) == 0
    else { throw TacuaSDKStartJournalError.invalidJournal }
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
    else { throw TacuaSDKStartJournalError.invalidJournal }
  }

  private func syncDirectory() throws {
    try syncDirectory(at: rootDirectory)
  }

  private func syncDirectory(at directory: URL) throws {
    let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
  }
}
