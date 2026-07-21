// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

enum TacuaTransportQueueError: Error, Equatable {
  case unsupportedSchemaVersion
  case invalidQueue
  case invalidIdentifier
  case invalidDigest
  case invalidTimestamp
  case invalidTimeAnchor
  case resumeRequired
  case missingCredential
  case credentialMismatch
  case transportConfigurationMismatch
  case operationNotAllowed
  case operationConflict
  case operationNotFound
  case responseConflict
  case cleanupNotAuthorized
  case deletionNotAuthorized
  case prohibitedPersistedMaterial
}

private enum TacuaQueueBounds {
  static let maximumEncodedBytes = 32 * 1_024 * 1_024
  static let maximumIdentifierBytes = 64
  static let maximumDigestBytes = 71
  static let maximumTimestampBytes = 20
  static let maximumRelativePathBytes = 1_024
  static let maximumBootSessionIDBytes = 255
  static let maximumPersistedJSONKeyBytes = 256
  static let maximumOperations = 4_099
  static let maximumCredentialEntries = 4_096
  static let maximumLocalPayloadPaths = 4_099
  static let maximumLegacyItems = 4_097
  static let maximumLegacyObjectKindBytes = 64
  static let maximumPayloadBindingsPerOperation = 2

  /// Older builds used this value when `kern.boottime` failed. It is not a boot identity: accepting
  /// it on two failures would incorrectly make distinct or unknown boot sessions compare equal.
  static let unavailableBootSessionID = "unavailable"

  static func validBootSessionID(_ value: String) -> Bool {
    !value.isEmpty && value != unavailableBootSessionID
      && value.utf8.count <= maximumBootSessionIDBytes
  }
}

private struct TacuaDynamicCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue: Int) { return nil }
}

private extension KeyedDecodingContainer {
  func decodeBoundedString(forKey key: Key, maximumUTF8Bytes: Int) throws -> String {
    let value = try decode(String.self, forKey: key)
    guard value.utf8.count <= maximumUTF8Bytes else {
      throw TacuaTransportQueueError.invalidQueue
    }
    return value
  }

  func decodeBoundedStringIfPresent(forKey key: Key, maximumUTF8Bytes: Int) throws -> String? {
    guard contains(key), try !decodeNil(forKey: key) else { return nil }
    return try decodeBoundedString(forKey: key, maximumUTF8Bytes: maximumUTF8Bytes)
  }

  func decodeBoundedArray<Element: Decodable>(
    _ type: Element.Type,
    forKey key: Key,
    maximumCount: Int
  ) throws -> [Element] {
    var valuesContainer = try nestedUnkeyedContainer(forKey: key)
    if let count = valuesContainer.count, count > maximumCount {
      throw TacuaTransportQueueError.invalidQueue
    }
    var values: [Element] = []
    values.reserveCapacity(min(valuesContainer.count ?? 0, maximumCount))
    while !valuesContainer.isAtEnd {
      guard values.count < maximumCount else {
        throw TacuaTransportQueueError.invalidQueue
      }
      values.append(try valuesContainer.decode(Element.self))
    }
    return values
  }

  func decodeBoundedArrayIfPresent<Element: Decodable>(
    _ type: Element.Type,
    forKey key: Key,
    maximumCount: Int
  ) throws -> [Element]? {
    guard contains(key), try !decodeNil(forKey: key) else { return nil }
    return try decodeBoundedArray(type, forKey: key, maximumCount: maximumCount)
  }

  func decodeBoundedStringArray(
    forKey key: Key,
    maximumCount: Int,
    maximumElementUTF8Bytes: Int
  ) throws -> [String] {
    var valuesContainer = try nestedUnkeyedContainer(forKey: key)
    if let count = valuesContainer.count, count > maximumCount {
      throw TacuaTransportQueueError.invalidQueue
    }
    var values: [String] = []
    values.reserveCapacity(min(valuesContainer.count ?? 0, maximumCount))
    while !valuesContainer.isAtEnd {
      guard values.count < maximumCount else {
        throw TacuaTransportQueueError.invalidQueue
      }
      let value = try valuesContainer.decode(String.self)
      guard value.utf8.count <= maximumElementUTF8Bytes else {
        throw TacuaTransportQueueError.invalidQueue
      }
      values.append(value)
    }
    return values
  }

  func decodeBoundedStringDictionaryIfPresent(
    forKey key: Key,
    maximumCount: Int,
    maximumKeyUTF8Bytes: Int,
    maximumValueUTF8Bytes: Int
  ) throws -> [String: String]? {
    guard contains(key), try !decodeNil(forKey: key) else { return nil }
    let valuesContainer = try nestedContainer(keyedBy: TacuaDynamicCodingKey.self, forKey: key)
    let keys = valuesContainer.allKeys
    guard keys.count <= maximumCount else { throw TacuaTransportQueueError.invalidQueue }
    var values: [String: String] = [:]
    values.reserveCapacity(keys.count)
    for key in keys {
      guard key.stringValue.utf8.count <= maximumKeyUTF8Bytes else {
        throw TacuaTransportQueueError.invalidQueue
      }
      let value = try valuesContainer.decode(String.self, forKey: key)
      guard value.utf8.count <= maximumValueUTF8Bytes else {
        throw TacuaTransportQueueError.invalidQueue
      }
      values[key.stringValue] = value
    }
    return values
  }
}

enum TacuaTransportCredentialCapability: String, Codable, Equatable {
  case requiresExchange = "requires_exchange"
  case requiresTransportRebind = "requires_transport_rebind"
  case active
  case completionReplayOrDeleteOnly = "completion_replay_or_delete_only"
  case deletionReplayOnly = "deletion_replay_only"
}

enum TacuaQueuedOperationKind: String, Codable, Equatable {
  case segment
  case diagnostic
  case completion
  case deletion
}

enum TacuaQueuedOperationState: String, Codable, Equatable {
  case queued
  case responseStored = "response_stored"
}

struct TacuaQueuedOperation: Codable, Equatable {
  let kind: TacuaQueuedOperationKind
  let operationID: String
  /// Immutable protocol truth. Rotation never rewrites this identifier.
  let requestCredentialID: String
  let requestDigest: String
  /// Exact canonical request bytes for replay. Launch exchanges are never queued.
  let canonicalRequest: Data
  /// Legacy queue-v2 inventory. It is retained for decoding, but never grants deletion authority.
  let localPayloadPath: String?
  /// Every removable file is bound to immutable request evidence. Optional preserves decoding of
  /// queues written before payload binding was introduced; nil is intentionally untrusted.
  let localPayloadBindings: [TacuaLocalPayloadBinding]?
  var state: TacuaQueuedOperationState
  var canonicalResponse: Data?
  var responseDigest: String?
  /// Protocol artifact digest (for example segment_receipt_digest), distinct from the hash of the
  /// complete canonical response bytes above.
  var responseArtifactDigest: String?

  private enum CodingKeys: String, CodingKey {
    case kind
    case operationID
    case requestCredentialID
    case requestDigest
    case canonicalRequest
    case localPayloadPath
    case localPayloadBindings
    case state
    case canonicalResponse
    case responseDigest
    case responseArtifactDigest
  }
}

extension TacuaQueuedOperation {
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    kind = try container.decode(TacuaQueuedOperationKind.self, forKey: .kind)
    operationID = try container.decodeBoundedString(
      forKey: .operationID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    requestCredentialID = try container.decodeBoundedString(
      forKey: .requestCredentialID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    requestDigest = try container.decodeBoundedString(
      forKey: .requestDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    canonicalRequest = try container.decode(Data.self, forKey: .canonicalRequest)
    guard canonicalRequest.count <= TacuaQueueBounds.maximumEncodedBytes else {
      throw TacuaTransportQueueError.invalidQueue
    }
    localPayloadPath = try container.decodeBoundedStringIfPresent(
      forKey: .localPayloadPath,
      maximumUTF8Bytes: TacuaQueueBounds.maximumRelativePathBytes
    )
    localPayloadBindings = try container.decodeBoundedArrayIfPresent(
      TacuaLocalPayloadBinding.self,
      forKey: .localPayloadBindings,
      maximumCount: TacuaQueueBounds.maximumPayloadBindingsPerOperation
    )
    state = try container.decode(TacuaQueuedOperationState.self, forKey: .state)
    canonicalResponse = try container.decodeIfPresent(Data.self, forKey: .canonicalResponse)
    if let canonicalResponse,
      canonicalResponse.count > TacuaQueueBounds.maximumEncodedBytes
    {
      throw TacuaTransportQueueError.invalidQueue
    }
    responseDigest = try container.decodeBoundedStringIfPresent(
      forKey: .responseDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    responseArtifactDigest = try container.decodeBoundedStringIfPresent(
      forKey: .responseArtifactDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
  }
}

enum TacuaLocalPayloadRole: String, Codable, Equatable, Hashable {
  case segmentMedia = "segment_media"
  case segmentSidecar = "segment_sidecar"
  case diagnosticEnvelope = "diagnostic_envelope"
}

struct TacuaLocalPayloadBinding: Codable, Equatable, Hashable {
  let role: TacuaLocalPayloadRole
  let relativePath: String
  let contentDigest: String

  private enum CodingKeys: String, CodingKey {
    case role
    case relativePath
    case contentDigest
  }
}

extension TacuaLocalPayloadBinding {
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    role = try container.decode(TacuaLocalPayloadRole.self, forKey: .role)
    relativePath = try container.decodeBoundedString(
      forKey: .relativePath,
      maximumUTF8Bytes: TacuaQueueBounds.maximumRelativePathBytes
    )
    contentDigest = try container.decodeBoundedString(
      forKey: .contentDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
  }
}

struct TacuaServerTimeAnchor: Codable, Equatable {
  let issuedAt: String
  let issuedEpochMilliseconds: Int64
  let uptimeMillisecondsAtIssue: Int64
  let bootSessionID: String
  let minimumEpochMilliseconds: Int64

  private enum CodingKeys: String, CodingKey {
    case issuedAt
    case issuedEpochMilliseconds
    case uptimeMillisecondsAtIssue
    case bootSessionID
    case minimumEpochMilliseconds
  }

  static func establish(issuedAt: String, clock: TacuaMonotonicClock) throws
    -> TacuaServerTimeAnchor
  {
    guard let epoch = TacuaProtocolTimestamp.parseMilliseconds(issuedAt) else {
      throw TacuaTransportQueueError.invalidTimestamp
    }
    let uptime = clock.uptimeMilliseconds
    let bootSessionID = clock.bootSessionID
    guard uptime >= 0, TacuaQueueBounds.validBootSessionID(bootSessionID) else {
      throw TacuaTransportQueueError.invalidTimeAnchor
    }
    return TacuaServerTimeAnchor(
      issuedAt: issuedAt,
      issuedEpochMilliseconds: epoch,
      uptimeMillisecondsAtIssue: uptime,
      bootSessionID: bootSessionID,
      minimumEpochMilliseconds: epoch
    )
  }

  func timestamp(clock: TacuaMonotonicClock) throws -> String {
    let currentBootSessionID = clock.bootSessionID
    let currentUptimeMilliseconds = clock.uptimeMilliseconds
    guard TacuaQueueBounds.validBootSessionID(bootSessionID),
      TacuaQueueBounds.validBootSessionID(currentBootSessionID),
      currentBootSessionID == bootSessionID,
      currentUptimeMilliseconds >= uptimeMillisecondsAtIssue
    else {
      throw TacuaTransportQueueError.resumeRequired
    }
    let elapsed = currentUptimeMilliseconds - uptimeMillisecondsAtIssue
    let derived = max(minimumEpochMilliseconds, issuedEpochMilliseconds + elapsed)
    return TacuaProtocolTimestamp.format(milliseconds: derived)
  }

  func advancing(
    toAuthoritativeServerTimestamp timestamp: String,
    clock: TacuaMonotonicClock
  ) throws -> TacuaServerTimeAnchor {
    _ = try self.timestamp(clock: clock)
    guard let authoritative = TacuaProtocolTimestamp.parseMilliseconds(timestamp) else {
      throw TacuaTransportQueueError.invalidTimestamp
    }
    return TacuaServerTimeAnchor(
      issuedAt: issuedAt,
      issuedEpochMilliseconds: issuedEpochMilliseconds,
      uptimeMillisecondsAtIssue: uptimeMillisecondsAtIssue,
      bootSessionID: bootSessionID,
      minimumEpochMilliseconds: max(minimumEpochMilliseconds, authoritative)
    )
  }
}

extension TacuaServerTimeAnchor {
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    issuedAt = try container.decodeBoundedString(
      forKey: .issuedAt,
      maximumUTF8Bytes: TacuaQueueBounds.maximumTimestampBytes
    )
    issuedEpochMilliseconds = try container.decode(Int64.self, forKey: .issuedEpochMilliseconds)
    uptimeMillisecondsAtIssue = try container.decode(
      Int64.self,
      forKey: .uptimeMillisecondsAtIssue
    )
    bootSessionID = try container.decodeBoundedString(
      forKey: .bootSessionID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumBootSessionIDBytes
    )
    minimumEpochMilliseconds = try container.decode(
      Int64.self,
      forKey: .minimumEpochMilliseconds
    )
  }
}

protocol TacuaMonotonicClock {
  var uptimeMilliseconds: Int64 { get }
  var bootSessionID: String { get }
}

struct TacuaSystemMonotonicClock: TacuaMonotonicClock {
  var uptimeMilliseconds: Int64 {
    Int64((ProcessInfo.processInfo.systemUptime * 1_000).rounded(.down))
  }

  var bootSessionID: String {
    var bootTime = timeval()
    var size = MemoryLayout<timeval>.size
    let result = sysctlbyname("kern.boottime", &bootTime, &size, nil, 0)
    guard result == 0, size == MemoryLayout<timeval>.size,
      bootTime.tv_sec > 0, bootTime.tv_usec >= 0, bootTime.tv_usec < 1_000_000
    else {
      // The empty value is deliberately invalid. In particular, do not return a stable sentinel:
      // two lookup failures must never be mistaken for the same boot session.
      return ""
    }
    return "boot_\(bootTime.tv_sec)_\(bootTime.tv_usec)"
  }
}

struct TacuaCompletionCleanupAuthority: Codable, Equatable {
  let completionID: String
  let completionReceiptDigest: String
  let manifestDigest: String
  let segmentReceiptDigests: [String]
  let diagnosticReceiptDigests: [String]

  private enum CodingKeys: String, CodingKey {
    case completionID
    case completionReceiptDigest
    case manifestDigest
    case segmentReceiptDigests
    case diagnosticReceiptDigests
  }
}

extension TacuaCompletionCleanupAuthority {
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    completionID = try container.decodeBoundedString(
      forKey: .completionID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    completionReceiptDigest = try container.decodeBoundedString(
      forKey: .completionReceiptDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    manifestDigest = try container.decodeBoundedString(
      forKey: .manifestDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    segmentReceiptDigests = try container.decodeBoundedStringArray(
      forKey: .segmentReceiptDigests,
      maximumCount: TacuaQueueBounds.maximumOperations,
      maximumElementUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    diagnosticReceiptDigests = try container.decodeBoundedStringArray(
      forKey: .diagnosticReceiptDigests,
      maximumCount: TacuaQueueBounds.maximumOperations,
      maximumElementUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
  }
}

struct TacuaDeletionCleanupAuthority: Codable, Equatable {
  let deletionID: String
  let tombstoneDigest: String
  let credentialID: String

  private enum CodingKeys: String, CodingKey {
    case deletionID
    case tombstoneDigest
    case credentialID
  }
}

extension TacuaDeletionCleanupAuthority {
  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    deletionID = try container.decodeBoundedString(
      forKey: .deletionID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    tombstoneDigest = try container.decodeBoundedString(
      forKey: .tombstoneDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    credentialID = try container.decodeBoundedString(
      forKey: .credentialID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
  }
}

enum TacuaPayloadCleanupState: String, Codable, Equatable {
  case none
  case tombstoneWritten = "tombstone_written"
  case payloadsRemoved = "payloads_removed"
}

enum TacuaCredentialCleanupState: String, Codable, Equatable {
  case none
  case tombstoneWritten = "tombstone_written"
  case credentialRemoved = "credential_removed"
}

struct TacuaTransportQueueV3: Codable, Equatable {
  static let schemaVersion = 3
  static let maximumEncodedBytes = TacuaQueueBounds.maximumEncodedBytes
  static let maximumLocalPayloadPaths = TacuaQueueBounds.maximumLocalPayloadPaths

  var schemaVersion: Int
  let localSessionID: String
  /// Exact digest of the build-pinned backend origin/policy used for the latest exchange.
  /// It is nil only before the first exchange or while an explicitly migrated V2 queue waits for
  /// a fresh transport-rebinding resume exchange, plus migrated deletion cleanup queues which
  /// intentionally cannot send again.
  var transportConfigurationDigest: String?
  var remoteSessionID: String?
  var scopeDigest: String?
  var currentCredentialID: String?
  var currentCredentialExpiresAt: String?
  /// Historical expiry is immutable request-validation context. It lets a response for credential
  /// B be validated after transport authentication has rotated to credential C.
  var credentialExpiryLedger: [String: String]?
  var pendingRevokedCredentialRemovals: [String]
  var credentialCapability: TacuaTransportCredentialCapability
  var timeAnchor: TacuaServerTimeAnchor?
  var operations: [TacuaQueuedOperation]
  var localPayloadPaths: [String]
  var completionCleanupAuthority: TacuaCompletionCleanupAuthority?
  var deletionCleanupAuthority: TacuaDeletionCleanupAuthority?
  var payloadCleanupState: TacuaPayloadCleanupState
  var credentialCleanupState: TacuaCredentialCleanupState

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case localSessionID
    case transportConfigurationDigest
    case remoteSessionID
    case scopeDigest
    case currentCredentialID
    case currentCredentialExpiresAt
    case credentialExpiryLedger
    case pendingRevokedCredentialRemovals
    case credentialCapability
    case timeAnchor
    case operations
    case localPayloadPaths
    case completionCleanupAuthority
    case deletionCleanupAuthority
    case payloadCleanupState
    case credentialCleanupState
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
    localSessionID = try container.decodeBoundedString(
      forKey: .localSessionID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    transportConfigurationDigest = try container.decodeBoundedStringIfPresent(
      forKey: .transportConfigurationDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    remoteSessionID = try container.decodeBoundedStringIfPresent(
      forKey: .remoteSessionID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    scopeDigest = try container.decodeBoundedStringIfPresent(
      forKey: .scopeDigest,
      maximumUTF8Bytes: TacuaQueueBounds.maximumDigestBytes
    )
    currentCredentialID = try container.decodeBoundedStringIfPresent(
      forKey: .currentCredentialID,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    currentCredentialExpiresAt = try container.decodeBoundedStringIfPresent(
      forKey: .currentCredentialExpiresAt,
      maximumUTF8Bytes: TacuaQueueBounds.maximumTimestampBytes
    )
    credentialExpiryLedger = try container.decodeBoundedStringDictionaryIfPresent(
      forKey: .credentialExpiryLedger,
      maximumCount: TacuaQueueBounds.maximumCredentialEntries,
      maximumKeyUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes,
      maximumValueUTF8Bytes: TacuaQueueBounds.maximumTimestampBytes
    )
    pendingRevokedCredentialRemovals = try container.decodeBoundedStringArray(
      forKey: .pendingRevokedCredentialRemovals,
      maximumCount: TacuaQueueBounds.maximumCredentialEntries,
      maximumElementUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    credentialCapability = try container.decode(
      TacuaTransportCredentialCapability.self,
      forKey: .credentialCapability
    )
    timeAnchor = try container.decodeIfPresent(TacuaServerTimeAnchor.self, forKey: .timeAnchor)
    operations = try container.decodeBoundedArray(
      TacuaQueuedOperation.self,
      forKey: .operations,
      maximumCount: TacuaQueueBounds.maximumOperations
    )
    localPayloadPaths = try container.decodeBoundedStringArray(
      forKey: .localPayloadPaths,
      maximumCount: TacuaQueueBounds.maximumLocalPayloadPaths,
      maximumElementUTF8Bytes: TacuaQueueBounds.maximumRelativePathBytes
    )
    completionCleanupAuthority = try container.decodeIfPresent(
      TacuaCompletionCleanupAuthority.self,
      forKey: .completionCleanupAuthority
    )
    deletionCleanupAuthority = try container.decodeIfPresent(
      TacuaDeletionCleanupAuthority.self,
      forKey: .deletionCleanupAuthority
    )
    payloadCleanupState = try container.decode(
      TacuaPayloadCleanupState.self,
      forKey: .payloadCleanupState
    )
    credentialCleanupState = try container.decode(
      TacuaCredentialCleanupState.self,
      forKey: .credentialCleanupState
    )
  }

  init(localSessionID: String, localPayloadPaths: [String] = []) throws {
    guard TacuaTransportQueueV3.validIdentifier(localSessionID),
      localPayloadPaths.count <= Self.maximumLocalPayloadPaths,
      localPayloadPaths.allSatisfy(TacuaTransportQueueV3.validRelativePath)
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    schemaVersion = Self.schemaVersion
    self.localSessionID = localSessionID
    transportConfigurationDigest = nil
    remoteSessionID = nil
    scopeDigest = nil
    currentCredentialID = nil
    currentCredentialExpiresAt = nil
    credentialExpiryLedger = [:]
    pendingRevokedCredentialRemovals = []
    credentialCapability = .requiresExchange
    timeAnchor = nil
    operations = []
    self.localPayloadPaths = localPayloadPaths
    completionCleanupAuthority = nil
    deletionCleanupAuthority = nil
    payloadCleanupState = .none
    credentialCleanupState = .none
  }

  static func decodeOrMigrate(_ data: Data) throws -> TacuaTransportQueueV3 {
    // Bound the parser itself, not just the subsequently encoded queue. JSONDecoder must still
    // materialize some Foundation values internally, but it never receives attacker-controlled
    // input larger than the durable queue limit.
    guard !data.isEmpty, data.count <= Self.maximumEncodedBytes else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let decoder = JSONDecoder()
    let probe = try decoder.decode(TacuaQueueSchemaProbe.self, from: data)
    switch probe.schemaVersion {
    case schemaVersion:
      var queue = try decoder.decode(TacuaTransportQueueV3.self, from: data)
      try normalizeDecodedQueue(&queue)
      try queue.validate()
      return queue
    case 2:
      var queue = try decoder.decode(TacuaTransportQueueV3.self, from: data)
      queue.schemaVersion = schemaVersion
      switch queue.credentialCapability {
      case .requiresExchange, .deletionReplayOnly:
        // A deletion receipt has already terminated transport authority. Keep its local cleanup
        // state terminal instead of manufacturing a resume transition which can never be valid.
        break
      case .active, .completionReplayOrDeleteOnly, .requiresTransportRebind:
        // V2 never bound authority to a backend transport configuration. Preserve immutable
        // requests and cleanup evidence, but block every send until a fresh resume exchange binds
        // the queue to the currently built origin/policy digest.
        queue.credentialCapability = .requiresTransportRebind
      }
      queue.transportConfigurationDigest = nil
      // Queue-v2 accepted `"unavailable"` when the OS boot identity could not be read. That
      // sentinel is not a trustworthy cross-restart anchor, but it must not make an otherwise
      // recoverable durable queue unreadable. Drop only the unusable anchor and require rebind.
      if let anchor = queue.timeAnchor,
        !TacuaQueueBounds.validBootSessionID(anchor.bootSessionID)
      {
        queue.timeAnchor = nil
      }
      try normalizeDecodedQueue(&queue)
      try queue.validate()
      return queue
    case 1:
      let legacy = try decoder.decode(TacuaLegacyUploadQueue.self, from: data)
      var queue = try TacuaTransportQueueV3(
        localSessionID: legacy.localSessionId,
        localPayloadPaths: legacy.items.compactMap { item in
          guard item.objectKind == "segment" || item.objectKind == "diagnostic_envelope" else {
            return nil
          }
          return "legacy/\(item.objectId)"
        }
      )
      // V1 grants cannot be upgraded to V1 protocol credentials or immutable scope.
      // Local payload inventory is retained, but a fresh launch/resume exchange is mandatory.
      queue.remoteSessionID = nil
      queue.scopeDigest = nil
      queue.currentCredentialID = nil
      queue.currentCredentialExpiresAt = nil
      queue.credentialExpiryLedger = [:]
      queue.pendingRevokedCredentialRemovals = []
      queue.credentialCapability = .requiresExchange
      queue.timeAnchor = nil
      try queue.validate()
      return queue
    default:
      throw TacuaTransportQueueError.unsupportedSchemaVersion
    }
  }

  private static func normalizeDecodedQueue(_ queue: inout TacuaTransportQueueV3) throws {
    if queue.credentialExpiryLedger == nil {
      if let credentialID = queue.currentCredentialID,
        let expiresAt = queue.currentCredentialExpiresAt
      {
        queue.credentialExpiryLedger = [credentialID: expiresAt]
      } else {
        queue.credentialExpiryLedger = [:]
      }
    }
    // queue-v2 also predates persisted protocol-artifact digests. Re-derive them from the exact
    // immutable request/response pair before validating cleanup authorities.
    for index in queue.operations.indices
    where queue.operations[index].state == .responseStored
      && queue.operations[index].responseArtifactDigest == nil
    {
      guard let response = queue.operations[index].canonicalResponse,
        let expiry = queue.credentialExpiryLedger?[
          queue.operations[index].requestCredentialID
        ],
        let receipt = try? TacuaSDKBackendProtocol.validateResponse(
          response,
          forCanonicalRequest: queue.operations[index].canonicalRequest,
          expectedCurrentCredentialExpiry: expiry
        )
      else { throw TacuaTransportQueueError.invalidQueue }
      queue.operations[index].responseArtifactDigest = receipt.responseDigest
    }
  }

  func encoded() throws -> Data {
    try validate()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(self)
    guard data.count <= Self.maximumEncodedBytes else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let parsed = try JSONSerialization.jsonObject(with: data)
    guard !Self.containsProhibitedKey(parsed) else {
      throw TacuaTransportQueueError.prohibitedPersistedMaterial
    }
    return data
  }

  mutating func applyExchange(
    remoteSessionID: String,
    scopeDigest: String,
    credentialID: String,
    transportConfigurationDigest: String,
    expiresAt: String,
    previousCredentialID: String? = nil,
    capability: TacuaTransportCredentialCapability,
    issuedAt: String,
    clock: TacuaMonotonicClock
  ) throws {
    guard Self.validIdentifier(remoteSessionID), Self.validDigest(scopeDigest),
      Self.validIdentifier(credentialID), capability != .requiresExchange,
      capability != .deletionReplayOnly,
      previousCredentialID.map(Self.validIdentifier) ?? true,
      previousCredentialID != credentialID,
      let expiryMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(expiresAt),
      let issueMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(issuedAt),
      expiryMilliseconds > issueMilliseconds
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    if let existingSession = self.remoteSessionID, existingSession != remoteSessionID {
      throw TacuaTransportQueueError.operationConflict
    }
    if let existingScope = self.scopeDigest, existingScope != scopeDigest {
      throw TacuaTransportQueueError.operationConflict
    }
    if let existingExpiry = credentialExpiryLedger?[credentialID], existingExpiry != expiresAt {
      throw TacuaTransportQueueError.operationConflict
    }
    guard credentialExpiryLedger?[credentialID] != nil
      || (credentialExpiryLedger?.count ?? 0) < 4_096
    else { throw TacuaTransportQueueError.invalidQueue }
    guard !pendingRevokedCredentialRemovals.contains(credentialID) else {
      throw TacuaTransportQueueError.credentialMismatch
    }
    let newAnchor = try TacuaServerTimeAnchor.establish(issuedAt: issuedAt, clock: clock)
    try applyExchange(
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      transportConfigurationDigest: transportConfigurationDigest,
      expiresAt: expiresAt,
      previousCredentialID: previousCredentialID,
      capability: capability,
      timeAnchor: newAnchor
    )
  }

  /// Reconstructs a validated START transition from the exact anchor captured when the receipt was
  /// observed. Recovery must never re-anchor an old server timestamp to a later uptime or reboot.
  mutating func applyRecoveredStart(
    remoteSessionID: String,
    scopeDigest: String,
    credentialID: String,
    transportConfigurationDigest: String,
    expiresAt: String,
    timeAnchor: TacuaServerTimeAnchor
  ) throws {
    guard self.remoteSessionID == nil, self.scopeDigest == nil,
      self.transportConfigurationDigest == nil, currentCredentialID == nil,
      currentCredentialExpiresAt == nil, credentialCapability == .requiresExchange,
      operations.isEmpty, pendingRevokedCredentialRemovals.isEmpty,
      completionCleanupAuthority == nil, deletionCleanupAuthority == nil
    else { throw TacuaTransportQueueError.operationConflict }
    try applyExchange(
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      transportConfigurationDigest: transportConfigurationDigest,
      expiresAt: expiresAt,
      previousCredentialID: nil,
      capability: .active,
      timeAnchor: timeAnchor
    )
  }

  private mutating func applyExchange(
    remoteSessionID: String,
    scopeDigest: String,
    credentialID: String,
    transportConfigurationDigest: String,
    expiresAt: String,
    previousCredentialID: String?,
    capability: TacuaTransportCredentialCapability,
    timeAnchor newAnchor: TacuaServerTimeAnchor
  ) throws {
    guard Self.validIdentifier(remoteSessionID), Self.validDigest(scopeDigest),
      Self.validIdentifier(credentialID), Self.validDigest(transportConfigurationDigest),
      capability != .requiresExchange, capability != .requiresTransportRebind,
      capability != .deletionReplayOnly,
      previousCredentialID.map(Self.validIdentifier) ?? true,
      previousCredentialID != credentialID,
      let expiryMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(expiresAt),
      let issueMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(newAnchor.issuedAt),
      expiryMilliseconds > issueMilliseconds,
      newAnchor.issuedEpochMilliseconds == issueMilliseconds,
      newAnchor.uptimeMillisecondsAtIssue >= 0,
      TacuaQueueBounds.validBootSessionID(newAnchor.bootSessionID),
      newAnchor.minimumEpochMilliseconds >= issueMilliseconds
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    if let existing = self.transportConfigurationDigest,
      existing != transportConfigurationDigest
    {
      throw TacuaTransportQueueError.transportConfigurationMismatch
    }
    var revokedCredentialID: String?
    if let existingCredentialID = currentCredentialID,
      existingCredentialID != credentialID
    {
      guard previousCredentialID == existingCredentialID else {
        throw TacuaTransportQueueError.credentialMismatch
      }
      revokedCredentialID = existingCredentialID
    }
    if let revokedCredentialID,
      !pendingRevokedCredentialRemovals.contains(revokedCredentialID)
    {
      pendingRevokedCredentialRemovals.append(revokedCredentialID)
    }
    self.remoteSessionID = remoteSessionID
    self.scopeDigest = scopeDigest
    self.transportConfigurationDigest = transportConfigurationDigest
    currentCredentialID = credentialID
    currentCredentialExpiresAt = expiresAt
    if credentialExpiryLedger == nil { credentialExpiryLedger = [:] }
    credentialExpiryLedger?[credentialID] = expiresAt
    credentialCapability = capability
    timeAnchor = newAnchor
  }

  mutating func advanceTimeAnchor(
    authoritativeServerTimestamp: String,
    clock: TacuaMonotonicClock
  ) throws {
    guard let anchor = timeAnchor else { throw TacuaTransportQueueError.resumeRequired }
    timeAnchor = try anchor.advancing(
      toAuthoritativeServerTimestamp: authoritativeServerTimestamp,
      clock: clock
    )
  }

  func timestampForNewOperation(clock: TacuaMonotonicClock) throws -> String {
    guard credentialCapability != .requiresExchange,
      credentialCapability != .requiresTransportRebind,
      transportConfigurationDigest != nil, let anchor = timeAnchor,
      let expiresAt = currentCredentialExpiresAt,
      let expiry = TacuaProtocolTimestamp.parseMilliseconds(expiresAt)
    else {
      throw TacuaTransportQueueError.resumeRequired
    }
    let timestamp = try anchor.timestamp(clock: clock)
    guard let now = TacuaProtocolTimestamp.parseMilliseconds(timestamp), now < expiry else {
      // Credential validity is half-open: [issued_at, expires_at).
      throw TacuaTransportQueueError.resumeRequired
    }
    return timestamp
  }

  mutating func enqueueNewOperation(
    kind: TacuaQueuedOperationKind,
    operationID: String,
    requestCredentialID: String,
    request: TacuaJSONValue,
    requestDigest: String,
    localPayloadPath: String? = nil,
    localPayloadBindings: [TacuaLocalPayloadBinding] = [],
    clock: TacuaMonotonicClock
  ) throws {
    guard Self.validIdentifier(operationID), Self.validIdentifier(requestCredentialID),
      Self.validDigest(requestDigest),
      operations.count < TacuaQueueBounds.maximumOperations,
      localPayloadBindings.count <= TacuaQueueBounds.maximumPayloadBindingsPerOperation,
      localPayloadPath.map(Self.validRelativePath) ?? true,
      localPayloadBindings.allSatisfy({
        Self.validRelativePath($0.relativePath) && Self.validDigest($0.contentDigest)
      }),
      Set(localPayloadBindings.map(\.relativePath)).count == localPayloadBindings.count,
      Set(localPayloadBindings.map(\.role)).count == localPayloadBindings.count,
      localPayloadPath == nil || localPayloadBindings.isEmpty
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    guard let currentCredentialID else { throw TacuaTransportQueueError.missingCredential }
    guard requestCredentialID == currentCredentialID else {
      throw TacuaTransportQueueError.credentialMismatch
    }
    try authorizeNew(kind: kind)
    _ = try timestampForNewOperation(clock: clock)
    let canonicalRequest = try TacuaCanonicalJSON.data(request)
    guard canonicalRequest.count <= Self.maximumEncodedBytes else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let persistedObject = try JSONSerialization.jsonObject(with: canonicalRequest)
    guard !Self.containsProhibitedKey(persistedObject) else {
      throw TacuaTransportQueueError.prohibitedPersistedMaterial
    }
    guard try TacuaCanonicalJSON.digest(request, omittingRootField: Self.digestField(for: kind))
      == requestDigest
    else {
      throw TacuaTransportQueueError.invalidDigest
    }
    if !localPayloadBindings.isEmpty {
      try Self.validateLocalPayloadBindings(localPayloadBindings, for: kind, request: request)
    }
    guard !operations.contains(where: { $0.operationID == operationID }) else {
      throw TacuaTransportQueueError.operationConflict
    }
    operations.append(
      TacuaQueuedOperation(
        kind: kind,
        operationID: operationID,
        requestCredentialID: requestCredentialID,
        requestDigest: requestDigest,
        canonicalRequest: canonicalRequest,
        localPayloadPath: localPayloadPath,
        localPayloadBindings: localPayloadBindings.isEmpty ? nil : localPayloadBindings,
        state: .queued,
        canonicalResponse: nil,
        responseDigest: nil,
        responseArtifactDigest: nil
      )
    )
  }

  /// Returns immutable request bytes and the current transport credential. Those IDs may differ
  /// after rotation; only the Authorization credential rotates during an exact durable replay.
  func attempt(
    operationID: String,
    expectedTransportConfigurationDigest: String,
    clock: TacuaMonotonicClock
  ) throws -> TacuaOperationAttempt {
    guard let operation = operations.first(where: { $0.operationID == operationID }) else {
      throw TacuaTransportQueueError.operationNotFound
    }
    guard let transportCredentialID = currentCredentialID else {
      throw TacuaTransportQueueError.missingCredential
    }
    guard Self.validDigest(expectedTransportConfigurationDigest),
      transportConfigurationDigest == expectedTransportConfigurationDigest
    else { throw TacuaTransportQueueError.transportConfigurationMismatch }
    _ = try timestampForNewOperation(clock: clock)
    switch credentialCapability {
    case .requiresExchange, .requiresTransportRebind:
      throw TacuaTransportQueueError.resumeRequired
    case .active:
      break
    case .completionReplayOrDeleteOnly:
      guard operation.kind == .deletion
        || (operation.kind == .completion
          && completionCleanupAuthority?.completionID == operation.operationID)
      else {
        throw TacuaTransportQueueError.operationNotAllowed
      }
    case .deletionReplayOnly:
      guard operation.kind == .deletion,
        deletionCleanupAuthority?.deletionID == operation.operationID
      else {
        throw TacuaTransportQueueError.operationNotAllowed
      }
    }
    return TacuaOperationAttempt(
      canonicalRequest: operation.canonicalRequest,
      immutableRequestCredentialID: operation.requestCredentialID,
      transportCredentialID: transportCredentialID
    )
  }

  mutating func storeResponse(
    operationID: String,
    canonicalResponse: Data,
    responseDigest: String
  ) throws {
    guard canonicalResponse.count <= Self.maximumEncodedBytes else {
      throw TacuaTransportQueueError.responseConflict
    }
    let responseValue = try TacuaCanonicalJSON.parse(canonicalResponse)
    let persistedResponse = try JSONSerialization.jsonObject(with: canonicalResponse)
    guard try TacuaCanonicalJSON.data(responseValue) == canonicalResponse,
      TacuaCanonicalJSON.digest(data: canonicalResponse) == responseDigest,
      !Self.containsProhibitedKey(persistedResponse)
    else {
      throw TacuaTransportQueueError.responseConflict
    }
    guard let index = operations.firstIndex(where: { $0.operationID == operationID }) else {
      throw TacuaTransportQueueError.operationNotFound
    }
    if let prior = operations[index].canonicalResponse {
      guard prior == canonicalResponse, operations[index].responseDigest == responseDigest else {
        throw TacuaTransportQueueError.responseConflict
      }
      return
    }
    operations[index].canonicalResponse = canonicalResponse
    operations[index].responseDigest = responseDigest
    operations[index].state = .responseStored
  }

  mutating func storeValidatedReceipt(_ receipt: TacuaValidatedBackendReceipt) throws {
    guard let operation = operations.first(where: { $0.operationID == receipt.operationID }) else {
      throw TacuaTransportQueueError.operationNotFound
    }
    let expectedKind: TacuaBackendOperationKind
    switch operation.kind {
    case .segment: expectedKind = .segment
    case .diagnostic: expectedKind = .diagnostic
    case .completion: expectedKind = .completion
    case .deletion: expectedKind = .deletion
    }
    guard receipt.operationKind == expectedKind,
      receipt.remoteSessionID == remoteSessionID,
      receipt.scopeDigest == scopeDigest,
      let requestCredentialExpiry = credentialExpiryLedger?[operation.requestCredentialID]
    else {
      throw TacuaTransportQueueError.responseConflict
    }
    // Re-derive every binding and cleanup authority from the exact stored request/response pair.
    // A caller-created value cannot inject an asserted completion or deletion authority.
    let independentlyValidated = try TacuaSDKBackendProtocol.validateResponse(
      receipt.canonicalResponse,
      forCanonicalRequest: operation.canonicalRequest,
      expectedCurrentCredentialExpiry: requestCredentialExpiry
    )
    guard independentlyValidated == receipt else {
      throw TacuaTransportQueueError.responseConflict
    }
    var candidate = self
    try candidate.storeResponse(
      operationID: receipt.operationID,
      canonicalResponse: receipt.canonicalResponse,
      responseDigest: TacuaCanonicalJSON.digest(data: receipt.canonicalResponse)
    )
    guard let storedIndex = candidate.operations.firstIndex(where: {
      $0.operationID == receipt.operationID
    }) else { throw TacuaTransportQueueError.operationNotFound }
    if let prior = candidate.operations[storedIndex].responseArtifactDigest,
      prior != receipt.responseDigest
    {
      throw TacuaTransportQueueError.responseConflict
    }
    candidate.operations[storedIndex].responseArtifactDigest = receipt.responseDigest
    if let authority = receipt.completionCleanupAuthority {
      try candidate.authorizeCompletionCleanup(authority)
    }
    if let authority = receipt.deletionCleanupAuthority {
      try candidate.authorizeDeletionCleanup(authority)
    }
    try candidate.validate()
    self = candidate
  }

  private mutating func authorizeCompletionCleanup(_ authority: TacuaCompletionCleanupAuthority) throws {
    guard Self.validIdentifier(authority.completionID),
      Self.validDigest(authority.completionReceiptDigest), Self.validDigest(authority.manifestDigest),
      authority.segmentReceiptDigests.allSatisfy(Self.validDigest),
      authority.diagnosticReceiptDigests.allSatisfy(Self.validDigest),
      let operation = operations.first(where: { $0.operationID == authority.completionID }),
      operation.kind == .completion, operation.state == .responseStored,
      operation.responseArtifactDigest == authority.completionReceiptDigest,
      try authorizedPayloadBindings(for: authority).isEmpty == false
    else {
      throw TacuaTransportQueueError.cleanupNotAuthorized
    }
    if let existing = completionCleanupAuthority, existing != authority {
      throw TacuaTransportQueueError.responseConflict
    }
    completionCleanupAuthority = authority
    credentialCapability = .completionReplayOrDeleteOnly
  }

  private mutating func authorizeDeletionCleanup(_ authority: TacuaDeletionCleanupAuthority) throws {
    guard Self.validIdentifier(authority.deletionID), Self.validDigest(authority.tombstoneDigest),
      Self.validIdentifier(authority.credentialID), authority.credentialID == currentCredentialID,
      let operation = operations.first(where: { $0.operationID == authority.deletionID }),
      operation.kind == .deletion, operation.state == .responseStored,
      operation.responseArtifactDigest == authority.tombstoneDigest
    else {
      throw TacuaTransportQueueError.deletionNotAuthorized
    }
    if let existing = deletionCleanupAuthority, existing != authority {
      throw TacuaTransportQueueError.responseConflict
    }
    deletionCleanupAuthority = authority
    credentialCapability = .deletionReplayOnly
  }

  func authorizedLocalPayloadBindings() throws -> [TacuaLocalPayloadBinding] {
    guard let authority = completionCleanupAuthority else {
      throw TacuaTransportQueueError.cleanupNotAuthorized
    }
    return try authorizedPayloadBindings(for: authority)
  }

  private func authorizedPayloadBindings(
    for authority: TacuaCompletionCleanupAuthority
  ) throws -> [TacuaLocalPayloadBinding] {
    guard authority.segmentReceiptDigests.count <= TacuaQueueBounds.maximumOperations,
      authority.diagnosticReceiptDigests.count <= TacuaQueueBounds.maximumOperations,
      authority.segmentReceiptDigests.count + authority.diagnosticReceiptDigests.count
        <= TacuaQueueBounds.maximumOperations,
      Set(authority.segmentReceiptDigests).count
      == authority.segmentReceiptDigests.count,
      Set(authority.diagnosticReceiptDigests).count
        == authority.diagnosticReceiptDigests.count
    else { throw TacuaTransportQueueError.cleanupNotAuthorized }

    let receivedSegments = operations.filter {
      $0.kind == .segment && $0.state == .responseStored
    }
    let receivedDiagnostics = operations.filter {
      $0.kind == .diagnostic && $0.state == .responseStored
    }
    guard Set(receivedSegments.compactMap(\.responseArtifactDigest))
      == Set(authority.segmentReceiptDigests),
      receivedSegments.allSatisfy({ $0.responseArtifactDigest != nil }),
      Set(receivedSegments.compactMap(\.responseArtifactDigest)).count
        == receivedSegments.count,
      Set(receivedDiagnostics.compactMap(\.responseArtifactDigest))
        == Set(authority.diagnosticReceiptDigests),
      receivedDiagnostics.allSatisfy({ $0.responseArtifactDigest != nil }),
      Set(receivedDiagnostics.compactMap(\.responseArtifactDigest)).count
        == receivedDiagnostics.count
    else { throw TacuaTransportQueueError.cleanupNotAuthorized }

    var bindings: [TacuaLocalPayloadBinding] = []
    for operation in receivedSegments + receivedDiagnostics {
      guard let operationBindings = operation.localPayloadBindings,
        !operationBindings.isEmpty,
        operation.localPayloadPath == nil,
        let request = try? TacuaCanonicalJSON.parse(operation.canonicalRequest)
      else { throw TacuaTransportQueueError.cleanupNotAuthorized }
      try Self.validateLocalPayloadBindings(
        operationBindings, for: operation.kind, request: request
      )
      bindings.append(contentsOf: operationBindings)
    }
    guard Set(bindings.map(\.relativePath)).count == bindings.count else {
      throw TacuaTransportQueueError.cleanupNotAuthorized
    }
    return bindings
  }

  func validate() throws {
    guard schemaVersion == Self.schemaVersion, Self.validIdentifier(localSessionID),
      localPayloadPaths.count <= Self.maximumLocalPayloadPaths,
      operations.count <= TacuaQueueBounds.maximumOperations,
      localPayloadPaths.allSatisfy(Self.validRelativePath),
      Set(localPayloadPaths).count == localPayloadPaths.count
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    guard remoteSessionID.map(Self.validIdentifier) ?? true,
      scopeDigest.map(Self.validDigest) ?? true,
      currentCredentialID.map(Self.validIdentifier) ?? true,
      transportConfigurationDigest.map(Self.validDigest) ?? true
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    guard pendingRevokedCredentialRemovals.count <= TacuaQueueBounds.maximumCredentialEntries,
      pendingRevokedCredentialRemovals.allSatisfy(Self.validIdentifier),
      Set(pendingRevokedCredentialRemovals).count == pendingRevokedCredentialRemovals.count,
      !pendingRevokedCredentialRemovals.contains(where: { $0 == currentCredentialID })
    else { throw TacuaTransportQueueError.invalidQueue }
    guard let credentialExpiryLedger,
      credentialExpiryLedger.count <= TacuaQueueBounds.maximumCredentialEntries,
      credentialExpiryLedger.allSatisfy({
        Self.validIdentifier($0.key)
          && TacuaProtocolTimestamp.parseMilliseconds($0.value) != nil
      })
    else { throw TacuaTransportQueueError.invalidQueue }
    guard pendingRevokedCredentialRemovals.allSatisfy({
      credentialExpiryLedger[$0] != nil
    }) else { throw TacuaTransportQueueError.invalidQueue }
    if let timeAnchor {
      guard let issuedEpoch = TacuaProtocolTimestamp.parseMilliseconds(timeAnchor.issuedAt),
        timeAnchor.issuedEpochMilliseconds == issuedEpoch,
        timeAnchor.uptimeMillisecondsAtIssue >= 0,
        TacuaQueueBounds.validBootSessionID(timeAnchor.bootSessionID),
        timeAnchor.minimumEpochMilliseconds >= issuedEpoch
      else { throw TacuaTransportQueueError.invalidQueue }
    }
    if credentialCapability == .requiresExchange {
      guard transportConfigurationDigest == nil, currentCredentialID == nil,
        currentCredentialExpiresAt == nil, timeAnchor == nil,
        credentialExpiryLedger.isEmpty
      else {
        throw TacuaTransportQueueError.invalidQueue
      }
    } else if credentialCapability == .requiresTransportRebind {
      guard transportConfigurationDigest == nil, remoteSessionID != nil, scopeDigest != nil,
        currentCredentialID != nil,
        currentCredentialExpiresAt.flatMap(TacuaProtocolTimestamp.parseMilliseconds) != nil,
        let currentCredentialID, let currentCredentialExpiresAt,
        credentialExpiryLedger[currentCredentialID] == currentCredentialExpiresAt
      else { throw TacuaTransportQueueError.invalidQueue }
    } else if credentialCapability == .deletionReplayOnly {
      // A migrated queue-v2 deletion has no trustworthy transport binding and must remain unable to
      // send. Its independently validated tombstone still authorizes completion of local cleanup.
      guard remoteSessionID != nil, scopeDigest != nil, deletionCleanupAuthority != nil else {
        throw TacuaTransportQueueError.invalidQueue
      }
      if credentialCleanupState == .credentialRemoved {
        guard currentCredentialID == nil, currentCredentialExpiresAt == nil else {
          throw TacuaTransportQueueError.invalidQueue
        }
      } else {
        guard let currentCredentialID, let currentCredentialExpiresAt,
          TacuaProtocolTimestamp.parseMilliseconds(currentCredentialExpiresAt) != nil,
          credentialExpiryLedger[currentCredentialID] == currentCredentialExpiresAt
        else { throw TacuaTransportQueueError.invalidQueue }
      }
    } else {
      guard transportConfigurationDigest.map(Self.validDigest) == true,
        remoteSessionID != nil, scopeDigest != nil, currentCredentialID != nil,
        currentCredentialExpiresAt.flatMap(TacuaProtocolTimestamp.parseMilliseconds) != nil,
        timeAnchor != nil || credentialCapability == .deletionReplayOnly
      else {
        throw TacuaTransportQueueError.invalidQueue
      }
      guard let currentCredentialID, let currentCredentialExpiresAt,
        credentialExpiryLedger[currentCredentialID] == currentCredentialExpiresAt
      else { throw TacuaTransportQueueError.invalidQueue }
    }
    var operationIDs = Set<String>()
    var boundPayloadPaths = Set<String>()
    for operation in operations {
      let bindings = operation.localPayloadBindings ?? []
      guard Self.validIdentifier(operation.operationID),
        Self.validIdentifier(operation.requestCredentialID),
        Self.validDigest(operation.requestDigest),
        operation.canonicalRequest.count <= Self.maximumEncodedBytes,
        bindings.count <= TacuaQueueBounds.maximumPayloadBindingsPerOperation,
        operationIDs.insert(operation.operationID).inserted,
        operation.localPayloadPath.map(Self.validRelativePath) ?? true,
        bindings.allSatisfy({
          Self.validRelativePath($0.relativePath) && Self.validDigest($0.contentDigest)
        }),
        Set(bindings.map(\.role)).count == bindings.count,
        bindings.allSatisfy({ boundPayloadPaths.insert($0.relativePath).inserted }),
        operation.localPayloadPath == nil || bindings.isEmpty,
        (try? TacuaCanonicalJSON.parse(operation.canonicalRequest)) != nil
      else {
        throw TacuaTransportQueueError.invalidQueue
      }
      let request = try TacuaCanonicalJSON.parse(operation.canonicalRequest)
      let requestObject = try JSONSerialization.jsonObject(with: operation.canonicalRequest)
      guard try TacuaCanonicalJSON.data(request) == operation.canonicalRequest,
        try TacuaCanonicalJSON.digest(
          request, omittingRootField: Self.digestField(for: operation.kind)
        ) == operation.requestDigest,
        !Self.containsProhibitedKey(requestObject)
      else { throw TacuaTransportQueueError.invalidQueue }
      switch operation.state {
      case .queued:
        guard operation.canonicalResponse == nil, operation.responseDigest == nil,
          operation.responseArtifactDigest == nil
        else {
          throw TacuaTransportQueueError.invalidQueue
        }
      case .responseStored:
        guard let response = operation.canonicalResponse,
          response.count <= Self.maximumEncodedBytes,
          operation.responseDigest.map(Self.validDigest) == true,
          operation.responseArtifactDigest.map(Self.validDigest) == true,
          (try? TacuaCanonicalJSON.parse(response)) != nil
        else {
          throw TacuaTransportQueueError.invalidQueue
        }
        let responseValue = try TacuaCanonicalJSON.parse(response)
        let responseObject = try JSONSerialization.jsonObject(with: response)
        guard try TacuaCanonicalJSON.data(responseValue) == response,
          TacuaCanonicalJSON.digest(data: response) == operation.responseDigest,
          !Self.containsProhibitedKey(responseObject)
        else { throw TacuaTransportQueueError.invalidQueue }
      }
      if !bindings.isEmpty {
        try Self.validateLocalPayloadBindings(bindings, for: operation.kind, request: request)
      }
    }
    if payloadCleanupState != .none { guard completionCleanupAuthority != nil else {
      throw TacuaTransportQueueError.invalidQueue
    }}
    if let completionCleanupAuthority {
      _ = try authorizedPayloadBindings(for: completionCleanupAuthority)
    }
    if credentialCleanupState != .none { guard deletionCleanupAuthority != nil else {
      throw TacuaTransportQueueError.invalidQueue
    }}
  }

  private func authorizeNew(kind: TacuaQueuedOperationKind) throws {
    switch credentialCapability {
    case .active:
      break
    case .completionReplayOrDeleteOnly:
      guard kind == .deletion else { throw TacuaTransportQueueError.operationNotAllowed }
    case .requiresExchange, .requiresTransportRebind:
      throw TacuaTransportQueueError.resumeRequired
    case .deletionReplayOnly:
      throw TacuaTransportQueueError.operationNotAllowed
    }
  }

  private static func digestField(for kind: TacuaQueuedOperationKind) -> String {
    switch kind {
    case .segment: return "intent_digest"
    case .diagnostic, .completion, .deletion: return "request_digest"
    }
  }

  private static func validateLocalPayloadBindings(
    _ bindings: [TacuaLocalPayloadBinding],
    for kind: TacuaQueuedOperationKind,
    request: TacuaJSONValue
  ) throws {
    guard let root = request.objectValue else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let expected: [TacuaLocalPayloadRole: String]
    switch kind {
    case .segment:
      guard let transport = root["transport"]?.objectValue,
        let contentDigest = transport["content_digest"]?.stringValue,
        let sidecarDigest = root["sidecar_digest"]?.stringValue
      else { throw TacuaTransportQueueError.invalidQueue }
      expected = [
        .segmentMedia: contentDigest,
        .segmentSidecar: sidecarDigest,
      ]
    case .diagnostic:
      guard let transport = root["transport"]?.objectValue,
        let contentDigest = transport["content_digest"]?.stringValue
      else { throw TacuaTransportQueueError.invalidQueue }
      expected = [.diagnosticEnvelope: contentDigest]
    case .completion, .deletion:
      expected = [:]
    }
    guard bindings.count == expected.count,
      bindings.allSatisfy({ expected[$0.role] == $0.contentDigest })
    else { throw TacuaTransportQueueError.invalidQueue }
  }

  fileprivate static func validIdentifier(_ value: String) -> Bool {
    guard (3...TacuaQueueBounds.maximumIdentifierBytes).contains(value.utf8.count) else {
      return false
    }
    return value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    guard value.utf8.count == TacuaQueueBounds.maximumDigestBytes else { return false }
    return value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func validRelativePath(_ value: String) -> Bool {
    let byteCount = value.utf8.count
    guard byteCount > 0, byteCount <= TacuaQueueBounds.maximumRelativePathBytes,
      !value.hasPrefix("/"), !value.contains("\0"), !value.contains("\\")
    else { return false }
    let components = value.split(separator: "/", omittingEmptySubsequences: false)
    return components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
  }

  private static func containsProhibitedKey(_ value: Any) -> Bool {
    if let object = value as? [String: Any] {
      let prohibited = Set([
        "launch_code", "authorization", "bearer", "password", "cookie", "set_cookie",
        "access_token", "refresh_token",
      ])
      if object.keys.contains(where: { key in
        guard key.utf8.count <= TacuaQueueBounds.maximumPersistedJSONKeyBytes else {
          return true
        }
        let normalized = key.lowercased().replacingOccurrences(of: "-", with: "_")
        return prohibited.contains(normalized) || normalized.contains("secret")
      }) { return true }
      return object.values.contains(where: containsProhibitedKey)
    }
    if let array = value as? [Any] { return array.contains(where: containsProhibitedKey) }
    return false
  }
}

struct TacuaOperationAttempt: Equatable {
  let canonicalRequest: Data
  let immutableRequestCredentialID: String
  let transportCredentialID: String
}

protocol TacuaTransportQueuePersisting {
  func persist(_ queue: TacuaTransportQueueV3) throws
}

protocol TacuaLocalPayloadRemoving {
  func removePayload(_ binding: TacuaLocalPayloadBinding) throws
}

enum TacuaTransportCleanup {
  static func removePendingRevokedCredentials(
    queue: inout TacuaTransportQueueV3,
    persistence: TacuaTransportQueuePersisting,
    credentialStore: TacuaCredentialStoring
  ) throws {
    guard !queue.pendingRevokedCredentialRemovals.contains(where: {
      $0 == queue.currentCredentialID
    }) else { throw TacuaTransportQueueError.credentialMismatch }
    // Persist the removal journal before touching Keychain. A crash after Keychain removal
    // is safe because removal is idempotent and the journal is replayed on recovery.
    try persistence.persist(queue)
    while let credentialID = queue.pendingRevokedCredentialRemovals.first {
      try credentialStore.remove(credentialID: credentialID)
      queue.pendingRevokedCredentialRemovals.removeFirst()
      try persistence.persist(queue)
    }
  }

  static func removeAuthorizedPayloads(
    queue: inout TacuaTransportQueueV3,
    persistence: TacuaTransportQueuePersisting,
    remover: TacuaLocalPayloadRemoving
  ) throws {
    let bindings = try queue.authorizedLocalPayloadBindings()
    if queue.payloadCleanupState == .none {
      queue.payloadCleanupState = .tombstoneWritten
      try persistence.persist(queue)
    }
    guard queue.payloadCleanupState == .tombstoneWritten else { return }
    for binding in bindings { try remover.removePayload(binding) }
    queue.payloadCleanupState = .payloadsRemoved
    try persistence.persist(queue)
  }

  static func removeAuthorizedCredential(
    queue: inout TacuaTransportQueueV3,
    persistence: TacuaTransportQueuePersisting,
    credentialStore: TacuaCredentialStoring
  ) throws {
    guard let authority = queue.deletionCleanupAuthority,
      authority.credentialID == queue.currentCredentialID
    else {
      throw TacuaTransportQueueError.deletionNotAuthorized
    }
    if queue.credentialCleanupState == .none {
      queue.credentialCleanupState = .tombstoneWritten
      try persistence.persist(queue)
    }
    guard queue.credentialCleanupState == .tombstoneWritten else { return }
    try credentialStore.remove(credentialID: authority.credentialID)
    queue.credentialCleanupState = .credentialRemoved
    queue.currentCredentialID = nil
    queue.currentCredentialExpiresAt = nil
    try persistence.persist(queue)
  }
}

private struct TacuaQueueSchemaProbe: Decodable { let schemaVersion: Int }

private struct TacuaLegacyUploadQueue: Decodable {
  let schemaVersion: Int
  let localSessionId: String
  let items: [TacuaLegacyUploadItem]

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case localSessionId
    case items
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
    localSessionId = try container.decodeBoundedString(
      forKey: .localSessionId,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    guard schemaVersion == 1, TacuaTransportQueueV3.validIdentifier(localSessionId) else {
      throw TacuaTransportQueueError.invalidQueue
    }
    items = try container.decodeBoundedArray(
      TacuaLegacyUploadItem.self,
      forKey: .items,
      maximumCount: TacuaQueueBounds.maximumLegacyItems
    )
  }
}

private struct TacuaLegacyUploadItem: Decodable {
  let objectId: String
  let objectKind: String

  private enum CodingKeys: String, CodingKey {
    case objectId
    case objectKind
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    objectId = try container.decodeBoundedString(
      forKey: .objectId,
      maximumUTF8Bytes: TacuaQueueBounds.maximumIdentifierBytes
    )
    objectKind = try container.decodeBoundedString(
      forKey: .objectKind,
      maximumUTF8Bytes: TacuaQueueBounds.maximumLegacyObjectKindBytes
    )
    guard TacuaTransportQueueV3.validIdentifier(objectId) else {
      throw TacuaTransportQueueError.invalidQueue
    }
  }
}

private enum TacuaProtocolTimestamp {
  static func parseMilliseconds(_ value: String) -> Int64? {
    guard value.utf8.count == TacuaQueueBounds.maximumTimestampBytes,
      value.range(
      of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
      options: .regularExpression
    ) != nil else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    let date = formatter.date(from: value)
    guard let date else { return nil }
    return Int64((date.timeIntervalSince1970 * 1_000).rounded())
  }

  static func format(milliseconds: Int64) -> String {
    let wholeSecondMilliseconds = milliseconds - (milliseconds % 1_000)
    let date = Date(
      timeIntervalSince1970: TimeInterval(wholeSecondMilliseconds) / 1_000
    )
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.string(from: date)
  }
}
