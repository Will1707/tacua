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
  case operationNotAllowed
  case operationConflict
  case operationNotFound
  case responseConflict
  case cleanupNotAuthorized
  case deletionNotAuthorized
  case prohibitedPersistedMaterial
}

enum TacuaTransportCredentialCapability: String, Codable, Equatable {
  case requiresExchange = "requires_exchange"
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
  let localPayloadPath: String?
  var state: TacuaQueuedOperationState
  var canonicalResponse: Data?
  var responseDigest: String?
}

struct TacuaServerTimeAnchor: Codable, Equatable {
  let issuedAt: String
  let issuedEpochMilliseconds: Int64
  let uptimeMillisecondsAtIssue: Int64
  let bootSessionID: String
  let minimumEpochMilliseconds: Int64

  static func establish(issuedAt: String, clock: TacuaMonotonicClock) throws
    -> TacuaServerTimeAnchor
  {
    guard let epoch = TacuaProtocolTimestamp.parseMilliseconds(issuedAt) else {
      throw TacuaTransportQueueError.invalidTimestamp
    }
    let uptime = clock.uptimeMilliseconds
    guard uptime >= 0, !clock.bootSessionID.isEmpty else {
      throw TacuaTransportQueueError.invalidTimeAnchor
    }
    return TacuaServerTimeAnchor(
      issuedAt: issuedAt,
      issuedEpochMilliseconds: epoch,
      uptimeMillisecondsAtIssue: uptime,
      bootSessionID: clock.bootSessionID,
      minimumEpochMilliseconds: epoch
    )
  }

  func timestamp(clock: TacuaMonotonicClock) throws -> String {
    guard clock.bootSessionID == bootSessionID,
      clock.uptimeMilliseconds >= uptimeMillisecondsAtIssue
    else {
      throw TacuaTransportQueueError.resumeRequired
    }
    let elapsed = clock.uptimeMilliseconds - uptimeMillisecondsAtIssue
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
    guard result == 0 else { return "unavailable" }
    return "boot_\(bootTime.tv_sec)_\(bootTime.tv_usec)"
  }
}

struct TacuaCompletionCleanupAuthority: Codable, Equatable {
  let completionID: String
  let completionReceiptDigest: String
  let manifestDigest: String
  let segmentReceiptDigests: [String]
  let diagnosticReceiptDigests: [String]
}

struct TacuaDeletionCleanupAuthority: Codable, Equatable {
  let deletionID: String
  let tombstoneDigest: String
  let credentialID: String
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

struct TacuaTransportQueueV2: Codable, Equatable {
  static let schemaVersion = 2

  let schemaVersion: Int
  let localSessionID: String
  var remoteSessionID: String?
  var scopeDigest: String?
  var currentCredentialID: String?
  var credentialCapability: TacuaTransportCredentialCapability
  var timeAnchor: TacuaServerTimeAnchor?
  var operations: [TacuaQueuedOperation]
  var localPayloadPaths: [String]
  var completionCleanupAuthority: TacuaCompletionCleanupAuthority?
  var deletionCleanupAuthority: TacuaDeletionCleanupAuthority?
  var payloadCleanupState: TacuaPayloadCleanupState
  var credentialCleanupState: TacuaCredentialCleanupState

  init(localSessionID: String, localPayloadPaths: [String] = []) throws {
    guard TacuaTransportQueueV2.validIdentifier(localSessionID),
      localPayloadPaths.allSatisfy(TacuaTransportQueueV2.validRelativePath)
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    schemaVersion = Self.schemaVersion
    self.localSessionID = localSessionID
    remoteSessionID = nil
    scopeDigest = nil
    currentCredentialID = nil
    credentialCapability = .requiresExchange
    timeAnchor = nil
    operations = []
    self.localPayloadPaths = localPayloadPaths
    completionCleanupAuthority = nil
    deletionCleanupAuthority = nil
    payloadCleanupState = .none
    credentialCleanupState = .none
  }

  static func decodeOrMigrate(_ data: Data) throws -> TacuaTransportQueueV2 {
    let probe = try JSONDecoder().decode(TacuaQueueSchemaProbe.self, from: data)
    switch probe.schemaVersion {
    case schemaVersion:
      let queue = try JSONDecoder().decode(TacuaTransportQueueV2.self, from: data)
      try queue.validate()
      return queue
    case 1:
      let legacy = try JSONDecoder().decode(TacuaLegacyUploadQueue.self, from: data)
      var queue = try TacuaTransportQueueV2(
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
      queue.credentialCapability = .requiresExchange
      queue.timeAnchor = nil
      try queue.validate()
      return queue
    default:
      throw TacuaTransportQueueError.unsupportedSchemaVersion
    }
  }

  func encoded() throws -> Data {
    try validate()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(self)
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
    capability: TacuaTransportCredentialCapability,
    issuedAt: String,
    clock: TacuaMonotonicClock
  ) throws {
    guard Self.validIdentifier(remoteSessionID), Self.validDigest(scopeDigest),
      Self.validIdentifier(credentialID), capability != .requiresExchange,
      capability != .deletionReplayOnly
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    if let existingSession = self.remoteSessionID, existingSession != remoteSessionID {
      throw TacuaTransportQueueError.operationConflict
    }
    if let existingScope = self.scopeDigest, existingScope != scopeDigest {
      throw TacuaTransportQueueError.operationConflict
    }
    self.remoteSessionID = remoteSessionID
    self.scopeDigest = scopeDigest
    currentCredentialID = credentialID
    credentialCapability = capability
    timeAnchor = try .establish(issuedAt: issuedAt, clock: clock)
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
    guard credentialCapability != .requiresExchange, let anchor = timeAnchor else {
      throw TacuaTransportQueueError.resumeRequired
    }
    return try anchor.timestamp(clock: clock)
  }

  mutating func enqueueNewOperation(
    kind: TacuaQueuedOperationKind,
    operationID: String,
    requestCredentialID: String,
    request: TacuaJSONValue,
    requestDigest: String,
    localPayloadPath: String? = nil,
    clock: TacuaMonotonicClock
  ) throws {
    guard Self.validIdentifier(operationID), Self.validIdentifier(requestCredentialID),
      Self.validDigest(requestDigest),
      localPayloadPath.map(Self.validRelativePath) ?? true
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
    guard try TacuaCanonicalJSON.digest(request, omittingRootField: Self.digestField(for: kind))
      == requestDigest
    else {
      throw TacuaTransportQueueError.invalidDigest
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
        state: .queued,
        canonicalResponse: nil,
        responseDigest: nil
      )
    )
  }

  /// Returns immutable request bytes and the current transport credential. Those IDs may differ
  /// after rotation; only the Authorization credential rotates during an exact durable replay.
  func attempt(operationID: String) throws -> TacuaOperationAttempt {
    guard let operation = operations.first(where: { $0.operationID == operationID }) else {
      throw TacuaTransportQueueError.operationNotFound
    }
    guard let transportCredentialID = currentCredentialID else {
      throw TacuaTransportQueueError.missingCredential
    }
    switch credentialCapability {
    case .requiresExchange:
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
    guard Self.validDigest(responseDigest),
      let index = operations.firstIndex(where: { $0.operationID == operationID })
    else {
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

  mutating func authorizeCompletionCleanup(_ authority: TacuaCompletionCleanupAuthority) throws {
    guard Self.validIdentifier(authority.completionID),
      Self.validDigest(authority.completionReceiptDigest), Self.validDigest(authority.manifestDigest),
      authority.segmentReceiptDigests.allSatisfy(Self.validDigest),
      authority.diagnosticReceiptDigests.allSatisfy(Self.validDigest),
      let operation = operations.first(where: { $0.operationID == authority.completionID }),
      operation.kind == .completion, operation.state == .responseStored
    else {
      throw TacuaTransportQueueError.cleanupNotAuthorized
    }
    if let existing = completionCleanupAuthority, existing != authority {
      throw TacuaTransportQueueError.responseConflict
    }
    completionCleanupAuthority = authority
    credentialCapability = .completionReplayOrDeleteOnly
  }

  mutating func authorizeDeletionCleanup(_ authority: TacuaDeletionCleanupAuthority) throws {
    guard Self.validIdentifier(authority.deletionID), Self.validDigest(authority.tombstoneDigest),
      Self.validIdentifier(authority.credentialID), authority.credentialID == currentCredentialID,
      let operation = operations.first(where: { $0.operationID == authority.deletionID }),
      operation.kind == .deletion, operation.state == .responseStored
    else {
      throw TacuaTransportQueueError.deletionNotAuthorized
    }
    if let existing = deletionCleanupAuthority, existing != authority {
      throw TacuaTransportQueueError.responseConflict
    }
    deletionCleanupAuthority = authority
    credentialCapability = .deletionReplayOnly
  }

  func validate() throws {
    guard schemaVersion == Self.schemaVersion, Self.validIdentifier(localSessionID),
      localPayloadPaths.allSatisfy(Self.validRelativePath), Set(localPayloadPaths).count == localPayloadPaths.count,
      operations.count <= 4_099
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    guard remoteSessionID.map(Self.validIdentifier) ?? true,
      scopeDigest.map(Self.validDigest) ?? true,
      currentCredentialID.map(Self.validIdentifier) ?? true
    else {
      throw TacuaTransportQueueError.invalidQueue
    }
    if credentialCapability == .requiresExchange {
      guard currentCredentialID == nil, timeAnchor == nil else {
        throw TacuaTransportQueueError.invalidQueue
      }
    } else if credentialCapability == .deletionReplayOnly,
      credentialCleanupState == .credentialRemoved
    {
      guard remoteSessionID != nil, scopeDigest != nil, currentCredentialID == nil else {
        throw TacuaTransportQueueError.invalidQueue
      }
    } else {
      guard remoteSessionID != nil, scopeDigest != nil, currentCredentialID != nil,
        timeAnchor != nil || credentialCapability == .deletionReplayOnly
      else {
        throw TacuaTransportQueueError.invalidQueue
      }
    }
    var operationIDs = Set<String>()
    for operation in operations {
      guard Self.validIdentifier(operation.operationID),
        Self.validIdentifier(operation.requestCredentialID),
        Self.validDigest(operation.requestDigest), operationIDs.insert(operation.operationID).inserted,
        operation.localPayloadPath.map(Self.validRelativePath) ?? true,
        (try? TacuaCanonicalJSON.parse(operation.canonicalRequest)) != nil
      else {
        throw TacuaTransportQueueError.invalidQueue
      }
      switch operation.state {
      case .queued:
        guard operation.canonicalResponse == nil, operation.responseDigest == nil else {
          throw TacuaTransportQueueError.invalidQueue
        }
      case .responseStored:
        guard let response = operation.canonicalResponse,
          operation.responseDigest.map(Self.validDigest) == true,
          (try? TacuaCanonicalJSON.parse(response)) != nil
        else {
          throw TacuaTransportQueueError.invalidQueue
        }
      }
    }
    if payloadCleanupState != .none { guard completionCleanupAuthority != nil else {
      throw TacuaTransportQueueError.invalidQueue
    }}
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
    case .requiresExchange:
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

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,127}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func validRelativePath(_ value: String) -> Bool {
    !value.isEmpty && !value.hasPrefix("/") && !value.contains("..")
      && !value.contains("\0") && value.utf8.count <= 1_024
  }

  private static func containsProhibitedKey(_ value: Any) -> Bool {
    if let object = value as? [String: Any] {
      let prohibited = Set(["secret", "launch_code", "authorization", "bearer"])
      if object.keys.contains(where: { prohibited.contains($0.lowercased()) }) { return true }
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
  func persist(_ queue: TacuaTransportQueueV2) throws
}

protocol TacuaLocalPayloadRemoving {
  func removePayload(atRelativePath path: String) throws
}

enum TacuaTransportCleanup {
  static func removeAuthorizedPayloads(
    queue: inout TacuaTransportQueueV2,
    persistence: TacuaTransportQueuePersisting,
    remover: TacuaLocalPayloadRemoving
  ) throws {
    guard queue.completionCleanupAuthority != nil else {
      throw TacuaTransportQueueError.cleanupNotAuthorized
    }
    if queue.payloadCleanupState == .none {
      queue.payloadCleanupState = .tombstoneWritten
      try persistence.persist(queue)
    }
    guard queue.payloadCleanupState == .tombstoneWritten else { return }
    for path in queue.localPayloadPaths { try remover.removePayload(atRelativePath: path) }
    queue.payloadCleanupState = .payloadsRemoved
    try persistence.persist(queue)
  }

  static func removeAuthorizedCredential(
    queue: inout TacuaTransportQueueV2,
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
    try persistence.persist(queue)
  }
}

private struct TacuaQueueSchemaProbe: Decodable { let schemaVersion: Int }

private struct TacuaLegacyUploadQueue: Decodable {
  let schemaVersion: Int
  let localSessionId: String
  let items: [TacuaLegacyUploadItem]
}

private struct TacuaLegacyUploadItem: Decodable {
  let objectId: String
  let objectKind: String
}

private enum TacuaProtocolTimestamp {
  static func parseMilliseconds(_ value: String) -> Int64? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = formatter.date(from: value) ?? {
      formatter.formatOptions = [.withInternetDateTime]
      return formatter.date(from: value)
    }()
    guard let date else { return nil }
    return Int64((date.timeIntervalSince1970 * 1_000).rounded())
  }

  static func format(milliseconds: Int64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1_000)
    let formatter = ISO8601DateFormatter()
    if milliseconds % 1_000 == 0 {
      formatter.formatOptions = [.withInternetDateTime]
    } else {
      formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    }
    return formatter.string(from: date)
  }
}
