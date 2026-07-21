// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaUploadObjectKind: String, Codable {
  case segment
  case diagnosticEnvelope = "diagnostic_envelope"
  case manifest
}

enum TacuaUploadItemState: String, Codable {
  case queued
  case uploading
  case retryWaiting = "retry_waiting"
  case failedPermanent = "failed_permanent"
  case received
}

struct TacuaUploadReceipt: Codable, Equatable {
  let receiptId: String
  let remoteSessionId: String
  let objectKind: TacuaUploadObjectKind
  let segmentIndex: Int?
  let contentDigest: String
  let byteLength: Int64
  let receivedAt: String
}

struct TacuaUploadItem: Codable, Equatable {
  let objectId: String
  let objectKind: TacuaUploadObjectKind
  let segmentIndex: Int?
  let contentDigest: String
  let byteLength: Int64
  var state: TacuaUploadItemState
  var attemptCount: Int
  var nextAttemptAt: String?
  var lastErrorCode: String?
  var receipt: TacuaUploadReceipt?
}

struct TacuaUploadQueue: Codable, Equatable {
  let schemaVersion: Int
  let localSessionId: String
  let remoteSessionId: String
  let organizationId: String
  let projectId: String
  let buildId: String
  let grantIdentifier: String
  let grantExpiresAt: String
  var items: [TacuaUploadItem]
}

enum TacuaUploadReceiptDisposition: Equatable {
  case accepted
  case duplicate
}

enum TacuaUploadRetryDecision: Equatable {
  case retryAt(String)
  case grantExpired
  case attemptsExhausted
  case permanentFailure
}

enum TacuaTransportPolicyError: Error, Equatable {
  case invalidIdentifier
  case invalidDigest
  case invalidByteLength
  case invalidSegmentIndex
  case duplicateObject
  case missingObject
  case unauthenticatedReceipt
  case receiptScopeMismatch
  case receiptContentMismatch
  case receiptConflict
  case invalidQueueShape
  case invalidUploadState
  case invalidTimestamp
  case invalidDiagnostic
  case prohibitedDiagnosticValue
}

enum TacuaCaptureTransportPolicy {
  static let queueSchemaVersion = 1
  static let maximumRetryAttempts = 8
  static let maximumRetryDelaySeconds = 300
  static let maximumDiagnosticElapsedMilliseconds = 1_800_000
  static let maximumUploadItems = 4_097
  static let maximumUploadObjectBytes: Int64 = 1_073_741_824

  static func validate(queue: TacuaUploadQueue) throws {
    guard queue.schemaVersion == queueSchemaVersion,
      validIdentifier(queue.localSessionId),
      validIdentifier(queue.remoteSessionId),
      validIdentifier(queue.organizationId),
      validIdentifier(queue.projectId),
      validIdentifier(queue.buildId),
      validIdentifier(queue.grantIdentifier)
    else {
      throw TacuaTransportPolicyError.invalidIdentifier
    }
    guard parseTimestamp(queue.grantExpiresAt) != nil else {
      throw TacuaTransportPolicyError.invalidTimestamp
    }

    guard !queue.items.isEmpty, queue.items.count <= maximumUploadItems else {
      throw TacuaTransportPolicyError.invalidQueueShape
    }

    var objectIds = Set<String>()
    var segmentIndexes = Set<Int>()
    var receiptIds = Set<String>()
    var segmentCount = 0
    var manifestCount = 0
    for item in queue.items {
      try validate(item: item, remoteSessionId: queue.remoteSessionId)
      guard objectIds.insert(item.objectId).inserted else {
        throw TacuaTransportPolicyError.duplicateObject
      }
      if let index = item.segmentIndex {
        guard segmentIndexes.insert(index).inserted else {
          throw TacuaTransportPolicyError.duplicateObject
        }
      }
      if item.objectKind == .segment { segmentCount += 1 }
      if item.objectKind == .manifest { manifestCount += 1 }
      if let receipt = item.receipt,
        !receiptIds.insert(receipt.receiptId).inserted
      {
        throw TacuaTransportPolicyError.receiptConflict
      }
    }
    guard segmentCount >= 1, manifestCount == 1 else {
      throw TacuaTransportPolicyError.invalidQueueShape
    }
  }

  static func apply(
    receipt: TacuaUploadReceipt,
    toObjectId objectId: String,
    queue: inout TacuaUploadQueue,
    transportAuthenticated: Bool
  ) throws -> TacuaUploadReceiptDisposition {
    guard transportAuthenticated else {
      throw TacuaTransportPolicyError.unauthenticatedReceipt
    }
    try validate(queue: queue)
    guard let index = queue.items.firstIndex(where: { $0.objectId == objectId }) else {
      throw TacuaTransportPolicyError.missingObject
    }
    let item = queue.items[index]
    guard validIdentifier(receipt.receiptId),
      receipt.remoteSessionId == queue.remoteSessionId,
      receipt.objectKind == item.objectKind,
      receipt.segmentIndex == item.segmentIndex
    else {
      throw TacuaTransportPolicyError.receiptScopeMismatch
    }
    guard validDigest(receipt.contentDigest), receipt.byteLength > 0,
      parseTimestamp(receipt.receivedAt) != nil
    else {
      throw TacuaTransportPolicyError.receiptContentMismatch
    }
    guard receipt.contentDigest == item.contentDigest,
      receipt.byteLength == item.byteLength
    else {
      throw TacuaTransportPolicyError.receiptContentMismatch
    }

    if let prior = item.receipt {
      guard prior == receipt else {
        throw TacuaTransportPolicyError.receiptConflict
      }
      return .duplicate
    }
    guard !queue.items.contains(where: { $0.receipt?.receiptId == receipt.receiptId }) else {
      throw TacuaTransportPolicyError.receiptConflict
    }

    queue.items[index].receipt = receipt
    queue.items[index].state = .received
    queue.items[index].nextAttemptAt = nil
    queue.items[index].lastErrorCode = nil
    return .accepted
  }

  static func canDeleteLocalMedia(queue: TacuaUploadQueue) -> Bool {
    guard (try? validate(queue: queue)) != nil else { return false }
    let segments = queue.items.filter { $0.objectKind == .segment }
    let manifests = queue.items.filter { $0.objectKind == .manifest }
    guard !segments.isEmpty, manifests.count == 1 else { return false }
    return (segments + manifests).allSatisfy { item in
      item.state == .received && item.receipt != nil
    }
  }

  static func retryDecision(
    retryable: Bool,
    completedAttemptCount: Int,
    now: Date,
    grantExpiresAt: String
  ) -> TacuaUploadRetryDecision {
    guard retryable else { return .permanentFailure }
    guard let expiry = parseTimestamp(grantExpiresAt), expiry > now else {
      return .grantExpired
    }
    guard completedAttemptCount >= 0, completedAttemptCount < maximumRetryAttempts else {
      return .attemptsExhausted
    }
    let exponent = min(completedAttemptCount, 20)
    let delay = min(1 << exponent, maximumRetryDelaySeconds)
    let retryAt = now.addingTimeInterval(TimeInterval(delay))
    guard retryAt < expiry else { return .grantExpired }
    return .retryAt(formatTimestamp(retryAt))
  }

  private static func validate(item: TacuaUploadItem, remoteSessionId: String) throws {
    guard validIdentifier(item.objectId) else {
      throw TacuaTransportPolicyError.invalidIdentifier
    }
    guard validDigest(item.contentDigest) else {
      throw TacuaTransportPolicyError.invalidDigest
    }
    guard item.byteLength > 0, item.byteLength <= maximumUploadObjectBytes else {
      throw TacuaTransportPolicyError.invalidByteLength
    }
    if item.objectKind == .segment {
      guard let index = item.segmentIndex, (0...2047).contains(index) else {
        throw TacuaTransportPolicyError.invalidSegmentIndex
      }
    } else if item.segmentIndex != nil {
      throw TacuaTransportPolicyError.invalidSegmentIndex
    }
    guard (0...maximumRetryAttempts).contains(item.attemptCount) else {
      throw TacuaTransportPolicyError.invalidDiagnostic
    }
    if let nextAttemptAt = item.nextAttemptAt, parseTimestamp(nextAttemptAt) == nil {
      throw TacuaTransportPolicyError.invalidTimestamp
    }
    if let code = item.lastErrorCode,
      code.range(of: "^[A-Z][A-Z0-9_]{2,63}$", options: .regularExpression) == nil
    {
      throw TacuaTransportPolicyError.invalidUploadState
    }
    if let receipt = item.receipt {
      guard receipt.remoteSessionId == remoteSessionId,
        receipt.objectKind == item.objectKind,
        receipt.segmentIndex == item.segmentIndex,
        receipt.contentDigest == item.contentDigest,
        receipt.byteLength == item.byteLength,
        validIdentifier(receipt.receiptId),
        parseTimestamp(receipt.receivedAt) != nil,
        item.state == .received,
        item.nextAttemptAt == nil,
        item.lastErrorCode == nil
      else {
        throw TacuaTransportPolicyError.receiptContentMismatch
      }
    } else if item.state == .received {
      throw TacuaTransportPolicyError.receiptContentMismatch
    }

    switch item.state {
    case .queued, .uploading:
      guard item.receipt == nil, item.nextAttemptAt == nil, item.lastErrorCode == nil else {
        throw TacuaTransportPolicyError.invalidUploadState
      }
    case .retryWaiting:
      guard item.receipt == nil, item.nextAttemptAt != nil, item.lastErrorCode != nil else {
        throw TacuaTransportPolicyError.invalidUploadState
      }
    case .failedPermanent:
      guard item.receipt == nil, item.nextAttemptAt == nil, item.lastErrorCode != nil else {
        throw TacuaTransportPolicyError.invalidUploadState
      }
    case .received:
      break
    }
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func parseTimestamp(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: value)
  }

  private static func formatTimestamp(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.string(from: date)
  }
}

enum TacuaDiagnosticEventKind: String, Codable {
  case buildIdentity = "build_identity"
  case routeTransition = "route_transition"
  case issueMark = "issue_mark"
  case runtimeError = "runtime_error"
  case networkRequest = "network_request"
}

struct TacuaDiagnosticBuildIdentity: Codable, Equatable {
  let buildIdentityDigest: String
}

struct TacuaDiagnosticRouteTransition: Codable, Equatable {
  let fromRouteTemplate: String?
  let toRouteTemplate: String
}

struct TacuaDiagnosticIssueMark: Codable, Equatable {
  let markerId: String
}

struct TacuaDiagnosticRuntimeError: Codable, Equatable {
  let errorClass: String
  let messageDigest: String?
  let handled: Bool
}

struct TacuaDiagnosticNetworkRequest: Codable, Equatable {
  let requestId: String
  let method: String
  let pathTemplate: String
  let statusCode: Int?
  let durationMilliseconds: Int?
  let outcome: String
}

struct TacuaDiagnosticEvent: Codable, Equatable {
  let schemaVersion: Int
  let eventId: String
  let sessionId: String
  let sequence: Int
  let elapsedMilliseconds: Int
  let kind: TacuaDiagnosticEventKind
  let buildIdentity: TacuaDiagnosticBuildIdentity?
  let routeTransition: TacuaDiagnosticRouteTransition?
  let issueMark: TacuaDiagnosticIssueMark?
  let runtimeError: TacuaDiagnosticRuntimeError?
  let networkRequest: TacuaDiagnosticNetworkRequest?
}

extension TacuaCaptureTransportPolicy {
  static func validate(diagnostic event: TacuaDiagnosticEvent) throws {
    guard event.schemaVersion == 1,
      validIdentifier(event.eventId),
      validIdentifier(event.sessionId),
      event.sequence >= 0,
      (0...maximumDiagnosticElapsedMilliseconds).contains(event.elapsedMilliseconds)
    else {
      throw TacuaTransportPolicyError.invalidDiagnostic
    }

    let populatedPayloads = [
      event.buildIdentity != nil,
      event.routeTransition != nil,
      event.issueMark != nil,
      event.runtimeError != nil,
      event.networkRequest != nil,
    ].filter { $0 }.count
    guard populatedPayloads == 1 else {
      throw TacuaTransportPolicyError.invalidDiagnostic
    }

    switch event.kind {
    case .buildIdentity:
      guard let payload = event.buildIdentity, validDigest(payload.buildIdentityDigest) else {
        throw TacuaTransportPolicyError.invalidDiagnostic
      }
    case .routeTransition:
      guard let payload = event.routeTransition,
        validRouteTemplate(payload.toRouteTemplate),
        payload.fromRouteTemplate.map(validRouteTemplate) ?? true
      else {
        throw TacuaTransportPolicyError.prohibitedDiagnosticValue
      }
    case .issueMark:
      guard let payload = event.issueMark, validIdentifier(payload.markerId) else {
        throw TacuaTransportPolicyError.invalidDiagnostic
      }
    case .runtimeError:
      guard let payload = event.runtimeError,
        validDiagnosticIdentifier(payload.errorClass, maximumLength: 128),
        payload.messageDigest.map(validDigest) ?? true
      else {
        throw TacuaTransportPolicyError.prohibitedDiagnosticValue
      }
    case .networkRequest:
      guard let payload = event.networkRequest,
        validDiagnosticIdentifier(payload.requestId, maximumLength: 128),
        ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].contains(payload.method),
        validRouteTemplate(payload.pathTemplate),
        payload.statusCode.map({ (100...599).contains($0) }) ?? true,
        payload.durationMilliseconds.map({
          (0...maximumDiagnosticElapsedMilliseconds).contains($0)
        }) ?? true,
        ["success", "error", "cancelled", "unknown"].contains(payload.outcome)
      else {
        throw TacuaTransportPolicyError.prohibitedDiagnosticValue
      }
    }
  }

  private static func validRouteTemplate(_ value: String) -> Bool {
    guard (1...512).contains(value.utf8.count), value.hasPrefix("/") else { return false }
    guard !value.contains("?"), !value.contains("#"), !value.contains("://") else { return false }
    guard validDiagnosticAtom(value, maximumLength: 512) else { return false }
    return value.range(
      of: "^/(?:[A-Za-z0-9._~-]+|:[A-Za-z][A-Za-z0-9_]*|\\{[A-Za-z][A-Za-z0-9_]*\\})(?:/(?:[A-Za-z0-9._~-]+|:[A-Za-z][A-Za-z0-9_]*|\\{[A-Za-z][A-Za-z0-9_]*\\}))*$",
      options: .regularExpression
    ) != nil
  }

  private static func validDiagnosticIdentifier(_ value: String, maximumLength: Int) -> Bool {
    guard value.utf8.count <= maximumLength else { return false }
    guard value.range(
      of: "^[A-Za-z][A-Za-z0-9._-]{0,127}$",
      options: .regularExpression
    ) != nil else { return false }
    return validDiagnosticAtom(value, maximumLength: maximumLength)
  }

  private static func validDiagnosticAtom(_ value: String, maximumLength: Int) -> Bool {
    guard !value.isEmpty, value.utf8.count <= maximumLength else { return false }
    guard value.unicodeScalars.allSatisfy({
      !CharacterSet.controlCharacters.contains($0)
    }) else { return false }
    let lowered = value.lowercased()
    let prohibited = [
      "authorization", "cookie", "set-cookie", "password", "private_key",
      "refresh_token", "access_token", "bearer ", "basic ", "token=", "secret=",
    ]
    return !prohibited.contains(where: lowered.contains)
  }
}
