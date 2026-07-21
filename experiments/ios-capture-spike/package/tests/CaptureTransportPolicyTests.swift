// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum TransportTestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw TransportTestFailure.assertion(message) }
}

private func expectTransportError(
  _ expected: TacuaTransportPolicyError,
  operation: () throws -> Void
) throws {
  do {
    try operation()
    throw TransportTestFailure.assertion("Expected \(expected), but validation succeeded")
  } catch let error as TacuaTransportPolicyError {
    try require(error == expected, "Expected \(expected), received \(error)")
  }
}

private let digestA = "sha256:" + String(repeating: "a", count: 64)
private let digestB = "sha256:" + String(repeating: "b", count: 64)

@main
enum CaptureTransportPolicyTests {
  static func main() throws {
    try authenticatedReceiptAndIdempotency()
    try receiptConflictsFailClosed()
    try queueShapeAndStateAreFailClosed()
    try deletionRequiresEveryReceipt()
    try boundedRetryAndGrantExpiry()
    try queueContainsNoBearerCredential()
    try diagnosticsAreShapeBoundAndSanitized()
    print("Tacua capture transport policy tests passed")
  }

  private static func makeQueue() -> TacuaUploadQueue {
    TacuaUploadQueue(
      schemaVersion: 1,
      localSessionId: "session_local_001",
      remoteSessionId: "session_remote_001",
      organizationId: "org_local",
      projectId: "project_kuzaba",
      buildId: "build_preview_001",
      grantIdentifier: "grant_001",
      grantExpiresAt: "2027-01-15T08:00:00Z",
      items: [
        TacuaUploadItem(
          objectId: "segment_000000",
          objectKind: .segment,
          segmentIndex: 0,
          contentDigest: digestA,
          byteLength: 42,
          state: .queued,
          attemptCount: 0,
          nextAttemptAt: nil,
          lastErrorCode: nil,
          receipt: nil
        ),
        TacuaUploadItem(
          objectId: "manifest_001",
          objectKind: .manifest,
          segmentIndex: nil,
          contentDigest: digestB,
          byteLength: 84,
          state: .queued,
          attemptCount: 0,
          nextAttemptAt: nil,
          lastErrorCode: nil,
          receipt: nil
        ),
      ]
    )
  }

  private static func receipt(
    id: String = "receipt_001",
    kind: TacuaUploadObjectKind = .segment,
    segmentIndex: Int? = 0,
    digest: String = digestA,
    byteLength: Int64 = 42
  ) -> TacuaUploadReceipt {
    TacuaUploadReceipt(
      receiptId: id,
      remoteSessionId: "session_remote_001",
      objectKind: kind,
      segmentIndex: segmentIndex,
      contentDigest: digest,
      byteLength: byteLength,
      receivedAt: "2026-07-21T12:00:00Z"
    )
  }

  private static func authenticatedReceiptAndIdempotency() throws {
    var queue = makeQueue()
    let accepted = try TacuaCaptureTransportPolicy.apply(
      receipt: receipt(),
      toObjectId: "segment_000000",
      queue: &queue,
      transportAuthenticated: true
    )
    try require(accepted == .accepted, "The first authenticated receipt must be accepted")
    let duplicate = try TacuaCaptureTransportPolicy.apply(
      receipt: receipt(),
      toObjectId: "segment_000000",
      queue: &queue,
      transportAuthenticated: true
    )
    try require(duplicate == .duplicate, "An exact receipt retry must be idempotent")

    var unauthenticated = makeQueue()
    try expectTransportError(.unauthenticatedReceipt) {
      _ = try TacuaCaptureTransportPolicy.apply(
        receipt: receipt(),
        toObjectId: "segment_000000",
        queue: &unauthenticated,
        transportAuthenticated: false
      )
    }
  }

  private static func receiptConflictsFailClosed() throws {
    var wrongDigest = makeQueue()
    try expectTransportError(.receiptContentMismatch) {
      _ = try TacuaCaptureTransportPolicy.apply(
        receipt: receipt(digest: digestB),
        toObjectId: "segment_000000",
        queue: &wrongDigest,
        transportAuthenticated: true
      )
    }

    var conflict = makeQueue()
    _ = try TacuaCaptureTransportPolicy.apply(
      receipt: receipt(),
      toObjectId: "segment_000000",
      queue: &conflict,
      transportAuthenticated: true
    )
    try expectTransportError(.receiptConflict) {
      _ = try TacuaCaptureTransportPolicy.apply(
        receipt: receipt(id: "receipt_002"),
        toObjectId: "segment_000000",
        queue: &conflict,
        transportAuthenticated: true
      )
    }

    var duplicateReceiptId = makeQueue()
    _ = try TacuaCaptureTransportPolicy.apply(
      receipt: receipt(),
      toObjectId: "segment_000000",
      queue: &duplicateReceiptId,
      transportAuthenticated: true
    )
    try expectTransportError(.receiptConflict) {
      _ = try TacuaCaptureTransportPolicy.apply(
        receipt: receipt(
          kind: .manifest,
          segmentIndex: nil,
          digest: digestB,
          byteLength: 84
        ),
        toObjectId: "manifest_001",
        queue: &duplicateReceiptId,
        transportAuthenticated: true
      )
    }
  }

  private static func queueShapeAndStateAreFailClosed() throws {
    var noManifest = makeQueue()
    noManifest.items.removeLast()
    try expectTransportError(.invalidQueueShape) {
      try TacuaCaptureTransportPolicy.validate(queue: noManifest)
    }

    var invalidRetry = makeQueue()
    invalidRetry.items[0].state = .retryWaiting
    invalidRetry.items[0].lastErrorCode = "UPLOAD_TIMEOUT"
    try expectTransportError(.invalidUploadState) {
      try TacuaCaptureTransportPolicy.validate(queue: invalidRetry)
    }

    var unbounded = makeQueue()
    unbounded.items[0] = TacuaUploadItem(
      objectId: "segment_000000",
      objectKind: .segment,
      segmentIndex: 0,
      contentDigest: digestA,
      byteLength: TacuaCaptureTransportPolicy.maximumUploadObjectBytes + 1,
      state: .queued,
      attemptCount: 0,
      nextAttemptAt: nil,
      lastErrorCode: nil,
      receipt: nil
    )
    try expectTransportError(.invalidByteLength) {
      try TacuaCaptureTransportPolicy.validate(queue: unbounded)
    }
  }

  private static func deletionRequiresEveryReceipt() throws {
    var queue = makeQueue()
    try require(
      !TacuaCaptureTransportPolicy.canDeleteLocalMedia(queue: queue),
      "Local media must remain before any upload receipt"
    )
    _ = try TacuaCaptureTransportPolicy.apply(
      receipt: receipt(),
      toObjectId: "segment_000000",
      queue: &queue,
      transportAuthenticated: true
    )
    try require(
      !TacuaCaptureTransportPolicy.canDeleteLocalMedia(queue: queue),
      "A segment receipt without the manifest receipt must not permit deletion"
    )
    _ = try TacuaCaptureTransportPolicy.apply(
      receipt: receipt(
        id: "receipt_manifest_001",
        kind: .manifest,
        segmentIndex: nil,
        digest: digestB,
        byteLength: 84
      ),
      toObjectId: "manifest_001",
      queue: &queue,
      transportAuthenticated: true
    )
    try require(
      TacuaCaptureTransportPolicy.canDeleteLocalMedia(queue: queue),
      "All segment and manifest receipts must permit scoped local deletion"
    )
  }

  private static func boundedRetryAndGrantExpiry() throws {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let retry = TacuaCaptureTransportPolicy.retryDecision(
      retryable: true,
      completedAttemptCount: 3,
      now: now,
      grantExpiresAt: "2027-01-15T08:10:00Z"
    )
    try require(retry == .retryAt("2027-01-15T08:00:08Z"), "Retry backoff must be deterministic")
    try require(
      TacuaCaptureTransportPolicy.retryDecision(
        retryable: false,
        completedAttemptCount: 0,
        now: now,
        grantExpiresAt: "2027-01-15T08:10:00Z"
      ) == .permanentFailure,
      "Non-retryable errors must remain permanent"
    )
    try require(
      TacuaCaptureTransportPolicy.retryDecision(
        retryable: true,
        completedAttemptCount: 8,
        now: now,
        grantExpiresAt: "2027-01-15T08:10:00Z"
      ) == .attemptsExhausted,
      "Retry attempts must be bounded"
    )
    try require(
      TacuaCaptureTransportPolicy.retryDecision(
        retryable: true,
        completedAttemptCount: 0,
        now: now,
        grantExpiresAt: "2027-01-15T07:59:59Z"
      ) == .grantExpired,
      "An expired grant must not be retried"
    )
  }

  private static func queueContainsNoBearerCredential() throws {
    let data = try JSONEncoder().encode(makeQueue())
    let encoded = String(decoding: data, as: UTF8.self).lowercased()
    try require(!encoded.contains("bearer"), "The persisted queue must not contain a bearer value")
    try require(!encoded.contains("access_token"), "The persisted queue must not define an access token")
    try require(!encoded.contains("secret"), "The persisted queue must not define a secret")
  }

  private static func diagnosticsAreShapeBoundAndSanitized() throws {
    let network = TacuaDiagnosticEvent(
      schemaVersion: 1,
      eventId: "event_network_001",
      sessionId: "session_local_001",
      sequence: 1,
      elapsedMilliseconds: 1_000,
      kind: .networkRequest,
      buildIdentity: nil,
      routeTransition: nil,
      issueMark: nil,
      runtimeError: nil,
      networkRequest: TacuaDiagnosticNetworkRequest(
        requestId: "request-001",
        method: "POST",
        pathTemplate: "/v1/profile/:profileId",
        statusCode: 500,
        durationMilliseconds: 250,
        outcome: "error"
      )
    )
    try TacuaCaptureTransportPolicy.validate(diagnostic: network)

    let query = TacuaDiagnosticEvent(
      schemaVersion: 1,
      eventId: "event_network_002",
      sessionId: "session_local_001",
      sequence: 2,
      elapsedMilliseconds: 1_100,
      kind: .networkRequest,
      buildIdentity: nil,
      routeTransition: nil,
      issueMark: nil,
      runtimeError: nil,
      networkRequest: TacuaDiagnosticNetworkRequest(
        requestId: "request-002",
        method: "GET",
        pathTemplate: "/v1/profile?access_token=forbidden",
        statusCode: 200,
        durationMilliseconds: 10,
        outcome: "success"
      )
    )
    try expectTransportError(.prohibitedDiagnosticValue) {
      try TacuaCaptureTransportPolicy.validate(diagnostic: query)
    }

    let mismatch = TacuaDiagnosticEvent(
      schemaVersion: 1,
      eventId: "event_route_001",
      sessionId: "session_local_001",
      sequence: 3,
      elapsedMilliseconds: 1_200,
      kind: .routeTransition,
      buildIdentity: nil,
      routeTransition: TacuaDiagnosticRouteTransition(
        fromRouteTemplate: "/home",
        toRouteTemplate: "/profile/:profileId"
      ),
      issueMark: TacuaDiagnosticIssueMark(markerId: "marker_001"),
      runtimeError: nil,
      networkRequest: nil
    )
    try expectTransportError(.invalidDiagnostic) {
      try TacuaCaptureTransportPolicy.validate(diagnostic: mismatch)
    }

    let errorWithCredential = TacuaDiagnosticEvent(
      schemaVersion: 1,
      eventId: "event_error_001",
      sessionId: "session_local_001",
      sequence: 4,
      elapsedMilliseconds: 1_300,
      kind: .runtimeError,
      buildIdentity: nil,
      routeTransition: nil,
      issueMark: nil,
      runtimeError: TacuaDiagnosticRuntimeError(
        errorClass: "Bearer forbidden-secret-value",
        messageDigest: nil,
        handled: true
      ),
      networkRequest: nil
    )
    try expectTransportError(.prohibitedDiagnosticValue) {
      try TacuaCaptureTransportPolicy.validate(diagnostic: errorWithCredential)
    }

    let untemplatedRoute = TacuaDiagnosticEvent(
      schemaVersion: 1,
      eventId: "event_route_002",
      sessionId: "session_local_001",
      sequence: 5,
      elapsedMilliseconds: 1_400,
      kind: .routeTransition,
      buildIdentity: nil,
      routeTransition: TacuaDiagnosticRouteTransition(
        fromRouteTemplate: "/home",
        toRouteTemplate: "/profile/user@example.com"
      ),
      issueMark: nil,
      runtimeError: nil,
      networkRequest: nil
    )
    try expectTransportError(.prohibitedDiagnosticValue) {
      try TacuaCaptureTransportPolicy.validate(diagnostic: untemplatedRoute)
    }
  }
}
