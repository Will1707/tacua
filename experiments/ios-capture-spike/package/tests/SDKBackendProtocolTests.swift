// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum ProtocolTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw ProtocolTestFailure.assertion(message) }
}

private func expectFailure(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw ProtocolTestFailure.assertion("Expected protocol validation to fail")
  } catch is ProtocolTestFailure {
    throw ProtocolTestFailure.assertion("Expected protocol validation to fail")
  } catch {
    return
  }
}

@main
enum SDKBackendProtocolTests {
  static func main() throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try validatesEveryPositiveLifecyclePair(fixtureRoot)
    try rejectsNonCanonicalAndUnboundedResponses(fixtureRoot)
    try validatesOnlyExactlyBoundHistoricalMissErrors(fixtureRoot)
    try rejectsUnknownFieldsAndReboundIdentifiers(fixtureRoot)
    try buildAndScopeProjectionMatchesFrozenSchema(fixtureRoot)
    try boundedTextUsesUnicodeCodePoints(fixtureRoot)
    try completionAuthorityComesFromExactReceipt(fixtureRoot)
    try resealedIncompleteCompletionCannotAuthorizeCleanup(fixtureRoot)
    try resealedManifestReceiptSetMismatchCannotAuthorizeCleanup(fixtureRoot)
    try deletionAuthorityComesFromExactTombstone(fixtureRoot)
    try exactWholeSecondTimestampsOnly(fixtureRoot)
    try launchRequestRejectsSameIdentifierRotation(fixtureRoot)
    try resumeReceiptCannotPredatePriorAuthority(fixtureRoot)
    try resealedDiagnosticUnknownAndUnavailableFieldsAreRejected(fixtureRoot)
    try resealedManifestStreamsRangesAndRetentionAreRejected(fixtureRoot)
    try resealedProcessingJobNestedFieldsAreRejected(fixtureRoot)
    print("Tacua SDK/backend protocol tests passed")
  }

  private static func canonicalFixture(_ root: URL, _ name: String) throws -> Data {
    let data = try Data(contentsOf: root.appendingPathComponent("\(name).json"))
    return try TacuaCanonicalJSON.data(try TacuaCanonicalJSON.parse(data))
  }

  private static func pair(_ root: URL, _ request: String, _ response: String) throws
    -> TacuaValidatedBackendReceipt
  {
    try TacuaSDKBackendProtocol.validateResponse(
      canonicalFixture(root, response),
      forCanonicalRequest: canonicalFixture(root, request)
    )
  }

  private static func replacingRoot(
    _ data: Data,
    receiptDigestField: String,
    mutate: (inout [String: TacuaJSONValue]) throws -> Void
  ) throws -> Data {
    guard case .object(var object) = try TacuaCanonicalJSON.parse(data) else {
      throw ProtocolTestFailure.assertion("Fixture root must be an object")
    }
    try mutate(&object)
    object[receiptDigestField] = .string(try TacuaCanonicalJSON.digest(
      .object(object), omittingRootField: receiptDigestField
    ))
    return try TacuaCanonicalJSON.data(.object(object))
  }

  private static func validatesEveryPositiveLifecyclePair(_ root: URL) throws {
    let start = try pair(root, "launch-exchange-request", "launch-exchange-receipt")
    try require(start.operationKind == .launch, "Launch receipt must validate")
    try require(start.credentialTransition?.capability == .active, "Start must issue active credential")
    try require(start.authoritativeTimestamp == "2026-07-21T09:57:01Z", "Launch must anchor from issued_at")

    let receiving = try pair(root, "receiving-resume-request", "receiving-resume-receipt")
    try require(receiving.credentialTransition?.credentialID == "credential_receiving_resume", "Resume must bind the new credential")

    let completed = try pair(root, "completed-resume-request", "completed-resume-receipt")
    try require(completed.credentialTransition?.capability == .completionReplayOrDeleteOnly, "Completed resume must stay upload-disabled")
    try require(completed.credentialTransition?.replayCompletionID == "completion_synthetic", "Completed resume must bind one completion")

    let segment = try pair(root, "segment-upload-intent", "segment-upload-receipt")
    try require(segment.operationKind == .segment, "Segment pair must validate")
    let diagnostic = try pair(root, "diagnostic-upload-request", "diagnostic-upload-receipt")
    try require(diagnostic.operationKind == .diagnostic, "Diagnostic pair must validate")
    let completion = try pair(root, "completion-request", "completion-receipt")
    try require(completion.operationKind == .completion, "Completion pair must validate")
    let deletion = try pair(root, "deletion-request", "deletion-tombstone")
    try require(deletion.operationKind == .deletion, "Deletion pair must validate")
  }

  private static func rejectsNonCanonicalAndUnboundedResponses(_ root: URL) throws {
    let request = try canonicalFixture(root, "launch-exchange-request")
    let response = try canonicalFixture(root, "launch-exchange-receipt")
    var padded = response
    padded.append(0x0A)
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(padded, forCanonicalRequest: request)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        response, forCanonicalRequest: request, maximumResponseBytes: response.count - 1
      )
    }
  }

  private static func validatesOnlyExactlyBoundHistoricalMissErrors(_ root: URL) throws {
    let request = try canonicalFixture(root, "diagnostic-upload-request")
    let authenticatedCredentialID = "credential_current"
    let response = try historicalMissError(
      for: request,
      authenticatedCredentialID: authenticatedCredentialID
    )
    let validated = try TacuaSDKBackendProtocol.validateErrorResponse(
      response,
      statusCode: 403,
      contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
      forCanonicalRequest: request,
      authenticatedCredentialID: authenticatedCredentialID
    )
    try require(validated.statusCode == 403, "Typed error must retain its status")
    try require(validated.code == .operationNotAuthorized, "Only the allowlisted code may surface")
    try require(
      validated.reconciliationOutcome == .historicalOperationNotFound,
      "Typed error must describe one historical durable-lookup miss"
    )
    try require(validated.operationKind == .diagnostic, "Request kind must bind the error")
    try require(validated.remoteSessionID == "session_synthetic", "Session must remain bound")
    try require(
      validated.operationID == "upload_diagnostic_synthetic",
      "Operation ID must remain bound"
    )
    try require(
      validated.requestCredentialID == "credential_receiving_resume"
        && validated.authenticatedCredentialID == authenticatedCredentialID,
      "Historical and authenticating credentials must remain distinct and bound"
    )
    for (requestName, expectedKind) in [
      ("segment-upload-intent", TacuaBackendOperationKind.segment),
      ("completion-request", TacuaBackendOperationKind.completion),
    ] {
      let additionalRequest = try canonicalFixture(root, requestName)
      let additionalError = try historicalMissError(
        for: additionalRequest,
        authenticatedCredentialID: authenticatedCredentialID
      )
      let additionalValidated = try TacuaSDKBackendProtocol.validateErrorResponse(
        additionalError,
        statusCode: 403,
        contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
        forCanonicalRequest: additionalRequest,
        authenticatedCredentialID: authenticatedCredentialID
      )
      try require(
        additionalValidated.operationKind == expectedKind,
        "Every recoverable historical operation kind must validate exactly"
      )
    }

    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateErrorResponse(
        response,
        statusCode: 409,
        contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
        forCanonicalRequest: request,
        authenticatedCredentialID: authenticatedCredentialID
      )
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateErrorResponse(
        response,
        statusCode: 403,
        contentType: "application/json",
        forCanonicalRequest: request,
        authenticatedCredentialID: authenticatedCredentialID
      )
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateErrorResponse(
        response + Data([0x0A]),
        statusCode: 403,
        contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
        forCanonicalRequest: request,
        authenticatedCredentialID: authenticatedCredentialID
      )
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateErrorResponse(
        Data(repeating: 0x20, count: TacuaSDKBackendProtocol.maximumBackendErrorBytes + 1),
        statusCode: 403,
        contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
        forCanonicalRequest: request,
        authenticatedCredentialID: authenticatedCredentialID
      )
    }

    let reboundFields = [
      ("code", "NOT_ALLOWLISTED"),
      ("session_id", "session_other"),
      ("operation_kind", "segment"),
      ("operation_id", "upload_other"),
      ("request_digest", "sha256:" + String(repeating: "0", count: 64)),
      ("request_credential_id", "credential_other"),
      ("authenticated_credential_id", "credential_other"),
      ("outcome", "unknown"),
    ]
    for (field, value) in reboundFields {
      var root = try rootObject(response)
      guard case .object(var error) = root["error"] else {
        throw ProtocolTestFailure.assertion("Missing structured error")
      }
      if field == "code" {
        error[field] = .string(value)
      } else {
        guard case .object(var reconciliation) = error["reconciliation"] else {
          throw ProtocolTestFailure.assertion("Missing reconciliation")
        }
        reconciliation[field] = .string(value)
        error["reconciliation"] = .object(reconciliation)
      }
      root["error"] = .object(error)
      let rebound = try TacuaCanonicalJSON.data(.object(root))
      try expectFailure {
        _ = try TacuaSDKBackendProtocol.validateErrorResponse(
          rebound,
          statusCode: 403,
          contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
          forCanonicalRequest: request,
          authenticatedCredentialID: authenticatedCredentialID
        )
      }
    }

    var extra = try rootObject(response)
    extra["ignored"] = .bool(true)
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateErrorResponse(
        try TacuaCanonicalJSON.data(.object(extra)),
        statusCode: 403,
        contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
        forCanonicalRequest: request,
        authenticatedCredentialID: authenticatedCredentialID
      )
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateErrorResponse(
        response,
        statusCode: 403,
        contentType: TacuaSDKBackendProtocol.backendErrorMediaType,
        forCanonicalRequest: canonicalFixture(root, "completion-request"),
        authenticatedCredentialID: authenticatedCredentialID
      )
    }
  }

  private static func historicalMissError(
    for requestData: Data,
    authenticatedCredentialID: String
  ) throws -> Data {
    let request = try rootObject(requestData)
    let kind = try TacuaSDKBackendProtocol.validateRequest(requestData)
    let digestField = kind == .segment ? "intent_digest" : "request_digest"
    let operationIDField = kind == .completion ? "completion_id" : "upload_id"
    let message = kind == .completion
      ? TacuaSDKBackendProtocol.backendCompletionErrorMessage
      : TacuaSDKBackendProtocol.backendErrorMessage
    let value = TacuaJSONValue.object([
      "contract_version": .string(TacuaSDKBackendProtocol.backendErrorContract),
      "media_type": .string(TacuaSDKBackendProtocol.backendErrorMediaType),
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "error": .object([
        "code": .string("OPERATION_NOT_AUTHORIZED"),
        "message": .string(message),
        "reconciliation": .object([
          "outcome": .string("historical_operation_not_found"),
          "session_id": request["session_id"]!,
          "operation_kind": .string(kind.rawValue),
          "operation_id": request[operationIDField]!,
          "request_digest": request[digestField]!,
          "request_credential_id": request["credential_id"]!,
          "authenticated_credential_id": .string(authenticatedCredentialID),
        ]),
      ]),
    ])
    return try TacuaCanonicalJSON.data(value)
  }

  private static func rejectsUnknownFieldsAndReboundIdentifiers(_ root: URL) throws {
    let startRequest = try canonicalFixture(root, "launch-exchange-request")
    let startResponse = try canonicalFixture(root, "launch-exchange-receipt")
    let unknown = try replacingRoot(
      startResponse, receiptDigestField: "exchange_receipt_digest"
    ) { $0["unexpected"] = .bool(true) }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(unknown, forCanonicalRequest: startRequest)
    }

    let resumeRequest = try canonicalFixture(root, "receiving-resume-request")
    let resumeResponse = try canonicalFixture(root, "receiving-resume-receipt")
    let rebound = try replacingRoot(
      resumeResponse, receiptDigestField: "exchange_receipt_digest"
    ) { $0["session_id"] = .string("session_other") }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(rebound, forCanonicalRequest: resumeRequest)
    }
  }

  private static func buildAndScopeProjectionMatchesFrozenSchema(_ root: URL) throws {
    for mutation in 0..<5 {
      var request = try rootObject(canonicalFixture(root, "launch-exchange-request"))
      guard case .object(var build) = request["build_identity"],
        case .object(var scope) = request["scope"]
      else { throw ProtocolTestFailure.assertion("Missing launch build or scope") }
      switch mutation {
      case 0:
        build["native_version"] = .string("1.0 invalid")
      case 1:
        build["bundle_identifier"] = .string(
          String(repeating: "a.", count: 127) + "aaa"
        )
      case 2:
        guard case .object(var expo) = build["expo"] else {
          throw ProtocolTestFailure.assertion("Missing Expo build identity")
        }
        expo["update_id"] = .null
        build["expo"] = .object(expo)
      case 3:
        guard case .object(var consent) = scope["consent"] else {
          throw ProtocolTestFailure.assertion("Missing consent policy")
        }
        consent["policy_version"] = .string("invalid policy")
        scope["consent"] = .object(consent)
      default:
        guard case .object(var retention) = scope["retention"] else {
          throw ProtocolTestFailure.assertion("Missing retention policy")
        }
        retention["policy_version"] = .string("invalid policy")
        scope["retention"] = .object(retention)
      }
      try resealLaunchRequest(&request, build: &build, scope: &scope)
      try expectFailure {
        _ = try TacuaSDKBackendProtocol.validateRequest(
          try TacuaCanonicalJSON.data(.object(request))
        )
      }
    }
  }

  private static func boundedTextUsesUnicodeCodePoints(_ root: URL) throws {
    var request = try rootObject(canonicalFixture(root, "launch-exchange-request"))
    guard case .object(var build) = request["build_identity"],
      case .object(var scope) = request["scope"],
      case .object(var expo) = build["expo"]
    else { throw ProtocolTestFailure.assertion("Missing Expo launch identity") }
    expo["update_id"] = .string(String(repeating: "é", count: 512))
    build["expo"] = .object(expo)
    try resealLaunchRequest(&request, build: &build, scope: &scope)
    _ = try TacuaSDKBackendProtocol.validateRequest(
      try TacuaCanonicalJSON.data(.object(request))
    )

    guard case .object(var oversizedExpo) = build["expo"] else {
      throw ProtocolTestFailure.assertion("Missing resealed Expo identity")
    }
    oversizedExpo["update_id"] = .string(String(repeating: "é", count: 513))
    build["expo"] = .object(oversizedExpo)
    try resealLaunchRequest(&request, build: &build, scope: &scope)
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateRequest(
        try TacuaCanonicalJSON.data(.object(request))
      )
    }
  }

  private static func resealLaunchRequest(
    _ request: inout [String: TacuaJSONValue],
    build: inout [String: TacuaJSONValue],
    scope: inout [String: TacuaJSONValue]
  ) throws {
    try reseal(&build, field: "build_identity_digest")
    scope["build_id"] = build["build_id"]
    scope["build_identity_digest"] = build["build_identity_digest"]
    try reseal(&scope, field: "scope_digest")
    request["build_identity"] = .object(build)
    request["scope"] = .object(scope)
    try reseal(&request, field: "request_digest")
  }

  private static func resumeReceiptCannotPredatePriorAuthority(_ root: URL) throws {
    let request = try canonicalFixture(root, "receiving-resume-request")
    let response = try canonicalFixture(root, "receiving-resume-receipt")
    _ = try TacuaSDKBackendProtocol.validateResponse(
      response,
      forCanonicalRequest: request,
      minimumLaunchReceiptTimestamp: "2026-07-21T09:57:01Z"
    )

    let resealed = try replacingRoot(
      response,
      receiptDigestField: "exchange_receipt_digest"
    ) { $0["received_at"] = .string("2026-07-21T09:00:00Z") }
    // Pair-local validation still proves that the server received the request before issuing B.
    _ = try TacuaSDKBackendProtocol.validateResponse(
      resealed,
      forCanonicalRequest: request
    )
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        resealed,
        forCanonicalRequest: request,
        minimumLaunchReceiptTimestamp: "2026-07-21T09:57:01Z"
      )
    }
  }

  private static func completionAuthorityComesFromExactReceipt(_ root: URL) throws {
    let request = try canonicalFixture(root, "completion-request")
    let response = try canonicalFixture(root, "completion-receipt")
    let receipt = try TacuaSDKBackendProtocol.validateResponse(response, forCanonicalRequest: request)
    let authority = try requireValue(receipt.completionCleanupAuthority, "Missing completion authority")
    try require(authority.completionID == "completion_synthetic", "Cleanup must bind completion")
    try require(authority.segmentReceiptDigests.count == 1, "Cleanup must bind all media receipts")
    try require(authority.diagnosticReceiptDigests.count == 1, "Cleanup must bind all diagnostic receipts")

    let wrongCredential = try replacingRoot(
      response, receiptDigestField: "completion_receipt_digest"
    ) { root in
      guard case .object(var credential) = root["credential"] else { return }
      credential["credential_id"] = .string("credential_wrong")
      root["credential"] = .object(credential)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(wrongCredential, forCanonicalRequest: request)
    }

    let wrongCleanup = try replacingRoot(
      response, receiptDigestField: "completion_receipt_digest"
    ) { root in
      guard case .object(var cleanup) = root["local_cleanup"] else { return }
      cleanup["segment_receipt_digests"] = .array([])
      root["local_cleanup"] = .object(cleanup)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(wrongCleanup, forCanonicalRequest: request)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        response,
        forCanonicalRequest: request,
        expectedCurrentCredentialExpiry: "2026-08-20T10:00:01Z"
      )
    }
  }

  private static func resealedIncompleteCompletionCannotAuthorizeCleanup(_ root: URL) throws {
    var request = try rootObject(canonicalFixture(root, "completion-request"))
    request["segment_receipts"] = .array([])
    try reseal(&request, field: "request_digest")
    let requestDigest = request["request_digest"]!.stringValue!

    var response = try rootObject(canonicalFixture(root, "completion-receipt"))
    response["request_digest"] = .string(requestDigest)
    guard case .object(var cleanup) = response["local_cleanup"] else {
      throw ProtocolTestFailure.assertion("Missing cleanup")
    }
    cleanup["segment_receipt_digests"] = .array([])
    response["local_cleanup"] = .object(cleanup)
    try reseal(&response, field: "completion_receipt_digest")
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        try TacuaCanonicalJSON.data(.object(response)),
        forCanonicalRequest: try TacuaCanonicalJSON.data(.object(request))
      )
    }
  }

  private static func resealedManifestReceiptSetMismatchCannotAuthorizeCleanup(_ root: URL) throws {
    var request = try rootObject(canonicalFixture(root, "completion-request"))
    guard case .object(var manifest) = request["capture_manifest"],
      case .array(var segments) = manifest["segments"],
      case .object(var segment) = segments.first
    else { throw ProtocolTestFailure.assertion("Missing manifest segment") }
    segment["segment_id"] = .string("segment_other")
    segments[0] = .object(segment)
    manifest["segments"] = .array(segments)
    try reseal(&manifest, field: "manifest_digest")
    request["capture_manifest"] = .object(manifest)
    try reseal(&request, field: "request_digest")
    let requestDigest = request["request_digest"]!.stringValue!
    let manifestDigest = manifest["manifest_digest"]!.stringValue!

    var response = try rootObject(canonicalFixture(root, "completion-receipt"))
    response["request_digest"] = .string(requestDigest)
    guard case .object(var cleanup) = response["local_cleanup"],
      case .object(var job) = response["processing_job"],
      case .object(var inputs) = job["inputs"]
    else { throw ProtocolTestFailure.assertion("Missing completion response bindings") }
    cleanup["manifest_digest"] = .string(manifestDigest)
    response["local_cleanup"] = .object(cleanup)
    inputs["capture_manifest_digest"] = .string(manifestDigest)
    job["inputs"] = .object(inputs)
    try reseal(&job, field: "job_digest")
    response["processing_job"] = .object(job)
    try reseal(&response, field: "completion_receipt_digest")
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        try TacuaCanonicalJSON.data(.object(response)),
        forCanonicalRequest: try TacuaCanonicalJSON.data(.object(request))
      )
    }
  }

  private static func deletionAuthorityComesFromExactTombstone(_ root: URL) throws {
    let receipt = try pair(root, "deletion-request", "deletion-tombstone")
    let authority = try requireValue(receipt.deletionCleanupAuthority, "Missing deletion authority")
    try require(authority.credentialID == "credential_receiving_resume", "Tombstone must bind Keychain credential")
    let request = try canonicalFixture(root, "deletion-request")
    let response = try canonicalFixture(root, "deletion-tombstone")
    let overRetained = try replacingRoot(
      response, receiptDigestField: "tombstone_digest"
    ) { root in
      root["tombstone_expires_at"] = .string("2026-09-30T10:03:05Z")
      guard case .object(var credential) = root["credential"] else { return }
      credential["verifier_retained_until"] = .string("2026-09-30T10:03:05Z")
      root["credential"] = .object(credential)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(overRetained, forCanonicalRequest: request)
    }
  }

  private static func exactWholeSecondTimestampsOnly(_ root: URL) throws {
    let request = try canonicalFixture(root, "launch-exchange-request")
    let response = try canonicalFixture(root, "launch-exchange-receipt")
    let fractional = try replacingRoot(
      response, receiptDigestField: "exchange_receipt_digest"
    ) { $0["issued_at"] = .string("2026-07-21T09:57:01.000Z") }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(fractional, forCanonicalRequest: request)
    }
  }

  private static func launchRequestRejectsSameIdentifierRotation(_ root: URL) throws {
    var request = try rootObject(canonicalFixture(root, "receiving-resume-request"))
    guard case .object(var credential) = request["credential"] else {
      throw ProtocolTestFailure.assertion("Missing credential")
    }
    credential["credential_id"] = request["previous_credential_id"]
    request["credential"] = .object(credential)
    try reseal(&request, field: "request_digest")
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateRequest(
        try TacuaCanonicalJSON.data(.object(request))
      )
    }
  }

  private static func resealedDiagnosticUnknownAndUnavailableFieldsAreRejected(
    _ root: URL
  ) throws {
    var eventRequest = try rootObject(canonicalFixture(root, "diagnostic-upload-request"))
    guard case .object(var envelope) = eventRequest["envelope"],
      case .array(var events) = envelope["events"],
      case .object(var firstEvent) = events.first,
      case .object(var eventData) = firstEvent["data"]
    else { throw ProtocolTestFailure.assertion("Missing diagnostic event") }
    eventData["ignored_by_old_validator"] = .bool(true)
    firstEvent["data"] = .object(eventData)
    events[0] = .object(firstEvent)
    envelope["events"] = .array(events)
    try resealDiagnosticRequest(&eventRequest, envelope: &envelope)
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateRequest(
        try TacuaCanonicalJSON.data(.object(eventRequest))
      )
    }

    var unavailableRequest = try rootObject(
      canonicalFixture(root, "diagnostic-upload-request")
    )
    guard case .object(var unavailableEnvelope) = unavailableRequest["envelope"],
      case .array(var evidence) = unavailableEnvelope["evidence"],
      let unavailableIndex = evidence.firstIndex(where: {
        $0.objectValue?["availability"]?.stringValue == "unavailable"
      }),
      case .object(var unavailableEvidence) = evidence[unavailableIndex],
      case .object(var unavailable) = unavailableEvidence["unavailable"]
    else { throw ProtocolTestFailure.assertion("Missing unavailable evidence") }
    unavailable["ignored"] = .string("must fail")
    unavailableEvidence["unavailable"] = .object(unavailable)
    evidence[unavailableIndex] = .object(unavailableEvidence)
    unavailableEnvelope["evidence"] = .array(evidence)
    try resealDiagnosticRequest(
      &unavailableRequest, envelope: &unavailableEnvelope
    )
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateRequest(
        try TacuaCanonicalJSON.data(.object(unavailableRequest))
      )
    }
  }

  private static func resealedManifestStreamsRangesAndRetentionAreRejected(
    _ root: URL
  ) throws {
    for mutation in 0..<3 {
      var request = try rootObject(canonicalFixture(root, "completion-request"))
      guard case .object(var manifest) = request["capture_manifest"] else {
        throw ProtocolTestFailure.assertion("Missing manifest")
      }
      switch mutation {
      case 0:
        guard case .object(var streams) = manifest["streams"] else {
          throw ProtocolTestFailure.assertion("Missing streams")
        }
        streams["ignored"] = .string("enabled")
        manifest["streams"] = .object(streams)
      case 1:
        guard case .array(var segments) = manifest["segments"],
          case .object(var segment) = segments[0],
          case .object(var timeRange) = segment["time_range"]
        else { throw ProtocolTestFailure.assertion("Missing segment range") }
        timeRange["end_ms"] = .integer(1_800_001)
        segment["time_range"] = .object(timeRange)
        segments[0] = .object(segment)
        manifest["segments"] = .array(segments)
      default:
        guard case .object(var retention) = manifest["retention"] else {
          throw ProtocolTestFailure.assertion("Missing retention")
        }
        retention["raw_media_expires_at"] = .string("2027-07-21T10:00:00Z")
        manifest["retention"] = .object(retention)
      }
      try reseal(&manifest, field: "manifest_digest")
      request["capture_manifest"] = .object(manifest)
      try reseal(&request, field: "request_digest")
      try expectFailure {
        _ = try TacuaSDKBackendProtocol.validateRequest(
          try TacuaCanonicalJSON.data(.object(request))
        )
      }
    }
  }

  private static func resealDiagnosticRequest(
    _ request: inout [String: TacuaJSONValue],
    envelope: inout [String: TacuaJSONValue]
  ) throws {
    try reseal(&envelope, field: "envelope_digest")
    let envelopeValue = TacuaJSONValue.object(envelope)
    let envelopeData = try TacuaCanonicalJSON.data(envelopeValue)
    guard case .object(var transport) = request["transport"] else {
      throw ProtocolTestFailure.assertion("Missing diagnostic transport")
    }
    transport["size_bytes"] = .integer(Int64(envelopeData.count))
    transport["content_digest"] = .string(TacuaCanonicalJSON.digest(data: envelopeData))
    request["transport"] = .object(transport)
    request["envelope"] = envelopeValue
    try reseal(&request, field: "request_digest")
  }

  private static func resealedProcessingJobNestedFieldsAreRejected(_ root: URL) throws {
    let request = try canonicalFixture(root, "completion-request")
    let unknownEgress = try resealedProcessingJobResponse(root) { job in
      guard case .object(var execution) = job["execution"],
        case .object(var egress) = execution["egress"]
      else { throw ProtocolTestFailure.assertion("Missing processing egress") }
      egress["ignored"] = .bool(true)
      execution["egress"] = .object(egress)
      job["execution"] = .object(execution)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        unknownEgress,
        forCanonicalRequest: request
      )
    }

    let laterVersion = try resealedProcessingJobResponse(root) { job in
      job["job_version"] = .integer(2)
      job["previous_job_digest"] = job["job_digest"]
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        laterVersion, forCanonicalRequest: request
      )
    }

    let reorderedStages = try resealedProcessingJobResponse(root) { job in
      guard case .object(var pipeline) = job["pipeline"],
        case .array(var stages) = pipeline["stages"]
      else { throw ProtocolTestFailure.assertion("Missing processing stages") }
      stages.swapAt(0, 1)
      pipeline["stages"] = .array(stages)
      job["pipeline"] = .object(pipeline)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        reorderedStages, forCanonicalRequest: request
      )
    }

    let attemptedStage = try resealedProcessingJobResponse(root) { job in
      guard case .object(var pipeline) = job["pipeline"],
        case .array(var stages) = pipeline["stages"],
        case .object(var firstStage) = stages.first
      else { throw ProtocolTestFailure.assertion("Missing processing stages") }
      firstStage["attempt_count"] = .integer(1)
      stages[0] = .object(firstStage)
      pipeline["stages"] = .array(stages)
      job["pipeline"] = .object(pipeline)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        attemptedStage, forCanonicalRequest: request
      )
    }

    let changedExecution = try resealedProcessingJobResponse(root) { job in
      guard case .object(var execution) = job["execution"] else {
        throw ProtocolTestFailure.assertion("Missing processing execution")
      }
      execution["max_attempts"] = .integer(4)
      job["execution"] = .object(execution)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        changedExecution, forCanonicalRequest: request
      )
    }
  }

  private static func resealedProcessingJobResponse(
    _ root: URL,
    mutate: (inout [String: TacuaJSONValue]) throws -> Void
  ) throws -> Data {
    var response = try rootObject(canonicalFixture(root, "completion-receipt"))
    guard case .object(var job) = response["processing_job"] else {
      throw ProtocolTestFailure.assertion("Missing processing job")
    }
    try mutate(&job)
    try reseal(&job, field: "job_digest")
    response["processing_job"] = .object(job)
    try reseal(&response, field: "completion_receipt_digest")
    return try TacuaCanonicalJSON.data(.object(response))
  }

  private static func requireValue<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw ProtocolTestFailure.assertion(message) }
    return value
  }

  private static func rootObject(_ data: Data) throws -> [String: TacuaJSONValue] {
    guard case .object(let object) = try TacuaCanonicalJSON.parse(data) else {
      throw ProtocolTestFailure.assertion("Expected object")
    }
    return object
  }

  private static func reseal(
    _ object: inout [String: TacuaJSONValue],
    field: String
  ) throws {
    object[field] = .string(try TacuaCanonicalJSON.digest(
      .object(object), omittingRootField: field
    ))
  }
}
