// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaSDKBackendProtocolError: Error, Equatable {
  case nonCanonicalMessage
  case unsupportedMessage
  case invalidConstant(String)
  case invalidIdentifier(String)
  case invalidDigest(String)
  case digestMismatch(String)
  case bindingMismatch(String)
  case invalidTimestamp(String)
  case invalidChronology
  case invalidCredentialTransition
  case invalidCleanupAuthority
  case invalidRuntimeArtifact
}

struct TacuaValidatedCredentialTransition: Equatable {
  let credentialID: String
  let capability: TacuaTransportCredentialCapability
  let expiresAt: String
  let replayCompletionID: String?
}

struct TacuaValidatedBackendReceipt: Equatable {
  let operationKind: TacuaBackendOperationKind
  let operationID: String
  let responseDigest: String
  let canonicalResponse: Data
  let authoritativeTimestamp: String
  let remoteSessionID: String
  let scopeDigest: String
  let credentialTransition: TacuaValidatedCredentialTransition?
  let completionCleanupAuthority: TacuaCompletionCleanupAuthority?
  let deletionCleanupAuthority: TacuaDeletionCleanupAuthority?
}

enum TacuaBackendOperationKind: String, Equatable {
  case launch
  case segment
  case diagnostic
  case completion
  case deletion
}

enum TacuaSDKBackendProtocol {
  static let version = "tacua.sdk-backend@1.0.0"
  static let maximumResponseBytes = 2 * 1_024 * 1_024
  static let maximumUploadBytes: Int64 = 1_073_741_824

  static func validateResponse(
    _ responseData: Data,
    forCanonicalRequest requestData: Data,
    maximumResponseBytes: Int = maximumResponseBytes,
    expectedCurrentCredentialExpiry: String? = nil
  ) throws -> TacuaValidatedBackendReceipt {
    let requestValue = try TacuaCanonicalJSON.parse(requestData)
    guard try TacuaCanonicalJSON.data(requestValue) == requestData else {
      throw TacuaSDKBackendProtocolError.nonCanonicalMessage
    }
    let responseValue = try TacuaCanonicalJSON.parse(
      responseData,
      maximumBytes: maximumResponseBytes
    )
    let canonicalResponse = try TacuaCanonicalJSON.data(responseValue)
    guard canonicalResponse == responseData else {
      throw TacuaSDKBackendProtocolError.nonCanonicalMessage
    }
    let request = try object(requestValue)
    switch try string(request, "message_type") {
    case "launch_exchange_request":
      return try validateLaunch(request: requestValue, response: responseValue, data: responseData)
    case "segment_upload_intent":
      return try validateSegment(request: requestValue, response: responseValue, data: responseData)
    case "diagnostic_upload_request":
      return try validateDiagnostic(request: requestValue, response: responseValue, data: responseData)
    case "completion_request":
      return try validateCompletion(
        request: requestValue,
        response: responseValue,
        data: responseData,
        expectedCredentialExpiry: expectedCurrentCredentialExpiry
      )
    case "deletion_request":
      return try validateDeletion(request: requestValue, response: responseValue, data: responseData)
    default:
      throw TacuaSDKBackendProtocolError.unsupportedMessage
    }
  }

  private static func validateLaunch(
    request requestValue: TacuaJSONValue,
    response responseValue: TacuaJSONValue,
    data: Data
  ) throws -> TacuaValidatedBackendReceipt {
    let request = try exactObject(requestValue, keys: [
      "protocol_version", "message_type", "exchange_kind", "exchange_id", "launch_code",
      "expected_session_id", "expected_session_state", "expected_completion_id",
      "previous_credential_id", "credential", "build_identity", "scope", "requested_at",
      "request_digest",
    ])
    try constant(request, "protocol_version", version)
    try constant(request, "message_type", "launch_exchange_request")
    try validateArtifactDigest(requestValue, field: "request_digest")
    let exchangeID = try identifier(request, "exchange_id")
    let requestDigest = try digest(request, "request_digest")
    _ = try timestamp(request, "requested_at")
    let kind = try string(request, "exchange_kind")
    guard ["start_session", "resume_session"].contains(kind) else {
      throw TacuaSDKBackendProtocolError.invalidConstant("exchange_kind")
    }
    let expectedState = try string(request, "expected_session_state")
    guard ["receiving", "completed"].contains(expectedState) else {
      throw TacuaSDKBackendProtocolError.invalidConstant("expected_session_state")
    }
    let expectedSessionID = try nullableString(request, "expected_session_id")
    let expectedCompletionID = try nullableString(request, "expected_completion_id")
    let previousCredentialID = try nullableString(request, "previous_credential_id")
    if kind == "start_session" {
      guard expectedSessionID == nil, expectedState == "receiving",
        expectedCompletionID == nil, previousCredentialID == nil
      else { throw TacuaSDKBackendProtocolError.bindingMismatch("start_session") }
    } else {
      guard expectedSessionID != nil, previousCredentialID != nil,
        (expectedState == "completed") == (expectedCompletionID != nil)
      else { throw TacuaSDKBackendProtocolError.bindingMismatch("resume_session") }
    }
    let launchCode = try string(request, "launch_code")
    guard launchCode.range(of: "^[A-Za-z0-9_-]{32,512}$", options: .regularExpression) != nil else {
      throw TacuaSDKBackendProtocolError.invalidIdentifier("launch_code")
    }
    let requestCredential = try exactObject(try required(request, "credential"), keys: [
      "credential_id", "secret", "authentication_scheme", "local_storage",
    ])
    let credentialID = try identifier(requestCredential, "credential_id")
    try constant(requestCredential, "authentication_scheme", "Bearer")
    try constant(
      requestCredential, "local_storage", "ios_keychain_when_unlocked_this_device_only"
    )
    let secret = try string(requestCredential, "secret")
    guard secret.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
      throw TacuaSDKBackendProtocolError.invalidCredentialTransition
    }
    let buildIdentity = try required(request, "build_identity")
    try validateBuildIdentity(buildIdentity)
    let scope = try required(request, "scope")
    let scopeDigest = try validateScope(scope)
    let build = try object(buildIdentity)
    let scopeObject = try object(scope)
    try equalString(scopeObject, "build_id", try string(build, "build_id"))
    try equalString(
      scopeObject, "build_identity_digest", try string(build, "build_identity_digest")
    )

    let response = try exactObject(responseValue, keys: [
      "protocol_version", "message_type", "exchange_kind", "exchange_id", "request_digest",
      "session_id", "session_state", "scope", "credential",
      "previous_credential_revocation", "received_at", "issued_at",
      "exchange_receipt_digest",
    ])
    try constant(response, "protocol_version", version)
    try constant(response, "message_type", "launch_exchange_receipt")
    try validateArtifactDigest(responseValue, field: "exchange_receipt_digest")
    try equalString(response, "exchange_kind", kind)
    try equalString(response, "exchange_id", exchangeID)
    try equalString(response, "request_digest", requestDigest)
    let remoteSessionID = try identifier(response, "session_id")
    if let expectedSessionID, remoteSessionID != expectedSessionID {
      throw TacuaSDKBackendProtocolError.bindingMismatch("session_id")
    }
    try equalString(response, "session_state", expectedState)
    guard try required(response, "scope") == scope else {
      throw TacuaSDKBackendProtocolError.bindingMismatch("scope")
    }
    let responseScopeDigest = try validateScope(try required(response, "scope"))
    guard responseScopeDigest == scopeDigest else {
      throw TacuaSDKBackendProtocolError.bindingMismatch("scope_digest")
    }
    let receivedAt = try timestamp(response, "received_at")
    let issuedAt = try timestamp(response, "issued_at")
    guard receivedAt <= issuedAt else { throw TacuaSDKBackendProtocolError.invalidChronology }

    let responseCredential = try exactObject(try required(response, "credential"), keys: [
      "credential_id", "authentication_scheme", "state", "replay_completion_id", "expires_at",
    ])
    try equalString(responseCredential, "credential_id", credentialID)
    try constant(responseCredential, "authentication_scheme", "Bearer")
    let credentialState = try string(responseCredential, "state")
    let replayCompletionID = try nullableString(responseCredential, "replay_completion_id")
    guard replayCompletionID == expectedCompletionID else {
      throw TacuaSDKBackendProtocolError.bindingMismatch("replay_completion_id")
    }
    let capability: TacuaTransportCredentialCapability
    if expectedState == "receiving" {
      guard credentialState == "active", replayCompletionID == nil else {
        throw TacuaSDKBackendProtocolError.invalidCredentialTransition
      }
      capability = .active
    } else {
      guard credentialState == "completion_replay_or_delete_only", replayCompletionID != nil else {
        throw TacuaSDKBackendProtocolError.invalidCredentialTransition
      }
      capability = .completionReplayOrDeleteOnly
    }
    let expiresAt = try string(responseCredential, "expires_at")
    guard let expires = parseTimestamp(expiresAt), expires > issuedAt else {
      throw TacuaSDKBackendProtocolError.invalidCredentialTransition
    }
    if kind == "start_session" {
      guard try required(response, "previous_credential_revocation") == .null else {
        throw TacuaSDKBackendProtocolError.invalidCredentialTransition
      }
    } else {
      let revocation = try exactObject(
        try required(response, "previous_credential_revocation"),
        keys: ["credential_id", "state", "revoked_at"]
      )
      try equalString(revocation, "credential_id", previousCredentialID!)
      try constant(revocation, "state", "revoked")
      try equalString(revocation, "revoked_at", try string(response, "issued_at"))
    }
    return TacuaValidatedBackendReceipt(
      operationKind: .launch,
      operationID: exchangeID,
      responseDigest: try digest(response, "exchange_receipt_digest"),
      canonicalResponse: data,
      authoritativeTimestamp: try string(response, "issued_at"),
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialTransition: TacuaValidatedCredentialTransition(
        credentialID: credentialID,
        capability: capability,
        expiresAt: expiresAt,
        replayCompletionID: replayCompletionID
      ),
      completionCleanupAuthority: nil,
      deletionCleanupAuthority: nil
    )
  }

  private static func validateSegment(
    request requestValue: TacuaJSONValue,
    response responseValue: TacuaJSONValue,
    data: Data
  ) throws -> TacuaValidatedBackendReceipt {
    let request = try exactObject(requestValue, keys: [
      "protocol_version", "message_type", "upload_id", "session_id", "scope_digest",
      "credential_id", "sequence", "segment_id", "transport", "sidecar_digest",
      "requested_at", "intent_digest",
    ])
    try requestPreamble(request, message: "segment_upload_intent")
    try validateArtifactDigest(requestValue, field: "intent_digest")
    let transport = try exactObject(try required(request, "transport"), keys: [
      "content_type", "size_bytes", "content_digest",
    ])
    let contentType = try string(transport, "content_type")
    guard ["video/mp4", "video/quicktime"].contains(contentType) else {
      throw TacuaSDKBackendProtocolError.invalidConstant("content_type")
    }
    let sizeBytes = try boundedPositiveInteger(
      transport, "size_bytes", maximum: maximumUploadBytes
    )
    let contentDigest = try digest(transport, "content_digest")
    _ = try digest(request, "sidecar_digest")
    let intentSequence = try integer(request, "sequence")
    guard (0...2_047).contains(intentSequence) else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    let requestedAt = try timestamp(request, "requested_at")

    let response = try exactObject(responseValue, keys: [
      "protocol_version", "message_type", "upload_id", "intent_digest", "session_id",
      "scope_digest", "credential_id", "sequence", "segment_id", "content_type",
      "sidecar_digest", "runtime_receipt", "transport_digest", "segment_receipt_digest",
    ])
    try responsePreamble(response, message: "segment_upload_receipt")
    try validateArtifactDigest(responseValue, field: "segment_receipt_digest")
    for field in ["upload_id", "intent_digest", "session_id", "scope_digest", "credential_id",
      "segment_id", "sidecar_digest"] {
      try equalString(response, field, try string(request, field))
    }
    let responseSequence = try integer(response, "sequence")
    let requestSequence = intentSequence
    guard responseSequence == requestSequence else {
      throw TacuaSDKBackendProtocolError.bindingMismatch("sequence")
    }
    try equalString(response, "content_type", contentType)
    try equalString(response, "transport_digest", contentDigest)
    let runtimeReceiptValue = try required(response, "runtime_receipt")
    let runtimeReceipt = try exactObject(runtimeReceiptValue, keys: [
      "object_id", "segment_id", "size_bytes", "content_digest", "received_at", "receipt_digest",
    ])
    try validateArtifactDigest(runtimeReceiptValue, field: "receipt_digest")
    _ = try identifier(runtimeReceipt, "object_id")
    try equalString(runtimeReceipt, "segment_id", try string(request, "segment_id"))
    try equalString(runtimeReceipt, "content_digest", contentDigest)
    guard try boundedPositiveInteger(
      runtimeReceipt, "size_bytes", maximum: maximumUploadBytes
    ) == sizeBytes else {
      throw TacuaSDKBackendProtocolError.bindingMismatch("size_bytes")
    }
    let receivedAt = try timestamp(runtimeReceipt, "received_at")
    guard receivedAt >= requestedAt else { throw TacuaSDKBackendProtocolError.invalidChronology }
    return TacuaValidatedBackendReceipt(
      operationKind: .segment,
      operationID: try identifier(request, "upload_id"),
      responseDigest: try digest(response, "segment_receipt_digest"),
      canonicalResponse: data,
      authoritativeTimestamp: try string(runtimeReceipt, "received_at"),
      remoteSessionID: try identifier(request, "session_id"),
      scopeDigest: try digest(request, "scope_digest"),
      credentialTransition: nil,
      completionCleanupAuthority: nil,
      deletionCleanupAuthority: nil
    )
  }

  private static func validateDiagnostic(
    request requestValue: TacuaJSONValue,
    response responseValue: TacuaJSONValue,
    data: Data
  ) throws -> TacuaValidatedBackendReceipt {
    let request = try exactObject(requestValue, keys: [
      "protocol_version", "message_type", "upload_id", "session_id", "scope_digest",
      "credential_id", "transport", "envelope", "requested_at", "request_digest",
    ])
    try requestPreamble(request, message: "diagnostic_upload_request")
    try validateArtifactDigest(requestValue, field: "request_digest")
    let transport = try exactObject(try required(request, "transport"), keys: [
      "content_type", "size_bytes", "content_digest",
    ])
    try constant(
      transport, "content_type",
      "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0"
    )
    let envelope = try object(try required(request, "envelope"))
    let envelopeID = try identifier(envelope, "envelope_id")
    let envelopeDigest = try digest(envelope, "envelope_digest")
    try validateArtifactDigest(try required(request, "envelope"), field: "envelope_digest")
    try equalString(envelope, "session_id", try string(request, "session_id"))
    let envelopeData = try TacuaCanonicalJSON.data(try required(request, "envelope"))
    let transportSize = try boundedPositiveInteger(
      transport, "size_bytes", maximum: maximumUploadBytes
    )
    let transportDigest = try digest(transport, "content_digest")
    guard Int64(envelopeData.count) == transportSize,
      TacuaCanonicalJSON.digest(data: envelopeData) == transportDigest
    else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
    let requestedAt = try timestamp(request, "requested_at")

    let response = try exactObject(responseValue, keys: [
      "protocol_version", "message_type", "receipt_id", "upload_id", "request_digest",
      "session_id", "scope_digest", "credential_id", "object_id", "size_bytes",
      "transport_digest", "envelope_id", "envelope_digest", "received_at",
      "diagnostic_receipt_digest",
    ])
    try responsePreamble(response, message: "diagnostic_upload_receipt")
    try validateArtifactDigest(responseValue, field: "diagnostic_receipt_digest")
    _ = try identifier(response, "receipt_id")
    _ = try identifier(response, "object_id")
    for field in ["upload_id", "request_digest", "session_id", "scope_digest", "credential_id"] {
      try equalString(response, field, try string(request, field))
    }
    try equalString(response, "envelope_id", envelopeID)
    try equalString(response, "envelope_digest", envelopeDigest)
    try equalString(response, "transport_digest", try string(transport, "content_digest"))
    let responseSize = try boundedPositiveInteger(
      response, "size_bytes", maximum: maximumUploadBytes
    )
    guard responseSize == transportSize else {
      throw TacuaSDKBackendProtocolError.bindingMismatch("size_bytes")
    }
    let receivedAt = try timestamp(response, "received_at")
    guard receivedAt >= requestedAt else { throw TacuaSDKBackendProtocolError.invalidChronology }
    return TacuaValidatedBackendReceipt(
      operationKind: .diagnostic,
      operationID: try identifier(request, "upload_id"),
      responseDigest: try digest(response, "diagnostic_receipt_digest"),
      canonicalResponse: data,
      authoritativeTimestamp: try string(response, "received_at"),
      remoteSessionID: try identifier(request, "session_id"),
      scopeDigest: try digest(request, "scope_digest"),
      credentialTransition: nil,
      completionCleanupAuthority: nil,
      deletionCleanupAuthority: nil
    )
  }

  private static func validateCompletion(
    request requestValue: TacuaJSONValue,
    response responseValue: TacuaJSONValue,
    data: Data,
    expectedCredentialExpiry: String?
  ) throws -> TacuaValidatedBackendReceipt {
    let request = try exactObject(requestValue, keys: [
      "protocol_version", "message_type", "completion_id", "session_id", "scope_digest",
      "credential_id", "capture_manifest", "segment_receipts", "diagnostic_receipts",
      "requested_at", "request_digest",
    ])
    try requestPreamble(request, message: "completion_request")
    try validateArtifactDigest(requestValue, field: "request_digest")
    let completionID = try identifier(request, "completion_id")
    let requestedAt = try timestamp(request, "requested_at")
    let bindings = try validateCompletionRequestBindings(
      request,
      requestedAt: requestedAt
    )
    let manifest = bindings.manifest
    let manifestDigest = bindings.manifestDigest
    let segmentDigests = bindings.segmentReceiptDigests
    let diagnosticDigests = bindings.diagnosticReceiptDigests

    let response = try exactObject(responseValue, keys: [
      "protocol_version", "message_type", "completion_id", "request_digest", "session_id",
      "scope_digest", "accepted_at", "processing_job", "credential", "local_cleanup",
      "completion_receipt_digest",
    ])
    try responsePreamble(response, message: "completion_receipt")
    try validateArtifactDigest(responseValue, field: "completion_receipt_digest")
    for field in ["completion_id", "request_digest", "session_id", "scope_digest"] {
      try equalString(response, field, try string(request, field))
    }
    let acceptedAt = try timestamp(response, "accepted_at")
    guard acceptedAt >= requestedAt else { throw TacuaSDKBackendProtocolError.invalidChronology }
    let credential = try exactObject(try required(response, "credential"), keys: [
      "credential_id", "state", "replay_completion_id", "expires_at",
    ])
    try equalString(credential, "credential_id", try string(request, "credential_id"))
    try constant(credential, "state", "completion_replay_or_delete_only")
    try equalString(credential, "replay_completion_id", completionID)
    let expiresAt = try string(credential, "expires_at")
    guard let expires = parseTimestamp(expiresAt), expires > acceptedAt else {
      throw TacuaSDKBackendProtocolError.invalidCredentialTransition
    }
    if let expectedCredentialExpiry, expiresAt != expectedCredentialExpiry {
      throw TacuaSDKBackendProtocolError.invalidCredentialTransition
    }
    let cleanup = try exactObject(try required(response, "local_cleanup"), keys: [
      "state", "manifest_digest", "segment_receipt_digests", "diagnostic_receipt_digests",
    ])
    try constant(cleanup, "state", "authorized_after_durable_receipt")
    try equalString(cleanup, "manifest_digest", manifestDigest)
    guard try stringArray(cleanup, "segment_receipt_digests") == segmentDigests,
      try stringArray(cleanup, "diagnostic_receipt_digests") == diagnosticDigests
    else { throw TacuaSDKBackendProtocolError.invalidCleanupAuthority }
    let jobValue = try required(response, "processing_job")
    let job = try validateQueuedProcessingJob(jobValue)
    for field in [
      "organization_id", "project_id", "build_id", "build_identity_digest", "session_id",
    ] {
      try equalString(job, field, try string(manifest, field))
    }
    try equalString(job, "requested_at", try string(response, "accepted_at"))
    let jobInputs = try object(try required(job, "inputs"))
    try equalString(jobInputs, "capture_manifest_digest", manifestDigest)
    let jobEnvelopeDigests = try stringArray(jobInputs, "diagnostic_envelope_digests")
    guard jobEnvelopeDigests == bindings.diagnosticEnvelopeDigests
    else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
    let responseDigest = try digest(response, "completion_receipt_digest")
    return TacuaValidatedBackendReceipt(
      operationKind: .completion,
      operationID: completionID,
      responseDigest: responseDigest,
      canonicalResponse: data,
      authoritativeTimestamp: try string(response, "accepted_at"),
      remoteSessionID: try identifier(request, "session_id"),
      scopeDigest: try digest(request, "scope_digest"),
      credentialTransition: TacuaValidatedCredentialTransition(
        credentialID: try identifier(credential, "credential_id"),
        capability: .completionReplayOrDeleteOnly,
        expiresAt: expiresAt,
        replayCompletionID: completionID
      ),
      completionCleanupAuthority: TacuaCompletionCleanupAuthority(
        completionID: completionID,
        completionReceiptDigest: responseDigest,
        manifestDigest: manifestDigest,
        segmentReceiptDigests: segmentDigests,
        diagnosticReceiptDigests: diagnosticDigests
      ),
      deletionCleanupAuthority: nil
    )
  }

  private static func validateDeletion(
    request requestValue: TacuaJSONValue,
    response responseValue: TacuaJSONValue,
    data: Data
  ) throws -> TacuaValidatedBackendReceipt {
    let request = try exactObject(requestValue, keys: [
      "protocol_version", "message_type", "deletion_id", "session_id", "scope_digest",
      "credential_id", "target", "reason", "requested_at", "request_digest",
    ])
    try requestPreamble(request, message: "deletion_request")
    try validateArtifactDigest(requestValue, field: "request_digest")
    try constant(request, "target", "session_all_data")
    let deletionID = try identifier(request, "deletion_id")
    let requestedAt = try timestamp(request, "requested_at")
    let response = try exactObject(responseValue, keys: [
      "protocol_version", "message_type", "deletion_id", "deletion_request_digest",
      "session_id", "scope_digest", "credential", "session_access", "erasure",
      "local_credential_cleanup", "accepted_at", "deleted_at", "tombstone_expires_at",
      "tombstone_digest",
    ])
    try responsePreamble(response, message: "deletion_tombstone")
    try validateArtifactDigest(responseValue, field: "tombstone_digest")
    try equalString(response, "deletion_id", deletionID)
    try equalString(response, "deletion_request_digest", try string(request, "request_digest"))
    for field in ["session_id", "scope_digest"] {
      try equalString(response, field, try string(request, field))
    }
    try constant(response, "local_credential_cleanup", "authorized_after_durable_tombstone")
    let credential = try exactObject(try required(response, "credential"), keys: [
      "credential_id", "state", "replay_deletion_id", "verifier_retained_until",
    ])
    let credentialID = try identifier(request, "credential_id")
    try equalString(credential, "credential_id", credentialID)
    try constant(credential, "state", "deletion_replay_only")
    try equalString(credential, "replay_deletion_id", deletionID)
    let access = try exactObject(try required(response, "session_access"), keys: [
      "uploads", "completion", "processing", "evidence",
    ])
    for field in ["uploads", "completion", "processing", "evidence"] {
      try constant(access, field, "revoked")
    }
    let erasure = try exactObject(try required(response, "erasure"), keys: [
      "raw_media", "diagnostics", "derived_data", "session_metadata", "erased_object_count",
    ])
    for field in ["raw_media", "diagnostics", "derived_data"] {
      try constant(erasure, field, "deleted")
    }
    try constant(
      erasure, "session_metadata", "deleted_except_tombstone_and_replay_verifier"
    )
    guard try integer(erasure, "erased_object_count") >= 0 else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    let acceptedAt = try timestamp(response, "accepted_at")
    let deletedAt = try timestamp(response, "deleted_at")
    let expiresAt = try timestamp(response, "tombstone_expires_at")
    guard acceptedAt >= requestedAt, deletedAt >= acceptedAt, expiresAt > deletedAt,
      expiresAt.timeIntervalSince(deletedAt) <= 30 * 24 * 60 * 60
    else { throw TacuaSDKBackendProtocolError.invalidChronology }
    try equalString(
      credential, "verifier_retained_until", try string(response, "tombstone_expires_at")
    )
    let tombstoneDigest = try digest(response, "tombstone_digest")
    return TacuaValidatedBackendReceipt(
      operationKind: .deletion,
      operationID: deletionID,
      responseDigest: tombstoneDigest,
      canonicalResponse: data,
      authoritativeTimestamp: try string(response, "accepted_at"),
      remoteSessionID: try identifier(request, "session_id"),
      scopeDigest: try digest(request, "scope_digest"),
      credentialTransition: TacuaValidatedCredentialTransition(
        credentialID: credentialID,
        capability: .deletionReplayOnly,
        expiresAt: try string(response, "tombstone_expires_at"),
        replayCompletionID: nil
      ),
      completionCleanupAuthority: nil,
      deletionCleanupAuthority: TacuaDeletionCleanupAuthority(
        deletionID: deletionID,
        tombstoneDigest: tombstoneDigest,
        credentialID: credentialID
      )
    )
  }

  private static func validateBuildIdentity(_ value: TacuaJSONValue) throws {
    let build = try exactObject(value, keys: [
      "protocol_version", "message_type", "build_id", "platform", "bundle_identifier",
      "native_version", "native_build", "build_variant", "distribution",
      "react_native_version", "expo", "source", "created_at",
      "transport_configuration_digest", "build_identity_digest",
    ])
    try constant(build, "protocol_version", version)
    try constant(build, "message_type", "build_identity")
    try constant(build, "platform", "ios")
    guard ["development", "preview"].contains(try string(build, "build_variant")) else {
      throw TacuaSDKBackendProtocolError.invalidConstant("build_variant")
    }
    _ = try digest(build, "transport_configuration_digest")
    _ = try timestamp(build, "created_at")
    _ = try exactObject(try required(build, "expo"), keys: [
      "sdk_version", "runtime_version", "update_id", "update_channel",
    ])
    _ = try exactObject(try required(build, "source"), keys: [
      "git_revision", "working_tree_dirty",
    ])
    try validateArtifactDigest(value, field: "build_identity_digest")
  }

  @discardableResult
  private static func validateScope(_ value: TacuaJSONValue) throws -> String {
    let scope = try exactObject(value, keys: [
      "protocol_version", "message_type", "organization_id", "project_id", "application_id",
      "build_id", "build_identity_digest", "capture_scope", "consent", "retention",
      "scope_digest",
    ])
    try constant(scope, "protocol_version", version)
    try constant(scope, "message_type", "capture_scope")
    try constant(scope, "capture_scope", "app_only")
    for field in ["organization_id", "project_id", "application_id", "build_id"] {
      _ = try identifier(scope, field)
    }
    _ = try digest(scope, "build_identity_digest")
    let consent = try exactObject(try required(scope, "consent"), keys: [
      "policy_version", "granted_at", "screen_recording", "microphone", "diagnostics",
      "raw_media_upload",
    ])
    for field in ["screen_recording", "microphone", "diagnostics", "raw_media_upload"] {
      try constant(consent, field, "granted")
    }
    _ = try timestamp(consent, "granted_at")
    let retention = try exactObject(try required(scope, "retention"), keys: [
      "policy_version", "raw_media_days", "derived_data_days",
    ])
    guard (1...30).contains(try integer(retention, "raw_media_days")),
      (1...365).contains(try integer(retention, "derived_data_days"))
    else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
    try validateArtifactDigest(value, field: "scope_digest")
    return try digest(scope, "scope_digest")
  }

  private struct CompletionRequestBindings {
    let manifest: [String: TacuaJSONValue]
    let manifestDigest: String
    let segmentReceiptDigests: [String]
    let diagnosticReceiptDigests: [String]
    let diagnosticEnvelopeDigests: [String]
  }

  private struct CompletionSegmentReceipt {
    let uploadID: String
    let segmentID: String
    let sequence: Int64
    let contentType: String
    let sidecarDigest: String
    let receiptDigest: String
    let runtimeReceipt: TacuaJSONValue
    let runtimeReceivedAt: Date
  }

  private struct CompletionDiagnosticReceipt {
    let uploadID: String
    let receiptID: String
    let objectID: String
    let receiptDigest: String
    let envelopeDigest: String
    let receivedAt: Date
  }

  private struct AvailableManifestSegment {
    let sequence: Int64
    let contentType: String
    let sidecarDigest: String
    let sizeBytes: Int64
    let contentDigest: String
  }

  private static func validateCompletionRequestBindings(
    _ request: [String: TacuaJSONValue],
    requestedAt: Date
  ) throws -> CompletionRequestBindings {
    let sessionID = try identifier(request, "session_id")
    let scopeDigest = try digest(request, "scope_digest")
    let manifestValue = try required(request, "capture_manifest")
    let manifest = try exactObject(manifestValue, keys: [
      "contract_version", "media_type", "manifest_version", "organization_id", "project_id",
      "build_id", "build_identity_digest", "session_id", "capture_scope", "started_at",
      "ended_at", "monotonic_duration_ms", "capture_state", "streams", "segments", "gaps",
      "upload", "retention", "manifest_digest",
    ])
    try validateArtifactDigest(manifestValue, field: "manifest_digest")
    try constant(manifest, "contract_version", "tacua.capture-upload-manifest@1.0.0")
    try constant(
      manifest, "media_type", "application/vnd.tacua.capture-upload-manifest+json;version=1.0.0"
    )
    try constant(manifest, "capture_scope", "app_only")
    try constant(manifest, "capture_state", "complete")
    for field in ["organization_id", "project_id", "build_id", "session_id"] {
      _ = try identifier(manifest, field)
    }
    _ = try digest(manifest, "build_identity_digest")
    try equalString(manifest, "session_id", sessionID)
    guard try integer(manifest, "manifest_version") >= 1,
      try integer(manifest, "monotonic_duration_ms") >= 0
    else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
    let startedAt = try timestamp(manifest, "started_at")
    let endedAt = try timestamp(manifest, "ended_at")
    guard endedAt >= startedAt else { throw TacuaSDKBackendProtocolError.invalidChronology }

    let segmentValues = try array(try required(manifest, "segments"))
    guard segmentValues.count <= 2_048 else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    var availableSegments: [String: AvailableManifestSegment] = [:]
    var manifestSegmentIDs = Set<String>()
    var manifestSequences = Set<Int64>()
    for value in segmentValues {
      let segment = try exactObject(value, keys: [
        "segment_id", "sequence", "time_range", "finalized", "availability", "content",
        "unavailable",
      ])
      let segmentID = try identifier(segment, "segment_id")
      let sequence = try integer(segment, "sequence")
      guard (0...2_047).contains(sequence), manifestSegmentIDs.insert(segmentID).inserted,
        manifestSequences.insert(sequence).inserted,
        try bool(segment, "finalized")
      else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
      switch try string(segment, "availability") {
      case "available":
        guard try required(segment, "unavailable") == .null else {
          throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
        }
        let content = try exactObject(try required(segment, "content"), keys: [
          "content_type", "size_bytes", "content_digest", "sidecar_digest",
        ])
        let contentType = try string(content, "content_type")
        guard ["video/mp4", "video/quicktime"].contains(contentType) else {
          throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
        }
        availableSegments[segmentID] = AvailableManifestSegment(
          sequence: sequence,
          contentType: contentType,
          sidecarDigest: try digest(content, "sidecar_digest"),
          sizeBytes: try boundedPositiveInteger(
            content, "size_bytes", maximum: maximumUploadBytes
          ),
          contentDigest: try digest(content, "content_digest")
        )
      case "unavailable":
        guard try required(segment, "content") == .null,
          try required(segment, "unavailable") != .null
        else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
      default:
        throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
      }
    }

    let segmentReceiptValues = try array(try required(request, "segment_receipts"))
    guard (1...2_048).contains(segmentReceiptValues.count) else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    var segmentReceipts: [String: CompletionSegmentReceipt] = [:]
    var segmentUploadIDs = Set<String>()
    var segmentSequences = Set<Int64>()
    var segmentReceiptDigests: [String] = []
    for value in segmentReceiptValues {
      let receipt = try validateCompletionSegmentReceipt(
        value, sessionID: sessionID, scopeDigest: scopeDigest
      )
      guard segmentReceipts[receipt.segmentID] == nil,
        segmentUploadIDs.insert(receipt.uploadID).inserted,
        segmentSequences.insert(receipt.sequence).inserted,
        !segmentReceiptDigests.contains(receipt.receiptDigest)
      else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
      segmentReceipts[receipt.segmentID] = receipt
      segmentReceiptDigests.append(receipt.receiptDigest)
    }
    guard Set(segmentReceipts.keys) == Set(availableSegments.keys) else {
      throw TacuaSDKBackendProtocolError.invalidCleanupAuthority
    }

    let upload = try exactObject(try required(manifest, "upload"), keys: [
      "state", "protocol", "remote_session_id", "receipts", "last_error", "completed_at",
    ])
    try constant(upload, "state", "complete")
    try constant(upload, "protocol", "segmented-resumable-v1")
    try equalString(upload, "remote_session_id", sessionID)
    guard try required(upload, "last_error") == .null else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    let uploadCompletedAt = try timestamp(upload, "completed_at")
    guard uploadCompletedAt >= endedAt, requestedAt >= uploadCompletedAt else {
      throw TacuaSDKBackendProtocolError.invalidChronology
    }
    let runtimeReceiptValues = try array(try required(upload, "receipts"))
    var runtimeReceipts: [String: TacuaJSONValue] = [:]
    for value in runtimeReceiptValues {
      let receipt = try validateRuntimeReceipt(value)
      let segmentID = try identifier(receipt, "segment_id")
      guard runtimeReceipts.updateValue(value, forKey: segmentID) == nil else {
        throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
      }
    }
    guard Set(runtimeReceipts.keys) == Set(segmentReceipts.keys) else {
      throw TacuaSDKBackendProtocolError.invalidCleanupAuthority
    }
    for (segmentID, protocolReceipt) in segmentReceipts {
      guard let manifestSegment = availableSegments[segmentID],
        let manifestRuntimeReceipt = runtimeReceipts[segmentID],
        manifestRuntimeReceipt == protocolReceipt.runtimeReceipt,
        protocolReceipt.sequence == manifestSegment.sequence,
        protocolReceipt.contentType == manifestSegment.contentType,
        protocolReceipt.sidecarDigest == manifestSegment.sidecarDigest
      else { throw TacuaSDKBackendProtocolError.invalidCleanupAuthority }
      let runtime = try object(protocolReceipt.runtimeReceipt)
      guard try boundedPositiveInteger(
        runtime, "size_bytes", maximum: maximumUploadBytes
      ) == manifestSegment.sizeBytes,
        try digest(runtime, "content_digest") == manifestSegment.contentDigest,
        uploadCompletedAt >= protocolReceipt.runtimeReceivedAt
      else { throw TacuaSDKBackendProtocolError.invalidCleanupAuthority }
    }

    let diagnosticReceiptValues = try array(try required(request, "diagnostic_receipts"))
    guard (1...2_048).contains(diagnosticReceiptValues.count) else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    var diagnosticUploadIDs = Set<String>()
    var diagnosticReceiptIDs = Set<String>()
    var diagnosticObjectIDs = Set<String>()
    var diagnosticReceiptDigests: [String] = []
    var diagnosticEnvelopeDigests: [String] = []
    for value in diagnosticReceiptValues {
      let receipt = try validateCompletionDiagnosticReceipt(
        value, sessionID: sessionID, scopeDigest: scopeDigest
      )
      guard diagnosticUploadIDs.insert(receipt.uploadID).inserted,
        diagnosticReceiptIDs.insert(receipt.receiptID).inserted,
        diagnosticObjectIDs.insert(receipt.objectID).inserted,
        !diagnosticReceiptDigests.contains(receipt.receiptDigest),
        requestedAt >= receipt.receivedAt
      else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
      diagnosticReceiptDigests.append(receipt.receiptDigest)
      diagnosticEnvelopeDigests.append(receipt.envelopeDigest)
    }
    return CompletionRequestBindings(
      manifest: manifest,
      manifestDigest: try digest(manifest, "manifest_digest"),
      segmentReceiptDigests: segmentReceiptDigests,
      diagnosticReceiptDigests: diagnosticReceiptDigests,
      diagnosticEnvelopeDigests: diagnosticEnvelopeDigests
    )
  }

  private static func validateCompletionSegmentReceipt(
    _ value: TacuaJSONValue,
    sessionID: String,
    scopeDigest: String
  ) throws -> CompletionSegmentReceipt {
    let receipt = try exactObject(value, keys: [
      "protocol_version", "message_type", "upload_id", "intent_digest", "session_id",
      "scope_digest", "credential_id", "sequence", "segment_id", "content_type",
      "sidecar_digest", "runtime_receipt", "transport_digest", "segment_receipt_digest",
    ])
    try responsePreamble(receipt, message: "segment_upload_receipt")
    try validateArtifactDigest(value, field: "segment_receipt_digest")
    try equalString(receipt, "session_id", sessionID)
    try equalString(receipt, "scope_digest", scopeDigest)
    let sequence = try integer(receipt, "sequence")
    guard (0...2_047).contains(sequence) else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    let contentType = try string(receipt, "content_type")
    guard ["video/mp4", "video/quicktime"].contains(contentType) else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    _ = try identifier(receipt, "credential_id")
    _ = try digest(receipt, "intent_digest")
    let sidecarDigest = try digest(receipt, "sidecar_digest")
    let runtimeValue = try required(receipt, "runtime_receipt")
    let runtime = try validateRuntimeReceipt(runtimeValue)
    try equalString(runtime, "segment_id", try string(receipt, "segment_id"))
    try equalString(receipt, "transport_digest", try string(runtime, "content_digest"))
    return CompletionSegmentReceipt(
      uploadID: try identifier(receipt, "upload_id"),
      segmentID: try identifier(receipt, "segment_id"),
      sequence: sequence,
      contentType: contentType,
      sidecarDigest: sidecarDigest,
      receiptDigest: try digest(receipt, "segment_receipt_digest"),
      runtimeReceipt: runtimeValue,
      runtimeReceivedAt: try timestamp(runtime, "received_at")
    )
  }

  private static func validateRuntimeReceipt(_ value: TacuaJSONValue) throws
    -> [String: TacuaJSONValue]
  {
    let receipt = try exactObject(value, keys: [
      "segment_id", "object_id", "size_bytes", "content_digest", "received_at",
      "receipt_digest",
    ])
    try validateArtifactDigest(value, field: "receipt_digest")
    _ = try identifier(receipt, "segment_id")
    _ = try identifier(receipt, "object_id")
    _ = try boundedPositiveInteger(receipt, "size_bytes", maximum: maximumUploadBytes)
    _ = try digest(receipt, "content_digest")
    _ = try timestamp(receipt, "received_at")
    return receipt
  }

  private static func validateCompletionDiagnosticReceipt(
    _ value: TacuaJSONValue,
    sessionID: String,
    scopeDigest: String
  ) throws -> CompletionDiagnosticReceipt {
    let receipt = try exactObject(value, keys: [
      "protocol_version", "message_type", "receipt_id", "upload_id", "request_digest",
      "session_id", "scope_digest", "credential_id", "object_id", "size_bytes",
      "transport_digest", "envelope_id", "envelope_digest", "received_at",
      "diagnostic_receipt_digest",
    ])
    try responsePreamble(receipt, message: "diagnostic_upload_receipt")
    try validateArtifactDigest(value, field: "diagnostic_receipt_digest")
    try equalString(receipt, "session_id", sessionID)
    try equalString(receipt, "scope_digest", scopeDigest)
    _ = try identifier(receipt, "credential_id")
    _ = try identifier(receipt, "envelope_id")
    _ = try digest(receipt, "request_digest")
    _ = try digest(receipt, "transport_digest")
    _ = try boundedPositiveInteger(receipt, "size_bytes", maximum: maximumUploadBytes)
    return CompletionDiagnosticReceipt(
      uploadID: try identifier(receipt, "upload_id"),
      receiptID: try identifier(receipt, "receipt_id"),
      objectID: try identifier(receipt, "object_id"),
      receiptDigest: try digest(receipt, "diagnostic_receipt_digest"),
      envelopeDigest: try digest(receipt, "envelope_digest"),
      receivedAt: try timestamp(receipt, "received_at")
    )
  }

  private static func validateQueuedProcessingJob(_ value: TacuaJSONValue) throws
    -> [String: TacuaJSONValue]
  {
    let job = try exactObject(value, keys: [
      "contract_version", "media_type", "job_id", "job_version", "organization_id",
      "project_id", "session_id", "build_id", "build_identity_digest", "status",
      "requested_at", "started_at", "completed_at", "inputs", "execution", "pipeline",
      "outputs", "failure", "previous_job_digest", "job_digest",
    ])
    try constant(job, "contract_version", "tacua.processing-job@1.0.0")
    try constant(
      job, "media_type", "application/vnd.tacua.processing-job+json;version=1.0.0"
    )
    try constant(job, "status", "queued")
    _ = try identifier(job, "job_id")
    _ = try identifier(job, "organization_id")
    _ = try identifier(job, "project_id")
    _ = try identifier(job, "build_id")
    _ = try identifier(job, "session_id")
    _ = try digest(job, "build_identity_digest")
    guard try integer(job, "job_version") >= 1 else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    _ = try timestamp(job, "requested_at")
    switch try required(job, "previous_job_digest") {
    case .null: break
    case .string: _ = try digest(job, "previous_job_digest")
    default: throw TacuaJSONError.wrongType
    }
    for field in ["started_at", "completed_at", "outputs", "failure"] {
      guard try required(job, field) == .null else {
        throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
      }
    }
    _ = try exactObject(try required(job, "inputs"), keys: [
      "capture_manifest_digest", "diagnostic_envelope_digests", "context_sources",
    ])
    try validateArtifactDigest(value, field: "job_digest")
    return job
  }

  private static func receiptDigests(_ value: TacuaJSONValue, field: String) throws -> [String] {
    guard case .array(let values) = value else { throw TacuaJSONError.wrongType }
    var result: [String] = []
    for value in values {
      try validateArtifactDigest(value, field: field)
      let item = try object(value)
      if field == "segment_receipt_digest" {
        let runtimeReceipt = try required(item, "runtime_receipt")
        try validateArtifactDigest(runtimeReceipt, field: "receipt_digest")
      }
      result.append(try digest(item, field))
    }
    guard Set(result).count == result.count else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    return result
  }

  private static func envelopeDigests(_ value: TacuaJSONValue) throws -> [String] {
    guard case .array(let values) = value else { throw TacuaJSONError.wrongType }
    return try values.map { value in
      let item = try object(value)
      return try digest(item, "envelope_digest")
    }
  }

  private static func requestPreamble(
    _ object: [String: TacuaJSONValue], message: String
  ) throws {
    try constant(object, "protocol_version", version)
    try constant(object, "message_type", message)
    _ = try identifier(object, "session_id")
    _ = try digest(object, "scope_digest")
    _ = try identifier(object, "credential_id")
  }

  private static func responsePreamble(
    _ object: [String: TacuaJSONValue], message: String
  ) throws {
    try constant(object, "protocol_version", version)
    try constant(object, "message_type", message)
  }

  private static func validateArtifactDigest(_ value: TacuaJSONValue, field: String) throws {
    let object = try object(value)
    let claimed = try digest(object, field)
    let computed = try TacuaCanonicalJSON.digest(value, omittingRootField: field)
    guard claimed == computed else {
      throw TacuaSDKBackendProtocolError.digestMismatch(field)
    }
  }

  private static func exactObject(
    _ value: TacuaJSONValue, keys: Set<String>
  ) throws -> [String: TacuaJSONValue] {
    try value.requiringObject(keys: keys)
  }

  private static func object(_ value: TacuaJSONValue) throws -> [String: TacuaJSONValue] {
    guard case .object(let object) = value else { throw TacuaJSONError.wrongType }
    return object
  }

  private static func required(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> TacuaJSONValue {
    guard let value = object[field] else { throw TacuaJSONError.missingField(field) }
    return value
  }

  private static func string(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> String {
    guard case .string(let value) = try required(object, field) else {
      throw TacuaJSONError.wrongType
    }
    return value
  }

  private static func nullableString(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> String? {
    switch try required(object, field) {
    case .null: return nil
    case .string(let value): return value
    default: throw TacuaJSONError.wrongType
    }
  }

  private static func integer(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> Int64 {
    guard case .integer(let value) = try required(object, field) else {
      throw TacuaJSONError.wrongType
    }
    return value
  }

  private static func bool(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> Bool {
    guard case .bool(let value) = try required(object, field) else {
      throw TacuaJSONError.wrongType
    }
    return value
  }

  private static func array(_ value: TacuaJSONValue) throws -> [TacuaJSONValue] {
    guard case .array(let values) = value else { throw TacuaJSONError.wrongType }
    return values
  }

  private static func positiveInteger(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> Int64 {
    let value = try integer(object, field)
    guard value > 0 else { throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact }
    return value
  }

  private static func boundedPositiveInteger(
    _ object: [String: TacuaJSONValue],
    _ field: String,
    maximum: Int64
  ) throws -> Int64 {
    let value = try positiveInteger(object, field)
    guard value <= maximum else {
      throw TacuaSDKBackendProtocolError.invalidRuntimeArtifact
    }
    return value
  }

  private static func stringArray(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> [String] {
    guard case .array(let values) = try required(object, field) else {
      throw TacuaJSONError.wrongType
    }
    return try values.map { value in
      guard case .string(let value) = value else { throw TacuaJSONError.wrongType }
      return value
    }
  }

  private static func identifier(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> String {
    let value = try string(object, field)
    guard value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil else {
      throw TacuaSDKBackendProtocolError.invalidIdentifier(field)
    }
    return value
  }

  private static func digest(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> String {
    let value = try string(object, field)
    guard value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil else {
      throw TacuaSDKBackendProtocolError.invalidDigest(field)
    }
    return value
  }

  private static func constant(
    _ object: [String: TacuaJSONValue], _ field: String, _ expected: String
  ) throws {
    guard try string(object, field) == expected else {
      throw TacuaSDKBackendProtocolError.invalidConstant(field)
    }
  }

  private static func equalString(
    _ object: [String: TacuaJSONValue], _ field: String, _ expected: String
  ) throws {
    guard try string(object, field) == expected else {
      throw TacuaSDKBackendProtocolError.bindingMismatch(field)
    }
  }

  private static func timestamp(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> Date {
    let value = try string(object, field)
    guard let date = parseTimestamp(value) else {
      throw TacuaSDKBackendProtocolError.invalidTimestamp(field)
    }
    return date
  }

  private static func parseTimestamp(_ value: String) -> Date? {
    guard value.range(
      of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
      options: .regularExpression
    ) != nil else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: value)
  }
}
