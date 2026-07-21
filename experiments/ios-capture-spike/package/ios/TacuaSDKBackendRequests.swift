// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaSDKBackendRequestError: Error, Equatable {
  case invalidIdentifier
  case invalidDigest
  case invalidTimestamp
  case invalidLaunchCode
  case invalidArtifact
  case transportConfigurationMismatch
  case invalidExchangeState
}

struct TacuaTransientLaunchRequest: Equatable {
  let exchangeID: String
  let credentialID: String
  let canonicalData: Data
  let requestDigest: String
}

struct TacuaPreparedBackendRequest: Equatable {
  let kind: TacuaQueuedOperationKind
  let operationID: String
  let credentialID: String
  let canonicalData: Data
  let requestDigest: String
}

struct TacuaSegmentTransportMetadata: Equatable {
  let contentType: String
  let sizeBytes: Int64
  let contentDigest: String
  let sidecarDigest: String
}

enum TacuaSDKBackendRequests {
  static func launch(
    preparedCredential: TacuaPreparedCredential,
    approvedLaunchID: String,
    consentGate: TacuaLaunchConsentGate,
    exchangeKind: String,
    expectedSessionID: String?,
    expectedSessionState: String,
    expectedCompletionID: String?,
    previousCredentialID: String?,
    buildIdentity: TacuaJSONValue,
    scope: TacuaJSONValue,
    requestedAt: String,
    configuration: TacuaBackendConfiguration
  ) throws -> TacuaTransientLaunchRequest {
    try consentGate.withApprovedLaunchCode(approvedLaunchID: approvedLaunchID) { launchCode in
      try launchAfterConsent(
        preparedCredential: preparedCredential,
        launchCode: launchCode,
        exchangeKind: exchangeKind,
        expectedSessionID: expectedSessionID,
        expectedSessionState: expectedSessionState,
        expectedCompletionID: expectedCompletionID,
        previousCredentialID: previousCredentialID,
        buildIdentity: buildIdentity,
        scope: scope,
        requestedAt: requestedAt,
        configuration: configuration
      )
    }
  }

  private static func launchAfterConsent(
    preparedCredential: TacuaPreparedCredential,
    launchCode: String,
    exchangeKind: String,
    expectedSessionID: String?,
    expectedSessionState: String,
    expectedCompletionID: String?,
    previousCredentialID: String?,
    buildIdentity: TacuaJSONValue,
    scope: TacuaJSONValue,
    requestedAt: String,
    configuration: TacuaBackendConfiguration
  ) throws -> TacuaTransientLaunchRequest {
    guard validIdentifier(preparedCredential.exchangeID),
      validIdentifier(preparedCredential.credentialID),
      preparedCredential.secret.count == TacuaKeychainCredentialStore.secretLength
    else { throw TacuaSDKBackendRequestError.invalidIdentifier }
    guard launchCode.range(of: "^[A-Za-z0-9_-]{32,512}$", options: .regularExpression) != nil else {
      throw TacuaSDKBackendRequestError.invalidLaunchCode
    }
    try validateTimestamp(requestedAt)
    let build = try artifact(buildIdentity, digestField: "build_identity_digest")
    guard build["transport_configuration_digest"]?.stringValue
      == configuration.configurationDigest
    else { throw TacuaSDKBackendRequestError.transportConfigurationMismatch }
    let scopeObject = try artifact(scope, digestField: "scope_digest")
    guard scopeObject["build_id"]?.stringValue == build["build_id"]?.stringValue,
      scopeObject["build_identity_digest"]?.stringValue
        == build["build_identity_digest"]?.stringValue
    else { throw TacuaSDKBackendRequestError.invalidArtifact }
    guard ["start_session", "resume_session"].contains(exchangeKind),
      ["receiving", "completed"].contains(expectedSessionState)
    else { throw TacuaSDKBackendRequestError.invalidExchangeState }
    if exchangeKind == "start_session" {
      guard expectedSessionID == nil, expectedSessionState == "receiving",
        expectedCompletionID == nil, previousCredentialID == nil
      else { throw TacuaSDKBackendRequestError.invalidExchangeState }
    } else {
      guard expectedSessionID.map(validIdentifier) == true,
        previousCredentialID.map(validIdentifier) == true,
        previousCredentialID != preparedCredential.credentialID,
        (expectedSessionState == "completed") == (expectedCompletionID != nil),
        expectedCompletionID.map(validIdentifier) ?? true
      else { throw TacuaSDKBackendRequestError.invalidExchangeState }
    }
    let secret = base64URL(preparedCredential.secret)
    guard secret.count == 43 else { throw TacuaSDKBackendRequestError.invalidArtifact }
    var object: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("launch_exchange_request"),
      "exchange_kind": .string(exchangeKind),
      "exchange_id": .string(preparedCredential.exchangeID),
      "launch_code": .string(launchCode),
      "expected_session_id": expectedSessionID.map(TacuaJSONValue.string) ?? .null,
      "expected_session_state": .string(expectedSessionState),
      "expected_completion_id": expectedCompletionID.map(TacuaJSONValue.string) ?? .null,
      "previous_credential_id": previousCredentialID.map(TacuaJSONValue.string) ?? .null,
      "credential": .object([
        "credential_id": .string(preparedCredential.credentialID),
        "secret": .string(secret),
        "authentication_scheme": .string("Bearer"),
        "local_storage": .string("ios_keychain_when_unlocked_this_device_only"),
      ]),
      "build_identity": buildIdentity,
      "scope": scope,
      "requested_at": .string(requestedAt),
    ]
    let digest = try digestAndSeal(&object, field: "request_digest")
    return TacuaTransientLaunchRequest(
      exchangeID: preparedCredential.exchangeID,
      credentialID: preparedCredential.credentialID,
      canonicalData: try TacuaCanonicalJSON.data(.object(object)),
      requestDigest: digest
    )
  }

  static func segment(
    uploadID: String,
    sessionID: String,
    scopeDigest: String,
    credentialID: String,
    sequence: Int64,
    segmentID: String,
    metadata: TacuaSegmentTransportMetadata,
    requestedAt: String
  ) throws -> TacuaPreparedBackendRequest {
    try validateCommon(
      operationID: uploadID, sessionID: sessionID, scopeDigest: scopeDigest,
      credentialID: credentialID, requestedAt: requestedAt
    )
    guard (0...2_047).contains(sequence), metadata.sizeBytes > 0,
      metadata.sizeBytes <= TacuaSDKBackendProtocol.maximumUploadBytes,
      ["video/mp4", "video/quicktime"].contains(metadata.contentType),
      validIdentifier(segmentID), validDigest(metadata.contentDigest),
      validDigest(metadata.sidecarDigest)
    else { throw TacuaSDKBackendRequestError.invalidArtifact }
    var object: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("segment_upload_intent"),
      "upload_id": .string(uploadID),
      "session_id": .string(sessionID),
      "scope_digest": .string(scopeDigest),
      "credential_id": .string(credentialID),
      "sequence": .integer(sequence),
      "segment_id": .string(segmentID),
      "transport": .object([
        "content_type": .string(metadata.contentType),
        "size_bytes": .integer(metadata.sizeBytes),
        "content_digest": .string(metadata.contentDigest),
      ]),
      "sidecar_digest": .string(metadata.sidecarDigest),
      "requested_at": .string(requestedAt),
    ]
    let digest = try digestAndSeal(&object, field: "intent_digest")
    return try prepared(.segment, uploadID, credentialID, object, digest)
  }

  static func diagnostic(
    uploadID: String,
    sessionID: String,
    scopeDigest: String,
    credentialID: String,
    envelope: TacuaJSONValue,
    requestedAt: String
  ) throws -> TacuaPreparedBackendRequest {
    try validateCommon(
      operationID: uploadID, sessionID: sessionID, scopeDigest: scopeDigest,
      credentialID: credentialID, requestedAt: requestedAt
    )
    let envelopeObject = try artifact(envelope, digestField: "envelope_digest")
    guard envelopeObject["session_id"]?.stringValue == sessionID else {
      throw TacuaSDKBackendRequestError.invalidArtifact
    }
    let envelopeData = try TacuaCanonicalJSON.data(envelope)
    var object: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("diagnostic_upload_request"),
      "upload_id": .string(uploadID),
      "session_id": .string(sessionID),
      "scope_digest": .string(scopeDigest),
      "credential_id": .string(credentialID),
      "transport": .object([
        "content_type": .string(
          "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0"
        ),
        "size_bytes": .integer(Int64(envelopeData.count)),
        "content_digest": .string(TacuaCanonicalJSON.digest(data: envelopeData)),
      ]),
      "envelope": envelope,
      "requested_at": .string(requestedAt),
    ]
    let digest = try digestAndSeal(&object, field: "request_digest")
    return try prepared(.diagnostic, uploadID, credentialID, object, digest)
  }

  static func completion(
    completionID: String,
    sessionID: String,
    scopeDigest: String,
    credentialID: String,
    captureManifest: TacuaJSONValue,
    segmentReceipts: [TacuaJSONValue],
    diagnosticReceipts: [TacuaJSONValue],
    requestedAt: String
  ) throws -> TacuaPreparedBackendRequest {
    try validateCommon(
      operationID: completionID, sessionID: sessionID, scopeDigest: scopeDigest,
      credentialID: credentialID, requestedAt: requestedAt
    )
    let manifest = try artifact(captureManifest, digestField: "manifest_digest")
    guard manifest["session_id"]?.stringValue == sessionID,
      manifest["capture_state"]?.stringValue == "complete"
    else { throw TacuaSDKBackendRequestError.invalidArtifact }
    try segmentReceipts.forEach { _ = try artifact($0, digestField: "segment_receipt_digest") }
    try diagnosticReceipts.forEach {
      _ = try artifact($0, digestField: "diagnostic_receipt_digest")
    }
    var object: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("completion_request"),
      "completion_id": .string(completionID),
      "session_id": .string(sessionID),
      "scope_digest": .string(scopeDigest),
      "credential_id": .string(credentialID),
      "capture_manifest": captureManifest,
      "segment_receipts": .array(segmentReceipts),
      "diagnostic_receipts": .array(diagnosticReceipts),
      "requested_at": .string(requestedAt),
    ]
    let digest = try digestAndSeal(&object, field: "request_digest")
    return try prepared(.completion, completionID, credentialID, object, digest)
  }

  static func deletion(
    deletionID: String,
    sessionID: String,
    scopeDigest: String,
    credentialID: String,
    reason: String,
    requestedAt: String
  ) throws -> TacuaPreparedBackendRequest {
    try validateCommon(
      operationID: deletionID, sessionID: sessionID, scopeDigest: scopeDigest,
      credentialID: credentialID, requestedAt: requestedAt
    )
    guard ["user_requested", "retention_expired", "operator_requested"].contains(reason) else {
      throw TacuaSDKBackendRequestError.invalidArtifact
    }
    var object: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("deletion_request"),
      "deletion_id": .string(deletionID),
      "session_id": .string(sessionID),
      "scope_digest": .string(scopeDigest),
      "credential_id": .string(credentialID),
      "target": .string("session_all_data"),
      "reason": .string(reason),
      "requested_at": .string(requestedAt),
    ]
    let digest = try digestAndSeal(&object, field: "request_digest")
    return try prepared(.deletion, deletionID, credentialID, object, digest)
  }

  private static func prepared(
    _ kind: TacuaQueuedOperationKind,
    _ operationID: String,
    _ credentialID: String,
    _ object: [String: TacuaJSONValue],
    _ digest: String
  ) throws -> TacuaPreparedBackendRequest {
    TacuaPreparedBackendRequest(
      kind: kind,
      operationID: operationID,
      credentialID: credentialID,
      canonicalData: try TacuaCanonicalJSON.data(.object(object)),
      requestDigest: digest
    )
  }

  private static func validateCommon(
    operationID: String,
    sessionID: String,
    scopeDigest: String,
    credentialID: String,
    requestedAt: String
  ) throws {
    guard validIdentifier(operationID), validIdentifier(sessionID),
      validIdentifier(credentialID), validDigest(scopeDigest)
    else { throw TacuaSDKBackendRequestError.invalidIdentifier }
    try validateTimestamp(requestedAt)
  }

  private static func artifact(
    _ value: TacuaJSONValue,
    digestField: String
  ) throws -> [String: TacuaJSONValue] {
    guard case .object(let object) = value,
      let claimed = object[digestField]?.stringValue,
      validDigest(claimed),
      try TacuaCanonicalJSON.digest(value, omittingRootField: digestField) == claimed
    else { throw TacuaSDKBackendRequestError.invalidArtifact }
    return object
  }

  private static func digestAndSeal(
    _ object: inout [String: TacuaJSONValue], field: String
  ) throws -> String {
    let digest = try TacuaCanonicalJSON.digest(.object(object))
    object[field] = .string(digest)
    return digest
  }

  private static func validateTimestamp(_ value: String) throws {
    guard value.range(
      of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
      options: .regularExpression
    ) != nil else { throw TacuaSDKBackendRequestError.invalidTimestamp }
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func base64URL(_ value: Data) -> String {
    value.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
