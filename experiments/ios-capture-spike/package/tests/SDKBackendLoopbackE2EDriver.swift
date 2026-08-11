// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum LoopbackE2EFailure: Error, CustomStringConvertible {
  case assertion(String)

  var description: String {
    switch self {
    case .assertion(let message): return message
    }
  }
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  guard condition() else { throw LoopbackE2EFailure.assertion(message) }
}

private final class InMemoryCredentialStore: TacuaCredentialStoring {
  private let lock = NSLock()
  private var values: [String: Data] = [:]

  func store(secret: Data, credentialID: String) throws {
    try TacuaKeychainCredentialStore.validate(credentialID: credentialID)
    guard secret.count == TacuaKeychainCredentialStore.secretLength else {
      throw TacuaCredentialStoreError.invalidSecretLength
    }
    lock.lock()
    defer { lock.unlock() }
    guard values[credentialID] == nil else {
      throw TacuaCredentialStoreError.duplicateCredential
    }
    values[credentialID] = secret
  }

  func read(credentialID: String) throws -> Data {
    try TacuaKeychainCredentialStore.validate(credentialID: credentialID)
    lock.lock()
    defer { lock.unlock() }
    guard let secret = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return secret
  }

  func remove(credentialID: String) throws {
    try TacuaKeychainCredentialStore.validate(credentialID: credentialID)
    lock.lock()
    values.removeValue(forKey: credentialID)
    lock.unlock()
  }
}

private final class RecordingTransport: TacuaBoundedHTTPTransporting {
  private let underlying: TacuaBoundedURLSessionTransport
  private let lock = NSLock()
  private var observedStatusCodes: [Int] = []

  init() {
    underlying = TacuaBoundedURLSessionTransport(
      configuration: TacuaBoundedURLSessionTransport.secureConfiguration()
    )
  }

  func data(for request: URLRequest, uploadFile: URL?) async throws
    -> (Data, HTTPURLResponse)
  {
    let (data, response) = try await underlying.data(for: request, uploadFile: uploadFile)
    lock.lock()
    observedStatusCodes.append(response.statusCode)
    lock.unlock()
    return (data, response)
  }

  func statusCodes() -> [Int] {
    lock.lock()
    defer { lock.unlock() }
    return observedStatusCodes
  }
}

@main
enum SDKBackendLoopbackE2EDriver {
  private static let requestedAt = "2026-07-21T10:00:00Z"

  static func main() async throws {
    guard CommandLine.arguments.count == 7 else {
      throw LoopbackE2EFailure.assertion(
        "usage: driver ORIGIN LAUNCH_CODE BUILD_JSON SCOPE_JSON SESSION_DIRECTORY SEGMENT_FILE"
      )
    }
    let origin = CommandLine.arguments[1]
    let launchCode = CommandLine.arguments[2]
    let buildURL = URL(fileURLWithPath: CommandLine.arguments[3])
    let scopeURL = URL(fileURLWithPath: CommandLine.arguments[4])
    let sessionDirectory = URL(
      fileURLWithPath: CommandLine.arguments[5],
      isDirectory: true
    )
    let segmentURL = URL(fileURLWithPath: CommandLine.arguments[6])

    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: origin,
      allowInsecureLoopback: true,
      debugBuild: true
    )
    let buildIdentity = try canonicalArtifact(at: buildURL)
    let scope = try canonicalArtifact(at: scopeURL)
    let credentials = InMemoryCredentialStore()
    let preparedCredential = TacuaPreparedCredential(
      exchangeID: "exchange_loopback_e2e",
      credentialID: "credential_loopback_e2e",
      secret: Data((0..<TacuaKeychainCredentialStore.secretLength).map(UInt8.init))
    )
    try credentials.store(
      secret: preparedCredential.secret,
      credentialID: preparedCredential.credentialID
    )

    let launchConfiguration = try TacuaLaunchLinkConfiguration(
      buildConfiguredScheme: "tacua-loopback-e2e"
    )
    let consentGate = TacuaLaunchConsentGate()
    let pending = try consentGate.prepare(
      rawURL: "\(launchConfiguration.scheme)://tacua/start?launch_code=\(launchCode)",
      configuration: launchConfiguration
    )
    let approvedLaunchID = try consentGate.confirm(
      consentRequestID: pending.consentRequestID,
      granted: true
    )
    let launchRequest = try TacuaSDKBackendRequests.launch(
      preparedCredential: preparedCredential,
      approvedLaunchID: approvedLaunchID,
      consentGate: consentGate,
      exchangeKind: "start_session",
      expectedSessionID: nil,
      expectedSessionState: "receiving",
      expectedCompletionID: nil,
      previousCredentialID: nil,
      buildIdentity: buildIdentity,
      scope: scope,
      requestedAt: requestedAt,
      configuration: configuration
    )

    let transport = RecordingTransport()
    let client = TacuaSDKBackendClient(
      configuration: configuration,
      credentialStore: credentials,
      transport: transport
    )
    let launchReceipt = try await client.exchange(launchRequest)
    try require(launchReceipt.operationKind == .launch, "START did not return a launch receipt")
    try require(
      launchReceipt.credentialTransition?.credentialID == preparedCredential.credentialID,
      "START receipt changed the credential binding"
    )
    try require(
      launchReceipt.credentialTransition?.capability == .active,
      "START receipt did not issue an active credential"
    )

    let payload = try Data(contentsOf: segmentURL, options: [.mappedIfSafe])
    try require(!payload.isEmpty, "segment fixture is empty")
    let contentDigest = TacuaCanonicalJSON.digest(data: payload)
    let segmentRequest = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_loopback_e2e",
      sessionID: launchReceipt.remoteSessionID,
      scopeDigest: launchReceipt.scopeDigest,
      credentialID: preparedCredential.credentialID,
      sequence: 0,
      segmentID: "segment_loopback_e2e",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: Int64(payload.count),
        contentDigest: contentDigest,
        sidecarDigest: "sha256:" + String(repeating: "4", count: 64)
      ),
      requestedAt: requestedAt
    )

    let firstReceipt = try await client.uploadSegment(
      segmentRequest,
      fileURL: segmentURL,
      sessionDirectory: sessionDirectory,
      transportCredentialID: preparedCredential.credentialID
    )
    let replayReceipt = try await client.uploadSegment(
      segmentRequest,
      fileURL: segmentURL,
      sessionDirectory: sessionDirectory,
      transportCredentialID: preparedCredential.credentialID
    )
    try require(firstReceipt.operationKind == .segment, "first upload did not return a segment receipt")
    try require(replayReceipt.operationKind == .segment, "replay did not return a segment receipt")
    try require(
      firstReceipt.canonicalResponse == replayReceipt.canonicalResponse,
      "exact replay response bytes changed"
    )
    let statusCodes = transport.statusCodes()
    try require(statusCodes == [201, 201, 200], "unexpected HTTP status sequence: \(statusCodes)")

    let summary: [String: Any] = [
      "content_digest": contentDigest,
      "receipt_bytes_equal": true,
      "response_bytes_digest": TacuaCanonicalJSON.digest(data: firstReceipt.canonicalResponse),
      "segment_receipt_digest": firstReceipt.responseDigest,
      "session_id": launchReceipt.remoteSessionID,
      "size_bytes": payload.count,
      "status_codes": statusCodes,
    ]
    let serialized = try JSONSerialization.data(
      withJSONObject: summary,
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
    FileHandle.standardOutput.write(serialized)
    FileHandle.standardOutput.write(Data([0x0A]))
  }

  private static func canonicalArtifact(at url: URL) throws -> TacuaJSONValue {
    let data = try Data(contentsOf: url)
    let value = try TacuaCanonicalJSON.parse(data)
    guard try TacuaCanonicalJSON.data(value) == data else {
      throw LoopbackE2EFailure.assertion("input artifact is not canonical JSON")
    }
    return value
  }
}
