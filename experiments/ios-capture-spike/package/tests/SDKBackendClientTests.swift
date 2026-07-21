// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum ClientTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw ClientTestFailure.assertion(message) }
}

private final class TestCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  func store(secret: Data, credentialID: String) throws { values[credentialID] = secret }
  func read(credentialID: String) throws -> Data {
    guard let value = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return value
  }
  func remove(credentialID: String) throws { values.removeValue(forKey: credentialID) }
}

private struct MockResponse {
  let status: Int
  let headers: [String: String]
  let data: Data
}

private final class MockURLProtocol: URLProtocol {
  private static let lock = NSLock()
  private static var responseHandler: ((URLRequest) -> MockResponse)?
  private static var observedRequests: [URLRequest] = []
  private static var observedBodies: [Data?] = []

  static func install(_ handler: @escaping (URLRequest) -> MockResponse) {
    lock.lock()
    responseHandler = handler
    observedRequests = []
    observedBodies = []
    lock.unlock()
  }

  static func requests() -> [URLRequest] {
    lock.lock()
    defer { lock.unlock() }
    return observedRequests
  }

  static func bodies() -> [Data?] {
    lock.lock()
    defer { lock.unlock() }
    return observedBodies
  }

  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    let body = Self.readBody(request)
    Self.lock.lock()
    Self.observedRequests.append(request)
    Self.observedBodies.append(body)
    let handler = Self.responseHandler
    Self.lock.unlock()
    guard let handler, let url = request.url else {
      client?.urlProtocol(self, didFailWithError: ClientTestFailure.assertion("Missing handler"))
      return
    }
    let response = handler(request)
    let http = HTTPURLResponse(
      url: url,
      statusCode: response.status,
      httpVersion: "HTTP/1.1",
      headerFields: response.headers
    )!
    client?.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: response.data)
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {}

  private static func readBody(_ request: URLRequest) -> Data? {
    if let body = request.httpBody { return body }
    guard let stream = request.httpBodyStream else { return nil }
    stream.open()
    defer { stream.close() }
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
    while stream.hasBytesAvailable {
      let count = stream.read(&buffer, maxLength: buffer.count)
      if count <= 0 { break }
      result.append(buffer, count: count)
    }
    return result
  }
}

@main
enum SDKBackendClientTests {
  static func main() async throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try requestBuildersMatchNormativeFixtures(fixtureRoot)
    try await launchIsTransientAndUnauthenticated(fixtureRoot)
    try await rotatedCredentialAuthenticatesExactHistoricalRequest(fixtureRoot)
    try await segmentUsesStreamingUploadAndExactHeaders(fixtureRoot)
    try await completionAndDeletionUseExactRoutes(fixtureRoot)
    try await redirectsAreRejectedWithoutForwardingAuthorization(fixtureRoot)
    try await responseBoundsAndContentTypeFailClosed(fixtureRoot)
    print("Tacua SDK backend client tests passed")
  }

  private static func requestBuildersMatchNormativeFixtures(_ root: URL) throws {
    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.tacua.example",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let build = try TacuaCanonicalJSON.parse(canonicalFixture(root, "build-identity"))
    let scope = try TacuaCanonicalJSON.parse(canonicalFixture(root, "capture-scope"))
    let encodedSecret = String(repeating: "S", count: 43) + "="
    let secret = try requireValue(Data(base64Encoded: encodedSecret), "Invalid fixture secret")
    let launch = try TacuaSDKBackendRequests.launch(
      preparedCredential: TacuaPreparedCredential(
        exchangeID: "exchange_synthetic",
        credentialID: "credential_synthetic",
        secret: secret
      ),
      launchCode: String(repeating: "L", count: 43),
      exchangeKind: "start_session",
      expectedSessionID: nil,
      expectedSessionState: "receiving",
      expectedCompletionID: nil,
      previousCredentialID: nil,
      buildIdentity: build,
      scope: scope,
      requestedAt: "2026-07-21T09:57:00Z",
      configuration: configuration
    )
    let builtLaunch = try rootObject(launch.canonicalData)
    let builtLaunchValue = TacuaJSONValue.object(builtLaunch)
    let computedLaunchDigest = try TacuaCanonicalJSON.digest(
      builtLaunchValue, omittingRootField: "request_digest"
    )
    try require(
      builtLaunch["request_digest"]?.stringValue
        == computedLaunchDigest,
      "Launch builder must seal the exact transient request"
    )
    let builtIdentity = try objectValue(builtLaunch, "build_identity")
    try require(
      builtIdentity["transport_configuration_digest"]?.stringValue
        == configuration.configurationDigest,
      "Launch must bind the build-pinned transport configuration"
    )

    let segmentFixtureData = try canonicalFixture(root, "segment-upload-intent")
    let segmentFixture = try rootObject(segmentFixtureData)
    let segmentTransport = try objectValue(segmentFixture, "transport")
    let segment = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_segment_synthetic",
      sessionID: "session_synthetic",
      scopeDigest: segmentFixture["scope_digest"]!.stringValue!,
      credentialID: "credential_synthetic",
      sequence: 0,
      segmentID: "segment_synthetic",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: segmentTransport["size_bytes"]!.integerValue!,
        contentDigest: segmentTransport["content_digest"]!.stringValue!,
        sidecarDigest: segmentFixture["sidecar_digest"]!.stringValue!
      ),
      requestedAt: "2026-07-21T10:01:59Z"
    )
    try require(segment.canonicalData == segmentFixtureData, "Segment builder must reproduce the normative intent")

    let diagnosticFixtureData = try canonicalFixture(root, "diagnostic-upload-request")
    let diagnosticFixture = try rootObject(diagnosticFixtureData)
    let diagnostic = try TacuaSDKBackendRequests.diagnostic(
      uploadID: "upload_diagnostic_synthetic",
      sessionID: "session_synthetic",
      scopeDigest: diagnosticFixture["scope_digest"]!.stringValue!,
      credentialID: "credential_receiving_resume",
      envelope: diagnosticFixture["envelope"]!,
      requestedAt: "2026-07-21T10:02:03Z"
    )
    try require(diagnostic.canonicalData == diagnosticFixtureData, "Diagnostic builder must reproduce the normative request")

    let completionFixtureData = try canonicalFixture(root, "completion-request")
    let completionFixture = try rootObject(completionFixtureData)
    let completion = try TacuaSDKBackendRequests.completion(
      completionID: "completion_synthetic",
      sessionID: "session_synthetic",
      scopeDigest: completionFixture["scope_digest"]!.stringValue!,
      credentialID: "credential_receiving_resume",
      captureManifest: completionFixture["capture_manifest"]!,
      segmentReceipts: try arrayValue(completionFixture, "segment_receipts"),
      diagnosticReceipts: try arrayValue(completionFixture, "diagnostic_receipts"),
      requestedAt: "2026-07-21T10:02:05Z"
    )
    try require(completion.canonicalData == completionFixtureData, "Completion builder must reproduce the normative request")

    let deletionFixtureData = try canonicalFixture(root, "deletion-request")
    let deletionFixture = try rootObject(deletionFixtureData)
    let deletion = try TacuaSDKBackendRequests.deletion(
      deletionID: "deletion_synthetic",
      sessionID: "session_synthetic",
      scopeDigest: deletionFixture["scope_digest"]!.stringValue!,
      credentialID: "credential_receiving_resume",
      reason: "user_requested",
      requestedAt: "2026-07-21T10:03:00Z"
    )
    try require(deletion.canonicalData == deletionFixtureData, "Deletion builder must reproduce the normative request")
  }

  private static func canonicalFixture(_ root: URL, _ name: String) throws -> Data {
    let data = try Data(contentsOf: root.appendingPathComponent("\(name).json"))
    return try TacuaCanonicalJSON.data(try TacuaCanonicalJSON.parse(data))
  }

  private static func makeClient(
    credentials: TestCredentialStore,
    maximumResponseBytes: Int = TacuaSDKBackendProtocol.maximumResponseBytes
  ) throws -> TacuaSDKBackendClient {
    let sessionConfiguration = TacuaBoundedURLSessionTransport.secureConfiguration()
    sessionConfiguration.protocolClasses = [MockURLProtocol.self]
    let transport = TacuaBoundedURLSessionTransport(
      configuration: sessionConfiguration,
      maximumResponseBytes: maximumResponseBytes
    )
    return TacuaSDKBackendClient(
      configuration: try TacuaBackendConfiguration(
        buildConfiguredOrigin: "https://qa.tacua.example",
        allowInsecureLoopback: false,
        debugBuild: false
      ),
      credentialStore: credentials,
      transport: transport
    )
  }

  private static func launchIsTransientAndUnauthenticated(_ root: URL) async throws {
    let requestData = try canonicalFixture(root, "launch-exchange-request")
    let responseData = try canonicalFixture(root, "launch-exchange-receipt")
    MockURLProtocol.install { _ in
      MockResponse(status: 201, headers: ["Content-Type": "application/json"], data: responseData)
    }
    let client = try makeClient(credentials: TestCredentialStore())
    let receipt = try await client.exchange(
      TacuaTransientLaunchRequest(
        exchangeID: "exchange_synthetic",
        credentialID: "credential_synthetic",
        canonicalData: requestData,
        requestDigest: "sha256:e142146903a8d73fb073ebef50904eeab1a9daf5ebb895545bf3000725a057df"
      )
    )
    try require(receipt.operationKind == .launch, "Launch response must validate")
    let request = try requireOneRequest()
    try require(request.httpMethod == "POST", "Launch must use POST")
    try require(request.url?.path == "/v1/sdk/launch-exchanges", "Launch route must be pinned")
    try require(request.value(forHTTPHeaderField: "Authorization") == nil, "Launch must not send Authorization")
    try require(
      MockURLProtocol.bodies().first! == requestData,
      "Launch code and new secret must remain in the transient body"
    )
  }

  private static func rotatedCredentialAuthenticatesExactHistoricalRequest(_ root: URL) async throws {
    let requestData = try canonicalFixture(root, "diagnostic-upload-request")
    let responseData = try canonicalFixture(root, "diagnostic-upload-receipt")
    MockURLProtocol.install { _ in
      MockResponse(status: 200, headers: ["Content-Type": "application/json; charset=utf-8"], data: responseData)
    }
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x41, count: 32)
    let client = try makeClient(credentials: credentials)
    let receipt = try await client.send(
      TacuaPreparedBackendRequest(
        kind: .diagnostic,
        operationID: "upload_diagnostic_synthetic",
        credentialID: "credential_receiving_resume",
        canonicalData: requestData,
        requestDigest: "sha256:8262c9a2865a735afe517349c57a40bc1b8135e785d0e1db1b3bd9056cc93d68"
      ),
      transportCredentialID: "credential_current"
    )
    try require(receipt.operationKind == .diagnostic, "Historical diagnostic receipt must validate")
    let request = try requireOneRequest()
    try require(request.url?.path == "/v1/sdk/sessions/session_synthetic/diagnostics/upload_diagnostic_synthetic", "Diagnostic route must be exact")
    try require(request.value(forHTTPHeaderField: "Authorization") == "Bearer QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE", "Current Keychain credential must authenticate")
    let sentBody = MockURLProtocol.bodies().first!
    try require(sentBody == requestData, "Historical canonical body must stay byte-identical")
    let body = try TacuaCanonicalJSON.parse(sentBody!)
    try require(body.objectValue?["credential_id"]?.stringValue == "credential_receiving_resume", "Rotation must not rewrite request credential_id")
  }

  private static func segmentUsesStreamingUploadAndExactHeaders(_ root: URL) async throws {
    let payload = Data("segment-payload".utf8)
    let payloadDigest = TacuaCanonicalJSON.digest(data: payload)
    let sidecarDigest = "sha256:" + String(repeating: "4", count: 64)
    let prepared = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_streaming",
      sessionID: "session_synthetic",
      scopeDigest: "sha256:112e576cdc6e5baac76cd40b0b2f49182e573039e7107a1eaf0605ff99f67f50",
      credentialID: "credential_historical",
      sequence: 7,
      segmentID: "segment_streaming",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: Int64(payload.count),
        contentDigest: payloadDigest,
        sidecarDigest: sidecarDigest
      ),
      requestedAt: "2026-07-21T10:01:59Z"
    )
    let responseData = try segmentResponse(for: prepared, fixtureRoot: root)
    MockURLProtocol.install { _ in
      MockResponse(status: 201, headers: ["Content-Type": "application/json"], data: responseData)
    }
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x42, count: 32)
    let client = try makeClient(credentials: credentials)
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-client-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("segment.mov")
    try payload.write(to: file, options: .atomic)
    let receipt = try await client.uploadSegment(
      prepared,
      fileURL: file,
      transportCredentialID: "credential_current"
    )
    try require(receipt.operationKind == .segment, "Segment response must validate")
    let request = try requireOneRequest()
    try require(request.httpMethod == "PUT", "Segment must use PUT upload task")
    try require(request.url?.path == "/v1/sdk/sessions/session_synthetic/segments/7/segment_streaming", "Segment route must bind sequence and ID")
    try require(request.value(forHTTPHeaderField: "Tacua-Credential-ID") == "credential_historical", "Header must retain immutable request credential")
    try require(request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer QkJC") == true, "Current credential must authenticate upload")
    try require(request.value(forHTTPHeaderField: "Tacua-Content-Digest") == payloadDigest, "Private content digest header must be exact")
    try require(request.value(forHTTPHeaderField: "Tacua-Sidecar-Digest") == sidecarDigest, "Sidecar digest must be transmitted")
  }

  private static func redirectsAreRejectedWithoutForwardingAuthorization(_ root: URL) async throws {
    let requestData = try canonicalFixture(root, "diagnostic-upload-request")
    MockURLProtocol.install { request in
      if request.url?.host == "qa.tacua.example" {
        return MockResponse(
          status: 302,
          headers: ["Location": "https://evil.example/steal", "Content-Type": "application/json"],
          data: Data()
        )
      }
      return MockResponse(status: 500, headers: ["Content-Type": "application/json"], data: Data())
    }
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x43, count: 32)
    let client = try makeClient(credentials: credentials)
    do {
      _ = try await client.send(
        TacuaPreparedBackendRequest(
          kind: .diagnostic,
          operationID: "upload_diagnostic_synthetic",
          credentialID: "credential_receiving_resume",
          canonicalData: requestData,
          requestDigest: "sha256:8262c9a2865a735afe517349c57a40bc1b8135e785d0e1db1b3bd9056cc93d68"
        ),
        transportCredentialID: "credential_current"
      )
      throw ClientTestFailure.assertion("Redirect must fail closed")
    } catch let error as TacuaSDKBackendClientError {
      try require(error == .unexpectedStatus(302), "Rejected redirect must surface original 302")
    }
    let requests = MockURLProtocol.requests()
    try require(requests.count == 1, "Redirect target must never receive a second request")
    try require(requests[0].url?.host == "qa.tacua.example", "Only pinned origin may receive Authorization")
  }

  private static func completionAndDeletionUseExactRoutes(_ root: URL) async throws {
    let credentials = TestCredentialStore()
    credentials.values["credential_receiving_resume"] = Data(repeating: 0x45, count: 32)

    let completionRequest = try canonicalFixture(root, "completion-request")
    let completionResponse = try canonicalFixture(root, "completion-receipt")
    MockURLProtocol.install { _ in
      MockResponse(status: 201, headers: ["Content-Type": "application/json"], data: completionResponse)
    }
    var client = try makeClient(credentials: credentials)
    _ = try await client.send(
      TacuaPreparedBackendRequest(
        kind: .completion,
        operationID: "completion_synthetic",
        credentialID: "credential_receiving_resume",
        canonicalData: completionRequest,
        requestDigest: "sha256:d5b45fc406ddc15489034b25ac8fcb0cc00f46bb1affed59774c281a844f1a8d"
      ),
      transportCredentialID: "credential_receiving_resume"
    )
    var observed = try requireOneRequest()
    try require(observed.httpMethod == "PUT", "Completion must use PUT")
    try require(observed.url?.path == "/v1/sdk/sessions/session_synthetic/completions/completion_synthetic", "Completion route must be exact")

    let deletionRequest = try canonicalFixture(root, "deletion-request")
    let deletionResponse = try canonicalFixture(root, "deletion-tombstone")
    MockURLProtocol.install { _ in
      MockResponse(status: 200, headers: ["Content-Type": "application/json"], data: deletionResponse)
    }
    client = try makeClient(credentials: credentials)
    _ = try await client.send(
      TacuaPreparedBackendRequest(
        kind: .deletion,
        operationID: "deletion_synthetic",
        credentialID: "credential_receiving_resume",
        canonicalData: deletionRequest,
        requestDigest: "sha256:896326b56812e6c1dbd8a776415901a57b47ee43706b89615b4f08c39bdf06a5"
      ),
      transportCredentialID: "credential_receiving_resume"
    )
    observed = try requireOneRequest()
    try require(observed.httpMethod == "PUT", "Deletion must use PUT")
    try require(observed.url?.path == "/v1/sdk/sessions/session_synthetic/deletions/deletion_synthetic", "Deletion route must be exact")
  }

  private static func responseBoundsAndContentTypeFailClosed(_ root: URL) async throws {
    let requestData = try canonicalFixture(root, "diagnostic-upload-request")
    let responseData = try canonicalFixture(root, "diagnostic-upload-receipt")
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x44, count: 32)
    MockURLProtocol.install { _ in
      MockResponse(status: 200, headers: ["Content-Type": "text/plain"], data: responseData)
    }
    var client = try makeClient(credentials: credentials)
    do {
      _ = try await client.send(diagnosticPrepared(requestData), transportCredentialID: "credential_current")
      throw ClientTestFailure.assertion("Non-JSON response must fail")
    } catch let error as TacuaSDKBackendClientError {
      try require(error == .unexpectedContentType, "MIME type must be strict")
    }

    MockURLProtocol.install { _ in
      MockResponse(
        status: 200,
        headers: ["Content-Type": "application/json", "Content-Length": String(responseData.count)],
        data: responseData
      )
    }
    client = try makeClient(credentials: credentials, maximumResponseBytes: 32)
    do {
      _ = try await client.send(diagnosticPrepared(requestData), transportCredentialID: "credential_current")
      throw ClientTestFailure.assertion("Oversized response must fail")
    } catch let error as TacuaSDKBackendClientError {
      try require(error == .responseTooLarge, "Bounded transport must cancel oversized responses")
    }
  }

  private static func diagnosticPrepared(_ data: Data) -> TacuaPreparedBackendRequest {
    TacuaPreparedBackendRequest(
      kind: .diagnostic,
      operationID: "upload_diagnostic_synthetic",
      credentialID: "credential_receiving_resume",
      canonicalData: data,
      requestDigest: "sha256:8262c9a2865a735afe517349c57a40bc1b8135e785d0e1db1b3bd9056cc93d68"
    )
  }

  private static func segmentResponse(
    for request: TacuaPreparedBackendRequest,
    fixtureRoot: URL
  ) throws -> Data {
    guard case .object(let intent) = try TacuaCanonicalJSON.parse(request.canonicalData),
      case .object(let transport)? = intent["transport"],
      case .object(var response) = try TacuaCanonicalJSON.parse(
        try canonicalFixture(fixtureRoot, "segment-upload-receipt")
      ),
      case .object(var runtime)? = response["runtime_receipt"]
    else { throw ClientTestFailure.assertion("Invalid segment fixture") }
    for field in ["upload_id", "session_id", "scope_digest", "credential_id", "sequence", "segment_id", "sidecar_digest"] {
      response[field] = intent[field]
    }
    response["intent_digest"] = intent["intent_digest"]
    response["content_type"] = transport["content_type"]
    response["transport_digest"] = transport["content_digest"]
    runtime["segment_id"] = intent["segment_id"]
    runtime["size_bytes"] = transport["size_bytes"]
    runtime["content_digest"] = transport["content_digest"]
    runtime["received_at"] = .string("2026-07-21T10:02:00Z")
    runtime["receipt_digest"] = .string(try TacuaCanonicalJSON.digest(
      .object(runtime), omittingRootField: "receipt_digest"
    ))
    response["runtime_receipt"] = .object(runtime)
    response["segment_receipt_digest"] = .string(try TacuaCanonicalJSON.digest(
      .object(response), omittingRootField: "segment_receipt_digest"
    ))
    return try TacuaCanonicalJSON.data(.object(response))
  }

  private static func requireOneRequest() throws -> URLRequest {
    let requests = MockURLProtocol.requests()
    try require(requests.count == 1, "Expected one network request, received \(requests.count)")
    return requests[0]
  }

  private static func rootObject(_ data: Data) throws -> [String: TacuaJSONValue] {
    guard case .object(let object) = try TacuaCanonicalJSON.parse(data) else {
      throw ClientTestFailure.assertion("Expected object")
    }
    return object
  }

  private static func objectValue(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> [String: TacuaJSONValue] {
    guard case .object(let value)? = object[field] else {
      throw ClientTestFailure.assertion("Expected object field \(field)")
    }
    return value
  }

  private static func arrayValue(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> [TacuaJSONValue] {
    guard case .array(let value)? = object[field] else {
      throw ClientTestFailure.assertion("Expected array field \(field)")
    }
    return value
  }

  private static func requireValue<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw ClientTestFailure.assertion(message) }
    return value
  }
}
