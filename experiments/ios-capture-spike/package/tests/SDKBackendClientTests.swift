// SPDX-License-Identifier: Apache-2.0

import Foundation
import Darwin

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
  private static var responseDelayMilliseconds = 0
  private static var stopLoadingCount = 0
  private let lifecycleLock = NSLock()
  private var stopped = false

  static func install(
    responseDelayMilliseconds: Int = 0,
    _ handler: @escaping (URLRequest) -> MockResponse
  ) {
    lock.lock()
    responseHandler = handler
    observedRequests = []
    observedBodies = []
    self.responseDelayMilliseconds = responseDelayMilliseconds
    stopLoadingCount = 0
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

  static func observedStopLoadingCount() -> Int {
    lock.lock()
    defer { lock.unlock() }
    return stopLoadingCount
  }

  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    let body = Self.readBody(request)
    Self.lock.lock()
    Self.observedRequests.append(request)
    Self.observedBodies.append(body)
    let handler = Self.responseHandler
    let delay = Self.responseDelayMilliseconds
    Self.lock.unlock()
    guard let handler, let url = request.url else {
      client?.urlProtocol(self, didFailWithError: ClientTestFailure.assertion("Missing handler"))
      return
    }
    let response = handler(request)
    if delay > 0 {
      DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay)) {
        [weak self] in
        self?.deliver(response, url: url)
      }
      return
    }
    deliver(response, url: url)
  }

  override func stopLoading() {
    lifecycleLock.lock()
    stopped = true
    lifecycleLock.unlock()
    Self.lock.lock()
    Self.stopLoadingCount += 1
    Self.lock.unlock()
  }

  private func deliver(_ response: MockResponse, url: URL) {
    lifecycleLock.lock()
    let shouldDeliver = !stopped
    lifecycleLock.unlock()
    guard shouldDeliver else { return }
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
    try transportConfigurationIsExplicitlyProcessBound()
    try await transportTaskCancellationIsBoundedAndCancelsURLSession()
    try requestBuildersMatchNormativeFixtures(fixtureRoot)
    try await launchIsTransientAndUnauthenticated(fixtureRoot)
    try await rotatedCredentialAuthenticatesExactHistoricalRequest(fixtureRoot)
    try await segmentUsesStreamingUploadAndExactHeaders(fixtureRoot)
    try await completionAndDeletionUseExactRoutes(fixtureRoot)
    try await redirectsAreRejectedWithoutForwardingAuthorization(fixtureRoot)
    try await responseBoundsAndContentTypeFailClosed(fixtureRoot)
    try await structuredErrorsSurfaceOnlyAfterExactValidation(fixtureRoot)
    try await resealedInvalidRequestsNeverReachTransport(fixtureRoot)
    try await uploadStagingScavengerIsBoundedAndFailClosed(fixtureRoot)
    try await unsafeSegmentSourcesNeverReachTransport(fixtureRoot)
    print("Tacua SDK backend client tests passed")
  }

  private static func transportConfigurationIsExplicitlyProcessBound() throws {
    let configuration = TacuaBoundedURLSessionTransport.secureConfiguration()
    try require(
      configuration.identifier == nil,
      "V1 transport must remain process-bound; a background session changes redirect semantics"
    )
    try require(
      configuration.requestCachePolicy == .reloadIgnoringLocalCacheData
        && configuration.urlCache == nil,
      "Transport must not persist backend responses in URL loading caches"
    )
    try require(
      configuration.httpCookieStorage == nil
        && !configuration.httpShouldSetCookies
        && configuration.httpCookieAcceptPolicy == .never,
      "Transport must not persist or accept ambient cookies"
    )
    try require(
      configuration.timeoutIntervalForRequest == 60
        && configuration.timeoutIntervalForResource == 30 * 60,
      "Transport time bounds changed without updating the V1 execution contract"
    )
  }

  private static func transportTaskCancellationIsBoundedAndCancelsURLSession() async throws {
    let configuration = TacuaBoundedURLSessionTransport.secureConfiguration()
    configuration.protocolClasses = [MockURLProtocol.self]
    let transport = TacuaBoundedURLSessionTransport(configuration: configuration)
    MockURLProtocol.install(responseDelayMilliseconds: 1_000) { request in
      MockResponse(
        status: 200,
        headers: ["Content-Type": "application/json"],
        data: Data("{}".utf8)
      )
    }
    let request = URLRequest(url: URL(string: "https://qa.tacua.example/cancel")!)
    let registered = Task { try await transport.data(for: request, uploadFile: nil) }
    for _ in 0..<500 where MockURLProtocol.requests().isEmpty {
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    try require(!MockURLProtocol.requests().isEmpty, "Cancellation test never registered a task")
    let cancellationStartedAt = Date()
    registered.cancel()
    do {
      _ = try await registered.value
      throw ClientTestFailure.assertion("Cancelled URLSession transport returned success")
    } catch ClientTestFailure.assertion {
      throw ClientTestFailure.assertion("Cancelled URLSession transport returned success")
    } catch {}
    try require(
      Date().timeIntervalSince(cancellationStartedAt) < 0.5,
      "Task cancellation waited for the delayed URLProtocol response"
    )
    try require(
      MockURLProtocol.observedStopLoadingCount() >= 1,
      "Task cancellation did not reach the concrete URLSession task"
    )

    // Repeated immediate cancellation exercises the before/during-registration race. Every
    // checked continuation must finish exactly once even when cancellation wins first.
    MockURLProtocol.install(responseDelayMilliseconds: 1_000) { request in
      MockResponse(
        status: 200,
        headers: ["Content-Type": "application/json"],
        data: Data("{}".utf8)
      )
    }
    let immediate = (0..<32).map { index in
      Task {
        try await transport.data(
          for: URLRequest(
            url: URL(string: "https://qa.tacua.example/cancel/\(index)")!
          ),
          uploadFile: nil
        )
      }
    }
    immediate.forEach { $0.cancel() }
    for task in immediate {
      do { _ = try await task.value }
      catch {}
    }
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
    let consentGate = TacuaLaunchConsentGate()
    let pendingLaunch = try consentGate.prepare(
      rawURL: "configured-target-scheme://tacua/start?launch_code="
        + String(repeating: "L", count: 43),
      configuration: try TacuaLaunchLinkConfiguration(
        buildConfiguredScheme: "configured-target-scheme"
      )
    )
    let approvedLaunchID = try consentGate.confirm(
      consentRequestID: pendingLaunch.consentRequestID,
      granted: true
    )
    let launch = try TacuaSDKBackendRequests.launch(
      preparedCredential: TacuaPreparedCredential(
        exchangeID: "exchange_synthetic",
        credentialID: "credential_synthetic",
        secret: secret
      ),
      approvedLaunchID: approvedLaunchID,
      consentGate: consentGate,
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
      sessionDirectory: directory,
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
    try require(
      MockURLProtocol.bodies().first! == payload,
      "Upload transport must read the immutable private snapshot"
    )
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

  private static func structuredErrorsSurfaceOnlyAfterExactValidation(_ root: URL) async throws {
    let requestData = try canonicalFixture(root, "diagnostic-upload-request")
    let authenticatedCredentialID = "credential_current"
    let errorData = try historicalMissError(
      for: requestData,
      authenticatedCredentialID: authenticatedCredentialID
    )
    let credentials = TestCredentialStore()
    credentials.values[authenticatedCredentialID] = Data(repeating: 0x49, count: 32)
    MockURLProtocol.install { _ in
      MockResponse(
        status: 403,
        headers: ["Content-Type": TacuaSDKBackendProtocol.backendErrorMediaType],
        data: errorData
      )
    }
    var client = try makeClient(credentials: credentials)
    do {
      _ = try await client.send(
        diagnosticPrepared(requestData),
        transportCredentialID: authenticatedCredentialID
      )
      throw ClientTestFailure.assertion("Validated backend error must throw")
    } catch let error as TacuaSDKBackendClientError {
      guard case .backend(let validated) = error else {
        throw ClientTestFailure.assertion("Exact backend error must remain typed")
      }
      try require(validated.code == .operationNotAuthorized, "Code must be allowlisted")
      try require(
        validated.reconciliationOutcome == .historicalOperationNotFound,
        "Outcome must prove the historical durable lookup missed"
      )
      try require(
        validated.operationID == "upload_diagnostic_synthetic"
          && validated.authenticatedCredentialID == authenticatedCredentialID,
        "Typed error must retain exact request and transport bindings"
      )
    }
    let observed = try requireOneRequest()
    try require(
      observed.value(forHTTPHeaderField: "Accept")
        == "application/json, \(TacuaSDKBackendProtocol.backendErrorMediaType)",
      "Authenticated requests must advertise the structured error media type"
    )

    let completionData = try canonicalFixture(root, "completion-request")
    let completionRoot = try rootObject(completionData)
    let completionError = try historicalMissError(
      for: completionData,
      authenticatedCredentialID: authenticatedCredentialID
    )
    MockURLProtocol.install { _ in
      MockResponse(
        status: 403,
        headers: ["Content-Type": TacuaSDKBackendProtocol.backendErrorMediaType],
        data: completionError
      )
    }
    client = try makeClient(credentials: credentials)
    do {
      _ = try await client.send(
        TacuaPreparedBackendRequest(
          kind: .completion,
          operationID: completionRoot["completion_id"]!.stringValue!,
          credentialID: completionRoot["credential_id"]!.stringValue!,
          canonicalData: completionData,
          requestDigest: completionRoot["request_digest"]!.stringValue!
        ),
        transportCredentialID: authenticatedCredentialID
      )
      throw ClientTestFailure.assertion("Validated missing completion must throw")
    } catch let error as TacuaSDKBackendClientError {
      guard case .backend(let validated) = error else {
        throw ClientTestFailure.assertion("Missing completion must remain typed")
      }
      try require(
        validated.operationKind == .completion
          && validated.operationID == "completion_synthetic",
        "Completion reconciliation must bind its exact completion request"
      )
    }

    let invalidResponses: [(String, Data)] = [
      ("application/json", errorData),
      (
        TacuaSDKBackendProtocol.backendErrorMediaType,
        try replacingHistoricalMissField(
          errorData,
          field: "authenticated_credential_id",
          value: "credential_other"
        )
      ),
      (
        TacuaSDKBackendProtocol.backendErrorMediaType,
        Data(repeating: 0x20, count: TacuaSDKBackendProtocol.maximumBackendErrorBytes + 1)
      ),
    ]
    for (contentType, body) in invalidResponses {
      MockURLProtocol.install { _ in
        MockResponse(status: 403, headers: ["Content-Type": contentType], data: body)
      }
      client = try makeClient(credentials: credentials)
      do {
        _ = try await client.send(
          diagnosticPrepared(requestData),
          transportCredentialID: authenticatedCredentialID
        )
        throw ClientTestFailure.assertion("Malformed backend error must throw")
      } catch let error as TacuaSDKBackendClientError {
        try require(
          error == .unexpectedStatus(403),
          "Untrusted non-success bodies must preserve generic status behavior"
        )
      }
    }
  }

  private static func resealedInvalidRequestsNeverReachTransport(_ root: URL) async throws {
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x46, count: 32)
    var diagnostic = try rootObject(canonicalFixture(root, "diagnostic-upload-request"))
    diagnostic["client_secret"] = .string("resealed-but-forbidden")
    try reseal(&diagnostic, field: "request_digest")
    MockURLProtocol.install { _ in
      MockResponse(status: 500, headers: ["Content-Type": "application/json"], data: Data())
    }
    var client = try makeClient(credentials: credentials)
    try await expectAsyncFailure {
      _ = try await client.send(
        TacuaPreparedBackendRequest(
          kind: .diagnostic,
          operationID: "upload_diagnostic_synthetic",
          credentialID: "credential_receiving_resume",
          canonicalData: try TacuaCanonicalJSON.data(.object(diagnostic)),
          requestDigest: diagnostic["request_digest"]!.stringValue!
        ),
        transportCredentialID: "credential_current"
      )
    }
    try require(MockURLProtocol.requests().isEmpty, "Forbidden diagnostic must fail locally")

    var completion = try rootObject(canonicalFixture(root, "completion-request"))
    guard case .object(var manifest) = completion["capture_manifest"],
      case .object(var streams) = manifest["streams"]
    else { throw ClientTestFailure.assertion("Missing manifest streams") }
    streams["ignored"] = .string("enabled")
    manifest["streams"] = .object(streams)
    try reseal(&manifest, field: "manifest_digest")
    completion["capture_manifest"] = .object(manifest)
    try reseal(&completion, field: "request_digest")
    MockURLProtocol.install { _ in
      MockResponse(status: 500, headers: ["Content-Type": "application/json"], data: Data())
    }
    client = try makeClient(credentials: credentials)
    try await expectAsyncFailure {
      _ = try await client.send(
        TacuaPreparedBackendRequest(
          kind: .completion,
          operationID: "completion_synthetic",
          credentialID: "credential_receiving_resume",
          canonicalData: try TacuaCanonicalJSON.data(.object(completion)),
          requestDigest: completion["request_digest"]!.stringValue!
        ),
        transportCredentialID: "credential_current"
      )
    }
    try require(MockURLProtocol.requests().isEmpty, "Invalid manifest must fail locally")
  }

  private static func unsafeSegmentSourcesNeverReachTransport(_ root: URL) async throws {
    let payload = Data("safe-segment".utf8)
    let prepared = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_local_security",
      sessionID: "session_synthetic",
      scopeDigest: "sha256:112e576cdc6e5baac76cd40b0b2f49182e573039e7107a1eaf0605ff99f67f50",
      credentialID: "credential_historical",
      sequence: 8,
      segmentID: "segment_local_security",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: Int64(payload.count),
        contentDigest: TacuaCanonicalJSON.digest(data: payload),
        sidecarDigest: "sha256:" + String(repeating: "5", count: 64)
      ),
      requestedAt: "2026-07-21T10:01:59Z"
    )
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x47, count: 32)
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-client-security-\(UUID().uuidString)", isDirectory: true)
    let outside = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-outside-\(UUID().uuidString).mov")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try payload.write(to: outside)
    defer {
      try? FileManager.default.removeItem(at: directory)
      try? FileManager.default.removeItem(at: outside)
    }
    let symlink = directory.appendingPathComponent("alias.mov")
    try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: outside)
    let hardlink = directory.appendingPathComponent("hardlink.mov")
    try FileManager.default.linkItem(at: outside, to: hardlink)
    let childDirectory = directory.appendingPathComponent("directory.mov", isDirectory: true)
    try FileManager.default.createDirectory(at: childDirectory, withIntermediateDirectories: true)
    let fifo = directory.appendingPathComponent("pipe.mov")
    guard mkfifo(fifo.path, 0o600) == 0 else {
      throw ClientTestFailure.assertion("Could not create FIFO fixture")
    }
    let sparse = directory.appendingPathComponent("oversize.mov")
    FileManager.default.createFile(atPath: sparse.path, contents: Data())
    let sparseHandle = try FileHandle(forWritingTo: sparse)
    try sparseHandle.truncate(
      atOffset: UInt64(TacuaSDKBackendProtocol.maximumUploadBytes + 1)
    )
    try sparseHandle.close()
    let grown = directory.appendingPathComponent("grown.mov")
    try (payload + Data("growth".utf8)).write(to: grown)

    for candidate in [outside, symlink, hardlink, childDirectory, fifo, grown, sparse] {
      MockURLProtocol.install { _ in
        MockResponse(status: 500, headers: ["Content-Type": "application/json"], data: Data())
      }
      let client = try makeClient(credentials: credentials)
      try await expectAsyncFailure {
        _ = try await client.uploadSegment(
          prepared,
          fileURL: candidate,
          sessionDirectory: directory,
          transportCredentialID: "credential_current"
        )
      }
      try require(
        MockURLProtocol.requests().isEmpty,
        "Unsafe local source \(candidate.lastPathComponent) must fail before transport"
      )
    }
    _ = root
  }

  private static func uploadStagingScavengerIsBoundedAndFailClosed(
    _ root: URL
  ) async throws {
    let payload = Data("staging-segment".utf8)
    let prepared = try TacuaSDKBackendRequests.segment(
      uploadID: "upload_staging_security",
      sessionID: "session_synthetic",
      scopeDigest: "sha256:112e576cdc6e5baac76cd40b0b2f49182e573039e7107a1eaf0605ff99f67f50",
      credentialID: "credential_historical",
      sequence: 9,
      segmentID: "segment_staging_security",
      metadata: TacuaSegmentTransportMetadata(
        contentType: "video/quicktime",
        sizeBytes: Int64(payload.count),
        contentDigest: TacuaCanonicalJSON.digest(data: payload),
        sidecarDigest: "sha256:" + String(repeating: "6", count: 64)
      ),
      requestedAt: "2026-07-21T10:01:59Z"
    )
    let response = try segmentResponse(for: prepared, fixtureRoot: root)
    let credentials = TestCredentialStore()
    credentials.values["credential_current"] = Data(repeating: 0x48, count: 32)

    func makeDirectory(_ suffix: String) throws -> (URL, URL, URL) {
      let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        "tacua-staging-\(suffix)-\(UUID().uuidString)",
        isDirectory: true
      )
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      let file = directory.appendingPathComponent("segment.mov")
      try payload.write(to: file)
      let staging = directory.appendingPathComponent(".tacua-upload-staging", isDirectory: true)
      try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
      return (directory, file, staging)
    }

    do {
      let (directory, file, staging) = try makeDirectory("stale")
      defer { try? FileManager.default.removeItem(at: directory) }
      let stale = staging.appendingPathComponent(
        "upload-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.snapshot"
      )
      try Data("crash-left-snapshot".utf8).write(to: stale)
      MockURLProtocol.install { _ in
        MockResponse(status: 201, headers: ["Content-Type": "application/json"], data: response)
      }
      _ = try await makeClient(credentials: credentials).uploadSegment(
        prepared,
        fileURL: file,
        sessionDirectory: directory,
        transportCredentialID: "credential_current"
      )
      let remaining = try FileManager.default.contentsOfDirectory(atPath: staging.path)
      try require(
        remaining.isEmpty,
        "A crash-left recognized snapshot must be scavenged before staging and the live copy removed"
      )
    }

    do {
      let (directory, file, staging) = try makeDirectory("symlink")
      defer { try? FileManager.default.removeItem(at: directory) }
      let link = staging.appendingPathComponent(
        "upload-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb.snapshot"
      )
      try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
      MockURLProtocol.install { _ in
        MockResponse(status: 500, headers: ["Content-Type": "application/json"], data: Data())
      }
      try await expectAsyncFailure {
        _ = try await makeClient(credentials: credentials).uploadSegment(
          prepared,
          fileURL: file,
          sessionDirectory: directory,
          transportCredentialID: "credential_current"
        )
      }
      try require(MockURLProtocol.requests().isEmpty, "A staged symlink must fail before transport")
    }

    do {
      let (directory, file, staging) = try makeDirectory("foreign")
      defer { try? FileManager.default.removeItem(at: directory) }
      try Data("foreign".utf8).write(to: staging.appendingPathComponent("keep-me.txt"))
      MockURLProtocol.install { _ in
        MockResponse(status: 500, headers: ["Content-Type": "application/json"], data: Data())
      }
      try await expectAsyncFailure {
        _ = try await makeClient(credentials: credentials).uploadSegment(
          prepared,
          fileURL: file,
          sessionDirectory: directory,
          transportCredentialID: "credential_current"
        )
      }
      try require(MockURLProtocol.requests().isEmpty, "A foreign staged name must fail before transport")
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
    return try TacuaCanonicalJSON.data(.object([
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
    ]))
  }

  private static func replacingHistoricalMissField(
    _ data: Data,
    field: String,
    value: String
  ) throws -> Data {
    var root = try rootObject(data)
    guard case .object(var error) = root["error"],
      case .object(var reconciliation) = error["reconciliation"]
    else { throw ClientTestFailure.assertion("Missing reconciliation error") }
    reconciliation[field] = .string(value)
    error["reconciliation"] = .object(reconciliation)
    root["error"] = .object(error)
    return try TacuaCanonicalJSON.data(.object(root))
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

  private static func reseal(
    _ object: inout [String: TacuaJSONValue], field: String
  ) throws {
    object[field] = .string(try TacuaCanonicalJSON.digest(
      .object(object), omittingRootField: field
    ))
  }

  private static func expectAsyncFailure(
    _ operation: () async throws -> Void
  ) async throws {
    do {
      try await operation()
      throw ClientTestFailure.assertion("Expected local failure")
    } catch is ClientTestFailure {
      throw ClientTestFailure.assertion("Expected local failure")
    } catch {
      return
    }
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
