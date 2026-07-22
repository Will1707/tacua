// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum BackendConfigurationTestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw BackendConfigurationTestFailure.assertion(message) }
}

private func expectConfigurationError(
  _ expected: TacuaBackendConfigurationError,
  origin: String,
  allowInsecureLoopback: Bool = false,
  debugBuild: Bool = false
) throws {
  do {
    _ = try TacuaBackendConfiguration(
      buildConfiguredOrigin: origin,
      allowInsecureLoopback: allowInsecureLoopback,
      debugBuild: debugBuild
    )
    throw BackendConfigurationTestFailure.assertion("Expected \(expected), but origin was accepted")
  } catch let error as TacuaBackendConfigurationError {
    try require(error == expected, "Expected \(expected), received \(error)")
  }
}

@main
enum BackendConfigurationTests {
  static func main() throws {
    try qaBuildGateRejectsProductionAndMalformedConfiguration()
    try buildIdentityMustMatchNativeQABuildAuthority()
    try normalizesBuildConfiguredHTTPSOrigin()
    try rejectsRuntimeOverrideShapes()
    try loopbackHTTPRequiresExplicitDebugConfiguration()
    try endpointCannotEscapeOrigin()
    try redirectsAreRejected()
    print("Tacua backend configuration tests passed")
  }

  private static func buildIdentityMustMatchNativeQABuildAuthority() throws {
    let qaBuild = try TacuaQABuildConfiguration(
      captureEnabled: true,
      buildVariant: "preview",
      distribution: "testflight",
      debugBuild: false
    )
    let config = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      qaBuildConfiguration: qaBuild
    )
    let matching = try TacuaCanonicalJSON.parse(
      Data(#"{"build_variant":"preview","distribution":"testflight"}"#.utf8)
    )
    try config.validateBuildIdentityBinding(matching)

    let mismatched = try TacuaCanonicalJSON.parse(
      Data(#"{"build_variant":"development","distribution":"internal"}"#.utf8)
    )
    do {
      try config.validateBuildIdentityBinding(mismatched)
      throw BackendConfigurationTestFailure.assertion(
        "Caller-supplied build identity escaped the native QA build authority"
      )
    } catch let error as TacuaBackendConfigurationError {
      try require(error == .buildIdentityMismatch, "Unexpected build binding error: \(error)")
    }
  }

  private static func qaBuildGateRejectsProductionAndMalformedConfiguration() throws {
    let development = try TacuaQABuildConfiguration(
      captureEnabled: true,
      buildVariant: "development",
      distribution: "local",
      debugBuild: true
    )
    try require(
      development.buildVariant == "development" && development.distribution == "local",
      "Development QA build was not accepted"
    )
    let preview = try TacuaQABuildConfiguration(
      captureEnabled: true,
      buildVariant: "preview",
      distribution: "testflight",
      debugBuild: false
    )
    try require(preview.buildVariant == "preview", "TestFlight preview build was not accepted")

    let invalid: [(
      Bool, String, String, Bool, TacuaQABuildConfigurationError
    )] = [
      (false, "preview", "testflight", false, .captureNotEnabled),
      (true, "production", "testflight", false, .invalidBuildVariant),
      (true, "preview", "appstore", false, .invalidDistribution),
      (true, "preview", "local", true, .unsupportedBuildPair),
      (true, "development", "testflight", true, .unsupportedBuildPair),
      (true, "development", "internal", false, .developmentBuildRequiresDebug),
    ]
    for (enabled, variant, distribution, debugBuild, expected) in invalid {
      do {
        _ = try TacuaQABuildConfiguration(
          captureEnabled: enabled,
          buildVariant: variant,
          distribution: distribution,
          debugBuild: debugBuild
        )
        throw BackendConfigurationTestFailure.assertion(
          "Invalid QA build configuration was accepted"
        )
      } catch let error as TacuaQABuildConfigurationError {
        try require(error == expected, "Unexpected QA build error: \(error)")
      }
    }
  }

  private static func normalizesBuildConfiguredHTTPSOrigin() throws {
    let config = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "HTTPS://QA.Example.COM:443",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    try require(config.normalizedOrigin == "https://qa.example.com", "Origin was not normalized")
    try require(
      config.configurationDigest
        == "sha256:c247c8dfdd0a21d4410748aa9f847d026008c7a0c3944f1a54a1183f1e67b452",
      "Configuration digest does not match the protocol subject"
    )
    let slashConfig = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com/",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    try require(slashConfig.normalizedOrigin == config.normalizedOrigin, "Root slash changed origin")
    try require(
      slashConfig.configurationDigest == config.configurationDigest,
      "Equivalent origins produced different configuration digests"
    )
  }

  private static func rejectsRuntimeOverrideShapes() throws {
    try expectConfigurationError(.invalidOrigin, origin: "https://user:pass@qa.example.com")
    try expectConfigurationError(.invalidOrigin, origin: "https://qa.example.com/v1")
    try expectConfigurationError(.invalidOrigin, origin: "https://qa.example.com?target=other")
    try expectConfigurationError(.invalidOrigin, origin: "https://qa.example.com#fragment")
    try expectConfigurationError(.insecureOrigin, origin: "http://qa.example.com")
    try expectConfigurationError(.invalidOrigin, origin: "file:///tmp/backend")
  }

  private static func loopbackHTTPRequiresExplicitDebugConfiguration() throws {
    try expectConfigurationError(.loopbackDevelopmentOnly, origin: "http://127.0.0.1:8787")
    try expectConfigurationError(
      .loopbackDevelopmentOnly,
      origin: "http://127.0.0.1:8787",
      allowInsecureLoopback: true,
      debugBuild: false
    )
    let config = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "http://127.0.0.1:8787",
      allowInsecureLoopback: true,
      debugBuild: true
    )
    try require(config.normalizedOrigin == "http://127.0.0.1:8787", "Loopback changed")
  }

  private static func endpointCannotEscapeOrigin() throws {
    let config = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com:8443",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    let endpoint = try config.endpoint(pathSegments: ["v1", "sdk", "sessions", "session_001"])
    try require(
      endpoint.absoluteString == "https://qa.example.com:8443/v1/sdk/sessions/session_001",
      "Endpoint path was not origin-bound"
    )
    do {
      _ = try config.endpoint(pathSegments: ["v1", "..", "other"])
      throw BackendConfigurationTestFailure.assertion("Path traversal segment was accepted")
    } catch let error as TacuaBackendConfigurationError {
      try require(error == .invalidPathSegment, "Unexpected path-segment error")
    }
  }

  private static func redirectsAreRejected() throws {
    let delegate = TacuaRejectRedirectSessionDelegate()
    let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
    defer { session.invalidateAndCancel() }
    let task = session.dataTask(with: URL(string: "https://qa.example.com/source")!)
    let response = HTTPURLResponse(
      url: URL(string: "https://qa.example.com/source")!,
      statusCode: 307,
      httpVersion: "HTTP/1.1",
      headerFields: ["Location": "https://other.example.com/target"]
    )!
    var redirectedRequest: URLRequest? = URLRequest(url: URL(string: "https://invalid.example")!)
    delegate.urlSession(
      session,
      task: task,
      willPerformHTTPRedirection: response,
      newRequest: URLRequest(url: URL(string: "https://other.example.com/target")!),
      completionHandler: { redirectedRequest = $0 }
    )
    try require(redirectedRequest == nil, "Redirect delegate forwarded a credential-bearing request")
  }
}
