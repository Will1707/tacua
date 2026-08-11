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
  debugBuild: Bool = false,
  maxSegmentBytes: Int = TacuaBackendConfiguration.defaultMaxSegmentBytes,
  maxDiagnosticBytes: Int = TacuaBackendConfiguration.defaultMaxDiagnosticBytes,
  maxCompletionBytes: Int = TacuaBackendConfiguration.defaultMaxCompletionBytes
) throws {
  do {
    _ = try TacuaBackendConfiguration(
      buildConfiguredOrigin: origin,
      allowInsecureLoopback: allowInsecureLoopback,
      debugBuild: debugBuild,
      maxSegmentBytes: maxSegmentBytes,
      maxDiagnosticBytes: maxDiagnosticBytes,
      maxCompletionBytes: maxCompletionBytes
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
    try transportLimitsAreExactNativeConfiguration()
    try bundleConfigurationReadsExactTransportLimits()
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
    for debugBuild in [false, true] {
      let development = try TacuaQABuildConfiguration(
        captureEnabled: true,
        buildVariant: "development",
        distribution: "local",
        debugBuild: debugBuild
      )
      try require(
        development.buildVariant == "development" && development.distribution == "local",
        "Local QA build was not accepted"
      )
    }
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
        == "sha256:edb112f00c2dfd730be887ac981f0bf6eeaaec72180506cfbf1541fb25652ac2",
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

  private static func transportLimitsAreExactNativeConfiguration() throws {
    let custom = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      maxSegmentBytes: 4_194_304,
      maxDiagnosticBytes: 1_048_576,
      maxCompletionBytes: 2_097_152
    )
    try require(custom.maxSegmentBytes == 4_194_304, "Segment limit was not retained")
    try require(custom.maxDiagnosticBytes == 1_048_576, "Diagnostic limit was not retained")
    try require(custom.maxCompletionBytes == 2_097_152, "Completion limit was not retained")

    let defaults = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false
    )
    try require(
      custom.configurationDigest != defaults.configurationDigest,
      "Transport limit changes did not change the sealed configuration digest"
    )
    try expectConfigurationError(
      .invalidTransportLimit,
      origin: "https://qa.example.com",
      maxSegmentBytes: 0
    )
    try expectConfigurationError(
      .invalidTransportLimit,
      origin: "https://qa.example.com",
      maxDiagnosticBytes: TacuaBackendConfiguration.maxDiagnosticBytesUpperBound + 1
    )
    try expectConfigurationError(
      .invalidTransportLimit,
      origin: "https://qa.example.com",
      maxCompletionBytes: 1_023
    )
    try expectConfigurationError(
      .invalidTransportLimit,
      origin: "https://qa.example.com",
      maxCompletionBytes: TacuaBackendConfiguration.maxCompletionBytesUpperBound + 1
    )
  }

  private static func bundleConfigurationReadsExactTransportLimits() throws {
    let bundleRoot = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-transport-limits-\(UUID().uuidString).bundle",
      isDirectory: true
    )
    let contents = bundleRoot.appendingPathComponent("Contents", isDirectory: true)
    try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: bundleRoot) }
    let plist: [String: Any] = [
      "CFBundleIdentifier": "dev.tacua.transport-limit-tests",
      "CFBundlePackageType": "BNDL",
      TacuaQABuildConfiguration.enabledInfoPlistKey: true,
      TacuaQABuildConfiguration.buildVariantInfoPlistKey: "preview",
      TacuaQABuildConfiguration.distributionInfoPlistKey: "testflight",
      TacuaBackendConfiguration.originInfoPlistKey: "https://qa.example.com",
      TacuaBackendConfiguration.insecureLoopbackInfoPlistKey: false,
      TacuaBackendConfiguration.maxSegmentBytesInfoPlistKey: 8_388_608,
      TacuaBackendConfiguration.maxDiagnosticBytesInfoPlistKey: 2_097_152,
      TacuaBackendConfiguration.maxCompletionBytesInfoPlistKey: 4_194_304,
    ]
    let plistBytes = try PropertyListSerialization.data(
      fromPropertyList: plist,
      format: .xml,
      options: 0
    )
    try plistBytes.write(to: contents.appendingPathComponent("Info.plist"))
    guard let bundle = Bundle(path: bundleRoot.path) else {
      throw BackendConfigurationTestFailure.assertion("Could not load temporary test bundle")
    }
    let configuration = try TacuaBackendConfiguration.fromBuildConfiguration(
      bundle: bundle,
      debugBuild: false
    )
    try require(configuration.maxSegmentBytes == 8_388_608, "Bundle segment pin was lost")
    try require(configuration.maxDiagnosticBytes == 2_097_152, "Bundle diagnostic pin was lost")
    try require(configuration.maxCompletionBytes == 4_194_304, "Bundle completion pin was lost")
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
