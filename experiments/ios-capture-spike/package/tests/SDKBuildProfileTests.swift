// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum SDKBuildProfileTestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw SDKBuildProfileTestFailure.assertion(message) }
}

@main
enum SDKBuildProfileTests {
  static func main() throws {
    guard CommandLine.arguments.count == 2 else {
      throw SDKBuildProfileTestFailure.assertion("Expected SDK profile fixture path")
    }
    let fixtureURL = URL(fileURLWithPath: CommandLine.arguments[1])
    let fileBytes = try Data(contentsOf: fixtureURL)
    guard fileBytes.last == 0x0A else {
      throw SDKBuildProfileTestFailure.assertion("Profile fixture must end in LF")
    }
    let canonical = fileBytes.dropLast()
    let root = try TacuaCanonicalJSON.parse(Data(canonical))
    let claimed = try required(
      root.objectValue?["profile_digest"]?.stringValue,
      "Profile fixture has no digest"
    )
    let qaBuild = try TacuaQABuildConfiguration(
      captureEnabled: true,
      buildVariant: "preview",
      distribution: "testflight",
      debugBuild: false
    )
    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      qaBuildConfiguration: qaBuild
    )
    let profile = try TacuaSDKBuildProfile(
      canonicalJSON: Data(canonical),
      claimedProfileDigest: claimed,
      configuration: configuration
    )
    let artifacts = try profile.captureArtifacts(
      consentGrantedAt: "2026-07-22T12:00:00Z"
    )
    try require(profile.configuration.maxSegmentBytes == 268_435_456, "Wrong segment limit")
    try require(profile.configuration.maxDiagnosticBytes == 3_145_728, "Wrong diagnostic limit")
    try require(profile.configuration.maxCompletionBytes == 4_194_304, "Wrong completion limit")
    try require(artifacts.buildID == "build_example", "Wrong build projection")
    try require(artifacts.bundleIdentifier == "com.example.app", "Wrong bundle projection")
    try require(
      artifacts.scope.objectValue?["scope_digest"]?.stringValue == artifacts.scopeDigest,
      "Generated scope is not sealed"
    )
    try require(
      artifacts.scope.objectValue?["consent"]?.objectValue?["granted_at"]?.stringValue
        == "2026-07-22T12:00:00Z",
      "Generated scope lost consent chronology"
    )

    let (v12Canonical, v12Digest) = try transportV12Profile(from: root)
    let v12Configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      transportPolicyVersion: TacuaBackendConfiguration.launchSchemePolicyVersion,
      launchScheme: "example-tacua-qa",
      qaBuildConfiguration: qaBuild
    )
    let v12Profile = try TacuaSDKBuildProfile(
      canonicalJSON: v12Canonical,
      claimedProfileDigest: v12Digest,
      configuration: v12Configuration
    )
    try require(
      v12Profile.configuration.launchScheme == "example-tacua-qa",
      "V1.2 profile lost its sealed launch scheme"
    )
    let wrongV12Scheme = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      transportPolicyVersion: TacuaBackendConfiguration.launchSchemePolicyVersion,
      launchScheme: "other-tacua-qa",
      qaBuildConfiguration: qaBuild
    )
    try expect(.transportConfigurationMismatch) {
      _ = try TacuaSDKBuildProfile(
        canonicalJSON: v12Canonical,
        claimedProfileDigest: v12Digest,
        configuration: wrongV12Scheme
      )
    }

    var tampered = root.objectValue!
    tampered["backend_origin"] = .string("https://attacker.example")
    try expect(.profileDigestMismatch) {
      _ = try TacuaSDKBuildProfile(
        canonicalJSON: TacuaCanonicalJSON.data(.object(tampered)),
        claimedProfileDigest: claimed,
        configuration: configuration
      )
    }
    let wrongLimits = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      maxSegmentBytes: 134_217_728,
      qaBuildConfiguration: qaBuild
    )
    try expect(.transportConfigurationMismatch) {
      _ = try TacuaSDKBuildProfile(
        canonicalJSON: Data(canonical),
        claimedProfileDigest: claimed,
        configuration: wrongLimits
      )
    }
    try expect(.profileDigestMismatch) {
      _ = try TacuaSDKBuildProfile(
        canonicalJSON: Data(canonical),
        claimedProfileDigest: "sha256:" + String(repeating: "0", count: 64),
        configuration: configuration
      )
    }
    try expect(.invalidConsentTimestamp) {
      _ = try profile.captureArtifacts(consentGrantedAt: "2026-07-22 12:00:00")
    }
    let wrongQA = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: true,
      qaBuildConfiguration: try TacuaQABuildConfiguration(
        captureEnabled: true,
        buildVariant: "development",
        distribution: "local",
        debugBuild: true
      )
    )
    try expect(.invalidProfile) {
      _ = try TacuaSDKBuildProfile(
        canonicalJSON: Data(canonical),
        claimedProfileDigest: claimed,
        configuration: wrongQA
      )
    }
    print("Tacua SDK build-profile tests passed")
  }

  private static func transportV12Profile(
    from root: TacuaJSONValue
  ) throws -> (Data, String) {
    var profile = try required(root.objectValue, "Profile fixture is not an object")
    var transport = try required(
      profile["transport_configuration"]?.objectValue,
      "Profile fixture has no transport"
    )
    transport["transport_policy_version"] = .string(
      TacuaBackendConfiguration.launchSchemePolicyVersion
    )
    transport["launch_scheme"] = .string("example-tacua-qa")
    let transportValue = TacuaJSONValue.object(transport)
    let transportDigest = try TacuaCanonicalJSON.digest(transportValue)
    profile["transport_configuration"] = transportValue
    profile["transport_configuration_digest"] = .string(transportDigest)

    var buildIdentity = try required(
      profile["build_identity"]?.objectValue,
      "Profile fixture has no build identity"
    )
    buildIdentity["transport_configuration_digest"] = .string(transportDigest)
    let buildIdentityDigest = try TacuaCanonicalJSON.digest(
      .object(buildIdentity),
      omittingRootField: "build_identity_digest"
    )
    buildIdentity["build_identity_digest"] = .string(buildIdentityDigest)
    profile["build_identity"] = .object(buildIdentity)

    var scope = try required(
      profile["capture_scope_policy"]?.objectValue,
      "Profile fixture has no capture scope"
    )
    scope["build_identity_digest"] = .string(buildIdentityDigest)
    profile["capture_scope_policy"] = .object(scope)

    let profileDigest = try TacuaCanonicalJSON.digest(
      .object(profile),
      omittingRootField: "profile_digest"
    )
    profile["profile_digest"] = .string(profileDigest)
    return (try TacuaCanonicalJSON.data(.object(profile)), profileDigest)
  }

  private static func required<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw SDKBuildProfileTestFailure.assertion(message) }
    return value
  }

  private static func expect(
    _ expected: TacuaSDKBuildProfileError,
    _ operation: () throws -> Void
  ) throws {
    do {
      try operation()
      throw SDKBuildProfileTestFailure.assertion("Expected \(expected)")
    } catch let error as TacuaSDKBuildProfileError {
      try require(error == expected, "Expected \(expected), received \(error)")
    }
  }
}
