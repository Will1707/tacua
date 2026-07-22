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

    var tampered = root.objectValue!
    tampered["backend_origin"] = .string("https://attacker.example")
    try expect(.profileDigestMismatch) {
      _ = try TacuaSDKBuildProfile(
        canonicalJSON: TacuaCanonicalJSON.data(.object(tampered)),
        claimedProfileDigest: claimed,
        configuration: configuration
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
