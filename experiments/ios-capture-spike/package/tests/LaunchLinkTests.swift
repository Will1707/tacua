// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum LaunchTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw LaunchTestFailure.assertion(message) }
}

private func expectLaunchError(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw LaunchTestFailure.assertion("Expected launch-link rejection")
  } catch is LaunchTestFailure {
    throw LaunchTestFailure.assertion("Expected launch-link rejection")
  } catch {
    return
  }
}

@main
enum LaunchLinkTests {
  static func main() throws {
    let configuration = try TacuaLaunchLinkConfiguration(
      buildConfiguredScheme: "configured-target-scheme"
    )
    let code = String(repeating: "A", count: 43)
    let valid = "configured-target-scheme://tacua/start?launch_code=\(code)"
    let parsed = try TacuaLaunchLinkParser.parse(valid, configuration: configuration)
    try require(parsed.launchCode == code, "The one opaque launch code must be extracted")

    let invalid = [
      "other://tacua/start?launch_code=\(code)",
      "configured-target-scheme://user@tacua/start?launch_code=\(code)",
      "configured-target-scheme://tacua:443/start?launch_code=\(code)",
      "configured-target-scheme://tacua/extra/start?launch_code=\(code)",
      "configured-target-scheme://tacua/start/extra?launch_code=\(code)",
      "configured-target-scheme://tacua/start?launch_code=\(code)&launch_code=\(code)",
      "configured-target-scheme://tacua/start?launch_code=\(code)&origin=https%3A%2F%2Fevil.example",
      "configured-target-scheme://tacua/start?launch_code=\(code)#fragment",
      "configured-target-scheme://tacua/start?launch_code=short",
      "configured-target-scheme://tacua/start",
    ]
    for candidate in invalid {
      try expectLaunchError {
        _ = try TacuaLaunchLinkParser.parse(candidate, configuration: configuration)
      }
    }

    let gate = TacuaLaunchConsentGate()
    let pending = try gate.prepare(rawURL: valid, configuration: configuration)
    try expectLaunchError {
      _ = try gate.withApprovedLaunchCode(
        approvedLaunchID: pending.consentRequestID,
        { _ in true }
      )
    }
    let approvedID = try gate.confirm(
      consentRequestID: pending.consentRequestID,
      granted: true
    )
    let consumed = try gate.withApprovedLaunchCode(approvedLaunchID: approvedID) { $0 }
    try require(consumed == code, "Consent must unlock the exact transient code once")
    try expectLaunchError {
      _ = try gate.withApprovedLaunchCode(approvedLaunchID: approvedID) { $0 }
    }

    let declined = try gate.prepare(rawURL: valid, configuration: configuration)
    try expectLaunchError {
      _ = try gate.confirm(consentRequestID: declined.consentRequestID, granted: false)
    }
    print("Tacua launch-link tests passed")
  }
}
