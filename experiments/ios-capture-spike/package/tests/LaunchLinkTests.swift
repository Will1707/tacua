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
    try require(parsed.expectedSessionID == nil, "START must remain session-unbound")

    let resumeSessionID = "session_resume_exact_001"
    let resume = valid + "&session_id=\(resumeSessionID)"
    let parsedResume = try TacuaLaunchLinkParser.parse(resume, configuration: configuration)
    try require(parsedResume.launchCode == code, "RESUME lost its opaque launch code")
    try require(
      parsedResume.expectedSessionID == resumeSessionID,
      "RESUME lost its exact remote-session hint"
    )

    let reservedSchemes = [
      "about", "blob", "data", "facetime", "facetime-audio", "file", "ftp", "ftps",
      "http", "https", "itms", "itms-apps", "javascript", "mailto", "sms", "tacua",
      "tel", "webcal", "ws", "wss",
    ]
    for scheme in reservedSchemes {
      try expectLaunchError {
        _ = try TacuaLaunchLinkConfiguration(buildConfiguredScheme: scheme)
      }
    }
    let maximumLengthScheme = "a" + String(repeating: "b", count: 63)
    _ = try TacuaLaunchLinkConfiguration(buildConfiguredScheme: maximumLengthScheme)
    try expectLaunchError {
      _ = try TacuaLaunchLinkConfiguration(
        buildConfiguredScheme: "a" + String(repeating: "b", count: 64)
      )
    }

    let invalid = [
      "other://tacua/start?launch_code=\(code)",
      "configured-target-scheme://user@tacua/start?launch_code=\(code)",
      "configured-target-scheme://tacua:443/start?launch_code=\(code)",
      "configured-target-scheme://tacua/extra/start?launch_code=\(code)",
      "configured-target-scheme://tacua/start/extra?launch_code=\(code)",
      "configured-target-scheme://tacua/start?launch_code=\(code)&launch_code=\(code)",
      "configured-target-scheme://tacua/start?launch_code=\(code)&origin=https%3A%2F%2Fevil.example",
      "configured-target-scheme://tacua/start?launch_code=\(code)&session_id=bad%20session",
      "configured-target-scheme://tacua/start?launch_code=\(code)&session_id=\(resumeSessionID)&session_id=\(resumeSessionID)",
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

    let resumeGate = TacuaLaunchConsentGate()
    let pendingResume = try resumeGate.prepare(rawURL: resume, configuration: configuration)
    try require(
      pendingResume.expectedSessionID == resumeSessionID,
      "Consent metadata did not expose the exact RESUME target"
    )
    let approvedResume = try resumeGate.confirm(
      consentRequestID: pendingResume.consentRequestID,
      granted: true
    )
    try expectLaunchError {
      _ = try resumeGate.withApprovedLaunchCode(
        approvedLaunchID: approvedResume,
        expectedSessionID: "session_wrong_target_001"
      ) { $0 }
    }
    let consumedResume = try resumeGate.withApprovedLaunchCode(
      approvedLaunchID: approvedResume,
      expectedSessionID: resumeSessionID
    ) { $0 }
    try require(
      consumedResume == code,
      "A wrong queue must not consume the exact RESUME one-shot handle"
    )

    let declined = try gate.prepare(rawURL: valid, configuration: configuration)
    try expectLaunchError {
      _ = try gate.confirm(consentRequestID: declined.consentRequestID, granted: false)
    }
    print("Tacua launch-link tests passed")
  }
}
