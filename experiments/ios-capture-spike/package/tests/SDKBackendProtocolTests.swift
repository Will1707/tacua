// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum ProtocolTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw ProtocolTestFailure.assertion(message) }
}

private func expectFailure(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw ProtocolTestFailure.assertion("Expected protocol validation to fail")
  } catch is ProtocolTestFailure {
    throw ProtocolTestFailure.assertion("Expected protocol validation to fail")
  } catch {
    return
  }
}

@main
enum SDKBackendProtocolTests {
  static func main() throws {
    let fixtureRoot = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    try validatesEveryPositiveLifecyclePair(fixtureRoot)
    try rejectsNonCanonicalAndUnboundedResponses(fixtureRoot)
    try rejectsUnknownFieldsAndReboundIdentifiers(fixtureRoot)
    try completionAuthorityComesFromExactReceipt(fixtureRoot)
    try deletionAuthorityComesFromExactTombstone(fixtureRoot)
    try exactWholeSecondTimestampsOnly(fixtureRoot)
    print("Tacua SDK/backend protocol tests passed")
  }

  private static func canonicalFixture(_ root: URL, _ name: String) throws -> Data {
    let data = try Data(contentsOf: root.appendingPathComponent("\(name).json"))
    return try TacuaCanonicalJSON.data(try TacuaCanonicalJSON.parse(data))
  }

  private static func pair(_ root: URL, _ request: String, _ response: String) throws
    -> TacuaValidatedBackendReceipt
  {
    try TacuaSDKBackendProtocol.validateResponse(
      canonicalFixture(root, response),
      forCanonicalRequest: canonicalFixture(root, request)
    )
  }

  private static func replacingRoot(
    _ data: Data,
    receiptDigestField: String,
    mutate: (inout [String: TacuaJSONValue]) throws -> Void
  ) throws -> Data {
    guard case .object(var object) = try TacuaCanonicalJSON.parse(data) else {
      throw ProtocolTestFailure.assertion("Fixture root must be an object")
    }
    try mutate(&object)
    object[receiptDigestField] = .string(try TacuaCanonicalJSON.digest(
      .object(object), omittingRootField: receiptDigestField
    ))
    return try TacuaCanonicalJSON.data(.object(object))
  }

  private static func validatesEveryPositiveLifecyclePair(_ root: URL) throws {
    let start = try pair(root, "launch-exchange-request", "launch-exchange-receipt")
    try require(start.operationKind == .launch, "Launch receipt must validate")
    try require(start.credentialTransition?.capability == .active, "Start must issue active credential")
    try require(start.authoritativeTimestamp == "2026-07-21T09:57:01Z", "Launch must anchor from issued_at")

    let receiving = try pair(root, "receiving-resume-request", "receiving-resume-receipt")
    try require(receiving.credentialTransition?.credentialID == "credential_receiving_resume", "Resume must bind the new credential")

    let completed = try pair(root, "completed-resume-request", "completed-resume-receipt")
    try require(completed.credentialTransition?.capability == .completionReplayOrDeleteOnly, "Completed resume must stay upload-disabled")
    try require(completed.credentialTransition?.replayCompletionID == "completion_synthetic", "Completed resume must bind one completion")

    let segment = try pair(root, "segment-upload-intent", "segment-upload-receipt")
    try require(segment.operationKind == .segment, "Segment pair must validate")
    let diagnostic = try pair(root, "diagnostic-upload-request", "diagnostic-upload-receipt")
    try require(diagnostic.operationKind == .diagnostic, "Diagnostic pair must validate")
    let completion = try pair(root, "completion-request", "completion-receipt")
    try require(completion.operationKind == .completion, "Completion pair must validate")
    let deletion = try pair(root, "deletion-request", "deletion-tombstone")
    try require(deletion.operationKind == .deletion, "Deletion pair must validate")
  }

  private static func rejectsNonCanonicalAndUnboundedResponses(_ root: URL) throws {
    let request = try canonicalFixture(root, "launch-exchange-request")
    let response = try canonicalFixture(root, "launch-exchange-receipt")
    var padded = response
    padded.append(0x0A)
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(padded, forCanonicalRequest: request)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(
        response, forCanonicalRequest: request, maximumResponseBytes: response.count - 1
      )
    }
  }

  private static func rejectsUnknownFieldsAndReboundIdentifiers(_ root: URL) throws {
    let startRequest = try canonicalFixture(root, "launch-exchange-request")
    let startResponse = try canonicalFixture(root, "launch-exchange-receipt")
    let unknown = try replacingRoot(
      startResponse, receiptDigestField: "exchange_receipt_digest"
    ) { $0["unexpected"] = .bool(true) }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(unknown, forCanonicalRequest: startRequest)
    }

    let resumeRequest = try canonicalFixture(root, "receiving-resume-request")
    let resumeResponse = try canonicalFixture(root, "receiving-resume-receipt")
    let rebound = try replacingRoot(
      resumeResponse, receiptDigestField: "exchange_receipt_digest"
    ) { $0["session_id"] = .string("session_other") }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(rebound, forCanonicalRequest: resumeRequest)
    }
  }

  private static func completionAuthorityComesFromExactReceipt(_ root: URL) throws {
    let request = try canonicalFixture(root, "completion-request")
    let response = try canonicalFixture(root, "completion-receipt")
    let receipt = try TacuaSDKBackendProtocol.validateResponse(response, forCanonicalRequest: request)
    let authority = try requireValue(receipt.completionCleanupAuthority, "Missing completion authority")
    try require(authority.completionID == "completion_synthetic", "Cleanup must bind completion")
    try require(authority.segmentReceiptDigests.count == 1, "Cleanup must bind all media receipts")
    try require(authority.diagnosticReceiptDigests.count == 1, "Cleanup must bind all diagnostic receipts")

    let wrongCredential = try replacingRoot(
      response, receiptDigestField: "completion_receipt_digest"
    ) { root in
      guard case .object(var credential) = root["credential"] else { return }
      credential["credential_id"] = .string("credential_wrong")
      root["credential"] = .object(credential)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(wrongCredential, forCanonicalRequest: request)
    }

    let wrongCleanup = try replacingRoot(
      response, receiptDigestField: "completion_receipt_digest"
    ) { root in
      guard case .object(var cleanup) = root["local_cleanup"] else { return }
      cleanup["segment_receipt_digests"] = .array([])
      root["local_cleanup"] = .object(cleanup)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(wrongCleanup, forCanonicalRequest: request)
    }
  }

  private static func deletionAuthorityComesFromExactTombstone(_ root: URL) throws {
    let receipt = try pair(root, "deletion-request", "deletion-tombstone")
    let authority = try requireValue(receipt.deletionCleanupAuthority, "Missing deletion authority")
    try require(authority.credentialID == "credential_receiving_resume", "Tombstone must bind Keychain credential")
    let request = try canonicalFixture(root, "deletion-request")
    let response = try canonicalFixture(root, "deletion-tombstone")
    let overRetained = try replacingRoot(
      response, receiptDigestField: "tombstone_digest"
    ) { root in
      root["tombstone_expires_at"] = .string("2026-09-30T10:03:05Z")
      guard case .object(var credential) = root["credential"] else { return }
      credential["verifier_retained_until"] = .string("2026-09-30T10:03:05Z")
      root["credential"] = .object(credential)
    }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(overRetained, forCanonicalRequest: request)
    }
  }

  private static func exactWholeSecondTimestampsOnly(_ root: URL) throws {
    let request = try canonicalFixture(root, "launch-exchange-request")
    let response = try canonicalFixture(root, "launch-exchange-receipt")
    let fractional = try replacingRoot(
      response, receiptDigestField: "exchange_receipt_digest"
    ) { $0["issued_at"] = .string("2026-07-21T09:57:01.000Z") }
    try expectFailure {
      _ = try TacuaSDKBackendProtocol.validateResponse(fractional, forCanonicalRequest: request)
    }
  }

  private static func requireValue<T>(_ value: T?, _ message: String) throws -> T {
    guard let value else { throw ProtocolTestFailure.assertion(message) }
    return value
  }
}
