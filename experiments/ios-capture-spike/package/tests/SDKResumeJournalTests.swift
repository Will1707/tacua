// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

private enum ResumeJournalTestFailure: Error {
  case assertion(String)
  case forcedBaseQueueMismatch
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw ResumeJournalTestFailure.assertion(message) }
}

private func expectJournalFailure(_ body: () throws -> Void) throws {
  do {
    try body()
    throw ResumeJournalTestFailure.assertion("Expected resume-journal rejection")
  } catch is TacuaSDKResumeJournalError {
    return
  }
}

private func requireJournalError(
  _ expected: TacuaSDKResumeJournalError,
  _ body: () throws -> Void
) throws {
  do {
    try body()
    throw ResumeJournalTestFailure.assertion("Expected \(expected)")
  } catch let error as TacuaSDKResumeJournalError {
    try require(error == expected, "Wrong resume-journal error: \(error)")
  }
}

@main
enum SDKResumeJournalTests {
  private static let baseDigest = digest("a")
  private static let resultDigest = digest("b")
  private static let scopeDigest = digest("c")
  private static let transportDigest = digest("d")
  private static let ownershipDigest = digest("e")
  private static let requestDigest = digest("f")
  private static let responseDigest = digest("1")

  static func main() throws {
    try canonicalRoundTripAndStateMachineAreStrict()
    try completedReceiptIsBoundToOneCompletion()
    try boundedClosedDecodingRejectsMalformedInput()
    try fileStoreIsPrivateAtomicAndOwnerChecked()
    print("Tacua SDK resume-journal tests passed")
  }

  private static func canonicalRoundTripAndStateMachineAreStrict() throws {
    let prepared = try receivingJournal()
    let encoded = try prepared.encoded()
    let decodedPrepared = try TacuaSDKResumeJournal.decode(encoded)
    try require(
      decodedPrepared == prepared,
      "Canonical resume journal did not round-trip"
    )
    let text = String(decoding: encoded, as: UTF8.self).lowercased()
    try require(!text.contains("launch_code"), "Resume journal persisted a launch code")
    try require(!text.contains("authorization"), "Resume journal persisted authorization")
    try require(!text.contains("\"secret\""), "Resume journal persisted a secret field")

    try expectJournalFailure {
      _ = try prepared.advancing(to: .exchangeOutcomeUnknown)
    }
    let attempted = try prepared.advancing(
      to: .exchangeOutcomeUnknown,
      requestDigest: requestDigest
    )
    try require(attempted.requestDigest == requestDigest, "Network intent lost its request digest")
    try require(
      attempted.validatedReceipt == nil,
      "Outcome-unknown state asserted a validated receipt"
    )
    // This is the critical resume invariant: after network intent is durable, deleting the new
    // credential could strand a remotely rotated session.
    try expectJournalFailure {
      _ = try attempted.advancing(to: .credentialPreparedResetPending)
    }

    let reset = try prepared.advancing(to: .credentialPreparedResetPending)
    try require(
      reset.requestDigest == nil && reset.validatedReceipt == nil,
      "Pre-network reset retained network evidence"
    )
    let resetRetry = try reset.advancing(to: .credentialPreparedResetPending)
    try require(
      resetRetry == reset,
      "Reset recovery was not idempotent"
    )

    let recovery = try receivingRecovery()
    let validated = try attempted.advancing(
      to: .receiptValidatedQueueCommitPending,
      validatedReceipt: recovery
    )
    try require(
      validated.validatedReceipt?.resultQueueDigest == resultDigest,
      "Validated receipt lost the exact result queue digest"
    )
    let decodedValidated = try TacuaSDKResumeJournal.decode(validated.encoded())
    try require(
      decodedValidated == validated,
      "Validated receipt recovery did not round-trip"
    )
    let validatedRetry = try validated.advancing(to: .receiptValidatedQueueCommitPending)
    try require(
      validatedRetry == validated,
      "Validated recovery confirmation was not idempotent"
    )

    let sameResult = TacuaSDKResumeReceiptRecovery(
      credentialCapability: .active,
      replayCompletionID: nil,
      credentialExpiresAt: "2026-08-21T10:00:00Z",
      responseDigest: responseDigest,
      resultQueueDigest: baseDigest,
      timeAnchor: receiptAnchor()
    )
    try expectJournalFailure {
      _ = try attempted.advancing(
        to: .receiptValidatedQueueCommitPending,
        validatedReceipt: sameResult
      )
    }
    let advancedAnchor = TacuaServerTimeAnchor(
      issuedAt: "2026-07-21T10:05:00Z",
      issuedEpochMilliseconds: 1_784_628_300_000,
      uptimeMillisecondsAtIssue: 400_000,
      bootSessionID: "boot_resume_001",
      minimumEpochMilliseconds: 1_784_628_301_000
    )
    let advancedRecovery = TacuaSDKResumeReceiptRecovery(
      credentialCapability: .active,
      replayCompletionID: nil,
      credentialExpiresAt: "2026-08-21T10:00:00Z",
      responseDigest: responseDigest,
      resultQueueDigest: resultDigest,
      timeAnchor: advancedAnchor
    )
    try expectJournalFailure {
      _ = try attempted.advancing(
        to: .receiptValidatedQueueCommitPending,
        validatedReceipt: advancedRecovery
      )
    }
  }

  private static func completedReceiptIsBoundToOneCompletion() throws {
    let completionID = "completion_resume_001"
    let prepared = try completedJournal(completionID: completionID)
    let attempted = try prepared.advancing(
      to: .exchangeOutcomeUnknown,
      requestDigest: requestDigest
    )
    let recovery = TacuaSDKResumeReceiptRecovery(
      credentialCapability: .completionReplayOrDeleteOnly,
      replayCompletionID: completionID,
      credentialExpiresAt: "2026-08-21T10:00:00Z",
      responseDigest: responseDigest,
      resultQueueDigest: resultDigest,
      timeAnchor: receiptAnchor()
    )
    let validated = try attempted.advancing(
      to: .receiptValidatedQueueCommitPending,
      validatedReceipt: recovery
    )
    try require(
      validated.validatedReceipt?.credentialCapability == .completionReplayOrDeleteOnly,
      "Completed resume was not upload-disabled"
    )

    let wrongReplay = TacuaSDKResumeReceiptRecovery(
      credentialCapability: .completionReplayOrDeleteOnly,
      replayCompletionID: "completion_other_001",
      credentialExpiresAt: "2026-08-21T10:00:00Z",
      responseDigest: responseDigest,
      resultQueueDigest: resultDigest,
      timeAnchor: receiptAnchor()
    )
    try expectJournalFailure {
      _ = try attempted.advancing(
        to: .receiptValidatedQueueCommitPending,
        validatedReceipt: wrongReplay
      )
    }
    let reenabled = TacuaSDKResumeReceiptRecovery(
      credentialCapability: .active,
      replayCompletionID: nil,
      credentialExpiresAt: "2026-08-21T10:00:00Z",
      responseDigest: responseDigest,
      resultQueueDigest: resultDigest,
      timeAnchor: receiptAnchor()
    )
    try expectJournalFailure {
      _ = try attempted.advancing(
        to: .receiptValidatedQueueCommitPending,
        validatedReceipt: reenabled
      )
    }
    try expectJournalFailure {
      _ = try TacuaSDKResumeJournal(
        localSessionID: "local_resume_invalid_completed",
        baseQueueDigest: baseDigest,
        previousCredentialID: "credential_previous_001",
        remoteSessionID: "session_remote_001",
        scopeDigest: scopeDigest,
        expectedSessionState: .completed,
        expectedCompletionID: nil,
        transportConfigurationDigest: transportDigest,
        exchangeID: "exchange_resume_001",
        newCredentialID: "credential_resume_001",
        newCredentialOwnershipDigest: ownershipDigest,
        createdAt: "2026-07-21T10:04:00Z",
        state: .credentialPrepared
      )
    }
  }

  private static func boundedClosedDecodingRejectsMalformedInput() throws {
    let encoded = try receivingJournal().encoded()
    let object = try JSONSerialization.jsonObject(with: encoded)
    let pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted])
    try expectJournalFailure { _ = try TacuaSDKResumeJournal.decode(pretty) }

    guard case .object(var root) = try TacuaCanonicalJSON.parse(encoded) else {
      throw ResumeJournalTestFailure.assertion("Resume journal fixture was not an object")
    }
    root["unexpected"] = .bool(true)
    try expectJournalFailure {
      _ = try TacuaSDKResumeJournal.decode(
        TacuaCanonicalJSON.data(.object(root))
      )
    }

    var wrongOptional = try rootWithoutUnexpected(encoded)
    wrongOptional["request_digest"] = .bool(false)
    try expectJournalFailure {
      _ = try TacuaSDKResumeJournal.decode(
        TacuaCanonicalJSON.data(.object(wrongOptional))
      )
    }
    try expectJournalFailure {
      _ = try TacuaSDKResumeJournal.decode(
        Data(repeating: 0x7b, count: TacuaSDKResumeJournal.maximumEncodedBytes + 1)
      )
    }
    var invalidBoot = try rootWithoutUnexpected(
      try receivingJournal()
        .advancing(to: .exchangeOutcomeUnknown, requestDigest: requestDigest)
        .advancing(
          to: .receiptValidatedQueueCommitPending,
          validatedReceipt: receivingRecovery()
        ).encoded()
    )
    guard case .object(var receipt)? = invalidBoot["validated_receipt"],
      case .object(var anchor)? = receipt["time_anchor"]
    else { throw ResumeJournalTestFailure.assertion("Missing receipt fixture") }
    anchor["boot_session_id"] = .string("unavailable")
    receipt["time_anchor"] = .object(anchor)
    invalidBoot["validated_receipt"] = .object(receipt)
    try expectJournalFailure {
      _ = try TacuaSDKResumeJournal.decode(
        TacuaCanonicalJSON.data(.object(invalidBoot))
      )
    }
  }

  private static func fileStoreIsPrivateAtomicAndOwnerChecked() throws {
    let parent = FileManager.default.temporaryDirectory.appendingPathComponent(
      "tacua-resume-journal-tests-\(UUID().uuidString)",
      isDirectory: true
    )
    let root = parent.appendingPathComponent("resume-journals", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: parent) }
    let store = try TacuaSDKResumeJournalFileStore(rootDirectory: root)

    let initialRootMode = try mode(root)
    try require(initialRootMode == 0o700, "Resume journal directory is not private")
    try requireJournalError(.invalidSessionID) {
      _ = try store.load(localSessionID: "../escape")
    }

    let blocked = try receivingJournal(localSessionID: "local_resume_blocked_001")
    do {
      try store.createWhileBaseQueueMatches(blocked) {
        throw ResumeJournalTestFailure.forcedBaseQueueMismatch
      }
      throw ResumeJournalTestFailure.assertion("Base-queue assertion failure installed a journal")
    } catch ResumeJournalTestFailure.forcedBaseQueueMismatch {}
    let blockedLoad = try store.load(localSessionID: blocked.localSessionID)
    try require(
      blockedLoad == nil,
      "Failed base-queue assertion published a resume owner"
    )

    let prepared = try receivingJournal(localSessionID: "local_resume_file_001")
    try store.createWhileBaseQueueMatches(prepared) {}
    let fileURL = try store.journalURL(localSessionID: prepared.localSessionID)
    let initialFileMode = try mode(fileURL)
    try require(initialFileMode == 0o600, "Resume journal file is not 0600")
    let preparedLoad = try store.load(localSessionID: prepared.localSessionID)
    try require(
      preparedLoad == prepared,
      "Resume journal file did not round-trip"
    )
    try requireJournalError(.ownershipConflict) { try store.create(prepared) }

    let attempted = try prepared.advancing(
      to: .exchangeOutcomeUnknown,
      requestDigest: requestDigest
    )
    try store.compareAndSwap(expected: prepared, replacement: attempted)
    // Exact installed replacement is accepted to confirm rename-then-fsync ambiguity.
    try store.compareAndSwap(expected: prepared, replacement: attempted)
    let staleReset = try prepared.advancing(to: .credentialPreparedResetPending)
    try requireJournalError(.stateConflict) {
      try store.compareAndSwap(expected: prepared, replacement: staleReset)
    }
    try requireJournalError(.stateConflict) {
      try store.compareAndSwap(expected: attempted, replacement: staleReset)
    }
    try requireJournalError(.stateConflict) { try store.remove(expected: prepared) }

    try FileManager.default.setAttributes(
      [.posixPermissions: 0o644],
      ofItemAtPath: fileURL.path
    )
    _ = try store.load(localSessionID: prepared.localSessionID)
    let repairedFileMode = try mode(fileURL)
    try require(repairedFileMode == 0o600, "Resume load did not repair file permissions")

    let orphan = root.appendingPathComponent(
      ".\(prepared.localSessionID).resume-v1.\(String(repeating: "a", count: 32)).tmp"
    )
    try Data("interrupted".utf8).write(to: orphan)
    let unrelated = root.appendingPathComponent(
      ".\(prepared.localSessionID).resume-v1.not-ours.tmp"
    )
    try Data("retain".utf8).write(to: unrelated)
    _ = try store.load(localSessionID: prepared.localSessionID)
    try require(
      !FileManager.default.fileExists(atPath: orphan.path),
      "Session-locked load retained an interrupted staged file"
    )
    try require(
      FileManager.default.fileExists(atPath: unrelated.path),
      "Temp scavenging removed an unrecognized file"
    )

    let recovery = try receivingRecovery()
    let validated = try attempted.advancing(
      to: .receiptValidatedQueueCommitPending,
      validatedReceipt: recovery
    )
    try store.compareAndSwap(expected: attempted, replacement: validated)
    let validatedLoad = try store.load(localSessionID: prepared.localSessionID)
    try require(
      validatedLoad == validated,
      "Validated CAS was not durable"
    )
    try store.remove(expected: validated)
    try store.confirmAbsent(expected: validated)
    let removedLoad = try store.load(localSessionID: prepared.localSessionID)
    try require(
      removedLoad == nil,
      "Expected-owner remove retained the resume journal"
    )

    let newer = try receivingJournal(localSessionID: prepared.localSessionID)
    try store.create(newer)
    try requireJournalError(.stateConflict) { try store.confirmAbsent(expected: validated) }
    try store.remove(expected: newer)

    let outside = parent.appendingPathComponent("outside.json")
    try prepared.encoded().write(to: outside)
    try FileManager.default.createSymbolicLink(at: fileURL, withDestinationURL: outside)
    try expectJournalFailure { _ = try store.load(localSessionID: prepared.localSessionID) }
    try FileManager.default.removeItem(at: fileURL)

    try FileManager.default.setAttributes(
      [.posixPermissions: 0o755],
      ofItemAtPath: root.path
    )
    _ = try TacuaSDKResumeJournalFileStore(rootDirectory: root)
    let repairedRootMode = try mode(root)
    try require(
      repairedRootMode == 0o700,
      "Store initialization did not repair directory permissions"
    )
  }

  private static func receivingJournal(
    localSessionID: String = "local_resume_001"
  ) throws -> TacuaSDKResumeJournal {
    try TacuaSDKResumeJournal(
      localSessionID: localSessionID,
      baseQueueDigest: baseDigest,
      previousCredentialID: "credential_previous_001",
      remoteSessionID: "session_remote_001",
      scopeDigest: scopeDigest,
      expectedSessionState: .receiving,
      expectedCompletionID: nil,
      transportConfigurationDigest: transportDigest,
      exchangeID: "exchange_resume_001",
      newCredentialID: "credential_resume_001",
      newCredentialOwnershipDigest: ownershipDigest,
      createdAt: "2026-07-21T10:04:00Z",
      state: .credentialPrepared
    )
  }

  private static func completedJournal(
    completionID: String
  ) throws -> TacuaSDKResumeJournal {
    try TacuaSDKResumeJournal(
      localSessionID: "local_resume_completed_001",
      baseQueueDigest: baseDigest,
      previousCredentialID: "credential_previous_001",
      remoteSessionID: "session_remote_001",
      scopeDigest: scopeDigest,
      expectedSessionState: .completed,
      expectedCompletionID: completionID,
      transportConfigurationDigest: transportDigest,
      exchangeID: "exchange_resume_completed_001",
      newCredentialID: "credential_resume_completed_001",
      newCredentialOwnershipDigest: ownershipDigest,
      createdAt: "2026-07-21T10:04:00Z",
      state: .credentialPrepared
    )
  }

  private static func receivingRecovery() throws -> TacuaSDKResumeReceiptRecovery {
    TacuaSDKResumeReceiptRecovery(
      credentialCapability: .active,
      replayCompletionID: nil,
      credentialExpiresAt: "2026-08-21T10:00:00Z",
      responseDigest: responseDigest,
      resultQueueDigest: resultDigest,
      timeAnchor: receiptAnchor()
    )
  }

  private static func receiptAnchor() -> TacuaServerTimeAnchor {
    TacuaServerTimeAnchor(
      issuedAt: "2026-07-21T10:05:00Z",
      issuedEpochMilliseconds: 1_784_628_300_000,
      uptimeMillisecondsAtIssue: 400_000,
      bootSessionID: "boot_resume_001",
      minimumEpochMilliseconds: 1_784_628_300_000
    )
  }

  private static func rootWithoutUnexpected(
    _ data: Data
  ) throws -> [String: TacuaJSONValue] {
    guard case .object(let root) = try TacuaCanonicalJSON.parse(data) else {
      throw ResumeJournalTestFailure.assertion("Expected an object fixture")
    }
    return root
  }

  private static func mode(_ url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
  }

  private static func digest(_ character: Character) -> String {
    "sha256:" + String(repeating: String(character), count: 64)
  }
}
