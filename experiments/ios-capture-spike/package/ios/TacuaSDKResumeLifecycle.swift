// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaSDKResumeLifecycleError: Error, Equatable {
  case invalidInput
  case resumeAlreadyInProgress
  case queueNotFound
  case resumeNotAuthorized(TacuaSDKResumeRequirementReason)
  case startRecoveryActionRequired
  case recoveryActionRequired(TacuaSDKResumeJournalState)
  case credentialPreparationFailed
  case credentialCleanupRequired
  case launchRequestRejected
  case exchangeOutcomeUnknown
  case receiptCommitPending
  case journalCleanupRequired
  case nothingToRecover
  case preparedResetOnly
  case recoveryStateMismatch
  case persistenceFailure

  var code: String {
    switch self {
    case .invalidInput: return "ERR_TACUA_BACKEND_RESUME_INPUT"
    case .resumeAlreadyInProgress: return "ERR_TACUA_BACKEND_RESUME_BUSY"
    case .queueNotFound: return "ERR_TACUA_BACKEND_RESUME_QUEUE_MISSING"
    case .resumeNotAuthorized: return "ERR_TACUA_BACKEND_RESUME_NOT_AUTHORIZED"
    case .startRecoveryActionRequired: return "ERR_TACUA_BACKEND_START_RECOVERY_REQUIRED"
    case .recoveryActionRequired: return "ERR_TACUA_BACKEND_RESUME_RECOVERY_REQUIRED"
    case .credentialPreparationFailed: return "ERR_TACUA_BACKEND_RESUME_CREDENTIAL"
    case .credentialCleanupRequired: return "ERR_TACUA_BACKEND_RESUME_CREDENTIAL_CLEANUP"
    case .launchRequestRejected: return "ERR_TACUA_BACKEND_RESUME_REQUEST"
    case .exchangeOutcomeUnknown: return "ERR_TACUA_BACKEND_RESUME_OUTCOME_UNKNOWN"
    case .receiptCommitPending: return "ERR_TACUA_BACKEND_RESUME_RECEIPT_COMMIT_PENDING"
    case .journalCleanupRequired: return "ERR_TACUA_BACKEND_RESUME_JOURNAL_CLEANUP"
    case .nothingToRecover: return "ERR_TACUA_BACKEND_RESUME_NOTHING_TO_RECOVER"
    case .preparedResetOnly: return "ERR_TACUA_BACKEND_RESUME_PREPARED_RESET_ONLY"
    case .recoveryStateMismatch: return "ERR_TACUA_BACKEND_RESUME_RECOVERY_MISMATCH"
    case .persistenceFailure: return "ERR_TACUA_BACKEND_RESUME_PERSISTENCE"
    }
  }

  var message: String {
    switch self {
    case .invalidInput:
      return "The backend RESUME input does not satisfy the frozen protocol."
    case .resumeAlreadyInProgress:
      return "A backend RESUME lifecycle operation is already in progress for this local session."
    case .queueNotFound:
      return "No committed backend transport queue exists for this local session."
    case .resumeNotAuthorized(let reason):
      return "The durable queue cannot consume a RESUME launch (\(reason.rawValue))."
    case .startRecoveryActionRequired:
      return "Resolve the existing backend START recovery state before resuming this session."
    case .recoveryActionRequired(let state):
      return "Resolve the existing backend RESUME recovery state before another exchange (\(state.rawValue))."
    case .credentialPreparationFailed:
      return "Tacua could not prepare the replacement device-only backend credential."
    case .credentialCleanupRequired:
      return "Tacua could not finish removing a locally prepared replacement credential."
    case .launchRequestRejected:
      return "The approved launch could not produce a valid frozen-protocol RESUME request; request a fresh reviewer launch."
    case .exchangeOutcomeUnknown:
      return "The backend RESUME outcome is unknown. The queue is quarantined because either the previous or replacement credential may be current."
    case .receiptCommitPending:
      return "The RESUME receipt was validated, but the durable queue rotation is pending recovery."
    case .journalCleanupRequired:
      return "The resumed queue is durable, but recovery-journal removal could not be confirmed."
    case .nothingToRecover:
      return "There is no validated backend RESUME receipt to recover."
    case .preparedResetOnly:
      return "Only a replacement credential prepared before network intent can be reset locally."
    case .recoveryStateMismatch:
      return "The backend RESUME journal and durable queue do not describe the same transition."
    case .persistenceFailure:
      return "Tacua could not read or write backend RESUME recovery state."
    }
  }
}

struct TacuaSDKResumeSessionInput {
  static let maximumArtifactBytes = TacuaSDKStartSessionInput.maximumArtifactBytes

  let approvedLaunchID: String
  let localSessionID: String
  let buildIdentityJSON: Data
  let scopeJSON: Data
  let requestedAt: String
}

struct TacuaSDKResumedSession: Equatable {
  let localSessionID: String
  let remoteSessionID: String
  let scopeDigest: String
  let credentialID: String
  let credentialExpiresAt: String
  let rawMediaExpiresAt: String
  let backendSessionState: TacuaSDKResumeExpectedSessionState
  let credentialCapability: TacuaTransportCredentialCapability
  let replayCompletionID: String?
  let credentialAvailability: TacuaCredentialAvailability
  let queueSchemaVersion: Int
  let pendingRevokedCredentialRemovalCount: Int
  let resumeRequired: Bool
}

enum TacuaSDKResumeRecoveryState: String, Equatable {
  case none
  case credentialPrepared = "credential_prepared"
  case credentialPreparedResetPending = "credential_prepared_reset_pending"
  case exchangeOutcomeUnknown = "exchange_outcome_unknown"
  case receiptValidatedQueueCommitPending = "receipt_validated_queue_commit_pending"
  case queueConflictRequiresReconciliation = "queue_conflict_requires_reconciliation"
  case queueCommitted = "queue_committed"
}

struct TacuaSDKResumeRecoveryStatus: Equatable {
  let localSessionID: String
  let state: TacuaSDKResumeRecoveryState
  let remoteCredentialMayExist: Bool
  let queueUsable: Bool
  let canRecoverWithoutLaunch: Bool
  let canResetPreparedCredential: Bool
  let requiresReconciliation: Bool
}

protocol TacuaSDKResumeQueueStoring: TacuaSDKStartQueueStoring {
  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws
}

extension TacuaTransportQueueFileStore: TacuaSDKResumeQueueStoring {}

final class TacuaSDKResumeLifecycleCoordinator {
  /// A validated receipt can replace the dry-run anchor with three JSON integers selected after
  /// network intent: two signed Int64 epoch fields (at most 20 bytes each) and one non-negative
  /// Int64 uptime field (at most 19 bytes). Each dry-run integer already occupies at least one
  /// byte, so 19 + 19 + 18 bytes is a conservative upper bound on encoded queue growth.
  private static let maximumServerAnchorEncodingGrowthBytes = 56

  private let configuration: TacuaBackendConfiguration
  private let consentGate: TacuaLaunchConsentGate
  private let credentialFactory: TacuaCredentialFactory
  private let exchanger: TacuaSDKLaunchExchanging
  private let queueStore: TacuaSDKResumeQueueStoring
  private let startJournalStore: TacuaSDKStartJournalPersisting
  private let journalStore: TacuaSDKResumeJournalPersisting
  private let retentionChecker: TacuaSDKLocalRetentionChecking?
  private let clock: TacuaMonotonicClock
  private let preparedQueueEncodedByteLimit: Int
  private let operationLock = NSLock()
  private var activeLocalSessionIDs = Set<String>()

  init(
    configuration: TacuaBackendConfiguration,
    consentGate: TacuaLaunchConsentGate,
    credentialFactory: TacuaCredentialFactory,
    exchanger: TacuaSDKLaunchExchanging,
    queueStore: TacuaSDKResumeQueueStoring,
    startJournalStore: TacuaSDKStartJournalPersisting,
    journalStore: TacuaSDKResumeJournalPersisting,
    retentionChecker: TacuaSDKLocalRetentionChecking? = nil,
    clock: TacuaMonotonicClock = TacuaSystemMonotonicClock(),
    preparedQueueEncodedByteLimit: Int = TacuaTransportQueueV3.maximumEncodedBytes
  ) {
    precondition(
      preparedQueueEncodedByteLimit > Self.maximumServerAnchorEncodingGrowthBytes
        && preparedQueueEncodedByteLimit <= TacuaTransportQueueV3.maximumEncodedBytes
    )
    self.configuration = configuration
    self.consentGate = consentGate
    self.credentialFactory = credentialFactory
    self.exchanger = exchanger
    self.queueStore = queueStore
    self.startJournalStore = startJournalStore
    self.journalStore = journalStore
    self.retentionChecker = retentionChecker
    self.clock = clock
    self.preparedQueueEncodedByteLimit = preparedQueueEncodedByteLimit
  }

  func resume(_ input: TacuaSDKResumeSessionInput) async throws -> TacuaSDKResumedSession {
    try reserve(input.localSessionID)
    defer { release(input.localSessionID) }
    let artifacts = try parseInput(input)
    let lifecycleLease = try acquireLifecycleLease(localSessionID: input.localSessionID)
    defer { lifecycleLease.release() }

    let baseQueue: TacuaTransportQueueV3
    let requirement: TacuaSDKResumeRequirement
    do {
      try requireNoStartRecovery(localSessionID: input.localSessionID)
      if let existing = try journalStore.load(localSessionID: input.localSessionID) {
        throw TacuaSDKResumeLifecycleError.recoveryActionRequired(existing.state)
      }
      guard let queue = try queueStore.load(localSessionID: input.localSessionID) else {
        throw TacuaSDKResumeLifecycleError.queueNotFound
      }
      baseQueue = queue
      requirement = try validateArtifactsAndRequirement(
        input: input,
        artifacts: artifacts,
        queue: queue
      )
    } catch let error as TacuaSDKResumeLifecycleError {
      throw error
    } catch {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }

    guard requirement.kind == .resumeSession,
      let expectedStateRaw = requirement.expectedSessionState,
      let expectedState = TacuaSDKResumeExpectedSessionState(rawValue: expectedStateRaw),
      let previousCredentialID = baseQueue.currentCredentialID,
      let remoteSessionID = baseQueue.remoteSessionID,
      let scopeDigest = baseQueue.scopeDigest
    else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }

    let baseQueueDigest: String
    do { baseQueueDigest = TacuaCanonicalJSON.digest(data: try baseQueue.encoded()) }
    catch { throw TacuaSDKResumeLifecycleError.persistenceFailure }

    var preparedJournal: TacuaSDKResumeJournal?
    let preparedCredential: TacuaPreparedCredential
    do {
      preparedCredential = try credentialFactory.prepare {
        exchangeID, credentialID, ownershipDigest in
        let journal = try TacuaSDKResumeJournal(
          localSessionID: input.localSessionID,
          baseQueueDigest: baseQueueDigest,
          previousCredentialID: previousCredentialID,
          remoteSessionID: remoteSessionID,
          scopeDigest: scopeDigest,
          expectedSessionState: expectedState,
          expectedCompletionID: requirement.expectedCompletionID,
          transportConfigurationDigest: self.configuration.configurationDigest,
          buildIdentityJSON: String(decoding: artifacts.buildIdentityJSON, as: UTF8.self),
          captureScopeJSON: String(decoding: artifacts.scopeJSON, as: UTF8.self),
          exchangeID: exchangeID,
          newCredentialID: credentialID,
          newCredentialOwnershipDigest: ownershipDigest,
          createdAt: input.requestedAt,
          state: .credentialPrepared
        )
        try self.journalStore.createWhileBaseQueueMatches(journal) {
          guard let current = try self.queueStore.load(localSessionID: input.localSessionID),
            current == baseQueue,
            TacuaCanonicalJSON.digest(data: try current.encoded()) == baseQueueDigest
          else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
          try self.requireNoStartRecovery(localSessionID: input.localSessionID)
        }
        preparedJournal = journal
      }
    } catch {
      if let journal = preparedJournal {
        do {
          try credentialFactory.removeIfOwned(
            credentialID: journal.newCredentialID,
            ownershipDigest: journal.newCredentialOwnershipDigest
          )
          try removeJournalDurably(journal)
        } catch {
          throw TacuaSDKResumeLifecycleError.credentialCleanupRequired
        }
      }
      if let existing = try? journalStore.load(localSessionID: input.localSessionID) {
        throw TacuaSDKResumeLifecycleError.recoveryActionRequired(existing.state)
      }
      throw TacuaSDKResumeLifecycleError.credentialPreparationFailed
    }
    guard let initialJournal = preparedJournal else {
      try? credentialFactory.remove(credentialID: preparedCredential.credentialID)
      throw TacuaSDKResumeLifecycleError.credentialPreparationFailed
    }

    do {
      // Reconfirm journal ownership after Keychain creation. A second process cannot reset this
      // credential while the shared lifecycle lease is held, and a stale/missing journal stops us
      // before consent is consumed.
      try transitionDurably(expected: initialJournal, replacement: initialJournal)
    } catch {
      do {
        try credentialFactory.removeIfOwned(
          credentialID: initialJournal.newCredentialID,
          ownershipDigest: initialJournal.newCredentialOwnershipDigest
        )
      } catch {
        throw TacuaSDKResumeLifecycleError.credentialCleanupRequired
      }
      throw error
    }

    do {
      // Everything below this point can reach the backend. Dry-run the exact structural queue
      // rotation first, using the generated credential ID, so deterministic clock, history,
      // credential-bound, and encoded-size failures never turn a valid remote rotation into an
      // unrecoverable outcome-unknown journal.
      try validatePreparedTransition(base: baseQueue, journal: initialJournal)
    } catch {
      do { try cleanupPreparedCredential(initialJournal) }
      catch { throw error }
      throw TacuaSDKResumeLifecycleError.invalidInput
    }

    let request: TacuaTransientLaunchRequest
    do {
      request = try TacuaSDKBackendRequests.launch(
        preparedCredential: preparedCredential,
        approvedLaunchID: input.approvedLaunchID,
        consentGate: consentGate,
        exchangeKind: "resume_session",
        expectedSessionID: remoteSessionID,
        expectedSessionState: expectedState.rawValue,
        expectedCompletionID: requirement.expectedCompletionID,
        previousCredentialID: previousCredentialID,
        buildIdentity: artifacts.buildIdentity,
        scope: artifacts.scope,
        requestedAt: input.requestedAt,
        configuration: configuration
      )
      guard try TacuaSDKBackendProtocol.validateRequest(
        request.canonicalData,
        expectedTransportConfigurationDigest: configuration.configurationDigest
      ) == .launch else { throw TacuaSDKResumeLifecycleError.launchRequestRejected }
    } catch {
      try cleanupPreparedCredential(initialJournal)
      throw TacuaSDKResumeLifecycleError.launchRequestRejected
    }

    let attemptedJournal: TacuaSDKResumeJournal
    do {
      attemptedJournal = try initialJournal.advancing(
        to: .exchangeOutcomeUnknown,
        requestDigest: request.requestDigest
      )
      // Publish uncertainty before network I/O. From this point on no local API may delete the
      // replacement credential or release the old queue for transport.
      try transitionDurably(expected: initialJournal, replacement: attemptedJournal)
    } catch let error as TacuaSDKResumeLifecycleError {
      throw error
    } catch {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }

    let receipt: TacuaValidatedBackendReceipt
    do {
      let received = try await exchanger.exchange(request)
      let independent = try TacuaSDKBackendProtocol.validateResponse(
        received.canonicalResponse,
        forCanonicalRequest: request.canonicalData,
        minimumLaunchReceiptTimestamp: baseQueue.timeAnchor.map {
          TacuaProtocolTimestamp.format(milliseconds: $0.minimumEpochMilliseconds)
        }
      )
      guard independent == received,
        received.operationKind == .launch,
        received.operationID == preparedCredential.exchangeID,
        received.remoteSessionID == remoteSessionID,
        received.scopeDigest == scopeDigest,
        let transition = received.credentialTransition,
        transition.credentialID == preparedCredential.credentialID,
        transition.capability == expectedCapability(for: expectedState),
        transition.replayCompletionID == requirement.expectedCompletionID
      else { throw TacuaSDKResumeLifecycleError.exchangeOutcomeUnknown }
      receipt = received
    } catch {
      throw TacuaSDKResumeLifecycleError.exchangeOutcomeUnknown
    }

    let candidate: TacuaTransportQueueV3
    let recovery: TacuaSDKResumeReceiptRecovery
    do {
      guard let transition = receipt.credentialTransition else {
        throw TacuaSDKResumeLifecycleError.recoveryStateMismatch
      }
      let timeAnchor = try TacuaServerTimeAnchor.establish(
        issuedAt: receipt.authoritativeTimestamp,
        clock: clock
      )
      if let previousAnchor = baseQueue.timeAnchor {
        guard timeAnchor.issuedEpochMilliseconds
          >= previousAnchor.minimumEpochMilliseconds
        else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
      }
      var queue = baseQueue
      try queue.bindDurableSessionArtifacts(artifacts)
      try queue.applyRecoveredResume(
        expectedCurrentCredentialID: previousCredentialID,
        newCredentialID: preparedCredential.credentialID,
        transportConfigurationDigest: configuration.configurationDigest,
        expiresAt: transition.expiresAt,
        capability: transition.capability,
        replayCompletionID: transition.replayCompletionID,
        timeAnchor: timeAnchor
      )
      try queue.validate()
      candidate = queue
      recovery = TacuaSDKResumeReceiptRecovery(
        credentialCapability: transition.capability,
        replayCompletionID: transition.replayCompletionID,
        credentialExpiresAt: transition.expiresAt,
        responseDigest: receipt.responseDigest,
        resultQueueDigest: TacuaCanonicalJSON.digest(data: try queue.encoded()),
        timeAnchor: timeAnchor
      )
    } catch {
      // The backend response was received but we cannot safely make its authority durable. Keep
      // the pre-network outcome-unknown journal and quarantine both credential possibilities.
      throw TacuaSDKResumeLifecycleError.exchangeOutcomeUnknown
    }

    let receiptJournal: TacuaSDKResumeJournal
    do {
      receiptJournal = try attemptedJournal.advancing(
        to: .receiptValidatedQueueCommitPending,
        validatedReceipt: recovery
      )
      try transitionDurably(expected: attemptedJournal, replacement: receiptJournal)
    } catch {
      throw TacuaSDKResumeLifecycleError.exchangeOutcomeUnknown
    }

    do {
      try commitQueueDurably(
        base: baseQueue,
        replacement: candidate,
        journal: receiptJournal
      )
    } catch {
      throw TacuaSDKResumeLifecycleError.receiptCommitPending
    }
    do { try removeJournalDurably(receiptJournal) }
    catch { throw TacuaSDKResumeLifecycleError.journalCleanupRequired }
    // RESUME is the only raw-data lifecycle operation allowed to cross a reboot without a valid
    // local anchor. Its new server receipt has now installed a current-boot anchor; enforce the
    // immutable START deadline before returning any renewed capture/transport authority.
    try retentionChecker?.requireActiveHoldingLifecycleLease(
      localSessionID: input.localSessionID
    )
    return try finishCommittedQueue(candidate)
  }

  func recoveryStatus(localSessionID: String) throws -> TacuaSDKResumeRecoveryStatus {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
    do {
      try requireNoStartRecovery(localSessionID: localSessionID)
      let journal = try journalStore.load(localSessionID: localSessionID)
      let queue = try queueStore.load(localSessionID: localSessionID)
      guard let journal else {
        return status(
          localSessionID: localSessionID,
          state: queue == nil ? .none : .queueCommitted,
          queue: queue
        )
      }
      do {
        try requireMatchingRecoveryQueue(queue, journal: journal)
      } catch TacuaSDKResumeLifecycleError.recoveryStateMismatch
        where journal.state == .receiptValidatedQueueCommitPending
      {
        return status(
          localSessionID: localSessionID,
          state: .queueConflictRequiresReconciliation
        )
      }
      switch journal.state {
      case .credentialPrepared:
        return status(localSessionID: localSessionID, state: .credentialPrepared)
      case .credentialPreparedResetPending:
        return status(localSessionID: localSessionID, state: .credentialPreparedResetPending)
      case .exchangeOutcomeUnknown:
        return status(localSessionID: localSessionID, state: .exchangeOutcomeUnknown)
      case .receiptValidatedQueueCommitPending:
        return status(
          localSessionID: localSessionID,
          state: .receiptValidatedQueueCommitPending
        )
      }
    } catch let error as TacuaSDKResumeLifecycleError {
      throw error
    } catch {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }
  }

  func recover(localSessionID: String) throws -> TacuaSDKResumedSession {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    do {
      try requireNoStartRecovery(localSessionID: localSessionID)
      guard let journal = try journalStore.load(localSessionID: localSessionID) else {
        throw TacuaSDKResumeLifecycleError.nothingToRecover
      }
      guard journal.state == .receiptValidatedQueueCommitPending,
        let receiptRecovery = journal.validatedReceipt,
        let current = try queueStore.load(localSessionID: localSessionID)
      else {
        if journal.state == .exchangeOutcomeUnknown {
          throw TacuaSDKResumeLifecycleError.exchangeOutcomeUnknown
        }
        throw TacuaSDKResumeLifecycleError.recoveryActionRequired(journal.state)
      }
      let currentDigest = TacuaCanonicalJSON.digest(data: try current.encoded())
      let candidate: TacuaTransportQueueV3
      if currentDigest == journal.baseQueueDigest {
        candidate = try resumedQueue(base: current, journal: journal)
        guard TacuaCanonicalJSON.digest(data: try candidate.encoded())
          == receiptRecovery.resultQueueDigest
        else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
      } else if currentDigest == receiptRecovery.resultQueueDigest {
        try requireMatchingResultQueue(current, journal: journal)
        candidate = current
      } else {
        throw TacuaSDKResumeLifecycleError.recoveryStateMismatch
      }
      try commitQueueDurably(base: current, replacement: candidate, journal: journal)
      try removeJournalDurably(journal)
      try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
      return try finishCommittedQueue(candidate)
    } catch let error as TacuaSDKResumeLifecycleError {
      throw error
    } catch {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }
  }

  func resetPrepared(localSessionID: String) throws {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    do {
      try requireNoStartRecovery(localSessionID: localSessionID)
      guard let journal = try journalStore.load(localSessionID: localSessionID) else {
        throw TacuaSDKResumeLifecycleError.nothingToRecover
      }
      guard journal.state == .credentialPrepared
        || journal.state == .credentialPreparedResetPending
      else { throw TacuaSDKResumeLifecycleError.preparedResetOnly }
      let claimed = try journal.advancing(to: .credentialPreparedResetPending)
      try transitionDurably(expected: journal, replacement: claimed)
      do {
        try credentialFactory.removeIfOwned(
          credentialID: claimed.newCredentialID,
          ownershipDigest: claimed.newCredentialOwnershipDigest
        )
        try removeJournalDurably(claimed)
      } catch {
        throw TacuaSDKResumeLifecycleError.credentialCleanupRequired
      }
    } catch let error as TacuaSDKResumeLifecycleError {
      throw error
    } catch {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }
  }

  private func parseInput(_ input: TacuaSDKResumeSessionInput) throws
    -> TacuaDurableSessionArtifacts
  {
    guard !input.approvedLaunchID.isEmpty,
      input.buildIdentityJSON.count <= TacuaSDKResumeSessionInput.maximumArtifactBytes,
      input.scopeJSON.count <= TacuaSDKResumeSessionInput.maximumArtifactBytes
    else { throw TacuaSDKResumeLifecycleError.invalidInput }
    do {
      _ = try TacuaTransportQueueV3(localSessionID: input.localSessionID)
      return try TacuaDurableSessionArtifacts.canonicalizing(
        buildIdentityJSON: input.buildIdentityJSON,
        scopeJSON: input.scopeJSON
      )
    } catch {
      throw TacuaSDKResumeLifecycleError.invalidInput
    }
  }

  private func validateArtifactsAndRequirement(
    input: TacuaSDKResumeSessionInput,
    artifacts: TacuaDurableSessionArtifacts,
    queue: TacuaTransportQueueV3
  ) throws -> TacuaSDKResumeRequirement {
    let requirement = resumeRequirement(queue)
    guard requirement.kind == .resumeSession,
      let remoteSessionID = queue.remoteSessionID,
      let previousCredentialID = queue.currentCredentialID,
      let expectedSessionState = requirement.expectedSessionState,
      artifacts.scopeDigest == queue.scopeDigest
    else {
      if requirement.kind != .resumeSession {
        throw TacuaSDKResumeLifecycleError.resumeNotAuthorized(requirement.reason)
      }
      throw TacuaSDKResumeLifecycleError.invalidInput
    }
    do {
      if let durable = try queue.durableSessionArtifacts() {
        guard durable.buildIdentityJSON == artifacts.buildIdentityJSON,
          durable.scopeJSON == artifacts.scopeJSON
        else { throw TacuaSDKResumeLifecycleError.invalidInput }
      }
      try TacuaSDKBackendRequests.validateResumeArtifacts(
        expectedSessionID: remoteSessionID,
        expectedSessionState: expectedSessionState,
        expectedCompletionID: requirement.expectedCompletionID,
        previousCredentialID: previousCredentialID,
        buildIdentity: artifacts.buildIdentity,
        scope: artifacts.scope,
        requestedAt: input.requestedAt,
        configuration: configuration
      )
      try configuration.validateBuildIdentityBinding(artifacts.buildIdentity)
      return requirement
    } catch {
      throw TacuaSDKResumeLifecycleError.invalidInput
    }
  }

  private func resumeRequirement(_ queue: TacuaTransportQueueV3)
    -> TacuaSDKResumeRequirement
  {
    let availability = TacuaCredentialAvailability.inspect(
      credentialID: queue.currentCredentialID,
      store: credentialFactory.credentialStore
    )
    return TacuaSDKResumeRequirement.evaluate(
      queue: queue,
      transportConfigurationDigest: configuration.configurationDigest,
      availability: availability,
      clock: clock
    )
  }

  private func expectedCapability(
    for state: TacuaSDKResumeExpectedSessionState
  ) -> TacuaTransportCredentialCapability {
    state == .receiving ? .active : .completionReplayOrDeleteOnly
  }

  private func resumedQueue(
    base: TacuaTransportQueueV3,
    journal: TacuaSDKResumeJournal
  ) throws -> TacuaTransportQueueV3 {
    guard let receipt = journal.validatedReceipt else {
      throw TacuaSDKResumeLifecycleError.recoveryStateMismatch
    }
    var candidate = base
    if let artifacts = try journal.durableSessionArtifacts() {
      try candidate.bindDurableSessionArtifacts(artifacts)
    }
    try candidate.applyRecoveredResume(
      expectedCurrentCredentialID: journal.previousCredentialID,
      newCredentialID: journal.newCredentialID,
      transportConfigurationDigest: journal.transportConfigurationDigest,
      expiresAt: receipt.credentialExpiresAt,
      capability: receipt.credentialCapability,
      replayCompletionID: receipt.replayCompletionID,
      timeAnchor: receipt.timeAnchor
    )
    return candidate
  }

  private func validatePreparedTransition(
    base: TacuaTransportQueueV3,
    journal: TacuaSDKResumeJournal
  ) throws {
    let requestedEpoch = TacuaProtocolTimestamp.parseMilliseconds(journal.createdAt)
    guard let requestedEpoch else { throw TacuaSDKResumeLifecycleError.invalidInput }
    let issueEpoch = max(base.timeAnchor?.minimumEpochMilliseconds ?? requestedEpoch, requestedEpoch)
    guard issueEpoch <= Int64.max - 31_536_000_000 else {
      throw TacuaSDKResumeLifecycleError.invalidInput
    }
    let anchor = try TacuaServerTimeAnchor.establish(
      issuedAt: TacuaProtocolTimestamp.format(milliseconds: issueEpoch),
      clock: clock
    )
    var candidate = base
    if let artifacts = try journal.durableSessionArtifacts() {
      try candidate.bindDurableSessionArtifacts(artifacts)
    }
    try candidate.applyRecoveredResume(
      expectedCurrentCredentialID: journal.previousCredentialID,
      newCredentialID: journal.newCredentialID,
      transportConfigurationDigest: journal.transportConfigurationDigest,
      expiresAt: TacuaProtocolTimestamp.format(
        milliseconds: issueEpoch + 31_536_000_000
      ),
      capability: expectedCapability(for: journal.expectedSessionState),
      replayCompletionID: journal.expectedCompletionID,
      timeAnchor: anchor
    )
    let encoded = try candidate.encoded()
    guard encoded.count
      <= preparedQueueEncodedByteLimit
        - Self.maximumServerAnchorEncodingGrowthBytes
    else { throw TacuaSDKResumeLifecycleError.invalidInput }
  }

  private func commitQueueDurably(
    base: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3,
    journal: TacuaSDKResumeJournal
  ) throws {
    guard let receipt = journal.validatedReceipt,
      TacuaCanonicalJSON.digest(data: try replacement.encoded()) == receipt.resultQueueDigest
    else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
    do {
      try queueStore.compareAndSwap(expected: base, replacement: replacement)
      return
    } catch {}
    guard let current = try? queueStore.load(localSessionID: journal.localSessionID) else {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }
    if current == replacement {
      do {
        try queueStore.compareAndSwap(expected: replacement, replacement: replacement)
        return
      } catch { throw TacuaSDKResumeLifecycleError.persistenceFailure }
    }
    if current == base {
      do {
        try queueStore.compareAndSwap(expected: base, replacement: replacement)
        return
      } catch { throw TacuaSDKResumeLifecycleError.persistenceFailure }
    }
    throw TacuaSDKResumeLifecycleError.recoveryStateMismatch
  }

  private func requireMatchingRecoveryQueue(
    _ queue: TacuaTransportQueueV3?,
    journal: TacuaSDKResumeJournal
  ) throws {
    switch journal.state {
    case .credentialPrepared, .credentialPreparedResetPending:
      // No network intent exists, so reset remains safe even if another queue writer from an
      // older SDK changed or removed the baseline before cross-gating was introduced.
      return
    case .exchangeOutcomeUnknown:
      // A third queue state does not make local reset safe; it still requires reconciliation.
      return
    case .receiptValidatedQueueCommitPending:
      guard let queue else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
      let digest = TacuaCanonicalJSON.digest(data: try queue.encoded())
      guard let resultDigest = journal.validatedReceipt?.resultQueueDigest,
        digest == journal.baseQueueDigest || digest == resultDigest
      else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
      if digest == resultDigest { try requireMatchingResultQueue(queue, journal: journal) }
    }
  }

  private func requireMatchingResultQueue(
    _ queue: TacuaTransportQueueV3,
    journal: TacuaSDKResumeJournal
  ) throws {
    guard let receipt = journal.validatedReceipt,
      queue.localSessionID == journal.localSessionID,
      queue.remoteSessionID == journal.remoteSessionID,
      queue.scopeDigest == journal.scopeDigest,
      queue.transportConfigurationDigest == journal.transportConfigurationDigest,
      queue.currentCredentialID == journal.newCredentialID,
      queue.currentCredentialExpiresAt == receipt.credentialExpiresAt,
      queue.credentialCapability == receipt.credentialCapability,
      queue.pendingRevokedCredentialRemovals.contains(journal.previousCredentialID),
      queue.timeAnchor == receipt.timeAnchor,
      queue.buildIdentityJSON == journal.buildIdentityJSON,
      queue.captureScopeJSON == journal.captureScopeJSON,
      TacuaCanonicalJSON.digest(data: try queue.encoded()) == receipt.resultQueueDigest
    else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
  }

  private func finishCommittedQueue(_ expected: TacuaTransportQueueV3) throws
    -> TacuaSDKResumedSession
  {
    // Revoked-credential removal is an idempotent queue-owned cleanup journal. Its failure must
    // not roll back newly committed backend authority; a later queue/status open retries it.
    let cleaned = (try? queueStore.recoverCredentialCleanup(
      localSessionID: expected.localSessionID,
      credentialStore: credentialFactory.credentialStore
    )) ?? (try? queueStore.load(localSessionID: expected.localSessionID)) ?? expected
    return try resumedSession(from: cleaned)
  }

  private func resumedSession(from queue: TacuaTransportQueueV3) throws
    -> TacuaSDKResumedSession
  {
    guard let remoteSessionID = queue.remoteSessionID,
      let scopeDigest = queue.scopeDigest,
      let credentialID = queue.currentCredentialID,
      let expiresAt = queue.currentCredentialExpiresAt,
      let rawMediaExpiresAt = queue.sessionRetentionAuthority?.rawMediaExpiresAt,
      queue.credentialCapability == .active
        || queue.credentialCapability == .completionReplayOrDeleteOnly
    else { throw TacuaSDKResumeLifecycleError.recoveryStateMismatch }
    let state: TacuaSDKResumeExpectedSessionState = queue.credentialCapability == .active
      ? .receiving : .completed
    let replayCompletionID = state == .completed ? queue.authorizedCompletionReplayID : nil
    guard (state == .completed) == (replayCompletionID != nil) else {
      throw TacuaSDKResumeLifecycleError.recoveryStateMismatch
    }
    let availability = TacuaCredentialAvailability.inspect(
      credentialID: credentialID,
      store: credentialFactory.credentialStore
    )
    return TacuaSDKResumedSession(
      localSessionID: queue.localSessionID,
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      credentialExpiresAt: expiresAt,
      rawMediaExpiresAt: rawMediaExpiresAt,
      backendSessionState: state,
      credentialCapability: queue.credentialCapability,
      replayCompletionID: replayCompletionID,
      credentialAvailability: availability,
      queueSchemaVersion: queue.schemaVersion,
      pendingRevokedCredentialRemovalCount: queue.pendingRevokedCredentialRemovals.count,
      resumeRequired: resumeRequirement(queue).kind == .resumeSession
    )
  }

  private func cleanupPreparedCredential(_ journal: TacuaSDKResumeJournal) throws {
    let claimed: TacuaSDKResumeJournal
    do {
      claimed = try journal.advancing(to: .credentialPreparedResetPending)
      try transitionDurably(expected: journal, replacement: claimed)
      try credentialFactory.removeIfOwned(
        credentialID: claimed.newCredentialID,
        ownershipDigest: claimed.newCredentialOwnershipDigest
      )
      try removeJournalDurably(claimed)
    } catch {
      throw TacuaSDKResumeLifecycleError.credentialCleanupRequired
    }
  }

  private func transitionDurably(
    expected: TacuaSDKResumeJournal,
    replacement: TacuaSDKResumeJournal
  ) throws {
    do {
      try journalStore.compareAndSwap(expected: expected, replacement: replacement)
      return
    } catch {}
    guard let current = try? journalStore.load(localSessionID: expected.localSessionID) else {
      throw TacuaSDKResumeLifecycleError.persistenceFailure
    }
    if current == replacement {
      do {
        try journalStore.compareAndSwap(expected: replacement, replacement: replacement)
        return
      } catch { throw TacuaSDKResumeLifecycleError.persistenceFailure }
    }
    if current == expected {
      do {
        try journalStore.compareAndSwap(expected: expected, replacement: replacement)
        return
      } catch { throw TacuaSDKResumeLifecycleError.persistenceFailure }
    }
    throw TacuaSDKResumeLifecycleError.recoveryActionRequired(current.state)
  }

  private func removeJournalDurably(_ journal: TacuaSDKResumeJournal) throws {
    do {
      try journalStore.remove(expected: journal)
      return
    } catch {}
    do {
      try journalStore.confirmAbsent(expected: journal)
    } catch {
      throw TacuaSDKResumeLifecycleError.journalCleanupRequired
    }
  }

  private func requireNoStartRecovery(localSessionID: String) throws {
    if try startJournalStore.load(localSessionID: localSessionID) != nil {
      throw TacuaSDKResumeLifecycleError.startRecoveryActionRequired
    }
  }

  private func acquireLifecycleLease(localSessionID: String) throws
    -> TacuaSDKStartLifecycleLease
  {
    do { return try startJournalStore.acquireLifecycleLease(localSessionID: localSessionID) }
    catch { throw TacuaSDKResumeLifecycleError.persistenceFailure }
  }

  private func validateLocalSessionID(_ localSessionID: String) throws {
    do { _ = try TacuaTransportQueueV3(localSessionID: localSessionID) }
    catch { throw TacuaSDKResumeLifecycleError.invalidInput }
  }

  private func reserve(_ localSessionID: String) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    guard activeLocalSessionIDs.insert(localSessionID).inserted else {
      throw TacuaSDKResumeLifecycleError.resumeAlreadyInProgress
    }
  }

  private func release(_ localSessionID: String) {
    operationLock.lock()
    activeLocalSessionIDs.remove(localSessionID)
    operationLock.unlock()
  }

  private func status(
    localSessionID: String,
    state: TacuaSDKResumeRecoveryState,
    queue: TacuaTransportQueueV3? = nil
  ) -> TacuaSDKResumeRecoveryStatus {
    switch state {
    case .none:
      return TacuaSDKResumeRecoveryStatus(
        localSessionID: localSessionID, state: state,
        remoteCredentialMayExist: false, queueUsable: false,
        canRecoverWithoutLaunch: false, canResetPreparedCredential: false,
        requiresReconciliation: false
      )
    case .queueCommitted:
      let remoteCredentialMayExist = queue?.remoteSessionID != nil
        && queue?.currentCredentialID != nil
        && queue?.credentialCapability != .requiresExchange
      let queueUsable = queue.map {
        let requirement = resumeRequirement($0)
        return requirement.kind == .none && requirement.reason == .ready
      } ?? false
      return TacuaSDKResumeRecoveryStatus(
        localSessionID: localSessionID, state: state,
        remoteCredentialMayExist: remoteCredentialMayExist, queueUsable: queueUsable,
        canRecoverWithoutLaunch: false, canResetPreparedCredential: false,
        requiresReconciliation: false
      )
    case .credentialPrepared, .credentialPreparedResetPending:
      return TacuaSDKResumeRecoveryStatus(
        localSessionID: localSessionID, state: state,
        remoteCredentialMayExist: false, queueUsable: false,
        canRecoverWithoutLaunch: false, canResetPreparedCredential: true,
        requiresReconciliation: false
      )
    case .exchangeOutcomeUnknown:
      return TacuaSDKResumeRecoveryStatus(
        localSessionID: localSessionID, state: state,
        remoteCredentialMayExist: true, queueUsable: false,
        canRecoverWithoutLaunch: false, canResetPreparedCredential: false,
        requiresReconciliation: true
      )
    case .queueConflictRequiresReconciliation:
      return TacuaSDKResumeRecoveryStatus(
        localSessionID: localSessionID, state: state,
        remoteCredentialMayExist: true, queueUsable: false,
        canRecoverWithoutLaunch: false, canResetPreparedCredential: false,
        requiresReconciliation: true
      )
    case .receiptValidatedQueueCommitPending:
      return TacuaSDKResumeRecoveryStatus(
        localSessionID: localSessionID, state: state,
        remoteCredentialMayExist: true, queueUsable: false,
        canRecoverWithoutLaunch: true, canResetPreparedCredential: false,
        requiresReconciliation: false
      )
    }
  }
}
