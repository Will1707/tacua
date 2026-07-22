// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaSDKStartLifecycleError: Error, Equatable {
  case invalidInput
  case startAlreadyInProgress
  case queueAlreadyCommitted
  case recoveryActionRequired(TacuaSDKStartJournalState)
  case resumeRecoveryActionRequired
  case credentialPreparationFailed
  case credentialCleanupRequired
  case launchRequestRejected
  case exchangeOutcomeUnknown
  case receiptCommitPending
  case journalCleanupRequired
  case nothingToRecover
  case resetAcknowledgementRequired
  case validatedReceiptCannotBeAbandoned
  case recoveryStateMismatch
  case persistenceFailure

  var code: String {
    switch self {
    case .invalidInput: return "ERR_TACUA_BACKEND_START_INPUT"
    case .startAlreadyInProgress: return "ERR_TACUA_BACKEND_START_BUSY"
    case .queueAlreadyCommitted: return "ERR_TACUA_BACKEND_START_EXISTS"
    case .recoveryActionRequired: return "ERR_TACUA_BACKEND_START_RECOVERY_REQUIRED"
    case .resumeRecoveryActionRequired: return "ERR_TACUA_BACKEND_RESUME_RECOVERY_REQUIRED"
    case .credentialPreparationFailed: return "ERR_TACUA_BACKEND_START_CREDENTIAL"
    case .credentialCleanupRequired: return "ERR_TACUA_BACKEND_START_CREDENTIAL_CLEANUP"
    case .launchRequestRejected: return "ERR_TACUA_BACKEND_START_REQUEST"
    case .exchangeOutcomeUnknown: return "ERR_TACUA_BACKEND_START_OUTCOME_UNKNOWN"
    case .receiptCommitPending: return "ERR_TACUA_BACKEND_START_RECEIPT_COMMIT_PENDING"
    case .journalCleanupRequired: return "ERR_TACUA_BACKEND_START_JOURNAL_CLEANUP"
    case .nothingToRecover: return "ERR_TACUA_BACKEND_START_NOTHING_TO_RECOVER"
    case .resetAcknowledgementRequired: return "ERR_TACUA_BACKEND_START_RESET_ACKNOWLEDGEMENT"
    case .validatedReceiptCannotBeAbandoned: return "ERR_TACUA_BACKEND_START_RECEIPT_MUST_RECOVER"
    case .recoveryStateMismatch: return "ERR_TACUA_BACKEND_START_RECOVERY_MISMATCH"
    case .persistenceFailure: return "ERR_TACUA_BACKEND_START_PERSISTENCE"
    }
  }

  var message: String {
    switch self {
    case .invalidInput:
      return "The backend START input does not satisfy the frozen protocol."
    case .startAlreadyInProgress:
      return "A backend START lifecycle operation is already in progress for this local session."
    case .queueAlreadyCommitted:
      return "This local session already has a committed backend transport queue."
    case .recoveryActionRequired(let state):
      return "Resolve the existing backend START recovery state before trying another launch (\(state.rawValue))."
    case .resumeRecoveryActionRequired:
      return "Resolve the existing backend RESUME recovery state before reading or changing this transport queue."
    case .credentialPreparationFailed:
      return "Tacua could not prepare the device-only backend credential."
    case .credentialCleanupRequired:
      return "Tacua could not finish removing an unused backend credential; use the recovery status and reset APIs."
    case .launchRequestRejected:
      return "The approved launch could not produce a valid frozen-protocol START request; request a fresh reviewer launch."
    case .exchangeOutcomeUnknown:
      return "The backend START exchange outcome is unknown. A fresh reviewer launch and explicit local reset are required; the remote session may exist."
    case .receiptCommitPending:
      return "The START receipt was validated, but the durable queue commit is pending recovery."
    case .journalCleanupRequired:
      return "The START queue is durable, but journal removal could not be confirmed; retry backend START recovery before using the session."
    case .nothingToRecover:
      return "There is no validated backend START receipt to recover."
    case .resetAcknowledgementRequired:
      return "Explicitly acknowledge that an unknown remote session may exist before abandoning local START state."
    case .validatedReceiptCannotBeAbandoned:
      return "A validated START receipt must be recovered into the durable queue; it cannot be locally abandoned."
    case .recoveryStateMismatch:
      return "The backend START journal and durable queue do not describe the same session."
    case .persistenceFailure:
      return "Tacua could not read or write backend START recovery state."
    }
  }
}

struct TacuaSDKStartSessionInput {
  static let maximumArtifactBytes = 256 * 1_024

  let approvedLaunchID: String
  let localSessionID: String
  let buildIdentityJSON: Data
  let scopeJSON: Data
  let requestedAt: String
}

struct TacuaSDKStartedSession: Equatable {
  let localSessionID: String
  let remoteSessionID: String
  let scopeDigest: String
  let credentialID: String
  let credentialExpiresAt: String
  let rawMediaExpiresAt: String
  let credentialCapability: TacuaTransportCredentialCapability
  let credentialAvailability: TacuaCredentialAvailability
  let queueSchemaVersion: Int
  let resumeRequired: Bool
}

enum TacuaSDKStartRecoveryState: String, Equatable {
  case none
  case credentialPrepared = "credential_prepared"
  case exchangeOutcomeUnknown = "exchange_outcome_unknown"
  case receiptValidatedQueueCommitPending = "receipt_validated_queue_commit_pending"
  case credentialPreparedResetPending = "credential_prepared_reset_pending"
  case exchangeOutcomeUnknownResetPending = "exchange_outcome_unknown_reset_pending"
  case queueCommitted = "queue_committed"
}

struct TacuaSDKStartRecoveryStatus: Equatable {
  let localSessionID: String
  let state: TacuaSDKStartRecoveryState
  let requiresFreshReviewerLaunch: Bool
  let remoteSessionMayExist: Bool
  let canRecoverWithoutLaunch: Bool
  let canAbandonLocally: Bool
  /// Nil when no validated remote credential exists yet.
  let resumeRequired: Bool?
  /// Nil when there is no durable queue or START journal to compare.
  let transportConfigurationMatchesBuild: Bool?
  /// Nil until a validated receipt or committed queue establishes remote credential authority.
  let credentialCapability: TacuaTransportCredentialCapability?
  /// Nil until a credential identifier exists. Temporary device-lock unavailability is distinct
  /// from a missing item and never, by itself, requests a fresh reviewer launch.
  let credentialAvailability: TacuaCredentialAvailability?
}

enum TacuaSDKResumeRequirementKind: String, Equatable {
  case none
  case resumeSession = "resume_session"
  case blocked
}

enum TacuaSDKResumeRequirementReason: String, Equatable {
  case ready
  case credentialTemporarilyUnavailable = "credential_temporarily_unavailable"
  case credentialUnavailable = "credential_unavailable"
  case terminalDeletion = "terminal_deletion"
  case credentialMissing = "credential_missing"
  case credentialExpiredOrClockInvalid = "credential_expired_or_clock_invalid"
  case transportBindingMissing = "transport_binding_missing"
  case transportConfigurationChanged = "transport_configuration_changed"
  case noRemoteSession = "no_remote_session"
  case invalidCompletionBinding = "invalid_completion_binding"
  case launchRecoveryRequired = "launch_recovery_required"
}

struct TacuaSDKResumeRequirement: Equatable {
  let kind: TacuaSDKResumeRequirementKind
  let reason: TacuaSDKResumeRequirementReason
  let expectedSessionState: String?
  let expectedCompletionID: String?

  var canConsumeApprovedLaunch: Bool { kind == .resumeSession }

  static func evaluate(
    queue: TacuaTransportQueueV3,
    transportConfigurationDigest: String,
    availability: TacuaCredentialAvailability,
    clock: TacuaMonotonicClock
  ) -> TacuaSDKResumeRequirement {
    func terminal(
      _ kind: TacuaSDKResumeRequirementKind,
      _ reason: TacuaSDKResumeRequirementReason
    ) -> TacuaSDKResumeRequirement {
      TacuaSDKResumeRequirement(
        kind: kind,
        reason: reason,
        expectedSessionState: nil,
        expectedCompletionID: nil
      )
    }
    func resumable(_ reason: TacuaSDKResumeRequirementReason)
      -> TacuaSDKResumeRequirement
    {
      let completionID = queue.authorizedCompletionReplayID
        ?? queue.outcomeUnknownCompletionReplayCandidateID
      return TacuaSDKResumeRequirement(
        kind: .resumeSession,
        reason: reason,
        expectedSessionState: completionID == nil ? "receiving" : "completed",
        expectedCompletionID: completionID
      )
    }

    guard queue.remoteSessionID != nil, queue.scopeDigest != nil,
      queue.currentCredentialID != nil
    else { return terminal(.blocked, .noRemoteSession) }
    if let pinned = queue.transportConfigurationDigest,
      pinned != transportConfigurationDigest
    {
      return terminal(.blocked, .transportConfigurationChanged)
    }
    switch queue.credentialCapability {
    case .requiresExchange:
      return terminal(.blocked, .noRemoteSession)
    case .deletionReplayOnly:
      return terminal(.none, .terminalDeletion)
    case .requiresTransportRebind:
      guard queue.transportConfigurationDigest == nil else {
        return terminal(.blocked, .transportConfigurationChanged)
      }
      return resumable(.transportBindingMissing)
    case .completionReplayOrDeleteOnly:
      guard queue.authorizedCompletionReplayID?.isEmpty == false else {
        return terminal(.blocked, .invalidCompletionBinding)
      }
    case .active:
      guard queue.completionCleanupAuthority == nil else {
        return terminal(.blocked, .invalidCompletionBinding)
      }
    }
    guard queue.transportConfigurationDigest == transportConfigurationDigest else {
      return terminal(.blocked, .transportConfigurationChanged)
    }
    switch availability {
    case .missing: return resumable(.credentialMissing)
    case .temporarilyUnavailable:
      return terminal(.none, .credentialTemporarilyUnavailable)
    case .unavailable: return terminal(.none, .credentialUnavailable)
    case .notApplicable: return terminal(.blocked, .noRemoteSession)
    case .available: break
    }
    guard (try? queue.timestampForNewOperation(clock: clock)) == nil else {
      return terminal(.none, .ready)
    }
    return resumable(.credentialExpiredOrClockInvalid)
  }
}

struct TacuaSDKBackendQueueStatus: Equatable {
  let localSessionID: String
  let remoteSessionID: String?
  let scopeDigest: String?
  let sessionArtifactsAvailable: Bool
  let currentCredentialID: String?
  let currentCredentialExpiresAt: String?
  let credentialCapability: TacuaTransportCredentialCapability
  let credentialAvailability: TacuaCredentialAvailability
  let credentialTimeValid: Bool
  let resumeRequired: Bool
  let resumeRequirement: TacuaSDKResumeRequirement
  let transportConfigurationMatchesBuild: Bool
  let operationCount: Int
  let queuedOperationCount: Int
  let storedResponseCount: Int
  let boundLocalPayloadCount: Int
  let legacyUnboundPayloadCount: Int
  let pendingRevokedCredentialRemovalCount: Int
  let payloadCleanupState: TacuaPayloadCleanupState
  let credentialCleanupState: TacuaCredentialCleanupState
  let completionCleanupAuthorized: Bool
  let deletionCleanupAuthorized: Bool
  let schemaVersion: Int
}

protocol TacuaSDKLaunchExchanging {
  func exchange(_ request: TacuaTransientLaunchRequest) async throws
    -> TacuaValidatedBackendReceipt
}

extension TacuaSDKBackendClient: TacuaSDKLaunchExchanging {}

protocol TacuaSDKStartQueueStoring: TacuaTransportQueuePersisting {
  func load(localSessionID: String) throws -> TacuaTransportQueueV3?
  func persistInitial(_ queue: TacuaTransportQueueV3) throws
  func recoverCredentialCleanup(
    localSessionID: String,
    credentialStore: TacuaCredentialStoring
  ) throws -> TacuaTransportQueueV3?
}

extension TacuaTransportQueueFileStore: TacuaSDKStartQueueStoring {}

final class TacuaSDKStartLifecycleCoordinator {
  private let configuration: TacuaBackendConfiguration
  private let consentGate: TacuaLaunchConsentGate
  private let credentialFactory: TacuaCredentialFactory
  private let exchanger: TacuaSDKLaunchExchanging
  private let queueStore: TacuaSDKStartQueueStoring
  private let journalStore: TacuaSDKStartJournalPersisting
  private let resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting?
  private let retentionChecker: TacuaSDKLocalRetentionChecking?
  private let clock: TacuaMonotonicClock
  private let operationLock = NSLock()
  private var activeLocalSessionIDs = Set<String>()

  init(
    configuration: TacuaBackendConfiguration,
    consentGate: TacuaLaunchConsentGate,
    credentialFactory: TacuaCredentialFactory,
    exchanger: TacuaSDKLaunchExchanging,
    queueStore: TacuaSDKStartQueueStoring,
    journalStore: TacuaSDKStartJournalPersisting,
    resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting? = nil,
    retentionChecker: TacuaSDKLocalRetentionChecking? = nil,
    clock: TacuaMonotonicClock = TacuaSystemMonotonicClock()
  ) {
    self.configuration = configuration
    self.consentGate = consentGate
    self.credentialFactory = credentialFactory
    self.exchanger = exchanger
    self.queueStore = queueStore
    self.journalStore = journalStore
    self.resumeRecoveryInspector = resumeRecoveryInspector
    self.retentionChecker = retentionChecker
    self.clock = clock
  }

  func start(_ input: TacuaSDKStartSessionInput) async throws -> TacuaSDKStartedSession {
    try reserve(input.localSessionID)
    defer { release(input.localSessionID) }

    let artifacts = try validateInput(input)
    let lifecycleLease = try acquireLifecycleLease(localSessionID: input.localSessionID)
    defer { lifecycleLease.release() }
    try retentionChecker?.requireActiveHoldingLifecycleLease(
      localSessionID: input.localSessionID
    )
    do {
      try requireNoResumeRecovery(localSessionID: input.localSessionID)
      if try queueStore.load(localSessionID: input.localSessionID) != nil {
        throw TacuaSDKStartLifecycleError.queueAlreadyCommitted
      }
      if let journal = try journalStore.load(localSessionID: input.localSessionID) {
        throw TacuaSDKStartLifecycleError.recoveryActionRequired(journal.state)
      }
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }

    var preparedJournal: TacuaSDKStartJournal?
    let preparedCredential: TacuaPreparedCredential
    do {
      preparedCredential = try credentialFactory.prepare {
        exchangeID, credentialID, credentialOwnershipDigest in
        let journal = try TacuaSDKStartJournal(
          localSessionID: input.localSessionID,
          exchangeID: exchangeID,
          credentialID: credentialID,
          credentialOwnershipDigest: credentialOwnershipDigest,
          transportConfigurationDigest: self.configuration.configurationDigest,
          buildIdentityJSON: String(decoding: artifacts.buildIdentityJSON, as: UTF8.self),
          captureScopeJSON: String(decoding: artifacts.scopeJSON, as: UTF8.self),
          createdAt: input.requestedAt,
          state: .credentialPrepared
        )
        try self.journalStore.createWhileQueueAbsent(journal) {
          guard try self.queueStore.load(localSessionID: input.localSessionID) == nil else {
            throw TacuaSDKStartLifecycleError.queueAlreadyCommitted
          }
        }
        // Ownership exists only after exclusive creation returns successfully.
        preparedJournal = journal
      }
    } catch {
      if let journal = preparedJournal {
        // A failed add may be a pre-existing duplicate or an implementation that installed the
        // item before reporting failure. Delete only an exact ownership-verifier match, then
        // remove the journal. A mismatch preserves the pre-existing item.
        do {
          try credentialFactory.removeIfOwned(
            credentialID: journal.credentialID,
            ownershipDigest: journal.credentialOwnershipDigest
          )
          try removeJournalDurably(journal)
        } catch {
          throw TacuaSDKStartLifecycleError.credentialCleanupRequired
        }
      }
      do {
        if try queueStore.load(localSessionID: input.localSessionID) != nil {
          throw TacuaSDKStartLifecycleError.queueAlreadyCommitted
        }
      } catch let lifecycleError as TacuaSDKStartLifecycleError {
        throw lifecycleError
      } catch {
        throw TacuaSDKStartLifecycleError.persistenceFailure
      }
      let existing: TacuaSDKStartJournal?
      do {
        existing = try journalStore.load(localSessionID: input.localSessionID)
      } catch {
        throw TacuaSDKStartLifecycleError.persistenceFailure
      }
      if let existing {
        throw TacuaSDKStartLifecycleError.recoveryActionRequired(existing.state)
      }
      throw TacuaSDKStartLifecycleError.credentialPreparationFailed
    }
    guard let initialJournal = preparedJournal else {
      try? credentialFactory.remove(credentialID: preparedCredential.credentialID)
      throw TacuaSDKStartLifecycleError.credentialPreparationFailed
    }

    do {
      // Keychain creation happens after journal publication. Reconfirm exact ownership before
      // consuming consent: another process may have abandoned that journal while SecItemAdd was
      // blocked. If ownership was lost, remove only the credential this attempt just created.
      try transitionDurably(expected: initialJournal, replacement: initialJournal)
    } catch {
      do {
        try credentialFactory.removeIfOwned(
          credentialID: preparedCredential.credentialID,
          ownershipDigest: initialJournal.credentialOwnershipDigest
        )
      } catch {
        throw TacuaSDKStartLifecycleError.credentialCleanupRequired
      }
      throw error
    }

    let request: TacuaTransientLaunchRequest
    do {
      request = try TacuaSDKBackendRequests.launch(
        preparedCredential: preparedCredential,
        approvedLaunchID: input.approvedLaunchID,
        consentGate: consentGate,
        exchangeKind: "start_session",
        expectedSessionID: nil,
        expectedSessionState: "receiving",
        expectedCompletionID: nil,
        previousCredentialID: nil,
        buildIdentity: artifacts.buildIdentity,
        scope: artifacts.scope,
        requestedAt: input.requestedAt,
        configuration: configuration
      )
      guard try TacuaSDKBackendProtocol.validateRequest(
        request.canonicalData,
        expectedTransportConfigurationDigest: configuration.configurationDigest
      ) == .launch else {
        throw TacuaSDKStartLifecycleError.launchRequestRejected
      }
    } catch {
      try cleanupUnusedCredential(initialJournal)
      throw TacuaSDKStartLifecycleError.launchRequestRejected
    }

    let attemptedJournal: TacuaSDKStartJournal
    do {
      attemptedJournal = try initialJournal.advancing(to: .exchangeOutcomeUnknown)
      // This conservative state is durable before network I/O. A crash immediately after this
      // write may have sent nothing, but recovery must not assert that as fact.
      try transitionDurably(expected: initialJournal, replacement: attemptedJournal)
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }

    let receipt: TacuaValidatedBackendReceipt
    do {
      let received = try await exchanger.exchange(request)
      let independent = try TacuaSDKBackendProtocol.validateResponse(
        received.canonicalResponse,
        forCanonicalRequest: request.canonicalData
      )
      guard independent == received,
        received.operationKind == .launch,
        received.operationID == preparedCredential.exchangeID,
        let transition = received.credentialTransition,
        transition.credentialID == preparedCredential.credentialID,
        transition.capability == .active,
        transition.replayCompletionID == nil
      else { throw TacuaSDKStartLifecycleError.exchangeOutcomeUnknown }
      receipt = received
    } catch {
      // The request may have reached the pinned backend. Retain the Keychain credential and the
      // secret-free journal until an explicit user-visible reset; never claim remote recovery.
      throw TacuaSDKStartLifecycleError.exchangeOutcomeUnknown
    }

    let transition = receipt.credentialTransition!
    let recovery: TacuaSDKStartReceiptRecovery
    do {
      recovery = TacuaSDKStartReceiptRecovery(
        remoteSessionID: receipt.remoteSessionID,
        scopeDigest: receipt.scopeDigest,
        credentialExpiresAt: transition.expiresAt,
        timeAnchor: try TacuaServerTimeAnchor.establish(
          issuedAt: receipt.authoritativeTimestamp,
          clock: clock
        ),
        sessionRetentionAuthority: try sessionRetentionAuthority(
          receivedAt: receipt.receivedTimestamp,
          scope: artifacts.scope
        )
      )
    } catch {
      throw TacuaSDKStartLifecycleError.exchangeOutcomeUnknown
    }
    let receiptJournal: TacuaSDKStartJournal
    do {
      receiptJournal = try attemptedJournal.advancing(
        to: .receiptValidatedQueueCommitPending,
        validatedReceipt: recovery
      )
      try transitionDurably(expected: attemptedJournal, replacement: receiptJournal)
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      // The prior outcome-unknown journal remains the only durable truth.
      throw TacuaSDKStartLifecycleError.exchangeOutcomeUnknown
    }

    let queue: TacuaTransportQueueV3
    do {
      queue = try committedQueue(from: receiptJournal)
      try queueStore.persistInitial(queue)
    } catch {
      throw TacuaSDKStartLifecycleError.receiptCommitPending
    }

    do {
      try removeJournalDurably(receiptJournal)
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.journalCleanupRequired
    }
    try retentionChecker?.requireActiveHoldingLifecycleLease(
      localSessionID: input.localSessionID
    )
    return try startedSession(from: queue)
  }

  func recoveryStatus(localSessionID: String) throws -> TacuaSDKStartRecoveryStatus {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
    do {
      try requireNoResumeRecovery(localSessionID: localSessionID)
      // Read the journal first: queue publication is durable before that journal can disappear.
      // This order cannot observe the false-empty window created by queue-then-journal reads.
      var journal = try journalStore.load(localSessionID: localSessionID)
      var queue = try queueStore.load(localSessionID: localSessionID)
      if journal == nil, queue == nil {
        // A concurrent START may have acquired ownership after the first read. One stabilizing
        // pass avoids returning `.none` for its already-published journal or queue.
        journal = try journalStore.load(localSessionID: localSessionID)
        queue = try queueStore.load(localSessionID: localSessionID)
      }
      if let queue {
        if let journal { try requireMatching(queue, journal: journal) }
        let canRecover = queueCanRecoverWithoutLaunch(queue)
        let availability = credentialAvailability(queue.currentCredentialID)
        return status(
          localSessionID: localSessionID,
          state: .queueCommitted,
          resumeRequired: credentialResumeRequired(queue, availability: availability),
          transportConfigurationMatchesBuild:
            queue.transportConfigurationDigest == configuration.configurationDigest,
          credentialCapability: queue.credentialCapability,
          credentialAvailability: availability,
          canRecoverWithoutLaunch: canRecover
        )
      }
      guard let journal else {
        return status(
          localSessionID: localSessionID,
          state: .none,
          resumeRequired: nil,
          transportConfigurationMatchesBuild: nil,
          credentialCapability: nil,
          credentialAvailability: nil,
          canRecoverWithoutLaunch: false
        )
      }
      let canRecover = journalCanRecoverWithoutLaunch(journal)
      let availability = journal.validatedReceipt == nil
        ? nil : credentialAvailability(journal.credentialID)
      return status(
        localSessionID: localSessionID,
        state: recoveryState(journal.state),
        resumeRequired: journal.validatedReceipt == nil
          ? nil : journalCredentialResumeRequired(
            journal,
            availability: availability ?? .notApplicable
          ),
        transportConfigurationMatchesBuild:
          journal.transportConfigurationDigest == configuration.configurationDigest,
        credentialCapability: journal.validatedReceipt == nil ? nil : .active,
        credentialAvailability: availability,
        canRecoverWithoutLaunch: canRecover
      )
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }
  }

  func queueStatus(localSessionID: String) throws -> TacuaSDKBackendQueueStatus? {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    do {
      try requireNoResumeRecovery(localSessionID: localSessionID)
      // A queue is not released for transport until its receipt journal is durably absent.
      // Holding the same cross-process lease as START also prevents cleanup from racing a
      // just-published queue between its atomic install and journal removal.
      if let journal = try journalStore.load(localSessionID: localSessionID) {
        if let queue = try queueStore.load(localSessionID: localSessionID) {
          try requireMatching(queue, journal: journal)
          throw TacuaSDKStartLifecycleError.journalCleanupRequired
        }
        throw TacuaSDKStartLifecycleError.recoveryActionRequired(journal.state)
      }
      guard let queue = try queueStore.recoverCredentialCleanup(
        localSessionID: localSessionID,
        credentialStore: credentialFactory.credentialStore
      ) else { return nil }
      let availability = credentialAvailability(queue.currentCredentialID)
      let credentialTimeValid = (try? queue.timestampForNewOperation(clock: clock)) != nil
      let transportConfigurationMatchesBuild = queue.transportConfigurationDigest
        == configuration.configurationDigest
      let resumeRequirement = resumeRequirement(queue, availability: availability)
      return TacuaSDKBackendQueueStatus(
        localSessionID: queue.localSessionID,
        remoteSessionID: queue.remoteSessionID,
        scopeDigest: queue.scopeDigest,
        sessionArtifactsAvailable: queue.hasDurableSessionArtifacts,
        currentCredentialID: queue.currentCredentialID,
        currentCredentialExpiresAt: queue.currentCredentialExpiresAt,
        credentialCapability: queue.credentialCapability,
        credentialAvailability: availability,
        credentialTimeValid: credentialTimeValid,
        resumeRequired: resumeRequirement.kind == .resumeSession,
        resumeRequirement: resumeRequirement,
        transportConfigurationMatchesBuild: transportConfigurationMatchesBuild,
        operationCount: queue.operations.count,
        queuedOperationCount: queue.operations.filter {
          $0.state == .prepared || $0.state == .outcomeUnknown
        }.count,
        storedResponseCount: queue.operations.filter { $0.state == .responseStored }.count,
        boundLocalPayloadCount: queue.operations.reduce(0) {
          $0 + ($1.localPayloadBindings?.count ?? 0)
        },
        legacyUnboundPayloadCount: queue.localPayloadPaths.count,
        pendingRevokedCredentialRemovalCount: queue.pendingRevokedCredentialRemovals.count,
        payloadCleanupState: queue.payloadCleanupState,
        credentialCleanupState: queue.credentialCleanupState,
        completionCleanupAuthorized: queue.completionCleanupAuthority != nil,
        deletionCleanupAuthorized: queue.deletionCleanupAuthority != nil,
        schemaVersion: queue.schemaVersion
      )
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }
  }

  func recover(localSessionID: String) throws -> TacuaSDKStartedSession {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    do {
      try requireNoResumeRecovery(localSessionID: localSessionID)
      let journal = try journalStore.load(localSessionID: localSessionID)
      if let existing = try queueStore.load(localSessionID: localSessionID) {
        if let journal {
          try requireMatching(existing, journal: journal)
          // A prior atomic write may have installed the queue and then reported an fsync failure.
          // Re-persist and fsync the exact queue successfully before removing recovery evidence.
          try queueStore.persistInitial(existing)
          try removeJournalDurably(journal)
          try retentionChecker?.requireActiveHoldingLifecycleLease(
            localSessionID: localSessionID
          )
          return try startedSession(from: existing)
        }
        try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
        return try startedSession(from: existing)
      }
      guard let journal else { throw TacuaSDKStartLifecycleError.nothingToRecover }
      switch journal.state {
      case .credentialPrepared:
        throw TacuaSDKStartLifecycleError.recoveryActionRequired(.credentialPrepared)
      case .exchangeOutcomeUnknown:
        throw TacuaSDKStartLifecycleError.exchangeOutcomeUnknown
      case .credentialPreparedResetPending, .exchangeOutcomeUnknownResetPending:
        throw TacuaSDKStartLifecycleError.recoveryActionRequired(journal.state)
      case .receiptValidatedQueueCommitPending:
        let queue = try committedQueue(from: journal)
        try queueStore.persistInitial(queue)
        try removeJournalDurably(journal)
        try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
        return try startedSession(from: queue)
      }
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }
  }

  func abandon(localSessionID: String, acknowledgeRemoteSessionMayExist: Bool) throws {
    try validateLocalSessionID(localSessionID)
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lifecycleLease = try acquireLifecycleLease(localSessionID: localSessionID)
    defer { lifecycleLease.release() }
    try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
    do {
      try requireNoResumeRecovery(localSessionID: localSessionID)
      guard try queueStore.load(localSessionID: localSessionID) == nil else {
        throw TacuaSDKStartLifecycleError.queueAlreadyCommitted
      }
      guard let journal = try journalStore.load(localSessionID: localSessionID) else {
        throw TacuaSDKStartLifecycleError.nothingToRecover
      }
      switch journal.state {
      case .credentialPrepared:
        try finishAbandon(
          journal,
          resetState: .credentialPreparedResetPending
        )
      case .exchangeOutcomeUnknown:
        guard acknowledgeRemoteSessionMayExist else {
          throw TacuaSDKStartLifecycleError.resetAcknowledgementRequired
        }
        try finishAbandon(
          journal,
          resetState: .exchangeOutcomeUnknownResetPending
        )
      case .credentialPreparedResetPending:
        try finishClaimedAbandon(journal)
      case .exchangeOutcomeUnknownResetPending:
        try finishClaimedAbandon(journal)
      case .receiptValidatedQueueCommitPending:
        throw TacuaSDKStartLifecycleError.validatedReceiptCannotBeAbandoned
      }
    } catch let error as TacuaSDKStartLifecycleError {
      throw error
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }
  }

  private func validateInput(_ input: TacuaSDKStartSessionInput) throws
    -> TacuaDurableSessionArtifacts
  {
    guard !input.approvedLaunchID.isEmpty,
      input.buildIdentityJSON.count <= TacuaSDKStartSessionInput.maximumArtifactBytes,
      input.scopeJSON.count <= TacuaSDKStartSessionInput.maximumArtifactBytes
    else { throw TacuaSDKStartLifecycleError.invalidInput }
    do {
      _ = try TacuaTransportQueueV3(localSessionID: input.localSessionID)
      let artifacts = try TacuaDurableSessionArtifacts.canonicalizing(
        buildIdentityJSON: input.buildIdentityJSON,
        scopeJSON: input.scopeJSON
      )
      try TacuaSDKBackendRequests.validateStartArtifacts(
        buildIdentity: artifacts.buildIdentity,
        scope: artifacts.scope,
        requestedAt: input.requestedAt,
        configuration: configuration
      )
      try configuration.validateBuildIdentityBinding(artifacts.buildIdentity)
      return artifacts
    } catch {
      throw TacuaSDKStartLifecycleError.invalidInput
    }
  }

  private func acquireLifecycleLease(localSessionID: String) throws
    -> TacuaSDKStartLifecycleLease
  {
    do {
      return try journalStore.acquireLifecycleLease(localSessionID: localSessionID)
    } catch {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }
  }

  private func validateLocalSessionID(_ localSessionID: String) throws {
    do {
      _ = try TacuaTransportQueueV3(localSessionID: localSessionID)
    } catch {
      throw TacuaSDKStartLifecycleError.invalidInput
    }
  }

  private func requireNoResumeRecovery(localSessionID: String) throws {
    if try resumeRecoveryInspector?.hasRecovery(localSessionID: localSessionID) == true {
      throw TacuaSDKStartLifecycleError.resumeRecoveryActionRequired
    }
  }

  private func committedQueue(from journal: TacuaSDKStartJournal) throws
    -> TacuaTransportQueueV3
  {
    return try queueFromJournal(journal)
  }

  private func queueFromJournal(_ journal: TacuaSDKStartJournal) throws
    -> TacuaTransportQueueV3
  {
    guard journal.state == .receiptValidatedQueueCommitPending,
      let receipt = journal.validatedReceipt
    else { throw TacuaSDKStartLifecycleError.recoveryStateMismatch }
    var queue = try TacuaTransportQueueV3(localSessionID: journal.localSessionID)
    let artifacts: TacuaDurableSessionArtifacts?
    do { artifacts = try journal.durableSessionArtifacts() }
    catch { throw TacuaSDKStartLifecycleError.recoveryStateMismatch }
    try queue.applyRecoveredStart(
      remoteSessionID: receipt.remoteSessionID,
      scopeDigest: receipt.scopeDigest,
      credentialID: journal.credentialID,
      transportConfigurationDigest: journal.transportConfigurationDigest,
      expiresAt: receipt.credentialExpiresAt,
      timeAnchor: receipt.timeAnchor,
      sessionRetentionAuthority: receipt.sessionRetentionAuthority,
      sessionArtifacts: artifacts
    )
    try queue.validate()
    return queue
  }

  private func requireMatching(
    _ queue: TacuaTransportQueueV3,
    journal: TacuaSDKStartJournal
  ) throws {
    guard journal.state == .receiptValidatedQueueCommitPending,
      let receipt = journal.validatedReceipt,
      queue.localSessionID == journal.localSessionID,
      queue.remoteSessionID == receipt.remoteSessionID,
      queue.scopeDigest == receipt.scopeDigest,
      queue.currentCredentialID == journal.credentialID,
      queue.currentCredentialExpiresAt == receipt.credentialExpiresAt,
      queue.transportConfigurationDigest == journal.transportConfigurationDigest,
      queue.timeAnchor.map({ anchorPreservesOrigin($0, receipt.timeAnchor) }) == true,
      queue.sessionRetentionAuthority == receipt.sessionRetentionAuthority,
      queue.buildIdentityJSON == journal.buildIdentityJSON,
      queue.captureScopeJSON == journal.captureScopeJSON,
      queue.credentialCapability == .active
    else { throw TacuaSDKStartLifecycleError.recoveryStateMismatch }
  }

  private func anchorPreservesOrigin(
    _ queueAnchor: TacuaServerTimeAnchor,
    _ journalAnchor: TacuaServerTimeAnchor
  ) -> Bool {
    queueAnchor.issuedAt == journalAnchor.issuedAt
      && queueAnchor.issuedEpochMilliseconds == journalAnchor.issuedEpochMilliseconds
      && queueAnchor.uptimeMillisecondsAtIssue == journalAnchor.uptimeMillisecondsAtIssue
      && queueAnchor.bootSessionID == journalAnchor.bootSessionID
      && queueAnchor.minimumEpochMilliseconds >= journalAnchor.minimumEpochMilliseconds
  }

  private func sessionRetentionAuthority(
    receivedAt: String,
    scope: TacuaJSONValue
  ) throws -> TacuaSessionRetentionAuthority {
    guard let receivedEpoch = TacuaProtocolTimestamp.parseMilliseconds(receivedAt),
      let retention = scope.objectValue?["retention"]?.objectValue,
      let rawDays = retention["raw_media_days"]?.integerValue,
      let derivedDays = retention["derived_data_days"]?.integerValue,
      (1...30).contains(rawDays), (1...365).contains(derivedDays)
    else { throw TacuaSDKStartLifecycleError.exchangeOutcomeUnknown }
    let dayMilliseconds: Int64 = 24 * 60 * 60 * 1_000
    let authority = TacuaSessionRetentionAuthority(
      sessionReceivedAt: receivedAt,
      rawMediaExpiresAt: TacuaProtocolTimestamp.format(
        milliseconds: receivedEpoch + rawDays * dayMilliseconds
      ),
      derivedDataExpiresAt: TacuaProtocolTimestamp.format(
        milliseconds: receivedEpoch + derivedDays * dayMilliseconds
      )
    )
    try authority.validate()
    return authority
  }

  private func startedSession(from queue: TacuaTransportQueueV3) throws
    -> TacuaSDKStartedSession
  {
    guard let remoteSessionID = queue.remoteSessionID,
      let scopeDigest = queue.scopeDigest,
      let credentialID = queue.currentCredentialID,
      let expiresAt = queue.currentCredentialExpiresAt,
      let rawMediaExpiresAt = queue.sessionRetentionAuthority?.rawMediaExpiresAt,
      queue.credentialCapability == .active
    else { throw TacuaSDKStartLifecycleError.recoveryStateMismatch }
    let availability = credentialAvailability(queue.currentCredentialID)
    return TacuaSDKStartedSession(
      localSessionID: queue.localSessionID,
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      credentialExpiresAt: expiresAt,
      rawMediaExpiresAt: rawMediaExpiresAt,
      credentialCapability: queue.credentialCapability,
      credentialAvailability: availability,
      queueSchemaVersion: queue.schemaVersion,
      resumeRequired: credentialResumeRequired(queue, availability: availability)
    )
  }

  private func cleanupUnusedCredential(_ journal: TacuaSDKStartJournal) throws {
    guard journal.state == .credentialPrepared else {
      throw TacuaSDKStartLifecycleError.recoveryActionRequired(journal.state)
    }
    try finishAbandon(journal, resetState: .credentialPreparedResetPending)
  }

  private func finishAbandon(
    _ journal: TacuaSDKStartJournal,
    resetState: TacuaSDKStartJournalState
  ) throws {
    let claimed = try journal.advancing(to: resetState)
    try transitionDurably(expected: journal, replacement: claimed)
    try finishClaimedAbandon(claimed)
  }

  private func finishClaimedAbandon(_ journal: TacuaSDKStartJournal) throws {
    do {
      try credentialFactory.removeIfOwned(
        credentialID: journal.credentialID,
        ownershipDigest: journal.credentialOwnershipDigest
      )
      do { try removeJournalDurably(journal) }
      catch { throw TacuaSDKStartLifecycleError.credentialCleanupRequired }
    } catch {
      throw TacuaSDKStartLifecycleError.credentialCleanupRequired
    }
  }

  private func transitionDurably(
    expected: TacuaSDKStartJournal,
    replacement: TacuaSDKStartJournal
  ) throws {
    do {
      try journalStore.compareAndSwap(expected: expected, replacement: replacement)
      return
    } catch {}

    guard let current = try? journalStore.load(localSessionID: expected.localSessionID) else {
      throw TacuaSDKStartLifecycleError.persistenceFailure
    }
    if current == replacement {
      do {
        // Re-write the installed target to turn an install-then-fsync-error into a confirmed
        // durable transition before this coordinator performs the next side effect.
        try journalStore.compareAndSwap(expected: replacement, replacement: replacement)
        return
      } catch {
        throw TacuaSDKStartLifecycleError.persistenceFailure
      }
    }
    if current == expected {
      do {
        try journalStore.compareAndSwap(expected: expected, replacement: replacement)
        return
      } catch {
        throw TacuaSDKStartLifecycleError.persistenceFailure
      }
    }
    throw TacuaSDKStartLifecycleError.recoveryActionRequired(current.state)
  }

  private func credentialResumeRequired(
    _ queue: TacuaTransportQueueV3,
    availability: TacuaCredentialAvailability
  ) -> Bool {
    // START recovery keeps this legacy boolean broad for compatibility: `true` means the queue
    // is not usable in this build, even when the richer queue requirement says a RESUME launch
    // is blocked (for example, a non-nil transport binding changed). New callers must branch on
    // `resumeRequirement` from queue status before consuming a launch.
    switch queue.credentialCapability {
    case .requiresExchange, .requiresTransportRebind:
      return true
    case .deletionReplayOnly:
      return false
    case .active, .completionReplayOrDeleteOnly:
      guard queue.transportConfigurationDigest == configuration.configurationDigest,
        (try? queue.timestampForNewOperation(clock: clock)) != nil
      else { return true }
      return availability == .missing
    }
  }

  private func resumeRequirement(
    _ queue: TacuaTransportQueueV3,
    availability: TacuaCredentialAvailability
  ) -> TacuaSDKResumeRequirement {
    TacuaSDKResumeRequirement.evaluate(
      queue: queue,
      transportConfigurationDigest: configuration.configurationDigest,
      availability: availability,
      clock: clock
    )
  }

  private func journalCredentialResumeRequired(
    _ journal: TacuaSDKStartJournal,
    availability: TacuaCredentialAvailability
  ) -> Bool {
    guard journal.transportConfigurationDigest == configuration.configurationDigest,
      let queue = try? queueFromJournal(journal)
    else { return true }
    return credentialResumeRequired(queue, availability: availability)
  }

  private func queueCanRecoverWithoutLaunch(_ queue: TacuaTransportQueueV3) -> Bool {
    // `recoverBackendStart` reconstructs/returns structural START state. Transport usability is a
    // separate `resumeRequired` decision and may be false only after Keychain/config/time checks.
    queue.credentialCapability == .active
  }

  private func journalCanRecoverWithoutLaunch(_ journal: TacuaSDKStartJournal) -> Bool {
    guard journal.state == .receiptValidatedQueueCommitPending,
      (try? queueFromJournal(journal)) != nil
    else { return false }
    // Queue reconstruction is structural and never needs the current build configuration or
    // Keychain item. Any missing transport authority is represented explicitly as resumeRequired.
    return true
  }

  private func removeJournalDurably(_ journal: TacuaSDKStartJournal) throws {
    do {
      try journalStore.remove(expected: journal)
      return
    } catch {}
    do {
      // `remove` may have unlinked the file before a directory fsync failed. Confirm the exact
      // canonical name is absent and fsync the parent before releasing any usable session.
      try journalStore.confirmAbsent(expected: journal)
    } catch {
      throw TacuaSDKStartLifecycleError.journalCleanupRequired
    }
  }

  private func credentialAvailability(_ credentialID: String?)
    -> TacuaCredentialAvailability
  {
    TacuaCredentialAvailability.inspect(
      credentialID: credentialID,
      store: credentialFactory.credentialStore
    )
  }

  private func status(
    localSessionID: String,
    state: TacuaSDKStartRecoveryState,
    resumeRequired: Bool?,
    transportConfigurationMatchesBuild: Bool?,
    credentialCapability: TacuaTransportCredentialCapability?,
    credentialAvailability: TacuaCredentialAvailability?,
    canRecoverWithoutLaunch: Bool
  ) -> TacuaSDKStartRecoveryStatus {
    let transportLaunchRequired = resumeRequired == true
    return TacuaSDKStartRecoveryStatus(
      localSessionID: localSessionID,
      state: state,
      requiresFreshReviewerLaunch: transportLaunchRequired
        || state == .credentialPrepared
        || state == .credentialPreparedResetPending
        || state == .exchangeOutcomeUnknown
        || state == .exchangeOutcomeUnknownResetPending,
      remoteSessionMayExist: state == .exchangeOutcomeUnknown
        || state == .exchangeOutcomeUnknownResetPending
        || state == .receiptValidatedQueueCommitPending || state == .queueCommitted,
      canRecoverWithoutLaunch: canRecoverWithoutLaunch,
      canAbandonLocally: state == .credentialPrepared
        || state == .credentialPreparedResetPending
        || state == .exchangeOutcomeUnknown
        || state == .exchangeOutcomeUnknownResetPending,
      resumeRequired: resumeRequired,
      transportConfigurationMatchesBuild: transportConfigurationMatchesBuild,
      credentialCapability: credentialCapability,
      credentialAvailability: credentialAvailability
    )
  }

  private func recoveryState(_ state: TacuaSDKStartJournalState)
    -> TacuaSDKStartRecoveryState
  {
    switch state {
    case .credentialPrepared: return .credentialPrepared
    case .exchangeOutcomeUnknown: return .exchangeOutcomeUnknown
    case .receiptValidatedQueueCommitPending: return .receiptValidatedQueueCommitPending
    case .credentialPreparedResetPending: return .credentialPreparedResetPending
    case .exchangeOutcomeUnknownResetPending: return .exchangeOutcomeUnknownResetPending
    }
  }

  private func reserve(_ localSessionID: String) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    guard activeLocalSessionIDs.insert(localSessionID).inserted else {
      throw TacuaSDKStartLifecycleError.startAlreadyInProgress
    }
  }

  private func release(_ localSessionID: String) {
    operationLock.lock()
    activeLocalSessionIDs.remove(localSessionID)
    operationLock.unlock()
  }
}
