// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaCaptureDeletionError: Error, Equatable {
  case invalidInput
  case alreadyInProgress
  case startRecoveryRequired
  case resumeRecoveryRequired
  case queueMissing
  case resumeRequired
  case credentialUnavailable
  case reconciliationRequired
  case transportOutcomeUnknown
  case receiptCommitPending
  case localRetirementPending
  case credentialCleanupPending
  case finalizationPending
  case persistenceFailure

  var code: String {
    switch self {
    case .invalidInput: return "ERR_TACUA_DELETE_INPUT"
    case .alreadyInProgress: return "ERR_TACUA_DELETE_BUSY"
    case .startRecoveryRequired: return "ERR_TACUA_DELETE_START_RECOVERY"
    case .resumeRecoveryRequired: return "ERR_TACUA_DELETE_RESUME_RECOVERY"
    case .queueMissing: return "ERR_TACUA_DELETE_QUEUE_MISSING"
    case .resumeRequired: return "ERR_TACUA_DELETE_RESUME_REQUIRED"
    case .credentialUnavailable: return "ERR_TACUA_DELETE_CREDENTIAL_UNAVAILABLE"
    case .reconciliationRequired: return "ERR_TACUA_DELETE_RECONCILIATION"
    case .transportOutcomeUnknown: return "ERR_TACUA_DELETE_OUTCOME_UNKNOWN"
    case .receiptCommitPending: return "ERR_TACUA_DELETE_RECEIPT_COMMIT"
    case .localRetirementPending: return "ERR_TACUA_DELETE_LOCAL_RETIREMENT"
    case .credentialCleanupPending: return "ERR_TACUA_DELETE_CREDENTIAL_CLEANUP"
    case .finalizationPending: return "ERR_TACUA_DELETE_FINALIZATION"
    case .persistenceFailure: return "ERR_TACUA_DELETE_PERSISTENCE"
    }
  }

  var message: String {
    switch self {
    case .invalidInput: return "The capture deletion input is malformed."
    case .alreadyInProgress: return "This capture already has a deletion in progress."
    case .startRecoveryRequired: return "Finish backend START recovery before deletion."
    case .resumeRecoveryRequired: return "Finish backend RESUME recovery before deletion."
    case .queueMissing: return "No durable capture queue or deletion proof exists."
    case .resumeRequired: return "Resume this backend session before requesting deletion."
    case .credentialUnavailable: return "The deletion credential is temporarily unavailable."
    case .reconciliationRequired:
      return "Durable deletion state conflicts with the expected user-requested operation."
    case .transportOutcomeUnknown:
      return "The deletion outcome is unknown; retry the exact durable operation."
    case .receiptCommitPending:
      return "A validated deletion tombstone could not yet be committed locally."
    case .localRetirementPending:
      return "Remote deletion is durable, but local capture retirement is still pending."
    case .credentialCleanupPending:
      return "Local capture retirement is complete, but credential removal is still pending."
    case .finalizationPending:
      return "Deletion cleanup is complete, but final local queue retirement is still pending."
    case .persistenceFailure: return "Tacua could not read or update durable deletion state."
    }
  }
}

struct TacuaCaptureDeletionResult: Equatable {
  let localSessionID: String
  let deletionID: String
  let tombstoneDigest: String
  let alreadyDeleted: Bool
}

protocol TacuaCaptureDeletionQueueStoring {
  func load(localSessionID: String) throws -> TacuaTransportQueueV3?
  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws
  func recoverPayloadCleanup(
    localSessionID: String,
    sessionDirectory: URL
  ) throws -> TacuaTransportQueueV3?
  func recoverCredentialCleanup(
    localSessionID: String,
    credentialStore: TacuaCredentialStoring
  ) throws -> TacuaTransportQueueV3?
  func deletionFinalization(localSessionID: String) throws
    -> TacuaDeletionFinalizationMarker?
  func finalizeDeletion(localSessionID: String) throws -> TacuaDeletionFinalizationMarker
}

extension TacuaTransportQueueFileStore: TacuaCaptureDeletionQueueStoring {}

private enum TacuaCaptureDeletionStep {
  case continueDriving
  case deleted(TacuaCaptureDeletionResult)
}

final class TacuaCaptureDeletionCoordinator {
  static let stableUserRequestedDeletionID = "deletion_user_requested_000001"

  private let configuration: TacuaBackendConfiguration
  private let captureRootDirectory: URL
  private let queueStore: TacuaCaptureDeletionQueueStoring
  private let lifecycleGate: TacuaCaptureAdmissionLifecycleGating
  private let resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting
  private let sender: TacuaSDKBackendOperationSending
  private let credentialStore: TacuaCredentialStoring
  private let clock: TacuaMonotonicClock
  private let operationLock = NSLock()
  private var activeLocalSessionIDs = Set<String>()

  init(
    configuration: TacuaBackendConfiguration,
    captureRootDirectory: URL,
    queueStore: TacuaCaptureDeletionQueueStoring,
    lifecycleGate: TacuaCaptureAdmissionLifecycleGating,
    resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting,
    sender: TacuaSDKBackendOperationSending,
    credentialStore: TacuaCredentialStoring,
    clock: TacuaMonotonicClock = TacuaSystemMonotonicClock()
  ) {
    self.configuration = configuration
    self.captureRootDirectory = captureRootDirectory.standardizedFileURL
    self.queueStore = queueStore
    self.lifecycleGate = lifecycleGate
    self.resumeRecoveryInspector = resumeRecoveryInspector
    self.sender = sender
    self.credentialStore = credentialStore
    self.clock = clock
  }

  func delete(localSessionID: String) async throws -> TacuaCaptureDeletionResult {
    guard Self.validIdentifier(localSessionID), captureRootDirectory.isFileURL else {
      throw TacuaCaptureDeletionError.invalidInput
    }
    try reserve(localSessionID)
    defer { release(localSessionID) }
    let lease: TacuaSDKStartLifecycleLease
    do { lease = try lifecycleGate.acquireLifecycleLease(localSessionID: localSessionID) }
    catch { throw TacuaCaptureDeletionError.persistenceFailure }
    defer { lease.release() }
    do {
      if try lifecycleGate.hasStartRecovery(localSessionID: localSessionID) {
        throw TacuaCaptureDeletionError.startRecoveryRequired
      }
      if try resumeRecoveryInspector.hasRecovery(localSessionID: localSessionID) {
        throw TacuaCaptureDeletionError.resumeRecoveryRequired
      }
    } catch let error as TacuaCaptureDeletionError { throw error }
    catch { throw TacuaCaptureDeletionError.persistenceFailure }

    while true {
      switch try await driveOne(localSessionID: localSessionID) {
      case .continueDriving: continue
      case .deleted(let result): return result
      }
    }
  }

  private func driveOne(localSessionID: String) async throws -> TacuaCaptureDeletionStep {
    do {
      if let finalization = try queueStore.deletionFinalization(
        localSessionID: localSessionID
      ) {
        return .deleted(result(finalization, alreadyDeleted: true))
      }
    } catch { throw TacuaCaptureDeletionError.persistenceFailure }

    let baseline: TacuaTransportQueueV3
    do {
      guard let queue = try queueStore.load(localSessionID: localSessionID) else {
        throw TacuaCaptureDeletionError.queueMissing
      }
      try queue.validate()
      baseline = queue
    } catch let error as TacuaCaptureDeletionError { throw error }
    catch { throw TacuaCaptureDeletionError.persistenceFailure }

    if baseline.deletionCleanupAuthority != nil {
      return .deleted(try finishAuthorizedDeletion(baseline))
    }
    guard baseline.transportConfigurationDigest == configuration.configurationDigest else {
      throw TacuaCaptureDeletionError.resumeRequired
    }
    switch baseline.credentialCapability {
    case .active, .completionReplayOrDeleteOnly:
      break
    case .requiresExchange, .requiresTransportRebind:
      throw TacuaCaptureDeletionError.resumeRequired
    case .deletionReplayOnly:
      throw TacuaCaptureDeletionError.reconciliationRequired
    }
    guard let currentCredentialID = baseline.currentCredentialID,
      baseline.remoteSessionID != nil,
      baseline.scopeDigest != nil
    else { throw TacuaCaptureDeletionError.resumeRequired }
    switch TacuaCredentialAvailability.inspect(
      credentialID: currentCredentialID,
      store: credentialStore
    ) {
    case .available: break
    case .missing, .notApplicable: throw TacuaCaptureDeletionError.resumeRequired
    case .temporarilyUnavailable, .unavailable:
      throw TacuaCaptureDeletionError.credentialUnavailable
    }

    let deletions = baseline.operations.filter { $0.kind == .deletion }
    if deletions.isEmpty {
      let replacement = try queueByEnqueuingDeletion(baseline)
      try commit(expected: baseline, replacement: replacement)
      return .continueDriving
    }
    guard deletions.count == 1 else {
      throw TacuaCaptureDeletionError.reconciliationRequired
    }
    try validateUserRequestedDeletion(deletions[0], queue: baseline)
    guard deletions[0].state != .responseStored else {
      throw TacuaCaptureDeletionError.reconciliationRequired
    }
    try await dispatch(deletions[0], baseline: baseline)
    return .continueDriving
  }

  private func queueByEnqueuingDeletion(
    _ baseline: TacuaTransportQueueV3
  ) throws -> TacuaTransportQueueV3 {
    guard let sessionID = baseline.remoteSessionID,
      let scopeDigest = baseline.scopeDigest,
      let credentialID = baseline.currentCredentialID
    else { throw TacuaCaptureDeletionError.resumeRequired }
    let requestedAt: String
    do { requestedAt = try baseline.timestampForNewOperation(clock: clock) }
    catch { throw TacuaCaptureDeletionError.resumeRequired }
    let request: TacuaPreparedBackendRequest
    do {
      request = try TacuaSDKBackendRequests.deletion(
        deletionID: Self.stableUserRequestedDeletionID,
        sessionID: sessionID,
        scopeDigest: scopeDigest,
        credentialID: credentialID,
        reason: "user_requested",
        requestedAt: requestedAt
      )
    } catch { throw TacuaCaptureDeletionError.reconciliationRequired }
    var replacement = baseline
    do {
      try replacement.enqueueNewOperation(
        kind: .deletion,
        operationID: request.operationID,
        requestCredentialID: request.credentialID,
        request: try TacuaCanonicalJSON.parse(request.canonicalData),
        requestDigest: request.requestDigest,
        clock: clock
      )
      try replacement.validate()
    } catch { throw TacuaCaptureDeletionError.reconciliationRequired }
    return replacement
  }

  private func dispatch(
    _ original: TacuaQueuedOperation,
    baseline: TacuaTransportQueueV3
  ) async throws {
    guard let currentCredentialID = baseline.currentCredentialID else {
      throw TacuaCaptureDeletionError.resumeRequired
    }
    if original.state == .prepared, original.requestCredentialID != currentCredentialID {
      let requestedAt: String
      do { requestedAt = try baseline.timestampForNewOperation(clock: clock) }
      catch { throw TacuaCaptureDeletionError.resumeRequired }
      var replacement = baseline
      do {
        let rebound = try TacuaSDKBackendRequests.rebound(
          original,
          credentialID: currentCredentialID,
          requestedAt: requestedAt
        )
        try replacement.rebindPreparedOperation(
          operationID: original.operationID,
          replacement: rebound,
          clock: clock
        )
        try replacement.validate()
      } catch { throw TacuaCaptureDeletionError.reconciliationRequired }
      try commit(expected: baseline, replacement: replacement)
      return
    }

    var attempted = baseline
    let attempt: TacuaOperationAttempt
    do {
      switch original.state {
      case .prepared:
        attempt = try attempted.beginAttempt(
          operationID: original.operationID,
          expectedTransportConfigurationDigest: configuration.configurationDigest,
          clock: clock
        )
        try commit(expected: baseline, replacement: attempted)
      case .outcomeUnknown:
        attempt = try attempted.outcomeUnknownAttempt(
          operationID: original.operationID,
          expectedTransportConfigurationDigest: configuration.configurationDigest,
          clock: clock
        )
      case .responseStored:
        throw TacuaCaptureDeletionError.reconciliationRequired
      }
    } catch let error as TacuaCaptureDeletionError { throw error }
    catch { throw TacuaCaptureDeletionError.resumeRequired }
    guard let durable = attempted.operations.first(where: {
      $0.operationID == original.operationID
    }), durable.kind == .deletion, durable.state == .outcomeUnknown,
      durable.canonicalRequest == attempt.canonicalRequest,
      durable.requestCredentialID == attempt.immutableRequestCredentialID
    else { throw TacuaCaptureDeletionError.persistenceFailure }
    let request = TacuaPreparedBackendRequest(
      kind: .deletion,
      operationID: durable.operationID,
      credentialID: durable.requestCredentialID,
      canonicalData: durable.canonicalRequest,
      requestDigest: durable.requestDigest
    )
    let receipt: TacuaValidatedBackendReceipt
    do {
      receipt = try await sender.send(
        request,
        transportCredentialID: attempt.transportCredentialID
      )
    } catch {
      // No authenticated historical-miss proof exists for deletion in protocol v1. The exact
      // request therefore remains outcome-unknown; it is never rewritten on a guessed miss.
      throw TacuaCaptureDeletionError.transportOutcomeUnknown
    }
    var replacement = attempted
    do {
      try replacement.storeValidatedReceipt(receipt)
      try replacement.observeAuthoritativeReceiptTimestamp(
        receipt.authoritativeTimestamp,
        clock: clock
      )
      try replacement.validate()
    } catch { throw TacuaCaptureDeletionError.receiptCommitPending }
    do { try commit(expected: attempted, replacement: replacement) }
    catch { throw TacuaCaptureDeletionError.receiptCommitPending }
  }

  private func finishAuthorizedDeletion(
    _ baseline: TacuaTransportQueueV3
  ) throws -> TacuaCaptureDeletionResult {
    let localSessionID = baseline.localSessionID
    let sessionDirectory = captureRootDirectory.appendingPathComponent(
      localSessionID,
      isDirectory: true
    ).standardizedFileURL
    let retired: TacuaTransportQueueV3
    do {
      guard let queue = try queueStore.recoverPayloadCleanup(
        localSessionID: localSessionID,
        sessionDirectory: sessionDirectory
      ) else { throw TacuaCaptureDeletionError.queueMissing }
      retired = queue
    } catch let error as TacuaCaptureDeletionError { throw error }
    catch { throw TacuaCaptureDeletionError.localRetirementPending }
    guard retired.payloadCleanupState == .payloadsRemoved,
      retired.deletionCleanupAuthority == baseline.deletionCleanupAuthority
    else { throw TacuaCaptureDeletionError.localRetirementPending }

    let cleaned: TacuaTransportQueueV3
    do {
      guard let queue = try queueStore.recoverCredentialCleanup(
        localSessionID: localSessionID,
        credentialStore: credentialStore
      ) else { throw TacuaCaptureDeletionError.queueMissing }
      cleaned = queue
    } catch let error as TacuaCaptureDeletionError { throw error }
    catch { throw TacuaCaptureDeletionError.credentialCleanupPending }
    guard cleaned.payloadCleanupState == .payloadsRemoved,
      cleaned.credentialCleanupState == .credentialRemoved,
      cleaned.currentCredentialID == nil,
      cleaned.pendingRevokedCredentialRemovals.isEmpty
    else { throw TacuaCaptureDeletionError.credentialCleanupPending }

    do {
      let marker = try queueStore.finalizeDeletion(localSessionID: localSessionID)
      return result(marker, alreadyDeleted: false)
    } catch { throw TacuaCaptureDeletionError.finalizationPending }
  }

  private func validateUserRequestedDeletion(
    _ operation: TacuaQueuedOperation,
    queue: TacuaTransportQueueV3
  ) throws {
    guard operation.localPayloadPath == nil,
      (operation.localPayloadBindings ?? []).isEmpty,
      try TacuaSDKBackendProtocol.validateRequest(operation.canonicalRequest) == .deletion,
      let root = try TacuaCanonicalJSON.parse(operation.canonicalRequest).objectValue,
      root["deletion_id"]?.stringValue == operation.operationID,
      root["session_id"]?.stringValue == queue.remoteSessionID,
      root["scope_digest"]?.stringValue == queue.scopeDigest,
      root["credential_id"]?.stringValue == operation.requestCredentialID,
      root["target"]?.stringValue == "session_all_data",
      root["reason"]?.stringValue == "user_requested",
      root["request_digest"]?.stringValue == operation.requestDigest
    else { throw TacuaCaptureDeletionError.reconciliationRequired }
  }

  private func commit(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws {
    do {
      try queueStore.compareAndSwap(expected: expected, replacement: replacement)
      return
    } catch {}
    guard let current = try? queueStore.load(localSessionID: expected.localSessionID),
      current == replacement
    else { throw TacuaCaptureDeletionError.persistenceFailure }
    do { try queueStore.compareAndSwap(expected: replacement, replacement: replacement) }
    catch { throw TacuaCaptureDeletionError.persistenceFailure }
  }

  private func result(
    _ marker: TacuaDeletionFinalizationMarker,
    alreadyDeleted: Bool
  ) -> TacuaCaptureDeletionResult {
    TacuaCaptureDeletionResult(
      localSessionID: marker.localSessionID,
      deletionID: marker.deletionID,
      tombstoneDigest: marker.tombstoneDigest,
      alreadyDeleted: alreadyDeleted
    )
  }

  private func reserve(_ localSessionID: String) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    guard activeLocalSessionIDs.insert(localSessionID).inserted else {
      throw TacuaCaptureDeletionError.alreadyInProgress
    }
  }

  private func release(_ localSessionID: String) {
    operationLock.lock()
    activeLocalSessionIDs.remove(localSessionID)
    operationLock.unlock()
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }
}
