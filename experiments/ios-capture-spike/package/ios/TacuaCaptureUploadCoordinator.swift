// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

enum TacuaCaptureUploadError: Error, Equatable {
  case invalidInput
  case alreadyInProgress
  case startRecoveryRequired
  case resumeRecoveryRequired
  case queueMissing
  case queueUnavailable
  case admissionMissing
  case admissionConflict
  case payloadUnavailable
  case transportOutcomeUnknown
  case receiptCommitPending
  case cleanupPending
  case retentionExpired
  case retentionCleanupPending
  case persistenceFailure

  var code: String {
    switch self {
    case .invalidInput: return "ERR_TACUA_UPLOAD_INPUT"
    case .alreadyInProgress: return "ERR_TACUA_UPLOAD_BUSY"
    case .startRecoveryRequired: return "ERR_TACUA_UPLOAD_START_RECOVERY"
    case .resumeRecoveryRequired: return "ERR_TACUA_UPLOAD_RESUME_RECOVERY"
    case .queueMissing: return "ERR_TACUA_UPLOAD_QUEUE_MISSING"
    case .queueUnavailable: return "ERR_TACUA_UPLOAD_QUEUE_UNAVAILABLE"
    case .admissionMissing: return "ERR_TACUA_UPLOAD_ADMISSION_MISSING"
    case .admissionConflict: return "ERR_TACUA_UPLOAD_ADMISSION_CONFLICT"
    case .payloadUnavailable: return "ERR_TACUA_UPLOAD_PAYLOAD"
    case .transportOutcomeUnknown: return "ERR_TACUA_UPLOAD_OUTCOME_UNKNOWN"
    case .receiptCommitPending: return "ERR_TACUA_UPLOAD_RECEIPT_COMMIT"
    case .cleanupPending: return "ERR_TACUA_UPLOAD_CLEANUP"
    case .retentionExpired: return "ERR_TACUA_UPLOAD_RETENTION_EXPIRED"
    case .retentionCleanupPending: return "ERR_TACUA_UPLOAD_RETENTION_CLEANUP"
    case .persistenceFailure: return "ERR_TACUA_UPLOAD_PERSISTENCE"
    }
  }

  var message: String {
    switch self {
    case .invalidInput: return "The admitted-capture upload input is malformed."
    case .alreadyInProgress: return "This capture already has an upload operation in progress."
    case .startRecoveryRequired: return "Finish backend START recovery before uploading."
    case .resumeRecoveryRequired: return "Finish backend RESUME recovery before uploading."
    case .queueMissing: return "No durable backend queue exists for this capture."
    case .queueUnavailable: return "The backend queue cannot currently upload this capture."
    case .admissionMissing: return "The immutable finalized-capture admission is missing."
    case .admissionConflict: return "The admission artifact and durable queue disagree."
    case .payloadUnavailable: return "An admitted local payload is missing or changed."
    case .transportOutcomeUnknown:
      return "The backend outcome is unknown; retry to recover the exact durable operation."
    case .receiptCommitPending:
      return "A validated backend receipt could not yet be committed locally; retry recovery."
    case .cleanupPending:
      return "Completion is durable, but receipt-authorized local cleanup is still pending."
    case .retentionExpired:
      return "The immutable raw-media retention deadline ended this upload."
    case .retentionCleanupPending:
      return "The raw-media deadline stopped transport, but local retirement must be retried."
    case .persistenceFailure: return "Tacua could not read or update durable upload state."
    }
  }
}

struct TacuaCaptureUploadResult: Equatable {
  let localSessionID: String
  let remoteSessionID: String
  let completionID: String
  let segmentReceiptCount: Int
  let diagnosticReceiptCount: Int
  let payloadCleanupState: TacuaPayloadCleanupState
  let alreadyCompleted: Bool
}

protocol TacuaCaptureUploadQueueStoring {
  func load(localSessionID: String) throws -> TacuaTransportQueueV3?
  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws
  func recoverPayloadCleanup(
    localSessionID: String,
    sessionDirectory: URL
  ) throws -> TacuaTransportQueueV3?
}

extension TacuaTransportQueueFileStore: TacuaCaptureUploadQueueStoring {}

private struct TacuaCaptureTransportPlan {
  struct Segment {
    let uploadID: String
    let segmentID: String
    let mediaRelativePath: String
    let sidecarRelativePath: String
    let sizeBytes: Int64
    let contentDigest: String
    let sidecarDigest: String
  }

  struct Diagnostic {
    let uploadID: String
    let relativePath: String
    let envelopeDigest: String
    let fileDigest: String
    let sourceJournalRelativePath: String?
    let sourceJournalDigest: String?
    let envelope: TacuaJSONValue
  }

  let admissionDigest: String
  let remoteSessionID: String
  let scopeDigest: String
  let completionID: String
  let segments: [Segment]
  let diagnostic: Diagnostic
  let captureManifestSeed: TacuaJSONValue

  var segmentUploadIDs: [String] { segments.map(\.uploadID) }
  var diagnosticUploadIDs: [String] { [diagnostic.uploadID] }
  var orderedUploadIDs: [String] { segmentUploadIDs + diagnosticUploadIDs }
}

private enum TacuaCaptureUploadStep {
  case continueDriving
  case completed(TacuaCaptureUploadResult)
}

private struct TacuaCaptureUploadDeadlineReached: Error {}

/// Exactly-once bridge for an unstructured sender/deadline race. The coordinator must be able to
/// return after cancelling a misbehaving test sender instead of waiting forever for structured
/// concurrency to join a child that ignores cancellation. A late sender result has no continuation
/// and therefore cannot reach queue receipt commit.
private final class TacuaCaptureUploadDeadlineRace: @unchecked Sendable {
  typealias Output = TacuaValidatedBackendReceipt

  private let lock = NSLock()
  private var continuation: CheckedContinuation<Output, Error>?
  private var pendingResolution: Result<Output, Error>?
  private var sendTask: Task<Void, Never>?
  private var deadlineTask: Task<Void, Never>?
  private var resolved = false

  func installContinuation(_ continuation: CheckedContinuation<Output, Error>) {
    lock.lock()
    if resolved {
      let result = pendingResolution
      pendingResolution = nil
      lock.unlock()
      if let result { continuation.resume(with: result) }
      return
    }
    self.continuation = continuation
    lock.unlock()
  }

  func installSendTask(_ task: Task<Void, Never>) {
    install(task, isSendTask: true)
  }

  func installDeadlineTask(_ task: Task<Void, Never>) {
    install(task, isSendTask: false)
  }

  func resolve(_ result: Result<Output, Error>, cancelSend: Bool) {
    lock.lock()
    guard !resolved else {
      lock.unlock()
      return
    }
    resolved = true
    let continuation = continuation
    self.continuation = nil
    if continuation == nil { pendingResolution = result }
    let sendTask = cancelSend ? sendTask : nil
    let deadlineTask = deadlineTask
    self.sendTask = nil
    self.deadlineTask = nil
    lock.unlock()

    sendTask?.cancel()
    deadlineTask?.cancel()
    continuation?.resume(with: result)
  }

  private func install(_ task: Task<Void, Never>, isSendTask: Bool) {
    lock.lock()
    guard !resolved else {
      lock.unlock()
      task.cancel()
      return
    }
    if isSendTask { sendTask = task } else { deadlineTask = task }
    lock.unlock()
  }
}

final class TacuaCaptureUploadCoordinator {
  private let configuration: TacuaBackendConfiguration
  private let captureRootDirectory: URL
  private let queueStore: TacuaCaptureUploadQueueStoring
  private let lifecycleGate: TacuaCaptureAdmissionLifecycleGating
  private let resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting
  private let retentionChecker: TacuaSDKLocalRetentionChecking?
  private let sender: TacuaSDKBackendOperationSending
  private let clock: TacuaMonotonicClock
  private let operationLock = NSLock()
  private var activeLocalSessionIDs = Set<String>()

  init(
    configuration: TacuaBackendConfiguration,
    captureRootDirectory: URL,
    queueStore: TacuaCaptureUploadQueueStoring,
    lifecycleGate: TacuaCaptureAdmissionLifecycleGating,
    resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting,
    sender: TacuaSDKBackendOperationSending,
    retentionChecker: TacuaSDKLocalRetentionChecking? = nil,
    clock: TacuaMonotonicClock = TacuaSystemMonotonicClock()
  ) {
    self.configuration = configuration
    self.captureRootDirectory = captureRootDirectory.standardizedFileURL
    self.queueStore = queueStore
    self.lifecycleGate = lifecycleGate
    self.resumeRecoveryInspector = resumeRecoveryInspector
    self.sender = sender
    self.retentionChecker = retentionChecker
    self.clock = clock
  }

  func drive(localSessionID: String) async throws -> TacuaCaptureUploadResult {
    guard validIdentifier(localSessionID), captureRootDirectory.isFileURL else {
      throw TacuaCaptureUploadError.invalidInput
    }
    try reserve(localSessionID)
    defer { release(localSessionID) }

    let lease: TacuaSDKStartLifecycleLease
    do { lease = try lifecycleGate.acquireLifecycleLease(localSessionID: localSessionID) }
    catch { throw TacuaCaptureUploadError.persistenceFailure }
    defer { lease.release() }
    try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
    do {
      if try lifecycleGate.hasStartRecovery(localSessionID: localSessionID) {
        throw TacuaCaptureUploadError.startRecoveryRequired
      }
      if try resumeRecoveryInspector.hasRecovery(localSessionID: localSessionID) {
        throw TacuaCaptureUploadError.resumeRecoveryRequired
      }
    } catch let error as TacuaCaptureUploadError { throw error }
    catch { throw TacuaCaptureUploadError.persistenceFailure }

    while true {
      try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
      switch try await driveOne(localSessionID: localSessionID) {
      case .continueDriving: continue
      case .completed(let result):
        try retentionChecker?.requireActiveHoldingLifecycleLease(localSessionID: localSessionID)
        return result
      }
    }
  }

  private func driveOne(localSessionID: String) async throws -> TacuaCaptureUploadStep {
    let baseline: TacuaTransportQueueV3
    do {
      guard let queue = try queueStore.load(localSessionID: localSessionID) else {
        throw TacuaCaptureUploadError.queueMissing
      }
      try queue.validate()
      baseline = queue
    } catch let error as TacuaCaptureUploadError { throw error }
    catch { throw TacuaCaptureUploadError.persistenceFailure }

    guard baseline.transportConfigurationDigest == configuration.configurationDigest,
      let remoteSessionID = baseline.remoteSessionID,
      baseline.scopeDigest != nil
    else { throw TacuaCaptureUploadError.queueUnavailable }

    let sessionDirectory = captureRootDirectory.appendingPathComponent(
      localSessionID,
      isDirectory: true
    ).standardizedFileURL

    // A validated completion receipt is self-contained cleanup authority. Once it is durable, raw
    // admitted payloads (including the diagnostic artifact) may already be absent, so terminal
    // recovery must not depend on rereading admission files that cleanup is specifically allowed to
    // remove. Queue validation above re-derives the authority from the exact stored receipt.
    if let authority = baseline.completionCleanupAuthority {
      let alreadyCompleted = baseline.payloadCleanupState == .payloadsRemoved
      let cleaned: TacuaTransportQueueV3
      do {
        guard let result = try queueStore.recoverPayloadCleanup(
          localSessionID: localSessionID,
          sessionDirectory: sessionDirectory
        ) else { throw TacuaCaptureUploadError.queueMissing }
        cleaned = result
      } catch let error as TacuaCaptureUploadError { throw error }
      catch { throw TacuaCaptureUploadError.cleanupPending }
      guard cleaned.payloadCleanupState == .payloadsRemoved,
        cleaned.completionCleanupAuthority == authority
      else { throw TacuaCaptureUploadError.cleanupPending }
      return .completed(result(
        queue: cleaned,
        remoteSessionID: remoteSessionID,
        completionID: authority.completionID,
        alreadyCompleted: alreadyCompleted
      ))
    }

    let plan = try loadTransportPlan(localSessionID: localSessionID, queue: baseline)
    guard plan.remoteSessionID == remoteSessionID,
      plan.scopeDigest == baseline.scopeDigest
    else { throw TacuaCaptureUploadError.admissionConflict }
    try validateQueuePlan(baseline, plan: plan)

    if let operation = nextUploadOperation(queue: baseline, plan: plan) {
      try await dispatch(
        localSessionID: localSessionID,
        operation: operation,
        baseline: baseline,
        sessionDirectory: sessionDirectory
      )
      return .continueDriving
    }

    let completionOperations = baseline.operations.filter { $0.kind == .completion }
    if completionOperations.isEmpty {
      let replacement = try queueByEnqueuingCompletion(baseline, plan: plan)
      try commit(expected: baseline, replacement: replacement)
      return .continueDriving
    }
    guard completionOperations.count == 1,
      completionOperations[0].operationID == plan.completionID
    else { throw TacuaCaptureUploadError.admissionConflict }
    try await dispatch(
      localSessionID: localSessionID,
      operation: completionOperations[0],
      baseline: baseline,
      sessionDirectory: sessionDirectory
    )
    return .continueDriving
  }

  private func nextUploadOperation(
    queue: TacuaTransportQueueV3,
    plan: TacuaCaptureTransportPlan
  ) -> TacuaQueuedOperation? {
    for operationID in plan.orderedUploadIDs {
      guard let operation = queue.operations.first(where: { $0.operationID == operationID }) else {
        return nil
      }
      if operation.state != .responseStored { return operation }
    }
    return nil
  }

  private func dispatch(
    localSessionID: String,
    operation original: TacuaQueuedOperation,
    baseline: TacuaTransportQueueV3,
    sessionDirectory: URL
  ) async throws {
    let rawMediaStopUptimeMilliseconds: Int64?
    do {
      rawMediaStopUptimeMilliseconds = try retentionChecker?
        .activeStopUptimeMillisecondsHoldingLifecycleLease(
          localSessionID: localSessionID
        )
    } catch {
      throw TacuaCaptureUploadError.retentionExpired
    }
    let activeSend = baseline.credentialCapability == .active
    let authorizedCompletionReplay = baseline.credentialCapability
      == .completionReplayOrDeleteOnly
      && original.kind == .completion
      && baseline.authorizedCompletionReplayID == original.operationID
      && original.state == .outcomeUnknown
    guard activeSend || authorizedCompletionReplay,
      let currentCredentialID = baseline.currentCredentialID
    else { throw TacuaCaptureUploadError.queueUnavailable }

    if original.state == .prepared, original.requestCredentialID != currentCredentialID {
      var replacement = baseline
      let requestedAt: String
      do { requestedAt = try baseline.timestampForNewOperation(clock: clock) }
      catch { throw TacuaCaptureUploadError.queueUnavailable }
      let rebound: TacuaPreparedBackendRequest
      do {
        rebound = try TacuaSDKBackendRequests.rebound(
          original,
          credentialID: currentCredentialID,
          requestedAt: requestedAt
        )
        try replacement.rebindPreparedOperation(
          operationID: original.operationID,
          replacement: rebound,
          clock: clock
        )
      } catch { throw TacuaCaptureUploadError.admissionConflict }
      try commit(expected: baseline, replacement: replacement)
      return
    }

    var attemptedQueue = baseline
    let attempt: TacuaOperationAttempt
    do {
      switch original.state {
      case .prepared:
        attempt = try attemptedQueue.beginAttempt(
          operationID: original.operationID,
          expectedTransportConfigurationDigest: configuration.configurationDigest,
          clock: clock
        )
        try commit(expected: baseline, replacement: attemptedQueue)
      case .outcomeUnknown:
        attempt = try attemptedQueue.outcomeUnknownAttempt(
          operationID: original.operationID,
          expectedTransportConfigurationDigest: configuration.configurationDigest,
          clock: clock
        )
      case .responseStored:
        return
      }
    } catch let error as TacuaCaptureUploadError { throw error }
    catch { throw TacuaCaptureUploadError.queueUnavailable }

    guard let durableOperation = attemptedQueue.operations.first(where: {
      $0.operationID == original.operationID
    }), durableOperation.state == .outcomeUnknown,
      durableOperation.canonicalRequest == attempt.canonicalRequest,
      durableOperation.requestCredentialID == attempt.immutableRequestCredentialID
    else { throw TacuaCaptureUploadError.persistenceFailure }
    let prepared = TacuaPreparedBackendRequest(
      kind: durableOperation.kind,
      operationID: durableOperation.operationID,
      credentialID: durableOperation.requestCredentialID,
      canonicalData: durableOperation.canonicalRequest,
      requestDigest: durableOperation.requestDigest
    )

    let receipt: TacuaValidatedBackendReceipt
    do {
      if durableOperation.kind == .segment {
        guard let binding = durableOperation.localPayloadBindings?.first(where: {
          $0.role == .segmentMedia
        }) else { throw TacuaCaptureUploadError.payloadUnavailable }
        let source = sessionDirectory.appendingPathComponent(binding.relativePath)
        receipt = try await sendBeforeRetentionDeadline(
          stopUptimeMilliseconds: rawMediaStopUptimeMilliseconds
        ) { [sender] in
          try await sender.uploadSegment(
            prepared,
            fileURL: source,
            sessionDirectory: sessionDirectory,
            transportCredentialID: attempt.transportCredentialID
          )
        }
      } else {
        receipt = try await sendBeforeRetentionDeadline(
          stopUptimeMilliseconds: rawMediaStopUptimeMilliseconds
        ) { [sender] in
          try await sender.send(
            prepared,
            transportCredentialID: attempt.transportCredentialID
          )
        }
      }
    } catch is TacuaCaptureUploadDeadlineReached {
      // The queue was already outcome-unknown before transport began. Cancel the concrete sender,
      // retire the local footprint under this existing lifecycle lease, and never let a late
      // uncooperative result flow back into receipt commit.
      guard let retentionChecker else { throw TacuaCaptureUploadError.retentionExpired }
      do {
        try retentionChecker.requireActiveHoldingLifecycleLease(
          localSessionID: localSessionID
        )
        // A timer may wake slightly early. Never claim retirement or resume transport while the
        // same immutable guard still considers raw data active.
        throw TacuaCaptureUploadError.retentionCleanupPending
      } catch TacuaSDKLocalRetentionError.expired {
        throw TacuaCaptureUploadError.retentionExpired
      } catch let error as TacuaCaptureUploadError {
        throw error
      } catch {
        throw TacuaCaptureUploadError.retentionCleanupPending
      }
    } catch let clientError as TacuaSDKBackendClientError {
      if case .backend(let proof) = clientError {
        try rebindAfterHistoricalMiss(
          proof: proof,
          operation: durableOperation,
          baseline: attemptedQueue
        )
        return
      }
      if clientError == .localPayloadMissing || clientError == .localPayloadMismatch
        || clientError == .unsafeLocalPayload || clientError == .localPayloadTooLarge
      {
        throw TacuaCaptureUploadError.payloadUnavailable
      }
      throw TacuaCaptureUploadError.transportOutcomeUnknown
    } catch let error as TacuaCaptureUploadError { throw error }
    catch { throw TacuaCaptureUploadError.transportOutcomeUnknown }

    var replacement = attemptedQueue
    do {
      try replacement.storeValidatedReceipt(receipt)
      try replacement.observeAuthoritativeReceiptTimestamp(
        receipt.authoritativeTimestamp,
        clock: clock
      )
      try replacement.validate()
    } catch { throw TacuaCaptureUploadError.receiptCommitPending }
    do { try commit(expected: attemptedQueue, replacement: replacement) }
    catch { throw TacuaCaptureUploadError.receiptCommitPending }
  }

  private func sendBeforeRetentionDeadline(
    stopUptimeMilliseconds: Int64?,
    operation: @escaping @Sendable () async throws -> TacuaValidatedBackendReceipt
  ) async throws -> TacuaValidatedBackendReceipt {
    guard let stopUptimeMilliseconds else { return try await operation() }
    let (remainingMilliseconds, subtractionOverflow) = stopUptimeMilliseconds
      .subtractingReportingOverflow(clock.uptimeMilliseconds)
    guard !subtractionOverflow, remainingMilliseconds > 0 else {
      throw TacuaCaptureUploadDeadlineReached()
    }
    let (sleepNanoseconds, overflow) = UInt64(remainingMilliseconds)
      .multipliedReportingOverflow(by: 1_000_000)
    guard !overflow else { throw TacuaCaptureUploadDeadlineReached() }

    let race = TacuaCaptureUploadDeadlineRace()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        race.installContinuation(continuation)
        let sendTask = Task {
          do {
            race.resolve(.success(try await operation()), cancelSend: false)
          } catch {
            race.resolve(.failure(error), cancelSend: false)
          }
        }
        race.installSendTask(sendTask)
        let deadlineTask = Task {
          do { try await Task.sleep(nanoseconds: sleepNanoseconds) }
          catch { return }
          race.resolve(.failure(TacuaCaptureUploadDeadlineReached()), cancelSend: true)
        }
        race.installDeadlineTask(deadlineTask)
      }
    } onCancel: {
      race.resolve(.failure(CancellationError()), cancelSend: true)
    }
  }

  private func rebindAfterHistoricalMiss(
    proof: TacuaValidatedBackendError,
    operation: TacuaQueuedOperation,
    baseline: TacuaTransportQueueV3
  ) throws {
    guard let currentCredentialID = baseline.currentCredentialID else {
      throw TacuaCaptureUploadError.queueUnavailable
    }
    let requestedAt: String
    do { requestedAt = try baseline.timestampForNewOperation(clock: clock) }
    catch { throw TacuaCaptureUploadError.queueUnavailable }
    var replacement = baseline
    do {
      let rebound = try TacuaSDKBackendRequests.rebound(
        operation,
        credentialID: currentCredentialID,
        requestedAt: requestedAt
      )
      try replacement.rebindProvenMissingHistoricalOperation(
        operationID: operation.operationID,
        replacement: rebound,
        proof: proof,
        clock: clock
      )
      try replacement.validate()
    } catch { throw TacuaCaptureUploadError.admissionConflict }
    try commit(expected: baseline, replacement: replacement)
  }

  private func queueByEnqueuingCompletion(
    _ baseline: TacuaTransportQueueV3,
    plan: TacuaCaptureTransportPlan
  ) throws -> TacuaTransportQueueV3 {
    guard baseline.credentialCapability == .active,
      let credentialID = baseline.currentCredentialID,
      let sessionID = baseline.remoteSessionID,
      let scopeDigest = baseline.scopeDigest
    else { throw TacuaCaptureUploadError.queueUnavailable }
    let requestedAt: String
    do { requestedAt = try baseline.timestampForNewOperation(clock: clock) }
    catch { throw TacuaCaptureUploadError.queueUnavailable }

    let segmentOperations = try plan.segmentUploadIDs.map { operationID in
      try requiredStoredOperation(baseline, operationID: operationID, kind: .segment)
    }
    let diagnosticOperations = try plan.diagnosticUploadIDs.map { operationID in
      try requiredStoredOperation(baseline, operationID: operationID, kind: .diagnostic)
    }
    let segmentReceipts = try segmentOperations.map {
      try TacuaCanonicalJSON.parse(requiredResponse($0))
    }
    let diagnosticReceipts = try diagnosticOperations.map {
      try TacuaCanonicalJSON.parse(requiredResponse($0))
    }
    let runtimeReceipts: [TacuaJSONValue] = try segmentReceipts.map { value in
      guard let runtime = value.objectValue?["runtime_receipt"] else {
        throw TacuaCaptureUploadError.admissionConflict
      }
      return runtime
    }

    guard case .object(var manifest) = plan.captureManifestSeed else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    manifest["upload"] = .object([
      "completed_at": .string(requestedAt),
      "last_error": .null,
      "protocol": .string("segmented-resumable-v1"),
      "receipts": .array(runtimeReceipts),
      "remote_session_id": .string(sessionID),
      "state": .string("complete"),
    ])
    let manifestDigest = try TacuaCanonicalJSON.digest(.object(manifest))
    manifest["manifest_digest"] = .string(manifestDigest)
    let request = try TacuaSDKBackendRequests.completion(
      completionID: plan.completionID,
      sessionID: sessionID,
      scopeDigest: scopeDigest,
      credentialID: credentialID,
      captureManifest: .object(manifest),
      segmentReceipts: segmentReceipts,
      diagnosticReceipts: diagnosticReceipts,
      requestedAt: requestedAt
    )
    guard try TacuaSDKBackendProtocol.validateRequest(request.canonicalData) == .completion else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    var replacement = baseline
    try replacement.enqueueNewOperation(
      kind: .completion,
      operationID: request.operationID,
      requestCredentialID: request.credentialID,
      request: try TacuaCanonicalJSON.parse(request.canonicalData),
      requestDigest: request.requestDigest,
      clock: clock
    )
    try replacement.validate()
    return replacement
  }

  private func requiredStoredOperation(
    _ queue: TacuaTransportQueueV3,
    operationID: String,
    kind: TacuaQueuedOperationKind
  ) throws -> TacuaQueuedOperation {
    guard let operation = queue.operations.first(where: { $0.operationID == operationID }),
      operation.kind == kind, operation.state == .responseStored,
      let response = operation.canonicalResponse,
      let expiry = queue.credentialExpiryLedger?[operation.requestCredentialID]
    else { throw TacuaCaptureUploadError.admissionConflict }
    let receipt = try TacuaSDKBackendProtocol.validateResponse(
      response,
      forCanonicalRequest: operation.canonicalRequest,
      expectedCurrentCredentialExpiry: expiry
    )
    guard receipt.responseDigest == operation.responseArtifactDigest else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    return operation
  }

  private func requiredResponse(_ operation: TacuaQueuedOperation) throws -> Data {
    guard let response = operation.canonicalResponse else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    return response
  }

  private func validateQueuePlan(
    _ queue: TacuaTransportQueueV3,
    plan: TacuaCaptureTransportPlan
  ) throws {
    let uploads = queue.operations.filter { $0.kind == .segment || $0.kind == .diagnostic }
    guard uploads.count == plan.orderedUploadIDs.count,
      Set(uploads.map(\.operationID)) == Set(plan.orderedUploadIDs),
      Set(plan.orderedUploadIDs).count == plan.orderedUploadIDs.count,
      queue.operations.filter({ $0.kind == .deletion }).isEmpty,
      queue.operations.filter({ $0.kind == .completion }).allSatisfy({
        $0.operationID == plan.completionID
      }),
      queue.operations.filter({ $0.kind == .completion }).count <= 1
    else { throw TacuaCaptureUploadError.admissionConflict }

    for (index, segment) in plan.segments.enumerated() {
      guard let operation = uploads.first(where: { $0.operationID == segment.uploadID }),
        operation.kind == .segment,
        (try? TacuaSDKBackendProtocol.validateRequest(operation.canonicalRequest)) == .segment,
        let request = try? TacuaCanonicalJSON.parse(operation.canonicalRequest),
        let object = request.objectValue,
        let transport = object["transport"]?.objectValue,
        object["upload_id"]?.stringValue == segment.uploadID,
        object["session_id"]?.stringValue == plan.remoteSessionID,
        object["scope_digest"]?.stringValue == plan.scopeDigest,
        object["segment_id"]?.stringValue == segment.segmentID,
        object["sequence"]?.integerValue == Int64(index),
        transport["content_type"]?.stringValue == "video/quicktime",
        transport["size_bytes"]?.integerValue == segment.sizeBytes,
        transport["content_digest"]?.stringValue == segment.contentDigest,
        object["sidecar_digest"]?.stringValue == segment.sidecarDigest,
        operation.localPayloadPath == nil,
        operation.localPayloadBindings == [
          TacuaLocalPayloadBinding(
            role: .segmentMedia,
            relativePath: segment.mediaRelativePath,
            contentDigest: segment.contentDigest
          ),
          TacuaLocalPayloadBinding(
            role: .segmentSidecar,
            relativePath: segment.sidecarRelativePath,
            contentDigest: segment.sidecarDigest
          ),
        ]
      else { throw TacuaCaptureUploadError.admissionConflict }
    }

    var expectedDiagnosticBindings = [
      TacuaLocalPayloadBinding(
        role: .diagnosticEnvelope,
        relativePath: plan.diagnostic.relativePath,
        contentDigest: plan.diagnostic.fileDigest
      )
    ]
    if let sourcePath = plan.diagnostic.sourceJournalRelativePath,
      let sourceDigest = plan.diagnostic.sourceJournalDigest
    {
      expectedDiagnosticBindings.append(TacuaLocalPayloadBinding(
        role: .diagnosticSourceJournal,
        relativePath: sourcePath,
        contentDigest: sourceDigest
      ))
    }
    guard (plan.diagnostic.sourceJournalRelativePath == nil)
      == (plan.diagnostic.sourceJournalDigest == nil),
      let diagnosticOperation = uploads.first(where: {
      $0.operationID == plan.diagnostic.uploadID
    }), diagnosticOperation.kind == .diagnostic,
      (try? TacuaSDKBackendProtocol.validateRequest(diagnosticOperation.canonicalRequest))
        == .diagnostic,
      let diagnosticRequest = try? TacuaCanonicalJSON.parse(
        diagnosticOperation.canonicalRequest
      ),
      let diagnosticObject = diagnosticRequest.objectValue,
      diagnosticObject["upload_id"]?.stringValue == plan.diagnostic.uploadID,
      diagnosticObject["session_id"]?.stringValue == plan.remoteSessionID,
      diagnosticObject["scope_digest"]?.stringValue == plan.scopeDigest,
      diagnosticObject["envelope"] == plan.diagnostic.envelope,
      diagnosticOperation.localPayloadPath == nil,
      diagnosticOperation.localPayloadBindings == expectedDiagnosticBindings
    else { throw TacuaCaptureUploadError.admissionConflict }

    if let completion = queue.operations.first(where: { $0.kind == .completion }) {
      guard (try? TacuaSDKBackendProtocol.validateRequest(completion.canonicalRequest))
        == .completion,
        let request = try? TacuaCanonicalJSON.parse(completion.canonicalRequest),
        let object = request.objectValue,
        object["completion_id"]?.stringValue == plan.completionID,
        object["session_id"]?.stringValue == plan.remoteSessionID,
        object["scope_digest"]?.stringValue == plan.scopeDigest,
        case .object(var manifest)? = object["capture_manifest"],
        manifest.removeValue(forKey: "upload") != nil,
        manifest.removeValue(forKey: "manifest_digest") != nil,
        TacuaJSONValue.object(manifest) == plan.captureManifestSeed,
        completion.localPayloadPath == nil,
        completion.localPayloadBindings == nil
      else { throw TacuaCaptureUploadError.admissionConflict }
    }
  }

  private func loadTransportPlan(
    localSessionID: String,
    queue: TacuaTransportQueueV3
  ) throws -> TacuaCaptureTransportPlan {
    let data = try readAdmission(localSessionID: localSessionID)
    let value: TacuaJSONValue
    do {
      value = try TacuaCanonicalJSON.parse(data)
      guard try TacuaCanonicalJSON.data(value) == data else {
        throw TacuaCaptureUploadError.admissionConflict
      }
    } catch let error as TacuaCaptureUploadError { throw error }
    catch { throw TacuaCaptureUploadError.admissionConflict }
    let root: [String: TacuaJSONValue]
    do {
      root = try value.requiringObject(keys: [
        "admission_digest", "admission_version", "build_identity", "capture_manifest_seed",
        "capture_summary", "contract_version", "credential_id_at_admission",
        "local_session_id", "media_type", "remote_session_id", "requested_at", "scope",
        "scope_digest", "server_time_anchor", "session_retention_authority",
        "transport_configuration_digest", "transport_plan",
      ])
    } catch { throw TacuaCaptureUploadError.admissionConflict }
    guard root["admission_version"]?.integerValue == 1,
      root["contract_version"]?.stringValue == "tacua.finalized-capture-admission@1.0.0",
      root["local_session_id"]?.stringValue == localSessionID,
      root["transport_configuration_digest"]?.stringValue == configuration.configurationDigest,
      root["media_type"]?.stringValue
        == "application/vnd.tacua.finalized-capture-admission+json;version=1.0.0",
      let requestedAt = root["requested_at"]?.stringValue,
      TacuaProtocolTimestamp.parseMilliseconds(requestedAt) != nil,
      let buildIdentity = root["build_identity"],
      let scope = root["scope"],
      let admissionDigest = root["admission_digest"]?.stringValue,
      (try? TacuaCanonicalJSON.digest(value, omittingRootField: "admission_digest"))
        == admissionDigest,
      let remoteSessionID = root["remote_session_id"]?.stringValue,
      let scopeDigest = root["scope_digest"]?.stringValue,
      let captureManifestSeed = root["capture_manifest_seed"],
      let transportPlanValue = root["transport_plan"]
    else { throw TacuaCaptureUploadError.admissionConflict }
    do {
      try TacuaSDKBackendRequests.validateStartArtifacts(
        buildIdentity: buildIdentity,
        scope: scope,
        requestedAt: requestedAt,
        configuration: configuration
      )
    } catch { throw TacuaCaptureUploadError.admissionConflict }
    guard let scopeObject = scope.objectValue,
      scopeObject["scope_digest"]?.stringValue == scopeDigest,
      let buildObject = buildIdentity.objectValue,
      let credentialAtAdmission = root["credential_id_at_admission"]?.stringValue,
      validIdentifier(credentialAtAdmission),
      queue.credentialExpiryLedger?[credentialAtAdmission] != nil,
      queue.remoteSessionID == remoteSessionID,
      queue.scopeDigest == scopeDigest,
      queue.transportConfigurationDigest == configuration.configurationDigest,
      let retentionAuthority = queue.sessionRetentionAuthority,
      root["session_retention_authority"] == retentionAuthorityValue(retentionAuthority),
      validateAdmissionAnchor(root["server_time_anchor"], requestedAt: requestedAt),
      validateRetentionScope(scopeObject["retention"], authority: retentionAuthority)
    else { throw TacuaCaptureUploadError.admissionConflict }

    let transportPlan: [String: TacuaJSONValue]
    do {
      transportPlan = try transportPlanValue.requiringObject(keys: [
        "completion_id", "diagnostic", "segments",
      ])
    } catch { throw TacuaCaptureUploadError.admissionConflict }
    guard let completionID = transportPlan["completion_id"]?.stringValue,
      completionID == "completion_capture_000001",
      let diagnosticValue = transportPlan["diagnostic"],
      let segmentValues = transportPlan["segments"]?.arrayValue,
      (1...2_048).contains(segmentValues.count)
    else { throw TacuaCaptureUploadError.admissionConflict }
    guard let diagnostic = diagnosticValue.objectValue else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    let diagnosticBaseKeys = Set(["envelope_digest", "relative_path", "upload_id"])
    let diagnosticKeys = Set(diagnostic.keys)
    guard diagnosticKeys == diagnosticBaseKeys
      || diagnosticKeys == diagnosticBaseKeys.union(["source_journal"])
    else { throw TacuaCaptureUploadError.admissionConflict }
    guard let diagnosticID = diagnostic["upload_id"]?.stringValue,
      diagnosticID == "upload_diagnostic_000001",
      diagnostic["relative_path"]?.stringValue
        == TacuaCaptureAdmissionCoordinator.diagnosticFileName,
      let envelopeDigest = diagnostic["envelope_digest"]?.stringValue,
      validDigest(envelopeDigest)
    else { throw TacuaCaptureUploadError.admissionConflict }
    var sourceJournalRelativePath: String?
    var sourceJournalDigest: String?
    if let sourceValue = diagnostic["source_journal"] {
      let source: [String: TacuaJSONValue]
      do {
        source = try sourceValue.requiringObject(keys: [
          "content_digest", "relative_path",
        ])
      } catch { throw TacuaCaptureUploadError.admissionConflict }
      let expectedSourcePath: String
      do { expectedSourcePath = try TacuaDiagnosticJournal.relativePath(
        localSessionID: localSessionID
      ) } catch { throw TacuaCaptureUploadError.admissionConflict }
      guard source["relative_path"]?.stringValue == expectedSourcePath,
        let digest = source["content_digest"]?.stringValue,
        validDigest(digest)
      else { throw TacuaCaptureUploadError.admissionConflict }
      sourceJournalRelativePath = expectedSourcePath
      sourceJournalDigest = digest
    }

    guard let manifestSeedObject = captureManifestSeed.objectValue else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    let legacyManifestSeedKeys: Set<String> = [
      "build_id", "build_identity_digest", "capture_scope", "capture_state",
      "contract_version", "ended_at", "gaps", "manifest_version", "media_type",
      "monotonic_duration_ms", "organization_id", "project_id", "retention", "segments",
      "session_id", "started_at", "streams",
    ]
    guard Set(manifestSeedObject.keys) == legacyManifestSeedKeys
      || Set(manifestSeedObject.keys)
        == legacyManifestSeedKeys.union(["app_audio_accounting"])
    else { throw TacuaCaptureUploadError.admissionConflict }
    guard manifestSeedObject["contract_version"]?.stringValue
        == "tacua.capture-upload-manifest@1.0.0",
      manifestSeedObject["media_type"]?.stringValue
        == "application/vnd.tacua.capture-upload-manifest+json;version=1.0.0",
      manifestSeedObject["manifest_version"]?.integerValue == 1,
      manifestSeedObject["session_id"]?.stringValue == remoteSessionID,
      manifestSeedObject["build_id"] == scopeObject["build_id"],
      manifestSeedObject["build_identity_digest"] == scopeObject["build_identity_digest"],
      manifestSeedObject["organization_id"] == scopeObject["organization_id"],
      manifestSeedObject["project_id"] == scopeObject["project_id"],
      manifestSeedObject["capture_scope"] == scopeObject["capture_scope"],
      manifestSeedObject["capture_state"]?.stringValue == "complete",
      manifestSeedObject["retention"] == manifestRetentionValue(retentionAuthority),
      validateManifestTimeline(manifestSeedObject),
      let runtimeSegments = manifestSeedObject["segments"]?.arrayValue,
      runtimeSegments.count == segmentValues.count
    else { throw TacuaCaptureUploadError.admissionConflict }
    do {
      try TacuaSDKBackendProtocol.validateRuntimeAppAudioAccounting(
        manifestSeedObject["app_audio_accounting"], runtimeSegments: runtimeSegments
      )
    } catch { throw TacuaCaptureUploadError.admissionConflict }

    let segments: [TacuaCaptureTransportPlan.Segment] = try segmentValues.enumerated().map {
      index, segmentValue in
      let segment: [String: TacuaJSONValue]
      do {
        segment = try segmentValue.requiringObject(keys: [
          "media_relative_path", "segment_id", "sidecar_relative_path", "upload_id",
        ])
      } catch { throw TacuaCaptureUploadError.admissionConflict }
      let expectedUploadID = String(format: "upload_segment_%06d", index)
      let expectedSegmentID = String(format: "segment_%06d", index)
      guard let uploadID = segment["upload_id"]?.stringValue,
        uploadID == expectedUploadID,
        let segmentID = segment["segment_id"]?.stringValue,
        segmentID == expectedSegmentID,
        let mediaPath = segment["media_relative_path"]?.stringValue,
        validRelativePath(mediaPath),
        mediaPath.range(of: "^segment-[0-9]{6}\\.mov$", options: .regularExpression) != nil,
        let sidecarPath = segment["sidecar_relative_path"]?.stringValue,
        validRelativePath(sidecarPath),
        sidecarPath == String(mediaPath.dropLast(4)) + ".segment.json",
        let runtime = runtimeSegments[index].objectValue,
        runtime["segment_id"]?.stringValue == segmentID,
        runtime["sequence"]?.integerValue == Int64(index),
        runtime["availability"]?.stringValue == "available",
        runtime["finalized"]?.boolValue == true,
        runtime["unavailable"] == .null,
        let content = runtime["content"]?.objectValue,
        content["content_type"]?.stringValue == "video/quicktime",
        let sizeBytes = content["size_bytes"]?.integerValue,
        sizeBytes > 0, sizeBytes <= TacuaSDKBackendProtocol.maximumUploadBytes,
        let contentDigest = content["content_digest"]?.stringValue,
        validDigest(contentDigest),
        let sidecarDigest = content["sidecar_digest"]?.stringValue,
        validDigest(sidecarDigest)
      else {
        throw TacuaCaptureUploadError.admissionConflict
      }
      return TacuaCaptureTransportPlan.Segment(
        uploadID: uploadID,
        segmentID: segmentID,
        mediaRelativePath: mediaPath,
        sidecarRelativePath: sidecarPath,
        sizeBytes: sizeBytes,
        contentDigest: contentDigest,
        sidecarDigest: sidecarDigest
      )
    }
    guard Set(segments.map(\.uploadID)).count == segments.count,
      Set(segments.map(\.mediaRelativePath)).count == segments.count,
      Set(segments.map(\.sidecarRelativePath)).count == segments.count,
      !segments.contains(where: { $0.uploadID == diagnosticID }),
      completionID != diagnosticID,
      !segments.contains(where: { $0.uploadID == completionID })
    else { throw TacuaCaptureUploadError.admissionConflict }

    let diagnosticData: Data?
    do {
      diagnosticData = try readCaptureArtifact(
        localSessionID: localSessionID,
        fileName: TacuaCaptureAdmissionCoordinator.diagnosticFileName,
        missingError: .admissionMissing
      )
    } catch TacuaCaptureUploadError.admissionMissing
      where queue.payloadCleanupState == .payloadsRemoved
        && queue.completionCleanupAuthority != nil
    {
      diagnosticData = nil
    }
    let diagnosticEnvelope: TacuaJSONValue
    let diagnosticFileDigest: String
    do {
      if let diagnosticData {
        diagnosticEnvelope = try TacuaCanonicalJSON.parse(diagnosticData)
        guard try TacuaCanonicalJSON.data(diagnosticEnvelope) == diagnosticData else {
          throw TacuaCaptureUploadError.admissionConflict
        }
        diagnosticFileDigest = TacuaCanonicalJSON.digest(data: diagnosticData)
      } else {
        guard let operation = queue.operations.first(where: {
          $0.kind == .diagnostic && $0.operationID == diagnosticID
        }),
          let request = try? TacuaCanonicalJSON.parse(operation.canonicalRequest),
          let envelope = request.objectValue?["envelope"],
          let binding = operation.localPayloadBindings?.first(where: {
            $0.role == .diagnosticEnvelope
              && $0.relativePath == TacuaCaptureAdmissionCoordinator.diagnosticFileName
          })
        else { throw TacuaCaptureUploadError.admissionConflict }
        diagnosticEnvelope = envelope
        diagnosticFileDigest = binding.contentDigest
      }
      guard
        diagnosticEnvelope.objectValue?["envelope_digest"]?.stringValue == envelopeDigest,
        try TacuaCanonicalJSON.digest(
          diagnosticEnvelope,
          omittingRootField: "envelope_digest"
        ) == envelopeDigest,
        validateDiagnosticEnvelope(
          diagnosticEnvelope,
          summary: root["capture_summary"],
          buildIdentity: buildObject,
          scope: scopeObject,
          remoteSessionID: remoteSessionID
        )
      else { throw TacuaCaptureUploadError.admissionConflict }
    } catch let error as TacuaCaptureUploadError { throw error }
    catch { throw TacuaCaptureUploadError.admissionConflict }

    return TacuaCaptureTransportPlan(
      admissionDigest: admissionDigest,
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      completionID: completionID,
      segments: segments,
      diagnostic: TacuaCaptureTransportPlan.Diagnostic(
        uploadID: diagnosticID,
        relativePath: TacuaCaptureAdmissionCoordinator.diagnosticFileName,
        envelopeDigest: envelopeDigest,
        fileDigest: diagnosticFileDigest,
        sourceJournalRelativePath: sourceJournalRelativePath,
        sourceJournalDigest: sourceJournalDigest,
        envelope: diagnosticEnvelope
      ),
      captureManifestSeed: captureManifestSeed
    )
  }

  private func readAdmission(localSessionID: String) throws -> Data {
    try readCaptureArtifact(
      localSessionID: localSessionID,
      fileName: TacuaCaptureAdmissionCoordinator.admissionFileName,
      missingError: .admissionMissing
    )
  }

  private func retentionAuthorityValue(
    _ authority: TacuaSessionRetentionAuthority
  ) -> TacuaJSONValue {
    .object([
      "derived_data_expires_at": .string(authority.derivedDataExpiresAt),
      "raw_media_expires_at": .string(authority.rawMediaExpiresAt),
      "session_received_at": .string(authority.sessionReceivedAt),
    ])
  }

  private func manifestRetentionValue(
    _ authority: TacuaSessionRetentionAuthority
  ) -> TacuaJSONValue {
    .object([
      "deletion_status": .string("active"),
      "derived_data_expires_at": .string(authority.derivedDataExpiresAt),
      "policy_version": .string("tacua.retention@1.0.0"),
      "raw_media_expires_at": .string(authority.rawMediaExpiresAt),
    ])
  }

  private func validateRetentionScope(
    _ value: TacuaJSONValue?,
    authority: TacuaSessionRetentionAuthority
  ) -> Bool {
    guard let value,
      let object = try? value.requiringObject(keys: [
        "derived_data_days", "policy_version", "raw_media_days",
      ]),
      object["policy_version"]?.stringValue == "tacua.retention-v1",
      let received = TacuaProtocolTimestamp.parseMilliseconds(authority.sessionReceivedAt),
      let raw = TacuaProtocolTimestamp.parseMilliseconds(authority.rawMediaExpiresAt),
      let derived = TacuaProtocolTimestamp.parseMilliseconds(authority.derivedDataExpiresAt),
      let rawDays = object["raw_media_days"]?.integerValue,
      let derivedDays = object["derived_data_days"]?.integerValue,
      raw == received + rawDays * 86_400_000,
      derived == received + derivedDays * 86_400_000
    else { return false }
    return true
  }

  private func validateAdmissionAnchor(
    _ value: TacuaJSONValue?,
    requestedAt: String
  ) -> Bool {
    guard let value,
      let object = try? value.requiringObject(keys: [
        "boot_session_id", "issued_at", "issued_epoch_milliseconds",
        "minimum_epoch_milliseconds", "uptime_milliseconds_at_issue",
      ]),
      let bootSessionID = object["boot_session_id"]?.stringValue,
      !bootSessionID.isEmpty, bootSessionID != "unavailable", bootSessionID.utf8.count <= 255,
      let issuedAt = object["issued_at"]?.stringValue,
      let issued = TacuaProtocolTimestamp.parseMilliseconds(issuedAt),
      object["issued_epoch_milliseconds"]?.integerValue == issued,
      let minimum = object["minimum_epoch_milliseconds"]?.integerValue,
      minimum >= issued,
      let uptime = object["uptime_milliseconds_at_issue"]?.integerValue,
      uptime >= 0,
      let requested = TacuaProtocolTimestamp.parseMilliseconds(requestedAt),
      requested >= minimum
    else { return false }
    return true
  }

  private func validateManifestTimeline(
    _ manifest: [String: TacuaJSONValue]
  ) -> Bool {
    guard let startedAt = manifest["started_at"]?.stringValue,
      let endedAt = manifest["ended_at"]?.stringValue,
      let started = TacuaProtocolTimestamp.parseMilliseconds(startedAt),
      let ended = TacuaProtocolTimestamp.parseMilliseconds(endedAt),
      ended >= started,
      let duration = manifest["monotonic_duration_ms"]?.integerValue,
      (0...1_800_000).contains(duration),
      abs((ended - started) - duration) < 1_000,
      let gaps = manifest["gaps"]?.arrayValue,
      gaps.count <= 2_048,
      manifest["streams"]?.objectValue != nil
    else { return false }
    return true
  }

  private func validateDiagnosticEnvelope(
    _ envelope: TacuaJSONValue,
    summary: TacuaJSONValue?,
    buildIdentity: [String: TacuaJSONValue],
    scope: [String: TacuaJSONValue],
    remoteSessionID: String
  ) -> Bool {
    guard let summary,
      (try? summary.requiringObject(keys: [
        "app_audio_accounting_complete", "app_audio_append_attempts",
        "app_audio_append_drops", "app_audio_available", "app_audio_unknown_range_count",
        "error_count", "gap_count", "marker_count", "microphone_available", "segment_count",
      ])) != nil,
      let root = try? envelope.requiringObject(keys: [
        "build_id", "build_identity_digest", "collection_gaps", "contract_version",
        "envelope_digest", "envelope_id", "envelope_version", "events", "evidence",
        "media_type", "organization_id", "project_id", "redaction", "sequence_range",
        "session_id",
      ]),
      root["contract_version"]?.stringValue == "tacua.diagnostic-envelope@1.0.0",
      root["media_type"]?.stringValue
        == "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0",
      root["session_id"]?.stringValue == remoteSessionID,
      root["build_id"] == scope["build_id"],
      root["build_identity_digest"] == buildIdentity["build_identity_digest"],
      root["organization_id"] == scope["organization_id"],
      root["project_id"] == scope["project_id"],
      let events = root["events"]?.arrayValue, !events.isEmpty,
      events.count <= TacuaDiagnosticJournal.maximumEvents,
      let event = events.last?.objectValue,
      let data = event["data"]?.objectValue,
      event["event_type"]?.stringValue == "custom_state",
      event["source"]?.stringValue == "mobile_sdk",
      data["snapshot_digest"]?.stringValue == (try? TacuaCanonicalJSON.digest(summary)),
      data["provider_id"]?.stringValue == "capture_summary",
      data["collection_status"]?.stringValue == "available"
    else { return false }
    return true
  }

  private func readCaptureArtifact(
    localSessionID: String,
    fileName: String,
    missingError: TacuaCaptureUploadError
  ) throws -> Data {
    guard !fileName.isEmpty, !fileName.contains("/"), fileName != ".", fileName != ".." else {
      throw TacuaCaptureUploadError.admissionConflict
    }
    let rootDescriptor = open(
      captureRootDirectory.path,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard rootDescriptor >= 0 else { throw missingError }
    defer { close(rootDescriptor) }
    let sessionDescriptor = localSessionID.withCString {
      openat(rootDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard sessionDescriptor >= 0 else { throw missingError }
    defer { close(sessionDescriptor) }
    let descriptor = fileName.withCString {
      openat(sessionDescriptor, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else { throw missingError }
    defer { close(descriptor) }
    var before = stat()
    guard fstat(descriptor, &before) == 0,
      (before.st_mode & S_IFMT) == S_IFREG, before.st_nlink == 1,
      before.st_size > 0, before.st_size <= TacuaCanonicalJSON.defaultMaximumBytes
    else { throw TacuaCaptureUploadError.admissionConflict }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    let data: Data
    do { data = try handle.readToEnd() ?? Data() }
    catch { throw TacuaCaptureUploadError.persistenceFailure }
    var after = stat()
    guard Int64(data.count) == before.st_size,
      fstat(descriptor, &after) == 0,
      before.st_dev == after.st_dev, before.st_ino == after.st_ino,
      before.st_size == after.st_size,
      before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
      before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
      before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
    else { throw TacuaCaptureUploadError.admissionConflict }
    return data
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
    else { throw TacuaCaptureUploadError.persistenceFailure }
    do { try queueStore.compareAndSwap(expected: replacement, replacement: replacement) }
    catch { throw TacuaCaptureUploadError.persistenceFailure }
  }

  private func result(
    queue: TacuaTransportQueueV3,
    remoteSessionID: String,
    completionID: String,
    alreadyCompleted: Bool
  ) -> TacuaCaptureUploadResult {
    TacuaCaptureUploadResult(
      localSessionID: queue.localSessionID,
      remoteSessionID: remoteSessionID,
      completionID: completionID,
      segmentReceiptCount: queue.operations.filter {
        $0.kind == .segment && $0.state == .responseStored
      }.count,
      diagnosticReceiptCount: queue.operations.filter {
        $0.kind == .diagnostic && $0.state == .responseStored
      }.count,
      payloadCleanupState: queue.payloadCleanupState,
      alreadyCompleted: alreadyCompleted
    )
  }

  private func reserve(_ localSessionID: String) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    guard activeLocalSessionIDs.insert(localSessionID).inserted else {
      throw TacuaCaptureUploadError.alreadyInProgress
    }
  }

  private func release(_ localSessionID: String) {
    operationLock.lock()
    activeLocalSessionIDs.remove(localSessionID)
    operationLock.unlock()
  }

  private func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private func validDigest(_ value: String) -> Bool {
    value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private func validRelativePath(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 1_024, !value.hasPrefix("/") else {
      return false
    }
    let components = value.split(separator: "/", omittingEmptySubsequences: false)
    return !components.isEmpty && components.allSatisfy {
      !$0.isEmpty && $0 != "." && $0 != ".."
    }
  }
}
