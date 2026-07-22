// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Darwin
import Foundation

enum TacuaCaptureAdmissionError: Error, Equatable {
  case invalidInput
  case startRecoveryRequired
  case resumeRecoveryRequired
  case queueMissing
  case queueUnavailable
  case retentionAuthorityMissing
  case captureMissing
  case captureNotFinalized
  case captureIdentityMismatch
  case captureClockUnavailable
  case noVerifiedSegments
  case microphoneSamplesMissing
  case unsafeCaptureStorage
  case captureArtifactMismatch
  case admissionConflict
  case persistenceFailure

  var code: String {
    switch self {
    case .invalidInput: return "ERR_TACUA_CAPTURE_ADMISSION_INPUT"
    case .startRecoveryRequired: return "ERR_TACUA_CAPTURE_ADMISSION_START_RECOVERY"
    case .resumeRecoveryRequired: return "ERR_TACUA_CAPTURE_ADMISSION_RESUME_RECOVERY"
    case .queueMissing: return "ERR_TACUA_CAPTURE_ADMISSION_QUEUE_MISSING"
    case .queueUnavailable: return "ERR_TACUA_CAPTURE_ADMISSION_QUEUE_UNAVAILABLE"
    case .retentionAuthorityMissing: return "ERR_TACUA_CAPTURE_ADMISSION_RETENTION_AUTHORITY"
    case .captureMissing: return "ERR_TACUA_CAPTURE_ADMISSION_CAPTURE_MISSING"
    case .captureNotFinalized: return "ERR_TACUA_CAPTURE_ADMISSION_NOT_FINALIZED"
    case .captureIdentityMismatch: return "ERR_TACUA_CAPTURE_ADMISSION_IDENTITY"
    case .captureClockUnavailable: return "ERR_TACUA_CAPTURE_ADMISSION_CLOCK"
    case .noVerifiedSegments: return "ERR_TACUA_CAPTURE_ADMISSION_NO_SEGMENTS"
    case .microphoneSamplesMissing: return "ERR_TACUA_CAPTURE_ADMISSION_MICROPHONE"
    case .unsafeCaptureStorage: return "ERR_TACUA_CAPTURE_ADMISSION_STORAGE_UNSAFE"
    case .captureArtifactMismatch: return "ERR_TACUA_CAPTURE_ADMISSION_ARTIFACT_MISMATCH"
    case .admissionConflict: return "ERR_TACUA_CAPTURE_ADMISSION_CONFLICT"
    case .persistenceFailure: return "ERR_TACUA_CAPTURE_ADMISSION_PERSISTENCE"
    }
  }

  var message: String {
    switch self {
    case .invalidInput:
      return "The finalized-capture admission input is malformed."
    case .startRecoveryRequired:
      return "Backend START recovery must finish before capture admission."
    case .resumeRecoveryRequired:
      return "Backend RESUME recovery must finish before capture admission."
    case .queueMissing:
      return "The capture has no committed backend session queue."
    case .queueUnavailable:
      return "The backend session cannot admit new capture uploads; finish RESUME recovery first."
    case .retentionAuthorityMissing:
      return "The backend queue predates durable START retention authority and cannot safely complete this capture."
    case .captureMissing:
      return "The finalized local capture session does not exist."
    case .captureNotFinalized:
      return "The local capture has not reached an uploadable terminal state."
    case .captureIdentityMismatch:
      return "The local capture, build identity, scope, and backend session do not describe the same app build."
    case .captureClockUnavailable:
      return "The capture chronology cannot be bound to the durable backend clock on this boot."
    case .noVerifiedSegments:
      return "The local capture has no verified finalized media segment."
    case .microphoneSamplesMissing:
      return "The narrated capture has no verified microphone samples."
    case .unsafeCaptureStorage:
      return "The local capture storage contains an unsafe file or path."
    case .captureArtifactMismatch:
      return "A finalized capture artifact changed or does not match its durable sidecar."
    case .admissionConflict:
      return "This session already contains a different capture admission or stable upload identifier."
    case .persistenceFailure:
      return "Tacua could not durably admit the finalized capture."
    }
  }
}

struct TacuaCaptureAdmissionInput {
  let localSessionID: String
  /// Optional only for migrated queues. Current queues carry these canonical public artifacts and
  /// admission derives them without asking the host to reconstruct earlier START state.
  let buildIdentityJSON: Data?
  let scopeJSON: Data?
}

struct TacuaCaptureAdmissionResult: Equatable {
  let localSessionID: String
  let remoteSessionID: String
  let admissionDigest: String
  let diagnosticEnvelopeDigest: String
  let segmentCount: Int
  let admittedOperationCount: Int
  let alreadyAdmitted: Bool
}

protocol TacuaCaptureAdmissionQueueStoring {
  func load(localSessionID: String) throws -> TacuaTransportQueueV3?
  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws
}

extension TacuaTransportQueueFileStore: TacuaCaptureAdmissionQueueStoring {}

protocol TacuaCaptureAdmissionLifecycleGating {
  func acquireLifecycleLease(localSessionID: String) throws -> TacuaSDKStartLifecycleLease
  func hasStartRecovery(localSessionID: String) throws -> Bool
}

extension TacuaSDKStartJournalFileStore: TacuaCaptureAdmissionLifecycleGating {
  func hasStartRecovery(localSessionID: String) throws -> Bool {
    try load(localSessionID: localSessionID) != nil
  }
}

private struct TacuaAdmissionLocalSegment: Codable, Equatable {
  let index: Int
  let fileName: String
  let sha256: String
  let byteLength: Int64
  let firstMediaPTSSeconds: Double
  let lastMediaPTSSeconds: Double
  let firstHostUptimeSeconds: Double
  let lastHostUptimeSeconds: Double
  let durationSeconds: Double
  let videoSamples: Int
  let heldVideoSamples: Int?
  let appAudioSamples: Int
  let microphoneSamples: Int
  let droppedVideoSamples: Int
  let droppedAppAudioSamples: Int
  let droppedMicrophoneSamples: Int
}

private struct TacuaAdmissionLocalGap: Decodable {
  let id: String
  let reason: String
  let openedHostUptimeSeconds: Double
  let closedHostUptimeSeconds: Double?
}

private struct TacuaAdmissionLocalMarker: Decodable {
  // Decode only chronology and the stable identifier. Marker labels and narration text never
  // enter admission.
  let id: String
  let hostUptimeSeconds: Double
}

private struct TacuaAdmissionDiagnosticSource {
  let snapshot: TacuaDiagnosticSnapshot
  let relativePath: String
  let contentDigest: String
  let identity: TacuaAdmissionFileIdentity
}

private struct TacuaAdmissionDiagnosticProjection {
  let events: [TacuaJSONValue]
  let collectionGaps: [TacuaJSONValue]
}

private enum TacuaAdmissionDiagnosticRetentionPriority: Int {
  /// Manifest fallbacks are the only remaining representation when the journal was already full.
  case manifestCritical = 0
  /// Native issue marks, capture gaps, and explicit collection-loss signals outrank routine data.
  case journalCritical = 1
  case ordinary = 2
}

private struct TacuaAdmissionDiagnosticCandidate {
  let eventID: String
  let elapsedMilliseconds: Int64
  let stableOrder: Int64
  let eventType: String
  let data: TacuaJSONValue
  let retentionPriority: TacuaAdmissionDiagnosticRetentionPriority
}

private struct TacuaAdmissionCollectionGapCandidate {
  let startMilliseconds: Int64
  let endMilliseconds: Int64
  let stableOrder: Int64
  let gapID: String
  let value: TacuaJSONValue
}

private struct TacuaAdmissionDiagnosticOverflow {
  let omittedEventCount: Int
  let startMilliseconds: Int64
  let endMilliseconds: Int64
}

private struct TacuaAdmissionManifestGapBinding {
  let originalOffset: Int
  let gap: TacuaAdmissionLocalGap
  let journalGapID: String
  let outputGapID: String
}

private struct TacuaAdmissionLocalManifest: Decodable {
  let schemaVersion: Int
  let bootSessionId: String?
  let sessionId: String
  let organizationId: String?
  let projectId: String?
  let buildId: String?
  let consentVersion: String?
  let expectedApplicationId: String?
  let expectedBuildNumber: String?
  let state: String
  let startedHostUptimeSeconds: Double?
  let stoppedHostUptimeSeconds: Double?
  let stopReason: String?
  let segments: [TacuaAdmissionLocalSegment]
  let gaps: [TacuaAdmissionLocalGap]
  let markers: [TacuaAdmissionLocalMarker]
  let errorCodes: [String]
  let microphoneSamplesObserved: Int?
  let appAudioSamplesObserved: Int?
}

private struct TacuaAdmissionFileIdentity: Equatable {
  let name: String
  let device: dev_t
  let inode: ino_t
  let size: off_t
  let modifiedSeconds: Int
  let modifiedNanoseconds: Int
  let changedSeconds: Int
  let changedNanoseconds: Int

  init(name: String, metadata: stat) {
    self.name = name
    device = metadata.st_dev
    inode = metadata.st_ino
    size = metadata.st_size
    modifiedSeconds = metadata.st_mtimespec.tv_sec
    modifiedNanoseconds = metadata.st_mtimespec.tv_nsec
    changedSeconds = metadata.st_ctimespec.tv_sec
    changedNanoseconds = metadata.st_ctimespec.tv_nsec
  }

  init(name: String, rebasing identity: TacuaAdmissionFileIdentity) {
    self.name = name
    device = identity.device
    inode = identity.inode
    size = identity.size
    modifiedSeconds = identity.modifiedSeconds
    modifiedNanoseconds = identity.modifiedNanoseconds
    changedSeconds = identity.changedSeconds
    changedNanoseconds = identity.changedNanoseconds
  }

  func matches(_ metadata: stat) -> Bool {
    device == metadata.st_dev && inode == metadata.st_ino && size == metadata.st_size
      && modifiedSeconds == metadata.st_mtimespec.tv_sec
      && modifiedNanoseconds == metadata.st_mtimespec.tv_nsec
      && changedSeconds == metadata.st_ctimespec.tv_sec
      && changedNanoseconds == metadata.st_ctimespec.tv_nsec
  }
}

private struct TacuaAdmissionVerifiedFile {
  let identity: TacuaAdmissionFileIdentity
  let digest: String
  let data: Data?
}

private struct TacuaAdmissionSegmentPlan {
  let sequence: Int64
  let segmentID: String
  let uploadID: String
  let mediaName: String
  let sidecarName: String
  let sizeBytes: Int64
  let contentDigest: String
  let sidecarDigest: String
  let startMilliseconds: Int64
  let endMilliseconds: Int64
}

private struct TacuaAdmissionAuthority {
  let credentialID: String
  let requestedAt: String
  let timeAnchor: TacuaServerTimeAnchor
  let retentionAuthority: TacuaSessionRetentionAuthority
}

private struct TacuaPreparedCaptureAdmission {
  let artifact: TacuaJSONValue
  let artifactData: Data
  let artifactDigest: String
  let diagnosticEnvelope: TacuaJSONValue
  let diagnosticData: Data
  let diagnosticDigest: String
  let operations: [(TacuaPreparedBackendRequest, [TacuaLocalPayloadBinding])]
  let trackedFiles: [TacuaAdmissionFileIdentity]
  let segmentCount: Int
}

final class TacuaCaptureAdmissionCoordinator {
  static let admissionFileName = "backend-admission-v1.json"
  static let diagnosticFileName = "diagnostic-envelope-v1.json"
  /// Leaves room in the four-MiB canonical envelope for collection-gap metadata and root fields.
  static let maximumProjectedDiagnosticEventBytes = 3 * 1_024 * 1_024
  static let maximumProjectedCollectionGaps = 2_048

  private let configuration: TacuaBackendConfiguration
  private let captureRootDirectory: URL
  private let queueStore: TacuaCaptureAdmissionQueueStoring
  private let lifecycleGate: TacuaCaptureAdmissionLifecycleGating
  private let resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting
  private let retentionChecker: TacuaSDKLocalRetentionChecking?
  private let clock: TacuaMonotonicClock
  private let directorySynchronizer: (Int32) -> Bool
  private let projectedDiagnosticEventLimit: Int
  private let projectedDiagnosticEventByteLimit: Int
  private let projectedCollectionGapLimit: Int
  private let operationLock = NSLock()
  private var activeLocalSessionIDs = Set<String>()

  init(
    configuration: TacuaBackendConfiguration,
    captureRootDirectory: URL,
    queueStore: TacuaCaptureAdmissionQueueStoring,
    lifecycleGate: TacuaCaptureAdmissionLifecycleGating,
    resumeRecoveryInspector: TacuaSDKResumeRecoveryInspecting,
    retentionChecker: TacuaSDKLocalRetentionChecking? = nil,
    clock: TacuaMonotonicClock = TacuaSystemMonotonicClock(),
    directorySynchronizer: @escaping (Int32) -> Bool = { fsync($0) == 0 },
    projectedDiagnosticEventLimit: Int = TacuaDiagnosticJournal.maximumEvents,
    projectedDiagnosticEventByteLimit: Int = TacuaCaptureAdmissionCoordinator
      .maximumProjectedDiagnosticEventBytes,
    projectedCollectionGapLimit: Int = TacuaCaptureAdmissionCoordinator
      .maximumProjectedCollectionGaps
  ) {
    precondition((3...TacuaDiagnosticJournal.maximumEvents).contains(
      projectedDiagnosticEventLimit
    ))
    precondition((16 * 1_024...TacuaCanonicalJSON.defaultMaximumBytes).contains(
      projectedDiagnosticEventByteLimit
    ))
    precondition((1...Self.maximumProjectedCollectionGaps).contains(
      projectedCollectionGapLimit
    ))
    self.configuration = configuration
    self.captureRootDirectory = captureRootDirectory.standardizedFileURL
    self.queueStore = queueStore
    self.lifecycleGate = lifecycleGate
    self.resumeRecoveryInspector = resumeRecoveryInspector
    self.retentionChecker = retentionChecker
    self.clock = clock
    self.directorySynchronizer = directorySynchronizer
    self.projectedDiagnosticEventLimit = projectedDiagnosticEventLimit
    self.projectedDiagnosticEventByteLimit = projectedDiagnosticEventByteLimit
    self.projectedCollectionGapLimit = projectedCollectionGapLimit
  }

  static func applicationSupportCaptureRoot(fileManager: FileManager = .default) throws -> URL {
    let applicationSupport = try fileManager.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: false
    )
    return applicationSupport.appendingPathComponent("TacuaCaptureSpike", isDirectory: true)
  }

  func admit(_ input: TacuaCaptureAdmissionInput) throws -> TacuaCaptureAdmissionResult {
    guard validIdentifier(input.localSessionID),
      captureRootDirectory.isFileURL
    else { throw TacuaCaptureAdmissionError.invalidInput }
    try reserve(input.localSessionID)
    defer { release(input.localSessionID) }

    let lease: TacuaSDKStartLifecycleLease
    do {
      lease = try lifecycleGate.acquireLifecycleLease(localSessionID: input.localSessionID)
    } catch {
      throw TacuaCaptureAdmissionError.persistenceFailure
    }
    defer { lease.release() }

    try retentionChecker?.requireActiveHoldingLifecycleLease(
      localSessionID: input.localSessionID
    )

    do {
      if try lifecycleGate.hasStartRecovery(localSessionID: input.localSessionID) {
        throw TacuaCaptureAdmissionError.startRecoveryRequired
      }
      if try resumeRecoveryInspector.hasRecovery(localSessionID: input.localSessionID) {
        throw TacuaCaptureAdmissionError.resumeRecoveryRequired
      }
    } catch let error as TacuaCaptureAdmissionError {
      throw error
    } catch {
      throw TacuaCaptureAdmissionError.persistenceFailure
    }

    let baseline: TacuaTransportQueueV3
    do {
      guard let loaded = try queueStore.load(localSessionID: input.localSessionID) else {
        throw TacuaCaptureAdmissionError.queueMissing
      }
      try loaded.validate()
      baseline = loaded
    } catch let error as TacuaCaptureAdmissionError {
      throw error
    } catch {
      throw TacuaCaptureAdmissionError.persistenceFailure
    }

    guard let remoteSessionID = baseline.remoteSessionID,
      let scopeDigest = baseline.scopeDigest,
      baseline.transportConfigurationDigest == configuration.configurationDigest
    else { throw TacuaCaptureAdmissionError.queueUnavailable }

    let artifacts = try resolveSessionArtifacts(input: input, queue: baseline)
    let buildIdentity = artifacts.buildIdentity
    let scope = artifacts.scope

    let rootDescriptor = open(
      captureRootDirectory.path,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    if rootDescriptor < 0 {
      if errno == ENOENT { throw TacuaCaptureAdmissionError.captureMissing }
      throw TacuaCaptureAdmissionError.unsafeCaptureStorage
    }
    defer { close(rootDescriptor) }
    var rootMetadata = stat()
    guard fstat(rootDescriptor, &rootMetadata) == 0,
      (rootMetadata.st_mode & S_IFMT) == S_IFDIR
    else { throw TacuaCaptureAdmissionError.unsafeCaptureStorage }

    let sessionDescriptor = input.localSessionID.withCString {
      openat(rootDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    if sessionDescriptor < 0 {
      if errno == ENOENT { throw TacuaCaptureAdmissionError.captureMissing }
      throw TacuaCaptureAdmissionError.unsafeCaptureStorage
    }
    defer { close(sessionDescriptor) }
    var sessionMetadata = stat()
    guard fstat(sessionDescriptor, &sessionMetadata) == 0,
      (sessionMetadata.st_mode & S_IFMT) == S_IFDIR
    else { throw TacuaCaptureAdmissionError.unsafeCaptureStorage }

    try scavengeMaterializationTemps(sessionDescriptor: sessionDescriptor)
    let existingAdmissionData = try readOptionalRegularFile(
      named: Self.admissionFileName,
      maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
      sessionDescriptor: sessionDescriptor
    )?.data

    let authority: TacuaAdmissionAuthority
    if let existingAdmissionData {
      authority = try authorityFromExistingAdmission(
        existingAdmissionData,
        localSessionID: input.localSessionID,
        remoteSessionID: remoteSessionID,
        scopeDigest: scopeDigest,
        buildIdentity: buildIdentity,
        scope: scope,
        baseline: baseline
      )
    } else {
      guard baseline.credentialCapability == .active,
        let credentialID = baseline.currentCredentialID,
        let timeAnchor = baseline.timeAnchor,
        let retentionAuthority = baseline.sessionRetentionAuthority
      else {
        if baseline.sessionRetentionAuthority == nil {
          throw TacuaCaptureAdmissionError.retentionAuthorityMissing
        }
        throw TacuaCaptureAdmissionError.queueUnavailable
      }
      let requestedAt: String
      do { requestedAt = try baseline.timestampForNewOperation(clock: clock) }
      catch { throw TacuaCaptureAdmissionError.queueUnavailable }
      authority = TacuaAdmissionAuthority(
        credentialID: credentialID,
        requestedAt: requestedAt,
        timeAnchor: timeAnchor,
        retentionAuthority: retentionAuthority
      )
    }

    let prepared = try prepareAdmission(
      localSessionID: input.localSessionID,
      remoteSessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      buildIdentity: buildIdentity,
      scope: scope,
      authority: authority,
      sessionDescriptor: sessionDescriptor
    )
    if let existingAdmissionData, existingAdmissionData != prepared.artifactData {
      throw TacuaCaptureAdmissionError.admissionConflict
    }

    let hasExactAdmission = queueContainsExactAdmissionOperations(
      baseline,
      expected: prepared.operations
    )
    let hasExistingAdmissionOperation = baseline.operations.contains {
      $0.kind == .segment || $0.kind == .diagnostic
    }
    guard hasExactAdmission || !hasExistingAdmissionOperation else {
      throw TacuaCaptureAdmissionError.admissionConflict
    }

    try materializeImmutable(
      prepared.diagnosticData,
      named: Self.diagnosticFileName,
      sessionDescriptor: sessionDescriptor
    )
    try materializeImmutable(
      prepared.artifactData,
      named: Self.admissionFileName,
      sessionDescriptor: sessionDescriptor
    )
    try prepared.trackedFiles.forEach {
      try verifyIdentity($0, sessionDescriptor: sessionDescriptor)
    }
    guard try readRequiredRegularFile(
      named: Self.diagnosticFileName,
      maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
      sessionDescriptor: sessionDescriptor
    ).data == prepared.diagnosticData,
      try readRequiredRegularFile(
        named: Self.admissionFileName,
        maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
        sessionDescriptor: sessionDescriptor
      ).data == prepared.artifactData
    else { throw TacuaCaptureAdmissionError.admissionConflict }

    if hasExactAdmission {
      try retentionChecker?.requireActiveHoldingLifecycleLease(
        localSessionID: input.localSessionID
      )
      return result(
        input: input,
        remoteSessionID: remoteSessionID,
        prepared: prepared,
        alreadyAdmitted: true
      )
    }
    guard authority.credentialID == baseline.currentCredentialID,
      baseline.credentialCapability == .active
    else { throw TacuaCaptureAdmissionError.admissionConflict }

    var replacement = baseline
    do {
      for (request, bindings) in prepared.operations {
        let requestValue = try TacuaCanonicalJSON.parse(request.canonicalData)
        guard try TacuaSDKBackendProtocol.validateRequest(request.canonicalData) == backendKind(
          request.kind
        ) else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
        try replacement.enqueueNewOperation(
          kind: request.kind,
          operationID: request.operationID,
          requestCredentialID: request.credentialID,
          request: requestValue,
          requestDigest: request.requestDigest,
          localPayloadBindings: bindings,
          clock: clock
        )
      }
      try replacement.validate()
    } catch let error as TacuaCaptureAdmissionError {
      throw error
    } catch {
      throw TacuaCaptureAdmissionError.admissionConflict
    }

    do {
      try retentionChecker?.requireActiveHoldingLifecycleLease(
        localSessionID: input.localSessionID
      )
      try queueStore.compareAndSwap(expected: baseline, replacement: replacement)
      try retentionChecker?.requireActiveHoldingLifecycleLease(
        localSessionID: input.localSessionID
      )
      return result(
        input: input,
        remoteSessionID: remoteSessionID,
        prepared: prepared,
        alreadyAdmitted: false
      )
    } catch {
      // A queue rename may have succeeded before its directory fsync reported failure. Reloading
      // can prove only this exact admission; every third state remains a conflict.
      if let current = try? queueStore.load(localSessionID: input.localSessionID),
        queueContainsExactAdmissionOperations(current, expected: prepared.operations)
      {
        try retentionChecker?.requireActiveHoldingLifecycleLease(
          localSessionID: input.localSessionID
        )
        return result(
          input: input,
          remoteSessionID: remoteSessionID,
          prepared: prepared,
          alreadyAdmitted: true
        )
      }
      throw TacuaCaptureAdmissionError.admissionConflict
    }
  }

  private func resolveSessionArtifacts(
    input: TacuaCaptureAdmissionInput,
    queue: TacuaTransportQueueV3
  ) throws -> TacuaDurableSessionArtifacts {
    let supplied: TacuaDurableSessionArtifacts?
    switch (input.buildIdentityJSON, input.scopeJSON) {
    case (nil, nil):
      supplied = nil
    case (.some(let build), .some(let scope)):
      do {
        supplied = try TacuaDurableSessionArtifacts.canonicalizing(
          buildIdentityJSON: build,
          scopeJSON: scope
        )
      } catch {
        throw TacuaCaptureAdmissionError.invalidInput
      }
    default:
      throw TacuaCaptureAdmissionError.invalidInput
    }

    let durable: TacuaDurableSessionArtifacts?
    do { durable = try queue.durableSessionArtifacts() }
    catch { throw TacuaCaptureAdmissionError.queueUnavailable }
    let resolved: TacuaDurableSessionArtifacts
    if let durable {
      if let supplied,
        supplied.buildIdentityJSON != durable.buildIdentityJSON
          || supplied.scopeJSON != durable.scopeJSON
      {
        throw TacuaCaptureAdmissionError.captureIdentityMismatch
      }
      resolved = durable
    } else {
      // A queue migrated from an older SDK cannot invent historical build/scope authority. The
      // host must provide both exact artifacts until a successful RESUME durably backfills them.
      guard let supplied else { throw TacuaCaptureAdmissionError.invalidInput }
      resolved = supplied
    }
    guard resolved.scopeDigest == queue.scopeDigest,
      resolved.transportConfigurationDigest == queue.transportConfigurationDigest
    else { throw TacuaCaptureAdmissionError.captureIdentityMismatch }
    do { try configuration.validateBuildIdentityBinding(resolved.buildIdentity) }
    catch { throw TacuaCaptureAdmissionError.captureIdentityMismatch }
    return resolved
  }

  private func prepareAdmission(
    localSessionID: String,
    remoteSessionID: String,
    scopeDigest: String,
    buildIdentity: TacuaJSONValue,
    scope: TacuaJSONValue,
    authority: TacuaAdmissionAuthority,
    sessionDescriptor: Int32
  ) throws -> TacuaPreparedCaptureAdmission {
    let manifestFile = try readRequiredRegularFile(
      named: "manifest.json",
      maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
      sessionDescriptor: sessionDescriptor
    )
    guard let manifestData = manifestFile.data else {
      throw TacuaCaptureAdmissionError.captureArtifactMismatch
    }
    let manifest: TacuaAdmissionLocalManifest
    do { manifest = try JSONDecoder().decode(TacuaAdmissionLocalManifest.self, from: manifestData) }
    catch { throw TacuaCaptureAdmissionError.captureArtifactMismatch }

    guard manifest.sessionId == localSessionID,
      ["completed", "partial_ready_for_upload"].contains(manifest.state),
      let startedHostUptime = manifest.startedHostUptimeSeconds,
      let stoppedHostUptime = manifest.stoppedHostUptimeSeconds
    else { throw TacuaCaptureAdmissionError.captureNotFinalized }
    guard manifest.schemaVersion == 3,
      manifest.bootSessionId == authority.timeAnchor.bootSessionID,
      manifest.bootSessionId == clock.bootSessionID
    else { throw TacuaCaptureAdmissionError.captureClockUnavailable }
    guard !manifest.segments.isEmpty, manifest.segments.count <= 2_048 else {
      throw TacuaCaptureAdmissionError.noVerifiedSegments
    }
    guard manifest.gaps.count <= TacuaCapturePolicy.maximumManifestGaps,
      manifest.markers.count <= TacuaCapturePolicy.maximumManifestMarkers,
      Set(manifest.gaps.map(\.id)).count == manifest.gaps.count,
      Set(manifest.markers.map(\.id)).count == manifest.markers.count
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    guard (manifest.microphoneSamplesObserved ?? 0) > 0 else {
      throw TacuaCaptureAdmissionError.microphoneSamplesMissing
    }

    let build: [String: TacuaJSONValue]
    let scopeObject: [String: TacuaJSONValue]
    do {
      try TacuaSDKBackendRequests.validateStartArtifacts(
        buildIdentity: buildIdentity,
        scope: scope,
        requestedAt: authority.requestedAt,
        configuration: configuration
      )
      try configuration.validateBuildIdentityBinding(buildIdentity)
      build = try buildIdentity.requiringObject(keys: [
        "protocol_version", "message_type", "build_id", "platform", "bundle_identifier",
        "native_version", "native_build", "build_variant", "distribution",
        "react_native_version", "expo", "source", "created_at",
        "transport_configuration_digest", "build_identity_digest",
      ])
      scopeObject = try scope.requiringObject(keys: [
        "protocol_version", "message_type", "organization_id", "project_id",
        "application_id", "build_id", "build_identity_digest", "capture_scope",
        "consent", "retention", "scope_digest",
      ])
    } catch { throw TacuaCaptureAdmissionError.invalidInput }
    guard scopeObject["scope_digest"]?.stringValue == scopeDigest,
      scopeObject["organization_id"]?.stringValue == manifest.organizationId,
      scopeObject["project_id"]?.stringValue == manifest.projectId,
      scopeObject["build_id"]?.stringValue == manifest.buildId,
      build["bundle_identifier"]?.stringValue == manifest.expectedApplicationId,
      build["native_build"]?.stringValue == manifest.expectedBuildNumber,
      manifest.consentVersion == "tacua-local-capture-consent-v1",
      build["build_id"] == scopeObject["build_id"],
      build["build_identity_digest"] == scopeObject["build_identity_digest"]
    else { throw TacuaCaptureAdmissionError.captureIdentityMismatch }

    try validateRetentionAuthority(authority.retentionAuthority, scope: scopeObject)
    let timeline = try captureTimeline(
      startedHostUptimeSeconds: startedHostUptime,
      stoppedHostUptimeSeconds: stoppedHostUptime,
      authority: authority
    )
    guard let requestedMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(authority.requestedAt),
      let startedWireMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(timeline.startedAt),
      let endedWireMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(timeline.endedAt),
      let sessionReceivedMilliseconds = TacuaProtocolTimestamp.parseMilliseconds(
        authority.retentionAuthority.sessionReceivedAt
      ),
      startedWireMilliseconds >= sessionReceivedMilliseconds,
      requestedMilliseconds >= endedWireMilliseconds
    else { throw TacuaCaptureAdmissionError.captureClockUnavailable }

    let sortedSegments = manifest.segments.sorted { left, right in left.index < right.index }
    guard Set(sortedSegments.map(\.index)).count == sortedSegments.count,
      sortedSegments.allSatisfy({ $0.index >= 0 })
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    var tracked = [manifestFile.identity]
    var segmentPlans: [TacuaAdmissionSegmentPlan] = []
    var previousEnd: Int64 = 0
    for (offset, segment) in sortedSegments.enumerated() {
      let expectedName = String(format: "segment-%06d.mov", segment.index)
      guard segment.fileName == expectedName,
        segment.sha256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
        segment.byteLength > 0,
        segment.byteLength <= TacuaSDKBackendProtocol.maximumUploadBytes,
        validSegmentMetrics(segment)
      else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
      let sidecarName = String(format: "segment-%06d.segment.json", segment.index)
      let media = try readRequiredRegularFile(
        named: segment.fileName,
        maximumBytes: Int(segment.byteLength),
        expectedBytes: segment.byteLength,
        retainData: false,
        sessionDescriptor: sessionDescriptor
      )
      let sidecar = try readRequiredRegularFile(
        named: sidecarName,
        maximumBytes: 256 * 1_024,
        sessionDescriptor: sessionDescriptor
      )
      guard media.digest == "sha256:\(segment.sha256)",
        let sidecarData = sidecar.data,
        (try? JSONDecoder().decode(TacuaAdmissionLocalSegment.self, from: sidecarData)) == segment
      else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }

      let rawStart = try relativeMilliseconds(
        segment.firstHostUptimeSeconds,
        origin: startedHostUptime,
        rounding: .down
      )
      let rawEnd = try relativeMilliseconds(
        segment.lastHostUptimeSeconds,
        origin: startedHostUptime,
        rounding: .up
      )
      let start = max(previousEnd, min(timeline.durationMilliseconds, rawStart))
      let end = max(start, min(timeline.durationMilliseconds, rawEnd))
      previousEnd = end
      let sequence = Int64(offset)
      segmentPlans.append(TacuaAdmissionSegmentPlan(
        sequence: sequence,
        segmentID: String(format: "segment_%06d", offset),
        uploadID: String(format: "upload_segment_%06d", offset),
        mediaName: segment.fileName,
        sidecarName: sidecarName,
        sizeBytes: segment.byteLength,
        contentDigest: media.digest,
        sidecarDigest: sidecar.digest,
        startMilliseconds: start,
        endMilliseconds: end
      ))
      tracked.append(media.identity)
      tracked.append(sidecar.identity)
    }

    let runtimeSegments: [TacuaJSONValue] = segmentPlans.map { segment in
      .object([
        "availability": .string("available"),
        "content": .object([
          "content_digest": .string(segment.contentDigest),
          "content_type": .string("video/quicktime"),
          "sidecar_digest": .string(segment.sidecarDigest),
          "size_bytes": .integer(segment.sizeBytes),
        ]),
        "finalized": .bool(true),
        "segment_id": .string(segment.segmentID),
        "sequence": .integer(segment.sequence),
        "time_range": timeRange(
          start: segment.startMilliseconds,
          end: segment.endMilliseconds
        ),
        "unavailable": .null,
      ])
    }
    let runtimeGaps = try sanitizedGaps(
      manifest.gaps,
      startedHostUptimeSeconds: startedHostUptime,
      durationMilliseconds: timeline.durationMilliseconds
    )
    let summary: TacuaJSONValue = .object([
      "app_audio_available": .bool((manifest.appAudioSamplesObserved ?? 0) > 0),
      "error_count": .integer(Int64(manifest.errorCodes.count)),
      "gap_count": .integer(Int64(manifest.gaps.count)),
      "marker_count": .integer(Int64(manifest.markers.count)),
      "microphone_available": .bool(true),
      "segment_count": .integer(Int64(segmentPlans.count)),
    ])
    let summaryDigest = try TacuaCanonicalJSON.digest(summary)
    let diagnosticSource = try loadDiagnosticSource(
      localSessionID: localSessionID,
      bootSessionID: manifest.bootSessionId!,
      sessionDescriptor: sessionDescriptor
    )
    if let diagnosticSource { tracked.append(diagnosticSource.identity) }
    func finalizeDiagnosticEnvelope(
      _ projection: TacuaAdmissionDiagnosticProjection
    ) throws -> (envelope: TacuaJSONValue, data: Data, digest: String) {
      var diagnosticEvents = projection.events
      diagnosticEvents.append(.object([
        "data": .object([
          "collection_status": .string("available"),
          "provider_id": .string("capture_summary"),
          "snapshot_digest": .string(summaryDigest),
        ]),
        "elapsed_ms": .integer(timeline.durationMilliseconds),
        "event_id": .string("event_capture_summary_000001"),
        "event_type": .string("custom_state"),
        "evidence_refs": .array([]),
        "occurred_at": .string(timeline.endedAt),
        "sequence": .integer(Int64(diagnosticEvents.count + 1)),
        "source": .string("mobile_sdk"),
      ]))
      guard diagnosticEvents.count <= projectedDiagnosticEventLimit,
        projection.collectionGaps.count <= projectedCollectionGapLimit
      else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
      var object: [String: TacuaJSONValue] = [
        "build_id": scopeObject["build_id"]!,
        "build_identity_digest": scopeObject["build_identity_digest"]!,
        "collection_gaps": .array(projection.collectionGaps),
        "contract_version": .string("tacua.diagnostic-envelope@1.0.0"),
        "envelope_id": .string("envelope_capture_000001"),
        "envelope_version": .integer(1),
        "events": .array(diagnosticEvents),
        "evidence": .array([]),
        "media_type": .string(
          "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0"
        ),
        "organization_id": scopeObject["organization_id"]!,
        "project_id": scopeObject["project_id"]!,
        "redaction": .object([
          "applied": .bool(true),
          "policy_version": .string("tacua.redaction@1.0.0"),
          "removed_field_count": .integer(
            Int64(manifest.markers.count + manifest.errorCodes.count)
          ),
        ]),
        "sequence_range": .object([
          "first": .integer(1),
          "last": .integer(Int64(diagnosticEvents.count)),
        ]),
        "session_id": .string(remoteSessionID),
      ]
      let digest = try TacuaCanonicalJSON.digest(.object(object))
      object["envelope_digest"] = .string(digest)
      let envelope = TacuaJSONValue.object(object)
      return (envelope, try TacuaCanonicalJSON.data(envelope), digest)
    }

    var diagnosticEventByteLimit = projectedDiagnosticEventByteLimit
    var diagnosticProjection = try projectDiagnosticEnvelope(
      source: diagnosticSource?.snapshot,
      markers: manifest.markers,
      gaps: manifest.gaps,
      startedHostUptimeSeconds: startedHostUptime,
      startedAt: timeline.startedAt,
      durationMilliseconds: timeline.durationMilliseconds,
      eventByteLimit: diagnosticEventByteLimit
    )
    var diagnosticArtifact = try finalizeDiagnosticEnvelope(diagnosticProjection)
    while diagnosticArtifact.data.count > TacuaCanonicalJSON.defaultMaximumBytes {
      let excess = diagnosticArtifact.data.count - TacuaCanonicalJSON.defaultMaximumBytes
      let nextLimit = diagnosticEventByteLimit - excess - 4_096
      guard nextLimit >= 16 * 1_024, nextLimit < diagnosticEventByteLimit else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
      diagnosticEventByteLimit = nextLimit
      diagnosticProjection = try projectDiagnosticEnvelope(
        source: diagnosticSource?.snapshot,
        markers: manifest.markers,
        gaps: manifest.gaps,
        startedHostUptimeSeconds: startedHostUptime,
        startedAt: timeline.startedAt,
        durationMilliseconds: timeline.durationMilliseconds,
        eventByteLimit: diagnosticEventByteLimit
      )
      diagnosticArtifact = try finalizeDiagnosticEnvelope(diagnosticProjection)
    }
    let diagnosticEnvelope = diagnosticArtifact.envelope
    let diagnosticData = diagnosticArtifact.data
    let envelopeDigest = diagnosticArtifact.digest

    var operations: [(TacuaPreparedBackendRequest, [TacuaLocalPayloadBinding])] = []
    for segment in segmentPlans {
      let request = try TacuaSDKBackendRequests.segment(
        uploadID: segment.uploadID,
        sessionID: remoteSessionID,
        scopeDigest: scopeDigest,
        credentialID: authority.credentialID,
        sequence: segment.sequence,
        segmentID: segment.segmentID,
        metadata: TacuaSegmentTransportMetadata(
          contentType: "video/quicktime",
          sizeBytes: segment.sizeBytes,
          contentDigest: segment.contentDigest,
          sidecarDigest: segment.sidecarDigest
        ),
        requestedAt: authority.requestedAt
      )
      operations.append((request, [
        TacuaLocalPayloadBinding(
          role: .segmentMedia,
          relativePath: segment.mediaName,
          contentDigest: segment.contentDigest
        ),
        TacuaLocalPayloadBinding(
          role: .segmentSidecar,
          relativePath: segment.sidecarName,
          contentDigest: segment.sidecarDigest
        ),
      ]))
    }
    let diagnosticRequest = try TacuaSDKBackendRequests.diagnostic(
      uploadID: "upload_diagnostic_000001",
      sessionID: remoteSessionID,
      scopeDigest: scopeDigest,
      credentialID: authority.credentialID,
      envelope: diagnosticEnvelope,
      requestedAt: authority.requestedAt
    )
    var diagnosticBindings = [
      TacuaLocalPayloadBinding(
        role: .diagnosticEnvelope,
        relativePath: Self.diagnosticFileName,
        contentDigest: TacuaCanonicalJSON.digest(data: diagnosticData)
      )
    ]
    if let diagnosticSource {
      diagnosticBindings.append(TacuaLocalPayloadBinding(
        role: .diagnosticSourceJournal,
        relativePath: diagnosticSource.relativePath,
        contentDigest: diagnosticSource.contentDigest
      ))
    }
    operations.append((diagnosticRequest, diagnosticBindings))
    for operation in operations {
      guard try TacuaSDKBackendProtocol.validateRequest(operation.0.canonicalData)
        == backendKind(operation.0.kind)
      else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    }

    let manifestSeed: TacuaJSONValue = .object([
      "build_id": scopeObject["build_id"]!,
      "build_identity_digest": scopeObject["build_identity_digest"]!,
      "capture_scope": .string("app_only"),
      "capture_state": .string("complete"),
      "contract_version": .string("tacua.capture-upload-manifest@1.0.0"),
      "ended_at": .string(timeline.endedAt),
      "gaps": .array(runtimeGaps),
      "manifest_version": .integer(1),
      "media_type": .string(
        "application/vnd.tacua.capture-upload-manifest+json;version=1.0.0"
      ),
      "monotonic_duration_ms": .integer(timeline.durationMilliseconds),
      "organization_id": scopeObject["organization_id"]!,
      "project_id": scopeObject["project_id"]!,
      "retention": .object([
        "deletion_status": .string("active"),
        "derived_data_expires_at": .string(
          authority.retentionAuthority.derivedDataExpiresAt
        ),
        "policy_version": .string("tacua.retention@1.0.0"),
        "raw_media_expires_at": .string(authority.retentionAuthority.rawMediaExpiresAt),
      ]),
      "segments": .array(runtimeSegments),
      "session_id": .string(remoteSessionID),
      "started_at": .string(timeline.startedAt),
      "streams": .object([
        "app_audio": .string(
          (manifest.appAudioSamplesObserved ?? 0) > 0 ? "enabled" : "unavailable"
        ),
        "app_video": .string("enabled"),
        "diagnostics": .string("enabled"),
        "microphone": .string("enabled"),
      ]),
    ])
    let transportSegments: [TacuaJSONValue] = segmentPlans.map { segment in
      .object([
        "media_relative_path": .string(segment.mediaName),
        "segment_id": .string(segment.segmentID),
        "sidecar_relative_path": .string(segment.sidecarName),
        "upload_id": .string(segment.uploadID),
      ])
    }
    var diagnosticTransportPlan: [String: TacuaJSONValue] = [
      "envelope_digest": .string(envelopeDigest),
      "relative_path": .string(Self.diagnosticFileName),
      "upload_id": .string("upload_diagnostic_000001"),
    ]
    if let diagnosticSource {
      diagnosticTransportPlan["source_journal"] = .object([
        "content_digest": .string(diagnosticSource.contentDigest),
        "relative_path": .string(diagnosticSource.relativePath),
      ])
    }
    var artifactObject: [String: TacuaJSONValue] = [
      "admission_version": .integer(1),
      "build_identity": buildIdentity,
      "capture_manifest_seed": manifestSeed,
      "capture_summary": summary,
      "contract_version": .string("tacua.finalized-capture-admission@1.0.0"),
      "credential_id_at_admission": .string(authority.credentialID),
      "local_session_id": .string(localSessionID),
      "media_type": .string(
        "application/vnd.tacua.finalized-capture-admission+json;version=1.0.0"
      ),
      "remote_session_id": .string(remoteSessionID),
      "requested_at": .string(authority.requestedAt),
      "scope": scope,
      "scope_digest": .string(scopeDigest),
      "server_time_anchor": timeAnchorValue(authority.timeAnchor),
      "session_retention_authority": .object([
        "derived_data_expires_at": .string(
          authority.retentionAuthority.derivedDataExpiresAt
        ),
        "raw_media_expires_at": .string(authority.retentionAuthority.rawMediaExpiresAt),
        "session_received_at": .string(authority.retentionAuthority.sessionReceivedAt),
      ]),
      "transport_configuration_digest": .string(configuration.configurationDigest),
      "transport_plan": .object([
        "completion_id": .string("completion_capture_000001"),
        "diagnostic": .object(diagnosticTransportPlan),
        "segments": .array(transportSegments),
      ]),
    ]
    let artifactDigest = try TacuaCanonicalJSON.digest(.object(artifactObject))
    artifactObject["admission_digest"] = .string(artifactDigest)
    let artifact = TacuaJSONValue.object(artifactObject)
    let artifactData = try TacuaCanonicalJSON.data(artifact)
    guard artifactData.count <= TacuaCanonicalJSON.defaultMaximumBytes,
      !containsSensitiveKey(artifact)
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }

    return TacuaPreparedCaptureAdmission(
      artifact: artifact,
      artifactData: artifactData,
      artifactDigest: artifactDigest,
      diagnosticEnvelope: diagnosticEnvelope,
      diagnosticData: diagnosticData,
      diagnosticDigest: envelopeDigest,
      operations: operations,
      trackedFiles: tracked,
      segmentCount: segmentPlans.count
    )
  }

  private func authorityFromExistingAdmission(
    _ data: Data,
    localSessionID: String,
    remoteSessionID: String,
    scopeDigest: String,
    buildIdentity: TacuaJSONValue,
    scope: TacuaJSONValue,
    baseline: TacuaTransportQueueV3
  ) throws -> TacuaAdmissionAuthority {
    let value: TacuaJSONValue
    let root: [String: TacuaJSONValue]
    do {
      value = try TacuaCanonicalJSON.parse(data)
      guard try TacuaCanonicalJSON.data(value) == data else {
        throw TacuaCaptureAdmissionError.admissionConflict
      }
      root = try value.requiringObject(keys: [
        "admission_digest", "admission_version", "build_identity", "capture_manifest_seed",
        "capture_summary", "contract_version", "credential_id_at_admission",
        "local_session_id", "media_type", "remote_session_id", "requested_at", "scope",
        "scope_digest", "server_time_anchor", "session_retention_authority",
        "transport_configuration_digest", "transport_plan",
      ])
    } catch let error as TacuaCaptureAdmissionError { throw error }
    catch { throw TacuaCaptureAdmissionError.admissionConflict }
    guard root["admission_version"]?.integerValue == 1,
      root["contract_version"]?.stringValue == "tacua.finalized-capture-admission@1.0.0",
      root["media_type"]?.stringValue
        == "application/vnd.tacua.finalized-capture-admission+json;version=1.0.0",
      root["local_session_id"]?.stringValue == localSessionID,
      root["remote_session_id"]?.stringValue == remoteSessionID,
      root["scope_digest"]?.stringValue == scopeDigest,
      root["transport_configuration_digest"]?.stringValue == configuration.configurationDigest,
      root["build_identity"] == buildIdentity,
      root["scope"] == scope,
      let claimedDigest = root["admission_digest"]?.stringValue,
      (try? TacuaCanonicalJSON.digest(value, omittingRootField: "admission_digest"))
        == claimedDigest,
      let credentialID = root["credential_id_at_admission"]?.stringValue,
      validIdentifier(credentialID),
      let requestedAt = root["requested_at"]?.stringValue,
      TacuaProtocolTimestamp.parseMilliseconds(requestedAt) != nil,
      let anchorValue = root["server_time_anchor"],
      let retentionValue = root["session_retention_authority"]
    else { throw TacuaCaptureAdmissionError.admissionConflict }
    let anchor = try parseTimeAnchor(anchorValue)
    let retention = try parseRetentionAuthority(retentionValue)
    guard baseline.remoteSessionID == remoteSessionID,
      baseline.scopeDigest == scopeDigest,
      baseline.transportConfigurationDigest == configuration.configurationDigest,
      baseline.sessionRetentionAuthority == retention
    else { throw TacuaCaptureAdmissionError.admissionConflict }
    return TacuaAdmissionAuthority(
      credentialID: credentialID,
      requestedAt: requestedAt,
      timeAnchor: anchor,
      retentionAuthority: retention
    )
  }

  private func captureTimeline(
    startedHostUptimeSeconds: Double,
    stoppedHostUptimeSeconds: Double,
    authority: TacuaAdmissionAuthority
  ) throws -> (
    startedAt: String,
    endedAt: String,
    durationMilliseconds: Int64
  ) {
    guard startedHostUptimeSeconds.isFinite, stoppedHostUptimeSeconds.isFinite,
      startedHostUptimeSeconds >= 0, stoppedHostUptimeSeconds >= startedHostUptimeSeconds,
      clock.bootSessionID == authority.timeAnchor.bootSessionID
    else { throw TacuaCaptureAdmissionError.captureClockUnavailable }
    let startedUptime = try absoluteMilliseconds(startedHostUptimeSeconds, rounding: .down)
    let stoppedUptime = try absoluteMilliseconds(stoppedHostUptimeSeconds, rounding: .up)
    guard stoppedUptime <= clock.uptimeMilliseconds + 1_000 else {
      throw TacuaCaptureAdmissionError.captureClockUnavailable
    }
    let duration = stoppedUptime - startedUptime
    guard (0...1_800_000).contains(duration) else {
      throw TacuaCaptureAdmissionError.captureClockUnavailable
    }
    let (uptimeDelta, deltaOverflow) = startedUptime.subtractingReportingOverflow(
      authority.timeAnchor.uptimeMillisecondsAtIssue
    )
    let (startedEpoch, startOverflow) = authority.timeAnchor.issuedEpochMilliseconds
      .addingReportingOverflow(uptimeDelta)
    let (endedEpoch, endOverflow) = startedEpoch.addingReportingOverflow(duration)
    guard !deltaOverflow, !startOverflow, !endOverflow, startedEpoch >= 0,
      endedEpoch >= startedEpoch
    else { throw TacuaCaptureAdmissionError.captureClockUnavailable }
    return (
      TacuaProtocolTimestamp.format(milliseconds: startedEpoch),
      TacuaProtocolTimestamp.format(milliseconds: endedEpoch),
      duration
    )
  }

  private func sanitizedGaps(
    _ gaps: [TacuaAdmissionLocalGap],
    startedHostUptimeSeconds: Double,
    durationMilliseconds: Int64
  ) throws -> [TacuaJSONValue] {
    try manifestGapBindings(gaps).map { binding in
      let gap = binding.gap
      let rawStart = try relativeMilliseconds(
        gap.openedHostUptimeSeconds,
        origin: startedHostUptimeSeconds,
        rounding: .down
      )
      let rawEnd = try gap.closedHostUptimeSeconds.map {
        try relativeMilliseconds($0, origin: startedHostUptimeSeconds, rounding: .up)
      } ?? durationMilliseconds
      let start = max(0, min(durationMilliseconds, rawStart))
      let end = max(start, min(durationMilliseconds, rawEnd))
      let reason = sanitizedGapReason(gap.reason)
      return .object([
        "affected_streams": .array(affectedStreams(reason).map(TacuaJSONValue.string)),
        "detail": .string(gapDetail(reason, originalReason: gap.reason)),
        "gap_id": .string(binding.outputGapID),
        "reason": .string(reason),
        "time_range": timeRange(start: start, end: end),
      ])
    }
  }

  /// Uses the same deterministic sort and identifiers for the capture manifest and diagnostic
  /// projection. This keeps every diagnostic `capture_gap` relationally bound to a real manifest
  /// gap while raw local UUIDs remain private.
  private func manifestGapBindings(
    _ gaps: [TacuaAdmissionLocalGap]
  ) throws -> [TacuaAdmissionManifestGapBinding] {
    guard gaps.count <= TacuaCapturePolicy.maximumManifestGaps else {
      throw TacuaCaptureAdmissionError.captureArtifactMismatch
    }
    let sorted = gaps.enumerated().sorted { left, right in
      if left.element.openedHostUptimeSeconds == right.element.openedHostUptimeSeconds {
        return left.offset < right.offset
      }
      return left.element.openedHostUptimeSeconds < right.element.openedHostUptimeSeconds
    }
    let bindings = sorted.enumerated().map { outputIndex, pair in
      TacuaAdmissionManifestGapBinding(
        originalOffset: pair.offset,
        gap: pair.element,
        journalGapID: stableIdentifier(prefix: "g", source: pair.element.id),
        outputGapID: String(format: "gap_%06d", outputIndex)
      )
    }
    guard Set(bindings.map(\.journalGapID)).count == bindings.count,
      Set(bindings.map(\.outputGapID)).count == bindings.count
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    return bindings
  }

  private func loadDiagnosticSource(
    localSessionID: String,
    bootSessionID: String,
    sessionDescriptor: Int32
  ) throws -> TacuaAdmissionDiagnosticSource? {
    var directoryMetadata = stat()
    let directoryResult = TacuaDiagnosticJournal.directoryName.withCString {
      fstatat(sessionDescriptor, $0, &directoryMetadata, AT_SYMLINK_NOFOLLOW)
    }
    if directoryResult != 0, errno == ENOENT { return nil }
    guard directoryResult == 0,
      (directoryMetadata.st_mode & S_IFMT) == S_IFDIR,
      (directoryMetadata.st_mode & 0o077) == 0
    else { throw TacuaCaptureAdmissionError.unsafeCaptureStorage }

    let relativePath: String
    let artifact: TacuaDiagnosticJournalArtifact
    do {
      relativePath = try TacuaDiagnosticJournal.relativePath(localSessionID: localSessionID)
      let sessionDirectory = captureRootDirectory.appendingPathComponent(
        localSessionID,
        isDirectory: true
      )
      let journal = try TacuaDiagnosticJournal(
        rootDirectory: TacuaDiagnosticJournal.rootDirectory(sessionDirectory: sessionDirectory),
        localSessionID: localSessionID,
        bootSessionID: bootSessionID,
        createIfMissing: false,
        maximumEvents: TacuaCapturePolicy.maximumDiagnosticJournalEvents,
        monotonicClock: { [clock] in clock.uptimeMilliseconds }
      )
      artifact = try journal.artifact()
    } catch {
      throw TacuaCaptureAdmissionError.captureArtifactMismatch
    }
    guard artifact.snapshot.localSessionID == localSessionID,
      artifact.snapshot.bootSessionID == bootSessionID
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }

    let verified = try readRequiredDiagnosticJournal(
      localSessionID: localSessionID,
      sessionDescriptor: sessionDescriptor
    )
    guard verified.data == artifact.data, verified.digest == artifact.contentDigest else {
      throw TacuaCaptureAdmissionError.captureArtifactMismatch
    }
    return TacuaAdmissionDiagnosticSource(
      snapshot: artifact.snapshot,
      relativePath: relativePath,
      contentDigest: artifact.contentDigest,
      identity: verified.identity
    )
  }

  private func projectDiagnosticEnvelope(
    source: TacuaDiagnosticSnapshot?,
    markers: [TacuaAdmissionLocalMarker],
    gaps: [TacuaAdmissionLocalGap],
    startedHostUptimeSeconds: Double,
    startedAt: String,
    durationMilliseconds: Int64,
    eventByteLimit: Int
  ) throws -> TacuaAdmissionDiagnosticProjection {
    let startedUptime = try absoluteMilliseconds(startedHostUptimeSeconds, rounding: .down)
    guard let startedEpoch = TacuaProtocolTimestamp.parseMilliseconds(startedAt) else {
      throw TacuaCaptureAdmissionError.captureClockUnavailable
    }
    let manifestGapBindings = try manifestGapBindings(gaps)
    let manifestGapByJournalID = Dictionary(
      uniqueKeysWithValues: manifestGapBindings.map { ($0.journalGapID, $0) }
    )
    var candidates: [TacuaAdmissionDiagnosticCandidate] = []
    var collectionGapCandidates: [TacuaAdmissionCollectionGapCandidate] = []
    var journalMarkerIDs = Set<String>()
    var journalGapIDs = Set<String>()
    var priorJournalElapsed: Int64 = 0

    // Validate every manifest marker before journal de-duplication so a matching journal record
    // cannot conceal malformed persisted chronology from admission.
    for marker in markers {
      let elapsed = try relativeMilliseconds(
        marker.hostUptimeSeconds,
        origin: startedHostUptimeSeconds,
        rounding: .down
      )
      guard elapsed <= durationMilliseconds + 1_000 else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
    }

    for entry in source?.entries ?? [] {
      let (rawElapsed, overflow) = entry.monotonicMilliseconds.subtractingReportingOverflow(
        startedUptime
      )
      let isRecoveryGap: Bool
      if case .collectionGap = entry.event { isRecoveryGap = true } else { isRecoveryGap = false }
      let latestAllowed = isRecoveryGap
        ? max(durationMilliseconds, clock.uptimeMilliseconds - startedUptime) + 1_000
        : durationMilliseconds + 1_000
      guard !overflow, rawElapsed >= -1, rawElapsed <= latestAllowed else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
      let elapsed = max(0, min(durationMilliseconds, rawElapsed))
      let eventType: String
      let data: TacuaJSONValue
      let retentionPriority: TacuaAdmissionDiagnosticRetentionPriority
      switch entry.event {
      case .event(.routeTransition(let fromRoute, let toRoute, let trigger)):
        eventType = "route_transition"
        retentionPriority = .ordinary
        data = .object([
          "from_route": fromRoute.map(TacuaJSONValue.string) ?? .null,
          "to_route": .string(toRoute),
          "trigger": .string(trigger.rawValue),
        ])
      case .event(.userInteraction(let action, let target)):
        eventType = "user_interaction"
        retentionPriority = .ordinary
        data = .object([
          "action": .string(action.rawValue),
          "target": .string(target),
          "value_capture": .string("not_collected"),
        ])
      case .event(.runtimeError(
        let errorClass, let sanitizedMessage, let stackTraceDigest, let handled
      )):
        eventType = "runtime_error"
        retentionPriority = .ordinary
        data = .object([
          "error_class": .string(errorClass),
          "handled": .bool(handled),
          "sanitized_message": .string(sanitizedMessage),
          "stack_trace_digest": stackTraceDigest.map(TacuaJSONValue.string) ?? .null,
        ])
      case .event(.networkRequestCompleted(
        let method, let host, let pathTemplate, let statusCode, let requestDuration, let traceID
      )):
        eventType = "network_request_completed"
        retentionPriority = .ordinary
        data = .object([
          "duration_ms": .integer(requestDuration),
          "host": .string(host),
          "method": .string(method.rawValue),
          "outcome": .string((200...399).contains(statusCode) ? "success" : "error"),
          "path_template": .string(pathTemplate),
          "request_body_capture": .string("not_collected"),
          "request_id": .string(stableIdentifier(prefix: "r", source: entry.eventID)),
          "response_body_capture": .string("not_collected"),
          "status_code": .integer(statusCode),
          "trace_id": traceID.map(TacuaJSONValue.string) ?? .null,
        ])
      case .event(.appStateChanged(let fromState, let toState)):
        eventType = "app_state_changed"
        retentionPriority = .ordinary
        data = .object([
          "from_state": .string(fromState.rawValue),
          "to_state": .string(toState.rawValue),
        ])
      case .event(.customState(let providerID, let snapshotDigest, let status)):
        eventType = "custom_state"
        retentionPriority = .ordinary
        data = .object([
          "collection_status": .string(status.rawValue),
          "provider_id": .string(providerID),
          "snapshot_digest": snapshotDigest.map(TacuaJSONValue.string) ?? .null,
        ])
      case .issueMark(let markerID, let kind):
        journalMarkerIDs.insert(markerID)
        eventType = "issue_mark"
        retentionPriority = .journalCritical
        data = .object([
          "kind": .string(kind.rawValue),
          "marker_id": .string(markerID),
          "narration_elapsed_ms": .integer(elapsed),
        ])
      case .captureGap(let gapID, let streams):
        retentionPriority = .journalCritical
        if let binding = manifestGapByJournalID[gapID] {
          journalGapIDs.insert(gapID)
          eventType = "capture_gap"
          data = .object([
            "affected_streams": .array(streams.map { .string($0.rawValue) }),
            "gap_id": .string(binding.outputGapID),
          ])
        } else {
          // A crash may commit the journal record before the corresponding manifest update. It
          // is collection loss, not a capture-manifest gap, and therefore must never manufacture
          // a capture_gap reference that fails the runtime bundle relation.
          eventType = "custom_state"
          data = unavailableCustomState(providerID: "capture_gap_unbound")
          collectionGapCandidates.append(collectionGapCandidate(
            gapIDSource: "unbound:\(entry.eventID)",
            start: priorJournalElapsed,
            end: elapsed,
            stableOrder: entry.sequence,
            reason: "diagnostic_collection_paused",
            detail: "A capture-gap diagnostic was recovered without a committed manifest gap."
          ))
        }
      case .collectionGap:
        eventType = "custom_state"
        retentionPriority = .journalCritical
        data = unavailableCustomState(providerID: "diagnostic_journal_recovery")
        collectionGapCandidates.append(collectionGapCandidate(
          gapIDSource: "collection:\(entry.eventID)",
          start: priorJournalElapsed,
          end: elapsed,
          stableOrder: entry.sequence,
          reason: "diagnostic_collection_paused",
          detail: "The native diagnostic journal recovered an incomplete final append."
        ))
      }
      candidates.append(TacuaAdmissionDiagnosticCandidate(
        eventID: entry.eventID,
        elapsedMilliseconds: elapsed,
        stableOrder: entry.sequence,
        eventType: eventType,
        data: data,
        retentionPriority: retentionPriority
      ))
      priorJournalElapsed = elapsed
    }

    for (offset, marker) in markers.enumerated() {
      let markerID = stableIdentifier(prefix: "m", source: marker.id)
      guard !journalMarkerIDs.contains(markerID) else { continue }
      let elapsed = try relativeMilliseconds(
        marker.hostUptimeSeconds,
        origin: startedHostUptimeSeconds,
        rounding: .down
      )
      guard elapsed <= durationMilliseconds + 1_000 else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
      let boundedElapsed = min(durationMilliseconds, elapsed)
      candidates.append(TacuaAdmissionDiagnosticCandidate(
        eventID: stableIdentifier(prefix: "event", source: "marker:\(marker.id)"),
        elapsedMilliseconds: boundedElapsed,
        stableOrder: 1_000_000 + Int64(offset),
        eventType: "issue_mark",
        data: .object([
          "kind": .string("manual"),
          "marker_id": .string(markerID),
          "narration_elapsed_ms": .integer(boundedElapsed),
        ]),
        retentionPriority: .manifestCritical
      ))
    }

    for (offset, binding) in manifestGapBindings.enumerated() {
      let gap = binding.gap
      guard !journalGapIDs.contains(binding.journalGapID) else { continue }
      let elapsed = try relativeMilliseconds(
        gap.openedHostUptimeSeconds,
        origin: startedHostUptimeSeconds,
        rounding: .down
      )
      guard elapsed <= durationMilliseconds + 1_000 else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
      let reason = sanitizedGapReason(gap.reason)
      candidates.append(TacuaAdmissionDiagnosticCandidate(
        eventID: stableIdentifier(prefix: "event", source: "gap:\(gap.id)"),
        elapsedMilliseconds: min(durationMilliseconds, elapsed),
        stableOrder: 2_000_000 + Int64(offset),
        eventType: "capture_gap",
        data: .object([
          "affected_streams": .array(
            diagnosticAffectedStreams(reason).map(TacuaJSONValue.string)
          ),
          "gap_id": .string(binding.outputGapID),
        ]),
        retentionPriority: .manifestCritical
      ))
    }

    let eventIDs = candidates.map(\.eventID)
    let collectionGapIDs = collectionGapCandidates.map(\.gapID)
    guard Set(eventIDs).count == eventIDs.count,
      Set(collectionGapIDs).count == collectionGapIDs.count,
      !eventIDs.contains("event_capture_summary_000001"),
      !eventIDs.contains("event_diagnostic_projection_overflow")
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }

    let selection = try selectDiagnosticCandidates(
      candidates,
      startedEpochMilliseconds: startedEpoch,
      eventByteLimit: eventByteLimit
    )
    let ordered = chronologicalDiagnosticCandidates(selection.retained)
    let events = ordered.enumerated().map { offset, candidate in
      diagnosticEvent(
        candidate,
        startedEpochMilliseconds: startedEpoch,
        sequence: Int64(offset + 1)
      )
    }
    return TacuaAdmissionDiagnosticProjection(
      events: events,
      collectionGaps: boundedCollectionGaps(
        collectionGapCandidates,
        diagnosticOverflow: selection.overflow
      )
    )
  }

  private func chronologicalDiagnosticCandidates(
    _ candidates: [TacuaAdmissionDiagnosticCandidate]
  ) -> [TacuaAdmissionDiagnosticCandidate] {
    candidates.sorted { left, right in
      if left.elapsedMilliseconds != right.elapsedMilliseconds {
        return left.elapsedMilliseconds < right.elapsedMilliseconds
      }
      if left.stableOrder != right.stableOrder { return left.stableOrder < right.stableOrder }
      return left.eventID < right.eventID
    }
  }

  private func diagnosticRetentionOrder(
    _ candidates: [TacuaAdmissionDiagnosticCandidate]
  ) -> [TacuaAdmissionDiagnosticCandidate] {
    candidates.sorted { left, right in
      if left.retentionPriority.rawValue != right.retentionPriority.rawValue {
        return left.retentionPriority.rawValue < right.retentionPriority.rawValue
      }
      if left.elapsedMilliseconds != right.elapsedMilliseconds {
        return left.elapsedMilliseconds < right.elapsedMilliseconds
      }
      if left.stableOrder != right.stableOrder { return left.stableOrder < right.stableOrder }
      return left.eventID < right.eventID
    }
  }

  private func diagnosticEvent(
    _ candidate: TacuaAdmissionDiagnosticCandidate,
    startedEpochMilliseconds: Int64,
    sequence: Int64
  ) -> TacuaJSONValue {
    .object([
      "data": candidate.data,
      "elapsed_ms": .integer(candidate.elapsedMilliseconds),
      "event_id": .string(candidate.eventID),
      "event_type": .string(candidate.eventType),
      "evidence_refs": .array([]),
      "occurred_at": .string(TacuaProtocolTimestamp.format(
        milliseconds: startedEpochMilliseconds + candidate.elapsedMilliseconds
      )),
      "sequence": .integer(sequence),
      "source": .string("mobile_sdk"),
    ])
  }

  private func selectDiagnosticCandidates(
    _ candidates: [TacuaAdmissionDiagnosticCandidate],
    startedEpochMilliseconds: Int64,
    eventByteLimit: Int
  ) throws -> (
    retained: [TacuaAdmissionDiagnosticCandidate],
    overflow: TacuaAdmissionDiagnosticOverflow?
  ) {
    // The terminal summary is appended by the caller. When selection overflows, this method also
    // reserves one event for an explicit content-free loss signal.
    let summaryByteReserve = 1_024
    let overflowByteReserve = 2_048
    let allBytes = try candidates.reduce(0) { partial, candidate in
      partial + (try TacuaCanonicalJSON.data(diagnosticEvent(
        candidate,
        startedEpochMilliseconds: startedEpochMilliseconds,
        sequence: Int64(projectedDiagnosticEventLimit)
      )).count) + 1
    }
    if candidates.count <= projectedDiagnosticEventLimit - 1,
      allBytes + summaryByteReserve <= eventByteLimit
    {
      return (candidates, nil)
    }

    var retained: [TacuaAdmissionDiagnosticCandidate] = []
    var retainedBytes = 0
    let eventCapacity = projectedDiagnosticEventLimit - 2
    let byteCapacity = max(
      0,
      eventByteLimit - summaryByteReserve - overflowByteReserve
    )
    for candidate in diagnosticRetentionOrder(candidates) {
      let size = try TacuaCanonicalJSON.data(diagnosticEvent(
        candidate,
        startedEpochMilliseconds: startedEpochMilliseconds,
        sequence: Int64(projectedDiagnosticEventLimit)
      )).count + 1
      guard retained.count < eventCapacity, retainedBytes + size <= byteCapacity else {
        continue
      }
      retained.append(candidate)
      retainedBytes += size
    }

    let retainedIDs = Set(retained.map(\.eventID))
    let omitted = candidates.filter { !retainedIDs.contains($0.eventID) }
    guard !omitted.isEmpty,
      let omittedStart = omitted.map(\.elapsedMilliseconds).min(),
      let omittedEnd = omitted.map(\.elapsedMilliseconds).max()
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    let overflow = TacuaAdmissionDiagnosticOverflow(
      omittedEventCount: omitted.count,
      startMilliseconds: omittedStart,
      endMilliseconds: omittedEnd
    )
    retained.append(TacuaAdmissionDiagnosticCandidate(
      eventID: "event_diagnostic_projection_overflow",
      elapsedMilliseconds: omittedEnd,
      stableOrder: Int64.max,
      eventType: "custom_state",
      data: unavailableCustomState(providerID: "diagnostic_projection_overflow"),
      retentionPriority: .journalCritical
    ))
    return (retained, overflow)
  }

  private func unavailableCustomState(providerID: String) -> TacuaJSONValue {
    .object([
      "collection_status": .string("unavailable"),
      "provider_id": .string(providerID),
      "snapshot_digest": .null,
    ])
  }

  private func collectionGapCandidate(
    gapIDSource: String,
    start: Int64,
    end: Int64,
    stableOrder: Int64,
    reason: String,
    detail: String
  ) -> TacuaAdmissionCollectionGapCandidate {
    let boundedStart = min(start, end)
    let boundedEnd = max(start, end)
    let gapID = stableIdentifier(prefix: "cg", source: gapIDSource)
    return TacuaAdmissionCollectionGapCandidate(
      startMilliseconds: boundedStart,
      endMilliseconds: boundedEnd,
      stableOrder: stableOrder,
      gapID: gapID,
      value: .object([
        "detail": .string(detail),
        "gap_id": .string(gapID),
        "reason": .string(reason),
        "time_range": timeRange(start: boundedStart, end: boundedEnd),
      ])
    )
  }

  private func boundedCollectionGaps(
    _ candidates: [TacuaAdmissionCollectionGapCandidate],
    diagnosticOverflow: TacuaAdmissionDiagnosticOverflow?
  ) -> [TacuaJSONValue] {
    let ordered = candidates.sorted { left, right in
      if left.startMilliseconds != right.startMilliseconds {
        return left.startMilliseconds < right.startMilliseconds
      }
      if left.endMilliseconds != right.endMilliseconds {
        return left.endMilliseconds < right.endMilliseconds
      }
      if left.stableOrder != right.stableOrder { return left.stableOrder < right.stableOrder }
      return left.gapID < right.gapID
    }
    let needsAggregate = diagnosticOverflow != nil || ordered.count > projectedCollectionGapLimit
    guard needsAggregate else { return ordered.map(\.value) }

    let retainedCount = max(0, projectedCollectionGapLimit - 1)
    let retained = Array(ordered.prefix(retainedCount))
    let omittedGaps = Array(ordered.dropFirst(retained.count))
    let ranges = omittedGaps.map { ($0.startMilliseconds, $0.endMilliseconds) }
      + (diagnosticOverflow.map { [($0.startMilliseconds, $0.endMilliseconds)] } ?? [])
    let start = ranges.map(\.0).min() ?? 0
    let end = ranges.map(\.1).max() ?? start
    let omittedEventCount = diagnosticOverflow?.omittedEventCount ?? 0
    let detail = "Projection omitted \(omittedEventCount) diagnostic events and "
      + "\(omittedGaps.count) additional collection-gap records to stay within bounded limits."
    let aggregate = collectionGapCandidate(
      gapIDSource: "overflow:\(omittedEventCount):\(omittedGaps.count):\(start):\(end)",
      start: start,
      end: end,
      stableOrder: Int64.max,
      reason: "buffer_overflow",
      detail: detail
    )
    return retained.map(\.value) + [aggregate.value]
  }

  private func validateRetentionAuthority(
    _ authority: TacuaSessionRetentionAuthority,
    scope: [String: TacuaJSONValue]
  ) throws {
    do { try authority.validate() }
    catch { throw TacuaCaptureAdmissionError.retentionAuthorityMissing }
    guard let retention = scope["retention"]?.objectValue,
      let rawDays = retention["raw_media_days"]?.integerValue,
      let derivedDays = retention["derived_data_days"]?.integerValue,
      let received = TacuaProtocolTimestamp.parseMilliseconds(authority.sessionReceivedAt),
      let rawExpiry = TacuaProtocolTimestamp.parseMilliseconds(authority.rawMediaExpiresAt),
      let derivedExpiry = TacuaProtocolTimestamp.parseMilliseconds(authority.derivedDataExpiresAt),
      rawExpiry == received + rawDays * 86_400_000,
      derivedExpiry == received + derivedDays * 86_400_000
    else { throw TacuaCaptureAdmissionError.captureIdentityMismatch }
  }

  private func validSegmentMetrics(_ segment: TacuaAdmissionLocalSegment) -> Bool {
    let doubles = [
      segment.firstMediaPTSSeconds, segment.lastMediaPTSSeconds,
      segment.firstHostUptimeSeconds, segment.lastHostUptimeSeconds,
      segment.durationSeconds,
    ]
    let counts = [
      segment.videoSamples, segment.heldVideoSamples ?? 0, segment.appAudioSamples,
      segment.microphoneSamples, segment.droppedVideoSamples,
      segment.droppedAppAudioSamples, segment.droppedMicrophoneSamples,
    ]
    return doubles.allSatisfy(\.isFinite)
      && segment.firstMediaPTSSeconds <= segment.lastMediaPTSSeconds
      && segment.firstHostUptimeSeconds <= segment.lastHostUptimeSeconds
      && segment.durationSeconds >= 0
      && counts.allSatisfy({ $0 >= 0 })
  }

  private func operation(
    _ operation: TacuaQueuedOperation,
    semanticallyMatches expected: TacuaPreparedBackendRequest,
    bindings: [TacuaLocalPayloadBinding]
  ) -> Bool {
    guard operation.kind == expected.kind,
      operation.operationID == expected.operationID,
      operation.localPayloadPath == nil,
      operation.localPayloadBindings == bindings,
      let persisted = try? semanticRequestIdentity(
        operation.canonicalRequest,
        kind: operation.kind
      ),
      let prepared = try? semanticRequestIdentity(expected.canonicalData, kind: expected.kind)
    else { return false }
    return persisted == prepared
  }

  /// Mirrors the queue's deliberately narrow prepared/historical-miss rebind rule. Credential,
  /// request timestamp, and their derived root digest may rotate; every semantic protocol field
  /// and the separately checked local payload bindings remain immutable.
  private func semanticRequestIdentity(
    _ data: Data,
    kind: TacuaQueuedOperationKind
  ) throws -> TacuaJSONValue {
    let value = try TacuaCanonicalJSON.parse(data)
    guard case .object(var object) = value else {
      throw TacuaCaptureAdmissionError.admissionConflict
    }
    object.removeValue(forKey: "credential_id")
    object.removeValue(forKey: "requested_at")
    object.removeValue(forKey: kind == .segment ? "intent_digest" : "request_digest")
    return .object(object)
  }

  /// Segment and diagnostic IDs are the stable namespace for one capture admission. Proving an
  /// idempotent retry therefore requires the exact whole set, not merely finding every expected
  /// operation in a queue that may also contain a different or partially overlapping admission.
  private func queueContainsExactAdmissionOperations(
    _ queue: TacuaTransportQueueV3,
    expected: [(TacuaPreparedBackendRequest, [TacuaLocalPayloadBinding])]
  ) -> Bool {
    let existing = queue.operations.filter {
      $0.kind == .segment || $0.kind == .diagnostic
    }
    guard existing.count == expected.count else { return false }
    return expected.allSatisfy { request, bindings in
      existing.contains(where: {
        operation($0, semanticallyMatches: request, bindings: bindings)
      })
    }
  }

  private func result(
    input: TacuaCaptureAdmissionInput,
    remoteSessionID: String,
    prepared: TacuaPreparedCaptureAdmission,
    alreadyAdmitted: Bool
  ) -> TacuaCaptureAdmissionResult {
    TacuaCaptureAdmissionResult(
      localSessionID: input.localSessionID,
      remoteSessionID: remoteSessionID,
      admissionDigest: prepared.artifactDigest,
      diagnosticEnvelopeDigest: prepared.diagnosticDigest,
      segmentCount: prepared.segmentCount,
      admittedOperationCount: prepared.operations.count,
      alreadyAdmitted: alreadyAdmitted
    )
  }

  private func backendKind(_ kind: TacuaQueuedOperationKind) -> TacuaBackendOperationKind {
    switch kind {
    case .segment: return .segment
    case .diagnostic: return .diagnostic
    case .completion: return .completion
    case .deletion: return .deletion
    }
  }

  private func readOptionalRegularFile(
    named name: String,
    maximumBytes: Int,
    sessionDescriptor: Int32
  ) throws -> TacuaAdmissionVerifiedFile? {
    do {
      return try readRequiredRegularFile(
        named: name,
        maximumBytes: maximumBytes,
        sessionDescriptor: sessionDescriptor
      )
    } catch TacuaCaptureAdmissionError.captureMissing {
      return nil
    }
  }

  private func readRequiredRegularFile(
    named name: String,
    maximumBytes: Int,
    expectedBytes: Int64? = nil,
    retainData: Bool = true,
    sessionDescriptor: Int32
  ) throws -> TacuaAdmissionVerifiedFile {
    guard validLeafName(name), maximumBytes > 0 else {
      throw TacuaCaptureAdmissionError.unsafeCaptureStorage
    }
    let descriptor = name.withCString {
      openat(sessionDescriptor, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    }
    if descriptor < 0 {
      if errno == ENOENT { throw TacuaCaptureAdmissionError.captureMissing }
      throw TacuaCaptureAdmissionError.unsafeCaptureStorage
    }
    defer { close(descriptor) }
    var initial = stat()
    guard fstat(descriptor, &initial) == 0,
      (initial.st_mode & S_IFMT) == S_IFREG,
      initial.st_nlink == 1,
      initial.st_size > 0,
      initial.st_size <= off_t(maximumBytes),
      expectedBytes.map({ initial.st_size == $0 }) ?? true
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    guard lseek(descriptor, 0, SEEK_SET) >= 0 else {
      throw TacuaCaptureAdmissionError.captureArtifactMismatch
    }
    var hasher = SHA256()
    var retained = Data()
    if retainData { retained.reserveCapacity(Int(initial.st_size)) }
    var total: Int64 = 0
    var buffer = [UInt8](repeating: 0, count: 256 * 1_024)
    while true {
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      if count < 0, errno == EINTR { continue }
      guard count >= 0 else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
      if count == 0 { break }
      total += Int64(count)
      guard total <= Int64(maximumBytes), total <= initial.st_size else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
      let chunk = Data(buffer[0..<count])
      hasher.update(data: chunk)
      if retainData { retained.append(chunk) }
    }
    var final = stat()
    guard total == initial.st_size, fstat(descriptor, &final) == 0,
      TacuaAdmissionFileIdentity(name: name, metadata: initial).matches(final)
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    var pathMetadata = stat()
    let pathResult = name.withCString {
      fstatat(sessionDescriptor, $0, &pathMetadata, AT_SYMLINK_NOFOLLOW)
    }
    guard pathResult == 0,
      TacuaAdmissionFileIdentity(name: name, metadata: initial).matches(pathMetadata),
      (pathMetadata.st_mode & S_IFMT) == S_IFREG,
      pathMetadata.st_nlink == 1
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    let hash = hasher.finalize().map { String(format: "%02x", $0) }.joined()
    return TacuaAdmissionVerifiedFile(
      identity: TacuaAdmissionFileIdentity(name: name, metadata: final),
      digest: "sha256:\(hash)",
      data: retainData ? retained : nil
    )
  }

  private func readRequiredDiagnosticJournal(
    localSessionID: String,
    sessionDescriptor: Int32
  ) throws -> TacuaAdmissionVerifiedFile {
    let relativePath: String
    do { relativePath = try TacuaDiagnosticJournal.relativePath(localSessionID: localSessionID) }
    catch { throw TacuaCaptureAdmissionError.unsafeCaptureStorage }
    let directoryDescriptor = TacuaDiagnosticJournal.directoryName.withCString {
      openat(
        sessionDescriptor,
        $0,
        O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
      )
    }
    guard directoryDescriptor >= 0 else {
      throw TacuaCaptureAdmissionError.unsafeCaptureStorage
    }
    defer { close(directoryDescriptor) }
    var directoryMetadata = stat()
    guard fstat(directoryDescriptor, &directoryMetadata) == 0,
      (directoryMetadata.st_mode & S_IFMT) == S_IFDIR,
      (directoryMetadata.st_mode & 0o077) == 0
    else { throw TacuaCaptureAdmissionError.unsafeCaptureStorage }
    let leafName = relativePath.split(separator: "/").last.map(String.init) ?? ""
    let verified = try readRequiredRegularFile(
      named: leafName,
      maximumBytes: TacuaDiagnosticJournal.maximumJournalBytes,
      sessionDescriptor: directoryDescriptor
    )
    return TacuaAdmissionVerifiedFile(
      identity: TacuaAdmissionFileIdentity(name: relativePath, rebasing: verified.identity),
      digest: verified.digest,
      data: verified.data
    )
  }

  private func verifyIdentity(
    _ identity: TacuaAdmissionFileIdentity,
    sessionDescriptor: Int32
  ) throws {
    if identity.name.contains("/") {
      let components = identity.name.split(separator: "/", omittingEmptySubsequences: false)
      guard components.count == 2,
        components[0] == Substring(TacuaDiagnosticJournal.directoryName),
        validLeafName(String(components[1]))
      else { throw TacuaCaptureAdmissionError.unsafeCaptureStorage }
      let directoryDescriptor = TacuaDiagnosticJournal.directoryName.withCString {
        openat(
          sessionDescriptor,
          $0,
          O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
      }
      guard directoryDescriptor >= 0 else {
        throw TacuaCaptureAdmissionError.captureArtifactMismatch
      }
      defer { close(directoryDescriptor) }
      var directoryMetadata = stat()
      var metadata = stat()
      let result = String(components[1]).withCString {
        fstatat(directoryDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
      }
      guard fstat(directoryDescriptor, &directoryMetadata) == 0,
        (directoryMetadata.st_mode & S_IFMT) == S_IFDIR,
        (directoryMetadata.st_mode & 0o077) == 0,
        result == 0,
        identity.matches(metadata),
        (metadata.st_mode & S_IFMT) == S_IFREG,
        metadata.st_nlink == 1
      else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
      return
    }
    var metadata = stat()
    let result = identity.name.withCString {
      fstatat(sessionDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0, identity.matches(metadata),
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_nlink == 1
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
  }

  private func materializeImmutable(
    _ data: Data,
    named name: String,
    sessionDescriptor: Int32
  ) throws {
    if let existing = try readOptionalRegularFile(
      named: name,
      maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
      sessionDescriptor: sessionDescriptor
    ) {
      guard existing.data == data else { throw TacuaCaptureAdmissionError.admissionConflict }
      guard directorySynchronizer(sessionDescriptor) else {
        throw TacuaCaptureAdmissionError.persistenceFailure
      }
      return
    }
    let suffix = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    let temporaryName = ".tacua-admission-\(suffix).tmp"
    let descriptor = temporaryName.withCString {
      openat(
        sessionDescriptor,
        $0,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        S_IRUSR | S_IWUSR
      )
    }
    guard descriptor >= 0 else { throw TacuaCaptureAdmissionError.persistenceFailure }
    defer {
      close(descriptor)
      _ = temporaryName.withCString { unlinkat(sessionDescriptor, $0, 0) }
    }
    try write(data, descriptor: descriptor)
    guard fchmod(descriptor, S_IRUSR) == 0, fsync(descriptor) == 0 else {
      throw TacuaCaptureAdmissionError.persistenceFailure
    }
    let linkResult = temporaryName.withCString { temporary in
      name.withCString { final in
        linkat(sessionDescriptor, temporary, sessionDescriptor, final, 0)
      }
    }
    if linkResult != 0 {
      if errno == EEXIST,
        let existing = try readOptionalRegularFile(
          named: name,
          maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
          sessionDescriptor: sessionDescriptor
        ),
        existing.data == data
      {
        guard directorySynchronizer(sessionDescriptor) else {
          throw TacuaCaptureAdmissionError.persistenceFailure
        }
        return
      }
      throw TacuaCaptureAdmissionError.admissionConflict
    }
    guard temporaryName.withCString({ unlinkat(sessionDescriptor, $0, 0) }) == 0,
      directorySynchronizer(sessionDescriptor)
    else { throw TacuaCaptureAdmissionError.persistenceFailure }
    let installed = try readRequiredRegularFile(
      named: name,
      maximumBytes: TacuaCanonicalJSON.defaultMaximumBytes,
      sessionDescriptor: sessionDescriptor
    )
    guard installed.data == data else { throw TacuaCaptureAdmissionError.persistenceFailure }
  }

  private func scavengeMaterializationTemps(sessionDescriptor: Int32) throws {
    let duplicate = dup(sessionDescriptor)
    guard duplicate >= 0, let directory = fdopendir(duplicate) else {
      if duplicate >= 0 { close(duplicate) }
      throw TacuaCaptureAdmissionError.unsafeCaptureStorage
    }
    defer { closedir(directory) }
    var removed = false
    while let entry = readdir(directory) {
      let name = withUnsafePointer(to: &entry.pointee.d_name) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
          String(cString: $0)
        }
      }
      guard name.range(
        of: "^\\.tacua-admission-[a-f0-9]{32}\\.tmp$",
        options: .regularExpression
      ) != nil else { continue }
      var metadata = stat()
      let status = name.withCString {
        fstatat(sessionDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
      }
      guard status == 0, (metadata.st_mode & S_IFMT) == S_IFREG else {
        throw TacuaCaptureAdmissionError.unsafeCaptureStorage
      }
      guard name.withCString({ unlinkat(sessionDescriptor, $0, 0) }) == 0 else {
        throw TacuaCaptureAdmissionError.persistenceFailure
      }
      removed = true
    }
    if removed, fsync(sessionDescriptor) != 0 {
      throw TacuaCaptureAdmissionError.persistenceFailure
    }
  }

  private func write(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { bytes in
      guard let base = bytes.baseAddress else {
        throw TacuaCaptureAdmissionError.persistenceFailure
      }
      var offset = 0
      while offset < data.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw TacuaCaptureAdmissionError.persistenceFailure }
        offset += count
      }
    }
  }

  private func parseTimeAnchor(_ value: TacuaJSONValue) throws -> TacuaServerTimeAnchor {
    let root: [String: TacuaJSONValue]
    do {
      root = try value.requiringObject(keys: [
        "boot_session_id", "issued_at", "issued_epoch_milliseconds",
        "minimum_epoch_milliseconds", "uptime_milliseconds_at_issue",
      ])
    } catch { throw TacuaCaptureAdmissionError.admissionConflict }
    guard let bootSessionID = root["boot_session_id"]?.stringValue,
      let issuedAt = root["issued_at"]?.stringValue,
      let issuedEpoch = root["issued_epoch_milliseconds"]?.integerValue,
      let minimumEpoch = root["minimum_epoch_milliseconds"]?.integerValue,
      let uptime = root["uptime_milliseconds_at_issue"]?.integerValue,
      TacuaProtocolTimestamp.parseMilliseconds(issuedAt) == issuedEpoch,
      !bootSessionID.isEmpty,
      uptime >= 0,
      minimumEpoch >= issuedEpoch
    else { throw TacuaCaptureAdmissionError.admissionConflict }
    return TacuaServerTimeAnchor(
      issuedAt: issuedAt,
      issuedEpochMilliseconds: issuedEpoch,
      uptimeMillisecondsAtIssue: uptime,
      bootSessionID: bootSessionID,
      minimumEpochMilliseconds: minimumEpoch
    )
  }

  private func parseRetentionAuthority(
    _ value: TacuaJSONValue
  ) throws -> TacuaSessionRetentionAuthority {
    let root: [String: TacuaJSONValue]
    do {
      root = try value.requiringObject(keys: [
        "derived_data_expires_at", "raw_media_expires_at", "session_received_at",
      ])
    } catch { throw TacuaCaptureAdmissionError.admissionConflict }
    guard let receivedAt = root["session_received_at"]?.stringValue,
      let rawExpiresAt = root["raw_media_expires_at"]?.stringValue,
      let derivedExpiresAt = root["derived_data_expires_at"]?.stringValue
    else { throw TacuaCaptureAdmissionError.admissionConflict }
    let authority = TacuaSessionRetentionAuthority(
      sessionReceivedAt: receivedAt,
      rawMediaExpiresAt: rawExpiresAt,
      derivedDataExpiresAt: derivedExpiresAt
    )
    do { try authority.validate() }
    catch { throw TacuaCaptureAdmissionError.admissionConflict }
    return authority
  }

  private func timeAnchorValue(_ anchor: TacuaServerTimeAnchor) -> TacuaJSONValue {
    .object([
      "boot_session_id": .string(anchor.bootSessionID),
      "issued_at": .string(anchor.issuedAt),
      "issued_epoch_milliseconds": .integer(anchor.issuedEpochMilliseconds),
      "minimum_epoch_milliseconds": .integer(anchor.minimumEpochMilliseconds),
      "uptime_milliseconds_at_issue": .integer(anchor.uptimeMillisecondsAtIssue),
    ])
  }

  private func timeRange(start: Int64, end: Int64) -> TacuaJSONValue {
    .object([
      "clock": .string("session_monotonic"),
      "end_ms": .integer(end),
      "start_ms": .integer(start),
    ])
  }

  private func absoluteMilliseconds(
    _ seconds: Double,
    rounding: FloatingPointRoundingRule
  ) throws -> Int64 {
    let milliseconds = seconds * 1_000
    guard milliseconds.isFinite, milliseconds >= 0,
      milliseconds <= Double(TacuaCanonicalJSON.maximumSafeInteger)
    else { throw TacuaCaptureAdmissionError.captureClockUnavailable }
    return Int64(milliseconds.rounded(rounding))
  }

  private func relativeMilliseconds(
    _ seconds: Double,
    origin: Double,
    rounding: FloatingPointRoundingRule
  ) throws -> Int64 {
    let milliseconds = (seconds - origin) * 1_000
    guard milliseconds.isFinite,
      milliseconds >= -1,
      milliseconds <= Double(TacuaCanonicalJSON.maximumSafeInteger)
    else { throw TacuaCaptureAdmissionError.captureArtifactMismatch }
    return max(0, Int64(milliseconds.rounded(rounding)))
  }

  private func sanitizedGapReason(_ value: String) -> String {
    if value == "capture_gap_overflow" { return "unknown" }
    if value == "app_backgrounded" { return "app_backgrounded" }
    if value.contains("audio") || value.contains("microphone") { return "audio_interrupted" }
    if value.contains("storage") { return "storage_pressure" }
    if value.contains("permission") { return "permission_revoked" }
    if value.contains("process") || value.contains("resume") { return "process_terminated" }
    if value.contains("clock") || value.contains("discontinuity") {
      return "clock_discontinuity"
    }
    if value.contains("capture") || value.contains("writer") || value.contains("start")
      || value.contains("stop")
    {
      return "extension_unavailable"
    }
    return "unknown"
  }

  private func affectedStreams(_ reason: String) -> [String] {
    switch reason {
    case "audio_interrupted": return ["app_audio", "microphone"]
    case "permission_revoked": return ["microphone"]
    case "storage_pressure": return ["app_video", "app_audio", "microphone"]
    default: return ["app_video", "app_audio", "microphone"]
    }
  }

  private func diagnosticAffectedStreams(_ reason: String) -> [String] {
    switch reason {
    case "audio_interrupted": return ["app_audio", "microphone"]
    case "permission_revoked": return ["microphone"]
    case "process_terminated", "clock_discontinuity":
      return ["app_audio", "app_video", "diagnostics", "microphone"]
    default: return ["app_audio", "app_video", "microphone"]
    }
  }

  /// Retains at least 232 SHA-256 bits while respecting the protocol's 64-byte identifier cap.
  private func stableIdentifier(prefix: String, source: String) -> String {
    let digest = SHA256.hash(data: Data(source.utf8)).map {
      String(format: "%02x", $0)
    }.joined()
    // Every call site uses a one-to-five-byte domain prefix, leaving at least 232 digest bits.
    let available = 64 - prefix.utf8.count - 1
    return "\(prefix)_\(digest.prefix(available))"
  }

  private func gapDetail(_ reason: String, originalReason: String) -> String {
    if originalReason == "capture_gap_overflow" {
      return "Additional local capture interruptions were coalesced at the bounded gap limit."
    }
    switch reason {
    case "app_backgrounded": return "Capture was interrupted while the tested app was backgrounded."
    case "audio_interrupted": return "One or more narrated-capture audio streams were interrupted."
    case "extension_unavailable": return "The local capture provider reported an interruption."
    case "storage_pressure": return "The local capture encountered storage pressure."
    case "permission_revoked": return "A required local capture permission became unavailable."
    case "process_terminated": return "The local capture crossed a process recovery boundary."
    case "clock_discontinuity": return "The local capture observed a clock discontinuity."
    default: return "The local capture recorded a sanitized interruption."
    }
  }

  private func validLeafName(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 255 && !value.contains("/")
      && !value.contains("\\") && !value.contains("\0") && value != "." && value != ".."
  }

  private func validIdentifier(_ value: String) -> Bool {
    (3...64).contains(value.utf8.count)
      && value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private func containsSensitiveKey(_ value: TacuaJSONValue) -> Bool {
    switch value {
    case .object(let object):
      let prohibited = Set([
        "launch_code", "authorization", "bearer", "password", "cookie", "set_cookie",
        "access_token", "refresh_token", "handoff_id", "handoff_token_identifier",
      ])
      if object.keys.contains(where: {
        let normalized = $0.lowercased().replacingOccurrences(of: "-", with: "_")
        return prohibited.contains(normalized) || normalized.contains("secret")
      }) { return true }
      return object.values.contains(where: containsSensitiveKey)
    case .array(let values): return values.contains(where: containsSensitiveKey)
    default: return false
    }
  }

  private func reserve(_ localSessionID: String) throws {
    operationLock.lock()
    defer { operationLock.unlock() }
    guard activeLocalSessionIDs.insert(localSessionID).inserted else {
      throw TacuaCaptureAdmissionError.admissionConflict
    }
  }

  private func release(_ localSessionID: String) {
    operationLock.lock()
    activeLocalSessionIDs.remove(localSessionID)
    operationLock.unlock()
  }
}
