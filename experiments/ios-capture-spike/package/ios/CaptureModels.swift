// SPDX-License-Identifier: Apache-2.0

import ExpoModulesCore
import Foundation

public struct TacuaCaptureStartOptions: Record {
  @Field public var sessionId: String = ""
  @Field public var segmentDurationSeconds: Double = 10
  @Field public var organizationId: String = ""
  @Field public var projectId: String = ""
  @Field public var buildId: String = ""
  @Field public var handoffId: String = ""
  @Field public var handoffTokenIdentifier: String?
  @Field public var expiresAt: String = ""
  /// Immutable backend START raw-media deadline. RESUME must return this exact value unchanged.
  @Field public var rawMediaExpiresAt: String = ""
  @Field public var consentVersion: String = ""
  @Field public var expectedApplicationId: String = ""
  @Field public var expectedBuildNumber: String = ""

  public init() {}
}

public struct TacuaCaptureRecoveryOptions: Record {
  @Field public var sessionId: String = ""
  @Field public var organizationId: String = ""
  @Field public var projectId: String = ""
  @Field public var buildId: String = ""
  @Field public var handoffId: String = ""
  @Field public var handoffTokenIdentifier: String?
  @Field public var expiresAt: String = ""
  @Field public var consentVersion: String = ""
  @Field public var expectedApplicationId: String = ""
  @Field public var expectedBuildNumber: String = ""

  public init() {}
}

/// Primary START surface: the host supplies only the one-shot reviewer approval and its chosen
/// bounded segment duration. Native code generates every identity, scope, timestamp, and handoff.
public struct TacuaCreateCaptureSessionPlanNativeOptions: Record {
  @Field public var approvedLaunchId: String = ""
  @Field public var segmentDurationSeconds: Double = 10

  public init() {}
}

/// Primary RESUME surface. Build/scope artifacts are loaded from the durable queue, never JS.
public struct TacuaResumeCaptureSessionPlanNativeOptions: Record {
  @Field public var approvedLaunchId: String = ""
  @Field public var localSessionId: String = ""
  @Field public var segmentDurationSeconds: Double = 10

  public init() {}
}

/// Receipt recovery does not consume a launch code. The local identifier selects the journal and
/// queue; the duration is the only host-selected capture tuning field.
public struct TacuaRecoverCaptureSessionPlanNativeOptions: Record {
  @Field public var localSessionId: String = ""
  @Field public var segmentDurationSeconds: Double = 10

  public init() {}
}

/// Advanced migration/testing primitive. Normal host integration must use the native-generated
/// plan APIs above; this surface exists only for old queues missing durable public artifacts.
public struct TacuaBackendStartSessionNativeOptions: Record {
  @Field public var approvedLaunchId: String = ""
  @Field public var localSessionId: String = ""
  @Field public var buildIdentityJson: String = ""
  @Field public var scopeJson: String = ""
  @Field public var requestedAt: String = ""

  public init() {}
}

/// Advanced migration/testing primitive for a queue without durable build/scope artifacts.
public struct TacuaBackendResumeSessionNativeOptions: Record {
  @Field public var approvedLaunchId: String = ""
  @Field public var localSessionId: String = ""
  @Field public var buildIdentityJson: String = ""
  @Field public var scopeJson: String = ""
  @Field public var requestedAt: String = ""

  public init() {}
}

/// Admission is explicit and secret-free. Native code verifies these exact artifacts against the
/// committed backend queue and the finalized capture before atomically adding upload operations.
public struct TacuaBackendAdmitFinalizedCaptureNativeOptions: Record {
  @Field public var localSessionId: String = ""
  @Field public var buildIdentityJson: String?
  @Field public var scopeJson: String?

  public init() {}
}

public struct TacuaBackendProcessAdmittedCaptureNativeOptions: Record {
  public init() {}

  @Field public var localSessionId: String = ""
}

/// Authenticated deletion is intentionally scoped by the committed local queue. Callers select
/// only the local session; native code derives the remote session, current credential, stable
/// deletion identifier, exact replay bytes, and fixed `user_requested` reason from durable state.
public struct TacuaBackendDeleteSessionNativeOptions: Record {
  public init() {}

  @Field public var localSessionId: String = ""
}

public struct TacuaDiagnosticRouteTransitionOptions: Record {
  public init() {}
  @Field public var fromRoute: String?
  @Field public var toRoute: String = ""
  @Field public var trigger: String = "unknown"
}

public struct TacuaDiagnosticUserInteractionOptions: Record {
  public init() {}
  @Field public var action: String = ""
  @Field public var target: String = ""
}

public struct TacuaDiagnosticRuntimeErrorOptions: Record {
  public init() {}
  @Field public var errorClass: String = ""
  @Field public var sanitizedMessage: String = ""
  @Field public var stackTraceDigest: String?
  @Field public var handled: Bool = false
}

public struct TacuaDiagnosticNetworkCompletionOptions: Record {
  public init() {}
  @Field public var method: String = ""
  @Field public var host: String = ""
  @Field public var pathTemplate: String = ""
  @Field public var statusCode: Int = 0
  @Field public var durationMilliseconds: Int = 0
  @Field public var traceId: String?
}

/// Custom state is content-addressed. The SDK never accepts or persists the raw state value.
public struct TacuaDiagnosticCustomStateOptions: Record {
  public init() {}
  @Field public var providerId: String = ""
  @Field public var snapshotDigest: String?
  @Field public var collectionStatus: String = "unavailable"
}

struct CaptureSegment: Codable {
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
  /// Present on schema-4 captures. Schema-3 sidecars intentionally decode these as nil.
  let appAudioAppendAttemptStartIndex: Int?
  let appAudioAppendAttempts: Int?
  let appAudioAppendDrops: [TacuaAppAudioAppendDrop]?
}

struct CaptureGap: Codable {
  let id: String
  let reason: String
  let openedHostUptimeSeconds: Double
  var closedHostUptimeSeconds: Double?
  let priorMediaPTSSeconds: Double?
  var nextMediaPTSSeconds: Double?
}

struct CaptureMarker: Codable {
  let id: String
  let label: String
  let hostUptimeSeconds: Double
  let latestMediaPTSSeconds: Double?
}

struct CaptureCalibration: Codable {
  let hostUptimeSeconds: Double
  let mediaPTSSeconds: Double
  let hostMinusMediaSeconds: Double
}

struct CaptureManifest: Codable {
  let schemaVersion: Int
  /// Durable boot identity for every host-uptime value in schema 3. Schema-2 manifests decode
  /// nil for local recovery but are deliberately ineligible for backend admission.
  let bootSessionId: String?
  let sessionId: String
  let organizationId: String?
  let projectId: String?
  let buildId: String?
  let handoffId: String?
  var handoffTokenIdentifier: String?
  var expiresAt: String?
  var rawMediaExpiresAt: String?
  let consentVersion: String?
  let expectedApplicationId: String?
  let expectedBuildNumber: String?
  let createdAt: String
  let segmentDurationSeconds: Double
  let maximumDurationSeconds: Double?
  var state: String
  var startedAt: String?
  var automaticStopAt: String?
  var startedHostUptimeSeconds: Double?
  var automaticStopHostUptimeSeconds: Double?
  var stoppedHostUptimeSeconds: Double?
  var stopReason: String?
  var resumeCount: Int?
  var lastResumedAt: String?
  var segments: [CaptureSegment]
  var gaps: [CaptureGap]
  var markers: [CaptureMarker]
  var calibrations: [CaptureCalibration]
  var errorCodes: [String]
  var droppedBeforeFirstVideo: [String: Int]
  var droppedDuringBackground: [String: Int]?
  var microphoneSamplesObserved: Int?
  var appAudioSamplesObserved: Int?
  /// Schema-4 app-audio accounting is optional only so existing schema-3 captures remain
  /// recoverable. Acceptance evidence requires all three fields and `complete == true`.
  var appAudioAppendAccountingVersion: Int?
  var appAudioAppendAccountingComplete: Bool?
  var appAudioAppendAttemptsObserved: Int?
  /// Inclusive crash-durable lease high-watermark. No index at or below this value may be
  /// reissued after process recovery, even when its writer tail never committed a sidecar.
  var appAudioAppendReservedThroughIndex: Int?
  /// Reserved indexes skipped after recovery because their append outcome cannot be reconstructed.
  var appAudioAppendUnknownRanges: [TacuaAppAudioAppendUnknownRange]?
}

enum TacuaCaptureSpikeError: Error {
  case invalidSessionId
  case invalidSegmentDuration
  case invalidHandoffField(String)
  case handoffExpired
  case retentionExpired
  case retentionAuthorityInvalid
  case handoffApplicationMismatch
  case handoffBuildMismatch
  case unsupportedConsentVersion
  case handoffManifestMismatch
  case sessionNotRecoverable
  case sessionHasNoVerifiedSegments
  case captureDisabledForBuild
  case captureUnavailable
  case captureAlreadyRunning
  case noCaptureRunning
  case microphonePermissionDenied
  case microphoneSamplesMissing
  case appAudioAccountingLimitExceeded
  case captureStartFailed(String)
  case captureStartCancelled
  case captureHandlerFailed
  case captureStopFailed
  case startTimeout
  case startCleanupPending
  case stopTimeout
  case moduleDestroyed
  case insufficientStorage
  case invalidMarkerLabel
  case markerLimitReached
  case storageIO(String)
  case recoveryIO(String)
  case writerCreation(String)
  case writerFailed(String)
  case writerTimeout
  case rotationLimitExceeded
  case diagnosticInvalid
  case diagnosticPrivacyViolation
  case diagnosticUnavailable
  case diagnosticEventLimitReached

  var code: String {
    switch self {
    case .invalidSessionId: return "ERR_TACUA_CAPTURE_SESSION_ID"
    case .invalidSegmentDuration: return "ERR_TACUA_CAPTURE_SEGMENT_DURATION"
    case .invalidHandoffField: return "ERR_TACUA_CAPTURE_HANDOFF_INVALID"
    case .handoffExpired: return "ERR_TACUA_CAPTURE_HANDOFF_EXPIRED"
    case .retentionExpired: return "ERR_TACUA_CAPTURE_RETENTION_EXPIRED"
    case .retentionAuthorityInvalid: return "ERR_TACUA_CAPTURE_RETENTION_AUTHORITY"
    case .handoffApplicationMismatch: return "ERR_TACUA_CAPTURE_APPLICATION_MISMATCH"
    case .handoffBuildMismatch: return "ERR_TACUA_CAPTURE_BUILD_MISMATCH"
    case .unsupportedConsentVersion: return "ERR_TACUA_CAPTURE_CONSENT_VERSION"
    case .handoffManifestMismatch: return "ERR_TACUA_CAPTURE_HANDOFF_MISMATCH"
    case .sessionNotRecoverable: return "ERR_TACUA_CAPTURE_SESSION_NOT_RECOVERABLE"
    case .sessionHasNoVerifiedSegments: return "ERR_TACUA_CAPTURE_NO_VERIFIED_SEGMENTS"
    case .captureDisabledForBuild: return "ERR_TACUA_CAPTURE_BUILD_DISABLED"
    case .captureUnavailable: return "ERR_TACUA_CAPTURE_UNAVAILABLE"
    case .captureAlreadyRunning: return "ERR_TACUA_CAPTURE_BUSY"
    case .noCaptureRunning: return "ERR_TACUA_CAPTURE_NOT_RUNNING"
    case .microphonePermissionDenied: return "ERR_TACUA_CAPTURE_MICROPHONE_DENIED"
    case .microphoneSamplesMissing: return "ERR_TACUA_CAPTURE_MICROPHONE_MISSING"
    case .appAudioAccountingLimitExceeded: return "ERR_TACUA_CAPTURE_APP_AUDIO_ACCOUNTING_LIMIT"
    case .captureStartFailed: return "ERR_TACUA_CAPTURE_START_FAILED"
    case .captureStartCancelled: return "ERR_TACUA_CAPTURE_START_CANCELLED"
    case .captureHandlerFailed: return "ERR_TACUA_CAPTURE_HANDLER_FAILED"
    case .captureStopFailed: return "ERR_TACUA_CAPTURE_STOP_FAILED"
    case .startTimeout: return "ERR_TACUA_CAPTURE_START_TIMEOUT"
    case .startCleanupPending: return "ERR_TACUA_CAPTURE_START_CLEANUP_PENDING"
    case .stopTimeout: return "ERR_TACUA_CAPTURE_STOP_TIMEOUT"
    case .moduleDestroyed: return "ERR_TACUA_CAPTURE_MODULE_DESTROYED"
    case .insufficientStorage: return "ERR_TACUA_CAPTURE_STORAGE_LOW"
    case .invalidMarkerLabel: return "ERR_TACUA_CAPTURE_MARKER_LABEL"
    case .markerLimitReached: return "ERR_TACUA_CAPTURE_MARKER_LIMIT"
    case .storageIO: return "ERR_TACUA_CAPTURE_STORAGE_IO"
    case .recoveryIO: return "ERR_TACUA_CAPTURE_RECOVERY_IO"
    case .writerCreation: return "ERR_TACUA_CAPTURE_WRITER_CREATE"
    case .writerFailed: return "ERR_TACUA_CAPTURE_WRITER_FINISH"
    case .writerTimeout: return "ERR_TACUA_CAPTURE_WRITER_TIMEOUT"
    case .rotationLimitExceeded: return "ERR_TACUA_CAPTURE_ROTATION_LIMIT"
    case .diagnosticInvalid: return "ERR_TACUA_DIAGNOSTIC_INVALID"
    case .diagnosticPrivacyViolation: return "ERR_TACUA_DIAGNOSTIC_PRIVACY"
    case .diagnosticUnavailable: return "ERR_TACUA_DIAGNOSTIC_UNAVAILABLE"
    case .diagnosticEventLimitReached: return "ERR_TACUA_DIAGNOSTIC_EVENT_LIMIT"
    }
  }

  var message: String {
    switch self {
    case .invalidSessionId:
      return "sessionId must contain only 1-64 ASCII letters, digits, underscores, or hyphens."
    case .invalidSegmentDuration:
      return "segmentDurationSeconds must be between 2 and 60 seconds."
    case .invalidHandoffField(let field):
      return "The candidate handoff field \(field) is malformed."
    case .handoffExpired:
      return "The candidate handoff has expired."
    case .retentionExpired:
      return "The backend raw-media retention deadline has expired."
    case .retentionAuthorityInvalid:
      return "The backend raw-media retention deadline is missing or inconsistent."
    case .handoffApplicationMismatch:
      return "The candidate handoff does not match this application identifier."
    case .handoffBuildMismatch:
      return "The candidate handoff does not match this application build."
    case .unsupportedConsentVersion:
      return "The candidate handoff uses an unsupported consent version."
    case .handoffManifestMismatch:
      return "The candidate handoff does not match the stored session identity."
    case .sessionNotRecoverable:
      return "The stored capture session is not in a recoverable state."
    case .sessionHasNoVerifiedSegments:
      return "The stored capture session has no verified segment to submit as partial."
    case .captureDisabledForBuild:
      return "Tacua capture is disabled because this binary is not an explicitly configured QA build."
    case .captureUnavailable:
      return "ReplayKit capture is unavailable on this device."
    case .captureAlreadyRunning:
      return "A Tacua capture session is already active."
    case .noCaptureRunning:
      return "No Tacua capture session is active."
    case .microphonePermissionDenied:
      return "Microphone permission is required before Tacua can start this narrated capture."
    case .microphoneSamplesMissing:
      return "Tacua did not receive microphone samples and stopped the capture."
    case .appAudioAccountingLimitExceeded:
      return "Tacua reached its bounded app-audio drop-accounting limit and stopped the capture."
    case .captureStartFailed(let detail):
      return "ReplayKit could not start the candidate capture (\(detail))."
    case .captureStartCancelled:
      return "The capture was stopped before ReplayKit finished starting."
    case .captureHandlerFailed:
      return "ReplayKit reported a fatal capture-handler failure."
    case .captureStopFailed:
      return "ReplayKit reported an error while stopping capture."
    case .startTimeout:
      return "ReplayKit did not finish starting within the bounded start window."
    case .startCleanupPending:
      return "ReplayKit start cleanup is still pending; retry Stop or relaunch the app process."
    case .stopTimeout:
      return "ReplayKit did not confirm stop within the bounded stop window."
    case .moduleDestroyed:
      return "The Expo module was destroyed before capture completed."
    case .insufficientStorage:
      return "At least 256 MiB of free device storage is required to start or rotate a capture segment."
    case .invalidMarkerLabel:
      return "Marker labels use 1-80 ASCII letters, digits, dots, underscores, or hyphens."
    case .markerLimitReached:
      return "The capture reached its bounded manual issue-marker limit."
    case .storageIO(let detail), .recoveryIO(let detail):
      return detail
    case .writerCreation(let detail), .writerFailed(let detail):
      return detail
    case .writerTimeout:
      return "The current capture segment did not finalize within the bounded writer window."
    case .rotationLimitExceeded:
      return "ReplayKit emitted a media-clock jump too large to segment safely."
    case .diagnosticInvalid:
      return "The diagnostic event does not match Tacua's bounded typed schema."
    case .diagnosticPrivacyViolation:
      return "The diagnostic event may contain a secret or untemplated private value."
    case .diagnosticUnavailable:
      return "The native diagnostic journal is unavailable or failed its integrity checks."
    case .diagnosticEventLimitReached:
      return "The native diagnostic journal reached its bounded event limit."
    }
  }
}

extension Error {
  var tacuaStableCode: String {
    if let error = self as? TacuaCaptureSpikeError {
      return error.code
    }
    let error = self as NSError
    return "\(error.domain):\(error.code)"
  }
}
