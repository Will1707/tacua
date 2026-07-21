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

/// The public TypeScript wrapper accepts typed protocol objects and serializes them only for this
/// native bridge. Native code parses, canonicalizes, and validates both objects before consent is
/// consumed or Keychain is mutated.
public struct TacuaBackendStartSessionNativeOptions: Record {
  @Field public var approvedLaunchId: String = ""
  @Field public var localSessionId: String = ""
  @Field public var buildIdentityJson: String = ""
  @Field public var scopeJson: String = ""
  @Field public var requestedAt: String = ""

  public init() {}
}

/// RESUME derives remote session state and both credential identifiers from the committed queue;
/// callers may provide only the same validated build/scope artifacts and an approved launch.
public struct TacuaBackendResumeSessionNativeOptions: Record {
  @Field public var approvedLaunchId: String = ""
  @Field public var localSessionId: String = ""
  @Field public var buildIdentityJson: String = ""
  @Field public var scopeJson: String = ""
  @Field public var requestedAt: String = ""

  public init() {}
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
  let sessionId: String
  let organizationId: String?
  let projectId: String?
  let buildId: String?
  let handoffId: String?
  var handoffTokenIdentifier: String?
  var expiresAt: String?
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
}

enum TacuaCaptureSpikeError: Error {
  case invalidSessionId
  case invalidSegmentDuration
  case invalidHandoffField(String)
  case handoffExpired
  case handoffApplicationMismatch
  case handoffBuildMismatch
  case unsupportedConsentVersion
  case handoffManifestMismatch
  case sessionNotRecoverable
  case sessionHasNoVerifiedSegments
  case captureUnavailable
  case captureAlreadyRunning
  case noCaptureRunning
  case microphonePermissionDenied
  case microphoneSamplesMissing
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
  case storageIO(String)
  case recoveryIO(String)
  case writerCreation(String)
  case writerFailed(String)
  case writerTimeout
  case rotationLimitExceeded

  var code: String {
    switch self {
    case .invalidSessionId: return "ERR_TACUA_CAPTURE_SESSION_ID"
    case .invalidSegmentDuration: return "ERR_TACUA_CAPTURE_SEGMENT_DURATION"
    case .invalidHandoffField: return "ERR_TACUA_CAPTURE_HANDOFF_INVALID"
    case .handoffExpired: return "ERR_TACUA_CAPTURE_HANDOFF_EXPIRED"
    case .handoffApplicationMismatch: return "ERR_TACUA_CAPTURE_APPLICATION_MISMATCH"
    case .handoffBuildMismatch: return "ERR_TACUA_CAPTURE_BUILD_MISMATCH"
    case .unsupportedConsentVersion: return "ERR_TACUA_CAPTURE_CONSENT_VERSION"
    case .handoffManifestMismatch: return "ERR_TACUA_CAPTURE_HANDOFF_MISMATCH"
    case .sessionNotRecoverable: return "ERR_TACUA_CAPTURE_SESSION_NOT_RECOVERABLE"
    case .sessionHasNoVerifiedSegments: return "ERR_TACUA_CAPTURE_NO_VERIFIED_SEGMENTS"
    case .captureUnavailable: return "ERR_TACUA_CAPTURE_UNAVAILABLE"
    case .captureAlreadyRunning: return "ERR_TACUA_CAPTURE_BUSY"
    case .noCaptureRunning: return "ERR_TACUA_CAPTURE_NOT_RUNNING"
    case .microphonePermissionDenied: return "ERR_TACUA_CAPTURE_MICROPHONE_DENIED"
    case .microphoneSamplesMissing: return "ERR_TACUA_CAPTURE_MICROPHONE_MISSING"
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
    case .storageIO: return "ERR_TACUA_CAPTURE_STORAGE_IO"
    case .recoveryIO: return "ERR_TACUA_CAPTURE_RECOVERY_IO"
    case .writerCreation: return "ERR_TACUA_CAPTURE_WRITER_CREATE"
    case .writerFailed: return "ERR_TACUA_CAPTURE_WRITER_FINISH"
    case .writerTimeout: return "ERR_TACUA_CAPTURE_WRITER_TIMEOUT"
    case .rotationLimitExceeded: return "ERR_TACUA_CAPTURE_ROTATION_LIMIT"
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
    case .storageIO(let detail), .recoveryIO(let detail):
      return detail
    case .writerCreation(let detail), .writerFailed(let detail):
      return detail
    case .writerTimeout:
      return "The current capture segment did not finalize within the bounded writer window."
    case .rotationLimitExceeded:
      return "ReplayKit emitted a media-clock jump too large to segment safely."
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
