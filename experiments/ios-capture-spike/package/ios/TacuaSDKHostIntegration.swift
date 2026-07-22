// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaSDKHostIntegrationError: Error, Equatable {
  case sealedBuildProfileInvalid
  case invalidApprovedLaunch
  case invalidSegmentDuration
  case invalidGeneratedLocalSessionID
  case durableSessionNotFound
  case durableSessionArtifactsUnavailable
  case durableSessionProfileMismatch
  case backendResultMismatch

  var code: String {
    switch self {
    case .sealedBuildProfileInvalid: return "ERR_TACUA_HOST_BUILD_PROFILE"
    case .invalidApprovedLaunch: return "ERR_TACUA_HOST_APPROVED_LAUNCH"
    case .invalidSegmentDuration: return "ERR_TACUA_HOST_SEGMENT_DURATION"
    case .invalidGeneratedLocalSessionID: return "ERR_TACUA_HOST_LOCAL_SESSION_ID"
    case .durableSessionNotFound: return "ERR_TACUA_HOST_SESSION_MISSING"
    case .durableSessionArtifactsUnavailable: return "ERR_TACUA_HOST_SESSION_ARTIFACTS_MISSING"
    case .durableSessionProfileMismatch: return "ERR_TACUA_HOST_SESSION_PROFILE_MISMATCH"
    case .backendResultMismatch: return "ERR_TACUA_HOST_BACKEND_RESULT_MISMATCH"
    }
  }

  var message: String {
    switch self {
    case .sealedBuildProfileInvalid:
      return "The installed QA build does not contain a valid sealed Tacua SDK profile."
    case .invalidApprovedLaunch:
      return "The approved reviewer launch is missing."
    case .invalidSegmentDuration:
      return "The segment duration must be a finite value from 2 through 60 seconds."
    case .invalidGeneratedLocalSessionID:
      return "Tacua could not allocate a valid local capture-session identifier."
    case .durableSessionNotFound:
      return "No committed backend session exists for this local capture session."
    case .durableSessionArtifactsUnavailable:
      return "This migrated session predates durable build/scope artifacts; use the advanced migration path."
    case .durableSessionProfileMismatch:
      return "The durable session does not match the sealed profile in this installed app build."
    case .backendResultMismatch:
      return "The backend lifecycle result did not bind the requested local session and capture scope."
    }
  }
}

/// The only values the ReplayKit layer needs from the backend lifecycle. Hosts receive this exact
/// projection; they do not construct build identity, capture scope, handoff, or timestamp fields.
struct TacuaSDKHostCaptureStartOptions: Equatable {
  let sessionID: String
  let segmentDurationSeconds: Double
  let organizationID: String
  let projectID: String
  let buildID: String
  let handoffID: String
  let handoffTokenIdentifier: String
  let expiresAt: String
  let rawMediaExpiresAt: String
  let consentVersion: String
  let expectedApplicationID: String
  let expectedBuildNumber: String
}

struct TacuaSDKHostStartedCapturePlan: Equatable {
  let backendSession: TacuaSDKStartedSession
  let captureOptions: TacuaSDKHostCaptureStartOptions
}

struct TacuaSDKHostResumedCapturePlan: Equatable {
  let backendSession: TacuaSDKResumedSession
  /// Completed sessions may replay completion or delete, but must never restart ReplayKit.
  let captureOptions: TacuaSDKHostCaptureStartOptions?
}

protocol TacuaSDKHostStarting: AnyObject {
  func start(_ input: TacuaSDKStartSessionInput) async throws -> TacuaSDKStartedSession
  func recover(localSessionID: String) throws -> TacuaSDKStartedSession
}

extension TacuaSDKStartLifecycleCoordinator: TacuaSDKHostStarting {}

protocol TacuaSDKHostResuming: AnyObject {
  func resume(_ input: TacuaSDKResumeSessionInput) async throws -> TacuaSDKResumedSession
  func recover(localSessionID: String) throws -> TacuaSDKResumedSession
}

extension TacuaSDKResumeLifecycleCoordinator: TacuaSDKHostResuming {}

protocol TacuaSDKHostSessionArtifactLoading: AnyObject {
  func durableSessionArtifacts(localSessionID: String) throws
    -> TacuaDurableSessionArtifacts??
}

extension TacuaTransportQueueFileStore: TacuaSDKHostSessionArtifactLoading {
  /// Outer nil means no queue; inner nil is an explicitly migrated queue without artifacts.
  func durableSessionArtifacts(localSessionID: String) throws
    -> TacuaDurableSessionArtifacts??
  {
    guard let queue = try load(localSessionID: localSessionID) else { return nil }
    return .some(try queue.durableSessionArtifacts())
  }
}

/// Native two-phase host integration. START commits the backend receipt before returning capture
/// options. The caller then starts ReplayKit with those returned options, so `localSessionID`
/// remains available even if ReplayKit startup later fails.
final class TacuaSDKHostIntegrationCoordinator {
  private let profile: TacuaSDKBuildProfile
  private let startService: TacuaSDKHostStarting
  private let resumeService: TacuaSDKHostResuming
  private let artifactStore: TacuaSDKHostSessionArtifactLoading
  private let localSessionIDFactory: () -> String
  private let timestampFactory: () -> String

  init(
    profile: TacuaSDKBuildProfile,
    startService: TacuaSDKHostStarting,
    resumeService: TacuaSDKHostResuming,
    artifactStore: TacuaSDKHostSessionArtifactLoading,
    localSessionIDFactory: @escaping () -> String = {
      "local_" + UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    },
    timestampFactory: @escaping () -> String = {
      let formatter = ISO8601DateFormatter()
      formatter.formatOptions = [.withInternetDateTime]
      return formatter.string(from: Date())
    }
  ) {
    self.profile = profile
    self.startService = startService
    self.resumeService = resumeService
    self.artifactStore = artifactStore
    self.localSessionIDFactory = localSessionIDFactory
    self.timestampFactory = timestampFactory
  }

  func start(
    approvedLaunchID: String,
    segmentDurationSeconds: Double
  ) async throws -> TacuaSDKHostStartedCapturePlan {
    try validatePublicInput(
      approvedLaunchID: approvedLaunchID,
      segmentDurationSeconds: segmentDurationSeconds
    )
    let localSessionID = localSessionIDFactory()
    do {
      _ = try TacuaTransportQueueV3(localSessionID: localSessionID)
    } catch {
      throw TacuaSDKHostIntegrationError.invalidGeneratedLocalSessionID
    }
    let requestedAt = timestampFactory()
    let artifacts = try profile.captureArtifacts(consentGrantedAt: requestedAt)
    let started = try await startService.start(
      TacuaSDKStartSessionInput(
        approvedLaunchID: approvedLaunchID,
        localSessionID: localSessionID,
        buildIdentityJSON: artifacts.buildIdentityJSON,
        scopeJSON: artifacts.scopeJSON,
        requestedAt: requestedAt
      )
    )
    guard started.localSessionID == localSessionID,
      started.scopeDigest == artifacts.scopeDigest
    else { throw TacuaSDKHostIntegrationError.backendResultMismatch }
    return TacuaSDKHostStartedCapturePlan(
      backendSession: started,
      captureOptions: try captureOptions(
        localSessionID: localSessionID,
        segmentDurationSeconds: segmentDurationSeconds,
        artifacts: try TacuaDurableSessionArtifacts.canonicalizing(
          buildIdentityJSON: artifacts.buildIdentityJSON,
          scopeJSON: artifacts.scopeJSON
        ),
        remoteSessionID: started.remoteSessionID,
        credentialID: started.credentialID,
        credentialExpiresAt: started.credentialExpiresAt,
        rawMediaExpiresAt: started.rawMediaExpiresAt
      )
    )
  }

  func resume(
    approvedLaunchID: String,
    localSessionID: String,
    segmentDurationSeconds: Double
  ) async throws -> TacuaSDKHostResumedCapturePlan {
    try validatePublicInput(
      approvedLaunchID: approvedLaunchID,
      segmentDurationSeconds: segmentDurationSeconds
    )
    let loaded = try artifactStore.durableSessionArtifacts(localSessionID: localSessionID)
    guard let loaded else { throw TacuaSDKHostIntegrationError.durableSessionNotFound }
    guard let artifacts = loaded else {
      throw TacuaSDKHostIntegrationError.durableSessionArtifactsUnavailable
    }
    try validateCurrentProfile(artifacts)
    let requestedAt = timestampFactory()
    let resumed = try await resumeService.resume(
      TacuaSDKResumeSessionInput(
        approvedLaunchID: approvedLaunchID,
        localSessionID: localSessionID,
        buildIdentityJSON: artifacts.buildIdentityJSON,
        scopeJSON: artifacts.scopeJSON,
        requestedAt: requestedAt
      )
    )
    guard resumed.localSessionID == localSessionID,
      resumed.scopeDigest == artifacts.scopeDigest
    else { throw TacuaSDKHostIntegrationError.backendResultMismatch }
    return TacuaSDKHostResumedCapturePlan(
      backendSession: resumed,
      captureOptions: try resumedCaptureOptions(
        localSessionID: localSessionID,
        segmentDurationSeconds: segmentDurationSeconds,
        artifacts: artifacts,
        remoteSessionID: resumed.remoteSessionID,
        credentialID: resumed.credentialID,
        credentialExpiresAt: resumed.credentialExpiresAt,
        rawMediaExpiresAt: resumed.rawMediaExpiresAt,
        backendSessionState: resumed.backendSessionState,
        credentialCapability: resumed.credentialCapability
      )
    )
  }

  /// Completes a crash-interrupted START receipt commit without another launch exchange, then
  /// projects the now-durable session into the same host plan as a normal START.
  func recoverStart(
    localSessionID: String,
    segmentDurationSeconds: Double
  ) throws -> TacuaSDKHostStartedCapturePlan {
    try validateRecoveryInput(
      localSessionID: localSessionID,
      segmentDurationSeconds: segmentDurationSeconds
    )
    let started = try startService.recover(localSessionID: localSessionID)
    let artifacts = try requiredCurrentArtifacts(localSessionID: localSessionID)
    guard started.localSessionID == localSessionID,
      started.scopeDigest == artifacts.scopeDigest
    else { throw TacuaSDKHostIntegrationError.backendResultMismatch }
    return TacuaSDKHostStartedCapturePlan(
      backendSession: started,
      captureOptions: try captureOptions(
        localSessionID: localSessionID,
        segmentDurationSeconds: segmentDurationSeconds,
        artifacts: artifacts,
        remoteSessionID: started.remoteSessionID,
        credentialID: started.credentialID,
        credentialExpiresAt: started.credentialExpiresAt,
        rawMediaExpiresAt: started.rawMediaExpiresAt
      )
    )
  }

  /// Completes a crash-interrupted RESUME receipt commit without another launch exchange and
  /// returns capture options carrying the recovered replacement credential.
  func recoverResume(
    localSessionID: String,
    segmentDurationSeconds: Double
  ) throws -> TacuaSDKHostResumedCapturePlan {
    try validateRecoveryInput(
      localSessionID: localSessionID,
      segmentDurationSeconds: segmentDurationSeconds
    )
    let resumed = try resumeService.recover(localSessionID: localSessionID)
    let artifacts = try requiredCurrentArtifacts(localSessionID: localSessionID)
    guard resumed.localSessionID == localSessionID,
      resumed.scopeDigest == artifacts.scopeDigest
    else { throw TacuaSDKHostIntegrationError.backendResultMismatch }
    return TacuaSDKHostResumedCapturePlan(
      backendSession: resumed,
      captureOptions: try resumedCaptureOptions(
        localSessionID: localSessionID,
        segmentDurationSeconds: segmentDurationSeconds,
        artifacts: artifacts,
        remoteSessionID: resumed.remoteSessionID,
        credentialID: resumed.credentialID,
        credentialExpiresAt: resumed.credentialExpiresAt,
        rawMediaExpiresAt: resumed.rawMediaExpiresAt,
        backendSessionState: resumed.backendSessionState,
        credentialCapability: resumed.credentialCapability
      )
    )
  }

  private func validatePublicInput(
    approvedLaunchID: String,
    segmentDurationSeconds: Double
  ) throws {
    guard !approvedLaunchID.isEmpty else {
      throw TacuaSDKHostIntegrationError.invalidApprovedLaunch
    }
    guard segmentDurationSeconds.isFinite, (2...60).contains(segmentDurationSeconds) else {
      throw TacuaSDKHostIntegrationError.invalidSegmentDuration
    }
  }

  private func validateRecoveryInput(
    localSessionID: String,
    segmentDurationSeconds: Double
  ) throws {
    do { _ = try TacuaTransportQueueV3(localSessionID: localSessionID) }
    catch { throw TacuaSDKHostIntegrationError.invalidGeneratedLocalSessionID }
    guard segmentDurationSeconds.isFinite, (2...60).contains(segmentDurationSeconds) else {
      throw TacuaSDKHostIntegrationError.invalidSegmentDuration
    }
  }

  private func requiredCurrentArtifacts(
    localSessionID: String
  ) throws -> TacuaDurableSessionArtifacts {
    let loaded = try artifactStore.durableSessionArtifacts(localSessionID: localSessionID)
    guard let loaded else { throw TacuaSDKHostIntegrationError.durableSessionNotFound }
    guard let artifacts = loaded else {
      throw TacuaSDKHostIntegrationError.durableSessionArtifactsUnavailable
    }
    try validateCurrentProfile(artifacts)
    return artifacts
  }

  /// Reconstructing the dynamic scope using its original consent timestamp makes the comparison
  /// exact while keeping that timestamp out of the JavaScript API.
  private func validateCurrentProfile(_ artifacts: TacuaDurableSessionArtifacts) throws {
    guard let consentTimestamp = artifacts.scope.objectValue?["consent"]?
      .objectValue?["granted_at"]?.stringValue
    else { throw TacuaSDKHostIntegrationError.durableSessionProfileMismatch }
    do {
      let expected = try profile.captureArtifacts(consentGrantedAt: consentTimestamp)
      guard expected.buildIdentityJSON == artifacts.buildIdentityJSON,
        expected.scopeJSON == artifacts.scopeJSON
      else { throw TacuaSDKHostIntegrationError.durableSessionProfileMismatch }
    } catch let error as TacuaSDKHostIntegrationError {
      throw error
    } catch {
      throw TacuaSDKHostIntegrationError.durableSessionProfileMismatch
    }
  }

  private func captureOptions(
    localSessionID: String,
    segmentDurationSeconds: Double,
    artifacts: TacuaDurableSessionArtifacts,
    remoteSessionID: String,
    credentialID: String,
    credentialExpiresAt: String,
    rawMediaExpiresAt: String
  ) throws -> TacuaSDKHostCaptureStartOptions {
    guard let scope = artifacts.scope.objectValue,
      let build = artifacts.buildIdentity.objectValue,
      let organizationID = scope["organization_id"]?.stringValue,
      let projectID = scope["project_id"]?.stringValue,
      let buildID = scope["build_id"]?.stringValue,
      let expectedApplicationID = build["bundle_identifier"]?.stringValue,
      let expectedBuildNumber = build["native_build"]?.stringValue,
      !remoteSessionID.isEmpty, !credentialID.isEmpty, !credentialExpiresAt.isEmpty,
      TacuaProtocolTimestamp.parseMilliseconds(rawMediaExpiresAt) != nil
    else { throw TacuaSDKHostIntegrationError.backendResultMismatch }
    return TacuaSDKHostCaptureStartOptions(
      sessionID: localSessionID,
      segmentDurationSeconds: segmentDurationSeconds,
      organizationID: organizationID,
      projectID: projectID,
      buildID: buildID,
      handoffID: remoteSessionID,
      handoffTokenIdentifier: credentialID,
      expiresAt: credentialExpiresAt,
      rawMediaExpiresAt: rawMediaExpiresAt,
      consentVersion: TacuaCapturePolicy.requiredConsentVersion,
      expectedApplicationID: expectedApplicationID,
      expectedBuildNumber: expectedBuildNumber
    )
  }

  private func resumedCaptureOptions(
    localSessionID: String,
    segmentDurationSeconds: Double,
    artifacts: TacuaDurableSessionArtifacts,
    remoteSessionID: String,
    credentialID: String,
    credentialExpiresAt: String,
    rawMediaExpiresAt: String,
    backendSessionState: TacuaSDKResumeExpectedSessionState,
    credentialCapability: TacuaTransportCredentialCapability
  ) throws -> TacuaSDKHostCaptureStartOptions? {
    switch backendSessionState {
    case .receiving:
      guard credentialCapability == .active else {
        throw TacuaSDKHostIntegrationError.backendResultMismatch
      }
      return try captureOptions(
        localSessionID: localSessionID,
        segmentDurationSeconds: segmentDurationSeconds,
        artifacts: artifacts,
        remoteSessionID: remoteSessionID,
        credentialID: credentialID,
        credentialExpiresAt: credentialExpiresAt,
        rawMediaExpiresAt: rawMediaExpiresAt
      )
    case .completed:
      guard credentialCapability == .completionReplayOrDeleteOnly else {
        throw TacuaSDKHostIntegrationError.backendResultMismatch
      }
      return nil
    }
  }
}
