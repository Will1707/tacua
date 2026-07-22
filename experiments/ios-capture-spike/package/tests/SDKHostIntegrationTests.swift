// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum SDKHostIntegrationTestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw SDKHostIntegrationTestFailure.assertion(message) }
}

private final class StartService: TacuaSDKHostStarting {
  var inputs: [TacuaSDKStartSessionInput] = []
  var result: TacuaSDKStartedSession!
  var recoveredLocalSessionIDs: [String] = []

  func start(_ input: TacuaSDKStartSessionInput) async throws -> TacuaSDKStartedSession {
    inputs.append(input)
    return result
  }

  func recover(localSessionID: String) throws -> TacuaSDKStartedSession {
    recoveredLocalSessionIDs.append(localSessionID)
    return result
  }
}

private final class ResumeService: TacuaSDKHostResuming {
  var inputs: [TacuaSDKResumeSessionInput] = []
  var result: TacuaSDKResumedSession!
  var recoveredLocalSessionIDs: [String] = []

  func resume(_ input: TacuaSDKResumeSessionInput) async throws -> TacuaSDKResumedSession {
    inputs.append(input)
    return result
  }

  func recover(localSessionID: String) throws -> TacuaSDKResumedSession {
    recoveredLocalSessionIDs.append(localSessionID)
    return result
  }
}

private final class ArtifactStore: TacuaSDKHostSessionArtifactLoading {
  enum Stored {
    case absent
    case legacy
    case artifacts(TacuaDurableSessionArtifacts)
  }

  var stored: Stored = .absent
  var requestedLocalSessionIDs: [String] = []

  func durableSessionArtifacts(localSessionID: String) throws
    -> TacuaDurableSessionArtifacts??
  {
    requestedLocalSessionIDs.append(localSessionID)
    switch stored {
    case .absent: return nil
    case .legacy: return .some(nil)
    case .artifacts(let artifacts): return .some(.some(artifacts))
    }
  }
}

@main
enum SDKHostIntegrationTests {
  private static let startTimestamp = "2026-07-22T12:00:00Z"
  private static let resumeTimestamp = "2026-07-22T13:00:00Z"
  private static let localSessionID = "local_00000000000000000000000000000001"

  static func main() async throws {
    guard CommandLine.arguments.count == 2 else {
      throw SDKHostIntegrationTestFailure.assertion("Expected SDK profile fixture path")
    }
    let profile = try loadProfile(URL(fileURLWithPath: CommandLine.arguments[1]))
    try await startBuildsEverySensitiveFieldNatively(profile)
    try await startRejectsUnsafeInputsBeforeLifecycle(profile)
    try await startRejectsMismatchedLifecycleResult(profile)
    try await resumeUsesOnlyDurableArtifacts(profile)
    try await completedResumeCannotRestartCapture(profile)
    try recoveryPlansUseCommittedArtifacts(profile)
    try await resumeRejectsUnavailableArtifacts(profile)
    try await resumeRejectsProfileDrift(profile)
    try await resumeRejectsMismatchedLifecycleResult(profile)
    print("Tacua SDK host-integration tests passed")
  }

  private static func startBuildsEverySensitiveFieldNatively(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let start = StartService()
    let resume = ResumeService()
    let store = ArtifactStore()
    let expectedArtifacts = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    start.result = started(
      localSessionID: localSessionID,
      scopeDigest: expectedArtifacts.scopeDigest
    )
    let coordinator = makeCoordinator(
      profile: profile,
      start: start,
      resume: resume,
      store: store
    )

    let plan = try await coordinator.start(
      approvedLaunchID: "approved_native_only",
      segmentDurationSeconds: 12
    )
    try require(start.inputs.count == 1, "START lifecycle was not called exactly once")
    let input = start.inputs[0]
    try require(input.localSessionID == localSessionID, "Local ID was not generated natively")
    try require(input.requestedAt == startTimestamp, "START timestamp was not generated natively")
    try require(
      input.buildIdentityJSON == expectedArtifacts.buildIdentityJSON,
      "START did not use the sealed build identity"
    )
    try require(input.scopeJSON == expectedArtifacts.scopeJSON, "START did not use sealed scope")
    try require(plan.backendSession == start.result, "Backend result was not preserved")
    let options = plan.captureOptions
    try require(options.sessionID == localSessionID, "Capture options lost local ID")
    try require(options.segmentDurationSeconds == 12, "Capture options changed segment duration")
    try require(options.organizationID == "org_example", "Organization was not profile-derived")
    try require(options.projectID == "project_example", "Project was not profile-derived")
    try require(options.buildID == "build_example", "Build was not profile-derived")
    try require(options.handoffID == "session_backend", "Handoff was not receipt-derived")
    try require(options.handoffTokenIdentifier == "cred_backend", "Credential was not receipt-derived")
    try require(options.expiresAt == "2099-07-22T13:00:00Z", "Expiry was not receipt-derived")
    try require(
      options.consentVersion == TacuaCapturePolicy.requiredConsentVersion,
      "Local capture consent contract was not SDK-derived"
    )
    try require(
      options.expectedApplicationID == "com.example.app",
      "Bundle identifier was not profile-derived"
    )
    try require(options.expectedBuildNumber == "1", "Build number was not profile-derived")
  }

  private static func startRejectsUnsafeInputsBeforeLifecycle(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let start = StartService()
    let coordinator = makeCoordinator(
      profile: profile,
      start: start,
      resume: ResumeService(),
      store: ArtifactStore()
    )
    try await expect(.invalidApprovedLaunch) {
      _ = try await coordinator.start(approvedLaunchID: "", segmentDurationSeconds: 10)
    }
    try await expect(.invalidSegmentDuration) {
      _ = try await coordinator.start(
        approvedLaunchID: "approved_native_only",
        segmentDurationSeconds: .nan
      )
    }
    try await expect(.invalidSegmentDuration) {
      _ = try await coordinator.start(
        approvedLaunchID: "approved_native_only",
        segmentDurationSeconds: 61
      )
    }
    try require(start.inputs.isEmpty, "Invalid public input reached START lifecycle")

    let invalidID = TacuaSDKHostIntegrationCoordinator(
      profile: profile,
      startService: start,
      resumeService: ResumeService(),
      artifactStore: ArtifactStore(),
      localSessionIDFactory: { "INVALID ID" },
      timestampFactory: { startTimestamp }
    )
    try await expect(.invalidGeneratedLocalSessionID) {
      _ = try await invalidID.start(
        approvedLaunchID: "approved_native_only",
        segmentDurationSeconds: 10
      )
    }
    try require(start.inputs.isEmpty, "Invalid generated ID reached START lifecycle")
  }

  private static func startRejectsMismatchedLifecycleResult(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let start = StartService()
    let expected = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    start.result = started(localSessionID: "local_wrong", scopeDigest: expected.scopeDigest)
    let coordinator = makeCoordinator(
      profile: profile,
      start: start,
      resume: ResumeService(),
      store: ArtifactStore()
    )
    try await expect(.backendResultMismatch) {
      _ = try await coordinator.start(
        approvedLaunchID: "approved_native_only",
        segmentDurationSeconds: 10
      )
    }
  }

  private static func resumeUsesOnlyDurableArtifacts(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let start = StartService()
    let resume = ResumeService()
    let store = ArtifactStore()
    let profileArtifacts = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    let durable = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: profileArtifacts.buildIdentityJSON,
      scopeJSON: profileArtifacts.scopeJSON
    )
    store.stored = .artifacts(durable)
    resume.result = resumed(localSessionID: localSessionID, scopeDigest: durable.scopeDigest)
    let coordinator = makeCoordinator(
      profile: profile,
      start: start,
      resume: resume,
      store: store,
      timestamp: resumeTimestamp
    )

    let plan = try await coordinator.resume(
      approvedLaunchID: "approved_resume_only",
      localSessionID: localSessionID,
      segmentDurationSeconds: 8
    )
    try require(resume.inputs.count == 1, "RESUME lifecycle was not called exactly once")
    let input = resume.inputs[0]
    try require(input.localSessionID == localSessionID, "RESUME changed the local ID")
    try require(input.requestedAt == resumeTimestamp, "RESUME timestamp was not native-generated")
    try require(input.buildIdentityJSON == durable.buildIdentityJSON, "RESUME rebuilt host identity")
    try require(input.scopeJSON == durable.scopeJSON, "RESUME rebuilt host scope")
    guard let captureOptions = plan.captureOptions else {
      throw SDKHostIntegrationTestFailure.assertion(
        "Receiving RESUME authority did not produce capture options"
      )
    }
    try require(captureOptions.handoffID == "session_backend", "RESUME lost remote session")
    try require(captureOptions.handoffTokenIdentifier == "cred_replacement", "RESUME lost replacement credential")
    try require(captureOptions.expiresAt == "2099-07-22T14:00:00Z", "RESUME lost replacement expiry")
    try require(captureOptions.segmentDurationSeconds == 8, "RESUME changed segment duration")
    try require(start.inputs.isEmpty, "RESUME called START lifecycle")
  }

  private static func resumeRejectsUnavailableArtifacts(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let resume = ResumeService()
    let store = ArtifactStore()
    var coordinator = makeCoordinator(
      profile: profile,
      start: StartService(),
      resume: resume,
      store: store,
      timestamp: resumeTimestamp
    )
    try await expect(.durableSessionNotFound) {
      _ = try await coordinator.resume(
        approvedLaunchID: "approved_resume_only",
        localSessionID: localSessionID,
        segmentDurationSeconds: 10
      )
    }
    store.stored = .legacy
    coordinator = makeCoordinator(
      profile: profile,
      start: StartService(),
      resume: resume,
      store: store,
      timestamp: resumeTimestamp
    )
    try await expect(.durableSessionArtifactsUnavailable) {
      _ = try await coordinator.resume(
        approvedLaunchID: "approved_resume_only",
        localSessionID: localSessionID,
        segmentDurationSeconds: 10
      )
    }
    try require(resume.inputs.isEmpty, "Missing artifacts consumed a RESUME launch")
  }

  private static func completedResumeCannotRestartCapture(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let profileArtifacts = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    let durable = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: profileArtifacts.buildIdentityJSON,
      scopeJSON: profileArtifacts.scopeJSON
    )
    let store = ArtifactStore()
    store.stored = .artifacts(durable)
    let resume = ResumeService()
    resume.result = TacuaSDKResumedSession(
      localSessionID: localSessionID,
      remoteSessionID: "session_backend",
      scopeDigest: durable.scopeDigest,
      credentialID: "cred_completed",
      credentialExpiresAt: "2099-07-22T14:00:00Z",
      rawMediaExpiresAt: "2099-08-01T00:00:00Z",
      backendSessionState: .completed,
      credentialCapability: .completionReplayOrDeleteOnly,
      replayCompletionID: "completion_000001",
      credentialAvailability: .available,
      queueSchemaVersion: TacuaTransportQueueV3.schemaVersion,
      pendingRevokedCredentialRemovalCount: 1,
      resumeRequired: false
    )
    let coordinator = makeCoordinator(
      profile: profile,
      start: StartService(),
      resume: resume,
      store: store,
      timestamp: resumeTimestamp
    )
    let plan = try await coordinator.resume(
      approvedLaunchID: "approved_resume_only",
      localSessionID: localSessionID,
      segmentDurationSeconds: 10
    )
    try require(plan.captureOptions == nil, "Completed RESUME exposed ReplayKit start options")
  }

  private static func recoveryPlansUseCommittedArtifacts(
    _ profile: TacuaSDKBuildProfile
  ) throws {
    let profileArtifacts = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    let durable = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: profileArtifacts.buildIdentityJSON,
      scopeJSON: profileArtifacts.scopeJSON
    )
    let store = ArtifactStore()
    store.stored = .artifacts(durable)
    let start = StartService()
    start.result = started(localSessionID: localSessionID, scopeDigest: durable.scopeDigest)
    let resume = ResumeService()
    resume.result = resumed(localSessionID: localSessionID, scopeDigest: durable.scopeDigest)
    let coordinator = makeCoordinator(
      profile: profile,
      start: start,
      resume: resume,
      store: store
    )

    let recoveredStart = try coordinator.recoverStart(
      localSessionID: localSessionID,
      segmentDurationSeconds: 9
    )
    try require(
      start.recoveredLocalSessionIDs == [localSessionID],
      "START recovery did not use the selected local session"
    )
    try require(
      recoveredStart.captureOptions.handoffTokenIdentifier == "cred_backend",
      "START recovery did not project the recovered credential"
    )
    let recoveredResume = try coordinator.recoverResume(
      localSessionID: localSessionID,
      segmentDurationSeconds: 9
    )
    try require(
      resume.recoveredLocalSessionIDs == [localSessionID],
      "RESUME recovery did not use the selected local session"
    )
    guard let recoveredResumeOptions = recoveredResume.captureOptions else {
      throw SDKHostIntegrationTestFailure.assertion(
        "Receiving RESUME recovery did not produce capture options"
      )
    }
    try require(
      recoveredResumeOptions.handoffTokenIdentifier == "cred_replacement",
      "RESUME recovery did not project the recovered replacement credential"
    )
    try require(
      store.requestedLocalSessionIDs == [localSessionID, localSessionID],
      "Recovery did not reload committed artifacts after each lifecycle commit"
    )
  }

  private static func resumeRejectsProfileDrift(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let artifacts = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    var scope = artifacts.scope.objectValue!
    var retention = scope["retention"]!.objectValue!
    retention["raw_media_days"] = .integer(8)
    scope["retention"] = .object(retention)
    scope.removeValue(forKey: "scope_digest")
    scope["scope_digest"] = .string(try TacuaCanonicalJSON.digest(.object(scope)))
    let drifted = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: artifacts.buildIdentityJSON,
      scopeJSON: TacuaCanonicalJSON.data(.object(scope))
    )
    let resume = ResumeService()
    let store = ArtifactStore()
    store.stored = .artifacts(drifted)
    let coordinator = makeCoordinator(
      profile: profile,
      start: StartService(),
      resume: resume,
      store: store,
      timestamp: resumeTimestamp
    )
    try await expect(.durableSessionProfileMismatch) {
      _ = try await coordinator.resume(
        approvedLaunchID: "approved_resume_only",
        localSessionID: localSessionID,
        segmentDurationSeconds: 10
      )
    }
    try require(resume.inputs.isEmpty, "Profile drift consumed a RESUME launch")
  }

  private static func resumeRejectsMismatchedLifecycleResult(
    _ profile: TacuaSDKBuildProfile
  ) async throws {
    let artifacts = try profile.captureArtifacts(consentGrantedAt: startTimestamp)
    let durable = try TacuaDurableSessionArtifacts.canonicalizing(
      buildIdentityJSON: artifacts.buildIdentityJSON,
      scopeJSON: artifacts.scopeJSON
    )
    let store = ArtifactStore()
    store.stored = .artifacts(durable)
    let resume = ResumeService()
    resume.result = resumed(localSessionID: "local_wrong", scopeDigest: durable.scopeDigest)
    let coordinator = makeCoordinator(
      profile: profile,
      start: StartService(),
      resume: resume,
      store: store,
      timestamp: resumeTimestamp
    )
    try await expect(.backendResultMismatch) {
      _ = try await coordinator.resume(
        approvedLaunchID: "approved_resume_only",
        localSessionID: localSessionID,
        segmentDurationSeconds: 10
      )
    }
  }

  private static func makeCoordinator(
    profile: TacuaSDKBuildProfile,
    start: StartService,
    resume: ResumeService,
    store: ArtifactStore,
    timestamp: String = startTimestamp
  ) -> TacuaSDKHostIntegrationCoordinator {
    return TacuaSDKHostIntegrationCoordinator(
      profile: profile,
      startService: start,
      resumeService: resume,
      artifactStore: store,
      localSessionIDFactory: { localSessionID },
      timestampFactory: { timestamp }
    )
  }

  private static func loadProfile(_ fixtureURL: URL) throws -> TacuaSDKBuildProfile {
    let bytes = try Data(contentsOf: fixtureURL)
    let canonical = bytes.last == 0x0A ? Data(bytes.dropLast()) : bytes
    let root = try TacuaCanonicalJSON.parse(canonical)
    guard let digest = root.objectValue?["profile_digest"]?.stringValue else {
      throw SDKHostIntegrationTestFailure.assertion("Profile fixture has no digest")
    }
    let configuration = try TacuaBackendConfiguration(
      buildConfiguredOrigin: "https://qa.example.com",
      allowInsecureLoopback: false,
      debugBuild: false,
      qaBuildConfiguration: try TacuaQABuildConfiguration(
        captureEnabled: true,
        buildVariant: "preview",
        distribution: "testflight",
        debugBuild: false
      )
    )
    return try TacuaSDKBuildProfile(
      canonicalJSON: canonical,
      claimedProfileDigest: digest,
      configuration: configuration
    )
  }

  private static func started(
    localSessionID: String,
    scopeDigest: String
  ) -> TacuaSDKStartedSession {
    TacuaSDKStartedSession(
      localSessionID: localSessionID,
      remoteSessionID: "session_backend",
      scopeDigest: scopeDigest,
      credentialID: "cred_backend",
      credentialExpiresAt: "2099-07-22T13:00:00Z",
      rawMediaExpiresAt: "2099-08-01T00:00:00Z",
      credentialCapability: .active,
      credentialAvailability: .available,
      queueSchemaVersion: TacuaTransportQueueV3.schemaVersion,
      resumeRequired: false
    )
  }

  private static func resumed(
    localSessionID: String,
    scopeDigest: String
  ) -> TacuaSDKResumedSession {
    TacuaSDKResumedSession(
      localSessionID: localSessionID,
      remoteSessionID: "session_backend",
      scopeDigest: scopeDigest,
      credentialID: "cred_replacement",
      credentialExpiresAt: "2099-07-22T14:00:00Z",
      rawMediaExpiresAt: "2099-08-01T00:00:00Z",
      backendSessionState: .receiving,
      credentialCapability: .active,
      replayCompletionID: nil,
      credentialAvailability: .available,
      queueSchemaVersion: TacuaTransportQueueV3.schemaVersion,
      pendingRevokedCredentialRemovalCount: 1,
      resumeRequired: false
    )
  }

  private static func expect(
    _ expected: TacuaSDKHostIntegrationError,
    _ operation: () async throws -> Void
  ) async throws {
    do {
      try await operation()
      throw SDKHostIntegrationTestFailure.assertion("Expected \(expected)")
    } catch let error as TacuaSDKHostIntegrationError {
      try require(error == expected, "Expected \(expected), received \(error)")
    }
  }
}
