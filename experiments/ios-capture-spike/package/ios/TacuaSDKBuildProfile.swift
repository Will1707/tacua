// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaSDKBuildProfileError: Error, Equatable {
  case missingBuildConfiguration
  case invalidProfile
  case profileDigestMismatch
  case transportConfigurationMismatch
  case installedBuildMismatch
  case invalidConsentTimestamp
}

struct TacuaSDKCaptureArtifacts: Equatable {
  let profileDigest: String
  let buildIdentity: TacuaJSONValue
  let scope: TacuaJSONValue
  let buildIdentityJSON: Data
  let scopeJSON: Data
  let scopeDigest: String
  let organizationID: String
  let projectID: String
  let applicationID: String
  let buildID: String
  let bundleIdentifier: String
  let nativeBuild: String
}

/// The secret-free profile compiled from the same backend deployment config and embedded by the
/// Expo config plugin. Runtime parsing is independent of JavaScript so an OTA update or caller
/// cannot substitute the registered build, capture scope, retention, or transport origin.
struct TacuaSDKBuildProfile: Equatable {
  static let contractVersion = "tacua.sdk-profile@1.0.0"
  static let scopePolicyContractVersion = "tacua.capture-scope-policy@1.0.0"
  static let retentionPolicyVersion = "tacua.retention-v1"
  static let profileJSONInfoPlistKey = "TacuaSDKProfileJSON"
  static let profileDigestInfoPlistKey = "TacuaSDKProfileDigest"
  static let maximumEncodedBytes = 64 * 1_024

  let canonicalJSON: Data
  let profileDigest: String
  let buildIdentity: TacuaJSONValue
  let scopePolicy: TacuaJSONValue
  let configuration: TacuaBackendConfiguration

  init(
    canonicalJSON: Data,
    claimedProfileDigest: String,
    configuration: TacuaBackendConfiguration
  ) throws {
    guard !canonicalJSON.isEmpty, canonicalJSON.count <= Self.maximumEncodedBytes else {
      throw TacuaSDKBuildProfileError.invalidProfile
    }
    let root: TacuaJSONValue
    do {
      root = try TacuaCanonicalJSON.parse(
        canonicalJSON,
        maximumBytes: Self.maximumEncodedBytes
      )
      guard try TacuaCanonicalJSON.data(root) == canonicalJSON else {
        throw TacuaSDKBuildProfileError.invalidProfile
      }
    } catch let error as TacuaSDKBuildProfileError {
      throw error
    } catch {
      throw TacuaSDKBuildProfileError.invalidProfile
    }

    let object: [String: TacuaJSONValue]
    do {
      object = try root.requiringObject(keys: [
        "backend_origin", "build_identity", "capture_scope_policy",
        "contract_version", "profile_digest", "transport_configuration",
        "transport_configuration_digest",
      ])
    } catch {
      throw TacuaSDKBuildProfileError.invalidProfile
    }
    guard object["contract_version"]?.stringValue == Self.contractVersion,
      let embeddedDigest = object["profile_digest"]?.stringValue,
      embeddedDigest == claimedProfileDigest,
      Self.validDigest(embeddedDigest)
    else { throw TacuaSDKBuildProfileError.profileDigestMismatch }
    do {
      guard try TacuaCanonicalJSON.digest(root, omittingRootField: "profile_digest")
        == embeddedDigest
      else { throw TacuaSDKBuildProfileError.profileDigestMismatch }
    } catch let error as TacuaSDKBuildProfileError {
      throw error
    } catch {
      throw TacuaSDKBuildProfileError.profileDigestMismatch
    }

    guard object["backend_origin"]?.stringValue == configuration.normalizedOrigin,
      object["transport_configuration_digest"]?.stringValue
        == configuration.configurationDigest,
      let transport = object["transport_configuration"],
      let buildIdentity = object["build_identity"],
      let scopePolicy = object["capture_scope_policy"]
    else { throw TacuaSDKBuildProfileError.transportConfigurationMismatch }
    do {
      let transportObject = try transport.requiringObject(keys: [
        "backend_origin", "transport_policy_version",
      ])
      guard transportObject["backend_origin"]?.stringValue == configuration.normalizedOrigin,
        transportObject["transport_policy_version"]?.stringValue
          == TacuaBackendConfiguration.policyVersion,
        try TacuaCanonicalJSON.digest(transport) == configuration.configurationDigest,
        buildIdentity.objectValue?["transport_configuration_digest"]?.stringValue
          == configuration.configurationDigest
      else { throw TacuaSDKBuildProfileError.transportConfigurationMismatch }
      try configuration.validateBuildIdentityBinding(buildIdentity)
      try Self.validateScopePolicy(scopePolicy, buildIdentity: buildIdentity)
    } catch let error as TacuaSDKBuildProfileError {
      throw error
    } catch {
      throw TacuaSDKBuildProfileError.invalidProfile
    }

    self.canonicalJSON = canonicalJSON
    self.profileDigest = embeddedDigest
    self.buildIdentity = buildIdentity
    self.scopePolicy = scopePolicy
    self.configuration = configuration

    guard let provisionalTimestamp = buildIdentity.objectValue?["created_at"]?.stringValue else {
      throw TacuaSDKBuildProfileError.invalidProfile
    }
    _ = try captureArtifacts(consentGrantedAt: provisionalTimestamp)
  }

  static func fromBuildConfiguration(
    bundle: Bundle = .main,
    debugBuild: Bool = _isDebugAssertConfiguration()
  ) throws -> TacuaSDKBuildProfile {
    guard let rawJSON = bundle.object(forInfoDictionaryKey: profileJSONInfoPlistKey) as? String,
      !rawJSON.isEmpty,
      let claimedDigest = bundle.object(
        forInfoDictionaryKey: profileDigestInfoPlistKey
      ) as? String
    else { throw TacuaSDKBuildProfileError.missingBuildConfiguration }
    let configuration = try TacuaBackendConfiguration.fromBuildConfiguration(
      bundle: bundle,
      debugBuild: debugBuild
    )
    let profile = try TacuaSDKBuildProfile(
      canonicalJSON: Data(rawJSON.utf8),
      claimedProfileDigest: claimedDigest,
      configuration: configuration
    )
    guard let build = profile.buildIdentity.objectValue,
      build["bundle_identifier"]?.stringValue == bundle.bundleIdentifier,
      build["native_version"]?.stringValue
        == bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
      build["native_build"]?.stringValue
        == bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
    else { throw TacuaSDKBuildProfileError.installedBuildMismatch }
    return profile
  }

  func captureArtifacts(consentGrantedAt: String) throws -> TacuaSDKCaptureArtifacts {
    guard Self.validTimestamp(consentGrantedAt),
      let policy = scopePolicy.objectValue,
      let consentPolicy = policy["consent"]?.objectValue,
      let retention = policy["retention"],
      let organizationID = policy["organization_id"]?.stringValue,
      let projectID = policy["project_id"]?.stringValue,
      let applicationID = policy["application_id"]?.stringValue,
      let buildID = policy["build_id"]?.stringValue,
      let build = buildIdentity.objectValue,
      let buildIdentityDigest = build["build_identity_digest"]?.stringValue,
      let bundleIdentifier = build["bundle_identifier"]?.stringValue,
      let nativeBuild = build["native_build"]?.stringValue
    else { throw TacuaSDKBuildProfileError.invalidConsentTimestamp }
    var scope: [String: TacuaJSONValue] = [
      "protocol_version": .string(TacuaSDKBackendProtocol.version),
      "message_type": .string("capture_scope"),
      "organization_id": .string(organizationID),
      "project_id": .string(projectID),
      "application_id": .string(applicationID),
      "build_id": .string(buildID),
      "build_identity_digest": .string(buildIdentityDigest),
      "capture_scope": .string("app_only"),
      "consent": .object([
        "policy_version": consentPolicy["policy_version"]!,
        "screen_recording": .string("granted"),
        "microphone": .string("granted"),
        "diagnostics": .string("granted"),
        "raw_media_upload": .string("granted"),
        "granted_at": .string(consentGrantedAt),
      ]),
      "retention": retention,
    ]
    let scopeDigest = try TacuaCanonicalJSON.digest(.object(scope))
    scope["scope_digest"] = .string(scopeDigest)
    let scopeValue = TacuaJSONValue.object(scope)
    do {
      try TacuaSDKBackendRequests.validateStartArtifacts(
        buildIdentity: buildIdentity,
        scope: scopeValue,
        requestedAt: consentGrantedAt,
        configuration: configuration
      )
    } catch {
      throw TacuaSDKBuildProfileError.invalidProfile
    }
    return TacuaSDKCaptureArtifacts(
      profileDigest: profileDigest,
      buildIdentity: buildIdentity,
      scope: scopeValue,
      buildIdentityJSON: try TacuaCanonicalJSON.data(buildIdentity),
      scopeJSON: try TacuaCanonicalJSON.data(scopeValue),
      scopeDigest: scopeDigest,
      organizationID: organizationID,
      projectID: projectID,
      applicationID: applicationID,
      buildID: buildID,
      bundleIdentifier: bundleIdentifier,
      nativeBuild: nativeBuild
    )
  }

  private static func validateScopePolicy(
    _ value: TacuaJSONValue,
    buildIdentity: TacuaJSONValue
  ) throws {
    let policy = try value.requiringObject(keys: [
      "application_id", "build_id", "build_identity_digest", "capture_scope",
      "consent", "contract_version", "organization_id", "project_id",
      "protocol_version", "retention",
    ])
    guard policy["contract_version"]?.stringValue == scopePolicyContractVersion,
      policy["protocol_version"]?.stringValue == TacuaSDKBackendProtocol.version,
      policy["capture_scope"]?.stringValue == "app_only",
      let build = buildIdentity.objectValue,
      policy["build_id"] == build["build_id"],
      policy["build_identity_digest"] == build["build_identity_digest"]
    else { throw TacuaSDKBuildProfileError.invalidProfile }
    for field in ["organization_id", "project_id", "application_id", "build_id"] {
      guard let value = policy[field]?.stringValue, validIdentifier(value) else {
        throw TacuaSDKBuildProfileError.invalidProfile
      }
    }
    let consent = try policy["consent"]?.requiringObject(keys: [
      "diagnostics", "microphone", "policy_version", "raw_media_upload",
      "screen_recording",
    ]) ?? { throw TacuaSDKBuildProfileError.invalidProfile }()
    guard let policyVersion = consent["policy_version"]?.stringValue,
      !policyVersion.isEmpty, policyVersion.utf8.count <= 128,
      ["diagnostics", "microphone", "raw_media_upload", "screen_recording"]
        .allSatisfy({ consent[$0]?.stringValue == "required" })
    else { throw TacuaSDKBuildProfileError.invalidProfile }
    let retention = try policy["retention"]?.requiringObject(keys: [
      "derived_data_days", "policy_version", "raw_media_days",
    ]) ?? { throw TacuaSDKBuildProfileError.invalidProfile }()
    guard retention["policy_version"]?.stringValue == retentionPolicyVersion,
      let rawDays = retention["raw_media_days"]?.integerValue,
      let derivedDays = retention["derived_data_days"]?.integerValue,
      (1...30).contains(rawDays), (1...365).contains(derivedDays)
    else { throw TacuaSDKBuildProfileError.invalidProfile }
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }

  private static func validDigest(_ value: String) -> Bool {
    value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
  }

  private static func validTimestamp(_ value: String) -> Bool {
    guard value.range(
      of: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
      options: .regularExpression
    ) != nil else { return false }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    guard let date = formatter.date(from: value) else { return false }
    return formatter.string(from: date) == value
  }
}
