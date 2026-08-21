// SPDX-License-Identifier: Apache-2.0

import CoreFoundation
import Foundation

enum TacuaQABuildConfigurationError: Error, Equatable {
  case captureNotEnabled
  case invalidCaptureFlag
  case invalidBuildVariant
  case invalidDistribution
  case unsupportedBuildPair
  case developmentBuildRequiresDebug
}

struct TacuaQABuildConfiguration: Equatable {
  static let enabledInfoPlistKey = "TacuaCaptureEnabled"
  static let buildVariantInfoPlistKey = "TacuaCaptureBuildVariant"
  static let distributionInfoPlistKey = "TacuaCaptureDistribution"

  let buildVariant: String
  let distribution: String

  init(
    captureEnabled: Bool,
    buildVariant: String,
    distribution: String,
    debugBuild: Bool
  ) throws {
    guard captureEnabled else {
      throw TacuaQABuildConfigurationError.captureNotEnabled
    }
    guard buildVariant == "development" || buildVariant == "preview" else {
      throw TacuaQABuildConfigurationError.invalidBuildVariant
    }
    guard ["local", "internal", "testflight"].contains(distribution) else {
      throw TacuaQABuildConfigurationError.invalidDistribution
    }
    guard !(
      (buildVariant == "development" && distribution == "testflight")
        || (buildVariant == "preview" && distribution == "local")
    ) else {
      throw TacuaQABuildConfigurationError.unsupportedBuildPair
    }
    // A local QA host may deliberately use a Release configuration so its
    // JavaScript bundle is embedded and immutable during evidence capture.
    // The native profile, explicit capture flag, and `local` distribution
    // remain required. Development builds distributed beyond the local device
    // boundary still require Debug; loopback HTTP is gated independently
    // below by TacuaBackendConfiguration.
    if buildVariant == "development" && distribution != "local" && !debugBuild {
      throw TacuaQABuildConfigurationError.developmentBuildRequiresDebug
    }
    self.buildVariant = buildVariant
    self.distribution = distribution
  }

  static func fromBuildConfiguration(
    bundle: Bundle = .main,
    debugBuild: Bool = _isDebugAssertConfiguration()
  ) throws -> TacuaQABuildConfiguration {
    let rawEnabled = bundle.object(forInfoDictionaryKey: enabledInfoPlistKey)
    guard rawEnabled != nil else {
      throw TacuaQABuildConfigurationError.captureNotEnabled
    }
    guard let captureEnabled = rawEnabled as? Bool else {
      throw TacuaQABuildConfigurationError.invalidCaptureFlag
    }
    guard captureEnabled else {
      throw TacuaQABuildConfigurationError.captureNotEnabled
    }
    guard let buildVariant = bundle.object(
      forInfoDictionaryKey: buildVariantInfoPlistKey
    ) as? String else {
      throw TacuaQABuildConfigurationError.invalidBuildVariant
    }
    guard let distribution = bundle.object(
      forInfoDictionaryKey: distributionInfoPlistKey
    ) as? String else {
      throw TacuaQABuildConfigurationError.invalidDistribution
    }
    return try TacuaQABuildConfiguration(
      captureEnabled: captureEnabled,
      buildVariant: buildVariant,
      distribution: distribution,
      debugBuild: debugBuild
    )
  }
}

enum TacuaBackendConfigurationError: Error, Equatable {
  case missingBuildConfiguration
  case invalidOrigin
  case insecureOrigin
  case loopbackDevelopmentOnly
  case invalidTransportLimit
  case invalidTransportPolicy
  case invalidLaunchScheme
  case invalidPathSegment
  case buildIdentityMismatch
}

struct TacuaBackendConfiguration: Equatable {
  static let originInfoPlistKey = "TacuaBackendOrigin"
  static let insecureLoopbackInfoPlistKey = "TacuaAllowInsecureLoopback"
  static let maxSegmentBytesInfoPlistKey = "TacuaMaxSegmentBytes"
  static let maxDiagnosticBytesInfoPlistKey = "TacuaMaxDiagnosticBytes"
  static let maxCompletionBytesInfoPlistKey = "TacuaMaxCompletionBytes"
  static let transportPolicyVersionInfoPlistKey = "TacuaTransportPolicyVersion"
  static let launchSchemeInfoPlistKey = "TacuaLaunchScheme"
  static let legacyPolicyVersion = "tacua.sdk-transport@1.1.0"
  static let launchSchemePolicyVersion = "tacua.sdk-transport@1.2.0"
  static let maxSegmentBytesUpperBound = 1_073_741_824
  static let maxDiagnosticBytesUpperBound = 3_145_728
  static let maxCompletionBytesUpperBound = 4_194_304
  static let defaultMaxSegmentBytes = 268_435_456
  static let defaultMaxDiagnosticBytes = maxDiagnosticBytesUpperBound
  static let defaultMaxCompletionBytes = maxCompletionBytesUpperBound

  let origin: URL
  let normalizedOrigin: String
  let maxSegmentBytes: Int
  let maxDiagnosticBytes: Int
  let maxCompletionBytes: Int
  let policyVersion: String
  let launchScheme: String?
  let configurationDigest: String
  /// Present for the real app-bundle configuration path. Direct construction is retained for
  /// isolated protocol tests and non-bundle tooling, which do not have an Info.plist authority.
  let qaBuildConfiguration: TacuaQABuildConfiguration?

  init(
    buildConfiguredOrigin: String,
    allowInsecureLoopback: Bool,
    debugBuild: Bool,
    maxSegmentBytes: Int = Self.defaultMaxSegmentBytes,
    maxDiagnosticBytes: Int = Self.defaultMaxDiagnosticBytes,
    maxCompletionBytes: Int = Self.defaultMaxCompletionBytes,
    transportPolicyVersion: String = Self.legacyPolicyVersion,
    launchScheme: String? = nil,
    qaBuildConfiguration: TacuaQABuildConfiguration? = nil
  ) throws {
    guard (1...Self.maxSegmentBytesUpperBound).contains(maxSegmentBytes),
      (1_024...Self.maxDiagnosticBytesUpperBound).contains(maxDiagnosticBytes),
      (1_024...Self.maxCompletionBytesUpperBound).contains(maxCompletionBytes)
    else { throw TacuaBackendConfigurationError.invalidTransportLimit }
    let validatedLaunchScheme: String?
    switch transportPolicyVersion {
    case Self.legacyPolicyVersion:
      guard launchScheme == nil else {
        throw TacuaBackendConfigurationError.invalidLaunchScheme
      }
      validatedLaunchScheme = nil
    case Self.launchSchemePolicyVersion:
      guard let launchScheme, Self.validLaunchScheme(launchScheme) else {
        throw TacuaBackendConfigurationError.invalidLaunchScheme
      }
      validatedLaunchScheme = launchScheme
    default:
      throw TacuaBackendConfigurationError.invalidTransportPolicy
    }
    guard var components = URLComponents(string: buildConfiguredOrigin),
      let rawScheme = components.scheme,
      let rawHost = components.host,
      components.user == nil,
      components.password == nil,
      components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
      components.percentEncodedQuery == nil,
      components.fragment == nil
    else {
      throw TacuaBackendConfigurationError.invalidOrigin
    }
    let scheme = rawScheme.lowercased()
    let host = rawHost.lowercased()
    guard ["http", "https"].contains(scheme), Self.validHost(host) else {
      throw TacuaBackendConfigurationError.invalidOrigin
    }
    if let port = components.port, !(1...65_535).contains(port) {
      throw TacuaBackendConfigurationError.invalidOrigin
    }
    if scheme == "http" {
      guard Self.isLoopback(host) else {
        throw TacuaBackendConfigurationError.insecureOrigin
      }
      guard allowInsecureLoopback, debugBuild else {
        throw TacuaBackendConfigurationError.loopbackDevelopmentOnly
      }
    }

    components.scheme = scheme
    components.host = host
    if (scheme == "https" && components.port == 443)
      || (scheme == "http" && components.port == 80)
    {
      components.port = nil
    }
    components.path = ""
    components.query = nil
    components.fragment = nil
    guard let normalizedURL = components.url else {
      throw TacuaBackendConfigurationError.invalidOrigin
    }
    let normalized = normalizedURL.absoluteString
    guard !normalized.hasSuffix("/") else {
      throw TacuaBackendConfigurationError.invalidOrigin
    }
    origin = normalizedURL
    normalizedOrigin = normalized
    self.maxSegmentBytes = maxSegmentBytes
    self.maxDiagnosticBytes = maxDiagnosticBytes
    self.maxCompletionBytes = maxCompletionBytes
    policyVersion = transportPolicyVersion
    self.launchScheme = validatedLaunchScheme
    self.qaBuildConfiguration = qaBuildConfiguration
    var transportConfiguration: [String: TacuaJSONValue] = [
      "backend_origin": .string(normalized),
      "max_completion_bytes": .integer(Int64(maxCompletionBytes)),
      "max_diagnostic_bytes": .integer(Int64(maxDiagnosticBytes)),
      "max_segment_bytes": .integer(Int64(maxSegmentBytes)),
      "transport_policy_version": .string(transportPolicyVersion),
    ]
    if let validatedLaunchScheme {
      transportConfiguration["launch_scheme"] = .string(validatedLaunchScheme)
    }
    configurationDigest = try TacuaCanonicalJSON.digest(.object(transportConfiguration))
  }

  static func fromBuildConfiguration(
    bundle: Bundle = .main,
    debugBuild: Bool = _isDebugAssertConfiguration()
  ) throws -> TacuaBackendConfiguration {
    let qaBuildConfiguration = try TacuaQABuildConfiguration.fromBuildConfiguration(
      bundle: bundle,
      debugBuild: debugBuild
    )
    guard let origin = bundle.object(forInfoDictionaryKey: originInfoPlistKey) as? String,
      !origin.isEmpty
    else {
      throw TacuaBackendConfigurationError.missingBuildConfiguration
    }
    let allowInsecureLoopback =
      bundle.object(forInfoDictionaryKey: insecureLoopbackInfoPlistKey) as? Bool ?? false
    let rawTransportPolicyVersion = bundle.object(
      forInfoDictionaryKey: transportPolicyVersionInfoPlistKey
    )
    let transportPolicyVersion: String
    if rawTransportPolicyVersion == nil {
      transportPolicyVersion = Self.legacyPolicyVersion
    } else if let configuredVersion = rawTransportPolicyVersion as? String {
      transportPolicyVersion = configuredVersion
    } else {
      throw TacuaBackendConfigurationError.invalidTransportPolicy
    }
    let launchScheme: String?
    if transportPolicyVersion == Self.launchSchemePolicyVersion {
      guard let configuredScheme = bundle.object(
        forInfoDictionaryKey: launchSchemeInfoPlistKey
      ) as? String else {
        throw TacuaBackendConfigurationError.invalidLaunchScheme
      }
      launchScheme = configuredScheme
    } else {
      launchScheme = nil
    }
    guard let maxSegmentBytes = Self.infoPlistInteger(
      bundle: bundle,
      key: maxSegmentBytesInfoPlistKey
    ), let maxDiagnosticBytes = Self.infoPlistInteger(
      bundle: bundle,
      key: maxDiagnosticBytesInfoPlistKey
    ), let maxCompletionBytes = Self.infoPlistInteger(
      bundle: bundle,
      key: maxCompletionBytesInfoPlistKey
    ) else { throw TacuaBackendConfigurationError.invalidTransportLimit }
    return try TacuaBackendConfiguration(
      buildConfiguredOrigin: origin,
      allowInsecureLoopback: allowInsecureLoopback,
      debugBuild: debugBuild,
      maxSegmentBytes: maxSegmentBytes,
      maxDiagnosticBytes: maxDiagnosticBytes,
      maxCompletionBytes: maxCompletionBytes,
      transportPolicyVersion: transportPolicyVersion,
      launchScheme: launchScheme,
      qaBuildConfiguration: qaBuildConfiguration
    )
  }

  /// Prevents caller-supplied JSON from claiming a different build channel than the native
  /// Info.plist compiled into the QA build. This check is deliberately independent of the
  /// protocol schema validation: the schema proves that values are allowed, while this proves
  /// that they describe this binary.
  func validateBuildIdentityBinding(_ buildIdentity: TacuaJSONValue) throws {
    guard let qaBuildConfiguration else { return }
    guard let object = buildIdentity.objectValue,
      object["build_variant"]?.stringValue == qaBuildConfiguration.buildVariant,
      object["distribution"]?.stringValue == qaBuildConfiguration.distribution
    else {
      throw TacuaBackendConfigurationError.buildIdentityMismatch
    }
  }

  func endpoint(pathSegments: [String]) throws -> URL {
    guard !pathSegments.isEmpty,
      pathSegments.allSatisfy({ segment in
        !segment.isEmpty
          && segment != "."
          && segment != ".."
          && segment.range(of: "^[A-Za-z0-9._~-]+$", options: .regularExpression) != nil
      })
    else {
      throw TacuaBackendConfigurationError.invalidPathSegment
    }
    var components = URLComponents(url: origin, resolvingAgainstBaseURL: false)
    components?.percentEncodedPath = "/" + pathSegments.joined(separator: "/")
    guard let url = components?.url,
      url.scheme == origin.scheme,
      url.host == origin.host,
      url.port == origin.port
    else {
      throw TacuaBackendConfigurationError.invalidPathSegment
    }
    return url
  }

  private static func isLoopback(_ host: String) -> Bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
  }

  private static func validLaunchScheme(_ value: String) -> Bool {
    let reserved: Set<String> = [
      "about", "blob", "data", "facetime", "facetime-audio", "file", "ftp", "ftps",
      "http", "https", "itms", "itms-apps", "javascript", "mailto", "sms", "tacua",
      "tel", "webcal", "ws", "wss",
    ]
    return value == value.precomposedStringWithCanonicalMapping
      && value.range(of: "^[a-z][a-z0-9+.-]{1,63}$", options: .regularExpression) != nil
      && !reserved.contains(value)
  }

  private static func infoPlistInteger(bundle: Bundle, key: String) -> Int? {
    guard let number = bundle.object(forInfoDictionaryKey: key) as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID(),
      ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"]
        .contains(String(cString: number.objCType))
    else { return nil }
    return Int(exactly: number.int64Value)
  }

  private static func validHost(_ host: String) -> Bool {
    guard !host.isEmpty, host.utf8.count <= 253,
      host.unicodeScalars.allSatisfy({ $0.isASCII })
    else {
      return false
    }
    if isLoopback(host) { return true }
    return host.range(
      of: "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$",
      options: .regularExpression
    ) != nil
  }
}

final class TacuaRejectRedirectSessionDelegate: NSObject, URLSessionTaskDelegate {
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}
