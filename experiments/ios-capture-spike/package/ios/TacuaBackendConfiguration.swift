// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaBackendConfigurationError: Error, Equatable {
  case missingBuildConfiguration
  case invalidOrigin
  case insecureOrigin
  case loopbackDevelopmentOnly
  case invalidPathSegment
}

struct TacuaBackendConfiguration: Equatable {
  static let originInfoPlistKey = "TacuaBackendOrigin"
  static let insecureLoopbackInfoPlistKey = "TacuaAllowInsecureLoopback"
  static let policyVersion = "tacua.sdk-transport@1.0.0"

  let origin: URL
  let normalizedOrigin: String
  let configurationDigest: String

  init(
    buildConfiguredOrigin: String,
    allowInsecureLoopback: Bool,
    debugBuild: Bool
  ) throws {
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
    configurationDigest = try TacuaCanonicalJSON.digest(
      .object([
        "backend_origin": .string(normalized),
        "transport_policy_version": .string(Self.policyVersion),
      ])
    )
  }

  static func fromBuildConfiguration(
    bundle: Bundle = .main,
    debugBuild: Bool = _isDebugAssertConfiguration()
  ) throws -> TacuaBackendConfiguration {
    guard let origin = bundle.object(forInfoDictionaryKey: originInfoPlistKey) as? String,
      !origin.isEmpty
    else {
      throw TacuaBackendConfigurationError.missingBuildConfiguration
    }
    let allowInsecureLoopback =
      bundle.object(forInfoDictionaryKey: insecureLoopbackInfoPlistKey) as? Bool ?? false
    return try TacuaBackendConfiguration(
      buildConfiguredOrigin: origin,
      allowInsecureLoopback: allowInsecureLoopback,
      debugBuild: debugBuild
    )
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
