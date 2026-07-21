// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaLaunchLinkError: Error, Equatable {
  case missingBuildConfiguration
  case invalidConfiguredScheme
  case invalidLaunchURL
  case consentRequestNotFound
  case consentDeclined
}

struct TacuaLaunchLinkConfiguration: Equatable {
  static let schemeInfoPlistKey = "TacuaLaunchScheme"

  let scheme: String

  init(buildConfiguredScheme: String) throws {
    guard buildConfiguredScheme == buildConfiguredScheme.lowercased(),
      buildConfiguredScheme.range(
        of: "^[a-z][a-z0-9+.-]{1,62}$", options: .regularExpression
      ) != nil
    else { throw TacuaLaunchLinkError.invalidConfiguredScheme }
    scheme = buildConfiguredScheme
  }

  static func fromBuildConfiguration(bundle: Bundle = .main) throws
    -> TacuaLaunchLinkConfiguration
  {
    guard let scheme = bundle.object(forInfoDictionaryKey: schemeInfoPlistKey) as? String,
      !scheme.isEmpty
    else { throw TacuaLaunchLinkError.missingBuildConfiguration }
    return try TacuaLaunchLinkConfiguration(buildConfiguredScheme: scheme)
  }
}

struct TacuaParsedLaunchLink: Equatable {
  let launchCode: String
}

enum TacuaLaunchLinkParser {
  static func parse(_ rawURL: String, configuration: TacuaLaunchLinkConfiguration) throws
    -> TacuaParsedLaunchLink
  {
    guard rawURL.utf8.count <= 2_048,
      let components = URLComponents(string: rawURL),
      components.scheme == configuration.scheme,
      components.user == nil,
      components.password == nil,
      components.host == "tacua",
      components.port == nil,
      components.percentEncodedPath == "/start",
      components.fragment == nil,
      let items = components.queryItems,
      items.count == 1,
      items[0].name == "launch_code",
      let launchCode = items[0].value,
      launchCode.range(
        of: "^[A-Za-z0-9_-]{32,512}$", options: .regularExpression
      ) != nil
    else { throw TacuaLaunchLinkError.invalidLaunchURL }
    return TacuaParsedLaunchLink(launchCode: launchCode)
  }
}

struct TacuaPendingLaunchConsent: Equatable {
  let consentRequestID: String
  let requiredConsentVersion: String
}

/// Keeps the launch code entirely in volatile native memory. Parsing creates a consent request;
/// only an affirmative second call creates an approved one-shot handle. Request construction and
/// exchange must consume that handle through `withApprovedLaunchCode`.
final class TacuaLaunchConsentGate {
  private let lock = NSLock()
  private var pending: (id: String, launchCode: String)?
  private var approved: (id: String, launchCode: String)?

  func prepare(
    rawURL: String,
    configuration: TacuaLaunchLinkConfiguration
  ) throws -> TacuaPendingLaunchConsent {
    let parsed = try TacuaLaunchLinkParser.parse(rawURL, configuration: configuration)
    let consentRequestID = Self.identifier(prefix: "consent")
    lock.lock()
    pending = (consentRequestID, parsed.launchCode)
    approved = nil
    lock.unlock()
    return TacuaPendingLaunchConsent(
      consentRequestID: consentRequestID,
      requiredConsentVersion: TacuaCapturePolicy.requiredConsentVersion
    )
  }

  func confirm(consentRequestID: String, granted: Bool) throws -> String {
    lock.lock()
    defer { lock.unlock() }
    guard let candidate = pending, candidate.id == consentRequestID else {
      throw TacuaLaunchLinkError.consentRequestNotFound
    }
    pending = nil
    guard granted else {
      approved = nil
      throw TacuaLaunchLinkError.consentDeclined
    }
    let approvedID = Self.identifier(prefix: "approved")
    approved = (approvedID, candidate.launchCode)
    return approvedID
  }

  func cancel(consentRequestID: String) {
    lock.lock()
    if pending?.id == consentRequestID { pending = nil }
    if approved?.id == consentRequestID { approved = nil }
    lock.unlock()
  }

  func withApprovedLaunchCode<T>(
    approvedLaunchID: String,
    _ body: (String) throws -> T
  ) throws -> T {
    let launchCode: String
    lock.lock()
    guard let candidate = approved, candidate.id == approvedLaunchID else {
      lock.unlock()
      throw TacuaLaunchLinkError.consentRequestNotFound
    }
    approved = nil
    launchCode = candidate.launchCode
    lock.unlock()
    return try body(launchCode)
  }

  private static func identifier(prefix: String) -> String {
    "\(prefix)_" + UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
  }
}
