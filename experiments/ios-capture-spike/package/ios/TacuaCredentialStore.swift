// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import Security

enum TacuaCredentialStoreError: Error, Equatable {
  case invalidIdentifier
  case invalidSecretLength
  case invalidOwnershipDigest
  case duplicateCredential
  case credentialNotFound
  case keychainFailure(Int32)
  case randomGenerationFailure(Int32)
}

enum TacuaCredentialAvailability: String, Equatable {
  case available
  case missing
  case temporarilyUnavailable = "temporarily_unavailable"
  case unavailable
  case notApplicable = "not_applicable"

  static func inspect(
    credentialID: String?,
    store: TacuaCredentialStoring
  ) -> TacuaCredentialAvailability {
    guard let credentialID else { return .notApplicable }
    do {
      return try store.read(credentialID: credentialID).count
        == TacuaKeychainCredentialStore.secretLength ? .available : .missing
    } catch TacuaCredentialStoreError.credentialNotFound,
      TacuaCredentialStoreError.invalidSecretLength
    {
      return .missing
    } catch TacuaCredentialStoreError.keychainFailure(let status)
      where status == errSecInteractionNotAllowed || status == errSecNotAvailable
    {
      // Device lock and transient Keychain service unavailability do not imply credential loss.
      return .temporarilyUnavailable
    } catch {
      return .unavailable
    }
  }
}

protocol TacuaCredentialStoring {
  func store(secret: Data, credentialID: String) throws
  func read(credentialID: String) throws -> Data
  func remove(credentialID: String) throws
}

protocol TacuaSecureRandomGenerating {
  func bytes(count: Int) throws -> Data
}

struct TacuaSystemSecureRandomGenerator: TacuaSecureRandomGenerating {
  func bytes(count: Int) throws -> Data {
    guard count > 0 else { throw TacuaCredentialStoreError.invalidSecretLength }
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else {
      throw TacuaCredentialStoreError.randomGenerationFailure(status)
    }
    return data
  }
}

struct TacuaKeychainCredentialStore: TacuaCredentialStoring {
  static let service = "dev.tacua.sdk.transport.v1"
  static let secretLength = 32

  func store(secret: Data, credentialID: String) throws {
    try Self.validate(credentialID: credentialID)
    guard secret.count == Self.secretLength else {
      throw TacuaCredentialStoreError.invalidSecretLength
    }
    let query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrAccount: credentialID,
      kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAttrSynchronizable: false,
      kSecValueData: secret,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecDuplicateItem {
      throw TacuaCredentialStoreError.duplicateCredential
    }
    guard status == errSecSuccess else {
      throw TacuaCredentialStoreError.keychainFailure(status)
    }
  }

  func read(credentialID: String) throws -> Data {
    try Self.validate(credentialID: credentialID)
    let query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrAccount: credentialID,
      kSecAttrSynchronizable: false,
      kSecReturnData: true,
      kSecMatchLimit: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    guard status == errSecSuccess, let data = result as? Data else {
      throw TacuaCredentialStoreError.keychainFailure(status)
    }
    guard data.count == Self.secretLength else {
      throw TacuaCredentialStoreError.invalidSecretLength
    }
    return data
  }

  func remove(credentialID: String) throws {
    try Self.validate(credentialID: credentialID)
    let query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.service,
      kSecAttrAccount: credentialID,
      kSecAttrSynchronizable: false,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw TacuaCredentialStoreError.keychainFailure(status)
    }
  }

  static func validate(credentialID: String) throws {
    guard credentialID.range(
      of: "^[a-z][a-z0-9_-]{2,63}$",
      options: .regularExpression
    ) != nil else {
      throw TacuaCredentialStoreError.invalidIdentifier
    }
  }
}

struct TacuaPreparedCredential: Equatable {
  let exchangeID: String
  let credentialID: String
  let secret: Data
}

struct TacuaCredentialFactory {
  private let store: TacuaCredentialStoring
  private let random: TacuaSecureRandomGenerating
  private let uuid: () -> UUID

  init(
    store: TacuaCredentialStoring,
    random: TacuaSecureRandomGenerating = TacuaSystemSecureRandomGenerator(),
    uuid: @escaping () -> UUID = UUID.init
  ) {
    self.store = store
    self.random = random
    self.uuid = uuid
  }

  /// The Keychain write completes before credential material is returned to a caller.
  func prepare() throws -> TacuaPreparedCredential {
    try prepare(beforeStore: { _, _, _ in })
  }

  /// Allows a lifecycle coordinator to durably journal the non-secret identifiers and ownership
  /// verifier before the Keychain mutation. The callback never receives credential material.
  func prepare(
    beforeStore: (
      _ exchangeID: String,
      _ credentialID: String,
      _ credentialOwnershipDigest: String
    ) throws -> Void
  ) throws -> TacuaPreparedCredential {
    let exchangeID = Self.identifier(prefix: "exchange", uuid: uuid())
    let credentialID = Self.identifier(prefix: "credential", uuid: uuid())
    let secret = try random.bytes(count: TacuaKeychainCredentialStore.secretLength)
    guard secret.count == TacuaKeychainCredentialStore.secretLength else {
      throw TacuaCredentialStoreError.invalidSecretLength
    }
    try beforeStore(exchangeID, credentialID, Self.ownershipDigest(for: secret))
    try store.store(secret: secret, credentialID: credentialID)
    return TacuaPreparedCredential(
      exchangeID: exchangeID,
      credentialID: credentialID,
      secret: secret
    )
  }

  func recover(credentialID: String) throws -> Data {
    try store.read(credentialID: credentialID)
  }

  func remove(credentialID: String) throws {
    try store.remove(credentialID: credentialID)
  }

  /// Deletes only an item whose bytes match the verifier published before `SecItemAdd`. This
  /// distinguishes an item created by this attempt from a pre-existing duplicate after a crash.
  @discardableResult
  func removeIfOwned(
    credentialID: String,
    ownershipDigest: String
  ) throws -> Bool {
    guard ownershipDigest.range(
      of: "^sha256:[a-f0-9]{64}$",
      options: .regularExpression
    ) != nil else { throw TacuaCredentialStoreError.invalidOwnershipDigest }
    let secret: Data
    do {
      secret = try store.read(credentialID: credentialID)
    } catch TacuaCredentialStoreError.credentialNotFound,
      TacuaCredentialStoreError.invalidSecretLength
    {
      return false
    }
    guard Self.ownershipDigest(for: secret) == ownershipDigest else { return false }
    try store.remove(credentialID: credentialID)
    return true
  }

  var credentialStore: TacuaCredentialStoring { store }

  static func ownershipDigest(for secret: Data) -> String {
    let hash = SHA256.hash(data: secret)
    return "sha256:" + hash.map { String(format: "%02x", $0) }.joined()
  }

  private static func identifier(prefix: String, uuid: UUID) -> String {
    let compact = uuid.uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    return "\(prefix)_\(compact)"
  }
}
