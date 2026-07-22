// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum CredentialTestFailure: Error {
  case assertion(String)
  case forcedStoreFailure
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw CredentialTestFailure.assertion(message) }
}

private final class InMemoryCredentialStore: TacuaCredentialStoring {
  var values: [String: Data] = [:]
  var calls: [String] = []
  var shouldFailStore = false

  func store(secret: Data, credentialID: String) throws {
    calls.append("store:\(credentialID)")
    if shouldFailStore { throw CredentialTestFailure.forcedStoreFailure }
    if values[credentialID] != nil { throw TacuaCredentialStoreError.duplicateCredential }
    values[credentialID] = secret
  }

  func read(credentialID: String) throws -> Data {
    calls.append("read:\(credentialID)")
    guard let value = values[credentialID] else {
      throw TacuaCredentialStoreError.credentialNotFound
    }
    return value
  }

  func remove(credentialID: String) throws {
    calls.append("remove:\(credentialID)")
    values.removeValue(forKey: credentialID)
  }
}

private struct DeterministicRandom: TacuaSecureRandomGenerating {
  let data: Data

  func bytes(count: Int) throws -> Data {
    data
  }
}

@main
enum CredentialStoreTests {
  static func main() throws {
    try persistsBeforeReturningMaterial()
    try rejectsWrongRandomLength()
    try doesNotReturnMaterialAfterStoreFailure()
    try recoverAndRemoveUseOnlyCredentialIdentifier()
    try ownershipVerifierPreventsDeletingAnotherItem()
    print("Tacua credential abstraction tests passed")
  }

  private static func persistsBeforeReturningMaterial() throws {
    let store = InMemoryCredentialStore()
    let secret = Data((0..<32).map(UInt8.init))
    var uuids = [
      UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
      UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
    ]
    let factory = TacuaCredentialFactory(
      store: store,
      random: DeterministicRandom(data: secret),
      uuid: { uuids.removeFirst() }
    )
    let material = try factory.prepare()
    try require(
      material.exchangeID == "exchange_11111111111111111111111111111111",
      "Exchange ID must be client-generated and protocol-safe"
    )
    try require(
      material.credentialID == "credential_22222222222222222222222222222222",
      "Credential ID must be client-generated and protocol-safe"
    )
    try require(material.secret == secret, "Factory returned different credential bytes")
    try require(
      store.values[material.credentialID] == secret,
      "Secret must already be durable before prepare returns"
    )
    try require(store.calls == ["store:\(material.credentialID)"], "Unexpected credential calls")
  }

  private static func rejectsWrongRandomLength() throws {
    let store = InMemoryCredentialStore()
    let factory = TacuaCredentialFactory(
      store: store,
      random: DeterministicRandom(data: Data(repeating: 1, count: 31))
    )
    do {
      _ = try factory.prepare()
      throw CredentialTestFailure.assertion("Short random output was accepted")
    } catch let error as TacuaCredentialStoreError {
      try require(error == .invalidSecretLength, "Unexpected short-secret error")
    }
    try require(store.calls.isEmpty, "Invalid secret must not reach storage")
  }

  private static func doesNotReturnMaterialAfterStoreFailure() throws {
    let store = InMemoryCredentialStore()
    store.shouldFailStore = true
    let factory = TacuaCredentialFactory(
      store: store,
      random: DeterministicRandom(data: Data(repeating: 2, count: 32))
    )
    do {
      _ = try factory.prepare()
      throw CredentialTestFailure.assertion("Factory returned after storage failure")
    } catch CredentialTestFailure.forcedStoreFailure {
      try require(store.values.isEmpty, "Failed storage must retain no secret")
    }
  }

  private static func recoverAndRemoveUseOnlyCredentialIdentifier() throws {
    let store = InMemoryCredentialStore()
    let credentialID = "credential_test_001"
    let secret = Data(repeating: 3, count: 32)
    store.values[credentialID] = secret
    let factory = TacuaCredentialFactory(store: store)
    let recovered = try factory.recover(credentialID: credentialID)
    try require(recovered == secret, "Recover failed")
    try factory.remove(credentialID: credentialID)
    try require(store.values[credentialID] == nil, "Remove retained credential")
  }

  private static func ownershipVerifierPreventsDeletingAnotherItem() throws {
    let store = InMemoryCredentialStore()
    let credentialID = "credential_owner_001"
    let owned = Data(repeating: 4, count: 32)
    let other = Data(repeating: 5, count: 32)
    let factory = TacuaCredentialFactory(store: store)
    store.values[credentialID] = other
    let removedMismatch = try factory.removeIfOwned(
      credentialID: credentialID,
      ownershipDigest: TacuaCredentialFactory.ownershipDigest(for: owned)
    )
    try require(!removedMismatch, "Ownership mismatch was reported as removed")
    try require(store.values[credentialID] == other, "Ownership mismatch removed another item")

    let removedMatch = try factory.removeIfOwned(
      credentialID: credentialID,
      ownershipDigest: TacuaCredentialFactory.ownershipDigest(for: other)
    )
    try require(removedMatch, "Ownership match was not removed")
    try require(store.values[credentialID] == nil, "Owned credential survived cleanup")
  }
}
