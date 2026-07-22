// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum CanonicalTestFailure: Error {
  case assertion(String)
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw CanonicalTestFailure.assertion(message) }
}

private func expectJSONError(
  _ expected: TacuaJSONError,
  _ data: Data,
  maximumBytes: Int = TacuaCanonicalJSON.defaultMaximumBytes
) throws {
  do {
    _ = try TacuaCanonicalJSON.parse(data, maximumBytes: maximumBytes)
    throw CanonicalTestFailure.assertion("Expected \(expected), but parsing succeeded")
  } catch let error as TacuaJSONError {
    try require(error == expected, "Expected \(expected), received \(error)")
  }
}

@main
enum CanonicalJSONTests {
  static func main() throws {
    guard CommandLine.arguments.count == 2 else {
      throw CanonicalTestFailure.assertion("Expected canonical vector path")
    }
    try committedVectors(path: CommandLine.arguments[1])
    try strictParsingFailures()
    try unicodeEscapesAndCanonicalization()
    print("Tacua canonical JSON tests passed")
  }

  private static func committedVectors(path: String) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let root = try TacuaCanonicalJSON.parse(data)
    guard case .object(let rootObject) = root,
      rootObject["specification"] == .string("tacua.canonical-json@1.0.0"),
      case .array(let vectors)? = rootObject["vectors"]
    else {
      throw CanonicalTestFailure.assertion("Canonical vector fixture shape changed")
    }

    for vector in vectors {
      guard case .object(let object) = vector,
        let name = object["name"]?.stringValue,
        let value = object["value"],
        let expectedCanonical = object["canonical_utf8"]?.stringValue,
        let expectedHex = object["canonical_utf8_hex"]?.stringValue,
        let expectedDigest = object["sha256"]?.stringValue
      else {
        throw CanonicalTestFailure.assertion("Malformed canonical vector")
      }
      let canonical = try TacuaCanonicalJSON.data(value)
      try require(
        String(data: canonical, encoding: .utf8) == expectedCanonical,
        "Canonical text mismatch for \(name)"
      )
      try require(
        canonical.map { String(format: "%02x", $0) }.joined() == expectedHex,
        "Canonical bytes mismatch for \(name)"
      )
      try require(
        TacuaCanonicalJSON.digest(data: canonical) == expectedDigest,
        "Digest mismatch for \(name)"
      )
      let roundTrip = try TacuaCanonicalJSON.parse(canonical)
      try require(roundTrip == value, "Canonical round trip mismatch for \(name)")
    }
  }

  private static func strictParsingFailures() throws {
    try expectJSONError(
      .duplicateKey("a"),
      Data(#"{"a":1,"a":2}"#.utf8)
    )
    try expectJSONError(.floatForbidden, Data(#"{"value":1.0}"#.utf8))
    try expectJSONError(.unsafeInteger, Data(#"9007199254740992"#.utf8))
    try expectJSONError(.invalidNumber, Data(#"01"#.utf8))
    var nonNFC = Data(#"{"value":"Cafe"#.utf8)
    nonNFC.append(contentsOf: [0xCC, 0x81, 0x22, 0x7D])
    try expectJSONError(.nonNFCString, nonNFC)
    try expectJSONError(.invalidUTF8, Data([0xEF, 0xBB, 0xBF, 0x6E, 0x75, 0x6C, 0x6C]))
    try expectJSONError(.responseTooLarge, Data(#"{"a":1}"#.utf8), maximumBytes: 2)
  }

  private static func unicodeEscapesAndCanonicalization() throws {
    let escaped = try TacuaCanonicalJSON.parse(Data(#"{"emoji":"\ud83d\udc1e","slash":"\/"}"#.utf8))
    let canonical = try TacuaCanonicalJSON.string(escaped)
    try require(canonical == #"{"emoji":"🐞","slash":"/"}"#, "Escapes must canonicalize")
    let reordered = TacuaJSONValue.object(["z": .integer(2), "a": .integer(1)])
    let reorderedString = try TacuaCanonicalJSON.string(reordered)
    try require(reorderedString == #"{"a":1,"z":2}"#, "ASCII keys must sort deterministically")
  }
}
