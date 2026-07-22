// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

enum TacuaJSONError: Error, Equatable {
  case responseTooLarge
  case invalidUTF8
  case unexpectedEnd
  case unexpectedToken
  case trailingContent
  case duplicateKey(String)
  case nonNFCString
  case floatForbidden
  case unsafeInteger
  case invalidNumber
  case invalidEscape
  case invalidUnicodeEscape
  case nestingTooDeep
  case wrongType
  case missingField(String)
  case unknownFields([String])
}

indirect enum TacuaJSONValue: Equatable {
  case null
  case bool(Bool)
  case integer(Int64)
  case string(String)
  case array([TacuaJSONValue])
  case object([String: TacuaJSONValue])

  var objectValue: [String: TacuaJSONValue]? {
    guard case .object(let value) = self else { return nil }
    return value
  }

  var arrayValue: [TacuaJSONValue]? {
    guard case .array(let value) = self else { return nil }
    return value
  }

  var stringValue: String? {
    guard case .string(let value) = self else { return nil }
    return value
  }

  var integerValue: Int64? {
    guard case .integer(let value) = self else { return nil }
    return value
  }

  var boolValue: Bool? {
    guard case .bool(let value) = self else { return nil }
    return value
  }

  func requiringObject(keys: Set<String>) throws -> [String: TacuaJSONValue] {
    guard case .object(let object) = self else { throw TacuaJSONError.wrongType }
    let actual = Set(object.keys)
    let missing = keys.subtracting(actual).sorted()
    if let first = missing.first { throw TacuaJSONError.missingField(first) }
    let extras = actual.subtracting(keys).sorted()
    if !extras.isEmpty { throw TacuaJSONError.unknownFields(extras) }
    return object
  }

  func objectRemoving(_ key: String) throws -> TacuaJSONValue {
    guard case .object(var object) = self else { throw TacuaJSONError.wrongType }
    object.removeValue(forKey: key)
    return .object(object)
  }
}

enum TacuaCanonicalJSON {
  static let maximumSafeInteger: Int64 = 9_007_199_254_740_991
  static let defaultMaximumBytes = 4 * 1_024 * 1_024

  static func parse(_ data: Data, maximumBytes: Int = defaultMaximumBytes) throws -> TacuaJSONValue {
    guard data.count <= maximumBytes else { throw TacuaJSONError.responseTooLarge }
    guard !data.starts(with: [0xEF, 0xBB, 0xBF]) else { throw TacuaJSONError.invalidUTF8 }
    var parser = TacuaStrictJSONParser(bytes: Array(data))
    return try parser.parse()
  }

  static func data(_ value: TacuaJSONValue) throws -> Data {
    var output = Data()
    try append(value, to: &output)
    return output
  }

  static func string(_ value: TacuaJSONValue) throws -> String {
    let encoded = try data(value)
    guard let string = String(data: encoded, encoding: .utf8) else {
      throw TacuaJSONError.invalidUTF8
    }
    return string
  }

  static func digest(_ value: TacuaJSONValue, omittingRootField field: String? = nil) throws -> String {
    let subject = try field.map { try value.objectRemoving($0) } ?? value
    return digest(data: try data(subject))
  }

  static func digest(data: Data) -> String {
    let hash = SHA256.hash(data: data)
    return "sha256:" + hash.map { String(format: "%02x", $0) }.joined()
  }

  private static func append(_ value: TacuaJSONValue, to output: inout Data) throws {
    switch value {
    case .null:
      output.append(contentsOf: [0x6E, 0x75, 0x6C, 0x6C])
    case .bool(let value):
      output.append(contentsOf: value ? [0x74, 0x72, 0x75, 0x65] : [0x66, 0x61, 0x6C, 0x73, 0x65])
    case .integer(let value):
      guard value >= -maximumSafeInteger, value <= maximumSafeInteger else {
        throw TacuaJSONError.unsafeInteger
      }
      output.append(contentsOf: String(value).utf8)
    case .string(let value):
      guard isNFC(value) else {
        throw TacuaJSONError.nonNFCString
      }
      appendEscaped(value, to: &output)
    case .array(let values):
      output.append(0x5B)
      for (index, child) in values.enumerated() {
        if index > 0 { output.append(0x2C) }
        try append(child, to: &output)
      }
      output.append(0x5D)
    case .object(let object):
      output.append(0x7B)
      for (index, key) in object.keys.sorted().enumerated() {
        guard isNFC(key) else {
          throw TacuaJSONError.nonNFCString
        }
        if index > 0 { output.append(0x2C) }
        appendEscaped(key, to: &output)
        output.append(0x3A)
        try append(object[key]!, to: &output)
      }
      output.append(0x7D)
    }
  }

  private static func appendEscaped(_ value: String, to output: inout Data) {
    output.append(0x22)
    for scalar in value.unicodeScalars {
      switch scalar.value {
      case 0x08: output.append(contentsOf: [0x5C, 0x62])
      case 0x09: output.append(contentsOf: [0x5C, 0x74])
      case 0x0A: output.append(contentsOf: [0x5C, 0x6E])
      case 0x0C: output.append(contentsOf: [0x5C, 0x66])
      case 0x0D: output.append(contentsOf: [0x5C, 0x72])
      case 0x22: output.append(contentsOf: [0x5C, 0x22])
      case 0x5C: output.append(contentsOf: [0x5C, 0x5C])
      case 0x00...0x1F:
        output.append(contentsOf: String(format: "\\u%04x", scalar.value).utf8)
      default:
        output.append(contentsOf: String(scalar).utf8)
      }
    }
    output.append(0x22)
  }

  fileprivate static func isNFC(_ value: String) -> Bool {
    Data(value.precomposedStringWithCanonicalMapping.utf8) == Data(value.utf8)
  }
}

private struct TacuaStrictJSONParser {
  private let bytes: [UInt8]
  private var index = 0
  private let maximumDepth = 64

  init(bytes: [UInt8]) {
    self.bytes = bytes
  }

  mutating func parse() throws -> TacuaJSONValue {
    skipWhitespace()
    let value = try parseValue(depth: 0)
    skipWhitespace()
    guard index == bytes.count else { throw TacuaJSONError.trailingContent }
    return value
  }

  private mutating func parseValue(depth: Int) throws -> TacuaJSONValue {
    guard depth <= maximumDepth else { throw TacuaJSONError.nestingTooDeep }
    guard index < bytes.count else { throw TacuaJSONError.unexpectedEnd }
    switch bytes[index] {
    case 0x6E:
      try consume("null")
      return .null
    case 0x74:
      try consume("true")
      return .bool(true)
    case 0x66:
      try consume("false")
      return .bool(false)
    case 0x22:
      return .string(try parseString())
    case 0x5B:
      return try parseArray(depth: depth + 1)
    case 0x7B:
      return try parseObject(depth: depth + 1)
    case 0x2D, 0x30...0x39:
      return .integer(try parseInteger())
    default:
      throw TacuaJSONError.unexpectedToken
    }
  }

  private mutating func parseArray(depth: Int) throws -> TacuaJSONValue {
    index += 1
    skipWhitespace()
    var values: [TacuaJSONValue] = []
    if consumeIf(0x5D) { return .array(values) }
    while true {
      values.append(try parseValue(depth: depth))
      skipWhitespace()
      if consumeIf(0x5D) { return .array(values) }
      guard consumeIf(0x2C) else { throw TacuaJSONError.unexpectedToken }
      skipWhitespace()
    }
  }

  private mutating func parseObject(depth: Int) throws -> TacuaJSONValue {
    index += 1
    skipWhitespace()
    var object: [String: TacuaJSONValue] = [:]
    if consumeIf(0x7D) { return .object(object) }
    while true {
      guard index < bytes.count, bytes[index] == 0x22 else {
        throw TacuaJSONError.unexpectedToken
      }
      let key = try parseString()
      guard object[key] == nil else { throw TacuaJSONError.duplicateKey(key) }
      skipWhitespace()
      guard consumeIf(0x3A) else { throw TacuaJSONError.unexpectedToken }
      skipWhitespace()
      object[key] = try parseValue(depth: depth)
      skipWhitespace()
      if consumeIf(0x7D) { return .object(object) }
      guard consumeIf(0x2C) else { throw TacuaJSONError.unexpectedToken }
      skipWhitespace()
    }
  }

  private mutating func parseString() throws -> String {
    guard consumeIf(0x22) else { throw TacuaJSONError.unexpectedToken }
    var value = ""
    var raw = Data()
    while index < bytes.count {
      let byte = bytes[index]
      index += 1
      if byte == 0x22 {
        try flush(raw: &raw, into: &value)
        guard TacuaCanonicalJSON.isNFC(value) else {
          throw TacuaJSONError.nonNFCString
        }
        return value
      }
      if byte == 0x5C {
        try flush(raw: &raw, into: &value)
        guard index < bytes.count else { throw TacuaJSONError.unexpectedEnd }
        let escape = bytes[index]
        index += 1
        switch escape {
        case 0x22: value.append("\"")
        case 0x5C: value.append("\\")
        case 0x2F: value.append("/")
        case 0x62: value.append("\u{8}")
        case 0x66: value.append("\u{c}")
        case 0x6E: value.append("\n")
        case 0x72: value.append("\r")
        case 0x74: value.append("\t")
        case 0x75: try appendUnicodeEscape(to: &value)
        default: throw TacuaJSONError.invalidEscape
        }
      } else {
        guard byte >= 0x20 else { throw TacuaJSONError.invalidEscape }
        raw.append(byte)
      }
    }
    throw TacuaJSONError.unexpectedEnd
  }

  private mutating func appendUnicodeEscape(to value: inout String) throws {
    let first = try readHexQuad()
    let scalarValue: UInt32
    if (0xD800...0xDBFF).contains(first) {
      guard index + 1 < bytes.count, bytes[index] == 0x5C, bytes[index + 1] == 0x75 else {
        throw TacuaJSONError.invalidUnicodeEscape
      }
      index += 2
      let second = try readHexQuad()
      guard (0xDC00...0xDFFF).contains(second) else {
        throw TacuaJSONError.invalidUnicodeEscape
      }
      scalarValue = 0x10000 + (UInt32(first - 0xD800) << 10) + UInt32(second - 0xDC00)
    } else {
      guard !(0xDC00...0xDFFF).contains(first) else {
        throw TacuaJSONError.invalidUnicodeEscape
      }
      scalarValue = UInt32(first)
    }
    guard let scalar = UnicodeScalar(scalarValue) else {
      throw TacuaJSONError.invalidUnicodeEscape
    }
    value.unicodeScalars.append(scalar)
  }

  private mutating func readHexQuad() throws -> UInt16 {
    guard index + 4 <= bytes.count else { throw TacuaJSONError.unexpectedEnd }
    var result: UInt16 = 0
    for _ in 0..<4 {
      let byte = bytes[index]
      index += 1
      let digit: UInt16
      switch byte {
      case 0x30...0x39: digit = UInt16(byte - 0x30)
      case 0x41...0x46: digit = UInt16(byte - 0x41 + 10)
      case 0x61...0x66: digit = UInt16(byte - 0x61 + 10)
      default: throw TacuaJSONError.invalidUnicodeEscape
      }
      result = (result << 4) | digit
    }
    return result
  }

  private mutating func parseInteger() throws -> Int64 {
    let start = index
    _ = consumeIf(0x2D)
    guard index < bytes.count else { throw TacuaJSONError.invalidNumber }
    if consumeIf(0x30) {
      if index < bytes.count, (0x30...0x39).contains(bytes[index]) {
        throw TacuaJSONError.invalidNumber
      }
    } else {
      guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else {
        throw TacuaJSONError.invalidNumber
      }
      index += 1
      while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
    }
    if index < bytes.count, [0x2E, 0x45, 0x65].contains(bytes[index]) {
      throw TacuaJSONError.floatForbidden
    }
    guard let string = String(bytes: bytes[start..<index], encoding: .utf8),
      let value = Int64(string)
    else {
      throw TacuaJSONError.invalidNumber
    }
    guard value >= -TacuaCanonicalJSON.maximumSafeInteger,
      value <= TacuaCanonicalJSON.maximumSafeInteger
    else {
      throw TacuaJSONError.unsafeInteger
    }
    return value
  }

  private mutating func consume(_ token: StaticString) throws {
    let expected = Array(String(describing: token).utf8)
    guard index + expected.count <= bytes.count,
      Array(bytes[index..<(index + expected.count)]) == expected
    else {
      throw TacuaJSONError.unexpectedToken
    }
    index += expected.count
  }

  private mutating func consumeIf(_ byte: UInt8) -> Bool {
    guard index < bytes.count, bytes[index] == byte else { return false }
    index += 1
    return true
  }

  private mutating func skipWhitespace() {
    while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) {
      index += 1
    }
  }

  private func flush(raw: inout Data, into value: inout String) throws {
    guard !raw.isEmpty else { return }
    guard let string = String(data: raw, encoding: .utf8) else {
      throw TacuaJSONError.invalidUTF8
    }
    value.append(string)
    raw.removeAll(keepingCapacity: true)
  }
}
