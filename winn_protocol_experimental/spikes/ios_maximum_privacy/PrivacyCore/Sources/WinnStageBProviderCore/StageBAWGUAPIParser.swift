import CryptoKit
import Darwin
import Foundation

public enum StageBAWGUAPIParserError: Error, Equatable, Sendable {
  case emptyInput
  case inputTooLarge
  case invalidUTF8
  case invalidLineTermination
  case tooManyLines
  case lineTooLong
  case malformedLine
  case unknownField
  case duplicateField
  case missingField
  case invalidHex
  case invalidDecimal
  case invalidProtocolVersion
  case invalidHandshakeNanoseconds
  case handshakeMillisecondsOverflow
  case zeroPeers
  case multiplePeers
  case wrongPeer
}

/// Strict parser for the direct `wgGetConfig(handle)` result produced by the
/// pinned AmneziaWG Apple bridge.
///
/// This is deliberately not a parser for the socket UAPI response format:
/// `wgGetConfig` returns only the `IpcGet()` payload and carries failure as a
/// null pointer, so an `errno=` line is not valid input here.
///
/// The parser never exposes interface private or preshared key material. It
/// admits exactly one expected peer and returns only the non-secret telemetry
/// required by Stage B.
public enum StageBAWGUAPIParser {
  public static let maximumInputBytes = 32 * 1024
  public static let maximumLines = 128
  public static let maximumLineBytes = 512
  public static let maximumAllowedIPs = 16

  /// Parses one native UAPI payload into the exact expected peer's telemetry.
  ///
  /// This returns peer telemetry only. Attaching a path binding, a native
  /// provenance token, and a sample time is the exclusive job of
  /// `StageBAWGNativeCaptureSource`, so parsing bytes alone cannot produce a
  /// `StageBAWGSnapshot`.
  public static func parsePeer(
    _ bytes: [UInt8],
    expectedPeerPublicKey: [UInt8]
  ) throws -> StageBAWGPeerSnapshot {
    guard !bytes.isEmpty else {
      throw StageBAWGUAPIParserError.emptyInput
    }
    guard bytes.count <= maximumInputBytes else {
      throw StageBAWGUAPIParserError.inputTooLarge
    }
    guard bytes.last == 0x0A, !bytes.contains(0x00), !bytes.contains(0x0D)
    else {
      throw StageBAWGUAPIParserError.invalidLineTermination
    }
    guard expectedPeerPublicKey.count == 32 else {
      throw StageBAWGUAPIParserError.invalidHex
    }
    guard let input = String(bytes: bytes, encoding: .utf8) else {
      throw StageBAWGUAPIParserError.invalidUTF8
    }

    let allLines = input.split(
      separator: "\n",
      omittingEmptySubsequences: false
    )
    guard allLines.last?.isEmpty == true else {
      throw StageBAWGUAPIParserError.invalidLineTermination
    }
    let lines = allLines.dropLast()
    guard !lines.isEmpty else {
      throw StageBAWGUAPIParserError.emptyInput
    }
    guard lines.count <= maximumLines else {
      throw StageBAWGUAPIParserError.tooManyLines
    }
    guard lines.allSatisfy({ $0.utf8.count <= maximumLineBytes }) else {
      throw StageBAWGUAPIParserError.lineTooLong
    }

    var interfaceFields = Set<String>()
    var peer: PeerAccumulator?
    var completedPeerCount = 0

    for line in lines {
      guard !line.isEmpty, let separator = line.firstIndex(of: "=") else {
        throw StageBAWGUAPIParserError.malformedLine
      }
      let key = String(line[..<separator])
      let value = String(line[line.index(after: separator)...])
      guard !key.isEmpty, !value.isEmpty else {
        throw StageBAWGUAPIParserError.malformedLine
      }

      if key == "public_key" {
        if peer != nil {
          completedPeerCount += 1
          guard completedPeerCount < 2 else {
            throw StageBAWGUAPIParserError.multiplePeers
          }
        }
        peer = PeerAccumulator()
      }

      if peer == nil {
        try validateInterfaceField(
          key: key,
          value: value,
          seen: &interfaceFields
        )
      } else {
        try peer?.consume(key: key, value: value)
      }
    }

    guard var parsedPeer = peer else {
      throw StageBAWGUAPIParserError.zeroPeers
    }
    guard interfaceFields.contains("private_key") else {
      throw StageBAWGUAPIParserError.missingField
    }
    completedPeerCount += 1
    guard completedPeerCount == 1 else {
      throw StageBAWGUAPIParserError.multiplePeers
    }
    return try parsedPeer.finish(
      expectedPeerPublicKey: expectedPeerPublicKey
    )
  }

  private static func validateInterfaceField(
    key: String,
    value: String,
    seen: inout Set<String>
  ) throws {
    guard seen.insert(key).inserted else {
      throw StageBAWGUAPIParserError.duplicateField
    }

    switch key {
    case "private_key":
      try validateHex32(value)
      guard value.utf8.contains(where: { $0 != 0x30 }) else {
        throw StageBAWGUAPIParserError.invalidHex
      }
    case "listen_port":
      guard
        try parseDecimal(value, maximum: UInt64(UInt16.max)) > 0
      else {
        throw StageBAWGUAPIParserError.invalidDecimal
      }
    case "fwmark", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
      guard
        try parseDecimal(value, maximum: UInt64(UInt32.max)) > 0
      else {
        throw StageBAWGUAPIParserError.invalidDecimal
      }
    case "h1", "h2", "h3", "h4":
      try validateHeaderSpec(value)
    default:
      guard ["i1", "i2", "i3", "i4", "i5"].contains(key) else {
        throw StageBAWGUAPIParserError.unknownField
      }
      try validateOpaqueASCII(value, permitsSpace: true)
    }
  }

  private static func validateOpaqueASCII(
    _ value: String,
    permitsSpace: Bool = false
  ) throws {
    let lowerBound: UInt8 = permitsSpace ? 0x20 : 0x21
    guard
      !value.isEmpty,
      value.utf8.count <= maximumLineBytes,
      value.utf8.allSatisfy({ $0 >= lowerBound && $0 <= 0x7E })
    else {
      throw StageBAWGUAPIParserError.malformedLine
    }
  }

  private static func validateHeaderSpec(_ value: String) throws {
    let parts = value.split(
      separator: "-",
      omittingEmptySubsequences: false
    )
    guard parts.count == 1 || parts.count == 2 else {
      throw StageBAWGUAPIParserError.malformedLine
    }
    let start = try parseDecimal(
      String(parts[0]),
      maximum: UInt64(UInt32.max)
    )
    if parts.count == 2 {
      let end = try parseDecimal(
        String(parts[1]),
        maximum: UInt64(UInt32.max)
      )
      guard end >= start else {
        throw StageBAWGUAPIParserError.malformedLine
      }
    }
  }

  private static func validateEndpoint(_ value: String) throws {
    let host: String
    let portText: String
    if value.first == "[" {
      guard
        let closing = value.firstIndex(of: "]"),
        value.index(after: closing) < value.endIndex,
        value[value.index(after: closing)] == ":"
      else {
        throw StageBAWGUAPIParserError.malformedLine
      }
      host = String(value[value.index(after: value.startIndex)..<closing])
      portText = String(value[value.index(closing, offsetBy: 2)...])
      guard validIPAddress(host, family: AF_INET6) else {
        throw StageBAWGUAPIParserError.malformedLine
      }
    } else {
      guard
        value.filter({ $0 == ":" }).count == 1,
        let separator = value.lastIndex(of: ":")
      else {
        throw StageBAWGUAPIParserError.malformedLine
      }
      host = String(value[..<separator])
      portText = String(value[value.index(after: separator)...])
      guard validIPAddress(host, family: AF_INET) else {
        throw StageBAWGUAPIParserError.malformedLine
      }
    }
    let port = try parseDecimal(portText, maximum: UInt64(UInt16.max))
    guard port > 0 else {
      throw StageBAWGUAPIParserError.malformedLine
    }
  }

  private static func validateAllowedIP(_ value: String) throws {
    let parts = value.split(
      separator: "/",
      omittingEmptySubsequences: false
    )
    guard parts.count == 2 else {
      throw StageBAWGUAPIParserError.malformedLine
    }
    let address = String(parts[0])
    let prefixText = String(parts[1])
    if validIPAddress(address, family: AF_INET) {
      _ = try parseDecimal(prefixText, maximum: 32)
    } else if validIPAddress(address, family: AF_INET6) {
      _ = try parseDecimal(prefixText, maximum: 128)
    } else {
      throw StageBAWGUAPIParserError.malformedLine
    }
  }

  private static func validIPAddress(_ value: String, family: Int32) -> Bool {
    var storage = [UInt8](
      repeating: 0,
      count: family == AF_INET ? 4 : 16
    )
    return value.withCString { pointer in
      storage.withUnsafeMutableBytes { destination in
        inet_pton(family, pointer, destination.baseAddress) == 1
      }
    }
  }

  fileprivate static func validateHex32(_ value: String) throws {
    guard value.utf8.count == 64 else {
      throw StageBAWGUAPIParserError.invalidHex
    }
    guard value.utf8.allSatisfy({ hexNibble($0) != nil }) else {
      throw StageBAWGUAPIParserError.invalidHex
    }
  }

  fileprivate static func decodeHex32(_ value: String) throws -> [UInt8] {
    guard value.utf8.count == 64 else {
      throw StageBAWGUAPIParserError.invalidHex
    }
    let characters = Array(value.utf8)
    var output = [UInt8]()
    output.reserveCapacity(32)
    for index in stride(from: 0, to: characters.count, by: 2) {
      guard
        let high = hexNibble(characters[index]),
        let low = hexNibble(characters[index + 1])
      else {
        throw StageBAWGUAPIParserError.invalidHex
      }
      output.append((high << 4) | low)
    }
    return output
  }

  private static func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39: return byte - 0x30
    case 0x61...0x66: return byte - 0x61 + 10
    default: return nil
    }
  }

  fileprivate static func parseDecimal(
    _ value: String,
    maximum: UInt64 = UInt64.max
  ) throws -> UInt64 {
    guard
      !value.isEmpty,
      value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
      !(value.count > 1 && value.first == "0")
    else {
      throw StageBAWGUAPIParserError.invalidDecimal
    }
    var result: UInt64 = 0
    for byte in value.utf8 {
      let digit = UInt64(byte - 0x30)
      guard result <= (maximum - digit) / 10 else {
        throw StageBAWGUAPIParserError.invalidDecimal
      }
      result = result * 10 + digit
    }
    return result
  }

  fileprivate static func checkedMilliseconds(
    seconds: UInt64,
    nanoseconds: UInt64
  ) throws -> UInt64 {
    guard nanoseconds < 1_000_000_000 else {
      throw StageBAWGUAPIParserError.invalidHandshakeNanoseconds
    }
    let fractionalMilliseconds = nanoseconds / 1_000_000
    guard seconds <= (UInt64.max - fractionalMilliseconds) / 1_000 else {
      throw StageBAWGUAPIParserError.handshakeMillisecondsOverflow
    }
    return seconds * 1_000 + fractionalMilliseconds
  }

  private struct PeerAccumulator {
    var seen = Set<String>()
    var allowedIPs = Set<String>()
    var publicKey: [UInt8]?
    var handshakeSeconds: UInt64?
    var handshakeNanoseconds: UInt64?
    var transmittedBytes: UInt64?
    var receivedBytes: UInt64?

    mutating func consume(key: String, value: String) throws {
      if key == "allowed_ip" {
        guard allowedIPs.count < StageBAWGUAPIParser.maximumAllowedIPs else {
          throw StageBAWGUAPIParserError.tooManyLines
        }
        guard allowedIPs.insert(value).inserted else {
          throw StageBAWGUAPIParserError.duplicateField
        }
        try StageBAWGUAPIParser.validateAllowedIP(value)
        return
      }
      guard seen.insert(key).inserted else {
        throw StageBAWGUAPIParserError.duplicateField
      }

      switch key {
      case "public_key":
        publicKey = try StageBAWGUAPIParser.decodeHex32(value)
      case "preshared_key":
        try StageBAWGUAPIParser.validateHex32(value)
      case "protocol_version":
        guard value == "1" else {
          throw StageBAWGUAPIParserError.invalidProtocolVersion
        }
      case "endpoint":
        try StageBAWGUAPIParser.validateEndpoint(value)
      case "last_handshake_time_sec":
        handshakeSeconds = try StageBAWGUAPIParser.parseDecimal(value)
      case "last_handshake_time_nsec":
        handshakeNanoseconds = try StageBAWGUAPIParser.parseDecimal(
          value,
          maximum: 999_999_999
        )
      case "tx_bytes":
        transmittedBytes = try StageBAWGUAPIParser.parseDecimal(value)
      case "rx_bytes":
        receivedBytes = try StageBAWGUAPIParser.parseDecimal(value)
      case "persistent_keepalive_interval":
        _ = try StageBAWGUAPIParser.parseDecimal(
          value,
          maximum: UInt64(UInt16.max)
        )
      default:
        throw StageBAWGUAPIParserError.unknownField
      }
    }

    mutating func finish(
      expectedPeerPublicKey: [UInt8]
    ) throws -> StageBAWGPeerSnapshot {
      let requiredFields: Set<String> = [
        "public_key",
        "preshared_key",
        "protocol_version",
        "last_handshake_time_sec",
        "last_handshake_time_nsec",
        "tx_bytes",
        "rx_bytes",
        "persistent_keepalive_interval",
      ]
      guard requiredFields.isSubset(of: seen) else {
        throw StageBAWGUAPIParserError.missingField
      }
      guard
        let publicKey,
        let handshakeSeconds,
        let handshakeNanoseconds,
        let transmittedBytes,
        let receivedBytes
      else {
        throw StageBAWGUAPIParserError.missingField
      }
      guard publicKey == expectedPeerPublicKey else {
        throw StageBAWGUAPIParserError.wrongPeer
      }
      guard !(handshakeSeconds == 0 && handshakeNanoseconds > 0) else {
        throw StageBAWGUAPIParserError.invalidHandshakeNanoseconds
      }
      _ = try StageBAWGUAPIParser.checkedMilliseconds(
        seconds: handshakeSeconds,
        nanoseconds: handshakeNanoseconds
      )
      return try StageBAWGPeerSnapshot(
        peerPublicKeySHA256: Array(SHA256.hash(data: Data(publicKey))),
        latestHandshakeUnixSeconds: handshakeSeconds,
        latestHandshakeNanoseconds: UInt32(handshakeNanoseconds),
        receivedBytes: receivedBytes,
        transmittedBytes: transmittedBytes
      )
    }
  }
}
