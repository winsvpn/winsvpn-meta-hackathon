import CryptoKit
import XCTest

@testable import WinnStageBProviderCore
import WinnPrivacyCore

final class StageBAWGUAPIParserTests: XCTestCase {
  func testParsesPinnedBridgeGoldenOutputAndProducesExactPeerSnapshot()
    throws
  {
    let fixture = ParserFixture()
    let peer = try fixture.parse(fixture.golden)

    XCTAssertEqual(
      peer.peerPublicKeySHA256,
      Array(SHA256.hash(data: Data(fixture.peerKey)))
    )
    XCTAssertEqual(peer.latestHandshakeUnixSeconds, 1_900_000_000)
    XCTAssertEqual(peer.latestHandshakeNanoseconds, 123_456_789)
    XCTAssertEqual(
      peer.latestHandshakeUnixMilliseconds,
      1_900_000_000_123
    )
    XCTAssertEqual(peer.transmittedBytes, 356)
    XCTAssertEqual(peer.receivedBytes, 712)
  }

  func testAllowsKnownAWGInterfaceFieldsAndMultipleUniqueAllowedIPs()
    throws
  {
    let fixture = ParserFixture()
    let input = """
      private_key=\(fixture.hex([UInt8](repeating: 0x44, count: 32)))
      listen_port=51820
      fwmark=7
      jc=4
      jmin=40
      jmax=70
      s1=90
      s2=91
      s3=92
      s4=93
      h1=1
      h2=4-6
      h3=7
      h4=10-12
      i1=<b 0a0b><d>
      public_key=\(fixture.hex(fixture.peerKey))
      preshared_key=\(fixture.hex([UInt8](repeating: 0, count: 32)))
      protocol_version=1
      endpoint=192.0.2.10:51820
      last_handshake_time_sec=0
      last_handshake_time_nsec=0
      tx_bytes=0
      rx_bytes=0
      persistent_keepalive_interval=25
      allowed_ip=0.0.0.0/0
      allowed_ip=::/0
      """ + "\n"

    XCTAssertNoThrow(try fixture.parse(input))

    let ipv6 = fixture.golden.replacingOccurrences(
      of: "endpoint=192.0.2.10:51820",
      with: "endpoint=[2001:db8::10]:51820"
    ).replacingOccurrences(
      of: "allowed_ip=0.0.0.0/0",
      with: "allowed_ip=2001:db8::/32"
    )
    XCTAssertNoThrow(try fixture.parse(ipv6))

    let exactUnixSecond = fixture.golden.replacingOccurrences(
      of: "last_handshake_time_nsec=123456789",
      with: "last_handshake_time_nsec=0"
    )
    XCTAssertNoThrow(try fixture.parse(exactUnixSecond))
  }

  func testRejectsEmptyOversizedInvalidEncodingAndTerminators() throws {
    let fixture = ParserFixture()
    XCTAssertThrowsError(try fixture.parseBytes([])) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .emptyInput)
    }
    XCTAssertThrowsError(
      try fixture.parseBytes(
        [UInt8](repeating: 0x61, count: StageBAWGUAPIParser.maximumInputBytes + 1)
      )
    ) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .inputTooLarge)
    }
    XCTAssertThrowsError(try fixture.parseBytes([0xFF, 0x0A])) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .invalidUTF8)
    }
    XCTAssertThrowsError(try fixture.parse(String(fixture.golden.dropLast()))) {
      XCTAssertEqual(
        $0 as? StageBAWGUAPIParserError,
        .invalidLineTermination
      )
    }
    XCTAssertThrowsError(
      try fixture.parse(fixture.golden.replacingOccurrences(of: "\n", with: "\r\n"))
    ) {
      XCTAssertEqual(
        $0 as? StageBAWGUAPIParserError,
        .invalidLineTermination
      )
    }
    XCTAssertThrowsError(
      try fixture.parseBytes(Array(fixture.golden.utf8) + [0, 0x0A])
    ) {
      XCTAssertEqual(
        $0 as? StageBAWGUAPIParserError,
        .invalidLineTermination
      )
    }
  }

  func testRejectsZeroAndMultiplePeers() throws {
    let fixture = ParserFixture()
    XCTAssertThrowsError(try fixture.parse("listen_port=51820\n")) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .zeroPeers)
    }
    let second =
      fixture.golden + fixture.peerBlock(key: fixture.peerKey) + "\n"
    XCTAssertThrowsError(try fixture.parse(second)) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .multiplePeers)
    }
  }

  func testRejectsWrongPeerDuplicateFieldsAndDuplicateAllowedIP() throws {
    let fixture = ParserFixture()
    let wrong = fixture.golden.replacingOccurrences(
      of: fixture.hex(fixture.peerKey),
      with: fixture.hex([UInt8](repeating: 0x99, count: 32))
    )
    XCTAssertThrowsError(try fixture.parse(wrong)) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .wrongPeer)
    }

    for duplicate in [
      fixture.golden.replacingOccurrences(
        of: "tx_bytes=356\n",
        with: "tx_bytes=356\ntx_bytes=356\n"
      ),
      fixture.golden.replacingOccurrences(
        of: "private_key=",
        with:
          "private_key=\(fixture.hex([UInt8](repeating: 0x44, count: 32)))\nprivate_key="
      ),
      fixture.golden.replacingOccurrences(
        of: "allowed_ip=0.0.0.0/0\n",
        with: "allowed_ip=0.0.0.0/0\nallowed_ip=0.0.0.0/0\n"
      ),
    ] {
      XCTAssertThrowsError(try fixture.parse(duplicate)) {
        XCTAssertEqual($0 as? StageBAWGUAPIParserError, .duplicateField)
      }
    }
  }

  func testRejectsMissingUnknownMalformedHexAndDecimalFields() throws {
    let fixture = ParserFixture()
    let cases: [(String, StageBAWGUAPIParserError)] = [
      (
        fixture.golden.replacingOccurrences(
          of: "rx_bytes=712\n",
          with: ""
        ),
        .missingField
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "rx_bytes=712\n",
          with: "mystery=712\n"
        ),
        .unknownField
      ),
      (
        fixture.golden.replacingOccurrences(
          of: fixture.hex(fixture.peerKey),
          with: String(repeating: "A", count: 64)
        ),
        .invalidHex
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "tx_bytes=356",
          with: "tx_bytes=-1"
        ),
        .invalidDecimal
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "tx_bytes=356",
          with: "tx_bytes=0356"
        ),
        .invalidDecimal
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "tx_bytes=356",
          with: "tx_bytes=18446744073709551616"
        ),
        .invalidDecimal
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "protocol_version=1",
          with: "protocol_version=2"
        ),
        .invalidProtocolVersion
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "persistent_keepalive_interval=25\n",
          with: ""
        ),
        .missingField
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "preshared_key=\(fixture.hex([UInt8](repeating: 0, count: 32)))\n",
          with: ""
        ),
        .missingField
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "endpoint=192.0.2.10:51820",
          with: "endpoint=example.com:51820"
        ),
        .malformedLine
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "allowed_ip=0.0.0.0/0",
          with: "allowed_ip=10.0.0.0/33"
        ),
        .invalidDecimal
      ),
      (
        "i６=valid\n" + fixture.golden,
        .unknownField
      ),
      (
        "i6=valid\n" + fixture.golden,
        .unknownField
      ),
      (
        fixture.golden.replacingOccurrences(
          of:
            "private_key=\(fixture.hex([UInt8](repeating: 0x44, count: 32)))\n",
          with: ""
        ),
        .missingField
      ),
      (
        fixture.golden.replacingOccurrences(
          of: fixture.hex([UInt8](repeating: 0x44, count: 32)),
          with: fixture.hex([UInt8](repeating: 0, count: 32))
        ),
        .invalidHex
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "listen_port=51820",
          with: "listen_port=0"
        ),
        .invalidDecimal
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "endpoint=192.0.2.10:51820",
          with: "endpoint=[2001:db8::10]51820"
        ),
        .malformedLine
      ),
      (
        fixture.golden.replacingOccurrences(
          of: "endpoint=192.0.2.10:51820",
          with: "endpoint=192.0.2.10:0"
        ),
        .malformedLine
      ),
    ]

    for (input, expectedError) in cases {
      XCTAssertThrowsError(try fixture.parse(input)) {
        XCTAssertEqual($0 as? StageBAWGUAPIParserError, expectedError)
      }
    }
  }

  func testRejectsInvalidNanosecondsAndMillisecondOverflow() throws {
    let fixture = ParserFixture()
    XCTAssertThrowsError(
      try fixture.parse(
        fixture.golden.replacingOccurrences(
          of: "last_handshake_time_nsec=123456789",
          with: "last_handshake_time_nsec=1000000000"
        )
      )
    ) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .invalidDecimal)
    }

    XCTAssertThrowsError(
      try fixture.parse(
        fixture.golden.replacingOccurrences(
          of: "last_handshake_time_sec=1900000000",
          with: "last_handshake_time_sec=0"
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBAWGUAPIParserError,
        .invalidHandshakeNanoseconds
      )
    }

    XCTAssertThrowsError(
      try fixture.parse(
        fixture.golden.replacingOccurrences(
          of: "last_handshake_time_sec=1900000000",
          with: "last_handshake_time_sec=18446744073709552"
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBAWGUAPIParserError,
        .handshakeMillisecondsOverflow
      )
    }
  }

  func testPeerSnapshotDerivesMillisecondsAndRejectsOverflow() throws {
    let peer = try StageBAWGPeerSnapshot(
      peerPublicKeySHA256: [UInt8](repeating: 1, count: 32),
      latestHandshakeUnixSeconds: 12,
      latestHandshakeNanoseconds: 345_678_901,
      receivedBytes: 1,
      transmittedBytes: 2
    )
    XCTAssertEqual(peer.latestHandshakeUnixMilliseconds, 12_345)

    XCTAssertThrowsError(
      try StageBAWGPeerSnapshot(
        peerPublicKeySHA256: [UInt8](repeating: 1, count: 32),
        latestHandshakeUnixSeconds: UInt64.max / 1_000 + 1,
        receivedBytes: 1,
        transmittedBytes: 2
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidAWGSnapshot
      )
    }
  }

  func testRejectsTooManyLinesTooLongLinesAndTooManyAllowedIPs()
    throws
  {
    let fixture = ParserFixture()
    let tooManyLines =
      (0...StageBAWGUAPIParser.maximumLines)
      .map { "i\($0 + 1)=1" }
      .joined(separator: "\n") + "\n"
    XCTAssertThrowsError(try fixture.parse(tooManyLines)) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .tooManyLines)
    }

    let longLine =
      "h1=" + String(repeating: "a", count: StageBAWGUAPIParser.maximumLineBytes)
      + "\n"
    XCTAssertThrowsError(try fixture.parse(longLine)) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .lineTooLong)
    }

    let allowed = (0...StageBAWGUAPIParser.maximumAllowedIPs)
      .map { "allowed_ip=10.0.\($0).0/24" }
      .joined(separator: "\n")
    let tooManyAllowed = fixture.golden.replacingOccurrences(
      of: "allowed_ip=0.0.0.0/0",
      with: allowed
    )
    XCTAssertThrowsError(try fixture.parse(tooManyAllowed)) {
      XCTAssertEqual($0 as? StageBAWGUAPIParserError, .tooManyLines)
    }
  }
}

private struct ParserFixture {
  let peerKey = [UInt8](repeating: 0x22, count: 32)
  var golden: String {
    """
    private_key=\(hex([UInt8](repeating: 0x44, count: 32)))
    listen_port=51820
    \(peerBlock(key: peerKey))
    """ + "\n"
  }

  func peerBlock(key: [UInt8]) -> String {
    """
    public_key=\(hex(key))
    preshared_key=\(hex([UInt8](repeating: 0, count: 32)))
    protocol_version=1
    endpoint=192.0.2.10:51820
    last_handshake_time_sec=1900000000
    last_handshake_time_nsec=123456789
    tx_bytes=356
    rx_bytes=712
    persistent_keepalive_interval=25
    allowed_ip=0.0.0.0/0
    """
  }

  func parse(_ input: String) throws -> StageBAWGPeerSnapshot {
    try parseBytes(Array(input.utf8))
  }

  func parseBytes(_ input: [UInt8]) throws -> StageBAWGPeerSnapshot {
    try StageBAWGUAPIParser.parsePeer(
      input,
      expectedPeerPublicKey: peerKey
    )
  }

  func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }
}

private func parserUUID(_ fill: UInt8) -> [UInt8] {
  var bytes = [UInt8](repeating: fill, count: 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  return bytes
}
