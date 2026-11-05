import CryptoKit
import Foundation
import XCTest

@testable import WinnStageBProviderCore
import WinnPrivacyCore

// MARK: - Hand-fixed wire vectors
//
// Every byte below was derived from the wire table in `StageBMessageCodec`
// by an independent reference implementation (scratch `goldenspec.py`), not
// by running the Swift encoder. `handAssemble` is a second, test-local
// implementation of the same layout. A golden vector produced by the encoder
// under test would prove nothing about encoding stability, so none of these
// values touch the production writer.

private enum Vector {
  static let attemptNonce: [UInt8] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
  ]
  static let pathID: [UInt8] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x4A, 0xA7,
    0x8B, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
  ]
  static let bindingDigest = ramp(from: 0x01, count: 32)
  static let challenge = ramp(from: 0x41, count: 32)
  static let t0: UInt64 = 1_000_000_000_000
  static let deadline: UInt64 = 1_003_000_000_000
  static let tData: UInt64 = 1_002_500_000_000

  static let dnsAddress: [UInt8] = [100, 64, 0, 53]
  static let dnsPort: UInt16 = 53
  static let dnsQuery = ramp(from: 0xD0, count: 24)
  static let dnsSentDigest = ramp(from: 0x51, count: 32)
  static let dnsResponse = ramp(from: 0x90, count: 48)

  static let reflectorAddress: [UInt8] = [100, 64, 0, 7]
  static let reflectorPort: UInt16 = 51_821
  static let reflectorRequest = ramp(from: 0x21, count: 64)
  static let reflectorSentDigest = ramp(from: 0x71, count: 32)
  static let reflectorResponse = ramp(from: 0x80, count: 80)

  /// Pinned chain field of each message, in transcript order. Index 0 is the
  /// attempt challenge; every later entry is
  /// `SHA-256("winn-stageb-hostprovider-wire/1\0" || previous message)`.
  static let chains: [[UInt8]] = [
    challenge,
    hex("a9d5ae5b1129a2aa6053fa977c06867ddbe9f0e271d66f498517f1c6365f8cd4"),
    hex("69728317d8495e2ba8c500fd2a11e1d905b1043b0b2e1aeed3aa7203b86fb74b"),
    hex("c21e382b1779547072e088f22531e71ae4ea4b80fde47587c7fa270ac513a06f"),
    hex("281d35ab020dd44ff31e45a0868e48e6926b354aef3624613ea1ca8ea5d45fd4"),
    hex("f8204a15574b97bbd16b17a8d60de13d35f0a39938f74f72ba9252d0a9032736"),
    hex("77e2706156d89bae7dd9d37e82fd7e3b3169b4b1c3637db63af7e9d41cd5e3d3"),
    hex("43595b48822bf3b23332646ee7ef6bfb922b9768e2624285ce4748fc381693f0"),
    hex("a058329ee770535613b6128093d1753936bbdc5a505434a5b40f585301f94628"),
    hex("ef6fef60165c5a555df61c62a2ff01979a554874f1f12f622b4afc559560ed08"),
    hex("b0ac9953404f0e68af03412dfa70f7c06c34a8654ff4ad3d54f5396a07338114"),
    hex("309b389e40f25595371827f724fcb25addefae6ca23e40e596584898058e5477"),
  ]

  /// The complete first message, pinned byte for byte.
  static let message1Hex =
    "5748503301010000"
    + "77696e6e2f33"
    + "112233445566478899aabbccddeeff00"
    + "a0a1a2a3a4a54aa78ba9aaabacadaeaf"
    + "0102030405060708090a0b0c0d0e0f10"
    + "1112131415161718191a1b1c1d1e1f20"
    + "0000000000000001"
    + "000000e8d4a51000"
    + "000000e987756e00"
    + "4142434445464748494a4b4c4d4e4f50"
    + "5152535455565758595a5b5c5d5e5f60"
    + "0000"
    + "0000"

  static let transcriptSHA256 =
    "f6829db74d402c90a3f433f8bf864ab6b9bca962f389b3ade8f0b88fa954a255"

  static let bindingHelperDigest =
    "b3f92f14a6dfbdf305554f6dd0cded1afd58164c7fa53bf401054f0148bde8bd"

  static func ramp(from start: UInt8, count: Int) -> [UInt8] {
    (0 ..< count).map { UInt8((Int(start) + $0) & 0xFF) }
  }

  static func hex(_ text: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var iterator = text.makeIterator()
    while let high = iterator.next(), let low = iterator.next() {
      bytes.append(UInt8(String([high, low]), radix: 16)!)
    }
    return bytes
  }

  static func be64(_ value: UInt64) -> [UInt8] {
    (0 ..< 8).map { UInt8((value >> UInt64(56 - $0 * 8)) & 0xFF) }
  }

  static func be16(_ value: UInt16) -> [UInt8] {
    [UInt8(value >> 8), UInt8(value & 0xFF)]
  }

  static func endpointBytes(
    family: UInt8,
    address: [UInt8],
    port: UInt16
  ) -> [UInt8] {
    var slot = [UInt8](repeating: 0, count: 16)
    slot.replaceSubrange(0 ..< address.count, with: address)
    return [family] + slot + be16(port)
  }

  static let dnsEndpointBytes = endpointBytes(
    family: 4,
    address: dnsAddress,
    port: dnsPort
  )

  static let reflectorEndpointBytes = endpointBytes(
    family: 4,
    address: reflectorAddress,
    port: reflectorPort
  )

  static let terminalPayload: [UInt8] =
    [1, 0, 0, 0] + be64(tData) + [1, 1, 1, 1]

  /// Second, test-local implementation of the fixed wire layout.
  static func handAssemble(
    kind: UInt8,
    sequence: UInt64,
    chain: [UInt8],
    payload: [UInt8],
    attemptNonce: [UInt8] = Vector.attemptNonce,
    pathID: [UInt8] = Vector.pathID,
    bindingDigest: [UInt8] = Vector.bindingDigest,
    t0: UInt64 = Vector.t0,
    deadline: UInt64 = Vector.deadline
  ) -> [UInt8] {
    var message: [UInt8] = []
    message += Array("WHP3".utf8)
    message += [1, kind]
    message += [0, 0]
    message += Array("winn/3".utf8)
    message += attemptNonce
    message += pathID
    message += bindingDigest
    message += be64(sequence)
    message += be64(t0)
    message += be64(deadline)
    message += chain
    message += be16(UInt16(payload.count))
    message += [0, 0]
    precondition(message.count == 138)
    return message + payload
  }

  /// The full twelve-message success transcript, hand-assembled.
  static let goldenTranscript: [[UInt8]] = {
    let payloads: [[UInt8]] = [
      [],
      dnsEndpointBytes + dnsQuery,
      dnsSentDigest,
      [],
      dnsResponse,
      [],
      [],
      reflectorEndpointBytes + reflectorRequest,
      reflectorSentDigest,
      [],
      reflectorResponse,
      terminalPayload,
    ]
    return (0 ..< 12).map { index in
      handAssemble(
        kind: UInt8(index + 1),
        sequence: UInt64(index + 1),
        chain: chains[index],
        payload: payloads[index]
      )
    }
  }()
}

// MARK: - Tests

final class StageBMessageCodecTests: XCTestCase {
  private func makeBinding() throws -> StageBMessageAttemptBinding {
    try StageBMessageAttemptBinding(
      attemptNonce: Vector.attemptNonce,
      pathID: Vector.pathID,
      bindingSHA256: Vector.bindingDigest,
      challenge: Vector.challenge,
      requestedAtMonotonicNanoseconds: Vector.t0
    )
  }

  private func makePair() throws -> (
    host: StageBHostMessageTranscript,
    provider: StageBProviderMessageTranscript
  ) {
    let binding = try makeBinding()
    return (
      StageBHostMessageTranscript(binding: binding),
      StageBProviderMessageTranscript(binding: binding)
    )
  }

  private func dnsEndpoint() throws -> StageBPrivateEndpoint {
    try StageBPrivateEndpoint(
      family: .ipv4,
      address: Vector.dnsAddress,
      port: Vector.dnsPort
    )
  }

  private func reflectorEndpoint() throws -> StageBPrivateEndpoint {
    try StageBPrivateEndpoint(
      family: .ipv4,
      address: Vector.reflectorAddress,
      port: Vector.reflectorPort
    )
  }

  private func successReport() throws -> StageBTerminalReport {
    try StageBTerminalReport(
      outcome: .success,
      failureCode: 0,
      dataCompleteMonotonicNanoseconds: Vector.tData,
      freshAWGHandshake: true,
      authenticatedTunnelBytes: true,
      protectedDNSResponse: true,
      authenticatedReflectorResponse: true
    )
  }

  /// Runs the real transcript for the first `steps` messages, asserting that
  /// each encode reproduces the hand-fixed golden bytes exactly and that the
  /// peer accepts them. Returns both transcripts positioned at `steps + 1`.
  @discardableResult
  private func drive(
    steps: Int,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws -> (
    host: StageBHostMessageTranscript,
    provider: StageBProviderMessageTranscript,
    decoded: [StageBMessage]
  ) {
    let pair = try makePair()
    var decoded: [StageBMessage] = []
    for step in 0 ..< steps {
      let golden = Vector.goldenTranscript[step]
      let produced: [UInt8]
      switch step {
      case 0: produced = try pair.host.encodePrepareDNSRequest()
      case 1:
        produced = try pair.provider.encodePrepareDNSReply(
          endpoint: try dnsEndpoint(),
          query: Vector.dnsQuery
        )
      case 2:
        produced = try pair.host.encodeDNSSent(
          requestDatagramSHA256: Vector.dnsSentDigest
        )
      case 3: produced = try pair.provider.encodeDNSSentAck()
      case 4:
        produced = try pair.host.encodeDNSResponse(Vector.dnsResponse)
      case 5: produced = try pair.provider.encodeDNSResponseAck()
      case 6:
        produced = try pair.host.encodePrepareReflectorRequest()
      case 7:
        produced = try pair.provider.encodePrepareReflectorReply(
          endpoint: try reflectorEndpoint(),
          requestDatagram: Vector.reflectorRequest
        )
      case 8:
        produced = try pair.host.encodeReflectorSent(
          requestDatagramSHA256: Vector.reflectorSentDigest
        )
      case 9: produced = try pair.provider.encodeReflectorSentAck()
      case 10:
        produced = try pair.host.encodeReflectorResponse(
          Vector.reflectorResponse
        )
      case 11:
        produced = try pair.provider.encodeTerminalResponse(
          try successReport()
        )
      default: fatalError("unreachable step")
      }
      XCTAssertEqual(
        produced,
        golden,
        "encoded bytes drifted at step \(step + 1)",
        file: file,
        line: line
      )
      // The peer accepts the hand-fixed golden bytes, not the produced ones.
      if step.isMultiple(of: 2) {
        decoded.append(try pair.provider.decode(golden))
      } else {
        decoded.append(try pair.host.decode(golden))
      }
    }
    return (pair.host, pair.provider, decoded)
  }

  // MARK: Golden vectors

  func testMessageOneMatchesThePinnedByteString() throws {
    XCTAssertEqual(
      Vector.goldenTranscript[0],
      Vector.hex(Vector.message1Hex),
      "hand-assembled message 1 drifted from the pinned literal"
    )
    XCTAssertEqual(Vector.goldenTranscript[0].count, 138)

    let pair = try makePair()
    XCTAssertEqual(
      try pair.host.encodePrepareDNSRequest(),
      Vector.hex(Vector.message1Hex)
    )
  }

  func testEveryEncodedMessageMatchesItsHandFixedGoldenVector() throws {
    try drive(steps: 12)
  }

  func testConcatenatedTranscriptMatchesThePinnedDigest() throws {
    let flattened = Vector.goldenTranscript.flatMap { $0 }
    XCTAssertEqual(flattened.count, 1_990)
    XCTAssertEqual(
      Array(SHA256.hash(data: Data(flattened))),
      Vector.hex(Vector.transcriptSHA256),
      "the hand-fixed transcript itself drifted"
    )
  }

  func testGoldenMessageLengthsAreExactlyHeaderPlusPayload() {
    let expected = [138, 181, 170, 138, 186, 138, 138, 221, 170, 138, 218, 154]
    XCTAssertEqual(Vector.goldenTranscript.map(\.count), expected)
  }

  func testDecodingTheGoldenTranscriptYieldsExactExpectedValues() throws {
    let run = try drive(steps: 12)
    let decoded = run.decoded

    XCTAssertEqual(decoded.map(\.kind), StageBMessageKind.allCases)
    XCTAssertEqual(decoded.map(\.sequence), (1 ... 12).map(UInt64.init))
    XCTAssertEqual(decoded.map(\.chain), Vector.chains)

    XCTAssertEqual(decoded[0].body, .empty)
    XCTAssertEqual(
      decoded[1].body,
      .dnsPrepare(endpoint: try dnsEndpoint(), query: Vector.dnsQuery)
    )
    XCTAssertEqual(
      decoded[2].body,
      .sendAcknowledgement(datagramSHA256: Vector.dnsSentDigest)
    )
    XCTAssertEqual(decoded[3].body, .empty)
    XCTAssertEqual(decoded[4].body, .datagram(Vector.dnsResponse))
    XCTAssertEqual(decoded[5].body, .empty)
    XCTAssertEqual(decoded[6].body, .empty)
    XCTAssertEqual(
      decoded[7].body,
      .reflectorPrepare(
        endpoint: try reflectorEndpoint(),
        requestDatagram: Vector.reflectorRequest
      )
    )
    XCTAssertEqual(
      decoded[8].body,
      .sendAcknowledgement(datagramSHA256: Vector.reflectorSentDigest)
    )
    XCTAssertEqual(decoded[9].body, .empty)
    XCTAssertEqual(decoded[10].body, .datagram(Vector.reflectorResponse))
    XCTAssertEqual(decoded[11].body, .terminal(try successReport()))

    XCTAssertEqual(run.host.phase, .terminated)
    XCTAssertEqual(run.provider.phase, .terminated)
  }

  func testChainFieldIsTheIndependentlyRecomputedPredecessorDigest() {
    let domain = Array("winn-stageb-hostprovider-wire/1".utf8) + [0]
    for index in 1 ..< 12 {
      var hasher = SHA256()
      hasher.update(data: Data(domain))
      hasher.update(data: Data(Vector.goldenTranscript[index - 1]))
      XCTAssertEqual(
        Vector.chains[index],
        Array(hasher.finalize()),
        "chain link \(index) is not the digest of its predecessor"
      )
    }
    XCTAssertEqual(Vector.chains[0], Vector.challenge)
  }

  func testBindingDigestHelperMatchesThePinnedVector() throws {
    let identity = try StageBAWGEnginePathIdentity(
      signedRuntimeArtifactSHA256: Vector.ramp(from: 0xB0, count: 32),
      wgTurnOnConfigSHA256: Vector.ramp(from: 0xC0, count: 32),
      expectedPeerPublicKeySHA256: Vector.ramp(from: 0xD0, count: 32),
      engineInstanceNonce: [
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x40, 0x81,
        0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29,
      ],
      engineGeneration: 7,
      pathGeneration: 11,
      winningInterfaceTokenSHA256: Vector.ramp(from: 0xE0, count: 32)
    )
    let context = try WCF3ConnectionContext(
      sessionID: [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x43, 0x38,
        0xA9, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x30,
      ],
      bindingID: [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x45, 0x58,
        0xBA, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x50,
      ],
      pskGeneration: 3,
      sequenceEpoch: 5
    )
    let binding = try StageBProviderPathBinding(
      pathID: Vector.pathID,
      identity: identity,
      context: context
    )
    XCTAssertEqual(
      StageBMessageCodec.bindingDigest(for: binding),
      Vector.hex(Vector.bindingHelperDigest)
    )

    // A single changed generation must change the digest.
    let rotated = try StageBProviderPathBinding(
      pathID: Vector.pathID,
      identity: try StageBAWGEnginePathIdentity(
        signedRuntimeArtifactSHA256: Vector.ramp(from: 0xB0, count: 32),
        wgTurnOnConfigSHA256: Vector.ramp(from: 0xC0, count: 32),
        expectedPeerPublicKeySHA256: Vector.ramp(from: 0xD0, count: 32),
        engineInstanceNonce: [
          0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x40, 0x81,
          0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29,
        ],
        engineGeneration: 7,
        pathGeneration: 12,
        winningInterfaceTokenSHA256: Vector.ramp(from: 0xE0, count: 32)
      ),
      context: context
    )
    XCTAssertNotEqual(
      StageBMessageCodec.bindingDigest(for: rotated),
      Vector.hex(Vector.bindingHelperDigest)
    )
  }

  // MARK: Mutation helpers

  /// Decodes `mutated` at transcript position `step` (1-based) and requires
  /// exactly `expected`.
  private func expectRejection(
    step: Int,
    mutate: ([UInt8]) -> [UInt8],
    _ expected: StageBMessageCodecError,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let pair = try drive(steps: step - 1)
    let mutated = mutate(Vector.goldenTranscript[step - 1])
    let decodeIt: ([UInt8]) throws -> StageBMessage =
      step.isMultiple(of: 2) ? pair.host.decode : pair.provider.decode
    XCTAssertThrowsError(try decodeIt(mutated), file: file, line: line) {
      XCTAssertEqual(
        $0 as? StageBMessageCodecError,
        expected,
        file: file,
        line: line
      )
    }
    // Any rejection is terminal for the channel.
    XCTAssertThrowsError(
      try decodeIt(Vector.goldenTranscript[step - 1]),
      file: file,
      line: line
    ) {
      XCTAssertEqual(
        $0 as? StageBMessageCodecError,
        .terminated,
        file: file,
        line: line
      )
    }
  }

  private func flip(_ bytes: [UInt8], at offset: Int) -> [UInt8] {
    var copy = bytes
    copy[offset] ^= 0x01
    return copy
  }

  private func set(
    _ bytes: [UInt8],
    at offset: Int,
    to value: UInt8
  ) -> [UInt8] {
    var copy = bytes
    copy[offset] = value
    return copy
  }

  private func replace(
    _ bytes: [UInt8],
    at offset: Int,
    with slice: [UInt8]
  ) -> [UInt8] {
    var copy = bytes
    copy.replaceSubrange(offset ..< offset + slice.count, with: slice)
    return copy
  }

  // MARK: Header field mutations

  func testMagicMutationIsRejectedAsInvalidMagic() throws {
    for offset in 0 ..< 4 {
      try expectRejection(
        step: 1,
        mutate: { self.flip($0, at: offset) },
        .invalidMagic
      )
    }
  }

  func testUnknownWireVersionFailsClosed() throws {
    for version: UInt8 in [0, 2, 0xFF] {
      try expectRejection(
        step: 1,
        mutate: { self.set($0, at: 4, to: version) },
        .unsupportedVersion
      )
    }
  }

  func testUnassignedKindByteFailsClosed() throws {
    for kind: UInt8 in [0, 13, 0xFF] {
      try expectRejection(
        step: 1,
        mutate: { self.set($0, at: 5, to: kind) },
        .unknownKind
      )
    }
  }

  func testEveryReservedByteMustBeZeroOnDecode() throws {
    for offset in [6, 7, 136, 137] {
      try expectRejection(
        step: 1,
        mutate: { self.set($0, at: offset, to: 0x01) },
        .nonzeroReserved
      )
    }
  }

  func testProtocolTagMutationIsRejected() throws {
    for offset in 8 ..< 14 {
      try expectRejection(
        step: 1,
        mutate: { self.flip($0, at: offset) },
        .invalidProtocol
      )
    }
  }

  func testAttemptNonceMutationIsRejectedAsAttemptMismatch() throws {
    for offset in [14, 21, 29] {
      try expectRejection(
        step: 1,
        mutate: { self.flip($0, at: offset) },
        .attemptMismatch
      )
    }
  }

  func testPathIDMutationIsRejectedAsPathMismatch() throws {
    for offset in [30, 37, 45] {
      try expectRejection(
        step: 1,
        mutate: { self.flip($0, at: offset) },
        .pathMismatch
      )
    }
  }

  func testBindingDigestMutationIsRejectedAsBindingMismatch() throws {
    for offset in [46, 60, 77] {
      try expectRejection(
        step: 1,
        mutate: { self.flip($0, at: offset) },
        .bindingMismatch
      )
    }
  }

  func testT0AndDeadlineMutationsAreRejectedAsDeadlineMismatch() throws {
    for offset in [86, 93, 94, 101] {
      try expectRejection(
        step: 1,
        mutate: { self.flip($0, at: offset) },
        .deadlineMismatch
      )
    }
  }

  func testChainDigestMutationIsRejectedAsChainMismatch() throws {
    for offset in [102, 118, 133] {
      try expectRejection(
        step: 5,
        mutate: { self.flip($0, at: offset) },
        .chainMismatch
      )
    }
  }

  func testChainOfADifferentAttemptChallengeIsRejected() throws {
    let pair = try makePair()
    let foreign = Vector.handAssemble(
      kind: 1,
      sequence: 1,
      chain: Vector.ramp(from: 0x61, count: 32),
      payload: []
    )
    XCTAssertThrowsError(try pair.provider.decode(foreign)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .chainMismatch)
    }
  }

  // MARK: Sequence mutations

  func testStaleSequenceIsRejectedForItsOwnReason() throws {
    // Message 5 is the kind this phase expects, so the ordering check passes
    // and the sequence check is what rejects the rewind.
    for stale: UInt64 in [1, 3, 4] {
      try expectRejection(
        step: 5,
        mutate: { self.replace($0, at: 78, with: Vector.be64(stale)) },
        .staleSequence
      )
    }
  }

  func testForwardSequenceGapIsRejected() throws {
    for ahead: UInt64 in [6, 7, 12] {
      try expectRejection(
        step: 5,
        mutate: { self.replace($0, at: 78, with: Vector.be64(ahead)) },
        .sequenceGap
      )
    }
  }

  func testSequenceOutsideTheFixedTranscriptRangeIsRejected() throws {
    for bad: UInt64 in [0, 13, UInt64.max] {
      try expectRejection(
        step: 5,
        mutate: { self.replace($0, at: 78, with: Vector.be64(bad)) },
        .sequenceOutOfRange
      )
    }
  }

  // MARK: Length and bound mutations

  func testTruncatedInputIsRejectedBeforeAnyFieldIsRead() throws {
    try expectRejection(
      step: 1,
      mutate: { Array($0.dropLast()) },
      .truncated
    )
    try expectRejection(
      step: 1,
      mutate: { _ in [] },
      .truncated
    )
  }

  func testTrailingBytesAreRejectedRatherThanIgnored() throws {
    try expectRejection(
      step: 5,
      mutate: { $0 + [0x00] },
      .lengthMismatch
    )
    try expectRejection(
      step: 5,
      mutate: { $0 + Vector.ramp(from: 0x01, count: 16) },
      .lengthMismatch
    )
  }

  func testDeclaredPayloadLengthMustMatchTheActualLength() throws {
    // Message 5 carries 48 bytes; both a longer and a shorter claim fail.
    try expectRejection(
      step: 5,
      mutate: { self.replace($0, at: 134, with: Vector.be16(49)) },
      .lengthMismatch
    )
    try expectRejection(
      step: 5,
      mutate: { self.replace($0, at: 134, with: Vector.be16(47)) },
      .lengthMismatch
    )
  }

  func testEmptyKindRejectsAnyDeclaredPayload() throws {
    try expectRejection(
      step: 1,
      mutate: { self.replace($0, at: 134, with: Vector.be16(1)) + [0xAA] },
      .payloadTooLarge
    )
  }

  func testOversizedInputIsRejectedInsteadOfAcceptingItsValidPrefix() throws {
    // The first 186 bytes are exactly the valid golden message 5.
    let padded =
      Vector.goldenTranscript[4]
      + [UInt8](repeating: 0x00, count: 4_096)
    XCTAssertEqual(padded.count, 4_282)
    XCTAssertGreaterThan(
      padded.count,
      StageBMessageCodec.maximumMessageBytes
    )
    try expectRejection(step: 5, mutate: { _ in padded }, .messageTooLarge)

    // One byte over the global bound is already too large.
    let justOver = [UInt8](
      repeating: 0x00,
      count: StageBMessageCodec.maximumMessageBytes + 1
    )
    try expectRejection(step: 5, mutate: { _ in justOver }, .messageTooLarge)
  }

  func testDataDecodeBoundsInputBeforeCopying() throws {
    let pair = try makePair()
    let huge = Data(count: 1_048_576)
    XCTAssertThrowsError(try pair.provider.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .messageTooLarge)
    }
    XCTAssertEqual(pair.provider.phase, .terminated)
    XCTAssertThrowsError(
      try pair.provider.decode(Vector.goldenTranscript[0])
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }
  }

  func testPerKindMaximumIsEnforcedBelowTheGlobalMaximum() throws {
    // A reflector response is capped at 512 even though the frame could carry
    // 1024, so the per-kind bound is not shadowed by the global one.
    XCTAssertEqual(StageBMessageCodec.maximumReflectorResponseBytes, 512)
    XCTAssertEqual(StageBMessageCodec.maximumPayloadBytes, 1_024)
    XCTAssertEqual(StageBMessageCodec.maximumMessageBytes, 138 + 1_024)

    let pair = try drive(steps: 10)
    let oversize = Vector.handAssemble(
      kind: 11,
      sequence: 11,
      chain: Vector.chains[10],
      payload: [UInt8](repeating: 0x5A, count: 513)
    )
    XCTAssertLessThan(
      oversize.count,
      StageBMessageCodec.maximumMessageBytes
    )
    XCTAssertThrowsError(try pair.provider.decode(oversize)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .payloadTooLarge)
    }
  }

  func testEncoderRefusesOversizedBodies() throws {
    var pair = try drive(steps: 4)
    XCTAssertThrowsError(
      try pair.host.encodeDNSResponse(
        [UInt8](repeating: 0x11, count: 1_025)
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .payloadTooLarge)
    }

    pair = try drive(steps: 10)
    XCTAssertThrowsError(
      try pair.host.encodeReflectorResponse(
        [UInt8](repeating: 0x11, count: 513)
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .payloadTooLarge)
    }

    pair = try drive(steps: 1)
    XCTAssertThrowsError(
      try pair.provider.encodePrepareDNSReply(
        endpoint: try dnsEndpoint(),
        query: [UInt8](repeating: 0x22, count: 513)
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .payloadTooLarge)
    }

    pair = try drive(steps: 7)
    XCTAssertThrowsError(
      try pair.provider.encodePrepareReflectorReply(
        endpoint: try reflectorEndpoint(),
        requestDatagram: [UInt8](repeating: 0x33, count: 513)
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .payloadTooLarge)
    }
  }

  func testMaximumSizedBodiesAtTheExactBoundAreAccepted() throws {
    let pair = try drive(steps: 4)
    let maximal = [UInt8](repeating: 0x77, count: 1_024)
    let encoded = try pair.host.encodeDNSResponse(maximal)
    XCTAssertEqual(encoded.count, StageBMessageCodec.maximumMessageBytes)
    let decoded = try pair.provider.decode(encoded)
    XCTAssertEqual(decoded.body, .datagram(maximal))
  }

  func testEmptyDatagramBodiesAreRejected() throws {
    let pair = try drive(steps: 4)
    XCTAssertThrowsError(try pair.host.encodeDNSResponse([])) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .payloadTooSmall)
    }
    try expectRejection(
      step: 5,
      mutate: { message in
        self.replace(
          Array(message.prefix(138)),
          at: 134,
          with: Vector.be16(0)
        )
      },
      .payloadTooSmall
    )
  }

  // MARK: Payload mutations

  func testEndpointFamilyMutationIsRejected() throws {
    for family: UInt8 in [0, 5, 16, 0xFF] {
      try expectRejection(
        step: 2,
        mutate: { self.set($0, at: 138, to: family) },
        .invalidEndpoint
      )
    }
  }

  func testUnusedAddressSlotBytesMustBeZero() throws {
    // IPv4 uses 4 of the 16 address bytes; the other 12 are reserved zero.
    for offset in [143, 149, 154] {
      try expectRejection(
        step: 2,
        mutate: { self.set($0, at: offset, to: 0x01) },
        .nonzeroReserved
      )
    }
  }

  func testEndpointPortZeroIsRejected() throws {
    try expectRejection(
      step: 2,
      mutate: { self.replace($0, at: 155, with: Vector.be16(0)) },
      .invalidEndpoint
    )
  }

  func testStructurallyImpossibleEndpointAddressesAreRejected() throws {
    let cases: [[UInt8]] = [
      [0, 0, 0, 0],
      [0, 1, 2, 3],
      [127, 0, 0, 1],
      [224, 0, 0, 251],
      [239, 255, 255, 250],
      [255, 255, 255, 255],
    ]
    for address in cases {
      try expectRejection(
        step: 2,
        mutate: { self.replace($0, at: 139, with: address) },
        .invalidEndpoint
      )
      XCTAssertThrowsError(
        try StageBPrivateEndpoint(
          family: .ipv4,
          address: address,
          port: 53
        )
      ) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .invalidEndpoint)
      }
    }
  }

  func testIPv6EndpointRoundTripsAndRejectsMulticastAndLoopback() throws {
    let unicast = try StageBPrivateEndpoint(
      family: .ipv6,
      address: Vector.ramp(from: 0xFD, count: 1)
        + Vector.ramp(from: 0x01, count: 15),
      port: 5_353
    )
    let pair = try drive(steps: 1)
    let encoded = try pair.provider.encodePrepareDNSReply(
      endpoint: unicast,
      query: Vector.dnsQuery
    )
    XCTAssertEqual(encoded[138], 6)
    let decoded = try pair.host.decode(encoded)
    XCTAssertEqual(
      decoded.body,
      .dnsPrepare(endpoint: unicast, query: Vector.dnsQuery)
    )

    for address in [
      [UInt8](repeating: 0xFF, count: 16),
      [UInt8](repeating: 0, count: 15) + [1],
      [UInt8](repeating: 0, count: 16),
    ] {
      XCTAssertThrowsError(
        try StageBPrivateEndpoint(
          family: .ipv6,
          address: address,
          port: 5_353
        )
      ) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .invalidEndpoint)
      }
    }
  }

  func testPrepareReplyWithoutAnyQueryBytesIsRejected() throws {
    try expectRejection(
      step: 2,
      mutate: { message in
        self.replace(
          Array(message.prefix(138)) + Vector.dnsEndpointBytes,
          at: 134,
          with: Vector.be16(19)
        )
      },
      .payloadTooSmall
    )
  }

  func testAllZeroSendAcknowledgementDigestIsRejected() throws {
    try expectRejection(
      step: 3,
      mutate: { message in
        self.replace(
          message,
          at: 138,
          with: [UInt8](repeating: 0, count: 32)
        )
      },
      .invalidDigest
    )
    let pair = try drive(steps: 2)
    XCTAssertThrowsError(
      try pair.host.encodeDNSSent(
        requestDatagramSHA256: [UInt8](repeating: 0, count: 32)
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidDigest)
    }
  }

  func testSendAcknowledgementLengthIsExactlyThirtyTwo() throws {
    try expectRejection(
      step: 3,
      mutate: { message in
        self.replace(
          Array(message.prefix(169)),
          at: 134,
          with: Vector.be16(31)
        )
      },
      .payloadTooSmall
    )
    try expectRejection(
      step: 3,
      mutate: { message in
        self.replace(
          message + [0x00],
          at: 134,
          with: Vector.be16(33)
        )
      },
      .payloadTooLarge
    )
  }

  // MARK: Terminal report mutations

  func testTerminalOutcomeByteMustBeAKnownOutcome() throws {
    for outcome: UInt8 in [0, 3, 0xFF] {
      try expectRejection(
        step: 12,
        mutate: { self.set($0, at: 138, to: outcome) },
        .invalidTerminalReport
      )
    }
  }

  func testTerminalReservedBytesMustBeZero() throws {
    for offset in [140, 141] {
      try expectRejection(
        step: 12,
        mutate: { self.set($0, at: offset, to: 0x01) },
        .nonzeroReserved
      )
    }
  }

  func testTerminalPredicateBytesAreStrictlyZeroOrOne() throws {
    for offset in 150 ..< 154 {
      // 2 is neither true nor false on this wire.
      try expectRejection(
        step: 12,
        mutate: { self.set($0, at: offset, to: 2) },
        .invalidTerminalReport
      )
      // A success report with a cleared predicate is self-contradictory.
      try expectRejection(
        step: 12,
        mutate: { self.set($0, at: offset, to: 0) },
        .invalidTerminalReport
      )
    }
  }

  /// A failure report may legitimately carry false predicates, so the
  /// success-consistency rule cannot shadow the wire rule here: only the
  /// strict "0 or 1" byte check can reject this. Without it, byte 2 would be
  /// silently read as `false` and the wire meaning would change on re-encode.
  func testNonBooleanPredicateByteIsRejectedEvenInAFailureReport() throws {
    for offset in 12 ..< 16 {
      var payload: [UInt8] =
        [2, 7, 0, 0] + Vector.be64(Vector.tData) + [0, 0, 0, 0]
      payload[offset] = 2
      let message = Vector.handAssemble(
        kind: 12,
        sequence: 12,
        chain: Vector.chains[11],
        payload: payload
      )
      let pair = try drive(steps: 11)
      XCTAssertThrowsError(
        try pair.host.decode(message),
        "predicate byte \(offset) accepted a non-Boolean value"
      ) {
        XCTAssertEqual(
          $0 as? StageBMessageCodecError,
          .invalidTerminalReport
        )
      }

      // The same report with a real Boolean is accepted, so the rejection
      // above is about the byte value and nothing else.
      payload[offset] = 1
      let legal = Vector.handAssemble(
        kind: 12,
        sequence: 12,
        chain: Vector.chains[11],
        payload: payload
      )
      let other = try drive(steps: 11)
      XCTAssertNoThrow(try other.host.decode(legal))
    }
  }

  func testSuccessMustCarryZeroFailureCodeAndFailureMustCarryNonzero()
    throws
  {
    try expectRejection(
      step: 12,
      mutate: { self.set($0, at: 139, to: 9) },
      .invalidTerminalReport
    )
    // outcome=failure with failureCode=0
    try expectRejection(
      step: 12,
      mutate: { self.set($0, at: 138, to: 2) },
      .invalidTerminalReport
    )
    XCTAssertThrowsError(
      try StageBTerminalReport(
        outcome: .failure,
        failureCode: 0,
        dataCompleteMonotonicNanoseconds: Vector.tData,
        freshAWGHandshake: false,
        authenticatedTunnelBytes: false,
        protectedDNSResponse: false,
        authenticatedReflectorResponse: false
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidTerminalReport)
    }
  }

  func testTerminalTimeBoundariesAreExact() throws {
    // Exactly the deadline is admissible for a success report.
    let atDeadline = Vector.handAssemble(
      kind: 12,
      sequence: 12,
      chain: Vector.chains[11],
      payload: [1, 0, 0, 0] + Vector.be64(Vector.deadline) + [1, 1, 1, 1]
    )
    let accepting = try drive(steps: 11)
    XCTAssertNoThrow(try accepting.host.decode(atDeadline))

    // One nanosecond later is not.
    try expectRejection(
      step: 12,
      mutate: { message in
        self.replace(
          message,
          at: 142,
          with: Vector.be64(Vector.deadline + 1)
        )
      },
      .invalidTerminalReport
    )
    // Before T0 is not.
    try expectRejection(
      step: 12,
      mutate: { message in
        self.replace(message, at: 142, with: Vector.be64(Vector.t0 - 1))
      },
      .invalidTerminalReport
    )
  }

  func testFailureReportMayUseTheBoundedReportingWindowOnly() throws {
    let slack = StageBMessageCodec.terminalSlackNanoseconds
    XCTAssertEqual(slack, 50_000_000)

    let inWindow = Vector.handAssemble(
      kind: 12,
      sequence: 12,
      chain: Vector.chains[11],
      payload: [2, 7, 0, 0]
        + Vector.be64(Vector.deadline + slack) + [1, 1, 1, 0]
    )
    let accepting = try drive(steps: 11)
    let decoded = try accepting.host.decode(inWindow)
    guard case let .terminal(report) = decoded.body else {
      return XCTFail("expected a terminal body")
    }
    XCTAssertEqual(report.outcome, .failure)
    XCTAssertEqual(report.failureCode, 7)
    XCTAssertFalse(report.authenticatedReflectorResponse)

    let past = Vector.handAssemble(
      kind: 12,
      sequence: 12,
      chain: Vector.chains[11],
      payload: [2, 7, 0, 0]
        + Vector.be64(Vector.deadline + slack + 1) + [1, 1, 1, 0]
    )
    let rejecting = try drive(steps: 11)
    XCTAssertThrowsError(try rejecting.host.decode(past)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidTerminalReport)
    }
  }

  // MARK: Ordering

  /// Minimal well-formed payload for each kind, so an ordering rejection can
  /// never be a disguised payload-length rejection.
  private static let minimalPayloads: [[UInt8]] = [
    [],
    Vector.dnsEndpointBytes + [0xAB],
    Vector.ramp(from: 0x01, count: 32),
    [],
    [0xCD],
    [],
    [],
    Vector.reflectorEndpointBytes + [0xEF],
    Vector.ramp(from: 0x02, count: 32),
    [],
    [0x12],
    Vector.terminalPayload,
  ]

  func testEveryPhaseAdmitsExactlyTheKindsItsDirectionAllows() throws {
    for step in 1 ... 12 {
      let providerIsDue = step.isMultiple(of: 2)
      for candidate in StageBMessageKind.allCases {
        let pair = try drive(steps: step - 1)
        let message = Vector.handAssemble(
          kind: candidate.rawValue,
          sequence: UInt64(step),
          chain: Vector.chains[step - 1],
          payload: Self.minimalPayloads[Int(candidate.rawValue) - 1]
        )
        let decodeIt: ([UInt8]) throws -> StageBMessage =
          providerIsDue ? pair.host.decode : pair.provider.decode
        let admissible =
          candidate.rawValue == UInt8(step)
          || (providerIsDue && candidate == .terminalResponse)
        if admissible {
          XCTAssertNoThrow(
            try decodeIt(message),
            "kind \(candidate) should be admissible at step \(step)"
          )
        } else {
          XCTAssertThrowsError(
            try decodeIt(message),
            "kind \(candidate) must not be admissible at step \(step)"
          ) {
            XCTAssertEqual(
              $0 as? StageBMessageCodecError,
              .outOfOrder,
              "kind \(candidate) at step \(step)"
            )
          }
        }
      }
    }
  }

  func testHostAndProviderKindsPartitionExactlySixAndSix() {
    let host = StageBMessageKind.allCases.filter { $0.role == .host }
    let provider = StageBMessageKind.allCases.filter { $0.role == .provider }
    XCTAssertEqual(host.count, 6)
    XCTAssertEqual(provider.count, 6)
    XCTAssertEqual(
      host,
      [
        .prepareDNSRequest, .dnsSent, .dnsResponse,
        .prepareReflectorRequest, .reflectorSent, .reflectorResponse,
      ]
    )
    XCTAssertEqual(StageBMessageKind.allCases.count, 12)
    XCTAssertEqual(
      StageBMessageKind.allCases.map(\.rawValue),
      Array(1 ... 12)
    )
  }

  func testResponseBeforeItsSendAcknowledgementIsRefused() throws {
    // Host side: the transcript has no way to skip `dns-sent`.
    let pair = try drive(steps: 2)
    XCTAssertEqual(pair.host.phase, .dnsSent)
    XCTAssertThrowsError(
      try pair.host.encodeDNSResponse(Vector.dnsResponse)
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }
    XCTAssertEqual(pair.host.phase, .terminated)

    // Provider side: a forged dns-response at the dns-sent slot is refused.
    let other = try drive(steps: 2)
    let forged = Vector.handAssemble(
      kind: 5,
      sequence: 3,
      chain: Vector.chains[2],
      payload: Vector.dnsResponse
    )
    XCTAssertThrowsError(try other.provider.decode(forged)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }
  }

  func testReflectorStepsCannotPrecedeTheDNSSteps() throws {
    let pair = try drive(steps: 0)
    XCTAssertThrowsError(try pair.host.encodePrepareReflectorRequest()) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }

    let other = try drive(steps: 0)
    let forged = Vector.handAssemble(
      kind: 7,
      sequence: 1,
      chain: Vector.chains[0],
      payload: []
    )
    XCTAssertThrowsError(try other.provider.decode(forged)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }
  }

  func testASideNeverDecodesItsOwnRolesMessage() throws {
    let pair = try drive(steps: 0)
    XCTAssertThrowsError(
      try pair.host.decode(Vector.goldenTranscript[0])
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }

    let other = try drive(steps: 1)
    XCTAssertThrowsError(
      try other.provider.decode(Vector.goldenTranscript[1])
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }
  }

  func testDuplicateOfTheJustAcceptedMessageIsRefused() throws {
    let pair = try makePair()
    _ = try pair.host.encodePrepareDNSRequest()
    _ = try pair.provider.decode(Vector.goldenTranscript[0])
    XCTAssertThrowsError(
      try pair.provider.decode(Vector.goldenTranscript[0])
    ) {
      // The provider now owes a reply, so nothing at all is decodable.
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }
    XCTAssertEqual(pair.provider.phase, .terminated)
  }

  func testTerminalResponseMayArriveAtAnyProviderTurnAndClosesTheChannel()
    throws
  {
    for step in [2, 4, 6, 8, 10, 12] {
      let pair = try drive(steps: step - 1)
      let terminal = Vector.handAssemble(
        kind: 12,
        sequence: UInt64(step),
        chain: Vector.chains[step - 1],
        payload: [2, 3, 0, 0]
          + Vector.be64(Vector.tData) + [0, 0, 0, 0]
      )
      let decoded = try pair.host.decode(terminal)
      XCTAssertEqual(decoded.kind, .terminalResponse)
      XCTAssertEqual(pair.host.phase, .terminated)
      XCTAssertThrowsError(try pair.host.decode(terminal)) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
      }
    }
  }

  func testEncodingAfterTheTerminalResponseIsRefused() throws {
    let pair = try drive(steps: 12)
    XCTAssertEqual(pair.provider.phase, .terminated)
    XCTAssertThrowsError(
      try pair.provider.encodeTerminalResponse(try successReport())
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }
    XCTAssertThrowsError(
      try pair.host.encodeReflectorResponse(Vector.reflectorResponse)
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }
  }

  func testARejectedEncodeAlsoPoisonsTheTranscript() throws {
    let pair = try drive(steps: 4)
    XCTAssertThrowsError(try pair.host.encodeDNSResponse([])) { _ in }
    XCTAssertEqual(pair.host.phase, .terminated)
    XCTAssertThrowsError(
      try pair.host.encodeDNSResponse(Vector.dnsResponse)
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }
  }

  func testCrossAttemptMessageIsRejectedAsAnIdentityMismatch() throws {
    let otherBinding = try StageBMessageAttemptBinding(
      attemptNonce: [
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x46, 0x78,
        0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
      ],
      pathID: Vector.pathID,
      bindingSHA256: Vector.bindingDigest,
      challenge: Vector.challenge,
      requestedAtMonotonicNanoseconds: Vector.t0
    )
    let stranger = StageBHostMessageTranscript(binding: otherBinding)
    let foreign = try stranger.encodePrepareDNSRequest()
    XCTAssertNotEqual(foreign, Vector.goldenTranscript[0])

    let pair = try makePair()
    XCTAssertThrowsError(try pair.provider.decode(foreign)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .attemptMismatch)
    }
  }

  // MARK: Construction guards

  func testAttemptBindingRejectsNonCanonicalOrDuplicateIdentifiers() throws {
    let notV4 = Vector.attemptNonce.enumerated().map {
      $0.offset == 6 ? UInt8(0x50) : $0.element
    }
    let badVariant = Vector.attemptNonce.enumerated().map {
      $0.offset == 8 ? UInt8(0x00) : $0.element
    }
    for nonce in [
      notV4,
      badVariant,
      [UInt8](repeating: 0, count: 16),
      Array(Vector.attemptNonce.prefix(15)),
    ] {
      XCTAssertThrowsError(
        try StageBMessageAttemptBinding(
          attemptNonce: nonce,
          pathID: Vector.pathID,
          bindingSHA256: Vector.bindingDigest,
          challenge: Vector.challenge,
          requestedAtMonotonicNanoseconds: Vector.t0
        )
      ) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .invalidBinding)
      }
    }

    XCTAssertThrowsError(
      try StageBMessageAttemptBinding(
        attemptNonce: Vector.pathID,
        pathID: Vector.pathID,
        bindingSHA256: Vector.bindingDigest,
        challenge: Vector.challenge,
        requestedAtMonotonicNanoseconds: Vector.t0
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidBinding)
    }
  }

  func testAttemptBindingRejectsZeroDigestsAndOverflowingT0() throws {
    for zero in [[UInt8]](repeating: [UInt8](repeating: 0, count: 32), count: 1)
    {
      XCTAssertThrowsError(
        try StageBMessageAttemptBinding(
          attemptNonce: Vector.attemptNonce,
          pathID: Vector.pathID,
          bindingSHA256: zero,
          challenge: Vector.challenge,
          requestedAtMonotonicNanoseconds: Vector.t0
        )
      ) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .invalidBinding)
      }
      XCTAssertThrowsError(
        try StageBMessageAttemptBinding(
          attemptNonce: Vector.attemptNonce,
          pathID: Vector.pathID,
          bindingSHA256: Vector.bindingDigest,
          challenge: zero,
          requestedAtMonotonicNanoseconds: Vector.t0
        )
      ) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .invalidBinding)
      }
    }

    XCTAssertThrowsError(
      try StageBMessageAttemptBinding(
        attemptNonce: Vector.attemptNonce,
        pathID: Vector.pathID,
        bindingSHA256: Vector.bindingDigest,
        challenge: Vector.challenge,
        requestedAtMonotonicNanoseconds: UInt64.max - 1_000
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidBinding)
    }
  }

  func testDeadlineIsDerivedFromT0AndIsNotCallerSupplied() throws {
    let binding = try makeBinding()
    XCTAssertEqual(binding.requestedAtMonotonicNanoseconds, Vector.t0)
    XCTAssertEqual(binding.deadlineMonotonicNanoseconds, Vector.deadline)
    XCTAssertEqual(
      binding.deadlineMonotonicNanoseconds
        - binding.requestedAtMonotonicNanoseconds,
      StageBProtectedFlow.deadlineNanoseconds
    )
  }

  func testMismatchedBodyForAKindFailsClosedInTheEngine() throws {
    // The public transcripts cannot express this pairing; the internal engine
    // still refuses it rather than emitting a wrongly shaped payload.
    let engine = StageBMessageTranscriptEngine(
      binding: try makeBinding(),
      role: .host
    )
    XCTAssertThrowsError(
      try engine.encode(.prepareDNSRequest, body: .datagram([0x01]))
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .outOfOrder)
    }
  }

  func testConstantTimeEqualityAgreesWithOrdinaryEquality() {
    let base = Vector.ramp(from: 0x00, count: 32)
    XCTAssertTrue(StageBMessageCodec.constantTimeEquals(base, base))
    XCTAssertFalse(
      StageBMessageCodec.constantTimeEquals(base, Array(base.dropLast()))
    )
    for offset in 0 ..< 32 {
      var mutated = base
      mutated[offset] ^= 0x80
      XCTAssertFalse(
        StageBMessageCodec.constantTimeEquals(base, mutated),
        "byte \(offset) not covered"
      )
    }
  }

  func testSchemaAndFramingConstantsArePinned() {
    XCTAssertEqual(
      StageBMessageCodec.schema,
      "winn-stageb-hostprovider-wire/1"
    )
    XCTAssertEqual(StageBMessageCodec.magic, Array("WHP3".utf8))
    XCTAssertEqual(StageBMessageCodec.wireVersion, 1)
    XCTAssertEqual(StageBMessageCodec.protocolTag, Array("winn/3".utf8))
    XCTAssertEqual(StageBMessageCodec.headerBytes, 138)
    XCTAssertEqual(StageBMessageCodec.maximumSequence, 12)
    XCTAssertEqual(
      StageBMessageCodec.chainDomain,
      Array("winn-stageb-hostprovider-wire/1".utf8) + [0]
    )
    for kind in StageBMessageKind.allCases {
      XCTAssertLessThanOrEqual(
        StageBMessageCodec.maximumPayload(for: kind),
        StageBMessageCodec.maximumPayloadBytes,
        "\(kind) exceeds the global payload bound"
      )
      XCTAssertLessThanOrEqual(
        StageBMessageCodec.minimumPayload(for: kind),
        StageBMessageCodec.maximumPayload(for: kind)
      )
    }
  }
  // MARK: Concurrency
  //
  // These assert order-INDEPENDENT invariants: every interleaving permitted by
  // the engine lock produces the same counts, so a run in which the threads
  // happen not to overlap proves the same thing as one in which they do.
  // `concurrentPerform` also guarantees every iteration executes, so a starved
  // worker shows up as a completion-count failure rather than a silent pass.

  private struct ConcurrentOutcome {
    var successes: [[UInt8]] = []
    var errors: [StageBMessageCodecError] = []
    var foreignErrors = 0
    var completions = 0

    func count(of error: StageBMessageCodecError) -> Int {
      errors.filter { $0 == error }.count
    }
  }

  private func runConcurrently(
    iterations: Int,
    _ body: (Int) throws -> [UInt8]
  ) -> ConcurrentOutcome {
    let lock = NSLock()
    var outcome = ConcurrentOutcome()
    DispatchQueue.concurrentPerform(iterations: iterations) { index in
      var success: [UInt8]?
      var failure: StageBMessageCodecError?
      var foreign = false
      do {
        success = try body(index)
      } catch let error as StageBMessageCodecError {
        failure = error
      } catch {
        foreign = true
      }
      lock.lock()
      outcome.completions += 1
      if let success { outcome.successes.append(success) }
      if let failure { outcome.errors.append(failure) }
      if foreign { outcome.foreignErrors += 1 }
      lock.unlock()
    }
    return outcome
  }

  func testConcurrentEncodersProduceExactlyOneWinner() throws {
    let iterations = 32
    let pair = try makePair()
    let outcome = runConcurrently(iterations: iterations) { _ in
      try pair.host.encodePrepareDNSRequest()
    }
    XCTAssertEqual(outcome.completions, iterations, "a worker was starved")
    XCTAssertEqual(outcome.foreignErrors, 0)
    // Serialization means: one winner, one ordering rejection that poisons the
    // transcript, and every later caller sees the poisoned state.
    XCTAssertEqual(outcome.successes.count, 1)
    XCTAssertEqual(outcome.successes.first, Vector.goldenTranscript[0])
    XCTAssertEqual(outcome.errors.count, iterations - 1)
    XCTAssertEqual(outcome.count(of: .outOfOrder), 1)
    XCTAssertEqual(outcome.count(of: .terminated), iterations - 2)
    XCTAssertEqual(pair.host.phase, .terminated)
  }

  func testConcurrentDecodersAcceptTheSameMessageExactlyOnce() throws {
    let iterations = 32
    let pair = try makePair()
    _ = try pair.host.encodePrepareDNSRequest()
    let golden = Vector.goldenTranscript[0]
    let outcome = runConcurrently(iterations: iterations) { _ in
      _ = try pair.provider.decode(golden)
      return golden
    }
    XCTAssertEqual(outcome.completions, iterations, "a worker was starved")
    XCTAssertEqual(outcome.foreignErrors, 0)
    XCTAssertEqual(outcome.successes.count, 1)
    XCTAssertEqual(outcome.errors.count, iterations - 1)
    XCTAssertEqual(outcome.count(of: .outOfOrder), 1)
    XCTAssertEqual(outcome.count(of: .terminated), iterations - 2)
    XCTAssertEqual(pair.provider.phase, .terminated)
  }

  func testConcurrentPoisonAndDecodeConvergeOnATerminatedTranscript() throws {
    let iterations = 32
    let pair = try makePair()
    _ = try pair.host.encodePrepareDNSRequest()
    let golden = Vector.goldenTranscript[0]
    let huge = Data(count: StageBMessageCodec.maximumMessageBytes + 1)
    let outcome = runConcurrently(iterations: iterations) { index in
      if index.isMultiple(of: 2) {
        _ = try pair.provider.decode(huge)
        return []
      }
      _ = try pair.provider.decode(golden)
      return golden
    }
    XCTAssertEqual(outcome.completions, iterations, "a worker was starved")
    XCTAssertEqual(outcome.foreignErrors, 0)
    // At most one oversized decode can ever report `.messageTooLarge`: the
    // first one to find the transcript live poisons it, and every later
    // oversized decode finds it dead and reports `.terminated`. This holds
    // under every interleaving.
    XCTAssertLessThanOrEqual(outcome.count(of: .messageTooLarge), 1)
    XCTAssertLessThanOrEqual(outcome.successes.count, 1)
    XCTAssertEqual(
      outcome.count(of: .messageTooLarge)
        + outcome.count(of: .terminated)
        + outcome.count(of: .outOfOrder),
      iterations - outcome.successes.count,
      "an unexpected error kind appeared"
    )
    XCTAssertEqual(pair.provider.phase, .terminated)
    XCTAssertThrowsError(try pair.provider.decode(golden)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }
  }

  func testConcurrentPhaseReadsOnlyEverObserveReachableStates() throws {
    let iterations = 64
    let pair = try makePair()
    let lock = NSLock()
    var observed: [StageBMessagePhase] = []
    DispatchQueue.concurrentPerform(iterations: iterations) { index in
      if index.isMultiple(of: 4) {
        _ = try? pair.host.encodePrepareDNSRequest()
      } else {
        let phase = pair.host.phase
        lock.lock()
        observed.append(phase)
        lock.unlock()
      }
    }
    // The only host operation here is `prepare-dns`, so exactly three states
    // are reachable. Anything else would mean the state was seen mid-update.
    let reachable: [StageBMessagePhase] = [
      .prepareDNS, .prepareDNSReply, .terminated,
    ]
    XCTAssertEqual(observed.count, iterations - iterations / 4)
    for phase in observed {
      XCTAssertTrue(
        reachable.contains(phase),
        "observed unreachable phase \(phase)"
      )
    }
  }

  // MARK: UInt64 ceiling

  func testTerminalSlackArithmeticIsSafeAtTheUInt64Ceiling() throws {
    let ceilingT0 =
      UInt64.max
      - StageBProtectedFlow.deadlineNanoseconds
      - StageBMessageCodec.terminalSlackNanoseconds
    let binding = try StageBMessageAttemptBinding(
      attemptNonce: Vector.attemptNonce,
      pathID: Vector.pathID,
      bindingSHA256: Vector.bindingDigest,
      challenge: Vector.challenge,
      requestedAtMonotonicNanoseconds: ceilingT0
    )
    // deadline + slack lands exactly on UInt64.max, so the failure-window
    // comparison is evaluated at the boundary rather than wrapping or trapping.
    XCTAssertEqual(
      binding.deadlineMonotonicNanoseconds,
      UInt64.max - StageBMessageCodec.terminalSlackNanoseconds
    )

    // One nanosecond past the ceiling must be refused, not trapped.
    XCTAssertThrowsError(
      try StageBMessageAttemptBinding(
        attemptNonce: Vector.attemptNonce,
        pathID: Vector.pathID,
        bindingSHA256: Vector.bindingDigest,
        challenge: Vector.challenge,
        requestedAtMonotonicNanoseconds: ceilingT0 + 1
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidBinding)
    }

    let host = StageBHostMessageTranscript(binding: binding)
    let provider = StageBProviderMessageTranscript(binding: binding)
    let first = try host.encodePrepareDNSRequest()
    _ = try provider.decode(first)

    // Recomputed locally, not taken from the codec.
    var hasher = SHA256()
    hasher.update(
      data: Data(Array("winn-stageb-hostprovider-wire/1".utf8) + [0])
    )
    hasher.update(data: Data(first))
    let chain = Array(hasher.finalize())

    // A failure report at the absolute ceiling is admissible.
    let atCeiling = Vector.handAssemble(
      kind: 12,
      sequence: 2,
      chain: chain,
      payload: [2, 9, 0, 0] + Vector.be64(UInt64.max) + [0, 0, 0, 0],
      t0: ceilingT0,
      deadline: binding.deadlineMonotonicNanoseconds
    )
    let decoded = try host.decode(atCeiling)
    guard case let .terminal(report) = decoded.body else {
      return XCTFail("expected a terminal body")
    }
    XCTAssertEqual(report.dataCompleteMonotonicNanoseconds, UInt64.max)

    // The same instant is still too late for a success report.
    let successHost = StageBHostMessageTranscript(binding: binding)
    _ = try successHost.encodePrepareDNSRequest()
    let successAtCeiling = Vector.handAssemble(
      kind: 12,
      sequence: 2,
      chain: chain,
      payload: [1, 0, 0, 0] + Vector.be64(UInt64.max) + [1, 1, 1, 1],
      t0: ceilingT0,
      deadline: binding.deadlineMonotonicNanoseconds
    )
    XCTAssertThrowsError(try successHost.decode(successAtCeiling)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .invalidTerminalReport)
    }
  }

  func testZeroT0IsAValidFloorAndDoesNotUnderflow() throws {
    let binding = try StageBMessageAttemptBinding(
      attemptNonce: Vector.attemptNonce,
      pathID: Vector.pathID,
      bindingSHA256: Vector.bindingDigest,
      challenge: Vector.challenge,
      requestedAtMonotonicNanoseconds: 0
    )
    XCTAssertEqual(binding.requestedAtMonotonicNanoseconds, 0)
    XCTAssertEqual(
      binding.deadlineMonotonicNanoseconds,
      StageBProtectedFlow.deadlineNanoseconds
    )
    let host = StageBHostMessageTranscript(binding: binding)
    XCTAssertNoThrow(try host.encodePrepareDNSRequest())
  }

  // MARK: Poison via the Data overload

  func testDataPoisonRefusesLaterEncodesOnBothRoles() throws {
    let huge = Data(count: StageBMessageCodec.maximumMessageBytes + 1)

    let hostSide = try makePair()
    XCTAssertThrowsError(try hostSide.host.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .messageTooLarge)
    }
    XCTAssertEqual(hostSide.host.phase, .terminated)
    XCTAssertThrowsError(try hostSide.host.encodePrepareDNSRequest()) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }

    let providerSide = try drive(steps: 1)
    XCTAssertThrowsError(try providerSide.provider.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .messageTooLarge)
    }
    XCTAssertEqual(providerSide.provider.phase, .terminated)
    XCTAssertThrowsError(
      try providerSide.provider.encodePrepareDNSReply(
        endpoint: try dnsEndpoint(),
        query: Vector.dnsQuery
      )
    ) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }

    // Exactly at the bound the Data overload does not poison.
    let atBound = try drive(steps: 4)
    let maximal = try atBound.host.encodeDNSResponse(
      [UInt8](repeating: 0x77, count: 1_024)
    )
    XCTAssertEqual(maximal.count, StageBMessageCodec.maximumMessageBytes)
    XCTAssertNoThrow(try atBound.provider.decode(Data(maximal)))
  }

  /// Once a transcript is poisoned it reports only that it is dead. It must
  /// not characterize the input, at any size. The live-transcript half of this
  /// test keeps the check honest: `.messageTooLarge` is still reachable, so
  /// this is an ordering guarantee and not a collapse to one error.
  func testPoisonedTranscriptReportsTerminatedAtEverySize() throws {
    let huge = Data(count: StageBMessageCodec.maximumMessageBytes + 1)
    let inBounds = Data(count: StageBMessageCodec.headerBytes)

    // Live transcripts still distinguish over-length input.
    let liveProvider = try makePair().provider
    XCTAssertThrowsError(try liveProvider.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .messageTooLarge)
    }
    let liveHost = try makePair().host
    XCTAssertThrowsError(try liveHost.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .messageTooLarge)
    }

    // Poisoned transcripts report `.terminated` regardless of size or role.
    for poisoned in [
      try makePair().provider as AnyObject,
      try makePair().host as AnyObject,
    ] {
      let decodeBytes: ([UInt8]) throws -> StageBMessage
      let decodeData: (Data) throws -> StageBMessage
      if let provider = poisoned as? StageBProviderMessageTranscript {
        decodeBytes = provider.decode
        decodeData = provider.decode
      } else if let host = poisoned as? StageBHostMessageTranscript {
        decodeBytes = host.decode
        decodeData = host.decode
      } else {
        return XCTFail("unexpected transcript type")
      }

      // Poison with an ordinary framing failure, not an oversize one.
      XCTAssertThrowsError(try decodeBytes([])) {
        XCTAssertEqual($0 as? StageBMessageCodecError, .truncated)
      }
      for input in [huge, inBounds] {
        XCTAssertThrowsError(try decodeData(input)) {
          XCTAssertEqual(
            $0 as? StageBMessageCodecError,
            .terminated,
            "a dead transcript characterized \(input.count)-byte input"
          )
        }
      }
    }

    // A transcript poisoned BY an oversize decode is equally dead, and the
    // second oversize decode no longer repeats `.messageTooLarge`.
    let repeated = try makePair().provider
    XCTAssertThrowsError(try repeated.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .messageTooLarge)
    }
    XCTAssertThrowsError(try repeated.decode(huge)) {
      XCTAssertEqual($0 as? StageBMessageCodecError, .terminated)
    }
    XCTAssertEqual(repeated.phase, .terminated)
  }

  // MARK: Fixed-width field edges

  func testMaximumRepresentablePayloadLengthFieldIsRejected() throws {
    // 0xFFFF is the largest value the two-byte field can express.
    try expectRejection(
      step: 5,
      mutate: { self.replace($0, at: 134, with: Vector.be16(0xFFFF)) },
      .payloadTooLarge
    )
    try expectRejection(
      step: 1,
      mutate: { self.replace($0, at: 134, with: Vector.be16(0xFFFF)) },
      .payloadTooLarge
    )
    // One byte past the per-kind ceiling is a payload error, not a length one.
    try expectRejection(
      step: 5,
      mutate: { self.replace($0, at: 134, with: Vector.be16(1_025)) },
      .payloadTooLarge
    )
  }

  func testMaximumUInt16PortRoundTrips() throws {
    let endpoint = try StageBPrivateEndpoint(
      family: .ipv4,
      address: Vector.dnsAddress,
      port: 65_535
    )
    let pair = try drive(steps: 1)
    let encoded = try pair.provider.encodePrepareDNSReply(
      endpoint: endpoint,
      query: Vector.dnsQuery
    )
    XCTAssertEqual(Array(encoded[155 ..< 157]), [0xFF, 0xFF])
    let decoded = try pair.host.decode(encoded)
    XCTAssertEqual(
      decoded.body,
      .dnsPrepare(endpoint: endpoint, query: Vector.dnsQuery)
    )
  }

  // MARK: Constant-time comparison call-site widths
  //
  // Evidence against the claim that `constantTimeEquals` has a variable-length
  // call path. Both operands at all four production call sites are pinned by
  // construction, so the length-dependent early return is unreachable there.

  func testEveryConstantTimeComparisonIsStructurallyFixedWidth() throws {
    let binding = try makeBinding()
    // Right-hand operands: widths enforced by the binding's own validation.
    XCTAssertEqual(binding.attemptNonce.count, 16)
    XCTAssertEqual(binding.pathID.count, 16)
    XCTAssertEqual(binding.bindingSHA256.count, 32)
    XCTAssertEqual(binding.challenge.count, 32)

    // The chain operand is only ever the challenge or a SHA-256 digest, which
    // is 32 bytes for every input length including degenerate ones.
    for length in [
      0, 1, 31, 32, 137, 138, StageBMessageCodec.maximumMessageBytes,
    ] {
      XCTAssertEqual(
        StageBMessageCodec.chainDigest(
          ofMessage: [UInt8](repeating: 0x5A, count: length)
        ).count,
        32
      )
    }

    // Left-hand operands: constant-width slices of a frame whose total length
    // was already pinned before any comparison is reached.
    XCTAssertEqual(StageBMessageCodec.headerBytes, 138)
    XCTAssertEqual(StageBMessageCodec.offsetAttemptNonce + 16, 30)
    XCTAssertEqual(StageBMessageCodec.offsetPathID + 16, 46)
    XCTAssertEqual(StageBMessageCodec.offsetBindingDigest + 32, 78)
    XCTAssertEqual(StageBMessageCodec.offsetChain + 32, 134)
  }
}
