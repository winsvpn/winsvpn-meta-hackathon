import CryptoKit
import Foundation
import WinnPrivacyCore

// MARK: - Errors

/// Every rejection reason of the fixed Stage B host/provider codec.
///
/// Cases are deliberately fine grained so a mutation test can prove that a
/// specific corrupted field was rejected *for that field's own reason* rather
/// than incidentally by a later parse step.
public enum StageBMessageCodecError: Error, Equatable, Sendable {
  // Framing
  case messageTooLarge
  case truncated
  case lengthMismatch
  case invalidMagic
  case unsupportedVersion
  case unknownKind
  case nonzeroReserved
  case invalidProtocol
  case payloadTooLarge
  case payloadTooSmall
  // Attempt binding
  case attemptMismatch
  case pathMismatch
  case bindingMismatch
  case deadlineMismatch
  // Ordering
  case outOfOrder
  case staleSequence
  case sequenceGap
  case sequenceOutOfRange
  case chainMismatch
  case terminated
  // Construction / payload
  case invalidBinding
  case invalidEndpoint
  case invalidDigest
  case invalidTerminalReport
}

// MARK: - Kinds

/// The complete set of Stage B host/provider message kinds.
///
/// The six host kinds and six provider kinds are exactly the exchanges named
/// by the app-probe integration contract: `prepare-dns`, `dns-sent`,
/// `dns-response`, `prepare-reflector`, `reflector-sent`, `reflector-response`
/// and their bound replies. There is no extension point: an unassigned kind
/// byte fails closed.
public enum StageBMessageKind: UInt8, CaseIterable, Equatable, Sendable {
  case prepareDNSRequest = 1
  case prepareDNSReply = 2
  case dnsSent = 3
  case dnsSentAck = 4
  case dnsResponse = 5
  case dnsResponseAck = 6
  case prepareReflectorRequest = 7
  case prepareReflectorReply = 8
  case reflectorSent = 9
  case reflectorSentAck = 10
  case reflectorResponse = 11
  case terminalResponse = 12

  /// The side that is permitted to originate this kind.
  public var role: StageBMessageRole {
    switch self {
    case .prepareDNSRequest, .dnsSent, .dnsResponse,
      .prepareReflectorRequest, .reflectorSent, .reflectorResponse:
      return .host
    case .prepareDNSReply, .dnsSentAck, .dnsResponseAck,
      .prepareReflectorReply, .reflectorSentAck, .terminalResponse:
      return .provider
    }
  }
}

public enum StageBMessageRole: Equatable, Sendable {
  case host
  case provider
}

// MARK: - Endpoint

public enum StageBEndpointFamily: UInt8, Equatable, Sendable {
  case ipv4 = 4
  case ipv6 = 6

  public var addressBytes: Int {
    self == .ipv4 ? 4 : 16
  }
}

/// A numeric-only probe endpoint.
///
/// This type cannot represent a hostname, a service name, or a URL, so the
/// contract's "no hostname fallback" rule is structural rather than a runtime
/// check. It rejects the address classes that can never be a unicast overlay
/// peer: unspecified, loopback, and multicast/reserved.
///
/// It does **not** and cannot prove that a well-formed unicast address is
/// reachable only through the selected AWG tunnel. That remains an adapter and
/// coordinator responsibility.
public struct StageBPrivateEndpoint: Equatable, Sendable {
  public static let encodedBytes = 19

  public let family: StageBEndpointFamily
  public let address: [UInt8]
  public let port: UInt16

  public init(
    family: StageBEndpointFamily,
    address: [UInt8],
    port: UInt16
  ) throws {
    guard address.count == family.addressBytes else {
      throw StageBMessageCodecError.invalidEndpoint
    }
    guard port != 0 else {
      throw StageBMessageCodecError.invalidEndpoint
    }
    guard !address.allSatisfy({ $0 == 0 }) else {
      throw StageBMessageCodecError.invalidEndpoint
    }
    switch family {
    case .ipv4:
      // 0.0.0.0/8 unusable, 127.0.0.0/8 loopback, 224.0.0.0/4 multicast and
      // 240.0.0.0/4 reserved (which contains 255.255.255.255).
      guard address[0] != 0, address[0] != 127, address[0] < 224 else {
        throw StageBMessageCodecError.invalidEndpoint
      }
    case .ipv6:
      // ff00::/8 multicast, and ::/128 plus ::1/128 (caught below).
      guard address[0] != 0xFF else {
        throw StageBMessageCodecError.invalidEndpoint
      }
      let loopback = [UInt8](repeating: 0, count: 15) + [1]
      guard address != loopback else {
        throw StageBMessageCodecError.invalidEndpoint
      }
    }
    self.family = family
    self.address = Array(address)
    self.port = port
  }
}

// MARK: - Terminal report

public enum StageBTerminalOutcome: UInt8, Equatable, Sendable {
  case success = 1
  case failure = 2
}

/// The single bound terminal response body.
///
/// A success report must carry all four provider-owned predicates and a zero
/// failure code; a failure report must carry a nonzero failure code. The
/// deadline relationship for `dataCompleteMonotonicNanoseconds` is enforced by
/// the transcript, which is the only holder of T0 and the deadline.
public struct StageBTerminalReport: Equatable, Sendable {
  public static let encodedBytes = 16

  public let outcome: StageBTerminalOutcome
  public let failureCode: UInt8
  public let dataCompleteMonotonicNanoseconds: UInt64
  public let freshAWGHandshake: Bool
  public let authenticatedTunnelBytes: Bool
  public let protectedDNSResponse: Bool
  public let authenticatedReflectorResponse: Bool

  public init(
    outcome: StageBTerminalOutcome,
    failureCode: UInt8,
    dataCompleteMonotonicNanoseconds: UInt64,
    freshAWGHandshake: Bool,
    authenticatedTunnelBytes: Bool,
    protectedDNSResponse: Bool,
    authenticatedReflectorResponse: Bool
  ) throws {
    switch outcome {
    case .success:
      guard failureCode == 0,
        freshAWGHandshake,
        authenticatedTunnelBytes,
        protectedDNSResponse,
        authenticatedReflectorResponse
      else {
        throw StageBMessageCodecError.invalidTerminalReport
      }
    case .failure:
      guard failureCode != 0 else {
        throw StageBMessageCodecError.invalidTerminalReport
      }
    }
    self.outcome = outcome
    self.failureCode = failureCode
    self.dataCompleteMonotonicNanoseconds =
      dataCompleteMonotonicNanoseconds
    self.freshAWGHandshake = freshAWGHandshake
    self.authenticatedTunnelBytes = authenticatedTunnelBytes
    self.protectedDNSResponse = protectedDNSResponse
    self.authenticatedReflectorResponse =
      authenticatedReflectorResponse
  }
}

// MARK: - Message body

public enum StageBMessageBody: Equatable, Sendable {
  case empty
  case dnsPrepare(endpoint: StageBPrivateEndpoint, query: [UInt8])
  case sendAcknowledgement(datagramSHA256: [UInt8])
  case datagram([UInt8])
  case reflectorPrepare(
    endpoint: StageBPrivateEndpoint,
    requestDatagram: [UInt8]
  )
  case terminal(StageBTerminalReport)
}

public struct StageBMessage: Equatable, Sendable {
  public let kind: StageBMessageKind
  public let sequence: UInt64
  public let chain: [UInt8]
  public let body: StageBMessageBody
}

// MARK: - Attempt binding

/// The immutable per-attempt binding every message on this channel carries.
///
/// `challenge` seeds the transcript chain: message 1 carries it verbatim and
/// every later message carries the exact digest of its predecessor.
public struct StageBMessageAttemptBinding: Equatable, Sendable {
  public let attemptNonce: [UInt8]
  public let pathID: [UInt8]
  public let bindingSHA256: [UInt8]
  public let challenge: [UInt8]
  public let requestedAtMonotonicNanoseconds: UInt64
  public let deadlineMonotonicNanoseconds: UInt64

  public init(
    attemptNonce: [UInt8],
    pathID: [UInt8],
    bindingSHA256: [UInt8],
    challenge: [UInt8],
    requestedAtMonotonicNanoseconds: UInt64
  ) throws {
    guard StageBMessageCodec.isCanonicalUUIDv4(attemptNonce),
      StageBMessageCodec.isCanonicalUUIDv4(pathID),
      attemptNonce != pathID
    else {
      throw StageBMessageCodecError.invalidBinding
    }
    guard StageBMessageCodec.isNonzeroDigest(bindingSHA256),
      StageBMessageCodec.isNonzeroDigest(challenge)
    else {
      throw StageBMessageCodecError.invalidBinding
    }
    let (deadline, overflow) =
      requestedAtMonotonicNanoseconds.addingReportingOverflow(
        StageBProtectedFlow.deadlineNanoseconds
      )
    guard !overflow,
      deadline
        <= UInt64.max - StageBMessageCodec.terminalSlackNanoseconds
    else {
      throw StageBMessageCodecError.invalidBinding
    }
    self.attemptNonce = Array(attemptNonce)
    self.pathID = Array(pathID)
    self.bindingSHA256 = Array(bindingSHA256)
    self.challenge = Array(challenge)
    self.requestedAtMonotonicNanoseconds =
      requestedAtMonotonicNanoseconds
    deadlineMonotonicNanoseconds = deadline
  }
}

// MARK: - Phases

/// The lock-step position of the transcript.
///
/// Exactly one kind (plus an early `terminalResponse` wherever the provider is
/// due to speak) is admissible in each phase, in each direction. This is what
/// makes `prepare -> send-ack -> response` unrepresentable out of order.
public enum StageBMessagePhase: Equatable, Sendable {
  case prepareDNS
  case prepareDNSReply
  case dnsSent
  case dnsSentAck
  case dnsResponse
  case dnsResponseAck
  case prepareReflector
  case prepareReflectorReply
  case reflectorSent
  case reflectorSentAck
  case reflectorResponse
  case terminal
  case terminated

  fileprivate var expected: (role: StageBMessageRole, kind: StageBMessageKind)? {
    switch self {
    case .prepareDNS: return (.host, .prepareDNSRequest)
    case .prepareDNSReply: return (.provider, .prepareDNSReply)
    case .dnsSent: return (.host, .dnsSent)
    case .dnsSentAck: return (.provider, .dnsSentAck)
    case .dnsResponse: return (.host, .dnsResponse)
    case .dnsResponseAck: return (.provider, .dnsResponseAck)
    case .prepareReflector: return (.host, .prepareReflectorRequest)
    case .prepareReflectorReply: return (.provider, .prepareReflectorReply)
    case .reflectorSent: return (.host, .reflectorSent)
    case .reflectorSentAck: return (.provider, .reflectorSentAck)
    case .reflectorResponse: return (.host, .reflectorResponse)
    case .terminal: return (.provider, .terminalResponse)
    case .terminated: return nil
    }
  }

  fileprivate var next: StageBMessagePhase {
    switch self {
    case .prepareDNS: return .prepareDNSReply
    case .prepareDNSReply: return .dnsSent
    case .dnsSent: return .dnsSentAck
    case .dnsSentAck: return .dnsResponse
    case .dnsResponse: return .dnsResponseAck
    case .dnsResponseAck: return .prepareReflector
    case .prepareReflector: return .prepareReflectorReply
    case .prepareReflectorReply: return .reflectorSent
    case .reflectorSent: return .reflectorSentAck
    case .reflectorSentAck: return .reflectorResponse
    case .reflectorResponse: return .terminal
    case .terminal, .terminated: return .terminated
    }
  }
}

// MARK: - Codec constants and pure helpers

/// Fixed binary Stage B host/provider codec.
///
/// All integers are unsigned big-endian, every offset and length is fixed,
/// UUIDs are the raw 16 RFC 4122 bytes, digests are raw 32-byte values, and
/// every reserved byte must be zero on the wire and is verified on decode.
/// There is no JSON, no optional field, and no extension point.
///
/// ```text
/// Offset  Len  Field
/// 0       4    ASCII magic "WHP3"
/// 4       1    wire version = 1
/// 5       1    message kind (1...12)
/// 6       2    reserved zero
/// 8       6    ASCII protocol "winn/3"
/// 14      16   attempt nonce (canonical UUIDv4 bytes)
/// 30      16   path ID (canonical UUIDv4 bytes)
/// 46      32   binding SHA-256 (not all zero)
/// 78      8    message sequence (1...12, strictly +1)
/// 86      8    T0, host first-click monotonic nanoseconds
/// 94      8    deadline monotonic nanoseconds (T0 + 3s exactly)
/// 102     32   chain: attempt challenge at sequence 1, else the exact
///              digest of the whole preceding message
/// 134     2    payload length
/// 136     2    reserved zero
/// 138     ..   payload
/// ```
public enum StageBMessageCodec {
  public static let schema = "winn-stageb-hostprovider-wire/1"
  public static let magic: [UInt8] = Array("WHP3".utf8)
  public static let wireVersion: UInt8 = 1
  public static let protocolTag: [UInt8] =
    Array(StageBProtectedFlow.protocolVersion.utf8)

  public static let headerBytes = 138
  public static let maximumSequence: UInt64 = 12

  public static let maximumDNSQueryBytes = 512
  public static let maximumDNSResponseBytes = 1_024
  public static let maximumReflectorRequestBytes = 512
  public static let maximumReflectorResponseBytes = 512
  public static let digestBytes = 32

  /// The largest payload any kind may carry. Every per-kind maximum is at or
  /// below this value, and this value is checked before any allocation.
  public static let maximumPayloadBytes = maximumDNSResponseBytes
  public static let maximumMessageBytes = headerBytes + maximumPayloadBytes

  /// Bound on a failure terminal report's captured time, from the contract's
  /// `(deadline, deadline + 50 ms]` terminal reporting window.
  public static let terminalSlackNanoseconds: UInt64 = 50_000_000

  static let chainDomain: [UInt8] = Array(schema.utf8) + [0]
  static let bindingDomain: [UInt8] =
    Array("winn-stageb-hostprovider-binding/1".utf8) + [0]

  // Field offsets.
  static let offsetMagic = 0
  static let offsetVersion = 4
  static let offsetKind = 5
  static let offsetReservedA = 6
  static let offsetProtocol = 8
  static let offsetAttemptNonce = 14
  static let offsetPathID = 30
  static let offsetBindingDigest = 46
  static let offsetSequence = 78
  static let offsetRequestedAt = 86
  static let offsetDeadline = 94
  static let offsetChain = 102
  static let offsetPayloadLength = 134
  static let offsetReservedB = 136

  /// The exact digest a successor message must carry.
  public static func chainDigest(ofMessage message: [UInt8]) -> [UInt8] {
    var hasher = SHA256()
    hasher.update(data: Data(chainDomain))
    hasher.update(data: Data(message))
    return Array(hasher.finalize())
  }

  /// Canonical `binding SHA-256` for a provider path binding.
  ///
  /// Both sides derive the wire field from the same fixed 224-byte
  /// serialization so the field cannot be a caller-asserted opaque value.
  public static func bindingDigest(
    for binding: StageBProviderPathBinding
  ) -> [UInt8] {
    var preimage: [UInt8] = []
    preimage.reserveCapacity(224)
    preimage += binding.pathID
    preimage += binding.identity.signedRuntimeArtifactSHA256
    preimage += binding.identity.wgTurnOnConfigSHA256
    preimage += binding.identity.expectedPeerPublicKeySHA256
    preimage += binding.identity.engineInstanceNonce
    preimage += bigEndian(binding.identity.engineGeneration)
    preimage += bigEndian(binding.identity.pathGeneration)
    preimage += binding.identity.winningInterfaceTokenSHA256
    preimage += binding.context.sessionID
    preimage += binding.context.bindingID
    preimage += bigEndian(binding.context.pskGeneration)
    preimage += bigEndian(binding.context.sequenceEpoch)
    var hasher = SHA256()
    hasher.update(data: Data(bindingDomain))
    hasher.update(data: Data(preimage))
    return Array(hasher.finalize())
  }

  static func isCanonicalUUIDv4(_ bytes: [UInt8]) -> Bool {
    bytes.count == 16
      && bytes[6] & 0xF0 == 0x40
      && bytes[8] & 0xC0 == 0x80
      && !bytes.allSatisfy { $0 == 0 }
  }

  static func isNonzeroDigest(_ bytes: [UInt8]) -> Bool {
    bytes.count == digestBytes && !bytes.allSatisfy { $0 == 0 }
  }

  static func bigEndian(_ value: UInt64) -> [UInt8] {
    (0 ..< 8).map { UInt8((value >> UInt64(56 - $0 * 8)) & 0xFF) }
  }

  static func bigEndian(_ value: UInt16) -> [UInt8] {
    [UInt8(value >> 8), UInt8(value & 0xFF)]
  }

  static func readUInt64(_ bytes: [UInt8], at offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0 ..< 8 {
      value = (value << 8) | UInt64(bytes[offset + index])
    }
    return value
  }

  static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
  }

  /// Constant-time equality for the challenge, chain, and binding digests.
  static func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for index in 0 ..< lhs.count {
      difference |= lhs[index] ^ rhs[index]
    }
    return difference == 0
  }

  static func maximumPayload(for kind: StageBMessageKind) -> Int {
    switch kind {
    case .prepareDNSRequest, .dnsSentAck, .dnsResponseAck,
      .prepareReflectorRequest, .reflectorSentAck:
      return 0
    case .prepareDNSReply:
      return StageBPrivateEndpoint.encodedBytes + maximumDNSQueryBytes
    case .prepareReflectorReply:
      return StageBPrivateEndpoint.encodedBytes
        + maximumReflectorRequestBytes
    case .dnsSent, .reflectorSent:
      return digestBytes
    case .dnsResponse:
      return maximumDNSResponseBytes
    case .reflectorResponse:
      return maximumReflectorResponseBytes
    case .terminalResponse:
      return StageBTerminalReport.encodedBytes
    }
  }

  static func minimumPayload(for kind: StageBMessageKind) -> Int {
    switch kind {
    case .prepareDNSRequest, .dnsSentAck, .dnsResponseAck,
      .prepareReflectorRequest, .reflectorSentAck:
      return 0
    case .prepareDNSReply, .prepareReflectorReply:
      return StageBPrivateEndpoint.encodedBytes + 1
    case .dnsSent, .reflectorSent:
      return digestBytes
    case .dnsResponse, .reflectorResponse:
      return 1
    case .terminalResponse:
      return StageBTerminalReport.encodedBytes
    }
  }
}

// MARK: - Transcript engine

/// The single serialized encode/decode authority for one attempt's channel.
///
/// Any thrown error poisons the transcript: the phase becomes `.terminated`
/// and every later encode or decode throws `.terminated` -- including an
/// over-length `Data` rejected before it reaches `decode`. A rejected message
/// can never be followed by an accepted one, so a caller cannot retry past a
/// binding, ordering, or framing violation.
final class StageBMessageTranscriptEngine: @unchecked Sendable {
  private let lock = NSLock()
  private let binding: StageBMessageAttemptBinding
  private let role: StageBMessageRole
  private var phase: StageBMessagePhase = .prepareDNS
  private var nextSequence: UInt64 = 1
  private var expectedChain: [UInt8]

  init(binding: StageBMessageAttemptBinding, role: StageBMessageRole) {
    self.binding = binding
    self.role = role
    expectedChain = binding.challenge
  }

  var currentPhase: StageBMessagePhase {
    lock.lock()
    defer { lock.unlock() }
    return phase
  }

  /// Terminalizes the transcript for input a caller rejected before it could
  /// be handed to `decode`, and reports which rejection applies.
  ///
  /// A single lock acquisition decides both, so a concurrent caller cannot
  /// observe the transcript live for the length test and dead for the poison.
  /// An already-dead transcript reports `.terminated`: once poisoned, the
  /// channel says only that it is dead and never characterizes the input.
  func rejectOversized() -> StageBMessageCodecError {
    lock.lock()
    defer { lock.unlock() }
    guard phase != .terminated else {
      return .terminated
    }
    phase = .terminated
    return .messageTooLarge
  }

  func encode(
    _ kind: StageBMessageKind,
    body: StageBMessageBody
  ) throws -> [UInt8] {
    lock.lock()
    defer { lock.unlock() }
    do {
      guard phase != .terminated else {
        throw StageBMessageCodecError.terminated
      }
      guard let expected = phase.expected else {
        throw StageBMessageCodecError.terminated
      }
      // Only the owning side may originate, and only the kind this phase is
      // waiting for -- plus an early provider terminal response.
      guard kind.role == role, expected.role == role else {
        throw StageBMessageCodecError.outOfOrder
      }
      guard kind == expected.kind || kind == .terminalResponse else {
        throw StageBMessageCodecError.outOfOrder
      }
      guard nextSequence <= StageBMessageCodec.maximumSequence else {
        throw StageBMessageCodecError.sequenceOutOfRange
      }
      let payload = try encodePayload(kind: kind, body: body)
      guard payload.count <= StageBMessageCodec.maximumPayload(for: kind)
      else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      guard payload.count >= StageBMessageCodec.minimumPayload(for: kind)
      else {
        throw StageBMessageCodecError.payloadTooSmall
      }

      var message: [UInt8] = []
      message.reserveCapacity(
        StageBMessageCodec.headerBytes + payload.count
      )
      message += StageBMessageCodec.magic
      message.append(StageBMessageCodec.wireVersion)
      message.append(kind.rawValue)
      message += [0, 0]
      message += StageBMessageCodec.protocolTag
      message += binding.attemptNonce
      message += binding.pathID
      message += binding.bindingSHA256
      message += StageBMessageCodec.bigEndian(nextSequence)
      message += StageBMessageCodec.bigEndian(
        binding.requestedAtMonotonicNanoseconds
      )
      message += StageBMessageCodec.bigEndian(
        binding.deadlineMonotonicNanoseconds
      )
      message += expectedChain
      message += StageBMessageCodec.bigEndian(UInt16(payload.count))
      message += [0, 0]
      guard message.count == StageBMessageCodec.headerBytes else {
        throw StageBMessageCodecError.lengthMismatch
      }
      message += payload

      advanceLocked(kind: kind, encoded: message)
      return message
    } catch {
      phase = .terminated
      throw error
    }
  }

  func decode(_ encoded: [UInt8]) throws -> StageBMessage {
    lock.lock()
    defer { lock.unlock() }
    do {
      return try decodeLocked(encoded)
    } catch {
      phase = .terminated
      throw error
    }
  }

  private func decodeLocked(_ encoded: [UInt8]) throws -> StageBMessage {
    guard phase != .terminated else {
      throw StageBMessageCodecError.terminated
    }
    // Oversize is rejected outright. A valid-looking prefix of an oversized
    // input is never accepted.
    guard encoded.count <= StageBMessageCodec.maximumMessageBytes else {
      throw StageBMessageCodecError.messageTooLarge
    }
    guard encoded.count >= StageBMessageCodec.headerBytes else {
      throw StageBMessageCodecError.truncated
    }
    guard
      Array(
        encoded[
          StageBMessageCodec.offsetMagic
            ..< StageBMessageCodec.offsetMagic + 4
        ]
      ) == StageBMessageCodec.magic
    else {
      throw StageBMessageCodecError.invalidMagic
    }
    guard
      encoded[StageBMessageCodec.offsetVersion]
        == StageBMessageCodec.wireVersion
    else {
      throw StageBMessageCodecError.unsupportedVersion
    }
    guard
      let kind = StageBMessageKind(
        rawValue: encoded[StageBMessageCodec.offsetKind]
      )
    else {
      throw StageBMessageCodecError.unknownKind
    }
    guard
      encoded[StageBMessageCodec.offsetReservedA] == 0,
      encoded[StageBMessageCodec.offsetReservedA + 1] == 0,
      encoded[StageBMessageCodec.offsetReservedB] == 0,
      encoded[StageBMessageCodec.offsetReservedB + 1] == 0
    else {
      throw StageBMessageCodecError.nonzeroReserved
    }
    guard
      Array(
        encoded[
          StageBMessageCodec.offsetProtocol
            ..< StageBMessageCodec.offsetProtocol + 6
        ]
      ) == StageBMessageCodec.protocolTag
    else {
      throw StageBMessageCodecError.invalidProtocol
    }

    let payloadLength = Int(
      StageBMessageCodec.readUInt16(
        encoded,
        at: StageBMessageCodec.offsetPayloadLength
      )
    )
    guard payloadLength <= StageBMessageCodec.maximumPayload(for: kind)
    else {
      throw StageBMessageCodecError.payloadTooLarge
    }
    guard payloadLength >= StageBMessageCodec.minimumPayload(for: kind)
    else {
      throw StageBMessageCodecError.payloadTooSmall
    }
    // Exact-length framing: no trailing bytes, no short payload.
    guard
      StageBMessageCodec.headerBytes + payloadLength == encoded.count
    else {
      throw StageBMessageCodecError.lengthMismatch
    }

    guard
      StageBMessageCodec.constantTimeEquals(
        Array(
          encoded[
            StageBMessageCodec.offsetAttemptNonce
              ..< StageBMessageCodec.offsetAttemptNonce + 16
          ]
        ),
        binding.attemptNonce
      )
    else {
      throw StageBMessageCodecError.attemptMismatch
    }
    guard
      StageBMessageCodec.constantTimeEquals(
        Array(
          encoded[
            StageBMessageCodec.offsetPathID
              ..< StageBMessageCodec.offsetPathID + 16
          ]
        ),
        binding.pathID
      )
    else {
      throw StageBMessageCodecError.pathMismatch
    }
    guard
      StageBMessageCodec.constantTimeEquals(
        Array(
          encoded[
            StageBMessageCodec.offsetBindingDigest
              ..< StageBMessageCodec.offsetBindingDigest + 32
          ]
        ),
        binding.bindingSHA256
      )
    else {
      throw StageBMessageCodecError.bindingMismatch
    }
    let requestedAt = StageBMessageCodec.readUInt64(
      encoded,
      at: StageBMessageCodec.offsetRequestedAt
    )
    let deadline = StageBMessageCodec.readUInt64(
      encoded,
      at: StageBMessageCodec.offsetDeadline
    )
    guard requestedAt == binding.requestedAtMonotonicNanoseconds,
      deadline == binding.deadlineMonotonicNanoseconds
    else {
      throw StageBMessageCodecError.deadlineMismatch
    }

    guard let expected = phase.expected else {
      throw StageBMessageCodecError.terminated
    }
    // A side never decodes its own role's messages.
    guard kind.role != role, expected.role != role else {
      throw StageBMessageCodecError.outOfOrder
    }
    guard kind == expected.kind || kind == .terminalResponse else {
      throw StageBMessageCodecError.outOfOrder
    }

    let sequence = StageBMessageCodec.readUInt64(
      encoded,
      at: StageBMessageCodec.offsetSequence
    )
    // Range first, so an out-of-band sequence is rejected as its own field
    // error rather than as an ordinary gap.
    guard sequence >= 1,
      sequence <= StageBMessageCodec.maximumSequence
    else {
      throw StageBMessageCodecError.sequenceOutOfRange
    }
    guard sequence >= nextSequence else {
      throw StageBMessageCodecError.staleSequence
    }
    guard sequence == nextSequence else {
      throw StageBMessageCodecError.sequenceGap
    }

    let chain = Array(
      encoded[
        StageBMessageCodec.offsetChain
          ..< StageBMessageCodec.offsetChain + 32
      ]
    )
    guard
      StageBMessageCodec.constantTimeEquals(chain, expectedChain)
    else {
      throw StageBMessageCodecError.chainMismatch
    }

    let payload = Array(
      encoded[StageBMessageCodec.headerBytes ..< encoded.count]
    )
    let body = try decodePayload(kind: kind, payload: payload)

    advanceLocked(kind: kind, encoded: encoded)
    return StageBMessage(
      kind: kind,
      sequence: sequence,
      chain: chain,
      body: body
    )
  }

  private func advanceLocked(kind: StageBMessageKind, encoded: [UInt8]) {
    expectedChain = StageBMessageCodec.chainDigest(ofMessage: encoded)
    nextSequence += 1
    phase = kind == .terminalResponse ? .terminated : phase.next
  }

  // MARK: Payload

  private func encodePayload(
    kind: StageBMessageKind,
    body: StageBMessageBody
  ) throws -> [UInt8] {
    switch (kind, body) {
    case (.prepareDNSRequest, .empty),
      (.dnsSentAck, .empty),
      (.dnsResponseAck, .empty),
      (.prepareReflectorRequest, .empty),
      (.reflectorSentAck, .empty):
      return []

    case let (.prepareDNSReply, .dnsPrepare(endpoint, query)):
      guard !query.isEmpty else {
        throw StageBMessageCodecError.payloadTooSmall
      }
      guard query.count <= StageBMessageCodec.maximumDNSQueryBytes else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      return Self.encodeEndpoint(endpoint) + query

    case let (
      .prepareReflectorReply, .reflectorPrepare(endpoint, datagram)
    ):
      guard !datagram.isEmpty else {
        throw StageBMessageCodecError.payloadTooSmall
      }
      guard
        datagram.count
          <= StageBMessageCodec.maximumReflectorRequestBytes
      else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      return Self.encodeEndpoint(endpoint) + datagram

    case let (.dnsSent, .sendAcknowledgement(digest)),
      let (.reflectorSent, .sendAcknowledgement(digest)):
      guard StageBMessageCodec.isNonzeroDigest(digest) else {
        throw StageBMessageCodecError.invalidDigest
      }
      return digest

    case let (.dnsResponse, .datagram(bytes)):
      guard !bytes.isEmpty else {
        throw StageBMessageCodecError.payloadTooSmall
      }
      guard
        bytes.count <= StageBMessageCodec.maximumDNSResponseBytes
      else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      return bytes

    case let (.reflectorResponse, .datagram(bytes)):
      guard !bytes.isEmpty else {
        throw StageBMessageCodecError.payloadTooSmall
      }
      guard
        bytes.count
          <= StageBMessageCodec.maximumReflectorResponseBytes
      else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      return bytes

    case let (.terminalResponse, .terminal(report)):
      try requireTerminalTiming(report)
      return [
        report.outcome.rawValue,
        report.failureCode,
        0, 0,
      ]
        + StageBMessageCodec.bigEndian(
          report.dataCompleteMonotonicNanoseconds
        )
        + [
          report.freshAWGHandshake ? 1 : 0,
          report.authenticatedTunnelBytes ? 1 : 0,
          report.protectedDNSResponse ? 1 : 0,
          report.authenticatedReflectorResponse ? 1 : 0,
        ]

    default:
      throw StageBMessageCodecError.outOfOrder
    }
  }

  private func decodePayload(
    kind: StageBMessageKind,
    payload: [UInt8]
  ) throws -> StageBMessageBody {
    switch kind {
    case .prepareDNSRequest, .dnsSentAck, .dnsResponseAck,
      .prepareReflectorRequest, .reflectorSentAck:
      return .empty

    case .prepareDNSReply:
      let endpoint = try Self.decodeEndpoint(payload)
      let query = Array(
        payload[StageBPrivateEndpoint.encodedBytes ..< payload.count]
      )
      guard query.count <= StageBMessageCodec.maximumDNSQueryBytes else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      return .dnsPrepare(endpoint: endpoint, query: query)

    case .prepareReflectorReply:
      let endpoint = try Self.decodeEndpoint(payload)
      let datagram = Array(
        payload[StageBPrivateEndpoint.encodedBytes ..< payload.count]
      )
      guard
        datagram.count
          <= StageBMessageCodec.maximumReflectorRequestBytes
      else {
        throw StageBMessageCodecError.payloadTooLarge
      }
      return .reflectorPrepare(
        endpoint: endpoint,
        requestDatagram: datagram
      )

    case .dnsSent, .reflectorSent:
      guard StageBMessageCodec.isNonzeroDigest(payload) else {
        throw StageBMessageCodecError.invalidDigest
      }
      return .sendAcknowledgement(datagramSHA256: payload)

    case .dnsResponse, .reflectorResponse:
      return .datagram(payload)

    case .terminalResponse:
      guard
        let outcome = StageBTerminalOutcome(rawValue: payload[0])
      else {
        throw StageBMessageCodecError.invalidTerminalReport
      }
      guard payload[2] == 0, payload[3] == 0 else {
        throw StageBMessageCodecError.nonzeroReserved
      }
      // Predicate bytes are strictly 0 or 1; "any nonzero is true" would let
      // a mutated byte survive as a valid report.
      for index in 12 ..< 16 {
        guard payload[index] <= 1 else {
          throw StageBMessageCodecError.invalidTerminalReport
        }
      }
      let report = try StageBTerminalReport(
        outcome: outcome,
        failureCode: payload[1],
        dataCompleteMonotonicNanoseconds:
          StageBMessageCodec.readUInt64(payload, at: 4),
        freshAWGHandshake: payload[12] == 1,
        authenticatedTunnelBytes: payload[13] == 1,
        protectedDNSResponse: payload[14] == 1,
        authenticatedReflectorResponse: payload[15] == 1
      )
      try requireTerminalTiming(report)
      return .terminal(report)
    }
  }

  private func requireTerminalTiming(
    _ report: StageBTerminalReport
  ) throws {
    let time = report.dataCompleteMonotonicNanoseconds
    guard time >= binding.requestedAtMonotonicNanoseconds else {
      throw StageBMessageCodecError.invalidTerminalReport
    }
    switch report.outcome {
    case .success:
      guard time <= binding.deadlineMonotonicNanoseconds else {
        throw StageBMessageCodecError.invalidTerminalReport
      }
    case .failure:
      guard
        time
          <= binding.deadlineMonotonicNanoseconds
          + StageBMessageCodec.terminalSlackNanoseconds
      else {
        throw StageBMessageCodecError.invalidTerminalReport
      }
    }
  }

  private static func encodeEndpoint(
    _ endpoint: StageBPrivateEndpoint
  ) -> [UInt8] {
    var slot = [UInt8](repeating: 0, count: 16)
    slot.replaceSubrange(0 ..< endpoint.address.count, with: endpoint.address)
    return [endpoint.family.rawValue] + slot
      + StageBMessageCodec.bigEndian(endpoint.port)
  }

  private static func decodeEndpoint(
    _ payload: [UInt8]
  ) throws -> StageBPrivateEndpoint {
    guard payload.count > StageBPrivateEndpoint.encodedBytes else {
      throw StageBMessageCodecError.payloadTooSmall
    }
    guard let family = StageBEndpointFamily(rawValue: payload[0]) else {
      throw StageBMessageCodecError.invalidEndpoint
    }
    let address = Array(payload[1 ..< 1 + family.addressBytes])
    // The unused tail of the 16-byte address slot is reserved zero.
    guard payload[(1 + family.addressBytes) ..< 17].allSatisfy({ $0 == 0 })
    else {
      throw StageBMessageCodecError.nonzeroReserved
    }
    let port = StageBMessageCodec.readUInt16(payload, at: 17)
    return try StageBPrivateEndpoint(
      family: family,
      address: address,
      port: port
    )
  }
}

// MARK: - Host transcript

/// The containing app's half of the Stage B channel.
///
/// This type has no method that can produce a provider message, so the host
/// cannot forge a reply to itself, and it can only originate the one host kind
/// its current phase is waiting for.
public final class StageBHostMessageTranscript: @unchecked Sendable {
  private let engine: StageBMessageTranscriptEngine

  public init(binding: StageBMessageAttemptBinding) {
    engine = StageBMessageTranscriptEngine(binding: binding, role: .host)
  }

  public var phase: StageBMessagePhase { engine.currentPhase }

  public func encodePrepareDNSRequest() throws -> [UInt8] {
    try engine.encode(.prepareDNSRequest, body: .empty)
  }

  public func encodeDNSSent(
    requestDatagramSHA256 digest: [UInt8]
  ) throws -> [UInt8] {
    try engine.encode(
      .dnsSent,
      body: .sendAcknowledgement(datagramSHA256: digest)
    )
  }

  public func encodeDNSResponse(_ bytes: [UInt8]) throws -> [UInt8] {
    try engine.encode(.dnsResponse, body: .datagram(bytes))
  }

  public func encodePrepareReflectorRequest() throws -> [UInt8] {
    try engine.encode(.prepareReflectorRequest, body: .empty)
  }

  public func encodeReflectorSent(
    requestDatagramSHA256 digest: [UInt8]
  ) throws -> [UInt8] {
    try engine.encode(
      .reflectorSent,
      body: .sendAcknowledgement(datagramSHA256: digest)
    )
  }

  public func encodeReflectorResponse(
    _ bytes: [UInt8]
  ) throws -> [UInt8] {
    try engine.encode(.reflectorResponse, body: .datagram(bytes))
  }

  public func decode(_ encoded: [UInt8]) throws -> StageBMessage {
    try engine.decode(encoded)
  }

  /// Bounds the input before it is copied out of `Data`.
  ///
  /// `count` is read without copying, so an over-length datagram is never
  /// materialized. A transcript that is already terminated reports
  /// `.terminated` rather than `.messageTooLarge`, at every size.
  public func decode(_ encoded: Data) throws -> StageBMessage {
    guard encoded.count <= StageBMessageCodec.maximumMessageBytes else {
      throw engine.rejectOversized()
    }
    return try engine.decode([UInt8](encoded))
  }
}

// MARK: - Provider transcript

/// The Packet Tunnel provider's half of the Stage B channel.
public final class StageBProviderMessageTranscript: @unchecked Sendable {
  private let engine: StageBMessageTranscriptEngine

  public init(binding: StageBMessageAttemptBinding) {
    engine = StageBMessageTranscriptEngine(
      binding: binding,
      role: .provider
    )
  }

  public var phase: StageBMessagePhase { engine.currentPhase }

  public func encodePrepareDNSReply(
    endpoint: StageBPrivateEndpoint,
    query: [UInt8]
  ) throws -> [UInt8] {
    try engine.encode(
      .prepareDNSReply,
      body: .dnsPrepare(endpoint: endpoint, query: query)
    )
  }

  public func encodeDNSSentAck() throws -> [UInt8] {
    try engine.encode(.dnsSentAck, body: .empty)
  }

  public func encodeDNSResponseAck() throws -> [UInt8] {
    try engine.encode(.dnsResponseAck, body: .empty)
  }

  public func encodePrepareReflectorReply(
    endpoint: StageBPrivateEndpoint,
    requestDatagram: [UInt8]
  ) throws -> [UInt8] {
    try engine.encode(
      .prepareReflectorReply,
      body: .reflectorPrepare(
        endpoint: endpoint,
        requestDatagram: requestDatagram
      )
    )
  }

  public func encodeReflectorSentAck() throws -> [UInt8] {
    try engine.encode(.reflectorSentAck, body: .empty)
  }

  public func encodeTerminalResponse(
    _ report: StageBTerminalReport
  ) throws -> [UInt8] {
    try engine.encode(.terminalResponse, body: .terminal(report))
  }

  public func decode(_ encoded: [UInt8]) throws -> StageBMessage {
    try engine.decode(encoded)
  }

  /// Bounds the input before it is copied out of `Data`.
  ///
  /// `count` is read without copying, so an over-length datagram is never
  /// materialized. A transcript that is already terminated reports
  /// `.terminated` rather than `.messageTooLarge`, at every size.
  public func decode(_ encoded: Data) throws -> StageBMessage {
    guard encoded.count <= StageBMessageCodec.maximumMessageBytes else {
      throw engine.rejectOversized()
    }
    return try engine.decode([UInt8](encoded))
  }
}
