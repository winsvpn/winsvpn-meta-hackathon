import CryptoKit
import Foundation
import WinnPrivacyCore

public enum StageBProviderValidationError: Error, Equatable, Sendable {
  case invalidIdentifier
  case invalidDigest
  case invalidGeneration
  case invalidDeadline
  case invalidAWGSnapshot
  case bindingMismatch
  case counterReset
  case handshakeReset
  case invalidDNSProof
  case dnsRequestNotSent
  case reflectorRequestNotSent
  case invalidReflectorProof
  case deadlineExceeded
  case coreRejected
  /// A sample was produced by a capture source that is not this attempt's.
  case foreignNativeProvenance
  /// A sample's native capture time is missing, reversed, or in the future
  /// relative to the coordinator's own monotonic authority.
  case invalidSampleTime
  /// A probe was offered before the predicate it must build on was proven.
  case predicateLadderViolation
  /// The reflector was driven before an accepted protected-DNS proof.
  case dnsProofNotAccepted
  /// A probe tried to reuse another probe's counter movement.
  case probeMovementNotIndependent
  /// The DNS response bytes are not a well-formed answer to this probe.
  case invalidDNSWireResponse
}

public enum StageBProviderStatus: String, Equatable, Sendable {
  case active
  case succeeded
  case failed
  case cancelled
  case superseded
}

public enum StageBProviderInputDisposition: Equatable, Sendable {
  case accepted
  case coalesced
  case ignoredTerminal
}

public enum StageBProviderTimerDirective: Equatable, Sendable {
  case rearm(atMonotonicNanoseconds: UInt64)
  case terminal
  case ignoredTerminal
}

/// Immutable, non-secret identity of the exact native engine instance and
/// winning virtual path carrying one Stage B attempt.
///
/// `winningInterfaceTokenSHA256` is the digest of a per-instance opaque token
/// supplied by the adapter. It is not an interface name, address, descriptor,
/// or Apple identifier. `engineInstanceNonce` is the raw 16-byte UUID value,
/// not Foundation's permissively parsed textual representation.
public struct StageBAWGEnginePathIdentity: Equatable, Sendable {
  public let signedRuntimeArtifactSHA256: [UInt8]
  public let wgTurnOnConfigSHA256: [UInt8]
  public let expectedPeerPublicKeySHA256: [UInt8]
  public let engineInstanceNonce: [UInt8]
  public let engineGeneration: UInt64
  public let pathGeneration: UInt64
  public let winningInterfaceTokenSHA256: [UInt8]

  public init(
    signedRuntimeArtifactSHA256: [UInt8],
    wgTurnOnConfigSHA256: [UInt8],
    expectedPeerPublicKeySHA256: [UInt8],
    engineInstanceNonce: [UInt8],
    engineGeneration: UInt64,
    pathGeneration: UInt64,
    winningInterfaceTokenSHA256: [UInt8]
  ) throws {
    for digest in [
      signedRuntimeArtifactSHA256,
      wgTurnOnConfigSHA256,
      expectedPeerPublicKeySHA256,
      winningInterfaceTokenSHA256,
    ] {
      guard
        StageBProviderPathBinding.validNonzero(digest, count: 32)
      else {
        throw StageBProviderValidationError.invalidDigest
      }
    }
    guard
      StageBProviderPathBinding.isCanonicalUUIDv4(engineInstanceNonce)
    else {
      throw StageBProviderValidationError.invalidIdentifier
    }
    guard engineGeneration > 0, pathGeneration > 0 else {
      throw StageBProviderValidationError.invalidGeneration
    }
    self.signedRuntimeArtifactSHA256 =
      Array(signedRuntimeArtifactSHA256)
    self.wgTurnOnConfigSHA256 = Array(wgTurnOnConfigSHA256)
    self.expectedPeerPublicKeySHA256 =
      Array(expectedPeerPublicKeySHA256)
    self.engineInstanceNonce = Array(engineInstanceNonce)
    self.engineGeneration = engineGeneration
    self.pathGeneration = pathGeneration
    self.winningInterfaceTokenSHA256 =
      Array(winningInterfaceTokenSHA256)
  }
}

/// Non-secret binding for the exact engine identity, virtual path, and WCF3
/// context carrying Stage B.
public struct StageBProviderPathBinding: Equatable, Sendable {
  public let pathID: [UInt8]
  public let identity: StageBAWGEnginePathIdentity
  public let context: WCF3ConnectionContext

  public init(
    pathID: [UInt8],
    identity: StageBAWGEnginePathIdentity,
    context: WCF3ConnectionContext
  ) throws {
    guard Self.isCanonicalUUIDv4(pathID) else {
      throw StageBProviderValidationError.invalidIdentifier
    }
    self.pathID = Array(pathID)
    self.identity = identity
    self.context = context
  }

  fileprivate static func validNonzero(
    _ bytes: [UInt8],
    count: Int
  ) -> Bool {
    bytes.count == count && !bytes.allSatisfy { $0 == 0 }
  }

  fileprivate static func isCanonicalUUIDv4(
    _ bytes: [UInt8]
  ) -> Bool {
    bytes.count == 16
      && bytes[6] & 0xf0 == 0x40
      && bytes[8] & 0xc0 == 0x80
  }
}

public struct StageBAWGPeerSnapshot: Equatable, Sendable {
  public let peerPublicKeySHA256: [UInt8]
  /// Raw native AWG `latest-handshake` wall-clock seconds.
  ///
  /// Zero means no completed handshake has been observed. This value is never
  /// converted to the coordinator's monotonic clock. The coordinator trusts
  /// only strict advancement of this raw engine telemetry and records its own
  /// monotonic observation time when the advancement is received.
  public let latestHandshakeUnixSeconds: UInt64
  /// Raw native AWG handshake nanosecond remainder.
  public let latestHandshakeNanoseconds: UInt32
  /// Checked, lossless-to-millisecond conversion used by physical evidence.
  ///
  /// Native telemetry validation constructs this value only after proving
  /// `seconds * 1000 + nanoseconds / 1_000_000` cannot overflow.
  public let latestHandshakeUnixMilliseconds: UInt64
  public let receivedBytes: UInt64
  public let transmittedBytes: UInt64

  public init(
    peerPublicKeySHA256: [UInt8],
    latestHandshakeUnixSeconds: UInt64,
    latestHandshakeNanoseconds: UInt32 = 0,
    receivedBytes: UInt64,
    transmittedBytes: UInt64
  ) throws {
    guard
      StageBProviderPathBinding.validNonzero(
        peerPublicKeySHA256,
        count: 32
      )
    else {
      throw StageBProviderValidationError.invalidDigest
    }
    guard latestHandshakeNanoseconds < 1_000_000_000 else {
      throw StageBProviderValidationError.invalidAWGSnapshot
    }
    let fractionalMilliseconds =
      UInt64(latestHandshakeNanoseconds) / 1_000_000
    guard
      latestHandshakeUnixSeconds
        <= (UInt64.max - fractionalMilliseconds) / 1_000
    else {
      throw StageBProviderValidationError.invalidAWGSnapshot
    }
    self.peerPublicKeySHA256 = Array(peerPublicKeySHA256)
    self.latestHandshakeUnixSeconds = latestHandshakeUnixSeconds
    self.latestHandshakeNanoseconds = latestHandshakeNanoseconds
    self.latestHandshakeUnixMilliseconds =
      latestHandshakeUnixSeconds * 1_000 + fractionalMilliseconds
    self.receivedBytes = receivedBytes
    self.transmittedBytes = transmittedBytes
  }
}

/// One bounded native AWG peer telemetry observation.
///
/// This value crosses the native/Core boundary without carrying a raw UAPI
/// buffer. It contains only the exact peer key and numeric telemetry needed by
/// Stage B. Its throwing initializer rejects malformed peer keys, invalid
/// nanosecond remainders, and handshake times that cannot be represented
/// losslessly at the millisecond precision used by physical evidence.
///
/// This is typed local telemetry, not cryptographic authentication of hostile
/// code and not proof that any particular device or kernel produced it.
public struct StageBAWGNativePeerTelemetry: Equatable, Sendable {
  public static let peerPublicKeyByteCount = 32
  public static let maximumHandshakeNanoseconds: UInt32 =
    999_999_999

  public let peerPublicKey: [UInt8]
  public let latestHandshakeUnixSeconds: UInt64
  public let latestHandshakeNanoseconds: UInt32
  public let receivedBytes: UInt64
  public let transmittedBytes: UInt64

  public init(
    peerPublicKey: [UInt8],
    latestHandshakeUnixSeconds: UInt64,
    latestHandshakeNanoseconds: UInt32,
    receivedBytes: UInt64,
    transmittedBytes: UInt64
  ) throws {
    guard
      StageBProviderPathBinding.validNonzero(
        peerPublicKey,
        count: Self.peerPublicKeyByteCount
      )
    else {
      throw StageBProviderValidationError.invalidDigest
    }
    guard
      latestHandshakeNanoseconds
        <= Self.maximumHandshakeNanoseconds
    else {
      throw StageBProviderValidationError.invalidAWGSnapshot
    }
    let fractionalMilliseconds =
      UInt64(latestHandshakeNanoseconds) / 1_000_000
    guard
      latestHandshakeUnixSeconds
        <= (UInt64.max - fractionalMilliseconds) / 1_000
    else {
      throw StageBProviderValidationError.invalidAWGSnapshot
    }
    self.peerPublicKey = Array(peerPublicKey)
    self.latestHandshakeUnixSeconds = latestHandshakeUnixSeconds
    self.latestHandshakeNanoseconds = latestHandshakeNanoseconds
    self.receivedBytes = receivedBytes
    self.transmittedBytes = transmittedBytes
  }

  fileprivate func makePeerSnapshot() throws -> StageBAWGPeerSnapshot {
    try StageBAWGPeerSnapshot(
      peerPublicKeySHA256: Array(
        SHA256.hash(data: Data(peerPublicKey))
      ),
      latestHandshakeUnixSeconds: latestHandshakeUnixSeconds,
      latestHandshakeNanoseconds: latestHandshakeNanoseconds,
      receivedBytes: receivedBytes,
      transmittedBytes: transmittedBytes
    )
  }
}

/// Identity of one native AWG capture path.
///
/// The type carries no value and compares by object identity. Instances exist
/// only inside `StageBAWGNativeCaptureSource`, whose initializer is not public
/// and whose only public factory is `StageBProviderEnvironment`. Copying the
/// bytes of a sample therefore cannot reproduce its provenance.
public final class StageBAWGNativeProvenance: Equatable, Sendable {
  fileprivate let clockAuthority: StageBProviderMonotonicAuthority

  fileprivate init(clockAuthority: StageBProviderMonotonicAuthority) {
    self.clockAuthority = clockAuthority
  }

  public static func == (
    lhs: StageBAWGNativeProvenance,
    rhs: StageBAWGNativeProvenance
  ) -> Bool {
    lhs === rhs
  }
}

/// One bounded, already-typed exact-peer AWG observation.
///
/// A value of this type can be produced only by
/// `StageBAWGNativeCaptureSource.capture()`: the initializer is internal to
/// this module, so no adapter, host, or test outside the module can construct
/// one. `provenance` names the capture source that produced it and
/// `sampledAtMonotonicNanoseconds` is read from that source's shared monotonic
/// authority, not supplied by a caller.
///
/// This type has no collection initializer and can represent exactly one peer
/// only. The coordinator validates every generation and WCF3 binding against
/// the winning attempt.
public struct StageBAWGSnapshot: Equatable, Sendable {
  public let binding: StageBProviderPathBinding
  public let peer: StageBAWGPeerSnapshot
  public let provenance: StageBAWGNativeProvenance
  /// Monotonic time read immediately before the native UAPI read began.
  public let sampleStartedAtMonotonicNanoseconds: UInt64
  /// Monotonic time read immediately after the native UAPI read returned.
  ///
  /// This is the sample time physical evidence records. It is never a message
  /// acceptance time and is never supplied by a caller.
  public let sampledAtMonotonicNanoseconds: UInt64

  init(
    binding: StageBProviderPathBinding,
    peer: StageBAWGPeerSnapshot,
    provenance: StageBAWGNativeProvenance,
    sampleStartedAtMonotonicNanoseconds: UInt64,
    sampledAtMonotonicNanoseconds: UInt64
  ) throws {
    guard
      sampledAtMonotonicNanoseconds
        >= sampleStartedAtMonotonicNanoseconds
    else {
      throw StageBProviderValidationError.invalidSampleTime
    }
    self.binding = binding
    self.peer = peer
    self.provenance = provenance
    self.sampleStartedAtMonotonicNanoseconds =
      sampleStartedAtMonotonicNanoseconds
    self.sampledAtMonotonicNanoseconds =
      sampledAtMonotonicNanoseconds
  }
}

/// The only way to obtain a `StageBAWGSnapshot`.
///
/// One source owns one immutable path binding, expected peer public key, and
/// typed native telemetry closure. It proves at construction that the expected
/// key is the preimage of the binding's `expectedPeerPublicKeySHA256`. Every
/// no-argument capture brackets that bound closure with two reads of the
/// environment's shared monotonic authority, so callers cannot inject bytes,
/// peer identity, path identity, or time at capture.
public final class StageBAWGNativeCaptureSource: Sendable {
  private let binding: StageBProviderPathBinding
  private let expectedPeerPublicKey: [UInt8]
  private let clockAuthority: StageBProviderMonotonicAuthority
  private let readNativeTelemetry: @Sendable () throws ->
    StageBAWGNativePeerTelemetry
  fileprivate let provenance: StageBAWGNativeProvenance

  fileprivate init(
    binding: StageBProviderPathBinding,
    expectedPeerPublicKey: [UInt8],
    clockAuthority: StageBProviderMonotonicAuthority,
    readNativeTelemetry:
      @escaping @Sendable () throws -> StageBAWGNativePeerTelemetry
  ) throws {
    guard
      StageBProviderPathBinding.validNonzero(
        expectedPeerPublicKey,
        count: StageBAWGNativePeerTelemetry.peerPublicKeyByteCount
      )
    else {
      throw StageBProviderValidationError.invalidDigest
    }
    guard
      Array(SHA256.hash(data: Data(expectedPeerPublicKey)))
        == binding.identity.expectedPeerPublicKeySHA256
    else {
      throw StageBProviderValidationError.bindingMismatch
    }
    self.binding = binding
    self.expectedPeerPublicKey = Array(expectedPeerPublicKey)
    self.clockAuthority = clockAuthority
    self.readNativeTelemetry = readNativeTelemetry
    provenance = StageBAWGNativeProvenance(
      clockAuthority: clockAuthority
    )
  }

  /// Brackets the source-bound typed telemetry closure and returns one sample.
  public func capture() throws -> StageBAWGSnapshot {
    let started = try clockAuthority.read()
    let telemetry = try readNativeTelemetry()
    let sampled = try clockAuthority.read()
    guard telemetry.peerPublicKey == expectedPeerPublicKey else {
      throw StageBProviderValidationError.bindingMismatch
    }
    let peer = try telemetry.makePeerSnapshot()
    return try StageBAWGSnapshot(
      binding: binding,
      peer: peer,
      provenance: provenance,
      sampleStartedAtMonotonicNanoseconds: started,
      sampledAtMonotonicNanoseconds: sampled
    )
  }
}

/// Opaque, non-Boolean identity of one cache-bypassing private DNS probe.
public struct StageBDNSProbeBinding: Equatable, Sendable {
  public let transactionID: UInt16
  public let questionSHA256: [UInt8]
  public let cacheBypassNonceSHA256: [UInt8]
  public let privateResolverIdentitySHA256: [UInt8]

  public init(
    transactionID: UInt16,
    questionSHA256: [UInt8],
    cacheBypassNonceSHA256: [UInt8],
    privateResolverIdentitySHA256: [UInt8]
  ) throws {
    guard transactionID > 0 else {
      throw StageBProviderValidationError.invalidDNSProof
    }
    for digest in [
      questionSHA256,
      cacheBypassNonceSHA256,
      privateResolverIdentitySHA256,
    ] {
      guard StageBProviderPathBinding.validNonzero(digest, count: 32)
      else {
        throw StageBProviderValidationError.invalidDigest
      }
    }
    self.transactionID = transactionID
    self.questionSHA256 = Array(questionSHA256)
    self.cacheBypassNonceSHA256 = Array(cacheBypassNonceSHA256)
    self.privateResolverIdentitySHA256 =
      Array(privateResolverIdentitySHA256)
  }
}

public struct StageBProtectedDNSRequestSendProof: Equatable, Sendable {
  public let probe: StageBDNSProbeBinding
  public let binding: StageBProviderPathBinding
  public let preRequestAWGSnapshot: StageBAWGSnapshot

  public init(
    probe: StageBDNSProbeBinding,
    binding: StageBProviderPathBinding,
    preRequestAWGSnapshot: StageBAWGSnapshot
  ) {
    self.probe = probe
    self.binding = binding
    self.preRequestAWGSnapshot = preRequestAWGSnapshot
  }
}

/// The exact DNS response bytes observed on the protected path.
///
/// This proof carries wire bytes, not a caller-computed digest. The
/// coordinator parses the header and question, checks them against the
/// attempt's probe binding, and computes the payload digest itself. There is
/// deliberately no digest-only entry point for a caller to use instead.
public struct StageBProtectedDNSProof: Equatable, Sendable {
  public let probe: StageBDNSProbeBinding
  public let responsePayload: Data
  public let binding: StageBProviderPathBinding
  public let preRequestAWGSnapshot: StageBAWGSnapshot
  public let postResponseAWGSnapshot: StageBAWGSnapshot

  public init(
    probe: StageBDNSProbeBinding,
    responsePayload: Data,
    binding: StageBProviderPathBinding,
    preRequestAWGSnapshot: StageBAWGSnapshot,
    postResponseAWGSnapshot: StageBAWGSnapshot
  ) {
    self.probe = probe
    self.responsePayload = responsePayload
    self.binding = binding
    self.preRequestAWGSnapshot = preRequestAWGSnapshot
    self.postResponseAWGSnapshot = postResponseAWGSnapshot
  }
}

public struct StageBReflectorRequestSendProof: Equatable, Sendable {
  public let requestDatagramSHA256: [UInt8]
  public let binding: StageBProviderPathBinding
  public let preSendAWGSnapshot: StageBAWGSnapshot

  public init(
    requestDatagramSHA256: [UInt8],
    binding: StageBProviderPathBinding,
    preSendAWGSnapshot: StageBAWGSnapshot
  ) throws {
    guard
      StageBProviderPathBinding.validNonzero(
        requestDatagramSHA256,
        count: 32
      )
    else {
      throw StageBProviderValidationError.invalidDigest
    }
    self.requestDatagramSHA256 = Array(requestDatagramSHA256)
    self.binding = binding
    self.preSendAWGSnapshot = preSendAWGSnapshot
  }
}

public struct StageBReflectorResponseProof: Equatable, Sendable {
  public let responseDatagram: Data
  public let binding: StageBProviderPathBinding
  public let postResponseAWGSnapshot: StageBAWGSnapshot

  public init(
    responseDatagram: Data,
    binding: StageBProviderPathBinding,
    postResponseAWGSnapshot: StageBAWGSnapshot
  ) {
    self.responseDatagram = responseDatagram
    self.binding = binding
    self.postResponseAWGSnapshot = postResponseAWGSnapshot
  }
}

public struct StageBProviderAttemptConfiguration: Equatable, Sendable {
  public let runID: [UInt8]
  public let attemptNonce: [UInt8]
  public let sourceSHA256: [UInt8]
  public let artifactSHA256: [UInt8]
  public let expectedPeerPublicKeySHA256: [UInt8]
  public let path: StageBProviderPathBinding
  public let canarySequence: UInt64
  public let issuedAtUnixMilliseconds: UInt64
  public let expiresAtUnixMilliseconds: UInt64
  public let challenge: [UInt8]
  public let dnsProbe: StageBDNSProbeBinding
  public let dnsResponsePayloadSHA256: [UInt8]
  /// The host's first-click T0. It is copied unchanged into the lease.
  public let requestedAtMonotonicNanoseconds: UInt64

  public init(
    runID: [UInt8],
    attemptNonce: [UInt8],
    sourceSHA256: [UInt8],
    artifactSHA256: [UInt8],
    expectedPeerPublicKeySHA256: [UInt8],
    path: StageBProviderPathBinding,
    canarySequence: UInt64,
    issuedAtUnixMilliseconds: UInt64,
    expiresAtUnixMilliseconds: UInt64,
    challenge: [UInt8],
    dnsProbe: StageBDNSProbeBinding,
    dnsResponsePayloadSHA256: [UInt8],
    requestedAtMonotonicNanoseconds: UInt64
  ) throws {
    let identifiers = [
      runID,
      attemptNonce,
      path.pathID,
      path.context.sessionID,
      path.context.bindingID,
      path.identity.engineInstanceNonce,
    ]
    guard
      identifiers.allSatisfy(
        StageBProviderPathBinding.isCanonicalUUIDv4
      ),
      Set(identifiers).count == identifiers.count
    else {
      throw StageBProviderValidationError.invalidIdentifier
    }
    for digest in [
      sourceSHA256,
      artifactSHA256,
      expectedPeerPublicKeySHA256,
      challenge,
      dnsResponsePayloadSHA256,
    ] {
      guard
        StageBProviderPathBinding.validNonzero(
          digest,
          count: 32
        )
      else {
        throw StageBProviderValidationError.invalidDigest
      }
    }
    guard canarySequence > 0 else {
      throw StageBProviderValidationError.invalidIdentifier
    }
    guard
      artifactSHA256
        == path.identity.signedRuntimeArtifactSHA256,
      expectedPeerPublicKeySHA256
        == path.identity.expectedPeerPublicKeySHA256
    else {
      throw StageBProviderValidationError.bindingMismatch
    }
    self.runID = Array(runID)
    self.attemptNonce = Array(attemptNonce)
    self.sourceSHA256 = Array(sourceSHA256)
    self.artifactSHA256 = Array(artifactSHA256)
    self.expectedPeerPublicKeySHA256 =
      Array(expectedPeerPublicKeySHA256)
    self.path = path
    self.canarySequence = canarySequence
    self.issuedAtUnixMilliseconds = issuedAtUnixMilliseconds
    self.expiresAtUnixMilliseconds = expiresAtUnixMilliseconds
    self.challenge = Array(challenge)
    self.dnsProbe = dnsProbe
    self.dnsResponsePayloadSHA256 =
      Array(dnsResponsePayloadSHA256)
    self.requestedAtMonotonicNanoseconds =
      requestedAtMonotonicNanoseconds
  }
}

public struct StageBProviderLocalSnapshot: Equatable, Sendable {
  public let schema: String
  public let protocolVersion: String
  public let measurementScope: String
  public let status: StageBProviderStatus
  public let failure: StageBProviderValidationError?
  public let requestedAtMonotonicNanoseconds: UInt64
  public let deadlineMonotonicNanoseconds: UInt64
  public let reflectorRequestSent: Bool
  public let freshAWGHandshake: Bool
  public let authenticatedTunnelBytes: Bool
  public let protectedDNSResponse: Bool
  public let authenticatedReflectorResponse: Bool

  fileprivate init(
    status: StageBProviderStatus,
    failure: StageBProviderValidationError?,
    lease: StageBAttemptLease,
    reflectorRequestSent: Bool,
    freshAWGHandshake: Bool,
    authenticatedTunnelBytes: Bool,
    protectedDNSResponse: Bool,
    authenticatedReflectorResponse: Bool
  ) {
    schema = "winn-stageb-provider-local-snapshot/1"
    protocolVersion = StageBProtectedFlow.protocolVersion
    measurementScope = StageBProtectedFlow.receiptScope
    self.status = status
    self.failure = failure
    requestedAtMonotonicNanoseconds =
      lease.requestedAtMonotonicNanoseconds
    deadlineMonotonicNanoseconds =
      lease.deadlineMonotonicNanoseconds
    self.reflectorRequestSent = reflectorRequestSent
    self.freshAWGHandshake = freshAWGHandshake
    self.authenticatedTunnelBytes = authenticatedTunnelBytes
    self.protectedDNSResponse = protectedDNSResponse
    self.authenticatedReflectorResponse =
      authenticatedReflectorResponse
  }
}

/// One native AWG sample as physical evidence records it.
///
/// Every field is copied from a sample the coordinator accepted. The sample
/// time is the capture source's bracketed native read time, never a message
/// acceptance time.
public struct StageBProviderAWGSampleRecord: Equatable, Sendable {
  public let sampledAtMonotonicNanoseconds: UInt64
  public let identity: StageBAWGEnginePathIdentity
  public let peerPublicKeySHA256: [UInt8]
  public let latestHandshakeUnixMilliseconds: UInt64
  public let receivedBytes: UInt64
  public let transmittedBytes: UInt64

  fileprivate init(_ snapshot: StageBAWGSnapshot) {
    sampledAtMonotonicNanoseconds =
      snapshot.sampledAtMonotonicNanoseconds
    identity = snapshot.binding.identity
    peerPublicKeySHA256 = snapshot.peer.peerPublicKeySHA256
    latestHandshakeUnixMilliseconds =
      snapshot.peer.latestHandshakeUnixMilliseconds
    receivedBytes = snapshot.peer.receivedBytes
    transmittedBytes = snapshot.peer.transmittedBytes
  }
}

/// The coordinator's single, immutable, once-emitted terminal record.
///
/// It is produced inside the coordinator's lock at the first terminal
/// transition and never changes afterwards. Every time in it was read by the
/// coordinator's own monotonic authority: predicate times that physical
/// evidence must equal a sample time are that sample's bracketed native read
/// time, and request/response times are the instant the coordinator accepted
/// the corresponding proof under its lock. An evidence producer can fill the
/// physical attempt schema's time and sample fields from this record without
/// reading any clock.
public struct StageBProviderTerminalEvidence: Equatable, Sendable {
  public let schema: String
  public let protocolVersion: String
  public let measurementScope: String
  public let status: StageBProviderStatus
  public let failure: StageBProviderValidationError?
  public let canarySequence: UInt64
  public let requestedAtMonotonicNanoseconds: UInt64
  public let deadlineMonotonicNanoseconds: UInt64
  public let terminalAtMonotonicNanoseconds: UInt64

  public let baselineSample: StageBProviderAWGSampleRecord
  public let handshakePostSample: StageBProviderAWGSampleRecord?
  public let counterPostSample: StageBProviderAWGSampleRecord?
  public let authenticatedOutboundDeltaBytes: UInt64
  public let authenticatedInboundDeltaBytes: UInt64

  public let freshAWGHandshakeAtMonotonicNanoseconds: UInt64?
  public let
    authenticatedBidirectionalBytesAtMonotonicNanoseconds: UInt64?
  public let protectedDNSAtMonotonicNanoseconds: UInt64?
  public let authenticatedReflectorAtMonotonicNanoseconds: UInt64?

  public let dnsAttempted: Bool
  public let dnsRequestSentAtMonotonicNanoseconds: UInt64?
  public let dnsResponseObservedAtMonotonicNanoseconds: UInt64?
  public let dnsQueryNonceSHA256: [UInt8]
  /// SHA-256 the coordinator computed over the DNS response bytes it parsed.
  ///
  /// It is present only when the coordinator accepted wire bytes, so it is
  /// never a caller-asserted digest.
  public let dnsResponsePayloadSHA256: [UInt8]?

  public let reflectorAttempted: Bool
  public let reflectorRequestSentAtMonotonicNanoseconds: UInt64?
  public let reflectorResponseObservedAtMonotonicNanoseconds: UInt64?

  fileprivate init(
    status: StageBProviderStatus,
    failure: StageBProviderValidationError?,
    canarySequence: UInt64,
    lease: StageBAttemptLease,
    terminalAtMonotonicNanoseconds: UInt64,
    baselineSample: StageBProviderAWGSampleRecord,
    handshakePostSample: StageBProviderAWGSampleRecord?,
    counterPostSample: StageBProviderAWGSampleRecord?,
    authenticatedOutboundDeltaBytes: UInt64,
    authenticatedInboundDeltaBytes: UInt64,
    protectedDNSAtMonotonicNanoseconds: UInt64?,
    authenticatedReflectorAtMonotonicNanoseconds: UInt64?,
    dnsRequestSentAtMonotonicNanoseconds: UInt64?,
    dnsQueryNonceSHA256: [UInt8],
    dnsResponsePayloadSHA256: [UInt8]?,
    reflectorRequestSentAtMonotonicNanoseconds: UInt64?
  ) {
    schema = "winn-stageb-provider-terminal-evidence/1"
    protocolVersion = StageBProtectedFlow.protocolVersion
    measurementScope = StageBProtectedFlow.receiptScope
    self.status = status
    self.failure = failure
    self.canarySequence = canarySequence
    requestedAtMonotonicNanoseconds =
      lease.requestedAtMonotonicNanoseconds
    deadlineMonotonicNanoseconds =
      lease.deadlineMonotonicNanoseconds
    self.terminalAtMonotonicNanoseconds =
      terminalAtMonotonicNanoseconds
    self.baselineSample = baselineSample
    self.handshakePostSample = handshakePostSample
    self.counterPostSample = counterPostSample
    self.authenticatedOutboundDeltaBytes =
      authenticatedOutboundDeltaBytes
    self.authenticatedInboundDeltaBytes =
      authenticatedInboundDeltaBytes
    freshAWGHandshakeAtMonotonicNanoseconds =
      handshakePostSample?.sampledAtMonotonicNanoseconds
    authenticatedBidirectionalBytesAtMonotonicNanoseconds =
      counterPostSample?.sampledAtMonotonicNanoseconds
    self.protectedDNSAtMonotonicNanoseconds =
      protectedDNSAtMonotonicNanoseconds
    self.authenticatedReflectorAtMonotonicNanoseconds =
      authenticatedReflectorAtMonotonicNanoseconds
    dnsAttempted = dnsRequestSentAtMonotonicNanoseconds != nil
    self.dnsRequestSentAtMonotonicNanoseconds =
      dnsRequestSentAtMonotonicNanoseconds
    dnsResponseObservedAtMonotonicNanoseconds =
      protectedDNSAtMonotonicNanoseconds
    self.dnsQueryNonceSHA256 = dnsQueryNonceSHA256
    self.dnsResponsePayloadSHA256 = dnsResponsePayloadSHA256
    reflectorAttempted =
      reflectorRequestSentAtMonotonicNanoseconds != nil
    self.reflectorRequestSentAtMonotonicNanoseconds =
      reflectorRequestSentAtMonotonicNanoseconds
    reflectorResponseObservedAtMonotonicNanoseconds =
      authenticatedReflectorAtMonotonicNanoseconds
  }
}

/// Shared provider timing, capture, and response-acceptance authority.
///
/// This is the only public coordinator and capture-source factory. It owns one
/// monotonic clock closure and supplies that exact closure to the acceptance
/// domain, to every coordinator it creates, and to every native capture source
/// it mints, so callers cannot accidentally split timing authority by
/// convention.
public final class StageBProviderEnvironment: @unchecked Sendable {
  private let clockAuthority: StageBProviderMonotonicAuthority
  private let acceptanceDomain: StageBAcceptanceDomain

  public init(
    responseReplayCapacity: Int,
    reflectorKey: [UInt8],
    monotonicClock: @escaping @Sendable () -> UInt64
  ) throws {
    let clockAuthority = StageBProviderMonotonicAuthority(
      source: monotonicClock
    )
    self.clockAuthority = clockAuthority
    acceptanceDomain = try StageBAcceptanceDomain(
      capacity: responseReplayCapacity,
      key: reflectorKey,
      monotonicClock: {
        clockAuthority.readForAcceptanceDomain()
      }
    )
  }

  public var acceptedResponseCount: Int {
    acceptanceDomain.acceptedResponseCount
  }

  public func makeNativeAWGCaptureSource(
    binding: StageBProviderPathBinding,
    expectedPeerPublicKey: [UInt8],
    readNativeTelemetry:
      @escaping @Sendable () throws -> StageBAWGNativePeerTelemetry
  ) throws -> StageBAWGNativeCaptureSource {
    try StageBAWGNativeCaptureSource(
      binding: binding,
      expectedPeerPublicKey: expectedPeerPublicKey,
      clockAuthority: clockAuthority,
      readNativeTelemetry: readNativeTelemetry
    )
  }

  public func makeCoordinator(
    configuration: StageBProviderAttemptConfiguration,
    baseline: StageBAWGSnapshot
  ) throws -> StageBProviderCoordinator {
    try StageBProviderCoordinator(
      configuration: configuration,
      baseline: baseline,
      acceptanceDomain: acceptanceDomain,
      clockAuthority: clockAuthority
    )
  }
}

fileprivate final class StageBProviderMonotonicAuthority:
  @unchecked Sendable
{
  private let source: @Sendable () -> UInt64
  private let lock = NSLock()
  private var watermark: UInt64?
  private var failed = false

  init(source: @escaping @Sendable () -> UInt64) {
    self.source = source
  }

  func read() throws -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    let value = source()
    guard !failed else {
      throw StageBProviderValidationError.invalidDeadline
    }
    if let watermark, value < watermark {
      failed = true
      throw StageBProviderValidationError.invalidDeadline
    }
    watermark = value
    return value
  }

  // StageBAcceptanceDomain's frozen clock signature cannot throw. UInt64.max
  // is outside every constructible coordinator lease, so it is a fail-closed
  // deadline value after this shared authority detects rollback.
  func readForAcceptanceDomain() -> UInt64 {
    (try? read()) ?? UInt64.max
  }
}

/// Pure, deterministic Stage B provider coordinator.
///
/// It deliberately contains no NetworkExtension API. A provider adapter must
/// turn native AWG, DNS, and tunnel-bound reflector observations into the
/// strongly typed values above. All mutable transitions are serialized by one
/// lock, and the first terminal transition wins.
///
/// Acceptance follows one ladder, enforced here rather than described:
/// a fresh AWG handshake, then authenticated bidirectional bytes, then the
/// protected DNS request and its accepted response, then the reflector request
/// and its authenticated response. Each probe must prove its own counter
/// movement: the reflector pre-send sample must show strictly more received
/// and transmitted bytes than the accepted DNS post-response sample, so the
/// adapter must not send the reflector request until protected traffic has
/// moved in both directions after DNS acceptance.
public final class StageBProviderCoordinator: @unchecked Sendable {
  public let lease: StageBAttemptLease
  public let outboundReflectorDatagram: Data

  private let lock = NSLock()
  private let clockAuthority: StageBProviderMonotonicAuthority
  private let expectedProvenance: StageBAWGNativeProvenance
  private let expectedPath: StageBProviderPathBinding
  private let expectedPeerPublicKeySHA256: [UInt8]
  private let expectedDNSProbe: StageBDNSProbeBinding
  private let expectedDNSResponsePayloadSHA256: [UInt8]
  private let canarySequence: UInt64
  private let requestDatagramSHA256: [UInt8]
  private let requestPreparedAtMonotonicNanoseconds: UInt64
  private let baselinePeer: StageBAWGPeerSnapshot
  private let baselineSample: StageBProviderAWGSampleRecord
  private let attempt: StageBProtectedFlowAttempt
  private let eventBinding: StageBEventBinding

  private var providerStatus: StageBProviderStatus = .active
  private var terminalFailure: StageBProviderValidationError?
  private var terminalEvidenceRecord: StageBProviderTerminalEvidence?
  private var lastAWGPeer: StageBAWGPeerSnapshot
  private var lastAcceptedSampleAtMonotonicNanoseconds: UInt64
  private var dnsRequestProof: StageBProtectedDNSRequestSendProof?
  private var dnsRequestSentAtMonotonicNanoseconds: UInt64?
  private var acceptedDNSProof: StageBProtectedDNSProof?
  private var dnsResponseObservedAtMonotonicNanoseconds: UInt64?
  private var observedDNSResponsePayloadSHA256: [UInt8]?
  private var reflectorRequestSent = false
  private var reflectorRequestProof: StageBReflectorRequestSendProof?
  private var reflectorRequestSentAtMonotonicNanoseconds: UInt64?
  private var acceptedReflectorProof: StageBReflectorResponseProof?
  private var reflectorObservedAtMonotonicNanoseconds: UInt64?
  private var handshakeRecorded = false
  private var handshakePostSample: StageBProviderAWGSampleRecord?
  private var bytesRecorded = false
  private var counterPostSample: StageBProviderAWGSampleRecord?
  private var authenticatedOutboundDeltaBytes: UInt64 = 0
  private var authenticatedInboundDeltaBytes: UInt64 = 0
  private var dnsRecorded = false
  private var reflectorRecorded = false
  private var monotonicWatermark: UInt64

  fileprivate init(
    configuration: StageBProviderAttemptConfiguration,
    baseline: StageBAWGSnapshot,
    acceptanceDomain: StageBAcceptanceDomain,
    clockAuthority: StageBProviderMonotonicAuthority
  ) throws {
    self.clockAuthority = clockAuthority
    guard baseline.provenance.clockAuthority === clockAuthority else {
      throw StageBProviderValidationError.foreignNativeProvenance
    }
    expectedProvenance = baseline.provenance
    expectedPath = configuration.path
    expectedPeerPublicKeySHA256 =
      Array(configuration.expectedPeerPublicKeySHA256)
    expectedDNSProbe = configuration.dnsProbe
    expectedDNSResponsePayloadSHA256 =
      Array(configuration.dnsResponsePayloadSHA256)
    canarySequence = configuration.canarySequence

    let lease = try StageBAttemptLease(
      attemptNonce: configuration.attemptNonce,
      pathID: configuration.path.pathID,
      context: configuration.path.context,
      requestedAtMonotonicNanoseconds:
        configuration.requestedAtMonotonicNanoseconds
    )
    guard lease.deadlineMonotonicNanoseconds < UInt64.max else {
      throw StageBProviderValidationError.invalidDeadline
    }
    self.lease = lease
    eventBinding = StageBEventBinding(lease: lease)

    let preparedAt = try clockAuthority.read()
    guard preparedAt >= lease.requestedAtMonotonicNanoseconds else {
      throw StageBProviderValidationError.invalidDeadline
    }
    guard preparedAt <= lease.deadlineMonotonicNanoseconds else {
      throw StageBProviderValidationError.deadlineExceeded
    }
    requestPreparedAtMonotonicNanoseconds = preparedAt
    monotonicWatermark = preparedAt
    let baselinePeer = try Self.validatePeer(
      baseline,
      expectedPath: configuration.path,
      expectedPeerPublicKeySHA256:
        configuration.expectedPeerPublicKeySHA256
    )
    guard
      baseline.sampledAtMonotonicNanoseconds
        >= lease.requestedAtMonotonicNanoseconds,
      baseline.sampledAtMonotonicNanoseconds <= preparedAt
    else {
      throw StageBProviderValidationError.invalidSampleTime
    }
    self.baselinePeer = baselinePeer
    baselineSample = StageBProviderAWGSampleRecord(baseline)
    lastAWGPeer = baselinePeer
    lastAcceptedSampleAtMonotonicNanoseconds =
      baseline.sampledAtMonotonicNanoseconds

    let request = try StageBRequest(
      runID: configuration.runID,
      attemptNonce: configuration.attemptNonce,
      sourceSHA256: configuration.sourceSHA256,
      artifactSHA256: configuration.artifactSHA256,
      context: configuration.path.context,
      canarySequence: configuration.canarySequence,
      issuedAtUnixMilliseconds:
        configuration.issuedAtUnixMilliseconds,
      expiresAtUnixMilliseconds:
        configuration.expiresAtUnixMilliseconds,
      requestSentMonotonicNanoseconds: preparedAt,
      challenge: configuration.challenge
    )
    attempt = try acceptanceDomain.makeAttempt(
      lease: lease,
      expectedRequest: request
    )
    outboundReflectorDatagram = attempt.requestDatagram
    requestDatagramSHA256 = Self.sha256(attempt.requestDatagram)
  }

  @discardableResult
  public func recordAWGSnapshot(
    _ snapshot: StageBAWGSnapshot
  ) throws -> StageBProviderInputDisposition {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else {
      return .ignoredTerminal
    }
    do {
      let now = try advanceMonotonicWatermarkLocked()
      return try processAWGLocked(snapshot, now: now)
    } catch let error as StageBProviderValidationError {
      throw failLocked(error)
    } catch {
      throw failLocked(Self.mapCoreError(error))
    }
  }

  @discardableResult
  public func recordProtectedDNSRequestSent(
    _ proof: StageBProtectedDNSRequestSendProof
  ) throws -> StageBProviderInputDisposition {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else {
      return .ignoredTerminal
    }
    do {
      let now = try advanceMonotonicWatermarkLocked()
      try requireWithinDeadline(now)
      try requireCurrentPath(proof.binding)
      guard proof.probe == expectedDNSProbe,
        proof.preRequestAWGSnapshot.binding == proof.binding
      else {
        throw StageBProviderValidationError.invalidDNSProof
      }
      if let existing = dnsRequestProof {
        guard proof == existing else {
          throw StageBProviderValidationError.invalidDNSProof
        }
        return .coalesced
      }
      _ = try processAWGLocked(
        proof.preRequestAWGSnapshot,
        now: now
      )
      // Ladder: physical evidence requires the bidirectional-byte predicate
      // to be proven no later than the DNS request, so the pre-request sample
      // is the last sample that can establish it.
      guard handshakeRecorded, bytesRecorded else {
        throw StageBProviderValidationError.predicateLadderViolation
      }
      dnsRequestProof = proof
      dnsRequestSentAtMonotonicNanoseconds = now
      return .accepted
    } catch let error as StageBProviderValidationError {
      throw failLocked(error)
    } catch {
      throw failLocked(Self.mapCoreError(error))
    }
  }

  @discardableResult
  public func recordProtectedDNSProof(
    _ proof: StageBProtectedDNSProof
  ) throws -> StageBProviderInputDisposition {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else {
      return .ignoredTerminal
    }
    do {
      let now = try advanceMonotonicWatermarkLocked()
      try requireWithinDeadline(now)
      try requireCurrentPath(proof.binding)
      guard
        let sentProof = dnsRequestProof,
        let sentAt = dnsRequestSentAtMonotonicNanoseconds
      else {
        throw StageBProviderValidationError.dnsRequestNotSent
      }
      guard now >= sentAt,
        proof.probe == expectedDNSProbe,
        proof.preRequestAWGSnapshot
          == sentProof.preRequestAWGSnapshot,
        proof.binding == sentProof.binding,
        proof.preRequestAWGSnapshot.binding == proof.binding,
        proof.postResponseAWGSnapshot.binding == proof.binding
      else {
        throw StageBProviderValidationError.invalidDNSProof
      }
      if let existing = acceptedDNSProof {
        guard proof == existing else {
          throw StageBProviderValidationError.invalidDNSProof
        }
        return .coalesced
      }
      guard
        proof.postResponseAWGSnapshot
          .sampledAtMonotonicNanoseconds >= sentAt
      else {
        throw StageBProviderValidationError.invalidSampleTime
      }
      let payloadDigest = try Self.verifiedDNSResponseDigest(
        proof.responsePayload,
        probe: expectedDNSProbe,
        expectedPayloadSHA256: expectedDNSResponsePayloadSHA256
      )
      try requireStrictBidirectionalMovement(
        from: proof.preRequestAWGSnapshot,
        to: proof.postResponseAWGSnapshot,
        invalidProof: .invalidDNSProof
      )
      _ = try processAWGLocked(
        proof.postResponseAWGSnapshot,
        now: now
      )
      _ = try attempt.recordProtectedDNSResponse(
        binding: eventBinding,
        atMonotonicNanoseconds: now
      )
      dnsRecorded = true
      acceptedDNSProof = proof
      dnsResponseObservedAtMonotonicNanoseconds = now
      observedDNSResponsePayloadSHA256 = payloadDigest
      synchronizeSuccessLocked()
      return .accepted
    } catch let error as StageBProviderValidationError {
      throw failLocked(error)
    } catch {
      throw failLocked(Self.mapCoreError(error))
    }
  }

  @discardableResult
  public func recordReflectorRequestSent(
    _ proof: StageBReflectorRequestSendProof
  ) throws -> StageBProviderInputDisposition {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else {
      return .ignoredTerminal
    }
    do {
      let now = try advanceMonotonicWatermarkLocked()
      try requireWithinDeadline(now)
      guard now >= requestPreparedAtMonotonicNanoseconds else {
        throw StageBProviderValidationError.invalidReflectorProof
      }
      try requireCurrentPath(proof.binding)
      guard proof.requestDatagramSHA256 == requestDatagramSHA256,
        proof.preSendAWGSnapshot.binding == proof.binding
      else {
        throw StageBProviderValidationError.invalidReflectorProof
      }
      if let existing = reflectorRequestProof {
        guard proof == existing else {
          throw StageBProviderValidationError.invalidReflectorProof
        }
        return .coalesced
      }
      // Ladder: the reflector may be driven only after an accepted DNS
      // proof. Ordering alone does not separate the two probes; the
      // independence check below is what does.
      guard
        let dnsProof = acceptedDNSProof,
        let dnsObservedAt = dnsResponseObservedAtMonotonicNanoseconds
      else {
        throw StageBProviderValidationError.dnsProofNotAccepted
      }
      guard
        proof.preSendAWGSnapshot.sampledAtMonotonicNanoseconds
          >= dnsObservedAt
      else {
        throw StageBProviderValidationError.invalidSampleTime
      }
      // Independence: the reflector's movement window starts strictly after
      // the DNS window ends, so the DNS round trip cannot satisfy it.
      let dnsPost = dnsProof.postResponseAWGSnapshot.peer
      let preSend = proof.preSendAWGSnapshot.peer
      guard preSend.receivedBytes > dnsPost.receivedBytes,
        preSend.transmittedBytes > dnsPost.transmittedBytes
      else {
        throw StageBProviderValidationError
          .probeMovementNotIndependent
      }
      _ = try processAWGLocked(
        proof.preSendAWGSnapshot,
        now: now
      )
      reflectorRequestSent = true
      reflectorRequestProof = proof
      reflectorRequestSentAtMonotonicNanoseconds = now
      return .accepted
    } catch let error as StageBProviderValidationError {
      throw failLocked(error)
    } catch {
      throw failLocked(.coreRejected)
    }
  }

  @discardableResult
  public func acceptReflectorResponse(
    _ proof: StageBReflectorResponseProof
  ) throws -> StageBProviderInputDisposition {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else {
      return .ignoredTerminal
    }
    do {
      let now = try advanceMonotonicWatermarkLocked()
      try requireWithinDeadline(now)
      guard reflectorRequestSent,
        let sentProof = reflectorRequestProof,
        let sentAt =
          reflectorRequestSentAtMonotonicNanoseconds,
        now >= sentAt
      else {
        throw StageBProviderValidationError
          .reflectorRequestNotSent
      }
      try requireCurrentPath(proof.binding)
      guard proof.binding == sentProof.binding,
        proof.postResponseAWGSnapshot.binding == proof.binding
      else {
        throw StageBProviderValidationError.invalidReflectorProof
      }
      // While the reflector response is the last rung of the ladder,
      // accepting one always completes the attempt, so this branch is
      // unreachable and repeats are answered as late terminal input above.
      // It is kept as a fail-closed guard for any future rung order.
      if let existing = acceptedReflectorProof {
        guard proof == existing else {
          throw StageBProviderValidationError.invalidReflectorProof
        }
        return .coalesced
      }
      guard
        proof.postResponseAWGSnapshot
          .sampledAtMonotonicNanoseconds >= sentAt
      else {
        throw StageBProviderValidationError.invalidSampleTime
      }
      try requireStrictBidirectionalMovement(
        from: sentProof.preSendAWGSnapshot,
        to: proof.postResponseAWGSnapshot,
        invalidProof: .invalidReflectorProof
      )
      _ = try processAWGLocked(
        proof.postResponseAWGSnapshot,
        now: now
      )
      _ = try attempt.acceptAuthenticatedReflectorResponse(
        proof.responseDatagram
      )
      // The replay authority stamps acceptance with the same shared clock.
      // That read is the authoritative response-observed time, and it is at
      // or after this method's own read, so the watermark adopts it.
      guard
        let observedAt = attempt.localReceipt()
          .reflectorObservedAtMonotonicNanoseconds,
        observedAt >= now,
        observedAt <= lease.deadlineMonotonicNanoseconds
      else {
        throw StageBProviderValidationError.invalidDeadline
      }
      monotonicWatermark = observedAt
      reflectorRecorded = true
      acceptedReflectorProof = proof
      reflectorObservedAtMonotonicNanoseconds = observedAt
      synchronizeSuccessLocked()
      return .accepted
    } catch let error as StageBProviderValidationError {
      throw failLocked(error)
    } catch {
      throw failLocked(Self.mapCoreError(error))
    }
  }

  @discardableResult
  public func cancel() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else { return false }
    guard (try? advanceMonotonicWatermarkLocked()) != nil else {
      _ = failLocked(.invalidDeadline)
      return false
    }
    providerStatus = .cancelled
    attempt.cancel()
    emitTerminalEvidenceLocked(
      status: .cancelled,
      failure: nil
    )
    return true
  }

  @discardableResult
  public func supersedePath() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else { return false }
    guard (try? advanceMonotonicWatermarkLocked()) != nil else {
      _ = failLocked(.invalidDeadline)
      return false
    }
    providerStatus = .superseded
    attempt.supersedePath()
    emitTerminalEvidenceLocked(
      status: .superseded,
      failure: nil
    )
    return true
  }

  /// Handles a trusted timer callback.
  ///
  /// Exactly at the inclusive deadline the attempt remains active and the
  /// adapter is explicitly told to rearm at deadline+1. Therefore a timer
  /// firing at exactly T0+3s cannot strand an active attempt.
  public func handleTimeoutFired() -> StageBProviderTimerDirective {
    lock.lock()
    defer { lock.unlock() }
    guard providerStatus == .active else {
      return .ignoredTerminal
    }
    let now: UInt64
    do {
      now = try advanceMonotonicWatermarkLocked()
    } catch {
      _ = failLocked(.invalidDeadline)
      return .terminal
    }
    if now <= lease.deadlineMonotonicNanoseconds {
      return .rearm(
        atMonotonicNanoseconds:
          lease.deadlineMonotonicNanoseconds + 1
      )
    }
    attempt.timeout(atMonotonicNanoseconds: now)
    providerStatus = .failed
    terminalFailure = .deadlineExceeded
    emitTerminalEvidenceLocked(
      status: .failed,
      failure: .deadlineExceeded
    )
    return .terminal
  }

  public func localSnapshot() -> StageBProviderLocalSnapshot {
    lock.lock()
    defer { lock.unlock() }
    return StageBProviderLocalSnapshot(
      status: providerStatus,
      failure: terminalFailure,
      lease: lease,
      reflectorRequestSent: reflectorRequestSent,
      freshAWGHandshake: handshakeRecorded,
      authenticatedTunnelBytes: bytesRecorded,
      protectedDNSResponse: dnsRecorded,
      authenticatedReflectorResponse: reflectorRecorded
    )
  }

  /// The once-emitted terminal record, or `nil` while the attempt is active.
  public func terminalEvidence() -> StageBProviderTerminalEvidence? {
    lock.lock()
    defer { lock.unlock() }
    return terminalEvidenceRecord
  }

  private func processAWGLocked(
    _ snapshot: StageBAWGSnapshot,
    now: UInt64
  ) throws -> StageBProviderInputDisposition {
    do {
      try requireWithinDeadline(now)
      let peer = try Self.validatePeer(
        snapshot,
        expectedPath: expectedPath,
        expectedPeerPublicKeySHA256:
          expectedPeerPublicKeySHA256
      )
      guard snapshot.provenance == expectedProvenance else {
        throw StageBProviderValidationError.foreignNativeProvenance
      }
      let sampledAt = snapshot.sampledAtMonotonicNanoseconds
      guard sampledAt >= lease.requestedAtMonotonicNanoseconds,
        sampledAt >= lastAcceptedSampleAtMonotonicNanoseconds,
        sampledAt <= now
      else {
        throw StageBProviderValidationError.invalidSampleTime
      }
      guard peer.receivedBytes >= lastAWGPeer.receivedBytes,
        peer.transmittedBytes >= lastAWGPeer.transmittedBytes
      else {
        throw StageBProviderValidationError.counterReset
      }
      guard !Self.handshakePrecedes(peer, lastAWGPeer)
      else {
        throw StageBProviderValidationError.handshakeReset
      }

      // One record per accepted sample: the core is given the same sample
      // time this record exports, rather than a separately derived value.
      let sample = StageBProviderAWGSampleRecord(snapshot)
      var accepted = false
      if !handshakeRecorded,
        peer.latestHandshakeUnixMilliseconds
          > baselinePeer.latestHandshakeUnixMilliseconds
      {
        _ = try attempt.recordFreshAWGHandshake(
          binding: eventBinding,
          atMonotonicNanoseconds:
            sample.sampledAtMonotonicNanoseconds
        )
        handshakeRecorded = true
        handshakePostSample = sample
        accepted = true
      }

      let receivedDelta =
        peer.receivedBytes - baselinePeer.receivedBytes
      let transmittedDelta =
        peer.transmittedBytes - baselinePeer.transmittedBytes
      if !bytesRecorded,
        receivedDelta > 0,
        transmittedDelta > 0
      {
        // Ladder: physical evidence rejects bidirectional bytes without a
        // fresh handshake, and requires the byte sample not to precede the
        // handshake sample.
        guard handshakeRecorded else {
          throw StageBProviderValidationError
            .predicateLadderViolation
        }
        _ = try attempt.recordAuthenticatedTunnelBytes(
          binding: eventBinding,
          outboundBytes: transmittedDelta,
          inboundBytes: receivedDelta,
          atMonotonicNanoseconds:
            sample.sampledAtMonotonicNanoseconds
        )
        bytesRecorded = true
        counterPostSample = sample
        authenticatedOutboundDeltaBytes = transmittedDelta
        authenticatedInboundDeltaBytes = receivedDelta
        accepted = true
      }
      lastAWGPeer = peer
      lastAcceptedSampleAtMonotonicNanoseconds = sampledAt
      synchronizeSuccessLocked()
      return accepted ? .accepted : .coalesced
    } catch let error as StageBProviderValidationError {
      throw failLocked(error)
    } catch {
      throw failLocked(Self.mapCoreError(error))
    }
  }

  private static func validatePeer(
    _ snapshot: StageBAWGSnapshot,
    expectedPath: StageBProviderPathBinding,
    expectedPeerPublicKeySHA256: [UInt8]
  ) throws -> StageBAWGPeerSnapshot {
    guard snapshot.binding == expectedPath else {
      throw StageBProviderValidationError.bindingMismatch
    }
    let peer = snapshot.peer
    guard peer.peerPublicKeySHA256 == expectedPeerPublicKeySHA256 else {
      throw StageBProviderValidationError.bindingMismatch
    }
    return peer
  }

  private func requireCurrentPath(
    _ binding: StageBProviderPathBinding
  ) throws {
    guard binding == expectedPath else {
      throw StageBProviderValidationError.bindingMismatch
    }
  }

  private func requireStrictBidirectionalMovement(
    from preSnapshot: StageBAWGSnapshot,
    to postSnapshot: StageBAWGSnapshot,
    invalidProof: StageBProviderValidationError
  ) throws {
    let pre = try Self.validatePeer(
      preSnapshot,
      expectedPath: expectedPath,
      expectedPeerPublicKeySHA256:
        expectedPeerPublicKeySHA256
    )
    let post = try Self.validatePeer(
      postSnapshot,
      expectedPath: expectedPath,
      expectedPeerPublicKeySHA256:
        expectedPeerPublicKeySHA256
    )
    guard
      preSnapshot.sampledAtMonotonicNanoseconds
        <= postSnapshot.sampledAtMonotonicNanoseconds
    else {
      throw StageBProviderValidationError.invalidSampleTime
    }
    guard post.receivedBytes > pre.receivedBytes,
      post.transmittedBytes > pre.transmittedBytes,
      !Self.handshakePrecedes(post, pre)
    else {
      throw invalidProof
    }
  }

  private static func handshakePrecedes(
    _ lhs: StageBAWGPeerSnapshot,
    _ rhs: StageBAWGPeerSnapshot
  ) -> Bool {
    if lhs.latestHandshakeUnixSeconds != rhs.latestHandshakeUnixSeconds {
      return lhs.latestHandshakeUnixSeconds < rhs.latestHandshakeUnixSeconds
    }
    return lhs.latestHandshakeNanoseconds
      < rhs.latestHandshakeNanoseconds
  }

  private func requireWithinDeadline(_ now: UInt64) throws {
    guard now >= lease.requestedAtMonotonicNanoseconds else {
      throw StageBProviderValidationError.invalidDeadline
    }
    guard now <= lease.deadlineMonotonicNanoseconds else {
      throw StageBProviderValidationError.deadlineExceeded
    }
  }

  private func advanceMonotonicWatermarkLocked() throws -> UInt64 {
    let now = try clockAuthority.read()
    guard now >= monotonicWatermark else {
      throw StageBProviderValidationError.invalidDeadline
    }
    monotonicWatermark = now
    return now
  }

  /// Validates DNS response wire bytes and returns their exact digest.
  ///
  /// The header, question, and cache-bypass nonce are parsed and checked
  /// against this attempt's probe binding. The remainder of the message,
  /// including the answer records, is pinned by the full-payload digest the
  /// attempt configuration carries; this function computes that digest from
  /// the bytes it parsed rather than accepting one from a caller. The private
  /// resolver identity is not observable in the response and remains bound by
  /// the probe binding alone.
  private static func verifiedDNSResponseDigest(
    _ payload: Data,
    probe: StageBDNSProbeBinding,
    expectedPayloadSHA256: [UInt8]
  ) throws -> [UInt8] {
    let bytes = [UInt8](payload)
    guard bytes.count >= 17, bytes.count <= 4_096 else {
      throw StageBProviderValidationError.invalidDNSWireResponse
    }
    let transactionID = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    guard transactionID == probe.transactionID else {
      throw StageBProviderValidationError.invalidDNSWireResponse
    }
    // QR=1 response, OPCODE=0 query, TC=0 untruncated, RCODE=0 no error.
    guard bytes[2] & 0x80 == 0x80,
      bytes[2] & 0x78 == 0,
      bytes[2] & 0x02 == 0,
      bytes[3] & 0x0f == 0
    else {
      throw StageBProviderValidationError.invalidDNSWireResponse
    }
    let questionCount = UInt16(bytes[4]) << 8 | UInt16(bytes[5])
    let answerCount = UInt16(bytes[6]) << 8 | UInt16(bytes[7])
    guard questionCount == 1, answerCount >= 1 else {
      throw StageBProviderValidationError.invalidDNSWireResponse
    }
    var index = 12
    var firstLabel: [UInt8]?
    var nameBytes = 0
    while true {
      guard index < bytes.count else {
        throw StageBProviderValidationError.invalidDNSWireResponse
      }
      let length = bytes[index]
      // A question name is never compressed, so a pointer or reserved
      // length prefix is malformed here rather than a name to follow.
      guard length & 0xc0 == 0 else {
        throw StageBProviderValidationError.invalidDNSWireResponse
      }
      if length == 0 {
        index += 1
        break
      }
      let start = index + 1
      let end = start + Int(length)
      guard end <= bytes.count else {
        throw StageBProviderValidationError.invalidDNSWireResponse
      }
      if firstLabel == nil {
        firstLabel = Array(bytes[start..<end])
      }
      nameBytes += Int(length) + 1
      guard nameBytes <= 254 else {
        throw StageBProviderValidationError.invalidDNSWireResponse
      }
      index = end
    }
    guard let nonceLabel = firstLabel, index + 4 <= bytes.count else {
      throw StageBProviderValidationError.invalidDNSWireResponse
    }
    let question = Array(bytes[12..<(index + 4)])
    guard
      Array(SHA256.hash(data: Data(question))) == probe.questionSHA256,
      Array(SHA256.hash(data: Data(nonceLabel)))
        == probe.cacheBypassNonceSHA256
    else {
      throw StageBProviderValidationError.invalidDNSWireResponse
    }
    let digest = Array(SHA256.hash(data: payload))
    guard digest == expectedPayloadSHA256 else {
      throw StageBProviderValidationError.invalidDNSProof
    }
    return digest
  }

  // Every terminal transition clears `.active` before it emits, and every
  // emitter first requires `.active`. That is what makes the terminal record
  // a single write rather than a last-writer-wins field.
  private func synchronizeSuccessLocked() {
    guard providerStatus == .active,
      attempt.status == .succeeded
    else {
      return
    }
    providerStatus = .succeeded
    emitTerminalEvidenceLocked(status: .succeeded, failure: nil)
  }

  private func failLocked(
    _ error: StageBProviderValidationError
  ) -> StageBProviderValidationError {
    if providerStatus == .active {
      providerStatus = .failed
      terminalFailure = error
      attempt.cancel()
      emitTerminalEvidenceLocked(status: .failed, failure: error)
    }
    return error
  }

  private func emitTerminalEvidenceLocked(
    status: StageBProviderStatus,
    failure: StageBProviderValidationError?
  ) {
    guard terminalEvidenceRecord == nil else { return }
    terminalEvidenceRecord = StageBProviderTerminalEvidence(
      status: status,
      failure: failure,
      canarySequence: canarySequence,
      lease: lease,
      terminalAtMonotonicNanoseconds: monotonicWatermark,
      baselineSample: baselineSample,
      handshakePostSample: handshakePostSample,
      counterPostSample: counterPostSample,
      authenticatedOutboundDeltaBytes:
        authenticatedOutboundDeltaBytes,
      authenticatedInboundDeltaBytes:
        authenticatedInboundDeltaBytes,
      protectedDNSAtMonotonicNanoseconds:
        dnsResponseObservedAtMonotonicNanoseconds,
      authenticatedReflectorAtMonotonicNanoseconds:
        reflectorObservedAtMonotonicNanoseconds,
      dnsRequestSentAtMonotonicNanoseconds:
        dnsRequestSentAtMonotonicNanoseconds,
      dnsQueryNonceSHA256: expectedDNSProbe.cacheBypassNonceSHA256,
      dnsResponsePayloadSHA256: observedDNSResponsePayloadSHA256,
      reflectorRequestSentAtMonotonicNanoseconds:
        reflectorRequestSentAtMonotonicNanoseconds
    )
  }

  private static func mapCoreError(
    _ error: Error
  ) -> StageBProviderValidationError {
    guard let stageBError = error as? StageBError else {
      return .coreRejected
    }
    switch stageBError {
    case .deadlineExceeded:
      return .deadlineExceeded
    case .bindingMismatch, .invalidContext:
      return .bindingMismatch
    default:
      return .coreRejected
    }
  }

  private static func sha256(_ data: Data) -> [UInt8] {
    Array(SHA256.hash(data: data))
  }
}
