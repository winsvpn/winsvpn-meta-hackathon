import CryptoKit
import Foundation
import WinnPrivacyStageACore

public enum StageBProtectedFlow {
    public static let protocolVersion = "winn/3"
    public static let wireSchema = "winn-stageb-reflector-wire/1"
    public static let receiptScope = "local-conformance-only"
    public static let requestBodyLength = 222
    public static let requestLength = 254
    public static let responseLength = 302
    public static let sharedKeyLength = 32
    public static let deadlineNanoseconds: UInt64 = 3_000_000_000
    public static let maximumLifetimeMilliseconds: UInt64 = 10_000
    public static let maximumReplayCapacity = 4_096
}

public enum StageBError: Error, Equatable, CustomStringConvertible {
    case invalidLength
    case invalidKey
    case invalidFixedField
    case invalidIdentifier
    case invalidDigest
    case invalidContext
    case invalidSequence
    case invalidByteCount
    case invalidLifetime
    case invalidClock
    case authenticationFailed
    case bindingMismatch
    case replay
    case cacheCapacity
    case duplicateEvent
    case reversedTime
    case deadlineExceeded
    case arithmeticOverflow
    case cancelled
    case superseded
    case terminal

    public var description: String {
        switch self {
        case .invalidLength: return "stage-b invalid length"
        case .invalidKey: return "stage-b invalid key"
        case .invalidFixedField: return "stage-b invalid fixed field"
        case .invalidIdentifier: return "stage-b invalid identifier"
        case .invalidDigest: return "stage-b invalid digest"
        case .invalidContext: return "stage-b invalid context"
        case .invalidSequence: return "stage-b invalid sequence"
        case .invalidByteCount: return "stage-b invalid byte count"
        case .invalidLifetime: return "stage-b invalid lifetime"
        case .invalidClock: return "stage-b invalid clock"
        case .authenticationFailed: return "stage-b authentication failed"
        case .bindingMismatch: return "stage-b binding mismatch"
        case .replay: return "stage-b replay rejected"
        case .cacheCapacity: return "stage-b replay cache full"
        case .duplicateEvent: return "stage-b duplicate event"
        case .reversedTime: return "stage-b reversed time"
        case .deadlineExceeded: return "stage-b deadline exceeded"
        case .arithmeticOverflow: return "stage-b arithmetic overflow"
        case .cancelled: return "stage-b cancelled"
        case .superseded: return "stage-b superseded"
        case .terminal: return "stage-b attempt terminal"
        }
    }
}

public struct StageBRequest: Equatable, Sendable {
    public let runID: [UInt8]
    public let attemptNonce: [UInt8]
    public let sourceSHA256: [UInt8]
    public let artifactSHA256: [UInt8]
    public let context: WCF3ConnectionContext
    public let canarySequence: UInt64
    public let issuedAtUnixMilliseconds: UInt64
    public let expiresAtUnixMilliseconds: UInt64
    public let requestSentMonotonicNanoseconds: UInt64
    public let challenge: [UInt8]

    public init(
        runID: [UInt8],
        attemptNonce: [UInt8],
        sourceSHA256: [UInt8],
        artifactSHA256: [UInt8],
        context: WCF3ConnectionContext,
        canarySequence: UInt64,
        issuedAtUnixMilliseconds: UInt64,
        expiresAtUnixMilliseconds: UInt64,
        requestSentMonotonicNanoseconds: UInt64,
        challenge: [UInt8]
    ) throws {
        guard Self.validNonzero(runID, count: 16),
              Self.validNonzero(attemptNonce, count: 16)
        else {
            throw StageBError.invalidIdentifier
        }
        guard Self.validNonzero(sourceSHA256, count: 32),
              Self.validNonzero(artifactSHA256, count: 32),
              Self.validNonzero(challenge, count: 32)
        else {
            throw StageBError.invalidDigest
        }
        guard canarySequence > 0 else {
            throw StageBError.invalidSequence
        }
        guard expiresAtUnixMilliseconds > issuedAtUnixMilliseconds else {
            throw StageBError.invalidLifetime
        }
        let (lifetime, underflow) =
            expiresAtUnixMilliseconds.subtractingReportingOverflow(
                issuedAtUnixMilliseconds
            )
        guard !underflow,
              lifetime <= StageBProtectedFlow.maximumLifetimeMilliseconds
        else {
            throw StageBError.invalidLifetime
        }
        self.runID = runID
        self.attemptNonce = attemptNonce
        self.sourceSHA256 = sourceSHA256
        self.artifactSHA256 = artifactSHA256
        self.context = context
        self.canarySequence = canarySequence
        self.issuedAtUnixMilliseconds = issuedAtUnixMilliseconds
        self.expiresAtUnixMilliseconds = expiresAtUnixMilliseconds
        self.requestSentMonotonicNanoseconds =
            requestSentMonotonicNanoseconds
        self.challenge = challenge
    }

    private static func validNonzero(
        _ bytes: [UInt8],
        count: Int
    ) -> Bool {
        bytes.count == count && !bytes.allSatisfy { $0 == 0 }
    }
}

public struct StageBVerifiedRequest: Equatable, Sendable {
    public let request: StageBRequest
    public let requestTag: [UInt8]
    fileprivate let requestBody: [UInt8]
}

public struct StageBVerifiedResponse: Equatable, Sendable {
    public let request: StageBRequest
    public let reflectorReceivedUnixMilliseconds: UInt64
    public let reflectorSentUnixMilliseconds: UInt64
    fileprivate let responseTag: [UInt8]
}

public enum StageBReflectorCodec {
    private static let magic = Array("WBR3".utf8)
    private static let protocolBytes =
        Array(StageBProtectedFlow.protocolVersion.utf8)
    private static let requestDomain =
        Array("winn-stageb-request/v1\0".utf8)
    private static let responseDomain =
        Array("winn-stageb-response/v1\0".utf8)

    static func encodeRequest(
        _ request: StageBRequest,
        key: [UInt8]
    ) throws -> Data {
        let key = try symmetricKey(key)
        let body = requestBody(request, messageType: 1)
        let tag = authenticationCode(
            domain: requestDomain,
            bytes: body,
            key: key
        )
        return Data(body + tag)
    }

    public static func verifyRequest(
        _ datagram: Data,
        key: [UInt8],
        reflectorNowUnixMilliseconds: UInt64
    ) throws -> StageBVerifiedRequest {
        guard datagram.count == StageBProtectedFlow.requestLength else {
            throw StageBError.invalidLength
        }
        let key = try symmetricKey(key)
        let bytes = [UInt8](datagram)
        let body = Array(bytes[0 ..< StageBProtectedFlow.requestBodyLength])
        let tag = Array(bytes[StageBProtectedFlow.requestBodyLength...])
        guard validAuthenticationCode(
            tag,
            domain: requestDomain,
            bytes: body,
            key: key
        ) else {
            throw StageBError.authenticationFailed
        }
        let request = try decodeBody(body, expectedMessageType: 1)
        guard reflectorNowUnixMilliseconds >=
                request.issuedAtUnixMilliseconds,
              reflectorNowUnixMilliseconds <=
                request.expiresAtUnixMilliseconds
        else {
            throw StageBError.invalidClock
        }
        return StageBVerifiedRequest(
            request: request,
            requestTag: tag,
            requestBody: body
        )
    }

    public static func encodeResponse(
        for verified: StageBVerifiedRequest,
        key: [UInt8],
        reflectorReceivedUnixMilliseconds: UInt64,
        reflectorSentUnixMilliseconds: UInt64
    ) throws -> Data {
        guard reflectorReceivedUnixMilliseconds >=
                verified.request.issuedAtUnixMilliseconds,
              reflectorReceivedUnixMilliseconds <=
                verified.request.expiresAtUnixMilliseconds,
              reflectorSentUnixMilliseconds >=
                reflectorReceivedUnixMilliseconds,
              reflectorSentUnixMilliseconds <=
                verified.request.expiresAtUnixMilliseconds
        else {
            throw StageBError.invalidClock
        }
        let key = try symmetricKey(key)
        let expectedRequestBody =
            requestBody(verified.request, messageType: 1)
        guard verified.requestBody == expectedRequestBody else {
            throw StageBError.bindingMismatch
        }
        guard validAuthenticationCode(
            verified.requestTag,
            domain: requestDomain,
            bytes: expectedRequestBody,
            key: key
        ) else {
            throw StageBError.authenticationFailed
        }
        var preceding = requestBody(verified.request, messageType: 2)
        preceding.append(contentsOf: verified.requestTag)
        appendUInt64(
            reflectorReceivedUnixMilliseconds,
            to: &preceding
        )
        appendUInt64(reflectorSentUnixMilliseconds, to: &preceding)
        let tag = authenticationCode(
            domain: responseDomain,
            bytes: preceding,
            key: key
        )
        return Data(preceding + tag)
    }

    static func verifyResponse(
        _ datagram: Data,
        expectedRequest: StageBRequest,
        key: [UInt8]
    ) throws -> StageBVerifiedResponse {
        let outbound = try encodeRequest(expectedRequest, key: key)
        let exactTag = Array(outbound.suffix(32))
        return try verifyResponse(
            datagram,
            expectedRequest: expectedRequest,
            exactOutboundRequestTag: exactTag,
            key: key
        )
    }

    fileprivate static func verifyResponse(
        _ datagram: Data,
        expectedRequest: StageBRequest,
        exactOutboundRequestTag: [UInt8],
        key: [UInt8]
    ) throws -> StageBVerifiedResponse {
        guard datagram.count == StageBProtectedFlow.responseLength else {
            throw StageBError.invalidLength
        }
        guard exactOutboundRequestTag.count == 32 else {
            throw StageBError.authenticationFailed
        }
        let key = try symmetricKey(key)
        let bytes = [UInt8](datagram)
        let authenticatedLength = StageBProtectedFlow.responseLength - 32
        let preceding = Array(bytes[0 ..< authenticatedLength])
        let responseTag = Array(bytes[authenticatedLength...])
        guard validAuthenticationCode(
            responseTag,
            domain: responseDomain,
            bytes: preceding,
            key: key
        ) else {
            throw StageBError.authenticationFailed
        }

        let body = Array(
            bytes[0 ..< StageBProtectedFlow.requestBodyLength]
        )
        let decoded = try decodeBody(body, expectedMessageType: 2)
        guard decoded == expectedRequest else {
            throw StageBError.bindingMismatch
        }

        let echoedTagStart = StageBProtectedFlow.requestBodyLength
        let echoedTag = Array(bytes[echoedTagStart ..< echoedTagStart + 32])
        guard constantTimeEqual(
            echoedTag,
            exactOutboundRequestTag
        ) else {
            throw StageBError.authenticationFailed
        }
        let expectedRequestBody =
            requestBody(expectedRequest, messageType: 1)
        guard validAuthenticationCode(
            echoedTag,
            domain: requestDomain,
            bytes: expectedRequestBody,
            key: key
        ) else {
            throw StageBError.authenticationFailed
        }

        let received = readUInt64(bytes, at: 254)
        let sent = readUInt64(bytes, at: 262)
        guard received >= expectedRequest.issuedAtUnixMilliseconds,
              received <= expectedRequest.expiresAtUnixMilliseconds,
              sent >= received,
              sent <= expectedRequest.expiresAtUnixMilliseconds
        else {
            throw StageBError.invalidClock
        }
        return StageBVerifiedResponse(
            request: decoded,
            reflectorReceivedUnixMilliseconds: received,
            reflectorSentUnixMilliseconds: sent,
            responseTag: responseTag
        )
    }

    private static func symmetricKey(_ bytes: [UInt8]) throws -> SymmetricKey {
        guard bytes.count == StageBProtectedFlow.sharedKeyLength else {
            throw StageBError.invalidKey
        }
        return SymmetricKey(data: bytes)
    }

    private static func requestBody(
        _ request: StageBRequest,
        messageType: UInt8
    ) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(StageBProtectedFlow.requestBodyLength)
        result.append(contentsOf: magic)
        result.append(1)
        result.append(messageType)
        result.append(contentsOf: [0, 0])
        result.append(contentsOf: protocolBytes)
        result.append(contentsOf: request.runID)
        result.append(contentsOf: request.attemptNonce)
        result.append(contentsOf: request.sourceSHA256)
        result.append(contentsOf: request.artifactSHA256)
        result.append(contentsOf: request.context.sessionID)
        result.append(contentsOf: request.context.bindingID)
        appendUInt64(request.context.pskGeneration, to: &result)
        appendUInt64(request.context.sequenceEpoch, to: &result)
        appendUInt64(request.canarySequence, to: &result)
        appendUInt64(request.issuedAtUnixMilliseconds, to: &result)
        appendUInt64(request.expiresAtUnixMilliseconds, to: &result)
        appendUInt64(
            request.requestSentMonotonicNanoseconds,
            to: &result
        )
        result.append(contentsOf: request.challenge)
        precondition(result.count == StageBProtectedFlow.requestBodyLength)
        return result
    }

    private static func decodeBody(
        _ body: [UInt8],
        expectedMessageType: UInt8
    ) throws -> StageBRequest {
        guard body.count == StageBProtectedFlow.requestBodyLength else {
            throw StageBError.invalidLength
        }
        guard Array(body[0 ..< 4]) == magic,
              body[4] == 1,
              body[5] == expectedMessageType,
              body[6] == 0,
              body[7] == 0,
              Array(body[8 ..< 14]) == protocolBytes
        else {
            throw StageBError.invalidFixedField
        }
        let context: WCF3ConnectionContext
        do {
            context = try WCF3ConnectionContext(
                sessionID: Array(body[110 ..< 126]),
                bindingID: Array(body[126 ..< 142]),
                pskGeneration: readUInt64(body, at: 142),
                sequenceEpoch: readUInt64(body, at: 150)
            )
        } catch {
            throw StageBError.invalidContext
        }
        return try StageBRequest(
            runID: Array(body[14 ..< 30]),
            attemptNonce: Array(body[30 ..< 46]),
            sourceSHA256: Array(body[46 ..< 78]),
            artifactSHA256: Array(body[78 ..< 110]),
            context: context,
            canarySequence: readUInt64(body, at: 158),
            issuedAtUnixMilliseconds: readUInt64(body, at: 166),
            expiresAtUnixMilliseconds: readUInt64(body, at: 174),
            requestSentMonotonicNanoseconds: readUInt64(body, at: 182),
            challenge: Array(body[190 ..< 222])
        )
    }

    private static func authenticationCode(
        domain: [UInt8],
        bytes: [UInt8],
        key: SymmetricKey
    ) -> [UInt8] {
        let code = HMAC<SHA256>.authenticationCode(
            for: Data(domain + bytes),
            using: key
        )
        return Array(code)
    }

    private static func validAuthenticationCode(
        _ candidate: [UInt8],
        domain: [UInt8],
        bytes: [UInt8],
        key: SymmetricKey
    ) -> Bool {
        guard candidate.count == 32 else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(
            candidate,
            authenticating: Data(domain + bytes),
            using: key
        )
    }

    private static func constantTimeEqual(
        _ left: [UInt8],
        _ right: [UInt8]
    ) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for index in left.indices {
            difference |= left[index] ^ right[index]
        }
        return difference == 0
    }

    private static func appendUInt64(
        _ value: UInt64,
        to bytes: inout [UInt8]
    ) {
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    private static func readUInt64(
        _ bytes: [UInt8],
        at offset: Int
    ) -> UInt64 {
        var value: UInt64 = 0
        for index in 0 ..< 8 {
            value = (value << 8) | UInt64(bytes[offset + index])
        }
        return value
    }
}

/// A race-safe, bounded replay guard for verified reflector requests.
///
/// Replay is checked before expired entries are pruned. A monotonic watermark
/// prevents clock rollback from re-admitting an entry after forward pruning.
public final class StageBReplayCache: @unchecked Sendable {
    private let capacity: Int
    private var expirationsByTag = [[UInt8]: UInt64]()
    private var clockWatermark: UInt64?
    private let lock = NSLock()

    public init(capacity: Int) throws {
        guard capacity > 0,
              capacity <= StageBProtectedFlow.maximumReplayCapacity
        else {
            throw StageBError.cacheCapacity
        }
        self.capacity = capacity
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return expirationsByTag.count
    }

    public func consume(
        verifiedRequest: StageBVerifiedRequest,
        nowUnixMilliseconds: UInt64
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        if let clockWatermark,
           nowUnixMilliseconds < clockWatermark {
            throw StageBError.reversedTime
        }
        clockWatermark = nowUnixMilliseconds
        guard expirationsByTag[verifiedRequest.requestTag] == nil else {
            throw StageBError.replay
        }
        guard nowUnixMilliseconds >=
                verifiedRequest.request.issuedAtUnixMilliseconds,
              nowUnixMilliseconds <=
                verifiedRequest.request.expiresAtUnixMilliseconds
        else {
            throw StageBError.invalidClock
        }
        expirationsByTag = expirationsByTag.filter {
            nowUnixMilliseconds <= $0.value
        }
        guard expirationsByTag.count < capacity else {
            throw StageBError.cacheCapacity
        }
        expirationsByTag[verifiedRequest.requestTag] =
            verifiedRequest.request.expiresAtUnixMilliseconds
    }
}

fileprivate final class StageBResponseReplayAuthority:
    @unchecked Sendable
{
    private let capacity: Int
    private let monotonicClock: @Sendable () -> UInt64
    private var expirationsByTag = [Data: UInt64]()
    private var clockWatermark: UInt64?
    private let lock = NSLock()

    init(
        capacity: Int,
        monotonicClock: @escaping @Sendable () -> UInt64
    ) throws {
        guard capacity > 0,
              capacity <= StageBProtectedFlow.maximumReplayCapacity
        else {
            throw StageBError.cacheCapacity
        }
        self.capacity = capacity
        self.monotonicClock = monotonicClock
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return expirationsByTag.count
    }

    func consume(
        responseTag: [UInt8],
        notBeforeMonotonicNanoseconds lowerBound: UInt64,
        expiresAtMonotonicNanoseconds expiry: UInt64
    ) throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let time = monotonicClock()
        if let clockWatermark, time < clockWatermark {
            throw StageBError.reversedTime
        }
        clockWatermark = time
        guard time >= lowerBound else {
            throw StageBError.reversedTime
        }
        guard time <= expiry else {
            throw StageBError.deadlineExceeded
        }
        let tag = Data(responseTag)
        guard expirationsByTag[tag] == nil else {
            throw StageBError.replay
        }
        expirationsByTag = expirationsByTag.filter {
            time <= $0.value
        }
        guard expirationsByTag.count < capacity else {
            throw StageBError.cacheCapacity
        }
        expirationsByTag[tag] = expiry
        return time
    }
}

/// One shared response-acceptance and trusted-clock domain.
///
/// The domain is the only public factory for Stage B attempts, preventing a
/// caller from accidentally splitting replay, cancellation, and timing
/// authority across independently constructed objects.
public final class StageBAcceptanceDomain: @unchecked Sendable {
    private let responseAuthority: StageBResponseReplayAuthority
    private let key: [UInt8]

    public init(
        capacity: Int,
        key: [UInt8],
        monotonicClock: @escaping @Sendable () -> UInt64
    ) throws {
        guard key.count == StageBProtectedFlow.sharedKeyLength else {
            throw StageBError.invalidKey
        }
        self.key = Array(key)
        responseAuthority = try StageBResponseReplayAuthority(
            capacity: capacity,
            monotonicClock: monotonicClock
        )
    }

    public var acceptedResponseCount: Int {
        responseAuthority.count
    }

    public func makeAttempt(
        lease: StageBAttemptLease,
        expectedRequest: StageBRequest
    ) throws -> StageBProtectedFlowAttempt {
        let requestDatagram = try StageBReflectorCodec.encodeRequest(
            expectedRequest,
            key: key
        )
        let exactRequestTag = Array(requestDatagram.suffix(32))
        return try StageBProtectedFlowAttempt(
            lease: lease,
            expectedRequest: expectedRequest,
            requestDatagram: requestDatagram,
            exactRequestTag: exactRequestTag,
            domainKey: key,
            responseAuthority: responseAuthority
        )
    }
}

public struct StageBAttemptLease: Equatable, Sendable {
    public let attemptNonce: [UInt8]
    public let pathID: [UInt8]
    public let context: WCF3ConnectionContext
    public let requestedAtMonotonicNanoseconds: UInt64
    public let deadlineMonotonicNanoseconds: UInt64

    public init(
        attemptNonce: [UInt8],
        pathID: [UInt8],
        context: WCF3ConnectionContext,
        requestedAtMonotonicNanoseconds: UInt64
    ) throws {
        guard attemptNonce.count == 16,
              !attemptNonce.allSatisfy({ $0 == 0 }),
              pathID.count == 16,
              !pathID.allSatisfy({ $0 == 0 })
        else {
            throw StageBError.invalidIdentifier
        }
        let (deadline, overflow) =
            requestedAtMonotonicNanoseconds.addingReportingOverflow(
                StageBProtectedFlow.deadlineNanoseconds
            )
        guard !overflow else { throw StageBError.arithmeticOverflow }
        self.attemptNonce = attemptNonce
        self.pathID = pathID
        self.context = context
        self.requestedAtMonotonicNanoseconds =
            requestedAtMonotonicNanoseconds
        self.deadlineMonotonicNanoseconds = deadline
    }
}

public struct StageBEventBinding: Equatable, Sendable {
    public let attemptNonce: [UInt8]
    public let pathID: [UInt8]
    public let context: WCF3ConnectionContext

    public init(lease: StageBAttemptLease) {
        attemptNonce = lease.attemptNonce
        pathID = lease.pathID
        context = lease.context
    }
}

public enum StageBAttemptStatus: String, Equatable, Sendable {
    case active
    case succeeded
    case failed
    case cancelled
    case superseded
}

public struct StageBLocalReceipt: Equatable, Sendable {
    public let schema: String
    public let protocolVersion: String
    public let measurementScope: String
    public let status: StageBAttemptStatus
    public let freshAWGHandshake: Bool
    public let authenticatedOutboundBytesObserved: Bool
    public let authenticatedInboundBytesObserved: Bool
    public let protectedDNSResponseObserved: Bool
    public let authenticatedReflectorResponseObserved: Bool
    public let reflectorObservedAtMonotonicNanoseconds: UInt64?

    fileprivate init(
        status: StageBAttemptStatus,
        freshAWGHandshake: Bool,
        outbound: Bool,
        inbound: Bool,
        dns: Bool,
        reflector: Bool,
        reflectorObservedAtMonotonicNanoseconds: UInt64?
    ) {
        schema = "winn-stageb-local-receipt/1"
        protocolVersion = StageBProtectedFlow.protocolVersion
        measurementScope = StageBProtectedFlow.receiptScope
        self.status = status
        self.freshAWGHandshake = freshAWGHandshake
        authenticatedOutboundBytesObserved = outbound
        authenticatedInboundBytesObserved = inbound
        protectedDNSResponseObserved = dns
        authenticatedReflectorResponseObserved = reflector
        self.reflectorObservedAtMonotonicNanoseconds =
            reflectorObservedAtMonotonicNanoseconds
    }
}

/// The single lifecycle and acceptance authority for one Stage B attempt.
///
/// Every mutable transition is serialized by this coordinator. There is no
/// separate response acceptor whose cancellation state could diverge.
public final class StageBProtectedFlowAttempt: @unchecked Sendable {
    public let lease: StageBAttemptLease
    public let expectedRequest: StageBRequest
    public let requestDatagram: Data

    private let responseAuthority: StageBResponseReplayAuthority
    private let exactRequestTag: [UInt8]
    private let domainKey: [UInt8]
    private let lock = NSLock()
    private var state: StageBAttemptStatus = .active
    private var handshake = false
    private var outbound = false
    private var inbound = false
    private var dns = false
    private var reflector = false
    private var reflectorObservedAtMonotonicNanoseconds: UInt64?
    private var lastEventMonotonicNanoseconds: UInt64

    public var status: StageBAttemptStatus {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    fileprivate init(
        lease: StageBAttemptLease,
        expectedRequest: StageBRequest,
        requestDatagram: Data,
        exactRequestTag: [UInt8],
        domainKey: [UInt8],
        responseAuthority: StageBResponseReplayAuthority
    ) throws {
        guard expectedRequest.attemptNonce == lease.attemptNonce,
              expectedRequest.context == lease.context
        else {
            throw StageBError.bindingMismatch
        }
        guard expectedRequest.requestSentMonotonicNanoseconds >=
                lease.requestedAtMonotonicNanoseconds
        else {
            throw StageBError.reversedTime
        }
        guard expectedRequest.requestSentMonotonicNanoseconds <=
                lease.deadlineMonotonicNanoseconds
        else {
            throw StageBError.deadlineExceeded
        }
        self.lease = lease
        self.expectedRequest = expectedRequest
        self.requestDatagram = requestDatagram
        self.exactRequestTag = exactRequestTag
        self.domainKey = Array(domainKey)
        self.responseAuthority = responseAuthority
        lastEventMonotonicNanoseconds =
            lease.requestedAtMonotonicNanoseconds
    }

    @discardableResult
    public func recordFreshAWGHandshake(
        binding: StageBEventBinding,
        atMonotonicNanoseconds time: UInt64
    ) throws -> StageBAttemptStatus {
        lock.lock()
        defer { lock.unlock() }
        try prepareLocked(binding: binding, time: time)
        guard !handshake else {
            return try failLocked(.duplicateEvent)
        }
        guard !outbound, !inbound, !dns, !reflector else {
            return try failLocked(.invalidSequence)
        }
        handshake = true
        lastEventMonotonicNanoseconds = time
        return finishIfCompleteLocked()
    }

    @discardableResult
    public func recordAuthenticatedTunnelBytes(
        binding: StageBEventBinding,
        outboundBytes: UInt64,
        inboundBytes: UInt64,
        atMonotonicNanoseconds time: UInt64
    ) throws -> StageBAttemptStatus {
        lock.lock()
        defer { lock.unlock() }
        try prepareLocked(binding: binding, time: time)
        guard !outbound, !inbound else {
            return try failLocked(.duplicateEvent)
        }
        guard handshake, !dns, !reflector else {
            return try failLocked(.invalidSequence)
        }
        guard outboundBytes > 0, inboundBytes > 0 else {
            return try failLocked(.invalidByteCount)
        }
        outbound = true
        inbound = true
        lastEventMonotonicNanoseconds = time
        return finishIfCompleteLocked()
    }

    @discardableResult
    public func recordProtectedDNSResponse(
        binding: StageBEventBinding,
        atMonotonicNanoseconds time: UInt64
    ) throws -> StageBAttemptStatus {
        lock.lock()
        defer { lock.unlock() }
        try prepareLocked(binding: binding, time: time)
        guard !dns else {
            return try failLocked(.duplicateEvent)
        }
        guard handshake, outbound, inbound, !reflector else {
            return try failLocked(.invalidSequence)
        }
        dns = true
        lastEventMonotonicNanoseconds = time
        return finishIfCompleteLocked()
    }

    @discardableResult
    public func acceptAuthenticatedReflectorResponse(
        _ datagram: Data
    ) throws -> StageBAttemptStatus {
        lock.lock()
        defer { lock.unlock() }
        try prepareLifecycleLocked()
        guard !reflector else {
            return try failLocked(.duplicateEvent)
        }
        guard handshake, outbound, inbound, dns else {
            return try failLocked(.invalidSequence)
        }
        let response: StageBVerifiedResponse
        do {
            response = try StageBReflectorCodec.verifyResponse(
                datagram,
                expectedRequest: expectedRequest,
                exactOutboundRequestTag: exactRequestTag,
                key: domainKey
            )
            let lowerBound = max(
                lease.requestedAtMonotonicNanoseconds,
                expectedRequest.requestSentMonotonicNanoseconds,
                lastEventMonotonicNanoseconds
            )
            let processingNow = try responseAuthority.consume(
                responseTag: response.responseTag,
                notBeforeMonotonicNanoseconds: lowerBound,
                expiresAtMonotonicNanoseconds:
                    lease.deadlineMonotonicNanoseconds
            )
            reflectorObservedAtMonotonicNanoseconds = processingNow
            lastEventMonotonicNanoseconds = processingNow
        } catch let error as StageBError {
            return try failLocked(error)
        } catch {
            return try failLocked(.authenticationFailed)
        }
        reflector = true
        return finishIfCompleteLocked()
    }

    public func cancel() {
        lock.lock()
        defer { lock.unlock() }
        guard state == .active else { return }
        state = .cancelled
    }

    public func supersedePath() {
        lock.lock()
        defer { lock.unlock() }
        guard state == .active else { return }
        state = .superseded
    }

    public func timeout(atMonotonicNanoseconds time: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .active,
              time > lease.deadlineMonotonicNanoseconds
        else { return }
        state = .failed
    }

    public func localReceipt() -> StageBLocalReceipt {
        lock.lock()
        defer { lock.unlock() }
        return StageBLocalReceipt(
            status: state,
            freshAWGHandshake: handshake,
            outbound: outbound,
            inbound: inbound,
            dns: dns,
            reflector: reflector,
            reflectorObservedAtMonotonicNanoseconds:
                reflectorObservedAtMonotonicNanoseconds
        )
    }

    private func prepareLifecycleLocked() throws {
        switch state {
        case .cancelled: throw StageBError.cancelled
        case .superseded: throw StageBError.superseded
        case .succeeded, .failed: throw StageBError.terminal
        case .active: break
        }
    }

    private func prepareLocked(
        binding: StageBEventBinding,
        time: UInt64
    ) throws {
        switch state {
        case .cancelled: throw StageBError.cancelled
        case .superseded: throw StageBError.superseded
        case .succeeded, .failed: throw StageBError.terminal
        case .active: break
        }
        guard binding.attemptNonce == lease.attemptNonce,
              binding.pathID == lease.pathID,
              binding.context == lease.context
        else {
            return try failVoidLocked(.bindingMismatch)
        }
        guard time >= lease.requestedAtMonotonicNanoseconds,
              time >= lastEventMonotonicNanoseconds
        else {
            return try failVoidLocked(.reversedTime)
        }
        guard time <= lease.deadlineMonotonicNanoseconds else {
            return try failVoidLocked(.deadlineExceeded)
        }
    }

    private func finishIfCompleteLocked() -> StageBAttemptStatus {
        if handshake && outbound && inbound && dns && reflector {
            state = .succeeded
        }
        return state
    }

    private func failLocked(
        _ error: StageBError
    ) throws -> StageBAttemptStatus {
        state = .failed
        throw error
    }

    private func failVoidLocked(_ error: StageBError) throws {
        state = .failed
        throw error
    }
}
