import Dispatch
import Foundation

// MARK: - Scope

/// Start-latency evidence shared by the isolated spike's host app and its
/// Packet Tunnel provider.
///
/// WHAT A PASSING MEASUREMENT PROVES, AND WHAT IT DOES NOT.
/// The Stage A provider installs only the synthetic RFC 2544 benchmark route
/// (`198.18.0.0/15`), performs no remote handshake, opens no socket, and
/// forwards no packet. A host-observed `NEVPNStatus.connected` inside the
/// 3.000-second bound therefore proves exactly one thing: a physical iOS
/// Packet Tunnel extension was activated and the host saw the connected state
/// within that interval. It does NOT prove that a usable VPN connection
/// exists, and it does NOT measure time-to-first-protected-packet. Measuring
/// the first protected flow is a separate later real-network gate; no value
/// produced by this file may be presented as that measurement.
public enum StartLatencyScope {
    /// Carried verbatim in every attestation and receipt so the narrow claim
    /// travels with the evidence instead of living only in documentation.
    public static let measurementScope = "ios-packet-tunnel-activation-only"

    /// A host start receipt is an observation artifact, not an attempt commit.
    ///
    /// Receipt persistence is deliberately performed off the main actor and
    /// may finish after the attempt deadline because a kernel write/sync call
    /// cannot be cancelled honestly. Consequently, the existence of the file
    /// proves only the bound activation observation and its provider evidence
    /// binding. It does NOT prove that persistence finished before a deadline,
    /// that the host reported the attempt as successful, or that the tunnel
    /// remained connected.
    public static let artifactScope =
        "activation-observation-not-attempt-success-or-persistence-timing"

    /// The host cannot encode the barrier outcome into the same immutable
    /// bytes whose publication produces that outcome. The provider JSONL
    /// barrier is bound explicitly; host receipt-file power-loss durability is
    /// therefore deliberately not claimed by the receipt itself.
    public static let hostReceiptDurabilityScope =
        "host-receipt-barrier-not-encoded-no-power-loss-claim"
}

// MARK: - Constants

public enum StartLatencyConstants {
    public static let receiptSchema =
        "winn-ios-privacy-spike-start-receipt/2"
    public static let attestationSchema =
        "winn-ios-privacy-spike-start-attestation/2"

    /// Start-option keys. Both live under the `WinnSpike` namespace so the
    /// provider can refuse anything unexpected that it owns without having to
    /// assume iOS never adds keys of its own.
    public static let optionNamespace = "WinnSpike"
    public static let nonceOptionKey = "WinnSpikeStartAttemptNonce"
    public static let requestedAtOptionKey =
        "WinnSpikeStartRequestedAtMonotonicNanoseconds"

    /// The host acceptance bound. A measured host latency equal to this value
    /// passes; one nanosecond more fails.
    public static let maximumHostStartLatencyNanoseconds: UInt64 =
        3_000_000_000

    /// Bounds the wait for a first `.connected`. It is deliberately larger
    /// than the acceptance bound so an over-budget activation is reported as
    /// a measured number rather than being indistinguishable from a tunnel
    /// that never connected at all.
    public static let startAttemptTimeoutNanoseconds: UInt64 =
        10_000_000_000

    /// Bounds the COMPLETION half of one attempt: provider attestation
    /// retrieval and immutable receipt publication. The attempt-scoped
    /// watchdog is re-armed with this budget when the first `.connected` is
    /// captured instead of being cancelled there, so no part of an attempt is
    /// left running without a deadline over it.
    public static let startAttemptCompletionTimeoutNanoseconds: UInt64 =
        5_000_000_000

    /// Bounds one provider round trip. NetworkExtension offers no guarantee
    /// that a `sendProviderMessage` reply handler is ever invoked, so every
    /// continuation the host suspends on carries its own bound; otherwise a
    /// provider that never replies suspends the attempt forever and the
    /// watchdog is the only thing left, with a suspended continuation leaked
    /// behind it.
    public static let providerMessageTimeoutNanoseconds: UInt64 =
        2_000_000_000

    /// A JSONL record plus its trailing line feed.
    public static let minimumFirstRecordBytes: UInt64 = 2
    public static let maximumFirstRecordBytes: UInt64 = 1 << 20
}

// MARK: - Errors

public enum StartLatencyError: Error, Equatable {
    /// The attempt refused to produce start options because the host had not
    /// yet reported that the status observer was registered.
    case observerNotRegistered
    case attemptAlreadyActive
    case attemptNotActive
    case notificationOutsideAttempt
    case duplicateConnectedNotification
    case timedOut
    /// The attestation/publication half of the attempt ran past its deadline.
    /// Distinct from `timedOut`, which is the pre-`.connected` bound.
    case completionDeadlineExceeded
    case boundedOperationTimedOut
    case malformedStartOptions(String)
    case invalidField(String)
    case reversedClock(String)
    case arithmeticOverflow(String)
    case latencyExceedsGate
    case bindingMismatch(String)
}

// MARK: - Production-used adapter seams

/// Captures a connected timestamp only after session identity and status have
/// both been checked. The host notification adapter uses this exact helper,
/// and tests inject ordered closures to prove the clock cannot run first.
public enum StartLatencyConnectedObservation {
    public static func capture(
        expectedSession: () -> Bool,
        connectedStatus: () -> Bool,
        clock: () -> UInt64
    ) -> UInt64? {
        guard expectedSession(), connectedStatus() else { return nil }
        return clock()
    }
}

private final class StartLatencyOneShotGate<Value>:
    @unchecked Sendable
{
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var pending: Result<Value, Error>?
    private var finished = false

    func attach(_ continuation: CheckedContinuation<Value, Error>) {
        lock.lock()
        if let settled = pending {
            pending = nil
            lock.unlock()
            continuation.resume(with: settled)
            return
        }
        self.continuation = continuation
        lock.unlock()
    }

    func finish(_ result: Result<Value, Error>) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        if let waiting = continuation {
            continuation = nil
            lock.unlock()
            waiting.resume(with: result)
            return
        }
        pending = result
        lock.unlock()
    }
}

/// Races an adapter callback against a monotonic timeout without waiting for
/// the losing operation.
///
/// The timeout bounds the caller's result; it does not claim to cancel the
/// underlying operation. This distinction is essential for provider callbacks
/// that may never arrive and filesystem calls that may remain blocked in the
/// kernel. A late callback is consumed by the one-shot gate and cannot resume
/// the continuation twice.
public enum StartLatencyBoundedOperation {
    public static func run<Value>(
        timeoutNanoseconds: UInt64,
        start: (
            @escaping @Sendable (Result<Value, Error>) -> Void
        ) throws -> Void
    ) async throws -> Value {
        let gate = StartLatencyOneShotGate<Value>()
        // Detached deliberately: cancellation or actor blockage in the caller
        // must not disable the only bound over a provider callback.
        let timeout = Task.detached(priority: .utility) { [gate] in
            do {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
            } catch {
                return
            }
            gate.finish(
                .failure(StartLatencyError.boundedOperationTimedOut)
            )
        }
        defer { timeout.cancel() }
        return try await withCheckedThrowingContinuation {
            continuation in
            gate.attach(continuation)
            do {
                try start { result in gate.finish(result) }
            } catch {
                gate.finish(.failure(error))
            }
        }
    }
}

/// Runs blocking adapter work outside the caller's actor and bounds only the
/// result wait. Cancellation of the wait never masquerades as cancellation of
/// a kernel call; the detached operation may finish later and its result is
/// safely discarded by the one-shot gate.
public enum StartLatencyDetachedExecutor {
    public static func run<Value: Sendable>(
        timeoutNanoseconds: UInt64,
        operation: @escaping @Sendable () throws -> Value
    ) async throws -> Value {
        try await StartLatencyBoundedOperation.run(
            timeoutNanoseconds: timeoutNanoseconds
        ) { finish in
            Task.detached(priority: .utility) {
                do {
                    finish(.success(try operation()))
                } catch {
                    finish(.failure(error))
                }
            }
        }
    }
}

/// Canonical JSON evidence is sorted, does not escape path separators, and
/// has exactly one trailing LF. Host start and stop receipts both use this
/// production helper; tests exercise those actual receipt types.
public enum CanonicalEvidenceJSONLine {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [
            .sortedKeys,
            .withoutEscapingSlashes,
        ]
        var bytes = try encoder.encode(value)
        bytes.append(0x0a)
        return bytes
    }
}

/// The host's actual stop-receipt wire type.
public struct HostStopReceipt: Codable, Equatable, Sendable {
    public let schema: String
    public let protocolVersion: String
    public let runID: String
    public let evidenceFileName: String
    public let evidenceSHA256: String
    public let requestedAtMonotonicNanoseconds: UInt64
    public let providerReceivedAtMonotonicNanoseconds: UInt64
    public let providerAcknowledgedAtMonotonicNanoseconds: UInt64
    public let hostReceivedAtMonotonicNanoseconds: UInt64
    public let roundTripNanoseconds: UInt64

    public init(
        schema: String,
        protocolVersion: String,
        runID: String,
        evidenceFileName: String,
        evidenceSHA256: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64,
        providerAcknowledgedAtMonotonicNanoseconds: UInt64,
        hostReceivedAtMonotonicNanoseconds: UInt64,
        roundTripNanoseconds: UInt64
    ) {
        self.schema = schema
        self.protocolVersion = protocolVersion
        self.runID = runID
        self.evidenceFileName = evidenceFileName
        self.evidenceSHA256 = evidenceSHA256
        self.requestedAtMonotonicNanoseconds =
            requestedAtMonotonicNanoseconds
        self.providerReceivedAtMonotonicNanoseconds =
            providerReceivedAtMonotonicNanoseconds
        self.providerAcknowledgedAtMonotonicNanoseconds =
            providerAcknowledgedAtMonotonicNanoseconds
        self.hostReceivedAtMonotonicNanoseconds =
            hostReceivedAtMonotonicNanoseconds
        self.roundTripNanoseconds = roundTripNanoseconds
    }
}

// MARK: - Canonical decimal text

/// Canonical unsigned decimal text: ASCII digits only, no sign, no whitespace,
/// no separators, no leading zero unless the value is exactly `0`, and an
/// exact round trip. Hand-rolled rather than delegated to `UInt64(String)`,
/// which accepts forms this evidence format must reject.
///
/// Honest note on the two redundant guards below. The explicit leading-zero
/// refusal and the closing round-trip check are JOINTLY load-bearing, not
/// individually: mutation showed that removing either one alone leaves the
/// suite green, because each catches every leading-zero form the other does,
/// and only removing both lets `"007"` through. Both are kept — the explicit
/// guard states the rule where a reader looks for it, and the round trip also
/// covers an accumulation bug that the guard cannot see — but neither may be
/// described as the check that stops non-canonical text on its own.
public enum CanonicalDecimal {
    public static func encode(_ value: UInt64) -> String {
        String(value)
    }

    public static func decode(_ text: String) -> UInt64? {
        let bytes = Array(text.utf8)
        // 18446744073709551615 is 20 digits; anything longer cannot be a
        // canonical UInt64 and is rejected before any arithmetic runs.
        guard !bytes.isEmpty, bytes.count <= 20 else { return nil }
        for byte in bytes where byte < 0x30 || byte > 0x39 {
            return nil
        }
        if bytes.count > 1, bytes[0] == 0x30 { return nil }
        var value: UInt64 = 0
        for byte in bytes {
            let (scaled, scaleOverflow) =
                value.multipliedReportingOverflow(by: 10)
            guard !scaleOverflow else { return nil }
            let (sum, sumOverflow) =
                scaled.addingReportingOverflow(UInt64(byte - 0x30))
            guard !sumOverflow else { return nil }
            value = sum
        }
        guard encode(value) == text else { return nil }
        return value
    }
}

// MARK: - Field validation

public enum StartLatencyValidation {
    /// Lowercase canonical UUID text. `Foundation.UUID(uuidString:)` accepts
    /// uppercase and is therefore not usable as this check.
    public static func isLowercaseUUID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 36 else { return false }
        for (index, byte) in bytes.enumerated() {
            switch index {
            case 8, 13, 18, 23:
                if byte != 0x2d { return false }
            default:
                let isDigit = byte >= 0x30 && byte <= 0x39
                let isLowerHex = byte >= 0x61 && byte <= 0x66
                if !isDigit, !isLowerHex { return false }
            }
        }
        return true
    }

    public static func isLowercaseSHA256(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 64 else { return false }
        for byte in bytes {
            let isDigit = byte >= 0x30 && byte <= 0x39
            let isLowerHex = byte >= 0x61 && byte <= 0x66
            if !isDigit, !isLowerHex { return false }
        }
        return true
    }

    /// A source digest must be a real digest. An all-zero placeholder is the
    /// exact value an unset `WINN_SPIKE_SOURCE_DIGEST` build setting would
    /// most plausibly be filled with by hand, so it is refused.
    public static func isBoundSourceDigest(_ value: String) -> Bool {
        isLowercaseSHA256(value) &&
            value != String(repeating: "0", count: 64)
    }

    public static func evidenceRelativePath(runID: String) -> String {
        "Evidence/runtime/\(runID)/stage-a.jsonl"
    }

    public static func evidenceFileName(runID: String) -> String {
        "\(runID).jsonl"
    }

    public static func startReceiptFileName(runID: String) -> String {
        "\(runID).start-receipt.json"
    }
}

// MARK: - Start options

public enum StartLatencyStartOptions {
    public static func encode(
        attemptNonce: String,
        requestedAtMonotonicNanoseconds: UInt64
    ) throws -> [String: String] {
        guard StartLatencyValidation.isLowercaseUUID(attemptNonce) else {
            throw StartLatencyError.invalidField("attemptNonce")
        }
        return [
            StartLatencyConstants.nonceOptionKey: attemptNonce,
            StartLatencyConstants.requestedAtOptionKey:
                CanonicalDecimal.encode(requestedAtMonotonicNanoseconds),
        ]
    }

    /// Strictly parses the spike's own start options.
    ///
    /// The caller passes only the entries whose keys begin with the
    /// `WinnSpike` namespace. Exactly the two known keys must be present, both
    /// values must be canonical, and any other namespaced key is refused.
    /// Keys outside the namespace are not inspected here: iOS owns the option
    /// dictionary it hands to `startTunnel(options:)` and this code cannot
    /// prove the system never adds entries of its own, so refusing unknown
    /// foreign keys would be a claim it cannot support.
    public static func parse(
        namespacedOptions: [String: String]
    ) throws -> (attemptNonce: String, requestedAtMonotonicNanoseconds: UInt64) {
        guard namespacedOptions.count == 2 else {
            throw StartLatencyError.malformedStartOptions("key set")
        }
        guard let nonce =
            namespacedOptions[StartLatencyConstants.nonceOptionKey]
        else {
            throw StartLatencyError.malformedStartOptions("nonce absent")
        }
        guard let requestedText =
            namespacedOptions[StartLatencyConstants.requestedAtOptionKey]
        else {
            throw StartLatencyError.malformedStartOptions("requested absent")
        }
        guard StartLatencyValidation.isLowercaseUUID(nonce) else {
            throw StartLatencyError.malformedStartOptions("nonce")
        }
        guard let requested = CanonicalDecimal.decode(requestedText) else {
            throw StartLatencyError.malformedStartOptions("requested")
        }
        return (nonce, requested)
    }
}

// MARK: - Provider attestation

/// What the Packet Tunnel provider attests about one start attempt.
///
/// The only way to obtain a fresh instance is
/// `ProviderStartAttestationRecorder.recordFirstStartedRecord`, which requires
/// a durable first-record append to have succeeded. Decoding is separately
/// available and revalidates every field, so a malformed attestation cannot be
/// decoded at all.
public struct ProviderStartAttestation: Codable, Equatable, Sendable {
    public let schema: String
    public let protocolVersion: String
    public let runID: String
    public let attemptNonce: String
    public let sourceDigest: String
    public let evidenceRelativePath: String
    public let firstRecordSHA256: String
    public let firstRecordBytes: UInt64
    public let evidenceDurabilityBarrier: String
    public let requestedAtMonotonicNanoseconds: UInt64
    public let providerReceivedAtMonotonicNanoseconds: UInt64
    public let providerReadyAtMonotonicNanoseconds: UInt64
    public let providerStartLatencyNanoseconds: UInt64
    public let measurementScope: String

    init(
        runID: String,
        attemptNonce: String,
        sourceDigest: String,
        firstRecordSHA256: String,
        firstRecordBytes: UInt64,
        evidenceDurabilityBarrier: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64,
        providerReadyAtMonotonicNanoseconds: UInt64
    ) throws {
        schema = StartLatencyConstants.attestationSchema
        protocolVersion = WCF3Constants.protocolVersion
        self.runID = runID
        self.attemptNonce = attemptNonce
        self.sourceDigest = sourceDigest
        evidenceRelativePath =
            StartLatencyValidation.evidenceRelativePath(runID: runID)
        self.firstRecordSHA256 = firstRecordSHA256
        self.firstRecordBytes = firstRecordBytes
        self.evidenceDurabilityBarrier = evidenceDurabilityBarrier
        self.requestedAtMonotonicNanoseconds =
            requestedAtMonotonicNanoseconds
        self.providerReceivedAtMonotonicNanoseconds =
            providerReceivedAtMonotonicNanoseconds
        self.providerReadyAtMonotonicNanoseconds =
            providerReadyAtMonotonicNanoseconds
        guard providerReadyAtMonotonicNanoseconds >=
            providerReceivedAtMonotonicNanoseconds
        else {
            throw StartLatencyError.reversedClock("providerReady")
        }
        providerStartLatencyNanoseconds =
            providerReadyAtMonotonicNanoseconds -
            providerReceivedAtMonotonicNanoseconds
        measurementScope = StartLatencyScope.measurementScope
        try validate()
    }

    /// Test seam: builds an instance without recomputing the derived latency,
    /// so a mutation test can present a self-inconsistent attestation to the
    /// validator. Not reachable from the provider, which has no access to it.
    init(
        schema: String,
        protocolVersion: String,
        runID: String,
        attemptNonce: String,
        sourceDigest: String,
        evidenceRelativePath: String,
        firstRecordSHA256: String,
        firstRecordBytes: UInt64,
        evidenceDurabilityBarrier: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64,
        providerReadyAtMonotonicNanoseconds: UInt64,
        providerStartLatencyNanoseconds: UInt64,
        measurementScope: String
    ) {
        self.schema = schema
        self.protocolVersion = protocolVersion
        self.runID = runID
        self.attemptNonce = attemptNonce
        self.sourceDigest = sourceDigest
        self.evidenceRelativePath = evidenceRelativePath
        self.firstRecordSHA256 = firstRecordSHA256
        self.firstRecordBytes = firstRecordBytes
        self.evidenceDurabilityBarrier = evidenceDurabilityBarrier
        self.requestedAtMonotonicNanoseconds =
            requestedAtMonotonicNanoseconds
        self.providerReceivedAtMonotonicNanoseconds =
            providerReceivedAtMonotonicNanoseconds
        self.providerReadyAtMonotonicNanoseconds =
            providerReadyAtMonotonicNanoseconds
        self.providerStartLatencyNanoseconds =
            providerStartLatencyNanoseconds
        self.measurementScope = measurementScope
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(String.self, forKey: .schema)
        protocolVersion = try container.decode(
            String.self, forKey: .protocolVersion
        )
        runID = try container.decode(String.self, forKey: .runID)
        attemptNonce = try container.decode(
            String.self, forKey: .attemptNonce
        )
        sourceDigest = try container.decode(
            String.self, forKey: .sourceDigest
        )
        evidenceRelativePath = try container.decode(
            String.self, forKey: .evidenceRelativePath
        )
        firstRecordSHA256 = try container.decode(
            String.self, forKey: .firstRecordSHA256
        )
        firstRecordBytes = try container.decode(
            UInt64.self, forKey: .firstRecordBytes
        )
        evidenceDurabilityBarrier = try container.decode(
            String.self, forKey: .evidenceDurabilityBarrier
        )
        requestedAtMonotonicNanoseconds = try container.decode(
            UInt64.self, forKey: .requestedAtMonotonicNanoseconds
        )
        providerReceivedAtMonotonicNanoseconds = try container.decode(
            UInt64.self, forKey: .providerReceivedAtMonotonicNanoseconds
        )
        providerReadyAtMonotonicNanoseconds = try container.decode(
            UInt64.self, forKey: .providerReadyAtMonotonicNanoseconds
        )
        providerStartLatencyNanoseconds = try container.decode(
            UInt64.self, forKey: .providerStartLatencyNanoseconds
        )
        measurementScope = try container.decode(
            String.self, forKey: .measurementScope
        )
        try validate()
    }

    public func validate() throws {
        guard schema == StartLatencyConstants.attestationSchema else {
            throw StartLatencyError.invalidField("schema")
        }
        guard protocolVersion == WCF3Constants.protocolVersion else {
            throw StartLatencyError.invalidField("protocolVersion")
        }
        guard StartLatencyValidation.isLowercaseUUID(runID) else {
            throw StartLatencyError.invalidField("runID")
        }
        guard StartLatencyValidation.isLowercaseUUID(attemptNonce) else {
            throw StartLatencyError.invalidField("attemptNonce")
        }
        guard StartLatencyValidation.isBoundSourceDigest(sourceDigest) else {
            throw StartLatencyError.invalidField("sourceDigest")
        }
        guard evidenceRelativePath ==
            StartLatencyValidation.evidenceRelativePath(runID: runID)
        else {
            throw StartLatencyError.invalidField("evidenceRelativePath")
        }
        guard StartLatencyValidation
            .isLowercaseSHA256(firstRecordSHA256)
        else {
            throw StartLatencyError.invalidField("firstRecordSHA256")
        }
        guard firstRecordBytes >=
            StartLatencyConstants.minimumFirstRecordBytes,
            firstRecordBytes <=
            StartLatencyConstants.maximumFirstRecordBytes
        else {
            throw StartLatencyError.invalidField("firstRecordBytes")
        }
        guard SpikeDurabilityBarrier(
            rawValue: evidenceDurabilityBarrier
        ) != nil else {
            throw StartLatencyError.invalidField(
                "evidenceDurabilityBarrier"
            )
        }
        guard measurementScope == StartLatencyScope.measurementScope else {
            throw StartLatencyError.invalidField("measurementScope")
        }
        try StartLatencyClocks.requireInterval(
            from: requestedAtMonotonicNanoseconds,
            to: providerReceivedAtMonotonicNanoseconds,
            named: "providerReceived"
        )
        try StartLatencyClocks.requireInterval(
            from: providerReceivedAtMonotonicNanoseconds,
            to: providerReadyAtMonotonicNanoseconds,
            named: "providerReady",
            equals: providerStartLatencyNanoseconds,
            latencyField: "providerStartLatencyNanoseconds"
        )
    }
}

// MARK: - Clock checks

enum StartLatencyClocks {
    /// Refuses a reversed interval and, when a declared duration is supplied,
    /// requires `from + duration == to` computed with overflow reporting.
    ///
    /// Honest note on what each half detects. The reversed-clock guard is
    /// DIAGNOSTIC, not independently load-bearing: a reversed pair also fails
    /// the arithmetic identity, just with a less specific error. The
    /// overflow-reported addition IS load-bearing — a declared duration large
    /// enough to wrap is refused here and nowhere else.
    static func requireInterval(
        from start: UInt64,
        to end: UInt64,
        named name: String,
        equals declared: UInt64? = nil,
        latencyField: String = ""
    ) throws {
        guard end >= start else {
            throw StartLatencyError.reversedClock(name)
        }
        guard let declared else { return }
        let (recomputed, overflow) =
            start.addingReportingOverflow(declared)
        guard !overflow else {
            throw StartLatencyError.arithmeticOverflow(latencyField)
        }
        guard recomputed == end else {
            throw StartLatencyError.invalidField(latencyField)
        }
    }
}

// MARK: - Host receipt

/// The host's canonical activation-observation receipt.
///
/// This is deliberately NOT called an attempt acceptance or commit receipt.
/// Its existence does not assert when host persistence completed or that the
/// host kept the attempt successful; `artifactScope` carries that limitation
/// inside every encoded artifact. See `StartLatencyScope`.
public struct HostStartReceipt: Codable, Equatable, Sendable {
    public let schema: String
    public let protocolVersion: String
    public let runID: String
    public let attemptNonce: String
    public let sourceDigest: String
    public let evidenceFileName: String
    public let firstRecordSHA256: String
    public let firstRecordBytes: UInt64
    public let evidenceDurabilityBarrier: String
    public let requestedAtMonotonicNanoseconds: UInt64
    public let providerReceivedAtMonotonicNanoseconds: UInt64
    public let providerReadyAtMonotonicNanoseconds: UInt64
    public let providerStartLatencyNanoseconds: UInt64
    public let hostObservedConnectedAtMonotonicNanoseconds: UInt64
    public let hostStartLatencyNanoseconds: UInt64
    public let measurementScope: String
    public let artifactScope: String
    public let hostReceiptDurabilityScope: String

    init(
        schema: String = StartLatencyConstants.receiptSchema,
        protocolVersion: String = WCF3Constants.protocolVersion,
        runID: String,
        attemptNonce: String,
        sourceDigest: String,
        evidenceFileName: String,
        firstRecordSHA256: String,
        firstRecordBytes: UInt64,
        evidenceDurabilityBarrier: String,
        requestedAtMonotonicNanoseconds: UInt64,
        providerReceivedAtMonotonicNanoseconds: UInt64,
        providerReadyAtMonotonicNanoseconds: UInt64,
        providerStartLatencyNanoseconds: UInt64,
        hostObservedConnectedAtMonotonicNanoseconds: UInt64,
        hostStartLatencyNanoseconds: UInt64,
        measurementScope: String = StartLatencyScope.measurementScope,
        artifactScope: String = StartLatencyScope.artifactScope,
        hostReceiptDurabilityScope: String =
            StartLatencyScope.hostReceiptDurabilityScope
    ) {
        self.schema = schema
        self.protocolVersion = protocolVersion
        self.runID = runID
        self.attemptNonce = attemptNonce
        self.sourceDigest = sourceDigest
        self.evidenceFileName = evidenceFileName
        self.firstRecordSHA256 = firstRecordSHA256
        self.firstRecordBytes = firstRecordBytes
        self.evidenceDurabilityBarrier = evidenceDurabilityBarrier
        self.requestedAtMonotonicNanoseconds =
            requestedAtMonotonicNanoseconds
        self.providerReceivedAtMonotonicNanoseconds =
            providerReceivedAtMonotonicNanoseconds
        self.providerReadyAtMonotonicNanoseconds =
            providerReadyAtMonotonicNanoseconds
        self.providerStartLatencyNanoseconds =
            providerStartLatencyNanoseconds
        self.hostObservedConnectedAtMonotonicNanoseconds =
            hostObservedConnectedAtMonotonicNanoseconds
        self.hostStartLatencyNanoseconds = hostStartLatencyNanoseconds
        self.measurementScope = measurementScope
        self.artifactScope = artifactScope
        self.hostReceiptDurabilityScope = hostReceiptDurabilityScope
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(String.self, forKey: .schema)
        protocolVersion = try container.decode(
            String.self, forKey: .protocolVersion
        )
        runID = try container.decode(String.self, forKey: .runID)
        attemptNonce = try container.decode(
            String.self, forKey: .attemptNonce
        )
        sourceDigest = try container.decode(
            String.self, forKey: .sourceDigest
        )
        evidenceFileName = try container.decode(
            String.self, forKey: .evidenceFileName
        )
        firstRecordSHA256 = try container.decode(
            String.self, forKey: .firstRecordSHA256
        )
        firstRecordBytes = try container.decode(
            UInt64.self, forKey: .firstRecordBytes
        )
        evidenceDurabilityBarrier = try container.decode(
            String.self, forKey: .evidenceDurabilityBarrier
        )
        requestedAtMonotonicNanoseconds = try container.decode(
            UInt64.self, forKey: .requestedAtMonotonicNanoseconds
        )
        providerReceivedAtMonotonicNanoseconds = try container.decode(
            UInt64.self, forKey: .providerReceivedAtMonotonicNanoseconds
        )
        providerReadyAtMonotonicNanoseconds = try container.decode(
            UInt64.self, forKey: .providerReadyAtMonotonicNanoseconds
        )
        providerStartLatencyNanoseconds = try container.decode(
            UInt64.self, forKey: .providerStartLatencyNanoseconds
        )
        hostObservedConnectedAtMonotonicNanoseconds =
            try container.decode(
                UInt64.self,
                forKey: .hostObservedConnectedAtMonotonicNanoseconds
            )
        hostStartLatencyNanoseconds = try container.decode(
            UInt64.self, forKey: .hostStartLatencyNanoseconds
        )
        measurementScope = try container.decode(
            String.self, forKey: .measurementScope
        )
        artifactScope = try container.decode(
            String.self, forKey: .artifactScope
        )
        hostReceiptDurabilityScope = try container.decode(
            String.self, forKey: .hostReceiptDurabilityScope
        )
        try validate()
    }

    public func validate() throws {
        guard schema == StartLatencyConstants.receiptSchema else {
            throw StartLatencyError.invalidField("schema")
        }
        guard protocolVersion == WCF3Constants.protocolVersion else {
            throw StartLatencyError.invalidField("protocolVersion")
        }
        guard StartLatencyValidation.isLowercaseUUID(runID) else {
            throw StartLatencyError.invalidField("runID")
        }
        guard StartLatencyValidation.isLowercaseUUID(attemptNonce) else {
            throw StartLatencyError.invalidField("attemptNonce")
        }
        guard StartLatencyValidation.isBoundSourceDigest(sourceDigest) else {
            throw StartLatencyError.invalidField("sourceDigest")
        }
        guard evidenceFileName ==
            StartLatencyValidation.evidenceFileName(runID: runID)
        else {
            throw StartLatencyError.invalidField("evidenceFileName")
        }
        guard StartLatencyValidation
            .isLowercaseSHA256(firstRecordSHA256)
        else {
            throw StartLatencyError.invalidField("firstRecordSHA256")
        }
        guard firstRecordBytes >=
            StartLatencyConstants.minimumFirstRecordBytes,
            firstRecordBytes <=
            StartLatencyConstants.maximumFirstRecordBytes
        else {
            throw StartLatencyError.invalidField("firstRecordBytes")
        }
        guard SpikeDurabilityBarrier(
            rawValue: evidenceDurabilityBarrier
        ) != nil else {
            throw StartLatencyError.invalidField(
                "evidenceDurabilityBarrier"
            )
        }
        guard measurementScope == StartLatencyScope.measurementScope else {
            throw StartLatencyError.invalidField("measurementScope")
        }
        guard artifactScope == StartLatencyScope.artifactScope else {
            throw StartLatencyError.invalidField("artifactScope")
        }
        guard hostReceiptDurabilityScope ==
            StartLatencyScope.hostReceiptDurabilityScope
        else {
            throw StartLatencyError.invalidField(
                "hostReceiptDurabilityScope"
            )
        }
        try StartLatencyClocks.requireInterval(
            from: requestedAtMonotonicNanoseconds,
            to: providerReceivedAtMonotonicNanoseconds,
            named: "providerReceived"
        )
        try StartLatencyClocks.requireInterval(
            from: providerReceivedAtMonotonicNanoseconds,
            to: providerReadyAtMonotonicNanoseconds,
            named: "providerReady",
            equals: providerStartLatencyNanoseconds,
            latencyField: "providerStartLatencyNanoseconds"
        )
        // Independently load-bearing: the host app and the extension are
        // separate processes reading the same system-wide monotonic clock,
        // and the host cannot see `.connected` before the provider finished
        // starting. Nothing else in this validator refuses that ordering.
        guard hostObservedConnectedAtMonotonicNanoseconds >=
            providerReadyAtMonotonicNanoseconds
        else {
            throw StartLatencyError.reversedClock("hostObservedConnected")
        }
        try StartLatencyClocks.requireInterval(
            from: requestedAtMonotonicNanoseconds,
            to: hostObservedConnectedAtMonotonicNanoseconds,
            named: "hostRequested",
            equals: hostStartLatencyNanoseconds,
            latencyField: "hostStartLatencyNanoseconds"
        )
        guard hostStartLatencyNanoseconds <=
            StartLatencyConstants.maximumHostStartLatencyNanoseconds
        else {
            throw StartLatencyError.latencyExceedsGate
        }
    }

    /// Cross-binding check. Deliberately separate from `validate()` and from
    /// construction so a decoded receipt can be rechecked against the
    /// attestation and the attempt inputs, and so each binding can be mutated
    /// independently in tests.
    public func validateBinding(
        attestation: ProviderStartAttestation,
        attemptNonce expectedNonce: String,
        requestedAtMonotonicNanoseconds expectedRequested: UInt64,
        sourceDigest expectedSourceDigest: String
    ) throws {
        try validate()
        try attestation.validate()
        guard attestation.attemptNonce == expectedNonce,
              attemptNonce == expectedNonce
        else {
            throw StartLatencyError.bindingMismatch("attemptNonce")
        }
        guard attestation.runID == runID else {
            throw StartLatencyError.bindingMismatch("runID")
        }
        guard attestation.sourceDigest == expectedSourceDigest,
              sourceDigest == expectedSourceDigest
        else {
            throw StartLatencyError.bindingMismatch("sourceDigest")
        }
        guard attestation.requestedAtMonotonicNanoseconds ==
            expectedRequested,
            requestedAtMonotonicNanoseconds == expectedRequested
        else {
            throw StartLatencyError.bindingMismatch(
                "requestedAtMonotonicNanoseconds"
            )
        }
        guard attestation.firstRecordSHA256 == firstRecordSHA256 else {
            throw StartLatencyError.bindingMismatch("firstRecordSHA256")
        }
        guard attestation.firstRecordBytes == firstRecordBytes else {
            throw StartLatencyError.bindingMismatch("firstRecordBytes")
        }
        guard attestation.evidenceDurabilityBarrier ==
            evidenceDurabilityBarrier
        else {
            throw StartLatencyError.bindingMismatch(
                "evidenceDurabilityBarrier"
            )
        }
        guard attestation.providerReceivedAtMonotonicNanoseconds ==
            providerReceivedAtMonotonicNanoseconds,
            attestation.providerReadyAtMonotonicNanoseconds ==
            providerReadyAtMonotonicNanoseconds
        else {
            throw StartLatencyError.bindingMismatch("providerTimestamps")
        }
    }
}

// MARK: - Host attempt state machine

/// One host start attempt.
///
/// Pure: it holds no timers, opens nothing, and knows nothing about
/// NetworkExtension. The host adapter registers the real
/// `NEVPNStatusDidChange` observer and drives this machine; the machine's job
/// is to make the required ordering and single-shot properties mechanically
/// checkable rather than a matter of reading the adapter carefully.
///
/// Not `Sendable`. The adapter confines it to the main actor, which is also
/// where the observer is registered.
public final class StartLatencyAttempt {
    public enum Phase: Equatable {
        case created
        case observing
        case awaitingConnected
        case captured
        /// The receipt store returned a barrier outcome before the attempt
        /// deadline. The immutable receipt itself explicitly does not encode
        /// or claim its host-file power-loss durability. Terminal and
        /// successful for the in-process attempt.
        case published
        case failed
    }

    public let attemptNonce: String
    public private(set) var phase: Phase = .created
    public private(set) var requestedAtMonotonicNanoseconds: UInt64?
    public private(set)
    var hostObservedConnectedAtMonotonicNanoseconds: UInt64?
    /// Set when `.connected` is captured. The completion half of the attempt
    /// must finish at or before this instant.
    public private(set) var completionDeadlineMonotonicNanoseconds: UInt64?
    public private(set) var failure: StartLatencyError?

    public init(attemptNonce: String) throws {
        guard StartLatencyValidation.isLowercaseUUID(attemptNonce) else {
            throw StartLatencyError.invalidField("attemptNonce")
        }
        self.attemptNonce = attemptNonce
    }

    /// Called by the adapter only after `NotificationCenter.addObserver`
    /// has returned.
    public func markObserverRegistered() throws {
        guard phase == .created else {
            throw StartLatencyError.attemptNotActive
        }
        phase = .observing
    }

    /// Produces the canonical start options and records the request time.
    ///
    /// This is the machine-checkable half of "observer before
    /// `startVPNTunnel`": the adapter has no other way to obtain the options
    /// it must pass, and this refuses to produce them until the observer has
    /// been registered.
    public func startOptions(
        requestedAtMonotonicNanoseconds requested: UInt64
    ) throws -> [String: String] {
        switch phase {
        case .created:
            throw StartLatencyError.observerNotRegistered
        case .observing:
            break
        case .awaitingConnected, .captured, .published, .failed:
            throw StartLatencyError.attemptNotActive
        }
        let options = try StartLatencyStartOptions.encode(
            attemptNonce: attemptNonce,
            requestedAtMonotonicNanoseconds: requested
        )
        requestedAtMonotonicNanoseconds = requested
        phase = .awaitingConnected
        return options
    }

    /// Captures the first `.connected` exactly once.
    ///
    /// A second `.connected` fails the attempt instead of overwriting the
    /// first. In production the adapter removes the observer the moment this
    /// returns, so a duplicate would have to have been queued already; the
    /// refusal exists so a duplicate can never silently change the measured
    /// number.
    ///
    /// An over-budget activation is refused HERE, not later at receipt
    /// validation. The deadline is a property of the attempt, so once the
    /// measured interval is known to exceed the bound there is nothing left to
    /// collect: no attestation is requested, no receipt is built, and the
    /// adapter stops the tunnel. The receipt validator keeps its own identical
    /// bound because a receipt can also arrive from decoding rather than from
    /// an attempt.
    @discardableResult
    public func observeConnected(
        atMonotonicNanoseconds observed: UInt64
    ) throws -> UInt64 {
        switch phase {
        case .created, .observing:
            fail(.notificationOutsideAttempt)
            throw StartLatencyError.notificationOutsideAttempt
        case .captured, .published:
            fail(.duplicateConnectedNotification)
            throw StartLatencyError.duplicateConnectedNotification
        case .failed:
            throw failure ?? StartLatencyError.attemptNotActive
        case .awaitingConnected:
            break
        }
        guard let requested = requestedAtMonotonicNanoseconds else {
            fail(.attemptNotActive)
            throw StartLatencyError.attemptNotActive
        }
        guard observed >= requested else {
            fail(.reversedClock("hostObservedConnected"))
            throw StartLatencyError.reversedClock("hostObservedConnected")
        }
        let latency = observed - requested
        guard latency <= StartLatencyConstants
            .maximumHostStartLatencyNanoseconds
        else {
            fail(.latencyExceedsGate)
            throw StartLatencyError.latencyExceedsGate
        }
        hostObservedConnectedAtMonotonicNanoseconds = observed
        // Saturating on purpose. A monotonic clock this close to `UInt64.max`
        // is not reachable on a real device, and a wrapped deadline would be
        // in the past, silently converting the bound into an immediate
        // refusal rather than the bound that was asked for.
        let (deadline, overflow) = observed.addingReportingOverflow(
            StartLatencyConstants.startAttemptCompletionTimeoutNanoseconds
        )
        completionDeadlineMonotonicNanoseconds =
            overflow ? UInt64.max : deadline
        phase = .captured
        return latency
    }

    /// Returns `true` when the attempt was still pending, meaning the adapter
    /// must stop the tunnel. A timer that fires after a successful capture is
    /// a no-op and never invalidates a good measurement.
    @discardableResult
    public func timeOut() -> Bool {
        guard phase == .awaitingConnected else { return false }
        fail(.timedOut)
        return true
    }

    /// Refuses to let the completion half of the attempt continue past its
    /// deadline. The adapter calls this after EVERY suspension point, because
    /// an `await` is exactly where an unbounded delay can be introduced.
    public func requireWithinCompletionDeadline(
        atMonotonicNanoseconds now: UInt64
    ) throws {
        guard phase == .captured,
              let deadline = completionDeadlineMonotonicNanoseconds
        else {
            throw failure ?? StartLatencyError.attemptNotActive
        }
        guard now <= deadline else {
            fail(.completionDeadlineExceeded)
            throw StartLatencyError.completionDeadlineExceeded
        }
    }

    /// Fired by the attempt-scoped watchdog once `.connected` has been
    /// captured. Returns `true` when the completion half was still running,
    /// meaning the adapter must tear the attempt down and stop the tunnel. A
    /// watchdog that fires after publication is a no-op.
    @discardableResult
    public func expireCompletion() -> Bool {
        guard phase == .captured else { return false }
        fail(.completionDeadlineExceeded)
        return true
    }

    /// Records that the immutable store returned a barrier outcome. The
    /// adapter calls it only after publish returned before the deadline. The
    /// receipt's own scope explicitly makes no host-file power-loss claim.
    public func markPublished() throws {
        guard phase == .captured else {
            throw failure ?? StartLatencyError.attemptNotActive
        }
        phase = .published
    }

    public var measuredHostLatencyNanoseconds: UInt64? {
        guard phase == .captured || phase == .published,
              let requested = requestedAtMonotonicNanoseconds,
              let observed = hostObservedConnectedAtMonotonicNanoseconds,
              observed >= requested
        else {
            return nil
        }
        return observed - requested
    }

    /// Builds the receipt for a captured attempt and rechecks every binding.
    /// Throws — and never returns a receipt — when the measured latency is
    /// above the acceptance bound.
    public func hostStartReceipt(
        attestation: ProviderStartAttestation,
        expectedSourceDigest: String
    ) throws -> HostStartReceipt {
        guard phase == .captured,
              let requested = requestedAtMonotonicNanoseconds,
              let observed = hostObservedConnectedAtMonotonicNanoseconds
        else {
            throw StartLatencyError.attemptNotActive
        }
        guard observed >= requested else {
            throw StartLatencyError.reversedClock("hostObservedConnected")
        }
        let receipt = HostStartReceipt(
            runID: attestation.runID,
            attemptNonce: attemptNonce,
            sourceDigest: attestation.sourceDigest,
            evidenceFileName: StartLatencyValidation
                .evidenceFileName(runID: attestation.runID),
            firstRecordSHA256: attestation.firstRecordSHA256,
            firstRecordBytes: attestation.firstRecordBytes,
            evidenceDurabilityBarrier:
                attestation.evidenceDurabilityBarrier,
            requestedAtMonotonicNanoseconds: requested,
            providerReceivedAtMonotonicNanoseconds:
                attestation.providerReceivedAtMonotonicNanoseconds,
            providerReadyAtMonotonicNanoseconds:
                attestation.providerReadyAtMonotonicNanoseconds,
            providerStartLatencyNanoseconds:
                attestation.providerStartLatencyNanoseconds,
            hostObservedConnectedAtMonotonicNanoseconds: observed,
            hostStartLatencyNanoseconds: observed - requested
        )
        do {
            try receipt.validateBinding(
                attestation: attestation,
                attemptNonce: attemptNonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: expectedSourceDigest
            )
        } catch {
            fail(error as? StartLatencyError ?? .attemptNotActive)
            throw error
        }
        return receipt
    }

    private func fail(_ error: StartLatencyError) {
        phase = .failed
        failure = error
    }
}

/// What a caller is permitted to do when it asks to tear an attempt down.
///
/// `stopTunnel` can only ever be `true` together with `releasedLatch`, and both
/// are `false` for an attempt that no longer owns the latch. That is the whole
/// point of the type: a stale attempt cannot be handed authority to stop a
/// tunnel that now belongs to a newer attempt, because there is no code path
/// that constructs such a value.
public struct StartLatencyTeardown: Equatable, Sendable {
    public let releasedLatch: Bool
    public let stopTunnel: Bool

    /// The stale answer. Authorises nothing at all.
    public static let none = StartLatencyTeardown(
        releasedLatch: false,
        stopTunnel: false
    )

    fileprivate init(releasedLatch: Bool, stopTunnel: Bool) {
        self.releasedLatch = releasedLatch
        self.stopTunnel = stopTunnel
    }
}

/// Value identities for the concrete session lease and completion task owned
/// by an adapter attempt. They are intentionally independent of the attempt
/// nonce: a delayed task cannot regain authority merely because it knows an
/// old nonce.
public struct StartLatencyAttemptContext: Equatable, Sendable {
    public let sessionLeaseID: String
    public let completionTaskID: String

    public init(
        sessionLeaseID: String,
        completionTaskID: String
    ) throws {
        guard StartLatencyValidation.isLowercaseUUID(sessionLeaseID) else {
            throw StartLatencyError.invalidField("sessionLeaseID")
        }
        guard StartLatencyValidation.isLowercaseUUID(completionTaskID) else {
            throw StartLatencyError.invalidField("completionTaskID")
        }
        self.sessionLeaseID = sessionLeaseID
        self.completionTaskID = completionTaskID
    }
}

/// Admits exactly one active attempt at a time, and is the single choke point
/// through which an attempt's shared resources — the status observer, the
/// watchdog, the completion task, the reported summary and the tunnel itself —
/// may be released.
///
/// Every teardown is identity-checked against the attempt that owns the latch.
/// A delayed completion belonging to an abandoned attempt therefore gets
/// `StartLatencyTeardown.none` back and can do nothing: it cannot release the
/// latch, and it cannot stop the newer attempt's tunnel. There is deliberately
/// no unchecked `release()`; the previous one made that mistake possible.
public final class StartLatencyAttemptLatch {
    private struct Active {
        let attempt: StartLatencyAttempt
        let context: StartLatencyAttemptContext?
    }

    private var active: Active?

    public init() {}

    public var hasActiveAttempt: Bool { active != nil }

    public func begin(
        attemptNonce: String,
        context: StartLatencyAttemptContext? = nil
    ) throws -> StartLatencyAttempt {
        guard active == nil else {
            throw StartLatencyError.attemptAlreadyActive
        }
        let attempt = try StartLatencyAttempt(attemptNonce: attemptNonce)
        active = Active(attempt: attempt, context: context)
        return attempt
    }

    public func current() -> StartLatencyAttempt? { active?.attempt }

    public func currentContext() -> StartLatencyAttemptContext? {
        active?.context
    }

    /// Identity, not equality: two attempts can share a nonce only through a
    /// programming error, and reference identity cannot be forged by one.
    public func isCurrent(_ attempt: StartLatencyAttempt) -> Bool {
        active?.attempt === attempt
    }

    /// The adapter's post-suspension ownership check. Both the attempt
    /// reference and its session/task context must still match.
    public func isCurrent(
        _ attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext
    ) -> Bool {
        active?.attempt === attempt && active?.context == context
    }

    /// Releases the latch for `attempt` and reports what the caller may do.
    ///
    /// Returns `.none` — releasing nothing and authorising nothing — when
    /// `attempt` is not the attempt that currently owns the latch.
    public func teardown(
        _ attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext? = nil,
        stopTunnel: Bool
    ) -> StartLatencyTeardown {
        guard active?.attempt === attempt else { return .none }
        if let context, active?.context != context { return .none }
        active = nil
        return StartLatencyTeardown(
            releasedLatch: true,
            stopTunnel: stopTunnel
        )
    }
}
