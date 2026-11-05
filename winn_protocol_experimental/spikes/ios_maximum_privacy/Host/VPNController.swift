import Combine
import CryptoKit
import Darwin
import Foundation
import NetworkExtension
import WinnPrivacyCore

private enum ExperimentalVPNError: Error {
    case providerSessionUnavailable
    case providerDidNotReply
    case invalidEvidencePath
    case appGroupUnavailable
    case hostSourceDigestUnavailable
    case startAttemptAlreadyActive
    case invalidFirstClickT0
    /// The attempt this work belongs to no longer owns the latch. Raised so a
    /// late continuation stops rather than acting on a newer attempt's tunnel.
    case startAttemptSuperseded
}

private struct ExperimentalProviderStatus: Decodable {
    let running: Bool
    let completed: Bool
    let runID: String?
    let evidenceRelativePath: String?
    let elapsedNanoseconds: UInt64
    let failureCode: String?
}

private struct ExperimentalProviderCommand: Encodable {
    let command: String
    let requestedAtMonotonicNanoseconds: UInt64
    let attemptNonce: String?
}

private struct ExperimentalStopAcknowledgement: Decodable {
    let schema: String
    let requestedAtMonotonicNanoseconds: UInt64
    let receivedAtMonotonicNanoseconds: UInt64
    let acknowledgedAtMonotonicNanoseconds: UInt64
    let status: ExperimentalProviderStatus
}

enum ExperimentalSpikeMode: String, CaseIterable, Identifiable, Sendable {
    case coreBaseline = "core-baseline"
    case maximumPrivacy = "maximum-privacy"

    var id: String { rawValue }
    var displayName: String {
        self == .coreBaseline ? "Core baseline" : "Maximum Privacy"
    }
}

enum ExperimentalTrafficProfile:
    String, CaseIterable, Identifiable, Sendable
{
    case idle
    case low
    case medium
    case saturated

    var id: String { rawValue }
    var displayName: String { rawValue.capitalized }
}

enum ExperimentalCoverSemantics:
    String, CaseIterable, Identifiable, Sendable
{
    case continuous = "continuousWhileConnected"
    case activityTail = "activityWithThirtySecondTail"

    var id: String { rawValue }
    var displayName: String {
        switch self {
        case .continuous: return "Continuous"
        case .activityTail: return "30-second activity tail"
        }
    }
}

enum ExperimentalRotationCadence:
    String, CaseIterable, Identifiable, Sendable
{
    case protocolFifteenMinutes = "protocol-15m"
    case acceleratedAllocation = "accelerated-allocation"

    var id: String { rawValue }
    var displayName: String {
        switch self {
        case .protocolFifteenMinutes: return "Protocol 15 minutes"
        case .acceleratedAllocation: return "Accelerated allocation"
        }
    }
}

enum ExperimentalDuration:
    UInt64, CaseIterable, Identifiable, Sendable
{
    case oneMinute = 60
    case fiveMinutes = 300
    case thirtyMinutes = 1_800
    case eightHours = 28_800

    var id: UInt64 { rawValue }
    var displayName: String {
        switch self {
        case .oneMinute: return "1 minute"
        case .fiveMinutes: return "5 minutes"
        case .thirtyMinutes: return "30 minutes"
        case .eightHours: return "8 hours"
        }
    }
}

enum ExperimentalTestCondition:
    String, CaseIterable, Identifiable, Sendable
{
    case foregroundWiFi = "foreground-wifi"
    case lockedWiFi = "locked-wifi"
    case unpluggedCellular = "unplugged-cellular"
    case lowPowerMode = "low-power-mode"
    case acceleratedAllocation = "accelerated-allocation"
    case eightHourLocked = "eight-hour-locked"
    case stopLatency = "stop-latency"
    case smoke

    var id: String { rawValue }
    var displayName: String {
        switch self {
        case .foregroundWiFi: return "Foreground Wi-Fi"
        case .lockedWiFi: return "Locked Wi-Fi"
        case .unpluggedCellular: return "Unplugged cellular"
        case .lowPowerMode: return "Low Power Mode"
        case .acceleratedAllocation: return "500 rotations"
        case .eightHourLocked: return "8-hour locked"
        case .stopLatency: return "Stop latency"
        case .smoke: return "Smoke"
        }
    }
}

struct ExperimentalSpikeConfiguration: Sendable {
    let mode: ExperimentalSpikeMode
    let trafficProfile: ExperimentalTrafficProfile
    let coverSemantics: ExperimentalCoverSemantics
    let rotationCadence: ExperimentalRotationCadence
    let testCondition: ExperimentalTestCondition
    let pairID: String
    let duration: ExperimentalDuration

    var summary: String {
        "\(mode.displayName), \(trafficProfile.displayName), "
            + "\(duration.displayName), \(rotationCadence.displayName), "
            + "\(testCondition.displayName), pair \(pairID.prefix(8))"
    }

    fileprivate var providerConfiguration: [String: Any] {
        [
            "schema": "winn-ios-privacy-spike/3",
            "mode": mode.rawValue,
            "traffic_profile": trafficProfile.rawValue,
            "cover_semantics": coverSemantics.rawValue,
            "rotation_cadence": rotationCadence.rawValue,
            "test_condition": testCondition.rawValue,
            "pair_id": pairID,
            "duration_seconds": NSNumber(value: duration.rawValue),
        ]
    }
}

@MainActor
final class VPNController: ObservableObject {
    static let providerBundleIdentifier =
        "org.winsvpn.experimental.wcf3privacyspike.PacketTunnel"
    static let localizedDescription =
        "WCF3 Maximum Privacy Feasibility Spike"
    static let appGroup =
        "group.org.winsvpn.experimental.wcf3privacyspike"

    @Published private(set) var status = "Not configured"
    /// Kept separate from `status` so the periodic run monitor cannot
    /// overwrite the start-latency result before an operator has read it.
    @Published private(set) var startLatencySummary =
        "No start attempt yet"
    private var manager: NETunnelProviderManager?
    private var monitorTask: Task<Void, Never>?
    private let startLatch = StartLatencyAttemptLatch()

    /// Everything one start attempt owns, kept together so nothing can be
    /// released for the wrong attempt. The session is captured at the moment
    /// the attempt begins and is the ONLY session the attempt ever talks to or
    /// stops, so a manager that has since been reloaded or replaced cannot be
    /// acted on by a late continuation.
    private struct ActiveStartAttempt {
        let attempt: StartLatencyAttempt
        let session: NETunnelProviderSession
        let context: StartLatencyAttemptContext
        var observer: NSObjectProtocol?
        var watchdog: Task<Void, Never>?
        var completion: Task<Void, Never>?
    }

    private var activeStart: ActiveStartAttempt?

    func refresh() async {
        do {
            manager = try await experimentalManagers().first
            status = manager == nil ? "Not configured" : "Configured"
        } catch {
            status = "Refresh failed: \(type(of: error))"
        }
    }

    func installExperimentalConfiguration(
        configuration: ExperimentalSpikeConfiguration
    ) async {
        do {
            let target =
                try await experimentalManagers().first ??
                NETunnelProviderManager()
            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier =
                Self.providerBundleIdentifier
            tunnelProtocol.serverAddress =
                "wcf3-privacy-spike.invalid"
            tunnelProtocol.providerConfiguration =
                configuration.providerConfiguration
            target.protocolConfiguration = tunnelProtocol
            target.localizedDescription = Self.localizedDescription
            target.isEnabled = true
            try await target.saveToPreferences()
            try await target.loadFromPreferences()
            manager = target
            status = "Configured: \(configuration.summary)"
        } catch {
            status = "Install failed: \(type(of: error))"
        }
    }

    /// Starts one measured attempt.
    ///
    /// Ordering is the whole point of this method and is fixed:
    /// 1. take the single-attempt latch;
    /// 2. register the exact `NEVPNStatusDidChange` observer on `.main`;
    /// 3. only then timestamp and call `startVPNTunnel(options:)`.
    ///
    /// `StartLatencyAttempt` refuses to produce the start options until step 2
    /// has been reported, so step 3 cannot be reached with no observer
    /// installed. The only work between the Stage A timestamp and the start
    /// call is canonically encoding and merging the disjoint Stage A and
    /// Stage B option dictionaries. It cannot be moved earlier, and charging
    /// it to the measured interval is the conservative direction.
    ///
    /// SCOPE: what this measures is Packet Tunnel activation observed by the
    /// host. It is not a usable VPN connection and not
    /// time-to-first-protected-packet. See `StartLatencyScope`.
    func start(stageBConnectButtonT0: UInt64) async {
        var begun: StartLatencyAttempt?
        do {
            guard let manager else {
                status = "Install the isolated configuration first"
                return
            }
            guard !startLatch.hasActiveAttempt else {
                throw ExperimentalVPNError.startAttemptAlreadyActive
            }
            guard Self.hostSourceDigest() != nil else {
                throw ExperimentalVPNError.hostSourceDigestUnavailable
            }
            // The provider is addressed through this exact session for the
            // whole attempt, never through `manager.connection` read again
            // later, so the attempt cannot drift onto another session.
            guard let session =
                manager.connection as? NETunnelProviderSession
            else {
                throw ExperimentalVPNError.providerSessionUnavailable
            }
            let context = try StartLatencyAttemptContext(
                sessionLeaseID: UUID().uuidString.lowercased(),
                completionTaskID: UUID().uuidString.lowercased()
            )
            let attemptNonce = UUID().uuidString.lowercased()
            let attempt = try startLatch.begin(
                attemptNonce: attemptNonce,
                context: context
            )
            begun = attempt
            activeStart = ActiveStartAttempt(
                attempt: attempt,
                session: session,
                context: context
            )
            registerStartObserver(
                for: session,
                attempt: attempt,
                context: context
            )
            try attempt.markObserverRegistered()
            let activationTimeoutSeconds =
                StartLatencyConstants.startAttemptTimeoutNanoseconds /
                1_000_000_000
            armStartWatchdog(
                for: attempt,
                context: context,
                nanoseconds: StartLatencyConstants
                    .startAttemptTimeoutNanoseconds,
                onExpiry: { $0.timeOut() },
                reason: "No NEVPNStatus.connected within "
                    + "\(activationTimeoutSeconds) s; tunnel stopped"
            )

            let requested = DispatchTime.now().uptimeNanoseconds
            let options = try attempt.startOptions(
                requestedAtMonotonicNanoseconds: requested
            )
            guard stageBConnectButtonT0 <= requested else {
                throw ExperimentalVPNError.invalidFirstClickT0
            }
            let stageBOptions = try StageBStartOptions.encode(
                attemptNonce: attemptNonce,
                connectButtonT0MonotonicNanoseconds:
                    stageBConnectButtonT0
            )
            var startOptions: [String: NSObject] = [:]
            for (key, value) in options {
                startOptions[key] = value as NSString
            }
            for (key, value) in stageBOptions {
                startOptions[key] = value as NSString
            }
            try session.startVPNTunnel(options: startOptions)
            status = "Start requested"
            startLatencySummary =
                "Awaiting the first NEVPNStatus.connected"
            startStatusMonitor()
        } catch {
            if let begun {
                abandonStartAttempt(
                    begun,
                    reason: "Start failed: \(type(of: error))",
                    stopTunnel: true
                )
            }
            status = "Start failed: \(type(of: error))"
        }
    }

    func stop() {
        monitorTask?.cancel()
        monitorTask = nil
        if let attempt = startLatch.current() {
            abandonStartAttempt(
                attempt,
                reason: "Start attempt abandoned: stop requested",
                stopTunnel: false
            )
        }
        Task { await stopWithAcknowledgement() }
    }

    func refreshRunStatus() async {
        do {
            _ = try await updateRunStatus()
        } catch {
            status = "Status unavailable: \(type(of: error))"
        }
    }

    func removeExperimentalConfiguration() async {
        do {
            monitorTask?.cancel()
            monitorTask = nil
            if let attempt = startLatch.current() {
                abandonStartAttempt(
                    attempt,
                    reason: "Start attempt abandoned: configuration removed",
                    stopTunnel: false
                )
            }
            for target in try await experimentalManagers() {
                try await target.removeFromPreferences()
            }
            manager = nil
            status = "Experimental configuration removed"
        } catch {
            status = "Removal failed: \(type(of: error))"
        }
    }

    private func startStatusMonitor() {
        monitorTask?.cancel()
        monitorTask = Task { [weak self] in
            for _ in 0 ..< 75 {
                do {
                    try await Task.sleep(
                        nanoseconds: 1_000_000_000
                    )
                } catch {
                    return
                }
                guard let self else { return }
                do {
                    if try await self.updateRunStatus() {
                        return
                    }
                } catch {
                    if Task.isCancelled { return }
                }
            }
        }
    }

    // MARK: - Start-latency evidence

    /// Registers the exact notification this measurement depends on, on the
    /// main queue, bound to this session object and this attempt only.
    ///
    /// ORDER MATTERS AND IS DELIBERATE. Identity and status are validated
    /// FIRST, and only then is the connected instant timestamped. Timestamping
    /// before the status is read would record an instant at which the tunnel
    /// was not yet known to be connected: if the status reached `.connected`
    /// after the timestamp was taken, the measured interval would be shorter
    /// than the real one. Charging this handler's own filtering to the
    /// measured interval is the conservative direction, and it is what
    /// happens now.
    private func registerStartObserver(
        for session: NETunnelProviderSession,
        attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext
    ) {
        removeStartObserver()
        // Compared by identity value rather than by capturing the session:
        // `NEVPNConnection` is not `Sendable`, and the notification block is.
        let expected = ObjectIdentifier(session)
        // Capture only the value-type nonce across the notification closure.
        // The main-actor hop resolves it back to the CURRENT latch owner, so
        // neither a non-Sendable attempt nor a stale attempt crosses queues.
        let expectedAttemptNonce = attempt.attemptNonce
        let observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: session,
            queue: .main
        ) { [weak self] notification in
            guard let observedConnection =
                notification.object as? NEVPNConnection,
                let observed = StartLatencyConnectedObservation.capture(
                    expectedSession: {
                        ObjectIdentifier(observedConnection) == expected
                    },
                    connectedStatus: {
                        observedConnection.status == .connected
                    },
                    clock: {
                        DispatchTime.now().uptimeNanoseconds
                    }
                )
            else {
                return
            }
            // The block is delivered on the main queue, which is the main
            // thread, so this is a synchronous hop and cannot reorder two
            // notifications relative to each other.
            MainActor.assumeIsolated {
                guard let self,
                      let current = self.startLatch.current(),
                      current.attemptNonce == expectedAttemptNonce,
                      self.startLatch.isCurrent(
                          current,
                          context: context
                      )
                else {
                    return
                }
                self.captureConnected(
                    atMonotonicNanoseconds: observed,
                    for: current,
                    context: context
                )
            }
        }
        activeStart?.observer = observer
    }

    private func removeStartObserver() {
        if let observer = activeStart?.observer {
            NotificationCenter.default.removeObserver(observer)
        }
        activeStart?.observer = nil
    }

    /// Arms the attempt-scoped watchdog.
    ///
    /// The watchdog is not cancelled when `.connected` arrives; it is re-armed
    /// with the completion budget, so attestation retrieval and receipt
    /// publication are covered by a deadline as well. It stands down only when
    /// the attempt is torn down or published.
    private func armStartWatchdog(
        for attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext,
        nanoseconds: UInt64,
        onExpiry: @escaping @Sendable (StartLatencyAttempt) -> Bool,
        reason: String
    ) {
        activeStart?.watchdog?.cancel()
        activeStart?.watchdog = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: nanoseconds)
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            guard let self else { return }
            // Identity is rechecked after the suspension: a watchdog belonging
            // to an attempt that has already been torn down must not fire on
            // whatever attempt happens to be current now.
            guard self.startLatch.isCurrent(
                attempt,
                context: context
            ), onExpiry(attempt) else {
                return
            }
            self.abandonStartAttempt(
                attempt,
                reason: reason,
                stopTunnel: true
            )
        }
    }

    private func captureConnected(
        atMonotonicNanoseconds observed: UInt64,
        for attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext
    ) {
        guard startLatch.isCurrent(attempt, context: context) else { return }
        // Stop listening the moment the first `.connected` is taken. A
        // duplicate that was already queued is still refused by the attempt
        // rather than silently replacing the measured number.
        removeStartObserver()
        do {
            let latency = try attempt.observeConnected(
                atMonotonicNanoseconds: observed
            )
            // Re-armed rather than cancelled: the deadline is held through
            // attestation retrieval and immutable receipt publication.
            let completionTimeoutSeconds =
                StartLatencyConstants
                    .startAttemptCompletionTimeoutNanoseconds /
                1_000_000_000
            armStartWatchdog(
                for: attempt,
                context: context,
                nanoseconds: StartLatencyConstants
                    .startAttemptCompletionTimeoutNanoseconds,
                onExpiry: { $0.expireCompletion() },
                reason: "Start evidence did not complete within "
                    + "\(completionTimeoutSeconds) s; tunnel stopped"
            )
            startLatencySummary = "Packet Tunnel activation observed in "
                + "\(latency) ns; collecting provider attestation"
            activeStart?.completion = Task { [weak self] in
                await self?.completeStartAttempt(
                    attempt,
                    context: context
                )
            }
        } catch {
            abandonStartAttempt(
                attempt,
                reason: "Start attempt refused: \(type(of: error))",
                stopTunnel: true
            )
        }
    }

    /// Collects the provider attestation and publishes the receipt for ONE
    /// attempt.
    ///
    /// Every suspension point is followed by a recheck of two things: that
    /// `attempt` still owns the latch, and that the completion deadline has
    /// not passed. Both are required. Ownership stops a delayed continuation
    /// belonging to an abandoned attempt from acting at all — it can neither
    /// publish a receipt nor release or stop a newer attempt, because
    /// `abandonStartAttempt` and `finishStartAttempt` both go through the
    /// latch's identity-checked teardown. The deadline stops a reply that
    /// arrives late but on the right attempt from being turned into a receipt.
    private func completeStartAttempt(
        _ attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext
    ) async {
        do {
            guard let owned = ownedStart(
                attempt,
                context: context
            ) else {
                return
            }
            guard let hostDigest = Self.hostSourceDigest(),
                  let requested =
                  attempt.requestedAtMonotonicNanoseconds
            else {
                throw ExperimentalVPNError.hostSourceDigestUnavailable
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [
                .sortedKeys,
                .withoutEscapingSlashes,
            ]
            let command = ExperimentalProviderCommand(
                command: "start-attestation",
                requestedAtMonotonicNanoseconds: requested,
                attemptNonce: attempt.attemptNonce
            )
            let response = try await providerResponse(
                try encoder.encode(command),
                session: owned.session
            )
            guard ownedStart(attempt, context: context) != nil else {
                throw ExperimentalVPNError.startAttemptSuperseded
            }
            try attempt.requireWithinCompletionDeadline(
                atMonotonicNanoseconds: DispatchTime.now().uptimeNanoseconds
            )
            let attestation = try JSONDecoder().decode(
                ProviderStartAttestation.self,
                from: response
            )
            // The host's own bundled digest is compared with the provider's,
            // so a host and an extension from different builds cannot produce
            // a receipt together.
            let receipt = try attempt.hostStartReceipt(
                attestation: attestation,
                expectedSourceDigest: hostDigest
            )
            guard let deadline =
                attempt.completionDeadlineMonotonicNanoseconds
            else {
                throw StartLatencyError.attemptNotActive
            }
            let published = try await persistStartReceipt(
                receipt,
                deadlineMonotonicNanoseconds: deadline
            )
            // The persistence adapter resumes at the deadline even when its
            // detached filesystem operation remains blocked. This ownership
            // check is therefore load-bearing: a late completion belonging to
            // an expired A cannot release or stop a newer B.
            guard ownedStart(attempt, context: context) != nil else {
                throw ExperimentalVPNError.startAttemptSuperseded
            }
            try attempt.requireWithinCompletionDeadline(
                atMonotonicNanoseconds: DispatchTime.now().uptimeNanoseconds
            )
            try attempt.markPublished()
            let teardown = startLatch.teardown(
                attempt,
                context: context,
                stopTunnel: false
            )
            guard teardown.releasedLatch else {
                throw ExperimentalVPNError.startAttemptSuperseded
            }
            releaseStartResources(attempt)
            startLatencySummary = "Packet Tunnel activation observed in "
                + "\(receipt.hostStartLatencyNanoseconds) ns "
                + "(activation only, not a usable connection and not "
                + "time-to-first-protected-packet; receipt persistence is "
                + "not a 3 s or attempt-success claim); \(published)"
        } catch {
            abandonStartAttempt(
                attempt,
                reason: "Start evidence rejected: \(type(of: error)); "
                    + "tunnel stopped",
                stopTunnel: true
            )
        }
    }

    /// The attempt's owned resources, or `nil` when it no longer owns them.
    private func ownedStart(
        _ attempt: StartLatencyAttempt,
        context: StartLatencyAttemptContext
    ) -> ActiveStartAttempt? {
        guard startLatch.isCurrent(attempt, context: context),
              let active = activeStart,
              active.attempt === attempt,
              active.context == context
        else {
            return nil
        }
        return active
    }

    /// Starts persistence on a detached executor and bounds only the caller's
    /// result. A kernel write or sync can continue after timeout and cannot be
    /// honestly cancelled. `HostStartReceipt.artifactScope` therefore makes a
    /// late file an activation-observation artifact only; its existence never
    /// claims persistence met this deadline or that the attempt succeeded.
    private func persistStartReceipt(
        _ receipt: HostStartReceipt,
        deadlineMonotonicNanoseconds deadline: UInt64
    ) async throws -> String {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now <= deadline else {
            throw StartLatencyError.completionDeadlineExceeded
        }
        let remaining = deadline - now
        let name = StartLatencyValidation
            .startReceiptFileName(runID: receipt.runID)
        let bytes = try CanonicalEvidenceJSONLine.encode(receipt)
        return try await StartLatencyDetachedExecutor.run(
            timeoutNanoseconds: remaining
        ) {
            let directory = try Self.collectedEvidenceDirectory()
            let outcome = try ExperimentalImmutableReceiptStore.publish(
                bytes,
                to: directory.appendingPathComponent(
                    name,
                    isDirectory: false
                )
            )
            switch outcome {
            case .published:
                return "published CollectedEvidence/\(name)"
            case .alreadyPublishedIdentical:
                return "CollectedEvidence/\(name) already "
                    + "published identically"
            }
        }
    }

    /// Tears one attempt down.
    ///
    /// The FIRST thing it does is ask the latch, which answers by identity. An
    /// attempt that no longer owns the latch gets `StartLatencyTeardown.none`
    /// back and this returns having done nothing at all: no observer removed,
    /// no watchdog or completion task cancelled, no summary overwritten, and —
    /// the property that matters most — no `stopVPNTunnel` on a session that
    /// now belongs to a newer attempt.
    private func abandonStartAttempt(
        _ attempt: StartLatencyAttempt,
        reason: String,
        stopTunnel: Bool
    ) {
        let context = activeStart?.attempt === attempt
            ? activeStart?.context
            : nil
        let teardown = startLatch.teardown(
            attempt,
            context: context,
            stopTunnel: stopTunnel
        )
        guard teardown.releasedLatch else { return }
        let session = activeStart?.attempt === attempt
            ? activeStart?.session
            : nil
        releaseStartResources(attempt)
        startLatencySummary = reason
        if teardown.stopTunnel {
            session?.stopVPNTunnel()
        }
    }

    /// Releases the observer and the tasks owned by `attempt`. Only ever
    /// called after the latch has confirmed ownership.
    private func releaseStartResources(_ attempt: StartLatencyAttempt) {
        guard activeStart?.attempt === attempt else { return }
        removeStartObserver()
        activeStart?.watchdog?.cancel()
        // The completion task is cancelled but is NOT relied upon to stop:
        // it may already be suspended inside a provider round trip that
        // ignores cancellation, which is exactly why it rechecks ownership
        // after every await.
        activeStart?.completion?.cancel()
        activeStart = nil
    }

    private static func hostSourceDigest() -> String? {
        guard let value = Bundle.main.object(
            forInfoDictionaryKey: "WinnSpikeSourceDigest"
        ) as? String,
            StartLatencyValidation.isBoundSourceDigest(value)
        else {
            return nil
        }
        return value
    }

    private func stopWithAcknowledgement() async {
        let requested = DispatchTime.now().uptimeNanoseconds
        defer { manager?.connection.stopVPNTunnel() }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let command = ExperimentalProviderCommand(
                command: "stop-and-ack",
                requestedAtMonotonicNanoseconds: requested,
                attemptNonce: nil
            )
            let response = try await providerResponse(
                try encoder.encode(command)
            )
            let acknowledgement = try JSONDecoder().decode(
                ExperimentalStopAcknowledgement.self,
                from: response
            )
            let finished = DispatchTime.now().uptimeNanoseconds
            guard acknowledgement.schema ==
                    "winn-ios-privacy-spike/3",
                  acknowledgement
                    .requestedAtMonotonicNanoseconds == requested,
                  acknowledgement
                    .receivedAtMonotonicNanoseconds >= requested,
                  acknowledgement
                    .acknowledgedAtMonotonicNanoseconds >=
                        acknowledgement
                        .receivedAtMonotonicNanoseconds,
                  finished >= requested
            else {
                status = "Stop acknowledgement invalid; evidence retained"
                return
            }
            let elapsed = finished - requested
            let retained: String
            do {
                let evidenceURL = try collectEvidenceURL(
                    acknowledgement.status
                )
                retained = try writeStopReceipt(
                    acknowledgement: acknowledgement,
                    hostReceivedNanoseconds: finished,
                    evidenceURL: evidenceURL
                )
            } catch {
                status =
                    "Stop acknowledged, but receipt collection failed"
                return
            }
            status = elapsed <= 250_000_000
                ? "Stop acknowledged in \(elapsed / 1_000_000) ms; "
                    + retained
                : "Stop exceeded 250 ms (\(elapsed / 1_000_000) ms); "
                    + retained
        } catch {
            status = "Stop acknowledgement failed; evidence retained"
        }
    }

    @discardableResult
    private func updateRunStatus() async throws -> Bool {
        let response = try await providerResponse(Data())
        let snapshot = try JSONDecoder().decode(
            ExperimentalProviderStatus.self,
            from: response
        )
        let seconds = snapshot.elapsedNanoseconds / 1_000_000_000
        if let failureCode = snapshot.failureCode {
            let retained = (try? collectEvidence(snapshot))
                ?? "provider App Group"
            status = "Failed: \(failureCode); retained in \(retained)"
            return true
        }
        if snapshot.completed {
            let collected = try collectEvidence(snapshot)
            manager?.connection.stopVPNTunnel()
            status = "Completed \(seconds) s; \(collected)"
            return true
        }
        if snapshot.running {
            let runID = snapshot.runID ?? "pending"
            status = "Running \(seconds) s; run \(runID)"
        } else {
            status = "Provider idle"
        }
        return false
    }

    private func providerResponse(_ message: Data) async throws -> Data {
        guard let session =
                manager?.connection as? NETunnelProviderSession
        else {
            throw ExperimentalVPNError.providerSessionUnavailable
        }
        return try await providerResponse(message, session: session)
    }

    /// One bounded provider round trip.
    ///
    /// NetworkExtension gives no guarantee that a `sendProviderMessage` reply
    /// handler is ever invoked. Without the bound below, a provider that never
    /// replies leaves this continuation suspended forever and the calling
    /// attempt with it. The gate resumes exactly once, from whichever of the
    /// reply and the timeout arrives first, and the reply handler's queue is
    /// not assumed.
    private func providerResponse(
        _ message: Data,
        session: NETunnelProviderSession,
        timeoutNanoseconds: UInt64 = StartLatencyConstants
            .providerMessageTimeoutNanoseconds
    ) async throws -> Data {
        try await StartLatencyBoundedOperation.run(
            timeoutNanoseconds: timeoutNanoseconds
        ) { finish in
            do {
                try session.sendProviderMessage(message) { data in
                    guard let data else {
                        finish(
                            .failure(
                                ExperimentalVPNError.providerDidNotReply
                            )
                        )
                        return
                    }
                    finish(.success(data))
                }
            } catch {
                finish(.failure(error))
            }
        }
    }

    private func collectEvidence(
        _ snapshot: ExperimentalProviderStatus
    ) throws -> String {
        let destination = try collectEvidenceURL(snapshot)
        return "CollectedEvidence/\(destination.lastPathComponent)"
    }

    private func collectEvidenceURL(
        _ snapshot: ExperimentalProviderStatus
    ) throws -> URL {
        guard let relativePath = snapshot.evidenceRelativePath,
              let runID = snapshot.runID,
              Self.isLowercaseUUID(runID),
              relativePath ==
                "Evidence/runtime/\(runID)/stage-a.jsonl"
        else {
            throw ExperimentalVPNError.invalidEvidencePath
        }
        guard let groupRoot = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroup
        ) else {
            throw ExperimentalVPNError.appGroupUnavailable
        }
        let destinationDirectory = try Self.collectedEvidenceDirectory()
        let destination = destinationDirectory.appendingPathComponent(
            "\(runID).jsonl",
            isDirectory: false
        )
        let groupResolved =
            groupRoot.resolvingSymlinksInPath().standardizedFileURL
        let source = groupRoot.appendingPathComponent(
            relativePath,
            isDirectory: false
        )
        let sourceResolved =
            source.resolvingSymlinksInPath().standardizedFileURL
        guard sourceResolved.path.hasPrefix(
            groupResolved.path + "/"
        ) else {
            throw ExperimentalVPNError.invalidEvidencePath
        }
        let temporary = destinationDirectory.appendingPathComponent(
            ".\(runID).collect-\(UUID().uuidString.lowercased()).tmp",
            isDirectory: false
        )
        do {
            try FileManager.default.copyItem(
                at: sourceResolved,
                to: temporary
            )
            guard try ExperimentalCollectedEvidenceValidator.validate(
                temporary,
                runID: runID
            ) else {
                throw ExperimentalVPNError.invalidEvidencePath
            }
            if FileManager.default.fileExists(
                atPath: destination.path
            ),
               try ExperimentalCollectedEvidenceValidator.validate(
                    destination,
                    runID: runID
               ),
               try Self.fileSHA256(destination) ==
                    Self.fileSHA256(temporary) {
                try FileManager.default.removeItem(at: temporary)
                return destination
            }
            // The copy claims durability, so it must obtain the same barrier
            // the receipt store does rather than a bare `FileHandle`
            // synchronize, which on this platform does not ask the drive to
            // flush its own cache. See `ExperimentalDurabilityBarrier` for
            // exactly how far that claim reaches.
            try ExperimentalImmutableReceiptStore
                .synchronizeArtifactDurably(at: temporary)
            if FileManager.default.fileExists(
                atPath: destination.path
            ) {
                let backup =
                    "\(runID).invalid-\(UUID().uuidString.lowercased()).jsonl"
                _ = try FileManager.default.replaceItemAt(
                    destination,
                    withItemAt: temporary,
                    backupItemName: backup
                )
            } else {
                try FileManager.default.moveItem(
                    at: temporary,
                    to: destination
                )
            }
            try ExperimentalImmutableReceiptStore
                .synchronizeArtifactDurably(at: destination)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
        return destination
    }

    private func writeStopReceipt(
        acknowledgement: ExperimentalStopAcknowledgement,
        hostReceivedNanoseconds: UInt64,
        evidenceURL: URL
    ) throws -> String {
        let status = acknowledgement.status
        guard let runID = status.runID,
              Self.isLowercaseUUID(runID),
              evidenceURL.lastPathComponent == "\(runID).jsonl",
              hostReceivedNanoseconds >=
                acknowledgement.requestedAtMonotonicNanoseconds
        else {
            throw ExperimentalVPNError.invalidEvidencePath
        }
        let evidenceData = try Data(contentsOf: evidenceURL)
        let evidenceDigest = SHA256.hash(data: evidenceData).map {
            String(format: "%02x", $0)
        }.joined()
        let receipt = HostStopReceipt(
            schema: "winn-ios-privacy-spike-stop-receipt/1",
            protocolVersion: "winn/3",
            runID: runID,
            evidenceFileName: evidenceURL.lastPathComponent,
            evidenceSHA256: evidenceDigest,
            requestedAtMonotonicNanoseconds:
                acknowledgement.requestedAtMonotonicNanoseconds,
            providerReceivedAtMonotonicNanoseconds:
                acknowledgement.receivedAtMonotonicNanoseconds,
            providerAcknowledgedAtMonotonicNanoseconds:
                acknowledgement.acknowledgedAtMonotonicNanoseconds,
            hostReceivedAtMonotonicNanoseconds:
                hostReceivedNanoseconds,
            roundTripNanoseconds:
                hostReceivedNanoseconds -
                acknowledgement.requestedAtMonotonicNanoseconds
        )
        // The stop receipt goes through the same publish-once store as the
        // start receipt: exact canonical bytes plus one line feed, published
        // at most once. A differing existing receipt is left EXACTLY as it
        // is — no backup, no replace, no temporary file — because a receipt
        // that has been published is evidence, and rewriting it while keeping
        // a copy under another name is still rewriting it.
        let bytes = try CanonicalEvidenceJSONLine.encode(receipt)
        let destination = evidenceURL.deletingLastPathComponent()
            .appendingPathComponent(
                "\(runID).stop-receipt.json",
                isDirectory: false
            )
        _ = try ExperimentalImmutableReceiptStore.publish(
            bytes,
            to: destination
        )
        return "CollectedEvidence/\(destination.lastPathComponent)"
    }

    /// The host's collected-evidence directory, created with its own directory
    /// entries made durable rather than left to `FileManager`, which does not
    /// synchronize anything.
    nonisolated private static func collectedEvidenceDirectory()
        throws -> URL
    {
        let documents = try FileManager.default.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = documents.appendingPathComponent(
            "CollectedEvidence",
            isDirectory: true
        )
        try ExperimentalImmutableReceiptStore.createDirectoryDurably(
            at: directory
        )
        return directory
    }

    private static func isLowercaseUUID(_ value: String) -> Bool {
        guard let parsed = UUID(uuidString: value) else { return false }
        return parsed.uuidString.lowercased() == value
    }

    private static func fileSHA256(_ url: URL) throws -> String {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        return SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
    }

    private func experimentalManagers() async throws
        -> [NETunnelProviderManager]
    {
        try await NETunnelProviderManager
            .loadAllFromPreferences()
            .filter { candidate in
                guard candidate.localizedDescription ==
                        Self.localizedDescription,
                      let tunnelProtocol =
                        candidate.protocolConfiguration
                        as? NETunnelProviderProtocol
                else {
                    return false
                }
                return tunnelProtocol.providerBundleIdentifier ==
                    Self.providerBundleIdentifier
            }
    }
}
