import Darwin
import Foundation
import NetworkExtension

/*
 * WinsWinn3HostContract.swift — the Apple half of §4 of
 * docs/handoff/WINN3_TUN_LAYER_20260808.md.
 *
 * ===========================================================================
 * WHAT THIS FILE IS, AND WHAT IT DELIBERATELY IS NOT
 * ===========================================================================
 *
 * winn/3 STANDALONE is not the AmneziaWG relay. In the relay, AmneziaWG owns
 * the utun device, does all of the cryptography, and Winn carries its already
 * encapsulated outer datagrams; on Apple that is `WinsWinnPacketEngine.m`, its
 * loopback seam and the UAPI repoint, and NOTHING in this file touches it.
 * Standalone has no AmneziaWG anywhere: the winn/3 driver loop owns the
 * session, the winn/3 tun layer validates inner IP, and the host's job reduces
 * to three obligations — a device, a carrier socket that is kept off the
 * tunnel, and a clock.
 *
 * This file is the Apple discharge of those three, plus the one predicate a
 * route promotion is allowed to be gated on.
 *
 * It contains NO decision to start anything. `kWinnHostCapabilities` reports
 * `.absent` on all five platforms and this file does not change that: an
 * integration is not evidence, and the only thing that can retire an `.absent`
 * is a measured session.
 *
 * ===========================================================================
 * THE THREE GO INTERFACES, AND WHAT SATISFIES EACH ON APPLE
 * ===========================================================================
 *
 * winn3/tun declares them (tun/params.go), and declares them IN THE TUN
 * PACKAGE rather than importing the session package, so a host reads one file:
 *
 *   type Device interface {
 *       ReadPacket(buf []byte) (int, error)
 *       WritePacket(pkt []byte) (int, error)
 *       MTU() int
 *   }
 *   type Clock interface { Now() time.Time }
 *   type FrameSink interface { SendData(pkt []byte) error }
 *
 * 1. Device  <- NEPacketTunnelFlow, ACROSS THE C ABI.
 *
 *    Linux and Android satisfy Device with the tun file descriptor and Go
 *    never copies. Apple cannot: NEPacketTunnelFlow is an asynchronous
 *    Objective-C object, `readPackets(completionHandler:)` /
 *    `writePackets(_:withProtocols:)`, and the only way to a descriptor behind
 *    it is a private key path that fails App Review. So the Go side's Device is
 *    a bounded queue whose two ends are the two ABI functions this file already
 *    uses for the relay:
 *
 *        packetFlow.readPackets  -> WinnTunnelWriteInbound -> Device.ReadPacket
 *        packetFlow.writePackets <- WinnTunnelReadOutbound <- Device.WritePacket
 *
 *    Seen from Go the interface is satisfied exactly; seen from Swift the
 *    device is `WinsWinn3PacketRelay`, which NEPacketTunnelFlow satisfies with
 *    an empty conformance. The cost is one copy per direction on a path that
 *    already copies at the NEPacketTunnelFlow boundary.
 *
 *    `MTU()` is `Sizing.InnerMTU` and the host must set the interface MTU to
 *    exactly that (§4.2). Larger is a black hole path-MTU discovery may not
 *    rescue; smaller is merely wasteful and is accepted.
 *
 * 2. The carrier socket, and its exclusion  <- excludedRoutes, not protect().
 *
 *    Android has VpnService.protect and Linux has SO_BINDTODEVICE. Apple has
 *    neither: a NEPacketTunnelProvider keeps its own sockets off the tunnel by
 *    ROUTING — an NEIPv4Settings.excludedRoutes /32 for the carrier endpoint —
 *    which means the exclusion is a property of the settings object, not of the
 *    socket. Two consequences the other four platforms do not have:
 *
 *      - The exclusion must be present in the BOOTSTRAP posture, not added at
 *        promotion. A socket dialled under a posture that does not exclude it
 *        is a socket the promotion can capture. §4.1 says this in one line and
 *        Apple is the platform where it is load-bearing.
 *      - Because the exclusion is administrative rather than structural, a
 *        configuration whose exclusion /32 resolves to loopback silently
 *        excludes nothing. `WinsTunnelConfig.transportIPv4ExclusionRoute`
 *        already carries that hazard for the relay; standalone inherits it,
 *        which is why `winn3CarrierExclusionIsUsable` below is a refusal and
 *        not a warning.
 *
 *    The descriptor itself: the ABI takes ownership of a UDP fd, or opens its
 *    own only under "allow_own_socket". Apple passes `allow_own_socket` true
 *    for the same reason the relay does — the appex has no way to hand a
 *    protected socket to anything, and the exclusion route is what protects it
 *    — and therefore MUST NOT start unless the exclusion route exists.
 *
 * 3. Clock  <- driver.SystemClock, in Go.
 *
 *    winn3/tun has no timer, no ticker and no sleep: its Clock exists so the
 *    ICMP rate limiter is deterministic under test. The driver loop's Clock is
 *    the one with a wait primitive. Neither needs anything from Apple, and a
 *    host clock crossing the C ABI would be a second time source that can
 *    disagree with the first. So Apple supplies NOTHING here, deliberately —
 *    the Go default is `driver.SystemClock`, which is `time.Now`.
 *
 *    The one Apple-specific hazard is not the clock's source but its
 *    CONTINUITY: an appex is suspended and resumed, and `time.Now` jumps.
 *    winn3/session's silence and probe draws are duration-based and tolerate
 *    it; the promotion deadline in this file is measured with
 *    `DispatchTime.now()`, which is monotonic, so a suspend cannot make a
 *    proof window expire early or late.
 *
 * 4. FrameSink is NOT the host's. The driver loop supplies it from the session
 *    driver through a one-line name adapter (winn3/driver/sink.go). It is
 *    listed here only so a reader of §5 does not go looking for the Apple
 *    implementation of an interface Apple has no business implementing.
 */

// MARK: - the names, which must equal the Go constants

/// The winn/3 standalone vocabulary, spelled once on this side of the ABI.
///
/// Every value here has a counterpart in
/// `winn_protocol_experimental/cdatapath/winn_datapath_winn3.go`, and
/// `verify_apple_winn3_host_contract.sh` asserts the equality against the real
/// archive rather than against a copy of it — a constant that agrees with a
/// comment and disagrees with the engine is the failure mode this whole seam
/// exists to make impossible.
enum WinsWinn3 {
  /// `[winn] carrier` value that selects the standalone datapath. Additive:
  /// `direct-awg` and `http3-connect-udp` keep their exact meanings.
  static let carrierName = "winn3"

  /// The payload class. It is the one the RELAY entry point refuses, and that
  /// asymmetry is the whole safety property: a host that pumps raw IP into the
  /// relay fails at create rather than forwarding cleartext, and a host that
  /// pumps AmneziaWG datagrams into standalone fails the same way.
  static let payloadClass = "ip-packet"

  /// Deliberately NOT `WINN_TUNNEL_CONTRACT_VERSION`. A host that found them
  /// equal would conclude a relay archive can carry inner IP.
  static let contract = "winn-datapath/1+winn3"

  /// The create symbol, resolved by name at run time for the same reason every
  /// other engine symbol is: the appex links no Go archive at build time.
  static let createSymbol = "WinnTunnelCreateWinn3"

  /// Stable, greppable marker for every log line this file emits.
  static let logToken = "WINS_WINN3_HOST_CONTRACT"
}

// MARK: - §4.1, the promotion predicate

/// The one predicate a winn/3 route promotion may be gated on.
///
/// § 4.1 of the tun lane's contract, in code and in one place:
///
///     Gate.State() == StateCarrying   AND   Stats().RxPackets > 0
///
/// Both, and neither alone.
///
/// - The gate alone says the session driver believes DATA may flow. It says
///   nothing about whether anything reached this host, and a tunnel whose
///   carrier is silently black-holing is `carrying` for as long as the liveness
///   probes take to fail.
/// - `RxPackets` alone would be a packet delivered under a gate that has since
///   closed — a rekey, a migration, a teardown.
///
/// `RxPackets` and not `RxOffered`: the first counts DELIVERIES, the second
/// counts ARRIVALS. A gate built on arrivals promotes on a packet the inner-IP
/// validator may have thrown away — wrong source address, martian destination,
/// oversize, bad checksum — which is to say on a packet that proves the carrier
/// and proves nothing above it. That distinction is §5 of the tun lane's
/// document and it is exactly the class of error a sibling lane caught on
/// 2026-08-08, so this type reads both and publishes both.
enum WinsWinn3PromotionGate {
  /// The engine status keys, spelled once. These are
  /// `WinsWinnSeamObservabilitySample.engineFieldPrefix` + the Go document's
  /// own key names, so nothing here has to know how the sampler namespaces.
  static let gateStateKey = WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_gate_state"
  static let rxPacketsKey = WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_rx_packets"
  static let rxOfferedKey = WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_rx_offered"
  static let mayCarryKey = WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_may_carry"
  static let innerMTUKey = WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_inner_mtu"

  /// The only value of `winn3_gate_state` that carries. It is
  /// `winn3/tun.StateCarrying.String()`.
  static let carryingState = "carrying"

  /// True only when BOTH halves hold. A missing key is false: an engine that
  /// cannot report is an engine that has proven nothing.
  ///
  /// A supervised engine's lifecycle can only subtract from this: a document
  /// that says `recovering`, `blocked`, `stopped` or `connecting`, or whose
  /// lifecycle is present but invalid, is not converged whatever its counters
  /// say. Only an ABSENT lifecycle (an engine older than the field) keeps the
  /// two-clause rule unchanged.
  static func converged(engineStatusFields: [String: Any]) -> Bool {
    gateIsCarrying(engineStatusFields: engineStatusFields)
      && deliveredPacketCount(engineStatusFields: engineStatusFields) > 0
      && WinsWinn3Lifecycle.permitsConnectedClaim(
        WinsWinn3Lifecycle.reading(engineStatusFields: engineStatusFields)
      )
  }

  static func gateIsCarrying(engineStatusFields: [String: Any]) -> Bool {
    guard let state = engineStatusFields[gateStateKey] as? String else {
      return false
    }
    return state == carryingState
  }

  /// `Stats().RxPackets`. Non-numeric or absent is zero, never "assume some".
  static func deliveredPacketCount(engineStatusFields: [String: Any]) -> UInt64 {
    unsignedValue(engineStatusFields[rxPacketsKey])
  }

  /// `Stats().RxOffered`. Read ONLY to publish it beside the delivered count;
  /// nothing in this type gates on it, and `TestPromotionGateIgnoresOffered`
  /// pins that.
  static func offeredPacketCount(engineStatusFields: [String: Any]) -> UInt64 {
    unsignedValue(engineStatusFields[rxOfferedKey])
  }

  static func unsignedValue(_ value: Any?) -> UInt64 {
    if let number = value as? NSNumber {
      let signed = number.int64Value
      return signed > 0 ? UInt64(signed) : 0
    }
    if let integer = value as? Int {
      return integer > 0 ? UInt64(integer) : 0
    }
    if let unsigned = value as? UInt64 {
      return unsigned
    }
    return 0
  }

  /// The status vocabulary this gate publishes.
  ///
  /// The prefix is `winn3_datapath_proof_`, NOT the relay gate's prefix, and
  /// the distinction is deliberate rather than cosmetic. The relay gate's
  /// fields are a pinned instrumentation surface — a shipped Debug appex
  /// carries an exact, recorded number of them, and that count is how a lane
  /// proves it neither lost nor invented a proof field. Reusing the prefix
  /// would move that number for a reason unrelated to the relay, and the next
  /// person to measure it would have to reconstruct why. A second prefix keeps
  /// both surfaces countable.
  ///
  /// The offered count is published next to the delivered one so a reader can
  /// see at a glance which counter the decision was made on.
  static func statusFields(engineStatusFields: [String: Any]) -> [String: Any] {
    let delivered = deliveredPacketCount(engineStatusFields: engineStatusFields)
    let offered = offeredPacketCount(engineStatusFields: engineStatusFields)
    return [
      "winn3_datapath_proof_gate_carrying":
        gateIsCarrying(engineStatusFields: engineStatusFields),
      "winn3_datapath_proof_rx_packets_delivered": Int(clamping: delivered),
      "winn3_datapath_proof_rx_packets_offered": Int(clamping: offered),
      "winn3_datapath_proof_converged":
        converged(engineStatusFields: engineStatusFields)
    ]
  }
}

// MARK: - the supervised engine's lifecycle (Round A2, consumed in Round A3)

/// The engine's recovery state, read off the sampled status document, and
/// what the Apple host makes of it.
///
/// `connected` is the only state in which this host may claim a connected
/// tunnel: the round the document read has its own delivery proof.
/// `recovering` means the engine is rebuilding its session in place; the host
/// keeps the tunnel, its network settings and its capture exactly as they are,
/// tears nothing down and claims nothing. `blocked` means the engine stopped
/// trying; capture stays installed (fail closed), the state is reported as
/// action-required with the cause as an OBSERVATION, and nothing here, or
/// anywhere it feeds, authorises AmneziaWG, Xray or any other protocol.
///
/// This host has no health watchdog that tears a running tunnel down (the
/// no-watchdog doctrine in both providers), so the one place it decides health
/// is `WinsWinn3Datapath.healthSnapshot`, whose verdict is the readiness the
/// provider reports to the app.
///
/// POLICY DIFFERENCE FROM ANDROID, deliberate. On Apple the host ceiling is a
/// REVERSIBLE reporting verdict: the engine keeps running, capture stays, and
/// a later engine-proven `connected` returns the verdict to connected. Android
/// latches the ceiling and stops the engine it owns, keeping capture
/// (`WinnV3LifecycleWatch`). Both keep capture and neither grants fallback;
/// they differ in whether the stuck engine keeps running.
enum WinsWinn3Lifecycle {
  static let lifecycleKey =
    WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_lifecycle"
  static let causeKey =
    WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_lifecycle_cause"
  /// Published by the sampler instead of a value it could not accept.
  static let lifecycleInvalidKey =
    lifecycleKey + WinsWinnSeamObservabilitySample.invalidVocabularySuffix

  /// `winn3/driver.Lifecycle*`, spelled exactly as the Go constants.
  enum State: String, CaseIterable {
    case connecting
    case connected
    case recovering
    case blocked
    case stopped
  }

  /// What one sampled document says, keeping ABSENT and PRESENT-INVALID apart.
  enum Reading: Equatable {
    /// No lifecycle key at all: an engine older than the field.
    case absent
    /// A lifecycle key this host could not accept (wrong type, empty,
    /// oversized, or outside the vocabulary).
    case invalid
    case state(State)
  }

  /// Who observed a blocked verdict.
  enum Observer: String {
    /// The engine published `blocked`, with its own cause.
    case engine
    /// Recovery outlived `WinsWinn3RecoveryCeiling`.
    case recoveryCeiling = "recovery_ceiling"
    /// The document carried a lifecycle this host could not trust.
    case invalidStatus = "invalid_status"
    /// After engine-proven `connected` on this datapath, the engine said
    /// `stopped` while capture is still installed.
    case sessionEnded = "session_ended"
    /// After a lifecycle was reported on this datapath: a post-proof
    /// `connecting` (the engine never returns to it after first proof), or
    /// the lifecycle disappearing outside a recovery episode.
    case invalidTransition = "invalid_transition"
  }

  /// The host's verdict for one sample.
  enum Verdict: Equatable {
    /// The engine reports `connected`. May claim connected.
    case connected
    /// The engine reports `recovering` inside the host ceiling.
    case recovering
    /// Keep capture, action required, and say who observed it.
    case blocked(Observer)
    /// `stopped` or `connecting` on a datapath that has never proven
    /// `connected`: not a live engine, and nothing held to describe yet.
    case notLive
    /// No lifecycle in the document: an engine older than the field.
    case unreported

    var wire: String {
      switch self {
      case .connected: return "connected"
      case .recovering: return "recovering"
      case .blocked: return "blocked"
      case .notLive: return "not_live"
      case .unreported: return "unreported"
      }
    }

    /// Only an engine-proven connected, or a legacy engine, may be called ready.
    var claimsConnected: Bool {
      self == .connected || self == .unreported
    }
  }

  static func reading(engineStatusFields fields: [String: Any]) -> Reading {
    if fields[lifecycleInvalidKey] as? Bool == true {
      return .invalid
    }
    guard let raw = fields[lifecycleKey] else {
      return .absent
    }
    guard let text = raw as? String, let state = State(rawValue: text) else {
      return .invalid
    }
    return .state(state)
  }

  static func cause(engineStatusFields: [String: Any]) -> String? {
    engineStatusFields[causeKey] as? String
  }

  /// Whether a document may be called connected (and so converge). Only a
  /// genuinely absent field keeps the old rule; present-invalid refuses.
  static func permitsConnectedClaim(_ reading: Reading) -> Bool {
    reading == .absent || reading == .state(.connected)
  }

  /// The pure decision. `recoveringFor` is how long this host has watched the
  /// current episode on a monotonic clock, or nil when it has not seen one.
  /// `history` is what THIS datapath had seen before this reading
  /// (`WinsWinn3LifecycleHistory`); the default is a datapath that has seen
  /// nothing, which keeps the legacy rules.
  static func verdict(
    reading: Reading,
    recoveringFor: TimeInterval?,
    history: WinsWinn3LifecycleHistory.Snapshot = .none,
    ceiling: TimeInterval = WinsWinn3RecoveryCeiling.ceilingSeconds
  ) -> Verdict {
    switch reading {
    case .absent:
      // No document this sample (sampling unavailable) inside an episode is
      // no delivery proof: the episode goes on aging and can reach the
      // ceiling. Outside an episode, a datapath that has reported a lifecycle
      // before has LOST it, which is an invalid transition, held and
      // actionable. Only a datapath that never reported one is a legacy
      // engine older than the field.
      if let recoveringFor {
        return recoveringFor > ceiling ? .blocked(.recoveryCeiling) : .recovering
      }
      if history.everReported {
        return .blocked(.invalidTransition)
      }
      return .unreported
    case .invalid:
      // The driver's vocabulary is closed: a host that meets a value it does
      // not know must treat it as blocked.
      return .blocked(.invalidStatus)
    case .state(.connected):
      return .connected
    case .state(.recovering):
      if let recoveringFor, recoveringFor > ceiling {
        return .blocked(.recoveryCeiling)
      }
      return .recovering
    case .state(.blocked):
      return .blocked(.engine)
    case .state(.stopped):
      // After promotion (engine-proven connected on this datapath) the
      // provider still has its routes installed: capture is held, and the
      // user must act. Reversible: a later engine-proven connected is
      // connected again.
      return history.everConnected ? .blocked(.sessionEnded) : .notLive
    case .state(.connecting):
      return history.everConnected ? .blocked(.invalidTransition) : .notLive
    }
  }

  /// THE promotion decision both providers make for a standalone datapath,
  /// and the handoff of its proof into that datapath's lifecycle history.
  ///
  /// It is §4.1's static gate (`WinsWinn3PromotionGate.converged`) AND the
  /// provider's probe requirement, exactly as both providers evaluated them
  /// inline before. When they hold, the lifecycle evidence the gate used is
  /// recorded as this datapath's PROMOTION, before the caller installs
  /// full-tunnel settings and publishes the datapath. So the first health
  /// sample after promotion already knows the session was promoted: a
  /// `stopped` or `connecting` there is an actionable held session, and a
  /// missing lifecycle or an unavailable sample is an invalid transition, not
  /// a legacy engine. A promotion on a document with NO lifecycle (a legacy
  /// engine) records no lifecycle history, so legacy absence semantics stay.
  static func promotionConverged(
    engineStatusFields fields: [String: Any],
    probeSatisfied: Bool,
    history: WinsWinn3LifecycleHistory
  ) -> Bool {
    guard probeSatisfied, WinsWinn3PromotionGate.converged(engineStatusFields: fields) else {
      return false
    }
    history.recordPromotion(reading(engineStatusFields: fields))
    return true
  }

  /// The whole host step `WinsWinn3Datapath.healthSnapshot` takes on one
  /// sampled document: read it (absent kept apart from invalid), age the
  /// episode on the monotonic clock, decide, and mint the host fields.
  static func hostStatus(
    engineStatusFields fields: [String: Any],
    clock: WinsWinn3RecoveryClock,
    history: WinsWinn3LifecycleHistory
  ) -> (verdict: Verdict, fields: [String: Any]) {
    let current = reading(engineStatusFields: fields)
    let recoveringFor = clock.observe(current)
    let seenBefore = history.record(current)
    let decided = verdict(reading: current, recoveringFor: recoveringFor, history: seenBefore)
    return (
      decided,
      statusFields(
        verdict: decided,
        engineCause: cause(engineStatusFields: fields),
        recoveringFor: recoveringFor
      )
    )
  }

  /// The host-derived keys, in the order `statusFields` can mint them. They
  /// are part of `WinsWinnSeamObservabilitySample.publishedStatusKeys`, which
  /// is the list the app forwarder iterates. The `winn3_recovery_` prefix is
  /// its own surface, separate from the pinned `winn3_datapath_proof_` one,
  /// and no value it publishes contains a denied token.
  static let hostStatusKeys = [
    "winn3_recovery_state",
    "winn3_recovery_observer",
    "winn3_recovery_cause",
    "winn3_recovery_claims_connected",
    "winn3_recovery_action_required",
    "winn3_recovery_capture_held",
    "winn3_recovery_observed_ms"
  ]

  /// Host-side fields published beside the engine's own, so the provider
  /// status names the state this host acted on.
  static func statusFields(
    verdict: Verdict,
    engineCause: String?,
    recoveringFor: TimeInterval?
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "winn3_recovery_state": verdict.wire,
      "winn3_recovery_claims_connected": verdict.claimsConnected,
      "winn3_recovery_action_required": false,
      "winn3_recovery_capture_held": false
    ]
    switch verdict {
    case .recovering:
      fields["winn3_recovery_capture_held"] = true
    case .blocked(let observer):
      fields["winn3_recovery_capture_held"] = true
      fields["winn3_recovery_action_required"] = true
      fields["winn3_recovery_observer"] = observer.rawValue
      if observer == .engine, let engineCause, !engineCause.isEmpty {
        fields["winn3_recovery_cause"] = engineCause
      }
    case .connected, .notLive, .unreported:
      break
    }
    if let recoveringFor {
      fields["winn3_recovery_observed_ms"] = Int(clamping: Int64(recoveringFor * 1000))
    }
    return fields
  }
}

/// The host-selected recovery ceiling: the longest interval this host
/// tolerates without renewed delivery proof, measured on a monotonic clock from
/// its first observation of `recovering` in an episode and reset only by an
/// engine-reported `connected`. The Android twin is `WinnV3RecoveryCeiling`;
/// the numbers match.
///
/// It is a POLICY VALUE informed by the failed-handshake timing model and is
/// not a proven upper bound on a correct recovery: the supervisor's budget
/// resets on authenticated traffic while `connected` needs delivery, and no
/// per-round deadline exists, so a correct but slow recovery can outlast it.
/// On Apple exceeding it changes only what is REPORTED (see the policy note on
/// `WinsWinn3Lifecycle`).
///
/// - One round that never establishes: the sum over i < 5 of min(8 s, 0.5 s *
///   2^i) plus one cap, 0.5 + 1 + 2 + 4 + 8 + 8 = 23.5 s.
/// - Five such rounds: 117.5 s.
/// - Five inter-round waits, each conservatively bounded by the 8 s cap: 40 s.
/// - Observation allowance: 10 s. Total 167.5 s.
enum WinsWinn3RecoveryCeiling {
  static let supervisorRounds = 5
  static let supervisorBackoffCapSeconds: TimeInterval = 8
  static let sessionRetryBaseSeconds: TimeInterval = 0.5
  static let sessionRetryCapSeconds: TimeInterval = 8
  static let sessionRetryAttempts = 5
  static let observationSlackSeconds: TimeInterval = 10

  /// The failed-handshake budget of one round.
  static func handshakeBudgetSeconds(
    base: TimeInterval = sessionRetryBaseSeconds,
    cap: TimeInterval = sessionRetryCapSeconds,
    attempts: Int = sessionRetryAttempts
  ) -> TimeInterval {
    var total: TimeInterval = 0
    var window = base
    for _ in 0..<attempts {
      total += window
      if window < cap {
        window = min(window * 2, cap)
      }
    }
    return total + cap
  }

  static var failedHandshakeEpisodeSeconds: TimeInterval {
    Double(supervisorRounds) * handshakeBudgetSeconds()
      + Double(supervisorRounds) * supervisorBackoffCapSeconds
  }

  static var ceilingSeconds: TimeInterval {
    failedHandshakeEpisodeSeconds + observationSlackSeconds
  }
}

/// What one datapath has seen of the engine's lifecycle: whether it ever
/// reported one, and whether it ever proved `connected` (promotion). One per
/// datapath, so disposing of the datapath disposes of it. It is what tells a
/// legacy engine (never reported) from a supervised one whose lifecycle
/// disappeared, and a pre-proof `stopped` from the end of a promoted session.
/// Thread-safe.
final class WinsWinn3LifecycleHistory {
  struct Snapshot: Equatable {
    var everReported = false
    var everConnected = false
    /// The provider's promotion gate passed on this datapath.
    var promoted = false

    static let none = Snapshot()
  }

  private let lock = NSLock()
  private var state = Snapshot.none

  /// The provider's promotion gate passed on a document whose lifecycle read
  /// as `reading` (connected, or absent for a legacy engine; the gate refuses
  /// every other reading). Records the promotion and that evidence.
  func recordPromotion(_ reading: WinsWinn3Lifecycle.Reading) {
    _ = record(reading)
    lock.lock()
    state.promoted = true
    lock.unlock()
  }

  /// Returns what was known BEFORE `reading`, then records it. A present but
  /// invalid lifecycle counts as reported.
  func record(_ reading: WinsWinn3Lifecycle.Reading) -> Snapshot {
    lock.lock()
    defer { lock.unlock() }
    let before = state
    switch reading {
    case .absent:
      break
    case .invalid:
      state.everReported = true
    case .state(let current):
      state.everReported = true
      if current == .connected {
        state.everConnected = true
      }
    }
    return before
  }
}

/// When this host first saw the current recovery episode, on an injectable
/// MONOTONIC elapsed source. Thread-safe; one per datapath, so disposing of
/// the datapath disposes of its episode.
///
/// The episode ends ONLY on engine-proven `connected` (renewed delivery
/// proof). An absent sample (`statusFields()` returns nothing when sampling
/// is unavailable), an invalid one, an engine `blocked`, `stopped` or
/// `connecting`: none of them is delivery proof, so none of them restarts the
/// episode's clock.
///
/// The default source is `DispatchTime.now()`, the same monotonic clock the
/// promotion deadline in this file uses, so a wall-clock change (forward or
/// back) can neither trip the ceiling early nor hold it off. No `Date` is read
/// here. The verdict itself stays pure in `WinsWinn3Lifecycle.verdict`.
final class WinsWinn3RecoveryClock {
  /// Seconds on the system's monotonic clock.
  static func monotonicSeconds() -> TimeInterval {
    TimeInterval(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
  }

  private let lock = NSLock()
  private let elapsed: () -> TimeInterval
  private var recoveringSince: TimeInterval?

  init(elapsed: @escaping () -> TimeInterval = WinsWinn3RecoveryClock.monotonicSeconds) {
    self.elapsed = elapsed
  }

  /// Records `reading` now and returns how long the current episode has been
  /// watched, or nil outside one. `recovering` opens an episode (or continues
  /// the open one); engine-proven `connected` closes it, so the next
  /// `recovering` starts its own clock; every other reading leaves an open
  /// episode open and aging.
  func observe(_ reading: WinsWinn3Lifecycle.Reading) -> TimeInterval? {
    let now = elapsed()
    lock.lock()
    defer { lock.unlock() }
    switch reading {
    case .state(.connected):
      recoveringSince = nil
      return nil
    case .state(.recovering):
      let since = recoveringSince ?? now
      recoveringSince = since
      return max(0, now - since)
    default:
      guard let since = recoveringSince else { return nil }
      return max(0, now - since)
    }
  }
}

// MARK: - which predicate a session is gated on

/// Which datapath a staged start is proving, and therefore which convergence
/// predicate applies.
///
/// This exists so the provider's convergence loop calls ONE function and the
/// choice of predicate is data rather than an `if` that can drift between the
/// two providers. The relay case is byte-for-byte the behaviour that shipped
/// before winn/3 existed; nothing about it changes.
enum WinsWinnDatapathKind {
  /// AmneziaWG owns the tun; Winn relays its outer datagrams. `direct-awg` and
  /// `http3-connect-udp`.
  case relay

  /// winn/3 owns the session and the inner-IP layer. `winn3`.
  case standalone

  /// Resolved from the `[winn] carrier` value. An unrecognised carrier is not
  /// mapped to a default here — `WinsTunnelConfig.validate()` has already
  /// refused it — and nil is returned so a caller cannot accidentally prove a
  /// standalone session with a relay predicate.
  static func forCarrier(_ carrier: String) -> WinsWinnDatapathKind? {
    switch carrier.lowercased() {
    case WinsTunnelConfig.supportedWinnCarrier,
         WinsTunnelConfig.supportedWinnCarrierHttp3:
      return .relay
    case WinsWinn3.carrierName:
      return .standalone
    default:
      return nil
    }
  }

  /// The §4.1 predicate for this kind.
  ///
  /// The relay predicate is `WinsWinnDatapathProofGate.converged`: the engine
  /// observed a handshake response AND payload-class transport in both
  /// directions. The standalone predicate is the gate plus a delivered packet.
  /// They are different because the two datapaths can prove different things:
  /// the relay cannot see inner IP at all, and standalone can.
  func converged(engineStatusFields: [String: Any]) -> Bool {
    switch self {
    case .relay:
      return WinsWinnDatapathProofGate.converged(engineStatusFields: engineStatusFields)
    case .standalone:
      return WinsWinn3PromotionGate.converged(engineStatusFields: engineStatusFields)
    }
  }

  /// The extra status fields this kind's proof publishes. Empty for the relay,
  /// which already publishes its own.
  func statusFields(engineStatusFields: [String: Any]) -> [String: Any] {
    switch self {
    case .relay:
      return [:]
    case .standalone:
      return WinsWinn3PromotionGate.statusFields(engineStatusFields: engineStatusFields)
    }
  }
}

// MARK: - §4.1, the bootstrap posture, checked on the object that was built

/// Whether a settings object is narrow enough to be a BOOTSTRAP.
///
/// § 4.3 rule 1: *"verifies narrowness on the settings object it just built
/// rather than trusting the code that built it."* That is the whole reason this
/// is a function over `NEPacketTunnelNetworkSettings` and not a set of flags
/// carried alongside one. The check is cheap; the failure it prevents is a
/// machine in Myanmar that lost its default route to an unproven tunnel.
///
/// A start that cannot build a narrow bootstrap MUST refuse. It must never
/// widen — never "fall back" to installing the full tunnel immediately —
/// because a refusal costs the user a retry while the system still reports
/// Connecting, and a promotion on an unproven datapath costs them their
/// traffic.
enum WinsWinn3BootstrapPosture {
  struct Verdict {
    let narrow: Bool
    let reasons: [String]
    let statusFields: [String: Any]
  }

  /// - Parameters:
  ///   - settings: the object about to be handed to `setTunnelNetworkSettings`.
  ///   - requiredInnerMTU: `Tunnel.InnerMTU()`, i.e. the plan floor's inner
  ///     MTU. §4.2 makes this an obligation, not a suggestion.
  ///   - carrierExclusionPresent: whether the outer transport's /32 is in
  ///     `excludedRoutes`. On Apple this is the ONLY thing keeping the carrier
  ///     socket off the tunnel, so a bootstrap without it is not narrow no
  ///     matter what its routes say.
  static func evaluate(
    _ settings: NEPacketTunnelNetworkSettings,
    requiredInnerMTU: Int,
    carrierExclusionPresent: Bool
  ) -> Verdict {
    var reasons: [String] = []

    let ipv4 = settings.ipv4Settings
    let includedRoutes = ipv4?.includedRoutes ?? []
    if includedRoutes.count > 1 {
      reasons.append("bootstrap carries \(includedRoutes.count) included routes; at most one is permitted")
    }
    if includedRoutes.contains(where: { $0.destinationAddress == "0.0.0.0" }) {
      reasons.append("bootstrap carries the IPv4 default route")
    }
    if let addresses = ipv4?.addresses, addresses.count != 1 {
      reasons.append("bootstrap carries \(addresses.count) IPv4 addresses; exactly one is permitted")
    }
    if let masks = ipv4?.subnetMasks, masks.contains(where: { $0 != "255.255.255.255" }) {
      reasons.append("bootstrap address is wider than a /32")
    }
    if settings.ipv6Settings != nil {
      reasons.append("bootstrap carries IPv6 settings; the host must keep its own IPv6")
    }
    if settings.dnsSettings != nil {
      reasons.append("bootstrap carries DNS settings; a resolver pointed into an unproven tunnel makes every lookup on the machine fail, including the app's own recovery path")
    }
    if !carrierExclusionPresent {
      reasons.append("bootstrap does not exclude the outer transport endpoint; on Apple that route is the only thing keeping the carrier socket out of the tunnel")
    }
    if requiredInnerMTU <= 0 {
      reasons.append("no inner MTU was published; the interface MTU must be exactly Tunnel.InnerMTU()")
    } else if settings.mtu?.intValue != requiredInnerMTU {
      let actual = settings.mtu.map { "\($0.intValue)" } ?? "unset"
      reasons.append("bootstrap MTU is \(actual); it must be exactly the \(requiredInnerMTU)-byte plan-floor inner MTU")
    }

    return Verdict(
      narrow: reasons.isEmpty,
      reasons: reasons,
      statusFields: [
        "winn3_datapath_proof_bootstrap_observably_narrow": reasons.isEmpty,
        "winn3_datapath_proof_bootstrap_included_route_count": includedRoutes.count,
        "winn3_datapath_proof_bootstrap_ipv6_settings_installed":
          settings.ipv6Settings != nil,
        "winn3_datapath_proof_bootstrap_dns_settings_installed":
          settings.dnsSettings != nil,
        "winn3_datapath_proof_carrier_exclusion_present": carrierExclusionPresent,
        "winn3_datapath_proof_bootstrap_mtu": settings.mtu?.intValue ?? 0,
        "winn3_datapath_proof_required_inner_mtu": requiredInnerMTU
      ]
    )
  }
}

// MARK: - the create document

/// The gateway public keys that make a winn/3 client require the
/// dual-signature session attestation.
///
/// The strings are kept in their canonical descriptor encoding so the exact
/// signed values cross the Swift/Go boundary. Validation decodes each value,
/// pins its byte length, then re-encodes it; accepting merely decodable input
/// would let a replaced textual representation stop being byte-for-byte the
/// signed descriptor material.
struct WinsWinn3DualAuthPublicKeys: Equatable {
  static let ed25519ByteCount = 32
  static let mldsa65ByteCount = 1952

  let ed25519Base64: String
  let mldsa65Base64: String

  struct Validation {
    let keys: WinsWinn3DualAuthPublicKeys?
    let unmetReasons: [String]
  }

  static func validate(
    ed25519Base64: String?,
    mldsa65Base64: String?
  ) -> Validation {
    if ed25519Base64 == nil && mldsa65Base64 == nil {
      return Validation(keys: nil, unmetReasons: [])
    }
    guard let ed25519Base64, let mldsa65Base64 else {
      return Validation(
        keys: nil,
        unmetReasons: [
          "[winn] auth_ed25519 and auth_mldsa65 are the optional pair and must be both present or both absent"
        ]
      )
    }

    var reasons: [String] = []
    if canonicalBytes(ed25519Base64, count: ed25519ByteCount) == nil {
      reasons.append("[winn] auth_ed25519 is not canonical base64 for exactly 32 bytes")
    }
    if canonicalBytes(mldsa65Base64, count: mldsa65ByteCount) == nil {
      reasons.append("[winn] auth_mldsa65 is not canonical base64 for exactly 1952 bytes")
    }
    guard reasons.isEmpty else {
      return Validation(keys: nil, unmetReasons: reasons)
    }
    return Validation(
      keys: WinsWinn3DualAuthPublicKeys(
        ed25519Base64: ed25519Base64,
        mldsa65Base64: mldsa65Base64
      ),
      unmetReasons: []
    )
  }

  private static func canonicalBytes(_ encoded: String, count: Int) -> Data? {
    guard let raw = Data(base64Encoded: encoded),
          raw.count == count,
          raw.base64EncodedString() == encoded else {
      return nil
    }
    return raw
  }
}

/// Builds the `WinnTunnelCreateWinn3` configuration.
///
/// Never logged and never echoed: it carries this device's static private key,
/// the gateway admission secret and, when the deployment has one, the
/// per-subscriber PSK. `description` is deliberately not implemented.
struct WinsWinn3CreateDocument {
  let gatewayEndpoint: String
  let staticPrivateBase64: String
  let gatewayStaticBase64: String
  /// The gateway id the ENGINE takes, which is the operator's own gateway name
  /// as text and NOT base64 — the one field in this document that is not.
  ///
  /// The asymmetry is deliberate and load-bearing. `admissionKeyBase64` is a
  /// secret whose bytes are arbitrary, so a JSON string cannot carry it any
  /// other way. The gateway id is an authenticated input to the admission tag
  /// that is never transmitted, so both ends must derive identical bytes from
  /// it with nothing on the wire to catch a disagreement — and every host in
  /// the tree except this one already derived them as the raw bytes of the
  /// operator's gateway name, `cmd/winn3-gateway` (the gateway that answers)
  /// included. The signed descriptor transports it base64; the decode happens
  /// once, at the descriptor boundary, in
  /// `WinsTunnelConfig.winn3GatewayIDOperatorText`.
  let gatewayIDText: String
  let admissionKeyBase64: String
  /// Optional only for byte-compatible legacy descriptors. When present, both
  /// exact public keys are emitted and the Go create path sets
  /// `session.DualAuth.Expected`; there is no one-key or silently-dropped form.
  let dualAuthPublicKeys: WinsWinn3DualAuthPublicKeys?
  let pskBase64: String?
  let innerV4: String
  let innerRouterV4: String
  let pathMTU: Int
  /// The MIGRATION PLAN — every class the session may escalate TO. The inner
  /// MTU is computed over the whole plan, never over the class dialled: a floor
  /// computed over the dialled class alone black-holes every full-size flow on
  /// the first migration while the tunnel still reports up, and the report
  /// comes from somewhere nobody can attach a debugger.
  let carrierClasses: [String]
  let sessionID: String

  /// Apple has no `protect()`. The appex cannot hand a protected descriptor to
  /// anything, so the engine opens its own socket and the excludedRoutes /32 is
  /// what keeps it off the tunnel. A start that has no usable exclusion route
  /// must therefore refuse — see `winn3CarrierExclusionIsUsable`.
  let allowOwnSocket: Bool

  func json() throws -> String {
    var document: [String: Any] = [
      "contract": WinsWinn3.contract,
      "payload": WinsWinn3.payloadClass,
      "carrier": WinsWinn3.carrierName,
      "gateway_endpoint": gatewayEndpoint,
      "static_private": staticPrivateBase64,
      "gateway_static": gatewayStaticBase64,
      "gateway_id": gatewayIDText,
      "admission_key": admissionKeyBase64,
      "inner_v4": innerV4,
      "inner_router_v4": innerRouterV4,
      "path_mtu": pathMTU,
      "carrier_classes": carrierClasses,
      "allow_own_socket": allowOwnSocket,
      "session_id": sessionID
    ]
    if let pskBase64, !pskBase64.isEmpty {
      document["psk"] = pskBase64
    }
    if let dualAuthPublicKeys {
      document["auth_ed25519"] = dualAuthPublicKeys.ed25519Base64
      document["auth_mldsa65"] = dualAuthPublicKeys.mldsa65Base64
    }
    let data = try JSONSerialization.data(
      withJSONObject: document,
      options: [.sortedKeys]
    )
    guard let text = String(data: data, encoding: .utf8) else {
      throw WinsWinn3Error.documentNotEncodable
    }
    return text
  }
}

enum WinsWinn3Error: LocalizedError {
  case documentNotEncodable
  case createSymbolUnavailable
  case createRefused(String)
  case carrierExclusionUnusable(String)

  var errorDescription: String? {
    switch self {
    case .documentNotEncodable:
      return "The winn3 create document could not be encoded."
    case .createSymbolUnavailable:
      return "\(WinsWinn3.createSymbol) is not present in this build; the winn3 datapath is not available."
    case .createRefused(let message):
      return "The winn3 datapath refused to start: \(message)"
    case .carrierExclusionUnusable(let message):
      return "The winn3 carrier exclusion route is unusable: \(message)"
    }
  }
}

// MARK: - the carrier exclusion, which on Apple is the whole of "protect"

/// Whether a configuration's outer-transport /32 is a route that actually
/// excludes something.
///
/// The hazard is documented at the top of `WinsWinnPacketEngine.m` for the
/// relay and it is worse for standalone, because standalone has no AmneziaWG
/// peer endpoint to fall back to: `transportIPv4ExclusionRoute` derives its /32
/// from `transportEndpointHost`, and if that resolves to loopback — or to
/// nothing — the /32 for the real gateway disappears and the engine's outer
/// socket is captured by the tunnel's own default route the moment it is
/// promoted. The session then either dies or, worse, loops.
///
/// Returns nil when the exclusion is usable, or the reason it is not.
func winn3CarrierExclusionIsUsable(_ config: WinsTunnelConfig) -> String? {
  guard let route = config.transportIPv4ExclusionRoute else {
    return "no /32 could be derived for the outer transport endpoint"
  }
  if route.prefixLength != 32 {
    return "the exclusion route is a /\(route.prefixLength), not a /32"
  }
  let destination = route.destinationAddress
  if destination.hasPrefix("127.") || destination == "0.0.0.0" {
    return "the exclusion route resolves to \(destination), which excludes nothing off this device"
  }
  return nil
}

// MARK: - the device, seen from Swift

/// The Apple side of `winn3/tun.Device`.
///
/// `NEPacketTunnelFlow` satisfies it with an empty conformance — the two
/// requirements are its own two methods, spelled identically — so the provider
/// hands `packetFlow` straight in and nothing adapts. The protocol exists only
/// so that this file, and its verifier, can be compiled and driven without a
/// NetworkExtension.
protocol WinsWinn3PacketRelay: AnyObject {
  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
  @discardableResult
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}

extension NEPacketTunnelFlow: WinsWinn3PacketRelay {}
