import Foundation
import NetworkExtension

/// The smallest honest kill switch on Apple: the POSTURE is the switch.
///
/// # What the switch is
///
/// In an `NEPacketTunnelProvider`, host traffic only egresses when the provider
/// forwards it — the system routes matching destinations into the tunnel
/// interface, and packets that are never read are dropped, never re-emitted on
/// the physical interface. That is the mechanism behind the 2026-08-05
/// "total host blackout" (a tunnel that held the default route and carried
/// nothing blacked the whole device) — and it is the same mechanism, run
/// deliberately, that a kill switch is made of:
///
///   * install the FULL-TUNNEL settings as the FIRST posture a session commits,
///     before the datapath is proven or even started, so every host family the
///     configuration intends to capture is drawn into the tunnel and dropped
///     until the datapath carries — egress is blocked from the instant the
///     session exists (the "before connect" window);
///   * keep those settings committed until the session ends, so the
///     "disconnecting" window is the same blocked posture while this
///     provider owns the installed settings. No on-demand relaunch rule is
///     registered here. Protection after provider death, automatic restart
///     and egress during any restart interval require device verification;
///   * never release settings while the datapath is still running, so a
///     teardown can never race its own stop into cleartext.
///
/// # What this is NOT
///
/// `NEVPNProtocol.enforceRoutes` is not a kill switch. It makes the tunnel's
/// routes WIN against injected more-specifics on the physical interface — a
/// route-injection decloak (TunnelVision class) — but it says nothing about the
/// windows this module exists to close: traffic the device emits before the
/// tunnel connects and while it is tearing down still egresses in the clear
/// unless the blocking posture is installed first (provider death is not
/// covered; see above). The posture is the switch; `enforceRoutes` is route
/// priority.
///
/// # What it deliberately does NOT block
///
///   * Split-tunnel intents (no default IPv4 route). The user asked for a
///     destination set outside the tunnel, so those destinations egress
///     directly by design, and `activeFor` returns false.
///   * Local-link traffic. `excludeLocalNetworks` keeps the LAN reachable, and
///     a captive portal must be passable before any tunnel can connect.
///   * Dev containment and held-proof runs. A contained/held session is the one
///     place "host untouched" is the POINT, so the provider classifies those
///     runs as dev runs and keeps today's narrow bootstrap for them.
///
/// # The verifier is a read-back, and it fails CLOSED
///
/// `egressBlocked(by:config:)` asks the SETTINGS OBJECT whether it captures each
/// host family the configuration intends to capture, the same way
/// `WinsDevContainmentObservation` and `WinsWinn3PromotedPosture` read their
/// objects back rather than trusting their builders. Each family is a separate
/// clause with its own false branch, and every clause defaults to false, so a
/// builder that silently narrows any one of them also silently turns
/// `egressBlocked` false and the provider refuses the session rather than
/// installing a posture that leaks. A green here is only worth something
/// because every clause can be made to go red on its own.
enum WinsKillSwitch {
  /// True when this session MUST block egress from the very first installed
  /// posture: the configuration carries a default IPv4 route (full-tunnel
  /// intent) and this is not a dev run.
  ///
  /// `devRunActive` is the provider's own classification of the run as
  /// contained or promotion-held — the two cases that are allowed to keep the
  /// narrow "host untouched" bootstrap. Every other full-tunnel session blocks.
  static func activeFor(
    config: WinsTunnelConfig,
    devRunActive: Bool
  ) -> Bool {
    config.defaultIPv4RouteEnabled && !devRunActive
  }

  /// Read-back verification: does `settings` route every host family the
  /// configuration intends to capture INTO the tunnel interface?
  ///
  /// Each family is verified independently and every clause defaults to false
  /// (fail closed), so each one can be individually broken:
  ///
  ///   * IPv4 — captured only by routes whose union is all of IPv4: a bare
  ///     `0.0.0.0/0` default, or the macOS full-tunnel `/1` pair. A narrow or
  ///     route-less set is not blocking.
  ///   * IPv6 — captured only when the configuration requests `::/0`
  ///     (`ipv6LeakProtectionEnabled`) AND the posture installs an
  ///     `NEIPv6Route.default()`. If the configuration does not request `::/0`
  ///     the clause is skipped — the switch matches the configuration's
  ///     capture intent, and does not invent one [1].
  ///   * DNS — captured only when a resolver is installed with a `matchDomains`
  ///     list that includes the root (`""`), so every name resolves through
  ///     the tunnel. A nil resolver set is not blocking.
  ///   * The carrier edge — the tunnel's own outer socket must be carved out of
  ///     the capture (`transportIPv4ExclusionRoute` present in
  ///     `excludedRoutes`) or the tunnel dead-loops its own packets. This is
  ///     the "exclude the endpoint" half of a WireGuard-style kill switch.
  ///
  /// [1] The product's own default full-tunnel document carries `::/0`, so on
  /// the shipping configuration the IPv6 clause always applies and always
  /// requires the sink, which is the same choice the promoted-posture verifiers
  /// make.
  static func egressBlocked(
    by settings: NEPacketTunnelNetworkSettings,
    config: WinsTunnelConfig
  ) -> Bool {
    guard let ipv4Settings = settings.ipv4Settings else { return false }
    let includedV4: [NEIPv4Route] = ipv4Settings.includedRoutes ?? []
    // IPv4 host traffic is captured only when the included routes together
    // cover every IPv4 destination: a bare `0.0.0.0/0`, or the macOS full-tunnel
    // `/1` pair. Anything narrower — a single /1, a /32, a bare route set, an
    // empty set — lets non-matching hosts pass.
    guard capturesAllIPv4(includedV4) else { return false }
    // Excluded routes beat included ones, so every exclusion is a hole in the
    // capture. The only hole a blocking posture may carry is the carrier /32.
    let excludedV4All: [NEIPv4Route] = ipv4Settings.excludedRoutes ?? []
    let carrierExclusion = config.transportIPv4ExclusionRoute
    let onlyCarrierExcluded = excludedV4All.allSatisfy { route in
      guard let carrierExclusion else { return false }
      return route.destinationAddress == carrierExclusion.destinationAddress
        && route.destinationSubnetMask == carrierExclusion.subnetMask
    }
    guard onlyCarrierExcluded else { return false }

    if config.ipv6LeakProtectionEnabled {
      let includedV6: [NEIPv6Route] = settings.ipv6Settings?.includedRoutes ?? []
      let capturesIPv6Default = includedV6.contains { route in
        route.destinationAddress == "::" && route.destinationNetworkPrefixLength == 0
      }
      guard capturesIPv6Default else { return false }
      let excludedV6: [NEIPv6Route] = settings.ipv6Settings?.excludedRoutes ?? []
      guard excludedV6.isEmpty else { return false }
    }

    // DNS is captured only if a resolver is installed AND it is named after the
    // root domain, so every query — including the traffic that flows through
    // the tunnel — goes to the tunnel's resolver rather than the ISP's.
    guard let dnsSettings = settings.dnsSettings else { return false }
    let capturesAllDNS = dnsSettings.matchDomains?.contains("") == true
    guard capturesAllDNS else { return false }

    // The carrier edge. When the configuration has a usable transport /32 the
    // posture must exclude it, or the tunnel's own outer socket is captured by
    // its own default route and the tunnel dead-loops.
    if let exclusionRoute = config.transportIPv4ExclusionRoute {
      let excludedV4: [NEIPv4Route] = ipv4Settings.excludedRoutes ?? []
      let excludesCarrier = excludedV4.contains { route in
        route.destinationAddress == exclusionRoute.destinationAddress
          && route.destinationSubnetMask == exclusionRoute.subnetMask
      }
      guard excludesCarrier else { return false }
    }

    return true
  }

  /// The status vocabulary for a session that blocks from the first installed
  /// posture. Split from the proof-gate's own vocabulary on purpose: those
  /// fields describe the ENGINE's proof while these describe the HOST's
  /// egress posture, and a reader asking "was egress actually blocked before
  /// the datapath carried?" needs the posture answer, which the proof fields
  /// do not give.
  static func bootstrapStatusFields(
    config: WinsTunnelConfig,
    verifiedBlocking: Bool,
    firstPostureBlocking: Bool
  ) -> [String: Any] {
    // Two namespaces on purpose: the proof gate's (a blocking bootstrap is
    // observably NOT narrow, and the gate is active) so shared readers see a
    // coherent, honest picture, and the kill switch's own.
    [
      "winn_datapath_proof_gate_active": true,
      "winn_datapath_proof_bootstrap_observably_narrow": !firstPostureBlocking,
      "kill_switch_active": activeFor(config: config, devRunActive: false),
      "kill_switch_first_posture": firstPostureBlocking ? "blocking" : "narrow",
      "kill_switch_egress_blocked_verified":
        verifiedBlocking && firstPostureBlocking,
      "kill_switch_ipv4_default_route_captured": verifiedBlocking,
      "kill_switch_matched_config_capture_intent": verifiedBlocking
    ]
  }

  /// The fields a teardown document can honestly state: the session held a
  /// blocking posture until the system ends it, so nothing it tore down
  /// released into cleartext. The release itself (when it works) happens only
  /// at session end, never while the datapath is still running.
  static func teardownStatusFields(
    heldBlockingPosture: Bool,
    datapathStoppedBeforeRelease: Bool
  ) -> [String: Any] {
    [
      "kill_switch_egress_blocked_through_teardown":
        heldBlockingPosture && datapathStoppedBeforeRelease,
      "kill_switch_teardown_release_after_datapath_stop": datapathStoppedBeforeRelease
    ]
  }

  /// True when `includedRoutes` captures every IPv4 destination: either a bare
  /// `0.0.0.0/0` default, or the macOS full-tunnel `/1` pair (`0.0.0.0/1` and
  /// `128.0.0.0/1`) that together span all of IPv4 space.
  ///
  /// WHY THE PAIR IS A CAPTURE. The macOS full tunnel installs the `/1` pair,
  /// not a bare `/0` — `WinsTunnelConfig.appleIncludedIPv4Routes` expands the
  /// config's full-tunnel default through
  /// `WinsIPv4Route.macosFullTunnelDefaultPair` (see that comment for the
  /// measured 2026-08-09 history). The two `/1`s are disjoint and their union
  /// is `0.0.0.0/0`, so every host destination is matched by exactly one of
  /// them. A predicate that recognised ONLY the bare `/0` would read the
  /// shipping macOS posture as NOT blocking; under the kill-switch path the
  /// provider would then refuse to install the very full-tunnel posture meant
  /// to carry the tunnel, and macOS would never start a v3 session at all. That
  /// is a false green of the exact class this repo's catalogue warns about — a
  /// check that asserts one concrete shape and silently misses the one the
  /// shipping code actually emits.
  ///
  /// Fail-closed by construction: every clause defaults to false, and any
  /// single missing half of the pair, any narrower route, and any bare-route
  /// set all read NOT blocking.
  static func capturesAllIPv4(_ includedRoutes: [NEIPv4Route]) -> Bool {
    // A bare default captures everything.
    if includedRoutes.contains(where: {
      $0.destinationAddress == "0.0.0.0"
        && prefixLength(ofSubnetMask: $0.destinationSubnetMask) == 0
    }) {
      return true
    }
    // The macOS full-tunnel `/1` pair: BOTH halves present, both exactly /1.
    let lowerHalf = includedRoutes.contains {
      $0.destinationAddress == "0.0.0.0"
        && prefixLength(ofSubnetMask: $0.destinationSubnetMask) == 1
    }
    let upperHalf = includedRoutes.contains {
      $0.destinationAddress == "128.0.0.0"
        && prefixLength(ofSubnetMask: $0.destinationSubnetMask) == 1
    }
    return lowerHalf && upperHalf
  }

  /// Dotted-quad subnet mask to prefix length. Malformed masks return -1
  /// so they cannot satisfy a default-route or carrier-exclusion clause.
  static func prefixLength(ofSubnetMask mask: String) -> Int {
    let parts = mask.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return -1 }
    var value: UInt32 = 0
    for part in parts {
      guard !part.isEmpty,
            part.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
            let octet = UInt8(part) else {
        return -1
      }
      value = (value << 8) | UInt32(octet)
    }
    let length = value.nonzeroBitCount
    let contiguous: UInt32 = length == 0
      ? 0 : UInt32.max << UInt32(32 - length)
    return value == contiguous ? length : -1
  }
}

/// What the iOS winn memory watchdog may do with one footprint sample.
/// A promoted (carrying) session is never cancelled by policy: cancelling it
/// releases the blocking posture and drops the device onto cleartext, which
/// the provider's no-production-watchdog doctrine forbids. Jetsam remains the
/// OS's decision, not ours. A failed sample is not evidence of pressure.
enum WinsWinnMemoryWatchdogPolicy: Equatable {
  case ignore
  case recordOnly
  case cancelBeforePromotion

  static func decide(footprintBytes: Int?, ceilingBytes: Int, promoted: Bool) -> Self {
    guard let footprintBytes, footprintBytes >= 0 else { return .ignore }
    guard footprintBytes >= ceilingBytes else { return .ignore }
    return promoted ? .recordOnly : .cancelBeforePromotion
  }
}
