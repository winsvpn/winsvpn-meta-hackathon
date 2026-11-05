import Foundation
import NetworkExtension

/*
 * WinsWinn3SessionStart.swift — the START DECISION for winn/3 STANDALONE on
 * Apple, and the two settings postures a standalone session installs.
 *
 * ===========================================================================
 * WHAT WAS MISSING, AND WHY THIS FILE IS IT
 * ===========================================================================
 *
 * Three files existed and none of them started anything.
 *
 *   WinsWinn3HostContract.swift  the decisions — the §4.1 promotion predicate,
 *                                the bootstrap-posture check, the carrier-
 *                                exclusion refusal, the create document. No
 *                                moving parts, deliberately.
 *   WinsWinn3Datapath.swift      the pump — dlsym, create, and the two loops
 *                                that move packets across the C ABI. It makes
 *                                NO start decision and promotes nothing,
 *                                deliberately.
 *   PacketTunnelProvider.swift   both of them, containing ZERO references to
 *                                winn3 and driving only the AmneziaWG relay.
 *
 * Between the contract and the pump there was no file that could answer the
 * two questions a provider actually has to ask: "may this configuration start
 * a standalone session at all", and "what does the interface look like while
 * it is being proven, and after". This file answers exactly those two and
 * nothing else. It opens no socket, installs no settings and starts no pump;
 * it builds the documents the provider hands to those.
 *
 * It lives in WinsTunnelCore rather than in either provider for the reason
 * every other decision here does: `tools/verify_apple_winn3_host_contract.sh`
 * globs every Swift source under `apple/WinsTunnelCore` and links them against
 * the REAL Go archive, so a rule written here is driven by a harness, and a
 * rule written in a provider is driven by nothing at all.
 *
 * ===========================================================================
 * WHY THE INI KEYS ARE SPELLED LIKE THE JSON KEYS
 * ===========================================================================
 *
 * The `[winn]` keys a standalone start reads are named identically to the
 * create document's own JSON fields — `inner_v4`, `inner_router_v4`,
 * `gateway_static`, `gateway_id`, `admission_key`, `psk`, `path_mtu`,
 * `carrier_classes`, `static_private`. Not a translation table, on purpose:
 * `WinsTunnelConfig` already reads `[winn] inner_v4` under that exact name, the
 * Go decoder refuses unknown fields, and the control-plane lane that will
 * eventually emit these has ONE spelling to match rather than two to keep in
 * sync. A reader can diff the INI section against the JSON document by eye.
 *
 * `auth_ed25519` and `auth_mldsa65` are the optional dual-signature pair. They
 * are consumed here with both-or-neither / exact canonical-length fail-closed
 * checks, then forwarded byte-for-byte into `WinnTunnelCreateWinn3`. The Go
 * create path binds them to `session.DualAuthConfig` before it opens a socket.
 *
 * ===========================================================================
 * THE INTERFACE ADDRESS IS THE INNER ADDRESS, AND THIS IS LOAD-BEARING
 * ===========================================================================
 *
 * Both postures below carry `[winn] inner_v4` as the interface address, NOT
 * `[interface] Address`. That is not tidiness. The winn/3 tun layer validates
 * the source address of every packet the host offers and drops what does not
 * match the assignment — so an interface carrying the AmneziaWG address would
 * hand the engine a stream of packets it silently discards as invalid, the
 * gate would never carry, and the session would fail closed at the deadline
 * with `winn3_rx_dropped_invalid` as the only clue. Standalone shares no
 * address space with the relay because it shares no session with it.
 */

// MARK: - the [winn] keys a standalone start reads

extension WinsTunnelConfig {
  private func winn3Field(_ key: String) -> String {
    (sections["winn"]?[key] ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  /// This tunnel's inner IPv4 address, from the signed gateway descriptor.
  var winn3InnerV4: String { winn3Field("inner_v4") }

  /// The inner next hop. Optional to the engine — it is used only as the
  /// source of a synthesised path-MTU packet — but required here, because it
  /// is also the one included route the bootstrap posture is allowed to carry.
  var winn3InnerRouterV4: String { winn3Field("inner_router_v4") }

  /// The gateway's INNER DNS RESPONDER address, from the same signed gateway
  /// descriptor `inner_router_v4` arrives on. Empty when the descriptor names
  /// none, which is every descriptor that exists today.
  ///
  /// Read here, beside `inner_router_v4`, because it is the same KIND of fact
  /// from the same document and carries the same trust: the descriptor is
  /// ML-DSA-65 signed, so a forged hub response cannot repoint DNS while the
  /// tunnel stays up. It is deliberately NOT a `[winn] dns` key —
  /// `conform.ServedWinnSectionCarriesNoPostureKey` pins `dns`, `dns_are_inner`,
  /// `dns_servers` and `resolvers` absent from this section and that list is
  /// untouched by this field.
  ///
  /// An ADDRESS, never a boolean. `WinsWinn3Resolvers` does not take this value
  /// as permission; it runs the same derivation it always ran, over a candidate
  /// this field supplied. Exactly ONE clause below consults it, and only to stop
  /// refusing the next hop BY NAME on the ground that nothing answers there —
  /// a ground that is false once, and only once, the gateway's `-resolver` is
  /// actually running.
  var winn3InnerResolverV4: String { winn3Field("inner_resolver_v4") }

  /// This device's X25519 static private key, base64.
  ///
  /// Deliberately NOT `[interface] PrivateKey`. That key is the AmneziaWG
  /// identity the relay uses; reusing it here would give one key material two
  /// protocols' worth of exposure and would make a v3 compromise a v1
  /// compromise, which is exactly the coupling the standalone ruling removes.
  var winn3StaticPrivate: String { winn3Field("static_private") }

  /// The gateway's X25519 static public key, base64. Descriptor field
  /// `static_pub` on the control-plane side.
  var winn3GatewayStatic: String { winn3Field("gateway_static") }

  /// The admission profile, both halves of it, base64. They arrive on the same
  /// ML-DSA-65-signed descriptor as `gateway_static`, and the descriptor carries
  /// every byte-valued field base64-encoded — the hub validates `gateway_id`
  /// that way and refuses anything else with `descriptor-field-not-base64`.
  ///
  /// `winn3GatewayID` is therefore the descriptor's ENCODED form. It is not what
  /// the engine is handed; see `winn3GatewayIDOperatorText`.
  var winn3GatewayID: String { winn3Field("gateway_id") }
  var winn3AdmissionKey: String { winn3Field("admission_key") }

  /// Dual-signature Ed25519 attestation public key, base64. Empty when the
  /// signed descriptor did not carry the pair.
  var winn3AuthEd25519: String { winn3Field("auth_ed25519") }
  var winn3AuthEd25519Value: String? { sections["winn"]?["auth_ed25519"] }

  /// Dual-signature ML-DSA-65 attestation public key, base64. Empty when the
  /// signed descriptor did not carry the pair.
  var winn3AuthMldsa65: String { winn3Field("auth_mldsa65") }
  var winn3AuthMldsa65Value: String? { sections["winn"]?["auth_mldsa65"] }

  /// The gateway id as the ENGINE takes it: the operator's own gateway name,
  /// decoded out of the descriptor's base64. Nil when `[winn] gateway_id` is
  /// absent, is not base64, or does not decode to text.
  ///
  /// ==========================================================================
  /// THIS IS THE DESCRIPTOR BOUNDARY, AND IT IS THE ONLY PLACE THE DECODE HAPPENS
  /// ==========================================================================
  ///
  /// `gateway_id` is an authenticated input to the admission tag and is NEVER
  /// TRANSMITTED, so the two ends never discover that they disagree about it.
  /// A client whose bytes differ from the gateway's computes a tag the gateway
  /// cannot verify, and a winn/3 gateway does not answer a datagram it could not
  /// authenticate — no response, no ICMP, no log line. On a censored network
  /// that is indistinguishable from the gateway being blocked, which is the
  /// worst possible failure for this product to have.
  ///
  /// Every other host in the tree hands the engine the raw bytes of the
  /// operator's gateway name: `cmd/winn3-gateway` (the gateway that answers),
  /// `cmd/winn-datapath`'s keys and profile documents, and `cmd/winn3-labrig`.
  /// The C ABI used to base64-decode it instead, making Apple the one platform
  /// that computed a different tag from the same operator value. It no longer
  /// does — `cdatapath/winn_datapath_winn3.go` takes the create document's
  /// `gateway_id` verbatim — so the descriptor's encoding has to come off HERE,
  /// at the layer that reads descriptor-shaped fields, and exactly once.
  ///
  /// Decoding here rather than in the engine is also what keeps the refusal
  /// loud. A malformed descriptor value becomes a named start refusal an
  /// operator can read, instead of a session that starts, reports up and is
  /// silently ignored by the gateway forever.
  var winn3GatewayIDOperatorText: String? {
    let encoded = winn3GatewayID
    guard !encoded.isEmpty,
          let raw = Data(base64Encoded: encoded),
          !raw.isEmpty,
          let text = String(data: raw, encoding: .utf8),
          !text.isEmpty else {
      return nil
    }
    return text
  }

  /// The optional per-subscriber preshared key, base64. Absent in the shipping
  /// deployment; absent is not a refusal.
  var winn3PSK: String { winn3Field("psk") }

  /// The OUTER path MTU the plan floor is computed at. Zero means "let the
  /// engine use its conservative default" (`tun.IPv6MinLinkMTU`), which is a
  /// real choice and not a missing value.
  var winn3PathMTU: Int {
    Int(winn3Field("path_mtu")) ?? 0
  }

  /// The MIGRATION PLAN: every carrier class the session may escalate TO.
  ///
  /// Empty means `{"udp"}` to the engine, which is a plan that FORBIDS
  /// migration rather than one that ignores it. Comma-separated because an INI
  /// value is one line; the engine refuses any name that is not udp/tcp/tls, so
  /// nothing is normalised or dropped here.
  var winn3CarrierClasses: [String] {
    winn3Field("carrier_classes")
      .split(separator: ",")
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }

  /// The opaque correlation id the engine echoes in its status document.
  var winn3SessionID: String { winn3Field("session_id") }
}

// MARK: - the start decision

/// Whether a configuration may start a winn/3 STANDALONE session, and why not.
///
/// ===========================================================================
/// WHAT THIS REFUSES, AND WHAT IT DELIBERATELY NO LONGER REFUSES
/// ===========================================================================
///
/// `WinsTunnelConfig.winn3StartRefusalReason` used to end in a blanket refusal:
/// *"winn/3 standalone is not enabled on this build: kWinnHostCapabilities
/// reports .absent for every platform."* That refusal was correct on the day it
/// was written — there was no pump, so nothing could have carried a packet —
/// and it is CIRCULAR now that there is one. `kWinnHostCapabilities` can only
/// ever be retired by a measured session; a session can only happen if a start
/// is permitted; and that refusal permitted none. Held any longer it would have
/// guaranteed the capability stayed absent forever for a reason unrelated to
/// whether the datapath works.
///
/// What replaces it is not a weaker gate, it is a CHECKABLE one: every field
/// the create document cannot be built without, named individually, plus the
/// one Apple-specific structural rule (the carrier exclusion). A configuration
/// that satisfies all of them may be ATTEMPTED. It is not thereby believed:
/// nothing here promotes a route, `WinsWinn3PromotionGate` is untouched, and a
/// session that never carries a validated packet still fails closed at the
/// provider's deadline with the host's routing, IPv6 and DNS never claimed.
///
/// What is NOT checked here, on purpose:
///
///   * Whether the datapath ABI is present in this build. `dlsym` against the
///     process is meaningless at parse time — the Go archive arrives with a
///     native engine component that is loaded later, so this check would report
///     "absent" on a build that has it and make config parsing depend on load
///     order. `WinsWinn3Datapath.start` throws `symbolsUnavailable` at the one
///     moment the answer is real.
///   * Whether the gateway is reachable, or exists. That is the session's
///     question and it is answered by the promotion gate, not by a parser.
enum WinsWinn3StartRequirements {
  /// Every reason this configuration cannot start a standalone session, in a
  /// stable order. Empty means "may be attempted".
  ///
  /// Enumerated rather than short-circuited so an operator holding a
  /// half-provisioned descriptor learns everything that is missing from one
  /// refusal instead of one field per retry.
  static func unmetReasons(_ config: WinsTunnelConfig) -> [String] {
    guard config.winn3Enabled else { return [] }
    var reasons: [String] = []

    if config.winnEndpoint.isEmpty {
      reasons.append("[winn] endpoint is absent; a standalone session has no gateway to dial")
    } else if !isIPv4Literal(config.winnEndpointHost) || config.winnEndpointPort == 0 {
      // The engine refuses a hostname because resolving one there is a lookup
      // outside the tunnel. Refusing it here too means the operator learns it
      // from the config layer rather than from a create failure — and, more
      // importantly, learns the REAL reason: a hostname also silently produces
      // no exclusion /32, so without this the refusal below would blame the
      // exclusion for a problem that is the endpoint's.
      reasons.append("[winn] endpoint must be an IP literal with a port; a hostname is refused because resolving one is a lookup outside the tunnel")
    }
    if config.winn3InnerV4.isEmpty {
      reasons.append("[winn] inner_v4 is absent; the inner address comes from the ML-DSA-65-signed gateway descriptor and nothing in this configuration carries it")
    }
    if config.winn3InnerRouterV4.isEmpty {
      reasons.append("[winn] inner_router_v4 is absent; it is the inner next hop and the only included route a bootstrap posture may carry")
    }
    if config.winn3StaticPrivate.isEmpty {
      reasons.append("[winn] static_private is absent; a standalone session has no AmneziaWG identity to borrow and needs its own X25519 static key")
    }
    if config.winn3GatewayStatic.isEmpty {
      reasons.append("[winn] gateway_static is absent; without the gateway's static public key no handshake can be sealed")
    }
    if config.winn3GatewayID.isEmpty {
      reasons.append("[winn] gateway_id is absent; it binds an admission tag to one gateway so an initiation captured at A cannot be replayed at B")
    } else if config.winn3GatewayIDOperatorText == nil {
      // Present but unusable. This refusal is the one that used to live in the
      // Go archive as "gateway_id is not base64", and it is kept rather than
      // dropped because the alternative is the silent failure: a gateway id the
      // host guesses at produces a tag the gateway cannot verify, and a winn/3
      // gateway answers nothing it cannot authenticate. Refusing here costs an
      // operator one readable message; not refusing costs a user a tunnel that
      // reports up and carries nothing, with no way to tell that apart from
      // censorship.
      reasons.append("[winn] gateway_id is not usable: the signed descriptor carries it base64-encoded over the operator's gateway name, and this value does not decode to one. The engine is handed the decoded name, byte for byte what the gateway itself is configured with, because the admission tag is computed over it and is never transmitted")
    }
    if config.winn3AdmissionKey.isEmpty {
      reasons.append("[winn] admission_key is absent; without it no initiation this client sends carries a tag the gateway will admit")
    }
    reasons.append(contentsOf: WinsWinn3DualAuthPublicKeys.validate(
      ed25519Base64: config.winn3AuthEd25519Value,
      mldsa65Base64: config.winn3AuthMldsa65Value
    ).unmetReasons)
    // Apple's whole of `protect()`. Checked here rather than at create because
    // a create that succeeds has already opened the outer socket, and a socket
    // opened under a configuration whose exclusion resolves to loopback is one
    // the promotion will capture.
    if let exclusionReason = winn3CarrierExclusionIsUsable(config) {
      reasons.append("the carrier exclusion route is unusable: \(exclusionReason). On Apple that /32 is the only thing keeping the engine's outer socket off the tunnel")
    }
    // THE PROMOTION PRE-FLIGHT, run at START.
    //
    // This is the shape linux/runner/linux_tunnel_backend.cc uses and it is
    // deliberately copied: it calls the REAL `BuildPromotedPosture` before it
    // has installed anything, so a configuration that could bootstrap but could
    // never promote is refused while there is nothing to tear down and the
    // outer socket has not been opened. A pre-flight that restated the policy
    // would be a second policy, and two policies drift — so the reason below
    // comes from the same function `WinsWinn3Settings.fullTunnel` refuses on.
    //
    // Refusing the START rather than the PROMOTION also matters on Apple
    // specifically. A session that bootstraps and then refuses to promote has
    // already dialled the gateway from this device; on the Myanmar threat model
    // that is an observable connection to a censored endpoint bought for a
    // session that was never going to carry anything.
    if let resolverReason = WinsWinn3Resolvers.promotionRefusalReason(config) {
      reasons.append(resolverReason)
    }
    return reasons
  }

  /// Whether `value` is a dotted-quad IPv4 literal.
  ///
  /// `inet_pton` rather than `WinsTunnelConfig`'s own validator, which is
  /// `private` and therefore file-scoped, and rather than a hand-rolled split:
  /// a second dotted-quad parser is a second set of edge cases (leading zeros,
  /// octal, trailing dots) that can disagree with the first about whether an
  /// endpoint is a literal, and the whole point of this check is to agree.
  static func isIPv4Literal(_ value: String) -> Bool {
    guard !value.isEmpty else { return false }
    var address = in_addr()
    return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
  }

  /// The reasons as one refusal string, or nil when the start may be attempted.
  static func refusalReason(_ config: WinsTunnelConfig) -> String? {
    let reasons = unmetReasons(config)
    guard !reasons.isEmpty else { return nil }
    if reasons.count == 1 {
      return "A winn/3 standalone session cannot start: \(reasons[0])."
    }
    let numbered = reasons.enumerated()
      .map { "(\($0.offset + 1)) \($0.element)" }
      .joined(separator: "; ")
    return "A winn/3 standalone session cannot start, for \(reasons.count) reasons: \(numbered)."
  }
}

// MARK: - the create document, built from a configuration

extension WinsWinn3CreateDocument {
  /// The create document for `config`, or nil when the configuration does not
  /// satisfy `WinsWinn3StartRequirements`.
  ///
  /// Returns nil rather than throwing a second copy of the refusal so there is
  /// exactly one place a refusal is worded — a caller that reaches here without
  /// checking has a bug, not a message to show a user.
  static func make(config: WinsTunnelConfig) -> WinsWinn3CreateDocument? {
    guard WinsWinn3StartRequirements.unmetReasons(config).isEmpty else {
      return nil
    }
    // Not force-unwrapped for tidiness: `unmetReasons` above already refuses a
    // gateway id that does not decode, so nil here would mean the two rules had
    // drifted apart, and the safe reading of that is "do not start" rather than
    // "start with a gateway id nobody chose".
    guard let gatewayIDText = config.winn3GatewayIDOperatorText else {
      return nil
    }
    let dualAuth = WinsWinn3DualAuthPublicKeys.validate(
      ed25519Base64: config.winn3AuthEd25519Value,
      mldsa65Base64: config.winn3AuthMldsa65Value
    ).keys
    return WinsWinn3CreateDocument(
      gatewayEndpoint: config.winnEndpoint,
      staticPrivateBase64: config.winn3StaticPrivate,
      gatewayStaticBase64: config.winn3GatewayStatic,
      gatewayIDText: gatewayIDText,
      admissionKeyBase64: config.winn3AdmissionKey,
      dualAuthPublicKeys: dualAuth,
      pskBase64: config.winn3PSK.isEmpty ? nil : config.winn3PSK,
      innerV4: config.winn3InnerV4,
      innerRouterV4: config.winn3InnerRouterV4,
      pathMTU: config.winn3PathMTU,
      carrierClasses: config.winn3CarrierClasses,
      sessionID: config.winn3SessionID,
      // Always true on Apple, and it is why the exclusion check above is a
      // refusal. The appex cannot hand a protected descriptor to anything —
      // there is no `protect()` and no `SO_BINDTODEVICE` — so the engine opens
      // its own socket and the excludedRoutes /32 is the whole of its
      // protection.
      allowOwnSocket: true
    )
  }
}

// MARK: - §4.4, which resolvers a standalone session may install

/// Which resolvers a winn/3 STANDALONE session is allowed to point the host at,
/// and why a candidate is not one of them.
///
/// ===========================================================================
/// THE DEFECT THIS CLOSES, MEASURED RATHER THAN ARGUED
/// ===========================================================================
///
/// `WinsWinn3Settings.fullTunnel` used to install `config.dnsServers`
/// unconditionally:
///
///     if !config.dnsServers.isEmpty {
///       let dnsSettings = NEDNSSettings(servers: config.dnsServers)
///       ...
///     }
///
/// `WinsTunnelConfig.dnsServers` is the AmneziaWG `[Interface] DNS` line, and
/// `lib/main.dart`'s `_nativeTunnelDnsServers` writes that line on Apple from a
/// fallback that substitutes the PUBLIC Quad9 literals `9.9.9.9,
/// 149.112.112.112` whenever the served DNS carries no public literal. So a
/// standalone session — which by the 2026-08-08 ruling shares nothing with the
/// v1 AmneziaWG stack — promoted with Quad9 as its resolver, routed into a
/// tunnel whose gateway `cmd/winn3-gateway` "forwards nothing, resolves nothing
/// and egresses nothing". Every lookup either died in the tunnel or, worse,
/// took the physical path in the clear, and nothing on this platform could
/// notice: Apple had no `dns_are_inner` gate at all.
///
/// ===========================================================================
/// WHY THE ANSWER IS A REFUSAL AND NOT A NARROWER DEFAULT
/// ===========================================================================
///
/// The desktop hosts refuse, and they refuse because the failure is a LEAK and
/// not a stall. Measured on a live Linux kernel with the promoted `/1` pair
/// installed: `ip route get` sends a LAN resolver out the PHYSICAL interface,
/// because that interface's connected prefix is more specific than `/1`. Every
/// DNS query keeps going to the resolver a censor operates, in the clear, while
/// pages load through the tunnel and the gate reports success. Nothing is
/// broken. That is the worst symptom shape this project has, and it is why
/// `windows/runner/winn3_posture.h` refuses to promote (a) with no resolver at
/// all and (b) with resolvers the host has not declared inner.
///
/// ===========================================================================
/// THE PREDICATE IS DERIVED. IT IS NEVER TRANSPORTED, AND THAT IS THE RULE
/// ===========================================================================
///
/// `winn3_posture.h` carries `dns_servers_are_inner` as "the host's own
/// declaration". Windows can take that declaration from a LOCAL `[winn3]` file
/// because somebody with the machine wrote it; Apple has no such file, and the
/// only document reaching this host is the unsigned `[winn]` section the hub
/// serves.
///
/// So Apple DERIVES it, and `winn3/conform` states why in one line: *a
/// transported boolean asserting "this resolver is inside the tunnel" is the
/// leak wearing a flag.* There is deliberately NO `[winn] dns` key and NO
/// `[winn] dns_are_inner` key — `conform.ServedWinnSectionCarriesNoPostureKey`
/// pins both absent — because the section is unsigned and the resolver address
/// decides where every name lookup in the session goes. The field belongs on
/// the ML-DSA-65-signed gateway descriptor, beside `inner_router_v4`, and until
/// it is there the honest derived answer for a served configuration is "none",
/// which is a refusal.
///
/// ===========================================================================
/// WHAT "INNER" IS DERIVED FROM, GIVEN THAT THE HOST IS TOLD NOTHING
/// ===========================================================================
///
/// A standalone session knows exactly two inner facts, both off the signed
/// descriptor: `[winn] inner_v4`, its own assignment, and `[winn]
/// inner_router_v4`, the next hop. Everything below is derived from those two
/// and from nothing else.
///
///   * NOT AN IPv4 LITERAL. A hostname resolver has to be resolved before it
///     can resolve, which is the lookup outside the tunnel that this whole
///     layer exists to prevent — the same reason `[winn] endpoint` refuses one.
///   * THE NEXT HOP ITSELF. `inner_router_v4` is documented as the inner next
///     hop *"for PMTU signals only"*, and the gateway behind it answers no
///     queries. Naming it would trade a leak for TOTAL name-resolution failure,
///     which is a different bug and not a fix.
///   * THE ASSIGNMENT ITSELF. That address is this device. Nothing answers
///     there, and a resolver pointed at the local tunnel address is a lookup
///     that times out rather than one that leaks.
///   * A PUBLIC LITERAL. This is the shipping defect above. A public resolver
///     is not inner by any reading: it is reachable off-tunnel by construction,
///     so the moment the tunnel drops it resolves over the censored path — and
///     while the tunnel is up it is reachable only if the gateway egresses,
///     which this one does not.
///   * OUTSIDE THE ASSIGNMENT'S OWN /24. This is the conservative floor. The
///     descriptor carries the assignment as a bare address with no prefix, so
///     the narrowest inner space this host can NAME without inventing a number
///     on the wire is the /24 around it — which is also the shape every one of
///     these deployments has (`DNS = 10.8.1.1` beside `Address = 10.8.1.3/32`).
///     A wider guess would accept a resolver the host cannot show is inside
///     this tunnel, and accepting is the direction that leaks.
///
/// The derivation can only ever UNDER-accept, and under-accepting refuses,
/// which is the safe direction. When the descriptor grows a resolver field the
/// filter is already here and already measured; nothing else has to move.
enum WinsWinn3Resolvers {
  /// The resolvers this host has to offer a standalone session today.
  ///
  /// It is `[interface] DNS`, and naming that here rather than reading it at
  /// the point of use is the point: this is the ONE resolver list an Apple host
  /// possesses, it belongs to the AmneziaWG relay, and a v1 resolver can only
  /// pass the derivation below by coincidence. A reader looking for "where does
  /// a standalone session get its resolvers" finds this function and the answer
  /// "nowhere it should", rather than an `NEDNSSettings` constructor three
  /// layers down.
  static func candidates(_ config: WinsTunnelConfig) -> [String] {
    // THE SIGNED FIELD WINS OUTRIGHT, AND IT REPLACES RATHER THAN JOINS.
    //
    // When the descriptor names an inner resolver, that is the ONLY resolver
    // this session may consider, and `[interface] DNS` — the AmneziaWG relay's
    // line, which lib/main.dart fills with PUBLIC Quad9 literals on Apple — is
    // not appended beside it. Appending would be the worse half of both:
    // `NEDNSSettings(servers:)` hands the whole list to the resolver library and
    // the LIBRARY, not this code, picks which one answers, so a public entry
    // sitting second in the list is a public resolver that answers whenever the
    // first is slow. `promotionRefusalReason` would refuse such a mixed list
    // anyway — the point of replacing is that the honest configuration does not
    // have to be rescued by a refusal.
    //
    // Empty descriptor field ⇒ this returns exactly what it returned before the
    // field existed, so every configuration served today derives, and refuses,
    // identically.
    let advertised = config.winn3InnerResolverV4
      .trimmingCharacters(in: .whitespacesAndNewlines)
    if !advertised.isEmpty {
      return [advertised]
    }
    return config.dnsServers
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }

  /// Why this host cannot derive that `resolver` is inside THIS session's
  /// tunnel, or nil when it can.
  ///
  /// Ordered so the most specific fact wins: a value that is both the next hop
  /// and inside the assignment's block is refused as the next hop, because that
  /// is the actionable half.
  static func notInnerReason(_ resolver: String, config: WinsTunnelConfig) -> String? {
    let value = resolver.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty else {
      return "it is empty"
    }
    guard let candidate = ipv4Value(value) else {
      return "\(value) is not an IPv4 literal, and a resolver that must itself be resolved is the lookup outside the tunnel this layer exists to prevent"
    }
    // THE ONE CLAUSE THAT NARROWED, AND EXACTLY HOW FAR.
    //
    // Was: "is the next hop" ⇒ refuse. Is now: "is the next hop AND the signed
    // descriptor names no resolver there" ⇒ refuse. Nothing else moved: a
    // hostname, this device's own assignment, a public literal and anything
    // outside the assignment's /24 are all still refused below, and they are
    // still refused even when the descriptor names them, because the descriptor
    // is a signed FACT about where the gateway listens and not a permission to
    // skip a check.
    //
    // The old ground was "the gateway behind it answers no queries", and that
    // was true of every gateway that has ever run. `cmd/winn3-gateway`'s
    // `-resolver` makes it false for a gateway that enables it, and it answers
    // at the gateway's own `-inner-v4` — which IS this client's next hop —
    // because winn3/tun's outbound validator requires a reply's source to equal
    // the endpoint's own assignment. A resolver at any second inner address
    // cannot answer through the tunnel at all. So "the resolver is the next hop"
    // is not an unfortunate coincidence to be tolerated; it is the only shape
    // this protocol permits, and the clause had to learn to see it.
    //
    // The equality is checked as PARSED VALUES, not as text: "10.64.0.1" and
    // "10.64.000.1" are the same address and a string compare would call the
    // descriptor's own resolver a different one, refuse it, and leave an
    // operator reading a message about a value that matches what they signed.
    let router = config.winn3InnerRouterV4.trimmingCharacters(in: .whitespacesAndNewlines)
    if !router.isEmpty, ipv4Value(router) == candidate {
      let advertised = config.winn3InnerResolverV4
        .trimmingCharacters(in: .whitespacesAndNewlines)
      if advertised.isEmpty || ipv4Value(advertised) != candidate {
        return "\(value) is [winn] inner_router_v4, which is documented as the inner next hop for PMTU signals only and answers no queries; naming it would trade a leak for total name-resolution failure. The signed descriptor does not name a resolver there — it carries [winn] inner_resolver_v4 = \"\(advertised)\" — so this host has no signed fact saying anything listens on that address"
      }
    }
    guard let assignment = ipv4Value(config.winn3InnerV4) else {
      return "\(value) cannot be shown to be inner because [winn] inner_v4 carries no IPv4 literal to derive an inner space from"
    }
    if candidate == assignment {
      return "\(value) is this session's own [winn] inner_v4 assignment, which is this device; nothing answers there"
    }
    if isPublicIPv4Literal(value) {
      return "\(value) is a PUBLIC resolver. It is reachable off-tunnel by construction, so it resolves over the censored path the moment the tunnel drops — and this is the value lib/main.dart's Apple fallback substitutes, so it is the one that actually ships"
    }
    if !sameInnerBlock(candidate, assignment) {
      return "\(value) is outside the /24 around this session's [winn] inner_v4 assignment (\(config.winn3InnerV4)), so this host cannot derive that it is reachable only through THIS tunnel — a resolver in another session's inner space is dropped by the winn/3 tun layer, not carried"
    }
    return nil
  }

  /// The resolvers a promoted posture may install: the candidates this host can
  /// DERIVE to be inner. Empty is the answer for every configuration the
  /// control plane serves today, and empty is a refusal rather than a posture
  /// with no DNS.
  static func inner(_ config: WinsTunnelConfig) -> [String] {
    candidates(config).filter { notInnerReason($0, config: config) == nil }
  }

  /// Why a standalone session may not promote, or nil.
  ///
  /// The two clauses are `windows/runner/winn3_posture.h`'s two, in its order
  /// and for its stated reasons.
  ///
  /// The second is a claim about the WHOLE LIST rather than about each member,
  /// which is also `winn3_posture.h`'s shape: `dns_servers_are_inner` is one
  /// boolean over `dns_servers`, declaring that EVERY resolver in it is
  /// reachable only through the tunnel. Filtering a mixed list down to its
  /// derivable members and promoting on the remainder would be worse than
  /// refusing it, because `NEDNSSettings(servers:)` hands the whole list to the
  /// resolver library and the library — not this code — picks which one answers.
  static func promotionRefusalReason(_ config: WinsTunnelConfig) -> String? {
    guard config.winn3Enabled else { return nil }
    let offered = candidates(config)
    if offered.isEmpty {
      return "a standalone winn/3 session has no resolver it can justify: this posture takes the default route, and a host that widens its routes without also moving name resolution leaves every DNS query going to the resolver it was handed by the network it is hiding from — in the clear, over the physical interface, while the tunnel reports carrying. There is no v3 resolver anywhere in the system today: the signed gateway descriptor's closed field set carries none, and [winn] deliberately has no dns key because the section is unsigned. The route set and the resolver set have to move together or neither may move"
    }
    var rejected: [String] = []
    for resolver in offered {
      if let reason = notInnerReason(resolver, config: config) {
        rejected.append(reason)
      }
    }
    if !rejected.isEmpty {
      return "a standalone winn/3 session cannot install the \(offered.count) resolver(s) this configuration offers, because this host cannot DERIVE that every one of them is reachable only through the tunnel: \(rejected.joined(separator: "; ")). They come from the AmneziaWG [Interface] DNS line, which belongs to a session this one shares nothing with. The declaration is derived and never transported — a boolean on the wire asserting a resolver is inside the tunnel is the leak wearing a flag"
    }
    return nil
  }

  /// `dns_servers_are_inner`, derived. True only when there is at least one
  /// resolver AND every one of them is derivable.
  static func areInner(_ config: WinsTunnelConfig) -> Bool {
    promotionRefusalReason(config) == nil
  }

  /// Whether `value` is a public IPv4 literal.
  ///
  /// The same ranges `lib/main.dart:_isPublicIpv4Literal` excludes, so the two
  /// sides of the seam cannot disagree about which literals are the ones that
  /// ship. A value that is not an IPv4 literal at all is not public — it is
  /// refused one clause earlier, and answering "true" here would give it the
  /// wrong diagnostic.
  static func isPublicIPv4Literal(_ value: String) -> Bool {
    guard let parsed = ipv4Value(value) else { return false }
    let first = (parsed >> 24) & 0xff
    let second = (parsed >> 16) & 0xff
    if first == 10 || first == 127 || first == 0 { return false }
    if first == 100 && second >= 64 && second <= 127 { return false }
    if first == 169 && second == 254 { return false }
    if first == 172 && second >= 16 && second <= 31 { return false }
    if first == 192 && second == 168 { return false }
    if first >= 224 { return false }
    return true
  }

  /// Two addresses in the same /24.
  static func sameInnerBlock(_ a: UInt32, _ b: UInt32) -> Bool {
    (a & 0xFFFF_FF00) == (b & 0xFFFF_FF00)
  }

  /// A dotted quad as a host-order integer, or nil.
  ///
  /// `inet_pton` for the same reason `WinsWinn3StartRequirements.isIPv4Literal`
  /// uses it: a second dotted-quad parser is a second set of edge cases that can
  /// disagree with the first about whether a value is a literal, and every
  /// decision here turns on that agreement.
  static func ipv4Value(_ text: String) -> UInt32? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    var address = in_addr()
    guard trimmed.withCString({ inet_pton(AF_INET, $0, &address) == 1 }) else {
      return nil
    }
    return UInt32(bigEndian: address.s_addr)
  }
}

// MARK: - §4.3, the promoted posture, checked on the object that was built

/// Whether a settings object is a usable PROMOTED posture.
///
/// The mirror of `WinsWinn3BootstrapPosture`, which asks *"did the narrow
/// posture stay narrow?"*. Until now nothing on Apple asked the opposite
/// question, and the opposite question is the one a served configuration makes
/// reachable: *"did the WIDE posture actually widen, and did name resolution
/// move with it?"*
///
/// It lives beside the builder rather than beside its sibling in
/// `WinsWinn3HostContract.swift` on purpose: `fullTunnel` calls it as the last
/// thing it does, and a verifier a builder can be edited away from is a
/// verifier that stops running without anything failing.
///
/// The reasoning is `windows/runner/winn3_posture.h`'s, and it is worth
/// restating because it is the whole point: a promotion gate that reports
/// success on a posture that captures nothing, or that captures traffic and
/// leaves name resolution behind, is worth LESS than no gate at all. No gate
/// leaves an operator knowing the state is unproven; a gate that says success
/// leaves them believing a proof happened, and everything downstream — the
/// status document, the UI, the user's decision about what to type into a
/// browser — reads that success.
enum WinsWinn3PromotedPosture {
  struct Verdict {
    let usable: Bool
    let reasons: [String]
    let statusFields: [String: Any]
  }

  static func evaluate(
    _ settings: NEPacketTunnelNetworkSettings,
    config: WinsTunnelConfig
  ) -> Verdict {
    var reasons: [String] = []

    let ipv4 = settings.ipv4Settings
    let includedRoutes = ipv4?.includedRoutes ?? []
    // Apple spells the default route as `NEIPv4Route.default()`, whose
    // destination is `0.0.0.0`. A promoted posture whose route set is all host
    // routes has widened nothing: the bootstrap already installed the one /32 it
    // is allowed, so such a posture would report carrying while every packet
    // still left by the physical interface.
    let capturesSomething = includedRoutes.contains { route in
      route.destinationAddress == "0.0.0.0" || route.destinationSubnetMask != "255.255.255.255"
    }
    if !capturesSomething {
      reasons.append("the promoted posture captures nothing: it takes no default route and its \(includedRoutes.count) route(s) are all single hosts, so the session would report carrying while every packet still left by the physical interface in the clear")
    }

    // THE IPv6 CLAUSE, ASKED OF THE OBJECT RATHER THAN OF THE BUILDER.
    //
    // Two failures, and this provider could produce neither today — which is
    // exactly why they are checked here rather than only at the point of
    // construction. `fullTunnel` guards both; a verifier that only re-states
    // what its own builder just decided is a verifier that stops meaning
    // anything the first time a second builder appears, and a split-tunnel
    // standalone mode is the obvious one.
    //
    //   * A promoted posture with NO IPv6 settings at all leaves the host's own
    //     IPv6 address and IPv6 default route on the physical interface while
    //     the IPv4 default route moves onto the tunnel. Windows and Linux
    //     shipped that until 2026-08-10; measured in a namespace rig the same
    //     day, `route get` for a global v6 destination resolved to the physical
    //     interface and the tunnel never saw the packets.
    //   * IPv6 settings on a link BELOW the RFC 8200 floor are a black hole
    //     rather than a narrow link, because IPv6 routers do not fragment.
    //
    // `settings.mtu` is read rather than an `innerMTU` parameter added, so this
    // asks about the interface that would actually be configured.
    if config.ipv6LeakProtectionEnabled, settings.ipv6Settings == nil {
      reasons.append("the promoted posture installs no IPv6 settings while the configuration requested ::/0 capture; host IPv6 would keep egressing on the physical interface beside a promoted IPv4 tunnel, which on this threat model is an attributable session the user cannot see")
    }
    if settings.ipv6Settings != nil {
      let mtu = settings.mtu?.intValue ?? 0
      if mtu < WinsWinn3Settings.ipv6MinLinkMTU {
        reasons.append("the promoted posture installs IPv6 at an interface MTU of \(mtu), below RFC 8200's \(WinsWinn3Settings.ipv6MinLinkMTU)-byte link floor; IPv6 routers do not fragment, so that is a black hole rather than a narrow link")
      }
    }

    let installed = settings.dnsSettings?.servers ?? []
    if installed.isEmpty {
      reasons.append("the promoted posture installs no resolver while taking the default route; the route set and the resolver set have to move together or neither may move")
    }
    for resolver in installed {
      if let reason = WinsWinn3Resolvers.notInnerReason(resolver, config: config) {
        reasons.append("the promoted posture installs a resolver this host cannot derive to be inner: \(reason)")
      }
    }
    // The object must carry the DERIVED set and nothing else. Comparing the two
    // lists rather than only re-running the predicate is what catches a builder
    // that filtered correctly and then attached a different array.
    if installed != WinsWinn3Resolvers.inner(config) {
      reasons.append("the promoted posture's resolver list is not the derived inner set")
    }

    return Verdict(
      usable: reasons.isEmpty,
      reasons: reasons,
      statusFields: [
        "winn3_datapath_proof_promoted_posture_usable": reasons.isEmpty,
        "winn3_datapath_proof_promoted_included_route_count": includedRoutes.count,
        "winn3_datapath_proof_promoted_resolver_count": installed.count,
        "winn3_datapath_proof_resolvers_derived_inner":
          WinsWinn3Resolvers.areInner(config)
      ]
    )
  }
}

// MARK: - the two postures

/// The settings a standalone session installs, in the order it installs them.
///
/// Both are built here, from the same configuration and the same published
/// inner MTU, so the pair can be inspected offline and so the difference
/// between them is one readable diff rather than two functions in two
/// providers that drift.
enum WinsWinn3Settings {
  /// RFC 8200's hard floor for a link that carries IPv6, and the number this
  /// tree did not have.
  ///
  /// # Why it is being added on 2026-08-10
  ///
  /// `fullTunnel` below installs an IPv6 sink — a /128 plus `NEIPv6Route
  /// .default()` — so that host IPv6 is drawn into the tunnel and dropped
  /// rather than left egressing on the physical interface beside a promoted
  /// IPv4 tunnel. That is the right posture and it has always been installed
  /// unconditionally. What was missing is any check that the link it is
  /// installed on can legally carry IPv6 at all: **grepping this whole tree —
  /// `apple/`, `ios/`, `macos/` — for `1280` found two test fixtures and one
  /// doc comment, and no guard anywhere.**
  ///
  /// The floor is not advisory. On Linux `ipv6_add_dev()` returns `-EINVAL`
  /// below it; measured on 2026-08-10 against a tun device, `ip -6 address add
  /// fd00:d951:1::2/128` was refused at 576, 1138, 1139 and 1279 with
  /// "Invalid argument" and accepted at 1280, 1281, 1309, 1331, 1373 and 1500.
  /// Apple's stack is not that kernel, but the sink's PURPOSE fails either way:
  /// an IPv6 route onto a link narrower than the minimum every IPv6 router may
  /// assume is a black hole, and IPv6 routers do not fragment.
  ///
  /// Until 2026-08-10 the fleet's default path MTU was 1280, which over the
  /// shipping migration plan yields an inner MTU of 1139 — below this floor.
  /// So this provider was installing a sink it had no right to install, and was
  /// correct only because nothing downstream complained. The default is now
  /// 1450, yielding 1309, which clears the floor. **The arithmetic moved; the
  /// code did not.** This constant makes the correctness structural instead.
  ///
  /// # It is plan-aware without re-deriving the plan
  ///
  /// The published path-MTU thresholds for inner IPv6 differ by migration plan
  /// — 1357 for udp alone, 1399 for `[udp,tcp]`, 1421 for `[udp,tcp,tls]` — and
  /// a flat 1421 check would refuse two configurations that work. None of that
  /// arithmetic belongs here: `innerMTU` is already `driver.NewSizing(...)
  /// .InnerMTU`, the plan floor the engine computed, and each threshold reduces
  /// to the same inner number (1357−77, 1399−119 and 1421−141 are all 1280).
  /// One comparison against the value about to be set on the interface is the
  /// plan-aware form of all three, and it is not a second implementation of
  /// `carrier.Floor` in Swift — which §4.2 makes a black hole rather than an
  /// inefficiency.
  static let ipv6MinLinkMTU = 1280

  /// The BOOTSTRAP posture: one /32, at most one included route, no default
  /// route, no IPv6, no DNS, the carrier exclusion present, and the interface
  /// MTU equal to the engine's published inner MTU.
  ///
  /// `innerMTU` is the engine's own `winn3_inner_mtu`, read from the status
  /// document after create. It is NOT recomputed here: the plan floor is
  /// `driver.NewSizing` over the whole migration plan, and a second
  /// implementation of that arithmetic in Swift would be a number that can
  /// disagree with the engine's — which §4.2 makes a black hole rather than an
  /// inefficiency.
  static func bootstrap(
    config: WinsTunnelConfig,
    innerMTU: Int
  ) -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: config.networkSettingsRemoteAddress
    )
    let ipv4Settings = NEIPv4Settings(
      addresses: [config.winn3InnerV4],
      subnetMasks: ["255.255.255.255"]
    )
    // The inner next hop, and nothing else. It is what makes the interface
    // usable enough to carry a convergence probe without making it usable
    // enough to carry the host's traffic.
    ipv4Settings.includedRoutes = [
      NEIPv4Route(
        destinationAddress: config.winn3InnerRouterV4,
        subnetMask: "255.255.255.255"
      )
    ]
    ipv4Settings.excludedRoutes = carrierExclusionRoutes(config)
    settings.ipv4Settings = ipv4Settings
    // ipv6Settings and dnsSettings left nil on purpose. The host keeps its own
    // IPv6 and its own resolvers: a resolver pointed into an unproven tunnel
    // makes every lookup on the machine fail, including the app's own recovery
    // path.
    settings.mtu = NSNumber(value: innerMTU)
    return settings
  }

  /// The FULL-TUNNEL posture, installed only after `WinsWinn3PromotionGate`
  /// has observed the gate carrying AND a validated packet delivered.
  ///
  /// Deliberately NOT the provider's `makeNetworkSettings(from:)` object. That
  /// one carries the AmneziaWG interface address and the AmneziaWG MTU, and
  /// promoting onto it would leave the engine dropping every packet the host
  /// offered as a source-address violation — a tunnel that reports up and
  /// carries nothing, which is the exact failure shape the promotion gate
  /// exists to prevent one layer down.
  ///
  /// # The IPv6 sink is installed, and black-holing v6 is the POINT
  ///
  /// This host reads no `inner_v6`, so `winn3_inner_ipv6` is false and a
  /// promoted standalone session cannot carry IPv6. There are two ways to
  /// promote under that fact and only one of them is safe:
  ///
  ///   * Install no IPv6 settings — the host keeps its own v6, and every
  ///     application with a v6 route reaches the network AROUND the tunnel. For
  ///     a user whose threat model is a state observer on the local network,
  ///     that is not a degraded tunnel, it is a silent, complete bypass of it.
  ///   * Install the sink — v6 is drawn into the tunnel, the winn/3 tun layer
  ///     drops it as an unassigned family, and v6 connectivity stops.
  ///
  /// The second is chosen, for the same reason the relay's own settings builder
  /// chooses it and calls it deliberate leak protection: a blackout the user can
  /// see beats a leak they cannot. It is also the direction the whole gate
  /// leans — a dead tunnel is safer than one that quietly carries cleartext.
  ///
  /// # It RETURNS NIL rather than widening, and that is the fix
  ///
  /// This used to return a settings object unconditionally and attach
  /// `config.dnsServers` — the AmneziaWG `[Interface] DNS` line — whenever that
  /// list was non-empty. See `WinsWinn3Resolvers` for what actually reaches
  /// that line on Apple and why installing it is a leak with a green gate.
  ///
  /// Now it refuses, which is `windows/runner/winn3_posture.h`'s discipline
  /// verbatim: *every Build function returns false and writes a diagnostic
  /// rather than returning a wider posture.* There is no path here that
  /// produces a default route with no resolver, and none that produces one with
  /// a resolver this host could not derive to be inner. A caller that gets nil
  /// must refuse the session; it must never fall back to the bootstrap posture
  /// and report Connected, because a bootstrap posture reports carrying while
  /// capturing nothing.
  ///
  /// In practice the refusal is caught one layer earlier, at
  /// `WinsWinn3StartRequirements.unmetReasons`, so a configuration that could
  /// never promote never opens the outer socket. This one stays because the
  /// object that installs the resolvers is the one that has to refuse them —
  /// the pre-flight is a caller, and callers get skipped.
  static func fullTunnel(
    config: WinsTunnelConfig,
    innerMTU: Int
  ) -> NEPacketTunnelNetworkSettings? {
    guard WinsWinn3Resolvers.promotionRefusalReason(config) == nil else {
      return nil
    }
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: config.networkSettingsRemoteAddress
    )
    let ipv4Settings = NEIPv4Settings(
      addresses: [config.winn3InnerV4],
      subnetMasks: ["255.255.255.255"]
    )
    ipv4Settings.includedRoutes = config.appleIncludedIPv4Routes.map { route in
      NEIPv4Route(
        destinationAddress: route.destinationAddress,
        subnetMask: route.subnetMask
      )
    }
    ipv4Settings.excludedRoutes = carrierExclusionRoutes(config)
    settings.ipv4Settings = ipv4Settings
    if config.ipv6LeakProtectionEnabled {
      // THE GUARD THIS TREE DID NOT HAVE. See `ipv6MinLinkMTU`.
      //
      // Refusing rather than installing-anyway, and refusing rather than
      // promoting-without-the-sink, because those are the only two options and
      // both of the alternatives are worse:
      //
      //   * install it anyway — the sink is on a link below the minimum every
      //     IPv6 router may assume, so it is a black hole rather than a
      //     blackout, and whether the platform even accepts it is a property of
      //     a stack this code does not own;
      //   * promote without it — that is exactly the leak Windows and Linux
      //     were shipping until today: the IPv4 default route moves onto the
      //     tunnel while the host's own IPv6 address and IPv6 default route
      //     stay on the physical interface, so every destination with a AAAA
      //     record is reached AROUND the tunnel while the session reports
      //     carrying. Measured in a namespace rig on 2026-08-10: with the sink
      //     absent, `route get` for a global v6 destination resolved to the
      //     physical interface and the tunnel's own file descriptor never saw
      //     the packets.
      //
      // So it returns nil, which is this function's existing discipline and
      // `winn3_posture.h`'s verbatim: *every Build function returns false and
      // writes a diagnostic rather than returning a wider posture.* A caller
      // that gets nil must refuse the session. It is unreachable at the fleet
      // default — path 1450 yields 1309 — and reachable only for an operator
      // who has served a path MTU below the plan's own published threshold.
      guard innerMTU >= Self.ipv6MinLinkMTU else {
        return nil
      }
      let ipv6Settings = NEIPv6Settings(
        addresses: [config.ipv6SinkAddress],
        networkPrefixLengths: [NSNumber(value: config.ipv6SinkPrefixLength)]
      )
      ipv6Settings.includedRoutes = [NEIPv6Route.default()]
      settings.ipv6Settings = ipv6Settings
    }
    // The DERIVED set, never `config.dnsServers`.
    //
    // BELT TO BRACES, AND MEASURED TO BE SO. Mutation-tested on 2026-08-09:
    // replacing this with `config.dnsServers` — which is the ORIGINAL DEFECT,
    // restored exactly — SURVIVED the whole Apple suite. It has to: the guard
    // above returns nil unless every candidate is derivable, and
    // `WinsTunnelConfig.csvValues` already trims and drops empties, so on every
    // input that reaches this line the two expressions are the same array. No
    // behavioural test can distinguish them.
    //
    // It is kept, and the reasoning is `winn3_posture.h`'s for its own
    // unreachable self-check: the edit that makes the difference reachable — a
    // guard that grows an exception, a resolver source that is not the
    // candidate list — is exactly the edit during which nobody is looking for
    // it, and by then the line would already be putting the AmneziaWG
    // `[Interface] DNS` line into an `NEDNSSettings`. What holds it is
    // `winn3/conform`'s `StandaloneResolverGuards`, which greps for it, because
    // a grep is the only thing that can.
    let resolvers = WinsWinn3Resolvers.inner(config)
    let dnsSettings = NEDNSSettings(servers: resolvers)
    if !config.dnsMatchDomains.isEmpty {
      dnsSettings.matchDomains = config.dnsMatchDomains
    }
    settings.dnsSettings = dnsSettings
    settings.mtu = NSNumber(value: innerMTU)
    // The built object is checked rather than the builder trusted, which is the
    // shape `WinsWinn3BootstrapPosture.evaluate` gives the other posture and the
    // shape §4.3 rule 1 asks for. It is the LAST thing this function does, so
    // there is no path returning a promoted object this predicate would reject.
    //
    // BELT TO BRACES, AND MEASURED TO BE SO. Mutation-tested on 2026-08-09:
    // deleting this call SURVIVED the whole Apple suite, for the same reason
    // the identical call in `windows/runner/winn3_posture.h` survived deleting
    // — the builder above cannot currently produce an object this predicate
    // rejects. `includedRoutes` comes from `allowedIPv4Routes`, whose default
    // route the fixture carries, and the resolver set is the derived one by
    // construction.
    //
    // It is kept for the edit that makes it reachable: a split-tunnel standalone
    // mode, or any future posture whose default route is conditional. What holds
    // it is `winn3/conform`'s `StandaloneResolverGuards`, which greps for it.
    guard WinsWinn3PromotedPosture.evaluate(settings, config: config).usable else {
      return nil
    }
    return settings
  }

  /// The carrier /32, as a route list.
  ///
  /// Empty when the configuration has no USABLE exclusion, which is a stronger
  /// test than "has a route". `transportIPv4ExclusionRoute` will happily derive
  /// a `127.0.0.1/32` from a loopback `[winn] endpoint` — a route that is
  /// present, well-formed, and excludes nothing off this device. Installing it
  /// would make the posture LOOK excluded to anything that counts routes, which
  /// is precisely the check `WinsWinn3BootstrapPosture` performs. Returning
  /// nothing instead makes such a posture observably not narrow, so the
  /// provider refuses to install it even if the start refusal above were ever
  /// bypassed.
  private static func carrierExclusionRoutes(
    _ config: WinsTunnelConfig
  ) -> [NEIPv4Route] {
    guard winn3CarrierExclusionIsUsable(config) == nil,
          let exclusionRoute = config.transportIPv4ExclusionRoute else {
      return []
    }
    return [
      NEIPv4Route(
        destinationAddress: exclusionRoute.destinationAddress,
        subnetMask: exclusionRoute.subnetMask
      )
    ]
  }

  /// Whether `settings` carries the configuration's carrier /32 in
  /// `excludedRoutes`.
  ///
  /// Read off the OBJECT rather than off the configuration that built it,
  /// because that is what `WinsWinn3BootstrapPosture.evaluate` is documented to
  /// want: §4.3 rule 1 verifies narrowness on the settings object it just built
  /// rather than trusting the code that built it, and passing "the config had
  /// one" would hand that check a fact about a different thing.
  static func carrierExclusionPresent(
    in settings: NEPacketTunnelNetworkSettings,
    config: WinsTunnelConfig
  ) -> Bool {
    // A route that excludes nothing is not an exclusion. Same reasoning as
    // `carrierExclusionRoutes`: a loopback /32 satisfies "a route is present"
    // and satisfies nothing the check is for.
    guard winn3CarrierExclusionIsUsable(config) == nil,
          let expected = config.transportIPv4ExclusionRoute else { return false }
    // Annotated rather than inferred: `NEIPv4Settings.excludedRoutes` is
    // imported as an implicitly-unwrapped optional array, and letting the
    // element type be inferred through `??` makes `contains(where:)` resolve
    // against the wrong overload.
    let excluded: [NEIPv4Route] = settings.ipv4Settings?.excludedRoutes ?? []
    return excluded.contains(where: { (route: NEIPv4Route) -> Bool in
      route.destinationAddress == expected.destinationAddress
        && route.destinationSubnetMask == expected.subnetMask
    })
  }
}

// MARK: - what a started standalone session publishes

/// The status vocabulary a standalone start adds, beyond the engine's own
/// document and the pump's own counters.
///
/// Separate from `WinsWinn3PromotionGate.statusFields` because these describe
/// the HOST's decisions — which posture is installed, whether the start was
/// attempted at all — where those describe the ENGINE's observations. A reader
/// asking "why did this not promote" needs both, and needs to be able to tell
/// which side each number came from.
enum WinsWinn3SessionStatus {
  static func startFields(
    config: WinsTunnelConfig,
    attempted: Bool,
    refusalReason: String?
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "winn3_datapath_proof_standalone_start_attempted": attempted,
      "winn3_datapath_proof_carrier": config.winnCarrier,
      "winn3_datapath_proof_unmet_requirement_count":
        WinsWinn3StartRequirements.unmetReasons(config).count,
      // Published beside the count so a reader can tell "this configuration is
      // missing a descriptor field" from "this configuration is complete and
      // has no resolver a standalone session could justify" — the second is the
      // state every served configuration is in today, and it is a DIFFERENT
      // conversation with the operator.
      "winn3_datapath_proof_resolver_candidate_count":
        WinsWinn3Resolvers.candidates(config).count,
      "winn3_datapath_proof_resolvers_derived_inner_count":
        WinsWinn3Resolvers.inner(config).count,
      "winn3_datapath_proof_resolvers_derived_inner":
        WinsWinn3Resolvers.areInner(config)
    ]
    if let refusalReason {
      // The reasons are field names and structural facts; none of them is key
      // material, and a refusal nobody can read is a refusal nobody can fix.
      fields["winn3_datapath_proof_start_refusal_reason"] = refusalReason
    }
    return fields
  }

  /// One convergence tick, as fields.
  ///
  /// Deliberately NOT `WinsWinnDatapathProofGate.progressStatusFields`. That
  /// vocabulary is the RELAY's — it reports the handshake-response and
  /// both-ways-transport flags a standalone status document never sets — and
  /// emitting it for a standalone session would publish four fields that are
  /// false for a reason no reader could distinguish from "the session failed".
  /// A standalone session reports the numbers a standalone session has.
  static func progressFields(
    engineStatusFields: [String: Any],
    pumpStatusFields: [String: Any],
    probeAvailable: Bool,
    probesSent: Int,
    probeResponsesObserved: Int,
    elapsedMilliseconds: Int,
    deadlineMilliseconds: Int,
    promoted: Bool
  ) -> [String: Any] {
    var fields = engineStatusFields
    fields.merge(pumpStatusFields) { _, new in new }
    fields.merge(
      WinsWinn3PromotionGate.statusFields(engineStatusFields: engineStatusFields)
    ) { _, new in new }
    fields.merge([
      "winn3_datapath_proof_probe_available": probeAvailable,
      "winn3_datapath_proof_probes_sent": probesSent,
      "winn3_datapath_proof_probe_responses_observed": probeResponsesObserved,
      "winn3_datapath_proof_elapsed_ms": elapsedMilliseconds,
      "winn3_datapath_proof_deadline_ms": deadlineMilliseconds,
      "winn3_datapath_proof_promoted": promoted
    ]) { _, new in new }
    return fields
  }

  static func postureFields(
    posture: String,
    innerMTU: Int,
    verdict: WinsWinn3BootstrapPosture.Verdict?
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "winn3_datapath_proof_posture_installed": posture,
      "winn3_datapath_proof_published_inner_mtu": innerMTU
    ]
    if let verdict {
      fields.merge(verdict.statusFields) { _, new in new }
      if !verdict.narrow {
        fields["winn3_datapath_proof_bootstrap_refusal_reasons"] =
          verdict.reasons.joined(separator: "; ")
      }
    }
    return fields
  }
}

// MARK: - Generation-bound typed native start outcome

/// The four native v3 start verdicts a runner may report after the Packet
/// Tunnel extension has written a generation-bound proof document.
///
/// `ordinary_connectivity` is the only verdict that may authorize a winn/1
/// fallback. Every other terminal result is fail-closed: a security refusal,
/// an unknown post-create failure, or a proven connected session.
enum WinsWinn3NativeStartOutcome: String, Equatable {
  case ordinaryConnectivity = "ordinary_connectivity"
  case terminalSecurity = "terminal_security"
  case unknownTerminal = "unknown_terminal"
  case connected = "connected"

  static let fieldKey = "winn3_start_outcome"
  static let ordinaryNetworkEvidenceKey = "winn3_ordinary_network_unreachability"
  static let ordinaryNetworkPosixErrnoKey = "winn3_ordinary_network_posix_errno"

  /// Darwin ENETDOWN / ENETUNREACH / EHOSTDOWN / EHOSTUNREACH. These are the
  /// only POSIX codes this host treats as positive ordinary unreachability.
  static let ordinaryNetworkPosixErrnos: Set<Int> = [50, 51, 64, 65]

  var authorizesV1Fallback: Bool {
    self == .ordinaryConnectivity
  }

  /// MethodChannel `startTunnel` may return `true` only for a proven session
  /// or for a positively ordinary network failure. Terminal security and
  /// unknown failures must throw so Dart cannot treat them as an accepted
  /// native start.
  var reportsNativeStartAccepted: Bool {
    self == .connected || self == .ordinaryConnectivity
  }

  var flutterErrorCode: String {
    switch self {
    case .terminalSecurity:
      return "APPLE_WINN3_TERMINAL_SECURITY"
    case .unknownTerminal:
      return "APPLE_WINN3_UNKNOWN_TERMINAL"
    case .ordinaryConnectivity, .connected:
      return ""
    }
  }
}

/// One observation of the cross-process status file for a single start
/// generation. Stale or in-flight documents keep the runner waiting rather
/// than minting a fallback-authorizing verdict.
enum WinsWinn3NativeStartObservation: Equatable {
  case waiting
  case canceled
  case finished(WinsWinn3NativeStartOutcome)
}

enum WinsWinn3NativeStartClassifier {
  static let proofWaitMilliseconds = 28_000
  static let proofPollMilliseconds = 250

  static let terminalSecurityCodes: Set<Int> = [
    1101, 1102, 1104, 1105, 1106,
    1202, 1203,
    1302, 1303, 1304, 1305, 1306, 1308, 1309, 1310,
    1502, 1503, 1504, 1505, 1506,
    1030, 1038, 1040, 1042, 1023, 1026, 1033, 1039
  ]

  static let engineDeathCodes: Set<Int> = [1022, 1036]
  static let proofTimeoutCodes: Set<Int> = [1020, 1037]
  static let canceledCode = 1013

  static let allClassifiedFailureCodes: [Int] = {
    var codes = Set<Int>()
    codes.formUnion(terminalSecurityCodes)
    codes.formUnion(engineDeathCodes)
    codes.formUnion(proofTimeoutCodes)
    codes.formUnion([
      1001, 1002, 1004, 1005, 1006, 1007, 1008, 1010, 1012, 1014, 1015, 1016,
      1017, 1018, 1019, 1021, 1024, 1031, 1032, 1034, 1035
    ])
    return codes.sorted()
  }()

  static func annotatedExtra(
    expectedGeneration: String,
    stage: String,
    engineReady: Bool,
    networkSettingsReady: Bool,
    error: Error?,
    extra: [String: Any]
  ) -> [String: Any] {
    var fields = extra
    var status = extra
    status["stage"] = stage
    status["engine_ready"] = engineReady
    status["network_settings_ready"] = networkSettingsReady
    status["status_generation"] = expectedGeneration
    status["status_schema_version"] = WinsPacketTunnelProviderStatus.schemaVersion
    if let error {
      let nsError = error as NSError
      status["error_domain"] = nsError.domain
      status["error_code"] = nsError.code
    }
    switch observe(
      expectedGeneration: expectedGeneration,
      status: status
    ) {
    case .finished(let outcome):
      fields[WinsWinn3NativeStartOutcome.fieldKey] = outcome.rawValue
    case .waiting, .canceled:
      break
    }
    return fields
  }

  static func observe(
    expectedGeneration: String,
    status: [String: Any]?,
    atDeadline: Bool = false
  ) -> WinsWinn3NativeStartObservation {
    let expected = WinsPacketTunnelProviderStatus.safeStatusGeneration(expectedGeneration)
    if expected.isEmpty {
      return .finished(.unknownTerminal)
    }
    guard let status else {
      return atDeadline ? .finished(.unknownTerminal) : .waiting
    }

    let merged = flattenExtra(status)
    let rawGeneration = stringValue(merged["status_generation"])
    let reportedGeneration = WinsPacketTunnelProviderStatus.safeStatusGeneration(rawGeneration)
    if !rawGeneration.isEmpty && reportedGeneration.isEmpty {
      return .finished(.unknownTerminal)
    }
    if reportedGeneration != expected {
      return atDeadline ? .finished(.unknownTerminal) : .waiting
    }

    if boolValue(merged["start_canceled"]) || intValue(merged["error_code"]) == canceledCode {
      return .canceled
    }

    let stage = stringValue(merged["stage"])
    if stage.isEmpty || !WinsPacketTunnelProviderStatus.validStage(stage) {
      return .finished(.unknownTerminal)
    }
    let schema = intValue(merged["status_schema_version"])
    if let schema, schema != WinsPacketTunnelProviderStatus.schemaVersion {
      return .finished(.unknownTerminal)
    }

    if isConnectedProof(stage: stage, status: merged) {
      return .finished(.connected)
    }

    if isInFlightProof(stage: stage, status: merged) {
      return atDeadline ? .finished(classifyTerminalFailure(status: merged)) : .waiting
    }

    return .finished(classifyTerminalFailure(status: merged))
  }

  static func waitForProof(
    expectedGeneration: String,
    isCurrent: () -> Bool,
    readStatus: () -> [String: Any]?,
    sleep: (TimeInterval) -> Void,
    now: () -> Date,
    deadline: Date,
    pollInterval: TimeInterval = TimeInterval(proofPollMilliseconds) / 1000.0
  ) -> WinsWinn3NativeStartObservation {
    while now() < deadline {
      guard isCurrent() else { return .canceled }
      let observation = observe(
        expectedGeneration: expectedGeneration,
        status: readStatus()
      )
      switch observation {
      case .waiting:
        sleep(pollInterval)
      case .canceled, .finished:
        return observation
      }
    }
    guard isCurrent() else { return .canceled }
    let timedOut = observe(
      expectedGeneration: expectedGeneration,
      status: readStatus(),
      atDeadline: true
    )
    if case .waiting = timedOut {
      return .finished(.unknownTerminal)
    }
    return timedOut
  }

  static func classifyFailureCode(
    _ code: Int,
    stage: String? = nil,
    status: [String: Any] = [:]
  ) -> WinsWinn3NativeStartOutcome {
    var fields = status
    fields["error_code"] = code
    if let stage, !stage.isEmpty {
      fields["stage"] = stage
    }
    return classifyTerminalFailure(status: fields)
  }

  private static func isConnectedProof(stage: String, status: [String: Any]) -> Bool {
    guard stage == "engine_started" else { return false }
    guard boolValue(status["engine_ready"]) else { return false }
    guard boolValue(status["network_settings_ready"]) else { return false }
    if status["error_code"] != nil { return false }
    if boolValue(status["start_canceled"]) { return false }
    return true
  }

  private static func isInFlightProof(stage: String, status: [String: Any]) -> Bool {
    if status["error_code"] != nil { return false }
    switch stage {
    case "config_saved", "app_message", "sleeping", "woke":
      return true
    case "engine_started":
      return !boolValue(status["network_settings_ready"]) || !boolValue(status["engine_ready"])
    default:
      return false
    }
  }

  private static func classifyTerminalFailure(status: [String: Any]) -> WinsWinn3NativeStartOutcome {
    let stage = stringValue(status["stage"])
    let code = intValue(status["error_code"])

    if hasSecurityIndicator(stage: stage, code: code, status: status) {
      return .terminalSecurity
    }
    if let code, proofTimeoutCodes.contains(code) || boolValue(status["winn_datapath_proof_timeout"]) {
      return .unknownTerminal
    }
    if let code, engineDeathCodes.contains(code) || boolValue(status["winn_datapath_proof_engine_exited"]) {
      return .unknownTerminal
    }
    if hasOrdinaryNetworkEvidence(status: status, code: code) {
      return .ordinaryConnectivity
    }
    if stage == "engine_start_failed" || stage == "engine_missing" || stage == "network_settings_failed"
      || stage == "stopped" {
      return .unknownTerminal
    }
    return .unknownTerminal
  }

  private static func hasSecurityIndicator(stage: String, code: Int?, status: [String: Any]) -> Bool {
    if stage == "start_rejected" { return true }
    if let code, terminalSecurityCodes.contains(code) { return true }
    if boolValue(status["persisted_live_secret_material_refused"]) { return true }
    if status["winn3_descriptor_node_bound"] as? Bool == false { return true }
    let refusal = stringValue(status["winn3_datapath_proof_start_refusal_reason"]).lowercased()
    if !refusal.isEmpty { return true }
    if status["client_key_pair_verified"] as? Bool == false
      && boolValue(status["client_key_pair_verification_required"]) {
      return true
    }
    return false
  }

  private static func hasOrdinaryNetworkEvidence(status: [String: Any], code: Int?) -> Bool {
    if let errno = intValue(status[WinsWinn3NativeStartOutcome.ordinaryNetworkPosixErrnoKey]),
       WinsWinn3NativeStartOutcome.ordinaryNetworkPosixErrnos.contains(errno) {
      return true
    }
    let domain = stringValue(status["error_domain"])
    if domain == NSPOSIXErrorDomain,
       let code,
       WinsWinn3NativeStartOutcome.ordinaryNetworkPosixErrnos.contains(code) {
      return true
    }
    return false
  }

  private static func flattenExtra(_ status: [String: Any]) -> [String: Any] {
    guard let extra = status["extra"] as? [String: Any] else {
      return status
    }
    var merged = extra
    merged.merge(status) { _, new in new }
    merged.removeValue(forKey: "extra")
    return merged
  }

  private static func stringValue(_ value: Any?) -> String {
    (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
  }

  private static func boolValue(_ value: Any?) -> Bool {
    if let bool = value as? Bool { return bool }
    if let number = value as? NSNumber { return number.boolValue }
    return false
  }

  /// An integer from a Flutter channel argument or a JSONSerialization map.
  /// Both deliver NSNumber, and Swift lets an NSNumber holding 0 or 1 cast to
  /// Bool, so a leading `value is Bool` test turns a real 1 into nil. A true
  /// boolean is recognised by its CFBoolean type instead.
  private static func intValue(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          !CFNumberIsFloatType(number) else {
      return nil
    }
    return number.intValue
  }
}

/// Fields Dart's `nativeWinn3ReadinessVerdict` actually reads. The Packet
/// Tunnel status file stores `winn3_start_outcome`; the runner must also echo
/// the Dart-issued integer generation and the typed `winn3_verdict` string or
/// a successful promotion and ordinary-connectivity cover both fail closed.
enum WinsWinn3NativeStartReadiness {
  static let verdictKey = "winn3_verdict"
  static let dartGenerationKey = "winn3_start_generation"
  static let dartGenerationArgumentKey = "winn3StartGeneration"
  static let dartTokenArgumentKey = "winn3StartToken"
  static let dartTokenKey = "winn3_start_token"
  static let dartSelectionArgumentKey = "winn3SelectionGeneration"
  static let dartSelectionKey = "winn3_selection_generation"
  static let dartFailedNodeArgumentKey = "winn3FailedNode"
  static let dartFailedNodeKey = "winn3_failed_node"
  static let authorizationTokenKey = "winn3_awg_xray_authorization_token"
  static let pendingVerdict = "pending"

  struct DartIdentities {
    var startToken: Int?
    var startGeneration: Int?
    var selectionGeneration: String?
    var failedNode: String?
  }

  static func dartStartGeneration(from arguments: Any?) -> Int? {
    dartIdentities(from: arguments).startGeneration
  }

  static func dartIdentities(from arguments: Any?) -> DartIdentities {
    guard let args = arguments as? [String: Any] else { return DartIdentities() }
    return DartIdentities(
      startToken: positiveInteger(args[dartTokenArgumentKey]),
      startGeneration: positiveInteger(args[dartGenerationArgumentKey]),
      selectionGeneration: exactSelectionGeneration(args[dartSelectionArgumentKey]),
      failedNode: exactNodeSlug(args[dartFailedNodeArgumentKey])
    )
  }

  static func fields(
    dartStartGeneration: Int?,
    expectedStatusGeneration: String,
    status: [String: Any]?,
    dartStartToken: Int? = nil,
    selectionGeneration: String? = nil,
    failedNode: String? = nil
  ) -> [String: Any] {
    guard dartStartGeneration != nil || !expectedStatusGeneration.isEmpty else {
      return [:]
    }
    var fields: [String: Any] = [:]
    if let dartStartGeneration {
      fields[dartGenerationKey] = dartStartGeneration
    }
    if let dartStartToken, dartStartToken > 0 {
      fields[dartTokenKey] = dartStartToken
    }
    if let selectionGeneration, !selectionGeneration.isEmpty {
      fields[dartSelectionKey] = selectionGeneration
    }
    if let failedNode, !failedNode.isEmpty {
      fields[dartFailedNodeKey] = failedNode
    }
    switch WinsWinn3NativeStartClassifier.observe(
      expectedGeneration: expectedStatusGeneration,
      status: status
    ) {
    case .waiting:
      if dartStartGeneration != nil {
        fields[verdictKey] = pendingVerdict
      }
    case .canceled:
      break
    case .finished(let outcome):
      fields[verdictKey] = outcome.rawValue
      if outcome == .ordinaryConnectivity,
         let dartStartToken,
         dartStartToken > 0 {
        fields[authorizationTokenKey] = dartStartToken
      }
    }
    return fields
  }

  private static func exactSelectionGeneration(_ value: Any?) -> String? {
    guard let text = value as? String else { return nil }
    guard text.count >= 8, text.count <= 64 else { return nil }
    guard let first = text.unicodeScalars.first,
          CharacterSet.alphanumerics.contains(first) else { return nil }
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._:-"))
    guard text.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
    return text
  }

  private static func exactNodeSlug(_ value: Any?) -> String? {
    guard let text = (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
          !text.isEmpty,
          text.lowercased() != "auto" else { return nil }
    return text
  }

  private static func positiveInteger(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          !CFNumberIsFloatType(number) else {
      return nil
    }
    let exact = number.intValue
    return exact > 0 ? exact : nil
  }
}

enum WinsWinn3CoverLeg: String {
  case awg
  case xray
}

enum WinsWinn3AwgXrayGrantStore {
  private static let lock = NSLock()
  private static var grant: Grant?
  private static let ttlMs: Int64 = 60_000

  private struct Grant {
    var startToken: Int
    var startGeneration: Int
    var selectionGeneration: String
    var failedV3Node: String
    var exactV1Target: String
    var issuedMonotonicMs: Int64
    var nextLeg: WinsWinn3CoverLeg
    var targetBound: Bool
  }

  static func clear() {
    lock.lock()
    grant = nil
    lock.unlock()
  }

  static func arm(
    startToken: Int,
    startGeneration: Int,
    selectionGeneration: String,
    failedV3Node: String,
    nowMs: Int64
  ) -> Bool {
    guard startToken > 0, startGeneration > 0, nowMs > 0 else { return false }
    guard (8...64).contains(selectionGeneration.count) else { return false }
    let failed = failedV3Node.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !failed.isEmpty, failed.lowercased() != "auto" else { return false }
    lock.lock()
    grant = Grant(
      startToken: startToken,
      startGeneration: startGeneration,
      selectionGeneration: selectionGeneration,
      failedV3Node: failed,
      exactV1Target: "",
      issuedMonotonicMs: nowMs,
      nextLeg: .awg,
      targetBound: false
    )
    lock.unlock()
    return true
  }

  static func consume(
    startToken: Int,
    startGeneration: Int,
    selectionGeneration: String,
    failedV3Node: String,
    exactV1Target: String,
    requestedLeg: WinsWinn3CoverLeg,
    nowMs: Int64
  ) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard var current = grant else { return false }
    if current.startToken <= 0 || current.issuedMonotonicMs <= 0 ||
        nowMs < current.issuedMonotonicMs ||
        nowMs - current.issuedMonotonicMs > ttlMs {
      grant = nil
      return false
    }
    let target = exactV1Target.trimmingCharacters(in: .whitespacesAndNewlines)
    if startToken != current.startToken ||
        startGeneration != current.startGeneration ||
        selectionGeneration != current.selectionGeneration ||
        failedV3Node != current.failedV3Node ||
        target.isEmpty || target.lowercased() == "auto" {
      grant = nil
      return false
    }
    if current.targetBound && target != current.exactV1Target {
      grant = nil
      return false
    }
    if requestedLeg != current.nextLeg {
      grant = nil
      return false
    }
    if requestedLeg == .awg {
      current.exactV1Target = target
      current.nextLeg = .xray
      current.targetBound = true
      grant = current
    } else {
      grant = nil
    }
    return true
  }
}

/// Contract checks for the typed native start outcome. Invoked by the Apple
/// host harness and by iOS/macOS RunnerTests so a missing failure-code case
/// cannot be green on only one surface.
enum WinsWinn3NativeStartOutcomeContract {
  static let currentGeneration = "generation-current"
  static let staleGeneration = "generation-stale"

  static func failures() -> [String] {
    var failures: [String] = []
    if WinsWinn3NativeStartReadiness.dartStartGeneration(
      from: [WinsWinn3NativeStartReadiness.dartGenerationArgumentKey: true]
    ) != nil {
      failures.append("boolean Dart generation must be rejected")
    }
    if WinsWinn3NativeStartReadiness.dartStartGeneration(
      from: [WinsWinn3NativeStartReadiness.dartGenerationArgumentKey: 7.5]
    ) != nil {
      failures.append("fractional Dart generation must be rejected")
    }
    if WinsWinn3NativeStartReadiness.dartStartGeneration(
      from: [WinsWinn3NativeStartReadiness.dartGenerationArgumentKey: "7"]
    ) != nil {
      failures.append("string Dart generation must be rejected")
    }
    func expect(
      _ observation: WinsWinn3NativeStartObservation,
      _ expected: WinsWinn3NativeStartObservation,
      _ label: String
    ) {
      if observation != expected {
        failures.append("\(label): got \(String(describing: observation)), expected \(String(describing: expected))")
      }
    }

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: connectedStatus()
      ),
      .finished(.connected),
      "successful promotion is connected"
    )
    if WinsWinn3NativeStartOutcome.connected.authorizesV1Fallback {
      failures.append("connected must not authorize v1")
    }
    if !WinsWinn3NativeStartOutcome.connected.reportsNativeStartAccepted {
      failures.append("connected must report native start accepted")
    }

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: provingStatus()
      ),
      .waiting,
      "in-flight proof must not report success"
    )

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: connectedStatus(generation: staleGeneration)
      ),
      .waiting,
      "cross-process stale connected status must not prove the current start"
    )
    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: connectedStatus(generation: staleGeneration),
        atDeadline: true
      ),
      .finished(.unknownTerminal),
      "stale connected status at the proof deadline is unknown_terminal"
    )

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: status(
          stage: "engine_start_failed",
          errorCode: 1013,
          extra: ["start_canceled": true]
        )
      ),
      .canceled,
      "cancellation is preserved"
    )

    let ordinary = status(
      stage: "engine_start_failed",
      extra: [
        "error_domain": NSPOSIXErrorDomain,
        "error_code": 51
      ]
    )
    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: ordinary
      ),
      .finished(.ordinaryConnectivity),
      "POSIX ENETUNREACH is ordinary network evidence"
    )
    if !WinsWinn3NativeStartOutcome.ordinaryConnectivity.authorizesV1Fallback {
      failures.append("ordinary_connectivity must be the only v1-authorizing verdict")
    }

    let posixOrdinary = status(
      stage: "engine_start_failed",
      extra: [
        "error_domain": NSPOSIXErrorDomain,
        "error_code": 51
      ]
    )
    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: posixOrdinary
      ),
      .finished(.ordinaryConnectivity),
      "POSIX ENETUNREACH is ordinary network evidence"
    )

    for code in [1036, 1037, 1022, 1020] {
      let observed = WinsWinn3NativeStartClassifier.classifyFailureCode(
        code,
        stage: "engine_start_failed",
        status: ["winn_datapath_proof_timeout": code == 1037 || code == 1020]
      )
      if observed != .unknownTerminal {
        failures.append("proof timeout/engine death \(code) must be unknown_terminal, got \(observed.rawValue)")
      }
      if observed.authorizesV1Fallback {
        failures.append("proof timeout/engine death \(code) must not authorize v1")
      }
    }

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: status(stage: "engine_start_failed", errorCode: 1031)
      ),
      .finished(.unknownTerminal),
      "engine_start_failed without ordinary evidence is unknown_terminal"
    )

    for code in [1101, 1105, 1030, 1038, 1040, 1042] {
      let observed = WinsWinn3NativeStartClassifier.classifyFailureCode(
        code,
        stage: "start_rejected"
      )
      if observed != .terminalSecurity {
        failures.append("credential/pin/admission/replay \(code) must be terminal_security, got \(observed.rawValue)")
      }
      if observed.authorizesV1Fallback {
        failures.append("credential/pin/admission/replay \(code) must not authorize v1")
      }
    }

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: status(
          stage: "start_rejected",
          extra: ["winn3_datapath_proof_start_refusal_reason": "admission_key is absent"]
        )
      ),
      .finished(.terminalSecurity),
      "admission refusal is terminal_security"
    )
    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: status(
          stage: "start_rejected",
          errorCode: 1042,
          extra: ["persisted_live_secret_material_refused": true]
        )
      ),
      .finished(.terminalSecurity),
      "replay of persisted secrets is terminal_security"
    )

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: status(stage: "not-a-stage", errorCode: 1037)
      ),
      .finished(.unknownTerminal),
      "malformed stage is unknown_terminal"
    )
    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: nil,
        atDeadline: true
      ),
      .finished(.unknownTerminal),
      "missing status at deadline is unknown_terminal"
    )

    for code in WinsWinn3NativeStartClassifier.allClassifiedFailureCodes {
      let outcome = WinsWinn3NativeStartClassifier.classifyFailureCode(
        code,
        stage: WinsWinn3NativeStartClassifier.terminalSecurityCodes.contains(code)
          ? "start_rejected"
          : "engine_start_failed"
      )
      if outcome.authorizesV1Fallback {
        failures.append("failure code \(code) classified \(outcome.rawValue) and must not authorize v1")
      }
      if outcome == .connected {
        failures.append("failure code \(code) must never classify as connected")
      }
    }

    let annotated = WinsWinn3NativeStartClassifier.annotatedExtra(
      expectedGeneration: currentGeneration,
      stage: "engine_start_failed",
      engineReady: false,
      networkSettingsReady: false,
      error: NSError(domain: "org.winsvpn.PacketTunnel", code: 1036, userInfo: nil),
      extra: ["status_generation": currentGeneration]
    )
    if annotated[WinsWinn3NativeStartOutcome.fieldKey] as? String
      != WinsWinn3NativeStartOutcome.unknownTerminal.rawValue {
      failures.append("1036 annotation must write unknown_terminal")
    }

    let promoted = WinsWinn3NativeStartClassifier.annotatedExtra(
      expectedGeneration: currentGeneration,
      stage: "engine_started",
      engineReady: true,
      networkSettingsReady: true,
      error: nil,
      extra: [
        "status_generation": currentGeneration,
        "winn3_datapath_proof_promoted": true
      ]
    )
    if promoted[WinsWinn3NativeStartOutcome.fieldKey] as? String
      != WinsWinn3NativeStartOutcome.connected.rawValue {
      failures.append("promoted annotation must write connected")
    }

    var staleReads = 0
    let waitResult = WinsWinn3NativeStartClassifier.waitForProof(
      expectedGeneration: currentGeneration,
      isCurrent: { true },
      readStatus: {
        staleReads += 1
        return connectedStatus(generation: staleGeneration)
      },
      sleep: { _ in },
      now: { staleReads > 2 ? Date().addingTimeInterval(1) : Date() },
      deadline: Date(),
      pollInterval: 0
    )
    expect(
      waitResult,
      .finished(.unknownTerminal),
      "waitForProof must not promote a stale cross-process connected document"
    )

    var canceled = false
    let canceledWait = WinsWinn3NativeStartClassifier.waitForProof(
      expectedGeneration: currentGeneration,
      isCurrent: {
        canceled = true
        return false
      },
      readStatus: { provingStatus() },
      sleep: { _ in },
      now: { Date() },
      deadline: Date().addingTimeInterval(1),
      pollInterval: 0
    )
    expect(canceledWait, .canceled, "waitForProof preserves cancellation")
    if !canceled {
      failures.append("waitForProof must consult the operation gate")
    }

    expect(
      WinsWinn3NativeStartClassifier.observe(
        expectedGeneration: currentGeneration,
        status: [
          "status_schema_version": WinsPacketTunnelProviderStatus.schemaVersion,
          "status_generation": currentGeneration,
          "stage": "engine_start_failed",
          "engine_ready": false,
          "network_settings_ready": false,
          "extra": [
            WinsWinn3NativeStartOutcome.ordinaryNetworkPosixErrnoKey: 51
          ]
        ]
      ),
      .finished(.ordinaryConnectivity),
      "nested extra POSIX errno is still ordinary_connectivity"
    )

    if WinsWinn3NativeStartReadiness.dartIdentities(
      from: ["winn3StartToken": true]
    ).startToken != nil {
      failures.append("boolean Dart start token must be rejected")
    }
    if WinsWinn3NativeStartReadiness.dartIdentities(
      from: ["winn3StartToken": 1.5]
    ).startToken != nil {
      failures.append("fractional Dart start token must be rejected")
    }
    if WinsWinn3NativeStartReadiness.dartIdentities(
      from: ["winn3StartToken": "9"]
    ).startToken != nil {
      failures.append("string Dart start token must be rejected")
    }

    let timeoutUnknown = WinsWinn3NativeStartClassifier.observe(
      expectedGeneration: currentGeneration,
      status: status(
        stage: "engine_start_failed",
        errorCode: 1037,
        extra: [
          "winn_datapath_proof_timeout": true,
          WinsWinn3NativeStartOutcome.ordinaryNetworkPosixErrnoKey: 51
        ]
      )
    )
    if timeoutUnknown != .finished(.unknownTerminal) {
      failures.append("proof timeout must be unknown_terminal even with POSIX errno")
    }

    let ordinaryReadinessWithToken = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: 42,
      expectedStatusGeneration: currentGeneration,
      status: ordinary,
      dartStartToken: 99
    )
    if ordinaryReadinessWithToken[WinsWinn3NativeStartReadiness.authorizationTokenKey] as? Int
      != 99 {
      failures.append("ordinary readiness must publish the matching authorization token")
    }
    let unknownReadinessNoToken = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: 42,
      expectedStatusGeneration: currentGeneration,
      status: status(stage: "engine_start_failed", errorCode: 1031),
      dartStartToken: 99
    )
    if unknownReadinessNoToken[WinsWinn3NativeStartReadiness.authorizationTokenKey] != nil {
      failures.append("unknown_terminal must not publish an authorization token")
    }

    WinsWinn3AwgXrayGrantStore.clear()
    if !WinsWinn3AwgXrayGrantStore.arm(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      nowMs: 1_000
    ) {
      failures.append("ordinary identities must arm a one-use grant")
    }
    if WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .xray,
      nowMs: 1_001
    ) {
      failures.append("Xray cannot consume before AWG")
    }
    _ = WinsWinn3AwgXrayGrantStore.arm(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      nowMs: 1_000
    )
    if !WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .awg,
      nowMs: 1_001
    ) {
      failures.append("first consume must be AWG")
    }
    if WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "other-node",
      requestedLeg: .xray,
      nowMs: 1_002
    ) {
      failures.append("Xray against a different node must be refused")
    }
    _ = WinsWinn3AwgXrayGrantStore.arm(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      nowMs: 1_000
    )
    if WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .awg,
      nowMs: 1_000 + 60_001
    ) {
      failures.append("grant must expire at 60s monotonic")
    }
    _ = WinsWinn3AwgXrayGrantStore.arm(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      nowMs: 1_000
    )
    if !WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .awg,
      nowMs: 1_010
    ) || !WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .xray,
      nowMs: 1_011
    ) {
      failures.append("AWG then Xray must consume the one-use grant")
    }
    if WinsWinn3AwgXrayGrantStore.consume(
      startToken: 9,
      startGeneration: 3,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .xray,
      nowMs: 1_012
    ) {
      failures.append("completed grant must not be reusable")
    }

    let dartGeneration = 42
    if WinsWinn3NativeStartReadiness.dartStartGeneration(
      from: ["winn3StartGeneration": dartGeneration]
    ) != dartGeneration {
      failures.append("runner must parse Dart winn3StartGeneration")
    }

    let ordinaryReadiness = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: dartGeneration,
      expectedStatusGeneration: currentGeneration,
      status: ordinary
    )
    if ordinaryReadiness[WinsWinn3NativeStartReadiness.dartGenerationKey] as? Int
      != dartGeneration {
      failures.append("readiness must echo the Dart start generation")
    }
    if ordinaryReadiness[WinsWinn3NativeStartReadiness.verdictKey] as? String
      != WinsWinn3NativeStartOutcome.ordinaryConnectivity.rawValue {
      failures.append("readiness must publish winn3_verdict=ordinary_connectivity")
    }

    let connectedReadiness = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: dartGeneration,
      expectedStatusGeneration: currentGeneration,
      status: connectedStatus()
    )
    if connectedReadiness[WinsWinn3NativeStartReadiness.verdictKey] as? String
      != WinsWinn3NativeStartOutcome.connected.rawValue {
      failures.append("readiness must publish winn3_verdict=connected for promotion")
    }

    let staleReadiness = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: dartGeneration,
      expectedStatusGeneration: currentGeneration,
      status: connectedStatus(generation: staleGeneration)
    )
    if staleReadiness[WinsWinn3NativeStartReadiness.verdictKey] as? String
      != WinsWinn3NativeStartReadiness.pendingVerdict {
      failures.append("stale cross-process connected status must stay pending, not connected")
    }

    let unknownReadiness = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: dartGeneration,
      expectedStatusGeneration: currentGeneration,
      status: status(stage: "engine_start_failed", errorCode: 1036)
    )
    if unknownReadiness[WinsWinn3NativeStartReadiness.verdictKey] as? String
      != WinsWinn3NativeStartOutcome.unknownTerminal.rawValue {
      failures.append("engine death readiness must publish unknown_terminal")
    }
    if unknownReadiness[WinsWinn3NativeStartReadiness.verdictKey] as? String
      == WinsWinn3NativeStartOutcome.ordinaryConnectivity.rawValue {
      failures.append("engine death must not publish ordinary_connectivity")
    }

    let idleReadiness = WinsWinn3NativeStartReadiness.fields(
      dartStartGeneration: nil,
      expectedStatusGeneration: "",
      status: connectedStatus()
    )
    if !idleReadiness.isEmpty {
      failures.append("v1 readiness must not publish a v3 start verdict")
    }

    return failures
  }

  private static func status(
    generation: String = currentGeneration,
    stage: String,
    engineReady: Bool = false,
    networkSettingsReady: Bool = false,
    errorCode: Int? = nil,
    extra: [String: Any] = [:]
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "status_schema_version": WinsPacketTunnelProviderStatus.schemaVersion,
      "status_generation": generation,
      "stage": stage,
      "engine_ready": engineReady,
      "network_settings_ready": networkSettingsReady
    ]
    if let errorCode {
      fields["error_code"] = errorCode
    }
    fields.merge(extra) { _, new in new }
    return fields
  }

  private static func connectedStatus(generation: String = currentGeneration) -> [String: Any] {
    status(
      generation: generation,
      stage: "engine_started",
      engineReady: true,
      networkSettingsReady: true,
      extra: ["winn3_datapath_proof_promoted": true]
    )
  }

  private static func provingStatus() -> [String: Any] {
    status(
      stage: "engine_started",
      engineReady: true,
      networkSettingsReady: false
    )
  }
}
