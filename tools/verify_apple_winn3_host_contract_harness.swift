import Darwin
import Foundation
import NetworkExtension

// verify_apple_winn3_host_contract_harness.swift
//
// The Apple half of §4 of docs/handoff/WINN3_TUN_LAYER_20260808.md, exercised
// against the REAL Go archive in one process.
//
// It starts no tunnel and installs no network settings. Exactly one create
// succeeds, and its carrier socket is connected to a listener in this same
// process on 127.0.0.1, so nothing this file does leaves the machine.

// MARK: - the C ABI, resolved the way the appex resolves it

typealias WinnCreateWinn3Fn = @convention(c) (
  UnsafeMutablePointer<CChar>?, Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int64
typealias WinnStatusJSONFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
typealias WinnCloseFn = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
typealias WinnFreeStringFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

/// dlsym against the process itself. The appex links no Go archive at build
/// time — every engine symbol is resolved by name at run time — so a harness
/// that used a header declaration would prove something the shipping build
/// does not do.
func winn3Symbol<T>(_ name: String, as type: T.Type) -> T? {
  guard let handle = dlopen(nil, RTLD_NOW | RTLD_LOCAL) else { return nil }
  defer { dlclose(handle) }
  guard let pointer = dlsym(handle, name) else { return nil }
  return unsafeBitCast(pointer, to: type)
}

// MARK: - check plumbing

var passed = 0
var failures: [String] = []

func check(_ condition: Bool, _ label: String) {
  if condition {
    passed += 1
    print("  ok  \(label)")
  } else {
    failures.append(label)
    print("  NOT OK  \(label)")
  }
}

func section(_ title: String) {
  print("\n[\(title)]")
}

/// True when `block` threw. Used instead of `(try? …) == nil`, which does not
/// compile for a Void-returning throwing call.
func refuses(_ block: () throws -> Void) -> Bool {
  do {
    try block()
    return false
  } catch {
    return true
  }
}

// MARK: - fixtures

/// Any 32 bytes are a valid X25519 scalar for the Go side and nothing here is a
/// real subscriber key. Distinct constants make a mix-up visible.
let localStatic = Data(repeating: 0x11, count: 32).base64EncodedString()
let gatewayStatic = Data(repeating: 0x22, count: 32).base64EncodedString()
/// The operator's own gateway name -- byte for byte what `cmd/winn3-gateway`
/// is started with in `-gateway-id`, and what the ENGINE is handed.
let gatewayIDText = "wins-lab-gateway"
/// The same value as the signed descriptor transports it: base64. This is what
/// `[winn] gateway_id` carries, and the host decodes it exactly once.
let gatewayID = Data(gatewayIDText.utf8).base64EncodedString()
let admissionKey = Data(repeating: 0x33, count: 32).base64EncodedString()
// Deterministic public test material: the base64 encoding of bytes 0...31.
// Structurally valid for the parser, which rejects redaction sentinels.
let wgKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func baseDocument(gatewayEndpoint: String = "192.0.2.9:51820") -> [String: Any] {
  [
    "contract": WinsWinn3.contract,
    "payload": WinsWinn3.payloadClass,
    "carrier": WinsWinn3.carrierName,
    "gateway_endpoint": gatewayEndpoint,
    "static_private": localStatic,
    "gateway_static": gatewayStatic,
    // RAW TEXT, not base64. The archive takes this field verbatim, because the
    // gateway computes its admission tag over the same raw bytes and never
    // tells the client when the two disagree.
    "gateway_id": gatewayIDText,
    "admission_key": admissionKey,
    "inner_v4": "10.13.0.2",
    "inner_router_v4": "10.13.0.1",
    "path_mtu": 1450,
    "carrier_classes": ["udp", "tls"],
    "allow_own_socket": false,
    "session_id": "winn3-host-contract"
  ]
}

func documentWith(_ overrides: [String: Any]) -> [String: Any] {
  baseDocument().merging(overrides) { _, new in new }
}

/// Calls the real create with NO descriptor and returns the refusal message, or
/// nil if it unexpectedly succeeded. Never opens a socket: every document here
/// either fails validation or fails the allow_own_socket rule.
func createRefusal(_ document: [String: Any]) -> String? {
  guard let create = winn3Symbol(WinsWinn3.createSymbol, as: WinnCreateWinn3Fn.self) else {
    return "SYMBOL MISSING"
  }
  guard let data = try? JSONSerialization.data(withJSONObject: document),
        let json = String(data: data, encoding: .utf8) else {
    return "DOCUMENT NOT ENCODABLE"
  }
  var errorOut: UnsafeMutablePointer<CChar>?
  let handle = json.withCString { pointer -> Int64 in
    let mutable = strdup(pointer)
    defer { free(mutable) }
    return create(mutable, -1, &errorOut)
  }
  if handle > 0 {
    if let close = winn3Symbol("WinnTunnelClose", as: WinnCloseFn.self) {
      _ = close(handle)
    }
    return nil
  }
  guard let errorOut else { return "REFUSED WITH NO MESSAGE" }
  let message = String(cString: errorOut)
  if let freeString = winn3Symbol("WinnTunnelFreeString", as: WinnFreeStringFn.self) {
    freeString(errorOut)
  }
  return message
}

// MARK: - 1. the names agree with the archive

func runNameTests() {
  section("names: the Swift constants and the Go archive")

  check(
    winn3Symbol(WinsWinn3.createSymbol, as: WinnCreateWinn3Fn.self) != nil,
    "\(WinsWinn3.createSymbol) is present in the archive and resolvable by dlsym"
  )
  check(
    WinsWinn3.carrierName == WinsTunnelConfig.supportedWinnCarrierWinn3,
    "WinsWinn3.carrierName and WinsTunnelConfig.supportedWinnCarrierWinn3 are the same string"
  )
  check(
    WinsWinn3.contract != "winn-datapath/1",
    "the standalone contract is NOT the relay contract; equal strings would mean a relay archive can carry inner IP"
  )
  check(
    createRefusal(documentWith(["contract": "winn-datapath/1"]))?.contains("contract") == true,
    "the archive refuses the RELAY contract string on the standalone entry point"
  )
  check(
    createRefusal(baseDocument())?.contains("contract") == false,
    "the archive accepts WinsWinn3.contract as its own: it refuses later, for the socket, not the contract"
  )
}

// MARK: - 2. the create refusals

func runCreateRefusalTests() {
  section("create: every refusal that keeps cleartext off the wire")

  check(
    createRefusal(documentWith(["payload": "awg-datagram"]))?.contains("payload") == true,
    "an awg-datagram payload is refused: that boundary belongs to the relay entry point"
  )
  for carrier in ["direct-awg", "http3-connect-udp", "http2-stream", ""] {
    check(
      createRefusal(documentWith(["carrier": carrier])) != nil,
      "carrier \"\(carrier)\" is refused here, so the anti-downgrade check cannot be bypassed by entry point"
    )
  }
  check(
    createRefusal(documentWith(["allow_downgrade": true])) != nil,
    "an unknown field is a hard refusal, not a silent default"
  )
  check(
    createRefusal(baseDocument(gatewayEndpoint: "gateway.example:51820"))?.contains("hostname") == true,
    "a hostname endpoint is refused: resolving it would leak a lookup outside the tunnel"
  )
  check(
    createRefusal(documentWith(["gateway_id": ""]))?.contains("gateway_id") == true,
    "an absent gateway_id is refused, naming the field"
  )
  check(
    createRefusal(documentWith(["admission_key": ""]))?.contains("admission_key") == true,
    "an absent admission_key is refused, naming the field"
  )
  // The archive no longer decodes gateway_id, so an ordinary operator gateway
  // name -- which is not valid base64, because of the hyphens -- must reach the
  // engine untouched instead of being refused as malformed.
  check(
    createRefusal(documentWith(["gateway_id": "wins-sea-01"]))?.contains("gateway_id") != true,
    "a gateway id that is not base64 is NOT refused: it is an operator's gateway name, taken verbatim, exactly as cmd/winn3-gateway takes it"
  )
  // The silent half. "winsgw01" is eight characters of the base64 alphabet, so
  // a decoder accepts it and yields six unrelated bytes -- the create succeeds,
  // the tunnel reports up, and every initiation is dropped by the gateway
  // without a word. Nothing here can observe the engine's internal bytes, so
  // this asserts the create is accepted; the byte-level pin is
  // cdatapath's TestWinn3GatewayIDThatIsAlsoValidBase64IsStillTakenVerbatim.
  check(
    createRefusal(documentWith(["gateway_id": "winsgw01"]))?.contains("gateway_id") != true,
    "a gateway id that happens to be valid base64 is still accepted as a name"
  )
  check(
    createRefusal(baseDocument())?.contains("allow_own_socket") == true,
    "a create with no descriptor and allow_own_socket false is refused: a socket the archive opened is a socket nobody excluded"
  )
  check(
    createRefusal(documentWith(["inner_v6": "fd00:13::2", "path_mtu": 1280]))?.contains("IPv6") == true,
    "an inner IPv6 assignment below the v6 floor is refused rather than silently dropped"
  )
  check(
    createRefusal(documentWith(["carrier_classes": ["udp", "quic"]])) != nil,
    "a migration plan naming a class this build has no floor for is refused"
  )
}

// MARK: - 3. one real create, over loopback, and its status document

/// A UDP socket connected to a listener in THIS process. Nothing leaves the
/// machine, and the descriptor is handed to the archive, which takes ownership.
func loopbackCarrierDescriptor() -> (fd: Int32, endpoint: String, listener: Int32)? {
  let listener = socket(AF_INET, SOCK_DGRAM, 0)
  guard listener >= 0 else { return nil }
  var address = sockaddr_in()
  address.sin_family = sa_family_t(AF_INET)
  address.sin_addr.s_addr = inet_addr("127.0.0.1")
  address.sin_port = 0
  let bound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
  }
  guard bound == 0 else { close(listener); return nil }

  var actual = sockaddr_in()
  var length = socklen_t(MemoryLayout<sockaddr_in>.size)
  let named = withUnsafeMutablePointer(to: &actual) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      getsockname(listener, $0, &length)
    }
  }
  guard named == 0 else { close(listener); return nil }
  let port = UInt16(bigEndian: actual.sin_port)

  let carrier = socket(AF_INET, SOCK_DGRAM, 0)
  guard carrier >= 0 else { close(listener); return nil }
  let connected = withUnsafePointer(to: &actual) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      connect(carrier, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
  }
  guard connected == 0 else { close(carrier); close(listener); return nil }
  return (carrier, "127.0.0.1:\(port)", listener)
}

func runStatusTests() {
  section("status: the two numbers a promotion may be gated on")

  guard let create = winn3Symbol(WinsWinn3.createSymbol, as: WinnCreateWinn3Fn.self),
        let statusJSON = winn3Symbol("WinnTunnelStatusJSON", as: WinnStatusJSONFn.self),
        let closeTunnel = winn3Symbol("WinnTunnelClose", as: WinnCloseFn.self),
        let freeString = winn3Symbol("WinnTunnelFreeString", as: WinnFreeStringFn.self),
        let carrier = loopbackCarrierDescriptor() else {
    check(false, "the winn3 C ABI and a loopback carrier descriptor are both available")
    return
  }
  defer { close(carrier.listener) }

  let document = baseDocument(gatewayEndpoint: carrier.endpoint)
  guard let data = try? JSONSerialization.data(withJSONObject: document),
        let json = String(data: data, encoding: .utf8) else {
    check(false, "the loopback create document encodes")
    return
  }
  var errorOut: UnsafeMutablePointer<CChar>?
  let handle = json.withCString { pointer -> Int64 in
    let mutable = strdup(pointer)
    defer { free(mutable) }
    return create(mutable, carrier.fd, &errorOut)
  }
  if let errorOut {
    print("  (create error: \(String(cString: errorOut)))")
    freeString(errorOut)
  }
  check(handle > 0, "a create with a host-supplied descriptor succeeds and returns a handle")
  guard handle > 0 else { return }

  var fields: [String: Any] = [:]
  if let raw = statusJSON(handle) {
    let text = String(cString: raw)
    freeString(raw)
    fields = WinsWinnSeamObservabilitySample.fields(
      seamStatsJSON: nil,
      engineStatusJSON: text
    )
  }

  check(
    fields[WinsWinn3PromotionGate.gateStateKey] as? String != nil,
    "the sampler maps winn3_gate_state, a STRING field, into the engine namespace"
  )
  check(
    fields[WinsWinn3PromotionGate.gateStateKey] as? String != WinsWinn3PromotionGate.carryingState,
    "a session that has not handshaken does not report a carrying gate"
  )
  check(
    WinsWinn3PromotionGate.deliveredPacketCount(engineStatusFields: fields) == 0,
    "a session that has delivered nothing reports zero delivered packets"
  )
  check(
    !WinsWinn3PromotionGate.converged(engineStatusFields: fields),
    "the promotion predicate is FALSE for a session that has proven nothing"
  )
  check(
    fields[WinsWinn3PromotionGate.innerMTUKey] != nil,
    "the sampler maps winn3_inner_mtu, so a host can check §4.2 against the engine's own number"
  )
  check(
    (fields[WinsWinn3PromotionGate.mayCarryKey] as? Bool) == false,
    "winn3_may_carry is published as a DIAGNOSTIC and is false before the handshake"
  )
  check(
    (fields[WinsWinnSeamObservabilitySample.engineFieldPrefix + "socket_owned_by_engine"] as? Bool) == false,
    "a supplied descriptor is reported as NOT engine-owned, which is what makes the exclusion checkable"
  )

  let closeError = closeTunnel(handle)
  if let closeError {
    print("  (close error: \(String(cString: closeError)))")
    freeString(closeError)
  }
  check(closeError == nil, "close on a live winn3 handle succeeds")
  check(closeTunnel(handle) == nil, "close is idempotent: closing a retired handle is not an error")
}

// MARK: - 4. §4.1, the promotion predicate itself

func promotionFields(gate: String?, rxPackets: Int?, rxOffered: Int?) -> [String: Any] {
  var fields: [String: Any] = [:]
  if let gate { fields[WinsWinn3PromotionGate.gateStateKey] = gate }
  if let rxPackets { fields[WinsWinn3PromotionGate.rxPacketsKey] = rxPackets }
  if let rxOffered { fields[WinsWinn3PromotionGate.rxOfferedKey] = rxOffered }
  return fields
}

func runPromotionTests() {
  section("promotion: Gate.State()==StateCarrying AND Stats().RxPackets>0")

  check(
    WinsWinn3PromotionGate.converged(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 1, rxOffered: 1)
    ),
    "a carrying gate AND one delivered packet converges"
  )
  check(
    !WinsWinn3PromotionGate.converged(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 0, rxOffered: 0)
    ),
    "a carrying gate with nothing delivered does NOT converge"
  )
  check(
    !WinsWinn3PromotionGate.converged(
      engineStatusFields: promotionFields(gate: "handshaking", rxPackets: 5, rxOffered: 5)
    ),
    "delivered packets under a non-carrying gate do NOT converge"
  )
  check(
    !WinsWinn3PromotionGate.converged(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 0, rxOffered: 9)
    ),
    "ARRIVALS are not deliveries: rx_offered alone never converges, which is the error a sibling lane caught"
  )
  check(
    !WinsWinn3PromotionGate.converged(engineStatusFields: [:]),
    "an engine that cannot report has proven nothing: missing keys are false, never assumed"
  )
  for state in ["down", "handshaking", "epoch0", "rekeying", "closed"] {
    check(
      !WinsWinn3PromotionGate.converged(
        engineStatusFields: promotionFields(gate: state, rxPackets: 3, rxOffered: 3)
      ),
      "gate state \(state) does not carry, so it cannot promote"
    )
  }
  check(
    WinsWinn3PromotionGate.offeredPacketCount(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 2, rxOffered: 7)
    ) == 7,
    "the offered count is published beside the delivered count so a reader sees which one decided"
  )
  check(
    WinsWinn3PromotionGate.statusFields(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 2, rxOffered: 7)
    )["winn3_datapath_proof_converged"] as? Bool == true,
    "the gate publishes its own verdict under a prefix distinct from the relay gate's"
  )

  section("promotion: the relay predicate is untouched and is not interchangeable")

  let relayConverged: [String: Any] = [
    WinsWinnDatapathProofGate.convergenceHandshakeKey: true,
    WinsWinnDatapathProofGate.convergenceTransportKey: true
  ]
  check(
    WinsWinnDatapathProofGate.converged(engineStatusFields: relayConverged),
    "the relay predicate still converges on its own two flags"
  )
  check(
    !WinsWinn3PromotionGate.converged(engineStatusFields: relayConverged),
    "a RELAY-converged status document does not satisfy the standalone predicate"
  )
  check(
    !WinsWinnDatapathProofGate.converged(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 1, rxOffered: 1)
    ),
    "a STANDALONE-converged status document does not satisfy the relay predicate"
  )
  check(
    WinsWinnDatapathKind.forCarrier("direct-awg") == .relay
      && WinsWinnDatapathKind.forCarrier("http3-connect-udp") == .relay,
    "both relay carriers resolve to the relay predicate"
  )
  check(
    WinsWinnDatapathKind.forCarrier("winn3") == .standalone,
    "winn3 resolves to the standalone predicate"
  )
  check(
    WinsWinnDatapathKind.forCarrier("http2-stream") == nil,
    "an unrecognised carrier resolves to no kind rather than defaulting into one"
  )
  check(
    WinsWinnDatapathKind.standalone.converged(
      engineStatusFields: promotionFields(gate: "carrying", rxPackets: 1, rxOffered: 1)
    ),
    "the kind selector routes a standalone document to the standalone predicate"
  )
  check(
    WinsWinnDatapathKind.relay.converged(engineStatusFields: relayConverged),
    "the kind selector routes a relay document to the relay predicate"
  )
}

// MARK: - 5. §4.1 and §4.3, the bootstrap posture

let referenceInnerMTU = 1168

func bootstrapSettings(
  includedRoutes: [NEIPv4Route] = [
    NEIPv4Route(destinationAddress: "10.13.0.1", subnetMask: "255.255.255.255")
  ],
  addresses: [String] = ["10.13.0.2"],
  masks: [String] = ["255.255.255.255"],
  mtu: Int? = referenceInnerMTU,
  ipv6: Bool = false,
  dns: Bool = false
) -> NEPacketTunnelNetworkSettings {
  let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.0.2.9")
  let ipv4 = NEIPv4Settings(addresses: addresses, subnetMasks: masks)
  ipv4.includedRoutes = includedRoutes
  settings.ipv4Settings = ipv4
  if let mtu { settings.mtu = NSNumber(value: mtu) }
  if ipv6 {
    settings.ipv6Settings = NEIPv6Settings(addresses: ["fd00:13::2"], networkPrefixLengths: [128])
  }
  if dns {
    settings.dnsSettings = NEDNSSettings(servers: ["10.13.0.1"])
  }
  return settings
}

func verdict(
  _ settings: NEPacketTunnelNetworkSettings,
  exclusion: Bool = true,
  mtu: Int = referenceInnerMTU
) -> WinsWinn3BootstrapPosture.Verdict {
  WinsWinn3BootstrapPosture.evaluate(
    settings,
    requiredInnerMTU: mtu,
    carrierExclusionPresent: exclusion
  )
}

func runBootstrapPostureTests() {
  section("bootstrap: narrow, or refuse — never widen")

  check(
    verdict(bootstrapSettings()).narrow,
    "a one-route /32 bootstrap with the exclusion present is narrow"
  )
  check(
    !verdict(
      bootstrapSettings(includedRoutes: [
        NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
      ])
    ).narrow,
    "a bootstrap carrying the IPv4 default route is REFUSED, not accepted with a warning"
  )
  check(
    !verdict(
      bootstrapSettings(includedRoutes: [
        NEIPv4Route(destinationAddress: "10.13.0.1", subnetMask: "255.255.255.255"),
        NEIPv4Route(destinationAddress: "10.13.0.5", subnetMask: "255.255.255.255")
      ])
    ).narrow,
    "a bootstrap carrying two included routes is refused: at most one is permitted"
  )
  check(!verdict(bootstrapSettings(ipv6: true)).narrow, "a bootstrap carrying IPv6 settings is refused")
  check(!verdict(bootstrapSettings(dns: true)).narrow, "a bootstrap carrying DNS settings is refused")
  check(
    !verdict(bootstrapSettings(masks: ["255.255.255.0"])).narrow,
    "a bootstrap address wider than a /32 is refused: the host must not originate from an address the tunnel drops"
  )
  check(
    !verdict(bootstrapSettings(), exclusion: false).narrow,
    "a bootstrap without the outer-transport exclusion is refused: on Apple that route IS the socket protection"
  )
  check(
    !verdict(bootstrapSettings(mtu: referenceInnerMTU + 1)).narrow,
    "an MTU one byte above the plan floor is refused: larger than the tunnel can carry is a black hole"
  )
  check(
    verdict(bootstrapSettings(mtu: referenceInnerMTU - 8)).narrow == false,
    "an MTU below the plan floor is also refused: §4.2 says EXACTLY, and a host that guesses is a host that drifts"
  )
  check(
    !verdict(bootstrapSettings(mtu: nil)).narrow,
    "an unset MTU is refused; §4.2 is an obligation, not a default"
  )
  check(
    verdict(bootstrapSettings())
      .statusFields["winn3_datapath_proof_bootstrap_observably_narrow"] as? Bool == true,
    "the verdict publishes its own narrowness, checked on the object that was built rather than trusted from the builder"
  )
  check(
    verdict(bootstrapSettings(dns: true)).reasons.contains(where: { $0.contains("DNS") }),
    "a refusal says which rule it broke"
  )
}

// MARK: - 6. the config layer

func winn3Config(_ carrier: String) -> String {
  // The obfuscation values are the seam harness's own proven-valid fixture:
  // the [winn] section's h1..h4 and s1..s4 must agree with [Interface]'s or
  // validate() refuses for a reason that has nothing to do with the carrier.
  """
  [Interface]
  PrivateKey = \(wgKey)
  Address = 10.13.0.2/32
  MTU = 1280
  DNS = 10.13.0.1
  Jc = 2
  Jmin = 10
  Jmax = 30
  S1 = 16
  S2 = 80
  S3 = 16
  S4 = 0
  H1 = 11
  H2 = 22
  H3 = 33
  H4 = 44

  [Peer]
  PublicKey = \(wgKey)
  Endpoint = 203.0.113.10:9110
  AllowedIPs = 0.0.0.0/0, ::/0
  PersistentKeepalive = 25

  [Winn]
  Enabled = true
  Endpoint = 198.51.100.7:51820
  Carrier = \(carrier)
  Session_Id = winn3-contract
  H1 = 11
  H2 = 22
  H3 = 33
  H4 = 44
  S1 = 16
  S2 = 80
  S3 = 16
  S4 = 0
  """
}

func runConfigTests() {
  section("config: winn3 is nameable, refused at start, and never a silent relay")

  let relay = WinsTunnelConfig.parse(winn3Config("direct-awg"))
  check(relay.winnCarrier == "direct-awg", "an explicit direct-awg carrier resolves to itself")
  check(!relay.winn3Enabled, "a direct-awg config is not a standalone config")
  check(
    relay.winnSeamComponent == "winn_packet_engine",
    "a relay config still selects the AmneziaWG seam component — nothing about the relay changed"
  )
  check(relay.winn3StartRefusalReason == nil, "a relay config carries no standalone refusal")
  check(!refuses { try relay.validate() }, "a direct-awg config still validates")
  check(
    winn3CarrierExclusionIsUsable(relay) == nil,
    "a real transport endpoint yields a usable /32 exclusion"
  )

  let standalone = WinsTunnelConfig.parse(winn3Config("winn3"))
  check(standalone.winn3Enabled, "carrier = winn3 is recognised as a STANDALONE configuration")
  check(
    standalone.winnSeamComponent == nil,
    "a standalone config selects NO relay seam component: handing inner IP to the AWG wrapper is the downgrade the gate prevents"
  )
  check(
    standalone.winn3StartRefusalReason != nil,
    "a standalone config carrying NO gateway descriptor REFUSES to start, with a reason, rather than silently becoming a relay"
  )
  check(
    refuses { try standalone.validate() },
    "validate() refuses a standalone config with no inner assignment and no admission profile — which is every config the control plane serves today"
  )
  check(
    !standalone.requiredEngineComponents.contains("winn_packet_engine"),
    "a standalone config does not require the relay seam component"
  )

  for carrier in ["http2-stream", "masque", "winn4"] {
    let bad = WinsTunnelConfig.parse(winn3Config(carrier))
    check(
      refuses { try bad.validate() },
      "a [winn] carrier of \(carrier) is still refused: widening by name did not relax the gate"
    )
  }

  check(
    WinsTunnelConfig.supportedWinnCarriers.contains(WinsTunnelConfig.supportedWinnCarrier)
      && WinsTunnelConfig.supportedWinnCarriers.contains(WinsTunnelConfig.supportedWinnCarrierHttp3)
      && WinsTunnelConfig.supportedWinnCarriers.contains(WinsTunnelConfig.supportedWinnCarrierWinn3),
    "the accepted carrier set is exactly the three named ones"
  )
  check(
    WinsTunnelConfig.supportedWinnCarriers.count == 3,
    "no fourth carrier crept into the set"
  )
}

// MARK: - 7. the create document builder

func runCreateDocumentTests() {
  section("create document: what the host would hand the archive")

  let built = WinsWinn3CreateDocument(
    gatewayEndpoint: "198.51.100.7:51820",
    staticPrivateBase64: localStatic,
    gatewayStaticBase64: gatewayStatic,
    gatewayIDText: gatewayIDText,
    admissionKeyBase64: admissionKey,
    dualAuthPublicKeys: nil,
    pskBase64: nil,
    innerV4: "10.13.0.2",
    innerRouterV4: "10.13.0.1",
    pathMTU: 1450,
    carrierClasses: ["udp", "tls"],
    sessionID: "doc-test",
    allowOwnSocket: false
  )
  guard let text = try? built.json(),
        let data = text.data(using: .utf8),
        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    check(false, "the create document encodes")
    return
  }
  check(object["contract"] as? String == WinsWinn3.contract, "the document names the standalone contract")
  check(object["payload"] as? String == WinsWinn3.payloadClass, "the document names the ip-packet payload class")
  check(object["carrier"] as? String == WinsWinn3.carrierName, "the document names the winn3 carrier")
  check(object["psk"] == nil, "an absent PSK is omitted rather than sent as an empty string")
  check(
    (object["carrier_classes"] as? [String]) == ["udp", "tls"],
    "the document carries the MIGRATION PLAN, which is what the inner MTU is computed over"
  )
  // The strongest available assertion short of starting a session: the real
  // archive parses the builder's own document and gets all the way to the
  // socket rule before refusing. A shape error would refuse earlier and with a
  // different message.
  check(
    createRefusal(object)?.contains("allow_own_socket") == true,
    "the real archive accepts the builder's document shape and refuses it only at the socket rule"
  )
}

// MARK: - 8. the pump, driven against the real archive

/// A stand-in for `NEPacketTunnelFlow`.
///
/// It is NOT a mock of a mock: `WinsWinn3Datapath` talks to the real Go archive
/// on the other side, and this class supplies only the half an appex supplies —
/// the OS. Its `readPackets` hands over one queued batch and then PARKS, which
/// is how the real flow behaves when no application is sending; a stand-in that
/// re-delivered on every call would spin the pump instead of testing it.
final class HarnessPacketRelay: WinsWinn3PacketRelay {
  private let lock = NSLock()
  private var pending: [[Data]]
  private var written: [Data] = []
  private var readCalls = 0
  private var parkedHandler: (@Sendable ([Data], [NSNumber]) -> Void)?

  init(batches: [[Data]]) {
    self.pending = batches
  }

  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
    lock.lock()
    readCalls += 1
    if pending.isEmpty {
      // Park: hold the handler and never call it, exactly as the real flow does
      // when the tun device is idle.
      parkedHandler = completionHandler
      lock.unlock()
      return
    }
    let batch = pending.removeFirst()
    lock.unlock()
    completionHandler(batch, batch.map { _ in NSNumber(value: AF_INET) })
  }

  @discardableResult
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
    lock.lock()
    written.append(contentsOf: packets)
    lock.unlock()
    return true
  }

  var writtenPackets: [Data] {
    lock.lock()
    defer { lock.unlock() }
    return written
  }

  var readCallCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return readCalls
  }

  var isParked: Bool {
    lock.lock()
    defer { lock.unlock() }
    return parkedHandler != nil
  }
}

/// A well-formed inner IPv4 packet from the session's own inner address.
///
/// Built correctly — real header length, total length and header checksum — so
/// that a drop can only be the gate's doing. A malformed packet would also be
/// dropped, and the test would pass for the wrong reason.
func innerIPv4Packet(source: String, destination: String, payload: Int) -> Data {
  var header = [UInt8](repeating: 0, count: 20)
  let total = 20 + payload
  header[0] = 0x45
  header[2] = UInt8((total >> 8) & 0xFF)
  header[3] = UInt8(total & 0xFF)
  header[8] = 64
  header[9] = 17 // UDP
  var sourceAddress = in_addr()
  var destinationAddress = in_addr()
  _ = inet_pton(AF_INET, source, &sourceAddress)
  _ = inet_pton(AF_INET, destination, &destinationAddress)
  withUnsafeBytes(of: sourceAddress.s_addr) { raw in
    for index in 0..<4 { header[12 + index] = raw[index] }
  }
  withUnsafeBytes(of: destinationAddress.s_addr) { raw in
    for index in 0..<4 { header[16 + index] = raw[index] }
  }
  var sum: UInt32 = 0
  for index in stride(from: 0, to: 20, by: 2) {
    sum &+= (UInt32(header[index]) << 8) | UInt32(header[index + 1])
  }
  while sum >> 16 != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
  let checksum = UInt16(truncatingIfNeeded: ~sum)
  header[10] = UInt8((checksum >> 8) & 0xFF)
  header[11] = UInt8(checksum & 0xFF)
  return Data(header) + Data(repeating: 0xAB, count: payload)
}

func integerField(_ fields: [String: Any], _ suffix: String) -> UInt64 {
  WinsWinn3PromotionGate.unsignedValue(
    fields[WinsWinnSeamObservabilitySample.engineFieldPrefix + suffix]
  )
}

/// Whether the sampler PUBLISHED a field at all, as distinct from what its
/// value is.
///
/// This exists because `integerField` cannot tell the difference. It maps a
/// missing key to zero — `unsignedValue(nil)` is 0 — so `integerField(fields,
/// "winn3_x") == 0` is satisfied both by a counter published as zero and by a
/// counter this platform cannot see at all. Every field whose only assertion is
/// a zero-comparison is therefore uncovered, and a 2026-08-09 mutation showed
/// exactly that: deleting `"winn3_tx_dropped_invalid"` from
/// `WinsWinnSeamObservabilitySample.engineIntegerFields` left this harness at a
/// clean pass. A field the host has gone blind to must fail here.
func hasEngineField(_ fields: [String: Any], _ suffix: String) -> Bool {
  fields[WinsWinnSeamObservabilitySample.engineFieldPrefix + suffix] != nil
}

func runPumpTests() {
  section("pump: packets actually cross the ABI, and the gate holds them")

  check(
    WinsWinn3ABI.pumpSymbolsAvailable,
    "every symbol the pump needs resolves as a SET: a build with create but no read would carry nothing"
  )

  guard let carrier = loopbackCarrierDescriptor() else {
    check(false, "a loopback carrier descriptor is available")
    return
  }
  defer { close(carrier.listener) }

  let datapath = WinsWinn3Datapath()
  let document = baseDocument(gatewayEndpoint: carrier.endpoint)
  guard let data = try? JSONSerialization.data(withJSONObject: document),
        let json = String(data: data, encoding: .utf8) else {
    check(false, "the pump create document encodes")
    return
  }

  do {
    try datapath.start(document: json, carrierDescriptor: carrier.fd)
    check(true, "the pump starts a REAL winn3 handle over a loopback carrier")
  } catch {
    check(false, "the pump starts a REAL winn3 handle over a loopback carrier (\(error))")
    return
  }

  check(datapath.isRunning, "a started pump reports itself running")
  check(datapath.currentHandle > 0, "a started pump owns a positive handle")

  let before = datapath.statusFields()
  let innerMTU = Int(clamping: integerField(before, "winn3_inner_mtu"))
  check(innerMTU > 0, "the engine publishes an inner MTU the pump can size its read buffer from")
  check(
    integerField(before, "winn3_tx_dropped_closed") == 0,
    "nothing has been dropped before the pump has sent anything"
  )

  // Three well-formed inner packets from the session's own inner address.
  let packets = (0..<3).map { _ in
    innerIPv4Packet(source: "10.13.0.2", destination: "10.13.0.1", payload: 64)
  }
  let relay = HarnessPacketRelay(batches: [packets])
  datapath.resume(relay: relay)

  // The pump is asynchronous on both sides; poll rather than sleep a fixed
  // amount, so a slow machine does not fail a passing implementation.
  var dropped: UInt64 = 0
  let deadline = Date().addingTimeInterval(5.0)
  while Date() < deadline {
    dropped = integerField(datapath.statusFields(), "winn3_tx_dropped_closed")
    if dropped >= UInt64(packets.count) { break }
    usleep(20_000)
  }

  check(
    dropped >= UInt64(packets.count),
    "every packet the host wrote reached the tun layer: winn3_tx_dropped_closed moved by \(packets.count) (saw \(dropped))"
  )
  check(
    datapath.pumpStatusFields()["winn3_datapath_proof_host_to_engine_packets"] as? Int == packets.count,
    "the pump counts what it handed the engine, so a silent loss on this side is visible"
  )

  let after = datapath.statusFields()
  check(
    integerField(after, "winn3_tx_packets") == 0,
    "NOTHING WAS SENT: a packet pumped before the gate opens is DROPPED, never put on the wire"
  )
  check(
    !WinsWinn3PromotionGate.converged(engineStatusFields: after),
    "pumping packets does not converge the promotion predicate; only a delivered packet can"
  )
  check(
    WinsWinn3PromotionGate.deliveredPacketCount(engineStatusFields: after) == 0,
    "no gateway answered, so nothing was delivered and rx_packets stays zero"
  )
  check(
    relay.writtenPackets.isEmpty,
    "the host received nothing, because a session with no handshake delivers nothing"
  )
  check(
    relay.isParked,
    "the pump re-armed the host read and is parked waiting, rather than spinning on an idle device"
  )
  check(
    relay.readCallCount >= 2,
    "the pump re-arms readPackets from inside its own completion handler, which is the only supported idiom"
  )

  // The reader thread is parked inside a blocking WinnTunnelReadOutbound right
  // now. Closing from this thread must unblock it, and must be prompt.
  let stopStarted = Date()
  let closeMessage = datapath.stop()
  let stopSeconds = Date().timeIntervalSince(stopStarted)
  check(closeMessage == nil, "closing a live winn3 handle reports no error")
  check(
    stopSeconds < 2.0,
    "stop() unblocks a reader parked in WinnTunnelReadOutbound promptly (took \(String(format: "%.3f", stopSeconds))s)"
  )
  check(!datapath.isRunning, "a stopped pump no longer reports itself running")
  check(datapath.currentHandle == 0, "a stopped pump has surrendered its handle")
  check(datapath.stop() == nil, "stop() is idempotent: a second close is not an error")
  check(
    datapath.statusFields().isEmpty,
    "a stopped pump reports no engine fields rather than stale ones"
  )
  check(
    !datapath.converged(),
    "a stopped pump cannot converge, so a teardown race cannot promote a route"
  )
}

// MARK: - 9. the standalone START DECISION and the two postures
//
// This is the half that used to be missing: `WinsWinn3HostContract.swift` held
// the decisions and `WinsWinn3Datapath.swift` held the pump, and nothing said
// whether a given CONFIGURATION may start a session or what the interface looks
// like while it is proved. `WinsWinn3SessionStart.swift` answers both, and this
// section drives it — including one deliberate mutation per required field, so
// a refusal that silently stops naming a field fails here rather than in
// Myanmar.

/// A COMPLETE standalone configuration, with the named `[winn]` keys removed.
///
/// Removing one at a time is the mutation: each produced config must be refused
/// AND the refusal must name the field, which is the only property that makes a
/// refusal actionable for someone holding a half-provisioned descriptor.
/// `interfaceDNS` is the AmneziaWG `[Interface] DNS` line, which is the ONLY
/// resolver list an Apple host has and which `lib/main.dart` rewrites to public
/// literals on this platform. It is a parameter because the whole of §9a turns
/// on what is in it, and the default is a resolver a standalone session can
/// actually justify — `10.13.0.9`, inside the /24 around the `inner_v4`
/// assignment, and neither the assignment nor the PMTU-only next hop.
///
/// It is deliberately NOT `10.13.0.1`, which is what this fixture carried until
/// 2026-08-09. That value is `inner_router_v4`, and §9a asserts it is refused.
func winn3StandaloneConfigText(
  removing: Set<String> = [],
  overriding: [String: String] = [:],
  interfaceDNS: String = "10.13.0.9"
) -> String {
  var winn: [(String, String)] = [
    ("Enabled", "true"),
    ("Endpoint", "198.51.100.7:51820"),
    ("Carrier", "winn3"),
    ("Session_Id", "winn3-standalone"),
    ("Inner_V4", "10.13.0.2"),
    ("Inner_Router_V4", "10.13.0.1"),
    ("Static_Private", localStatic),
    ("Gateway_Static", gatewayStatic),
    ("Gateway_Id", gatewayID),
    ("Admission_Key", admissionKey),
    ("Path_Mtu", "1450"),
    ("Carrier_Classes", "udp, tls"),
    ("H1", "11"), ("H2", "22"), ("H3", "33"), ("H4", "44"),
    ("S1", "16"), ("S2", "80"), ("S3", "16"), ("S4", "0")
  ]
  winn.removeAll { removing.contains($0.0.lowercased()) }
  winn = winn.map { key, value in
    (key, overriding[key.lowercased()] ?? value)
  }
  for (key, value) in overriding {
    if !winn.contains(where: { $0.0.lowercased() == key.lowercased() }) {
      winn.append((key, value))
    }
  }
  let winnSection = winn.map { "\($0.0) = \($0.1)" }.joined(separator: "\n")
  return """
    [Interface]
    PrivateKey = \(wgKey)
    Address = 10.13.0.2/32
    MTU = 1280
    DNS = \(interfaceDNS)
    Jc = 2
    Jmin = 10
    Jmax = 30
    S1 = 16
    S2 = 80
    S3 = 16
    S4 = 0
    H1 = 11
    H2 = 22
    H3 = 33
    H4 = 44

    [Peer]
    PublicKey = \(wgKey)
    Endpoint = 203.0.113.10:9110
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25

    [Winn]
    \(winnSection)
    """
}

func winn3StandaloneConfig(
  removing: Set<String> = [],
  overriding: [String: String] = [:],
  interfaceDNS: String = "10.13.0.9"
) -> WinsTunnelConfig {
  WinsTunnelConfig.parse(winn3StandaloneConfigText(
    removing: removing,
    overriding: overriding,
    interfaceDNS: interfaceDNS
  ))
}

func runStandaloneStartTests() {
  section("standalone start: which configurations may be attempted, and why not")

  let complete = winn3StandaloneConfig()
  check(complete.winn3Enabled, "the complete fixture is a standalone configuration")
  check(
    WinsWinn3StartRequirements.unmetReasons(complete).isEmpty,
    "a configuration carrying a full gateway descriptor has no unmet requirement"
  )
  check(
    complete.winn3StartRefusalReason == nil,
    "a complete standalone configuration is no longer refused by a blanket capability clause"
  )
  check(
    !refuses { try complete.validate() },
    "validate() accepts a complete standalone configuration"
  )

  // The accessors read the create document's own key names, so an INI section
  // and a create document can be diffed by eye.
  check(complete.winn3InnerV4 == "10.13.0.2", "[winn] inner_v4 is read")
  check(complete.winn3InnerRouterV4 == "10.13.0.1", "[winn] inner_router_v4 is read")
  check(complete.winn3StaticPrivate == localStatic, "[winn] static_private is read")
  check(complete.winn3GatewayStatic == gatewayStatic, "[winn] gateway_static is read")
  check(complete.winn3GatewayID == gatewayID, "[winn] gateway_id is read")
  check(
    complete.winn3GatewayIDOperatorText == gatewayIDText,
    "[winn] gateway_id is DECODED at the descriptor boundary into the operator's gateway name"
  )
  // The refusal that used to live in the Go archive as "gateway_id is not
  // base64". It moved here with the decode; it did not disappear. Losing it
  // would turn a readable start refusal into a session that starts, reports up
  // and is ignored by the gateway forever.
  for unusable in ["wins-sea-01", "not base64 at all", "="] {
    let bad = winn3StandaloneConfig(overriding: ["gateway_id": unusable])
    check(
      bad.winn3GatewayIDOperatorText == nil,
      "a [winn] gateway_id of \(unusable) does not decode, so no gateway id is guessed at"
    )
    check(
      bad.winn3StartRefusalReason?.contains("gateway_id") == true,
      "a [winn] gateway_id of \(unusable) refuses the start and NAMES the field"
    )
    check(
      WinsWinn3CreateDocument.make(config: bad) == nil,
      "no create document is built from a [winn] gateway_id of \(unusable)"
    )
  }
  // Base64 that decodes to bytes which are not text. The engine's document is
  // JSON and a JSON string is UTF-8, so this cannot be carried and must refuse
  // rather than be mangled into replacement characters -- a mangled gateway id
  // is a wrong admission tag, which is the silent failure.
  let nonUTF8 = winn3StandaloneConfig(
    overriding: ["gateway_id": Data([0xC3, 0x28, 0xA0, 0xA1]).base64EncodedString()]
  )
  check(
    nonUTF8.winn3GatewayIDOperatorText == nil,
    "a gateway id whose descriptor bytes are not UTF-8 does not decode"
  )
  check(
    nonUTF8.winn3StartRefusalReason?.contains("gateway_id") == true,
    "a gateway id whose descriptor bytes are not UTF-8 refuses the start, naming the field"
  )
  check(complete.winn3AdmissionKey == admissionKey, "[winn] admission_key is read")
  check(complete.winn3PathMTU == 1450, "[winn] path_mtu is read as a number")
  check(
    complete.winn3CarrierClasses == ["udp", "tls"],
    "[winn] carrier_classes is the MIGRATION PLAN, comma-separated and order-preserving"
  )
  check(
    complete.winn3PSK.isEmpty,
    "an absent psk is empty rather than a refusal: it is optional in the shipping deployment"
  )
  check(
    winn3StandaloneConfig(removing: ["carrier_classes"]).winn3CarrierClasses.isEmpty,
    "an absent carrier_classes yields an empty plan, which the engine reads as udp-only rather than as unset"
  )

  let dualEd = Data(repeating: 0xAA, count: 32).base64EncodedString()
  let dualMl = Data(repeating: 0xBB, count: 1952).base64EncodedString()
  let missingMl = winn3StandaloneConfig(overriding: ["auth_ed25519": dualEd])
  check(
    missingMl.winn3StartRefusalReason?.contains("auth_ed25519") == true &&
      missingMl.winn3StartRefusalReason?.contains("auth_mldsa65") == true,
    "a missing auth_mldsa65 half is refused and names both keys"
  )
  check(
    WinsWinn3CreateDocument.make(config: missingMl) == nil,
    "no create document is built from a half-provisioned dual-auth pair"
  )
  let missingEd = winn3StandaloneConfig(overriding: ["auth_mldsa65": dualMl])
  check(
    missingEd.winn3StartRefusalReason?.contains("auth_ed25519") == true &&
      WinsWinn3CreateDocument.make(config: missingEd) == nil,
    "a missing auth_ed25519 half is refused before create"
  )
  let explicitlyEmpty = winn3StandaloneConfig(overriding: [
    "auth_ed25519": "", "auth_mldsa65": ""
  ])
  check(
    explicitlyEmpty.winn3StartRefusalReason?.contains("auth_ed25519") == true &&
      explicitlyEmpty.winn3StartRefusalReason?.contains("auth_mldsa65") == true &&
      WinsWinn3CreateDocument.make(config: explicitlyEmpty) == nil,
    "an explicitly present empty pair cannot select absent legacy mode"
  )
  let mismatch = winn3StandaloneConfig(overriding: [
    "auth_ed25519": Data(repeating: 0xAA, count: 31).base64EncodedString(),
    "auth_mldsa65": dualMl
  ])
  check(
    mismatch.winn3StartRefusalReason?.contains("auth_ed25519") == true,
    "a 31-byte Ed25519 attestation key is a named length mismatch"
  )
  let longEd = winn3StandaloneConfig(overriding: [
    "auth_ed25519": Data(repeating: 0xAA, count: 33).base64EncodedString(),
    "auth_mldsa65": dualMl
  ])
  check(
    longEd.winn3StartRefusalReason?.contains("auth_ed25519") == true,
    "a 33-byte Ed25519 attestation key is a named length mismatch"
  )
  let shortMl = winn3StandaloneConfig(overriding: [
    "auth_ed25519": dualEd,
    "auth_mldsa65": Data(repeating: 0xBB, count: 1951).base64EncodedString()
  ])
  check(
    shortMl.winn3StartRefusalReason?.contains("auth_mldsa65") == true,
    "a 1951-byte ML-DSA-65 attestation key is a named length mismatch"
  )
  let longMl = winn3StandaloneConfig(overriding: [
    "auth_ed25519": dualEd,
    "auth_mldsa65": Data(repeating: 0xBB, count: 1953).base64EncodedString()
  ])
  check(
    longMl.winn3StartRefusalReason?.contains("auth_mldsa65") == true,
    "a 1953-byte ML-DSA-65 attestation key is a named length mismatch"
  )
  for (field, ed, ml) in [
    ("auth_ed25519", "not base64!", dualMl),
    ("auth_mldsa65", dualEd, "not base64!")
  ] {
    check(
      !WinsWinn3DualAuthPublicKeys.validate(
        ed25519Base64: ed,
        mldsa65Base64: ml
      ).unmetReasons.filter { $0.contains(field) }.isEmpty,
      "invalid base64 is refused for \(field)"
    )
  }
  check(
    !WinsWinn3DualAuthPublicKeys.validate(
      ed25519Base64: dualEd + "\n",
      mldsa65Base64: dualMl
    ).unmetReasons.isEmpty,
    "non-canonical Ed25519 base64 is refused rather than normalized"
  )
  check(
    !WinsWinn3DualAuthPublicKeys.validate(
      ed25519Base64: dualEd,
      mldsa65Base64: dualMl + "\n"
    ).unmetReasons.isEmpty,
    "non-canonical ML-DSA-65 base64 is refused rather than normalized"
  )
  let both = winn3StandaloneConfig(overriding: [
    "auth_ed25519": dualEd,
    "auth_mldsa65": dualMl
  ])
  check(both.winn3AuthEd25519 == dualEd && both.winn3AuthMldsa65 == dualMl,
        "both dual-auth values are consumed from [winn]")
  check(
    both.winn3StartRefusalReason == nil,
    "a canonical exact-length pair is accepted by the Apple create path"
  )
  let bothJSON = try? WinsWinn3CreateDocument.make(config: both)?.json()
  let bothObject = bothJSON
    .flatMap { $0.data(using: .utf8) }
    .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
  check(bothObject?["auth_ed25519"] as? String == dualEd,
        "the create document carries the exact signed auth_ed25519 text")
  check(bothObject?["auth_mldsa65"] as? String == dualMl,
        "the create document carries the exact signed auth_mldsa65 text")
  var dualAuthRefusalObject = bothObject ?? [:]
  dualAuthRefusalObject["allow_own_socket"] = false
  check(
    createRefusal(dualAuthRefusalObject)?.contains("allow_own_socket") == true,
    "the real archive accepts both dual-auth fields and reaches the socket rule"
  )
  let replacedText = winn3StandaloneConfigText(overriding: [
    "auth_ed25519": dualEd,
    "auth_mldsa65": dualMl
  ]) + "\nAuth_Ed25519 = \(Data(repeating: 0xCC, count: 32).base64EncodedString())\n"
  check(
    refuses { _ = try WinsTunnelConfig.parseAndValidate(replacedText) },
    "a later duplicate auth_ed25519 cannot replace the signed descriptor value"
  )
  let replacedMlText = winn3StandaloneConfigText(overriding: [
    "auth_ed25519": dualEd,
    "auth_mldsa65": dualMl
  ]) + "\nAuth_MLDSA65 = \(Data(repeating: 0xCD, count: 1952).base64EncodedString())\n"
  check(
    refuses { _ = try WinsTunnelConfig.parseAndValidate(replacedMlText) },
    "a later duplicate auth_mldsa65 cannot replace the signed descriptor value"
  )
  let replacementEd = Data(repeating: 0xCC, count: 32).base64EncodedString()
  let replacementMl = Data(repeating: 0xDD, count: 1952).base64EncodedString()
  let replacement = winn3StandaloneConfig(overriding: [
    "auth_ed25519": replacementEd,
    "auth_mldsa65": replacementMl
  ])
  let replacementJSON = try? WinsWinn3CreateDocument.make(config: replacement)?.json()
  check(
    replacementJSON?.contains(replacementEd) == true &&
      replacementJSON?.contains(replacementMl) == true &&
      replacementJSON?.contains(dualEd) != true &&
      replacementJSON?.contains(dualMl) != true,
    "a fresh create binds only its own replacement pair, never predecessor bytes"
  )
  let stale = winn3StandaloneConfig()
  check(
    stale.winn3AuthEd25519.isEmpty && stale.winn3AuthMldsa65.isEmpty &&
      stale.winn3StartRefusalReason == nil,
    "a later parse without the pair does not rebind stale dual-auth values"
  )
  let staleJSON = try? WinsWinn3CreateDocument.make(config: stale)?.json()
  check(
    staleJSON != nil && staleJSON?.contains("auth_ed25519") != true
      && staleJSON?.contains("auth_mldsa65") != true,
    "a stale dual-auth pair is not rebound into the create document"
  )

  // THE MUTATIONS. One required field removed at a time; each must refuse AND
  // name the field it removed.
  let mutations: [(String, String)] = [
    ("endpoint", "endpoint"),
    ("inner_v4", "inner_v4"),
    ("inner_router_v4", "inner_router_v4"),
    ("static_private", "static_private"),
    ("gateway_static", "gateway_static"),
    ("gateway_id", "gateway_id"),
    ("admission_key", "admission_key")
  ]
  for (removedKey, namedIn) in mutations {
    let mutated = winn3StandaloneConfig(removing: [removedKey])
    let reason = mutated.winn3StartRefusalReason
    check(
      reason != nil,
      "removing [winn] \(removedKey) refuses the start"
    )
    check(
      reason?.contains(namedIn) == true,
      "the refusal for a missing \(removedKey) NAMES the field, so a half-provisioned descriptor is actionable"
    )
    check(
      refuses { try mutated.validate() },
      "validate() refuses a standalone configuration missing \(removedKey)"
    )
    check(
      WinsWinn3CreateDocument.make(config: mutated) == nil,
      "no create document is built for a configuration missing \(removedKey)"
    )
  }

  // Every field missing at once: the refusal enumerates rather than stopping at
  // the first, which is what stops an operator learning one field per retry.
  let bare = winn3StandaloneConfig(removing: [
    "inner_v4", "inner_router_v4", "static_private",
    "gateway_static", "gateway_id", "admission_key"
  ])
  // SEVEN, not six, and the seventh is not noise. The resolver pre-flight is
  // derived from `[winn] inner_v4`, so a configuration missing the assignment
  // cannot derive an inner space to judge a resolver against and says so. It is
  // reported rather than suppressed for the same reason the other six are
  // enumerated: an operator holding a half-provisioned descriptor learns
  // everything that is missing from one refusal instead of one field per retry.
  check(
    WinsWinn3StartRequirements.unmetReasons(bare).count == 7,
    "six missing descriptor fields produce six reasons, not one — plus the resolver pre-flight, which cannot derive an inner space without inner_v4"
  )
  for field in ["inner_v4", "inner_router_v4", "static_private", "gateway_static", "gateway_id", "admission_key"] {
    check(
      bare.winn3StartRefusalReason?.contains(field) == true,
      "the combined refusal still names \(field)"
    )
  }

  // A hostname endpoint. The engine refuses one because resolving it is a
  // lookup outside the tunnel; refusing it here means the operator learns it
  // from the config layer rather than from a create failure.
  let hostnameEndpoint = winn3StandaloneConfig(
    overriding: ["endpoint": "gateway.example.org:51820"]
  )
  check(
    hostnameEndpoint.winn3StartRefusalReason?.contains("IP literal") == true,
    "a hostname gateway endpoint is refused, and the refusal says why"
  )

  // THE CARRIER EXCLUSION, which on Apple is the whole of protect(). A loopback
  // endpoint yields a /32 that excludes nothing off this device.
  let loopbackEndpoint = winn3StandaloneConfig(
    overriding: ["endpoint": "127.0.0.1:51820"]
  )
  check(
    loopbackEndpoint.winn3StartRefusalReason != nil,
    "a loopback gateway endpoint refuses a standalone start: its /32 excludes nothing"
  )
  check(
    WinsWinn3CreateDocument.make(config: loopbackEndpoint) == nil,
    "no create document is built when the carrier exclusion is unusable, so the socket is never opened"
  )

  // The relay is untouched by all of this.
  let relay = WinsTunnelConfig.parse(winn3Config("direct-awg"))
  check(
    WinsWinn3StartRequirements.unmetReasons(relay).isEmpty,
    "the standalone requirements say nothing about a relay configuration"
  )
  check(
    relay.winn3StartRefusalReason == nil,
    "a relay configuration still carries no standalone refusal"
  )
}

func runCreateDocumentFromConfigTests() {
  section("create document from a configuration: the fields the archive will read")

  guard let document = WinsWinn3CreateDocument.make(config: winn3StandaloneConfig()) else {
    check(false, "a complete standalone configuration yields a create document")
    return
  }
  guard let json = try? document.json(),
        let parsed = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else {
    check(false, "the config-derived create document encodes")
    return
  }

  check(parsed["contract"] as? String == WinsWinn3.contract, "the document carries the winn/3 contract, not the relay's")
  check(parsed["payload"] as? String == WinsWinn3.payloadClass, "the document carries payload ip-packet")
  check(parsed["carrier"] as? String == WinsWinn3.carrierName, "the document carries carrier winn3")
  check(parsed["gateway_endpoint"] as? String == "198.51.100.7:51820", "the gateway endpoint comes from [winn] endpoint")
  check(parsed["inner_v4"] as? String == "10.13.0.2", "the inner address comes from [winn] inner_v4")
  check(parsed["inner_router_v4"] as? String == "10.13.0.1", "the inner next hop comes from [winn] inner_router_v4")
  check(
    parsed["gateway_id"] as? String == gatewayIDText,
    "the gateway id reaches the engine DECODED: [winn] gateway_id carries the "
      + "descriptor's base64, and the engine is handed the operator's gateway "
      + "name, which is what cmd/winn3-gateway computes its admission tag over"
  )
  check(
    parsed["gateway_id"] as? String != gatewayID,
    "the document does NOT carry the descriptor's base64 through to the engine: "
      + "that was the cross-platform defect -- Apple computed a tag over "
      + "different bytes than every other host, and a gateway that cannot "
      + "verify a tag answers nothing at all"
  )
  check(parsed["admission_key"] as? String == admissionKey, "the admission key comes from [winn] admission_key")
  check(parsed["path_mtu"] as? Int == 1450, "the path MTU comes from [winn] path_mtu")
  check(parsed["carrier_classes"] as? [String] == ["udp", "tls"], "the migration plan survives into the document")
  check(
    parsed["allow_own_socket"] as? Bool == true,
    "allow_own_socket is TRUE on Apple: the appex cannot hand a protected descriptor to anything, and the /32 is what protects it"
  )
  check(parsed["psk"] == nil, "an absent psk is omitted rather than sent empty")
  check(
    parsed["static_private"] as? String == localStatic,
    "the static private key comes from [winn] static_private, NOT from [interface] PrivateKey"
  )
  check(
    (parsed["static_private"] as? String) != wgKey,
    "a standalone session never borrows the AmneziaWG identity: one key compromise must not be two protocols' compromise"
  )

  // The REAL archive accepts it. The endpoint is swapped for the in-process
  // loopback listener so nothing leaves the machine — the only difference
  // between this document and the one a provider would hand over.
  guard let carrier = loopbackCarrierDescriptor() else {
    check(false, "a loopback carrier descriptor is available for the config-derived document")
    return
  }
  defer { close(carrier.listener) }
  var loopbackDocument = parsed
  loopbackDocument["gateway_endpoint"] = carrier.endpoint
  loopbackDocument["allow_own_socket"] = false
  guard let create = winn3Symbol(WinsWinn3.createSymbol, as: WinnCreateWinn3Fn.self),
        let data = try? JSONSerialization.data(withJSONObject: loopbackDocument),
        let text = String(data: data, encoding: .utf8) else {
    check(false, "the loopback variant of the config-derived document encodes")
    return
  }
  var errorOut: UnsafeMutablePointer<CChar>?
  let handle = text.withCString { pointer -> Int64 in
    let mutable = strdup(pointer)
    defer { free(mutable) }
    return create(mutable, carrier.fd, &errorOut)
  }
  check(
    handle > 0,
    "the REAL archive accepts a document built from a WinsTunnelConfig — every field name and type agrees with the Go decoder's DisallowUnknownFields"
  )
  if handle > 0, let close = winn3Symbol("WinnTunnelClose", as: WinnCloseFn.self) {
    _ = close(handle)
  } else if let errorOut {
    print("      archive refusal: \(String(cString: errorOut))")
  }
}

func runStandalonePostureTests() {
  section("standalone postures: what the provider installs, before and after the proof")

  let config = winn3StandaloneConfig()
  let innerMTU = 1312

  let bootstrap = WinsWinn3Settings.bootstrap(config: config, innerMTU: innerMTU)
  let verdict = WinsWinn3BootstrapPosture.evaluate(
    bootstrap,
    requiredInnerMTU: innerMTU,
    carrierExclusionPresent: WinsWinn3Settings.carrierExclusionPresent(
      in: bootstrap,
      config: config
    )
  )
  check(verdict.narrow, "the bootstrap this provider builds passes the §4.3 narrowness check it will be given")
  check(
    bootstrap.ipv4Settings?.addresses == ["10.13.0.2"],
    "the bootstrap carries the INNER address; an AmneziaWG address would be dropped by the tun layer as a source violation"
  )
  check(
    bootstrap.ipv4Settings?.subnetMasks == ["255.255.255.255"],
    "the bootstrap address is a /32"
  )
  check(
    (bootstrap.ipv4Settings?.includedRoutes ?? []).count == 1,
    "the bootstrap carries exactly one included route"
  )
  check(
    bootstrap.ipv4Settings?.includedRoutes?.first?.destinationAddress == "10.13.0.1",
    "the one included route is the inner next hop"
  )
  check(
    !(bootstrap.ipv4Settings?.includedRoutes ?? []).contains { $0.destinationAddress == "0.0.0.0" },
    "the bootstrap carries NO default route"
  )
  check(bootstrap.ipv6Settings == nil, "the bootstrap installs no IPv6: the host keeps its own")
  check(bootstrap.dnsSettings == nil, "the bootstrap installs no DNS: a resolver in an unproven tunnel breaks every lookup on the machine")
  check(
    bootstrap.mtu?.intValue == innerMTU,
    "the bootstrap MTU is exactly the engine's published inner MTU, as §4.2 requires"
  )
  check(
    WinsWinn3Settings.carrierExclusionPresent(in: bootstrap, config: config),
    "the carrier /32 is present in the FIRST posture, not added at promotion"
  )

  // MUTATION: an MTU that is not the inner MTU must fail the posture check.
  // §4.2 makes a too-large interface MTU a black hole path-MTU discovery may
  // not rescue, so this is a refusal and not a warning.
  let wrongMTU = WinsWinn3Settings.bootstrap(config: config, innerMTU: innerMTU + 1)
  check(
    !WinsWinn3BootstrapPosture.evaluate(
      wrongMTU,
      requiredInnerMTU: innerMTU,
      carrierExclusionPresent: true
    ).narrow,
    "a bootstrap whose MTU is not exactly the inner MTU is refused"
  )

  // MUTATION: an unusable carrier exclusion must fail the posture check even
  // when every route is narrow — on Apple that /32 is the whole of protect().
  let loopbackConfig = winn3StandaloneConfig(overriding: ["endpoint": "127.0.0.1:51820"])
  let loopbackBootstrap = WinsWinn3Settings.bootstrap(config: loopbackConfig, innerMTU: innerMTU)
  check(
    !WinsWinn3Settings.carrierExclusionPresent(in: loopbackBootstrap, config: loopbackConfig),
    "a loopback endpoint yields no carrier exclusion to install"
  )
  check(
    !WinsWinn3BootstrapPosture.evaluate(
      loopbackBootstrap,
      requiredInnerMTU: innerMTU,
      carrierExclusionPresent: WinsWinn3Settings.carrierExclusionPresent(
        in: loopbackBootstrap,
        config: loopbackConfig
      )
    ).narrow,
    "a bootstrap with no carrier exclusion is NOT narrow, however narrow its routes are"
  )

  // The full-tunnel posture: what promotion installs, and what it must not.
  //
  // It is OPTIONAL now. `fullTunnel` refuses rather than widening when this
  // configuration has no resolver a standalone session can justify, which is
  // §9a's whole subject; here the fixture carries one, so it must build.
  guard let full = WinsWinn3Settings.fullTunnel(config: config, innerMTU: innerMTU) else {
    check(false, "a standalone configuration offering a derivable inner resolver builds a promoted posture")
    return
  }
  check(
    full.ipv4Settings?.addresses == ["10.13.0.2"],
    "the promoted posture keeps the INNER address"
  )
  check(
    (full.ipv4Settings?.includedRoutes ?? []).contains { $0.destinationAddress == "0.0.0.0" },
    "the promoted posture carries the default route the bootstrap withheld"
  )
  check(
    WinsWinn3Settings.carrierExclusionPresent(in: full, config: config),
    "the carrier /32 SURVIVES the promotion; without it the default route captures the engine's own socket"
  )
  check(
    full.dnsSettings?.servers == ["10.13.0.9"],
    "the promoted posture installs the DERIVED inner resolver set, not the AmneziaWG [Interface] DNS line it happens to have been read from"
  )
  check(
    WinsWinn3PromotedPosture.evaluate(full, config: config).usable,
    "the promoted posture this provider builds passes the promotion check it will be given — the object is checked, not the builder trusted"
  )
  check(
    full.ipv6Settings != nil,
    "the promoted posture installs the IPv6 SINK: this session carries no inner v6, and drawing v6 into a tunnel that drops it is leak protection — leaving the host's own v6 in place would route every v6-capable app around the tunnel entirely"
  )
  check(
    full.ipv6Settings?.includedRoutes?.count == 1,
    "the v6 sink takes the default v6 route, which is the whole of what makes it a sink"
  )
  check(
    bootstrap.ipv6Settings == nil && full.ipv6Settings != nil,
    "IPv6 is claimed at PROMOTION and never at bootstrap: an unproven tunnel must not take the host's v6, and a proven one must not leave it outside"
  )
  check(
    full.mtu?.intValue == innerMTU,
    "the promoted posture keeps the inner MTU: promotion changes routes, never the packet size the engine sized its plan for"
  )
  check(
    !WinsWinn3BootstrapPosture.evaluate(
      full,
      requiredInnerMTU: innerMTU,
      carrierExclusionPresent: true
    ).narrow,
    "the FULL-TUNNEL posture is deliberately not narrow — if it passed the bootstrap check the two postures would be the same object"
  )

  // The status vocabulary a reader gets when a start refuses.
  let refused = winn3StandaloneConfig(removing: ["gateway_id"])
  let fields = WinsWinn3SessionStatus.startFields(
    config: refused,
    attempted: false,
    refusalReason: refused.winn3StartRefusalReason
  )
  check(
    fields["winn3_datapath_proof_standalone_start_attempted"] as? Bool == false,
    "a refused start records that it was never attempted"
  )
  check(
    fields["winn3_datapath_proof_unmet_requirement_count"] as? Int == 1,
    "the unmet-requirement count is published so a reader can tell one missing field from six"
  )
  check(
    (fields["winn3_datapath_proof_start_refusal_reason"] as? String)?.contains("gateway_id") == true,
    "the refusal reason survives into the status document"
  )

  let progress = WinsWinn3SessionStatus.progressFields(
    engineStatusFields: [
      WinsWinn3PromotionGate.gateStateKey: WinsWinn3PromotionGate.carryingState,
      WinsWinn3PromotionGate.rxPacketsKey: 7
    ],
    pumpStatusFields: ["winn3_datapath_proof_host_to_engine_packets": 3],
    probeAvailable: true,
    probesSent: 4,
    probeResponsesObserved: 1,
    elapsedMilliseconds: 900,
    deadlineMilliseconds: 25_000,
    promoted: false
  )
  check(
    progress["winn3_datapath_proof_converged"] as? Bool == true,
    "the progress document republishes the §4.1 verdict rather than a second opinion of it"
  )
  check(
    progress["winn3_datapath_proof_host_to_engine_packets"] as? Int == 3,
    "the pump's own counters travel with the engine's, because only the pump can see them"
  )
  check(
    progress["winn3_datapath_proof_probe_responses_observed"] as? Int == 1,
    "the probe response count is published beside the gate, since it is an additional requirement for promotion"
  )
  check(
    progress["winn_datapath_proof_transport_observed_both_ways"] == nil,
    "a standalone session does not publish the RELAY's proof vocabulary: those flags are false for a reason no reader could distinguish from failure"
  )
}

// MARK: - 9a. §4.4, the resolver a standalone session may install
//
// THE DEFECT THIS SECTION HOLDS SHUT
//
// `WinsWinn3Settings.fullTunnel` used to attach `config.dnsServers` whenever it
// was non-empty. That property is the AmneziaWG `[Interface] DNS` line, and
// `lib/main.dart:_nativeTunnelDnsServers` writes that line on Apple from a
// fallback that substitutes the PUBLIC Quad9 literals `9.9.9.9,
// 149.112.112.112` whenever the served DNS carries no public literal. So a
// standalone v3 session — which shares nothing with the v1 AmneziaWG stack —
// promoted with Quad9 as its resolver, routed into a tunnel whose gateway
// forwards nothing. Apple had no `dns_are_inner` gate of any kind, so nothing
// could notice.
//
// WHY THESE ARE REFUSALS AND NOT NARROWER DEFAULTS
//
// Measured on a live Linux kernel with the promoted `/1` pair installed:
// `ip route get` sends a LAN resolver out the PHYSICAL interface, because that
// interface's connected prefix is more specific than `/1`. Every DNS query
// keeps going to the resolver a censor operates, in the clear, while pages load
// and the gate reports success. A LEAK, not a stall — which is why
// windows/runner/winn3_posture.h refuses, and why this does.
//
// WHAT IS DELIBERATELY NOT TESTED HERE, BECAUSE IT MUST NOT EXIST
//
// There is no `[winn] dns` key and no `[winn] dns_are_inner` key. The predicate
// is DERIVED from the two inner facts the signed descriptor carries, and
// `winn3/conform` states why in one line: a transported boolean asserting "this
// resolver is inside the tunnel" is the leak wearing a flag.

// MARK: - 9b. the IPv6 sink, and the floor it may only be installed above
//
// THE DEFECT THIS SECTION HOLDS SHUT
//
// `WinsWinn3Settings.fullTunnel` installs an IPv6 sink — a /128 with
// `NEIPv6Route.default()` — so host IPv6 is drawn into the tunnel and dropped
// rather than left egressing on the physical interface beside a promoted IPv4
// tunnel. It has always installed it unconditionally, and until 2026-08-10 it
// installed it with NO MTU CHECK ANYWHERE IN THIS TREE: grepping `apple/`,
// `ios/` and `macos/` for `1280` found two test fixtures and one doc comment.
//
// That mattered because the fleet's default path MTU was 1280, which over the
// shipping migration plan yields an inner MTU of 1139 — below RFC 8200's floor
// for any link carrying IPv6. Measured on 2026-08-10 against a Linux tun
// device, `ip -6 address add fd00:d951:1::2/128` was refused at 576, 1138,
// 1139 and 1279 ("RTNETLINK answers: Invalid argument") and accepted at 1280
// and above. Apple's stack is not that kernel, but the sink's purpose fails
// either way: an IPv6 route onto a link narrower than the minimum every IPv6
// router may assume is a black hole, because IPv6 routers do not fragment.
//
// The default is now 1450, yielding 1309, which clears the floor. So this
// provider became correct by an arithmetic change made elsewhere, and these
// checks make it correct by construction instead.
//
// WHY BOTH A BUILDER GUARD AND A VERIFIER CLAUSE
//
// Measured by mutation on 2026-08-10, against private copies of these sources:
// removing EITHER guard alone left every one of these checks green, because the
// other one still refuses. Removing BOTH turned the three sub-floor cases red.
// They are kept as a pair, and the pair is stated here so the redundancy is a
// recorded decision rather than an accident the next mutation run rediscovers.
func runStandaloneIPv6SinkTests() {
  section("standalone IPv6: the sink, and the link floor it may only sit above")

  let config = winn3StandaloneConfig()

  check(
    WinsWinn3Settings.ipv6MinLinkMTU == 1280,
    "the floor is RFC 8200's 1280, and it now EXISTS in this tree — until 2026-08-10 no constant, guard or check in apple/, ios/ or macos/ mentioned it"
  )

  // Below the floor: refused, not installed and not silently skipped. Skipping
  // it is the leak Windows and Linux shipped until the same day — the IPv4
  // default route moves onto the tunnel while the host's own IPv6 address and
  // IPv6 default route stay on the physical interface.
  for narrow in [576, 1139, 1279] {
    check(
      WinsWinn3Settings.fullTunnel(config: config, innerMTU: narrow) == nil,
      "no promoted posture is built at an inner MTU of \(narrow): the sink would sit on a link below the IPv6 floor, and promoting without it would leave host IPv6 on the physical interface"
    )
  }

  // At and above the floor: the sink is installed, at Apple's own constant,
  // with exactly one route. The three MTUs are the plan floor at the fleet
  // default path MTU of 1450 over the three shipping migration plans —
  // [udp,tcp,tls], [udp,tcp] and udp alone — so this is the arithmetic that
  // actually reaches devices rather than a round number.
  for wide in [1280, 1309, 1331, 1373] {
    guard let settings = WinsWinn3Settings.fullTunnel(config: config, innerMTU: wide) else {
      check(false, "a promoted posture must build at an inner MTU of \(wide)")
      continue
    }
    check(
      settings.ipv6Settings?.addresses == [WinsTunnelConfig.ipv6SinkAddress],
      "inner MTU \(wide) installs the sink at Apple's own address, which is the address Android and the desktop hosts also sink to — three hosts blackholing at three addresses would be three behaviours wearing one name"
    )
    check(
      settings.ipv6Settings?.includedRoutes?.count == 1,
      "inner MTU \(wide) installs exactly one IPv6 route, the default: the sink captures v6 rather than sharing it with the physical interface"
    )
    check(
      settings.mtu?.intValue == wide,
      "inner MTU \(wide) is the interface MTU, so the guard and the interface cannot disagree"
    )
  }

  // THE VERIFIER, ASKED OF OBJECTS THE BUILDER CANNOT CURRENTLY PRODUCE.
  //
  // Same reasoning as the resolver clauses above and as `winn3_posture.h`'s own
  // unreachable self-check: the edit that makes these reachable — a split-tunnel
  // standalone mode, or any posture whose IPv6 capture is conditional — is
  // exactly the edit during which nobody is looking for them.
  guard let built = WinsWinn3Settings.fullTunnel(config: config, innerMTU: 1309) else {
    check(false, "the fixture must build a promoted posture at the fleet default inner MTU")
    return
  }
  check(
    WinsWinn3PromotedPosture.evaluate(built, config: config).usable,
    "a correctly sized promoted posture is usable, so the clauses below are refusing something specific rather than everything"
  )

  built.ipv6Settings = nil
  let stripped = WinsWinn3PromotedPosture.evaluate(built, config: config)
  check(
    !stripped.usable,
    "the SAME object with its IPv6 settings removed is refused on the object: this is the Windows and Linux leak reconstructed on Apple, and nothing here could see it before"
  )
  check(
    stripped.reasons.contains { $0.contains("no IPv6 settings") },
    "and the refusal names the missing IPv6 settings rather than firing for one of the resolver reasons"
  )

  guard let sized = WinsWinn3Settings.fullTunnel(config: config, innerMTU: 1309) else {
    check(false, "the fixture must build a second promoted posture")
    return
  }
  sized.mtu = NSNumber(value: 1139)
  let belowFloor = WinsWinn3PromotedPosture.evaluate(sized, config: config)
  check(
    !belowFloor.usable,
    "IPv6 settings on a 1139-byte interface are refused on the object: 1139 is what the OLD fleet default path MTU of 1280 produced over the shipping plan"
  )
  check(
    belowFloor.reasons.contains { $0.contains("1280") },
    "and the refusal names the floor, so an operator reading it knows which number to raise"
  )
}

func runStandaloneResolverTests() {
  section("standalone resolvers: which ones a session can justify, and what it does when it cannot")

  let config = winn3StandaloneConfig()

  // The derivation, positively. One resolver, inside the assignment's own /24,
  // neither the assignment nor the PMTU-only next hop.
  check(
    WinsWinn3Resolvers.candidates(config) == ["10.13.0.9"],
    "the candidate list is the host's ONE resolver source, named as what it is: the AmneziaWG [Interface] DNS line"
  )
  check(
    WinsWinn3Resolvers.notInnerReason("10.13.0.9", config: config) == nil,
    "a resolver inside the /24 around [winn] inner_v4 is derivable as inner"
  )
  check(
    WinsWinn3Resolvers.inner(config) == ["10.13.0.9"],
    "the derived inner set is the candidates that survive the derivation"
  )
  check(
    WinsWinn3Resolvers.areInner(config),
    "dns_are_inner is DERIVED true for a configuration whose every resolver is derivable"
  )
  check(
    WinsWinn3Resolvers.promotionRefusalReason(config) == nil,
    "such a configuration is not refused"
  )

  // THE SHIPPING DEFECT. This is exactly what lib/main.dart writes on Apple.
  let quad9 = winn3StandaloneConfig(interfaceDNS: "9.9.9.9,149.112.112.112")
  check(
    WinsWinn3Resolvers.inner(quad9).isEmpty,
    "NEITHER Quad9 literal survives the derivation: a public resolver is not inner by any reading"
  )
  check(
    WinsWinn3Resolvers.notInnerReason("9.9.9.9", config: quad9)?.contains("PUBLIC") == true,
    "the refusal for a public resolver NAMES it as public, so an operator reading it looks at the right line of lib/main.dart"
  )
  check(
    WinsWinn3Settings.fullTunnel(config: quad9, innerMTU: 1312) == nil,
    "no promoted posture is built for a configuration whose resolvers are the public Quad9 literals"
  )
  check(
    quad9.winn3StartRefusalReason != nil,
    "and the START is refused, so the outer socket is never opened for a session that could never promote"
  )
  check(
    WinsWinn3CreateDocument.make(config: quad9) == nil,
    "no create document is built either: the refusal lands before anything dials the gateway"
  )

  // A MIXED list. One derivable resolver does not license the public one beside
  // it: NEDNSSettings hands the whole list to the resolver library, and the
  // library picks. This is the clause that cannot be reached by any single-entry
  // fixture, and it is the reason the predicate is a claim about the LIST.
  let mixed = winn3StandaloneConfig(interfaceDNS: "10.13.0.9,9.9.9.9")
  check(
    WinsWinn3Resolvers.inner(mixed) == ["10.13.0.9"],
    "the derivation still identifies which member of a mixed list is inner"
  )
  check(
    !WinsWinn3Resolvers.areInner(mixed),
    "but dns_are_inner is DERIVED FALSE for the list as a whole, exactly as winn3_posture.h's single boolean is a claim over the whole of dns_servers"
  )
  check(
    WinsWinn3Settings.fullTunnel(config: mixed, innerMTU: 1312) == nil,
    "a mixed list is REFUSED rather than filtered: promoting on the survivors would leave the choice of resolver to the system, not to this code"
  )

  // THE ANDROID SIBLING VALUE, measured on Apple. `10.8.1.1` is the v1 inner
  // space; a standalone session's tun layer drops it.
  let v1Space = winn3StandaloneConfig(interfaceDNS: "10.8.1.1")
  check(
    WinsWinn3Resolvers.notInnerReason("10.8.1.1", config: v1Space) != nil,
    "a resolver in the v1 AmneziaWG inner space is not derivable as inner for a standalone session"
  )
  check(
    WinsWinn3Settings.fullTunnel(config: v1Space, innerMTU: 1312) == nil,
    "and it is refused: private is not the same as inside THIS tunnel"
  )

  // THE NEXT HOP. Documented as the inner next hop for PMTU signals only.
  let nextHop = winn3StandaloneConfig(interfaceDNS: "10.13.0.1")
  check(
    WinsWinn3Resolvers.notInnerReason("10.13.0.1", config: nextHop)?.contains("PMTU") == true,
    "naming [winn] inner_router_v4 as the resolver is refused, and the refusal says why: it answers no queries, so it would trade a leak for total name-resolution failure"
  )
  check(
    WinsWinn3Settings.fullTunnel(config: nextHop, innerMTU: 1312) == nil,
    "no promoted posture points name resolution at the PMTU-only next hop"
  )

  // THE ASSIGNMENT ITSELF. That address is this device.
  let selfResolver = winn3StandaloneConfig(interfaceDNS: "10.13.0.2")
  check(
    WinsWinn3Resolvers.notInnerReason("10.13.0.2", config: selfResolver) != nil,
    "a resolver pointed at this session's own inner assignment is refused: nothing answers there"
  )

  // A HOSTNAME. A resolver that must itself be resolved is the lookup outside
  // the tunnel this whole layer exists to prevent.
  let hostnameResolver = winn3StandaloneConfig(interfaceDNS: "dns.example.org")
  check(
    WinsWinn3Resolvers.notInnerReason("dns.example.org", config: hostnameResolver) != nil,
    "a hostname resolver is refused for the same reason [winn] endpoint refuses a hostname"
  )

  // NO RESOLVER AT ALL — the clause winn3_posture.h added on 2026-08-09, and
  // the state every served configuration is in today, because the signed
  // descriptor carries no resolver field.
  let none = winn3StandaloneConfig(interfaceDNS: "")
  check(
    WinsWinn3Resolvers.candidates(none).isEmpty,
    "a configuration with no [Interface] DNS offers no candidate resolver"
  )
  check(
    WinsWinn3Resolvers.promotionRefusalReason(none) != nil,
    "a promotion that would install NO resolver is REFUSED, not permitted: it widens the routes onto the tunnel and leaves name resolution where it was"
  )
  check(
    WinsWinn3Resolvers.promotionRefusalReason(none)?.contains("default route") == true,
    "and the refusal states the mechanism — the posture takes the default route, which does not beat the physical link's connected prefix"
  )
  check(
    WinsWinn3Settings.fullTunnel(config: none, innerMTU: 1312) == nil,
    "no promoted posture is built with an empty resolver set"
  )
  check(
    none.winn3StartRefusalReason != nil,
    "the START is refused, so a session that could never promote never dials the gateway from this device"
  )

  // THE BOOTSTRAP IS UNTOUCHED BY ALL OF THIS. A resolver in an unproven tunnel
  // breaks every lookup on the machine, so the narrow posture still installs
  // none — including for the configuration that has a perfectly good one.
  let bootstrap = WinsWinn3Settings.bootstrap(config: config, innerMTU: 1312)
  check(
    bootstrap.dnsSettings == nil,
    "a derivable resolver does NOT reach the bootstrap posture: §4.4's two postures move in opposite directions and both are required"
  )

  // The built-object check refuses what the builder would never produce, which
  // is the point of having it: it holds the edit that makes the builder produce
  // it. Both halves are exercised, because `default_route` and the resolver set
  // are two independent ways for a promoted posture to be useless.
  let noRoutes = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.51.100.7")
  let hostOnly = NEIPv4Settings(addresses: ["10.13.0.2"], subnetMasks: ["255.255.255.255"])
  hostOnly.includedRoutes = [
    NEIPv4Route(destinationAddress: "10.13.0.1", subnetMask: "255.255.255.255")
  ]
  noRoutes.ipv4Settings = hostOnly
  noRoutes.dnsSettings = NEDNSSettings(servers: ["10.13.0.9"])
  let capturesNothing = WinsWinn3PromotedPosture.evaluate(noRoutes, config: config)
  check(
    !capturesNothing.usable,
    "a promoted posture whose routes are all single hosts is refused: it would report carrying while every packet still left by the physical interface"
  )
  check(
    capturesNothing.reasons.contains { $0.contains("captures nothing") },
    "and the refusal says so in those words, because the symptom is that NOTHING IS BROKEN"
  )

  // A WIDE posture carrying resolvers, built by hand so each of the verifier's
  // three resolver clauses can be reached ALONE. Mutation testing on
  // 2026-08-09 found all three initially indistinguishable: each of these three
  // objects was refused by a clause other than the one it was written for, so
  // deleting any single clause survived the whole suite. The fixtures below are
  // the fix, and the reason strings are asserted rather than only the verdict —
  // a refusal that fires for the wrong reason is not the refusal that was
  // tested.
  func promotedObject(resolvers: [String]?) -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.51.100.7")
    let wide = NEIPv4Settings(addresses: ["10.13.0.2"], subnetMasks: ["255.255.255.255"])
    wide.includedRoutes = [NEIPv4Route.default()]
    settings.ipv4Settings = wide
    if let resolvers {
      settings.dnsSettings = NEDNSSettings(servers: resolvers)
    }
    return settings
  }

  let leaks = WinsWinn3PromotedPosture.evaluate(promotedObject(resolvers: ["9.9.9.9"]), config: config)
  check(
    !leaks.usable,
    "a promoted posture that took the default route and installed a PUBLIC resolver is refused on the object, not merely on the config that built it"
  )
  check(
    leaks.reasons.contains { $0.contains("cannot derive to be inner") },
    "and the object is re-derived RESOLVER BY RESOLVER, so the refusal names which one and why rather than only that the list was wrong"
  )

  check(
    !WinsWinn3PromotedPosture.evaluate(promotedObject(resolvers: nil), config: config).usable,
    "a promoted posture that took the default route and installed NO resolver is refused on the object"
  )
  // ISOLATES THE EMPTY CLAUSE. Against a configuration that also derives no
  // resolver, the set comparison sees [] == [] and the per-resolver loop has
  // nothing to walk, so only `installed.isEmpty` can fire. Without this the
  // clause was measurably dead: deleting it survived the suite.
  let emptyOnEmpty = WinsWinn3PromotedPosture.evaluate(
    promotedObject(resolvers: nil),
    config: none
  )
  check(
    !emptyOnEmpty.usable,
    "a promoted posture with no resolver is refused even when the configuration derives none either — the state EVERY served configuration is in today, and the one that must never quietly promote"
  )
  check(
    emptyOnEmpty.reasons.contains { $0.contains("installs no resolver") },
    "and the refusal is the empty-resolver one, not a set mismatch that happens to be true"
  )
  // ISOLATES THE SET COMPARISON. Every member is derivable and the list is
  // non-empty, so the other two clauses pass; only "this is not the derived
  // set" can fire. It is the clause that catches a builder which filtered
  // correctly and then attached a different array.
  let duplicated = WinsWinn3PromotedPosture.evaluate(
    promotedObject(resolvers: ["10.13.0.9", "10.13.0.9"]),
    config: config
  )
  check(
    !duplicated.usable,
    "a promoted posture whose resolvers are all derivable but are not EXACTLY the derived set is refused"
  )
  check(
    duplicated.reasons.contains { $0.contains("not the derived inner set") },
    "and it is refused as a set mismatch, which is the only clause that can see a builder that attached a different array"
  )

  // The status vocabulary. A reader has to be able to tell "a descriptor field
  // is missing" from "this configuration is complete and has no resolver a
  // standalone session could justify" — they are different conversations.
  let refusedFields = WinsWinn3SessionStatus.startFields(
    config: quad9,
    attempted: false,
    refusalReason: quad9.winn3StartRefusalReason
  )
  check(
    refusedFields["winn3_datapath_proof_resolver_candidate_count"] as? Int == 2,
    "the candidate count is published, so a reader sees the host HAD resolvers offered to it"
  )
  check(
    refusedFields["winn3_datapath_proof_resolvers_derived_inner_count"] as? Int == 0,
    "beside the derived count, which is what makes the refusal legible rather than mysterious"
  )
  check(
    refusedFields["winn3_datapath_proof_resolvers_derived_inner"] as? Bool == false,
    "and the derived predicate itself, which is the Apple spelling of dns_are_inner"
  )
  check(
    (refusedFields["winn3_datapath_proof_start_refusal_reason"] as? String)?
      .contains("derive") == true,
    "the refusal reason says the declaration is DERIVED, so nobody reads it as a missing field they could add to the [winn] section"
  )

  // The relay is untouched. It reads the same [Interface] DNS line and must
  // keep doing so: that line IS the relay's resolver, and this whole derivation
  // is about a different protocol.
  let relay = WinsTunnelConfig.parse(winn3Config("direct-awg"))
  check(
    WinsWinn3Resolvers.promotionRefusalReason(relay) == nil,
    "a RELAY configuration is not subject to the standalone resolver derivation at all"
  )
  check(
    !relay.dnsServers.isEmpty,
    "and its own resolvers are untouched: the relay still installs [Interface] DNS, which is its resolver and always was"
  )
}

// MARK: - 10. the outbound deanonymisation refusal, and the counter proving it
//
// `winn3_tx_dropped_invalid` is the count of packets the tun layer refused to
// carry with the gate OPEN — most importantly a packet whose source address
// this session was never assigned, which is precisely the packet that would
// have identified this host to anything watching past the gateway. Until it was
// published to the host the only way to show such a packet never left was a
// packet capture, which is not something a user in Myanmar can take on their
// phone and attach to a support ticket.
//
// WHAT THIS SECTION PROVES, AND WHAT IT CANNOT
//
// It proves the counter is PUBLISHED and readable by name on this platform, and
// it proves the fail-closed ORDERING that decides which counter a forged packet
// lands in. It does NOT show the deanonymisation validator incrementing it,
// and no harness without a gateway can: `winn3/tun.Tunnel.Outbound` takes the
// gate BEFORE it parses the packet —
//
//     if !t.gate.enter() { t.c.txDroppedClosed.Add(1); return ErrNotCarrying }
//     p, err := t.v.outbound(b)
//     if err != nil { t.c.txDroppedInvalid.Add(1); return err }
//
// — and that order is deliberate: "a closed gate produces exactly one
// observable effect, a counter increment, and zero bytes anywhere.
// Validate-then-gate would have the same return value and a path-MTU packet
// written to the host of a session that no longer exists." With no handshake
// the gate is never carrying, so the validator is never reached and the
// counter cannot move. Showing it move needs a session that is CARRYING, which
// needs a reachable winn/3 gateway.
//
// That is not a hole in the coverage the mutation asked for. The mutant is the
// ALLOWLIST ENTRY, and a host that cannot see the counter fails the presence
// check below whether or not anything ever incremented it.

func runOutboundRefusalTests() {
  section("outbound refusal: the counter proving a forged source never left")

  guard let carrier = loopbackCarrierDescriptor() else {
    check(false, "a loopback carrier descriptor is available for the refusal test")
    return
  }
  defer { close(carrier.listener) }

  let datapath = WinsWinn3Datapath()
  let document = baseDocument(gatewayEndpoint: carrier.endpoint)
  guard let data = try? JSONSerialization.data(withJSONObject: document),
        let json = String(data: data, encoding: .utf8) else {
    check(false, "the refusal-test create document encodes")
    return
  }
  do {
    try datapath.start(document: json, carrierDescriptor: carrier.fd)
  } catch {
    check(false, "the refusal test starts a winn3 handle over a loopback carrier (\(error))")
    return
  }
  defer { datapath.stop() }

  // PRESENCE, not value. See `hasEngineField`: a zero-comparison is satisfied
  // by a counter this platform has gone blind to, which is how this entry sat
  // uncovered while being published correctly end to end.
  let before = datapath.statusFields()
  check(
    hasEngineField(before, "winn3_tx_dropped_invalid"),
    "winn3_tx_dropped_invalid is PUBLISHED to the host — the only in-process evidence that a packet with an unassigned source address was refused before the wire, and the alternative is a packet capture nobody can take on a user's phone"
  )
  check(
    hasEngineField(before, "winn3_rx_dropped_invalid"),
    "its inbound twin is published beside it: a host holding only one of the pair reads the missing direction as a healthy tunnel"
  )
  check(
    integerField(before, "winn3_tx_dropped_invalid") == 0,
    "nothing has been refused before anything has been offered"
  )

  // A packet whose source address this session was NEVER ASSIGNED. The
  // assignment is 10.13.0.2; this is the deanonymising packet.
  let forged = (0..<2).map { _ in
    innerIPv4Packet(source: "198.51.100.9", destination: "10.13.0.1", payload: 48)
  }
  let relay = HarnessPacketRelay(batches: [forged])
  datapath.resume(relay: relay)

  var closed: UInt64 = 0
  let deadline = Date().addingTimeInterval(5.0)
  while Date() < deadline {
    closed = integerField(datapath.statusFields(), "winn3_tx_dropped_closed")
    if closed >= UInt64(forged.count) { break }
    usleep(20_000)
  }
  let after = datapath.statusFields()

  check(
    closed == UInt64(forged.count),
    "both forged packets reached the tun layer and were refused: winn3_tx_dropped_closed moved by \(forged.count) (saw \(closed))"
  )
  check(
    integerField(after, "winn3_tx_packets") == 0,
    "NOTHING WAS SENT: a packet carrying a source address this session was never assigned did not reach the wire"
  )
  // THE ORDERING. Under the shipping order the gate refuses first and the
  // validator is never reached, so the forged packets land in _closed and
  // _invalid stays 0. Under validate-then-gate they would land in _invalid
  // instead — so this pins which of the two the fail-closed path uses, and it
  // is the assertion that fails if that order is ever swapped.
  check(
    integerField(after, "winn3_tx_dropped_invalid") == 0,
    "the GATE refused first, before the packet was parsed: a shut gate produces one counter increment and zero bytes anywhere, which is why _closed moved and _invalid did not"
  )
  check(
    hasEngineField(after, "winn3_tx_dropped_invalid"),
    "the counter is still published after traffic, so a reader cannot mistake a blind host for a host with nothing to report"
  )
}

// MARK: - 11. every winn/3 field the allowlist claims to publish, by NAME
//
// THE DEFECT CLASS THIS SECTION EXISTS TO CLOSE
//
// `WinsWinnSeamObservabilitySample` allowlists twenty `winn3_*` keys, and until
// 2026-08-09 deleting fourteen of them from that allowlist did not fail this
// harness. A mutation run that afternoon deleted each of the twenty in turn:
// six failed, fourteen passed at a clean 207/207. The host would simply have
// gone blind to those counters and nothing here would have said so.
//
// The mechanism is exact and it is worth stating, because it is easy to write
// a new assertion that has the same hole. `integerField` is
// `WinsWinn3PromotionGate.unsignedValue(fields[prefix + suffix])`, and
// `unsignedValue(nil)` is 0. So `integerField(f, "winn3_x") == 0` is satisfied
// by a counter published as zero AND by a counter that is not published at
// all. Every field whose only mention in this file was a zero-comparison was
// therefore uncovered — `winn3_tx_packets` among them, which is named
// literally three times and was still a survivor. A value assertion can never
// catch this. Only a PRESENCE assertion can, which is what `hasEngineField`
// is for and what this section is built from.
//
// WHY THE LIST BELOW IS WRITTEN OUT AND NOT DERIVED
//
// Deriving it from `WinsWinnSeamObservabilitySample.engineIntegerFields` would
// be shorter and would prove nothing: deleting an allowlist entry would also
// shrink the loop, every remaining assertion would pass, and the harness would
// be green about a host that had gone blind. The names are literals here for
// the same reason the mutation is meaningful.
//
// WHAT IS PROVED, AND WHAT IS ONLY PROVED PRESENT
//
// PRESENT, not moving, for all but one of these. `winn3/tun.Tunnel.Outbound`
// takes the gate BEFORE it parses the packet, so with no handshake the gate is
// never carrying, the validator is never reached and nothing downstream of it
// can increment. Only `winn3_tx_dropped_closed` moves in a gateway-less
// harness — §10 above moves it and asserts the movement — and every inbound
// counter needs a reachable winn/3 gateway to move at all. That is a limit of
// the harness, not of the assertion: the mutant here is the ALLOWLIST ENTRY,
// and a host that cannot see a counter fails a presence check whether or not
// anything ever incremented it.

/// The winn/3 keys a live `statusFields()` document actually carries, each with
/// the question a reader answers with it.
///
/// TWENTY — the allowlist's full set, as of 2026-08-09.
///
/// It read "seventeen, not the allowlist's twenty" until the three keys the
/// sampler ate were renamed past the tokens that were killing them. Those three
/// are now the last three entries below, and the section that used to assert
/// they NEVER REACH THE HOST has become `runAllowlistDenylistCollisionGuard()`
/// — a guard over the whole allowlist rather than three hard-coded exceptions.
/// The exceptions are gone because the defect is gone, not because the
/// assertions were deleted to make a red run green.
let publishedWinn3EngineFields: [(String, String)] = [
  ("winn3_gate_state", "WHY a promotion has not happened yet — six states, only one of which carries"),
  ("winn3_may_carry", "the same gate as a boolean, the DIAGNOSTIC half of the promotion pair"),
  ("winn3_carrier_class", "which transport the carrier rode: udp, tcp or tls, and therefore which overhead sized the plan"),
  ("winn3_inner_mtu", "the number §4.2 requires the interface MTU to equal exactly"),
  ("winn3_plan_message_size", "the message floor the plan was sized to, which is how an MTU complaint is told from a plan complaint"),
  ("winn3_rx_packets", "DELIVERIES — the §4.1 promotion counter itself"),
  ("winn3_rx_offered", "ARRIVALS — published beside deliveries so a host gating on the wrong one is visibly wrong"),
  ("winn3_rx_bytes", "inbound volume, which separates a tunnel carrying nothing from one carrying keepalives"),
  ("winn3_tx_packets", "what reached the wire, as distinct from what the host offered"),
  ("winn3_tx_bytes", "outbound volume, the other half of the same distinction"),
  ("winn3_tx_dropped_closed", "the shut gate refusing outbound: one counter increment and zero bytes anywhere"),
  ("winn3_rx_dropped_closed", "the shut gate refusing inbound, and the only in-process evidence that an arriving packet was not delivered"),
  ("winn3_tx_dropped_invalid", "the OUTBOUND deanonymisation refusal: gate open, packet refused, most often a source address this session was never assigned"),
  ("winn3_rx_dropped_invalid", "its inbound twin — a host holding one of the pair reads the missing direction as a healthy tunnel"),
  ("winn3_messages_sent", "carrier-level messages out, which move during a handshake the tun counters cannot see"),
  ("winn3_messages_received", "carrier-level messages in, which is how a gateway that answers nothing is told from one that is unreachable"),
  ("winn3_migrations", "carrier migrations, the count that explains a session that survived a path change"),
  // The three that were renamed on 2026-08-09 so the sampler would stop eating
  // them. Each was allowlisted, forwarded by both host apps, and dropped by
  // `sanitizedRuntimeFields` before any reader saw it.
  ("winn3_plan_mtu_ceiling", "the largest carrier datagram the plan may emit — was winn3_plan_path_mtu, eaten on its `path` token"),
  ("winn3_queue_dropped_outbound", "outbound ring overflow — was winn3_host_queue_dropped_outbound, eaten on its `host` token"),
  ("winn3_queue_dropped_inbound", "inbound ring overflow, and the ONLY evidence the host-side ring dropped packets at all — was winn3_host_queue_dropped_inbound, eaten on its `host` token"),
  // Round A3: the supervised engine's lifecycle, which every started handle
  // publishes (`connecting` before proof).
  ("winn3_lifecycle", "the supervised engine's recovery state, which decides whether the host may claim connected at all")
]

/// Allowlisted winn/3 keys a healthy live document does NOT carry, each with
/// the condition that publishes it. They are excluded from the promised-and-
/// received comparison below by NAME, never by pattern, and the lifecycle
/// harness (`tools/verify_apple_winn3_lifecycle.sh`) drives each condition.
let conditionallyPublishedWinn3EngineFields: [(String, String)] = [
  ("winn3_lifecycle_cause", "only beside `blocked`"),
  ("winn3_lifecycle_invalid", "only for a document whose lifecycle is present but not in the vocabulary"),
  ("winn3_lifecycle_cause_invalid", "only for a document whose cause is present but not in the vocabulary")
]

// MARK: - 11a. THE GUARD: no allowlisted key may collide with a denied token
//
// WHAT THIS REPLACED, AND WHY THAT IS NOT A DELETION
//
// Until 2026-08-09 this spot held `deniedWinn3EngineFields` — three keys pinned
// as "in the allowlist, and NEVER RECEIVED by the host":
// `winn3_plan_path_mtu` (denied on its `path` token),
// `winn3_host_queue_dropped_outbound` and `winn3_host_queue_dropped_inbound`
// (both denied on `host`). Both host apps forwarded all three; the host got
// none of them. One of them was the only evidence the host-side ring had
// dropped packets, so host-side packet loss on Apple was unobservable.
//
// They were RENAMED past the tokens — see the last three entries of
// `publishedWinn3EngineFields` — so the exceptions no longer exist to pin. The
// three-key list is gone because the defect is gone. What replaced it is
// strictly stronger: a guard over the WHOLE allowlist, so the next counter
// someone names `*_host_*` or `*_path_*` fails HERE, loudly, instead of
// vanishing silently the way these three did for as long as they existed.
//
// WHY IT DRIVES THE REAL SANITIZER INSTEAD OF RE-LISTING THE TOKENS
//
// `deniedRuntimeStatusFragments` is private to
// `WinsPacketTunnelEngineRuntimeStatus`, and copying its thirteen tokens here
// would create a second list that drifts from the one that actually decides —
// which is the same "two lists, one authority" failure the seam prefix comment
// warns about. So this feeds each allowlisted key through
// `sanitizedRuntimeFields` itself, the exact function the sampler ends with,
// and asserts the key comes back out. That also covers the length cap and the
// legal-character rule for free, not just the denylist.

/// Feeds one key through the REAL sampler filter and reports whether it
/// survives. `sanitizedRuntimeFields` keeps a key only if `safeRuntimeStatusKey`
/// accepts it, so a key that does not come back is a key no host can ever read.
func keySurvivesSampler(_ key: String) -> Bool {
  WinsPacketTunnelEngineRuntimeStatus.sanitizedRuntimeFields([key: 1])[key] != nil
}

/// The token that got a key rejected, when one can be identified.
///
/// Derived by probing, not by re-listing: each token of the key is offered to
/// the same sanitizer as `engine_runtime_<token>`, which is a well-formed key in
/// every other respect, so a probe that does not survive names a denied token.
/// Nothing here needs `deniedRuntimeStatusFragments` to be visible, and nothing
/// here can drift from it.
func deniedTokenIn(_ key: String) -> String? {
  key.split(whereSeparator: { $0 == "_" || $0 == "-" })
    .map(String.init)
    .first { !keySurvivesSampler("engine_runtime_" + $0) }
}

func runAllowlistDenylistCollisionGuard() {
  section("guard: every allowlisted key survives the sampler's own filter")

  let keys = WinsWinnSeamObservabilitySample.publishedStatusKeys
  check(!keys.isEmpty, "the published-key allowlist is non-empty, so the guard below has something to guard")

  var collisions: [String] = []
  for key in keys where !keySurvivesSampler(key) {
    collisions.append(
      deniedTokenIn(key).map { "\(key) (denied token `\($0)`)" } ?? "\(key) (rejected, token not isolated)"
    )
  }

  check(
    collisions.isEmpty,
    "NO allowlisted key is eaten by sanitizedRuntimeFields"
      + (collisions.isEmpty
         ? " — all \(keys.count) survive"
         : """
            — these are allowlisted, forwarded by both host apps, and DROPPED \
           before any reader sees them: \(collisions.sorted()). RENAME the key \
           past the token in the Go json tag and the Swift allowlist together. \
           Do NOT widen deniedRuntimeStatusFragments: it keeps endpoints, \
           hostnames and file paths out of a document a bug report carries.
           """)
  )

  // The guard must be able to FAIL. A collision check that cannot detect a
  // collision is the same false comfort as the zero-comparison assertions
  // described at the top of §11, so the detector is exercised against a key
  // that is known to collide — the `path` spelling this lane removed.
  check(
    !keySurvivesSampler(WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_plan_path_mtu"),
    "the guard's detector works: the pre-rename spelling winn3_plan_path_mtu is still rejected by the sampler"
  )
  check(
    deniedTokenIn(WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_host_queue_dropped_inbound") == "host",
    "the guard names the offending token: the pre-rename spelling is identified as colliding on `host`"
  )
}

func runPublishedFieldCoverageTests() {
  section("published fields: every winn/3 counter the host can see, asserted BY NAME")

  guard let carrier = loopbackCarrierDescriptor() else {
    check(false, "a loopback carrier descriptor is available for the field-coverage test")
    return
  }
  defer { close(carrier.listener) }

  let datapath = WinsWinn3Datapath()
  let document = baseDocument(gatewayEndpoint: carrier.endpoint)
  guard let data = try? JSONSerialization.data(withJSONObject: document),
        let json = String(data: data, encoding: .utf8) else {
    check(false, "the field-coverage create document encodes")
    return
  }
  do {
    try datapath.start(document: json, carrierDescriptor: carrier.fd)
  } catch {
    check(false, "the field-coverage test starts a winn3 handle over a loopback carrier (\(error))")
    return
  }
  defer { datapath.stop() }

  // A LIVE document from the real archive — not a synthetic dictionary. The
  // promotion tests in §4 exercise `winn3_gate_state`, `winn3_rx_packets`,
  // `winn3_rx_offered` and `winn3_may_carry` against hand-built dictionaries,
  // and a dictionary this file built cannot show whether the SAMPLER published
  // the key. Only a document that came out of the engine can.
  let live = datapath.statusFields()

  for (key, why) in publishedWinn3EngineFields {
    check(
      hasEngineField(live, key),
      "\(key) is PUBLISHED to the host — \(why)"
    )
  }

  // The whole SET, so a counter added to the Go document and the allowlist
  // without being registered here cannot arrive unwatched, and so a deletion
  // fails twice rather than once.
  let winn3Prefix = WinsWinnSeamObservabilitySample.engineFieldPrefix + "winn3_"
  let observed = Set(live.keys.filter { $0.hasPrefix(winn3Prefix) })
  let expected = Set(
    publishedWinn3EngineFields.map {
      WinsWinnSeamObservabilitySample.engineFieldPrefix + $0.0
    }
  )
  let prefixLength = WinsWinnSeamObservabilitySample.engineFieldPrefix.count
  let missing = expected.subtracting(observed).map { String($0.dropFirst(prefixLength)) }.sorted()
  let arrived = observed.subtracting(expected).map { String($0.dropFirst(prefixLength)) }.sorted()
  check(
    missing.isEmpty && arrived.isEmpty,
    "the published winn/3 key set is EXACTLY the twenty-one named above"
      + (missing.isEmpty ? "" : " — MISSING \(missing)")
      + (arrived.isEmpty ? "" : " — UNREGISTERED \(arrived)")
  )

  // The set above is what the host RECEIVED. This is what the allowlist
  // PROMISED. They were different until 2026-08-09 — twenty promised, seventeen
  // delivered — and nothing failed, because the two counts were never compared.
  // Comparing them is what makes a future sampler-eaten key impossible to miss
  // even if someone forgets to register it in `publishedWinn3EngineFields`.
  let conditional = Set(
    conditionallyPublishedWinn3EngineFields.map {
      WinsWinnSeamObservabilitySample.engineFieldPrefix + $0.0
    }
  )
  let allowlistedWinn3 = Set(
    WinsWinnSeamObservabilitySample.publishedStatusKeys.filter { $0.hasPrefix(winn3Prefix) }
  ).subtracting(conditional)
  let promisedNotDelivered = allowlistedWinn3.subtracting(observed)
    .map { String($0.dropFirst(prefixLength)) }.sorted()
  check(
    promisedNotDelivered.isEmpty,
    "every winn/3 key the allowlist PROMISES is a key the host actually RECEIVES"
      + (promisedNotDelivered.isEmpty
         ? " — \(allowlistedWinn3.count) promised, \(observed.count) received"
         : " — PROMISED BUT EATEN \(promisedNotDelivered)")
  )

  // The same set after traffic. A sampler that publishes a key at zero and
  // drops it once it moves — a coercion that only bites a non-zero value, a
  // string rule that only bites a changed gate state — is the same blindness
  // arriving later, and a document sampled once at rest cannot see it.
  let packets = (0..<3).map { _ in
    innerIPv4Packet(source: "10.13.0.2", destination: "10.13.0.1", payload: 64)
  }
  let relay = HarnessPacketRelay(batches: [packets])
  datapath.resume(relay: relay)
  var moved: UInt64 = 0
  let deadline = Date().addingTimeInterval(5.0)
  while Date() < deadline {
    moved = integerField(datapath.statusFields(), "winn3_tx_dropped_closed")
    if moved >= UInt64(packets.count) { break }
    usleep(20_000)
  }
  let afterTraffic = datapath.statusFields()
  check(
    moved >= UInt64(packets.count),
    "the field-coverage session moved a counter, so the sample below is of a tunnel that has done something"
  )
  check(
    Set(afterTraffic.keys.filter { $0.hasPrefix(winn3Prefix) }) == observed,
    "the published key set is UNCHANGED after traffic: a host that could read a counter at rest can still read it once it moves"
  )
}

func runWinn3NativeStartOutcomeTests() {
  section("native start outcome: generation-bound, typed, fail-closed")
  let failures = WinsWinn3NativeStartOutcomeContract.failures()
  check(
    failures.isEmpty,
    "typed start outcomes are generation-bound and unknown/security failures cannot authorize v1"
      + (failures.isEmpty ? "" : " — " + failures.joined(separator: "; "))
  )
  check(
    !WinsWinn3NativeStartOutcome.connected.authorizesV1Fallback,
    "connected does not authorize v1"
  )
  check(
    WinsWinn3NativeStartOutcome.ordinaryConnectivity.authorizesV1Fallback,
    "only ordinary_connectivity authorizes v1"
  )
  check(
    !WinsWinn3NativeStartOutcome.terminalSecurity.authorizesV1Fallback
      && !WinsWinn3NativeStartOutcome.unknownTerminal.authorizesV1Fallback,
    "terminal_security and unknown_terminal cannot authorize v1"
  )
}

@main
struct WinsAppleWinn3HostContractHarness {
  static func main() {
    runNameTests()
    runCreateRefusalTests()
    runStatusTests()
    runPromotionTests()
    runBootstrapPostureTests()
    runConfigTests()
    runCreateDocumentTests()
    runStandaloneStartTests()
    runCreateDocumentFromConfigTests()
    runStandalonePostureTests()
    runStandaloneResolverTests()
    runStandaloneIPv6SinkTests()
    runPumpTests()
    runOutboundRefusalTests()
    runPublishedFieldCoverageTests()
    runAllowlistDenylistCollisionGuard()
    runWinn3NativeStartOutcomeTests()

    print("")
    if failures.isEmpty {
      print("Apple winn3 host-contract harness passed: \(passed)/\(passed) checks.")
      exit(0)
    }
    print("Apple winn3 host-contract harness FAILED: \(failures.count) of \(passed + failures.count) checks.")
    for failure in failures {
      print("  FAIL  \(failure)")
    }
    exit(1)
  }
}
