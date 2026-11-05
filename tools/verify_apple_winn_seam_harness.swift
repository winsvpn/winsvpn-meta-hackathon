// Apple Winn seam integration harness.
//
// Links the REAL apple/WinsTunnelCore Swift host, the REAL
// apple/EngineWrappers/WinsWinnPacketEngine.m, and the REAL Go c-archive
// (libwinn-datapath-darwin-arm64.a) into one process, and drives the actual
// WinsNativePacketTunnelEngine start path. Only AmneziaWG is stubbed, because
// wgTurnOn() needs a utun device that does not exist outside an appex.

import Darwin
import Foundation

@_silgen_name("wins_test_captured_awg_uapi")
func wins_test_captured_awg_uapi() -> UnsafePointer<CChar>?

@_silgen_name("wins_test_reset_awg_stub")
func wins_test_reset_awg_stub()

@_silgen_name("wins_test_awg_create_calls")
func wins_test_awg_create_calls() -> Int32

@_silgen_name("wins_test_awg_start_calls")
func wins_test_awg_start_calls() -> Int32

@_silgen_name("wins_test_awg_stop_calls")
func wins_test_awg_stop_calls() -> Int32

@_silgen_name("wins_test_awg_destroy_calls")
func wins_test_awg_destroy_calls() -> Int32

struct HarnessError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}

var passed = 0

func check(_ condition: Bool, _ label: String) throws {
  guard condition else { throw HarnessError("FAIL: \(label)") }
  passed += 1
  print("  ok  \(label)")
}

// MARK: - UDP helpers

func makeLoopbackUDPSocket() throws -> (fd: Int32, port: UInt16) {
  let fd = socket(AF_INET, SOCK_DGRAM, 0)
  guard fd >= 0 else { throw HarnessError("socket() failed") }
  var address = sockaddr_in()
  address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
  address.sin_family = sa_family_t(AF_INET)
  address.sin_port = 0
  address.sin_addr.s_addr = inet_addr("127.0.0.1")
  let bound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
      bind(fd, raw, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
  }
  guard bound == 0 else {
    close(fd)
    throw HarnessError("bind() failed: \(String(cString: strerror(errno)))")
  }
  var bound_address = sockaddr_in()
  var length = socklen_t(MemoryLayout<sockaddr_in>.size)
  let named = withUnsafeMutablePointer(to: &bound_address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
      getsockname(fd, raw, &length)
    }
  }
  guard named == 0 else {
    close(fd)
    throw HarnessError("getsockname() failed")
  }
  var timeout = timeval(tv_sec: 3, tv_usec: 0)
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
  return (fd, UInt16(bigEndian: bound_address.sin_port))
}

func send(_ payload: [UInt8], from fd: Int32, toPort port: UInt16) throws {
  var address = sockaddr_in()
  address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
  address.sin_family = sa_family_t(AF_INET)
  address.sin_port = port.bigEndian
  address.sin_addr.s_addr = inet_addr("127.0.0.1")
  let sent = payload.withUnsafeBufferPointer { buffer in
    withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
        sendto(fd, buffer.baseAddress, buffer.count, 0, raw, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
  }
  guard sent == payload.count else {
    throw HarnessError("sendto() wrote \(sent) of \(payload.count)")
  }
}

/// Receives one datagram, or nil on timeout. Also reports the sender's port.
func receive(on fd: Int32) -> (payload: [UInt8], port: UInt16)? {
  var buffer = [UInt8](repeating: 0, count: 4096)
  var address = sockaddr_in()
  var length = socklen_t(MemoryLayout<sockaddr_in>.size)
  let count = buffer.withUnsafeMutableBufferPointer { raw -> Int in
    withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddress in
        recvfrom(fd, raw.baseAddress, raw.count, 0, sockaddress, &length)
      }
    }
  }
  guard count > 0 else { return nil }
  return (Array(buffer[0..<count]), UInt16(bigEndian: address.sin_port))
}

// MARK: - Fixtures

// Deterministic public test material: the base64 encoding of bytes 0...31.
// The real WinsTunnelConfig validator refuses redaction sentinels and any
// value that is not 32-byte base64 (code 1101). This is the same non-secret
// fixture tools/verify_apple_tunnel_config.swift uses.
let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func baseConfig(peerEndpoint: String = "203.0.113.10:9110") -> String {
  """
  [Interface]
  PrivateKey = \(key)
  Address = 10.8.0.2/32
  MTU = 1280
  DNS = 10.8.0.1
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
  PublicKey = \(key)
  Endpoint = \(peerEndpoint)
  AllowedIPs = 0.0.0.0/0, ::/0
  PersistentKeepalive = 25
  """
}

func winnSection(endpoint: String) -> String {
  """

  [Winn]
  Enabled = true
  Endpoint = \(endpoint)
  Session_Id = harness-session
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

func endpointLine(_ uapi: String) -> String? {
  uapi.components(separatedBy: "\n").first { $0.hasPrefix("endpoint=") }
}

// MARK: - Tests

func runConfigTests() throws {
  print("\n[config] carrier selection and the exclusion-route trap")

  try check(
    Data(base64Encoded: key)?.count == 32 && !key.contains("REDACTED") && !key.hasPrefix("<"),
    "the seam fixture is 32-byte base64 non-secret test material, not a redaction sentinel"
  )

  // 1. AmneziaWG-only configs are untouched by every change here.
  // parseAndValidate is the real validator: acceptance here is the proof the
  // deterministic fixture is structurally valid.
  let plain = try WinsTunnelConfig.parseAndValidate(baseConfig())
  try check(
    plain.interfacePrivateKey == key,
    "the real validator accepted the deterministic non-secret interface private key"
  )
  try check(plain.winnEnabled == false, "a config with no [winn] section is not Winn")
  try check(
    plain.requiredEngineComponents == ["amneziawg_packet_engine"],
    "an AmneziaWG-only config still requires exactly the AmneziaWG engine"
  )
  try check(plain.transportMode == "amneziawg", "an AmneziaWG-only config still reports transport_mode=amneziawg")
  try check(
    plain.transportEndpointHost == "203.0.113.10",
    "an AmneziaWG-only config still derives its transport host from the peer endpoint"
  )

  // 2. A Winn config requires BOTH engines, with AmneziaWG first so the tun
  //    owner resolves to AmneziaWG and never to Winn.
  let winn = try WinsTunnelConfig.parseAndValidate(
    baseConfig() + winnSection(endpoint: "198.51.100.7:51820")
  )
  try check(winn.winnEnabled, "a [winn] section with enabled=true is Winn")
  try check(
    winn.packetCarrierComponent == "amneziawg_packet_engine",
    "Winn does NOT replace AmneziaWG as the packet carrier"
  )
  try check(
    winn.requiredEngineComponents == ["amneziawg_packet_engine", "winn_packet_engine"],
    "a Winn config requires both engines, AmneziaWG first"
  )
  try check(winn.transportMode == "winn", "a Winn config reports transport_mode=winn")

  // 3. THE TRAP. The /32 must follow the [winn] endpoint, not the AWG peer.
  try check(
    winn.transportEndpointHost == "198.51.100.7",
    "the transport host is the [winn] gateway, not the AmneziaWG peer"
  )
  guard let route = winn.transportIPv4ExclusionRoute else {
    throw HarnessError("FAIL: a full-tunnel Winn config produced no transport exclusion route")
  }
  try check(
    route.destinationAddress == "198.51.100.7" && route.prefixLength == 32,
    "the exclusion route is a /32 for the Winn gateway"
  )
  try check(
    winn.networkSettingsRemoteAddress == "198.51.100.7",
    "the NetworkExtension remote address is the Winn gateway"
  )

  // 4. Refusals.
  func expectInvalid(_ raw: String, code: Int, _ label: String) throws {
    do {
      _ = try WinsTunnelConfig.parseAndValidate(raw)
      throw HarnessError("FAIL: \(label) was accepted")
    } catch let error as WinsTunnelValidationError {
      try check(error.code == code, "\(label) is refused with code \(code) (got \(error.code))")
    }
  }

  try expectInvalid(
    baseConfig() + "\n[Winn]\nEnabled = true\n",
    code: 1503,
    "a Winn config with no gateway endpoint"
  )
  try expectInvalid(
    baseConfig() + winnSection(endpoint: "gw.example.invalid:51820"),
    code: 1503,
    "a Winn gateway that is a hostname rather than an IP literal"
  )
  try expectInvalid(
    baseConfig() + winnSection(endpoint: "127.0.0.1:51820"),
    code: 1504,
    "a Winn gateway that is loopback (the dead-loop the /32 exists to stop)"
  )
  try expectInvalid(
    baseConfig() + winnSection(endpoint: "127.0.0.9:51820"),
    code: 1504,
    "a Winn gateway elsewhere in 127.0.0.0/8"
  )
  try expectInvalid(
    baseConfig(peerEndpoint: "127.0.0.1:42110") + winnSection(endpoint: "198.51.100.7:51820"),
    code: 1505,
    "a Winn config whose AmneziaWG peer is already loopback"
  )
  // The outer-transport downgrade. This Apple ABI builds direct-awg and
  // http3-connect-udp (given a carrier profile — proven in
  // runDowngradeTests() and runCarrierProfileTests()); every other carrier
  // must still fail rather than quietly run plain UDP. http2-stream is named
  // explicitly rather than folded into "any unknown carrier": the engine
  // implements it, but its dialer needs a connected, protected TCP socket
  // this host does not open, so it is refused for a host-capability reason,
  // not a protocol one — the same distinction Android and Linux draw.
  for carrier in ["http2-stream", "masque", "HTTP2-STREAM"] {
    try expectInvalid(
      baseConfig() + winnSection(endpoint: "198.51.100.7:51820") + "\nCarrier = \(carrier)\n",
      code: 1506,
      "a [winn] carrier of \(carrier), which this ABI cannot build"
    )
  }
  let explicitDirect = try WinsTunnelConfig.parseAndValidate(
    baseConfig() + winnSection(endpoint: "198.51.100.7:51820") + "\nCarrier = direct-awg\n"
  )
  try check(explicitDirect.winnEnabled, "an explicit direct-awg carrier is accepted")

  // WIDENED BY NAME: http3-connect-udp is now a carrier THIS VALIDATOR names
  // rather than refuses. It is deliberately NOT this INI validator's job to
  // decide whether a carrier PROFILE exists and is complete for it — that
  // question depends on this device's App Group container, which is not a
  // property of the served config, so it is answered by
  // WinsPacketTunnelEngine.start() instead. See runDowngradeTests() and
  // supportedWinnCarriers's doc comment in WinsTunnelConfig.swift.
  for carrier in ["http3-connect-udp", "HTTP3-CONNECT-UDP"] {
    let explicitHttp3 = try WinsTunnelConfig.parseAndValidate(
      baseConfig() + winnSection(endpoint: "198.51.100.7:51820") + "\nCarrier = \(carrier)\n"
    )
    try check(
      explicitHttp3.winnEnabled,
      "an explicit \(carrier) carrier is accepted at validate() time, case-insensitively"
    )
  }

  let xrayPlusWinn = """
  [Interface]
  PrivateKey = \(key)
  Address = 10.8.0.2/32
  MTU = 1280
  DNS = 10.8.0.1
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
  PublicKey = \(key)
  Endpoint = 127.0.0.1:42110
  AllowedIPs = 0.0.0.0/0, ::/0
  PersistentKeepalive = 25

  [Xray]
  Enabled = true
  Uuid = 8b6f3a0e-2c11-4d3a-9f5e-7a1b2c3d4e5f
  Host = 198.51.100.22
  Port = 443
  ServerName = 198.51.100.22
  Path = /ws
  Security = tls
  LocalPort = 42110
  RemoteAwgHost = 127.0.0.1
  RemoteAwgPort = 9110
  """ + winnSection(endpoint: "198.51.100.7:51820")
  try expectInvalid(
    xrayPlusWinn,
    code: 1502,
    "Winn and the Xray stealth transport in one config"
  )

  // 5. The UAPI rewrite itself.
  let uapi = try winn.amneziaWGUAPIConfiguration()
  try check(
    endpointLine(uapi) == "endpoint=203.0.113.10:9110",
    "the unrewritten UAPI still names the real AmneziaWG gateway"
  )
  guard let repointed = WinsTunnelConfig.amneziaWGUAPIConfiguration(
    uapi,
    rewritingEndpointTo: "127.0.0.1:65000"
  ) else {
    throw HarnessError("FAIL: a well-formed UAPI document could not be repointed")
  }
  try check(
    endpointLine(repointed) == "endpoint=127.0.0.1:65000",
    "the repointed UAPI names the seam"
  )
  try check(
    repointed.components(separatedBy: "\n").filter { $0.hasPrefix("endpoint=") }.count == 1,
    "repointing produces exactly one endpoint line"
  )
  try check(
    repointed.components(separatedBy: "\n").count == uapi.components(separatedBy: "\n").count,
    "repointing changes no other line"
  )
  try check(
    repointed.replacingOccurrences(of: "endpoint=127.0.0.1:65000", with: "endpoint=203.0.113.10:9110") == uapi,
    "repointing is byte-identical to the original apart from the endpoint line"
  )
  try check(
    WinsTunnelConfig.amneziaWGUAPIConfiguration("private_key=aa\n", rewritingEndpointTo: "127.0.0.1:1") == nil,
    "a UAPI document with NO endpoint line is refused, not quietly appended to"
  )
  try check(
    WinsTunnelConfig.amneziaWGUAPIConfiguration(
      "endpoint=a:1\nendpoint=b:2\n", rewritingEndpointTo: "127.0.0.1:1"
    ) == nil,
    "a UAPI document with two endpoint lines is refused"
  )
  try check(
    WinsTunnelConfig.amneziaWGUAPIConfiguration(uapi, rewritingEndpointTo: "127.0.0.1") == nil,
    "a portless replacement endpoint is refused"
  )
}

func runEngineTests() throws {
  print("\n[engine] real Go archive, real ObjC wrapper, real Swift host")

  let gateway = try makeLoopbackUDPSocket()
  defer { close(gateway.fd) }

  // The [winn] endpoint is loopback here ONLY because the fake gateway has to
  // live on this machine. `validate()` refuses a loopback gateway in
  // production, which runConfigTests() proves, so this config is built with
  // parse() rather than parseAndValidate().
  let config = WinsTunnelConfig.parse(
    baseConfig() + winnSection(endpoint: "127.0.0.1:\(gateway.port)")
  )
  try check(config.winnEnabled, "the harness config is a Winn config")

  wins_test_reset_awg_stub()
  let packetFlow = NSObject()
  let engine = WinsPacketTunnelEngineFactory.makeEngine(
    config: config,
    packetFlow: packetFlow,
    adapter: WinsNativePacketTunnelEngineAdapter(bundle: .main)
  )
  try check(
    engine.plan.bundleProbe.allRequiredComponentsPresent,
    "both engine components resolve in-process (linked, not dlopened from a bundle)"
  )

  let result = try engine.start()
  try check(result.engineReady, "the engine reports ready")
  try check(engine.isRunning, "the engine reports running")
  try check(
    result.statusFields["engine_runtime_winn_started"] as? Bool == true,
    "the Winn seam reports started"
  )
  try check(
    result.statusFields["engine_runtime_winn_seam_bound"] as? Bool == true,
    "the Winn seam reports a bound loopback port"
  )
  try check(
    result.statusFields["engine_runtime_winn_awg_uapi_repointed"] as? Bool == true,
    "the AmneziaWG UAPI reports repointed"
  )

  // What AmneziaWG was actually handed. This is the whole ordering claim: the
  // seam had to be created, started and asked for its port before this string
  // could exist.
  guard let capturedPointer = wins_test_captured_awg_uapi() else {
    throw HarnessError("FAIL: the AmneziaWG engine was never created")
  }
  let captured = String(cString: capturedPointer)
  try check(wins_test_awg_create_calls() == 1, "AmneziaWG was created exactly once")
  try check(wins_test_awg_start_calls() == 1, "AmneziaWG was started exactly once")

  guard let line = endpointLine(captured) else {
    throw HarnessError("FAIL: the captured AmneziaWG UAPI has no endpoint line")
  }
  try check(
    line.hasPrefix("endpoint=127.0.0.1:"),
    "AmneziaWG was pointed at the loopback seam, not at the gateway (\(line))"
  )
  guard let seamPort = UInt16(line.replacingOccurrences(of: "endpoint=127.0.0.1:", with: "")) else {
    throw HarnessError("FAIL: could not read the seam port out of \(line)")
  }
  try check(seamPort != 0, "the seam port is not zero")
  try check(seamPort != gateway.port, "the seam port is not the gateway port")
  try check(
    !captured.contains("203.0.113.10"),
    "the real AmneziaWG gateway does not survive anywhere in the repointed UAPI"
  )
  try check(
    captured.contains("private_key=") && captured.contains("public_key=")
      && captured.contains("allowed_ip=0.0.0.0/0"),
    "everything else in the UAPI document survived the repoint"
  )

  // Outbound: an AmneziaWG outer datagram sent to the seam must reach the
  // gateway byte-identically, through the real Go datapath.
  let awg = try makeLoopbackUDPSocket()
  defer { close(awg.fd) }
  let outbound: [UInt8] = [0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44]
  try send(outbound, from: awg.fd, toPort: seamPort)
  guard let atGateway = receive(on: gateway.fd) else {
    throw HarnessError("FAIL: the gateway received nothing from the seam")
  }
  try check(atGateway.payload == outbound, "the outbound datagram reached the gateway byte-identically")

  // Inbound: the gateway's reply must come back out of the seam to the pinned
  // AmneziaWG sender.
  let inbound: [UInt8] = [0x04, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0x55, 0x66]
  try send(inbound, from: gateway.fd, toPort: atGateway.port)
  guard let atAwg = receive(on: awg.fd) else {
    throw HarnessError("FAIL: the AmneziaWG side received nothing back from the seam")
  }
  try check(atAwg.payload == inbound, "the inbound datagram came back byte-identically")
  try check(atAwg.port == seamPort, "the inbound datagram came from the seam port")

  // Ordering, 32 datagrams.
  var ordered = true
  for index in 0..<32 {
    let payload: [UInt8] = [0x04, 0x00, 0x00, 0x00, UInt8(index), 0x99]
    try send(payload, from: awg.fd, toPort: seamPort)
    guard let received = receive(on: gateway.fd), received.payload == payload else {
      ordered = false
      break
    }
  }
  try check(ordered, "32 sequential datagrams arrive in order and unmodified")

  // Peer pinning: a second local sender must never reach the gateway.
  let intruder = try makeLoopbackUDPSocket()
  defer { close(intruder.fd) }
  try send([0x04, 0x00, 0x00, 0x00, 0x00, 0x01], from: intruder.fd, toPort: seamPort)
  try check(receive(on: gateway.fd) == nil, "an unpinned local sender never reaches the gateway")

  // Teardown.
  engine.stop()
  try check(!engine.isRunning, "the engine reports stopped")
  try check(wins_test_awg_stop_calls() >= 1, "AmneziaWG was stopped")
  try check(wins_test_awg_destroy_calls() >= 1, "AmneziaWG was destroyed")
  engine.stop()
  try check(!engine.isRunning, "a second stop is idempotent")

  // The seam port must be released; rebinding it proves the socket is closed.
  let rebind = socket(AF_INET, SOCK_DGRAM, 0)
  var address = sockaddr_in()
  address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
  address.sin_family = sa_family_t(AF_INET)
  address.sin_port = seamPort.bigEndian
  address.sin_addr.s_addr = inet_addr("127.0.0.1")
  let rebound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
      bind(rebind, raw, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
  }
  close(rebind)
  try check(rebound == 0, "the seam port is free after stop")
}

func runDowngradeTests() throws {
  print("\n[anti-downgrade] a Winn config can never quietly start as classical AmneziaWG")

  // A plan can never name Winn WITHOUT AmneziaWG. Winn contains no AmneziaWG
  // implementation, so a tunnel carried by it alone would hand raw tun packets
  // to a datapath that forwards them in cleartext. `WinsPacketTunnelEnginePlan`
  // derives requiredComponents from the config rather than from its bundle
  // probe, so this is the only place the list can be decided, and every Winn
  // config it can produce puts AmneziaWG first.
  for endpoint in ["198.51.100.7:51820", "203.0.113.10:9110", "192.0.2.1:1"] {
    let winnConfig = WinsTunnelConfig.parse(baseConfig() + winnSection(endpoint: endpoint))
    let plan = WinsPacketTunnelEnginePlan(
      config: winnConfig,
      bundleProbe: WinsPacketTunnelEngineBundleProbe(
        requiredComponents: ["winn_packet_engine"],
        availableComponents: ["winn_packet_engine"]
      ),
      packetFlowAvailable: true
    )
    try check(
      plan.requiredComponents == ["amneziawg_packet_engine", "winn_packet_engine"],
      "a Winn plan for \(endpoint) names AmneziaWG first, whatever the bundle probe says"
    )
    try check(
      plan.transportMode == "winn",
      "a Winn plan for \(endpoint) still reports itself as Winn, not as AmneziaWG"
    )
  }

  // A Winn config whose seam cannot start must fail the WHOLE start rather
  // than continue into AmneziaWG with the original gateway -- which would
  // succeed, bring the tun up, and run a winn/3 session as classical
  // AmneziaWG with nobody told.
  let unstartable: [String: String] = [
    // Refused by the ObjC wrapper before the archive is called at all.
    "a max_datagram above the archive's own ceiling":
      "\n[Winn]\nEnabled = true\nEndpoint = 198.51.100.7:51820\nMax_Datagram = 999999\n",
    "pairwise-equal AmneziaWG header types":
      "\n[Winn]\nEnabled = true\nEndpoint = 198.51.100.7:51820\nH1 = 7\nH2 = 7\nH3 = 8\nH4 = 9\n",
    // Refused by the REAL Go archive at create time.
    "a gateway hostname the engine will not resolve":
      "\n[Winn]\nEnabled = true\nEndpoint = gw.example.invalid:51820\n",
    "a gateway endpoint with no port":
      "\n[Winn]\nEnabled = true\nEndpoint = 198.51.100.7\n",
    // The ObjC wrapper's own carrier gate, reached with validate() bypassed so
    // it is the wrapper being tested rather than the Swift rule above it.
    "a carrier this ABI cannot build, with the Swift gate bypassed":
      "\n[Winn]\nEnabled = true\nEndpoint = 198.51.100.7:51820\nCarrier = http2-stream\n",
    // http3-connect-udp is now NAMEABLE, but naming it with no carrier profile
    // fields at all must still fail the whole start: WinsPacketTunnelEngine
    // resolves the carrier from [winn] itself (not from validate(), which no
    // longer checks profile completeness) and WinsWinnCarrierProfile.from
    // refuses a section with no masque_template before any App Group lookup
    // even happens.
    "an http3-connect-udp carrier with no carrier profile fields at all":
      "\n[Winn]\nEnabled = true\nEndpoint = 198.51.100.7:51820\nCarrier = http3-connect-udp\n",
    // A STRUCTURALLY COMPLETE carrier profile — every field WinsWinnCarrierProfile.from
    // requires, correctly shaped — for a device with no provisioned Winn
    // carrier credentials, which is every device today. This is the case that
    // proves the new seam is wired all the way to real credential resolution
    // rather than merely not crashing: see runCarrierProfileTests() for the
    // same claim proven directly, with fixture credential files, independent
    // of whatever this machine's App Group container happens to contain.
    "an http3-connect-udp carrier with a complete profile and unprovisioned credentials": """

    [Winn]
    Enabled = true
    Endpoint = 198.51.100.7:51820
    Carrier = http3-connect-udp
    Masque_Template = https://carrier.example.invalid/.well-known/masque/udp/{target_host}/{target_port}/
    Public_Target = 198.51.100.7:51820
    Server_Name = carrier.example.invalid
    Suite = x25519-mlkem768
    Controller_Id = controller-under-test
    Device_Id = device-under-test
    Device_Pq_Algorithm = mldsa65
    Manifest_Digest = 0000000000000000000000000000000000000000000000000000000000000000
    """
  ]
  for (label, section) in unstartable.sorted(by: { $0.key < $1.key }) {
    wins_test_reset_awg_stub()
    let failing = WinsPacketTunnelEngineFactory.makeEngine(
      config: WinsTunnelConfig.parse(baseConfig() + section),
      packetFlow: NSObject(),
      adapter: WinsNativePacketTunnelEngineAdapter(bundle: .main)
    )
    do {
      _ = try failing.start()
      throw HarnessError("FAIL: \(label) still started a tunnel")
    } catch let error as WinsPacketTunnelEngineError {
      try check(
        error.message.contains("Winn"),
        "\(label): the whole start fails, naming Winn"
      )
      // A carrier case must be refused BY THE PROFILE BUILDER, and this check
      // exists because the one above does not discriminate.
      //
      // `makeWinnCarrierProfileJSON` was missing from the engine between the
      // 2026-08-08 loss event and its restoration
      // (docs/handoff/APPLE_SEAM_GAPS_CLOSED_20260808.md). Without it, an
      // http3-connect-udp config still failed closed -- but only because the
      // OBJECTIVE-C wrapper refused a create with no `winn_carrier_profile`
      // key and returned NULL, which surfaces as the generic
      // "Win's VPN Winn Protocol packet engine was not created." That message
      // contains "Winn", so every assertion above passed against an engine
      // that could not honour the carrier at all. This harness was green for
      // the whole period the defect existed.
      //
      // The profile builder's refusals all carry its own prefix and name the
      // field or the credential file that is wrong. Asserting the prefix is
      // what makes a silently-absent producer a red run instead of a green
      // one. If this ever fails while the "naming Winn" check above passes,
      // the producer is gone again -- look at makeLaunchDescriptorJSON first.
      if label.hasPrefix("an http3-connect-udp carrier") {
        try check(
          error.message.contains("Winn carrier profile"),
          "\(label): the refusal comes from the carrier profile builder, not a bare create-NULL"
        )
      }
    }
    try check(
      wins_test_captured_awg_uapi() == nil,
      "\(label): AmneziaWG was NEVER created -- no silent downgrade"
    )
    try check(
      wins_test_awg_start_calls() == 0,
      "\(label): AmneziaWG was never started"
    )
  }
}

func runCarrierProfileTests() throws {
  print("\n[carrier profile] WinsWinnCarrierProfile validation and credential resolution")

  let validSection: [String: String] = [
    "masque_template":
      "https://carrier.example.invalid/.well-known/masque/udp/{target_host}/{target_port}/",
    "public_target": "198.51.100.7:51820",
    "server_name": "carrier.example.invalid",
    "suite": "x25519-mlkem768",
    "controller_id": "controller-under-test",
    "device_id": "device-under-test",
    "device_pq_algorithm": "mldsa65",
    "manifest_digest": "0000000000000000000000000000000000000000000000000000000000000000"
  ]
  let credentialFileNames = [
    "controller_pins.json", "winn_root_ca.pem", "ech_config_list.bin",
    "device_mldsa_seed.bin", "client_cert.pem", "client_key.pem"
  ]

  // 1. A well-formed section over an EMPTY credential directory fails, naming
  // the first file WinnCarrierProfile.kt's identically-ordered REQUIRED_FILES
  // also names first: controller_pins.json.
  let emptyDirectory = FileManager.default.temporaryDirectory
    .appendingPathComponent("wins-winn-carrier-empty-\(UUID().uuidString)", isDirectory: true)
  do {
    _ = try WinsWinnCarrierProfile.from(
      section: validSection, carrier: "http3-connect-udp", credentialDirectory: emptyDirectory
    )
    throw HarnessError("FAIL: a profile with no provisioned credentials was accepted")
  } catch let error as WinsWinnCarrierProfileError {
    try check(
      error.message.contains("controller_pins.json"),
      "an empty credential directory fails, naming controller_pins.json first"
    )
  }

  // 2. A real credential directory with all six fixture files: the profile
  // builds, and its JSON matches the carrierhost.Profile schema.
  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent("wins-winn-carrier-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: directory) }
  for name in credentialFileNames {
    try Data("fixture credential, not a real key".utf8)
      .write(to: directory.appendingPathComponent(name, isDirectory: false))
  }

  let profile = try WinsWinnCarrierProfile.from(
    section: validSection, carrier: "http3-connect-udp", credentialDirectory: directory
  )
  try check(profile.carrier == "http3-connect-udp", "a well-formed profile resolves the requested carrier")

  let json = profile.toJSON()
  try check(
    json.hasPrefix("{\"profile\":\"winn-carrier-profile/1\",\"carrier\":\"http3-connect-udp\""),
    "toJSON() opens with profile then carrier, matching Kotlin/C++ field order"
  )
  try check(json.contains("\"masque_template\":"), "toJSON() carries masque_template for an http3 profile")
  let controllerPinsPath = directory.appendingPathComponent("controller_pins.json").path
  try check(
    json.contains("\"controller_pins_path\":\(WinsWinnCarrierProfile.jsonString(controllerPinsPath))"),
    "toJSON() names the resolved, absolute controller pins path"
  )
  try check(json.contains("\"authorization_mode\":\"identity\""), "toJSON() always names identity mode")
  try check(!json.contains("manifest_path"), "toJSON() never emits manifest_path")
  try check(profile.sessionID.count == 32, "a fresh 32-character session id is generated")
  try check(
    profile.sessionID.allSatisfy(\.isHexDigit) && profile.sessionID == profile.sessionID.lowercased(),
    "the generated session id is lowercase hexadecimal"
  )

  let decoded = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
  try check(decoded != nil, "toJSON() produces syntactically valid JSON")
  try check(decoded?["max_inner_datagram"] is Int, "max_inner_datagram is a JSON number, not a string")
  try check(decoded?.count == 20, "the document carries exactly the 20 fields an http3 profile without sequence_epoch has")

  // 3. A credential file that is a SYMBOLIC LINK is refused, not followed —
  // the Apple analogue of Linux's O_NOFOLLOW.
  let symlinkDirectory = FileManager.default.temporaryDirectory
    .appendingPathComponent("wins-winn-carrier-symlink-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: symlinkDirectory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: symlinkDirectory) }
  for name in credentialFileNames where name != "client_key.pem" {
    try Data("fixture credential, not a real key".utf8)
      .write(to: symlinkDirectory.appendingPathComponent(name, isDirectory: false))
  }
  let elsewhere = symlinkDirectory.appendingPathComponent("elsewhere.pem", isDirectory: false)
  try Data("fixture credential, not a real key".utf8).write(to: elsewhere)
  try FileManager.default.createSymbolicLink(
    at: symlinkDirectory.appendingPathComponent("client_key.pem", isDirectory: false),
    withDestinationURL: elsewhere
  )
  do {
    _ = try WinsWinnCarrierProfile.from(
      section: validSection, carrier: "http3-connect-udp", credentialDirectory: symlinkDirectory
    )
    throw HarnessError("FAIL: a symlinked credential file was accepted")
  } catch let error as WinsWinnCarrierProfileError {
    try check(
      error.message.contains("symbolic link"),
      "a symlinked credential file is refused by name, not silently followed"
    )
  }

  // 4. http2-stream is refused by name: the engine has it, this host cannot
  // supply the socket kind its dialer needs.
  do {
    _ = try WinsWinnCarrierProfile.from(
      section: validSection, carrier: "http2-stream", credentialDirectory: directory
    )
    throw HarnessError("FAIL: http2-stream was accepted")
  } catch let error as WinsWinnCarrierProfileError {
    try check(
      error.message.contains("CONNECTED"),
      "http2-stream is refused by name, naming the socket-kind reason"
    )
  }

  // 5. The suite allowlist is load-bearing: a classical-only suite is caught
  // here rather than deferred to the engine's create-time ParseSuite, by
  // which point a protected socket would already be handed over.
  var classicalSuite = validSection
  classicalSuite["suite"] = "classical-only-suite"
  do {
    _ = try WinsWinnCarrierProfile.from(
      section: classicalSuite, carrier: "http3-connect-udp", credentialDirectory: directory
    )
    throw HarnessError("FAIL: an unrecognised suite was accepted")
  } catch let error as WinsWinnCarrierProfileError {
    try check(error.message.contains("suite"), "an unrecognised suite is refused, naming the field")
  }

  // 6. A relative masque_template (not an absolute https URL) is refused.
  var badTemplate = validSection
  badTemplate["masque_template"] = "carrier.example.invalid/udp"
  do {
    _ = try WinsWinnCarrierProfile.from(
      section: badTemplate, carrier: "http3-connect-udp", credentialDirectory: directory
    )
    throw HarnessError("FAIL: a non-absolute-https masque_template was accepted")
  } catch let error as WinsWinnCarrierProfileError {
    try check(
      error.message.contains("masque_template"),
      "a malformed masque_template is refused, naming the field"
    )
  }

  try runSPACarrierProfileTests(validSection: validSection, directory: directory)
}

/// Single packet authorization: the five served knock parameters must reach the
/// emitted document, and must be absent from it when SPA is off.
///
/// WHY THIS EXISTS. `WinsWinnCarrierProfile` used to carry a closed key
/// allowlist that excluded every `spa_` field. The fields were in
/// `carrierhost.Profile`, no Apple client could put one into a document, and
/// nothing failed anywhere -- single packet authorization was simply
/// unreachable from this platform. Nothing in the suite could notice, because
/// the document the emitter produced was perfectly well-formed.
func runSPACarrierProfileTests(
  validSection: [String: String],
  directory: URL
) throws {
  print("\n[carrier profile] single packet authorization")

  let knockKeyURL = directory.appendingPathComponent(
    WinsWinnCarrierProfileKeys.spaKeyCredentialFileName, isDirectory: false)
  // A syntactically valid single-line hex key. This host never opens it --
  // knock.LoadKeysFromFile inside the engine owns the format -- so the value is
  // a marker chosen so the checks below can assert it did NOT reach the
  // document.
  let knockKeyMarker =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  try Data((knockKeyMarker + "\n").utf8).write(to: knockKeyURL)
  defer { try? FileManager.default.removeItem(at: knockKeyURL) }

  var spaSection = validSection
  spaSection["spa_mode"] = "required"
  spaSection["spa_target"] = "198.51.100.7:9111"
  spaSection["spa_packet_size"] = "256"
  spaSection["spa_bucket_window_seconds"] = "10"
  spaSection["spa_max_skew_seconds"] = "60"

  // 1. THE HEADLINE CHECK. Every served knock parameter survives the emitter
  // unmodified, and the key is named by a device-local path this host resolved
  // rather than by anything the served config chose.
  let spaProfile = try WinsWinnCarrierProfile.from(
    section: spaSection, carrier: "http3-connect-udp", credentialDirectory: directory
  )
  let spaJSON = spaProfile.toJSON()
  try check(spaJSON.contains("\"spa_mode\":\"required\""), "spa_mode survives the emitter")
  try check(
    spaJSON.contains("\"spa_target\":\"198.51.100.7:9111\""),
    "spa_target survives the emitter unmodified")
  // Numbers, not strings: carrierhost decodes these into ints, so a quoted
  // value is a hard parse failure rather than a coercion.
  try check(spaJSON.contains("\"spa_packet_size\":256"), "spa_packet_size is a JSON number")
  try check(
    spaJSON.contains("\"spa_bucket_window_seconds\":10"),
    "spa_bucket_window_seconds is a JSON number")
  try check(
    spaJSON.contains("\"spa_max_skew_seconds\":60"),
    "spa_max_skew_seconds is a JSON number")
  try check(
    spaJSON.contains("\"spa_key_path\":\(WinsWinnCarrierProfile.jsonString(knockKeyURL.path))"),
    "the knock key is named by its resolved absolute path")
  try check(
    !spaJSON.contains(knockKeyMarker),
    "THE KEY ITSELF NEVER REACHES THE DOCUMENT -- only its path")

  // 2. The document is still valid JSON and carries exactly the fields an
  // http3 SPA profile has: the 20 of a plain profile plus the six spa_ ones.
  let spaDecoded = try JSONSerialization.jsonObject(with: Data(spaJSON.utf8)) as? [String: Any]
  try check(spaDecoded != nil, "an SPA profile is syntactically valid JSON")
  try check(spaDecoded?.count == 26, "an SPA profile carries exactly 26 fields (20 + 6)")

  // 3. Field order matches carrierhost.Profile's declaration order and the
  // other three platforms, which are compared byte for byte in review.
  var previous = spaJSON.startIndex
  for key in ["\"privacy_profile\"", "\"spa_mode\"", "\"spa_key_path\"", "\"spa_target\"",
              "\"spa_packet_size\"", "\"spa_bucket_window_seconds\"",
              "\"spa_max_skew_seconds\""] {
    guard let at = spaJSON.range(of: key)?.lowerBound, at >= previous else {
      throw HarnessError("FAIL: \(key) is out of schema order in the SPA document")
    }
    previous = at
  }
  try check(true, "the six spa_ fields are emitted last, in carrierhost.Profile's order")

  // 4. SPA OFF EMITS NOTHING -- a contract rather than tidiness, but be exact
  // about the reason. carrierhost REFUSES a document carrying a NON-EMPTY spa_
  // field while the mode is off (ErrSPAFieldWithoutMode); an emitter that wrote
  // "spa_mode":"off" or "spa_target":"" would NOT break non-SPA Apple sessions,
  // because the stray sweep tests TrimSpace(...) != "" and != 0, so those parse
  // fine. (An earlier version of this comment claimed the opposite; it was
  // checked against ParseProfile and is false.) The check below is still the
  // right one: "no spa_ substring anywhere" is checkable without modelling
  // which empty values are forgiven, and it makes the one shape that IS a hard
  // refusal -- a non-empty stray -- unreachable from this emitter.
  let plain = try WinsWinnCarrierProfile.from(
    section: validSection, carrier: "http3-connect-udp", credentialDirectory: directory
  )
  try check(!plain.toJSON().contains("spa_"), "a profile without SPA emits no spa_ field at all")
  try check(plain.describeForLog().contains("spa=off"), "the log summary reports spa=off")

  // 5. A stray spa_ field with the mode off is a REFUSAL, not a silent drop.
  // Dropping it is exactly how this capability came to be unreachable.
  for stray in WinsWinnCarrierProfileKeys.spa.sorted() where stray != "spa_mode" {
    var strayed = validSection
    strayed[stray] = stray == "spa_target" ? "198.51.100.7:9111" : "10"
    do {
      _ = try WinsWinnCarrierProfile.from(
        section: strayed, carrier: "http3-connect-udp", credentialDirectory: directory
      )
      throw HarnessError("FAIL: \(stray) without spa_mode was accepted")
    } catch let error as WinsWinnCarrierProfileError {
      try check(error.message.contains(stray), "\(stray) without spa_mode is refused by name")
    }
  }

  // 6. THE REFUSAL THAT REPLACES A SILENT RUNTIME FAILURE. carrierhost accepts
  // any non-empty spa_key_path at PARSE time; the file is not opened until
  // BuildDialer, at create time, long after the outer socket exists. So an
  // unprovisioned device would build a valid-looking profile, start a tunnel,
  // and fail somewhere a user experiences only as "it doesn't connect".
  try FileManager.default.removeItem(at: knockKeyURL)
  do {
    _ = try WinsWinnCarrierProfile.from(
      section: spaSection, carrier: "http3-connect-udp", credentialDirectory: directory
    )
    throw HarnessError("FAIL: SPA with no provisioned knock key was accepted")
  } catch let error as WinsWinnCarrierProfileError {
    try check(
      error.message.contains(WinsWinnCarrierProfileKeys.spaKeyCredentialFileName),
      "an unprovisioned knock key is refused by name, before anything is allocated")
  }
  try Data((knockKeyMarker + "\n").utf8).write(to: knockKeyURL)

  // 7. An unknown mode, a hostname target and an out-of-range knock size are
  // each refused, naming the field.
  let malformed: [(String, String, String)] = [
    ("spa_mode", "advisory", "spa_mode"),
    ("spa_target", "gate.example.invalid:9111", "spa_target"),
    ("spa_target", "198.51.100.7", "spa_target"),
    ("spa_packet_size", "16", "spa_packet_size"),
    ("spa_packet_size", "4000", "spa_packet_size"),
    ("spa_packet_size", "not-a-number", "spa_packet_size")
  ]
  for (key, value, named) in malformed {
    var bad = spaSection
    bad[key] = value
    do {
      _ = try WinsWinnCarrierProfile.from(
        section: bad, carrier: "http3-connect-udp", credentialDirectory: directory
      )
      throw HarnessError("FAIL: \(key) = \(value) was accepted")
    } catch let error as WinsWinnCarrierProfileError {
      try check(error.message.contains(named), "\(key) = \(value) is refused, naming the field")
    }
  }

  // 8. The log summary names the MODE and nothing else. The key path names a
  // credential file and the target names a host that is supposed to be
  // invisible; publishing either would undo the point of gating it.
  let described = spaProfile.describeForLog()
  try check(described.contains("spa=required"), "the log summary reports spa=required")
  try check(!described.contains("198.51.100.7:9111"), "the log summary never names the knock target")
  try check(!described.contains("spa_knock_key"), "the log summary never names the key file")

  // 9. The generated key list really is the one this emitter uses, and
  // spa_key_path is deliberately NOT in it: a control plane that could choose
  // it would be choosing which file the engine opens.
  try check(
    WinsWinnCarrierProfile.carrierProfileKeys.isSuperset(of: WinsWinnCarrierProfileKeys.spa),
    "the emitter's key list carries every served spa_ parameter")
  try check(
    !WinsWinnCarrierProfile.carrierProfileKeys.contains("spa_key_path"),
    "spa_key_path is never a served key")
}

@main
struct WinsAppleWinnSeamHarness {
  static func main() {
    do {
      try runConfigTests()
      try runCarrierProfileTests()
      try runEngineTests()
      try runDowngradeTests()
      print("\nApple Winn seam harness passed: \(passed)/\(passed) checks.")
    } catch {
      print("\n\(error)")
      exit(1)
    }
  }
}
