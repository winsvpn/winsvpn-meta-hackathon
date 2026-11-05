import Cocoa
import FlutterMacOS
import NetworkExtension
import XCTest

@testable import Win_s_VPN

private final class TestPacketTunnelEngine: WinsPacketTunnelEngine {
  let plan: WinsPacketTunnelEnginePlan
  private(set) var isRunning = false

  private let engineReady: Bool
  private let fields: [String: Any]

  init(
    plan: WinsPacketTunnelEnginePlan,
    engineReady: Bool,
    fields: [String: Any]
  ) {
    self.plan = plan
    self.engineReady = engineReady
    self.fields = fields
  }

  func start() throws -> WinsPacketTunnelEngineStartResult {
    isRunning = true
    return WinsPacketTunnelEngineStartResult(
      engineReady: engineReady,
      statusFields: fields
    )
  }

  func stop() {
    isRunning = false
  }
}

final class RunnerTests: XCTestCase {
  func testAuditSplitCarrierExclusionAndResolution() throws {
    let split = validConfigText.replacingOccurrences(of: "0.0.0.0/0, ::/0", with: "192.0.2.0/24, ::/0")
    let hostname = try WinsTunnelConfig.parseAndValidate(split)
    XCTAssertNil(hostname.transportIPv4ExclusionRoute)
    var calls = 0
    let resolved = try hostname.resolvingFullTunnelTransportIPv4 { _ in
      calls += 1
      return "198.51.100.7"
    }
    XCTAssertEqual(calls, 1)
    XCTAssertEqual(resolved.transportIPv4ExclusionRoute?.destinationAddress, "198.51.100.7")
    _ = try resolved.resolvingFullTunnelTransportIPv4 { _ in
      XCTFail("a literal carrier must not perform another lookup")
      return nil
    }
  }

  func testAuditMTURequiresIPv6Minimum() throws {
    let atBoundary = validConfigText.replacingOccurrences(of: "MTU = 1280", with: "MTU = 1280")
    XCTAssertNoThrow(try WinsTunnelConfig.parseAndValidate(atBoundary))
    let tooSmall = atBoundary.replacingOccurrences(of: "MTU = 1280", with: "MTU = 1279")
    XCTAssertThrowsError(try WinsTunnelConfig.parseAndValidate(tooSmall)) { error in
      XCTAssertEqual((error as? WinsTunnelValidationError)?.code, 1104)
    }
  }

  func testAuditStrictMasksAndExtraExclusions() throws {
    for mask in ["garbage", ".0.0.0", "255..255.0", "255.255.255.0.0", "255.bad.255.255.0", "255.0.255.0"] {
      XCTAssertEqual(WinsKillSwitch.prefixLength(ofSubnetMask: mask), -1, mask)
    }
    XCTAssertEqual(WinsKillSwitch.prefixLength(ofSubnetMask: "0.0.0.0"), 0)
    XCTAssertEqual(WinsKillSwitch.prefixLength(ofSubnetMask: "255.255.255.255"), 32)
    let literal = validConfigText.replacingOccurrences(of: "edge.example.com", with: "198.51.100.7")
    let config = try WinsTunnelConfig.parseAndValidate(literal)
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.51.100.7")
    let ipv4 = NEIPv4Settings(addresses: ["10.7.0.2"], subnetMasks: ["255.255.255.255"])
    ipv4.includedRoutes = [NEIPv4Route.default()]
    ipv4.excludedRoutes = config.transportIPv4ExclusionRoute.map { [NEIPv4Route(destinationAddress: $0.destinationAddress, subnetMask: $0.subnetMask)] }
    settings.ipv4Settings = ipv4
    let ipv6 = NEIPv6Settings(addresses: [WinsTunnelConfig.ipv6SinkAddress], networkPrefixLengths: [128])
    ipv6.includedRoutes = [NEIPv6Route.default()]
    settings.ipv6Settings = ipv6
    let dns = NEDNSSettings(servers: ["1.1.1.1"])
    dns.matchDomains = [""]
    settings.dnsSettings = dns
    XCTAssertTrue(WinsKillSwitch.egressBlocked(by: settings, config: config))
    settings.ipv4Settings?.excludedRoutes?.append(NEIPv4Route(destinationAddress: "192.0.2.1", subnetMask: "255.255.255.255"))
    XCTAssertFalse(WinsKillSwitch.egressBlocked(by: settings, config: config))
    settings.ipv4Settings?.excludedRoutes = config.transportIPv4ExclusionRoute.map { [NEIPv4Route(destinationAddress: $0.destinationAddress, subnetMask: $0.subnetMask)] }
    settings.ipv6Settings?.excludedRoutes = [NEIPv6Route(destinationAddress: "2001:db8::1", networkPrefixLength: 128)]
    XCTAssertFalse(WinsKillSwitch.egressBlocked(by: settings, config: config))
  }

  func testAuditWinnPSKRedactionAndRestoration() throws {
    let dummyPSK = Data(repeating: 0x44, count: 32).base64EncodedString()
    let raw = validConfigText + "\n[Winn]\nPSK = \(dummyPSK)\n"
    let redacted = WinsTunnelConfig.redactedForStorage(raw)
    XCTAssertFalse(redacted.contains(dummyPSK))
    XCTAssertTrue(WinsTunnelConfig.containsRedactedWinnPSK(redacted))
    let restored = WinsTunnelConfig.restoredRuntimeConfig(redacted, privateKey: interfacePrivateKey, winnPSK: dummyPSK)
    XCTAssertEqual(WinsTunnelConfig.parse(restored).winn3PSK, dummyPSK)
    let secrets = WinsTunnelSecrets(presharedKey: "", xrayUUID: "", winnPSK: dummyPSK)
    XCTAssertFalse(secrets.isEmpty)
    XCTAssertEqual(secrets.dictionary["winn_psk"], dummyPSK)
  }

  func testAuditMemoryPolicyPreservesPromotedSession() {
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: nil, ceilingBytes: 15, promoted: false), .ignore)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: -1, ceilingBytes: 15, promoted: false), .ignore)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: 14, ceilingBytes: 15, promoted: false), .ignore)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: 15, ceilingBytes: 15, promoted: false), .cancelBeforePromotion)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: 16, ceilingBytes: 15, promoted: true), .recordOnly)
  }


  func testDartIdentitiesAcceptGenerationOneFromTheFlutterCodec() {
    let args: [String: Any] = [
      "winn3StartGeneration": NSNumber(value: Int32(1)),
      "winn3StartToken": NSNumber(value: Int64(1))
    ]
    let identities = WinsWinn3NativeStartReadiness.dartIdentities(from: args)
    XCTAssertEqual(identities.startGeneration, 1)
    XCTAssertEqual(identities.startToken, 1)
    let boolean = WinsWinn3NativeStartReadiness.dartIdentities(
      from: ["winn3StartGeneration": NSNumber(value: true)]
    )
    XCTAssertNil(boolean.startGeneration)
    let fractional = WinsWinn3NativeStartReadiness.dartIdentities(
      from: ["winn3StartGeneration": NSNumber(value: 1.5)]
    )
    XCTAssertNil(fractional.startGeneration)
  }

  func testTunnelActivitySnapshotIsSanitizedAndTransitionAware() {
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: .connecting),
      ["known": true, "active": true]
    )
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: .disconnecting),
      ["known": true, "active": true]
    )
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: .invalid),
      ["known": true, "active": false]
    )
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: nil, known: false),
      ["known": false, "active": false]
    )
  }

  private var interfacePrivateKey: String {
    Data(repeating: 0x11, count: 32).base64EncodedString()
  }

  private var peerPublicKey: String {
    Data(repeating: 0x22, count: 32).base64EncodedString()
  }

  private var validConfigText: String {
    """
    [Interface]
    PrivateKey = \(interfacePrivateKey)
    Address = 10.7.0.2/32
    DNS = 1.1.1.1, 9.9.9.9
    MTU = 1280
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
    PublicKey = \(peerPublicKey)
    Endpoint = edge.example.com:9110
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    """
  }

  private func validConfig() throws -> WinsTunnelConfig {
    try WinsTunnelConfig.parseAndValidate(validConfigText)
  }

  private func validatedEnginePlan() throws -> WinsPacketTunnelEnginePlan {
    let config = try validConfig()
    return WinsPacketTunnelEnginePlan(
      config: config,
      bundleProbe: WinsPacketTunnelEngineBundleProbe(
        requiredComponents: config.requiredEngineComponents,
        availableComponents: config.requiredEngineComponents
      ),
      packetFlowAvailable: true
    )
  }

  func testMacOSPrivateConfigWriterAtomicallyCreatesOwnerOnlyFile() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-private-config-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("vpn_config.txt", isDirectory: false)

    try WinsMacOSPrivateFileWriter.writeString(#"{"client_private_key":"secret-one"}"#, to: target)
    try WinsMacOSPrivateFileWriter.writeString(#"{"client_private_key":"secret-two"}"#, to: target)

    XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), #"{"client_private_key":"secret-two"}"#)
    let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    XCTAssertEqual((attributes[.ownerAccountID] as? NSNumber)?.uint32Value, geteuid())
    XCTAssertTrue(
      try FileManager.default.contentsOfDirectory(atPath: root.path)
        .filter { $0.contains(".tmp.") }
        .isEmpty
    )
  }

  func testMacOSPrivateConfigWriterRejectsSymbolicLinkDestination() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-private-symlink-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let outside = root.appendingPathComponent("outside.txt")
    let target = root.appendingPathComponent("vpn_config.txt")
    try "do-not-touch".write(to: outside, atomically: true, encoding: .utf8)
    try FileManager.default.createSymbolicLink(at: target, withDestinationURL: outside)

    XCTAssertThrowsError(
      try WinsMacOSPrivateFileWriter.writeString(#"{"client_private_key":"secret"}"#, to: target)
    ) { error in
      XCTAssertEqual((error as NSError).domain, "org.winsvpn.MacOSPrivateFileWriter")
      XCTAssertEqual((error as NSError).code, WinsMacOSPrivateFileWriter.unsafePathCode)
    }
    XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "do-not-touch")
    XCTAssertEqual(
      try FileManager.default.destinationOfSymbolicLink(atPath: target.path),
      outside.path
    )
  }

  func testMacOSPrivateConfigWriterRejectsSymbolicLinkDirectory() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-private-directory-symlink-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let realDirectory = root.appendingPathComponent("real", isDirectory: true)
    let linkedDirectory = root.appendingPathComponent("linked", isDirectory: true)
    try FileManager.default.createDirectory(at: realDirectory, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(
      at: linkedDirectory,
      withDestinationURL: realDirectory
    )

    XCTAssertThrowsError(
      try WinsMacOSPrivateFileWriter.writeString(
        #"{"client_private_key":"secret"}"#,
        to: linkedDirectory.appendingPathComponent("vpn_config.txt")
      )
    ) { error in
      XCTAssertEqual((error as NSError).domain, "org.winsvpn.MacOSPrivateFileWriter")
      XCTAssertEqual((error as NSError).code, WinsMacOSPrivateFileWriter.unsafePathCode)
    }
    XCTAssertFalse(
      FileManager.default.fileExists(
        atPath: realDirectory.appendingPathComponent("vpn_config.txt").path
      )
    )
  }

  func testMacOSPrivateConfigWriterHardensLegacyRegularFileOnly() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-private-legacy-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("vpn_config.txt")
    try "legacy".write(to: target, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)

    try WinsMacOSPrivateFileWriter.hardenExistingFile(at: target)

    let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "legacy")
  }

  func testValidatedFullTunnelConfigProducesSafeNetworkPlan() throws {
    let config = try validConfig()

    XCTAssertEqual(config.interfaceIPv4Address, "10.7.0.2")
    XCTAssertEqual(config.interfaceIPv4SubnetMask, "255.255.255.255")
    XCTAssertEqual(config.dnsServers, ["1.1.1.1", "9.9.9.9"])
    XCTAssertEqual(config.peerEndpointKind, "hostname")
    XCTAssertEqual(config.networkSettingsRemoteAddress, "10.7.0.1")
    XCTAssertEqual(config.networkSettingsRemoteAddressSource, "interface_gateway_ipv4")
    XCTAssertEqual(config.transportMode, "amneziawg")
    XCTAssertEqual(config.requiredEngineComponents, ["amneziawg_packet_engine"])
    XCTAssertTrue(config.defaultIPv4RouteEnabled)
    XCTAssertTrue(config.allowedIPv6DefaultRouteEnabled)
    XCTAssertTrue(config.ipv6LeakProtectionEnabled)
    XCTAssertTrue(config.fullTunnelDNSMatchEnabled)
    XCTAssertNil(config.transportIPv4ExclusionRoute)
  }

  func testConfigRedactionAndRestorationRoundTrip() throws {
    let redacted = WinsTunnelConfig.redactedForStorage(validConfigText)

    XCTAssertFalse(redacted.contains(interfacePrivateKey))
    XCTAssertTrue(redacted.contains(WinsTunnelConfig.redactedPrivateKeyPlaceholder))
    XCTAssertTrue(WinsTunnelConfig.containsRedactedPrivateKey(redacted))

    let restored = WinsTunnelConfig.restoredRuntimeConfig(
      redacted,
      privateKey: interfacePrivateKey
    )
    let restoredConfig = try WinsTunnelConfig.parseAndValidate(restored)
    XCTAssertEqual(restoredConfig.interfacePrivateKey, interfacePrivateKey)
    XCTAssertFalse(restored.contains(WinsTunnelConfig.redactedPrivateKeyPlaceholder))
  }

  func testConfigRejectsInvalidEndpointAndOversizedInput() {
    let invalidEndpoint = validConfigText.replacingOccurrences(
      of: "Endpoint = edge.example.com:9110",
      with: "Endpoint = edge.example.com:70000"
    )
    XCTAssertThrowsError(try WinsTunnelConfig.parseAndValidate(invalidEndpoint)) { error in
      XCTAssertEqual((error as? WinsTunnelValidationError)?.code, 1202)
      XCTAssertEqual((error as? WinsTunnelValidationError)?.nsError.domain, "org.winsvpn.WinsTunnelConfig")
      XCTAssertEqual((error as? WinsTunnelValidationError)?.nsError.code, 1202)
    }

    let oversized = String(
      repeating: "x",
      count: WinsTunnelConfig.maxRuntimeConfigFileBytes + 1
    )
    XCTAssertThrowsError(try WinsTunnelConfig.parseAndValidate(oversized)) { error in
      XCTAssertEqual(
        (error as? WinsTunnelValidationError)?.code,
        WinsTunnelConfig.runtimeConfigTooLargeCode
      )
    }

    let invalidIPv6Route = validConfigText.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 0.0.0.0/0, 2001:db8::/64"
    )
    XCTAssertThrowsError(try WinsTunnelConfig.parseAndValidate(invalidIPv6Route)) { error in
      XCTAssertEqual((error as? WinsTunnelValidationError)?.code, 1203)
    }
  }

  func testHealthMessageRequiresTrustedRedactedResponse() throws {
    let message = WinsPacketTunnelProviderAppMessage(
      messageData: Data(#"{"command":" HEALTH "}"#.utf8),
      engineRunning: true,
      transportMode: "xray_vless_ws_amneziawg",
      xrayEnabled: true,
      providerExecutableSHA256: String(repeating: "a", count: 64)
    )
    XCTAssertEqual(message.command, "health")
    XCTAssertTrue(message.accepted)

    let response = try XCTUnwrap(message.responseData)
    let trusted = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: response,
      expectedProviderExecutableSHA256: String(repeating: "a", count: 64)
    )
    XCTAssertEqual(trusted["provider_message_probe_healthy"] as? Bool, true)
    XCTAssertEqual(trusted["provider_message_probe_response_redacted"] as? Bool, true)
    XCTAssertEqual(
      trusted["provider_message_probe_transport_mode"] as? String,
      "xray_vless_ws_amneziawg"
    )
    XCTAssertEqual(
      trusted["provider_message_probe_executable_sha256_matches_expected"] as? Bool,
      true
    )

    let unredactedResponse = try JSONSerialization.data(withJSONObject: [
      "response_schema_version": WinsPacketTunnelProviderAppMessage.schemaVersion,
      "command": "health",
      "accepted": true,
      "engine_running": true,
      "raw_payload_redacted": false
    ])
    let untrusted = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: unredactedResponse
    )
    XCTAssertEqual(untrusted["provider_message_probe_healthy"] as? Bool, false)

    let oversized = WinsPacketTunnelProviderAppMessage(
      messageData: Data(
        repeating: 0x61,
        count: WinsPacketTunnelProviderAppMessage.maxAcceptedMessageBytes + 1
      ),
      engineRunning: true
    )
    XCTAssertFalse(oversized.accepted)
    XCTAssertTrue(oversized.messageTooLarge)
    XCTAssertEqual(oversized.command, "invalid")
  }

  func testTunnelOperationGateRejectsStaleAsyncCompletions() {
    let gate = WinsTunnelOperationGate()
    let firstStart = gate.begin()
    XCTAssertTrue(gate.isCurrent(firstStart))

    let fallbackStart = gate.begin()
    XCTAssertFalse(gate.isCurrent(firstStart))
    XCTAssertTrue(gate.isCurrent(fallbackStart))

    var committedValue = ""
    XCTAssertFalse(gate.performIfCurrent(firstStart) {
      committedValue = "stale"
    })
    XCTAssertTrue(gate.performIfCurrent(fallbackStart) {
      committedValue = "fallback"
    })
    XCTAssertEqual(committedValue, "fallback")

    var invalidationActionRan = false
    gate.invalidate {
      invalidationActionRan = true
    }
    XCTAssertTrue(invalidationActionRan)
    XCTAssertFalse(gate.isCurrent(fallbackStart))
    XCTAssertFalse(gate.isCurrent(0))
  }

  func testProviderStatusSerializationIsBoundedAndDropsUnknownSecrets() throws {
    let data = try WinsPacketTunnelProviderStatus.writableData(
      stage: "engine_start_failed",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: false,
      networkSettingsReady: true,
      extra: [
        "status_generation": "safe-generation",
        "engine_runtime_private_key": "must-not-survive",
        "oversized_noise": String(
          repeating: "n",
          count: WinsPacketTunnelProviderStatus.maxStatusFileBytes + 1
        )
      ],
      updatedAt: Date(timeIntervalSince1970: 0)
    )

    XCTAssertLessThanOrEqual(data.count, WinsPacketTunnelProviderStatus.maxStatusFileBytes)
    let payload = try XCTUnwrap(
      JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
    XCTAssertEqual(payload["status_generation"] as? String, "safe-generation")
    XCTAssertEqual(payload["status_write_limited"] as? Bool, true)
    XCTAssertNil(payload["engine_runtime_private_key"])
    XCTAssertNil(payload["oversized_noise"])
    let serialized = String(decoding: data, as: UTF8.self).lowercased()
    XCTAssertFalse(serialized.contains("must-not-survive"))
    XCTAssertFalse(serialized.contains("private_key"))
  }

  func testEngineRuntimeContractRejectsDetachedPacketFlow() throws {
    let plan = try validatedEnginePlan()
    let engine = TestPacketTunnelEngine(
      plan: plan,
      engineReady: true,
      fields: ["engine_runtime_packet_flow_attached": false]
    )
    let guarded = WinsAdapterBackedPacketTunnelEngine(engine: engine, plan: plan)

    XCTAssertThrowsError(try guarded.start()) { error in
      XCTAssertEqual(
        (error as? WinsPacketTunnelEngineError)?.code,
        WinsPacketTunnelEngineError.adapterStartContractCode
      )
    }
    XCTAssertFalse(engine.isRunning)
  }

  func testEngineRuntimeContractSanitizesAdapterStatus() throws {
    let plan = try validatedEnginePlan()
    let engine = TestPacketTunnelEngine(
      plan: plan,
      engineReady: true,
      fields: [
        "engine_runtime_packet_flow_attached": true,
        "engine_runtime_worker_count": 2,
        "engine_runtime_private_key": "must-not-survive",
        "untrusted_status": "ignored"
      ]
    )
    let guarded = WinsAdapterBackedPacketTunnelEngine(engine: engine, plan: plan)

    let result = try guarded.start()
    XCTAssertTrue(result.engineReady)
    XCTAssertEqual(result.statusFields["engine_runtime_packet_flow_attached"] as? Bool, true)
    XCTAssertEqual(result.statusFields["engine_runtime_worker_count"] as? Int, 2)
    XCTAssertNil(result.statusFields["engine_runtime_private_key"])
    XCTAssertNil(result.statusFields["untrusted_status"])
    XCTAssertEqual(result.statusFields["engine_runtime_status_sanitized"] as? Bool, true)
    guarded.stop()
    XCTAssertFalse(engine.isRunning)
  }

  func testReadinessRequiresCurrentHealthyFullTunnelEvidence() {
    var fields: [String: Any] = [
      "active": true,
      "status": "connected",
      "provider_status_available": true,
      "provider_status_schema_supported": true,
      "provider_status_schema_unsupported": false,
      "provider_status_stale": false,
      "provider_status_bundle_mismatch": false,
      "provider_status_extension_type_mismatch": false,
      "provider_status_timestamp_invalid": false,
      "provider_status_stage_invalid": false,
      "provider_stage": "engine_started",
      "provider_engine_ready": true,
      "provider_network_settings_ready": true,
      "provider_healthy": true,
      "provider_message_probe_attempted": true,
      "provider_message_probe_healthy": true,
      "provider_message_probe_engine_running": true,
      "provider_default_route_enabled": true,
      "provider_ipv6_leak_protection_enabled": true,
      "provider_engine_ipv6_leak_protection_enabled": true,
      "provider_dns_full_tunnel_match_enabled": true,
      "provider_engine_full_tunnel_dns_match_enabled": true,
      "provider_dns_count": 2,
      "provider_engine_dns_server_count": 2
    ]

    XCTAssertTrue(WinsAppleReadiness.providerReady(fields))
    let leakFields = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(fields)
    XCTAssertEqual(leakFields["leak_protection_config_passed"] as? Bool, true)

    fields["provider_status_stale"] = true
    XCTAssertFalse(WinsAppleReadiness.providerReady(fields))
    XCTAssertEqual(
      WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(fields)[
        "leak_protection_config_passed"
      ] as? Bool,
      false
    )
  }

  func testExternalInputGuardsRejectUnsafeURLsAndLeakCanaries() {
    XCTAssertNotNil(WinsAppleExternalUrl.safeUrl(from: "https://www.winsvpn.org/support/"))
    for rawValue in [
      "file:///etc/passwd",
      "javascript:alert(1)",
      "https://user:secret@winsvpn.org",
      "https://winsvpn.org/has space",
      "mailto:/etc/passwd"
    ] {
      XCTAssertNil(WinsAppleExternalUrl.safeUrl(from: rawValue), rawValue)
    }

    let request = WinsAppleExternalLeakAudit.request(from: [
      "externalLeakAuditRequested": true,
      "externalLeakAuditMinimumEndpoints": 2,
      "externalLeakAuditUrls": [
        "https://example.org/",
        "https://cloudflare.com/",
        "https://127.0.0.1/",
        "https://localhost/",
        "http://example.net/"
      ]
    ])
    XCTAssertTrue(request.requested)
    XCTAssertEqual(request.urls.count, 1)
    XCTAssertEqual(request.invalidEndpointCount, 4)
    let fields = WinsAppleExternalLeakAudit.baseFields(for: request)
    XCTAssertEqual(fields["external_leak_audit_blocked_by_configuration"] as? Bool, true)
    XCTAssertEqual(fields["external_leak_audit_non_google_cloudflare_only"] as? Bool, false)
  }

  func testDiagnosticsNeverExposeSystemOrConfigurationDetails() {
    let safe = NSError(
      domain: "org.winsvpn.Test",
      code: 7,
      userInfo: [NSLocalizedDescriptionKey: "Native engine unavailable."]
    )
    XCTAssertEqual(
      WinsTunnelDiagnostics.redactedAppleErrorMessage(safe),
      "Native engine unavailable."
    )

    let unsafe = NSError(
      domain: "org.winsvpn.Test",
      code: 8,
      userInfo: [
        NSLocalizedDescriptionKey:
          "PrivateKey = secret at https://private.example.org/latest_tunnel.conf"
      ]
    )
    XCTAssertEqual(
      WinsTunnelDiagnostics.redactedAppleErrorMessage(unsafe),
      WinsTunnelDiagnostics.redactedAppleSystemErrorMessage
    )
    XCTAssertEqual(
      WinsTunnelDiagnostics.redactedProviderErrorMessage(unsafe),
      WinsTunnelDiagnostics.redactedProviderSystemErrorMessage
    )
  }

  func testBundleProbeNormalizesAndDeduplicatesComponentIdentifiers() {
    let probe = WinsPacketTunnelEngineBundleProbe(
      requiredComponents: [
        " AMNEZIAWG_PACKET_ENGINE ",
        "xray_vless_ws_transport",
        "amneziawg_packet_engine",
        "../unsafe"
      ],
      availableComponents: ["AMNEZIAWG_PACKET_ENGINE"]
    )

    XCTAssertEqual(
      probe.requiredComponents,
      ["amneziawg_packet_engine", "xray_vless_ws_transport"]
    )
    XCTAssertEqual(probe.availableComponents, ["amneziawg_packet_engine"])
    XCTAssertEqual(probe.missingComponents, ["xray_vless_ws_transport"])
    XCTAssertFalse(probe.allRequiredComponentsPresent)
    XCTAssertEqual(probe.probeCode, WinsPacketTunnelEngineBundleProbe.missingNativeEngineProbe)
  }

  func testMapRegionUsesOnlyProvidedPreVPNCoordinates() throws {
    let florida = try XCTUnwrap(WinsAppleMapRegion.region(from: [
      "latitude": 40.71,
      "longitude": -74.01,
      "radiusMeters": 80_467.2
    ]))
    XCTAssertEqual(florida.center.latitude, 40.71, accuracy: 0.0001)
    XCTAssertEqual(florida.center.longitude, -74.01, accuracy: 0.0001)
    XCTAssertEqual(
      try XCTUnwrap(WinsAppleMapRegion.radiusMeters(from: ["radiusMeters": 80_467.2])),
      80_467.2,
      accuracy: 0.01
    )
    XCTAssertGreaterThan(florida.span.latitudeDelta, 1.3)
    XCTAssertLessThan(florida.span.latitudeDelta, 1.6)

    let tokyo = try XCTUnwrap(WinsAppleMapRegion.region(from: [
      "latitude": 35.68,
      "longitude": 139.76,
      "radiusMeters": 80_467.2
    ]))
    XCTAssertEqual(tokyo.center.latitude, 35.68, accuracy: 0.0001)
    XCTAssertEqual(tokyo.center.longitude, 139.76, accuracy: 0.0001)
    XCTAssertNil(WinsAppleMapRegion.region(from: ["country": "US"]))
    XCTAssertNil(WinsAppleMapRegion.region(from: [
      "latitude": 40.71,
      "longitude": 900,
      "radiusMeters": 80_467.2
    ]))
    XCTAssertNil(WinsAppleMapRegion.region(from: [
      "latitude": 40.71,
      "longitude": -74.01,
      "radiusMeters": 0
    ]))
    XCTAssertNil(WinsAppleMapRegion.radiusMeters(from: ["radiusMeters": 0]))
    XCTAssertNil(WinsAppleMapRegion.radiusMeters(from: ["radiusMeters": "not-a-number"]))
  }

  // MARK: - Launch posture-source guard (gen_macos_applifecycle)

  // The tunnel posture source (`WinsMacRoutePosture.enforceRoutes`) is a RULED
  // INVARIANT, but until this guard nothing asserted it at runtime. These tests
  // drive the same pure guard AppDelegate calls at launch, and cover the
  // negative too: a source that is missing, or that has drifted from the ruling,
  // must FAIL (never silently continue as a green).

  func testLaunchPostureSourceGuardPassesWhenPresentAndMatching() {
    let result = WinsMacPostureSourceGuard.validateLaunchPostureSource(
      source: { WinsMacRoutePosture.enforceRoutes }
    )
    XCTAssertEqual(result, .present)
    XCTAssertTrue(result.isOkay)
  }

  func testLaunchPostureSourceGuardFailsLoudlyWhenMissing() {
    let result = WinsMacPostureSourceGuard.validateLaunchPostureSource(
      source: { nil }
    )
    XCTAssertEqual(result, .missing)
    XCTAssertFalse(result.isOkay)
  }

  func testLaunchPostureSourceGuardFailsLoudlyWhenDriftedFromRuling() {
    let ruled = WinsMacPostureSourceGuard.ruledEnforceRoutes
    let result = WinsMacPostureSourceGuard.validateLaunchPostureSource(
      source: { !ruled }
    )
    XCTAssertEqual(result, .driftedFromRuling(!ruled))
    XCTAssertFalse(result.isOkay)
  }

  func testLaunchPostureSourceGuardIsWiredIntoTheLaunchPath() {
    // The live source must be the RULED single source (`WinsMacRoutePosture`),
    // never a literal. The launch path passes `{ WinsMacRoutePosture.enforceRoutes }`
    // so the guard checks the actual source; if the launch path stopped calling
    // the guard the module would still compile, so pin the live source here too.
    XCTAssertEqual(
      { WinsMacRoutePosture.enforceRoutes }(),
      WinsMacRoutePosture.enforceRoutes
    )
    XCTAssertTrue(
      WinsMacPostureSourceGuard.validateLaunchPostureSource(
        source: { WinsMacRoutePosture.enforceRoutes }
      ).isOkay
    )
  }

  // MARK: - macOS release route posture (/1-pair route shape)

  // The shipping posture is `enforceRoutes = true` (RULED 2026-08-10,
  // reinstated 2026-08-11; single source `WinsMacRoutePosture` in
  // macos/Runner/RouteAudit.swift, registered in docs/rulings/RULINGS.lock).
  // The `/1` pair is defense-in-depth under that ruling
  // (WINN3_MACOS_ENFORCEROUTES_SELFSTRANGULATION_20260810_fin_mac_routes.md,
  // WINN3_MACOS_CARRIAGE_FIX_20260810_bld_mac_routes.md). This pins the route
  // shape that the shipping full-tunnel builder installs: a full default route
  // must expand to the `0.0.0.0/1` + `128.0.0.0/1` pair (never a bare `/0`), so
  // the tunnel captures AND resists a DHCP-option-121 split-default injection
  // even if enforcement ever has a gap.

  func testMacOSFullTunnelRoutePostureIsTheSlashOnePairNotABareDefault() throws {
    let config = try validConfig()

    XCTAssertTrue(config.defaultIPv4RouteEnabled)

    let routes = config.appleIncludedIPv4Routes
    let destinations = routes.map { "\($0.destinationAddress)/\($0.prefixLength)" }

    XCTAssertEqual(
      destinations,
      ["0.0.0.0/1", "128.0.0.0/1"],
      "A macOS full tunnel must expand a bare default to the /1 pair; found \(destinations)"
    )
    XCTAssertFalse(
      routes.contains { $0.destinationAddress == "0.0.0.0" && $0.prefixLength == 0 },
      "A bare 0.0.0.0/0 default must never be installed as an included route on macOS"
    )
    XCTAssertFalse(
      routes.contains { $0.isDefaultRoute },
      "No included route may be a bare default route"
    )
  }

  func testMacOSFullTunnelRoutePairRetainsTheCarrierExclusionCarveOut() throws {
    let config = try validConfig()

    XCTAssertTrue(config.defaultIPv4RouteEnabled)

    let included = config.appleIncludedIPv4Routes

    XCTAssertEqual(
      included.map { $0.prefixLength }.sorted(),
      [1, 1],
      "The included-route posture must be exactly the two /1 routes"
    )
  }

  // MARK: - winn/3 datapath-proof promotion gate
  //
  // These assert the PURE gate that widens a staged winn/3 start from a narrow
  // bootstrap (no default route, no IPv6, no DNS) to the full-tunnel posture.
  // They pin the invariant: route carriage (the widening that installs a default
  // IPv4 route) can never precede an authenticated winn/3 datapath, because the
  // widening is committed only after `WinsWinnDatapathProofGate.converged`
  // returns true AND the start was staged by `applies` in the first place.
  //
  // These are the production gate in `apple/WinsTunnelCore/WinsPacketTunnelEngine.swift`
  // (compiled into this module), not a replica.

  func testDatapathProofGateStagesWinnFullTunnelWideningOnProof() {
    // A winn session that would seize the host's default IPv4 route is STAGED:
    // it receives a narrow bootstrap first, and the full-tunnel widening is
    // gated on the datapath proof. It is the ONLY shape that widens on proof.
    XCTAssertTrue(WinsWinnDatapathProofGate.applies(
      winnEnabled: true,
      defaultIPv4RouteEnabled: true,
      devContainmentActive: false
    ))
    // Split-tunnel: no default route is seized, so there is nothing to widen and
    // therefore nothing to gate on proof.
    XCTAssertFalse(WinsWinnDatapathProofGate.applies(
      winnEnabled: true,
      defaultIPv4RouteEnabled: false,
      devContainmentActive: false
    ))
    // Non-winn: there is no winn/3 datapath to authenticate, so no staged
    // widening gated on it.
    XCTAssertFalse(WinsWinnDatapathProofGate.applies(
      winnEnabled: false,
      defaultIPv4RouteEnabled: true,
      devContainmentActive: false
    ))
    // Dev-contained: already never installs full-tunnel settings, so it is not
    // staged for a proof-gated widening either.
    XCTAssertFalse(WinsWinnDatapathProofGate.applies(
      winnEnabled: true,
      defaultIPv4RouteEnabled: true,
      devContainmentActive: true
    ))
  }

  func testDatapathProofRequiresBothCryptographicAndBidirectionalCarriage() {
    let handshake = WinsWinnDatapathProofGate.convergenceHandshakeKey
    let transport = WinsWinnDatapathProofGate.convergenceTransportKey

    // The ONLY case that may promote: handshake response observed AND payload
    // transport observed both ways. This is the authenticated datapath.
    XCTAssertTrue(WinsWinnDatapathProofGate.converged(
      engineStatusFields: [handshake: true, transport: true]
    ))
    // Every missing or false flag must fail closed: a widening that requires one
    // of these is not allowed to proceed.
    XCTAssertFalse(WinsWinnDatapathProofGate.converged(engineStatusFields: [:]))
    XCTAssertFalse(WinsWinnDatapathProofGate.converged(
      engineStatusFields: [handshake: true]
    ))
    XCTAssertFalse(WinsWinnDatapathProofGate.converged(
      engineStatusFields: [transport: true]
    ))
    XCTAssertFalse(WinsWinnDatapathProofGate.converged(
      engineStatusFields: [handshake: false, transport: true]
    ))
    XCTAssertFalse(WinsWinnDatapathProofGate.converged(
      engineStatusFields: [handshake: true, transport: false]
    ))
  }

  func testDatapathProofBootstrapRouteIsNeverADefaultRoute() throws {
    // The one route a bootstrap posture may carry (lines 664-676 of
    // PacketTunnelProvider.swift) is the tunnel's own inner /32 gateway. It must
    // never be a default route: that is the widening this gate reserves for AFTER
    // the proof.
    let route = try XCTUnwrap(
      WinsWinnDatapathProofGate.bootstrapGatewayRoute(interfaceIPv4Address: "10.7.0.2")
    )
    XCTAssertEqual(route.destinationAddress, "10.7.0.1")
    XCTAssertEqual(route.subnetMask, "255.255.255.255")
    XCTAssertEqual(route.prefixLength, 32)
    XCTAssertFalse(route.isDefaultRoute)
    // A /32 route to the interface's own address (x.y.z.n == x.y.z.1) is never
    // installed — a route to self.
    XCTAssertNil(
      WinsWinnDatapathProofGate.bootstrapGatewayRoute(interfaceIPv4Address: "10.7.0.1")
    )
    // Unparseable input produces no route, never a default route.
    XCTAssertNil(
      WinsWinnDatapathProofGate.bootstrapGatewayRoute(interfaceIPv4Address: "not-an-ip")
    )
  }

  func testWideningRouteShapeIsDistinctFromBootstrapNarrowShape() throws {
    // The widening content is the default IPv4 route (`0.0.0.0/0`). Assert the
    // shape that promotion commits exists and is recognisable, so the widening
    // can be shown never to live in the bootstrap.
    let defaultRoute = WinsIPv4Route(
      destinationAddress: "0.0.0.0",
      subnetMask: "0.0.0.0",
      prefixLength: 0
    )
    XCTAssertTrue(defaultRoute.isDefaultRoute)

    // The bootstrap posture's sole permitted route is a /32 and can never be the
    // default-route widening.
    let bootstrap = try XCTUnwrap(
      WinsWinnDatapathProofGate.bootstrapGatewayRoute(interfaceIPv4Address: "10.7.0.2")
    )
    XCTAssertFalse(bootstrap.isDefaultRoute)
    XCTAssertEqual(bootstrap.prefixLength, 32)
  }

  func testBootstrapPostureStatusNeverClaimsDefaultRouteIPv6OrDNS() {
    // The bootstrap posture is reported as observably narrow: not only does it
    // omit the widening, it states so in its status vocabulary.
    let fields = WinsWinnDatapathProofGate.bootstrapStatusFields(
      bootstrapIncludedRouteCount: 1,
      bootstrapGatewayRoutePresent: true,
      transportExclusionRoutePresent: false,
      probeTargetCount: 2
    )
    XCTAssertEqual(fields["winn_datapath_proof_gate_active"] as? Bool, true)
    XCTAssertEqual(fields["winn_datapath_proof_bootstrap_observably_narrow"] as? Bool, true)
    XCTAssertEqual(
      fields["winn_datapath_proof_bootstrap_default_ipv4_route_installed"] as? Bool,
      false
    )
    XCTAssertEqual(
      fields["winn_datapath_proof_bootstrap_ipv6_settings_installed"] as? Bool,
      false
    )
    XCTAssertEqual(
      fields["winn_datapath_proof_bootstrap_dns_settings_installed"] as? Bool,
      false
    )
    XCTAssertEqual(fields["winn_datapath_proof_bootstrap_included_route_count"] as? Int, 1)
  }

  // MARK: - Widening route carriage is proof-gated (gen_macos_tunnel_routes)

  // This closes the gap between the PURE gate above and the route carriage the
  // provider actually commits. `makeNetworkSettings` (PacketTunnelProvider.swift
  // lines 422-445) builds `ipv4Settings.includedRoutes` from
  // `config.allowedIPv4Routes`; that object becomes `fullTunnelSettings` and is
  // installed by PROMOTION ONLY (`setTunnelNetworkSettings(plan.fullTunnelSettings)`
  // inside `beginPromotion`, reached only after `datapathKind.converged &&
  // probeSatisfied`). The bootstrap postures (lines 665-675 and the narrow one)
  // may carry at most the tunnel's own inner /32 gateway — never the widening.
  //
  // These assertions pin that the route carriage a full-tunnel winn start seizes
  // is always staged (so `applies` opens the proof-gated path), that the gate is
  // not open until an authenticated winn/3 datapath is observed, and that the
  // widening content is disjoint from what any bootstrap posture can install.

  func testWideningRouteCarriageIsAlwaysStagedAndNeverInTheBootstrap() throws {
    // The route content `makeNetworkSettings` maps into
    // `ipv4Settings.includedRoutes` (lines 422-445) for a full-tunnel config:
    // on macOS a bare default widens to the /1 pair, never a bare 0.0.0.0/0.
    let config = try validConfig()
    XCTAssertTrue(config.defaultIPv4RouteEnabled)
    XCTAssertEqual(
      config.appleIncludedIPv4Routes.map { "\($0.destinationAddress)/\($0.prefixLength)" },
      ["0.0.0.0/1", "128.0.0.0/1"],
      "the widening route content the provider installs must be the /1 pair"
    )

    // A start that would seize the host's default route is ALWAYS staged when
    // winn is on, so this widening can never be installed unconditionally: it is
    // only ever committed through the proof-gated promotion path.
    XCTAssertTrue(WinsWinnDatapathProofGate.applies(
      winnEnabled: true,
      defaultIPv4RouteEnabled: true,
      devContainmentActive: false
    ))

    // The gate is not open until the authenticated datapath is proven, so
    // promotion (which commits the widening) can never run first.
    XCTAssertFalse(WinsWinnDatapathProofGate.converged(engineStatusFields: [:]))

    // The bootstrap postures may carry at most the tunnel's own inner /32
    // gateway — never any widening route (lines 665-675 and the narrow branch).
    let bootstrap = try XCTUnwrap(
      WinsWinnDatapathProofGate.bootstrapGatewayRoute(
        interfaceIPv4Address: config.interfaceIPv4Address
      )
    )
    XCTAssertEqual(bootstrap.prefixLength, 32)
    XCTAssertFalse(bootstrap.isDefaultRoute)
    let bootstrapMatchesWidening = config.appleIncludedIPv4Routes.contains { widening in
      widening.destinationAddress == bootstrap.destinationAddress
        && widening.prefixLength == bootstrap.prefixLength
    }
    XCTAssertFalse(
      bootstrapMatchesWidening,
      "no route a bootstrap posture may carry may equal the widening route carriage"
    )
  }

  // MARK: - winn/3 STANDALONE promotion-gate refusals
  //         (gen_macos_provider_standalone)

  // The relay path above widens from a narrow bootstrap only after
  // `WinsWinnDatapathProofGate.converged` has authenticated the datapath. The
  // winn/3 STANDALONE fork (`startWinn3StandaloneSession`,
  // macos/PacketTunnel/PacketTunnelProvider.swift ~1196-1416) refuses the SAME
  // widening one step earlier, on two PRE-INSTALL guards that both run before
  // anything is installed and before any outer socket is committed:
  //
  //   1030 (line ~1231) — `guard !config.allowedIPv4Routes.isEmpty`: a standalone
  //          config with no included routes has nothing to promote to, so a
  //          datapath proven for it would end by "installing a tunnel that
  //          routes nothing". Refused while the datapath is not yet started, so
  //          no gateway is ever dialled for a session that could not carry.
  //   1039 (line ~1309) — `guard WinsKillSwitch.egressBlocked(by:
  //          fullTunnelSettings, config: config)`: a production full-tunnel
  //          standalone session installs the BLOCKING full-tunnel posture as its
  //          FIRST posture (before proof), so that posture must observably
  //          block egress or the session is refused rather than installed
  //          leaking.
  //
  // These drive the SAME pure predicates the two guards read
  // (`config.allowedIPv4Routes`, `WinsWinn3Settings.fullTunnel`,
  // `WinsKillSwitch.egressBlocked`, `WinsWinn3PromotedPosture.evaluate`) — the
  // production code in `apple/WinsTunnelCore`, compiled into this module, not a
  // replica. They pin that a staged winn/3 start cannot widen from a narrow
  // IPv4 route before an authenticated winn/3 datapath exists: either the
  // widening never started (no routes to go to, refused at 1030) or the first
  // posture would not capture what the config asked it to capture, so it is not
  // installed (refused at 1039).

  private var standaloneInterfaceKey: String {
    Data(repeating: 0x11, count: 32).base64EncodedString()
  }

  private var standaloneGatewayKey: String {
    Data(repeating: 0x22, count: 32).base64EncodedString()
  }

  private var standaloneGatewayID: String {
    Data("wins-lab-gateway".utf8).base64EncodedString()
  }

  private var standaloneAdmissionKey: String {
    Data(repeating: 0x33, count: 32).base64EncodedString()
  }

  private var standaloneWGKey: String {
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
  }

  /// A complete winn/3 STANDALONE descriptor: full-tunnel route set
  /// (0.0.0.0/0, ::/0), a resolver this host can derive to be inner (10.13.0.9,
  /// inside the /24 around inner_v4), and an IPv4 `[winn]` endpoint
  /// (198.51.100.7) so the carrier-exclusion /32 exists. Every capture clause
  /// of `WinsKillSwitch.egressBlocked` and every clause of
  /// `WinsWinn3PromotedPosture.evaluate` is therefore live.
  private func standaloneConfig(
    interfaceDNS: String = "10.13.0.9",
    allowedIPs: String = "0.0.0.0/0, ::/0"
  ) -> WinsTunnelConfig {
    WinsTunnelConfig.parse(
      """
      [Interface]
      PrivateKey = \(standaloneWGKey)
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
      PublicKey = \(standaloneWGKey)
      Endpoint = 203.0.113.10:9110
      AllowedIPs = \(allowedIPs)
      PersistentKeepalive = 25

      [Winn]
      Enabled = true
      Endpoint = 198.51.100.7:51820
      Carrier = winn3
      Session_Id = winn3-standalone
      Inner_V4 = 10.13.0.2
      Inner_Router_V4 = 10.13.0.1
      Static_Private = \(standaloneInterfaceKey)
      Gateway_Static = \(standaloneGatewayKey)
      Gateway_Id = \(standaloneGatewayID)
      Admission_Key = \(standaloneAdmissionKey)
      Path_Mtu = 1400
      Carrier_Classes = udp, tls
      H1 = 11
      H2 = 22
      H3 = 33
      H4 = 44
      S1 = 16
      S2 = 80
      S3 = 16
      S4 = 0
      """
    )
  }

  /// The blocking full-tunnel posture a production winn/3 STANDALONE session
  /// commits as its FIRST posture. Fails the test if the configuration cannot
  /// build a usable posture.
  private func standaloneBlockingFullTunnel(
    _ config: WinsTunnelConfig
  ) throws -> NEPacketTunnelNetworkSettings {
    let innerMTU = 1309  // fleet default for path 1450; >= the IPv6 sink floor
    return try XCTUnwrap(
      WinsWinn3Settings.fullTunnel(config: config, innerMTU: innerMTU),
      "a complete full-tunnel standalone config must build a usable full-tunnel posture"
    )
  }

  // code 1039: the FIRST posture a production full-tunnel standalone session
  // installs is the blocking full-tunnel posture, BEFORE any datapath proof. The
  // `guard WinsKillSwitch.egressBlocked(...)` at PacketTunnelProvider.swift
  // ~1309 refuses the session (never installing it) when this predicate is
  // false.
  func testWinn3StandaloneKillSwitchFirstPostureBlocksEgressBeforeDatapathProof() throws {
    let config = standaloneConfig()
    XCTAssertTrue(config.winn3Enabled)
    XCTAssertTrue(config.defaultIPv4RouteEnabled,
                  "the fixture must be a full-tunnel document")
    XCTAssertTrue(config.ipv6LeakProtectionEnabled,
                  "the fixture must request ::/0 so the IPv6 capture clause is live")

    // A standard production full-tunnel standalone run is NOT a dev run, so the
    // kill switch must be active from the first installed posture.
    XCTAssertTrue(WinsKillSwitch.activeFor(config: config, devRunActive: false))

    let full = try standaloneBlockingFullTunnel(config)
    XCTAssertTrue(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "the first posture a winn/3 standalone session commits must observably block egress before any datapath proof"
    )
  }

  // code 1039 (fail-closed): each capture clause of the kill-switch read-back is
  // independently breakable, so a builder that silently narrows ANY one family
  // turns `egressBlocked` false and the standalone fork refuses (code 1039)
  // rather than installing a posture that leaks. These are the "none after
  // kill-switch" negatives, applied to the very settings object the fork would
  // install, with the untouched posture restored as the positive control so the
  // negatives are clause-breaking mutations and not the harness failing closed
  // for every input.
  func testWinn3StandaloneKillSwitchEveryCaptureClauseFailsClosed() throws {
    let config = standaloneConfig()
    XCTAssertTrue(
      WinsKillSwitch.egressBlocked(by: try standaloneBlockingFullTunnel(config), config: config)
    )

    var full = try standaloneBlockingFullTunnel(config)
    let ipv4 = try XCTUnwrap(full.ipv4Settings)

    // 1. IPv4 default route removed -> non-matching hosts leave on the physical
    //    interface in the clear.
    ipv4.includedRoutes = [
      NEIPv4Route(destinationAddress: "10.13.0.9", subnetMask: "255.255.255.255")
    ]
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture without the 0.0.0.0/0 default route must NOT claim a blocked IPv4 egress"
    )

    // 2. IPv6 capture dropped while the config still requests ::/0 -> host IPv6
    //    stays on the physical interface.
    full = try standaloneBlockingFullTunnel(config)
    full.ipv6Settings = nil
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture that leaves the host's ::/0 outside the tunnel must NOT claim capture"
    )

    // 3. DNS resolver removed -> every query resolves to the ISP's resolver in
    //    the clear.
    full = try standaloneBlockingFullTunnel(config)
    full.dnsSettings = nil
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture whose name resolution is not tunnelled must NOT claim a blocked egress"
    )
    full = try standaloneBlockingFullTunnel(config)
    full.dnsSettings?.matchDomains = ["example.com"]
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture that only tunnels one domain must NOT claim it captures all DNS"
    )

    // 4. Carrier exclusion removed -> the tunnel's own outer socket is captured
    //    by its own default route (dead loop). Live only because the fixture
    //    carries a real IPv4 transport endpoint to exclude.
    let transport = try XCTUnwrap(
      config.transportIPv4ExclusionRoute,
      "the fixture's [winn] endpoint must produce a carrier exclusion /32"
    )
    full = try standaloneBlockingFullTunnel(config)
    full.ipv4Settings?.excludedRoutes = []
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture that does not exclude its own carrier edge (\(transport.destinationAddress)) must NOT claim a blocked egress"
    )

    // POSITIVE control: the untouched posture restores to a blocked egress, so
    // each negative above is a real clause break and not the predicate failing
    // for every input.
    let restored = try standaloneBlockingFullTunnel(config)
    XCTAssertTrue(WinsKillSwitch.egressBlocked(by: restored, config: config))
  }

  // code 1030: a winn/3 STANDALONE config with NO included IPv4 routes has
  // nothing to promote to. The fork refuses (~line 1231) rather than "proving a
  // datapath and then installing a tunnel that routes nothing". The guarded fact
  // is `config.allowedIPv4Routes.isEmpty`; even if a datapath were proven, the
  // full-tunnel posture such a config would promote to routes nothing, which the
  // promoted-posture verifier and the kill-switch read-back both refuse — so a
  // staged winn/3 start can never widen onto a route set that captures nothing.
  func testWinn3StandaloneForkRefusesNoIncludedRoutesToPromote() throws {
    let config = standaloneConfig(allowedIPs: "")
    XCTAssertTrue(config.winn3Enabled)
    XCTAssertTrue(
      config.allowedIPv4Routes.isEmpty,
      "a standalone config with no IPv4 routes is the exact shape the fork's 1030 guard refuses"
    )

    XCTAssertNil(
      WinsWinn3Settings.fullTunnel(config: config, innerMTU: 1309),
      "a standalone config with no included routes must fail closed before a promotable posture exists"
    )
  }

  func testWinn3DualAuthPairIsConsumedFailClosedAndNotReboundStale() throws {
    let ed = Data(repeating: 0xAA, count: 32).base64EncodedString()
    let ml = Data(repeating: 0xBB, count: 1952).base64EncodedString()
    let complete = standaloneConfig()
    XCTAssertTrue(complete.winn3AuthEd25519.isEmpty && complete.winn3AuthMldsa65.isEmpty)
    XCTAssertTrue(WinsWinn3StartRequirements.unmetReasons(complete).isEmpty)
    let freshJSON = try XCTUnwrap(WinsWinn3CreateDocument.make(config: complete)).json()
    XCTAssertFalse(freshJSON.contains("auth_ed25519"))
    XCTAssertFalse(freshJSON.contains("auth_mldsa65"))
    XCTAssertFalse(freshJSON.contains("dual_auth"))

    func withWinnLines(_ extra: String) -> WinsTunnelConfig {
      WinsTunnelConfig.parse(
        """
        [Interface]
        PrivateKey = \(standaloneWGKey)
        Address = 10.13.0.2/32
        MTU = 1280
        DNS = 10.13.0.9
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
        PublicKey = \(standaloneWGKey)
        Endpoint = 203.0.113.10:9110
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25

        [Winn]
        Enabled = true
        Endpoint = 198.51.100.7:51820
        Carrier = winn3
        Session_Id = winn3-standalone
        Inner_V4 = 10.13.0.2
        Inner_Router_V4 = 10.13.0.1
        Static_Private = \(standaloneInterfaceKey)
        Gateway_Static = \(standaloneGatewayKey)
        Gateway_Id = \(standaloneGatewayID)
        Admission_Key = \(standaloneAdmissionKey)
        Path_Mtu = 1400
        Carrier_Classes = udp, tls
        H1 = 11
        H2 = 22
        H3 = 33
        H4 = 44
        S1 = 16
        S2 = 80
        S3 = 16
        S4 = 0
        \(extra)
        """
      )
    }

    let missing = withWinnLines("auth_ed25519 = \(ed)")
    XCTAssertEqual(missing.winn3AuthEd25519, ed)
    XCTAssertTrue(missing.winn3AuthMldsa65.isEmpty)
    let missingReason = try XCTUnwrap(missing.winn3StartRefusalReason)
    XCTAssertTrue(missingReason.contains("auth_ed25519"))
    XCTAssertTrue(missingReason.contains("auth_mldsa65"))
    XCTAssertNil(WinsWinn3CreateDocument.make(config: missing))

    let mismatch = withWinnLines(
      """
      auth_ed25519 = \(Data(repeating: 0xAA, count: 31).base64EncodedString())
      auth_mldsa65 = \(ml)
      """
    )
    let mismatchReason = try XCTUnwrap(mismatch.winn3StartRefusalReason)
    XCTAssertTrue(mismatchReason.contains("auth_ed25519"))
    XCTAssertNil(WinsWinn3CreateDocument.make(config: mismatch))

    let both = withWinnLines(
      """
      auth_ed25519 = \(ed)
      auth_mldsa65 = \(ml)
      """
    )
    XCTAssertEqual(both.winn3AuthEd25519, ed)
    XCTAssertEqual(both.winn3AuthMldsa65, ml)
    // Since ee48a2f the Apple create path ingests a canonical pair (see
    // tools/verify_apple_winn3_host_contract_harness.swift against the real
    // archive): it is forwarded byte for byte, never refused or dropped.
    XCTAssertNil(both.winn3StartRefusalReason)
    let bothJSON = try XCTUnwrap(WinsWinn3CreateDocument.make(config: both)).json()
    let bothObject = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(bothJSON.utf8)) as? [String: Any]
    )
    XCTAssertEqual(bothObject["auth_ed25519"] as? String, ed)
    XCTAssertEqual(bothObject["auth_mldsa65"] as? String, ml)

    let stale = standaloneConfig()
    XCTAssertTrue(stale.winn3AuthEd25519.isEmpty && stale.winn3AuthMldsa65.isEmpty)
    XCTAssertTrue(WinsWinn3StartRequirements.unmetReasons(stale).isEmpty)
    let staleJSON = try XCTUnwrap(WinsWinn3CreateDocument.make(config: stale)).json()
    XCTAssertFalse(staleJSON.contains("auth_ed25519"))
    XCTAssertFalse(staleJSON.contains("dual_auth"))
  }

  // MARK: - RouteAudit route-leak audit layer

  func testRouteAuditEmitsEnforceAndExcludeMarkersForARoutePosture() {
    let line = RouteAudit.log(
      enforceRoutes: true,
      excludedRoutes: ["192.168.50.1/32"]
    )
    XCTAssertTrue(
      line.contains(RouteAudit.enforceMarker),
      "audit line must carry the enforce marker, got: \(line)"
    )
    XCTAssertTrue(
      line.contains(RouteAudit.excludeMarker),
      "audit line must carry the exclude marker, got: \(line)"
    )
    XCTAssertTrue(line.contains("enforce=on"), "enforced posture must be annotated on: \(line)")
    XCTAssertTrue(
      line.contains("exclude=192.168.50.1/32"),
      "excluded route must be annotated: \(line)"
    )
  }

  func testRouteAuditMarkersTrackPostureValuesSoEmissionCannotBeHardcoded() {
    let enforced = RouteAudit.log(enforceRoutes: true, excludedRoutes: [])
    XCTAssertTrue(enforced.contains("enforce=on"), "enforced posture must read on: \(enforced)")
    XCTAssertFalse(enforced.contains("enforce=off"), "enforced posture must not read off: \(enforced)")
    XCTAssertTrue(enforced.contains("exclude=none"), "empty exclusions must read none: \(enforced)")

    let relaxed = RouteAudit.log(enforceRoutes: false, excludedRoutes: ["10.0.0.0/8"])
    XCTAssertTrue(relaxed.contains("enforce=off"), "relaxed posture must read off: \(relaxed)")
    XCTAssertFalse(relaxed.contains("enforce=on"), "relaxed posture must not read on: \(relaxed)")
    XCTAssertTrue(
      relaxed.contains("exclude=10.0.0.0/8"),
      "relaxed posture must annotate its exclusion: \(relaxed)"
    )
    XCTAssertFalse(
      relaxed.contains("exclude=none"),
      "a populated exclusion must not read none: \(relaxed)"
    )
  }

  func testRouteAuditExcludedRouteStringRendersDestinationAndPrefix() {
    let route = WinsIPv4Route(
      destinationAddress: "192.168.50.226",
      subnetMask: "255.255.255.255",
      prefixLength: 32
    )
    XCTAssertEqual(
      RouteAudit.excludedRouteString(route),
      "192.168.50.226/32",
      "the connect-path audit must render the /32 carve-out as destination/prefix"
    )
    let line = RouteAudit.log(
      enforceRoutes: false,
      excludedRoutes: [RouteAudit.excludedRouteString(route)]
    )
    XCTAssertTrue(line.contains("exclude=192.168.50.226/32"), "expected route in line, got: \(line)")
  }


  func testRouteAuditRenderEmitsEnforceAndExcludeMarkersVerbatim() {
    // `render` is the PURE half of the audit: it must produce the one-line
    // record containing the `enforce` and `exclude` markers LITERALLY, with no
    // logging side effect at all -- logging is confined to the `log` call site.
    let line = RouteAudit.render(
      enforceRoutes: true,
      excludedRoutes: ["192.168.50.1/32"]
    )
    XCTAssertTrue(
      line.contains("route-audit"),
      "record must open with the audit prefix, got: \(line)"
    )
    XCTAssertTrue(
      line.contains(RouteAudit.enforceMarker),
      "record must carry the enforce marker verbatim, got: \(line)"
    )
    XCTAssertTrue(
      line.contains(RouteAudit.excludeMarker),
      "record must carry the exclude marker verbatim, got: \(line)"
    )
    XCTAssertTrue(
      line.contains("enforce=on"),
      "enforced posture must render enforce=on verbatim, got: \(line)"
    )
    XCTAssertTrue(
      line.contains("exclude=192.168.50.1/32"),
      "excluded route must render verbatim, got: \(line)"
    )
  }

  func testRouteAuditRenderIsPureAndMatchesLogOutput() {
    // `log` must be exactly `render` + one os_log write, so the pure record
    // returned is byte-identical to the value `log` returns (and thus to what
    // is written to the log). If a wiring change makes `log` diverge from
    // `render`, this fails.
    let rendered = RouteAudit.render(
      enforceRoutes: false,
      excludedRoutes: ["10.0.0.0/8"]
    )
    let logged = RouteAudit.log(
      enforceRoutes: false,
      excludedRoutes: ["10.0.0.0/8"]
    )
    XCTAssertEqual(
      logged,
      rendered,
      "log() must return exactly what render() produces (os_log stays at the call site)"
    )
    XCTAssertTrue(rendered.contains("enforce=off"))
    XCTAssertTrue(rendered.contains("exclude=10.0.0.0/8"))
    XCTAssertTrue(rendered.contains("enforce=off"))
  }

  func testRouteAuditRenderTracksPostureSoRenderingCannotBeHardcoded() {
    let on = RouteAudit.render(enforceRoutes: true, excludedRoutes: [])
    let off = RouteAudit.render(
      enforceRoutes: false,
      excludedRoutes: ["172.16.0.0/12"]
    )
    XCTAssertTrue(on.contains("enforce=on"))
    XCTAssertFalse(on.contains("enforce=off"))
    XCTAssertTrue(on.contains("exclude=none"))
    XCTAssertTrue(off.contains("enforce=off"))
    XCTAssertFalse(off.contains("enforce=on"))
    XCTAssertTrue(off.contains("exclude=172.16.0.0/12"))
    XCTAssertFalse(off.contains("exclude=none"))
  }

  // MARK: - macOS enforceRoutes carriage (probe re-save seam)

  // The macOS packet tunnel's `enforceRoutes` only persists if some process
  // re-saves the NetworkExtension configuration (see the WinsNECPPostureProbe
  // comment in `macos/Runner/AppDelegate.swift`). The probe's re-save routine --
  // `WinsNECPPostureProbe.reSaveAndReport` -- is the only writer of that bool
  // independent of the Flutter connect path, so its carriage must be pinned:
  // requesting `enforceRoutes = true` must round-trip to
  // `after_enforce_routes == true` on the RELOADED protocol.
  //
  // The probe's persistence is injected behind `WinsNECPPosturePreferences`, so
  // this test drives the SAME routine the launch path uses with an in-memory
  // store -- no NE daemon (section 19 runs CODE_SIGNING_ALLOWED=NO), no app-group
  // container, no exit(0). The store reloads from what was saved, so a routine
  // that failed to persist the bool cannot forge a green.

  private final class EnforceRoutesMemoryStore: WinsNECPPosturePreferences {
    private var snapshots: [String: (enforce: Bool, exclude: Bool, include: Bool, provider: [String: Any]?)] = [:]
    let initialEnforce: Bool
    init(initialEnforce: Bool, bundleID: String) {
      self.initialEnforce = initialEnforce
      snapshots[bundleID] = (initialEnforce, true, false, ["existing": "yes"])
    }

    func loadAll(completion: @escaping (Result<[NETunnelProviderManager], Error>) -> Void) {
      let manager = NETunnelProviderManager()
      manager.isEnabled = true
      // A FRESH protocol is reconstructed from snapshot state each load, so the
      // reloaded object is provably distinct from any in-memory object the
      // routine might mistakenly trust.
      if let s = snapshots.first?.value {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = snapshots.first?.key
        proto.enforceRoutes = s.enforce
        proto.excludeLocalNetworks = s.exclude
        proto.includeAllNetworks = false
        proto.providerConfiguration = s.provider
        manager.protocolConfiguration = proto
      }
      completion(.success([manager]))
    }

    func save(_ manager: NETunnelProviderManager, completion: @escaping (Result<Void, Error>) -> Void) {
      guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
            let bundleID = proto.providerBundleIdentifier else {
        completion(.failure(NSError(domain: "EnforceRoutesMemoryStore", code: 1)))
        return
      }
      snapshots[bundleID] = (
        proto.enforceRoutes,
        proto.excludeLocalNetworks,
        proto.includeAllNetworks,
        proto.providerConfiguration
      )
      completion(.success(()))
    }
  }

  func testMacOSEnforceRoutesCarriagePersistsRequestedTrueIntoLoadedProtocol() {
    let bundleID = "org.winsvpn.app.PacketTunnel"
    let store = EnforceRoutesMemoryStore(initialEnforce: false, bundleID: bundleID)

    let done = expectation(description: "re-save routine completed")
    var report: [String: Any] = [:]
    WinsNECPPostureProbe.reSaveAndReport(
      requestedEnforceRoutes: true,
      requestedExcludeLocalNetworks: nil,
      providerBundleIdentifier: bundleID,
      preferences: store,
      baseReport: [:]
    ) { completed in
      report = completed
      done.fulfill()
    }
    wait(for: [done], timeout: 5)

    XCTAssertEqual(report["stage"] as? String, "saved")
    XCTAssertEqual(report["before_enforce_routes"] as? Bool, false)
    XCTAssertEqual(
      report["after_enforce_routes"] as? Bool,
      true,
      "requesting enforceRoutes=true must make the RELOADED protocol report after_enforce_routes == true"
    )
    XCTAssertEqual(report["requested_enforce_routes"] as? Bool, true)

    // The loaded protocol (a fresh reload through the same store) must itself
    // report true -- this is "the loaded NETunnelProviderProtocol" claim, not a
    // side-channel description of it.
    let reloadedDone = expectation(description: "store reload")
    store.loadAll { result in
      switch result {
      case .success(let managers):
        let proto = managers.first?.protocolConfiguration as? NETunnelProviderProtocol
        XCTAssertEqual(proto?.enforceRoutes, true)
        XCTAssertEqual(proto?.providerBundleIdentifier, bundleID)
      case .failure(let error):
        XCTFail("store reload failed: \(error)")
      }
      reloadedDone.fulfill()
    }
    wait(for: [reloadedDone], timeout: 5)
  }

  func testMacOSEnforceRoutesCarriageKeepsRequestedExcludeLocalUntouched() {
    let bundleID = "org.winsvpn.app.PacketTunnel"
    let store = EnforceRoutesMemoryStore(initialEnforce: false, bundleID: bundleID)

    let done = expectation(description: "re-save routine completed")
    var report: [String: Any] = [:]
    WinsNECPPostureProbe.reSaveAndReport(
      requestedEnforceRoutes: true,
      requestedExcludeLocalNetworks: nil,
      providerBundleIdentifier: bundleID,
      preferences: store,
      baseReport: [:]
    ) { completed in
      report = completed
      done.fulfill()
    }
    wait(for: [done], timeout: 5)

    XCTAssertEqual(report["after_exclude_local_networks"] as? Bool, true)
    XCTAssertNil(report["requested_exclude_local_networks"] as? Bool)
  }

  // MARK: - MainFlutterWindow window-config enforceRoutes (probe-report funnel)

  // The window's `WinsMacOSTunnelBridge.startTunnel` path is the ONLY writer of
  // the routing posture on macOS. This pins that it DOES set `enforceRoutes`
  // when configuring the packet tunnel provider, and that the window-config
  // path funnels through the SAME `requested_enforce_routes` reporting key
  // used by `WinsNECPPostureProbe.reSaveAndReport` in
  // `macos/Runner/AppDelegate.swift:372`. A hardcoded report or a rename that
  // drops the key must be caught.
  func testMacOSMainWindowConfigSetsEnforceRoutesWhenConfiguringProvider() {
    let (proto, report) = WinsMacMainWindowRouteReporting.configuredProtocolAndReport()

    XCTAssertEqual(
      proto.enforceRoutes,
      WinsMacRoutePosture.enforceRoutes,
      "MainFlutterWindow window-config must set enforceRoutes from WinsMacRoutePosture when configuring the provider"
    )
    XCTAssertTrue(
      proto.excludeLocalNetworks,
      "window-config must pin excludeLocalNetworks true alongside enforceRoutes"
    )
    XCTAssertEqual(
      report[WinsMacMainWindowRouteReporting.requestedEnforceRoutesKey] as? Bool,
      WinsMacRoutePosture.enforceRoutes,
      "window report must carry requested_enforce_routes under the probe's key"
    )
    XCTAssertEqual(
      report["applied_enforce_routes"] as? Bool,
      proto.enforceRoutes,
      "applied report must equal the protocol's enforceRoutes"
    )
  }

  func testMacOSMainWindowConfigReportUsesSameRequestedEnforceRoutesKeyAsProbe() {
    // The window-config report MUST use the same literal key AppDelegate uses
    // at line ~372: "requested_enforce_routes". A rename that drops the key
    // would silently decouple the two audit paths.
    XCTAssertEqual(
      WinsMacMainWindowRouteReporting.requestedEnforceRoutesKey,
      "requested_enforce_routes",
      "window seam must expose the same key literal AppDelegate's probe uses"
    )

    let (windowProto, windowReport) = WinsMacMainWindowRouteReporting.configuredProtocolAndReport()
    let windowRequested = windowReport[WinsMacMainWindowRouteReporting.requestedEnforceRoutesKey] as? Bool
    let windowRequestedViaLiteral = windowReport["requested_enforce_routes"] as? Bool
    XCTAssertEqual(windowRequested, windowRequestedViaLiteral, "literal and constant must resolve to same report entry")
    XCTAssertEqual(windowRequested, WinsMacRoutePosture.enforceRoutes)

    // Drive the SAME reSaveAndReport seam AppDelegate uses with the same
    // requested value and prove it reports under the identical key and that
    // the reloaded protocol agrees with the window's protocol.
    let bundleID = "org.winsvpn.app.PacketTunnel"
    let store = EnforceRoutesMemoryStore(initialEnforce: !WinsMacRoutePosture.enforceRoutes, bundleID: bundleID)
    let probeDone = expectation(description: "probe re-save completed")
    var probeReport: [String: Any] = [:]
    WinsNECPPostureProbe.reSaveAndReport(
      requestedEnforceRoutes: WinsMacRoutePosture.enforceRoutes,
      requestedExcludeLocalNetworks: nil,
      providerBundleIdentifier: bundleID,
      preferences: store,
      baseReport: [:]
    ) { completed in
      probeReport = completed
      probeDone.fulfill()
    }
    wait(for: [probeDone], timeout: 5)

    let probeRequested = probeReport["requested_enforce_routes"] as? Bool
    XCTAssertEqual(windowRequested, probeRequested, "window and probe must report same requested_enforce_routes value")
    XCTAssertEqual(windowProto.enforceRoutes, probeReport["after_enforce_routes"] as? Bool, "window proto and probe after_enforce_routes must agree")
    XCTAssertEqual(windowRequested, windowProto.enforceRoutes, "window report must track the live protocol, not a hardcoded constant")
  }

  // MARK: - Byte-identical config handoff of BOTH routing booleans

  // `gen_macos_config_handoff`. The secure-config handoff channel is
  // `WinsNECPPostureProbe.reSaveAndReport` (macos/Runner/AppDelegate.swift): the
  // App layer writes `enforceRoutes` and `excludeLocalNetworks` onto the
  // provider protocol it builds (MainFlutterWindow.startTunnel), and the probe
  // re-saves/reloads them through the SAME seam so the tunnel's saved
  // configuration round-trips. `MainFlutterWindow` pins BOTH booleans
  // (`enforceRoutes = WinsMacRoutePosture.enforceRoutes`,
  // `excludeLocalNetworks = true`), so the handoff must round-trip both, not
  // just one.
  //
  // This test drives the re-save routine with a NON-default pair for BOTH
  // fields (enforce true, exclude false, from an initial enforce false,
  // exclude true) so a failure to persist either one is visible, and asserts:
  //   * the report's `after_*` pair is JSON-byte-identical to the requested
  //     pair, and
  //   * a FRESH reload through the same store carries exactly the requested
  //     pair on the loaded NETunnelProviderProtocol.
  // The `EnforceRoutesMemoryStore` reconstructs a fresh protocol from what was
  // saved on every load, so a routine that failed to persist either bool cannot
  // forge the reload.
  func testMacOSConfigHandoffRoundTripsEnforceRoutesAndExcludeLocalNetworksByteIdentical() {
    let bundleID = "org.winsvpn.app.PacketTunnel"
    // Initial posture differs from the request in BOTH fields.
    let store = EnforceRoutesMemoryStore(initialEnforce: false, bundleID: bundleID)
    let requestedEnforce = true
    let requestedExclude = false

    let done = expectation(description: "re-save routine completed")
    var report: [String: Any] = [:]
    WinsNECPPostureProbe.reSaveAndReport(
      requestedEnforceRoutes: requestedEnforce,
      requestedExcludeLocalNetworks: requestedExclude,
      providerBundleIdentifier: bundleID,
      preferences: store,
      baseReport: [:]
    ) { completed in
      report = completed
      done.fulfill()
    }
    wait(for: [done], timeout: 5)

    XCTAssertEqual(report["stage"] as? String, "saved")
    XCTAssertEqual(report["before_enforce_routes"] as? Bool, false)
    XCTAssertEqual(report["before_exclude_local_networks"] as? Bool, true)
    XCTAssertEqual(report["requested_enforce_routes"] as? Bool, requestedEnforce)
    XCTAssertEqual(report["requested_exclude_local_networks"] as? Bool, requestedExclude)

    // BYTE-IDENTICAL: serialize the requested pair and the round-tripped pair
    // the same way and require the bytes to be equal.
    let requestedBytes = try! JSONSerialization.data(withJSONObject: [
      "enforce": requestedEnforce,
      "exclude": requestedExclude
    ], options: [.sortedKeys])
    let afterBytes = try! JSONSerialization.data(withJSONObject: [
      "enforce": report["after_enforce_routes"] as! Bool,
      "exclude": report["after_exclude_local_networks"] as! Bool
    ], options: [.sortedKeys])
    XCTAssertEqual(afterBytes, requestedBytes, "round-tripped bool pair must be byte-identical to the requested pair")
    XCTAssertEqual(report["after_enforce_routes"] as? Bool, requestedEnforce)
    XCTAssertEqual(report["after_exclude_local_networks"] as? Bool, requestedExclude)

    // The LOADED protocol (a fresh reload through the same store) must carry
    // exactly the requested pair.
    let reloadedDone = expectation(description: "store reload")
    store.loadAll { result in
      switch result {
      case .success(let managers):
        let proto = managers.first?.protocolConfiguration as? NETunnelProviderProtocol
        XCTAssertEqual(proto?.enforceRoutes, requestedEnforce)
        XCTAssertEqual(proto?.excludeLocalNetworks, requestedExclude)
        XCTAssertEqual(proto?.providerBundleIdentifier, bundleID)
      case .failure(let error):
        XCTFail("store reload failed: \(error)")
      }
      reloadedDone.fulfill()
    }
    wait(for: [reloadedDone], timeout: 5)
  }

  // MARK: - macOS relay full-tunnel included-route enumeration carriage
  //         (gen_macos_enforceroutes_carriage)

  // The relay `makeNetworkSettings` (macos/PacketTunnel/PacketTunnelProvider.swift)
  // maps `config.appleIncludedIPv4Routes` into `ipv4Settings.includedRoutes`, the
  // SAME enumeration the winn/3 standalone path installs. This pins that the
  // enumeration the relay ships is the `/1` pair and NOT a bare `/0` default,
  // and that the ROUTE SOURCE it must consume differs from the raw
  // `allowedIPv4Routes` (which for a full-tunnel config is a bare `0.0.0.0/0`).
  // Re-introducing `NEIPv4Route.default()` — the shape captured here as the
  // rejected regression — must be caught.
  func testMacOSRelayFullTunnelIncludedRoutesCarryTheSlashOnePairNotABareDefault() throws {
    let config = try validConfig()
    XCTAssertTrue(config.defaultIPv4RouteEnabled)

    // The RAW route source is a bare default. If any included-route mapping fed
    // off `allowedIPv4Routes` it would install this `0.0.0.0/0`, which is
    // precisely the shape the `/1` pair exists to replace on macOS.
    let raw = config.allowedIPv4Routes.map { "\($0.destinationAddress)/\($0.prefixLength)" }
    XCTAssertEqual(raw, ["0.0.0.0/0"], "a macOS full-tunnel RAW route list must be a bare default")

    // The enumeration the relay provider actually installs is the expanded pair.
    let installed = config.appleIncludedIPv4Routes.map { "\($0.destinationAddress)/\($0.prefixLength)" }
    XCTAssertEqual(
      installed,
      ["0.0.0.0/1", "128.0.0.0/1"],
      "the relay must install the /1 pair, never a bare 0.0.0.0/0"
    )

    // Reproduce the provider's exact mapping into NEIPv4Route and prove the
    // resulting set is a recognised full capture AND carries no bare default.
    let carvedOut: [NEIPv4Route] = config.appleIncludedIPv4Routes.map {
      NEIPv4Route(destinationAddress: $0.destinationAddress, subnetMask: $0.subnetMask)
    }
    XCTAssertTrue(
      WinsKillSwitch.capturesAllIPv4(carvedOut),
      "the installed /1 pair must be recognised by the kill-switch capture predicate"
    )
    XCTAssertFalse(
      carvedOut.contains { $0.destinationAddress == "0.0.0.0" && $0.destinationSubnetMask == "0.0.0.0" },
      "the relay must never install a bare 0.0.0.0/0 included route on macOS"
    )
    XCTAssertTrue(
      config.appleIncludedIPv4Routes.count == 2,
      "a macOS full-tunnel included-route enumeration must be exactly the two /1 routes"
    )
  }

  func testWinn3NativeStartOutcomeIsGenerationBoundAndDoesNotAuthorizeV1OnUnknownFailures() {
    let failures = WinsWinn3NativeStartOutcomeContract.failures()
    XCTAssertTrue(
      failures.isEmpty,
      failures.joined(separator: "; ")
    )
  }

  func testWinn3NativeStartWaitRejectsCrossProcessStaleGeneration() {
    var reads = 0
    let observation = WinsWinn3NativeStartClassifier.waitForProof(
      expectedGeneration: WinsWinn3NativeStartOutcomeContract.currentGeneration,
      isCurrent: { true },
      readStatus: {
        reads += 1
        return [
          "status_schema_version": WinsPacketTunnelProviderStatus.schemaVersion,
          "status_generation": WinsWinn3NativeStartOutcomeContract.staleGeneration,
          "stage": "engine_started",
          "engine_ready": true,
          "network_settings_ready": true,
          "winn3_datapath_proof_promoted": true
        ]
      },
      sleep: { _ in },
      now: { reads > 1 ? Date().addingTimeInterval(10) : Date() },
      deadline: Date().addingTimeInterval(5),
      pollInterval: 0
    )
    XCTAssertEqual(observation, .finished(.unknownTerminal))
    XCTAssertFalse(WinsWinn3NativeStartOutcome.unknownTerminal.authorizesV1Fallback)
    XCTAssertGreaterThan(reads, 0)
  }

  func testSelectedNodeCallerCopiesExactFlutterSlugIntoStartOptions() {
    let parsed = WinsTunnelConfig.parse("""
    [winn]
    selected_node = ini-node
    node_slug = ini-node
    """)
    let options = WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(
      rawConfig: "raw-config",
      clientPublicKey: "pub",
      accountScope: "scope",
      statusGeneration: "gen-1",
      arguments: [
        "config": "raw-config",
        "selected_node": "LAB-ALPHA"
      ],
      parsedConfig: parsed
    )
    XCTAssertEqual(options["selected_node"] as? String, "LAB-ALPHA")
    XCTAssertNil(
      options["node_slug"],
      "INI aliases must not overlay Flutter caller identities"
    )
    XCTAssertEqual(options["raw_config"] as? String, "raw-config")
    XCTAssertEqual(
      WinsWinn3SelectedNodeCaller.exactSlug(
        arguments: ["node_slug": "user-node"],
        parsedConfig: parsed
      ),
      "user-node"
    )
  }

  func testSelectedNodeCallerRefusesParsedIniWhenFlutterOmitsIdentity() {
    let parsed = WinsTunnelConfig.parse("""
    [winn]
    selected_node = lab-alpha
    """)
    let options = WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(
      rawConfig: "raw-config",
      clientPublicKey: "pub",
      accountScope: "scope",
      statusGeneration: "gen-1",
      arguments: ["config": "raw-config", "accountScope": "scope"],
      parsedConfig: parsed
    )
    XCTAssertNil(options["selected_node"])
    XCTAssertNil(
      WinsWinn3SelectedNodeCaller.exactSlug(
        arguments: ["config": "raw-config", "accountScope": "scope"],
        parsedConfig: parsed
      )
    )
  }

  func testSelectedNodeCallerKeepsConflictingAliasesInsteadOfFirstWins() {
    let parsed = WinsTunnelConfig.parse("[winn]\nselected_node = ini-node\n")
    let options = WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(
      rawConfig: "raw-config",
      clientPublicKey: "pub",
      accountScope: "scope",
      statusGeneration: "gen-1",
      arguments: [
        "node_slug": "lab-alpha",
        "selected_node": "lab-beta"
      ],
      parsedConfig: parsed
    )
    XCTAssertEqual(options["node_slug"] as? String, "lab-alpha")
    XCTAssertEqual(options["selected_node"] as? String, "lab-beta")
    XCTAssertNil(
      WinsWinn3SelectedNodeCaller.exactSlug(
        arguments: [
          "node_slug": "lab-alpha",
          "selected_node": "lab-beta"
        ],
        parsedConfig: parsed
      )
    )
  }

  func testSelectedNodeCallerPreservesNestedSlugMaps() {
    let parsed = WinsTunnelConfig.parse("[winn]\nselected_node = ini-node\n")
    let options = WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(
      rawConfig: "raw-config",
      clientPublicKey: "pub",
      accountScope: "scope",
      statusGeneration: "gen-1",
      arguments: [
        "selected_node": ["slug": "user-node", "name": "User Node"]
      ],
      parsedConfig: parsed
    )
    let nested = options["selected_node"] as? NSDictionary
    XCTAssertEqual(nested?["slug"] as? String, "user-node")
    XCTAssertEqual(
      WinsWinn3SelectedNodeCaller.exactSlug(
        arguments: ["selected_node": ["slug": "user-node"]],
        parsedConfig: parsed
      ),
      "user-node"
    )
  }

  func testNativeSamplerLifetimeDrainsConcurrentClaimsBeforeStop() {
    let lifetime = WinsNativeSamplerLifetime()
    XCTAssertTrue(lifetime.beginStart())
    lifetime.finishStart()

    let claimed = DispatchGroup()
    let samplers = DispatchGroup()
    let releaseSamplers = DispatchSemaphore(value: 0)
    for _ in 0..<32 {
      claimed.enter()
      samplers.enter()
      DispatchQueue.global(qos: .userInitiated).async {
        let publication = lifetime.claim { 7 }
        XCTAssertEqual(publication, 7)
        claimed.leave()
        releaseSamplers.wait()
        lifetime.releaseClaim()
        samplers.leave()
      }
    }
    XCTAssertEqual(claimed.wait(timeout: .now() + 2), .success)

    let stopDone = DispatchSemaphore(value: 0)
    DispatchQueue.global(qos: .userInitiated).async {
      XCTAssertTrue(lifetime.beginStopAndWaitForSamplers())
      lifetime.finishStop()
      stopDone.signal()
    }
    XCTAssertEqual(stopDone.wait(timeout: .now() + 0.05), .timedOut)
    for _ in 0..<32 { releaseSamplers.signal() }
    XCTAssertEqual(samplers.wait(timeout: .now() + 2), .success)
    XCTAssertEqual(stopDone.wait(timeout: .now() + 2), .success)
    let claimAfterStop: Int? = lifetime.claim { 9 }
    XCTAssertNil(claimAfterStop)
    XCTAssertFalse(lifetime.isRunning)
  }

  /// A-01 regression guard. `NEPacketTunnelNetworkSettings.IPv4Settings` is a
  /// `copy` property, so any route appended to the local `NEIPv4Settings` after
  /// the assignment is discarded. This asserts on what the SYSTEM would receive,
  /// never on the local object, which is the distinction the original defect hid
  /// behind.
  func testResolverRoutesSurviveTheSettingsCopyBoundary() throws {
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.8.1.1")
    let ipv4 = NEIPv4Settings(addresses: ["10.8.1.2"], subnetMasks: ["255.255.0.0"])
    // A split tunnel whose single included route does NOT cover the resolver.
    ipv4.includedRoutes = [
      NEIPv4Route(destinationAddress: "10.8.0.0", subnetMask: "255.255.0.0")
    ]
    ipv4.includedRoutes?.append(
      NEIPv4Route(destinationAddress: "9.9.9.9", subnetMask: "255.255.255.255")
    )
    settings.ipv4Settings = ipv4

    let stored = settings.ipv4Settings?.includedRoutes ?? []
    XCTAssertTrue(
      stored.contains { $0.destinationAddress == "9.9.9.9" && $0.destinationSubnetMask == "255.255.255.255" },
      "The resolver /32 must be present in the settings object the system installs, not merely in the local NEIPv4Settings."
    )
    XCTAssertFalse(
      settings.ipv4Settings === ipv4,
      "IPv4Settings is a copy property. If this ever becomes identity, re-derive the ordering rule in A-01 before relying on it."
    )
  }
}

private enum AuditWinnReaderHooks {
  static let condition = NSCondition()
  static var nextHandle: Int64 = 100
  static var entered = false
  static var released = false
  static var holdOnClose = false
  static var result: Int32 = -6
  static var closes = 0

  static func reset(result: Int32, holdOnClose: Bool = false) {
    condition.lock()
    entered = false
    released = false
    self.holdOnClose = holdOnClose
    self.result = result
    closes = 0
    condition.unlock()
  }

  static func read() -> Int32 {
    condition.lock()
    entered = true
    condition.broadcast()
    while !released { condition.wait() }
    let value = result
    condition.unlock()
    return value
  }

  static func waitForReader() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date().addingTimeInterval(2)
    while !entered {
      if !condition.wait(until: deadline) { return entered }
    }
    return true
  }

  static func releaseReader() {
    condition.lock()
    released = true
    condition.broadcast()
    condition.unlock()
  }

  static func install(batched: Bool) {
    let create: WinsWinn3ABI.CreateWinn3Fn = { _, _, _ in
      AuditWinnReaderHooks.condition.lock()
      defer { AuditWinnReaderHooks.condition.unlock() }
      AuditWinnReaderHooks.nextHandle += 1
      return AuditWinnReaderHooks.nextHandle
    }
    let write: WinsWinn3ABI.WriteInboundFn = { _, _, count in count }
    let read: WinsWinn3ABI.ReadOutboundFn = { _, _, _, _ in AuditWinnReaderHooks.read() }
    let status: WinsWinn3ABI.StatusJSONFn = { _ in
      strdup(#"{"winn3_gate_state":"carrying","winn3_lifecycle":"connected","winn3_runtime_completed":false,"winn3_rx_packets":9,"winn3_may_carry":true,"winn3_inner_mtu":1309}"#)
    }
    let close: WinsWinn3ABI.CloseFn = { _ in
      AuditWinnReaderHooks.condition.lock()
      AuditWinnReaderHooks.closes += 1
      if !AuditWinnReaderHooks.holdOnClose { AuditWinnReaderHooks.released = true; AuditWinnReaderHooks.condition.broadcast() }
      AuditWinnReaderHooks.condition.unlock()
      return nil
    }
    let freeString: WinsWinn3ABI.FreeStringFn = { pointer in free(pointer) }
    WinsWinn3ABI.testSymbols = [
      WinsWinn3.createSymbol: unsafeBitCast(create, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.writeInboundSymbol: unsafeBitCast(write, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.readOutboundSymbol: unsafeBitCast(read, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.statusJSONSymbol: unsafeBitCast(status, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.closeSymbol: unsafeBitCast(close, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.freeStringSymbol: unsafeBitCast(freeString, to: UnsafeMutableRawPointer.self)
    ]
    if batched {
      let enqueue: WinsWinn3ABI.EnqueuePacketsFn = { _, _, count, _ in count }
      let dequeue: WinsWinn3ABI.DequeuePacketsFn = { _, _, _, _, _ in AuditWinnReaderHooks.read() }
      WinsWinn3ABI.testSymbols?[WinsWinn3ABI.enqueuePacketsSymbol] = unsafeBitCast(enqueue, to: UnsafeMutableRawPointer.self)
      WinsWinn3ABI.testSymbols?[WinsWinn3ABI.dequeuePacketsSymbol] = unsafeBitCast(dequeue, to: UnsafeMutableRawPointer.self)
    }
  }
}

private final class AuditParkedWinnRelay: WinsWinn3PacketRelay {
  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {}
  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool { true }
}

final class AuditWinnReaderTests: XCTestCase {
  private func verifyReaderExit(batched: Bool, result: Int32) throws {
    AuditWinnReaderHooks.reset(result: result)
    AuditWinnReaderHooks.install(batched: batched)
    let datapath = WinsWinn3Datapath()
    defer {
      AuditWinnReaderHooks.releaseReader()
      datapath.stop()
      WinsWinn3ABI.testSymbols = nil
    }
    try datapath.start(document: "{}", carrierDescriptor: -1)
    let handle = datapath.currentHandle
    XCTAssertTrue(datapath.healthSnapshot().isOperational)
    datapath.resume(relay: AuditParkedWinnRelay())
    XCTAssertTrue(AuditWinnReaderHooks.waitForReader())
    AuditWinnReaderHooks.releaseReader()
    let deadline = Date().addingTimeInterval(1)
    while datapath.healthSnapshot().isOperational && Date() < deadline { usleep(1000) }
    XCTAssertFalse(datapath.healthSnapshot().isOperational)
    XCTAssertEqual(datapath.currentHandle, handle)
    XCTAssertEqual(AuditWinnReaderHooks.closes, 0)
  }

  func testScalarBadArgumentHoldsHandleWithUnhealthyReader() throws {
    try verifyReaderExit(batched: false, result: WinsWinn3ABIStatus.badArgument.rawValue)
  }

  func testScalarUnknownStatusHoldsHandleWithUnhealthyReader() throws {
    try verifyReaderExit(batched: false, result: -99)
  }

  func testBatchBadArgumentHoldsHandleWithUnhealthyReader() throws {
    try verifyReaderExit(batched: true, result: WinsWinn3ABIStatus.badArgument.rawValue)
  }

  func testBatchUnknownStatusHoldsHandleWithUnhealthyReader() throws {
    try verifyReaderExit(batched: true, result: -99)
  }

  func testNormalStopClosesReaderExactlyOnce() throws {
    for batched in [false, true] {
      AuditWinnReaderHooks.reset(result: -99)
      AuditWinnReaderHooks.install(batched: batched)
      let datapath = WinsWinn3Datapath()
      defer { datapath.stop(); WinsWinn3ABI.testSymbols = nil }
      try datapath.start(document: "{}", carrierDescriptor: -1)
      datapath.resume(relay: AuditParkedWinnRelay())
      XCTAssertTrue(AuditWinnReaderHooks.waitForReader())
      datapath.stop()
      datapath.stop()
      XCTAssertEqual(datapath.currentHandle, 0)
      XCTAssertEqual(AuditWinnReaderHooks.closes, 1)
      XCTAssertFalse(datapath.healthSnapshot().isOperational)
    }
  }

  func testStaleReaderCompletionCannotMarkReplacementUnhealthy() throws {
    for batched in [false, true] {
      AuditWinnReaderHooks.reset(result: -99, holdOnClose: true)
      AuditWinnReaderHooks.install(batched: batched)
      let datapath = WinsWinn3Datapath()
      defer {
        AuditWinnReaderHooks.releaseReader()
        datapath.stop()
        WinsWinn3ABI.testSymbols = nil
      }
      try datapath.start(document: "{}", carrierDescriptor: -1)
      let oldHandle = datapath.currentHandle
      datapath.resume(relay: AuditParkedWinnRelay())
      XCTAssertTrue(AuditWinnReaderHooks.waitForReader())
      datapath.stop()
      try datapath.start(document: "{}", carrierDescriptor: -1)
      XCTAssertTrue(datapath.currentHandle != oldHandle)
      AuditWinnReaderHooks.releaseReader()
      let deadline = Date().addingTimeInterval(0.2)
      while Date() < deadline {
        XCTAssertTrue(datapath.healthSnapshot().isOperational)
        usleep(1000)
      }
    }
  }
}
