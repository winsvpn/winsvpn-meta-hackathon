import Flutter
import Foundation
import NetworkExtension
import UIKit
import XCTest

@testable import Runner

/// Test-only storage for the fake winn/3 ABI. `@convention(c)` closures cannot
/// capture context, so the injected ABI functions record what they observed in
/// file-scope statics instead.
private enum Winn3ABITestHooks {
  /// A tiny conformance fixture: the create document the pump hands the engine.
  /// Kept deliberately small and self-contained; the test asserts the strings
  /// come through the `withCString` path byte-for-byte.
  static let conformanceCreateDocument =
    #"{"contract":"winn-datapath/1+winn3","gateway_id":"Z3ctbWFkaWQ=","admission_key":"c2VjcmV0","inner_v4":"10.13.0.2","inner_mtu":1139,"carrier":"winn3"}"#

  /// The handle the fake `WinnTunnelCreateWinn3` returns, so the test can prove
  /// the session the document created is the handle packet dispatch uses.
  static let fakeHandle: Int64 = 0x5EED

  static var receivedDocument = ""
  static var receivedCarrier: Int32 = -1
  static var dispatchedHandle: Int64 = 0
  static var dispatchedBytes = Data()

  static func reset() {
    receivedDocument = ""
    receivedCarrier = -1
    dispatchedHandle = 0
    dispatchedBytes = Data()
  }
}

/// Fake `NEPacketTunnelFlow` substitute. `readPackets` is one-shot exactly like
/// the real flow: it asynchronously delivers its packet a single time and then
/// never completes again, so the pump's re-arm parks instead of recursing.
/// `onDelivered` fires once the packet has been written to the engine, which is
/// how the test synchronises with the async delivery.
private final class TestWinn3Relay: WinsWinn3PacketRelay {
  private let packets: [Data]
  private let onDelivered: (() -> Void)?
  private var delivered = false
  private(set) var written: [Data] = []

  init(packets: [Data], onDelivered: (() -> Void)? = nil) {
    self.packets = packets
    self.onDelivered = onDelivered
  }

  func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
    guard !delivered else { return }
    delivered = true
    DispatchQueue.global().async {
      completionHandler(self.packets, [])
      self.onDelivered?()
    }
  }

  func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
    written.append(contentsOf: packets)
    return true
  }
}

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

  func testWinnMemoryWatchdogNeverCancelsAPromotedSession() {
    let ceiling = 15 * 1024 * 1024
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: ceiling + 1, ceilingBytes: ceiling, promoted: true), .recordOnly)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: ceiling + 1, ceilingBytes: ceiling, promoted: false), .cancelBeforePromotion)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: nil, ceilingBytes: ceiling, promoted: true), .ignore)
    XCTAssertEqual(WinsWinnMemoryWatchdogPolicy.decide(footprintBytes: ceiling - 1, ceilingBytes: ceiling, promoted: false), .ignore)
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
      WinsAppleTunnelActivitySnapshot.value(for: .connected),
      ["known": true, "active": true]
    )
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: .reasserting),
      ["known": true, "active": true]
    )
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: .disconnected),
      ["known": true, "active": false]
    )
    XCTAssertEqual(
      WinsAppleTunnelActivitySnapshot.value(for: nil, known: false),
      ["known": false, "active": false]
    )
  }

  func testCalculatorCamouflageUsesAlternateIconAndUnlockRestoresPrimaryIcon() {
    XCTAssertEqual(
      WinsAppleAlternateIconPolicy.iconName(camouflageEnabled: true),
      WinsAppleAlternateIconPolicy.calculatorIconName
    )
    XCTAssertNil(WinsAppleAlternateIconPolicy.iconName(camouflageEnabled: false))
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

  func testIOSPrivateConfigStoreCreatesAndReplacesProtectedOwnerOnlyFile() throws {
    let root = try makePrivateConfigTestRoot()
    let target = root.appendingPathComponent(WinsIOSPrivateConfigStore.fileName)
    let first = #"{"client_private_key":"secret-one"}"#
    let second = #"{"client_private_key":"secret-two"}"#

    try WinsIOSPrivateConfigStore.writeString(first, to: target)
    try WinsIOSPrivateConfigStore.writeString(second, to: target)

    XCTAssertEqual(
      try WinsIOSPrivateConfigStore.readString(from: target, maximumBytes: 4_096),
      second
    )
    let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    XCTAssertEqual(WinsIOSPrivateConfigStore.requiredProtection, .complete)
    #if targetEnvironment(simulator)
      XCTAssertFalse(WinsIOSPrivateConfigStore.requiresRuntimeDataProtectionValidation)
    #else
      XCTAssertTrue(WinsIOSPrivateConfigStore.requiresRuntimeDataProtectionValidation)
      XCTAssertEqual(attributes[.protectionKey] as? FileProtectionType, .complete)
    #endif
    XCTAssertEqual(
      try target.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup,
      true
    )
  }

  func testIOSPrivateConfigStoreRejectsSymlinkDestination() throws {
    let root = try makePrivateConfigTestRoot()
    try WinsIOSPrivateConfigStore.ensurePrivateDirectory(at: root)
    let outside = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-ios-private-outside-\(UUID().uuidString)")
    try Data("outside".utf8).write(to: outside)
    addTeardownBlock { try? FileManager.default.removeItem(at: outside) }
    let target = root.appendingPathComponent(WinsIOSPrivateConfigStore.fileName)
    try FileManager.default.createSymbolicLink(at: target, withDestinationURL: outside)

    XCTAssertThrowsError(
      try WinsIOSPrivateConfigStore.writeString(
        #"{"client_private_key":"must-not-write"}"#,
        to: target
      )
    ) { error in
      XCTAssertEqual((error as NSError).code, WinsIOSPrivateConfigStore.unsafePathCode)
    }
    XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "outside")
  }

  func testIOSPrivateConfigStoreRejectsSymlinkDirectory() throws {
    let parent = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-ios-private-parent-\(UUID().uuidString)", isDirectory: true)
    let outside = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-ios-private-dir-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
    addTeardownBlock {
      try? FileManager.default.removeItem(at: parent)
      try? FileManager.default.removeItem(at: outside)
    }
    let linkedDirectory = parent.appendingPathComponent("wins_vpn", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: linkedDirectory, withDestinationURL: outside)
    let target = linkedDirectory.appendingPathComponent(WinsIOSPrivateConfigStore.fileName)

    XCTAssertThrowsError(
      try WinsIOSPrivateConfigStore.writeString(
        #"{"client_private_key":"must-not-write"}"#,
        to: target
      )
    ) { error in
      XCTAssertEqual((error as NSError).code, WinsIOSPrivateConfigStore.unsafePathCode)
    }
    XCTAssertFalse(FileManager.default.fileExists(
      atPath: outside.appendingPathComponent(WinsIOSPrivateConfigStore.fileName).path
    ))
  }

  func testIOSPrivateConfigStoreHardensLegacyFileWithoutChangingBytes() throws {
    let root = try makePrivateConfigTestRoot()
    try WinsIOSPrivateConfigStore.ensurePrivateDirectory(at: root)
    let target = root.appendingPathComponent(WinsIOSPrivateConfigStore.fileName)
    let legacy = #"{"client_private_key":"legacy-secret"}"#
    try Data(legacy.utf8).write(to: target)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o644, .protectionKey: FileProtectionType.none],
      ofItemAtPath: target.path
    )

    try WinsIOSPrivateConfigStore.hardenExistingFile(at: target)

    XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), legacy)
    let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    XCTAssertEqual(WinsIOSPrivateConfigStore.requiredProtection, .complete)
    #if targetEnvironment(simulator)
      XCTAssertFalse(WinsIOSPrivateConfigStore.requiresRuntimeDataProtectionValidation)
    #else
      XCTAssertTrue(WinsIOSPrivateConfigStore.requiresRuntimeDataProtectionValidation)
      XCTAssertEqual(attributes[.protectionKey] as? FileProtectionType, .complete)
    #endif
    XCTAssertEqual(
      try target.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup,
      true
    )
  }

  func testIOSPrivateConfigStoreRejectsOversizedReadAndSafeDeleteRejectsSymlink() throws {
    let root = try makePrivateConfigTestRoot()
    let target = root.appendingPathComponent(WinsIOSPrivateConfigStore.fileName)
    try WinsIOSPrivateConfigStore.writeString(String(repeating: "x", count: 64), to: target)
    XCTAssertThrowsError(
      try WinsIOSPrivateConfigStore.readString(from: target, maximumBytes: 32)
    )

    try WinsIOSPrivateConfigStore.delete(at: target)
    XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))

    let outside = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-ios-delete-outside-\(UUID().uuidString)")
    try Data("outside".utf8).write(to: outside)
    addTeardownBlock { try? FileManager.default.removeItem(at: outside) }
    try FileManager.default.createSymbolicLink(at: target, withDestinationURL: outside)
    XCTAssertThrowsError(try WinsIOSPrivateConfigStore.delete(at: target)) { error in
      XCTAssertEqual((error as NSError).code, WinsIOSPrivateConfigStore.unsafePathCode)
    }
    XCTAssertEqual(try String(contentsOf: outside, encoding: .utf8), "outside")
  }

  private func makePrivateConfigTestRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-ios-private-config-\(UUID().uuidString)", isDirectory: true)
    addTeardownBlock { try? FileManager.default.removeItem(at: root) }
    return root
  }

  // MARK: - winn/3 datapath ABI

  func testWinn3DatapathStartExposesCreateSymbolAndRoundTripsDocumentToPacketDispatch() throws {
    // Negative control first: without the required create symbol in the image
    // the pump MUST refuse to start. This is what stops the test from being a
    // green that could not fail — start() genuinely depends on the symbol being
    // exposed.
    WinsWinn3ABI.testSymbols = nil
    XCTAssertFalse(WinsWinn3ABI.pumpSymbolsAvailable)
    let bareDatapath = WinsWinn3Datapath()
    XCTAssertThrowsError(try bareDatapath.start(
      document: Winn3ABITestHooks.conformanceCreateDocument,
      carrierDescriptor: -1
    )) { error in
      XCTAssertEqual(
        (error as? WinsWinn3Datapath.StartError)?.errorDescription,
        WinsWinn3Datapath.StartError.symbolsUnavailable.errorDescription
      )
    }

    Winn3ABITestHooks.reset()

    // The required symbol is the create entry point, spelled by name.
    XCTAssertEqual(WinsWinn3.createSymbol, "WinnTunnelCreateWinn3")

    let createFn: WinsWinn3ABI.CreateWinn3Fn = { document, carrier, _ in
      if let document {
        Winn3ABITestHooks.receivedDocument = String(cString: document)
      }
      Winn3ABITestHooks.receivedCarrier = carrier
      return Winn3ABITestHooks.fakeHandle
    }
    let writeFn: WinsWinn3ABI.WriteInboundFn = { handle, bytes, length in
      Winn3ABITestHooks.dispatchedHandle = handle
      if let bytes, length > 0 {
        Winn3ABITestHooks.dispatchedBytes = Data(bytes: bytes, count: Int(length))
      }
      return length
    }
    // Terminal immediately so the reader thread exits on its own and never spins.
    let readFn: WinsWinn3ABI.ReadOutboundFn = { _, _, _, _ in
      WinsWinn3ABIStatus.closed.rawValue
    }
    let statusFn: WinsWinn3ABI.StatusJSONFn = { _ in
      strdup(#"{"winn3_inner_mtu":1139}"#)
    }
    let closeFn: WinsWinn3ABI.CloseFn = { _ in nil }
    let freeFn: WinsWinn3ABI.FreeStringFn = { pointer in
      if let pointer { free(pointer) }
    }

    WinsWinn3ABI.testSymbols = [
      WinsWinn3.createSymbol: unsafeBitCast(createFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.writeInboundSymbol: unsafeBitCast(writeFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.readOutboundSymbol: unsafeBitCast(readFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.statusJSONSymbol: unsafeBitCast(statusFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.closeSymbol: unsafeBitCast(closeFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.freeStringSymbol: unsafeBitCast(freeFn, to: UnsafeMutableRawPointer.self)
    ]
    defer { WinsWinn3ABI.testSymbols = nil }

    // With the symbol exposed, start() must succeed — proving the method exposes
    // the required symbol rather than refusing.
    XCTAssertTrue(WinsWinn3ABI.pumpSymbolsAvailable)

    let datapath = WinsWinn3Datapath()
    XCTAssertNoThrow(try datapath.start(
      document: Winn3ABITestHooks.conformanceCreateDocument,
      carrierDescriptor: -1
    ))

    // The doc-withCString path round-trips: the exact bytes of the document the
    // caller supplied must be what the ABI create entry point receives.
    XCTAssertEqual(Winn3ABITestHooks.receivedDocument, Winn3ABITestHooks.conformanceCreateDocument)
    XCTAssertEqual(Winn3ABITestHooks.receivedCarrier, -1)
    XCTAssertEqual(datapath.currentHandle, Winn3ABITestHooks.fakeHandle)

    // Round-trips back into packet dispatch: the session created from that
    // document must be the handle that drives a packet into the engine's
    // WinnTunnelWriteInbound.
    let testPacket = Data([0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00])
    let delivered = expectation(description: "host->engine packet delivered")
    datapath.resume(relay: TestWinn3Relay(packets: [testPacket], onDelivered: {
      delivered.fulfill()
    }))
    wait(for: [delivered], timeout: 5)
    XCTAssertEqual(Winn3ABITestHooks.dispatchedHandle, Winn3ABITestHooks.fakeHandle)
    XCTAssertEqual(Winn3ABITestHooks.dispatchedBytes, testPacket)

    datapath.stop()
  }

  // MARK: - enforceRoutes route-set regression (pre-proof)

  // Regression guard for the routing posture that `tunnelProtocol.enforceRoutes
  // = true` (set at AppDelegate.swift:1084 and :1837) protects. That property
  // itself lives on `NETunnelProviderProtocol` and can only be exercised by a
  // live tunnel, which this lane is forbidden to bring up on-device. What CAN be
  // proven statically is the route set that enforcing routes is what makes win:
  // the promoted full-tunnel posture must carry the IPv4 default (/0) so that
  // "routes win regardless of specificity" has a route to win with, it must draw
  // IPv6 into the tunnel via the sink rather than leak it on the physical
  // interface, and the carrier /32 exclusion must SURVIVE promotion — the
  // AppDelegate comment at :1809-:1812 and :1814-:1821 is explicit that
  // `excludedRoutes` still apply under `enforceRoutes`, which is the only thing
  // keeping the engine's own outer socket off a /0 that enforceRoutes makes the
  // tunnel's. These assertions read the settings OBJECTS the builder produced
  // and the postures' own guards (the same guards `startWinn3StandaloneSession`
  // runs), never the builder being trusted.
  //
  // Test-name honesty: these confirm the route set HOLDS (a default-route leak
  // is absent from the built object), which is a pre-proof — they do not assert
  // the promise was induced into the kernel, which cannot be measured without a
  // device.

  private var enforceRoutesWinn3FixturePrivateKey: String {
    Data(repeating: 0x11, count: 32).base64EncodedString()
  }

  private func makeEnforceRoutesWinn3Config() -> WinsTunnelConfig {
    let localStatic = Data(repeating: 0x11, count: 32).base64EncodedString()
    let gatewayStatic = Data(repeating: 0x22, count: 32).base64EncodedString()
    let gatewayID = Data("wins-lab-gateway".utf8).base64EncodedString()
    let admissionKey = Data(repeating: 0x33, count: 32).base64EncodedString()
    let wgKey = "<REDACTED_WG_KEY>"
    return WinsTunnelConfig.parse("""
      [Interface]
      PrivateKey = \(wgKey)
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
      PublicKey = \(wgKey)
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
      Static_Private = \(localStatic)
      Gateway_Static = \(gatewayStatic)
      Gateway_Id = \(gatewayID)
      Admission_Key = \(admissionKey)
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
      """)
  }

  func testEnforceRoutesFullTunnelCarriesDefaultIPv4WithoutCleartextLeak() throws {
    let config = makeEnforceRoutesWinn3Config()
    let innerMTU = 1312

    XCTAssertTrue(config.defaultIPv4RouteEnabled, "fixture must request the /0 default so enforceRoutes has a route to win with")
    XCTAssertTrue(config.ipv6LeakProtectionEnabled, "fixture must request ::/0 so the IPv6 sink is required")

    guard let full = WinsWinn3Settings.fullTunnel(config: config, innerMTU: innerMTU) else {
      return XCTFail("a standalone fixture carrying a derivable inner resolver must build a promoted posture")
    }

    // The /0 must actually be in the included set of the object that would be
    // installed. A promoted posture whose routes are all host /32s has widened
    // nothing: it would report carrying while every packet still left by the
    // physical interface in the clear.
    let included: [NEIPv4Route] = full.ipv4Settings?.includedRoutes ?? []
    XCTAssertTrue(
      included.contains { $0.destinationAddress == "0.0.0.0" },
      "the promoted posture must carry the default IPv4 route; without it enforceRoutes wins nothing and the tunnel captures no traffic"
    )

    // The flip side of enforceRoutes: the engine's outer socket is a MORE
    // SPECIFIC route on the physical interface than the tunnel's /0. Under
    // enforceRoutes the /0 would win and capture the socket unless the /32 is
    // placed in excludedRoutes (which the AppDelegate comment at :1814-:1821
    // says still apply). Assert the object ACTUALLY carries the exclusion.
    XCTAssertTrue(
      WinsWinn3Settings.carrierExclusionPresent(in: full, config: config),
      "the carrier /32 exclusion must survive promotion into excludedRoutes, or enforceRoutes lets the /0 capture the engine's own socket"
    )

    // The object the guard this lane's provider runs next (in
    // `startWinn3StandaloneSession`) must accept the POSTURE that goes with
    // enforceRoutes: defaults taken, resolvers moved in. If this flips, the
    // provider would refuse to promote the very posture enforceRoutes is set to
    // protect.
    let verdict = WinsWinn3PromotedPosture.evaluate(full, config: config)
    XCTAssertTrue(
      verdict.usable,
      "the promoted built object must pass its own promotion check; reasons: \(verdict.reasons.joined(separator: "; "))"
    )
  }

  func testEnforceRoutesFullTunnelDrawsIPv6IntoSinkNotLeakingIt() throws {
    let config = makeEnforceRoutesWinn3Config()
    let innerMTU = 1312

    guard let full = WinsWinn3Settings.fullTunnel(config: config, innerMTU: innerMTU) else {
      return XCTFail("fixture must build a promoted posture")
    }

    XCTAssertNotNil(full.ipv6Settings, "with ::/0 requested and enforceRoutes taking the default, IPv6 must be drawn into the tunnel via the sink; leaving host IPv6 in place routes every v6-capable app around the tunnel")
    let v6Included: [NEIPv6Route] = full.ipv6Settings?.includedRoutes ?? []
    XCTAssertEqual(v6Included.count, 1, "the v6 sink takes exactly the default v6 route")
    XCTAssertEqual(
      v6Included.first?.destinationAddress,
      NEIPv6Route.default().destinationAddress,
      "the v6 sink must be the ::/0 default route"
    )
  }

  func testEnforceRoutesLeakPosturesFailClosed() throws {
    // The recurring survivor from the false-green catalogue is a POSITIVE fact
    // with nothing asserting the negative. These are the negatives: the same
    // guard that passes the built posture above must REJECT the two most
    // dangerous leak shapes, or "usable" is a rubber stamp.
    let config = makeEnforceRoutesWinn3Config()
    let innerResolvers = WinsWinn3Resolvers.inner(config)

    // Leak shape 1: a posture that captures nothing — all host /32 routes, no
    // default. This is a session that reports carrying while every packet still
    // leaves on the physical interface in the clear.
    let capturesNothing = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.13.0.1")
    let ipv4Hosts = NEIPv4Settings(addresses: ["10.13.0.2"], subnetMasks: ["255.255.255.255"])
    ipv4Hosts.includedRoutes = [
      NEIPv4Route(destinationAddress: "10.13.0.1", subnetMask: "255.255.255.255")
    ]
    capturesNothing.ipv4Settings = ipv4Hosts
    capturesNothing.ipv6Settings = nil
    capturesNothing.dnsSettings = NEDNSSettings(servers: innerResolvers)
    capturesNothing.mtu = NSNumber(value: 1312)
    let noCapture = WinsWinn3PromotedPosture.evaluate(capturesNothing, config: config)
    XCTAssertFalse(
      noCapture.usable,
      "a posture with no /0 capture must be refused, or enforceRoutes would let a capture-nothing session report protected: \(noCapture.reasons.joined(separator: "; "))"
    )
    XCTAssertTrue(
      noCapture.reasons.joined(separator: "; ").contains("captures nothing"),
      "the refusal must NAME the capture leak"
    )

    // Leak shape 2: default IPv4 captured but no IPv6 sink while the document
    // requests ::/0 — the old iOS-leak shape where host v6 egresses in the clear
    // beside a promoted IPv4 tunnel.
    let noV6Sink = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.13.0.1")
    let ipv4Default = NEIPv4Settings(addresses: ["10.13.0.2"], subnetMasks: ["255.255.255.255"])
    ipv4Default.includedRoutes = [NEIPv4Route.default()]
    noV6Sink.ipv4Settings = ipv4Default
    noV6Sink.ipv6Settings = nil
    noV6Sink.dnsSettings = NEDNSSettings(servers: innerResolvers)
    noV6Sink.mtu = NSNumber(value: 1312)
    let v6Leak = WinsWinn3PromotedPosture.evaluate(noV6Sink, config: config)
    XCTAssertFalse(
      v6Leak.usable,
      "with ::/0 requested, a default-IPv4 posture missing the IPv6 sink must be refused: \(v6Leak.reasons.joined(separator: "; "))"
    )
    XCTAssertTrue(
      v6Leak.reasons.joined(separator: "; ").contains("no IPv6 settings"),
      "the refusal must NAME the IPv6 sink gap"
    )
  }

  /// The PRE-PROOF phase of `startWinn3StandaloneSession` installs the narrow
  /// bootstrap posture FIRST — before the datapath is proven — and only then,
  /// after `WinsWinn3PromotionGate` observes the gate carrying, promotes onto
  /// the full-tunnel posture that `enforceRoutes = true` (AppDelegate) makes
  /// win. The whole point of that ordering is that an UNPROVEN datapath must
  /// never capture the phone's default route: a session that installs a /0
  /// before it can carry bytes would black-hole or leak every unhooked packet
  /// on the device. This is the specific "no default-route leak pre-proof" the
  /// route set is designed to give: the bootstrap object carrying the SAME
  /// `enforceRoutes`-protected route set must be observably narrow — exactly
  /// one /32 included route, no default route, no IPv6, no DNS, the carrier
  /// /32 exclusion present — and `WinsWinn3BootstrapPosture` (the guard
  /// `startWinn3StandaloneSession` runs before committing it) must say so.
  func testEnforceRoutesBootstrapHoldsNarrowWithoutDefaultRoutePreProof() throws {
    let config = makeEnforceRoutesWinn3Config()
    let innerMTU = 1312

    let bootstrap = WinsWinn3Settings.bootstrap(config: config, innerMTU: innerMTU)

    // The pre-proof posture must NOT carry the default route: enforcing routes
    // only matters once there is a promoted /0 to enforce, and the bootstrap
    // deliberately precedes that. Assert on the object, not the builder.
    let included: [NEIPv4Route] = bootstrap.ipv4Settings?.includedRoutes ?? []
    XCTAssertEqual(included.count, 1,
                   "the pre-proof bootstrap must install exactly one included route, not the default")
    XCTAssertFalse(
      included.contains { $0.destinationAddress == "0.0.0.0" },
      "the pre-proof bootstrap must not carry the IPv4 default route; an unproven datapath must never capture the phone's traffic"
    )
    XCTAssertEqual(
      included.first?.destinationAddress, "10.13.0.1",
      "the single pre-proof included route must be the inner /32 next hop, not a default"
    )
    XCTAssertEqual(
      included.first?.destinationSubnetMask, "255.255.255.255",
      "the pre-proof included route must be a /32"
    )

    // IPv4/IPv6 excluded/included set must hold: the carrier /32 exclusion the
    // enforceRoutes /0 would otherwise capture must already be present in the
    // untested bootstrap, and the host keeps its own IPv6 and resolvers.
    XCTAssertTrue(
      WinsWinn3Settings.carrierExclusionPresent(in: bootstrap, config: config),
      "the carrier /32 exclusion must survive into the pre-proof bootstrap's excludedRoutes, or enforceRoutes would capture the engine's own socket once the /0 is promoted"
    )
    XCTAssertNil(bootstrap.ipv6Settings,
                 "the pre-proof bootstrap must leave the host's own IPv6 in place; an unproven tunnel must not draw v6 into a sink that cannot carry it yet")
    XCTAssertNil(bootstrap.dnsSettings,
                 "the pre-proof bootstrap must leave the host's own resolvers in place; a probe into an unproven tunnel must not point every lookup at it")

    // The GUARD `startWinn3StandaloneSession` runs before committing this object
    // must accept it — and, in the negative control, must refuse the same object
    // carrying a default route, proving the pre-proof no-leak property is
    // actually enforced rather than assumed.
    let verdict = WinsWinn3BootstrapPosture.evaluate(
      bootstrap,
      requiredInnerMTU: innerMTU,
      carrierExclusionPresent: WinsWinn3Settings.carrierExclusionPresent(in: bootstrap, config: config)
    )
    XCTAssertTrue(verdict.narrow,
                  "the pre-proof bootstrap must be observably narrow; reasons: \(verdict.reasons.joined(separator: "; "))")

    // Negative control: the identical posture with a default route added must
    // be REFUSED. Without this the "no default-route leak pre-proof" above is a
    // positive fact with nothing asserting the negative.
    let leaking = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.13.0.1")
    let ipv4Leak = NEIPv4Settings(addresses: ["10.13.0.2"], subnetMasks: ["255.255.255.255"])
    ipv4Leak.includedRoutes = [
      NEIPv4Route.default(),
      NEIPv4Route(destinationAddress: "10.13.0.1", subnetMask: "255.255.255.255")
    ]
    ipv4Leak.excludedRoutes = bootstrap.ipv4Settings?.excludedRoutes
    leaking.ipv4Settings = ipv4Leak
    leaking.mtu = NSNumber(value: innerMTU)
    let leakVerdict = WinsWinn3BootstrapPosture.evaluate(
      leaking,
      requiredInnerMTU: innerMTU,
      carrierExclusionPresent: WinsWinn3Settings.carrierExclusionPresent(in: leaking, config: config)
    )
    XCTAssertFalse(leakVerdict.narrow,
                   "a pre-proof posture carrying a default route must be refused, or the unproven tunnel would capture the phone's traffic")
    XCTAssertTrue(
      leakVerdict.reasons.joined(separator: "; ").contains("default route"),
      "the refusal must NAME the pre-proof default-route leak"
    )
  }

  // MARK: - Kill-switch egress, winn/3 standalone (post-proof point ~2016)

  // A complete winn/3 standalone descriptor, mirroring
  // tools/verify_apple_winn3_host_contract_harness.swift: a full-tunnel route
  // set (0.0.0.0/0, ::/0), a DNS resolver this host can derive to be inner
  // (10.13.0.9, inside the /24 around inner_v4), and an IPv4 [winn] endpoint
  // (198.51.100.7) so the carrier-exclusion /32 exists. Every one of
  // `WinsKillSwitch.egressBlocked`'s four capture clauses is therefore live.
  private var winn3InterfaceKey: String {
    Data(repeating: 0x11, count: 32).base64EncodedString()
  }

  private var winn3GatewayKey: String {
    Data(repeating: 0x22, count: 32).base64EncodedString()
  }

  private var winn3GatewayID: String {
    Data("wins-lab-gateway".utf8).base64EncodedString()
  }

  private var winn3AdmissionKey: String {
    Data(repeating: 0x33, count: 32).base64EncodedString()
  }

  private var winn3WGKey: String {
    Data(repeating: 0x44, count: 32).base64EncodedString()
  }

  private func winn3StandaloneConfig(
    interfaceDNS: String = "10.13.0.9",
    allowedIPs: String = "0.0.0.0/0, ::/0"
  ) -> WinsTunnelConfig {
    WinsTunnelConfig.parse(
      """
      [Interface]
      PrivateKey = \(winn3WGKey)
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
      PublicKey = \(winn3WGKey)
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
      Static_Private = \(winn3InterfaceKey)
      Gateway_Static = \(winn3GatewayKey)
      Gateway_Id = \(winn3GatewayID)
      Admission_Key = \(winn3AdmissionKey)
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

  /// A `[winn] carrier = direct-awg` (RELAY) config — the same `winnEnabled`
  /// document shape but a non-standalone carrier, so the winn/3 gate is
  /// consulted and must report `winn3Enabled == false`.
  private func nonWinn3CarrierConfig() -> WinsTunnelConfig {
    WinsTunnelConfig.parse(
      """
      [Winn]
      Enabled = true
      Carrier = direct-awg
      Session_Id = winn2-session
      Endpoint = 198.51.100.7:51820
      Inner_V4 = 10.13.0.2
      Inner_Router_V4 = 10.13.0.1
      Static_Private = \(winn3InterfaceKey)
      Gateway_Static = \(winn3GatewayKey)
      Gateway_Id = \(winn3GatewayID)
      Admission_Key = \(winn3AdmissionKey)
      Path_Mtu = 1400
      Carrier_Classes = udp, tls
      """
    )
  }

  /// The RAWTEXT of the winn/3 standalone fixture (`winn3StandaloneConfig()`
  /// parses exactly this document) so a test can hand it to
  /// `WinsTunnelConfig.parseAndValidate` and to the control-plane admission
  /// gate -- the round-trip the delivery path performs before redacted storage.
  private var standaloneWinn3INI: String {
    """
    [Interface]
    PrivateKey = \(winn3WGKey)
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
    PublicKey = \(winn3WGKey)
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
    Static_Private = \(winn3InterfaceKey)
    Gateway_Static = \(winn3GatewayKey)
    Gateway_Id = \(winn3GatewayID)
    Admission_Key = \(winn3AdmissionKey)
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
  }

  /// `standaloneWinn3INI` with the standalone carrier replaced by `direct-awg`
  /// (a RELAY). Same document shape, same validation, but `winn3Enabled` must
  /// read false and the control-plane gate must refuse it: the delivery path
  /// must never install a relay profile.
  private var relayWinn3INI: String {
    standaloneWinn3INI
      .replacingOccurrences(of: "Carrier = winn3", with: "Carrier = direct-awg")
      .replacingOccurrences(of: "Session_Id = winn3-standalone", with: "Session_Id = winn2-session")
  }

  /// Builds the blocking full-tunnel posture a production winn/3 standalone
  /// session commits as its FIRST posture, or fails the test (an unusable
  /// posture would never be installed).
  private func blockingFullTunnel(
    _ config: WinsTunnelConfig
  ) throws -> NEPacketTunnelNetworkSettings {
    let innerMTU = 1309  // the fleet default for path 1450; >= the IPv6 sink floor
    return try XCTUnwrap(
      WinsWinn3Settings.fullTunnel(config: config, innerMTU: innerMTU),
      "a complete full-tunnel standalone config must build a usable full-tunnel posture"
    )
  }

  /// The FIRST posture a production full-tunnel standalone session installs is
  /// the blocking full-tunnel posture, BEFORE the datapath is proven or the
  /// pump moves a single packet. `startWinn3StandaloneSession` (line 1904)
  /// installs it as `firstPosture` only after `WinsKillSwitch.egressBlocked`
  /// returns true (line 2012, the post-proof guard ~2016), and the pump starts
  /// only after that posture is committed (line 2107). So this predicate holding
  /// is exactly the logic that guarantees "no egress before datapath proof".
  func testWinn3StandaloneKillSwitchFirstPostureBlocksEgressBeforeDatapathProof() throws {
    let config = winn3StandaloneConfig()
    XCTAssertTrue(config.winn3Enabled)
    XCTAssertTrue(config.defaultIPv4RouteEnabled,
                  "the fixture must be a full-tunnel document")
    XCTAssertTrue(config.ipv6LeakProtectionEnabled,
                  "the fixture must request ::/0 so the IPv6 capture clause is live")

    // A standard production full-tunnel standalone run is NOT a dev run, so the
    // kill switch must be active from the first installed posture.
    XCTAssertTrue(WinsKillSwitch.activeFor(config: config, devRunActive: false))

    let full = try blockingFullTunnel(config)
    XCTAssertTrue(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "the first posture a winn/3 standalone session commits must observably block egress before any datapath proof"
    )
  }

  /// Each capture clause in the kill-switch read-back must be independently
  /// breakable: a builder that silently narrows ANY one of the four families
  /// must turn `egressBlocked` false, failing CLOSED so the provider refuses the
  /// session (code 1039) rather than installing a posture that leaks. These are
  /// the "none after kill-switch" mutations, applied to the very settings object
  /// the provider would install at the post-proof point ~2016.
  func testWinn3StandaloneKillSwitchEveryCaptureClauseFailsClosed() throws {
    let config = winn3StandaloneConfig()

    // Baseline: all four clauses hold.
    XCTAssertTrue(WinsKillSwitch.egressBlocked(by: try blockingFullTunnel(config), config: config))

    var full = try blockingFullTunnel(config)
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
    full = try blockingFullTunnel(config)
    full.ipv6Settings = nil
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture that leaves the host's ::/0 outside the tunnel must NOT claim capture"
    )

    // 3. DNS resolver removed -> every query resolves to the ISP's resolver in
    //    the clear.
    full = try blockingFullTunnel(config)
    full.dnsSettings = nil
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture whose name resolution is not tunnelled must NOT claim a blocked egress"
    )
    full = try blockingFullTunnel(config)
    full.dnsSettings?.matchDomains = ["example.com"]
    XCTAssertFalse(
      WinsKillSwitch.egressBlocked(by: full, config: config),
      "a posture that only tunnels one domain must NOT claim it captures all DNS"
    )

    // 4. Carrier exclusion removed -> the tunnel's own outer socket is captured
    //    by its own default route (dead loop). Only live when the config has a
    //    real IPv4 transport endpoint to exclude.
    let transport = try XCTUnwrap(config.transportIPv4ExclusionRoute,
                                  "the fixture's [winn] endpoint must produce a carrier exclusion /32")
    full = try blockingFullTunnel(config)
    full.ipv4Settings?.excludedRoutes = []
    XCTAssertTrue(
      WinsKillSwitch.egressBlocked(by: full, config: config) == false,
      "a posture that does not exclude its own carrier edge (\(transport.destinationAddress)) must NOT claim a blocked egress"
    )
  }

  /// The kill switch is deliberately OFF for the two non-production shapes (dev
  /// containment / held-proof runs keep the narrow "host untouched" bootstrap;
  /// split-tunnel offers the user a requested external destination set), and it
  /// reports teardown honesty: egress is blocked through teardown only when the
  /// datapath stops before the posture is released — the "none after
  /// kill-switch" rule that a teardown can never race its stop into cleartext.
  func testWinn3StandaloneKillSwitchActiveAndTeardownSemantics() {
    let config = winn3StandaloneConfig()
    XCTAssertTrue(WinsKillSwitch.activeFor(config: config, devRunActive: false))
    XCTAssertFalse(WinsKillSwitch.activeFor(config: config, devRunActive: true),
                   "a dev/held run is allowed to keep the narrow bootstrap")

    let split = winn3StandaloneConfig(allowedIPs: "10.13.0.0/24, ::/0")
    XCTAssertFalse(split.defaultIPv4RouteEnabled,
                   "the split-tunnel fixture must not carry the IPv4 default route")
    XCTAssertFalse(WinsKillSwitch.activeFor(config: split, devRunActive: false),
                   "a split tunnel is not a kill switch; the destination set is external by design")

    let held = WinsKillSwitch.teardownStatusFields(
      heldBlockingPosture: true,
      datapathStoppedBeforeRelease: true
    )
    XCTAssertEqual(held["kill_switch_egress_blocked_through_teardown"] as? Bool, true)
    XCTAssertEqual(held["kill_switch_teardown_release_after_datapath_stop"] as? Bool, true)

    let releasedEarly = WinsKillSwitch.teardownStatusFields(
      heldBlockingPosture: true,
      datapathStoppedBeforeRelease: false
    )
    XCTAssertEqual(releasedEarly["kill_switch_egress_blocked_through_teardown"] as? Bool, false,
                   "egress is 'blocked through teardown' only when the datapath stops before the posture is released")
    XCTAssertEqual(releasedEarly["kill_switch_teardown_release_after_datapath_stop"] as? Bool, false)
  }

  // MARK: - winn/3 config emission: golden wire pin + round-trip into the datapath

  /// The exact on-the-wire JSON that `WinsWinn3CreateDocument.json()` emits for
  /// the `winn3StandaloneConfig()` fixture, pinned here and mirrored byte-for-byte
  /// in `apple/WinsTunnelCore/Tests/Fixtures/WinsWinn3CreateDocument.golden.json`.
  ///
  /// JSONSerialization renders the `/` in `winn-datapath/1+winn3` as the slash
  /// escape `\/`, so the golden carries that escape; any change to how the
  /// document is rendered must redefine this string, the fixture, and nothing
  /// else. A test name is a claim — this value is the whole bound.
  private var winn3GoldenDocument: String {
    "{\"admission_key\":\"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\",\"allow_own_socket\":true,\"carrier\":\"winn3\",\"carrier_classes\":[\"udp\",\"tls\"],\"contract\":\"winn-datapath\\/1+winn3\",\"gateway_endpoint\":\"198.51.100.7:51820\",\"gateway_id\":\"wins-lab-gateway\",\"gateway_static\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=\",\"inner_router_v4\":\"10.13.0.1\",\"inner_v4\":\"10.13.0.2\",\"path_mtu\":1400,\"payload\":\"ip-packet\",\"session_id\":\"winn3-standalone\",\"static_private\":\"ERERERERERERERERERERERERERERERERERERERERERE=\"}"
  }

  /// A standalone `[winn]` configuration with one case-normalised field removed,
  /// so a negative test can observe the create boundary refusing rather than
  /// emitting a document with a hole.
  private func winn3MutilatedConfig(removingField field: String) -> WinsTunnelConfig {
    var winn = [
      "Enabled = true",
      "Endpoint = 198.51.100.7:51820",
      "Carrier = winn3",
      "Session_Id = winn3-standalone",
      "Inner_V4 = 10.13.0.2",
      "Inner_Router_V4 = 10.13.0.1",
      "Static_Private = \(winn3InterfaceKey)",
      "Gateway_Static = \(winn3GatewayKey)",
      "Gateway_Id = \(winn3GatewayID)",
      "Admission_Key = \(winn3AdmissionKey)",
      "Path_Mtu = 1400",
      "Carrier_Classes = udp, tls",
      "H1 = 11", "H2 = 22", "H3 = 33", "H4 = 44",
      "S1 = 16", "S2 = 80", "S3 = 16", "S4 = 0"
    ]
    winn.removeAll { $0.hasPrefix(field + " =") }
    let winnSection = winn.joined(separator: "\n")
    return WinsTunnelConfig.parse(
      """
      [Interface]
      PrivateKey = \(winn3WGKey)
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
      PublicKey = \(winn3WGKey)
      Endpoint = 203.0.113.10:9110
      AllowedIPs = 0.0.0.0/0, ::/0
      PersistentKeepalive = 25

      [Winn]
      \(winnSection)
      """
    )
  }

  /// Pins the EXACT `WinsWinn3CreateDocument` wire output — the whole document,
  /// not a field-by-field read — so a regression that drops, renames or
  /// re-orders any emitted field turns this test red, and the checked-in golden
  /// fixture under `apple/` cannot drift from the code that emits it.
  func testWinn3CreateDocumentWireOutputIsPinnedToGoldenFixture() throws {
    let document = try XCTUnwrap(WinsWinn3CreateDocument.make(config: winn3StandaloneConfig()))
    let emitted = try document.json()

    XCTAssertEqual(
      emitted, winn3GoldenDocument,
      "the emitted create document must be byte-for-byte the pinned wire output"
    )
    XCTAssertTrue(
      emitted.contains("winn-datapath\\/1+winn3"),
      "the on-wire contract string is slash-escaped; a rendering change must be re-pinned, not silently escaped"
    )

    // Spot the sentinel fields against the pinned whole, so an over-broad edit
    // to both the code and the golden together still has a second reader.
    let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(emitted.utf8)) as? [String: Any])
    XCTAssertEqual(parsed["gateway_id"] as? String, "wins-lab-gateway")
    XCTAssertEqual(parsed["session_id"] as? String, "winn3-standalone")
    XCTAssertEqual(parsed["path_mtu"] as? Int, 1400)
    XCTAssertEqual(parsed["carrier_classes"] as? [String], ["udp", "tls"])
    XCTAssertEqual(parsed["allow_own_socket"] as? Bool, true)
    XCTAssertNil(parsed["psk"], "an absent psk is omitted, never sent empty")

    let fixtureURL = try XCTUnwrap(
      Bundle(for: type(of: self)).url(
        forResource: "WinsWinn3CreateDocument.golden",
        withExtension: "json"
      )
    )
    let fixture = try String(contentsOf: fixtureURL, encoding: .utf8)
      .trimmingCharacters(in: .newlines)
    XCTAssertEqual(
      fixture, winn3GoldenDocument,
      "the checked-in golden fixture must equal the pinned wire output, or the two have silently drifted"
    )
  }

  /// Negative control for the create boundary: `WinsWinn3CreateDocument.make`
  /// returns nil — never a document — when a required descriptor field is
  /// absent, so a half-provisioned configuration cannot emit a wire document
  /// that the datapath would start against.
  func testWinn3CreateDocumentIsNotBuiltFromIncompleteConfig() {
    XCTAssertNotNil(WinsWinn3CreateDocument.make(config: winn3StandaloneConfig()))
    let mutilated = winn3MutilatedConfig(removingField: "Admission_Key")
    XCTAssertTrue(
      WinsWinn3StartRequirements.unmetReasons(mutilated)
        .contains { $0.contains("admission_key") },
      "removing the admission key must produce a refusal that names the field"
    )
    XCTAssertNil(WinsWinn3CreateDocument.make(config: mutilated))
  }

  /// THE round-trip the task names: the document emitted by
  /// `WinsWinn3CreateDocument.make(config:)` is handed to
  /// `WinsWinn3Datapath.start(document:carrierDescriptor:)`, and the ABI create
  /// entry point must receive exactly those bytes. Uses the fake ABI injected via
  /// `WinsWinn3ABI.testSymbols`, so start() reaches its `withCString` boundary
  /// and hands the engine the document WITHOUT bringing up any tunnel.
  func testEmittedWinn3CreateDocumentRoundTripsIntoDatapathStart() throws {
    let document = try XCTUnwrap(WinsWinn3CreateDocument.make(config: winn3StandaloneConfig()))
    let emitted = try document.json()
    Winn3ABITestHooks.reset()

    let createFn: WinsWinn3ABI.CreateWinn3Fn = { document, carrier, _ in
      if let document { Winn3ABITestHooks.receivedDocument = String(cString: document) }
      Winn3ABITestHooks.receivedCarrier = carrier
      return Winn3ABITestHooks.fakeHandle
    }
    let writeFn: WinsWinn3ABI.WriteInboundFn = { handle, _, _ in handle > 0 ? 1 : 0 }
    let readFn: WinsWinn3ABI.ReadOutboundFn = { _, _, _, _ in WinsWinn3ABIStatus.timedOut.rawValue }
    let statusFn: WinsWinn3ABI.StatusJSONFn = { _ in
      strdup(#"{"winn3_inner_mtu":1139}"#)
    }
    let closeFn: WinsWinn3ABI.CloseFn = { _ in nil }
    let freeFn: WinsWinn3ABI.FreeStringFn = { pointer in if let pointer { free(pointer) } }

    WinsWinn3ABI.testSymbols = [
      WinsWinn3.createSymbol: unsafeBitCast(createFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.writeInboundSymbol: unsafeBitCast(writeFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.readOutboundSymbol: unsafeBitCast(readFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.statusJSONSymbol: unsafeBitCast(statusFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.closeSymbol: unsafeBitCast(closeFn, to: UnsafeMutableRawPointer.self),
      WinsWinn3ABI.freeStringSymbol: unsafeBitCast(freeFn, to: UnsafeMutableRawPointer.self)
    ]
    defer {
      WinsWinn3ABI.testSymbols = nil
      Winn3ABITestHooks.reset()
    }

    let datapath = WinsWinn3Datapath()
    XCTAssertNoThrow(try datapath.start(document: emitted, carrierDescriptor: -1))
    defer { datapath.stop() }

    XCTAssertTrue(datapath.isRunning)
    XCTAssertEqual(datapath.currentHandle, Winn3ABITestHooks.fakeHandle)
    XCTAssertEqual(
      Winn3ABITestHooks.receivedDocument, emitted,
      "the document emitted by make(config:) must be exactly what WinsWinn3Datapath.start hands to the engine, byte for byte"
    )
    XCTAssertEqual(Winn3ABITestHooks.receivedCarrier, -1)
  }

  // MARK: - winn/3 carrier gate (WinsTunnelConfig)

  /// The standalone carrier is a named constant, not a bare inline string, so a
  /// carrier select that stops matching the engine's `winn3Carrier` (or a config
  /// parser that starts naming it differently) has one authoritative spelling.
  func testSupportedWinnCarrierWinn3IsExactlyWinn3() {
    XCTAssertEqual(
      WinsTunnelConfig.supportedWinnCarrierWinn3, "winn3",
      "the standalone carrier name must equal the Go archive's winn3Carrier"
    )
    XCTAssertTrue(
      WinsTunnelConfig.supportedWinnCarriers
        .contains(WinsTunnelConfig.supportedWinnCarrierWinn3),
      "winn3 must be a member of the supported carrier set or the gate can never admit it"
    )
  }

  /// A `[winn] carrier = winn3` document resolves to the standalone carrier and
  /// therefore sets `winn3Enabled` true. This is the admission side of the gate:
  /// the seam component must be selected for exactly these configs and a
  /// standalone session must be refused for any other carrier.
  func testWinn3CarrierConfigSetsWinn3Enabled() throws {
    let config = winn3StandaloneConfig()
    XCTAssertEqual(config.winnCarrier, "winn3")
    XCTAssertTrue(config.winn3Enabled)
  }

  /// The refusal side of the gate: `winn3StartRefusalReason` is nil for a
  /// non-winn3 config (the standalone gate is not even consulted), a real reason
  /// naming the field for a winn3 config missing a start requirement, and nil
  /// again for a complete standalone config that may be ATTEMPTED.
  func testWinn3StartRefusalReasonGate() throws {
    let nonWinn3 = nonWinn3CarrierConfig()
    XCTAssertFalse(nonWinn3.winn3Enabled)
    XCTAssertNil(nonWinn3.winn3StartRefusalReason,
                 "a non-winn3 config must not consult the winn/3 gate")

    let mutilated = winn3MutilatedConfig(removingField: "Admission_Key")
    XCTAssertTrue(mutilated.winn3Enabled)
    XCTAssertEqual(
      mutilated.winn3StartRefusalReason, WinsWinn3StartRequirements.refusalReason(mutilated),
      "the winn3StartRefusalReason path must delegate to WinsWinn3StartRequirements"
    )
    let reason = try XCTUnwrap(
      mutilated.winn3StartRefusalReason,
      "a standalone config missing the admission key must carry a refusal"
    )
    XCTAssertTrue(
      reason.contains("admission_key"),
      "the refusal must name the missing field, not refuse the whole platform"
    )

    XCTAssertNil(winn3StandaloneConfig().winn3StartRefusalReason,
                 "a complete standalone config is permitted to be attempted, so the gate opens")
  }

  // MARK: - winn/3 control-plane delivery: emitted INI round-trip + refusal

  /// The emit half of the delivery vocabulary: a transient winn/3 STANDALONE
  /// INI accepted by the delivery path must survive
  /// `WinsTunnelConfig.parseAndValidate` as a standalone winn3 carrier, so only
  /// a resolved winn/3 document can ever be admitted to delivery.
  ///
  /// Also pins the emitted vocabulary literal, read off the SAME constant the
  /// shipping method writes into the profile (`protocol_version`/`carrier`), so
  /// the payload and the gate cannot drift.
  func testWinn3ControlPlaneEmittedINIRoundTripsAsStandalone() throws {
    XCTAssertEqual(WinsWinn3ControlPlaneDelivery.protocolVersion, "winn/3",
                   "the served v3 literal must stay the negotiated protocol string")
    XCTAssertEqual(WinsWinn3ControlPlaneDelivery.carrier, "winn3",
                   "the delivered carrier must be the standalone carrier name")

    let config = try WinsTunnelConfig.parseAndValidate(standaloneWinn3INI)
    XCTAssertTrue(config.winn3Enabled,
                  "the emitted winn/3 INI must round-trip as a standalone winn3 carrier")

    XCTAssertNil(
      WinsWinn3ControlPlaneDelivery.admission(
        rawProtocolVersion: nil, rawCarrier: nil, config: standaloneWinn3INI
      ),
      "a standalone winn/3 INI must be acceptable to the delivery gate"
    )
  }

  /// The refusal half: a RELAY carrier (`direct-awg`) in an otherwise identical
  /// document still round-trips through `parseAndValidate`, but it is NOT a
  /// standalone carrier, so `winn3Enabled` is false and the delivery gate must
  /// refuse it with the exact "not a standalone winn3 carrier" message -- the
  /// delivery path can never be used to install a relay profile.
  func testWinn3ControlPlaneRefusesRelayCarrierWithNotStandaloneMessage() throws {
    let relay = try WinsTunnelConfig.parseAndValidate(relayWinn3INI)
    XCTAssertFalse(relay.winn3Enabled,
                   "a relay carrier must not resolve as a standalone winn3 carrier")
    XCTAssertNil(relay.winn3StartRefusalReason,
                 "a relay carrier must not consult the winn/3 start gate at all")

    XCTAssertEqual(
      WinsWinn3ControlPlaneDelivery.admission(
        rawProtocolVersion: nil, rawCarrier: nil, config: relayWinn3INI
      ),
      WinsWinn3ControlPlaneDelivery.notStandaloneMessage
    )
    XCTAssertTrue(
      WinsWinn3ControlPlaneDelivery.notStandaloneMessage.contains("not a standalone winn3 carrier"),
      "the refusal wording must carry the exact 'not a standalone winn3 carrier' the task names"
    )
  }

  /// A standalone INI delivered with a `protocol_version` other than `winn/3`
  /// must be refused before the carrier is even inspected, so a mismatched
  /// protocol cannot reach the carrier gate (silent-refusal family #1/#7: an
  /// encoding or version mismatch must never install a profile that looks like
  /// a resolved v3 session).
  func testWinn3ControlPlaneRefusesNonWinn3ProtocolVersion() {
    XCTAssertEqual(
      WinsWinn3ControlPlaneDelivery.admission(
        rawProtocolVersion: "winn/2", rawCarrier: nil, config: standaloneWinn3INI
      ),
      "The winn/3 control-plane delivery requires protocol_version winn/3."
    )
  }

  /// Asserts the thin posture helper (`WinsIOSRoutePosture`) that makes the iOS
  /// `enforceRoutes`/`excludeLocalNetworks` carriage unit-checkable.
  ///
  /// The RULINGS.lock (docs/rulings/RULINGS.lock) independently guards the
  /// LITERAL `tunnelProtocol.enforceRoutes = true` inside AppDelegate.swift, and
  /// `tools/verify_rulings.sh` checks that after every lane merge. This helper is
  /// the unit-testable companion to that grep: it encodes the SAME ruled value as
  /// a typed constant and asserts a protocol shaped exactly like the connect path
  /// reads as carrying it. Both a positive case (flag set) and a negative control
  /// (flag dropped) are asserted, because a test with only the positive side is
  /// the recurring false-green shape that passes when the flag silently flips.
  func testWinsIOSRoutePostureHelperAssertsRuledCarriage() throws {
    XCTAssertTrue(
      WinsIOSRoutePosture.enforceRoutes,
      "WinsIOSRoutePosture.enforceRoutes must carry the ruled true (RULINGS.lock REQUIRE)"
    )
    XCTAssertTrue(
      WinsIOSRoutePosture.excludeLocalNetworks,
      "excludeLocalNetworks must stay true alongside enforceRoutes or the local-capture deadlock returns"
    )

    guard WinsIOSRoutePosture.canApply() else {
      throw XCTSkip("the ruled enforceRoutes/excludeLocalNetworks posture is gated at iOS 14.2")
    }

    // Positive: a protocol built exactly the way the AppDelegate connect path
    // builds it (both flags true) must read as carrying the ruled posture.
    let compliant = enforceRoutesProtocol(enforceRoutes: true)
    XCTAssertTrue(WinsIOSRoutePosture.carriesEnforceRoutes(compliant))
    XCTAssertTrue(WinsIOSRoutePosture.carriesExcludeLocalNetworks(compliant))
    XCTAssertTrue(
      WinsIOSRoutePosture.carriesRuledPosture(compliant),
      "the AppDelegate-shaped protocol must carry the ruled full posture"
    )

    // Negative control: a protocol that never set enforceRoutes must NOT read as
    // carrying the ruled posture. Without this, a helper that hardcodes true (or
    // a connect path that silently drops the flag) would pass this test green.
    let dropped = enforceRoutesProtocol(enforceRoutes: false)
    XCTAssertFalse(WinsIOSRoutePosture.carriesEnforceRoutes(dropped))
    XCTAssertFalse(
      WinsIOSRoutePosture.carriesRuledPosture(dropped),
      "a protocol that dropped enforceRoutes must not read as carrying the ruled posture"
    )
  }

  /// iOS `enforceRoutes` split-tunnel-leak proof.
  ///
  /// The app's tunnel authority path sets `enforceRoutes = true` (with
  /// `excludeLocalNetworks = true`) before saving the `NETunnelProviderProtocol`
  /// (AppDelegate, connect path ~line 1801). That flag is what closes the one
  /// leak the current settings cannot: a MORE SPECIFIC route on the physical
  /// interface otherwise beats the tunnel's 0.0.0.0/0 and carries that traffic
  /// in the clear. This test builds that SAME protocol and proves the flag
  /// survives the framework's persistence save/load round-trip. If
  /// `enforceRoutes` were ever dropped on reload, the running tunnel would
  /// silently degrade back to the split-tunnel posture -- and this test is what
  /// would go red.
  func testEnforceRoutesSurvivesSaveLoadRoundTripClosingSplitTunnelLeak() throws {
    guard #available(iOS 14.2, *) else {
      throw XCTSkip("the enforceRoutes/excludeLocalNetworks routing posture needs iOS 14.2")
    }

    let fileURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("wins-enforceroutes-\(UUID().uuidString).plist")
    addTeardownBlock { try? FileManager.default.removeItem(at: fileURL) }

    let saver = enforceRoutesProtocol(enforceRoutes: true)
    let archived = try NSKeyedArchiver.archivedData(
      withRootObject: saver,
      requiringSecureCoding: true
    )
    try archived.write(to: fileURL, options: .atomic)
    XCTAssertGreaterThan(archived.count, 0)

    let onDisk = try Data(contentsOf: fileURL)
    let reloaded = try XCTUnwrap(
      NSKeyedUnarchiver.unarchivedObject(
        ofClass: NETunnelProviderProtocol.self,
        from: onDisk
      ),
      "the framework must reconstruct the tunnel protocol from the saved bytes"
    )

    XCTAssertEqual(reloaded.providerBundleIdentifier, saver.providerBundleIdentifier)
    XCTAssertEqual(reloaded.serverAddress, saver.serverAddress)
    XCTAssertEqual(reloaded.enforceRoutes, true,
                   "enforceRoutes must survive the save/load round-trip or the split-tunnel leak stays open")
    XCTAssertEqual(reloaded.excludeLocalNetworks, true)

    // Negative control: a protocol that never set enforceRoutes must reload as
    // false. This proves the positive assertion is testing the flag itself and
    // not an always-true artifact of the encode/decode path.
    let baseline = enforceRoutesProtocol(enforceRoutes: false)
    let baselineArchived = try NSKeyedArchiver.archivedData(
      withRootObject: baseline,
      requiringSecureCoding: true
    )
    let baselineReloaded = try XCTUnwrap(
      NSKeyedUnarchiver.unarchivedObject(
        ofClass: NETunnelProviderProtocol.self,
        from: baselineArchived
      )
    )
    XCTAssertEqual(baselineReloaded.enforceRoutes, false,
                   "without enforceRoutes the reloaded protocol must be false, or the test cannot distinguish the flag")
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

  func testWinn3SecurityRefusalNeverAuthorizesV1Fallback() {
    let observation = WinsWinn3NativeStartClassifier.observe(
      expectedGeneration: "generation-current",
      status: [
        "status_schema_version": WinsPacketTunnelProviderStatus.schemaVersion,
        "status_generation": "generation-current",
        "stage": "start_rejected",
        "error_code": 1040,
        "winn3_descriptor_node_bound": false
      ]
    )
    XCTAssertEqual(observation, .finished(.terminalSecurity))
    XCTAssertFalse(WinsWinn3NativeStartOutcome.terminalSecurity.authorizesV1Fallback)
    XCTAssertFalse(WinsWinn3NativeStartOutcome.terminalSecurity.reportsNativeStartAccepted)
  }

  func testWinn3ProofTimeoutNeverAuthorizesV1EvenWithNetworkErrno() {
    let observation = WinsWinn3NativeStartClassifier.observe(
      expectedGeneration: "generation-current",
      status: [
        "status_schema_version": WinsPacketTunnelProviderStatus.schemaVersion,
        "status_generation": "generation-current",
        "stage": "engine_start_failed",
        "error_code": 1037,
        "winn_datapath_proof_timeout": true,
        WinsWinn3NativeStartOutcome.ordinaryNetworkPosixErrnoKey: 51
      ]
    )
    XCTAssertEqual(observation, .finished(.unknownTerminal))
    XCTAssertFalse(WinsWinn3NativeStartOutcome.unknownTerminal.authorizesV1Fallback)
  }

  func testWinn3OrdinaryConnectivityGrantRequiresAwgBeforeXray() {
    WinsWinn3AwgXrayGrantStore.clear()
    defer { WinsWinn3AwgXrayGrantStore.clear() }

    XCTAssertTrue(WinsWinn3AwgXrayGrantStore.arm(
      startToken: 101,
      startGeneration: 7,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      nowMs: 1_000
    ))
    XCTAssertFalse(WinsWinn3AwgXrayGrantStore.consume(
      startToken: 101,
      startGeneration: 7,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .xray,
      nowMs: 1_001
    ))

    XCTAssertTrue(WinsWinn3AwgXrayGrantStore.arm(
      startToken: 101,
      startGeneration: 7,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      nowMs: 2_000
    ))
    XCTAssertTrue(WinsWinn3AwgXrayGrantStore.consume(
      startToken: 101,
      startGeneration: 7,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .awg,
      nowMs: 2_001
    ))
    XCTAssertTrue(WinsWinn3AwgXrayGrantStore.consume(
      startToken: 101,
      startGeneration: 7,
      selectionGeneration: "0123456789abcdef",
      failedV3Node: "v3-node",
      exactV1Target: "v1-cover",
      requestedLeg: .xray,
      nowMs: 2_002
    ))
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

  /// Builds the same `NETunnelProviderProtocol` the app's tunnel authority path
  /// constructs before saving (AppDelegate line ~1801) so the persistence
  /// assertion applies to the exact rendezvous the app persists. The routing-
  /// relevant fields (enforceRoutes, excludeLocalNetworks, provider bundle,
  /// server address) mirror that path.
  private func enforceRoutesProtocol(enforceRoutes: Bool) -> NETunnelProviderProtocol {
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = "org.winsvpn.app.PacketTunnel"
    tunnelProtocol.serverAddress = "WinsVPN"
    tunnelProtocol.providerConfiguration = [
      "wins_manager_signature": "test-signature",
      "app_group_id": "group.org.winsvpn.app",
      "shared_config_private_key_redacted": true
    ]
    if #available(iOS 14.2, *) {
      tunnelProtocol.enforceRoutes = enforceRoutes
      tunnelProtocol.excludeLocalNetworks = true
    }
    return tunnelProtocol
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
