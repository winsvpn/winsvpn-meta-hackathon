import Foundation
import Security

@main
struct WinsAppleTunnelConfigHarness {
  // Deterministic public test material: the base64 encoding of bytes 0...31.
  // This must be structurally valid because the parser deliberately rejects
  // redaction sentinels before any runtime tunnel can be created.
  private static let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

  static func main() throws {
    try expectValid(directConfig, endpoint: "203.0.113.10:9110", xrayEnabled: false)
    try expectValid(xrayConfig, endpoint: "127.0.0.1:42110", xrayEnabled: true)
    try expectOptionalAwgSpecialJunkUapi()
    try expectXrayIPv4TransportExclusion()
    try expectWinnCarrierAndTransportExclusion()
    try expectWinnAmneziaWGUAPIRepoint()
    try expectInvalid(winnMissingEndpointConfig, code: 1503)
    try expectInvalid(winnHostnameEndpointConfig, code: 1503)
    try expectInvalid(winnLoopbackEndpointConfig, code: 1504)
    try expectInvalid(winnLoopbackPeerConfig, code: 1505)
    try expectInvalid(winnWithXrayConfig, code: 1502)
    // WinsTunnelConfig.validXraySecurity accepts only TLS: `none` would put the
    // VLESS UUID, WebSocket path and Host header on the wire in cleartext.
    try expectInvalid(xrayConfig.replacingOccurrences(of: "Security = tls", with: "Security = none"), code: 1307)
    try expectInvalid(winnHttp2CarrierConfig, code: 1506)
    try expectWinnDirectCarrierAccepted()
    try expectWinnHttp3CarrierAccepted()
    try expectPreTunnelTransportResolution()
    try expectSplitRoutes(splitRouteConfig)
    try expectSplitTunnelWithIPv6DefaultRouteStillProtectsIPv6()
    try expectFullTunnelIPv6ProtectionUnchanged()
    try expectValidateRequiresIPv6DefaultRoute()
    try expectSplitTunnelStillForcesFullDNSCapture()
    try expectNormalizedAllowedIPv4Routes()
    try expectNoDevContainmentInOrdinaryConfigs()
    try expectDevContainmentPlanNarrowsEverything()
    try expectDevContainmentRefusesToWiden()
    try expectDevContainmentFailsLeakProtectionCheck()
    try expectInvalid(missingPrivateKeyConfig, code: 1101)
    try expectInvalid(invalidInterfaceAddressConfig, code: 1102)
    try expectInvalid(invalidMTUConfig, code: 1104)
    try expectInvalid(missingAwgObfuscationConfig, code: 1106)
    try expectInvalid(invalidEndpointConfig, code: 1202)
    try expectInvalid(invalidAllowedIPsConfig, code: 1203)
    try expectInvalid(missingIPv6DefaultRouteConfig, code: 1203)
    try expectInvalid(partialIPv6RouteConfig, code: 1203)
    try expectInvalid(invalidOptionalAwgSpecialJunkConfig, code: 1106)
    try expectInvalid(invalidXrayUuidConfig, code: 1304)
    try expectInvalid(invalidXrayPortConfig, code: 1305)
    try expectInvalid(invalidXrayServerNameConfig, code: 1306)
    try expectInvalid(invalidXrayPathConfig, code: 1302)
    try expectInvalid(invalidXrayLocalPortConfig, code: 1303)
    try expectInvalid(invalidXrayEndpointConfig, code: 1308)
    try expectInvalid(invalidXrayRemoteAwgHostConfig, code: 1309)
    try expectInvalid(invalidXrayRemoteAwgPortConfig, code: 1310)
    try expectRuntimeConfigSizeValidation()
    try expectRedactedStorageConfig()
    try expectInterfaceKeyPairValidation()
    try expectGeneratedClientKeyPair()
    try expectGeneratedInstallIdentity()
    try expectTunnelManagerIdentity()
    try expectAppGroupValidation()
    try expectBoundedUTF8FileReader()
    try expectAppGroupFileWriter()
    try expectAppGroupDuressPurge()
    try expectKeychainDuressPurge()
    try expectSharedConfigPathGuard()
    try expectProviderErrorRedaction()
    try expectProviderStatusPayload(directConfig, xrayEnabled: false)
    try expectProviderStatusPayload(xrayConfig, xrayEnabled: true)
    try expectProviderStatusGenerationSanitization()
    try expectProviderRuntimeInputSelection()
    try expectProviderStatusWritableDataLimit()
    try expectNetworkSettingsReleaseStatusFields()
    try expectNetworkSettingsReleaseFieldsSurviveCompaction()
    try expectDevContainmentIsCarriedIntoTheStopDocument()
    try expectDevContainmentStopCarrySurvivesCompaction()
    try expectProviderStatusMappedValueSanitization()
    try expectProviderStatusStageValidation()
    try expectAppleReadinessValidation()
    try expectProviderLifecycleAndAppMessagePayload()
    try expectEngineBundleProbe()
    try expectFrameworkWithoutExecutableBitStillResolves()
    try expectExternalUrlValidation()
    try expectShareTextValidation()
    try expectNotificationTextValidation()
    try expectWinn3NativeStartOutcomeClassification()
    print("Apple tunnel config and client key harness passed.")
  }

  private static func expectValid(
    _ rawConfig: String,
    endpoint: String,
    xrayEnabled: Bool
  ) throws {
    let config = try WinsTunnelConfig.parseAndValidate(rawConfig)
    guard config.peerEndpoint == endpoint else {
      throw HarnessError("Expected endpoint \(endpoint), got \(config.peerEndpoint).")
    }
    guard config.xrayEnabled == xrayEnabled else {
      throw HarnessError("Expected xrayEnabled=\(xrayEnabled), got \(config.xrayEnabled).")
    }
    let expectedTransportMode = xrayEnabled ? "xray_vless_ws_amneziawg" : "amneziawg"
    guard config.transportMode == expectedTransportMode else {
      throw HarnessError("Expected transport mode \(expectedTransportMode), got \(config.transportMode).")
    }
    let expectedComponents = xrayEnabled
      ? ["amneziawg_packet_engine", "xray_vless_ws_transport"]
      : ["amneziawg_packet_engine"]
    let expectedPeerKind = xrayEnabled ? "loopback" : "ipv4"
    let expectedTransportKind = xrayEnabled ? "hostname" : "ipv4"
    let expectedRemoteSource = xrayEnabled ? "interface_gateway_ipv4" : "transport_endpoint_ipv4"
    guard config.requiredEngineComponents == expectedComponents else {
      throw HarnessError("Expected engine components \(expectedComponents), got \(config.requiredEngineComponents).")
    }
    let enginePlan = WinsPacketTunnelEnginePlan(config: config)
    guard enginePlan.transportMode == expectedTransportMode,
          enginePlan.requiredComponents == expectedComponents else {
      throw HarnessError("Packet engine plan did not match parsed config.")
    }
    let engineStatus = enginePlan.statusFields
    guard engineStatus["engine_adapter_version"] as? Int == WinsPacketTunnelEnginePlan.adapterVersion,
          engineStatus["engine_adapter_required"] as? Bool == true,
          engineStatus["engine_adapter_available"] as? Bool == false,
          engineStatus["engine_bundle_probe"] as? String == WinsPacketTunnelEnginePlan.missingNativeEngineProbe,
          engineStatus["engine_bundle_probe_schema_version"] as? Int == WinsPacketTunnelEngineBundleProbe.schemaVersion,
          engineStatus["engine_bundle_required_components"] as? [String] == expectedComponents,
          engineStatus["engine_bundle_available_components"] as? [String] == [],
          engineStatus["engine_bundle_missing_components"] as? [String] == expectedComponents,
          engineStatus["engine_bundle_required_component_count"] as? Int == expectedComponents.count,
          engineStatus["engine_bundle_available_component_count"] as? Int == 0,
          engineStatus["engine_bundle_missing_component_count"] as? Int == expectedComponents.count,
          engineStatus["engine_bundle_all_required_components_present"] as? Bool == false,
          engineStatus["engine_transport_mode"] as? String == expectedTransportMode,
          engineStatus["engine_required_components"] as? [String] == expectedComponents,
          engineStatus["engine_lifecycle_state"] as? String == "not_started",
          engineStatus["engine_launch_descriptor_schema_version"] as? Int == WinsPacketTunnelEngineLaunchDescriptor.schemaVersion,
          engineStatus["engine_launch_descriptor_ready"] as? Bool == true,
          engineStatus["engine_launch_descriptor_secret_material_redacted"] as? Bool == true,
          engineStatus["engine_launch_descriptor_config_source"] as? String == "validated_wins_tunnel_config",
          engineStatus["engine_launch_descriptor_transport_mode"] as? String == expectedTransportMode,
          engineStatus["engine_launch_contract_version"] as? Int == WinsPacketTunnelEnginePlan.launchContractVersion,
          engineStatus["engine_packet_flow_required"] as? Bool == true,
          engineStatus["engine_packet_flow_available"] as? Bool == false,
          engineStatus["engine_interface_private_key_present"] as? Bool == true,
          engineStatus["engine_interface_private_key_redacted"] as? Bool == true,
          engineStatus["engine_peer_public_key_present"] as? Bool == true,
          engineStatus["engine_peer_public_key_redacted"] as? Bool == true,
          engineStatus["engine_peer_preshared_key_present"] as? Bool == false,
          engineStatus["engine_peer_preshared_key_redacted"] as? Bool == true,
          engineStatus["engine_peer_keepalive_present"] as? Bool == true,
          engineStatus["engine_awg_obfuscation_present"] as? Bool == true,
          engineStatus["engine_awg_obfuscation_field_count"] as? Int == 11,
          engineStatus["engine_awg_uapi_config_ready"] as? Bool == true,
          engineStatus["engine_awg_uapi_secret_material_redacted"] as? Bool == true,
          engineStatus["engine_allowed_ipv4_route_count"] as? Int == 1,
          engineStatus["engine_default_route_enabled"] as? Bool == true,
          engineStatus["engine_ipv6_leak_protection_enabled"] as? Bool == true,
          engineStatus["engine_ipv6_sink_prefix_length"] as? Int == 128,
          engineStatus["engine_dns_server_count"] as? Int == 1,
          engineStatus["engine_full_tunnel_dns_match_enabled"] as? Bool == true,
          engineStatus["engine_mtu"] as? Int == 1_280,
          engineStatus["engine_peer_endpoint_kind"] as? String == expectedPeerKind,
          engineStatus["engine_transport_endpoint_kind"] as? String == expectedTransportKind,
          engineStatus["engine_network_settings_remote_address_kind"] as? String == "ipv4",
          engineStatus["engine_network_settings_remote_address_source"] as? String == expectedRemoteSource,
          engineStatus["engine_transport_ipv4_exclusion_route_present"] as? Bool == !xrayEnabled,
          engineStatus["engine_xray_transport_required"] as? Bool == xrayEnabled else {
      throw HarnessError("Packet engine status fields are incomplete: \(engineStatus).")
    }
    if xrayEnabled {
      guard engineStatus["engine_xray_uuid_present"] as? Bool == true,
            engineStatus["engine_xray_uuid_redacted"] as? Bool == true,
            engineStatus["engine_xray_security"] as? String == "tls",
            engineStatus["engine_xray_host_present"] as? Bool == true,
            engineStatus["engine_xray_host_redacted"] as? Bool == true,
            engineStatus["engine_xray_server_name_present"] as? Bool == true,
            engineStatus["engine_xray_server_name_redacted"] as? Bool == true,
            engineStatus["engine_xray_path_present"] as? Bool == true,
            engineStatus["engine_xray_path_redacted"] as? Bool == true,
            engineStatus["engine_xray_remote_port_present"] as? Bool == true,
            engineStatus["engine_xray_local_port_present"] as? Bool == true,
            engineStatus["engine_xray_remote_awg_loopback"] as? Bool == true,
            engineStatus["engine_xray_remote_awg_port_present"] as? Bool == true else {
        throw HarnessError("Packet engine Xray launch contract is incomplete: \(engineStatus).")
      }
    } else if engineStatus.keys.contains(where: { $0.hasPrefix("engine_xray_") && $0 != "engine_xray_transport_required" }) {
      throw HarnessError("Direct packet engine status unexpectedly included Xray-only fields: \(engineStatus).")
    }
    let engineStatusDescription = String(describing: engineStatus)
    for rawFragment in [
      key,
      "203.0.113.10",
      "sync.example.invalid",
      "00000000-0000-0000-0000-000000000000",
      "/wins-stealth-tunnel",
      "42110",
      "9110"
    ] where engineStatusDescription.contains(rawFragment) {
      throw HarnessError("Packet engine status leaked raw runtime config fragment: \(rawFragment).")
    }
    let missingEngine = WinsMissingPacketTunnelEngine(config: config)
    guard missingEngine.plan.transportMode == expectedTransportMode,
          missingEngine.isRunning == false else {
      throw HarnessError("Missing packet engine initialized with unexpected state.")
    }
    do {
      _ = try missingEngine.start()
      throw HarnessError("Missing packet engine unexpectedly started.")
    } catch let error as WinsPacketTunnelEngineError {
      guard error.code == 1003,
            error.errorCode == 1003,
            type(of: error).errorDomain == "org.winsvpn.PacketTunnelEngine",
            error.localizedDescription.contains("native packet engine is not bundled yet") else {
        throw HarnessError("Missing packet engine error was incomplete: \(error).")
      }
    }
    missingEngine.stop()
    guard missingEngine.isRunning == false else {
      throw HarnessError("Missing packet engine stop did not settle state.")
    }
    guard config.interfaceIPv4Address == "10.8.0.2" else {
      throw HarnessError("Expected interface IPv4 10.8.0.2, got \(config.interfaceIPv4Address).")
    }
    guard config.interfaceIPv4SubnetMask == "255.255.255.255" else {
      throw HarnessError("Expected /32 subnet mask, got \(config.interfaceIPv4SubnetMask).")
    }
    guard config.dnsServers == ["10.8.0.1"] else {
      throw HarnessError("Expected DNS 10.8.0.1, got \(config.dnsServers).")
    }
    guard config.dnsMatchDomains == [""],
          config.fullTunnelDNSMatchEnabled else {
      throw HarnessError("Expected full-tunnel DNS match domains, got \(config.dnsMatchDomains).")
    }
    guard config.mtu == 1_280 else {
      throw HarnessError("Expected MTU 1280, got \(config.mtu).")
    }
    guard config.peerEndpointHost == endpoint.split(separator: ":").dropLast().joined(separator: ":") else {
      throw HarnessError("Endpoint host parsing failed for \(endpoint).")
    }
    guard config.peerEndpointKind == expectedPeerKind else {
      throw HarnessError("Expected peer endpoint kind \(expectedPeerKind), got \(config.peerEndpointKind).")
    }
    guard config.peerEndpointPort > 0 else {
      throw HarnessError("Endpoint port parsing failed for \(endpoint).")
    }
    guard config.allowedIPs == ["0.0.0.0/0", "::/0"] else {
      throw HarnessError("Expected IPv4 and IPv6 default routes, got \(config.allowedIPs).")
    }
    guard config.allowedIPv4Routes.count == 1,
          config.allowedIPv4Routes[0].isDefaultRoute,
          config.allowedIPv4Routes[0].subnetMask == "0.0.0.0" else {
      throw HarnessError("Expected parsed default route, got \(config.allowedIPv4Routes).")
    }
    guard config.defaultIPv4RouteEnabled else {
      throw HarnessError("Expected default IPv4 route to be detected.")
    }
    guard config.ipv6LeakProtectionEnabled,
          config.ipv6SinkAddress == WinsTunnelConfig.ipv6SinkAddress,
          config.ipv6SinkPrefixLength == WinsTunnelConfig.ipv6SinkPrefixLength else {
      throw HarnessError("Expected full-tunnel config to enable IPv6 leak protection.")
    }
    let expectedTransportHost = xrayEnabled ? "sync.example.invalid" : "203.0.113.10"
    guard config.transportEndpointHost == expectedTransportHost else {
      throw HarnessError("Expected transport endpoint \(expectedTransportHost), got \(config.transportEndpointHost).")
    }
    guard config.transportEndpointKind == expectedTransportKind,
          config.networkSettingsRemoteAddressKind == "ipv4",
          config.networkSettingsRemoteAddressSource == expectedRemoteSource else {
      throw HarnessError("Expected transport endpoint kind \(expectedTransportKind) and IPv4 Network Extension remote via \(expectedRemoteSource), got \(config.transportEndpointKind)/\(config.networkSettingsRemoteAddressKind)/\(config.networkSettingsRemoteAddressSource).")
    }
    let expectedNetworkRemote = xrayEnabled ? "10.8.0.1" : expectedTransportHost
    guard config.networkSettingsRemoteAddress == expectedNetworkRemote else {
      throw HarnessError("Expected Network Extension remote address \(expectedNetworkRemote), got \(config.networkSettingsRemoteAddress).")
    }
    if xrayEnabled {
      guard config.transportIPv4ExclusionRoute == nil else {
        throw HarnessError("Domain-based Xray transport unexpectedly produced an IPv4 exclusion route.")
      }
    } else {
      guard let exclusionRoute = config.transportIPv4ExclusionRoute,
            exclusionRoute.destinationAddress == "203.0.113.10",
            exclusionRoute.subnetMask == "255.255.255.255",
            exclusionRoute.prefixLength == 32 else {
        throw HarnessError("Expected direct transport IPv4 exclusion route, got \(String(describing: config.transportIPv4ExclusionRoute)).")
      }
    }
    guard let obfuscation = config.awgObfuscation,
          obfuscation.jc == 2,
          obfuscation.jmin == 10,
          obfuscation.jmax == 30,
          obfuscation.s1 == 16,
          obfuscation.s2 == 80,
          obfuscation.s3 == 16,
          obfuscation.s4 == 0,
          // h1..h4 became WinsAwgHeaderSpec(start:end:) when header *ranges*
          // landed; a scalar header is the degenerate range start == end, so
          // these four still assert exactly the values they always did.
          obfuscation.h1 == WinsAwgHeaderSpec(start: 11, end: 11),
          obfuscation.h2 == WinsAwgHeaderSpec(start: 22, end: 22),
          obfuscation.h3 == WinsAwgHeaderSpec(start: 33, end: 33),
          obfuscation.h4 == WinsAwgHeaderSpec(start: 44, end: 44) else {
      throw HarnessError("Expected parsed AmneziaWG obfuscation settings.")
    }
    let awgUapi = try config.amneziaWGUAPIConfiguration()
    let fixtureKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    for expectedLine in [
      "private_key=\(fixtureKeyHex)",
      "jc=2",
      "jmin=10",
      "jmax=30",
      "s1=16",
      "s2=80",
      "s3=16",
      "s4=0",
      "h1=11",
      "h2=22",
      "h3=33",
      "h4=44",
      "replace_peers=true",
      "public_key=\(fixtureKeyHex)",
      "endpoint=\(endpoint)",
      "persistent_keepalive_interval=25",
      "replace_allowed_ips=true",
      "allowed_ip=0.0.0.0/0",
      "allowed_ip=::/0"
    ] {
      guard awgUapi.contains("\(expectedLine)\n") else {
        throw HarnessError("AmneziaWG UAPI config missed expected line \(expectedLine): \(awgUapi).")
      }
    }
    for rawFragment in [key, "PrivateKey", "PublicKey", "Jc =", "S3 =", "H4 ="] where awgUapi.contains(rawFragment) {
      throw HarnessError("AmneziaWG UAPI config retained raw wg-quick fragment: \(rawFragment).")
    }
    if xrayEnabled {
      guard let xray = config.xrayRuntimeConfig else {
        throw HarnessError("Expected parsed Xray runtime settings.")
      }
      guard xray.uuid == "00000000-0000-0000-0000-000000000000",
            xray.host == "sync.example.invalid",
            xray.port == 80,
            xray.serverName == "sync.example.invalid",
            xray.path == "/wins-stealth-tunnel",
            xray.security == "tls",
            xray.localPort == 42110,
            xray.remoteAwgHost == "127.0.0.1",
            xray.remoteAwgPort == 9110 else {
        throw HarnessError("Xray runtime settings parsed incorrectly: \(xray).")
      }
    } else if config.xrayRuntimeConfig != nil {
      throw HarnessError("Direct config unexpectedly produced Xray runtime settings.")
    }
  }

  private static func expectEngineBundleProbe() throws {
    let directProbe = WinsPacketTunnelEngineBundleProbe(
      requiredComponents: ["amneziawg_packet_engine"],
      availableComponents: []
    )
    guard directProbe.probeCode == WinsPacketTunnelEngineBundleProbe.missingNativeEngineProbe,
          directProbe.requiredComponents == ["amneziawg_packet_engine"],
          directProbe.availableComponents == [],
          directProbe.missingComponents == ["amneziawg_packet_engine"],
          directProbe.allRequiredComponentsPresent == false else {
      throw HarnessError("Direct bundle probe did not report the missing AWG engine: \(directProbe.statusFields).")
    }

    let partialXrayProbe = WinsPacketTunnelEngineBundleProbe(
      requiredComponents: ["amneziawg_packet_engine", "xray_vless_ws_transport"],
      availableComponents: [
        "AMNEZIAWG_PACKET_ENGINE",
        "unused_component",
        "/tmp/xray_vless_ws_transport.framework",
        "xray.vless.ws.transport"
      ]
    )
    guard partialXrayProbe.probeCode == WinsPacketTunnelEngineBundleProbe.missingNativeEngineProbe,
          partialXrayProbe.availableComponents == ["amneziawg_packet_engine"],
          partialXrayProbe.missingComponents == ["xray_vless_ws_transport"],
          partialXrayProbe.allRequiredComponentsPresent == false else {
      throw HarnessError("Partial Xray bundle probe did not isolate the missing Xray component: \(partialXrayProbe.statusFields).")
    }

    let completeXrayProbe = WinsPacketTunnelEngineBundleProbe(
      requiredComponents: ["amneziawg_packet_engine", "xray_vless_ws_transport"],
      availableComponents: ["xray_vless_ws_transport", "amneziawg_packet_engine"]
    )
    guard completeXrayProbe.probeCode == WinsPacketTunnelEngineBundleProbe.nativeEngineAdapterMissingProbe,
          completeXrayProbe.availableComponents == ["amneziawg_packet_engine", "xray_vless_ws_transport"],
          completeXrayProbe.missingComponents == [],
          completeXrayProbe.allRequiredComponentsPresent == true else {
      throw HarnessError("Complete Xray bundle probe did not report adapter wiring as the next blocker: \(completeXrayProbe.statusFields).")
    }

    let config = try WinsTunnelConfig.parseAndValidate(xrayConfig)
    let completePlan = WinsPacketTunnelEnginePlan(
      config: config,
      availableBundleComponents: ["amneziawg_packet_engine", "xray_vless_ws_transport"]
    )
    let completeStatus = completePlan.statusFields
    guard completeStatus["engine_bundle_probe"] as? String == WinsPacketTunnelEngineBundleProbe.nativeEngineAdapterMissingProbe,
          completeStatus["engine_bundle_missing_components"] as? [String] == [],
          completeStatus["engine_bundle_all_required_components_present"] as? Bool == true else {
      throw HarnessError("Complete bundle plan did not preserve sanitized bundle status: \(completeStatus).")
    }

    let (partialRuntimeBundle, partialRuntimeBundleURL) = try makeTemporaryProbeBundle(
      artifacts: ["WinsAmneziaWGPacketEngine.framework"]
    )
    defer {
      try? FileManager.default.removeItem(at: partialRuntimeBundleURL)
    }
    let partialRuntimeProbe = WinsPacketTunnelEngineBundleProbe.probe(
      requiredComponents: ["amneziawg_packet_engine", "xray_vless_ws_transport"],
      bundle: partialRuntimeBundle
    )
    guard partialRuntimeProbe.availableComponents == ["amneziawg_packet_engine"],
          partialRuntimeProbe.missingComponents == ["xray_vless_ws_transport"],
          partialRuntimeProbe.probeCode == WinsPacketTunnelEngineBundleProbe.missingNativeEngineProbe else {
      throw HarnessError("Runtime bundle probe did not detect the embedded AWG artifact: \(partialRuntimeProbe.statusFields).")
    }

    let (completeRuntimeBundle, completeRuntimeBundleURL) = try makeTemporaryProbeBundle(
      artifacts: [
        "WinsAmneziaWGPacketEngine.framework",
        "WinsXrayVlessWsTransport"
      ]
    )
    defer {
      try? FileManager.default.removeItem(at: completeRuntimeBundleURL)
    }
    let packetFlow = NSObject()
    let runtimeEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: completeRuntimeBundle,
      packetFlow: packetFlow
    )
    guard runtimeEngine.plan.bundleProbe.availableComponents == [
            "amneziawg_packet_engine",
            "xray_vless_ws_transport"
          ],
          runtimeEngine.plan.bundleProbe.missingComponents == [],
          runtimeEngine.plan.bundleProbe.probeCode == WinsPacketTunnelEngineBundleProbe.nativeEngineAdapterMissingProbe else {
      throw HarnessError("Engine factory did not preserve complete runtime bundle probe state: \(runtimeEngine.plan.statusFields).")
    }
    do {
      _ = try runtimeEngine.start()
      throw HarnessError("Runtime-probed missing packet engine unexpectedly started.")
    } catch let error as WinsPacketTunnelEngineError {
      guard error.code == 1003,
            error.localizedDescription.contains("native packet engine adapter was not available at runtime") else {
        throw HarnessError("Runtime-probed missing engine error did not identify the adapter blocker: \(error).")
      }
    }

    let missingPacketFlowEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: completeRuntimeBundle,
      adapter: HarnessPacketTunnelEngineAdapter()
    )
    do {
      _ = try missingPacketFlowEngine.start()
      throw HarnessError("Adapter-backed engine unexpectedly started without packet flow.")
    } catch let error as WinsPacketTunnelEngineError {
      guard error.code == 1003,
            error.statusFields["engine_packet_flow_available"] as? Bool == false,
            missingPacketFlowEngine.plan.statusFields["engine_packet_flow_available"] as? Bool == false,
            error.localizedDescription.contains("packet flow is unavailable") else {
        throw HarnessError("Missing packet-flow engine did not stay fail-closed: \(error).")
      }
    }

    let incompleteAdaptedEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: partialRuntimeBundle,
      packetFlow: packetFlow,
      adapter: HarnessPacketTunnelEngineAdapter()
    )
    do {
      _ = try incompleteAdaptedEngine.start()
      throw HarnessError("Incomplete runtime bundle unexpectedly started through the adapter.")
    } catch let error as WinsPacketTunnelEngineError {
      guard error.code == 1003,
            incompleteAdaptedEngine.plan.statusFields["engine_adapter_available"] as? Bool == false,
            error.localizedDescription.contains("native packet engine is not bundled yet") else {
        throw HarnessError("Incomplete adapted engine did not stay fail-closed: \(error).")
      }
    }

    let notReadyEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: completeRuntimeBundle,
      packetFlow: packetFlow,
      adapter: HarnessPacketTunnelEngineAdapter(engineReady: false)
    )
    do {
      _ = try notReadyEngine.start()
      throw HarnessError("Adapter-backed engine started without reporting readiness.")
    } catch let error as WinsPacketTunnelEngineError {
      try expectAdapterContractFailureStatus(
        error,
        readyReported: false,
        runningReported: true,
        packetFlowAttached: true
      )
      guard error.code == WinsPacketTunnelEngineError.adapterStartContractCode,
            !notReadyEngine.isRunning,
            error.localizedDescription.contains("running packet flow") else {
        throw HarnessError("Adapter readiness contract did not fail closed: \(error).")
      }
    }

    let notRunningEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: completeRuntimeBundle,
      packetFlow: packetFlow,
      adapter: HarnessPacketTunnelEngineAdapter(runningAfterStart: false)
    )
    do {
      _ = try notRunningEngine.start()
      throw HarnessError("Adapter-backed engine started without a running engine.")
    } catch let error as WinsPacketTunnelEngineError {
      try expectAdapterContractFailureStatus(
        error,
        readyReported: true,
        runningReported: false,
        packetFlowAttached: true
      )
      guard error.code == WinsPacketTunnelEngineError.adapterStartContractCode,
            !notRunningEngine.isRunning,
            error.localizedDescription.contains("running packet flow") else {
        throw HarnessError("Adapter running-state contract did not fail closed: \(error).")
      }
    }

    let detachedPacketFlowEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: completeRuntimeBundle,
      packetFlow: packetFlow,
      adapter: HarnessPacketTunnelEngineAdapter(packetFlowAttached: false)
    )
    do {
      _ = try detachedPacketFlowEngine.start()
      throw HarnessError("Adapter-backed engine started without attaching packet flow.")
    } catch let error as WinsPacketTunnelEngineError {
      try expectAdapterContractFailureStatus(
        error,
        readyReported: true,
        runningReported: true,
        packetFlowAttached: false
      )
      guard error.code == WinsPacketTunnelEngineError.adapterStartContractCode,
            !detachedPacketFlowEngine.isRunning,
            error.localizedDescription.contains("running packet flow") else {
        throw HarnessError("Adapter packet-flow contract did not fail closed: \(error).")
      }
    }

    let adaptedEngine = WinsPacketTunnelEngineFactory.makeEngine(
      config: config,
      bundle: completeRuntimeBundle,
      packetFlow: packetFlow,
      adapter: HarnessPacketTunnelEngineAdapter()
    )
    guard adaptedEngine.plan.bundleProbe.allRequiredComponentsPresent else {
      throw HarnessError("Adapted engine lost complete bundle probe state: \(adaptedEngine.plan.statusFields).")
    }
    let adaptedStart = try adaptedEngine.start()
    guard adaptedStart.engineReady,
          adaptedEngine.isRunning,
          adaptedStart.statusFields["engine_adapter_available"] as? Bool == true,
          adaptedStart.statusFields["engine_lifecycle_state"] as? String == "running",
          adaptedStart.statusFields["engine_packet_flow_available"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_packet_flow_attached"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_packet_flow_provided"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_awg_started"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_xray_started"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_secret_material_redacted"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_status_sanitized"] as? Bool == true,
          adaptedStart.statusFields["engine_runtime_attempt_count"] as? Int == 1,
          adaptedStart.statusFields["engine_runtime_components"] as? [String] == [
            "amneziawg_packet_engine",
            "xray_vless_ws_transport"
          ],
          adaptedStart.statusFields["engine_runtime_endpoint"] == nil,
          adaptedStart.statusFields["engine_runtime_log_path"] == nil,
          adaptedStart.statusFields["engine_runtime_publickey"] == nil,
          adaptedStart.statusFields["engine_bundle_missing_components"] as? [String] == [] else {
      throw HarnessError("Adapted engine start result did not expose safe runtime readiness: \(adaptedStart.statusFields).")
    }
    adaptedEngine.stop()
    guard !adaptedEngine.isRunning else {
      throw HarnessError("Adapted engine stop did not settle running state.")
    }

    let probeDescription = String(describing: [
      directProbe.statusFields,
      partialXrayProbe.statusFields,
      completeXrayProbe.statusFields,
      completeStatus,
      partialRuntimeProbe.statusFields,
      runtimeEngine.plan.statusFields,
      missingPacketFlowEngine.plan.statusFields,
      incompleteAdaptedEngine.plan.statusFields,
      adaptedEngine.plan.statusFields,
      adaptedStart.statusFields
    ])
    for rawFragment in [
      ".framework",
      "/tmp/",
      "WinsAmneziaWGPacketEngine",
      "WinsXrayVlessWsTransport",
      "xray.vless.ws.transport",
      key,
      "203.0.113.10",
      "sync.example.invalid",
      "/wins-stealth-tunnel",
      "42110",
      "9110"
    ] where probeDescription.contains(rawFragment) {
      throw HarnessError("Bundle probe leaked an unsafe runtime or path fragment: \(rawFragment).")
    }
  }

  private static func expectAdapterContractFailureStatus(
    _ error: WinsPacketTunnelEngineError,
    readyReported: Bool,
    runningReported: Bool,
    packetFlowAttached: Bool
  ) throws {
    guard let userInfoStatus = error.errorUserInfo[
      WinsPacketTunnelEngineError.statusFieldsUserInfoKey
    ] as? [String: Any],
      userInfoStatus["engine_runtime_contract_failed"] as? Bool == true else {
      throw HarnessError("Adapter contract failure did not expose sanitized status in userInfo.")
    }
    guard error.statusFields["engine_adapter_available"] as? Bool == true,
          error.statusFields["engine_packet_flow_available"] as? Bool == true,
          error.statusFields["engine_lifecycle_state"] as? String == "failed",
          error.statusFields["engine_runtime_contract_failed"] as? Bool == true,
          error.statusFields["engine_runtime_engine_ready_reported"] as? Bool == readyReported,
          error.statusFields["engine_runtime_engine_running_reported"] as? Bool == runningReported,
          error.statusFields["engine_runtime_packet_flow_attached"] as? Bool == packetFlowAttached,
          error.statusFields["engine_runtime_awg_started"] as? Bool == true,
          error.statusFields["engine_runtime_xray_started"] as? Bool == true,
          error.statusFields["engine_runtime_secret_material_redacted"] as? Bool == true,
          error.statusFields["engine_runtime_status_sanitized"] as? Bool == true else {
      throw HarnessError("Adapter contract failure status was incomplete: \(error.statusFields).")
    }
  }

  /// A probe fixture shaped like the REAL product: an app extension inside a
  /// containing app, with the engine artifacts staged in the containing app's
  /// `Frameworks` directory. That is the layout on both platforms, and it is
  /// the layout the tier-2 lookup bug lived in.
  ///
  /// A `.framework` artifact is created WITH A BINARY INSIDE. It previously was
  /// an empty directory, which passed the old loose probe and could never have
  /// been loaded — precisely the "probe says present, resolver says missing"
  /// contradiction this fixture should have been catching rather than
  /// modelling. The binary is a stub, not a Mach-O: these cases assert LOOKUP,
  /// and a resolved-but-unloadable image is a different (1004) failure.
  private static func makeTemporaryProbeBundle(artifacts: [String]) throws -> (Bundle, URL) {
    let fileManager = FileManager.default
    let rootURL = fileManager.temporaryDirectory
      .appendingPathComponent("WinsProbe-\(UUID().uuidString)", isDirectory: true)
    let appURL = rootURL.appendingPathComponent("Runner.app", isDirectory: true)
    let bundleURL = appURL
      .appendingPathComponent("PlugIns", isDirectory: true)
      .appendingPathComponent("PacketTunnel.appex", isDirectory: true)
    let frameworksURL = appURL.appendingPathComponent("Frameworks", isDirectory: true)
    try fileManager.createDirectory(at: bundleURL, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: frameworksURL, withIntermediateDirectories: true)
    let infoPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>CFBundleIdentifier</key>
      <string>org.winsvpn.probe.\(UUID().uuidString)</string>
      <key>CFBundlePackageType</key>
      <string>XPC!</string>
      <key>CFBundleVersion</key>
      <string>1</string>
    </dict>
    </plist>
    """
    try infoPlist.write(
      to: bundleURL.appendingPathComponent("Info.plist"),
      atomically: true,
      encoding: .utf8
    )

    for artifact in artifacts {
      if artifact.hasSuffix(".framework") {
        let frameworkURL = frameworksURL.appendingPathComponent(artifact, isDirectory: true)
        try fileManager.createDirectory(at: frameworkURL, withIntermediateDirectories: true)
        let binaryName = String(artifact.dropLast(".framework".count))
        try Data("stub".utf8).write(
          to: frameworkURL.appendingPathComponent(binaryName, isDirectory: false)
        )
      } else {
        try Data("stub".utf8).write(
          to: frameworksURL.appendingPathComponent(artifact, isDirectory: false)
        )
      }
    }

    guard let bundle = Bundle(url: bundleURL) else {
      throw HarnessError("Could not create temporary probe bundle at \(bundleURL.lastPathComponent).")
    }
    return (bundle, rootURL)
  }

  /// THE REGRESSION TEST FOR THE TIER-2 CONTRADICTION.
  ///
  /// A framework whose binary exists but carries no executable bit is exactly
  /// what an unlinked iOS appex sees for a framework staged in its containing
  /// app: `isExecutableFile` is `access(X_OK)`, a filesystem permission test
  /// that does not describe whether `dlopen` can load the image. Before the
  /// shared locator, the bundle probe reported such a component PRESENT and the
  /// runtime resolver threw 1003 "not bundled" for the same file.
  ///
  /// Both halves are asserted: the probe and the resolver must agree, and the
  /// resolution must actually happen rather than merely stop contradicting
  /// itself.
  private static func expectFrameworkWithoutExecutableBitStillResolves() throws {
    let fileManager = FileManager.default
    let (bundle, rootURL) = try makeTemporaryProbeBundle(
      artifacts: ["WinsAmneziaWGPacketEngine.framework", "WinsWinnPacketEngine.framework"]
    )
    defer { try? fileManager.removeItem(at: rootURL) }

    let frameworksURL = rootURL
      .appendingPathComponent("Runner.app", isDirectory: true)
      .appendingPathComponent("Frameworks", isDirectory: true)
    for name in ["WinsAmneziaWGPacketEngine", "WinsWinnPacketEngine"] {
      let binaryURL = frameworksURL
        .appendingPathComponent("\(name).framework", isDirectory: true)
        .appendingPathComponent(name, isDirectory: false)
      try fileManager.setAttributes(
        [.posixPermissions: NSNumber(value: 0o644)],
        ofItemAtPath: binaryURL.path
      )
      guard fileManager.fileExists(atPath: binaryURL.path),
            !fileManager.isExecutableFile(atPath: binaryURL.path) else {
        throw HarnessError(
          "Fixture did not produce a non-executable framework binary for \(name)."
        )
      }
    }

    let components = ["amneziawg_packet_engine", "winn_packet_engine"]
    for component in components {
      let resolution = WinsNativeEngineArtifactLocator.resolve(
        component: component,
        bundle: bundle,
        fileManager: fileManager
      )
      guard resolution.isResolved else {
        throw HarnessError(
          "Tier 2 failed to resolve \(component) whose binary exists without an "
            + "executable bit: \(resolution.diagnostics)."
        )
      }
      guard resolution.resolvedVia == "framework_existence" else {
        throw HarnessError(
          "Expected \(component) to resolve by existence, got \(resolution.resolvedVia)."
        )
      }
      let prefix = "engine_runtime_lookup_\(component)_"
      guard resolution.diagnostics["\(prefix)fw_dir_found"] as? Bool == true,
            resolution.diagnostics["\(prefix)bin_exists"] as? Bool == true,
            resolution.diagnostics["\(prefix)bin_readable"] as? Bool == true,
            resolution.diagnostics["\(prefix)bin_exec_bit"] as? Bool == false else {
        throw HarnessError(
          "Lookup diagnostics did not name the failing predicate for \(component): "
            + "\(resolution.diagnostics)."
        )
      }
    }

    let probe = WinsPacketTunnelEngineBundleProbe.probe(
      requiredComponents: components,
      bundle: bundle
    )
    guard probe.availableComponents == components,
          probe.missingComponents.isEmpty,
          probe.allRequiredComponentsPresent else {
      throw HarnessError(
        "Bundle probe disagreed with the resolver about a non-executable-bit "
          + "framework: \(probe.statusFields)."
      )
    }

    // AND THE CONVERSE, which is the half that makes them "agree" rather than
    // "both loose": a framework directory with NO binary inside resolves for
    // neither. The probe used to call that present.
    let (emptyBundle, emptyRootURL) = try makeTemporaryProbeBundle(artifacts: [])
    defer { try? fileManager.removeItem(at: emptyRootURL) }
    let emptyFrameworksURL = emptyRootURL
      .appendingPathComponent("Runner.app", isDirectory: true)
      .appendingPathComponent("Frameworks", isDirectory: true)
    try fileManager.createDirectory(
      at: emptyFrameworksURL.appendingPathComponent(
        "WinsWinnPacketEngine.framework",
        isDirectory: true
      ),
      withIntermediateDirectories: true
    )
    let emptyResolution = WinsNativeEngineArtifactLocator.resolve(
      component: "winn_packet_engine",
      bundle: emptyBundle,
      fileManager: fileManager
    )
    let emptyProbe = WinsPacketTunnelEngineBundleProbe.probe(
      requiredComponents: ["winn_packet_engine"],
      bundle: emptyBundle
    )
    guard !emptyResolution.isResolved,
          emptyProbe.missingComponents == ["winn_packet_engine"] else {
      throw HarnessError(
        "An empty .framework directory was treated as a loadable component: "
          + "resolved=\(emptyResolution.isResolved) probe=\(emptyProbe.statusFields)."
      )
    }
    guard emptyResolution.diagnostics[
      "engine_runtime_lookup_winn_packet_engine_fw_dir_found"
    ] as? Bool == true else {
      throw HarnessError("Empty-framework diagnostics did not record the directory.")
    }
  }

  private static func expectTunnelManagerIdentity() throws {
    let installed = WinsTunnelManagerIdentity.signature(
      shortVersion: "1.0.14",
      buildVersion: "29",
      location: "installed"
    )
    guard installed == "wins_vpn.apple_packet_tunnel.v3.1.0.14.29.installed" else {
      throw HarnessError("Apple tunnel manager identity was not version/build/location scoped: \(installed).")
    }
    let sanitized = WinsTunnelManagerIdentity.signature(
      shortVersion: " 1/2 ",
      buildVersion: nil,
      location: "development path"
    )
    guard sanitized == "wins_vpn.apple_packet_tunnel.v3.1-2.unknown.development-path",
          !sanitized.contains("/"),
          !sanitized.contains(" ") else {
      throw HarnessError("Apple tunnel manager identity did not sanitize dynamic components: \(sanitized).")
    }
  }

  // MARK: - DEV-ONLY host containment
  //
  // The regression these four cases exist for: on 2026-08-05 a macOS dev
  // session took the host's IPv4 default route, its IPv6 (to a sink) and all of
  // its DNS (empty match domain = every domain), then carried nothing, because
  // the winn/3 handshake does not complete on macOS yet. Total host blackout,
  // surviving the app being killed, cleared only by a reboot.

  /// Every config the app actually ships must be untouched by the containment
  /// marker: absent, therefore not requested, therefore full tunnel.
  private static func expectNoDevContainmentInOrdinaryConfigs() throws {
    for (name, rawConfig) in [
      ("direct", directConfig),
      ("xray", xrayConfig),
      ("winn", winnConfig),
      ("split", splitRouteConfig)
    ] {
      let config = WinsTunnelConfig.parse(rawConfig)
      guard !config.devContainmentRequested else {
        throw HarnessError("\(name) config unexpectedly requests dev containment.")
      }
      let plan = config.devContainmentPlan
      guard !plan.requested, !plan.usable, !plan.unusableTestRoute else {
        throw HarnessError("\(name) config produced an active containment plan.")
      }
    }
    // And the shipping full-tunnel posture is still exactly what it was.
    let shipping = try WinsTunnelConfig.parseAndValidate(directConfig)
    guard shipping.defaultIPv4RouteEnabled,
          shipping.ipv6LeakProtectionEnabled,
          shipping.fullTunnelDNSMatchEnabled,
          shipping.dnsMatchDomains == [""] else {
      throw HarnessError("Shipping full-tunnel leak protection changed.")
    }
  }

  /// A marker-carrying config still validates as full tunnel (the document must
  /// keep `0.0.0.0/0, ::/0` for codes 1203/1504), but its containment plan
  /// narrows every one of the three things that caused the blackout.
  private static func expectDevContainmentPlanNarrowsEverything() throws {
    let config = try WinsTunnelConfig.parseAndValidate(containedDevConfig)
    guard config.devContainmentRequested else {
      throw HarnessError("Contained dev config did not request containment.")
    }
    // The config still ASKS for full tunnel — that is the trap this guards.
    guard config.defaultIPv4RouteEnabled,
          config.ipv6LeakProtectionEnabled,
          config.fullTunnelDNSMatchEnabled else {
      throw HarnessError("Contained dev config no longer states full-tunnel intent.")
    }

    let plan = config.devContainmentPlan
    guard plan.requested, plan.usable, !plan.unusableTestRoute else {
      throw HarnessError("Contained dev config produced an unusable plan.")
    }
    // 1. One narrow route, derived from the interface address, never a default.
    guard let route = plan.testRoute else {
      throw HarnessError("Contained plan has no test route.")
    }
    guard route.prefixLength == 32,
          route.subnetMask == "255.255.255.255",
          route.destinationAddress == "10.8.0.1",
          !route.isDefaultRoute else {
      throw HarnessError("Contained plan test route is not the derived /32: \(route).")
    }
    // 2 and 3. No IPv6, no DNS, and the status says so out loud.
    let fields = plan.statusFields
    guard fields["dev_containment_active"] as? Bool == true,
          fields["dev_containment_kind"] as? String == "dev_narrow_route_no_ipv6_no_dns",
          fields["dev_containment_default_ipv4_route_installed"] as? Bool == false,
          fields["dev_containment_ipv6_settings_installed"] as? Bool == false,
          fields["dev_containment_dns_settings_installed"] as? Bool == false,
          fields["dev_containment_included_route_count"] as? Int == 1,
          fields["dev_containment_test_route_prefix_length"] as? Int == 32 else {
      throw HarnessError("Contained plan status fields do not describe containment: \(fields).")
    }
    // The gap between intent and reality is recorded, not hidden.
    guard fields["dev_containment_config_requested_default_route"] as? Bool == true,
          fields["dev_containment_config_requested_ipv6_leak_protection"] as? Bool == true,
          fields["dev_containment_config_requested_full_tunnel_dns"] as? Bool == true else {
      throw HarnessError("Contained plan did not record the config's full-tunnel intent.")
    }
    // The transport /32 exclusion still exists, so the outer socket stays off
    // the tunnel exactly as it does on the shipping path.
    guard plan.transportExclusionRoute != nil else {
      throw HarnessError("Contained plan lost the transport exclusion route.")
    }
  }

  /// The containment knob must never be usable to re-create the blackout. Any
  /// `TestRoute` broader than a /32 — above all a default route — yields no
  /// plan, which the provider turns into a refusal rather than a wide tunnel.
  private static func expectDevContainmentRefusesToWiden() throws {
    for widened in ["0.0.0.0/0", "10.8.0.0/16", "10.8.0.0/24", "0.0.0.0/1", "not-an-address"] {
      let raw = containedDevConfigWithTestRoute(widened)
      let config = try WinsTunnelConfig.parseAndValidate(raw)
      guard config.devContainmentRequested else {
        throw HarnessError("Widened contained config lost its marker.")
      }
      guard config.devContainmentTestRoute == nil else {
        throw HarnessError("Containment accepted a non-/32 test route: \(widened).")
      }
      let plan = config.devContainmentPlan
      guard !plan.usable, plan.unusableTestRoute else {
        throw HarnessError("Containment plan was usable for test route \(widened).")
      }
    }
    // An explicit /32 IS accepted, and is reported as explicit.
    let explicit = try WinsTunnelConfig.parseAndValidate(
      containedDevConfigWithTestRoute("10.8.0.9/32")
    )
    guard let route = explicit.devContainmentTestRoute,
          route.destinationAddress == "10.8.0.9",
          route.prefixLength == 32,
          explicit.devContainmentPlan.usable,
          explicit.devContainmentPlan.statusFields[
            "dev_containment_test_route_explicit"
          ] as? Bool == true else {
      throw HarnessError("Containment rejected a valid explicit /32 test route.")
    }
  }

  /// The field that keeps a contained run from being mistaken for a validated
  /// full-tunnel one. A contained session's CONFIG satisfies all eight
  /// full-tunnel terms, so without this the check would report a pass.
  private static func expectDevContainmentFailsLeakProtectionCheck() throws {
    let fullTunnelFields: [String: Any] = [
      "active": true,
      "provider_status_available": true,
      "provider_status_schema_supported": true,
      "provider_engine_ready": true,
      "provider_network_settings_applied": true,
      "provider_healthy": true,
      "provider_default_route_enabled": true,
      "provider_ipv6_leak_protection_enabled": true,
      "provider_engine_ipv6_leak_protection_enabled": true,
      "provider_dns_full_tunnel_match_enabled": true,
      "provider_engine_full_tunnel_dns_match_enabled": true,
      "provider_dns_count": 1,
      "provider_engine_dns_server_count": 1
    ]
    // Production, unchanged: no containment field present at all.
    let production = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(fullTunnelFields)
    guard production["leak_protection_config_passed"] as? Bool == true,
          production["leak_protection_dev_containment_active"] as? Bool == false else {
      throw HarnessError("Containment term changed the production leak-protection verdict.")
    }
    // An explicit false is identical to absent.
    var explicitlyNotContained = fullTunnelFields
    explicitlyNotContained["provider_dev_containment_active"] = false
    guard WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(
      explicitlyNotContained
    )["leak_protection_config_passed"] as? Bool == true else {
      throw HarnessError("An explicit not-contained flag changed the verdict.")
    }
    // Contained: every other term still true, verdict false.
    var contained = fullTunnelFields
    contained["provider_dev_containment_active"] = true
    let containedResult = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(contained)
    guard containedResult["leak_protection_config_passed"] as? Bool == false,
          containedResult["leak_protection_dev_containment_active"] as? Bool == true,
          containedResult["leak_protection_default_route_enabled"] as? Bool == true,
          containedResult["leak_protection_ipv6_enabled"] as? Bool == true else {
      throw HarnessError(
        "A contained session reported a passing full-tunnel leak-protection posture."
      )
    }
    // A contained run must not masquerade as a FAILING full-tunnel run either:
    // that reads like a real leak-protection regression and trains a developer
    // to ignore the one verdict that matters in production.
    guard containedResult["leak_protection_config_kind"] as? String
            == "dev_contained_not_full_tunnel",
          production["leak_protection_config_kind"] as? String
            == "full_tunnel_route_dns_ipv6" else {
      throw HarnessError(
        "Contained and full-tunnel sessions report the same leak-protection kind."
      )
    }
  }

  /// IPv4 route PARSING, on a document that requests no `::/0`.
  ///
  /// This deliberately uses the non-validating `parse`. It used to use
  /// `parseAndValidate`, and that was the assertion recording the residual gap:
  /// `validate()` required `::/0` only when the IPv4 default route was present,
  /// so this `::/0`-less split document was accepted, and a provider handed it
  /// would install no IPv6 settings at all. `validate()` now requires `::/0`
  /// unconditionally, so the document below is no longer a legal config — the
  /// rejection is asserted at the bottom of this function, at the exact site
  /// that used to assert acceptance.
  ///
  /// The parser-level assertions are kept verbatim on `parse` rather than being
  /// re-derived against a `::/0`-carrying fixture, for two reasons. First, none
  /// of them is about IPv6: they pin CIDR parsing, network-address masking and
  /// `isDefaultRoute`, and moving them to a different fixture would mean
  /// re-deriving expectations that currently cannot silently weaken. Second,
  /// `splitRouteWithIPv6DefaultRouteConfig` already carries `::/0` and already
  /// runs through `parseAndValidate`, so adding `::/0` here would have made this
  /// fixture a textual duplicate of that one while DELETING the only coverage
  /// that `ipv6LeakProtectionEnabled` is false when no IPv6 route is requested.
  /// That property still matters — it is what makes the gate below meaningful —
  /// so it is asserted here, on the only path that can still reach it.
  private static func expectSplitRoutes(_ rawConfig: String) throws {
    let config = WinsTunnelConfig.parse(rawConfig)
    let routes = config.allowedIPv4Routes
    guard routes.count == 2 else {
      throw HarnessError("Expected 2 split routes, got \(routes.count).")
    }
    guard routes[0].destinationAddress == "10.42.0.0",
          routes[0].subnetMask == "255.255.0.0",
          routes[0].prefixLength == 16,
          !routes[0].isDefaultRoute else {
      throw HarnessError("First split route parsed incorrectly.")
    }
    guard routes[1].destinationAddress == "172.16.5.0",
          routes[1].subnetMask == "255.255.255.0",
          routes[1].prefixLength == 24,
          !routes[1].isDefaultRoute else {
      throw HarnessError("Second split route parsed incorrectly.")
    }
    // `splitRouteConfig` carries NO `::/0` at all, so IPv6 leak protection is
    // off because the document requested no IPv6 route — NOT because the IPv4
    // routes are non-default. That distinction is the whole point of
    // `expectSplitTunnelWithIPv6DefaultRouteStillProtectsIPv6` below, which
    // covers the shape the app ACTUALLY ships.
    guard !config.allowedIPv6DefaultRouteEnabled else {
      throw HarnessError("splitRouteConfig should not request an IPv6 default route.")
    }
    guard !config.defaultIPv4RouteEnabled,
          !config.ipv6LeakProtectionEnabled,
          let exclusion = config.transportIPv4ExclusionRoute,
          exclusion.destinationAddress == "203.0.113.10",
          exclusion.subnetMask == "255.255.255.255",
          exclusion.prefixLength == 32 else {
      throw HarnessError("Split routes must retain the exact carrier /32 without enabling default routes.")
    }
    // RE-DERIVED. This used to assert `dnsMatchDomains.isEmpty`, which was the
    // DNS half of the same coupling: a split tunnel dropped the empty match
    // domain, the providers left `NEDNSSettings.matchDomains` nil, and every
    // unmatched query went to the PHYSICAL interface's resolver in the clear.
    // The empty match domain is now unconditional.
    guard config.dnsMatchDomains == [""],
          config.fullTunnelDNSMatchEnabled else {
      throw HarnessError(
        "DNS LEAK: split routes dropped the empty match domain, so queries would fall back to the "
          + "physical interface's resolver. Got \(config.dnsMatchDomains)."
      )
    }

    // THE FAIL-CLOSED GATE, asserted where acceptance used to be. A document
    // that never asks for `::/0` cannot be validated at all, so a provider can
    // never be handed one and silently leave `ipv6Settings` nil.
    try expectRejectedForMissingIPv6DefaultRoute("splitRouteConfig", rawConfig)
  }

  /// A config that requests no `::/0` must be refused with 1203, and the failure
  /// must say WHY — this is the assertion a future config-generator change will
  /// trip, and "expected 1203" alone would not tell that engineer what they
  /// broke.
  private static func expectRejectedForMissingIPv6DefaultRoute(
    _ name: String,
    _ rawConfig: String
  ) throws {
    do {
      _ = try WinsTunnelConfig.parseAndValidate(rawConfig)
      throw HarnessError(
        "IPv6 LEAK: \(name) was accepted without requesting ::/0. ipv6LeakProtectionEnabled would "
          + "be false, both providers would leave settings.ipv6Settings nil, and every IPv6 packet "
          + "would exit on the physical interface in the clear. validate() must require ::/0 "
          + "unconditionally — not only when the IPv4 default route is present."
      )
    } catch let error as WinsTunnelValidationError {
      guard error.code == 1203 else {
        throw HarnessError("\(name): expected validation error 1203, got \(error.code).")
      }
    }
  }

  /// REGRESSION GUARD: a split tunnel must not silently drop IPv6 leak
  /// protection.
  ///
  /// This is the shape `lib/main.dart` `_buildConfig` actually emits the moment
  /// a user types one bypass CIDR into "Destinations outside VPN (all operating
  /// systems)": `AllowedIPs = <IPv4 complement>, ::/0`. The IPv4 default route
  /// is gone; `::/0` is still there.
  ///
  /// It once made `ipv6LeakProtectionEnabled` false — because that property read
  /// `defaultIPv4RouteEnabled && allowedIPv6DefaultRouteEnabled` — so both
  /// providers left `settings.ipv6Settings` nil and every IPv6 packet left on the
  /// physical interface in the clear, while the engine was still handed
  /// `allowed_ip=::/0` and the app still reported protection.
  ///
  /// The invariant asserted here is the correct one: IPv6 capture follows the
  /// IPv6 route the document asks for, and nothing else.
  private static func expectSplitTunnelWithIPv6DefaultRouteStillProtectsIPv6() throws {
    let config = try WinsTunnelConfig.parseAndValidate(splitRouteWithIPv6DefaultRouteConfig)

    // Precondition: this really is a split tunnel that still asks for ::/0.
    guard !config.defaultIPv4RouteEnabled else {
      throw HarnessError("Split-tunnel IPv6 fixture unexpectedly kept the IPv4 default route.")
    }
    guard config.allowedIPv4Routes.count == 2,
          config.allowedIPv4Routes.allSatisfy({ !$0.isDefaultRoute }) else {
      throw HarnessError("Split-tunnel IPv6 fixture did not parse two non-default IPv4 routes.")
    }
    guard config.allowedIPv6DefaultRouteEnabled else {
      throw HarnessError("Split-tunnel IPv6 fixture lost its ::/0 route.")
    }

    // THE INVARIANT. Non-default IPv4 routes must not disable IPv6 capture.
    guard config.ipv6LeakProtectionEnabled else {
      throw HarnessError(
        "IPv6 LEAK: a split-tunnel config that requests ::/0 disabled IPv6 leak protection, "
          + "so the provider would leave ipv6Settings nil and all IPv6 would exit in the clear."
      )
    }
    guard config.ipv6SinkAddress == WinsTunnelConfig.ipv6SinkAddress,
          config.ipv6SinkPrefixLength == WinsTunnelConfig.ipv6SinkPrefixLength else {
      throw HarnessError("Split-tunnel IPv6 capture did not use the shared sink address.")
    }

    // And the full-tunnel POSTURE must still refuse to call this a full tunnel:
    // the leak-protection gate ANDs `default_route_enabled` in separately, so
    // widening IPv6 capture must not let a split session claim a passing
    // full-tunnel posture.
    let splitFields: [String: Any] = [
      "provider_status_available": true,
      "provider_status_current": true,
      "provider_default_route_enabled": config.defaultIPv4RouteEnabled,
      "provider_ipv6_leak_protection_enabled": config.ipv6LeakProtectionEnabled,
      "provider_engine_ipv6_leak_protection_enabled": config.ipv6LeakProtectionEnabled,
      "provider_dns_full_tunnel_match_enabled": config.fullTunnelDNSMatchEnabled,
      "provider_engine_full_tunnel_dns_match_enabled": config.fullTunnelDNSMatchEnabled,
      "provider_dns_count": config.dnsServers.count,
      "provider_engine_dns_server_count": config.dnsServers.count
    ]
    let leakFields = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(splitFields)
    // IPv6 capture is on ...
    guard leakFields["leak_protection_ipv6_enabled"] as? Bool == true,
          leakFields["leak_protection_engine_ipv6_enabled"] as? Bool == true else {
      throw HarnessError("Split-tunnel IPv6 capture did not reach the leak-protection fields.")
    }
    // ... and the session is still, correctly, not a full tunnel, for the
    // specific reason that the IPv4 default route is absent.
    guard leakFields["leak_protection_default_route_enabled"] as? Bool == false else {
      throw HarnessError("Split-tunnel session claimed a full-tunnel default route.")
    }
    guard leakFields["leak_protection_config_passed"] as? Bool == false else {
      throw HarnessError("A split-tunnel session reported a passing FULL-tunnel leak-protection posture.")
    }
  }

  /// The primary safety property, asserted directly rather than by implication:
  /// a full-tunnel document still enables IPv6 capture. Widening the split-tunnel
  /// case must never be paid for out of this one.
  private static func expectFullTunnelIPv6ProtectionUnchanged() throws {
    for (name, rawConfig) in [
      ("direct", directConfig),
      ("xray", xrayConfig),
      ("winn", winnConfig)
    ] {
      let config = try WinsTunnelConfig.parseAndValidate(rawConfig)
      guard config.defaultIPv4RouteEnabled,
            config.allowedIPv6DefaultRouteEnabled,
            config.ipv6LeakProtectionEnabled,
            config.fullTunnelDNSMatchEnabled else {
        throw HarnessError("\(name) full-tunnel leak protection regressed.")
      }
    }
  }

  /// FAIL-CLOSED: no document is valid unless it requests `::/0`.
  ///
  /// The residual half of the 2026-08-06 IPv6 leak. Fixing
  /// `ipv6LeakProtectionEnabled` made IPv6 capture follow the requested IPv6
  /// route honestly, which left exactly one way to lose it: hand the provider a
  /// document that never requested `::/0`. `validate()` used to permit that for
  /// any config without the IPv4 default route — i.e. for every split tunnel —
  /// so a future config generator could reintroduce the leak without tripping a
  /// single check. It now cannot: the document is refused before any provider
  /// sees it.
  ///
  /// Each case below is a shape that was ACCEPTED before this change.
  private static func expectValidateRequiresIPv6DefaultRoute() throws {
    let leakyShapes: [(String, String)] = [
      // The two harness fixtures that used to validate.
      ("split, two non-default routes", "10.42.0.0/16, 172.16.5.0/24"),
      ("split, un-normalized host bits", "10.42.3.7/16, 172.16.5.99/24, 192.0.2.44/32"),
      // One narrow route and nothing else — the minimal leaky document.
      ("single /32", "192.0.2.44/32"),
      // The shape a naive "exclude one LAN" generator would emit if it forgot
      // to append `::/0` — an IPv4 complement, no IPv6 at all.
      ("IPv4 complement without ::/0", "0.0.0.0/8, 128.0.0.0/1")
    ]
    for (name, allowedIPs) in leakyShapes {
      let rawConfig = directConfig.replacingOccurrences(
        of: "AllowedIPs = 0.0.0.0/0, ::/0",
        with: "AllowedIPs = \(allowedIPs)"
      )
      // Precondition: the shape really is IPv6-less, and the PARSER still says
      // so — the gate is what changed, not the parsing.
      let parsed = WinsTunnelConfig.parse(rawConfig)
      guard !parsed.allowedIPv6DefaultRouteEnabled, !parsed.ipv6LeakProtectionEnabled else {
        throw HarnessError("\(name): fixture unexpectedly requests an IPv6 default route.")
      }
      try expectRejectedForMissingIPv6DefaultRoute(name, rawConfig)
    }

    // The Windows per-app shape. `lib/split_tunnel_routes.dart`
    // `windowsPerAppAllowedIpCidrs` emits `::/1` + `8000::/1` instead of `::/0`,
    // and it is called from exactly one site behind `Platform.isWindows`
    // (`lib/main.dart:3752`); Windows consumes its config in
    // `windows/runner/windows_tunnel_backend.cpp` and never reaches this parser.
    // Asserted anyway: if that isolation is ever broken, the Apple side must
    // refuse the document rather than run it with no IPv6 capture.
    try expectRejectedForMissingIPv6DefaultRoute(
      "Windows ::/1 + 8000::/1 shape",
      windowsShapedAllowedIPsConfig
    )

    // And the change is a REJECTION only. The shape the app actually ships —
    // non-default IPv4 routes plus `::/0` — is still accepted, still a split
    // tunnel, and still protects IPv6.
    let shipping = try WinsTunnelConfig.parseAndValidate(splitRouteWithIPv6DefaultRouteConfig)
    guard !shipping.defaultIPv4RouteEnabled,
          shipping.allowedIPv6DefaultRouteEnabled,
          shipping.ipv6LeakProtectionEnabled else {
      throw HarnessError("The shipping split-tunnel shape stopped validating or stopped protecting IPv6.")
    }
  }

  /// REGRESSION GUARD: a split tunnel must not drop the empty DNS match domain.
  ///
  /// The DNS twin of the IPv6 route leak, and the same boolean coupling:
  /// `dnsMatchDomains` read `defaultIPv4RouteEnabled ? [""] : []`, so one IPv4
  /// bypass CIDR emptied it, both providers skipped the assignment
  /// (`if !config.dnsMatchDomains.isEmpty`), and `NEDNSSettings.matchDomains`
  /// was left nil.
  ///
  /// Nil is not "the tunnel resolver handles everything". Per `man 5 resolver`,
  /// an unmatched query falls to the DEFAULT client — the primary service's
  /// resolver — and a split tunnel is not the primary service precisely because
  /// it declines the default route. So every unmatched lookup went out on the
  /// physical interface in cleartext, naming each site to a state-controlled
  /// ISP before a single packet was sent.
  private static func expectSplitTunnelStillForcesFullDNSCapture() throws {
    // Every shape that can reach this parser, split and full alike.
    let shapes: [(String, String)] = [
      ("full tunnel", "0.0.0.0/0, ::/0"),
      ("split, two non-default routes", "10.42.0.0/16, 172.16.5.0/24, ::/0"),
      ("split, single /32", "192.0.2.44/32, ::/0"),
      ("split, IPv4 complement", "0.0.0.0/8, 128.0.0.0/1, ::/0")
    ]
    for (name, allowedIPs) in shapes {
      let rawConfig = directConfig.replacingOccurrences(
        of: "AllowedIPs = 0.0.0.0/0, ::/0",
        with: "AllowedIPs = \(allowedIPs)"
      )
      let config = try WinsTunnelConfig.parseAndValidate(rawConfig)
      guard config.dnsMatchDomains == [""], config.fullTunnelDNSMatchEnabled else {
        throw HarnessError(
          "DNS LEAK: \(name) produced matchDomains \(config.dnsMatchDomains) instead of [\"\"]. "
            + "The provider would leave NEDNSSettings.matchDomains nil and unmatched queries would "
            + "fall back to the physical interface's resolver in the clear."
        )
      }
      // The resolver the queries are being forced to must actually exist.
      guard !config.dnsServers.isEmpty else {
        throw HarnessError("\(name): forced full DNS capture with no resolver configured.")
      }
    }

    // HONESTY. Capturing DNS must not let a split tunnel claim a full-tunnel
    // posture. `fullTunnelDNSMatchEnabled` is now constant, so the route term is
    // the only thing left holding the verdict false — assert that it does.
    let split = try WinsTunnelConfig.parseAndValidate(splitRouteWithIPv6DefaultRouteConfig)
    let splitFields: [String: Any] = [
      "provider_status_available": true,
      "provider_status_current": true,
      "provider_default_route_enabled": split.defaultIPv4RouteEnabled,
      "provider_ipv6_leak_protection_enabled": split.ipv6LeakProtectionEnabled,
      "provider_engine_ipv6_leak_protection_enabled": split.ipv6LeakProtectionEnabled,
      "provider_dns_full_tunnel_match_enabled": split.fullTunnelDNSMatchEnabled,
      "provider_engine_full_tunnel_dns_match_enabled": split.fullTunnelDNSMatchEnabled,
      "provider_dns_count": split.dnsServers.count,
      "provider_engine_dns_server_count": split.dnsServers.count
    ]
    let leakFields = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(splitFields)
    guard leakFields["leak_protection_dns_full_tunnel_match_enabled"] as? Bool == true,
          leakFields["leak_protection_engine_dns_full_tunnel_match_enabled"] as? Bool == true else {
      throw HarnessError("Split-tunnel DNS capture did not reach the leak-protection fields.")
    }
    guard leakFields["leak_protection_default_route_enabled"] as? Bool == false else {
      throw HarnessError("Split-tunnel session claimed a full-tunnel default route.")
    }
    guard leakFields["leak_protection_config_passed"] as? Bool == false else {
      throw HarnessError(
        "A split-tunnel session reported a PASSING full-tunnel leak-protection posture. Forcing DNS "
          + "capture must not be readable as being a full tunnel."
      )
    }
    guard leakFields["leak_protection_config_kind"] as? String == "full_tunnel_route_dns_ipv6" else {
      throw HarnessError("Split-tunnel leak-protection kind changed unexpectedly.")
    }
  }

  private static func expectXrayIPv4TransportExclusion() throws {
    let rawConfig = xrayConfig
      .replacingOccurrences(of: "Host = sync.example.invalid", with: "Host = 198.51.100.22")
      .replacingOccurrences(of: "ServerName = sync.example.invalid", with: "ServerName = 198.51.100.22")
    let config = try WinsTunnelConfig.parseAndValidate(rawConfig)
    guard config.transportEndpointHost == "198.51.100.22" else {
      throw HarnessError("Xray IPv4 transport endpoint host was not selected.")
    }
    guard config.networkSettingsRemoteAddress == "198.51.100.22" else {
      throw HarnessError("Xray IPv4 Network Extension remote address was not selected.")
    }
    guard let exclusionRoute = config.transportIPv4ExclusionRoute,
          exclusionRoute.destinationAddress == "198.51.100.22",
          exclusionRoute.subnetMask == "255.255.255.255",
          exclusionRoute.prefixLength == 32 else {
      throw HarnessError("Expected Xray IPv4 transport exclusion route, got \(String(describing: config.transportIPv4ExclusionRoute)).")
    }
  }

  /// Winn Protocol carrier selection, and the exclusion route the whole design
  /// hangs on.
  ///
  /// Winn does not REPLACE AmneziaWG on Apple, it sits below it: AmneziaWG keeps
  /// the utun device and all of the cryptography and only its outer datagrams
  /// are diverted through a loopback seam. Two things follow, and both are
  /// checked here because getting either wrong is silent.
  ///
  ///  1. A Winn config must require BOTH engines, AmneziaWG first.
  ///  2. The transport /32 must follow `[winn] endpoint`, not the AmneziaWG peer
  ///     endpoint. That /32 is the only thing keeping the Winn engine's own
  ///     outer UDP socket off the tunnel it is carrying — Apple has no
  ///     `protect()` — and the peer endpoint is repointed at loopback at start,
  ///     so reading it would make the /32 vanish and the tunnel dead-loop.
  private static func expectWinnCarrierAndTransportExclusion() throws {
    let config = try WinsTunnelConfig.parseAndValidate(winnConfig)
    guard config.winnEnabled else {
      throw HarnessError("Winn config did not report winnEnabled.")
    }
    guard config.packetCarrierComponent == "amneziawg_packet_engine" else {
      throw HarnessError(
        "Winn replaced AmneziaWG as the packet carrier, got \(config.packetCarrierComponent)."
      )
    }
    guard config.requiredEngineComponents == ["amneziawg_packet_engine", "winn_packet_engine"] else {
      throw HarnessError(
        "Winn config required \(config.requiredEngineComponents), expected AmneziaWG then Winn."
      )
    }
    guard config.transportMode == "winn" else {
      throw HarnessError("Winn config reported transport mode \(config.transportMode).")
    }
    guard config.transportEndpointHost == "198.51.100.7" else {
      throw HarnessError(
        "Winn transport host was \(config.transportEndpointHost), expected the [winn] gateway."
      )
    }
    guard config.networkSettingsRemoteAddress == "198.51.100.7" else {
      throw HarnessError("Winn Network Extension remote address was not the Winn gateway.")
    }
    guard let exclusionRoute = config.transportIPv4ExclusionRoute,
          exclusionRoute.destinationAddress == "198.51.100.7",
          exclusionRoute.subnetMask == "255.255.255.255",
          exclusionRoute.prefixLength == 32 else {
      throw HarnessError(
        "Expected a /32 exclusion route for the Winn gateway, got \(String(describing: config.transportIPv4ExclusionRoute))."
      )
    }
    // An AmneziaWG-only config must be completely unaffected by all of the above.
    let plain = try WinsTunnelConfig.parseAndValidate(directConfig)
    guard plain.requiredEngineComponents == ["amneziawg_packet_engine"],
          plain.transportEndpointHost == "203.0.113.10",
          plain.transportMode == "amneziawg" else {
      throw HarnessError("An AmneziaWG-only config was changed by the Winn carrier wiring.")
    }
  }

  /// The one line that actually puts AmneziaWG's outer datagrams into the seam.
  ///
  /// A document that quietly kept the real gateway would produce a tunnel that
  /// is configured as Winn, reports itself as Winn, and is classical AmneziaWG
  /// on the wire, so anything other than exactly one rewrite must be refused
  /// rather than patched up.
  private static func expectWinnAmneziaWGUAPIRepoint() throws {
    let config = try WinsTunnelConfig.parseAndValidate(winnConfig)
    let uapi = try config.amneziaWGUAPIConfiguration()
    guard uapi.contains("endpoint=203.0.113.10:9110") else {
      throw HarnessError("The unrewritten UAPI did not name the real AmneziaWG gateway.")
    }
    guard let repointed = WinsTunnelConfig.amneziaWGUAPIConfiguration(
      uapi,
      rewritingEndpointTo: "127.0.0.1:65000"
    ) else {
      throw HarnessError("A well-formed UAPI document could not be repointed at the seam.")
    }
    guard repointed.contains("endpoint=127.0.0.1:65000"),
          !repointed.contains("203.0.113.10") else {
      throw HarnessError("The repointed UAPI did not replace the AmneziaWG endpoint.")
    }
    guard repointed.components(separatedBy: "\n").count
            == uapi.components(separatedBy: "\n").count,
          repointed.replacingOccurrences(
            of: "endpoint=127.0.0.1:65000",
            with: "endpoint=203.0.113.10:9110"
          ) == uapi else {
      throw HarnessError("Repointing the UAPI changed something other than the endpoint line.")
    }
    guard WinsTunnelConfig.amneziaWGUAPIConfiguration(
      "private_key=aa\n",
      rewritingEndpointTo: "127.0.0.1:1"
    ) == nil else {
      throw HarnessError("A UAPI document with no endpoint line was repointed instead of refused.")
    }
    guard WinsTunnelConfig.amneziaWGUAPIConfiguration(
      "endpoint=a:1\nendpoint=b:2\n",
      rewritingEndpointTo: "127.0.0.1:1"
    ) == nil else {
      throw HarnessError("A UAPI document with two endpoint lines was repointed instead of refused.")
    }
    guard WinsTunnelConfig.amneziaWGUAPIConfiguration(
      uapi,
      rewritingEndpointTo: "127.0.0.1"
    ) == nil else {
      throw HarnessError("A portless replacement endpoint was accepted.")
    }
  }

  /// An explicit `direct-awg` carrier, and an absent one, are both accepted:
  /// `lib/winn_protocol_dispatch.dart` now emits the key on every winn/3
  /// config, and a config written before it existed must keep working.
  private static func expectWinnDirectCarrierAccepted() throws {
    for raw in [winnConfig, winnConfig + "\nCarrier = direct-awg\n"] {
      let config = try WinsTunnelConfig.parseAndValidate(raw)
      guard config.winnEnabled,
            config.requiredEngineComponents == ["amneziawg_packet_engine", "winn_packet_engine"] else {
        throw HarnessError("A direct-awg Winn config was not accepted as a Winn config.")
      }
    }
    guard WinsTunnelConfig.supportedWinnCarrier == "direct-awg" else {
      throw HarnessError(
        "supportedWinnCarrier must equal WINS_WINN_SUPPORTED_CARRIER in WinsWinnPacketEngine.m."
      )
    }
  }

  /// `http3-connect-udp` is ACCEPTED by `validate()`, and this is not a
  /// relaxation of the carrier gate.
  ///
  /// It was refused while `WinnTunnelCreate` was the only C export: it takes a
  /// single config string, so an authenticated carrier's credentials had no way
  /// to reach Go, and accepting the name would have run plain `direct-awg` UDP
  /// underneath a config that said MASQUE — a downgrade of the TRANSPORT that
  /// no winn/3 version gate would have seen. `WinnTunnelCreateWithCarrier`
  /// (apple/EngineWrappers/WinnTunnel.h) now takes the carrier profile as a
  /// second C string, built by `WinsWinnCarrierProfile`, so the name is
  /// buildable and the refusal became stale rather than protective.
  ///
  /// What is deliberately NOT asserted here: that a carrier profile exists and
  /// is usable. That depends on this device's App Group container, not on the
  /// served config, so this INI validator cannot answer it. It is answered by
  /// `WinsPacketTunnelEngine.start()`, which fails the WHOLE start rather than
  /// falling back to direct-awg — proven in `runDowngradeTests()` and
  /// `runCarrierProfileTests()` in tools/verify_apple_winn_seam_harness.swift.
  /// So the downgrade the old assertion guarded against is still refused; it is
  /// refused one layer lower, where the question can actually be answered.
  private static func expectWinnHttp3CarrierAccepted() throws {
    guard WinsTunnelConfig.supportedWinnCarrierHttp3 == "http3-connect-udp" else {
      throw HarnessError(
        "supportedWinnCarrierHttp3 must equal WINS_WINN_SUPPORTED_CARRIER_HTTP3 in WinsWinnPacketEngine.m."
      )
    }
    // Case-insensitively, matching the carrier gate in WinsTunnelConfig.validate()
    // and the same pair asserted in verify_apple_winn_seam_harness.swift.
    for carrier in ["http3-connect-udp", "HTTP3-CONNECT-UDP"] {
      let config = try WinsTunnelConfig.parseAndValidate(
        winnConfig + "\nCarrier = \(carrier)\n"
      )
      guard config.winnEnabled else {
        throw HarnessError("An \(carrier) Winn config was not accepted as a Winn config.")
      }
      // Accepting the carrier must not disturb the seam wiring: AmneziaWG still
      // owns the tun, Winn is still additive, and the /32 must still follow the
      // `[winn]` gateway. If accepting http3 had quietly repointed any of these,
      // the tunnel would dead-loop rather than fail.
      guard config.packetCarrierComponent == "amneziawg_packet_engine",
            config.requiredEngineComponents == ["amneziawg_packet_engine", "winn_packet_engine"],
            config.transportMode == "winn" else {
        throw HarnessError(
          "An \(carrier) config changed the packet carrier wiring: \(config.requiredEngineComponents)."
        )
      }
      guard let exclusionRoute = config.transportIPv4ExclusionRoute,
            exclusionRoute.destinationAddress == "198.51.100.7",
            exclusionRoute.prefixLength == 32 else {
        throw HarnessError(
          "An \(carrier) config lost the /32 exclusion route for the Winn gateway."
        )
      }
    }
    // The carrier gate is still a gate: an unbuildable carrier is still refused,
    // so acceptance above is by name and not because the check stopped running.
    for carrier in ["http2-stream", "masque", "quic-datagram"] {
      try expectInvalid(winnConfig + "\nCarrier = \(carrier)\n", code: 1506)
    }
  }

  private static func expectPreTunnelTransportResolution() throws {
    let xrayConfig = try WinsTunnelConfig.parseAndValidate(Self.xrayConfig)
    let resolvedXray = try xrayConfig.resolvingFullTunnelTransportIPv4 { host in
      host == "sync.example.invalid" ? "198.51.100.44" : nil
    }
    guard resolvedXray.transportEndpointHost == "198.51.100.44",
          resolvedXray.transportEndpointKind == "ipv4",
          resolvedXray.xrayRuntimeConfig?.serverName == "sync.example.invalid",
          resolvedXray.peerEndpoint == xrayConfig.peerEndpoint,
          let xrayExclusion = resolvedXray.transportIPv4ExclusionRoute,
          xrayExclusion.destinationAddress == "198.51.100.44",
          xrayExclusion.prefixLength == 32 else {
      throw HarnessError("Pre-tunnel Xray hostname resolution did not pin the transport and /32 exclusion.")
    }

    let hostnameDirectConfig = directConfig.replacingOccurrences(
      of: "Endpoint = 203.0.113.10:9110",
      with: "Endpoint = edge.example.invalid:9110"
    )
    let direct = try WinsTunnelConfig.parseAndValidate(hostnameDirectConfig)
    let resolvedDirect = try direct.resolvingFullTunnelTransportIPv4 { host in
      host == "edge.example.invalid" ? "203.0.113.77" : nil
    }
    guard resolvedDirect.peerEndpoint == "203.0.113.77:9110",
          resolvedDirect.transportEndpointHost == "203.0.113.77",
          resolvedDirect.transportIPv4ExclusionRoute?.destinationAddress == "203.0.113.77" else {
      throw HarnessError("Pre-tunnel direct-AWG hostname resolution did not pin the peer endpoint.")
    }

    do {
      _ = try xrayConfig.resolvingFullTunnelTransportIPv4 { _ in nil }
      throw HarnessError("Full-tunnel hostname resolution unexpectedly accepted a missing address.")
    } catch let error as WinsTunnelValidationError where error.code == 1401 {
      // Expected: fail closed before the default route is installed.
    }

    // Split routes can still cover the outer carrier, even without 0.0.0.0/0.
    // Resolve before network settings and retain the exact carrier /32 so the
    // tunnel cannot capture its own transport. Keep the TLS name unchanged.
    let splitXrayConfig = try WinsTunnelConfig.parseAndValidate(
      Self.xrayConfig.replacingOccurrences(
        of: "AllowedIPs = 0.0.0.0/0, ::/0",
        with: "AllowedIPs = 10.42.0.0/16, 198.51.100.0/24, ::/0"
      )
    )
    guard !splitXrayConfig.defaultIPv4RouteEnabled,
          splitXrayConfig.transportEndpointKind == "hostname" else {
      throw HarnessError("Split-tunnel Xray fixture did not describe a hostname carrier without a default IPv4 route.")
    }
    let resolvedSplitXray = try splitXrayConfig.resolvingFullTunnelTransportIPv4 { host in
      host == "sync.example.invalid" ? "198.51.100.44" : nil
    }
    guard resolvedSplitXray.transportEndpointHost == "198.51.100.44",
          resolvedSplitXray.transportEndpointKind == "ipv4",
          resolvedSplitXray.xrayRuntimeConfig?.host == "198.51.100.44",
          resolvedSplitXray.xrayRuntimeConfig?.serverName == "sync.example.invalid",
          resolvedSplitXray.peerEndpoint == splitXrayConfig.peerEndpoint,
          resolvedSplitXray.sections["peer"] == splitXrayConfig.sections["peer"],
          !resolvedSplitXray.defaultIPv4RouteEnabled,
          resolvedSplitXray.ipv6LeakProtectionEnabled,
          resolvedSplitXray.dnsMatchDomains == [""],
          let exclusion = resolvedSplitXray.transportIPv4ExclusionRoute,
          exclusion.destinationAddress == "198.51.100.44",
          exclusion.subnetMask == "255.255.255.255",
          exclusion.prefixLength == 32 else {
      throw HarnessError("Split-tunnel Xray must resolve the carrier and retain its exact /32 without changing routes, TLS name, peer, or leak protection.")
    }
    for (answer, expectedCode) in [(nil as String?, 1401), ("not-an-ipv4", 1402)] {
      do {
        _ = try splitXrayConfig.resolvingFullTunnelTransportIPv4 { _ in answer }
        throw HarnessError("Split-tunnel hostname resolution accepted an invalid address.")
      } catch let error as WinsTunnelValidationError where error.code == expectedCode {
        // Fail closed before installing routes or DNS settings.
      }
    }
  }

  /// Host-bit normalization of `AllowedIPs` CIDRs. As in `expectSplitRoutes`,
  /// this fixture requests no `::/0`, so it is no longer a legal document and
  /// the assertions run on the non-validating `parse`; the rejection is
  /// asserted at the end, where acceptance used to be.
  private static func expectNormalizedAllowedIPv4Routes() throws {
    let rawConfig = directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 10.42.3.7/16, 172.16.5.99/24, 192.0.2.44/32"
    )
    let config = WinsTunnelConfig.parse(rawConfig)
    let routes = config.allowedIPv4Routes
    guard routes.count == 3 else {
      throw HarnessError("Expected 3 normalized routes, got \(routes.count).")
    }
    guard routes[0].destinationAddress == "10.42.0.0",
          routes[0].subnetMask == "255.255.0.0",
          routes[0].prefixLength == 16 else {
      throw HarnessError("First normalized route was wrong: \(routes[0]).")
    }
    guard routes[1].destinationAddress == "172.16.5.0",
          routes[1].subnetMask == "255.255.255.0",
          routes[1].prefixLength == 24 else {
      throw HarnessError("Second normalized route was wrong: \(routes[1]).")
    }
    guard routes[2].destinationAddress == "192.0.2.44",
          routes[2].subnetMask == "255.255.255.255",
          routes[2].prefixLength == 32 else {
      throw HarnessError("Third normalized route was wrong: \(routes[2]).")
    }
    // As in `expectSplitRoutes`: this fixture requests no `::/0`, so IPv6 leak
    // protection is off for want of an IPv6 route, not because the IPv4 routes
    // are non-default. Asserting the precondition keeps that reading honest — if
    // someone adds `::/0` to this fixture, the next guard must be re-derived
    // rather than silently re-pinning the leak.
    guard !config.allowedIPv6DefaultRouteEnabled else {
      throw HarnessError("Normalized split fixture should not request an IPv6 default route.")
    }
    guard !config.defaultIPv4RouteEnabled,
          !config.ipv6LeakProtectionEnabled,
          let exclusion = config.transportIPv4ExclusionRoute,
          exclusion.destinationAddress == "203.0.113.10",
          exclusion.subnetMask == "255.255.255.255",
          exclusion.prefixLength == 32 else {
      throw HarnessError("Normalized split routes must retain the exact carrier /32 without enabling default routes.")
    }
    guard config.dnsMatchDomains == [""],
          config.fullTunnelDNSMatchEnabled else {
      throw HarnessError(
        "DNS LEAK: normalized split routes dropped the empty match domain. Got \(config.dnsMatchDomains)."
      )
    }

    try expectRejectedForMissingIPv6DefaultRoute("normalized split fixture", rawConfig)
  }

  private static func expectInvalid(_ rawConfig: String, code: Int) throws {
    do {
      _ = try WinsTunnelConfig.parseAndValidate(rawConfig)
      throw HarnessError("Expected validation error \(code), but config was accepted.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == code else {
        throw HarnessError("Expected validation error \(code), got \(error.code).")
      }
    }
  }

  private static func expectRuntimeConfigSizeValidation() throws {
    try WinsTunnelConfig.validateRuntimeConfigSize(directConfig)

    let base = directConfig + "\n# "
    guard base.utf8.count <= WinsTunnelConfig.maxRuntimeConfigFileBytes else {
      throw HarnessError("Base direct config is larger than the runtime config ceiling.")
    }
    let exactLimitConfig = base + String(
      repeating: "a",
      count: WinsTunnelConfig.maxRuntimeConfigFileBytes - base.utf8.count
    )
    guard exactLimitConfig.utf8.count == WinsTunnelConfig.maxRuntimeConfigFileBytes else {
      throw HarnessError("Runtime config exact-limit fixture used the wrong byte count.")
    }
    _ = try WinsTunnelConfig.parseAndValidate(exactLimitConfig)

    let oversizedConfig = exactLimitConfig + "a"
    try expectInvalid(oversizedConfig, code: WinsTunnelConfig.runtimeConfigTooLargeCode)
  }

  private static func expectGeneratedClientKeyPair() throws {
    let keyPair = try WinsClientKeyStore.makeNewKeyPair()
    let derivedPublicKey = try WinsClientKeyStore.publicKeyBase64(
      privateKeyBase64: keyPair.privateKey
    )
    guard derivedPublicKey == keyPair.publicKey else {
      throw HarnessError("Generated client public key does not match the private key.")
    }
  }

  private static func expectInterfaceKeyPairValidation() throws {
    let matchingPair = try WinsClientKeyStore.makeNewKeyPair()
    let matchingConfig = directConfig.replacingOccurrences(
      of: "PrivateKey = \(key)",
      with: "PrivateKey = \(matchingPair.privateKey)"
    )
    let parsedConfig = try WinsTunnelConfig.parseAndValidate(matchingConfig)
    guard WinsTunnelConfig.validWireGuardPublicKey(matchingPair.publicKey),
          !WinsTunnelConfig.validWireGuardPublicKey("not-a-wireguard-key") else {
      throw HarnessError("Apple client public key validator accepted an invalid key.")
    }
    try parsedConfig.validateInterfacePrivateKeyMatches(matchingPair)
    try parsedConfig.validateInterfacePrivateKeyMatchesPublicKey(matchingPair.publicKey)

    var otherPair = try WinsClientKeyStore.makeNewKeyPair()
    while otherPair.publicKey == matchingPair.publicKey {
      otherPair = try WinsClientKeyStore.makeNewKeyPair()
    }
    do {
      try parsedConfig.validateInterfacePrivateKeyMatches(otherPair)
      throw HarnessError("Expected interface private key mismatch to be rejected.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == 1105 else {
        throw HarnessError("Expected validation error 1105, got \(error.code).")
      }
    }
    do {
      try parsedConfig.validateInterfacePrivateKeyMatchesPublicKey("not-a-wireguard-key")
      throw HarnessError("Expected invalid public key to be rejected.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == 1105 else {
        throw HarnessError("Expected validation error 1105, got \(error.code).")
      }
    }
  }

  private static func expectRedactedStorageConfig() throws {
    let redactedConfig = WinsTunnelConfig.redactedForStorage(directConfig)
    guard !redactedConfig.contains("PrivateKey = \(key)") else {
      throw HarnessError("Redacted storage config still contains the interface private-key line.")
    }
    guard redactedConfig.contains("PrivateKey = \(WinsTunnelConfig.redactedPrivateKeyPlaceholder)") else {
      throw HarnessError("Redacted storage config is missing the private-key placeholder.")
    }
    guard WinsTunnelConfig.containsRedactedPrivateKey(redactedConfig) else {
      throw HarnessError("Redacted storage config was not detected as redacted.")
    }
    let restoredConfig = WinsTunnelConfig.restoredRuntimeConfig(redactedConfig, privateKey: key)
    guard restoredConfig.contains("PrivateKey = \(key)") else {
      throw HarnessError("Restored runtime config did not replace the private-key placeholder.")
    }
    try expectValid(restoredConfig, endpoint: "203.0.113.10:9110", xrayEnabled: false)
    guard redactedConfig.contains("PublicKey = \(key)"),
          redactedConfig.contains("Endpoint = 203.0.113.10:9110") else {
      throw HarnessError("Redacted storage config removed non-secret peer settings.")
    }
    try expectInvalid(redactedConfig, code: 1101)
  }

  private static func expectGeneratedInstallIdentity() throws {
    let installId = try WinsInstallIdentityStore.makeNewInstallId()
    guard WinsInstallIdentityStore.validInstallId(installId) else {
      throw HarnessError("Generated install identity failed validation.")
    }
  }

  private static func expectAppGroupValidation() throws {
    let allowedFields = WinsAppleAppGroup.statusFields(
      rawIdentifier: WinsAppleAppGroup.identifier,
      containerAvailable: true
    )
    guard allowedFields["config_app_group_id_present"] as? Bool == true,
          allowedFields["config_app_group_id_allowed"] as? Bool == true,
          allowedFields["config_app_group_container_available"] as? Bool == true else {
      throw HarnessError("App Group validator did not accept the expected identifier.")
    }

    let missingFields = WinsAppleAppGroup.statusFields(
      rawIdentifier: nil,
      containerAvailable: true
    )
    guard missingFields["config_app_group_id_present"] as? Bool == false,
          missingFields["config_app_group_id_allowed"] as? Bool == false,
          missingFields["config_app_group_container_available"] as? Bool == false else {
      throw HarnessError("App Group validator accepted a missing identifier.")
    }

    let wrongFields = WinsAppleAppGroup.statusFields(
      rawIdentifier: " group.com.example.secret ",
      containerAvailable: true
    )
    guard wrongFields["config_app_group_id_present"] as? Bool == true,
          wrongFields["config_app_group_id_allowed"] as? Bool == false,
          wrongFields["config_app_group_container_available"] as? Bool == false else {
      throw HarnessError("App Group validator accepted an unexpected identifier.")
    }

    let fieldsDescription = String(describing: wrongFields)
    guard !fieldsDescription.contains("group.com.example.secret") else {
      throw HarnessError("App Group validator status fields leaked the supplied identifier.")
    }
  }

  private static func expectBoundedUTF8FileReader() throws {
    let fileManager = FileManager.default
    let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    defer {
      try? fileManager.removeItem(at: directory)
    }

    let configUrl = directory.appendingPathComponent("latest_tunnel.conf", isDirectory: false)
    try directConfig.write(to: configUrl, atomically: true, encoding: .utf8)
    let configResult = try WinsBoundedUTF8FileReader.read(
      url: configUrl,
      maxBytes: directConfig.utf8.count
    )
    guard configResult.text == directConfig,
          configResult.byteCount == directConfig.utf8.count else {
      throw HarnessError("Bounded UTF-8 reader did not preserve valid config contents.")
    }

    let oversizedUrl = directory.appendingPathComponent("oversized.conf", isDirectory: false)
    try Data(repeating: 0x61, count: 17).write(to: oversizedUrl)
    do {
      _ = try WinsBoundedUTF8FileReader.read(url: oversizedUrl, maxBytes: 16)
      throw HarnessError("Bounded UTF-8 reader accepted an oversized file.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == WinsBoundedUTF8FileReader.fileTooLargeCode else {
        throw HarnessError("Oversized file used the wrong error code: \(error.code).")
      }
    }

    let invalidUtf8Url = directory.appendingPathComponent("invalid-utf8.conf", isDirectory: false)
    try Data([0xff, 0xfe, 0xfd]).write(to: invalidUtf8Url)
    do {
      _ = try WinsBoundedUTF8FileReader.read(url: invalidUtf8Url, maxBytes: 16)
      throw HarnessError("Bounded UTF-8 reader accepted invalid UTF-8.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == WinsBoundedUTF8FileReader.invalidUTF8Code else {
        throw HarnessError("Invalid UTF-8 used the wrong error code: \(error.code).")
      }
    }

    let missingUrl = directory.appendingPathComponent("missing.conf", isDirectory: false)
    do {
      _ = try WinsBoundedUTF8FileReader.read(url: missingUrl, maxBytes: 16)
      throw HarnessError("Bounded UTF-8 reader accepted a missing file.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == WinsBoundedUTF8FileReader.fileUnreadableCode else {
        throw HarnessError("Missing file used the wrong error code: \(error.code).")
      }
    }

    let symlinkUrl = directory.appendingPathComponent("linked.conf", isDirectory: false)
    try fileManager.createSymbolicLink(at: symlinkUrl, withDestinationURL: configUrl)
    do {
      _ = try WinsBoundedUTF8FileReader.read(
        url: symlinkUrl,
        maxBytes: WinsTunnelConfig.maxRuntimeConfigFileBytes
      )
      throw HarnessError("Bounded UTF-8 reader accepted a symbolic link.")
    } catch let error as WinsTunnelValidationError {
      guard error.code == WinsBoundedUTF8FileReader.symbolicLinkCode else {
        throw HarnessError("Symbolic link used the wrong error code: \(error.code).")
      }
    }
  }

  private static func expectAppGroupFileWriter() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let outsideDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: outsideDirectory, withIntermediateDirectories: true)
    defer {
      try? fileManager.removeItem(at: root)
      try? fileManager.removeItem(at: outsideDirectory)
    }

    let handoffDirectory = root.appendingPathComponent("Tunnel", isDirectory: true)
    try fileManager.createSymbolicLink(at: handoffDirectory, withDestinationURL: outsideDirectory)
    let statusUrl = handoffDirectory.appendingPathComponent("latest_status.json", isDirectory: false)
    try WinsAppGroupFileWriter.writeData(Data(#"{"ok":true}"#.utf8), to: statusUrl)

    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: handoffDirectory.path, isDirectory: &isDirectory),
          isDirectory.boolValue,
          (try? fileManager.destinationOfSymbolicLink(atPath: handoffDirectory.path)) == nil else {
      throw HarnessError("App Group writer did not replace a symbolic-link handoff directory.")
    }
    guard !fileManager.fileExists(
      atPath: outsideDirectory.appendingPathComponent("latest_status.json").path
    ) else {
      throw HarnessError("App Group writer followed a symbolic-link handoff directory.")
    }
    let statusContents = try String(contentsOf: statusUrl, encoding: .utf8)
    guard statusContents == #"{"ok":true}"# else {
      throw HarnessError("App Group writer did not write status data into the safe directory.")
    }

    let outsideFile = outsideDirectory.appendingPathComponent("outside-target.txt", isDirectory: false)
    try "do-not-touch".write(to: outsideFile, atomically: true, encoding: .utf8)
    let configUrl = handoffDirectory.appendingPathComponent("latest_tunnel.conf", isDirectory: false)
    try fileManager.createSymbolicLink(at: configUrl, withDestinationURL: outsideFile)
    try WinsAppGroupFileWriter.writeString("safe-config", to: configUrl)

    guard (try? fileManager.destinationOfSymbolicLink(atPath: configUrl.path)) == nil else {
      throw HarnessError("App Group writer did not replace a symbolic-link handoff file.")
    }
    let configContents = try String(contentsOf: configUrl, encoding: .utf8)
    let outsideContents = try String(contentsOf: outsideFile, encoding: .utf8)
    guard configContents == "safe-config",
          outsideContents == "do-not-touch" else {
      throw HarnessError("App Group writer followed a symbolic-link handoff file.")
    }

    let attributes = try fileManager.attributesOfItem(atPath: configUrl.path)
    let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
    guard mode & 0o777 == 0o600 else {
      throw HarnessError("App Group writer did not apply private file permissions.")
    }
    // B-APP-003: the writer no longer treats backup exclusion as best-effort
    // (it throws hardeningFailedCode when it cannot be set), so a successful
    // write must carry the exclusion.
    let excluded = try configUrl.resourceValues(forKeys: [.isExcludedFromBackupKey])
      .isExcludedFromBackup
    guard excluded == true else {
      throw HarnessError("App Group writer did not exclude the handoff file from backups.")
    }

    // F-05 (final audit 2026-08-28): the writer hardens a temporary file and
    // publishes it atomically, so (a) a successful write leaves no temporary
    // litter, (b) a write over an EXISTING published file keeps the hardened
    // metadata (replaceItemAt with .usingNewMetadataOnly -- the default
    // options would copy the replaced item's metadata over the new one), and
    // (c) a failed write leaves the previously published file byte-identical
    // and removes every intermediate.
    let litterAfterFirstWrite = try fileManager.contentsOfDirectory(atPath: handoffDirectory.path)
      .filter { $0.hasPrefix(".latest_tunnel.conf.tmp-") }
    guard litterAfterFirstWrite.isEmpty else {
      throw HarnessError(
        "App Group writer left temporary files behind: \(litterAfterFirstWrite)."
      )
    }

    try WinsAppGroupFileWriter.writeString("safe-config-2", to: configUrl)
    guard try String(contentsOf: configUrl, encoding: .utf8) == "safe-config-2" else {
      throw HarnessError("App Group writer did not replace an existing published file.")
    }
    let replacedAttributes = try fileManager.attributesOfItem(atPath: configUrl.path)
    let replacedMode = (replacedAttributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
    guard replacedMode & 0o777 == 0o600 else {
      throw HarnessError(
        "App Group writer lost private permissions across the atomic replace."
      )
    }
    let replacedExcluded = try configUrl.resourceValues(forKeys: [.isExcludedFromBackupKey])
      .isExcludedFromBackup
    guard replacedExcluded == true else {
      throw HarnessError(
        "App Group writer lost backup exclusion across the atomic replace."
      )
    }

    // Failure path: a read-only handoff directory makes the temporary write
    // fail. The previously published file must survive byte-identical, and no
    // intermediate may remain.
    try fileManager.setAttributes([.posixPermissions: 0o500], ofItemAtPath: handoffDirectory.path)
    var writeFailure: Error?
    do {
      try WinsAppGroupFileWriter.writeString("must-not-publish", to: configUrl)
    } catch {
      writeFailure = error
    }
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: handoffDirectory.path)
    guard writeFailure != nil else {
      throw HarnessError("App Group writer accepted a write into a read-only directory.")
    }
    guard try String(contentsOf: configUrl, encoding: .utf8) == "safe-config-2" else {
      throw HarnessError(
        "App Group writer replaced the published file when its own write failed."
      )
    }
    let litterAfterFailure = try fileManager.contentsOfDirectory(atPath: handoffDirectory.path)
      .filter { $0.hasPrefix(".latest_tunnel.conf.tmp-") }
    guard litterAfterFailure.isEmpty else {
      throw HarnessError(
        "App Group writer left a temporary file behind after a failed write: \(litterAfterFailure)."
      )
    }
  }

  /// The duress purge of the App Group container, checked against a REAL
  /// directory rather than against the delete call.
  ///
  /// This exists because the container was, until 2026-08-07, reached by no
  /// deletion path on any platform: the duress sweep in `lib/main.dart` can
  /// only enumerate the directory `getAppDocumentsDirectory` returns (the
  /// app's own `Application Support/wins_vpn`), no Flutter plugin is
  /// registered on either Apple platform that could reach further, no method
  /// channel exposed the container, and neither provider ever deletes. A
  /// seized device kept `Tunnel/latest_tunnel.conf` -- gateway endpoint,
  /// gateway public key, this device's own client public key and the whole
  /// AmneziaWG obfuscation parameter set, in plaintext -- through a wipe the
  /// user believed had cleared it.
  ///
  /// Three cases, and the last two matter as much as the first: a purge that
  /// cannot report its own failure is indistinguishable from one that never
  /// runs.
  private static func expectAppGroupDuressPurge() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let outsideDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: outsideDirectory, withIntermediateDirectories: true)
    defer {
      try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
      try? fileManager.removeItem(at: root)
      try? fileManager.removeItem(at: outsideDirectory)
    }

    // CASE 1 — a populated container, shaped like a real one: the handoff
    // documents the host writes, the credential directory
    // `WinsWinnCarrierProfile` resolves in-container, a system Library
    // subtree, the container-manager metadata that must SURVIVE, and a
    // symbolic link pointing out of the container that must be unlinked
    // rather than followed.
    let tunnelDirectory = root.appendingPathComponent("Tunnel", isDirectory: true)
    let credentialDirectory = WinsWinnCarrierProfile.credentialDirectoryComponents
      .reduce(root) { $0.appendingPathComponent($1, isDirectory: true) }
    let libraryDirectory = root.appendingPathComponent("Library/Caches", isDirectory: true)
    for directory in [tunnelDirectory, credentialDirectory, libraryDirectory] {
      try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    for name in ["latest_tunnel.conf", "latest_tunnel.json", "latest_status.json"] {
      try "handoff".write(
        to: tunnelDirectory.appendingPathComponent(name),
        atomically: true,
        encoding: .utf8
      )
    }
    for (name, _) in WinsWinnCarrierProfile.CredentialSet.requiredFiles {
      try "credential".write(
        to: credentialDirectory.appendingPathComponent(name),
        atomically: true,
        encoding: .utf8
      )
    }
    try "credential".write(
      to: credentialDirectory
        .appendingPathComponent(WinsWinnCarrierProfileKeys.spaKeyCredentialFileName),
      atomically: true,
      encoding: .utf8
    )
    try "cache".write(
      to: libraryDirectory.appendingPathComponent("provider.cache"),
      atomically: true,
      encoding: .utf8
    )
    let metadataName = ".com.apple.containermanagerd.metadata.plist"
    try "metadata".write(
      to: root.appendingPathComponent(metadataName),
      atomically: true,
      encoding: .utf8
    )
    let outsideFile = outsideDirectory.appendingPathComponent("precious.txt")
    try "do-not-touch".write(to: outsideFile, atomically: true, encoding: .utf8)
    try fileManager.createSymbolicLink(
      at: root.appendingPathComponent("outward_link"),
      withDestinationURL: outsideFile
    )

    let report = WinsAppGroupDuressPurge.purge(containerURL: root, fileManager: fileManager)
    guard report.containerAvailable, report.remainingObserved, report.complete else {
      throw HarnessError("App Group duress purge did not report a complete purge.")
    }
    // The assertion that matters is against the FILESYSTEM, not the report.
    let survivors = try fileManager.contentsOfDirectory(atPath: root.path).sorted()
    guard survivors == [metadataName] else {
      throw HarnessError(
        "App Group duress purge left \(survivors.count) entries behind; only the "
          + "container-manager metadata may survive."
      )
    }
    guard try String(contentsOf: outsideFile, encoding: .utf8) == "do-not-touch" else {
      throw HarnessError("App Group duress purge followed a symbolic link out of the container.")
    }

    // CASE 2 — the guard must be able to FIRE. A container whose entries
    // cannot be unlinked has not been cleared, and a purge that reported
    // success here would be one more delete nobody ever watched delete.
    try fileManager.createDirectory(
      at: root.appendingPathComponent("Tunnel", isDirectory: true),
      withIntermediateDirectories: true
    )
    try fileManager.setAttributes([.posixPermissions: 0o500], ofItemAtPath: root.path)
    let blocked = WinsAppGroupDuressPurge.purge(containerURL: root, fileManager: fileManager)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    guard !blocked.complete,
          blocked.failedRelativePaths == ["Tunnel"],
          blocked.remainingRelativePaths == ["Tunnel"] else {
      throw HarnessError("App Group duress purge reported success over a blocked removal.")
    }

    // CASE 3 — a container that is not there was not cleared. Absence must
    // never be reported as an empty container, which is the same
    // silent-absence defect in its purest form.
    let missing = WinsAppGroupDuressPurge.purge(
      containerURL: root.appendingPathComponent(UUID().uuidString, isDirectory: true),
      fileManager: fileManager
    )
    guard !missing.containerAvailable, !missing.remainingObserved, !missing.complete else {
      throw HarnessError("App Group duress purge reported success for a missing container.")
    }

    // The status document that crosses the method channel must name files
    // relatively and never leak the container's absolute path.
    let fieldsDescription = String(describing: report.statusFields)
    guard !fieldsDescription.contains(root.path),
          !fieldsDescription.lowercased().contains("group containers") else {
      throw HarnessError("App Group duress purge status fields leaked a container path.")
    }
  }

  // MARK: - Keychain duress purge
  //
  // These cases run against the REAL Keychain on the machine executing the
  // harness, because a delete that was never observed to delete is the whole
  // defect class this path exists to close. They are confined to scratch
  // service names carrying a fresh UUID -- never `org.winsvpn.client-keypair`,
  // `org.winsvpn.tunnel-secrets`, `org.winsvpn.install-identity` or
  // `org.winsvpn.app.secure-state` -- so nothing this app or any other app
  // actually stores can be reached. Everything written is swept in `defer`,
  // including on failure.
  //
  // On macOS an UNSIGNED harness binary can use the legacy file keychain but
  // is refused the Data Protection Keychain (`errSecMissingEntitlement`,
  // -34018). That refusal is not a limitation to work around -- it is the
  // blocked case, delivered by the real Keychain rather than a mock.

  private static func scratchKeychainService() -> String {
    "org.winsvpn.harness-scratch.\(UUID().uuidString)"
  }

  private static let harnessFileKeychainScope = WinsKeychainQueryScope(
    useDataProtectionKeychain: false,
    accessGroup: nil
  )

  /// Adds one scratch item directly, bypassing the app's stores, so the purge
  /// is exercised against real Keychain rows rather than against itself.
  private static func addScratchKeychainItem(service: String, account: String) throws {
    let status = SecItemAdd([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
      kSecValueData as String: Data("scratch".utf8)
    ] as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw HarnessError(
        "Could not seed a scratch Keychain item (status \(status)); the Keychain "
          + "purge cases cannot be trusted without one."
      )
    }
  }

  /// An INDEPENDENT look at the store, not the purge's own re-read. This is
  /// what makes the assertion evidence rather than a restatement of the report.
  private static func scratchKeychainAccountCount(service: String) -> (observed: Bool, count: Int) {
    var item: CFTypeRef?
    let status = SecItemCopyMatching([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnAttributes as String: kCFBooleanTrue as Any
    ] as CFDictionary, &item)
    if status == errSecItemNotFound { return (true, 0) }
    guard status == errSecSuccess else { return (false, 0) }
    return (true, (item as? [[String: Any]])?.count ?? 0)
  }

  private static func removeScratchKeychainService(_ service: String) {
    for _ in 0..<WinsKeychainDuressPurge.maxDeletePasses {
      let status = SecItemDelete([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrSynchronizable as String: kSecAttrSynchronizableAny
      ] as CFDictionary)
      if status != errSecSuccess { return }
    }
  }

  private static func expectKeychainDuressPurge() throws {
    let purgedService = scratchKeychainService()
    let absentService = scratchKeychainService()
    let blockedService = scratchKeychainService()
    let keepService = scratchKeychainService()
    let scratchServices = [purgedService, absentService, blockedService, keepService]
    defer { scratchServices.forEach(removeScratchKeychainService) }

    // CASE A -- material present, then observed gone.
    //
    // FOUR accounts, not one, and that number is load-bearing. Observed on a
    // real macOS Keychain on 2026-08-07: `SecItemDelete` over a
    // service-scoped query removes ONE matching item per call. A one-shot
    // delete passes a single-item test and silently leaves three of four
    // client keys behind on an install that has switched accounts -- exactly
    // the shape of survivor this whole audit is about.
    let purgedAccounts = [
      "wireguard-x25519-v2",
      "wireguard-x25519-v3:alpha",
      "wireguard-x25519-v3:beta",
      "wireguard-x25519-v3:gamma"
    ]
    for account in purgedAccounts {
      try addScratchKeychainItem(service: purgedService, account: account)
    }
    let seeded = scratchKeychainAccountCount(service: purgedService)
    guard seeded.observed, seeded.count == purgedAccounts.count else {
      throw HarnessError("Scratch Keychain seeding did not take; purge cases cannot run.")
    }

    let purged = WinsKeychainDuressPurge.purge(
      target: WinsKeychainPurgeTarget(label: "scratch-purged", service: purgedService),
      scopes: [harnessFileKeychainScope]
    )
    guard purged.complete,
          purged.status == "purged",
          purged.itemsBefore == purgedAccounts.count,
          purged.itemsRemaining == 0,
          !purged.blocked else {
      throw HarnessError(
        "Keychain duress purge did not report a complete purge over \(purgedAccounts.count) "
          + "seeded items (status \(purged.status), before \(purged.itemsBefore), "
          + "remaining \(purged.itemsRemaining))."
      )
    }
    // THE ASSERTION THAT MATTERS: an independent query, not the report.
    let afterPurge = scratchKeychainAccountCount(service: purgedService)
    guard afterPurge.observed, afterPurge.count == 0 else {
      throw HarnessError(
        "Keychain duress purge reported success while \(afterPurge.count) items remained."
      )
    }

    // CASE B -- refused, and reported as refused rather than as success.
    //
    // A REAL Keychain refusal, not a mock: an access group this binary holds
    // no entitlement for makes `SecItemCopyMatching` itself return
    // `errSecMissingEntitlement` (-34018). The store's contents behind that
    // scope are therefore UNKNOWN, and unknown must never read as clean --
    // which is the point, because the item really could be sitting in an
    // access group the purge failed to reach. This is the Keychain's version
    // of the chmod-0500 container case above.
    //
    // The seeded item is deliberately reachable through the OTHER scope, so
    // the purge partly succeeds. A report that let a successful scope paper
    // over a refused one would be the exact defect.
    try addScratchKeychainItem(service: blockedService, account: "wireguard-x25519-v2")
    // Data Protection Keychain, because that is the one that ENFORCES access
    // groups on macOS -- the legacy file keychain ignores the attribute
    // outright, which is the same asymmetry `WinsClientKeyStore`'s migration
    // path documents at its `isRunningInAppExtension` guard.
    let unreachableGroupScope = WinsKeychainQueryScope(
      useDataProtectionKeychain: true,
      accessGroup: "ZZZZZZZZZZ.org.winsvpn.harness-unentitled"
    )
    let blocked = WinsKeychainDuressPurge.purge(
      target: WinsKeychainPurgeTarget(label: "scratch-blocked", service: blockedService),
      scopes: [harnessFileKeychainScope, unreachableGroupScope]
    )
    guard blocked.blocked, !blocked.complete, blocked.status == "blocked" else {
      throw HarnessError(
        "Keychain duress purge reported \(blocked.status) over a Keychain scope it "
          + "was refused; an unreadable store must never read as a cleared one."
      )
    }
    guard !blocked.observedBefore, !blocked.observedAfter else {
      throw HarnessError(
        "Keychain duress purge claimed to have observed a scope the Keychain refused."
      )
    }
    // ...and the scope it COULD reach was still swept. A refusal on one scope
    // must not abort the others; a wipe that stops at the first refusal leaves
    // more behind than one that keeps going and reports what it could not do.
    let blockedSurvivors = scratchKeychainAccountCount(service: blockedService)
    guard blockedSurvivors.observed, blockedSurvivors.count == 0 else {
      throw HarnessError(
        "A refused Keychain scope aborted the sweep of a reachable one."
      )
    }

    // The two remaining ways a store is blocked are a refused DELETE and items
    // still present on the re-read. Neither can be staged from an unsigned
    // harness against a real Keychain (they need a locked keychain or a
    // hostile item ACL), so the classification itself is pinned here: whatever
    // produces them, they are never `complete`.
    let deleteRefused = WinsKeychainStorePurgeOutcome(
      label: "scratch-delete-refused",
      observedBefore: true,
      itemsBefore: 2,
      deleteFailed: true,
      observedAfter: true,
      itemsRemaining: 0
    )
    let survivorsRemain = WinsKeychainStorePurgeOutcome(
      label: "scratch-survivors",
      observedBefore: true,
      itemsBefore: 2,
      deleteFailed: false,
      observedAfter: true,
      itemsRemaining: 1
    )
    guard deleteRefused.blocked, !deleteRefused.complete, deleteRefused.status == "blocked",
          survivorsRemain.blocked, !survivorsRemain.complete,
          survivorsRemain.status == "blocked" else {
      throw HarnessError(
        "A refused delete or a surviving item is not being classified as a blocked purge."
      )
    }
    guard !WinsKeychainPurgeReport(outcomes: [purged, survivorsRemain]).complete else {
      throw HarnessError("One blocked store did not make the whole Keychain purge incomplete.")
    }

    // CASE C -- a service that was never written must NOT report complete.
    //
    // This is the case that caught the App Group lane's own first draft, and
    // it bites harder here. A directory can be listed; a Keychain can only be
    // asked, and `errSecItemNotFound` is the identical answer to "empty" and
    // to "your query names the wrong service, the wrong access group, or the
    // wrong one of macOS's two keychains". Nothing-found is therefore evidence
    // about the QUERY, not about the key -- so it reports `absent`, which is
    // neither success nor failure, and `complete` stays false.
    let absent = WinsKeychainDuressPurge.purge(
      target: WinsKeychainPurgeTarget(label: "scratch-absent", service: absentService),
      scopes: [harnessFileKeychainScope]
    )
    guard !absent.complete, absent.status == "absent", absent.absent, !absent.blocked,
          absent.observedBefore, absent.observedAfter,
          absent.itemsBefore == 0, absent.itemsRemaining == 0 else {
      throw HarnessError(
        "Keychain duress purge reported \(absent.status) for a service that never held "
          + "anything; absence must not stand in for a completed purge."
      )
    }
    guard absent.status != blocked.status else {
      throw HarnessError(
        "Keychain duress purge cannot distinguish an empty store from an unreadable one."
      )
    }

    // CASE D -- the one record that must SURVIVE.
    //
    // `vpn_settings.txt` carries the queued duress dispatch. A sweep that took
    // it would destroy the only copy of an undelivered call for help while
    // reporting a clean wipe.
    for account in ["user_pin.txt", "vpn_settings.txt", "pending_logout.json"] {
      try addScratchKeychainItem(service: keepService, account: account)
    }
    let kept = WinsKeychainDuressPurge.purge(
      target: WinsKeychainPurgeTarget(
        label: "scratch-kept",
        service: keepService,
        keptAccounts: ["vpn_settings.txt"]
      ),
      scopes: [harnessFileKeychainScope]
    )
    guard kept.complete, kept.itemsBefore == 2, kept.itemsRemaining == 0 else {
      throw HarnessError(
        "Keychain duress purge did not clear the sweepable records beside a kept one."
      )
    }
    let keepSurvivors = scratchKeychainAccountCount(service: keepService)
    guard keepSurvivors.observed, keepSurvivors.count == 1 else {
      throw HarnessError(
        "Keychain duress purge left \(keepSurvivors.count) records where exactly the "
          + "queued duress dispatch should have survived."
      )
    }

    // The production target list, and what it may never carry into a log.
    let targets = WinsKeychainDuressPurge.targets(preserveEmergencyQueue: true)
    let services = Set(targets.map(\.service))
    guard services == [
      "org.winsvpn.client-keypair",
      "org.winsvpn.tunnel-secrets",
      "org.winsvpn.install-identity",
      "org.winsvpn.app.secure-state"
    ] else {
      throw HarnessError("The Keychain duress purge target set changed without review.")
    }
    guard targets.first(where: { $0.service == "org.winsvpn.app.secure-state" })?
      .keptAccounts == ["vpn_settings.txt"] else {
      throw HarnessError("The queued duress dispatch is no longer kept by the Keychain purge.")
    }
    guard WinsKeychainDuressPurge.targets(preserveEmergencyQueue: false)
      .allSatisfy({ $0.keptAccounts.isEmpty }) else {
      throw HarnessError("The Keychain purge kept a record with no queued dispatch to protect.")
    }
    // Scoped deletes are for logout; duress names the SERVICE and nothing else,
    // so an account the user switched away from cannot outlive the wipe.
    guard targets.allSatisfy({ $0.label.rangeOfCharacter(from: .whitespaces) == nil }) else {
      throw HarnessError("Keychain purge labels must stay single tokens for the report.")
    }

    // The report crosses a method channel and can reach a debug log. It may
    // carry counts and fixed labels; it may never carry an account, which for
    // the client key store embeds the account scope token itself.
    let fieldsDescription = String(describing: purged.label) + " "
      + String(
        describing: WinsKeychainPurgeReport(outcomes: [purged, absent, kept]).statusFields
      )
    for leaked in purgedAccounts + ["vpn_settings.txt", "user_pin.txt", purgedService] {
      guard !fieldsDescription.contains(leaked) else {
        throw HarnessError("Keychain duress purge status fields leaked an account or service name.")
      }
    }
  }

  private static func expectSharedConfigPathGuard() throws {
    let fileManager = FileManager.default
    let containerUrl = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try fileManager.createDirectory(at: containerUrl, withIntermediateDirectories: true)
    defer {
      try? fileManager.removeItem(at: containerUrl)
    }

    let expectedUrl = WinsSharedConfigPathGuard.expectedConfigURL(
      containerURL: containerUrl,
      directoryName: "Tunnel",
      fileName: "latest_tunnel.conf"
    )
    let allowed = WinsSharedConfigPathGuard.validateSharedConfigPath(
      expectedUrl.path,
      containerURL: containerUrl,
      directoryName: "Tunnel",
      fileName: "latest_tunnel.conf"
    )
    guard allowed.url?.path == expectedUrl.path,
          allowed.statusFields["config_shared_path_present"] as? Bool == true,
          allowed.statusFields["config_shared_path_allowed"] as? Bool == true,
          allowed.statusFields["config_shared_path_matches_expected"] as? Bool == true,
          allowed.statusFields["config_shared_path_inside_app_group"] as? Bool == true else {
      throw HarnessError("Shared config path guard rejected the exact App Group handoff path.")
    }

    let normalizedPath = "\(containerUrl.path)/Tunnel/../Tunnel/latest_tunnel.conf"
    let normalized = WinsSharedConfigPathGuard.validateSharedConfigPath(
      normalizedPath,
      containerURL: containerUrl,
      directoryName: "Tunnel",
      fileName: "latest_tunnel.conf"
    )
    guard normalized.url?.path == expectedUrl.path,
          normalized.statusFields["config_shared_path_allowed"] as? Bool == true else {
      throw HarnessError("Shared config path guard rejected a normalized App Group handoff path.")
    }

    let missing = WinsSharedConfigPathGuard.validateSharedConfigPath(
      nil,
      containerURL: containerUrl,
      directoryName: "Tunnel",
      fileName: "latest_tunnel.conf"
    )
    guard missing.url == nil,
          missing.statusFields["config_shared_path_present"] as? Bool == false,
          missing.statusFields["config_shared_path_allowed"] as? Bool == false else {
      throw HarnessError("Shared config path guard accepted a missing path.")
    }

    let wrongFile = WinsSharedConfigPathGuard.validateSharedConfigPath(
      containerUrl.appendingPathComponent("Tunnel/other.conf").path,
      containerURL: containerUrl,
      directoryName: "Tunnel",
      fileName: "latest_tunnel.conf"
    )
    guard wrongFile.url == nil,
          wrongFile.statusFields["config_shared_path_inside_app_group"] as? Bool == true,
          wrongFile.statusFields["config_shared_path_matches_expected"] as? Bool == false,
          wrongFile.statusFields["config_shared_path_allowed"] as? Bool == false else {
      throw HarnessError("Shared config path guard accepted a wrong App Group file.")
    }

    let outside = WinsSharedConfigPathGuard.validateSharedConfigPath(
      "/Users/winsvpn/.ssh/id_rsa",
      containerURL: containerUrl,
      directoryName: "Tunnel",
      fileName: "latest_tunnel.conf"
    )
    guard outside.url == nil,
          outside.statusFields["config_shared_path_inside_app_group"] as? Bool == false,
          outside.statusFields["config_shared_path_matches_expected"] as? Bool == false,
          outside.statusFields["config_shared_path_allowed"] as? Bool == false else {
      throw HarnessError("Shared config path guard accepted a path outside the App Group container.")
    }

    let fieldsDescription = String(describing: outside.statusFields)
    guard !fieldsDescription.contains("/Users/"),
          !fieldsDescription.contains("id_rsa"),
          !fieldsDescription.contains("latest_tunnel.conf"),
          !fieldsDescription.contains(containerUrl.path) else {
      throw HarnessError("Shared config path guard status fields leaked a raw filesystem path.")
    }
  }

  private static func expectProviderErrorRedaction() throws {
    let controlledError = NSError(
      domain: "org.winsvpn.PacketTunnel",
      code: 1002,
      userInfo: [NSLocalizedDescriptionKey: "Incomplete packet tunnel network settings."]
    )
    let controlledMessage = WinsTunnelDiagnostics.redactedProviderErrorMessage(controlledError)
    guard controlledMessage == "Incomplete packet tunnel network settings." else {
      throw HarnessError("Controlled Win's VPN provider error was unexpectedly redacted: \(controlledMessage).")
    }

    let unsafeControlledError = NSError(
      domain: "org.winsvpn.PacketTunnel",
      code: 1999,
      userInfo: [
        NSLocalizedDescriptionKey:
          "Provider rejected Endpoint = 203.0.113.10:9110 from /Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_tunnel.conf."
      ]
    )
    let unsafeControlledProviderMessage =
      WinsTunnelDiagnostics.redactedProviderErrorMessage(unsafeControlledError)
    guard unsafeControlledProviderMessage == WinsTunnelDiagnostics.redactedSystemErrorMessage else {
      throw HarnessError("Unsafe controlled provider error was not redacted: \(unsafeControlledProviderMessage).")
    }
    let unsafeControlledHostMessage =
      WinsTunnelDiagnostics.redactedAppleErrorMessage(unsafeControlledError)
    guard unsafeControlledHostMessage == WinsTunnelDiagnostics.redactedAppleSystemErrorMessage else {
      throw HarnessError("Unsafe controlled host error was not redacted: \(unsafeControlledHostMessage).")
    }
    for rawFragment in [
      "/Users/",
      "Group Containers",
      "latest_tunnel.conf",
      "Endpoint =",
      "203.0.113.10"
    ] {
      guard !unsafeControlledProviderMessage.contains(rawFragment),
            !unsafeControlledHostMessage.contains(rawFragment) else {
        throw HarnessError("Redacted controlled native error leaked raw fragment: \(rawFragment).")
      }
    }

    for unsafeMessage in [
      "Provider rejected hostname stream.winsvpn.org during probe.",
      "Provider rejected UUID 00000000-0000-0000-0000-000000000000.",
      "Provider rejected IPv6 address 2001:db8::1.",
      "Provider rejected file URL file:///Users/winsvpn/latest_tunnel.conf.",
      "Provider rejected control character \u{0007}.",
      String(repeating: "A", count: WinsTunnelDiagnostics.maxControlledErrorMessageLength + 1)
    ] {
      let unsafeError = NSError(
        domain: "org.winsvpn.PacketTunnel",
        code: 1998,
        userInfo: [NSLocalizedDescriptionKey: unsafeMessage]
      )
      let providerMessage = WinsTunnelDiagnostics.redactedProviderErrorMessage(unsafeError)
      let hostMessage = WinsTunnelDiagnostics.redactedAppleErrorMessage(unsafeError)
      guard providerMessage == WinsTunnelDiagnostics.redactedSystemErrorMessage,
            hostMessage == WinsTunnelDiagnostics.redactedAppleSystemErrorMessage else {
        throw HarnessError("Unsafe controlled native error was not redacted: \(unsafeMessage).")
      }
      let redactedFields = WinsTunnelDiagnostics.redactedAppleErrorFields(unsafeError)
      guard redactedFields["native_error_domain"] as? String == "org.winsvpn.PacketTunnel",
            redactedFields["native_error_code"] as? Int == 1998,
            redactedFields["error"] as? String == WinsTunnelDiagnostics.redactedAppleSystemErrorMessage else {
        throw HarnessError("Redacted host error fields lost safe structured details: \(redactedFields).")
      }
      let fieldsDescription = String(describing: redactedFields)
      for rawFragment in [
        "stream.winsvpn.org",
        "00000000-0000-0000-0000-000000000000",
        "2001:db8::1",
        "file://",
        "latest_tunnel.conf"
      ] where fieldsDescription.contains(rawFragment) {
        throw HarnessError("Redacted host error fields leaked unsafe fragment: \(rawFragment).")
      }
    }

    let systemError = NSError(
      domain: NSCocoaErrorDomain,
      code: NSFileReadNoSuchFileError,
      userInfo: [
        NSLocalizedDescriptionKey:
          "The file /Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_tunnel.conf could not be read."
      ]
    )
    let redactedMessage = WinsTunnelDiagnostics.redactedProviderErrorMessage(systemError)
    guard redactedMessage == WinsTunnelDiagnostics.redactedSystemErrorMessage else {
      throw HarnessError("System provider error was not reduced to the stable redacted message: \(redactedMessage).")
    }
    guard !redactedMessage.contains("/Users/"),
          !redactedMessage.contains("latest_tunnel.conf"),
          !redactedMessage.contains("Group Containers") else {
      throw HarnessError("Redacted system provider error still contains local file details.")
    }

    let hostMessage = WinsTunnelDiagnostics.redactedAppleErrorMessage(systemError)
    guard hostMessage == WinsTunnelDiagnostics.redactedAppleSystemErrorMessage else {
      throw HarnessError("System host error was not reduced to the stable Apple redacted message: \(hostMessage).")
    }
    guard !hostMessage.contains("/Users/"),
          !hostMessage.contains("latest_tunnel.conf"),
          !hostMessage.contains("Group Containers") else {
      throw HarnessError("Redacted system host error still contains local file details.")
    }
  }

  private static func expectProviderStatusPayload(
    _ rawConfig: String,
    xrayEnabled: Bool
  ) throws {
    let config = try WinsTunnelConfig.parseAndValidate(rawConfig)
    let engineStatus = WinsPacketTunnelEnginePlan(config: config).statusFields
    let systemError = NSError(
      domain: NSCocoaErrorDomain,
      code: NSFileReadNoSuchFileError,
      userInfo: [
        NSLocalizedDescriptionKey:
          "The file /Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_tunnel.conf could not be read."
      ]
    )
    var extra = engineStatus
    extra["status_generation"] = "current-generation"
    let payload = WinsPacketTunnelProviderStatus.payload(
      stage: "engine_missing",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      config: config,
      engineReady: false,
      networkSettingsReady: true,
      error: systemError,
      extra: extra,
      fallbackStatusGeneration: "fallback-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )

    guard payload["status_schema_version"] as? Int == WinsPacketTunnelProviderStatus.schemaVersion,
          payload["stage"] as? String == "engine_missing",
          payload["healthy"] as? Bool == false,
          payload["engine_ready"] as? Bool == false,
          payload["network_settings_ready"] as? Bool == true,
          payload["provider_bundle_id"] as? String == "org.winsvpn.app.PacketTunnel",
          payload["network_extension_type"] as? String == WinsPacketTunnelProviderStatus.networkExtensionType,
          payload["status_generation"] as? String == "current-generation",
          payload["peer_endpoint_present"] as? Bool == true,
          payload["peer_endpoint_kind"] as? String == (xrayEnabled ? "loopback" : "ipv4"),
          payload["transport_endpoint_kind"] as? String == (xrayEnabled ? "hostname" : "ipv4"),
          payload["interface_ipv4_address_present"] as? Bool == true,
          payload["route_count"] as? Int == 1,
          payload["default_route_enabled"] as? Bool == true,
          payload["ipv6_leak_protection_enabled"] as? Bool == true,
          payload["ipv6_sink_address_present"] as? Bool == true,
          payload["ipv6_sink_prefix_length"] as? Int == 128,
          payload["dns_count"] as? Int == 1,
          payload["dns_full_tunnel_match_enabled"] as? Bool == true,
          payload["transport_mode"] as? String == (xrayEnabled ? "xray_vless_ws_amneziawg" : "amneziawg"),
          payload["required_engine_components"] as? [String] == config.requiredEngineComponents,
          payload["engine_launch_descriptor_schema_version"] as? Int == WinsPacketTunnelEngineLaunchDescriptor.schemaVersion,
          payload["engine_launch_descriptor_ready"] as? Bool == true,
          payload["engine_launch_descriptor_secret_material_redacted"] as? Bool == true,
          payload["engine_launch_descriptor_config_source"] as? String == "validated_wins_tunnel_config",
          payload["engine_interface_private_key_present"] as? Bool == true,
          payload["engine_interface_private_key_redacted"] as? Bool == true,
          payload["engine_peer_public_key_present"] as? Bool == true,
          payload["engine_peer_public_key_redacted"] as? Bool == true,
          payload["engine_peer_preshared_key_present"] as? Bool == false,
          payload["engine_peer_preshared_key_redacted"] as? Bool == true,
          payload["engine_peer_keepalive_present"] as? Bool == true,
          payload["engine_awg_obfuscation_field_count"] as? Int == 11,
          payload["engine_awg_uapi_config_ready"] as? Bool == true,
          payload["engine_awg_uapi_secret_material_redacted"] as? Bool == true,
          payload["engine_bundle_probe_schema_version"] as? Int == WinsPacketTunnelEngineBundleProbe.schemaVersion,
          payload["engine_bundle_required_components"] as? [String] == config.requiredEngineComponents,
          payload["engine_bundle_available_components"] as? [String] == [],
          payload["engine_bundle_missing_components"] as? [String] == config.requiredEngineComponents,
          payload["engine_bundle_required_component_count"] as? Int == config.requiredEngineComponents.count,
          payload["engine_bundle_available_component_count"] as? Int == 0,
          payload["engine_bundle_missing_component_count"] as? Int == config.requiredEngineComponents.count,
          payload["engine_bundle_all_required_components_present"] as? Bool == false,
          payload["engine_launch_contract_version"] as? Int == WinsPacketTunnelEnginePlan.launchContractVersion,
          payload["engine_packet_flow_required"] as? Bool == true,
          payload["engine_packet_flow_available"] as? Bool == false,
          payload["engine_ipv6_leak_protection_enabled"] as? Bool == true,
          payload["engine_ipv6_sink_prefix_length"] as? Int == 128,
          payload["engine_xray_transport_required"] as? Bool == xrayEnabled,
          payload["error_domain"] as? String == NSCocoaErrorDomain,
          payload["error_code"] as? Int == NSFileReadNoSuchFileError,
          payload["error_message"] as? String == WinsTunnelDiagnostics.redactedSystemErrorMessage else {
      throw HarnessError("Provider status payload was incomplete: \(payload).")
    }
    if xrayEnabled {
      guard payload["xray_host_present"] as? Bool == true,
            payload["xray_server_name_present"] as? Bool == true,
            payload["xray_path_present"] as? Bool == true,
            payload["xray_security"] as? String == "tls",
            payload["xray_local_port_present"] as? Bool == true,
            payload["xray_remote_awg_loopback"] as? Bool == true,
            payload["xray_remote_awg_port_present"] as? Bool == true,
            payload["engine_xray_uuid_present"] as? Bool == true,
            payload["engine_xray_uuid_redacted"] as? Bool == true,
            payload["engine_xray_host_redacted"] as? Bool == true,
            payload["engine_xray_server_name_redacted"] as? Bool == true,
            payload["engine_xray_path_redacted"] as? Bool == true,
            payload["engine_xray_remote_port_present"] as? Bool == true else {
        throw HarnessError("Provider status Xray fields were incomplete: \(payload).")
      }
    }

    let fallbackPayload = WinsPacketTunnelProviderStatus.payload(
      stage: "stopped",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      extra: [:],
      fallbackStatusGeneration: "fallback-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard fallbackPayload["status_generation"] as? String == "fallback-generation" else {
      throw HarnessError("Provider status did not apply fallback status generation: \(fallbackPayload).")
    }

    let payloadDescription = String(describing: payload)
    for rawFragment in [
      key,
      "203.0.113.10",
      "sync.example.invalid",
      "00000000-0000-0000-0000-000000000000",
      "/wins-stealth-tunnel",
      "42110",
      "9110",
      WinsTunnelConfig.ipv6SinkAddress,
      "/Users/",
      "latest_tunnel.conf",
      "Group Containers"
    ] where payloadDescription.contains(rawFragment) {
      throw HarnessError("Provider status payload leaked raw runtime fragment: \(rawFragment).")
    }
  }

  private static func expectProviderStatusWritableDataLimit() throws {
    let config = try WinsTunnelConfig.parseAndValidate(directConfig)
    let oversizedStatusValue = String(
      repeating: "safe-diagnostic-value",
      count: WinsPacketTunnelProviderStatus.maxStatusFileBytes
    )
    let systemError = NSError(
      domain: NSCocoaErrorDomain,
      code: NSFileWriteOutOfSpaceError,
      userInfo: [
        NSLocalizedDescriptionKey:
          "The file /Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json could not be written."
      ]
    )
    let data = try WinsPacketTunnelProviderStatus.writableData(
      stage: "app_message",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      config: config,
      engineReady: true,
      networkSettingsReady: true,
      error: systemError,
      extra: [
        "status_generation": "limited-generation",
        "config_source": "app_group_fallback",
        "config_file_symbolic_link": true,
        "config_shared_path_present": true,
        "config_shared_path_allowed": true,
        "config_shared_path_matches_expected": true,
        "config_shared_path_inside_app_group": true,
        "app_message_command": "health",
        "app_message_bytes": NSNumber(value: 42.5),
        "stop_reason": NSNumber(value: 2),
        "app_message_raw_payload_redacted": true,
        "unsafe_large_debug_blob": oversizedStatusValue
      ],
      fallbackStatusGeneration: "fallback-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard data.count <= WinsPacketTunnelProviderStatus.maxStatusFileBytes else {
      throw HarnessError("Writable provider status exceeded host read ceiling: \(data.count).")
    }
    guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          payload["status_schema_version"] as? Int == WinsPacketTunnelProviderStatus.schemaVersion,
          payload["stage"] as? String == "app_message",
          payload["status_write_limited"] as? Bool == true,
          payload["status_write_payload_too_large"] as? Bool == true,
          payload["status_write_original_stage"] as? String == "app_message",
          payload["status_generation"] as? String == "limited-generation",
          payload["config_source"] as? String == "app_group_fallback",
          payload["config_file_symbolic_link"] as? Bool == true,
          payload["config_shared_path_present"] as? Bool == true,
          payload["config_shared_path_allowed"] as? Bool == true,
          payload["config_shared_path_matches_expected"] as? Bool == true,
          payload["config_shared_path_inside_app_group"] as? Bool == true,
          payload["app_message_command"] as? String == "health",
          payload["app_message_bytes"] == nil,
          payload["stop_reason"] as? Int == 2,
          payload["app_message_raw_payload_redacted"] as? Bool == true,
          payload["error_message"] as? String == WinsTunnelDiagnostics.redactedSystemErrorMessage else {
      throw HarnessError("Compact writable provider status was incomplete.")
    }

    let payloadDescription = String(describing: payload)
    for rawFragment in [
      oversizedStatusValue,
      "/Users/",
      "Group Containers",
      "latest_status.json",
      "203.0.113.10",
      key
    ] where payloadDescription.contains(rawFragment) {
      throw HarnessError("Compact writable provider status leaked raw fragment: \(rawFragment.prefix(64)).")
    }
  }

  /// The release outcome must be readable from the status document on its own
  /// terms: a rejection has to be distinguishable from a deadline expiry, and
  /// the rejecting error's real domain and code have to be present. The
  /// 2026-08-06 contained session failed exactly here — the provider logged
  /// "See provider_error_domain and provider_error_code" and wrote neither.
  private static func expectNetworkSettingsReleaseStatusFields() throws {
    let released = WinsNetworkSettingsRelease.statusFields(
      outcome: .released,
      elapsedMilliseconds: 4,
      deadlineMilliseconds: 2000
    )
    guard released["network_settings_release_requested"] as? Bool == true,
          released["network_settings_release_outcome"] as? String == "released",
          released["network_settings_release_completed"] as? Bool == true,
          released["network_settings_release_failed"] as? Bool == false,
          released["network_settings_release_elapsed_ms"] as? Int == 4,
          released["network_settings_release_deadline_ms"] as? Int == 2000,
          released["network_settings_release_error_domain"] == nil,
          released["network_settings_release_error_code"] == nil else {
      throw HarnessError("Successful network settings release reported the wrong status fields.")
    }

    // The observed macOS teardown error, verbatim: nesessionmanager answers a
    // clear-configuration request from a session in NESMVPNSessionStateStopping
    // with NSError(domain: NEAgentErrorDomain, code: 1, userInfo: nil).
    let rejected = WinsNetworkSettingsRelease.statusFields(
      outcome: .failed,
      error: NSError(domain: "NEAgentErrorDomain", code: 1, userInfo: nil),
      elapsedMilliseconds: 10,
      deadlineMilliseconds: 2000
    )
    guard rejected["network_settings_release_outcome"] as? String == "failed",
          rejected["network_settings_release_completed"] as? Bool == true,
          rejected["network_settings_release_failed"] as? Bool == true,
          rejected["network_settings_release_error_domain"] as? String == "NEAgentErrorDomain",
          rejected["network_settings_release_error_code"] as? Int == 1,
          rejected["network_settings_release_elapsed_ms"] as? Int == 10 else {
      throw HarnessError("Rejected network settings release did not record the failing error identity.")
    }

    // A deadline expiry is NOT a rejection. Nothing is known about whether the
    // release would have succeeded, so it must not carry an error identity and
    // must not claim the settings were released.
    let expired = WinsNetworkSettingsRelease.statusFields(
      outcome: .deadline,
      elapsedMilliseconds: 2000,
      deadlineMilliseconds: 2000
    )
    guard expired["network_settings_release_outcome"] as? String == "deadline",
          expired["network_settings_release_completed"] as? Bool == false,
          expired["network_settings_release_failed"] as? Bool == false,
          expired["network_settings_release_requested"] as? Bool == true,
          expired["network_settings_release_error_domain"] == nil,
          expired["network_settings_release_error_code"] == nil else {
      throw HarnessError("Deadline-expired network settings release was reported as a rejection.")
    }

    // A monotonic clock read that runs backwards must not produce a negative
    // duration, and an absurd error domain must not become an unbounded string.
    let bounded = WinsNetworkSettingsRelease.statusFields(
      outcome: .failed,
      error: NSError(
        domain: String(repeating: "D", count: 4096),
        code: -1,
        userInfo: nil
      ),
      elapsedMilliseconds: -5,
      deadlineMilliseconds: -1
    )
    guard bounded["network_settings_release_elapsed_ms"] as? Int == 0,
          bounded["network_settings_release_deadline_ms"] as? Int == 0,
          bounded["network_settings_release_error_code"] as? Int == -1,
          let boundedDomain = bounded["network_settings_release_error_domain"] as? String,
          boundedDomain.count == WinsNetworkSettingsRelease.maxErrorDomainLength else {
      throw HarnessError("Network settings release fields were not bounded.")
    }

    let emptyDomain = WinsNetworkSettingsRelease.statusFields(
      outcome: .failed,
      error: NSError(domain: "   ", code: 7, userInfo: nil),
      elapsedMilliseconds: 1,
      deadlineMilliseconds: 2000
    )
    guard emptyDomain["network_settings_release_error_domain"] as? String
      == WinsNetworkSettingsRelease.unknownErrorDomain else {
      throw HarnessError("Blank release error domain was not replaced with a readable fallback.")
    }
  }

  /// A stop is the write most likely to be compacted — it carries the whole
  /// `previous_*_before_stop` set plus the seam counters. If the release fields
  /// were dropped there, the one document a reader consults after a teardown
  /// would be silent about the teardown, which is the failure this whole change
  /// exists to remove.
  private static func expectNetworkSettingsReleaseFieldsSurviveCompaction() throws {
    let releaseError = NSError(domain: "NEAgentErrorDomain", code: 1, userInfo: nil)
    var extra: [String: Any] = [
      "status_generation": "release-generation",
      "stop_reason": 1,
      "engine_was_running_before_stop": true,
      // Forces the compacted write: the full payload cannot fit.
      "unsafe_large_debug_blob": String(
        repeating: "safe-diagnostic-value",
        count: WinsPacketTunnelProviderStatus.maxStatusFileBytes
      )
    ]
    extra.merge(
      WinsNetworkSettingsRelease.statusFields(
        outcome: .failed,
        error: releaseError,
        elapsedMilliseconds: 10,
        deadlineMilliseconds: 2000
      )
    ) { _, new in new }

    let data = try WinsPacketTunnelProviderStatus.writableData(
      stage: "stopped",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: false,
      networkSettingsReady: false,
      error: releaseError,
      extra: extra,
      fallbackStatusGeneration: "fallback-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard data.count <= WinsPacketTunnelProviderStatus.maxStatusFileBytes,
          let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw HarnessError("Compacted stop status was unreadable or over the host read ceiling.")
    }
    guard payload["status_write_limited"] as? Bool == true,
          payload["status_write_payload_too_large"] as? Bool == true,
          payload["status_write_original_stage"] as? String == "stopped" else {
      throw HarnessError("Release compaction case did not actually take the compacted write path.")
    }
    // The two fields the redacted failure message names, by their status
    // document spelling. The host maps these to provider_error_domain and
    // provider_error_code.
    guard payload["error_domain"] as? String == "NEAgentErrorDomain",
          payload["error_code"] as? Int == 1,
          payload["error_message"] as? String
            == WinsTunnelDiagnostics.redactedProviderSystemErrorMessage else {
      throw HarnessError("Compacted stop status lost the fields its own error message names.")
    }
    guard payload["network_settings_release_requested"] as? Bool == true,
          payload["network_settings_release_outcome"] as? String == "failed",
          payload["network_settings_release_completed"] as? Bool == true,
          payload["network_settings_release_failed"] as? Bool == true,
          payload["network_settings_release_elapsed_ms"] as? Int == 10,
          payload["network_settings_release_deadline_ms"] as? Int == 2000,
          payload["network_settings_release_error_domain"] as? String == "NEAgentErrorDomain",
          payload["network_settings_release_error_code"] as? Int == 1 else {
      throw HarnessError("Compacted stop status dropped the network settings release fields.")
    }
    guard payload["stop_reason"] as? Int == 1,
          payload["engine_was_running_before_stop"] as? Bool == true else {
      throw HarnessError("Release compaction case lost pre-existing compacted stop fields.")
    }
    guard String(describing: payload).contains("safe-diagnostic-valuesafe-diagnostic-value") == false else {
      throw HarnessError("Compacted stop status leaked the oversized debug blob.")
    }
  }

  /// A contained run's terminal document must say it was contained, an
  /// uncontained run's must say it was not, and a document that cannot tell must
  /// say that instead of going quiet. Before this, all three looked identical.
  private static func expectDevContainmentIsCarriedIntoTheStopDocument() throws {
    let containedStatus: [String: Any] = [
      "status_generation": "run-a",
      "stage": "app_message",
      "dev_containment_active": true,
      "dev_containment_requested": true,
      "dev_containment_kind": "dev_narrow_route_no_ipv6_no_dns",
      "dev_containment_test_route_usable": true,
      "dev_containment_default_ipv4_route_installed": false,
      "dev_containment_ipv6_settings_installed": false,
      "dev_containment_dns_settings_installed": false,
      "dev_containment_included_route_count": 1,
      "dev_containment_test_route_prefix_length": 32,
      "dev_containment_config_requested_default_route": true,
      "healthy": true
    ]
    let carried = WinsDevContainmentStopCarry.fields(
      previousStatus: containedStatus,
      expectedStatusGeneration: "run-a"
    )
    guard carried["dev_containment_at_stop"] as? String == "contained",
          carried["dev_containment_active"] as? Bool == true,
          carried["dev_containment_kind"] as? String == "dev_narrow_route_no_ipv6_no_dns",
          carried["dev_containment_requested"] as? Bool == true,
          carried["dev_containment_test_route_usable"] as? Bool == true,
          carried["dev_containment_ipv6_settings_installed"] as? Bool == false,
          carried["dev_containment_dns_settings_installed"] as? Bool == false,
          carried["dev_containment_included_route_count"] as? Int == 1,
          carried["dev_containment_test_route_prefix_length"] as? Int == 32,
          carried["dev_containment_config_requested_default_route"] as? Bool == true else {
      throw HarnessError("A contained run's stop document did not carry its containment fields.")
    }
    // Nothing outside the namespace may ride along.
    guard carried["healthy"] == nil, carried["stage"] == nil else {
      throw HarnessError("Containment carry copied fields outside the dev_containment_ namespace.")
    }

    // An uncontained run: readable, attributable, and explicitly NOT contained.
    let uncontained = WinsDevContainmentStopCarry.fields(
      previousStatus: ["status_generation": "run-b", "stage": "app_message", "healthy": true],
      expectedStatusGeneration: "run-b"
    )
    guard uncontained["dev_containment_at_stop"] as? String == "not_contained",
          uncontained["dev_containment_active"] as? Bool == false,
          uncontained.keys.filter({ $0.hasPrefix("dev_containment_") }).count == 2 else {
      throw HarnessError("An uncontained run's stop document did not say so explicitly.")
    }

    // No previous document at all: the answer is "unknown", and it must NOT
    // assert dev_containment_active either way — claiming false here would be
    // the same silent-absence lie in a new costume.
    let unreadable = WinsDevContainmentStopCarry.fields(previousStatus: nil)
    guard unreadable["dev_containment_at_stop"] as? String == "unknown",
          unreadable["dev_containment_active"] == nil,
          unreadable.count == 1 else {
      throw HarnessError("An unreadable previous status did not produce an honest unknown.")
    }

    // A stale document from a DIFFERENT run must never lend this one its
    // containment state, in either direction.
    let mismatched = WinsDevContainmentStopCarry.fields(
      previousStatus: containedStatus,
      expectedStatusGeneration: "run-z"
    )
    guard mismatched["dev_containment_at_stop"] as? String == "unknown",
          mismatched["dev_containment_active"] == nil,
          mismatched.count == 1 else {
      throw HarnessError("Containment state was attributed across a status generation mismatch.")
    }

    // A generation missing on either side cannot be checked, so the carry still
    // happens — the pre-generation schema must not become permanently "unknown".
    let unversioned = WinsDevContainmentStopCarry.fields(
      previousStatus: ["dev_containment_active": true],
      expectedStatusGeneration: "run-a"
    )
    guard unversioned["dev_containment_at_stop"] as? String == "contained" else {
      throw HarnessError("Containment carry refused a previous document that carries no generation.")
    }

    // Values are sanitized on the way through: the previous document is a file
    // on disk and is not trusted to be well-formed.
    let unsafe = WinsDevContainmentStopCarry.fields(
      previousStatus: [
        "dev_containment_active": true,
        "dev_containment_kind": "/Users/winsvpn/Library/Group Containers/x/Tunnel/latest_status.json",
        "dev_containment_note": String(repeating: "n", count: 4096)
      ]
    )
    guard unsafe["dev_containment_at_stop"] as? String == "contained",
          unsafe["dev_containment_kind"] == nil,
          unsafe["dev_containment_note"] == nil else {
      throw HarnessError("Containment carry passed unsanitized values through from disk.")
    }
  }

  /// The stop document is the one most likely to be compacted, so the answer to
  /// "was this run contained?" has to survive that path — including the
  /// tri-state marker, whose whole purpose is defeated if it can go missing.
  private static func expectDevContainmentStopCarrySurvivesCompaction() throws {
    var extra: [String: Any] = [
      "status_generation": "contained-generation",
      "stop_reason": 1,
      "unsafe_large_debug_blob": String(
        repeating: "safe-diagnostic-value",
        count: WinsPacketTunnelProviderStatus.maxStatusFileBytes
      )
    ]
    extra.merge(
      WinsDevContainmentStopCarry.fields(
        previousStatus: [
          "status_generation": "contained-generation",
          "dev_containment_active": true,
          "dev_containment_requested": true,
          "dev_containment_kind": "dev_narrow_route_no_ipv6_no_dns",
          "dev_containment_test_route_usable": true,
          "dev_containment_ipv6_settings_installed": false
        ],
        expectedStatusGeneration: "contained-generation"
      )
    ) { _, new in new }

    let data = try WinsPacketTunnelProviderStatus.writableData(
      stage: "stopped",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: false,
      networkSettingsReady: false,
      extra: extra,
      fallbackStatusGeneration: "fallback-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard data.count <= WinsPacketTunnelProviderStatus.maxStatusFileBytes,
          let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          payload["status_write_payload_too_large"] as? Bool == true else {
      throw HarnessError("Containment compaction case did not take the compacted write path.")
    }
    guard payload["dev_containment_at_stop"] as? String == "contained",
          payload["dev_containment_active"] as? Bool == true,
          payload["dev_containment_kind"] as? String == "dev_narrow_route_no_ipv6_no_dns",
          payload["dev_containment_requested"] as? Bool == true,
          payload["dev_containment_test_route_usable"] as? Bool == true else {
      throw HarnessError("A compacted stop document could not say the run was contained.")
    }

    // The uncontained case has to survive compaction too, or the reviewer is
    // back to reading absence.
    let uncontainedData = try WinsPacketTunnelProviderStatus.writableData(
      stage: "stopped",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      extra: [
        "status_generation": "plain-generation",
        "unsafe_large_debug_blob": String(
          repeating: "safe-diagnostic-value",
          count: WinsPacketTunnelProviderStatus.maxStatusFileBytes
        )
      ].merging(
        WinsDevContainmentStopCarry.fields(
          previousStatus: ["status_generation": "plain-generation"],
          expectedStatusGeneration: "plain-generation"
        )
      ) { _, new in new },
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard let uncontainedPayload = try JSONSerialization
      .jsonObject(with: uncontainedData) as? [String: Any],
      uncontainedPayload["status_write_payload_too_large"] as? Bool == true,
      uncontainedPayload["dev_containment_at_stop"] as? String == "not_contained",
      uncontainedPayload["dev_containment_active"] as? Bool == false else {
      throw HarnessError("A compacted stop document could not say the run was NOT contained.")
    }
  }

  private static func expectProviderStatusGenerationSanitization() throws {
    guard WinsPacketTunnelProviderStatus.safeStatusGeneration(
      " status-generation-123 "
    ) == "status-generation-123",
      WinsPacketTunnelProviderStatus.safeStatusGeneration("") == "",
      WinsPacketTunnelProviderStatus.safeStatusGeneration(nil) == "" else {
      throw HarnessError("Provider status generation sanitizer rejected safe generation values.")
    }

    for unsafeGeneration in [
      "generation\nsecret",
      String(repeating: "a", count: 65),
      "/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json",
      "Endpoint = 203.0.113.10:9110",
      "https://www.winsvpn.org/debug"
    ] {
      guard WinsPacketTunnelProviderStatus.safeStatusGeneration(unsafeGeneration) == "" else {
        throw HarnessError("Provider status generation sanitizer accepted unsafe value: \(unsafeGeneration.prefix(64)).")
      }
    }

    let payload = WinsPacketTunnelProviderStatus.payload(
      stage: "config_saved",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      extra: [
        "status_generation":
          "/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json"
      ],
      fallbackStatusGeneration: "fallback-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard payload["status_generation"] as? String == "fallback-generation" else {
      throw HarnessError("Provider status payload did not replace unsafe generation with fallback: \(payload).")
    }

    let unsafePayload = WinsPacketTunnelProviderStatus.payload(
      stage: "config_saved",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      extra: ["status_generation": "Endpoint = 203.0.113.10:9110"],
      fallbackStatusGeneration: "PrivateKey = \(key)",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard unsafePayload["status_generation"] == nil else {
      throw HarnessError("Provider status payload kept unsafe status generation: \(unsafePayload).")
    }
  }

  private static func expectProviderRuntimeInputSelection() throws {
    guard WinsPacketTunnelProviderStatus.preferredStatusGeneration(
      saved: " saved-generation ",
      transient: "transient-generation"
    ) == "saved-generation" else {
      throw HarnessError("Provider runtime input selector did not prefer saved status generation.")
    }
    guard WinsPacketTunnelProviderStatus.preferredStatusGeneration(
      saved: nil,
      transient: " transient-generation "
    ) == "transient-generation" else {
      throw HarnessError("Provider runtime input selector did not fall back to transient status generation.")
    }
    guard WinsPacketTunnelProviderStatus.preferredStatusGeneration(
      saved: "/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_status.json",
      transient: "safe-transient-generation"
    ) == "safe-transient-generation" else {
      throw HarnessError("Provider runtime input selector did not reject unsafe saved status generation.")
    }
    guard WinsPacketTunnelProviderStatus.preferredStatusGeneration(
      saved: "safe-saved-generation",
      transient: "Endpoint = 203.0.113.10:9110"
    ) == "safe-saved-generation" else {
      throw HarnessError("Provider runtime input selector let unsafe transient generation override saved generation.")
    }
    guard WinsPacketTunnelProviderStatus.preferredStatusGeneration(
      saved: "PrivateKey = \(key)",
      transient: "Endpoint = 203.0.113.10:9110"
    ).isEmpty else {
      throw HarnessError("Provider runtime input selector accepted unsafe status generations.")
    }

    guard WinsPacketTunnelProviderStatus.preferredClientPublicKey(
      saved: " saved-public-key ",
      transient: "transient-public-key"
    ) == "saved-public-key" else {
      throw HarnessError("Provider runtime input selector did not prefer saved client public key.")
    }
    guard WinsPacketTunnelProviderStatus.preferredClientPublicKeySource(
      saved: " saved-public-key ",
      transient: "transient-public-key"
    ) == "saved_tunnel_preference" else {
      throw HarnessError("Provider runtime input selector did not report saved client public key source.")
    }
    guard WinsPacketTunnelProviderStatus.preferredClientPublicKey(
      saved: " ",
      transient: " transient-public-key "
    ) == "transient-public-key" else {
      throw HarnessError("Provider runtime input selector did not fall back to transient client public key.")
    }
    let transientSelection = WinsPacketTunnelProviderStatus.preferredClientPublicKeySelection(
      saved: " ",
      transient: " transient-public-key "
    )
    guard transientSelection.publicKey == "transient-public-key",
          transientSelection.source == "transient_start_options" else {
      throw HarnessError("Provider runtime input selector did not report transient client public key source.")
    }
    let missingSelection = WinsPacketTunnelProviderStatus.preferredClientPublicKeySelection(
      saved: nil,
      transient: nil
    )
    guard missingSelection.publicKey.isEmpty,
          missingSelection.source == "missing" else {
      throw HarnessError("Provider runtime input selector did not report missing client public key source.")
    }
  }

  private static func expectProviderStatusMappedValueSanitization() throws {
    guard WinsPacketTunnelProviderStatus.safeMappedStatusValue(
      true,
      sourceKey: "healthy"
    ) as? Bool == true,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        42,
        sourceKey: "route_count"
      ) as? Int == 42,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        NSNumber(value: 42),
        sourceKey: "route_count"
      ) as? Int == 42,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        NSNumber(value: true),
        sourceKey: "app_message_accepted"
      ) as? Bool == true,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        NSNumber(value: false),
        sourceKey: "app_message_engine_running"
      ) as? Bool == false,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        "engine_missing",
        sourceKey: "stage"
      ) as? String == "engine_missing" else {
      throw HarnessError("Provider status mapped scalar sanitizer rejected safe values.")
    }
    guard WinsPacketTunnelProviderStatus.safeMappedStatusValue(
      "engine_start_failed",
      sourceKey: "stage"
    ) as? String == "engine_start_failed" else {
      throw HarnessError("Provider status mapped scalar sanitizer rejected engine-start failure stage.")
    }
    guard WinsPacketTunnelProviderStatus.safeStatusByteCount(42) == 42,
          WinsPacketTunnelProviderStatus.safeStatusByteCount(UInt64(Int.max) + 1) == Int.max else {
      throw HarnessError("Provider status byte-count sanitizer did not clamp to codec-safe integers.")
    }

    guard let components = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
      ["amneziawg_packet_engine", "xray_transport_loopback"],
      sourceKey: "engine_bundle_missing_components"
    ) as? [String],
      components == ["amneziawg_packet_engine", "xray_transport_loopback"] else {
      throw HarnessError("Provider status mapped array sanitizer rejected safe engine components.")
    }

    guard let dnsMatchDomains = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
      ["", "winsvpn.org"],
      sourceKey: "dns_match_domains"
    ) as? [String],
      dnsMatchDomains == ["", "winsvpn.org"] else {
      throw HarnessError("Provider status mapped array sanitizer rejected safe DNS match domains.")
    }

    for unsafeString in [
      "/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json",
      "Endpoint = 203.0.113.10:9110",
      "PrivateKey = \(key)",
      "https://www.winsvpn.org/debug",
      "provider error leaked 203.0.113.10",
      "safe\nunsafe",
      String(repeating: "a", count: 257)
    ] {
      guard WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        unsafeString,
        sourceKey: "error_message"
      ) == nil else {
        throw HarnessError("Provider status mapped sanitizer accepted unsafe string: \(unsafeString.prefix(64)).")
      }
    }

    for unsafeNumber in [
      NSNumber(value: 42.5),
      NSNumber(value: Double.nan),
      NSNumber(value: Double.infinity),
      NSNumber(value: UInt64(Int.max) + 1)
    ] {
      guard WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        unsafeNumber,
        sourceKey: "route_count"
      ) == nil else {
        throw HarnessError("Provider status mapped sanitizer accepted unsafe number: \(unsafeNumber).")
      }
    }

    guard let filteredComponents = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
      [
        "amneziawg_packet_engine",
        "/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json"
      ],
      sourceKey: "engine_bundle_missing_components"
    ) as? [String],
      filteredComponents == ["amneziawg_packet_engine"] else {
      throw HarnessError("Provider status mapped sanitizer did not filter unsafe array entries.")
    }

    guard WinsPacketTunnelProviderStatus.safeMappedStatusValue(
      ["/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json"],
      sourceKey: "engine_bundle_missing_components"
    ) == nil,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        ["amneziawg_packet_engine"],
        sourceKey: "stage"
      ) == nil,
      WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        ["unexpected": "dictionary"],
        sourceKey: "stage"
      ) == nil else {
      throw HarnessError("Provider status mapped sanitizer accepted unsupported mapped values.")
    }
  }

  private static func expectProviderLifecycleAndAppMessagePayload() throws {
    let rawMessage = #"{"command":"health","raw":"secret raw payload"}"#
    let providerExecutableSHA256 = String(repeating: "a", count: 64)
    let appMessage = WinsPacketTunnelProviderAppMessage(
      messageData: Data(rawMessage.utf8),
      engineRunning: true,
      transportMode: "xray_vless_ws_amneziawg",
      xrayEnabled: true,
      providerExecutableSHA256: providerExecutableSHA256
    )
    guard appMessage.accepted,
          appMessage.command == "health",
          appMessage.statusFields["app_message_command_is_health"] as? Bool == true,
          appMessage.messageBytes == Data(rawMessage.utf8).count,
          appMessage.messageTooLarge == false,
          appMessage.engineRunning else {
      throw HarnessError("Provider app message parser did not accept health check: \(appMessage.statusFields).")
    }
    guard let responseData = appMessage.responseData,
          let response = try JSONSerialization.jsonObject(with: responseData) as? [String: Any],
          response["response_schema_version"] as? Int == WinsPacketTunnelProviderAppMessage.schemaVersion,
          response["command"] as? String == "health",
          response["accepted"] as? Bool == true,
          response["engine_running"] as? Bool == true,
          response["transport_mode"] as? String == "xray_vless_ws_amneziawg",
          response["xray_enabled"] as? Bool == true,
          response["provider_executable_sha256"] as? String == providerExecutableSHA256,
          response["raw_payload_redacted"] as? Bool == true else {
      throw HarnessError("Provider app message response was incomplete.")
    }
    let healthyProbeFields = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: responseData,
      expectedProviderExecutableSHA256: providerExecutableSHA256
    )
    guard healthyProbeFields["provider_message_probe_healthy"] as? Bool == true,
          healthyProbeFields["provider_message_probe_accepted"] as? Bool == true,
          healthyProbeFields["provider_message_probe_engine_running"] as? Bool == true,
          healthyProbeFields["provider_message_probe_command"] as? String == "health",
          healthyProbeFields["provider_message_probe_command_is_health"] as? Bool == true,
          healthyProbeFields["provider_message_probe_response_schema_version"] as? Int
            == WinsPacketTunnelProviderAppMessage.schemaVersion,
          healthyProbeFields["provider_message_probe_response_schema_supported"] as? Bool == true,
          healthyProbeFields["provider_message_probe_transport_mode"] as? String
            == "xray_vless_ws_amneziawg",
          healthyProbeFields["provider_message_probe_xray_enabled"] as? Bool == true,
          healthyProbeFields["provider_message_probe_transport_mode_supported"] as? Bool == true,
          healthyProbeFields["provider_message_probe_transport_mode_consistent"] as? Bool == true,
          healthyProbeFields["provider_message_probe_executable_sha256"] as? String
            == providerExecutableSHA256,
          healthyProbeFields["provider_message_probe_executable_sha256_matches_expected"] as? Bool
            == true,
          healthyProbeFields["provider_message_probe_response_json_valid"] as? Bool == true,
          healthyProbeFields["provider_message_probe_response_too_large"] as? Bool == false,
          healthyProbeFields["provider_message_probe_response_bytes"] as? Int == responseData.count,
          healthyProbeFields["provider_message_probe_response_max_bytes"] as? Int
            == WinsPacketTunnelProviderAppMessage.maxResponseMessageBytes,
          healthyProbeFields["provider_message_probe_raw_payload_redacted"] as? Bool == true,
          healthyProbeFields["provider_message_probe_response_redacted"] as? Bool == true else {
      throw HarnessError("Provider health probe response parser rejected a valid response: \(healthyProbeFields).")
    }

    let mismatchedExecutableProbeFields =
      WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
        responseData: responseData,
        expectedProviderExecutableSHA256: String(repeating: "b", count: 64)
      )
    guard mismatchedExecutableProbeFields["provider_message_probe_healthy"] as? Bool == false,
          mismatchedExecutableProbeFields[
            "provider_message_probe_executable_sha256_matches_expected"
          ] as? Bool == false,
          mismatchedExecutableProbeFields[
            "provider_message_probe_transport_mode_consistent"
          ] as? Bool == true else {
      throw HarnessError(
        "Provider health probe accepted a response from the wrong executable: \(mismatchedExecutableProbeFields)."
      )
    }

    let inconsistentTransportProbeData = try JSONSerialization.data(
      withJSONObject: [
        "response_schema_version": WinsPacketTunnelProviderAppMessage.schemaVersion,
        "command": "health",
        "accepted": true,
        "engine_running": true,
        "transport_mode": "xray_vless_ws_amneziawg",
        "xray_enabled": false,
        "provider_executable_sha256": providerExecutableSHA256,
        "raw_payload_redacted": true
      ],
      options: [.sortedKeys]
    )
    let inconsistentTransportProbeFields =
      WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
        responseData: inconsistentTransportProbeData,
        expectedProviderExecutableSHA256: providerExecutableSHA256
      )
    guard inconsistentTransportProbeFields["provider_message_probe_healthy"] as? Bool == false,
          inconsistentTransportProbeFields[
            "provider_message_probe_transport_mode_consistent"
          ] as? Bool == false,
          inconsistentTransportProbeFields[
            "provider_message_probe_executable_sha256_matches_expected"
          ] as? Bool == true else {
      throw HarnessError(
        "Provider health probe accepted an inconsistent Xray transport response: \(inconsistentTransportProbeFields)."
      )
    }

    let unsupportedMessage = WinsPacketTunnelProviderAppMessage(
      messageData: Data(#"{"command":"readiness"}"#.utf8),
      engineRunning: true
    )
    guard unsupportedMessage.command == "readiness",
          unsupportedMessage.accepted == false,
          unsupportedMessage.statusFields["app_message_command_is_health"] as? Bool == false,
          unsupportedMessage.messageTooLarge == false,
          let unsupportedResponseData = unsupportedMessage.responseData,
          let unsupportedResponse = try JSONSerialization.jsonObject(
            with: unsupportedResponseData
          ) as? [String: Any],
          unsupportedResponse["command"] as? String == "readiness",
          unsupportedResponse["accepted"] as? Bool == false,
          unsupportedResponse["engine_running"] as? Bool == true else {
      throw HarnessError("Provider app message parser accepted an unsupported command.")
    }
    let unsupportedProbeFields = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: unsupportedResponseData
    )
    guard unsupportedProbeFields["provider_message_probe_healthy"] as? Bool == false,
          unsupportedProbeFields["provider_message_probe_accepted"] as? Bool == false,
          unsupportedProbeFields["provider_message_probe_engine_running"] as? Bool == true,
          unsupportedProbeFields["provider_message_probe_command"] as? String == "readiness",
          unsupportedProbeFields["provider_message_probe_command_is_health"] as? Bool == false,
          unsupportedProbeFields["provider_message_probe_response_schema_version"] as? Int
            == WinsPacketTunnelProviderAppMessage.schemaVersion,
          unsupportedProbeFields["provider_message_probe_response_schema_supported"] as? Bool == true,
          unsupportedProbeFields["provider_message_probe_response_redacted"] as? Bool == true else {
      throw HarnessError("Provider health probe parser did not reject unsupported commands clearly: \(unsupportedProbeFields).")
    }

    let unsafeCommandMessage = WinsPacketTunnelProviderAppMessage(
      messageData: Data(#"{"command":"../health"}"#.utf8),
      engineRunning: true
    )
    guard unsafeCommandMessage.command == "invalid",
          unsafeCommandMessage.accepted == false,
          let unsafeCommandResponseData = unsafeCommandMessage.responseData,
          let unsafeCommandResponse = try JSONSerialization.jsonObject(
            with: unsafeCommandResponseData
          ) as? [String: Any],
          unsafeCommandResponse["command"] as? String == "invalid",
          unsafeCommandResponse["accepted"] as? Bool == false else {
      throw HarnessError("Provider app message parser promoted an unsafe command to health.")
    }

    let wrongSchemaProbeData = try JSONSerialization.data(
      withJSONObject: [
        "response_schema_version": 999,
        "command": "health",
        "accepted": true,
        "engine_running": true,
        "raw_payload_redacted": true
      ],
      options: [.sortedKeys]
    )
    let wrongSchemaProbeFields = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: wrongSchemaProbeData
    )
    guard wrongSchemaProbeFields["provider_message_probe_healthy"] as? Bool == false,
          wrongSchemaProbeFields["provider_message_probe_command"] as? String == "health",
          wrongSchemaProbeFields["provider_message_probe_command_is_health"] as? Bool == true,
          wrongSchemaProbeFields["provider_message_probe_response_schema_version"] as? Int == 999,
          wrongSchemaProbeFields["provider_message_probe_response_schema_supported"] as? Bool == false else {
      throw HarnessError("Provider health probe parser accepted an unsupported schema: \(wrongSchemaProbeFields).")
    }

    let invalidProbeFields = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: Data("PrivateKey = secret".utf8)
    )
    guard invalidProbeFields["provider_message_probe_healthy"] as? Bool == false,
          invalidProbeFields["provider_message_probe_response_json_valid"] as? Bool == false,
          invalidProbeFields["provider_message_probe_response_too_large"] as? Bool == false,
          invalidProbeFields["provider_message_probe_response_bytes"] as? Int == 19,
          invalidProbeFields["provider_message_probe_command_is_health"] as? Bool == false,
          invalidProbeFields["provider_message_probe_response_schema_supported"] as? Bool == false,
          invalidProbeFields["provider_message_probe_raw_payload_redacted"] as? Bool == true,
          invalidProbeFields["provider_message_probe_response_redacted"] as? Bool == true else {
      throw HarnessError("Provider health probe parser did not reject invalid JSON safely: \(invalidProbeFields).")
    }

    let oversizedProbeData = Data(
      repeating: 0x61,
      count: WinsPacketTunnelProviderAppMessage.maxResponseMessageBytes + 1
    )
    let oversizedProbeFields = WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
      responseData: oversizedProbeData
    )
    guard oversizedProbeFields["provider_message_probe_healthy"] as? Bool == false,
          oversizedProbeFields["provider_message_probe_response_json_valid"] as? Bool == false,
          oversizedProbeFields["provider_message_probe_response_too_large"] as? Bool == true,
          oversizedProbeFields["provider_message_probe_response_bytes"] as? Int == oversizedProbeData.count,
          oversizedProbeFields["provider_message_probe_response_max_bytes"] as? Int
            == WinsPacketTunnelProviderAppMessage.maxResponseMessageBytes,
          oversizedProbeFields["provider_message_probe_command_is_health"] as? Bool == false,
          oversizedProbeFields["provider_message_probe_response_schema_supported"] as? Bool == false,
          oversizedProbeFields["provider_message_probe_raw_payload_redacted"] as? Bool == true,
          oversizedProbeFields["provider_message_probe_response_redacted"] as? Bool == true else {
      throw HarnessError("Provider health probe parser did not reject oversized responses safely: \(oversizedProbeFields).")
    }

    let appMessagePayload = WinsPacketTunnelProviderStatus.payload(
      stage: "app_message",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: true,
      networkSettingsReady: true,
      extra: appMessage.statusFields,
      fallbackStatusGeneration: "lifecycle-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard appMessagePayload["status_schema_version"] as? Int == WinsPacketTunnelProviderStatus.schemaVersion,
          appMessagePayload["stage"] as? String == "app_message",
          appMessagePayload["healthy"] as? Bool == true,
          appMessagePayload["app_message_schema_version"] as? Int == WinsPacketTunnelProviderAppMessage.schemaVersion,
          appMessagePayload["app_message_command"] as? String == "health",
          appMessagePayload["app_message_command_is_health"] as? Bool == true,
          appMessagePayload["app_message_accepted"] as? Bool == true,
          appMessagePayload["app_message_too_large"] as? Bool == false,
          appMessagePayload["app_message_raw_payload_redacted"] as? Bool == true,
          appMessagePayload["app_message_engine_running"] as? Bool == true,
          appMessagePayload["status_generation"] as? String == "lifecycle-generation" else {
      throw HarnessError("Provider app message payload was incomplete: \(appMessagePayload).")
    }

    let unsupportedAppMessageReady = unsupportedMessage.engineRunning && unsupportedMessage.accepted
    let unsupportedAppMessagePayload = WinsPacketTunnelProviderStatus.payload(
      stage: "app_message",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: unsupportedAppMessageReady,
      networkSettingsReady: unsupportedAppMessageReady,
      extra: unsupportedMessage.statusFields,
      fallbackStatusGeneration: "lifecycle-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard unsupportedAppMessagePayload["stage"] as? String == "app_message",
          unsupportedAppMessagePayload["healthy"] as? Bool == false,
          unsupportedAppMessagePayload["engine_ready"] as? Bool == false,
          unsupportedAppMessagePayload["network_settings_ready"] as? Bool == false,
          unsupportedAppMessagePayload["app_message_command"] as? String == "readiness",
          unsupportedAppMessagePayload["app_message_command_is_health"] as? Bool == false,
          unsupportedAppMessagePayload["app_message_accepted"] as? Bool == false,
          unsupportedAppMessagePayload["app_message_engine_running"] as? Bool == true else {
      throw HarnessError("Provider app message payload treated an unsupported command as healthy: \(unsupportedAppMessagePayload).")
    }

    let unsafeMessage = WinsPacketTunnelProviderAppMessage(
      messageData: Data("health /tmp/latest_status.json".utf8),
      engineRunning: false
    )
    guard unsafeMessage.command == "invalid",
          unsafeMessage.accepted == false,
          unsafeMessage.statusFields["app_message_command_is_health"] as? Bool == false,
          unsafeMessage.statusFields["app_message_raw_payload_redacted"] as? Bool == true else {
      throw HarnessError("Unsafe app message should be rejected instead of promoted to health: \(unsafeMessage.statusFields).")
    }

    guard WinsPacketTunnelProviderAppMessage.safeResponseCommand(" HEALTH ") == "health",
          WinsPacketTunnelProviderAppMessage.safeResponseCommand("readiness") == "readiness",
          WinsPacketTunnelProviderAppMessage.safeResponseCommand("ping") == "ping" else {
      throw HarnessError("Provider response command sanitizer rejected safe commands.")
    }
    for unsafeCommand in ["", "health /tmp/latest_status.json", "health\nsecret", String(repeating: "a", count: 33)] {
      guard WinsPacketTunnelProviderAppMessage.safeResponseCommand(unsafeCommand) == "invalid" else {
        throw HarnessError("Provider response command sanitizer accepted unsafe command: \(unsafeCommand).")
      }
    }

    let tooLargeMessage = WinsPacketTunnelProviderAppMessage(
      messageData: Data(repeating: 0x61, count: WinsPacketTunnelProviderAppMessage.maxAcceptedMessageBytes + 1),
      engineRunning: false
    )
    guard tooLargeMessage.command == "invalid",
          tooLargeMessage.accepted == false,
          tooLargeMessage.statusFields["app_message_command_is_health"] as? Bool == false,
          tooLargeMessage.messageTooLarge == true else {
      throw HarnessError("Oversized app message was not rejected safely: \(tooLargeMessage.statusFields).")
    }

    let sleepPayload = WinsPacketTunnelProviderStatus.payload(
      stage: "sleeping",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: false,
      networkSettingsReady: false,
      extra: WinsPacketTunnelProviderLifecycle.statusFields(
        event: "sleep",
        engineRunning: true
      ),
      fallbackStatusGeneration: "lifecycle-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard sleepPayload["lifecycle_schema_version"] as? Int == WinsPacketTunnelProviderLifecycle.schemaVersion,
          sleepPayload["lifecycle_event"] as? String == "sleep",
          sleepPayload["lifecycle_engine_running"] as? Bool == true,
          sleepPayload["lifecycle_suspended"] as? Bool == true,
          sleepPayload["engine_ready"] as? Bool == false,
          sleepPayload["network_settings_ready"] as? Bool == false,
          sleepPayload["healthy"] as? Bool == false else {
      throw HarnessError("Provider lifecycle payload was incomplete: \(sleepPayload).")
    }

    let wakePayload = WinsPacketTunnelProviderStatus.payload(
      stage: "woke",
      providerBundleIdentifier: "org.winsvpn.app.PacketTunnel",
      engineReady: true,
      networkSettingsReady: true,
      extra: WinsPacketTunnelProviderLifecycle.statusFields(
        event: "wake",
        engineRunning: true
      ),
      fallbackStatusGeneration: "lifecycle-generation",
      updatedAt: Date(timeIntervalSince1970: 0)
    )
    guard wakePayload["lifecycle_event"] as? String == "wake",
          wakePayload["lifecycle_suspended"] as? Bool == false,
          wakePayload["healthy"] as? Bool == true else {
      throw HarnessError("Provider wake lifecycle payload was incomplete: \(wakePayload).")
    }

    let lifecycleDescription = String(describing: [
      response,
      healthyProbeFields,
      invalidProbeFields,
      oversizedProbeFields,
      appMessagePayload,
      unsafeMessage.statusFields,
      tooLargeMessage.statusFields,
      sleepPayload
    ])
    for rawFragment in [
      "secret raw payload",
      "/tmp/",
      "latest_status.json",
      "health /tmp/latest_status.json"
    ] where lifecycleDescription.contains(rawFragment) {
      throw HarnessError("Provider lifecycle/app-message status leaked raw payload fragment: \(rawFragment).")
    }
  }

  private static func expectProviderStatusStageValidation() throws {
    let expectedStages: Set<String> = [
      "config_saved",
      "start_rejected",
      "network_settings_failed",
      "engine_started",
      "engine_missing",
      "engine_start_failed",
      "stopped",
      "app_message",
      "sleeping",
      "woke"
    ]
    guard WinsPacketTunnelProviderStatus.knownStages == expectedStages else {
      throw HarnessError("Provider status stage allowlist drifted: \(WinsPacketTunnelProviderStatus.knownStages).")
    }
    for stage in expectedStages {
      guard WinsPacketTunnelProviderStatus.validStage(stage) else {
        throw HarnessError("Provider status stage was unexpectedly rejected: \(stage).")
      }
    }
    for unsafeStage in ["", "connecting", "engine started", "secret-stage", "woke\nsecret"] {
      guard !WinsPacketTunnelProviderStatus.validStage(unsafeStage) else {
        throw HarnessError("Provider status stage was unexpectedly accepted: \(unsafeStage).")
      }
    }
  }

  private static func expectAppleReadinessValidation() throws {
    let readyFields: [String: Any] = [
      "active": true,
      "provider_status_available": true,
      "provider_status_schema_supported": true,
      "provider_engine_ready": true,
      "provider_network_settings_applied": true,
      "provider_healthy": true,
      "provider_default_route_enabled": true,
      "provider_ipv6_leak_protection_enabled": true,
      "provider_engine_ipv6_leak_protection_enabled": true,
      "provider_dns_full_tunnel_match_enabled": true,
      "provider_engine_full_tunnel_dns_match_enabled": true,
      "provider_dns_count": 1,
      "provider_engine_dns_server_count": 1,
      "provider_message_probe_attempted": true,
      "provider_message_probe_healthy": true
    ]
    guard WinsAppleReadiness.providerStatusCurrent(readyFields),
          WinsAppleReadiness.providerReady(readyFields) else {
      throw HarnessError("Apple readiness helper rejected a healthy provider response.")
    }
    let leakProtectionFields = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(readyFields)
    guard leakProtectionFields["leak_protection_config_checked"] as? Bool == true,
          leakProtectionFields["leak_protection_config_kind"] as? String == "full_tunnel_route_dns_ipv6",
          leakProtectionFields["leak_protection_provider_status_current"] as? Bool == true,
          leakProtectionFields["leak_protection_config_passed"] as? Bool == true,
          leakProtectionFields["leak_protection_dns_server_count"] as? Int == 1,
          leakProtectionFields["leak_protection_engine_dns_server_count"] as? Int == 1 else {
      throw HarnessError("Apple leak-protection helper rejected full-tunnel DNS/route/IPv6 settings.")
    }
    var missingIPv6LeakProtection = readyFields
    missingIPv6LeakProtection["provider_ipv6_leak_protection_enabled"] = false
    missingIPv6LeakProtection["provider_engine_ipv6_leak_protection_enabled"] = false
    guard WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(
      missingIPv6LeakProtection
    )["leak_protection_config_passed"] as? Bool == false else {
      throw HarnessError("Apple leak-protection helper accepted missing IPv6 protection.")
    }
    var missingDNSLeakProtection = readyFields
    missingDNSLeakProtection["provider_dns_count"] = 0
    guard WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(
      missingDNSLeakProtection
    )["leak_protection_config_passed"] as? Bool == false else {
      throw HarnessError("Apple leak-protection helper accepted missing provider DNS.")
    }
    // THE CONTAINMENT TERM, as a negative test alongside its siblings above.
    //
    // This one is load-bearing in a way the others are not. Every sibling
    // above fails because the CONFIG stopped asking for full tunnel. A
    // contained dev session's config still asks for all of it — it carries
    // `0.0.0.0/0, ::/0` and full-tunnel DNS, because the native validator
    // requires that pairing — so all eight terms above read true and this
    // single boolean is the only thing standing between a contained session
    // and a `leak_protection_config_passed: true` that would be a lie.
    var containedSession = readyFields
    containedSession["provider_dev_containment_active"] = true
    let containedVerdict = WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(
      containedSession
    )
    guard containedVerdict["leak_protection_config_passed"] as? Bool == false else {
      throw HarnessError(
        "Apple leak-protection helper reported a PASS for a contained dev session."
      )
    }
    guard containedVerdict["leak_protection_dev_containment_active"] as? Bool == true,
          containedVerdict["leak_protection_config_kind"] as? String
            == "dev_contained_not_full_tunnel" else {
      throw HarnessError(
        "A contained session did not report its own leak-protection kind."
      )
    }
    // ... while every full-tunnel term it inherited still reads true, which is
    // precisely why the containment term has to exist.
    guard containedVerdict["leak_protection_default_route_enabled"] as? Bool == true,
          containedVerdict["leak_protection_ipv6_enabled"] as? Bool == true,
          containedVerdict["leak_protection_dns_full_tunnel_match_enabled"] as? Bool == true else {
      throw HarnessError("Contained-session fixture no longer exercises the real trap.")
    }

    var missingSchemaProof = readyFields
    missingSchemaProof.removeValue(forKey: "provider_status_schema_supported")
    guard !WinsAppleReadiness.providerSchemaSupported(missingSchemaProof),
          !WinsAppleReadiness.providerSchemaUnsupported(missingSchemaProof),
          !WinsAppleReadiness.providerStatusCurrent(missingSchemaProof),
          !WinsAppleReadiness.providerReady(missingSchemaProof) else {
      throw HarnessError("Apple readiness helper accepted provider status without schema proof.")
    }

    var connectedByStatus = readyFields
    connectedByStatus["active"] = false
    connectedByStatus["status"] = " connected "
    guard WinsAppleReadiness.providerReady(connectedByStatus) else {
      throw HarnessError("Apple readiness helper rejected connected status string.")
    }

    var noProbeAttempted = readyFields
    noProbeAttempted["provider_message_probe_attempted"] = false
    noProbeAttempted["provider_message_probe_healthy"] = false
    guard WinsAppleReadiness.providerReady(noProbeAttempted) else {
      throw HarnessError("Apple readiness helper rejected readiness before provider message probe.")
    }

    var stringCoerced = readyFields
    stringCoerced["active"] = "true"
    stringCoerced["provider_status_available"] = "true"
    stringCoerced["provider_status_schema_supported"] = "true"
    stringCoerced["provider_engine_ready"] = "true"
    stringCoerced["provider_network_settings_applied"] = "true"
    stringCoerced["provider_healthy"] = "true"
    stringCoerced["provider_message_probe_attempted"] = "true"
    stringCoerced["provider_message_probe_healthy"] = "true"
    guard WinsAppleReadiness.providerReady(stringCoerced) else {
      throw HarnessError("Apple readiness helper did not coerce native string booleans.")
    }

    var staleFields = readyFields
    staleFields["provider_status_stale"] = true
    guard !WinsAppleReadiness.providerStatusCurrent(staleFields),
          !WinsAppleReadiness.providerReady(staleFields) else {
      throw HarnessError("Apple readiness helper accepted stale provider status.")
    }

    var unhealthyProbe = readyFields
    unhealthyProbe["provider_message_probe_healthy"] = false
    guard !WinsAppleReadiness.providerReady(unhealthyProbe) else {
      throw HarnessError("Apple readiness helper accepted unhealthy provider probe.")
    }

    var acceptedAppMessage = readyFields
    acceptedAppMessage["provider_stage"] = "app_message"
    acceptedAppMessage["provider_app_message_accepted"] = true
    acceptedAppMessage["provider_app_message_command_is_health"] = true
    acceptedAppMessage["provider_app_message_raw_payload_redacted"] = true
    guard WinsAppleReadiness.providerAppMessageStatusTrusted(acceptedAppMessage),
          WinsAppleReadiness.providerReady(acceptedAppMessage) else {
      throw HarnessError("Apple readiness helper rejected accepted provider app-message status.")
    }

    var probeOnlyAppMessage = readyFields
    probeOnlyAppMessage["provider_stage"] = "app_message"
    probeOnlyAppMessage["provider_engine_ready"] = false
    probeOnlyAppMessage["provider_network_settings_ready"] = false
    probeOnlyAppMessage["provider_healthy"] = false
    probeOnlyAppMessage["provider_message_probe_attempted"] = true
    probeOnlyAppMessage["provider_message_probe_healthy"] = true
    probeOnlyAppMessage["provider_message_probe_engine_running"] = true
    guard WinsAppleReadiness.providerAppMessageStatusTrusted(probeOnlyAppMessage),
          WinsAppleReadiness.providerReady(probeOnlyAppMessage) else {
      throw HarnessError("Apple readiness helper rejected healthy provider message probe for app-message status.")
    }

    var rejectedAppMessage = acceptedAppMessage
    rejectedAppMessage["provider_app_message_accepted"] = false
    guard !WinsAppleReadiness.providerAppMessageStatusTrusted(rejectedAppMessage),
          !WinsAppleReadiness.providerReady(rejectedAppMessage) else {
      throw HarnessError("Apple readiness helper accepted rejected provider app-message status.")
    }

    var wrongCommandAppMessage = acceptedAppMessage
    wrongCommandAppMessage["provider_app_message_command_is_health"] = false
    guard !WinsAppleReadiness.providerReady(wrongCommandAppMessage) else {
      throw HarnessError("Apple readiness helper accepted non-health provider app-message status.")
    }

    var unredactedAppMessage = acceptedAppMessage
    unredactedAppMessage["provider_app_message_raw_payload_redacted"] = false
    guard !WinsAppleReadiness.providerReady(unredactedAppMessage) else {
      throw HarnessError("Apple readiness helper accepted unredacted provider app-message status.")
    }

    var sleepingLifecycle = readyFields
    sleepingLifecycle["provider_stage"] = "sleeping"
    sleepingLifecycle["provider_lifecycle_suspended"] = true
    sleepingLifecycle["provider_lifecycle_event"] = "sleep"
    guard !WinsAppleReadiness.providerLifecycleStatusTrusted(sleepingLifecycle),
          !WinsAppleReadiness.providerReady(sleepingLifecycle) else {
      throw HarnessError("Apple readiness helper accepted suspended provider lifecycle status.")
    }

    var wokeLifecycle = readyFields
    wokeLifecycle["provider_stage"] = "woke"
    wokeLifecycle["provider_lifecycle_suspended"] = false
    wokeLifecycle["provider_lifecycle_event"] = "wake"
    guard WinsAppleReadiness.providerLifecycleStatusTrusted(wokeLifecycle),
          WinsAppleReadiness.providerReady(wokeLifecycle) else {
      throw HarnessError("Apple readiness helper rejected wake provider lifecycle status.")
    }

    var notConnected = readyFields
    notConnected["active"] = false
    notConnected["status"] = "disconnected"
    guard !WinsAppleReadiness.providerReady(notConnected) else {
      throw HarnessError("Apple readiness helper accepted disconnected status.")
    }
  }

  private static func expectOptionalAwgSpecialJunkUapi() throws {
    let config = try WinsTunnelConfig.parseAndValidate(optionalAwgSpecialJunkConfig)
    guard let obfuscation = config.awgObfuscation,
          obfuscation.i1 == 101,
          obfuscation.i2 == nil,
          obfuscation.i3 == nil,
          obfuscation.i4 == nil,
          obfuscation.i5 == 105,
          obfuscation.fieldCount == 13 else {
      throw HarnessError("Optional AmneziaWG I1/I5 fields were not parsed correctly.")
    }
    let engineStatus = WinsPacketTunnelEnginePlan(config: config).statusFields
    guard engineStatus["engine_awg_obfuscation_field_count"] as? Int == 13,
          engineStatus["engine_awg_uapi_config_ready"] as? Bool == true,
          engineStatus["engine_awg_uapi_secret_material_redacted"] as? Bool == true else {
      throw HarnessError("Optional AWG special-junk status fields were incomplete: \(engineStatus).")
    }
    let awgUapi = try config.amneziaWGUAPIConfiguration()
    for expectedLine in ["i1=101", "i5=105"] {
      guard awgUapi.contains("\(expectedLine)\n") else {
        throw HarnessError("Optional AWG special-junk UAPI field missing: \(expectedLine).")
      }
    }
    for omittedLine in ["i2=", "i3=", "i4="] where awgUapi.contains(omittedLine) {
      throw HarnessError("Optional AWG special-junk UAPI unexpectedly included \(omittedLine).")
    }
  }

  private static func expectExternalUrlValidation() throws {
    let accepted = [
      " https://winsvpn.org/#get ",
      "http://winsvpn.org",
      "HTTPS://winsvpn.org/support",
      "mailto:support@winsvpn.org",
      "mailto:support@winsvpn.org?subject=WinVPN",
      "tel:+14249467876",
      "sms:+14249467876"
    ]
    for rawUrl in accepted {
      guard WinsAppleExternalUrl.safeUrl(from: rawUrl) != nil else {
        throw HarnessError("Expected Apple external URL to be accepted: \(rawUrl).")
      }
    }

    let rejected: [String?] = [
      nil,
      "",
      "   ",
      "file:///etc/passwd",
      "javascript:alert(1)",
      "data:text/plain,hello",
      "https:///missing-host",
      "http://",
      "mailto:",
      "mailto://support@winsvpn.org",
      "mailto:/etc/passwd",
      "mailto:../support@winsvpn.org",
      "mailto:javascript:alert(1)",
      "mailto:support@winsvpn.org?body=file:///etc/passwd",
      "mailto:support@winsvpn.org token",
      "tel:",
      "tel://+14249467876",
      "tel:../../root",
      "tel:javascript:alert(1)",
      "tel:+1-800-WINSVPN",
      "sms:",
      "sms://+14249467876",
      "sms:../../root",
      "sms:javascript:alert(1)",
      "ftp://winsvpn.org",
      "https://user:secret@winsvpn.org",
      "https://winsvpn.org/has space",
      "https://winsvpn.org/\nprobe",
      "https://winsvpn.org/\(String(repeating: "a", count: WinsAppleExternalUrl.maxLength))"
    ]
    for rawUrl in rejected {
      guard WinsAppleExternalUrl.safeUrl(from: rawUrl) == nil else {
        throw HarnessError("Expected Apple external URL to be rejected: \(rawUrl ?? "nil").")
      }
    }
  }

  private static func expectNotificationTextValidation() throws {
    guard WinsAppleNotification.announcementPayload(title: "Title", body: nil) == nil,
          WinsAppleNotification.announcementPayload(title: "Title", body: "   ") == nil else {
      throw HarnessError("Apple notification payload accepted an empty body.")
    }

    guard let trimmedPayload = WinsAppleNotification.announcementPayload(
      title: "  Service update  ",
      body: "  Maintenance complete  "
    ),
    trimmedPayload.title == "Service update",
    trimmedPayload.body == "Maintenance complete" else {
      throw HarnessError("Apple notification payload did not trim title/body.")
    }

    guard let fallbackTitlePayload = WinsAppleNotification.announcementPayload(
      title: " ",
      body: "Ready"
    ),
    fallbackTitlePayload.title == WinsAppleNotification.defaultTitle,
    fallbackTitlePayload.body == "Ready" else {
      throw HarnessError("Apple notification payload did not apply default title.")
    }

    let longTitle = String(repeating: "T", count: WinsAppleNotification.maxTitleLength + 20)
    let longBody = String(repeating: "B", count: WinsAppleNotification.maxBodyLength + 20)
    guard let boundedPayload = WinsAppleNotification.announcementPayload(
      title: longTitle,
      body: longBody
    ),
    boundedPayload.title.count == WinsAppleNotification.maxTitleLength,
    boundedPayload.title.hasSuffix("..."),
    boundedPayload.body.count == WinsAppleNotification.maxBodyLength,
    boundedPayload.body.hasSuffix("...") else {
      throw HarnessError("Apple notification payload did not bound long title/body.")
    }
  }

  private static func expectShareTextValidation() throws {
    guard WinsAppleShare.sharePayload(title: "Share", text: nil) == nil,
          WinsAppleShare.sharePayload(title: "Share", text: "   ") == nil else {
      throw HarnessError("Apple share payload accepted empty text.")
    }

    guard let trimmedPayload = WinsAppleShare.sharePayload(
      title: "  Share Win's VPN  ",
      text: "  Try Win's VPN  "
    ),
    trimmedPayload.title == "Share Win's VPN",
    trimmedPayload.text == "Try Win's VPN" else {
      throw HarnessError("Apple share payload did not trim title/text.")
    }

    guard let noTitlePayload = WinsAppleShare.sharePayload(
      title: " ",
      text: "Official link"
    ),
    noTitlePayload.title == nil,
    noTitlePayload.text == "Official link" else {
      throw HarnessError("Apple share payload did not drop blank title.")
    }

    let longTitle = String(repeating: "S", count: WinsAppleShare.maxTitleLength + 20)
    let longText = String(repeating: "L", count: WinsAppleShare.maxTextLength + 20)
    guard let boundedPayload = WinsAppleShare.sharePayload(
      title: longTitle,
      text: longText
    ),
    boundedPayload.title?.count == WinsAppleShare.maxTitleLength,
    boundedPayload.title?.hasSuffix("...") == true,
    boundedPayload.text.count == WinsAppleShare.maxTextLength,
    boundedPayload.text.hasSuffix("...") else {
      throw HarnessError("Apple share payload did not bound long title/text.")
    }
  }

  private static var directConfig: String {
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
    Endpoint = 203.0.113.10:9110
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    """
  }

  /// A DEV-ONLY contained config, in the shape
  /// `lib/winn_protocol_dev_session.dart` assembles: an ordinary full-tunnel
  /// AmneziaWG document plus the `[WinsDevContainment]` marker. The AllowedIPs
  /// stay `0.0.0.0/0, ::/0` on purpose — `validate()` requires that pairing
  /// (code 1203) and the transport /32 is derived from it (code 1504) — which
  /// is exactly why containment cannot be inferred from the routes and needs
  /// its own marker.
  private static var containedDevConfig: String {
    directConfig + """


    [WinsDevContainment]
    Enabled = true
    """
  }

  private static func containedDevConfigWithTestRoute(_ testRoute: String) -> String {
    directConfig + """


    [WinsDevContainment]
    Enabled = true
    TestRoute = \(testRoute)
    """
  }

  /// A `winn/3` config in the shape `lib/winn_protocol_dispatch.dart` emits:
  /// the AmneziaWG peer still names the real gateway (it is repointed at the
  /// seam only at start, by `WinsPacketTunnelEngine`), and `[Winn] Endpoint`
  /// names the gateway the Winn engine's own outer socket sends to.
  private static var winnConfig: String {
    directConfig + """

    [Winn]
    Enabled = true
    Endpoint = 198.51.100.7:51820
    Session_Id = apple-harness
    Max_Datagram = 1400
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

  /// This Apple ABI now builds `direct-awg` AND `http3-connect-udp`: the latter
  /// needs an authenticated carrier profile, and `WinnTunnelCreateWithCarrier`
  /// is the C export that carries one to Go. See
  /// `expectWinnHttp3CarrierAccepted()`.
  private static var winnHttp3CarrierConfig: String {
    winnConfig + "\nCarrier = http3-connect-udp\n"
  }

  /// `http2-stream` stays refused, and the reason is a HOST capability rather
  /// than a protocol one: the engine implements it, but its dialer needs a
  /// connected, protected TCP socket this host does not open — the same
  /// distinction Android and Linux draw. Running direct-awg for it would
  /// replace an authenticated post-quantum outer transport with plain UDP while
  /// the session still came up — a downgrade of the TRANSPORT rather than of
  /// the protocol version, which none of the winn/3 version gates would see.
  private static var winnHttp2CarrierConfig: String {
    winnConfig + "\nCarrier = http2-stream\n"
  }

  private static var winnMissingEndpointConfig: String {
    winnConfig.replacingOccurrences(of: "Endpoint = 198.51.100.7:51820\n", with: "")
  }

  /// The Winn engine refuses a hostname because resolving one would leave the
  /// device outside the tunnel.
  private static var winnHostnameEndpointConfig: String {
    winnConfig.replacingOccurrences(
      of: "Endpoint = 198.51.100.7:51820",
      with: "Endpoint = gw.example.invalid:51820"
    )
  }

  /// The dead-loop. A loopback Winn gateway yields no /32, so the engine's own
  /// outer socket is matched by the tunnel's default route.
  private static var winnLoopbackEndpointConfig: String {
    winnConfig.replacingOccurrences(
      of: "Endpoint = 198.51.100.7:51820",
      with: "Endpoint = 127.0.0.9:51820"
    )
  }

  /// An AmneziaWG peer that is ALREADY loopback describes a different
  /// arrangement, and its real gateway is unrecoverable from here.
  private static var winnLoopbackPeerConfig: String {
    winnConfig.replacingOccurrences(
      of: "Endpoint = 203.0.113.10:9110",
      with: "Endpoint = 127.0.0.1:42110"
    )
  }

  /// Winn and Xray are mutually exclusive outer transports: each wants the
  /// AmneziaWG peer endpoint pointed at its own relay.
  private static var winnWithXrayConfig: String {
    xrayConfig + """

    [Winn]
    Enabled = true
    Endpoint = 198.51.100.7:51820
    H1 = 11
    H2 = 22
    H3 = 33
    H4 = 44
    """
  }

  private static var optionalAwgSpecialJunkConfig: String {
    directConfig.replacingOccurrences(
      of: "H4 = 44",
      with: "H4 = 44\nI1 = 101\nI5 = 105"
    )
  }

  private static var invalidOptionalAwgSpecialJunkConfig: String {
    directConfig.replacingOccurrences(
      of: "H4 = 44",
      with: "H4 = 44\nI2 = invalid"
    )
  }

  private static var xrayConfig: String {
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
    Endpoint = 127.0.0.1:42110
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25

    [Xray]
    Enabled = true
    Uuid = 00000000-0000-0000-0000-000000000000
    Host = sync.example.invalid
    Port = 80
    ServerName = sync.example.invalid
    Path = /wins-stealth-tunnel
    Security = tls
    LocalPort = 42110
    RemoteAwgHost = 127.0.0.1
    RemoteAwgPort = 9110
    """
  }

  private static var splitRouteConfig: String {
    directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 10.42.0.0/16, 172.16.5.0/24"
    )
  }

  /// The split tunnel the app ACTUALLY SHIPS. `lib/main.dart` `_buildConfig`
  /// builds `AllowedIPs` as `[...allowedIpv4CidrsExcluding(excluded), '::/0']`,
  /// so a user bypass CIDR removes the IPv4 default route and LEAVES `::/0`.
  /// `splitRouteConfig` above drops `::/0` too and therefore never exercised the
  /// combination that leaked.
  private static var splitRouteWithIPv6DefaultRouteConfig: String {
    directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 10.42.0.0/16, 172.16.5.0/24, ::/0"
    )
  }

  /// What `lib/split_tunnel_routes.dart` `windowsPerAppAllowedIpCidrs` emits:
  /// the IPv4 default route split into halves, and `::/0` likewise split into
  /// `::/1` + `8000::/1` to dodge the Windows WireGuard service's implicit `/0`
  /// firewall. It never reaches this parser (the call site is behind
  /// `Platform.isWindows`), and it must be refused if it ever does.
  private static var windowsShapedAllowedIPsConfig: String {
    directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1"
    )
  }

  private static var missingPrivateKeyConfig: String {
    directConfig.replacingOccurrences(of: "PrivateKey = \(key)", with: "PrivateKey = ")
  }

  private static var invalidInterfaceAddressConfig: String {
    directConfig.replacingOccurrences(of: "Address = 10.8.0.2/32", with: "Address = 10.8.0.2")
  }

  private static var invalidMTUConfig: String {
    directConfig.replacingOccurrences(of: "MTU = 1280", with: "MTU = 128")
  }

  private static var missingAwgObfuscationConfig: String {
    directConfig.replacingOccurrences(of: "Jc = 2", with: "Jc = ")
  }

  private static var invalidEndpointConfig: String {
    directConfig.replacingOccurrences(of: "Endpoint = 203.0.113.10:9110", with: "Endpoint = 203.0.113.10")
  }

  private static var invalidAllowedIPsConfig: String {
    directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = not-a-route"
    )
  }

  private static var missingIPv6DefaultRouteConfig: String {
    directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 0.0.0.0/0"
    )
  }

  private static var partialIPv6RouteConfig: String {
    directConfig.replacingOccurrences(
      of: "AllowedIPs = 0.0.0.0/0, ::/0",
      with: "AllowedIPs = 0.0.0.0/0, 2001:db8::/64"
    )
  }

  private static var invalidXrayUuidConfig: String {
    xrayConfig.replacingOccurrences(
      of: "Uuid = 00000000-0000-0000-0000-000000000000",
      with: "Uuid = not-a-uuid"
    )
  }

  private static var invalidXrayPortConfig: String {
    xrayConfig.replacingOccurrences(of: "Port = 80", with: "Port = 0")
  }

  private static var invalidXrayServerNameConfig: String {
    xrayConfig.replacingOccurrences(of: "ServerName = sync.example.invalid", with: "ServerName = bad host")
  }

  private static var invalidXrayPathConfig: String {
    xrayConfig.replacingOccurrences(of: "Path = /wins-stealth-tunnel", with: "Path = wins-stealth-tunnel")
  }

  private static var invalidXrayLocalPortConfig: String {
    xrayConfig.replacingOccurrences(of: "LocalPort = 42110", with: "LocalPort = 99999")
  }

  private static var invalidXrayEndpointConfig: String {
    xrayConfig.replacingOccurrences(of: "Endpoint = 127.0.0.1:42110", with: "Endpoint = 127.0.0.1:42111")
  }

  private static var invalidXrayRemoteAwgHostConfig: String {
    xrayConfig.replacingOccurrences(of: "RemoteAwgHost = 127.0.0.1", with: "RemoteAwgHost = bad host")
  }

  private static var invalidXrayRemoteAwgPortConfig: String {
    xrayConfig.replacingOccurrences(of: "RemoteAwgPort = 9110", with: "RemoteAwgPort = 99999")
  }

  private static func expectWinn3NativeStartOutcomeClassification() throws {
    let failures = WinsWinn3NativeStartOutcomeContract.failures()
    guard failures.isEmpty else {
      throw HarnessError(
        "Winn v3 native start outcome contract failed: \(failures.joined(separator: "; "))"
      )
    }
  }
}

private struct HarnessPacketTunnelEngineAdapter: WinsPacketTunnelEngineAdapter {
  var engineReady = true
  var runningAfterStart = true
  var packetFlowAttached = true

  func makeEngine(plan: WinsPacketTunnelEnginePlan, packetFlow: AnyObject) -> WinsPacketTunnelEngine? {
    HarnessPacketTunnelEngine(
      plan: plan,
      engineReady: engineReady,
      runningAfterStart: runningAfterStart,
      packetFlowAttached: packetFlowAttached,
      packetFlowProvided: packetFlow is NSObject
    )
  }
}

private final class HarnessPacketTunnelEngine: WinsPacketTunnelEngine {
  let plan: WinsPacketTunnelEnginePlan
  private let engineReady: Bool
  private let runningAfterStart: Bool
  private let packetFlowAttached: Bool
  private let packetFlowProvided: Bool
  private(set) var isRunning = false

  init(
    plan: WinsPacketTunnelEnginePlan,
    engineReady: Bool,
    runningAfterStart: Bool,
    packetFlowAttached: Bool,
    packetFlowProvided: Bool
  ) {
    self.plan = plan
    self.engineReady = engineReady
    self.runningAfterStart = runningAfterStart
    self.packetFlowAttached = packetFlowAttached
    self.packetFlowProvided = packetFlowProvided
  }

  func start() throws -> WinsPacketTunnelEngineStartResult {
    isRunning = runningAfterStart
    return WinsPacketTunnelEngineStartResult(
      engineReady: engineReady,
      statusFields: [
        "engine_runtime_packet_flow_attached": packetFlowAttached,
        "engine_runtime_packet_flow_provided": packetFlowProvided,
        "engine_runtime_awg_started": true,
        "engine_runtime_xray_started": true,
        "engine_runtime_secret_material_redacted": false,
        "engine_runtime_attempt_count": 1,
        "engine_runtime_components": [
          "amneziawg_packet_engine",
          "xray_vless_ws_transport",
          "/tmp/WinsXrayVlessWsTransport"
        ],
        "engine_runtime_endpoint": "203.0.113.10:9110",
        "engine_runtime_log_path": "/tmp/privatekey-leak.log",
        "engine_runtime_publickey": "unsafe-public-key",
        "engine_bundle_missing_components": ["unsafe_override"]
      ]
    )
  }

  func stop() {
    isRunning = false
  }
}

private struct HarnessError: LocalizedError {
  let message: String

  init(_ message: String) {
    self.message = message
  }

  var errorDescription: String? {
    message
  }
}
