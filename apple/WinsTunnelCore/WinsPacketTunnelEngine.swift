import Darwin
import CryptoKit
import Foundation
import NetworkExtension

/// One ownership authority for native engine sampling and teardown.
///
/// Native calls run without this condition held. A sampler first claims the
/// published handle under the condition; stop flips the phase to `.stopping`,
/// rejects new claims, and waits until every existing claim has returned before
/// any native handle or loaded image can be destroyed.
final class WinsNativeSamplerLifetime {
  private enum Phase {
    case idle
    case starting
    case running
    case stopping
  }

  private let condition = NSCondition()
  private var phase: Phase = .idle
  private var inFlightSamplers = 0

  var isRunning: Bool {
    condition.lock()
    defer { condition.unlock() }
    return phase == .running
  }

  func beginStart() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    while phase == .starting || phase == .stopping {
      condition.wait()
    }
    guard phase != .running else { return false }
    phase = .starting
    return true
  }

  func finishStart() {
    condition.lock()
    precondition(phase == .starting)
    phase = .running
    condition.broadcast()
    condition.unlock()
  }

  func finishFailedStart() {
    condition.lock()
    precondition(phase == .starting)
    phase = .idle
    condition.broadcast()
    condition.unlock()
  }

  func claim<T>(_ snapshot: () -> T?) -> T? {
    condition.lock()
    defer { condition.unlock() }
    guard phase == .running, let value = snapshot() else { return nil }
    inFlightSamplers += 1
    return value
  }

  func releaseClaim() {
    condition.lock()
    precondition(inFlightSamplers > 0)
    inFlightSamplers -= 1
    if inFlightSamplers == 0 {
      condition.broadcast()
    }
    condition.unlock()
  }

  func beginStopAndWaitForSamplers() -> Bool {
    condition.lock()
    while phase == .starting {
      condition.wait()
    }
    if phase == .stopping {
      while phase == .stopping {
        condition.wait()
      }
      condition.unlock()
      return false
    }
    guard phase == .running else {
      condition.unlock()
      return false
    }
    phase = .stopping
    while inFlightSamplers > 0 {
      condition.wait()
    }
    condition.unlock()
    return true
  }

  func finishStop() {
    condition.lock()
    precondition(phase == .stopping)
    precondition(inFlightSamplers == 0)
    phase = .idle
    condition.broadcast()
    condition.unlock()
  }
}

struct WinsPacketTunnelEngineStartResult {
  let engineReady: Bool
  let statusFields: [String: Any]
}

struct WinsPacketTunnelEngineBundleProbe {
  static let schemaVersion = 1
  static let missingNativeEngineProbe = "missing_native_engine_library"
  static let nativeEngineAdapterMissingProbe = "native_engine_adapter_missing"

  private static let bundleArtifactNamesByComponent = [
    "amneziawg_packet_engine": [
      "WinsAmneziaWGPacketEngine",
      "AmneziaWGPacketEngine",
      "amneziawg_packet_engine"
    ],
    "xray_vless_ws_transport": [
      "WinsXrayVlessWsTransport",
      "XrayVlessWsTransport",
      "xray_vless_ws_transport"
    ],
    "winn_packet_engine": [
      "WinsWinnPacketEngine",
      "WinnPacketEngine",
      "winn_packet_engine"
    ]
  ]

  private static let linkedProbeSymbolByComponent = [
    "amneziawg_packet_engine": "wins_amneziawg_packet_engine_contract_version",
    "xray_vless_ws_transport": "wins_xray_vless_ws_transport_contract_version",
    "winn_packet_engine": "wins_winn_packet_engine_contract_version"
  ]

  let requiredComponents: [String]
  let availableComponents: [String]
  let missingComponents: [String]

  init(requiredComponents: [String], availableComponents: [String] = []) {
    let sanitizedRequired = Self.sanitizedComponentIdentifiers(requiredComponents)
    let sanitizedAvailable = Self.sanitizedComponentIdentifiers(availableComponents)
    let availableSet = Set(sanitizedAvailable)

    self.requiredComponents = sanitizedRequired
    self.availableComponents = sanitizedRequired.filter { availableSet.contains($0) }
    self.missingComponents = sanitizedRequired.filter { !availableSet.contains($0) }
  }

  var allRequiredComponentsPresent: Bool {
    !requiredComponents.isEmpty && missingComponents.isEmpty
  }

  var probeCode: String {
    allRequiredComponentsPresent
      ? Self.nativeEngineAdapterMissingProbe
      : Self.missingNativeEngineProbe
  }

  var statusFields: [String: Any] {
    [
      "engine_bundle_probe_schema_version": Self.schemaVersion,
      "engine_bundle_probe": probeCode,
      "engine_bundle_required_components": requiredComponents,
      "engine_bundle_available_components": availableComponents,
      "engine_bundle_missing_components": missingComponents,
      "engine_bundle_required_component_count": requiredComponents.count,
      "engine_bundle_available_component_count": availableComponents.count,
      "engine_bundle_missing_component_count": missingComponents.count,
      "engine_bundle_all_required_components_present": allRequiredComponentsPresent
    ]
  }

  static func probe(
    requiredComponents: [String],
    bundle: Bundle = .main,
    fileManager: FileManager = .default
  ) -> WinsPacketTunnelEngineBundleProbe {
    let availableComponents = sanitizedComponentIdentifiers(requiredComponents).filter { component in
      bundleContainsArtifact(for: component, bundle: bundle, fileManager: fileManager)
    }
    return WinsPacketTunnelEngineBundleProbe(
      requiredComponents: requiredComponents,
      availableComponents: availableComponents
    )
  }

  private static func sanitizedComponentIdentifiers(_ components: [String]) -> [String] {
    var seen = Set<String>()
    var result: [String] = []
    for rawComponent in components {
      let component = rawComponent
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
      guard isSafeComponentIdentifier(component),
            !seen.contains(component) else {
        continue
      }
      seen.insert(component)
      result.append(component)
    }
    return result
  }

  private static func isSafeComponentIdentifier(_ value: String) -> Bool {
    let scalars = value.unicodeScalars
    guard !scalars.isEmpty, scalars.count <= 80 else {
      return false
    }
    return scalars.allSatisfy { scalar in
      switch scalar.value {
      case 48...57, 65...90, 97...122, 45, 95:
        return true
      default:
        return false
      }
    }
  }

  private static func bundleContainsArtifact(
    for component: String,
    bundle: Bundle,
    fileManager: FileManager
  ) -> Bool {
    if processContainsLinkedArtifact(for: component) {
      return true
    }
    let artifactNames = bundleArtifactNamesByComponent[component] ?? [component]
    return artifactNames.contains { artifactName in
      bundle.url(forResource: artifactName, withExtension: "framework") != nil ||
        bundle.url(forResource: artifactName, withExtension: "dylib") != nil ||
        bundle.url(forResource: artifactName, withExtension: nil) != nil ||
        bundle.url(forAuxiliaryExecutable: artifactName) != nil ||
        bundle.url(forAuxiliaryExecutable: "\(artifactName).dylib") != nil ||
        bundlePathContainsArtifact(
          artifactName,
          bundle: bundle,
          fileManager: fileManager
        )
    }
  }

  private static func processContainsLinkedArtifact(for component: String) -> Bool {
    guard let symbol = linkedProbeSymbolByComponent[component],
          let handle = dlopen(nil, RTLD_NOW | RTLD_LOCAL) else {
      return false
    }
    defer { dlclose(handle) }
    return dlsym(handle, symbol) != nil
  }

  private static func bundlePathContainsArtifact(
    _ artifactName: String,
    bundle: Bundle,
    fileManager: FileManager
  ) -> Bool {
    let candidateDirectories = [
      containingAppFrameworksURL(bundle: bundle),
      bundle.privateFrameworksURL,
      bundle.resourceURL,
      bundle.resourceURL?.appendingPathComponent("Frameworks", isDirectory: true),
      bundle.resourceURL?.appendingPathComponent("Libraries", isDirectory: true),
      bundle.executableURL?.deletingLastPathComponent()
    ].compactMap { $0 }
    let candidateFileNames = [
      "\(artifactName).framework",
      "lib\(artifactName).dylib",
      "\(artifactName).dylib",
      artifactName
    ]

    for directory in candidateDirectories {
      for fileName in candidateFileNames {
        let candidateURL = directory.appendingPathComponent(fileName)
        if fileName.hasSuffix(".framework") {
          let binaryName = String(fileName.dropLast(".framework".count))
          let binaryURL = candidateURL.appendingPathComponent(binaryName)
          if fileManager.fileExists(atPath: binaryURL.path) {
            return true
          }
        } else if fileManager.fileExists(atPath: candidateURL.path) {
          return true
        }
      }
    }
    return false
  }

  private static func containingAppFrameworksURL(bundle: Bundle) -> URL? {
    let plugInsURL = bundle.bundleURL.deletingLastPathComponent()
    guard plugInsURL.lastPathComponent == "PlugIns" else {
      return nil
    }
    return plugInsURL
      .deletingLastPathComponent()
      .appendingPathComponent("Frameworks", isDirectory: true)
  }
}

protocol WinsPacketTunnelEngine: AnyObject {
  var plan: WinsPacketTunnelEnginePlan { get }
  var isRunning: Bool { get }

  func start() throws -> WinsPacketTunnelEngineStartResult
  func stop()

  /// A LIVE sample of the running engine's own observability counters, as
  /// status-document fields. Safe to call at any time, from any thread, on a
  /// stopped or never-started engine — it never blocks the datapath and returns
  /// an empty dictionary when there is nothing to sample.
  ///
  /// # Why this exists on the protocol
  ///
  /// `start()` returns the fields ONCE, at start. That was enough while nothing
  /// read the engine after start, but the staged winn/3 datapath proof gate
  /// must watch `transport_observed_both_ways` change from false to true while
  /// the session is still in its BOOTSTRAP posture — which is a question about
  /// the engine's state NOW, not at start. A start-time snapshot can never
  /// answer it.
  ///
  /// # Missing counters stay missing
  ///
  /// A counter this engine could not sample is OMITTED, never defaulted to 0.
  /// A 0 that actually means "not measured" would recreate exactly the
  /// blindness these counters exist to remove, and — because the proof gate
  /// treats a missing flag as false — a fabricated 0 would be a fabricated
  /// proof. An engine that cannot report is an engine that has proven nothing.
  func seamObservabilityStatusFields() -> [String: Any]
}

extension WinsPacketTunnelEngine {
  /// Default for every engine that samples nothing: the missing engine, the
  /// AmneziaWG carrier (whose runtime exposes no promotion field to this
  /// provider), and offline test doubles. Deliberately empty rather than
  /// synthesised — see the protocol comment.
  func seamObservabilityStatusFields() -> [String: Any] {
    [:]
  }
}

protocol WinsPacketTunnelEngineAdapter {
  func makeEngine(plan: WinsPacketTunnelEnginePlan, packetFlow: AnyObject) -> WinsPacketTunnelEngine?
}

struct WinsPacketTunnelEngineLaunchDescriptor {
  static let schemaVersion = 1

  let config: WinsTunnelConfig

  var statusFields: [String: Any] {
    var fields: [String: Any] = [
      "engine_launch_descriptor_schema_version": Self.schemaVersion,
      "engine_launch_descriptor_ready": true,
      "engine_launch_descriptor_secret_material_redacted": true,
      "engine_launch_descriptor_config_source": "validated_wins_tunnel_config",
      "engine_launch_descriptor_transport_mode": config.transportMode,
      "engine_launch_contract_version": WinsPacketTunnelEnginePlan.launchContractVersion,
      "engine_packet_flow_required": true,
      "engine_interface_private_key_present": !config.interfacePrivateKey.isEmpty,
      "engine_interface_private_key_redacted": true,
      "engine_peer_public_key_present": !config.peerPublicKey.isEmpty,
      "engine_peer_public_key_redacted": true,
      "engine_peer_preshared_key_present": !config.peerPresharedKey.isEmpty,
      "engine_peer_preshared_key_redacted": true,
      "engine_peer_keepalive_present": config.persistentKeepaliveWasDeclared,
      "engine_peer_keepalive_seconds": config.persistentKeepaliveSeconds,
      "engine_awg_obfuscation_present": config.awgObfuscation != nil,
      "engine_awg_obfuscation_field_count": config.awgObfuscation?.fieldCount ?? 0,
      "engine_awg_uapi_config_ready": (try? config.amneziaWGUAPIConfiguration()) != nil,
      "engine_awg_uapi_secret_material_redacted": true,
      "engine_allowed_ipv4_route_count": config.allowedIPv4Routes.count,
      "engine_default_route_enabled": config.defaultIPv4RouteEnabled,
      "engine_ipv6_leak_protection_enabled": config.ipv6LeakProtectionEnabled,
      "engine_ipv6_sink_prefix_length": config.ipv6SinkPrefixLength,
      "engine_dns_server_count": config.dnsServers.count,
      "engine_full_tunnel_dns_match_enabled": config.fullTunnelDNSMatchEnabled,
      "engine_mtu": config.mtu,
      "engine_peer_endpoint_kind": config.peerEndpointKind,
      "engine_transport_endpoint_kind": config.transportEndpointKind,
      "engine_network_settings_remote_address_kind": config.networkSettingsRemoteAddressKind,
      "engine_network_settings_remote_address_source": config.networkSettingsRemoteAddressSource,
      "engine_transport_ipv4_exclusion_route_present": config.transportIPv4ExclusionRoute != nil,
      "engine_xray_transport_required": config.xrayEnabled
    ]
    if let xray = config.xrayRuntimeConfig {
      fields["engine_xray_uuid_present"] = !xray.uuid.isEmpty
      fields["engine_xray_uuid_redacted"] = true
      fields["engine_xray_security"] = xray.security
      fields["engine_xray_host_present"] = !xray.host.isEmpty
      fields["engine_xray_host_redacted"] = true
      fields["engine_xray_server_name_present"] = !xray.serverName.isEmpty
      fields["engine_xray_server_name_redacted"] = true
      fields["engine_xray_path_present"] = !xray.path.isEmpty
      fields["engine_xray_path_redacted"] = true
      fields["engine_xray_remote_port_present"] = xray.port > 0
      fields["engine_xray_local_port_present"] = xray.localPort > 0
      fields["engine_xray_remote_awg_loopback"] = xray.remoteAwgHost == "127.0.0.1"
      fields["engine_xray_remote_awg_port_present"] = xray.remoteAwgPort > 0
    }
    return fields
  }
}

struct WinsPacketTunnelEnginePlan {
  static let adapterVersion = 1
  static let launchContractVersion = 1
  static let missingNativeEngineProbe = WinsPacketTunnelEngineBundleProbe.missingNativeEngineProbe

  let transportMode: String
  let requiredComponents: [String]
  let bundleProbe: WinsPacketTunnelEngineBundleProbe
  let launchDescriptor: WinsPacketTunnelEngineLaunchDescriptor
  let packetFlowAvailable: Bool

  init(
    config: WinsTunnelConfig,
    availableBundleComponents: [String] = [],
    packetFlowAvailable: Bool = false
  ) {
    self.init(
      config: config,
      bundleProbe: WinsPacketTunnelEngineBundleProbe(
        requiredComponents: config.requiredEngineComponents,
        availableComponents: availableBundleComponents
      ),
      packetFlowAvailable: packetFlowAvailable
    )
  }

  init(
    config: WinsTunnelConfig,
    bundleProbe: WinsPacketTunnelEngineBundleProbe,
    packetFlowAvailable: Bool = false
  ) {
    transportMode = config.transportMode
    requiredComponents = config.requiredEngineComponents
    self.bundleProbe = bundleProbe
    launchDescriptor = WinsPacketTunnelEngineLaunchDescriptor(config: config)
    self.packetFlowAvailable = packetFlowAvailable
  }

  var missingEngineMessage: String {
    if bundleProbe.allRequiredComponentsPresent && !packetFlowAvailable {
      return "Apple Packet Tunnel target is present, but the Packet Tunnel packet flow is unavailable for the native engine."
    }
    if bundleProbe.allRequiredComponentsPresent {
      return "Apple Packet Tunnel target is present, but the Win's VPN native packet engine adapter was not available at runtime."
    }
    let missing = bundleProbe.missingComponents.isEmpty ? requiredComponents : bundleProbe.missingComponents
    return "Apple Packet Tunnel target is present, but the Win's VPN native packet engine is not bundled yet. Missing components: \(missing.joined(separator: ", "))."
  }

  var statusFields: [String: Any] {
    var fields: [String: Any] = [
      "engine_adapter_version": Self.adapterVersion,
      "engine_adapter_required": true,
      "engine_adapter_available": false,
      "engine_transport_mode": transportMode,
      "engine_required_components": requiredComponents,
      "engine_packet_flow_available": packetFlowAvailable,
      "engine_lifecycle_state": "not_started"
    ]
    fields.merge(bundleProbe.statusFields) { _, new in new }
    fields.merge(launchDescriptor.statusFields) { _, new in new }
    return fields
  }
}

enum WinsPacketTunnelEngineFactory {
  static func makeEngine(
    config: WinsTunnelConfig,
    bundle: Bundle = .main,
    packetFlow: AnyObject? = nil,
    adapter: WinsPacketTunnelEngineAdapter? = nil
  ) -> WinsPacketTunnelEngine {
    let bundleProbe = WinsPacketTunnelEngineBundleProbe.probe(
      requiredComponents: config.requiredEngineComponents,
      bundle: bundle
    )
    let plan = WinsPacketTunnelEnginePlan(
      config: config,
      bundleProbe: bundleProbe,
      packetFlowAvailable: packetFlow != nil
    )
    if bundleProbe.allRequiredComponentsPresent,
       let packetFlow,
       let adapter,
       let engine = adapter.makeEngine(plan: plan, packetFlow: packetFlow) {
      return WinsAdapterBackedPacketTunnelEngine(engine: engine, plan: plan)
    }
    return WinsMissingPacketTunnelEngine(plan: plan)
  }
}

enum WinsPacketTunnelProviderLifecycle {
  static let schemaVersion = 1

  static func statusFields(event: String, engineRunning: Bool) -> [String: Any] {
    [
      "lifecycle_schema_version": schemaVersion,
      "lifecycle_event": event,
      "lifecycle_engine_running": engineRunning,
      "lifecycle_suspended": event == "sleep"
    ]
  }
}

final class WinsTunnelOperationGate {
  private let lock = NSLock()
  private var generation: UInt64 = 0

  /// Runs a scope without advancing the operation generation.
  /// The action must not reenter this nonrecursive gate.
  func withLock<Result>(_ action: () -> Result) -> Result {
    lock.lock()
    defer { lock.unlock() }
    return action()
  }

  @discardableResult
  func begin() -> UInt64 {
    begin(perform: {})
  }

  @discardableResult
  func begin(perform action: () -> Void) -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    generation &+= 1
    if generation == 0 {
      generation = 1
    }
    action()
    return generation
  }

  @discardableResult
  func invalidate() -> UInt64 {
    begin()
  }

  @discardableResult
  func invalidate(perform action: () -> Void) -> UInt64 {
    begin(perform: action)
  }

  func isCurrent(_ candidate: UInt64) -> Bool {
    guard candidate != 0 else { return false }
    lock.lock()
    defer { lock.unlock() }
    return generation == candidate
  }

  @discardableResult
  func performIfCurrent(_ candidate: UInt64, action: () -> Void) -> Bool {
    guard candidate != 0 else { return false }
    lock.lock()
    defer { lock.unlock() }
    guard generation == candidate else { return false }
    action()
    return true
  }
}

struct WinsPacketTunnelProviderAppMessage {
  static let schemaVersion = 2
  static let maxAcceptedMessageBytes = 4_096
  static let maxResponseMessageBytes = 4_096
  private static let healthCommand = "health"
  private static let supportedTransportModes: Set<String> = [
    "amneziawg",
    "xray_vless_ws_amneziawg",
    "winn",
    "xray_vless_ws_winn"
  ]

  let command: String
  let accepted: Bool
  let messageBytes: Int
  let messageTooLarge: Bool
  let engineRunning: Bool
  let transportMode: String
  let xrayEnabled: Bool
  let providerExecutableSHA256: String

  init(
    messageData: Data,
    engineRunning: Bool,
    transportMode: String = "",
    xrayEnabled: Bool = false,
    providerExecutableSHA256: String = ""
  ) {
    messageBytes = messageData.count
    messageTooLarge = messageData.count > Self.maxAcceptedMessageBytes
    self.engineRunning = engineRunning
    self.transportMode = Self.safeTransportMode(transportMode)
    self.xrayEnabled = xrayEnabled
    self.providerExecutableSHA256 = Self.safeSHA256(providerExecutableSHA256)

    let parsedCommand = messageTooLarge ? "" : Self.command(from: messageData)
    command = parsedCommand.isEmpty ? "invalid" : parsedCommand
    accepted = !messageTooLarge && command == Self.healthCommand
  }

  var statusFields: [String: Any] {
    [
      "app_message_schema_version": Self.schemaVersion,
      "app_message_command": command,
      "app_message_command_is_health": command == Self.healthCommand,
      "app_message_accepted": accepted,
      "app_message_bytes": messageBytes,
      "app_message_too_large": messageTooLarge,
      "app_message_raw_payload_redacted": true,
      "app_message_engine_running": engineRunning
    ]
  }

  var responseData: Data? {
    let response: [String: Any] = [
      "response_schema_version": Self.schemaVersion,
      "command": command,
      "accepted": accepted,
      "engine_running": engineRunning,
      "transport_mode": transportMode,
      "xray_enabled": xrayEnabled,
      "provider_executable_sha256": providerExecutableSHA256,
      "message_too_large": messageTooLarge,
      "raw_payload_redacted": true
    ]
    return try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
  }

  static func safeResponseCommand(_ rawCommand: String) -> String {
    let command = sanitizedCommand(rawCommand)
    return command.isEmpty ? "invalid" : command
  }

  static func healthProbeResponseStatusFields(
    responseData: Data?,
    expectedProviderExecutableSHA256: String = ""
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "provider_message_probe_raw_payload_redacted": true,
      "provider_message_probe_response_redacted": true,
      "provider_message_probe_response_json_valid": false,
      "provider_message_probe_response_too_large": false,
      "provider_message_probe_response_bytes": responseData?.count ?? 0,
      "provider_message_probe_response_max_bytes": maxResponseMessageBytes,
      "provider_message_probe_command_is_health": false,
      "provider_message_probe_response_schema_supported": false,
      "provider_message_probe_transport_mode_supported": false,
      "provider_message_probe_transport_mode_consistent": false,
      "provider_message_probe_executable_sha256_matches_expected": false
    ]

    guard let responseData else {
      fields["provider_message_probe_healthy"] = false
      fields["provider_message_probe_accepted"] = false
      fields["provider_message_probe_engine_running"] = false
      fields["provider_message_probe_response_schema_version"] = 0
      return fields
    }

    guard responseData.count <= maxResponseMessageBytes else {
      fields["provider_message_probe_healthy"] = false
      fields["provider_message_probe_accepted"] = false
      fields["provider_message_probe_engine_running"] = false
      fields["provider_message_probe_response_schema_version"] = 0
      fields["provider_message_probe_response_too_large"] = true
      return fields
    }

    guard let response = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
      fields["provider_message_probe_healthy"] = false
      fields["provider_message_probe_accepted"] = false
      fields["provider_message_probe_engine_running"] = false
      fields["provider_message_probe_response_schema_version"] = 0
      return fields
    }

    let accepted = response["accepted"] as? Bool == true
    let engineRunning = response["engine_running"] as? Bool == true
    let command = safeResponseCommand(response["command"] as? String ?? "")
    let responseSchemaVersion = response["response_schema_version"] as? Int ?? 0
    let rawPayloadRedacted = response["raw_payload_redacted"] as? Bool == true
    let transportMode = safeTransportMode(response["transport_mode"] as? String ?? "")
    let xrayEnabled = response["xray_enabled"] as? Bool == true
    let providerExecutableSHA256 = safeSHA256(
      response["provider_executable_sha256"] as? String ?? ""
    )
    let expectedExecutableSHA256 = safeSHA256(expectedProviderExecutableSHA256)
    let commandIsHealth = command == Self.healthCommand
    let responseSchemaSupported = responseSchemaVersion == schemaVersion
    let transportModeSupported = supportedTransportModes.contains(transportMode)
    let transportModeConsistent = transportModeSupported &&
      (xrayEnabled == transportMode.hasPrefix("xray_vless_ws_"))
    let executableSHA256MatchesExpected = !expectedExecutableSHA256.isEmpty &&
      providerExecutableSHA256 == expectedExecutableSHA256
    fields["provider_message_probe_accepted"] = accepted
    fields["provider_message_probe_engine_running"] = engineRunning
    fields["provider_message_probe_healthy"] =
      accepted &&
      engineRunning &&
      commandIsHealth &&
      responseSchemaSupported &&
      rawPayloadRedacted &&
      transportModeConsistent &&
      executableSHA256MatchesExpected
    fields["provider_message_probe_command"] = command
    fields["provider_message_probe_command_is_health"] = commandIsHealth
    fields["provider_message_probe_response_schema_version"] = responseSchemaVersion
    fields["provider_message_probe_response_schema_supported"] = responseSchemaSupported
    fields["provider_message_probe_response_redacted"] = rawPayloadRedacted
    fields["provider_message_probe_response_json_valid"] = true
    fields["provider_message_probe_transport_mode"] = transportMode
    fields["provider_message_probe_xray_enabled"] = xrayEnabled
    fields["provider_message_probe_transport_mode_supported"] = transportModeSupported
    fields["provider_message_probe_transport_mode_consistent"] = transportModeConsistent
    fields["provider_message_probe_executable_sha256"] = providerExecutableSHA256
    fields["provider_message_probe_executable_sha256_matches_expected"] =
      executableSHA256MatchesExpected
    return fields
  }

  private static let runningExecutableDigest = computeExecutableDigest(.main)

  private static func computeExecutableDigest(_ bundle: Bundle) -> String {
    guard let executableURL = bundle.executableURL,
          let data = try? Data(
            contentsOf: executableURL,
            options: [.mappedIfSafe]
          ) else {
      return ""
    }
    return SHA256.hash(data: data)
      .map { String(format: "%02x", $0) }
      .joined()
  }

  static func bundleExecutableSHA256(_ bundle: Bundle) -> String {
    if bundle.bundleURL == Bundle.main.bundleURL,
       bundle.executableURL == Bundle.main.executableURL {
      return runningExecutableDigest
    }
    return computeExecutableDigest(bundle)
  }

  static func embeddedProviderExecutableSHA256(in hostBundle: Bundle) -> String {
    guard let pluginsURL = hostBundle.builtInPlugInsURL,
          let providerBundle = Bundle(
            url: pluginsURL.appendingPathComponent("PacketTunnel.appex", isDirectory: true)
          ) else {
      return ""
    }
    return bundleExecutableSHA256(providerBundle)
  }

  private static func command(from messageData: Data) -> String {
    guard !messageData.isEmpty else {
      return healthCommand
    }

    if let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
       let command = object["command"] as? String {
      return sanitizedCommand(command)
    }

    if let rawCommand = String(data: messageData, encoding: .utf8) {
      return sanitizedCommand(rawCommand)
    }

    return ""
  }

  private static func sanitizedCommand(_ rawCommand: String) -> String {
    let command = rawCommand
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()
    let scalars = command.unicodeScalars
    guard !scalars.isEmpty, scalars.count <= 32 else {
      return ""
    }
    let isSafe = scalars.allSatisfy { scalar in
      switch scalar.value {
      case 48...57, 97...122, 45, 46, 95:
        return true
      default:
        return false
      }
    }
    return isSafe ? command : ""
  }

  private static func safeTransportMode(_ rawValue: String) -> String {
    let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return supportedTransportModes.contains(value) ? value : ""
  }

  private static func safeSHA256(_ rawValue: String) -> String {
    let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard value.count == 64,
          value.unicodeScalars.allSatisfy({ scalar in
            (48...57).contains(scalar.value) || (97...102).contains(scalar.value)
          }) else {
      return ""
    }
    return value
  }
}

enum WinsPacketTunnelProviderStatus {
  static let schemaVersion = 2
  static let networkExtensionType = "packet_tunnel"
  static let maxStatusFileBytes = 65_536
  private static let mappedStatusStringMaxLength = 256
  private static let mappedStatusArrayStringMaxLength = 96
  private static let mappedStatusArrayMaxCount = 16
  private static let jsonWriteOptions: JSONSerialization.WritingOptions = [.prettyPrinted, .sortedKeys]
  private static let mappedStatusArrayKeys: Set<String> = [
    "dns_match_domains",
    "required_engine_components",
    "engine_bundle_required_components",
    "engine_bundle_available_components",
    "engine_bundle_missing_components",
    "engine_required_components"
  ]
  private static let rawMappedStatusFragments = [
    "/users/",
    "group containers",
    "latest_tunnel.conf",
    "latest_status.json",
    "privatekey",
    "private key",
    "presharedkey",
    "preshared key",
    "endpoint =",
    "publickey =",
    "allowedips =",
    "address =",
    "http://",
    "https://"
  ]
  private static let compactExtraKeys: Set<String> = [
    "status_generation",
    "config_source",
    "config_source_available",
    "config_file_present",
    "config_file_readable",
    "config_file_symbolic_link",
    "config_file_too_large",
    "config_too_large",
    "config_utf8_valid",
    "config_empty",
    "config_size_bytes",
    "config_max_size_bytes",
    "config_shared_path_present",
    "config_shared_path_allowed",
    "config_shared_path_matches_expected",
    "config_shared_path_inside_app_group",
    "config_app_group_id_present",
    "config_app_group_id_allowed",
    "config_app_group_container_available",
    "dev_containment_at_stop",
    "dev_containment_active",
    "dev_containment_requested",
    "dev_containment_kind",
    "dev_containment_test_route_usable",
    "dev_containment_ipv6_settings_installed",
    "dev_containment_observed_contained",
    "dev_containment_supported_by_build",
    "private_key_source",
    "shared_config_private_key_redacted",
    "shared_keychain_private_key_available",
    "client_key_pair_verification_required",
    "expected_client_public_key_available",
    "expected_client_public_key_source",
    "expected_client_public_key_valid",
    "client_key_pair_verified",
    "network_settings_applied",
    "network_settings_release_requested",
    "network_settings_release_outcome",
    "network_settings_release_completed",
    "network_settings_release_failed",
    "network_settings_release_elapsed_ms",
    "network_settings_release_deadline_ms",
    "network_settings_release_error_domain",
    "network_settings_release_error_code",
    "engine_adapter_available",
    "engine_lifecycle_state",
    "engine_bundle_probe",
    "engine_bundle_all_required_components_present",
    "engine_transport_mode",
    "engine_launch_descriptor_ready",
    "engine_launch_descriptor_secret_material_redacted",
    "engine_awg_uapi_config_ready",
    "engine_awg_uapi_secret_material_redacted",
    "engine_packet_flow_available",
    "engine_runtime_packet_flow_attached",
    "engine_runtime_contract_failed",
    "engine_runtime_engine_ready_reported",
    "engine_runtime_engine_running_reported",
    "engine_runtime_secret_material_redacted",
    "engine_runtime_status_sanitized",
    "app_message_schema_version",
    "app_message_command",
    "app_message_command_is_health",
    "app_message_accepted",
    "app_message_bytes",
    "app_message_too_large",
    "app_message_raw_payload_redacted",
    "app_message_engine_running",
    "lifecycle_schema_version",
    "lifecycle_event",
    "lifecycle_engine_running",
    "lifecycle_suspended",
    "engine_was_running_before_stop",
    "previous_stage_before_stop",
    "previous_healthy_before_stop",
    "previous_engine_ready_before_stop",
    "previous_network_settings_ready_before_stop",
    "previous_network_settings_applied_before_stop",
    "previous_peer_endpoint_kind_before_stop",
    "previous_transport_endpoint_kind_before_stop",
    "previous_network_settings_remote_address_kind_before_stop",
    "previous_network_settings_remote_address_source_before_stop",
    "previous_transport_mode_before_stop",
    "previous_xray_enabled_before_stop",
    "previous_engine_transport_mode_before_stop",
    "previous_engine_bundle_probe_before_stop",
    "previous_engine_bundle_all_required_components_present_before_stop",
    "previous_engine_runtime_engine_ready_reported_before_stop",
    "previous_engine_runtime_engine_running_reported_before_stop",
    "previous_app_message_command_before_stop",
    "previous_app_message_command_is_health_before_stop",
    "previous_app_message_accepted_before_stop",
    "previous_app_message_raw_payload_redacted_before_stop",
    "previous_app_message_engine_running_before_stop",
    "winn_memory_gate_available_bytes",
    "winn_memory_gate_refusal_reason",
    "stop_reason",
    "winn3_start_outcome",
    "winn3_ordinary_network_unreachability",
    "winn3_ordinary_network_posix_errno",
    "start_canceled",
    "winn_datapath_proof_timeout",
    "winn_datapath_proof_engine_exited",
    "persisted_live_secret_material_refused",
    "winn3_datapath_proof_start_refusal_reason",
    "winn3_descriptor_node_bound"
  ]
  static let knownStages: Set<String> = [
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

  static func validStage(_ stage: String) -> Bool {
    knownStages.contains(stage)
  }

  static func safeStatusGeneration(_ value: String?) -> String {
    guard let value else {
      return ""
    }
    return safeMappedStatusString(value, maxLength: 64) ?? ""
  }

  static func preferredStatusGeneration(saved: String?, transient: String?) -> String {
    let savedGeneration = safeStatusGeneration(saved)
    if !savedGeneration.isEmpty {
      return savedGeneration
    }
    return safeStatusGeneration(transient)
  }

  static func preferredClientPublicKey(saved: String?, transient: String?) -> String {
    preferredClientPublicKeySelection(saved: saved, transient: transient).publicKey
  }

  static func preferredClientPublicKeySource(saved: String?, transient: String?) -> String {
    preferredClientPublicKeySelection(saved: saved, transient: transient).source
  }

  static func preferredClientPublicKeySelection(
    saved: String?,
    transient: String?
  ) -> (publicKey: String, source: String) {
    let savedKey = saved?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !savedKey.isEmpty {
      return (savedKey, "saved_tunnel_preference")
    }
    let transientKey = transient?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !transientKey.isEmpty {
      return (transientKey, "transient_start_options")
    }
    return ("", "missing")
  }

  static func safeClientKeyAccountScope(_ value: String?) -> String {
    guard let value else {
      return ""
    }
    return safeMappedStatusString(value, maxLength: 64) ?? ""
  }

  // The saved provider configuration always reflects whichever account scope
  // last had a shared config file written for it (both are written together
  // in the same startTunnel call), so it takes priority over the transient
  // start options. An empty result (e.g. a provider preference saved before
  // this scoping existed) intentionally falls back to WinsClientKeyStore's
  // legacy unscoped Keychain item rather than failing the tunnel start.
  static func preferredClientKeyAccountScope(saved: String?, transient: String?) -> String {
    let savedScope = safeClientKeyAccountScope(saved)
    if !savedScope.isEmpty {
      return savedScope
    }
    return safeClientKeyAccountScope(transient)
  }

  static func safeMappedStatusValue(_ value: Any, sourceKey: String) -> Any? {
    switch value {
    case let bool as Bool where isNativeStatusScalar(value, typeName: "Bool"):
      return bool
    case let int as Int where isNativeStatusScalar(value, typeName: "Int"):
      return int
    case let int32 as Int32 where isNativeStatusScalar(value, typeName: "Int32"):
      return Int(int32)
    case let int64 as Int64 where isNativeStatusScalar(value, typeName: "Int64"):
      guard int64 <= Int64(Int.max), int64 >= Int64(Int.min) else {
        return nil
      }
      return Int(int64)
    case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID():
      return number.boolValue
    case let number as NSNumber:
      return safeStatusNumber(number)
    case let string as String:
      if sourceKey == "status_generation" {
        let generation = safeStatusGeneration(string)
        return generation.isEmpty ? nil : generation
      }
      return safeMappedStatusString(string, maxLength: mappedStatusStringMaxLength)
    case let array as [Any] where mappedStatusArrayKeys.contains(sourceKey):
      let values = array.compactMap { element -> String? in
        guard let string = element as? String else {
          return nil
        }
        return safeMappedStatusString(
          string,
          maxLength: mappedStatusArrayStringMaxLength,
          allowEmpty: sourceKey == "dns_match_domains"
        )
      }.prefix(mappedStatusArrayMaxCount)
      let mappedValues = Array(values)
      return mappedValues.isEmpty ? nil : mappedValues
    default:
      return nil
    }
  }

  static func safeStatusByteCount(_ value: UInt64) -> Int {
    guard value <= UInt64(Int.max) else {
      return Int.max
    }
    return Int(value)
  }

  static func payload(
    stage: String,
    providerBundleIdentifier: String,
    config: WinsTunnelConfig? = nil,
    engineReady: Bool = false,
    networkSettingsReady: Bool = false,
    error: Error? = nil,
    extra: [String: Any] = [:],
    fallbackStatusGeneration: String = "",
    updatedAt: Date = Date()
  ) -> [String: Any] {
    var payload: [String: Any] = [
      "status_schema_version": schemaVersion,
      "updated_at": ISO8601DateFormatter().string(from: updatedAt),
      "stage": stage,
      "healthy": error == nil && engineReady && networkSettingsReady,
      "engine_ready": engineReady,
      "network_settings_ready": networkSettingsReady,
      "provider_bundle_id": providerBundleIdentifier,
      "network_extension_type": networkExtensionType
    ]

    if let config {
      payload.merge(configStatusFields(config)) { _, new in new }
    }

    if let error {
      let nsError = error as NSError
      payload["error_domain"] = nsError.domain
      payload["error_code"] = nsError.code
      payload["error_message"] = WinsTunnelDiagnostics.redactedProviderErrorMessage(nsError)
    }

    for (key, value) in extra {
      payload[key] = value
    }
    let payloadStatusGeneration = safeStatusGeneration(payload["status_generation"] as? String)
    let fallbackGeneration = safeStatusGeneration(fallbackStatusGeneration)
    if payloadStatusGeneration.isEmpty {
      payload.removeValue(forKey: "status_generation")
    } else {
      payload["status_generation"] = payloadStatusGeneration
    }
    if payloadStatusGeneration.isEmpty, !fallbackGeneration.isEmpty {
      payload["status_generation"] = fallbackGeneration
    }

    return payload
  }

  static func writableData(
    stage: String,
    providerBundleIdentifier: String,
    config: WinsTunnelConfig? = nil,
    engineReady: Bool = false,
    networkSettingsReady: Bool = false,
    error: Error? = nil,
    extra: [String: Any] = [:],
    fallbackStatusGeneration: String = "",
    updatedAt: Date = Date()
  ) throws -> Data {
    let fullPayload = payload(
      stage: stage,
      providerBundleIdentifier: providerBundleIdentifier,
      config: config,
      engineReady: engineReady,
      networkSettingsReady: networkSettingsReady,
      error: error,
      extra: extra,
      fallbackStatusGeneration: fallbackStatusGeneration,
      updatedAt: updatedAt
    )
    let fullData = try data(from: fullPayload)
    guard fullData.count > maxStatusFileBytes else {
      return fullData
    }

    let compactPayload = compactWritablePayload(
      stage: stage,
      providerBundleIdentifier: providerBundleIdentifier,
      engineReady: engineReady,
      networkSettingsReady: networkSettingsReady,
      error: error,
      extra: extra,
      fallbackStatusGeneration: fallbackStatusGeneration,
      updatedAt: updatedAt
    )
    let compactData = try data(from: compactPayload)
    guard compactData.count > maxStatusFileBytes else {
      return compactData
    }

    return try data(from: minimalWritablePayload(
      stage: stage,
      providerBundleIdentifier: providerBundleIdentifier,
      updatedAt: updatedAt
    ))
  }

  private static func data(from payload: [String: Any]) throws -> Data {
    try JSONSerialization.data(
      withJSONObject: payload,
      options: jsonWriteOptions
    )
  }

  private static func compactWritablePayload(
    stage: String,
    providerBundleIdentifier: String,
    engineReady: Bool,
    networkSettingsReady: Bool,
    error: Error?,
    extra: [String: Any],
    fallbackStatusGeneration: String,
    updatedAt: Date
  ) -> [String: Any] {
    var compact = minimalWritablePayload(
      stage: stage,
      providerBundleIdentifier: providerBundleIdentifier,
      updatedAt: updatedAt
    )
    compact["engine_ready"] = engineReady
    compact["network_settings_ready"] = networkSettingsReady
    compact["status_write_limited"] = true
    compact["status_write_payload_too_large"] = true
    compact["status_write_original_stage"] = safeStatusString(stage, maxLength: 64) ?? "unknown"

    if let error {
      let nsError = error as NSError
      compact["error_domain"] = safeStatusString(nsError.domain, maxLength: 128)
      compact["error_code"] = nsError.code
      compact["error_message"] = WinsTunnelDiagnostics.redactedProviderErrorMessage(nsError)
    }

    for key in compactExtraKeys.sorted() {
      guard let value = extra[key],
            let compactValue = safeCompactValue(value) else {
        continue
      }
      compact[key] = compactValue
    }

    let payloadStatusGeneration = safeStatusGeneration(compact["status_generation"] as? String)
    let fallbackGeneration = safeStatusGeneration(fallbackStatusGeneration)
    if payloadStatusGeneration.isEmpty {
      compact.removeValue(forKey: "status_generation")
    } else {
      compact["status_generation"] = payloadStatusGeneration
    }
    if payloadStatusGeneration.isEmpty, !fallbackGeneration.isEmpty {
      compact["status_generation"] = fallbackGeneration
    }

    return compact
  }

  private static func minimalWritablePayload(
    stage: String,
    providerBundleIdentifier: String,
    updatedAt: Date
  ) -> [String: Any] {
    [
      "status_schema_version": schemaVersion,
      "updated_at": ISO8601DateFormatter().string(from: updatedAt),
      "stage": stage,
      "healthy": false,
      "engine_ready": false,
      "network_settings_ready": false,
      "provider_bundle_id": providerBundleIdentifier,
      "network_extension_type": networkExtensionType,
      "status_write_limited": true,
      "status_write_payload_too_large": true
    ]
  }

  private static func safeCompactValue(_ value: Any) -> Any? {
    switch value {
    case let bool as Bool where isNativeStatusScalar(value, typeName: "Bool"):
      return bool
    case let int as Int where isNativeStatusScalar(value, typeName: "Int"):
      return int
    case let int32 as Int32 where isNativeStatusScalar(value, typeName: "Int32"):
      return Int(int32)
    case let int64 as Int64 where isNativeStatusScalar(value, typeName: "Int64"):
      guard int64 <= Int64(Int.max), int64 >= Int64(Int.min) else {
        return nil
      }
      return Int(int64)
    case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID():
      return number.boolValue
    case let number as NSNumber:
      return safeStatusNumber(number)
    case let string as String:
      return safeStatusString(string, maxLength: 128)
    default:
      return nil
    }
  }

  private static func safeStatusString(_ value: String, maxLength: Int) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty,
          trimmed.count <= maxLength,
          trimmed.rangeOfCharacter(from: .controlCharacters) == nil else {
      return nil
    }
    return trimmed
  }

  private static func safeStatusNumber(_ number: NSNumber) -> Int? {
    if CFGetTypeID(number) == CFBooleanGetTypeID() {
      return nil
    }
    let type = String(cString: number.objCType)
    switch type {
    case "i", "s", "l", "q":
      let value = number.int64Value
      guard value <= Int64(Int.max), value >= Int64(Int.min) else {
        return nil
      }
      return Int(value)
    case "I", "S", "L", "Q":
      let value = number.uint64Value
      guard value <= UInt64(Int.max) else {
        return nil
      }
      return Int(value)
    default:
      return nil
    }
  }

  private static func isNativeStatusScalar(_ value: Any, typeName: String) -> Bool {
    String(describing: Mirror(reflecting: value).subjectType) == typeName
  }

  private static func safeMappedStatusString(
    _ value: String,
    maxLength: Int,
    allowEmpty: Bool = false
  ) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard (allowEmpty || !trimmed.isEmpty),
          trimmed.count <= maxLength,
          trimmed.rangeOfCharacter(from: .controlCharacters) == nil,
          !containsRawMappedStatusFragment(trimmed) else {
      return nil
    }
    return trimmed
  }

  private static func containsRawMappedStatusFragment(_ value: String) -> Bool {
    let lowercased = value.lowercased()
    if rawMappedStatusFragments.contains(where: { lowercased.contains($0) }) {
      return true
    }
    return value.range(
      of: #"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"#,
      options: .regularExpression
    ) != nil
  }

  private static func configStatusFields(_ config: WinsTunnelConfig) -> [String: Any] {
    var fields: [String: Any] = [
      "peer_endpoint_present": !config.peerEndpoint.isEmpty,
      "peer_endpoint_kind": config.peerEndpointKind,
      "transport_endpoint_kind": config.transportEndpointKind,
      "network_settings_remote_address_kind": config.networkSettingsRemoteAddressKind,
      "network_settings_remote_address_source": config.networkSettingsRemoteAddressSource,
      "interface_ipv4_address_present": !config.interfaceIPv4Address.isEmpty,
      "route_count": config.allowedIPv4Routes.count,
      "default_route_enabled": config.defaultIPv4RouteEnabled,
      "ipv6_leak_protection_enabled": config.ipv6LeakProtectionEnabled,
      "ipv6_sink_address_present": config.ipv6LeakProtectionEnabled && !config.ipv6SinkAddress.isEmpty,
      "ipv6_sink_prefix_length": config.ipv6SinkPrefixLength,
      "transport_ipv4_route_excluded": config.transportIPv4ExclusionRoute != nil,
      "transport_ipv4_exclusion_route_present": config.transportIPv4ExclusionRoute != nil,
      "dns_count": config.dnsServers.count,
      "dns_match_domains": config.dnsMatchDomains,
      "dns_full_tunnel_match_enabled": config.fullTunnelDNSMatchEnabled,
      "mtu": config.mtu,
      "xray_enabled": config.xrayEnabled,
      "transport_mode": config.transportMode,
      "required_engine_components": config.requiredEngineComponents,
      "awg_obfuscation_present": config.awgObfuscation != nil
    ]
    if let xray = config.xrayRuntimeConfig {
      fields["xray_host_present"] = !xray.host.isEmpty
      fields["xray_server_name_present"] = !xray.serverName.isEmpty
      fields["xray_path_present"] = !xray.path.isEmpty
      fields["xray_security"] = xray.security
      fields["xray_local_port_present"] = xray.localPort > 0
      fields["xray_remote_awg_loopback"] = xray.remoteAwgHost == "127.0.0.1"
      fields["xray_remote_awg_port_present"] = xray.remoteAwgPort > 0
    }
    return fields
  }
}

struct WinsPacketTunnelEngineError: LocalizedError, CustomNSError {
  static let errorDomain = "org.winsvpn.PacketTunnelEngine"
  static let statusFieldsUserInfoKey = "wins_packet_tunnel_engine_status_fields"
  static let missingNativeEngineCode = 1003
  static let adapterStartContractCode = 1004

  let code: Int
  let message: String
  let statusFields: [String: Any]

  init(code: Int, message: String, statusFields: [String: Any] = [:]) {
    self.code = code
    self.message = message
    self.statusFields = statusFields
  }

  var errorDescription: String? {
    message
  }

  var errorCode: Int {
    code
  }

  var errorUserInfo: [String: Any] {
    var userInfo: [String: Any] = [NSLocalizedDescriptionKey: message]
    if !statusFields.isEmpty {
      userInfo[Self.statusFieldsUserInfoKey] = statusFields
    }
    return userInfo
  }
}

final class WinsMissingPacketTunnelEngine: WinsPacketTunnelEngine {
  let plan: WinsPacketTunnelEnginePlan
  private(set) var isRunning = false

  init(plan: WinsPacketTunnelEnginePlan) {
    self.plan = plan
  }

  convenience init(config: WinsTunnelConfig, bundleProbe: WinsPacketTunnelEngineBundleProbe? = nil) {
    self.init(
      plan: WinsPacketTunnelEnginePlan(
        config: config,
        bundleProbe: bundleProbe ?? WinsPacketTunnelEngineBundleProbe(
          requiredComponents: config.requiredEngineComponents
        ),
        packetFlowAvailable: false
      )
    )
  }

  func start() throws -> WinsPacketTunnelEngineStartResult {
    throw WinsPacketTunnelEngineError(
      code: WinsPacketTunnelEngineError.missingNativeEngineCode,
      message: plan.missingEngineMessage,
      statusFields: plan.statusFields
    )
  }

  func stop() {
    isRunning = false
  }
}

enum WinsPacketTunnelEngineRuntimeStatus {
  private static let maxRuntimeStatusKeyScalars = 80
  private static let maxRuntimeStatusStringScalars = 96
  private static let maxRuntimeStatusArrayCount = 16
  private static let deniedRuntimeStatusFragments = [
    "private",
    "preshared",
    "publickey",
    "endpoint",
    "address",
    "host",
    "server",
    "path",
    "port",
    "uuid",
    "key",
    "http",
    "user"
  ]

  static func sanitizedAdapterStatusFields(
    _ rawFields: [String: Any],
    plan: WinsPacketTunnelEnginePlan,
    engineReady: Bool
  ) -> [String: Any] {
    var fields = plan.statusFields

    for (rawKey, rawValue) in rawFields {
      guard let key = safeRuntimeStatusKey(rawKey),
            let value = safeRuntimeStatusValue(rawValue) else {
        continue
      }
      fields[key] = value
    }

    fields["engine_adapter_available"] = true
    fields["engine_lifecycle_state"] = engineReady ? "running" : "starting"
    fields["engine_runtime_secret_material_redacted"] = true
    fields["engine_runtime_status_sanitized"] = true
    return fields
  }

  private static func safeRuntimeStatusKey(_ rawKey: String) -> String? {
    let key = rawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard key.hasPrefix("engine_runtime_"),
          key.unicodeScalars.count <= maxRuntimeStatusKeyScalars,
          key.unicodeScalars.allSatisfy(isRuntimeIdentifierScalar),
          !containsDeniedRuntimeStatusFragment(key) else {
      return nil
    }
    return key
  }

  private static func safeRuntimeStatusValue(_ value: Any) -> Any? {
    switch value {
    case let bool as Bool where isNativeRuntimeStatusScalar(value, typeName: "Bool"):
      return bool
    case let int as Int where isNativeRuntimeStatusScalar(value, typeName: "Int"):
      return int
    case let int32 as Int32 where isNativeRuntimeStatusScalar(value, typeName: "Int32"):
      return Int(int32)
    case let int64 as Int64 where isNativeRuntimeStatusScalar(value, typeName: "Int64"):
      guard int64 <= Int64(Int.max), int64 >= Int64(Int.min) else {
        return nil
      }
      return Int(int64)
    case let number as NSNumber:
      return safeRuntimeStatusNumber(number)
    case let string as String:
      return safeRuntimeStatusString(string)
    case let array as [Any]:
      let values = array.compactMap { element -> String? in
        guard let string = element as? String else {
          return nil
        }
        return safeRuntimeStatusString(string)
      }.prefix(maxRuntimeStatusArrayCount)
      let mappedValues = Array(values)
      return mappedValues.isEmpty ? nil : mappedValues
    default:
      return nil
    }
  }

  private static func safeRuntimeStatusString(_ rawValue: String) -> String? {
    let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !value.isEmpty,
          value.unicodeScalars.count <= maxRuntimeStatusStringScalars,
          value.unicodeScalars.allSatisfy(isRuntimeIdentifierScalar),
          !containsDeniedRuntimeStatusFragment(value) else {
      return nil
    }
    return value
  }

  private static func safeRuntimeStatusNumber(_ number: NSNumber) -> Int? {
    if CFGetTypeID(number) == CFBooleanGetTypeID() {
      return nil
    }
    let type = String(cString: number.objCType)
    switch type {
    case "i", "s", "l", "q":
      let value = number.int64Value
      guard value <= Int64(Int.max), value >= Int64(Int.min) else {
        return nil
      }
      return Int(value)
    case "I", "S", "L", "Q":
      let value = number.uint64Value
      guard value <= UInt64(Int.max) else {
        return nil
      }
      return Int(value)
    default:
      return nil
    }
  }

  private static func isRuntimeIdentifierScalar(_ scalar: UnicodeScalar) -> Bool {
    switch scalar.value {
    case 48...57, 97...122, 45, 95:
      return true
    default:
      return false
    }
  }

  private static func containsDeniedRuntimeStatusFragment(_ value: String) -> Bool {
    let tokens = value.split { scalar in
      scalar == "_" || scalar == "-"
    }
    return tokens.contains { token in
      deniedRuntimeStatusFragments.contains(String(token))
    }
  }

  private static func isNativeRuntimeStatusScalar(_ value: Any, typeName: String) -> Bool {
    String(describing: Mirror(reflecting: value).subjectType) == typeName
  }
}

extension WinsPacketTunnelEngineRuntimeStatus {
  /// The same key/value filter `sanitizedAdapterStatusFields` applies, without
  /// the plan fields — for callers that publish a live sample rather than a
  /// start result. Belt and braces: every key this file mints comes from a
  /// fixed allowlist already, and still goes through the shared filter, so a
  /// future allowlist edit cannot smuggle a secret-bearing field past it.
  static func sanitizedRuntimeFields(_ rawFields: [String: Any]) -> [String: Any] {
    var fields: [String: Any] = [:]
    for (rawKey, rawValue) in rawFields {
      guard let key = safeRuntimeStatusKey(rawKey),
            let value = safeRuntimeStatusValue(rawValue) else {
        continue
      }
      fields[key] = value
    }
    return fields
  }
}

/// Turns the two JSON documents the Winn wrapper can produce into
/// status-document fields.
///
/// PURE, and internal for that reason: an offline driver compiles this and
/// predicts exactly which fields a live sample would publish, with no engine,
/// no socket and no session — the same way the staged start's gate is
/// predicted.
///
/// # Why an allowlist and not a filter
///
/// `WinnTunnelStatusJSON` carries `gateway_endpoint`, `local_endpoint` and
/// `session_id`. `WinnTunnel.h` calls the gateway endpoint "secret-bearing and
/// process-local: never log it", and this file's output is written to the
/// provider status document, which the app reads and a bug report can carry.
/// So NO string field of that document is published, ever, and the numeric and
/// boolean fields that are published are named one by one below. A denylist
/// would publish any field a future archive adds; this publishes only what has
/// been read and judged safe.
enum WinsWinnSeamObservabilitySample {
  /// Fields sampled from the Go engine's own status document — what the ENGINE
  /// saw.
  static let engineFieldPrefix = "engine_runtime_winn_engine_"
  /// Fields sampled from the wrapper's seam counters — what reached, or failed
  /// to reach, the engine. Read them together: the burst-loss defect was
  /// visible only on the seam side.
  ///
  /// The seam document's own keys are already `seam_`-prefixed, so this stops
  /// at `engine_runtime_winn_` and the published key is
  /// `engine_runtime_winn_seam_rx_ring_dropped`, not a stuttering
  /// `..._winn_seam_seam_rx_ring_dropped`. The Go document's keys are bare, so
  /// its prefix carries the `engine_` segment itself.
  ///
  /// RESTORED 2026-08-08. This is the 2026-08-06 author's own design (git
  /// object `934f7b4`, engine file line 2146, where the constant is spelled
  /// `seamKeyPrefix`); they identified this exact hazard and wrote the comment
  /// above to prevent it. The trailing `seam_` came back in a later
  /// generation, which doubled all fifteen published seam keys. Do not
  /// "helpfully" re-add it, and do not strip `seam_` from the names in
  /// `seamIntegerFields` below instead — those names are the native seam
  /// document's own keys, and renaming them would break the lookup in
  /// `fields(…)` against the document `wins_winn_packet_engine_seam_stats`
  /// actually produces. The prefix is the half that was wrong.
  static let seamFieldPrefix = "engine_runtime_winn_"

  /// Booleans of the engine status document that may be published.
  ///
  /// `up` is included as a DIAGNOSTIC only. `WinnTunnel.h` is explicit that a
  /// route-promotion gate may not read it — it is true for a socket that has
  /// never carried a byte — and the only gate in this project that could is
  /// `WinsWinnDatapathProofGate`, which reads the two `*_observed*` flags and
  /// nothing else.
  static let engineBooleanFields = [
    "up",
    "closed",
    "socket_owned_by_engine",
    "gateway_sender_filter",
    "handshake_response_observed",
    "transport_observed_both_ways",
    // winn/3 STANDALONE. `winn3_may_carry` is the tun gate as a boolean and is
    // a DIAGNOSTIC here for the same reason `up` is: it says the session
    // believes DATA may flow, not that anything reached this host.
    // `WinsWinn3PromotionGate` gates on the gate state AND a delivered packet,
    // and on nothing else.
    "winn3_may_carry",
    "winn3_runtime_completed"
  ]

  /// Integers of the engine status document that may be published.
  static let engineIntegerFields = [
    "max_datagram",
    "queue_depth",
    "queue_length",
    "uptime_ms",
    "tx_datagrams",
    "tx_bytes",
    "tx_rejected",
    "tx_handshake_initiations",
    "tx_transport_datagrams",
    "tx_transport_payload_datagrams",
    "rx_datagrams",
    "rx_bytes",
    "rx_dropped",
    "rx_oversize",
    "rx_foreign_sender",
    "rx_handshake_responses",
    "rx_transport_datagrams",
    "rx_transport_payload_datagrams",
    // winn/3 STANDALONE. `winn3_rx_packets` is the promotion counter —
    // DELIVERIES — and `winn3_rx_offered` is ARRIVALS. Both are published, and
    // published together, because the whole failure mode here is a host that
    // gates on the second believing it is the first.
    "winn3_rx_packets",
    "winn3_rx_offered",
    "winn3_rx_bytes",
    "winn3_tx_packets",
    "winn3_tx_bytes",
    "winn3_tx_dropped_closed",
    "winn3_rx_dropped_closed",
    "winn3_rx_dropped_invalid",
    // `winn3_tx_dropped_invalid` is the OUTBOUND refusal and is published
    // alongside its inbound twin above, because a host holding only one of the
    // pair reads the missing direction as a healthy tunnel. It is the gate OPEN
    // and the packet refused anyway — most often a source address the session
    // was never assigned, which is the packet that would have identified this
    // host past the gateway.
    //
    // Safe to publish under the rule this allowlist encodes: it is a COUNT of
    // packets the engine refused locally, so it carries no address, no endpoint
    // and no identifier. Before it was here the only evidence the refusal had
    // fired was a packet capture, which is not available on a user's phone.
    "winn3_tx_dropped_invalid",
    "winn3_inner_mtu",
    "winn3_plan_message_size",
    // RENAMED 2026-08-09 from `winn3_plan_path_mtu`, and the rename is the
    // whole point: `sanitizedRuntimeFields` splits every key on `_`/`-` and
    // drops it if any token is in `deniedRuntimeStatusFragments`, which holds
    // `path`. So this entry was here, both host apps forwarded it, and the
    // host never once received it. The denylist keeps endpoints, hostnames and
    // file paths out of a document a bug report carries — that is a real
    // control under this threat model and it was NOT weakened. The key moved
    // instead. Keep the Go json tag and this string identical: renaming one
    // side alone recreates the same silence with a different cause.
    "winn3_plan_mtu_ceiling",
    "winn3_messages_sent",
    "winn3_messages_received",
    "winn3_migrations",
    // RENAMED 2026-08-09 from `winn3_host_queue_dropped_{outbound,inbound}`,
    // which died on the denied `host` token exactly as above. These two are
    // the ONLY evidence that the ring between the engine and this host
    // overflowed, so while they were being eaten, host-side packet loss was
    // unobservable on Apple: a user reporting a slow or lossy tunnel produced
    // a diagnostic bundle with the cause silently missing.
    "winn3_queue_dropped_outbound",
    "winn3_queue_dropped_inbound"
  ]

  /// Strings of the engine status document that may be published.
  ///
  /// There is exactly one class of them and it exists for one field:
  /// `winn3_gate_state`, the tun layer's gate rendered as
  /// `winn3/tun.State.String()`. It is a string rather than a boolean because
  /// the gate is not a boolean — `down`, `handshaking`, `epoch0`, `rekeying`,
  /// `closed` and `carrying` are six distinct states, only one of which
  /// carries, and collapsing them at the sampler would throw away the
  /// diagnostic that tells a reader WHY a promotion has not happened yet.
  ///
  /// Values are length-capped and passed through the same sanitizer as every
  /// other field, so a hostile or corrupt document cannot inject an unbounded
  /// string into a status document the app displays.
  static let engineStringFields = [
    "winn3_gate_state",
    "winn3_carrier_class"
  ]

  /// Closed-vocabulary strings of the engine status document (Round A2): the
  /// supervised engine's recovery state and, when it is `blocked`, the cause
  /// it OBSERVED. Lower-case identifiers with no address, endpoint or
  /// identifier in them; every token of every published key clears
  /// `deniedRuntimeStatusFragments`.
  ///
  /// These are NOT sampled like `engineStringFields`, because for them an
  /// ABSENT key and a PRESENT but unusable one mean different things: absent
  /// is an engine older than the field and keeps the rule it had before,
  /// while present-invalid (a non-string, an empty or oversized string, or a
  /// value outside the vocabulary, compared exactly and before any case
  /// folding) is a document this host must not believe. So a valid value is
  /// published under its own key, and an invalid one publishes NO value and
  /// the boolean `<name>_invalid` instead, which `WinsWinn3Lifecycle` reads
  /// as a refusal of both the connected claim and promotion.
  static let engineVocabularyFields: [(name: String, vocabulary: Set<String>)] = [
    ("winn3_lifecycle", ["connecting", "connected", "recovering", "blocked", "stopped"]),
    ("winn3_lifecycle_cause", ["never_established", "budget_spent", "terminal"])
  ]

  /// The flag published beside a present-invalid vocabulary field.
  static let invalidVocabularySuffix = "_invalid"

  /// The longest a sampled string field may be. Every legitimate value is under
  /// a dozen characters; anything longer is not a state name.
  static let maximumStringFieldLength = 64

  /// The fifteen counters `wins_winn_packet_engine_seam_stats` serialises.
  /// Every one is an integer the wrapper counted itself — nothing here is
  /// config-derived, which is why the whole set is publishable.
  static let seamIntegerFields = [
    "seam_rx_datagrams",
    "seam_rx_bytes",
    "seam_rx_ring_dropped",
    "seam_rx_foreign_sender",
    "seam_rx_oversize",
    "seam_tx_written",
    "seam_tx_too_large",
    "seam_tx_failed",
    "seam_sent_to_awg",
    "seam_send_failed",
    "seam_no_peer",
    "seam_ring_slots",
    "seam_ring_queued",
    "seam_rx_backlog_high_water_bytes",
    "seam_rcvbuf_bytes"
  ]

  /// Every status-document key this type can publish. `WinsWinnSeamObservability`
  /// forwards exactly this list app-side, so the two can never drift.
  ///
  /// It also carries the Apple host's own lifecycle verdict
  /// (`WinsWinn3Lifecycle.hostStatusKeys`), which is derived beside the engine
  /// sample rather than sampled; listing it here is what gives it a path to
  /// the app, because the app forwarder iterates exactly this list.
  static var publishedStatusKeys: [String] {
    engineBooleanFields.map { engineFieldPrefix + $0 }
      + engineIntegerFields.map { engineFieldPrefix + $0 }
      + engineStringFields.map { engineFieldPrefix + $0 }
      + engineVocabularyFields.flatMap { field in
        [engineFieldPrefix + field.name, engineFieldPrefix + field.name + invalidVocabularySuffix]
      }
      + seamIntegerFields.map { seamFieldPrefix + $0 }
      + WinsWinn3Lifecycle.hostStatusKeys
  }

  /// Maps whichever of the two documents could be sampled. A document that is
  /// nil, empty, unparseable or not a JSON object contributes NOTHING rather
  /// than defaults — see the protocol comment on `seamObservabilityStatusFields`.
  static func fields(
    seamStatsJSON: String?,
    engineStatusJSON: String?
  ) -> [String: Any] {
    var fields: [String: Any] = [:]
    if let document = jsonObject(engineStatusJSON) {
      for name in engineBooleanFields {
        guard let value = document[name] else { continue }
        guard let flag = boolean(value) else { continue }
        fields[engineFieldPrefix + name] = flag
      }
      for name in engineIntegerFields {
        guard let value = document[name], let number = integer(value) else { continue }
        fields[engineFieldPrefix + name] = number
      }
      for name in engineStringFields {
        guard let text = string(value: document[name]) else { continue }
        fields[engineFieldPrefix + name] = text
      }
      for field in engineVocabularyFields {
        // `document[name]` is nil only when the key is absent; a JSON null is
        // NSNull, which is present and invalid.
        guard let value = document[field.name] else { continue }
        if let text = value as? String, field.vocabulary.contains(text) {
          fields[engineFieldPrefix + field.name] = text
        } else {
          fields[engineFieldPrefix + field.name + invalidVocabularySuffix] = true
        }
      }
    }
    if let document = jsonObject(seamStatsJSON) {
      for name in seamIntegerFields {
        guard let value = document[name], let number = integer(value) else { continue }
        fields[seamFieldPrefix + name] = number
      }
    }
    return WinsPacketTunnelEngineRuntimeStatus.sanitizedRuntimeFields(fields)
  }

  private static func jsonObject(_ json: String?) -> [String: Any]? {
    guard let json,
          !json.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          let data = json.data(using: .utf8),
          let parsed = try? JSONSerialization.jsonObject(with: data),
          let document = parsed as? [String: Any] else {
      return nil
    }
    return document
  }

  /// A JSON `true`/`false` only. A number is NOT accepted as a boolean here:
  /// the flags this reads are the promotion gate's inputs, and a permissive
  /// coercion is how a non-boolean becomes a proof.
  private static func boolean(_ value: Any) -> Bool? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID() else {
      return nil
    }
    return number.boolValue
  }

  private static func integer(_ value: Any) -> NSNumber? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID() else {
      return nil
    }
    return number
  }

  /// A JSON string only, length-capped. A number is NOT stringified: the one
  /// field this reads is a state name, and a coercion here is how "3" becomes a
  /// state nobody defined.
  private static func string(value: Any?) -> String? {
    guard let text = value as? String,
          !text.isEmpty,
          text.count <= maximumStringFieldLength else {
      return nil
    }
    return text
  }
}

/// The app-side forwarding list for the Winn seam counters.
///
/// # Why this is a forwarder and not a list
///
/// The host apps map provider status fields into their own `provider_*`
/// diagnostic namespace with hand-written, name-by-name tables
/// (`ios/Runner/AppDelegate.swift`, `macos/Runner/MainFlutterWindow.swift`).
/// Hand-copying the seam counters into those tables would drift the first time
/// a counter was added, and the resulting symptom — a counter silently missing
/// from diagnostics — is the exact blindness this line of work exists to
/// remove. So both apps iterate this list instead, and this list is *derived*
/// from the producer rather than retyped.
///
/// `WinsWinnSeamObservabilitySample` above is that producer: it owns the field
/// names and the prefixes, and mints every key it can publish. Forwarding its
/// `publishedStatusKeys` verbatim is what makes the two sides unable to drift,
/// which is the invariant stated on that type.
///
/// # Provenance — read before "restoring" more of this type
///
/// A 2026-08-06 version of this enum (git object `934f7b4`, engine file line
/// 2125) was a 245-line *producer*: it carried `BufferedDocumentFunction`, its
/// own buffer sizes, four availability-flag keys and a `statusFields(…)` that
/// sampled the wrapper directly. That design was superseded on 2026-08-08 by
/// `WinsWinnSeamObservabilitySample`, which samples via
/// `WinnObservabilityDocumentFunction`, publishes 39 keys rather than 33, and
/// coerces booleans strictly because those flags are a promotion gate's inputs.
///
/// Re-adding the old body beside the new producer would create a second,
/// 33-key list drifting from the live 39-key one — precisely the failure both
/// generations were written to prevent. If you are here to recover the
/// 2026-08-08 `git reset --hard`, this forwarder *is* the recovered form.
/// See `docs/handoff/WINN3_IOS_INSTRUMENTATION_RECOVERED_20260808.md`.
enum WinsWinnSeamObservability {

  /// Status-document keys carrying Winn seam and engine counters, in the
  /// producer's order. Both call sites prefix each key with `provider_` and run
  /// the value through the same sanitizer as their explicit mapping tables.
  ///
  /// A key listed here whose value was not sampled forwards nothing: both loops
  /// are guarded by `if let value = status[source]`. That is deliberate — a
  /// counter that could not be measured stays absent rather than being
  /// defaulted to 0, because a 0 meaning "not measured" would recreate the
  /// blindness these counters exist to remove.
  static var publishedStatusKeys: [String] {
    WinsWinnSeamObservabilitySample.publishedStatusKeys
  }
}

// MARK: - Staged winn/3 start (shared by every Apple packet-tunnel provider)
//
// HOISTED here on 2026-08-08 from `ios/PacketTunnel/PacketTunnelProvider.swift`,
// where these three types were file-private and therefore invisible to the macOS
// appex — which referenced them and could not build. They are NOT copied per
// platform on purpose: a second private proof gate would let one platform
// promote a tunnel onto weaker evidence than the other, silently. The iOS and
// macOS copies were compared before the move and differed only in four comment
// words ("device"/"phone" vs "host"), so nothing behavioural was reconciled.
//
// This file already compiles into all four targets (both Runner apps and both
// PacketTunnel appexes) in both Xcode projects, so the move needed no
// `project.pbxproj` edit — the same route the `WinsWinnSeamObservability`
// forwarder above took. See
// `docs/handoff/MACOS_STAGED_PLAN_RESTORED_20260808.md`.
//
// What stays per-platform: `makeWinnStagedStartPlan`, the convergence loop and
// the hold check are instance methods on each `NEPacketTunnelProvider` subclass
// — they touch `setTunnelNetworkSettings`, `packetFlow`, the lifecycle gate and
// per-provider status writing, none of which exist here.

/// Both postures of a staged winn/3 start, built together before either is
/// installed so a start that cannot express BOTH is refused up front.
///
/// `promotionHeld` runs a staged start as far as PROVEN and then stops on
/// purpose, instead of promoting — the affordance that lets the gate be
/// exercised on a workstation without the session ever claiming that machine's
/// default route, IPv6 and DNS. It defaults to false, so a caller that does not
/// offer it behaves exactly as it did before this type was shared.
struct WinsWinnStagedStartPlan {
  let bootstrapSettings: NEPacketTunnelNetworkSettings
  let fullTunnelSettings: NEPacketTunnelNetworkSettings
  let interfaceIPv4Address: String
  let probeDNSServers: [String]
  let bootstrapStatusFields: [String: Any]
  let promotionHeld: Bool

  /// False when the first posture already IS the full tunnel (the kill-switch
  /// path hands the same object as both). Re-committing an identical
  /// settings object only adds an NE reconfiguration to connect time.
  var promotionInstallsNewSettings: Bool {
    bootstrapSettings !== fullTunnelSettings
  }

  init(
    bootstrapSettings: NEPacketTunnelNetworkSettings,
    fullTunnelSettings: NEPacketTunnelNetworkSettings,
    interfaceIPv4Address: String,
    probeDNSServers: [String],
    bootstrapStatusFields: [String: Any],
    promotionHeld: Bool = false
  ) {
    self.bootstrapSettings = bootstrapSettings
    self.fullTunnelSettings = fullTunnelSettings
    self.interfaceIPv4Address = interfaceIPv4Address
    self.probeDNSServers = probeDNSServers
    self.bootstrapStatusFields = bootstrapStatusFields
    self.promotionHeld = promotionHeld
  }
}

/// The PURE half of the staged winn/3 start: the applicability decision, the
/// bootstrap /32 derivation, the convergence predicate and the status-field
/// vocabulary. No sockets, no NetworkExtension calls, no state — deliberately,
/// so an offline driver can compile this file with WinsTunnelCore and predict
/// a staged start's posture before any session runs, exactly the way
/// `devContainmentPlan` is predicted for contained sessions.
///
/// Internal (not private) for that reason alone.
enum WinsWinnDatapathProofGate {
  /// Stable, greppable marker for every log line the gate emits. Unlike the
  /// containment absence probe this is SUPPOSED to be present in a Release
  /// binary: the staged start is shipping behaviour.
  static let logToken = "WINS_WINN_DATAPATH_PROOF_GATE"

  /// The two engine-status keys the gate reads, spelled once. They are the
  /// published names from `WinsWinnSeamObservability` — the handshake-response
  /// liveness bit and the field the Go datapath documents as "the single field
  /// a route-promotion gate may read". `up` is deliberately not here:
  /// WinnTunnel.h:221 forbids gating on it, and the Windows gate obeys the
  /// same rule.
  static let convergenceHandshakeKey =
    "engine_runtime_winn_engine_handshake_response_observed"
  static let convergenceTransportKey =
    "engine_runtime_winn_engine_transport_observed_both_ways"

  /// A start is staged exactly when it is a winn session that would otherwise
  /// seize the host device (default IPv4 route requested) and is not already
  /// running under dev containment (which never installs full-tunnel settings
  /// at all).
  static func applies(
    winnEnabled: Bool,
    defaultIPv4RouteEnabled: Bool,
    devContainmentActive: Bool
  ) -> Bool {
    winnEnabled && defaultIPv4RouteEnabled && !devContainmentActive
  }

  /// The one route a bootstrap posture may include: the tunnel's own inner
  /// gateway, `x.y.z.1` for interface address `x.y.z.n`. Same derivation as
  /// `WinsTunnelConfig.tunnelGatewayIPv4Address` (private there, restated here
  /// with the same semantics: nil when the interface address IS `.1`, so a
  /// route to self is never installed). An address inside the VPN's own space,
  /// routing nothing the host device owns.
  static func bootstrapGatewayRoute(interfaceIPv4Address: String) -> WinsIPv4Route? {
    guard let value = ipv4AddressValue(interfaceIPv4Address) else {
      return nil
    }
    let gatewayValue = (value & 0xffff_ff00) | 1
    guard gatewayValue != value else {
      return nil
    }
    return WinsIPv4Route(
      destinationAddress: ipv4AddressString(gatewayValue),
      subnetMask: "255.255.255.255",
      prefixLength: 32
    )
  }

  /// True only when the engine's own status document reports BOTH proofs: the
  /// handshake response was observed (the cryptographic path answered) and
  /// payload-class transport datagrams were observed in BOTH directions (the
  /// carrier delivers; keepalives and the handshake itself deliberately do not
  /// count, per `carriesTransportPayload` in the Go datapath). Missing keys
  /// are false: an engine that cannot report is an engine that has proven
  /// nothing.
  static func converged(engineStatusFields: [String: Any]) -> Bool {
    flag(engineStatusFields[convergenceHandshakeKey])
      && flag(engineStatusFields[convergenceTransportKey])
  }

  static func flag(_ value: Any?) -> Bool {
    if let boolValue = value as? Bool {
      return boolValue
    }
    if let numberValue = value as? NSNumber {
      return numberValue.boolValue
    }
    return false
  }

  /// The Windows convergence probe, byte for byte
  /// (`windows/runner/windows_tunnel_backend.cpp`): a minimal DNS A query for
  /// connectivitycheck.gstatic.com. The transaction id is local-only and no
  /// response content is ever retained or parsed; the sole purpose is to give
  /// the engine payload-class traffic to observe in both directions. On the
  /// wire outside the tunnel an observer sees only encrypted outer datagrams.
  static func dnsProbeQuery(transactionID: UInt16) -> [UInt8] {
    var query: [UInt8] = [
      UInt8(transactionID >> 8),
      UInt8(transactionID & 0xff),
      0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    ]
    query += [17]
    query += Array("connectivitycheck".utf8)
    query += [7]
    query += Array("gstatic".utf8)
    query += [3]
    query += Array("com".utf8)
    query += [0, 0x00, 0x01, 0x00, 0x01]
    return query
  }

  /// The static description of a bootstrap posture, merged into
  /// `verifiedStatusFields` BEFORE the first settings callback so every
  /// document a staged start can produce already carries it.
  static func bootstrapStatusFields(
    bootstrapIncludedRouteCount: Int,
    bootstrapGatewayRoutePresent: Bool,
    transportExclusionRoutePresent: Bool,
    probeTargetCount: Int
  ) -> [String: Any] {
    [
      "winn_datapath_proof_gate_active": true,
      "winn_datapath_proof_bootstrap_observably_narrow": true,
      "winn_datapath_proof_bootstrap_included_route_count": bootstrapIncludedRouteCount,
      "winn_datapath_proof_bootstrap_gateway_route_present": bootstrapGatewayRoutePresent,
      "winn_datapath_proof_bootstrap_default_ipv4_route_installed": false,
      "winn_datapath_proof_bootstrap_ipv6_settings_installed": false,
      "winn_datapath_proof_bootstrap_dns_settings_installed": false,
      "winn_datapath_proof_transport_exclusion_route_present": transportExclusionRoutePresent,
      "winn_datapath_proof_probe_target_count": probeTargetCount
    ]
  }

  /// The dynamic half, refreshed by the convergence loop and terminal writes.
  static func progressStatusFields(
    probeAvailable: Bool,
    probesSent: Int,
    probeResponsesObserved: Int,
    engineStatusFields: [String: Any],
    converged: Bool,
    promoted: Bool,
    elapsedMilliseconds: Int,
    deadlineMilliseconds: Int
  ) -> [String: Any] {
    [
      "winn_datapath_proof_gate_active": true,
      "winn_datapath_proof_probe_available": probeAvailable,
      "winn_datapath_proof_probe_response_required": probeAvailable,
      "winn_datapath_proof_probes_sent": probesSent,
      "winn_datapath_proof_probe_responses_observed": probeResponsesObserved,
      "winn_datapath_proof_handshake_response_observed":
        flag(engineStatusFields[convergenceHandshakeKey]),
      "winn_datapath_proof_transport_observed_both_ways":
        flag(engineStatusFields[convergenceTransportKey]),
      "winn_datapath_proof_converged": converged,
      "winn_datapath_proof_promoted": promoted,
      "winn_datapath_proof_elapsed_ms": elapsedMilliseconds,
      "winn_datapath_proof_deadline_ms": deadlineMilliseconds
    ]
  }

  static func ipv4AddressValue(_ address: String) -> UInt32? {
    let components = address.split(separator: ".", omittingEmptySubsequences: false)
    guard components.count == 4 else {
      return nil
    }
    var value: UInt32 = 0
    for component in components {
      guard component.count <= 3,
            !component.isEmpty,
            let octet = UInt32(component),
            octet <= 255 else {
        return nil
      }
      value = (value << 8) | octet
    }
    return value
  }

  static func ipv4AddressString(_ value: UInt32) -> String {
    "\((value >> 24) & 0xff).\((value >> 16) & 0xff).\((value >> 8) & 0xff).\(value & 0xff)"
  }
}

/// The in-tunnel convergence probe: one non-blocking UDP socket, bound to the
/// tunnel's own interface BY INDEX (`IP_BOUND_IF`) and to the tunnel's own
/// address as source. The interface binding — not the route table — is what
/// puts the probe inside the tunnel, so the bootstrap posture never needs a
/// route to a public resolver: a /32 to a real resolver in the route table
/// would capture unrelated host traffic to that resolver during the proof
/// window, and this class exists so that never happens.
///
/// The targets are the config's OWN resolvers — the exact servers every user
/// query will depend on after promotion — so the proof exercises precisely
/// what the full tunnel is about to promise. Against a lab echo gateway the
/// probe's payload comes straight back and converges the same fields; content
/// is never parsed either way.
final class WinsWinnDatapathProofProbe {
  private let socketDescriptor: Int32
  private let targets: [sockaddr_in]
  private var nextTargetIndex = 0
  private(set) var probesSent = 0
  private(set) var responsesObserved = 0

  init?(interfaceIPv4Address: String, dnsServers: [String]) {
    guard !interfaceIPv4Address.isEmpty else {
      return nil
    }
    let resolvedTargets: [sockaddr_in] = dnsServers.compactMap { server in
      var address = in_addr()
      guard inet_pton(AF_INET, server, &address) == 1 else {
        return nil
      }
      var target = sockaddr_in()
      target.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
      target.sin_family = sa_family_t(AF_INET)
      target.sin_port = in_port_t(53).bigEndian
      target.sin_addr = address
      return target
    }
    guard !resolvedTargets.isEmpty else {
      return nil
    }
    guard let interfaceName = Self.interfaceName(forIPv4Address: interfaceIPv4Address) else {
      return nil
    }
    var interfaceIndex = if_nametoindex(interfaceName)
    guard interfaceIndex != 0 else {
      return nil
    }
    let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
    guard descriptor >= 0 else {
      return nil
    }
    guard setsockopt(
      descriptor,
      IPPROTO_IP,
      IP_BOUND_IF,
      &interfaceIndex,
      socklen_t(MemoryLayout<UInt32>.size)
    ) == 0 else {
      close(descriptor)
      return nil
    }
    var localAddress = in_addr()
    guard inet_pton(AF_INET, interfaceIPv4Address, &localAddress) == 1 else {
      close(descriptor)
      return nil
    }
    var local = sockaddr_in()
    local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    local.sin_family = sa_family_t(AF_INET)
    local.sin_port = 0
    local.sin_addr = localAddress
    let bindResult = withUnsafePointer(to: &local) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        bind(descriptor, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    guard bindResult == 0 else {
      close(descriptor)
      return nil
    }
    let flags = fcntl(descriptor, F_GETFL, 0)
    guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
      close(descriptor)
      return nil
    }
    socketDescriptor = descriptor
    targets = resolvedTargets
  }

  func sendNextProbe() {
    guard !targets.isEmpty else {
      return
    }
    var target = targets[nextTargetIndex % targets.count]
    nextTargetIndex += 1
    var query = WinsWinnDatapathProofGate.dnsProbeQuery(
      transactionID: UInt16.random(in: UInt16.min...UInt16.max)
    )
    let sent = query.withUnsafeBytes { queryBytes in
      withUnsafePointer(to: &target) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
          sendto(
            socketDescriptor,
            queryBytes.baseAddress,
            queryBytes.count,
            0,
            socketAddress,
            socklen_t(MemoryLayout<sockaddr_in>.size)
          )
        }
      }
    }
    if sent == query.count {
      probesSent += 1
    }
    for index in query.indices {
      query[index] = 0
    }
  }

  func drainResponses() {
    var buffer = [UInt8](repeating: 0, count: 512)
    while true {
      let received = buffer.withUnsafeMutableBytes { bufferBytes in
        recv(socketDescriptor, bufferBytes.baseAddress, bufferBytes.count, 0)
      }
      guard received > 0 else {
        break
      }
      // Deliberately not parsed and immediately discarded — the datagram's
      // existence is the evidence, its content is nobody's business.
      responsesObserved += 1
      for index in buffer.indices {
        buffer[index] = 0
      }
    }
  }

  func invalidate() {
    close(socketDescriptor)
  }

  private static func interfaceName(forIPv4Address address: String) -> String? {
    var expected = in_addr()
    guard inet_pton(AF_INET, address, &expected) == 1 else {
      return nil
    }
    var interfaceList: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&interfaceList) == 0, let firstInterface = interfaceList else {
      return nil
    }
    defer { freeifaddrs(firstInterface) }
    var cursor: UnsafeMutablePointer<ifaddrs>? = firstInterface
    while let current = cursor {
      if let rawAddress = current.pointee.ifa_addr,
         rawAddress.pointee.sa_family == sa_family_t(AF_INET) {
        let interfaceAddress = rawAddress.withMemoryRebound(
          to: sockaddr_in.self,
          capacity: 1
        ) { $0.pointee.sin_addr }
        if interfaceAddress.s_addr == expected.s_addr {
          return String(cString: current.pointee.ifa_name)
        }
      }
      cursor = current.pointee.ifa_next
    }
    return nil
  }
}

final class WinsAdapterBackedPacketTunnelEngine: WinsPacketTunnelEngine {
  private let engine: WinsPacketTunnelEngine
  private let validatedPlan: WinsPacketTunnelEnginePlan

  var plan: WinsPacketTunnelEnginePlan {
    validatedPlan
  }

  var isRunning: Bool {
    engine.isRunning
  }

  init(engine: WinsPacketTunnelEngine, plan: WinsPacketTunnelEnginePlan) {
    self.engine = engine
    validatedPlan = plan
  }

  func start() throws -> WinsPacketTunnelEngineStartResult {
    let result = try engine.start()
    var fields = WinsPacketTunnelEngineRuntimeStatus.sanitizedAdapterStatusFields(
      result.statusFields,
      plan: validatedPlan,
      engineReady: result.engineReady
    )
    let packetFlowAttached = fields["engine_runtime_packet_flow_attached"] as? Bool == true
    let engineRunning = engine.isRunning
    guard result.engineReady, engineRunning, packetFlowAttached else {
      fields["engine_lifecycle_state"] = "failed"
      fields["engine_runtime_contract_failed"] = true
      fields["engine_runtime_engine_ready_reported"] = result.engineReady
      fields["engine_runtime_engine_running_reported"] = engineRunning
      fields["engine_runtime_packet_flow_attached"] = packetFlowAttached
      engine.stop()
      throw WinsPacketTunnelEngineError(
        code: WinsPacketTunnelEngineError.adapterStartContractCode,
        message: "Win's VPN native packet engine did not report a running packet flow.",
        statusFields: fields
      )
    }
    return WinsPacketTunnelEngineStartResult(
      engineReady: result.engineReady,
      statusFields: fields
    )
  }

  func stop() {
    engine.stop()
  }

  /// Straight through to the wrapped engine. Nothing is added, defaulted or
  /// remembered here: a live sample must describe the engine, not this
  /// decorator's idea of it.
  func seamObservabilityStatusFields() -> [String: Any] {
    engine.seamObservabilityStatusFields()
  }
}

final class WinsNativePacketTunnelEngineAdapter: WinsPacketTunnelEngineAdapter {
  private let bundle: Bundle
  private let fileManager: FileManager

  init(bundle: Bundle = .main, fileManager: FileManager = .default) {
    self.bundle = bundle
    self.fileManager = fileManager
  }

  func makeEngine(plan: WinsPacketTunnelEnginePlan, packetFlow: AnyObject) -> WinsPacketTunnelEngine? {
    WinsNativePacketTunnelEngine(
      plan: plan,
      packetFlow: packetFlow,
      bundle: bundle,
      fileManager: fileManager
    )
  }
}

/// The component that owns the packet path. AmneziaWG is what ships; Winn
/// Protocol is the additive second carrier. Both native wrappers export the
/// identical v1 Win's VPN C ABI shape, so only the symbol names differ.
private struct WinsPacketCarrier {
  let component: String
  let contractVersionSymbol: String
  let createSymbol: String
  let startSymbol: String
  let stopSymbol: String
  let destroySymbol: String
  let startedStatusField: String
  let createFailureMessage: String
  let startFailureMessage: String

  static let amneziaWG = WinsPacketCarrier(
    component: "amneziawg_packet_engine",
    contractVersionSymbol: "wins_amneziawg_packet_engine_contract_version",
    createSymbol: "wins_amneziawg_packet_engine_create",
    startSymbol: "wins_amneziawg_packet_engine_start",
    stopSymbol: "wins_amneziawg_packet_engine_stop",
    destroySymbol: "wins_amneziawg_packet_engine_destroy",
    startedStatusField: "engine_runtime_awg_started",
    createFailureMessage: "Win's VPN AmneziaWG packet engine was not created.",
    startFailureMessage: "Win's VPN AmneziaWG packet engine did not start."
  )

  static let winn = WinsPacketCarrier(
    component: "winn_packet_engine",
    contractVersionSymbol: "wins_winn_packet_engine_contract_version",
    createSymbol: "wins_winn_packet_engine_create",
    startSymbol: "wins_winn_packet_engine_start",
    stopSymbol: "wins_winn_packet_engine_stop",
    destroySymbol: "wins_winn_packet_engine_destroy",
    startedStatusField: "engine_runtime_winn_started",
    createFailureMessage: "Win's VPN Winn Protocol packet engine was not created.",
    startFailureMessage: "Win's VPN Winn Protocol packet engine did not start."
  )

  /// The additive SIXTH Winn wrapper symbol, deliberately outside the shared
  /// five-symbol carrier ABI that the generic loader resolves for every
  /// carrier. Only a Winn-aware caller looks it up; widening the shared ABI for
  /// something one carrier has would have made every other wrapper implement a
  /// no-op. Implemented at `apple/EngineWrappers/WinsWinnPacketEngine.m:1889`,
  /// required by `tools/build_apple_engine_wrappers.sh`, and checked for by
  /// `tools/verify_apple_readiness.sh`.
  ///
  /// Its absence is a FAILED CONNECTION, not a degraded one: without the port,
  /// AmneziaWG cannot be repointed, and an AmneziaWG that is not repointed is
  /// not carrying Winn at all. That is why `start()` resolves it with `try` and
  /// the two observability symbols are resolved with `try?`.
  static let winnSeamPortSymbol = "wins_winn_packet_engine_awg_seam_port"

  /// The host half of the endpoint AmneziaWG is repointed at. Written once,
  /// here, so the repoint and anything that later checks it cannot disagree.
  /// IPv4 loopback: the seam is a socket in this same process.
  static let winnSeamLoopbackHost = "127.0.0.1"

  static let all = [amneziaWG, winn]

  /// Resolves in `requiredComponents` order so the config decides the carrier
  /// and the order here never does.
  static func carrier(for requiredComponents: [String]) -> WinsPacketCarrier? {
    for component in requiredComponents {
      if let carrier = all.first(where: { $0.component == component }) {
        return carrier
      }
    }
    return nil
  }
}

private final class WinsNativePacketTunnelEngine: WinsPacketTunnelEngine {
  private typealias ContractVersionFunction = @convention(c) () -> Int32
  private typealias CarrierCreateFunction =
    @convention(c) (UnsafePointer<CChar>, UnsafeRawPointer?) -> UnsafeMutableRawPointer?
  private typealias CarrierStartFunction = @convention(c) (UnsafeMutableRawPointer?) -> Int32
  private typealias CarrierStopFunction = @convention(c) (UnsafeMutableRawPointer?) -> Void
  private typealias CarrierDestroyFunction = @convention(c) (UnsafeMutableRawPointer?) -> Void
  private typealias XrayConfigureFunction = @convention(c) (UnsafePointer<CChar>) -> Int32
  private typealias XrayStartFunction = @convention(c) () -> Int32
  private typealias XrayStopFunction = @convention(c) () -> Void
  /// Shape of `wins_winn_packet_engine_awg_seam_port`: `(engine) -> port`,
  /// where 0 is what the wrapper returns before start and after stop.
  private typealias WinnSeamPortFunction = @convention(c) (UnsafeMutableRawPointer?) -> Int32
  /// Shape of `wins_winn_packet_engine_expect_awg_port`: `(engine, port) -> 1|0`.
  private typealias WinnExpectAwgPortFunction =
    @convention(c) (UnsafeMutableRawPointer?, Int32) -> Int32
  /// Shape of both additive Winn observability symbols: `(engine, out,
  /// capacity) -> bytes written excluding the terminator, or 0`. Spelled with
  /// the same C types the wrapper declares — a difference that is merely
  /// ABI-compatible today is still a difference, and one that is not is memory
  /// corruption no linker can catch.
  private typealias WinnObservabilityDocumentFunction =
    @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?, Int32) -> Int32

  private struct WinnSamplePublication {
    let handle: UnsafeMutableRawPointer
    let component: WinsNativeEngineComponent
    let seamStats: WinnObservabilityDocumentFunction?
    let engineStatus: WinnObservabilityDocumentFunction?
  }

  /// Big enough for the Winn engine's full status document with headroom; the
  /// seam counters need a fraction of it. Both symbols write nothing and
  /// return 0 rather than truncating, so this only has to be generous.
  private static let observabilityDocumentCapacity = 8192

  let plan: WinsPacketTunnelEnginePlan

  private let packetFlow: AnyObject
  private let bundle: Bundle
  private let fileManager: FileManager
  private let lifetime = WinsNativeSamplerLifetime()
  private var loadedComponents: [WinsNativeEngineComponent] = []
  private var activeCarrier: WinsPacketCarrier?
  private var carrierHandle: UnsafeMutableRawPointer?
  /// The Winn seam engine, which is NOT `carrierHandle`. On Apple the carrier
  /// is always AmneziaWG (`WinsTunnelConfig.packetCarrierComponent`) and Winn is
  /// the additive seam in front of it, so the two handles are different engines
  /// with different lifetimes: the seam starts first and is destroyed last.
  private var winnSeamHandle: UnsafeMutableRawPointer?
  private var winnSamplePublication: WinnSamplePublication?
  private var xrayStop: XrayStopFunction?
  var isRunning: Bool { lifetime.isRunning }

  init(
    plan: WinsPacketTunnelEnginePlan,
    packetFlow: AnyObject,
    bundle: Bundle,
    fileManager: FileManager
  ) {
    self.plan = plan
    self.packetFlow = packetFlow
    self.bundle = bundle
    self.fileManager = fileManager
  }

  func start() throws -> WinsPacketTunnelEngineStartResult {
    guard lifetime.beginStart() else {
      return WinsPacketTunnelEngineStartResult(
        engineReady: true,
        statusFields: [
          "engine_runtime_packet_flow_attached": true,
          "engine_runtime_engine_ready_reported": true,
          "engine_runtime_engine_running_reported": true,
          "engine_runtime_already_running": true
        ]
      )
    }

    var runtimeFields: [String: Any] = [:]
    do {
      let launchDescriptor = try makeLaunchDescriptorJSON()
      guard let carrier = WinsPacketCarrier.carrier(for: plan.requiredComponents) else {
        throw adapterFailure("Win's VPN native engine plan names no supported packet carrier.")
      }
      activeCarrier = carrier
      runtimeFields = [
        "engine_runtime_adapter_contract_version": WinsPacketTunnelEnginePlan.launchContractVersion,
        "engine_runtime_packet_flow_attached": false,
        "engine_runtime_engine_ready_reported": false,
        "engine_runtime_engine_running_reported": false,
        carrier.startedStatusField: false,
        "engine_runtime_component_count": plan.requiredComponents.count
      ]
      let components = try plan.requiredComponents.map {
        try WinsNativeEngineComponent(component: $0, bundle: bundle, fileManager: fileManager)
      }
      loadedComponents = components

      let carrierComponent = try component(named: carrier.component)
      try carrierComponent.requireContractVersion(
        ContractVersionFunction.self,
        symbol: carrier.contractVersionSymbol,
        expected: Int32(WinsPacketTunnelEnginePlan.launchContractVersion)
      )
      let carrierCreate: CarrierCreateFunction =
        try carrierComponent.symbol(carrier.createSymbol)
      let carrierStart: CarrierStartFunction =
        try carrierComponent.symbol(carrier.startSymbol)

      if let xray = loadedComponents.first(where: { $0.component == "xray_vless_ws_transport" }) {
        runtimeFields["engine_runtime_xray_started"] = false
        try xray.requireContractVersion(
          ContractVersionFunction.self,
          symbol: "wins_xray_vless_ws_transport_contract_version",
          expected: Int32(WinsPacketTunnelEnginePlan.launchContractVersion)
        )
        let configure: XrayConfigureFunction =
          try xray.symbol("wins_xray_vless_ws_transport_configure")
        let start: XrayStartFunction = try xray.symbol("wins_xray_vless_ws_transport_start")
        xrayStop = try xray.symbol("wins_xray_vless_ws_transport_stop")
        let configured = launchDescriptor.withCString { pointer -> Int32 in
          configure(pointer)
        }
        guard configured != 0 else {
          throw adapterFailure(
            "Win's VPN Xray transport rejected the launch descriptor.",
            extra: runtimeFields
          )
        }
        guard start() != 0 else {
          throw adapterFailure(
            "Win's VPN Xray transport did not start.",
            extra: runtimeFields
          )
        }
        runtimeFields["engine_runtime_xray_started"] = true
      }

      let packetFlowPointer = Unmanaged.passUnretained(packetFlow).toOpaque()

      // --- Winn Protocol loopback seam ------------------------------------
      //
      // RE-LANDED 2026-08-08. This block, and the three status fields it
      // writes, were written on 2026-08-06, destroyed by a `git reset --hard`
      // before they were committed, and survived only in the off-HEAD snapshot
      // `934f7b4`. Every other layer kept describing it -- the wrapper's
      // ORDERING comment, `WinsTunnelConfig.requiredEngineComponents`,
      // `tools/build_apple_engine_wrappers.sh`, the readiness gate -- while the
      // code that honoured it was gone. See
      // `docs/handoff/SEAM_STATUS_PRODUCERS_20260808.md`.
      //
      // Started BEFORE AmneziaWG, and only because it has to be: the seam binds
      // an EPHEMERAL loopback port, so the port does not exist until the seam
      // is running, and AmneziaWG's peer endpoint cannot be written until the
      // port is known. Choosing the port on this side instead would mean
      // binding a probe socket, closing it, and hoping nothing took the port in
      // between; the wrapper grew an additive accessor rather than that race.
      // This is also the order Android uses (WinnAwgLoopbackSeam.kt).
      //
      // The seam is ADDITIVE, never a replacement. `activeCarrier` stays
      // AmneziaWG throughout -- `WinsTunnelConfig.packetCarrierComponent`
      // returns `amneziawg_packet_engine` unconditionally, and handing raw IP
      // packets to a datapath with no AmneziaWG implementation is a mistake the
      // wrapper refuses at create time on purpose.
      //
      // THIS BLOCK FAILS CLOSED, AND THAT IS THE POINT ON THIS PLATFORM. Every
      // guard below throws. Not one of them may fall through to the AmneziaWG
      // start with the original endpoint, because that start succeeds: the tun
      // comes up, traffic flows, and a session the gateway negotiated as winn/3
      // runs as classical AmneziaWG with nobody told. A seam that cannot be
      // created, cannot start, or cannot report its port is a failed
      // connection, never a quieter one.
      var amneziaWGLaunchDescriptor = launchDescriptor
      if plan.requiredComponents.contains(WinsPacketCarrier.winn.component) {
        let seam = WinsPacketCarrier.winn
        // Written false first, all three, so a start that dies mid-block
        // reports how far it got rather than reporting nothing. A missing key
        // and a false key are the same to `as? Bool == true`, but they are not
        // the same to a person reading a failed start's status document.
        runtimeFields[seam.startedStatusField] = false
        runtimeFields["engine_runtime_winn_seam_bound"] = false
        runtimeFields["engine_runtime_winn_awg_uapi_repointed"] = false

        let seamComponent = try component(named: seam.component)
        try seamComponent.requireContractVersion(
          ContractVersionFunction.self,
          symbol: seam.contractVersionSymbol,
          expected: Int32(WinsPacketTunnelEnginePlan.launchContractVersion)
        )
        let seamCreate: CarrierCreateFunction = try seamComponent.symbol(seam.createSymbol)
        let seamStart: CarrierStartFunction = try seamComponent.symbol(seam.startSymbol)
        let seamPort: WinnSeamPortFunction =
          try seamComponent.symbol(WinsPacketCarrier.winnSeamPortSymbol)

        let seamEngine = launchDescriptor.withCString { pointer -> UnsafeMutableRawPointer? in
          seamCreate(pointer, packetFlowPointer)
        }
        guard let seamEngine else {
          throw adapterFailure(seam.createFailureMessage, extra: runtimeFields)
        }
        winnSeamHandle = seamEngine
        guard seamStart(seamEngine) != 0 else {
          throw adapterFailure(seam.startFailureMessage, extra: runtimeFields)
        }
        runtimeFields[seam.startedStatusField] = true

        // 0 is what the wrapper returns before start and after stop, so it is
        // the value a seam that silently did nothing would report. Hence
        // `> 0`, not `!= -1`.
        let boundPort = Int(seamPort(seamEngine))
        guard boundPort > 0, boundPort <= 65_535 else {
          throw adapterFailure(
            "Win's VPN Winn Protocol packet engine did not report a loopback seam.",
            extra: runtimeFields
          )
        }
        runtimeFields["engine_runtime_winn_seam_bound"] = true

        amneziaWGLaunchDescriptor = try makeLaunchDescriptorJSON(
          amneziaWGEndpoint: "\(WinsPacketCarrier.winnSeamLoopbackHost):\(boundPort)"
        )
        // The only field that distinguishes "Winn is carrying this session"
        // from "we fell through and this is plain AmneziaWG".
        //
        // SUNSET: this key names a relationship Winn Protocol v3 is leaving
        // behind. Retire it the day an Apple winn3 carrier exists and
        // `packetCarrierComponent` stops returning `amneziawg_packet_engine`.
        // Until then it is the only check on the fall-through above, and
        // `docs/handoff/SEAM_STATUS_PRODUCERS_20260808.md` section 4 is the
        // standing permission to delete it -- producer and harness assertion
        // together, in one commit, never one without the other.
        runtimeFields["engine_runtime_winn_awg_uapi_repointed"] = true
      }

      let nativeEngine = amneziaWGLaunchDescriptor.withCString { pointer -> UnsafeMutableRawPointer? in
        carrierCreate(pointer, packetFlowPointer)
      }
      guard let nativeEngine else {
        throw adapterFailure(
          carrier.createFailureMessage,
          extra: runtimeFields
        )
      }
      carrierHandle = nativeEngine
      guard carrierStart(nativeEngine) != 0 else {
        throw adapterFailure(
          carrier.startFailureMessage,
          extra: runtimeFields
        )
      }

      if let seamHandle = winnSeamHandle {
        guard let seamComponent = loadedComponents.first(
          where: { $0.component == WinsPacketCarrier.winn.component }
        ) else {
          throw adapterFailure(
            "The Winn seam component is unavailable.",
            extra: runtimeFields
          )
        }
        let listenPort: WinnSeamPortFunction = try carrierComponent.symbol(
          "wins_amneziawg_packet_engine_listen_port"
        )
        let expectPort: WinnExpectAwgPortFunction = try seamComponent.symbol(
          "wins_winn_packet_engine_expect_awg_port"
        )
        let awgPort = listenPort(nativeEngine)
        guard awgPort > 0, expectPort(seamHandle, awgPort) == 1 else {
          throw adapterFailure(
            "The Winn seam could not bind the AWG source port.",
            extra: runtimeFields
          )
        }
        runtimeFields["engine_runtime_winn_seam_awg_port_pinned"] = true
      }
      runtimeFields["engine_runtime_packet_flow_attached"] = true
      runtimeFields["engine_runtime_engine_ready_reported"] = true
      runtimeFields["engine_runtime_engine_running_reported"] = true
      runtimeFields[carrier.startedStatusField] = true
      if let seamHandle = winnSeamHandle,
         let seamComponent = loadedComponents.first(
           where: { $0.component == WinsPacketCarrier.winn.component }
         ) {
        winnSamplePublication = WinnSamplePublication(
          handle: seamHandle,
          component: seamComponent,
          seamStats: try? seamComponent.symbol(
            "wins_winn_packet_engine_seam_stats"
          ),
          engineStatus: try? seamComponent.symbol(
            "wins_winn_packet_engine_status_json"
          )
        )
      }
      lifetime.finishStart()
      return WinsPacketTunnelEngineStartResult(
        engineReady: true,
        statusFields: runtimeFields
      )
    } catch let error as WinsPacketTunnelEngineError {
      stopUnpublishedNativeState()
      lifetime.finishFailedStart()
      throw error
    } catch {
      stopUnpublishedNativeState()
      lifetime.finishFailedStart()
      throw adapterFailure(
        "Win's VPN native engine adapter failed: \(WinsTunnelDiagnostics.redactedProviderErrorMessage(error))",
        extra: runtimeFields
      )
    }
  }

  func stop() {
    guard lifetime.beginStopAndWaitForSamplers() else { return }
    winnSamplePublication = nil
    stopUnpublishedNativeState()
    lifetime.finishStop()
  }

  /// Called only while the lifetime phase is `starting` or `stopping`, when no
  /// sampler can hold or acquire a native handle. Native stop/destroy executes
  /// without the condition held, so joining worker threads cannot deadlock on
  /// a status callback trying to release its claim.
  private func stopUnpublishedNativeState() {
    if let carrierHandle,
       let carrier = activeCarrier,
       let carrierComponent = loadedComponents.first(where: { $0.component == carrier.component }) {
      if let stop: CarrierStopFunction = try? carrierComponent.symbol(carrier.stopSymbol) {
        stop(carrierHandle)
      }
      if let destroy: CarrierDestroyFunction =
        try? carrierComponent.symbol(carrier.destroySymbol) {
        destroy(carrierHandle)
      }
    }
    carrierHandle = nil
    activeCarrier = nil

    // The seam is torn down AFTER AmneziaWG, the reverse of the start order:
    // AmneziaWG's outer datagrams leave through it, so closing it first would
    // strand them with nowhere to go while the tun was still up.
    //
    // Cleared BEFORE the destroy, so `seamObservabilityStatusFields()` cannot
    // sample an engine that is being freed. Both accessors are bounded and
    // neither blocks on the datapath, so nothing of consequence waits here.
    let seamHandleAtStop = winnSeamHandle
    winnSeamHandle = nil
    if let seamHandleAtStop,
       let seamComponent = loadedComponents.first(
         where: { $0.component == WinsPacketCarrier.winn.component }
       ) {
      if let stop: CarrierStopFunction =
        try? seamComponent.symbol(WinsPacketCarrier.winn.stopSymbol) {
        stop(seamHandleAtStop)
      }
      if let destroy: CarrierDestroyFunction =
        try? seamComponent.symbol(WinsPacketCarrier.winn.destroySymbol) {
        destroy(seamHandleAtStop)
      }
    }

    xrayStop?()
    xrayStop = nil
    loadedComponents.removeAll()
  }

  /// Live sample of the Winn wrapper's two observability documents.
  ///
  /// # Why dlsym and not a header declaration
  ///
  /// `wins_winn_packet_engine_seam_stats` and
  /// `wins_winn_packet_engine_status_json` are the wrapper's own additive
  /// symbols, deliberately outside the five-symbol carrier ABI this loader
  /// resolves for every carrier — the same treatment
  /// `wins_winn_packet_engine_awg_seam_port` already gets. They are resolved
  /// here, per call, by the same `symbol(_:)` path, so a build whose Winn
  /// component predates them degrades to "no fields" instead of failing to
  /// link. They are NOT added to `WinnTunnel.h`: that header is the archive's
  /// ABI surface, byte-checked against the cgo-generated header by
  /// `tools/verify_winn_abi_conformance.sh`, and these are not archive symbols.
  ///
  /// AmneziaWG returns nothing here, on purpose: its runtime exposes no
  /// promotion field to this provider, and the Go datapath's own documentation
  /// forbids synthesising one.
  func seamObservabilityStatusFields() -> [String: Any] {
    // Samples `winnSeamHandle`, NOT `carrierHandle`. The carrier is always
    // AmneziaWG on Apple, so the previous gate -- `activeCarrier` being the
    // Winn component -- could never be true and this returned `[:]` for every
    // config, publishing none of the fifteen seam counters or the engine status
    // fields. Corrected 2026-08-08 alongside the seam start block, which is
    // what makes `winnSeamHandle` exist. `nil` after `stop()`, which is what
    // makes a post-teardown sample report nothing instead of reading a
    // destroyed engine.
    guard let publication = lifetime.claim({ winnSamplePublication }) else {
      return [:]
    }
    defer { lifetime.releaseClaim() }
    return WinsWinnSeamObservabilitySample.fields(
      seamStatsJSON: Self.sampleDocument(
        publication.seamStats,
        handle: publication.handle
      ),
      engineStatusJSON: Self.sampleDocument(
        publication.engineStatus,
        handle: publication.handle
      )
    )
  }

  /// Calls one buffer-filling wrapper symbol. Both report "nothing written"
  /// with a 0 return — including the case where the document did not fit — so
  /// a truncated document is never parsed as a whole one.
  private static func sampleDocument(
    _ function: WinnObservabilityDocumentFunction?,
    handle: UnsafeMutableRawPointer
  ) -> String? {
    guard let function else {
      return nil
    }
    var buffer = [CChar](repeating: 0, count: observabilityDocumentCapacity)
    let written = buffer.withUnsafeMutableBufferPointer { pointer -> Int32 in
      guard let base = pointer.baseAddress else {
        return 0
      }
      return function(handle, base, Int32(pointer.count))
    }
    guard written > 0, written < Int32(observabilityDocumentCapacity) else {
      return nil
    }
    return String(cString: buffer)
  }

  private func component(named component: String) throws -> WinsNativeEngineComponent {
    guard let loaded = loadedComponents.first(where: { $0.component == component }) else {
      throw adapterFailure("Win's VPN native engine component \(component) was not loaded.")
    }
    return loaded
  }

  /// Builds the launch descriptor. With `amneziaWGEndpoint` set, this is the
  /// SECOND descriptor of a Winn start: the same document with AmneziaWG's peer
  /// endpoint rewritten to the seam's ephemeral loopback port, which is the
  /// whole mechanism by which AmneziaWG's outer datagrams enter Winn instead of
  /// going on the wire.
  private func makeLaunchDescriptorJSON(amneziaWGEndpoint: String? = nil) throws -> String {
    let config = plan.launchDescriptor.config
    var uapiConfiguration = try config.amneziaWGUAPIConfiguration()
    var peer = config.sections["peer"] ?? [:]
    if let amneziaWGEndpoint {
      guard let repointed = WinsTunnelConfig.amneziaWGUAPIConfiguration(
        uapiConfiguration,
        rewritingEndpointTo: amneziaWGEndpoint
      ) else {
        throw adapterFailure(
          "Win's VPN AmneziaWG configuration could not be repointed at the Winn loopback seam."
        )
      }
      uapiConfiguration = repointed
      // Kept in step with the UAPI document so nothing downstream can read a
      // stale gateway out of the descriptor. The AmneziaWG wrapper itself reads
      // only `amneziawg_uapi_config`.
      peer["endpoint"] = amneziaWGEndpoint
    }
    var descriptor: [String: Any] = [
      "schema_version": WinsPacketTunnelEnginePlan.launchContractVersion,
      "transport_mode": config.transportMode,
      "interface": config.sections["interface"] ?? [:],
      "peer": peer,
      "amneziawg_uapi_config": uapiConfiguration,
      "required_components": plan.requiredComponents,
      "packet_flow_object": "ne_packet_tunnel_flow_opaque_pointer"
    ]
    if let xray = config.sections["xray"] {
      descriptor["xray"] = xray
    }
    if let winn = config.sections["winn"] {
      descriptor["winn"] = winn
      // The carrier profile is built and validated HERE, once, for the
      // Winn engine's own create call only -- never for the descriptor that
      // repoints AmneziaWG at the loopback seam (`amneziaWGEndpoint != nil`),
      // which does not read this key and would otherwise mint a second,
      // unused profile with its own fresh session id for no reason. Building
      // it only once also means a credential-resolution failure is reported
      // exactly once rather than differently on a second attempt.
      if amneziaWGEndpoint == nil {
        let carrier = (winn["carrier"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
          .lowercased()
        if carrier == WinsTunnelConfig.supportedWinnCarrierHttp3 {
          descriptor["winn_carrier_profile"] = try makeWinnCarrierProfileJSON(section: winn, carrier: carrier)
        }
      }
    }
    let data = try JSONSerialization.data(withJSONObject: descriptor, options: [.sortedKeys])
    guard let json = String(data: data, encoding: .utf8) else {
      throw adapterFailure("Win's VPN native engine launch descriptor could not be encoded.")
    }
    return json
  }

  /// Builds the carrier profile document for a `[winn]` section whose carrier
  /// is `http3-connect-udp`, resolving its six credential files against this
  /// device's App Group container.
  ///
  /// THIS FAILS THE WHOLE START, never falls back to direct-awg. A carrier
  /// session with no usable profile is exactly as unstartable as one with no
  /// `[winn]` endpoint -- see the fail-closed rule in the seam block of
  /// `start()`.
  ///
  /// # Why this exists, and what its absence did
  ///
  /// Lost from this file in the 2026-08-08 loss event
  /// (`docs/handoff/RECOVERY_20260808.md`) along with the seam start sequence,
  /// and reported but not fixed by
  /// `docs/handoff/SEAM_STATUS_PRODUCERS_20260808.md` section 6.2. Every other
  /// layer of the `http3-connect-udp` path survived: `WinsTunnelConfig` still
  /// accepts the carrier (`:1371`), `WinsWinnCarrierProfile` still builds and
  /// validates the document, the wrapper still reads `winn_carrier_profile`
  /// out of this descriptor (`WinsWinnPacketEngine.m:153`) and still routes a
  /// session that has one through `WinnTunnelCreateWithCarrier` (`:1698`), and
  /// the archive still exports it. Only this call was missing, so an
  /// `http3-connect-udp` configuration passed `validate()` and then could not
  /// be honoured: the wrapper's create refused for want of the key
  /// (`WinsWinnPacketEngine.m:1594-1601`) and reported a bare NULL, which is a
  /// failure with no name on it. A validator must not accept a configuration
  /// this code cannot honour -- so the code now honours it.
  ///
  /// # Why the v3-standalone ruling does not retire this
  ///
  /// `docs/handoff/WINN3_STANDALONE_PROTOCOL_DESIGN_20260808.md` scopes itself
  /// to `winn_protocol_experimental/winn3/` and states that carriers are not
  /// built there. There is no Apple `winn3` carrier, and `http3-connect-udp`
  /// on Apple is this profile, this wrapper and this archive. The ruling
  /// retires the *AmneziaWG relay*, not the carrier document.
  private func makeWinnCarrierProfileJSON(
    section: [String: String],
    carrier: String
  ) throws -> String {
    guard let containerURL = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: WinsAppleAppGroup.identifier
    ) else {
      throw adapterFailure(
        "Win's VPN could not resolve its App Group container, so the Winn " +
          "carrier credentials cannot be located; refusing rather than " +
          "starting an unauthenticated carrier."
      )
    }
    var credentialDirectory = containerURL
    for component in WinsWinnCarrierProfile.credentialDirectoryComponents {
      credentialDirectory = credentialDirectory.appendingPathComponent(component, isDirectory: true)
    }
    do {
      let profile = try WinsWinnCarrierProfile.from(
        section: section,
        carrier: carrier,
        credentialDirectory: credentialDirectory,
        fileManager: fileManager
      )
      return profile.toJSON()
    } catch let error as WinsWinnCarrierProfileError {
      throw adapterFailure("Win's VPN Winn carrier profile: \(error.message)")
    }
  }

  private func adapterFailure(
    _ message: String,
    extra: [String: Any] = [:]
  ) -> WinsPacketTunnelEngineError {
    var fields = WinsPacketTunnelEngineRuntimeStatus.sanitizedAdapterStatusFields(
      extra,
      plan: plan,
      engineReady: false
    )
    fields["engine_lifecycle_state"] = "failed"
    fields["engine_runtime_contract_failed"] = true
    fields["engine_runtime_engine_ready_reported"] = false
    fields["engine_runtime_engine_running_reported"] = false
    fields["engine_runtime_packet_flow_attached"] =
      fields["engine_runtime_packet_flow_attached"] as? Bool == true
    return WinsPacketTunnelEngineError(
      code: WinsPacketTunnelEngineError.adapterStartContractCode,
      message: message,
      statusFields: fields
    )
  }
}

private final class WinsNativeEngineComponent {
  private static let artifactNamesByComponent = [
    "amneziawg_packet_engine": [
      "WinsAmneziaWGPacketEngine",
      "AmneziaWGPacketEngine",
      "amneziawg_packet_engine"
    ],
    "xray_vless_ws_transport": [
      "WinsXrayVlessWsTransport",
      "XrayVlessWsTransport",
      "xray_vless_ws_transport"
    ],
    "winn_packet_engine": [
      "WinsWinnPacketEngine",
      "WinnPacketEngine",
      "winn_packet_engine"
    ]
  ]

  let component: String
  private let handle: UnsafeMutableRawPointer

  init(component: String, bundle: Bundle, fileManager: FileManager) throws {
    self.component = component
    if let linkedHandle = Self.linkedProcessHandle(component: component) {
      handle = linkedHandle
      return
    }
    let artifactURL = try Self.artifactExecutableURL(
      component: component,
      bundle: bundle,
      fileManager: fileManager
    )
    guard let handle = dlopen(artifactURL.path, RTLD_NOW | RTLD_LOCAL) else {
      let message = String(cString: dlerror())
      throw WinsPacketTunnelEngineError(
        code: WinsPacketTunnelEngineError.adapterStartContractCode,
        message: "Win's VPN native engine component \(component) could not be loaded.",
        statusFields: [
          "engine_runtime_contract_failed": true,
          "engine_runtime_component_load_failed": true,
          "engine_runtime_loader_error": Self.safeLoaderError(message)
        ]
      )
    }
    self.handle = handle
  }

  deinit {
    dlclose(handle)
  }

  func symbol<T>(_ name: String) throws -> T {
    guard let pointer = dlsym(handle, name) else {
      throw WinsPacketTunnelEngineError(
        code: WinsPacketTunnelEngineError.adapterStartContractCode,
        message: "Win's VPN native engine component \(component) is missing symbol \(name).",
        statusFields: [
          "engine_runtime_contract_failed": true,
          "engine_runtime_symbol_missing": true
        ]
      )
    }
    return unsafeBitCast(pointer, to: T.self)
  }

  func requireContractVersion<T>(
    _ type: T.Type,
    symbol: String,
    expected: Int32
  ) throws {
    let versionFunction: ContractVersionFunction = try self.symbol(symbol)
    guard versionFunction() == expected else {
      throw WinsPacketTunnelEngineError(
        code: WinsPacketTunnelEngineError.adapterStartContractCode,
        message: "Win's VPN native engine component \(component) has an unsupported contract version.",
        statusFields: [
          "engine_runtime_contract_failed": true,
          "engine_runtime_contract_version_supported": false
        ]
      )
    }
  }

  private typealias ContractVersionFunction = @convention(c) () -> Int32

  private static func linkedProcessHandle(component: String) -> UnsafeMutableRawPointer? {
    guard let symbol = linkedProbeSymbol(component: component),
          let handle = dlopen(nil, RTLD_NOW | RTLD_LOCAL) else {
      return nil
    }
    guard dlsym(handle, symbol) != nil else {
      dlclose(handle)
      return nil
    }
    return handle
  }

  private static func linkedProbeSymbol(component: String) -> String? {
    switch component {
    case "amneziawg_packet_engine":
      return "wins_amneziawg_packet_engine_contract_version"
    case "xray_vless_ws_transport":
      return "wins_xray_vless_ws_transport_contract_version"
    case "winn_packet_engine":
      return "wins_winn_packet_engine_contract_version"
    default:
      return nil
    }
  }

  private static func artifactExecutableURL(
    component: String,
    bundle: Bundle,
    fileManager: FileManager
  ) throws -> URL {
    let artifactNames = artifactNamesByComponent[component] ?? [component]
    let candidateDirectories = [
      containingAppFrameworksURL(bundle: bundle),
      bundle.privateFrameworksURL,
      bundle.resourceURL,
      bundle.resourceURL?.appendingPathComponent("Frameworks", isDirectory: true),
      bundle.resourceURL?.appendingPathComponent("Libraries", isDirectory: true),
      bundle.executableURL?.deletingLastPathComponent()
    ].compactMap { $0 }

    for artifactName in artifactNames {
      if let frameworkURL = bundle.url(forResource: artifactName, withExtension: "framework"),
         let executableURL = frameworkExecutableURL(
           frameworkURL: frameworkURL,
           frameworkName: artifactName,
           fileManager: fileManager
         ) {
        return executableURL
      }
      if let dylibURL = bundle.url(forResource: artifactName, withExtension: "dylib") {
        return dylibURL
      }
      if let executableURL = bundle.url(forAuxiliaryExecutable: artifactName) {
        return executableURL
      }
      if let executableURL = bundle.url(forAuxiliaryExecutable: "\(artifactName).dylib") {
        return executableURL
      }
      for directory in candidateDirectories {
        let frameworkURL = directory.appendingPathComponent(
          "\(artifactName).framework",
          isDirectory: true
        )
        if let executableURL = frameworkExecutableURL(
          frameworkURL: frameworkURL,
          frameworkName: artifactName,
          fileManager: fileManager
        ) {
          return executableURL
        }
        for fileName in ["lib\(artifactName).dylib", "\(artifactName).dylib", artifactName] {
          let fileURL = directory.appendingPathComponent(fileName, isDirectory: false)
          if fileManager.fileExists(atPath: fileURL.path) {
            return fileURL
          }
        }
      }
    }

    throw WinsPacketTunnelEngineError(
      code: WinsPacketTunnelEngineError.missingNativeEngineCode,
      message: "Win's VPN native engine component \(component) is not bundled.",
      statusFields: [
        "engine_runtime_contract_failed": true,
        "engine_runtime_component_missing": true
      ]
    )
  }

  private static func containingAppFrameworksURL(bundle: Bundle) -> URL? {
    let plugInsURL = bundle.bundleURL.deletingLastPathComponent()
    guard plugInsURL.lastPathComponent == "PlugIns" else {
      return nil
    }
    return plugInsURL
      .deletingLastPathComponent()
      .appendingPathComponent("Frameworks", isDirectory: true)
  }

  private static func frameworkExecutableURL(
    frameworkURL: URL,
    frameworkName: String,
    fileManager: FileManager
  ) -> URL? {
    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: frameworkURL.path, isDirectory: &isDirectory),
          isDirectory.boolValue else {
      return nil
    }

    let defaultExecutable = frameworkURL.appendingPathComponent(
      frameworkName,
      isDirectory: false
    )
    if fileManager.isExecutableFile(atPath: defaultExecutable.path) {
      return defaultExecutable
    }

    let infoURL = frameworkURL.appendingPathComponent("Info.plist", isDirectory: false)
    if let info = NSDictionary(contentsOf: infoURL),
       let executableName = info["CFBundleExecutable"] as? String {
      let executableURL = frameworkURL.appendingPathComponent(executableName, isDirectory: false)
      if fileManager.isExecutableFile(atPath: executableURL.path) {
        return executableURL
      }
    }
    return nil
  }

  private static func safeLoaderError(_ rawValue: String) -> String {
    let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty, value.unicodeScalars.count <= 96 else {
      return "loader_error_redacted"
    }
    let lowercased = value.lowercased()
    guard !lowercased.contains("/users/"),
          !lowercased.contains("/var/"),
          !lowercased.contains("/private/"),
          !lowercased.contains("key") else {
      return "loader_error_redacted"
    }
    return lowercased
      .unicodeScalars
      .filter { scalar in
        switch scalar.value {
        case 32, 45, 46, 48...57, 65...90, 95, 97...122:
          return true
        default:
          return false
        }
      }
      .map(String.init)
      .joined()
  }
}
