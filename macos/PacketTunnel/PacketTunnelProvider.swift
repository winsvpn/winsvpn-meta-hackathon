import Foundation
import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
  private static let sharedConfigDirectoryName = "Tunnel"
  private static let sharedConfigFileName = "latest_tunnel.conf"
  private static let sharedStatusFileName = "latest_status.json"
  private static let providerStatusFieldsUserInfoKey = "wins_provider_status_fields"
  /// How long a winn/3 start may spend in the BOOTSTRAP posture proving its
  /// datapath before the start FAILS CLOSED with the Mac untouched. Parity
  /// with the Windows host, where the same gate is
  /// `kAwgConvergenceDeadlineMilliseconds` (25 000) followed by
  /// `kWinnTransportConvergenceDeadlineMilliseconds` (5 000); here both proofs
  /// are collected inside one combined window, and the window must stay well
  /// under the system's own start watchdog (~60 s) so the failure is always
  /// this provider's explicit, recorded refusal rather than a SIGKILL.
  private static let winnDatapathProofDeadlineSeconds = 25.0
  /// Cadence of the convergence loop. Every tick reads the engine's own status
  /// document; every second tick sends one in-tunnel convergence probe.
  private static let winnDatapathProofTickMilliseconds = 250
  /// How long the PROMOTION `setTunnelNetworkSettings` call may take before the
  /// start is failed rather than left in limbo. The callback is expected, but a
  /// start must never be able to hang on it.
  private static let winnDatapathPromotionSettingsDeadlineSeconds = 10.0
  /// Start option / provider-configuration key that runs a staged start as far
  /// as PROVEN and then stops, deliberately, instead of promoting. See
  /// `winnDatapathProofPromotionHeld`.
  private static let winnDatapathProofHoldKey = "winn_datapath_proof_hold"

  #if DEBUG
  private let logger = OSLog(
    subsystem: "org.winsvpn.app.PacketTunnel",
    category: "PacketTunnel"
  )
  #else
  private let logger = OSLog.disabled
  #endif
  private var packetEngine: WinsPacketTunnelEngine?
  private var provingPacketEngine: WinsPacketTunnelEngine?
  private var provingWinn3Datapath: WinsWinn3Datapath?
  private let provingStopLock = NSLock()
  /// The winn/3 STANDALONE session, when one is running.
  ///
  /// A separate property from `packetEngine` because it is a separate thing:
  /// `WinsPacketTunnelEngine` is the AmneziaWG-owning relay stack, and a
  /// standalone session contains no AmneziaWG at all. Making one masquerade as
  /// the other would put a relay's vocabulary — seam ports, UAPI repoints,
  /// handshake-response flags — on a session that has none of them, which is
  /// the drift the standalone ruling exists to stop.
  private var winn3Datapath: WinsWinn3Datapath?
  private var activeStatusGeneration = ""
  private var activeConfig: WinsTunnelConfig?
  private var activeEngineStatusFields: [String: Any] = [:]
  private let lifecycleGate = WinsTunnelOperationGate()

  /// True when a session of either kind is carrying.
  private var anySessionRunning: Bool {
    packetEngine?.isRunning == true || winn3Datapath?.isRunning == true
  }

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    var previousEngine: WinsPacketTunnelEngine?
    var previousWinn3: WinsWinn3Datapath?
    var previousProvingEngine: WinsPacketTunnelEngine?
    var previousProvingWinn3: WinsWinn3Datapath?
    let lifecycleToken = lifecycleGate.begin {
      previousEngine = packetEngine
      previousWinn3 = winn3Datapath
      previousProvingEngine = provingPacketEngine
      previousProvingWinn3 = provingWinn3Datapath
      provingPacketEngine = nil
      provingWinn3Datapath = nil
      packetEngine = nil
      winn3Datapath = nil
      activeStatusGeneration = statusGeneration(options: options)
      activeConfig = nil
      activeEngineStatusFields = [:]
    }
    provingStopLock.lock()
    previousProvingEngine?.stop()
    previousProvingWinn3?.stop()
    provingStopLock.unlock()
    previousEngine?.stop()
    previousWinn3?.stop()
    do {
      let runtimeConfig = try loadRuntimeConfig(options: options)
      let parsedConfig = try WinsTunnelConfig
        .parseAndValidate(runtimeConfig.rawConfig)
        .resolvingFullTunnelTransportIPv4()
      try bindWinn3DescriptorToSelectedNode(parsedConfig, options: options)
      guard lifecycleGate.performIfCurrent(lifecycleToken, action: {
        activeStatusGeneration = runtimeConfig.statusGeneration
        activeConfig = parsedConfig
      }) else {
        completionHandler(Self.canceledStartError())
        return
      }
      var verifiedStatusFields: [String: Any]
      do {
        verifiedStatusFields = try runtimeConfig.verifiedStatusFields(for: parsedConfig)
      } catch {
        let completedCurrentOperation = lifecycleGate.performIfCurrent(lifecycleToken) {
          writeProviderStatus(
            stage: "start_rejected",
            config: parsedConfig,
            error: error,
            extra: runtimeConfig.statusFields(clientKeyPairVerified: false),
            statusGeneration: runtimeConfig.statusGeneration
          )
        }
        completionHandler(completedCurrentOperation ? error : Self.canceledStartError())
        return
      }
      os_log(
        "Validated packet tunnel config summary peer_kind=%{public}@ transport_kind=%{public}@ interface_ipv4_present=%{public}@ route_count=%{public}d default_route=%{public}@ mtu=%{public}d",
        log: logger,
        type: .info,
        parsedConfig.peerEndpointKind,
        parsedConfig.transportEndpointKind,
        parsedConfig.interfaceIPv4Address.isEmpty ? "false" : "true",
        parsedConfig.allowedIPv4Routes.count,
        parsedConfig.defaultIPv4RouteEnabled ? "true" : "false",
        parsedConfig.mtu
      )
      // THE MEMORY GATE, BEFORE ANY NETWORK SETTINGS ARE INSTALLED.
      //
      // Non-winn starts are not gated. `winnAppexMemoryGate` returns nil for
      // them, this block is skipped entirely, and no field it owns is written.
      // On macOS, `os_proc_available_memory()` does not exist, so unmeasurable
      // headroom is a platform fact rather than a low-memory reading: the gate
      // proceeds and records `winn_memory_gate_macos_unknown_headroom_allowed`.
      if let memoryGate = winnAppexMemoryGate(for: parsedConfig) {
        verifiedStatusFields.merge(memoryGate.statusFields) { _, new in new }
        if let refusalReason = memoryGate.refusalReason {
          os_log(
            "Refusing winn/3 start: %{public}@ (available=%{public}d required=%{public}d carrier=%{public}@).",
            log: logger,
            type: .error,
            refusalReason,
            memoryGate.availableBytes ?? -1,
            memoryGate.requiredBytes,
            memoryGate.carrier.isEmpty ? "direct-awg-implicit" : memoryGate.carrier
          )
          let error = Self.providerError(
            code: 1018,
            message: "Refusing to start the winn/3 datapath: \(refusalReason).",
            statusFields: memoryGate.statusFields
          )
          let completedCurrentOperation = lifecycleGate.performIfCurrent(lifecycleToken) {
            writeProviderStatus(
              stage: "start_rejected",
              config: parsedConfig,
              error: error,
              extra: verifiedStatusFields,
              statusGeneration: runtimeConfig.statusGeneration
            )
          }
          completionHandler(completedCurrentOperation ? error : Self.canceledStartError())
          return
        }
      }
      // THE winn/3 STANDALONE FORK, taken before any AmneziaWG object exists.
      //
      // It is placed here — above `makeNetworkSettings`, above the engine
      // factory — because everything below it is the RELAY: settings built
      // around `[interface] Address` and an MTU from `[interface] MTU`, and an
      // engine whose tun owner is AmneziaWG. A standalone session shares none
      // of that. Falling through even one step would build a posture whose
      // address the winn/3 tun layer rejects as a source-address violation, and
      // the session would fail closed for a reason that looks like the gateway.
      //
      // A standalone start never returns to this path. There is no fallback to
      // `direct-awg` on any branch below: a standalone session silently
      // downgraded to a relay is the exact outcome the 2026-08-08 ruling
      // retires, and the gateway would have negotiated one transport while this
      // client ran another with nobody told.
      if parsedConfig.winn3Enabled {
        try startWinn3StandaloneSession(
          config: parsedConfig,
          baseStatusFields: verifiedStatusFields,
          promotionHeld: winnDatapathProofPromotionHeld(options: options),
          lifecycleToken: lifecycleToken,
          statusGeneration: runtimeConfig.statusGeneration,
          completionHandler: completionHandler
        )
        return
      }
      let fullTunnelSettings = try makeNetworkSettings(from: parsedConfig)
      // THE STAGED winn/3 START. For a winn full-tunnel session the settings
      // installed FIRST are a narrow bootstrap (no default route, no IPv6, no
      // DNS); the full-tunnel settings built above are installed only after the
      // datapath has been proven to carry traffic. Nil for every non-winn
      // start and every split-tunnel start — all of those keep today's
      // single-install behaviour byte for byte.
      let stagedWinnStart = try makeWinnStagedStartPlan(
        from: parsedConfig,
        fullTunnelSettings: fullTunnelSettings,
        promotionHeld: winnDatapathProofPromotionHeld(options: options)
      )
      let networkSettings = stagedWinnStart?.bootstrapSettings ?? fullTunnelSettings
      if let stagedWinnStart {
        // Merged BEFORE the settings callback so that every status document
        // this start can produce — success, rejection, or engine failure —
        // already says the session began in the bootstrap posture. A start that
        // failed before promotion must never be readable as a full-tunnel one.
        verifiedStatusFields.merge(stagedWinnStart.bootstrapStatusFields) { _, new in new }
      }
      setTunnelNetworkSettings(networkSettings) { settingsError in
        var statusFields = verifiedStatusFields
        statusFields["network_settings_applied"] = settingsError == nil
        if let settingsError {
          os_log(
            "Packet tunnel network settings rejected: %{public}@",
            log: self.logger,
            type: .error,
            WinsTunnelDiagnostics.redactedProviderErrorMessage(settingsError)
          )
          let completedCurrentOperation = self.lifecycleGate.performIfCurrent(lifecycleToken) {
            self.writeProviderStatus(
              stage: "network_settings_failed",
              config: parsedConfig,
              engineReady: false,
              networkSettingsReady: false,
              error: settingsError,
              extra: statusFields,
              statusGeneration: runtimeConfig.statusGeneration
            )
          }
          completionHandler(
            completedCurrentOperation ? settingsError : Self.canceledStartError()
          )
          return
        }

        guard self.lifecycleGate.isCurrent(lifecycleToken) else {
          completionHandler(Self.canceledStartError())
          return
        }

        let engine = WinsPacketTunnelEngineFactory.makeEngine(
          config: parsedConfig,
          packetFlow: self.packetFlow,
          adapter: WinsNativePacketTunnelEngineAdapter(bundle: .main)
        )
        statusFields.merge(engine.plan.statusFields) { _, new in new }
        do {
          let startResult = try engine.start()
          statusFields.merge(startResult.statusFields) { _, new in new }
          // Baseline seam sample, so the very first status document already
          // says whether the counters are readable at all. Every later refresh
          // overwrites these with a fresh sample.
          statusFields.merge(engine.seamObservabilityStatusFields()) { _, new in new }
          if let stagedWinnStart {
            // The staged start does NOT complete here. The engine is running
            // against the bootstrap posture; the start completes — and the
            // session first claims this Mac's routing, IPv6 and DNS — only
            // after the convergence loop has observed the datapath carrying
            // traffic both ways. Until then `packetEngine` stays nil on
            // purpose: this session is not yet something `handleAppMessage`
            // may describe as ready, and the convergence loop owns the
            // engine's teardown on every failure path.
            self.runWinnDatapathProofConvergence(
              plan: stagedWinnStart,
              engine: engine,
              startResult: startResult,
              parsedConfig: parsedConfig,
              baseStatusFields: statusFields,
              lifecycleToken: lifecycleToken,
              statusGeneration: runtimeConfig.statusGeneration,
              completionHandler: completionHandler
            )
            return
          }
          guard self.lifecycleGate.performIfCurrent(lifecycleToken, action: {
            self.packetEngine = engine
            self.activeEngineStatusFields = statusFields
            self.writeProviderStatus(
              stage: "engine_started",
              config: parsedConfig,
              engineReady: startResult.engineReady,
              networkSettingsReady: true,
              extra: statusFields,
              statusGeneration: runtimeConfig.statusGeneration
            )
          }) else {
            engine.stop()
            completionHandler(Self.canceledStartError())
            return
          }
          completionHandler(nil)
        } catch {
          statusFields.merge(Self.providerStatusFields(from: error)) { _, new in new }
          let completedCurrentOperation = self.lifecycleGate.performIfCurrent(lifecycleToken) {
            self.packetEngine = nil
            self.activeEngineStatusFields = [:]
            self.writeProviderStatus(
              stage: Self.engineFailureStage(for: error),
              config: parsedConfig,
              engineReady: false,
              networkSettingsReady: true,
              error: error,
              extra: statusFields,
              statusGeneration: runtimeConfig.statusGeneration
            )
          }
          guard completedCurrentOperation else {
            engine.stop()
            completionHandler(Self.canceledStartError())
            return
          }
          completionHandler(error)
        }
      }
    } catch {
      os_log(
        "Packet tunnel start rejected: %{public}@",
        log: logger,
        type: .error,
        WinsTunnelDiagnostics.redactedProviderErrorMessage(error)
      )
      var statusFields = statusGenerationFields(options: options)
      statusFields.merge(Self.providerStatusFields(from: error)) { _, new in new }
      let completedCurrentOperation = lifecycleGate.performIfCurrent(lifecycleToken) {
        writeProviderStatus(
          stage: "start_rejected",
          error: error,
          extra: statusFields,
          statusGeneration: statusGeneration(options: options)
        )
      }
      completionHandler(completedCurrentOperation ? error : Self.canceledStartError())
    }
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    os_log("Packet tunnel stopped with reason %{public}d", log: logger, type: .info, reason.rawValue)
    var engineAtStop: WinsPacketTunnelEngine?
    var winn3AtStop: WinsWinn3Datapath?
    var provingEngineAtStop: WinsPacketTunnelEngine?
    var provingWinn3AtStop: WinsWinn3Datapath?
    var configAtStop: WinsTunnelConfig?
    var statusGenerationAtStop = ""
    lifecycleGate.invalidate {
      engineAtStop = packetEngine
      winn3AtStop = winn3Datapath
      provingEngineAtStop = provingPacketEngine
      provingWinn3AtStop = provingWinn3Datapath
      provingPacketEngine = nil
      provingWinn3Datapath = nil
      configAtStop = activeConfig
      statusGenerationAtStop = activeStatusGeneration
      packetEngine = nil
      winn3Datapath = nil
      activeConfig = nil
      activeEngineStatusFields = [:]
    }
    let engineWasRunning =
      engineAtStop?.isRunning == true || winn3AtStop?.isRunning == true
    // SAMPLED BEFORE stop(). The seam engine is destroyed in there, and this is
    // the last chance to record what the session actually carried — including
    // the two flags the promotion gate read. Same for the standalone session:
    // once the handle is closed its status document is empty, so the delivered
    // and dropped counts have to be taken now or not at all.
    var seamFieldsAtStop = engineAtStop?.seamObservabilityStatusFields() ?? [:]
    if let winn3AtStop {
      seamFieldsAtStop.merge(winn3AtStop.statusFields()) { _, new in new }
      seamFieldsAtStop.merge(winn3AtStop.pumpStatusFields()) { _, new in new }
      seamFieldsAtStop.merge(
        WinsWinn3PromotionGate.statusFields(
          engineStatusFields: winn3AtStop.statusFields()
        )
      ) { _, new in new }
    }
    var stopFields = previousProviderStatusFieldsBeforeStop()
    stopFields.merge([
      "stop_reason": reason.rawValue,
      "engine_was_running_before_stop": engineWasRunning,
      "status_generation": statusGenerationAtStop
    ]) { _, new in new }
    stopFields.merge(seamFieldsAtStop) { _, new in new }
    // KILL SWITCH, TEARDOWN OBSERVABILITY. The datapath is stopped (above and
    // below) and macOS never releases the settings during a teardown — it relies
    // on the system reclaiming them at session end — so a full-tunnel session's
    // blocking posture is held until the session is actually gone, meaning the
    // disconnecting window stays blocked rather than dropping to cleartext.
    stopFields.merge(
      WinsKillSwitch.teardownStatusFields(
        heldBlockingPosture: configAtStop?.defaultIPv4RouteEnabled == true,
        datapathStoppedBeforeRelease: true
      )
    ) { _, new in new }
    provingStopLock.lock()
    if provingEngineAtStop !== engineAtStop {
      provingEngineAtStop?.stop()
    }
    if provingWinn3AtStop !== winn3AtStop {
      provingWinn3AtStop?.stop()
    }
    provingStopLock.unlock()
    engineAtStop?.stop()
    winn3AtStop?.stop()
    writeProviderStatus(
      stage: "stopped",
      config: configAtStop,
      engineReady: false,
      networkSettingsReady: false,
      extra: stopFields,
      statusGeneration: statusGenerationAtStop
    )
    completionHandler()
  }

  override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)?
  ) {
    let providerExecutableSHA256 =
      WinsPacketTunnelProviderAppMessage.bundleExecutableSHA256(.main)
    // Sampling and synchronous status publication hold the lifecycle gate.
    // Slow native sampling or file IO can delay stop; completion runs unlocked.
    let responseData = lifecycleGate.withLock {
      let statusGeneration = currentStatusGeneration()
      // Either kind of session counts. A standalone session is not a
      // `WinsPacketTunnelEngine` and never will be, so reading only `packetEngine`
      // here would report a running winn/3 tunnel as not ready.
      let standaloneDatapath = winn3Datapath
      let standaloneHealth = standaloneDatapath?.healthSnapshot()
      let engineRunning = (packetEngine?.isRunning ?? false)
        || (standaloneHealth?.isOperational ?? false)
      let message = WinsPacketTunnelProviderAppMessage(
        messageData: messageData,
        engineRunning: engineRunning,
        transportMode: activeConfig?.transportMode ?? "",
        xrayEnabled: activeConfig?.xrayEnabled == true,
        providerExecutableSHA256: providerExecutableSHA256
      )
      let appMessageReady = engineRunning && message.accepted
      var statusFields = activeEngineStatusFields
      if let standaloneHealth {
        // Cached native fields must not stand in for an unavailable live sample.
        for key in WinsWinnSeamObservabilitySample.publishedStatusKeys {
          statusFields.removeValue(forKey: key)
        }
        statusFields.merge(standaloneHealth.fields) { _, new in new }
      }
      statusFields.merge(message.statusFields) { _, new in new }
      statusFields.merge(packetEngine?.seamObservabilityStatusFields() ?? [:]) { _, new in new }
      if activeConfig?.winnEnabled == true {
        statusFields.merge(Self.winnRuntimeMemorySampleFields()) { _, new in new }
      }
      if statusGeneration.isEmpty {
        statusFields.removeValue(forKey: "status_generation")
      } else {
        statusFields["status_generation"] = statusGeneration
      }
      writeProviderStatus(
        stage: "app_message",
        config: activeConfig,
        engineReady: appMessageReady,
        networkSettingsReady: appMessageReady,
        extra: statusFields,
        statusGeneration: statusGeneration
      )
      return message.responseData
    }
    completionHandler?(responseData)
  }

  private static func winnRuntimeMemorySampleFields() -> [String: Any] {
    var fields: [String: Any] = ["winn_memory_sample_taken": true]
    if let footprint = physicalFootprintBytes() {
      fields["winn_memory_sample_phys_footprint_bytes"] = footprint
    }
    if let available = availableProcessMemoryBytes() {
      fields["winn_memory_sample_available_bytes"] = available
      fields["winn_memory_sample_available_measured"] = true
    } else {
      fields["winn_memory_sample_available_measured"] = false
    }
    return fields
  }

  override func sleep(completionHandler: @escaping () -> Void) {
    let engineRunning = anySessionRunning
    var sleepFields = WinsPacketTunnelProviderLifecycle.statusFields(
      event: "sleep",
      engineRunning: engineRunning
    )
    sleepFields.merge(packetEngine?.seamObservabilityStatusFields() ?? [:]) { _, new in new }
    writeProviderStatus(
      stage: "sleeping",
      config: activeConfig,
      engineReady: false,
      networkSettingsReady: false,
      extra: sleepFields
    )
    completionHandler()
  }

  override func wake() {
    let engineRunning = anySessionRunning
    var wakeFields = WinsPacketTunnelProviderLifecycle.statusFields(
      event: "wake",
      engineRunning: engineRunning
    )
    wakeFields.merge(packetEngine?.seamObservabilityStatusFields() ?? [:]) { _, new in new }
    writeProviderStatus(
      stage: "woke",
      config: activeConfig,
      engineReady: engineRunning,
      networkSettingsReady: engineRunning,
      extra: wakeFields
    )
  }

  private func makeNetworkSettings(from config: WinsTunnelConfig) throws -> NEPacketTunnelNetworkSettings {
    guard !config.networkSettingsRemoteAddress.isEmpty,
          !config.interfaceIPv4Address.isEmpty,
          !config.interfaceIPv4SubnetMask.isEmpty,
          !config.dnsServers.isEmpty,
          !config.allowedIPv4Routes.isEmpty else {
      throw Self.providerError(code: 1002, message: "Incomplete packet tunnel network settings.")
    }

    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: config.networkSettingsRemoteAddress
    )
    let ipv4Settings = NEIPv4Settings(
      addresses: [config.interfaceIPv4Address],
      subnetMasks: [config.interfaceIPv4SubnetMask]
    )
    // On macOS a full-tunnel default (`0.0.0.0/0`) must be installed as the
    // `/1` pair, never a bare `/0`: `appleIncludedIPv4Routes` expands it through
    // `WinsIPv4Route.macosFullTunnelDefaultPair` (RULED 2026-08-10, single
    // source `WinsMacRoutePosture`). This is the SAME enumeration the winn/3
    // standalone path (`WinsWinn3SessionStart`) installs, and the same
    // included-route shape `WinsKillSwitch.capturesAllIPv4` recognises as a
    // full capture. `NEIPv4Route.default()` is deliberately never used here; it
    // would reintroduce the bare `/0` the `/1` pair exists to replace.
    ipv4Settings.includedRoutes = config.appleIncludedIPv4Routes.map { route in
      NEIPv4Route(
        destinationAddress: route.destinationAddress,
        subnetMask: route.subnetMask
      )
    }
    if let exclusionRoute = config.transportIPv4ExclusionRoute {
      ipv4Settings.excludedRoutes = [
        NEIPv4Route(
          destinationAddress: exclusionRoute.destinationAddress,
          subnetMask: exclusionRoute.subnetMask
        )
      ]
    }
    // THE RESOLVER IS ROUTED THROUGH THE TUNNEL, ALWAYS.
    //
    // `allowedIPv4Routes` is the complement of the user's excluded CIDRs, so a
    // SPLIT tunnel does not guarantee a covering route for the resolver's own
    // address. lib/main.dart's Apple fallback installs a PUBLIC resolver (Quad9),
    // and without a covering route a query to it egresses the physical interface
    // in the clear, the exact name leak this product exists to prevent, while
    // the kill switch still reports "DNS captured" because matchDomains = [""]
    // names every name to that resolver. matchDomains only selects WHICH resolver
    // answers; it does not route that resolver's own packets. A /32 for each
    // IPv4 resolver pins its packets to the tunnel in both full and split
    // sessions, the same "protected resolver route" the Linux direct-AWG policy
    // commits. Only dotted-quad IPv4 literals are added; `NEDNSSettings` may
    // also carry IPv6 servers, which belong on the IPv6 route table, not here.
    //
    // ORDERING IS LOAD-BEARING. `NEPacketTunnelNetworkSettings.IPv4Settings` is
    // declared `@property (copy)`, so assigning `ipv4Settings` into `settings`
    // snapshots the route array at that instant. Every route appended after the
    // assignment lands on an object the system never reads. These /32 routes are
    // therefore built BEFORE the assignment below, never after it.
    for server in config.dnsServers where Self.isIPv4Literal(server) {
      ipv4Settings.includedRoutes?.append(
        NEIPv4Route(destinationAddress: server, subnetMask: "255.255.255.255")
      )
    }
    settings.ipv4Settings = ipv4Settings
    if config.ipv6LeakProtectionEnabled {
      let ipv6Settings = NEIPv6Settings(
        addresses: [config.ipv6SinkAddress],
        networkPrefixLengths: [NSNumber(value: config.ipv6SinkPrefixLength)]
      )
      ipv6Settings.includedRoutes = [NEIPv6Route.default()]
      settings.ipv6Settings = ipv6Settings
    }
    let dnsSettings = NEDNSSettings(servers: config.dnsServers)
    if !config.dnsMatchDomains.isEmpty {
      dnsSettings.matchDomains = config.dnsMatchDomains
    }
    settings.dnsSettings = dnsSettings
    settings.mtu = NSNumber(value: config.mtu)
    return settings
  }

  /// Whether `value` is a dotted-quad IPv4 literal. `NEDNSSettings` may carry
  /// IPv6 servers too, and only IPv4 servers belong on the tunnel's IPv4
  /// included-route table. Each `.`-separated part must parse as a 0-255 octet.
  private static func isIPv4Literal(_ value: String) -> Bool {
    let parts = value.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { UInt8($0) != nil }
  }

  // MARK: - Runtime appex memory gate (winn/3 only)

  private static let winnDirectAwgDatapathRequiredBytes = 12 * 1024 * 1024

  struct WinsWinnAppexMemoryGate {
    let availableBytes: Int?
    let carrier: String
    let requiredBytes: Int
    let physicalFootprintBytes: Int?

    var refusalReason: String? {
      if !carrier.isEmpty, carrier != WinsTunnelConfig.supportedWinnCarrier {
        if carrier != WinsTunnelConfig.supportedWinnCarrierWinn3 {
          return "winn_carrier_memory_profile_unmeasured"
        }
      }
      // `os_proc_available_memory()` is iOS-only. macOS has no iOS-style
      // NetworkExtension jetsam ceiling, so unmeasurable headroom is a
      // platform fact, not a low-memory reading. Proceed and record the
      // deviation via `winn_memory_gate_macos_unknown_headroom_allowed`.
      guard let availableBytes else {
        return nil
      }
      if availableBytes < requiredBytes {
        return "appex_available_memory_below_winn_datapath_requirement"
      }
      return nil
    }

    var allowed: Bool { refusalReason == nil }

    var statusFields: [String: Any] {
      var fields: [String: Any] = [
        "winn_memory_gate_checked": true,
        "winn_memory_gate_allowed": allowed,
        "winn_memory_gate_required_bytes": requiredBytes,
        "winn_memory_gate_available_measured": availableBytes != nil,
        "winn_memory_gate_carrier": carrier.isEmpty ? "direct-awg-implicit" : carrier
      ]
      if let availableBytes {
        fields["winn_memory_gate_available_bytes"] = availableBytes
      } else {
        fields["winn_memory_gate_macos_unknown_headroom_allowed"] = true
      }
      if let physicalFootprintBytes {
        fields["winn_memory_gate_phys_footprint_bytes"] = physicalFootprintBytes
      }
      if let refusalReason {
        fields["winn_memory_gate_refusal_reason"] = refusalReason
      }
      return fields
    }
  }

  private static func physicalFootprintBytes() -> Int? {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(
      MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size
    )
    let result = withUnsafeMutablePointer(to: &info) {
      $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
        task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
      }
    }
    guard result == KERN_SUCCESS else {
      return nil
    }
    let footprint = info.phys_footprint
    return footprint <= UInt64(Int.max) ? Int(footprint) : nil
  }

  private static func availableProcessMemoryBytes() -> Int? {
    #if os(iOS)
    let available = os_proc_available_memory()
    return available > 0 ? available : nil
    #else
    return nil
    #endif
  }

  private func winnAppexMemoryGate(for config: WinsTunnelConfig) -> WinsWinnAppexMemoryGate? {
    guard config.winnEnabled else {
      return nil
    }
    return WinsWinnAppexMemoryGate(
      availableBytes: Self.availableProcessMemoryBytes(),
      carrier: (config.sections["winn"]?["carrier"] ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased(),
      requiredBytes: Self.winnDirectAwgDatapathRequiredBytes,
      physicalFootprintBytes: Self.physicalFootprintBytes()
    )
  }

  // MARK: - Staged winn/3 start: prove the datapath, then take the host
  //
  // # The failure this exists to make impossible
  //
  // Until this change the ONE call to `setTunnelNetworkSettings` installed the
  // full-tunnel settings — default IPv4 route, IPv6 sink with `::/0`, DNS with
  // an empty match domain (= every domain) — BEFORE anything had shown the
  // datapath could carry a packet. A winn/3 session whose handshake never
  // completed therefore held all three and carried nothing: total host
  // blackout, surviving the app because the appex outlives it (2026-08-05, and
  // the owner lost the machine to it and had to reboot). The dev-only
  // containment above exists because of that failure — but containment is
  // `#if DEBUG` and must stay dev-only, which made the blackout structurally
  // unfixable on the SHIPPING path. This section fixes the shipping path
  // itself.
  //
  // # The shape, and where it comes from
  //
  // This is deliberately the WINDOWS HOST'S design, not a new one.
  // `windows/runner/windows_tunnel_backend.cpp` pins the `[winn]` endpoint /32
  // on the physical interface BEFORE any tunnel route, sends an in-tunnel DNS
  // convergence probe, and promotes to full-tunnel routing only on
  // `transport_observed_both_ways` plus a proven-recent AWG handshake — and
  // fails CLOSED (`FailClosedPrivilegedTunnel`) if neither arrives in time.
  // The Go datapath was designed for exactly this gate:
  // `winn_protocol_experimental/datapath/classify.go` calls
  // `TransportObservedBothWays` "the single field a route-promotion gate may
  // read", and is explicit that `up` may gate nothing. Apple was the only
  // host installing full-tunnel settings before that field could possibly be
  // true. Now:
  //
  //  1. BOOTSTRAP — `startTunnel` installs a narrow posture first: interface
  //     address, at most one /32 included route (the tunnel's own inner
  //     gateway, the same derivation `WinsTunnelConfig`'s own inner-gateway
  //     helper uses), the transport /32
  //     exclusion, no default route, no IPv6, no DNS. The host's routing,
  //     resolvers and IPv6 are untouched, exactly as before pressing Connect.
  //  2. PROVE — the engine starts against that posture. `PersistentKeepalive`
  //     makes AmneziaWG initiate immediately, and the provider sends small
  //     in-tunnel DNS probes (the Windows convergence probe, byte for byte) to
  //     the config's own resolvers so there is payload-class traffic for the
  //     engine to observe. The loop reads the engine's own status fields —
  //     never `up` — until `handshake_response_observed` AND
  //     `transport_observed_both_ways` are both true, and (whenever the probe
  //     socket exists) at least one probe RESPONSE has arrived back through
  //     AmneziaWG decryption — end-to-end cryptographic proof, the analogue of
  //     the AWG-runtime handshake check the Windows gate reads.
  //  3. PROMOTE — only then is `setTunnelNetworkSettings` called AGAIN with
  //     the exact full-tunnel settings object `makeNetworkSettings` built,
  //     unchanged, and only after THAT commit does `startTunnel` complete, so
  //     the system never reports Connected for a tunnel that has not carried
  //     traffic both ways.
  //  4. FAIL CLOSED — on deadline, engine exit, or supersession the start
  //     fails while the host still holds its own routes, resolvers and IPv6.
  //     The worst wedge (`NEAgentErrorDomain` code 1 has been reproduced on
  //     both platforms; a settings release can be refused) now strands at most
  //     one VPN-owned /32 and one exclusion /32 — not the host.
  //
  // # THE KILL SWITCH OVERRIDES POINT 1 (and therefore the narrow-reading of
  // # points 1 and 4) FOR PRODUCTION FULL-TUNNEL RUNS, PUT THERE 2026-08-10
  //
  // 1. INSTALL was the narrow posture only to keep the host untouched while the
  //    datapath was proven. That is the anti-kill-switch: while the host is
  //    untouched, traffic the device emits during the connect window egresses
  //    in the clear, which for these users is the leak the whole product exists
  //    to prevent. So `makeWinnStagedStartPlan` now makes the FIRST posture the
  //    BLOCKING (full-tunnel) one for every production full-tunnel winn start,
  //    verified blocking by `WinsKillSwitch.egressBlocked`. The block is held
  //    from the first settings commit; the proof loop and its fail-closed
  //    deadline are unchanged and still gate the START from completing.
  // 4. FAIL-CLOSED therefore means: on deadline/engine-exit/supersession, the
  //    start fails and the host is released when the session ends (teardown),
  //    not untouched throughout. The user sees a failed connect after a bounded
  //    blackout — the fail-closed direction the no-watchdog doctrine already
  //    takes ("a dead tunnel that blacks out is still safer than one that
  //    silently falls back to cleartext"). The one exception is the
  //    `winn_datapath_proof_hold` lab run, which keeps today's narrow
  //    "never claims the host" posture because it exists to test promotion
  //    without taking this machine.
  //
  // # What this deliberately does NOT change
  //
  //  * Non-winn starts. AmneziaWG and Xray production sessions install their
  //    settings in one step exactly as before — byte-identical documents,
  //    byte-identical behaviour. Their engines expose no
  //    `transport_observed_both_ways` to this provider today, so a staged
  //    start for them would have to gate on something the Go datapath's own
  //    documentation forbids, and this section refuses to invent one.
  //  * Split-tunnel winn starts. Without a default route there is no host
  //    seizure to stage, so nothing is staged.
  //  * The no-watchdog doctrine. `releaseTunnelNetworkSettings`'s doc comment
  //    promises no health watchdog ever tears down a RUNNING tunnel onto
  //    cleartext, and that stands: this gate acts strictly BEFORE the session
  //    first claims the host, while the system still reports Connecting and
  //    the user has been promised nothing. After promotion the tunnel holds
  //    its routes fail-closed exactly as before — for a user under a hostile
  //    state, a dead tunnel that blacks out is still safer than one that
  //    silently falls back to cleartext.

  /// True when this start must run as far as PROVEN and then STOP, instead of
  /// promoting. Selected by `winnDatapathProofHoldKey`, read from the start
  /// options and from the saved provider configuration.
  ///
  /// Either source is enough, deliberately. Holding can only ever REFUSE a
  /// promotion and never cause one, so the permissive read is the safe read —
  /// unlike every other option here, where the transient value overrides the
  /// saved one.
  ///
  /// It exists because the promotion commit takes this machine's IPv4 default
  /// route, IPv6 and DNS in a single `setTunnelNetworkSettings` call. On a
  /// workstation that is the developer's own connectivity, so exercising the
  /// gate end to end had no safe form. Held, the start proves the datapath,
  /// records the identical evidence, and fails closed untouched.
  private func winnDatapathProofPromotionHeld(options: [String: NSObject]?) -> Bool {
    let transient: Any? = options?[Self.winnDatapathProofHoldKey]
    let saved: Any? = (protocolConfiguration as? NETunnelProviderProtocol)?
      .providerConfiguration?[Self.winnDatapathProofHoldKey]
    return Self.winnDatapathProofHoldFlag(transient)
      || Self.winnDatapathProofHoldFlag(saved)
  }

  /// Bools, plist numbers and the string spellings a hand-edited provider
  /// configuration is likely to carry. Anything unrecognised is NOT a hold.
  private static func winnDatapathProofHoldFlag(_ value: Any?) -> Bool {
    if let stringValue = value as? String {
      return ["1", "true", "yes", "on"].contains(
        stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
      )
    }
    return WinsWinnDatapathProofGate.flag(value)
  }

  /// Decides whether this start is staged, and builds both postures up front
  /// if so. Returns nil for every start that must keep today's single-install
  /// behaviour. Throwing is reserved for a bootstrap that cannot be built
  /// safely — a start that WOULD be staged but cannot be is refused, never
  /// silently widened to an immediate full tunnel: a start that cannot express
  /// BOTH postures is not a start this provider knows how to make safely.
  private func makeWinnStagedStartPlan(
    from config: WinsTunnelConfig,
    fullTunnelSettings: NEPacketTunnelNetworkSettings,
    promotionHeld: Bool
  ) throws -> WinsWinnStagedStartPlan? {
    guard WinsWinnDatapathProofGate.applies(
      winnEnabled: config.winnEnabled,
      defaultIPv4RouteEnabled: config.defaultIPv4RouteEnabled,
      // Always false here. Dev containment is an iOS-provider construct; this
      // provider has no containment path at all, so there is no contained
      // session for the gate to decline to widen. Spelled out rather than
      // dropped so the shared predicate keeps one signature on both platforms.
      devContainmentActive: false
    ) else {
      return nil
    }

    // THE KILL SWITCH: for a production full-tunnel winn session the FIRST
    // posture is the blocking one, not the narrow one. See `WinsKillSwitch`.
    // The proof loop still gates the START from completing (it will not report
    // carrying until the datapath is proven), but the host is routed into the
    // tunnel from the instant the first settings commit, so nothing the device
    // emits during the connect window egresses in the clear.
    //
    // `promotionHeld` (the `winn_datapath_proof_hold` lab run) is the one dev
    // case: a held run deliberately never claims the host, so it keeps today's
    // narrow bootstrap.
    if !promotionHeld,
       WinsKillSwitch.activeFor(config: config, devRunActive: promotionHeld) {
      // Read back, refuse rather than install if the posture does not block.
      let verifiedBlocking = WinsKillSwitch.egressBlocked(
        by: fullTunnelSettings,
        config: config
      )
      guard verifiedBlocking else {
        throw Self.providerError(
          code: 1026,
          message: "The kill-switch posture for this staged winn start does not observably block egress; refusing to install it.",
          statusFields: WinsKillSwitch.bootstrapStatusFields(
            config: config,
            verifiedBlocking: false,
            firstPostureBlocking: true
          )
        )
      }
      return WinsWinnStagedStartPlan(
        bootstrapSettings: fullTunnelSettings,
        fullTunnelSettings: fullTunnelSettings,
        interfaceIPv4Address: config.interfaceIPv4Address,
        probeDNSServers: config.dnsServers,
        bootstrapStatusFields: WinsKillSwitch.bootstrapStatusFields(
          config: config,
          verifiedBlocking: true,
          firstPostureBlocking: true
        ),
        promotionHeld: promotionHeld
      )
    }

    let gatewayRoute = WinsWinnDatapathProofGate.bootstrapGatewayRoute(
      interfaceIPv4Address: config.interfaceIPv4Address
    )
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: config.networkSettingsRemoteAddress
    )
    let ipv4Settings = NEIPv4Settings(
      addresses: [config.interfaceIPv4Address],
      subnetMasks: [config.interfaceIPv4SubnetMask]
    )
    if let gatewayRoute {
      ipv4Settings.includedRoutes = [
        NEIPv4Route(
          destinationAddress: gatewayRoute.destinationAddress,
          subnetMask: gatewayRoute.subnetMask
        )
      ]
    } else {
      // No derivable inner gateway: bootstrap with no included routes at all.
      // The convergence probe does not depend on this route — it reaches the
      // tunnel by interface binding, not by the route table.
      ipv4Settings.includedRoutes = []
    }
    if let exclusionRoute = config.transportIPv4ExclusionRoute {
      // Installed from the very first posture so the engine's outer socket can
      // never be captured later by the promotion commit.
      ipv4Settings.excludedRoutes = [
        NEIPv4Route(
          destinationAddress: exclusionRoute.destinationAddress,
          subnetMask: exclusionRoute.subnetMask
        )
      ]
    }
    settings.ipv4Settings = ipv4Settings
    // settings.ipv6Settings deliberately left nil — the host keeps its IPv6.
    // settings.dnsSettings deliberately left nil — the host keeps its
    // resolvers; name resolution never depends on an unproven tunnel.
    settings.mtu = NSNumber(value: config.mtu)

    // Observably narrow, verified on the object just built rather than assumed
    // from the code that built it — the same fail-closed posture the iOS
    // containment observation established. A bootstrap that somehow carries a
    // default route, DNS or IPv6 must refuse the start, never install.
    let includedRoutes = settings.ipv4Settings?.includedRoutes ?? []
    let carriesDefaultRoute = includedRoutes.contains { route in
      route.destinationAddress == "0.0.0.0"
    }
    guard !carriesDefaultRoute,
          includedRoutes.count <= 1,
          settings.dnsSettings == nil,
          settings.ipv6Settings == nil else {
      throw Self.providerError(
        code: 1023,
        message: "Staged winn start built bootstrap settings that are not observably narrow; refusing to start rather than installing them.",
        statusFields: [
          "winn_datapath_proof_gate_active": true,
          "winn_datapath_proof_bootstrap_observably_narrow": false
        ]
      )
    }

    return WinsWinnStagedStartPlan(
      bootstrapSettings: settings,
      fullTunnelSettings: fullTunnelSettings,
      interfaceIPv4Address: config.interfaceIPv4Address,
      probeDNSServers: config.dnsServers,
      bootstrapStatusFields: WinsWinnDatapathProofGate.bootstrapStatusFields(
        bootstrapIncludedRouteCount: includedRoutes.count,
        bootstrapGatewayRoutePresent: gatewayRoute != nil,
        transportExclusionRoutePresent: config.transportIPv4ExclusionRoute != nil,
        probeTargetCount: config.dnsServers.count
      ),
      promotionHeld: promotionHeld
    )
  }

  /// The PROVE and PROMOTE stages. Runs after the bootstrap settings are
  /// committed and the engine has started; owns the engine until it either
  /// hands it to `packetEngine` on promotion or stops it on any failure.
  ///
  /// `packetEngine` stays nil until promotion so readiness stays accurate.
  /// `provingPacketEngine` gives stopTunnel ownership during proof.
  private func runWinnDatapathProofConvergence(
    plan: WinsWinnStagedStartPlan,
    engine: WinsPacketTunnelEngine,
    startResult: WinsPacketTunnelEngineStartResult,
    parsedConfig: WinsTunnelConfig,
    baseStatusFields: [String: Any],
    lifecycleToken: UInt64,
    statusGeneration: String,
    completionHandler: @escaping (Error?) -> Void
  ) {
    guard lifecycleGate.performIfCurrent(lifecycleToken, action: {
      provingPacketEngine = engine
    }) else {
      engine.stop()
      completionHandler(Self.canceledStartError())
      return
    }

    func stopProvingResource() {
      provingStopLock.lock()
      defer { provingStopLock.unlock() }
      engine.stop()
      _ = lifecycleGate.performIfCurrent(lifecycleToken) {
        if provingPacketEngine === engine {
          provingPacketEngine = nil
        }
      }
    }

    let startedAt = DispatchTime.now()
    let deadlineMilliseconds = Int(
      (Self.winnDatapathProofDeadlineSeconds * 1000).rounded()
    )

    // WHICH DATAPATH IS BEING PROVEN, and therefore which §4.1 predicate
    // applies. A relay session (`direct-awg`, `http3-connect-udp`) is proven by
    // the engine's handshake-response and both-ways-transport flags; a winn/3
    // STANDALONE session is proven by the tun gate carrying AND an inner packet
    // validated and delivered. They are different predicates because the two
    // datapaths can prove different things — a relay cannot see inner IP at all
    // — and resolving the choice ONCE, here, is what stops the two providers
    // from drifting apart.
    //
    // An unrecognised carrier resolves to nil and falls back to the relay
    // predicate. That is the conservative direction: the relay predicate is
    // strictly harder to satisfy for a standalone session (it reads flags a
    // standalone status document never sets), so the failure mode of guessing
    // wrong here is a refusal at the deadline, never a promotion.
    let datapathKind =
      WinsWinnDatapathKind.forCarrier(parsedConfig.winnCarrier) ?? .relay
    os_log(
      "%{public}@ BOOTSTRAP posture active: no default IPv4 route, no IPv6 settings, no DNS settings. The full tunnel is installed only after the datapath is proven.",
      log: logger,
      type: .info,
      WinsWinnDatapathProofGate.logToken
    )

    let probe = WinsWinnDatapathProofProbe(
      interfaceIPv4Address: plan.interfaceIPv4Address,
      dnsServers: plan.probeDNSServers
    )
    if probe == nil {
      // Recorded, not fatal by itself: keepalives still force the handshake,
      // and if nothing ever produces payload traffic the gate fails closed at
      // the deadline — which is the correct outcome for a tunnel that cannot
      // demonstrably carry payload.
      os_log(
        "%{public}@ convergence probe unavailable; relying on engine-observed traffic only.",
        log: logger,
        type: .error,
        WinsWinnDatapathProofGate.logToken
      )
    }

    func elapsedMilliseconds() -> Int {
      let elapsed = DispatchTime.now().uptimeNanoseconds &- startedAt.uptimeNanoseconds
      return Int(min(elapsed / 1_000_000, UInt64(Int.max)))
    }

    func progressFields(
      engineFields: [String: Any],
      converged: Bool,
      promoted: Bool
    ) -> [String: Any] {
      var fields = baseStatusFields
      fields.merge(engineFields) { _, new in new }
      fields.merge(WinsWinnDatapathProofGate.progressStatusFields(
        probeAvailable: probe != nil,
        probesSent: probe?.probesSent ?? 0,
        probeResponsesObserved: probe?.responsesObserved ?? 0,
        engineStatusFields: engineFields,
        converged: converged,
        promoted: promoted,
        elapsedMilliseconds: elapsedMilliseconds(),
        deadlineMilliseconds: deadlineMilliseconds
      )) { _, new in new }
      // Empty for a relay session, which already publishes its own proof
      // fields. For a standalone session this is the gate state, the DELIVERED
      // packet count and the OFFERED count side by side, so a reader can see
      // which counter the promotion decision was made on.
      fields.merge(datapathKind.statusFields(engineStatusFields: engineFields)) { _, new in new }
      return fields
    }

    // The first status document of the staged phase: engine running, host NOT
    // claimed. `networkSettingsReady: false` keeps every healthy/ready reader
    // honest about a session that is still proving itself.
    _ = lifecycleGate.performIfCurrent(lifecycleToken) {
      writeProviderStatus(
        stage: "engine_started",
        config: parsedConfig,
        engineReady: startResult.engineReady,
        networkSettingsReady: false,
        extra: progressFields(
          engineFields: [:],
          converged: false,
          promoted: false
        ),
        statusGeneration: statusGeneration
      )
    }

    let queue = DispatchQueue(
      label: "org.winsvpn.app.PacketTunnel.winn-datapath-proof",
      qos: .userInitiated
    )
    let timer = DispatchSource.makeTimerSource(queue: queue)
    var finished = false
    var tickCount = 0

    func finishCanceled() {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      completionHandler(Self.canceledStartError())
    }

    func finishFailure(stage: String, error: NSError, engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      os_log(
        "%{public}@ FAILED CLOSED before promotion: %{public}@ The host's routing, IPv6 and DNS were never claimed.",
        log: logger,
        type: .error,
        WinsWinnDatapathProofGate.logToken,
        WinsTunnelDiagnostics.redactedProviderErrorMessage(error)
      )
      var fields = progressFields(
        engineFields: engineFields,
        converged: false,
        promoted: false
      )
      fields.merge(Self.providerStatusFields(from: error)) { _, new in new }
      _ = lifecycleGate.performIfCurrent(lifecycleToken) {
        writeProviderStatus(
          stage: stage,
          config: parsedConfig,
          engineReady: false,
          networkSettingsReady: false,
          error: error,
          extra: fields,
          statusGeneration: statusGeneration
        )
      }
      completionHandler(error)
    }

    /// PROVEN, then stop — the deliberate non-promotion the
    /// `winn_datapath_proof_hold` key selects. Everything up to the promotion
    /// commit has already happened, so the recorded evidence is exactly what a
    /// promoting run would have recorded; only the commit is withheld, and the
    /// Mac's routing, IPv6 and DNS are never claimed. Reported as a failed
    /// start because that is what it is: no tunnel is left running.
    func finishProvenWithPromotionHeld(engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      os_log(
        "%{public}@ PROVEN; promotion HELD on purpose. The host's routing, IPv6 and DNS were never claimed.",
        log: logger,
        type: .info,
        WinsWinnDatapathProofGate.logToken
      )
      let error = Self.providerError(
        code: 1024,
        message: "The winn datapath was proven and promotion was held on purpose; full-tunnel settings were not installed.",
        statusFields: ["winn_datapath_proof_promotion_held": true]
      )
      var fields = progressFields(
        engineFields: engineFields,
        converged: true,
        promoted: false
      )
      fields.merge(Self.providerStatusFields(from: error)) { _, new in new }
      _ = lifecycleGate.performIfCurrent(lifecycleToken) {
        writeProviderStatus(
          stage: "engine_start_failed",
          config: parsedConfig,
          engineReady: false,
          networkSettingsReady: false,
          error: error,
          extra: fields,
          statusGeneration: statusGeneration
        )
      }
      completionHandler(error)
    }

    func beginPromotion(engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      os_log(
        "%{public}@ datapath proven (handshake response observed, transport observed both ways); promoting to full-tunnel settings.",
        log: logger,
        type: .info,
        WinsWinnDatapathProofGate.logToken
      )
      let promotionLock = NSLock()
      var promotionCompleted = false
      func completePromotionOnce(_ action: @escaping () -> Void) {
        promotionLock.lock()
        let alreadyCompleted = promotionCompleted
        promotionCompleted = true
        promotionLock.unlock()
        guard !alreadyCompleted else { return }
        action()
      }
      // The promotion commit is expected to call back, but a start must never
      // be able to hang on it — same reasoning as the settings-release
      // deadline in `releaseTunnelNetworkSettings`.
      queue.asyncAfter(
        deadline: .now() + Self.winnDatapathPromotionSettingsDeadlineSeconds
      ) {
        completePromotionOnce {
          let error = Self.providerError(
            code: 1021,
            message: "Full-tunnel promotion settings did not commit before the deadline.",
            statusFields: ["winn_datapath_proof_promotion_deadline_expired": true]
          )
          stopProvingResource()
          var fields = progressFields(
            engineFields: engineFields,
            converged: true,
            promoted: false
          )
          fields.merge(Self.providerStatusFields(from: error)) { _, new in new }
          _ = self.lifecycleGate.performIfCurrent(lifecycleToken) {
            self.writeProviderStatus(
              stage: "network_settings_failed",
              config: parsedConfig,
              engineReady: false,
              networkSettingsReady: false,
              error: error,
              extra: fields,
              statusGeneration: statusGeneration
            )
          }
          completionHandler(error)
        }
      }
      let commitPromotion: (@escaping (Error?) -> Void) -> Void = { done in
        if plan.promotionInstallsNewSettings {
          self.setTunnelNetworkSettings(plan.fullTunnelSettings, completionHandler: done)
        } else {
          done(nil)
        }
      }
      commitPromotion { settingsError in
        queue.async {
          completePromotionOnce {
            if let settingsError {
              stopProvingResource()
              var fields = progressFields(
                engineFields: engineFields,
                converged: true,
                promoted: false
              )
              fields["network_settings_applied"] = false
              _ = self.lifecycleGate.performIfCurrent(lifecycleToken) {
                self.writeProviderStatus(
                  stage: "network_settings_failed",
                  config: parsedConfig,
                  engineReady: false,
                  networkSettingsReady: false,
                  error: settingsError,
                  extra: fields,
                  statusGeneration: statusGeneration
                )
              }
              completionHandler(settingsError)
              return
            }
            let promotedFields = progressFields(
              engineFields: engine.seamObservabilityStatusFields(),
              converged: true,
              promoted: true
            )
            let handedOver = self.lifecycleGate.performIfCurrent(lifecycleToken) {
              if self.provingPacketEngine === engine {
                self.provingPacketEngine = nil
              }
              self.packetEngine = engine
              self.activeEngineStatusFields = promotedFields
              self.writeProviderStatus(
                stage: "engine_started",
                config: parsedConfig,
                engineReady: startResult.engineReady,
                networkSettingsReady: true,
                extra: promotedFields,
                statusGeneration: statusGeneration
              )
            }
            guard handedOver else {
              stopProvingResource()
              completionHandler(Self.canceledStartError())
              return
            }
            os_log(
              "%{public}@ PROMOTED: full-tunnel settings committed after datapath proof.",
              log: self.logger,
              type: .info,
              WinsWinnDatapathProofGate.logToken
            )
            completionHandler(nil)
          }
        }
      }
    }

    timer.setEventHandler {
      guard !finished else { return }
      guard self.lifecycleGate.isCurrent(lifecycleToken) else {
        finishCanceled()
        return
      }
      guard engine.isRunning else {
        finishFailure(
          stage: "engine_start_failed",
          error: Self.providerError(
            code: 1022,
            message: "The winn engine exited while the datapath was still being proven.",
            statusFields: ["winn_datapath_proof_engine_exited": true]
          ),
          engineFields: engine.seamObservabilityStatusFields()
        )
        return
      }
      tickCount += 1
      if let probe, tickCount % 2 == 1 {
        probe.sendNextProbe()
      }
      probe?.drainResponses()
      let engineFields = engine.seamObservabilityStatusFields()
      // The engine's two flags prove the carrier observed a handshake response
      // and payload-class traffic in both directions. When the probe socket
      // exists, one probe RESPONSE is additionally required: a datagram that
      // came back through AmneziaWG decryption onto the tunnel interface,
      // which is end-to-end cryptographic proof that no datagram-shape
      // classification can forge. (Windows proves the same half by reading the
      // AWG runtime's own handshake and transfer counters; this provider
      // cannot reach those, so it proves it end to end instead — strictly
      // stronger.) Only when no probe socket could be created does the gate
      // fall back to the engine flags alone, and the status fields say so.
      //
      // For a winn/3 STANDALONE session `datapathKind.converged` is the tun
      // lane's §4.1 predicate instead: `Gate.State() == StateCarrying` AND
      // `Stats().RxPackets > 0` — validated and DELIVERED, not merely arrived.
      // The in-tunnel probe requirement still applies on top of it, because a
      // delivered packet the gateway sent unprompted is weaker evidence than
      // one that came back because this host asked for it.
      let probeSatisfied = probe == nil || (probe?.responsesObserved ?? 0) > 0
      if datapathKind.converged(engineStatusFields: engineFields),
         probeSatisfied {
        if plan.promotionHeld {
          finishProvenWithPromotionHeld(engineFields: engineFields)
        } else {
          beginPromotion(engineFields: engineFields)
        }
        return
      }
      if elapsedMilliseconds() >= deadlineMilliseconds {
        finishFailure(
          stage: "engine_start_failed",
          error: Self.providerError(
            code: 1020,
            message: "The winn datapath was not proven within the fail-closed deadline; refusing to install full-tunnel settings.",
            statusFields: ["winn_datapath_proof_timeout": true]
          ),
          engineFields: engineFields
        )
      }
    }
    timer.schedule(
      deadline: .now() + .milliseconds(Self.winnDatapathProofTickMilliseconds),
      repeating: .milliseconds(Self.winnDatapathProofTickMilliseconds)
    )
    timer.resume()
  }

  // MARK: - winn/3 STANDALONE
  //
  // # What this is, and why it is not the staged relay start above
  //
  // Everything above this line proves an AmneziaWG relay: AmneziaWG owns the
  // utun, does all of the cryptography, and Winn carries its already-
  // encapsulated outer datagrams. The staged start proves it with the engine's
  // handshake-response and both-ways-transport flags.
  //
  // winn/3 STANDALONE has no AmneziaWG in it anywhere. The winn/3 driver loop
  // owns the session, the winn/3 tun layer validates inner IP, and this
  // provider's job reduces to the three obligations
  // `WinsWinn3HostContract.swift` names: a device (`packetFlow`, across the C
  // ABI, driven by `WinsWinn3Datapath`), a carrier socket kept off the tunnel
  // (the excludedRoutes /32, present from the first posture), and a clock
  // (Go's, deliberately not this host's).
  //
  // # The order, which is not the relay's order and cannot be
  //
  // The relay start installs settings and then starts an engine. Standalone
  // CREATES FIRST and installs second, because §4.2 makes the interface MTU an
  // obligation — it must be exactly `Tunnel.InnerMTU()` — and only the engine
  // knows that number. It is `driver.NewSizing` over the whole migration plan,
  // and a second implementation of that arithmetic in Swift would be a number
  // that can disagree with the engine's, which §4.2 makes a black hole rather
  // than an inefficiency.
  //
  // Creating first does open the outer socket before any posture exists. That
  // is safe, and it is the SAFE ORDER rather than merely a tolerable one: until
  // `setTunnelNetworkSettings` is called this provider's tunnel has no routes
  // at all, so there is nothing for the socket to be captured by; and the
  // exclusion /32 is present from the very first posture installed, which is
  // the one thing §4.1 actually requires — the capture it warns about happens
  // at PROMOTION, and the /32 predates it.
  //
  // The PUMP, by contrast, does not start at create. It starts after the
  // bootstrap is committed, so no inner packet can move under a posture nobody
  // has verified is narrow.
  //
  // # What this still does not do
  //
  // It does not flip `kWinnHostCapabilities`. A start that is permitted is not
  // a session that happened. Release force-loads the Winn archive, while
  // `WinsWinn3Datapath.start` still refuses with `symbolsUnavailable` before
  // anything else here runs if staging or linking produced a broken appex.

  /// Starts a winn/3 STANDALONE session, or refuses without touching the Mac.
  ///
  /// The memory gate above (`winnAppexMemoryGate`, in `startTunnel`) decides
  /// whether the datapath MAY start; this is the step that turns an allowed
  /// verdict into a datapath that actually receives configuration.
  private func emitWinn3Config(
    for config: WinsTunnelConfig,
    statusFields: [String: Any]
  ) throws -> WinsWinn3CreateDocument {
    guard let createDocument = WinsWinn3CreateDocument.make(config: config) else {
      throw Self.providerError(
        code: 1030,
        message: WinsWinn3StartRequirements.refusalReason(config)
          ?? "A winn/3 standalone session cannot start from this configuration.",
        statusFields: statusFields
      )
    }
    return createDocument
  }

  /// Throws before any settings are installed. Every throw lands in
  /// `startTunnel`'s own catch, which writes a `start_rejected` document
  /// carrying the status fields the error hauls with it — so a refusal is
  /// always readable, and is never a silent fallback to the relay.
  private func startWinn3StandaloneSession(
    config: WinsTunnelConfig,
    baseStatusFields: [String: Any],
    promotionHeld: Bool,
    lifecycleToken: UInt64,
    statusGeneration: String,
    completionHandler: @escaping (Error?) -> Void
  ) throws {
    var statusFields = baseStatusFields
    statusFields.merge(
      WinsWinn3SessionStatus.startFields(
        config: config,
        attempted: true,
        refusalReason: nil
      )
    ) { _, new in new }

    let createDocument = try emitWinn3Config(for: config, statusFields: statusFields)
    guard !config.allowedIPv4Routes.isEmpty else {
      throw Self.providerError(
        code: 1030,
        message: "A winn/3 standalone start has no included routes to promote to; refusing rather than proving a datapath and then installing a tunnel that routes nothing.",
        statusFields: statusFields
      )
    }

    let datapath = WinsWinn3Datapath()
    do {
      try datapath.start(document: try createDocument.json(), carrierDescriptor: -1)
    } catch {
      datapath.stop()
      throw Self.providerError(
        code: 1031,
        message: "The winn/3 standalone datapath could not be created: \(WinsTunnelDiagnostics.redactedProviderErrorMessage(error))",
        statusFields: statusFields
      )
    }

    guard lifecycleGate.performIfCurrent(lifecycleToken, action: {
      provingWinn3Datapath = datapath
    }) else {
      datapath.stop()
      completionHandler(Self.canceledStartError())
      return
    }
    let publishedFields = datapath.statusFields()
    statusFields.merge(publishedFields) { _, new in new }
    let innerMTU = Int(
      clamping: WinsWinn3PromotionGate.unsignedValue(
        publishedFields[WinsWinn3PromotionGate.innerMTUKey]
      )
    )
    guard innerMTU > 0 else {
      datapath.stop()
      throw Self.providerError(
        code: 1032,
        message: "The winn/3 engine published no inner MTU. §4.2 makes the interface MTU exactly Tunnel.InnerMTU(), and there is nothing to set it to.",
        statusFields: statusFields
      )
    }

    // THE PROMOTED POSTURE IS BUILT BEFORE ANYTHING IS INSTALLED.
    //
    // Not for tidiness: `fullTunnel` REFUSES — it returns nil rather than a
    // wider posture — when this configuration has no resolver a standalone
    // session can justify, and building it here means that refusal lands while
    // nothing has been installed and nothing has to be torn down. It is the
    // same pre-flight linux/runner/linux_tunnel_backend.cc performs with the
    // real `BuildPromotedPosture` at START.
    //
    // A session that reached this point with no usable promotion would
    // otherwise bootstrap, prove its datapath, and then have nowhere to go: it
    // would either sit on a posture that captures nothing while reporting
    // carrying, or promote and hand every DNS query to the resolver the censor
    // operates. Both report success. See `WinsWinn3Resolvers`.
    guard let fullTunnelSettings = WinsWinn3Settings.fullTunnel(config: config, innerMTU: innerMTU) else {
      datapath.stop()
      let reason = WinsWinn3Resolvers.promotionRefusalReason(config)
        ?? "the promoted posture failed its own narrowness check"
      statusFields.merge(
        WinsWinn3PromotedPosture.evaluate(
          WinsWinn3Settings.bootstrap(config: config, innerMTU: innerMTU),
          config: config
        ).statusFields
      ) { _, new in new }
      throw Self.providerError(
        code: 1038,
        message: "The winn/3 standalone session was refused before anything was installed: \(reason).",
        statusFields: statusFields
      )
    }

    // THE KILL SWITCH. For a production full-tunnel standalone session the
    // FIRST posture installed is the blocking full-tunnel posture, so egress is
    // captured from the instant the session exists rather than only after the
    // datapath is proven. `promotionHeld` (a contained/held dev run) is the one
    // case that keeps the narrow "host untouched" bootstrap.
    let killSwitchActive =
      !promotionHeld && WinsKillSwitch.activeFor(config: config, devRunActive: promotionHeld)

    let firstPosture: NEPacketTunnelNetworkSettings
    let postureName: String
    if killSwitchActive {
      guard WinsKillSwitch.egressBlocked(by: fullTunnelSettings, config: config) else {
        datapath.stop()
        throw Self.providerError(
          code: 1039,
          message: "The kill-switch posture for this winn/3 standalone session does not observably block egress; refusing to install it.",
          statusFields: statusFields.merging(
            WinsKillSwitch.bootstrapStatusFields(
              config: config,
              verifiedBlocking: false,
              firstPostureBlocking: true
            )
          ) { _, new in new }
        )
      }
      firstPosture = fullTunnelSettings
      postureName = "full_tunnel (kill switch)"
    } else {
      let bootstrapSettings = WinsWinn3Settings.bootstrap(config: config, innerMTU: innerMTU)
      let verdict = WinsWinn3BootstrapPosture.evaluate(
        bootstrapSettings,
        requiredInnerMTU: innerMTU,
        carrierExclusionPresent: WinsWinn3Settings.carrierExclusionPresent(
          in: bootstrapSettings,
          config: config
        )
      )
      statusFields.merge(
        WinsWinn3SessionStatus.postureFields(
          posture: "bootstrap",
          innerMTU: innerMTU,
          verdict: verdict
        )
      ) { _, new in new }
      guard verdict.narrow else {
        // Never widened to an immediate full tunnel. A refusal costs the user a
        // retry while the system still reports Connecting; a promotion onto an
        // unproven datapath costs them their traffic.
        datapath.stop()
        throw Self.providerError(
          code: 1033,
          message: "The winn/3 bootstrap posture is not observably narrow, so it was not installed: \(verdict.reasons.joined(separator: "; ")).",
          statusFields: statusFields
        )
      }
      firstPosture = bootstrapSettings
      postureName = "bootstrap"
    }

    if killSwitchActive {
      statusFields.merge(
        WinsKillSwitch.bootstrapStatusFields(
          config: config,
          verifiedBlocking: WinsKillSwitch.egressBlocked(by: firstPosture, config: config),
          firstPostureBlocking: true
        )
      ) { _, new in new }
    }
    let committedStatusFields = statusFields
    os_log(
      "%{public}@ %{public}@ posture for a STANDALONE session (inner MTU %{public}d).",
      log: logger,
      type: .info,
      WinsWinn3.logToken,
      postureName,
      innerMTU
    )

    setTunnelNetworkSettings(firstPosture) { settingsError in
      var fields = committedStatusFields
      fields["network_settings_applied"] = settingsError == nil
      if let settingsError {
        datapath.stop()
        let completedCurrentOperation = self.lifecycleGate.performIfCurrent(lifecycleToken) {
          self.writeProviderStatus(
            stage: "network_settings_failed",
            config: config,
            engineReady: false,
            networkSettingsReady: false,
            error: settingsError,
            extra: fields,
            statusGeneration: statusGeneration
          )
        }
        completionHandler(
          completedCurrentOperation ? settingsError : Self.canceledStartError()
        )
        return
      }
      guard self.lifecycleGate.isCurrent(lifecycleToken) else {
        datapath.stop()
        completionHandler(Self.canceledStartError())
        return
      }
      // THE PUMP STARTS HERE. Not at create: a packet moved before this point
      // would have moved under a posture nothing had verified was narrow.
      datapath.resume(relay: self.packetFlow)
      self.runWinn3StandaloneConvergence(
        datapath: datapath,
        config: config,
        fullTunnelSettings: fullTunnelSettings,
        fullTunnelAlreadyCommitted: firstPosture === fullTunnelSettings,
        baseStatusFields: fields,
        promotionHeld: promotionHeld,
        lifecycleToken: lifecycleToken,
        statusGeneration: statusGeneration,
        completionHandler: completionHandler
      )
    }
  }

  /// The PROVE and PROMOTE stages for a standalone session.
  ///
  /// `winn3Datapath` stays nil until promotion. `provingWinn3Datapath` gives
  /// stopTunnel ownership while this loop is still proving the session.
  private func runWinn3StandaloneConvergence(
    datapath: WinsWinn3Datapath,
    config: WinsTunnelConfig,
    fullTunnelSettings: NEPacketTunnelNetworkSettings,
    fullTunnelAlreadyCommitted: Bool,
    baseStatusFields: [String: Any],
    promotionHeld: Bool,
    lifecycleToken: UInt64,
    statusGeneration: String,
    completionHandler: @escaping (Error?) -> Void
  ) {
    guard lifecycleGate.performIfCurrent(lifecycleToken, action: {
      provingWinn3Datapath = datapath
    }) else {
      datapath.stop()
      completionHandler(Self.canceledStartError())
      return
    }

    func stopProvingResource() {
      provingStopLock.lock()
      defer { provingStopLock.unlock() }
      datapath.stop()
      _ = lifecycleGate.performIfCurrent(lifecycleToken) {
        if provingWinn3Datapath === datapath {
          provingWinn3Datapath = nil
        }
      }
    }

    let startedAt = DispatchTime.now()
    let deadlineMilliseconds = Int(
      (Self.winnDatapathProofDeadlineSeconds * 1000).rounded()
    )
    // Bound to the INNER address, which for a standalone session is
    // `[winn] inner_v4` and not `[interface] Address`: the tun layer validates
    // the source of everything this host offers, so a probe from the AmneziaWG
    // address would be counted as invalid and dropped rather than carried.
    let probe = WinsWinnDatapathProofProbe(
      interfaceIPv4Address: config.winn3InnerV4,
      dnsServers: WinsWinn3Resolvers.inner(config)
    )
    if probe == nil {
      os_log(
        "%{public}@ convergence probe unavailable; relying on engine-observed deliveries only.",
        log: logger,
        type: .error,
        WinsWinn3.logToken
      )
    }

    func elapsedMilliseconds() -> Int {
      let elapsed = DispatchTime.now().uptimeNanoseconds &- startedAt.uptimeNanoseconds
      return Int(min(elapsed / 1_000_000, UInt64(Int.max)))
    }

    func progressFields(engineFields: [String: Any], promoted: Bool) -> [String: Any] {
      var fields = baseStatusFields
      fields.merge(
        WinsWinn3SessionStatus.progressFields(
          engineStatusFields: engineFields,
          pumpStatusFields: datapath.pumpStatusFields(),
          probeAvailable: probe != nil,
          probesSent: probe?.probesSent ?? 0,
          probeResponsesObserved: probe?.responsesObserved ?? 0,
          elapsedMilliseconds: elapsedMilliseconds(),
          deadlineMilliseconds: deadlineMilliseconds,
          promoted: promoted
        )
      ) { _, new in new }
      return fields
    }

    _ = lifecycleGate.performIfCurrent(lifecycleToken) {
      writeProviderStatus(
        stage: "engine_started",
        config: config,
        engineReady: true,
        networkSettingsReady: false,
        extra: progressFields(engineFields: datapath.statusFields(), promoted: false),
        statusGeneration: statusGeneration
      )
    }

    let queue = DispatchQueue(
      label: "org.winsvpn.app.PacketTunnel.winn3-standalone-proof",
      qos: .userInitiated
    )
    let timer = DispatchSource.makeTimerSource(queue: queue)
    var finished = false
    var tickCount = 0

    func finishCanceled() {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      completionHandler(Self.canceledStartError())
    }

    func finishFailure(code: Int, message: String, engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      let error = Self.providerError(code: code, message: message)
      os_log(
        "%{public}@ FAILED CLOSED before promotion: %{public}@ The host's routing, IPv6 and DNS were never claimed.",
        log: logger,
        type: .error,
        WinsWinn3.logToken,
        WinsTunnelDiagnostics.redactedProviderErrorMessage(error)
      )
      var fields = progressFields(engineFields: engineFields, promoted: false)
      fields.merge(Self.providerStatusFields(from: error)) { _, new in new }
      _ = lifecycleGate.performIfCurrent(lifecycleToken) {
        writeProviderStatus(
          stage: "engine_start_failed",
          config: config,
          engineReady: false,
          networkSettingsReady: false,
          error: error,
          extra: fields,
          statusGeneration: statusGeneration
        )
      }
      completionHandler(error)
    }

    /// PROVEN, then stop — the same deliberate non-promotion
    /// `winn_datapath_proof_hold` selects for the relay, and it matters more
    /// here: the promotion commit takes this machine's IPv4 default route and
    /// DNS in one call, and on a workstation that is the developer's own
    /// connectivity.
    func finishProvenWithPromotionHeld(engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      os_log(
        "%{public}@ PROVEN; promotion HELD on purpose. The host's routing, IPv6 and DNS were never claimed.",
        log: logger,
        type: .info,
        WinsWinn3.logToken
      )
      let error = Self.providerError(
        code: 1034,
        message: "The winn/3 standalone datapath was proven and promotion was held on purpose; full-tunnel settings were not installed.",
        statusFields: ["winn_datapath_proof_promotion_held": true]
      )
      var fields = progressFields(engineFields: engineFields, promoted: false)
      fields.merge(Self.providerStatusFields(from: error)) { _, new in new }
      _ = lifecycleGate.performIfCurrent(lifecycleToken) {
        writeProviderStatus(
          stage: "engine_start_failed",
          config: config,
          engineReady: false,
          networkSettingsReady: false,
          error: error,
          extra: fields,
          statusGeneration: statusGeneration
        )
      }
      completionHandler(error)
    }

    func beginPromotion(engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      os_log(
        "%{public}@ datapath proven (gate carrying, validated packet delivered); promoting to full-tunnel settings.",
        log: logger,
        type: .info,
        WinsWinn3.logToken
      )
      let promotionLock = NSLock()
      var promotionCompleted = false
      func completePromotionOnce(_ action: @escaping () -> Void) {
        promotionLock.lock()
        let alreadyCompleted = promotionCompleted
        promotionCompleted = true
        promotionLock.unlock()
        guard !alreadyCompleted else { return }
        action()
      }
      queue.asyncAfter(
        deadline: .now() + Self.winnDatapathPromotionSettingsDeadlineSeconds
      ) {
        completePromotionOnce {
          let error = Self.providerError(
            code: 1035,
            message: "Full-tunnel promotion settings did not commit before the deadline.",
            statusFields: ["winn_datapath_proof_promotion_deadline_expired": true]
          )
          stopProvingResource()
          var fields = progressFields(engineFields: engineFields, promoted: false)
          fields.merge(Self.providerStatusFields(from: error)) { _, new in new }
          _ = self.lifecycleGate.performIfCurrent(lifecycleToken) {
            self.writeProviderStatus(
              stage: "network_settings_failed",
              config: config,
              engineReady: false,
              networkSettingsReady: false,
              error: error,
              extra: fields,
              statusGeneration: statusGeneration
            )
          }
          completionHandler(error)
        }
      }
      let commitPromotion: (@escaping (Error?) -> Void) -> Void = { done in
        if fullTunnelAlreadyCommitted {
          done(nil)
        } else {
          self.setTunnelNetworkSettings(fullTunnelSettings, completionHandler: done)
        }
      }
      commitPromotion { settingsError in
        queue.async {
          completePromotionOnce {
            if let settingsError {
              stopProvingResource()
              var fields = progressFields(engineFields: engineFields, promoted: false)
              fields["network_settings_applied"] = false
              _ = self.lifecycleGate.performIfCurrent(lifecycleToken) {
                self.writeProviderStatus(
                  stage: "network_settings_failed",
                  config: config,
                  engineReady: false,
                  networkSettingsReady: false,
                  error: settingsError,
                  extra: fields,
                  statusGeneration: statusGeneration
                )
              }
              completionHandler(settingsError)
              return
            }
            var promotedFields = progressFields(
              engineFields: datapath.statusFields(),
              promoted: true
            )
            promotedFields.merge(
              WinsWinn3SessionStatus.postureFields(
                posture: "full_tunnel",
                innerMTU: fullTunnelSettings.mtu?.intValue ?? 0,
                verdict: nil
              )
            ) { _, new in new }
            let handedOver = self.lifecycleGate.performIfCurrent(lifecycleToken) {
              if self.provingWinn3Datapath === datapath {
                self.provingWinn3Datapath = nil
              }
              self.winn3Datapath = datapath
              self.activeEngineStatusFields = promotedFields
              self.writeProviderStatus(
                stage: "engine_started",
                config: config,
                engineReady: true,
                networkSettingsReady: true,
                extra: promotedFields,
                statusGeneration: statusGeneration
              )
            }
            guard handedOver else {
              stopProvingResource()
              completionHandler(Self.canceledStartError())
              return
            }
            os_log(
              "%{public}@ PROMOTED: full-tunnel settings committed after a standalone datapath proof.",
              log: self.logger,
              type: .info,
              WinsWinn3.logToken
            )
            completionHandler(nil)
          }
        }
      }
    }

    timer.setEventHandler {
      guard !finished else { return }
      guard self.lifecycleGate.isCurrent(lifecycleToken) else {
        finishCanceled()
        return
      }
      guard datapath.isRunning else {
        finishFailure(
          code: 1036,
          message: "The winn/3 standalone datapath closed while it was still being proven.",
          engineFields: [:]
        )
        return
      }
      tickCount += 1
      if let probe, tickCount % 2 == 1 {
        probe.sendNextProbe()
      }
      probe?.drainResponses()
      let engineFields = datapath.statusFields()
      // §4.1, and ONLY §4.1: `Gate.State() == StateCarrying` AND
      // `Stats().RxPackets > 0` — validated and DELIVERED, not merely arrived.
      // The probe response is required ON TOP of it whenever a probe socket
      // exists, because a packet the gateway sent unprompted is weaker evidence
      // than one that came back because this host asked for it. That can only
      // ever refuse a promotion, never cause one.
      let probeSatisfied = probe == nil || (probe?.responsesObserved ?? 0) > 0
      // The same static gate and probe rule, now in WinsTunnelCore so the
      // proof is recorded into this datapath's lifecycle history BEFORE the
      // settings commit and the datapath is published (Round A3).
      if datapath.promotionConverged(
        engineStatusFields: engineFields,
        probeSatisfied: probeSatisfied
      ) {
        if promotionHeld {
          finishProvenWithPromotionHeld(engineFields: engineFields)
        } else {
          beginPromotion(engineFields: engineFields)
        }
        return
      }
      if elapsedMilliseconds() >= deadlineMilliseconds {
        finishFailure(
          code: 1037,
          message: "The winn/3 standalone datapath was not proven within the fail-closed deadline; refusing to install full-tunnel settings.",
          engineFields: engineFields
        )
      }
    }
    timer.schedule(
      deadline: .now() + .milliseconds(Self.winnDatapathProofTickMilliseconds),
      repeating: .milliseconds(Self.winnDatapathProofTickMilliseconds)
    )
    timer.resume()
  }

  private func loadRuntimeConfig(options: [String: NSObject]?) throws -> ProviderRuntimeConfig {
    let statusGeneration = statusGeneration(options: options)
    let expectedClientPublicKeySelection = expectedClientPublicKey(options: options)
    let expectedClientPublicKey = expectedClientPublicKeySelection.publicKey
    let expectedClientPublicKeySource = expectedClientPublicKeySelection.source
    let accountScope = clientKeyAccountScope(options: options)
    let appGroupValidation = providerAppGroupValidation()
    if let rawConfig = options?["raw_config"] as? String,
       !rawConfig.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      var loadStatusFields = runtimeConfigStringStatusFields(
        source: "transient_start_options",
        byteCount: rawConfig.utf8.count
      )
      loadStatusFields.merge(appGroupValidation.statusFields) { _, new in new }
      guard appGroupValidation.containerURL != nil else {
        throw Self.appGroupValidationProviderError(
          source: "transient_start_options",
          validation: appGroupValidation,
          statusFields: loadStatusFields
        )
      }
      guard rawConfig.utf8.count <= WinsTunnelConfig.maxRuntimeConfigFileBytes else {
        var fields = loadStatusFields
        fields["config_too_large"] = true
        throw Self.providerError(
          code: 1005,
          message: "Packet Tunnel transient config is too large.",
          statusFields: fields
        )
      }
      return try usableRuntimeConfig(
        rawConfig,
        source: "transient_start_options",
        nonRedactedPrivateKeySource: "transient_start_options",
        expectedClientPublicKey: expectedClientPublicKey,
        expectedClientPublicKeySource: expectedClientPublicKeySource,
        accountScope: accountScope,
        statusGeneration: statusGeneration,
        loadStatusFields: loadStatusFields
      )
    }

    // Persisted `winn3_ini` in NETunnelProviderProtocol.providerConfiguration is
    // not a start source on macOS. That blob is written into NEVPN preferences,
    // survives process death, and can be replayed when startTunnel is invoked
    // with no transient options. Starting from it would (1) leak static_private
    // / admission_key into a durable system store and (2) replay a previously
    // delivered descriptor without going through the host's selected-node
    // binding. The App Group shared file is redacted; transient start options
    // are the only in-memory secret handoff. Presence of the key is ignored;
    // its bytes are never parsed.
    if let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
       providerProtocol.providerConfiguration?["winn3_ini"] != nil {
      os_log(
        "Ignoring persisted winn3_ini in providerConfiguration; macOS Packet Tunnel refuses that replay path.",
        log: logger,
        type: .info
      )
    }

    var lastConfigLoadError: Error?
    if let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
       let providerConfiguration = providerProtocol.providerConfiguration {
      if let sharedConfigPath = providerConfiguration["shared_config_path"] as? String,
         !sharedConfigPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        if let containerUrl = appGroupValidation.containerURL {
          let pathValidation = WinsSharedConfigPathGuard.validateSharedConfigPath(
            sharedConfigPath,
            containerURL: containerUrl,
            directoryName: Self.sharedConfigDirectoryName,
            fileName: Self.sharedConfigFileName
          )
          var extraFields = pathValidation.statusFields
          extraFields.merge(appGroupValidation.statusFields) { _, new in new }
          if let fileUrl = pathValidation.url {
            do {
              let loadResult = try runtimeConfigFileContents(
                at: fileUrl,
                source: "shared_config_path",
                extraFields: extraFields
              )
              return try usableRuntimeConfig(
                loadResult.rawConfig,
                source: "shared_config_path",
                nonRedactedPrivateKeySource: "embedded_config",
                expectedClientPublicKey: expectedClientPublicKey,
                expectedClientPublicKeySource: expectedClientPublicKeySource,
                accountScope: accountScope,
                statusGeneration: statusGeneration,
                loadStatusFields: loadResult.statusFields
              )
            } catch {
              lastConfigLoadError = error
            }
          } else {
            lastConfigLoadError = Self.providerError(
              code: 1010,
              message: "Packet Tunnel shared config path is outside the App Group handoff location.",
              statusFields: extraFields
            )
          }
        } else {
          var statusFields: [String: Any] = [
            "config_source": "shared_config_path",
            "config_source_available": true,
            "config_shared_path_present": true,
            "config_shared_path_allowed": false,
            "config_shared_path_matches_expected": false,
            "config_shared_path_inside_app_group": false
          ]
          statusFields.merge(appGroupValidation.statusFields) { _, new in new }
          lastConfigLoadError = Self.appGroupValidationProviderError(
            source: "shared_config_path",
            validation: appGroupValidation,
            statusFields: statusFields
          )
        }
      }

      if appGroupValidation.statusFields["config_app_group_id_present"] as? Bool == true {
        guard let containerUrl = appGroupValidation.containerURL else {
          var statusFields: [String: Any] = [
            "config_source": "app_group_fallback"
          ]
          statusFields.merge(appGroupValidation.statusFields) { _, new in new }
          lastConfigLoadError = Self.appGroupValidationProviderError(
            source: "app_group_fallback",
            validation: appGroupValidation,
            statusFields: statusFields
          )
          throw lastConfigLoadError!
        }
        let fileUrl = WinsSharedConfigPathGuard.expectedConfigURL(
          containerURL: containerUrl,
          directoryName: Self.sharedConfigDirectoryName,
          fileName: Self.sharedConfigFileName
        )
        do {
          let loadResult = try runtimeConfigFileContents(
            at: fileUrl,
            source: "app_group_fallback",
            extraFields: appGroupValidation.statusFields
          )
          return try usableRuntimeConfig(
            loadResult.rawConfig,
            source: "app_group_fallback",
            nonRedactedPrivateKeySource: "embedded_config",
            expectedClientPublicKey: expectedClientPublicKey,
            expectedClientPublicKeySource: expectedClientPublicKeySource,
            accountScope: accountScope,
            statusGeneration: statusGeneration,
            loadStatusFields: loadResult.statusFields
          )
        } catch {
          lastConfigLoadError = error
        }
      }
    }

    if let lastConfigLoadError {
      throw lastConfigLoadError
    }
    throw Self.providerError(
      code: 1001,
      message: "Missing Win's VPN tunnel config.",
      statusFields: [
        "config_source_available": false
      ]
    )
  }

  private func runtimeConfigFileContents(
    at fileUrl: URL,
    source: String,
    extraFields: [String: Any] = [:]
  ) throws -> (rawConfig: String, statusFields: [String: Any]) {
    let fileManager = FileManager.default
    var fields = runtimeConfigStringStatusFields(source: source, byteCount: nil)
    fields["config_file_present"] = fileManager.fileExists(atPath: fileUrl.path)
    for (key, value) in extraFields {
      fields[key] = value
    }
    let attributes = try? fileManager.attributesOfItem(atPath: fileUrl.path)
    if let fileSize = (attributes?[.size] as? NSNumber)?.uint64Value,
       fileSize <= UInt64(Int.max) {
      fields["config_size_bytes"] = Int(fileSize)
    }

    do {
      let readResult = try WinsBoundedUTF8FileReader.read(
        url: fileUrl,
        maxBytes: WinsTunnelConfig.maxRuntimeConfigFileBytes,
        fileManager: fileManager
      )
      fields["config_file_readable"] = true
      fields["config_utf8_valid"] = true
      fields["config_size_bytes"] = readResult.byteCount
      guard !readResult.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        fields["config_empty"] = true
        throw Self.providerError(
          code: 1008,
          message: "Packet Tunnel config file is empty.",
          statusFields: fields
        )
      }
      return (readResult.text, fields)
    } catch let error as NSError where error.domain == "org.winsvpn.PacketTunnel" {
      throw error
    } catch let error as WinsTunnelValidationError {
      switch error.code {
      case WinsBoundedUTF8FileReader.fileTooLargeCode:
        fields["config_file_too_large"] = true
        throw Self.providerError(
          code: 1005,
          message: "Packet Tunnel config file is too large.",
          statusFields: fields
        )
      case WinsBoundedUTF8FileReader.invalidUTF8Code:
        fields["config_file_readable"] = true
        fields["config_utf8_valid"] = false
        throw Self.providerError(
          code: 1007,
          message: "Packet Tunnel config file is not valid UTF-8.",
          statusFields: fields
        )
      case WinsBoundedUTF8FileReader.symbolicLinkCode:
        fields["config_file_symbolic_link"] = true
        fields["config_file_readable"] = false
        throw Self.providerError(
          code: 1012,
          message: "Packet Tunnel config file is not a regular handoff file.",
          statusFields: fields
        )
      default:
        fields["config_file_readable"] = false
        throw Self.providerError(
          code: 1006,
          message: "Packet Tunnel config file could not be read.",
          statusFields: fields
        )
      }
    } catch {
      fields["config_file_readable"] = false
      throw Self.providerError(
        code: 1006,
        message: "Packet Tunnel config file could not be read.",
        statusFields: fields
      )
    }
  }

  private func runtimeConfigStringStatusFields(source: String, byteCount: Int?) -> [String: Any] {
    var fields: [String: Any] = [
      "config_source": source,
      "config_source_available": true,
      "config_max_size_bytes": WinsTunnelConfig.maxRuntimeConfigFileBytes
    ]
    if let byteCount {
      fields["config_size_bytes"] = byteCount
    }
    return fields
  }

  private func providerAppGroupValidation() -> WinsAppleAppGroupValidation {
    return WinsAppleAppGroup.validate(
      rawIdentifier: savedProviderConfigurationString("app_group_id")
    )
  }

  /// Binds a standalone winn/3 start to the node the host selected.
  ///
  /// A signed descriptor is necessary but not sufficient. Every present
  /// selected-node identity on the INI `[winn]` section and on start options
  /// must be a strict ASCII slug and must equal the descriptor's `node`.
  /// Conflicting aliases are a mismatch, not a first-wins preference: a
  /// matching decoy `node_slug` must not hide a different `location_slug` or
  /// `selected_node`. Unicode case-folding (for example U+212A KELVIN SIGN
  /// onto `k`) is refused rather than treated as a match. Both identities are
  /// mandatory. A missing counterpart, a malformed slug, or a mismatch
  /// refuses before this credential-bearing INI can become an accepted
  /// session plan.
  private func bindWinn3DescriptorToSelectedNode(
    _ config: WinsTunnelConfig,
    options: [String: NSObject]?
  ) throws {
    guard config.winn3Enabled else {
      return
    }

    func winn3AsciiLowercase(_ value: String) -> String {
      var out: [UInt8] = []
      out.reserveCapacity(value.utf8.count)
      for unit in value.utf8 {
        if unit >= 0x41 && unit <= 0x5A {
          out.append(unit &+ 0x20)
        } else {
          out.append(unit)
        }
      }
      return String(bytes: out, encoding: .ascii) ?? ""
    }

    func winn3IsAllAscii(_ value: String) -> Bool {
      for unit in value.utf8 where unit > 0x7F {
        return false
      }
      return true
    }

    func winn3AsciiTrim(_ value: String) -> String {
      let units = Array(value.utf8)
      func isAsciiSpace(_ unit: UInt8) -> Bool {
        unit == 0x20 || unit == 0x09 || unit == 0x0A || unit == 0x0D
      }
      var start = 0
      var end = units.count
      while start < end && isAsciiSpace(units[start]) {
        start += 1
      }
      while end > start && isAsciiSpace(units[end - 1]) {
        end -= 1
      }
      return String(bytes: units[start..<end], encoding: .ascii) ?? ""
    }

    func winn3IsNodeIdentity(_ value: String) -> Bool {
      let units = Array(value.utf8)
      guard (2...40).contains(units.count) else {
        return false
      }
      let first = units[0]
      let firstIsAlphanumeric =
        (first >= 0x61 && first <= 0x7A) || (first >= 0x30 && first <= 0x39)
      guard firstIsAlphanumeric else {
        return false
      }
      for unit in units {
        let allowed =
          (unit >= 0x61 && unit <= 0x7A) ||
          (unit >= 0x30 && unit <= 0x39) ||
          unit == 0x2D
        if !allowed {
          return false
        }
      }
      return true
    }

    func winn3NormalizedNodeIdentity(_ raw: String?) -> String? {
      guard let raw else {
        return nil
      }
      // Scan the untrimmed value. Foundation trim/lowercased() fold NBSP and
      // U+212A onto ASCII slugs; those must not bind.
      guard winn3IsAllAscii(raw) else {
        return nil
      }
      let trimmed = winn3AsciiTrim(raw)
      if trimmed.isEmpty {
        return nil
      }
      let lowered = winn3AsciiLowercase(trimmed)
      guard lowered != "auto", winn3IsNodeIdentity(lowered) else {
        return nil
      }
      return lowered
    }

    enum Winn3NodeIdentityRead {
      case absent
      case invalid
      case ok(String)
    }

    func winn3StringKeyedMap(_ raw: Any) -> [String: Any]? {
      if let typed = raw as? [String: Any] {
        return typed
      }
      guard let dict = raw as? NSDictionary else {
        return nil
      }
      var out: [String: Any] = [:]
      out.reserveCapacity(dict.count)
      for (key, value) in dict {
        guard let stringKey = key as? String else {
          return nil
        }
        out[stringKey] = value
      }
      return out
    }

    func winn3ReadNodeIdentityValue(_ raw: Any?) -> Winn3NodeIdentityRead {
      guard let raw else {
        return .absent
      }
      if raw is NSNull {
        return .absent
      }
      if let string = raw as? String {
        if winn3AsciiTrim(string).isEmpty {
          return winn3IsAllAscii(string) ? .absent : .invalid
        }
        guard let normalized = winn3NormalizedNodeIdentity(string) else {
          return .invalid
        }
        return .ok(normalized)
      }
      if let map = winn3StringKeyedMap(raw) {
        let nestedKeys = [
          "slug",
          "node_slug",
          "nodeslug",
          "location_slug",
          "locationslug"
        ]
        var bound: String?
        var sawSlug = false
        for key in nestedKeys {
          guard let nested = map[key] else {
            continue
          }
          if nested is NSNull {
            continue
          }
          sawSlug = true
          guard let nestedString = nested as? String else {
            return .invalid
          }
          if winn3AsciiTrim(nestedString).isEmpty {
            return .invalid
          }
          guard let normalized = winn3NormalizedNodeIdentity(nestedString) else {
            return .invalid
          }
          if bound == nil {
            bound = normalized
          } else if bound != normalized {
            return .invalid
          }
        }
        guard sawSlug, let bound else {
          return .invalid
        }
        return .ok(bound)
      }
      return .invalid
    }

    func winn3SelectedNodeIdentity(
      winn: [String: String],
      options: [String: NSObject]?
    ) -> String {
      let identityKeys = [
        "node_slug",
        "nodeslug",
        "location_slug",
        "locationslug",
        "selected_node",
        "selectednode"
      ]
      var bound: String?
      var sawTransientIdentity = false
      for key in identityKeys {
        switch winn3ReadNodeIdentityValue(options?[key]) {
        case .absent:
          continue
        case .invalid:
          return ""
        case .ok(let value):
          sawTransientIdentity = true
          if bound == nil {
            bound = value
          } else if bound != value {
            return ""
          }
        }
      }
      guard sawTransientIdentity, let bound else {
        return ""
      }
      for key in identityKeys {
        switch winn3ReadNodeIdentityValue(winn[key]) {
        case .absent:
          continue
        case .invalid:
          return ""
        case .ok(let value):
          if value != bound {
            return ""
          }
        }
      }
      return bound
    }

    let winn = config.sections["winn"] ?? [:]
    let descriptorNode = winn3NormalizedNodeIdentity(winn["node"]) ?? ""
    let selectedNode = winn3SelectedNodeIdentity(winn: winn, options: options)
    guard !descriptorNode.isEmpty,
          !selectedNode.isEmpty,
          descriptorNode == selectedNode else {
      throw Self.providerError(
        code: 1040,
        message: "The signed winn/3 gateway record is for a different node than the one selected for this connection.",
        statusFields: [
          "winn3_descriptor_node_bound": false,
          "winn3_descriptor_node_present": !descriptorNode.isEmpty,
          "winn3_selected_node_present": !selectedNode.isEmpty
        ]
      )
    }
  }

  /// True when `rawConfig` still embeds live key material rather than the
  /// Keychain placeholders `redactedForStorage` writes. Persisted sources
  /// (App Group file, leftover providerConfiguration) must not carry these.
  private static func runtimeConfigContainsLiveSecretMaterial(_ rawConfig: String) -> Bool {
    let parsed = WinsTunnelConfig.parse(rawConfig)
    func isLive(_ value: String, placeholder: String) -> Bool {
      let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
      return !trimmed.isEmpty && trimmed != placeholder
    }
    return isLive(parsed.interfacePrivateKey, placeholder: WinsTunnelConfig.redactedPrivateKeyPlaceholder)
      || isLive(parsed.peerPresharedKey, placeholder: WinsTunnelConfig.redactedPresharedKeyPlaceholder)
      || isLive(
        parsed.sections["xray"]?["uuid"] ?? "",
        placeholder: WinsTunnelConfig.redactedXrayUUIDPlaceholder
      )
      || isLive(parsed.winn3StaticPrivate, placeholder: WinsTunnelConfig.redactedWinnStaticPrivatePlaceholder)
      || isLive(parsed.winn3AdmissionKey, placeholder: WinsTunnelConfig.redactedWinnAdmissionKeyPlaceholder)
      || isLive(parsed.winn3PSK, placeholder: WinsTunnelConfig.redactedWinnPSKPlaceholder)
  }

  private func usableRuntimeConfig(
    _ rawConfig: String,
    source: String,
    nonRedactedPrivateKeySource: String,
    expectedClientPublicKey: String,
    expectedClientPublicKeySource: String,
    accountScope: String,
    statusGeneration: String,
    loadStatusFields: [String: Any] = [:]
  ) throws -> ProviderRuntimeConfig {
    if source != "transient_start_options",
       Self.runtimeConfigContainsLiveSecretMaterial(rawConfig) {
      var fields = loadStatusFields
      fields["config_source"] = source
      fields["persisted_live_secret_material_refused"] = true
      throw Self.providerError(
        code: 1042,
        message: "Packet Tunnel persisted config still carries live secret material and was refused.",
        statusFields: fields
      )
    }
    let needsPrivateKeyRestore = WinsTunnelConfig.containsRedactedPrivateKey(rawConfig)
    let needsPresharedKeyRestore = WinsTunnelConfig.containsRedactedPresharedKey(rawConfig)
    let needsXrayUUIDRestore = WinsTunnelConfig.containsRedactedXrayUUID(rawConfig)
    let needsWinnStaticPrivateRestore = WinsTunnelConfig.containsRedactedWinnStaticPrivate(rawConfig)
    let needsWinnAdmissionKeyRestore = WinsTunnelConfig.containsRedactedWinnAdmissionKey(rawConfig)
    let needsWinnPSKRestore = WinsTunnelConfig.containsRedactedWinnPSK(rawConfig)
    guard needsPrivateKeyRestore || needsPresharedKeyRestore || needsXrayUUIDRestore ||
            needsWinnStaticPrivateRestore || needsWinnAdmissionKeyRestore || needsWinnPSKRestore else {
      return ProviderRuntimeConfig(
        rawConfig: rawConfig,
        configSource: source,
        privateKeySource: nonRedactedPrivateKeySource,
        sharedConfigPrivateKeyRedacted: false,
        sharedConfigPresharedKeyRedacted: false,
        sharedConfigXrayUUIDRedacted: false,
        expectedClientPublicKey: expectedClientPublicKey,
        expectedClientPublicKeySource: expectedClientPublicKeySource,
        statusGeneration: statusGeneration,
        configLoadStatusFields: loadStatusFields
      )
    }

    var privateKey = ""
    if needsPrivateKeyRestore {
      guard let keyPair = try WinsClientKeyStore.loadExisting(accountScope: accountScope) else {
        var fields = loadStatusFields
        fields["config_source"] = source
        fields["private_key_source"] = "shared_keychain"
        fields["shared_config_private_key_redacted"] = true
        fields["shared_keychain_private_key_available"] = false
        fields["client_key_pair_verification_required"] = !expectedClientPublicKey.isEmpty
        fields["expected_client_public_key_available"] = !expectedClientPublicKey.isEmpty
        fields["expected_client_public_key_source"] = expectedClientPublicKeySource
        fields["expected_client_public_key_valid"] =
          !expectedClientPublicKey.isEmpty &&
          WinsTunnelConfig.validWireGuardPublicKey(expectedClientPublicKey)
        fields["client_key_pair_verified"] = false
        throw Self.providerError(
          code: 1004,
          message: "Win's VPN tunnel config from \(source) redacts the private key, and the shared Keychain client key is unavailable.",
          statusFields: fields
        )
      }
      privateKey = keyPair.privateKey
    }

    var presharedKey: String?
    var xrayUUID: String?
    var winnStaticPrivate: String?
    var winnAdmissionKey: String?
    var winnPSK: String?
    if needsPresharedKeyRestore || needsXrayUUIDRestore ||
         needsWinnStaticPrivateRestore || needsWinnAdmissionKeyRestore || needsWinnPSKRestore {
      guard let secrets = try WinsTunnelSecretStore.loadExisting(accountScope: accountScope) else {
        var fields = loadStatusFields
        fields["config_source"] = source
        fields["shared_config_preshared_key_redacted"] = needsPresharedKeyRestore
        fields["shared_config_xray_uuid_redacted"] = needsXrayUUIDRestore
        fields["shared_keychain_tunnel_secrets_available"] = false
        throw Self.providerError(
          code: 1014,
          message: "Win's VPN tunnel config from \(source) redacts the preshared key or Xray UUID, and the shared Keychain tunnel secrets are unavailable.",
          statusFields: fields
        )
      }
      presharedKey = needsPresharedKeyRestore ? secrets.presharedKey : nil
      xrayUUID = needsXrayUUIDRestore ? secrets.xrayUUID : nil
      winnStaticPrivate = needsWinnStaticPrivateRestore ? secrets.winnStaticPrivate : nil
      winnAdmissionKey = needsWinnAdmissionKeyRestore ? secrets.winnAdmissionKey : nil
      winnPSK = needsWinnPSKRestore ? secrets.winnPSK : nil
      if (needsWinnStaticPrivateRestore && winnStaticPrivate?.isEmpty != false) ||
           (needsWinnAdmissionKeyRestore && winnAdmissionKey?.isEmpty != false) ||
           (needsWinnPSKRestore && winnPSK?.isEmpty != false) {
        throw Self.providerError(
          code: 1015,
          message: "Win's VPN persisted Winn Protocol v3 secrets are unavailable.",
          statusFields: loadStatusFields
        )
      }
    }

    return ProviderRuntimeConfig(
      rawConfig: WinsTunnelConfig.restoredRuntimeConfig(
        rawConfig,
        privateKey: privateKey,
        presharedKey: presharedKey,
        xrayUUID: xrayUUID,
        winnStaticPrivate: winnStaticPrivate,
        winnAdmissionKey: winnAdmissionKey,
        winnPSK: winnPSK
      ),
      configSource: source,
      privateKeySource: needsPrivateKeyRestore ? "shared_keychain" : nonRedactedPrivateKeySource,
      sharedConfigPrivateKeyRedacted: needsPrivateKeyRestore,
      sharedConfigPresharedKeyRedacted: needsPresharedKeyRestore,
      sharedConfigXrayUUIDRedacted: needsXrayUUIDRestore,
      expectedClientPublicKey: expectedClientPublicKey,
      expectedClientPublicKeySource: expectedClientPublicKeySource,
      statusGeneration: statusGeneration,
      configLoadStatusFields: loadStatusFields
    )
  }

  private func expectedClientPublicKey(options: [String: NSObject]?) -> (
    publicKey: String,
    source: String
  ) {
    WinsPacketTunnelProviderStatus.preferredClientPublicKeySelection(
      saved: savedProviderConfigurationString("client_public_key"),
      transient: options?["client_public_key"] as? String
    )
  }

  private func clientKeyAccountScope(options: [String: NSObject]?) -> String {
    WinsPacketTunnelProviderStatus.preferredClientKeyAccountScope(
      saved: savedProviderConfigurationString("client_key_account_scope"),
      transient: options?["client_key_account_scope"] as? String
    )
  }

  private func statusGenerationFields(options: [String: NSObject]?) -> [String: Any] {
    let generation = statusGeneration(options: options)
    return generation.isEmpty ? [:] : ["status_generation": generation]
  }

  private func statusGeneration(options: [String: NSObject]?) -> String {
    WinsPacketTunnelProviderStatus.preferredStatusGeneration(
      saved: savedProviderConfigurationString("status_generation"),
      transient: options?["status_generation"] as? String
    )
  }

  private func savedProviderConfigurationString(_ key: String) -> String? {
    guard let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
      return nil
    }
    return providerProtocol.providerConfiguration?[key] as? String
  }

  private func currentStatusGeneration() -> String {
    let generation = WinsPacketTunnelProviderStatus.safeStatusGeneration(activeStatusGeneration)
    if !generation.isEmpty {
      return generation
    }
    return statusGeneration(options: nil)
  }

  private func writeProviderStatus(
    stage: String,
    config: WinsTunnelConfig? = nil,
    engineReady: Bool = false,
    networkSettingsReady: Bool = false,
    error: Error? = nil,
    extra: [String: Any] = [:],
    statusGeneration: String? = nil
  ) {
    guard let statusUrl = providerStatusURL() else {
      return
    }

    do {
      let intendedStatusGeneration = WinsPacketTunnelProviderStatus.safeStatusGeneration(
        statusGeneration ?? currentStatusGeneration()
      )
      if shouldSkipStaleStopStatusWrite(
        stage: stage,
        statusUrl: statusUrl,
        intendedStatusGeneration: intendedStatusGeneration
      ) {
        return
      }
      let annotatedExtra = WinsWinn3NativeStartClassifier.annotatedExtra(
        expectedGeneration: intendedStatusGeneration,
        stage: stage,
        engineReady: engineReady,
        networkSettingsReady: networkSettingsReady,
        error: error,
        extra: extra
      )
      let data = try WinsPacketTunnelProviderStatus.writableData(
        stage: stage,
        providerBundleIdentifier: Bundle.main.bundleIdentifier ?? "",
        config: config,
        engineReady: engineReady,
        networkSettingsReady: networkSettingsReady,
        error: error,
        extra: annotatedExtra,
        fallbackStatusGeneration: intendedStatusGeneration
      )
      try WinsAppGroupFileWriter.writeData(data, to: statusUrl)
    } catch {
      os_log(
        "Packet tunnel status write failed: %{public}@",
        log: logger,
        type: .error,
        WinsTunnelDiagnostics.redactedProviderErrorMessage(error)
      )
    }
  }

  private func shouldSkipStaleStopStatusWrite(
    stage: String,
    statusUrl: URL,
    intendedStatusGeneration: String
  ) -> Bool {
    guard stage == "stopped" else {
      return false
    }
    guard !intendedStatusGeneration.isEmpty,
          let data = try? Data(contentsOf: statusUrl),
          let status = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return false
    }
    let rawFileGeneration = (status["status_generation"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let fileGeneration = WinsPacketTunnelProviderStatus.safeStatusGeneration(rawFileGeneration)
    return !fileGeneration.isEmpty && fileGeneration != intendedStatusGeneration
  }

  private func previousProviderStatusFieldsBeforeStop() -> [String: Any] {
    guard let statusUrl = providerStatusURL(),
          let data = try? Data(contentsOf: statusUrl),
          let status = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return [:]
    }

    var fields: [String: Any] = [:]
    func copy(_ source: String, as target: String) {
      guard let value = status[source],
            let safeValue = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
              value,
              sourceKey: source
            ) else {
        return
      }
      fields[target] = safeValue
    }

    if let previousStage = status["stage"] as? String,
       WinsPacketTunnelProviderStatus.validStage(previousStage) {
      fields["previous_stage_before_stop"] = previousStage
    }
    copy("healthy", as: "previous_healthy_before_stop")
    copy("engine_ready", as: "previous_engine_ready_before_stop")
    copy("network_settings_ready", as: "previous_network_settings_ready_before_stop")
    copy("network_settings_applied", as: "previous_network_settings_applied_before_stop")
    copy("peer_endpoint_kind", as: "previous_peer_endpoint_kind_before_stop")
    copy("transport_endpoint_kind", as: "previous_transport_endpoint_kind_before_stop")
    copy(
      "network_settings_remote_address_kind",
      as: "previous_network_settings_remote_address_kind_before_stop"
    )
    copy(
      "network_settings_remote_address_source",
      as: "previous_network_settings_remote_address_source_before_stop"
    )
    copy("transport_mode", as: "previous_transport_mode_before_stop")
    copy("xray_enabled", as: "previous_xray_enabled_before_stop")
    copy("engine_transport_mode", as: "previous_engine_transport_mode_before_stop")
    copy("engine_bundle_probe", as: "previous_engine_bundle_probe_before_stop")
    copy(
      "engine_bundle_all_required_components_present",
      as: "previous_engine_bundle_all_required_components_present_before_stop"
    )
    copy(
      "engine_runtime_engine_ready_reported",
      as: "previous_engine_runtime_engine_ready_reported_before_stop"
    )
    copy(
      "engine_runtime_engine_running_reported",
      as: "previous_engine_runtime_engine_running_reported_before_stop"
    )
    copy("app_message_command", as: "previous_app_message_command_before_stop")
    copy(
      "app_message_command_is_health",
      as: "previous_app_message_command_is_health_before_stop"
    )
    copy("app_message_accepted", as: "previous_app_message_accepted_before_stop")
    copy(
      "app_message_raw_payload_redacted",
      as: "previous_app_message_raw_payload_redacted_before_stop"
    )
    copy("app_message_engine_running", as: "previous_app_message_engine_running_before_stop")
    return fields
  }

  private static func engineFailureStage(for error: Error) -> String {
    let nsError = error as NSError
    if nsError.domain == WinsPacketTunnelEngineError.errorDomain,
       nsError.code == WinsPacketTunnelEngineError.missingNativeEngineCode {
      return "engine_missing"
    }
    return "engine_start_failed"
  }

  private static func canceledStartError() -> NSError {
    providerError(
      code: 1013,
      message: "Packet Tunnel start was canceled.",
      statusFields: ["start_canceled": true]
    )
  }

  private func providerStatusURL() -> URL? {
    guard let containerUrl = providerAppGroupValidation().containerURL else {
      return nil
    }

    return containerUrl
      .appendingPathComponent(Self.sharedConfigDirectoryName, isDirectory: true)
      .appendingPathComponent(Self.sharedStatusFileName, isDirectory: false)
  }

  private static func providerStatusFields(from error: Error) -> [String: Any] {
    let nsError = error as NSError
    var fields = nsError.userInfo[providerStatusFieldsUserInfoKey] as? [String: Any] ?? [:]
    if let engineFields = nsError.userInfo[
      WinsPacketTunnelEngineError.statusFieldsUserInfoKey
    ] as? [String: Any] {
      fields.merge(engineFields) { _, new in new }
    }
    return fields
  }

  private static func appGroupValidationProviderError(
    source: String,
    validation: WinsAppleAppGroupValidation,
    statusFields: [String: Any] = [:]
  ) -> NSError {
    let appGroupAllowed = validation.statusFields["config_app_group_id_allowed"] as? Bool == true
    var fields = statusFields
    fields["config_source"] = source
    fields.merge(validation.statusFields) { _, new in new }
    return providerError(
      code: appGroupAllowed ? 1009 : 1011,
      message: appGroupAllowed
        ? "Packet Tunnel App Group container is unavailable."
        : "Packet Tunnel App Group identifier is not allowed.",
      statusFields: fields
    )
  }

  fileprivate static func providerError(
    code: Int,
    message: String,
    statusFields: [String: Any] = [:]
  ) -> NSError {
    var userInfo: [String: Any] = [NSLocalizedDescriptionKey: message]
    if !statusFields.isEmpty {
      userInfo[providerStatusFieldsUserInfoKey] = statusFields
    }
    return NSError(
      domain: "org.winsvpn.PacketTunnel",
      code: code,
      userInfo: userInfo
    )
  }

}

private struct ProviderRuntimeConfig {
  let rawConfig: String
  let configSource: String
  let privateKeySource: String
  let sharedConfigPrivateKeyRedacted: Bool
  let sharedConfigPresharedKeyRedacted: Bool
  let sharedConfigXrayUUIDRedacted: Bool
  let expectedClientPublicKey: String
  let expectedClientPublicKeySource: String
  let statusGeneration: String
  let configLoadStatusFields: [String: Any]

  var clientKeyPairVerificationRequired: Bool {
    !expectedClientPublicKey.isEmpty
  }

  var expectedClientPublicKeyValid: Bool {
    clientKeyPairVerificationRequired &&
      WinsTunnelConfig.validWireGuardPublicKey(expectedClientPublicKey)
  }

  func verifiedStatusFields(for config: WinsTunnelConfig) throws -> [String: Any] {
    var fields = statusFields(clientKeyPairVerified: false)
    if clientKeyPairVerificationRequired {
      try config.validateInterfacePrivateKeyMatchesPublicKey(expectedClientPublicKey)
      fields["client_key_pair_verified"] = true
    }
    return fields
  }

  func statusFields(clientKeyPairVerified: Bool) -> [String: Any] {
    var fields = configLoadStatusFields
    fields["config_source"] = configSource
    fields.merge([
      "config_source": configSource,
      "private_key_source": privateKeySource,
      "shared_config_private_key_redacted": sharedConfigPrivateKeyRedacted,
      "shared_config_preshared_key_redacted": sharedConfigPresharedKeyRedacted,
      "shared_config_xray_uuid_redacted": sharedConfigXrayUUIDRedacted,
      "client_key_pair_verification_required": clientKeyPairVerificationRequired,
      "expected_client_public_key_available": clientKeyPairVerificationRequired,
      "expected_client_public_key_source": expectedClientPublicKeySource,
      "expected_client_public_key_valid": expectedClientPublicKeyValid,
      "client_key_pair_verified": clientKeyPairVerified
    ]) { _, new in new }
    if !statusGeneration.isEmpty {
      fields["status_generation"] = statusGeneration
    }
    return fields
  }
}
