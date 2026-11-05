import Foundation
import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
  private static let sharedConfigDirectoryName = "Tunnel"
  private static let sharedConfigFileName = "latest_tunnel.conf"
  private static let sharedStatusFileName = "latest_status.json"
  private static let providerStatusFieldsUserInfoKey = "wins_provider_status_fields"
  /// How long `releaseTunnelNetworkSettings` waits for the settings-release
  /// callback before completing the stop anyway. Short on purpose: the release
  /// is a best effort that must never be able to wedge a teardown.
  private static let networkSettingsReleaseDeadlineSeconds = 2.0
  /// How long a winn/3 start may spend in the BOOTSTRAP posture proving its
  /// datapath before the start FAILS CLOSED with the phone untouched. Parity
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
  /// start is failed rather than left in limbo. Same belt-and-braces shape as
  /// `networkSettingsReleaseDeadlineSeconds`: the callback is expected, but a
  /// start must never be able to hang on it.
  private static let winnDatapathPromotionSettingsDeadlineSeconds = 10.0

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
  private let winnMemoryWatchdogQueue = DispatchQueue(
    label: "org.winsvpn.app.PacketTunnel.winn-memory-watchdog",
    qos: .utility
  )
  // Owned by lifecycleGate, including timer identity checks and cancellation.
  private var winnMemoryWatchdog: WinnMemoryWatchdog?

  private final class WinnMemoryWatchdog {
    let timer: DispatchSourceTimer
    /// Set once the session is promoted and the cadence has been relaxed.
    var relaxed = false

    init(timer: DispatchSourceTimer) {
      self.timer = timer
    }

    deinit {
      timer.cancel()
    }
  }

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
      stopWinnMemoryWatchdog()
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
      // Placed here on purpose: being jetsammed AFTER installing full-tunnel
      // settings is the blackout, so a session that cannot fit must be refused
      // while the phone's routing, IPv6 and DNS are still untouched.
      //
      // Non-winn starts are not gated. `winnAppexMemoryGate` returns nil for
      // them, this block is skipped entirely, and no field it owns is written:
      // so a production start is unchanged, including the size and shape of its
      // status document.
      if let memoryGate = winnAppexMemoryGate(for: parsedConfig) {
        verifiedStatusFields.merge(memoryGate.statusFields) { _, new in new }
        if let refusalReason = memoryGate.refusalReason {
          os_log(
            "Refusing winn/3 start: %{public}@ (available=%{public}d required=%{public}d carrier=%{public}@). The project requires measured physical footprint to stay strictly below 15 MiB.",
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
      let networkSettingsResult = try makeNetworkSettings(from: parsedConfig)
      // THE winn/3 STANDALONE FORK, taken before any AmneziaWG object exists.
      //
      // Placed above the staged relay start and above the engine factory
      // because everything below it is the RELAY: settings built around
      // `[interface] Address` with an MTU from `[interface] MTU`, and an engine
      // whose tun owner is AmneziaWG. A standalone session shares none of that,
      // and falling through even one step would build a posture whose address
      // the winn/3 tun layer rejects as a source-address violation — the
      // session would then fail closed for a reason that looks like the
      // gateway.
      //
      // It is placed BELOW the memory gate on purpose. That gate is the one
      // thing that must run before any settings exist at all: being jetsammed
      // after installing settings is the blackout, and it is the phone this is
      // worst on.
      //
      // CONTAINMENT MAPS TO PROMOTION-HELD. A contained dev session is one that
      // must never take the phone; a standalone start whose promotion is held
      // proves the datapath and then stops without claiming anything. Those are
      // the same guarantee, so containment selects the held path rather than a
      // second contained posture that would have to be kept narrow separately.
      //
      // No branch below ever falls back to `direct-awg`: a standalone session
      // silently downgraded to a relay violates the standalone carrier
      // contract enforced by the shipping Dart dispatcher and native parser.
      if parsedConfig.winn3Enabled {
        verifiedStatusFields.merge(networkSettingsResult.statusFields) { _, new in new }
        try startWinn3StandaloneSession(
          config: parsedConfig,
          baseStatusFields: verifiedStatusFields,
          promotionHeld:
            networkSettingsResult.statusFields["dev_containment_active"] as? Bool == true,
          lifecycleToken: lifecycleToken,
          statusGeneration: runtimeConfig.statusGeneration,
          completionHandler: completionHandler
        )
        return
      }
      // THE STAGED winn/3 START. For a winn full-tunnel session the settings
      // installed FIRST are a narrow bootstrap (no default route, no IPv6, no
      // DNS); the full-tunnel settings built above are installed only after the
      // datapath has been proven to carry traffic. Nil for every non-winn
      // start, every split-tunnel start, and every contained dev start — all
      // of those keep today's single-install behaviour byte for byte. Runs
      // AFTER the memory gate above, which keeps its own placement: a session
      // that cannot fit is still refused before ANY settings exist, and a
      // jetsam during the proof phase now kills an appex holding only the
      // bootstrap posture rather than the phone's routing, IPv6 and DNS.
      let stagedWinnStart = try makeWinnStagedStartPlan(
        from: parsedConfig,
        fullTunnelResult: networkSettingsResult
      )
      let networkSettings = stagedWinnStart?.bootstrapSettings
        ?? networkSettingsResult.settings
      // Merged BEFORE the settings callback so that every status document this
      // start can produce — success, rejection, or engine failure — already
      // says whether the session was contained. A contained run must never be
      // readable as a validated full-tunnel one.
      verifiedStatusFields.merge(networkSettingsResult.statusFields) { _, new in new }
      if let stagedWinnStart {
        // Same reasoning as containment above: every document this start can
        // produce must already say the session began in the bootstrap posture,
        // so a failure before promotion can never be read as a full-tunnel one.
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
            // session first claims the phone's routing, IPv6 and DNS — only
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
            self.startWinnMemoryWatchdog(lifecycleToken: lifecycleToken)
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

  override func cancelTunnelWithError(_ error: Error?) {
    // Cancel pending starts too, so no later handoff can re-arm the watchdog.
    lifecycleGate.invalidate {
      cancelTunnelUnderLifecycleGate(error)
    }
  }

  /// The caller holds lifecycleGate through the actual cancellation request.
  private func cancelTunnelUnderLifecycleGate(_ error: Error?) {
    stopWinnMemoryWatchdog()
    super.cancelTunnelWithError(error)
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
      stopWinnMemoryWatchdog()
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
    // the last chance to record what the session actually lost — the totals a
    // burst-loss report is written from. Same for the standalone session: once
    // the handle is closed its status document is empty, so the delivered and
    // dropped counts have to be taken now or not at all.
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
    // KILL SWITCH, TEARDOWN OBSERVABILITY. The datapath stops FIRST (immediately
    // below) and the settings release — even the awaited one in
    // `releaseTunnelNetworkSettings` — happens only after the datapath is
    // stopped, so a full-tunnel session never tears down into cleartext: the
    // system reclaims the settings at session end, and until then the blocking
    // posture is held.
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
    // ORDER MATTERS, AND IT IS NOT THE macOS ORDER.
    //
    // macOS writes the "stopped" document first and then fires the release
    // alongside the completion handler. That has two defects, both observed:
    // the completion can be signalled while the release is still in flight (so
    // the system may tear the extension down mid-call), and the release's
    // outcome cannot appear in the document that was already written — the
    // macOS log even tells a reader to consult `provider_error_domain` and
    // `provider_error_code`, which that path never writes.
    //
    // Here the release is AWAITED, its real outcome is folded into the status
    // fields, the document is written with that outcome in it, and only then is
    // the stop completed. The first real iOS session therefore answers "does
    // setTunnelNetworkSettings(nil) actually release anything?" from the
    // recorded evidence rather than from a reassuring log line.
    releaseTunnelNetworkSettings(context: "stop_tunnel") { releaseFields in
      stopFields.merge(releaseFields) { _, new in new }
      self.writeProviderStatus(
        stage: "stopped",
        config: configAtStop,
        engineReady: false,
        networkSettingsReady: false,
        extra: stopFields,
        statusGeneration: statusGenerationAtStop
      )
      completionHandler()
    }
  }

  /// Asks the system to hand the phone's routing, IPv6 and DNS back, WAITS for
  /// the answer, and reports what actually happened.
  ///
  /// Calls `completion` exactly once, with status fields describing the
  /// outcome, and never before the release has either completed or timed out.
  ///
  /// # Why this exists
  ///
  /// `setTunnelNetworkSettings` was called in exactly one place — at start —
  /// and never with `nil`. Teardown relied entirely on the system reclaiming
  /// the settings when the extension process goes away. That is the usual
  /// behaviour, but it was not something this provider ever asked for, and on
  /// 2026-08-05 the macOS sibling showed what it costs: a session holding the
  /// default route, IPv6 and all DNS survived the host app being killed and
  /// needed a reboot. A phone is the worse place for that — it is the device a
  /// user in a hostile network depends on and the one they can least afford to
  /// reboot blind.
  ///
  /// # THIS IS NOT KNOWN TO WORK, AND THAT IS WHY IT REPORTS
  ///
  /// The macOS provider issues the same call from the same place, and a real
  /// contained session showed it FAILING, ~10 ms after the stop:
  /// "Packet tunnel network settings release reported an error: Apple system
  /// error occurred." Host routing and DNS did recover there — but only because
  /// the extension process exited, which is exactly what happened before the
  /// call existed. So on macOS this call has never been shown to release
  /// anything, and the leading hypothesis is that NetworkExtension will not
  /// accept a settings change on a session that is already tearing down.
  ///
  /// That hypothesis, if correct, applies to iOS too. This code therefore does
  /// NOT claim to fix teardown on iOS. It does three things that the macOS
  /// version does not, so that the first real session settles the question
  /// instead of leaving a reassuring log line behind:
  ///
  ///  1. It AWAITS the release. The stop completion is signalled from inside
  ///     the release callback, not raced against it, so the system cannot be
  ///     tearing the extension down mid-call because this provider said it was
  ///     finished.
  ///  2. It records the REAL `NSError` domain and code in the status document
  ///     (`network_settings_release_error_domain` / `..._code`), so "Apple
  ///     system error occurred" becomes an identifiable error rather than a
  ///     phrase. Those keys are in `WinsPacketTunnelProviderStatus`'s
  ///     compact-write allowlist, so they survive an oversized document.
  ///  3. It records WHICH path completed the stop
  ///     (`network_settings_release_outcome`: `released`, `failed`, or
  ///     `deadline`), so a deadline expiry is never mistaken for a success.
  ///
  /// If a real session reports `failed` here with the same system error macOS
  /// saw, then this call cannot work where it is placed, and the honest
  /// mitigation is the Debug-only self-cancel below plus external recovery —
  /// not a louder version of this.
  ///
  /// # Why it still cannot hang a stop
  ///
  /// The callback is not guaranteed to fire while an extension is being torn
  /// down. So a deadline still exists as an anti-wedge — but it is now the
  /// LOSING path rather than an equal one, and when it wins it says so.
  ///
  /// # What it does NOT do
  ///
  /// It does not cancel or shorten a running tunnel. It runs only from
  /// `stopTunnel`, when the tunnel is already going down for a reason the
  /// system or the user chose. There is deliberately no production health
  /// watchdog that tears down a tunnel which is up but not yet passing traffic:
  /// for a user under a hostile state, a slow tunnel is safer than an automatic
  /// disconnection onto cleartext.
  private func releaseTunnelNetworkSettings(
    context: String,
    then completion: @escaping ([String: Any]) -> Void
  ) {
    // A dedicated once-guard, deliberately NOT `lifecycleGate`: that gate
    // arbitrates tunnel starts, and bumping its generation from a stop would
    // cancel a concurrent start for no reason.
    let completionLock = NSLock()
    var completionFired = false
    let startedAt = Date()
    func completeOnce(_ fields: [String: Any]) {
      completionLock.lock()
      let alreadyFired = completionFired
      completionFired = true
      completionLock.unlock()
      guard !alreadyFired else {
        return
      }
      var reported = fields
      reported["network_settings_release_requested"] = true
      reported["network_settings_release_elapsed_ms"] =
        Int(Date().timeIntervalSince(startedAt) * 1000)
      // WHICH SESSION STATE THE RELEASE WAS ISSUED FROM. This is the whole
      // experiment now: `-[NESMVPNSessionStateStopping handleClearConfiguration]`
      // returns NO with no path to YES, so a release issued from `stopTunnel`
      // is structurally incapable of succeeding. A release issued from the
      // self-cancel path reaches the agent while the session is still Running,
      // which is the one state where clear-configuration can succeed.
      reported["network_settings_release_context"] = context
      completion(reported)
    }

    DispatchQueue.global(qos: .userInitiated)
      .asyncAfter(deadline: .now() + Self.networkSettingsReleaseDeadlineSeconds) {
        // The anti-wedge path. Reaching it means the callback never came, which
        // is itself the finding: the release neither succeeded nor reported a
        // failure within the deadline.
        // INTEGER MILLISECONDS, NOT A Double OF SECONDS. `safeStatusNumber`
        // accepts only integer objCType codes (i,s,l,q,I,S,L,Q) and returns nil
        // for "d", so a Double is SILENTLY DISCARDED on a compacted write —
        // exactly the truncated-document path where this field matters most.
        // `_ms` as an Int also matches `network_settings_release_elapsed_ms`
        // and the macOS lane's vocabulary, so the two providers' status
        // documents stay one dialect rather than two.
        completeOnce([
          "network_settings_release_outcome": "deadline",
          "network_settings_release_completed": false,
          "network_settings_release_deadline_ms":
            Int(Self.networkSettingsReleaseDeadlineSeconds * 1000)
        ])
      }
    setTunnelNetworkSettings(nil) { [weak self] releaseError in
      guard let releaseError else {
        self.map {
          os_log(
            "Packet tunnel network settings released.",
            log: $0.logger,
            type: .info
          )
        }
        completeOnce([
          "network_settings_release_outcome": "released",
          "network_settings_release_completed": true,
          "network_settings_release_failed": false
        ])
        return
      }
      let nsError = releaseError as NSError
      self.map {
        os_log(
          // Names the fields it actually writes. The macOS version points a
          // reader at provider_error_domain/provider_error_code, which its own
          // stop path never writes; that is a dead end and is not repeated here.
          "Packet tunnel network settings release FAILED: %{public}@ (domain=%{public}@ code=%{public}d). Recorded in the provider status as network_settings_release_error_domain / network_settings_release_error_code.",
          log: $0.logger,
          type: .error,
          WinsTunnelDiagnostics.redactedProviderErrorMessage(releaseError),
          nsError.domain,
          nsError.code
        )
      }
      completeOnce([
        "network_settings_release_outcome": "failed",
        "network_settings_release_completed": true,
        "network_settings_release_failed": true,
        // The real domain and code, not a phrase. These are Apple-minted
        // identifiers and carry no user or key material.
        "network_settings_release_error_domain": nsError.domain,
        "network_settings_release_error_code": nsError.code
      ])
    }
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
      // THE SAMPLE POINT THAT MATTERS. The containing app's health message is
      // the only thing that refreshes the status document at a useful cadence
      // while a tunnel is up, so the seam counters are read here — on a message
      // the app already sends, on the thread already writing the document, and
      // never on the datapath.
      statusFields.merge(packetEngine?.seamObservabilityStatusFields() ?? [:]) { _, new in new }
      // THE UNDER-TRAFFIC MEMORY SAMPLE. Same reasoning as the seam counters
      // above: the app's health message is the only thing that refreshes the
      // status document at a useful cadence while a tunnel is up, so this is
      // where a live footprint can be observed at all.
      //
      // winn-only, deliberately. A production AmneziaWG session writes none of
      // these fields, so its status document keeps exactly the shape and size it
      // had before this lane. The numbers are only needed for the datapath whose
      // memory cost is in question.
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

  /// A live memory sample for a running winn/3 session: the footprint jetsam
  /// accounts against this process, and the headroom the system says is left.
  ///
  /// Both, not one. `phys_footprint` alone cannot say how close to the limit it
  /// is, because the limit differs by OS version (~50 MB on iOS 15+, roughly
  /// 15 MB on iOS 13/14) and by device; `os_proc_available_memory()` alone
  /// cannot say what this datapath actually costs. Together they calibrate the
  /// gate against the fleet instead of against an assumption.
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
    // Brackets the suspension: a sleep sample and the matching wake sample
    // below make loss that happened across a suspend attributable to it.
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

  private func makeNetworkSettings(
    from config: WinsTunnelConfig
  ) throws -> (settings: NEPacketTunnelNetworkSettings, statusFields: [String: Any]) {
    guard !config.networkSettingsRemoteAddress.isEmpty,
          !config.interfaceIPv4Address.isEmpty,
          !config.interfaceIPv4SubnetMask.isEmpty,
          !config.dnsServers.isEmpty,
          !config.allowedIPv4Routes.isEmpty else {
      throw Self.providerError(code: 1002, message: "Incomplete packet tunnel network settings.")
    }

    // THE CONTAINMENT DECISION. Read the marker unconditionally, act on it only
    // in a Debug appex, and REFUSE — never widen — in every other build shape.
    //
    // # Why the `requested` test is outside `#if DEBUG`, unlike macOS
    //
    // `macos/PacketTunnel/PacketTunnelProvider.swift` puts the whole test inside
    // `#if DEBUG`, so a Release appex ignores the marker and starts a full
    // tunnel. That is safe THERE because the macOS project defines
    // `SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG` at the PBXProject level, so
    // any Debug build of that appex genuinely has the containment path compiled
    // in — the "marker present but not honoured" state is unreachable for a
    // developer.
    //
    // On iOS that guarantee did NOT exist. Before this change the iOS project
    // set `SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG` only on the RunnerTests
    // and RunnerUITests targets; neither the PBXProject Debug configuration nor
    // the PacketTunnel target set it, which `xcodebuild -showBuildSettings
    // -target PacketTunnel -configuration Debug` confirmed by not listing it at
    // all. A verbatim copy of the macOS shape would therefore have compiled the
    // containment branch OUT of a Debug iOS appex, and a dev session that
    // believed itself contained would have taken the phone's default route, its
    // IPv6 and all of its DNS — the 2026-08-05 blackout, on the one device the
    // owner cannot casually reboot and a user in Myanmar may depend on.
    //
    // The build setting is fixed now (PacketTunnel target, Debug only), but a
    // safety property that depends on one line of a 1200-line pbxproj staying
    // put is not a safety property. So iOS FAILS CLOSED: a config that asked to
    // be contained either gets contained settings or gets no tunnel. There is
    // no build shape of this file in which the marker is silently ignored.
    //
    // # Why this does not touch production
    //
    // `requested` is false for every config the shipping app can produce.
    // `_buildRawAmneziaConfig` (`lib/main.dart`) never emits
    // `[WinsDevContainment]`, and the only writer of that section in the tree is
    // `lib/winn_protocol_dev_session.dart`, which is reachable solely from a
    // non-default `--target` and is therefore absent from a shipping binary.
    // For every production start this `if` is false and control falls through to
    // the full-tunnel body below, which is byte-identical to its pre-change form.
    let containmentPlan = config.devContainmentPlan
    if containmentPlan.requested {
      #if DEBUG
      return try makeContainedDevNetworkSettings(from: config, plan: containmentPlan)
      #else
      throw Self.providerError(
        code: 1016,
        message: "This Packet Tunnel build cannot contain a dev session, and refuses to start a full tunnel for a config that asked to be contained.",
        statusFields: [
          "dev_containment_active": false,
          "dev_containment_requested": true,
          "dev_containment_supported_by_build": false
        ]
      )
      #endif
    }

    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: config.networkSettingsRemoteAddress
    )
    let ipv4Settings = NEIPv4Settings(
      addresses: [config.interfaceIPv4Address],
      subnetMasks: [config.interfaceIPv4SubnetMask]
    )
    ipv4Settings.includedRoutes = config.allowedIPv4Routes.map { route in
      if route.isDefaultRoute {
        return NEIPv4Route.default()
      }
      return NEIPv4Route(
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
    return (settings, [:])
  }

  /// Whether `value` is a dotted-quad IPv4 literal. `NEDNSSettings` may carry
  /// IPv6 servers too, and only IPv4 servers belong on the tunnel's IPv4
  /// included-route table. Each `.`-separated part must parse as a 0-255 octet.
  private static func isIPv4Literal(_ value: String) -> Bool {
    let parts = value.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { UInt8($0) != nil }
  }

  #if DEBUG
  /// DEV-ONLY. The contained counterpart of `makeNetworkSettings`: the settings
  /// a proving session gets INSTEAD of full tunnel, so that a datapath which
  /// does not yet carry packets costs the session and not the whole phone.
  ///
  /// Point by point against what the shipping path installs:
  ///
  ///  * IPv4 — `includedRoutes` is exactly one /32 to the test endpoint.
  ///    `NEIPv4Route.default()` is never constructed here, so the phone's own
  ///    default route survives the session untouched.
  ///  * IPv6 — `settings.ipv6Settings` is left nil. No sink address, no
  ///    `NEIPv6Route.default()`. Host IPv6 is not touched at all.
  ///  * DNS — `settings.dnsSettings` is left nil. The shipping path sets
  ///    resolvers with `matchDomains = [""]`, which captures EVERY domain; a
  ///    contained session sets no DNS whatsoever, so the phone keeps its own
  ///    working resolvers and name resolution never depends on this tunnel.
  ///
  /// It FAILS rather than widens, in two independent ways. If the marker is
  /// present but no usable /32 can be derived, this throws. And if the settings
  /// object this function itself just built does not OBSERVABLY have those three
  /// properties, it throws too — see `WinsDevContainmentObservation`.
  private func makeContainedDevNetworkSettings(
    from config: WinsTunnelConfig,
    plan: WinsDevContainmentPlan
  ) throws -> (settings: NEPacketTunnelNetworkSettings, statusFields: [String: Any]) {
    guard let testRoute = plan.testRoute else {
      throw Self.providerError(
        code: 1015,
        message: "Contained dev session has no usable /32 test route; refusing to start rather than installing full-tunnel settings.",
        statusFields: [
          "dev_containment_active": false,
          "dev_containment_requested": true,
          "dev_containment_supported_by_build": true,
          "dev_containment_test_route_usable": false,
          "dev_containment_test_route_explicit": plan.testRouteRawPresent
        ]
      )
    }

    os_log(
      "%{public}@ CONTAINED dev packet tunnel: no default IPv4 route, no IPv6 settings, no DNS settings. One /32 included route only. This is NOT a validated full-tunnel session.",
      log: logger,
      type: .error,
      WinsDevContainmentApplication.absenceProbe
    )

    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: config.networkSettingsRemoteAddress
    )
    let ipv4Settings = NEIPv4Settings(
      addresses: [config.interfaceIPv4Address],
      subnetMasks: [config.interfaceIPv4SubnetMask]
    )
    ipv4Settings.includedRoutes = [
      NEIPv4Route(
        destinationAddress: testRoute.destinationAddress,
        subnetMask: testRoute.subnetMask
      )
    ]
    // Belt and braces. With no default route the outer socket is already
    // outside the tunnel; keeping the /32 exclusion makes that explicit and
    // costs nothing.
    if let exclusionRoute = plan.transportExclusionRoute {
      ipv4Settings.excludedRoutes = [
        NEIPv4Route(
          destinationAddress: exclusionRoute.destinationAddress,
          subnetMask: exclusionRoute.subnetMask
        )
      ]
    }
    settings.ipv4Settings = ipv4Settings
    // settings.ipv6Settings deliberately left nil — see the doc comment.
    // settings.dnsSettings deliberately left nil — see the doc comment.
    settings.mtu = NSNumber(value: config.mtu)

    // THE DIFFERENCE BETWEEN "CONTAINED" AND "SAID IT WAS CONTAINED".
    //
    // Everything above is intent. This reads the object that was actually built
    // and refuses the start unless the three properties that matter are
    // observably true of it. The status fields below are then derived from that
    // OBSERVATION, not from the plan — so `dev_containment_active: true` in a
    // provider status document means "these settings were inspected and found
    // narrow", not "some code intended them to be".
    let observation = WinsDevContainmentObservation(settings: settings)
    guard observation.isContained else {
      throw Self.providerError(
        code: 1017,
        message: "Contained dev session built settings that are not observably contained; refusing to install them.",
        statusFields: observation.statusFields.merging([
          "dev_containment_active": false,
          "dev_containment_requested": true,
          "dev_containment_supported_by_build": true,
          "dev_containment_test_route_usable": true
        ]) { _, new in new }
      )
    }

    // Armed only once containment is established — never for a session that
    // fell through to full tunnel, because such a session does not exist on
    // this path (both refusals above throw).
    armContainedDevSessionSelfCancel()

    var statusFields = plan.statusFields
    statusFields.merge(observation.statusFields) { _, new in new }
    statusFields["dev_containment_requested"] = true
    statusFields["dev_containment_supported_by_build"] = true
    statusFields["dev_containment_test_route_usable"] = true
    statusFields["dev_containment_self_cancel_armed"] = true
    // Integer milliseconds, matching the release fields' vocabulary. The value
    // was already `Int(...)` here so it was never at risk of the Double drop,
    // but a second unit in the same document is its own bug.
    statusFields["dev_containment_self_cancel_deadline_ms"] =
      Int(Self.containedDevSessionSelfCancelSeconds * 1000)
    statusFields["dev_containment_probe"] = WinsDevContainmentApplication.absenceProbe
    return (settings, statusFields)
  }

  /// DEV-ONLY. What an `NEPacketTunnelNetworkSettings` object ACTUALLY carries,
  /// read back off the object rather than assumed from the code that built it.
  ///
  /// The three properties are exactly the three the 2026-08-05 blackout
  /// consisted of, inverted: a default IPv4 route, any IPv6 settings at all, and
  /// any DNS settings at all. `isContained` is the conjunction of their
  /// absence plus "exactly one included route, and it is a /32".
  ///
  /// This exists because the honest failure mode of a containment feature is not
  /// "the code was never written" — it is "the code was written, something later
  /// widened what it produced, and the status kept saying `contained`". A stamp
  /// cannot catch that. A read-back can.
  private struct WinsDevContainmentObservation {
    let includedRouteCount: Int
    let includedRoutePrefixLengths: [Int]
    let defaultIPv4RouteInstalled: Bool
    let ipv6SettingsInstalled: Bool
    let dnsSettingsInstalled: Bool

    init(settings: NEPacketTunnelNetworkSettings) {
      let included = settings.ipv4Settings?.includedRoutes ?? []
      includedRouteCount = included.count
      includedRoutePrefixLengths = included.map {
        WinsDevContainmentObservation.prefixLength(ofSubnetMask: $0.destinationSubnetMask)
      }
      // NEIPv4Route.default() is 0.0.0.0/0. Compared by value rather than by
      // identity so that any route equivalent to a default route is caught,
      // however it was constructed.
      defaultIPv4RouteInstalled = included.contains {
        $0.destinationAddress == "0.0.0.0" &&
          WinsDevContainmentObservation.prefixLength(ofSubnetMask: $0.destinationSubnetMask) == 0
      }
      ipv6SettingsInstalled = settings.ipv6Settings != nil
      dnsSettingsInstalled = settings.dnsSettings != nil
    }

    /// Dotted-quad subnet mask to prefix length. Returns 0 for anything it
    /// cannot parse, which is the conservative answer here: an unparseable mask
    /// reads as a default route and fails containment rather than passing it.
    static func prefixLength(ofSubnetMask mask: String) -> Int {
      let octets = mask.split(separator: ".").compactMap { UInt8($0) }
      guard octets.count == 4 else {
        return 0
      }
      return octets.reduce(0) { $0 + $1.nonzeroBitCount }
    }

    var isContained: Bool {
      !defaultIPv4RouteInstalled &&
        !ipv6SettingsInstalled &&
        !dnsSettingsInstalled &&
        includedRouteCount == 1 &&
        includedRoutePrefixLengths == [32]
    }

    /// Namespaced `dev_containment_observed_*` so a reader can tell at a glance
    /// which fields were intended (`dev_containment_*`, from the plan) and which
    /// were measured off the settings object.
    var statusFields: [String: Any] {
      [
        "dev_containment_observed": true,
        "dev_containment_observed_contained": isContained,
        "dev_containment_observed_included_route_count": includedRouteCount,
        "dev_containment_observed_included_route_prefix_lengths":
          includedRoutePrefixLengths.map { String($0) }.joined(separator: ","),
        "dev_containment_observed_default_ipv4_route_installed": defaultIPv4RouteInstalled,
        "dev_containment_observed_ipv6_settings_installed": ipv6SettingsInstalled,
        "dev_containment_observed_dns_settings_installed": dnsSettingsInstalled
      ]
    }
  }

  /// How long a CONTAINED DEV session may run before the provider cancels
  /// itself. Only ever armed for a contained dev session, and only in a Debug
  /// appex.
  private static let containedDevSessionSelfCancelSeconds = 15.0 * 60.0

  /// DEV-ONLY. The contained-session deadline cancellation.
  ///
  /// # The gap it closes
  ///
  /// `stopTunnel` is only ever reached when something asks the tunnel to stop,
  /// and on both Apple platforms the only actor that asks is the host app. Kill
  /// the app and nothing can stop the tunnel: the extension outlives it, keeps
  /// whatever settings it was given, and waits. On macOS that produced a
  /// machine that needed a reboot. On a phone there is no equivalent of "reboot
  /// the laptop and get on with it" for someone relying on the device.
  ///
  /// `cancelTunnelWithError` is the only mechanism that lets the extension end
  /// its own session from the inside, and it does not depend on the settings
  /// release working — it initiates the whole teardown, including the system's
  /// own reclamation, rather than asking for a settings change on a session
  /// that is already stopping.
  ///
  /// # Why it is Debug-only and contained-only, and must stay that way
  ///
  /// This is NOT a production health watchdog, and must never become one. A
  /// timer that disconnects a tunnel which is up but not yet passing traffic
  /// would drop a user in a hostile state onto cleartext — for them a slow
  /// tunnel is strictly safer than an automatic disconnection. The macOS lane
  /// considered and rejected exactly that, correctly.
  ///
  /// What makes this safe is that it is armed only for a session that is
  /// already CONTAINED: one /32, no IPv6, no DNS, no user traffic on it, and no
  /// user behind it. Cancelling one costs a developer a restarted experiment.
  /// The two conditions are independent: `#if DEBUG` (absent from any shipping
  /// appex) AND containment established (absent from any production config).
  private func armContainedDevSessionSelfCancel() {
    let deadline = Self.containedDevSessionSelfCancelSeconds
    os_log(
      "%{public}@ CONTAINED dev session self-cancel armed: this tunnel will cancel itself in %{public}d seconds. This exists so a dev session cannot outlive the app that started it on a device you cannot casually reboot.",
      log: logger,
      type: .error,
      WinsDevContainmentApplication.absenceProbe,
      Int(deadline)
    )
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + deadline) {
      [weak self] in
      guard let self else {
        return
      }
      os_log(
        "%{public}@ CONTAINED dev session self-cancel firing now.",
        log: self.logger,
        type: .error,
        WinsDevContainmentApplication.absenceProbe
      )
      // A contained session is the only start that arms this timer, and a
      // contained posture is not a kill switch. If classification was wrong
      // and this session actually holds a blocking full-tunnel posture, do
      // NOT release settings while the datapath is still running: that is
      // the teardown race into cleartext the kill switch exists to forbid.
      // cancelTunnelWithError still ends the session; stopTunnel then stops
      // the datapath before any stop-path release.
      if let config = self.activeConfig,
         WinsKillSwitch.activeFor(config: config, devRunActive: false) {
        self.writeProviderStatus(
          stage: "stopping",
          config: config,
          engineReady: false,
          networkSettingsReady: true,
          extra: [
            "dev_containment_self_cancel_fired": true,
            "dev_containment_self_cancel_deadline_ms": Int(deadline * 1000),
            "dev_containment_self_cancel_release_skipped_kill_switch_held": true
          ]
        )
        self.cancelTunnelWithError(
          Self.providerError(
            code: 1019,
            message: "Contained dev session reached its self-cancel deadline.",
            statusFields: [
              "dev_containment_self_cancel_fired": true,
              "dev_containment_self_cancel_release_skipped_kill_switch_held": true
            ]
          )
        )
        return
      }
      // RELEASE FIRST, WHILE THE SESSION IS STILL RUNNING.
      //
      // This ordering is the entire reason the self-cancel is the primary
      // teardown lever rather than a fallback. The macOS lane disassembled
      // `/usr/libexec/nesessionmanager` and found
      // `-[NESMVPNSessionStateStopping handleClearConfiguration]` returns NO
      // with NO PATH TO YES: the state machine refuses clear-configuration for
      // ANY stopping session, unconditionally. A release issued from
      // `stopTunnel` is therefore structurally incapable of succeeding, however
      // carefully it is written.
      //
      // Here the session has not been asked to stop yet. It is still Running,
      // which is the one state in which clear-configuration can return YES. So
      // the settings release is attempted here, its outcome is recorded under
      // its own `dev_containment_self_cancel_release_*` namespace so it can
      // never be confused with the stop-path attempt, and only then is the
      // cancel issued.
      self.releaseTunnelNetworkSettings(context: "self_cancel_running") {
        releaseFields in
        var fields: [String: Any] = [
          "dev_containment_self_cancel_fired": true,
          "dev_containment_self_cancel_deadline_ms": Int(deadline * 1000)
        ]
        // Re-namespaced rather than merged, so a reader can tell at a glance
        // which attempt each outcome belongs to.
        for (key, value) in releaseFields {
          fields["dev_containment_self_cancel_" + key] = value
        }
        // Written BEFORE the cancel. Once `cancelTunnelWithError` is called the
        // system may tear this process down at any moment, and a document
        // written after it is a document that may never exist. This is the only
        // place the running-session release outcome can be durably recorded.
        self.writeProviderStatus(
          stage: "stopping",
          config: self.activeConfig,
          engineReady: false,
          networkSettingsReady: false,
          extra: fields
        )
        os_log(
          "%{public}@ CONTAINED dev session self-cancel: settings release from a RUNNING session reported %{public}@. Issuing cancelTunnelWithError now.",
          log: self.logger,
          type: .error,
          WinsDevContainmentApplication.absenceProbe,
          (releaseFields["network_settings_release_outcome"] as? String) ?? "unknown"
        )
        self.cancelTunnelWithError(
          Self.providerError(
            code: 1019,
            message: "Contained dev session reached its self-cancel deadline.",
            statusFields: fields
          )
        )
      }
    }
  }

  /// DEV-ONLY marker type. Exists so "did a Release appex compile the
  /// containment path in?" is answered mechanically rather than argued:
  ///
  /// ```
  /// strings <PacketTunnel.appex binary> | grep WINS_IOS_DEV_CONTAINMENT_ABSENCE_PROBE
  /// ```
  ///
  /// must produce NOTHING for a Release/Profile build, and a hit for Debug. The
  /// whole type is inside `#if DEBUG`, so the literal cannot reach a Release
  /// binary even as dead data. The literal is deliberately DIFFERENT from the
  /// macOS provider's, so a `strings` result names which platform's appex it
  /// came from and one platform's probe can never vouch for the other's.
  private enum WinsDevContainmentApplication {
    static let absenceProbe = "WINS_IOS_DEV_CONTAINMENT_ABSENCE_PROBE_3d9f52a1"
  }
  #endif

  // MARK: - Runtime appex memory gate (winn/3 only)

  /// Conservative marginal reserve for the measured direct-AWG and standalone
  /// Winn datapaths. System headroom must accommodate this reserve before
  /// network settings are installed. Physical footprint is measured separately.
  /// The 15 MiB ceiling is project policy, independent of the OS jetsam limit.
  private static let winnDirectAwgDatapathRequiredBytes = 12 * 1024 * 1024
  private static let winnStrictPhysicalFootprintCeilingBytes = 15 * 1024 * 1024
  private static let winnMemoryWatchdogIntervalSeconds = 1.0
  /// After promotion the watchdog only records (it never cancels a carrying
  /// session), so it samples every 5 s with 2 s of leeway and coalesces with
  /// the radio's own wake-ups.
  private static let winnMemoryWatchdogPromotedIntervalSeconds = 5.0

  /// Call only while lifecycleGate owns the current lifecycle operation.
  private func stopWinnMemoryWatchdog() {
    let watchdog = winnMemoryWatchdog
    winnMemoryWatchdog = nil
    watchdog?.timer.setEventHandler {}
    watchdog?.timer.cancel()
  }

  /// Called inside each successful lifecycle handoff, before start completion.
  private func startWinnMemoryWatchdog(lifecycleToken: UInt64) {
    stopWinnMemoryWatchdog()
    guard activeConfig?.winnEnabled == true else { return }
    let timer = DispatchSource.makeTimerSource(queue: winnMemoryWatchdogQueue)
    let watchdog = WinnMemoryWatchdog(timer: timer)
    timer.schedule(
      deadline: .now(),
      repeating: Self.winnMemoryWatchdogIntervalSeconds,
      leeway: .milliseconds(100)
    )
    timer.setEventHandler { [weak self, weak watchdog] in
      guard let self, let watchdog else { return }
      // Cancellation does not interrupt an in-flight dispatch handler. Keep
      // the sample and cancel in the same critical section as begin/stop so
      // an old handler cannot cancel a replacement session or its timer.
      self.lifecycleGate.performIfCurrent(lifecycleToken) {
        guard self.winnMemoryWatchdog === watchdog else { return }
        let footprint = Self.physicalFootprintBytes()
        let promoted = self.packetEngine != nil || self.winn3Datapath != nil
        if promoted && !watchdog.relaxed {
          watchdog.relaxed = true
          watchdog.timer.schedule(
            deadline: .now() + Self.winnMemoryWatchdogPromotedIntervalSeconds,
            repeating: Self.winnMemoryWatchdogPromotedIntervalSeconds,
            leeway: .seconds(2)
          )
        }
        let decision = WinsWinnMemoryWatchdogPolicy.decide(
          footprintBytes: footprint,
          ceilingBytes: Self.winnStrictPhysicalFootprintCeilingBytes,
          promoted: promoted
        )
        if decision == .ignore {
          return
        }
        if decision == .recordOnly {
          self.activeEngineStatusFields["winn_memory_watchdog_ceiling_exceeded"] = true
          self.activeEngineStatusFields["winn_memory_watchdog_canceled"] = false
          if let footprint {
            self.activeEngineStatusFields["winn_memory_sample_phys_footprint_bytes"] = footprint
          }
          return
        }
        var fields: [String: Any] = [
          "winn_memory_watchdog_canceled": true,
          "winn_memory_watchdog_sample_failed": footprint == nil || (footprint ?? 0) < 0,
          "winn_memory_watchdog_ceiling_exceeded":
            (footprint ?? -1) >= Self.winnStrictPhysicalFootprintCeilingBytes,
          "winn_memory_gate_physical_footprint_ceiling_bytes":
            Self.winnStrictPhysicalFootprintCeilingBytes
        ]
        if let footprint {
          fields["winn_memory_sample_phys_footprint_bytes"] = footprint
        }
        let error = Self.providerError(
          code: 1038,
          message: "The Winn session cannot remain below its strict physical memory ceiling.",
          statusFields: fields
        )
        self.writeProviderStatus(
          stage: "stopping",
          config: self.activeConfig,
          engineReady: false,
          networkSettingsReady: true,
          error: error,
          extra: fields,
          statusGeneration: self.activeStatusGeneration
        )
        // Already under lifecycleGate. Calling the override would re-enter it.
        self.cancelTunnelUnderLifecycleGate(error)
      }
    }
    winnMemoryWatchdog = watchdog
    timer.resume()
  }

  /// Whether the winn/3 datapath may start, given the memory this process
  /// actually has left.
  ///
  /// Deliberately a pure value type over an `availableBytes: Int?` parameter:
  /// the measurement is iOS-only (`os_proc_available_memory()` does not exist on
  /// macOS) but the DECISION must be compilable and testable everywhere,
  /// including in the verification harness that runs on this Mac. Only the
  /// measurement is `#if os(iOS)`; none of the logic is.
  struct WinsWinnAppexMemoryGate {
    /// Bytes remaining before this process hits its own limit, or nil when the
    /// platform could not report it.
    let availableBytes: Int?
    /// `[winn] carrier`, verbatim and lowercased. Empty for a pre-carrier config.
    let carrier: String
    let requiredBytes: Int
    let physicalFootprintCeilingBytes: Int
    /// `TASK_VM_INFO.phys_footprint` must stay strictly below the project
    /// ceiling, regardless of the OS-reported headroom.
    let physicalFootprintBytes: Int?

    /// A named, specific refusal, or nil when the session may proceed.
    /// Never a bare bool: a refusal a user or an operator cannot read is a
    /// refusal they will work around.
    var refusalReason: String? {
      // The carrier datapath's footprint has never been measured. The
      // direct-awg number describes a different Go call graph — one without
      // quic-go, without ML-DSA, and without an uncapped QUIC receive window —
      // so applying it here would be inventing evidence, not applying it.
      //
      // EXCEPT for the standalone winn/3 carrier. That one
      // marginal IS measured now:
      // docs/handoff/IOS_APPEX_MEMORY_CEILING_STANDALONE_FOOTPRINT_20260810_ds_iosmem.md
      // reports ≈ +4.7…+5.5 MiB over a host that already has the runtime
      // resident, across four in-rig runs against a real cdatapath archive,
      // with a live sampler control (+8.6 MiB for an 8 MiB memset) proving the
      // sampler moves. That is BELOW the 8.1 MiB relay-path marginal that
      // `winnDirectAwgDatapathRequiredBytes` was rounded up from, so the
      // existing 12 MiB requirement does not under-gate the standalone shape
      // and no new constant is invented here — the measuring lane's own stated
      // "cheapest correct change".
      //
      // The standalone v3 rollout uses this measured profile in Release.
      // Both the available-memory reserve and strict physical footprint
      // budget are checked for every start, independently of the SDK floor.
      if !carrier.isEmpty, carrier != WinsTunnelConfig.supportedWinnCarrier {
        if carrier != WinsTunnelConfig.supportedWinnCarrierWinn3 {
          return "winn_carrier_memory_profile_unmeasured"
        }
      }
      guard let availableBytes else {
        return "appex_available_memory_unknown"
      }
      guard let physicalFootprintBytes, physicalFootprintBytes >= 0 else {
        return "appex_physical_footprint_unknown"
      }
      guard physicalFootprintBytes < physicalFootprintCeilingBytes else {
        return "appex_physical_footprint_ceiling_reached"
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
        "winn_memory_gate_physical_footprint_ceiling_bytes": physicalFootprintCeilingBytes,
        "winn_memory_gate_available_measured": availableBytes != nil,
        "winn_memory_gate_carrier": carrier.isEmpty ? "direct-awg-implicit" : carrier
      ]
      if let availableBytes {
        // Recorded on EVERY winn start, allowed or refused. This is the first
        // real measurement of the appex's true three-runtime headroom on a
        // device, and a refusal is exactly the case where the number is most
        // worth having.
        fields["winn_memory_gate_available_bytes"] = availableBytes
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

  /// This process's real memory footprint, in bytes, or nil if `task_info`
  /// fails.
  ///
  /// `TASK_VM_INFO.phys_footprint` is the number jetsam actually accounts
  /// against a process — the same field the preceding lane measured 14.2 MiB
  /// with — so it is the one to record alongside the headroom. Available on
  /// both iOS and macOS, deliberately not `#if os(iOS)`, so the verification
  /// harness on the Mac exercises this code rather than a stub.
  ///
  /// Sampling shape reused from
  /// `winn_protocol_experimental/spikes/ios_maximum_privacy/PacketTunnel/PacketTunnelProvider.swift`
  /// rather than reinvented.
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

  /// The system's own report of this process's remaining headroom, or nil where
  /// the platform cannot report it.
  ///
  /// `os_proc_available_memory()` is iOS 13.0+ and does not exist on macOS, so
  /// the non-iOS branch exists ONLY so this file typechecks against the macOS
  /// SDK during verification. It returns nil, which the gate treats as
  /// `appex_available_memory_unknown` and REFUSES on — the conservative answer,
  /// and the same answer the shipping iOS branch gives if the system ever
  /// reports 0.
  private static func availableProcessMemoryBytes() -> Int? {
    #if os(iOS)
    let available = os_proc_available_memory()
    return available > 0 ? available : nil
    #else
    return nil
    #endif
  }

  /// Builds the gate for a parsed config. Non-winn configs are not gated at
  /// all: this returns nil for them and the start proceeds exactly as it did
  /// before this gate existed, writing none of its fields.
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
      physicalFootprintCeilingBytes: Self.winnStrictPhysicalFootprintCeilingBytes,
      physicalFootprintBytes: Self.physicalFootprintBytes()
    )
  }

  // MARK: - Staged winn/3 start: prove the datapath, then take the phone
  //
  // # The failure this exists to make impossible
  //
  // Until this change the ONE call to `setTunnelNetworkSettings` installed the
  // full-tunnel settings — default IPv4 route, IPv6 sink with `::/0`, DNS with
  // an empty match domain (= every domain) — BEFORE anything had shown the
  // datapath could carry a packet. A winn/3 session whose handshake never
  // completed therefore held all three and carried nothing: total blackout,
  // surviving the app because the appex outlives it (2026-08-05 on macOS, and
  // the owner lost the machine to it and had to reboot; on a phone the same
  // failure lands on the one device its owner may depend on to reach anyone).
  // The dev-only containment above exists because of that failure — but
  // containment is a dev-session mechanism that must stay dev-only (this file
  // FAILS CLOSED rather than containing in a non-Debug build), which made the
  // blackout structurally unfixable on the SHIPPING path. This section fixes
  // the shipping path itself.
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
  //     gateway, the same derivation dev containment uses), the transport /32
  //     exclusion, no default route, no IPv6, no DNS. The phone's routing,
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
  //     fails while the phone still holds its own routes, resolvers and IPv6.
  //     The worst wedge (`NEAgentErrorDomain` code 1 has been reproduced on
  //     both platforms; a settings release can be refused) now strands at most
  //     one VPN-owned /32 and one exclusion /32 — not the phone.
  //
  // # THE KILL SWITCH OVERRIDES POINT 1 (and the narrow reading of points 1 and
  // # 4) FOR PRODUCTION FULL-TUNNEL RUNS, PUT THERE 2026-08-10
  //
  // 1. INSTALL was the narrow posture only to keep the phone untouched while
  //    the datapath was proven. That is the anti-kill-switch: while the phone
  //    is untouched, traffic it emits during the connect window egresses in the
  //    clear, which is the leak the whole product exists to prevent. So
  //    `makeWinnStagedStartPlan` now makes the FIRST posture the BLOCKING
  //    (full-tunnel) one for every production full-tunnel winn start, verified
  //    blocking by `WinsKillSwitch.egressBlocked`, and the containment/
  //    narrow-bootstrap path survives only for contained dev sessions.
  // 4. FAIL-CLOSED therefore means: on deadline/engine-exit/supersession the
  //    start fails and the phone is released when the session ends (teardown),
  //    not untouched throughout. It is the fail-closed direction the
  //    no-watchdog doctrine already takes ("a dead tunnel that blacks out is
  //    still safer than one that silently falls back to cleartext"). The memory
  //    gate keeps its meaning: a jetsam during proof kills an appex holding
  //    the blocking posture, which is a blackout until the system reclaims the
  //    settings at session end — not a leak.
  //  * Dev containment is the one case that keeps the narrow posture (that is
  //    the point of containment), and it never reaches this gate.
  //
  // # What this deliberately does NOT change
  //
  //  * Non-winn starts. AmneziaWG and Xray production sessions install their
  //    settings in one step exactly as before — byte-identical documents,
  //    byte-identical behaviour. Their engines expose no
  //    `transport_observed_both_ways` to this provider today, so a staged
  //    start for them would have to gate on something the Go datapath's own
  //    documentation forbids, and this section refuses to invent one.
  //  * Split-tunnel winn starts. Without a default route there is no seizure
  //    to stage, so nothing is staged.
  //  * The memory gate above. It keeps its placement BEFORE any settings
  //    exist, and gains a second layer: a jetsam during the proof phase now
  //    kills an appex that holds only the bootstrap posture, not the phone.
  //  * The no-watchdog doctrine. `releaseTunnelNetworkSettings`'s doc comment
  //    promises no health watchdog ever tears down a RUNNING tunnel onto
  //    cleartext, and that stands: this gate acts strictly BEFORE the session
  //    first claims the phone, while the system still reports Connecting and
  //    the user has been promised nothing. After promotion the tunnel holds
  //    its routes fail-closed exactly as before — for a user under a hostile
  //    state, a dead tunnel that blacks out is still safer than one that
  //    silently falls back to cleartext.
  //  * Dev containment. A contained session never reaches this gate (it never
  //    installs full-tunnel settings at all), and the gate never widens a
  //    contained session: `makeWinnStagedStartPlan` returns nil whenever the
  //    settings it was handed are containment's.

  /// Decides whether this start is staged, and builds both postures up front
  /// if so. Returns nil for every start that must keep today's single-install
  /// behaviour. Throwing is reserved for a bootstrap that cannot be built
  /// safely — a start that WOULD be staged but cannot be is refused, never
  /// silently widened to an immediate full tunnel, for exactly the reason
  /// containment never falls back to full tunnel.
  private func makeWinnStagedStartPlan(
    from config: WinsTunnelConfig,
    fullTunnelResult: (settings: NEPacketTunnelNetworkSettings, statusFields: [String: Any])
  ) throws -> WinsWinnStagedStartPlan? {
    let containmentActive =
      fullTunnelResult.statusFields["dev_containment_active"] as? Bool == true
    guard WinsWinnDatapathProofGate.applies(
      winnEnabled: config.winnEnabled,
      defaultIPv4RouteEnabled: config.defaultIPv4RouteEnabled,
      devContainmentActive: containmentActive
    ) else {
      return nil
    }

    // THE KILL SWITCH. A contained session never reaches this gate (it returns
    // nil above), so every start that reaches here is a production full-tunnel
    // winn start: its FIRST posture is the blocking one, not the narrow one,
    // so nothing the phone emits during the connect window egresses in the
    // clear. See `WinsKillSwitch`. The proof loop still gates the start from
    // completing (it will not report carrying until the datapath is proven);
    // only the posture timing changes.
    if WinsKillSwitch.activeFor(config: config, devRunActive: false) {
      guard WinsKillSwitch.egressBlocked(by: fullTunnelResult.settings, config: config) else {
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
        bootstrapSettings: fullTunnelResult.settings,
        fullTunnelSettings: fullTunnelResult.settings,
        interfaceIPv4Address: config.interfaceIPv4Address,
        probeDNSServers: config.dnsServers,
        bootstrapStatusFields: WinsKillSwitch.bootstrapStatusFields(
          config: config,
          verifiedBlocking: true,
          firstPostureBlocking: true
        )
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
    // settings.ipv6Settings deliberately left nil — the phone keeps its IPv6.
    // settings.dnsSettings deliberately left nil — the phone keeps its
    // resolvers; name resolution never depends on an unproven tunnel.
    settings.mtu = NSNumber(value: config.mtu)

    // Observably narrow, verified on the object just built rather than assumed
    // from the code that built it — the same fail-closed posture
    // `WinsDevContainmentObservation` established for contained sessions. A
    // bootstrap that somehow carries a default route, DNS or IPv6 must refuse
    // the start, never install.
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
      fullTunnelSettings: fullTunnelResult.settings,
      interfaceIPv4Address: config.interfaceIPv4Address,
      probeDNSServers: config.dnsServers,
      bootstrapStatusFields: WinsWinnDatapathProofGate.bootstrapStatusFields(
        bootstrapIncludedRouteCount: includedRoutes.count,
        bootstrapGatewayRoutePresent: gatewayRoute != nil,
        transportExclusionRoutePresent: config.transportIPv4ExclusionRoute != nil,
        probeTargetCount: config.dnsServers.count
      )
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
      startWinnMemoryWatchdog(lifecycleToken: lifecycleToken)
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
        stopWinnMemoryWatchdog()
      }
    }

    let startedAt = DispatchTime.now()
    let deadlineMilliseconds = Int(
      (Self.winnDatapathProofDeadlineSeconds * 1000).rounded()
    )
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
      return fields
    }

    // The first status document of the staged phase: engine running, phone NOT
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
        "%{public}@ FAILED CLOSED before promotion: %{public}@ The phone's routing, IPv6 and DNS were never claimed.",
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
              self.startWinnMemoryWatchdog(lifecycleToken: lifecycleToken)
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
      let probeSatisfied = probe == nil || (probe?.responsesObserved ?? 0) > 0
      if WinsWinnDatapathProofGate.converged(engineStatusFields: engineFields),
         probeSatisfied {
        beginPromotion(engineFields: engineFields)
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
  /// EMIT-CONFIG INTEGRATION for the winn/3 standalone session.
  ///
  /// The memory gate above (`winnAppexMemoryGate`, in `startTunnel`) decides
  /// whether the datapath MAY start; this is the step that turns an allowed
  /// verdict into a datapath that actually receives configuration. It emits the
  /// create document the datapath consumes — `WinsWinn3CreateDocument.json()` is
  /// the exact bytes `WinsWinn3Datapath.start(document:carrierDescriptor:)`
  /// hands to the engine — so the gate's "under the limit" branch is visibly
  /// tied to a winn3Datapath start rather than to a gate that only refuses.
  ///
  /// Kept on the provider rather than inside `WinsWinn3CreateDocument` so the
  /// gate-to-pump seam has one named, verifiable point instead of a bare
  /// `make(config:)` in the middle of the start function.
  ///
  /// - Throws: exactly the refusal `startWinn3StandaloneSession` used to throw
  ///   before this step was extracted — same code, same message, same
  ///   `statusFields` carrier — so behaviour is byte-for-byte unchanged.
  private func emitWinn3Config(
    for config: WinsTunnelConfig,
    statusFields: [String: Any]
  ) throws -> WinsWinn3CreateDocument {
    guard let createDocument = WinsWinn3CreateDocument.make(config: config) else {
      // Unreachable through `startTunnel` — `parseAndValidate` already refused
      // an incomplete standalone config with the same reasons — and checked
      // anyway, because "a validator ran earlier" is an assumption and this is
      // the last place before a socket is opened.
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

    // The emitted config is the create document the datapath starts from. The
    // memory gate has already allowed this start (it is above, in `startTunnel`);
    // this is where an allowed verdict becomes a datapath that holds the bytes.
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
    // datapath is proven. `promotionHeld` (contained/dev runs — on iOS this is
    // set exactly when dev containment is active) is the one case that keeps
    // the narrow "host untouched" bootstrap.
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
      startWinnMemoryWatchdog(lifecycleToken: lifecycleToken)
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
        stopWinnMemoryWatchdog()
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
        "%{public}@ FAILED CLOSED before promotion: %{public}@ The phone's routing, IPv6 and DNS were never claimed.",
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

    /// PROVEN, then stop. On iOS this is what CONTAINMENT selects: a contained
    /// dev session must never take the phone, and holding the promotion is
    /// exactly that guarantee — everything up to the commit has happened, the
    /// evidence recorded is what a promoting run would have recorded, and the
    /// phone's routing, IPv6 and DNS are never claimed. Reported as a failed
    /// start because that is what it is: no tunnel is left running.
    func finishProvenWithPromotionHeld(engineFields: [String: Any]) {
      guard !finished else { return }
      finished = true
      timer.cancel()
      probe?.invalidate()
      stopProvingResource()
      os_log(
        "%{public}@ PROVEN; promotion HELD on purpose. The phone's routing, IPv6 and DNS were never claimed.",
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
              self.startWinnMemoryWatchdog(lifecycleToken: lifecycleToken)
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
    // not a start source on iOS. That blob is written into NEVPN preferences,
    // survives process death, and is what iOS On Demand / Settings toggles
    // replay when startTunnel is invoked with no transient options. Starting
    // from it would (1) leak static_private / admission_key into a durable
    // system store and (2) replay a previously delivered descriptor without
    // going through the host's selected-node binding. The App Group shared
    // file is redacted; transient start options are the only in-memory secret
    // handoff. Presence of the key is ignored; its bytes are never parsed.
    if let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
       providerProtocol.providerConfiguration?["winn3_ini"] != nil {
      os_log(
        "Ignoring persisted winn3_ini in providerConfiguration; iOS Packet Tunnel refuses that replay path.",
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
    // DEV-ONLY CONTAINMENT, CARRIED INTO THE `stopped` DOCUMENT.
    //
    // The macOS sibling has a hole here: its copy list omits every
    // `dev_containment_*` field, so the FINAL document of a contained run does
    // not record that the run was contained. Post-hoc "was this session
    // contained?" is the first question anyone reviewing a run asks, and the
    // stopped document is usually the one still on disk when they ask it.
    //
    // Copied under the SAME key names rather than `previous_*_before_stop`
    // ones, deliberately: `dev_containment_active` is the term
    // `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields` reads to fail
    // `leak_protection_config_passed`, and renaming it here would let a
    // stopped contained session read as a passing full-tunnel posture — the
    // exact confusion the field exists to prevent.
    //
    // Production writes none of these, so this copies nothing for a shipping
    // session and the stopped document is unchanged for one.
    for containmentKey in [
      "dev_containment_active",
      "dev_containment_requested",
      "dev_containment_supported_by_build",
      "dev_containment_kind",
      "dev_containment_observed",
      "dev_containment_observed_contained",
      "dev_containment_default_ipv4_route_installed",
      "dev_containment_ipv6_settings_installed",
      "dev_containment_dns_settings_installed",
      "dev_containment_test_route_prefix_length",
      "dev_containment_self_cancel_armed"
    ] {
      copy(containmentKey, as: containmentKey)
    }
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

// The staged winn/3 start's shared half — `WinsWinnStagedStartPlan`,
// `WinsWinnDatapathProofGate` and `WinsWinnDatapathProofProbe` — was HOISTED on
// 2026-08-08 into `apple/WinsTunnelCore/WinsPacketTunnelEngine.swift`, which
// already compiles into this appex and into the macOS one. It used to be
// file-private here, which is exactly why the macOS provider could not build.
// Do not re-declare it in this file: a second proof gate is a second promotion
// standard. See `docs/handoff/MACOS_STAGED_PLAN_RESTORED_20260808.md`.

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
