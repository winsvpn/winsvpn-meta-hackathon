import Cocoa
import FlutterMacOS
import NetworkExtension
import os

// ---------------------------------------------------------------------------
// WinsAppLifecycle -- macOS launch-path instrumentation.
//
// WHY IT USES os_log AND NOT NSLog, AND WHY THAT MATTERS MORE THAN IT LOOKS.
//
// `AppDelegate.applicationDidFinishLaunching` was recorded in this repo as
// "never executed at runtime" on Release builds installed to /Applications, on
// the strength of an `NSLog` placed as its first statement producing no output
// under
//
//     log show --predicate 'processImagePath CONTAINS "Win'\''s VPN"'
//
// That measurement was wrong, and it was wrong in a way that will repeat.
// Foundation hands the whole composed `NSLog` message to the unified log as a
// *dynamic argument*, so every `NSLog` in this process is recorded as
//
//     Df  Win's VPN[...] (Foundation) <private>
//
// The line is present; only its body is redacted. Measured 20260809: a launch
// that emitted 13 `NSLog` calls produced exactly 13 `(Foundation) <private>`
// entries under that predicate and zero readable ones. Grepping the log for
// your own message text therefore reports "it never ran" for a method that ran
// every single time.
//
// `os_log` with a `%{public}` argument is not redacted, so a lifecycle line
// logged through here is visible under the owner's own predicate with no
// profile, no `log config`, and no terminal launch. Log launch-path facts
// through `WinsAppLifecycle`, never through `NSLog`, or the next reader
// inherits the same false negative.
//
// Nothing logged here carries user data, key material, server identity or
// anything about a tunnel session: it is two lines of "the app started".
//
// THE RULE ABOVE IS ABOUT LAUNCH-PATH FACTS ONLY. DO NOT GENERALISE IT INTO A
// SWEEP THAT CONVERTS EVERY `NSLog` IN THIS APP TO `os_log`. That sweep would
// be a privacy regression, and here is the measurement that says so (20260810,
// this machine, one process emitting all six shapes, read back with
// `/usr/bin/log show --style compact`):
//
//   NSLog("... %@", detail)                 -> (Foundation) <private>
//   NSLog("bare literal, no interpolation") -> (Foundation) <private>
//   os_log("static text", log:)             -> static text          [PUBLIC]
//   os_log("prefix %{private}@", …, detail) -> prefix <private>     [PUBLIC prefix]
//   os_log("prefix %@", …, detail)          -> prefix <private>     [PUBLIC prefix]
//   os_log("prefix %{public}@", …, detail)  -> prefix SENSITIVEDETAIL
//
// An `os_log` FORMAT STRING IS ALWAYS PUBLIC. Privacy qualifiers apply to the
// arguments and never to the literal, so `%{private}` cannot hide the words you
// wrote. `NSLog` is therefore STRICTLY MORE PRIVATE than any `os_log` shape --
// it is the only one in which the message text itself is redacted, because
// Foundation hands the whole composed string over as a dynamic argument.
//
// That accident is load-bearing for this product. This is a censorship-
// circumvention app whose users may have a device searched, and the unified log
// persists and is collected by `sysdiagnose`. For a tunnel-state fact the
// EXISTENCE of a legible line is the disclosure, independently of its wording:
// a public "tunnel start stage accepted" timestamps the user connecting to a
// VPN, which is precisely the inference a search is looking for. There is no
// `%{private}` rescue for those sites, because the public prefix alone would
// carry the meaning. So:
//
//   * launch-path facts ("an app on this device started")  -> WinsAppLifecycle.
//   * tunnel state, session detail, camouflage state,
//     server identity, key or user data                    -> NSLog, and leave
//     it there. Its absence from `log show` is CORRECT, not a bug to fix.
//
// See docs/handoff/APPLE_NSLOG_REDACTION_AUDIT_20260810.md for the per-site
// audit of all 22 remaining call sites, and
// docs/handoff/OWNERSHIP_CLAIM_ATTRIBUTION_AND_SESSION_LABEL_20260807.md §5,
// which already lists the macOS tunnel-stage lines as unretractable residue.
// ---------------------------------------------------------------------------
enum WinsAppLifecycle {
  #if DEBUG
  static let log = OSLog(subsystem: "org.winsvpn.app", category: "lifecycle")
  #else
  static let log = OSLog.disabled
  #endif

  /// Marker every launch-path line carries so one grep finds all of them.
  static let marker = "WINSLIFECYCLE"

  static func note(_ message: String) {
    os_log("WINSLIFECYCLE %{public}@", log: log, type: .default, message)
  }

  static func fault(_ message: String) {
    os_log("WINSLIFECYCLE FAULT %{public}@", log: log, type: .fault, message)
  }
}

// ---------------------------------------------------------------------------
// WinsMacLaunchWatchdog -- fails loudly if the delegate stops being called.
//
// A lifecycle entry point that stops firing is this codebase's signature
// defect, and it is silent by construction: the app still launches, the window
// still appears, and only the work hanging off the dead method disappears. The
// Android session watchdog checked the wrong field for weeks before anyone
// noticed, and this very method spent months documented as dead.
//
// So: arm at `AppDelegate.init` -- the nib instantiating the delegate, the
// earliest point in the delegate's own life -- and disarm on the first
// statement of `applicationDidFinishLaunching`. If the deadline passes
// undisarmed, emit an os_log FAULT, which is visible under the owner's
// predicate and is what `tools/verify_macos_app_lifecycle.sh` fails on.
//
// The deadline runs on a global queue ON PURPOSE. `applicationDidFinishLaunching`
// is delivered on the main thread, so a watchdog scheduled on the main queue
// would be blocked by exactly the wedge it exists to report.
// ---------------------------------------------------------------------------
enum WinsMacLaunchWatchdog {
  private static let deadlineSeconds: Double = 8
  private static let lock = NSLock()
  private static var armed = false
  private static var didFinishLaunchingRan = false

  static func arm() {
    lock.lock()
    if armed {
      lock.unlock()
      return
    }
    armed = true
    lock.unlock()

    WinsAppLifecycle.note(
      "AppDelegate.init -- launch watchdog armed, deadline=\(Int(deadlineSeconds))s"
    )

    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + deadlineSeconds) {
      lock.lock()
      let ran = didFinishLaunchingRan
      lock.unlock()
      guard !ran else { return }

      WinsAppLifecycle.fault(
        "applicationDidFinishLaunching DID NOT RUN within \(Int(deadlineSeconds))s of "
          + "AppDelegate.init. NSApplication is not calling this delegate. Everything "
          + "reachable only from that method -- ensureMainWindowVisible() and anything "
          + "added to it since -- is dead code in this build. Check the MainMenu nib "
          + "delegate outlet and any late NSApp.delegate assignment. "
          + "See docs/handoff/MACOS_APPDELEGATE_LIFECYCLE_20260809.md"
      )
      #if DEBUG
      assertionFailure(
        "applicationDidFinishLaunching did not run within \(Int(deadlineSeconds))s"
      )
      #endif
    }
  }

  static func recordDidFinishLaunching() {
    lock.lock()
    didFinishLaunchingRan = true
    lock.unlock()
    WinsAppLifecycle.note(
      "applicationDidFinishLaunching ENTER -- launch watchdog disarmed"
    )
  }
}

// ---------------------------------------------------------------------------
// WinsMacPostureSourceGuard -- fails loudly if the tunnel posture source is
// missing, or has drifted from the ruling, at launch.
//
// The shipping `enforceRoutes` posture lives in ONE place, `WinsMacRoutePosture`
// (macos/Runner/RouteAudit.swift), and it is a RULED INVARIANT registered in
// docs/rulings/RULINGS.lock. `tools/verify_rulings.sh` asserts the source still
// assigns that constant at merge/release time, but nothing asserted it at
// RUNTIME. On 2026-08-10 a lane silently reverted the posture to `false` and the
// tree carried an open route-injection decloak for a day with every lane check
// green; only `verify_rulings.sh` (a merge gate) ever caught it, and only after
// it was detected by hand.
//
// This guard makes the same failure LOUD at launch instead of silent: if the
// posture source is missing at launch, or reports a value that no longer matches
// the ruling, `applicationDidFinishLaunching` emits a `WINSLIFECYCLE FAULT` --
// the exact line `tools/verify_macos_app_lifecycle.sh` fails on. A healthy
// launch emits a plain note, never a fault.
//
// The source is injected as `() -> Bool?` so the guard is a pure function the
// unit tests can drive: nil is "the source is missing", a value different from
// the ruling is "the ruled invariant was silently reverted". The live launch
// path supplies `{ WinsMacRoutePosture.enforceRoutes }`.
// ---------------------------------------------------------------------------
enum WinsMacPostureSourceGuard {
  /// The ruled shipping value the source must report. This mirrors the REQUIRE
  /// entry in docs/rulings/RULINGS.lock; it is a launch-time CHECK of the
  /// ruling, not a re-definition of the source (`WinsMacRoutePosture` remains
  /// the single definition).
  static let ruledEnforceRoutes = true

  enum Result: Equatable {
    case present               // source present and matches the ruling
    case missing               // source is absent at launch
    case driftedFromRuling(Bool) // source present but disagrees with the ruling

    var isOkay: Bool { self == .present }
  }

  @discardableResult
  static func validateLaunchPostureSource(source: () -> Bool?) -> Result {
    guard let enforce = source() else {
      WinsAppLifecycle.fault(
        "tunnel posture source (WinsMacRoutePosture) is MISSING at launch. "
          + "The ruled route posture cannot be applied; the tunnel could establish "
          + "without enforcement. See docs/rulings/RULINGS.lock."
      )
      return .missing
    }
    guard enforce == ruledEnforceRoutes else {
      WinsAppLifecycle.fault(
        "tunnel posture source drifted from ruling: enforceRoutes=\(enforce) "
          + "(ruled \(ruledEnforceRoutes)). A lane silently reverted the ruled "
          + "posture. See docs/rulings/RULINGS.lock."
      )
      return .driftedFromRuling(enforce)
    }
    WinsAppLifecycle.note(
      "tunnel posture source present and matches ruling: enforceRoutes=\(enforce)"
    )
    return .present
  }
}

@main
class AppDelegate: FlutterAppDelegate {
  override init() {
    super.init()
    WinsMacLaunchWatchdog.arm()
  }

  override func applicationDidFinishLaunching(_ notification: Notification) {
    // FIRST statement, before any guard, so the watchdog records the method
    // being entered and not merely the method completing.
    WinsMacLaunchWatchdog.recordDidFinishLaunching()

    // POSTURE-SOURCE GUARD, LAUNCH PATH. Fails loudly (a `WINSLIFECYCLE FAULT`
    // line, which tools/verify_macos_app_lifecycle.sh fails on) if the tunnel
    // posture source `WinsMacRoutePosture` is missing at launch or has drifted
    // from the ruling -- rather than silently continuing the launch. Placed
    // deliberately before the Flutter window finishes launching: the guard must
    // not depend on the engine having started, and a healthy launch must log its
    // note before the engine can block the main thread.
    WinsMacPostureSourceGuard.validateLaunchPostureSource(
      source: { WinsMacRoutePosture.enforceRoutes }
    )

    // ROUTE-AUDIT, LAUNCH PATH. Emit a baseline posture line under the
    // `org.winsvpn.app.routeaudit` subsystem so an audit record exists on every
    // launch, before any PacketTunnelProvider can start. This is deliberately
    // placed before the Flutter window finishes launching: the baseline line
    // must not depend on the engine having finished starting. At this point
    // no config has been parsed and no /32 carve-out is installed, so the
    // exclusions legitimately read `none`; the `enforce` value is the shipping
    // posture this build will apply on connect (`WinsMacRoutePosture`, the same
    // single source MainFlutterWindow.startTunnel sets
    // `tunnelProtocol.enforceRoutes` from). The connect path emits a SECOND,
    // fully-resolved line (the actual exclusion route) immediately before
    // `startVPNTunnel`. This is a record of the posture, never a claim that it
    // carries.
    RouteAudit.log(
      enforceRoutes: WinsMacRoutePosture.enforceRoutes,
      excludedRoutes: []
    )

    DispatchQueue.main.async { [weak self] in
      self?.ensureMainWindowVisible()
    }
  }

  override func applicationShouldHandleReopen(
    _ sender: NSApplication,
    hasVisibleWindows flag: Bool
  ) -> Bool {
    ensureMainWindowVisible()
    return true
  }

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return true
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }

  private func ensureMainWindowVisible() {
    if let window = NSApp.windows.first(where: { window in
      window is MainFlutterWindow || window.contentViewController is FlutterViewController
    }) {
      show(window)
      return
    }

    let screenFrame = NSScreen.main?.visibleFrame
      ?? NSRect(x: 0, y: 0, width: 980, height: 720)
    let width = min(980, screenFrame.width * 0.92)
    let height = min(720, screenFrame.height * 0.92)
    let frame = NSRect(
      x: screenFrame.midX - width / 2,
      y: screenFrame.midY - height / 2,
      width: width,
      height: height
    )
    let window = MainFlutterWindow(
      contentRect: frame,
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered,
      defer: false
    )
    window.title = "Win's VPN"
    window.minSize = NSSize(width: 360, height: 520)

    let flutterViewController = FlutterViewController()
    window.contentViewController = flutterViewController
    RegisterGeneratedPlugins(registry: flutterViewController)
    WinsMacOSTunnelBridge.register(with: flutterViewController.engine.binaryMessenger)
    show(window)
  }

  private func show(_ window: NSWindow) {
    window.setIsVisible(true)
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }
}

#if DEBUG
// ---------------------------------------------------------------------------
// WinsNECPPostureProbe -- LAB INSTRUMENT for the macOS NECP admission question.
//
// COMPILED OUT OF RELEASE ON PURPOSE. It can rewrite the saved VPN routing
// posture from a file dropped in the app group container, which is exactly the
// shape of harness this repo has twice had to remove from a shipping build.
// Keep it behind `#if DEBUG`; do not give it a UI or method-channel entry.
//
// WHY THIS EXISTS. `MainFlutterWindow.swift` sets `enforceRoutes` and
// `excludeLocalNetworks = true` on the tunnel protocol, and both are baked into
// the SAVED NetworkExtension configuration -- editing the source changes
// nothing until some process re-saves that configuration. (The enforceRoutes
// value is a measured posture decision recorded in
// `WINN3_MACOS_CARRIAGE_FIX_20260810_bld_mac_routes.md`; do not pin it here.)
// The only writer today
// is the Flutter connect path, which needs the hub, a PIN and the login flow to
// reach. This probe re-saves ONLY those two booleans on the manager that is
// already there, leaving `providerConfiguration`, `providerBundleIdentifier`,
// `serverAddress` and every other field exactly as the connect path last wrote
// them, so a measurement taken after it varies one thing and not a bundle.
//
// It carries no secret, reads no key material, and writes only a posture
// report. It is unreachable unless `WINS_NECP_POSTURE` is set in the
// environment, which a Finder/LaunchServices launch cannot do; it must never be
// given a UI affordance or a method-channel entry point.
//
// Usage:  WINS_NECP_POSTURE='enforce=0,excludelocal=1' "…/Win's VPN.app/Contents/MacOS/Win's VPN"
// Report: <app group>/Tunnel/necp_posture_probe.json
// ---------------------------------------------------------------------------
// WinsNECPPosturePreferences -- the persistence seam for the re-save routine.
//
// The launch-path probe today calls `NETunnelProviderManager.loadAllFromPreferences`
// / `saveToPreferences` directly, so the routine itself is not drivable from an
// XCTest: section 19 runs with `CODE_SIGNING_ALLOWED=NO` (no NE daemon access)
// and the probe's launch wrapper ends in `exit(0)`. Splitting the *persistence*
// behind this protocol lets `macos/RunnerTests/RunnerTests.swift` drive the SAME
// routine with an in-memory store and assert that a requested `enforceRoutes =
// true` round-trips to `after_enforce_routes == true` on the reloaded
// `NETunnelProviderProtocol` -- without the daemon, without signing, and without
// touching the app-group container. The live store below is what the launch
// path uses, so production behaviour is unchanged (same two NE calls, same
// order, same report keys).
// ---------------------------------------------------------------------------
protocol WinsNECPPosturePreferences: AnyObject {
  func loadAll(completion: @escaping (Result<[NETunnelProviderManager], Error>) -> Void)
  func save(_ manager: NETunnelProviderManager, completion: @escaping (Result<Void, Error>) -> Void)
}

final class LiveWinsNECPPosturePreferencesStore: WinsNECPPosturePreferences {
  func loadAll(completion: @escaping (Result<[NETunnelProviderManager], Error>) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error {
        completion(.failure(error))
        return
      }
      completion(.success(managers ?? []))
    }
  }

  func save(_ manager: NETunnelProviderManager, completion: @escaping (Result<Void, Error>) -> Void) {
    manager.saveToPreferences { error in
      if let error {
        completion(.failure(error))
        return
      }
      completion(.success(()))
    }
  }
}

// ---------------------------------------------------------------------------
enum WinsNECPPostureProbe {
  private static let requestVariable = "WINS_NECP_POSTURE"
  private static let appGroupIdentifier = "5YT8H4U72M.group.org.winsvpn.app"
  private static let providerBundleIdentifier = "org.winsvpn.app.PacketTunnel"

  /// The request may arrive either in the environment (terminal launch) or as a
  /// one-line file in the app group container. The file form exists because a
  /// sandboxed, LaunchServices-started app does not reliably inherit a shell's
  /// environment, and a probe that silently declines to run is indistinguishable
  /// from a probe that ran and found nothing.
  private static func requestText() -> (text: String, source: String)? {
    let environment = ProcessInfo.processInfo.environment
    if let fromEnvironment = environment[requestVariable],
       !fromEnvironment.trimmingCharacters(in: .whitespaces).isEmpty {
      return (fromEnvironment, "environment")
    }
    guard let container = FileManager.default.containerURL(
      forSecurityApplicationGroupIdentifier: appGroupIdentifier
    ) else {
      return nil
    }
    let requestURL = container
      .appendingPathComponent("Tunnel", isDirectory: true)
      .appendingPathComponent("necp_posture_request.txt")
    guard let contents = try? String(contentsOf: requestURL, encoding: .utf8) else {
      return nil
    }
    let trimmed = contents.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : (trimmed, "file")
  }

  @discardableResult
  static func handleLaunchIfRequested() -> Bool {
    guard let (request, requestSource) = requestText() else {
      NSLog("WINS_NECP_POSTURE probe: no request (inert launch)")
      return false
    }
    NSLog("WINS_NECP_POSTURE probe: request=%@ source=%@", request, requestSource)

    let requested = parse(request)
    var report: [String: Any] = [
      "request": request,
      "request_source": requestSource,
      "requested_enforce_routes": requested.enforceRoutes ?? NSNull(),
      "requested_exclude_local_networks": requested.excludeLocalNetworks ?? NSNull(),
      "started_at": ISO8601DateFormatter().string(from: Date())
    ]

    reSaveAndReport(
      requestedEnforceRoutes: requested.enforceRoutes,
      requestedExcludeLocalNetworks: requested.excludeLocalNetworks,
      providerBundleIdentifier: providerBundleIdentifier,
      preferences: LiveWinsNECPPosturePreferencesStore(),
      baseReport: report
    ) { completed in
      report = completed
      finish(report)
    }

    // A probe launch that never gets a NetworkExtension reply must still end,
    // and must end saying so rather than sitting on the owner's dock.
    DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
      report["stage"] = "timeout"
      finish(report)
    }
    return true
  }

  /// The re-save routine, and the thing the macOS XCTest drives.
  ///
  /// Given a requested `enforceRoutes` / `excludeLocalNetworks` pair and a
  /// persistence `preferences` store, it loads all managers, finds the one whose
  /// protocol carries `providerBundleIdentifier`, records `before_*`, mutates
  /// ONLY the requested booleans, saves, reloads through the SAME store (never
  /// trusts the in-memory object), and records `after_*`. `baseReport` is the
  /// launch metadata the caller started (request/request_source/requested_*/
  /// started_at); the completion is handed the same report with `before_*`,
  /// `manager_count`, `stage`, `error` and `after_*` added. Report keys are
  /// identical to the pre-seam launch path so production output is unchanged.
  static func reSaveAndReport(
    requestedEnforceRoutes: Bool?,
    requestedExcludeLocalNetworks: Bool?,
    providerBundleIdentifier: String,
    preferences: WinsNECPPosturePreferences,
    baseReport: [String: Any],
    completion: @escaping ([String: Any]) -> Void
  ) {
    var report = baseReport
    // Ensure the requested posture is recorded in the report even when the
    // caller supplies an empty baseReport (as the XCTest does). The live
    // launch path already puts these keys into baseReport, so this preserves
    // production output while making the seam drivable.
    if report["requested_enforce_routes"] == nil {
      report["requested_enforce_routes"] = requestedEnforceRoutes ?? NSNull()
    }
    if report["requested_exclude_local_networks"] == nil {
      report["requested_exclude_local_networks"] = requestedExcludeLocalNetworks ?? NSNull()
    }

    preferences.loadAll { loadResult in
      let candidates: [NETunnelProviderManager]
      switch loadResult {
      case .failure(let loadError):
        report["stage"] = "load_failed"
        report["error"] = String(describing: loadError)
        completion(report)
        return
      case .success(let loaded):
        candidates = loaded
      }

      report["manager_count"] = candidates.count
      guard let manager = candidates.first(where: { manager in
        (manager.protocolConfiguration as? NETunnelProviderProtocol)?
          .providerBundleIdentifier == providerBundleIdentifier
      }),
        let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
        report["stage"] = "no_matching_manager"
        completion(report)
        return
      }

      report["before_enforce_routes"] = tunnelProtocol.enforceRoutes
      report["before_exclude_local_networks"] = tunnelProtocol.excludeLocalNetworks
      report["before_include_all_networks"] = tunnelProtocol.includeAllNetworks
      report["before_provider_configuration_keys"] =
        Array((tunnelProtocol.providerConfiguration ?? [:]).keys).sorted()

      // The ONLY mutation. Everything else on this manager is left as loaded.
      if let enforceRoutes = requestedEnforceRoutes {
        tunnelProtocol.enforceRoutes = enforceRoutes
      }
      if let excludeLocalNetworks = requestedExcludeLocalNetworks {
        tunnelProtocol.excludeLocalNetworks = excludeLocalNetworks
      }
      manager.protocolConfiguration = tunnelProtocol
      manager.isEnabled = true

      preferences.save(manager) { saveResult in
        switch saveResult {
        case .failure(let saveError):
          report["stage"] = "save_failed"
          report["error"] = String(describing: saveError)
          completion(report)
          return
        case .success:
          break
        }

        // Re-read rather than trust the in-memory object: "it took effect" is
        // the claim under test, and a save that NetworkExtension silently
        // normalised would otherwise read as a success.
        preferences.loadAll { reloadResult in
          switch reloadResult {
          case .failure(let reloadError):
            report["stage"] = "saved_reload_failed"
            report["error"] = String(describing: reloadError)
          case .success(let reloaded):
            report["stage"] = "saved"
            if let confirmed = reloaded.compactMap({
              $0.protocolConfiguration as? NETunnelProviderProtocol
            }).first(where: { $0.providerBundleIdentifier == providerBundleIdentifier }) {
              report["after_enforce_routes"] = confirmed.enforceRoutes
              report["after_exclude_local_networks"] = confirmed.excludeLocalNetworks
              report["after_include_all_networks"] = confirmed.includeAllNetworks
              report["after_provider_configuration_keys"] =
                Array((confirmed.providerConfiguration ?? [:]).keys).sorted()
            }
          }
          completion(report)
        }
      }
    }
  }

  private static func parse(_ request: String) -> (enforceRoutes: Bool?, excludeLocalNetworks: Bool?) {
    var enforceRoutes: Bool?
    var excludeLocalNetworks: Bool?
    for field in request.split(separator: ",") {
      let pair = field.split(separator: "=", maxSplits: 1)
      guard pair.count == 2 else { continue }
      let key = pair[0].trimmingCharacters(in: .whitespaces).lowercased()
      let value = (pair[1].trimmingCharacters(in: .whitespaces) as NSString).boolValue
      switch key {
      case "enforce", "enforceroutes": enforceRoutes = value
      case "excludelocal", "excludelocalnetworks": excludeLocalNetworks = value
      default: continue
      }
    }
    return (enforceRoutes, excludeLocalNetworks)
  }

  private static var finished = false

  private static func finish(_ report: [String: Any]) {
    DispatchQueue.main.async {
      guard !finished else { return }
      finished = true
      var payload = report
      payload["finished_at"] = ISO8601DateFormatter().string(from: Date())
      let data = (try? JSONSerialization.data(
        withJSONObject: payload,
        options: [.prettyPrinted, .sortedKeys]
      )) ?? Data()
      // The whole payload goes to the log first. A sandbox denial on the
      // container write must not be able to swallow the measurement.
      NSLog(
        "WINS_NECP_POSTURE probe result: %@",
        String(data: data, encoding: .utf8) ?? "<unserialisable>"
      )
      if let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: appGroupIdentifier
      ) {
        let directory = container.appendingPathComponent("Tunnel", isDirectory: true)
        try? FileManager.default.createDirectory(
          at: directory,
          withIntermediateDirectories: true
        )
        try? data.write(
          to: directory.appendingPathComponent("necp_posture_probe.json"),
          options: .atomic
        )
        // Consume the request so the next ordinary launch is inert.
        try? FileManager.default.removeItem(
          at: directory.appendingPathComponent("necp_posture_request.txt")
        )
      }
      // `NSApp.terminate` is a request the Flutter engine may defer; the write
      // above is synchronous and atomic, so leaving immediately is safe and
      // keeps a probe launch from lingering on the owner's dock.
      exit(0)
    }
  }
}
#endif
