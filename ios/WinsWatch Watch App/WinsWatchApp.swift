import SwiftUI
import WatchKit
#if DEBUG
import WatchConnectivity
#endif

/// The watchOS application delegate. The modern SwiftUI watch app routes the
/// WatchKit application lifecycle through this object via
/// WKApplicationDelegate Adaptor, mirroring how the iOS app wires
/// UIApplicationDelegate Adaptor. Keeping a real `WKApplicationDelegate`
/// means the Watch app gets the standard `applicationDidFinishLaunching`
/// hook without falling back to the deprecated `WKInterfaceController`-centric
/// lifecycle.
final class WinsWatchAppDelegate: NSObject, WKApplicationDelegate {

  /// Called exactly once after the WatchKit application has been launched.
  func applicationDidFinishLaunching() {
    // The heavy lifting (phone state, tunnel config) lives on the iPhone; the
    // watch only needs to surface a connect/disconnect toggle, so there is
    // nothing heavyweight to set up here.
  }
}

/// The entire watch app: a connect/disconnect toggle and a country list.
///
/// There is deliberately no settings screen, no account screen and no
/// diagnostics. Anything that needs a credential, a key or the tunnel
/// configuration belongs on the iPhone, which is also the only place iOS will
/// present VPN configuration approval.
@main
struct WinsWatchApp: App {
  @WKApplicationDelegateAdaptor(WinsWatchAppDelegate.self) private var appDelegate
  @StateObject private var phone = PhoneLink()
  @Environment(\.scenePhase) private var scenePhase

  var body: some Scene {
    WindowGroup {
      ContentView(phone: phone)
      #if DEBUG
        .onAppear { WatchCompanionSmoke.startIfRequested(phone: phone) }
      #endif
    }
    .onChange(of: scenePhase) { newPhase in
      // Returning to the app after the phone changed state elsewhere must not
      // show a stale toggle.
      if newPhase == .active {
        phone.refresh()
      }
    }
  }
}

#if DEBUG
/// Debug-only Watch companion smoke (R22 Y3 D2, part 2).
///
/// Compiled only where DEBUG is defined, which for this target is its Debug
/// configuration alone, so Release and Profile builds (and therefore the
/// shipped IPA) contain none of it; tools/test_apple_watch_companion_smoke.py
/// and the release contamination gate check that. Even in a Debug build it is
/// inert unless the app is launched with
/// `--wins-watch-companion-smoke <32 lowercase hex nonce>`.
///
/// It records what WatchConnectivity reports on the watch side, the state the
/// shipping `PhoneLink` reached, and whether the phone app answered a
/// `requestState` (the same message `PhoneLink.refresh()` already sends), then
/// writes that as JSON to Documents/wins_watch_companion_smoke.json in this
/// app's own data container. tools/apple_watch_companion_smoke.py reads it
/// with `xcrun simctl get_app_container`. Only the shape of a phone snapshot is
/// recorded (key names, protocol version, timestamp, tunnel status), never
/// its country list.
enum WatchCompanionSmoke {
  static let argument = "--wins-watch-companion-smoke"
  static let fileName = "wins_watch_companion_smoke.json"
  static let contract = "wins-watch-companion-smoke-observation-v1"
  static let deadlineSeconds: TimeInterval = 90

  private static var active: Runner?

  static func startIfRequested(phone: PhoneLink) {
    guard active == nil else { return }
    let arguments = ProcessInfo.processInfo.arguments
    guard let index = arguments.firstIndex(of: argument), index + 1 < arguments.count else {
      return
    }
    let nonce = arguments[index + 1]
    guard nonce.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else {
      return
    }
    let runner = Runner(nonce: nonce, phone: phone)
    active = runner
    runner.tick()
  }

  private static func name(_ state: WCSessionActivationState) -> String {
    switch state {
    case .notActivated: return "notActivated"
    case .inactive: return "inactive"
    case .activated: return "activated"
    @unknown default: return "unknown"
    }
  }

  private static func name(_ link: PhoneLinkState) -> String {
    switch link {
    case .connecting: return "connecting"
    case .linked: return "linked"
    case .unreachable: return "unreachable"
    }
  }

  private static func shape(_ payload: [String: Any]) -> [String: Any] {
    var shape: [String: Any] = [
      "keys": payload.keys.sorted(),
      "present": !payload.isEmpty,
    ]
    if let version = payload[WatchLink.Key.version] as? NSNumber {
      shape["protocol_version"] = version.intValue
    }
    if let updatedAt = payload["updatedAt"] as? NSNumber {
      shape["updated_at_ms"] = updatedAt.doubleValue
    }
    if let status = payload["status"] as? String {
      shape["status"] = status
    }
    return shape
  }

  private static func utc(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
  }

  /// Main-thread only: every mutation happens in `tick()` or on a block the
  /// reply and error handlers hop onto the main queue.
  private final class Runner {
    let nonce: String
    weak var phone: PhoneLink?
    let started = Date()
    var finished = false
    var activationStatesSeen: [String] = []
    var reachableEver = false
    var companionInstalledEver = false
    var probeAttempts = 0
    var probeInFlight = false
    var probeSentAt: Date?
    var nextProbeAt = Date.distantPast
    var probeErrors: [String] = []
    var reply: [String: Any]?
    var replyRoundTripMs: Double?
    var linkedSeen = false

    init(nonce: String, phone: PhoneLink) {
      self.nonce = nonce
      self.phone = phone
    }

    func tick() {
      guard !finished else { return }
      let session: WCSession? = WCSession.isSupported() ? WCSession.default : nil
      if let session {
        let state = WatchCompanionSmoke.name(session.activationState)
        if activationStatesSeen.last != state {
          activationStatesSeen.append(state)
        }
        // Reachability and installation are only meaningful (and only read
        // without a WatchConnectivity error) once the session is activated.
        if session.activationState == .activated {
          reachableEver = reachableEver || session.isReachable
          companionInstalledEver = companionInstalledEver || session.isCompanionAppInstalled
          if session.isReachable, reply == nil, !probeInFlight, probeAttempts < 12,
            Date() >= nextProbeAt
          {
            probe(session)
          }
        }
      }
      linkedSeen = linkedSeen || phone?.link == .linked
      // Done once the shipping PhoneLink holds phone state at least as new as
      // the reply: its own 4 s request timeout may still mark the link
      // unreachable on a slow simulator host, which is recorded, not judged.
      let replyUpdatedAt = (reply?["updatedAt"] as? NSNumber)?.doubleValue ?? 0
      let current = phone.map { replyUpdatedAt > 0 && $0.snapshot.updatedAt >= replyUpdatedAt } ?? false
      let elapsed = Date().timeIntervalSince(started)
      let done = (reply != nil && current) || elapsed >= WatchCompanionSmoke.deadlineSeconds
      write(session: session, complete: done)
      if done {
        finished = true
        return
      }
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [self] in
        tick()
      }
    }

    private func probe(_ session: WCSession) {
      probeInFlight = true
      probeAttempts += 1
      probeSentAt = Date()
      session.sendMessage(
        WatchLink.message(.requestState),
        replyHandler: { [self] payload in
          DispatchQueue.main.async { [self] in
            probeInFlight = false
            reply = payload
            if let sent = probeSentAt {
              replyRoundTripMs = Date().timeIntervalSince(sent) * 1000
            }
          }
        },
        errorHandler: { [self] error in
          let nsError = error as NSError
          DispatchQueue.main.async { [self] in
            probeInFlight = false
            probeErrors.append("\(nsError.domain):\(nsError.code)")
            nextProbeAt = Date().addingTimeInterval(2)
          }
        }
      )
    }

    private func write(session: WCSession?, complete: Bool) {
      let now = Date()
      var probe: [String: Any] = [
        "attempts": probeAttempts,
        "errors": probeErrors,
        "reply_received": reply != nil,
      ]
      if let reply {
        probe["reply"] = WatchCompanionSmoke.shape(reply)
      }
      if let replyRoundTripMs {
        probe["round_trip_ms"] = replyRoundTripMs
      }
      var phoneLink: [String: Any] = ["observed": phone != nil, "linked_seen": linkedSeen]
      if let phone {
        phoneLink["link"] = WatchCompanionSmoke.name(phone.link)
        phoneLink["snapshot_updated_at_ms"] = phone.snapshot.updatedAt
        phoneLink["snapshot_status"] = phone.snapshot.status.rawValue
      }
      var record: [String: Any] = [
        "contract": WatchCompanionSmoke.contract,
        "nonce": nonce,
        "complete": complete,
        "started_at_utc": WatchCompanionSmoke.utc(started),
        "written_at_utc": WatchCompanionSmoke.utc(now),
        "elapsed_ms": now.timeIntervalSince(started) * 1000,
        "watch_bundle_id": Bundle.main.bundleIdentifier ?? "",
        "companion_bundle_id":
          Bundle.main.object(forInfoDictionaryKey: "WKCompanionAppBundleIdentifier") as? String ?? "",
        "wc_supported": session != nil,
        "activation_states_seen": activationStatesSeen,
        "reachable_ever": reachableEver,
        "companion_app_installed_ever": companionInstalledEver,
        "probe": probe,
        "phone_link": phoneLink,
      ]
      if let session {
        let activated = session.activationState == .activated
        record["activation_state"] = WatchCompanionSmoke.name(session.activationState)
        record["is_reachable"] = activated && session.isReachable
        record["is_companion_app_installed"] = activated && session.isCompanionAppInstalled
        record["application_context"] = WatchCompanionSmoke.shape(
          activated ? session.receivedApplicationContext : [:])
      }
      guard
        let directory = FileManager.default.urls(
          for: .documentDirectory, in: .userDomainMask
        ).first,
        let data = try? JSONSerialization.data(
          withJSONObject: record, options: [.sortedKeys, .prettyPrinted])
      else { return }
      try? FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true)
      try? data.write(
        to: directory.appendingPathComponent(WatchCompanionSmoke.fileName), options: .atomic)
    }
  }
}
#endif
