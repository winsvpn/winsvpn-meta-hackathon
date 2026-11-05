import Foundation
import WatchConnectivity

/// iPhone half of the Apple Watch remote control.
///
/// Deliberately Flutter-free so it can be reasoned about (and compiled) on its
/// own; `WatchBridgeRegistration.swift` is the only place that knows about
/// method channels.
///
/// Design constraints this file exists to enforce:
///
///  - The watch is a remote control, never a second VPN client. It sends intent
///    and renders state. Nothing here reads the keychain, the App Group tunnel
///    configuration, or `NETunnelProviderManager`; the only thing that crosses
///    the link is whatever Dart chose to publish.
///  - Every action routes back into the phone's own connect/disconnect path.
///    In particular this file never calls into NetworkExtension directly, so it
///    cannot bypass the approval iOS requires the user to give on the phone.
///
/// The bridge is bonded to the winn/3 status surface (`WinsWinn3` /
/// `WinsWinn3PromotionGate`): it owns the `carrier` and `state` key names on
/// this side of the link and forwards the values the phone publishes verbatim,
/// so the watch reflects the session's carrier and gate state through one
/// native contract instead of a Dart string. A missing value is surfaced as an
/// empty string, never a guessed carrier or state -- the watch renders nothing
/// until a phone build actually publishes one.
final class WatchSessionBridge: NSObject {

  /// Invoked on the main thread when the watch asks for something.
  /// `command` is one of connect / disconnect / selectCountry.
  typealias CommandHandler = (_ command: String, _ slug: String) -> Void

  static let shared = WatchSessionBridge()

  private static let protocolVersion = 1
  private static let commandKey = "command"
  private static let slugKey = "slug"
  private static let requestStateCommand = "requestState"

  private let lock = NSLock()
  private var commandHandler: CommandHandler?
  private var lastPublishedPayload: String?
  private var lastSnapshot: [String: Any]?

  // MARK: - winn/3 status surface keys

  /// The phone-to-watch key names for the winn/3 status surface, owned here so
  /// "watch reflects session carrier/state" has exactly one native contract.
  /// The carrier wire value is the winn/3 host contract's own
  /// `WinsWinn3.carrierName`; the bridge never restates that literal, it only
  /// forwards what the phone publishes.
  private enum Winn3Carrier {
    static let carrierKey = "carrier"
    static let stateKey = "state"

    /// Canonical absent values: an empty carrier/state is "the phone has not
    /// published these", never a guessed value.
    static let absent = (carrier: "", state: "")
  }

  /// The winn/3 carrier/state the phone published, or the canonical absent
  /// pair.
  private func winn3CarrierState(from snapshot: [String: Any]) -> (carrier: String, state: String) {
    let carrier = (snapshot[Winn3Carrier.carrierKey] as? String ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let state = (snapshot[Winn3Carrier.stateKey] as? String ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    if carrier.isEmpty && state.isEmpty { return Winn3Carrier.absent }
    return (carrier, state)
  }

  private var session: WCSession? {
    WCSession.isSupported() ? WCSession.default : nil
  }

  private override init() {
    super.init()
  }

  /// Called once, when the Flutter engine comes up.
  func start(commandHandler: @escaping CommandHandler) {
    lock.lock()
    self.commandHandler = commandHandler
    lock.unlock()

    guard let session else { return }
    session.delegate = self
    if session.activationState != .activated {
      session.activate()
    }
  }

  /// Publish current state.
  ///
  /// - Parameter payload: the semantic JSON Dart produced -- status, detail,
  ///   selectedSlug, countries, canConnect. Nothing else is added except a
  ///   publish timestamp.
  /// - Returns: true when this changed something and was pushed to the watch.
  @discardableResult
  func publish(payload: String) -> Bool {
    lock.lock()
    let unchanged = (payload == lastPublishedPayload)
    if !unchanged {
      lastPublishedPayload = payload
    }
    lock.unlock()
    if unchanged { return false }

    guard
      let data = payload.data(using: .utf8),
      var snapshot = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else {
      NSLog("[WinsWatch] Rejected malformed watch payload from Dart.")
      return false
    }

    snapshot["v"] = Self.protocolVersion
    snapshot["updatedAt"] = Date().timeIntervalSince1970 * 1000

    // Bond the winn/3 status surface into the pushed snapshot: forward the
    // carrier/state the phone published (empty when it did not), so the watch
    // reflects the session's carrier and gate state on the native contract.
    let winn3 = winn3CarrierState(from: snapshot)
    snapshot[Winn3Carrier.carrierKey] = winn3.carrier
    snapshot[Winn3Carrier.stateKey] = winn3.state

    lock.lock()
    lastSnapshot = snapshot
    lock.unlock()

    push(snapshot)
    return true
  }

  private func push(_ snapshot: [String: Any]) {
    guard let session, session.activationState == .activated else { return }
    // Retained, so re-opening the watch app shows last-known state rather than
    // a spinner.
    do {
      try session.updateApplicationContext(snapshot)
    } catch {
      // MUST STAY `NSLog`, and the reason is the timing rather than the words.
      // This string names no tunnel state -- but `push` is only reached from
      // `publish(payload:)` on a payload that CHANGED, and that payload is the
      // tunnel status. So a legible line here is a timestamp of a VPN state
      // transition regardless of what it says, and a burst of them is a
      // connection history. Judge the existence of a line, not only its text.
      // `NSLog` renders the whole message `<private>`; an `os_log` literal
      // would be public whatever the privacy qualifiers on its arguments
      // (measured 20260810, matrix in macos/Runner/AppDelegate.swift).
      // See docs/handoff/APPLE_NSLOG_REDACTION_AUDIT_20260810.md.
      NSLog("[WinsWatch] Application context update failed.")
    }
    // Immediate, so a tap on the watch feels instant when the link is up.
    if session.isReachable {
      session.sendMessage(snapshot, replyHandler: nil, errorHandler: nil)
    }
  }

  /// State to answer a watch request with.
  ///
  /// When Dart has not published yet -- for instance the app was launched into
  /// the background by WatchConnectivity and the widget tree has not built --
  /// this reports "cannot act" rather than guessing at a tunnel state it has no
  /// authority over.
  private func currentSnapshot() -> [String: Any] {
    lock.lock()
    let snapshot = lastSnapshot
    lock.unlock()
    return snapshot ?? [
      "v": Self.protocolVersion,
      "status": "unknown",
      "detail": "",
      "selectedSlug": "",
      "countries": [],
      "canConnect": false,
      Winn3Carrier.carrierKey: Winn3Carrier.absent.carrier,
      Winn3Carrier.stateKey: Winn3Carrier.absent.state,
      "updatedAt": Date().timeIntervalSince1970 * 1000,
    ]
  }

  private func handle(message: [String: Any]) {
    let command = (message[Self.commandKey] as? String ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !command.isEmpty, command != Self.requestStateCommand else { return }

    let slug = (message[Self.slugKey] as? String ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)

    lock.lock()
    let handler = commandHandler
    lock.unlock()
    guard let handler else { return }

    DispatchQueue.main.async {
      handler(command, slug)
    }
  }
}

extension WatchSessionBridge: WCSessionDelegate {

  func session(
    _ session: WCSession,
    activationDidCompleteWith activationState: WCSessionActivationState,
    error: Error?
  ) {
    guard error == nil, activationState == .activated else { return }
    push(currentSnapshot())
  }

  func sessionDidBecomeInactive(_ session: WCSession) {}

  func sessionDidDeactivate(_ session: WCSession) {
    // Re-activate for the newly paired watch, otherwise the bridge goes quiet
    // after a watch swap until the app is relaunched.
    session.activate()
  }

  func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
    handle(message: message)
  }

  func session(
    _ session: WCSession,
    didReceiveMessage message: [String: Any],
    replyHandler: @escaping ([String: Any]) -> Void
  ) {
    // Reply first, with state as it stands. The result of the command arrives
    // as its own push once Dart has actually applied it -- replying late would
    // risk the reply timing out and the watch showing a dead button.
    replyHandler(currentSnapshot())
    handle(message: message)
  }

  func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any] = [:]) {
    // Queued (non-interactive) deliveries can arrive arbitrarily late. A
    // state-changing command must only ever come from a live sendMessage, so
    // queued ones are dropped; the watch refreshes state on its next launch.
    _ = userInfo
  }

  func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
    // The watch does not send application contexts, but this delegate exists
    // for completeness if future use arises. Watch-to-phone commands arrive
    // via didReceiveMessage only.
  }
}
