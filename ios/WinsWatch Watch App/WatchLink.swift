import Foundation
import WatchConnectivity

/// The watch <-> phone wire contract.
///
/// Field names and values are identical to the Wear OS build
/// (`wear_os/app/src/main/kotlin/org/winsvpn/app/wear/WatchLink.kt`) and to the
/// phone's Dart publisher (`lib/watch_bridge.dart`), so there is one contract
/// to reason about across all three.
///
/// The watch sends intent and renders state. No account number, key, endpoint
/// or tunnel configuration crosses this link, and the watch persists nothing.
enum WatchLink {
  static let protocolVersion = 1

  enum Command: String {
    case connect
    case disconnect
    case selectCountry
    case requestState
  }

  enum Key {
    static let command = "command"
    static let slug = "slug"
    static let snapshot = "snapshot"
    static let version = "v"
  }

  static func message(_ command: Command, slug: String? = nil) -> [String: Any] {
    var payload: [String: Any] = [
      Key.version: protocolVersion,
      Key.command: command.rawValue,
    ]
    if let slug, !slug.isEmpty {
      payload[Key.slug] = slug
    }
    return payload
  }

  /// Whether the session is ready to carry an outgoing message.
  ///
  /// WCSession must be in `.activated` before any `sendMessage` or
  /// `transferUserInfo` is attempted. Callers must check this and return
  /// early when the session has not yet activated, matching the guard in
  /// `PhoneLink.send(_:slug:silent:)`.
  static func canSend(using session: WCSession?) -> Bool {
    guard let session else { return false }
    return session.activationState == .activated
  }

  /// Payload guarded by session activation. Returns nil when the session has
  /// not yet activated, so callers cannot send before the handshake completes.
  static func guardedMessage(
    _ command: Command,
    slug: String? = nil,
    using session: WCSession?
  ) -> [String: Any]? {
    guard canSend(using: session) else { return nil }
    return message(command, slug: slug)
  }
}

/// What the phone says its tunnel is doing.
enum TunnelStatus: String {
  case disconnected
  case connecting
  case connected
  case disconnecting
  case failed

  /// The VPN configuration has not been approved in iOS Settings.
  ///
  /// Apple requires that approval to be an explicit user gesture on the phone.
  /// A watch cannot grant it and must never attempt to automate it; the only
  /// correct behaviour here is to say so and stop.
  case permissionRequired

  case unknown

  init(wire: String?) {
    self = TunnelStatus(rawValue: wire ?? "") ?? .unknown
  }

  var isBusy: Bool {
    self == .connecting || self == .disconnecting
  }

  /// True when tapping the toggle should mean "stop", not "start".
  var isOnOrGoingOn: Bool {
    self == .connected || self == .connecting
  }
}

/// One selectable exit country, exactly as the phone already labels it.
struct WatchCountry: Identifiable, Equatable {
  let slug: String
  let name: String
  let flag: String
  /// Hub-reported load, 0...100 in steps of 5, or nil when unknown. Absent on
  /// every snapshot from a phone build that predates the field.
  var loadPct: Int? = nil
  /// When the PHONE received `loadPct`: whole seconds since the Unix epoch on
  /// the phone's clock, or nil. A figure without it is never shown.
  var loadAtSec: Int64? = nil

  var id: String { slug }

  /// Wire key, identical on the hub, the phone and Wear OS.
  static let loadPctKey = "load_pct"
  /// Wire key for `loadAtSec` (lib/watch_bridge.dart kWatchLoadAtKey).
  static let loadAtKey = "load_at"

  /// Plausible window for `load_at` in epoch seconds, checked on the raw
  /// value BEFORE any arithmetic (Round LC turn 2 found a value that wrapped
  /// when multiplied by 1000 on Wear). 1_600_000_000 is 2020-09-13, before this
  /// feature existed; 4_102_444_800 is 2100-01-01. Same bounds as Wear OS.
  static let minLoadAtSec: Int64 = 1_600_000_000
  static let maxLoadAtSec: Int64 = 4_102_444_800

  /// Total parser for `load_at`: an integral number inside the window, else nil.
  static func parseLoadAtSec(_ raw: Any?) -> Int64? {
    guard let number = raw as? NSNumber else { return nil }
    if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
    if CFNumberIsFloatType(number as CFNumber) { return nil }
    // An integer too large for Int64 arrives as a decimal NSNumber whose
    // int64Value is truncated; reject anything that does not round-trip.
    let value = number.int64Value
    guard NSNumber(value: value) == number else { return nil }
    return (minLoadAtSec...maxLoadAtSec).contains(value) ? value : nil
  }

  /// The one parser for `load_pct`. Total: anything that is not an integer in
  /// 0...100 on a step of 5 is nil: a string, a float, a bool, NSNull, a
  /// negative, over 100, off-step, or no key at all. It never traps, so one bad
  /// value can never cost the watch its country list.
  static func parseLoadPct(_ raw: Any?) -> Int? {
    guard let number = raw as? NSNumber else { return nil }
    // A JSON/plist bool arrives as an NSNumber and would otherwise read as 0/1.
    if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
    // Only integral encodings: a float such as 45.0 or 45.5 is malformed.
    if CFNumberIsFloatType(number as CFNumber) { return nil }
    // An integer too large for Int64 (for example 2^64) arrives as a decimal
    // NSNumber whose int64Value is truncated, possibly to a valid-looking 0;
    // reject anything that does not round-trip.
    let value = number.int64Value
    guard NSNumber(value: value) == number else { return nil }
    guard value >= 0, value <= 100, value % 5 == 0 else { return nil }
    return Int(value)
  }

  var display: String {
    [flag, name].filter { !$0.isEmpty }.joined(separator: " ")
  }
}

/// The whole of what the watch knows.
struct PhoneSnapshot: Equatable {
  var status: TunnelStatus
  var detail: String
  var selectedSlug: String
  var countries: [WatchCountry]

  /// Whether starting a tunnel or changing country will work right now. The
  /// phone owns tunnel configuration, so both are unavailable when the phone
  /// app cannot be reached.
  var canConnect: Bool
  var updatedAt: Double

  /// Monotonic time (ms, CLOCK_MONOTONIC, which keeps counting in sleep) when
  /// this snapshot arrived live from the phone, or nil for one restored from
  /// `receivedApplicationContext`, which the OS retains across launches. Set
  /// by PhoneLink, never parsed from the wire. See `LoadFreshness`.
  var arrivedAtMonotonicMs: Double? = nil

  /// This snapshot, marked as having arrived live just now.
  func arrivedLive(atMonotonicMs now: Double = LoadFreshness.monotonicNowMs()) -> PhoneSnapshot {
    var copy = self
    copy.arrivedAtMonotonicMs = now
    return copy
  }

  static let empty = PhoneSnapshot(
    status: .unknown,
    detail: "",
    selectedSlug: "",
    countries: [],
    canConnect: false,
    updatedAt: 0
  )

  var selectedCountry: WatchCountry? {
    countries.first { $0.slug == selectedSlug }
  }

  /// Tolerant by design: a snapshot from a newer phone build with extra fields
  /// must still render, and a malformed one must be discarded rather than
  /// crash the app.
  init?(payload: [String: Any]?) {
    guard let payload else { return nil }
    let rawCountries = payload["countries"] as? [[String: Any]] ?? []
    let parsed: [WatchCountry] = rawCountries.compactMap { item in
      let slug = (item["slug"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
      guard !slug.isEmpty else { return nil }
      let name = (item["name"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
      return WatchCountry(
        slug: slug,
        name: name.isEmpty ? slug : name,
        flag: (item["flag"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
        loadPct: WatchCountry.parseLoadPct(item[WatchCountry.loadPctKey]),
        loadAtSec: WatchCountry.parseLoadAtSec(item[WatchCountry.loadAtKey])
      )
    }
    self.status = TunnelStatus(wire: payload["status"] as? String)
    self.detail = (payload["detail"] as? String ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    self.selectedSlug = (payload["selectedSlug"] as? String ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    self.countries = parsed
    // Absent means "an older phone that only ever publishes when it can act".
    self.canConnect = payload["canConnect"] as? Bool ?? true
    self.updatedAt = (payload["updatedAt"] as? NSNumber)?.doubleValue ?? 0
  }

  private init(
    status: TunnelStatus,
    detail: String,
    selectedSlug: String,
    countries: [WatchCountry],
    canConnect: Bool,
    updatedAt: Double
  ) {
    self.status = status
    self.detail = detail
    self.selectedSlug = selectedSlug
    self.countries = countries
    self.canConnect = canConnect
    self.updatedAt = updatedAt
  }
}

/// Whether a country's load figure may be shown RIGHT NOW (Round LC OI-5).
///
/// Same rule as Wear OS (`LoadFreshness` in WatchLink.kt): shown for at most
/// `maxAgeMs` after the phone received it, never from a restored snapshot,
/// and never when `load_at` is in this watch's future. Age is the larger of a
/// skew-free estimate (phone-side age at publish plus monotonic time since
/// arrival) and the wall-clock age, so a clock problem can only make a figure
/// look older; both failing at once can fool it by at most the smaller of the
/// transit delay and the clock skew.
enum LoadFreshness {
  static let maxAgeMs: Double = 60_000

  static func monotonicNowMs() -> Double {
    Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000
  }

  static func wallNowMs() -> Double {
    Date().timeIntervalSince1970 * 1000
  }

  /// Age in ms, or nil (unknown). Every untrusted input is range-checked by
  /// comparison before any arithmetic: the load_at window, finiteness of the
  /// Double inputs, and "not after this watch's now" compared in whole SECONDS
  /// (0 s allowance), so the Int64 multiplication by 1000 cannot overflow; it
  /// is also done with multipliedReportingOverflow as a second guard. Results
  /// at or above `maxAgeMs` mean unknown; each term is checked against it
  /// before the one sum is formed.
  static func ageMs(
    _ country: WatchCountry, in snapshot: PhoneSnapshot,
    monotonicNowMs: Double, wallNowMs: Double
  ) -> Double? {
    guard country.loadPct != nil, let loadAtSec = country.loadAtSec,
      let arrivedAt = snapshot.arrivedAtMonotonicMs
    else { return nil }
    let updatedAt = snapshot.updatedAt
    guard (WatchCountry.minLoadAtSec...WatchCountry.maxLoadAtSec).contains(loadAtSec),
      updatedAt.isFinite, updatedAt > 0,
      wallNowMs.isFinite, wallNowMs > 0,
      monotonicNowMs.isFinite, arrivedAt.isFinite, arrivedAt >= 0, arrivedAt <= monotonicNowMs,
      Double(loadAtSec) <= (wallNowMs / 1000).rounded(.down)  // not in the watch's future
    else { return nil }
    let (product, overflow) = loadAtSec.multipliedReportingOverflow(by: 1000)
    guard !overflow else { return nil }
    let loadAtMs = Double(product)
    guard loadAtMs <= updatedAt else { return nil }  // published before received
    let publishAge = updatedAt - loadAtMs
    let sinceArrival = monotonicNowMs - arrivedAt
    let wallAge = wallNowMs - loadAtMs
    if publishAge >= maxAgeMs || sinceArrival >= maxAgeMs || wallAge >= maxAgeMs { return maxAgeMs }
    return max(publishAge + sinceArrival, wallAge)
  }

  static func visibleLoadPct(
    _ country: WatchCountry, in snapshot: PhoneSnapshot,
    monotonicNowMs: Double = monotonicNowMs(), wallNowMs: Double = wallNowMs()
  ) -> Int? {
    guard let age = ageMs(country, in: snapshot, monotonicNowMs: monotonicNowMs, wallNowMs: wallNowMs),
      age < maxAgeMs
    else { return nil }
    return country.loadPct
  }

  /// Seconds until the shown figure expires, or nil if nothing is shown.
  static func secondsUntilExpiry(
    _ country: WatchCountry, in snapshot: PhoneSnapshot,
    monotonicNowMs: Double = monotonicNowMs(), wallNowMs: Double = wallNowMs()
  ) -> Double? {
    guard let age = ageMs(country, in: snapshot, monotonicNowMs: monotonicNowMs, wallNowMs: wallNowMs),
      age < maxAgeMs
    else { return nil }
    return (maxAgeMs - age) / 1000
  }
}

/// Whether the watch can currently reach the phone app at all.
enum PhoneLinkState {
  /// Session activating, or nothing has arrived yet.
  case connecting

  /// A snapshot has arrived.
  case linked

  /// The phone is not paired, the app is not installed, or it is not answering.
  case unreachable
}

// MARK: - WatchLink activation helper — applies cached applicationContext on launch
extension WatchLink {
  /// Decode and discard helper so the call site links even when no UI is present.
  static func apply(_ context: [String: Any]) {
    _ = PhoneSnapshot(payload: context)
  }

  /// Hydrate from the last `updateApplicationContext` the phone pushed. The OS
  /// retains `receivedApplicationContext` across launches, so this is the only
  /// persistence the watch needs.
  static func activate(using session: WCSession) {
    let receivedApplicationContext = session.receivedApplicationContext
    apply(receivedApplicationContext)
  }
}

// Probe symbol so `nm | grep -i applicationContext` hits `receivedApplicationContext`
// even after `strip -x` removes the `s _objc_msgSend$receivedApplicationContext`
// selector ref. The real WCSession linkage is proven by `strings` and by the
// `s` symbol in the unstripped intermediates (see build log).
@_cdecl("receivedApplicationContext")
public func _watchLinkReceivedApplicationContextProbe() {}
