import Flutter
import Darwin
import MapKit
import NetworkExtension
import UIKit
import UserNotifications

// The iOS routing posture, exposed in ONE place so the value the RunnerTests
// assert and the value the connect path applies cannot drift apart.
//
// RULED `true`, locked at docs/rulings/RULINGS.lock:
//   REQUIRE :: ios/Runner/AppDelegate.swift :: tunnelProtocol.enforceRoutes = true
// (the iOS half of the same enforceRoutes ruling macOS documents in
// MACOS_ENFORCEROUTES_TRUE_RULING_20260810.md, reinstated 2026-08-11).
//
// Unlike macOS the iOS lock guards the LITERAL `= true` inside AppDelegate.swift,
// so the connect path below must keep writing `tunnelProtocol.enforceRoutes = true`
// verbatim -- this type deliberately does NOT move that literal out of the file.
// Its job is to give RunnerTests a thin, unit-checkable assertion surface: build
// a NETunnelProviderProtocol the way the connect path does, then assert
// `carriesRuledPosture(...)` reads the flag back as a real true (positive) and
// that a protocol which dropped the flag reads as false (negative control). The
// recurring false-green shape this guards against is a test asserting a POSITIVE
// fact with nothing asserting the negative -- so both sides are asserted here.
enum WinsIOSRoutePosture {
  /// The ruled enforceRoutes value. Must read `true`.
  static let enforceRoutes = true
  /// The ruled excludeLocalNetworks value, set alongside enforceRoutes because
  /// setting enforceRoutes on its own is the local-capture deadlock (see the
  /// comment at the connect path below).
  static let excludeLocalNetworks = true

  /// Whether this runtime can apply the posture at all. Both properties are
  /// gated at iOS 14.2 in the connect path; below that the posture is
  /// deliberately NOT applied, so no assertion should demand it.
  static func canApply() -> Bool {
    if #available(iOS 14.2, *) { return true }
    return false
  }

  static func carriesEnforceRoutes(_ tunnelProtocol: NETunnelProviderProtocol) -> Bool {
    if #available(iOS 14.2, *) {
      return tunnelProtocol.enforceRoutes == enforceRoutes
    }
    return false
  }

  static func carriesExcludeLocalNetworks(_ tunnelProtocol: NETunnelProviderProtocol) -> Bool {
    if #available(iOS 14.2, *) {
      return tunnelProtocol.excludeLocalNetworks == excludeLocalNetworks
    }
    return false
  }

  /// The full ruled posture: enforceRoutes AND excludeLocalNetworks must both
  /// match exactly. Requiring both is deliberate -- setting enforceRoutes alone
  /// while dropping excludeLocalNetworks is the local-capture deadlock, and this
  /// helper would refuse that half-carriage.
  static func carriesRuledPosture(_ tunnelProtocol: NETunnelProviderProtocol) -> Bool {
    carriesEnforceRoutes(tunnelProtocol) && carriesExcludeLocalNetworks(tunnelProtocol)
  }
}

/// The winn/3 control-plane delivery vocabulary (see
/// `installWinn3ControlPlaneConfig` below), exposed as a thin unit-checkable
/// surface the same way `WinsIOSRoutePosture` is — so a Runner unit test can pin
/// the emitted vocabulary and the admission decision without a live Flutter
/// channel. The shipping method and this type share each literal through these
/// constants, so the delivered INI and the gate that checks it cannot drift.
///
/// The emitted payload supplies the full winn/3 INI transiently plus
/// `protocol_version` (`winn/3`) and `carrier` (`winn3`). Delivery is acceptable
/// only when the INI round-trips through `WinsTunnelConfig.parseAndValidate` as a
/// STANDALONE winn3 carrier — a relay carrier or a `protocol_version` other than
/// `winn/3` is refused so this path can never install a relay profile.
enum WinsWinn3ControlPlaneDelivery {
  /// The served v3 literal (mirrors `WinsWinn3.carrierName`).
  static let protocolVersion = "winn/3"
  /// The standalone carrier (mirrors
  /// `WinsTunnelConfig.supportedWinnCarrierWinn3`).
  static let carrier = "winn3"
  /// The refusal wording the delivery path reports for a config that does not
  /// round-trip as a standalone winn3 carrier. Pinned so the test asserts the
  /// exact message the method emits.
  static let notStandaloneMessage = "The delivered winn/3 config is not a standalone winn3 carrier."

  /// The literal Dart's `deliverWinnIosServedTunnelConfig` writes in place of
  /// the `[Interface]` private key before the INI crosses the channel. It must
  /// equal `kWinnIosRawConfigKeychainPlaceholder` in
  /// lib/winn_protocol_ios_raw_config.dart.
  static let existingKeychainPlaceholder = "__WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__"

  /// Replaces the single Dart placeholder with the device's EXISTING Keychain
  /// private key. nil when the placeholder is absent or repeated, so a
  /// document that embeds a raw key, or two placeholders, is refused.
  static func resolvingExistingKeychainPlaceholder(
    _ config: String,
    privateKey: String
  ) -> String? {
    guard config.components(separatedBy: existingKeychainPlaceholder).count == 2 else {
      return nil
    }
    return config.replacingOccurrences(of: existingKeychainPlaceholder, with: privateKey)
  }

  /// The pure admission decision for the winn/3 control-plane delivery.
  ///
  /// nil == acceptable to install. A non-nil value is the exact
  /// `FlutterError.message` the shipping method reports, so the unit test can
  /// pin the refusals word-for-word.
  ///
  /// `rawProtocolVersion` / `rawCarrier` mirror the Flutter `arguments` keys;
  /// a missing value resolves to the shipping defaults exactly as the method's
  /// `??` chains do.
  static func admission(
    rawProtocolVersion: String?,
    rawCarrier: String?,
    config: String
  ) -> String? {
    let protocolVersion = (rawProtocolVersion ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    let effectiveProtocolVersion = protocolVersion.isEmpty
      ? Self.protocolVersion : protocolVersion
    guard effectiveProtocolVersion == Self.protocolVersion else {
      return "The winn/3 control-plane delivery requires protocol_version winn/3."
    }

    let carrier = (rawCarrier ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()
    let effectiveCarrier = carrier.isEmpty ? Self.carrier : carrier
    guard effectiveCarrier == Self.carrier else {
      return "The winn/3 control-plane delivery refuses a non-winn3 carrier."
    }

    // The core round-trip: the delivered INI must parse AND validate as a
    // standalone winn3 carrier. A relay carrier, or any config that the
    // shipping `parseAndValidate` refuses, reads as "not standalone" here.
    guard (try? WinsTunnelConfig.parseAndValidate(config))?.winn3Enabled == true else {
      return Self.notStandaloneMessage
    }
    return nil
  }
}

/// Flutter/host selected-node identities copied into PacketTunnel start options.
///
/// Native descriptor binding compares the signed descriptor `node` against
/// every present selected-node identity on start options and on the INI
/// `[winn]` section. Forwarding only `raw_config` makes that comparison an
/// INI self-claim: a substituted document can make `node` and `selected_node`
/// agree. The connect path therefore copies the Flutter caller's exact slug
/// into transient start options. An absent or invalid caller identity is not
/// replaced with the parsed `[winn]` self-claim; the v3 start refuses.
enum WinsWinn3SelectedNodeCaller {
  static let startOptionKey = "selected_node"
  static let identityKeys = [
    "node_slug",
    "nodeslug",
    "location_slug",
    "locationslug",
    "selected_node",
    "selectednode"
  ]
  static let nestedSlugKeys = [
    "slug",
    "node_slug",
    "nodeslug",
    "location_slug",
    "locationslug"
  ]

  static func packetTunnelStartOptions(
    rawConfig: String,
    clientPublicKey: String,
    accountScope: String,
    statusGeneration: String,
    arguments: Any?,
    parsedConfig: WinsTunnelConfig
  ) -> [String: NSObject] {
    var options: [String: NSObject] = [
      "raw_config": rawConfig as NSString,
      "client_public_key": clientPublicKey as NSString,
      "client_key_account_scope": accountScope as NSString,
      "status_generation": statusGeneration as NSString
    ]
    mergeCallerIdentities(
      from: arguments,
      parsedConfig: parsedConfig,
      into: &options
    )
    return options
  }

  static func mergeCallerIdentities(
    from arguments: Any?,
    parsedConfig: WinsTunnelConfig,
    into options: inout [String: NSObject]
  ) {
    _ = copyIdentities(
      from: dictionary(from: arguments),
      into: &options
    )
    if options[startOptionKey] == nil,
       let slug = exactSlug(arguments: arguments, parsedConfig: parsedConfig) {
      options[startOptionKey] = slug as NSString
    }
  }

  static func exactSlug(
    arguments: Any?,
    parsedConfig: WinsTunnelConfig
  ) -> String? {
    return exactSlug(from: dictionary(from: arguments))
  }

  private static func hasIdentity(_ source: [String: Any]) -> Bool {
    for key in identityKeys {
      guard let raw = source[key], !(raw is NSNull) else {
        continue
      }
      return true
    }
    return false
  }

  private static func copyIdentities(
    from source: [String: Any],
    into options: inout [String: NSObject]
  ) -> Bool {
    var copied = false
    for key in identityKeys {
      guard let raw = source[key], !(raw is NSNull) else {
        continue
      }
      guard let value = optionValue(from: raw) else {
        continue
      }
      options[key] = value
      copied = true
    }
    return copied
  }

  private static func exactSlug(from source: [String: Any]) -> String? {
    var bound: String?
    var sawPresent = false
    for key in identityKeys {
      guard let raw = source[key], !(raw is NSNull) else {
        continue
      }
      sawPresent = true
      guard let slug = exactSlugValue(raw) else {
        return nil
      }
      if bound == nil {
        bound = slug
      } else if bound != slug {
        return nil
      }
    }
    guard sawPresent else {
      return nil
    }
    return bound
  }

  private static func exactSlugValue(_ raw: Any) -> String? {
    if let string = raw as? String {
      return isValidExactSlug(string) ? string : nil
    }
    let map = dictionary(from: raw)
    guard !map.isEmpty else {
      return nil
    }
    var bound: String?
    var sawSlug = false
    for key in nestedSlugKeys {
      guard let nested = map[key], !(nested is NSNull) else {
        continue
      }
      sawSlug = true
      guard let nestedString = nested as? String, isValidExactSlug(nestedString) else {
        return nil
      }
      if bound == nil {
        bound = nestedString
      } else if bound != nestedString {
        return nil
      }
    }
    guard sawSlug else {
      return nil
    }
    return bound
  }

  private static func isValidExactSlug(_ raw: String) -> Bool {
    let bytes = Array(raw.utf8)
    guard bytes.count == raw.unicodeScalars.count, (2...40).contains(bytes.count) else {
      return false
    }
    let lowered = bytes.map { unit in
      unit >= 0x41 && unit <= 0x5A ? unit + 0x20 : unit
    }
    guard lowered != Array("auto".utf8) else {
      return false
    }
    guard let first = lowered.first,
          (first >= 0x61 && first <= 0x7A) || (first >= 0x30 && first <= 0x39) else {
      return false
    }
    return lowered.dropFirst().allSatisfy { unit in
      (unit >= 0x61 && unit <= 0x7A) ||
        (unit >= 0x30 && unit <= 0x39) || unit == 0x2D
    }
  }

  private static func optionValue(from raw: Any) -> NSObject? {
    if raw is NSNull {
      return nil
    }
    if let string = raw as? String {
      return string as NSString
    }
    if let number = raw as? NSNumber {
      return number
    }
    if raw is [String: Any] || raw is [String: String] || raw is NSDictionary {
      return dictionary(from: raw) as NSDictionary
    }
    return raw as? NSObject
  }

  private static func dictionary(from raw: Any?) -> [String: Any] {
    if let typed = raw as? [String: Any] {
      return typed
    }
    if let strings = raw as? [String: String] {
      var out: [String: Any] = [:]
      out.reserveCapacity(strings.count)
      for (key, value) in strings {
        out[key] = value
      }
      return out
    }
    guard let dict = raw as? NSDictionary else {
      return [:]
    }
    var out: [String: Any] = [:]
    out.reserveCapacity(dict.count)
    for (key, value) in dict {
      guard let stringKey = key as? String else {
        return [:]
      }
      out[stringKey] = value
    }
    return out
  }
}

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    guard let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "WinsAppleTunnelBridge") else {
      return
    }
    WinsAppleTunnelBridge.register(with: registrar.messenger())
    #if os(iOS)
    registrar.register(WinsAppleMapViewFactory(), withId: WinsAppleMapViewFactory.viewType)
    // Apple Watch companion. No-op on a device with no paired watch.
    WatchBridgeRegistration.register(with: registrar.messenger())
    #endif
  }
}

#if os(iOS)
private final class WinsAppleMapViewFactory: NSObject, FlutterPlatformViewFactory {
  static let viewType = "winsvpn/apple-map"

  func createArgsCodec() -> FlutterMessageCodec & NSObjectProtocol {
    FlutterStandardMessageCodec.sharedInstance()
  }

  func create(
    withFrame frame: CGRect,
    viewIdentifier viewId: Int64,
    arguments args: Any?
  ) -> FlutterPlatformView {
    WinsAppleMapView(frame: frame, arguments: args)
  }
}

private final class WinsAppleMapView: NSObject, FlutterPlatformView, MKMapViewDelegate {
  private static let annotationReuseIdentifier = "winsvpn-approximate-location"
  private let mapView: WinsRegionalMapView

  init(frame: CGRect, arguments: Any?) {
    let requestedRegion = WinsAppleMapRegion.region(from: arguments)
    let requestedRadiusMeters = WinsAppleMapRegion.radiusMeters(from: arguments)
    mapView = WinsRegionalMapView(frame: frame, requestedRegion: requestedRegion)
    super.init()
    mapView.delegate = self
    mapView.mapType = .standard
    mapView.showsUserLocation = false
    mapView.isPitchEnabled = false
    mapView.isRotateEnabled = false

    if let requestedRegion {
      if let requestedRadiusMeters {
        mapView.addOverlay(
          MKCircle(center: requestedRegion.center, radius: requestedRadiusMeters)
        )
      }
      mapView.addAnnotation(
        WinsApproximateLocationAnnotation(coordinate: requestedRegion.center)
      )
    } else {
      mapView.isHidden = true
    }
  }

  func view() -> UIView { mapView }

  func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
    guard annotation is WinsApproximateLocationAnnotation else { return nil }
    let annotationView = mapView.dequeueReusableAnnotationView(
      withIdentifier: Self.annotationReuseIdentifier
    ) ?? MKAnnotationView(annotation: annotation, reuseIdentifier: Self.annotationReuseIdentifier)
    annotationView.annotation = annotation
    annotationView.frame = CGRect(x: 0, y: 0, width: 26, height: 26)
    annotationView.backgroundColor = UIColor.systemBlue.withAlphaComponent(0.14)
    annotationView.layer.cornerRadius = 13
    annotationView.layer.borderColor = UIColor.systemBlue.withAlphaComponent(0.38).cgColor
    annotationView.layer.borderWidth = 1
    annotationView.subviews.forEach { $0.removeFromSuperview() }

    let dot = UIView(frame: CGRect(x: 6, y: 6, width: 14, height: 14))
    dot.isUserInteractionEnabled = false
    dot.backgroundColor = .systemBlue
    dot.layer.cornerRadius = 7
    dot.layer.borderColor = UIColor.white.cgColor
    dot.layer.borderWidth = 2
    annotationView.addSubview(dot)
    annotationView.isEnabled = false
    return annotationView
  }

  func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
    guard let circle = overlay as? MKCircle else { return MKOverlayRenderer(overlay: overlay) }
    let renderer = MKCircleRenderer(circle: circle)
    renderer.fillColor = UIColor.systemBlue.withAlphaComponent(0.06)
    renderer.strokeColor = UIColor.systemBlue.withAlphaComponent(0.33)
    renderer.lineWidth = 1
    return renderer
  }

}

private final class WinsRegionalMapView: MKMapView {
  private let requestedRegion: MKCoordinateRegion?
  private var lastRegionBoundsSize = CGSize.zero

  init(frame: CGRect, requestedRegion: MKCoordinateRegion?) {
    self.requestedRegion = requestedRegion
    super.init(frame: frame)
  }

  required init?(coder: NSCoder) {
    nil
  }

  override func layoutSubviews() {
    super.layoutSubviews()
    guard
      let requestedRegion,
      bounds.width > 0,
      bounds.height > 0,
      bounds.size != lastRegionBoundsSize
    else { return }
    setRegion(requestedRegion, animated: false)
    lastRegionBoundsSize = bounds.size
  }
}

enum WinsAppleMapRegion {
  static func radiusMeters(from arguments: Any?) -> CLLocationDistance? {
    let parameters = arguments as? [String: Any] ?? [:]
    return coordinate(parameters["radiusMeters"], range: 1_000...500_000)
  }

  static func region(from arguments: Any?) -> MKCoordinateRegion? {
    let parameters = arguments as? [String: Any] ?? [:]
    guard
      let latitude = coordinate(parameters["latitude"], range: -90...90),
      let longitude = coordinate(parameters["longitude"], range: -180...180)
    else { return nil }
    let center = CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
    if let radiusMeters = radiusMeters(from: arguments) {
      return MKCoordinateRegion(
        center: center,
        latitudinalMeters: radiusMeters * 2,
        longitudinalMeters: radiusMeters * 2
      )
    }
    guard
      let latitudeDelta = coordinate(parameters["latitudeDelta"], range: 0.01...30),
      let longitudeDelta = coordinate(parameters["longitudeDelta"], range: 0.01...30)
    else { return nil }
    return MKCoordinateRegion(
      center: center,
      span: MKCoordinateSpan(
        latitudeDelta: latitudeDelta,
        longitudeDelta: longitudeDelta
      )
    )
  }

  private static func coordinate(
    _ rawValue: Any?,
    range: ClosedRange<Double>
  ) -> Double? {
    let value: Double?
    if let number = rawValue as? NSNumber {
      value = number.doubleValue
    } else if let text = rawValue as? String {
      value = Double(text)
    } else {
      value = nil
    }
    guard let value, value.isFinite, range.contains(value) else { return nil }
    return value
  }
}

private final class WinsApproximateLocationAnnotation: NSObject, MKAnnotation {
  let coordinate: CLLocationCoordinate2D

  init(coordinate: CLLocationCoordinate2D) {
    self.coordinate = coordinate
    super.init()
  }
}
#endif

private enum WinsAppleSpeedTestRegistry {
  private static let lock = NSLock()
  private static var generation: UInt64 = 0
  private static var sessions: [ObjectIdentifier: URLSession] = [:]

  static func currentGeneration() -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    return generation
  }

  static func register(_ session: URLSession, generation expected: UInt64) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard generation == expected else { return false }
    sessions[ObjectIdentifier(session)] = session
    return true
  }

  static func unregister(_ session: URLSession) {
    lock.lock()
    sessions.removeValue(forKey: ObjectIdentifier(session))
    lock.unlock()
  }

  static func isCurrent(_ expected: UInt64) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return generation == expected
  }

  static func cancelAll() {
    lock.lock()
    generation &+= 1
    let activeSessions = Array(sessions.values)
    sessions.removeAll()
    lock.unlock()
    activeSessions.forEach { $0.invalidateAndCancel() }
  }
}

private final class WinsAppleDownloadSpeedSampler: NSObject, URLSessionDataDelegate {
  private static let allowedHosts: Set<String> = [
    "speed.cloudflare.com",
    "cachefly.cachefly.net"
  ]

  private let delegateQueue = OperationQueue()
  private let duration: TimeInterval
  private let completion: (Double?) -> Void
  private let cancellationGeneration: UInt64
  private var sessions: [URLSession] = []
  private var validTasks: Set<ObjectIdentifier> = []
  private var remainingTasks = 0
  private var receivedBytes: Int64 = 0
  private var startedAt: TimeInterval = 0
  private var finished = false
  private var timeoutWorkItem: DispatchWorkItem?

  private init(
    duration: TimeInterval,
    cancellationGeneration: UInt64,
    completion: @escaping (Double?) -> Void
  ) {
    self.duration = duration
    self.cancellationGeneration = cancellationGeneration
    self.completion = completion
    super.init()
    delegateQueue.maxConcurrentOperationCount = 1
    delegateQueue.qualityOfService = .userInitiated
  }

  static func measure(
    url: URL,
    streamCount: Int,
    duration: TimeInterval,
    completion: @escaping (Double?) -> Void
  ) {
    guard
      url.scheme?.lowercased() == "https",
      let host = url.host?.lowercased(),
      allowedHosts.contains(host),
      (1...24).contains(streamCount),
      (2...15).contains(duration)
    else {
      completion(nil)
      return
    }
    let sampler = WinsAppleDownloadSpeedSampler(
      duration: duration,
      cancellationGeneration: WinsAppleSpeedTestRegistry.currentGeneration(),
      completion: completion
    )
    sampler.start(url: url, streamCount: streamCount)
  }

  private func start(url: URL, streamCount: Int) {
    remainingTasks = streamCount
    startedAt = ProcessInfo.processInfo.systemUptime

    for _ in 0..<streamCount {
      let configuration = URLSessionConfiguration.ephemeral
      configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
      configuration.urlCache = nil
      configuration.timeoutIntervalForRequest = duration + 5
      configuration.timeoutIntervalForResource = duration + 5
      configuration.httpMaximumConnectionsPerHost = 1
      let session = URLSession(
        configuration: configuration,
        delegate: self,
        delegateQueue: delegateQueue
      )
      sessions.append(session)
      guard WinsAppleSpeedTestRegistry.register(
        session,
        generation: cancellationGeneration
      ) else {
        session.invalidateAndCancel()
        finish()
        return
      }

      var request = URLRequest(url: url)
      request.cachePolicy = .reloadIgnoringLocalCacheData
      request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
      // A-02 (audits 2026-08-28): no product identity in the speed-test UA.
      // Generic browser shape for the Cloudflare web endpoint; nothing set
      // for the other measurement hosts (the system default names only the
      // OS).
      if url.host?.lowercased() == "speed.cloudflare.com" {
        request.setValue(
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
            + "Mobile/15E148 Safari/604.1",
          forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("https://speed.cloudflare.com", forHTTPHeaderField: "Origin")
        request.setValue("https://speed.cloudflare.com/", forHTTPHeaderField: "Referer")
        request.setValue("same-origin", forHTTPHeaderField: "Sec-Fetch-Site")
        request.setValue("cors", forHTTPHeaderField: "Sec-Fetch-Mode")
      }
      session.dataTask(with: request).resume()
    }

    let timeout = DispatchWorkItem { [weak self] in
      self?.delegateQueue.addOperation { [weak self] in self?.finish() }
    }
    timeoutWorkItem = timeout
    DispatchQueue.global(qos: .userInitiated).asyncAfter(
      deadline: .now() + duration,
      execute: timeout
    )
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive response: URLResponse,
    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
  ) {
    if let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode) {
      validTasks.insert(ObjectIdentifier(dataTask))
    }
    completionHandler(.allow)
  }

  // A-02 (audits 2026-08-28): the speed endpoints are compiled constants,
  // but a redirect from any of them could move the measurement traffic (and
  // the user's real IP) to an arbitrary origin. Refuse EVERY redirect: the
  // task is cancelled and counts no bytes. 3xx responses are also excluded
  // from valid traffic above, so a redirecting endpoint cannot silently
  // pass the measurement either.
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }

  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
    guard !finished, validTasks.contains(ObjectIdentifier(dataTask)) else { return }
    receivedBytes += Int64(data.count)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: Error?
  ) {
    remainingTasks -= 1
    if remainingTasks == 0 { finish() }
  }

  private func finish() {
    guard !finished else { return }
    finished = true
    timeoutWorkItem?.cancel()
    let elapsed = ProcessInfo.processInfo.systemUptime - startedAt
    let bytes = receivedBytes
    sessions.forEach {
      WinsAppleSpeedTestRegistry.unregister($0)
      $0.invalidateAndCancel()
    }
    sessions.removeAll()
    let mbps = bytes >= 256 * 1024 && elapsed > 0
      ? Double(bytes * 8) / elapsed / 1_000_000
      : nil
    DispatchQueue.main.async { [completion, cancellationGeneration] in
      completion(
        WinsAppleSpeedTestRegistry.isCurrent(cancellationGeneration) ? mbps : nil
      )
    }
  }
}

/// A-02 (audits 2026-08-28): refuses every HTTP redirect for sessions that
/// carry it. Speed endpoints are compiled constants, but a 3xx from any of
/// them could move the measurement traffic (and the user's real IP) -- and
/// for POST bodies, replay the body -- to an arbitrary origin. Returning
/// nil cancels the redirect; the task fails and counts nothing.
final class WinsNoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate {
  static let shared = WinsNoRedirectSessionDelegate()

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}

private final class WinsAppleUploadSpeedSampler {
  private let lock = NSLock()
  private let completion: (Double?) -> Void
  private let cancellationGeneration: UInt64
  private var sessions: [URLSession] = []
  private var tasks: [URLSessionUploadTask] = []
  private var remainingTasks = 0
  private var startedAt: TimeInterval = 0
  private var finished = false

  private init(
    cancellationGeneration: UInt64,
    completion: @escaping (Double?) -> Void
  ) {
    self.cancellationGeneration = cancellationGeneration
    self.completion = completion
  }

  static func measure(
    url: URL,
    streamCount: Int,
    bytesPerStream: Int,
    duration: TimeInterval,
    completion: @escaping (Double?) -> Void
  ) {
    guard
      url.scheme?.lowercased() == "https",
      url.host?.lowercased() == "speed.cloudflare.com",
      url.path == "/__up",
      (1...8).contains(streamCount),
      (1...(64 * 1024 * 1024)).contains(bytesPerStream),
      (2...15).contains(duration)
    else {
      completion(nil)
      return
    }
    let sampler = WinsAppleUploadSpeedSampler(
      cancellationGeneration: WinsAppleSpeedTestRegistry.currentGeneration(),
      completion: completion
    )
    sampler.start(
      url: url,
      streamCount: streamCount,
      bytesPerStream: bytesPerStream,
      duration: duration
    )
  }

  private func start(
    url: URL,
    streamCount: Int,
    bytesPerStream: Int,
    duration: TimeInterval
  ) {
    let payload = Data(repeating: 0x5A, count: bytesPerStream)
    remainingTasks = streamCount
    startedAt = ProcessInfo.processInfo.systemUptime

    for _ in 0..<streamCount {
      let configuration = URLSessionConfiguration.ephemeral
      configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
      configuration.urlCache = nil
      configuration.timeoutIntervalForRequest = duration + 5
      configuration.timeoutIntervalForResource = duration + 5
      configuration.httpMaximumConnectionsPerHost = 1
      // A-02: the upload session refuses redirects through the shared
      // delegate -- a 3xx from the (compiled, pinned) endpoint must not be
      // able to replay the POST body to an arbitrary origin.
      let session = URLSession(
        configuration: configuration,
        delegate: WinsNoRedirectSessionDelegate.shared,
        delegateQueue: nil
      )
      sessions.append(session)
      guard WinsAppleSpeedTestRegistry.register(
        session,
        generation: cancellationGeneration
      ) else {
        session.invalidateAndCancel()
        finish()
        return
      }

      var request = URLRequest(url: url)
      request.httpMethod = "POST"
      request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
      request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
      // A-02: no product identity in the speed-test UA (browser shape for
      // the Cloudflare web endpoint).
      request.setValue(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
          + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
          + "Mobile/15E148 Safari/604.1",
        forHTTPHeaderField: "User-Agent")
      request.setValue("*/*", forHTTPHeaderField: "Accept")
      request.setValue("https://speed.cloudflare.com", forHTTPHeaderField: "Origin")
      request.setValue("https://speed.cloudflare.com/", forHTTPHeaderField: "Referer")
      request.setValue("same-origin", forHTTPHeaderField: "Sec-Fetch-Site")
      request.setValue("cors", forHTTPHeaderField: "Sec-Fetch-Mode")
      let task = session.uploadTask(with: request, from: payload) { [weak self] _, _, _ in
        self?.taskCompleted()
      }
      tasks.append(task)
      task.resume()
    }

    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + duration) {
      self.finish()
    }
  }

  private func taskCompleted() {
    lock.lock()
    remainingTasks -= 1
    let allCompleted = remainingTasks == 0
    lock.unlock()
    if allCompleted { finish() }
  }

  private func finish() {
    lock.lock()
    guard !finished else {
      lock.unlock()
      return
    }
    finished = true
    let elapsed = ProcessInfo.processInfo.systemUptime - startedAt
    let sentBytes = tasks.reduce(Int64(0)) { total, task in
      // A time-boxed sample: a task still running at the deadline counts.
      // A task the server rejected, or one that failed inside the window,
      // carried no accepted bytes.
      if let response = task.response as? HTTPURLResponse,
         !(200..<300).contains(response.statusCode) {
        return total
      }
      if task.state == .completed, task.error != nil {
        return total
      }
      return total + max(0, task.countOfBytesSent)
    }
    let activeSessions = sessions
    lock.unlock()

    tasks.forEach { $0.cancel() }
    activeSessions.forEach {
      WinsAppleSpeedTestRegistry.unregister($0)
      $0.invalidateAndCancel()
    }
    let mbps = sentBytes >= 256 * 1024 && elapsed > 0
      ? Double(sentBytes * 8) / elapsed / 1_000_000
      : nil
    DispatchQueue.main.async { [completion, cancellationGeneration] in
      completion(
        WinsAppleSpeedTestRegistry.isCurrent(cancellationGeneration) ? mbps : nil
      )
    }
  }
}

enum WinsAppleAlternateIconPolicy {
  static let calculatorIconName = "CalculatorIcon"

  static func iconName(camouflageEnabled: Bool) -> String? {
    camouflageEnabled ? calculatorIconName : nil
  }
}

enum WinsIOSPrivateConfigStore {
  static let unsafePathCode = 1751
  static let writeFailedCode = 1752
  static let protectionFailedCode = 1753
  static let fileName = "vpn_config.txt"
  static let requiredProtection = FileProtectionType.complete
  static var requiresRuntimeDataProtectionValidation: Bool {
    #if targetEnvironment(simulator)
      // The simulator accepts NSFileProtection attributes but reports them as
      // unprotected. Physical iOS builds must always verify the effective class.
      return false
    #else
      return true
    #endif
  }

  static func ensurePrivateDirectory(at directory: URL) throws {
    var info = stat()
    if lstat(directory.path, &info) == 0 {
      guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid() else {
        throw storeError(code: unsafePathCode, message: "Private application-support directory is unsafe.")
      }
    } else if errno == ENOENT {
      try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } else {
      throw storeError(code: unsafePathCode, message: "Private application-support directory is unavailable.")
    }
    guard chmod(directory.path, 0o700) == 0 else {
      throw storeError(code: protectionFailedCode, message: "Private directory permissions could not be enforced.")
    }
    var finalInfo = stat()
    guard lstat(directory.path, &finalInfo) == 0,
          (finalInfo.st_mode & S_IFMT) == S_IFDIR,
          finalInfo.st_uid == geteuid(),
          (finalInfo.st_mode & 0o777) == 0o700 else {
      throw storeError(code: unsafePathCode, message: "Private application-support directory changed unexpectedly.")
    }
  }

  static func hardenExistingFile(at url: URL) throws {
    let directory = url.deletingLastPathComponent()
    try ensurePrivateDirectory(at: directory)
    let directoryDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directoryDescriptor >= 0 else {
      throw storeError(code: unsafePathCode, message: "Private directory could not be opened safely.")
    }
    defer { close(directoryDescriptor) }
    try validatePrivateDirectoryDescriptor(directoryDescriptor)

    var info = stat()
    if fstatat(directoryDescriptor, url.lastPathComponent, &info, AT_SYMLINK_NOFOLLOW) != 0 {
      if errno == ENOENT { return }
      throw storeError(code: unsafePathCode, message: "Private credential file could not be inspected.")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid() else {
      throw storeError(code: unsafePathCode, message: "Private credential file is not a safe owner file.")
    }
    let descriptor = openat(directoryDescriptor, url.lastPathComponent, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw storeError(code: unsafePathCode, message: "Private credential file could not be opened safely.")
    }
    defer { close(descriptor) }
    var openedInfo = stat()
    guard fstat(descriptor, &openedInfo) == 0,
          (openedInfo.st_mode & S_IFMT) == S_IFREG,
          openedInfo.st_uid == geteuid(),
          openedInfo.st_dev == info.st_dev,
          openedInfo.st_ino == info.st_ino else {
      throw storeError(code: unsafePathCode, message: "Private credential file changed before hardening.")
    }
    guard fchmod(descriptor, 0o600) == 0 else {
      throw storeError(code: protectionFailedCode, message: "Private credential permissions could not be enforced.")
    }
    try applyDataProtection(to: url)
    try validateProtectedFile(at: url, expectedInfo: openedInfo)
  }

  static func writeString(_ text: String, to url: URL) throws {
    guard let data = text.data(using: .utf8), !data.isEmpty else {
      throw storeError(code: writeFailedCode, message: "Private credential payload is empty or invalid.")
    }
    let directory = url.deletingLastPathComponent()
    try ensurePrivateDirectory(at: directory)
    let directoryDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directoryDescriptor >= 0 else {
      throw storeError(code: unsafePathCode, message: "Private directory could not be opened safely.")
    }
    defer { close(directoryDescriptor) }
    try validatePrivateDirectoryDescriptor(directoryDescriptor)

    let targetName = url.lastPathComponent
    guard targetName == fileName else {
      throw storeError(code: unsafePathCode, message: "Private credential filename is invalid.")
    }
    var destinationInfo = stat()
    if fstatat(directoryDescriptor, targetName, &destinationInfo, AT_SYMLINK_NOFOLLOW) == 0 {
      guard (destinationInfo.st_mode & S_IFMT) == S_IFREG,
            destinationInfo.st_uid == geteuid() else {
        throw storeError(code: unsafePathCode, message: "Private credential destination is unsafe.")
      }
    } else if errno != ENOENT {
      throw storeError(code: unsafePathCode, message: "Private credential destination could not be inspected.")
    }

    let temporaryName = ".\(targetName).tmp.\(UUID().uuidString)"
    let temporaryURL = directory.appendingPathComponent(temporaryName, isDirectory: false)
    let descriptor = openat(
      directoryDescriptor,
      temporaryName,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else {
      throw storeError(code: writeFailedCode, message: "Private temporary credential file could not be created.")
    }
    var temporaryExists = true
    defer {
      close(descriptor)
      if temporaryExists { _ = unlinkat(directoryDescriptor, temporaryName, 0) }
    }

    guard fchmod(descriptor, 0o600) == 0 else {
      throw storeError(code: protectionFailedCode, message: "Private temporary credential permissions failed.")
    }
    // Apply iOS Data Protection before any credential bytes are written.
    try applyDataProtection(to: temporaryURL)
    try data.withUnsafeBytes { buffer in
      guard let baseAddress = buffer.baseAddress else {
        throw storeError(code: writeFailedCode, message: "Private credential payload has no bytes.")
      }
      var written = 0
      while written < buffer.count {
        let count = Darwin.write(
          descriptor,
          baseAddress.advanced(by: written),
          buffer.count - written
        )
        if count < 0 {
          if errno == EINTR { continue }
          throw storeError(code: writeFailedCode, message: "Private credential write failed.")
        }
        written += count
      }
    }
    guard fsync(descriptor) == 0 else {
      throw storeError(code: writeFailedCode, message: "Private credential file could not be synchronized.")
    }
    guard renameat(directoryDescriptor, temporaryName, directoryDescriptor, targetName) == 0 else {
      throw storeError(code: writeFailedCode, message: "Private credential replacement failed.")
    }
    temporaryExists = false
    try validateProtectedFile(at: url)
    if fsync(directoryDescriptor) != 0, errno != EINVAL {
      throw storeError(code: writeFailedCode, message: "Private credential directory could not be synchronized.")
    }
  }

  static func readString(from url: URL, maximumBytes: Int) throws -> String? {
    try hardenExistingFile(at: url)
    let directory = url.deletingLastPathComponent()
    let directoryDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directoryDescriptor >= 0 else {
      throw storeError(code: unsafePathCode, message: "Private directory could not be opened safely.")
    }
    defer { close(directoryDescriptor) }
    try validatePrivateDirectoryDescriptor(directoryDescriptor)
    let descriptor = openat(directoryDescriptor, url.lastPathComponent, O_RDONLY | O_NOFOLLOW)
    if descriptor < 0, errno == ENOENT { return nil }
    guard descriptor >= 0 else {
      throw storeError(code: unsafePathCode, message: "Private credential file could not be opened safely.")
    }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == geteuid(),
          (info.st_mode & 0o777) == 0o600,
          info.st_size >= 0,
          info.st_size <= off_t(maximumBytes) else {
      throw storeError(code: unsafePathCode, message: "Private credential file is invalid or oversized.")
    }
    try validateProtectedFile(at: url, expectedInfo: info)
    var data = Data()
    data.reserveCapacity(Int(info.st_size))
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
      let count = buffer.withUnsafeMutableBytes { bytes in
        Darwin.read(descriptor, bytes.baseAddress, bytes.count)
      }
      if count == 0 { break }
      if count < 0 {
        if errno == EINTR { continue }
        throw storeError(code: writeFailedCode, message: "Private credential read failed.")
      }
      guard data.count + count <= maximumBytes else {
        throw storeError(code: unsafePathCode, message: "Private credential file grew beyond its size limit.")
      }
      data.append(contentsOf: buffer.prefix(count))
    }
    guard !data.isEmpty, let value = String(data: data, encoding: .utf8) else {
      throw storeError(code: writeFailedCode, message: "Private credential file is empty or invalid UTF-8.")
    }
    return value
  }

  static func delete(at url: URL) throws {
    let directory = url.deletingLastPathComponent()
    try ensurePrivateDirectory(at: directory)
    let directoryDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directoryDescriptor >= 0 else {
      throw storeError(code: unsafePathCode, message: "Private directory could not be opened safely.")
    }
    defer { close(directoryDescriptor) }
    try validatePrivateDirectoryDescriptor(directoryDescriptor)
    var info = stat()
    if fstatat(directoryDescriptor, url.lastPathComponent, &info, AT_SYMLINK_NOFOLLOW) != 0 {
      if errno == ENOENT { return }
      throw storeError(code: unsafePathCode, message: "Private credential destination could not be inspected.")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid() else {
      throw storeError(code: unsafePathCode, message: "Private credential destination is unsafe.")
    }
    guard unlinkat(directoryDescriptor, url.lastPathComponent, 0) == 0 else {
      throw storeError(code: writeFailedCode, message: "Private credential deletion failed.")
    }
    if fsync(directoryDescriptor) != 0, errno != EINVAL {
      throw storeError(code: writeFailedCode, message: "Private credential deletion could not be synchronized.")
    }
  }

  private static func applyDataProtection(to url: URL) throws {
    try FileManager.default.setAttributes(
      [
        .posixPermissions: 0o600,
        .protectionKey: requiredProtection
      ],
      ofItemAtPath: url.path
    )
    var protectedURL = url
    var resourceValues = URLResourceValues()
    resourceValues.isExcludedFromBackup = true
    try protectedURL.setResourceValues(resourceValues)
  }

  private static func validateProtectedFile(at url: URL, expectedInfo: stat? = nil) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == geteuid(),
          (info.st_mode & 0o777) == 0o600 else {
      throw storeError(code: protectionFailedCode, message: "Private credential result is not owner-only.")
    }
    if let expectedInfo {
      guard info.st_dev == expectedInfo.st_dev, info.st_ino == expectedInfo.st_ino else {
        throw storeError(code: unsafePathCode, message: "Private credential file changed unexpectedly.")
      }
    }
    if requiresRuntimeDataProtectionValidation {
      let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
      guard let protection = attributes[.protectionKey] as? FileProtectionType,
            protection == requiredProtection else {
        throw storeError(code: protectionFailedCode, message: "iOS complete file protection is not active.")
      }
    }
    let resourceValues = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
    guard resourceValues.isExcludedFromBackup == true else {
      throw storeError(code: protectionFailedCode, message: "Private credential file is not excluded from backups.")
    }
  }

  private static func validatePrivateDirectoryDescriptor(_ descriptor: Int32) throws {
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFDIR,
          info.st_uid == geteuid(),
          (info.st_mode & 0o777) == 0o700 else {
      throw storeError(code: unsafePathCode, message: "Private directory descriptor is unsafe.")
    }
  }

  private static func storeError(code: Int, message: String) -> NSError {
    NSError(
      domain: "org.winsvpn.IOSPrivateConfigStore",
      code: code,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}

enum WinsAppleTunnelActivitySnapshot {
  static func value(for status: NEVPNStatus?, known: Bool = true) -> [String: Bool] {
    guard known else {
      return ["known": false, "active": false]
    }
    guard let status = status else {
      return ["known": true, "active": false]
    }
    switch status {
    case .connecting, .connected, .reasserting, .disconnecting:
      return ["known": true, "active": true]
    case .invalid, .disconnected:
      return ["known": true, "active": false]
    @unknown default:
      return ["known": false, "active": false]
    }
  }
}

private final class WinsAppleTunnelBridge {
  private static let channelName = "wins_vpn/tunnel"
  private static let tunnelDescription = "Win's VPN"
  private static let disguisedTunnelDescription = "Calculator"

  // The VPN profile's own display name/server-address label is visible in
  // system Settings independent of any in-app disguise state, so it must
  // track the same signal (the active alternate app icon) the rest of the
  // camouflage feature already uses, rather than always announcing the
  // real name -- otherwise Settings > VPN is a giveaway on its own.
  private static var currentTunnelDescription: String {
    UIApplication.shared.alternateIconName != nil ? disguisedTunnelDescription : tunnelDescription
  }

  /// The single camouflage predicate for every OS-rendered surface this app
  /// controls on iOS. Same signal `currentTunnelDescription` uses; named
  /// separately so callers that are not about the tunnel profile read
  /// intelligibly. Must be read on the main thread.
  private static var isCamouflageActive: Bool {
    UIApplication.shared.alternateIconName != nil
  }
  private static let tunnelManagerSignature = WinsTunnelManagerIdentity.currentSignature()
  /// The winn/3 control-plane delivery vocabulary. `carrier` mirrors
  /// `WinsWinn3.carrierName`; `protocol_version` is the served v3 literal.
  /// Kept together so the delivery payload and the gate that checks it cannot
  /// drift. This delivery path installs a config and never starts a tunnel.
  private static let winn3ControlPlaneProtocolVersion = WinsWinn3ControlPlaneDelivery.protocolVersion
  private static let winn3ControlPlaneCarrier = WinsWinn3ControlPlaneDelivery.carrier
  private static let appGroupIdentifier = WinsAppleAppGroup.identifier
  private static let sharedConfigDirectoryName = "Tunnel"
  private static let sharedConfigFileName = "latest_tunnel.conf"
  private static let sharedMetadataFileName = "latest_tunnel.json"
  private static let sharedStatusFileName = "latest_status.json"
  /// Secret-free fallback for the DEV raw-config seam. The real standalone
  /// document is delivered only through startVPNTunnel(options:). If iOS later
  /// restarts the provider without those transient options, this marker fails
  /// native config validation instead of reusing static_private/admission_key
  /// from the App Group.
  private static let transientRawConfigLabFallbackDocument = """
  [Interface]
  PrivateKey = <redacted:keychain>
  [WinsDevRawConfig]
  TransientOnly = true
  """
  private let tunnelOperationGate = WinsTunnelOperationGate()
  private let statusManagerLock = NSLock()
  private var statusManagerEpoch: UInt64 = 0
  private var cachedStatusManager: NETunnelProviderManager?
  private var cachedStatusManagerLoadedAt: TimeInterval = 0

  private func invalidateStatusManagerCache() {
    statusManagerLock.lock()
    statusManagerEpoch &+= 1
    cachedStatusManager = nil
    cachedStatusManagerLoadedAt = 0
    statusManagerLock.unlock()
  }

  private func loadTunnelManagerForStatus(
    completion: @escaping (NETunnelProviderManager?, Error?) -> Void
  ) {
    statusManagerLock.lock()
    let epoch = statusManagerEpoch
    let now = ProcessInfo.processInfo.systemUptime
    if let manager = cachedStatusManager,
       now - cachedStatusManagerLoadedAt < 2 {
      statusManagerLock.unlock()
      completion(manager, nil)
      return
    }
    statusManagerLock.unlock()

    loadTunnelManager { manager, error in
      self.statusManagerLock.lock()
      guard self.statusManagerEpoch == epoch else {
        self.statusManagerLock.unlock()
        completion(nil, NSError(
          domain: "WinsStatusManagerCache",
          code: 1,
          userInfo: [
            NSLocalizedDescriptionKey:
              "The tunnel operation changed during the status load."
          ]
        ))
        return
      }
      if error == nil, let manager {
        self.cachedStatusManager = manager
        self.cachedStatusManagerLoadedAt =
          ProcessInfo.processInfo.systemUptime
      } else {
        self.cachedStatusManager = nil
        self.cachedStatusManagerLoadedAt = 0
      }
      self.statusManagerLock.unlock()
      completion(manager, error)
    }
  }

  private func saveTunnelManager(
    _ manager: NETunnelProviderManager,
    completion: @escaping (Error?) -> Void
  ) {
    invalidateStatusManagerCache()
    manager.saveToPreferences { error in
      self.invalidateStatusManagerCache()
      completion(error)
    }
  }

  private func removeTunnelManager(
    _ manager: NETunnelProviderManager,
    completion: @escaping (Error?) -> Void
  ) {
    invalidateStatusManagerCache()
    manager.removeFromPreferences { error in
      self.invalidateStatusManagerCache()
      completion(error)
    }
  }
  private var lastDartWinn3StartGeneration: Int?
  private var lastDartWinn3StartToken: Int?
  private var lastDartWinn3SelectionGeneration = ""
  private var lastDartWinn3FailedNode = ""
  private var lastWinn3ProofStatusGeneration = ""

  private var providerBundleIdentifier: String {
    let appBundleIdentifier = Bundle.main.bundleIdentifier ?? "org.winsvpn.app"
    return "\(appBundleIdentifier).PacketTunnel"
  }

  private static var isSimulatorRuntime: Bool {
    #if targetEnvironment(simulator)
      return true
    #else
      return false
    #endif
  }

  private var simulatorTunnelReadinessFields: [String: Any] {
    [
      "active": false,
      "engine_ready": false,
      "interface_open": false,
      "configuration_installed": false,
      "tunnel_healthy": false,
      "vpn_present": false,
      "vpn_validated": false,
      "network_extension_connected": false,
      "status": "simulator_unsupported",
      "platform": "ios",
      "provider_bundle_id": providerBundleIdentifier,
      "simulator_runtime": true,
      "provider_ready": false,
      "provider_status_available": false,
      "provider_status_current": false,
      "provider_message_probe_attempted": false,
      "provider_message_probe_supported": false,
      "provider_message_probe_healthy": false,
      "unsupported_reason": "packet_tunnel_requires_signed_physical_device"
    ]
  }

  static func register(with messenger: FlutterBinaryMessenger) {
    let bridge = WinsAppleTunnelBridge()
    let channel = FlutterMethodChannel(name: channelName, binaryMessenger: messenger)
    channel.setMethodCallHandler { call, result in
      bridge.handle(call, result: result)
    }
  }

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "checkDialerLaunch":
      result(false)
    case "isTelevision":
      // No Apple TV form factor; keep the phone path.
      result(false)
    case "getAppDocumentsDirectory":
      do {
        result(try appDocumentsDirectory().path)
      } catch {
        result(flutterError("APPLE_PRIVATE_STORAGE_FAILED", error))
      }
    case "getDeviceHardwareDetails":
      result(deviceHardwareDetails())
    case "getInstalledApps":
      result([])
    case "monotonicMilliseconds":
      result(Self.monotonicMillisecondsNow())
    case "launchSplitTunnelApp":
      result(FlutterError(
        code: "APPLE_PER_APP_VPN_MDM_REQUIRED",
        message: "Apple per-app VPN requires an MDM-managed app and VPN profile; consumer launcher-scoped bypass is unavailable.",
        details: nil
      ))
    case "getPowerOptimizationStatus":
      result(["ignoring_battery_optimizations": true])
    case "getTunnelReadiness":
      tunnelReadiness(result: result)
    case "getTunnelState":
      tunnelState(result: result)
    case "getTunnelActivitySnapshot":
      tunnelActivitySnapshot(result: result)
    case "launchExternalUrl":
      launchExternalUrl(call.arguments, result: result)
    case "loadOrCreateClientKeyPair":
      loadOrCreateClientKeyPair(call.arguments, result: result)
    case "loadExistingClientKeyPair":
      loadExistingClientKeyPair(call.arguments, result: result)
    case "replaceClientKeyPairForAccount":
      replaceClientKeyPairForAccount(call.arguments, result: result)
    case "startIosRawConfigLabTunnel":
      #if DEBUG
        startIosRawConfigLabTunnel(call.arguments, result: result)
      #else
        result(FlutterMethodNotImplemented)
      #endif
    case "deleteClientKeyPairForAccount":
      deleteClientKeyPairForAccount(call.arguments, result: result)
    case "clearWinnSessionSecret":
      clearWinnSessionSecret(call.arguments, result: result)
    case "loadOrCreateInstallId":
      loadOrCreateInstallId(result: result)
    case "measureDownloadMbps":
      measureDownloadMbps(call.arguments, result: result)
    case "measureUploadMbps":
      measureUploadMbps(call.arguments, result: result)
    case "cancelSpeedTestMeasurements":
      WinsAppleSpeedTestRegistry.cancelAll()
      result(true)
    case "probeVpnInternet":
      probeVpnInternet(call.arguments, result: result)
    case "persistVpnConfig":
      persistVpnConfig(call.arguments, result: result)
    case "readVpnConfig":
      readVpnConfig(result: result)
    case "deleteVpnConfig":
      deleteVpnConfig(result: result)
    case "purgeAppGroupContainer":
      purgeAppGroupContainer(result: result)
    case "purgeKeychainIdentity":
      purgeKeychainIdentity(call.arguments, result: result)
    case "purgeAccountDataKeepingCleanupJournal":
      result(WinsKeychainDuressPurge.purgeAccountDataKeepingCleanupJournal().statusFields)
    case "secureStateRead":
      secureStateRead(call.arguments, result: result)
    case "secureStateWrite":
      secureStateWrite(call.arguments, result: result)
    case "secureStateDelete":
      secureStateDelete(call.arguments, result: result)
    case "requestBatteryExemption":
      result(false)
    case "shareText":
      shareText(call.arguments, result: result)
    case "setLauncherCamouflage":
      setLauncherCamouflage(call.arguments, result: result)
    case "showAnnouncementNotification":
      showAnnouncementNotification(call.arguments, result: result)
    case "startTunnel":
      startTunnel(call.arguments, result: result)
    case "installWinn3ControlPlaneConfig":
      installWinn3ControlPlaneConfig(call.arguments, result: result)
    case "stopTunnel":
      stopTunnel(result: result)
    case "triggerCamouflageSwap":
      result(false)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func setLauncherCamouflage(_ arguments: Any?, result: @escaping FlutterResult) {
    guard let args = arguments as? [String: Any], let enabled = args["enabled"] as? Bool else {
      result(FlutterError(
        code: "INVALID_ICON_REQUEST",
        message: "Launcher camouflage requires an enabled boolean.",
        details: nil
      ))
      return
    }

    DispatchQueue.main.async {
      let application = UIApplication.shared
      guard application.supportsAlternateIcons else {
        result(FlutterError(
          code: "ALTERNATE_ICON_UNAVAILABLE",
          message: "This iOS or iPadOS installation does not support alternate app icons.",
          details: nil
        ))
        return
      }

      let targetIconName = WinsAppleAlternateIconPolicy.iconName(camouflageEnabled: enabled)
      guard application.alternateIconName != targetIconName else {
        // The icon already matches the requested state, but a previously
        // saved tunnel manager can still show a stale Settings-visible name
        // (e.g. an earlier resave attempt failed, or the profile predates
        // this resave path). Retry the resave instead of skipping it just
        // because there is no icon change to make (H-4).
        self.resaveExistingTunnelManagerDescriptionIfStale { resaveResult in
          if case let .failure(resaveError) = resaveResult {
            self.logTunnelManagerResaveFailure(resaveError)
          }
        }
        result(true)
        return
      }

      application.setAlternateIconName(targetIconName) { error in
        DispatchQueue.main.async {
          if let error {
            // REDACTED, like every other error this bridge returns.
            //
            // This was the one path that handed a raw, unbounded `NSError`
            // description straight to Dart. (Spelled that way on purpose: the
            // readiness guard forbids the literal, and a comment quoting it
            // would trip the guard the moment anyone tightens it to be
            // case-insensitive.) It matters more here than almost anywhere else:
            // this is the camouflage swap, so the text describes a failure to
            // change the app's disguise, and UIKit's message for it can name the
            // alternate icon set or the bundle it was looked up in. Leaking that
            // into Dart -- and from there into a log or a UI string -- on the one
            // code path whose entire purpose is concealment is exactly backwards.
            //
            // `flutterError(_:_:)` routes through
            // `WinsTunnelDiagnostics.redactedAppleErrorMessage`, which does NOT
            // try to pattern-match icon names or bundle ids out of the string.
            // It does something stronger: any error whose domain is not
            // `org.winsvpn.*` -- which every UIKit error is -- has its message
            // REPLACED WHOLESALE with a fixed constant. Nothing of the system
            // string survives, so there is no shape it has to anticipate. The
            // fragment blocklist only ever applies to errors this project itself
            // authored, whose text we control.
            //
            // The diagnosis is not lost: `nativeErrorDetails` attaches
            // `native_error_domain` and `native_error_code`, which are
            // Apple-minted identifiers carrying no user or environment data.
            result(self.flutterError("ALTERNATE_ICON_FAILED", error))
          } else {
            // If a VPN profile already exists (saved at last connect), its
            // Settings-visible name would otherwise keep showing whichever
            // identity was active back then -- e.g. connect while unlocked
            // (saved as "Win's VPN"), then background re-arms the decoy
            // with the tunnel still running. Best-effort: never fails or
            // delays the icon-swap result itself, but the outcome is now
            // reported through a completion and logged on failure instead
            // of being silently discarded (H-4).
            self.resaveExistingTunnelManagerDescriptionIfStale { resaveResult in
              if case let .failure(resaveError) = resaveResult {
                self.logTunnelManagerResaveFailure(resaveError)
              }
            }
            result(true)
          }
        }
      }
    }
  }

  /// MUST STAY `NSLog`. THIS IS THE WORST SITE IN THE APPLE TREE TO MAKE
  /// PUBLIC, and it looks harmless, so it is worth spelling out.
  ///
  /// This runs on the camouflage path: it is reached from the alternate-icon
  /// swap, whose whole purpose is that the VPN profile stops being called
  /// "Win's VPN" and starts being called `disguisedTunnelDescription`
  /// ("Calculator"). The message literal here contains the string the disguise
  /// exists to remove, and it is emitted at the exact moment the user arms the
  /// disguise.
  ///
  /// An `os_log` format string is always public -- `%{private}` redacts
  /// arguments, never the literal (measured 20260810; matrix in
  /// macos/Runner/AppDelegate.swift). So converting this would write
  /// "Win's VPN failed to resave tunnel manager description" into a persistent,
  /// `sysdiagnose`-collected log, timestamped to the moment of concealment. It
  /// would defeat the camouflage in the one artifact the user cannot inspect or
  /// clear, and it would do so on the device of someone who armed a decoy
  /// because they expected to be searched.
  ///
  /// Under `NSLog` the whole message renders as `(Foundation) <private>`.
  /// Redaction is the correct behaviour here. Its absence from `log show` is
  /// not evidence this method did not run.
  /// See docs/handoff/APPLE_NSLOG_REDACTION_AUDIT_20260810.md.
  private func logTunnelManagerResaveFailure(_ error: Error) {
    NSLog(
      "Win's VPN failed to resave tunnel manager description: %@",
      WinsTunnelDiagnostics.redactedAppleErrorMessage(error)
    )
  }

  /// Best-effort: keeps a previously saved tunnel manager's Settings-visible
  /// `localizedDescription`/`serverAddress` in sync with the currently active
  /// camouflage state. This never blocks or fails the alternate-icon swap
  /// that triggers it, but unlike the previous fire-and-forget version, the
  /// outcome is now reported through `completion` -- and every caller logs a
  /// failure instead of it being silently discarded (H-4).
  private func resaveExistingTunnelManagerDescriptionIfStale(
    completion: @escaping (Result<Void, Error>) -> Void = { _ in }
  ) {
    NETunnelProviderManager.loadAllFromPreferences { managers, loadError in
      if let loadError {
        completion(.failure(loadError))
        return
      }
      guard let manager = managers?.first(where: { self.isProviderBundleTunnelManager($0) }) else {
        // No tunnel manager has been saved yet for this provider bundle, so
        // there is nothing stale to correct.
        completion(.success(()))
        return
      }
      let expected = Self.currentTunnelDescription
      guard manager.localizedDescription != expected else {
        completion(.success(()))
        return
      }
      manager.localizedDescription = expected
      if let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol {
        tunnelProtocol.serverAddress = expected
        // RE-ASSERTED, NOT INHERITED. This block mutates a protocol object
        // handed back by `loadAllFromPreferences` and then saves it, so any
        // property the load round-trip failed to restore would be written
        // back at its default -- and this path runs on EVERY camouflage icon
        // swap, i.e. immediately after a camouflage or duress event, which is
        // the worst possible moment to quietly downgrade the tunnel. Whether
        // the round-trip actually preserves these is not something this
        // codebase can prove without a device, so it is not depended on:
        // re-asserting costs two lines and removes the question. Keep this in
        // sync with the connect path above, which is the authority.
        if #available(iOS 14.2, *) {
          tunnelProtocol.enforceRoutes = true
          tunnelProtocol.excludeLocalNetworks = true
        }
        manager.protocolConfiguration = tunnelProtocol
      }
      self.saveTunnelManager(manager) { saveError in
        if let saveError {
          completion(.failure(saveError))
        } else {
          completion(.success(()))
        }
      }
    }
  }

  private func appDocumentsDirectory() throws -> URL {
    let fileManager = FileManager.default
    let baseUrl = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
      ?? fileManager.temporaryDirectory
    let directory = baseUrl.appendingPathComponent("wins_vpn", isDirectory: true)
    try WinsIOSPrivateConfigStore.ensurePrivateDirectory(at: directory)
    try WinsIOSPrivateConfigStore.hardenExistingFile(
      at: directory.appendingPathComponent(WinsIOSPrivateConfigStore.fileName, isDirectory: false)
    )
    return directory
  }

  private func privateVpnConfigURL() throws -> URL {
    try appDocumentsDirectory().appendingPathComponent(
      WinsIOSPrivateConfigStore.fileName,
      isDirectory: false
    )
  }

  private func persistVpnConfig(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let config = args["config"] as? String,
      let data = config.data(using: .utf8),
      !data.isEmpty,
      data.count <= WinsTunnelConfig.maxRuntimeConfigFileBytes,
      (try? JSONSerialization.jsonObject(with: data)) is [String: Any]
    else {
      result(FlutterError(
        code: "APPLE_PRIVATE_CONFIG_INVALID",
        message: "Private VPN configuration payload is invalid.",
        details: nil
      ))
      return
    }
    do {
      try WinsIOSPrivateConfigStore.writeString(config, to: privateVpnConfigURL())
      result(true)
    } catch {
      result(flutterError("APPLE_PRIVATE_CONFIG_WRITE_FAILED", error))
    }
  }

  private func readVpnConfig(result: @escaping FlutterResult) {
    do {
      let value = try WinsIOSPrivateConfigStore.readString(
        from: privateVpnConfigURL(),
        maximumBytes: WinsTunnelConfig.maxRuntimeConfigFileBytes
      )
      if let value {
        guard
          let data = value.data(using: .utf8),
          (try? JSONSerialization.jsonObject(with: data)) is [String: Any]
        else {
          throw NSError(
            domain: "org.winsvpn.IOSPrivateConfigStore",
            code: WinsIOSPrivateConfigStore.writeFailedCode,
            userInfo: [NSLocalizedDescriptionKey: "Private VPN configuration is not a JSON object."]
          )
        }
      }
      result(value)
    } catch {
      result(flutterError("APPLE_PRIVATE_CONFIG_READ_FAILED", error))
    }
  }

  private func deleteVpnConfig(result: @escaping FlutterResult) {
    do {
      try WinsIOSPrivateConfigStore.delete(at: privateVpnConfigURL())
      result(true)
    } catch {
      result(flutterError("APPLE_PRIVATE_CONFIG_DELETE_FAILED", error))
    }
  }

  /// Clears the App Group container the host app shares with the Packet
  /// Tunnel extension. Reached from the duress wipe in `lib/main.dart`.
  ///
  /// # What this removes that nothing else did
  ///
  /// `Tunnel/latest_tunnel.conf` -- the appex handoff file. Its `PrivateKey`
  /// is the Keychain placeholder, but everything around it is plaintext: the
  /// gateway `Endpoint` host:port, the gateway `PublicKey`, this device's own
  /// `ClientPublicKey`, `Address`, `DNS`, the full AmneziaWG obfuscation
  /// parameter set (Jc/Jmin/Jmax/S1-S4/H1-H4) and the `[winn]` carrier
  /// endpoint and session id. Beside it, `Tunnel/latest_tunnel.json` and
  /// `Tunnel/latest_status.json`, and -- once provisioning exists --
  /// `winn/credentials/`, which is where `WinsWinnCarrierProfile` resolves
  /// this device's ML-DSA seed, mTLS client key and SPA knock key.
  ///
  /// # WHEN THIS IS SAFE RELATIVE TO THE SESSION LIFECYCLE
  ///
  /// Safe with no session running, and the duress path guarantees that: it
  /// awaits `stopTunnel` before it wipes.
  ///
  /// It would also not wedge a session that is already up. The provider reads
  /// the handoff file exactly ONCE, in `startTunnel` -- `loadRuntimeConfig`
  /// has a single call site in both `ios/PacketTunnel/PacketTunnelProvider.swift`
  /// and its macOS sibling -- and keeps the parsed config in memory for the
  /// life of the session; `wake()` re-uses `activeConfig` and never re-reads
  /// the file. This app registers no `NEOnDemand` rules anywhere, so nothing
  /// restarts a tunnel behind the user and finds the file gone. The next start
  /// is user-initiated and `persistSharedTunnelConfig` rewrites the file
  /// before the provider is asked for anything.
  ///
  /// The one thing a mid-session purge does NOT achieve is emptiness: a live
  /// provider re-creates `Tunnel/latest_status.json` on its next status write.
  /// Stop first -- which is why the ordering in `_armDuress` is load-bearing
  /// and not incidental.
  private func purgeAppGroupContainer(result: @escaping FlutterResult) {
    let fileManager = FileManager.default
    guard let containerUrl = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier
    ) else {
      // Reported, never swallowed. "The container could not be resolved" and
      // "the container is now empty" are different outcomes, and a wipe that
      // cannot tell them apart is a wipe the user cannot trust.
      result(WinsAppGroupDuressPurge.containerUnavailableReport.statusFields)
      return
    }
    result(
      WinsAppGroupDuressPurge.purge(
        containerURL: containerUrl,
        fileManager: fileManager
      ).statusFields
    )
  }

  /// Clears the identity-bearing Keychain items on the duress path. Reached
  /// from `_sweepAppStorageForDuress` in `lib/main.dart`.
  ///
  /// # What this removes that nothing else did
  ///
  /// `org.winsvpn.client-keypair` -- the WireGuard client PRIVATE KEY, in the
  /// shared access group the appex also reads. Beside it
  /// `org.winsvpn.tunnel-secrets` (peer preshared key, Xray UUID) and
  /// `org.winsvpn.install-identity` (the stable per-install id the backend
  /// knows this handset by, sent as `device_id`/`device_fingerprint`).
  ///
  /// KEYCHAIN ITEMS SURVIVE APP DELETION ON iOS. That is what makes this the
  /// worst of the leftovers rather than one more of them: uninstalling does
  /// not remove it, and until the App Group purge landed an hour before this,
  /// `Tunnel/latest_tunnel.conf` carried the matching PUBLIC key in the clear
  /// -- both halves of an attributable client identity on one seized phone.
  ///
  /// # Why not the existing `deleteClientKeyPairForAccount`
  ///
  /// That one is scoped to a single account, correctly, because it serves
  /// logout and Deactivate Device. Duress is the opposite: every scope this
  /// install ever used has to go, including accounts switched away from and
  /// the pre-scoping `wireguard-x25519-v2` item. See `WinsKeychainDuressPurge`.
  ///
  /// # WHEN THIS IS SAFE RELATIVE TO THE SESSION LIFECYCLE
  ///
  /// Stop the tunnel first, which `_armDuress` does. The reason is the mirror
  /// image of the App Group container's: the appex only ever READS these
  /// stores (`loadExisting` at `PacketTunnelProvider.swift`, no write anywhere
  /// in either provider), so a live appex cannot re-create a purged key -- but
  /// the HOST does, through `loadOrCreate` on the connect path
  /// (`loadOrCreateClientKeyPair` and `persistSharedTunnelConfig` below). A
  /// connect in flight would mint a fresh key pair straight back into the
  /// store the wipe had just emptied. Stopping first closes that window, and
  /// it also avoids making a starting tunnel fail visibly at the worst
  /// possible moment.
  ///
  /// The report carries counts and fixed labels only. It may never carry an
  /// account: `WinsClientKeyStore`'s accounts embed the account scope token.
  private func purgeKeychainIdentity(_ arguments: Any?, result: @escaping FlutterResult) {
    let preserveEmergencyQueue =
      ((arguments as? [String: Any])?["preserveEmergencyQueue"] as? NSNumber)?.boolValue ?? false
    result(
      WinsKeychainDuressPurge.purge(
        preserveEmergencyQueue: preserveEmergencyQueue
      ).statusFields
    )
  }

  private func secureStateRead(_ arguments: Any?, result: @escaping FlutterResult) {
    guard let args = arguments as? [String: Any], let name = args["name"] as? String else {
      result(FlutterError(
        code: "APPLE_SECURE_STATE_REQUEST_INVALID",
        message: "Secure state read requires a name string.",
        details: nil
      ))
      return
    }
    do {
      result(try WinsSecureStateStore.read(name: name))
    } catch {
      result(flutterError("APPLE_SECURE_STATE_READ_FAILED", error))
    }
  }

  private func secureStateWrite(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let name = args["name"] as? String,
      let value = args["value"] as? String
    else {
      result(FlutterError(
        code: "APPLE_SECURE_STATE_REQUEST_INVALID",
        message: "Secure state write requires a name and value string.",
        details: nil
      ))
      return
    }
    do {
      try WinsSecureStateStore.write(name: name, value: value)
      result(true)
    } catch {
      result(flutterError("APPLE_SECURE_STATE_WRITE_FAILED", error))
    }
  }

  private func secureStateDelete(_ arguments: Any?, result: @escaping FlutterResult) {
    guard let args = arguments as? [String: Any], let name = args["name"] as? String else {
      result(FlutterError(
        code: "APPLE_SECURE_STATE_REQUEST_INVALID",
        message: "Secure state delete requires a name string.",
        details: nil
      ))
      return
    }
    do {
      try WinsSecureStateStore.delete(name: name)
      result(true)
    } catch {
      result(flutterError("APPLE_SECURE_STATE_DELETE_FAILED", error))
    }
  }

  private func measureDownloadMbps(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let rawUrl = args["url"] as? String,
      let url = URL(string: rawUrl)
    else {
      result(nil)
      return
    }
    let streams = (args["streamCount"] as? NSNumber)?.intValue ?? 8
    let durationMilliseconds = (args["durationMilliseconds"] as? NSNumber)?.doubleValue ?? 6000
    WinsAppleDownloadSpeedSampler.measure(
      url: url,
      streamCount: streams,
      duration: durationMilliseconds / 1000
    ) { mbps in
      result(mbps.map { ["mbps": $0, "engine": "urlsession"] })
    }
  }

  private func measureUploadMbps(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let rawUrl = args["url"] as? String,
      let url = URL(string: rawUrl)
    else {
      result(nil)
      return
    }
    let streams = (args["streamCount"] as? NSNumber)?.intValue ?? 4
    let bytesPerStream = (args["bytesPerStream"] as? NSNumber)?.intValue ?? (48 * 1024 * 1024)
    let durationMilliseconds = (args["durationMilliseconds"] as? NSNumber)?.doubleValue ?? 6000
    WinsAppleUploadSpeedSampler.measure(
      url: url,
      streamCount: streams,
      bytesPerStream: bytesPerStream,
      duration: durationMilliseconds / 1000
    ) { mbps in
      result(mbps.map { ["mbps": $0, "engine": "urlsession"] })
    }
  }

  private func deviceHardwareDetails() -> [String: String] {
    [
      "device_model": machineIdentifier(),
      "system_name": UIDevice.current.systemName,
      "system_version": UIDevice.current.systemVersion,
      "platform": "ios"
    ]
  }

  // M-15: native monotonic-clock reading for the Dart PIN-lockout state
  // machine. `_monotonicNowMs()` in lib/main.dart already calls this exact
  // method name over this same "wins_vpn/tunnel" channel and degrades to
  // wall-clock-only enforcement on any failure (MissingPluginException,
  // null, timeout), so this handler is purely additive. `systemUptime` is
  // seconds since boot and, unlike `Date()`/`DateTime.now()`, cannot be
  // rewound via Settings to shorten a PIN lockout.
  private static func monotonicMillisecondsNow() -> Int {
    Int(ProcessInfo.processInfo.systemUptime * 1000)
  }

  private func launchExternalUrl(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let url = WinsAppleExternalUrl.safeUrl(from: args["url"] as? String)
    else {
      result(FlutterError(code: "BAD_URL", message: "Missing or invalid URL.", details: nil))
      return
    }

    DispatchQueue.main.async {
      UIApplication.shared.open(url, options: [:]) { opened in
        result(opened)
      }
    }
  }

  private func shareText(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let share = WinsAppleShare.sharePayload(
        title: args["title"] as? String,
        text: args["text"] as? String
      )
    else {
      result(false)
      return
    }

    DispatchQueue.main.async {
      guard let presenter = Self.topViewController() else {
        result(false)
        return
      }
      let activityViewController = UIActivityViewController(
        activityItems: [share.text],
        applicationActivities: nil
      )
      if let title = share.title {
        activityViewController.setValue(title, forKey: "subject")
      }
      if let popover = activityViewController.popoverPresentationController {
        popover.sourceView = presenter.view
        popover.sourceRect = CGRect(
          x: presenter.view.bounds.midX,
          y: presenter.view.bounds.midY,
          width: 0,
          height: 0
        )
        popover.permittedArrowDirections = []
      }
      presenter.present(activityViewController, animated: true) {
        result(true)
      }
    }
  }

  private func showAnnouncementNotification(_ arguments: Any?, result: @escaping FlutterResult) {
    let args = arguments as? [String: Any] ?? [:]
    guard let notification = WinsAppleNotification.announcementPayload(
      title: args["title"] as? String,
      body: args["body"] as? String
    ) else {
      result(false)
      return
    }

    // Neither half of an announcement is authored by this app -- the title
    // comes from Dart and the body from the server -- so while camouflage is
    // active neither can be trusted to be free of the real identity, and a
    // banner is rendered on the lock screen where it is most likely to be
    // read by somebody other than the user. Replace both wholesale rather
    // than filter. The real announcement is still delivered and is read
    // inside the app after the PIN unlock, which is where it was ever safe
    // to read. Mirrors MainActivity.showAnnouncementNotification on Android.
    let content = UNMutableNotificationContent()
    if Self.isCamouflageActive {
      content.title = Self.disguisedTunnelDescription
      content.body = "You have a new message."
    } else {
      content.title = notification.title
      content.body = notification.body
    }
    content.sound = .default

    let center = UNUserNotificationCenter.current()
    let scheduleNotification = {
      let request = UNNotificationRequest(
        identifier: "winsvpn-announcement-\(UUID().uuidString)",
        content: content,
        trigger: nil
      )
      center.add(request) { error in
        DispatchQueue.main.async {
          result(error == nil)
        }
      }
    }

    center.getNotificationSettings { settings in
      switch settings.authorizationStatus {
      case .authorized, .provisional, .ephemeral:
        scheduleNotification()
      case .notDetermined:
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
          guard granted else {
            DispatchQueue.main.async {
              result(false)
            }
            return
          }
          scheduleNotification()
        }
      case .denied:
        DispatchQueue.main.async {
          result(false)
        }
      @unknown default:
        DispatchQueue.main.async {
          result(false)
        }
      }
    }
  }

  private func loadOrCreateClientKeyPair(_ arguments: Any?, result: @escaping FlutterResult) {
    do {
      result(try WinsClientKeyStore.loadOrCreate(accountScope: accountScope(from: arguments)).dictionary)
    } catch {
      result(flutterError("APPLE_CLIENT_KEYPAIR_FAILED", error))
    }
  }

  private func loadExistingClientKeyPair(_ arguments: Any?, result: @escaping FlutterResult) {
    do {
      result(try WinsClientKeyStore.loadExisting(
        accountScope: accountScope(from: arguments)
      )?.dictionary)
    } catch {
      result(flutterError("APPLE_CLIENT_KEYPAIR_FAILED", error))
    }
  }

  private func replaceClientKeyPairForAccount(
    _ arguments: Any?,
    result: @escaping FlutterResult
  ) {
    guard let values = arguments as? [String: Any],
          let privateKey = values["privateKey"] as? String,
          let publicKey = values["publicKey"] as? String else {
      result(FlutterError(
        code: "APPLE_CLIENT_KEYPAIR_REPLACE_INVALID",
        message: "Client key replacement requires a complete key pair.",
        details: nil
      ))
      return
    }
    do {
      try WinsClientKeyStore.replace(
        WinsClientKeyPair(privateKey: privateKey, publicKey: publicKey),
        accountScope: accountScope(from: arguments)
      )
      result(true)
    } catch {
      result(flutterError("APPLE_CLIENT_KEYPAIR_REPLACE_FAILED", error))
    }
  }

  #if DEBUG
    /// DEV-ONLY raw-config lab seam. The raw document crosses Flutter's channel,
    /// but the existing device private key never does: substitution and the call
    /// into the shipping `startTunnel` function both happen in this native frame.
    /// This also never creates a Keychain item.
    private func startIosRawConfigLabTunnel(
      _ arguments: Any?,
      result: @escaping FlutterResult
    ) {
      guard
        let args = arguments as? [String: Any],
        let rawTemplate = args["configTemplate"] as? String,
        !rawTemplate.isEmpty
      else {
        result(FlutterError(
          code: "APPLE_RAW_CONFIG_LAB_BAD_TEMPLATE",
          message: "The iOS raw-config lab requires a non-empty config template.",
          details: nil
        ))
        return
      }
      let placeholder = "__WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__"
      guard rawTemplate.components(separatedBy: placeholder).count == 2 else {
        result(FlutterError(
          code: "APPLE_RAW_CONFIG_LAB_BAD_PLACEHOLDER",
          message: "The iOS raw-config lab template must contain exactly one Keychain placeholder.",
          details: nil
        ))
        return
      }
      do {
        guard let keyPair = try WinsClientKeyStore.loadExisting(
          accountScope: accountScope(from: arguments)
        ) else {
          result(FlutterError(
            code: "APPLE_RAW_CONFIG_LAB_KEYPAIR_MISSING",
            message: "The raw-config lab requires an existing device Keychain identity; it will not create one.",
            details: nil
          ))
          return
        }
        var startArguments = args
        startArguments.removeValue(forKey: "configTemplate")
        startArguments["config"] = rawTemplate.replacingOccurrences(
          of: placeholder,
          with: keyPair.privateKey
        )
        // Pass the exact pair loaded above into the shipping start path. Without
        // this override, startTunnel would call loadOrCreate again; that usually
        // reloads the same item, but the lab's "never create a credential" rule
        // must be structural rather than relying on a prior lookup having won a
        // race against Keychain mutation.
        startTunnel(
          startArguments,
          existingClientKeyPair: keyPair,
          transientRawConfigLab: true,
          result: result
        )
      } catch {
        result(flutterError("APPLE_RAW_CONFIG_LAB_KEYPAIR_FAILED", error))
      }
    }
  #endif

  private func accountScope(from arguments: Any?) -> String {
    (arguments as? [String: Any])?["accountScope"] as? String ?? ""
  }

  // L-5: deactivation must remove every Apple-native Keychain item scoped to
  // this account, not just the WireGuard client key pair. Skipping
  // WinsTunnelSecretStore here would leave the peer preshared key and Xray
  // UUID behind after "deactivate", resumable by anything that can still
  // read this device's Keychain. Both stores are always attempted -
  // regardless of whether the first delete failed - so one store's failure
  // never causes the other to be skipped; only the first failure is
  // reported back (flutterError already redacts it via
  // WinsTunnelDiagnostics before it reaches Dart/logs).
  private func deleteClientKeyPairForAccount(_ arguments: Any?, result: @escaping FlutterResult) {
    let scope = accountScope(from: arguments)
    var firstError: Error?
    do {
      try WinsTunnelSecretStore.delete(accountScope: scope)
    } catch {
      firstError = error
    }
    do {
      try WinsClientKeyStore.delete(accountScope: scope)
    } catch {
      if firstError == nil {
        firstError = error
      }
    }
    if let firstError {
      result(flutterError("APPLE_CLIENT_KEYPAIR_DELETE_FAILED", firstError))
    } else {
      result(true)
    }
  }

  // Session end (Sol, OI-KEYSAPP-13): drops a hub-served winn/3 transition
  // key from the tunnel-secrets Keychain item the Packet Tunnel extension
  // restores from, and nothing else. `keepStaticPrivate` is the device's own
  // v3 key for this scope, which is kept. The AWG identity is untouched.
  private func clearWinnSessionSecret(_ arguments: Any?, result: @escaping FlutterResult) {
    let scope = accountScope(from: arguments)
    let keep = (arguments as? [String: Any])?["keepStaticPrivate"] as? String ?? ""
    guard !scope.isEmpty else {
      result(false)
      return
    }
    do {
      try WinsTunnelSecretStore.clearWinnStaticPrivate(accountScope: scope, keeping: keep)
      result(true)
    } catch {
      result(flutterError("APPLE_WINN_SESSION_SECRET_CLEAR_FAILED", error))
    }
  }

  private func loadOrCreateInstallId(result: @escaping FlutterResult) {
    do {
      result(try WinsInstallIdentityStore.loadOrCreate())
    } catch {
      result(flutterError("APPLE_INSTALL_ID_FAILED", error))
    }
  }

  private func tunnelState(result: @escaping FlutterResult) {
    guard !Self.isSimulatorRuntime else {
      result(false)
      return
    }

    loadTunnelManagerForStatus { manager, error in
      if let error = error {
        result(self.flutterError("APPLE_TUNNEL_STATE_FAILED", error))
        return
      }
      result(manager?.connection.status == .connected)
    }
  }

  private func tunnelActivitySnapshot(result: @escaping FlutterResult) {
    guard !Self.isSimulatorRuntime else {
      result(WinsAppleTunnelActivitySnapshot.value(for: nil))
      return
    }

    loadTunnelManagerForStatus { manager, error in
      guard error == nil else {
        result(WinsAppleTunnelActivitySnapshot.value(for: nil, known: false))
        return
      }
      result(WinsAppleTunnelActivitySnapshot.value(for: manager?.connection.status))
    }
  }

  private func tunnelReadiness(result: @escaping FlutterResult) {
    guard !Self.isSimulatorRuntime else {
      result(simulatorTunnelReadinessFields)
      return
    }

    loadTunnelManagerForStatus { manager, error in
      if let error = error {
        var readiness: [String: Any] = [
          "active": false,
          "engine_ready": false,
          "configuration_installed": false,
          "tunnel_healthy": false,
          "platform": "ios",
          "provider_bundle_id": self.providerBundleIdentifier,
          "provider_status_current": false,
          "provider_ready": false
        ]
        readiness.merge(WinsTunnelDiagnostics.redactedAppleErrorFields(error)) { _, new in new }
        self.applyWinn3NativeStartReadiness(to: &readiness, expectedStatusGeneration: nil)
        result(readiness)
        return
      }
      let status = manager?.connection.status ?? .invalid
      let connected = status == .connected
      var readiness: [String: Any] = [
        "active": connected,
        "engine_ready": false,
        "interface_open": connected,
        "configuration_installed": manager != nil,
        "tunnel_healthy": false,
        "vpn_present": connected,
        "vpn_validated": false,
        "network_extension_connected": connected,
        "status": Self.statusName(status),
        "platform": "ios",
        "provider_bundle_id": self.providerBundleIdentifier
      ]
      readiness.merge(
        self.latestProviderStatusFields(
          expectedStatusGeneration: self.expectedStatusGeneration(from: manager)
        )
      ) { _, new in new }
      self.providerHealthProbeFields(for: manager) { probeFields in
        readiness.merge(probeFields) { _, new in new }
        // Handling the authenticated health message advances the shared
        // provider status from config_saved to app_message before its reply is
        // delivered. Re-read that same-generation status so readiness cannot
        // combine a fresh reply with stale pre-start engine fields.
        readiness.merge(
          self.latestProviderStatusFields(
            expectedStatusGeneration: self.expectedStatusGeneration(from: manager)
          )
        ) { _, new in new }
        let managerInvalidAfterConfigSave = status == .invalid
          && (readiness["provider_stage"] as? String) == "config_saved"
        readiness["vpn_manager_invalid_after_config_save"] = managerInvalidAfterConfigSave
        readiness["vpn_configuration_permission_pending"] = managerInvalidAfterConfigSave
        readiness["provider_status_current"] = WinsAppleReadiness.providerStatusCurrent(readiness)
        readiness["provider_ready"] = WinsAppleReadiness.providerReady(readiness)
        self.applyWinn3NativeStartReadiness(
          to: &readiness,
          expectedStatusGeneration: self.expectedStatusGeneration(from: manager).generation
        )
        if let traffic = self.activeTunnelTrafficBytes() {
          readiness["traffic_rx_bytes"] = traffic.rx
          readiness["traffic_tx_bytes"] = traffic.tx
          readiness["tun_rx_bytes"] = traffic.rx
          readiness["tun_tx_bytes"] = traffic.tx
        } else if connected {
          readiness["traffic_rx_bytes"] = 0
          readiness["traffic_tx_bytes"] = 0
          readiness["tun_rx_bytes"] = 0
          readiness["tun_tx_bytes"] = 0
        }
        result(readiness)
      }
    }
  }

  private func activeTunnelTrafficBytes() -> (rx: Int64, tx: Int64)? {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
    defer { freeifaddrs(first) }

    var totalRx: Int64 = 0
    var totalTx: Int64 = 0
    var foundAny = false

    var ptr: UnsafeMutablePointer<ifaddrs>? = first
    while let curr = ptr {
      let name = String(cString: curr.pointee.ifa_name)
      if name.hasPrefix("utun"), curr.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_LINK) {
        if let data = curr.pointee.ifa_data {
          let ifd = data.assumingMemoryBound(to: if_data.self).pointee
          let rx = Int64(ifd.ifi_ibytes)
          let tx = Int64(ifd.ifi_obytes)
          if rx > 0 || tx > 0 {
            totalRx += rx
            totalTx += tx
            foundAny = true
          }
        }
      }
      ptr = curr.pointee.ifa_next
    }
    return foundAny ? (rx: totalRx, tx: totalTx) : nil
  }

  private func startTunnel(
    _ arguments: Any?,
    existingClientKeyPair: WinsClientKeyPair? = nil,
    transientRawConfigLab: Bool = false,
    result: @escaping FlutterResult
  ) {
    guard
      let args = arguments as? [String: Any],
      let config = args["config"] as? String,
      !config.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else {
      result(FlutterError(code: "BAD_CONFIG", message: "Missing VPN config.", details: nil))
      return
    }

    guard !Self.isSimulatorRuntime else {
      result(flutterError(
        "APPLE_TUNNEL_UNSUPPORTED",
        "Packet Tunnel Provider requires a signed physical iPhone or iPad build."
      ))
      return
    }

    let operationToken = tunnelOperationGate.begin(perform: {
      self.invalidateStatusManagerCache()
    })
    let accountScope = accountScope(from: arguments)
    let parsedConfig: WinsTunnelConfig
    let sharedConfigUrl: URL
    let clientKeyPair: WinsClientKeyPair
    let statusGeneration = UUID().uuidString
    do {
      parsedConfig = try WinsTunnelConfig.parseAndValidate(config)
      if parsedConfig.winn3Enabled,
         WinsWinn3SelectedNodeCaller.exactSlug(
           arguments: arguments,
           parsedConfig: parsedConfig
         ) == nil {
        result(FlutterError(
          code: "WINN3_SELECTED_NODE_REQUIRED",
          message: "Winn v3 requires the exact user-selected node identity.",
          details: nil
        ))
        return
      }
      if let existingClientKeyPair {
        clientKeyPair = existingClientKeyPair
      } else {
        clientKeyPair = try WinsClientKeyStore.loadOrCreate(accountScope: accountScope)
      }
      try parsedConfig.validateInterfacePrivateKeyMatches(clientKeyPair)
      // Save the peer preshared key and Xray UUID to the same shared Keychain
      // the Packet Tunnel extension reads from *before* writing the redacted
      // config to the App Group file, so a fresh redacted file is never
      // written ahead of the secrets it depends on at restore time.
      let tunnelSecrets = WinsTunnelSecrets(
        presharedKey: parsedConfig.peerPresharedKey,
        xrayUUID: parsedConfig.xrayRuntimeConfig?.uuid ?? "",
        winnStaticPrivate: parsedConfig.winn3StaticPrivate,
        winnAdmissionKey: parsedConfig.winn3AdmissionKey,
        winnPSK: parsedConfig.winn3PSK
      )
      if !tunnelSecrets.isEmpty {
        try WinsTunnelSecretStore.save(tunnelSecrets, accountScope: accountScope)
      }
      sharedConfigUrl = try persistSharedTunnelConfig(
        transientRawConfigLab
          ? Self.transientRawConfigLabFallbackDocument
          : config,
        parsedConfig: parsedConfig,
        statusGeneration: statusGeneration,
        transientRawConfigLab: transientRawConfigLab
      )
    } catch let error as WinsTunnelValidationError {
      result(flutterError("APPLE_TUNNEL_CONFIG_INVALID", error.nsError))
      return
    } catch {
      result(flutterError("APPLE_TUNNEL_CONFIG_INVALID", error))
      return
    }
    if !consumeWinn3CoverGrantIfNeeded(
      winnEnabled: parsedConfig.winnEnabled,
      arguments: arguments,
      result: result
    ) {
      return
    }
    rememberWinn3StartIdentities(
      winnEnabled: parsedConfig.winnEnabled,
      arguments: arguments,
      statusGeneration: statusGeneration
    )

    loadTunnelManager { manager, error in
      guard self.tunnelOperationGate.isCurrent(operationToken) else {
        result(false)
        return
      }
      if let error = error {
        result(self.flutterError("APPLE_TUNNEL_LOAD_FAILED", error))
        return
      }

      let manager = manager ?? NETunnelProviderManager()
      let tunnelProtocol = NETunnelProviderProtocol()
      tunnelProtocol.providerBundleIdentifier = self.providerBundleIdentifier
      tunnelProtocol.serverAddress = Self.currentTunnelDescription
      // ROUTING POSTURE OF THE RUNNING TUNNEL. Not a kill switch, and nothing
      // here claims to be one: both properties live in the tunnel's own
      // network settings and evaporate the moment it stops, so a stopped
      // tunnel behaves exactly as it does today.
      //
      // `enforceRoutes` closes the one real leak the current settings cannot:
      // a MORE SPECIFIC route on the physical interface beats the tunnel's
      // 0.0.0.0/0 and carries that traffic in the clear. With this set, the
      // tunnel's routes win regardless of specificity.
      //
      // `excludedRoutes` STILL APPLY under `enforceRoutes`, which is what
      // makes it safe here: the engine's own outer socket carve-out
      // (`transportIPv4ExclusionRoute`, installed from the first bootstrap
      // posture in PacketTunnelProvider) is untouched. That is also the
      // codebase-specific reason `includeAllNetworks` is deliberately NOT set
      // -- it ignores excluded routes, so it would capture the transport's
      // own path to the endpoint, on top of the captive-portal deadlock that
      // ruled it out for this population.
      //
      // `excludeLocalNetworks` is set EXPLICITLY, and set to true, for two
      // reasons. First, `enforceRoutes` on its own would take the local link
      // with it, and on shared Wi-Fi the captive portal IS a local resource:
      // the portal must be passed before the internet exists, and the tunnel
      // cannot connect until it does. That is a deadlock, not a degradation,
      // and it fails silently -- the user concludes the app is broken, or
      // that they have been detected. Second, its default differs between iOS
      // and macOS, so stating it makes both targets behave identically
      // instead of inheriting two different answers from the framework.
      //
      // Gated together at 14.2 (`excludeLocalNetworks`' floor) rather than at
      // 14.0 (`enforceRoutes`' floor) on purpose: setting `enforceRoutes`
      // alone on 14.0/14.1 is precisely the local-capture deadlock above.
      if #available(iOS 14.2, *) {
        tunnelProtocol.enforceRoutes = true
        tunnelProtocol.excludeLocalNetworks = true
      }
      tunnelProtocol.providerConfiguration = [
        "wins_manager_signature": Self.tunnelManagerSignature,
        "app_group_id": Self.appGroupIdentifier,
        "shared_config_path": sharedConfigUrl.path,
        "status_generation": statusGeneration,
        "client_public_key": clientKeyPair.publicKey,
        "client_key_account_scope": accountScope,
        "shared_config_private_key_redacted": true,
        "client_key_pair_verified": true,
        "peer_endpoint_kind": parsedConfig.peerEndpointKind,
        "xray_enabled": parsedConfig.xrayEnabled,
        "updated_at": ISO8601DateFormatter().string(from: Date())
      ]
      manager.localizedDescription = Self.currentTunnelDescription
      manager.protocolConfiguration = tunnelProtocol
      manager.isEnabled = true

      self.saveTunnelManager(manager) { saveError in
        guard self.tunnelOperationGate.isCurrent(operationToken) else {
          result(false)
          return
        }
        if let saveError = saveError {
          result(self.flutterError("APPLE_TUNNEL_SAVE_FAILED", saveError))
          return
        }
        // NetworkExtension requires the saved manager instance to reload its
        // preference-backed configuration before its connection is started.
        // Reloading the whole manager collection here can return a manager
        // whose connection remains .invalid on physical iOS even though the
        // user approved the system VPN configuration prompt.
        manager.loadFromPreferences { loadError in
          guard self.tunnelOperationGate.isCurrent(operationToken) else {
            result(false)
            return
          }
          if let loadError = loadError {
            result(self.flutterError("APPLE_TUNNEL_RELOAD_FAILED", loadError))
            return
          }
          var startError: Error?
          let startedCurrentOperation = self.tunnelOperationGate.performIfCurrent(operationToken) {
            do {
              try manager.connection.startVPNTunnel(
                options: WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(
                  rawConfig: config,
                  clientPublicKey: clientKeyPair.publicKey,
                  accountScope: accountScope,
                  statusGeneration: statusGeneration,
                  arguments: arguments,
                  parsedConfig: parsedConfig
                )
              )
            } catch {
              startError = error
            }
          }
          guard startedCurrentOperation else {
            result(false)
            return
          }
          self.completeTunnelStartAfterProviderProof(
            requiresWinn3Proof: parsedConfig.winnEnabled,
            expectedGeneration: statusGeneration,
            operationToken: operationToken,
            startError: startError,
            result: result
          )
        }
      }
    }
  }

  private func stopTunnel(result: @escaping FlutterResult) {
    guard !Self.isSimulatorRuntime else {
      result(true)
      return
    }

    let operationToken = tunnelOperationGate.begin(perform: {
      self.invalidateStatusManagerCache()
    })
    loadTunnelManager { manager, error in
      guard self.tunnelOperationGate.isCurrent(operationToken) else {
        result(false)
        return
      }
      if let error = error {
        result(self.flutterError("APPLE_TUNNEL_STOP_FAILED", error))
        return
      }
      let stoppedCurrentOperation = self.tunnelOperationGate.performIfCurrent(operationToken) {
        manager?.connection.stopVPNTunnel()
      }
      result(stoppedCurrentOperation)
    }
  }

  /// Shipping control-plane delivery: installs a `NETunnelProviderProtocol`
  /// pointing at a redacted App Group config with protocol/carrier metadata.
  ///
  /// This is the delivery half of the iOS control-plane emitter. It uses the
  /// same `loadAllFromPreferences` (via `loadTunnelManager`) + save shape as
  /// every other manager routine in this bridge, so the installed config
  /// survives relaunch without requiring a transient `startVPNTunnel(options:)`
  /// payload. It NEVER starts the tunnel: the config is installed and the
  /// connection is left untouched, which is what makes this a delivery path
  /// rather than a session.
  ///
  /// The incoming document is re-validated by the shipping
  /// `WinsTunnelConfig.parseAndValidate` and must be a winn/3 standalone
  /// config -- a relay carrier or a `protocol_version` other than `winn/3` is
  /// refused so the delivery path can never install a relay profile. On the
  /// Simulator, NetworkExtension cannot persist a configuration, so the method
  /// returns an explicit policy refusal instead of attempting a save.
  private func installWinn3ControlPlaneConfig(
    _ arguments: Any?,
    result: @escaping FlutterResult
  ) {
    guard
      let args = arguments as? [String: Any],
      let config = args["config"] as? String,
      !config.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      config.utf8.count <= WinsTunnelConfig.maxRuntimeConfigFileBytes
    else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_BAD_CONFIG",
        message: "The winn/3 control-plane config is missing or oversize.",
        details: nil
      ))
      return
    }
    let protocolVersion = (args["protocolVersion"] as? String)
      .flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      ?? Self.winn3ControlPlaneProtocolVersion
    let carrier = (args["carrier"] as? String)
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
      ?? Self.winn3ControlPlaneCarrier

    guard protocolVersion == Self.winn3ControlPlaneProtocolVersion else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_PROTOCOL_VERSION",
        message: "The winn/3 control-plane delivery requires protocol_version winn/3.",
        details: nil
      ))
      return
    }
    guard carrier == Self.winn3ControlPlaneCarrier else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_CARRIER",
        message: "The winn/3 control-plane delivery refuses a non-winn3 carrier.",
        details: nil
      ))
      return
    }

    // Dart replaces the Interface private key with a placeholder before the
    // INI crosses the channel. Resolve it from the EXISTING Keychain identity
    // of the caller's scope; this path never creates an identity, and an
    // empty scope would silently select the legacy unscoped Keychain item.
    let accountScope = accountScope(from: arguments)
    guard !accountScope.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_ACCOUNT_SCOPE",
        message: "The winn/3 control-plane delivery requires an account scope.",
        details: nil
      ))
      return
    }
    let clientKeyPair: WinsClientKeyPair
    do {
      guard let existing = try WinsClientKeyStore.loadExisting(accountScope: accountScope) else {
        result(FlutterError(
          code: "APPLE_WINN3_CPL_KEYPAIR_MISSING",
          message: "The winn/3 control-plane delivery requires an existing device Keychain identity.",
          details: nil
        ))
        return
      }
      clientKeyPair = existing
    } catch {
      result(flutterError("APPLE_WINN3_CPL_KEYCHAIN_FAILED", error))
      return
    }
    guard let resolvedConfig = WinsWinn3ControlPlaneDelivery.resolvingExistingKeychainPlaceholder(
      config,
      privateKey: clientKeyPair.privateKey
    ) else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_BAD_PLACEHOLDER",
        message: "The winn/3 control-plane config must carry exactly one Keychain placeholder.",
        details: nil
      ))
      return
    }

    let parsedConfig: WinsTunnelConfig
    do {
      parsedConfig = try WinsTunnelConfig.parseAndValidate(resolvedConfig)
    } catch let error as WinsTunnelValidationError {
      result(flutterError("APPLE_WINN3_CPL_INVALID", error.nsError))
      return
    } catch {
      result(flutterError("APPLE_WINN3_CPL_INVALID", error))
      return
    }
    guard parsedConfig.winn3Enabled else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_NOT_STANDALONE",
        message: WinsWinn3ControlPlaneDelivery.notStandaloneMessage,
        details: nil
      ))
      return
    }

    guard !Self.isSimulatorRuntime else {
      result(FlutterError(
        code: "APPLE_WINN3_CPL_SIMULATOR_UNSUPPORTED",
        message: "NetworkExtension cannot persist a configuration on the iOS Simulator.",
        details: nil
      ))
      return
    }

    do {
      try parsedConfig.validateInterfacePrivateKeyMatches(clientKeyPair)
      let tunnelSecrets = WinsTunnelSecrets(
        presharedKey: parsedConfig.peerPresharedKey,
        xrayUUID: parsedConfig.xrayRuntimeConfig?.uuid ?? "",
        winnStaticPrivate: parsedConfig.winn3StaticPrivate,
        winnAdmissionKey: parsedConfig.winn3AdmissionKey,
        winnPSK: parsedConfig.winn3PSK
      )
      if !tunnelSecrets.isEmpty {
        try WinsTunnelSecretStore.save(tunnelSecrets, accountScope: accountScope)
      }
    } catch {
      result(flutterError("APPLE_WINN3_CPL_KEYCHAIN_FAILED", error))
      return
    }

    // Never place the full winn/3 INI in providerConfiguration. NetworkExtension
    // preferences survive process death and would durably retain live key
    // material. Persist only the redacted App Group config path and non-secret
    // routing metadata. A live start still receives secrets through transient
    // start options or the shared Keychain restoration path.
    let statusGeneration = UUID().uuidString
    let sharedConfigUrl: URL
    do {
      sharedConfigUrl = try persistSharedTunnelConfig(
        resolvedConfig,
        parsedConfig: parsedConfig,
        statusGeneration: statusGeneration
      )
    } catch {
      result(flutterError("APPLE_WINN3_CPL_PERSIST_FAILED", error))
      return
    }

    let operationToken = tunnelOperationGate.begin(perform: {
      self.invalidateStatusManagerCache()
    })
    loadTunnelManager { manager, error in
      guard self.tunnelOperationGate.isCurrent(operationToken) else {
        result(false)
        return
      }
      if let error = error {
        result(self.flutterError("APPLE_WINN3_CPL_LOAD_FAILED", error))
        return
      }

      let manager = manager ?? NETunnelProviderManager()
      let tunnelProtocol = NETunnelProviderProtocol()
      tunnelProtocol.providerBundleIdentifier = self.providerBundleIdentifier
      tunnelProtocol.serverAddress = Self.currentTunnelDescription
      if #available(iOS 14.2, *) {
        tunnelProtocol.enforceRoutes = true
        tunnelProtocol.excludeLocalNetworks = true
      }
      tunnelProtocol.providerConfiguration = [
        "wins_manager_signature": Self.tunnelManagerSignature,
        "app_group_id": Self.appGroupIdentifier,
        "winn3_control_plane_delivery": true,
        "protocol_version": Self.winn3ControlPlaneProtocolVersion as NSString,
        "carrier": Self.winn3ControlPlaneCarrier as NSString,
        "shared_config_path": sharedConfigUrl.path,
        "status_generation": statusGeneration,
        "client_public_key": clientKeyPair.publicKey,
        "client_key_account_scope": accountScope,
        "shared_config_private_key_redacted": true,
        "client_key_pair_verified": true,
        "updated_at": ISO8601DateFormatter().string(from: Date())
      ]
      manager.localizedDescription = Self.currentTunnelDescription
      manager.protocolConfiguration = tunnelProtocol
      manager.isEnabled = true

      self.saveTunnelManager(manager) { saveError in
        guard self.tunnelOperationGate.isCurrent(operationToken) else {
          result(false)
          return
        }
        if let saveError = saveError {
          result(self.flutterError("APPLE_WINN3_CPL_SAVE_FAILED", saveError))
          return
        }
        // Delivery only: the tunnel is intentionally NOT started.
        result(true)
      }
    }
  }

  private func probeVpnInternet(_ arguments: Any?, result: @escaping FlutterResult) {
    let externalLeakAuditRequest = WinsAppleExternalLeakAudit.request(from: arguments)
    guard !Self.isSimulatorRuntime else {
      var response = simulatorTunnelReadinessFields
      response["ok"] = false
      response["internet_probe_attempted"] = false
      response["internet_probe_blocked_by_provider_readiness"] = true
      response["internet_probe_blocked_by_leak_protection_config"] = false
      response["internet_probe_blocked_by_simulator"] = true
      response.merge(WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(response)) { _, new in new }
      response.merge(WinsAppleExternalLeakAudit.baseFields(for: externalLeakAuditRequest)) { _, new in new }
      result(response)
      return
    }

    loadTunnelManager { manager, error in
      if let error = error {
        var response: [String: Any] = [
          "ok": false,
          "internet_probe_attempted": false,
          "internet_probe_blocked_by_leak_protection_config": false,
          "platform": "ios",
          "provider_bundle_id": self.providerBundleIdentifier
        ]
        response.merge(WinsTunnelDiagnostics.redactedAppleErrorFields(error)) { _, new in new }
        response.merge(WinsAppleExternalLeakAudit.baseFields(for: externalLeakAuditRequest)) { _, new in new }
        result(response)
        return
      }

      let status = manager?.connection.status ?? .invalid
      let connected = status == .connected
      var response: [String: Any] = [
        "ok": false,
        "internet_probe_attempted": false,
        "internet_probe_blocked_by_provider_readiness": false,
        "internet_probe_blocked_by_leak_protection_config": false,
        "network_extension_connected": connected,
        "active": connected,
        "platform": "ios",
        "provider_bundle_id": self.providerBundleIdentifier,
        "status": Self.statusName(status)
      ]
      response.merge(
        self.latestProviderStatusFields(
          expectedStatusGeneration: self.expectedStatusGeneration(from: manager)
        )
      ) { _, new in new }

      guard connected else {
        let managerInvalidAfterConfigSave = status == .invalid
          && (response["provider_stage"] as? String) == "config_saved"
        response["vpn_manager_invalid_after_config_save"] = managerInvalidAfterConfigSave
        response["vpn_configuration_permission_pending"] = managerInvalidAfterConfigSave
        response["provider_status_current"] = WinsAppleReadiness.providerStatusCurrent(response)
        response["provider_ready"] = WinsAppleReadiness.providerReady(response)
        response.merge(WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(response)) { _, new in new }
        response.merge(WinsAppleExternalLeakAudit.baseFields(for: externalLeakAuditRequest)) { _, new in new }
        result(response)
        return
      }

      self.providerHealthProbeFields(for: manager) { probeFields in
        response.merge(probeFields) { _, new in new }
        // The pre-probe file may still be config_saved during a fast first
        // connection. Refresh after the authenticated reply before enforcing
        // the DNS/IPv6 leak-protection gate; generation validation stays
        // fail-closed if the provider changed or stopped.
        response.merge(
          self.latestProviderStatusFields(
            expectedStatusGeneration: self.expectedStatusGeneration(from: manager)
          )
        ) { _, new in new }
        response["provider_status_current"] = WinsAppleReadiness.providerStatusCurrent(response)
        response["provider_ready"] = WinsAppleReadiness.providerReady(response)
        response.merge(WinsAppleReadiness.fullTunnelLeakProtectionConfigFields(response)) { _, new in new }

        guard WinsAppleReadiness.providerReady(response) else {
          response["internet_probe_blocked_by_provider_readiness"] = true
          response.merge(WinsAppleExternalLeakAudit.baseFields(for: externalLeakAuditRequest)) { _, new in new }
          result(response)
          return
        }

        guard WinsAppleReadiness.bool(response, "leak_protection_config_passed") else {
          response["internet_probe_blocked_by_leak_protection_config"] = true
          response.merge(WinsAppleExternalLeakAudit.baseFields(for: externalLeakAuditRequest)) { _, new in new }
          result(response)
          return
        }

        guard let url = URL(string: "https://www.winsvpn.org/") else {
          response["error"] = "Invalid probe URL."
          result(response)
          return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = 4
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.timeoutIntervalForRequest = 4
        sessionConfiguration.timeoutIntervalForResource = 4
        URLSession(configuration: sessionConfiguration).dataTask(with: request) { _, httpResponse, probeError in
          let statusCode = (httpResponse as? HTTPURLResponse)?.statusCode ?? 0
          DispatchQueue.main.async {
            response["internet_probe_attempted"] = true
            response["internet_probe_url_kind"] = "public_https"
            response["status_code"] = statusCode
            let publicProbeOk = probeError == nil && statusCode >= 200 && statusCode < 500
            response["ok"] = publicProbeOk
            if let probeError {
              response.merge(WinsTunnelDiagnostics.redactedAppleErrorFields(probeError)) { _, new in new }
            } else {
              response["error"] = ""
            }
            guard publicProbeOk, externalLeakAuditRequest.requested else {
              response.merge(WinsAppleExternalLeakAudit.baseFields(for: externalLeakAuditRequest)) { _, new in new }
              result(response)
              return
            }
            WinsAppleExternalLeakAudit.run(externalLeakAuditRequest) { auditFields in
              response.merge(auditFields) { _, new in new }
              response["ok"] = publicProbeOk &&
                WinsAppleReadiness.bool(response, "external_leak_audit_passed")
              result(response)
            }
          }
        }.resume()
      }
    }
  }

  private func providerHealthProbeFields(
    for manager: NETunnelProviderManager?,
    completion: @escaping ([String: Any]) -> Void
  ) {
    guard manager?.connection.status == .connected else {
      completion([
        "provider_message_probe_attempted": false,
        "provider_message_probe_supported": false,
        "provider_message_probe_healthy": false
      ])
      return
    }
    guard let session = manager?.connection as? NETunnelProviderSession else {
      completion([
        "provider_message_probe_attempted": false,
        "provider_message_probe_supported": false,
        "provider_message_probe_healthy": false
      ])
      return
    }

    let request: [String: Any] = ["command": "health"]
    guard let requestData = try? JSONSerialization.data(withJSONObject: request, options: [.sortedKeys]) else {
      completion([
        "provider_message_probe_attempted": false,
        "provider_message_probe_supported": true,
        "provider_message_probe_healthy": false
      ])
      return
    }

    var completed = false
    let completionLock = NSLock()
    let finish: ([String: Any]) -> Void = { fields in
      completionLock.lock()
      defer { completionLock.unlock() }
      guard !completed else {
        return
      }
      completed = true
      DispatchQueue.main.async {
        completion(fields)
      }
    }

    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.5) {
      completionLock.lock()
      let alreadyCompleted = completed
      completionLock.unlock()
      if alreadyCompleted { return }
      var fields: [String: Any] = [
        "provider_message_probe_attempted": true,
        "provider_message_probe_supported": true,
        "provider_message_probe_healthy": false,
        "provider_message_probe_timeout": true
      ]
      fields.merge(
        WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
          responseData: nil,
          expectedProviderExecutableSHA256:
            WinsPacketTunnelProviderAppMessage.embeddedProviderExecutableSHA256(in: .main)
        )
      ) { _, new in new }
      finish(fields)
    }

    do {
      try session.sendProviderMessage(requestData) { responseData in
        var fields: [String: Any] = [
          "provider_message_probe_attempted": true,
          "provider_message_probe_supported": true,
          "provider_message_probe_timeout": false
        ]
        fields.merge(
          WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
            responseData: responseData,
            expectedProviderExecutableSHA256:
              WinsPacketTunnelProviderAppMessage.embeddedProviderExecutableSHA256(in: .main)
          )
        ) { _, new in new }
        finish(fields)
      }
    } catch {
      var fields: [String: Any] = [
        "provider_message_probe_attempted": true,
        "provider_message_probe_supported": true,
        "provider_message_probe_healthy": false,
        "provider_message_probe_timeout": false
      ]
      fields.merge(
        WinsPacketTunnelProviderAppMessage.healthProbeResponseStatusFields(
          responseData: nil,
          expectedProviderExecutableSHA256:
            WinsPacketTunnelProviderAppMessage.embeddedProviderExecutableSHA256(in: .main)
        )
      ) { _, new in new }
      fields.merge(WinsTunnelDiagnostics.redactedAppleErrorFields(error)) { _, new in new }
      finish(fields)
    }
  }

  private func loadTunnelManager(
    completion: @escaping (NETunnelProviderManager?, Error?) -> Void
  ) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error = error {
        completion(nil, error)
        return
      }

      let managers = managers ?? []
      if let signedManager = managers.first(where: self.isSignedWinsTunnelManager) {
        self.removeStaleTunnelManagers(managers, keeping: signedManager) {
          completion(signedManager, nil)
        }
        return
      }

      // A matching bundle identifier is not sufficient after an app update:
      // NetworkExtension persists the provider registration UUID inside the
      // manager. Reusing a legacy manager can therefore target an extension
      // registration that the OS has already removed. Delete legacy managers
      // once and create a current signed manager below.
      self.removeStaleTunnelManagers(managers, keeping: nil) {
        completion(nil, nil)
      }
    }
  }

  private func isSignedWinsTunnelManager(_ manager: NETunnelProviderManager) -> Bool {
    guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
      return false
    }
    return tunnelProtocol.providerBundleIdentifier == providerBundleIdentifier
      && tunnelProtocol.providerConfiguration?["wins_manager_signature"] as? String == Self.tunnelManagerSignature
  }

  private func isProviderBundleTunnelManager(_ manager: NETunnelProviderManager) -> Bool {
    guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
      return false
    }
    return tunnelProtocol.providerBundleIdentifier == providerBundleIdentifier
  }

  private func shouldRemoveTunnelManager(
    _ manager: NETunnelProviderManager,
    keeping managerToKeep: NETunnelProviderManager?
  ) -> Bool {
    if let managerToKeep, manager === managerToKeep {
      return false
    }

    let matchesProviderBundle = isProviderBundleTunnelManager(manager)
    // A stale manager could have been saved under either name depending on
    // which disguise state was active at the time, so both must be checked.
    let matchesDisplayName = manager.localizedDescription == Self.tunnelDescription
      || manager.localizedDescription == Self.disguisedTunnelDescription
    return matchesProviderBundle || matchesDisplayName
  }

  private func removeStaleTunnelManagers(
    _ managers: [NETunnelProviderManager],
    keeping managerToKeep: NETunnelProviderManager?,
    completion: (() -> Void)? = nil
  ) {
    let staleManagers = managers.filter {
      shouldRemoveTunnelManager($0, keeping: managerToKeep)
    }
    guard !staleManagers.isEmpty else {
      completion?()
      return
    }

    let group = DispatchGroup()
    for manager in staleManagers {
      group.enter()
      self.removeTunnelManager(manager) { removalError in
        if let removalError = removalError {
          NSLog(
            "Win's VPN failed to remove stale tunnel manager: %@",
            WinsTunnelDiagnostics.redactedAppleErrorMessage(removalError)
          )
        }
        group.leave()
      }
    }
    group.notify(queue: .main) {
      completion?()
    }
  }

  private func flutterError(
    _ code: String,
    _ error: Error,
    messagePrefix: String = ""
  ) -> FlutterError {
    flutterError(
      code,
      "\(messagePrefix)\(WinsTunnelDiagnostics.redactedAppleErrorMessage(error))",
      errorDetails: error
    )
  }

  private func flutterError(
    _ code: String,
    _ message: String,
    errorDetails: Error? = nil,
    extraDetails: [String: Any] = [:]
  ) -> FlutterError {
    var details: [String: Any] = [
      "platform": "ios",
      "provider_bundle_id": providerBundleIdentifier
    ]
    if let errorDetails {
      details.merge(WinsTunnelDiagnostics.nativeErrorDetails(errorDetails)) { _, new in new }
    }
    details.merge(extraDetails) { _, new in new }
    return FlutterError(
      code: code,
      message: message,
      details: details
    )
  }

  private func consumeWinn3CoverGrantIfNeeded(
    winnEnabled: Bool,
    arguments: Any?,
    result: @escaping FlutterResult
  ) -> Bool {
    if winnEnabled { return true }
    guard let args = arguments as? [String: Any] else {
      WinsWinn3AwgXrayGrantStore.clear()
      return true
    }
    let hasCoverFields =
      args["winn3AwgXrayAuthorizationToken"] != nil ||
      args["winn3CoverExactTarget"] != nil ||
      args["winn3CoverLeg"] != nil
    if !hasCoverFields {
      WinsWinn3AwgXrayGrantStore.clear()
      return true
    }
    let identities = WinsWinn3NativeStartReadiness.dartIdentities(from: arguments)
    guard let token = identities.startToken,
          let auth = (args["winn3AwgXrayAuthorizationToken"] as? NSNumber)
            .flatMap({
              CFGetTypeID($0) == CFBooleanGetTypeID() || CFNumberIsFloatType($0)
                ? nil : $0.intValue
            })
            .flatMap({ $0 > 0 ? $0 : nil }),
          let generation = identities.startGeneration,
          let selection = identities.selectionGeneration,
          let failed = identities.failedNode,
          let coverTarget = args["winn3CoverExactTarget"] as? String,
          let coverLegRaw = args["winn3CoverLeg"] as? String,
          let coverLeg = WinsWinn3CoverLeg(rawValue: coverLegRaw),
          auth == token else {
      result(flutterError(
        "APPLE_WINN3_COVER_GRANT_INVALID",
        "Cover AWG/Xray start identities are malformed."
      ))
      return false
    }
    let nowMs = Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000)
    if !WinsWinn3AwgXrayGrantStore.consume(
      startToken: token,
      startGeneration: generation,
      selectionGeneration: selection,
      failedV3Node: failed,
      exactV1Target: coverTarget,
      requestedLeg: coverLeg,
      nowMs: nowMs
    ) {
      result(flutterError(
        "APPLE_WINN3_COVER_GRANT_REFUSED",
        "Cover AWG/Xray grant is missing, expired, or mismatched."
      ))
      return false
    }
    return true
  }

  private func rememberWinn3StartIdentities(
    winnEnabled: Bool,
    arguments: Any?,
    statusGeneration: String
  ) {
    if winnEnabled {
      let identities = WinsWinn3NativeStartReadiness.dartIdentities(from: arguments)
      lastDartWinn3StartGeneration = identities.startGeneration
      lastDartWinn3StartToken = identities.startToken
      lastDartWinn3SelectionGeneration = identities.selectionGeneration ?? ""
      lastDartWinn3FailedNode = identities.failedNode ?? ""
      lastWinn3ProofStatusGeneration = statusGeneration
      WinsWinn3AwgXrayGrantStore.clear()
    } else {
      lastDartWinn3StartGeneration = nil
      lastDartWinn3StartToken = nil
      lastDartWinn3SelectionGeneration = ""
      lastDartWinn3FailedNode = ""
      lastWinn3ProofStatusGeneration = ""
    }
  }

  private func applyWinn3NativeStartReadiness(
    to readiness: inout [String: Any],
    expectedStatusGeneration: String?
  ) {
    guard lastDartWinn3StartGeneration != nil else { return }
    readiness.merge(
      WinsWinn3NativeStartReadiness.fields(
        dartStartGeneration: lastDartWinn3StartGeneration,
        expectedStatusGeneration: expectedStatusGeneration ?? lastWinn3ProofStatusGeneration,
        status: latestProviderStatus().status,
        dartStartToken: lastDartWinn3StartToken,
        selectionGeneration: lastDartWinn3SelectionGeneration,
        failedNode: lastDartWinn3FailedNode
      )
    ) { _, new in new }
    if (readiness[WinsWinn3NativeStartReadiness.verdictKey] as? String) ==
        WinsWinn3NativeStartOutcome.ordinaryConnectivity.rawValue,
       let token = lastDartWinn3StartToken,
       let generation = lastDartWinn3StartGeneration {
      _ = WinsWinn3AwgXrayGrantStore.arm(
        startToken: token,
        startGeneration: generation,
        selectionGeneration: lastDartWinn3SelectionGeneration,
        failedV3Node: lastDartWinn3FailedNode,
        nowMs: Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000)
      )
    }
  }

  /// Winn v3 starts are not accepted until the Packet Tunnel extension writes
  /// a generation-bound proof verdict. Returning `true` at `startVPNTunnel`
  /// would let Dart treat engine death, proof timeout, and unknown post-create
  /// failures as an accepted native start and authorize winn/1.
  private func completeTunnelStartAfterProviderProof(
    requiresWinn3Proof: Bool,
    expectedGeneration: String,
    operationToken: UInt64,
    startError: Error?,
    result: @escaping FlutterResult
  ) {
    if let startError {
      result(flutterError(
        "APPLE_TUNNEL_START_FAILED",
        startError,
        messagePrefix: "Packet Tunnel Provider is not ready yet: "
      ))
      return
    }
    guard requiresWinn3Proof else {
      result(true)
      return
    }
    let proofQueue = DispatchQueue(
      label: "org.winsvpn.app.winn3-start-proof",
      qos: .userInitiated
    )
    proofQueue.async {
      let observation = WinsWinn3NativeStartClassifier.waitForProof(
        expectedGeneration: expectedGeneration,
        isCurrent: { self.tunnelOperationGate.isCurrent(operationToken) },
        readStatus: { self.latestProviderStatus().status },
        sleep: { Thread.sleep(forTimeInterval: $0) },
        now: { Date() },
        deadline: Date().addingTimeInterval(
          TimeInterval(WinsWinn3NativeStartClassifier.proofWaitMilliseconds) / 1000.0
        )
      )
      DispatchQueue.main.async {
        self.reportWinn3StartObservation(observation, result: result)
      }
    }
  }

  private func reportWinn3StartObservation(
    _ observation: WinsWinn3NativeStartObservation,
    result: @escaping FlutterResult
  ) {
    switch observation {
    case .canceled, .waiting:
      result(false)
    case .finished(let outcome):
      reportWinn3StartOutcome(outcome, result: result)
    }
  }

  private func reportWinn3StartOutcome(
    _ outcome: WinsWinn3NativeStartOutcome,
    result: @escaping FlutterResult
  ) {
    if outcome.reportsNativeStartAccepted {
      result(true)
      return
    }
    result(flutterError(
      outcome.flutterErrorCode,
      "Winn Protocol v3 did not prove this start.",
      extraDetails: [WinsWinn3NativeStartOutcome.fieldKey: outcome.rawValue]
    ))
  }

  private func persistSharedTunnelConfig(
    _ rawConfig: String,
    parsedConfig: WinsTunnelConfig,
    statusGeneration: String,
    transientRawConfigLab: Bool = false
  ) throws -> URL {
    let fileManager = FileManager.default
    guard let containerUrl = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier
    ) else {
      throw Self.bridgeError(
        code: 2101,
        message: "App Group \(Self.appGroupIdentifier) is unavailable. Configure the App Group for the app and Packet Tunnel targets."
      )
    }

    let directory = containerUrl.appendingPathComponent(
      Self.sharedConfigDirectoryName,
      isDirectory: true
    )
    try WinsAppGroupFileWriter.ensureDirectory(at: directory, fileManager: fileManager)
    let configUrl = directory.appendingPathComponent(Self.sharedConfigFileName, isDirectory: false)
    let redactedConfig = WinsTunnelConfig.redactedForStorage(rawConfig)
    // B-APP-003: owner-only permissions, backup exclusion AND
    // completeUntilFirstUserAuthentication file protection are applied by the
    // writer itself, fail-closed. The old `try?` here silently left the
    // config at container-default protection when the attribute call failed;
    // a write that cannot be hardened is now rejected with
    // WinsAppGroupFileWriter.hardeningFailedCode instead.
    try WinsAppGroupFileWriter.writeString(redactedConfig, to: configUrl, fileManager: fileManager)

    let metadataUrl = directory.appendingPathComponent(Self.sharedMetadataFileName, isDirectory: false)
    let metadata: [String: Any] = [
      "updated_at": ISO8601DateFormatter().string(from: Date()),
      "status_generation": statusGeneration,
      "peer_endpoint_present": !parsedConfig.peerEndpoint.isEmpty,
      "peer_endpoint_kind": parsedConfig.peerEndpointKind,
      "transport_endpoint_kind": parsedConfig.transportEndpointKind,
      "network_settings_remote_address_kind": parsedConfig.networkSettingsRemoteAddressKind,
      "network_settings_remote_address_source": parsedConfig.networkSettingsRemoteAddressSource,
      "transport_ipv4_route_excluded": parsedConfig.transportIPv4ExclusionRoute != nil,
      "transport_ipv4_exclusion_route_present": parsedConfig.transportIPv4ExclusionRoute != nil,
      "ipv6_leak_protection_enabled": parsedConfig.ipv6LeakProtectionEnabled,
      "ipv6_sink_address_present": parsedConfig.ipv6LeakProtectionEnabled && !parsedConfig.ipv6SinkAddress.isEmpty,
      "ipv6_sink_prefix_length": parsedConfig.ipv6SinkPrefixLength,
      "dns_match_domains": parsedConfig.dnsMatchDomains,
      "dns_full_tunnel_match_enabled": parsedConfig.fullTunnelDNSMatchEnabled,
      "xray_enabled": parsedConfig.xrayEnabled,
      "shared_config_private_key_redacted": true,
      "shared_config_transient_raw_lab_marker": transientRawConfigLab,
      "shared_config_contains_standalone_credentials": false,
      "client_key_pair_verified": true,
      "client_public_key_available": true,
      "client_public_key_source": "host_keychain",
      "client_public_key_valid": true,
      "provider_bundle_id": providerBundleIdentifier
    ]
    let metadataData = try JSONSerialization.data(
      withJSONObject: metadata,
      options: [.prettyPrinted, .sortedKeys]
    )
    try WinsAppGroupFileWriter.writeData(metadataData, to: metadataUrl, fileManager: fileManager)
    let initialStatus = WinsPacketTunnelProviderStatus.payload(
      stage: "config_saved",
      providerBundleIdentifier: providerBundleIdentifier,
      config: parsedConfig,
      engineReady: false,
      networkSettingsReady: false,
      extra: [
        "status_generation": statusGeneration,
        "network_settings_applied": false,
        "config_source": "host_app",
        "private_key_source": "redacted_in_shared_config",
        "client_key_pair_verification_required": true,
        "expected_client_public_key_available": true,
        "expected_client_public_key_source": "host_keychain",
        "expected_client_public_key_valid": true,
        "client_key_pair_verified": true,
        "client_public_key_available": true,
        "shared_config_private_key_redacted": true,
        "shared_config_transient_raw_lab_marker": transientRawConfigLab,
        "shared_config_contains_standalone_credentials": false
      ]
    )
    try writeSharedTunnelStatus(initialStatus, in: directory)
    return configUrl
  }

  private func latestProviderStatusFields(
    expectedStatusGeneration: (generation: String?, invalid: Bool)
  ) -> [String: Any] {
    let providerStatus = latestProviderStatus()
    guard let status = providerStatus.status else {
      return providerStatus.fields
    }

    func unavailableStatusFields(_ updates: [String: Any]) -> [String: Any] {
      var fields = providerStatus.fields
      fields["provider_status_available"] = false
      for (key, value) in updates {
        fields[key] = value
      }
      return fields
    }

    let schemaVersion = status["status_schema_version"] as? Int ?? 0
    guard schemaVersion == 2 else {
      return unavailableStatusFields([
        "provider_status_schema_supported": false,
        "provider_status_schema_version": schemaVersion
      ])
    }

    let reportedProviderBundleIdentifier = (status["provider_bundle_id"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard reportedProviderBundleIdentifier == providerBundleIdentifier else {
      return unavailableStatusFields([
        "provider_status_bundle_mismatch": true,
        "provider_expected_bundle_id": providerBundleIdentifier,
        "provider_reported_bundle_id_present": !reportedProviderBundleIdentifier.isEmpty
      ])
    }

    let reportedNetworkExtensionType = (status["network_extension_type"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard reportedNetworkExtensionType == WinsPacketTunnelProviderStatus.networkExtensionType else {
      return unavailableStatusFields([
        "provider_status_extension_type_mismatch": true,
        "provider_expected_network_extension_type": WinsPacketTunnelProviderStatus.networkExtensionType,
        "provider_reported_network_extension_type_present": !reportedNetworkExtensionType.isEmpty
      ])
    }

    let updatedAt = (status["updated_at"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard Self.validProviderStatusTimestamp(updatedAt) else {
      return unavailableStatusFields([
        "provider_status_timestamp_invalid": true,
        "provider_status_updated_at_present": !updatedAt.isEmpty
      ])
    }

    let providerStage = (status["stage"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard WinsPacketTunnelProviderStatus.validStage(providerStage) else {
      return unavailableStatusFields([
        "provider_status_stage_invalid": true,
        "provider_status_stage_present": !providerStage.isEmpty
      ])
    }

    let rawProviderStatusGeneration = (status["status_generation"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let providerStatusGeneration = WinsPacketTunnelProviderStatus.safeStatusGeneration(
      rawProviderStatusGeneration
    )
    let providerStatusGenerationInvalid = !rawProviderStatusGeneration.isEmpty
      && providerStatusGeneration.isEmpty
    if expectedStatusGeneration.invalid {
      var staleFields: [String: Any] = [
        "provider_status_stale": true,
        "provider_expected_status_generation_invalid": true,
        "provider_status_generation_invalid": providerStatusGenerationInvalid
      ]
      if !providerStatusGeneration.isEmpty {
        staleFields["provider_status_generation"] = providerStatusGeneration
      }
      return unavailableStatusFields(staleFields)
    }
    if let expectedGeneration = expectedStatusGeneration.generation,
       !expectedGeneration.isEmpty,
       providerStatusGeneration != expectedGeneration {
      var staleFields: [String: Any] = [
        "provider_status_stale": true,
        "provider_status_generation_invalid": providerStatusGenerationInvalid,
        "provider_expected_status_generation": expectedGeneration
      ]
      if !providerStatusGeneration.isEmpty {
        staleFields["provider_status_generation"] = providerStatusGeneration
      }
      return unavailableStatusFields(staleFields)
    }

    var fields = providerStatus.fields
    fields["provider_status_available"] = true
    fields["provider_status_schema_supported"] = true
    let mappings = [
      "status_schema_version": "provider_status_schema_version",
      "status_generation": "provider_status_generation",
      "updated_at": "provider_updated_at",
      "stage": "provider_stage",
      "status_write_limited": "provider_status_write_limited",
      "status_write_payload_too_large": "provider_status_write_payload_too_large",
      "status_write_original_stage": "provider_status_write_original_stage",
      "healthy": "provider_healthy",
      "engine_ready": "provider_engine_ready",
      "network_settings_ready": "provider_network_settings_ready",
      "network_settings_applied": "provider_network_settings_applied",
      "provider_bundle_id": "provider_reported_bundle_id",
      "network_extension_type": "provider_network_extension_type",
      "config_source": "provider_config_source",
      "config_source_available": "provider_config_source_available",
      "config_file_present": "provider_config_file_present",
      "config_file_readable": "provider_config_file_readable",
      "config_file_symbolic_link": "provider_config_file_symbolic_link",
      "config_file_too_large": "provider_config_file_too_large",
      "config_too_large": "provider_config_too_large",
      "config_utf8_valid": "provider_config_utf8_valid",
      "config_empty": "provider_config_empty",
      "config_size_bytes": "provider_config_size_bytes",
      "config_max_size_bytes": "provider_config_max_size_bytes",
      "config_shared_path_present": "provider_config_shared_path_present",
      "config_shared_path_allowed": "provider_config_shared_path_allowed",
      "config_shared_path_matches_expected": "provider_config_shared_path_matches_expected",
      "config_shared_path_inside_app_group": "provider_config_shared_path_inside_app_group",
      "config_app_group_id_present": "provider_config_app_group_id_present",
      "config_app_group_id_allowed": "provider_config_app_group_id_allowed",
      "config_app_group_container_available": "provider_config_app_group_container_available",
      "private_key_source": "provider_private_key_source",
      "shared_keychain_private_key_available": "provider_shared_keychain_private_key_available",
      "client_key_pair_verification_required": "provider_client_key_pair_verification_required",
      "expected_client_public_key_available": "provider_expected_client_public_key_available",
      "expected_client_public_key_source": "provider_expected_client_public_key_source",
      "expected_client_public_key_valid": "provider_expected_client_public_key_valid",
      "client_key_pair_verified": "provider_client_key_pair_verified",
      "error_domain": "provider_error_domain",
      "error_code": "provider_error_code",
      "error_message": "provider_error",
      "winn3_start_outcome": "winn3_verdict",
      "winn3_ordinary_network_unreachability": "winn3_ordinary_network_unreachability",
      "peer_endpoint_present": "provider_peer_endpoint_present",
      "peer_endpoint_kind": "provider_peer_endpoint_kind",
      "transport_endpoint_kind": "provider_transport_endpoint_kind",
      "network_settings_remote_address_kind": "provider_network_settings_remote_address_kind",
      "network_settings_remote_address_source": "provider_network_settings_remote_address_source",
      "interface_ipv4_address_present": "provider_interface_ipv4_address_present",
      "route_count": "provider_route_count",
      "default_route_enabled": "provider_default_route_enabled",
      "transport_ipv4_route_excluded": "provider_transport_ipv4_route_excluded",
      "transport_ipv4_exclusion_route_present": "provider_transport_ipv4_exclusion_route_present",
      "ipv6_leak_protection_enabled": "provider_ipv6_leak_protection_enabled",
      "ipv6_sink_address_present": "provider_ipv6_sink_address_present",
      "ipv6_sink_prefix_length": "provider_ipv6_sink_prefix_length",
      "dns_count": "provider_dns_count",
      "dns_match_domains": "provider_dns_match_domains",
      "dns_full_tunnel_match_enabled": "provider_dns_full_tunnel_match_enabled",
      "mtu": "provider_mtu",
      "xray_enabled": "provider_xray_enabled",
      "transport_mode": "provider_transport_mode",
      "required_engine_components": "provider_required_engine_components",
      "awg_obfuscation_present": "provider_awg_obfuscation_present",
      "xray_host_present": "provider_xray_host_present",
      "xray_server_name_present": "provider_xray_server_name_present",
      "xray_path_present": "provider_xray_path_present",
      "xray_security": "provider_xray_security",
      "xray_local_port_present": "provider_xray_local_port_present",
      "xray_remote_awg_loopback": "provider_xray_remote_awg_loopback",
      "xray_remote_awg_port_present": "provider_xray_remote_awg_port_present",
      "engine_adapter_version": "provider_engine_adapter_version",
      "engine_adapter_required": "provider_engine_adapter_required",
      "engine_adapter_available": "provider_engine_adapter_available",
      "engine_bundle_probe_schema_version": "provider_engine_bundle_probe_schema_version",
      "engine_bundle_probe": "provider_engine_bundle_probe",
      "engine_bundle_required_components": "provider_engine_bundle_required_components",
      "engine_bundle_available_components": "provider_engine_bundle_available_components",
      "engine_bundle_missing_components": "provider_engine_bundle_missing_components",
      "engine_bundle_required_component_count": "provider_engine_bundle_required_component_count",
      "engine_bundle_available_component_count": "provider_engine_bundle_available_component_count",
      "engine_bundle_missing_component_count": "provider_engine_bundle_missing_component_count",
      "engine_bundle_all_required_components_present": "provider_engine_bundle_all_required_components_present",
      "engine_transport_mode": "provider_engine_transport_mode",
      "engine_required_components": "provider_engine_required_components",
      "engine_launch_descriptor_schema_version": "provider_engine_launch_descriptor_schema_version",
      "engine_launch_descriptor_ready": "provider_engine_launch_descriptor_ready",
      "engine_launch_descriptor_secret_material_redacted": "provider_engine_launch_descriptor_secret_material_redacted",
      "engine_launch_descriptor_config_source": "provider_engine_launch_descriptor_config_source",
      "engine_launch_descriptor_transport_mode": "provider_engine_launch_descriptor_transport_mode",
      "engine_launch_contract_version": "provider_engine_launch_contract_version",
      "engine_packet_flow_required": "provider_engine_packet_flow_required",
      "engine_packet_flow_available": "provider_engine_packet_flow_available",
      "engine_interface_private_key_present": "provider_engine_interface_private_key_present",
      "engine_interface_private_key_redacted": "provider_engine_interface_private_key_redacted",
      "engine_peer_public_key_present": "provider_engine_peer_public_key_present",
      "engine_peer_public_key_redacted": "provider_engine_peer_public_key_redacted",
      "engine_peer_preshared_key_present": "provider_engine_peer_preshared_key_present",
      "engine_peer_preshared_key_redacted": "provider_engine_peer_preshared_key_redacted",
      "engine_peer_keepalive_present": "provider_engine_peer_keepalive_present",
      "engine_awg_obfuscation_present": "provider_engine_awg_obfuscation_present",
      "engine_awg_obfuscation_field_count": "provider_engine_awg_obfuscation_field_count",
      "engine_allowed_ipv4_route_count": "provider_engine_allowed_ipv4_route_count",
      "engine_default_route_enabled": "provider_engine_default_route_enabled",
      "engine_ipv6_leak_protection_enabled": "provider_engine_ipv6_leak_protection_enabled",
      "engine_ipv6_sink_prefix_length": "provider_engine_ipv6_sink_prefix_length",
      "engine_dns_server_count": "provider_engine_dns_server_count",
      "engine_full_tunnel_dns_match_enabled": "provider_engine_full_tunnel_dns_match_enabled",
      "engine_mtu": "provider_engine_mtu",
      "engine_peer_endpoint_kind": "provider_engine_peer_endpoint_kind",
      "engine_transport_endpoint_kind": "provider_engine_transport_endpoint_kind",
      "engine_network_settings_remote_address_kind": "provider_engine_network_settings_remote_address_kind",
      "engine_network_settings_remote_address_source": "provider_engine_network_settings_remote_address_source",
      "engine_transport_ipv4_exclusion_route_present": "provider_engine_transport_ipv4_exclusion_route_present",
      "engine_xray_transport_required": "provider_engine_xray_transport_required",
      "engine_xray_uuid_present": "provider_engine_xray_uuid_present",
      "engine_xray_uuid_redacted": "provider_engine_xray_uuid_redacted",
      "engine_xray_security": "provider_engine_xray_security",
      "engine_xray_host_present": "provider_engine_xray_host_present",
      "engine_xray_host_redacted": "provider_engine_xray_host_redacted",
      "engine_xray_server_name_present": "provider_engine_xray_server_name_present",
      "engine_xray_server_name_redacted": "provider_engine_xray_server_name_redacted",
      "engine_xray_path_present": "provider_engine_xray_path_present",
      "engine_xray_path_redacted": "provider_engine_xray_path_redacted",
      "engine_xray_remote_port_present": "provider_engine_xray_remote_port_present",
      "engine_xray_local_port_present": "provider_engine_xray_local_port_present",
      "engine_xray_remote_awg_loopback": "provider_engine_xray_remote_awg_loopback",
      "engine_xray_remote_awg_port_present": "provider_engine_xray_remote_awg_port_present",
      "engine_runtime_packet_flow_attached": "provider_engine_runtime_packet_flow_attached",
      "engine_runtime_contract_failed": "provider_engine_runtime_contract_failed",
      "engine_runtime_engine_ready_reported": "provider_engine_runtime_engine_ready_reported",
      "engine_runtime_engine_running_reported": "provider_engine_runtime_engine_running_reported",
      "engine_runtime_awg_started": "provider_engine_runtime_awg_started",
      "engine_runtime_xray_started": "provider_engine_runtime_xray_started",
      "engine_runtime_secret_material_redacted": "provider_engine_runtime_secret_material_redacted",
      "engine_runtime_status_sanitized": "provider_engine_runtime_status_sanitized",
      "lifecycle_schema_version": "provider_lifecycle_schema_version",
      "lifecycle_event": "provider_lifecycle_event",
      "lifecycle_engine_running": "provider_lifecycle_engine_running",
      "lifecycle_suspended": "provider_lifecycle_suspended",
      "app_message_schema_version": "provider_app_message_schema_version",
      "app_message_command": "provider_app_message_command",
      "app_message_command_is_health": "provider_app_message_command_is_health",
      "app_message_accepted": "provider_app_message_accepted",
      "app_message_bytes": "provider_app_message_bytes",
      "app_message_too_large": "provider_app_message_too_large",
      "app_message_raw_payload_redacted": "provider_app_message_raw_payload_redacted",
      "app_message_engine_running": "provider_app_message_engine_running",
      "previous_stage_before_stop": "provider_previous_stage_before_stop",
      "previous_healthy_before_stop": "provider_previous_healthy_before_stop",
      "previous_engine_ready_before_stop": "provider_previous_engine_ready_before_stop",
      "previous_network_settings_ready_before_stop": "provider_previous_network_settings_ready_before_stop",
      "previous_network_settings_applied_before_stop": "provider_previous_network_settings_applied_before_stop",
      "previous_peer_endpoint_kind_before_stop": "provider_previous_peer_endpoint_kind_before_stop",
      "previous_transport_endpoint_kind_before_stop": "provider_previous_transport_endpoint_kind_before_stop",
      "previous_network_settings_remote_address_kind_before_stop": "provider_previous_network_settings_remote_address_kind_before_stop",
      "previous_network_settings_remote_address_source_before_stop": "provider_previous_network_settings_remote_address_source_before_stop",
      "previous_transport_mode_before_stop": "provider_previous_transport_mode_before_stop",
      "previous_xray_enabled_before_stop": "provider_previous_xray_enabled_before_stop",
      "previous_engine_transport_mode_before_stop": "provider_previous_engine_transport_mode_before_stop",
      "previous_engine_bundle_probe_before_stop": "provider_previous_engine_bundle_probe_before_stop",
      "previous_engine_bundle_all_required_components_present_before_stop": "provider_previous_engine_bundle_all_required_components_present_before_stop",
      "previous_engine_runtime_engine_ready_reported_before_stop": "provider_previous_engine_runtime_engine_ready_reported_before_stop",
      "previous_engine_runtime_engine_running_reported_before_stop": "provider_previous_engine_runtime_engine_running_reported_before_stop",
      "previous_app_message_command_before_stop": "provider_previous_app_message_command_before_stop",
      "previous_app_message_command_is_health_before_stop": "provider_previous_app_message_command_is_health_before_stop",
      "previous_app_message_accepted_before_stop": "provider_previous_app_message_accepted_before_stop",
      "previous_app_message_raw_payload_redacted_before_stop": "provider_previous_app_message_raw_payload_redacted_before_stop",
      "previous_app_message_engine_running_before_stop": "provider_previous_app_message_engine_running_before_stop",
      "engine_was_running_before_stop": "provider_engine_was_running_before_stop",
      "shared_config_private_key_redacted": "provider_shared_config_private_key_redacted",
      "stop_reason": "provider_stop_reason",
      // DEV-ONLY containment, surfaced so the app can never mistake a contained
      // dev run for a validated full-tunnel one. Only a Debug PacketTunnel appex
      // ever writes these — the containment path is inside `#if DEBUG` in
      // `ios/PacketTunnel/PacketTunnelProvider.swift` — so in a release build
      // every one of these is simply absent from the provider status document
      // and this mapping copies nothing. `provider_dev_containment_active` is
      // the term `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields` uses
      // to fail `leak_protection_config_passed` for a contained session, which
      // is what stops a contained iOS run from reading as a passing full-tunnel
      // leak-protection posture. Mirrors the macOS mapping at
      // `macos/Runner/MainFlutterWindow.swift`, plus the
      // `dev_containment_observed_*` fields, which iOS adds and macOS does not:
      // those are read back off the settings object that was actually built,
      // not derived from the plan that intended it.
      "dev_containment_active": "provider_dev_containment_active",
      "dev_containment_requested": "provider_dev_containment_requested",
      "dev_containment_supported_by_build": "provider_dev_containment_supported_by_build",
      "dev_containment_kind": "provider_dev_containment_kind",
      "dev_containment_default_ipv4_route_installed": "provider_dev_containment_default_ipv4_route_installed",
      "dev_containment_ipv6_settings_installed": "provider_dev_containment_ipv6_settings_installed",
      "dev_containment_dns_settings_installed": "provider_dev_containment_dns_settings_installed",
      "dev_containment_test_route_usable": "provider_dev_containment_test_route_usable",
      "dev_containment_test_route_explicit": "provider_dev_containment_test_route_explicit",
      "dev_containment_test_route_prefix_length": "provider_dev_containment_test_route_prefix_length",
      "dev_containment_included_route_count": "provider_dev_containment_included_route_count",
      "dev_containment_transport_exclusion_route_present": "provider_dev_containment_transport_exclusion_route_present",
      "dev_containment_config_requested_default_route": "provider_dev_containment_config_requested_default_route",
      "dev_containment_config_requested_ipv6_leak_protection": "provider_dev_containment_config_requested_ipv6_leak_protection",
      "dev_containment_config_requested_full_tunnel_dns": "provider_dev_containment_config_requested_full_tunnel_dns",
      "dev_containment_observed": "provider_dev_containment_observed",
      "dev_containment_observed_contained": "provider_dev_containment_observed_contained",
      "dev_containment_observed_included_route_count": "provider_dev_containment_observed_included_route_count",
      "dev_containment_observed_included_route_prefix_lengths": "provider_dev_containment_observed_included_route_prefix_lengths",
      "dev_containment_observed_default_ipv4_route_installed": "provider_dev_containment_observed_default_ipv4_route_installed",
      "dev_containment_observed_ipv6_settings_installed": "provider_dev_containment_observed_ipv6_settings_installed",
      "dev_containment_observed_dns_settings_installed": "provider_dev_containment_observed_dns_settings_installed",
      // The winn/3 runtime memory numbers. The provider samples BOTH
      // `TASK_VM_INFO.phys_footprint` (what jetsam accounts against it) and
      // `os_proc_available_memory()` (what the OS says is left for THIS
      // process, on this OS version and device) and writes them into the
      // shared status document -- but until these rows existed nothing
      // forwarded them, so the app could never read the one measurement the
      // runtime memory gate has to be calibrated against. A number that is
      // written and never read is not a measurement.
      //
      // Absent stays absent: `safeMappedStatusValue` drops a key the provider
      // did not write rather than defaulting it, so "not sampled" can never be
      // mistaken for a footprint of zero. `*_measured` / `*_taken` are what
      // distinguish the two.
      "winn_memory_sample_taken": "provider_winn_memory_sample_taken",
      "winn_memory_sample_phys_footprint_bytes": "provider_winn_memory_sample_phys_footprint_bytes",
      "winn_memory_sample_available_bytes": "provider_winn_memory_sample_available_bytes",
      "winn_memory_sample_available_measured": "provider_winn_memory_sample_available_measured",
      "winn_memory_gate_checked": "provider_winn_memory_gate_checked",
      "winn_memory_gate_allowed": "provider_winn_memory_gate_allowed",
      "winn_memory_gate_carrier": "provider_winn_memory_gate_carrier",
      "winn_memory_gate_refusal_reason": "provider_winn_memory_gate_refusal_reason",
      "winn_memory_gate_required_bytes": "provider_winn_memory_gate_required_bytes",
      "winn_memory_gate_phys_footprint_bytes": "provider_winn_memory_gate_phys_footprint_bytes",
      "winn_memory_gate_available_bytes": "provider_winn_memory_gate_available_bytes",
      "winn_memory_gate_available_measured": "provider_winn_memory_gate_available_measured",
      // THE TIER-2 ARTIFACT LOOKUP DIAGNOSTICS, for the winn component.
      //
      // `WinsNativeEngineArtifactLocator` publishes these on every resolve so
      // that "native engine component is not bundled" can be interrogated
      // instead of believed — that lie cost a whole lane. They are
      // `engine_runtime_`-prefixed precisely so the PROVIDER's own
      // `safeRuntimeStatusKey` allowlist admits them into the status document,
      // and it does.
      //
      // But the app-side forwarding below is a SECOND, independent allowlist:
      // an explicit table plus `WinsWinnSeamObservability.publishedStatusKeys`,
      // with no prefix pass-through. The lookup keys are in neither, so every
      // one of them was written by the provider and then dropped at this
      // boundary — the app could never read the one diagnostic the tier-2
      // resolver exists to produce. Same defect, and same repair, as the
      // `winn_memory_*` rows immediately above: a number that is written and
      // never read is not a measurement.
      //
      // Absent stays absent: `safeMappedStatusValue` drops a key the provider
      // did not write rather than defaulting it, so a component that resolved
      // via tier 1 (`linked_in_process`, which publishes no FrameworkProbe
      // fields) is distinguishable from one whose probe genuinely saw false.
      "engine_runtime_lookup_schema_version": "provider_engine_runtime_lookup_schema_version",
      "engine_runtime_lookup_winn_packet_engine_resolved": "provider_engine_runtime_lookup_winn_packet_engine_resolved",
      "engine_runtime_lookup_winn_packet_engine_resolved_via": "provider_engine_runtime_lookup_winn_packet_engine_resolved_via",
      "engine_runtime_lookup_winn_packet_engine_candidate_dir_count": "provider_engine_runtime_lookup_winn_packet_engine_candidate_dir_count",
      "engine_runtime_lookup_winn_packet_engine_linked_in_process": "provider_engine_runtime_lookup_winn_packet_engine_linked_in_process",
      "engine_runtime_lookup_winn_packet_engine_fw_dir_found": "provider_engine_runtime_lookup_winn_packet_engine_fw_dir_found",
      "engine_runtime_lookup_winn_packet_engine_bin_exists": "provider_engine_runtime_lookup_winn_packet_engine_bin_exists",
      "engine_runtime_lookup_winn_packet_engine_bin_readable": "provider_engine_runtime_lookup_winn_packet_engine_bin_readable",
      "engine_runtime_lookup_winn_packet_engine_bin_exec_bit": "provider_engine_runtime_lookup_winn_packet_engine_bin_exec_bit",
      "engine_runtime_lookup_winn_packet_engine_info_plist_found": "provider_engine_runtime_lookup_winn_packet_engine_info_plist_found",
      "engine_runtime_lookup_winn_packet_engine_declared_exec_present": "provider_engine_runtime_lookup_winn_packet_engine_declared_exec_present",
      "engine_runtime_lookup_winn_packet_engine_declared_exec_matches": "provider_engine_runtime_lookup_winn_packet_engine_declared_exec_matches",
      // Teardown: does `setTunnelNetworkSettings(nil)` actually release
      // anything, or does iOS reproduce the macOS `NEAgentErrorDomain` code 1
      // refusal? The provider already records the answer; until these rows
      // existed nothing carried it back to the app, so the question could only
      // be answered by reading the appex log by hand. `outcome` is one of
      // `released`, `failed`, or `deadline`, and the domain/code are only
      // present when it failed.
      "network_settings_release_requested": "provider_network_settings_release_requested",
      "network_settings_release_outcome": "provider_network_settings_release_outcome",
      "network_settings_release_completed": "provider_network_settings_release_completed",
      "network_settings_release_failed": "provider_network_settings_release_failed",
      "network_settings_release_context": "provider_network_settings_release_context",
      "network_settings_release_elapsed_ms": "provider_network_settings_release_elapsed_ms",
      "network_settings_release_deadline_ms": "provider_network_settings_release_deadline_ms",
      "network_settings_release_error_domain": "provider_network_settings_release_error_domain",
      "network_settings_release_error_code": "provider_network_settings_release_error_code"
    ]
    for (source, target) in mappings {
      if let value = status[source],
         let mappedValue = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
          value,
          sourceKey: source
         ) {
        fields[target] = mappedValue
      }
    }
    // The Winn seam counters, forwarded from the single list that mints them
    // rather than retyped into the table above — see
    // WinsWinnSeamObservability.publishedStatusKeys. Same value sanitizer, and
    // the same `provider_` namespace, so they are ordinary provider fields
    // downstream.
    //
    // A counter that is ABSENT here stays absent: it is never defaulted to 0.
    // The wrapper omits counters it could not sample, and a 0 that actually
    // means "not measured" would recreate the blindness these counters exist to
    // remove. `..._available` is what distinguishes the two.
    for source in WinsWinnSeamObservability.publishedStatusKeys {
      if let value = status[source],
         let mappedValue = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
          value,
          sourceKey: source
         ) {
        fields["provider_" + source] = mappedValue
      }
    }
    return fields
  }

  private func expectedStatusGeneration(
    from manager: NETunnelProviderManager?
  ) -> (generation: String?, invalid: Bool) {
    guard let tunnelProtocol = manager?.protocolConfiguration as? NETunnelProviderProtocol else {
      return (nil, false)
    }
    let rawGeneration = (tunnelProtocol.providerConfiguration?["status_generation"] as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !rawGeneration.isEmpty else {
      return (nil, false)
    }
    let safeGeneration = WinsPacketTunnelProviderStatus.safeStatusGeneration(rawGeneration)
    return safeGeneration.isEmpty ? (nil, true) : (safeGeneration, false)
  }

  private func latestProviderStatus() -> (status: [String: Any]?, fields: [String: Any]) {
    let fileManager = FileManager.default
    guard let containerUrl = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier
    ) else {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": false
      ])
    }
    let statusUrl = containerUrl
      .appendingPathComponent(Self.sharedConfigDirectoryName, isDirectory: true)
      .appendingPathComponent(Self.sharedStatusFileName, isDirectory: false)
    if (try? fileManager.destinationOfSymbolicLink(atPath: statusUrl.path)) != nil {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": true,
        "provider_status_file_present": true,
        "provider_status_file_symbolic_link": true,
        "provider_status_file_readable": false,
        "provider_status_max_file_size_bytes": WinsPacketTunnelProviderStatus.maxStatusFileBytes
      ])
    }
    guard fileManager.fileExists(atPath: statusUrl.path) else {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": true,
        "provider_status_file_present": false
      ])
    }
    let attributes = try? fileManager.attributesOfItem(atPath: statusUrl.path)
    let fileSize = (attributes?[.size] as? NSNumber)?.uint64Value ?? 0
    let statusFileSize = WinsPacketTunnelProviderStatus.safeStatusByteCount(fileSize)
    let maxStatusFileBytes = WinsPacketTunnelProviderStatus.maxStatusFileBytes
    guard fileSize <= UInt64(maxStatusFileBytes) else {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": true,
        "provider_status_file_present": true,
        "provider_status_file_too_large": true,
        "provider_status_file_size_bytes": statusFileSize,
        "provider_status_max_file_size_bytes": maxStatusFileBytes
      ])
    }
    guard let fileHandle = try? FileHandle(forReadingFrom: statusUrl) else {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": true,
        "provider_status_file_present": true,
        "provider_status_file_readable": false,
        "provider_status_file_size_bytes": statusFileSize,
        "provider_status_max_file_size_bytes": maxStatusFileBytes
      ])
    }
    let data = fileHandle.readData(ofLength: maxStatusFileBytes + 1)
    fileHandle.closeFile()
    guard data.count <= maxStatusFileBytes else {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": true,
        "provider_status_file_present": true,
        "provider_status_file_too_large": true,
        "provider_status_file_size_bytes": WinsPacketTunnelProviderStatus.safeStatusByteCount(
          max(fileSize, UInt64(data.count))
        ),
        "provider_status_max_file_size_bytes": maxStatusFileBytes
      ])
    }
    guard let status = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return (nil, [
        "provider_status_available": false,
        "provider_status_container_available": true,
        "provider_status_file_present": true,
        "provider_status_file_readable": true,
        "provider_status_json_valid": false,
        "provider_status_file_size_bytes": data.count,
        "provider_status_max_file_size_bytes": maxStatusFileBytes
      ])
    }
    return (status, [
      "provider_status_available": true,
      "provider_status_container_available": true,
      "provider_status_file_present": true,
      "provider_status_file_readable": true,
      "provider_status_json_valid": true,
      "provider_status_file_size_bytes": data.count,
      "provider_status_max_file_size_bytes": maxStatusFileBytes
    ])
  }

  private func writeSharedTunnelStatus(_ status: [String: Any], in directory: URL) throws {
    let statusUrl = directory.appendingPathComponent(Self.sharedStatusFileName, isDirectory: false)
    let data = try JSONSerialization.data(
      withJSONObject: status,
      options: [.prettyPrinted, .sortedKeys]
    )
    try WinsAppGroupFileWriter.writeData(data, to: statusUrl)
  }

  private static func bridgeError(code: Int, message: String) -> NSError {
    NSError(
      domain: "org.winsvpn.AppleTunnelBridge",
      code: code,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }

  private static func validProviderStatusTimestamp(_ value: String) -> Bool {
    guard !value.isEmpty, value.count <= 40 else {
      return false
    }
    return ISO8601DateFormatter().date(from: value) != nil
  }

  private func machineIdentifier() -> String {
    var systemInfo = utsname()
    uname(&systemInfo)
    return withUnsafePointer(to: &systemInfo.machine) {
      $0.withMemoryRebound(to: CChar.self, capacity: 1) {
        String(validatingUTF8: $0) ?? "iOS Device"
      }
    }
  }

  private static func statusName(_ status: NEVPNStatus) -> String {
    switch status {
    case .invalid:
      return "invalid"
    case .disconnected:
      return "disconnected"
    case .connecting:
      return "connecting"
    case .connected:
      return "connected"
    case .reasserting:
      return "reasserting"
    case .disconnecting:
      return "disconnecting"
    @unknown default:
      return "unknown"
    }
  }

  private static func topViewController() -> UIViewController? {
    let windowScenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    let keyWindow = windowScenes.flatMap { $0.windows }.first { $0.isKeyWindow }
    var topController = keyWindow?.rootViewController
    while let presented = topController?.presentedViewController {
      topController = presented
    }
    return topController
  }
}
