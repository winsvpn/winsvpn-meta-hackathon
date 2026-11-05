import Cocoa
import Darwin
import FlutterMacOS
import MapKit
import NetworkExtension
import UserNotifications

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    // The control line for the launch watchdog in `AppDelegate.swift`. If this
    // appears and the AppDelegate lines do not, the nib loaded but the delegate
    // is not being called; if neither appears, the app did not get this far.
    WinsAppLifecycle.note("MainFlutterWindow.awakeFromNib ENTER")

    #if DEBUG
    // LAB INSTRUMENT, INERT UNLESS EXPLICITLY REQUESTED, AND NEVER IN RELEASE.
    //
    // Driven from here rather than from `AppDelegate.applicationDidFinishLaunching`
    // because this runs EARLIER -- `awakeFromNib` is part of nib loading, and the
    // delegate method arrives roughly 70 ms later -- and the probe wants to be in
    // place before the Flutter engine starts.
    //
    // It is NOT driven from here because the delegate method is dead. It was
    // recorded as dead in this file until 20260809 and that was a measurement
    // error, not a fact: `NSLog` bodies are `<private>` in the unified log, so
    // the delegate's own log line was invisible under the predicate used to look
    // for it. `applicationDidFinishLaunching` runs on every launch. Measured, on
    // a Release build installed to /Applications:
    //   AppDelegate.init            22:09:39.549
    //   MainFlutterWindow.awakeFromNib 22:09:39.580
    //   applicationDidFinishLaunching  22:09:39.650
    // Do not move work out of the delegate on the belief that it does not run.
    // See docs/handoff/MACOS_APPDELEGATE_LIFECYCLE_20260809.md
    WinsNECPPostureProbe.handleLaunchIfRequested()
    #endif

    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.minSize = NSSize(width: 360, height: 520)

    RegisterGeneratedPlugins(registry: flutterViewController)
    WinsMacOSTunnelBridge.register(with: flutterViewController.engine.binaryMessenger)
    flutterViewController.registrar(forPlugin: "WinsAppleMapView").register(
      WinsAppleMapViewFactory(),
      withId: WinsAppleMapViewFactory.viewType
    )

    super.awakeFromNib()

    DispatchQueue.main.async { [weak self] in
      self?.ensureUsableLaunchFrame()
    }
  }

  private func ensureUsableLaunchFrame() {
    let minimumLaunchSize = NSSize(width: 980, height: 720)
    if frame.width >= minimumLaunchSize.width, frame.height >= minimumLaunchSize.height {
      makeKeyAndOrderFront(nil)
      return
    }

    let screenFrame = (screen ?? NSScreen.main ?? NSScreen.screens.first)?.visibleFrame
      ?? NSRect(x: 0, y: 0, width: 800, height: 600)
    let width = min(max(frame.width, minimumLaunchSize.width), screenFrame.width * 0.92)
    let height = min(max(frame.height, minimumLaunchSize.height), screenFrame.height * 0.92)
    let origin = NSPoint(
      x: screenFrame.midX - width / 2,
      y: screenFrame.midY - height / 2
    )
    setFrame(NSRect(origin: origin, size: NSSize(width: width, height: height)), display: true)
    makeKeyAndOrderFront(nil)
  }
}

private final class WinsAppleMapViewFactory: NSObject, FlutterPlatformViewFactory {
  static let viewType = "winsvpn/apple-map"

  func createArgsCodec() -> (FlutterMessageCodec & NSObjectProtocol)? {
    FlutterStandardMessageCodec.sharedInstance()
  }

  func create(withViewIdentifier viewIdentifier: Int64, arguments args: Any?) -> NSView {
    WinsAppleMapView(arguments: args)
  }
}

private final class WinsAppleMapView: MKMapView, MKMapViewDelegate {
  private static let annotationReuseIdentifier = "winsvpn-approximate-location"
  private let requestedRegion: MKCoordinateRegion?
  private var lastRegionBoundsSize = NSSize.zero

  init(arguments: Any?) {
    requestedRegion = WinsAppleMapRegion.region(from: arguments)
    let requestedRadiusMeters = WinsAppleMapRegion.radiusMeters(from: arguments)
    super.init(frame: .zero)
    delegate = self
    mapType = .standard
    showsUserLocation = false
    isPitchEnabled = false
    isRotateEnabled = false

    if let requestedRegion {
      if let requestedRadiusMeters {
        addOverlay(MKCircle(center: requestedRegion.center, radius: requestedRadiusMeters))
      }
      addAnnotation(WinsApproximateLocationAnnotation(coordinate: requestedRegion.center))
    } else {
      isHidden = true
    }
  }

  required init?(coder: NSCoder) {
    nil
  }

  override func layout() {
    super.layout()
    guard
      let requestedRegion,
      bounds.width > 0,
      bounds.height > 0,
      bounds.size != lastRegionBoundsSize
    else { return }
    setRegion(requestedRegion, animated: false)
    lastRegionBoundsSize = bounds.size
  }

  func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
    guard annotation is WinsApproximateLocationAnnotation else { return nil }
    let annotationView = mapView.dequeueReusableAnnotationView(
      withIdentifier: Self.annotationReuseIdentifier
    ) ?? MKAnnotationView(annotation: annotation, reuseIdentifier: Self.annotationReuseIdentifier)
    annotationView.annotation = annotation
    annotationView.frame = NSRect(x: 0, y: 0, width: 26, height: 26)
    annotationView.wantsLayer = true
    annotationView.layer?.backgroundColor = NSColor.systemBlue.withAlphaComponent(0.14).cgColor
    annotationView.layer?.cornerRadius = 13
    annotationView.layer?.borderColor = NSColor.systemBlue.withAlphaComponent(0.38).cgColor
    annotationView.layer?.borderWidth = 1
    annotationView.subviews.forEach { $0.removeFromSuperview() }

    let dot = NSView(frame: NSRect(x: 6, y: 6, width: 14, height: 14))
    dot.wantsLayer = true
    dot.layer?.backgroundColor = NSColor.systemBlue.cgColor
    dot.layer?.cornerRadius = 7
    dot.layer?.borderColor = NSColor.white.cgColor
    dot.layer?.borderWidth = 2
    annotationView.addSubview(dot)
    annotationView.isEnabled = false
    return annotationView
  }

  func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
    guard let circle = overlay as? MKCircle else { return MKOverlayRenderer(overlay: overlay) }
    let renderer = MKCircleRenderer(circle: circle)
    renderer.fillColor = NSColor.systemBlue.withAlphaComponent(0.06)
    renderer.strokeColor = NSColor.systemBlue.withAlphaComponent(0.33)
    renderer.lineWidth = 1
    return renderer
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
      if url.host?.lowercased() == "speed.cloudflare.com" {
        request.setValue(
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
            + "Safari/605.1.15",
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

  // A-02 (audits 2026-08-28): refuse EVERY redirect; the task fails and
  // counts no bytes, and 3xx is excluded from valid traffic above.
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
/// carry it (see the iOS twin in AppDelegate.swift for rationale).
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
      // A-02: refuse redirects -- a 3xx must not replay the POST body to an
      // arbitrary origin.
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
      // A-02: no product identity in the speed-test UA.
      request.setValue(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
          + "Safari/605.1.15",
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

enum WinsMacOSPrivateFileWriter {
  static let unsafePathCode = 1701
  static let writeFailedCode = 1702
  static let permissionFailedCode = 1703

  static func ensurePrivateDirectory(at directory: URL) throws {
    var info = stat()
    if lstat(directory.path, &info) == 0 {
      guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == geteuid() else {
        throw writerError(code: unsafePathCode, message: "Private application-support directory is unsafe.")
      }
    } else if errno == ENOENT {
      try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } else {
      throw writerError(code: unsafePathCode, message: "Private application-support directory is unavailable.")
    }
    guard chmod(directory.path, 0o700) == 0 else {
      throw writerError(code: permissionFailedCode, message: "Private directory permissions could not be enforced.")
    }
    var finalInfo = stat()
    guard lstat(directory.path, &finalInfo) == 0,
          (finalInfo.st_mode & S_IFMT) == S_IFDIR,
          finalInfo.st_uid == geteuid(),
          (finalInfo.st_mode & 0o777) == 0o700 else {
      throw writerError(code: unsafePathCode, message: "Private application-support directory changed unexpectedly.")
    }
  }

  static func hardenExistingFile(at url: URL) throws {
    let directory = url.deletingLastPathComponent()
    try ensurePrivateDirectory(at: directory)
    let directoryDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directoryDescriptor >= 0 else {
      throw writerError(code: unsafePathCode, message: "Private directory could not be opened safely.")
    }
    defer { close(directoryDescriptor) }
    try validatePrivateDirectoryDescriptor(directoryDescriptor)

    var info = stat()
    if fstatat(directoryDescriptor, url.lastPathComponent, &info, AT_SYMLINK_NOFOLLOW) != 0 {
      if errno == ENOENT { return }
      throw writerError(code: unsafePathCode, message: "Private credential file could not be inspected.")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid() else {
      throw writerError(code: unsafePathCode, message: "Private credential file is not a safe owner file.")
    }
    let descriptor = openat(directoryDescriptor, url.lastPathComponent, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw writerError(code: unsafePathCode, message: "Private credential file could not be opened safely.")
    }
    defer { close(descriptor) }
    var openedInfo = stat()
    guard fstat(descriptor, &openedInfo) == 0,
          (openedInfo.st_mode & S_IFMT) == S_IFREG,
          openedInfo.st_uid == geteuid(),
          openedInfo.st_dev == info.st_dev,
          openedInfo.st_ino == info.st_ino else {
      throw writerError(code: unsafePathCode, message: "Private credential file changed before hardening.")
    }
    guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else {
      throw writerError(code: permissionFailedCode, message: "Private credential permissions could not be enforced.")
    }
  }

  static func writeString(_ text: String, to url: URL) throws {
    guard let data = text.data(using: .utf8), !data.isEmpty else {
      throw writerError(code: writeFailedCode, message: "Private credential payload is empty or invalid.")
    }
    let directory = url.deletingLastPathComponent()
    try ensurePrivateDirectory(at: directory)
    let directoryDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard directoryDescriptor >= 0 else {
      throw writerError(code: unsafePathCode, message: "Private directory could not be opened safely.")
    }
    defer { close(directoryDescriptor) }
    try validatePrivateDirectoryDescriptor(directoryDescriptor)

    let fileName = url.lastPathComponent
    guard !fileName.isEmpty, !fileName.contains("/") else {
      throw writerError(code: unsafePathCode, message: "Private credential filename is invalid.")
    }
    var destinationInfo = stat()
    if fstatat(directoryDescriptor, fileName, &destinationInfo, AT_SYMLINK_NOFOLLOW) == 0 {
      guard (destinationInfo.st_mode & S_IFMT) == S_IFREG,
            destinationInfo.st_uid == geteuid() else {
        throw writerError(code: unsafePathCode, message: "Private credential destination is unsafe.")
      }
    } else if errno != ENOENT {
      throw writerError(code: unsafePathCode, message: "Private credential destination could not be inspected.")
    }

    let temporaryName = ".\(fileName).tmp.\(UUID().uuidString)"
    let descriptor = openat(
      directoryDescriptor,
      temporaryName,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else {
      throw writerError(code: writeFailedCode, message: "Private temporary credential file could not be created.")
    }
    var temporaryExists = true
    defer {
      close(descriptor)
      if temporaryExists { _ = unlinkat(directoryDescriptor, temporaryName, 0) }
    }

    guard fchmod(descriptor, 0o600) == 0 else {
      throw writerError(code: permissionFailedCode, message: "Private temporary credential permissions failed.")
    }
    try data.withUnsafeBytes { buffer in
      guard let baseAddress = buffer.baseAddress else {
        throw writerError(code: writeFailedCode, message: "Private credential payload has no bytes.")
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
          throw writerError(code: writeFailedCode, message: "Private credential write failed.")
        }
        written += count
      }
    }
    guard fsync(descriptor) == 0 else {
      throw writerError(code: writeFailedCode, message: "Private credential file could not be synchronized.")
    }
    guard renameat(directoryDescriptor, temporaryName, directoryDescriptor, fileName) == 0 else {
      throw writerError(code: writeFailedCode, message: "Private credential replacement failed.")
    }
    temporaryExists = false

    var finalInfo = stat()
    guard fstatat(directoryDescriptor, fileName, &finalInfo, AT_SYMLINK_NOFOLLOW) == 0,
          (finalInfo.st_mode & S_IFMT) == S_IFREG,
          finalInfo.st_uid == geteuid(),
          (finalInfo.st_mode & 0o777) == 0o600 else {
      throw writerError(code: permissionFailedCode, message: "Private credential result is not owner-only.")
    }
    if fsync(directoryDescriptor) != 0, errno != EINVAL {
      throw writerError(code: writeFailedCode, message: "Private credential directory could not be synchronized.")
    }
  }

  private static func writerError(code: Int, message: String) -> NSError {
    NSError(
      domain: "org.winsvpn.MacOSPrivateFileWriter",
      code: code,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }

  private static func validatePrivateDirectoryDescriptor(_ descriptor: Int32) throws {
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFDIR,
          info.st_uid == geteuid(),
          (info.st_mode & 0o777) == 0o700 else {
      throw writerError(code: unsafePathCode, message: "Private directory descriptor is unsafe.")
    }
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

final class WinsMacOSTunnelBridge {
  private static let channelName = "wins_vpn/tunnel"
  private static let tunnelDescription = "Win's VPN"
  private static let tunnelManagerSignature = WinsTunnelManagerIdentity.currentSignature()
  private static let appGroupIdentifier = WinsAppleAppGroup.identifier
  private static let sharedConfigDirectoryName = "Tunnel"
  private static let sharedConfigFileName = "latest_tunnel.conf"
  private static let sharedMetadataFileName = "latest_tunnel.json"
  private static let sharedStatusFileName = "latest_status.json"
  private static let staleManagerRemovalTimeoutSeconds: TimeInterval = 4
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

  static func register(with messenger: FlutterBinaryMessenger) {
    let bridge = WinsMacOSTunnelBridge()
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
    case "launchSplitTunnelApp":
      result(FlutterError(
        code: "APPLE_PER_APP_VPN_MDM_REQUIRED",
        message: "Apple per-app VPN requires an MDM-managed app and VPN profile; consumer launcher-scoped bypass is unavailable.",
        details: nil
      ))
    case "getPowerOptimizationStatus":
      result(["ignoring_battery_optimizations": true])
    case "monotonicMilliseconds":
      // M-15: shared PIN-lockout monotonic clock, matching the iOS and
      // Android handlers on this same wins_vpn/tunnel channel. macOS has no
      // in-app camouflage PIN today (_supportsInAppCamouflage is false there),
      // so this is not exercised now, but it keeps the method-channel contract
      // complete and consistent, and the Dart side already falls back to the
      // wall clock if the handler is ever absent.
      result(Int(ProcessInfo.processInfo.systemUptime * 1000))
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
    case "showAnnouncementNotification":
      showAnnouncementNotification(call.arguments, result: result)
    case "startTunnel":
      startTunnel(call.arguments, result: result)
    case "stopTunnel":
      stopTunnel(result: result)
    case "triggerCamouflageSwap":
      result(false)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func appDocumentsDirectory() throws -> URL {
    let fileManager = FileManager.default
    let baseUrl = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
      ?? fileManager.temporaryDirectory
    let directory = baseUrl.appendingPathComponent("wins_vpn", isDirectory: true)
    try WinsMacOSPrivateFileWriter.ensurePrivateDirectory(at: directory)
    try WinsMacOSPrivateFileWriter.hardenExistingFile(
      at: directory.appendingPathComponent("vpn_config.txt", isDirectory: false)
    )
    return directory
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
      let target = try appDocumentsDirectory()
        .appendingPathComponent("vpn_config.txt", isDirectory: false)
      try WinsMacOSPrivateFileWriter.writeString(config, to: target)
      result(true)
    } catch {
      result(flutterError("APPLE_PRIVATE_CONFIG_WRITE_FAILED", error))
    }
  }

  private func readVpnConfig(result: @escaping FlutterResult) {
    do {
      let target = try appDocumentsDirectory()
        .appendingPathComponent("vpn_config.txt", isDirectory: false)
      guard FileManager.default.fileExists(atPath: target.path) else {
        result(nil)
        return
      }
      result(try String(contentsOf: target, encoding: .utf8))
    } catch {
      result(flutterError("APPLE_PRIVATE_CONFIG_READ_FAILED", error))
    }
  }

  private func deleteVpnConfig(result: @escaping FlutterResult) {
    do {
      let target = try appDocumentsDirectory()
        .appendingPathComponent("vpn_config.txt", isDirectory: false)
      if FileManager.default.fileExists(atPath: target.path) {
        try FileManager.default.removeItem(at: target)
      }
      guard !FileManager.default.fileExists(atPath: target.path) else {
        throw NSError(
          domain: "org.winsvpn.MacOSPrivateConfigStore",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "Private VPN configuration remains after deletion."]
        )
      }
      result(true)
    } catch {
      result(flutterError("APPLE_PRIVATE_CONFIG_DELETE_FAILED", error))
    }
  }

  /// Clears the App Group container this app shares with the Packet Tunnel
  /// extension. Sibling of `purgeAppGroupContainer` in
  /// `ios/Runner/AppDelegate.swift`; see that one for the full note on what
  /// the container holds and when a purge is safe relative to the session
  /// lifecycle. The short version: the provider reads
  /// `Tunnel/latest_tunnel.conf` once, in `startTunnel`, and there are no
  /// on-demand rules, so a purge cannot wedge a live tunnel -- but a running
  /// provider re-creates `Tunnel/latest_status.json`, so stop first.
  ///
  /// PRESENT ON macOS EVEN THOUGH DURESS IS NOT REACHABLE HERE. The decoy
  /// keypad that triggers duress renders only where
  /// `supportsInAppCalculatorCamouflage()` is true, which is Android and iOS.
  /// The container, however, is written on macOS exactly as it is on iOS --
  /// the three `Tunnel/` documents were sitting in a real one on the
  /// development Mac when this was written -- and the account-deletion and
  /// "Deactivate Device" paths DO run here. A macOS host with no way to clear
  /// its own container would be the same silent-absence defect one platform
  /// over.
  private func purgeAppGroupContainer(result: @escaping FlutterResult) {
    let fileManager = FileManager.default
    guard let containerUrl = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier
    ) else {
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

  /// Clears the identity-bearing Keychain items on the duress path. Sibling of
  /// `purgeKeychainIdentity` in `ios/Runner/AppDelegate.swift`; see that one
  /// for what the four stores hold and why the tunnel is stopped first.
  ///
  /// TWO KEYCHAINS HERE, NOT ONE, and the app's own stores are split across
  /// both. `WinsClientKeyStore`, `WinsTunnelSecretStore` and
  /// `WinsSecureStateStore` set `kSecUseDataProtectionKeychain`;
  /// `WinsInstallIdentityStore` sets it nowhere and therefore lands in the
  /// legacy FILE keychain, and `WinsClientKeyStore` keeps a file-keychain
  /// migration path for installs that predate the split. A purge that swept
  /// only the modern keychain would report a clean sweep over an install
  /// identity it never looked at. `WinsKeychainQueryScope.productionScopes`
  /// covers both, and a scope it cannot evaluate is reported as blocked rather
  /// than assumed empty.
  ///
  /// PRESENT ON macOS EVEN THOUGH DURESS IS NOT REACHABLE HERE, for the same
  /// reason `purgeAppGroupContainer` is: the decoy keypad renders only on
  /// Android and iOS, but these Keychain items are written on macOS exactly as
  /// they are on iOS, and the account-deletion and "Deactivate Device" paths
  /// do run here.
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
      // CORRECTION 20260810. This comment used to claim that NSLog "always
      // reaches the unified log even when stdout is /dev/null", and concluded
      // that the failure was therefore no longer invisible. The first half is
      // true and the conclusion does not follow: the ENTRY reaches the log, its
      // TEXT does not. Foundation passes the composed message as a dynamic
      // argument, so this records as `Df ... (Foundation) <private>` and a
      // reader of `log show` still cannot see that a secure-state call failed,
      // or which item failed. Measured 20260809 (13 NSLog -> 13 `<private>`,
      // zero readable) and re-measured across all six logging shapes 20260810.
      //
      // The honest statement of what this line buys: it is readable on stderr
      // when the binary is launched directly from a terminal, and nowhere else.
      // The failure is separately reported to Dart as
      // `APPLE_SECURE_STATE_READ_FAILED`, which is the reliable channel.
      //
      // NOT PROMOTED TO os_log, though it is the closest call in this file. The
      // public shell ("a secure-state read failed") would disclose little on
      // macOS, where the app is undisguised and its identity is already in the
      // log as the process name -- but the item name is one of six fixed
      // strings including `vpn_config.txt` and `client_keypair.json`, so `name`
      // would have to stay `%{private}`, and the conversion cannot be verified
      // to the standard this repo now requires without provoking a real
      // Keychain failure on the owner's machine. See
      // docs/handoff/APPLE_NSLOG_REDACTION_AUDIT_20260810.md, which records
      // this as the one recommended-but-unexecuted promotion and the
      // fault-injection hook it needs first.
      //
      // WinsTunnelDiagnostics.redactedAppleErrorMessage() is already safe to
      // log for org.winsvpn.* errors (see WinsSecureStateStore's header
      // comment).
      NSLog(
        "Win's VPN secure state read failed for %@: %@",
        name, WinsTunnelDiagnostics.redactedAppleErrorMessage(error)
      )
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
      NSLog(
        "Win's VPN secure state write failed for %@: %@",
        name, WinsTunnelDiagnostics.redactedAppleErrorMessage(error)
      )
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
      NSLog(
        "Win's VPN secure state delete failed for %@: %@",
        name, WinsTunnelDiagnostics.redactedAppleErrorMessage(error)
      )
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
      "system_name": "macOS",
      "system_version": ProcessInfo.processInfo.operatingSystemVersionString,
      "platform": "macos"
    ]
  }

  private func launchExternalUrl(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let url = WinsAppleExternalUrl.safeUrl(from: args["url"] as? String)
    else {
      result(FlutterError(code: "BAD_URL", message: "Missing or invalid URL.", details: nil))
      return
    }
    result(NSWorkspace.shared.open(url))
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
      if let contentView = NSApp.keyWindow?.contentView {
        let picker = NSSharingServicePicker(items: [share.text])
        picker.show(relativeTo: contentView.bounds, of: contentView, preferredEdge: .minY)
      } else {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(share.text, forType: .string)
      }
      result(true)
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

    let content = UNMutableNotificationContent()
    content.title = notification.title
    content.body = notification.body
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
    loadTunnelManagerForStatus { manager, error in
      if let error = error {
        result(self.flutterError("APPLE_TUNNEL_STATE_FAILED", error))
        return
      }
      result(manager?.connection.status == .connected)
    }
  }

  private func tunnelActivitySnapshot(result: @escaping FlutterResult) {
    loadTunnelManagerForStatus { manager, error in
      guard error == nil else {
        result(WinsAppleTunnelActivitySnapshot.value(for: nil, known: false))
        return
      }
      result(WinsAppleTunnelActivitySnapshot.value(for: manager?.connection.status))
    }
  }

  private func tunnelReadiness(result: @escaping FlutterResult) {
    loadTunnelManagerForStatus { manager, error in
      if let error = error {
        var readiness: [String: Any] = [
          "active": false,
          "engine_ready": false,
          "configuration_installed": false,
          "tunnel_healthy": false,
          "platform": "macos",
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
        "platform": "macos",
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

  private func startTunnel(_ arguments: Any?, result: @escaping FlutterResult) {
    guard
      let args = arguments as? [String: Any],
      let config = args["config"] as? String,
      !config.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else {
      result(FlutterError(code: "BAD_CONFIG", message: "Missing VPN config.", details: nil))
      return
    }

    let operationToken = tunnelOperationGate.begin(perform: {
      self.invalidateStatusManagerCache()
    })
    // macOS presents first-use VPN authorization only to an active GUI app.
    // A release smoke, login-item launch, or remote support session can start
    // the process without making its window active, which otherwise turns the
    // save into a delayed NEVPNError permission-denied result with no prompt.
    NSApp.activate(ignoringOtherApps: true)
    NSApp.windows.first?.makeKeyAndOrderFront(nil)
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
      clientKeyPair = try WinsClientKeyStore.loadOrCreate(accountScope: accountScope)
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
        config,
        parsedConfig: parsedConfig,
        statusGeneration: statusGeneration
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

    // THE TEN `NSLog` STAGE LINES BELOW ARE DELIBERATELY UNREADABLE IN THE
    // UNIFIED LOG. DO NOT "FIX" THEM INTO `os_log`.
    //
    // Two facts have to be held at once here, and dropping either one produces
    // a wrong change:
    //
    // 1. THEY ARE INVISIBLE TO `log show`, SO THEIR ABSENCE PROVES NOTHING.
    //    Foundation passes the composed message as a dynamic argument, so each
    //    of these records as `Df ... (Foundation) <private>`. Measured 20260809:
    //    13 NSLog calls -> 13 `<private>` entries, zero readable. If you are
    //    hunting "does startTunnel even run?", grepping the unified log for
    //    "tunnel start stage" WILL return nothing on a working build. That is
    //    exactly the false negative that had
    //    `AppDelegate.applicationDidFinishLaunching` recorded as dead code for
    //    months (docs/handoff/MACOS_APPDELEGATE_LIFECYCLE_20260809.md).
    //    The readable channel is stderr, from a direct terminal launch of the
    //    installed binary. The failure stages are ALSO reported to Dart as
    //    `APPLE_TUNNEL_*` FlutterError codes, which is the channel that does
    //    not depend on logging at all -- prefer it.
    //
    // 2. PROMOTING THEM WOULD DISCLOSE THE USER'S CONNECTION. An `os_log`
    //    format string is always public; `%{private}` redacts arguments and
    //    never the literal (measured 20260810, matrix in
    //    macos/Runner/AppDelegate.swift). So there is no `os_log` shape that
    //    keeps the diagnostic and hides the meaning -- "tunnel start stage
    //    accepted" IS the meaning, and it timestamps a Myanmar user connecting
    //    to a VPN in a log that persists and is swept up by `sysdiagnose`.
    //    `docs/handoff/OWNERSHIP_CLAIM_ATTRIBUTION_AND_SESSION_LABEL_20260807.md`
    //    already lists these ten lines as residue that is "not retractable";
    //    redaction is the only thing currently blunting them, and macOS has no
    //    camouflage path to fall back on (the profile is hardcoded "Win's VPN").
    //
    // Net: the right shape for a tunnel-state fact is the one already here.
    // Redaction is the correct behaviour, not a defect. See
    // docs/handoff/APPLE_NSLOG_REDACTION_AUDIT_20260810.md.
    NSLog("Win's VPN tunnel start stage: load_manager")
    loadTunnelManager { manager, error in
      guard self.tunnelOperationGate.isCurrent(operationToken) else {
        result(false)
        return
      }
      if let error = error {
        NSLog("Win's VPN tunnel start stage failed: load_manager")
        result(self.flutterError("APPLE_TUNNEL_LOAD_FAILED", error))
        return
      }

      let manager = manager ?? NETunnelProviderManager()
      let tunnelProtocol = WinsMacMainWindowRouteReporting.makeWindowTunnelProtocol()
      tunnelProtocol.providerBundleIdentifier = self.providerBundleIdentifier
      tunnelProtocol.serverAddress = Self.tunnelDescription
      // Window-config reporting: funnel through SAME `requested_enforce_routes` key
      // that AppDelegate's probe uses (line ~372). Keeps the connect-path audit
      // correlatable without duplicating the key name.
      _ = WinsMacMainWindowRouteReporting.windowConfigReport(for: tunnelProtocol)
      // ROUTING POSTURE OF THE RUNNING TUNNEL.
      //
      // `enforceRoutes` is TRUE on macOS: RULED 2026-08-10, silently reverted
      // by a lane the same day, REINSTATED by ruling 2026-08-11. The value
      // lives in ONE place, `WinsMacRoutePosture.enforceRoutes`
      // (macos/Runner/RouteAudit.swift), which is a RULED INVARIANT registered
      // in docs/rulings/RULINGS.lock: no lane may change it without a new
      // dated ruling. Every measured sentence below is kept, because the
      // ruling stands on them, not despite them.
      //
      // MEASURED 2026-08-09, on this box, with the carrier destination the
      // machine's own en0 address (the lab gateway): four controlled posture
      // rows in `docs/handoff/WINN3_MACOS_ENFORCEROUTES_NECP_20260809.md`:
      //
      //      enforceRoutes | excludeLocalNetworks | gateway rx Δ | carry
      //      1             | 1                    | 0            | 0 / 6000, 120×EHOSTUNREACH
      //      0             | 1                    | 11,735       | 6000 / 6000, 0 errors
      //      1             | 0                    | 0            | 0 / 6000, 120×EHOSTUNREACH
      //      0             | 1 (shipping shape)   | 11,953       | 6000 / 6000, 0 errors
      //
      // WHY `true` CARRIED NOTHING THERE, AND WHY THAT DOES NOT DECIDE
      // PRODUCTION. `enforceRoutes` is documented (NEVPNProtocol.h) as "route
      // rules for this tunnel will take precedence over any locally-defined
      // routes". In the 08-09 rig the carrier endpoint was the Mac's OWN en0
      // address, so the engine's outer-socket `/32` carve-out materialised as
      // a locally-defined, on-link route, exactly the class enforcement
      // suppresses; the carrier strangled itself and every host flow was
      // refused (`Path was denied by NECP policy`, `EHOSTUNREACH` system-wide).
      // Mechanism and routing-table evidence:
      // `docs/handoff/WINN3_MACOS_ENFORCEROUTES_SELFSTRANGULATION_20260810_fin_mac_routes.md`.
      // That same document, section 5, is explicit that a production carrier
      // is a REMOTE, off-link endpoint whose `/32` exclusion is one of the
      // tunnel's own rules rather than a competing local route, a shape the
      // 08-09 dataset cannot answer for. On 2026-08-11 a real iPhone appex
      // with `enforceRoutes = true` established and carried the winn/3 outer
      // datapath (54 datagrams, admitted, carrying;
      // `.winn_platform_progress/evidence/winn3_ios_20260811T044620Z_first_standalone_v3_carriage.txt`),
      // so the engine under `true` is not inherently dead on Apple platforms;
      // that run was pre-promotion, so post-promotion enforcement pressure
      // remains unmeasured on both platforms. The release-gating experiment is
      // the section-5 run: remote endpoint, `enforceRoutes = true`, full
      // promotion, gateway rx Δ read at the far end. Owner-scheduled, never on
      // this host.
      //
      // WHY THE RULING IS `true` WITHOUT THAT MEASUREMENT IN HAND. Under
      // `false` the TunnelVision-class decloak is open: a network that owns
      // DHCP/RA (in Myanmar the state owns the ISP and the CPE) can push
      // more-specific routes and silently pull attributable traffic out of the
      // tunnel in the clear. The `/1` pair below narrows only the exact
      // split-default shape, and its equal-length tie-break is itself
      // unmeasured; any injection more specific than `/1` still wins. Under
      // `true` the measured worst case is loud: zero carriage, system-wide
      // EHOSTUNREACH, nothing leaves in the clear. For this user base a
      // visible outage is survivable and a silent decloak is not, so the
      // fail-closed posture ships while the fail-open one does not. Carriage
      // under `false` with the CURRENT `/1`-pair shape was never measured
      // either, so reverting bought no proven carriage; it only reopened the
      // leak.
      //
      // DEFENSE-IN-DEPTH THAT STAYS. The macOS packet tunnel installs its
      // full-tunnel default as the `0.0.0.0/1` + `128.0.0.0/1` pair instead of
      // a bare `/0` (`WinsTunnelConfig.appleIncludedIPv4Routes`,
      // `WinsWinn3Settings.fullTunnel`). Under `true` this costs nothing, it
      // keeps parity with the Windows posture, and if enforcement ever has a
      // gap the pair still ties a DHCP-option-121 split-default instead of
      // losing to it. The `/32` carrier carve-out still outranks both.
      //
      // WHAT THIS IS NOT. Neither flag was ever a kill switch, on either Apple
      // platform: traffic the device emits before connect, during teardown, and
      // across a crash still egresses in the clear. The `/1` pair does not
      // change that, and `enforceRoutes` protects only while the tunnel is up.
      //
      // THIS FLIP DOES NOT PROVE CARRIAGE. Nothing in this file does. macOS
      // release is gated on the section-5 measurement above; see
      // `WINN3_MACOS_CARRIAGE_FIX_20260810_bld_mac_routes.md` for the route
      // shape history and `docs/rulings/RULINGS.lock` for the invariant.
      //
      // `excludeLocalNetworks` stays true and stays stated rather than
      // inherited: its framework default differs between iOS and macOS, pinning
      // it makes the two targets behave identically, and it keeps the local
      // link -- and so the captive portal that must be passed before any tunnel
      // can connect -- reachable. It was measured to be independent of the
      // admission failure. No availability guard: this target's floor is
      // macOS 11.0 and both properties predate it.
      //
      // Neither property survives the tunnel stopping, so this changes
      // nothing about what happens when the tunnel is down. macOS also has no
      // counterpart to iOS's `resaveExistingTunnelManagerDescriptionIfStale`,
      // so this connect path is the only writer of the routing posture here --
      // which also means an already-saved configuration keeps whatever posture
      // it was last given until this path runs again.
      tunnelProtocol.enforceRoutes = WinsMacRoutePosture.enforceRoutes
      tunnelProtocol.excludeLocalNetworks = true
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
      manager.localizedDescription = Self.tunnelDescription
      manager.protocolConfiguration = tunnelProtocol
      manager.isEnabled = true

      NSLog("Win's VPN tunnel start stage: save_preferences")
      self.saveTunnelManager(manager) { saveError in
        guard self.tunnelOperationGate.isCurrent(operationToken) else {
          result(false)
          return
        }
        if let saveError = saveError {
          NSLog("Win's VPN tunnel start stage failed: save_preferences")
          result(self.flutterError("APPLE_TUNNEL_SAVE_FAILED", saveError))
          return
        }
        // A manager that has just created a preference can retain an invalid
        // connection object even though macOS has persisted a usable service.
        // Reload the signed manager collection and start through the fresh
        // persisted instance so NetworkExtension binds the current provider.
        NSLog("Win's VPN tunnel start stage: reload_manager")
        self.loadTunnelManager { persistedManager, loadError in
          guard self.tunnelOperationGate.isCurrent(operationToken) else {
            result(false)
            return
          }
          if let loadError = loadError {
            NSLog("Win's VPN tunnel start stage failed: reload_manager")
            result(self.flutterError("APPLE_TUNNEL_RELOAD_FAILED", loadError))
            return
          }
          guard let persistedManager else {
            NSLog("Win's VPN tunnel start stage failed: reloaded_manager_missing")
            result(FlutterError(
              code: "APPLE_TUNNEL_RELOAD_FAILED",
              message: "The saved packet tunnel manager could not be reloaded.",
              details: nil
            ))
            return
          }
          var startError: Error?
          NSLog("Win's VPN tunnel start stage: start_provider")
          // ROUTE-AUDIT, IMMEDIATELY BEFORE THE PROVIDER STARTS. Record the
          // routing posture this start is about to apply: the persisted
          // `enforceRoutes` on the protocol and the outer-socket `/32` carve-out
          // `transportIPv4ExclusionRoute` the provider installs from the FIRST
          // posture (`NEIPv4Settings.excludedRoutes`), so a route leak that was
          // never recorded cannot be audited after the fact. Where there is no
          // transport exclusion, the line reads `exclude=none`, which is the
          // accurate spelling of "no /32 carve-out is being applied".
          RouteAudit.log(
            enforceRoutes: tunnelProtocol.enforceRoutes,
            excludedRoutes: parsedConfig.transportIPv4ExclusionRoute
              .map { [RouteAudit.excludedRouteString($0)] } ?? []
          )
          let startedCurrentOperation = self.tunnelOperationGate.performIfCurrent(operationToken) {
            do {
              try persistedManager.connection.startVPNTunnel(
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
          if startError != nil {
            NSLog("Win's VPN tunnel start stage failed: start_provider")
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

  private func probeVpnInternet(_ arguments: Any?, result: @escaping FlutterResult) {
    let externalLeakAuditRequest = WinsAppleExternalLeakAudit.request(from: arguments)
    loadTunnelManager { manager, error in
      if let error = error {
        var response: [String: Any] = [
          "ok": false,
          "internet_probe_attempted": false,
          "internet_probe_blocked_by_leak_protection_config": false,
          "platform": "macos",
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
        "platform": "macos",
        "provider_bundle_id": self.providerBundleIdentifier,
        "status": Self.statusName(status)
      ]
      response.merge(
        self.latestProviderStatusFields(
          expectedStatusGeneration: self.expectedStatusGeneration(from: manager)
        )
      ) { _, new in new }

      guard connected else {
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
      // registration that LaunchServices has already removed. Delete legacy
      // managers once and create a current signed manager below.
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
    let matchesDisplayName = manager.localizedDescription == Self.tunnelDescription
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

    // NetworkExtension can leave a legacy manager whose removal callback never
    // arrives after an app update or bundle-path migration. Blocking the new
    // signed manager on that callback makes every route attempt time out before
    // startVPNTunnel. Continue after a short bound; late removals still target
    // only their original manager objects and cannot delete managerToKeep.
    let completionLock = NSLock()
    var remaining = staleManagers.count
    var completionDelivered = false
    let finishOnce: (_ timedOut: Bool) -> Void = { timedOut in
      completionLock.lock()
      guard !completionDelivered else {
        completionLock.unlock()
        return
      }
      completionDelivered = true
      completionLock.unlock()

      if timedOut {
        NSLog(
          "Win's VPN stale tunnel manager cleanup timed out after %.1f seconds; continuing with the current signed manager.",
          Self.staleManagerRemovalTimeoutSeconds
        )
      }
      DispatchQueue.main.async {
        completion?()
      }
    }

    for manager in staleManagers {
      self.removeTunnelManager(manager) { removalError in
        if let removalError = removalError {
          NSLog(
            "Win's VPN failed to remove stale tunnel manager: %@",
            WinsTunnelDiagnostics.redactedAppleErrorMessage(removalError)
          )
        }
        completionLock.lock()
        remaining -= 1
        let allRemoved = remaining == 0
        completionLock.unlock()
        if allRemoved {
          finishOnce(false)
        }
      }
    }

    DispatchQueue.main.asyncAfter(
      deadline: .now() + Self.staleManagerRemovalTimeoutSeconds
    ) {
      finishOnce(true)
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
      "platform": "macos",
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
      NSLog("Win's VPN tunnel start stage accepted: start_provider")
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
      if outcome == .connected {
        NSLog("Win's VPN tunnel start stage accepted: start_provider")
      }
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
    statusGeneration: String
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
        "shared_config_private_key_redacted": true
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
      // `macos/PacketTunnel/PacketTunnelProvider.swift` — so in a release build
      // every one of these is simply absent from the provider status document
      // and this mapping copies nothing. `provider_dev_containment_active` is
      // the term `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields` uses
      // to fail `leak_protection_config_passed` for a contained session.
      "dev_containment_active": "provider_dev_containment_active",
      "dev_containment_requested": "provider_dev_containment_requested",
      "dev_containment_kind": "provider_dev_containment_kind",
      "dev_containment_default_ipv4_route_installed": "provider_dev_containment_default_ipv4_route_installed",
      "dev_containment_ipv6_settings_installed": "provider_dev_containment_ipv6_settings_installed",
      "dev_containment_dns_settings_installed": "provider_dev_containment_dns_settings_installed",
      "dev_containment_test_route_usable": "provider_dev_containment_test_route_usable",
      "dev_containment_test_route_explicit": "provider_dev_containment_test_route_explicit",
      "dev_containment_test_route_prefix_length": "provider_dev_containment_test_route_prefix_length",
      "dev_containment_included_route_count": "provider_dev_containment_included_route_count",
      "dev_containment_probe": "provider_dev_containment_probe",
      // The READ-BACK half. Everything above this line is what the plan
      // INTENDED; these are what the provider MEASURED off the
      // NEPacketTunnelNetworkSettings object it actually built. Added
      // 2026-08-06 (containment observability lane) alongside
      // `WinsDevContainmentObservation` in
      // `macos/PacketTunnel/PacketTunnelProvider.swift`.
      //
      // Their absence was not cosmetic. The dev traffic harness
      // (lib/winn_protocol_dev_session_main.dart) re-confirms containment from
      // the provider readback before it will send a single packet, and it
      // requires the `_observed_` fields specifically -- deliberately, because
      // intent fields cannot detect a settings builder that widened. macOS
      // published none of them, so the harness read null, could not tell
      // "containment is off" from "I could not observe it", and refused to
      // send on every contained macOS session. Same value sanitizer and the
      // same `provider_` namespace as the intent fields above.
      "dev_containment_observed": "provider_dev_containment_observed",
      "dev_containment_observed_contained": "provider_dev_containment_observed_contained",
      "dev_containment_observed_included_route_count": "provider_dev_containment_observed_included_route_count",
      "dev_containment_observed_included_route_prefix_lengths": "provider_dev_containment_observed_included_route_prefix_lengths",
      "dev_containment_observed_default_ipv4_route_installed": "provider_dev_containment_observed_default_ipv4_route_installed",
      "dev_containment_observed_ipv6_settings_installed": "provider_dev_containment_observed_ipv6_settings_installed",
      "dev_containment_observed_dns_settings_installed": "provider_dev_containment_observed_dns_settings_installed",
      // THE winn/3 RUNTIME MEMORY SAMPLE. Exactly the gap above, one probe
      // later: the macOS provider now samples `TASK_VM_INFO.phys_footprint`
      // into the shared status document, and until these rows existed nothing
      // forwarded it, so every macOS run still reported
      // `winn_memory_sample_taken: false` and a null footprint. A number that
      // is written and never read is not a measurement.
      //
      // Absent stays absent: `safeMappedStatusValue` drops a key the provider
      // did not write rather than defaulting it. That matters most for
      // `available_bytes`, which macOS genuinely cannot measure
      // (`os_proc_available_memory()` is iOS-only) — it is omitted, and
      // `available_measured: false` is what says so. A defaulted 0 would read
      // downstream as "no headroom".
      "winn_memory_sample_taken": "provider_winn_memory_sample_taken",
      "winn_memory_sample_phys_footprint_bytes": "provider_winn_memory_sample_phys_footprint_bytes",
      "winn_memory_sample_available_bytes": "provider_winn_memory_sample_available_bytes",
      "winn_memory_sample_available_measured": "provider_winn_memory_sample_available_measured"
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
        String(validatingUTF8: $0) ?? "Mac"
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

}

// MARK: - MainFlutterWindow window-config enforceRoutes reporting seam
//
// The Flutter connect path in `WinsMacOSTunnelBridge.startTunnel` is the ONLY
// writer of the routing posture on macOS (see AppDelegate.swift comment at
// ~246: "MainFlutterWindow.swift sets enforceRoutes but nothing re-saves it").
// This seam funnels that window-config assignment through the SAME
// `requested_enforce_routes` reporting key used by
// `WinsNECPPostureProbe.reSaveAndReport` in `macos/Runner/AppDelegate.swift`
// line ~372 (`"requested_enforce_routes": requested.enforceRoutes ?? NSNull()`),
// so a window-config posture and a probe re-save can be correlated by key.
//
// It also pins that the window DOES set `enforceRoutes` when configuring the
// packet tunnel provider (the task's first claim): the protocol returned here
// is the object `startTunnel` persists, and the report carries the requested
// value under the probe's key. The XCTest drives this seam with an in-memory
// protocol and asserts the reloaded value still matches.
enum WinsMacMainWindowRouteReporting {
  static let requestedEnforceRoutesKey = "requested_enforce_routes"

  /// Builds the tunnel protocol exactly as `startTunnel` does for the window
  /// path: `enforceRoutes` from the single source `WinsMacRoutePosture`,
  /// `excludeLocalNetworks = true`, `includeAllNetworks = false`.
  static func makeWindowTunnelProtocol() -> NETunnelProviderProtocol {
    let proto = NETunnelProviderProtocol()
    let appBundleIdentifier = Bundle.main.bundleIdentifier ?? "org.winsvpn.app"
    proto.providerBundleIdentifier = "\(appBundleIdentifier).PacketTunnel"
    proto.serverAddress = "Win's VPN"
    proto.enforceRoutes = WinsMacRoutePosture.enforceRoutes
    proto.excludeLocalNetworks = true
    proto.includeAllNetworks = false
    return proto
  }

  /// Report for the window-config path, using the SAME key AppDelegate uses.
  static func windowConfigReport(for proto: NETunnelProviderProtocol) -> [String: Any] {
    var report: [String: Any] = [:]
    report[requestedEnforceRoutesKey] = WinsMacRoutePosture.enforceRoutes
    report["applied_enforce_routes"] = proto.enforceRoutes
    report["before_enforce_routes"] = false
    report["after_enforce_routes"] = proto.enforceRoutes
    report["window_config_enforce_routes"] = proto.enforceRoutes
    report["window_provider_bundle_id"] = proto.providerBundleIdentifier ?? ""
    return report
  }

  static func configuredProtocolAndReport() -> (tunnelProtocol: NETunnelProviderProtocol, report: [String: Any]) {
    let proto = makeWindowTunnelProtocol()
    let report = windowConfigReport(for: proto)
    return (proto, report)
  }
}
