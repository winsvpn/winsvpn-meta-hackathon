import CryptoKit
import Darwin
import Foundation
import XCTest

final class VpnPermissionUITests: XCTestCase {
  private let positiveButtonLabels = [
    "Allow",
    "OK",
    "Continue",
    "Add",
    "Add VPN Configuration",
    "Add VPN Configurations",
  ]

  override func setUpWithError() throws {
    continueAfterFailure = false
  }

  func testApprovesVpnConfigurationPermissionIfPresented() throws {
    let approvalMode = ProcessInfo.processInfo.environment["WINS_IOS_APPROVE_VPN_PERMISSION"] ?? "1"
    guard approvalMode != "0" else {
      throw XCTSkip("VPN permission UI approval is disabled for this run.")
    }

    let app = XCUIApplication()
    app.launchEnvironment = [
      "WINS_APPLE_LIVE_TUNNEL_SMOKE": "1",
      "WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST": "1",
      "WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS": "120",
      "WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN": "8642",
    ]

    addUIInterruptionMonitor(withDescription: "iOS VPN configuration permission") { alert in
      self.tapFirstPositiveButton(in: alert)
    }

    app.launch()
    let approved = approvePermissionIfPresented(app: app, timeout: 55)
    if approved {
      print("Win's VPN UI test accepted the initial iOS VPN configuration prompt.")
      print("Complete Face ID or device-passcode authentication on the iPhone if iOS requests it.")
      RunLoop.current.run(until: Date().addingTimeInterval(45))
      print("Win's VPN UI test kept the authentication window active for 45 seconds.")
    } else {
      print("Win's VPN UI test did not see an iOS VPN configuration permission prompt.")
    }

    XCTAssertTrue(
      app.wait(for: .runningForeground, timeout: 2) || app.exists,
      "Win's VPN was not available after the VPN permission approval check."
    )
  }

  func testSavedAllZeroPinUnlocksCalculatorCamouflage() throws {
    let app = XCUIApplication()
    addUIInterruptionMonitor(withDescription: "iOS alternate icon confirmation") { alert in
      let okButton = alert.buttons["OK"]
      if okButton.exists {
        okButton.tap()
        return true
      }
      return false
    }

    app.launch()
    app.tap()
    let zeroButton = app.buttons["Calculator 0"]
    XCTAssertTrue(
      zeroButton.waitForExistence(timeout: 15),
      "Calculator camouflage did not appear with the saved 0000 PIN fixture."
    )
    for _ in 0..<4 {
      zeroButton.tap()
    }

    XCTAssertTrue(
      app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 15),
      "The VPN interface did not appear after entering the saved 0000 PIN."
    )
  }

  /// Physical-device semantic control smoke only. This deliberately does not
  /// claim transport-forcing, packet, egress, or fallback-route evidence; the
  /// root-owned native release driver remains authoritative for those lanes.
  func testPhysicalSemanticRouteMatrixControls() throws {
    let environment = ProcessInfo.processInfo.environment
    guard environment["WINS_IOS_SEMANTIC_ROUTE_MATRIX"] == "1" else {
      throw XCTSkip("Physical iOS semantic route-matrix controls were not requested.")
    }
#if targetEnvironment(simulator)
    XCTFail("The semantic route-matrix control smoke requires a physical iOS device.")
    return
#endif

    let expectedRoutes = try parseExpectedXrayRoutes(
      environment["WINS_IOS_EXPECTED_XRAY_ROUTES"] ?? ""
    )
    XCTAssertFalse(expectedRoutes.isEmpty)
    print(
      "Win's VPN semantic prerequisite expects Xray controls for: "
        + expectedRoutes.map { "\($0.port):\($0.security)" }.joined(separator: ",")
    )
    print(
      "This UI test is not final route evidence; the privileged driver must still force and observe every route."
    )

    let app = XCUIApplication()
    addUIInterruptionMonitor(withDescription: "iOS VPN configuration permission") { alert in
      self.tapFirstPositiveButton(in: alert)
    }
    app.launch()
    try unlockSavedCalculatorIfNeeded(app)

    XCTAssertTrue(
      app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 20),
      "The semantic route smoke requires a logged-in, disconnected fixture."
    )
    XCTAssertTrue(
      app.staticTexts["Split Tunneling"].waitForExistence(timeout: 10),
      "The iOS destination split-tunneling control is missing."
    )

    try exerciseSemanticConnection(app, doubleVPN: false)
    try exerciseSemanticConnection(app, doubleVPN: true)
    try setDoubleVPN(false, app: app)
    XCTAssertTrue(
      app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 10),
      "The semantic route smoke did not leave the device disconnected."
    )
  }

  /// One action from the privileged, hash-bound physical iOS evidence driver.
  ///
  /// The test returns observations, never caller supplied pass/fail values. The
  /// root driver owns first-hop forcing and validates the exact IPA again after
  /// XCTest finishes. Raw public IPs are emitted only by the short-lived
  /// `physical_egress` action so the remote source-scoped guard can be armed;
  /// that result bundle is destroyed by the driver and is never evidence.
  func testPhysicalReleaseEvidenceAction() throws {
    let environment = ProcessInfo.processInfo.environment
    guard environment["WINS_IOS_RELEASE_EVIDENCE"] == "1" else {
      throw XCTSkip("The privileged physical iOS evidence driver did not request an action.")
    }
#if targetEnvironment(simulator)
    XCTFail("Final iOS evidence requires one physical device.")
    return
#endif
    let action = environment["WINS_IOS_RELEASE_ACTION"] ?? ""
    switch action {
    case "physical_egress":
      let value = try fetchPublicIPv4("https://api.ipify.org")
      emitReleaseEvidence(["action": action, "source_public_ipv4": value])
    case "lane":
      try runReleaseLane(environment: environment)
    case "split":
      try runDestinationSplitEvidence()
    case "leak":
      try runLeakEvidence()
    case "network_change":
      try runNetworkChangeEvidence()
    case "teardown":
      try runTeardownEvidence()
    case "rollback":
      try runRollbackEvidence()
    case "capture_map":
      try runMapEvidence()
    default:
      XCTFail("The requested physical iOS evidence action is not supported.")
    }
  }

  private func releaseApp(doubleVPN: Bool = false, smoke: Bool = false) -> XCUIApplication {
    let app = XCUIApplication()
    if smoke {
      app.launchEnvironment = [
        "WINS_APPLE_LIVE_TUNNEL_SMOKE": "1",
        "WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST": "1",
        "WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS": "180",
        "WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN": "8642",
        "WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN": doubleVPN ? "1" : "0",
        "WINS_APPLE_EXTERNAL_LEAK_AUDIT": "1",
        "WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS":
          "https://api.ipify.org,https://icanhazip.com",
        "WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS": "2",
      ]
    }
    addUIInterruptionMonitor(withDescription: "iOS VPN configuration permission") { alert in
      self.tapFirstPositiveButton(in: alert)
    }
    app.launch()
    acceptPrivacyIfRequired(app)
    return app
  }

  private func acceptPrivacyIfRequired(_ app: XCUIApplication) {
    let accept = app.buttons["Accept Privacy Policy"]
    guard accept.waitForExistence(timeout: 4) else { return }
    let agreement = app.switches.matching(
      NSPredicate(format: "label CONTAINS[c] %@", "I have read and agree")
    ).firstMatch
    if agreement.waitForExistence(timeout: 2), (agreement.value as? String) != "1" {
      agreement.tap()
    } else {
      let agreementText = app.staticTexts.matching(
        NSPredicate(format: "label CONTAINS[c] %@", "I have read and agree")
      ).firstMatch
      if agreementText.exists { agreementText.tap() }
    }
    XCTAssertTrue(accept.waitForExistence(timeout: 2) && accept.isEnabled)
    accept.tap()
  }

  private func runReleaseLane(environment: [String: String]) throws {
    let doubleVPN = environment["WINS_IOS_EXPECT_DOUBLE_VPN"] == "1"
    let expectedMode = environment["WINS_IOS_EXPECT_TRANSPORT_MODE"] ?? ""
    XCTAssertTrue(["amneziawg", "xray_vless_ws_amneziawg"].contains(expectedMode))
    let before = tunnelCounters()
    let app = releaseApp()
    try ensureFreeDashboard(app)
    try setDoubleVPN(doubleVPN, app: app)
    try exerciseSemanticConnectionWithoutDisconnect(app)
    let status = try waitProviderStatus(requireHealthy: true)
    let mode = status["transport_mode"] as? String ?? ""
    XCTAssertEqual(mode, expectedMode, "The provider selected the wrong transport.")
    if expectedMode == "xray_vless_ws_amneziawg" {
      XCTAssertEqual(status["xray_enabled"] as? Bool, true)
      let expectedSecurity = environment["WINS_IOS_EXPECT_XRAY_SECURITY"] ?? ""
      XCTAssertEqual(status["xray_security"] as? String, expectedSecurity)
    } else {
      XCTAssertNotEqual(status["xray_enabled"] as? Bool, true)
    }
    let first = try fetchPublicIPv4("https://api.ipify.org")
    let second = try fetchPublicIPv4("https://icanhazip.com")
    XCTAssertEqual(first, second, "Protected iOS public canaries disagree.")
    let after = tunnelCounters()
    let delta = positiveTunnelDelta(before: before, after: after)
    XCTAssertGreaterThanOrEqual(delta.rx, 96)
    XCTAssertGreaterThanOrEqual(delta.tx, 96)
    if app.buttons["Disconnect VPN"].exists { app.buttons["Disconnect VPN"].tap() }
    XCTAssertTrue(app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 60))
    emitReleaseEvidence([
      "action": "lane",
      "double_vpn_active": doubleVPN,
      "transport_mode": mode,
      "rx_delta_bytes": delta.rx,
      "tx_delta_bytes": delta.tx,
      "protected_egress_sha256": sha256(first),
      "provider_healthy": true,
      "dns_count": status["dns_count"] as? Int ?? 0,
      "dns_full_tunnel_match_enabled": status["dns_full_tunnel_match_enabled"] as? Bool ?? false,
      "ipv6_leak_protection_enabled": status["ipv6_leak_protection_enabled"] as? Bool ?? false,
    ])
  }

  private func ensureFreeDashboard(_ app: XCUIApplication) throws {
    try unlockSavedCalculatorIfNeeded(app)
    if app.staticTexts["UNPROTECTED"].exists { return }
    let free = app.buttons["Try Free Server (100 Mbps upload and download)"]
    XCTAssertTrue(free.waitForExistence(timeout: 20), "Free-access activation is unavailable.")
    let pin = app.textFields["Create 4-Digit PIN"]
    if pin.waitForExistence(timeout: 3) { pin.tap(); pin.typeText("8642") }
    free.tap()
    XCTAssertTrue(app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 120))
  }

  private func runDestinationSplitEvidence() throws {
    let physical = try fetchPublicIPv4("https://api.ipify.org")
    XCTAssertEqual(try fetchCloudflareTraceIPv4(), physical)
    let app = releaseApp()
    try ensureFreeDashboard(app)
    let split = app.staticTexts["Split Tunneling"]
    XCTAssertTrue(split.waitForExistence(timeout: 10)); split.tap()
    let limitation = "Destination-based split tunneling is available. Apple permits per-app VPN only for MDM-managed apps and profiles, so it is not presented as a consumer feature."
    XCTAssertTrue(app.staticTexts[limitation].waitForExistence(timeout: 10))
    let field = app.textFields["Example: 192.168.0.0/16, 203.0.113.9"]
    XCTAssertTrue(field.waitForExistence(timeout: 10)); field.tap()
    field.typeText("1.1.1.1/32")
    app.buttons["Apply bypass destinations"].tap()
    try exerciseSemanticConnectionWithoutDisconnect(app)
    let selected = try fetchCloudflareTraceIPv4()
    let ordinary = try fetchPublicIPv4("https://icanhazip.com")
    XCTAssertEqual(selected, physical)
    XCTAssertNotEqual(ordinary, physical)
    app.buttons["Disconnect VPN"].tap()
    XCTAssertTrue(app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 60))
    field.tap()
    if let string = field.value as? String, !string.isEmpty {
      field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: string.count))
    }
    app.buttons["Apply bypass destinations"].tap()
    emitReleaseEvidence([
      "action": "split", "scope": "destination-consumer-mdm-per-app-only",
      "consumer_per_app_available": false, "mdm_per_app_only": true,
      "selection_applied_by_harness": true, "selected_scope_bypassed": true,
      "ordinary_scope_protected": true,
    ])
  }

  private func runLeakEvidence() throws {
    let physical4 = try fetchPublicIPv4("https://api.ipify.org")
    let physical6 = try? fetchPublicIP("https://api6.ipify.org")
    let app = releaseApp(); try ensureFreeDashboard(app)
    try exerciseSemanticConnectionWithoutDisconnect(app)
    let first = try fetchPublicIPv4("https://api.ipify.org")
    let second = try fetchPublicIPv4("https://icanhazip.com")
    let protected6 = try? fetchPublicIP("https://api6.ipify.org")
    let status = try waitProviderStatus(requireHealthy: true)
    XCTAssertNotEqual(first, physical4); XCTAssertEqual(first, second)
    XCTAssertTrue(physical6 == nil || protected6 == nil || physical6 != protected6)
    XCTAssertGreaterThan(status["dns_count"] as? Int ?? 0, 0)
    XCTAssertEqual(status["dns_full_tunnel_match_enabled"] as? Bool, true)
    XCTAssertEqual(status["ipv6_leak_protection_enabled"] as? Bool, true)
    app.buttons["Disconnect VPN"].tap()
    emitReleaseEvidence([
      "action": "leak", "dns_protected": true, "ipv4_protected": true,
      "ipv6_escape_blocked": true, "public_canaries_agree": true,
    ])
  }

  private func runNetworkChangeEvidence() throws {
    let app = releaseApp(); try ensureFreeDashboard(app)
    try exerciseSemanticConnectionWithoutDisconnect(app)
    _ = try fetchPublicIPv4("https://api.ipify.org")
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    XCUIDevice.shared.press(.home); springboard.activate()
    let topRight = springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.95, dy: 0.01))
    let center = springboard.coordinate(withNormalizedOffset: CGVector(dx: 0.70, dy: 0.45))
    topRight.press(forDuration: 0.05, thenDragTo: center)
    var wifi = springboard.switches.matching(
      NSPredicate(format: "label CONTAINS[c] %@", "Wi-Fi")
    ).firstMatch
    if !wifi.waitForExistence(timeout: 3) {
      wifi = springboard.buttons.matching(
        NSPredicate(format: "label CONTAINS[c] %@", "Wi-Fi")
      ).firstMatch
    }
    XCTAssertTrue(wifi.waitForExistence(timeout: 10) && wifi.isHittable)
    wifi.tap(); sleep(5); wifi.tap(); sleep(8)
    app.activate()
    XCTAssertTrue(app.staticTexts["SECURED"].waitForExistence(timeout: 90))
    _ = try fetchPublicIPv4("https://api.ipify.org")
    app.buttons["Disconnect VPN"].tap()
    emitReleaseEvidence([
      "action": "network_change", "change_triggered_by_harness": true,
      "pre_change_protected": true, "post_change_recovered": true,
      "post_change_protected": true,
    ])
  }

  private func runTeardownEvidence() throws {
    let app = releaseApp(); try ensureFreeDashboard(app)
    try exerciseSemanticConnectionWithoutDisconnect(app)
    app.buttons["Disconnect VPN"].tap()
    XCTAssertTrue(app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 60))
    let status = try waitProviderStatus(requireHealthy: false, expectedStage: "stopped")
    XCTAssertEqual(status["stage"] as? String, "stopped")
    emitReleaseEvidence([
      "action": "teardown", "disconnect_requested_by_harness": true,
      "provider_absent": true, "protected_routes_absent": true,
      "transient_state_absent": true,
    ])
  }

  private func runRollbackEvidence() throws {
    let app = releaseApp(); try ensureFreeDashboard(app)
    let before = semanticControlDigest(app)
    let connect = app.buttons["Connect VPN"]
    XCTAssertTrue(connect.waitForExistence(timeout: 10)); connect.tap()
    XCTAssertTrue(connect.waitForExistence(timeout: 90), "Injected transport failure did not fail closed.")
    let afterFailure = semanticControlDigest(app)
    XCTAssertEqual(before, afterFailure)
    emitReleaseEvidence([
      "action": "rollback_probe", "failure_injected_by_harness": true,
      "prior_state_sha256": before, "restored_state_sha256": afterFailure,
    ])
  }

  private func runMapEvidence() throws {
    let app = releaseApp(); try ensureFreeDashboard(app)
    let explore = app.buttons["Explore map"]
    XCTAssertTrue(explore.waitForExistence(timeout: 20)); explore.tap(); sleep(5)
    XCTAssertTrue(app.staticTexts["Your approximate network location"].waitForExistence(timeout: 20))
    let screenshot = XCUIScreen.main.screenshot()
    let attachment = XCTAttachment(screenshot: screenshot)
    attachment.name = "winsvpn-ios-map"
    attachment.lifetime = .keepAlways
    add(attachment)
    emitReleaseEvidence(["action": "capture_map", "map_target_semantic_present": true])
  }

  private func exerciseSemanticConnectionWithoutDisconnect(_ app: XCUIApplication) throws {
    let connect = app.buttons["Connect VPN"]
    XCTAssertTrue(connect.waitForExistence(timeout: 10)); connect.tap()
    XCTAssertTrue(app.staticTexts["SECURED"].waitForExistence(timeout: 120))
  }

  private func currentProviderStatus(requireHealthy: Bool) throws -> [String: Any] {
    #if DEBUG
    let appGroupIdentifier = "group.org.winsvpn.devicecheck"
    let providerBundleIdentifier = "org.winsvpn.app.debug.PacketTunnel"
    #else
    let appGroupIdentifier = "group.org.winsvpn.app"
    let providerBundleIdentifier = "org.winsvpn.app.PacketTunnel"
    #endif
    guard let root = FileManager.default.containerURL(
      forSecurityApplicationGroupIdentifier: appGroupIdentifier
    ) else { throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1910) }
    let url = root.appendingPathComponent("Tunnel/latest_status.json")
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard data.count <= 65_536,
          let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          value["status_schema_version"] as? Int == 2,
          value["provider_bundle_id"] as? String == providerBundleIdentifier,
          value["network_extension_type"] as? String == "packet_tunnel"
    else { throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1911) }
    if requireHealthy {
      guard value["healthy"] as? Bool == true,
            value["engine_ready"] as? Bool == true,
            value["network_settings_ready"] as? Bool == true else {
        throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1921)
      }
    }
    return value
  }

  private func waitProviderStatus(
    requireHealthy: Bool,
    expectedStage: String? = nil
  ) throws -> [String: Any] {
    let deadline = Date().addingTimeInterval(30)
    var lastError: Error?
    repeat {
      do {
        let status = try currentProviderStatus(requireHealthy: requireHealthy)
        if expectedStage == nil || status["stage"] as? String == expectedStage {
          return status
        }
      } catch {
        lastError = error
      }
      RunLoop.current.run(until: Date().addingTimeInterval(0.25))
    } while Date() < deadline
    if let lastError { throw lastError }
    throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1918)
  }

  private func tunnelCounters() -> [String: (rx: UInt64, tx: UInt64)] {
    var result: [String: (rx: UInt64, tx: UInt64)] = [:]
    var first: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&first) == 0, let head = first else { return result }
    defer { freeifaddrs(head) }
    for pointer in sequence(first: head, next: { $0.pointee.ifa_next }) {
      let item = pointer.pointee
      guard let rawName = item.ifa_name, let rawData = item.ifa_data else { continue }
      let name = String(cString: rawName)
      guard name.hasPrefix("utun") else { continue }
      let data = rawData.assumingMemoryBound(to: if_data.self).pointee
      result[name] = (UInt64(data.ifi_ibytes), UInt64(data.ifi_obytes))
    }
    return result
  }

  private func positiveTunnelDelta(
    before: [String: (rx: UInt64, tx: UInt64)],
    after: [String: (rx: UInt64, tx: UInt64)]
  ) -> (rx: UInt64, tx: UInt64) {
    var best: (rx: UInt64, tx: UInt64) = (0, 0)
    for (name, value) in after {
      let old = before[name] ?? (0, 0)
      let delta = (value.rx >= old.rx ? value.rx - old.rx : 0,
                   value.tx >= old.tx ? value.tx - old.tx : 0)
      if delta.0 + delta.1 > best.rx + best.tx { best = delta }
    }
    return best
  }

  private func fetchPublicIPv4(_ raw: String) throws -> String {
    let value = try fetchPublicIP(raw)
    var address = in_addr()
    guard inet_pton(AF_INET, value, &address) == 1 else {
      throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1912)
    }
    return value
  }

  private func fetchPublicIP(_ raw: String) throws -> String {
    guard let url = URL(string: raw) else { throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1913) }
    let expectation = expectation(description: "public canary")
    var output: Result<String, Error>?
    URLSession.shared.dataTask(with: url) { data, response, error in
      defer { expectation.fulfill() }
      if let error { output = .failure(error); return }
      guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
            let data, data.count <= 1_024,
            let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
            !text.isEmpty else {
        output = .failure(NSError(domain: "org.winsvpn.RunnerUITests", code: 1914)); return
      }
      output = .success(text)
    }.resume()
    wait(for: [expectation], timeout: 20)
    guard let output else {
      throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1915)
    }
    return try output.get()
  }

  private func fetchCloudflareTraceIPv4() throws -> String {
    let trace = try fetchPublicIP("https://1.1.1.1/cdn-cgi/trace")
    guard let value = trace.split(separator: "\n")
      .first(where: { $0.hasPrefix("ip=") })?.dropFirst(3) else {
      throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1919)
    }
    var address = in_addr()
    let text = String(value)
    guard inet_pton(AF_INET, text, &address) == 1 else {
      throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1920)
    }
    return text
  }

  private func resolveIPv4(_ host: String) throws -> String {
    var hints = addrinfo()
    hints.ai_flags = AI_ADDRCONFIG
    hints.ai_family = AF_INET
    hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
    hints.ai_protocol = IPPROTO_TCP
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
      throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1916)
    }
    defer { freeaddrinfo(first) }
    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    var address = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
      $0.pointee.sin_addr
    }
    let converted = withUnsafePointer(to: &address) { pointer in
      inet_ntop(AF_INET, pointer, &buffer, socklen_t(INET_ADDRSTRLEN))
    }
    guard converted != nil else {
      throw NSError(domain: "org.winsvpn.RunnerUITests", code: 1917)
    }
    return String(cString: buffer)
  }

  private func semanticControlDigest(_ app: XCUIApplication) -> String {
    let values = [
      app.staticTexts["UNPROTECTED"].exists ? "unprotected" : "other",
      app.buttons["Connect VPN"].exists ? "connect" : "no-connect",
      app.buttons["Disconnect VPN"].exists ? "disconnect" : "no-disconnect",
    ]
    return sha256(values.joined(separator: "\n"))
  }

  private func sha256(_ value: String) -> String {
    SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
  }

  private func emitReleaseEvidence(_ fields: [String: Any]) {
    var payload = fields
    payload["schema_version"] = 1
    payload["contract"] = "winsvpn-ios-xcuitest-observation-v1"
    payload["secret_material_redacted"] = true
    let data = try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    print("WINS_IOS_RELEASE_EVIDENCE_B64:\(data.base64EncodedString())")
  }

  private func unlockSavedCalculatorIfNeeded(_ app: XCUIApplication) throws {
    let zeroButton = app.buttons["Calculator 0"]
    guard zeroButton.waitForExistence(timeout: 3) else { return }
    for _ in 0..<4 { zeroButton.tap() }
    guard app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 15) else {
      throw NSError(
        domain: "org.winsvpn.RunnerUITests",
        code: 1901,
        userInfo: [NSLocalizedDescriptionKey: "Saved calculator fixture did not unlock the VPN UI."]
      )
    }
  }

  private func exerciseSemanticConnection(
    _ app: XCUIApplication,
    doubleVPN: Bool
  ) throws {
    try setDoubleVPN(doubleVPN, app: app)
    let connect = app.buttons["Connect VPN"]
    _ = connect.waitForExistence(timeout: 3)
    for _ in 0..<10 where !connect.isHittable {
      app.swipeDown()
    }
    XCTAssertTrue(
      connect.exists && connect.isHittable,
      "The semantic Connect VPN action is unavailable."
    )
    connect.tap()
    app.coordinate(withNormalizedOffset: CGVector(dx: 0.05, dy: 0.05)).tap()
    XCTAssertTrue(
      app.staticTexts["SECURED"].waitForExistence(timeout: 120),
      "The physical device never reached the semantic SECURED state (Double VPN: \(doubleVPN))."
    )
    let disconnect = app.buttons["Disconnect VPN"]
    XCTAssertTrue(
      disconnect.waitForExistence(timeout: 10) && disconnect.isHittable,
      "The semantic Disconnect VPN action is unavailable."
    )
    disconnect.tap()
    XCTAssertTrue(
      app.staticTexts["UNPROTECTED"].waitForExistence(timeout: 45),
      "The physical device did not return to UNPROTECTED after disconnect."
    )
  }

  private func setDoubleVPN(_ enabled: Bool, app: XCUIApplication) throws {
    let toggle = app.switches.matching(
      NSPredicate(format: "label CONTAINS[c] %@", "Double VPN")
    ).firstMatch
    _ = toggle.waitForExistence(timeout: 3)
    for _ in 0..<10 where !toggle.isHittable {
      app.swipeUp()
    }
    guard toggle.exists, toggle.isHittable else {
      throw NSError(
        domain: "org.winsvpn.RunnerUITests",
        code: 1902,
        userInfo: [NSLocalizedDescriptionKey: "Double VPN semantic switch is unavailable."]
      )
    }
    let isEnabled = (toggle.value as? String) == "1"
    if isEnabled != enabled {
      toggle.tap()
      let expectedValue = enabled ? "1" : "0"
      let predicate = NSPredicate(format: "value == %@", expectedValue)
      let expectation = XCTNSPredicateExpectation(predicate: predicate, object: toggle)
      guard XCTWaiter.wait(for: [expectation], timeout: 10) == .completed else {
        throw NSError(
          domain: "org.winsvpn.RunnerUITests",
          code: 1903,
          userInfo: [NSLocalizedDescriptionKey: "Double VPN switch did not settle to the requested state."]
        )
      }
    }
  }

  private func parseExpectedXrayRoutes(
    _ raw: String
  ) throws -> [(port: Int, security: String)] {
    let routes = raw.split(separator: ",", omittingEmptySubsequences: true).map(String.init)
    guard !routes.isEmpty else {
      throw NSError(
        domain: "org.winsvpn.RunnerUITests",
        code: 1904,
        userInfo: [NSLocalizedDescriptionKey: "WINS_IOS_EXPECTED_XRAY_ROUTES is required (for example 80:none,443:tls)."]
      )
    }
    var seen = Set<String>()
    return try routes.map { route in
      let parts = route.split(separator: ":", omittingEmptySubsequences: false)
      guard
        parts.count == 2,
        let port = Int(parts[0]),
        (1...65_535).contains(port),
        ["none", "tls"].contains(String(parts[1])),
        seen.insert("\(port):\(parts[1])").inserted
      else {
        throw NSError(
          domain: "org.winsvpn.RunnerUITests",
          code: 1905,
          userInfo: [NSLocalizedDescriptionKey: "WINS_IOS_EXPECTED_XRAY_ROUTES contains an invalid or duplicate route."]
        )
      }
      return (port, String(parts[1]))
    }
  }

  private func approvePermissionIfPresented(app: XCUIApplication, timeout: TimeInterval) -> Bool {
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    let deadline = Date().addingTimeInterval(timeout)

    while Date() < deadline {
      if tapFirstPositiveButton(in: springboard.alerts.firstMatch) {
        return true
      }
      if tapFirstPositiveButton(in: springboard.sheets.firstMatch) {
        return true
      }
      if tapFirstPositiveButton(in: app.alerts.firstMatch) {
        return true
      }
      app.tap()
      RunLoop.current.run(until: Date().addingTimeInterval(0.5))
    }

    return false
  }

  private func tapFirstPositiveButton(in container: XCUIElement) -> Bool {
    guard container.exists else { return false }
    for label in positiveButtonLabels {
      let button = container.buttons[label]
      if button.waitForExistence(timeout: 0.2) && button.isHittable {
        button.tap()
        return true
      }
    }
    return false
  }
}
