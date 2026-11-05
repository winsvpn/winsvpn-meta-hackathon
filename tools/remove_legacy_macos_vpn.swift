import AppKit
import Foundation
import NetworkExtension

private let legacyProviderBundleIdentifier = "org.winsvpn.macos.PacketTunnel"
private let expectedManagerSignature = "wins_vpn.apple_packet_tunnel.v1"
private let resultPathEnvironmentKey = "WINS_LEGACY_VPN_REMOVAL_RESULT_PATH"

private final class LegacyVPNRemovalDelegate: NSObject, NSApplicationDelegate {
  private var hasFinished = false

  func applicationDidFinishLaunching(_ notification: Notification) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      if let error {
        self.finish(status: "load_failed", details: ["error": error.localizedDescription], exitCode: 2)
        return
      }

      let matchingManagers = (managers ?? []).filter { manager in
        guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
          return false
        }
        guard tunnelProtocol.providerBundleIdentifier == legacyProviderBundleIdentifier else {
          return false
        }

        let signature = tunnelProtocol.providerConfiguration?["wins_manager_signature"] as? String
        return signature == expectedManagerSignature || manager.localizedDescription == "Win's VPN"
      }

      guard !matchingManagers.isEmpty else {
        self.finish(status: "not_found", details: ["removed_count": 0], exitCode: 0)
        return
      }

      let group = DispatchGroup()
      let lock = NSLock()
      var removalErrors: [String] = []
      for manager in matchingManagers {
        group.enter()
        manager.connection.stopVPNTunnel()
        manager.removeFromPreferences { removalError in
          if let removalError {
            lock.lock()
            removalErrors.append(removalError.localizedDescription)
            lock.unlock()
          }
          group.leave()
        }
      }

      group.notify(queue: .main) {
        if removalErrors.isEmpty {
          self.finish(
            status: "removed",
            details: ["removed_count": matchingManagers.count],
            exitCode: 0
          )
        } else {
          self.finish(
            status: "remove_failed",
            details: [
              "attempted_count": matchingManagers.count,
              "errors": removalErrors,
            ],
            exitCode: 3
          )
        }
      }
    }
  }

  private func finish(status: String, details: [String: Any], exitCode: Int32) {
    guard !hasFinished else { return }
    hasFinished = true

    var payload = details
    payload["legacy_provider_bundle_id"] = legacyProviderBundleIdentifier
    payload["status"] = status

    if let resultPath = ProcessInfo.processInfo.environment[resultPathEnvironmentKey],
       let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) {
      try? data.write(to: URL(fileURLWithPath: resultPath), options: .atomic)
    }

    if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
       let output = String(data: data, encoding: .utf8) {
      print("WINS_LEGACY_VPN_REMOVAL_RESULT \(output)")
    }

    NSApplication.shared.terminate(nil)
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
      exit(exitCode)
    }
  }
}

private let application = NSApplication.shared
private let delegate = LegacyVPNRemovalDelegate()
application.delegate = delegate
application.setActivationPolicy(.prohibited)
application.run()
