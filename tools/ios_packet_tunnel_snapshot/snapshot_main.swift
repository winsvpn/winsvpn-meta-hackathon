// iOS Packet Tunnel network-settings SNAPSHOT harness.
//
// Purpose: run the REAL `makeNetworkSettings` body out of
// `ios/PacketTunnel/PacketTunnelProvider.swift` against a set of shipping
// config fixtures and print a complete, deterministic description of the
// NEPacketTunnelNetworkSettings object it produces (or of the error it throws).
//
// The provider source is used verbatim except for two mechanical rewrites,
// applied to a COPY, which the runner script prints:
//   1. the superclass is swapped for the stand-in below, because
//      NEPacketTunnelProvider cannot be instantiated outside an extension host
//      (a plain CLI segfaults on `NEPacketTunnelProvider()` -- verified);
//   2. `private func makeNetworkSettings` loses `private`, so this file can
//      call it.
// Neither touches the body under test.

import Foundation
import NetworkExtension

/// Stand-in for NEPacketTunnelProvider. Declares exactly the members the
/// provider file overrides or calls, and nothing else. `makeNetworkSettings`
/// touches none of them.
class WinsHarnessProviderBase: NSObject {
  var packetFlow: NEPacketTunnelFlow {
    fatalError("the snapshot harness never starts a tunnel")
  }
  var protocolConfiguration: NEVPNProtocol? { nil }
  func setTunnelNetworkSettings(
    _ settings: NEPacketTunnelNetworkSettings?,
    completionHandler: ((Error?) -> Void)?
  ) {
    completionHandler?(nil)
  }
  func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {}
  func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {}
  func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {}
  func sleep(completionHandler: @escaping () -> Void) {}
  func wake() {}
  /// Recorded rather than performed: the harness must be able to observe that a
  /// contained dev session armed a self-cancel without a tunnel existing.
  func cancelTunnelWithError(_ error: Error?) {
    FileHandle.standardError.write("cancelTunnelWithError called\n".data(using: .utf8)!)
  }
}

func out(_ line: String) {
  FileHandle.standardOutput.write((line + "\n").data(using: .utf8)!)
}

func describe(_ route: NEIPv4Route) -> String {
  "\(route.destinationAddress)/\(route.destinationSubnetMask)"
}

func describe(_ route: NEIPv6Route) -> String {
  "\(route.destinationAddress)/\(route.destinationNetworkPrefixLength)"
}

/// Every property of the settings object that can affect what the host routes,
/// resolves, or leaks. Deliberately exhaustive: a snapshot that omits a field
/// cannot prove that field did not change.
func snapshot(_ settings: NEPacketTunnelNetworkSettings) -> [String] {
  var lines: [String] = []
  lines.append("tunnelRemoteAddress = \(settings.tunnelRemoteAddress)")
  lines.append("mtu = \(settings.mtu.map { "\($0)" } ?? "nil")")

  if let v4 = settings.ipv4Settings {
    lines.append("ipv4Settings = present")
    lines.append("ipv4.addresses = \(v4.addresses.joined(separator: ","))")
    lines.append("ipv4.subnetMasks = \(v4.subnetMasks.joined(separator: ","))")
    let included = (v4.includedRoutes ?? []).map(describe).sorted()
    let excluded = (v4.excludedRoutes ?? []).map(describe).sorted()
    lines.append("ipv4.includedRoutes.count = \(v4.includedRoutes?.count ?? -1)")
    lines.append("ipv4.includedRoutes = [\(included.joined(separator: " "))]")
    lines.append("ipv4.excludedRoutes.count = \(v4.excludedRoutes?.count ?? -1)")
    lines.append("ipv4.excludedRoutes = [\(excluded.joined(separator: " "))]")
    let hasDefault = (v4.includedRoutes ?? []).contains {
      $0.destinationAddress == "0.0.0.0" && $0.destinationSubnetMask == "0.0.0.0"
    }
    lines.append("ipv4.hasDefaultRoute = \(hasDefault)")
  } else {
    lines.append("ipv4Settings = nil")
  }

  if let v6 = settings.ipv6Settings {
    lines.append("ipv6Settings = present")
    lines.append("ipv6.addresses = \(v6.addresses.joined(separator: ","))")
    lines.append(
      "ipv6.networkPrefixLengths = \(v6.networkPrefixLengths.map { "\($0)" }.joined(separator: ","))"
    )
    let included = (v6.includedRoutes ?? []).map(describe).sorted()
    lines.append("ipv6.includedRoutes.count = \(v6.includedRoutes?.count ?? -1)")
    lines.append("ipv6.includedRoutes = [\(included.joined(separator: " "))]")
  } else {
    lines.append("ipv6Settings = nil")
  }

  if let dns = settings.dnsSettings {
    lines.append("dnsSettings = present")
    lines.append("dns.servers = \(dns.servers.joined(separator: ","))")
    lines.append("dns.matchDomains = \((dns.matchDomains ?? []).map { "\"\($0)\"" }.joined(separator: ","))")
    lines.append("dns.matchDomainsNoSearch = \(dns.matchDomainsNoSearch)")
  } else {
    lines.append("dnsSettings = nil")
  }
  return lines
}

// MARK: - Fixtures
//
// `directConfig` is copied verbatim from `tools/verify_apple_tunnel_config.swift`
// (the shipping harness's own fixture), so these are the same documents the
// production validator is already exercised with.

let key = "<REDACTED_WG_KEY>"

let directConfig = """
[Interface]
PrivateKey = \(key)
Address = 10.8.0.2/32
MTU = 1280
DNS = 10.8.0.1
Jc = 2
Jmin = 10
Jmax = 30
S1 = 16
S2 = 80
S3 = 16
S4 = 0
H1 = 11
H2 = 22
H3 = 33
H4 = 44

[Peer]
PublicKey = \(key)
Endpoint = 203.0.113.10:9110
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

let xrayConfig = """
[Interface]
PrivateKey = \(key)
Address = 10.8.0.2/32
MTU = 1280
DNS = 10.8.0.1
Jc = 2
Jmin = 10
Jmax = 30
S1 = 16
S2 = 80
S3 = 16
S4 = 0
H1 = 11
H2 = 22
H3 = 33
H4 = 44

[Peer]
PublicKey = \(key)
Endpoint = 127.0.0.1:42110
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[Xray]
Enabled = true
Uuid = 00000000-0000-0000-0000-000000000000
Host = sync.example.invalid
Port = 80
ServerName = sync.example.invalid
Path = /wins-stealth-tunnel
Security = none
LocalPort = 42110
RemoteAwgHost = 127.0.0.1
RemoteAwgPort = 9110
"""

let winnConfig = directConfig + """


[winn]
enabled = true
version = winn/3
carrier = direct-awg
endpoint = 203.0.113.10:9110
mtu = 1280
"""

let splitRouteConfig = directConfig.replacingOccurrences(
  of: "AllowedIPs = 0.0.0.0/0, ::/0",
  with: "AllowedIPs = 10.42.0.0/16, ::/0"
)

// POSITIVE CONTROL. The document `lib/winn_protocol_dev_session.dart` assembles:
// full-tunnel AllowedIPs plus the containment marker.
let containedDevConfig = directConfig + """


[WinsDevContainment]
Enabled = true
"""

let containedDevConfigBadRoute = directConfig + """


[WinsDevContainment]
Enabled = true
TestRoute = 0.0.0.0/0
"""

let fixtures: [(String, String)] = [
  ("PRODUCTION direct full tunnel", directConfig),
  ("PRODUCTION xray full tunnel", xrayConfig),
  ("PRODUCTION winn/3 full tunnel", winnConfig),
  ("PRODUCTION split tunnel (ipv6 default kept)", splitRouteConfig),
  ("CONTROL contained dev session (marker, derived /32)", containedDevConfig),
  ("CONTROL contained dev session (marker, 0.0.0.0/0 test route)", containedDevConfigBadRoute)
]

// MARK: - Run

#if DEBUG
out("BUILD_SHAPE = DEBUG")
#else
out("BUILD_SHAPE = RELEASE")
#endif

let provider = PacketTunnelProvider()

for (name, raw) in fixtures {
  out("")
  out("### \(name)")
  do {
    let parsed = try WinsTunnelConfig.parseAndValidate(raw)
    out("config.devContainmentRequested = \(parsed.devContainmentRequested)")
    out("config.defaultIPv4RouteEnabled = \(parsed.defaultIPv4RouteEnabled)")
    out("config.ipv6LeakProtectionEnabled = \(parsed.ipv6LeakProtectionEnabled)")
    out("config.fullTunnelDNSMatchEnabled = \(parsed.fullTunnelDNSMatchEnabled)")
    out("config.dnsMatchDomains = \(parsed.dnsMatchDomains.map { "\"\($0)\"" }.joined(separator: ","))")
    let result = try provider.makeNetworkSettingsForHarness(parsed)
    out("RESULT = settings")
    for line in snapshot(result.settings) {
      out("  " + line)
    }
    let statusKeys = result.statusFields.keys.sorted()
    out("  statusFields.count = \(result.statusFields.count)")
    for key in statusKeys {
      out("  status.\(key) = \(result.statusFields[key] ?? "nil")")
    }
  } catch let error as NSError {
    out("RESULT = throw")
    out("  error.domain = \(error.domain)")
    out("  error.code = \(error.code)")
    out("  error.message = \(error.localizedDescription)")
    if let fields = error.userInfo["wins_provider_status_fields"] as? [String: Any] {
      for key in fields.keys.sorted() {
        out("  status.\(key) = \(fields[key] ?? "nil")")
      }
    }
  }
}

out("")
out("END OF SNAPSHOT")
