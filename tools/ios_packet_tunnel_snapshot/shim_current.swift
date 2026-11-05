import Foundation
import NetworkExtension
extension PacketTunnelProvider {
  func makeNetworkSettingsForHarness(
    _ config: WinsTunnelConfig
  ) throws -> (settings: NEPacketTunnelNetworkSettings, statusFields: [String: Any]) {
    try makeNetworkSettings(from: config)
  }
}
