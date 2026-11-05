import Foundation

/// What happened to the explicit `setTunnelNetworkSettings(nil)` a Packet Tunnel
/// provider issues while it is stopping — and the status fields that make that
/// answer recoverable from the status document afterwards.
enum WinsNetworkSettingsRelease {
  enum Outcome: String {
    case released = "released"
    case failed = "failed"
    case deadline = "deadline"
  }
  static let maxErrorDomainLength = 128
  static let unknownErrorDomain = "unknown"
  static func statusFields(
    outcome: Outcome,
    error: Error? = nil,
    elapsedMilliseconds: Int,
    deadlineMilliseconds: Int
  ) -> [String: Any] {
    var fields: [String: Any] = [
      "network_settings_release_requested": true,
      "network_settings_release_outcome": outcome.rawValue,
      "network_settings_release_completed": outcome != .deadline,
      "network_settings_release_failed": outcome == .failed,
      "network_settings_release_elapsed_ms": max(0, elapsedMilliseconds),
      "network_settings_release_deadline_ms": max(0, deadlineMilliseconds)
    ]
    guard let error else { return fields }
    let nsError = error as NSError
    fields["network_settings_release_error_domain"] = WinsAppleText.boundedText(
      nsError.domain,
      fallback: unknownErrorDomain,
      maxLength: maxErrorDomainLength
    )
    fields["network_settings_release_error_code"] = nsError.code
    return fields
  }
}

enum WinsDevContainmentStopCarry {
  static let statusKey = "dev_containment_at_stop"
  static let fieldPrefix = "dev_containment_"
  static let activeKey = "dev_containment_active"
  enum Attribution: String {
    case contained = "contained"
    case notContained = "not_contained"
    case unknown = "unknown"
  }
  static func fields(
    previousStatus: [String: Any]?,
    expectedStatusGeneration: String = ""
  ) -> [String: Any] {
    guard let previousStatus else {
      return [statusKey: Attribution.unknown.rawValue]
    }
    let expected = WinsPacketTunnelProviderStatus.safeStatusGeneration(expectedStatusGeneration)
    let previous = WinsPacketTunnelProviderStatus.safeStatusGeneration(
      previousStatus["status_generation"] as? String
    )
    guard expected.isEmpty || previous.isEmpty || expected == previous else {
      return [statusKey: Attribution.unknown.rawValue]
    }
    var fields: [String: Any] = [:]
    for (key, value) in previousStatus where key.hasPrefix(fieldPrefix) {
      guard let safeValue = WinsPacketTunnelProviderStatus.safeMappedStatusValue(
        value,
        sourceKey: key
      ) else { continue }
      fields[key] = safeValue
    }
    let contained = fields[activeKey] as? Bool == true
    fields[activeKey] = contained
    fields[statusKey] = (contained ? Attribution.contained : Attribution.notContained).rawValue
    return fields
  }
}
