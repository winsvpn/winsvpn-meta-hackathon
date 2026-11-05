import Foundation
import CryptoKit
import CoreFoundation

// Messages contain only capability state. Credentials never cross into Safari.
enum SafariControlError: Error {
    case invalidMessage, authenticationFailed, replay, capacity, unavailable
}

struct SafariProviderStatus: Codable, Equatable {
    let engineReady: Bool
    let flowAdapterReady: Bool
    let dnsReady: Bool
    let captureReady: Bool

    var routing: Bool { engineReady && flowAdapterReady && dnsReady && captureReady }

    static let unavailable = SafariProviderStatus(
        engineReady: false, flowAdapterReady: false, dnsReady: false, captureReady: false
    )
}

struct SafariControlMessage: Codable {
    let version: Int
    let kind: String
    let nonce: String
    let issuedAt: Int64
    let status: SafariProviderStatus?
}

private struct SafariControlEnvelope: Codable {
    let payload: Data
    let authentication: Data
}

enum SafariControlProtocol {
    static let maximumBytes = 4096
    static let lifetime: Int64 = 30

    static func encode(_ message: SafariControlMessage, key: Data) throws -> Data {
        guard key.count == 32 else { throw SafariControlError.authenticationFailed }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let payload = try encoder.encode(message)
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: key))
        let encoded = try encoder.encode(SafariControlEnvelope(payload: payload, authentication: Data(mac)))
        guard encoded.count <= maximumBytes else { throw SafariControlError.invalidMessage }
        return encoded
    }

    static func decode(_ data: Data, key: Data, now: Int64) throws -> SafariControlMessage {
        guard data.count <= maximumBytes, key.count == 32 else {
            throw SafariControlError.invalidMessage
        }
        let envelope = try JSONDecoder().decode(SafariControlEnvelope.self, from: data)
        guard envelope.authentication.count == 32,
              HMAC<SHA256>.isValidAuthenticationCode(
                envelope.authentication, authenticating: envelope.payload, using: SymmetricKey(data: key)
              ) else { throw SafariControlError.authenticationFailed }
        let message = try JSONDecoder().decode(SafariControlMessage.self, from: envelope.payload)
        guard message.version == 1, UUID(uuidString: message.nonce)?.uuidString == message.nonce,
              message.issuedAt >= now - lifetime, message.issuedAt <= now + 5,
              (message.kind == "status" && message.status == nil)
                || (message.kind == "status_reply" && message.status != nil) else {
            throw SafariControlError.invalidMessage
        }
        return message
    }

    static func isCapabilityProbe(_ value: Any?) -> Bool {
        guard let request = value as? [String: Any], Set(request.keys) == ["v", "type"],
              let version = request["v"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
              request["type"] as? String == "capability_probe" else { return false }
        return true
    }
}

// Refuse excess clients instead of evicting still-live replay entries.
final class SafariReplayWindow {
    private var seen: [String: Int64] = [:]
    private let lock = NSLock()
    private let capacity: Int

    init(capacity: Int = 512) { self.capacity = capacity }

    func accept(_ message: SafariControlMessage, now: Int64) throws {
        lock.lock()
        defer { lock.unlock() }
        seen = seen.filter { $0.value >= now - SafariControlProtocol.lifetime }
        guard seen[message.nonce] == nil else { throw SafariControlError.replay }
        guard seen.count < capacity else { throw SafariControlError.capacity }
        seen[message.nonce] = message.issuedAt
    }
}
