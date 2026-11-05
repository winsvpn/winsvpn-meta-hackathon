import Foundation

@main
struct ControlProtocolTests {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        precondition(condition(), message)
    }

    static func rejects(_ label: String, _ action: () throws -> Void) {
        do { try action(); preconditionFailure("Accepted: \(label)") } catch {}
    }

    static func main() throws {
        // Synthetic test values only; the test never calls Keychain or a network API.
        let key = Data(repeating: 0xA5, count: 32)
        let now: Int64 = 1000
        let request = SafariControlMessage(version: 1, kind: "status", nonce: UUID().uuidString,
            issuedAt: now, status: nil)
        let encoded = try SafariControlProtocol.encode(request, key: key)
        let decoded = try SafariControlProtocol.decode(encoded, key: key, now: now)
        require(decoded.nonce == request.nonce, "nonce was not preserved")
        rejects("wrong key") { _ = try SafariControlProtocol.decode(encoded, key: Data(repeating: 0, count: 32), now: now) }
        var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        object["payload"] = Data("{}".utf8).base64EncodedString()
        let tampered = try JSONSerialization.data(withJSONObject: object)
        rejects("tampered payload") { _ = try SafariControlProtocol.decode(tampered, key: key, now: now) }
        rejects("expired") { _ = try SafariControlProtocol.decode(encoded, key: key, now: now + 31) }
        rejects("future") { _ = try SafariControlProtocol.decode(encoded, key: key, now: now - 6) }
        rejects("oversized") { _ = try SafariControlProtocol.decode(Data(repeating: 65, count: 4097), key: key, now: now) }
        let replay = SafariReplayWindow(capacity: 1)
        try replay.accept(decoded, now: now)
        rejects("replayed request") { try replay.accept(decoded, now: now) }
        let another = SafariControlMessage(version: 1, kind: "status", nonce: UUID().uuidString,
            issuedAt: now, status: nil)
        rejects("full replay cache") { try replay.accept(another, now: now) }
        let later = SafariControlMessage(version: 1, kind: "status", nonce: UUID().uuidString,
            issuedAt: now + 31, status: nil)
        try replay.accept(later, now: now + 31)
        let invalid = SafariControlMessage(version: 1, kind: "connect", nonce: UUID().uuidString,
            issuedAt: now, status: nil)
        let unknown = try SafariControlProtocol.encode(invalid, key: key)
        rejects("unknown command") { _ = try SafariControlProtocol.decode(unknown, key: key, now: now) }
        require(SafariControlProtocol.isCapabilityProbe(["v": 1, "type": "capability_probe"]), "valid probe")
        require(!SafariControlProtocol.isCapabilityProbe(["v": true, "type": "capability_probe"]), "Boolean version accepted")
        require(!SafariControlProtocol.isCapabilityProbe(["v": 1, "type": "capability_probe", "extra": 1]), "extra field accepted")
        require(!SafariControlProtocol.isCapabilityProbe(["v": "1", "type": "capability_probe"]), "string version accepted")
        require(!SafariControlProtocol.isCapabilityProbe(["v": 1.5, "type": "capability_probe"]), "fractional version accepted")
        require(!SafariControlProtocol.isCapabilityProbe(nil), "nil accepted")
        for mask in 0..<16 {
            let status = SafariProviderStatus(engineReady: mask & 1 != 0, flowAdapterReady: mask & 2 != 0,
                dnsReady: mask & 4 != 0, captureReady: mask & 8 != 0)
            require(status.routing == (mask == 15), "partial readiness permitted routing")
            let reply = SafariControlMessage(version: 1, kind: "status_reply", nonce: request.nonce,
                issuedAt: now, status: status)
            let wire = try SafariControlProtocol.encode(reply, key: key)
            let roundTrip = try SafariControlProtocol.decode(wire, key: key, now: now)
            require(roundTrip.status == status, "reply status changed")
        }
        require(!SafariWinnPacketABI.validPacket(Data("GET / HTTP/1.1\r\n".utf8)), "plaintext stream treated as IP")
        require(!SafariWinnPacketABI.validPacket(Data()), "empty IP accepted")
        var ipv4 = Data(repeating: 0, count: 20)
        ipv4[0] = 0x45; ipv4[3] = 20
        require(SafariWinnPacketABI.validPacket(ipv4), "IPv4 packet rejected")
        ipv4[3] = 19
        require(!SafariWinnPacketABI.validPacket(ipv4), "truncated IPv4 accepted")
        var ipv6 = Data(repeating: 0, count: 40)
        ipv6[0] = 0x60
        require(SafariWinnPacketABI.validPacket(ipv6), "IPv6 packet rejected")
        ipv6[5] = 1
        require(!SafariWinnPacketABI.validPacket(ipv6), "truncated IPv6 accepted")
        rejects("absent production engine") { _ = try SafariWinnPacketABI() }
        print("PASS: authenticated control, tamper, replay, bounds, readiness, probe schema, packet framing, absent engine")
    }
}
