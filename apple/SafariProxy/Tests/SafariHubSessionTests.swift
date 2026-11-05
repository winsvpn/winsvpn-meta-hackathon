import Foundation
import CryptoKit
import Security

private struct OfflineTransport: SafariHubTransport {
    let reply: SafariHubResponse
    let expectedPublic: String
    let expectedWinn: String

    func send(_ request: URLRequest) async throws -> SafariHubResponse {
        precondition(request.url?.absoluteString == "https://a.app-cloud-sync.net/free/verify")
        precondition(request.httpMethod == "POST")
        precondition(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        let object = try JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any]
        precondition(object["client_public_key"] as? String == expectedPublic)
        precondition(object["winn3_static_public"] as? String == expectedWinn)
        precondition(object["winn3_static_private"] == nil)
        precondition(object["private_key"] == nil)
        precondition(object["supports_awg"] as? Bool == false)
        precondition(object["supports_winn3_spa"] as? Bool == false)
        precondition(object["supports_winn3_dualauth"] as? Bool == true)
        return reply
    }
}

@main
private struct SafariHubSessionTests {
    static func main() async throws {
        var passed = 0
        func check(_ condition: @autoclosure () -> Bool) {
            precondition(condition())
            passed += 1
        }
        func rejects(_ expected: SafariSessionError, _ operation: () throws -> Void) {
            do { try operation(); fatalError("expected refusal: \(expected.rawValue)") }
            catch let error as SafariSessionError { precondition(error == expected); passed += 1 }
            catch { fatalError("unexpected error type") }
        }
        // Fresh test-only signing material stays in memory and is never printed.
        let signer = Curve25519.Signing.PrivateKey()
        let ringData = signer.publicKey.rawRepresentation
        let wire = "g1=" + ringData.map { String(format: "%02x", $0) }.joined() + "\n"
        let digest = SHA256.hash(data: Data(wire.utf8)).map { String(format: "%02x", $0) }.joined()
        let verifier = try SafariDescriptorVerifier(publicKeys: ["g1": ringData], expectedIdentity: digest)
        let identity = SafariClientIdentity()
        check(identity.clientPublicKey != identity.winn3PublicKey)
        let request = SafariFreeSessionRequest(installID: "INSTALL-OFFLINE-FIXTURE", deviceModel: "MACOS DEVICE",
            platform: "macos", appVersion: "1.0.16", locale: "en_US", location: "test-node",
            legal: SafariLegalAcceptance(version: "fixture-legal", hash: String(repeating: "1", count: 64),
                privacyVersion: "fixture-privacy", privacyURL: "https://www.winsvpn.org/privacy/"))
        let now = Date()
        rejects(.invalidRequest) {
            _ = try SafariLegalAcceptance.bundled(displayedBody: "unrelated text",
                privacyVersion: "2026-10-04.v5", privacyURL: "https://www.winsvpn.org/privacy/")
        }
        let emptyHashRequest = SafariFreeSessionRequest(installID: "INSTALL-OFFLINE-FIXTURE", deviceModel: "MACOS DEVICE",
            platform: "macos", appVersion: "1.0.16", locale: "en_US", location: "test-node",
            legal: SafariLegalAcceptance(version: "2026-10-04.v5", hash: "",
                privacyVersion: "2026-10-04.v5", privacyURL: "https://www.winsvpn.org/privacy/"))
        rejects(.invalidRequest) { _ = try emptyHashRequest.body(identity: identity) }
        if CommandLine.arguments.count > 1 {
            let body = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
            let legal = try SafariLegalAcceptance.bundled(displayedBody: body,
                privacyVersion: "2026-10-04.v5", privacyURL: "https://www.winsvpn.org/privacy/")
            check(legal.hash.isEmpty)
            check(legal.displayHash == "52c21408988ae08e29ff1c06a2b6b661be3c2447b19ed02de702f46a46ce3ab8")
            let bundledRequest = SafariFreeSessionRequest(installID: "INSTALL-OFFLINE-FIXTURE", deviceModel: "MACOS DEVICE",
                platform: "macos", appVersion: "1.0.16", locale: "en_US", location: "test-node", legal: legal)
            let wire = try JSONSerialization.jsonObject(with: bundledRequest.body(identity: identity)) as! [String: Any]
            check(wire["legal_hash"] as? String == "")
            check(wire["display_hash"] == nil)
        }
        let seconds = Int(now.timeIntervalSince1970)
        var payload: [String: Any] = [
            "admission_gen": 1, "admission_secret": Data(String(repeating: "0123456789abcdef", count: 4).utf8).base64EncodedString(),
            "alg": "ed25519", "bucket_window_s": 10, "endpoint": "192.0.2.2:443",
            "gateway_id": Data("test-gateway".utf8).base64EncodedString(), "iat": seconds - 1,
            "inner_resolver_v4": "10.10.0.1", "inner_router_v4": "10.10.0.1", "kid": "g1",
            "max_skew_s": 60, "node": "test-node", "not_after": seconds + 7200,
            "padding": "bucket", "seq": 1, "static_pub": identity.clientPublicKey, "tag_size": 32, "v": 3
        ]
        func envelope(_ p: [String: Any], domain: String = "winsvpn-winn3-descriptor/v1\0") throws -> [String: Any] {
            let bytes = try JSONSerialization.data(withJSONObject: p, options: [.sortedKeys])
            return ["payload": bytes.base64EncodedString(),
                    "sig": try signer.signature(for: Data(domain.utf8) + bytes).base64EncodedString()]
        }
        let validEnvelope = try envelope(payload)
        let descriptor = try verifier.verify(validEnvelope, now: now)
        check(descriptor.gatewayID == "test-gateway")
        check(descriptor.resolverV4 == "10.10.0.1")
        rejects(.descriptorRing) { _ = try SafariDescriptorVerifier(publicKeys: ["g1": ringData], expectedIdentity: "0") }
        _ = try SafariDescriptorVerifier.production
        passed += 1
        rejects(.descriptorSignature) { _ = try verifier.verify(envelope(payload, domain: "other\0"), now: now) }
        var changed = payload
        changed["endpoint"] = "192.0.2.3:443"
        var swapped = try envelope(changed)
        swapped["sig"] = validEnvelope["sig"]
        rejects(.descriptorSignature) { _ = try verifier.verify(swapped, now: now) }
        for key in ["v", "tag_size", "bucket_window_s", "max_skew_s"] {
            changed = payload; changed[key] = true
            rejects(.descriptorSchema) { _ = try verifier.verify(envelope(changed), now: now) }
        }
        changed = payload; changed["unexpected"] = "future-field"
        rejects(.descriptorSchema) { _ = try verifier.verify(envelope(changed), now: now) }
        rejects(.descriptorLifetime) { _ = try verifier.verify(validEnvelope, now: Date(timeIntervalSince1970: Double(seconds + 7200))) }
        rejects(.descriptorLifetime) { _ = try verifier.verify(validEnvelope, now: Date(timeIntervalSince1970: Double(seconds - 2))) }
        changed = payload; changed["iat"] = Int64.min; changed["not_after"] = Int64.max
        rejects(.descriptorLifetime) { _ = try verifier.verify(envelope(changed), now: now) }
        changed = payload; changed["inner_resolver_v4"] = "8.8.8.8"
        rejects(.descriptorAddress) { _ = try verifier.verify(envelope(changed), now: now) }
        changed = payload; changed["endpoint"] = "gateway.example:443"
        rejects(.descriptorAddress) { _ = try verifier.verify(envelope(changed), now: now) }
        changed = payload; changed["gateway_id"] = Data("test-gateway ".utf8).base64EncodedString()
        rejects(.descriptorMaterial) { _ = try verifier.verify(envelope(changed), now: now) }
        changed = payload; changed["admission_secret"] = Data([9, 1, 2]).base64EncodedString()
        rejects(.descriptorMaterial) { _ = try verifier.verify(envelope(changed), now: now) }
        changed = payload; changed["auth_ed25519"] = identity.clientPublicKey
        rejects(.descriptorMaterial) { _ = try verifier.verify(envelope(changed), now: now) }
        changed = payload; changed["auth_ed25519"] = false; changed["auth_mldsa65"] = []
        rejects(.descriptorMaterial) { _ = try verifier.verify(envelope(changed), now: now) }
        for key in ["seq", "admission_gen"] {
            for badValue: Any in [0, -1, true, "1"] {
                changed = payload; changed[key] = badValue
                rejects(.descriptorSchema) { _ = try verifier.verify(envelope(changed), now: now) }
            }
        }
        let canonical = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let duplicate = Data("{\"seq\":2,".utf8) + canonical.dropFirst()
        let duplicateEnvelope: [String: Any] = ["payload": duplicate.base64EncodedString(),
            "sig": try signer.signature(for: Data("winsvpn-winn3-descriptor/v1\0".utf8) + duplicate).base64EncodedString()]
        rejects(.descriptorMissing) { _ = try verifier.verify(duplicateEnvelope, now: now) }
        check(SafariSessionValidation.hasDuplicateObjectKeys(Data("{\"v\":1,\"\\u0076\":2}".utf8)))
        check(!SafariSessionValidation.hasDuplicateObjectKeys(Data("{\"a\":{\"v\":1},\"b\":{\"v\":2}}".utf8)))
        changed = payload; changed["node"] = "t\u{212a}1"
        rejects(.descriptorNode) { _ = try verifier.verify(envelope(changed), now: now) }
        rejects(.descriptorMissing) {
            _ = try verifier.verify(["payload": String(repeating: "A", count: 8193), "sig": validEnvelope["sig"]!], now: now)
        }
        var config: [String: Any] = [
            "protocol_version": "winn/3", "protocol_params": ["carrier": "winn3", "session_id": "offline"],
            "node_slug": "test-node", "winn3_inner_v4": "10.10.0.2", "winn3_carrier_classes": "udp,tcp,tls",
            "winn3_static_public": identity.winn3PublicKey, "client_public_key": identity.clientPublicKey,
            "winn3_descriptor": validEnvelope
        ]
        func response(_ c: [String: Any], status: Int = 200) throws -> SafariHubResponse {
            SafariHubResponse(status: status, body: try JSONSerialization.data(withJSONObject:
                ["status": "authenticated", "vpn_config": c], options: [.sortedKeys]))
        }
        let transport = OfflineTransport(reply: try response(config), expectedPublic: identity.clientPublicKey,
                                         expectedWinn: identity.winn3PublicKey)
        let client = try SafariHubSessionClient(transport: transport, verifier: verifier)
        let verified = try await client.acquire(request, identity: identity, origin: SafariPinnedHubTransport.defaultOrigin)
        let createData = try verified.engineCreateJSON(now: now)
        let create = try JSONSerialization.jsonObject(with: createData) as! [String: Any]
        check(create["contract"] as? String == "winn-datapath/1+winn3")
        check(create["payload"] as? String == "ip-packet")
        check(create["carrier"] as? String == "winn3")
        check(create["allow_own_socket"] as? Bool == true)
        check(create["gateway_id"] as? String == "test-gateway")
        check(create["path_mtu"] as? Int == 0)
        check(create["static_private"] as? String == identity.winn3Key.rawRepresentation.base64EncodedString())
        changed = payload
        changed["auth_ed25519"] = identity.clientPublicKey
        let ml = Data(repeating: 7, count: 1952).base64EncodedString()
        changed["auth_mldsa65"] = ml
        var dualConfig = config
        dualConfig["winn3_descriptor"] = try envelope(changed)
        let dual = try client.validate(response(dualConfig), request: request, identity: identity, now: now)
        let dualJSON = try JSONSerialization.jsonObject(with: dual.engineCreateJSON(now: now)) as! [String: Any]
        check(dualJSON["auth_ed25519"] as? String == identity.clientPublicKey)
        check(dualJSON["auth_mldsa65"] as? String == ml)
        rejects(.descriptorLifetime) { _ = try verified.engineCreateJSON(now: verified.expiresAt) }
        func validate(_ c: [String: Any]) throws { _ = try client.validate(response(c), request: request, identity: identity, now: now) }
        var bad = config; bad["winn3_static_public"] = identity.clientPublicKey
        rejects(.identityMismatch) { try validate(bad) }
        bad = config; bad.removeValue(forKey: "winn3_static_public")
        rejects(.identityMismatch) { try validate(bad) }
        bad = config; bad["winn3_static_private"] = identity.clientPublicKey
        rejects(.servedPrivateKey) { try validate(bad) }
        bad = config; bad["location_slug"] = "wrong-node"
        rejects(.descriptorNode) { try validate(bad) }
        bad = config; bad["selected_node"] = ["slug": "test-node", "node_slug": "wrong-node"]
        rejects(.descriptorNode) { try validate(bad) }
        bad = config; bad["winn3_inner_v4"] = "10.10.0.1"
        rejects(.invalidConfiguration) { try validate(bad) }
        bad = config; bad["winn3_inner_v4"] = "10.10.1.2"
        rejects(.invalidConfiguration) { try validate(bad) }
        changed = payload; changed["inner_resolver_v4"] = "8.8.8.8"; changed["inner_router_v4"] = "8.8.8.8"
        bad = config; bad["winn3_inner_v4"] = "8.8.8.9"; bad["winn3_descriptor"] = try envelope(changed)
        rejects(.invalidConfiguration) { try validate(bad) }
        changed = payload; changed["admission_secret"] = Data(repeating: 7, count: 31).base64EncodedString()
        rejects(.descriptorMaterial) { _ = try verifier.verify(envelope(changed), now: now) }
        bad = config; bad.removeValue(forKey: "winn3_carrier_classes")
        rejects(.invalidConfiguration) { try validate(bad) }
        bad = config; bad["winn3_path_mtu"] = "-1"
        rejects(.invalidConfiguration) { try validate(bad) }
        bad = config; bad["protocol_version"] = "winn/1"
        rejects(.unsupportedProtocol) { try validate(bad) }
        bad = config; bad["protocol_params"] = ["carrier": "winn3", "spa_key": "unhandled"]
        rejects(.unsupportedProtocol) { try validate(bad) }
        rejects(.rateLimited) { _ = try client.validate(response(config, status: 429), request: request, identity: identity, now: now) }
        rejects(.freeUnavailable) { _ = try client.validate(response(config, status: 503), request: request, identity: identity, now: now) }
        rejects(.responseTooLarge) {
            _ = try client.validate(SafariHubResponse(status: 200, body: Data(repeating: 32, count: 262145)),
                                    request: request, identity: identity, now: now)
        }
        check(SafariPinnedHubTransport.allowedOrigin(SafariPinnedHubTransport.defaultOrigin))
        for raw in ["http://a.app-cloud-sync.net", "https://a.app-cloud-sync.net@evil.example",
                    "https://a.app-cloud-sync.net.evil.example", "https://a.app-cloud-sync.net:8443",
                    "https://a.app-cloud-sync.net/path", "https://a.app-cloud-sync.net?query=1"] {
            check(!SafariPinnedHubTransport.allowedOrigin(URL(string: raw)!))
        }
        let anchors = try SafariPinnedHubTransport.anchors()
        check(anchors.count == 12)
        var trust: SecTrust?
        check(SecTrustCreateWithCertificates(anchors[0], SecPolicyCreateSSL(true, "a.app-cloud-sync.net" as CFString), &trust) == errSecSuccess)
        // A pinned CA root is not a valid server leaf for the requested hostname.
        check(!SafariPinnedHubTransport.accepts(trust!, host: "a.app-cloud-sync.net"))
        check(!SafariPinnedHubTransport.accepts(trust!, host: "evil.example"))
        payload.removeAll(); config.removeAll()
        print("Safari session offline tests passed: \(passed) assertions; no network requests")
    }
}
