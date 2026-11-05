import Foundation
import CryptoKit
import CoreFoundation
import Darwin

enum SafariSessionError: String, Error {
    case invalidRequest, invalidOrigin, transportRejected, responseTooLarge
    case unauthenticated, freeUnavailable, rateLimited, identityMismatch
    case servedPrivateKey, unsupportedProtocol, invalidConfiguration
    case descriptorMissing, descriptorSignature, descriptorRing, descriptorSchema
    case descriptorLifetime, descriptorNode, descriptorAddress, descriptorMaterial
}

// These are separate protocol identities. Neither private key is sent to the hub.
// The containing app owns persistence in its protected, standalone keychain group.
struct SafariClientIdentity {
    let clientKey: Curve25519.KeyAgreement.PrivateKey
    let winn3Key: Curve25519.KeyAgreement.PrivateKey

    init() {
        clientKey = Curve25519.KeyAgreement.PrivateKey()
        winn3Key = Curve25519.KeyAgreement.PrivateKey()
    }

    init(clientPrivate: Data, winn3Private: Data) throws {
        guard clientPrivate != winn3Private else { throw SafariSessionError.invalidRequest }
        clientKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: clientPrivate)
        winn3Key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: winn3Private)
    }

    var clientPublicKey: String { clientKey.publicKey.rawRepresentation.base64EncodedString() }
    var winn3PublicKey: String { winn3Key.publicKey.rawRepresentation.base64EncodedString() }
}

// Construct only from the document actually shown and accepted by the user.
// This helper neither supplies acceptance nor writes an acceptance record.
struct SafariLegalAcceptance {
    let version: String
    let hash: String
    let privacyVersion: String
    let privacyURL: String
    let displayHash: String?

    init(version: String, hash: String, privacyVersion: String, privacyURL: String) {
        self.version = version
        self.hash = hash
        self.privacyVersion = privacyVersion
        self.privacyURL = privacyURL
        displayHash = nil
    }

    // The signed app's exact bundled document leaves the server hash empty;
    // that lets the hub record its canonical document hash. This distinct
    // digest binds what was displayed and must be persisted by the caller.
    static func bundled(displayedBody: String, privacyVersion: String,
                        privacyURL: String) throws -> SafariLegalAcceptance {
        let digest = SHA256.hash(data: Data(displayedBody.utf8)).map { String(format: "%02x", $0) }.joined()
        guard digest == bundledDisplayHash, privacyVersion == bundledVersion else {
            throw SafariSessionError.invalidRequest
        }
        return SafariLegalAcceptance(privacyVersion: privacyVersion, privacyURL: privacyURL)
    }

    private init(privacyVersion: String, privacyURL: String) {
        version = Self.bundledLegalVersion
        hash = ""
        self.privacyVersion = privacyVersion
        self.privacyURL = privacyURL
        displayHash = Self.bundledDisplayHash
    }

    private static let bundledVersion = "2026-10-04.v5"
    // The hub's legal version (LEGAL_DOCUMENT_VERSION), distinct from the
    // privacy-policy version above: the hub answers 409 to any other value.
    private static let bundledLegalVersion = "2026-08-31.v4"
    private static let bundledDisplayHash = "52c21408988ae08e29ff1c06a2b6b661be3c2447b19ed02de702f46a46ce3ab8"

    fileprivate func fields() throws -> [String: Any] {
        let liveHash = SafariSessionValidation.matches(hash, "^[0-9a-fA-F]{64}$")
        let exactBundle = hash.isEmpty && version == Self.bundledLegalVersion && displayHash == Self.bundledDisplayHash
        guard !version.isEmpty, liveHash || exactBundle,
              !privacyVersion.isEmpty, let url = URL(string: privacyURL),
              url.scheme == "https", url.host != nil else {
            throw SafariSessionError.invalidRequest
        }
        return ["legal_version": version, "legal_hash": hash,
                "accepted_terms": true, "accepted_hold_harmless": true,
                "accepted_limitation_liability": true, "accepted_electronic_records": true,
                "accepted_privacy_policy": true, "privacy_policy_version": privacyVersion,
                "privacy_policy_url": privacyURL, "acceptance_method": "clickwrap"]
    }
}

struct SafariFreeSessionRequest {
    let installID: String
    let deviceModel: String
    let platform: String
    let appVersion: String
    let locale: String
    let location: String
    let legal: SafariLegalAcceptance

    func body(identity: SafariClientIdentity) throws -> Data {
        guard [installID, deviceModel, appVersion, locale].allSatisfy({
            !$0.isEmpty && $0.utf8.count <= 256 && !$0.unicodeScalars.contains(where: { $0.value < 32 })
        }), ["macos", "ios"].contains(platform),
        location == "auto" || SafariSessionValidation.node(location) != nil else {
            throw SafariSessionError.invalidRequest
        }
        var fields = try legal.fields()
        fields.merge([
            "device_id": installID, "device_fingerprint": installID,
            "device_model": deviceModel, "platform": platform,
            "app_version": appVersion, "locale": locale, "location": location,
            "stealth_mode": false, "double_vpn": false, "double_vpn_enabled": false,
            "client_public_key": identity.clientPublicKey,
            "winn3_static_public": identity.winn3PublicKey,
            "supports_awg": false, "supports_xray": false,
            "supports_split_tunnel": false, "supports_per_app_split_tunnel": false,
            "supports_winn3": true, "supports_winn3_descriptor": true,
            "supports_winn3_client_key": true, "supports_winn3_spa": false,
            // WinnTunnelCreateWinn3 consumes both exact attestation keys.
            // Call acquisition only after the containing host verifies its ABI.
            "supports_winn3_dualauth": true
        ]) { _, new in new }
        return try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    }
}

struct SafariHubResponse {
    let status: Int
    let body: Data
}

protocol SafariHubTransport {
    func send(_ request: URLRequest) async throws -> SafariHubResponse
}

struct SafariVerifiedDescriptor {
    let node: String
    let endpoint: String
    let routerV4: String
    let resolverV4: String
    let gatewayStatic: String
    let gatewayID: String
    let admissionKey: String
    let authEd25519: String?
    let authMLDSA65: String?
    let expiresAt: Date
}

struct SafariVerifiedSession {
    let innerV4: String
    let innerV6 = ""
    var resolverV4: String { descriptor.resolverV4 }
    var expiresAt: Date { descriptor.expiresAt }
    let descriptor: SafariVerifiedDescriptor
    private let staticPrivate: String
    private let pathMTU: Int
    private let carrierClasses: [String]
    private let sessionID: String
    private let psk: String?

    fileprivate init(innerV4: String, descriptor: SafariVerifiedDescriptor,
                     identity: SafariClientIdentity, pathMTU: Int,
                     carrierClasses: [String], sessionID: String, psk: String?) {
        self.innerV4 = innerV4
        self.descriptor = descriptor
        staticPrivate = identity.winn3Key.rawRepresentation.base64EncodedString()
        self.pathMTU = pathMTU
        self.carrierClasses = carrierClasses
        self.sessionID = sessionID
        self.psk = psk
    }

    // Successful validation is permission to attempt the engine handshake only.
    // The provider must separately prove carrying state and protected DNS.
    func engineCreateJSON(now: Date = Date()) throws -> Data {
        guard now < expiresAt else { throw SafariSessionError.descriptorLifetime }
        var document: [String: Any] = [
            "contract": "winn-datapath/1+winn3", "payload": "ip-packet", "carrier": "winn3",
            "gateway_endpoint": descriptor.endpoint, "static_private": staticPrivate,
            "gateway_static": descriptor.gatewayStatic, "gateway_id": descriptor.gatewayID,
            "admission_key": descriptor.admissionKey, "inner_v4": innerV4,
            "inner_router_v4": descriptor.routerV4, "path_mtu": pathMTU,
            "carrier_classes": carrierClasses, "session_id": sessionID,
            "allow_own_socket": true
        ]
        if let psk { document["psk"] = psk }
        if let ed = descriptor.authEd25519, let ml = descriptor.authMLDSA65 {
            document["auth_ed25519"] = ed
            document["auth_mldsa65"] = ml
        }
        return try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys])
    }
}

struct SafariDescriptorVerifier {
    private let keys: [String: Curve25519.Signing.PublicKey]

    init(publicKeys: [String: Data], expectedIdentity: String) throws {
        guard !publicKeys.isEmpty, Set(publicKeys.keys).isSubset(of: ["g1", "g2", "g3"]) else {
            throw SafariSessionError.descriptorRing
        }
        let canonical = publicKeys.keys.sorted().map { slot in
            slot + "=" + publicKeys[slot]!.map { String(format: "%02x", $0) }.joined() + "\n"
        }.joined()
        let digest = SHA256.hash(data: Data(canonical.utf8)).map { String(format: "%02x", $0) }.joined()
        guard digest == expectedIdentity else { throw SafariSessionError.descriptorRing }
        keys = try publicKeys.mapValues { try Curve25519.Signing.PublicKey(rawRepresentation: $0) }
    }

    static var production: SafariDescriptorVerifier {
        get throws {
            try SafariDescriptorVerifier(publicKeys: [
                "g1": Data(base64Encoded: "L2mAYdYIXPCFuNoH5ntgBBubFSnnlzIAnXwKttpehaQ=")!,
                "g2": Data(base64Encoded: "eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=")!,
                "g3": Data(base64Encoded: "53JhsQBxKH5DG145LcaBunOX4lbt+J7Js0oPyJnj9Q0=")!
            ], expectedIdentity: "52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032")
        }
    }

    func verify(_ envelope: [String: Any], now: Date) throws -> SafariVerifiedDescriptor {
        guard let p = envelope["payload"] as? String, p.utf8.count <= 8192,
              let s = envelope["sig"] as? String, s.utf8.count <= 256,
              let payload = Data(base64Encoded: p), payload.count <= 4096,
              let signature = Data(base64Encoded: s), signature.count == 64,
              SafariSessionValidation.depth(payload) <= 8,
              !SafariSessionValidation.hasDuplicateObjectKeys(payload),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let kid = object["kid"] as? String, let key = keys[kid] else {
            throw SafariSessionError.descriptorMissing
        }
        let message = Data("winsvpn-winn3-descriptor/v1\0".utf8) + payload
        guard key.isValidSignature(signature, for: message) else { throw SafariSessionError.descriptorSignature }
        let required: Set<String> = ["admission_gen", "admission_secret", "alg", "bucket_window_s",
            "endpoint", "gateway_id", "iat", "inner_resolver_v4", "inner_router_v4", "kid",
            "max_skew_s", "node", "not_after", "padding", "seq", "static_pub", "tag_size", "v"]
        let allowed = required.union(["auth_ed25519", "auth_mldsa65"])
        guard required.isSubset(of: Set(object.keys)), Set(object.keys).isSubset(of: allowed),
              SafariSessionValidation.integer(object["v"]) == 3,
              object["alg"] as? String == "ed25519",
              SafariSessionValidation.integer(object["tag_size"]) == 32,
              object["padding"] as? String == "bucket",
              SafariSessionValidation.integer(object["bucket_window_s"]) == 10,
              SafariSessionValidation.integer(object["max_skew_s"]) == 60,
              let sequence = SafariSessionValidation.integer(object["seq"]), sequence > 0,
              let generation = SafariSessionValidation.integer(object["admission_gen"]), generation > 0 else {
            throw SafariSessionError.descriptorSchema
        }
        guard let issued = SafariSessionValidation.integer(object["iat"]),
              let expires = SafariSessionValidation.integer(object["not_after"]),
              expires > issued, !expires.subtractingReportingOverflow(issued).overflow,
              expires.subtractingReportingOverflow(issued).partialValue >= 3600,
              expires.subtractingReportingOverflow(issued).partialValue <= 30 * 24 * 3600,
              now.timeIntervalSince1970 >= Double(issued), now.timeIntervalSince1970 < Double(expires) else {
            throw SafariSessionError.descriptorLifetime
        }
        guard let node = SafariSessionValidation.node(object["node"]) else { throw SafariSessionError.descriptorNode }
        guard let endpoint = object["endpoint"] as? String, SafariSessionValidation.endpoint(endpoint),
              let router = object["inner_router_v4"] as? String, SafariSessionValidation.innerIPv4(router),
              let resolver = object["inner_resolver_v4"] as? String, resolver == router else {
            throw SafariSessionError.descriptorAddress
        }
        guard let pub = object["static_pub"] as? String, SafariSessionValidation.base64(pub, length: 32) != nil,
              let id = object["gateway_id"] as? String, let idData = Data(base64Encoded: id),
              !idData.isEmpty, idData.count <= 255, let idText = String(data: idData, encoding: .utf8),
              idText == idText.trimmingCharacters(in: .whitespacesAndNewlines),
              let admission = object["admission_secret"] as? String,
              let admissionBytes = Data(base64Encoded: admission), admissionBytes.count >= 32,
              !SafariSessionValidation.edgeWhitespace(admissionBytes) else {
            throw SafariSessionError.descriptorMaterial
        }
        guard (object["auth_ed25519"] == nil || object["auth_ed25519"] is String),
              (object["auth_mldsa65"] == nil || object["auth_mldsa65"] is String) else {
            throw SafariSessionError.descriptorMaterial
        }
        let ed = object["auth_ed25519"] as? String ?? ""
        let ml = object["auth_mldsa65"] as? String ?? ""
        guard (ed.isEmpty && ml.isEmpty) ||
                (SafariSessionValidation.base64(ed, length: 32) != nil &&
                 SafariSessionValidation.base64(ml, length: 1952) != nil) else {
            throw SafariSessionError.descriptorMaterial
        }
        return SafariVerifiedDescriptor(node: node, endpoint: endpoint, routerV4: router,
            resolverV4: resolver, gatewayStatic: pub, gatewayID: idText,
            admissionKey: admission, authEd25519: ed.isEmpty ? nil : ed,
            authMLDSA65: ml.isEmpty ? nil : ml,
            expiresAt: Date(timeIntervalSince1970: Double(expires)))
    }
}

struct SafariHubSessionClient {
    let transport: SafariHubTransport
    let verifier: SafariDescriptorVerifier

    init(transport: SafariHubTransport = SafariPinnedHubTransport(),
         verifier: SafariDescriptorVerifier? = nil) throws {
        self.transport = transport
        self.verifier = try verifier ?? SafariDescriptorVerifier.production
    }

    func acquire(_ request: SafariFreeSessionRequest, identity: SafariClientIdentity,
                 origin: URL, deviceToken: String? = nil) async throws -> SafariVerifiedSession {
        guard SafariPinnedHubTransport.allowedOrigin(origin) else { throw SafariSessionError.invalidOrigin }
        var http = URLRequest(url: origin.appendingPathComponent("free/verify"), timeoutInterval: 10)
        http.httpMethod = "POST"
        http.setValue("application/json", forHTTPHeaderField: "Content-Type")
        http.setValue("application/json", forHTTPHeaderField: "Accept")
        if let deviceToken, !deviceToken.isEmpty {
            guard deviceToken.utf8.count <= 4096, !deviceToken.contains("\r"),
                  !deviceToken.contains("\n") else { throw SafariSessionError.invalidRequest }
            http.setValue("Bearer " + deviceToken, forHTTPHeaderField: "Authorization")
        }
        http.httpBody = try request.body(identity: identity)
        let reply = try await transport.send(http)
        try Task.checkCancellation()
        return try validate(reply, request: request, identity: identity, now: Date())
    }

    func validate(_ reply: SafariHubResponse, request: SafariFreeSessionRequest,
                  identity: SafariClientIdentity, now: Date) throws -> SafariVerifiedSession {
        guard reply.body.count <= 262144, SafariSessionValidation.depth(reply.body) <= 16 else {
            throw SafariSessionError.responseTooLarge
        }
        if reply.status == 429 { throw SafariSessionError.rateLimited }
        if reply.status == 503 { throw SafariSessionError.freeUnavailable }
        guard reply.status == 200,
              !SafariSessionValidation.hasDuplicateObjectKeys(reply.body),
              let object = try? JSONSerialization.jsonObject(with: reply.body) as? [String: Any],
              object["status"] as? String == "authenticated",
              let config = (object["vpn_config"] ?? object["vpnconfig"]) as? [String: Any] else {
            throw SafariSessionError.unauthenticated
        }
        let client = try SafariSessionValidation.alias(config, ["client_public_key", "clientpublickey"])
        let winn = try SafariSessionValidation.alias(config, ["winn3_static_public", "winn3staticpublic"])
        guard (client.isEmpty || client == identity.clientPublicKey), winn == identity.winn3PublicKey else {
            throw SafariSessionError.identityMismatch
        }
        guard try SafariSessionValidation.alias(config, ["winn3_static_private", "winn3staticprivate"]).isEmpty else {
            throw SafariSessionError.servedPrivateKey
        }
        let version = try SafariSessionValidation.alias(config, ["protocol_version", "protocolversion"])
        guard version == "winn/3", config["stealth_active"] as? Bool != true,
              let parameters = config["protocol_params"] as? [String: Any],
              parameters["carrier"] as? String == "winn3",
              Set(parameters.keys).isSubset(of: ["carrier", "session_id", "gateway_endpoint", "max_datagram"]) else {
            throw SafariSessionError.unsupportedProtocol
        }
        guard let envelope = (config["winn3_descriptor"] ?? config["winn3descriptor"]) as? [String: Any] else {
            throw SafariSessionError.descriptorMissing
        }
        let descriptor = try verifier.verify(envelope, now: now)
        guard SafariSessionValidation.selectedNode(config) == descriptor.node,
              request.location == "auto" || SafariSessionValidation.node(request.location) == descriptor.node else {
            throw SafariSessionError.descriptorNode
        }
        let inner = try SafariSessionValidation.alias(config, ["winn3_inner_v4", "winn3innerv4"])
        let plan = try SafariSessionValidation.alias(config, ["winn3_carrier_classes", "winn3carrierclasses"])
        let mtu = try SafariSessionValidation.alias(config, ["winn3_path_mtu", "winn3pathmtu"])
        // Current C ABI refuses an absent migration plan. Zero MTU lets the
        // engine select carrier.DefaultPathMTU, matching the PacketTunnel path.
        let classes = plan.split(separator: ",", omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        let pathMTU = mtu.isEmpty ? 0 : Int(mtu)
        let sessionID = parameters["session_id"] as? String ?? ""
        guard SafariSessionValidation.innerIPv4(inner),
              SafariSessionValidation.innerResolver(descriptor.resolverV4, assignment: inner),
              let pathMTU, pathMTU == 0 || (1280...65535).contains(pathMTU),
              classes.contains("udp"),
              classes.allSatisfy({ ["udp", "tcp", "tls"].contains($0) }),
              sessionID.utf8.count <= 128 else { throw SafariSessionError.invalidConfiguration }
        let rawPSK = try SafariSessionValidation.alias(config, ["winn3_psk", "winn3psk"])
        guard rawPSK.isEmpty || SafariSessionValidation.base64(rawPSK, length: 32) != nil else {
            throw SafariSessionError.invalidConfiguration
        }
        return SafariVerifiedSession(innerV4: inner, descriptor: descriptor, identity: identity,
            pathMTU: pathMTU, carrierClasses: classes, sessionID: sessionID,
            psk: rawPSK.isEmpty ? nil : rawPSK)
    }
}

enum SafariSessionValidation {
    static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }

    static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !["f", "d"].contains(String(cString: number.objCType)) else { return nil }
        return Int64(number.stringValue)
    }

    static func node(_ value: Any?) -> String? {
        guard let raw = value as? String, raw.utf8.allSatisfy({ $0 < 128 }) else { return nil }
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return matches(normalized, "^[a-z0-9][a-z0-9-]{1,39}$") ? normalized : nil
    }

    static func selectedNode(_ config: [String: Any]) -> String? {
        var found: String?
        for key in ["node_slug", "nodeslug", "location_slug", "locationslug", "selected_node", "selectednode"] {
            guard let value = config[key], !(value is NSNull) else { continue }
            let candidate: String?
            if let nested = value as? [String: Any] {
                var nestedFound: String?
                for child in ["slug", "node_slug", "nodeslug", "location_slug", "locationslug"] {
                    guard let raw = nested[child], !(raw is NSNull) else { continue }
                    guard let next = node(raw), nestedFound == nil || nestedFound == next else { return nil }
                    nestedFound = next
                }
                candidate = nestedFound
            } else if let string = value as? String, string.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                continue
            } else { candidate = node(value) }
            guard let candidate, found == nil || found == candidate else { return nil }
            found = candidate
        }
        return found
    }

    static func alias(_ object: [String: Any], _ keys: [String]) throws -> String {
        var found: String?
        for key in keys {
            guard let raw = object[key], !(raw is NSNull) else { continue }
            let string: String
            if let text = raw as? String { string = text.trimmingCharacters(in: .whitespacesAndNewlines) }
            else if let n = integer(raw) { string = String(n) }
            else { throw SafariSessionError.invalidConfiguration }
            if string.isEmpty { continue }
            guard found == nil || found == string else { throw SafariSessionError.invalidConfiguration }
            found = string
        }
        return found ?? ""
    }

    static func base64(_ text: String, length: Int) -> Data? {
        guard let data = Data(base64Encoded: text), data.count == length,
              data.base64EncodedString() == text else { return nil }
        return data
    }

    static func innerIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts.allSatisfy({
            !$0.isEmpty && $0.count <= 3 && $0.utf8.allSatisfy({ (48...57).contains($0) }) &&
                !($0.count > 1 && $0.first == "0") && (Int($0) ?? 256) <= 255
        }), let first = Int(parts[0]) else { return false }
        return first != 0 && first != 127 && first < 224
    }

    static func endpoint(_ value: String) -> Bool {
        // The current Apple socket/exclusion contract supports numeric IPv4.
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count == 2 && innerIPv4(String(parts[0])) &&
            parts[1].utf8.allSatisfy({ (48...57).contains($0) }) &&
            (1...65535).contains(Int(parts[1]) ?? 0)
    }

    static func innerResolver(_ resolver: String, assignment: String) -> Bool {
        guard innerIPv4(resolver), innerIPv4(assignment), resolver != assignment else { return false }
        let r = resolver.split(separator: ".").compactMap { Int($0) }
        let a = assignment.split(separator: ".").compactMap { Int($0) }
        let nonpublic = r[0] == 10 || (r[0] == 100 && (64...127).contains(r[1])) ||
            (r[0] == 169 && r[1] == 254) || (r[0] == 172 && (16...31).contains(r[1])) ||
            (r[0] == 192 && r[1] == 168)
        return nonpublic && r.prefix(3).elementsEqual(a.prefix(3))
    }

    static func edgeWhitespace(_ data: Data) -> Bool {
        let ws: Set<UInt8> = [9, 10, 11, 12, 13, 32]
        return data.first.map(ws.contains) == true || data.last.map(ws.contains) == true
    }

    static func depth(_ data: Data) -> Int {
        var depth = 0, maximum = 0
        var quoted = false, escaped = false
        for b in data {
            if quoted {
                if escaped { escaped = false }
                else if b == 92 { escaped = true }
                else if b == 34 { quoted = false }
            } else if b == 34 { quoted = true }
            else if b == 123 || b == 91 { depth += 1; maximum = max(maximum, depth) }
            else if b == 125 || b == 93 { depth -= 1 }
        }
        return maximum
    }

    // JSONSerialization and Dart's decoder select the last duplicate member.
    // Reject ambiguity before either the signed payload or hub reply is used.
    static func hasDuplicateObjectKeys(_ data: Data) -> Bool {
        let bytes = Array(data)
        var stack: [Set<String>?] = []
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if byte == 123 { stack.append(Set<String>()) }
            else if byte == 91 { stack.append(nil) }
            else if byte == 125 || byte == 93 {
                if !stack.isEmpty { stack.removeLast() }
            } else if byte == 34 {
                let start = index
                index += 1
                var escaped = false
                while index < bytes.count {
                    let current = bytes[index]
                    if escaped { escaped = false }
                    else if current == 92 { escaped = true }
                    else if current == 34 { break }
                    index += 1
                }
                guard index < bytes.count else { return false }
                var after = index + 1
                while after < bytes.count && [9, 10, 13, 32].contains(bytes[after]) { after += 1 }
                if after < bytes.count, bytes[after] == 58, !stack.isEmpty,
                   var keys = stack[stack.count - 1],
                   let key = try? JSONSerialization.jsonObject(with: Data(bytes[start...index]),
                                                               options: [.fragmentsAllowed]) as? String {
                    if keys.contains(key) { return true }
                    keys.insert(key)
                    stack[stack.count - 1] = keys
                }
            }
            index += 1
        }
        return false
    }
}
