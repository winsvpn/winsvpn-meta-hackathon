import Foundation
import Security
import LocalAuthentication

struct SafariStoredSession: Codable {
    let document: Data
    let innerV4: String
    let innerV6: String
    let resolver: String
    let expiresAt: Date
}

// Only the containing app and its network extension have this access group.
// The Safari Web Extension gets capability status, never session material.
enum SafariSessionStore {
    private static func attributes(_ account: String) throws -> [String: Any] {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "SafariProxySessionAccessGroup") as? String,
              !group.isEmpty, !group.contains("$("), !group.contains("${") else { throw SafariForwardError.unavailable }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "SafariProxySession",
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: group,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrSynchronizable as String: false]
    }

    static func read(_ account: String) throws -> Data {
        var query = try attributes(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext(); context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw SafariForwardError.missing }
        guard status == errSecSuccess,
              let data = result as? Data, data.count <= 131072 else { throw SafariForwardError.unavailable }
        return data
    }

    static func optionalRead(_ account: String) throws -> Data? {
        do { return try read(account) }
        catch SafariForwardError.missing { return nil }
    }

    static func clearSession() throws {
        let status = SecItemDelete(try attributes("active-v1") as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SafariForwardError.unavailable }
    }

    static func write(_ data: Data, account: String) throws {
        guard data.count <= 131072 else { throw SafariForwardError.invalid }
        let query = try attributes(account)
        let values: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            guard SecItemAdd(query.merging(values) { _, new in new } as CFDictionary, nil) == errSecSuccess else {
                throw SafariForwardError.unavailable
            }
        } else if status != errSecSuccess { throw SafariForwardError.unavailable }
    }

    static func load() throws -> SafariStoredSession {
        let session = try JSONDecoder().decode(SafariStoredSession.self, from: read("active-v1"))
        guard session.expiresAt > Date() else {
            try clearSession()
            throw SafariForwardError.unavailable
        }
        return session
    }

    static func brokerKey() throws -> Data {
        let key = try read("dns-broker-v1")
        guard key.count == 32 else { throw SafariForwardError.invalid }
        return key
    }

    static func prepareBrokerKey() throws {
        if let existing = try optionalRead("dns-broker-v1") {
            guard existing.count == 32 else { throw SafariForwardError.invalid }
            return
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw SafariForwardError.unavailable }
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        try write(Data(bytes), account: "dns-broker-v1")
    }

    // Port discovery contains no credential. Both sides authenticate every
    // request/response; a substituted port can only cause an unavailable state.
    static func brokerURL() throws -> URL {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "SafariProxyAppGroup") as? String,
              !group.contains("$("), !group.contains("${"),
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            throw SafariForwardError.unavailable
        }
        return container.appendingPathComponent("dns-broker-port-v1.json")
    }

    static func publish(port: UInt16) throws {
        try JSONEncoder().encode(port).write(to: brokerURL(), options: [.atomic])
    }

    // Best effort: once the broker no longer listens, the DNS proxy must stop
    // addressing the port, because any local process may bind it next.
    static func unpublish() {
        guard let url = try? brokerURL() else { return }
        try? FileManager.default.removeItem(at: url)
    }

    static func port() throws -> UInt16 {
        let data = try Data(contentsOf: brokerURL(), options: [.mappedIfSafe])
        guard data.count <= 8 else { throw SafariForwardError.invalid }
        let port = try JSONDecoder().decode(UInt16.self, from: data)
        guard port > 0 else { throw SafariForwardError.invalid }
        return port
    }
}
