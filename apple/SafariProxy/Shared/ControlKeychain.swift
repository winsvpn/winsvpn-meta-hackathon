import Foundation
import Security
import LocalAuthentication

// A separate access group prevents the full VPN app from becoming a dependency.
enum SafariControlKeychain {
    private static func query(bundle: Bundle) throws -> [String: Any] {
        guard let group = bundle.object(forInfoDictionaryKey: "SafariProxyKeychainAccessGroup") as? String,
              !group.isEmpty, !group.contains("$("), !group.contains("${") else {
            throw SafariControlError.unavailable
        }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "SafariProxyControl",
            kSecAttrAccount as String: "native-control-v1",
            kSecAttrAccessGroup as String: group,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
    }

    static func read(bundle: Bundle = .main) throws -> Data {
        var attributes = try query(bundle: bundle)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext()
        context.interactionNotAllowed = true
        attributes[kSecUseAuthenticationContext as String] = context
        var item: CFTypeRef?
        guard SecItemCopyMatching(attributes as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, data.count == 32 else {
            throw SafariControlError.unavailable
        }
        return data
    }

    // Called only by the containing app following an explicit local UI action.
    static func prepare(bundle: Bundle = .main) throws {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SafariControlError.unavailable
        }
        defer { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var attributes = try query(bundle: bundle)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        attributes[kSecValueData as String] = Data(bytes)
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw SafariControlError.unavailable
        }
        _ = try read(bundle: bundle)
    }
}
