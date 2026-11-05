#if os(macOS)
import Foundation
import NetworkExtension
import CryptoKit

final class SafariConnection {
    private var manager: NETransparentProxyManager?

    static func legalDocument() throws -> [String: String] {
        guard let url = Bundle.main.url(forResource: "Legal", withExtension: "plist"),
              let value = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil) as? [String: String]
        else { throw SafariForwardError.unavailable }
        return value
    }

    func connect(legal: SafariLegalAcceptance) async throws {
        let existing: [NETransparentProxyManager] = try await withCheckedThrowingContinuation { c in
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                if let error { c.resume(throwing: error) } else { c.resume(returning: managers ?? []) }
            }
        }
        let identifier = Bundle.main.object(forInfoDictionaryKey: "SafariProxySystemExtensionIdentifier") as? String
        guard !existing.contains(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == identifier &&
                $0.connection.status != .disconnected && $0.connection.status != .invalid
        }) else { throw SafariForwardError.invalid }
        try Task.checkCancellation()
        try SafariControlKeychain.prepare()
        try SafariSessionStore.prepareBrokerKey()
        let acceptance = ["version": legal.version, "display_hash": legal.displayHash,
            "accepted_at": ISO8601DateFormatter().string(from: Date())]
        try SafariSessionStore.write(JSONEncoder().encode(acceptance), account: "legal-acceptance-v1")
        let identity: SafariClientIdentity
        let stored = try SafariSessionStore.optionalRead("identity-v1")
        if let stored {
            guard stored.count == 64 else { throw SafariForwardError.invalid }
            identity = try SafariClientIdentity(clientPrivate: Data(stored.prefix(32)), winn3Private: Data(stored.suffix(32)))
        } else {
            identity = SafariClientIdentity()
            try SafariSessionStore.write(identity.clientKey.rawRepresentation + identity.winn3Key.rawRepresentation, account: "identity-v1")
        }
        let installID: String
        if let saved = try SafariSessionStore.optionalRead("install-id-v1") {
            guard let id = String(data: saved, encoding: .utf8), UUID(uuidString: id) != nil else { throw SafariForwardError.invalid }
            installID = id
        } else {
            installID = UUID().uuidString
            try SafariSessionStore.write(Data(installID.utf8), account: "install-id-v1")
        }
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let request = SafariFreeSessionRequest(installID: installID, deviceModel: "Mac", platform: "macos",
            appVersion: version, locale: Locale.current.identifier, location: "auto", legal: legal)
        let verified = try await SafariHubSessionClient().acquire(request, identity: identity,
            origin: SafariPinnedHubTransport.defaultOrigin)
        try Task.checkCancellation()
        let storedSession = SafariStoredSession(document: try verified.engineCreateJSON(), innerV4: verified.innerV4,
            innerV6: verified.innerV6, resolver: verified.resolverV4, expiresAt: verified.expiresAt)
        try SafariSessionStore.write(JSONEncoder().encode(storedSession), account: "active-v1")
        do { try await startProviders() }
        catch {
            manager?.connection.stopVPNTunnel()
            try SafariSessionStore.clearSession()
            throw error
        }
    }

    private func startProviders() async throws {
        guard let identifier = Bundle.main.object(forInfoDictionaryKey: "SafariProxySystemExtensionIdentifier") as? String,
              !identifier.contains("$(") else { throw SafariForwardError.invalid }
        let all: [NETransparentProxyManager] = try await withCheckedThrowingContinuation { continuation in
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: managers ?? []) }
            }
        }
        let matches = all.filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == identifier }
        try Task.checkCancellation()
        guard matches.count <= 1 else { throw SafariForwardError.invalid }
        let manager = matches.first ?? NETransparentProxyManager()
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else { throw SafariForwardError.invalid }
        let config = NETunnelProviderProtocol()
        config.providerBundleIdentifier = identifier
        config.serverAddress = "Standalone Safari proxy"
        manager.protocolConfiguration = config; manager.localizedDescription = "Win's VPN Safari Proxy"
        manager.isEnabled = true
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in if let error { c.resume(throwing: error) } else { c.resume() } }
        }
        try Task.checkCancellation()
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in if let error { c.resume(throwing: error) } else { c.resume() } }
        }
        self.manager = manager
        try Task.checkCancellation()
        try manager.connection.startVPNTunnel()
        do {
            let dns = NEDNSProxyManager.shared()
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                dns.loadFromPreferences { error in if let error { c.resume(throwing: error) } else { c.resume() } }
            }
            try Task.checkCancellation()
            let protocolConfig = NEDNSProxyProviderProtocol()
            protocolConfig.providerBundleIdentifier = identifier
            dns.providerProtocol = protocolConfig
            dns.localizedDescription = "Win's VPN Safari protected DNS"
            dns.isEnabled = true
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                dns.saveToPreferences { error in if let error { c.resume(throwing: error) } else { c.resume() } }
            }
            try Task.checkCancellation()
        } catch { manager.connection.stopVPNTunnel(); throw error }
    }

    func disconnect() async throws {
        guard let identifier = Bundle.main.object(forInfoDictionaryKey: "SafariProxySystemExtensionIdentifier") as? String,
              !identifier.contains("$(") else { throw SafariForwardError.invalid }
        var failure: Error?
        // Each cleanup path runs even if the other preference store fails.
        // stopVPNTunnel requests stop; the UI does not claim acknowledgement.
        manager?.connection.stopVPNTunnel()
        do {
            let managers: [NETransparentProxyManager] = try await withCheckedThrowingContinuation { c in
                NETransparentProxyManager.loadAllFromPreferences { managers, error in
                    if let error { c.resume(throwing: error) } else { c.resume(returning: managers ?? []) }
                }
            }
            for own in managers where (own.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == identifier {
                own.connection.stopVPNTunnel()
            }
        } catch { failure = error }
        do {
            let dns = NEDNSProxyManager.shared()
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                dns.loadFromPreferences { error in if let error { c.resume(throwing: error) } else { c.resume() } }
            }
            if dns.providerProtocol?.providerBundleIdentifier == identifier {
                dns.isEnabled = false
                try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                    dns.saveToPreferences { error in if let error { c.resume(throwing: error) } else { c.resume() } }
                }
            }
        } catch { failure = failure ?? error }
        do { try SafariSessionStore.clearSession() } catch { failure = failure ?? error }
        if let failure { throw failure }
    }

}
#endif
