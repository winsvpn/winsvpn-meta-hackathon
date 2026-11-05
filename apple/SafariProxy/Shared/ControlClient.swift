import Foundation
import NetworkExtension

final class SafariControlClient {
    static func status(completion: @escaping (SafariProviderStatus?) -> Void) {
        #if os(macOS)
        let once = SafariSingleReply(completion)
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { once.finish(nil) }
        guard let identifier = Bundle.main.object(
            forInfoDictionaryKey: "SafariProxySystemExtensionIdentifier"
        ) as? String, !identifier.contains("$("),
              let key = try? SafariControlKeychain.read() else { once.finish(nil); return }
        let nonce = UUID().uuidString
        let now = Int64(Date().timeIntervalSince1970)
        let request = SafariControlMessage(version: 1, kind: "status", nonce: nonce, issuedAt: now, status: nil)
        guard let payload = try? SafariControlProtocol.encode(request, key: key) else {
            once.finish(nil); return
        }
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            guard error == nil else { once.finish(nil); return }
            let matches = (managers ?? []).filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == identifier
            }
            guard matches.count == 1, let manager = matches.first,
                  manager.isEnabled, manager.connection.status == .connected,
                  let session = manager.connection as? NETunnelProviderSession else {
                once.finish(nil); return
            }
            do {
                try session.sendProviderMessage(payload) { response in
                    guard let response,
                          let message = try? SafariControlProtocol.decode(
                            response, key: key, now: Int64(Date().timeIntervalSince1970)
                          ), message.kind == "status_reply", message.nonce == nonce else {
                        once.finish(nil); return
                    }
                    once.finish(message.status)
                }
            } catch { once.finish(nil) }
        }
        #else
        // NETransparentProxyProvider is explicitly unavailable in the iOS SDK.
        completion(nil)
        #endif
    }
}

private final class SafariSingleReply {
    private let lock = NSLock()
    private var completion: ((SafariProviderStatus?) -> Void)?

    init(_ completion: @escaping (SafariProviderStatus?) -> Void) { self.completion = completion }

    func finish(_ status: SafariProviderStatus?) {
        lock.lock()
        let callback = completion
        completion = nil
        lock.unlock()
        callback?(status)
    }
}
