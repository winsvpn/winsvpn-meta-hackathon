import SafariServices

// Safari delivers messages only to its own app extension. The native status
// query adds authentication between this handler and the dedicated provider.
// No endpoint, credential, account or browsing data is returned to JavaScript.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        guard context.inputItems.count == 1,
              let item = context.inputItems.first as? NSExtensionItem,
              SafariControlProtocol.isCapabilityProbe(item.userInfo?[SFExtensionMessageKey]) else {
            reply(context, payload: ["v": 1, "type": "error", "routing": false, "reason": "invalid_request"])
            return
        }
        SafariControlClient.status { status in
            // JavaScript has no proxy control. The native app owns routing;
            // its authenticated readiness is reported separately.
            #if os(macOS)
            let platform = "macos"
            #else
            let platform = "ios"
            #endif
            self.reply(context, payload: [
                "v": 1, "type": "capability", "routing": false,
                "reason": "native_app_managed", "platform": platform,
                "nativeAuthenticated": status != nil,
                "nativeRouting": status?.routing == true,
            ])
        }
    }

    private func reply(_ context: NSExtensionContext, payload: [String: Any]) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: payload]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }
}
