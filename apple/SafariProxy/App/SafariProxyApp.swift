#if os(macOS)
import AppKit

@main
final class SafariProxyApp: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var activation: SafariProxyActivation?
    private let connection = SafariConnection()
    private var connecting = false
    private var disconnecting = false
    private var connectionTask: Task<Void, Never>?
    private var operation = UUID()
    private var statusTimer: Timer?
    private let detail = NSTextField(wrappingLabelWithString:
        "Disconnected. Safari traffic is not protected.")

    static func main() {
        let app = NSApplication.shared
        let delegate = SafariProxyApp()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
        withExtendedLifetime(delegate) {}
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 580, height: 400),
            styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Win's VPN Safari Proxy"
        let title = NSTextField(labelWithString: window.title)
        title.font = .boldSystemFont(ofSize: 22)
        let explanation = NSTextField(wrappingLabelWithString:
            "Approve the native extension, then connect using free access. Safari traffic and system DNS use Win's VPN while connected. The full VPN app is not required. Other apps keep their existing traffic routes. Enabling protected DNS replaces any other active DNS proxy.")
        let check = NSButton(title: "Check native status", target: self, action: #selector(checkStatus))
        let approve = NSButton(title: "Request system extension approval", target: self, action: #selector(requestApproval))
        let connect = NSButton(title: "Connect free", target: self, action: #selector(connectFree))
        let disconnect = NSButton(title: "Disconnect", target: self, action: #selector(disconnectProxy))
        let stack = NSStackView(views: [title, detail, explanation, approve, connect, disconnect, check])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView?.addSubview(stack)
        if let content = window.contentView {
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
                stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
                stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            ])
        }
        self.window = window
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        statusTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            if self?.connecting == false { self?.checkStatus() }
        }
    }

    @objc private func checkStatus() {
        let current = operation
        SafariControlClient.status { status in
            DispatchQueue.main.async {
                guard self.operation == current, !self.connecting else { return }
                self.detail.stringValue = status?.routing == true
                    ? "Connected. Safari routing and protected system DNS are active."
                    : "Protection is not ready. Safari traffic is not confirmed protected."
            }
        }
    }

    @objc private func requestApproval() {
        do {
            try SafariControlKeychain.prepare()
            let request = try SafariProxyActivation()
            activation = request
            try request.activate()
            detail.stringValue = "Approval requested. After macOS approves the extension, select Connect free."
        } catch {
            detail.stringValue = "Component approval could not start. A signed app with the required entitlements is needed."
        }
    }

    @objc private func connectFree() {
        guard !connecting else { return }
        do {
            let document = try SafariConnection.legalDocument()
            guard let body = document["body"], let privacy = document["privacy"],
                  let privacyVersion = document["privacyVersion"], let privacyURL = document["privacyURL"] else {
                throw SafariForwardError.invalid
            }
            let alert = NSAlert()
            alert.messageText = "Terms and privacy"
            alert.informativeText = "Read the terms and privacy policy below. Agreeing accepts the terms, hold-harmless provisions, limitation of liability, electronic records and privacy policy. It also enables Safari routing and system DNS protection."
            alert.addButton(withTitle: "Agree and connect")
            alert.addButton(withTitle: "Cancel")
            let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 600, height: 360))
            scroll.hasVerticalScroller = true
            let text = NSTextView(frame: scroll.bounds)
            text.isEditable = false; text.isSelectable = true
            text.isVerticallyResizable = true; text.isHorizontallyResizable = false
            text.autoresizingMask = [.width]
            text.textContainer?.widthTracksTextView = true
            text.string = body + "\n\nPrivacy Policy\n\n" + privacy
            scroll.documentView = text; alert.accessoryView = scroll
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            let legal = try SafariLegalAcceptance.bundled(displayedBody: body,
                privacyVersion: privacyVersion, privacyURL: privacyURL)
            connecting = true; detail.stringValue = "Connecting free access and protected DNS..."
            operation = UUID(); let current = operation
            connectionTask = Task {
                do {
                    try await connection.connect(legal: legal)
                    await MainActor.run {
                        guard self.operation == current else { return }
                        self.connecting = false; self.connectionTask = nil; self.checkStatus()
                    }
                } catch {
                    await MainActor.run {
                        guard self.operation == current else { return }
                        self.connecting = false
                        self.connectionTask = nil
                        self.detail.stringValue = "Connection failed. Check native approval and try again. Safari protection is not confirmed."
                    }
                }
            }
        } catch { detail.stringValue = "The bundled consent document is unavailable. Connection did not start." }
    }

    @objc private func disconnectProxy() {
        guard !disconnecting else { return }
        disconnecting = true
        let pending = connectionTask
        pending?.cancel(); connectionTask = nil; operation = UUID()
        let current = operation
        connecting = true
        connectionTask = Task {
            await pending?.value
            do {
                try await connection.disconnect()
                await MainActor.run {
                    guard self.operation == current else { return }
                    self.connecting = false; self.disconnecting = false; self.connectionTask = nil
                    self.detail.stringValue = "Disconnect requested. Check native status for the current state."
                }
            } catch {
                await MainActor.run {
                    guard self.operation == current else { return }
                    self.connecting = false; self.disconnecting = false; self.connectionTask = nil
                    self.detail.stringValue = "Disconnect could not finish. Check macOS network settings."
                }
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
#else
import UIKit

@main
final class SafariProxyApp: UIResponder, UIApplicationDelegate {
    static func main() {
        UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(SafariProxyApp.self))
    }

    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "SafariProxy", sessionRole: session.role)
        configuration.delegateClass = SafariProxySceneDelegate.self
        return configuration
    }
}

final class SafariProxySceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: scene)
        let controller = UIViewController()
        controller.view.backgroundColor = .systemBackground
        let title = UILabel()
        title.text = "Win's VPN Safari Proxy"
        title.font = .preferredFont(forTextStyle: .title1)
        title.numberOfLines = 0
        let detail = UILabel()
        detail.text = "This iOS package contains the Safari extension only and does not protect traffic. Winn v3 routing on iOS needs a packet tunnel and a VPN configuration approved by you. A separate lightweight app can provide that without the full VPN app."
        detail.numberOfLines = 0
        detail.font = .preferredFont(forTextStyle: .body)
        let stack = UIStackView(arrangedSubviews: [title, detail])
        stack.axis = .vertical
        stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        controller.view.addSubview(stack)
        let safe = controller.view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: safe.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: safe.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: safe.topAnchor, constant: 32),
        ])
        window.rootViewController = controller
        self.window = window
        window.makeKeyAndVisible()
    }
}
#endif
