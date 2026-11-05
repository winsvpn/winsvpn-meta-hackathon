import Foundation
import NetworkExtension

final class TransparentProxyProvider: NETransparentProxyProvider {
    private let replay = SafariReplayWindow()

    private let state = DispatchQueue(label: "SafariProxy.provider")
    private var runtime: SafariPacketRuntime?
    private var broker: SafariDNSBroker?
    private var timer: DispatchSourceTimer?
    private var generation = UUID()
    private var dnsUntil: UInt64 = 0
    private var capture = false
    private var installing = false
    private var startReply: ((Error?) -> Void)?
    private var flows: [UUID: SafariAppFlow] = [:]

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        state.async { [self] in
            guard runtime == nil else { completionHandler(SafariForwardError.invalid); return }
            generation = UUID(); let epoch = generation
            startReply = completionHandler
            do {
                let session = try SafariSessionStore.load()
                let instance = try SafariPacketRuntime(document: session.document, innerV4: session.innerV4,
                    innerV6: session.innerV6, resolver: session.resolver, expiresAt: session.expiresAt)
                runtime = instance
                instance.onFailure = { [weak self] in
                    self?.state.async { self?.failed(epoch) }
                }
                instance.start()
                let server = try SafariDNSBroker(key: SafariSessionStore.brokerKey(), query: { query, tcp, reply in
                    DispatchQueue.global().async {
                        do { reply(.success(try instance.dns(query, tcp: tcp))) }
                        catch { reply(.failure(error)) }
                    }
                }, readinessLease: { [weak self] reply in
                    guard let self else { reply(false); return }
                    self.state.async {
                        guard self.generation == epoch, instance.carrying else { reply(false); return }
                        self.dnsUntil = DispatchTime.now().uptimeNanoseconds + 6_000_000_000
                        self.installCapture(epoch)
                        reply(true)
                    }
                })
                broker = server
                server.start { [weak self] result in
                    self?.state.async {
                        guard let self, self.generation == epoch else { return }
                        do { try SafariSessionStore.publish(port: result.get()) }
                        catch { self.failed(epoch) }
                    }
                }
                let tick = DispatchSource.makeTimerSource(queue: state)
                tick.schedule(deadline: .now() + 1, repeating: 1)
                tick.setEventHandler { [weak self] in self?.checkHealth(epoch) }
                timer = tick; tick.resume()
                state.asyncAfter(deadline: .now() + 30) { [weak self] in
                    guard let self, self.generation == epoch, self.startReply != nil else { return }
                    self.failed(epoch)
                }
            } catch { failed(epoch) }
        }
    }

    private var ready: Bool {
        capture && runtime?.carrying == true && dnsUntil > DispatchTime.now().uptimeNanoseconds
    }

    private func installCapture(_ epoch: UUID) {
        guard generation == epoch, !capture, !installing else { return }
        installing = true
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
            localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)]
        setTunnelNetworkSettings(settings) { [weak self] error in
            self?.state.async {
                guard let self, self.generation == epoch else { return }
                self.installing = false
                guard error == nil else { self.failed(epoch); return }
                self.capture = true
                guard self.runtime?.carrying == true,
                      self.dnsUntil > DispatchTime.now().uptimeNanoseconds else { self.failed(epoch); return }
                let reply = self.startReply; self.startReply = nil
                reply?(nil)
                self.checkHealth(epoch)
            }
        }
    }

    private func checkHealth(_ epoch: UUID) {
        guard generation == epoch else { return }
        if !ready {
            let current = Array(flows.values); flows.removeAll()
            for flow in current { flow.close() }
        }
        if runtime?.active != true { failed(epoch) }
    }

    private func failed(_ epoch: UUID) {
        guard generation == epoch else { return }
        generation = UUID()
        let reply = startReply; startReply = nil
        // Once capture is installed, keep it while unhealthy so accepted
        // Safari traffic is refused, never returned for direct forwarding.
        dnsUntil = 0
        let current = Array(flows.values); flows.removeAll()
        for flow in current { flow.close() }
        runtime?.stop()
        broker?.stop(); broker = nil; timer?.cancel(); timer = nil
        SafariSessionStore.unpublish()
        try? SafariSessionStore.clearSession()
        reply?(SafariForwardError.unavailable)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        state.async { [self] in
            generation = UUID(); capture = false; installing = false; dnsUntil = 0
            timer?.cancel(); timer = nil
            let current = Array(flows.values); flows.removeAll()
            for flow in current { flow.close() }
            broker?.stop(); broker = nil
            SafariSessionStore.unpublish()
            runtime?.stop(); runtime = nil
            try? SafariSessionStore.clearSession()
            let reply = startReply; startReply = nil; reply?(SafariForwardError.closed)
            completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Metadata attributes the originating app. Other apps and the provider's
        // carrier sockets retain their original routes. Signed Safari/WebKit
        // attribution must also be checked on the installed target OS.
        guard ["com.apple.Safari", "com.apple.SafariTechnologyPreview"].contains(flow.metaData.sourceAppSigningIdentifier) else { return false }
        state.async { [self] in
            guard ready, let runtime, flows.count < 256 else {
                flow.closeReadWithError(SafariForwardError.unavailable)
                flow.closeWriteWithError(SafariForwardError.unavailable)
                return
            }
            let id = UUID()
            let adapter = SafariAppFlow(flow: flow, runtime: runtime) { [weak self] in
                self?.state.async { self?.flows.removeValue(forKey: id) }
            }
            flows[id] = adapter; adapter.start()
        }
        return true
    }

    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint: NWEndpoint) -> Bool {
        handleNewFlow(flow)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        do {
            let key = try SafariControlKeychain.read()
            let now = Int64(Date().timeIntervalSince1970)
            let request = try SafariControlProtocol.decode(messageData, key: key, now: now)
            guard request.kind == "status" else { throw SafariControlError.invalidMessage }
            try replay.accept(request, now: now)
            let response = SafariControlMessage(version: 1, kind: "status_reply", nonce: request.nonce,
                issuedAt: now, status: state.sync {
                    SafariProviderStatus(engineReady: runtime?.carrying == true,
                        flowAdapterReady: runtime?.active == true,
                        dnsReady: dnsUntil > DispatchTime.now().uptimeNanoseconds, captureReady: capture)
                })
            completionHandler?(try SafariControlProtocol.encode(response, key: key))
        } catch { completionHandler?(nil) }
    }
}
