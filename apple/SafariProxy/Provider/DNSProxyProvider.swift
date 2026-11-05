import Foundation
import NetworkExtension

// All system DNS crosses the one v3 session. No second engine, host resolver,
// or external DNS socket is created by this provider.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let queue = DispatchQueue(label: "SafariProxy.dns")
    private var epoch = UUID()
    private var timer: DispatchSourceTimer?
    private var key = Data()
    private var initial: ((Error?) -> Void)?
    private var checking = false
    private var heartbeatClient: SafariDNSBrokerClient?
    private var clients: [UUID: SafariDNSFlow] = [:]

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        queue.async { [self] in
            epoch = UUID(); let generation = epoch; initial = completionHandler
            do { key = try SafariSessionStore.brokerKey() }
            catch { initial = nil; completionHandler(error); return }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now(), repeating: 2)
            timer.setEventHandler { [weak self] in self?.heartbeat(generation) }
            self.timer = timer; timer.resume()
            queue.asyncAfter(deadline: .now() + 25) { [weak self] in
                guard let self, self.epoch == generation, let callback = self.initial else { return }
                self.epoch = UUID(); self.checking = false
                self.heartbeatClient?.cancel(); self.heartbeatClient = nil
                self.initial = nil; self.timer?.cancel(); self.timer = nil
                callback(SafariForwardError.unavailable)
            }
        }
    }

    private func heartbeat(_ generation: UUID) {
        guard epoch == generation, timer != nil, !checking else { return }
        checking = true
        do {
            let port = try SafariSessionStore.port()
            // Prove the resolver through TCP before leasing readiness. TCP
            // retransmits across the initial engine handshake.
            let probe = Data([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1])
            heartbeatClient = SafariDNSBrokerClient.query(port: port, key: key, query: probe, tcp: true) { [weak self] result in
                guard let self else { return }
                self.queue.async {
                    guard self.epoch == generation else { return }
                    self.heartbeatClient = nil
                    guard case .success = result else { self.checking = false; return }
                    if let callback = self.initial {
                        self.initial = nil; self.checking = false
                        callback(nil)
                        // Readiness is leased on a later timer turn after DNS
                        // startup has completed, never before its completion.
                        return
                    }
                    self.heartbeatClient = SafariDNSBrokerClient.lease(port: port, key: self.key, timeout: 3) { [weak self] result in
                        self?.queue.async {
                            guard let self, self.epoch == generation else { return }
                            self.heartbeatClient = nil
                            self.checking = false
                            if case .success = result {
                                let callback = self.initial; self.initial = nil; callback?(nil)
                            }
                        }
                    }
                }
            }
        } catch { checking = false }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async { [self] in
            epoch = UUID(); timer?.cancel(); timer = nil; checking = false
            heartbeatClient?.cancel(); heartbeatClient = nil
            let active = Array(clients.values); clients.removeAll()
            for client in active { client.stop() }
            let callback = initial; initial = nil; callback?(SafariForwardError.closed)
            key = Data(); completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        queue.async { [self] in
            guard timer != nil, clients.count < 128 else {
                flow.closeReadWithError(SafariForwardError.unavailable)
                flow.closeWriteWithError(SafariForwardError.unavailable)
                return
            }
            let id = UUID()
            let client = SafariDNSFlow(flow: flow, key: key) { [weak self] in
                self?.queue.async { self?.clients.removeValue(forKey: id) }
            }
            clients[id] = client; client.start()
        }
        return true
    }
}

private final class SafariDNSFlow {
    private let flow: NEAppProxyFlow
    private let key: Data
    private let finished: () -> Void
    private let queue = DispatchQueue(label: "SafariProxy.dns.flow")
    private var closed = false
    private var buffer = Data()
    private var exchange: SafariDNSBrokerClient?

    init(flow: NEAppProxyFlow, key: Data, finished: @escaping () -> Void) {
        self.flow = flow; self.key = key; self.finished = finished
    }
    func stop() { queue.async { self.close() } }
    private func close() {
        guard !closed else { return }
        closed = true; exchange?.cancel(); exchange = nil
        flow.closeReadWithError(SafariForwardError.closed)
        flow.closeWriteWithError(SafariForwardError.closed)
        finished()
    }
    func start() {
        flow.open(withLocalEndpoint: nil) { [self] error in
            queue.async {
                guard error == nil, !self.closed else { self.close(); return }
                if let tcp = self.flow as? NEAppProxyTCPFlow { self.readTCP(tcp) }
                else if let udp = self.flow as? NEAppProxyUDPFlow { self.readUDP(udp) }
                else { self.close() }
            }
        }
    }
    private func query(_ packet: Data, tcp: Bool, completion: @escaping (Data) -> Void) {
        guard !closed else { return }
        do {
            exchange = SafariDNSBrokerClient.query(port: try SafariSessionStore.port(), key: key,
                query: packet, tcp: tcp) { [self] result in
                queue.async {
                    guard !self.closed else { return }
                    self.exchange = nil
                    guard case .success(let reply) = result, reply.count >= 12, packet.count >= 12,
                          reply[0] == packet[0], reply[1] == packet[1], reply[2] & 0x80 != 0 else {
                        self.close(); return
                    }
                    completion(reply)
                }
            }
        } catch { close() }
    }
    private func readTCP(_ tcp: NEAppProxyTCPFlow) {
        guard !closed else { return }
        if buffer.count >= 2 {
            let size = Int(buffer[0]) * 256 + Int(buffer[1])
            guard size >= 12 else { close(); return }
            if buffer.count >= size + 2 {
                let packet = Data(buffer[2..<size+2]); buffer = Data(buffer.dropFirst(size+2))
                query(packet, tcp: true) { [self] reply in
                    let framed = Data([UInt8(reply.count >> 8), UInt8(reply.count & 255)]) + reply
                    tcp.write(framed) { error in
                        self.queue.async {
                            guard error == nil else { self.close(); return }
                            self.readTCP(tcp)
                        }
                    }
                }
                return
            }
        }
        tcp.readData { [self] data, error in
            queue.async {
                guard error == nil, let data, !data.isEmpty, self.buffer.count + data.count <= 131074 else {
                    self.close(); return
                }
                self.buffer.append(data); self.readTCP(tcp)
            }
        }
    }
    private func readUDP(_ udp: NEAppProxyUDPFlow) {
        guard !closed else { return }
        udp.readDatagrams { [self] packets, endpoints, error in
            queue.async {
                guard error == nil, let packets, let endpoints, !packets.isEmpty,
                      packets.count == endpoints.count, packets.count <= 256 else { self.close(); return }
                self.sendUDP(udp, packets, endpoints, index: 0)
            }
        }
    }
    private func sendUDP(_ udp: NEAppProxyUDPFlow, _ packets: [Data], _ endpoints: [NWEndpoint], index: Int) {
        guard !closed else { return }
        guard index < packets.count else { readUDP(udp); return }
        query(packets[index], tcp: false) { [self] reply in
            udp.writeDatagrams([reply], sentBy: [endpoints[index]]) { error in
                self.queue.async {
                    guard error == nil else { self.close(); return }
                    self.sendUDP(udp, packets, endpoints, index: index + 1)
                }
            }
        }
    }
}
