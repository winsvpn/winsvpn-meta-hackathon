import Foundation
import NetworkExtension

// Each accepted flow owns at most one TCP stream or 64 UDP destinations.
// Reads advance only after the corresponding write completes.
final class SafariAppFlow {
    private let flow: NEAppProxyFlow
    private let runtime: SafariPacketRuntime
    private let lock = NSLock()
    private var closed = false
    private var streams: [String: Int64] = [:]
    private var tcpEnds = 0
    private let finished: () -> Void

    init(flow: NEAppProxyFlow, runtime: SafariPacketRuntime, finished: @escaping () -> Void) {
        self.flow = flow; self.runtime = runtime; self.finished = finished
    }

    private var active: Bool {
        lock.lock(); defer { lock.unlock() }
        return !closed && runtime.active
    }

    func close(_ error: Error? = SafariForwardError.closed) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let handles = Array(streams.values); streams.removeAll()
        lock.unlock()
        for handle in handles { runtime.stack.close(handle) }
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        finished()
    }

    private func register(_ handle: Int64, key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { runtime.stack.close(handle); return false }
        streams[key] = handle
        return true
    }

    func start() {
        flow.open(withLocalEndpoint: nil) { [self] error in
            guard error == nil, active else { close(error); return }
            if let tcp = flow as? NEAppProxyTCPFlow {
                DispatchQueue.global().async { [self] in
                    do {
                        guard let remote = tcp.remoteEndpoint as? NWHostEndpoint,
                              let port = Int(remote.port) else { throw SafariForwardError.invalid }
                        let handle = try dial(host: remote.hostname, port: port, datagram: false)
                        guard register(handle, key: "tcp") else { return }
                        readTCP(tcp, handle)
                        receiveTCP(tcp, handle)
                    } catch { close(error) }
                }
            } else if let udp = flow as? NEAppProxyUDPFlow {
                readUDP(udp)
            } else { close(SafariForwardError.invalid) }
        }
    }

    private func dial(host: String, port: Int, datagram: Bool) throws -> Int64 {
        let addresses = try runtime.resolve(host)
        for ip in addresses {
            guard active else { throw SafariForwardError.closed }
            if let handle = try? runtime.stack.dial(ip: ip, port: port, datagram: datagram) { return handle }
        }
        throw SafariForwardError.closed
    }

    private func endedTCP() {
        lock.lock(); tcpEnds += 1; let done = tcpEnds == 2; lock.unlock()
        if done { close(nil) }
    }

    private func readTCP(_ tcp: NEAppProxyTCPFlow, _ handle: Int64) {
        guard active else { close(); return }
        tcp.readData { [self] data, error in
            guard error == nil, let data, active else { close(error); return }
            DispatchQueue.global().async { [self] in
                do {
                    if data.isEmpty {
                        try runtime.stack.finishWrite(handle)
                        tcp.closeReadWithError(nil)
                        endedTCP()
                    } else {
                        // NE may return more than one stack write buffer.
                        var offset = 0
                        while offset < data.count {
                            guard active else { throw SafariForwardError.closed }
                            let end = min(offset + 65535, data.count)
                            try runtime.stack.write(Data(data[offset..<end]), to: handle, datagram: false)
                            offset = end
                        }
                        readTCP(tcp, handle)
                    }
                } catch { close(error) }
            }
        }
    }

    private func receiveTCP(_ tcp: NEAppProxyTCPFlow, _ handle: Int64) {
        DispatchQueue.global().async { [self] in
            do {
                guard active else { close(); return }
                guard let data = try runtime.stack.read(handle) else { receiveTCP(tcp, handle); return }
                if data.isEmpty { tcp.closeWriteWithError(nil); endedTCP(); return }
                tcp.write(data) { error in
                    if let error { self.close(error) }
                    else { self.receiveTCP(tcp, handle) }
                }
            } catch { close(error) }
        }
    }

    private func readUDP(_ udp: NEAppProxyUDPFlow) {
        guard active else { close(); return }
        udp.readDatagrams { [self] packets, endpoints, error in
            guard error == nil, let packets, let endpoints, packets.count == endpoints.count,
                  !packets.isEmpty, packets.count <= 256, active else { close(error); return }
            DispatchQueue.global().async { [self] in
                do {
                    for (packet, endpoint) in zip(packets, endpoints) {
                        guard active, let endpoint = endpoint as? NWHostEndpoint,
                              let port = Int(endpoint.port) else { throw SafariForwardError.invalid }
                        let key = endpoint.hostname + ":" + endpoint.port
                        lock.lock(); let existing = streams[key]; let count = streams.count; lock.unlock()
                        let handle: Int64
                        if let existing { handle = existing }
                        else {
                            guard count < 64 else { throw SafariForwardError.capacity }
                            handle = try dial(host: endpoint.hostname, port: port, datagram: true)
                            guard register(handle, key: key) else { return }
                            receiveUDP(udp, handle, endpoint)
                        }
                        try runtime.stack.write(packet, to: handle, datagram: true)
                    }
                    readUDP(udp)
                } catch { close(error) }
            }
        }
    }

    private func receiveUDP(_ udp: NEAppProxyUDPFlow, _ handle: Int64, _ endpoint: NWHostEndpoint) {
        DispatchQueue.global().async { [self] in
            do {
                guard active else { close(); return }
                guard let packet = try runtime.stack.read(handle) else { receiveUDP(udp, handle, endpoint); return }
                udp.writeDatagrams([packet], sentBy: [endpoint]) { error in
                    if let error { self.close(error) }
                    else { self.receiveUDP(udp, handle, endpoint) }
                }
            } catch { close(error) }
        }
    }
}
