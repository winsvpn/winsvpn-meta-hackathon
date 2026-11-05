import Foundation
import Darwin
import CoreFoundation

// One Go image contains the original WinnTunnel exports and the local gVisor
// adapter exports. Linking two Go c-archives would duplicate the Go runtime.
final class SafariNetstack {
    typealias Create = @convention(c) (UnsafeMutablePointer<CChar>?, UnsafeMutablePointer<CChar>?, Int32) -> Int64
    typealias PacketWrite = @convention(c) (Int64, UnsafeMutableRawPointer?, Int32) -> Int32
    typealias Read = @convention(c) (Int64, UnsafeMutableRawPointer?, Int32, Int32) -> Int32
    typealias Dial = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32, Int32) -> Int64
    typealias HalfClose = @convention(c) (Int64) -> Int32
    typealias Close = @convention(c) (Int64) -> Void
    private let image: UnsafeMutableRawPointer
    private let make: Create
    private let enqueue: PacketWrite
    private let dequeue: Read
    private let tcp: Dial
    private let udp: Dial
    private let readFlow: Read
    private let writeFlow: Read
    private let halfClose: HalfClose
    private let closeFlow: Close
    private let closeStack: Close
    private let handle: Int64

    init(ipv4: String, ipv6: String, mtu: Int) throws {
        guard (576...65535).contains(mtu), let image = dlopen(nil, RTLD_NOW | RTLD_LOCAL) else {
            throw SafariForwardError.unavailable
        }
        func symbol<T>(_ name: String, _ type: T.Type) throws -> T {
            guard let pointer = dlsym(image, name) else { throw SafariForwardError.unavailable }
            return unsafeBitCast(pointer, to: type)
        }
        do {
            make = try symbol("SafariStackCreate", Create.self)
            enqueue = try symbol("SafariStackEnqueuePacket", PacketWrite.self)
            dequeue = try symbol("SafariStackDequeuePacket", Read.self)
            tcp = try symbol("SafariStackDialTCP", Dial.self)
            udp = try symbol("SafariStackDialUDP", Dial.self)
            readFlow = try symbol("SafariFlowRead", Read.self)
            writeFlow = try symbol("SafariFlowWrite", Read.self)
            halfClose = try symbol("SafariFlowCloseWrite", HalfClose.self)
            closeFlow = try symbol("SafariFlowClose", Close.self)
            closeStack = try symbol("SafariStackClose", Close.self)
            var v4 = Array(ipv4.utf8CString), v6 = Array(ipv6.utf8CString)
            handle = make(&v4, &v6, Int32(mtu))
            guard handle > 0 else { throw SafariForwardError.invalid }
        } catch { dlclose(image); throw error }
        self.image = image
    }

    deinit { close(); dlclose(image) }
    func close() { closeStack(handle) }
    func close(_ flow: Int64) { closeFlow(flow) }

    func inject(_ packet: Data) throws {
        guard SafariWinnPacketABI.validPacket(packet) else { throw SafariForwardError.invalid }
        var bytes = [UInt8](packet)
        guard enqueue(handle, &bytes, Int32(bytes.count)) == bytes.count else { throw SafariForwardError.closed }
    }

    func nextPacket() throws -> Data? {
        var buffer = [UInt8](repeating: 0, count: 65535)
        let count = dequeue(handle, &buffer, Int32(buffer.count), 250)
        if count == -3 { return nil }
        guard count > 0, count <= buffer.count else { throw SafariForwardError.closed }
        return Data(buffer.prefix(Int(count)))
    }

    func dial(ip: String, port: Int, datagram: Bool) throws -> Int64 {
        guard Self.numericIP(ip), (1...65535).contains(port) else { throw SafariForwardError.invalid }
        var address = Array(ip.utf8CString)
        let flow = (datagram ? udp : tcp)(handle, &address, Int32(port), 10000)
        guard flow > 0 else { throw SafariForwardError.closed }
        return flow
    }

    static func numericIP(_ ip: String) -> Bool {
        guard !ip.utf8.contains(0) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        return ip.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }

    func read(_ flow: Int64, capacity: Int = 65535) throws -> Data? {
        guard (1...65535).contains(capacity) else { throw SafariForwardError.invalid }
        var buffer = [UInt8](repeating: 0, count: capacity)
        let count = readFlow(flow, &buffer, Int32(capacity), 250)
        if count == -3 { return nil }
        guard count >= 0, count <= capacity else { throw SafariForwardError.closed }
        return Data(buffer.prefix(Int(count)))
    }

    func write(_ data: Data, to flow: Int64, datagram: Bool) throws {
        guard data.count <= 65535 else { throw SafariForwardError.invalid }
        // A zero-byte UDP datagram is meaningful. Supply a non-null buffer.
        var bytes = [UInt8](data.isEmpty ? Data([0]) : data)
        var offset = 0
        repeat {
            let count = bytes.withUnsafeMutableBytes {
                writeFlow(flow, $0.baseAddress!.advanced(by: offset), Int32(data.count - offset), 10000)
            }
            guard count >= 0, count <= data.count - offset,
                  count > 0 || data.isEmpty else { throw SafariForwardError.closed }
            offset += Int(count)
            if datagram {
                guard offset == data.count else { throw SafariForwardError.invalid }
                return
            }
        } while offset < data.count
    }

    func finishWrite(_ flow: Int64) throws {
        guard halfClose(flow) == 0 else { throw SafariForwardError.closed }
    }
}

final class SafariPacketRuntime {
    private let engine: SafariWinnPacketABI
    private let engineHandle: Int64
    let stack: SafariNetstack
    let resolver: String
    let innerV6: String
    let expiresAt: Date
    private let lock = NSLock()
    private var stopped = false
    private let pumps = DispatchGroup()
    var onFailure: (() -> Void)?

    init(document: Data, innerV4: String, innerV6: String, resolver: String, expiresAt: Date) throws {
        guard expiresAt > Date(), SafariNetstack.numericIP(resolver) else { throw SafariForwardError.invalid }
        let engine = try SafariWinnPacketABI()
        let handle = try engine.create(document: document)
        do {
            let status = try engine.status(handle)
            guard let mtu = status["winn3_inner_mtu"] as? NSNumber,
                  CFGetTypeID(mtu) != CFBooleanGetTypeID(), mtu.doubleValue == Double(mtu.intValue) else {
                throw SafariForwardError.invalid
            }
            stack = try SafariNetstack(ipv4: innerV4, ipv6: innerV6, mtu: mtu.intValue)
        } catch { engine.close(handle); throw error }
        self.engine = engine; engineHandle = handle
        self.resolver = resolver; self.innerV6 = innerV6; self.expiresAt = expiresAt
    }

    var active: Bool {
        lock.lock(); defer { lock.unlock() }
        return !stopped && Date() < expiresAt
    }

    static func carrying(_ fields: [String: Any]) -> Bool {
        guard fields["winn3_gate_state"] as? String == "carrying",
              let count = fields["winn3_rx_packets"] as? NSNumber,
              CFGetTypeID(count) != CFBooleanGetTypeID(), count.doubleValue >= 1,
              count.doubleValue.rounded(.down) == count.doubleValue else { return false }
        if let lifecycle = fields["winn3_lifecycle"] {
            guard lifecycle as? String == "connected" else { return false }
        }
        return true
    }

    var carrying: Bool {
        active && ((try? engine.status(engineHandle)).map(Self.carrying) ?? false)
    }

    func start() {
        for direction in 0..<2 {
            pumps.enter()
            Thread.detachNewThread { [self] in
                defer { pumps.leave() }
                do {
                    while active {
                        if direction == 0 {
                            if let packet = try stack.nextPacket() { try engine.write(packet, to: engineHandle) }
                        } else {
                            if let packet = try engine.read(from: engineHandle) { try stack.inject(packet) }
                        }
                    }
                } catch { }
                stop()
            }
        }
    }

    func stop() {
        lock.lock()
        let first = !stopped; stopped = true
        lock.unlock()
        guard first else { return }
        stack.close()
        engine.close(engineHandle)
        onFailure?()
    }

    deinit { stop() }

    // This resolver is reached only through the stack's IP packet queue and
    // Winn/3. No URLSession, host resolver or ordinary outbound socket exists.
    func dns(_ query: Data, tcp: Bool) throws -> Data {
        guard active, (12...65535).contains(query.count), query[2] & 0x80 == 0 else {
            throw SafariForwardError.invalid
        }
        let flow = try stack.dial(ip: resolver, port: 53, datagram: !tcp)
        defer { stack.close(flow) }
        if tcp {
            for part in try SafariDNSWire.tcpSegments(query) { try stack.write(part, to: flow, datagram: false) }
        } else { try stack.write(query, to: flow, datagram: true) }
        let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        var reply = Data()
        var frame = SafariDNSWire.TCPReply()
        var completeFrame = false
        while active && DispatchTime.now().uptimeNanoseconds < deadline {
            guard let chunk = try stack.read(flow) else { continue }
            if !tcp { reply = chunk; break }
            guard !chunk.isEmpty else { throw SafariForwardError.closed }
            if let payload = try frame.append(chunk) {
                reply = payload
                completeFrame = true
                break
            }
        }
        guard (12...65535).contains(reply.count), reply[0] == query[0], reply[1] == query[1],
              reply[2] & 0x80 != 0, (!tcp || completeFrame) else {
            throw SafariForwardError.timeout
        }
        return reply
    }
}
