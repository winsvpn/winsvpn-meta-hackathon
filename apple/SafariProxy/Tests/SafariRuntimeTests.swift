import Foundation

@main
struct SafariRuntimeTests {
    static func main() throws {
        precondition(!SafariPacketRuntime.carrying([:]))
        precondition(!SafariPacketRuntime.carrying(["winn3_gate_state": "carrying", "winn3_rx_packets": true]))
        precondition(!SafariPacketRuntime.carrying(["winn3_gate_state": "carrying", "winn3_rx_packets": 1.5]))
        precondition(!SafariPacketRuntime.carrying(["winn3_gate_state": "carrying", "winn3_rx_packets": 2, "winn3_lifecycle": "recovering"]))
        precondition(SafariPacketRuntime.carrying(["winn3_gate_state": "carrying", "winn3_rx_packets": 2, "winn3_lifecycle": "connected"]))
        precondition(!SafariNetstack.numericIP("example.invalid"))
        precondition(!SafariNetstack.numericIP("127.0.0.1\0invalid"))
        precondition(SafariNetstack.numericIP("2001:db8::1"))
        let engine = try SafariWinnPacketABI()
        do { _ = try engine.create(document: Data("{}".utf8)); fatalError("invalid create accepted") }
        catch SafariWinnPacketABI.Failure.configuration { }

        let stack = try SafariNetstack(ipv4: "10.10.0.2", ipv6: "", mtu: 1280)
        let flow = try stack.dial(ip: "10.10.0.1", port: 53, datagram: true)
        try stack.write(Data([1, 2, 3]), to: flow, datagram: true)
        guard let packet = try stack.nextPacket() else { fatalError("no UDP IP packet") }
        var bytes = [UInt8](packet)
        precondition(bytes[0] >> 4 == 4 && bytes[9] == 17)
        let header = Int(bytes[0] & 15) * 4
        precondition(Array(bytes.suffix(3)) == [1, 2, 3])
        let source = Array(bytes[12..<16]), destination = Array(bytes[16..<20])
        bytes.replaceSubrange(12..<16, with: destination)
        bytes.replaceSubrange(16..<20, with: source)
        let srcPort = Array(bytes[header..<header+2]), dstPort = Array(bytes[header+2..<header+4])
        bytes.replaceSubrange(header..<header+2, with: dstPort)
        bytes.replaceSubrange(header+2..<header+4, with: srcPort)
        bytes[header+6] = 0; bytes[header+7] = 0
        bytes[10] = 0; bytes[11] = 0
        var sum: UInt32 = 0
        for i in stride(from: 0, to: header, by: 2) { sum += UInt32(bytes[i]) * 256 + UInt32(bytes[i+1]) }
        while sum >> 16 > 0 { sum = (sum & 65535) + (sum >> 16) }
        let checksum = ~UInt16(sum)
        bytes[10] = UInt8(checksum >> 8); bytes[11] = UInt8(checksum & 255)
        try stack.inject(Data(bytes))
        let response = try stack.read(flow)
        precondition(response == Data([1, 2, 3]))
        stack.close(flow); stack.close()
        do { _ = try stack.read(flow); fatalError("stale flow accepted") }
        catch SafariForwardError.closed { }

        let query = try SafariDNSWire.question(host: "example.invalid", id: 123, type: 1)
        var reply = [UInt8](query)
        reply[2] = 0x81; reply[3] = 0x80; reply[7] = 1
        reply += [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 10]
        let addresses = try SafariDNSWire.addresses(reply: Data(reply), query: query)
        precondition(addresses == ["192.0.2.10"])
        reply[0] ^= 1
        do { _ = try SafariDNSWire.addresses(reply: Data(reply), query: query); fatalError("wrong DNS id accepted") }
        catch SafariForwardError.invalid { }
        reply[0] ^= 1; reply[12] = 0xc0; reply[13] = 12
        do { _ = try SafariDNSWire.addresses(reply: Data(reply), query: query); fatalError("DNS cycle accepted") }
        catch SafariForwardError.invalid { }
        for name in ["", "bad..name", "bad\0name", String(repeating: "x", count: 64) + ".invalid"] {
            do { _ = try SafariDNSWire.question(host: name, id: 1, type: 1); fatalError("bad DNS name") }
            catch SafariForwardError.invalid { }
        }
        for size in [65533, 65534, 65535] {
            let large = Data(repeating: 0, count: size)
            let parts = try SafariDNSWire.tcpSegments(large)
            precondition(parts.count == 2 && parts[0].count == 2 && parts[1].count == size)
            var decoder = SafariDNSWire.TCPReply()
            let prefixOnly = try decoder.append(parts[0])
            precondition(prefixOnly == nil)
            let payload = try decoder.append(parts[1])
            precondition(payload == large)
        }
        var partial = SafariDNSWire.TCPReply()
        var crafted = Data(repeating: 0, count: 32768)
        crafted[0] = 0x80; crafted[1] = 0; crafted[2] = 0x80
        let incomplete = try partial.append(crafted)
        precondition(incomplete == nil)
        let completed = try partial.append(Data([0, 0]))
        precondition(completed?.count == 32768)
        do { _ = try partial.append(Data([0])); fatalError("second frame accepted") }
        catch SafariForwardError.invalid { }
        print("PASS: real Swift/C stack packet roundtrip, engine ABI, readiness, DNS parsing")
    }
}
