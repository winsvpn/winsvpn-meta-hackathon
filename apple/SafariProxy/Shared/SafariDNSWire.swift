import Foundation
import Darwin

enum SafariDNSWire {
    static func tcpSegments(_ query: Data) throws -> [Data] {
        guard (12...65535).contains(query.count) else { throw SafariForwardError.invalid }
        return [Data([UInt8(query.count >> 8), UInt8(query.count & 255)]), query]
    }

    struct TCPReply {
        private var bytes = Data()
        private var expected: Int?
        private var complete = false

        mutating func append(_ chunk: Data) throws -> Data? {
            guard !complete, !chunk.isEmpty, bytes.count + chunk.count <= 65537 else { throw SafariForwardError.invalid }
            bytes.append(chunk)
            if expected == nil && bytes.count >= 2 {
                let length = Int(bytes[0]) * 256 + Int(bytes[1])
                guard length >= 12 else { throw SafariForwardError.invalid }
                expected = length + 2
            }
            guard let expected, bytes.count >= expected else { return nil }
            guard bytes.count == expected else { throw SafariForwardError.invalid }
            complete = true
            return Data(bytes.dropFirst(2))
        }
    }

    static func question(host: String, id: UInt16, type: UInt16) throws -> Data {
        let host = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard !host.isEmpty, host.utf8.count <= 253 else { throw SafariForwardError.invalid }
        var data = Data([UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            let bytes = Array(label.utf8)
            guard (1...63).contains(bytes.count), bytes.allSatisfy({
                (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
            }) else { throw SafariForwardError.invalid }
            data.append(UInt8(bytes.count)); data.append(contentsOf: bytes)
        }
        data.append(contentsOf: [0, UInt8(type >> 8), UInt8(type & 255), 0, 1])
        return data
    }

    private static func name(_ bytes: [UInt8], _ offset: inout Int) throws -> String {
        var cursor = offset, end: Int?, visited = Set<Int>(), labels: [String] = []
        while cursor < bytes.count && visited.count < 128 {
            guard visited.insert(cursor).inserted else { throw SafariForwardError.invalid }
            let length = Int(bytes[cursor]); cursor += 1
            if length == 0 { offset = end ?? cursor; return labels.joined(separator: ".").lowercased() }
            if length & 0xc0 == 0xc0 {
                guard cursor < bytes.count else { throw SafariForwardError.invalid }
                end = end ?? cursor + 1
                cursor = (length & 63) * 256 + Int(bytes[cursor])
            } else {
                guard length <= 63, cursor + length <= bytes.count,
                      let label = String(bytes: bytes[cursor..<cursor+length], encoding: .ascii) else {
                    throw SafariForwardError.invalid
                }
                labels.append(label); cursor += length
                guard labels.joined(separator: ".").utf8.count <= 253 else { throw SafariForwardError.invalid }
            }
        }
        throw SafariForwardError.invalid
    }

    static func addresses(reply: Data, query: Data) throws -> [String] {
        let b = [UInt8](reply), q = [UInt8](query)
        guard b.count >= 12, q.count >= 17, b[0...1] == q[0...1], b[2] & 0x80 != 0,
              b[2] & 0x7a == 0, b[3] & 15 == 0, b[4] == 0, b[5] == 1 else { throw SafariForwardError.invalid }
        var qp = 12, p = 12
        let expected = try name(q, &qp), actual = try name(b, &p)
        guard expected == actual, p + 4 <= b.count, qp + 4 == q.count,
              b[p..<p+4] == q[qp..<qp+4] else { throw SafariForwardError.invalid }
        let type = Int(q[qp]) * 256 + Int(q[qp+1]); p += 4
        let count = Int(b[6]) * 256 + Int(b[7])
        guard count <= 256 else { throw SafariForwardError.invalid }
        var records: [(String, Int, Data)] = [], aliases: [String: String] = [:]
        for _ in 0..<count {
            let owner = try name(b, &p)
            guard p + 10 <= b.count else { throw SafariForwardError.invalid }
            let kind = Int(b[p]) * 256 + Int(b[p+1]), klass = Int(b[p+2]) * 256 + Int(b[p+3])
            let size = Int(b[p+8]) * 256 + Int(b[p+9]); p += 10
            guard p + size <= b.count else { throw SafariForwardError.invalid }
            if klass == 1 && kind == 5 {
                var cp = p; let target = try name(b, &cp)
                guard cp == p + size else { throw SafariForwardError.invalid }
                aliases[owner] = target
            } else if klass == 1 { records.append((owner, kind, Data(b[p..<p+size]))) }
            p += size
        }
        var permitted = Set([expected]), current = expected
        for _ in 0..<16 {
            guard let next = aliases[current] else { break }
            guard permitted.insert(next).inserted else { throw SafariForwardError.invalid }
            current = next
        }
        var addresses: [String] = []
        for (owner, kind, bytes) in records where permitted.contains(owner) && kind == type {
            guard (kind == 1 && bytes.count == 4) || (kind == 28 && bytes.count == 16) else { continue }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let ok = bytes.withUnsafeBytes { inet_ntop(kind == 1 ? AF_INET : AF_INET6, $0.baseAddress, &buffer, socklen_t(buffer.count)) }
            guard ok != nil else { throw SafariForwardError.invalid }
            addresses.append(String(cString: buffer))
        }
        return addresses
    }
}

extension SafariPacketRuntime {
    func resolve(_ host: String) throws -> [String] {
        if SafariNetstack.numericIP(host) { return [host] }
        // Query only families assigned to this session, through its resolver.
        var addresses: [String] = []
        for type: UInt16 in innerV6.isEmpty ? [1] : [1, 28] {
            let query = try SafariDNSWire.question(host: host, id: UInt16.random(in: 0...65535), type: type)
            do {
                var reply = try dns(query, tcp: false)
                if reply[2] & 2 != 0 { reply = try dns(query, tcp: true) }
                addresses += try SafariDNSWire.addresses(reply: reply, query: query)
            } catch { continue }
        }
        guard !addresses.isEmpty else { throw SafariForwardError.unavailable }
        return Array(addresses.prefix(16))
    }
}
