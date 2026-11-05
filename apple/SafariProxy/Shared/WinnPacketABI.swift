import Foundation
import Darwin

// The packet boundary matches the existing macOS PacketTunnel ABI. Only the
// standalone create accepts IP packets. App streams first cross SafariNetstack.
final class SafariWinnPacketABI {
    enum Failure: Error { case missingEngine, contract, configuration, refused, packet, status }
    private typealias Create = @convention(c) (UnsafeMutablePointer<CChar>?, Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int64
    private typealias Write = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32) -> Int32
    private typealias Read = @convention(c) (Int64, UnsafeMutablePointer<CChar>?, Int32, Int32) -> Int32
    private typealias Text = @convention(c) () -> UnsafeMutablePointer<CChar>?
    private typealias Status = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
    private typealias Close = @convention(c) (Int64) -> UnsafeMutablePointer<CChar>?
    private typealias Free = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
    private let image: UnsafeMutableRawPointer
    private let createFunction: Create
    private let writeFunction: Write
    private let readFunction: Read
    private let statusFunction: Status
    private let closeFunction: Close
    private let freeFunction: Free

    init() throws {
        guard let image = dlopen(nil, RTLD_NOW | RTLD_LOCAL) else { throw Failure.missingEngine }
        func symbol<T>(_ name: String, _ type: T.Type) throws -> T {
            guard let pointer = dlsym(image, name) else { throw Failure.missingEngine }
            return unsafeBitCast(pointer, to: type)
        }
        do {
            createFunction = try symbol("WinnTunnelCreateWinn3", Create.self)
            writeFunction = try symbol("WinnTunnelWriteInbound", Write.self)
            readFunction = try symbol("WinnTunnelReadOutbound", Read.self)
            statusFunction = try symbol("WinnTunnelStatusJSON", Status.self)
            closeFunction = try symbol("WinnTunnelClose", Close.self)
            let free = try symbol("WinnTunnelFreeString", Free.self)
            freeFunction = free
            let contract = try symbol("WinnTunnelContractVersion", Text.self)
            let version = try symbol("WinnTunnelProtocolVersion", Text.self)
            let contractText = contract()
            let versionText = version()
            defer { free(contractText); free(versionText) }
            guard let contractText, let versionText,
                  String(cString: contractText) == "winn-datapath/1",
                  String(cString: versionText) == "winn/3" else { throw Failure.contract }
        } catch { dlclose(image); throw error }
        self.image = image
    }

    deinit { dlclose(image) }

    func create(document: Data) throws -> Int64 {
        guard document.count <= 65536, !document.contains(0),
              let fields = try JSONSerialization.jsonObject(with: document) as? [String: Any],
              fields["contract"] as? String == "winn-datapath/1+winn3",
              fields["payload"] as? String == "ip-packet",
              fields["carrier"] as? String == "winn3",
              fields["allow_own_socket"] as? Bool == true else { throw Failure.configuration }
        var bytes = [CChar](document.map { CChar(bitPattern: $0) }) + [0]
        defer { bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var error: UnsafeMutablePointer<CChar>?
        // Transparent providers own their outer socket. Passing -1 avoids the
        // existing supplied-fd create failure's ambiguous ownership boundary.
        let handle = createFunction(&bytes, -1, &error)
        defer { freeFunction(error) }
        guard handle > 0, error == nil else {
            if handle > 0 { close(handle) }
            throw Failure.refused
        }
        return handle
    }

    func write(_ packet: Data, to handle: Int64) throws {
        guard Self.validPacket(packet) else { throw Failure.packet }
        var bytes = [CChar](packet.map { CChar(bitPattern: $0) })
        guard writeFunction(handle, &bytes, Int32(bytes.count)) == bytes.count else { throw Failure.packet }
    }

    func read(from handle: Int64) throws -> Data? {
        var bytes = [CChar](repeating: 0, count: 65535)
        let count = readFunction(handle, &bytes, Int32(bytes.count), 250)
        if count == -3 { return nil }
        guard count > 0, count <= bytes.count else { throw Failure.packet }
        let packet = Data(bytes: bytes, count: Int(count))
        guard Self.validPacket(packet) else { throw Failure.packet }
        return packet
    }

    func status(_ handle: Int64) throws -> [String: Any] {
        guard let text = statusFunction(handle) else { throw Failure.status }
        defer { freeFunction(text) }
        // Engine status is local and bounded. Never return it to browser JS.
        let count = strnlen(text, 65537)
        guard count <= 65536,
              let fields = try JSONSerialization.jsonObject(with: Data(bytes: text, count: count)) as? [String: Any]
        else { throw Failure.status }
        return fields
    }

    func close(_ handle: Int64) { freeFunction(closeFunction(handle)) }

    static func validPacket(_ data: Data) -> Bool {
        guard let first = data.first, data.count <= 65535 else { return false }
        let bytes = [UInt8](data)
        if first >> 4 == 4 {
            guard bytes.count >= 20 else { return false }
            let header = Int(first & 15) * 4
            let length = Int(bytes[2]) * 256 + Int(bytes[3])
            return header >= 20 && header <= bytes.count && length == bytes.count
        }
        if first >> 4 == 6 {
            guard bytes.count >= 40 else { return false }
            return Int(bytes[4]) * 256 + Int(bytes[5]) + 40 == bytes.count
        }
        return false
    }

}
