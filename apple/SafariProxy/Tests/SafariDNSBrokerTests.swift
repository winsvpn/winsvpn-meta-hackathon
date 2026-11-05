import Foundation
import Network

@main
enum SafariDNSBrokerTests {
    static let key = Data(repeating: 0x41, count: 32)
    static let question = Data([0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    static func wait<T>(_ body: (@escaping (Result<T, Error>) -> Void) -> Void) -> Result<T, Error> {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: Result<T, Error>?
        var calls = 0
        body { value in
            lock.lock()
            calls += 1
            precondition(calls == 1, "Completion called twice")
            result = value
            lock.unlock()
            semaphore.signal()
        }
        precondition(semaphore.wait(timeout: .now() + 8) == .success, "Operation exceeded test deadline")
        lock.lock()
        defer { lock.unlock() }
        return result!
    }

    static func failed<T>(_ result: Result<T, Error>) -> Bool {
        if case .failure = result { return true }
        return false
    }

    static func raw(port: UInt16, bytes: Data) -> Result<Data, Error> {
        wait { completion in
            let connection = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let queue = DispatchQueue(label: "SafariDNSBroker.tests.raw")
            var done = false
            func finish(_ result: Result<Data, Error>) {
                guard !done else { return }
                done = true
                connection.stateUpdateHandler = nil
                connection.cancel()
                completion(result)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: bytes, completion: .contentProcessed { error in
                        if let error { finish(.failure(error)); return }
                        SafariDNSBrokerWire.receive(connection, completion: finish)
                    })
                case .failed(let error): finish(.failure(error))
                default: break
                }
            }
            queue.asyncAfter(deadline: .now() + 3) { finish(.failure(SafariDNSBrokerError.timeout)) }
            connection.start(queue: queue)
        }
    }

    static func main() throws {
        let now = SafariDNSBrokerWire.now()
        let message = SafariDNSBrokerMessage(version: 1, kind: "query", nonce: UUID().uuidString,
            issuedAt: now, tcp: false, payload: question)
        let encoded = try SafariDNSBrokerWire.encode(message, key: key)
        let decoded = try SafariDNSBrokerWire.decode(Data(encoded.dropFirst(4)), key: key, now: now)
        precondition(decoded.nonce == message.nonce && decoded.payload == question)
        // The frame is sealed: neither the message schema nor the question
        // payload is readable by a process that only holds the loopback port.
        precondition(encoded.range(of: Data("\"kind\"".utf8)) == nil)
        precondition(encoded.range(of: Data(question.base64EncodedString().utf8)) == nil)
        precondition(encoded.range(of: message.nonce.data(using: .utf8)!) == nil)
        // A frame shorter than the sealed overhead is refused before any key use.
        precondition(failed(Result { try SafariDNSBrokerWire.decode(Data(repeating: 0, count: SafariDNSBrokerWire.sealedOverhead), key: key, now: now) }))
        // A one-bit change anywhere in the frame fails authentication.
        var tampered = Data(encoded.dropFirst(4)); tampered[tampered.count - 1] ^= 1
        precondition(failed(Result { try SafariDNSBrokerWire.decode(tampered, key: key, now: now) }))
        precondition(failed(Result { try SafariDNSBrokerWire.decode(Data(encoded.dropFirst(4)), key: Data(repeating: 1, count: 32), now: now) }))
        precondition(failed(Result { try SafariDNSBrokerWire.decode(Data(encoded.dropFirst(4)), key: key, now: now + 31) }))
        let oversized = SafariDNSBrokerMessage(version: 1, kind: "query", nonce: UUID().uuidString,
            issuedAt: now, tcp: false, payload: Data(repeating: 0, count: 65536))
        precondition(failed(Result { try SafariDNSBrokerWire.encode(oversized, key: key) }))
        for fill: UInt8 in [0, 255] {
            let maximum = SafariDNSBrokerMessage(version: 1, kind: "query", nonce: UUID().uuidString,
                issuedAt: now, tcp: true, payload: Data(repeating: fill, count: 65535))
            let maximumEncoded = try SafariDNSBrokerWire.encode(maximum, key: key)
            precondition(maximumEncoded.count <= SafariDNSBrokerWire.maximumFrame + 4)
            let maximumDecoded = try SafariDNSBrokerWire.decode(
                Data(maximumEncoded.dropFirst(4)), key: key, now: now)
            precondition(maximumDecoded.payload == maximum.payload)
        }

        let lock = NSLock()
        var kinds: [Bool] = []
        let server = try SafariDNSBroker(key: key, timeout: 1, maximumConcurrent: 2, query: { query, tcp, reply in
            lock.lock(); kinds.append(tcp); lock.unlock()
            reply(.success(query))
            reply(.failure(SafariDNSBrokerError.unavailable))
        }, readinessLease: { $0(true) })
        let port = try wait { server.start(completion: $0) }.get()
        for tcp in [false, true] {
            let response = try wait { SafariDNSBrokerClient.query(port: port, key: key, query: question, tcp: tcp, timeout: 2, completion: $0) }.get()
            precondition(response == question)
        }
        lock.lock(); precondition(kinds == [false, true]); lock.unlock()
        try wait { SafariDNSBrokerClient.lease(port: port, key: key, timeout: 2, completion: $0) }.get()
        precondition(failed(wait { SafariDNSBrokerClient.query(port: port, key: Data(repeating: 2, count: 32), query: question, tcp: false, timeout: 2, completion: $0) }))
        let first = try raw(port: port, bytes: encoded).get()
        let firstReply = try SafariDNSBrokerWire.decode(first, key: key, now: SafariDNSBrokerWire.now())
        precondition(firstReply.nonce == message.nonce)
        precondition(failed(raw(port: port, bytes: encoded)))
        precondition(failed(raw(port: port, bytes: Data([0x7f, 0xff, 0xff, 0xff]))))
        precondition(failed(raw(port: port, bytes: Data([0, 0]))))
        server.stop()

        let queryEntered = DispatchSemaphore(value: 0)
        let blocked = try SafariDNSBroker(key: key, timeout: 0.5, maximumConcurrent: 1, query: { _, _, _ in
            queryEntered.signal()
        }, readinessLease: { $0(false) })
        let blockedPort = try wait { blocked.start(completion: $0) }.get()
        let slowDone = DispatchSemaphore(value: 0)
        SafariDNSBrokerClient.query(port: blockedPort, key: key, query: question, tcp: true, timeout: 2) { result in
            precondition(failed(result)); slowDone.signal()
        }
        precondition(queryEntered.wait(timeout: .now() + 3) == .success)
        precondition(failed(wait { SafariDNSBrokerClient.query(port: blockedPort, key: key, query: question, tcp: false, timeout: 1, completion: $0) }))
        precondition(slowDone.wait(timeout: .now() + 3) == .success)
        precondition(failed(wait { SafariDNSBrokerClient.lease(port: blockedPort, key: key, timeout: 1, completion: $0) }))
        blocked.stop()

        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let wrongNonce = try NWListener(using: parameters)
        let wrongNonceQueue = DispatchQueue(label: "SafariDNSBroker.tests.wrong-nonce")
        wrongNonce.newConnectionHandler = { connection in
            connection.start(queue: wrongNonceQueue)
            SafariDNSBrokerWire.receive(connection) { result in
                do {
                    let received = try SafariDNSBrokerWire.decode(result.get(), key: key, now: SafariDNSBrokerWire.now())
                    let reply = SafariDNSBrokerMessage(version: 1, kind: "query_reply", nonce: UUID().uuidString,
                        issuedAt: SafariDNSBrokerWire.now(), tcp: received.tcp, payload: received.payload)
                    let bytes = try SafariDNSBrokerWire.encode(reply, key: key)
                    connection.send(content: bytes, completion: .contentProcessed { _ in connection.cancel() })
                } catch { connection.cancel() }
            }
        }
        let wrongNoncePort: UInt16 = try wait { completion in
            wrongNonce.stateUpdateHandler = { state in
                switch state {
                case .ready: completion(.success(wrongNonce.port!.rawValue))
                case .failed(let error): completion(.failure(error))
                default: break
                }
            }
            wrongNonce.start(queue: wrongNonceQueue)
        }.get()
        precondition(failed(wait { SafariDNSBrokerClient.query(port: wrongNoncePort, key: key, query: question, tcp: false, timeout: 1, completion: $0) }))
        wrongNonce.stateUpdateHandler = nil
        wrongNonce.cancel()
        print("Safari DNS broker wire and loopback checks passed")
    }
}
