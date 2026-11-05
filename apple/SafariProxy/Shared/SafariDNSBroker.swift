import Foundation
import Network
import CryptoKit

enum SafariDNSBrokerError: Error {
    case invalidMessage, authentication, expired, replay, capacity, timeout, stopped, unavailable
}

struct SafariDNSBrokerMessage: Codable {
    let version: Int
    let kind: String
    let nonce: String
    let issuedAt: Int64
    let tcp: Bool
    let payload: Data
}

enum SafariDNSBrokerWire {
    static let maximumFrame = 100 * 1024
    static let maximumDNS = 65535
    static let lifetime: Int64 = 30
    // ChaChaPoly combined form: 12-byte nonce + 16-byte tag around the body.
    static let sealedOverhead = 28
    private static let domain = Data("SafariDNSBroker-v2\u{0}".utf8)

    static func now() -> Int64 { Int64(Date().timeIntervalSince1970) }

    static func encode(_ message: SafariDNSBrokerMessage, key: Data) throws -> Data {
        guard key.count == 32, message.payload.count <= maximumDNS else {
            throw SafariDNSBrokerError.invalidMessage
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let body = try encoder.encode(message)
        // Sealed, not merely authenticated: the frame crosses a loopback port
        // that any local process can hold once the broker has released it,
        // and the body carries the DNS question in the clear. The nonce is
        // 12 random bytes chosen by CryptoKit per call; the combined layout
        // is nonce + ciphertext + 16-byte tag.
        let sealed = try ChaChaPoly.seal(body, using: SymmetricKey(data: key), authenticating: domain)
        let frame = sealed.combined
        guard frame.count <= maximumFrame else { throw SafariDNSBrokerError.invalidMessage }
        let length = UInt32(frame.count)
        return Data([UInt8(length >> 24), UInt8((length >> 16) & 255), UInt8((length >> 8) & 255), UInt8(length & 255)]) + frame
    }

    static func decode(_ frame: Data, key: Data, now: Int64) throws -> SafariDNSBrokerMessage {
        guard key.count == 32, frame.count > sealedOverhead, frame.count <= maximumFrame else {
            throw SafariDNSBrokerError.invalidMessage
        }
        guard let box = try? ChaChaPoly.SealedBox(combined: frame),
              let body = try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: domain) else {
            throw SafariDNSBrokerError.authentication
        }
        let message = try JSONDecoder().decode(SafariDNSBrokerMessage.self, from: body)
        guard message.version == 1, UUID(uuidString: message.nonce)?.uuidString == message.nonce,
              message.payload.count <= maximumDNS else { throw SafariDNSBrokerError.invalidMessage }
        guard message.issuedAt >= now - lifetime, message.issuedAt <= now + 5 else {
            throw SafariDNSBrokerError.expired
        }
        switch message.kind {
        case "query", "query_reply":
            guard message.payload.count >= 12 else { throw SafariDNSBrokerError.invalidMessage }
        case "lease", "lease_reply", "error":
            guard message.payload.isEmpty, !message.tcp else { throw SafariDNSBrokerError.invalidMessage }
        default: throw SafariDNSBrokerError.invalidMessage
        }
        return message
    }

    static func receive(_ connection: NWConnection, completion: @escaping (Result<Data, Error>) -> Void) {
        receiveExactly(connection, count: 4) { result in
            do {
                let header = try result.get()
                let count = header.reduce(0) { ($0 << 8) | Int($1) }
                guard count > sealedOverhead, count <= maximumFrame else { throw SafariDNSBrokerError.invalidMessage }
                receiveExactly(connection, count: count, completion: completion)
            } catch { completion(.failure(error)) }
        }
    }

    private static func receiveExactly(_ connection: NWConnection, count: Int, accumulated: Data = Data(),
                                       completion: @escaping (Result<Data, Error>) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - accumulated.count) { data, _, closed, error in
            if let error { completion(.failure(error)); return }
            let collected = accumulated + (data ?? Data())
            if collected.count == count { completion(.success(collected)); return }
            guard !closed, let data, !data.isEmpty else {
                completion(.failure(SafariDNSBrokerError.invalidMessage)); return
            }
            receiveExactly(connection, count: count, accumulated: collected, completion: completion)
        }
    }
}

final class SafariDNSBroker {
    // Handlers return promptly and may complete on any queue. The broker drops
    // late completions; the engine owner cancels its own timed-out work.
    typealias Query = (Data, Bool, @escaping (Result<Data, Error>) -> Void) -> Void
    typealias ReadinessLease = (@escaping (Bool) -> Void) -> Void
    private final class Exchange {
        let connection: NWConnection
        var timer: DispatchWorkItem?
        var answered = false
        init(_ connection: NWConnection) { self.connection = connection }
    }
    private let queue = DispatchQueue(label: "SafariDNSBroker.server")
    private let key: Data
    private let timeout: TimeInterval
    private let maximumConcurrent: Int
    private let query: Query
    private let readinessLease: ReadinessLease
    private var listener: NWListener?
    private var exchanges: [UUID: Exchange] = [:]
    private var seen: [String: Int64] = [:]
    private var startCompletion: ((Result<UInt16, Error>) -> Void)?
    private var stopped = false

    init(key: Data, timeout: TimeInterval = 10, maximumConcurrent: Int = 32,
         query: @escaping Query, readinessLease: @escaping ReadinessLease) throws {
        guard key.count == 32, timeout.isFinite, timeout > 0, timeout <= 60,
              (1...128).contains(maximumConcurrent) else { throw SafariDNSBrokerError.invalidMessage }
        self.key = key
        self.timeout = timeout
        self.maximumConcurrent = maximumConcurrent
        self.query = query
        self.readinessLease = readinessLease
    }

    func start(completion: @escaping (Result<UInt16, Error>) -> Void) {
        queue.async { [self] in
            guard self.listener == nil, !self.stopped else { completion(.failure(SafariDNSBrokerError.stopped)); return }
            do {
                let parameters = NWParameters.tcp
                parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
                let listener = try NWListener(using: parameters)
                self.startCompletion = completion
                self.listener = listener
                listener.newConnectionHandler = { [weak self] connection in
                    guard let self else { connection.cancel(); return }
                    self.accept(connection)
                }
                listener.stateUpdateHandler = { [weak self] state in
                    guard let self else { return }
                    switch state {
                    case .ready:
                        guard let port = self.listener?.port else { self.shutdown(SafariDNSBrokerError.unavailable); return }
                        let callback = self.startCompletion
                        self.startCompletion = nil
                        callback?(.success(port.rawValue))
                    case .failed(let error): self.shutdown(error)
                    case .cancelled: self.shutdown(SafariDNSBrokerError.stopped)
                    default: break
                    }
                }
                listener.start(queue: self.queue)
                self.queue.asyncAfter(deadline: .now() + self.timeout) { [weak self] in
                    guard let self, self.startCompletion != nil else { return }
                    self.shutdown(SafariDNSBrokerError.timeout)
                }
            } catch { completion(.failure(error)) }
        }
    }

    func stop() { queue.async { self.shutdown(SafariDNSBrokerError.stopped) } }

    private func shutdown(_ error: Error) {
        stopped = true
        listener?.newConnectionHandler = nil
        listener?.stateUpdateHandler = nil
        listener?.cancel()
        listener = nil
        for id in Array(exchanges.keys) { finish(id) }
        let callback = startCompletion
        startCompletion = nil
        callback?(.failure(error))
    }

    private func accept(_ connection: NWConnection) {
        guard !stopped, exchanges.count < maximumConcurrent else { connection.cancel(); return }
        let id = UUID()
        let exchange = Exchange(connection)
        exchanges[id] = exchange
        let timer = DispatchWorkItem { [weak self] in self?.finish(id) }
        exchange.timer = timer
        queue.asyncAfter(deadline: .now() + timeout, execute: timer)
        connection.start(queue: queue)
        SafariDNSBrokerWire.receive(connection) { [weak self] result in
            guard let self, self.exchanges[id] != nil else { return }
            do {
                let now = SafariDNSBrokerWire.now()
                let request = try SafariDNSBrokerWire.decode(result.get(), key: self.key, now: now)
                guard request.kind == "query" || request.kind == "lease" else { throw SafariDNSBrokerError.invalidMessage }
                self.seen = self.seen.filter { $0.value >= now - SafariDNSBrokerWire.lifetime }
                guard self.seen[request.nonce] == nil else { throw SafariDNSBrokerError.replay }
                guard self.seen.count < 4096 else { throw SafariDNSBrokerError.capacity }
                self.seen[request.nonce] = request.issuedAt
                if request.kind == "query" {
                    self.query(request.payload, request.tcp) { [weak self] result in
                        guard let self else { return }
                        self.queue.async { self.respond(id, request: request, result: result) }
                    }
                } else {
                    self.readinessLease { [weak self] ready in
                        guard let self else { return }
                        self.queue.async {
                            self.respond(id, request: request, result: ready ? .success(Data()) : .failure(SafariDNSBrokerError.unavailable))
                        }
                    }
                }
            } catch { self.finish(id) }
        }
    }

    private func respond(_ id: UUID, request: SafariDNSBrokerMessage, result: Result<Data, Error>) {
        guard let exchange = exchanges[id], !exchange.answered else { return }
        exchange.answered = true
        do {
            let response: SafariDNSBrokerMessage
            switch result {
            case .success(let payload):
                guard request.kind == "lease" ? payload.isEmpty : (12...SafariDNSBrokerWire.maximumDNS).contains(payload.count) else {
                    throw SafariDNSBrokerError.invalidMessage
                }
                response = SafariDNSBrokerMessage(version: 1, kind: request.kind + "_reply", nonce: request.nonce,
                    issuedAt: SafariDNSBrokerWire.now(), tcp: request.tcp, payload: payload)
            case .failure:
                response = SafariDNSBrokerMessage(version: 1, kind: "error", nonce: request.nonce,
                    issuedAt: SafariDNSBrokerWire.now(), tcp: false, payload: Data())
            }
            let bytes = try SafariDNSBrokerWire.encode(response, key: key)
            exchange.connection.send(content: bytes, completion: .contentProcessed { [weak self] _ in self?.finish(id) })
        } catch { finish(id) }
    }

    private func finish(_ id: UUID) {
        guard let exchange = exchanges.removeValue(forKey: id) else { return }
        exchange.timer?.cancel()
        exchange.connection.cancel()
    }
}

final class SafariDNSBrokerClient {
    private let queue = DispatchQueue(label: "SafariDNSBroker.client")
    private let connection: NWConnection
    private let key: Data
    private let request: SafariDNSBrokerMessage
    private var callback: ((Result<Data, Error>) -> Void)?
    private var timer: DispatchWorkItem?
    private var sent = false

    @discardableResult
    static func query(port: UInt16, key: Data, query: Data, tcp: Bool, timeout: TimeInterval = 10,
                      completion: @escaping (Result<Data, Error>) -> Void) -> SafariDNSBrokerClient? {
        start(port: port, key: key, kind: "query", payload: query, tcp: tcp, timeout: timeout, completion: completion)
    }

    @discardableResult
    static func lease(port: UInt16, key: Data, timeout: TimeInterval = 10,
                      completion: @escaping (Result<Void, Error>) -> Void) -> SafariDNSBrokerClient? {
        start(port: port, key: key, kind: "lease", payload: Data(), tcp: false, timeout: timeout) { result in
            completion(result.map { _ in () })
        }
    }

    private static func start(port: UInt16, key: Data, kind: String, payload: Data, tcp: Bool,
                              timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) -> SafariDNSBrokerClient? {
        guard port != 0, key.count == 32, timeout.isFinite, timeout > 0, timeout <= 60,
              kind == "lease" || (12...SafariDNSBrokerWire.maximumDNS).contains(payload.count) else {
            completion(.failure(SafariDNSBrokerError.invalidMessage)); return nil
        }
        let client = SafariDNSBrokerClient(port: port, key: key, kind: kind, payload: payload, tcp: tcp, completion: completion)
        client.run(timeout: timeout)
        return client
    }

    private init(port: UInt16, key: Data, kind: String, payload: Data, tcp: Bool,
                 completion: @escaping (Result<Data, Error>) -> Void) {
        connection = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        self.key = key
        request = SafariDNSBrokerMessage(version: 1, kind: kind, nonce: UUID().uuidString,
            issuedAt: SafariDNSBrokerWire.now(), tcp: tcp, payload: payload)
        callback = completion
    }

    func cancel() { queue.async { self.finish(.failure(SafariDNSBrokerError.stopped)) } }

    private func run(timeout: TimeInterval) {
        queue.async {
            let timer = DispatchWorkItem { self.finish(.failure(SafariDNSBrokerError.timeout)) }
            self.timer = timer
            self.queue.asyncAfter(deadline: .now() + timeout, execute: timer)
            self.connection.stateUpdateHandler = { state in
                switch state {
                case .ready: self.send()
                case .failed(let error): self.finish(.failure(error))
                case .cancelled: self.finish(.failure(SafariDNSBrokerError.stopped))
                default: break
                }
            }
            self.connection.start(queue: self.queue)
        }
    }

    private func send() {
        guard callback != nil, !sent else { return }
        sent = true
        do {
            let bytes = try SafariDNSBrokerWire.encode(request, key: key)
            connection.send(content: bytes, completion: .contentProcessed { error in
                if let error { self.finish(.failure(error)); return }
                SafariDNSBrokerWire.receive(self.connection) { result in
                    do {
                        let response = try SafariDNSBrokerWire.decode(result.get(), key: self.key, now: SafariDNSBrokerWire.now())
                        guard response.nonce == self.request.nonce else { throw SafariDNSBrokerError.authentication }
                        guard response.kind != "error" else { throw SafariDNSBrokerError.unavailable }
                        guard response.kind == self.request.kind + "_reply", response.tcp == self.request.tcp else {
                            throw SafariDNSBrokerError.invalidMessage
                        }
                        self.finish(.success(response.payload))
                    } catch { self.finish(.failure(error)) }
                }
            })
        } catch { finish(.failure(error)) }
    }

    private func finish(_ result: Result<Data, Error>) {
        guard let callback else { return }
        self.callback = nil
        timer?.cancel()
        timer = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        callback(result)
    }
}
