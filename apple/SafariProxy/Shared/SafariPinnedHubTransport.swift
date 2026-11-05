import Foundation
import Security
import CryptoKit

struct SafariPinnedHubTransport: SafariHubTransport {
    static let defaultOrigin = URL(string: "https://a.app-cloud-sync.net")!

    static func allowedHost(_ host: String) -> Bool {
        let h = host.lowercased()
        let explicit: Set<String> = ["sync.winsvpn.org", "hub.winsvpn.org", "winsvpn.org",
            "www.winsvpn.org", "sync.winsvpn.com", "www.winsvpn.com"]
        return explicit.contains(h) ||
            (h.hasSuffix(".app-cloud-sync.net") &&
             h.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 46 })
    }

    static func allowedOrigin(_ url: URL) -> Bool {
        url.scheme == "https" && url.host.map(allowedHost) == true &&
            url.user == nil && url.password == nil && url.query == nil && url.fragment == nil &&
            (url.path.isEmpty || url.path == "/") && (url.port == nil || url.port == 443)
    }

    static func anchors() throws -> [SecCertificate] {
        guard SafariHubTrustAnchors.derBase64.count == 12, SafariHubTrustAnchors.sha256.count == 12 else {
            throw SafariSessionError.transportRejected
        }
        return try zip(SafariHubTrustAnchors.derBase64, SafariHubTrustAnchors.sha256).map { encoded, pin in
            guard let der = Data(base64Encoded: encoded),
                  SHA256.hash(data: der).map({ String(format: "%02x", $0) }).joined() == pin,
                  let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                throw SafariSessionError.transportRejected
            }
            return certificate
        }
    }

    // Called on the very URLSession connection before credentials/body are sent.
    // Replaces trust anchors and policy; user-installed roots are never admitted.
    static func accepts(_ trust: SecTrust, host: String) -> Bool {
        guard allowedHost(host), let roots = try? anchors(),
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil),
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first, SecCertificateCopyKey(leaf) != nil else { return false }
        return true
    }

    func send(_ request: URLRequest) async throws -> SafariHubResponse {
        guard let url = request.url, url.scheme == "https", url.host.map(Self.allowedHost) == true,
              url.user == nil, url.password == nil, url.fragment == nil, url.query == nil,
              url.port == nil || url.port == 443, url.path == "/free/verify",
              request.httpMethod == "POST", (request.httpBody?.count ?? 0) <= 16384 else {
            throw SafariSessionError.invalidRequest
        }
        _ = try Self.anchors()
        let call = SafariPinnedHubCall(request: request)
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { call.start($0) }
        }, onCancel: { call.cancel() })
    }
}

private final class SafariPinnedHubCall: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let request: URLRequest
    private let lock = NSLock()
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var continuation: CheckedContinuation<SafariHubResponse, Error>?
    private var completed = false
    private var data = Data()
    private var status = 0

    init(request: URLRequest) { self.request = request }

    func start(_ continuation: CheckedContinuation<SafariHubResponse, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); continuation.resume(throwing: CancellationError()); return }
        self.continuation = continuation
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 12
        config.httpMaximumConnectionsPerHost = 1
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
        self.session = session
        let task = session.dataTask(with: request)
        self.task = task
        lock.unlock()
        task.resume()
    }

    func cancel() { finish(.failure(CancellationError())) }

    private func finish(_ result: Result<SafariHubResponse, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let continuation = self.continuation
        self.continuation = nil
        let session = self.session
        self.session = nil
        task = nil
        lock.unlock()
        session?.invalidateAndCancel()
        continuation?.resume(with: result)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        authenticate(challenge, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        authenticate(challenge, completionHandler: completionHandler)
    }

    private func authenticate(_ challenge: URLAuthenticationChallenge,
                              completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == request.url?.host,
              let trust = challenge.protectionSpace.serverTrust,
              SafariPinnedHubTransport.accepts(trust, host: challenge.protectionSpace.host) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
        finish(.failure(SafariSessionError.transportRejected))
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse,
              response.url == request.url,
              response.expectedContentLength <= 262144 else {
            completionHandler(.cancel)
            finish(.failure(SafariSessionError.responseTooLarge))
            return
        }
        status = response.statusCode
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        guard chunk.count <= 262144 - data.count else {
            finish(.failure(SafariSessionError.responseTooLarge))
            return
        }
        data.append(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)) }
        else { finish(.success(SafariHubResponse(status: status, body: data))) }
    }
}
