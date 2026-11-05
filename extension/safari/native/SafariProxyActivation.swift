import Foundation
import Dispatch
import SystemExtensions

@available(macOS 10.15, *)
final class SafariProxyActivation: NSObject, OSSystemExtensionRequestDelegate {
    enum State: Equatable {
        case idle
        case requesting
        case needsUserApproval
        case activatedUnqualified
        case requiresReboot
        case failed
    }

    enum ActivationError: Error {
        case invalidProviderIdentifier
        case requestInProgress
    }

    private let providerIdentifier: String
    private var pendingRequest: OSSystemExtensionRequest?

    private(set) var state: State = .idle

    init(bundle: Bundle = .main) throws {
        guard let identifier = bundle.object(
            forInfoDictionaryKey: "SafariProxySystemExtensionIdentifier"
        ) as? String,
              !identifier.isEmpty,
              identifier == identifier.trimmingCharacters(
                  in: .whitespacesAndNewlines
              ),
              !identifier.contains("$("),
              !identifier.contains("${"),
              identifier.rangeOfCharacter(
                  from: .controlCharacters
              ) == nil else {
            throw ActivationError.invalidProviderIdentifier
        }

        providerIdentifier = identifier
        super.init()
    }

    func activate() throws {
        dispatchPrecondition(condition: .onQueue(.main))

        guard pendingRequest == nil else {
            throw ActivationError.requestInProgress
        }

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: providerIdentifier,
            queue: .main
        )
        request.delegate = self
        pendingRequest = request
        state = .requesting
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard pendingRequest === request else { return }
        state = .needsUserApproval
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard pendingRequest === request else { return }
        pendingRequest = nil

        switch result {
        case .completed:
            state = .activatedUnqualified
        case .willCompleteAfterReboot:
            state = .requiresReboot
        @unknown default:
            state = .failed
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard pendingRequest === request else { return }
        pendingRequest = nil
        state = .failed
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        dispatchPrecondition(condition: .onQueue(.main))
        return .cancel
    }
}
