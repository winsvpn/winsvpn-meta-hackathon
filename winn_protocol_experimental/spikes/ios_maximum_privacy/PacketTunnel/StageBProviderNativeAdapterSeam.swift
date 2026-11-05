import CryptoKit
import Foundation
import WinnStageBProviderCore

enum StageBProviderNativeBridgeError: Error {
  case invalidNativeStatus(Int32)
  case invalidStartResult
  case invalidStartHandle
  case invalidStartReservedBytes
  case startConfigIdentityMismatch
  case startPeerIdentityMismatch
  case startGenerationMismatch
  case invalidCaptureResult
  case invalidStopResult
  case captureCounterExhausted
  case lifecycleConflict
  case staleProviderGeneration
  case ownerDestroyFailed(Int32)
}

/// The only Swift-owned view of a successful native Stage B start.
///
/// The concrete adapter remains provider-private.  This facade exposes only a
/// no-argument, closure-bound typed capture and explicit stop; raw UAPI bytes,
/// the raw lifecycle handle, and the secret start allocation never cross it.
final class StageBProviderNativeSession: @unchecked Sendable {
  private let adapter: StageBProviderNativeAdapter

  fileprivate init(adapter: StageBProviderNativeAdapter) {
    self.adapter = adapter
  }

  var binding: StageBProviderPathBinding {
    adapter.binding
  }

  func capture() throws -> StageBAWGSnapshot {
    try adapter.capture()
  }

  fileprivate func stopAndDestroy() throws {
    try adapter.stopAndDestroy()
  }
}

/// Provider-queue authority for starting, abandoning, and stopping a native
/// session.
///
/// Start runs on its own queue because framework loading, utun discovery, and
/// `wgTurnOn` may block.  Completion is always validated against this
/// authority's generation on the provider queue.  Abandon uses an independent
/// control queue so it can reach C while start is blocked.
final class StageBProviderNativeLifecycle: @unchecked Sendable {
  typealias PathBinder =
    @Sendable (StageBAWGEnginePathIdentity) throws
      -> StageBProviderPathBinding
  typealias StartCompletion =
    @Sendable (Result<StageBProviderNativeSession, Error>) -> Void

  private final class StartAuthority: @unchecked Sendable {
    let providerGeneration: UInt64

    init(providerGeneration: UInt64) {
      self.providerGeneration = providerGeneration
    }
  }

  private final class Pending: @unchecked Sendable {
    let providerGeneration: UInt64
    let owner: WinnStageBProviderNativeOwner
    let generation: WinnStageBProviderNativeGeneration

    init(
      providerGeneration: UInt64,
      owner: WinnStageBProviderNativeOwner,
      generation: WinnStageBProviderNativeGeneration
    ) {
      self.providerGeneration = providerGeneration
      self.owner = owner
      self.generation = generation
    }

    func abandon() {
      var owner = owner
      var generation = generation
      _ = withUnsafePointer(to: &owner) { ownerPointer in
        withUnsafePointer(to: &generation) { generationPointer in
          winn_stage_b_provider_native_owner_abandon(
            ownerPointer,
            generationPointer
          )
        }
      }
    }
  }

  private let providerQueue: DispatchQueue
  private let nativeStartQueue = DispatchQueue(
    label: "org.winsvpn.experimental.stage-b.native-start",
    qos: .userInitiated
  )
  private let nativeControlQueue = DispatchQueue(
    label: "org.winsvpn.experimental.stage-b.native-control",
    qos: .userInitiated
  )
  private var providerGeneration: UInt64 = 0
  private var activeStartAuthority: StartAuthority?
  private var pending: Pending?
  private var session: StageBProviderNativeSession?
  private var startWorkerInFlight = false
  private var stopCleanupInFlight = false
  private var terminalStopCompletions = [() -> Void]()
  // Retaining a failed session preserves the only tokenized cleanup authority.
  // It intentionally leaks instead of risking a second opaque void stop.
  private var retainedFailedSessions = [StageBProviderNativeSession]()

  init(providerQueue: DispatchQueue) {
    self.providerQueue = providerQueue
  }

  /// Transfers one C-populated start structure to the native queue.
  ///
  /// The pointer and its containing allocation must remain valid through
  /// completion.  Only C may populate its secret buffer.  Swift reads only the
  /// non-secret generation/digests before `owner_start` consumes and clears
  /// the structure; it never reads or copies `config.bytes`.
  func start(
    consumingNativeStart: UnsafeMutablePointer<
      WinnStageBProviderNativeStart
    >,
    environment: StageBProviderEnvironment,
    makeBinding: @escaping PathBinder,
    completion: @escaping StartCompletion
  ) {
    dispatchPrecondition(condition: .onQueue(providerQueue))
    guard activeStartAuthority == nil,
          pending == nil, session == nil,
          !startWorkerInFlight,
          !stopCleanupInFlight,
          terminalStopCompletions.isEmpty,
          retainedFailedSessions.isEmpty,
          providerGeneration < UInt64.max
    else {
      // Ownership was offered to this method.  Refusal still consumes through
      // the C erasure path so a caller cannot be left with ambiguous secret
      // ownership.
      winn_stage_b_provider_native_bridge_discard_start(
        consumingNativeStart
      )
      completion(.failure(
        StageBProviderNativeBridgeError.lifecycleConflict
      ))
      return
    }
    providerGeneration += 1
    let requestedGeneration = providerGeneration
    let authority = StartAuthority(
      providerGeneration: requestedGeneration
    )
    activeStartAuthority = authority
    startWorkerInFlight = true

    nativeStartQueue.async {
      do {
        let prepared = try StageBProviderNativeAdapter.prepare(
          consumingNativeStart: consumingNativeStart
        )
        let pending = Pending(
          providerGeneration: requestedGeneration,
          owner: prepared.owner,
          generation: prepared.generation
        )
        self.providerQueue.async {
          if self.activeStartAuthority === authority,
             self.providerGeneration == requestedGeneration,
             self.pending == nil,
             self.session == nil {
            self.pending = pending
          } else {
            self.nativeControlQueue.async {
              pending.abandon()
            }
          }
        }

        let result = Result {
          let adapter = try prepared.finish(
            environment: environment,
            makeBinding: makeBinding
          )
          return StageBProviderNativeSession(adapter: adapter)
        }
        self.providerQueue.async {
          let isCurrent =
            self.activeStartAuthority === authority
              && self.providerGeneration == requestedGeneration
              && self.pending === pending
          if isCurrent {
            self.activeStartAuthority = nil
            self.pending = nil
            self.startWorkerInFlight = false
            if case let .success(newSession) = result {
              self.session = newSession
            }
            completion(result)
            self.completeTerminalStopsIfPossible()
            return
          }
          if case let .success(staleSession) = result {
            self.nativeControlQueue.async {
              do {
                try staleSession.stopAndDestroy()
              } catch {
                self.providerQueue.async {
                  self.retainedFailedSessions.append(staleSession)
                  self.startWorkerInFlight = false
                  self.completeTerminalStopsIfPossible()
                }
                return
              }
              self.providerQueue.async {
                self.startWorkerInFlight = false
                self.completeTerminalStopsIfPossible()
              }
            }
          } else {
            self.startWorkerInFlight = false
            self.completeTerminalStopsIfPossible()
          }
          completion(.failure(
            StageBProviderNativeBridgeError.staleProviderGeneration
          ))
        }
      } catch {
        self.providerQueue.async {
          if self.activeStartAuthority === authority,
             self.providerGeneration == requestedGeneration {
            self.activeStartAuthority = nil
            self.pending = nil
            self.startWorkerInFlight = false
            completion(.failure(error))
          } else {
            self.startWorkerInFlight = false
            completion(.failure(
              StageBProviderNativeBridgeError.staleProviderGeneration
            ))
          }
          self.completeTerminalStopsIfPossible()
        }
      }
    }
  }

  func abandonCurrentStart() {
    dispatchPrecondition(condition: .onQueue(providerQueue))
    let abandoned = pending
    guard activeStartAuthority != nil || abandoned != nil else {
      return
    }
    activeStartAuthority = nil
    if providerGeneration < UInt64.max {
      providerGeneration += 1
    }
    self.pending = nil
    if let abandoned {
      nativeControlQueue.async {
        abandoned.abandon()
      }
    }
  }

  func stop(completion: @escaping () -> Void) {
    dispatchPrecondition(condition: .onQueue(providerQueue))
    terminalStopCompletions.append(completion)
    activeStartAuthority = nil
    if providerGeneration < UInt64.max {
      providerGeneration += 1
    }
    if let pending {
      self.pending = nil
      nativeControlQueue.async {
        pending.abandon()
      }
    }
    guard let session else {
      completeTerminalStopsIfPossible()
      return
    }
    self.session = nil
    stopCleanupInFlight = true
    nativeControlQueue.async {
      do {
        try session.stopAndDestroy()
      } catch {
        self.providerQueue.async {
          self.retainedFailedSessions.append(session)
        }
      }
      self.providerQueue.async {
        self.stopCleanupInFlight = false
        self.completeTerminalStopsIfPossible()
      }
    }
  }

  /// Releases every provider stop exactly once, but only after all native
  /// authority that existed when stop was requested has reached a terminal
  /// state. A retained failed session is terminal fail-closed: extension exit,
  /// rather than a second opaque stop, owns its eventual reclamation.
  private func completeTerminalStopsIfPossible() {
    dispatchPrecondition(condition: .onQueue(providerQueue))
    guard !startWorkerInFlight,
          !stopCleanupInFlight,
          pending == nil,
          session == nil
    else {
      return
    }
    let completions = terminalStopCompletions
    terminalStopCompletions.removeAll(keepingCapacity: true)
    completions.forEach { $0() }
  }
}

private final class StageBProviderNativeAdapter: @unchecked Sendable {
  fileprivate final class PreparedStart: @unchecked Sendable {
    fileprivate var owner: WinnStageBProviderNativeOwner
    fileprivate let generation: WinnStageBProviderNativeGeneration
    private let consumedStart:
      UnsafeMutablePointer<WinnStageBProviderNativeStart>
    private let configSHA256: [UInt8]
    private let expectedPeerPublicKey: [UInt8]
    private let expectedPeerSHA256: [UInt8]
    private let engineGeneration: UInt64
    private let pathGeneration: UInt64

    fileprivate init(
      owner: WinnStageBProviderNativeOwner,
      generation: WinnStageBProviderNativeGeneration,
      consumedStart: UnsafeMutablePointer<WinnStageBProviderNativeStart>,
      configSHA256: [UInt8],
      expectedPeerPublicKey: [UInt8],
      engineGeneration: UInt64,
      pathGeneration: UInt64
    ) {
      self.owner = owner
      self.generation = generation
      self.consumedStart = consumedStart
      self.configSHA256 = configSHA256
      self.expectedPeerPublicKey = expectedPeerPublicKey
      expectedPeerSHA256 = Array(
        SHA256.hash(data: Data(expectedPeerPublicKey))
      )
      self.engineGeneration = engineGeneration
      self.pathGeneration = pathGeneration
    }

    fileprivate func finish(
      environment: StageBProviderEnvironment,
      makeBinding: StageBProviderNativeLifecycle.PathBinder
    ) throws -> StageBProviderNativeAdapter {
      var result = WinnStageBProviderNativeStartResult()
      let status = withUnsafePointer(to: &owner) { ownerPointer in
        winn_stage_b_provider_native_owner_start(
          ownerPointer,
          consumedStart,
          &result
        )
      }
      guard status == WINN_STAGE_B_PROVIDER_NATIVE_OK else {
        Self.cleanupFailedStart(
          owner: &owner,
          generation: generation,
          lifecycleHandle: result.lifecycle_handle
        )
        throw StageBProviderNativeBridgeError.invalidNativeStatus(
          Int32(status.rawValue)
        )
      }

      do {
        let nativeIdentity = result.identity
        guard result.lifecycle_handle >= 0 else {
          throw StageBProviderNativeBridgeError.invalidStartHandle
        }
        guard Self.bytes(result.reserved, count: 4)
          .allSatisfy({ $0 == 0 })
        else {
          throw StageBProviderNativeBridgeError
            .invalidStartReservedBytes
        }
        guard Self.bytes(nativeIdentity.config_sha256, count: 32)
          == configSHA256
        else {
          throw StageBProviderNativeBridgeError
            .startConfigIdentityMismatch
        }
        guard Self.bytes(
          nativeIdentity.expected_peer_sha256,
          count: 32
        ) == expectedPeerSHA256 else {
          throw StageBProviderNativeBridgeError
            .startPeerIdentityMismatch
        }
        guard nativeIdentity.engine_generation == engineGeneration,
              nativeIdentity.path_generation == pathGeneration
        else {
          throw StageBProviderNativeBridgeError
            .startGenerationMismatch
        }

        let identity = try StageBAWGEnginePathIdentity(
          signedRuntimeArtifactSHA256: Self.bytes(
            result.signed_runtime_sha256,
            count: 32
          ),
          wgTurnOnConfigSHA256: configSHA256,
          expectedPeerPublicKeySHA256: expectedPeerSHA256,
          engineInstanceNonce: Self.bytes(
            nativeIdentity.engine_instance_uuid,
            count: 16
          ),
          engineGeneration: engineGeneration,
          pathGeneration: pathGeneration,
          winningInterfaceTokenSHA256: Self.bytes(
            nativeIdentity.winning_interface_token_sha256,
            count: 32
          )
        )
        let binding = try makeBinding(identity)
        guard binding.identity == identity else {
          throw StageBProviderNativeBridgeError.invalidStartResult
        }
        let captureState = CaptureState(
          owner: owner,
          generation: generation,
          nativeIdentity: nativeIdentity,
          expectedPeerPublicKey: expectedPeerPublicKey,
          lifecycleHandle: result.lifecycle_handle
        )
        let captureSource =
          try environment.makeNativeAWGCaptureSource(
            binding: binding,
            expectedPeerPublicKey: expectedPeerPublicKey,
            readNativeTelemetry: {
              try captureState.readNativeTelemetry()
            }
          )
        return StageBProviderNativeAdapter(
          binding: binding,
          captureState: captureState,
          captureSource: captureSource
        )
      } catch {
        Self.cleanupFailedStart(
          owner: &owner,
          generation: generation,
          lifecycleHandle: result.lifecycle_handle
        )
        throw error
      }
    }

    private static func cleanupFailedStart(
      owner: inout WinnStageBProviderNativeOwner,
      generation: WinnStageBProviderNativeGeneration,
      lifecycleHandle: Int32
    ) {
      if lifecycleHandle >= 0 {
        var generation = generation
        var stop = WinnStageBProviderNativeStopResult()
        let stopStatus = withUnsafePointer(to: &owner) { ownerPointer in
          withUnsafePointer(to: &generation) { generationPointer in
            winn_stage_b_provider_native_owner_stop(
              ownerPointer,
              generationPointer,
              lifecycleHandle,
              &stop
            )
          }
        }
        guard stopStatus == WINN_STAGE_B_PROVIDER_NATIVE_OK,
              stop.invocation
                == WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED,
              stop.lifecycle_handle == lifecycleHandle,
              stop.lifecycle_acknowledgement_permitted == 1,
              stop.owner_poisoned_after_invocation == 0,
              bytes(stop.reserved, count: 2).allSatisfy({ $0 == 0 })
        else {
          return
        }
      }
      _ = winn_stage_b_provider_native_owner_destroy(&owner)
    }

    fileprivate static func bytes<T>(
      _ value: T,
      count: Int
    ) -> [UInt8] {
      var copy = value
      return withUnsafeBytes(of: &copy) {
        Array($0.prefix(count))
      }
    }
  }

  private final class CaptureState: @unchecked Sendable {
    private var owner: WinnStageBProviderNativeOwner
    private let generation: WinnStageBProviderNativeGeneration
    private let nativeIdentity: WinnStageBNativeIdentity
    private let expectedPeerPublicKey: [UInt8]
    private let expectedPeerSHA256: [UInt8]
    private let lifecycleHandle: Int32
    private var nextCaptureOrdinal: UInt64 = 1
    private var stopWasAttempted = false
    private var destroyed = false
    private let lock = NSLock()

    init(
      owner: WinnStageBProviderNativeOwner,
      generation: WinnStageBProviderNativeGeneration,
      nativeIdentity: WinnStageBNativeIdentity,
      expectedPeerPublicKey: [UInt8],
      lifecycleHandle: Int32
    ) {
      self.owner = owner
      self.generation = generation
      self.nativeIdentity = nativeIdentity
      self.expectedPeerPublicKey = expectedPeerPublicKey
      expectedPeerSHA256 = Array(
        SHA256.hash(data: Data(expectedPeerPublicKey))
      )
      self.lifecycleHandle = lifecycleHandle
    }

    func readNativeTelemetry() throws -> StageBAWGNativePeerTelemetry {
      lock.lock()
      defer { lock.unlock() }
      guard !stopWasAttempted, !destroyed else {
        throw StageBProviderNativeBridgeError.lifecycleConflict
      }
      var capture = WinnStageBProviderNativeCapture()
      var owner = owner
      var generation = generation
      let status = withUnsafePointer(to: &owner) { ownerPointer in
        withUnsafePointer(to: &generation) { generationPointer in
          winn_stage_b_provider_native_owner_capture(
            ownerPointer,
            generationPointer,
            &capture
          )
        }
      }
      guard status == WINN_STAGE_B_PROVIDER_NATIVE_OK else {
        throw StageBProviderNativeBridgeError.invalidNativeStatus(
          Int32(status.rawValue)
        )
      }
      guard capture.capture_ordinal == nextCaptureOrdinal,
            Self.identitiesEqual(
              capture.observation.identity,
              nativeIdentity
            )
      else {
        throw StageBProviderNativeBridgeError.invalidCaptureResult
      }
      let telemetry = capture.observation.telemetry
      let peerPublicKey = Self.bytes(
        telemetry.peer_public_key,
        count: 32
      )
      guard peerPublicKey == expectedPeerPublicKey,
            Array(SHA256.hash(data: Data(peerPublicKey)))
              == expectedPeerSHA256,
            Self.bytes(telemetry.reserved, count: 4)
              .allSatisfy({ $0 == 0 }),
            telemetry.latest_handshake_nanoseconds < 1_000_000_000
      else {
        throw StageBProviderNativeBridgeError.invalidCaptureResult
      }
      let fractionalMilliseconds =
        UInt64(telemetry.latest_handshake_nanoseconds) / 1_000_000
      guard telemetry.latest_handshake_unix_seconds
        <= (UInt64.max - fractionalMilliseconds) / 1_000
      else {
        throw StageBProviderNativeBridgeError.invalidCaptureResult
      }
      guard nextCaptureOrdinal < UInt64.max else {
        throw StageBProviderNativeBridgeError.captureCounterExhausted
      }
      nextCaptureOrdinal += 1
      return try StageBAWGNativePeerTelemetry(
        peerPublicKey: peerPublicKey,
        latestHandshakeUnixSeconds:
          telemetry.latest_handshake_unix_seconds,
        latestHandshakeNanoseconds:
          telemetry.latest_handshake_nanoseconds,
        receivedBytes: telemetry.received_bytes,
        transmittedBytes: telemetry.transmitted_bytes
      )
    }

    func stopAndDestroy() throws {
      lock.lock()
      defer { lock.unlock() }
      guard !stopWasAttempted, !destroyed else {
        throw StageBProviderNativeBridgeError.lifecycleConflict
      }
      stopWasAttempted = true
      var stop = WinnStageBProviderNativeStopResult()
      var generation = generation
      let status = withUnsafePointer(to: &owner) { ownerPointer in
        withUnsafePointer(to: &generation) { generationPointer in
          winn_stage_b_provider_native_owner_stop(
            ownerPointer,
            generationPointer,
            lifecycleHandle,
            &stop
          )
        }
      }
      guard status == WINN_STAGE_B_PROVIDER_NATIVE_OK else {
        // If the void invocation returned, C has already made retry
        // impermissible.  If it did not return, this bridge still refuses an
        // automatic retry: retaining the tokenized owner is safer than an
        // accidental double-stop after an ambiguous foreign failure.
        throw StageBProviderNativeBridgeError.invalidNativeStatus(
          Int32(status.rawValue)
        )
      }
      guard stop.invocation
                == WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED,
            stop.lifecycle_handle == lifecycleHandle,
            stop.lifecycle_acknowledgement_permitted == 1,
            stop.owner_poisoned_after_invocation == 0,
            Self.bytes(stop.reserved, count: 2)
              .allSatisfy({ $0 == 0 })
      else {
        throw StageBProviderNativeBridgeError.invalidStopResult
      }
      let destroyStatus =
        winn_stage_b_provider_native_owner_destroy(&owner)
      guard destroyStatus == WINN_STAGE_B_PROVIDER_NATIVE_OK else {
        throw StageBProviderNativeBridgeError.ownerDestroyFailed(
          Int32(destroyStatus.rawValue)
        )
      }
      destroyed = true
    }

    private static func identitiesEqual(
      _ lhs: WinnStageBNativeIdentity,
      _ rhs: WinnStageBNativeIdentity
    ) -> Bool {
      bytes(lhs.engine_instance_uuid, count: 16)
          == bytes(rhs.engine_instance_uuid, count: 16)
        && bytes(lhs.winning_interface_token_sha256, count: 32)
          == bytes(rhs.winning_interface_token_sha256, count: 32)
        && bytes(lhs.expected_peer_sha256, count: 32)
          == bytes(rhs.expected_peer_sha256, count: 32)
        && bytes(lhs.config_sha256, count: 32)
          == bytes(rhs.config_sha256, count: 32)
        && lhs.engine_generation == rhs.engine_generation
        && lhs.path_generation == rhs.path_generation
    }

    private static func bytes<T>(
      _ value: T,
      count: Int
    ) -> [UInt8] {
      var copy = value
      return withUnsafeBytes(of: &copy) {
        Array($0.prefix(count))
      }
    }
  }

  let binding: StageBProviderPathBinding
  private let captureState: CaptureState
  private let captureSource: StageBAWGNativeCaptureSource

  private init(
    binding: StageBProviderPathBinding,
    captureState: CaptureState,
    captureSource: StageBAWGNativeCaptureSource
  ) {
    self.binding = binding
    self.captureState = captureState
    self.captureSource = captureSource
  }

  static func prepare(
    consumingNativeStart: UnsafeMutablePointer<
      WinnStageBProviderNativeStart
    >
  ) throws -> PreparedStart {
    let start = consumingNativeStart.pointee
    let generation = start.generation
    let configSHA256 = PreparedStart.bytes(
      start.config_sha256,
      count: 32
    )
    let expectedPeerPublicKey = PreparedStart.bytes(
      start.expected_peer_public_key,
      count: 32
    )
    var owner = WinnStageBProviderNativeOwner()
    let status =
      winn_stage_b_provider_native_owner_create(&owner)
    guard status == WINN_STAGE_B_PROVIDER_NATIVE_OK else {
      winn_stage_b_provider_native_bridge_discard_start(
        consumingNativeStart
      )
      throw StageBProviderNativeBridgeError.invalidNativeStatus(
        Int32(status.rawValue)
      )
    }
    return PreparedStart(
      owner: owner,
      generation: generation,
      consumedStart: consumingNativeStart,
      configSHA256: configSHA256,
      expectedPeerPublicKey: expectedPeerPublicKey,
      engineGeneration: start.engine_generation,
      pathGeneration: start.path_generation
    )
  }

  func capture() throws -> StageBAWGSnapshot {
    try captureSource.capture()
  }

  func stopAndDestroy() throws {
    try captureState.stopAndDestroy()
  }
}
