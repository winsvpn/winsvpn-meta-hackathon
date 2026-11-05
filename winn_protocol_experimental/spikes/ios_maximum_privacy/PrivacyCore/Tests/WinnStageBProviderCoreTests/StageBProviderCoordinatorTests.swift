import CryptoKit
import Foundation
import WinnPrivacyCore
import WinnStageBProviderCore
import XCTest

// This target imports `WinnStageBProviderCore` without `@testable` on
// purpose. `StageBAWGSnapshot` has no public initializer, so every sample in
// this file must come from a real `StageBAWGNativeCaptureSource` capture. A
// hand-built sample would not compile here, which is the property the
// coordinator relies on.

final class StageBProviderCoordinatorTests: XCTestCase {
  private let t0: UInt64 = 1_000_000
  private let key = [UInt8](repeating: 0x41, count: 32)

  func testFirstClickT0IsCopiedUnchangedAndRequestDoesNotResetIt()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 123)
    let coordinator = try harness.makeCoordinator()

    XCTAssertEqual(
      coordinator.lease.requestedAtMonotonicNanoseconds,
      t0
    )
    XCTAssertEqual(
      coordinator.lease.deadlineMonotonicNanoseconds,
      t0 + StageBProtectedFlow.deadlineNanoseconds
    )
    let verified = try StageBReflectorCodec.verifyRequest(
      coordinator.outboundReflectorDatagram,
      key: key,
      reflectorNowUnixMilliseconds: 1_500
    )
    XCTAssertEqual(
      verified.request.requestSentMonotonicNanoseconds,
      t0 + 123
    )
    XCTAssertEqual(
      verified.request.attemptNonce,
      harness.fixture.attemptNonce
    )
    XCTAssertNil(coordinator.terminalEvidence())
  }

  func testAllPredicatesPassAtExactInclusiveDeadline() throws {
    let deadline = t0 + StageBProtectedFlow.deadlineNanoseconds
    let harness = try Harness(t0: t0, key: key, now: t0)
    let coordinator = try harness.makeCoordinator()
    let response = try response(for: coordinator)
    harness.clock.set(deadline)
    let ladder = try harness.ladder()

    XCTAssertEqual(
      try coordinator.recordProtectedDNSRequestSent(
        harness.dnsSendProof(ladder)
      ),
      .accepted
    )
    XCTAssertEqual(
      try coordinator.recordProtectedDNSProof(
        harness.dnsProof(ladder)
      ),
      .accepted
    )
    XCTAssertEqual(
      try coordinator.recordReflectorRequestSent(
        harness.reflectorSendProof(ladder, for: coordinator)
      ),
      .accepted
    )
    XCTAssertEqual(
      try coordinator.acceptReflectorResponse(
        harness.reflectorProof(ladder, response: response)
      ),
      .accepted
    )

    let snapshot = coordinator.localSnapshot()
    XCTAssertEqual(snapshot.status, .succeeded)
    XCTAssertNil(snapshot.failure)
    XCTAssertTrue(snapshot.freshAWGHandshake)
    XCTAssertTrue(snapshot.authenticatedTunnelBytes)
    XCTAssertTrue(snapshot.protectedDNSResponse)
    XCTAssertTrue(snapshot.authenticatedReflectorResponse)
    XCTAssertEqual(snapshot.measurementScope, "local-conformance-only")
  }

  func testEventAtDeadlinePlusOneFailsClosed() throws {
    let harness = try Harness(t0: t0, key: key, now: t0)
    let coordinator = try harness.makeCoordinator()
    let current = try harness.currentSample()
    harness.clock.set(t0 + StageBProtectedFlow.deadlineNanoseconds + 1)

    XCTAssertThrowsError(
      try coordinator.recordAWGSnapshot(current)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .deadlineExceeded
      )
    }
    XCTAssertEqual(coordinator.localSnapshot().status, .failed)
    XCTAssertEqual(
      coordinator.localSnapshot().failure,
      .deadlineExceeded
    )
  }

  func testTimerAtExactDeadlineRequiresExplicitPlusOneRearm()
    throws
  {
    let deadline = t0 + StageBProtectedFlow.deadlineNanoseconds
    let harness = try Harness(t0: t0, key: key, now: t0)
    let coordinator = try harness.makeCoordinator()
    let current = try harness.currentSample()
    harness.clock.set(deadline)

    XCTAssertEqual(
      coordinator.handleTimeoutFired(),
      .rearm(atMonotonicNanoseconds: deadline + 1)
    )
    XCTAssertEqual(coordinator.localSnapshot().status, .active)

    harness.clock.set(deadline + 1)
    XCTAssertEqual(coordinator.handleTimeoutFired(), .terminal)
    XCTAssertEqual(coordinator.localSnapshot().status, .failed)
    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(current),
      .ignoredTerminal
    )
  }

  func testTimerRollbackBelowT0TerminalizesFailClosed() throws {
    let harness = try Harness(t0: t0, key: key, now: t0)
    let coordinator = try harness.makeCoordinator()
    harness.clock.set(t0 - 1)

    XCTAssertEqual(coordinator.handleTimeoutFired(), .terminal)
    XCTAssertEqual(coordinator.localSnapshot().status, .failed)
    XCTAssertEqual(
      coordinator.localSnapshot().failure,
      .invalidDeadline
    )
    XCTAssertEqual(coordinator.handleTimeoutFired(), .ignoredTerminal)
  }

  func testNearUInt64MaxDeadlinePlusOneRejectsEveryEventClass()
    throws
  {
    let nearMaxT0 =
      UInt64.max - StageBProtectedFlow.deadlineNanoseconds - 1

    func assertDeadlineFailure(
      after prefix:
        (Harness, StageBProviderCoordinator, Ladder) throws -> Void = {
          _, _, _ in
        },
      operation:
        (Harness, StageBProviderCoordinator, Ladder) throws -> Void,
      file: StaticString = #filePath,
      line: UInt = #line
    ) throws {
      let harness = try Harness(
        t0: nearMaxT0,
        key: key,
        now: nearMaxT0
      )
      let coordinator = try harness.makeCoordinator()
      let ladder = try harness.ladder()
      try prefix(harness, coordinator, ladder)
      harness.clock.set(UInt64.max)
      XCTAssertThrowsError(
        try operation(harness, coordinator, ladder),
        file: file,
        line: line
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .deadlineExceeded,
          file: file,
          line: line
        )
      }
    }

    try assertDeadlineFailure(
      operation: { _, coordinator, ladder in
        _ = try coordinator.recordAWGSnapshot(ladder.dnsPre)
      }
    )
    try assertDeadlineFailure(
      operation: { harness, coordinator, ladder in
        _ = try coordinator.recordProtectedDNSRequestSent(
          harness.dnsSendProof(ladder)
        )
      }
    )
    try assertDeadlineFailure(
      operation: { harness, coordinator, ladder in
        _ = try coordinator.recordReflectorRequestSent(
          harness.reflectorSendProof(ladder, for: coordinator)
        )
      }
    )
    try assertDeadlineFailure(
      after: { harness, coordinator, ladder in
        _ = try coordinator.recordProtectedDNSRequestSent(
          harness.dnsSendProof(ladder)
        )
      },
      operation: { harness, coordinator, ladder in
        _ = try coordinator.recordProtectedDNSProof(
          harness.dnsProof(ladder)
        )
      }
    )
    try assertDeadlineFailure(
      after: { harness, coordinator, ladder in
        try harness.driveToReflectorSend(coordinator, ladder)
      },
      operation: { harness, coordinator, ladder in
        _ = try coordinator.acceptReflectorResponse(
          harness.reflectorProof(
            ladder,
            response: try self.response(for: coordinator)
          )
        )
      }
    )

    let harness = try Harness(
      t0: nearMaxT0,
      key: key,
      now: nearMaxT0 + StageBProtectedFlow.deadlineNanoseconds
    )
    let timer = try harness.makeCoordinator()
    XCTAssertEqual(
      timer.handleTimeoutFired(),
      .rearm(atMonotonicNanoseconds: UInt64.max)
    )
    harness.clock.set(UInt64.max)
    XCTAssertEqual(timer.handleTimeoutFired(), .terminal)
    XCTAssertEqual(timer.localSnapshot().failure, .deadlineExceeded)
  }

  func testRepeatedAWGPollsAreCoalescedAndCoreIsCalledOnce()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let coordinator = try harness.makeCoordinator()

    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(harness.baseline),
      .coalesced
    )
    let current = try harness.currentSample()
    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(current),
      .accepted
    )
    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(current),
      .coalesced
    )
    XCTAssertTrue(coordinator.localSnapshot().freshAWGHandshake)
    XCTAssertTrue(coordinator.localSnapshot().authenticatedTunnelBytes)
  }

  func testCounterAndRawHandshakeRollbackFailClosed() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)

    let counterReset = try harness.makeCoordinator()
    XCTAssertThrowsError(
      try counterReset.recordAWGSnapshot(
        try harness.sample(
          handshake: harness.fixture.baselineHandshake,
          received: harness.fixture.baselineReceived - 1,
          transmitted: harness.fixture.baselineTransmitted
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .counterReset
      )
    }

    let handshakeReset = try harness.makeCoordinator()
    XCTAssertThrowsError(
      try handshakeReset.recordAWGSnapshot(
        try harness.sample(
          handshake: harness.fixture.baselineHandshake - 1,
          received: harness.fixture.baselineReceived,
          transmitted: harness.fixture.baselineTransmitted
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .handshakeReset
      )
    }
  }

  func testRawHandshakeIsNeverConvertedToMonotonicTime() throws {
    let harness = try Harness(t0: t0, key: key, now: t0)
    let coordinator = try harness.makeCoordinator()
    let rawWallTimeFarBeyondMonotonicClock = try harness.sample(
      handshake: UInt64.max / 1_000,
      received: harness.fixture.baselineReceived + 1,
      transmitted: harness.fixture.baselineTransmitted + 1
    )

    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(
        rawWallTimeFarBeyondMonotonicClock
      ),
      .accepted
    )
    XCTAssertTrue(coordinator.localSnapshot().freshAWGHandshake)
  }

  func testSameSecondMillisecondAdvanceIsFreshAndNanosecondRollbackFails()
    throws
  {
    let harness = try Harness(
      t0: t0,
      key: key,
      now: t0,
      baselineHandshakeNanoseconds: 100_000_000
    )
    let coordinator = try harness.makeCoordinator()

    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(
        try harness.sample(
          handshake: harness.fixture.baselineHandshake,
          handshakeNanoseconds: 101_000_000,
          received: harness.fixture.baselineReceived + 1,
          transmitted: harness.fixture.baselineTransmitted + 1
        )
      ),
      .accepted
    )
    XCTAssertTrue(coordinator.localSnapshot().freshAWGHandshake)

    XCTAssertThrowsError(
      try coordinator.recordAWGSnapshot(
        try harness.sample(
          handshake: harness.fixture.baselineHandshake,
          handshakeNanoseconds: 100_999_999,
          received: harness.fixture.baselineReceived + 2,
          transmitted: harness.fixture.baselineTransmitted + 2
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .handshakeReset
      )
    }
  }

  /// A sub-millisecond handshake advance is not physical freshness, so bytes
  /// that move on it are an out-of-order predicate rather than a success.
  func testSubMillisecondAdvanceIsNotFreshAndCannotCarryBytes() throws {
    let harness = try Harness(
      t0: t0,
      key: key,
      now: t0,
      baselineHandshakeNanoseconds: 100_000_000
    )
    let subMillisecond = try harness.makeCoordinator()

    XCTAssertThrowsError(
      try subMillisecond.recordAWGSnapshot(
        try harness.sample(
          handshake: harness.fixture.baselineHandshake,
          handshakeNanoseconds: 100_999_999,
          received: harness.fixture.baselineReceived + 1,
          transmitted: harness.fixture.baselineTransmitted + 1
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .predicateLadderViolation
      )
    }
    XCTAssertFalse(subMillisecond.localSnapshot().freshAWGHandshake)
    XCTAssertFalse(
      subMillisecond.localSnapshot().authenticatedTunnelBytes
    )

    // Positive control: the identical byte movement one full millisecond
    // later is accepted, so the rejection above is the freshness rule and
    // not the byte movement.
    let fullMillisecond = try harness.makeCoordinator()
    XCTAssertEqual(
      try fullMillisecond.recordAWGSnapshot(
        try harness.sample(
          handshake: harness.fixture.baselineHandshake,
          handshakeNanoseconds: 101_000_000,
          received: harness.fixture.baselineReceived + 1,
          transmitted: harness.fixture.baselineTransmitted + 1
        )
      ),
      .accepted
    )
    XCTAssertTrue(fullMillisecond.localSnapshot().freshAWGHandshake)
    XCTAssertTrue(
      fullMillisecond.localSnapshot().authenticatedTunnelBytes
    )
  }

  func testExactPeerSnapshotShapeAndWrongPeerOrBindingAreRejected()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture

    let labels = Set(
      Mirror(reflecting: try harness.currentSample())
        .children
        .compactMap(\.label)
    )
    XCTAssertEqual(
      labels,
      [
        "binding",
        "peer",
        "provenance",
        "sampleStartedAtMonotonicNanoseconds",
        "sampledAtMonotonicNanoseconds",
      ]
    )
    XCTAssertFalse(labels.contains("peers"))

    // A capture source cannot claim a peer whose key it does not hold: the
    // raw key must be the preimage of the binding's expected peer digest.
    XCTAssertThrowsError(
      try harness.environment.makeNativeAWGCaptureSource(
        binding: fixture.path,
        expectedPeerPublicKey: [UInt8](repeating: 0x99, count: 32),
        readNativeTelemetry: {
          try fixture.telemetry(
            handshake: fixture.baselineHandshake,
            received: fixture.baselineReceived,
            transmitted: fixture.baselineTransmitted
          )
        }
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }
    XCTAssertThrowsError(
      try harness.environment.makeNativeAWGCaptureSource(
        binding: fixture.path,
        expectedPeerPublicKey: [UInt8](repeating: 0x55, count: 31),
        readNativeTelemetry: {
          try fixture.telemetry(
            handshake: fixture.baselineHandshake,
            received: fixture.baselineReceived,
            transmitted: fixture.baselineTransmitted
          )
        }
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDigest
      )
    }

    let wrongContext = try WCF3ConnectionContext(
      sessionID: fixture.context.sessionID,
      bindingID: fixture.context.bindingID,
      pskGeneration: fixture.context.pskGeneration + 1,
      sequenceEpoch: fixture.context.sequenceEpoch
    )
    let wrongBindings = [
      try fixture.alteredPath(pathID: stageBUUID(0xac)),
      try fixture.alteredPath(
        signedRuntimeArtifactSHA256:
          [UInt8](repeating: 0xc1, count: 32)
      ),
      try fixture.alteredPath(
        wgTurnOnConfigSHA256:
          [UInt8](repeating: 0xc2, count: 32)
      ),
      try fixture.alteredPath(
        engineInstanceNonce: stageBUUID(0xad)
      ),
      try fixture.alteredPath(engineGeneration: 99),
      try fixture.alteredPath(pathGeneration: 99),
      try fixture.alteredPath(
        winningInterfaceTokenSHA256:
          [UInt8](repeating: 0xcc, count: 32)
      ),
      try fixture.alteredPath(context: wrongContext),
    ]
    for binding in wrongBindings {
      let target = try harness.makeCoordinator()
      let foreignFeed = TestTelemetryFeed(
        try fixture.telemetry(
          handshake: fixture.baselineHandshake + 1,
          received: fixture.baselineReceived + 1,
          transmitted: fixture.baselineTransmitted + 1
        )
      )
      let foreignSource =
        try harness.environment.makeNativeAWGCaptureSource(
          binding: binding,
          expectedPeerPublicKey: fixture.peerKey,
          readNativeTelemetry: { try foreignFeed.read() }
        )
      XCTAssertThrowsError(
        try target.recordAWGSnapshot(
          try harness.sample(
            handshake: fixture.baselineHandshake + 1,
            received: fixture.baselineReceived + 1,
            transmitted: fixture.baselineTransmitted + 1,
            from: foreignSource,
            feed: foreignFeed
          )
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .bindingMismatch
        )
      }
    }

    // The expected-peer digest cannot even be altered in a binding a capture
    // source will accept, because no key hashes to the altered digest.
    XCTAssertThrowsError(
      try harness.environment.makeNativeAWGCaptureSource(
        binding: try fixture.alteredPath(
          expectedPeerPublicKeySHA256:
            [UInt8](repeating: 0xc3, count: 32)
        ),
        expectedPeerPublicKey: fixture.peerKey,
        readNativeTelemetry: {
          try fixture.telemetry(
            handshake: fixture.baselineHandshake,
            received: fixture.baselineReceived,
            transmitted: fixture.baselineTransmitted
          )
        }
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }

    XCTAssertThrowsError(
      try StageBAWGPeerSnapshot(
        peerPublicKeySHA256: [],
        latestHandshakeUnixSeconds: 0,
        receivedBytes: 0,
        transmittedBytes: 0
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDigest
      )
    }
  }

  func testNativeCaptureSourceBindsTypedClosureAndCaptureHasNoInputs()
    throws
  {
    let fixture = try Fixture(t0: t0)
    let clock = TestClock(t0)
    let calls = LockedCounter()
    let feed = TestTelemetryFeed(
      try fixture.telemetry(
        handshake: fixture.baselineHandshake,
        received: fixture.baselineReceived,
        transmitted: fixture.baselineTransmitted
      )
    )
    let environment = try StageBProviderEnvironment(
      responseReplayCapacity: 4,
      reflectorKey: key,
      monotonicClock: { clock() }
    )
    let source = try environment.makeNativeAWGCaptureSource(
      binding: fixture.path,
      expectedPeerPublicKey: fixture.peerKey,
      readNativeTelemetry: {
        calls.increment()
        return try feed.read()
      }
    )

    let first = try source.capture()
    feed.set(
      try fixture.telemetry(
        handshake: fixture.baselineHandshake + 1,
        received: UInt64.max,
        transmitted: UInt64.max
      )
    )
    let second = try source.capture()

    XCTAssertEqual(calls.value, 2)
    XCTAssertEqual(first.binding, fixture.path)
    XCTAssertEqual(second.binding, fixture.path)
    XCTAssertEqual(second.peer.receivedBytes, UInt64.max)
    XCTAssertEqual(second.peer.transmittedBytes, UInt64.max)
    XCTAssertEqual(first.provenance, second.provenance)
  }

  func testNativeCaptureRejectsClosurePeerMismatch() throws {
    let fixture = try Fixture(t0: t0)
    let clock = TestClock(t0)
    let environment = try StageBProviderEnvironment(
      responseReplayCapacity: 4,
      reflectorKey: key,
      monotonicClock: { clock() }
    )
    let source = try environment.makeNativeAWGCaptureSource(
      binding: fixture.path,
      expectedPeerPublicKey: fixture.peerKey,
      readNativeTelemetry: {
        try StageBAWGNativePeerTelemetry(
          peerPublicKey: [UInt8](repeating: 0x99, count: 32),
          latestHandshakeUnixSeconds: fixture.baselineHandshake,
          latestHandshakeNanoseconds: 0,
          receivedBytes: fixture.baselineReceived,
          transmittedBytes: fixture.baselineTransmitted
        )
      }
    )

    XCTAssertThrowsError(try source.capture()) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }
  }

  func testNativeCaptureRejectsClockRollbackAcrossBoundClosure()
    throws
  {
    let fixture = try Fixture(t0: t0)
    let clock = TestClock(t0)
    let environment = try StageBProviderEnvironment(
      responseReplayCapacity: 4,
      reflectorKey: key,
      monotonicClock: { clock() }
    )
    let source = try environment.makeNativeAWGCaptureSource(
      binding: fixture.path,
      expectedPeerPublicKey: fixture.peerKey,
      readNativeTelemetry: {
        try fixture.telemetry(
          handshake: fixture.baselineHandshake,
          received: fixture.baselineReceived,
          transmitted: fixture.baselineTransmitted
        )
      }
    )
    clock.scheduleReadValue(after: 1, to: t0 - 1)

    XCTAssertThrowsError(try source.capture()) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDeadline
      )
    }
  }

  func testNativeCapturePropagatesBoundClosureFailure() throws {
    let fixture = try Fixture(t0: t0)
    let clock = TestClock(t0)
    let calls = LockedCounter()
    let environment = try StageBProviderEnvironment(
      responseReplayCapacity: 4,
      reflectorKey: key,
      monotonicClock: { clock() }
    )
    let source = try environment.makeNativeAWGCaptureSource(
      binding: fixture.path,
      expectedPeerPublicKey: fixture.peerKey,
      readNativeTelemetry: {
        calls.increment()
        throw TestNativeTelemetryError.readFailed
      }
    )

    XCTAssertThrowsError(try source.capture()) {
      XCTAssertEqual($0 as? TestNativeTelemetryError, .readFailed)
    }
    XCTAssertEqual(calls.value, 1)
  }

  func testNativeTelemetryExactBounds() throws {
    let fixture = try Fixture(t0: t0)
    let maximumNanoseconds =
      StageBAWGNativePeerTelemetry.maximumHandshakeNanoseconds
    let fractionalMilliseconds =
      UInt64(maximumNanoseconds) / 1_000_000
    let maximumSeconds =
      (UInt64.max - fractionalMilliseconds) / 1_000
    let maximum = try StageBAWGNativePeerTelemetry(
      peerPublicKey: fixture.peerKey,
      latestHandshakeUnixSeconds: maximumSeconds,
      latestHandshakeNanoseconds: maximumNanoseconds,
      receivedBytes: UInt64.max,
      transmittedBytes: UInt64.max
    )

    XCTAssertEqual(
      maximum.peerPublicKey.count,
      StageBAWGNativePeerTelemetry.peerPublicKeyByteCount
    )
    XCTAssertEqual(maximum.latestHandshakeUnixSeconds, maximumSeconds)
    XCTAssertEqual(
      maximum.latestHandshakeNanoseconds,
      maximumNanoseconds
    )
    XCTAssertEqual(maximum.receivedBytes, UInt64.max)
    XCTAssertEqual(maximum.transmittedBytes, UInt64.max)

    for invalidKey in [
      [UInt8](repeating: 0x55, count: 31),
      [UInt8](repeating: 0x55, count: 33),
      [UInt8](repeating: 0, count: 32),
    ] {
      XCTAssertThrowsError(
        try StageBAWGNativePeerTelemetry(
          peerPublicKey: invalidKey,
          latestHandshakeUnixSeconds: 0,
          latestHandshakeNanoseconds: 0,
          receivedBytes: 0,
          transmittedBytes: 0
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDigest
        )
      }
    }
    XCTAssertThrowsError(
      try StageBAWGNativePeerTelemetry(
        peerPublicKey: fixture.peerKey,
        latestHandshakeUnixSeconds: 0,
        latestHandshakeNanoseconds: maximumNanoseconds + 1,
        receivedBytes: 0,
        transmittedBytes: 0
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidAWGSnapshot
      )
    }
    XCTAssertThrowsError(
      try StageBAWGNativePeerTelemetry(
        peerPublicKey: fixture.peerKey,
        latestHandshakeUnixSeconds: maximumSeconds + 1,
        latestHandshakeNanoseconds: maximumNanoseconds,
        receivedBytes: 0,
        transmittedBytes: 0
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidAWGSnapshot
      )
    }
  }

  func testEnginePathIdentityValidatesEveryFieldAndUUIDBits()
    throws
  {
    let fixture = try Fixture(t0: t0)
    let identity = fixture.path.identity
    XCTAssertEqual(
      Set(Mirror(reflecting: identity).children.compactMap(\.label)),
      [
        "signedRuntimeArtifactSHA256",
        "wgTurnOnConfigSHA256",
        "expectedPeerPublicKeySHA256",
        "engineInstanceNonce",
        "engineGeneration",
        "pathGeneration",
        "winningInterfaceTokenSHA256",
      ]
    )

    let invalidDigests = [
      [UInt8](repeating: 1, count: 31),
      [UInt8](repeating: 0, count: 32),
    ]
    for invalidDigest in invalidDigests {
      for mutation in [
        {
          try fixture.identity(
            signedRuntimeArtifactSHA256: invalidDigest
          )
        },
        {
          try fixture.identity(
            wgTurnOnConfigSHA256: invalidDigest
          )
        },
        {
          try fixture.identity(
            expectedPeerPublicKeySHA256: invalidDigest
          )
        },
        {
          try fixture.identity(
            winningInterfaceTokenSHA256: invalidDigest
          )
        },
      ] {
        XCTAssertThrowsError(try mutation()) {
          XCTAssertEqual(
            $0 as? StageBProviderValidationError,
            .invalidDigest
          )
        }
      }
    }

    for mutation in [
      { try fixture.identity(engineGeneration: 0) },
      { try fixture.identity(pathGeneration: 0) },
    ] {
      XCTAssertThrowsError(try mutation()) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidGeneration
        )
      }
    }

    var wrongVersion = identity.engineInstanceNonce
    wrongVersion[6] = (wrongVersion[6] & 0x0f) | 0x50
    var wrongVariant = identity.engineInstanceNonce
    wrongVariant[8] &= 0x3f
    for nonce in [
      Array(identity.engineInstanceNonce.dropLast()),
      wrongVersion,
      wrongVariant,
    ] {
      XCTAssertThrowsError(
        try fixture.identity(engineInstanceNonce: nonce)
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidIdentifier
        )
      }
    }

    var invalidPathID = fixture.path.pathID
    invalidPathID[6] = (invalidPathID[6] & 0x0f) | 0x30
    XCTAssertThrowsError(
      try fixture.alteredPath(pathID: invalidPathID)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidIdentifier
      )
    }
  }

  func testAttemptRequiresArtifactPeerAndPairwiseUUIDContinuity()
    throws
  {
    let fixture = try Fixture(t0: t0)

    XCTAssertThrowsError(
      try fixture.configuration(
        artifactSHA256: [UInt8](repeating: 0xe1, count: 32)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }
    XCTAssertThrowsError(
      try fixture.configuration(
        expectedPeerPublicKeySHA256:
          [UInt8](repeating: 0xe2, count: 32)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }

    let baseIdentifiers = [
      fixture.runID,
      fixture.attemptNonce,
      fixture.path.pathID,
      fixture.context.sessionID,
      fixture.context.bindingID,
      fixture.path.identity.engineInstanceNonce,
    ]
    var pairwiseCollisionCount = 0
    for left in 0..<baseIdentifiers.count {
      for right in (left + 1)..<baseIdentifiers.count {
        var identifiers = baseIdentifiers
        identifiers[right] = identifiers[left]
        let context = try WCF3ConnectionContext(
          sessionID: identifiers[3],
          bindingID: identifiers[4],
          pskGeneration: fixture.context.pskGeneration,
          sequenceEpoch: fixture.context.sequenceEpoch
        )
        let path = try fixture.alteredPath(
          pathID: identifiers[2],
          engineInstanceNonce: identifiers[5],
          context: context
        )
        XCTAssertThrowsError(
          try fixture.configuration(
            runID: identifiers[0],
            attemptNonce: identifiers[1],
            path: path
          ),
          "UUID pair \(left),\(right)"
        ) {
          XCTAssertEqual(
            $0 as? StageBProviderValidationError,
            .invalidIdentifier,
            "UUID pair \(left),\(right)"
          )
        }
        pairwiseCollisionCount += 1
      }
    }
    XCTAssertEqual(pairwiseCollisionCount, 15)

    var wrongVersion = fixture.runID
    wrongVersion[6] = (wrongVersion[6] & 0x0f) | 0x50
    var wrongVariant = fixture.runID
    wrongVariant[8] = (wrongVariant[8] & 0x3f) | 0xc0
    for runID in [
      Array(fixture.runID.dropLast()),
      wrongVersion,
      wrongVariant,
    ] {
      XCTAssertThrowsError(
        try fixture.configuration(runID: runID)
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidIdentifier
        )
      }
    }
    XCTAssertThrowsError(
      try fixture.configuration(attemptNonce: wrongVersion)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidIdentifier
      )
    }

    for invalidSessionID in [
      Array(fixture.context.sessionID.dropLast()),
      fixture.context.sessionID + [0],
    ] {
      XCTAssertThrowsError(
        try WCF3ConnectionContext(
          sessionID: invalidSessionID,
          bindingID: fixture.context.bindingID,
          pskGeneration: fixture.context.pskGeneration,
          sequenceEpoch: fixture.context.sequenceEpoch
        )
      ) {
        XCTAssertEqual($0 as? WCF3Error, .invalidConnectionContext)
      }
    }
    for invalidBindingID in [
      Array(fixture.context.bindingID.dropLast()),
      fixture.context.bindingID + [0],
    ] {
      XCTAssertThrowsError(
        try WCF3ConnectionContext(
          sessionID: fixture.context.sessionID,
          bindingID: invalidBindingID,
          pskGeneration: fixture.context.pskGeneration,
          sequenceEpoch: fixture.context.sequenceEpoch
        )
      ) {
        XCTAssertEqual($0 as? WCF3Error, .invalidConnectionContext)
      }
    }

    for mutateSession in [true, false] {
      for invalidIdentifier in [wrongVersion, wrongVariant] {
        let invalidWCF3 = try WCF3ConnectionContext(
          sessionID:
            mutateSession
            ? invalidIdentifier : fixture.context.sessionID,
          bindingID:
            mutateSession
            ? fixture.context.bindingID : invalidIdentifier,
          pskGeneration: fixture.context.pskGeneration,
          sequenceEpoch: fixture.context.sequenceEpoch
        )
        XCTAssertThrowsError(
          try fixture.configuration(
            path: fixture.alteredPath(context: invalidWCF3)
          )
        ) {
          XCTAssertEqual(
            $0 as? StageBProviderValidationError,
            .invalidIdentifier
          )
        }
      }
    }
  }

  func testEveryEngineIdentityFieldIsCheckedAtEveryProofSnapshot()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let mutatedBindings = [
      try fixture.alteredPath(
        signedRuntimeArtifactSHA256:
          [UInt8](repeating: 0xd1, count: 32)
      ),
      try fixture.alteredPath(
        wgTurnOnConfigSHA256:
          [UInt8](repeating: 0xd2, count: 32)
      ),
      try fixture.alteredPath(
        engineInstanceNonce: stageBUUID(0xd4)
      ),
      try fixture.alteredPath(engineGeneration: 91),
      try fixture.alteredPath(pathGeneration: 92),
      try fixture.alteredPath(
        winningInterfaceTokenSHA256:
          [UInt8](repeating: 0xd7, count: 32)
      ),
    ]
    XCTAssertEqual(mutatedBindings.count, 6)

    for mutatedBinding in mutatedBindings {
      let mutatedFeed = TestTelemetryFeed(
        try fixture.telemetry(
          handshake: fixture.baselineHandshake + 1,
          received: fixture.baselineReceived + 100,
          transmitted: fixture.baselineTransmitted + 200
        )
      )
      let mutatedSource =
        try harness.environment.makeNativeAWGCaptureSource(
          binding: mutatedBinding,
          expectedPeerPublicKey: fixture.peerKey,
          readNativeTelemetry: { try mutatedFeed.read() }
        )
      let mutatedPre = try harness.sample(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 100,
        transmitted: fixture.baselineTransmitted + 200,
        from: mutatedSource,
        feed: mutatedFeed
      )
      let mutatedPost = try harness.sample(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 300,
        transmitted: fixture.baselineTransmitted + 400,
        from: mutatedSource,
        feed: mutatedFeed
      )

      let dnsPre = try harness.makeCoordinator()
      let ladder = try harness.ladder()
      XCTAssertThrowsError(
        try dnsPre.recordProtectedDNSRequestSent(
          harness.dnsSendProof(ladder, pre: mutatedPre)
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDNSProof
        )
      }

      let dnsPost = try harness.makeCoordinator()
      _ = try dnsPost.recordProtectedDNSRequestSent(
        harness.dnsSendProof(ladder)
      )
      XCTAssertThrowsError(
        try dnsPost.recordProtectedDNSProof(
          harness.dnsProof(ladder, post: mutatedPost)
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDNSProof
        )
      }

      let reflectorPre = try harness.makeCoordinator()
      try harness.driveToDNSAccepted(reflectorPre, ladder)
      XCTAssertThrowsError(
        try reflectorPre.recordReflectorRequestSent(
          harness.reflectorSendProof(
            ladder,
            for: reflectorPre,
            pre: mutatedPost
          )
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidReflectorProof
        )
      }

      let reflectorPost = try harness.makeCoordinator()
      try harness.driveToReflectorSend(reflectorPost, ladder)
      XCTAssertThrowsError(
        try reflectorPost.acceptReflectorResponse(
          harness.reflectorProof(
            ladder,
            response: try response(for: reflectorPost),
            post: mutatedPost
          )
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidReflectorProof
        )
      }
    }
  }

  func testDNSRequiresRequestFirstAndPostRequestBidirectionalBytes()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let ladder = try harness.ladder()

    let beforeSend = try harness.makeCoordinator()
    XCTAssertThrowsError(
      try beforeSend.recordProtectedDNSProof(harness.dnsProof(ladder))
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .dnsRequestNotSent
      )
    }

    let noPostRequestMovement = try harness.makeCoordinator()
    _ = try noPostRequestMovement.recordProtectedDNSRequestSent(
      harness.dnsSendProof(ladder)
    )
    XCTAssertThrowsError(
      try noPostRequestMovement.recordProtectedDNSProof(
        harness.dnsProof(ladder, post: ladder.dnsPre)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDNSProof
      )
    }

    for (receivedDelta, transmittedDelta) in [(1, 0), (0, 1)] {
      let oneSided = try harness.makeCoordinator()
      _ = try oneSided.recordProtectedDNSRequestSent(
        harness.dnsSendProof(ladder)
      )
      let post = try harness.sample(
        handshake: fixture.baselineHandshake + 1,
        received:
          ladder.dnsPre.peer.receivedBytes + UInt64(receivedDelta),
        transmitted:
          ladder.dnsPre.peer.transmittedBytes
          + UInt64(transmittedDelta)
      )
      XCTAssertThrowsError(
        try oneSided.recordProtectedDNSProof(
          harness.dnsProof(ladder, post: post)
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDNSProof
        )
      }
    }
  }

  /// The DNS request may be sent only once the handshake and bidirectional
  /// byte predicates already hold, because physical evidence requires the
  /// byte sample not to follow the request.
  func testDNSRequestBeforeHandshakeAndByteEvidenceIsRejected() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture

    let noEvidence = try harness.makeCoordinator()
    XCTAssertThrowsError(
      try noEvidence.recordProtectedDNSRequestSent(
        StageBProtectedDNSRequestSendProof(
          probe: fixture.dnsProbe,
          binding: fixture.path,
          preRequestAWGSnapshot: harness.baseline
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .predicateLadderViolation
      )
    }

    // Handshake only, no byte movement: still short of the ladder.
    let handshakeOnly = try harness.makeCoordinator()
    XCTAssertThrowsError(
      try handshakeOnly.recordProtectedDNSRequestSent(
        harness.dnsSendProof(
          try harness.ladder(),
          pre: try harness.sample(
            handshake: fixture.baselineHandshake + 1,
            received: fixture.baselineReceived,
            transmitted: fixture.baselineTransmitted
          )
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .predicateLadderViolation
      )
    }
    XCTAssertTrue(handshakeOnly.localSnapshot().freshAWGHandshake)
    XCTAssertFalse(
      handshakeOnly.localSnapshot().authenticatedTunnelBytes
    )
  }

  func testDNSStrongBindingsAndTrustedOrderingAreRequired() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let ladder = try harness.ladder()

    let alteredProbes = [
      try StageBDNSProbeBinding(
        transactionID: fixture.dnsProbe.transactionID + 1,
        questionSHA256: fixture.dnsProbe.questionSHA256,
        cacheBypassNonceSHA256:
          fixture.dnsProbe.cacheBypassNonceSHA256,
        privateResolverIdentitySHA256:
          fixture.dnsProbe.privateResolverIdentitySHA256
      ),
      try StageBDNSProbeBinding(
        transactionID: fixture.dnsProbe.transactionID,
        questionSHA256: [UInt8](repeating: 0x96, count: 32),
        cacheBypassNonceSHA256:
          fixture.dnsProbe.cacheBypassNonceSHA256,
        privateResolverIdentitySHA256:
          fixture.dnsProbe.privateResolverIdentitySHA256
      ),
      try StageBDNSProbeBinding(
        transactionID: fixture.dnsProbe.transactionID,
        questionSHA256: fixture.dnsProbe.questionSHA256,
        cacheBypassNonceSHA256: [UInt8](repeating: 0x98, count: 32),
        privateResolverIdentitySHA256:
          fixture.dnsProbe.privateResolverIdentitySHA256
      ),
      try StageBDNSProbeBinding(
        transactionID: fixture.dnsProbe.transactionID,
        questionSHA256: fixture.dnsProbe.questionSHA256,
        cacheBypassNonceSHA256:
          fixture.dnsProbe.cacheBypassNonceSHA256,
        privateResolverIdentitySHA256: [UInt8](repeating: 0x95, count: 32)
      ),
    ]
    for alteredProbe in alteredProbes {
      let wrongProbe = try harness.makeCoordinator()
      XCTAssertThrowsError(
        try wrongProbe.recordProtectedDNSRequestSent(
          harness.dnsSendProof(ladder, probe: alteredProbe)
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDNSProof
        )
      }
    }

    let wrongInterface = try harness.makeCoordinator()
    XCTAssertThrowsError(
      try wrongInterface.recordProtectedDNSRequestSent(
        StageBProtectedDNSRequestSendProof(
          probe: fixture.dnsProbe,
          binding: try fixture.alteredPath(
            winningInterfaceTokenSHA256:
              [UInt8](repeating: 0x94, count: 32)
          ),
          preRequestAWGSnapshot: ladder.dnsPre
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }

    let reversed = try harness.makeCoordinator()
    _ = try reversed.recordProtectedDNSRequestSent(
      harness.dnsSendProof(ladder)
    )
    harness.clock.set(t0 + 9)
    XCTAssertThrowsError(
      try reversed.recordProtectedDNSProof(harness.dnsProof(ladder))
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDeadline
      )
    }
  }

  /// The coordinator parses the DNS response itself; it never compares two
  /// caller-supplied digests.
  func testDNSResponseWireBytesAreValidatedAgainstTheProbe() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let ladder = try harness.ladder()

    var truncatedQuestion = [UInt8](fixture.dnsResponse)
    truncatedQuestion.removeLast(truncatedQuestion.count - 14)
    var compressedQuestion = [UInt8](fixture.dnsResponse)
    compressedQuestion[12] = 0xc0
    var zeroLengthName = [UInt8](fixture.dnsResponse)
    zeroLengthName[12] = 0x00

    let malformed: [(String, Data)] = [
      ("wrong transaction id", dnsResponse(transactionID: 0x1235)),
      ("question, not response", dnsResponse(flagsHigh: 0x01)),
      ("truncated bit set", dnsResponse(flagsHigh: 0x83)),
      ("non-query opcode", dnsResponse(flagsHigh: 0x89)),
      ("non-zero rcode", dnsResponse(flagsLow: 0x83)),
      ("no answer records", dnsResponse(answerCount: 0)),
      ("two questions", dnsResponse(questionCount: 2)),
      ("different question name", dnsResponse(secondLabel: "other")),
      ("truncated question", Data(truncatedQuestion)),
      ("compression pointer in question", Data(compressedQuestion)),
      ("root-only question name", Data(zeroLengthName)),
    ]
    for (label, payload) in malformed {
      let coordinator = try harness.makeCoordinator()
      _ = try coordinator.recordProtectedDNSRequestSent(
        harness.dnsSendProof(ladder)
      )
      XCTAssertThrowsError(
        try coordinator.recordProtectedDNSProof(
          harness.dnsProof(ladder, responsePayload: payload)
        ),
        label
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDNSWireResponse,
          label
        )
      }
    }

    // Structurally valid for this probe, but not the pinned answer.
    let otherAnswer = try harness.makeCoordinator()
    _ = try otherAnswer.recordProtectedDNSRequestSent(
      harness.dnsSendProof(ladder)
    )
    XCTAssertThrowsError(
      try otherAnswer.recordProtectedDNSProof(
        harness.dnsProof(
          ladder,
          responsePayload: dnsResponse(answerByte: 0x2b)
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDNSProof
      )
    }

    // The cache-bypass nonce is checked independently of the question
    // digest: same wire bytes, same question pin, mismatched nonce pin.
    let nonceMismatchProbe = try StageBDNSProbeBinding(
      transactionID: fixture.dnsProbe.transactionID,
      questionSHA256: fixture.dnsProbe.questionSHA256,
      cacheBypassNonceSHA256: Array(
        SHA256.hash(data: Data("not-the-nonce-label".utf8))
      ),
      privateResolverIdentitySHA256:
        fixture.dnsProbe.privateResolverIdentitySHA256
    )
    let nonceHarness = try Harness(
      t0: t0,
      key: key,
      now: t0 + 10,
      dnsProbe: nonceMismatchProbe
    )
    let nonceLadder = try nonceHarness.ladder()
    let nonceCoordinator = try nonceHarness.makeCoordinator()
    _ = try nonceCoordinator.recordProtectedDNSRequestSent(
      nonceHarness.dnsSendProof(nonceLadder)
    )
    XCTAssertThrowsError(
      try nonceCoordinator.recordProtectedDNSProof(
        nonceHarness.dnsProof(nonceLadder)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDNSWireResponse
      )
    }
  }

  func testReflectorRequiresExactSendAndPostSendBidirectionalBytes()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let ladder = try harness.ladder()

    let beforeSend = try harness.makeCoordinator()
    try harness.driveToDNSAccepted(beforeSend, ladder)
    XCTAssertThrowsError(
      try beforeSend.acceptReflectorResponse(
        harness.reflectorProof(
          ladder,
          response: try response(for: beforeSend)
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .reflectorRequestNotSent
      )
    }

    let wrongHash = try harness.makeCoordinator()
    try harness.driveToDNSAccepted(wrongHash, ladder)
    XCTAssertThrowsError(
      try wrongHash.recordReflectorRequestSent(
        try StageBReflectorRequestSendProof(
          requestDatagramSHA256: [UInt8](repeating: 0x77, count: 32),
          binding: fixture.path,
          preSendAWGSnapshot: ladder.reflectorPre
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidReflectorProof
      )
    }

    let noPostSendMovement = try harness.makeCoordinator()
    try harness.driveToReflectorSend(noPostSendMovement, ladder)
    XCTAssertThrowsError(
      try noPostSendMovement.acceptReflectorResponse(
        harness.reflectorProof(
          ladder,
          response: try response(for: noPostSendMovement),
          post: ladder.reflectorPre
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidReflectorProof
      )
    }

    for (receivedDelta, transmittedDelta) in [(1, 0), (0, 1)] {
      let oneSided = try harness.makeCoordinator()
      try harness.driveToReflectorSend(oneSided, ladder)
      let post = try harness.sample(
        handshake: fixture.baselineHandshake + 1,
        received:
          ladder.reflectorPre.peer.receivedBytes
          + UInt64(receivedDelta),
        transmitted:
          ladder.reflectorPre.peer.transmittedBytes
          + UInt64(transmittedDelta)
      )
      XCTAssertThrowsError(
        try oneSided.acceptReflectorResponse(
          harness.reflectorProof(
            ladder,
            response: try response(for: oneSided),
            post: post
          )
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidReflectorProof
        )
      }
    }
  }

  /// The reflector may not be driven before DNS is accepted, and its own
  /// counter window may not overlap the accepted DNS window.
  func testReflectorRequiresAcceptedDNSAndIndependentMovement() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let ladder = try harness.ladder()

    let beforeDNS = try harness.makeCoordinator()
    _ = try beforeDNS.recordProtectedDNSRequestSent(
      harness.dnsSendProof(ladder)
    )
    XCTAssertThrowsError(
      try beforeDNS.recordReflectorRequestSent(
        harness.reflectorSendProof(ladder, for: beforeDNS)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .dnsProofNotAccepted
      )
    }

    // Reusing the accepted DNS post-response sample as the reflector
    // pre-send sample is exactly the interleaving that let one round trip
    // satisfy both probes.
    let borrowed = try harness.makeCoordinator()
    try harness.driveToDNSAccepted(borrowed, ladder)
    XCTAssertThrowsError(
      try borrowed.recordReflectorRequestSent(
        harness.reflectorSendProof(
          ladder,
          for: borrowed,
          pre: ladder.dnsPost
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .probeMovementNotIndependent
      )
    }

    for (receivedDelta, transmittedDelta) in [(1, 0), (0, 1)] {
      let oneSided = try harness.makeCoordinator()
      try harness.driveToDNSAccepted(oneSided, ladder)
      let pre = try harness.sample(
        handshake: fixture.baselineHandshake + 1,
        received:
          ladder.dnsPost.peer.receivedBytes + UInt64(receivedDelta),
        transmitted:
          ladder.dnsPost.peer.transmittedBytes
          + UInt64(transmittedDelta)
      )
      XCTAssertThrowsError(
        try oneSided.recordReflectorRequestSent(
          harness.reflectorSendProof(ladder, for: oneSided, pre: pre)
        )
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .probeMovementNotIndependent
        )
      }
    }

    // Positive control: one byte of movement in each direction after the
    // accepted DNS sample is enough, so the rejections above are the
    // independence rule and not the surrounding flow.
    let independent = try harness.makeCoordinator()
    try harness.driveToDNSAccepted(independent, ladder)
    let pre = try harness.sample(
      handshake: fixture.baselineHandshake + 1,
      received: ladder.dnsPost.peer.receivedBytes + 1,
      transmitted: ladder.dnsPost.peer.transmittedBytes + 1
    )
    XCTAssertEqual(
      try independent.recordReflectorRequestSent(
        harness.reflectorSendProof(ladder, for: independent, pre: pre)
      ),
      .accepted
    )
  }

  /// The same sample cannot close the DNS window and the reflector window.
  func testOneSampleCannotBeBothDNSPostAndReflectorPost() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let coordinator = try harness.makeCoordinator()
    try harness.driveToReflectorSend(coordinator, ladder)

    XCTAssertThrowsError(
      try coordinator.acceptReflectorResponse(
        harness.reflectorProof(
          ladder,
          response: try response(for: coordinator),
          post: ladder.dnsPost
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidReflectorProof
      )
    }
  }

  func testReflectorRejectsWrongBindingAtSendAndResponseBoundaries()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let wrongPath = try harness.fixture.alteredPath(pathGeneration: 99)

    let wrongSend = try harness.makeCoordinator()
    try harness.driveToDNSAccepted(wrongSend, ladder)
    XCTAssertThrowsError(
      try wrongSend.recordReflectorRequestSent(
        try StageBReflectorRequestSendProof(
          requestDatagramSHA256: Array(
            SHA256.hash(data: wrongSend.outboundReflectorDatagram)
          ),
          binding: wrongPath,
          preSendAWGSnapshot: ladder.reflectorPre
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }

    let wrongResponse = try harness.makeCoordinator()
    try harness.driveToReflectorSend(wrongResponse, ladder)
    XCTAssertThrowsError(
      try wrongResponse.acceptReflectorResponse(
        StageBReflectorResponseProof(
          responseDatagram: try response(for: wrongResponse),
          binding: wrongPath,
          postResponseAWGSnapshot: ladder.reflectorPost
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .bindingMismatch
      )
    }
  }

  func testExactDuplicatesCoalesceAndConflictingDuplicatesFailClosed()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()

    let dnsSend = try harness.makeCoordinator()
    let dnsSendProof = harness.dnsSendProof(ladder)
    XCTAssertEqual(
      try dnsSend.recordProtectedDNSRequestSent(dnsSendProof),
      .accepted
    )
    XCTAssertEqual(
      try dnsSend.recordProtectedDNSRequestSent(dnsSendProof),
      .coalesced
    )
    XCTAssertThrowsError(
      try dnsSend.recordProtectedDNSRequestSent(
        harness.dnsSendProof(ladder, pre: ladder.dnsPost)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDNSProof
      )
    }

    let dnsResponseTarget = try harness.makeCoordinator()
    _ = try dnsResponseTarget.recordProtectedDNSRequestSent(dnsSendProof)
    let dnsProof = harness.dnsProof(ladder)
    XCTAssertEqual(
      try dnsResponseTarget.recordProtectedDNSProof(dnsProof),
      .accepted
    )
    XCTAssertEqual(
      try dnsResponseTarget.recordProtectedDNSProof(dnsProof),
      .coalesced
    )
    XCTAssertThrowsError(
      try dnsResponseTarget.recordProtectedDNSProof(
        harness.dnsProof(
          ladder,
          responsePayload: dnsResponse(answerByte: 0x2c)
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDNSProof
      )
    }

    let reflectorSend = try harness.makeCoordinator()
    try harness.driveToDNSAccepted(reflectorSend, ladder)
    let reflectorSendProof = try harness.reflectorSendProof(
      ladder,
      for: reflectorSend
    )
    XCTAssertEqual(
      try reflectorSend.recordReflectorRequestSent(reflectorSendProof),
      .accepted
    )
    XCTAssertEqual(
      try reflectorSend.recordReflectorRequestSent(reflectorSendProof),
      .coalesced
    )
    XCTAssertThrowsError(
      try reflectorSend.recordReflectorRequestSent(
        harness.reflectorSendProof(
          ladder,
          for: reflectorSend,
          pre: ladder.reflectorPost
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidReflectorProof
      )
    }

    let reflectorResponse = try harness.makeCoordinator()
    try harness.driveToReflectorSend(reflectorResponse, ladder)
    let validResponse = try response(for: reflectorResponse)
    let reflectorProof = harness.reflectorProof(
      ladder,
      response: validResponse
    )
    XCTAssertEqual(
      try reflectorResponse.acceptReflectorResponse(reflectorProof),
      .accepted
    )
    // The reflector response is the last rung, so accepting it always
    // completes the attempt. Repeats and conflicts after that are late input
    // to a terminal attempt, not coalescing.
    XCTAssertEqual(reflectorResponse.localSnapshot().status, .succeeded)
    XCTAssertEqual(
      try reflectorResponse.acceptReflectorResponse(reflectorProof),
      .ignoredTerminal
    )
    var conflictingResponse = validResponse
    conflictingResponse[conflictingResponse.startIndex] ^= 1
    XCTAssertEqual(
      try reflectorResponse.acceptReflectorResponse(
        harness.reflectorProof(ladder, response: conflictingResponse)
      ),
      .ignoredTerminal
    )
    XCTAssertEqual(reflectorResponse.localSnapshot().status, .succeeded)
    XCTAssertEqual(
      reflectorResponse.terminalEvidence()?.status,
      .succeeded
    )
  }

  func testExactCoalescedCallbacksCannotHideClockRollback() throws {
    let dnsHarness = try Harness(t0: t0, key: key, now: t0 + 10)
    let dnsLadder = try dnsHarness.ladder()
    let dns = try dnsHarness.makeCoordinator()
    let dnsProof = dnsHarness.dnsSendProof(dnsLadder)
    _ = try dns.recordProtectedDNSRequestSent(dnsProof)
    dnsHarness.clock.set(t0 + 9)
    XCTAssertThrowsError(
      try dns.recordProtectedDNSRequestSent(dnsProof)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDeadline
      )
    }
    XCTAssertEqual(dns.localSnapshot().status, .failed)

    let reflectorHarness = try Harness(t0: t0, key: key, now: t0 + 10)
    let reflectorLadder = try reflectorHarness.ladder()
    let reflector = try reflectorHarness.makeCoordinator()
    try reflectorHarness.driveToDNSAccepted(reflector, reflectorLadder)
    let sendProof = try reflectorHarness.reflectorSendProof(
      reflectorLadder,
      for: reflector
    )
    _ = try reflector.recordReflectorRequestSent(sendProof)
    reflectorHarness.clock.set(t0 + 9)
    XCTAssertThrowsError(
      try reflector.recordReflectorRequestSent(sendProof)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidDeadline
      )
    }
    XCTAssertEqual(reflector.localSnapshot().status, .failed)
  }

  func testSharedClockAuthorityRejectsRollbackInsideResponseAcceptance()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let coordinator = try harness.makeCoordinator()
    try harness.driveToReflectorSend(coordinator, ladder)
    let response = try response(for: coordinator)

    // The next read is this method's own; the read after it is the shared
    // acceptance domain's, and that is the one that rolls back.
    harness.clock.scheduleReadValue(after: 1, to: t0 + 9)
    XCTAssertThrowsError(
      try coordinator.acceptReflectorResponse(
        harness.reflectorProof(ladder, response: response)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .deadlineExceeded
      )
    }
    XCTAssertEqual(harness.environment.acceptedResponseCount, 0)
    XCTAssertEqual(coordinator.localSnapshot().status, .failed)
  }

  /// Exactly one callback ordering is admissible, and it is the ladder the
  /// physical verifier requires.
  func testOnlyTheLadderCallbackOrderingSucceeds() throws {
    let ladderOrder: [Event] = [
      .dnsSend,
      .dnsResponse,
      .reflectorSend,
      .reflectorResponse,
    ]
    var succeeded = 0
    for permutation in permutations(Event.allCases) {
      let harness = try Harness(t0: t0, key: key, now: t0 + 10)
      let ladder = try harness.ladder()
      let coordinator = try harness.makeCoordinator()
      let response = try response(for: coordinator)
      var thrown: Error?
      for event in permutation {
        do {
          switch event {
          case .dnsSend:
            _ = try coordinator.recordProtectedDNSRequestSent(
              harness.dnsSendProof(ladder)
            )
          case .dnsResponse:
            _ = try coordinator.recordProtectedDNSProof(
              harness.dnsProof(ladder)
            )
          case .reflectorSend:
            _ = try coordinator.recordReflectorRequestSent(
              harness.reflectorSendProof(ladder, for: coordinator)
            )
          case .reflectorResponse:
            _ = try coordinator.acceptReflectorResponse(
              harness.reflectorProof(ladder, response: response)
            )
          }
        } catch {
          thrown = error
          break
        }
      }
      if permutation == ladderOrder {
        XCTAssertNil(thrown, "permutation \(permutation)")
        XCTAssertEqual(
          coordinator.localSnapshot().status,
          .succeeded,
          "permutation \(permutation)"
        )
        succeeded += 1
      } else {
        XCTAssertNotNil(thrown, "permutation \(permutation)")
        XCTAssertEqual(
          coordinator.localSnapshot().status,
          .failed,
          "permutation \(permutation)"
        )
      }
    }
    XCTAssertEqual(succeeded, 1)
  }

  func testSharedAcceptanceDomainRejectsCrossCoordinatorReplay()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let first = try harness.makeCoordinator(sharedEnvironment: true)
    let second = try harness.makeCoordinator(sharedEnvironment: true)
    XCTAssertEqual(
      first.outboundReflectorDatagram,
      second.outboundReflectorDatagram
    )
    let response = try response(for: first)

    try harness.driveToReflectorSend(first, ladder)
    try harness.driveToReflectorSend(second, ladder)
    XCTAssertEqual(
      try first.acceptReflectorResponse(
        harness.reflectorProof(ladder, response: response)
      ),
      .accepted
    )
    XCTAssertThrowsError(
      try second.acceptReflectorResponse(
        harness.reflectorProof(ladder, response: response)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .coreRejected
      )
    }
    XCTAssertEqual(harness.environment.acceptedResponseCount, 1)
    XCTAssertEqual(second.localSnapshot().status, .failed)
  }

  func testConcurrentTerminalTransitionHasOneWinnerAndLateInputIsNoOp()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let coordinator = try harness.makeCoordinator()
    let current = try harness.currentSample()
    let winners = LockedCounter()
    let group = DispatchGroup()
    let queue = DispatchQueue(
      label: "winn.stageb.concurrent-test",
      attributes: .concurrent
    )
    for index in 0..<100 {
      group.enter()
      queue.async {
        let won =
          index.isMultiple(of: 2)
          ? coordinator.cancel()
          : coordinator.supersedePath()
        if won { winners.increment() }
        group.leave()
      }
    }
    group.wait()

    XCTAssertEqual(winners.value, 1)
    XCTAssertTrue(
      coordinator.localSnapshot().status == .cancelled
        || coordinator.localSnapshot().status == .superseded
    )
    XCTAssertEqual(
      try coordinator.recordAWGSnapshot(current),
      .ignoredTerminal
    )
    XCTAssertEqual(
      coordinator.handleTimeoutFired(),
      .ignoredTerminal
    )
    XCTAssertEqual(
      coordinator.terminalEvidence()?.status,
      coordinator.localSnapshot().status
    )
  }

  func testSuccessCancelSupersedeAndTimeoutRaceOrderingsAreTerminal()
    throws
  {
    func ready() throws -> (Harness, Ladder, StageBProviderCoordinator, Data) {
      let harness = try Harness(t0: t0, key: key, now: t0 + 10)
      let ladder = try harness.ladder()
      let coordinator = try harness.makeCoordinator()
      try harness.driveToReflectorSend(coordinator, ladder)
      return (
        harness, ladder, coordinator, try response(for: coordinator)
      )
    }

    for terminalAction in [
      { (coordinator: StageBProviderCoordinator) in
        coordinator.cancel()
      },
      { (coordinator: StageBProviderCoordinator) in
        coordinator.supersedePath()
      },
    ] {
      let (successHarness, successLadder, successFirst, successDatagram) =
        try ready()
      XCTAssertEqual(
        try successFirst.acceptReflectorResponse(
          successHarness.reflectorProof(
            successLadder,
            response: successDatagram
          )
        ),
        .accepted
      )
      XCTAssertFalse(terminalAction(successFirst))
      XCTAssertEqual(successFirst.localSnapshot().status, .succeeded)

      let (terminalHarness, terminalLadder, terminalFirst, lateResponse) =
        try ready()
      XCTAssertTrue(terminalAction(terminalFirst))
      XCTAssertEqual(
        try terminalFirst.acceptReflectorResponse(
          terminalHarness.reflectorProof(
            terminalLadder,
            response: lateResponse
          )
        ),
        .ignoredTerminal
      )
      XCTAssertNotEqual(terminalFirst.localSnapshot().status, .succeeded)
    }

    let (timeoutHarness, timeoutLadder, successBeforeTimeout, datagram) =
      try ready()
    XCTAssertEqual(
      try successBeforeTimeout.acceptReflectorResponse(
        timeoutHarness.reflectorProof(timeoutLadder, response: datagram)
      ),
      .accepted
    )
    timeoutHarness.clock.set(
      t0 + StageBProtectedFlow.deadlineNanoseconds + 1
    )
    XCTAssertEqual(
      successBeforeTimeout.handleTimeoutFired(),
      .ignoredTerminal
    )

    let (lateHarness, lateLadder, timeoutFirst, lateResponse) =
      try ready()
    lateHarness.clock.set(
      t0 + StageBProtectedFlow.deadlineNanoseconds + 1
    )
    XCTAssertEqual(timeoutFirst.handleTimeoutFired(), .terminal)
    XCTAssertEqual(
      try timeoutFirst.acceptReflectorResponse(
        lateHarness.reflectorProof(lateLadder, response: lateResponse)
      ),
      .ignoredTerminal
    )
    XCTAssertEqual(timeoutFirst.localSnapshot().status, .failed)
    XCTAssertEqual(
      timeoutFirst.localSnapshot().failure,
      .deadlineExceeded
    )
  }

  func testCoreRejectionIsSanitizedAndTerminal() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let coordinator = try harness.makeCoordinator()
    try harness.driveToReflectorSend(coordinator, ladder)
    let malformed = StageBReflectorResponseProof(
      responseDatagram: Data([1, 2, 3]),
      binding: harness.fixture.path,
      postResponseAWGSnapshot: ladder.reflectorPost
    )

    XCTAssertThrowsError(
      try coordinator.acceptReflectorResponse(malformed)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .coreRejected
      )
    }
    XCTAssertEqual(coordinator.localSnapshot().status, .failed)
    XCTAssertEqual(
      coordinator.localSnapshot().failure,
      .coreRejected
    )
  }

  func testLocalSnapshotContainsOnlySanitizedAllowlistedFields()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0)
    let coordinator = try harness.makeCoordinator()
    let labels = Set(
      Mirror(reflecting: coordinator.localSnapshot())
        .children
        .compactMap(\.label)
    )
    XCTAssertEqual(
      labels,
      [
        "schema",
        "protocolVersion",
        "measurementScope",
        "status",
        "failure",
        "requestedAtMonotonicNanoseconds",
        "deadlineMonotonicNanoseconds",
        "reflectorRequestSent",
        "freshAWGHandshake",
        "authenticatedTunnelBytes",
        "protectedDNSResponse",
        "authenticatedReflectorResponse",
      ]
    )
    XCTAssertFalse(labels.contains("key"))
    XCTAssertFalse(labels.contains("address"))
    XCTAssertFalse(labels.contains("peerPublicKeySHA256"))
    XCTAssertFalse(labels.contains("winningInterfaceTokenSHA256"))
  }

  // MARK: - Native provenance

  /// A sample whose bytes are identical but whose capture source is not this
  /// attempt's is rejected, so provenance is an identity and not a value.
  func testByteIdenticalSampleFromAnotherCaptureSourceIsRejected()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let coordinator = try harness.makeCoordinator()
    let twinFeed = TestTelemetryFeed(
      try fixture.telemetry(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 100,
        transmitted: fixture.baselineTransmitted + 200
      )
    )
    let twin = try harness.environment.makeNativeAWGCaptureSource(
      binding: fixture.path,
      expectedPeerPublicKey: fixture.peerKey,
      readNativeTelemetry: { try twinFeed.read() }
    )
    let mine = try harness.currentSample()
    let theirs = try harness.sample(
      handshake: fixture.baselineHandshake + 1,
      received: fixture.baselineReceived + 100,
      transmitted: fixture.baselineTransmitted + 200,
      from: twin,
      feed: twinFeed
    )

    XCTAssertEqual(mine.binding, theirs.binding)
    XCTAssertEqual(mine.peer, theirs.peer)
    XCTAssertEqual(
      mine.sampledAtMonotonicNanoseconds,
      theirs.sampledAtMonotonicNanoseconds
    )
    XCTAssertNotEqual(mine, theirs)

    XCTAssertThrowsError(
      try coordinator.recordAWGSnapshot(theirs)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .foreignNativeProvenance
      )
    }

    // Positive control: the byte-identical sample from this attempt's own
    // source is accepted.
    let accepting = try harness.makeCoordinator()
    XCTAssertEqual(
      try accepting.recordAWGSnapshot(mine),
      .accepted
    )
  }

  /// A baseline captured under a different environment splits timing
  /// authority, so the coordinator refuses to exist.
  func testBaselineFromAnotherEnvironmentCannotStartAnAttempt() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let other = try Harness(t0: t0, key: key, now: t0 + 10)

    XCTAssertThrowsError(
      try harness.environment.makeCoordinator(
        configuration: try harness.fixture.configuration(),
        baseline: other.baseline
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .foreignNativeProvenance
      )
    }
    XCTAssertNoThrow(
      try harness.environment.makeCoordinator(
        configuration: try harness.fixture.configuration(),
        baseline: harness.baseline
      )
    )
  }

  // MARK: - Sample times

  /// Predicate times are capture times, and a sample taken before the event
  /// it is offered as evidence for is rejected.
  func testStaleSamplesAreRejectedAtEveryProofBoundary() throws {
    // A DNS post-response sample captured before the request was reported
    // sent cannot be that request's response evidence.
    let staleDNS = try Harness(t0: t0, key: key, now: t0 + 10)
    let staleDNSLadder = try staleDNS.ladder()
    let staleDNSTarget = try staleDNS.makeCoordinator()
    staleDNS.clock.set(t0 + 20)
    _ = try staleDNSTarget.recordProtectedDNSRequestSent(
      staleDNS.dnsSendProof(staleDNSLadder)
    )
    XCTAssertThrowsError(
      try staleDNSTarget.recordProtectedDNSProof(
        staleDNS.dnsProof(staleDNSLadder)
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidSampleTime
      )
    }

    // Positive control: the identical samples and proofs are accepted when
    // the post-response sample follows the reported send.
    let freshDNS = try Harness(t0: t0, key: key, now: t0 + 10)
    let freshDNSLadder = try freshDNS.ladder()
    let freshDNSTarget = try freshDNS.makeCoordinator()
    XCTAssertEqual(
      try freshDNSTarget.recordProtectedDNSRequestSent(
        freshDNS.dnsSendProof(freshDNSLadder)
      ),
      .accepted
    )
    XCTAssertEqual(
      try freshDNSTarget.recordProtectedDNSProof(
        freshDNS.dnsProof(freshDNSLadder)
      ),
      .accepted
    )

    // A reflector pre-send sample captured before DNS was accepted cannot
    // start the reflector's own movement window.
    let staleReflector = try Harness(t0: t0, key: key, now: t0 + 10)
    let staleReflectorLadder = try staleReflector.ladder()
    let staleReflectorTarget = try staleReflector.makeCoordinator()
    _ = try staleReflectorTarget.recordProtectedDNSRequestSent(
      staleReflector.dnsSendProof(staleReflectorLadder)
    )
    staleReflector.clock.set(t0 + 20)
    _ = try staleReflectorTarget.recordProtectedDNSProof(
      staleReflector.dnsProof(staleReflectorLadder)
    )
    XCTAssertThrowsError(
      try staleReflectorTarget.recordReflectorRequestSent(
        staleReflector.reflectorSendProof(
          staleReflectorLadder,
          for: staleReflectorTarget
        )
      )
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidSampleTime
      )
    }

    let freshReflector = try Harness(t0: t0, key: key, now: t0 + 10)
    let freshReflectorLadder = try freshReflector.ladder()
    let freshReflectorTarget = try freshReflector.makeCoordinator()
    try freshReflector.driveToDNSAccepted(
      freshReflectorTarget,
      freshReflectorLadder
    )
    XCTAssertEqual(
      try freshReflectorTarget.recordReflectorRequestSent(
        freshReflector.reflectorSendProof(
          freshReflectorLadder,
          for: freshReflectorTarget
        )
      ),
      .accepted
    )

    // An out-of-order sample with non-decreasing counters is rejected on its
    // capture time alone, not on its counters.
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let fixture = harness.fixture
    let outOfOrder = try harness.makeCoordinator()
    let early = try harness.sample(
      handshake: fixture.baselineHandshake + 1,
      received: fixture.baselineReceived + 100,
      transmitted: fixture.baselineTransmitted + 200
    )
    harness.clock.set(t0 + 40)
    let late = try harness.sample(
      handshake: fixture.baselineHandshake + 1,
      received: fixture.baselineReceived + 100,
      transmitted: fixture.baselineTransmitted + 200
    )
    XCTAssertEqual(early.peer, late.peer)
    XCTAssertEqual(try outOfOrder.recordAWGSnapshot(late), .accepted)
    XCTAssertThrowsError(
      try outOfOrder.recordAWGSnapshot(early)
    ) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidSampleTime
      )
    }
  }

  // MARK: - Terminal evidence

  func testTerminalEvidenceCarriesSampleAlignedTimesAndIsEmittedOnce()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let coordinator = try harness.makeCoordinator()
    XCTAssertNil(coordinator.terminalEvidence())

    let ladder = try harness.ladder()
    let response = try response(for: coordinator)
    // Every sample is captured strictly before the message that carries it is
    // accepted, so a predicate stamped with an acceptance time would be
    // visibly different from the sample it claims to rest on.
    harness.clock.set(t0 + 15)
    _ = try coordinator.recordProtectedDNSRequestSent(
      harness.dnsSendProof(ladder)
    )
    harness.clock.set(t0 + 18)
    let dnsPost = try harness.sample(
      handshake: harness.fixture.baselineHandshake + 1,
      received: ladder.dnsPre.peer.receivedBytes + 10,
      transmitted: ladder.dnsPre.peer.transmittedBytes + 10
    )
    harness.clock.set(t0 + 20)
    _ = try coordinator.recordProtectedDNSProof(
      harness.dnsProof(ladder, post: dnsPost)
    )
    harness.clock.set(t0 + 30)
    let reflectorPre = try harness.sample(
      handshake: harness.fixture.baselineHandshake + 1,
      received: dnsPost.peer.receivedBytes + 10,
      transmitted: dnsPost.peer.transmittedBytes + 10
    )
    harness.clock.set(t0 + 35)
    _ = try coordinator.recordReflectorRequestSent(
      harness.reflectorSendProof(
        ladder,
        for: coordinator,
        pre: reflectorPre
      )
    )
    harness.clock.set(t0 + 38)
    let reflectorPost = try harness.sample(
      handshake: harness.fixture.baselineHandshake + 1,
      received: reflectorPre.peer.receivedBytes + 10,
      transmitted: reflectorPre.peer.transmittedBytes + 10
    )
    harness.clock.set(t0 + 40)
    _ = try coordinator.acceptReflectorResponse(
      harness.reflectorProof(
        ladder,
        response: response,
        post: reflectorPost
      )
    )

    let evidence = try XCTUnwrap(coordinator.terminalEvidence())
    XCTAssertEqual(evidence.status, .succeeded)
    XCTAssertNil(evidence.failure)
    XCTAssertEqual(
      evidence.schema,
      "winn-stageb-provider-terminal-evidence/1"
    )
    XCTAssertEqual(
      evidence.requestedAtMonotonicNanoseconds,
      t0
    )
    XCTAssertEqual(
      evidence.baselineSample.sampledAtMonotonicNanoseconds,
      t0 + 10
    )

    // The two predicates physical evidence requires to equal a sample time
    // do equal that sample's capture time, not a message acceptance time.
    let handshakeSample = try XCTUnwrap(evidence.handshakePostSample)
    let counterSample = try XCTUnwrap(evidence.counterPostSample)
    XCTAssertEqual(
      evidence.freshAWGHandshakeAtMonotonicNanoseconds,
      handshakeSample.sampledAtMonotonicNanoseconds
    )
    XCTAssertEqual(
      evidence.authenticatedBidirectionalBytesAtMonotonicNanoseconds,
      counterSample.sampledAtMonotonicNanoseconds
    )
    XCTAssertEqual(
      handshakeSample.sampledAtMonotonicNanoseconds,
      ladder.dnsPre.sampledAtMonotonicNanoseconds
    )
    XCTAssertEqual(
      counterSample.sampledAtMonotonicNanoseconds,
      ladder.dnsPre.sampledAtMonotonicNanoseconds
    )
    XCTAssertEqual(
      counterSample.receivedBytes,
      ladder.dnsPre.peer.receivedBytes
    )
    XCTAssertEqual(
      evidence.authenticatedInboundDeltaBytes,
      ladder.dnsPre.peer.receivedBytes
        - harness.baseline.peer.receivedBytes
    )
    XCTAssertEqual(
      evidence.authenticatedOutboundDeltaBytes,
      ladder.dnsPre.peer.transmittedBytes
        - harness.baseline.peer.transmittedBytes
    )
    XCTAssertEqual(
      handshakeSample.identity,
      harness.fixture.path.identity
    )

    // Event times are acceptance times under the coordinator's own lock and
    // follow the ladder the physical verifier requires. They are strictly
    // later than the sample times above, so the two kinds of time cannot be
    // silently interchanged.
    XCTAssertEqual(
      evidence.dnsRequestSentAtMonotonicNanoseconds,
      t0 + 15
    )
    XCTAssertEqual(
      evidence.protectedDNSAtMonotonicNanoseconds,
      t0 + 20
    )
    XCTAssertEqual(
      evidence.dnsResponseObservedAtMonotonicNanoseconds,
      evidence.protectedDNSAtMonotonicNanoseconds
    )
    XCTAssertEqual(
      evidence.reflectorRequestSentAtMonotonicNanoseconds,
      t0 + 35
    )
    XCTAssertEqual(
      evidence.authenticatedReflectorAtMonotonicNanoseconds,
      t0 + 40
    )
    XCTAssertEqual(
      evidence.reflectorResponseObservedAtMonotonicNanoseconds,
      evidence.authenticatedReflectorAtMonotonicNanoseconds
    )
    XCTAssertEqual(evidence.terminalAtMonotonicNanoseconds, t0 + 40)
    XCTAssertTrue(evidence.dnsAttempted)
    XCTAssertTrue(evidence.reflectorAttempted)
    XCTAssertEqual(
      evidence.dnsResponsePayloadSHA256,
      Array(SHA256.hash(data: harness.fixture.dnsResponse))
    )
    XCTAssertEqual(
      evidence.dnsQueryNonceSHA256,
      harness.fixture.dnsProbe.cacheBypassNonceSHA256
    )
    XCTAssertEqual(
      evidence.canarySequence,
      harness.fixture.canarySequence
    )

    let ordered = [
      evidence.requestedAtMonotonicNanoseconds,
      evidence.baselineSample.sampledAtMonotonicNanoseconds,
      handshakeSample.sampledAtMonotonicNanoseconds,
      counterSample.sampledAtMonotonicNanoseconds,
      try XCTUnwrap(evidence.dnsRequestSentAtMonotonicNanoseconds),
      try XCTUnwrap(evidence.protectedDNSAtMonotonicNanoseconds),
      try XCTUnwrap(
        evidence.reflectorRequestSentAtMonotonicNanoseconds
      ),
      try XCTUnwrap(
        evidence.authenticatedReflectorAtMonotonicNanoseconds
      ),
      evidence.terminalAtMonotonicNanoseconds,
    ]
    XCTAssertEqual(ordered, ordered.sorted())

    // Emitted once: a later terminal call cannot rewrite it.
    XCTAssertFalse(coordinator.cancel())
    XCTAssertEqual(coordinator.terminalEvidence(), evidence)
  }

  func testFailureTerminalEvidenceRecordsOnlyProvenPredicates() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let coordinator = try harness.makeCoordinator()
    _ = try coordinator.recordProtectedDNSRequestSent(
      harness.dnsSendProof(ladder)
    )
    XCTAssertThrowsError(
      try coordinator.recordProtectedDNSProof(
        harness.dnsProof(ladder, post: ladder.dnsPre)
      )
    )

    let evidence = try XCTUnwrap(coordinator.terminalEvidence())
    XCTAssertEqual(evidence.status, .failed)
    XCTAssertEqual(evidence.failure, .invalidDNSProof)
    XCTAssertNotNil(evidence.handshakePostSample)
    XCTAssertNotNil(evidence.counterPostSample)
    XCTAssertTrue(evidence.dnsAttempted)
    XCTAssertNil(evidence.protectedDNSAtMonotonicNanoseconds)
    XCTAssertNil(evidence.dnsResponsePayloadSHA256)
    XCTAssertFalse(evidence.reflectorAttempted)
    XCTAssertNil(evidence.reflectorRequestSentAtMonotonicNanoseconds)
    XCTAssertNil(
      evidence.authenticatedReflectorAtMonotonicNanoseconds
    )
    XCTAssertEqual(evidence.terminalAtMonotonicNanoseconds, t0 + 10)
  }

  func testTerminalEvidenceContainsOnlyAllowlistedFields() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let coordinator = try harness.makeCoordinator()
    XCTAssertTrue(coordinator.cancel())
    let evidence = try XCTUnwrap(coordinator.terminalEvidence())
    let labels = Set(
      Mirror(reflecting: evidence).children.compactMap(\.label)
    )
    XCTAssertEqual(
      labels,
      [
        "schema",
        "protocolVersion",
        "measurementScope",
        "status",
        "failure",
        "canarySequence",
        "requestedAtMonotonicNanoseconds",
        "deadlineMonotonicNanoseconds",
        "terminalAtMonotonicNanoseconds",
        "baselineSample",
        "handshakePostSample",
        "counterPostSample",
        "authenticatedOutboundDeltaBytes",
        "authenticatedInboundDeltaBytes",
        "freshAWGHandshakeAtMonotonicNanoseconds",
        "authenticatedBidirectionalBytesAtMonotonicNanoseconds",
        "protectedDNSAtMonotonicNanoseconds",
        "authenticatedReflectorAtMonotonicNanoseconds",
        "dnsAttempted",
        "dnsRequestSentAtMonotonicNanoseconds",
        "dnsResponseObservedAtMonotonicNanoseconds",
        "dnsQueryNonceSHA256",
        "dnsResponsePayloadSHA256",
        "reflectorAttempted",
        "reflectorRequestSentAtMonotonicNanoseconds",
        "reflectorResponseObservedAtMonotonicNanoseconds",
      ]
    )
    XCTAssertFalse(labels.contains("challenge"))
    XCTAssertFalse(labels.contains("responseDatagram"))
    XCTAssertEqual(evidence.status, .cancelled)
    XCTAssertNil(evidence.handshakePostSample)
    XCTAssertNil(evidence.counterPostSample)
    XCTAssertEqual(evidence.authenticatedInboundDeltaBytes, 0)
  }

  /// The reflector observation time comes from the shared acceptance domain's
  /// own read, which can be later than this method's read, and the terminal
  /// record must not predate it.
  func testReflectorObservationTimeIsTheSharedDomainReadAndBoundsTerminal()
    throws
  {
    let harness = try Harness(t0: t0, key: key, now: t0 + 10)
    let ladder = try harness.ladder()
    let coordinator = try harness.makeCoordinator()
    try harness.driveToReflectorSend(coordinator, ladder)
    let response = try response(for: coordinator)

    // Read 1 is this method's own; read 2 is the acceptance domain's.
    harness.clock.scheduleReadValue(after: 1, to: t0 + 25)
    XCTAssertEqual(
      try coordinator.acceptReflectorResponse(
        harness.reflectorProof(ladder, response: response)
      ),
      .accepted
    )

    let evidence = try XCTUnwrap(coordinator.terminalEvidence())
    XCTAssertEqual(
      evidence.authenticatedReflectorAtMonotonicNanoseconds,
      t0 + 25
    )
    XCTAssertEqual(
      evidence.terminalAtMonotonicNanoseconds,
      t0 + 25
    )
    XCTAssertGreaterThanOrEqual(
      evidence.terminalAtMonotonicNanoseconds,
      try XCTUnwrap(
        evidence.authenticatedReflectorAtMonotonicNanoseconds
      )
    )
  }

  /// A non-canonical question name is refused even when every digest in the
  /// probe binding was chosen to match how a permissive parser would read it.
  func testNonCanonicalQuestionNameIsRefusedEvenWithMatchingPins() throws {
    let pointer = dnsPointerShapedQuestionResponse()
    let root = dnsRootQuestionResponse()
    let cases: [(String, Data, [UInt8], [UInt8])] = [
      (
        "compression/reserved label prefix",
        pointer.payload,
        pointer.question,
        pointer.firstLabel
      ),
      ("root-only name", root.payload, root.question, []),
    ]

    for (label, payload, question, firstLabel) in cases {
      let probe = try StageBDNSProbeBinding(
        transactionID: dnsTransactionID,
        questionSHA256: Array(SHA256.hash(data: Data(question))),
        cacheBypassNonceSHA256: Array(
          SHA256.hash(data: Data(firstLabel))
        ),
        privateResolverIdentitySHA256:
          [UInt8](repeating: 0x79, count: 32)
      )
      let harness = try Harness(
        t0: t0,
        key: key,
        now: t0 + 10,
        dnsProbe: probe,
        dnsResponse: payload
      )
      let ladder = try harness.ladder()
      let coordinator = try harness.makeCoordinator()
      _ = try coordinator.recordProtectedDNSRequestSent(
        harness.dnsSendProof(ladder)
      )
      XCTAssertThrowsError(
        try coordinator.recordProtectedDNSProof(
          harness.dnsProof(ladder)
        ),
        label
      ) {
        XCTAssertEqual(
          $0 as? StageBProviderValidationError,
          .invalidDNSWireResponse,
          label
        )
      }
    }
  }

  func testBaselineSampledBeforeT0CannotStartAnAttempt() throws {
    let harness = try Harness(t0: t0, key: key, now: t0 - 100)
    harness.clock.set(t0 + 10)
    XCTAssertThrowsError(try harness.makeCoordinator()) {
      XCTAssertEqual(
        $0 as? StageBProviderValidationError,
        .invalidSampleTime
      )
    }

    // Positive control: the same attempt starts once the baseline is taken
    // at or after T0.
    let inWindow = try Harness(t0: t0, key: key, now: t0)
    inWindow.clock.set(t0 + 10)
    XCTAssertNoThrow(try inWindow.makeCoordinator())
  }

  private func response(
    for coordinator: StageBProviderCoordinator
  ) throws -> Data {
    let verified = try StageBReflectorCodec.verifyRequest(
      coordinator.outboundReflectorDatagram,
      key: key,
      reflectorNowUnixMilliseconds: 1_500
    )
    return try StageBReflectorCodec.encodeResponse(
      for: verified,
      key: key,
      reflectorReceivedUnixMilliseconds: 1_500,
      reflectorSentUnixMilliseconds: 1_501
    )
  }
}

private enum Event: CaseIterable {
  case dnsSend
  case dnsResponse
  case reflectorSend
  case reflectorResponse
}

private enum TestNativeTelemetryError: Error, Equatable {
  case readFailed
}

private func permutations<T>(_ values: [T]) -> [[T]] {
  guard let first = values.first else { return [[]] }
  return permutations(Array(values.dropFirst())).flatMap { suffix in
    (0...suffix.count).map { index in
      var result = suffix
      result.insert(first, at: index)
      return result
    }
  }
}

private final class TestClock: @unchecked Sendable {
  private let lock = NSLock()
  private var current: UInt64
  private var readsBeforeRollback: Int?
  private var rollbackValue: UInt64 = 0

  init(_ current: UInt64) {
    self.current = current
  }

  func set(_ value: UInt64) {
    lock.lock()
    current = value
    lock.unlock()
  }

  /// After `reads` further reads, every later read returns `value`.
  ///
  /// `value` may be behind or ahead of the current time, which is how a
  /// rollback or an advance that lands between two reads inside one call is
  /// expressed.
  func scheduleReadValue(after reads: Int, to value: UInt64) {
    lock.lock()
    readsBeforeRollback = reads
    rollbackValue = value
    lock.unlock()
  }

  func callAsFunction() -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    if let remaining = readsBeforeRollback {
      if remaining == 0 { return rollbackValue }
      readsBeforeRollback = remaining - 1
    }
    return current
  }
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0

  var value: Int {
    lock.lock()
    defer { lock.unlock() }
    return count
  }

  func increment() {
    lock.lock()
    count += 1
    lock.unlock()
  }
}

private final class TestTelemetryFeed: @unchecked Sendable {
  private let lock = NSLock()
  private var telemetry: StageBAWGNativePeerTelemetry

  init(_ telemetry: StageBAWGNativePeerTelemetry) {
    self.telemetry = telemetry
  }

  func set(_ telemetry: StageBAWGNativePeerTelemetry) {
    lock.lock()
    self.telemetry = telemetry
    lock.unlock()
  }

  func read() throws -> StageBAWGNativePeerTelemetry {
    lock.lock()
    defer { lock.unlock() }
    return telemetry
  }
}

/// The four samples of one admissible attempt.
///
/// `dnsPre` proves the handshake and bidirectional-byte predicates before the
/// DNS request. `dnsPost` closes the DNS window. `reflectorPre` starts a new
/// window strictly beyond `dnsPost`, and `reflectorPost` closes it.
private struct Ladder {
  let dnsPre: StageBAWGSnapshot
  let dnsPost: StageBAWGSnapshot
  let reflectorPre: StageBAWGSnapshot
  let reflectorPost: StageBAWGSnapshot
}

/// One environment, one native capture source, and one baseline capture.
///
/// Every sample in these tests is produced by `source`, because there is no
/// other way to produce one.
private final class Harness {
  let fixture: Fixture
  let clock: TestClock
  let environment: StageBProviderEnvironment
  let telemetryFeed: TestTelemetryFeed
  let source: StageBAWGNativeCaptureSource
  let baseline: StageBAWGSnapshot

  init(
    t0: UInt64,
    key: [UInt8],
    now: UInt64,
    baselineHandshake: UInt64 = 100,
    baselineHandshakeNanoseconds: UInt32 = 0,
    dnsProbe: StageBDNSProbeBinding? = nil,
    dnsResponse: Data? = nil
  ) throws {
    fixture = try Fixture(
      t0: t0,
      baselineHandshake: baselineHandshake,
      baselineHandshakeNanoseconds: baselineHandshakeNanoseconds,
      dnsProbe: dnsProbe,
      dnsResponse: dnsResponse
    )
    let clock = TestClock(now)
    self.clock = clock
    environment = try StageBProviderEnvironment(
      responseReplayCapacity: 64,
      reflectorKey: key,
      monotonicClock: { clock() }
    )
    let telemetryFeed = TestTelemetryFeed(
      try fixture.telemetry(
        handshake: fixture.baselineHandshake,
        handshakeNanoseconds: fixture.baselineHandshakeNanoseconds,
        received: fixture.baselineReceived,
        transmitted: fixture.baselineTransmitted
      )
    )
    self.telemetryFeed = telemetryFeed
    source = try environment.makeNativeAWGCaptureSource(
      binding: fixture.path,
      expectedPeerPublicKey: fixture.peerKey,
      readNativeTelemetry: { try telemetryFeed.read() }
    )
    baseline = try Harness.capture(
      fixture: fixture,
      source: source,
      feed: telemetryFeed,
      handshake: fixture.baselineHandshake,
      handshakeNanoseconds: fixture.baselineHandshakeNanoseconds,
      received: fixture.baselineReceived,
      transmitted: fixture.baselineTransmitted
    )
  }

  private static func capture(
    fixture: Fixture,
    source: StageBAWGNativeCaptureSource,
    feed: TestTelemetryFeed,
    handshake: UInt64,
    handshakeNanoseconds: UInt32,
    received: UInt64,
    transmitted: UInt64
  ) throws -> StageBAWGSnapshot {
    feed.set(
      try fixture.telemetry(
        handshake: handshake,
        handshakeNanoseconds: handshakeNanoseconds,
        received: received,
        transmitted: transmitted
      )
    )
    return try source.capture()
  }

  func sample(
    handshake: UInt64,
    handshakeNanoseconds: UInt32 = 0,
    received: UInt64,
    transmitted: UInt64,
    from source: StageBAWGNativeCaptureSource? = nil,
    feed: TestTelemetryFeed? = nil
  ) throws -> StageBAWGSnapshot {
    try Harness.capture(
      fixture: fixture,
      source: source ?? self.source,
      feed: feed ?? telemetryFeed,
      handshake: handshake,
      handshakeNanoseconds: handshakeNanoseconds,
      received: received,
      transmitted: transmitted
    )
  }

  /// The sample used wherever a test only needs "some later observation".
  func currentSample() throws -> StageBAWGSnapshot {
    try sample(
      handshake: fixture.baselineHandshake + 1,
      received: fixture.baselineReceived + 100,
      transmitted: fixture.baselineTransmitted + 200
    )
  }

  func ladder() throws -> Ladder {
    Ladder(
      dnsPre: try sample(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 100,
        transmitted: fixture.baselineTransmitted + 200
      ),
      dnsPost: try sample(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 110,
        transmitted: fixture.baselineTransmitted + 210
      ),
      reflectorPre: try sample(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 120,
        transmitted: fixture.baselineTransmitted + 220
      ),
      reflectorPost: try sample(
        handshake: fixture.baselineHandshake + 1,
        received: fixture.baselineReceived + 130,
        transmitted: fixture.baselineTransmitted + 230
      )
    )
  }

  func makeCoordinator(
    sharedEnvironment: Bool = false
  ) throws -> StageBProviderCoordinator {
    _ = sharedEnvironment
    return try environment.makeCoordinator(
      configuration: fixture.configuration(),
      baseline: baseline
    )
  }

  func dnsSendProof(
    _ ladder: Ladder,
    probe: StageBDNSProbeBinding? = nil,
    pre: StageBAWGSnapshot? = nil
  ) -> StageBProtectedDNSRequestSendProof {
    StageBProtectedDNSRequestSendProof(
      probe: probe ?? fixture.dnsProbe,
      binding: fixture.path,
      preRequestAWGSnapshot: pre ?? ladder.dnsPre
    )
  }

  func dnsProof(
    _ ladder: Ladder,
    responsePayload: Data? = nil,
    pre: StageBAWGSnapshot? = nil,
    post: StageBAWGSnapshot? = nil
  ) -> StageBProtectedDNSProof {
    StageBProtectedDNSProof(
      probe: fixture.dnsProbe,
      responsePayload: responsePayload ?? fixture.dnsResponse,
      binding: fixture.path,
      preRequestAWGSnapshot: pre ?? ladder.dnsPre,
      postResponseAWGSnapshot: post ?? ladder.dnsPost
    )
  }

  func reflectorSendProof(
    _ ladder: Ladder,
    for coordinator: StageBProviderCoordinator,
    pre: StageBAWGSnapshot? = nil
  ) throws -> StageBReflectorRequestSendProof {
    try StageBReflectorRequestSendProof(
      requestDatagramSHA256: Array(
        SHA256.hash(data: coordinator.outboundReflectorDatagram)
      ),
      binding: fixture.path,
      preSendAWGSnapshot: pre ?? ladder.reflectorPre
    )
  }

  func reflectorProof(
    _ ladder: Ladder,
    response: Data,
    post: StageBAWGSnapshot? = nil
  ) -> StageBReflectorResponseProof {
    StageBReflectorResponseProof(
      responseDatagram: response,
      binding: fixture.path,
      postResponseAWGSnapshot: post ?? ladder.reflectorPost
    )
  }

  func driveToDNSAccepted(
    _ coordinator: StageBProviderCoordinator,
    _ ladder: Ladder
  ) throws {
    _ = try coordinator.recordProtectedDNSRequestSent(
      dnsSendProof(ladder)
    )
    _ = try coordinator.recordProtectedDNSProof(dnsProof(ladder))
  }

  func driveToReflectorSend(
    _ coordinator: StageBProviderCoordinator,
    _ ladder: Ladder
  ) throws {
    try driveToDNSAccepted(coordinator, ladder)
    _ = try coordinator.recordReflectorRequestSent(
      try reflectorSendProof(ladder, for: coordinator)
    )
  }
}

private struct Fixture {
  let t0: UInt64
  let runID = stageBUUID(0x11)
  let attemptNonce = stageBUUID(0x22)
  let sourceSHA256 = [UInt8](repeating: 0x33, count: 32)
  let artifactSHA256 = [UInt8](repeating: 0x44, count: 32)
  let configSHA256 = [UInt8](repeating: 0x45, count: 32)
  let peerKey = [UInt8](repeating: 0x55, count: 32)
  let peerSHA256: [UInt8]
  let challenge = [UInt8](repeating: 0x66, count: 32)
  let canarySequence: UInt64 = 1
  let dnsResponse: Data
  let dnsResponsePayloadSHA256: [UInt8]
  let baselineReceived: UInt64 = 10
  let baselineTransmitted: UInt64 = 20
  let baselineHandshake: UInt64
  let context: WCF3ConnectionContext
  let path: StageBProviderPathBinding
  let dnsProbe: StageBDNSProbeBinding
  let baselineHandshakeNanoseconds: UInt32

  init(
    t0: UInt64,
    baselineHandshake: UInt64 = 100,
    baselineHandshakeNanoseconds: UInt32 = 0,
    dnsProbe: StageBDNSProbeBinding? = nil,
    dnsResponse: Data? = nil
  ) throws {
    self.t0 = t0
    self.baselineHandshake = baselineHandshake
    self.baselineHandshakeNanoseconds = baselineHandshakeNanoseconds
    peerSHA256 = Array(
      SHA256.hash(data: Data([UInt8](repeating: 0x55, count: 32)))
    )
    context = try WCF3ConnectionContext(
      sessionID: stageBUUID(0x88),
      bindingID: stageBUUID(0x99),
      pskGeneration: 7,
      sequenceEpoch: 9
    )
    path = try StageBProviderPathBinding(
      pathID: stageBUUID(0xaa),
      identity: try StageBAWGEnginePathIdentity(
        signedRuntimeArtifactSHA256: artifactSHA256,
        wgTurnOnConfigSHA256: configSHA256,
        expectedPeerPublicKeySHA256: peerSHA256,
        engineInstanceNonce: stageBUUID(0xab),
        engineGeneration: 3,
        pathGeneration: 4,
        winningInterfaceTokenSHA256:
          [UInt8](repeating: 0xbb, count: 32)
      ),
      context: context
    )
    let response = dnsResponse ?? dnsResponsePayload()
    self.dnsResponse = response
    dnsResponsePayloadSHA256 = Array(SHA256.hash(data: response))
    self.dnsProbe =
      try dnsProbe
      ?? StageBDNSProbeBinding(
        transactionID: dnsTransactionID,
        questionSHA256: Array(
          SHA256.hash(data: Data(dnsQuestionBytes()))
        ),
        cacheBypassNonceSHA256: Array(
          SHA256.hash(data: Data(dnsNonceLabel))
        ),
        privateResolverIdentitySHA256:
          [UInt8](repeating: 0x79, count: 32)
      )
  }

  func telemetry(
    handshake: UInt64,
    handshakeNanoseconds: UInt32 = 0,
    received: UInt64,
    transmitted: UInt64
  ) throws -> StageBAWGNativePeerTelemetry {
    try StageBAWGNativePeerTelemetry(
      peerPublicKey: peerKey,
      latestHandshakeUnixSeconds: handshake,
      latestHandshakeNanoseconds: handshakeNanoseconds,
      receivedBytes: received,
      transmittedBytes: transmitted
    )
  }

  func configuration(
    runID: [UInt8]? = nil,
    attemptNonce: [UInt8]? = nil,
    artifactSHA256: [UInt8]? = nil,
    expectedPeerPublicKeySHA256: [UInt8]? = nil,
    path: StageBProviderPathBinding? = nil
  ) throws -> StageBProviderAttemptConfiguration {
    try StageBProviderAttemptConfiguration(
      runID: runID ?? self.runID,
      attemptNonce: attemptNonce ?? self.attemptNonce,
      sourceSHA256: sourceSHA256,
      artifactSHA256: artifactSHA256 ?? self.artifactSHA256,
      expectedPeerPublicKeySHA256:
        expectedPeerPublicKeySHA256 ?? peerSHA256,
      path: path ?? self.path,
      canarySequence: canarySequence,
      issuedAtUnixMilliseconds: 1_000,
      expiresAtUnixMilliseconds: 2_000,
      challenge: challenge,
      dnsProbe: dnsProbe,
      dnsResponsePayloadSHA256: dnsResponsePayloadSHA256,
      requestedAtMonotonicNanoseconds: t0
    )
  }

  func alteredPath(
    pathID: [UInt8]? = nil,
    signedRuntimeArtifactSHA256: [UInt8]? = nil,
    wgTurnOnConfigSHA256: [UInt8]? = nil,
    expectedPeerPublicKeySHA256: [UInt8]? = nil,
    engineInstanceNonce: [UInt8]? = nil,
    engineGeneration: UInt64? = nil,
    pathGeneration: UInt64? = nil,
    winningInterfaceTokenSHA256: [UInt8]? = nil,
    context: WCF3ConnectionContext? = nil
  ) throws -> StageBProviderPathBinding {
    try StageBProviderPathBinding(
      pathID: pathID ?? path.pathID,
      identity: try StageBAWGEnginePathIdentity(
        signedRuntimeArtifactSHA256:
          signedRuntimeArtifactSHA256
          ?? path.identity.signedRuntimeArtifactSHA256,
        wgTurnOnConfigSHA256:
          wgTurnOnConfigSHA256
          ?? path.identity.wgTurnOnConfigSHA256,
        expectedPeerPublicKeySHA256:
          expectedPeerPublicKeySHA256
          ?? path.identity.expectedPeerPublicKeySHA256,
        engineInstanceNonce:
          engineInstanceNonce ?? path.identity.engineInstanceNonce,
        engineGeneration:
          engineGeneration ?? path.identity.engineGeneration,
        pathGeneration:
          pathGeneration ?? path.identity.pathGeneration,
        winningInterfaceTokenSHA256:
          winningInterfaceTokenSHA256
          ?? path.identity.winningInterfaceTokenSHA256
      ),
      context: context ?? path.context
    )
  }

  func identity(
    signedRuntimeArtifactSHA256: [UInt8]? = nil,
    wgTurnOnConfigSHA256: [UInt8]? = nil,
    expectedPeerPublicKeySHA256: [UInt8]? = nil,
    engineInstanceNonce: [UInt8]? = nil,
    engineGeneration: UInt64? = nil,
    pathGeneration: UInt64? = nil,
    winningInterfaceTokenSHA256: [UInt8]? = nil
  ) throws -> StageBAWGEnginePathIdentity {
    try StageBAWGEnginePathIdentity(
      signedRuntimeArtifactSHA256:
        signedRuntimeArtifactSHA256
        ?? path.identity.signedRuntimeArtifactSHA256,
      wgTurnOnConfigSHA256:
        wgTurnOnConfigSHA256
        ?? path.identity.wgTurnOnConfigSHA256,
      expectedPeerPublicKeySHA256:
        expectedPeerPublicKeySHA256
        ?? path.identity.expectedPeerPublicKeySHA256,
      engineInstanceNonce:
        engineInstanceNonce ?? path.identity.engineInstanceNonce,
      engineGeneration:
        engineGeneration ?? path.identity.engineGeneration,
      pathGeneration:
        pathGeneration ?? path.identity.pathGeneration,
      winningInterfaceTokenSHA256:
        winningInterfaceTokenSHA256
        ?? path.identity.winningInterfaceTokenSHA256
    )
  }
}

// MARK: - DNS wire fixtures

private let dnsTransactionID: UInt16 = 0x1234
private let dnsNonceLabel = Array("n0nce-7f3a91c4".utf8)

/// The question section exactly as it appears on the wire.
private func dnsQuestionBytes(
  nonceLabel: [UInt8] = dnsNonceLabel,
  secondLabel: String = "probe"
) -> [UInt8] {
  var bytes: [UInt8] = []
  for label in [nonceLabel, Array(secondLabel.utf8), Array("winn".utf8)] {
    bytes.append(UInt8(label.count))
    bytes += label
  }
  bytes.append(0)
  bytes += [0x00, 0x10]  // TXT
  bytes += [0x00, 0x01]  // IN
  return bytes
}

/// One well-formed private DNS answer, with every checked field alterable.
private func dnsResponsePayload(
  transactionID: UInt16 = dnsTransactionID,
  flagsHigh: UInt8 = 0x81,
  flagsLow: UInt8 = 0x80,
  questionCount: UInt16 = 1,
  answerCount: UInt16 = 1,
  nonceLabel: [UInt8] = dnsNonceLabel,
  secondLabel: String = "probe",
  answerByte: UInt8 = 0x2a
) -> Data {
  var bytes: [UInt8] = [
    UInt8(transactionID >> 8),
    UInt8(transactionID & 0xff),
    flagsHigh,
    flagsLow,
    UInt8(questionCount >> 8),
    UInt8(questionCount & 0xff),
    UInt8(answerCount >> 8),
    UInt8(answerCount & 0xff),
    0, 0,
    0, 0,
  ]
  bytes += dnsQuestionBytes(
    nonceLabel: nonceLabel,
    secondLabel: secondLabel
  )
  bytes += [0xc0, 0x0c]  // NAME: pointer to the question name
  bytes += [0x00, 0x10]  // TYPE: TXT
  bytes += [0x00, 0x01]  // CLASS: IN
  bytes += [0x00, 0x00, 0x00, 0x00]  // TTL 0
  bytes += [0x00, 0x02]  // RDLENGTH
  bytes += [0x01, answerByte]  // RDATA
  return Data(bytes)
}

private func dnsResponse(
  transactionID: UInt16 = dnsTransactionID,
  flagsHigh: UInt8 = 0x81,
  flagsLow: UInt8 = 0x80,
  questionCount: UInt16 = 1,
  answerCount: UInt16 = 1,
  secondLabel: String = "probe",
  answerByte: UInt8 = 0x2a
) -> Data {
  dnsResponsePayload(
    transactionID: transactionID,
    flagsHigh: flagsHigh,
    flagsLow: flagsLow,
    questionCount: questionCount,
    answerCount: answerCount,
    secondLabel: secondLabel,
    answerByte: answerByte
  )
}

/// A response whose question name starts with a compression/reserved label
/// prefix, returned with the exact question and label bytes a parser that
/// tolerated that prefix would hash.
private func dnsPointerShapedQuestionResponse()
  -> (payload: Data, question: [UInt8], firstLabel: [UInt8])
{
  var bytes: [UInt8] = [
    UInt8(dnsTransactionID >> 8),
    UInt8(dnsTransactionID & 0xff),
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
  ]
  // 0xc0 is a pointer prefix; a permissive parser reads it as a 192-byte
  // label, so 192 bytes of label follow to keep that reading in bounds.
  let label = [UInt8](repeating: 0x61, count: 192)
  bytes.append(0xc0)
  bytes += label
  bytes.append(0)
  bytes += [0x00, 0x10, 0x00, 0x01]
  let question = Array(bytes[12...])
  bytes += dnsAnswerRecord()
  return (Data(bytes), question, label)
}

/// A response whose question name is the root name, so it carries no label
/// that could be a cache-bypass nonce.
private func dnsRootQuestionResponse()
  -> (payload: Data, question: [UInt8])
{
  var bytes: [UInt8] = [
    UInt8(dnsTransactionID >> 8),
    UInt8(dnsTransactionID & 0xff),
    0x81, 0x80,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
  ]
  bytes.append(0)
  bytes += [0x00, 0x10, 0x00, 0x01]
  let question = Array(bytes[12...])
  bytes += dnsAnswerRecord()
  return (Data(bytes), question)
}

private func dnsAnswerRecord(answerByte: UInt8 = 0x2a) -> [UInt8] {
  var bytes: [UInt8] = [0xc0, 0x0c]
  bytes += [0x00, 0x10]
  bytes += [0x00, 0x01]
  bytes += [0x00, 0x00, 0x00, 0x00]
  bytes += [0x00, 0x02]
  bytes += [0x01, answerByte]
  return bytes
}

private func stageBUUID(_ fill: UInt8) -> [UInt8] {
  var bytes = [UInt8](repeating: fill, count: 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  return bytes
}
