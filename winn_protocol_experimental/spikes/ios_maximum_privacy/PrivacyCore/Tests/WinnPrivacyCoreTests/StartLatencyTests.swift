import CryptoKit
import Foundation
import XCTest
@testable import WinnPrivacyCore
@testable import WinnPrivacyStageACore

private enum InjectedFailure: Error { case synchronize }

private let nonce = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
private let runID = "01234567-89ab-cdef-0123-456789abcdef"
private let sourceDigest = String(repeating: "a", count: 64)
private let firstDigest = String(repeating: "b", count: 64)
private let durabilityBarrier =
    SpikeDurabilityBarrier.fullFsync.rawValue

final class StartLatencyTests: XCTestCase {
    func testStageBStartOptionsPreserveFirstClickT0InSeparateNamespace()
        throws
    {
        let nonce = "01234567-89ab-4def-8123-456789abcdef"
        let encoded = try StageBStartOptions.encode(
            attemptNonce: nonce,
            connectButtonT0MonotonicNanoseconds: 123
        )
        XCTAssertEqual(Set(encoded.keys), [
            StageBStartOptions.attemptNonceKey,
            StageBStartOptions.connectButtonT0Key,
            StageBStartOptions.attemptSchemaKey,
        ])
        XCTAssertTrue(
            encoded.keys.allSatisfy {
                $0.hasPrefix(StageBStartOptions.optionNamespace)
            }
        )
        XCTAssertFalse(
            encoded.keys.contains {
                $0.hasPrefix(StartLatencyConstants.optionNamespace)
            }
        )
        let parsed = try StageBStartOptions.parse(
            namespacedOptions: encoded
        )
        XCTAssertEqual(parsed.attemptNonce, nonce)
        XCTAssertEqual(
            parsed.connectButtonT0MonotonicNanoseconds,
            123
        )
    }

    func testStageBStartOptionsRejectEveryMalformedShape() throws {
        let nonce = "01234567-89ab-4def-8123-456789abcdef"
        let valid = try StageBStartOptions.encode(
            attemptNonce: nonce,
            connectButtonT0MonotonicNanoseconds: 123
        )
        let mutations: [(inout [String: String]) -> Void] = [
            { (value: inout [String: String]) in
                value.removeValue(
                    forKey: StageBStartOptions.attemptNonceKey
                )
            },
            { (value: inout [String: String]) in
                value[StageBStartOptions.attemptNonceKey] =
                    nonce.uppercased()
            },
            { (value: inout [String: String]) in
                value[StageBStartOptions.attemptNonceKey] =
                    "01234567-89ab-5def-8123-456789abcdef"
            },
            { (value: inout [String: String]) in
                value[StageBStartOptions.attemptNonceKey] =
                    "01234567-89ab-4def-7123-456789abcdef"
            },
            { (value: inout [String: String]) in
                value[StageBStartOptions.connectButtonT0Key] = "0"
            },
            { (value: inout [String: String]) in
                value[StageBStartOptions.connectButtonT0Key] = "0123"
            },
            { (value: inout [String: String]) in
                value[StageBStartOptions.attemptSchemaKey] =
                    "winn-stageb-physical-attempt/1"
            },
            { (value: inout [String: String]) in
                value["WinnStageBUnknown"] = "1"
            },
        ]
        for mutation in mutations {
            var candidate = valid
            mutation(&candidate)
            XCTAssertThrowsError(
                try StageBStartOptions.parse(
                    namespacedOptions: candidate
                )
            )
        }
    }

    func testStageBProviderStartOptionsBindNamespacesAndChronology()
        throws
    {
        let nonce = "01234567-89ab-4def-8123-456789abcdef"
        var entries: [(key: String, value: Any)] = [
            (
                StartLatencyConstants.nonceOptionKey,
                nonce as NSString
            ),
            (
                StartLatencyConstants.requestedAtOptionKey,
                "200" as NSString
            ),
        ]
        entries += try StageBStartOptions.encode(
            attemptNonce: nonce,
            connectButtonT0MonotonicNanoseconds: 100
        ).map { (key: $0.key, value: $0.value as NSString) }
        entries.append((key: "SystemForeignKey", value: 7))

        let parsed = try StageBProviderStartOptions.parse(
            entries: entries,
            providerReceivedAtMonotonicNanoseconds: 300
        )
        XCTAssertEqual(parsed.attemptNonce, nonce)
        XCTAssertEqual(parsed.connectButtonT0MonotonicNanoseconds, 100)
        XCTAssertEqual(parsed.requestedAtMonotonicNanoseconds, 200)
    }

    func testStageBProviderStartOptionsAdmitBothInclusiveBoundaries()
        throws
    {
        let nonce = "01234567-89ab-4def-8123-456789abcdef"
        var entries: [(key: String, value: Any)] = [
            (StartLatencyConstants.nonceOptionKey, nonce),
            (StartLatencyConstants.requestedAtOptionKey, "200"),
        ]
        entries += try StageBStartOptions.encode(
            attemptNonce: nonce,
            connectButtonT0MonotonicNanoseconds: 200
        ).map { (key: $0.key, value: $0.value as Any) }
        XCTAssertNoThrow(
            try StageBProviderStartOptions.parse(
                entries: entries,
                providerReceivedAtMonotonicNanoseconds: 200
            )
        )
    }

    func testStageBProviderStartOptionsRejectBindingAndChronologyMutations()
        throws
    {
        let nonce = "01234567-89ab-4def-8123-456789abcdef"
        func options(
            stageBNonce: String = nonce,
            t0: UInt64 = 100,
            requested: UInt64 = 200
        ) throws -> [(key: String, value: Any)] {
            var result: [(key: String, value: Any)] = [
                (
                    StartLatencyConstants.nonceOptionKey,
                    nonce
                ),
                (
                    StartLatencyConstants.requestedAtOptionKey,
                    CanonicalDecimal.encode(requested)
                ),
            ]
            result += try StageBStartOptions.encode(
                attemptNonce: stageBNonce,
                connectButtonT0MonotonicNanoseconds: t0
            ).map { (key: $0.key, value: $0.value as Any) }
            return result
        }

        XCTAssertThrowsError(
            try StageBProviderStartOptions.parse(
                entries: options(
                    stageBNonce:
                        "fedcba98-7654-4321-8765-0123456789ab"
                ),
                providerReceivedAtMonotonicNanoseconds: 300
            )
        )
        XCTAssertThrowsError(
            try StageBProviderStartOptions.parse(
                entries: options(t0: 201),
                providerReceivedAtMonotonicNanoseconds: 300
            )
        )
        XCTAssertThrowsError(
            try StageBProviderStartOptions.parse(
                entries: options(),
                providerReceivedAtMonotonicNanoseconds: 199
            )
        )

        var malformedOwned = try options()
        malformedOwned.append(
            (key: "WinnStageBForeignOwned", value: 7)
        )
        XCTAssertThrowsError(
            try StageBProviderStartOptions.parse(
                entries: malformedOwned,
                providerReceivedAtMonotonicNanoseconds: 300
            )
        )

        var duplicateOwned = try options()
        duplicateOwned.append(
            (key: StartLatencyConstants.nonceOptionKey, value: nonce)
        )
        XCTAssertThrowsError(
            try StageBProviderStartOptions.parse(
                entries: duplicateOwned,
                providerReceivedAtMonotonicNanoseconds: 300
            )
        )
    }

    // MARK: - Canonical decimal

    func testCanonicalDecimalRoundTripsEveryBoundaryValue() {
        for value: UInt64 in [
            0, 1, 9, 10, 99, 100, 1_000_000_000, 3_000_000_000,
            UInt64.max - 1, UInt64.max,
        ] {
            let text = CanonicalDecimal.encode(value)
            XCTAssertEqual(CanonicalDecimal.decode(text), value, text)
            XCTAssertTrue(
                text.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 },
                text
            )
            XCTAssertTrue(text.count == 1 || !text.hasPrefix("0"), text)
        }
    }

    func testCanonicalDecimalRejectsNoncanonicalText() {
        for text in [
            "", "00", "007", "0000000000", "+7", "-7", " 7", "7 ", "\t7",
            "7\n", "7.0", "1e3", "0x10", "1_000", "١٢٣", "１２３", "7a",
            "18446744073709551616", "99999999999999999999",
            "184467440737095516150",
        ] {
            XCTAssertNil(CanonicalDecimal.decode(text), text)
        }
    }

    // MARK: - Start options

    func testStartOptionsEncodeCanonically() throws {
        let options = try StartLatencyStartOptions.encode(
            attemptNonce: nonce,
            requestedAtMonotonicNanoseconds: 1_234_567_890
        )
        XCTAssertEqual(
            options[StartLatencyConstants.nonceOptionKey],
            nonce
        )
        XCTAssertEqual(
            options[StartLatencyConstants.requestedAtOptionKey],
            "1234567890"
        )
        let parsed = try StartLatencyStartOptions.parse(
            namespacedOptions: options
        )
        XCTAssertEqual(parsed.attemptNonce, nonce)
        XCTAssertEqual(parsed.requestedAtMonotonicNanoseconds, 1_234_567_890)
    }

    func testStartOptionParsingRefusesEveryMalformedShape() {
        let good = [
            StartLatencyConstants.nonceOptionKey: nonce,
            StartLatencyConstants.requestedAtOptionKey: "1000",
        ]
        var missingNonce = good
        missingNonce[StartLatencyConstants.nonceOptionKey] = nil
        var extraNamespaced = good
        extraNamespaced["WinnSpikeSomethingElse"] = "1"
        var uppercaseNonce = good
        uppercaseNonce[StartLatencyConstants.nonceOptionKey] =
            nonce.uppercased()
        var leadingZero = good
        leadingZero[StartLatencyConstants.requestedAtOptionKey] = "01000"
        var signed = good
        signed[StartLatencyConstants.requestedAtOptionKey] = "+1000"
        var spaced = good
        spaced[StartLatencyConstants.requestedAtOptionKey] = " 1000"
        for candidate in [
            [:], missingNonce, extraNamespaced, uppercaseNonce,
            leadingZero, signed, spaced,
        ] as [[String: String]] {
            XCTAssertThrowsError(
                try StartLatencyStartOptions.parse(
                    namespacedOptions: candidate
                ),
                "\(candidate)"
            )
        }
        XCTAssertNoThrow(
            try StartLatencyStartOptions.parse(namespacedOptions: good)
        )
    }

    func testConnectedTimestampRunsAfterIdentityAndStatusChecks() {
        var events: [String] = []
        let observed = StartLatencyConnectedObservation.capture(
            expectedSession: {
                events.append("identity")
                return true
            },
            connectedStatus: {
                events.append("status")
                return true
            },
            clock: {
                events.append("clock")
                return 42
            }
        )
        XCTAssertEqual(observed, 42)
        XCTAssertEqual(events, ["identity", "status", "clock"])

        events = []
        XCTAssertNil(
            StartLatencyConnectedObservation.capture(
                expectedSession: {
                    events.append("identity")
                    return true
                },
                connectedStatus: {
                    events.append("status")
                    return false
                },
                clock: {
                    events.append("clock")
                    return 99
                }
            )
        )
        XCTAssertEqual(events, ["identity", "status"])
    }

    func testBoundedProviderAdapterTimesOutAndIgnoresLateReply() async {
        var lateReply:
            (@Sendable (Result<Int, Error>) -> Void)?
        do {
            _ = try await StartLatencyBoundedOperation.run(
                timeoutNanoseconds: 1_000_000
            ) { finish in
                lateReply = finish
            } as Int
            XCTFail("an adapter that never replies must time out")
        } catch {
            XCTAssertEqual(
                error as? StartLatencyError,
                .boundedOperationTimedOut
            )
        }
        // Executable exactly-once check: a real provider callback can arrive
        // after timeout and must be consumed without a second continuation
        // resume or crash.
        lateReply?(.success(7))
    }

    func testBoundedProviderAdapterReturnsImmediateReply() async throws {
        let value: Int = try await StartLatencyBoundedOperation.run(
            timeoutNanoseconds: 1_000_000_000
        ) { finish in
            finish(.success(7))
        }
        XCTAssertEqual(value, 7)
    }

    func testDetachedExecutorBoundsCallerWithoutClaimingCancellation()
        async
    {
        let blocked = DispatchSemaphore(value: 0)
        do {
            let _: Int = try await StartLatencyDetachedExecutor.run(
                timeoutNanoseconds: 1_000_000
            ) {
                blocked.wait()
                return 7
            }
            XCTFail("the caller must not wait for blocked adapter work")
        } catch {
            XCTAssertEqual(
                error as? StartLatencyError,
                .boundedOperationTimedOut
            )
        }
        // Release the deliberately un-cancelled operation so this test leaves
        // no blocked executor work behind.
        blocked.signal()
    }

    // MARK: - Attempt ordering, latch, and single capture

    func testAttemptRefusesStartOptionsBeforeObserverRegistration() throws {
        let attempt = try StartLatencyAttempt(attemptNonce: nonce)
        XCTAssertThrowsError(
            try attempt.startOptions(
                requestedAtMonotonicNanoseconds: 1_000
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .observerNotRegistered
            )
        }
        try attempt.markObserverRegistered()
        XCTAssertNoThrow(
            try attempt.startOptions(
                requestedAtMonotonicNanoseconds: 1_000
            )
        )
    }

    func testAttemptRefusesASecondStart() throws {
        let attempt = try StartLatencyAttempt(attemptNonce: nonce)
        try attempt.markObserverRegistered()
        _ = try attempt.startOptions(
            requestedAtMonotonicNanoseconds: 1_000
        )
        XCTAssertThrowsError(
            try attempt.startOptions(
                requestedAtMonotonicNanoseconds: 2_000
            )
        ) { error in
            XCTAssertEqual(error as? StartLatencyError, .attemptNotActive)
        }
    }

    func testLatchAdmitsExactlyOneActiveAttempt() throws {
        let latch = StartLatencyAttemptLatch()
        XCTAssertFalse(latch.hasActiveAttempt)
        let first = try latch.begin(attemptNonce: nonce)
        XCTAssertTrue(latch.hasActiveAttempt)
        XCTAssertThrowsError(
            try latch.begin(attemptNonce: runID)
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .attemptAlreadyActive
            )
        }
        let teardown = latch.teardown(first, stopTunnel: false)
        XCTAssertTrue(teardown.releasedLatch)
        XCTAssertFalse(teardown.stopTunnel)
        XCTAssertNoThrow(try latch.begin(attemptNonce: runID))
    }

    func testStaleTeardownCannotReleaseOrStopANewerAttempt() throws {
        let latch = StartLatencyAttemptLatch()
        let first = try latch.begin(attemptNonce: nonce)
        let firstTeardown = latch.teardown(first, stopTunnel: true)
        XCTAssertTrue(firstTeardown.releasedLatch)
        XCTAssertTrue(firstTeardown.stopTunnel)
        let second = try latch.begin(attemptNonce: runID)

        XCTAssertEqual(
            latch.teardown(first, stopTunnel: true),
            .none
        )
        XCTAssertTrue(latch.hasActiveAttempt)
        XCTAssertTrue(latch.isCurrent(second))
        XCTAssertFalse(latch.isCurrent(first))
    }

    func testPostAwaitOwnerCheckIsolatesStaleSessionAndTask()
        async throws
    {
        let latch = StartLatencyAttemptLatch()
        let contextA = try StartLatencyAttemptContext(
            sessionLeaseID: nonce,
            completionTaskID: runID
        )
        let contextB = try StartLatencyAttemptContext(
            sessionLeaseID:
                "ffffffff-1111-2222-3333-444444444444",
            completionTaskID:
                "99999999-8888-7777-6666-555555555555"
        )
        let attemptA = try latch.begin(
            attemptNonce: nonce,
            context: contextA
        )
        await Task.yield()
        XCTAssertTrue(latch.isCurrent(attemptA, context: contextA))
        XCTAssertFalse(latch.isCurrent(attemptA, context: contextB))

        XCTAssertTrue(
            latch.teardown(
                attemptA,
                context: contextA,
                stopTunnel: true
            ).releasedLatch
        )
        let attemptB = try latch.begin(
            attemptNonce: runID,
            context: contextB
        )
        await Task.yield()

        XCTAssertFalse(latch.isCurrent(attemptA, context: contextA))
        XCTAssertTrue(latch.isCurrent(attemptB, context: contextB))
        XCTAssertEqual(
            latch.teardown(
                attemptA,
                context: contextA,
                stopTunnel: true
            ),
            .none
        )
        XCTAssertTrue(latch.isCurrent(attemptB, context: contextB))
    }

    func testLatchRefusesANonUUIDNonce() {
        let latch = StartLatencyAttemptLatch()
        XCTAssertThrowsError(try latch.begin(attemptNonce: "not-a-uuid"))
        XCTAssertThrowsError(
            try latch.begin(attemptNonce: nonce.uppercased())
        )
        XCTAssertFalse(latch.hasActiveAttempt)
    }

    func testAttemptCapturesTheFirstConnectedExactlyOnce() throws {
        let attempt = try StartLatencyAttempt(attemptNonce: nonce)
        try attempt.markObserverRegistered()
        _ = try attempt.startOptions(
            requestedAtMonotonicNanoseconds: 1_000
        )
        XCTAssertEqual(
            try attempt.observeConnected(atMonotonicNanoseconds: 1_500),
            500
        )
        XCTAssertEqual(attempt.phase, .captured)
        XCTAssertThrowsError(
            try attempt.observeConnected(atMonotonicNanoseconds: 1_900)
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .duplicateConnectedNotification
            )
        }
        XCTAssertEqual(attempt.phase, .failed)
        // The duplicate must not have replaced the first measurement.
        XCTAssertEqual(
            attempt.hostObservedConnectedAtMonotonicNanoseconds, 1_500
        )
    }

    func testAttemptRefusesConnectedBeforeTheStartCall() throws {
        let attempt = try StartLatencyAttempt(attemptNonce: nonce)
        try attempt.markObserverRegistered()
        XCTAssertThrowsError(
            try attempt.observeConnected(atMonotonicNanoseconds: 1_500)
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .notificationOutsideAttempt
            )
        }
        XCTAssertEqual(attempt.phase, .failed)
    }

    func testAttemptRefusesAReversedConnectedClock() throws {
        let attempt = try StartLatencyAttempt(attemptNonce: nonce)
        try attempt.markObserverRegistered()
        _ = try attempt.startOptions(
            requestedAtMonotonicNanoseconds: 5_000
        )
        XCTAssertThrowsError(
            try attempt.observeConnected(atMonotonicNanoseconds: 4_999)
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .reversedClock("hostObservedConnected")
            )
        }
        XCTAssertEqual(attempt.phase, .failed)
        XCTAssertNil(attempt.measuredHostLatencyNanoseconds)
    }

    func testTimeoutRequiresAStopOnlyWhileTheAttemptIsPending() throws {
        let pending = try StartLatencyAttempt(attemptNonce: nonce)
        try pending.markObserverRegistered()
        _ = try pending.startOptions(
            requestedAtMonotonicNanoseconds: 1_000
        )
        XCTAssertTrue(pending.timeOut())
        XCTAssertEqual(pending.phase, .failed)
        XCTAssertEqual(pending.failure, .timedOut)
        XCTAssertFalse(pending.timeOut())

        let captured = try StartLatencyAttempt(attemptNonce: nonce)
        try captured.markObserverRegistered()
        _ = try captured.startOptions(
            requestedAtMonotonicNanoseconds: 1_000
        )
        _ = try captured.observeConnected(atMonotonicNanoseconds: 1_100)
        XCTAssertFalse(captured.timeOut())
        XCTAssertEqual(captured.phase, .captured)
    }

    func testAttemptRefusesLateDataAfterATimeout() throws {
        let attempt = try StartLatencyAttempt(attemptNonce: nonce)
        try attempt.markObserverRegistered()
        _ = try attempt.startOptions(
            requestedAtMonotonicNanoseconds: 1_000
        )
        XCTAssertTrue(attempt.timeOut())
        XCTAssertThrowsError(
            try attempt.observeConnected(atMonotonicNanoseconds: 2_000)
        ) { error in
            XCTAssertEqual(error as? StartLatencyError, .timedOut)
        }
        XCTAssertThrowsError(
            try attempt.hostStartReceipt(
                attestation: try validAttestation(),
                expectedSourceDigest: sourceDigest
            )
        )
    }

    func testCompletionDeadlineCoversReceiptPublicationBoundary() throws {
        let attempt = try capturedAttempt(
            requested: 1_000,
            connected: 2_000
        )
        let deadline = try XCTUnwrap(
            attempt.completionDeadlineMonotonicNanoseconds
        )
        XCTAssertNoThrow(
            try attempt.requireWithinCompletionDeadline(
                atMonotonicNanoseconds: deadline
            )
        )
        XCTAssertNoThrow(try attempt.markPublished())
        XCTAssertEqual(attempt.phase, .published)
        XCTAssertFalse(attempt.expireCompletion())

        let late = try capturedAttempt(
            requested: 1_000,
            connected: 2_000
        )
        let lateDeadline = try XCTUnwrap(
            late.completionDeadlineMonotonicNanoseconds
        )
        XCTAssertThrowsError(
            try late.requireWithinCompletionDeadline(
                atMonotonicNanoseconds: lateDeadline + 1
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .completionDeadlineExceeded
            )
        }
        XCTAssertEqual(late.phase, .failed)
        XCTAssertThrowsError(try late.markPublished())
    }

    func testCompletionWatchdogExpiresOnlyCapturedAttempt() throws {
        let captured = try capturedAttempt(
            requested: 1_000,
            connected: 2_000
        )
        XCTAssertTrue(captured.expireCompletion())
        XCTAssertEqual(captured.phase, .failed)
        XCTAssertEqual(
            captured.failure,
            .completionDeadlineExceeded
        )
        XCTAssertFalse(captured.expireCompletion())
    }

    // MARK: - The 3.000-second acceptance boundary

    func testExactlyThreeSecondsPassesAndOneNanosecondMoreFails() throws {
        let exact = try boundaryReceipt(latency: 3_000_000_000)
        XCTAssertNoThrow(try exact.validate())
        let over = try boundaryReceipt(latency: 3_000_000_001)
        XCTAssertThrowsError(try over.validate()) { error in
            XCTAssertEqual(error as? StartLatencyError, .latencyExceedsGate)
        }
    }

    func testAttemptRefusesToIssueAnOverBudgetReceipt() throws {
        let requested: UInt64 = 1_000_000_000
        let attestation = try validAttestation(
            requested: requested,
            providerReceived: requested + 1_000,
            providerReady: requested + 2_000
        )
        let good = try capturedAttempt(
            requested: requested,
            connected: requested + 3_000_000_000
        )
        XCTAssertNoThrow(
            try good.hostStartReceipt(
                attestation: attestation,
                expectedSourceDigest: sourceDigest
            )
        )
        XCTAssertThrowsError(
            try capturedAttempt(
                requested: requested,
                connected: requested + 3_000_000_001
            )
        ) { error in
            XCTAssertEqual(error as? StartLatencyError, .latencyExceedsGate)
        }
    }

    // MARK: - Receipt field validation

    func testReceiptRefusesEveryMalformedField() throws {
        let cases: [(String, HostStartReceipt)] = [
            ("schema", try mutatedReceipt { $0.schema = "winn/other" }),
            (
                "protocolVersion",
                try mutatedReceipt { $0.protocolVersion = "winn/2" }
            ),
            ("runID", try mutatedReceipt {
                $0.runID = runID.uppercased()
                $0.evidenceFileName = "\(runID.uppercased()).jsonl"
            }),
            (
                "attemptNonce",
                try mutatedReceipt { $0.attemptNonce = "not-a-uuid" }
            ),
            (
                "sourceDigest",
                try mutatedReceipt { $0.sourceDigest = sourceDigest + "a" }
            ),
            (
                "sourceDigest",
                try mutatedReceipt {
                    $0.sourceDigest = String(repeating: "0", count: 64)
                }
            ),
            (
                "evidenceFileName",
                try mutatedReceipt { $0.evidenceFileName = "run.jsonl" }
            ),
            (
                "firstRecordSHA256",
                try mutatedReceipt { $0.firstRecordSHA256 = "AB" }
            ),
            (
                "firstRecordSHA256",
                try mutatedReceipt {
                    $0.firstRecordSHA256 = firstDigest.uppercased()
                }
            ),
            (
                "firstRecordBytes",
                try mutatedReceipt { $0.firstRecordBytes = 0 }
            ),
            (
                "firstRecordBytes",
                try mutatedReceipt { $0.firstRecordBytes = 1 << 21 }
            ),
            (
                "evidenceDurabilityBarrier",
                try mutatedReceipt {
                    $0.evidenceDurabilityBarrier = "unknown"
                }
            ),
            (
                "measurementScope",
                try mutatedReceipt { $0.measurementScope = "vpn-connected" }
            ),
            (
                "artifactScope",
                try mutatedReceipt {
                    $0.artifactScope = "attempt-accepted"
                }
            ),
            (
                "hostReceiptDurabilityScope",
                try mutatedReceipt {
                    $0.hostReceiptDurabilityScope =
                        "power-loss-durable"
                }
            ),
        ]
        for (field, receipt) in cases {
            XCTAssertThrowsError(try receipt.validate(), field)
        }
        XCTAssertNoThrow(try mutatedReceipt { _ in }.validate())
    }

    func testActualStartAndStopReceiptCanonicalBytesIncludeOneLF()
        throws
    {
        let start = try mutatedReceipt { _ in }
        let startBytes = try CanonicalEvidenceJSONLine.encode(start)
        XCTAssertEqual(startBytes.last, 0x0a)
        XCTAssertNotEqual(startBytes.dropLast().last, 0x0a)
        XCTAssertEqual(
            startBytes,
            try CanonicalEvidenceJSONLine.encode(start)
        )
        XCTAssertEqual(
            try JSONDecoder().decode(
                HostStartReceipt.self,
                from: Data(startBytes.dropLast())
            ),
            start
        )
        XCTAssertEqual(
            start.artifactScope,
            StartLatencyScope.artifactScope
        )
        XCTAssertEqual(
            start.hostReceiptDurabilityScope,
            StartLatencyScope.hostReceiptDurabilityScope
        )

        let stop = HostStopReceipt(
            schema: "winn-ios-privacy-spike-stop-receipt/1",
            protocolVersion: WCF3Constants.protocolVersion,
            runID: runID,
            evidenceFileName: "\(runID).jsonl",
            evidenceSHA256: sourceDigest,
            requestedAtMonotonicNanoseconds: 1_000,
            providerReceivedAtMonotonicNanoseconds: 1_100,
            providerAcknowledgedAtMonotonicNanoseconds: 1_200,
            hostReceivedAtMonotonicNanoseconds: 1_300,
            roundTripNanoseconds: 300
        )
        let stopBytes = try CanonicalEvidenceJSONLine.encode(stop)
        XCTAssertEqual(stopBytes.last, 0x0a)
        XCTAssertNotEqual(stopBytes.dropLast().last, 0x0a)
        XCTAssertEqual(
            stopBytes,
            try CanonicalEvidenceJSONLine.encode(stop)
        )
        XCTAssertEqual(
            try JSONDecoder().decode(
                HostStopReceipt.self,
                from: Data(stopBytes.dropLast())
            ),
            stop
        )
    }

    func testReceiptRefusesReversedAndInconsistentClocks() throws {
        let reversedProviderReceived = try mutatedReceipt {
            $0.providerReceivedAtMonotonicNanoseconds =
                $0.requestedAtMonotonicNanoseconds - 1
        }
        XCTAssertThrowsError(
            try reversedProviderReceived.validate()
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .reversedClock("providerReceived")
            )
        }

        let reversedProviderReady = try mutatedReceipt {
            $0.providerReadyAtMonotonicNanoseconds =
                $0.providerReceivedAtMonotonicNanoseconds - 1
        }
        XCTAssertThrowsError(
            try reversedProviderReady.validate()
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .reversedClock("providerReady")
            )
        }

        // The host cannot see `.connected` before the provider finished.
        let connectedBeforeReady = try mutatedReceipt {
            $0.hostObservedConnectedAtMonotonicNanoseconds =
                $0.providerReadyAtMonotonicNanoseconds - 1
            $0.hostStartLatencyNanoseconds =
                $0.hostObservedConnectedAtMonotonicNanoseconds -
                $0.requestedAtMonotonicNanoseconds
        }
        XCTAssertThrowsError(
            try connectedBeforeReady.validate()
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .reversedClock("hostObservedConnected")
            )
        }

        let wrongProviderLatency = try mutatedReceipt {
            $0.providerStartLatencyNanoseconds += 1
        }
        XCTAssertThrowsError(try wrongProviderLatency.validate())

        let wrongHostLatency = try mutatedReceipt {
            $0.hostStartLatencyNanoseconds += 1
        }
        XCTAssertThrowsError(try wrongHostLatency.validate()) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .invalidField("hostStartLatencyNanoseconds")
            )
        }
    }

    func testReceiptRefusesOverflowingHostArithmetic() throws {
        let receipt = try mutatedReceipt {
            $0.requestedAtMonotonicNanoseconds = UInt64.max - 10
            $0.providerReceivedAtMonotonicNanoseconds = UInt64.max - 9
            $0.providerReadyAtMonotonicNanoseconds = UInt64.max - 8
            $0.providerStartLatencyNanoseconds = 1
            $0.hostObservedConnectedAtMonotonicNanoseconds = UInt64.max - 5
            $0.hostStartLatencyNanoseconds = UInt64.max
        }
        XCTAssertThrowsError(try receipt.validate()) { error in
            // The declared latency is large enough that recomputing
            // `requested + latency` wraps. Only the overflow-reported
            // addition refuses this; a plain subtraction would not.
            XCTAssertEqual(
                error as? StartLatencyError,
                .arithmeticOverflow("hostStartLatencyNanoseconds")
            )
        }
    }

    func testReceiptDecodingRevalidates() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let decoder = JSONDecoder()
        let good = try mutatedReceipt { _ in }
        let encoded = try encoder.encode(good)
        XCTAssertEqual(
            try decoder.decode(HostStartReceipt.self, from: encoded),
            good
        )
        let tampered = try encoder.encode(
            try mutatedReceipt { $0.hostStartLatencyNanoseconds += 1 }
        )
        XCTAssertThrowsError(
            try decoder.decode(HostStartReceipt.self, from: tampered)
        )
        // A receipt missing a required key must not decode either.
        var object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: encoded)
                as? [String: Any]
        )
        object.removeValue(forKey: "measurementScope")
        let incomplete = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(
            try decoder.decode(HostStartReceipt.self, from: incomplete)
        )
    }

    // MARK: - Attestation validation

    func testAttestationBindsItsRunIDToTheEvidencePath() throws {
        let mismatched = ProviderStartAttestation(
            schema: StartLatencyConstants.attestationSchema,
            protocolVersion: WCF3Constants.protocolVersion,
            runID: runID,
            attemptNonce: nonce,
            sourceDigest: sourceDigest,
            evidenceRelativePath:
            "Evidence/runtime/\(nonce)/stage-a.jsonl",
            firstRecordSHA256: firstDigest,
            firstRecordBytes: 512,
            evidenceDurabilityBarrier: durabilityBarrier,
            requestedAtMonotonicNanoseconds: 1_000,
            providerReceivedAtMonotonicNanoseconds: 2_000,
            providerReadyAtMonotonicNanoseconds: 3_000,
            providerStartLatencyNanoseconds: 1_000,
            measurementScope: StartLatencyScope.measurementScope
        )
        XCTAssertThrowsError(try mismatched.validate()) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .invalidField("evidenceRelativePath")
            )
        }
        let invalidBarrier = ProviderStartAttestation(
            schema: StartLatencyConstants.attestationSchema,
            protocolVersion: WCF3Constants.protocolVersion,
            runID: runID,
            attemptNonce: nonce,
            sourceDigest: sourceDigest,
            evidenceRelativePath:
                "Evidence/runtime/\(runID)/stage-a.jsonl",
            firstRecordSHA256: firstDigest,
            firstRecordBytes: 512,
            evidenceDurabilityBarrier: "unknown",
            requestedAtMonotonicNanoseconds: 1_000,
            providerReceivedAtMonotonicNanoseconds: 2_000,
            providerReadyAtMonotonicNanoseconds: 3_000,
            providerStartLatencyNanoseconds: 1_000,
            measurementScope: StartLatencyScope.measurementScope
        )
        XCTAssertThrowsError(try invalidBarrier.validate()) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .invalidField("evidenceDurabilityBarrier")
            )
        }
        XCTAssertNoThrow(try validAttestation().validate())
    }

    func testAttestationDecodingRevalidates() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(try validAttestation())
        XCTAssertNoThrow(
            try JSONDecoder().decode(
                ProviderStartAttestation.self, from: encoded
            )
        )
        var object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: encoded)
                as? [String: Any]
        )
        object["providerStartLatencyNanoseconds"] = 999_999
        let tampered = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ProviderStartAttestation.self, from: tampered
            )
        )
    }

    // MARK: - Cross-binding

    func testBindingRefusesEveryCrossFieldMismatch() throws {
        let requested: UInt64 = 1_000_000
        let attestation = try validAttestation(
            requested: requested,
            providerReceived: requested + 100,
            providerReady: requested + 200
        )
        let attempt = try capturedAttempt(
            requested: requested,
            connected: requested + 300
        )
        let receipt = try attempt.hostStartReceipt(
            attestation: attestation,
            expectedSourceDigest: sourceDigest
        )
        XCTAssertNoThrow(
            try receipt.validateBinding(
                attestation: attestation,
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        )

        let otherNonce = "ffffffff-1111-2222-3333-444444444444"
        let otherRun = "fedcba98-7654-3210-fedc-ba9876543210"

        // Nonce.
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: try validAttestation(
                    attemptNonce: otherNonce,
                    requested: requested,
                    providerReceived: requested + 100,
                    providerReady: requested + 200
                ),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .bindingMismatch("attemptNonce")
            )
        }

        // Run ID.
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: try validAttestation(
                    runID: otherRun,
                    requested: requested,
                    providerReceived: requested + 100,
                    providerReady: requested + 200
                ),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .bindingMismatch("runID")
            )
        }

        // Source digest.
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: attestation,
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: String(repeating: "c", count: 64)
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError, .bindingMismatch("sourceDigest")
            )
        }

        // Requested time.
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: attestation,
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested + 1,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .bindingMismatch("requestedAtMonotonicNanoseconds")
            )
        }

        // First-record digest and byte count.
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: try validAttestation(
                    firstRecordSHA256: String(repeating: "d", count: 64),
                    requested: requested,
                    providerReceived: requested + 100,
                    providerReady: requested + 200
                ),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .bindingMismatch("firstRecordSHA256")
            )
        }
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: try validAttestation(
                    firstRecordBytes: 511,
                    requested: requested,
                    providerReceived: requested + 100,
                    providerReady: requested + 200
                ),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .bindingMismatch("firstRecordBytes")
            )
        }

        // Provider timestamps.
        XCTAssertThrowsError(
            try receipt.validateBinding(
                attestation: try validAttestation(
                    requested: requested,
                    providerReceived: requested + 101,
                    providerReady: requested + 201
                ),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .bindingMismatch("providerTimestamps")
            )
        }

        let mismatchedBarrier = try mutatedReceipt {
            $0.evidenceDurabilityBarrier =
                SpikeDurabilityBarrier.fsyncOnly.rawValue
        }
        XCTAssertThrowsError(
            try mismatchedBarrier.validateBinding(
                attestation: attestation,
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: requested,
                sourceDigest: sourceDigest
            )
        ) { error in
            XCTAssertEqual(
                error as? StartLatencyError,
                .bindingMismatch("evidenceDurabilityBarrier")
            )
        }
    }

    // MARK: - First-record digest over the exact bytes

    func testFirstRecordDigestCoversTheTrailingLineFeed() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("stage-a.jsonl")
        let writer = try JSONLEvidenceWriter(fileURL: file)
        let recorded = try writer.appendFirstRecordDurably(
            try startedRecord()
        )

        let content = try Data(contentsOf: file)
        let feed = try XCTUnwrap(content.firstIndex(of: 0x0a))
        let withFeed = content[content.startIndex ... feed]
        let withoutFeed = content[content.startIndex ..< feed]
        XCTAssertEqual(recorded.digest, hexSHA256(Data(withFeed)))
        XCTAssertEqual(recorded.byteCount, UInt64(withFeed.count))
        // The line feed is inside the hashed range: dropping it changes the
        // digest, so a verifier that hashes the stripped line cannot agree.
        XCTAssertNotEqual(recorded.digest, hexSHA256(Data(withoutFeed)))
        XCTAssertEqual(writer.firstRecordDigest?.digest, recorded.digest)
    }

    func testFirstRecordDigestIsRefusedAfterAnyEarlierWrite() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let writer = try JSONLEvidenceWriter(
            fileURL: directory.appendingPathComponent("stage-a.jsonl")
        )
        try writer.append(try startedRecord())
        XCTAssertThrowsError(
            try writer.appendFirstRecordDurably(try startedRecord())
        ) { error in
            XCTAssertEqual(
                error as? SpikeMetricError, .notTheFirstRecord
            )
        }
        XCTAssertNil(writer.firstRecordDigest)
    }

    func testFirstRecordDigestIsRefusedTwice() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let writer = try JSONLEvidenceWriter(
            fileURL: directory.appendingPathComponent("stage-a.jsonl")
        )
        _ = try writer.appendFirstRecordDurably(try startedRecord())
        XCTAssertThrowsError(
            try writer.appendFirstRecordDurably(try startedRecord())
        ) { error in
            XCTAssertEqual(
                error as? SpikeMetricError, .firstRecordAlreadyRecorded
            )
        }
    }

    // MARK: - A provider synchronize failure fails startup

    func testSynchronizeFailureFailsStartupAndProducesNoAttestation() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("stage-a.jsonl")
        let writer = try JSONLEvidenceWriter(fileURL: file)
        writer.synchronizeHook = { throw InjectedFailure.synchronize }
        var readyClockCalls = 0
        XCTAssertThrowsError(
            try ProviderStartAttestationRecorder.recordFirstStartedRecord(
                writer: writer,
                record: try startedRecord(),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: 1_000,
                providerReceivedAtMonotonicNanoseconds: 2_000,
                providerReadyClock: {
                    readyClockCalls += 1
                    return 3_000
                }
            )
        ) { error in
            XCTAssertEqual(error as? InjectedFailure, .synchronize)
        }
        // Startup fails, nothing is attested, the ready clock is never
        // reached, and no half-record survives.
        XCTAssertNil(writer.firstRecordDigest)
        XCTAssertEqual(readyClockCalls, 0)
        XCTAssertEqual(try Data(contentsOf: file).count, 0)
    }

    func testSynchronizeHookIsInertInProduction() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let writer = try JSONLEvidenceWriter(
            fileURL: directory.appendingPathComponent("stage-a.jsonl")
        )
        XCTAssertNil(writer.synchronizeHook)
        XCTAssertNoThrow(
            try writer.appendFirstRecordDurably(try startedRecord())
        )
    }

    func testDirectorySynchronizeFailureProducesNoAttestation() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        let file = root
            .appendingPathComponent("new-run", isDirectory: true)
            .appendingPathComponent("nested", isDirectory: true)
            .appendingPathComponent("stage-a.jsonl")
        let writer = try JSONLEvidenceWriter(fileURL: file)
        var synchronized: [URL] = []
        writer.directorySynchronizeHook = { directory in
            synchronized.append(directory.standardizedFileURL)
            throw InjectedFailure.synchronize
        }
        var readyClockCalls = 0

        XCTAssertThrowsError(
            try ProviderStartAttestationRecorder.recordFirstStartedRecord(
                writer: writer,
                record: try startedRecord(),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: 1_000,
                providerReceivedAtMonotonicNanoseconds: 2_000,
                providerReadyClock: {
                    readyClockCalls += 1
                    return 3_000
                }
            )
        ) { error in
            XCTAssertEqual(error as? InjectedFailure, .synchronize)
        }
        XCTAssertEqual(
            synchronized,
            [root.standardizedFileURL]
        )
        XCTAssertEqual(
            writer.synchronizedDirectories,
            [
                root.standardizedFileURL,
                root.appendingPathComponent(
                    "new-run",
                    isDirectory: true
                ).standardizedFileURL,
                file.deletingLastPathComponent().standardizedFileURL,
            ]
        )
        XCTAssertNil(writer.firstRecordDigest)
        XCTAssertEqual(readyClockCalls, 0)
        XCTAssertEqual(try Data(contentsOf: file).count, 0)

        // The failed append was rolled back, so a later attempt can obtain
        // every real directory barrier and only then produce an attestation.
        writer.directorySynchronizeHook = nil
        XCTAssertNoThrow(
            try ProviderStartAttestationRecorder.recordFirstStartedRecord(
                writer: writer,
                record: try startedRecord(),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: 1_000,
                providerReceivedAtMonotonicNanoseconds: 2_000,
                providerReadyClock: {
                    readyClockCalls += 1
                    return 3_000
                }
            )
        )
        XCTAssertNotNil(writer.firstRecordDigest)
        XCTAssertEqual(readyClockCalls, 1)
    }

    func testRecorderProducesAnAttestationBoundToTheWrittenBytes() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("stage-a.jsonl")
        let writer = try JSONLEvidenceWriter(fileURL: file)
        let attestation = try ProviderStartAttestationRecorder
            .recordFirstStartedRecord(
                writer: writer,
                record: try startedRecord(),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: 1_000,
                providerReceivedAtMonotonicNanoseconds: 2_000,
                providerReadyClock: { 3_000 }
            )
        let content = try Data(contentsOf: file)
        let feed = try XCTUnwrap(content.firstIndex(of: 0x0a))
        XCTAssertEqual(
            attestation.firstRecordSHA256,
            hexSHA256(Data(content[content.startIndex ... feed]))
        )
        XCTAssertEqual(attestation.providerStartLatencyNanoseconds, 1_000)
        XCTAssertEqual(
            attestation.evidenceDurabilityBarrier,
            writer.durabilityBarrier?.rawValue
        )
        XCTAssertEqual(
            attestation.evidenceRelativePath,
            "Evidence/runtime/\(runID)/stage-a.jsonl"
        )
    }

    func testRecorderRefusesARecordThatDoesNotCarryTheBinding() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let writer = try JSONLEvidenceWriter(
            fileURL: directory.appendingPathComponent("stage-a.jsonl")
        )
        XCTAssertThrowsError(
            try ProviderStartAttestationRecorder.recordFirstStartedRecord(
                writer: writer,
                record: try startedRecord(event: "sample-window"),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: 1_000,
                providerReceivedAtMonotonicNanoseconds: 2_000,
                providerReadyClock: { 3_000 }
            )
        )
        XCTAssertThrowsError(
            try ProviderStartAttestationRecorder.recordFirstStartedRecord(
                writer: writer,
                record: try startedRecord(),
                attemptNonce: nonce,
                requestedAtMonotonicNanoseconds: 1_001,
                providerReceivedAtMonotonicNanoseconds: 2_000,
                providerReadyClock: { 3_000 }
            )
        )
        XCTAssertNil(writer.firstRecordDigest)
    }

    // MARK: - Record-level binding

    func testMetricRecordRefusesAPartialStartAttemptBinding() {
        XCTAssertThrowsError(
            try startedRecord(
                startRequested: nil
            )
        ) { error in
            XCTAssertEqual(
                error as? SpikeMetricError, .invalidStartAttemptBinding
            )
        }
        XCTAssertThrowsError(
            try startedRecord(startNonce: nonce.uppercased())
        )
        XCTAssertThrowsError(
            try startedRecord(startRequested: 2_001, providerReceived: 2_000)
        )
        XCTAssertNoThrow(
            try startedRecord(
                startNonce: nil,
                startRequested: nil,
                providerReceived: nil
            )
        )
    }
}

// MARK: - Fixtures

private func hexSHA256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func startedRecord(
    event: String = "started",
    startNonce: String? = nonce,
    startRequested: UInt64? = 1_000,
    providerReceived: UInt64? = 2_000
) throws -> SpikeMetricRecord {
    try SpikeMetricRecord(
        runID: runID,
        event: event,
        monotonicNanoseconds: 2_500,
        wallTimeUTC: "2026-07-27T00:00:00.000Z",
        mode: .maximumPrivacy,
        trafficProfile: .low,
        coverSemantics: .continuousWhileConnected,
        rotationCadence: .protocolFifteenMinutes,
        durationNanoseconds: 60_000_000_000,
        trafficActiveNanoseconds: 60_000_000_000,
        sourceDigest: sourceDigest,
        artifactDigest: String(repeating: "b", count: 64),
        startAttemptNonce: startNonce,
        startRequestedAtMonotonicNanoseconds: startRequested,
        providerReceivedAtMonotonicNanoseconds: providerReceived
    )
}

private func validAttestation(
    runID attestedRunID: String = runID,
    attemptNonce attestedNonce: String = nonce,
    firstRecordSHA256: String = firstDigest,
    firstRecordBytes: UInt64 = 512,
    requested: UInt64 = 1_000,
    providerReceived: UInt64 = 2_000,
    providerReady: UInt64 = 3_000
) throws -> ProviderStartAttestation {
    try ProviderStartAttestation(
        runID: attestedRunID,
        attemptNonce: attestedNonce,
        sourceDigest: sourceDigest,
        firstRecordSHA256: firstRecordSHA256,
        firstRecordBytes: firstRecordBytes,
        evidenceDurabilityBarrier: durabilityBarrier,
        requestedAtMonotonicNanoseconds: requested,
        providerReceivedAtMonotonicNanoseconds: providerReceived,
        providerReadyAtMonotonicNanoseconds: providerReady
    )
}

private func capturedAttempt(
    requested: UInt64,
    connected: UInt64
) throws -> StartLatencyAttempt {
    let attempt = try StartLatencyAttempt(attemptNonce: nonce)
    try attempt.markObserverRegistered()
    _ = try attempt.startOptions(
        requestedAtMonotonicNanoseconds: requested
    )
    _ = try attempt.observeConnected(atMonotonicNanoseconds: connected)
    return attempt
}

/// A mutable mirror of `HostStartReceipt` so each field can be corrupted on
/// its own without the builder silently repairing the others.
private struct MutableReceipt {
    var schema = StartLatencyConstants.receiptSchema
    var protocolVersion = WCF3Constants.protocolVersion
    var runID = "01234567-89ab-cdef-0123-456789abcdef"
    var attemptNonce = nonce
    var sourceDigest = String(repeating: "a", count: 64)
    var evidenceFileName = "01234567-89ab-cdef-0123-456789abcdef.jsonl"
    var firstRecordSHA256 = String(repeating: "b", count: 64)
    var firstRecordBytes: UInt64 = 512
    var evidenceDurabilityBarrier = durabilityBarrier
    var requestedAtMonotonicNanoseconds: UInt64 = 1_000_000
    var providerReceivedAtMonotonicNanoseconds: UInt64 = 1_000_100
    var providerReadyAtMonotonicNanoseconds: UInt64 = 1_000_200
    var providerStartLatencyNanoseconds: UInt64 = 100
    var hostObservedConnectedAtMonotonicNanoseconds: UInt64 = 1_000_300
    var hostStartLatencyNanoseconds: UInt64 = 300
    var measurementScope = StartLatencyScope.measurementScope
    var artifactScope = StartLatencyScope.artifactScope
    var hostReceiptDurabilityScope =
        StartLatencyScope.hostReceiptDurabilityScope
}

private func mutatedReceipt(
    _ mutate: (inout MutableReceipt) -> Void
) throws -> HostStartReceipt {
    var draft = MutableReceipt()
    mutate(&draft)
    return HostStartReceipt(
        schema: draft.schema,
        protocolVersion: draft.protocolVersion,
        runID: draft.runID,
        attemptNonce: draft.attemptNonce,
        sourceDigest: draft.sourceDigest,
        evidenceFileName: draft.evidenceFileName,
        firstRecordSHA256: draft.firstRecordSHA256,
        firstRecordBytes: draft.firstRecordBytes,
        evidenceDurabilityBarrier: draft.evidenceDurabilityBarrier,
        requestedAtMonotonicNanoseconds:
            draft.requestedAtMonotonicNanoseconds,
        providerReceivedAtMonotonicNanoseconds:
            draft.providerReceivedAtMonotonicNanoseconds,
        providerReadyAtMonotonicNanoseconds:
            draft.providerReadyAtMonotonicNanoseconds,
        providerStartLatencyNanoseconds:
            draft.providerStartLatencyNanoseconds,
        hostObservedConnectedAtMonotonicNanoseconds:
            draft.hostObservedConnectedAtMonotonicNanoseconds,
        hostStartLatencyNanoseconds: draft.hostStartLatencyNanoseconds,
        measurementScope: draft.measurementScope,
        artifactScope: draft.artifactScope,
        hostReceiptDurabilityScope:
            draft.hostReceiptDurabilityScope
    )
}

private func boundaryReceipt(latency: UInt64) throws -> HostStartReceipt {
    try mutatedReceipt {
        $0.requestedAtMonotonicNanoseconds = 1_000_000
        $0.providerReceivedAtMonotonicNanoseconds = 1_000_100
        $0.providerReadyAtMonotonicNanoseconds = 1_000_200
        $0.providerStartLatencyNanoseconds = 100
        $0.hostObservedConnectedAtMonotonicNanoseconds =
            1_000_000 + latency
        $0.hostStartLatencyNanoseconds = latency
    }
}
