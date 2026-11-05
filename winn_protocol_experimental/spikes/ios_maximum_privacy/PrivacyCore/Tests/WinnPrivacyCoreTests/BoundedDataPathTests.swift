import XCTest
@testable import WinnPrivacyCore

final class BoundedDataPathTests: XCTestCase {
    func testRingRejectsCapacityPlusOneWithoutGrowing() throws {
        let ring = try FixedCellRing(capacity: 2)
        for sequence in 1 ... 2 {
            XCTAssertTrue(
                try ring.enqueue(
                    enqueuedAtNanoseconds: 0,
                    releaseDeadlineNanoseconds: 0,
                    sequence: UInt64(sequence),
                    isCover: false
                ) { destination in
                    destination.initializeMemory(
                        as: UInt8.self,
                        repeating: UInt8(sequence)
                    )
                    return destination.count
                }
            )
        }
        XCTAssertFalse(
            try ring.enqueue(
                enqueuedAtNanoseconds: 0,
                releaseDeadlineNanoseconds: 0,
                sequence: 3,
                isCover: false
            ) { destination in
                XCTFail("encoder must not run for a full ring")
                return destination.count
            }
        )
        let snapshot = ring.snapshot()
        XCTAssertEqual(snapshot.capacity, 2)
        XCTAssertEqual(snapshot.occupied, 2)
        XCTAssertEqual(snapshot.highWatermark, 2)
        XCTAssertEqual(snapshot.rejectedFull, 1)
        XCTAssertEqual(ring.allocatedCellBytes, 2_048)
    }

    func testRingTracksPendingAndRetiredCoverWithoutScanning() throws {
        let ring = try FixedCellRing(capacity: 2)
        for (sequence, isCover) in [(UInt64(1), true), (2, false)] {
            XCTAssertTrue(
                try ring.enqueue(
                    enqueuedAtNanoseconds: 0,
                    releaseDeadlineNanoseconds: 10,
                    sequence: sequence,
                    isCover: isCover
                ) { destination in
                    destination.initializeMemory(
                        as: UInt8.self,
                        repeating: UInt8(sequence)
                    )
                    return destination.count
                }
            )
        }
        XCTAssertEqual(ring.snapshot().occupiedCover, 1)
        ring.reset()
        let snapshot = ring.snapshot()
        XCTAssertEqual(snapshot.occupied, 0)
        XCTAssertEqual(snapshot.occupiedCover, 0)
        XCTAssertEqual(snapshot.retiredCover, 1)
        XCTAssertEqual(snapshot.retiredData, 1)
    }

    func testShaperDeadlineNeverExceedsTwentyMilliseconds() throws {
        let context = try testContext()
        let shaper = try PrivacyShaper(capacity: 4)
        let payload = [UInt8](repeating: 0x42, count: 32)
        let now: UInt64 = 100_000_000
        try payload.withUnsafeBytes { bytes in
            XCTAssertTrue(
                try shaper.enqueue(
                    header: WCF3FrameHeader(
                        kind: .data,
                        context: context,
                        sequence: 1
                    ),
                    payload: bytes,
                    nowNanoseconds: now,
                    scheduleWord: UInt64.max,
                    paddingFiller: deterministicPadding
                )
            )
        }
        var output = [UInt8](repeating: 0, count: 1_024)
        let early = try output.withUnsafeMutableBytes {
            try shaper.dequeueEligible(
                nowNanoseconds:
                    now + WCF3Constants.maximumShuffleNanoseconds - 1,
                selectionWord: 0,
                into: $0
            )
        }
        if early == nil {
            let due = try output.withUnsafeMutableBytes {
                try shaper.dequeueEligible(
                    nowNanoseconds:
                        now + WCF3Constants.maximumShuffleNanoseconds,
                    selectionWord: 0,
                    into: $0
                )
            }
            XCTAssertNotNil(due)
        }
        XCTAssertLessThanOrEqual(
            shaper.maximumShuffleNanoseconds,
            20_000_000
        )
    }

    func testRotationPreallocatesExactlyTwoBidirectionalPools() throws {
        let pool = try RotationBufferPool(capacityPerDirection: 4)
        XCTAssertEqual(pool.maximumConcurrentCircuits, 2)
        XCTAssertEqual(
            pool.allocatedCellBytes,
            2 * 2 * 4 * WCF3Constants.privacyCellSize
        )
        XCTAssertEqual(
            pool.beginRotation(nowNanoseconds: 10),
            .started(
                standbyIndex: 1,
                deadlineNanoseconds:
                    10 +
                    WCF3Constants.spikeRotationOverlapNanoseconds
            )
        )
        XCTAssertEqual(
            pool.beginRotation(nowNanoseconds: 11),
            .alreadyOverlapping
        )
        XCTAssertTrue(pool.cancelRotation())
        XCTAssertNil(pool.state().standbyIndex)
        XCTAssertEqual(
            pool.beginRotation(nowNanoseconds: 12),
            .started(
                standbyIndex: 1,
                deadlineNanoseconds:
                    12 +
                    WCF3Constants.spikeRotationOverlapNanoseconds
            )
        )
        XCTAssertTrue(pool.completeRotation())
        XCTAssertNil(pool.state().standbyIndex)
    }

    func testStageAContinuousCoverShapesDrainsAndStops() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .idle,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = try harness.step(nowNanoseconds: 1_000_000_000)
        XCTAssertEqual(snapshot.dataPath.coverPairsAccepted, 1)
        XCTAssertEqual(snapshot.dataPath.coverPairsEmitted, 0)
        XCTAssertEqual(snapshot.dataPath.acceptedCells, 2)
        snapshot = try harness.step(nowNanoseconds: 1_100_000_000)
        XCTAssertEqual(snapshot.dataPath.emittedCells, 2)
        XCTAssertEqual(snapshot.dataPath.coverPairsEmitted, 1)
        let stopped = harness.stop(nowNanoseconds: 1_100_000_000)
        XCTAssertTrue(stopped.completed)
        snapshot = try harness.step(nowNanoseconds: 10_000_000_000)
        XCTAssertEqual(snapshot.dataPath.coverPairsEmitted, 1)
        XCTAssertEqual(snapshot.dataPath.acceptedCells, 2)
    }

    func testStageAStopCompletesWithin250msUnderLoad() throws {
        // PRIVACY_SPIKE_SPEC.md: "Explicit Stop completes within 250 ms with
        // no later cover." Saturated load with the 15-minute cadence fills and
        // keeps every fixed-cell ring full, so Stop performs its heaviest
        // in-place snapshot work; the 250 ms bound must still hold.
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .saturated,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 400 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertGreaterThan(snapshot.dataPath.outboundQueueDepth, 0)
        let coverPairsBeforeStop = snapshot.dataPath.coverPairsEmitted
        let acceptedBeforeStop = snapshot.dataPath.acceptedCells

        let clock = ContinuousClock()
        var stopped: StageAHarnessSnapshot?
        let elapsed = clock.measure {
            stopped = harness.stop(nowNanoseconds: 4_000_000_000)
        }
        XCTAssertLessThan(elapsed, .milliseconds(250))
        XCTAssertEqual(stopped?.completed, true)

        // Stop is idempotent and never emits a later cover or synthetic cell.
        let again = harness.stop(nowNanoseconds: 4_000_000_000)
        XCTAssertEqual(again.completed, true)
        let afterStop = try harness.step(
            nowNanoseconds: 120_000_000_000
        )
        XCTAssertEqual(
            afterStop.dataPath.coverPairsEmitted,
            coverPairsBeforeStop
        )
        XCTAssertEqual(
            afterStop.dataPath.acceptedCells,
            acceptedBeforeStop
        )
    }

    func testLowProfileDrainIncludesAdditiveCoverCapacity() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .low,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 300_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 12_000 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertEqual(snapshot.dataPath.droppedCells, 0)
        XCTAssertLessThan(snapshot.dataPath.inboundQueueDepth, 10)
        XCTAssertLessThan(snapshot.dataPath.outboundQueueDepth, 10)
        XCTAssertEqual(
            snapshot.dataPath.coverInboundCellsEmitted,
            snapshot.dataPath.coverOutboundCellsEmitted
        )
        XCTAssertGreaterThan(
            snapshot.dataPath.coverPairsEmitted,
            100
        )
        XCTAssertGreaterThan(snapshot.dataPath.queueDelaySamples, 0)
        XCTAssertLessThanOrEqual(
            snapshot.dataPath.queueDelayP99UpperBoundNanoseconds,
            25_000_000
        )
        XCTAssertEqual(
            snapshot.dataPath.queueDelayOver25Milliseconds,
            0
        )
        XCTAssertLessThan(
            snapshot.dataPath.inboundOccupancyP99Cells,
            WCF3Constants.defaultRingCapacity / 2
        )
        XCTAssertLessThan(
            snapshot.dataPath.outboundOccupancyP99Cells,
            WCF3Constants.defaultRingCapacity / 2
        )
    }

    func testSchedulingGapIsRetainedAsUnderdriveEvidence() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .low,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        let snapshot = try harness.step(
            nowNanoseconds: 250_000_000
        )
        XCTAssertEqual(
            snapshot.dataPath.unaccountedWorkNanoseconds,
            150_000_000
        )
    }

    func testIdleCoverUsesDeadlineDrivenWakeups() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .idle,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        XCTAssertEqual(
            harness.recommendedNextStepDelayNanoseconds(
                nowNanoseconds: 0
            ),
            1_000_000_000
        )
        _ = try harness.step(nowNanoseconds: 1_000_000_000)
        XCTAssertEqual(
            harness.recommendedNextStepDelayNanoseconds(
                nowNanoseconds: 1_000_000_000
            ),
            WCF3Constants.maximumShuffleNanoseconds
        )
        let drained = try harness.step(
            nowNanoseconds: 1_020_000_000
        )
        XCTAssertEqual(drained.dataPath.coverPairsEmitted, 1)
        XCTAssertEqual(
            harness.recommendedNextStepDelayNanoseconds(
                nowNanoseconds: 1_020_000_000
            ),
            980_000_000
        )
        XCTAssertEqual(
            drained.dataPath.unaccountedWorkNanoseconds,
            0
        )
    }

    func testPhysicalActivityTailStopsTrafficBeforeRunEnds() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .low,
                coverSemantics: .activityWithThirtySecondTail,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 60_000_000_000
            )
        )
        XCTAssertEqual(
            harness.configuration.trafficActiveNanoseconds,
            30_000_000_000
        )
        harness.start(nowNanoseconds: 0)
        var atTrafficEnd = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 3_000 {
            atTrafficEnd = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        let acceptedAtTrafficEnd =
            atTrafficEnd.dataPath.acceptedCells
        let coverAtTrafficEnd =
            atTrafficEnd.dataPath.coverPairsAccepted
        var duringTail = atTrafficEnd
        for tick in 3_001 ... 5_999 {
            duringTail = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertGreaterThan(
            duringTail.dataPath.coverPairsAccepted,
            coverAtTrafficEnd + 25
        )
        // After user production stops, only one cover pair/second may enter.
        XCTAssertLessThan(
            duringTail.dataPath.acceptedCells -
                acceptedAtTrafficEnd,
            70
        )
        XCTAssertFalse(duringTail.completed)
        let completed = try harness.step(
            nowNanoseconds: 60_000_000_000
        )
        XCTAssertTrue(completed.completed)
    }

    func testStageASaturatedProfileDropsAtFixedCapacity() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .saturated,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 200 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertGreaterThan(snapshot.dataPath.droppedCells, 0)
        XCTAssertGreaterThan(snapshot.dataPath.backpressureEvents, 0)
        XCTAssertGreaterThan(snapshot.dataPath.backpressuredCells, 0)
        XCTAssertLessThanOrEqual(
            snapshot.dataPath.inboundQueueDepth,
            WCF3Constants.defaultRingCapacity
        )
        XCTAssertLessThanOrEqual(
            snapshot.dataPath.outboundQueueDepth,
            WCF3Constants.defaultRingCapacity
        )
        XCTAssertEqual(
            harness.privacyPool?.allocatedCellBytes,
            2_097_152
        )
    }

    func testStageAAcceleratedRotationUsesOnlyTwoPools() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .low,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .acceleratedAllocation,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 100 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertGreaterThanOrEqual(snapshot.dataPath.rotationCount, 5)
        XCTAssertEqual(
            harness.privacyPool?.maximumConcurrentCircuits,
            2
        )
        XCTAssertEqual(
            harness.privacyPool?.allocatedCellBytes,
            2_097_152
        )
        XCTAssertLessThanOrEqual(
            snapshot.dataPath.maximumRotationOverlapNanoseconds,
            60_000_000
        )
    }

    func testStageACompletesFiveHundredAcceleratedRotations() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .idle,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .acceleratedAllocation,
                durationNanoseconds: 300_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 6_000 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertGreaterThanOrEqual(
            snapshot.dataPath.rotationCount,
            500
        )
        XCTAssertEqual(
            snapshot.dataPath.allocatedPrivacyCellBytes,
            2_097_152
        )
        XCTAssertLessThanOrEqual(
            snapshot.dataPath.maximumRotationOverlapNanoseconds,
            60_000_000
        )
    }

    func testCoreBaselineOwnsNoPrivacyCellAllocation() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .coreBaseline,
                trafficProfile: .medium,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .acceleratedAllocation,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        let snapshot = try harness.step(
            nowNanoseconds: 10_000_000_000
        )
        XCTAssertNil(harness.privacyPool)
        XCTAssertEqual(
            snapshot.dataPath.allocatedPrivacyCellBytes,
            0
        )
        XCTAssertEqual(snapshot.dataPath.acceptedCells, 0)
        XCTAssertEqual(snapshot.dataPath.coverPairsEmitted, 0)
        XCTAssertEqual(snapshot.dataPath.rotationCount, 0)
        XCTAssertGreaterThan(snapshot.dataPath.commonPathUnits, 0)
    }

    func testCoreAndPrivacyPerformMatchedCommonPathWork() throws {
        let core = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .coreBaseline,
                trafficProfile: .medium,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        let privacy = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .medium,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        core.start(nowNanoseconds: 0)
        privacy.start(nowNanoseconds: 0)
        var coreSnapshot = core.snapshot(nowNanoseconds: 0)
        var privacySnapshot = privacy.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 100 {
            let now = UInt64(tick) * 10_000_000
            coreSnapshot = try core.step(nowNanoseconds: now)
            privacySnapshot = try privacy.step(nowNanoseconds: now)
        }
        XCTAssertEqual(
            coreSnapshot.dataPath.commonPathUnits,
            privacySnapshot.dataPath.commonPathUnits
        )
        XCTAssertEqual(
            coreSnapshot.dataPath.commonPathChecksum,
            privacySnapshot.dataPath.commonPathChecksum
        )
        XCTAssertEqual(
            core.recommendedNextStepDelayNanoseconds(
                nowNanoseconds: 1_000_000_000
            ),
            10_000_000
        )
        XCTAssertEqual(coreSnapshot.dataPath.allocatedPrivacyCellBytes, 0)
        XCTAssertEqual(
            privacySnapshot.dataPath.allocatedPrivacyCellBytes,
            2_097_152
        )
    }

    func testCompletionAccountsExactFinalBusyInterval() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .low,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 3_000 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertTrue(snapshot.completed)
        XCTAssertEqual(snapshot.dataPath.commonPathUnits, 3_000)
        XCTAssertEqual(
            snapshot.dataPath.commonPathActiveNanoseconds,
            30_000_000_000
        )
        XCTAssertEqual(snapshot.dataPath.coverPairsAccepted, 30)
        XCTAssertEqual(snapshot.dataPath.coverPairsEmitted, 29)
        XCTAssertEqual(snapshot.dataPath.coverInboundCellsPending, 1)
        XCTAssertEqual(snapshot.dataPath.coverOutboundCellsPending, 1)
        XCTAssertEqual(snapshot.dataPath.acceptedCells, 3_060)
        XCTAssertEqual(snapshot.dataPath.droppedCells, 0)
    }

    func testCompletionClampsOvershootToConfiguredDuration() throws {
        func run(finalNanoseconds: UInt64) throws
            -> StageAHarnessSnapshot
        {
            let harness = try StageAHarness(
                configuration: StageAConfiguration(
                    mode: .maximumPrivacy,
                    trafficProfile: .low,
                    coverSemantics: .continuousWhileConnected,
                    rotationCadence: .protocolFifteenMinutes,
                    durationNanoseconds: 30_000_000_000
                )
            )
            harness.start(nowNanoseconds: 0)
            for tick in 1 ... 2_999 {
                _ = try harness.step(
                    nowNanoseconds: UInt64(tick) * 10_000_000
                )
            }
            return try harness.step(
                nowNanoseconds: finalNanoseconds
            )
        }
        let exact = try run(finalNanoseconds: 30_000_000_000)
        let overshot = try run(finalNanoseconds: 30_500_000_000)
        XCTAssertEqual(
            overshot.dataPath.commonPathUnits,
            exact.dataPath.commonPathUnits
        )
        XCTAssertEqual(
            overshot.dataPath.acceptedCells,
            exact.dataPath.acceptedCells
        )
        XCTAssertEqual(
            overshot.dataPath.coverPairsAccepted,
            exact.dataPath.coverPairsAccepted
        )
        XCTAssertEqual(
            overshot.dataPath.unaccountedWorkNanoseconds,
            exact.dataPath.unaccountedWorkNanoseconds
        )
        XCTAssertEqual(
            exact.dataPath.maximumCoverLatenessNanoseconds,
            0
        )
        XCTAssertEqual(exact.dataPath.coverDeadlinesMissed, 0)
        XCTAssertEqual(
            overshot.dataPath.maximumCoverLatenessNanoseconds,
            500_000_000
        )
        XCTAssertEqual(overshot.dataPath.coverDeadlinesMissed, 1)
    }

    func testActivityTailUsesExactTrafficBoundary() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .low,
                coverSemantics: .activityWithThirtySecondTail,
                rotationCadence: .protocolFifteenMinutes,
                durationNanoseconds: 60_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        for tick in 1 ... 58 {
            _ = try harness.step(
                nowNanoseconds: UInt64(tick) * 500_000_000
            )
        }
        _ = try harness.step(nowNanoseconds: 30_500_000_000)
        var beforeLast = harness.snapshot(
            nowNanoseconds: 30_500_000_000
        )
        for second in 31 ... 58 {
            beforeLast = try harness.step(
                nowNanoseconds:
                    UInt64(second) * 1_000_000_000 + 500_000_000
            )
        }
        let last = try harness.step(
            nowNanoseconds: 59_500_000_000
        )
        XCTAssertFalse(last.completed)
        XCTAssertEqual(
            last.dataPath.coverPairsAccepted,
            beforeLast.dataPath.coverPairsAccepted + 1
        )
        let completed = try harness.step(
            nowNanoseconds: 60_000_000_000
        )
        XCTAssertTrue(completed.completed)
        XCTAssertEqual(completed.dataPath.coverPairsAccepted, 60)
        XCTAssertEqual(
            completed.dataPath.coverInboundCellsAccepted,
            completed.dataPath.coverPairsAccepted
        )
        XCTAssertEqual(
            completed.dataPath.coverOutboundCellsAccepted,
            completed.dataPath.coverPairsAccepted
        )
        XCTAssertEqual(
            completed.dataPath.coverInboundCellsAccepted,
            completed.dataPath.coverInboundCellsEmitted +
                UInt64(completed.dataPath.coverInboundCellsPending) +
                completed.dataPath.coverInboundCellsRetired
        )
        XCTAssertEqual(
            completed.dataPath.coverOutboundCellsAccepted,
            completed.dataPath.coverOutboundCellsEmitted +
                UInt64(completed.dataPath.coverOutboundCellsPending) +
                completed.dataPath.coverOutboundCellsRetired
        )
    }

    func testNaturalCompletionReturnsToSingleActiveCircuit() throws {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .idle,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .acceleratedAllocation,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        var snapshot = harness.snapshot(nowNanoseconds: 0)
        for tick in 1 ... 3_000 {
            snapshot = try harness.step(
                nowNanoseconds: UInt64(tick) * 10_000_000
            )
        }
        XCTAssertTrue(snapshot.completed)
        XCTAssertNil(snapshot.dataPath.rotationStandbyCircuit)
        XCTAssertNil(
            snapshot.dataPath.rotationOverlapDeadlineNanoseconds
        )
        XCTAssertNil(harness.privacyPool?.state().standbyIndex)
        let accepted = snapshot.dataPath.acceptedCells
        let afterCompletion = try harness.step(
            nowNanoseconds: 31_000_000_000
        )
        XCTAssertEqual(
            afterCompletion.dataPath.acceptedCells,
            accepted
        )
    }

    func testAcceleratedCompletionDoesNotStartUnfinishableOverlap()
        throws
    {
        let harness = try StageAHarness(
            configuration: StageAConfiguration(
                mode: .maximumPrivacy,
                trafficProfile: .idle,
                coverSemantics: .continuousWhileConnected,
                rotationCadence: .acceleratedAllocation,
                durationNanoseconds: 30_000_000_000
            )
        )
        harness.start(nowNanoseconds: 0)
        _ = try harness.step(nowNanoseconds: 29_800_000_000)
        _ = try harness.step(nowNanoseconds: 29_860_000_000)
        let beforeCompletion = try harness.step(
            nowNanoseconds: 29_960_000_000
        )
        XCTAssertNil(
            beforeCompletion.dataPath.rotationStandbyCircuit
        )
        let completed = try harness.step(
            nowNanoseconds: 30_000_000_000
        )
        XCTAssertTrue(completed.completed)
        XCTAssertNil(completed.dataPath.rotationStandbyCircuit)
        XCTAssertEqual(completed.dataPath.retiredDataCells, 0)
        XCTAssertEqual(completed.dataPath.retiredCoverCells, 0)
    }
}
