import XCTest
@testable import WinnPrivacyCore

final class CoverSchedulerTests: XCTestCase {
    func testContinuousPolicyEmitsOnePairAndNeverCatchesUp() {
        var scheduler = CoverScheduler(
            semantics: .continuousWhileConnected
        )
        scheduler.connect(nowNanoseconds: 0)
        XCTAssertNil(scheduler.poll(nowNanoseconds: 999_999_999))
        let first = scheduler.poll(nowNanoseconds: 1_000_000_000)
        XCTAssertEqual(first?.outboundCells, 1)
        XCTAssertEqual(first?.inboundCells, 1)
        let late = scheduler.poll(nowNanoseconds: 10_000_000_000)
        XCTAssertEqual(late?.outboundCells, 1)
        XCTAssertNil(scheduler.poll(nowNanoseconds: 10_000_000_001))
        XCTAssertEqual(
            scheduler.nextDeadlineNanoseconds,
            11_000_000_000
        )
        scheduler.stop()
        XCTAssertNil(scheduler.poll(nowNanoseconds: UInt64.max))
    }

    func testSmallLatenessDoesNotAccumulateScheduleDrift() {
        var scheduler = CoverScheduler(
            semantics: .continuousWhileConnected
        )
        scheduler.connect(nowNanoseconds: 0)
        for second in 1 ... 10 {
            let emission = scheduler.poll(
                nowNanoseconds:
                    UInt64(second) * 1_000_000_000 + 10_000_000
            )
            XCTAssertEqual(
                emission?.scheduledNanoseconds,
                UInt64(second) * 1_000_000_000
            )
            XCTAssertEqual(
                emission?.latenessNanoseconds,
                10_000_000
            )
        }
        XCTAssertEqual(
            scheduler.nextDeadlineNanoseconds,
            11_000_000_000
        )
    }

    func testActivityPolicyStopsAfterThirtySecondTail() {
        var scheduler = CoverScheduler(
            semantics: .activityWithThirtySecondTail
        )
        scheduler.connect(nowNanoseconds: 0)
        XCTAssertNil(scheduler.poll(nowNanoseconds: 2_000_000_000))
        scheduler.noteUserTraffic(nowNanoseconds: 2_000_000_000)
        var emissions = 0
        for second in 3 ... 32 {
            if scheduler.poll(
                nowNanoseconds: UInt64(second) * 1_000_000_000
            ) != nil {
                emissions += 1
            }
        }
        XCTAssertEqual(emissions, 30)
        XCTAssertNil(scheduler.poll(nowNanoseconds: 33_000_000_000))
    }
}
