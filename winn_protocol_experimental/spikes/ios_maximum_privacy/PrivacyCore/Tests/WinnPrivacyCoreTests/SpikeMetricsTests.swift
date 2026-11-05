import Foundation
import XCTest
@testable import WinnPrivacyCore

final class SpikeMetricsTests: XCTestCase {
    func testJSONLRetainsSuccessAndFailureRecords() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("metrics.jsonl")
        let writer = try JSONLEvidenceWriter(fileURL: file)
        let digest = String(repeating: "a", count: 64)
        let success = try SpikeMetricRecord(
            runID: "0123456789abcdef",
            event: "sample",
            monotonicNanoseconds: 1,
            wallTimeUTC: "2026-07-23T00:00:00Z",
            mode: .maximumPrivacy,
            trafficProfile: .low,
            coverSemantics: .continuousWhileConnected,
            rotationCadence: .protocolFifteenMinutes,
            durationNanoseconds: 60_000_000_000,
            trafficActiveNanoseconds: 60_000_000_000,
            sourceDigest: digest,
            artifactDigest: digest
        )
        let failure = try SpikeMetricRecord(
            runID: "0123456789abcdef",
            event: "terminated",
            monotonicNanoseconds: 2,
            wallTimeUTC: "2026-07-23T00:00:01Z",
            mode: .maximumPrivacy,
            trafficProfile: .low,
            coverSemantics: .continuousWhileConnected,
            rotationCadence: .acceleratedAllocation,
            durationNanoseconds: 60_000_000_000,
            trafficActiveNanoseconds: 30_000_000_000,
            sourceDigest: digest,
            artifactDigest: digest,
            failureCode: "extension-terminated"
        )
        try writer.append(success)
        try writer.append(failure, synchronize: true)
        let lines = try String(contentsOf: file)
            .split(separator: "\n")
        XCTAssertEqual(lines.count, 2)
        let decoder = JSONDecoder()
        let decoded = try lines.map {
            try decoder.decode(
                SpikeMetricRecord.self,
                from: Data($0.utf8)
            )
        }
        XCTAssertNil(decoded[0].failureCode)
        XCTAssertEqual(
            decoded[1].failureCode,
            "extension-terminated"
        )
        XCTAssertEqual(
            decoded[0].constants.cellBytes,
            WCF3Constants.privacyCellSize
        )
        XCTAssertEqual(
            decoded[0].rotationCadence,
            .protocolFifteenMinutes
        )
        XCTAssertEqual(
            decoded[1].rotationCadence,
            .acceleratedAllocation
        )
        XCTAssertEqual(
            decoded[0].durationNanoseconds,
            60_000_000_000
        )
        XCTAssertEqual(
            decoded[1].trafficActiveNanoseconds,
            30_000_000_000
        )
    }

    func testJSONLWriterRefusesExistingPath() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let file = directory.appendingPathComponent("metrics.jsonl")
        XCTAssertTrue(
            FileManager.default.createFile(
                atPath: file.path,
                contents: Data("retained\n".utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONLEvidenceWriter(fileURL: file)
        ) { error in
            XCTAssertEqual(
                error as? SpikeMetricError,
                .evidencePathExistsOrIsUnsafe
            )
        }
        XCTAssertEqual(
            try String(contentsOf: file),
            "retained\n"
        )
    }

    func testJSONLWriterRefusesASymbolicLinkParent() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        let realParent = root.appendingPathComponent(
            "real",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: realParent,
            withIntermediateDirectories: false
        )
        let linkedParent = root.appendingPathComponent(
            "linked",
            isDirectory: true
        )
        try FileManager.default.createSymbolicLink(
            at: linkedParent,
            withDestinationURL: realParent
        )

        XCTAssertThrowsError(
            try JSONLEvidenceWriter(
                fileURL: linkedParent
                    .appendingPathComponent("stage-a.jsonl")
            )
        ) { error in
            XCTAssertEqual(
                error as? SpikeMetricError,
                .evidencePathExistsOrIsUnsafe
            )
        }
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: realParent
                    .appendingPathComponent("stage-a.jsonl").path
            )
        )
    }

    func testOneHertzWindowAggregatesWithoutRetainingSamples() {
        var window = SpikeResourceWindowAccumulator()
        window.add(
            SpikeResourceSnapshot(
                residentBytes: 10,
                physicalFootprintBytes: 20,
                availableProcessBytes: 100,
                userCPUNanoseconds: 1,
                systemCPUNanoseconds: 2,
                interruptWakeups: 3,
                packageIdleWakeups: 4,
                energyNanojoules: 5,
                thermalState: "nominal",
                lowPowerMode: false
            ),
            monotonicNanoseconds: 1_000_000_000
        )
        window.add(
            SpikeResourceSnapshot(
                residentBytes: 15,
                physicalFootprintBytes: 25,
                availableProcessBytes: 80,
                userCPUNanoseconds: 11,
                systemCPUNanoseconds: 22,
                interruptWakeups: 33,
                packageIdleWakeups: 44,
                energyNanojoules: 55,
                thermalState: "serious",
                lowPowerMode: true
            ),
            monotonicNanoseconds: 2_000_000_000,
            scheduledSamples: 2
        )
        let result = window.finish()
        XCTAssertEqual(result?.sampleCount, 2)
        XCTAssertEqual(result?.scheduledSampleCount, 3)
        XCTAssertEqual(result?.peakResidentBytes, 15)
        XCTAssertEqual(result?.peakPhysicalFootprintBytes, 25)
        XCTAssertEqual(result?.minimumAvailableProcessBytes, 80)
        XCTAssertEqual(result?.userCPUDeltaNanoseconds, 10)
        XCTAssertEqual(result?.systemCPUDeltaNanoseconds, 20)
        XCTAssertEqual(result?.interruptWakeupDelta, 30)
        XCTAssertEqual(result?.packageIdleWakeupDelta, 40)
        XCTAssertEqual(result?.energyDeltaNanojoules, 50)
        XCTAssertEqual(result?.worstThermalState, "serious")
        XCTAssertEqual(result?.lowPowerModeObserved, true)
        XCTAssertTrue(window.isEmpty)
    }
}
