import Foundation

enum ExperimentalCollectedEvidenceValidator {
    static func validate(
        _ url: URL,
        runID: String
    ) throws -> Bool {
        let values = try url.resourceValues(
            forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey,
                .fileSizeKey,
            ]
        )
        guard values.isRegularFile == true,
              values.isSymbolicLink != true,
              let fileSize = values.fileSize,
              fileSize > 0,
              fileSize <= 64 * 1_024 * 1_024
        else {
            return false
        }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        var lines = data.split(
            separator: 0x0a,
            omittingEmptySubsequences: false
        )
        if lines.last?.isEmpty == true {
            lines.removeLast()
        }
        guard lines.count >= 2,
              !lines.contains(where: \.isEmpty)
        else {
            return false
        }
        var expectedSchema: String?
        var expectedProtocolVersion: String?
        var expectedSourceDigest: String?
        var expectedArtifactDigest: String?
        var expectedMode: String?
        var expectedTrafficProfile: String?
        var expectedCoverSemantics: String?
        var expectedRotationCadence: String?
        var expectedTestCondition: String?
        var expectedPairID: String?
        var expectedDurationNanoseconds: UInt64?
        var previousMonotonicNanoseconds: UInt64?
        var terminalCount = 0
        for (index, line) in lines.enumerated() {
            guard let record = try JSONSerialization.jsonObject(
                with: Data(line)
            ) as? [String: Any],
                  let schema = record["schema"] as? String,
                  schema == "winn-ios-privacy-spike/3",
                  let protocolVersion =
                    record["protocolVersion"] as? String,
                  protocolVersion == "winn/3",
                  record["runID"] as? String == runID,
                  let event = record["event"] as? String,
                  let sourceDigest =
                    record["sourceDigest"] as? String,
                  Self.isLowercaseSHA256(sourceDigest),
                  let artifactDigest =
                    record["artifactDigest"] as? String,
                  Self.isLowercaseSHA256(artifactDigest),
                  let mode = record["mode"] as? String,
                  let trafficProfile =
                    record["trafficProfile"] as? String,
                  let coverSemantics =
                    record["coverSemantics"] as? String,
                  let rotationCadence =
                    record["rotationCadence"] as? String,
                  let testCondition =
                    record["testCondition"] as? String,
                  let pairID = record["pairID"] as? String,
                  let durationNumber =
                    record["durationNanoseconds"] as? NSNumber,
                  let durationNanoseconds =
                    UInt64(durationNumber.stringValue),
                  durationNanoseconds > 0,
                  let monotonicNumber =
                    record["monotonicNanoseconds"] as? NSNumber,
                  let monotonicNanoseconds =
                    UInt64(monotonicNumber.stringValue),
                  record["failureCode"] == nil
            else {
                return false
            }
            if index == 0 {
                guard event == "started" else { return false }
                expectedSchema = schema
                expectedProtocolVersion = protocolVersion
                expectedSourceDigest = sourceDigest
                expectedArtifactDigest = artifactDigest
                expectedMode = mode
                expectedTrafficProfile = trafficProfile
                expectedCoverSemantics = coverSemantics
                expectedRotationCadence = rotationCadence
                expectedTestCondition = testCondition
                expectedPairID = pairID
                expectedDurationNanoseconds = durationNanoseconds
            } else {
                guard schema == expectedSchema,
                      protocolVersion == expectedProtocolVersion,
                      sourceDigest == expectedSourceDigest,
                      artifactDigest == expectedArtifactDigest,
                      mode == expectedMode,
                      trafficProfile == expectedTrafficProfile,
                      coverSemantics == expectedCoverSemantics,
                      rotationCadence == expectedRotationCadence,
                      testCondition == expectedTestCondition,
                      pairID == expectedPairID,
                      durationNanoseconds ==
                        expectedDurationNanoseconds
                else {
                    return false
                }
            }
            if let previousMonotonicNanoseconds,
               monotonicNanoseconds <= previousMonotonicNanoseconds {
                return false
            }
            previousMonotonicNanoseconds = monotonicNanoseconds
            let isLast = index == lines.count - 1
            if event == "completed" ||
                event == "stop-acknowledged" {
                terminalCount += 1
                guard isLast else { return false }
            } else if event == "sample-window" {
                guard index > 0, !isLast else { return false }
            } else if index > 0 {
                return false
            }
        }
        return terminalCount == 1
    }

    private static func isLowercaseSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) ||
                ($0 >= 97 && $0 <= 102)
        }
    }
}
