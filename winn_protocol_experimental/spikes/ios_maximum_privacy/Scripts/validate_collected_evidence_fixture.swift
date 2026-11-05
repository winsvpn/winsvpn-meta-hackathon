import Foundation

@main
struct ValidateCollectedEvidenceFixture {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            throw ValidationError.invalidArguments
        }
        let source = URL(fileURLWithPath: CommandLine.arguments[1])
        let runID = "01234567-89ab-cdef-0123-456789abcdef"
        guard try ExperimentalCollectedEvidenceValidator.validate(
            source,
            runID: runID
        ) else {
            throw ValidationError.validFixtureRejected
        }
        let original = try Data(contentsOf: source)
        guard var text = String(data: original, encoding: .utf8) else {
            throw ValidationError.invalidEncoding
        }
        text = text.replacingOccurrences(
            of: "\"durationNanoseconds\"",
            with: "\"durationSeconds\""
        )
        let tampered = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "winn-host-validator-\(UUID().uuidString).jsonl"
            )
        defer { try? FileManager.default.removeItem(at: tampered) }
        try Data(text.utf8).write(to: tampered, options: .atomic)
        guard try !ExperimentalCollectedEvidenceValidator.validate(
            tampered,
            runID: runID
        ) else {
            throw ValidationError.wrongDurationKeyAccepted
        }
        guard try !ExperimentalCollectedEvidenceValidator.validate(
            source,
            runID: "ffffffff-ffff-ffff-ffff-ffffffffffff"
        ) else {
            throw ValidationError.wrongRunAccepted
        }
        print("HOST_EVIDENCE_VALIDATOR_PASS")
    }

    private enum ValidationError: Error {
        case invalidArguments
        case validFixtureRejected
        case invalidEncoding
        case wrongDurationKeyAccepted
        case wrongRunAccepted
    }
}
