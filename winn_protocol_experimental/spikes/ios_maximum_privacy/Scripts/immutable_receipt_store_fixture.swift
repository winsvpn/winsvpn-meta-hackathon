import Darwin
import Foundation

/// Exercises `Host/ImmutableReceiptStore.swift` on its own. It is the only
/// executable check of the receipt publish path outside a physical device run,
/// so it asserts the properties that matter: single write, byte-identical
/// idempotency, fail-closed on any difference, refusal to follow a symbolic
/// link either at the receipt path or at its parent, refusal of a receipt that
/// is reachable under a second name or by another user, and — the property
/// this fixture exists for — that a durability failure in EITHER phase is not
/// convertible into a reported success by retrying.
@main
enum ImmutableReceiptStoreFixture {
    static func main() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(
                "winn-receipt-store-\(UUID().uuidString.lowercased())",
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        try publishAndIdempotency(in: root)
        try stopReceiptIsExactAndImmutable(in: root)
        try refusesUnsafePaths(in: root)
        try fileBarrierFailureRequiresSuccessfulResynchronization(in: root)
        try directoryBarrierFailureIsNotConvertibleToSuccess(in: root)
        try directoryCreationFailureIsNotConvertibleToSuccess(in: root)
        try refusesAMultiplyLinkedOrPermissiveReceipt(in: root)

        print("PASS: immutable start-receipt publish, idempotency, "
            + "fail-closed behaviour, unsafe-path refusal, and "
            + "non-convertible durability failures")
    }

    // MARK: - Publish, idempotency, fail closed

    private static func publishAndIdempotency(in root: URL) throws {
        let receipt = root.appendingPathComponent("run.start-receipt.json")
        let bytes = Data(#"{"schema":"start-receipt"}"#.utf8) + Data([0x0a])

        let first = try ExperimentalImmutableReceiptStore.publish(
            bytes, to: receipt
        )
        guard case .published = first else {
            try fail("a fresh receipt must publish")
        }
        // Reported, not asserted. `.fsyncOnly` means F_FULLFSYNC was refused
        // by this filesystem and no power-loss claim is being made; the run is
        // still valid, the claim is just narrower. Asserting `.fullFsync` here
        // would make the fixture a filesystem test rather than a store test.
        print("note: receipt durability barrier is \(first.barrier.rawValue)")

        try expect(
            try Data(contentsOf: receipt) == bytes,
            "published bytes must match exactly"
        )

        let second = try ExperimentalImmutableReceiptStore.publish(
            bytes, to: receipt
        )
        guard case .alreadyPublishedIdentical = second else {
            try fail("a byte-identical republish must be idempotent")
        }
        try expect(
            try ExperimentalImmutableReceiptStore.read(receipt) == bytes,
            "the store must read back the exact published bytes"
        )

        let different = Data(#"{"schema":"start-receipt "}"#.utf8) +
            Data([0x0a])
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    different, to: receipt
                )
            },
            "a differing republish must fail closed"
        )
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "a refused republish must leave the original untouched"
        )

        // One byte shorter, same prefix: length alone must not decide.
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes.dropLast(), to: receipt
                )
            },
            "a truncated republish must fail closed"
        )
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "a refused truncated republish must leave the original untouched"
        )
    }

    private static func stopReceiptIsExactAndImmutable(
        in root: URL
    ) throws {
        let receipt = root.appendingPathComponent(
            "run.stop-receipt.json"
        )
        let bytes = Data(
            #"{"roundTripNanoseconds":300,"schema":"stop-receipt"}"#.utf8
        ) + Data([0x0a])
        _ = try ExperimentalImmutableReceiptStore.publish(
            bytes,
            to: receipt
        )
        _ = try ExperimentalImmutableReceiptStore.publish(
            bytes,
            to: receipt
        )
        let differing = Data(
            #"{"roundTripNanoseconds":301,"schema":"stop-receipt"}"#.utf8
        ) + Data([0x0a])
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    differing,
                    to: receipt
                )
            },
            "a byte-different stop receipt must never replace the original"
        )
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "the exact stop receipt plus LF must remain immutable"
        )
    }

    // MARK: - Unsafe paths

    private static func refusesUnsafePaths(in root: URL) throws {
        let bytes = Data(#"{"schema":"start-receipt"}"#.utf8) + Data([0x0a])

        // A symbolic link at the receipt path must never be followed, either
        // to create through or to compare against.
        let target = root.appendingPathComponent("elsewhere.json")
        try bytes.write(to: target)
        let link = root.appendingPathComponent("linked.start-receipt.json")
        try FileManager.default.createSymbolicLink(
            at: link,
            withDestinationURL: target
        )
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes, to: link
                )
            },
            "a symbolic link at the receipt path must be refused"
        )

        // A symbolic link standing in for the PARENT directory must be
        // refused too: the parent is opened O_DIRECTORY|O_NOFOLLOW and every
        // later operation is relative to that descriptor.
        let realParent = root.appendingPathComponent(
            "real-parent",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: realParent,
            withIntermediateDirectories: false
        )
        let linkedParent = root.appendingPathComponent(
            "linked-parent",
            isDirectory: true
        )
        try FileManager.default.createSymbolicLink(
            at: linkedParent,
            withDestinationURL: realParent
        )
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes,
                    to: linkedParent
                        .appendingPathComponent("run.start-receipt.json")
                )
            },
            "a symbolic link standing in for the parent must be refused"
        )
        try expect(
            !FileManager.default.fileExists(
                atPath: realParent
                    .appendingPathComponent("run.start-receipt.json").path
            ),
            "a refused symbolic-link parent must not have been written through"
        )

        let empty = root.appendingPathComponent("empty.start-receipt.json")
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    Data(), to: empty
                )
            },
            "an empty receipt must be refused"
        )

        let oversized = root.appendingPathComponent("big.start-receipt.json")
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    Data(
                        repeating: 0x61,
                        count: ExperimentalImmutableReceiptStore
                            .maximumBytes + 1
                    ),
                    to: oversized
                )
            },
            "an oversized receipt must be refused"
        )

        // A trailing-slash URL has no usable final component; it must not be
        // silently treated as some other name inside the parent.
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes,
                    to: root.appendingPathComponent("..", isDirectory: false)
                )
            },
            "a receipt name of `..` must be refused"
        )
    }

    // MARK: - Failure phases

    /// No failed artifact is unlinked by pathname. A complete write whose file
    /// barrier failed remains present and can recover only through an exact
    /// identical retry that successfully re-establishes both barriers.
    private static func fileBarrierFailureRequiresSuccessfulResynchronization(
        in root: URL
    ) throws {
        let directory = root.appendingPathComponent(
            "file-barrier",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        let receipt = directory
            .appendingPathComponent("run.start-receipt.json")
        let bytes = Data(#"{"schema":"file-barrier"}"#.utf8) + Data([0x0a])

        ExperimentalImmutableReceiptStore.injectedFileSynchronizeFailure = EIO
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes, to: receipt
                )
            },
            "a file-barrier failure must fail the publish"
        )
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "a file-barrier failure must retain the exact refused artifact"
        )
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes, to: receipt
                )
            },
            "a persistent file-barrier failure must not become success merely "
                + "because complete bytes are present"
        )
        ExperimentalImmutableReceiptStore.injectedFileSynchronizeFailure = nil
        let recovered = try ExperimentalImmutableReceiptStore.publish(
            bytes, to: receipt
        )
        guard case .alreadyPublishedIdentical = recovered else {
            try fail(
                "a successful exact retry must report idempotent recovery"
            )
        }
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "recovery must leave the exact artifact bytes untouched"
        )
    }

    /// The property this fixture exists for. A directory-barrier failure must
    /// never become a success just because the bytes are already there.
    private static func directoryBarrierFailureIsNotConvertibleToSuccess(
        in root: URL
    ) throws {
        let directory = root.appendingPathComponent(
            "directory-barrier",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        let receipt = directory
            .appendingPathComponent("run.start-receipt.json")
        let bytes = Data(#"{"schema":"directory-barrier"}"#.utf8) +
            Data([0x0a])

        ExperimentalImmutableReceiptStore
            .injectedDirectorySynchronizeFailure = EIO
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes, to: receipt
                )
            },
            "a directory-barrier failure must fail the publish"
        )
        // The written bytes are deliberately left in place: they are what the
        // retry has to reopen and re-establish durability over.
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "a directory-barrier failure must leave the written bytes in place"
        )

        // While the failure persists, every retry must keep failing. If the
        // retry short-circuited on "the bytes already match", the durability
        // failure would be laundered into a reported success.
        for _ in 0 ..< 3 {
            try expectThrows(
                {
                    _ = try ExperimentalImmutableReceiptStore.publish(
                        bytes, to: receipt
                    )
                },
                "a persistent directory-barrier failure must never be "
                    + "convertible to success"
            )
        }

        ExperimentalImmutableReceiptStore
            .injectedDirectorySynchronizeFailure = nil
        let recovered = try ExperimentalImmutableReceiptStore.publish(
            bytes, to: receipt
        )
        guard case .alreadyPublishedIdentical = recovered else {
            try fail(
                "once the directory barrier succeeds, the identical retry "
                    + "must report idempotent republication"
            )
        }
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "recovery must not have altered the receipt"
        )

        // A differing republish is still refused while the barrier is broken,
        // and the original is still untouched.
        ExperimentalImmutableReceiptStore
            .injectedDirectorySynchronizeFailure = EIO
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    Data(#"{"schema":"other"}"#.utf8) + Data([0x0a]),
                    to: receipt
                )
            },
            "a differing republish must fail closed regardless of the barrier"
        )
        ExperimentalImmutableReceiptStore
            .injectedDirectorySynchronizeFailure = nil
        try expect(
            try Data(contentsOf: receipt) == bytes,
            "a refused differing republish must leave the original untouched"
        )
    }

    /// Directory creation has the same retry trap as receipt publication: the
    /// name may exist even though synchronizing its container failed. A retry
    /// must re-establish that barrier rather than interpreting existence as
    /// proof of durability.
    private static func directoryCreationFailureIsNotConvertibleToSuccess(
        in root: URL
    ) throws {
        let directory = root.appendingPathComponent(
            "durable-directory",
            isDirectory: true
        )
        ExperimentalImmutableReceiptStore
            .injectedDirectorySynchronizeFailure = EIO
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore
                    .createDirectoryDurably(at: directory)
            },
            "a directory-entry synchronize failure must fail creation"
        )
        try expect(
            FileManager.default.fileExists(atPath: directory.path),
            "the retry fixture requires the created name to remain present"
        )
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore
                    .createDirectoryDurably(at: directory)
            },
            "an existing directory must not convert a persistent barrier "
                + "failure into success"
        )
        ExperimentalImmutableReceiptStore
            .injectedDirectorySynchronizeFailure = nil
        _ = try ExperimentalImmutableReceiptStore
            .createDirectoryDurably(at: directory)
    }

    // MARK: - Existing-file acceptance checks

    private static func refusesAMultiplyLinkedOrPermissiveReceipt(
        in root: URL
    ) throws {
        let directory = root.appendingPathComponent(
            "acceptance",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        let receipt = directory
            .appendingPathComponent("run.start-receipt.json")
        let bytes = Data(#"{"schema":"acceptance"}"#.utf8) + Data([0x0a])
        _ = try ExperimentalImmutableReceiptStore.publish(bytes, to: receipt)

        // A hard link means the published bytes are also reachable, and
        // mutable, through a name this store never checked.
        let second = directory.appendingPathComponent("second-name.json")
        try FileManager.default.linkItem(at: receipt, to: second)
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes, to: receipt
                )
            },
            "a multiply linked receipt must be refused"
        )
        try FileManager.default.removeItem(at: second)
        try expect(
            try isIdempotent(
                ExperimentalImmutableReceiptStore.publish(bytes, to: receipt)
            ),
            "removing the extra link must restore idempotent republication"
        )

        // This store creates receipts 0600 and a umask can only clear bits, so
        // any group or other access proves the file was not created here.
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o644)],
            ofItemAtPath: receipt.path
        )
        try expectThrows(
            {
                _ = try ExperimentalImmutableReceiptStore.publish(
                    bytes, to: receipt
                )
            },
            "a group- or other-accessible receipt must be refused"
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o600)],
            ofItemAtPath: receipt.path
        )
        try expect(
            try isIdempotent(
                ExperimentalImmutableReceiptStore.publish(bytes, to: receipt)
            ),
            "restoring 0600 must restore idempotent republication"
        )

        // Ownership is checked in the store as well, but only the POSITIVE
        // direction is exercised here and this fixture says so rather than
        // implying coverage it does not have: creating a receipt owned by a
        // different user requires privileges this process does not have and
        // must not acquire.
        var status = stat()
        try expect(
            stat(receipt.path, &status) == 0 && status.st_uid == geteuid(),
            "the published receipt must be owned by this process"
        )
    }

    private static func isIdempotent(
        _ outcome: @autoclosure () throws -> ExperimentalImmutableReceiptOutcome
    ) throws -> Bool {
        if case .alreadyPublishedIdentical = try outcome() { return true }
        return false
    }

    // MARK: - Assertions

    private static func expect(
        _ condition: @autoclosure () throws -> Bool,
        _ message: String
    ) throws {
        guard try condition() else {
            try fail(message)
        }
    }

    private static func expectThrows(
        _ operation: () throws -> Void,
        _ message: String
    ) throws {
        do {
            try operation()
        } catch {
            return
        }
        try fail(message)
    }

    private static func fail(_ message: String) throws -> Never {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}
