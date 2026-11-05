import Darwin
import Foundation

enum ExperimentalImmutableReceiptError: Error, Equatable {
    case invalidName
    case parentOpenFailed(Int32)
    case openFailed(Int32)
    case readFailed(Int32)
    case writeFailed(Int32)
    case fileSynchronizeFailed(Int32)
    case directorySynchronizeFailed(Int32)
    case directoryCreationFailed(Int32)
    case notARegularFile
    case multiplyLinked
    case groupOrOtherAccessible
    case foreignOwner
    case oversized
    case existingContentDiffers
}

/// Which storage barrier a synchronize actually obtained.
///
/// The claim is deliberately narrow, because the platform's is. On Darwin
/// `fsync(2)` moves data out of the kernel to the drive but explicitly does
/// NOT ask the drive to flush its own write cache; `F_FULLFSYNC` is documented
/// as the call that additionally requests that flush.
///
/// - `.fullFsync`: the strongest barrier this platform exposes was accepted.
///   This is still NOT an absolute power-loss guarantee — a drive may decline
///   to honour the flush, and nothing here can observe whether it did.
/// - `.fsyncOnly`: `F_FULLFSYNC` was refused by the filesystem and plain
///   `fsync` was used instead. The bytes left the kernel and may be sitting in
///   a volatile device cache. **No power-loss claim is made in this case.**
///
/// The barrier is returned to the caller rather than swallowed, so which of
/// the two actually happened is visible instead of assumed.
enum ExperimentalDurabilityBarrier: String, Equatable {
    case fullFsync = "f-fullfsync"
    case fsyncOnly = "fsync-only"

    /// The weaker of two barriers, for combining a file with its directory.
    func combined(
        with other: ExperimentalDurabilityBarrier
    ) -> ExperimentalDurabilityBarrier {
        self == .fullFsync && other == .fullFsync ? .fullFsync : .fsyncOnly
    }
}

enum ExperimentalImmutableReceiptOutcome: Equatable {
    case published(ExperimentalDurabilityBarrier)
    case alreadyPublishedIdentical(ExperimentalDurabilityBarrier)

    var barrier: ExperimentalDurabilityBarrier {
        switch self {
        case let .published(barrier): return barrier
        case let .alreadyPublishedIdentical(barrier): return barrier
        }
    }
}

/// Publishes a receipt at a path that is written exactly once.
///
/// Every operation is bound to a parent directory opened once with
/// `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`, and the receipt itself is reached
/// only through `openat` relative to that descriptor. The create uses
/// `O_EXCL | O_NOFOLLOW`, so it never follows a symbolic link and never
/// truncates an existing file. When the name already exists the bytes are
/// reopened and compared; a byte-identical republish re-establishes BOTH
/// halves of the durability barrier and is then reported as idempotent, and
/// anything else fails closed, leaving the original untouched. There is no
/// unlink, replace, rename, or backup path: even a failed partial artifact is
/// retained and refused rather than removed through a raceable pathname.
///
/// WHAT THE PARENT BINDING DOES AND DOES NOT COVER, stated rather than
/// implied. Opening the parent with `O_NOFOLLOW` refuses a symbolic link in
/// that directory's FINAL component, and every later operation is relative to
/// the descriptor, so the directory cannot be swapped underneath the sequence.
/// Darwin's `O_NOFOLLOW_ANY`, which would also refuse a symbolic link at any
/// intermediate component, is deliberately not used: ordinary paths on this
/// platform legitimately traverse system symbolic links — `/var` is one, and
/// every temporary and app-group container path goes through it — so requiring
/// it refuses the real evidence directory with `ELOOP`. That was measured, not
/// assumed. Intermediate components are therefore NOT protected against
/// substitution.
///
/// Deliberately byte-oriented rather than typed, and dependent on nothing but
/// Darwin and Foundation, so `Scripts/immutable_receipt_store_fixture.swift`
/// can compile and exercise it on its own without the host app,
/// NetworkExtension, or the shared package. `SpikeDurability` in
/// `PrivacyCore/Sources/WinnPrivacyCore/SpikeMetrics.swift` carries an
/// equivalent copy of the barrier logic for the same reason; the two must be
/// kept in step.
enum ExperimentalImmutableReceiptStore {
    static let maximumBytes = 64 * 1_024

    /// Failure seams for `Scripts/immutable_receipt_store_fixture.swift`.
    ///
    /// Both are `nil` in production and nothing in the host app ever sets
    /// them. They exist because the two failure phases that matter here — the
    /// file barrier and the directory barrier — cannot be provoked on a real
    /// filesystem from user space, and a durability path whose failure branch
    /// is never executed is a durability path that is not known to work.
    static var injectedFileSynchronizeFailure: Int32?
    static var injectedDirectorySynchronizeFailure: Int32?

    @discardableResult
    static func publish(
        _ bytes: Data,
        to url: URL
    ) throws -> ExperimentalImmutableReceiptOutcome {
        guard !bytes.isEmpty, bytes.count <= maximumBytes else {
            throw ExperimentalImmutableReceiptError.oversized
        }
        let name = try receiptName(url)
        let parent = try openParentDirectory(url.deletingLastPathComponent())
        defer { closeDescriptor(parent) }

        var descriptor: Int32 = -1
        var openFailure: Int32 = 0
        while true {
            descriptor = name.withCString {
                openat(
                    parent,
                    $0,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR
                )
            }
            if descriptor >= 0 { break }
            openFailure = errno
            if openFailure == EINTR { continue }
            break
        }
        guard descriptor >= 0 else {
            guard openFailure == EEXIST else {
                throw ExperimentalImmutableReceiptError
                    .openFailed(openFailure)
            }
            return try republishIdentical(bytes, parent: parent, name: name)
        }

        let fileBarrier: ExperimentalDurabilityBarrier
        do {
            try writeAll(descriptor, bytes)
            try validateOpenReceipt(
                descriptor,
                expectedByteCount: bytes.count
            )
            fileBarrier = try synchronizeFile(descriptor)
        } catch {
            closeDescriptor(descriptor)
            // No pathname cleanup is attempted. Darwin has no descriptor-only
            // unlink for this file, so fstatat+unlinkat would retain a race in
            // which another inode could be removed. A failed partial artifact
            // is safer left present and permanently refused; a complete,
            // byte-identical artifact can recover only by re-establishing both
            // barriers through `republishIdentical`.
            throw error
        }
        closeDescriptor(descriptor)

        // Deliberately NOT rolled back. A fully written, file-synchronized
        // receipt whose directory entry did not complete its requested
        // barrier is left
        // exactly where it is, so the retry below has to reopen those bytes
        // and re-establish the directory barrier. Unlinking here would turn a
        // persistent directory-sync failure into a clean create on the next
        // attempt, which is precisely the conversion that must not exist.
        let directoryBarrier = try synchronizeDirectory(parent)
        return .published(fileBarrier.combined(with: directoryBarrier))
    }

    /// The retry path for a name that already exists.
    ///
    /// It reopens the exact regular bytes through the parent descriptor,
    /// requires them to be identical, and only then re-establishes the file
    /// AND directory barriers. Because both are re-established here, a
    /// directory synchronize that keeps failing keeps failing: it can never be
    /// converted into a reported success by retrying.
    private static func republishIdentical(
        _ bytes: Data,
        parent: Int32,
        name: String
    ) throws -> ExperimentalImmutableReceiptOutcome {
        var descriptor: Int32 = -1
        while true {
            descriptor = name.withCString {
                openat(parent, $0, O_RDONLY | O_NOFOLLOW)
            }
            if descriptor >= 0 { break }
            let failure = errno
            if failure == EINTR { continue }
            throw ExperimentalImmutableReceiptError.readFailed(failure)
        }
        defer { closeDescriptor(descriptor) }
        let content = try readAll(descriptor)
        guard content == bytes else {
            throw ExperimentalImmutableReceiptError.existingContentDiffers
        }
        let fileBarrier = try synchronizeFile(descriptor)
        let directoryBarrier = try synchronizeDirectory(parent)
        return .alreadyPublishedIdentical(
            fileBarrier.combined(with: directoryBarrier)
        )
    }

    /// Reads a published receipt through its parent directory descriptor,
    /// applying the same acceptance checks as the retry path.
    static func read(_ url: URL) throws -> Data {
        let name = try receiptName(url)
        let parent = try openParentDirectory(url.deletingLastPathComponent())
        defer { closeDescriptor(parent) }
        var descriptor: Int32 = -1
        while true {
            descriptor = name.withCString {
                openat(parent, $0, O_RDONLY | O_NOFOLLOW)
            }
            if descriptor >= 0 { break }
            let failure = errno
            if failure == EINTR { continue }
            throw ExperimentalImmutableReceiptError.readFailed(failure)
        }
        defer { closeDescriptor(descriptor) }
        return try readAll(descriptor)
    }

    /// Creates every missing component of `directory` and makes each new
    /// directory entry durable.
    ///
    /// At least one EXISTING entry is synchronized too. This is load-bearing:
    /// if a prior call created a component and then its directory barrier
    /// failed, the component is present on retry. Treating "already exists" as
    /// success would convert that prior durability failure into success. With
    /// missing components, the container of the deepest existing ancestor is
    /// synchronized before creation resumes. With none missing, the target's
    /// own entry is re-synchronized through its parent.
    @discardableResult
    static func createDirectoryDurably(
        at directory: URL
    ) throws -> ExperimentalDurabilityBarrier {
        var missing: [URL] = []
        var cursor = directory.standardizedFileURL
        while !FileManager.default.fileExists(atPath: cursor.path) {
            missing.append(cursor)
            let parent = cursor.deletingLastPathComponent().standardizedFileURL
            if parent.path == cursor.path { break }
            cursor = parent
        }
        let recoveryContainer = missing.isEmpty
            ? directory.deletingLastPathComponent().standardizedFileURL
            : cursor.deletingLastPathComponent().standardizedFileURL
        var barrier: ExperimentalDurabilityBarrier?
        for url in missing.reversed() {
            var made: Int32 = -1
            while true {
                made = url.path.withCString { mkdir($0, S_IRWXU) }
                if made == 0 { break }
                let failure = errno
                if failure == EINTR { continue }
                if failure == EEXIST { break }
                throw ExperimentalImmutableReceiptError
                    .directoryCreationFailed(failure)
            }
            let container = try openParentDirectory(
                url.deletingLastPathComponent()
            )
            let obtained: ExperimentalDurabilityBarrier
            do {
                defer { closeDescriptor(container) }
                obtained = try synchronizeDirectory(container)
            }
            barrier = barrier.map { $0.combined(with: obtained) } ?? obtained
        }
        let recoveryDescriptor = try openParentDirectory(recoveryContainer)
        let recovered: ExperimentalDurabilityBarrier
        do {
            defer { closeDescriptor(recoveryDescriptor) }
            recovered = try synchronizeDirectory(recoveryDescriptor)
        }
        return barrier.map { $0.combined(with: recovered) } ?? recovered
    }

    /// Re-establishes the file and directory barriers for an artifact that was
    /// written by some other path. Used by the collected-evidence copier,
    /// which claims durability and must obtain the same barrier this store
    /// does rather than a bare `fsync` on a `FileHandle`.
    @discardableResult
    static func synchronizeArtifactDurably(
        at url: URL
    ) throws -> ExperimentalDurabilityBarrier {
        let name = try receiptName(url)
        let parent = try openParentDirectory(url.deletingLastPathComponent())
        defer { closeDescriptor(parent) }
        var descriptor: Int32 = -1
        while true {
            descriptor = name.withCString {
                openat(parent, $0, O_RDONLY | O_NOFOLLOW)
            }
            if descriptor >= 0 { break }
            let failure = errno
            if failure == EINTR { continue }
            throw ExperimentalImmutableReceiptError.readFailed(failure)
        }
        defer { closeDescriptor(descriptor) }
        let fileBarrier = try synchronizeFile(descriptor)
        let directoryBarrier = try synchronizeDirectory(parent)
        return fileBarrier.combined(with: directoryBarrier)
    }

    // MARK: - POSIX seams

    private static func receiptName(_ url: URL) throws -> String {
        let name = url.lastPathComponent
        guard !name.isEmpty, name != ".", name != "..",
              !name.contains("/"), !name.utf8.contains(0)
        else {
            throw ExperimentalImmutableReceiptError.invalidName
        }
        return name
    }

    private static func openParentDirectory(_ directory: URL) throws -> Int32 {
        while true {
            let descriptor = directory.path.withCString {
                open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            }
            if descriptor >= 0 { return descriptor }
            let failure = errno
            if failure == EINTR { continue }
            throw ExperimentalImmutableReceiptError.parentOpenFailed(failure)
        }
    }

    /// `close` is not retried on `EINTR`. On Darwin the descriptor is released
    /// even when `EINTR` is reported, so retrying could close an unrelated
    /// descriptor that has since taken the same number.
    private static func closeDescriptor(_ descriptor: Int32) {
        _ = close(descriptor)
    }

    private static func synchronizeFile(
        _ descriptor: Int32
    ) throws -> ExperimentalDurabilityBarrier {
        if let injectedFileSynchronizeFailure {
            throw ExperimentalImmutableReceiptError
                .fileSynchronizeFailed(injectedFileSynchronizeFailure)
        }
        let result = synchronize(descriptor: descriptor)
        if let failure = result.failure {
            throw ExperimentalImmutableReceiptError
                .fileSynchronizeFailed(failure)
        }
        return result.barrier
    }

    private static func synchronizeDirectory(
        _ descriptor: Int32
    ) throws -> ExperimentalDurabilityBarrier {
        if let injectedDirectorySynchronizeFailure {
            throw ExperimentalImmutableReceiptError
                .directorySynchronizeFailed(
                    injectedDirectorySynchronizeFailure
                )
        }
        let result = synchronize(descriptor: descriptor)
        if let failure = result.failure {
            throw ExperimentalImmutableReceiptError
                .directorySynchronizeFailed(failure)
        }
        return result.barrier
    }

    private static func synchronize(
        descriptor: Int32
    ) -> (barrier: ExperimentalDurabilityBarrier, failure: Int32?) {
        while true {
            if fcntl(descriptor, F_FULLFSYNC) == 0 {
                return (.fullFsync, nil)
            }
            let failure = errno
            if failure == EINTR { continue }
            // Only a refusal of the operation itself falls back to `fsync`. A
            // real I/O error must surface as an error rather than be retried
            // as a weaker barrier that then reports success.
            guard failure == ENOTSUP || failure == EINVAL ||
                failure == ENOTTY || failure == EOPNOTSUPP ||
                failure == EPERM || failure == EBADF
            else {
                return (.fsyncOnly, failure)
            }
            break
        }
        while true {
            if fsync(descriptor) == 0 { return (.fsyncOnly, nil) }
            let failure = errno
            if failure == EINTR { continue }
            return (.fsyncOnly, failure)
        }
    }

    private static func descriptorStatus(
        _ descriptor: Int32,
        into status: inout stat
    ) -> Int32? {
        while true {
            if fstat(descriptor, &status) == 0 { return nil }
            let failure = errno
            if failure == EINTR { continue }
            return failure
        }
    }

    private static func validateOpenReceipt(
        _ descriptor: Int32,
        expectedByteCount: Int
    ) throws {
        var status = stat()
        if let failure = descriptorStatus(descriptor, into: &status) {
            throw ExperimentalImmutableReceiptError.readFailed(failure)
        }
        guard status.st_mode & S_IFMT == S_IFREG else {
            throw ExperimentalImmutableReceiptError.notARegularFile
        }
        guard status.st_nlink == 1 else {
            throw ExperimentalImmutableReceiptError.multiplyLinked
        }
        guard status.st_mode & (S_IRWXG | S_IRWXO) == 0 else {
            throw ExperimentalImmutableReceiptError.groupOrOtherAccessible
        }
        guard status.st_uid == geteuid() else {
            throw ExperimentalImmutableReceiptError.foreignOwner
        }
        guard status.st_size == off_t(expectedByteCount) else {
            throw ExperimentalImmutableReceiptError.writeFailed(EIO)
        }
    }

    private static func writeAll(
        _ descriptor: Int32,
        _ bytes: Data
    ) throws {
        var written = 0
        let total = bytes.count
        while written < total {
            let count: Int = bytes.withUnsafeBytes { raw in
                Darwin.write(
                    descriptor,
                    raw.baseAddress!.advanced(by: written),
                    total - written
                )
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw ExperimentalImmutableReceiptError.writeFailed(errno)
            }
            if count == 0 {
                throw ExperimentalImmutableReceiptError.writeFailed(EIO)
            }
            written += count
        }
    }

    /// Reads an already-open receipt, refusing anything that is not a plain,
    /// singly linked, private file owned by this process.
    private static func readAll(_ descriptor: Int32) throws -> Data {
        var status = stat()
        if let failure = descriptorStatus(descriptor, into: &status) {
            throw ExperimentalImmutableReceiptError.readFailed(failure)
        }
        guard status.st_mode & S_IFMT == S_IFREG else {
            throw ExperimentalImmutableReceiptError.notARegularFile
        }
        // A second name for the same inode means the published bytes are also
        // reachable, and mutable, through a path this store never checked.
        guard status.st_nlink == 1 else {
            throw ExperimentalImmutableReceiptError.multiplyLinked
        }
        // This store creates receipts 0600. A umask can only clear bits, so a
        // receipt readable or writable by group or other was not created here.
        guard status.st_mode & (S_IRWXG | S_IRWXO) == 0 else {
            throw ExperimentalImmutableReceiptError.groupOrOtherAccessible
        }
        guard status.st_uid == geteuid() else {
            throw ExperimentalImmutableReceiptError.foreignOwner
        }
        guard status.st_size >= 0, status.st_size <= maximumBytes else {
            throw ExperimentalImmutableReceiptError.oversized
        }
        var content = Data()
        var buffer = [UInt8](repeating: 0, count: 8 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw ExperimentalImmutableReceiptError.readFailed(errno)
            }
            if count == 0 { break }
            content.append(contentsOf: buffer[0 ..< count])
            guard content.count <= maximumBytes else {
                throw ExperimentalImmutableReceiptError.oversized
            }
        }
        return content
    }
}
