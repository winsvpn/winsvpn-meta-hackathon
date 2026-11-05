package org.winsvpn.app

import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.annotation.RequiresApi
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

/**
 * The `-winn3-keys` document, and the key files it names.
 *
 * ## Why this exists at all, and how the requirement was found
 *
 * [WinnV3Host.FLAG_WINN3] was written against an engine seam that did not yet
 * exist, and it described the argv as `-winn3` alone. The seam has since landed,
 * and the real binary :  cross-compiled for `android/arm64` and run on an API 34
 * device :  refuses that argv:
 *
 *     winn-datapath: -winn3 needs -winn3-keys PATH: the static key, the
 *     gateway's static key and the admission secret are named by a document
 *     this process opens itself, because a channel whose payload is
 *     peer-supplied by construction is not where key material belongs.
 *
 * A host that spawned `-winn3` alone would therefore start a subprocess that
 * exits 1 before a single frame crossed. Nothing in the Kotlin unit tests could
 * have caught that, because they assert the argv this host BUILDS rather than
 * the argv the engine ACCEPTS.
 *
 * ## The document holds no key material
 *
 * It holds PATHS. That is `winn3_keys.go`'s own rule :  *IT CONTAINS NO KEY
 * MATERIAL, only paths* :  and it is the same rule [WinnCarrierProfile] already
 * follows for the carrier profile. The engine opens each file itself, under
 * this application's uid, and makes the trust decision there rather than
 * accepting one asserted by whoever wrote the frame.
 *
 * ## Nothing here is logged
 *
 * `[winn]` values may carry secrets and three of the values this class reads
 * definitely do. No function below puts a value in a message, and
 * [describeForLog] emits key names and paths only. The same discipline
 * [WinnEngineConfig] applies to its own document.
 *
 * ## Cleanup is bound to created identities
 *
 * [writeTo] records the directory and each child by owner, mode, nlink, device
 * and inode at exclusive creation, and on a device holds the parent, directory
 * and child descriptors from that `Os.open(..., O_NOFOLLOW)`. Public SDK
 * `android.jar` does not expose an atomic compare-and-unlink operation. After
 * CreateAck, [destroy] therefore erases every created inode through its held
 * descriptor and verifies a zero length. It deliberately leaves zero-length
 * generation-scoped tombstones instead of unlinking a pathname that a same-UID
 * process could replace between inspection and removal. A false return stops
 * CONNECTED whenever descriptor-bound erasure cannot be proven.
 */
internal class WinnV3Keys private constructor(
    private val gatewayId: String,
    private val staticKeyHex: String,
    private val gatewayStaticKeyHex: String,
    private val admissionSecret: ByteArray,
    private val dualAuthEd25519Hex: String?,
    private val dualAuthMldsa65Hex: String?,
) {

    private val boundLock = Any()
    private val boundDirectories = LinkedHashMap<String, BoundDirectory>()

    /**
     * Writes the three key files and the document that names them, and returns
     * the document.
     *
     * Every file is created 0600 inside a 0700 directory. On a real Android
     * device the creates use the held directory descriptor with
     * `O_NOFOLLOW|O_EXCL`; later erasure truncates that created inode through
     * the held descriptor after owner, mode and inode checks. JVM unit tests use the same
     * identity contract through `LinkOption.NOFOLLOW_LINKS`. Any failure after
     * the first create rolls the bound children back, including when the caller
     * has not yet stored this instance for later [destroy].
     */
    @Throws(IOException::class)
    fun writeTo(directory: File): File {
        refuseSymlink(
            directory,
            "Refusing to write Winn v3 keys into a symbolic link directory: ${directory.absolutePath}",
        )
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IOException("could not create the winn3 key directory")
        }
        refuseSymlink(
            directory,
            "Winn v3 key directory is a symbolic link after creation: ${directory.absolutePath}",
        )
        if (!directory.isDirectory) {
            throw IOException("Winn v3 key path is not a directory: ${directory.absolutePath}")
        }
        restrictToOwner(directory, executable = true)
        if (!isOwnerOnly(directory)) {
            throw IOException(
                "Refusing to use a Winn v3 key directory that is not owner-only: ${directory.absolutePath}"
            )
        }

        val bound = bindDirectory(directory)
        try {
            val staticFile = writeSecret(
                bound, "static.key", staticKeyHex.toByteArray(Charsets.US_ASCII),
            )
            val gatewayFile = writeSecret(
                bound, "gateway.pub", gatewayStaticKeyHex.toByteArray(Charsets.US_ASCII),
            )
            val admissionFile = writeSecret(bound, "admission.key", admissionSecret)
            val dualAuthEd25519File =
                dualAuthEd25519Hex?.let {
                    writeSecret(bound, "auth_ed25519.pub", it.toByteArray(Charsets.US_ASCII))
                }
            val dualAuthMldsa65File =
                dualAuthMldsa65Hex?.let {
                    writeSecret(bound, "auth_mldsa65.pub", it.toByteArray(Charsets.US_ASCII))
                }
            val documentText = buildString {
                append('{')
                append("\"version\":\"").append(VERSION).append("\",")
                append("\"role\":\"").append(ROLE_CLIENT).append("\",")
                append("\"gateway_id\":").append(jsonString(gatewayId)).append(',')
                append("\"static_path\":").append(jsonString(staticFile.absolutePath)).append(',')
                append("\"gateway_static_path\":").append(jsonString(gatewayFile.absolutePath))
                    .append(',')
                append("\"admission_path\":").append(jsonString(admissionFile.absolutePath))
                    .append(',')
                if (dualAuthEd25519File != null && dualAuthMldsa65File != null) {
                    append("\"dual_auth_ed25519_pub_path\":")
                        .append(jsonString(dualAuthEd25519File.absolutePath)).append(',')
                    append("\"dual_auth_mldsa65_pub_path\":")
                        .append(jsonString(dualAuthMldsa65File.absolutePath)).append(',')
                }
                append("\"outer_socket_exclusion\":\"\",")
                append("\"fast_pq\":false,")
                append("\"rekey_after_messages\":0")
                append('}')
            }
            val document = writeSecret(
                bound, DOCUMENT_NAME, documentText.toByteArray(Charsets.UTF_8),
            )
            rememberBound(bound)
            return document
        } catch (thrown: Throwable) {
            if (!destroyBound(bound)) {
                // Keep every still-open creation descriptor reachable so the
                // service-level finally block can retry. Reporting the
                // original write error while silently abandoning unerased
                // plaintext would be a false-success cleanup result.
                rememberBound(bound)
                val cleanupFailure = IOException(
                    "Winn v3 key write failed and descriptor-bound cleanup is incomplete"
                )
                cleanupFailure.addSuppressed(thrown)
                throw cleanupFailure
            }
            if (thrown is IOException) throw thrown
            throw IOException(
                "Winn v3 key write failed at ${directory.absolutePath}",
                thrown,
            )
        }
    }

    /**
     * Erases plaintext left by process death before CreateAck.
     *
     * A new tunnel generation never reuses an earlier directory name. Before
     * writing the next generation, the service binds [filesDir] once, enumerates
     * every earlier `winn3-*` candidate through that held descriptor, and
     * truncates known children through descriptors opened from it. A same-UID
     * rename of [filesDir] or of a listed candidate therefore cannot redirect
     * recovery onto a substitute and report success. Unknown names, symlinks,
     * unsafe ownership or modes, leftover plaintext under [filesDir], and any
     * incomplete erase fail closed. Incomplete erase retries through the held
     * descriptors and then closes them so a false start cannot leak custody.
     * Zero-length tombstones remain so recovery never deletes a pathname that a
     * same-UID process could swap.
     */
    fun recoverStale(filesDir: File, currentDirectory: File): Boolean {
        val filesDirBound = try {
            bindDirectory(filesDir, requireOwnerOnly = false)
        } catch (_: Throwable) {
            return false
        }
        try {
            return recoverStaleFromHeld(filesDirBound, currentDirectory)
        } finally {
            closeDirFd(filesDirBound)
        }
    }

    /**
     * Removes the generation-scoped plaintext files after the engine has
     * acknowledged Create and loaded them into its private process memory.
     *
     * Every child inode recorded by [writeTo] is truncated and synchronized
     * through the descriptor retained at exclusive creation. Unknown children,
     * a symlink at the bound path, a rename plus replacement, a hard link, and a
     * same-UID parent-directory swap cannot redirect erasure or cause an
     * attacker-substituted pathname to be deleted.
     */
    fun destroy(directory: File): Boolean {
        val bound = synchronized(boundLock) {
            boundDirectories[directory.absolutePath]
        }
        if (bound == null) {
            return try {
                !directoryExistsNoFollow(directory)
            } catch (_: IOException) {
                false
            }
        }
        val complete = destroyBound(bound)
        if (complete) {
            synchronized(boundLock) {
                if (boundDirectories[directory.absolutePath] === bound) {
                    boundDirectories.remove(directory.absolutePath)
                }
            }
        }
        return complete
    }

    /** Key names and paths only. Never a value. */
    fun describeForLog(): String =
        "winn3 keys: version=$VERSION role=$ROLE_CLIENT gateway_id=<set> " +
            "static_path=<written> gateway_static_path=<written> admission_path=<written> " +
            "dual_auth=<${dualAuthEd25519Hex != null}> " +
            "fast_pq=false rekey_after_messages=0"

    private fun rememberBound(bound: BoundDirectory) {
        synchronized(boundLock) {
            val previous = boundDirectories.put(bound.directory.absolutePath, bound)
            if (previous != null && previous !== bound) {
                if (!destroyBoundWithRetry(previous)) {
                    releaseBound(previous)
                }
            }
        }
    }

    private fun writeSecret(bound: BoundDirectory, name: String, bytes: ByteArray): File {
        if (name !in MATERIAL_FILE_NAMES) {
            throw IOException("Refusing to write unexpected Winn v3 key name")
        }
        refuseRelativeName(name)
        refuseSymlink(
            bound.directory,
            "Refusing to write into a symbolic link directory: ${bound.directory.absolutePath}",
        )
        if (!directoryIdentityMatches(bound)) {
            throw IOException(
                "Winn v3 key directory identity changed before writing $name"
            )
        }
        val file = File(bound.directory, name)
        val child = if (nativeDirOpsAvailable()) {
            nativeCreateExclusive(bound, name, bytes)
        } else {
            nioCreateExclusive(bound.directory, name, bytes)
        }
        bound.children[name] = child
        return file
    }

    private fun bindDirectory(
        directory: File,
        requireOwnerOnly: Boolean = true,
    ): BoundDirectory {
        return if (nativeDirOpsAvailable()) {
            nativeBindDirectory(directory, requireOwnerOnly)
        } else {
            nioBindDirectory(directory, requireOwnerOnly)
        }
    }

    private fun recoverStaleFromHeld(
        filesDirBound: BoundDirectory,
        currentDirectory: File,
    ): Boolean {
        if (!heldDirectoryStillMatches(filesDirBound)) return false
        val names = try {
            heldDirectoryNames(filesDirBound)
        } catch (_: Throwable) {
            return false
        }
        if (!heldDirectoryStillMatches(filesDirBound)) return false
        val currentName = currentDirectory.name
        for (name in names.sorted()) {
            if (name == currentName) continue
            if (!STALE_DIRECTORY_NAME.matches(name)) continue
            val bound = try {
                bindStaleCandidate(filesDirBound, name)
            } catch (_: Throwable) {
                return false
            }
            val loaded = try {
                bindStaleChildren(bound)
            } catch (_: Throwable) {
                false
            }
            if (!loaded || !destroyBoundWithRetry(bound)) {
                releaseBound(bound)
                return false
            }
        }
        return try {
            !heldHasLeftoverPlaintext(filesDirBound, currentName)
        } catch (_: Throwable) {
            false
        }
    }

    private fun bindStaleCandidate(parent: BoundDirectory, name: String): BoundDirectory {
        return if (nativeDirOpsAvailable()) {
            nativeBindStaleDirectory(parent, name)
        } else {
            nioBindStaleDirectory(parent, name)
        }
    }

    private fun bindStaleChildren(bound: BoundDirectory): Boolean {
        val names = heldDirectoryNames(bound)
        if (!MATERIAL_FILE_NAMES.containsAll(names)) return false
        for (name in names.sorted()) {
            val child = if (nativeDirOpsAvailable()) {
                nativeBindStaleChild(bound, name)
            } else {
                nioBindStaleChild(bound.directory, name)
            }
            bound.children[name] = child
        }
        return true
    }

    private fun heldDirectoryNames(bound: BoundDirectory): Set<String> {
        return if (nativeDirOpsAvailable()) {
            nativeHeldDirectoryNames(bound)
        } else {
            nioHeldDirectoryNames(bound)
        }
    }

    private fun heldDirectoryStillMatches(bound: BoundDirectory): Boolean {
        val dirFd = bound.dirFd
        if (dirFd != null) {
            return try {
                directoryStatMatches(
                    Os.fstat(dirFd),
                    bound.identity,
                    bound.requireOwnerOnly,
                )
            } catch (_: Throwable) {
                false
            }
        }
        return try {
            !isSymlink(bound.directory) &&
                liveDirectoryIdentity(bound.directory) == bound.identity
        } catch (_: Throwable) {
            false
        }
    }

    private fun destroyBoundWithRetry(bound: BoundDirectory): Boolean {
        if (destroyBound(bound)) return true
        return destroyBound(bound)
    }

    private fun releaseBound(bound: BoundDirectory) {
        destroyBound(bound)
        closeChildFds(bound)
        closeDirFd(bound)
        synchronized(boundLock) {
            if (boundDirectories[bound.directory.absolutePath] === bound) {
                boundDirectories.remove(bound.directory.absolutePath)
            }
        }
    }

    private fun heldHasLeftoverPlaintext(
        filesDirBound: BoundDirectory,
        currentName: String,
    ): Boolean {
        if (!heldDirectoryStillMatches(filesDirBound)) return true
        val names = heldDirectoryNames(filesDirBound)
        for (name in names.sorted()) {
            if (name == currentName) continue
            val leftover = if (nativeDirOpsAvailable()) {
                nativeEntryHasPlaintext(filesDirBound, name)
            } else {
                nioEntryHasPlaintext(filesDirBound, name)
            }
            if (leftover) return true
        }
        return false
    }

    private fun destroyBound(bound: BoundDirectory): Boolean {
        var complete = true
        for (child in bound.children.values) {
            if (!eraseBoundChild(child)) {
                complete = false
            }
        }
        if (complete) {
            closeChildFds(bound)
            closeDirFd(bound)
        }
        return complete
    }

    private fun eraseBoundChild(child: BoundChild): Boolean =
        child.fd?.let { nativeEraseHeldFile(it, child.identity) }
            ?: child.channel?.let { nioEraseHeldFile(it) }
            ?: false

    private fun directoryIdentityMatches(bound: BoundDirectory): Boolean {
        if (isSymlink(bound.directory)) return false
        val live = liveDirectoryIdentity(bound.directory)
        if (live != bound.identity) return false
        val dirFd = bound.dirFd
        if (dirFd != null) {
            val held = try {
                Os.fstat(dirFd)
            } catch (_: Throwable) {
                return false
            }
            if (!directoryStatMatches(
                    held,
                    bound.identity,
                    bound.requireOwnerOnly,
                )
            ) return false
        }
        return true
    }

    private fun liveDirectoryIdentity(directory: File): FileIdentity {
        return if (nativeDirOpsAvailable()) {
            nativeLstatIdentity(directory, expectDirectory = true)
        } else {
            nioIdentity(directory, expectDirectory = true)
        }
    }

    private fun directoryExistsNoFollow(directory: File): Boolean {
        return try {
            if (isSymlink(directory)) true else directory.exists()
        } catch (thrown: IOException) {
            throw thrown
        }
    }

    private fun jsonString(value: String): String = buildString {
        append('"')
        for (ch in value) {
            when (ch) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
            }
        }
        append('"')
    }

    private fun restrictToOwner(file: File, executable: Boolean) {
        try {
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
            if (executable) {
                file.setExecutable(true, true)
            }
        } catch (thrown: Throwable) {
            throw IOException(
                "Could not restrict Winn v3 key path to owner-only: ${file.absolutePath}",
                thrown,
            )
        }
        if (!isOwnerOnly(file)) {
            throw IOException(
                "Could not restrict Winn v3 key path to owner-only: ${file.absolutePath}"
            )
        }
    }

    /**
     * Whether [file] is a symbolic link. The production app has minSdk 26, so
     * `java.nio.file.Files` exists on every supported device. The lstat branch
     * remains for direct unit coverage of the legacy SDK path. Both inspect the final path
     * component only; a symlink in a parent (e.g. /data/data -> /data/user/0)
     * does not count. Inspection failures fail closed rather than pretending
     * the path is a regular file.
     */
    private fun isSymlink(file: File): Boolean =
        isSymlinkFor(android.os.Build.VERSION.SDK_INT, file)

    internal fun isSymlinkFor(sdkInt: Int, file: File): Boolean {
        if (sdkInt >= android.os.Build.VERSION_CODES.O) {
            @android.annotation.SuppressLint("NewApi")
            return nioIsSymlink(file)
        }
        if (sdkInt == 0) {
            @android.annotation.SuppressLint("NewApi")
            return nioIsSymlink(file)
        }
        return statIsSymlink(file)
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioIsSymlink(file: File): Boolean {
        return try {
            java.nio.file.Files.isSymbolicLink(file.toPath())
        } catch (thrown: java.nio.file.NoSuchFileException) {
            false
        } catch (thrown: Throwable) {
            throw IOException(
                "Winn v3 key path could not be checked for a symbolic link: ${file.absolutePath}",
                thrown,
            )
        }
    }

    private fun statIsSymlink(file: File): Boolean {
        return try {
            val st = Os.lstat(file.absolutePath)
            @Suppress("DEPRECATION")
            (st.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFLNK
        } catch (thrown: ErrnoException) {
            if (thrown.errno == OsConstants.ENOENT) return false
            throw IOException(
                "Winn v3 key path could not be checked for a symbolic link: ${file.absolutePath}",
                thrown,
            )
        } catch (thrown: Throwable) {
            throw IOException(
                "Winn v3 key path could not be checked for a symbolic link: ${file.absolutePath}",
                thrown,
            )
        }
    }

    /**
     * Whether [file] is owner-only (no group/other permission). When the mode
     * cannot be read the answer is false: a key file we cannot prove is
     * owner-only is refused rather than handed to the engine.
     */
    private fun isOwnerOnly(file: File): Boolean {
        val mode = posixModeOrNull(file) ?: return false
        return mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS == 0
    }

    private fun posixModeOrNull(file: File): Int? =
        posixModeOrNullFor(android.os.Build.VERSION.SDK_INT, file)

    internal fun posixModeOrNullFor(sdkInt: Int, file: File): Int? {
        if (sdkInt >= android.os.Build.VERSION_CODES.O) {
            @android.annotation.SuppressLint("NewApi")
            val m = nioPosixModeOrNull(file)
            return m
        }
        if (sdkInt > 0) {
            return statPosixModeOrNull(file)
        }
        @android.annotation.SuppressLint("NewApi")
        val offDevice = nioPosixModeOrNull(file)
        return offDevice
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioPosixModeOrNull(file: File): Int? {
        return try {
            val permissions = java.nio.file.Files.getPosixFilePermissions(file.toPath())
            var mode = 0
            for (permission in permissions) {
                val bit = when (permission.name) {
                    "OWNER_READ" -> 0b100_000_000
                    "OWNER_WRITE" -> 0b010_000_000
                    "OWNER_EXECUTE" -> 0b001_000_000
                    "GROUP_READ" -> 0b000_100_000
                    "GROUP_WRITE" -> 0b000_010_000
                    "GROUP_EXECUTE" -> 0b000_001_000
                    "OTHERS_READ" -> 0b000_000_100
                    "OTHERS_WRITE" -> 0b000_000_010
                    "OTHERS_EXECUTE" -> 0b000_000_001
                    else -> return null
                }
                mode = mode or bit
            }
            mode
        } catch (_: Throwable) {
            null
        }
    }

    private fun statPosixModeOrNull(file: File): Int? {
        return try {
            Os.lstat(file.absolutePath).st_mode and 0b111_111_111
        } catch (_: Throwable) {
            null
        }
    }

    @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.R)
    private fun nativeDirOpsAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    @RequiresApi(Build.VERSION_CODES.R)
    private fun nativeBindDirectory(
        directory: File,
        requireOwnerOnly: Boolean,
    ): BoundDirectory {
        refuseRelativeName(directory.name)
        val flags = OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC
        val fd = try {
            Os.open(directory.absolutePath, flags, 0)
        } catch (thrown: Throwable) {
            throw IOException(
                "Could not open Winn v3 key directory without following links: ${directory.absolutePath}",
                thrown,
            )
        }
        var parentFd: FileDescriptor? = null
        var transferred = false
        try {
            val st = Os.fstat(fd)
            refuseUnsafeDirectoryStat(st, directory, requireOwnerOnly)
            val parent = directory.absoluteFile.parentFile
                ?: throw IOException(
                    "Winn v3 key directory has no parent: ${directory.absolutePath}"
                )
            parentFd = try {
                Os.open(parent.absolutePath, flags, 0)
            } catch (thrown: Throwable) {
                throw IOException(
                    "Could not open Winn v3 key parent directory without following links: ${parent.absolutePath}",
                    thrown,
                )
            }
            val openedParent = parentFd
                ?: throw IOException(
                    "Winn v3 key parent directory has no held descriptor: ${parent.absolutePath}"
                )
            val parentSt = Os.fstat(openedParent)
            if ((parentSt.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFDIR) {
                throw IOException(
                    "Winn v3 key parent path is not a directory: ${parent.absolutePath}"
                )
            }
            if (parentSt.st_uid != Os.getuid()) {
                throw IOException(
                    "Refusing to use a Winn v3 key parent directory with a foreign owner: ${parent.absolutePath}"
                )
            }
            val viaParent = openHeld(openedParent, directory.name, flags, 0)
            try {
                val viaSt = Os.fstat(viaParent)
                if (FileIdentity(viaSt.st_dev, viaSt.st_ino) != FileIdentity(st.st_dev, st.st_ino)) {
                    throw IOException(
                        "Winn v3 key directory identity does not match its parent lookup"
                    )
                }
            } finally {
                closeFdQuietly(viaParent)
            }
            val bound = BoundDirectory(
                directory = directory,
                identity = FileIdentity(st.st_dev, st.st_ino),
                dirFd = fd,
                parentFd = parentFd,
                dirName = directory.name,
                requireOwnerOnly = requireOwnerOnly,
            )
            transferred = true
            return bound
        } catch (thrown: Throwable) {
            if (thrown is IOException) throw thrown
            throw IOException(
                "Could not bind Winn v3 key directory: ${directory.absolutePath}",
                thrown,
            )
        } finally {
            if (!transferred) {
                closeFdQuietly(fd)
                parentFd?.let { closeFdQuietly(it) }
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun nativeBindStaleDirectory(parent: BoundDirectory, name: String): BoundDirectory {
        refuseRelativeName(name)
        val parentFd = parent.dirFd
            ?: throw IOException("Winn v3 filesDir has no held descriptor")
        if (!heldDirectoryStillMatches(parent)) {
            throw IOException("Winn v3 filesDir identity changed during stale recovery")
        }
        val flags = OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC
        val fd = openHeld(parentFd, name, flags, 0)
        var transferred = false
        try {
            val st = Os.fstat(fd)
            refuseUnsafeDirectoryStat(st, File(parent.directory, name))
            transferred = true
            return BoundDirectory(
                directory = File(parent.directory, name),
                identity = FileIdentity(st.st_dev, st.st_ino),
                dirFd = fd,
                parentFd = null,
                dirName = name,
            )
        } catch (thrown: Throwable) {
            if (thrown is IOException) throw thrown
            throw IOException("Could not bind a Winn v3 stale key directory", thrown)
        } finally {
            if (!transferred) closeFdQuietly(fd)
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun nativeCreateExclusive(
        bound: BoundDirectory,
        name: String,
        bytes: ByteArray,
    ): BoundChild {
        refuseRelativeName(name)
        if (!directoryIdentityMatches(bound)) {
            throw IOException("Winn v3 key directory identity changed before writing $name")
        }
        val dirFd = bound.dirFd
            ?: throw IOException("Winn v3 key directory has no held descriptor")
        val flags = OsConstants.O_RDWR or OsConstants.O_CREAT or OsConstants.O_EXCL or
            OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC
        val fd = try {
            openHeld(dirFd, name, flags, OWNER_FILE_MODE)
        } catch (thrown: Throwable) {
            throw IOException("Winn v3 key file $name could not be created exclusively", thrown)
        }
        var transferred = false
        try {
            Os.fchmod(fd, OWNER_FILE_MODE)
            val created = Os.fstat(fd)
            refuseUnsafeFileStat(created, name)
            val child = BoundChild(FileIdentity(created.st_dev, created.st_ino), fd, null)
            // Register custody before the first secret byte is written. Any
            // later short write or validation failure is then retried through
            // the same held descriptor by writeTo's rollback path.
            bound.children[name] = child
            transferred = true
            val buffer = java.nio.ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) {
                val wrote = Os.write(fd, buffer)
                if (wrote <= 0) {
                    throw IOException("Winn v3 key write of $name returned $wrote")
                }
            }
            val st = Os.fstat(fd)
            refuseUnsafeFileStat(st, name)
            if (!directoryIdentityMatches(bound)) {
                throw IOException("Winn v3 key directory identity changed while writing $name")
            }
            return child
        } catch (thrown: Throwable) {
            try {
                Os.ftruncate(fd, 0)
                Os.fsync(fd)
            } catch (_: Throwable) {
            }
            if (thrown is IOException) throw thrown
            throw IOException("Winn v3 key write of $name failed", thrown)
        } finally {
            if (!transferred) closeFdQuietly(fd)
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun nativeHeldDirectoryNames(bound: BoundDirectory): Set<String> {
        val dirFd = bound.dirFd
            ?: throw IOException("Winn v3 stale key directory has no held descriptor")
        val duplicate = duplicateCloexec(dirFd)
        try {
            val listed = File("/proc/self/fd/${duplicate.fd}").list()
                ?: throw IOException("Could not list a held Winn v3 stale key directory")
            return listedNames(listed)
        } finally {
            closePfdQuietly(duplicate)
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun nativeEntryHasPlaintext(parent: BoundDirectory, name: String): Boolean {
        refuseRelativeName(name)
        val parentFd = parent.dirFd
            ?: throw IOException("Winn v3 filesDir has no held descriptor")
        val fd = openHeld(
            parentFd,
            name,
            OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
            0,
        )
        try {
            val st = Os.fstat(fd)
            val type = st.st_mode and OsConstants.S_IFMT
            if (type == OsConstants.S_IFREG) {
                return name in MATERIAL_FILE_NAMES && st.st_size > 0L
            }
            if (type != OsConstants.S_IFDIR) return false
            val duplicate = duplicateCloexec(fd)
            val childNames = try {
                listedNames(
                    File("/proc/self/fd/${duplicate.fd}").list()
                        ?: throw IOException("Could not list a held Winn v3 directory entry"),
                )
            } finally {
                closePfdQuietly(duplicate)
            }
            var materialPlaintext = false
            for (childName in childNames) {
                if (childName !in MATERIAL_FILE_NAMES) continue
                val childFd = openHeld(
                    fd,
                    childName,
                    OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                    0,
                )
                try {
                    val childSt = Os.fstat(childFd)
                    if ((childSt.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFREG &&
                        childSt.st_size > 0L
                    ) {
                        materialPlaintext = true
                        break
                    }
                } finally {
                    closeFdQuietly(childFd)
                }
            }
            if (!materialPlaintext) return false
            return STALE_DIRECTORY_NAME.matches(name) ||
                MATERIAL_FILE_NAMES.containsAll(childNames)
        } finally {
            closeFdQuietly(fd)
        }
    }

    private fun listedNames(listed: Array<String>): Set<String> =
        listed.filter { it != "." && it != ".." }.toSet()

    @RequiresApi(Build.VERSION_CODES.R)
    private fun nativeBindStaleChild(bound: BoundDirectory, name: String): BoundChild {
        refuseRelativeName(name)
        val dirFd = bound.dirFd
            ?: throw IOException("Winn v3 stale key directory has no held descriptor")
        val fd = openHeld(
            dirFd,
            name,
            OsConstants.O_RDWR or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
            0,
        )
        var transferred = false
        try {
            val st = Os.fstat(fd)
            if ((st.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFREG ||
                (st.st_mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS) != 0 ||
                st.st_uid != Os.getuid() || st.st_nlink < 1L
            ) {
                throw IOException("Refusing unsafe Winn v3 stale key material")
            }
            transferred = true
            return BoundChild(FileIdentity(st.st_dev, st.st_ino), fd, null)
        } finally {
            if (!transferred) closeFdQuietly(fd)
        }
    }

    private fun nativeEraseHeldFile(fd: FileDescriptor, identity: FileIdentity): Boolean {
        return try {
            val before = Os.fstat(fd)
            if (!regularFileStatMatches(before, identity)) return false
            Os.ftruncate(fd, 0L)
            Os.fsync(fd)
            val after = Os.fstat(fd)
            regularFileStatMatches(after, identity) && after.st_size == 0L
        } catch (_: Throwable) {
            false
        }
    }

    private fun nativeLstatIdentity(file: File, expectDirectory: Boolean): FileIdentity {
        val st = try {
            Os.lstat(file.absolutePath)
        } catch (thrown: Throwable) {
            throw IOException("Could not inspect ${file.absolutePath}", thrown)
        }
        val type = st.st_mode and OsConstants.S_IFMT
        if (type == OsConstants.S_IFLNK) {
            throw IOException("Winn v3 key path is a symbolic link: ${file.absolutePath}")
        }
        if (expectDirectory && type != OsConstants.S_IFDIR) {
            throw IOException("Winn v3 key path is not a directory: ${file.absolutePath}")
        }
        if (!expectDirectory && type != OsConstants.S_IFREG) {
            throw IOException("Winn v3 key path is not a regular file: ${file.absolutePath}")
        }
        if (st.st_uid != Os.getuid()) {
            throw IOException(
                "Refusing to use a Winn v3 key path with a foreign owner: ${file.absolutePath}"
            )
        }
        if ((st.st_mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS) != 0) {
            throw IOException(
                "Refusing to use a Winn v3 key path that is not owner-only: ${file.absolutePath}"
            )
        }
        if (!expectDirectory && st.st_nlink != 1L) {
            throw IOException(
                "Refusing to use a Winn v3 key path that is not a single-link regular file: ${file.absolutePath}"
            )
        }
        if (expectDirectory && st.st_nlink < 1L) {
            throw IOException(
                "Refusing to use a Winn v3 key directory with an impossible link count: ${file.absolutePath}"
            )
        }
        return FileIdentity(st.st_dev, st.st_ino)
    }

    private fun closeDirFd(bound: BoundDirectory) {
        val fd = bound.dirFd
        bound.dirFd = null
        if (fd != null) closeFdQuietly(fd)
        val parent = bound.parentFd
        bound.parentFd = null
        if (parent != null) closeFdQuietly(parent)
    }

    private fun closeChildFd(child: BoundChild) {
        val fd = child.fd
        child.fd = null
        if (fd != null) closeFdQuietly(fd)
        val channel = child.channel
        child.channel = null
        if (channel != null) {
            try {
                channel.close()
            } catch (_: Throwable) {
            }
        }
    }

    private fun closeChildFds(bound: BoundDirectory) {
        for (child in bound.children.values) {
            closeChildFd(child)
        }
    }

    private fun closeFdQuietly(fd: FileDescriptor) {
        try {
            Os.close(fd)
        } catch (_: Throwable) {
        }
    }

    private fun closePfdQuietly(pfd: ParcelFileDescriptor) {
        try {
            pfd.close()
        } catch (_: Throwable) {
        }
    }

    private fun refuseRelativeName(name: String) {
        if (name.isEmpty() || name == "." || name == ".." ||
            name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 ||
            name.indexOf('\u0000') >= 0
        ) {
            throw IOException("Refusing to write unexpected Winn v3 key name")
        }
    }

    /**
     * Create or open a child of a held directory. Public Android `Os` has no
     * `openat`; `/proc/self/fd/<dirfd>/<name>` is the
     * descriptor-relative lookup that keeps the held inode across a same-UID
     * parent rename.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    private fun openHeld(
        dirFd: FileDescriptor,
        name: String,
        flags: Int,
        mode: Int,
    ): FileDescriptor {
        refuseRelativeName(name)
        val pfd = duplicateCloexec(dirFd)
        try {
            return Os.open("/proc/self/fd/${pfd.fd}/$name", flags, mode)
        } finally {
            closePfdQuietly(pfd)
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun duplicateCloexec(fd: FileDescriptor): ParcelFileDescriptor {
        val duplicate = Os.fcntlInt(fd, OsConstants.F_DUPFD_CLOEXEC, 0)
        return ParcelFileDescriptor.adoptFd(duplicate)
    }

    private fun refuseUnsafeDirectoryStat(
        st: StructStat,
        directory: File,
        requireOwnerOnly: Boolean = true,
    ) {
        if ((st.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFDIR) {
            throw IOException("Winn v3 key path is not a directory: ${directory.absolutePath}")
        }
        if (requireOwnerOnly &&
            (st.st_mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS) != 0
        ) {
            throw IOException(
                "Refusing to use a Winn v3 key directory that is not owner-only: ${directory.absolutePath}"
            )
        }
        if (st.st_uid != Os.getuid()) {
            throw IOException(
                "Refusing to use a Winn v3 key directory with a foreign owner: ${directory.absolutePath}"
            )
        }
        if (st.st_nlink < 1L) {
            throw IOException(
                "Refusing to use a Winn v3 key directory with an impossible link count: ${directory.absolutePath}"
            )
        }
    }

    private fun refuseUnsafeFileStat(st: StructStat, name: String) {
        if ((st.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFREG) {
            throw IOException("Newly created key file $name is not a regular file")
        }
        if ((st.st_mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS) != 0) {
            throw IOException("Refusing to hand the engine a key file that is not owner-only")
        }
        if (st.st_uid != Os.getuid()) {
            throw IOException("Refusing to hand the engine a key file with a foreign owner")
        }
        if (st.st_nlink != 1L) {
            throw IOException(
                "Refusing to hand the engine a key file that is not a single-link regular file"
            )
        }
    }

    private fun directoryStatMatches(
        st: StructStat,
        expected: FileIdentity,
        requireOwnerOnly: Boolean,
    ): Boolean {
        if ((st.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFDIR) return false
        if (requireOwnerOnly &&
            (st.st_mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS) != 0
        ) return false
        if (st.st_uid != Os.getuid()) return false
        if (st.st_nlink < 1L) return false
        return FileIdentity(st.st_dev, st.st_ino) == expected
    }

    private fun regularFileStatMatches(st: StructStat, expected: FileIdentity): Boolean {
        if ((st.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFREG) return false
        if ((st.st_mode and WinnCarrierProfile.GROUP_AND_OTHER_BITS) != 0) return false
        if (st.st_uid != Os.getuid()) return false
        return FileIdentity(st.st_dev, st.st_ino) == expected
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioBindDirectory(
        directory: File,
        requireOwnerOnly: Boolean,
    ): BoundDirectory {
        if (nioIsSymlink(directory)) {
            throw IOException(
                "Refusing to write Winn v3 keys into a symbolic link directory: ${directory.absolutePath}"
            )
        }
        val path = directory.toPath()
        val isDir = try {
            java.nio.file.Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        } catch (thrown: Throwable) {
            throw IOException(
                "Winn v3 key path could not be checked as a directory: ${directory.absolutePath}",
                thrown,
            )
        }
        if (!isDir) {
            throw IOException("Winn v3 key path is not a directory: ${directory.absolutePath}")
        }
        if (requireOwnerOnly && !isOwnerOnly(directory)) {
            throw IOException(
                "Refusing to use a Winn v3 key directory that is not owner-only: ${directory.absolutePath}"
            )
        }
        return BoundDirectory(
            directory = directory,
            identity = nioIdentity(directory, expectDirectory = true),
            dirFd = null,
            requireOwnerOnly = requireOwnerOnly,
        )
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioBindStaleDirectory(parent: BoundDirectory, name: String): BoundDirectory {
        refuseRelativeName(name)
        if (!heldDirectoryStillMatches(parent)) {
            throw IOException("Winn v3 filesDir identity changed during stale recovery")
        }
        val directory = File(parent.directory, name)
        val bound = nioBindDirectory(directory, requireOwnerOnly = true)
        if (!heldDirectoryStillMatches(parent)) {
            throw IOException("Winn v3 filesDir identity changed while binding $name")
        }
        return bound
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioHeldDirectoryNames(bound: BoundDirectory): Set<String> {
        if (!heldDirectoryStillMatches(bound)) {
            throw IOException("Winn v3 key directory identity changed during stale recovery")
        }
        val listed = bound.directory.list()
            ?: throw IOException("Could not list a held Winn v3 stale key directory")
        return listedNames(listed)
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioEntryHasPlaintext(parent: BoundDirectory, name: String): Boolean {
        refuseRelativeName(name)
        val child = File(parent.directory, name)
        if (isSymlink(child)) return true
        if (child.isFile) {
            return name in MATERIAL_FILE_NAMES && child.length() > 0L
        }
        if (!child.isDirectory) return false
        val childNames = child.list() ?: return true
        val listed = listedNames(childNames)
        var materialPlaintext = false
        for (childName in listed) {
            if (childName !in MATERIAL_FILE_NAMES) continue
            val material = File(child, childName)
            if (isSymlink(material)) return true
            if (material.isFile && material.length() > 0L) materialPlaintext = true
        }
        if (!materialPlaintext) return false
        return STALE_DIRECTORY_NAME.matches(name) ||
            MATERIAL_FILE_NAMES.containsAll(listed)
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioCreateExclusive(directory: File, name: String, bytes: ByteArray): BoundChild {
        val file = File(directory, name)
        val path = file.toPath()
        val options = hashSetOf<java.nio.file.OpenOption>(
            java.nio.file.StandardOpenOption.CREATE_NEW,
            java.nio.file.StandardOpenOption.WRITE,
            java.nio.file.LinkOption.NOFOLLOW_LINKS,
        )
        var channel: java.nio.channels.FileChannel? = null
        try {
            channel = java.nio.channels.FileChannel.open(path, options)
            val buffer = java.nio.ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) {
                if (channel.write(buffer) <= 0) {
                    throw IOException("Winn v3 key write of $name returned a short write")
                }
            }
            val view = java.nio.file.Files.getFileAttributeView(
                path,
                java.nio.file.attribute.PosixFileAttributeView::class.java,
                java.nio.file.LinkOption.NOFOLLOW_LINKS,
            ) ?: throw IOException("Winn v3 key file $name has no POSIX view")
            view.setPermissions(
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
            )
            if (nioIsSymlink(file) || !isOwnerOnly(file)) {
                throw IOException(
                    "Refusing to hand the engine a key file that is not owner-only: ${file.absolutePath}"
                )
            }
            if (nioUnixLong(path, "unix:nlink") != 1L) {
                throw IOException(
                    "Refusing to hand the engine a key file that is not a single-link regular file"
                )
            }
            if (nioUnixLong(path, "unix:uid") != nioUnixLong(directory.toPath(), "unix:uid")) {
                throw IOException("Refusing to hand the engine a key file with a foreign owner")
            }
            val child = BoundChild(
                nioIdentity(file, expectDirectory = false),
                null,
                channel,
            )
            channel = null
            return child
        } catch (thrown: Throwable) {
            try {
                channel?.truncate(0L)
                channel?.force(true)
            } catch (_: Throwable) {
            } finally {
                try {
                    channel?.close()
                } catch (_: Throwable) {
                }
            }
            if (thrown is IOException) throw thrown
            throw IOException("Winn v3 key file $name could not be created exclusively", thrown)
        }
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioBindStaleChild(directory: File, name: String): BoundChild {
        refuseRelativeName(name)
        val file = File(directory, name)
        val path = file.toPath()
        val channel = java.nio.channels.FileChannel.open(
            path,
            setOf<java.nio.file.OpenOption>(
                java.nio.file.StandardOpenOption.READ,
                java.nio.file.StandardOpenOption.WRITE,
                java.nio.file.LinkOption.NOFOLLOW_LINKS,
            ),
        )
        var transferred = false
        try {
            if (nioIsSymlink(file) || !java.nio.file.Files.isRegularFile(
                    path,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ) || !isOwnerOnly(file) || nioUnixLong(path, "unix:nlink") < 1L
            ) {
                throw IOException("Refusing unsafe Winn v3 stale key material")
            }
            val identity = FileIdentity(
                nioUnixLong(path, "unix:dev"),
                nioUnixLong(path, "unix:ino"),
            )
            transferred = true
            return BoundChild(identity, null, channel)
        } finally {
            if (!transferred) channel.close()
        }
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioEraseHeldFile(channel: java.nio.channels.FileChannel): Boolean {
        return try {
            channel.truncate(0L)
            channel.force(true)
            channel.size() == 0L
        } catch (_: Throwable) {
            false
        }
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioIdentity(file: File, expectDirectory: Boolean): FileIdentity {
        val path = file.toPath()
        val attrs = try {
            java.nio.file.Files.readAttributes(
                path,
                java.nio.file.attribute.BasicFileAttributes::class.java,
                java.nio.file.LinkOption.NOFOLLOW_LINKS,
            )
        } catch (thrown: Throwable) {
            if (thrown is java.nio.file.NoSuchFileException) throw thrown
            throw IOException("Could not inspect ${file.absolutePath}", thrown)
        }
        if (attrs.isSymbolicLink) {
            throw IOException("Winn v3 key path is a symbolic link: ${file.absolutePath}")
        }
        if (expectDirectory && !attrs.isDirectory) {
            throw IOException("Winn v3 key path is not a directory: ${file.absolutePath}")
        }
        if (!expectDirectory && !attrs.isRegularFile) {
            throw IOException("Winn v3 key path is not a regular file: ${file.absolutePath}")
        }
        if (!expectDirectory && nioUnixLong(path, "unix:nlink") != 1L) {
            throw IOException(
                "Winn v3 key path is not a single-link regular file: ${file.absolutePath}"
            )
        }
        if (expectDirectory && nioUnixLong(path, "unix:nlink") < 1L) {
            throw IOException(
                "Winn v3 key directory has an impossible link count: ${file.absolutePath}"
            )
        }
        return FileIdentity(nioUnixLong(path, "unix:dev"), nioUnixLong(path, "unix:ino"))
    }

    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.O)
    private fun nioUnixLong(path: java.nio.file.Path, attribute: String): Long {
        val value = try {
            java.nio.file.Files.getAttribute(
                path,
                attribute,
                java.nio.file.LinkOption.NOFOLLOW_LINKS,
            )
        } catch (thrown: Throwable) {
            throw IOException("Could not read $attribute for $path", thrown)
        }
        return when (value) {
            is Long -> value
            is Int -> value.toLong()
            is Number -> value.toLong()
            else -> throw IOException(
                "Unsupported $attribute type ${value?.javaClass?.name} for $path"
            )
        }
    }

    private fun refuseSymlink(file: File, message: String) {
        if (isSymlink(file)) throw IOException(message)
    }

    private data class FileIdentity(val device: Long, val inode: Long)

    private class BoundChild(
        val identity: FileIdentity,
        var fd: FileDescriptor?,
        var channel: java.nio.channels.FileChannel?,
    )

    private class BoundDirectory(
        val directory: File,
        val identity: FileIdentity,
        var dirFd: FileDescriptor?,
        var parentFd: FileDescriptor? = null,
        val dirName: String = directory.name,
        val requireOwnerOnly: Boolean = true,
        val children: LinkedHashMap<String, BoundChild> = LinkedHashMap(),
    )

    companion object {
        /** `winn3KeysVersion`. The only version the engine accepts. */
        const val VERSION = "winn3-keys/1"

        /** `winn3RoleClient`. A host is always the client. */
        const val ROLE_CLIENT = "client"

        const val DOCUMENT_NAME = "winn3-keys.json"
        private const val DIRECTORY_NAME = "winn3"
        private val STALE_DIRECTORY_NAME = Regex("^winn3-[0-9]+-[1-9][0-9]*$")
        private const val OWNER_FILE_MODE = 0b110_000_000
        private val MATERIAL_FILE_NAMES = setOf(
            DOCUMENT_NAME,
            "static.key",
            "gateway.pub",
            "admission.key",
            "auth_ed25519.pub",
            "auth_mldsa65.pub",
        )

        /** X25519 keys are 32 bytes, and this document carries them as hex. */
        const val KEY_HEX_LENGTH = 64

        // =====================================================================
        // THE SERVED SPELLING. These four names, and these encodings, are the
        // control plane's contract and Apple's, and as of 2026-08-09 they are
        // this host's too.
        // =====================================================================
        //
        // WHAT THEY USED TO BE, AND WHY THAT WAS DANGEROUS RATHER THAN UNTIDY.
        // Until 2026-08-09 this class read `v3_gateway_id`, `v3_static_key`,
        // `v3_gateway_static_key` and `v3_admission_secret`, with the two
        // statics as lowercase HEX and the gateway id as PLAIN TEXT. Nothing
        // emitted those names. `lib/winn_protocol_dispatch.dart` writes the
        // names below and `WinsWinn3SessionStart.swift` reads them, so the hub
        // could serve exactly one of the two spellings and Android was not it :
        // `from` threw NO_KEY_MATERIAL naming four fields no served config has
        // ever contained.
        //
        // That was LOUD, which was luck rather than design. The dangerous
        // neighbour of that state is a section that satisfies the old spelling
        // PARTIALLY: this host took its inner address from the AmneziaWG
        // `clientIp` rather than from `inner_v4`, and the winn/3 tun layer drops
        // every packet whose source does not match its assignment. A session
        // that starts, reports up at both ends and carries nothing is the one
        // failure mode this whole protocol's diagnostics cannot distinguish
        // from a censor.
        //
        // BASE64 RATHER THAN HEX, AND IT IS NOT A PREFERENCE. The values reach
        // a device on an ML-DSA-65-signed descriptor that carries every
        // byte-valued field base64-encoded; the hub validates them that way and
        // refuses anything else with `descriptor-field-not-base64`. A host that
        // wanted hex would have to re-encode, and every re-encoding is one more
        // place two ends can disagree about a value neither ever transmits.
        //
        // It also fixes a whitespace divergence for free, and that one was
        // measured. `cmd/winn3-gateway` keys with `-gateway-id` UNTRIMMED, so an
        // operator name with one trailing space is nine bytes there. The old
        // plain-text `v3_gateway_id` was `.trim()`ed here, giving eight :  iOS
        // connected and Android did not, silently. Base64 moves the trim onto
        // the TRANSPORT TEXT, where it cannot reach the decoded bytes, which is
        // exactly why Apple already agreed with the gateway.
        const val KEY_GATEWAY_ID = "gateway_id"
        const val KEY_STATIC = "static_private"
        const val KEY_GATEWAY_STATIC = "gateway_static"
        const val KEY_ADMISSION = "admission_key"
        const val KEY_AUTH_ED25519 = "auth_ed25519"
        const val KEY_AUTH_MLDSA65 = "auth_mldsa65"

        /** The `[winn]` keys this class consumes. Folded into `V3_KEYS`. */
        val SECTION_KEYS =
            setOf(KEY_GATEWAY_ID, KEY_STATIC, KEY_GATEWAY_STATIC, KEY_ADMISSION,
                KEY_AUTH_ED25519, KEY_AUTH_MLDSA65)

        /** X25519 keys are 32 bytes. `static_private` and `gateway_static`
         *  carry exactly that many, base64-encoded. */
        const val KEY_BYTE_LENGTH = 32

        /** The directory the document and its key files live in. */
        fun keyDirectory(filesDir: File, generation: Int, startToken: Long): File {
            require(generation >= 0) { "tunnel generation must be non-negative" }
            require(startToken > 0L) { "Winn v3 start token must be positive" }
            return File(filesDir, "$DIRECTORY_NAME-$generation-$startToken")
        }

        /**
         * The refusal when a v3 session has no key material.
         *
         * A constant, so a test can assert the gap is reported rather than
         * worked around :  the same shape as [WinnV3Host.NO_V3_ENGINE] and
         * [WinnTunnelBridge.NO_DATAGRAM_SEAM]. Spawning the engine anyway would
         * produce a subprocess that exits 1 with a message only logcat sees,
         * and a tunnel that fails for a reason the host could have named.
         */
        const val NO_KEY_MATERIAL =
            "Refusing to start a Winn Protocol v3 session: the [winn] section carries no v3 key " +
                "material. v3 authenticates with a static X25519 key pair and a gateway " +
                "admission secret, and there is no anonymous mode :  a client authenticates the " +
                "gateway by its static key. The section needs $KEY_GATEWAY_ID, $KEY_STATIC, " +
                "$KEY_GATEWAY_STATIC and $KEY_ADMISSION. Starting a v1 session instead would be " +
                "a silent downgrade of the user's protocol, so this refuses."

        /**
         * Reads the key material from a `[winn]` section, or throws.
         *
         * @throws IllegalArgumentException naming the offending field, never its
         *   value.
         */
        fun from(section: Map<String, String>): WinnV3Keys {
            // Every value is trimmed as TRANSPORT TEXT and never as a secret.
            // Base64 text has no significant leading or trailing whitespace, so
            // this trim cannot reach a decoded byte :  which is the entire
            // reason the encoding was chosen over hex and plain text. See the
            // constants above.
            val gatewayIdBase64 = section[KEY_GATEWAY_ID]?.trim().orEmpty()
            val staticBase64 = section[KEY_STATIC]?.trim().orEmpty()
            val gatewayStaticBase64 = section[KEY_GATEWAY_STATIC]?.trim().orEmpty()
            val admissionBase64 = section[KEY_ADMISSION]?.trim().orEmpty()

            require(
                gatewayIdBase64.isNotEmpty() || staticBase64.isNotEmpty() ||
                    gatewayStaticBase64.isNotEmpty() || admissionBase64.isNotEmpty()
            ) { NO_KEY_MATERIAL }

            require(gatewayIdBase64.isNotEmpty()) {
                "Winn $KEY_GATEWAY_ID is empty: without it an initiation captured at one " +
                    "gateway replays at another that shares the admission key"
            }
            // THE DESCRIPTOR BOUNDARY, AND THE ONLY DECODE OF THIS FIELD.
            //
            // `gateway_id` is an authenticated input to the admission tag and is
            // NEVER TRANSMITTED, so the two ends never discover that they
            // disagree about it. The engine is handed the operator's own gateway
            // NAME :  byte for byte what `cmd/winn3-gateway -gateway-id` was
            // given :  and the signed descriptor carries that name base64. So the
            // encoding comes off here, once, and `writeTo` puts the decoded text
            // in the key document verbatim.
            //
            // Decoding twice is not a loud mistake: `winsgw01` is eight
            // characters of the base64 alphabet, so a second decode yields six
            // plausible bytes, a tag the gateway cannot verify, and the silence
            // a v3 gateway answers every unauthenticated datagram with.
            val gatewayIdBytes = decodeBase64(gatewayIdBase64)
            require(gatewayIdBytes != null && gatewayIdBytes.isNotEmpty()) {
                "Winn $KEY_GATEWAY_ID is not usable: the signed descriptor carries it " +
                    "base64-encoded over the operator's gateway name, and this value does not " +
                    "decode to one. The engine is handed the decoded name, byte for byte what " +
                    "the gateway itself is configured with, because the admission tag is " +
                    "computed over it and is never transmitted"
            }
            val gatewayId = String(gatewayIdBytes, Charsets.UTF_8)
            require(gatewayId.isNotEmpty() && gatewayId.toByteArray(Charsets.UTF_8)
                    .contentEquals(gatewayIdBytes)
            ) {
                "Winn $KEY_GATEWAY_ID does not decode to text. It names a gateway an operator " +
                    "typed, and a value that is not text is one no gateway was ever configured with"
            }

            val staticKey = decodeX25519(staticBase64, KEY_STATIC, isPrivate = true)
            val gatewayStatic = decodeX25519(gatewayStaticBase64, KEY_GATEWAY_STATIC, isPrivate = false)

            require(admissionBase64.isNotEmpty()) {
                "Winn $KEY_ADMISSION is empty: the admission secret is what the initiation's tag " +
                    "is derived from"
            }
            // OPAQUE, AND THE TRANSPORT ENCODING IS THE ONLY THING REMOVED.
            //
            // What is underneath is the key FILE'S BYTES :  keygen's 64 ASCII hex
            // characters :  and they are never hex-decoded. Decoding them keys 32
            // bytes against the gateway's 64: the datagram passes the size
            // pre-filter, a session is BUILT, and the gateway then answers
            // nothing at all.
            // Dual-signature attestation keys: OPTIONAL AS A PAIR, decoded at
            // the descriptor boundary exactly once. Written as lowercase hex,
            // the encoding winn-datapath's readDualAuthPublic decodes.
            val authEd25519B64 = section[KEY_AUTH_ED25519]?.trim().orEmpty()
            val authMldsa65B64 = section[KEY_AUTH_MLDSA65]?.trim().orEmpty()
            require(authEd25519B64.isEmpty() == authMldsa65B64.isEmpty()) {
                "Winn $KEY_AUTH_ED25519 and $KEY_AUTH_MLDSA65 are the optional pair and must be " +
                    "both present or both absent"
            }
            val dualAuthEd25519Hex =
                if (authEd25519B64.isEmpty()) null else {
                    val raw = decodeBase64(authEd25519B64)
                    require(raw != null && raw.size == 32) {
                        "Winn $KEY_AUTH_ED25519 is not 32 bytes of base64"
                    }
                    val h = StringBuilder(64)
                    for (b in raw) h.append(HEX_DIGITS[(b.toInt() shr 4) and 0xF])
                        .append(HEX_DIGITS[b.toInt() and 0xF])
                    h.toString()
                }
            val dualAuthMldsa65Hex =
                if (authMldsa65B64.isEmpty()) null else {
                    val raw = decodeBase64(authMldsa65B64)
                    require(raw != null && raw.size == 1952) {
                        "Winn $KEY_AUTH_MLDSA65 is not 1952 bytes of base64"
                    }
                    val h = StringBuilder(3904)
                    for (b in raw) h.append(HEX_DIGITS[(b.toInt() shr 4) and 0xF])
                        .append(HEX_DIGITS[b.toInt() and 0xF])
                    h.toString()
                }

            val admission = decodeBase64(admissionBase64)
            require(admission != null && admission.isNotEmpty()) {
                "Winn $KEY_ADMISSION is not base64. The signed descriptor carries the admission " +
                    "secret base64-encoded over the key file's own bytes; what is underneath is " +
                    "opaque and is never decoded again"
            }

            return WinnV3Keys(
                gatewayId = gatewayId,
                staticKeyHex = staticKey,
                gatewayStaticKeyHex = gatewayStatic,
                admissionSecret = admission,
                dualAuthEd25519Hex = dualAuthEd25519Hex,
                dualAuthMldsa65Hex = dualAuthMldsa65Hex,
            )
        }

        /**
         * A base64 value that must be exactly one X25519 key, rendered as the
         * hex the engine's `winn3ReadKeyFile` reads.
         *
         * The re-encoding is deliberate and is not a second interpretation: the
         * key FILE format is unchanged (64 hex characters, which survives a
         * truncation as a decode error rather than as a silently short key),
         * while the TRANSPORT is the descriptor's base64. Length is checked
         * here because 32 is the only length X25519 has, and a key of any other
         * length produces a handshake that fails for a reason no log names.
         */
        private fun decodeX25519(value: String, key: String, isPrivate: Boolean): String {
            val role = if (isPrivate) {
                "a 32-byte X25519 private key"
            } else {
                "the gateway's 32-byte X25519 public key; a client authenticates the gateway " +
                    "by its static key and there is no anonymous mode"
            }
            require(value.isNotEmpty()) { "Winn $key is empty: it must carry base64 over $role" }
            val raw = decodeBase64(value)
            require(raw != null) {
                "Winn $key is not base64. Every byte-valued field on the signed gateway " +
                    "descriptor is base64-encoded and reaches the `[winn]` section untouched"
            }
            require(raw.size == KEY_BYTE_LENGTH) {
                "Winn $key decodes to ${raw.size} bytes; it must be $KEY_BYTE_LENGTH :  $role"
            }
            val hex = StringBuilder(KEY_HEX_LENGTH)
            for (b in raw) hex.append(HEX_DIGITS[(b.toInt() shr 4) and 0xF])
                .append(HEX_DIGITS[b.toInt() and 0xF])
            return hex.toString()
        }

        private const val HEX_DIGITS = "0123456789abcdef"

        /**
         * STRICT standard-alphabet base64, or null.
         *
         * Hand-written for two reasons. `java.util.Base64` is API 26 and this
         * module's `minSdk` is 24, and `android.util.Base64` is an Android
         * import this file deliberately does not have :  every rule in it runs
         * under a plain-JVM test, which is the only reason the encoding
         * contract is checkable at all without a device.
         *
         * STRICT is the load-bearing word. It refuses embedded whitespace, the
         * URL-safe alphabet, missing padding and trailing garbage, and returns
         * null rather than a best effort. A lenient decoder turns a mangled
         * descriptor value into plausible bytes, and plausible bytes are how
         * every defect this contract exists to prevent presents: a tag the
         * gateway cannot verify, and no answer from anywhere.
         */
        internal fun decodeBase64(value: String): ByteArray? {
            if (value.isEmpty() || value.length % 4 != 0) return null
            var padding = 0
            while (padding < 2 && value.length > padding &&
                value[value.length - 1 - padding] == '='
            ) padding++
            val out = ByteArray(value.length / 4 * 3 - padding)
            var outIndex = 0
            var i = 0
            while (i < value.length) {
                var block = 0
                var bits = 0
                for (j in 0 until 4) {
                    val ch = value[i + j]
                    if (ch == '=') {
                        // Padding is only ever the last one or two characters.
                        if (i + 4 != value.length || j < 4 - padding) return null
                        block = block shl 6
                        continue
                    }
                    val sextet = base64Sextet(ch)
                    if (sextet < 0) return null
                    block = (block shl 6) or sextet
                    bits += 6
                }
                var shift = 16
                var produced = 0
                while (produced < bits / 8) {
                    out[outIndex++] = ((block shr shift) and 0xFF).toByte()
                    shift -= 8
                    produced++
                }
                i += 4
            }
            return if (outIndex == out.size) out else null
        }

        private fun base64Sextet(ch: Char): Int = when (ch) {
            in 'A'..'Z' -> ch - 'A'
            in 'a'..'z' -> ch - 'a' + 26
            in '0'..'9' -> ch - '0' + 52
            '+' -> 62
            '/' -> 63
            else -> -1
        }
    }
}
