package org.winsvpn.app

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Before
import org.junit.Test

/**
 * Exact reproductions of the Android Winn v3 plaintext-key custody P1 findings:
 * partial-write leftover secrets, identity-unbound cleanup, fail-open symlink
 * and permission checks, and CONNECTED publication while original secrets
 * survive. Behavioural cases run on the JVM; the service ordering is pinned
 * against source because that path cannot be executed without a VpnService.
 */
class WinnV3KeysCustodyTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        root = Files.createTempDirectory("winnv3-keys-custody-").toFile()
        Files.setPosixFilePermissions(root.toPath(), PosixFilePermissions.fromString("rwx------"))
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun `generation and start token names are unique including edges`() {
        assertEquals("winn3-0-1", WinnV3Keys.keyDirectory(root, 0, 1L).name)
        assertEquals(
            "winn3-${Int.MAX_VALUE}-${Long.MAX_VALUE}",
            WinnV3Keys.keyDirectory(root, Int.MAX_VALUE, Long.MAX_VALUE).name,
        )
        assertThrows(IllegalArgumentException::class.java) {
            WinnV3Keys.keyDirectory(root, -1, 1L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            WinnV3Keys.keyDirectory(root, 0, 0L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            WinnV3Keys.keyDirectory(root, 1, -1L)
        }
        assertFalse(
            WinnV3Keys.keyDirectory(root, 1, 23L).absolutePath ==
                WinnV3Keys.keyDirectory(root, 12, 3L).absolutePath,
        )
    }

    @Test
    fun `writeTo creates owner-only files and describeForLog holds no secrets`() {
        val directory = WinnV3Keys.keyDirectory(root, 7, 101L)
        val keys = WinnV3Keys.from(keySection())
        val document = keys.writeTo(directory)
        assertTrue(document.isFile)
        assertEquals("rwx------", posix(directory))
        assertEquals("rw-------", posix(File(directory, "static.key")))
        assertEquals("rw-------", posix(File(directory, "gateway.pub")))
        assertEquals("rw-------", posix(File(directory, "admission.key")))
        assertEquals("rw-------", posix(document))
        assertEquals(STATIC_HEX, File(directory, "static.key").readText())
        val log = keys.describeForLog()
        for (secret in listOf(STATIC_HEX, GATEWAY_HEX, ADMISSION_SECRET, STATIC_B64, GATEWAY_B64, ADMISSION_B64)) {
            assertFalse("log leaked $secret: $log", log.contains(secret))
        }
        assertTrue(keys.destroy(directory))
        assertZeroedTombstones(directory)
    }

    @Test
    fun `partial write rolls back leftover secrets when a later create fails`() {
        val directory = WinnV3Keys.keyDirectory(root, 7, 101L)
        assertTrue(directory.mkdirs())
        val blocker = File(directory, "admission.key")
        assertTrue(blocker.mkdir())
        File(blocker, "child").writeText("keep")
        val keys = WinnV3Keys.from(keySection())
        val thrown = assertThrows(IOException::class.java) { keys.writeTo(directory) }
        val message = thrown.message ?: thrown.javaClass.simpleName
        assertTrue(message, message.contains("admission.key"))
        assertEquals(0L, File(directory, "static.key").length())
        assertEquals(0L, File(directory, "gateway.pub").length())
        assertTrue(
            "the pre-existing blocker must not be deleted",
            File(blocker, "child").isFile,
        )
    }

    @Test
    fun `symlink replacement of the bound directory fails closed`() {
        val first = WinnV3Keys.keyDirectory(root, 7, 101L)
        val successor = WinnV3Keys.keyDirectory(root, 8, 102L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(first)
        keys.writeTo(successor)
        val relocated = File(root, "relocated-first")
        assertTrue(first.renameTo(relocated))
        Files.createSymbolicLink(first.toPath(), successor.toPath())
        assertTrue(keys.destroy(first))
        assertZeroedTombstones(relocated)
        assertTrue(
            "successor secrets must not be deleted through the symlink",
            File(successor, "admission.key").isFile,
        )
        assertTrue(Files.isSymbolicLink(first.toPath()))
    }

    @Test
    fun `rename plus replacement fails closed without deleting the substitute`() {
        val first = WinnV3Keys.keyDirectory(root, 7, 101L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(first)
        val relocated = File(root, "relocated-first")
        assertTrue(first.renameTo(relocated))
        assertTrue(first.mkdirs())
        val substitute = File(first, "static.key")
        substitute.writeText("ATTACKER")
        assertTrue(keys.destroy(first))
        assertZeroedTombstones(relocated)
        assertEquals("ATTACKER", substitute.readText())
    }

    @Test
    fun `hostile parent-directory swap fails closed without deleting the substitute`() {
        val parent = File(root, "files")
        assertTrue(parent.mkdirs())
        val directory = WinnV3Keys.keyDirectory(parent, 7, 101L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(directory)

        val relocatedParent = File(root, "files-relocated")
        assertTrue(parent.renameTo(relocatedParent))
        assertTrue(parent.mkdirs())
        val substituteDir = WinnV3Keys.keyDirectory(parent, 7, 101L)
        assertTrue(substituteDir.mkdirs())
        val substitute = File(substituteDir, "static.key")
        substitute.writeText("ATTACKER")
        val victim = File(substituteDir, "victim-other")
        victim.writeText("DO-NOT-DELETE")

        assertTrue(keys.destroy(directory))

        val original = File(relocatedParent, directory.name)
        assertZeroedTombstones(original)
        assertEquals("ATTACKER", substitute.readText())
        assertEquals("DO-NOT-DELETE", victim.readText())
        assertTrue(substituteDir.isDirectory)
    }

    @Test
    fun `native create and descriptor erase never delete mutable pathnames`() {
        val source = readMainSource("WinnV3Keys.kt")
        val create = functionBodyOf(source, "private fun nativeCreateExclusive(")
        assertTrue(create, create.contains("openHeld("))
        assertFalse(
            "native create must not Os.open a child by caller pathname",
            create.contains("Os.open(file.absolutePath"),
        )
        assertFalse(
            "native create must not build a child pathname for I/O",
            create.contains("File(bound.directory, name)"),
        )
        val erase = functionBodyOf(source, "private fun nativeEraseHeldFile(")
        assertTrue(erase, erase.contains("Os.ftruncate(fd, 0L)"))
        assertTrue(erase, erase.contains("Os.fsync(fd)"))
        assertTrue(erase, erase.contains("after.st_size == 0L"))
        assertFalse(source.contains("Os.remove("))
        assertFalse(source.contains("removeHeld("))
        val heldOpen = functionBodyOf(source, "private fun openHeld(")
        assertTrue(heldOpen, heldOpen.contains("/proc/self/fd/"))
        val duplicate = functionBodyOf(source, "private fun duplicateCloexec(")
        assertTrue(duplicate, duplicate.contains("F_DUPFD_CLOEXEC"))
        assertTrue(
            "create must keep owner, mode, nlink and inode checks",
            create.contains("refuseUnsafeFileStat(created, name)") &&
                create.contains("refuseUnsafeFileStat(st, name)"),
        )
        assertTrue(
            "native custody must be registered before the first secret write",
            create.indexOf("bound.children[name] = child") <
                create.indexOf("val buffer = java.nio.ByteBuffer.wrap(bytes)"),
        )
        val destroyBound = functionBodyOf(source, "private fun destroyBound(")
        assertTrue(destroyBound.contains("if (complete)"))
        assertFalse(
            "failed erasure must retain descriptors for a retry",
            destroyBound.contains("finally"),
        )
        val fileStat = functionBodyOf(source, "private fun refuseUnsafeFileStat(")
        assertTrue(fileStat.contains("st_uid"))
        assertTrue(fileStat.contains("st_nlink"))
        assertTrue(fileStat.contains("GROUP_AND_OTHER_BITS"))
        val dirStat = functionBodyOf(source, "private fun refuseUnsafeDirectoryStat(")
        assertTrue(dirStat.contains("st_uid"))
        assertTrue(dirStat.contains("st_nlink"))
        assertTrue(dirStat.contains("GROUP_AND_OTHER_BITS"))
        assertTrue(
            source.contains("FileIdentity(st.st_dev, st.st_ino)"),
        )
        val recover = functionBodyOf(
            source,
            "fun recoverStale(filesDir: File, currentDirectory: File): Boolean",
        )
        assertTrue(
            recover,
            recover.contains("bindDirectory(filesDir, requireOwnerOnly = false)"),
        )
        assertFalse(
            "recoverStale must not list filesDir by pathname",
            recover.contains("listFiles()"),
        )
        val recoverHeld = functionBodyOf(source, "private fun recoverStaleFromHeld(")
        assertTrue(recoverHeld, recoverHeld.contains("heldDirectoryNames(filesDirBound)"))
        assertTrue(recoverHeld, recoverHeld.contains("bindStaleCandidate("))
        assertTrue(recoverHeld, recoverHeld.contains("destroyBoundWithRetry("))
        assertTrue(recoverHeld, recoverHeld.contains("releaseBound("))
        assertTrue(recoverHeld, recoverHeld.contains("heldHasLeftoverPlaintext("))
        val bindStale = functionBodyOf(source, "private fun nativeBindStaleDirectory(")
        assertTrue(bindStale, bindStale.contains("openHeld("))
        assertFalse(
            "stale candidates must not be reopened by pathname",
            bindStale.contains("Os.open(") && bindStale.contains("absolutePath"),
        )
        val retry = functionBodyOf(source, "private fun destroyBoundWithRetry(")
        assertTrue(retry, retry.contains("destroyBound(bound)"))
        assertTrue(
            "incomplete erase must retry the same held descriptors",
            retry.indexOf("if (destroyBound(bound)) return true") <
                retry.lastIndexOf("destroyBound(bound)"),
        )
        val release = functionBodyOf(source, "private fun releaseBound(")
        assertTrue(release, release.contains("closeChildFds(bound)"))
        assertTrue(release, release.contains("closeDirFd(bound)"))
    }

    @Test
    fun `unknown children survive while original identities are erased`() {
        val directory = WinnV3Keys.keyDirectory(root, 9, 103L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(directory)
        val unknown = File(directory, "unexpected")
        unknown.writeText("do-not-delete")
        assertTrue(keys.destroy(directory))
        assertTrue(unknown.isFile)
        assertZeroedTombstones(directory)
        assertTrue(directory.isDirectory)
    }

    @Test
    fun `stale predecessor destroy cannot touch a successor directory`() {
        val first = WinnV3Keys.keyDirectory(root, 7, 101L)
        val successor = WinnV3Keys.keyDirectory(root, 8, 102L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(first)
        keys.writeTo(successor)
        assertTrue(keys.destroy(first))
        assertZeroedTombstones(first)
        assertTrue(File(successor, "admission.key").length() > 0L)
        assertTrue(keys.destroy(successor))
        assertZeroedTombstones(successor)
    }

    @Test
    fun `new process recovery erases stale crash plaintext before the next generation`() {
        val stale = WinnV3Keys.keyDirectory(root, 13, 203L)
        writeStaleFixture(stale)
        val current = WinnV3Keys.keyDirectory(root, 14, 204L)
        val recoveredByNewInstance = WinnV3Keys.from(keySection())

        assertTrue(recoveredByNewInstance.recoverStale(root, current))
        assertZeroedTombstones(stale)
        assertFalse(current.exists())
        assertNoBoundDirectories(recoveredByNewInstance)
    }

    @Test
    fun `stale recovery accepts the Android filesDir 0771 container mode`() {
        Files.setPosixFilePermissions(
            root.toPath(),
            PosixFilePermissions.fromString("rwxrwx--x"),
        )
        val stale = WinnV3Keys.keyDirectory(root, 14, 204L)
        writeStaleFixture(stale)
        val keys = WinnV3Keys.from(keySection())

        assertTrue(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 15, 205L)))
        assertZeroedTombstones(stale)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery zeros hardlinked stale inodes without deleting either name`() {
        val stale = WinnV3Keys.keyDirectory(root, 15, 205L)
        writeStaleFixture(stale)
        val external = File(root, "stale-hardlinks")
        assertTrue(external.mkdirs())
        Files.setPosixFilePermissions(
            external.toPath(),
            PosixFilePermissions.fromString("rwx------"),
        )
        for (name in materialNames()) {
            Files.createLink(File(external, name).toPath(), File(stale, name).toPath())
        }
        val keys = WinnV3Keys.from(keySection())

        assertTrue(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 16, 206L)))
        assertZeroedTombstones(stale)
        for (name in materialNames()) {
            assertEquals("stale hardlink $name retained plaintext", 0L, File(external, name).length())
        }
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery refuses unknown stale children without deleting them`() {
        val stale = WinnV3Keys.keyDirectory(root, 17, 207L)
        writeStaleFixture(stale)
        val unknown = File(stale, "unexpected")
        unknown.writeText("DO-NOT-DELETE")
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 18, 208L)))
        assertEquals("DO-NOT-DELETE", unknown.readText())
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery parent swap during listing fails closed without deleting the substitute`() {
        val stale = WinnV3Keys.keyDirectory(root, 19, 209L)
        writeStaleFixture(stale)
        val relocated = File(root.parentFile, root.name + "-relocated")
        val filesDir = OnceSwapFile(root) {
            assertTrue(root.renameTo(relocated))
            assertTrue(root.mkdirs())
            Files.setPosixFilePermissions(
                root.toPath(),
                PosixFilePermissions.fromString("rwx------"),
            )
            val substitute = WinnV3Keys.keyDirectory(root, 19, 209L)
            writeStaleFixture(substitute)
            File(substitute, "victim-other").writeText("DO-NOT-DELETE")
        }
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(filesDir, WinnV3Keys.keyDirectory(root, 20, 210L)))
        assertTrue(File(relocated, stale.name).let { File(it, "admission.key") }.length() > 0L)
        val substitute = WinnV3Keys.keyDirectory(root, 19, 209L)
        assertEquals("DO-NOT-DELETE", File(substitute, "victim-other").readText())
        assertTrue(File(substitute, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery candidate swap during listing fails closed without deleting the substitute`() {
        val stale = WinnV3Keys.keyDirectory(root, 21, 211L)
        writeStaleFixture(stale)
        val relocated = File(root, "relocated-candidate")
        val filesDir = OnceSwapFile(root) {
            assertTrue(stale.renameTo(relocated))
            writeStaleFixture(stale)
            File(stale, "victim-other").writeText("DO-NOT-DELETE")
        }
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(filesDir, WinnV3Keys.keyDirectory(root, 22, 212L)))
        assertTrue(File(relocated, "admission.key").length() > 0L)
        assertEquals("DO-NOT-DELETE", File(stale, "victim-other").readText())
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery refuses a symlink candidate without touching the target`() {
        val stale = WinnV3Keys.keyDirectory(root, 23, 213L)
        val target = File(root, "symlink-target")
        writeStaleFixture(target)
        Files.createSymbolicLink(stale.toPath(), target.toPath())
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 24, 214L)))
        assertTrue(Files.isSymbolicLink(stale.toPath()))
        assertTrue(File(target, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery refuses a symlink filesDir without following it`() {
        val real = File(root, "real-files")
        assertTrue(real.mkdirs())
        Files.setPosixFilePermissions(real.toPath(), PosixFilePermissions.fromString("rwx------"))
        val stale = WinnV3Keys.keyDirectory(real, 25, 215L)
        writeStaleFixture(stale)
        val link = File(root, "files-link")
        Files.createSymbolicLink(link.toPath(), real.toPath())
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(link, WinnV3Keys.keyDirectory(link, 26, 216L)))
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery refuses a group-readable stale directory`() {
        val stale = WinnV3Keys.keyDirectory(root, 27, 217L)
        writeStaleFixture(stale)
        Files.setPosixFilePermissions(
            stale.toPath(),
            PosixFilePermissions.fromString("rwxr-x---"),
        )
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 28, 218L)))
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `crash recovery refuses a group-readable stale child`() {
        val stale = WinnV3Keys.keyDirectory(root, 29, 219L)
        writeStaleFixture(stale)
        Files.setPosixFilePermissions(
            File(stale, "admission.key").toPath(),
            PosixFilePermissions.fromString("rw-r-----"),
        )
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 30, 220L)))
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `failed stale recovery closes bound directories instead of leaking them`() {
        val stale = WinnV3Keys.keyDirectory(root, 31, 221L)
        writeStaleFixture(stale)
        File(stale, "unexpected").writeText("DO-NOT-DELETE")
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 32, 222L)))
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `successful stale recovery does not retain bound directories`() {
        val stale = WinnV3Keys.keyDirectory(root, 33, 223L)
        writeStaleFixture(stale)
        val keys = WinnV3Keys.from(keySection())

        assertTrue(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 34, 224L)))
        assertZeroedTombstones(stale)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun `incomplete stale erase retries then closes without reporting success`() {
        val stale = WinnV3Keys.keyDirectory(root, 35, 225L)
        writeStaleFixture(stale)
        val locked = File(stale, "admission.key")
        val lockedFlag = ProcessBuilder("chflags", "uchg", locked.absolutePath)
            .redirectErrorStream(true)
            .start()
        Assume.assumeTrue(
            "chflags uchg must freeze the inode on this host",
            lockedFlag.waitFor() == 0,
        )
        val keys = WinnV3Keys.from(keySection())
        try {
            assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 36, 226L)))
            assertTrue(locked.length() > 0L)
            assertNoBoundDirectories(keys)
        } finally {
            ProcessBuilder("chflags", "nouchg", locked.absolutePath).start().waitFor()
        }
    }

    @Test
    fun `write refuses a symlink directory without writing secrets`() {
        val target = File(root, "target")
        assertTrue(target.mkdirs())
        val link = File(root, "winn3-4-5")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        val keys = WinnV3Keys.from(keySection())
        assertThrows(IOException::class.java) { keys.writeTo(link) }
        assertTrue(target.listFiles()?.isEmpty() == true)
    }

    @Test
    fun `dual-auth files are bound and destroyed with the rest of the material`() {
        val directory = WinnV3Keys.keyDirectory(root, 11, 201L)
        val keys = WinnV3Keys.from(dualAuthSection())
        val document = keys.writeTo(directory)
        val json = document.readText()
        assertTrue(json.contains("dual_auth_ed25519_pub_path"))
        assertTrue(json.contains("dual_auth_mldsa65_pub_path"))
        assertTrue(File(directory, "auth_ed25519.pub").isFile)
        assertTrue(File(directory, "auth_mldsa65.pub").isFile)
        assertTrue(keys.destroy(directory))
        assertZeroedTombstones(directory)
        assertEquals(0L, File(directory, "auth_ed25519.pub").length())
        assertEquals(0L, File(directory, "auth_mldsa65.pub").length())
    }

    @Test
    fun `hardlinks and removed live names cannot leave plaintext after successful destroy`() {
        val directory = WinnV3Keys.keyDirectory(root, 12, 202L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(directory)
        val links = File(root, "hostile-links")
        assertTrue(links.mkdirs())
        for (name in materialNames()) {
            val original = File(directory, name)
            val linked = File(links, name)
            Files.createLink(linked.toPath(), original.toPath())
            assertTrue(original.delete())
            assertTrue(linked.length() > 0L)
        }

        assertTrue(keys.destroy(directory))
        for (name in materialNames()) {
            assertEquals("hardlink $name retained plaintext", 0L, File(links, name).length())
        }
    }

    @Test
    fun `service assigns ownership before writeTo and CONNECTED requires destroy`() {
        val body = functionBodyOf(
            readMainSource("VpnTunnelService.kt"),
            "private fun startWinnV3EngineThread(",
        )
        val assign = body.indexOf("keyMaterial = keys to keyDirectory")
        val recover = body.indexOf("keys.recoverStale(applicationContext.filesDir, keyDirectory)")
        val write = body.indexOf("keys.writeTo(keyDirectory)")
        val destroy = body.indexOf("keys.destroy(keyDirectory)")
        val connected = body.indexOf("WinnV3NativeVerdict.CONNECTED")
        assertTrue("ownership must be assigned", assign >= 0)
        assertTrue("stale crash recovery must exist", recover >= 0)
        assertTrue("writeTo must exist", write >= 0)
        assertTrue("stale recovery must precede ownership and write", recover < assign && recover < write)
        assertTrue("ownership must be assigned before writeTo", assign < write)
        assertTrue("CreateAck cleanup must exist", destroy >= 0)
        assertTrue("CONNECTED must exist", connected >= 0)
        assertTrue("destroy must precede CONNECTED", destroy < connected)
        assertTrue(
            body.contains("Winn v3 plaintext key cleanup failed after CreateAck"),
        )
    }

    @Test
    fun `symlink and permission inspection failures fail closed`() {
        val keys = readMainSource("WinnV3Keys.kt")
        val nioSymlink = functionBodyOf(keys, "private fun nioIsSymlink(file: File): Boolean")
        assertTrue(nioSymlink.contains("catch (thrown: Throwable)"))
        assertTrue(nioSymlink.contains("throw IOException"))
        val statSymlink = functionBodyOf(keys, "private fun statIsSymlink(file: File): Boolean")
        assertTrue(statSymlink.contains("catch (thrown: Throwable)"))
        assertTrue(statSymlink.contains("throw IOException"))
        val ownerOnly = functionBodyOf(keys, "private fun isOwnerOnly(file: File): Boolean")
        assertTrue(
            "unread POSIX mode must refuse rather than satisfy owner-only",
            ownerOnly.contains("posixModeOrNull(file) ?: return false"),
        )
    }

    private fun posix(file: File): String =
        PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath()))

    private fun materialNames(): List<String> =
        listOf("static.key", "gateway.pub", "admission.key", WinnV3Keys.DOCUMENT_NAME)

    private fun assertZeroedTombstones(directory: File) {
        assertTrue(directory.isDirectory)
        for (name in materialNames()) {
            val file = File(directory, name)
            if (file.exists()) {
                assertEquals("$name retained plaintext", 0L, file.length())
            }
        }
    }

    private fun assertNoBoundDirectories(keys: WinnV3Keys) {
        val field = WinnV3Keys::class.java.getDeclaredField("boundDirectories")
        field.isAccessible = true
        val directories = field.get(keys) as Map<*, *>
        assertTrue(
            "stale recovery must not retain bound directories: ${directories.keys}",
            directories.isEmpty(),
        )
    }

    private class OnceSwapFile(
        original: File,
        private val swap: () -> Unit,
    ) : File(original.absolutePath) {
        private val swapped = java.util.concurrent.atomic.AtomicBoolean(false)

        private fun maybeSwap() {
            if (swapped.compareAndSet(false, true)) swap()
        }

        override fun list(): Array<String>? {
            val names = super.list()
            maybeSwap()
            return names
        }

        override fun listFiles(): Array<File>? {
            val files = super.listFiles()
            maybeSwap()
            return files
        }
    }

    private fun writeStaleFixture(directory: File) {
        assertTrue(directory.mkdirs())
        Files.setPosixFilePermissions(
            directory.toPath(),
            PosixFilePermissions.fromString("rwx------"),
        )
        for (name in materialNames()) {
            val file = File(directory, name)
            file.writeText("stale-secret-$name")
            Files.setPosixFilePermissions(
                file.toPath(),
                PosixFilePermissions.fromString("rw-------"),
            )
        }
    }

    private fun functionBodyOf(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("could not find $signature", start >= 0)
        val open = source.indexOf('{', start + signature.length - 1)
        assertTrue("no body for $signature", open >= 0)
        var depth = 0
        var i = open
        while (i < source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> depth--
            }
            if (depth == 0) return source.substring(open, i + 1)
            i++
        }
        throw AssertionError("unterminated body for $signature")
    }

    private fun readMainSource(name: String): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app/src/main/kotlin/org/winsvpn/app/$name")
            if (candidate.isFile) return candidate.readText()
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app/$name")
            if (here.isFile) return here.readText()
            dir = dir.parentFile
        }
        throw AssertionError("could not find $name")
    }

    private companion object {
        val STATIC_HEX = "1f".repeat(32)
        val GATEWAY_HEX = "2e".repeat(32)
        const val ADMISSION_SECRET = "lab-admission-secret-padded-to-32-bytes"
        const val STATIC_B64 = "Hx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8="
        const val GATEWAY_B64 = "Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4="
        const val ADMISSION_B64 = "bGFiLWFkbWlzc2lvbi1zZWNyZXQtcGFkZGVkLXRvLTMyLWJ5dGVz"
        const val GATEWAY_ID_B64 = "Z3ctbGFiLTE="

        fun keySection(): Map<String, String> = mapOf(
            WinnV3Keys.KEY_GATEWAY_ID to GATEWAY_ID_B64,
            WinnV3Keys.KEY_STATIC to STATIC_B64,
            WinnV3Keys.KEY_GATEWAY_STATIC to GATEWAY_B64,
            WinnV3Keys.KEY_ADMISSION to ADMISSION_B64,
        )

        fun dualAuthSection(): Map<String, String> = keySection() + mapOf(
            WinnV3Keys.KEY_AUTH_ED25519 to
                java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 0x11 }),
            WinnV3Keys.KEY_AUTH_MLDSA65 to
                java.util.Base64.getEncoder().encodeToString(ByteArray(1952) { 0x22 }),
        )
    }
}
