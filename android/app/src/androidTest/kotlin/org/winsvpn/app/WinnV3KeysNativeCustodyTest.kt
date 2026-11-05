package org.winsvpn.app

import android.content.Context
import android.os.Build
import android.system.Os
import android.system.OsConstants
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.io.FileDescriptor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class WinnV3KeysNativeCustodyTest {
    private lateinit var root: File

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        root = File(context.filesDir, "winnv3-native-custody-${System.nanoTime()}")
        assertTrue(root.mkdirs())
        Os.chmod(root.absolutePath, 0b111_000_000)
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun nativeHeldDescriptorsAreCloexecAndEraseEveryHardlink() {
        assertTrue("device test must execute the Android Os path", Build.VERSION.SDK_INT >= 24)
        val directory = WinnV3Keys.keyDirectory(root, 1, 101L)
        val keys = WinnV3Keys.from(keySection())
        keys.writeTo(directory)

        for (fd in heldChildDescriptors(keys)) {
            val flags = Os.fcntlInt(fd, OsConstants.F_GETFD, 0)
            assertTrue("held key descriptor is missing FD_CLOEXEC", flags and OsConstants.FD_CLOEXEC != 0)
        }

        val links = File(root, "hardlinks")
        assertTrue(links.mkdirs())
        Os.chmod(links.absolutePath, 0b111_000_000)
        for (name in materialNames()) {
            Os.link(File(directory, name).absolutePath, File(links, name).absolutePath)
        }

        assertTrue(keys.destroy(directory))
        for (name in materialNames()) {
            assertEquals("$name tombstone retained plaintext", 0L, File(directory, name).length())
            assertEquals("$name hardlink retained plaintext", 0L, File(links, name).length())
        }
    }

    @Test
    fun newInstanceRecoversCrashPlaintextBeforeCurrentGeneration() {
        val stale = WinnV3Keys.keyDirectory(root, 2, 102L)
        writeStaleFixture(stale)
        val current = WinnV3Keys.keyDirectory(root, 3, 103L)
        val keys = WinnV3Keys.from(keySection())

        assertTrue(keys.recoverStale(root, current))
        assertFalse(current.exists())
        for (name in materialNames()) {
            assertEquals("stale $name retained plaintext", 0L, File(stale, name).length())
        }
        assertNoBoundDirectories(keys)
    }

    @Test
    fun recoveryAcceptsAndroidFilesDirMode() {
        Os.chmod(root.absolutePath, 0b111_111_001)
        val stale = WinnV3Keys.keyDirectory(root, 3, 103L)
        writeStaleFixture(stale)
        val keys = WinnV3Keys.from(keySection())

        assertTrue(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 4, 104L)))
        for (name in materialNames()) {
            assertEquals("stale $name retained plaintext", 0L, File(stale, name).length())
        }
        assertNoBoundDirectories(keys)
    }

    @Test
    fun unknownCrashChildFailsClosedAndIsNotDeleted() {
        val stale = WinnV3Keys.keyDirectory(root, 4, 104L)
        writeStaleFixture(stale)
        val unknown = File(stale, "unexpected")
        unknown.writeText("DO-NOT-DELETE")
        Os.chmod(unknown.absolutePath, 0b110_000_000)
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 5, 105L)))
        assertEquals("DO-NOT-DELETE", unknown.readText())
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun parentSwapToSymlinkFailsClosedWithoutFollowing() {
        val real = File(root, "real-files")
        assertTrue(real.mkdirs())
        Os.chmod(real.absolutePath, 0b111_000_000)
        val stale = WinnV3Keys.keyDirectory(real, 7, 107L)
        writeStaleFixture(stale)
        val link = File(root, "files-link")
        Os.symlink(real.absolutePath, link.absolutePath)
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(link, WinnV3Keys.keyDirectory(link, 8, 108L)))
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun candidateSwapRenameLeavesOriginalAndDoesNotDeleteSubstitute() {
        val stale = WinnV3Keys.keyDirectory(root, 9, 109L)
        writeStaleFixture(stale)
        val relocated = File(root, "relocated-candidate")
        assertTrue(stale.renameTo(relocated))
        writeStaleFixture(stale)
        val victim = File(stale, "victim-other")
        victim.writeText("DO-NOT-DELETE")
        Os.chmod(victim.absolutePath, 0b110_000_000)
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 10, 110L)))
        assertTrue(File(relocated, "admission.key").length() > 0L)
        assertEquals("DO-NOT-DELETE", victim.readText())
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun symlinkCandidateFailsClosedWithoutTouchingTarget() {
        val stale = WinnV3Keys.keyDirectory(root, 11, 111L)
        val target = File(root, "symlink-target")
        writeStaleFixture(target)
        Os.symlink(target.absolutePath, stale.absolutePath)
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 12, 112L)))
        assertTrue(File(target, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun unsafeDirectoryModeFailsClosedAndKeepsPlaintext() {
        val stale = WinnV3Keys.keyDirectory(root, 13, 113L)
        writeStaleFixture(stale)
        Os.chmod(stale.absolutePath, 0b111_101_000)
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 14, 114L)))
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun unsafeChildModeFailsClosedAndKeepsPlaintext() {
        val stale = WinnV3Keys.keyDirectory(root, 15, 115L)
        writeStaleFixture(stale)
        Os.chmod(File(stale, "admission.key").absolutePath, 0b110_100_000)
        val keys = WinnV3Keys.from(keySection())

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 16, 116L)))
        assertTrue(File(stale, "admission.key").length() > 0L)
        assertNoBoundDirectories(keys)
    }

    @Test
    fun hardlinkedStaleInodesAreZeroedWithoutDeletingNames() {
        val stale = WinnV3Keys.keyDirectory(root, 17, 117L)
        writeStaleFixture(stale)
        val links = File(root, "stale-hardlinks")
        assertTrue(links.mkdirs())
        Os.chmod(links.absolutePath, 0b111_000_000)
        for (name in materialNames()) {
            Os.link(File(stale, name).absolutePath, File(links, name).absolutePath)
        }
        val keys = WinnV3Keys.from(keySection())

        assertTrue(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 18, 118L)))
        for (name in materialNames()) {
            assertEquals("stale $name retained plaintext", 0L, File(stale, name).length())
            assertEquals("hardlink $name retained plaintext", 0L, File(links, name).length())
        }
        assertNoBoundDirectories(keys)
    }

    @Test
    fun failedRecoveryDoesNotGrowHeldDescriptors() {
        val stale = WinnV3Keys.keyDirectory(root, 19, 119L)
        writeStaleFixture(stale)
        File(stale, "unexpected").writeText("DO-NOT-DELETE")
        Os.chmod(File(stale, "unexpected").absolutePath, 0b110_000_000)
        val keys = WinnV3Keys.from(keySection())
        val before = openFdCount()

        assertFalse(keys.recoverStale(root, WinnV3Keys.keyDirectory(root, 20, 120L)))
        assertNoBoundDirectories(keys)
        val after = openFdCount()
        assertTrue(
            "stale recovery leaked descriptors: before=$before after=$after",
            after <= before + 2,
        )
    }

    private fun heldChildDescriptors(keys: WinnV3Keys): List<FileDescriptor> {
        val directoriesField = WinnV3Keys::class.java.getDeclaredField("boundDirectories")
        directoriesField.isAccessible = true
        val directories = directoriesField.get(keys) as Map<*, *>
        assertEquals(1, directories.size)
        val bound = directories.values.single() ?: throw AssertionError("missing bound directory")
        val childrenField = bound.javaClass.getDeclaredField("children")
        childrenField.isAccessible = true
        val children = childrenField.get(bound) as Map<*, *>
        assertTrue(children.isNotEmpty())
        return children.values.map { childValue ->
            val child = childValue ?: throw AssertionError("missing bound child")
            val fdField = child.javaClass.getDeclaredField("fd")
            fdField.isAccessible = true
            fdField.get(child) as? FileDescriptor
                ?: throw AssertionError("native custody child has no held descriptor")
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

    private fun openFdCount(): Int = File("/proc/self/fd").list()?.size ?: 0

    private fun writeStaleFixture(directory: File) {
        assertTrue(directory.mkdirs())
        Os.chmod(directory.absolutePath, 0b111_000_000)
        for (name in materialNames()) {
            val file = File(directory, name)
            file.writeText("stale-secret-$name")
            Os.chmod(file.absolutePath, 0b110_000_000)
        }
    }

    private fun materialNames(): List<String> =
        listOf("static.key", "gateway.pub", "admission.key", WinnV3Keys.DOCUMENT_NAME)

    private fun keySection(): Map<String, String> = mapOf(
        WinnV3Keys.KEY_GATEWAY_ID to "Z3ctbGFiLTE=",
        WinnV3Keys.KEY_STATIC to "Hx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8=",
        WinnV3Keys.KEY_GATEWAY_STATIC to "Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4=",
        WinnV3Keys.KEY_ADMISSION to "bGFiLWFkbWlzc2lvbi1zZWNyZXQtcGFkZGVkLXRvLTMyLWJ5dGVz",
    )
}
