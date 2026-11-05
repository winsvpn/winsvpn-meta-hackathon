package org.winsvpn.app

import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * ONE DEFECT SHAPE, GUARDED IN THE TWO PLACES IT WAS FOUND.
 *
 * Android lint ran on this project for the first time on 2026-08-08 and its
 * only two errors were both on one line: an API 26 call under `minSdk 24`. The
 * interesting part was not the API level. It was that the call was already
 * wrapped in `catch (_: Exception)` and that this did nothing, because a class
 * missing from the runtime raises `NoClassDefFoundError` -- an `Error`, which
 * is not an `Exception`. The handler looked like a fallback and was in fact a
 * crash on every API 24 and 25 handset.
 *
 * A sweep for the same shape found a second one that lint could not see,
 * because nothing about it is an API level: `System.loadLibrary` raises
 * `UnsatisfiedLinkError`, also an `Error`, and both of `VpnTunnelService`'s
 * engine run loops catch `Exception`. There it was worse than a crash -- the
 * handler that was skipped is the one calling `clearRestartConfig()`, so the
 * service came back and did it again.
 *
 * These tests pin both fixes. The behavioural half runs. The API-level gate
 * itself is exercised directly: it is now a pure function of the API level
 * (`posixModeOrNullFor`), so each branch is asserted for real instead of only
 * being read off the source. `SDK_INT` on the unit-test `android.jar` is a
 * `static final` constant the runtime will not let a test rewrite and
 * `android.system.Os` is a `Method ... not mocked` stub, so the decision is
 * parameterized rather than mocked -- passing the level in is what lets a test
 * answer "what does API 35 do?" deterministically.
 */
class ApiLevelGateTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        root = File.createTempFile("winn-mode-gate", "").let {
            it.delete()
            it.mkdirs()
            it
        }
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    // ---- the policy, which depends on no platform at all -----------------

    @Test
    fun `owner-only is exactly the modes with no group or other bit`() {
        // All 512 permission modes. `securefile.ReadPrivateLimited` refuses on
        // `Perm()&0o077 != 0`, so this enumeration IS the engine's rule.
        for (mode in 0..0b111_111_111) {
            val expected = (mode and 0b111_111) == 0
            assertEquals(
                "mode 0${mode.toString(8)}",
                expected,
                WinnCarrierProfile.modeIsOwnerOnly(mode),
            )
        }
    }

    @Test
    fun `the two modes this host actually writes are owner-only`() {
        // restrictToOwner() produces 0600 for a file and 0700 for a directory.
        assertTrue(WinnCarrierProfile.modeIsOwnerOnly(0b110_000_000))
        assertTrue(WinnCarrierProfile.modeIsOwnerOnly(0b111_000_000))
    }

    @Test
    fun `one group or other bit is enough to lose owner-only`() {
        assertFalse("group read", WinnCarrierProfile.modeIsOwnerOnly(0b110_100_000))
        assertFalse("other read", WinnCarrierProfile.modeIsOwnerOnly(0b110_000_100))
        assertFalse("other execute", WinnCarrierProfile.modeIsOwnerOnly(0b110_000_001))
    }

    // ---- the file-reading half, on the java.nio path this JVM takes -------

    @Test
    fun `isOwnerOnly reports the real mode rather than a conservative true`() {
        // The assertion the old implementation could not make. It answered
        // `true` from a `catch` on every failure, so a test that only ever
        // checked the positive case would have passed against a stub.
        val file = File(root, "profile.json")
        file.writeText("{}")
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setExecutable(false, false)
        file.setReadable(true, true)
        file.setWritable(true, true)
        assertTrue("0600 must read as owner-only", WinnCarrierProfile.isOwnerOnly(file))

        // Widen it to everyone and the same call must now say so.
        file.setReadable(true, false)
        assertFalse("world-readable must not read as owner-only", WinnCarrierProfile.isOwnerOnly(file))
    }

    // ---- the API gate, answered directly for each level ---------------------
    //
    // `posixModeOrNullFor(sdkInt, file)` takes the level as an argument, so each
    // branch is executable here. This is what closes the Android-jar stub gap:
    // `SDK_INT` cannot be rewritten on the unit-test `android.jar` (it is a
    // `static final` constant the runtime refuses to set) and `android.system.Os`
    // is a `Method ... not mocked` stub, so the only way to assert "what does the
    // gate do on API 35?" deterministically is to pass the level in and call it.

    @Test
    fun `on Android 15 the gate reads the real mode through java nio`() {
        // API 35 is Android 15. It remains a valid nio branch (>= 26) even
        // though the 2026-10-06 ruling pins targetSdk to API 37.
        val file = ownerOnlyFile()
        val mode = WinnCarrierProfile.posixModeOrNullFor(35, file)
        assertTrue(
            "Android 15 must answer with a real mode, not null",
            mode != null && WinnCarrierProfile.modeIsOwnerOnly(mode),
        )
        // Widen to world-readable; the same API level must now say so. A stub
        // that always answered "owner-only" would fail here.
        file.setReadable(true, false)
        val widened = WinnCarrierProfile.posixModeOrNullFor(35, file)
            ?: throw AssertionError("Android 15 must report a real mode when widened")
        assertFalse("world-readable must not read as owner-only on Android 15",
            WinnCarrierProfile.modeIsOwnerOnly(widened))
    }

    @Test
    fun `on Android 16 the gate reads the real mode through java nio`() {
        // API 36 is Android 16, the previous ruled targetSdk (1.0.16+33).
        val file = ownerOnlyFile()
        val mode = WinnCarrierProfile.posixModeOrNullFor(36, file)
        assertTrue(
            "Android 16 must answer with a real mode, not null",
            mode != null && WinnCarrierProfile.modeIsOwnerOnly(mode),
        )
        file.setReadable(true, false)
        val widened = WinnCarrierProfile.posixModeOrNullFor(36, file)
            ?: throw AssertionError("Android 16 must report a real mode when widened")
        assertFalse(
            "world-readable must not read as owner-only on Android 16",
            WinnCarrierProfile.modeIsOwnerOnly(widened),
        )
    }

    @Test
    fun `on Android 17 the gate reads the real mode through java nio`() {
        // API 37 is Android 17, the ruled targetSdk since 2026-10-06.
        val file = ownerOnlyFile()
        val mode = WinnCarrierProfile.posixModeOrNullFor(37, file)
        assertTrue(
            "Android 17 must answer with a real mode, not null",
            mode != null && WinnCarrierProfile.modeIsOwnerOnly(mode),
        )
        file.setReadable(true, false)
        val widened = WinnCarrierProfile.posixModeOrNullFor(37, file)
            ?: throw AssertionError("Android 17 must report a real mode when widened")
        assertFalse(
            "world-readable must not read as owner-only on Android 17",
            WinnCarrierProfile.modeIsOwnerOnly(widened),
        )
    }

    @Test
    fun `release Gradle pins compile and target SDK 37 and NDK r30`() {
        val gradle = androidAppGradle()
        assertTrue(gradle.contains("compileSdk = 37"))
        assertTrue(gradle.contains("targetSdk = 37"))
        assertTrue(gradle.contains("ndkVersion = \"30.0.16248370\""))
        assertTrue(gradle.contains("fun verifyAndroidReleaseIdentityAndApi37()"))
    }

    @Test
    fun `Android 15 goes to java nio while API 24 goes to the Os stat branch`() {
        val file = ownerOnlyFile()
        // API 35 (>= 26): the java.nio half, which answers for real on this JVM.
        val api35 = WinnCarrierProfile.posixModeOrNullFor(35, file)
        assertTrue(
            "API 35 must answer through java.nio",
            api35 != null && WinnCarrierProfile.modeIsOwnerOnly(api35),
        )
        // API 24 (< 26, > 0): the android.system.Os.stat half. Under the
        // unit-test android.jar that call is a "Method ... not mocked" stub, so
        // the branch is contained by its catch(Throwable) and reports null -- it
        // must NOT fall through to java.nio. If the gate wrongly routed 24 to the
        // java.nio half, this call would answer the real 0600 mode and fail here.
        assertNull(
            "API 24 must take the Os branch, whose not-mocked stub is contained as null",
            WinnCarrierProfile.posixModeOrNullFor(24, file),
        )
        // And a level that is neither device nor off-device-enough must be the
        // only remaining case: 0 (the off-device JVM) still answers through nio.
        assertTrue(
            "the off-device JVM must read through java.nio",
            WinnCarrierProfile.modeIsOwnerOnly(
                WinnCarrierProfile.posixModeOrNullFor(0, file)
                    ?: throw AssertionError("off-device level 0 must report a real mode"),
            ),
        )
    }

    // ---- the API gate, still pinned structurally as belt ----------------

    @Test
    fun `the API 26 call is reached only above API 26`() {
        val source = mainSource("WinnCarrierProfile.kt")
        val chooser = functionBody(source, "internal fun posixModeOrNullFor(sdkInt: Int, file: File): Int?")
        assertTrue(
            "posixModeOrNullFor must gate on sdkInt; without it, API 24/25 raises " +
                "NoClassDefFoundError out of java.nio.file",
            chooser.contains(
                "sdkInt >= android.os.Build.VERSION_CODES.O",
            ),
        )
        // Order is the whole gate: the java.nio branch must return before any
        // device below 26 can reach it.
        val nioAt = chooser.indexOf("nioPosixModeOrNull(file)")
        val statAt = chooser.indexOf("statPosixModeOrNull(file)")
        assertTrue("both branches must be present", nioAt >= 0 && statAt >= 0)
        assertTrue(
            "the java.nio branch must sit inside the sdkInt >= O test that precedes it",
            chooser.lastIndexOf("VERSION_CODES.O", nioAt) >= 0,
        )
        val onDeviceTestAt = chooser.indexOf("sdkInt > 0")
        assertTrue(
            "android.system.Os must answer for every remaining on-device level, " +
                "behind an explicit \"on a device\" test",
            onDeviceTestAt in 0 until statAt,
        )
    }

    @Test
    fun `java nio is confined to explicitly gated functions in main sources`() {
        // Any new `java.nio.file` call must be enumerated here and placed behind
        // the same API 26/device/off-device split. This keeps source discovery
        // broad without treating the key-file guard's two reviewed call sites
        // as defects.
        val offenders = mutableMapOf<String, Int>()
        for (file in mainKotlinSources()) {
            val hits = Regex("java\\.nio\\.file\\.Files\\.[A-Za-z]+\\(")
                .findAll(withoutDocComments(file.readText())).count()
            if (hits > 0) offenders[file.name] = hits
        }
        assertEquals(
            "java.nio.file.Files may only be called from reviewed helpers; found $offenders",
            setOf("WinnCarrierProfile.kt", "WinnV3Keys.kt"),
            offenders.keys,
        )
        assertEquals(1, offenders["WinnCarrierProfile.kt"])
        val keysText = withoutDocComments(mainSource("WinnV3Keys.kt"))
        val keysHits = Regex("java\\.nio\\.file\\.Files\\.[A-Za-z]+\\(")
            .findAll(keysText)
            .map { match ->
                val before = keysText.lastIndexOf("\n    private fun ", match.range.first)
                val line = keysText.substring(before + 1, match.range.first)
                line
            }
            .toList()
        assertTrue("WinnV3Keys must call Files", keysHits.isNotEmpty())
        for (context in keysHits) {
            assertTrue(
                "Files calls in WinnV3Keys must stay inside nio helpers, found near: $context",
                context.contains("private fun nio"),
            )
        }
        val nio = functionBody(
            mainSource("WinnCarrierProfile.kt"),
            "private fun nioPosixModeOrNull(file: File): Int?",
        )
        assertTrue("the one call must be the one inside the gated function",
            nio.contains("java.nio.file.Files.getPosixFilePermissions"))

        val keys = mainSource("WinnV3Keys.kt")
        val symlinkGate = functionBody(
            keys,
            "internal fun isSymlinkFor(sdkInt: Int, file: File): Boolean",
        )
        assertTrue(
            "WinnV3Keys symlink checks must gate java.nio at API 26",
            symlinkGate.contains("sdkInt >= android.os.Build.VERSION_CODES.O"),
        )
        assertTrue(
            "the API-gated symlink branch must delegate to nioIsSymlink",
            symlinkGate.contains("nioIsSymlink(file)"),
        )
        val nioSymlink = functionBody(
            keys,
            "private fun nioIsSymlink(file: File): Boolean",
        )
        assertTrue(
            "the reviewed symlink helper must contain the Files call",
            nioSymlink.contains("java.nio.file.Files.isSymbolicLink"),
        )
        assertTrue(
            "the reviewed symlink helper must contain linkage and filesystem failures",
            nioSymlink.contains("catch (thrown: Throwable)"),
        )
        assertTrue(
            "symlink inspection failures must fail closed",
            nioSymlink.contains("throw IOException"),
        )

        val keysModeGate = functionBody(
            keys,
            "internal fun posixModeOrNullFor(sdkInt: Int, file: File): Int?",
        )
        assertTrue(
            "WinnV3Keys mode checks must gate java.nio at API 26",
            keysModeGate.contains("sdkInt >= android.os.Build.VERSION_CODES.O"),
        )
        val keysNioMode = functionBody(
            keys,
            "private fun nioPosixModeOrNull(file: File): Int?",
        )
        assertTrue(
            "the reviewed key-file mode helper must contain the Files call",
            keysNioMode.contains("java.nio.file.Files.getPosixFilePermissions"),
        )
        assertTrue(
            "the reviewed key-file mode helper must contain linkage and filesystem failures",
            keysNioMode.contains("catch (_: Throwable)"),
        )
    }

    @Test
    fun `both mode readers catch Throwable and not Exception`() {
        // The whole point: an `Error` here must not walk past the handler.
        val source = mainSource("WinnCarrierProfile.kt")
        for (signature in listOf(
            "private fun nioPosixModeOrNull(file: File): Int?",
            "private fun statPosixModeOrNull(file: File): Int?",
        )) {
            val body = functionBody(source, signature)
            assertTrue("$signature must catch Throwable", body.contains("catch (_: Throwable)"))
            assertFalse("$signature must not narrow to Exception", body.contains("catch (_: Exception)"))
        }
    }

    // ---- the sibling: UnsatisfiedLinkError out of the tunnel engine -------

    @Test
    fun `the native library load converts its Error into an Exception`() {
        val body = functionBody(
            mainSource("VpnTunnelService.kt"),
            "private fun ensureAwgNativeLoaded()",
        )
        assertTrue(
            "System.loadLibrary raises UnsatisfiedLinkError, an Error; both engine run " +
                "loops catch Exception, so it must be converted here or it escapes both",
            body.contains("catch (e: UnsatisfiedLinkError)"),
        )
        assertTrue(
            "it must be rethrown as something the run loops' catch (e: Exception) sees, " +
                "so clearRestartConfig() runs and the service does not crash-loop",
            body.contains("throw IOException("),
        )
    }

    @Test
    fun `the native library is loaded from exactly one place`() {
        val offenders = mutableMapOf<String, Int>()
        for (file in mainKotlinSources()) {
            val hits = Regex("System\\.loadLibrary\\(")
                .findAll(withoutDocComments(file.readText())).count()
            if (hits > 0) offenders[file.name] = hits
        }
        assertEquals(
            "System.loadLibrary belongs only in VpnTunnelService.ensureAwgNativeLoaded, " +
                "which is the one place that converts UnsatisfiedLinkError; found $offenders",
            mapOf("VpnTunnelService.kt" to 1),
            offenders,
        )
    }

    // ---- helpers, matching CamouflageLatchedSurfaceTest -------------------

    /** A 0600 temp file under [root], the exact shape [writeTo] produces. */
    private fun ownerOnlyFile(): File {
        val file = File(root, "gate.json")
        file.writeText("{}")
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setExecutable(false, false)
        file.setReadable(true, true)
        file.setWritable(true, true)
        return file
    }

    private fun functionBody(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("could not find $signature", start >= 0)
        val open = source.indexOf('{', start)
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

    private fun mainSourceDir(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/main/kotlin/org/winsvpn/app",
                "android/app/src/main/kotlin/org/winsvpn/app",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isDirectory) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate the application's main Kotlin sources")
    }

    /**
     * Discovered rather than listed: a hardcoded file list is a place to forget
     * a new source, which is exactly how the second instance of this defect
     * survived the first one.
     */
    private fun mainKotlinSources(): List<File> =
        mainSourceDir().listFiles()
            ?.filter { it.isFile && it.name.endsWith(".kt") }
            ?.sortedBy { it.name }
            ?: throw AssertionError("main Kotlin source directory is unreadable")

    private fun mainSource(name: String): String = File(mainSourceDir(), name).readText()

    private fun androidAppGradle(): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf("build.gradle.kts", "android/app/build.gradle.kts")) {
                val candidate = File(dir, relative)
                if (candidate.isFile && candidate.readText().contains("applicationId = \"org.winsvpn.app\"")) {
                    return candidate.readText()
                }
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate android/app/build.gradle.kts")
    }

    /**
     * KDoc stripped before the two whole-file sweeps above, so that *writing
     * about* `System.loadLibrary` or `java.nio.file` -- which the fix for both
     * defects does at length, right beside the code -- is not itself counted as
     * a second call site.
     */
    private fun withoutDocComments(source: String): String =
        source.replace(Regex("/\\*\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
}
