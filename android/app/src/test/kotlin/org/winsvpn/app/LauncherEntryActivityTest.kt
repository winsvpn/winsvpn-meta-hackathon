package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The launcher entry is the first thing the OS hands a tap on the home-screen
 * icon to. In this app it is a deliberate *shallow forward*: a tiny Activity
 * that does nothing but hand the launch on to `MainActivity` and disappear.
 *
 * Two properties make that the right shape for a warm start (the app already
 * running, the user tapping the icon again):
 *
 *  1. **Shallow.** It draws nothing (`setContentView` is never called), so
 *     there is no shim UI to ever be visible.
 *  2. **Flash-free.** It forwards with `FLAG_ACTIVITY_NEW_TASK | CLEAR_TOP |
 *     SINGLE_TOP`, which lands the launch on the already-running `MainActivity`
 *     instance and brings its task to the front instead of stacking a fresh
 *     one, and it calls `overridePendingTransition(0, 0)` so no empty window
 *     animates in between.
 *
 * These are structural facts about the source (this project's unit tests have
 * no Robolectric runtime, so the intent that would be fired is asserted from
 * the source that fires it, in the same style as
 * `CamouflageLatchedSurfaceTest`). A regression that stops the shim forwarding
 * -- or stops it being shallow, or drops the warm-start flags -- fails here.
 */
class LauncherEntryActivityTest {

    @Test
    fun `the launcher entry is a shallow forward into MainActivity`() {
        val src = launcherSource()
        assertTrue("must forward explicitly into MainActivity", src.contains("MainActivity::class.java"))
        assertTrue("must actually start an Activity", src.contains("startActivity("))
        // Shallow: nothing may ever be drawn in this Activity's window. A
        // `setContentView` here would mean a visible shim, which would flash
        // on every launch.
        assertFalse("a shallow forward must not render content", src.contains("setContentView"))
        // Warm-start flags: these are what make a repeated icon tap land on the
        // existing MainActivity task rather than stacking a second instance.
        assertTrue("warm-start needs NEW_TASK", src.contains("FLAG_ACTIVITY_NEW_TASK"))
        assertTrue("warm-start needs CLEAR_TOP", src.contains("FLAG_ACTIVITY_CLEAR_TOP"))
        assertTrue("warm-start needs SINGLE_TOP", src.contains("FLAG_ACTIVITY_SINGLE_TOP"))
        // Disappear immediately and suppress the transition so there is no
        // empty window flash between this shim and MainActivity.
        assertTrue("the shim must finish immediately", src.contains("finish()"))
        assertTrue("the transition must be suppressed", src.contains("overridePendingTransition(0, 0)"))
    }

    @Test
    fun `both launcher aliases inherit the shallow forward`() {
        val src = launcherSource()
        assertTrue(
            "RealLauncherActivity must be a shim, not a standalone activity",
            src.contains("class RealLauncherActivity : LauncherEntryActivity()"),
        )
        assertTrue(
            "DecoyLauncherActivity must be a shim, not a standalone activity",
            src.contains("class DecoyLauncherActivity : LauncherEntryActivity()"),
        )
    }

    @Test
    fun `the manifest launcher aliases both point at the forwarding shims`() {
        val manifest = mainManifest()
        assertTrue(
            "the real launcher alias must resolve to the forwarding activity",
            manifest.contains("android:targetActivity=\".RealLauncherActivity\""),
        )
        assertTrue(
            "the decoy launcher alias must resolve to the forwarding activity",
            manifest.contains("android:targetActivity=\".DecoyLauncherActivity\""),
        )
        // Exactly two launcher entries exist, so MainActivity itself is never a
        // launcher: every path into the app goes through a forwarding shim.
        assertEquals(
            "expected exactly two LAUNCHER intent-filters",
            2,
            Regex("android.intent.category.LAUNCHER").findAll(manifest).count(),
        )
    }

    /** The launcher entry Kotlin source, discovered from the test working dir. */
    private fun launcherSource(): String =
        mainSourceFile("LauncherEntryActivity.kt")

    /** The phone app's `AndroidManifest.xml`, discovered from the test working dir. */
    private fun mainManifest(): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/main/AndroidManifest.xml",
                "android/app/src/main/AndroidManifest.xml",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate AndroidManifest.xml from ${System.getProperty("user.dir")}",
        )
    }

    private fun mainSourceFile(name: String): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/main/kotlin/org/winsvpn/app/$name",
                "android/app/src/main/kotlin/org/winsvpn/app/$name",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate $name from ${System.getProperty("user.dir")}",
        )
    }
}
