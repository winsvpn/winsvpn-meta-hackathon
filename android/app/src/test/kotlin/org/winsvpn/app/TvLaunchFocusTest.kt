package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FOCUS-SAFETY FOR THE TV LAUNCH ACTIVITY.
 *
 * The TV variant (`src/tv`) has no Kotlin source of its own: it reuses the
 * application's [MainActivity], which `src/tv/AndroidManifest.xml` declares as
 * both the LAUNCHER and the LEANBACK_LAUNCHER activity. A leanback build is
 * driven by a D-pad remote, so the launch activity must be focus-safe -- it
 * must not intercept touch events in a way that would swallow D-pad
 * navigation and lock the user out.
 *
 * The decisive signal on Android is an `onTouchEvent` / `dispatchTouchEvent`
 * override in the activity. A FlutterActivity subclass that overrode
 * `onTouchEvent` to consume touches (the "decoy calculator" Material+InkWell
 *+onTap pattern this repo explicitly keeps OFF the TV build -- see the
 * `src/tv/AndroidManifest.xml` header comment) would make the launcher
 * effectively touch-only, unreachable with a remote. This test pins the
 * negative: the launch activity declares NO touch-only event handling.
 *
 * It reads `MainActivity.kt` and `src/tv/AndroidManifest.xml` off disk
 * (walking up from the Gradle test working directory), which is the only way
 * a plain JVM unit test can inspect the compiled-away source of an Android
 * `Activity` without Robolectric. The manifest check is what anchors the
 * assertion to the TV variant: without it, this test could silently be
 * inspecting a class the TV build never launches.
 */
class TvLaunchFocusTest {

    @Test
    fun `the TV launcher activity is MainActivity`() {
        val tvManifest = tvManifest()!!
        val text = stripXmlComments(tvManifest.readText())
        val activityTag = activityTagRecord(text, "android.intent.action.MAIN")
        assertTrue(
            "src/tv must declare the LAUNCHER activity as MainActivity",
            activityTag != null &&
                activityTag.contains("org.winsvpn.app.MainActivity"),
        )
        assertTrue(
            "the TV launcher must carry the LEANBACK_LAUNCHER category",
            text.contains("android.intent.category.LEANBACK_LAUNCHER"),
        )
    }

    @Test
    fun `MainActivity declares no onTouchEvent override requirement`() {
        val mainActivity = mainSource("MainActivity.kt")

        // The touch-consumption overrides. Either one existing in the launch
        // activity is a touch-only event-handling requirement that would
        // break D-pad focus on a leanback build.
        assertFalse(
            "MainActivity must not override onTouchEvent: a touch-only override " +
                "would make the TV launcher unreachable with a D-pad remote",
            Regex("""override\s+fun\s+onTouchEvent\s*\(""").containsMatchIn(mainActivity),
        )
        assertFalse(
            "MainActivity must not override dispatchTouchEvent: a touch-only " +
                "override would make the TV launcher unreachable with a D-pad remote",
            Regex("""override\s+fun\s+dispatchTouchEvent\s*\(""").containsMatchIn(mainActivity),
        )

        // Belt-to-braces: even a bare (non-override) reference is a smell, but
        // the load-bearing negative is the two override assertions above.
        assertFalse(
            "MainActivity must not reference onTouchEvent at all",
            mainActivity.contains("onTouchEvent("),
        )
        assertFalse(
            "MainActivity must not reference dispatchTouchEvent at all",
            mainActivity.contains("dispatchTouchEvent("),
        )
    }

    @Test
    fun `MainActivity stays input-method pipe open for D-pad focus`() {
        // A FlutterActivity launch keeps Android's default key/focus
        // plumbing. Nothing in the activity may disable key events coming in.
        // This is the positive side of the same invariant: the widget system
        // and the platform need key events, so the activity must not turn
        // them off with FLAG_NOT_FOCUSABLE.
        val mainActivity = mainSource("MainActivity.kt")
        assertFalse(
            "MainActivity must not set FLAG_NOT_FOCUSABLE: that would disable " +
                "all D-pad/key focus on the TV launcher",
            mainActivity.contains("FLAG_NOT_FOCUSABLE"),
        )
    }

    // ---- source locating -------------------------------------------------

    private fun tvManifest(): File? {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf("src/tv/AndroidManifest.xml", "android/app/src/tv/AndroidManifest.xml")) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        return null
    }

    private fun mainSource(name: String): String {
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

    /** XML with comments removed, so no `>` inside a comment ends a tag. */
    private fun stripXmlComments(xml: String): String =
        xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")

    /**
     * The `<activity ...>` record in [text] that contains an intent-filter
     * with the given [action]. Returns null if no activity declares it. The
     * record is counted only to the tag boundary it belongs to, so a match
     * cannot come from a different activity in the same manifest.
     */
    private fun activityTagRecord(text: String, action: String): String? {
        val pattern = Regex("""<activity\b[^>]*>""", RegexOption.DOT_MATCHES_ALL)
        for (match in pattern.findAll(text)) {
            val fromActivity = text.indexOf("</activity>", match.range.last)
            val end = if (fromActivity >= 0) fromActivity else match.range.last
            val record = text.substring(match.range.first, end)
            if (record.contains(action)) return record
        }
        return null
    }
}
