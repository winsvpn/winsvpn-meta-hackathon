package org.winsvpn.app

import android.app.Instrumentation
import android.app.UiAutomation
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.SystemClock
import android.view.KeyEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.BufferedReader
import java.io.InputStreamReader
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real-device (ZY22GTV6Z3) proof that a D-pad DPAD_DOWN key event lands focus on a
 * control wrapped by the TV focus decoration from `lib/tv_dpad_support.dart` and that
 * the amber `kTvFocusColor` (#FFD21F) ring is visible on screen.
 *
 * It is scored as a differential, not an assertion on a single painting state:
 *   - it records the amber-ring pixel footprint BEFORE any D-pad input (negative
 *     control: a screen that already shows the ring cannot demonstrate the event
 *     moved focus onto a decorated control);
 *   - it sends a real DPAD_DOWN key event into the foreground activity;
 *   - it asserts the amber `#FFD21F` footprint is materially LARGER after the event
 *     AND above an absolute threshold (POSITIVE control). The ring is drawn only by
 *     TvFocusDecoration/TvActivatable when their child has focus, so a post-event
 *     amber ring is exactly "focus landed on the decorated control".
 *   - it also verifies the app's own TV traversal telemetry line (`TVD_FOCUS order=`,
 *     emitted by TvDpadWrapper when focus moves to an ordered control) reached logcat,
 *     read back in-process from the debuggable target's own UID.
 *
 * The tv-debug APK uses `org.winsvpn.app.debug`. Phone and TV release variants
 * must share `org.winsvpn.app` for one Play listing, so the two debug flavors
 * are tested separately rather than installed side by side. It drives the REAL
 * phone, never an emulator.
 */
@RunWith(AndroidJUnit4::class)
class TvDpadRealPhoneTest {

    private val instrumentation: Instrumentation = InstrumentationRegistry.getInstrumentation()
    private val automation: UiAutomation = instrumentation.uiAutomation

    // kTvFocusColor from lib/tv_dpad_support.dart = Color(0xFFFFD21F) -> RGB(255, 210, 31).
    private val amberArgb: Int = Color.rgb(0xFF, 0xD2, 0x1F)

    private companion object {
        const val TARGET_PKG = "org.winsvpn.app.debug"
        const val SCREEN_WAIT_MS = 18_000L
        const val SETTLE_MS = 2_000L
        // Absolute floor so a handful of stray near-amber pixels can never pass.
        const val MIN_AMBER_PIXELS = 80
        const val MIN_AMBER_DELTA = 80
    }

    @Test
    fun dpadDownLandsFocusOnDecoratedControl_and_amberRingShown() {
        wakeAndUnlock()

        val launchIntent = instrumentation.targetContext.packageManager
            .getLaunchIntentForPackage(TARGET_PKG)
        assertNotNull("tv-debug package ($TARGET_PKG) must resolve a launcher intent", launchIntent)
        launchIntent!!.addFlags(
            Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK,
        )
        instrumentation.targetContext.startActivity(launchIntent)
        SystemClock.sleep(SCREEN_WAIT_MS)

        clearLogcat()

        // NEGATIVE control: amber footprint with no D-pad input.
        val beforeAmber = countAmberPixels()

        // Send a real downward D-pad key event into the foreground activity.
        instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_DPAD_DOWN)
        SystemClock.sleep(SETTLE_MS)

        val afterAmber = countAmberPixels()

        // POSITIVE: the amber ring (#FFD21F) is now on screen above an absolute floor.
        assertTrue(
            "DPAD_DOWN must leave the amber kTvFocus ring (#FFD21F) on screen; " +
                "amber pixels before=$beforeAmber after=$afterAmber",
            afterAmber >= MIN_AMBER_PIXELS,
        )

        // POSITIVE differential: the event actually moved focus onto a decorated
        // control. If the ring were already showing before, the event proved nothing.
        assertTrue(
            "DPAD_DOWN must increase the amber ring footprint (focus moved onto the " +
                "decorated control); before=$beforeAmber after=$afterAmber",
            afterAmber > beforeAmber + MIN_AMBER_DELTA,
        )

        // The app's own traversal telemetry confirms focus is on an ordered/decorated
        // control (TvDpadWrapper logs `TVD_FOCUS order=<n>` when focus moves).
        val focusLines = readLogcatFor("TVD_FOCUS order=")
        assertTrue(
            "TvDpadWrapper telemetry must report focus on an ordered control after " +
                "DPAD_DOWN (saw: ${focusLines.joinToString(" | ").ifBlank { "<none>" }})",
            focusLines.isNotEmpty(),
        )
    }

    private fun wakeAndUnlock() {
        // Best-effort: bring the phone out of sleep and past keyguard so key events
        // and screenshots are meaningful. Failures here are non-fatal (the runner
        // keeps the device awake on its own in most connected-test setups).
        runCatching { automation.executeShellCommand("input keyevent KEYCODE_WAKEUP").close() }
        runCatching { automation.executeShellCommand("wm dismiss-keyguard").close() }
        SystemClock.sleep(1_500L)
    }

    private fun clearLogcat() {
        try {
            val p = Runtime.getRuntime().exec(arrayOf("logcat", "-c"))
            p.waitFor()
        } catch (_: Exception) {
            // Not fatal; the read below degrades to whatever logcat already holds.
        }
    }

    private fun readLogcatFor(substring: String): List<String> {
        return try {
            val p = Runtime.getRuntime()
                .exec(arrayOf("logcat", "-d", "-v", "brief", "-s", "flutter:I", "*:S"))
            val out = StringBuilder()
            BufferedReader(InputStreamReader(p.inputStream)).use { r ->
                var line: String? = r.readLine()
                while (line != null) {
                    out.append(line).append('\n')
                    line = r.readLine()
                }
            }
            val all = out.toString()
            all.lines()
                .filter { it.contains(substring) }
                .map { it.trim() }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Counts screen pixels close to the amber ring color, sampling the full frame. */
    private fun countAmberPixels(): Int {
        val shot: Bitmap = automation.takeScreenshot() ?: error("UiAutomation.takeScreenshot() returned null")
        val w = shot.width
        val h = shot.height
        val pixels = IntArray(w * h)
        shot.getPixels(pixels, 0, w, 0, 0, w, h)
        var count = 0
        for (p in pixels) {
            val r = (p shr 16) and 0xFF
            val g = (p shr 8) and 0xFF
            val b = p and 0xFF
            // Amber: r high, g mid, b low. Tolerance around (255,210,31).
            val dr = r - 255
            val dg = g - 210
            val db = b - 31
            if (dr * dr + dg * dg + db * db <= 45 * 45) count++
        }
        return count
    }
}
