package org.winsvpn.app

import java.io.ByteArrayInputStream
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Document
import org.w3c.dom.Element

/**
 * D-PAD FOCUS ROUTE FOR THE TV FLAVOR MainActivity.
 *
 * The TV variant (`src/tv`) reuses the shared [MainActivity] and is driven by
 * a D-pad remote (leanback / TELEVISION uiMode with no touchscreen). For the
 * launcher to be reachable with a remote, the merged tv-flavor debug manifest
 * must carry `android:focusable="true"` (and `focusableInTouchMode`) on that
 * activity. `src/tv/AndroidManifest.xml` declares them, but the SOURCE file is
 * only half the route: AGP MERGES the main and tv manifests, and the merge is
 * what actually ships. A focus attribute that never survives the merge would
 * leave a source-level declaration that passes review while the shipped
 * activity is still unfocusable by D-pad.
 *
 * This guard therefore reads the MERGED tvDebug manifest that
 * `./gradlew assembleTvDebug` produced -- the debug manifest path -- and
 * asserts the resolving activity named `org.winsvpn.app.MainActivity` carries
 * the focus attributes. The merged manifest is the same artifact a
 * root-inspection of the packaged APK would reveal, made readable to a plain
 * JVM unit test.
 *
 * The debug manifest is the assembleTvDebug output; it exists only after that
 * task runs, so this suite's proper execution order is
 * `assembleTvDebug` then `testTvDebugUnitTest`.
 */
class TvDpadFocusRouteTest {

    @Test
    fun `merged tvDebug manifest is present at the debug manifest path`() {
        // A guard that cannot find its own fixture is a tautology that passes
        // by throwing in setup. Confirm the merged debug manifest exists and
        // is readable before any assertion on it is trusted.
        val manifest = mergedTvDebugManifest()
        assertTrue(
            "merged tvDebug manifest must exist and be readable at " +
                "${manifest.path} (run assembleTvDebug first)",
            manifest.isFile && manifest.canRead(),
        )
    }

    @Test
    fun `tv flavor MainActivity carries focusable true in the merged debug manifest`() {
        val mainActivity = mainActivityElement(parseXml(mergedTvDebugManifest().readText()))
        assertTrue(
            "merged tvDebug manifest must declare org.winsvpn.app.MainActivity with " +
                "android:focusable=\"true\" for D-pad focus to work",
            focusAttrTrue(mainActivity, "focusable"),
        )
    }

    @Test
    fun `tv flavor MainActivity carries focusableInTouchMode true in the merged debug manifest`() {
        val mainActivity = mainActivityElement(parseXml(mergedTvDebugManifest().readText()))
        assertTrue(
            "merged tvDebug manifest must declare org.winsvpn.app.MainActivity with " +
                "android:focusableInTouchMode=\"true\" for D-pad focus to work",
            focusAttrTrue(mainActivity, "focusableInTouchMode"),
        )
    }

    @Test
    fun `tv launcher entry points at MainActivity with LEANBACK_LAUNCHER in merged debug manifest`() {
        val doc = parseXml(mergedTvDebugManifest().readText())
        val mainActivity = mainActivityElement(doc)
        assertTrue(
            "the merged tvDebug MainActivity must be the LEANBACK_LAUNCHER so the " +
                "focus route is actually the one a TV remote launches",
            elementHasLeanbackCategory(mainActivity),
        )
    }

    @Test
    fun `the guard detects a MainActivity without focusable true`() {
        // Mutation control (negative). A resolving MainActivity that lost its
        // focusable attribute must NOT satisfy the guard, or the assertion has
        // no teeth against a merge that drops it.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <activity android:name="org.winsvpn.app.MainActivity"
                            android:exported="true" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertFalse(
            "MainActivity without android:focusable must not satisfy the focusable guard",
            focusAttrTrue(mainActivityElement(doc), "focusable"),
        )
    }

    @Test
    fun `the guard detects focusable false`() {
        // Mutation control. An explicit focusable="false" is the same failure
        // shape (not focusable by D-pad) and must be caught.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <activity android:name="org.winsvpn.app.MainActivity"
                            android:focusable="false"
                            android:focusableInTouchMode="false" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertFalse(
            "MainActivity with focusable=\"false\" must not satisfy the focusable guard",
            focusAttrTrue(mainActivityElement(doc), "focusable"),
        )
    }

    @Test
    fun `the guard passes a synthetic manifest with focusable true`() {
        // Positive control. A well-formed document must satisfy the guard, so
        // a guard that always reports false is visible rather than silent.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <activity android:name="org.winsvpn.app.MainActivity"
                            android:exported="true"
                            android:focusable="true"
                            android:focusableInTouchMode="true" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        val mainActivity = mainActivityElement(doc)
        assertTrue(
            "synthetic MainActivity with focusable=true must satisfy the guard",
            focusAttrTrue(mainActivity, "focusable") &&
                focusAttrTrue(mainActivity, "focusableInTouchMode"),
        )
    }

    // ---- helpers ---------------------------------------------------------

    private fun mainActivityElement(doc: Document): Element? {
        val activities = doc.getElementsByTagName("activity")
        return (0 until activities.length).firstOrNull { i ->
            val el = activities.item(i) as Element
            el.getAttribute("android:name") == "org.winsvpn.app.MainActivity"
        }?.let { activities.item(it) as Element }
    }

    private fun focusAttrTrue(mainActivity: Element?, attr: String): Boolean =
        mainActivity?.getAttribute("android:$attr") == "true"

    private fun elementHasLeanbackCategory(activity: Element?): Boolean {
        if (activity == null) return false
        val categories = activity.getElementsByTagName("category")
        return (0 until categories.length).any { i ->
            (categories.item(i) as Element).getAttribute("android:name") ==
                "android.intent.category.LEANBACK_LAUNCHER"
        }
    }

    private fun mergedTvDebugManifest(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "build/app/intermediates/merged_manifests/tvDebug/processTvDebugManifest/AndroidManifest.xml",
                "android/build/app/intermediates/merged_manifests/tvDebug/processTvDebugManifest/AndroidManifest.xml",
                "../../build/app/intermediates/merged_manifests/tvDebug/processTvDebugManifest/AndroidManifest.xml",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate the merged tvDebug AndroidManifest.xml from " +
                System.getProperty("user.dir") +
                " (run ./gradlew assembleTvDebug first)",
        )
    }

    private fun parseXml(xml: String): Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        return factory.newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
    }
}
