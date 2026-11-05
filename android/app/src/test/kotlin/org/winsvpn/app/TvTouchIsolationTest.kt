package org.winsvpn.app

import java.io.ByteArrayInputStream
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.w3c.dom.Document
import org.w3c.dom.Element

/**
 * TV/PHONE SURFACE ISOLATION FOR "TOUCHSCREEN NOT REQUIRED".
 *
 * The TV variant and the phone variant must declare touchscreen policy in
 * DIFFERENT manifests. The TV build (`src/tv/AndroidManifest.xml`) is the
 * surface that is allowed to opt out of a touchscreen: Android TV boxes and
 * sticks are driven by a D-pad remote, so `android.hardware.touchscreen` with
 * `android:required="false"` lives there -- without it a TV device would demand
 * a touchscreen it does not have and refuse to install.
 *
 * The phone surface is the opposite. The phone is a touch-first disguise (the
 * camo/decoy surface this repo explicitly keeps off the TV build -- see the
 * `src/tv/AndroidManifest.xml` header comment). If the shared
 * `src/main/AndroidManifest.xml` were to hard-require
 * `android.hardware.touchscreen = false`, two things go wrong: the phone build
 * would advertise itself as NOT needing a touchscreen, which lets it install on
 * TV/non-touch devices where the touch-only decoy would lock the user out; and
 * it would silently couple the two surfaces, so a touchscreen policy change
 * meant to be TV-only would leak into every phone install. This class pins the
 * invariant that `src/main` is NOT the source of touchscreen-not-required.
 *
 * It reads `src/main/AndroidManifest.xml` and `src/tv/AndroidManifest.xml` off
 * disk (walking up from the Gradle test working directory), mirroring
 * [TvLeanbackFeatureTest] and [TvLaunchFocusTest]. The only mutation exercised
 * is against a synthetic in-memory document, never the shared tree.
 */
class TvTouchIsolationTest {

    @Test
    fun `the phone main manifest does not hard-require touchscreen not-required`() {
        val main = mainManifest()
        assertTrue(
            "phone main manifest must exist and be readable: ${main.path}",
            main.isFile && main.canRead(),
        )
        val doc = parseXml(main.readText())
        assertTrue(
            "android/app/src/main/AndroidManifest.xml must NOT declare " +
                "<uses-feature android:name=\"android.hardware.touchscreen\" " +
                "android:required=\"false\">. touchscreen-not-required is a TV-surface " +
                "invariant; on the shared/phone manifest it would advertise the phone " +
                "as installable on non-touch TV devices and lock the decoy out",
            !hasTouchscreenRequiredFalse(doc),
        )
    }

    @Test
    fun `touchscreen not-required is a tv-surface invariant, not a phone one`() {
        val main = parseXml(mainManifest().readText())
        val tv = parseXml(tvManifest().readText())

        assertTrue(
            "the TV manifest must declare touchscreen not-required so a remote-only " +
                "device can install it",
            hasTouchscreenRequiredFalse(tv),
        )
        assertTrue(
            "the phone main manifest must NOT declare touchscreen not-required -- " +
                "tv and phone surfaces must stay distinct and the phone must keep " +
                "claiming a touchscreen",
            !hasTouchscreenRequiredFalse(main),
        )
    }

    @Test
    fun `the negative guard detects a main manifest that hard-requires touchscreen false`() {
        // Mutation control against a synthetic document, never the shared tree.
        // The positive assertion above must have a failure mode; if the guard
        // cannot see a hard-required touchscreen=false it is a tautology.
        val synthetic =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="false" />
                </application>
            </manifest>
            """.trimIndent()
        val doc = parseXml(synthetic)
        assertTrue(
            "synthetic main manifest with touchscreen required=false must be detected",
            hasTouchscreenRequiredFalse(doc),
        )
    }

    @Test
    fun `the guard does not mistake a required-true touchscreen for a not-required one`() {
        // The phone sharing a manifest with the TV surface must not cause a false
        // green either: a touchscreen declared required=true (a normal phone) is
        // NOT the forbidden hard-required=false form and must not be flagged.
        val synthetic =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="true" />
                </application>
            </manifest>
            """.trimIndent()
        val doc = parseXml(synthetic)
        if (hasTouchscreenRequiredFalse(doc)) {
            fail("required=true touchscreen must not be treated as required=false")
        }
    }

    // ---- feature detection ----------------------------------------------

    private fun hasTouchscreenRequiredFalse(doc: Document): Boolean {
        val featureNodes = doc.getElementsByTagName("uses-feature")
        for (i in 0 until featureNodes.length) {
            val el = featureNodes.item(i) as Element
            if (el.getAttribute("android:name") == "android.hardware.touchscreen") {
                if (el.getAttribute("android:required").equals("false", ignoreCase = true)) {
                    return true
                }
            }
        }
        return false
    }

    // ---- source locating -------------------------------------------------

    private fun mainManifest(): File =
        locateManifest(listOf("src/main/AndroidManifest.xml", "android/app/src/main/AndroidManifest.xml"))

    private fun tvManifest(): File =
        locateManifest(listOf("src/tv/AndroidManifest.xml", "android/app/src/tv/AndroidManifest.xml"))

    private fun locateManifest(relativePaths: List<String>): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in relativePaths) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate ${relativePaths.last()} from " +
                System.getProperty("user.dir"),
        )
    }

    private fun parseXml(xml: String): Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        return factory.newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
    }
}
