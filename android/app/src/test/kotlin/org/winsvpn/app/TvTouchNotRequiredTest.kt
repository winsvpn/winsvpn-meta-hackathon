package org.winsvpn.app

import java.io.ByteArrayInputStream
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Android TV / Google TV installs normally sit on devices with no touchscreen,
 * so a manifest that declares `android.hardware.touchscreen` as `required`
 * (either omitted, which defaults to `true`, or explicitly `required="true"`)
 * causes the Play Store to filter the app out of the TV storefront entirely and
 * can influence install enablement on TV hardware. This guard reads the TV
 * variant's manifest (the source set that actually ships a TV build) and fails
 * unless it declares:
 *
 *     <uses-feature android:name="android.hardware.touchscreen"
 *         android:required="false" />
 *
 * The TV manifest is owned by another lane (`src/tv/AndroidManifest.xml`), so
 * this class only ever READS it; every mutation control is exercised against a
 * synthetic in-memory document, never the shared tree.
 */
class TvTouchNotRequiredTest {

    @Test
    fun `the tv manifest declares touchscreen not required`() {
        val manifest = tvManifest()
        assertTrue(
            "android/app/src/tv/AndroidManifest.xml must declare " +
                "<uses-feature android:name=\"android.hardware.touchscreen\" " +
                "android:required=\"false\">; the declaration is absent or not " +
                "marked not-required",
            declaresTouchscreenNotRequired(parseXml(manifest.readText())),
        )
    }

    @Test
    fun `the tv manifest is present at the expected path`() {
        // A guard that cannot find its own fixture is not a guard; it is a
        // tautology that always passes by throwing in setup. Locate and
        // confirm the file before the feature assertion above is trusted.
        val manifest = tvManifest()
        assertTrue(
            "TV manifest must exist and be readable: ${manifest.path}",
            manifest.isFile && manifest.canRead(),
        )
    }

    @Test
    fun `the guard detects touchscreen declared required true`() {
        // Mutation control. required="true" must NOT satisfy the guard, or the
        // assertion has no teeth.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <uses-feature android:name="android.hardware.touchscreen"
                            android:required="true" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertFalse(
            "touchscreen with required=\"true\" must not satisfy the not-required guard",
            declaresTouchscreenNotRequired(doc),
        )
    }

    @Test
    fun `the guard detects a missing required attribute`() {
        // A missing `android:required` defaults to `true` on the platform, so
        // it is the same failure shape and must not satisfy the guard either.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <uses-feature android:name="android.hardware.touchscreen" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertFalse(
            "touchscreen without android:required must not satisfy the not-required guard",
            declaresTouchscreenNotRequired(doc),
        )
    }

    @Test
    fun `the guard detects an absent touchscreen feature`() {
        // A manifest with no touchscreen declaration at all must not satisfy
        // the guard.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <uses-feature android:name="android.software.leanback"
                            android:required="false" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertFalse(
            "manifest without a touchscreen feature must not satisfy the guard",
            declaresTouchscreenNotRequired(doc),
        )
    }

    @Test
    fun `the guard detects a touchscreen feature not marked not-required even when leanback present`() {
        // A focused positive: the exact real shape (both features declared) with
        // the touchscreen flipped to required must be caught. Proves the guard
        // inspects each uses-feature node rather than assuming the first match.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <uses-feature android:name="android.software.leanback"
                            android:required="false" />
                        <uses-feature android:name="android.hardware.touchscreen"
                            android:required="true" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertFalse(
            "touchscreen required within a realistic two-feature TV manifest must be caught",
            declaresTouchscreenNotRequired(doc),
        )
    }

    @Test
    fun `the guard passes a synthetic manifest correctly marking touchscreen not required`() {
        // Positive control: a well-formed document must satisfy the guard, so a
        // guard that always reports false is visible rather than silent.
        val doc =
            parseXml(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <uses-feature android:name="android.hardware.touchscreen"
                            android:required="false" />
                    </application>
                </manifest>
                """.trimIndent(),
            )
        assertTrue(
            "well-formed touchscreen required=\"false\" must satisfy the guard",
            declaresTouchscreenNotRequired(doc),
        )
    }

    private fun declaresTouchscreenNotRequired(doc: org.w3c.dom.Document): Boolean {
        val nodes = doc.getElementsByTagName("uses-feature")
        return (0 until nodes.length).any { i ->
            val el = nodes.item(i) as org.w3c.dom.Element
            el.getAttribute("android:name") == "android.hardware.touchscreen" &&
                el.getAttribute("android:required") == "false"
        }
    }

    private fun tvManifest(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf("src/tv/AndroidManifest.xml", "android/app/src/tv/AndroidManifest.xml")) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate android/app/src/tv/AndroidManifest.xml from " +
                System.getProperty("user.dir"),
        )
    }

    private fun parseXml(xml: String): org.w3c.dom.Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        return factory.newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
    }
}
