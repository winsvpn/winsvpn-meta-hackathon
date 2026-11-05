package org.winsvpn.app

import java.io.ByteArrayInputStream
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Android TV / Google TV installs require the app to declare the Leanback
 * (`android.software.leanback`) software feature or the platform will not
 * treat it as a TV app: it stays absent from the TV launcher's "apps" row and,
 * for Play, from the TV-facing catalogue entirely. This guard reads the TV
 * variant's manifest (the source set that actually ships a TV build) and fails
 * if that declaration is missing.
 *
 * The TV manifest is owned by another lane (`src/tv/AndroidManifest.xml`), so
 * this class only ever READS it; the only mutation exercised is against a
 * synthetic in-memory document, never the shared tree.
 */
class TvLeanbackFeatureTest {

    @Test
    fun `the tv manifest declares android dot software dot leanback`() {
        val manifest = tvManifest()
        val doc = parseXml(manifest.readText())
        val nodes = doc.getElementsByTagName("uses-feature")

        val declared =
            (0 until nodes.length).any { i ->
                (nodes.item(i) as org.w3c.dom.Element)
                    .getAttribute("android:name") == "android.software.leanback"
            }

        assertTrue(
            "android/app/src/tv/AndroidManifest.xml must declare " +
                "<uses-feature android:name=\"android.software.leanback\"> so the TV " +
                "build is recognised as a TV app; it is absent",
            declared,
        )
    }

    @Test
    fun `the guard really detects a manifest missing the leanback feature`() {
        // Mutation control against a synthetic document, never the shared tree.
        val withoutLeanback =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="false" />
                </application>
            </manifest>
            """.trimIndent()

        val doc = parseXml(withoutLeanback)
        val nodes = doc.getElementsByTagName("uses-feature")
        val declared =
            (0 until nodes.length).any { i ->
                (nodes.item(i) as org.w3c.dom.Element)
                    .getAttribute("android:name") == "android.software.leanback"
            }
        if (declared) fail("synthetic manifest without leanback must not be detected")
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

    private fun tvManifest(): File {
        // Gradle unit tests run with the working directory set to `android/app`,
        // but the test must also work from an IDE or a repo-root launch at any
        // depth, so the manifest is located by walking up and trying every
        // plausible relative path at each level (including the `source/wins_vpn`
        // repo layout) rather than assuming a single working directory.
        val candidates =
            listOf(
                "src/tv/AndroidManifest.xml",
                "android/app/src/tv/AndroidManifest.xml",
                "source/wins_vpn/android/app/src/tv/AndroidManifest.xml",
                "wins_vpn/android/app/src/tv/AndroidManifest.xml",
            )
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in candidates) {
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
