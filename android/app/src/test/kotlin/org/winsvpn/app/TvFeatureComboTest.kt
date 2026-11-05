package org.winsvpn.app

import java.io.ByteArrayInputStream
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.w3c.dom.Element

/**
 * The TV variant (`src/tv/AndroidManifest.xml`) must be installable on BOTH a
 * TV (leanback) and a phone-style device, so its single `<manifest>` must
 * declare, together, the Leanback software feature AND the touchscreen feature
 * marked `required="false"`.
 *
 * The two go together because each one is necessary and neither is sufficient:
 *   - `android.software.leanback` makes the platform treat the app as a TV app
 *     and appears in the TV launcher's app row. Without it the TV build is not
 *     even listed.
 *   - `android.hardware.touchscreen required="false"` tells the platform the
 *     app does NOT require a touchscreen. Without it, a TV (which has no
 *     touchscreen) is treated as not hardware-compatible and the app cannot be
 *     installed there at all. Android appends an implied
 *     `<uses-feature android:name="android.hardware.touchscreen" required="true">`
 *     when the manifest is silent, which would disqualify every touchless TV.
 *
 * So the TV manifest must carry BOTH declarations as direct children of the
 * same `<manifest>` element. Android's schema rejects `<uses-feature>` inside
 * `<application>`, so the scoping below asserts the packageable structure
 * rather than just that both strings appear somewhere in the file.
 *
 * The TV manifest is owned by another lane, so this class only ever READS it.
 * The only mutations exercised are against synthetic in-memory documents, never
 * the shared tree.
 */
class TvFeatureComboTest {

    @Test
    fun `tv manifest carries leanback AND touchscreen-not-required in one application`() {
        val manifest = singleManifest(tvManifest().readText())

        val leanback =
            feature(manifest, "android.software.leanback") != null
        val touchscreenNotRequired =
            feature(manifest, "android.hardware.touchscreen")?.let { it == "false" } == true

        assertTrue(
            "android/app/src/tv/AndroidManifest.xml must declare " +
                "<uses-feature android:name=\"android.software.leanback\" /> directly inside " +
                "<manifest> so the TV build is recognised as a TV app; it is absent",
            leanback,
        )
        assertTrue(
            "android/app/src/tv/AndroidManifest.xml must declare " +
                "<uses-feature android:name=\"android.hardware.touchscreen\" " +
                "android:required=\"false\" /> directly inside <manifest> so the build stays " +
                "installable on touchless TV hardware; it is absent or required=true",
            touchscreenNotRequired,
        )
    }

    @Test
    fun `the combo guard fails when leanback is missing`() {
        // Negative control against a synthetic document: a valid application that
        // omits leanback must be rejected by the same scoped check.
        val manifest =
            singleManifest(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="false" />
                    <application />
                </manifest>
                """.trimIndent(),
            )
        if (feature(manifest, "android.software.leanback") != null) {
            fail("synthetic manifest without leanback must not pass the combo guard")
        }
    }

    @Test
    fun `the combo guard fails when touchscreen is required`() {
        // Negative control: touchscreen present but required=true (the implied
        // default when omitted) must be rejected -- this is the touchless-TV
        // disqualification this combo exists to prevent.
        val manifest =
            singleManifest(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <uses-feature android:name="android.software.leanback" />
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="true" />
                    <application />
                </manifest>
                """.trimIndent(),
            )
        val required = feature(manifest, "android.hardware.touchscreen")
        if (required == "false") {
            fail("synthetic manifest with touchscreen required=true must not pass the combo guard")
        }
    }

    @Test
    fun `the tv manifest is present at the expected path`() {
        val manifest = tvManifest()
        assertTrue(
            "TV manifest must exist and be readable: ${manifest.path}",
            manifest.isFile && manifest.canRead(),
        )
    }

    /** The document's single `<manifest>` root; fails loudly on another root. */
    private fun singleManifest(xml: String): Element {
        val doc = parseXml(xml)
        val root = doc.documentElement
        if (root == null || root.tagName != "manifest") {
            fail("expected <manifest> as the document root")
        }
        return root
    }

    /**
     * The `android:required` attribute of the descendant `<uses-feature>` named
     * [name], or null if the feature is not declared as a direct child of
     * [manifest]. A nested declaration is invalid and cannot satisfy the guard.
     */
    private fun feature(manifest: Element, name: String): String? {
        val nodes = manifest.childNodes
        for (i in 0 until nodes.length) {
            val el = nodes.item(i) as? Element ?: continue
            if (el.tagName != "uses-feature") continue
            if (el.getAttribute("android:name") == name) {
                return el.getAttribute("android:required").ifBlank { null }
            }
        }
        return null
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
