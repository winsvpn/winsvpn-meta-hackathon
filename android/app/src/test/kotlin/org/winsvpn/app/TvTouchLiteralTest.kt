package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The TV variant's manifest must keep the touchscreen feature as a
 * REQUIRED=FALSE LITERAL in the source, not as a resource indirection such as
 * `android:required="@bool/touchscreen_required"`.
 *
 * Why the literal matters: `android:required` is read directly off the
 * manifest element by the platform and by the Play storefront filter. A
 * resource reference is resolved only by tooling that understands it; a raw
 * manifest (or a partial merge, or a consumer that does not allocate the bool)
 * sees the reference and can treat the feature as required-by-default, which
 * drops the app off non-touch TV/tablet devices. The earlier
 * [TvTouchNotRequiredTest] already proves the value resolves to `false`; this
 * guard proves the source says it literally, so no resolution step can turn it
 * into anything else.
 *
 * The TV manifest is owned by another lane (`src/tv/AndroidManifest.xml`), so
 * this class only ever READS it; every mutation control is exercised against a
 * synthetic in-memory string, never the shared tree.
 */
class TvTouchLiteralTest {

    @Test
    fun `the tv manifest writes touchscreen required false as a literal`() {
        val manifest = tvManifest()
        val xml = stripXmlComments(manifest.readText())
        val touchBlock = usesFeatureBlock(xml, "android.hardware.touchscreen")
        assertTrue(
            "android/app/src/tv/AndroidManifest.xml must carry the literal " +
                "android:required=\"false\" on the touchscreen uses-feature line; " +
                "a resource indirection (e.g. @bool/...) fails this guard. Found: " +
                touchBlock,
            touchBlock.contains("android:required=\"false\""),
        )
    }

    @Test
    fun `the tv manifest is present at the expected path`() {
        // A guard that cannot find its own fixture is not a guard; it is a
        // tautology that always passes by throwing in setup. Locate and
        // confirm the file before the literal assertion above is trusted.
        val manifest = tvManifest()
        assertTrue(
            "TV manifest must exist and be readable: ${manifest.path}",
            manifest.isFile && manifest.canRead(),
        )
    }

    @Test
    fun `the guard rejects a resource-indirection required value`() {
        // The exact failure the guard exists to catch: required points at a
        // resource, not at a literal "false". Must NOT pass.
        val xml =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="@bool/touchscreen_not_required" />
                </application>
            </manifest>
            """.trimIndent()
        val touchBlock = usesFeatureBlock(xml, "android.hardware.touchscreen")
        assertFalse(
            "android:required=\"@bool/...\" must not satisfy the literal guard",
            touchBlock.contains("android:required=\"false\""),
        )
    }

    @Test
    fun `the guard rejects required true`() {
        val xml =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="true" />
                </application>
            </manifest>
            """.trimIndent()
        val touchBlock = usesFeatureBlock(xml, "android.hardware.touchscreen")
        assertFalse(
            "android:required=\"true\" must not satisfy the literal guard",
            touchBlock.contains("android:required=\"false\""),
        )
    }

    @Test
    fun `the guard rejects a missing required attribute`() {
        val xml =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.hardware.touchscreen" />
                </application>
            </manifest>
            """.trimIndent()
        val touchBlock = usesFeatureBlock(xml, "android.hardware.touchscreen")
        assertFalse(
            "a touchscreen uses-feature with no required attribute must not " +
                "satisfy the literal guard",
            touchBlock.contains("android:required=\"false\""),
        )
    }

    @Test
    fun `the guard passes the real two-feature shape`() {
        // Positive control mirroring the actual tv manifest: leanback then
        // touchscreen, both literals. Must PASS, or the guard is broken.
        val xml =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <uses-feature android:name="android.software.leanback"
                        android:required="false" />
                    <uses-feature android:name="android.hardware.touchscreen"
                        android:required="false" />
                </application>
            </manifest>
            """.trimIndent()
        val touchBlock = usesFeatureBlock(xml, "android.hardware.touchscreen")
        assertTrue(
            "two-feature tv shape with literal false must satisfy the guard",
            touchBlock.contains("android:required=\"false\""),
        )
    }

    private fun usesFeatureBlock(xml: String, featureName: String): String {
        val marker = "<uses-feature"
        var index = xml.indexOf(marker)
        while (index >= 0) {
            val end = xml.indexOf('>', index)
            if (end < 0) throw AssertionError("unterminated $marker")
            val block = xml.substring(index, end + 1)
            val name = Regex("android:name=\"([^\"]*)\"")
                .find(block)
                ?.groupValues
                ?.get(1)
            if (name == featureName) return block
            index = xml.indexOf(marker, end + 1)
        }
        throw AssertionError("no <uses-feature> for $featureName in the TV manifest")
    }

    private fun stripXmlComments(xml: String): String =
        xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")

    private fun tvManifest(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/tv/AndroidManifest.xml",
                "android/app/src/tv/AndroidManifest.xml",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "TV manifest not found at android/app/src/tv/AndroidManifest.xml from " +
                System.getProperty("user.dir"),
        )
    }
}
