package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TV BANNER REFERENCE GUARD.
 *
 * Android TV surfaces the app's `android:banner` drawable on the TV launcher's
 * "apps" row (and as the card shown when the app has no live preview). If the
 * reference is missing or the drawable it points at is empty, the TV build
 * either fails to resolve the resource at runtime or shows a blank/placeholder
 * card. This class pins BOTH halves:
 *
 *   1. `src/tv/AndroidManifest.xml` declares the application-level
 *      `android:banner="@drawable/banner"`.
 *   2. `src/tv/res/drawable-xhdpi/banner.png` exists and is non-empty.
 *
 * The manifest and the banner drawable are owned by other lanes, so this class
 * only ever READS them off disk (walking up from the Gradle test working
 * directory, the same convention as the other TV manifest guards). All
 * mutation controls run against synthetic in-memory strings, never against the
 * shared tree.
 *
 * Both a positive control (a synthetic manifest that DOES declare the banner is
 * detected) and a negative control (a synthetic manifest without it is not) are
 * present, so the reference detection cannot silently become a tautology.
 */
class TvBannerRefTest {

    @Test
    fun `the tv manifest declares the banner drawable on the application`() {
        val text = tvManifestText()
        assertTrue(
            "src/tv/AndroidManifest.xml must declare " +
                "android:banner=\"@drawable/banner\" on the <application> tag so " +
                "Android TV can show the app on the launcher; it is absent:\n$text",
            manifestDeclaresBanner(text),
        )
    }

    @Test
    fun `the banner reference really is detected when present`() {
        // POSITIVE control: prove the detector can see the reference at all,
        // so a pass above cannot be an artifact of an always-green detector.
        val withBanner =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:label="Win's VPN" android:banner="@drawable/banner">
                    <activity android:name="org.winsvpn.app.MainActivity" />
                </application>
            </manifest>
            """.trimIndent()
        assertTrue(
            "synthetic manifest declaring android:banner must be detected",
            manifestDeclaresBanner(withBanner),
        )
    }

    @Test
    fun `a manifest missing the banner reference is not detected`() {
        // NEGATIVE control: the same detector must NOT match a manifest whose
        // application lacks the banner attribute, or the positive assertion
        // above is meaningless.
        val withoutBanner =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application android:label="Win's VPN">
                    <activity android:name="org.winsvpn.app.MainActivity" />
                </application>
            </manifest>
            """.trimIndent()
        assertFalse(
            "synthetic manifest without android:banner must not be detected",
            manifestDeclaresBanner(withoutBanner),
        )
    }

    @Test
    fun `the tv banner drawable exists and is non-empty`() {
        val png = bannerPng()
        assertTrue(
            "src/tv banner drawable must exist and be readable: ${png.path}",
            png.isFile && png.canRead(),
        )
        val bytes = png.length()
        assertTrue(
            "src/tv banner PNG must be non-empty; ${png.path} is $bytes bytes",
            bytes > 0,
        )
    }

    @Test
    fun `a zero-byte banner is caught by the non-empty guard`() {
        // NEGATIVE control for the size assertion: a synthetic empty file must
        // NOT satisfy the non-empty check, so a live zero-byte PNG cannot pass
        // silently. Never touches the shared tree.
        val syntheticEmpty = java.io.File.createTempFile("tv_banner_empty", ".png")
        try {
            assertFalse(
                "a zero-byte banner must not be treated as non-empty",
                syntheticEmpty.length() > 0,
            )
        } finally {
            syntheticEmpty.delete()
        }
    }

    @Test
    fun `the tv manifest is present at the expected path`() {
        // A guard that cannot find its own fixture is not a guard; it is a
        // tautology that throws in setup. Locate and confirm the file first.
        val manifest = tvManifest()
        assertTrue(
            "TV manifest must exist and be readable: ${manifest.path}",
            manifest.isFile && manifest.canRead(),
        )
    }

    // ---- detection -------------------------------------------------------

    private fun manifestDeclaresBanner(text: String): Boolean {
        // The reference appears on the root <application ...> element. Match
        // the exact attribute spelling (no whitespace around the '=' matters
        // here only if it is present in the file; the manifest keeps it flush).
        return Regex("""android:banner\s*=\s*"@drawable/banner"""").containsMatchIn(text)
    }

    // ---- source locating ------------------------------------------------

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
            "could not locate android/app/src/tv/AndroidManifest.xml from " +
                System.getProperty("user.dir"),
        )
    }

    private fun tvManifestText(): String {
        val manifest = tvManifest()
        // Remove comment blocks so a `>` inside a comment cannot fake a match.
        return manifest.readText().replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
    }

    private fun bannerPng(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/tv/res/drawable-xhdpi/banner.png",
                "android/app/src/tv/res/drawable-xhdpi/banner.png",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate android/app/src/tv/res/drawable-xhdpi/banner.png from " +
                System.getProperty("user.dir"),
        )
    }
}
