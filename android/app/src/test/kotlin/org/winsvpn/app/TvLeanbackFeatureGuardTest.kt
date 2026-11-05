@file:Suppress("ObjectPropertyName")

package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * JVM guard for the TV variant's leanback declaration.
 *
 * The Android TV build must be recognised as a TV app by the platform and by
 * Play's TV catalogue, which requires the merged manifest to declare
 * `<uses-feature android:name="android.software.leanback">`. The declaration
 * must stay `required="false"`: `required="true"` filters the app off every
 * non-TV device -- most importantly every tablet.
 *
 * Unlike an instrumented/Android test this is a plain JVM (host) test: it reads
 * `android/app/src/tv/AndroidManifest.xml` straight off disk and asserts on the
 * literal text, so it runs anywhere `testDebugUnitTest` can, needs no device
 * and no merged-manifest task to be executed.
 */
class TvLeanbackFeatureGuardTest {

    private val leanback = "android.software.leanback"

    /** The guard's own detection of a feature declaration in a manifest body. */
    private fun usesFeatureDeclared(xml: String, featureName: String): Boolean =
        usesFeature(xml, featureName) != null

    /** The `android:required` value of the feature's block, or null if absent. */
    private fun requiredValue(xml: String, featureName: String): String? =
        usesFeature(xml, featureName)
            ?.let { block -> Regex("android:required=\"([^\"]*)\"").find(block)?.groupValues?.get(1) }

    /** True when the feature is declared AND pinned to required="false". */
    private fun isNonRequired(xml: String, featureName: String): Boolean =
        requiredValue(xml, featureName) == "false"

    @Test
    fun `tv manifest declares leanback as a non-required feature`() {
        val xml = tvManifest().readText()

        assertTrue(
            "android/app/src/tv/AndroidManifest.xml must declare " +
                "<uses-feature android:name=\"$leanback\"> so the TV build is " +
                "recognised as a TV app; it is absent",
            usesFeatureDeclared(xml, leanback),
        )

        assertTrue(
            "android.software.leanback must be declared required=\"false\"; " +
                "required=true filters the app off non-TV devices (tablets) on Play",
            isNonRequired(xml, leanback),
        )
    }

    @Test
    fun `negative control - an absent feature name never passes`() {
        // A guard whose positive assertion can never go red is not evidence.
        // Feed the detection logic a manifest body with NO leanback declaration
        // and require it to NOT be detected and NOT be considered non-required.
        val withoutLeanback =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-feature android:name="android.hardware.touchscreen" android:required="false" />
                <application/>
            </manifest>
            """.trimIndent()

        assertFalse(
            "detector must not report the leanback feature in a manifest that lacks it",
            usesFeatureDeclared(withoutLeanback, leanback),
        )

        assertFalse(
            "absent feature must not satisfy the non-required predicate",
            isNonRequired(withoutLeanback, leanback),
        )
    }

    @Test
    fun `negative control - required true is not accepted as non required`() {
        // A required=true leanback declaration must fail the non-required check,
        // or the guard would happily accept the distribution-blocking form.
        val requiredTrue =
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <uses-feature android:name="android.software.leanback" android:required="true" />
                <application/>
            </manifest>
            """.trimIndent()

        assertTrue("precondition: detector sees the feature block", usesFeatureDeclared(requiredTrue, leanback))
        assertFalse(
            "leanback declared required=true must fail the non-required guard",
            isNonRequired(requiredTrue, leanback),
        )
    }

    @Test
    fun `the tv manifest can be located on disk`() {
        // A guard that cannot find its fixture is a tautology that throws in
        // setup and "passes" nothing; confirm the file exists and is readable.
        val manifest = tvManifest()
        assertTrue(
            "TV manifest must exist and be readable: ${manifest.path}",
            manifest.isFile && manifest.canRead(),
        )
    }

    private fun tvManifest(): File {
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

    /**
     * Locates the `<uses-feature ... />` block (self-closing or with children)
     * whose android:name equals [featureName], using the raw text so no XML
     * parser namespace quirks can hide the declaration. Comments are stripped
     * first so a mention inside an explanatory comment cannot be misread as a
     * declaration.
     */
    private fun usesFeature(xml: String, featureName: String): String? {
        val body = xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
        val marker = "<uses-feature"
        var index = body.indexOf(marker)
        while (index >= 0) {
            var end = body.indexOf('>', index)
            if (end < 0) throw AssertionError("unterminated <uses-feature> in: $body")
            // Skip past a trailing '/>' or '>' — the loop looks for the START
            // of the next occurrence after this element, so advance past this
            // closing tag entirely.
            if (end < body.length - 1 && body[end - 1] == '/') end = end + 1
            val block = body.substring(index, end + 1)
            val name =
                Regex("android:name=\"([^\"]*)\"")
                    .find(block)
                    ?.groupValues
                    ?.get(1)
            if (name == featureName) return block
            index = body.indexOf(marker, end + 1)
        }
        return null
    }
}
