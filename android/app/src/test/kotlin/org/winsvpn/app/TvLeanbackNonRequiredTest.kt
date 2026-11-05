package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The TV source set declares `android.software.leanback` so the Android TV
 * variant is visible to the Play Store's TV catalogue. That declaration must
 * stay `required="false"`: `required="true"` filters the app off every
 * non-TV device -- most importantly every tablet -- which is a distribution
 * restriction this app does not intend. This test fails if the leanback
 * feature is declared with `required="true"`.
 */
class TvLeanbackNonRequiredTest {

    @Test
    fun `leanback is declared required false in the TV manifest`() {
        val tvManifest = locateTvManifest()
        val xml = stripXmlComments(tvManifest.readText())
        val leanback = usesFeatureBlock(xml, "android.software.leanback")
        assertEquals(
            "android.software.leanback must not be declared required=true; " +
                "that filters the app off non-TV devices (tablets) on Play",
            "false",
            requiredAttributeOf(leanback),
        )
    }

    private fun locateTvManifest(): java.io.File {
        var dir: java.io.File? =
            java.io.File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/tv/AndroidManifest.xml",
                "android/app/src/tv/AndroidManifest.xml",
            )) {
                val candidate = java.io.File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "TV manifest not found at android/app/src/tv/AndroidManifest.xml " +
                "from ${System.getProperty("user.dir")}",
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
        throw AssertionError(
            "no <uses-feature> for $featureName in the TV manifest",
        )
    }

    private fun requiredAttributeOf(block: String): String {
        val value = Regex("android:required=\"([^\"]*)\"")
            .find(block)
            ?.groupValues
            ?.get(1)
            ?: throw AssertionError(
                "$block has no android:required attribute; " +
                    "leanback must be explicitly declared required=false",
            )
        return value
    }

    private fun stripXmlComments(xml: String): String =
        xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
}
