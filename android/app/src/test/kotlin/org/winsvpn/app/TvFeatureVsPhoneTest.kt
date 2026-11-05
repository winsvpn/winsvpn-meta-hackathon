package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * THE TV LEANBACK INVARIANT MUST NOT LEAK INTO THE PHONE DISGUISE.
 *
 * The phone build (`src/main`) is deliberately a touchscreen "Calculator"
 * disguise (see the `android:label="Calculator"` in `src/main/AndroidManifest.xml`).
 * Android TV (`src/tv`) is never disguised and drives the launcher with a D-pad
 * remote, which requires the leanback feature to be declared (`android.software.leanback`).
 *
 * These two postures must stay disjoint in one specific way:
 *  - `src/tv`  MUST carry `android.software.leanback` (without it the TV build
 *    is not installable as a leanback launcher, and remote-driven focus is gone);
 *  - `src/main` MUST NOT carry `android.software.leanback` (a phone build that
 *    declares leanback advertises TV-style D-pad handling and says "appliance /
 *    set-top box" in the Play filtering and in the permission/feature census —
 *    a fingerprint the touchscreen disguise exists to avoid, and the reason the
 *    main manifest has that attribute only as an absent negative).
 *
 * So this test pins both sides of the invariant on the real manifest files:
 * the POSITIVE that tv keeps leanback, and the NEGATIVE that main does not
 * gain it. Either drift — tv drops leanback, or main acquires it — fails the
 * named side and tells you which manifest regressed.
 *
 * The manifests are read off disk by walking up from the Gradle test working
 * directory (no Robolectric needed), following the same locating scheme as
 * [TvLaunchFocusTest].
 */
class TvFeatureVsPhoneTest {

    @Test
    fun `tv keeps leanback while the phone does not gain it`() {
        val tv = stripXmlComments(tvManifest()!!.readText())
        val main = stripXmlComments(mainManifest()!!.readText())

        // POSITIVE side: the TV variant must keep the leanback feature. This is
        // the fact the TV build's installability and D-pad focus depend on.
        assertTrue(
            "src/tv must carry android.software.leanback: dropping it makes the " +
                "TV variant uninstallable as a leanback launcher",
            hasLeanbackFeature(tv),
        )

        // NEGATIVE side: the phone disguise must NOT gain the leanback feature.
        // This is the half of the invariant a positive-only test can never see
        // go red, which is why it is asserted explicitly.
        assertFalse(
            "src/main must NOT carry android.software.leanback: a phone build " +
                "declaring leanback advertises TV-style D-pad handling and leaks " +
                "the appliance posture the Calculator disguise exists to avoid",
            hasLeanbackFeature(main),
        )
    }

    /** True iff [text] declares `android.software.leanback` as a uses-feature. */
    private fun hasLeanbackFeature(text: String): Boolean =
        Regex("""<uses-feature[^>]*android:name\s*=\s*"android\.software\.leanback"[^>]*>""")
            .containsMatchIn(text)

    // ---- source locating -------------------------------------------------

    private fun tvManifest(): File? {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf("src/tv/AndroidManifest.xml", "android/app/src/tv/AndroidManifest.xml")) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        return null
    }

    private fun mainManifest(): File? {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf("src/main/AndroidManifest.xml", "android/app/src/main/AndroidManifest.xml")) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate
            }
            dir = dir.parentFile
        }
        return null
    }

    /** XML with comments removed, so no `>` inside a comment ends a tag. */
    private fun stripXmlComments(xml: String): String =
        xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
}
