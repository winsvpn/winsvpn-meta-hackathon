package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TV BANNER RESOURCE GUARD.
 *
 * The TV variant references the application banner as `@drawable/banner` (see
 * the sibling [TvBannerRefTest], which pins that the manifest carries the
 * attribute). That reference is only resolvable if a drawable named `banner`
 * actually exists on disk in the TV resource set, i.e. a `banner.png` /
 * `banner.webp` / `banner.xml` file sitting directly inside a `drawable/` or
 * `drawable-<density>/` directory under `src/tv/res/` (lineage for AGP
 * resource merging and the runtime resource table).
 *
 * If the reference resolves to nothing, the TV build emits a merge error or
 * the launcher shows a blank card, so this class pins the NEGATIVE of that:
 * the resource string `@drawable/banner` must map to an existing file.
 *
 * Plain JVM unit test, no Robolectric: it reads the resource set off disk,
 * walking up from the Gradle test working directory (the same convention as
 * the other TV guards). All mutation controls run against the REVERSE of the
 * live claim -- an unknown drawable name must NOT resolve -- so a live
 * resolution cannot be an artifact of an always-green detector.
 */
class TvBannerResourceTest {

    @Test
    fun `drawable banner resolves to an existing file under src tv res`() {
        val png = resolveDrawableFile("banner")
        assertTrue(
            "resource @drawable/banner must map to an existing file under " +
                "src/tv/res; found none under ${tvResDir().path}",
            png.isFile && png.canRead(),
        )
    }

    @Test
    fun `an unknown drawable name does not resolve`() {
        // NEGATIVE control: prove the detector can fail. If resolution returned
        // true unconditionally, the positive assertion above would be a
        // tautology. Mutation: point at a name that cannot exist in this set.
        val resolved = resolveDrawableFileOrNull("banner_resource_test_nonexistent_$RANDOM_SUFFIX")
        assertFalse(
            "an absent drawable must never resolve, or the positive guard is vacuous",
            resolved != null && resolved.isFile,
        )
    }

    @Test
    fun `the resolved banner file is non-empty`() {
        val png = resolveDrawableFile("banner")
        val bytes = png.length()
        assertTrue(
            "resolved banner drawable must be non-empty; ${png.path} is $bytes bytes",
            bytes > 0,
        )
    }

    // ---- helpers ---------------------------------------------------------

    /** A compile-time-varying suffix so the negative control name is truly absent. */
    private val RANDOM_SUFFIX: String =
        java.util.UUID.randomUUID().toString().substring(0, 8)

    private fun resolveDrawableFile(name: String): File =
        resolveDrawableFileOrNull(name)
            ?: throw AssertionError(
                "could not resolve drawable '$name' under ${tvResDir().path}",
            )

    private fun resolveDrawableFileOrNull(name: String): File? {
        val res = tvResDir()
        val dirs = res.listFiles() ?: return null
        for (dir in dirs) {
            // Only resource drawable folders participate: "drawable", or a
            // "drawable-<qualifier>" density bucket like "drawable-xhdpi".
            if (!dir.isDirectory || !dir.name.startsWith("drawable")) continue
            for (ext in listOf(".png", ".webp", ".jpg", ".xml")) {
                val candidate = File(dir, name + ext)
                if (candidate.isFile && candidate.canRead()) return candidate
            }
        }
        return null
    }

    private fun tvResDir(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/tv/res",
                "android/app/src/tv/res",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isDirectory) return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate android/app/src/tv/res from " +
                System.getProperty("user.dir"),
        )
    }
}
