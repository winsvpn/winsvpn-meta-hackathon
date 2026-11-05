package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * D-PAD TRAVERSAL SMOKE FOR THE TV LAUNCH THEME.
 *
 * A leanback build is driven by a D-pad remote, never a touchscreen. An item
 * that only exists as a pointer target is unreachable on a TV: the launcher
 * must paint focus so the user can see where the remote cursor sits. That
 * focus surface lives on the launch theme in `src/tv/res/values/styles.xml` as
 * a `focusedItemBackground` item on the `LaunchTheme` style -- the theme
 * `src/tv/AndroidManifest.xml` pins on the launcher activity.
 *
 * This test parses that styles.xml off disk (walking up from the Gradle test
 * working directory, the same convention every disk-reading test here uses)
 * and asserts the launcher theme still declares the item. It is scoped to the
 * `LaunchTheme` block specifically, so the companion `NormalTheme` (which runs
 * after first frame and is never the launch screen) cannot smuggle the item in
 * and make the assertion vacuously pass.
 *
 * Mutate control: deleting the `focusedItemBackground` item from `LaunchTheme`
 * must turn this test red. That is the negative that makes the positive
 * meaningful -- a theme with no declared focused background would launch with
 * invisible (pointer-only) focus.
 */
class TvDpadThemeTest {

    @Test
    fun `the TV launch theme declares a focused item background`() {
        val styles = tvStyles()
        val launchTheme = styleBlock(stripXmlComments(styles), "LaunchTheme")

        assertTrue(
            "Load-bearing positive: the launcher (LaunchTheme) must declare a " +
                "focusedItemBackground so D-pad focus is painted and traversal is " +
                "not pointer-only. LaunchTheme block was:$launchTheme",
            launchTheme.contains("focusedItemBackground"),
        )

        assertTrue(
            "the focused item background must be a real style item (name=...) on " +
                "the launch theme, not merely a word in a comment",
            Regex("""<item\b[^>]*name\s*=\s*["']focusedItemBackground["'][^>]*>""")
                .containsMatchIn(launchTheme),
        )
    }

    @Test
    fun `the focused item background belongs to the launcher, not the normal theme`() {
        val styles = stripXmlComments(tvStyles())
        val normalTheme = styleBlock(styles, "NormalTheme")

        assertFalse(
            "the launch-focus guarantee must not be satisfied by NormalTheme, " +
                "which only runs after first frame and never is the launch screen",
            normalTheme.contains("focusedItemBackground"),
        )
    }

    // ---- source locating ------------------------------------------------

    /** The `src/tv/res/values/styles.xml` file, found by walking up from the Gradle test dir. */
    private fun tvStyles(): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/tv/res/values/styles.xml",
                "android/app/src/tv/res/values/styles.xml",
            )) {
                val candidate = File(dir, relative)
                if (candidate.isFile) return candidate.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate src/tv/res/values/styles.xml from " +
                System.getProperty("user.dir"),
        )
    }

    /** The body of the named `<style>` element, or the whole text if it cannot be bounded. */
    private fun styleBlock(xml: String, styleName: String): String {
        val style = Regex(
            """<style\b[^>]*name\s*=\s*["']$styleName["'][^>]*>""",
            RegexOption.DOT_MATCHES_ALL,
        )
        val match = style.find(xml)
            ?: return ""
        val fromStyle = xml.indexOf("</style>", match.range.last)
        return xml.substring(match.range.first, if (fromStyle >= 0) fromStyle else xml.length)
    }

    /** XML with comments removed, so no `>` inside a comment ends a tag. */
    private fun stripXmlComments(xml: String): String =
        xml.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
}
