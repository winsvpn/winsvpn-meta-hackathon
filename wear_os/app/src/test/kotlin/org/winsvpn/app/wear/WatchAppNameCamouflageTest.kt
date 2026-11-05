package org.winsvpn.app.wear

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The watch app is a second device sitting entirely outside the phone's
 * camouflage. The phone can present as a calculator on every surface it owns
 * and still be given away by a paired watch whose app list names the product --
 * a place an inspector is not expected to look and, more to the point, a place
 * the user does not think to check.
 *
 * `app_name` is the whole of that exposure. It is the launcher label, the name
 * in the watch's own Settings > Apps, and the app the watch tells the user to
 * open on their phone. There is no runtime swap available for it (see the
 * comment on the string itself), so the only guard is that the checked-in
 * value stays disguised -- in the default locale and in every other one.
 *
 * These tests read the resource XML directly rather than through `R`, because
 * the failure being guarded against is somebody editing the XML.
 */
class WatchAppNameCamouflageTest {

    /** Matches the phone's `<application android:label>`. If the phone's base
     *  label is ever changed, this must change with it. */
    private val expectedName = "Calculator"

    private val resDir: File
        get() {
            // Gradle runs unit tests with the module directory as the working
            // directory; fall back to the repo-relative path so the test also
            // passes when run from an IDE rooted elsewhere.
            val candidates = listOf(
                File("src/main/res"),
                File("app/src/main/res"),
                File("wear_os/app/src/main/res"),
            )
            return candidates.firstOrNull { it.isDirectory }
                ?: error("watch res/ directory not found from ${File(".").absolutePath}")
        }

    private fun appNameIn(stringsXml: File): String? {
        val text = stringsXml.readText()
        val match = Regex(
            """<string\s+name="app_name"\s*>(.*?)</string>""",
            RegexOption.DOT_MATCHES_ALL,
        ).find(text) ?: return null
        // Android resource escaping: \' is a literal apostrophe.
        return match.groupValues[1].replace("\\'", "'").trim()
    }

    @Test
    fun `the default locale names the watch app after the disguise`() {
        val defaults = File(resDir, "values/strings.xml")
        assertTrue("res/values/strings.xml is missing", defaults.isFile)
        assertEquals(
            "the watch launcher label must carry the disguise, not the product name",
            expectedName,
            appNameIn(defaults),
        )
    }

    @Test
    fun `no locale overrides app_name back to the product name`() {
        // The leak this closes is locale-shaped: an override in, say,
        // res/values-my/ would fire only for users whose watch is set to that
        // language, which is precisely the population this app protects.
        val overrides = resDir.listFiles()
            .orEmpty()
            .filter { it.isDirectory && it.name.startsWith("values") && it.name != "values" }
            .mapNotNull { dir ->
                val strings = File(dir, "strings.xml")
                if (!strings.isFile) null else appNameIn(strings)?.let { dir.name to it }
            }

        val bad = overrides.filter { (_, name) -> name != expectedName }
        assertTrue(
            "these locales override app_name away from the disguise: $bad",
            bad.isEmpty(),
        )
    }

    @Test
    fun `no watch string carries the product name`() {
        // Catches the brand reappearing in a status line or a translated
        // string rather than in app_name itself.
        val offenders = mutableListOf<String>()
        resDir.walkTopDown()
            .filter { it.isFile && it.name == "strings.xml" }
            .forEach { file ->
                file.readLines().forEachIndexed { index, line ->
                    // Only <string> elements; the file's own explanatory
                    // comments are allowed to discuss the product by name.
                    if (!line.contains("<string")) return@forEachIndexed
                    val normalised = line.replace("\\'", "'")
                    if (normalised.contains("Win's VPN", ignoreCase = true) ||
                        normalised.contains("WinsVPN", ignoreCase = true)
                    ) {
                        offenders += "${file.parentFile?.name}/strings.xml:${index + 1}"
                    }
                }
            }
        assertTrue("watch strings naming the product: $offenders", offenders.isEmpty())
    }
}
