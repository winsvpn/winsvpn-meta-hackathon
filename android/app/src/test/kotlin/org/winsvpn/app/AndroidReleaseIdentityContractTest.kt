package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source pins for the 1.0.16+33 phone/TV Play identity.
 *
 * These tests read Gradle, not a signed AAB. A green run is not evidence that
 * a release artifact was produced, obfuscated, or signed.
 */
class AndroidReleaseIdentityContractTest {

    @Test
    fun `phone and TV share org winsvpn app at 1_0_16 plus 33`() {
        val gradle = androidAppGradle()
        assertTrue(gradle.contains("compileSdk = 37"))
        assertTrue(gradle.contains("targetSdk = 37"))
        assertTrue(gradle.contains("ndkVersion = \"30.0.16248370\""))
        assertTrue(gradle.contains("applicationId = \"org.winsvpn.app\""))
        assertTrue(gradle.contains("versionName = \"1.0.16\""))
        assertTrue(gradle.contains("versionCode = 33"))
        assertTrue(flavorBody(gradle, "tv").contains("versionCode = 3302"))
        assertFalse(flavorBody(gradle, "phone").contains("applicationIdSuffix"))
        assertFalse(flavorBody(gradle, "tv").contains("applicationIdSuffix"))
        assertFalse(gradle.contains("applicationId = \"org.winsvpn.app.tv\""))
        assertFalse(gradle.contains("applicationId = \"com.example.wins_vpn\""))
    }

    @Test
    fun `release packaging is fail closed for R8 and Flutter obfuscation`() {
        val gradle = androidAppGradle()
        val release = buildTypeBody(gradle, "release")
        assertTrue(release.contains("isMinifyEnabled = true"))
        assertTrue(release.contains("isShrinkResources = true"))
        assertTrue(gradle.contains("fun verifyAndroidReleaseIdentityAndApi37()"))
        assertTrue(gradle.contains("fun verifyAndroidReleaseR8AndFlutterObfuscation("))
        assertTrue(gradle.contains("dartObfuscation != true"))
        assertTrue(gradle.contains("findProperty(\"dart-obfuscation\")"))
        assertTrue(gradle.contains("findProperty(\"split-debug-info\")"))
        assertTrue(gradle.contains("verifyAndroidReleaseIdentityAndApi37()"))
        assertTrue(gradle.contains("verifyAndroidReleaseR8AndFlutterObfuscation(allTasks)"))
    }

    @Test
    fun `historical TV landscape verify file is not current identity evidence`() {
        val historical = repoFile("android/app/src/tv/tv_manifest_landscape_verify.txt")
        assertTrue(historical.contains("SUPERSEDED"))
        assertTrue(historical.contains("MUST NOT be used as release"))
        assertTrue(historical.contains("org.winsvpn.app / versionCode 3002"))
    }

    private fun flavorBody(gradle: String, name: String): String {
        val header = Regex("""create\("$name"\)\s*\{""")
        val match = header.find(gradle) ?: throw AssertionError("missing create(\"$name\")")
        return braceBody(gradle, match.range.last)
    }

    private fun buildTypeBody(gradle: String, name: String): String {
        val header = Regex("""getByName\("$name"\)\s*\{""")
        val match = header.find(gradle) ?: throw AssertionError("missing getByName(\"$name\")")
        return braceBody(gradle, match.range.last)
    }

    private fun braceBody(source: String, from: Int): String {
        val open = source.indexOf('{', from)
        var depth = 0
        var index = open
        while (index < source.length) {
            when (source[index]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return source.substring(open, index + 1)
                }
            }
            index++
        }
        throw AssertionError("unterminated brace body")
    }

    private fun androidAppGradle(): String = repoFile("android/app/build.gradle.kts")

    private fun repoFile(relative: String): String {
        val file = repoPath(relative)
        assertTrue("missing $relative", file.isFile)
        return file.readText()
    }

    private fun repoPath(relative: String): File {
        var directory: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (directory != null) {
            if (File(directory, "winn_protocol_experimental/go.mod").isFile) {
                return File(directory, relative)
            }
            directory = directory.parentFile
        }
        throw AssertionError("cannot locate repository root")
    }
}
