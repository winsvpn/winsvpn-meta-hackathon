package org.winsvpn.app.wear

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source pins for the 1.0.16+33 Wear Play identity.
 *
 * These tests read Gradle, the keep file, and the source manifest. A green run
 * is not evidence that minifyReleaseWithR8 or a signed Wear AAB succeeded.
 */
class WearReleaseIdentityContractTest {

    @Test
    fun `wear shares org winsvpn app at watch code 3301`() {
        val gradle = wearAppGradle()
        assertTrue(gradle.contains("compileSdk = 37"))
        assertTrue(gradle.contains("targetSdk = 37"))
        assertTrue(gradle.contains("ndkVersion = \"30.0.16248370\""))
        assertTrue(gradle.contains("applicationId = \"org.winsvpn.app\""))
        assertTrue(gradle.contains("versionName = \"1.0.16\""))
        assertTrue(gradle.contains("versionCode = 3301"))
        assertFalse(Regex("""applicationIdSuffix\s*=""").containsMatchIn(gradle))
        assertFalse(gradle.contains("applicationId = \"org.winsvpn.app.tv\""))
        assertFalse(gradle.contains("applicationId = \"com.example.wins_vpn\""))
        assertTrue(gradle.contains("fun verifyWearReleaseIdentityAndApi37()"))
        assertTrue(gradle.contains("fun wearReleaseSigningIsOwnerUploadKey()"))
        assertTrue(gradle.contains("OWNER-BLOCKED: missing Android upload keystore"))
        assertTrue(gradle.contains("debug or test key"))
        assertTrue(gradle.contains("verifyWearReleaseIdentityAndApi37()"))
        assertTrue(gradle.contains("isMinifyEnabled = true"))
        assertTrue(gradle.contains("isShrinkResources = true"))
        assertTrue(gradle.contains("wearCompanionMustNotPackagePhoneVpnEngines"))
    }

    @Test
    fun `wear keep file retains only the launcher constructor`() {
        val keep = repoFile("wear_os/app/proguard-rules.pro")
        assertTrue(keep.contains("-keep class org.winsvpn.app.wear.MainActivity"))
        assertTrue(keep.contains("<init>();"))
        assertFalse(keep.contains("{ *; }"))
        assertTrue(keep.contains("do not prove a successful R8 run"))
    }

    @Test
    fun `wear source manifest requires the watch feature and is not TV`() {
        val manifest = repoFile("wear_os/app/src/main/AndroidManifest.xml")
        assertTrue(manifest.contains("android.hardware.type.watch"))
        assertTrue(manifest.contains("android:required=\"true\""))
        assertTrue(manifest.contains("com.google.android.wearable.standalone"))
        assertTrue(manifest.contains("android:value=\"false\""))
        assertFalse(manifest.contains("LEANBACK_LAUNCHER"))
        assertFalse(manifest.contains("org.winsvpn.app.tv"))
        assertFalse(manifest.contains("android.permission.INTERNET"))
        assertFalse(manifest.contains("QUERY_ALL_PACKAGES"))
        assertFalse(manifest.contains("BIND_VPN_SERVICE"))
    }

    private fun wearAppGradle(): String = repoFile("wear_os/app/build.gradle.kts")

    private fun repoFile(relative: String): String {
        val file = repoPath(relative)
        assertTrue("missing $relative from ${File(".").absolutePath}", file.isFile)
        return file.readText()
    }

    private fun repoPath(relative: String): File {
        val candidates = listOf(
            File(relative),
            File("../$relative"),
            File("../../$relative"),
        )
        candidates.firstOrNull { it.isFile }?.let { return it }
        var directory: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (directory != null) {
            val candidate = File(directory, relative)
            if (candidate.isFile) return candidate
            directory = directory.parentFile
        }
        throw AssertionError("cannot locate $relative")
    }
}
