package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source contract (Android Keystore cannot run on the JVM): removing an
 * unreadable settings record first records the kill switch as armed when no
 * explicit record exists, on both removal paths.
 */
class SecureFileStoreLegacyKillSwitchContractTest {
    @Test
    fun `both removal paths keep the kill switch armed before removing settings`() {
        val source = sourceFile("SecureFileStore.kt").readText()
        val guarded = Regex(
            """keepKillSwitchArmedBeforeRemoving\(name\)\s*\n\s*Log\.w\(TAG, "A secure record failed authentication; removing it"\)\s*\n\s*(encryptedFile|legacy)\.delete\(\)""",
        ).findAll(source).map { it.groupValues[1] }.toList()
        assertEquals(listOf("encryptedFile", "legacy"), guarded)
        assertTrue(source.contains("""private const val LEGACY_KILL_SWITCH_SOURCE = "vpn_settings.txt""""))
        assertTrue(source.contains("""private const val KILL_SWITCH_RECORD = "wins_kill_switch_armed""""))
        assertTrue(source.contains("""write(KILL_SWITCH_RECORD, "true")"""))
        assertTrue(
            sourceFile("VpnTunnelService.kt").readText()
                .contains("""KILL_SWITCH_STATE = "wins_kill_switch_armed""""),
        )
    }

    private fun sourceFile(name: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app/src/main/kotlin/org/winsvpn/app/$name")
            if (candidate.isFile) return candidate
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app/$name")
            if (here.isFile) return here
            dir = dir.parentFile
        }
        throw AssertionError("could not locate $name")
    }
}
