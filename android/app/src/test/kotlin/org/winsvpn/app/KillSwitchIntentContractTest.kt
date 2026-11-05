package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KillSwitchIntentContractTest {

    @Test
    fun `explicit state is authoritative and read failure holds the block`() {
        val service = source("VpnTunnelService.kt")
        val body = service.substringAfter("private fun isKillSwitchArmed(): Boolean {")
            .substringBefore("private fun setKillSwitchArmed")
        assertTrue(body.contains("toBooleanStrictOrNull() ?: true"))
        assertTrue(body.contains("always_on_enabled"))
        assertTrue(Regex("catch\\s*\\([^)]*\\)\\s*\\{\\s*true").containsMatchIn(body))
        val setter = source("MainActivity.kt").substringAfter("private fun setAlwaysOnVpn(")
            .substringBefore("private fun legacyAppFile")
        assertTrue(setter.contains("enabled.toString()"))
        assertFalse(setter.contains("getMethod("))
    }

    private fun source(name: String): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (prefix in listOf("android/app/src/main/kotlin", "app/src/main/kotlin")) {
                for (owner in listOf("winsvpn")) {
                    val file = File(dir, "$prefix/org/$owner/app/$name")
                    if (file.isFile) return file.readText()
                }
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate $name")
    }
}
