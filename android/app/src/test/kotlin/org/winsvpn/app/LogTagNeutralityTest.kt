package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LogTagNeutralityTest {

    @Test
    fun `log tags and thread names do not carry product names`() {
        val service = source("VpnTunnelService.kt")
        assertTrue(service.contains("const val LOG_TAG = \"CalcCore\""))
        val owner = locateDirectory()
        val tags = Regex("\"(?:WinsVpnService|WinsVpnMain|WinsVpnActivity|WinsVpnProbe|WinsFallbackSecurity|WinsFallback|WinsSpeedUpload|WinnUpload|WinsKillSwitch|WinsWatchBridge|SecureFileStore)\"")
        val violations = owner.listFiles { f -> f.extension == "kt" }!!.filter {
            val text = it.readText()
            tags.containsMatchIn(text) || text.contains("\"WinsVPN-")
        }
        assertTrue("nonneutral literals: ${violations.map { it.name }}", violations.isEmpty())
    }

    private fun locateDirectory(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (prefix in listOf("android/app/src/main/kotlin", "app/src/main/kotlin")) {
                for (owner in listOf("winsvpn")) {
                    val file = File(dir, "$prefix/org/$owner/app")
                    if (file.isDirectory) return file
                }
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate Kotlin sources")
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
