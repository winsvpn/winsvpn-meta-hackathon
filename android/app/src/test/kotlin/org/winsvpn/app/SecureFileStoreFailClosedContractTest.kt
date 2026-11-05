package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecureFileStoreFailClosedContractTest {

    @Test
    fun `unreadable explicit kill switch state is retained and rethrown`() {
        val store = source("SecureFileStore.kt")
        assertTrue(store.contains("setOf(\"wins_kill_switch_armed\")"))
        assertEquals(2, store.split("|| name in failClosedNames) throw e").size - 1)
        assertEquals("wins_kill_switch_armed", VpnTunnelService.KILL_SWITCH_STATE)
        val reader = source("VpnTunnelService.kt").substringAfter("private fun isKillSwitchArmed(): Boolean {")
            .substringBefore("private fun setKillSwitchArmed")
        assertTrue(Regex("catch\\s*\\([^)]*\\)\\s*\\{\\s*true").containsMatchIn(reader))
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
