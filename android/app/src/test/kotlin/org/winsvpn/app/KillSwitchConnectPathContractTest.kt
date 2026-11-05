package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KillSwitchConnectPathContractTest {

    @Test
    fun `connect never invokes hidden always on writes`() {
        val service = source("VpnTunnelService.kt")
        assertTrue(service.contains("val suppliedConfig"))
        val connect = service.substringAfter("val suppliedConfig").substringBefore("establish()")
        assertFalse(connect.contains("armAlwaysOnLockdown("))
        assertTrue(service.contains("ACTION_ARM_KILLSWITCH"))
        assertTrue(service.contains("ACTION_DISARM_KILLSWITCH"))
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
