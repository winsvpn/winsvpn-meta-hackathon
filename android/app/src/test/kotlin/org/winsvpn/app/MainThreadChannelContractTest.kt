package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MainThreadChannelContractTest {
    @Test
    fun readinessAndEngineStartupLeaveThePlatformThreadAndServiceLock() {
        val activity = source("MainActivity.kt")
        val branch = activity.substringAfter("\"getTunnelReadiness\" -> {")
            .substringBefore("\"probeVpnInternet\" -> {")
        assertTrue(branch.contains("readinessExecutor.execute"))

        val service = source("VpnTunnelService.kt")
        val install = service.substringAfter("val installIfStillOwner:")
            .substringBefore("val staged = WinnV3StagedStart(")
        val locked = install.substringAfter("val installed = synchronized(winnEngineLock) {")
            .substringBefore("if (installed && posture.stage")
        assertTrue(locked.contains("install(posture)"))
        assertFalse(locked.contains("created.start()"))
        assertFalse(locked.contains(".start()"))
        assertTrue(install.contains("created.start()"))
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
