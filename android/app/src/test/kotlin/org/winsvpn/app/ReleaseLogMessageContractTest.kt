package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseLogMessageContractTest {

    @Test
    fun `identifier bearing direct messages are debug gated`() {
        val main = source("MainActivity.kt")
        for (release in listOf(
            "Probe failed: ${'$'}{e.javaClass.simpleName}",
            "tunnel ingest run failed: ${'$'}{e.javaClass.simpleName}",
            "DNS lookup failed: ${'$'}{e.javaClass.simpleName}",
        )) assertTrue(release, main.contains(release))
        for (debug in listOf(
            "Probe ${'$'}probeUrl failed",
            "tunnel ingest run failed: ${'$'}{e.javaClass.simpleName}: ${'$'}{e.message}",
            "DNS lookup for ${'$'}{url.host}",
        )) {
            val index = main.indexOf(debug)
            assertTrue("debug message missing: $debug", index >= 0)
            assertTrue(debug, main.substring(maxOf(0, index - 120), index)
                .contains("if (BuildConfig.DEBUG) {"))
        }
        assertFalse(source("VpnTunnelService.kt").contains("search domain ${'$'}domain"))
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
