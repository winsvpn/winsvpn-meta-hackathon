package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayTlsOnlyContractTest {

    @Test
    fun `fallback accepts TLS only and uses its default port`() {
        val body = source("VpnTunnelService.kt").substringAfter("private fun startXrayTransportIfNeeded(")
            .substringBefore("private fun writeXrayClientConfig")
        assertTrue(body.contains("require(security == \"tls\")"))
        assertFalse(body.contains("\"none\""))
        assertFalse(body.contains("allowinsecuretransport"))
        assertTrue(body.contains("section[\"port\"]?.toIntOrNull() ?: 443"))
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
