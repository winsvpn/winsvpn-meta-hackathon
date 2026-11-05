package org.winsvpn.app

import java.io.File
import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AwgNativeApiTest {
    @Test
    fun everyHandleOperationUsesTheSameJvmMonitor() {
        val methods = AwgNativeApi::class.java.declaredMethods
            .filter { it.name.startsWith("awg") }
        assertEquals(
            setOf("awgTurnOn", "awgTurnOff", "awgGetSocketV4", "awgGetSocketV6",
                "awgGetConfig", "awgUpdateTunnelPeers"),
            methods.map { it.name }.toSet(),
        )
        for (method in methods) {
            assertTrue(method.name, Modifier.isSynchronized(method.modifiers))
            assertTrue("all operations must lock the singleton", !Modifier.isStatic(method.modifiers))
        }
    }

    @Test
    fun appCallersCannotBypassSerialization() {
        val roots = listOf(File("android/app"), File("app"), File("."))
        val directory = roots.map { File(it, "src/main/kotlin/org/winsvpn/app") }
            .first { File(it, "VpnTunnelService.kt").isFile }
        val bypasses = directory.listFiles()!!.filter { file ->
            file.extension == "kt" && file.name != "AwgNativeApi.kt" &&
                Regex("\\bGoBackend\\.awg[A-Za-z0-9]+\\(").containsMatchIn(file.readText())
        }.map { it.name }
        assertEquals("native handle access must go through AwgNativeApi", emptyList<String>(), bypasses)
    }
}
