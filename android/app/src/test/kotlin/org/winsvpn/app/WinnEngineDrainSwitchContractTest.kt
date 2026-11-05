package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The debug-only drain low water switch for the S26 A/B: debug builds of a
 * v3 spawn only, set before the engine starts, 1 with the switch file absent
 * (the Go default, so the switch-off arm is the shipped arm) and 16 with it
 * present, under the variable name the engine actually reads.
 */
class WinnEngineDrainSwitchContractTest {

    private val assignment = "builder.environment()[\"WINN3_DRAIN_LOW_WATER\"] = lowWater"

    @Test
    fun `the drain switch is debug only, v3 only and set before the engine starts`() {
        val host = file("android/app/src/main/kotlin/org/winsvpn/app/WinnAndroidEngineHost.kt")
        assertEquals("one assignment", 1, host.split(assignment).size - 1)
        val gate = host.indexOf("if (BuildConfig.DEBUG && winn3) {")
        val at = host.indexOf(assignment)
        assertTrue("the debug gate is missing", gate >= 0)
        assertTrue("the assignment is not inside the debug gate",
            at > gate && !host.substring(gate, at).contains('}'))
        assertTrue("the variable is set after the engine started",
            at < host.indexOf("process = builder.start()"))
        val block = host.substring(gate, host.indexOf(assignment))
        assertTrue(block.contains("File(context.filesDir, \"winn3_drain_low_water_16\").exists()"))
        assertTrue(block.contains(") \"16\" else \"1\""))
    }

    @Test
    fun `the switch-off value is the shipped Go default and the name is the one the engine reads`() {
        val ring = file("winn_protocol_experimental/cmd/winn-datapath/winn3_to_engine_ring.go")
        assertTrue("the shipped default is no longer 1",
            Regex("""winn3DrainLowWaterDefault\s*=\s*1\n""").containsMatchIn(ring))
        assertTrue(ring.contains("os.Getenv(\"WINN3_DRAIN_LOW_WATER\")"))
    }

    private fun file(relative: String): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, relative)
            if (candidate.isFile) return candidate.readText()
            dir = dir.parentFile
        }
        throw AssertionError("could not locate $relative")
    }
}
