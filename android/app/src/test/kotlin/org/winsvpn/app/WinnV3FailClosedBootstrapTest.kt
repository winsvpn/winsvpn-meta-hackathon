package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class WinnV3FailClosedBootstrapTest {
    private val gateway = WinnV3Route("203.0.113.7", 32)
    // VpnTunnelService.IPV6_FAIL_CLOSED_SINK
    private val sink = "fd00:d951:0001::1"

    private fun narrow(builder: WinnV3PostureSink? = null): WinnV3PostureRecord =
        WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway).applyTo(builder)

    private fun captured(): WinnV3PostureRecord {
        val r = narrow()
        WinnV3Posture.verifyNarrow(r, requireExclusion = true)
        WinnV3Posture.applyFailClosedBootstrapCapture(r, sink)
        return r
    }

    @Test
    fun `a capture applied through the record verifies and the record describes it`() {
        val r = captured()
        WinnV3Posture.verifyFailClosedBootstrap(r, sink, requireExclusion = true)
        assertTrue(r.hasDefaultRoute())
        assertTrue(r.hasAnyIpv6())
        assertEquals(listOf(gateway), r.excludedRoutes)
    }

    @Test
    fun `the record forwards every capture call to the builder`() {
        val calls = mutableListOf<String>()
        val builder = object : WinnV3PostureSink {
            override fun addAddress(address: String, prefixLength: Int) { calls += "address $address/$prefixLength" }
            override fun addRoute(address: String, prefixLength: Int) { calls += "route $address/$prefixLength" }
            override fun excludeRoute(address: String, prefixLength: Int): Boolean { calls += "exclude $address/$prefixLength"; return true }
            override fun setMtu(mtu: Int) {}
            override fun addDnsServer(server: String) {}
            override fun allowFamily(family: Int) {}
        }
        val r = narrow(builder)
        calls.clear()
        WinnV3Posture.applyFailClosedBootstrapCapture(r, sink)
        assertEquals(listOf("route 0.0.0.0/0", "address $sink/128", "route ::/0"), calls)
    }

    @Test
    fun `a narrow record without the capture is refused`() {
        refusal { WinnV3Posture.verifyFailClosedBootstrap(narrow(), sink, requireExclusion = true) }
    }

    @Test
    fun `a capture without the IPv6 default route is refused`() {
        val r = narrow()
        r.addRoute("0.0.0.0", 0)
        r.addAddress(sink, 128)
        val e = refusal { WinnV3Posture.verifyFailClosedBootstrap(r, sink, requireExclusion = true) }
        assertTrue(e.message!!.contains("both families"))
    }

    @Test
    fun `an include that shadows the outer exclusion is refused`() {
        val r = captured()
        r.addRoute(gateway.address, gateway.prefixLength)
        // The include is also a fourth route, so either clause may refuse it;
        // what must never happen is neither.
        assertEquals(listOf(gateway), r.shadowedExclusions)
        refusal { WinnV3Posture.verifyFailClosedBootstrap(r, sink, requireExclusion = true) }
    }

    @Test
    fun `a resolver after the capture is refused`() {
        val r = captured()
        r.addDnsServer("10.8.1.1")
        refusal { WinnV3Posture.verifyFailClosedBootstrap(r, sink, requireExclusion = true) }
    }

    // A fail-closed bootstrap captures everything, so it must never be tagged
    // as the narrow bootstrap: a teardown whose blocking hold is refused
    // closes a narrow interface but keeps any full capture.
    @Test
    fun `a fail-closed bootstrap is never tagged as the narrow bootstrap interface`() {
        val install = source("VpnTunnelService.kt")
            .substringAfter("val install: (WinnV3Posture) -> Unit")
            .substringBefore("val installIfStillOwner")
        val declared = install.indexOf("var wasProtected = false")
        val bootstrap = install.indexOf("if (posture.stage == WinnV3Stage.BOOTSTRAP) {")
        val assigned = install.indexOf("wasProtected = vpnInterface != null ||")
        val established = install.indexOf("WinnV3AndroidTunDevice.establish(")
        assertTrue(declared in 0 until bootstrap)
        assertTrue(assigned in bootstrap until established)
        assertTrue(
            Regex(
                """narrowBootstrapInterface =\s*if \(posture\.stage == WinnV3Stage\.BOOTSTRAP && !wasProtected\) original else null""",
            ).containsMatchIn(install),
        )
        assertFalse(
            Regex("""narrowBootstrapInterface =\s*if \(posture\.stage == WinnV3Stage\.BOOTSTRAP\) original""")
                .containsMatchIn(install),
        )
    }

    private fun source(name: String): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (prefix in listOf("android/app/src/main/kotlin", "app/src/main/kotlin")) {
                val file = File(dir, "$prefix/org/winsvpn/app/$name")
                if (file.isFile) return file.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate $name")
    }

    private fun refusal(block: () -> Unit): WinnV3PostureRefusal =
        try {
            block()
            throw AssertionError("expected a WinnV3PostureRefusal and none was thrown")
        } catch (e: WinnV3PostureRefusal) {
            e
        }
}
