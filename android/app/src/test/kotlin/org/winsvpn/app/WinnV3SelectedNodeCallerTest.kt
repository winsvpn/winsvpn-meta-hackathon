package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phone and TV native callers must pass the user-selected node into Winn v3
 * session planning. Descriptor `node` is a self-claim; without the Intent extra
 * a substituted INI can make `selected_node` agree with itself and skip the
 * user's selection.
 */
class WinnV3SelectedNodeCallerTest {

    @Test
    fun `method argument and INI selected_node agree after ASCII fold`() {
        val config = winnIni(selected = "LAB-ALPHA")
        assertEquals(
            "lab-alpha",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to "Lab-Alpha"),
                config,
            ),
        )
    }

    @Test
    fun `each method-argument alias alone is a caller identity`() {
        val config = winnIni(selected = null)
        for (key in WinnV3SelectedNodeCaller.METHOD_ARGUMENT_KEYS) {
            assertEquals(
                key,
                "lab-alpha",
                WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                    mapOf(key to "lab-alpha"),
                    config,
                ),
            )
        }
    }

    @Test
    fun `INI selected_node cannot replace an omitted phone caller identity`() {
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                emptyMap<String, Any>(),
                winnIni(selected = "lab-alpha"),
            ),
        )
        assertFalse(
            WinnV3SelectedNodeCaller.methodHasIdentityArgument(emptyMap<String, Any>()),
        )
    }

    @Test
    fun `descriptor node self-claim is not a selected-node identity`() {
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                emptyMap<String, Any>(),
                winnIni(selected = null),
            ),
        )
    }

    @Test
    fun `method argument disagreeing with INI selected_node is a mismatch not first-wins`() {
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to "lab-beta"),
                winnIni(selected = "lab-alpha"),
            ),
        )
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf(
                    "selected_node" to "lab-alpha",
                    "location_slug" to "lab-beta",
                ),
                winnIni(selected = "lab-alpha"),
            ),
        )
    }

    @Test
    fun `nested selected_node map binds through its slug and refuses toString`() {
        assertEquals(
            "lab-alpha",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to mapOf("slug" to "lab-alpha")),
                winnIni(selected = null),
            ),
        )
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf(
                    "selected_node" to mapOf(
                        "name" to "Lab Alpha",
                    ),
                ),
                winnIni(selected = null),
            ),
        )
        assertTrue(
            WinnV3SelectedNodeCaller.methodHasIdentityArgument(
                mapOf("selected_node" to mapOf("name" to "Lab Alpha")),
            ),
        )
    }

    @Test
    fun `Kelvin Unicode fold and dotted identifiers are missing not a match`() {
        val kelvin = "\u212A1"
        assertEquals("k1", kelvin.lowercase())
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to kelvin),
                winnIni(node = "k1", selected = "k1"),
            ),
        )
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to "id.1"),
                winnIni(selected = null),
            ),
        )
        assertTrue(
            WinnV3SelectedNodeCaller.methodHasIdentityArgument(
                mapOf("selected_node" to kelvin),
            ),
        )
    }

    @Test
    fun `numbers lists and whitespace are not coerced into a node identity`() {
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to 1),
                winnIni(selected = null),
            ),
        )
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to listOf("lab-alpha")),
                winnIni(selected = null),
            ),
        )
        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to "   "),
                winnIni(selected = null),
            ),
        )
        assertFalse(
            WinnV3SelectedNodeCaller.methodHasIdentityArgument(
                mapOf("selected_node" to "   "),
            ),
        )
    }

    @Test
    fun `planning requires the caller extra and overlays it onto a descriptor-only section`() {
        val selfClaim = served() - WinnV3SessionPlan.KEY_SELECTED_NODE
        assertFalse(WinnV3SessionPlan.descriptorMatchesSelectedNode(selfClaim))
        assertNull(WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = null))
        assertNull(WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = "   "))
        assertNull(WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = "lab-beta"))

        val bound = WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = "LAB-ALPHA")
        assertNotNull(bound)
        assertEquals("lab-alpha", bound!![WinnV3SessionPlan.KEY_SELECTED_NODE])
        assertTrue(WinnV3SessionPlan.descriptorMatchesSelectedNode(bound))
        plan(bound)
    }

    @Test
    fun `a self-consistent INI cannot skip the caller extra`() {
        val matchingIni = served()
        assertTrue(WinnV3SessionPlan.descriptorMatchesSelectedNode(matchingIni))
        assertNull(WinnV3SelectedNodeCaller.planningSection(matchingIni, extra = null))
        assertNotNull(
            WinnV3SelectedNodeCaller.planningSection(matchingIni, extra = "lab-alpha"),
        )
        assertNull(
            WinnV3SelectedNodeCaller.planningSection(matchingIni, extra = "lab-beta"),
        )
    }

    @Test
    fun `caller extra disagreeing with an INI alias is a mismatch not an overwrite`() {
        val aliased = served("node_slug" to "lab-alpha", "location_slug" to "lab-alpha")
        assertNull(WinnV3SelectedNodeCaller.bindToSection(aliased, "lab-beta"))
        assertNull(WinnV3SelectedNodeCaller.planningSection(aliased, extra = "lab-beta"))
    }

    @Test
    fun `phone and TV share MainActivity and both pass the selected-node extra`() {
        val activity = stripComments(readMainSource("MainActivity.kt"))
        val start = functionBodyOf(activity, "\"startTunnel\" -> {")
        assertTrue(start.contains("WinnV3SelectedNodeCaller.resolveFromStartTunnel("))
        assertTrue(start.contains("WinnV3SelectedNodeCaller.methodHasIdentityArgument("))
        assertTrue(
            start.contains("Winn v3 start requires the exact user-selected node identity"),
        )
        val identityCheck = start.indexOf("winn3SelectedNode.isEmpty()")
        val activate = start.indexOf("activateNativeVpnEngine()")
        assertTrue("caller identity must be required before the VPN service starts", identityCheck in 0 until activate)

        val launch = functionBodyOf(activity, "private fun executeServiceLaunch()")
        assertTrue(launch.contains("putExtra(WinnV3SelectedNodeCaller.EXTRA_SELECTED_NODE"))
        assertEquals(
            "WINN3_SELECTED_NODE",
            WinnV3SelectedNodeCaller.EXTRA_SELECTED_NODE,
        )

        val tvMain = File(androidAppDir(), "src/tv").walkTopDown()
            .filter { it.name == "MainActivity.kt" }
            .toList()
        assertTrue("TV must reuse the phone MainActivity caller", tvMain.isEmpty())
    }

    @Test
    fun `VpnTunnelService refuses before planning when the caller extra is missing`() {
        val service = stripComments(readMainSource("VpnTunnelService.kt"))
        val connect = functionBodyOf(service, "override fun onStartCommand(")
        val planning = connect.indexOf("WinnV3SelectedNodeCaller.planningSection(")
        val engine = connect.indexOf("startWinnV3EngineThread(")
        val refuse = connect.indexOf("refuseWinn3Start(", planning)
        assertTrue("v3 must bind the caller extra before session planning", planning in 0 until engine)
        assertTrue(connect.contains("winnSection = planningSection"))
        assertTrue(connect.contains("WinnV3SelectedNodeCaller.EXTRA_SELECTED_NODE"))
        assertTrue(
            "a missing caller identity is a terminal security refusal",
            refuse in planning until engine,
        )
        val sticky = connect.indexOf("return START_NOT_STICKY", planning)
        assertTrue(sticky in refuse until engine)
        assertFalse(
            "AWG/Xray cover must not be authorized from a selected-node refusal",
            connect.substring(planning, engine).contains("ORDINARY_CONNECTIVITY"),
        )
    }

    @Test
    fun `v3 sticky start persists the caller identity a system restart needs`() {
        val service = stripComments(readMainSource("VpnTunnelService.kt"))
        val connect = functionBodyOf(service, "override fun onStartCommand(")
        assertTrue(connect.contains("if (restoredBySystem) loadRestartSelectedNode()"))
        val engine = connect.indexOf("startWinnV3EngineThread(")
        assertTrue("v3 launch must exist", engine >= 0)
        val sticky = connect.indexOf("return START_STICKY", engine)
        assertTrue("v3 sticky return must exist", sticky > engine)
        val beforeReturn = connect.substring(engine, sticky)
        assertTrue(beforeReturn.contains("persistRestartConfig(config)"))
        assertTrue(
            "a restored v3 start refuses without the persisted caller node",
            beforeReturn.contains("persistRestartSelectedNode(callerSelectedNode)"),
        )
    }

    private fun winnIni(node: String = "lab-alpha", selected: String?): String {
        val selectedLine = if (selected == null) "" else "selected_node = $selected\n"
        return """
            [winn]
            protocol = 3
            node = $node
            $selectedLine
        """.trimIndent()
    }

    private fun served(vararg extra: Pair<String, String>): Map<String, String> {
        val section = linkedMapOf(
            "enabled" to "true",
            WinnV3SessionPlan.KEY_CARRIER to WinnV3SessionPlan.CARRIER_WINN3,
            "endpoint" to "203.0.113.7:51820",
            WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "lab-alpha",
            WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-alpha",
            WinnV3SessionPlan.KEY_INNER_V4 to "10.10.0.9",
            WinnV3SessionPlan.KEY_INNER_ROUTER_V4 to "10.10.0.1",
            WinnV3SessionPlan.KEY_INNER_RESOLVER_V4 to "10.10.0.1",
            "static_private" to "ERERERERERERERERERERERERERERERERERERERERERE=",
            "gateway_static" to "U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=",
            "gateway_id" to "d2luc2d3MDE=",
            "admission_key" to "NmYzOWEwYzFkMjRiN2U4ZjVhM2M5MDEyYjRkNmU4ZjAxYTJiM2M0ZDVlNmY3MDgxOTJhM2I0YzVkNmU3ZjgwOQ==",
        )
        section.putAll(extra)
        return section
    }

    private fun plan(section: Map<String, String>): WinnV3SessionPlan =
        WinnV3SessionPlan.from(
            section = section,
            relayInnerAddress = "",
            dnsServers = listOf("10.10.0.1"),
            promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
            ipv6SinkAddress = "fd00:d951:0001::1",
        )

    private fun functionBodyOf(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("could not find $signature", start >= 0)
        val open = source.indexOf('{', start + signature.length - 1)
        assertTrue("no body for $signature", open >= 0)
        var depth = 0
        var i = open
        while (i < source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> depth--
            }
            if (depth == 0) return source.substring(open, i + 1)
            i++
        }
        throw AssertionError("unterminated body for $signature")
    }

    private fun stripComments(text: String): String =
        text.replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("(?m)//.*$"), "")

    private fun readMainSource(name: String): String =
        File(mainSourceDir(), name).readText()

    private fun mainSourceDir(): File {
        val dir = File(androidAppDir(), "src/main/kotlin/org/winsvpn/app")
        assertTrue("missing $dir", dir.isDirectory)
        return dir
    }

    private fun androidAppDir(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app")
            if (candidate.isDirectory) return candidate
            if (dir.name == "app" && File(dir, "src/main/kotlin/org/winsvpn/app").isDirectory) {
                return dir
            }
            dir = dir.parentFile
        }
        throw AssertionError("could not locate android/app from ${System.getProperty("user.dir")}")
    }
}
