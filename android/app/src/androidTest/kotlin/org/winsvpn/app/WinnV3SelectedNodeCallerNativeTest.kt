package org.winsvpn.app

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device ART proof that the phone/TV caller overlay does not Unicode-fold a
 * selected node onto the signed descriptor identity.
 */
@RunWith(AndroidJUnit4::class)
class WinnV3SelectedNodeCallerNativeTest {

    @Test
    fun nativeArtRequiresCallerExtraAndRefusesKelvinFold() {
        assertTrue("device test must execute on Android ART", Build.VERSION.SDK_INT >= 24)

        val kelvin = "\u212A1"
        assertEquals("k1", kelvin.lowercase())
        val selfClaim = served() - WinnV3SessionPlan.KEY_SELECTED_NODE
        assertFalse(WinnV3SessionPlan.descriptorMatchesSelectedNode(selfClaim))
        assertNull(WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = null))
        assertNull(WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = kelvin))
        assertNull(WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = "lab-beta"))

        val bound = WinnV3SelectedNodeCaller.planningSection(selfClaim, extra = "LAB-ALPHA")
        assertNotNull(bound)
        assertTrue(WinnV3SessionPlan.descriptorMatchesSelectedNode(bound!!))
        val plan = WinnV3SessionPlan.from(
            section = bound,
            relayInnerAddress = "",
            dnsServers = listOf("10.10.0.1"),
            promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
            ipv6SinkAddress = "fd00:d951:0001::1",
        )
        assertEquals("10.10.0.9", plan.engineConfig.innerAddress)

        assertEquals(
            "",
            WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                mapOf("selected_node" to kelvin),
                "[winn]\nprotocol = 3\nnode = k1\nselected_node = k1\n",
            ),
        )
    }

    private fun served(): Map<String, String> = linkedMapOf(
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
}
