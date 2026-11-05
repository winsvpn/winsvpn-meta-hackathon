package org.winsvpn.app

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device ART proof of the same descriptor-to-selected-node contract the JVM
 * tests pin. Unicode `String.lowercase()` is locale- and ICU-sensitive on
 * Android; this class is the independent native gate on the phone/TV runtime.
 */
@RunWith(AndroidJUnit4::class)
class WinnV3SessionPlanNodeBindingNativeTest {

    @Test
    fun nativeArtRefusesUnicodeFoldConflictingAliasMissingIdentityAndReplay() {
        assertTrue("device test must execute on Android ART", Build.VERSION.SDK_INT >= 24)

        val kelvin = "\u212A1"
        assertEquals("k1", kelvin.lowercase())
        assertNull(WinnV3SessionPlan.normalizedNodeIdentity(kelvin))
        assertEquals("k1", WinnV3SessionPlan.normalizedNodeIdentity("k1"))
        assertEquals("lab-alpha", WinnV3SessionPlan.normalizedNodeIdentity("LAB-ALPHA"))

        val matching = served()
        assertTrue(WinnV3SessionPlan.descriptorMatchesSelectedNode(matching))
        val plan = WinnV3SessionPlan.from(
            section = matching,
            relayInnerAddress = "",
            dnsServers = listOf("10.10.0.1"),
            promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
            ipv6SinkAddress = "fd00:d951:0001::1",
        )
        assertEquals("10.10.0.9", plan.engineConfig.innerAddress)

        expectRefusal(served("location_slug" to "lab-beta"))
        expectRefusal(served() - WinnV3SessionPlan.KEY_SELECTED_NODE)
        expectRefusal(served(WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta"))
        expectRefusal(
            served(
                WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "k1",
                WinnV3SessionPlan.KEY_SELECTED_NODE to kelvin,
            ),
        )

        val protocolOnly = served() - WinnV3SessionPlan.KEY_CARRIER +
            (WinnV3SessionPlan.KEY_PROTOCOL to WinnV3SessionPlan.PROTOCOL_V3) +
            (WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta")
        assertTrue(WinnV3SessionPlan.isRequested(protocolOnly))
        expectRefusal(protocolOnly)
        assertFalse(WinnV3SessionPlan.descriptorMatchesSelectedNode(protocolOnly))
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
        )
        section.putAll(extra)
        return section
    }

    private fun expectRefusal(section: Map<String, String>) {
        val stripped = section - WinnV3SessionPlan.KEY_INNER_V4
        val error = assertThrows(IllegalArgumentException::class.java) {
            WinnV3SessionPlan.from(
                section = stripped,
                relayInnerAddress = "",
                dnsServers = listOf("10.10.0.1"),
                promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
                ipv6SinkAddress = "fd00:d951:0001::1",
            )
        }
        assertEquals(
            WinnV3SessionPlan.DESCRIPTOR_NODE_BINDING_REFUSAL,
            error.message,
        )
    }
}
