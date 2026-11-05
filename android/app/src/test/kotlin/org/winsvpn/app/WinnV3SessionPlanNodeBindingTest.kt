package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Native Android descriptor-to-selected-node binding, independent of Dart.
 *
 * Dart already refuses Unicode case folding, conflicting aliases, a missing
 * identity, and cross-node replay before it emits `[winn]`. This class is the
 * native gate for a hostile INI that skipped that path: [WinnV3SessionPlan.from]
 * must refuse the same shapes before it reads `inner_v4` or any other
 * credential-bearing field.
 */
class WinnV3SessionPlanNodeBindingTest {

    @Test
    fun `ASCII mixed-case selected node matches the signed descriptor node`() {
        assertEquals("lab-alpha", WinnV3SessionPlan.normalizedNodeIdentity("Lab-Alpha"))
        assertEquals("lab-alpha", WinnV3SessionPlan.normalizedNodeIdentity(" lab-alpha "))
        assertEquals("lab-alpha", WinnV3SessionPlan.asciiLowercase("LAB-ALPHA"))
        assertEquals("id-1", WinnV3SessionPlan.normalizedNodeIdentity("ID-1"))

        val plan = plan(
            served(
                WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "Lab-Alpha",
                WinnV3SessionPlan.KEY_SELECTED_NODE to "LAB-ALPHA",
            ),
        )
        assertEquals("203.0.113.7:51820", plan.gatewayEndpoint)
        assertEquals("10.10.0.9", plan.engineConfig.innerAddress)
    }

    @Test
    fun `each selected-node alias alone binds when it names the signed node`() {
        for (key in WinnV3SessionPlan.SELECTED_NODE_IDENTITY_KEYS) {
            val section = served() - WinnV3SessionPlan.KEY_SELECTED_NODE
            val bound = section + (key to "lab-alpha")
            assertEquals(key, "lab-alpha", WinnV3SessionPlan.selectedNodeIdentity(bound))
            assertTrue(key, WinnV3SessionPlan.descriptorMatchesSelectedNode(bound))
            plan(bound)
        }
    }

    @Test
    fun `agreeing aliases still start`() {
        val section = served(
            "node_slug" to "lab-alpha",
            "nodeslug" to "LAB-ALPHA",
            "location_slug" to "lab-alpha",
            WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-alpha",
        )
        assertEquals("lab-alpha", WinnV3SessionPlan.selectedNodeIdentity(section))
        plan(section)
    }

    @Test
    fun `a matching decoy alias cannot hide a different selected node`() {
        expectBindingRefusal(
            served(
                "node_slug" to "lab-alpha",
                "location_slug" to "lab-beta",
            ),
        )
    }

    @Test
    fun `selected_node disagreeing with node_slug is a mismatch not first-wins`() {
        expectBindingRefusal(
            served(
                "node_slug" to "lab-alpha",
                WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta",
            ),
        )
    }

    @Test
    fun `missing selected-node identity refuses before credentials`() {
        val missing = served() - WinnV3SessionPlan.KEY_SELECTED_NODE
        assertEquals("", WinnV3SessionPlan.selectedNodeIdentity(missing))
        expectBindingRefusal(missing, innerV4MustStayUnread = true)
    }

    @Test
    fun `whitespace-only selected node is missing not a match`() {
        expectBindingRefusal(
            served(WinnV3SessionPlan.KEY_SELECTED_NODE to "   "),
        )
    }

    @Test
    fun `literal auto is reserved and cannot bind as a concrete route`() {
        assertNull(WinnV3SessionPlan.normalizedNodeIdentity("auto"))
        expectBindingRefusal(
            served(
                WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "auto",
                WinnV3SessionPlan.KEY_SELECTED_NODE to "auto",
            ),
        )
    }

    @Test
    fun `a JSON object string is not toString-coerced into a slug`() {
        expectBindingRefusal(
            served() - WinnV3SessionPlan.KEY_SELECTED_NODE +
                (WinnV3SessionPlan.KEY_SELECTED_NODE to "{slug=lab-alpha, name=Lab Alpha}"),
        )
    }

    @Test
    fun `cross-node signed lab-alpha cannot start as lab-beta`() {
        val replayed = served(WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta")
        assertEquals(
            "lab-alpha",
            WinnV3SessionPlan.normalizedNodeIdentity(
                replayed[WinnV3SessionPlan.KEY_DESCRIPTOR_NODE],
            ),
        )
        assertFalse(WinnV3SessionPlan.descriptorMatchesSelectedNode(replayed))
        expectBindingRefusal(replayed)
    }

    @Test
    fun `replayed descriptor cannot retarget a previously accepted envelope`() {
        val accepted = served()
        plan(accepted)
        val replayed = accepted + (WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta")
        assertEquals(
            accepted[WinnV3SessionPlan.KEY_DESCRIPTOR_NODE],
            replayed[WinnV3SessionPlan.KEY_DESCRIPTOR_NODE],
        )
        assertEquals(
            accepted["inner_v4"],
            replayed["inner_v4"],
        )
        expectBindingRefusal(replayed)
    }

    @Test
    fun `protocol 3 without carrier is not a binding bypass`() {
        val hostile = served() - WinnV3SessionPlan.KEY_CARRIER +
            (WinnV3SessionPlan.KEY_PROTOCOL to WinnV3SessionPlan.PROTOCOL_V3) +
            (WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta")
        assertTrue(WinnV3SessionPlan.isRequested(hostile))
        expectBindingRefusal(hostile)
    }

    @Test
    fun `Unicode homoglyphs folds and compatibility forms cannot bind`() {
        val hostileSelected = listOf(
            "l\u0430b-alpha", // Cyrillic a
            "lab-\u03b1lpha", // Greek alpha
            "lab-alpha\u200b", // zero-width space
            "lab-\u0061\u0301lpha", // combining acute
            "lab\u2010alpha", // hyphen vs non-breaking hyphen
            "\uff4c\uff41\uff42-\uff41\uff4c\uff50\uff48\uff41", // fullwidth
            "lab-alpha\u00a0", // NBSP: Kotlin trim() would eat it
        )
        for (selected in hostileSelected) {
            assertNull(
                "selected=$selected must not fold onto lab-alpha",
                WinnV3SessionPlan.normalizedNodeIdentity(selected),
            )
            expectBindingRefusal(
                served(WinnV3SessionPlan.KEY_SELECTED_NODE to selected),
            )
        }
    }

    @Test
    fun `Kelvin-sign case fold cannot match a signed k1 node`() {
        val kelvin = "\u212A1"
        assertEquals(
            "this host's Unicode lowercase still folds Kelvin; ASCII identity is the gate",
            "k1",
            kelvin.lowercase(),
        )
        assertNull(WinnV3SessionPlan.normalizedNodeIdentity(kelvin))
        assertEquals("k1", WinnV3SessionPlan.normalizedNodeIdentity("k1"))
        assertEquals("\u212A1", WinnV3SessionPlan.asciiLowercase(kelvin))

        expectBindingRefusal(
            served(
                WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "k1",
                WinnV3SessionPlan.KEY_SELECTED_NODE to kelvin,
            ),
        )
        expectBindingRefusal(
            served(
                WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to kelvin,
                WinnV3SessionPlan.KEY_SELECTED_NODE to "k1",
            ),
        )
    }

    @Test
    fun `Turkish dotted I cannot fold onto ascii i`() {
        val dotted = "\u0130d-1"
        assertNull(WinnV3SessionPlan.normalizedNodeIdentity(dotted))
        expectBindingRefusal(
            served(
                WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "id-1",
                WinnV3SessionPlan.KEY_SELECTED_NODE to dotted,
            ),
        )
    }

    @Test
    fun `binding refusal does not authorize reading device or gateway keys`() {
        val hostile = served(WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta")
        val error = expectBindingRefusal(hostile, innerV4MustStayUnread = true)
        assertFalse(error.message.orEmpty().contains("static_private"))
        assertFalse(error.message.orEmpty().contains("gateway_static"))
        assertFalse(error.message.orEmpty().contains("admission_key"))
        assertFalse(error.message.orEmpty().contains("inner_v4"))
    }

    @Test
    fun `V3_KEYS reserves every selected-node alias`() {
        for (key in WinnV3SessionPlan.SELECTED_NODE_IDENTITY_KEYS) {
            assertTrue(key, key in WinnV3SessionPlan.V3_KEYS)
        }
        assertTrue(WinnV3SessionPlan.KEY_DESCRIPTOR_NODE in WinnV3SessionPlan.V3_KEYS)
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

    private fun expectBindingRefusal(
        section: Map<String, String>,
        innerV4MustStayUnread: Boolean = false,
    ): IllegalArgumentException {
        val toBuild = if (innerV4MustStayUnread) {
            section - WinnV3SessionPlan.KEY_INNER_V4
        } else {
            section
        }
        val error = assertThrows(IllegalArgumentException::class.java) {
            WinnV3SessionPlan.from(
                section = toBuild,
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
        return error
    }
}
