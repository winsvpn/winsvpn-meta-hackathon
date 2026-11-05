package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the protocol gate of [WinnEngineConfig].
 *
 * [WinnEngineConfig.from] is the v1 configuration builder and the FOURTH
 * anti-downgrade gate: it refuses to emit a document for a `[winn]` section that
 * selects Winn Protocol v3, because a v1 document built for a v3 configuration
 * is a silent downgrade -- a session the user believes is censored-resistant
 * Winn v3 while it carries classical AmneziaWG. The gate keys on the host's
 * selector constants in [WinnV3SessionPlan], and those constants are what this
 * file pins.
 *
 * The engine's canonical protocol version string -- the one the control plane
 * and the datapath emit as `protocol_version` -- is `"winn/3"`
 * (`winn_protocol_experimental/internal/connectivity/contract.go`, `Version`;
 * `winn_protocol_experimental/winn3/session/config.go`,
 * `winn3ProtocolVersion`). This host's own INI-level selector is the bare `"3"`,
 * and the two are NOT interchangeable: [WinnV3SessionPlan.isRequested] matches
 * exactly `"3"`, and a served value like `"winn/3"` is REFUSED rather than
 * defaulted. Pinning that exactness is the whole point -- a fuzzy match here
 * would decide which protocol the user's traffic crosses, with no symptom when
 * it is wrong.
 */
class WinnEngineConfigPinTest {

    private fun v1Section(vararg pairs: Pair<String, String>): Map<String, String> =
        linkedMapOf("enabled" to "true", "endpoint" to "203.0.113.7:51820", *pairs)

    // ------------------------------------------------------------------
    // The pinned constants. If either KEY_PROTOCOL or PROTOCOL_V3 drifts, the
    // behavioural gate below stops firing against a real v3 section and the
    // tests in the next block go red -- that is the mutation this pin exists
    // to catch.
    // ------------------------------------------------------------------

    @Test
    fun `the gate selector is pinned to protocol equals 3`() {
        assertEquals(
            "the [winn] key that selects v3",
            "protocol",
            WinnV3SessionPlan.KEY_PROTOCOL,
        )
        assertEquals(
            "the exact value that means v3 -- not the engine's 'winn/3', not 'v3', not '3.0'",
            "3",
            WinnV3SessionPlan.PROTOCOL_V3,
        )
        // The two spellings must not be confused: the host selector is "3", the
        // engine's canonical protocol_version is "winn/3". Asserting both means
        // a future alignment edit that renames the selector to "winn/3" fails
        // here, loudly, instead of silently changing what the gate matches.
        assertTrue(
            "the host selector '3' is what selects v3",
            WinnV3SessionPlan.isRequested(mapOf("protocol" to "3")),
        )
        assertFalse(
            "the engine's spelling 'winn/3' is not the host's selector",
            WinnV3SessionPlan.isRequested(mapOf("protocol" to "winn/3")),
        )
    }

    // ------------------------------------------------------------------
    // The gate, behavioural. A change to PROTOCOL_V3 that stops the gate firing
    // on a real "3" section fails here even if the constant pin above were
    // deleted.
    // ------------------------------------------------------------------

    @Test
    fun `WinnEngineConfig refuses a protocol 3 section reaching the v1 builder`() {
        val thrown = runCatching {
            WinnEngineConfig.from(
                section = v1Section("protocol" to WinnV3SessionPlan.PROTOCOL_V3),
                mtu = 1280,
            )
        }.exceptionOrNull()
        assertNotNull(
            "a section selecting protocol 3 reaching the v1 builder must be refused, " +
                "or the user gets AmneziaWG while believing they have winn/3",
            thrown,
        )
        val message = thrown!!.message.orEmpty()
        assertTrue(
            "the refusal must name the silent downgrade",
            message.contains("silent downgrade"),
        )
        assertTrue(
            "it must state the payload it refuses to emit",
            message.contains(WinnEngineConfig.PAYLOAD_AWG_DATAGRAM),
        )
    }

    @Test
    fun `the served carrier spelling winn3 trips the same gate`() {
        // The control plane serves `[winn] carrier = winn3`; it must be refused
        // here just as hard as `protocol = 3`.
        val thrown = runCatching {
            WinnEngineConfig.from(
                section = v1Section("carrier" to "winn3"),
                mtu = 1280,
            )
        }.exceptionOrNull()
        assertNotNull(
            "a carrier=winn3 section reaching the v1 builder must be refused",
            thrown,
        )
        assertTrue(thrown!!.message.orEmpty().contains("silent downgrade"))
    }

    // ------------------------------------------------------------------
    // Controls. The gate must fire only for v3, never for a v1 section.
    // ------------------------------------------------------------------

    @Test
    fun `a section without the v3 selector still builds`() {
        val config = WinnEngineConfig.from(section = v1Section(), mtu = 1280)
        assertTrue(config.toConfigJson().contains("\"payload\":\"awg-datagram\""))
    }

    @Test
    fun `the canonical engine string winn3 is refused as a host protocol value, never defaulted`() {
        val refused = WinnV3SessionPlan.refuseUnknownProtocol(mapOf("protocol" to "winn/3"))
        assertNotNull(
            "the engine's 'winn/3' must not be accepted as a host protocol selector; " +
                "a fuzzy match here is a downgrade the user cannot see",
            refused,
        )
        assertTrue(refused!!, refused.contains("winn/3"))
        assertFalse(
            "a served 'winn/3' must not be treated as v3",
            WinnV3SessionPlan.isRequested(mapOf("protocol" to "winn/3")),
        )
    }
}
