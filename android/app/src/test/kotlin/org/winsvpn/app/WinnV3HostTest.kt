package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The v3 host contract: the capability probe, the spawn argv and the create
 * payload.
 *
 * The most load-bearing test in this file is
 * [the probe refuses the shipping banner], because the shipping banner names
 * both payloads in English and a substring search would match the sentence that
 * says the OPPOSITE of what a v3 host needs.
 */
class WinnV3HostTest {

    /** The banner `cmd/winn-datapath -print-contract` emits today, verbatim. */
    private val shippingBanner = """
        {"contract":"1","protocol_version":3,"wire":1,"frame_magic":"0x334E4E57",
         "frame_version":1,"frame_header_size":16,"max_frame_payload":65535,
         "max_datagram":65535,
         "payload_semantics":"inbound and outbound frames carry AmneziaWG outer datagrams, not raw IP packets",
         "carrier_profile_version":1,"carriers":["direct-awg","http3","http2"],
         "goos":"android","goarch":"arm64"}
    """.trimIndent()

    // --- the capability probe ------------------------------------------------

    @Test
    fun `the probe refuses the shipping banner`() {
        // It contains the words "ip packets" and the word "payload". A prose
        // match would pass. The probe must not.
        assertFalse(WinnV3Host.engineSupportsV3(shippingBanner))
    }

    @Test
    fun `the probe accepts a machine readable payload list naming ip-packet`() {
        val v3 = """{"frame_version":1,"payloads":["awg-datagram","ip-packet"]}"""
        assertTrue(WinnV3Host.engineSupportsV3(v3))
    }

    @Test
    fun `the probe refuses a payload list that does not name ip-packet`() {
        assertFalse(WinnV3Host.engineSupportsV3("""{"payloads":["awg-datagram"]}"""))
        assertFalse(WinnV3Host.engineSupportsV3("""{"payloads":[]}"""))
    }

    @Test
    fun `the probe refuses a truncated or empty banner rather than guessing`() {
        assertFalse(WinnV3Host.engineSupportsV3(""))
        assertFalse(WinnV3Host.engineSupportsV3("""{"payloads":["ip-packet" """))
        assertFalse(WinnV3Host.engineSupportsV3("not json at all"))
    }

    @Test
    fun `the probe does not match a substring of a longer payload name`() {
        // "ip-packet-experimental" is not "ip-packet".
        assertFalse(WinnV3Host.engineSupportsV3("""{"payloads":["ip-packet-experimental"]}"""))
    }

    @Test
    fun `the refusal names the seam so it can be acted on without this file`() {
        val text = WinnV3Host.capabilityRefusal(shippingBanner)
        assertTrue(text.contains("cmd/winn-datapath"))
        assertTrue(text.contains("-winn3"))
        assertTrue(text.contains("rx_packets"))
        assertTrue(text.contains("carrier.NewUDP"))
        // The banner is quoted so the log says what was actually found.
        assertTrue(text.contains("payload_semantics"))
    }

    @Test
    fun `the refusal explains why a v2 fallback would be a downgrade`() {
        assertTrue(WinnV3Host.NO_V3_ENGINE.contains("silent downgrade"))
    }

    // --- the spawn argv --------------------------------------------------------

    @Test
    fun `the v3 argv is the v2 argv plus one flag`() {
        val v2 = WinnAndroidEngineHost.engineArguments("/lib/libwinnengine.so", "chan-1")
        val v3 = WinnV3Host.engineArguments("/lib/libwinnengine.so", "chan-1")
        assertEquals(v2 + WinnV3Host.FLAG_WINN3, v3)
        // The spawn contract is read from the engine, not assumed: nothing is
        // positional, because flags.NArg() != 0 is fatal in cmd/winn-datapath.
        assertEquals("/lib/libwinnengine.so", v3.first())
        assertTrue(v3.contains("-transport"))
        assertTrue(v3.contains("unix"))
        assertTrue(v3.contains("@chan-1"))
        assertTrue(v3.contains("-receive-fd"))
        assertEquals(0, v3.drop(1).count { !it.startsWith("-") && !isFlagValue(v3, it) })
    }

    @Test
    fun `the v3 argv carries a carrier profile when one is supplied`() {
        val v3 = WinnV3Host.engineArguments("/lib/e.so", "chan", "/data/profile.json")
        assertTrue(v3.contains("-carrier-profile"))
        assertTrue(v3.contains("/data/profile.json"))
        assertEquals(WinnV3Host.FLAG_WINN3, v3.last())
    }

    // --- the create payload ------------------------------------------------------

    @Test
    fun `a v3 config announces ip-packet and never the v2 payload`() {
        val json = config().toJson()
        assertTrue(json.contains("\"payload\":\"ip-packet\""))
        assertFalse(json.contains(WinnEngineConfig.PAYLOAD_AWG_DATAGRAM))
    }

    @Test
    fun `a v3 config never lets the engine open its own socket or own the tun`() {
        val json = config().toJson()
        assertTrue(json.contains("\"allow_own_socket\":false"))
        assertTrue(json.contains("\"owns_tun\":false"))
    }

    @Test
    fun `a v3 config carries the inner MTU and the migration plan`() {
        val json = config().toJson()
        // 1359, not 1443. 1443 is InnerMTUForPath(1500, 28) — the overhead of a
        // DIALLED UDP-over-IPv4 carrier — and this plan may migrate to TLS over
        // IPv6, whose overhead is 112. The 84-byte difference is the black hole.
        assertTrue(json, json.contains("\"inner_mtu\":1359"))
        assertFalse(json.contains("\"inner_mtu\":1443"))
        assertTrue(json.contains("\"path_mtu\":1500"))
        assertTrue(json.contains("\"carrier_classes\":[\"udp\",\"tcp\",\"tls\"]"))
    }

    @Test
    fun `the create document is byte for byte what the Go seam decodes`() {
        // Pinned as a whole string, not field by field, because the thing being
        // proved is that THESE BYTES are accepted by decodeWinn3Create — the
        // same literal appears in the round-trip run recorded for this fix. A
        // per-field assertion would still pass if the framing drifted.
        assertEquals(
            """{"payload":"ip-packet","gateway_endpoint":"203.0.113.9:51820",""" +
                """"inner_address":"10.8.1.3","inner_next_hop":"10.8.1.1",""" +
                """"inner_mtu":1359,"path_mtu":1500,""" +
                """"carrier_classes":["udp","tcp","tls"],"session_id":"session-1",""" +
                """"allow_own_socket":false,"owns_tun":false}""",
            config().toJson(),
        )
    }

    // --- the plan floor, which is the whole of §4.2 --------------------------

    @Test
    fun `a v3 config refuses the dialled carriers inner MTU`() {
        // The exact fixture cmd/winn-datapath's TestTheAndroidFixtureIsRefused
        // runs. It must now be unrepresentable on this side of the seam.
        val e = try {
            WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1", innerMtu = 1443, pathMtu = 1500,
                carrierClasses = listOf("udp", "tcp", "tls"), sessionId = "session-1",
            )
            throw AssertionError("the 1443 fixture was accepted; the 84-byte gap is unguarded")
        } catch (e: IllegalArgumentException) {
            e
        }
        // The refusal names both numbers and what would happen, so a log line is
        // actionable without this file.
        assertTrue(e.message, e.message!!.contains("1443"))
        assertTrue(e.message, e.message!!.contains("1359"))
        assertTrue(e.message, e.message!!.contains("black-hole"))
    }

    @Test
    fun `a v3 config refuses an inner MTU one byte either side of the floor`() {
        // "At most the floor" is the wrong check and would pass 1358. The seam
        // accepts only the floor exactly; see TestTheFloorIsTheOnlyAcceptableInnerMTU.
        for (mtu in listOf(1360, 1358)) {
            try {
                WinnV3EngineConfig(
                    gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3",
                    innerNextHop = "10.8.1.1", innerMtu = mtu, pathMtu = 1500,
                    carrierClasses = listOf("udp", "tcp", "tls"), sessionId = "s",
                )
                throw AssertionError("inner MTU $mtu was accepted; only the floor may be")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.contains("1359"))
            }
        }
    }

    @Test
    fun `the floor depends on the whole plan and not on the class that was dialled`() {
        // A udp-only plan is genuinely wider, and the config layer must accept
        // ITS floor rather than one number for every plan. This is the test that
        // fails if the floor is ever hard-coded.
        val udpOnly = WinnV3EngineConfig(
            gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3",
            innerNextHop = "10.8.1.1",
            innerMtu = WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp")),
            pathMtu = 1500, carrierClasses = listOf("udp"), sessionId = "s",
        )
        // udp over IPv6 is the narrower family: 1500 − 48 − 29.
        assertTrue(udpOnly.toJson(), udpOnly.toJson().contains("\"inner_mtu\":1423"))
        // Adding tcp and tls to the plan narrows it by 64 more bytes.
        assertEquals(1359, WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp", "tcp", "tls")))
    }

    @Test
    fun `a v3 config refuses a carrier class the engine does not know`() {
        val e = try {
            WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1", innerMtu = 1359, pathMtu = 1500,
                carrierClasses = listOf("udp", "http3"), sessionId = "s",
            )
            throw AssertionError("an unknown carrier class was accepted")
        } catch (e: IllegalArgumentException) {
            e
        }
        assertTrue(e.message, e.message!!.contains("http3"))
    }

    @Test
    fun `a v3 config refuses an empty migration plan`() {
        val e = try {
            WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1", innerMtu = 1359, pathMtu = 1500,
                carrierClasses = emptyList(), sessionId = "s",
            )
            throw AssertionError("expected a refusal")
        } catch (e: IllegalArgumentException) {
            e
        }
        assertTrue(e.message!!.contains("84 bytes"))
    }

    @Test
    fun `a v3 config refuses an inner MTU below the IPv4 floor`() {
        try {
            WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820", innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1", innerMtu = 500, pathMtu = 1500,
                carrierClasses = listOf("udp"), sessionId = "s",
            )
            throw AssertionError("expected a refusal")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("576"))
        }
    }

    @Test
    fun `a v3 config refuses a blank gateway or a blank assignment`() {
        for (bad in listOf("gateway", "address")) {
            try {
                WinnV3EngineConfig(
                    gatewayEndpoint = if (bad == "gateway") "" else "203.0.113.9:51820",
                    innerAddress = if (bad == "address") "" else "10.8.1.3",
                    innerNextHop = "10.8.1.1", innerMtu = 1423, pathMtu = 1500,
                    carrierClasses = listOf("udp"), sessionId = "s",
                )
                throw AssertionError("expected a refusal for $bad")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
    }

    @Test
    fun `the v2 and v3 payload constants are different strings`() {
        assertFalse(WinnV3Host.PAYLOAD_IP_PACKET == WinnEngineConfig.PAYLOAD_AWG_DATAGRAM)
    }

    /**
     * The fixture, with the one number corrected.
     *
     * `cmd/winn-datapath/winn3_frame_test.go`'s `validCreate()` is this document
     * and carries the same 1359; `TestTheAndroidFixtureIsRefused` in that file
     * runs the bytes this used to produce and requires them refused.
     */
    private fun config() = WinnV3EngineConfig(
        gatewayEndpoint = "203.0.113.9:51820",
        innerAddress = "10.8.1.3",
        innerNextHop = "10.8.1.1",
        innerMtu = 1359,
        pathMtu = 1500,
        carrierClasses = listOf("udp", "tcp", "tls"),
        sessionId = "session-1",
    )

    private fun isFlagValue(argv: List<String>, value: String): Boolean {
        val i = argv.indexOf(value)
        return i > 0 && argv[i - 1].startsWith("-")
    }
}
