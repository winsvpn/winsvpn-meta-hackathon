package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The configuration document the engine actually decodes.
 *
 * `datapath.Config` uses `DisallowUnknownFields`, so a key this host invents is
 * a hard create-time failure rather than a silent default. That the real engine
 * accepts what this class emits is proved against the real binary in
 * WinnEngineInteropTest; these tests pin the shape and the local validation.
 */
class WinnEngineConfigTest {

    private fun section(vararg pairs: Pair<String, String>): Map<String, String> =
        linkedMapOf("enabled" to "true", "endpoint" to "203.0.113.7:51820", *pairs)

    private fun config(vararg pairs: Pair<String, String>) =
        WinnEngineConfig.from(section = section(*pairs), mtu = 1280)

    @Test
    fun anAbsentOrFalseSectionLeavesTheShippingPathAlone() {
        assertFalse(WinnEngineConfig.isEnabled(emptyMap()))
        assertFalse(WinnEngineConfig.isEnabled(mapOf("enabled" to "false")))
        assertFalse(WinnEngineConfig.isEnabled(mapOf("enabled" to "")))
        assertFalse(WinnEngineConfig.isEnabled(mapOf("endpoint" to "a:1")))
        for (truthy in listOf("true", "TRUE", "1", "yes", "y", " true ")) {
            assertTrue(truthy, WinnEngineConfig.isEnabled(mapOf("enabled" to truthy)))
        }
    }

    @Test
    fun emitsOnlyFieldsTheEngineDefines() {
        val json = config().toConfigJson()
        // Exactly the keys of datapath.Config, and no others.
        val keys = Regex("\"([a-z0-9_]+)\":").findAll(json).map { it.groupValues[1] }.toList()
        assertEquals(
            listOf(
                "contract", "payload", "carrier", "gateway_endpoint",
                "max_datagram", "allow_own_socket",
            ),
            keys,
        )
        assertTrue(json, json.contains("\"contract\":\"winn-datapath/1\""))
        assertTrue(json, json.contains("\"payload\":\"awg-datagram\""))
        assertTrue(json, json.contains("\"carrier\":\"direct-awg\""))
        assertTrue(json, json.contains("\"gateway_endpoint\":\"203.0.113.7:51820\""))
    }

    @Test
    fun noneOfTheOldKeysSurvive() {
        // Every one of these was in the previous document, and not one of them
        // is a field of datapath.Config. The first would have failed the decode
        // even if the framing had been right.
        val json = config().toConfigJson()
        for (dead in listOf(
            "winn_framing_version", "role", "\"endpoint\"", "\"mtu\"",
            "tunnel_address", "\"dns\"", "udp_socket", "params",
        )) {
            assertFalse("$dead must not appear: $json", json.contains(dead))
        }
    }

    @Test
    fun theEngineIsNeverPermittedToOpenItsOwnSocket() {
        // On Android an unmarked socket dead-loops the tunnel.
        assertTrue(config().toConfigJson().contains("\"allow_own_socket\":false"))
    }

    @Test
    fun payloadIsAlwaysTheAwgDatagramMode() {
        // Declaring ip-packet would be refused by the engine, and declaring
        // awg-datagram while pumping tun packets would put cleartext on the
        // wire. The host declares the truthful mode and supplies it or refuses
        // to start; see WinnTunnelBridge.
        assertTrue(config().toConfigJson().contains("\"payload\":\"awg-datagram\""))
        assertEquals("awg-datagram", WinnEngineConfig.PAYLOAD_AWG_DATAGRAM)
    }

    @Test
    fun hostnameEndpointsAreRefusedBecauseTheEngineWillNotResolveThem() {
        for (bad in listOf(
            "winn.example.org:51820",
            "localhost:51820",
            "example.com:1",
            "203.0.113.7",
            "203.0.113.7:0",
            "203.0.113.7:70000",
            "0.0.0.0:51820",
            "239.1.2.3:51820",
            "",
        )) {
            try {
                WinnEngineConfig.from(
                    section = linkedMapOf("enabled" to "true", "endpoint" to bad),
                    mtu = 1280,
                )
                fail("endpoint '$bad' should have been refused")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun ipLiteralEndpointsAreAccepted() {
        assertTrue(WinnEngineConfig.isIpLiteralEndpoint("203.0.113.7:51820"))
        assertTrue(WinnEngineConfig.isIpLiteralEndpoint("[2001:db8::1]:51820"))
        assertFalse(WinnEngineConfig.isIpLiteralEndpoint("[2001:db8::1]"))
        assertFalse(WinnEngineConfig.isIpLiteralEndpoint("winn.example.org:51820"))
        assertFalse(WinnEngineConfig.isIpLiteralEndpoint("[ff02::1]:51820"))
        for (bad in listOf("[:::]:51820", "[2001::db8::1]:51820", "[2001:db8:zz::1]:51820",
                "[fe80::1%wlan0]:51820", "[::]:51820")) {
            assertFalse(bad, WinnEngineConfig.isIpLiteralEndpoint(bad))
        }
    }

    @Test
    fun unknownSectionKeysAreRefusedRatherThanForwardedOrDropped() {
        // Forwarding them would fail the engine's decode; dropping them would
        // leave an operator believing a setting took effect.
        //
        // The example used to be `suite`, which is now a REAL carrier profile
        // key -- so it is deliberately something no document defines, to keep
        // this testing the refusal rather than a key that has since been
        // implemented.
        try {
            WinnEngineConfig.from(section = section("kem_ciphertext" to "BASE64"), mtu = 1280)
            fail("an unknown [winn] key should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("kem_ciphertext"))
            assertTrue(e.message!!, e.message!!.contains("rejects unknown fields"))
        }
    }

    @Test
    fun aCarrierKeyIsConsumedAndNeverForwardedToTheEngine() {
        // Every carrier profile key is accepted by the section parser and
        // absent from the Create document. datapath.Config's decoder would
        // reject any of them, so forwarding one is a hard create-time error.
        val carrierSection = section(
            "carrier" to WinnEngineConfig.CARRIER_HTTP3,
            "masque_template" to "https://c.example/.well-known/masque/udp/{target_host}/{target_port}/",
            "public_target" to "198.51.100.20:51820",
            "server_name" to "gateway.example",
            "suite" to "x25519-mlkem768",
            "controller_id" to "controller-1",
            "device_id" to "device-1",
            "device_pq_algorithm" to "mldsa65",
            "manifest_digest" to "a".repeat(64),
            "privacy_profile" to "high-risk",
        )
        val config = WinnEngineConfig.from(section = carrierSection, mtu = 1280)
        assertTrue(config.requiresCarrierProfile)
        assertEquals(WinnEngineConfig.CARRIER_HTTP3, config.carrier)
        val json = config.toConfigJson()
        assertTrue(json, json.contains("\"carrier\":\"http3-connect-udp\""))
        for (key in WinnCarrierProfile.CARRIER_KEYS) {
            assertFalse("$key leaked into the Create document: $json", json.contains("\"$key\""))
        }
    }

    @Test
    fun aCarrierWithoutItsProfileFieldsIsRefusedByName() {
        // The section named an authenticated carrier and carried nothing to
        // build a profile from. Starting direct-awg instead would be the silent
        // downgrade three layers of gates exist to prevent.
        try {
            WinnEngineConfig.from(
                section = section("carrier" to WinnEngineConfig.CARRIER_HTTP3),
                mtu = 1280,
            )
            fail("a carrier with no profile fields should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("manifest_digest"))
            assertTrue(e.message!!, e.message!!.contains("suite"))
            assertFalse(e.message!!, e.message!!.contains("starting direct-awg"))
        }
    }

    @Test
    fun http2IsRefusedForTheSocketThisHostDoesNotOpen() {
        try {
            WinnEngineConfig.from(
                section = section("carrier" to WinnEngineConfig.CARRIER_HTTP2),
                mtu = 1280,
            )
            fail("http2-stream should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("connected"))
            assertTrue(e.message!!, e.message!!.contains("TCP"))
        }
    }

    @Test
    fun anAbsentCarrierIsStillDirectAwgAndNeedsNoProfile() {
        val config = WinnEngineConfig.from(section = section(), mtu = 1280)
        assertEquals(WinnEngineConfig.CARRIER_DIRECT_AWG, config.carrier)
        assertFalse(config.requiresCarrierProfile)
    }

    @Test
    fun anUnknownCarrierIsRefusedRatherThanResolvedToDirectAwg() {
        for (carrier in listOf("reality-xhttp", "websocket-tls", "quic-v2")) {
            try {
                WinnEngineConfig.from(section = section("carrier" to carrier), mtu = 1280)
                fail("carrier '$carrier' should have been refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains(carrier))
                assertTrue(e.message!!, e.message!!.contains("refusing"))
            }
        }
    }

    @Test
    fun amneziaWgHeaderTypesAreAllOrNothingAndMustBeDistinct() {
        val json = config("h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40").toConfigJson()
        // s1..s4 are always emitted, defaulting to 0 (the unpadded WireGuard
        // layout) when the section omits them.
        assertTrue(
            json,
            json.contains(
                "\"awg_header_types\":{\"h1\":10,\"h2\":20,\"h3\":30,\"h4\":40," +
                    "\"s1\":0,\"s2\":0,\"s3\":0,\"s4\":0}"
            ),
        )

        try {
            config("h1" to "10", "h2" to "20").toConfigJson()
            fail("a partial header type set should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("all of h1..h4 or none"))
        }
        try {
            config("h1" to "10", "h2" to "10", "h3" to "30", "h4" to "40").toConfigJson()
            fail("duplicate header types should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("pairwise distinct"))
        }
        // Omitted entirely is legal: the engine falls back to WireGuard 1..4
        // and says so in status.
        assertFalse(config().toConfigJson().contains("awg_header_types"))
    }

    /**
     * The prefix padding sizes must survive the boundary.
     *
     * AmneziaWG PREPENDS s1 random bytes to a handshake initiation, s2 to a
     * response, s3 to a cookie reply and s4 to a transport datagram, so the
     * header word is at that offset rather than at 0. `datapath/classify.go`
     * is explicit that omitting s1/s2/s3 silently kills the handshake counters
     * and omitting a nonzero s4 kills the TRANSPORT counters -- the ones
     * `transport_observed_both_ways` is built from, which is the only field a
     * route-promotion gate may use.
     *
     * This app writes `S1 = 16`, `S2 = 80`, `S3 = 16`, `S4 = 0` into the
     * AmneziaWG `[Interface]` section, so those are the real offsets in use.
     */
    @Test
    fun amneziaWgPaddingSizesReachTheEngine() {
        val json = config(
            "h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40",
            "s1" to "16", "s2" to "80", "s3" to "16", "s4" to "0",
        ).toConfigJson()
        assertTrue(
            json,
            json.contains(
                "\"awg_header_types\":{\"h1\":10,\"h2\":20,\"h3\":30,\"h4\":40," +
                    "\"s1\":16,\"s2\":80,\"s3\":16,\"s4\":0}"
            ),
        )

        // Not all-or-none, unlike h1..h4: the shipping profile sets S4 = 0
        // deliberately while S1..S3 are nonzero, so requiring all four would
        // refuse this app's own configuration.
        val partial = config(
            "h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40", "s1" to "16",
        ).toConfigJson()
        assertTrue(partial, partial.contains("\"s1\":16,\"s2\":0,\"s3\":0,\"s4\":0"))

        // Padding without header types is refused rather than dropped: it would
        // shift where a header word is read from that the engine has no table
        // to match against.
        try {
            config("s1" to "16").toConfigJson()
            fail("padding without header types should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("require the header types"))
        }

        // 16-bit bound, matching the engine's uint16 fields.
        try {
            config(
                "h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40",
                "s1" to "65536",
            ).toConfigJson()
            fail("an out-of-range padding size should have been refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("16-bit unsigned"))
        }
    }

    @Test
    fun maxDatagramIsBoundedByTheEnginesOwnCeiling() {
        assertTrue(config().toConfigJson().contains("\"max_datagram\":1500"))
        assertTrue(config("max_datagram" to "").toConfigJson().contains("\"max_datagram\":1500"))
        assertTrue(config("max_datagram" to "1280").toConfigJson().contains("\"max_datagram\":1280"))
        for (bad in listOf("0", "31", "1501", "65535", "bad", "1280x", "999999999999999")) {
            try {
                config("max_datagram" to bad).toConfigJson()
                fail("max_datagram $bad should have been refused")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun sessionIdIsOptionalAndBounded() {
        assertFalse(config().toConfigJson().contains("session_id"))
        assertTrue(config("session_id" to "abc").toConfigJson().contains("\"session_id\":\"abc\""))
        try {
            config("session_id" to "x".repeat(129)).toConfigJson()
            fail("an over-long session_id should have been refused")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun anOutOfRangeMtuIsRefused() {
        for (mtu in listOf(0, 575, 9001)) {
            try {
                WinnEngineConfig.from(section = section(), mtu = mtu)
                fail("mtu $mtu should have been refused")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun describeForLogNeverCarriesAValue() {
        val described = config("session_id" to "super-secret-correlator").describeForLog()
        assertFalse(described, described.contains("super-secret-correlator"))
        assertFalse(described, described.contains("203.0.113.7"))
    }

    @Test
    fun jsonStringEscapesControlCharacters() {
        assertEquals("\"a\\\"b\"", WinnEngineConfig.jsonString("a\"b"))
        assertEquals("\"a\\\\b\"", WinnEngineConfig.jsonString("a\\b"))
        assertEquals("\"a\\nb\"", WinnEngineConfig.jsonString("a\nb"))
        assertEquals("\"\\u0000\"", WinnEngineConfig.jsonString("\u0000"))
    }
    /**
     * The THIRD anti-downgrade gate.
     *
     * Both other gates are in Dart. `toConfigJson` sits below both, and until
     * 2026-08-03 it emitted the carrier as a hard-coded constant -- so a
     * `winn/3` config those gates correctly approved still became whatever this
     * file said, beneath every gate that existed. Not an active downgrade while
     * direct-awg is the only buildable carrier, but a latent one the moment a
     * carrier lands.
     */
    @Test
    fun theCarrierIsResolvedAndAnUnsupportedOneIsRefused() {
        // Absent: today's behaviour, unchanged.
        assertTrue(config().toConfigJson().contains("\"carrier\":\"direct-awg\""))

        // Declared and supported: honoured, not ignored.
        assertTrue(
            config("carrier" to "direct-awg").toConfigJson()
                .contains("\"carrier\":\"direct-awg\"")
        )

        // Declared but unbuildable: refused rather than silently replaced with
        // direct-awg, which is exactly the downgrade this gate exists to stop.
        for (unsupported in listOf("h2", "h3", "masque", "anything-else")) {
            try {
                config("carrier" to unsupported).toConfigJson()
                fail("carrier '$unsupported' should have been refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!, e.message!!.contains("is not one this engine can build"))
            }
        }
    }

}
