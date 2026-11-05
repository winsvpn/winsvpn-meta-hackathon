package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Focused coverage for [WinnEngineConfig] field defaulting and the JVM
 * "method not mocked" path documented at WinnEngineConfig.kt:37.
 *
 * The class deliberately builds its JSON by hand (no `org.json`). On the
 * Android unit-test `android.jar`, `org.json` is a stub whose every method
 * throws "not mocked", so a config builder that used it would be untestable on
 * the JVM. These tests pin the defaults the way the shipping path resolves
 * them, and assert the exact document a defaulted section produces -- so if a
 * future edit pulls in a stubbed Android API, the JVM run fails here instead of
 * silently.
 */
class WinnEngineConfigDefaultingTest {

    private fun section(vararg pairs: Pair<String, String>): Map<String, String> =
        linkedMapOf("enabled" to "true", "endpoint" to "203.0.113.7:51820", *pairs)

    private fun config(vararg pairs: Pair<String, String>) =
        WinnEngineConfig.from(section = section(*pairs), mtu = 1280)

    @Test
    fun everyFieldDefaultsToItsShippingValue() {
        // A section that names only what a v1 deployment always names. Every
        // other field must land on its documented default, not on a sentinel.
        val c = config()
        assertEquals(WinnEngineConfig.CARRIER_DIRECT_AWG, c.carrier)
        assertEquals(WinnEngineConfig.MAX_DATAGRAM_CEILING, c.maxDatagram)
        assertEquals("", c.sessionId)
        assertNull(c.awgHeaderTypes)
        assertFalse(c.requiresCarrierProfile)
    }

    @Test
    fun aDefaultedSectionEmitsExactlyTheEngineDocument() {
        // The exact document `datapath.Config` decodes for the defaulted
        // section. Deterministic byte-for-byte output is the strongest proof
        // that this builder runs on the plain JVM without any Android API.
        val expected =
            "{\"contract\":\"winn-datapath/1\",\"payload\":\"awg-datagram\"," +
                "\"carrier\":\"direct-awg\",\"gateway_endpoint\":\"203.0.113.7:51820\"," +
                "\"max_datagram\":1500,\"allow_own_socket\":false}"
        assertEquals(expected, config().toConfigJson())
    }

    @Test
    fun theJsonBuilderRunsOnTheJvmWithoutANotMockedStub() {
        // org.json on the unit-test android.jar throws "not mocked" for every
        // call. If toConfigJson ever started using it, this call would throw a
        // RuntimeException whose message contains "not mocked" instead of
        // returning a document. The document must never be built that way.
        val json = config("h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40")
            .toConfigJson()
        assertTrue(json, json.startsWith("{"))
        assertTrue(json, json.endsWith("}"))
        // A "not mocked" stub would have surfaced a RuntimeException before we
        // ever got a value here; reaching the assertion at all is the guard.
        assertTrue(json, json.contains("\"awg_header_types\""))
    }

    @Test
    fun explicitValuesOverrideEveryDefault() {
        val c = config(
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
            "max_datagram" to "1280",
            "session_id" to "abc",
            "h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40",
            "s1" to "16", "s2" to "80", "s3" to "16", "s4" to "0",
        )
        assertEquals(WinnEngineConfig.CARRIER_HTTP3, c.carrier)
        assertEquals(1280, c.maxDatagram)
        assertEquals("abc", c.sessionId)
        assertTrue(c.requiresCarrierProfile)
        val json = c.toConfigJson()
        assertTrue(json, json.contains("\"carrier\":\"http3-connect-udp\""))
        assertTrue(json, json.contains("\"max_datagram\":1280"))
        assertTrue(json, json.contains("\"session_id\":\"abc\""))
        assertTrue(json, json.contains("\"s1\":16,\"s2\":80,\"s3\":16,\"s4\":0"))
    }

    @Test
    fun thePaddingOffsetsThatShippingProfileUsesSurviveTheBoundary() {
        // The app writes S1=16, S2=80, S3=16, S4=0 into the AmneziaWG
        // [Interface] section; those are the real offsets in use. They must
        // reach the engine unchanged, not be re-defaulted to zero.
        val json = config(
            "h1" to "10", "h2" to "20", "h3" to "30", "h4" to "40",
            "s1" to "16", "s2" to "80", "s3" to "16", "s4" to "0",
        ).toConfigJson()
        assertTrue(json, json.contains("\"h1\":10,\"h2\":20,\"h3\":30,\"h4\":40"))
        assertTrue(json, json.contains("\"s1\":16,\"s2\":80,\"s3\":16,\"s4\":0"))
    }

    @Test
    fun aRangeHeaderTypeTravelsAsAQuotedString() {
        // Ranges are JSON strings, scalars are JSON numbers -- mirrors the hub
        // and the Go datapath. A regression that emitted a range as a number
        // would produce a document the engine's decoder rejects.
        val json = config("h1" to "10-100", "h2" to "200", "h3" to "300", "h4" to "400")
            .toConfigJson()
        assertTrue(json, json.contains("\"h1\":\"10-100\""))
        assertTrue(json, json.contains("\"h2\":200"))
    }
}