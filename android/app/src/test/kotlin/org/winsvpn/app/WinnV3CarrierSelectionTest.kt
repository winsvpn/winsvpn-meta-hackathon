package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The `carrier = winn3` parsing and normalisation branch.
 *
 * A `[winn]` section can carry `carrier = winn3`. That value is a PROTOCOL
 * selector: it chooses the v3 session plan (`WinnV3SessionPlan`) and must not
 * be confused with a carrier *profile* carrier such as `http3-connect-udp`,
 * which `WinnCarrierProfile` documents, or a buildable `datapath` carrier such
 * as `direct-awg`, which `WinnEngineConfig` admits. The three modules already
 * keep the two meanings apart; these tests pin where the boundary is and assert
 * the normalisation each side applies.
 *
 * Normalisation is real, not cosmetic: the selector trims and lower-cases the
 * served value before deciding which protocol crosses the user's traffic. A
 * value that stops matching after normalisation is refused or routed elsewhere,
 * never fuzzy-matched -- a fuzzy match here is a silently invisible downgrade.
 *
 * [WinnV3SessionPlan.isRequested] is the served branch and the subject of the
 * winn3 coverage. The `WinnEngineConfig` and `WinnCarrierProfile` checks in this
 * class are there because the same `carrier` spelling is parsed in three places
 * and a drift between them would mis-route a served config.
 */
class WinnV3CarrierSelectionTest {

    private fun carrier(raw: String): Map<String, String> =
        mapOf(WinnV3SessionPlan.KEY_CARRIER to raw)

    @Test
    fun carrierWinn3SelectsV3() {
        assertTrue(
            "carrier = winn3 must select the v3 plan",
            WinnV3SessionPlan.isRequested(carrier(WinnV3SessionPlan.CARRIER_WINN3)),
        )
    }

    @Test
    fun carrierValueIsNormalizedBeforeTheWinn3Test() {
        // The served spelling may arrive upper-cased, padded or tab-delimited.
        // The selector trims and lower-cases before comparing, so every one of
        // these resolves to the same winn3 branch. Removing either normaliser
        // makes at least one of these fail.
        for (raw in listOf(
            "winn3", "WINN3", "Winn3", " winn3 ", "WINN3   ", "\twinn3\t",
        )) {
            assertTrue("'$raw' must normalise to winn3", WinnV3SessionPlan.isRequested(carrier(raw)))
        }
    }

    @Test
    fun onlyExactWinn3AfterNormalizationSelectsV3() {
        // Negative controls. Both a fuzzy match (startsWith/contains) and a
        // miss silently change which protocol crosses the traffic, so each of
        // these must stay on the v1 side. A `startsWith` or missing-char
        // mutation makes one of these pass.
        for (raw in listOf(
            "winn2", "winn", "winns3", "winn3x", "winn32", "winn/3",
            "winn3-connect", "winn3_prod", "http3-connect-udp", "http2-stream",
            "direct-awg", "", " ",
        )) {
            assertFalse(
                "'$raw' must NOT select v3",
                WinnV3SessionPlan.isRequested(carrier(raw)),
            )
        }
    }

    @Test
    fun anEmptyOrAbsentCarrierDoesNotSelectV3() {
        assertFalse(WinnV3SessionPlan.isRequested(emptyMap()))
        assertFalse(WinnV3SessionPlan.isRequested(mapOf("protocol" to "1")))
        assertFalse(WinnV3SessionPlan.isRequested(mapOf("carrier" to "")))
    }

    @Test
    fun theTwoV3SpellingsAreIndependentSelectors() {
        // protocol = 3 selects v3 without a carrier, and carrier = winn3
        // selects v3 without protocol = 3. They are an OR, not a bundle.
        assertTrue(WinnV3SessionPlan.isRequested(mapOf("protocol" to "3")))
        assertTrue(WinnV3SessionPlan.isRequested(carrier("winn3")))
        // A carrier that is not winn3 does not rescue a missing protocol.
        assertFalse(WinnV3SessionPlan.isRequested(mapOf("protocol" to "1", "carrier" to "winn2")))
        // An unrecognised protocol spelling is not accepted as v3.
        assertFalse(
            WinnV3SessionPlan.isRequested(mapOf("protocol" to "v3", "carrier" to "http3-connect-udp")),
        )
    }

    private fun engineSection(vararg pairs: Pair<String, String>): Map<String, String> =
        linkedMapOf("enabled" to "true", "endpoint" to "203.0.113.7:51820", *pairs)

    @Test
    fun theEngineConfigRefusesAWinn3CarrierAtTheVDowngradeGate() {
        // The v1 `WinnEngineConfig` builder and `WinnV3SessionPlan` normalise
        // the served carrier value the same way (trim + lowercase), and the two
        // agree: WINN3 is winn3, and winn3 is a v3 PROTOCOL selector. So a
        // `carrier = WINN3` section reaching the v1 builder is refused by its
        // v3 anti-downgrade gate (which fires before carrier validation), not
        // by the "not a buildable carrier" branch -- a winn3 carrier here is a
        // silent downgrade in the making, and the gate is the load-bearing
        // guard for exactly that. This pins the boundary: `isRequested` accepts
        // winn3 for the v3 route, while this v1 builder refuses the same value
        // via the downgrade gate. If normalisation stopped lower-casing, WINN3
        // would no longer match `CARRIER_WINN3`, `isRequested` would return
        // false, and the section would fall through to the carrier branch and
        // be accepted as a v1 session -- so this test is what keeps the two
        // parsers in agreement.
        try {
            WinnEngineConfig.from(section = engineSection("carrier" to "WINN3"), mtu = 1280)
            fail("carrier = WINN3 normalises to winn3 and must be refused as a v3 request")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains(WinnV3SessionPlan.KEY_PROTOCOL))
            assertTrue(e.message, e.message!!.contains("downgrade"))
        }
    }

    @Test
    fun winn3IsACarrierProfileRefusalBecauseItSelectsTheV3Plan() {
        // WinnCarrierProfile documents the http3 profile and nothing else.
        // The `carrier = winn3` value a served section carries is a v3 protocol
        // selector, routed by isRequested to the plan -- so this builder must
        // refuse it loudly rather than treat it as a carrier it cannot
        // document. Passing carrier = winn3 here (rather than a http3 value)
        // exercises the exact misspelling/route confusion the three-way split
        // exists to catch. The refusal fires before credential resolution, so
        // no provisioned directory is needed.
        try {
            WinnCarrierProfile.from(
                section = engineSection("protocol" to "3", "carrier" to "winn3"),
                carrier = "winn3",
                credentialDirectory = File("/nonexistent/winn3-refusal"),
            )
            fail("carrier 'winn3' must be refused by the carrier profile builder")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("no carrier profile"))
            assertTrue(e.message!!, e.message!!.contains("winn3"))
        }
    }
}
