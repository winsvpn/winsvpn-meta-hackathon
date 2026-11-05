package org.winsvpn.app.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The watch must pair only with the signed release phone build.
 *
 * Wear's Data Layer pairs a watch node with a phone node only when both run the
 * same package signed with the same certificate, and the match is keyed on this
 * app's own identity. That makes the release binding a property of the exact
 * application id -- so a `.debug` or `.test` phone build (distinct application
 * ids, added in `android/app/build.gradle.kts`) is refused by construction.
 *
 * These tests pin [PairingMatcher] to that contract from BOTH directions: the
 * release package is accepted, and every non-release spelling is refused with a
 * reason naming why. Testing only the accepted case would be a positive fact
 * with nothing asserting the negative; the refusal cases are the load-bearing
 * half of the guarantee.
 */
class PairingMatcherTest {

    @Test
    fun `state and commands belong only to the selected phone node`() {
        assertTrue(PairingMatcher.matchesSelectedNode("phone-a", "phone-a"))
        assertFalse(PairingMatcher.matchesSelectedNode("phone-a", "phone-b"))
        assertFalse(PairingMatcher.matchesSelectedNode(null, "phone-a"))
        assertFalse(PairingMatcher.matchesSelectedNode("", "phone-a"))
        assertFalse(PairingMatcher.matchesSelectedNode("phone-a", null))
    }

    @Test
    fun `the release package is the only accepted identity`() {
        assertTrue(PairingMatcher.isRelease(PairingMatcher.RELEASE_PACKAGE))
        assertEquals(PairingMatcher.Verdict.Accepted, PairingMatcher.evaluate(PairingMatcher.RELEASE_PACKAGE))
    }

    @Test
    fun `the debug build is rejected`() {
        assertFalse(PairingMatcher.isRelease(PairingMatcher.DEBUG_PACKAGE))
        val verdict = PairingMatcher.evaluate(PairingMatcher.DEBUG_PACKAGE)
        assertFalse("debug must not be accepted", verdict is PairingMatcher.Verdict.Accepted)
        assertTrue("refusal must name why", (verdict as PairingMatcher.Verdict.Refused).reason.isNotBlank())
    }

    @Test
    fun `the QA test build is rejected`() {
        assertFalse(PairingMatcher.isRelease(PairingMatcher.QA_PACKAGE))
        val verdict = PairingMatcher.evaluate(PairingMatcher.QA_PACKAGE)
        assertFalse("qa must not be accepted", verdict is PairingMatcher.Verdict.Accepted)
        assertTrue("refusal must name why", (verdict as PairingMatcher.Verdict.Refused).reason.isNotBlank())
    }

    @Test
    fun `the stale TV package is rejected as contamination`() {
        assertFalse(PairingMatcher.isRelease(PairingMatcher.STALE_TV_PACKAGE))
        val verdict = PairingMatcher.evaluate(PairingMatcher.STALE_TV_PACKAGE)
        assertTrue(verdict is PairingMatcher.Verdict.Refused)
        assertEquals(
            "contaminated TV companion identity",
            (verdict as PairingMatcher.Verdict.Refused).reason,
        )
    }

    @Test
    fun `an unknown identity is rejected, not assumed release`() {
        assertFalse(PairingMatcher.isRelease("org.winsvpn.app.evil"))
        assertFalse(PairingMatcher.isRelease("com.attacker.org.winsvpn.app"))
        assertFalse(PairingMatcher.isRelease("org.winsvpn.app."))
        assertTrue(PairingMatcher.evaluate("org.winsvpn.app.evil") is PairingMatcher.Verdict.Refused)
    }

    @Test
    fun `a null identity is rejected as unknown`() {
        assertFalse(PairingMatcher.isRelease(null))
        assertTrue(PairingMatcher.evaluate(null) is PairingMatcher.Verdict.Refused)
    }

    @Test
    fun `the release check is exact, not a prefix match`() {
        // `.debug` and `.test` are suffixes of the release id; an exact-match
        // gate must not accept them. This is the regression that would silently
        // re-bind a watch to a non-release phone.
        assertFalse(PairingMatcher.RELEASE_PACKAGE.startsWith(PairingMatcher.DEBUG_PACKAGE))
        assertFalse(PairingMatcher.RELEASE_PACKAGE.startsWith(PairingMatcher.QA_PACKAGE))
        assertFalse(PairingMatcher.isRelease(PairingMatcher.DEBUG_PACKAGE))
        assertFalse(PairingMatcher.isRelease(PairingMatcher.QA_PACKAGE))
    }
}
