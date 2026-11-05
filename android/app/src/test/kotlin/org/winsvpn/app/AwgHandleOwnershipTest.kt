package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression coverage for the ownership check `VpnTunnelService` uses to
 * decide whether a teardown call still owns the AmneziaWG engine handle it
 * is about to turn off.
 *
 * The motivating defect (found on real hardware, motorola edge plus 2023,
 * Android 15, 2026-08-04T10:52Z, devicecheck step
 * `9c-double-teardown-is-a-no-op`): AmneziaWG reissued the SAME integer
 * handle (`0`) to a brand new tunnel immediately after the previous tunnel
 * that also held handle `0` was torn down. A teardown path that identifies
 * "the engine I started" purely by that integer cannot tell the two
 * sessions apart, so a superseded session's late or duplicate release can
 * match -- and shut off -- a completely different, live successor.
 */
class AwgHandleOwnershipTest {

    @Test
    fun normalReleaseStopsEverythingItPublished() {
        val ownership = AwgHandleOwnership()

        val published = ownership.publishIfFreeAnd(7, generation = 1) { true }
        assertTrue("publish should succeed against a free slot", published)
        assertEquals(7, ownership.current())

        val released = ownership.releaseIfOwned(7, generation = 1)
        assertTrue("the session that published the handle must be able to release it", released)
        assertEquals(-1, ownership.current())
    }

    @Test
    fun doubleReleaseOfTheSameSessionIsANoOp() {
        val ownership = AwgHandleOwnership()
        ownership.publishIfFreeAnd(3, generation = 1) { true }

        val first = ownership.releaseIfOwned(3, generation = 1)
        assertTrue("the first release call must succeed", first)
        assertEquals(-1, ownership.current())

        val second = ownership.releaseIfOwned(3, generation = 1)
        assertFalse(
            "a second release of the exact same (handle, generation) must be a no-op, " +
                "not an error and not a double-off",
            second,
        )
        assertEquals(-1, ownership.current())
    }

    /**
     * THE REGRESSION TEST. Reproduces exactly what devicecheck step 9c
     * measured on real hardware: session A publishes handle 0 and tears
     * itself down normally; session B then starts and is (by AmneziaWG's
     * choice, not this class's) handed the SAME raw handle value, 0. A late
     * or duplicate release from A -- using A's own captured (handle,
     * generation), unaware B now exists -- must not be able to touch B.
     *
     * Without the generation check (i.e. comparing only `handle == handle`,
     * which is what `stopAwgEngineIfOwned` did before this fix), the second
     * `releaseIfOwned(0, generationA)` call below would incorrectly return
     * `true` and B's live handle would read back as released. This is
     * confirmed by temporarily reverting [AwgHandleOwnership.releaseIfOwned]
     * to a handle-only comparison and rerunning this test: it fails, with
     * `current()` reading -1 instead of B's handle.
     */
    @Test
    fun supersededSessionsLateReleaseDoesNotStopASuccessorThatReusedTheHandle() {
        val ownership = AwgHandleOwnership()

        // Session A: publishes handle 0 at generation 1, then tears down
        // normally -- exactly like `teardown[first]` in the device harness.
        val generationA = 1
        val publishedA = ownership.publishIfFreeAnd(0, generationA) { true }
        assertTrue(publishedA)
        val firstReleaseOfA = ownership.releaseIfOwned(0, generationA)
        assertTrue("session A's own normal teardown must succeed", firstReleaseOfA)
        assertEquals(-1, ownership.current())

        // Session B starts. AmneziaWG reissues the exact same integer handle
        // A had -- this is the real, observed hazard, not a contrived input.
        val generationB = 2
        val publishedB = ownership.publishIfFreeAnd(0, generationB) { true }
        assertTrue("session B must be able to publish into the now-free slot", publishedB)
        assertEquals(0, ownership.current())

        // A's late/duplicate release arrives after B is already live, using
        // A's own stale (handle, generation) pair. It must be refused.
        val staleReleaseOfA = ownership.releaseIfOwned(0, generationA)
        assertFalse(
            "a superseded session's late release must not match a live successor " +
                "just because the raw handle value is numerically identical",
            staleReleaseOfA,
        )
        assertEquals(
            "session B's handle must remain published and untouched",
            0,
            ownership.current(),
        )

        // B can still release itself normally afterwards.
        val releaseOfB = ownership.releaseIfOwned(0, generationB)
        assertTrue("session B must still be able to release its own handle", releaseOfB)
        assertEquals(-1, ownership.current())
    }

    @Test
    fun publishRefusesWhenTheSlotIsAlreadyOccupied() {
        val ownership = AwgHandleOwnership()
        assertTrue(ownership.publishIfFreeAnd(1, generation = 1) { true })

        val secondPublish = ownership.publishIfFreeAnd(2, generation = 2) { true }
        assertFalse("a second publish must not overwrite a still-live handle", secondPublish)
        assertEquals("the original publish must be unaffected", 1, ownership.current())
    }

    @Test
    fun publishRefusesWhenStillWantedIsFalse() {
        val ownership = AwgHandleOwnership()

        val published = ownership.publishIfFreeAnd(5, generation = 1) { false }
        assertFalse(
            "a publish whose caller reports it is no longer wanted (e.g. the " +
                "tunnel generation moved on mid-start) must be refused",
            published,
        )
        assertEquals(-1, ownership.current())
    }

    @Test
    fun releaseIfOwnedFailsWhenNothingIsPublished() {
        val ownership = AwgHandleOwnership()
        assertFalse(ownership.releaseIfOwned(0, generation = 1))
        assertEquals(-1, ownership.current())
    }

    @Test
    fun releaseIfOwnedFailsOnAGenerationMismatchEvenWithTheRightHandle() {
        val ownership = AwgHandleOwnership()
        ownership.publishIfFreeAnd(9, generation = 1) { true }

        val wrongGeneration = ownership.releaseIfOwned(9, generation = 2)
        assertFalse(wrongGeneration)
        assertEquals("an unmatched release must not touch the live handle", 9, ownership.current())
    }

    @Test
    fun forceReleaseClearsWhateverIsPublishedRegardlessOfGeneration() {
        val ownership = AwgHandleOwnership()
        ownership.publishIfFreeAnd(4, generation = 1) { true }

        val forced = ownership.forceRelease()
        assertEquals("forceRelease must return what it cleared", 4, forced)
        assertEquals(-1, ownership.current())

        val forcedAgainWithNothingLive = ownership.forceRelease()
        assertEquals(-1, forcedAgainWithNothingLive)
    }

    @Test
    fun forceReleaseUnblocksTheSlotForANewPublish() {
        val ownership = AwgHandleOwnership()
        ownership.publishIfFreeAnd(11, generation = 1) { true }
        ownership.forceRelease()

        val publishedAfterForceRelease = ownership.publishIfFreeAnd(12, generation = 2) { true }
        assertTrue(publishedAfterForceRelease)
        assertEquals(12, ownership.current())
    }
}
