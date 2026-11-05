package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The observable truth table of `KillSwitchPolicy`.
 *
 * The policy decides, from LIVE OS state, whether the machine is guaranteed
 * blocked while OUR tunnel is down. Every branch in here is scored for BOTH
 * polarities, because the survivor this codebase keeps shipping is a test that
 * asserts a positive fact with nothing asserting the negative — `is_executable`
 * replaced by constant `true` once passed an entire suite. Here, each rule has
 * an explicit "must be false" neighbour, and the always-on/other-app state is
 * pinned to the fail-closed direction because that is the one that most reads
 * like a false green.
 */
class KillSwitchPolicyTest {

    private val ourPackage = "org.winsvpn.app"
    private val otherPackage = "com.someone.else"

    // ---- blockConnectionsState: the full classification table --------------

    @Test
    fun `below the always-on floor everything is unavailable`() {
        for (level in listOf(19, 21, 23)) {
            assertEquals(
                KillSwitchPolicy.BlockConnectionsState.UNAVAILABLE,
                KillSwitchPolicy.blockConnectionsState(
                    apiLevel = level,
                    alwaysOnPackage = null,
                    lockdownEnabled = true,
                    ourPackage = ourPackage,
                ),
            )
            assertEquals(
                KillSwitchPolicy.BlockConnectionsState.UNAVAILABLE,
                KillSwitchPolicy.blockConnectionsState(
                    apiLevel = level,
                    alwaysOnPackage = ourPackage,
                    lockdownEnabled = false,
                    ourPackage = ourPackage,
                ),
            )
        }
    }

    @Test
    fun `lockdown off is never active whatever the always-on package`() {
        for (alwaysOn in listOf(ourPackage, otherPackage, null)) {
            assertEquals(
                KillSwitchPolicy.BlockConnectionsState.NOT_ARMED,
                KillSwitchPolicy.blockConnectionsState(
                    apiLevel = 35,
                    alwaysOnPackage = alwaysOn,
                    lockdownEnabled = false,
                    ourPackage = ourPackage,
                ),
            )
        }
    }

    @Test
    fun `our package plus lockdown is active, and only that combination`() {
        assertEquals(
            KillSwitchPolicy.BlockConnectionsState.OUR_APP_ACTIVE,
            KillSwitchPolicy.blockConnectionsState(
                apiLevel = 35,
                alwaysOnPackage = ourPackage,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
    }

    @Test
    fun `another app as always-on with lockdown is not our guarantee`() {
        assertEquals(
            KillSwitchPolicy.BlockConnectionsState.LOCKDOWN_OTHER_APP,
            KillSwitchPolicy.blockConnectionsState(
                apiLevel = 35,
                alwaysOnPackage = otherPackage,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
    }

    @Test
    fun `lockdown on with no always-on package at all reports not armed`() {
        assertEquals(
            KillSwitchPolicy.BlockConnectionsState.NOT_ARMED,
            KillSwitchPolicy.blockConnectionsState(
                apiLevel = 35,
                alwaysOnPackage = null,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
    }

    // ---- osGuaranteesBlockedWhileDown: the one load-bearing boolean ---------

    @Test
    fun `only our active always-on lockdown guarantees the block`() {
        val guaranteed = KillSwitchPolicy.osGuaranteesBlockedWhileDown(
            apiLevel = 35,
            alwaysOnPackage = ourPackage,
            lockdownEnabled = true,
            ourPackage = ourPackage,
        )
        assertTrue("our app always-on with lockdown must be the guarantee", guaranteed)
    }

    @Test
    fun `every other state must not be claimed as a guarantee`() {
        val cases = listOf(
            // Other app always-on, lockdown on: blocks only while THAT app's
            // tunnel is down — no guarantee for ours. THE classic false green.
            Pair(otherPackage, true),
            // Lockdown off, whatever the package.
            Pair(ourPackage, false),
            Pair(otherPackage, false),
            Pair(null, false),
            // Lockdown on but no always-on package.
            Pair(null, true),
        )
        for ((alwaysOn, lockdown) in cases) {
            assertFalse(
                "alwaysOn=$alwaysOn lockdown=$lockdown must NOT be claimed as a " +
                    "guarantee for our tunnel-down window",
                KillSwitchPolicy.osGuaranteesBlockedWhileDown(
                    apiLevel = 35,
                    alwaysOnPackage = alwaysOn,
                    lockdownEnabled = lockdown,
                    ourPackage = ourPackage,
                ),
            )
        }
    }

    @Test
    fun `below the floor there is no OS guarantee either`() {
        assertFalse(
            KillSwitchPolicy.osGuaranteesBlockedWhileDown(
                apiLevel = 23,
                alwaysOnPackage = ourPackage,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
    }

    // ---- mustHoldBlockingInterface: what the teardown must do ---------------

    @Test
    fun `a disarmed kill switch never holds a blocking interface`() {
        // Even with the OS fully guaranteeing the block, the user chose a plain
        // tunnel, so hold nothing — normal teardown semantics.
        assertFalse(
            KillSwitchPolicy.mustHoldBlockingInterface(
                killSwitchArmed = false,
                apiLevel = 35,
                alwaysOnPackage = ourPackage,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
        assertFalse(
            KillSwitchPolicy.mustHoldBlockingInterface(
                killSwitchArmed = false,
                apiLevel = 35,
                alwaysOnPackage = otherPackage,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
    }

    @Test
    fun `an armed kill switch holds a blocking interface unless the OS is ours`() {
        assertFalse(
            "with OUR always-on lockdown, the OS blocks; the app holds nothing",
            KillSwitchPolicy.mustHoldBlockingInterface(
                killSwitchArmed = true,
                apiLevel = 35,
                alwaysOnPackage = ourPackage,
                lockdownEnabled = true,
                ourPackage = ourPackage,
            ),
        )
    }

    @Test
    fun `an armed kill switch holds a blocking interface when the OS is not ours`() {
        val holdCases = listOf(
            // The two too-close states that read as guarantees and are not:
            Triple(otherPackage, true, 35),   // another app's lockdown
            Triple(null, true, 35),            // lockdown on, nothing armed to it
            Triple(ourPackage, false, 35),     // our app always-on but lockdown off
            Triple(null, false, 35),           // nothing at all
            Triple(ourPackage, true, 23),      // below the floor: nothing the OS can do
        )
        for ((alwaysOn, lockdown, apiLevel) in holdCases) {
            assertTrue(
                "armed kill switch with alwaysOn=$alwaysOn lockdown=$lockdown at " +
                    "api=$apiLevel must hold a blocking interface",
                KillSwitchPolicy.mustHoldBlockingInterface(
                    killSwitchArmed = true,
                    apiLevel = apiLevel,
                    alwaysOnPackage = alwaysOn,
                    lockdownEnabled = lockdown,
                    ourPackage = ourPackage,
                ),
            )
        }
    }

    @Test
    fun `an unreadable always-on read fails closed to holding`() {
        // The readers in AndroidKillSwitch return null for a failed hidden-API
        // read; that null must route to holding, not to a claimed guarantee.
        assertTrue(
            KillSwitchPolicy.mustHoldBlockingInterface(
                killSwitchArmed = true,
                apiLevel = 35,
                alwaysOnPackage = null,
                lockdownEnabled = false,
                ourPackage = ourPackage,
            ),
        )
    }
}