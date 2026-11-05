package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The VPN session name is the string Android renders in
 * Settings > Network & internet > VPN and in its own VPN status surfaces.
 * It used to be hardcoded to "WinsVPN", which announced the real identity on
 * a system screen the calculator disguise otherwise covers.
 *
 * The subtle part is which signal decides it. `VpnService.Builder.setSession`
 * is read by the OS once, at `establish()`, and there is no API to rename a
 * live session -- so the decision has to be made from the sticky "this
 * install uses camouflage" fact rather than from whether the decoy happens to
 * be armed at that instant. The ordinary flow is unlock-with-PIN (decoy
 * disarmed) -> Connect -> background (decoy re-arms), and a momentary-state
 * check would latch the real identity in exactly that flow.
 */
class CamouflageSessionNameTest {

    @Test
    fun `an install with no camouflage keeps the real session name`() {
        assertEquals(
            "WinsVPN",
            VpnTunnelService.vpnSessionNameFor(camouflageEnrolled = false, decoyActive = false),
        )
    }

    @Test
    fun `an enrolled install stays disguised while the decoy is disarmed`() {
        // This is the case the hardcoded name got wrong: the user has
        // unlocked with their PIN and is pressing Connect, so the decoy is
        // momentarily down, but the session name established right now is the
        // one an inspector reads later -- after the decoy has re-armed.
        assertEquals(
            VpnTunnelService.DISGUISED_DISPLAY_NAME,
            VpnTunnelService.vpnSessionNameFor(camouflageEnrolled = true, decoyActive = false),
        )
    }

    @Test
    fun `an armed decoy is disguised even if the enrollment flag never landed`() {
        // Defence in depth: if the SharedPreferences write failed, the live
        // launcher-alias state still forces the disguise.
        assertEquals(
            VpnTunnelService.DISGUISED_DISPLAY_NAME,
            VpnTunnelService.vpnSessionNameFor(camouflageEnrolled = false, decoyActive = true),
        )
    }

    @Test
    fun `no camouflage state ever produces a name carrying the real identity`() {
        for (enrolled in listOf(true, false)) {
            for (armed in listOf(true, false)) {
                val name = VpnTunnelService.vpnSessionNameFor(enrolled, armed)
                if (enrolled || armed) {
                    assertNotEquals(
                        "camouflage active but session name leaks the real identity",
                        "WinsVPN",
                        name,
                    )
                    assertEquals(VpnTunnelService.DISGUISED_DISPLAY_NAME, name)
                }
            }
        }
    }

    @Test
    fun `the disguised name matches the launcher alias label in the manifest`() {
        // AndroidManifest's LauncherDecoy activity-alias uses the literal
        // label "Calculator". If these two ever drift, the VPN entry in
        // Settings and the home-screen icon disagree, which is worse than
        // either name alone.
        assertEquals("Calculator", VpnTunnelService.DISGUISED_DISPLAY_NAME)
    }
}
