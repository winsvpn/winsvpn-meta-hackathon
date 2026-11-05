package org.winsvpn.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `VpnTunnelService` installs an IPv6 fail-closed sink -- a `/128` ULA address
 * plus a `::/0` route -- so that IPv6 cannot leave outside the tunnel.
 *
 * Until 2026-08-07 the failure of that installation was handled by a `catch`
 * that called `logWarning("IPv6 fail-closed route is unavailable.")` and then
 * fell through to `Builder.establish()`. The tunnel came up, the app reported
 * Connected, and every IPv6 packet kept egressing on the physical interface in
 * the clear. The log string named a guarantee the control flow did not provide.
 *
 * The decision is now a named predicate so it is greppable, unit-testable, and
 * cannot be quietly inverted. This suite is the thing that goes red if a future
 * lane restores fail-open.
 *
 * Both halves are load-bearing and this file states why:
 *  - address without route: the interface has an IPv6 identity but nothing
 *    steers IPv6 destinations into it, so they take the physical route.
 *  - route without address: not a configuration Android documents as
 *    blackholing, and the same "route installed, no address assigned" shape is
 *    an open, unresolved question on Windows. An unresolved question is not a
 *    protection, and this population cannot be asked to gamble on one.
 */
class Ipv6FailClosedGateTest {

    @Test
    fun `a fully installed sink is the only state that may establish`() {
        assertTrue(
            VpnTunnelService.mayEstablishTunnel(
                ipv6SinkAddressApplied = true,
                ipv6SinkRouteApplied = true,
            ),
        )
    }

    @Test
    fun `a sink address with no default route may not establish`() {
        // The tunnel would carry IPv4 while IPv6 kept its physical route --
        // the precise shape of the defect this gate exists for.
        assertFalse(
            VpnTunnelService.mayEstablishTunnel(
                ipv6SinkAddressApplied = true,
                ipv6SinkRouteApplied = false,
            ),
        )
    }

    @Test
    fun `a default route with no sink address may not establish`() {
        // Deliberately refused rather than assumed to blackhole. Whether an
        // address-less family route drops or falls back is version and OEM
        // dependent, and "probably drops" is not a guarantee worth a user's
        // attribution.
        assertFalse(
            VpnTunnelService.mayEstablishTunnel(
                ipv6SinkAddressApplied = false,
                ipv6SinkRouteApplied = true,
            ),
        )
    }

    @Test
    fun `a sink the platform rejected outright may not establish`() {
        assertFalse(
            VpnTunnelService.mayEstablishTunnel(
                ipv6SinkAddressApplied = false,
                ipv6SinkRouteApplied = false,
            ),
        )
    }

    @Test
    fun `exactly one of the four sink states is permitted to establish`() {
        // Stated as a whole-truth-table count so that widening the gate has to
        // be an edit someone makes on purpose. Erring toward refusal is the
        // fail-safe direction here: the cost of a false refusal is a user who
        // must retry or switch networks, and the cost of a false acceptance is
        // a user who believes they are protected while they are not.
        var permitted = 0
        for (address in listOf(true, false)) {
            for (route in listOf(true, false)) {
                if (VpnTunnelService.mayEstablishTunnel(address, route)) permitted++
            }
        }
        org.junit.Assert.assertEquals(1, permitted)
    }
}
