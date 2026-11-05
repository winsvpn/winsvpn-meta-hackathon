package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnRouteParserTest {
    @Test
    fun parsesExactIpv4AllowedRoutesAndIgnoresIpv6() {
        val config = """
            [Interface]
            Address = 10.8.1.3/32

            [Peer]
            AllowedIPs = 0.0.0.0/1, 128.0.0.0/2, ::/0
        """.trimIndent()

        assertEquals(
            listOf(
                VpnIpv4Route("0.0.0.0", 1),
                VpnIpv4Route("128.0.0.0", 2),
            ),
            VpnRouteParser.allowedIpv4Routes(config),
        )
    }

    @Test
    fun rejectsMalformedRoutesInsteadOfExpandingToDefaultRoute() {
        val config = """
            [Peer]
            AllowedIPs = invalid, 10.0.0.999/8, 10.0.0.0/33, ::/0
        """.trimIndent()

        assertEquals(emptyList<VpnIpv4Route>(), VpnRouteParser.allowedIpv4Routes(config))
    }

    @Test
    fun collectsAllPeerRoutesAndIgnoresInlineCommentsAndDuplicates() {
        val config = """
            [Peer]
            AllowedIPs = 10.8.0.0/16 # first peer
            AllowedIPs = 192.0.2.0/24
            [Peer]
            AllowedIPs = 198.51.100.0/24, 10.8.0.0/16, ::/0 # second peer
        """.trimIndent()
        assertEquals(
            listOf(VpnIpv4Route("10.8.0.0", 16), VpnIpv4Route("192.0.2.0", 24),
                VpnIpv4Route("198.51.100.0", 24)),
            VpnRouteParser.allowedIpv4Routes(config),
        )
    }
}
