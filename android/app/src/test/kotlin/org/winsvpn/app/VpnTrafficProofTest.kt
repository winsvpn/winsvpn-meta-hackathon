package org.winsvpn.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnTrafficProofTest {
    @Test
    fun `accepts only a recent handshake with bidirectional payload`() {
        assertTrue(
            VpnTrafficProof.isSatisfied(
                handshakeRecent = true,
                receivedBytes = 512,
                transmittedBytes = 768,
            )
        )
    }

    @Test
    fun `rejects a handshake without returned payload`() {
        assertFalse(
            VpnTrafficProof.isSatisfied(
                handshakeRecent = true,
                receivedBytes = 0,
                transmittedBytes = 4096,
            )
        )
    }

    @Test
    fun `rejects stale and undersized traffic`() {
        assertFalse(
            VpnTrafficProof.isSatisfied(
                handshakeRecent = false,
                receivedBytes = 4096,
                transmittedBytes = 4096,
            )
        )
        assertFalse(
            VpnTrafficProof.isSatisfied(
                handshakeRecent = true,
                receivedBytes = VpnTrafficProof.MINIMUM_BIDIRECTIONAL_BYTES - 1,
                transmittedBytes = VpnTrafficProof.MINIMUM_BIDIRECTIONAL_BYTES,
            )
        )
    }
}
