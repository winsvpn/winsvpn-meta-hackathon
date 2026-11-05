package org.winsvpn.app

internal object VpnTrafficProof {
    const val MINIMUM_BIDIRECTIONAL_BYTES = 92L

    fun isSatisfied(
        handshakeRecent: Boolean,
        receivedBytes: Long,
        transmittedBytes: Long,
        minimumBytes: Long = MINIMUM_BIDIRECTIONAL_BYTES,
    ): Boolean {
        if (!handshakeRecent || minimumBytes <= 0L) return false
        return receivedBytes >= minimumBytes && transmittedBytes >= minimumBytes
    }
}
