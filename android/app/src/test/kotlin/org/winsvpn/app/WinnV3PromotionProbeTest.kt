package org.winsvpn.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The self-starting promotion probe's packet builder.
 *
 * The builder is the one part of [WinnV3PromotionProbe] that can run on a
 * plain JVM, and it is the part most worth pinning: a packet whose checksum
 * is wrong is silently dropped by the responder kernel that is supposed to
 * answer it, and the whole probe then looks like "the gateway never
 * answered" when the real defect was one folded sum. Both checksums are
 * therefore verified here on every synthesized packet, the way
 * winn3/tun's own TestChecksumSelfVerifies does for its packets.
 */
class WinnV3PromotionProbeTest {

    @Test
    fun `the echo request is a minimal valid IPv4 ICMP echo`() {
        val packet = WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "10.10.0.1", 1)
        assertTrue(packet != null)
        assertEquals(WinnV3PromotionProbe.PACKET_BYTES, packet!!.size)
        // version 4, IHL 5, no options.
        assertEquals(0x45, packet[0].toInt() and 0xff)
        // protocol = ICMP, TTL = 64.
        assertEquals(1, packet[9].toInt() and 0xff)
        assertEquals(64, packet[8].toInt() and 0xff)
        // type = echo request, code = 0.
        assertEquals(8, packet[20].toInt() and 0xff)
        assertEquals(0, packet[21].toInt() and 0xff)
        assertArrayEquals(byteArrayOf(10, 10, 0, 2), packet.copyOfRange(12, 16))
        assertArrayEquals(byteArrayOf(10, 10, 0, 1), packet.copyOfRange(16, 20))
        // total length field matches the packet size.
        val total = ((packet[2].toInt() and 0xff) shl 8) or (packet[3].toInt() and 0xff)
        assertEquals(WinnV3PromotionProbe.PACKET_BYTES, total)
    }

    @Test
    fun `both checksums verify on every sequence number`() {
        for (sequence in 1..WinnV3PromotionProbe.MAX_PROBE_ATTEMPTS) {
            val packet = WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "10.10.0.1", sequence)
            assertTrue(packet != null)
            // A correct checksum sums with its field to 0xFFFF; its one's
            // complement is therefore 0.
            assertEquals(
                "IPv4 header checksum failed at sequence $sequence",
                0xFFFF,
                WinnV3PromotionProbe.onesComplementSum(packet!!, 0, 20),
            )
            assertEquals(
                "ICMP checksum failed at sequence $sequence",
                0xFFFF,
                WinnV3PromotionProbe.onesComplementSum(packet, 20, 16),
            )
        }
    }

    @Test
    fun `the sequence number travels in the ICMP sequence field`() {
        for (sequence in 1..WinnV3PromotionProbe.MAX_PROBE_ATTEMPTS) {
            val packet = WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "10.10.0.1", sequence)
            val carried = ((packet!![26].toInt() and 0xff) shl 8) or (packet[27].toInt() and 0xff)
            assertEquals(sequence, carried)
        }
    }

    @Test
    fun `a non-IPv4 literal is refused rather than synthesized`() {
        assertNull(WinnV3PromotionProbe.buildEchoRequest("not-an-address", "10.10.0.1", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "not-an-address", 1))
        // An IPv6 address is a parseable address but not a v4 probe source.
        assertNull(WinnV3PromotionProbe.buildEchoRequest("fd00::1", "10.10.0.1", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "fd00::1", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("", "10.10.0.1", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "", 1))
    }

    @Test
    fun `a name-shaped value is refused, never resolved`() {
        // A resolver would return 127.0.0.1 for this, and the whole point of
        // the strict parser is that no lookup happens on this path at all.
        assertNull(WinnV3PromotionProbe.buildEchoRequest("localhost", "10.10.0.1", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "localhost", 1))
        // Not dotted quads, so they are refused as literals too.
        assertNull(WinnV3PromotionProbe.buildEchoRequest("300.10.0.2", "10.10.0.1", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "10.10.0", 1))
        assertNull(WinnV3PromotionProbe.buildEchoRequest("10.10.0.2", "10.10.0.1.1", 1))
    }
}
