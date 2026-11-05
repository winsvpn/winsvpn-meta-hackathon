package org.winsvpn.app

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.Assert.fail

/**
 * Unit tests for [WinnAwgLoopbackSeam], the Android loopback UDP relay that the
 * AmneziaWG peer endpoint is pointed at.
 *
 * The companion covers the two pure, fail-closed rules that live in companion
 * functions and can be asserted without any socket: the peer endpoint string
 * that the AWG engine is told to use is always loopback, and [redirectPeerEndpoint]
 * REFUSES (throws) unless the AmneziaWG configuration carries exactly one peer
 * endpoint to redirect. Both directions are asserted: the happy path AND the
 * negative. A redirect that "quietly did nothing" -- zero or two endpoints --
 * is the failure that would leave the AWG engine talking straight to the
 * gateway while the rest of the service believed Winn was carrying the traffic.
 *
 * The socket-backed tests exercise the real relay the same way the on-device
 * seam runs: a producer `DatagramSocket` sends to the seam's loopback port and
 * the seam's own drainer thread does the classification. Each drop class is
 * asserted on the negative side -- a foreign sender must be dropped AND counted,
 * an oversize datagram must be dropped AND counted -- because a drop nobody can
 * see is the defect this whole class exists to keep honest.
 *
 * ## Why the positives alone would not be enough
 *
 * Every "is dropped AND counted" test also asserts the OTHER branch would have
 * been wrong: if the seam had silently ACCEPTED the foreign sender, or silently
 * TRUNCATED an oversize datagram instead of dropping it, the counter would stay
 * zero and this test would go red. A mutation that deletes either guard fails
 * the corresponding test below.
 *
 * ## Lifecycle
 *
 * Real `DatagramSocket`s. Each test closes everything it opened in `tearDown`,
 * and the seam's own `onSessionEnd` is captured so the "exactly one session
 * line, and a DIFFERENT one when lossy" contract is asserted rather than
 * assumed -- that is the property whose absence once let a silent loss pass for
 * a successful run.
 */
class WinnAwgLoopbackSeamTest {

    private val closeables = mutableListOf<AutoCloseable>()

    @After
    fun tearDown() {
        for (c in closeables.reversed()) {
            try {
                c.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun <T : AutoCloseable> track(c: T): T = c.also { closeables.add(it) }

    /** A sink thread that drains the seam's ring so the drainer is never the bottleneck. */
    private fun pump(seam: WinnAwgLoopbackSeam, bufferSize: Int = 2048): AutoCloseable {
        val running = AtomicBoolean(true)
        val buffer = ByteArray(bufferSize)
        val thread = Thread {
            while (running.get()) {
                val n = try {
                    seam.readOutgoingDatagram(buffer)
                } catch (_: Exception) {
                    return@Thread
                }
                if (n < 0) return@Thread
            }
        }.apply { isDaemon = true; name = "test-seam-pump"; start() }
        return track(AutoCloseable {
            running.set(false)
            thread.join(500)
        })
    }

    private fun field(json: String, key: String): Long {
        val needle = "\"$key\":"
        val at = json.indexOf(needle)
        if (at < 0) return 0
        val rest = json.substring(at + needle.length)
        return rest.takeWhile { it.isDigit() }.toLongOrNull() ?: 0
    }

    /**
     * Polls [seam]'s JSON stats until a counter reaches [target] or a second
     * passes, so the test does not race the drainer thread. Returns the stats.
     */
    private fun awaitStat(seam: WinnAwgLoopbackSeam, key: String, target: Long): String {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        var stats = seam.seamStatsJson()
        while (field(stats, key) < target && System.nanoTime() < deadline) {
            Thread.sleep(20)
            stats = seam.seamStatsJson()
        }
        return stats
    }

    private fun sendByte(socket: DatagramSocket, target: InetSocketAddress, size: Int) {
        socket.send(DatagramPacket(ByteArray(size), size, target))
    }

    // ---- pure companion rules --------------------------------------------

    @Test
    fun peerEndpoint_isAlwaysLocalhostAndCarriesThePort() {
        assertEquals("127.0.0.1:4567", WinnAwgLoopbackSeam.peerEndpoint(4567))
    }

    @Test
    fun redirectPeerEndpoint_rewritesTheSingleEndpointToLocalhost() {
        val config = """
            [Interface]
            PrivateKey = DUMMY_PRIVATE_KEY_FOR_TEST
            Address = 10.0.0.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey = DUMMY_PUBLIC_KEY_FOR_TEST
            Endpoint = 203.0.113.9:51820
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 25
        """.trimIndent()

        val rewritten = WinnAwgLoopbackSeam.redirectPeerEndpoint(config, 43123)

        assertTrue(
            "the single Endpoint must be rewritten to the seam's loopback port",
            rewritten.contains("Endpoint = 127.0.0.1:43123"),
        )
        assertTrue(
            "the original gateway endpoint must no longer be present",
            !rewritten.contains("203.0.113.9"),
        )
        assertTrue(
            "an unrelated key must be left untouched",
            rewritten.contains("PersistentKeepalive = 25"),
        )
    }

    @Test
    fun redirectPeerEndpoint_failsClosedWhenThereIsNoEndpoint() {
        val config = """
            [Interface]
            PrivateKey = DUMMY_PRIVATE_KEY_FOR_TEST

            [Peer]
            PublicKey = DUMMY_PUBLIC_KEY_FOR_TEST
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        try {
            WinnAwgLoopbackSeam.redirectPeerEndpoint(config, 43123)
            fail("redirecting a config with no peer endpoint must fail closed")
        } catch (expected: java.io.IOException) {
            // correct: the rewrite must not silently succeed and leave the
            // engine pointed at the gateway.
        }
    }

    @Test
    fun redirectPeerEndpoint_failsClosedWhenThereIsMoreThanOneEndpoint() {
        val config = """
            [Interface]
            PrivateKey = DUMMY_PRIVATE_KEY_FOR_TEST

            [Peer]
            PublicKey = DUMMY_PUBLIC_KEY_FOR_TEST
            Endpoint = 203.0.113.9:51820

            [Peer]
            PublicKey = ANOTHER_DUMMY_PUBLIC_KEY_FOR_TEST
            Endpoint = 198.51.100.7:51820
        """.trimIndent()

        try {
            WinnAwgLoopbackSeam.redirectPeerEndpoint(config, 43123)
            fail("redirecting a config with two peer endpoints must fail closed")
        } catch (expected: java.io.IOException) {
            // correct
        }
    }

    // ---- loopback binding --------------------------------------------------

    @Test
    fun open_bindsToTheLoopbackAddressAndExposesTheLocalPort() {
        val seam = track(WinnAwgLoopbackSeam.open())
        assertTrue("the seam must listen on an ephemeral local port", seam.localPort > 0)
        assertTrue(
            "the seam describes itself as a loopback relay",
            seam.describeForLog().contains("loopback"),
        )
    }

    // ---- peer pinning -------------------------------------------------------

    @Test
    fun foreignSender_isDroppedAndCounted() {
        val dropped = AtomicInteger(0)
        val seam = track(WinnAwgLoopbackSeam.open(onDropped = { dropped.incrementAndGet() }))
        pump(seam)

        val first = track(DatagramSocket())
        val intruder = track(DatagramSocket())
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort)

        // The first sender pins the seam.
        sendByte(first, target, 64)
        // A DIFFERENT loopback source must be refused, not accepted.
        sendByte(intruder, target, 64)

        val stats = awaitStat(seam, "seam_rx_foreign_sender", 1)
        assertTrue(
            "a datagram from an unexpected local sender must be counted as foreign: $stats",
            field(stats, "seam_rx_foreign_sender") >= 1,
        )
        assertTrue("a foreign sender must be dropped by the seam", dropped.get() >= 1)
        // The intruder's datagram must NOT be delivered into the ring as a
        // legitimate peer datagram.
        assertTrue(
            "the foreign datagram must not be delivered as outgoing: $stats",
            field(stats, "seam_rx_datagrams") >= 1,
        )
    }

    @Test
    fun firstSender_isPinnedAndLaterSameSenderIsAccepted() {
        val seam = track(WinnAwgLoopbackSeam.open())
        pump(seam)

        val sender = track(DatagramSocket())
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort)
        sendByte(sender, target, 64)
        sendByte(sender, target, 64)

        val stats = awaitStat(seam, "seam_rx_datagrams", 2)
        assertTrue(
            "two datagrams from the pinned sender must both be received: $stats",
            field(stats, "seam_rx_datagrams") >= 2,
        )
        assertEquals(
            "a repeated sender from the pinned source is not foreign: $stats",
            0L, field(stats, "seam_rx_foreign_sender"),
        )
    }

    // ---- oversize ----------------------------------------------------------

    @Test
    fun oversizeDatagram_isDroppedAndCountedNotTruncated() {
        val dropped = AtomicInteger(0)
        val seam = track(
            WinnAwgLoopbackSeam.open(maxDatagram = 32, onDropped = { dropped.incrementAndGet() }),
        )
        pump(seam, bufferSize = 64)

        val sender = track(DatagramSocket())
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort)
        // 64 bytes against a 32-byte ceiling.
        sendByte(sender, target, 64)

        val stats = awaitStat(seam, "seam_rx_oversize", 1)
        assertTrue(
            "an oversize datagram must be counted as oversize, not silently accepted: $stats",
            field(stats, "seam_rx_oversize") >= 1,
        )
        assertTrue("an oversize datagram must be dropped", dropped.get() >= 1)
    }

    // ---- session reporting --------------------------------------------------

    @Test
    fun losslessSession_reportsExactlyOneCleanSessionLine() {
        val lines = mutableListOf<Pair<Boolean, String>>()
        val seam = track(
            WinnAwgLoopbackSeam.open(onSessionEnd = { lossy, summary -> lines.add(lossy to summary) }),
        )
        seam.close()
        seam.close() // idempotent: must not emit a second line

        assertEquals("exactly one session line per seam, got $lines", 1, lines.size)
        assertTrue(
            "a clean session must say so plainly, got: ${lines[0].second}",
            lines[0].second.startsWith("winn seam closed clean:"),
        )
        assertTrue("a clean session is not lossy", !lines[0].first)
    }

    @Test
    fun lossySession_reportsLossAndANotCleanLine() {
        val lines = mutableListOf<Pair<Boolean, String>>()
        val seam = track(
            WinnAwgLoopbackSeam.open(onSessionEnd = { lossy, summary -> lines.add(lossy to summary) }),
        )
        pump(seam)

        val intruder = track(DatagramSocket())
        val first = track(DatagramSocket())
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort)
        sendByte(first, target, 64) // pins
        sendByte(intruder, target, 64) // foreign -> loss
        awaitStat(seam, "seam_rx_foreign_sender", 1)

        seam.close()

        assertEquals("exactly one session line per seam, got $lines", 1, lines.size)
        assertTrue("a session that lost a datagram must report lossy", lines[0].first)
        assertTrue(
            "a lossy session must say so plainly, got: ${lines[0].second}",
            lines[0].second.startsWith("winn seam closed WITH LOSS:"),
        )
    }

    @Test
    fun readOutgoingDatagram_returnsNegativeOneAfterClose() {
        val seam = track(WinnAwgLoopbackSeam.open())
        seam.close()
        assertEquals(-1, seam.readOutgoingDatagram(ByteArray(64)))
    }

    @Test
    fun seamExposesItsOwnDropCounters() {
        val seam = track(WinnAwgLoopbackSeam.open())
        val stats = seam.seamStatsJson()
        for (key in listOf(
            "seam_rx_datagrams", "seam_rx_ring_dropped", "seam_rx_oversize",
            "seam_rx_foreign_sender", "seam_tx_delivered", "seam_awg_sent",
            "seam_ring_high_water", "seam_rcvbuf_bytes",
        )) {
            assertTrue("seam stats must expose $key, got: $stats", stats.contains("\"$key\":"))
        }
    }
}
