package org.winsvpn.app

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The UNPACED-BURST regression for the Android Winn loopback seam.
 *
 * ## Why this exists
 *
 * The Android seam was recorded as proven by a device run that was PACED. A
 * paced producer never creates the condition this file tests, so that proof
 * could not have caught a burst defect and did not. Correctness and rate are
 * different properties. See
 * `docs/handoff/WINN_SEAM_BURST_BACKPRESSURE_20260805.md`.
 *
 * ## What it drives
 *
 * ```
 *   producer DatagramSocket
 *        -> the REAL WinnAwgLoopbackSeam
 *        -> a pump shaped exactly like WinnTunnelBridge's inbound pump:
 *           readOutgoingDatagram(), then a BLOCKING write
 *        -> a sink that records which sequence numbers came out
 * ```
 *
 * The pump's write stands in for `transport.writeFrame`, which writes into the
 * engine's `LocalSocket` and blocks whenever the engine is slower than the AWG
 * engine is fast. That is the whole mechanism: BEFORE the fix, one thread did
 * both the receive and that blocking write, so while it was blocked nothing
 * drained the socket and the kernel discarded the burst.
 *
 * ## What it asserts, and what it deliberately does not
 *
 * It does NOT assert "nothing is ever lost". A loopback UDP seam whose producer
 * is the app's own AmneziaWG engine cannot be made to block: on loopback UDP a
 * send succeeds even when the receiver's queue is full and the kernel discards
 * at delivery. Asserting zero loss at any rate would only tempt someone to grow
 * the ring until the number went away.
 *
 * It asserts the one thing that holds at ANY offered rate, and that is the
 * property whose absence made this defect invisible:
 *
 *   **every datagram that did not come out the far side is IN A COUNTER.**
 *
 * A datagram the kernel discarded on the receive queue appears in NEITHER the
 * delivered set NOR any counter, so this identity is exactly what catches it.
 * No `/proc` counter is needed and none is available on every host this test
 * runs on, which is why the accounting identity is the ground truth here.
 */
class WinnAwgLoopbackSeamBurstTest {

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

    private companion object {
        /** The real session's average OUTER AmneziaWG datagram size. */
        const val DATAGRAM_BYTES = 1073

        /** The burst of record: 4 MiB of outer AmneziaWG traffic. */
        const val BURST_OF_RECORD = 4195

        const val MAX_DATAGRAM = 1400

        /**
         * How long the stand-in for `transport.writeFrame` blocks. This is the
         * defect's mechanism made explicit and controllable: a real engine
         * stalls for a scheduling quantum at a time, and any nonzero value here
         * reproduces it. 60 microseconds over 4,195 datagrams is ~250 ms of
         * cumulative stall, comfortably longer than the socket buffer can cover.
         */
        const val WRITE_STALL_MICROS = 60L
    }

    /** An AmneziaWG transport-data frame with its sequence in the counter field. */
    private fun datagram(sequence: Int): ByteArray {
        val bytes = ByteArray(DATAGRAM_BYTES)
        bytes[0] = 4 // transport data
        for (i in 0 until 8) {
            bytes[8 + i] = ((sequence.toLong() shr (8 * i)) and 0xff).toByte()
        }
        return bytes
    }

    private fun sequenceOf(bytes: ByteArray): Int {
        var value = 0L
        for (i in 0 until 8) {
            value = value or ((bytes[8 + i].toLong() and 0xff) shl (8 * i))
        }
        return value.toInt()
    }

    /**
     * Shaped exactly like [WinnTunnelBridge]'s inbound pump: read a datagram
     * from the seam, then do a BLOCKING write. Deliberately not the bridge
     * itself, which needs a LocalSocket and therefore a device -- the loop
     * shape is what carries the defect, and it is reproduced here exactly.
     */
    private class Pump(
        private val seam: WinnAwgLoopbackSeam,
        private val onWritten: (ByteArray, Int) -> Unit,
    ) : AutoCloseable {
        private val running = AtomicBoolean(true)
        val delivered = AtomicLong(0)
        private val thread = Thread {
            val buffer = ByteArray(MAX_DATAGRAM)
            while (running.get()) {
                val n = try {
                    seam.readOutgoingDatagram(buffer)
                } catch (_: Exception) {
                    return@Thread
                }
                if (n < 0) return@Thread
                if (n == 0) continue
                // THE BLOCKING WRITE. Before the fix this ran on the same
                // thread as the socket receive.
                val stallUntil = System.nanoTime() + WRITE_STALL_MICROS * 1000
                while (System.nanoTime() < stallUntil) {
                    // busy-wait: microsecond scale, finer than any sleep
                }
                onWritten(buffer, n)
                delivered.incrementAndGet()
            }
        }.apply {
            name = "test-winn-pump"
            isDaemon = true
            start()
        }

        override fun close() {
            running.set(false)
            thread.join(1000)
        }
    }

    private class Result(
        val offered: Int,
        val delivered: Int,
        val accountedDrops: Long,
        val stats: String,
        val elapsedMs: Long,
    ) {
        val lost: Int get() = offered - delivered
        val unaccounted: Long get() = lost - accountedDrops

        override fun toString(): String =
            "offered=$offered delivered=$delivered lost=$lost " +
                "accounted=$accountedDrops UNACCOUNTED=$unaccounted " +
                "elapsed=${elapsedMs}ms rate=${
                    if (elapsedMs > 0) offered * 1000L / elapsedMs else 0
                }/s\n    $stats"
    }

    private fun runBurst(count: Int, paceMicros: Long): Result {
        val seen = BooleanArray(count)
        val seam = WinnAwgLoopbackSeam.open(maxDatagram = MAX_DATAGRAM)
        closeables.add(seam)

        val pump = Pump(seam) { buffer, length ->
            if (length >= 16) {
                val sequence = sequenceOf(buffer)
                if (sequence in 0 until count) seen[sequence] = true
            }
        }
        closeables.add(pump)

        val producer = DatagramSocket()
        closeables.add(AutoCloseable { producer.close() })
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.localPort)

        val started = System.currentTimeMillis()
        val startedNanos = System.nanoTime()
        for (i in 0 until count) {
            if (paceMicros > 0) {
                val due = startedNanos + i * paceMicros * 1000
                while (System.nanoTime() < due) {
                    // busy-wait
                }
            }
            val bytes = datagram(i)
            producer.send(DatagramPacket(bytes, bytes.size, target))
        }
        val elapsed = System.currentTimeMillis() - started

        // Let the chain drain. The point is never to blame the seam for a
        // datagram that was merely still in flight.
        Thread.sleep(3000)

        val stats = seam.seamStatsJson()
        val accounted = field(stats, "seam_rx_ring_dropped") +
            field(stats, "seam_rx_oversize") +
            field(stats, "seam_rx_foreign_sender")
        return Result(count, seen.count { it }, accounted, stats, elapsed)
    }

    private fun field(json: String, key: String): Long {
        val needle = "\"$key\":"
        val at = json.indexOf(needle)
        if (at < 0) return 0
        val rest = json.substring(at + needle.length)
        return rest.takeWhile { it.isDigit() }.toLongOrNull() ?: 0
    }

    // ---- the control ------------------------------------------------------

    /**
     * A failure HERE is a harness fault, not a seam defect, and it invalidates
     * every other number in this file.
     */
    @Test
    fun control_producerAndSinkLoseNothingWithoutTheSeam() {
        val count = BURST_OF_RECORD
        val seen = BooleanArray(count)
        val sink = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        sink.receiveBufferSize = 4 * 1024 * 1024
        sink.soTimeout = 500
        closeables.add(AutoCloseable { sink.close() })
        val done = CountDownLatch(1)
        val receiver = Thread {
            val buffer = ByteArray(2048)
            val packet = DatagramPacket(buffer, buffer.size)
            while (true) {
                packet.setData(buffer, 0, buffer.size)
                try {
                    sink.receive(packet)
                } catch (_: Exception) {
                    break
                }
                if (packet.length >= 16) {
                    val sequence = sequenceOf(buffer)
                    if (sequence in 0 until count) seen[sequence] = true
                }
            }
            done.countDown()
        }.apply { isDaemon = true; start() }

        val producer = DatagramSocket()
        closeables.add(AutoCloseable { producer.close() })
        val target = InetSocketAddress(InetAddress.getByName("127.0.0.1"), sink.localPort)
        for (i in 0 until count) {
            val bytes = datagram(i)
            producer.send(DatagramPacket(bytes, bytes.size, target))
        }
        Thread.sleep(1500)
        sink.close()
        done.await(2, TimeUnit.SECONDS)
        receiver.join(1000)

        assertEquals(
            "CONTROL: the harness's own producer and sink must lose nothing",
            count, seen.count { it },
        )
    }

    // ---- the regression ---------------------------------------------------

    /**
     * THE REGRESSION. Before the fix this fails with hundreds to thousands of
     * datagrams missing from the delivered set AND from every counter, because
     * they were discarded by the kernel while the single pump thread was parked
     * in its blocking write.
     */
    @Test
    fun burstOfRecord_everyLostDatagramIsInACounter() {
        val result = runBurst(BURST_OF_RECORD, paceMicros = 0)
        println("burst of record: $result")

        assertEquals(
            "BURST OF RECORD: every datagram that did not arrive must be in a " +
                "counter — an unaccounted datagram is one the kernel discarded " +
                "where nothing on Android can see it. $result",
            0L, result.unaccounted,
        )
    }

    /**
     * Above carrying capacity, datagrams are still lost -- no finite buffer
     * absorbs an unbounded deficit, and pretending otherwise is how a ring gets
     * grown until a number goes away. They must all still be COUNTED.
     */
    @Test
    fun sustainedOverload_everyLostDatagramIsStillInACounter() {
        val result = runBurst(BURST_OF_RECORD * 3, paceMicros = 0)
        println("sustained overload: $result")

        assertEquals(
            "SUSTAINED OVERLOAD: loss is permitted here, silence is not. $result",
            0L, result.unaccounted,
        )
    }

    /**
     * The shape of the ORIGINAL Android proof: paced, and lossless. It must
     * stay lossless -- the fix must not regress the path that already worked.
     */
    @Test
    fun pacedPath_doesNotRegress() {
        val result = runBurst(2000, paceMicros = 200)
        println("paced: $result")

        assertEquals("PACED PATH: must remain lossless. $result", 0, result.lost)
        assertEquals("PACED PATH: nothing dropped. $result", 0L, result.accountedDrops)
    }

    /**
     * The counters must exist and be readable, because a drop nobody can see is
     * the actual defect this whole change is about.
     */
    @Test
    fun seamExposesItsOwnCounters() {
        val seam = WinnAwgLoopbackSeam.open(maxDatagram = MAX_DATAGRAM)
        closeables.add(seam)
        val stats = seam.seamStatsJson()
        for (key in listOf(
            "seam_rx_datagrams", "seam_rx_ring_dropped", "seam_rx_oversize",
            "seam_rx_foreign_sender", "seam_ring_slots", "seam_ring_high_water",
            "seam_rcvbuf_bytes",
        )) {
            assertTrue("seam stats must expose $key, got: $stats", stats.contains("\"$key\":"))
        }
    }

    /**
     * A lossless session and a lossy session produced byte-for-byte identical
     * output before this existed. That is the property that let a 26-34% loss
     * pass for a successful run, so it is asserted rather than assumed.
     */
    @Test
    fun closeAlwaysReportsExactlyOneSessionLine() {
        val lines = mutableListOf<Pair<Boolean, String>>()
        val seam = WinnAwgLoopbackSeam.open(
            maxDatagram = MAX_DATAGRAM,
            onSessionEnd = { lossy, summary -> lines.add(lossy to summary) },
        )
        seam.close()
        seam.close() // idempotent: must not produce a second line

        assertEquals("exactly one session line per seam, got $lines", 1, lines.size)
        assertTrue(
            "a clean session must say so plainly, got: ${lines[0].second}",
            lines[0].second.startsWith("winn seam closed clean:"),
        )
        assertTrue("a clean session is not lossy", !lines[0].first)
    }
}
