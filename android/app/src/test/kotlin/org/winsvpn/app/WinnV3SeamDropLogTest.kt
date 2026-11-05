package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch

/** Every drop is counted; a burst of drops is one log line, not one per packet. */
class WinnV3SeamDropLogTest {

    private class FloodDevice(private val packets: Int) : WinnV3TunDevice {
        override val mtu: Int = 1359
        private var sent = 0
        private val idle = CountDownLatch(1)
        override fun read(buffer: ByteArray): Int {
            if (sent < packets) {
                buffer[0] = 0x45
                sent++
                return 20
            }
            idle.await()
            return -1
        }
        override fun write(packet: ByteArray, length: Int) = Unit
        override fun close() = idle.countDown()
    }

    @Test
    fun `every drop is counted but a burst of drops logs once`() {
        val lines = mutableListOf<String>()
        val device = FloodDevice(packets = 400)
        val seam = WinnV3AndroidIpPacketSeam(
            device,
            onDropped = { synchronized(lines) { lines += it } },
            queueDepth = 4,
        )
        try {
            val deadline = System.currentTimeMillis() + 5_000
            while (seam.droppedCount() < 396 && System.currentTimeMillis() < deadline) {
                Thread.sleep(5)
            }
            assertEquals("nothing drains, so everything past the depth is dropped and counted",
                396L, seam.droppedCount())
            val logged = synchronized(lines) { lines.toList() }
            assertTrue("a burst inside one interval is one line, not one per packet: $logged",
                logged.size in 1..2)
            assertTrue(logged.first().startsWith("outbound queue full; dropped "))
        } finally {
            seam.close()
        }
    }

    @Test
    fun everyDropIsCountedAcrossTheLogBoundary() {
        val device = object : WinnV3TunDevice {
            override val mtu = 1200
            override fun read(buffer: ByteArray): Int = -1
            override fun write(packet: ByteArray, length: Int) = Unit
            override fun close() = Unit
        }
        var now = 0L
        val lines = mutableListOf<String>()
        val seam = WinnV3AndroidIpPacketSeam(
            device, onDropped = { lines += it }, queueDepth = 4,
            dropLogNow = { now },
        )
        try {
            val packet = byteArrayOf(0x45)
            repeat(4) { assertTrue(seam.injectOutgoingPacket(packet, 1)) }
            repeat(396) { assertFalse(seam.injectOutgoingPacket(packet, 1)) }
            assertEquals(396L, seam.droppedCount())
            assertEquals(1, lines.size)
            now = 999_999_999L
            assertFalse(seam.injectOutgoingPacket(packet, 1))
            assertEquals(397L, seam.droppedCount())
            assertEquals(1, lines.size)
            now = 1_000_000_000L
            assertFalse(seam.injectOutgoingPacket(packet, 1))
            assertEquals(398L, seam.droppedCount())
            assertEquals(2, lines.size)
            assertTrue(lines.last().endsWith("dropped 398 so far"))
        } finally {
            seam.close()
        }
    }
}
