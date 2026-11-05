package org.winsvpn.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * The seam's contract around a batch-writing device: bounded runs in order,
 * the per-packet path kept for a device without the native writer or with its
 * runtime switch off, a rebind noticed between runs, a rebind that retires a
 * device in the middle of a run, the same fault handling as the per-packet
 * loop, and a delivered count that never claims a packet the device did not
 * take. The native writer itself is covered by
 * android/tools/test_winn_tun_write_run.cpp.
 */
class WinnV3BulkTunWriteSeamTest {

    private class RunRecordingDevice(
        override val supportsBatchWrite: Boolean = true,
        private val onRun: (RunRecordingDevice, Int, Int) -> Unit = { _, _, _ -> },
    ) : WinnV3BatchWriteTunDevice {
        override val mtu: Int = 1359
        val runs = mutableListOf<Pair<Int, Int>>()
        val packets = mutableListOf<ByteArray>()
        val singleWrites = AtomicInteger(0)
        var fail: IOException? = null

        override fun writeBatch(batch: WinnV3PacketBatch, start: Int, end: Int) {
            fail?.let { throw it }
            synchronized(runs) { runs += start to end }
            for (i in start until end) {
                packets += batch.bytes.copyOfRange(batch.offset(i), batch.offset(i) + batch.length(i))
            }
            onRun(this, start, end)
        }

        override fun write(packet: ByteArray, offset: Int, length: Int) {
            singleWrites.incrementAndGet()
            packets += packet.copyOfRange(offset, offset + length)
        }

        override fun write(packet: ByteArray, length: Int) = write(packet, 0, length)

        private val idle = CountDownLatch(1)

        override fun read(buffer: ByteArray): Int {
            // Never readable: these tests only exercise the write side.
            idle.await()
            return -1
        }

        override fun close() = idle.countDown()
    }

    private fun outboundBatch(count: Int): WinnV3PacketBatch {
        val batch = WinnV3PacketBatch()
        for (i in 0 until count) {
            val payload = ByteArray(40 + i % 5) { (i + it).toByte() }
            payload[0] = 0x45
            payload[1] = i.toByte()
            batch.append(WinnFraming.OP_OUTBOUND, payload, 0, payload.size)
        }
        return batch
    }

    @Test
    fun `a batch-writing device gets bounded runs in order and no per-packet writes`() {
        val device = RunRecordingDevice()
        val seam = WinnV3AndroidIpPacketSeam(device)
        try {
            val batch = outboundBatch(150)
            assertEquals(150, seam.writeIncomingBatch(batch, 0, 150))
            val chunk = WinnV3TunBulkWrite.MAX_PACKETS_PER_CALL
            assertEquals(if (WinnV3TunBulkWrite.LANES > 1) 128 else 32, chunk)
            val expected = (0 until 150 step chunk).map { it to minOf(150, it + chunk) }
            assertEquals(expected, device.runs)
            assertEquals(0, device.singleWrites.get())
            assertEquals(150L, seam.nativeWritePacketCount())
            assertEquals(150, device.packets.size)
            for (i in 0 until 150) {
                assertEquals("packet $i keeps its place", i.toByte(), device.packets[i][1])
                assertArrayEquals(
                    batch.bytes.copyOfRange(batch.offset(i), batch.offset(i) + batch.length(i)),
                    device.packets[i],
                )
            }
        } finally {
            seam.close()
        }
    }

    @Test
    fun `a device without the native writer keeps the per-packet path`() {
        val device = RunRecordingDevice(supportsBatchWrite = false)
        val seam = WinnV3AndroidIpPacketSeam(device)
        try {
            assertEquals(7, seam.writeIncomingBatch(outboundBatch(10), 2, 9))
            assertTrue(device.runs.isEmpty())
            assertEquals(7, device.singleWrites.get())
            assertEquals(0L, seam.nativeWritePacketCount())
            assertEquals(2.toByte(), device.packets.first()[1])
        } finally {
            seam.close()
        }
    }

    @Test
    fun `a rebind between runs stops the rest of the batch reaching the old device`() {
        lateinit var seam: WinnV3AndroidIpPacketSeam
        val replacement = RunRecordingDevice()
        val rebound = CountDownLatch(1)
        val old = RunRecordingDevice { self, start, _ ->
            if (start == 0) {
                Thread {
                    seam.rebindDevice(replacement)
                    rebound.countDown()
                }.start()
                // The rebind takes the device away before it waits for this
                // writer, so the seam sees the swap at the next run boundary.
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (seam.currentDevice() === self && System.nanoTime() < deadline) {
                    Thread.sleep(1)
                }
            }
        }
        seam = WinnV3AndroidIpPacketSeam(old)
        try {
            val delivered = seam.writeIncomingBatch(outboundBatch(200), 0, 200)
            assertTrue(rebound.await(5, TimeUnit.SECONDS))
            assertEquals("only the first run reached the replaced device",
                listOf(0 to WinnV3TunBulkWrite.MAX_PACKETS_PER_CALL), old.runs)
            assertEquals("the count is what the old device took",
                WinnV3TunBulkWrite.MAX_PACKETS_PER_CALL, delivered)
            assertTrue("the rest of that batch is not replayed onto the new one", replacement.runs.isEmpty())
            assertTrue(seam.currentDevice() === replacement)
        } finally {
            seam.close()
        }
    }

    @Test
    fun `a fault on the live device propagates and a fault after close does not`() {
        val device = RunRecordingDevice()
        device.fail = IOException("device gone")
        val seam = WinnV3AndroidIpPacketSeam(device)
        assertThrows(IOException::class.java) { seam.writeIncomingBatch(outboundBatch(3), 0, 3) }
        seam.close()
        // Closed: the write is a no-op, and in particular does not throw.
        assertEquals(0, seam.writeIncomingBatch(outboundBatch(3), 0, 3))
    }

    @Test
    fun `the run driver waits after a full device and resumes until the run is done`() {
        val results = ArrayDeque(listOf(10, 10, 37, 64))
        var waits = 0
        WinnV3TunBulkWrite.drive(
            count = 64,
            attempt = { results.removeFirst() },
            awaitWritable = { waits++ },
            fault = { errno -> IOException("fault $errno") },
        )
        assertEquals("one wait per call that stopped short", 3, waits)
        assertTrue(results.isEmpty())
    }

    @Test
    fun `the run driver throws a fault, an over-report and a retired wait`() {
        val fault = assertThrows(IOException::class.java) {
            WinnV3TunBulkWrite.drive(8, { -9 }, { }, { errno -> IOException("errno $errno") })
        }
        assertEquals("errno 9", fault.message)
        assertThrows(IOException::class.java) {
            WinnV3TunBulkWrite.drive(8, { 9 }, { }, { errno -> IOException("errno $errno") })
        }
        // On the device the wait is the lifetime-checked poll, which throws
        // once the device is retired: that ends the loop, it is not retried.
        var attempts = 0
        val retired = assertThrows(IOException::class.java) {
            WinnV3TunBulkWrite.drive(
                8, { attempts++; 3 }, { throw IOException("Winn tun device is closed") },
                { errno -> IOException("errno $errno") },
            )
        }
        assertEquals("Winn tun device is closed", retired.message)
        assertEquals(1, attempts)
    }

    // Adopted from the GPT seat's Turn 1 (WinnV3BatchTunDispatchTest), adapted
    // to this interface: a rebind retires the device whose batch write is in
    // progress BEFORE it waits for that writer, so a writer stuck on a full
    // device is released by the retirement, the rebind finishes, and nothing
    // of the old batch reaches the replacement.
    @Test
    fun `a rebind retires an active batch write before waiting for it`() {
        val entered = CountDownLatch(1)
        val retired = CountDownLatch(1)
        val old = object : WinnV3BatchWriteTunDevice {
            override val mtu = 1359
            override val supportsBatchWrite = true
            override fun read(buffer: ByteArray): Int = -1
            override fun write(packet: ByteArray, length: Int) = throw AssertionError("unexpected per-packet write")
            override fun write(packet: ByteArray, offset: Int, length: Int) = throw AssertionError("unexpected per-packet write")
            override fun writeBatch(batch: WinnV3PacketBatch, start: Int, end: Int) {
                entered.countDown()
                // Stands in for the lifetime-checked POLLOUT wait on a full
                // device: it ends only when the device is retired.
                if (!retired.await(3, TimeUnit.SECONDS)) throw AssertionError("writer was not retired")
                throw IOException("Winn tun device is closed")
            }
            override fun close() = retired.countDown()
        }
        val seam = WinnV3AndroidIpPacketSeam(old)
        val replacement = RunRecordingDevice()
        val failure = AtomicReference<Throwable?>()
        val delivered = AtomicInteger(-1)
        val batch = outboundBatch(1)
        val writer = Thread {
            try { delivered.set(seam.writeIncomingBatch(batch, 0, 1)) } catch (e: Throwable) { failure.compareAndSet(null, e) }
        }.apply { isDaemon = true }
        val rebinder = Thread {
            try { seam.rebindDevice(replacement) } catch (e: Throwable) { failure.compareAndSet(null, e) }
        }.apply { isDaemon = true }
        try {
            writer.start()
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            rebinder.start()
            writer.join(2000)
            rebinder.join(2000)
            assertTrue("writer did not stop", !writer.isAlive)
            assertTrue("rebind did not finish", !rebinder.isAlive)
            failure.get()?.let { throw AssertionError("concurrent delivery failed", it) }
            assertEquals("a run cut short by the rebind is not counted", 0, delivered.get())
            assertTrue(replacement.runs.isEmpty())
            assertTrue(seam.currentDevice() === replacement)
            assertEquals(0L, seam.nativeWritePacketCount())
        } finally {
            old.close()
            seam.close()
            writer.join(1000)
            rebinder.join(1000)
        }
    }

    // Adopted from the GPT seat's Turn 1: one invalid member refuses the whole
    // prefix before any device write, on the batch path as on the old loop.
    @Test
    fun `an invalid member refuses the whole run before any write`() {
        val device = RunRecordingDevice()
        val seam = WinnV3AndroidIpPacketSeam(device)
        try {
            val batch = WinnV3PacketBatch()
            batch.append(WinnFraming.OP_OUTBOUND, byteArrayOf(0x45, 1), 0, 2)
            batch.append(WinnFraming.OP_INBOUND, byteArrayOf(0x45, 2), 0, 2)
            assertThrows(IOException::class.java) { seam.writeIncomingBatch(batch, 0, 2) }
            assertTrue(device.runs.isEmpty())
            assertTrue(device.packets.isEmpty())
            assertEquals(0, device.singleWrites.get())
        } finally {
            seam.close()
        }
    }

    // From the implementation lane: the invalid member sits past the first
    // run, so the check must cover the whole range before the first run.
    @Test
    fun `an invalid packet anywhere in the range prevents every write`() {
        val device = RunRecordingDevice()
        val seam = WinnV3AndroidIpPacketSeam(device)
        try {
            val batch = outboundBatch(40)
            batch.append(WinnFraming.OP_INBOUND, byteArrayOf(0x45), 0, 1)
            assertThrows(IOException::class.java) { seam.writeIncomingBatch(batch, 0, 41) }
            assertTrue(device.runs.isEmpty())
            assertTrue(device.packets.isEmpty())
            assertEquals(0L, seam.nativeWritePacketCount())
        } finally {
            seam.close()
        }
    }
}
