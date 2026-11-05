package org.winsvpn.app

import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.IOException
import java.io.InterruptedIOException
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * The Android tun device behind [WinnV3TunDevice]: one established interface,
 * plus the MTU this host set on it.
 *
 * The MTU is carried rather than queried because `VpnService.Builder` has no
 * getter for it :  see [WinnV3Posture]'s note on the same problem :  and because
 * `tun.New` checks `Device.MTU()` against the tunnel's inner MTU and refuses a
 * device that reports more. A host that reported one number and configured
 * another would have built the black hole §4.2 exists to prevent, so the number
 * that is reported here is the same variable that was passed to `setMtu`.
 *
 * What crosses is an IP packet starting at its version nibble. Android's tun
 * delivers exactly that :  no Darwin 4-byte address-family prefix, no Linux
 * `PACKET_INFO` header :  so nothing here adds framing and nothing strips it.
 */
internal class WinnV3AndroidTunDevice private constructor(
    private val pfd: ParcelFileDescriptor,
    override val mtu: Int,
    nativeBatchWrite: Boolean,
) : WinnV3BurstTunDevice, WinnV3BatchWriteTunDevice {

    companion object {
        private const val POLL_BACKSTOP_MS = 250

        // The callback transfers the service owner before duplicate setup.
        // The production callback only publishes fields and cannot throw.
        // nativeBatchWrite is the runtime switch for the native downlink
        // writer (see WinnV3TunBulkWrite); false keeps the Kotlin path.
        fun establish(
            builder: VpnService.Builder,
            mtu: Int,
            nullMessage: String,
            nativeBatchWrite: Boolean = false,
            retainServiceOwner: (ParcelFileDescriptor) -> Unit,
        ): WinnV3AndroidTunDevice {
            val original = builder.setBlocking(false).establish()
                ?: throw IOException(nullMessage)
            try {
                retainServiceOwner(original)
            } catch (failure: Exception) {
                try { original.close() } catch (_: IOException) { }
                throw failure
            }
            var duplicate: ParcelFileDescriptor? = null
            try {
                val owned = ParcelFileDescriptor.dup(original.fileDescriptor)
                duplicate = owned
                return WinnV3AndroidTunDevice(owned, mtu, nativeBatchWrite)
            } catch (failure: Exception) {
                try { duplicate?.close() } catch (_: IOException) { }
                // The service retains the established interface for teardown.
                throw failure
            }
        }
    }

    private val lifetime = WinnV3IoLifetime(pfd)

    private val fd = pfd.fileDescriptor

    // The native descriptor number for [WinnV3TunBulkRead.readBatch]. The
    // ParcelFileDescriptor keeps ownership; the bulk reader only borrows the
    // number for read(), exactly as [fd] is borrowed for Os.read.
    private val fdNumber: Int = pfd.fd

    // One StructPollfd per direction, allocated once. A burst at a gigabit is
    // roughly 95,000 packets a second; allocating a pollfd array per poll would
    // put that same rate through the allocator for no reason. The read side is
    // touched only by the reader thread and the write side only under the
    // seam's incomingDelivery monitor, so neither is shared.
    private val readPoll = arrayOf(StructPollfd().also {
        it.fd = fd
        it.events = OsConstants.POLLIN.toShort()
    })
    private val writePoll = arrayOf(StructPollfd().also {
        it.fd = fd
        it.events = OsConstants.POLLOUT.toShort()
    })

    // Construction proves public nonblocking establishment before duplication.
    override val supportsBurst: Boolean = true

    /**
     * Blocks until at least one packet is readable, or [timeoutMs] elapses.
     * Returns true when the kernel says there is something to read.
     */
    override fun awaitReadable(timeoutMs: Int): Boolean = poll(readPoll, timeoutMs)

    /**
     * One read that never parks.
     *
     * Returns the packet length, 0 at end of stream, or -1 when the kernel has
     * nothing queued or the drain was interrupted. This retryable boundary
     * lets the reader observe retirement; it
     * must never be conflated with the -1 that [read] returns for end of
     * stream.
     */
    override fun readNonBlocking(buffer: ByteArray): Int {
        while (true) {
            try {
                lifetime.begin()
                try {
                    return Os.read(fd, buffer, 0, buffer.size)
                } finally {
                    lifetime.end()
                }
            } catch (e: ErrnoException) {
                when (e.errno) {
                    // End this drain so retirement can be observed.
                    OsConstants.EINTR -> return -1
                    // EWOULDBLOCK is the same value as EAGAIN on Linux and
                    // android.system.OsConstants does not define it separately.
                    OsConstants.EAGAIN -> return -1
                    else -> throw IOException("Winn tun read failed", e)
                }
            } catch (e: InterruptedIOException) {
                // Os.read reports a signal that arrived after a partial
                // transfer this way. On a tun descriptor a read is one whole
                // packet, so bytesTransferred is either 0 or the packet.
                if (e.bytesTransferred > 0) return e.bytesTransferred
                return -1
            }
        }
    }

    /**
     * The blocking read the fallback reader and the old contract expect:
     * a packet length, or -1 at end of stream.
     */
    override fun read(buffer: ByteArray): Int {
        while (true) {
            val n = readNonBlocking(buffer)
            if (n > 0) return n
            // Os.read returns 0 at end of stream where InputStream returns -1,
            // and the reader loop is written against the InputStream meaning.
            if (n == 0) return -1
            awaitReadable(POLL_BACKSTOP_MS)
        }
    }

    /**
     * One JNI call that drains up to [maxPackets] packets the kernel already
     * holds into the direct [slab] (maxPackets slots of [slotBytes] bytes) and
     * records lengths into the direct [lengths] buffer (little endian Int32s
     * at 4-byte stride, as the native side writes them). Return conventions
     * are documented on [WinnV3TunBulkRead]. -4 maps to IOException here; the
     * oversize and end-of-stream sentinels stay the caller's decision.
     */
    internal fun readBulk(slab: ByteBuffer, lengths: ByteBuffer, maxPackets: Int, slotBytes: Int): Int {
        lifetime.begin()
        try {
            val n = WinnV3TunBulkRead.readBatch(fdNumber, slab, lengths, maxPackets, slotBytes)
            if (n == WinnV3TunBulkRead.READ_FAILED) throw IOException("Winn tun read failed")
            return n
        } finally {
            lifetime.end()
        }
    }

    override fun write(packet: ByteArray, length: Int) {
        write(packet, 0, length)
    }

    /**
     * EAGAIN ON THE WRITE SIDE WAITS FOR POLLOUT; IT DOES NOT DROP.
     *
     * O_NONBLOCK applies to both directions of the same descriptor, so making
     * the read side non-blocking made the write side non-blocking too. A tun
     * write that returns EAGAIN means the interface queue is momentarily full.
     * Treating that as a completed write would be silent inbound packet loss
     * that no counter on either side would ever report, so this waits for the
     * descriptor to be writable and retries.
     */
    override fun write(packet: ByteArray, offset: Int, length: Int) {
        var sent = 0
        while (sent < length) {
            val n = try {
                writeOnce(packet, offset + sent, length - sent)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EINTR -> continue
                    // Same value as EWOULDBLOCK on Linux; OsConstants has only
                    // this name for it.
                    OsConstants.EAGAIN -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            val deadlineNs = System.nanoTime() + 60_000L
                            var spun = false
                            while (System.nanoTime() < deadlineNs) {
                                Thread.onSpinWait()
                                try {
                                    val wn = writeOnce(packet, offset + sent, length - sent)
                                    if (wn > 0) {
                                        sent += wn
                                        spun = true
                                        break
                                    }
                                } catch (se: ErrnoException) {
                                    if (se.errno == OsConstants.EINTR) continue
                                    if (se.errno != OsConstants.EAGAIN) throw IOException("Winn tun write failed", se)
                                }
                            }
                            if (spun) continue
                        }
                        poll(writePoll, POLL_BACKSTOP_MS)
                        continue
                    }
                    else -> throw IOException("Winn tun write failed", e)
                }
            } catch (e: InterruptedIOException) {
                sent += e.bytesTransferred
                continue
            }
            if (n <= 0) throw IOException("Winn tun write made no progress")
            sent += n
        }
    }

    // Native writes need the runtime switch on for this device, the
    // descriptor number the bulk reader already borrows and the writer
    // symbol; any one missing keeps the Kotlin path. Fixed for the device's
    // life, so one connection is one arm of an A/B and the switch is read
    // again at the next establish.
    override val supportsBatchWrite: Boolean =
        nativeBatchWrite && WinnV3TunBulkRead.available && WinnV3TunBulkWrite.available

    // One done flag per packet of the run being written: the native writer
    // marks what went out and skips it on the call after a full device.
    // Touched only by writeBatch, which the seam's incomingDelivery monitor
    // serializes.
    private val writeDone = ByteArray(512)

    /**
     * Writes packets [start, end) of [batch] through the native writer: one
     * lifetime lease and one JNI call per run instead of per packet, in order
     * per flow ([WinnV3TunBulkWrite.LANES] decides whether flows share one
     * thread). The JNI call never waits: a full device (or a signal) ends it
     * with the packets it did write. That is waited out here, outside native
     * code, the way [write] waits it out: on API 33 and later up to 60 us of
     * spinning retries, each one a fresh lease, then POLLOUT under the
     * lifetime lease check in [poll]. The retry skips every packet already
     * written, so nothing is dropped or doubled and a close is never held up
     * by a full device. A device fault throws the same IOException, with the
     * same ErrnoException cause, that a failed Os.write produces.
     */
    override fun writeBatch(batch: WinnV3PacketBatch, start: Int, end: Int) {
        require(start in 0..end && end <= batch.count && end - start <= writeDone.size)
        val count = end - start
        if (count == 0) return
        java.util.Arrays.fill(writeDone, 0, count, 0.toByte())
        WinnV3TunBulkWrite.drive(
            count = count,
            attempt = {
                var done = writeRunOnce(batch, start, end)
                if (done in 0 until count && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val deadlineNs = System.nanoTime() + 60_000L
                    while (done in 0 until count && System.nanoTime() < deadlineNs) {
                        Thread.onSpinWait()
                        done = writeRunOnce(batch, start, end)
                    }
                }
                done
            },
            awaitWritable = { poll(writePoll, POLL_BACKSTOP_MS) },
            fault = { errno -> IOException("Winn tun write failed", ErrnoException("write", errno)) },
        )
    }

    private fun writeRunOnce(batch: WinnV3PacketBatch, start: Int, end: Int): Int {
        lifetime.begin()
        try {
            return WinnV3TunBulkWrite.writeBatch(
                fdNumber, batch.bytes, batch.offsets, batch.lengths, start, end,
                WinnV3TunBulkWrite.LANES, writeDone,
            )
        } finally {
            lifetime.end()
        }
    }

    private fun writeOnce(packet: ByteArray, offset: Int, length: Int): Int {
        lifetime.begin()
        try {
            return Os.write(fd, packet, offset, length)
        } finally {
            lifetime.end()
        }
    }

    private fun poll(fds: Array<StructPollfd>, timeoutMs: Int): Boolean {
        while (true) {
            try {
                lifetime.begin()
                try {
                    return Os.poll(fds, timeoutMs) > 0
                } finally {
                    lifetime.end()
                }
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) return false
                throw IOException("Winn tun poll failed", e)
            }
        }
    }

    override fun close() {
        lifetime.retire()
    }
}

/**
 * A tun device whose reader can drain everything the kernel already holds
 * without parking between packets.
 *
 * The seam checks [supportsBurst] rather than the type, so a descriptor that
 * refused O_NONBLOCK and a plain test double both take the blocking reader and
 * behave exactly as they did before.
 */
internal interface WinnV3BurstTunDevice : WinnV3SliceTunDevice {
    /** False when the descriptor refused O_NONBLOCK; the fallback reader runs. */
    val supportsBurst: Boolean

    /** Parks until readable or the timeout expires. True means data is ready. */
    fun awaitReadable(timeoutMs: Int): Boolean

    /** Length, 0 at end of stream, or -1 for "nothing ready": the terminator. */
    fun readNonBlocking(buffer: ByteArray): Int
}

/**
 * Bounded packet slots between the physical tun and the framed stream pump.
 * Each device has its own reader, so a promotion never waits on an old read.
 * One scratch array per reader feeds a fixed MTU-sized slab, with no packet
 * arrays or queue-node allocation. Kernel reads and writes remain per packet.
 *
 * The state monitor covers generation checks, enqueue, drain and invalidation.
 * Independent delivery monitors serialize each direction with rebind without
 * blocking incoming delivery behind an outgoing socket write. A batch drained
 * before a swap must either finish sending before the swap or be discarded.
 * No monitor is held across the physical read or while waiting for queue data.
 * Close invalidates state and wakes consumers before closing the descriptor.
 */
internal class WinnV3AndroidIpPacketSeam(
    initialDevice: WinnV3TunDevice,
    private val onDropped: (String) -> Unit = {},
    private val onDebug: (String) -> Unit = {},
    private val queueDepth: Int = DEFAULT_QUEUE_DEPTH,
    private val dropLogNow: () -> Long = System::nanoTime,
) : WinnV3BatchedIpPacketSeam {
    companion object {
        const val DEFAULT_QUEUE_DEPTH = 8192

        // Twice WinnV3PacketBatch's 256-packet capacity, so one drain can fill
        // a whole batch and still have the next one started when the pump comes
        // back for it. Bounded rather than unbounded because a drain that never
        // ends is a reader that never notices a rebind or a close: at a gigabit
        // the kernel can hand over packets faster than this thread retires
        // them, and 512 caps the blind window at roughly 5.4 ms of link time.
        const val MAX_BURST_PACKETS = 512

        // The poll backstop for the burst reader. Same role as awaitPacket's
        // 250 ms: it is not how packets arrive, it is how the loop gets back to
        // its close and generation checks on an idle tunnel.
        const val READ_POLL_TIMEOUT_MS = 250

        // At most one drop line per second. Every drop is still counted in
        // droppedCount(); only the logging is rate limited, because a log
        // write per dropped packet on the reader thread is what turns a
        // momentary overflow into a sustained one.
        const val DROP_LOG_INTERVAL_NS = 1_000_000_000L
        private const val NEVER_LOGGED = Long.MIN_VALUE
    }

    private val packetCapacity = WinnV3Bridge.bufferSizeFor(initialDevice.mtu)
    init {
        require(queueDepth in 1..8192)
        require(initialDevice.mtu in 1..WinnFraming.MAX_PAYLOAD_BYTES)
        require(queueDepth.toLong() * packetCapacity <= 32 * 1024 * 1024)
    }
    private val slab = ByteArray(queueDepth * packetCapacity)
    private val lengths = IntArray(queueDepth)
    private var head = 0
    private var count = 0
    private var queueEpoch = 0
    private var waiters = 0
    private var readerFailure: IOException? = null
    private var readerEnded = false
    private val state = Object()
    // Guards the single-consumer invariant of readOutgoingBatch. Phase 2 runs
    // with the monitor released, so a second consumer would claim the same
    // slots and deliver every packet twice.
    private var claimActive = false
    private val delivery = Any()
    private val incomingDelivery = Any()
    private val incomingScratch = ByteArray(packetCapacity)
    private val device = AtomicReference<WinnV3TunDevice?>(initialDevice)
    private val closed = AtomicBoolean(false)
    private val dropped = AtomicLong(0L)
    private val nativeWritePackets = AtomicLong(0L)
    private val lastDropLogNanos = AtomicLong(NEVER_LOGGED)
    private val readerGeneration = AtomicLong(0L)

    init {
        try {
            startReader(initialDevice, readerGeneration.get())
        } catch (failure: Exception) {
            close()
            throw failure
        }
    }

    fun currentDevice(): WinnV3TunDevice? = device.get()
    override fun droppedCount(): Long = dropped.get()

    /** Downlink packets written through the native batch writer. Telemetry only. */
    override fun nativeWritePacketCount(): Long = nativeWritePackets.get()

    // Kernel thread id of the newest tun reader, for the pump census's
    // per-thread CPU time. -1 before the first reader runs or without procfs.
    @Volatile private var readerTid = -1
    fun readerThreadId(): Int = readerTid

    private fun startReader(target: WinnV3TunDevice, generation: Long) {
        Thread {
            if (readerGeneration.get() == generation) {
                readerTid = WinnV3ThreadStat.currentThreadId()
            }
            try {
                android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)
            } catch (_: Exception) {
            }
            // More than the device MTU capacity, so a packet above the configured
            // MTU cannot masquerade as a valid short read into an MTU-sized array.
            val buffer = ByteArray(packetCapacity + 1)
            try {
                val burst = target as? WinnV3BurstTunDevice
                if (burst != null && burst.supportsBurst) {
                    if (burst is WinnV3AndroidTunDevice && WinnV3TunBulkRead.available) {
                        runBurstReaderBulk(burst, generation)
                    } else {
                        runBurstReader(burst, generation, buffer)
                    }
                } else {
                    runBlockingReader(target, generation, buffer)
                }
            } catch (e: Exception) {
                val active = synchronized(state) {
                    if (closed.get() || readerGeneration.get() != generation) false
                    else {
                        readerFailure = if (e is IOException) e else IOException("Winn tun reader failed", e)
                        state.notifyAll()
                        true
                    }
                }
                if (active) onDebug("winn3: tun reader ended: ${e.javaClass.simpleName}")
            }
        }.apply {
            name = "Calc-WinnV3-TunRead-$generation"
            // The reader already asks the kernel for THREAD_PRIORITY_URGENT_AUDIO
            // above. This is the JVM-level counterpart, set for the same reason
            // the two pump threads in WinnV3Bridge now set it: on a
            // heterogeneous SoC a default-priority participant in this handoff
            // can be placed on a little core and preempted on every packet.
            priority = Thread.MAX_PRIORITY
            isDaemon = true
            start()
        }
    }

    /**
     * ONE WAKE CARRIES A WHOLE BURST. THIS IS THE UPLINK FIX.
     *
     * The old reader enqueued one packet and notified, while the batch pump sat
     * in state.wait(250). The pump therefore woke on the FIRST packet of every
     * burst, drained a batch of exactly one, and did one AF_UNIX write carrying
     * one 1325-byte frame. At a 1309-byte inner MTU, 1 Gbps is 95,493 packets a
     * second: 95,493 futex wakes, thread switches and single-frame socket
     * writes, and the wake round trip alone caps the uplink around 233 to 416
     * Mbps. Measured on a Samsung Galaxy S26 Ultra against the Canada gateway,
     * the uplink ran 21.5 to 255 Mbps where the same handset with no VPN did
     * 1652.9 Mbps up.
     *
     * The downlink never had this problem: its producer and consumer are both
     * Go goroutines coupled by a channel and the engine flushes up to 128
     * frames per write, which is why the same handset gets 600 to 711 Mbps down
     * off a 1742.7 Mbps raw path.
     *
     * So: park in poll, then take everything the kernel already has, enqueue
     * each packet under the state monitor with NO notify, and notify exactly
     * once at the end. Latency does not regress, because when only one packet
     * is ready the drain ends on the first EAGAIN and the notify goes out
     * immediately.
     *
     * The state monitor is taken PER PACKET and never held across a read
     * syscall. Holding it across the drain would block readOutgoingBatch,
     * writeOutgoingBatchIfCurrent, rebind and close for the length of a burst.
     */
    private fun runBurstReader(device: WinnV3BurstTunDevice, generation: Long, buffer: ByteArray) {
        val miniBatchSize = 256
        val scratchBuffers = Array(miniBatchSize) { ByteArray(packetCapacity + 1) }
        val scratchLengths = IntArray(miniBatchSize)

        while (!closed.get() && readerGeneration.get() == generation) {
            // False is a timeout, not a failure: fall through to the gate checks.
            if (!device.awaitReadable(READ_POLL_TIMEOUT_MS)) continue
            var drained = 0
            while (drained < MAX_BURST_PACKETS) {
                var batchCount = 0
                var endOfStream = false
                var kernelEmpty = false

                while (batchCount < miniBatchSize && drained + batchCount < MAX_BURST_PACKETS) {
                    val n = device.readNonBlocking(scratchBuffers[batchCount])
                    if (n > 0) {
                        if (n > device.mtu || n > packetCapacity || n > scratchBuffers[batchCount].size) {
                            throw IOException("Winn tun packet exceeds configured MTU")
                        }
                        scratchLengths[batchCount] = n
                        batchCount++
                        continue
                    }
                    if (n == 0) {
                        endOfStream = true
                        break
                    }
                    // n < 0 (EAGAIN): kernel queue momentarily empty. Break immediately
                    // to dispatch the ready packets rather than throwing repeated exceptions.
                    kernelEmpty = true
                    break
                }

                if (batchCount > 0) {
                    var stale = false
                    var overflowCount = 0
                    var enqueuedCount = 0
                    synchronized(state) {
                        if (closed.get() || readerGeneration.get() != generation) {
                            stale = true
                        } else {
                            for (i in 0 until batchCount) {
                                if (!enqueue(scratchBuffers[i], scratchLengths[i], notify = false)) {
                                    overflowCount++
                                } else {
                                    enqueuedCount++
                                }
                            }
                            if (enqueuedCount > 0 && waiters > 0) {
                                state.notifyAll()
                            }
                        }
                    }
                    if (stale) return
                    if (overflowCount > 0) recordDrops("outbound queue full", overflowCount)
                    drained += batchCount
                }

                if (endOfStream) {
                    markReaderEnded(generation)
                    return
                }
                if (kernelEmpty) {
                    break
                }
            }
            if (drained == 0) {
                // A readable poll that drained nothing is a spurious wake.
                // Yielding avoids a 1 ms latency stall on high-bandwidth paths.
                Thread.yield()
            }
        }
    }

    /**
     * The bulk variant of [runBurstReader]: identical semantics, one JNI call
     * per drain instead of one Os.read per packet. Where the Kotlin loop pays
     * a JVM transition and exception machinery per packet at the uplink's
     * ~68,000 packets per second, this pays one transition per burst and a
     * plain memcpy per packet.
     *
     * Invariants carried over unchanged: the state monitor is taken once per
     * drained batch and never across a read syscall; notify stays deferred to
     * one gated wake per batch; oversize and end-of-stream keep their
     * [runBurstReader] meanings via the [WinnV3TunBulkRead] sentinels; a
     * generation swap or close between poll and enqueue discards the batch
     * exactly as before.
     */
    private fun runBurstReaderBulk(device: WinnV3AndroidTunDevice, generation: Long) {
        val miniBatchSize = 256
        val slotBytes = packetCapacity + 1
        val staging = ByteBuffer.allocateDirect(miniBatchSize * slotBytes)
        val stagingLengths = ByteBuffer.allocateDirect(miniBatchSize * 4).order(ByteOrder.nativeOrder())
        val packetLengths = IntArray(miniBatchSize)

        while (!closed.get() && readerGeneration.get() == generation) {
            if (!device.awaitReadable(READ_POLL_TIMEOUT_MS)) continue
            var drained = 0
            while (drained < MAX_BURST_PACKETS) {
                val max = minOf(miniBatchSize, MAX_BURST_PACKETS - drained)
                val n = device.readBulk(staging, stagingLengths, max, slotBytes)
                if (n == WinnV3TunBulkRead.KERNEL_EMPTY) break
                if (n == WinnV3TunBulkRead.END_OF_STREAM) {
                    markReaderEnded(generation)
                    return
                }
                if (n == WinnV3TunBulkRead.OVERSIZE) {
                    throw IOException("Winn tun packet exceeds configured MTU")
                }
                if (n < 0) throw IOException("Winn tun bulk read failed: $n")
                if (n > max || n > packetLengths.size || n > stagingLengths.capacity() / 4 ||
                    n > staging.capacity() / slotBytes) {
                    throw IOException("Winn tun bulk read exceeds configured batch capacity")
                }
                for (i in 0 until n) {
                    val len = stagingLengths.getInt(i * 4)
                    if (len <= 0) throw IOException("Winn tun bulk read returned invalid packet length")
                    if (len > device.mtu || len > packetCapacity) {
                        throw IOException("Winn tun packet exceeds configured MTU")
                    }
                    packetLengths[i] = len
                }

                var stale = false
                var overflowCount = 0
                synchronized(state) {
                    if (closed.get() || readerGeneration.get() != generation) {
                        stale = true
                    } else {
                        val accepted = minOf(n, queueDepth - count)
                        overflowCount = n - accepted
                        for (i in 0 until accepted) {
                            val len = packetLengths[i]
                            val slot = (head + count) % queueDepth
                            staging.position(i * slotBytes)
                            staging.get(slab, slot * packetCapacity, len)
                            lengths[slot] = len
                            count++
                        }
                        if (accepted > 0 && waiters > 0) state.notifyAll()
                    }
                }
                staging.clear()
                if (stale) return
                if (overflowCount > 0) recordDrops("outbound queue full", overflowCount)
                drained += n
            }
            if (drained == 0) {
                // A readable poll that drained nothing is a spurious wake.
                // Yielding avoids a 1 ms latency stall on high-bandwidth paths.
                Thread.yield()
            }
        }
    }

    /**
     * The single notify that ends a burst.
     *
     * Taking the monitor again here is what makes the deferred notify safe.
     * waiters is incremented under this same monitor immediately before
     * Object.wait releases it, so by the time this block holds the monitor the
     * pump is either parked with waiters non-zero, or it is not parked and will
     * see count > 0 the moment it looks. Neither ordering loses the wake.
     */
    private fun notifyPending(generation: Long) {
        synchronized(state) {
            if (readerGeneration.get() != generation) return
            if (count > 0 && waiters > 0) state.notifyAll()
        }
    }

    private fun markReaderEnded(generation: Long) {
        synchronized(state) {
            if (!closed.get() && readerGeneration.get() == generation) {
                readerEnded = true
                state.notifyAll()
            }
        }
    }

    /**
     * The fallback, behaviour-identical to the reader that shipped before the
     * burst drain: one blocking read, one enqueue, one notify.
     *
     * It runs for a descriptor that refused O_NONBLOCK and for test doubles
     * that implement the plain [WinnV3TunDevice] contract. Slower, and correct.
     */
    private fun runBlockingReader(target: WinnV3TunDevice, generation: Long, buffer: ByteArray) {
        while (!closed.get() && readerGeneration.get() == generation) {
            val n = target.read(buffer)
            if (n <= 0) {
                if (n < 0) {
                    markReaderEnded(generation)
                    return
                }
                try {
                    Thread.sleep(10)
                } catch (_: InterruptedException) {
                    return
                }
                continue
            }
            var overflow = false
            var stale = false
            synchronized(state) {
                // This must be AFTER read, including a read that returned
                // after close or rebind deactivated its descriptor.
                if (closed.get() || readerGeneration.get() != generation) {
                    stale = true
                } else {
                    if (n > target.mtu || n > packetCapacity || n > buffer.size) {
                        throw IOException("Winn tun packet exceeds configured MTU")
                    }
                    overflow = !enqueue(buffer, n, notify = true)
                }
            }
            if (stale) return
            if (overflow) recordDrop("outbound queue full")
        }
    }

    /**
     * Called with state held; admission copies only into preallocated storage.
     *
     * THE NOTIFY IS BOTH GATED AND OPTIONAL, AND BOTH ARE THROUGHPUT FIXES.
     *
     * notify = false is what the burst reader passes for every packet in a
     * drain, so one wake carries the whole burst instead of one wake per
     * packet. See runBurstReader for the measured numbers. The injection path
     * and the blocking fallback reader pass true, because neither has a burst
     * boundary to defer to.
     *
     * The waiters gate is the older half of the same fix. An unconditional
     * notifyAll() fires even when nobody is parked, and every one of those
     * wakes drags the batch pump out of its wait to collect a single packet.
     * The pump is built to drain up to 128 packets into one AF_UNIX write;
     * waking it per packet turns every one of those writes into a batch of one
     * and multiplies the syscall count on the engine side by the same factor.
     *
     * waiters is incremented under this very monitor, immediately before
     * Object.wait releases it, so a wake cannot be lost: either the pump holds
     * the monitor and will see count > 0 without waiting at all, or it is
     * parked and waiters is non-zero. When the pump is busy writing the
     * previous batch, waiters is zero and the queue simply accumulates, which
     * is exactly the batching the design asked for.
     */
    private fun enqueue(packet: ByteArray, length: Int, notify: Boolean): Boolean {
        if (count == queueDepth) return false
        val slot = (head + count) % queueDepth
        System.arraycopy(packet, 0, slab, slot * packetCapacity, length)
        lengths[slot] = length
        count++
        if (notify && waiters > 0) state.notifyAll()
        return true
    }

    private fun recordDrop(reason: String) = recordDrops(reason, 1)

    /**
     * Counts every drop, and logs at most one line per [DROP_LOG_INTERVAL_NS].
     * A line that is logged carries the total at that instant; drops after it
     * are counted but not logged until the next line, so when a burst stops
     * the last line can stay behind indefinitely. Read droppedCount() for the
     * final total, never the last log line.
     */
    private fun recordDrops(reason: String, count: Int) {
        val total = dropped.addAndGet(count.toLong())
        val now = dropLogNow()
        val last = lastDropLogNanos.get()
        if (last != NEVER_LOGGED && now - last < DROP_LOG_INTERVAL_NS) return
        if (!lastDropLogNanos.compareAndSet(last, now)) return
        onDropped("$reason; dropped $total so far")
    }

    private fun awaitPacket(): Boolean {
        while (count == 0 && !closed.get()) {
            readerFailure?.let { throw it }
            if (readerEnded) return false
            waiters++
            try {
                // A backstop, not a poll. Every state change that matters
                // (enqueue, reader failure, reader end, rebind, close) notifies
                // under this monitor, so this timeout only bounds a wakeup lost
                // to a bug rather than being the mechanism. The old value was
                // 2 ms, which on an idle tunnel was 500 pointless wakeups a
                // second on a handset's battery.
                state.wait(250)
            } finally {
                waiters--
            }
        }
        if (closed.get()) return false
        readerFailure?.let { throw it }
        return true
    }

    override fun readOutgoingPacket(buffer: ByteArray): Int = synchronized(state) {
        if (!awaitPacket()) return@synchronized -1
        val n = lengths[head]
        if (n > buffer.size) throw IOException("Winn tun destination too small: ${buffer.size} < $n")
        System.arraycopy(slab, head * packetCapacity, buffer, 0, n)
        head = (head + 1) % queueDepth
        count--
        n
    }

    override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int {
        batch.clear()

        val claimHead: Int
        val claimCount: Int
        val claimEpoch: Int
        val claimGeneration: Long
        // Snapshot the ring backing stores under the monitor. rebindDevice may
        // reassign them; a plain field read from the unlocked Phase 2 loop has
        // no ordering guarantee against that assignment and could mix two rings.
        val claimSlab: ByteArray
        val claimLengths: IntArray
        val claimDepth: Int
        val claimStride: Int

        // Phase 1: claim under the monitor without advancing head or count, so
        // the producer's free-slot computation still excludes the claimed range
        // for the entire unlocked window.
        synchronized(state) {
            check(!claimActive) { "Winn tun readOutgoingBatch is single-consumer" }
            if (!awaitPacket()) return -1
            claimGeneration = readerGeneration.get()
            claimEpoch = queueEpoch
            claimHead = head
            claimSlab = slab
            claimLengths = lengths
            claimDepth = queueDepth
            claimStride = packetCapacity
            // Stateful admission. A canAppend loop without accumulation always
            // tests the empty batch and would claim every queued packet
            // regardless of packetCapacity, overflowing Phase 2.
            claimCount = batch.planClaim(claimLengths, claimHead, count, claimDepth)
            if (claimCount == 0) throw IOException("Winn tun batch destination too small")
            claimActive = true
        }

        batch.generation = claimGeneration

        // Phase 2: framing and payload copy with the monitor released.
        // Visibility: the Phase 1 monitor acquire is ordered after the
        // producer's publishing monitor release, and these reads follow that
        // acquire in program order on this thread, so the slab bytes and
        // lengths are visible without any additional fence.
        try {
            for (i in 0 until claimCount) {
                val slot = (claimHead + i) % claimDepth
                batch.append(
                    WinnFraming.OP_INBOUND,
                    claimSlab,
                    slot * claimStride,
                    claimLengths[slot],
                )
            }
        } catch (e: Exception) {
            synchronized(state) {
                claimActive = false
                if (waiters > 0) state.notifyAll()
            }
            batch.clear()
            throw e
        }

        // Phase 3: commit only if the ring was untouched for the whole unlocked
        // window. On mismatch the copied bytes are suspect, so the batch is
        // cleared and nothing is delivered. Gating only the head/count advance
        // would still hand torn or duplicated frames to the caller.
        synchronized(state) {
            claimActive = false
            if (closed.get()) {
                batch.clear()
                if (waiters > 0) state.notifyAll()
                return -1
            }
            if (readerGeneration.get() != claimGeneration || queueEpoch != claimEpoch) {
                batch.clear()
                if (waiters > 0) state.notifyAll()
                return 0
            }
            head = (claimHead + claimCount) % claimDepth
            count -= claimCount
            if (waiters > 0) state.notifyAll()
        }
        return batch.count
    }

    override fun writeOutgoingBatchIfCurrent(batch: WinnV3PacketBatch, write: () -> Unit): Boolean =
        synchronized(delivery) {
            if (closed.get() || batch.generation != readerGeneration.get()) return@synchronized false
            write()
            true
        }

    fun injectOutgoingPacket(packet: ByteArray, length: Int): Boolean {
        require(length in 1..packet.size && length <= packetCapacity)
        val accepted = synchronized(state) {
            if (closed.get()) return false
            if (length > (device.get()?.mtu ?: 0)) return false
            // An injection has no burst around it to defer the wake to.
            enqueue(packet, length, notify = true)
        }
        if (!accepted) recordDrop("outbound queue full while injecting")
        return accepted
    }

    override fun writeIncomingPacket(packet: ByteArray, length: Int) {
        require(length in 1..packet.size)
        synchronized(incomingDelivery) {
            val target = device.get() ?: return
            if (closed.get()) return
            if (length > target.mtu) throw IOException("Winn inbound packet exceeds configured MTU")
            try {
                target.write(packet, length)
            } catch (failure: IOException) {
                if (!closed.get() && device.get() === target) throw failure
            }
        }
    }

    /**
     * Returns how many packets of [start, end) reached the device. Fewer than
     * the range only when a close or a rebind retired the device part way; a
     * native run cut short that way is not counted, so the result never
     * claims a packet the device may not have taken.
     */
    override fun writeIncomingBatch(batch: WinnV3PacketBatch, start: Int, end: Int): Int {
        require(start >= 0 && start <= end && end <= batch.count)
        synchronized(incomingDelivery) {
            val target = device.get() ?: return 0
            if (closed.get()) return 0
            // Reject the whole prefix before a device write if any member is invalid.
            for (i in start until end) {
                if (batch.opcode(i) != WinnFraming.OP_OUTBOUND || batch.length(i) > target.mtu) {
                    throw IOException("Invalid Winn inbound packet batch")
                }
            }
            val batchTarget = target as? WinnV3BatchWriteTunDevice
            if (batchTarget != null && batchTarget.supportsBatchWrite) {
                // Runs, not the whole range, so a rebind or close is noticed
                // between runs just as the loop below notices it between
                // packets.
                var run = start
                while (run < end) {
                    if (closed.get() || device.get() !== target) return run - start
                    val runEnd = minOf(end, run + WinnV3TunBulkWrite.MAX_PACKETS_PER_CALL)
                    try {
                        batchTarget.writeBatch(batch, run, runEnd)
                    } catch (failure: IOException) {
                        if (!closed.get() && device.get() === target) throw failure
                        return run - start
                    }
                    nativeWritePackets.addAndGet((runEnd - run).toLong())
                    run = runEnd
                }
                return end - start
            }
            val sliceTarget = target as? WinnV3SliceTunDevice
            for (i in start until end) {
                if (closed.get() || device.get() !== target) return i - start
                val n = batch.length(i)
                try {
                    if (sliceTarget != null) {
                        sliceTarget.write(batch.bytes, batch.offset(i), n)
                    } else {
                        System.arraycopy(batch.bytes, batch.offset(i), incomingScratch, 0, n)
                        target.write(incomingScratch, n)
                    }
                } catch (failure: IOException) {
                    if (!closed.get() && device.get() === target) throw failure
                    return i - start
                }
            }
            return end - start
        }
    }

    override fun rebindDevice(newDevice: WinnV3TunDevice) {
        var accepted = false
        try {
            synchronized(delivery) {
                val previous = synchronized(state) {
                    if (closed.get()) throw IOException("Winn tun seam is closed")
                    require(newDevice.mtu in 1..packetCapacity)
                    if (device.get() === newDevice) {
                        accepted = true
                        return
                    }
                    // Invalidate old errors before retiring the writer's device.
                    readerGeneration.incrementAndGet()
                    val old = device.getAndSet(null)
                    head = 0
                    count = 0
                    queueEpoch++
                    readerFailure = null
                    readerEnded = false
                    state.notifyAll()
                    old
                }
                // No descriptor close waits for a leased I/O operation.
                // Retire before waiting for incomingDelivery's active writer.
                try {
                    previous?.close()
                } catch (e: Exception) {
                    onDebug("winn3: previous tun device close was incomplete: ${e.javaClass.simpleName}")
                }
                synchronized(incomingDelivery) {
                    synchronized(state) {
                        if (closed.get()) throw IOException("Winn tun seam is closed")
                        device.set(newDevice)
                        try {
                            startReader(newDevice, readerGeneration.get())
                            accepted = true
                        } catch (failure: Exception) {
                            device.set(null)
                            closed.set(true)
                            readerGeneration.incrementAndGet()
                            state.notifyAll()
                            throw failure
                        }
                    }
                }
            }
        } finally {
            if (!accepted) newDevice.close()
        }
    }

    override fun close() {
        val target: WinnV3TunDevice?
        synchronized(state) {
            if (!closed.compareAndSet(false, true)) return
            readerGeneration.incrementAndGet()
            target = device.getAndSet(null)
            head = 0
            count = 0
            queueEpoch++
            state.notifyAll()
        }
        try {
            target?.close()
        } catch (_: Exception) {
        }
    }
}

/**
 * [WinnV3PostureSink] over the real `VpnService.Builder`.
 *
 * The four-line adapter [WinnV3Posture] says the service supplies. It contains
 * no policy: every decision about what a posture may contain is made in
 * [WinnV3Posture] and verified against [WinnV3PostureRecord], which wraps this.
 */
internal class WinnV3BuilderSink(
    private val builder: VpnService.Builder,
) : WinnV3PostureSink {

    override fun addAddress(address: String, prefixLength: Int) {
        builder.addAddress(address, prefixLength)
    }

    override fun addRoute(address: String, prefixLength: Int) {
        builder.addRoute(address, prefixLength)
    }

    /**
     * `Builder.excludeRoute` arrived in API 33 and this app's `minSdk` is 24.
     *
     * THE GUARD IS A VERSION CHECK, NOT A CATCH. `WinnCarrierProfile` shipped
     * an API-26 call under a `catch (Exception)` on this same `minSdk`, and
     * every API 24/25 user crashed on first connect, because the real failure
     * was `NoClassDefFoundError` :  an `Error`, which that clause does not
     * catch. The same trap is here twice over: `excludeRoute` is a missing
     * METHOD (`NoSuchMethodError`) and `IpPrefix`'s public constructor is
     * API 31 (`NoClassDefFoundError`). Both are `Error`s. A version check never
     * reaches either, which is why this is a check and not a wider catch :  the
     * tree has exactly three `Error`-catching clauses and this adds none.
     *
     * Returning false below API 33 is not a weakening. The outer-transport
     * exclusion on Android is carried by `VpnService.protect()` on the carrier
     * socket, which marks the kernel socket so route lookups skip the tunnel's
     * rules entirely :  a stronger guarantee than a route a later, more specific
     * route could shadow. See [WinnV3Posture.OUTER_EXCLUSION_NOTE].
     */
    override fun excludeRoute(address: String, prefixLength: Int): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        return try {
            builder.excludeRoute(IpPrefix(InetAddress.getByName(address), prefixLength))
            true
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: java.net.UnknownHostException) {
            // getByName does not resolve an IP literal, so this means the
            // caller passed something that is not one. Refusing the exclusion
            // rather than the tunnel is correct: protect() still carries it.
            false
        }
    }

    override fun setMtu(mtu: Int) {
        builder.setMtu(mtu)
    }

    override fun addDnsServer(server: String) {
        builder.addDnsServer(server)
    }

    override fun allowFamily(family: Int) {
        // WinnV3Posture keeps its own plain-int constants so it stays free of
        // Android imports; this is the one place they meet OsConstants, and the
        // mapping is asserted by WinnV3AdoptionTest rather than assumed.
        val mapped = when (family) {
            WinnV3Posture.AF_INET -> OsConstants.AF_INET
            WinnV3Posture.AF_INET6 -> OsConstants.AF_INET6
            else -> return
        }
        builder.allowFamily(mapped)
    }
}
