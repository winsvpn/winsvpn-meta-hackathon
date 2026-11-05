package org.winsvpn.app

import java.io.EOFException
import java.io.FileDescriptor
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/** A reusable, bounded slab of complete legacy WNN3 frames, owned by one pump. */
internal class WinnV3PacketBatch(
    val packetCapacity: Int = 256,
    byteCapacity: Int = 512 * 1024,
) {
    init {
        require(packetCapacity in 1..512)
        require(byteCapacity in WinnFraming.HEADER_BYTES + 1..2 * 1024 * 1024)
    }

    val bytes = ByteArray(byteCapacity)
    // Internal rather than private so a native bulk writer can take the whole
    // table in one call; Kotlin callers keep using offset(i) and length(i).
    internal val offsets = IntArray(packetCapacity)
    internal val lengths = IntArray(packetCapacity)
    private val opcodes = IntArray(packetCapacity)
    var count = 0
        private set
    var byteCount = 0
        private set
    var generation = -1L
        internal set

    fun offset(index: Int): Int { require(index in 0 until count); return offsets[index] }
    fun length(index: Int): Int { require(index in 0 until count); return lengths[index] }
    fun opcode(index: Int): Int { require(index in 0 until count); return opcodes[index] }

    fun clear() {
        count = 0
        byteCount = 0
        generation = -1L
    }

    /** Pure admission predicate against an explicit accumulator state. */
    private fun admits(packets: Int, currentBytes: Int, length: Int): Boolean =
        length >= 0 && packets < packetCapacity &&
            length <= bytes.size - currentBytes - WinnFraming.HEADER_BYTES

    /**
     * Number of leading ring packets, starting at [head], that this batch can
     * accept in order given its current occupancy. Mirrors exactly what
     * [append] consumes, so a claim planned here cannot overflow.
     */
    fun planClaim(lengths: IntArray, head: Int, available: Int, depth: Int): Int {
        var planned = 0
        var packets = count
        var currentBytes = byteCount
        while (planned < available) {
            val length = lengths[(head + planned) % depth]
            if (!admits(packets, currentBytes, length)) break
            currentBytes += WinnFraming.HEADER_BYTES + length
            packets++
            planned++
        }
        return planned
    }

    fun canAppend(length: Int): Boolean = admits(count, byteCount, length)

    fun append(opcode: Int, source: ByteArray, offset: Int, length: Int) {
        require(offset >= 0 && length >= 0 && offset <= source.size - length)
        require(WinnFraming.isKnown(opcode))
        require(length <= WinnFraming.MAX_PAYLOAD_BYTES)
        require(!WinnFraming.mustBeEmpty(opcode) || length == 0)
        require(!WinnFraming.mustBeNonEmpty(opcode) || length > 0)
        require(canAppend(length)) { "Winn batch capacity exceeded" }
        val start = byteCount
        put32(start, WinnFraming.MAGIC)
        put16(start + 4, WinnFraming.FRAMING_VERSION)
        put16(start + 6, opcode)
        put32(start + 8, length)
        put32(start + 12, 0)
        val payload = start + WinnFraming.HEADER_BYTES
        System.arraycopy(source, offset, bytes, payload, length)
        offsets[count] = payload
        lengths[count] = length
        opcodes[count] = opcode
        count++
        byteCount = payload + length
    }

    private fun put16(offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
    }

    private fun put32(offset: Int, value: Int) {
        put16(offset, value)
        put16(offset + 2, value ushr 16)
    }
}

internal interface WinnV3BatchedIpPacketSeam : WinnV3IpPacketSeam {
    /** Blocks only for the first packet, then drains the ready prefix. */
    fun readOutgoingBatch(batch: WinnV3PacketBatch): Int

    /** Serializes the send with rebind so a drained old batch cannot escape later. */
    fun writeOutgoingBatchIfCurrent(batch: WinnV3PacketBatch, write: () -> Unit): Boolean

    /**
     * Delivers the OUTBOUND prefix [start, end) without allocating payload
     * arrays, and returns how many of those packets reached the device.
     */
    fun writeIncomingBatch(batch: WinnV3PacketBatch, start: Int, end: Int): Int

    /** Uplink packets dropped because the seam's queue was full; -1 when not counted. */
    fun droppedCount(): Long = -1L

    /** Downlink packets the native tun writer delivered; -1 when not counted. */
    fun nativeWritePacketCount(): Long = -1L
}

internal interface WinnV3SliceTunDevice : WinnV3TunDevice {
    fun write(packet: ByteArray, offset: Int, length: Int)
}

/**
 * A device that can write a run of a batch's packets in one call.
 *
 * Same contract as calling [WinnV3SliceTunDevice.write] for each packet of
 * [start, end) in order: every packet is written whole, a full device is
 * waited out rather than dropped, and a device fault throws IOException.
 */
internal interface WinnV3BatchWriteTunDevice : WinnV3SliceTunDevice {
    /**
     * False keeps the per-packet path: a host without the native writer, or a
     * device whose runtime switch is off.
     */
    val supportsBatchWrite: Boolean

    /** At most [WinnV3TunBulkWrite.MAX_PACKETS_PER_CALL] packets per call. */
    fun writeBatch(batch: WinnV3PacketBatch, start: Int, end: Int)
}

internal interface WinnV3BatchTransport : WinnEngineTransport {
    fun writeBatch(batch: WinnV3PacketBatch)
    fun readBatch(batch: WinnV3PacketBatch): Int
}

/**
 * Stream adapter for the existing 16-byte WNN3 header, including its 4-byte
 * little-endian payload length. Batching concatenates ordinary frames; it
 * adds no opcode or packet envelope. The callbacks retain platform ownership
 * of descriptor handoff, read timeout and socket shutdown.
 *
 * One reader owns the input slab. All writers, including descriptor handoff,
 * share a lock. A batch is one OutputStream.write plus one flush under that
 * lock. Close never waits for the write lock: closing the platform socket must
 * unblock a writer stalled by bounded kernel backpressure.
 */
internal class WinnV3FramedStreamTransport(
    private val input: InputStream,
    private val output: OutputStream,
    private val descriptorSender: (FileDescriptor) -> Unit,
    private val timeoutSetter: (Int) -> Unit,
    private val socketCloser: () -> Unit,
    private val descriptorGroupSender: ((Array<FileDescriptor>) -> Unit)? = null,
    private val descriptorChannelSender: ((Array<FileDescriptor>) -> Unit)? = null,
) : WinnV3BatchTransport {
    private val writeLock = Any()
    private val singleWrite = WinnV3PacketBatch(1, WinnFraming.MAX_PAYLOAD_BYTES + WinnFraming.HEADER_BYTES)
    private val singleRead = WinnV3PacketBatch(1, WinnFraming.MAX_PAYLOAD_BYTES + WinnFraming.HEADER_BYTES)
    private val pending = ByteArray(2 * 1024 * 1024)
    private var begin = 0
    private var end = 0
    private var readFailure: IOException? = null
    private var writeFailure: IOException? = null
    @Volatile private var closed = false

    override fun writeFrame(opcode: Int, payload: ByteArray) {
        synchronized(writeLock) {
            singleWrite.clear()
            singleWrite.append(opcode, payload, 0, payload.size)
            writeBatch(singleWrite)
        }
    }

    override fun writeBatch(batch: WinnV3PacketBatch) {
        require(batch.count > 0)
        // Validate the whole batch before the first byte is emitted.
        for (i in 0 until batch.count) {
            require(WinnFraming.isHostToEngine(batch.opcode(i))) { "wrong frame direction" }
        }
        synchronized(writeLock) {
            writeFailure?.let { throw it }
            if (closed) throw IOException("Winn frame stream closed")
            try {
                output.write(batch.bytes, 0, batch.byteCount)
                output.flush()
            } catch (e: IOException) {
                // An unknown prefix may have reached the peer. Never retry it.
                writeFailure = e
                throw e
            }
        }
    }

    override fun sendDescriptor(fd: FileDescriptor) {
        synchronized(writeLock) {
            writeFailure?.let { throw it }
            if (closed) throw IOException("Winn frame stream closed")
            try {
                descriptorSender(fd)
            } catch (e: IOException) {
                writeFailure = e
                throw e
            }
        }
    }

    override fun sendDescriptors(fds: Array<FileDescriptor>) {
        if (fds.size == 1) {
            sendDescriptor(fds[0])
            return
        }
        synchronized(writeLock) {
            writeFailure?.let { throw it }
            if (closed) throw IOException("Winn frame stream closed")
            try {
                val send = descriptorGroupSender
                    ?: throw IOException("protected TCP descriptor handoff is unavailable")
                send(fds)
            } catch (e: IOException) {
                writeFailure = e
                throw e
            }
        }
    }

    override fun sendDescriptorChannel(udp: FileDescriptor, channel: FileDescriptor) {
        synchronized(writeLock) {
            writeFailure?.let { throw it }
            if (closed) throw IOException("Winn frame stream closed")
            try {
                val send = descriptorChannelSender
                    ?: throw IOException("protected TCP request channel handoff is unavailable")
                send(arrayOf(udp, channel))
            } catch (e: IOException) {
                writeFailure = e
                throw e
            }
        }
    }

    override fun setReadTimeoutMs(timeoutMs: Int) = timeoutSetter(timeoutMs)

    override fun readFrame(): WinnFrame? {
        if (readBatch(singleRead) < 0) return null
        val offset = singleRead.offset(0)
        return WinnFrame(singleRead.opcode(0), singleRead.bytes.copyOfRange(offset, offset + singleRead.length(0)))
    }

    override fun readBatch(batch: WinnV3PacketBatch): Int {
        batch.clear()
        readFailure?.let { throw it }
        try {
            while (batch.count < batch.packetCapacity) {
                if (closed) throw IOException("Winn frame stream closed")
                if (end - begin >= WinnFraming.HEADER_BYTES) {
                    val opcode = WinnFraming.uint16LE(pending, begin + 6)
                    val length = WinnFraming.uint32LE(pending, begin + 8)
                    if (WinnFraming.uint32LE(pending, begin) != WinnFraming.MAGIC.toLong() ||
                        WinnFraming.uint16LE(pending, begin + 4) != WinnFraming.FRAMING_VERSION ||
                        WinnFraming.uint32LE(pending, begin + 12) != 0L ||
                        !WinnFraming.isEngineToHost(opcode) ||
                        length > WinnFraming.MAX_PAYLOAD_BYTES ||
                        (WinnFraming.mustBeEmpty(opcode) && length != 0L) ||
                        (WinnFraming.mustBeNonEmpty(opcode) && length == 0L)
                    ) throw IOException("Invalid Winn frame header")
                    val n = length.toInt()
                    if (!batch.canAppend(n)) {
                        if (batch.count == 0) throw IOException("Winn batch buffer too small for frame")
                        return batch.count
                    }
                    if (end - begin >= WinnFraming.HEADER_BYTES + n) {
                        batch.append(opcode, pending, begin + WinnFraming.HEADER_BYTES, n)
                        begin += WinnFraming.HEADER_BYTES + n
                        continue
                    }
                }
                // If we already accumulated packets, only return early if no more data is waiting in the socket.
                if (batch.count > 0) {
                    if (input.available() <= 0) {
                        return batch.count
                    }
                }
                if (begin == end) {
                    begin = 0
                    end = 0
                } else if (pending.size - end < 65536) {
                    System.arraycopy(pending, begin, pending, 0, end - begin)
                    end -= begin
                    begin = 0
                }
                val n = input.read(pending, end, pending.size - end)
                if (n < 0) {
                    if (end != 0) throw EOFException("Winn stream ended inside a frame")
                    return -1
                }
                if (n == 0) throw IOException("Winn stream read made no progress")
                end += n
            }
            return batch.count
        } catch (e: IOException) {
            batch.clear()
            readFailure = e
            throw e
        }
    }

    override fun close() {
        closed = true
        socketCloser()
    }
}
