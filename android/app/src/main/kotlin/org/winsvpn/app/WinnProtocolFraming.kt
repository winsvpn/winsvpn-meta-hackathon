package org.winsvpn.app

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Winn Protocol host <-> engine framing: the WNN3 wire format.
 *
 * NORMATIVE, AND NOT THIS FILE'S TO CHOOSE. The byte layout below is fixed by
 * WINN_PROTOCOL_PLATFORM_PLAN.md section 2 and its reference implementation,
 * `windows/runner/winn_frame.h`. The Go side of the same header is
 * `winn_protocol_experimental/datapath/duplex`. Where any two of the three
 * disagree, the C++ header is right and the other two are the bug.
 *
 * HISTORY, because it is the whole reason this file looks like this. Section 2
 * originally fixed the five-call API surface and the per-platform transport but
 * NOT the byte layout, so the `android` and `windows` lanes each invented one.
 * Android's was `type:u8 + len:u24` big-endian with types 0x01..0x08. The
 * arbitration of 2026-08-03 made the Windows layout normative for every
 * subprocess host. This file is that convergence, performed in code. Until it
 * landed, the plan claimed a convergence that did not exist and the packaged
 * engine and this host could not exchange a single frame.
 *
 * Wire format -- every message is one frame, every field little-endian:
 *
 *     offset  size  field
 *     0       4     magic     u32 LE = 0x334E4E57  ("WNN3")
 *     4       2     version   u16 LE = 1
 *     6       2     opcode    u16 LE
 *     8       4     length    u32 LE, payload byte count
 *     12      4     reserved  u32 LE, must be zero
 *     16      len   payload
 *
 * Message table (H = host/Kotlin, E = engine/Go subprocess):
 *
 * | opcode | name           | dir  | payload                                  |
 * |--------|----------------|------|------------------------------------------|
 * | 0x0001 | Create         | H->E | datapath configuration JSON (UTF-8)      |
 * | 0x0002 | CreateAck      | E->H | initial status JSON                      |
 * | 0x0010 | Inbound        | H->E | exactly one datagram, host -> protocol   |
 * | 0x0011 | Outbound       | E->H | exactly one datagram, protocol -> host   |
 * | 0x0020 | StatusRequest  | H->E | empty                                    |
 * | 0x0021 | StatusResponse | E->H | status JSON                              |
 * | 0x0030 | Close          | H->E | empty                                    |
 * | 0x0031 | CloseAck       | E->H | empty, then the stream ends              |
 * | 0x00F0 | Error          | E->H | UTF-8 error text, at any time            |
 *
 * The old vocabulary maps on as the arbitration directed: `HELLO`/`READY` are
 * [OP_CREATE]/[OP_CREATE_ACK], and `SHUTDOWN` is [OP_CLOSE]. `CloseAck` carries
 * no payload, so a host that wants final counters must send `StatusRequest`
 * BEFORE `Close`; there is no status in the acknowledgement to read them from.
 *
 * WHAT THE PACKET PAYLOADS ARE. In legacy wrapper mode (without -winn3),
 * `Inbound` and `Outbound` carry **AmneziaWG outer datagrams** (the bytes the
 * host's own AWG engine would otherwise have sent to and received from the
 * gateway's UDP endpoint). In standalone mode (with -winn3), they carry raw
 * inner IP packets (`payload:"ip-packet"`) and no AmneziaWG is involved at all.
 * See [WinnV3Host] and [WinnAwgDatagramSeam].
 *
 * NO RESYNCHRONISATION. A frame whose magic, version, reserved field, opcode,
 * direction or length is wrong tears the channel down. It is never skipped and
 * the stream is never scanned forward for the next magic: rejecting a bad
 * header still consumes its 16 bytes, so continuing would land the next read on
 * attacker-chosen bytes and hand them back as a valid frame. [WinnFrameReader]
 * latches its first terminal error for exactly that reason, mirroring
 * `DecodeStatus::kInvalid` in the reference header and the `failed` field in
 * the Go reader.
 *
 * This object is deliberately free of any Android import so it runs, and is
 * tested, on a plain JVM -- including against the real Go engine binary. See
 * WinnEngineInteropTest.
 */
internal object WinnFraming {
    /**
     * The on-the-wire `version` field. Bumped only when the layout changes
     * incompatibly, and never on one side alone.
     */
    const val FRAMING_VERSION = 1

    /** 'W' 'N' 'N' '3' read as a little-endian u32. */
    const val MAGIC = 0x334E4E57

    const val HEADER_BYTES = 16

    /**
     * kMaxFramePayloadBytes: 65535, not 65536. This bounds the frame, not the
     * datagram -- the engine's own `max_datagram` is far smaller (1500 ceiling)
     * and it enforces that itself.
     */
    const val MAX_PAYLOAD_BYTES = 65535

    const val OP_CREATE = 0x0001
    const val OP_CREATE_ACK = 0x0002
    const val OP_INBOUND = 0x0010
    const val OP_OUTBOUND = 0x0011
    const val OP_STATUS_REQUEST = 0x0020
    const val OP_STATUS_RESPONSE = 0x0021
    const val OP_CLOSE = 0x0030
    const val OP_CLOSE_ACK = 0x0031
    const val OP_ERROR = 0x00F0

    private val HOST_TO_ENGINE = setOf(OP_CREATE, OP_INBOUND, OP_STATUS_REQUEST, OP_CLOSE)
    private val ENGINE_TO_HOST =
        setOf(OP_CREATE_ACK, OP_OUTBOUND, OP_STATUS_RESPONSE, OP_CLOSE_ACK, OP_ERROR)

    fun isHostToEngine(opcode: Int): Boolean = opcode in HOST_TO_ENGINE

    fun isEngineToHost(opcode: Int): Boolean = opcode in ENGINE_TO_HOST

    fun isKnown(opcode: Int): Boolean = isHostToEngine(opcode) || isEngineToHost(opcode)

    /**
     * Opcodes whose payload is fixed as empty. A trailing payload on one of
     * these would otherwise be silently discarded.
     */
    fun mustBeEmpty(opcode: Int): Boolean =
        opcode == OP_STATUS_REQUEST || opcode == OP_CLOSE || opcode == OP_CLOSE_ACK

    /**
     * Opcodes that carry exactly one datagram. A zero-length one carries
     * nothing and is a protocol error rather than a no-op, because silently
     * dropping it hides a broken peer.
     */
    fun mustBeNonEmpty(opcode: Int): Boolean = opcode == OP_INBOUND || opcode == OP_OUTBOUND

    fun opcodeName(opcode: Int): String = when (opcode) {
        OP_CREATE -> "create"
        OP_CREATE_ACK -> "create-ack"
        OP_INBOUND -> "inbound"
        OP_OUTBOUND -> "outbound"
        OP_STATUS_REQUEST -> "status-request"
        OP_STATUS_RESPONSE -> "status-response"
        OP_CLOSE -> "close"
        OP_CLOSE_ACK -> "close-ack"
        OP_ERROR -> "error"
        else -> "unknown(0x%04x)".format(opcode)
    }

    /**
     * Builds the 16-byte header. Refuses anything the peer's decoder would
     * reject, so an encoding bug fails here rather than tearing down the
     * channel at the far end where it is much harder to attribute.
     */
    fun encodeHeader(opcode: Int, length: Int): ByteArray {
        require(isKnown(opcode)) {
            "Winn opcode ${opcodeName(opcode)} is not defined"
        }
        require(length in 0..MAX_PAYLOAD_BYTES) {
            "Winn frame payload length out of range: $length"
        }
        require(!(mustBeEmpty(opcode) && length != 0)) {
            "Winn ${opcodeName(opcode)} carries no payload, got $length bytes"
        }
        require(!(mustBeNonEmpty(opcode) && length == 0)) {
            "Winn ${opcodeName(opcode)} must carry exactly one datagram"
        }
        val header = ByteArray(HEADER_BYTES)
        putUint32LE(header, 0, MAGIC)
        putUint16LE(header, 4, FRAMING_VERSION)
        putUint16LE(header, 6, opcode)
        putUint32LE(header, 8, length)
        putUint32LE(header, 12, 0)
        return header
    }

    /**
     * Writes one frame. Callers that share an [OutputStream] between threads
     * must serialize; [WinnEngineTransport] implementations do that for us.
     */
    fun writeFrame(
        out: OutputStream,
        opcode: Int,
        payload: ByteArray,
        offset: Int = 0,
        length: Int = payload.size,
    ) {
        require(offset >= 0 && length >= 0 && offset + length <= payload.size) {
            "Winn frame payload slice is out of bounds"
        }
        // Header and payload go out as one write so a frame is never split
        // across two syscalls on a stream the peer is reading eagerly.
        val header = encodeHeader(opcode, length)
        if (length == 0) {
            out.write(header)
        } else {
            val fused = ByteArray(HEADER_BYTES + length)
            System.arraycopy(header, 0, fused, 0, HEADER_BYTES)
            System.arraycopy(payload, offset, fused, HEADER_BYTES, length)
            out.write(fused)
        }
        out.flush()
    }

    private fun putUint16LE(buffer: ByteArray, offset: Int, value: Int) {
        buffer[offset] = (value and 0xFF).toByte()
        buffer[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    private fun putUint32LE(buffer: ByteArray, offset: Int, value: Int) {
        buffer[offset] = (value and 0xFF).toByte()
        buffer[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        buffer[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        buffer[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    internal fun uint16LE(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xFF) or ((buffer[offset + 1].toInt() and 0xFF) shl 8)

    internal fun uint32LE(buffer: ByteArray, offset: Int): Long =
        (buffer[offset].toLong() and 0xFF) or
            ((buffer[offset + 1].toLong() and 0xFF) shl 8) or
            ((buffer[offset + 2].toLong() and 0xFF) shl 16) or
            ((buffer[offset + 3].toLong() and 0xFF) shl 24)
}

/**
 * Reads WNN3 frames from one stream, for one role.
 *
 * Single-threaded by construction: one dedicated reader per stream. It is a
 * class rather than a free function because refusing to resynchronise requires
 * state -- see the latch note in [WinnFraming].
 *
 * @param acceptEngineToHost the direction filter. A host passes true, an engine
 *   passes false. Getting it backwards is not a subtle bug: it rejects every
 *   frame immediately.
 */
internal class WinnFrameReader(
    private val input: InputStream,
    private val acceptEngineToHost: Boolean,
) {
    private val header = ByteArray(WinnFraming.HEADER_BYTES)
    private var failed: IOException? = null

    /**
     * Returns the next frame, or null on a clean end of stream (the peer closed
     * between frames). A stream that dies mid-frame is an error, not a clean
     * close, and raises [EOFException].
     *
     * Once this reader has failed it stays failed: every later call rethrows
     * the first terminal error rather than reading on from a stream whose frame
     * boundaries are no longer trustworthy.
     */
    fun read(): WinnFrame? {
        failed?.let { throw it }
        try {
            return readFrame()
        } catch (e: IOException) {
            failed = e
            throw e
        }
    }

    private fun readFrame(): WinnFrame? {
        val first = input.read()
        if (first < 0) return null
        header[0] = first.toByte()
        readFully(header, 1, WinnFraming.HEADER_BYTES - 1)

        val magic = WinnFraming.uint32LE(header, 0)
        if (magic != (WinnFraming.MAGIC.toLong() and 0xFFFFFFFFL)) {
            throw IOException(
                "Winn frame magic 0x%08x, want 0x%08x".format(magic, WinnFraming.MAGIC)
            )
        }
        val version = WinnFraming.uint16LE(header, 4)
        if (version != WinnFraming.FRAMING_VERSION) {
            throw IOException(
                "Winn frame version $version, want ${WinnFraming.FRAMING_VERSION}"
            )
        }
        val reserved = WinnFraming.uint32LE(header, 12)
        if (reserved != 0L) {
            throw IOException(
                "Winn frame reserved field is 0x%08x, must be zero".format(reserved)
            )
        }
        val opcode = WinnFraming.uint16LE(header, 6)
        val length = WinnFraming.uint32LE(header, 8)
        if (!WinnFraming.isKnown(opcode)) {
            throw IOException("Winn frame opcode 0x%04x is not defined".format(opcode))
        }
        val accepted =
            if (acceptEngineToHost) WinnFraming.isEngineToHost(opcode)
            else WinnFraming.isHostToEngine(opcode)
        if (!accepted) {
            throw IOException(
                "Winn ${WinnFraming.opcodeName(opcode)} travels the other way on this channel"
            )
        }
        if (length > WinnFraming.MAX_PAYLOAD_BYTES) {
            throw IOException(
                "Winn frame announced $length bytes, over the " +
                    "${WinnFraming.MAX_PAYLOAD_BYTES} cap"
            )
        }
        if (WinnFraming.mustBeEmpty(opcode) && length != 0L) {
            throw IOException(
                "Winn ${WinnFraming.opcodeName(opcode)} carries no payload, " +
                    "declared $length bytes"
            )
        }
        if (WinnFraming.mustBeNonEmpty(opcode) && length == 0L) {
            throw IOException(
                "Winn ${WinnFraming.opcodeName(opcode)} must carry exactly one datagram"
            )
        }
        if (length == 0L) return WinnFrame(opcode, ByteArray(0))
        val payload = ByteArray(length.toInt())
        readFully(payload, 0, payload.size)
        return WinnFrame(opcode, payload)
    }

    private fun readFully(buffer: ByteArray, offset: Int, length: Int) {
        var read = 0
        while (read < length) {
            val n = input.read(buffer, offset + read, length - read)
            if (n < 0) {
                throw EOFException("Winn stream ended mid-frame after $read of $length bytes")
            }
            read += n
        }
    }
}

internal class WinnFrame(val opcode: Int, val payload: ByteArray) {
    fun payloadAsText(): String = String(payload, Charsets.UTF_8)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WinnFrame) return false
        return opcode == other.opcode && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int = 31 * opcode + payload.contentHashCode()

    override fun toString(): String =
        "WinnFrame(${WinnFraming.opcodeName(opcode)}, ${payload.size} bytes)"
}
