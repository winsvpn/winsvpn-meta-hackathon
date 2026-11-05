package org.winsvpn.app

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The WNN3 framing, on its own terms. Cross-language agreement with the real
 * engine is proved in WinnEngineInteropTest.
 */
class WinnProtocolFramingTest {

    private fun hostReader(bytes: ByteArray) =
        WinnFrameReader(ByteArrayInputStream(bytes), acceptEngineToHost = true)

    private fun engineReader(bytes: ByteArray) =
        WinnFrameReader(ByteArrayInputStream(bytes), acceptEngineToHost = false)

    @Test
    fun headerIsSixteenLittleEndianBytes() {
        assertArrayEquals(
            byteArrayOf(
                0x57, 0x4E, 0x4E, 0x33, // magic "WNN3" as u32 LE
                0x01, 0x00, // version 1
                0x10, 0x00, // opcode 0x0010 inbound
                0x39, 0x05, 0x00, 0x00, // length 1337
                0x00, 0x00, 0x00, 0x00, // reserved
            ),
            WinnFraming.encodeHeader(WinnFraming.OP_INBOUND, 1337),
        )
        assertArrayEquals(
            byteArrayOf(
                0x57, 0x4E, 0x4E, 0x33,
                0x01, 0x00,
                0x01, 0x00, // create
                0x00, 0x00, 0x00, 0x00, // an empty create is legal
                0x00, 0x00, 0x00, 0x00,
            ),
            WinnFraming.encodeHeader(WinnFraming.OP_CREATE, 0),
        )
        assertArrayEquals(
            byteArrayOf(
                0x57, 0x4E, 0x4E, 0x33,
                0x01, 0x00,
                0x11, 0x00, // outbound
                0xFF.toByte(), 0xFF.toByte(), 0x00, 0x00, // 65535
                0x00, 0x00, 0x00, 0x00,
            ),
            WinnFraming.encodeHeader(WinnFraming.OP_OUTBOUND, 65535),
        )
    }

    @Test
    fun roundTripsPayloadsIncludingMaximum() {
        val payloads = listOf(
            byteArrayOf(0x45, 0x00, 0x00, 0x54),
            ByteArray(WinnFraming.MAX_PAYLOAD_BYTES) { (it and 0xFF).toByte() },
        )
        val out = ByteArrayOutputStream()
        for (payload in payloads) {
            WinnFraming.writeFrame(out, WinnFraming.OP_OUTBOUND, payload)
        }
        val reader = hostReader(out.toByteArray())
        for (payload in payloads) {
            val frame = reader.read()!!
            assertEquals(WinnFraming.OP_OUTBOUND, frame.opcode)
            assertArrayEquals(payload, frame.payload)
        }
        assertNull("stream should be drained", reader.read())
    }

    @Test
    fun emptyPayloadOpcodesRoundTrip() {
        val out = ByteArrayOutputStream()
        WinnFraming.writeFrame(out, WinnFraming.OP_CLOSE_ACK, ByteArray(0))
        val frame = hostReader(out.toByteArray()).read()!!
        assertEquals(WinnFraming.OP_CLOSE_ACK, frame.opcode)
        assertEquals(0, frame.payload.size)
    }

    @Test
    fun cleanEndOfStreamBetweenFramesReturnsNull() {
        assertNull(hostReader(ByteArray(0)).read())
    }

    @Test
    fun truncatedFrameIsAnErrorNotACleanClose() {
        val out = ByteArrayOutputStream()
        WinnFraming.writeFrame(out, WinnFraming.OP_OUTBOUND, ByteArray(64))
        val truncated = out.toByteArray().copyOf(32)
        try {
            hostReader(truncated).read()
            fail("expected EOFException")
        } catch (e: EOFException) {
            assertTrue(e.message!!, e.message!!.contains("mid-frame"))
        }
    }

    @Test
    fun aWrongMagicIsRejected() {
        val out = ByteArrayOutputStream()
        WinnFraming.writeFrame(out, WinnFraming.OP_OUTBOUND, byteArrayOf(1))
        val corrupted = out.toByteArray().also { it[0] = 0x58 }
        try {
            hostReader(corrupted).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("magic"))
        }
    }

    @Test
    fun aWrongVersionIsRejected() {
        val out = ByteArrayOutputStream()
        WinnFraming.writeFrame(out, WinnFraming.OP_OUTBOUND, byteArrayOf(1))
        val corrupted = out.toByteArray().also { it[4] = 0x02 }
        try {
            hostReader(corrupted).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("version"))
        }
    }

    @Test
    fun aNonZeroReservedFieldIsRejected() {
        // The reserved field is the one free extension slot. Accepting a
        // nonzero value would spend it silently.
        val out = ByteArrayOutputStream()
        WinnFraming.writeFrame(out, WinnFraming.OP_OUTBOUND, byteArrayOf(1))
        val corrupted = out.toByteArray().also { it[12] = 0x01 }
        try {
            hostReader(corrupted).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("reserved"))
        }
    }

    @Test
    fun aBadHeaderIsTerminalAndTheReaderNeverResynchronises() {
        val good = ByteArrayOutputStream()
        WinnFraming.writeFrame(good, WinnFraming.OP_STATUS_RESPONSE, "{}".toByteArray())
        val corrupt = ByteArray(WinnFraming.HEADER_BYTES) { 0x22 }
        val reader = hostReader(corrupt + good.toByteArray())
        try {
            reader.read()
            fail("expected the bad header to be rejected")
        } catch (_: IOException) {
        }
        try {
            reader.read()
            fail("a latched reader must not hand back the following frame")
        } catch (e: IOException) {
            // Rejecting a header still consumed its 16 bytes, so continuing
            // would let a peer choose where the next frame starts.
            assertTrue(e.message!!, e.message!!.contains("magic"))
        }
    }

    @Test
    fun payloadLengthOverTheCapIsRejectedBeforeAllocating() {
        val header = WinnFraming.encodeHeader(WinnFraming.OP_OUTBOUND, 1)
        // Rewrite the length to 65536, one over the cap.
        header[8] = 0x00
        header[9] = 0x00
        header[10] = 0x01
        header[11] = 0x00
        try {
            hostReader(header).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("over the"))
        }
    }

    @Test
    fun unknownOpcodeIsRejected() {
        val header = WinnFraming.encodeHeader(WinnFraming.OP_OUTBOUND, 1)
        header[6] = 0x7F
        header[7] = 0x00
        try {
            hostReader(header).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("not defined"))
        }
    }

    @Test
    fun aFrameTravellingTheWrongWayIsRejected() {
        // A host must never accept an Inbound frame: acting on one would let a
        // confused or hostile peer have its own packet looped straight back.
        val out = ByteArrayOutputStream()
        WinnFraming.writeFrame(out, WinnFraming.OP_INBOUND, byteArrayOf(1, 2, 3))
        try {
            hostReader(out.toByteArray()).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("travels the other way"))
        }
        // The engine role is the mirror image.
        val fromHost = ByteArrayOutputStream()
        WinnFraming.writeFrame(fromHost, WinnFraming.OP_OUTBOUND, byteArrayOf(1, 2, 3))
        try {
            engineReader(fromHost.toByteArray()).read()
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("travels the other way"))
        }
    }

    @Test
    fun payloadPresenceRulesAreEnforcedInBothDirections() {
        // Close/CloseAck/StatusRequest carry nothing; a trailing payload would
        // otherwise be silently dropped.
        try {
            WinnFraming.writeFrame(ByteArrayOutputStream(), WinnFraming.OP_CLOSE, byteArrayOf(1))
            fail("expected close with a payload to be refused")
        } catch (_: IllegalArgumentException) {
        }
        // Inbound/Outbound carry exactly one datagram; a zero-length one is a
        // protocol error rather than a no-op.
        try {
            WinnFraming.writeFrame(ByteArrayOutputStream(), WinnFraming.OP_INBOUND, ByteArray(0))
            fail("expected an empty inbound to be refused")
        } catch (_: IllegalArgumentException) {
        }

        val emptyInbound = WinnFraming.encodeHeader(WinnFraming.OP_INBOUND, 1).also { it[8] = 0 }
        try {
            engineReader(emptyInbound).read()
            fail("expected an empty inbound to be rejected on read")
        } catch (e: IOException) {
            assertTrue(e.message!!, e.message!!.contains("exactly one datagram"))
        }
    }

    @Test
    fun writingOverTheCapIsRejected() {
        try {
            WinnFraming.writeFrame(
                ByteArrayOutputStream(),
                WinnFraming.OP_INBOUND,
                ByteArray(WinnFraming.MAX_PAYLOAD_BYTES + 1),
            )
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun frameDirectionsArePartitioned() {
        val hostToEngine = listOf(
            WinnFraming.OP_CREATE,
            WinnFraming.OP_INBOUND,
            WinnFraming.OP_STATUS_REQUEST,
            WinnFraming.OP_CLOSE,
        )
        val engineToHost = listOf(
            WinnFraming.OP_CREATE_ACK,
            WinnFraming.OP_OUTBOUND,
            WinnFraming.OP_STATUS_RESPONSE,
            WinnFraming.OP_CLOSE_ACK,
            WinnFraming.OP_ERROR,
        )
        for (opcode in hostToEngine) {
            assertTrue(WinnFraming.opcodeName(opcode), WinnFraming.isHostToEngine(opcode))
            assertTrue(WinnFraming.opcodeName(opcode), !WinnFraming.isEngineToHost(opcode))
        }
        for (opcode in engineToHost) {
            assertTrue(WinnFraming.opcodeName(opcode), WinnFraming.isEngineToHost(opcode))
            assertTrue(WinnFraming.opcodeName(opcode), !WinnFraming.isHostToEngine(opcode))
        }
    }

    @Test
    fun wireConstantsArePinned() {
        // The Go datapath lane and windows/runner/winn_frame.h implement the
        // mirror of this. Changing it is a cross-lane contract change, so make
        // it fail loudly here first.
        assertEquals(1, WinnFraming.FRAMING_VERSION)
        assertEquals(0x334E4E57, WinnFraming.MAGIC)
        assertEquals(16, WinnFraming.HEADER_BYTES)
        assertEquals(65535, WinnFraming.MAX_PAYLOAD_BYTES)
        assertEquals(0x0001, WinnFraming.OP_CREATE)
        assertEquals(0x0002, WinnFraming.OP_CREATE_ACK)
        assertEquals(0x0010, WinnFraming.OP_INBOUND)
        assertEquals(0x0011, WinnFraming.OP_OUTBOUND)
        assertEquals(0x0020, WinnFraming.OP_STATUS_REQUEST)
        assertEquals(0x0021, WinnFraming.OP_STATUS_RESPONSE)
        assertEquals(0x0030, WinnFraming.OP_CLOSE)
        assertEquals(0x0031, WinnFraming.OP_CLOSE_ACK)
        assertEquals(0x00F0, WinnFraming.OP_ERROR)
    }
}
