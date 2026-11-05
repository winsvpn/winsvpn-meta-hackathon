package org.winsvpn.app

import java.io.FileDescriptor
import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class WinnV3TcpChannelTest {
    @Test
    fun `UDP only plan never opens or sends a TCP request channel`() {
        val fixture = Fixture(listOf("udp"), ChannelResult.Throw(IOException("must not open")))
        try {
            fixture.bridge.start()
            assertTrue(fixture.bridge.isRunning())
            assertEquals(0, fixture.host.channelOpens)
            assertEquals(listOf("udp", "create"), fixture.transport.events)
            assertEquals(0, fixture.host.warnings.size)
        } finally {
            fixture.bridge.close()
        }
        assertTrue(fixture.underlay.closed)
    }

    @Test
    fun `advertised TCP without a channel still starts on UDP`() {
        val fixture = Fixture(listOf("udp", "tcp", "tls"), ChannelResult.Missing)
        try {
            fixture.bridge.start()
            assertTrue(fixture.bridge.isRunning())
            assertEquals(1, fixture.host.channelOpens)
            assertEquals(listOf("udp", "create"), fixture.transport.events)
            assertEquals(1, fixture.host.warnings.size)
        } finally {
            fixture.bridge.close()
        }
        assertTrue(fixture.underlay.closed)
    }

    @Test
    fun `channel creation failure leaves the UDP start available`() {
        val error = IOException("channel unavailable")
        val fixture = Fixture(listOf("udp", "tcp"), ChannelResult.Throw(error))
        try {
            fixture.bridge.start()
            assertTrue(fixture.bridge.isRunning())
            assertEquals(listOf("udp", "create"), fixture.transport.events)
            assertEquals(1, fixture.host.warnings.size)
            assertSame(error, fixture.host.warnings.single())
        } finally {
            fixture.bridge.close()
        }
    }

    @Test
    fun `available TCP channel is handed off before Create and closed`() {
        val fixture = Fixture(listOf("udp", "tcp"), ChannelResult.Available)
        try {
            fixture.bridge.start()
            assertTrue(fixture.bridge.isRunning())
            assertEquals(listOf("udp+channel", "create"), fixture.transport.events)
            assertSame(fixture.underlay.descriptor, fixture.transport.sentUdp)
            assertSame(fixture.channel.descriptor, fixture.transport.sentChannel)
            assertEquals(0, fixture.host.warnings.size)
            assertFalse(fixture.channel.closed)
        } finally {
            fixture.bridge.close()
        }
        assertTrue(fixture.channel.closed)
        assertTrue(fixture.underlay.closed)
    }

    @Test
    fun `TCP handoff refusal fails start and releases both descriptors`() {
        val fixture = Fixture(listOf("udp", "tcp"), ChannelResult.Available)
        fixture.transport.refuseChannel = true
        try {
            fixture.bridge.start()
            throw AssertionError("start accepted a rejected TCP channel handoff")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("handoff refused"))
        } finally {
            fixture.bridge.close()
        }
        assertEquals(listOf("udp+channel"), fixture.transport.events)
        assertTrue(fixture.transport.closed)
        assertTrue(fixture.channel.closed)
        assertTrue(fixture.underlay.closed)
    }

    private sealed class ChannelResult {
        object Missing : ChannelResult()
        object Available : ChannelResult()
        class Throw(val error: IOException) : ChannelResult()
    }

    private class FakeUnderlay : WinnUnderlaySocket {
        override val descriptor = FileDescriptor()
        override val protectedBeforeHandoff = true
        override val localPort = 40404
        var closed = false
        override fun close() { closed = true }
    }

    private class FakeChannel : WinnProtectedStreamChannel {
        override val descriptor = FileDescriptor()
        var closed = false
        override fun close() { closed = true }
    }

    private class FakeTransport : WinnEngineTransport {
        val events = mutableListOf<String>()
        private val replies = LinkedBlockingQueue<WinnFrame>()
        var sentUdp: FileDescriptor? = null
        var sentChannel: FileDescriptor? = null
        var refuseChannel = false
        var closed = false

        override fun sendDescriptor(fd: FileDescriptor) {
            events += "udp"
            sentUdp = fd
        }

        override fun sendDescriptorChannel(udp: FileDescriptor, channel: FileDescriptor) {
            events += "udp+channel"
            if (refuseChannel) throw IOException("handoff refused")
            sentUdp = udp
            sentChannel = channel
        }

        override fun writeFrame(opcode: Int, payload: ByteArray) {
            when (opcode) {
                WinnFraming.OP_CREATE -> {
                    events += "create"
                    replies.put(WinnFrame(WinnFraming.OP_CREATE_ACK, ByteArray(0)))
                }
                WinnFraming.OP_CLOSE -> replies.put(WinnFrame(WinnFraming.OP_CLOSE_ACK, ByteArray(0)))
            }
        }

        override fun readFrame(): WinnFrame = replies.take()
        override fun setReadTimeoutMs(timeoutMs: Int) = Unit
        override fun close() {
            closed = true
            replies.offer(WinnFrame(WinnFraming.OP_CLOSE_ACK, ByteArray(0)))
        }
    }

    private class FakeSeam : WinnV3IpPacketSeam {
        private val finished = CountDownLatch(1)
        override fun readOutgoingPacket(buffer: ByteArray): Int {
            finished.await()
            return -1
        }
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() { finished.countDown() }
    }

    private class FakeHost(
        private val underlay: FakeUnderlay,
        private val channel: FakeChannel,
        private val result: ChannelResult,
        private val transport: FakeTransport,
    ) : WinnEngineHost {
        var channelOpens = 0
        val warnings = mutableListOf<Throwable?>()
        override fun openProtectedUnderlaySocket(): WinnUnderlaySocket = underlay
        override fun openProtectedStreamChannel(): WinnProtectedStreamChannel? {
            channelOpens++
            return when (result) {
                is ChannelResult.Missing -> null
                is ChannelResult.Available -> channel
                is ChannelResult.Throw -> throw result.error
            }
        }
        override fun startEngineProcess(): WinnEngineProcess = object : WinnEngineProcess {
            private val alive = AtomicBoolean(true)
            override val transport: WinnEngineTransport = this@FakeHost.transport
            override fun isAlive(): Boolean = alive.get()
            override fun describe(): String = "fake"
            override fun close() {
                alive.set(false)
                transport.close()
            }
        }
        override fun openAwgDatagramSeam(): WinnAwgDatagramSeam? = null
        override fun onDebug(message: String) = Unit
        override fun onWarning(message: String, error: Throwable?) { warnings += error }
        override fun onError(message: String, error: Throwable?) = Unit
    }

    private class Fixture(classes: List<String>, result: ChannelResult) {
        val underlay = FakeUnderlay()
        val channel = FakeChannel()
        val transport = FakeTransport()
        val host = FakeHost(underlay, channel, result, transport)
        val bridge = WinnV3Bridge(
            host,
            FakeSeam(),
            WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820",
                innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1",
                innerMtu = WinnV3Sizing.planFloorInnerMtu(1500, classes),
                pathMtu = 1500,
                carrierClasses = classes,
                sessionId = "tcp-channel-test",
            ),
        )
    }
}
