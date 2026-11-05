package org.winsvpn.app

import java.io.BufferedInputStream
import java.io.Closeable
import java.io.FileDescriptor
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Local stand-in for the Go engine, speaking the WNN3 framing.
 *
 * READ THIS BEFORE TRUSTING IT. A double that speaks whatever
 * WinnProtocolFraming speaks cannot detect a disagreement with the real engine
 * -- that is exactly how the Android and Go lanes both stayed green while being
 * mutually unusable. This double exists to exercise the bridge's *logic*
 * (ordering, pumping, failure handling, shutdown) quickly and without a
 * subprocess. The claim that the wire format is correct comes from
 * WinnEngineInteropTest, which drives the real binary, and from
 * android/devicecheck/, which does it on real hardware over a real
 * LocalSocket.
 *
 * WHAT THIS DOUBLE DOES NOT COVER, and must not be read as covering:
 *  - The wire format's agreement with the engine. See above.
 *  - SCM_RIGHTS descriptor passing. The double runs over a loopback TCP
 *    socket and only records which FileDescriptor the bridge handed it.
 *  - VpnService.protect(). There is no VpnService on a JVM; the fake host
 *    records that protection was claimed, in the right order.
 */
internal class WinnEngineDouble(
    private val socket: Socket,
    private val behaviour: Behaviour = Behaviour(),
) : Closeable {

    class Behaviour(
        /** Opcode the double answers Create with. */
        val createReply: Int = WinnFraming.OP_CREATE_ACK,
        val createReplyPayload: String = "{\"contract\":\"winn-datapath/1\",\"up\":true}",
        /** Reflect every Inbound straight back as an Outbound. */
        val echoInbound: Boolean = true,
        val answerStatusRequests: Boolean = true,
        /** Drop the channel once this many frames have been read (-1 = never). */
        val closeChannelAfterFrames: Int = -1,
    )

    val receivedCreatePayloads = CopyOnWriteArrayList<String>()
    val receivedInbound = CopyOnWriteArrayList<ByteArray>()
    val sawClose = AtomicBoolean(false)
    val statusRequests = java.util.concurrent.atomic.AtomicInteger(0)

    private val input: InputStream = BufferedInputStream(socket.getInputStream())
    private val output: OutputStream = socket.getOutputStream()
    private val stopped = AtomicBoolean(false)

    // The engine role accepts host-to-engine opcodes only.
    private val reader = WinnFrameReader(input, acceptEngineToHost = false)
    private var thread: Thread? = null

    fun start() {
        thread = Thread {
            var framesRead = 0
            try {
                while (!stopped.get()) {
                    val frame = reader.read() ?: return@Thread
                    framesRead++
                    when (frame.opcode) {
                        WinnFraming.OP_CREATE -> {
                            receivedCreatePayloads += frame.payloadAsText()
                            writeFrame(
                                behaviour.createReply,
                                behaviour.createReplyPayload.toByteArray(Charsets.UTF_8),
                            )
                        }
                        WinnFraming.OP_INBOUND -> {
                            receivedInbound += frame.payload
                            if (behaviour.echoInbound) {
                                writeFrame(WinnFraming.OP_OUTBOUND, frame.payload)
                            }
                        }
                        WinnFraming.OP_STATUS_REQUEST -> {
                            statusRequests.incrementAndGet()
                            if (behaviour.answerStatusRequests) {
                                writeFrame(
                                    WinnFraming.OP_STATUS_RESPONSE,
                                    "{\"up\":true,\"state\":\"up\"}".toByteArray(Charsets.UTF_8),
                                )
                            }
                        }
                        WinnFraming.OP_CLOSE -> {
                            sawClose.set(true)
                            // CloseAck carries no payload, then the stream ends.
                            writeFrame(WinnFraming.OP_CLOSE_ACK, ByteArray(0))
                            return@Thread
                        }
                    }
                    if (behaviour.closeChannelAfterFrames in 1..framesRead) {
                        socket.close()
                        return@Thread
                    }
                }
            } catch (_: Exception) {
                // A closed channel is the normal way this thread ends.
            }
        }.apply {
            name = "WinnEngineDouble"
            isDaemon = true
            start()
        }
    }

    @Synchronized
    private fun writeFrame(opcode: Int, payload: ByteArray) {
        WinnFraming.writeFrame(output, opcode, payload)
    }

    /** Pushes an unsolicited frame, e.g. to simulate a mid-session failure. */
    fun push(opcode: Int, payload: ByteArray) = writeFrame(opcode, payload)

    override fun close() {
        stopped.set(true)
        try {
            socket.close()
        } catch (_: Exception) {
        }
        thread?.join(1_000)
    }

    companion object {
        /** A connected loopback socket pair: (host side, engine side). */
        fun connectedPair(): Pair<Socket, Socket> {
            ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
                val hostSide = Socket()
                hostSide.connect(InetSocketAddress(server.inetAddress, server.localPort), 2_000)
                val engineSide = server.accept()
                hostSide.tcpNoDelay = true
                engineSide.tcpNoDelay = true
                return hostSide to engineSide
            }
        }
    }
}

/**
 * [WinnEngineTransport] over a plain socket, for the double. Mirrors the real
 * LocalSocket transport except that the descriptor is recorded rather than
 * actually sent -- TCP has no SCM_RIGHTS.
 */
internal class LoopbackWinnTransport(private val socket: Socket) : WinnEngineTransport {
    val descriptorsHandedOver = CopyOnWriteArrayList<FileDescriptor>()

    /** Frames written before the descriptor was sent. Must be empty: the real
     *  engine reads the descriptor before it reads a single frame. */
    val framesBeforeDescriptor = CopyOnWriteArrayList<Int>()

    private val out: OutputStream = socket.getOutputStream()
    private val input: InputStream = BufferedInputStream(socket.getInputStream())
    private val writeLock = Object()
    private val reader = WinnFrameReader(input, acceptEngineToHost = true)

    override fun writeFrame(opcode: Int, payload: ByteArray) {
        synchronized(writeLock) {
            if (descriptorsHandedOver.isEmpty()) framesBeforeDescriptor += opcode
            WinnFraming.writeFrame(out, opcode, payload)
        }
    }

    override fun sendDescriptor(fd: FileDescriptor) {
        synchronized(writeLock) {
            descriptorsHandedOver += fd
            // The real transport writes one byte with the descriptor attached.
            // TCP carries no ancillary data, and writing the byte here would
            // desynchronise the double's frame reader, so it is recorded only.
        }
    }

    override fun readFrame(): WinnFrame? = reader.read()

    override fun setReadTimeoutMs(timeoutMs: Int) {
        socket.soTimeout = timeoutMs
    }

    override fun close() {
        try {
            socket.close()
        } catch (_: Exception) {
        }
    }
}

/**
 * An AmneziaWG outer-datagram seam stand-in. Each read returns exactly one
 * datagram, like the real seam would, and each write is recorded as exactly one
 * datagram.
 *
 * NOTE WHAT THIS IS NOT. It is not a tun device, and the bytes it carries are
 * not IP packets. The engine's Inbound/Outbound frames carry AWG outer
 * datagrams; a fake that pretended to be a tun would re-encode the exact
 * confusion this lane had to fix.
 */
internal class FakeAwgDatagramSeam : WinnAwgDatagramSeam {
    private val outgoing = LinkedBlockingQueue<ByteArray>()
    private val incoming = LinkedBlockingQueue<ByteArray>()
    private val closed = AtomicBoolean(false)

    val closeCount = java.util.concurrent.atomic.AtomicInteger(0)

    override fun readOutgoingDatagram(buffer: ByteArray): Int {
        while (!closed.get()) {
            val datagram = outgoing.poll(25, TimeUnit.MILLISECONDS) ?: continue
            val n = minOf(buffer.size, datagram.size)
            System.arraycopy(datagram, 0, buffer, 0, n)
            return n
        }
        return -1
    }

    override fun writeIncomingDatagram(datagram: ByteArray, length: Int) {
        incoming.put(datagram.copyOf(length))
    }

    /** Queues an outer datagram the AWG engine wants sent to the gateway. */
    fun injectFromAwgEngine(datagram: ByteArray) {
        outgoing.put(datagram)
    }

    /** The next outer datagram delivered back to the AWG engine. */
    fun awaitDeliveredToAwgEngine(timeoutMs: Long): ByteArray? =
        incoming.poll(timeoutMs, TimeUnit.MILLISECONDS)

    override fun close() {
        closeCount.incrementAndGet()
        closed.set(true)
    }
}
