package org.winsvpn.app

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Host side of the Winn Protocol contract in WINN_PROTOCOL_PLATFORM_PLAN.md
 * section 2, speaking the normative WNN3 framing. It owns the outer UDP socket;
 * the engine subprocess owns only the protocol.
 *
 *     WinnTunnelCreate(configJson, udpFd)  -> descriptor byte, then Create
 *     WinnTunnelWriteInbound(...)          -> Inbound  frames (host -> engine)
 *     WinnTunnelReadOutbound(...)          -> Outbound frames (engine -> host)
 *     WinnTunnelStatusJSON(...)            -> StatusRequest / StatusResponse
 *     WinnTunnelClose(...)                 -> Close, acknowledged by CloseAck
 *
 * WHAT CROSSES INBOUND AND OUTBOUND. AmneziaWG outer datagrams, supplied by a
 * [WinnAwgDatagramSeam] -- NOT raw IP packets off the tun device. This bridge
 * used to read the tun directly and label those packets `INBOUND`, which the
 * engine refuses at create time (`payload:"ip-packet"` -> a hard error) because
 * the datapath module has no AmneziaWG implementation and would forward them to
 * the gateway in cleartext. Rather than relabel the same bytes, this bridge now
 * requires a real source of outer datagrams and refuses to start without one.
 * [WinnAwgDatagramSeam] documents why Android has none today and what building
 * one entails.
 *
 * Deliberately free of Android imports so it can be exercised on a plain JVM
 * against both a local double and the real Go engine binary. Everything
 * platform-specific sits behind [WinnEngineHost].
 */
internal class WinnTunnelBridge(
    private val host: WinnEngineHost,
    private val maxDatagram: Int,
    private val configJson: String,
    private val clockMs: () -> Long = { System.currentTimeMillis() },
) : Closeable {

    companion object {
        /** How long the engine has to answer Create with CreateAck. */
        const val CREATE_ACK_TIMEOUT_MS = 10_000

        /**
         * A status reply older than this means the engine is not answering,
         * whatever its process table entry says. Process existence is not
         * health.
         */
        const val STATUS_STALE_MS = 45_000L

        private const val SHUTDOWN_DRAIN_MS = 1_000L
        private const val CLOSE_ACK_WAIT_MS = 750L

        /**
         * The refusal message when no outer-datagram source exists. Held as a
         * constant so a test can assert the gap is reported rather than
         * silently worked around.
         */
        const val NO_DATAGRAM_SEAM =
            "Refusing to start the Winn engine: this host has no AmneziaWG outer-datagram " +
                "seam. The engine's Inbound/Outbound frames carry AWG outer datagrams, not raw " +
                "IP packets, and it refuses payload \"ip-packet\" at create time because it " +
                "contains no AmneziaWG implementation -- feeding it tun packets would forward " +
                "cleartext to the gateway. Supplying this payload needs the app's AmneziaWG " +
                "engine to expose its outer datagrams instead of sending them itself, which is " +
                "a change to the AmneziaWG integration and not to the Winn wire format."
    }

    @Volatile private var running = false
    @Volatile private var closed = false

    // Round L: set when close() could not confirm it finished (a resource
    // close threw, or a pump outlived its bounded join). See closeCompleted.
    @Volatile private var closeIncomplete = false

    // Round L: counted down when close() has FINISHED, successfully or not.
    private val closeFinished = java.util.concurrent.CountDownLatch(1)
    @Volatile private var failureReason: String? = null

    private var underlay: WinnUnderlaySocket? = null
    private var engine: WinnEngineProcess? = null
    private var seam: WinnAwgDatagramSeam? = null
    private var inboundPump: Thread? = null
    private var outboundPump: Thread? = null

    private val lastStatusAtMs = AtomicLong(0L)
    @Volatile private var lastStatusJson: String = ""
    private val closeAcknowledged = CountDownLatch(1)
    private val statusArrived = Object()
    private var statusSequence = 0L

    private fun publishStatus(json: String) {
        synchronized(statusArrived) {
            lastStatusJson = json
            lastStatusAtMs.set(clockMs())
            statusSequence++
            statusArrived.notifyAll()
        }
    }

    fun requestStatusAndAwait(timeoutMs: Long): String {
        require(timeoutMs in 1..1_000)
        val before = synchronized(statusArrived) { statusSequence }
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        requestStatus()
        synchronized(statusArrived) {
            while (statusSequence == before && running && !closed) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0L) break
                statusArrived.wait(
                    remaining / 1_000_000L,
                    (remaining % 1_000_000L).toInt(),
                )
            }
            return lastStatusJson
        }
    }
    private val startLock = Object()

    /**
     * Brings the engine up. Returns once the engine has acknowledged the
     * config with CreateAck and both datagram pumps are running. Throws, having
     * released everything it allocated, if any step fails.
     */
    @Throws(IOException::class)
    fun start() {
        synchronized(startLock) {
            check(!running && !closed) { "Winn bridge already started" }

            // Step 0, before anything is allocated: is there a correct source
            // of the bytes this engine carries? If not, stop here rather than
            // open a socket and spawn a process for a session that could only
            // ever send the wrong payload.
            val datagrams = host.openAwgDatagramSeam()
                ?: throw IOException(NO_DATAGRAM_SEAM)
            seam = datagrams

            // Step 1, before the engine process exists at all: open the outer
            // UDP socket here and protect it here. The engine is never given
            // the chance to open one of its own.
            val socket = try {
                host.openProtectedUnderlaySocket()
            } catch (e: Exception) {
                closeQuietly(datagrams)
                seam = null
                throw if (e is IOException) e else IOException("Winn outer UDP socket failed", e)
            }
            underlay = socket
            if (!socket.protectedBeforeHandoff) {
                closeQuietly(socket)
                underlay = null
                closeQuietly(datagrams)
                seam = null
                throw IOException(
                    "Refusing to start the Winn engine: the outer UDP socket was not protected " +
                        "before handoff. An unprotected socket routes back into this service's own " +
                        "tun and the tunnel dead-loops."
                )
            }
            host.onDebug("Winn outer UDP socket opened and protected on local port ${socket.localPort}.")

            val process: WinnEngineProcess
            try {
                process = host.startEngineProcess()
            } catch (e: Exception) {
                closeQuietly(socket)
                underlay = null
                closeQuietly(datagrams)
                seam = null
                throw IOException("Winn engine subprocess did not start", e)
            }
            engine = process

            try {
                val transport = process.transport
                transport.setReadTimeoutMs(CREATE_ACK_TIMEOUT_MS)

                // The descriptor goes first, on its own, because the engine
                // collects it with a one-byte recvmsg before it reads a single
                // frame. See WinnEngineTransport.sendDescriptor.
                transport.sendDescriptor(socket.descriptor)
                transport.writeFrame(
                    WinnFraming.OP_CREATE,
                    configJson.toByteArray(Charsets.UTF_8),
                )
                awaitCreateAck(transport)
                transport.setReadTimeoutMs(0)

                running = true
                startPumps(transport, datagrams)
                host.onDebug("Winn engine created the datapath; pumps running (${process.describe()}).")
            } catch (e: Exception) {
                running = false
                closeQuietly(process)
                engine = null
                closeQuietly(socket)
                underlay = null
                closeQuietly(datagrams)
                seam = null
                throw if (e is IOException) e else IOException("Winn engine handshake failed", e)
            }
        }
    }

    private fun awaitCreateAck(transport: WinnEngineTransport) {
        val frame = transport.readFrame()
            ?: throw IOException("Winn engine closed the channel before acknowledging the config")
        when (frame.opcode) {
            WinnFraming.OP_CREATE_ACK -> {
                publishStatus(frame.payloadAsText())
            }
            WinnFraming.OP_ERROR ->
                throw IOException("Winn engine rejected the config: ${frame.payloadAsText().take(300)}")
            else ->
                throw IOException(
                    "Winn engine sent ${WinnFraming.opcodeName(frame.opcode)} before create-ack"
                )
        }
    }

    private fun startPumps(transport: WinnEngineTransport, datagrams: WinnAwgDatagramSeam) {
        val started = CountDownLatch(2)

        val batched = transport as? WinnV3BatchTransport

        outboundPump = Thread {
            started.countDown()
            // One reusable slab; readBatch coalesces every frame already queued.
            val batch = batched?.let { WinnV3PacketBatch(64, 512 * 1024) }
            try {
                while (running && !closed) {
                    if (batched != null && batch != null) {
                        val count = batched.readBatch(batch)
                        if (count < 0) {
                            fail("Winn engine closed the channel")
                            return@Thread
                        }
                        for (i in 0 until count) {
                            val keepGoing = handleEngineFrame(
                                batch.opcode(i), batch.bytes, batch.offset(i), batch.length(i),
                                datagrams,
                            )
                            if (!keepGoing) return@Thread
                        }
                    } else {
                        val frame = transport.readFrame() ?: run {
                            fail("Winn engine closed the channel")
                            return@Thread
                        }
                        val keepGoing = handleEngineFrame(
                            frame.opcode, frame.payload, 0, frame.payload.size, datagrams,
                        )
                        if (!keepGoing) return@Thread
                    }
                }
            } catch (e: Exception) {
                if (running && !closed) fail("Winn outbound pump stopped: ${e.javaClass.simpleName}")
            } finally {
                // Never leave close() blocked on an acknowledgement that can no
                // longer arrive.
                closeAcknowledged.countDown()
            }
        }.apply {
            name = "Calc-Winn-Outbound"
            isDaemon = true
            start()
        }

        inboundPump = Thread {
            started.countDown()
            val capacity = minOf(WinnFraming.MAX_PAYLOAD_BYTES, maxOf(maxDatagram, 1500))
            val buffer = ByteArray(capacity)
            // Header and payload are built in place in one reusable slab: no
            // per-datagram allocation, one write per datagram.
            val frame = batched?.let { WinnV3PacketBatch(1, capacity + WinnFraming.HEADER_BYTES) }
            try {
                while (running && !closed) {
                    val n = datagrams.readOutgoingDatagram(buffer)
                    if (n < 0) {
                        if (running && !closed) fail("AmneziaWG datagram seam ended")
                        return@Thread
                    }
                    // A zero-length Inbound is a protocol error on this wire,
                    // not a no-op, so it is dropped here rather than sent.
                    if (n == 0) continue
                    if (batched != null && frame != null) {
                        frame.clear()
                        frame.append(WinnFraming.OP_INBOUND, buffer, 0, n)
                        batched.writeBatch(frame)
                    } else {
                        transport.writeFrame(WinnFraming.OP_INBOUND, buffer.copyOf(n))
                    }
                }
            } catch (e: Exception) {
                if (running && !closed) fail("Winn inbound pump stopped: ${e.javaClass.simpleName}")
            }
        }.apply {
            name = "Calc-Winn-Inbound"
            isDaemon = true
            start()
        }

        started.await(2, TimeUnit.SECONDS)
    }


    /** One engine-to-host frame. False means the outbound pump must stop. */
    private fun handleEngineFrame(
        opcode: Int,
        bytes: ByteArray,
        offset: Int,
        length: Int,
        datagrams: WinnAwgDatagramSeam,
    ): Boolean = when (opcode) {
        WinnFraming.OP_OUTBOUND -> {
            datagrams.writeIncomingDatagram(bytes, offset, length)
            true
        }
        WinnFraming.OP_STATUS_RESPONSE, WinnFraming.OP_CREATE_ACK -> {
            publishStatus(String(bytes, offset, length, Charsets.UTF_8))
            true
        }
        WinnFraming.OP_CLOSE_ACK -> {
            // CloseAck carries no payload by the normative framing; the
            // stream ends after it.
            closeAcknowledged.countDown()
            false
        }
        WinnFraming.OP_ERROR -> {
            // The engine's text stays in the stored reason only;
            // see WinnV3Bridge's OP_ERROR branch.
            fail(
                "Winn engine reported: ${String(bytes, offset, length, Charsets.UTF_8).take(300)}",
                logged = "Winn engine reported an error",
            )
            false
        }
        else -> {
            // The reader already enforces direction and rejects unknown
            // opcodes, so this means the reader and this switch disagree.
            fail("Winn engine sent an unhandled opcode: " + WinnFraming.opcodeName(opcode))
            false
        }
    }

    private fun fail(reason: String, logged: String = reason) {
        if (failureReason == null) failureReason = reason
        running = false
        synchronized(statusArrived) { statusArrived.notifyAll() }
        host.onError("Winn tunnel failed: $logged", null)
    }

    /** `WinnTunnelStatusJSON`. Fire-and-forget; the reply lands asynchronously. */
    fun requestStatus() {
        if (!running || closed) return
        try {
            engine?.transport?.writeFrame(WinnFraming.OP_STATUS_REQUEST, ByteArray(0))
        } catch (e: Exception) {
            fail("Winn status request could not be sent: ${e.javaClass.simpleName}")
        }
    }

    /** The most recent status document the engine sent. Never contains host secrets. */
    fun statusJson(): String = lastStatusJson

    fun failure(): String? = failureReason

    /**
     * Liveness that a live process alone cannot fake: the engine must have
     * answered a status round trip recently. Call [requestStatus] on an
     * interval for this to stay meaningful.
     */
    fun isHealthy(): Boolean {
        if (!running || closed) return false
        if (engine?.isAlive() != true) return false
        val last = lastStatusAtMs.get()
        if (last <= 0L) return false
        return clockMs() - last <= STATUS_STALE_MS
    }

    fun isRunning(): Boolean = running && !closed

    /**
     * `WinnTunnelClose`. Idempotent.
     *
     * Note that CloseAck carries no payload, so this is the end of the
     * conversation: a caller that wants final counters must call
     * [requestStatus] and read [statusJson] BEFORE closing.
     */
    override fun close() {
        synchronized(startLock) {
            if (closed) return
            closed = true
            running = false
        }
        synchronized(statusArrived) { statusArrived.notifyAll() }
        // Round L: `closed` above marks the close STARTED; closeFinished marks
        // it finished. A concurrent caller returns at the check above and must
        // use closeCompleted()/awaitCloseCompleted() to learn how it ended.
        // No catch: anything thrown still propagates, and a close that did
        // not return normally is recorded as incomplete before it finishes.
        var returnedNormally = false
        try {
            closeResources()
            returnedNormally = true
        } finally {
            if (!returnedNormally) closeIncomplete = true
            closeFinished.countDown()
        }
    }

    private fun closeResources() {
        val process = engine
        if (process != null) {
            try {
                process.transport.writeFrame(WinnFraming.OP_CLOSE, ByteArray(0))
                // Give the engine a moment to acknowledge so it can shut its own
                // datapath down in order. Failing to hear back is not an error:
                // the channel is being torn down either way.
                closeAcknowledged.await(CLOSE_ACK_WAIT_MS, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
            }
        }
        // Closing the channel unblocks the outbound pump; closing the seam
        // unblocks the inbound pump.
        closeQuietly(process)
        closeQuietly(seam)
        closeQuietly(underlay)
        engine = null
        underlay = null
        seam = null
        joinQuietly(outboundPump)
        joinQuietly(inboundPump)
        outboundPump = null
        inboundPump = null
    }

    private fun joinQuietly(thread: Thread?) {
        if (thread == null) return
        if (thread === Thread.currentThread()) {
            // A pump closing its own bridge cannot confirm its own exit.
            closeIncomplete = true
            return
        }
        try {
            thread.join(SHUTDOWN_DRAIN_MS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        if (thread.isAlive) closeIncomplete = true
    }

    /**
     * Round L: true once close() has FINISHED and confirmed every step: each
     * resource closed without throwing and each pump exited within its
     * bounded join. False before close(), false while a close (this caller's
     * or a concurrent one's) is still running, and false for a close that
     * could not confirm itself. The release acknowledgement rests on this.
     */
    fun closeCompleted(): Boolean = closeFinished.count == 0L && !closeIncomplete

    /** [closeCompleted], waiting up to [timeoutMs] for a running close to finish. */
    fun awaitCloseCompleted(timeoutMs: Long): Boolean {
        val finished = try {
            closeFinished.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        return finished && !closeIncomplete
    }

    /** This bridge's close, as something a teardown pass can await. */
    fun closeCompletion(): WinnV3Completion = WinnV3Completion { awaitCloseCompleted(it) }

    private fun closeQuietly(closeable: Closeable?) {
        try {
            closeable?.close()
        } catch (e: Exception) {
            closeIncomplete = true
            host.onWarning("Winn resource close was incomplete", e)
        }
    }
}
