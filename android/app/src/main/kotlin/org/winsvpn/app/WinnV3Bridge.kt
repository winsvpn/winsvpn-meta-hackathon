package org.winsvpn.app

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * The v3 counterpart of [WinnTunnelBridge]: it drives `winn-datapath -winn3`
 * and pumps **inner IP packets** across `Inbound`/`Outbound`.
 *
 * ## Why this is a separate class and not a mode on [WinnTunnelBridge]
 *
 * The same reason [WinnV3IpPacketSeam] is a separate interface from
 * [WinnAwgDatagramSeam], stated in that file: the two carry different bytes,
 * and a single pump whose payload meaning depends on a field elsewhere is
 * exactly how a host ends up labelling tun packets as AmneziaWG datagrams  :
 * which is cleartext on the wire. [WinnTunnelBridge] takes a
 * [WinnAwgDatagramSeam] and emits [WinnEngineConfig.PAYLOAD_AWG_DATAGRAM];
 * this takes a [WinnV3IpPacketSeam] and emits [WinnV3Host.PAYLOAD_IP_PACKET].
 * Neither can be handed the other's seam, because the types do not convert.
 *
 * ## What is deliberately NOT here
 *
 *  - **No AmneziaWG.** v3 needs no outer-datagram seam at all  :  `winn3/core`
 *    is the crypto. [WinnV3Host] §5 is the argument; the consequence is that
 *    this bridge never calls [WinnEngineHost.openAwgDatagramSeam], so the
 *    `NO_DATAGRAM_SEAM` refusal that blocks v2 on Android does not apply.
 *  - **No clock.** [WinnV3Host] §3: one timing authority per tunnel and it is
 *    inside the engine. The `clockMs` below is used only to age this host's own
 *    status bookkeeping, never sent.
 *  - **No promotion decision.** That is [WinnV3StagedStart]'s, gated by
 *    [WinnV3PromotionGate]. This class only reports what the engine said.
 *
 * Free of Android imports, for the same reason [WinnTunnelBridge] is: the pump
 * and lifecycle rules are exercised on a plain JVM. Everything platform-specific
 * is behind [WinnEngineHost] and [WinnV3IpPacketSeam].
 */
internal class WinnV3Bridge(
    private val host: WinnEngineHost,
    private val seam: WinnV3IpPacketSeam,
    private val config: WinnV3EngineConfig,
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    private val probeProtectedSocketErrno: () -> WinnV3ProtectedSocketErrno.Result = {
        WinnV3ProtectedSocketErrno.Result(closed = true)
    },
) : Closeable {

    companion object {
        /** How long the engine has to answer Create with CreateAck. */
        const val CREATE_ACK_TIMEOUT_MS = 10_000

        /**
         * A status reply older than this means the engine is not answering,
         * whatever its process table entry says. Same rule and same number as
         * [WinnTunnelBridge.STATUS_STALE_MS]: process existence is not health.
         */
        const val STATUS_STALE_MS = 45_000L

        private const val SHUTDOWN_DRAIN_MS = 1_000L
        private const val CLOSE_ACK_WAIT_MS = 750L

        /**
         * The read buffer for the tun pump.
         *
         * Sized from the interface MTU rather than from `max_datagram`, because
         * what crosses here is an inner IP packet and the interface MTU is
         * exactly the largest one the kernel will hand up. One byte of slack is
         * NOT added: a read that returned more than the MTU would mean the host
         * configured an interface it did not size, and truncating it silently is
         * how a black hole gets built. It cannot happen, and if it ever does the
         * frame writer's own bound is the thing that complains.
         */
        fun bufferSizeFor(innerMtu: Int): Int =
            minOf(WinnFraming.MAX_PAYLOAD_BYTES, maxOf(innerMtu, WinnV3Sizing.MIN_INNER_MTU_V4))
    }

    @Volatile private var running = false
    @Volatile private var closed = false

    // Round L: set when close() could not confirm it finished (a resource
    // close threw, or a pump outlived its bounded join). See closeCompleted.
    @Volatile private var closeIncomplete = false

    // Round L: counted down when close() has FINISHED, successfully or not.
    private val closeFinished = java.util.concurrent.CountDownLatch(1)
    @Volatile private var failureReason: String? = null
    @Volatile private var recordedFailureCause: Throwable? = null
    @Volatile private var recordedOrdinaryNetworkFailure: WinnV3OrdinaryNetworkFailureClass? = null
    @Volatile private var recordedOrdinaryNetworkPosixErrno: Int? = null
    @Volatile private var cachedProtectedSocketProbe: WinnV3ProtectedSocketErrno.Result? = null

    @Volatile private var underlay: WinnUnderlaySocket? = null
    @Volatile private var streamChannel: WinnProtectedStreamChannel? = null
    @Volatile private var engine: WinnEngineProcess? = null
    private var inboundPump: Thread? = null
    private var outboundPump: Thread? = null

    private val lastStatusAtMs = AtomicLong(0L)
    @Volatile private var lastStatusJson: String = ""

    // Pump census. Each counter is written only by the pump that owns its
    // direction and read by the health watchdog for a debug-build perf line.
    // Telemetry only: nothing here decides anything. The downlink write time
    // covers the whole tun write of one engine batch and its packet count is
    // what the seam reports it delivered to the device; the uplink write time
    // is the whole channel write of one host batch, which is where a slow
    // engine makes this side wait, counted only for batches actually written.
    // Write times are wall time inside the call, which includes blocking and
    // descheduling: a busy fraction near 1 says the pump is the bottleneck
    // stage, and per-thread CPU (top -H) says whether it is CPU it spends.
    private val downlinkPackets = AtomicLong(0L)
    private val downlinkWrites = AtomicLong(0L)
    private val downlinkWriteNanos = AtomicLong(0L)
    private val downlinkWriteMaxNanos = AtomicLong(0L)
    private val uplinkPackets = AtomicLong(0L)
    private val uplinkWrites = AtomicLong(0L)
    private val uplinkWriteNanos = AtomicLong(0L)
    private val uplinkWriteMaxNanos = AtomicLong(0L)
    // Kernel thread ids of the two pumps, recorded by each pump as it starts,
    // so the census can read each thread's user and kernel CPU time. -1 until
    // the pump runs, and on a host without procfs.
    @Volatile private var downlinkThreadId = -1
    @Volatile private var uplinkThreadId = -1
    private val closeAcknowledged = CountDownLatch(1)
    private val startLock = Object()
    private val closeLock = Any()
    @Volatile private var startInProgress = false

    // The one thread that writes StatusRequest frames, and the single request
    // it may have outstanding. See [requestStatus].
    private val statusWriterLock = Object()
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
        val deadlineNs = System.nanoTime() + timeoutMs * 1_000_000L
        val before = synchronized(statusArrived) { statusSequence }
        requestStatus()

        synchronized(statusArrived) {
            while (statusSequence == before && running && !closed) {
                val remainingNs = deadlineNs - System.nanoTime()
                if (remainingNs <= 0L) break
                try {
                    statusArrived.wait(
                        remainingNs / 1_000_000L,
                        (remainingNs % 1_000_000L).toInt(),
                    )
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw e
                }
            }
            return lastStatusJson
        }
    }
    private val statusRequestPending = AtomicBoolean(false)
    private val statusWakeup = Semaphore(0)
    private var statusWriter: Thread? = null

    /**
     * Brings the v3 engine up. Returns once it has acknowledged the create
     * document and both packet pumps are running.
     *
     * Note the ordering difference from [WinnTunnelBridge.start]: there is no
     * "step 0" seam check, because the seam is a constructor argument and
     * therefore cannot be absent. The socket rule is unchanged and is still
     * step 1  :  open and protect here, before the child exists, so the engine is
     * never given the chance to open an unmarked socket of its own.
     */
    @Throws(IOException::class)
    fun start() {
        synchronized(startLock) {
            synchronized(closeLock) {
                check(!running && !closed) { "Winn v3 bridge already started" }
                startInProgress = true
            }
            try {

            val socket = try {
                host.openProtectedUnderlaySocket()
            } catch (e: Exception) {
                throw if (e is IOException) e else IOException("Winn v3 outer UDP socket failed", e)
            }
            underlay = socket
            if (!socket.protectedBeforeHandoff) {
                closeQuietly(socket)
                underlay = null
                throw IOException(
                    "Refusing to start the Winn v3 engine: the outer UDP socket was not " +
                        "protected before handoff. An unprotected socket routes back into this " +
                        "service's own tun and the tunnel dead-loops."
                )
            }
            host.onDebug(
                "Winn v3 outer UDP socket opened and protected on local port ${socket.localPort}."
            )

            var tcpChannelFailure: Exception? = null
            val tcpChannel = try {
                if (config.carrierClasses.contains("tcp")) host.openProtectedStreamChannel() else null
            } catch (e: Exception) {
                tcpChannelFailure = e
                null
            }
            if (config.carrierClasses.contains("tcp") && tcpChannel == null) {
                host.onWarning(
                    "Winn v3 protected TCP request channel unavailable; TCP fallback will refuse without a protected socket",
                    tcpChannelFailure,
                )
            }
            streamChannel = tcpChannel

            val process: WinnEngineProcess
            try {
                if (closed) throw IOException("Winn v3 bridge was closed during start")
                process = host.startEngineProcess()
            } catch (e: Exception) {
                closeQuietly(tcpChannel)
                streamChannel = null
                closeQuietly(socket)
                underlay = null
                throw IOException("Winn v3 engine subprocess did not start", e)
            }
            engine = process

            try {
                // close() publishes `closed` before it reads `engine`; this reads
                // `closed` after publishing `engine`, so a close that raced the
                // spawn is seen by at least one side.
                if (closed) throw IOException("Winn v3 bridge was closed during start")
                val transport = process.transport
                transport.setReadTimeoutMs(CREATE_ACK_TIMEOUT_MS)
                if (tcpChannel != null) {
                    transport.sendDescriptorChannel(socket.descriptor, tcpChannel.descriptor)
                } else {
                    transport.sendDescriptor(socket.descriptor)
                }
                transport.writeFrame(
                    WinnFraming.OP_CREATE,
                    config.toJson().toByteArray(Charsets.UTF_8),
                )
                awaitCreateAck(transport)
                transport.setReadTimeoutMs(0)
                if (closed) throw IOException("Winn v3 bridge was closed during start")

                val pumpsStarted = synchronized(closeLock) {
                    if (closed) throw IOException("Winn v3 bridge closed during start")
                    running = true
                    startPumps(transport)
                }
                pumpsStarted.await(2, TimeUnit.SECONDS)
                host.onDebug("Winn v3 engine created the datapath; packet pumps running (${process.describe()}).")
            } catch (e: Exception) {
                running = false
                closeQuietly(process)
                engine = null
                closeQuietly(socket)
                underlay = null
                closeQuietly(tcpChannel)
                streamChannel = null
                throw if (e is IOException) e else IOException("Winn v3 engine handshake failed", e)
            }
            } finally {
                startInProgress = false
            }
        }
    }

    private fun awaitCreateAck(transport: WinnEngineTransport) {
        val frame = transport.readFrame()
            ?: throw IOException("Winn v3 engine closed the channel before acknowledging the config")
        when (frame.opcode) {
            WinnFraming.OP_CREATE_ACK -> {
                publishStatus(frame.payloadAsText())
            }
            WinnFraming.OP_ERROR ->
                throw IOException("Winn v3 engine rejected the config: ${frame.payloadAsText().take(300)}")
            else ->
                throw IOException(
                    "Winn v3 engine sent ${WinnFraming.opcodeName(frame.opcode)} before create-ack"
                )
        }
    }

    private fun startPumps(transport: WinnEngineTransport): CountDownLatch {
        val started = CountDownLatch(2)

        outboundPump = Thread {
            downlinkThreadId = WinnV3ThreadStat.currentThreadId()
            started.countDown()
            try {
                val batchTransport = transport as? WinnV3BatchTransport
                val batch = if (batchTransport != null) WinnV3PacketBatch() else null
                while (running && !closed) {
                    if (batchTransport != null && batch != null) {
                        if (batchTransport.readBatch(batch) < 0) {
                            fail("Winn v3 engine closed the channel")
                            return@Thread
                        }
                        var index = 0
                        while (index < batch.count && running && !closed) {
                            val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
                            if (batch.opcode(index) == WinnFraming.OP_OUTBOUND && batchedSeam != null) {
                                var end = index + 1
                                while (end < batch.count && batch.opcode(end) == WinnFraming.OP_OUTBOUND) end++
                                val writeStarted = System.nanoTime()
                                val delivered = batchedSeam.writeIncomingBatch(batch, index, end)
                                notePumpWrite(
                                    downlinkPackets, downlinkWrites, downlinkWriteNanos,
                                    downlinkWriteMaxNanos, delivered, System.nanoTime() - writeStarted,
                                )
                                index = end
                            } else {
                                if (!handleEngineFrame(batch.opcode(index), batch.bytes,
                                        batch.offset(index), batch.length(index))) return@Thread
                                index++
                            }
                        }
                    } else {
                        val frame = transport.readFrame() ?: run {
                            fail("Winn v3 engine closed the channel")
                            return@Thread
                        }
                        if (!handleEngineFrame(frame.opcode, frame.payload, 0, frame.payload.size)) return@Thread
                    }
                }
            } catch (e: Exception) {
                // Gate on !closed (not running): the outbound pump's EOF path
                // may already have stopped the bridge, but a typed errno thrown
                // here is still real network-unreachability evidence and must
                // not be discarded.
                if (!closed) {
                    fail("Winn v3 outbound pump stopped: ${e.javaClass.simpleName}", e)
                }
            } finally {
                closeAcknowledged.countDown()
            }
        }.apply {
            name = "Calc-WinnV3-Outbound"
            // The tun reader asks the kernel for THREAD_PRIORITY_URGENT_AUDIO,
            // and until now both pumps ran at the inherited default. On a
            // heterogeneous SoC that lets the scheduler park a pump on a little
            // core and preempt it on every handoff, which shows up as the
            // packet rate the handoff can sustain rather than as a stall.
            // Measured on a Samsung Galaxy S26 Ultra to the Canada gateway:
            // 600 to 711 Mbps down and 21.5 to 255 Mbps up, against 1742.7 and
            // 1652.9 Mbps raw. Thread.MAX_PRIORITY rather than
            // android.os.Process.setThreadPriority, because this file is
            // deliberately free of Android imports so it runs under a plain-JVM
            // unit test.
            priority = Thread.MAX_PRIORITY
            isDaemon = true
            start()
        }

        inboundPump = Thread {
            uplinkThreadId = WinnV3ThreadStat.currentThreadId()
            started.countDown()
            val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
            val batchTransport = transport as? WinnV3BatchTransport
            // Uplink geometry only. 512 * (1373 MTU + 16 header) = 711,168 B,
            // so the 1 MiB byte cap is not binding at full MTU and
            // packetCapacity is the operative limit. Downlink keeps the frozen
            // 256 / 512 KiB defaults.
            val batch = WinnV3PacketBatch(
                packetCapacity = 512,
                byteCapacity = 1024 * 1024,
            )
            val buffer = if (batchedSeam == null) ByteArray(bufferSizeFor(config.innerMtu)) else null
            try {
                while (running && !closed) {
                    val n = if (batchedSeam != null) {
                        batchedSeam.readOutgoingBatch(batch)
                    } else {
                        batch.clear()
                        val length = seam.readOutgoingPacket(buffer!!)
                        if (length > buffer.size) throw IOException("Winn tun seam overreported packet length")
                        if (length > 0) batch.append(WinnFraming.OP_INBOUND, buffer, 0, length)
                        length
                    }
                    if (n < 0) {
                        if (running && !closed) fail("Winn v3 tun seam ended")
                        return@Thread
                    }
                    if (n == 0 || !running || closed) continue
                    if (batchedSeam != null) {
                        batchedSeam.writeOutgoingBatchIfCurrent(batch) {
                            if (running && !closed) writeUplinkBatch(transport, batchTransport, batch)
                        }
                    } else {
                        writeUplinkBatch(transport, batchTransport, batch)
                    }
                }
            } catch (e: Exception) {
                // Gate on !closed (not running): a typed errno from this pump is
                // still genuine unreachability evidence even if the outbound
                // pump stopped the bridge first.
                if (!closed) {
                    fail("Winn v3 inbound pump stopped: ${e.javaClass.simpleName}", e)
                }
            }
        }.apply {
            name = "Calc-WinnV3-Inbound"
            // Same reason as the outbound pump above, and this is the thread
            // the uplink burst drain hands its batches to, so a preemption here
            // undoes the fix the tun reader just paid for.
            priority = Thread.MAX_PRIORITY
            isDaemon = true
            start()
        }

        return started
    }

    /**
     * The uplink channel write, timed and counted only when it actually ran:
     * a batch the seam refused as stale, or one skipped because the bridge was
     * closing, never reaches here, and a write that throws is not counted.
     */
    private fun writeUplinkBatch(
        transport: WinnEngineTransport,
        batchTransport: WinnV3BatchTransport?,
        batch: WinnV3PacketBatch,
    ) {
        val writeStarted = System.nanoTime()
        writePacketBatch(transport, batchTransport, batch)
        notePumpWrite(
            uplinkPackets, uplinkWrites, uplinkWriteNanos,
            uplinkWriteMaxNanos, batch.count, System.nanoTime() - writeStarted,
        )
    }

    /** One pump write into the census. Single writer per counter set. */
    private fun notePumpWrite(
        packets: AtomicLong,
        writes: AtomicLong,
        nanos: AtomicLong,
        maxNanos: AtomicLong,
        count: Int,
        elapsedNanos: Long,
    ) {
        val elapsed = if (elapsedNanos > 0L) elapsedNanos else 0L
        packets.addAndGet(count.toLong())
        writes.incrementAndGet()
        nanos.addAndGet(elapsed)
        if (elapsed > maxNanos.get()) maxNanos.set(elapsed)
    }

    /** The pump census at this instant, with the seam's own counts when it keeps them. */
    fun pumpCensus(): WinnV3PumpCensus {
        val batchedSeam = seam as? WinnV3BatchedIpPacketSeam
        return WinnV3PumpCensus(
            downlinkPackets = downlinkPackets.get(),
            downlinkWrites = downlinkWrites.get(),
            downlinkWriteNanos = downlinkWriteNanos.get(),
            downlinkWriteMaxNanos = downlinkWriteMaxNanos.get(),
            uplinkPackets = uplinkPackets.get(),
            uplinkWrites = uplinkWrites.get(),
            uplinkWriteNanos = uplinkWriteNanos.get(),
            uplinkWriteMaxNanos = uplinkWriteMaxNanos.get(),
            nativeWritePackets = batchedSeam?.nativeWritePacketCount() ?: -1L,
            seamDrops = batchedSeam?.droppedCount() ?: -1L,
            downlinkThreadTicks = WinnV3ThreadStat.cpuTicks(downlinkThreadId),
            uplinkThreadTicks = WinnV3ThreadStat.cpuTicks(uplinkThreadId),
            readerThreadTicks = WinnV3ThreadStat.cpuTicks(
                (seam as? WinnV3AndroidIpPacketSeam)?.readerThreadId() ?: -1,
            ),
        )
    }

    private fun writePacketBatch(
        transport: WinnEngineTransport,
        batchTransport: WinnV3BatchTransport?,
        batch: WinnV3PacketBatch,
    ) {
        if (batchTransport != null) {
            batchTransport.writeBatch(batch)
        } else {
            // Compatibility for old transports and test doubles. The Android
            // stream adapter uses writeBatch and never takes this copying path.
            for (i in 0 until batch.count) {
                transport.writeFrame(WinnFraming.OP_INBOUND,
                    batch.bytes.copyOfRange(batch.offset(i), batch.offset(i) + batch.length(i)))
            }
        }
    }

    private fun handleEngineFrame(opcode: Int, payload: ByteArray, offset: Int, length: Int): Boolean {
        when (opcode) {
            WinnFraming.OP_OUTBOUND -> {
                if (offset == 0 && length == payload.size) seam.writeIncomingPacket(payload, length)
                else seam.writeIncomingPacket(payload.copyOfRange(offset, offset + length), length)
            }
            WinnFraming.OP_STATUS_RESPONSE, WinnFraming.OP_CREATE_ACK -> {
                publishStatus(String(payload, offset, length, Charsets.UTF_8))
            }
            WinnFraming.OP_CLOSE_ACK -> {
                closeAcknowledged.countDown()
                return false
            }
            WinnFraming.OP_ERROR -> {
                // The engine's text can name endpoints. It stays in the stored
                // reason, which reaches a log only as an exception message (and
                // describeThrowable prints messages in debug builds alone), and
                // never in the error line itself.
                fail(
                    "Winn v3 engine reported: ${String(payload, offset, length, Charsets.UTF_8).take(300)}",
                    logged = "Winn v3 engine reported an error",
                )
                return false
            }
            else -> {
                fail("Winn v3 engine sent an unhandled opcode: " + WinnFraming.opcodeName(opcode))
                return false
            }
        }
        return true
    }

    /**
     * Records the failure. The human string is diagnostics only;
     * ordinary-network authorization reads the typed OS errno on [cause] or
     * the protected-socket probe, never the class name or message text.
     *
     * Typed ordinary-network evidence is STICKY: a classified errno is kept
     * even when a generic (non-typed) pump failure was recorded first. Both
     * pumps can stop around the same instant -- the outbound `readFrame` EOF
     * path records a null-cause failure and flips [running] to false before
     * the inbound pump's typed errno arrives, and without this rule the real
     * ENETUNREACH/EHOSTUNREACH would be dropped and legitimate Winn v1 cover
     * refused. A null classification is never written, so a genuine typed
     * errno can never be clobbered by a generic stop.
     */
    private fun fail(reason: String, cause: Throwable? = null, logged: String = reason) {
        val classified = WinnV3OrdinaryNetworkEvidence.classifyThrowable(cause)
        if (classified != null) {
            recordedOrdinaryNetworkFailure = classified
            recordedOrdinaryNetworkPosixErrno = classified.posixErrno
        }
        if (failureReason == null) {
            failureReason = reason
            recordedFailureCause = cause
        }
        running = false
        synchronized(statusArrived) {
            statusArrived.notifyAll()
        }
        host.onError("Winn v3 tunnel failed: $logged", cause)
    }

    /**
     * `StatusRequest`. Fire-and-forget, and NEVER blocks the caller; the reply
     * lands on the outbound pump.
     *
     * The write happens on this bridge's own status writer thread, and at most
     * one request is outstanding: while a write is still in progress a further
     * call is coalesced into it and returns false at once. This matters because
     * the transport write has no timeout of its own and a packet writer can
     * hold the transport lock while a full socket buffer blocks it (see
     * [close]). A caller that wrote synchronously, like the health watchdog and
     * the post-promotion loop both did, would stall with the transport and take
     * every time-based check it makes (status staleness, the host recovery
     * ceiling) down with it. Now a wedged transport only freezes
     * [statusJson]: the callers keep running and judge that frozen document on
     * their own monotonic clock, and [isHealthy] goes stale on schedule.
     *
     * Returns true when a request was handed to the writer.
     */
    fun requestStatus(): Boolean {
        if (!running || closed) return false
        if (!statusRequestPending.compareAndSet(false, true)) return false
        if (!ensureStatusWriter()) {
            statusRequestPending.set(false)
            return false
        }
        statusWakeup.release()
        return true
    }

    private fun ensureStatusWriter(): Boolean {
        synchronized(statusWriterLock) {
            if (closed) return false
            if (statusWriter != null) return true
            statusWriter = Thread {
                try {
                    while (!closed) {
                        statusWakeup.acquire()
                        if (closed) break
                        try {
                            engine?.transport?.writeFrame(WinnFraming.OP_STATUS_REQUEST, ByteArray(0))
                        } catch (e: Exception) {
                            if (!closed) {
                                fail("Winn v3 status request could not be sent: ${e.javaClass.simpleName}", e)
                            }
                        } finally {
                            statusRequestPending.set(false)
                        }
                    }
                } catch (_: InterruptedException) {
                }
            }.apply {
                name = "Calc-WinnV3-Status"
                isDaemon = true
                start()
            }
            return true
        }
    }

    /**
     * The most recent status document the engine sent.
     *
     * This is what [WinnV3StagedStart]'s `readStatus` reads. It is deliberately
     * the LAST document rather than a fresh round trip: a synchronous
     * request/response here would have to block the caller on a channel the
     * outbound pump already owns. The staged start polls on an interval and
     * calls [requestStatus] each time, so a stale document costs one poll of
     * latency and never a missed promotion  :  and, importantly, an engine that
     * has stopped answering leaves this frozen at a document whose `rx_packets`
     * cannot advance, so the gate refuses rather than promoting on a stale
     * success.
     */
    fun statusJson(): String = lastStatusJson

    /**
     * Milliseconds since the last status document arrived, on this bridge's
     * clock (monotonic in production), or -1 when none has arrived. A perf
     * line carries it so a stale engine census is never read as a fresh one.
     */
    fun statusAgeMs(): Long {
        val last = lastStatusAtMs.get()
        if (last <= 0L) return -1L
        return maxOf(0L, clockMs() - last)
    }

    fun failure(): String? = failureReason

    fun failureCause(): Throwable? = recordedFailureCause

    fun ordinaryNetworkFailure(): WinnV3OrdinaryNetworkFailureClass? =
        mergedOrdinaryEvidence().failure

    fun ordinaryNetworkPosixErrno(): Int? = mergedOrdinaryEvidence().posixErrno

    /**
     * What [WinnV3StagedStart] polls. Typed OS network evidence travels with
     * the stopped-pump state so a class-name collapse cannot erase it. A live
     * bridge without a pump errno still reports a numeric errno captured at
     * the protected `Os.connect` boundary; [java.net.SocketException] text from
     * `DatagramChannelImpl.send0` never appears here as authorization.
     */
    fun snapshot(): WinnV3BridgeSnapshot {
        val merged = mergedOrdinaryEvidence()
        return WinnV3BridgeSnapshot(
            running = isRunning(),
            failure = failureReason,
            ordinaryNetworkFailure = merged.failure,
            ordinaryNetworkPosixErrno = merged.posixErrno,
            cause = recordedFailureCause ?: merged.cause,
        )
    }

    private data class MergedOrdinaryEvidence(
        val failure: WinnV3OrdinaryNetworkFailureClass?,
        val posixErrno: Int?,
        val cause: Throwable?,
    )

    private fun mergedOrdinaryEvidence(): MergedOrdinaryEvidence {
        val probed = probeProtectedSocketIfNeeded()
        val errno = recordedOrdinaryNetworkPosixErrno ?: probed.posixErrno
        val failure = recordedOrdinaryNetworkFailure
            ?: errno?.let { WinnV3OrdinaryNetworkFailureClass.fromPosixErrno(it) }
        return MergedOrdinaryEvidence(
            failure = failure,
            posixErrno = errno,
            cause = probed.cause,
        )
    }

    private fun probeProtectedSocketIfNeeded(): WinnV3ProtectedSocketErrno.Result {
        recordedOrdinaryNetworkFailure?.let { known ->
            return WinnV3ProtectedSocketErrno.Result(
                posixErrno = known.posixErrno,
                protected = true,
                closed = true,
            )
        }
        cachedProtectedSocketProbe?.let { return it }
        if (closed) {
            return cachedProtectedSocketProbe ?: WinnV3ProtectedSocketErrno.Result(closed = true)
        }
        val got = try {
            probeProtectedSocketErrno()
        } catch (_: Exception) {
            WinnV3ProtectedSocketErrno.Result(closed = true)
        }
        cachedProtectedSocketProbe = got
        return got
    }

    fun isHealthy(): Boolean {
        if (!running || closed) return false
        if (engine?.isAlive() != true) return false
        val last = lastStatusAtMs.get()
        if (last <= 0L) return false
        return clockMs() - last <= STATUS_STALE_MS
    }

    fun isRunning(): Boolean = running && !closed

    /** `Close`. Idempotent. */
    override fun close() {
        synchronized(closeLock) {
            if (closed) return
            closed = true
            running = false
        }
        synchronized(statusArrived) {
            statusArrived.notifyAll()
        }
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
        var closeWriter: Thread? = null
        if (process != null) {
            // A packet writer can be blocked by a full socket buffer while it
            // owns the transport lock. Bound the graceful request itself, then
            // close the channel to wake every blocked writer and reader.
            closeWriter = Thread {
                try {
                    process.transport.writeFrame(WinnFraming.OP_CLOSE, ByteArray(0))
                } catch (_: Exception) {
                }
            }.apply {
                name = "Calc-WinnV3-Close"
                isDaemon = true
                start()
            }
            try {
                closeAcknowledged.await(CLOSE_ACK_WAIT_MS, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        // Closing the channel unblocks the outbound pump; closing the seam
        // unblocks the inbound pump's read on the tun.
        closeQuietly(process)
        closeQuietly(seam)
        closeQuietly(underlay)
        closeQuietly(streamChannel)
        engine = null
        underlay = null
        streamChannel = null
        // Closing the channel above also wakes a status write parked on it.
        val writer = synchronized(statusWriterLock) { statusWriter.also { statusWriter = null } }
        statusWakeup.release()
        joinQuietly(writer)
        joinQuietly(closeWriter)
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
    fun closeCompleted(): Boolean =
        closeFinished.count == 0L && !closeIncomplete && !startInProgress

    /** [closeCompleted], waiting up to [timeoutMs] for a running close to finish. */
    fun awaitCloseCompleted(timeoutMs: Long): Boolean {
        val finished = try {
            closeFinished.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        return finished && !closeIncomplete && !startInProgress
    }

    /** This bridge's close, as something a teardown pass can await. */
    fun closeCompletion(): WinnV3Completion = WinnV3Completion { awaitCloseCompleted(it) }

    private fun closeQuietly(closeable: Closeable?) {
        try {
            closeable?.close()
        } catch (e: Exception) {
            closeIncomplete = true
            host.onWarning("Winn v3 resource close was incomplete", e)
        }
    }
}

/**
 * The bridge's pump census: packets, writes and time spent writing, per
 * direction. Downlink is engine to tun, uplink is tun to engine.
 */
internal data class WinnV3PumpCensus(
    val downlinkPackets: Long,
    val downlinkWrites: Long,
    val downlinkWriteNanos: Long,
    val downlinkWriteMaxNanos: Long,
    val uplinkPackets: Long,
    val uplinkWrites: Long,
    val uplinkWriteNanos: Long,
    val uplinkWriteMaxNanos: Long,
    /** Downlink packets the native tun writer delivered; -1 when not counted. */
    val nativeWritePackets: Long = -1L,
    /** Uplink packets the tun seam dropped because its queue was full; -1 when not counted. */
    val seamDrops: Long = -1L,
    // User and kernel CPU time of the downlink pump, the uplink pump and the
    // tun reader, in clock ticks; null where the thread or procfs is absent.
    val downlinkThreadTicks: WinnV3ThreadTicks? = null,
    val uplinkThreadTicks: WinnV3ThreadTicks? = null,
    val readerThreadTicks: WinnV3ThreadTicks? = null,
)

/**
 * One debug-build perf line: the pump census plus the engine's queue census
 * read out of the last status document. Counts only. The engine keys are a
 * fixed list and only plain integers are copied, so nothing the engine writes
 * can put free text into the line.
 *
 * mono_ns is a monotonic clock reading taken with the census, so busy
 * fractions are computed from differences between two lines, never from
 * logcat's wall-clock stamps. status_age_ms says how old the engine half is
 * (-1: no document yet); an engine key that is absent from a line whose
 * status is fresh is zero, because the engine omits zero census fields.
 * dl_native_pkts and ul_seam_drops come from the tun seam and are left out
 * when the seam does not count them (a negative census value).
 */
internal object WinnV3PerfLine {
    val ENGINE_KEYS = listOf(
        "rx_packets", "tx_packets", "messages_received", "messages_sent",
        "recv_batches", "send_batches", "host_queue_depth", "host_queue_high_water",
        "dropped_to_host", "host_write_batches", "host_write_packets", "host_write_ns",
        "host_write_max_ns", "engine_queue_depth", "engine_queue_high_water",
        "dropped_to_engine", "ring_pop_calls", "ring_pop_packets", "ring_wake_park",
        "send_queue_high_water", "tx_dropped_sink", "rx_dropped_closed",
        "tx_dropped_closed", "data_frames_dropped", "rekeys", "rekey_init_resends",
        "unopenable", "outer_reordered", "outer_lost", "send_queue_depth",
    )

    private val integerMember = Regex(""""([a-z_]+)"\s*:\s*(\d{1,20})""")

    fun format(
        census: WinnV3PumpCensus,
        statusJson: String,
        statusAgeMs: Long,
        monotonicNanos: Long,
    ): String {
        val engine = HashMap<String, String>()
        for (match in integerMember.findAll(statusJson.take(64 * 1024))) {
            val key = match.groupValues[1]
            if (key in ENGINE_KEYS && key !in engine) engine[key] = match.groupValues[2]
        }
        return buildString {
            append("datapath perf")
            append(" mono_ns=").append(monotonicNanos)
            append(" status_age_ms=").append(if (statusAgeMs < 0L) -1L else statusAgeMs)
            append(" dl_pkts=").append(census.downlinkPackets)
            append(" dl_writes=").append(census.downlinkWrites)
            append(" dl_write_ns=").append(census.downlinkWriteNanos)
            append(" dl_write_max_ns=").append(census.downlinkWriteMaxNanos)
            if (census.nativeWritePackets >= 0L) append(" dl_native_pkts=").append(census.nativeWritePackets)
            append(" ul_pkts=").append(census.uplinkPackets)
            append(" ul_writes=").append(census.uplinkWrites)
            append(" ul_write_ns=").append(census.uplinkWriteNanos)
            append(" ul_write_max_ns=").append(census.uplinkWriteMaxNanos)
            if (census.seamDrops >= 0L) append(" ul_seam_drops=").append(census.seamDrops)
            appendTicks("dl", census.downlinkThreadTicks)
            appendTicks("ul", census.uplinkThreadTicks)
            appendTicks("rd", census.readerThreadTicks)
            for (key in ENGINE_KEYS) {
                val value = engine[key] ?: continue
                append(' ').append(key).append('=').append(value)
            }
        }
    }

    private fun StringBuilder.appendTicks(prefix: String, ticks: WinnV3ThreadTicks?) {
        if (ticks == null) return
        append(' ').append(prefix).append("_utime_ticks=").append(ticks.user)
        append(' ').append(prefix).append("_stime_ticks=").append(ticks.kernel)
    }
}
