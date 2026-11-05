package org.winsvpn.app

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The [WinnAwgDatagramSeam] for Android: a loopback UDP relay that the
 * AmneziaWG engine's peer endpoint is pointed at.
 *
 * ## The arrangement
 *
 *     apps -> tun -> [AmneziaWG engine, GoBackend.awgTurnOn]
 *                       Endpoint = 127.0.0.1:<localPort>
 *                          |  outer AWG datagrams over loopback
 *                          v
 *                    [THIS SEAM]  <- readOutgoingDatagram / writeIncomingDatagram
 *                          |
 *                    [WinnTunnelBridge] -- WNN3 Inbound/Outbound frames
 *                          |
 *                    [winn-datapath subprocess]
 *                          |  the ONE protected socket, handed over by SCM_RIGHTS
 *                          v
 *                       gateway
 *
 * The bytes crossing this class are therefore exactly what
 * [WinnAwgDatagramSeam] requires: AmneziaWG OUTER datagrams, produced and
 * consumed by the app's own AWG engine. No cleartext tun packet is ever seen
 * here, because the AWG engine has already encapsulated everything before it
 * reaches loopback.
 *
 * ## Burst backpressure: why there is a thread and a ring in here
 *
 * See `docs/handoff/WINN_SEAM_BURST_BACKPRESSURE_20260805.md`, and
 * `apple/EngineWrappers/WinsWinnPacketEngine.m`, the reference implementation.
 *
 * [WinnTunnelBridge]'s inbound pump used to be the only thing touching this
 * socket, and it ran `readOutgoingDatagram()` and `transport.writeFrame()` on
 * ONE thread. `writeFrame` writes into the engine's `LocalSocket` and BLOCKS
 * whenever the engine is slower than the AWG engine is fast -- which is genuine
 * downstream backpressure, correctly applied. But while it blocked, NOTHING was
 * draining this socket, and everything AmneziaWG sent during that window was
 * discarded by the kernel on the receive queue, upstream of every counter in
 * the system. On Linux the identical defect lost 26.51% of a 4 MiB burst with
 * the kernel's own RcvbufErrors moving by exactly the number missing.
 *
 * THERE IS NO TRUE BACKPRESSURE AVAILABLE AT THIS SEAM, and saying so is better
 * than shipping something named backpressure that is not. The producer is the
 * app's own AmneziaWG engine sending to its configured peer endpoint over UDP.
 * On loopback UDP a send COMPLETES SUCCESSFULLY even when the receiver's queue
 * is full; the kernel accepts the datagram and discards it at delivery. No
 * socket option makes that sender block.
 *
 * So instead: a thread in here does nothing but `receive()`, and hands each
 * datagram to a bounded ring. [readOutgoingDatagram] pops from that ring. The
 * bridge's pump is UNCHANGED and still blocks in `writeFrame` -- it just no
 * longer blocks the drain while it does. When the ring fills, the datagram is
 * dropped BY US, with an exact count and a log line, rather than by the kernel
 * where Android exposes no per-socket drop statistic at all.
 *
 * ## Why this does not need `VpnService.protect()`, and why that is a feature
 *
 * The [WinnUnderlaySocket] KDoc records the dead-loop rule: a socket the tunnel
 * does not bypass has its datagrams matched by the tunnel's own routes, written
 * back into this service's tun, re-encapsulated and re-emitted forever.
 *
 * This socket cannot enter that loop, and not because it was marked. It is
 * BOUND TO THE LOOPBACK ADDRESS and only ever talks to the loopback address.
 * Android's routing rules put `from all lookup local` ahead of every VPN rule,
 * so 127.0.0.0/8 is resolved by the local table before any tunnel rule is
 * consulted; loopback traffic never enters a tun. The exclusion is structural
 * rather than administrative: a socket bound to 127.0.0.1 cannot send to an
 * off-device address at all, so this seam has no reachable path to the network
 * even if every routing rule were wrong.
 *
 * That is the whole point of this design. The ONLY socket in the Winn data path
 * that touches the network remains the single outer UDP socket that
 * [WinnEngineHost.openProtectedUnderlaySocket] opens, protects, and hands to the
 * engine as a descriptor. There is no second unprotected network socket to
 * dead-loop, which is precisely the failure the alternative -- letting the
 * engine or the AWG backend open its own -- would have risked.
 *
 * Contrast the stealth-Xray transport, which points the same AWG peer endpoint
 * at a loopback port (`lib/main.dart`, `_buildRawAmneziaConfig`) but whose
 * relay is an external subprocess whose OUTER sockets cannot be protected from
 * Kotlin, and which therefore still needs `addDisallowedApplication` to exclude
 * the whole app UID. Winn needs no such coarse exclusion: its outer socket is
 * individually protected before the engine ever exists.
 *
 * ## Peer pinning
 *
 * Only the AWG engine may use this relay. The first sender is pinned and every
 * later datagram must come from the same address and port; anything else is
 * dropped. This mirrors `RelayLocalUDP`'s `ExpectedLocalPeer` in
 * `winn_protocol_experimental/internal/carrier/relay.go`, which is the Linux
 * implementation of this same arrangement, and it stops any other process on
 * the device from injecting datagrams into the tunnel or from harvesting the
 * gateway's replies.
 *
 * ## Roaming
 *
 * Pointing a WireGuard peer at loopback would be unsound if the engine then
 * rebound that peer to whatever address answered. It does not: Android's
 * `awgTurnOn` calls `DisableSomeRoamingForBrokenMobileSemantics()` immediately
 * after `IpcSet`, which sets `peer.endpoint.disableRoaming` for every peer that
 * has a configured endpoint, and the receive path honours it. The peer endpoint
 * therefore stays pinned to this seam for the life of the tunnel. That call is
 * unconditional and already applies to every tunnel this app starts today.
 *
 * ## MTU
 *
 * Nothing here changes the MTU. AmneziaWG's MTU is a configured value
 * (`MTU = ...` in the `[Interface]` section, and the same number is given to
 * `VpnService.Builder.setMtu`), not a path measurement, and neither the AWG
 * engine nor this relay performs path-MTU discovery on the outer socket. A
 * loopback path with a 65536-byte device MTU therefore produces exactly the
 * same outer datagram sizes as a physical path would. What bounds a datagram
 * here is the engine's `max_datagram`, which [WinnTunnelBridge] sizes the read
 * buffer from.
 */
internal class WinnAwgLoopbackSeam private constructor(
    private val socket: DatagramSocket,
    /** The port the AmneziaWG peer `Endpoint` must be pointed at. */
    val localPort: Int,
    private val maxDatagram: Int,
    /** The AmneziaWG engine's reserved ListenPort; 0 learns the first loopback sender. */
    private val expectedPeerPort: Int,
    private val onDropped: (String) -> Unit,
    private val onSessionEnd: (lossy: Boolean, summary: String) -> Unit,
) : WinnAwgDatagramSeam {

    companion object {
        /**
         * Ring slots between the drainer and [readOutgoingDatagram]. Derived on
         * Apple from measured rates and then verified there and on Linux, not
         * chosen to make a test pass: it is the smallest power of two with real
         * margin at the 4 MiB burst of record. Raising it does NOT remove loss
         * under sustained overload -- no finite buffer absorbs an unbounded
         * deficit -- which is why the regression test asserts accounting rather
         * than zero loss.
         *
         * THE MEMORY COST IS REAL AND IS NOT HIDDEN: 2048 * (maxDatagram + 1),
         * about 3.1 MB at a 1500-byte ceiling. That is the first number to
         * revisit if this service ever measures close to its memory ceiling.
         */
        const val RING_SLOTS = 2048

        /** Default datagram ceiling when a caller does not name one. */
        const val DEFAULT_MAX_DATAGRAM = 1500

        /**
         * Requested `SO_RCVBUF`. A shock absorber for the gap between a burst
         * arriving and the drainer being scheduled. IT IS NOT THE FIX -- a
         * bigger buffer only moves the cliff -- which is exactly why the GRANTED
         * value is read back and reported next to a backlog high-water mark, so
         * anyone can see whether the buffer is even the mechanism.
         */
        const val RECEIVE_BUFFER_BYTES = 2 * 1024 * 1024

        /** At most one drop line per second; a burst would otherwise flood. */
        const val DROP_LOG_INTERVAL_MS = 1000L
        /**
         * Builds the AmneziaWG peer endpoint string for a seam listening on
         * [port]. Kept here, next to the socket that binds it, so the address
         * the engine is told to use and the address this relay actually listens
         * on can never drift apart.
         */
        fun peerEndpoint(port: Int): String = "127.0.0.1:$port"

        /**
         * Rewrites the AmneziaWG `[Peer]` endpoint to point at a seam on
         * [port], returning the new configuration.
         *
         * THIS IS FAIL-CLOSED ON PURPOSE. If the rewrite quietly did nothing --
         * because the section moved, the key was spelled differently, or the
         * config carried no endpoint -- the AmneziaWG engine would keep talking
         * straight to the gateway from its own socket while the rest of the
         * service believed Winn was carrying the traffic. That failure is
         * invisible in every log and produces either a tunnel that silently
         * bypasses Winn or, if that socket is not protected, the dead loop
         * [WinnUnderlaySocket] describes. So anything other than exactly one
         * rewritten endpoint throws.
         *
         * @throws IOException if the configuration does not contain exactly one
         *   peer endpoint to redirect.
         */
        @Throws(IOException::class)
        fun redirectPeerEndpoint(awgConfig: String, port: Int, awgListenPort: Int = 0): String {
            val lines = awgConfig.split("\n")
            var rewritten = 0
            var listenPortWritten = false
            val out = ArrayList<String>(lines.size + 1)
            for (line in lines) {
                val separator = line.indexOf('=')
                val key = if (separator > 0) line.substring(0, separator).trim() else ""
                if (key.equals("Endpoint", ignoreCase = true)) {
                    rewritten++
                    out.add("Endpoint = ${peerEndpoint(port)}")
                } else if (awgListenPort > 0 && key.equals("ListenPort", ignoreCase = true)) {
                    continue
                } else {
                    out.add(line)
                    if (awgListenPort > 0 && !listenPortWritten &&
                        line.trim().equals("[Interface]", ignoreCase = true)
                    ) {
                        out.add("ListenPort = $awgListenPort")
                        listenPortWritten = true
                    }
                }
            }
            if (rewritten != 1) {
                throw IOException(
                    "Refusing to start Winn: the AmneziaWG configuration has $rewritten peer " +
                        "endpoints, and exactly one is required so it can be redirected to the " +
                        "Winn outer-datagram seam. Leaving it pointed at the gateway would send " +
                        "AmneziaWG traffic straight out of the AmneziaWG engine's own socket, " +
                        "bypassing the Winn engine entirely."
                )
            }
            if (awgListenPort > 0 && !listenPortWritten) {
                throw IOException(
                    "Refusing to start Winn: no [Interface] section to pin the AmneziaWG " +
                        "ListenPort in, so the seam could not tell the engine from another " +
                        "local sender."
                )
            }
            return out.joinToString("\n")
        }

        /**
         * A free UDP port for the AmneziaWG engine's own ListenPort, chosen by
         * the host so the seam can pin its peer before the engine sends anything.
         */
        @Throws(IOException::class)
        fun reserveAwgListenPort(): Int = DatagramSocket(0).use { it.localPort }

        /**
         * Opens the relay on an ephemeral loopback port and starts its drainer.
         *
         * @param maxDatagram the engine's datagram ceiling. Sizes the ring
         *   slots, and anything larger is dropped rather than truncated.
         * @param onDropped called with a reason whenever a datagram is
         *   discarded. Never given datagram contents.
         * @param onSessionEnd called EXACTLY ONCE at close with a one-line
         *   summary, and with [lossy] set when this session lost anything. A
         *   lossless session and a lossy one produced byte-for-byte identical
         *   output before this existed, which is how a 26-34% loss passed for a
         *   successful run on two platforms.
         */
        @Throws(IOException::class)
        fun open(
            maxDatagram: Int = DEFAULT_MAX_DATAGRAM,
            expectedPeerPort: Int = 0,
            onDropped: (String) -> Unit = {},
            onSessionEnd: (lossy: Boolean, summary: String) -> Unit = { _, _ -> },
        ): WinnAwgLoopbackSeam {
            // Bound to the loopback address, not the wildcard. This is the
            // structural containment described in the class KDoc: the socket
            // has no route off the device.
            val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            return try {
                // Best effort, and the GRANTED value is what gets reported.
                try {
                    socket.receiveBufferSize = RECEIVE_BUFFER_BYTES
                } catch (_: SocketException) {
                    // An inherited default is worse than this, but it still works.
                }
                val ceiling = if (maxDatagram > 0) maxDatagram else DEFAULT_MAX_DATAGRAM
                WinnAwgLoopbackSeam(
                    socket, socket.localPort, ceiling, expectedPeerPort, onDropped, onSessionEnd,
                ).also { it.startDrainer() }
            } catch (e: Exception) {
                socket.close()
                throw if (e is IOException) e else IOException("Winn AWG loopback seam failed", e)
            }
        }
    }

    /**
     * The AWG engine's own source address, learned from its first datagram and
     * fixed thereafter. Writes go back to exactly this address, which is also
     * what stops the seam from ever replying to an unrelated local process.
     */
    @Volatile private var awgPeer: InetSocketAddress? = null

    @Volatile private var closed = false

    /** Set when the drainer died under a seam nobody closed; the pump then gets -1. */
    @Volatile private var drainerFailed = false

    /** Datagrams accepted from the AWG engine. Diagnostics only. */
    @Volatile var outgoingCount: Long = 0L
        private set

    /** Datagrams delivered back into the AWG engine. Diagnostics only. */
    @Volatile var incomingCount: Long = 0L
        private set

    // ---- the ring between the drainer and the bridge's pump ---------------
    //
    // Single producer (the drainer), single consumer (the bridge's inbound
    // pump). Strictly FIFO, tail-drop only, so datagram ORDER is unchanged: a
    // reordering seam would turn a rate defect into an authentication failure
    // at the gateway. Storage is preallocated, so a datagram crossing this
    // class costs ONE array copy and NO allocation -- the old path allocated a
    // DatagramPacket per receive and the pump then allocated a copy per frame.

    /** One byte larger than the ceiling, so oversize is DETECTED not truncated. */
    private val slotBytes = maxDatagram + 1
    private val ringStorage = ByteArray(RING_SLOTS * slotBytes)
    private val ringLengths = IntArray(RING_SLOTS)
    private val ringLock = ReentrantLock()
    private val ringNotEmpty = ringLock.newCondition()
    private var ringHead = 0
    private var ringQueued = 0

    // ---- counters. Every one of these is an integer this class counted -----
    // itself: no endpoint, no session id, no datagram byte. Safe to log in full.

    private val rxDatagrams = AtomicLong(0)
    private val rxBytes = AtomicLong(0)
    private val rxRingDropped = AtomicLong(0)
    private val rxForeignSender = AtomicLong(0)
    private val rxOversize = AtomicLong(0)
    private val txSendFailed = AtomicLong(0)
    private val txNoPeer = AtomicLong(0)
    private val ringHighWater = AtomicLong(0)
    private val lastDropLogMs = AtomicLong(0)

    /** The `SO_RCVBUF` the kernel actually granted, not the one requested. */
    private val grantedReceiveBuffer: Int = try {
        socket.receiveBufferSize
    } catch (_: SocketException) {
        -1
    }

    @Volatile private var drainer: Thread? = null

    /**
     * The drain thread. IT MUST NEVER BLOCK ON ANYTHING BUT `receive()`.
     *
     * Every statement in the loop is a socket read, a bounded array copy, or a
     * counter. The blocking `writeFrame` that used to share this thread is now
     * the bridge pump's job, on the far side of the ring. If a future change
     * puts anything here that can wait on the engine, the defect this exists to
     * remove comes straight back -- and `WinnAwgLoopbackSeamBurstTest` says so.
     */
    private fun startDrainer() {
        drainer = Thread {
            val scratch = ByteArray(slotBytes)
            val packet = DatagramPacket(scratch, scratch.size)
            while (!closed) {
                // MUST be reset: DatagramPacket.receive sets the length to what
                // arrived, and a shorter next datagram would otherwise be capped
                // by the previous one's length.
                packet.setData(scratch, 0, scratch.size)
                try {
                    socket.receive(packet)
                } catch (e: SocketException) {
                    // close() closes the socket to unblock this. Anything else is
                    // a socket that failed under a live seam: wake the pump with -1
                    // so the bridge fails the session instead of idling while the
                    // tunnel still reports connected.
                    if (!closed) {
                        onDropped("seam socket failed: ${e.javaClass.simpleName}")
                        ringLock.withLock {
                            drainerFailed = true
                            ringNotEmpty.signalAll()
                        }
                    }
                    return@Thread
                } catch (e: IOException) {
                    if (closed) return@Thread
                    continue
                }

                rxDatagrams.incrementAndGet()
                rxBytes.addAndGet(packet.length.toLong())

                val sender = InetSocketAddress(packet.address, packet.port)
                val pinned = awgPeer
                if (pinned == null) {
                    if (!packet.address.isLoopbackAddress ||
                        (expectedPeerPort > 0 && packet.port != expectedPeerPort)
                    ) {
                        // Only the AmneziaWG engine's reserved ListenPort may claim
                        // the pin; any local app can send from loopback.
                        rxForeignSender.incrementAndGet()
                        reportDrainerDropIfDue(
                            "first sender was not the AmneziaWG engine's reserved port",
                        )
                        continue
                    }
                    awgPeer = sender
                } else if (pinned != sender) {
                    rxForeignSender.incrementAndGet()
                    reportDrainerDropIfDue("datagram from an unexpected local sender")
                    continue
                }

                if (packet.length > maxDatagram) {
                    rxOversize.incrementAndGet()
                    reportDrainerDropIfDue(
                        "datagram of ${packet.length} bytes exceeds the engine's max_datagram",
                    )
                    continue
                }

                if (!push(scratch, packet.length)) {
                    // THE DROP WE OWN. This is the datagram that used to be
                    // discarded by the kernel on the receive queue, where
                    // Android exposes no per-socket statistic and it could not
                    // be counted, attributed, or logged by anyone.
                    rxRingDropped.incrementAndGet()
                    logDropIfDue()
                }
            }
        }.apply {
            name = "Calc-Winn-SeamDrain"
            isDaemon = true
            start()
        }
    }

    /** Tail-drop enqueue. False when the ring was full. */
    private fun push(data: ByteArray, length: Int): Boolean = ringLock.withLock {
        if (closed) return false
        if (ringQueued >= RING_SLOTS) return false
        val slot = (ringHead + ringQueued) % RING_SLOTS
        System.arraycopy(data, 0, ringStorage, slot * slotBytes, length)
        ringLengths[slot] = length
        ringQueued++
        if (ringQueued > ringHighWater.get()) ringHighWater.set(ringQueued.toLong())
        ringNotEmpty.signal()
        true
    }

    private fun logDropIfDue() {
        val now = System.currentTimeMillis()
        val previous = lastDropLogMs.get()
        if (now - previous < DROP_LOG_INTERVAL_MS) return
        if (!lastDropLogMs.compareAndSet(previous, now)) return
        onDropped(
            "winn seam dropping outbound datagrams: ring_dropped=${rxRingDropped.get()} " +
                "received=${rxDatagrams.get()} delivered=$outgoingCount " +
                "ring_high_water=${ringHighWater.get()} rcvbuf=$grantedReceiveBuffer",
        )
    }


    private val lastDrainerReportMs = AtomicLong(0)

    /**
     * Foreign and oversize drops, at most one line per interval. Every one is
     * still counted; only the log line is limited, so a local sender cannot
     * make this thread log at line rate.
     */
    private fun reportDrainerDropIfDue(reason: String) {
        val now = System.currentTimeMillis()
        val previous = lastDrainerReportMs.get()
        if (now - previous < DROP_LOG_INTERVAL_MS) return
        if (!lastDrainerReportMs.compareAndSet(previous, now)) return
        onDropped(reason)
    }

    /**
     * Pops the next datagram. Blocks until one is queued or the seam closes.
     *
     * This no longer touches the socket at all, which is the entire point: the
     * caller may take as long as it likes over the frame write that follows,
     * and the drainer keeps emptying the receive queue throughout.
     */
    override fun readOutgoingDatagram(buffer: ByteArray): Int {
        ringLock.withLock {
            while (true) {
                while (ringQueued == 0 && !closed && !drainerFailed) ringNotEmpty.await()
                if (ringQueued == 0) return -1
                val slot = ringHead
                val length = ringLengths[slot]
                ringHead = (ringHead + 1) % RING_SLOTS
                ringQueued--
                if (length > buffer.size) {
                    // The caller's buffer is smaller than the ceiling this seam
                    // was opened with. Dropped, never truncated -- a truncated
                    // AWG datagram would fail authentication at the gateway and
                    // look like a network fault instead of a configuration one.
                    //
                    // SAME REASON AND SAME WORDING as the drainer's own ceiling
                    // check: [WinnTunnelBridge] sizes this buffer FROM the
                    // engine's max_datagram, so from the caller's side these are
                    // one condition, and reporting them as two would make an
                    // operator hunt for a second defect that does not exist.
                    rxOversize.incrementAndGet()
                    onDropped("datagram of $length bytes exceeds the engine's max_datagram")
                    continue
                }
                System.arraycopy(ringStorage, slot * slotBytes, buffer, 0, length)
                outgoingCount++
                return length
            }
            @Suppress("UNREACHABLE_CODE")
            return -1
        }
    }

    /**
     * The seam's own counters as JSON.
     *
     * NOT the engine's counters and not a substitute for them: the engine's
     * `tx_rejected`/`rx_dropped` count what the ENGINE REFUSED, and they were
     * zero throughout a 26% loss event because nothing ever reached the engine
     * to be refused. These count what the HOST saw at the seam.
     */
    fun seamStatsJson(): String = ringLock.withLock {
        "{\"seam_rx_datagrams\":${rxDatagrams.get()}" +
            ",\"seam_rx_bytes\":${rxBytes.get()}" +
            ",\"seam_rx_ring_dropped\":${rxRingDropped.get()}" +
            ",\"seam_rx_foreign_sender\":${rxForeignSender.get()}" +
            ",\"seam_rx_oversize\":${rxOversize.get()}" +
            ",\"seam_tx_delivered\":$outgoingCount" +
            ",\"seam_awg_sent\":$incomingCount" +
            ",\"seam_awg_send_failed\":${txSendFailed.get()}" +
            ",\"seam_awg_no_peer\":${txNoPeer.get()}" +
            ",\"seam_ring_slots\":$RING_SLOTS" +
            ",\"seam_ring_queued\":$ringQueued" +
            ",\"seam_ring_high_water\":${ringHighWater.get()}" +
            ",\"seam_rcvbuf_bytes\":$grantedReceiveBuffer}"
    }

    /** Reused by the bridge's single outbound pump; never shared between threads. */
    private val incomingPacket = DatagramPacket(ByteArray(0), 0)

    override fun writeIncomingDatagram(datagram: ByteArray, length: Int) =
        writeIncomingDatagram(datagram, 0, length)

    override fun writeIncomingDatagram(datagram: ByteArray, offset: Int, length: Int) {
        if (closed) return
        val destination = awgPeer ?: run {
            // The gateway answered before the AWG engine ever spoke. There is
            // no address to deliver to, and guessing one would mean writing
            // gateway traffic to an arbitrary local port. Counted.
            txNoPeer.incrementAndGet()
            onDropped("inbound datagram arrived before the AWG engine sent anything")
            return
        }
        try {
            incomingPacket.setData(datagram, offset, length)
            incomingPacket.socketAddress = destination
            socket.send(incomingPacket)
            incomingCount++
        } catch (e: IOException) {
            // KNOWN LIMIT, NOT CLAIMED AS FIXED: the AmneziaWG engine owns the
            // RECEIVING socket on this leg. If it is not draining, the kernel
            // discards on delivery and this send still reports success.
            txSendFailed.incrementAndGet()
            if (!closed) onDropped("loopback write failed: ${e.javaClass.simpleName}")
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        // Unblocks the drainer, which is parked in receive().
        socket.close()
        // ...and the pump, which may be parked waiting on the ring.
        ringLock.withLock { ringNotEmpty.signalAll() }
        drainer?.join(500)
        drainer = null

        // ONE LINE PER SESSION, ALWAYS, and a DIFFERENT one when something was
        // lost. This is the property whose absence let a 26-34% loss pass for a
        // successful run: a lossless session and a lossy session produced
        // identical output before, and they no longer do.
        val dropped = rxRingDropped.get()
        val lossy = dropped + rxOversize.get() + rxForeignSender.get() +
            txSendFailed.get() > 0
        val summary = if (lossy) {
            "winn seam closed WITH LOSS: received=${rxDatagrams.get()} " +
                "delivered=$outgoingCount ring_dropped=$dropped " +
                "oversize=${rxOversize.get()} foreign_sender=${rxForeignSender.get()} " +
                "send_failed=${txSendFailed.get()} no_peer=${txNoPeer.get()} " +
                "ring_high_water=${ringHighWater.get()} rcvbuf=$grantedReceiveBuffer"
        } else {
            "winn seam closed clean: received=${rxDatagrams.get()} " +
                "delivered=$outgoingCount ring_high_water=${ringHighWater.get()} " +
                "rcvbuf=$grantedReceiveBuffer"
        }
        onSessionEnd(lossy, summary)
    }

    fun describeForLog(): String =
        "winn awg loopback seam: port=$localPort peer=${awgPeer?.port ?: -1} " +
            "outgoing=$outgoingCount incoming=$incomingCount " +
            "ring_dropped=${rxRingDropped.get()} ring_high_water=${ringHighWater.get()} " +
            "rcvbuf=$grantedReceiveBuffer"
}
