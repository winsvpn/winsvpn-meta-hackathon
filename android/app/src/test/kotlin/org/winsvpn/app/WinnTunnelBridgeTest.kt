package org.winsvpn.app

import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Drives the whole Android host side of the contract against
 * [WinnEngineDouble]. Nothing here needs the Go engine, a device, or the
 * Android framework.
 *
 * These tests cover the bridge's LOGIC. They deliberately cannot tell you the
 * wire format is right -- the double speaks whatever this host speaks. That
 * claim belongs to WinnEngineInteropTest and android/devicecheck/.
 */
class WinnTunnelBridgeTest {

    private val cleanups = mutableListOf<Closeable>()

    @After
    fun tearDown() {
        for (c in cleanups.reversed()) {
            try {
                c.close()
            } catch (_: Exception) {
            }
        }
    }

    // ---- fakes -----------------------------------------------------------

    private class FakeUnderlaySocket(
        override val protectedBeforeHandoff: Boolean,
    ) : WinnUnderlaySocket {
        override val descriptor: FileDescriptor = FileDescriptor()
        override val localPort: Int = 40404
        val closed = AtomicBoolean(false)
        override fun close() {
            closed.set(true)
        }
    }

    private class FakeEngineProcess(
        override val transport: WinnEngineTransport,
        private val alive: AtomicBoolean,
    ) : WinnEngineProcess {
        val closed = AtomicBoolean(false)
        override fun isAlive(): Boolean = alive.get()
        override fun describe(): String = "double"
        override fun close() {
            closed.set(true)
            alive.set(false)
            transport.close()
        }
    }

    private class FakeHost(
        private val underlay: FakeUnderlaySocket,
        private val seam: WinnAwgDatagramSeam?,
        private val engineFactory: (() -> FakeEngineProcess)?,
    ) : WinnEngineHost {
        /** Ordered log of the lifecycle events the ordering rules care about. */
        val lifecycle = CopyOnWriteArrayList<String>()
        val errors = CopyOnWriteArrayList<String>()
        val engineStarts = AtomicInteger(0)
        var lastEngine: FakeEngineProcess? = null

        override fun openProtectedUnderlaySocket(): WinnUnderlaySocket {
            lifecycle += "open+protect-udp-socket"
            return underlay
        }

        override fun startEngineProcess(): WinnEngineProcess {
            lifecycle += "spawn-engine"
            engineStarts.incrementAndGet()
            val factory = engineFactory ?: throw IOException("engine unavailable")
            val engine = factory()
            lastEngine = engine
            return engine
        }

        override fun openAwgDatagramSeam(): WinnAwgDatagramSeam? {
            lifecycle += "open-awg-datagram-seam"
            return seam
        }

        override fun onDebug(message: String) = Unit
        override fun onWarning(message: String, error: Throwable?) = Unit
        override fun onError(message: String, error: Throwable?) {
            errors += message
        }
    }

    private class Harness(
        val bridge: WinnTunnelBridge,
        val host: FakeHost,
        val underlay: FakeUnderlaySocket,
        val engineDouble: WinnEngineDouble,
        val transport: LoopbackWinnTransport,
        val seam: FakeAwgDatagramSeam,
        val alive: AtomicBoolean,
    )

    private fun harness(
        behaviour: WinnEngineDouble.Behaviour = WinnEngineDouble.Behaviour(),
        underlayProtected: Boolean = true,
        maxDatagram: Int = 1500,
        wrapTransport: (WinnEngineTransport) -> WinnEngineTransport = { it },
    ): Harness {
        val (hostSide, engineSide) = WinnEngineDouble.connectedPair()
        val double = WinnEngineDouble(engineSide, behaviour)
        double.start()
        val transport = LoopbackWinnTransport(hostSide)
        val alive = AtomicBoolean(true)
        val underlay = FakeUnderlaySocket(underlayProtected)
        val seam = FakeAwgDatagramSeam()
        val host = FakeHost(underlay, seam) {
            FakeEngineProcess(wrapTransport(transport), alive)
        }
        val bridge = WinnTunnelBridge(
            host = host,
            maxDatagram = maxDatagram,
            configJson = "{\"contract\":\"winn-datapath/1\",\"payload\":\"awg-datagram\"}",
        )
        cleanups += bridge
        cleanups += double
        cleanups += Closeable { closeQuietly(hostSide) }
        return Harness(bridge, host, underlay, double, transport, seam, alive)
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (_: Exception) {
        }
    }

    // ---- payload semantics ----------------------------------------------

    @Test
    fun withoutAnOuterDatagramSeamTheBridgeRefusesToStartAndAllocatesNothing() {
        // The honest state of the Android integration: the engine carries AWG
        // outer datagrams and this host has no source of them, so it must
        // refuse rather than relabel tun packets as datagrams.
        val underlay = FakeUnderlaySocket(protectedBeforeHandoff = true)
        val host = FakeHost(underlay, seam = null, engineFactory = null)
        val bridge = WinnTunnelBridge(host = host, maxDatagram = 1500, configJson = "{}")
        cleanups += bridge
        try {
            bridge.start()
            fail("expected the bridge to refuse to start without a datagram seam")
        } catch (e: IOException) {
            assertEquals(WinnTunnelBridge.NO_DATAGRAM_SEAM, e.message)
            assertTrue(e.message!!, e.message!!.contains("not raw IP packets"))
            assertTrue(e.message!!, e.message!!.contains("cleartext"))
        }
        // Nothing was opened and nothing was spawned.
        assertEquals(listOf("open-awg-datagram-seam"), host.lifecycle.toList())
        assertEquals(0, host.engineStarts.get())
        assertFalse(underlay.closed.get())
        assertFalse(bridge.isRunning())
    }

    // ---- the UDP socket rule --------------------------------------------

    @Test
    fun theOuterUdpSocketIsOpenedAndProtectedBeforeTheEngineProcessExists() {
        // This is the whole reason the Android side is shaped this way. If the
        // engine were spawned first it could open an unprotected socket of its
        // own, whose datagrams would match the tunnel routes, be written back
        // into our own tun, and loop forever.
        val h = harness()
        h.bridge.start()
        assertEquals(
            listOf("open-awg-datagram-seam", "open+protect-udp-socket", "spawn-engine"),
            h.host.lifecycle.toList(),
        )
    }

    @Test
    fun anUnprotectedSocketIsRefusedAndTheEngineIsNeverSpawned() {
        val h = harness(underlayProtected = false)
        try {
            h.bridge.start()
            fail("expected the bridge to refuse an unprotected socket")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("was not protected"))
            assertTrue(e.message, e.message!!.contains("dead-loop"))
        }
        assertEquals(0, h.host.engineStarts.get())
        assertTrue("the refused socket must be closed", h.underlay.closed.get())
        assertTrue("the seam must be released", h.seam.closeCount.get() >= 1)
        assertFalse(h.bridge.isRunning())
    }

    @Test
    fun theDescriptorIsHandedOverExactlyOnceAndBeforeAnyFrame() {
        // Ordering is the contract: the engine's -receive-fd path reads the
        // descriptor with a one-byte recvmsg BEFORE it reads a single frame.
        // Fusing it onto Create -- what this host used to do -- leaves the rest
        // of the frame queued and starts the engine's reader mid-header.
        val h = harness()
        h.bridge.start()
        assertEquals(1, h.transport.descriptorsHandedOver.size)
        assertTrue(h.transport.descriptorsHandedOver[0] === h.underlay.descriptor)
        assertEquals(
            "no frame may precede the descriptor",
            emptyList<Int>(),
            h.transport.framesBeforeDescriptor.toList(),
        )
    }

    // ---- handshake -------------------------------------------------------

    @Test
    fun createCarriesTheConfigAndTheEngineAcknowledgesWithCreateAck() {
        val h = harness()
        h.bridge.start()
        assertTrue(h.bridge.isRunning())
        // The double records what it actually received off the wire.
        val create = h.engineDouble.receivedCreatePayloads.firstOrNull()
        assertNotNull("engine never received Create", create)
        assertTrue(create!!, create.contains("awg-datagram"))
        assertTrue(h.bridge.statusJson().contains("winn-datapath/1"))
    }

    @Test
    fun anEngineThatRejectsTheConfigFailsTheStartAndReleasesEverything() {
        val h = harness(
            WinnEngineDouble.Behaviour(
                createReply = WinnFraming.OP_ERROR,
                createReplyPayload = "unsupported suite",
            )
        )
        try {
            h.bridge.start()
            fail("expected start() to fail")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("unsupported suite"))
        }
        assertFalse(h.bridge.isRunning())
        assertTrue("underlay socket leaked", h.underlay.closed.get())
        assertTrue("engine process leaked", h.host.lastEngine!!.closed.get())
        assertTrue("seam leaked", h.seam.closeCount.get() >= 1)
    }

    @Test
    fun aFrameBeforeCreateAckIsAProtocolErrorRatherThanBeingActedOn() {
        val h = harness(WinnEngineDouble.Behaviour(createReply = WinnFraming.OP_STATUS_RESPONSE))
        try {
            h.bridge.start()
            fail("expected start() to fail")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("before create-ack"))
        }
        assertFalse(h.bridge.isRunning())
    }

    // ---- datagram path ---------------------------------------------------

    @Test
    fun outerDatagramsFlowFromTheAwgSeamToTheEngineAndBack() {
        val h = harness()
        h.bridge.start()

        val datagram = ByteArray(120) { (it and 0xFF).toByte() }
        h.seam.injectFromAwgEngine(datagram)

        val returned = h.seam.awaitDeliveredToAwgEngine(5_000)
        assertNotNull("no datagram came back to the AWG engine", returned)
        assertArrayEquals(datagram, returned)
        assertEquals(1, h.engineDouble.receivedInbound.size)
        assertArrayEquals(datagram, h.engineDouble.receivedInbound[0])
    }

    @Test
    fun datagramBoundariesArePreservedOneDatagramPerFrame() {
        val h = harness()
        h.bridge.start()

        val datagrams = (1..25).map { size -> ByteArray(size * 7) { (size and 0xFF).toByte() } }
        datagrams.forEach { h.seam.injectFromAwgEngine(it) }

        val received = datagrams.indices.map {
            h.seam.awaitDeliveredToAwgEngine(5_000) ?: throw AssertionError("datagram $it never arrived")
        }
        for (i in datagrams.indices) {
            assertArrayEquals("datagram $i", datagrams[i], received[i])
        }
        assertEquals(datagrams.size, h.engineDouble.receivedInbound.size)
    }

    @Test
    fun aFullSizeDatagramSurvivesTheRoundTrip() {
        val h = harness(maxDatagram = 1500)
        val datagram = ByteArray(1500) { 0x5A }
        h.bridge.start()
        h.seam.injectFromAwgEngine(datagram)
        assertArrayEquals(datagram, h.seam.awaitDeliveredToAwgEngine(5_000))
    }

    // ---- status and health ----------------------------------------------

    @Test
    fun statusIsARoundTripNotAProcessExistenceCheck() {
        val h = harness()
        h.bridge.start()
        assertTrue(h.bridge.isHealthy())

        h.bridge.requestStatus()
        val deadline = System.currentTimeMillis() + 5_000
        while (h.engineDouble.statusRequests.get() == 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }
        assertEquals(1, h.engineDouble.statusRequests.get())

        val untilStatus = System.currentTimeMillis() + 5_000
        while (!h.bridge.statusJson().contains("\"state\":\"up\"") &&
            System.currentTimeMillis() < untilStatus
        ) {
            Thread.sleep(10)
        }
        assertTrue(h.bridge.statusJson(), h.bridge.statusJson().contains("\"state\":\"up\""))
        assertTrue(h.bridge.isHealthy())
    }

    @Test
    fun aLiveProcessThatStoppedAnsweringIsNotHealthy() {
        // Deliberately the opposite of "the process is in the process table,
        // therefore it works".
        val h = harness()
        h.bridge.start()
        assertTrue(h.bridge.isHealthy())

        val stale = WinnTunnelBridge(
            host = h.host,
            maxDatagram = 1500,
            configJson = "{}",
            // Every clock read is far past the staleness window.
            clockMs = { System.currentTimeMillis() + WinnTunnelBridge.STATUS_STALE_MS * 10 },
        )
        cleanups += stale
        // The process is alive; only the answer is stale.
        assertTrue(h.alive.get())
        assertFalse(stale.isHealthy())
    }

    @Test
    fun anEngineErrorMidSessionStopsTheTunnelAndIsReported() {
        val h = harness()
        h.bridge.start()
        assertTrue(h.bridge.isRunning())

        h.engineDouble.push(WinnFraming.OP_ERROR, "handshake lost".toByteArray())

        val deadline = System.currentTimeMillis() + 5_000
        while (h.bridge.isRunning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }
        assertFalse(h.bridge.isRunning())
        assertTrue(h.bridge.failure(), h.bridge.failure()!!.contains("handshake lost"))
        // The engine's text is the stored reason, never the logged line.
        assertTrue(h.host.errors.any { it.contains("Winn engine reported an error") })
        assertTrue(h.host.errors.none { it.contains("handshake lost") })
    }

    @Test
    fun aChannelDroppedMidSessionLeavesTheBridgeRefusingTheEngineNotReportingUp() {
        // Failure-path proof that a stale "up" document and a live process
        // table entry are NOT health. The drop lands after the session is
        // genuinely up AND carrying -- Create was acknowledged, the bridge is
        // running and healthy, and an outer datagram already made the round
        // trip -- so lastStatusJson holds a real "up" document and the double's
        // process still reports alive. The bridge must STILL refuse the tunnel
        // rather than keep answering as if it were up.
        //
        // closeChannelAfterFrames = 2 closes the channel right after the double
        // reflects the Inbound as an Outbound, i.e. after real mid-session
        // traffic, not during create.
        val h = harness(WinnEngineDouble.Behaviour(closeChannelAfterFrames = 2))
        h.bridge.start()

        // Prove it was genuinely up before the drop, so the drop below is
        // mid-session rather than a failed start.
        assertTrue(h.bridge.isRunning())
        assertTrue(h.bridge.isHealthy())
        assertTrue(h.bridge.statusJson(), h.bridge.statusJson().contains("\"up\":true"))

        // Carry one outer datagram; the double drops the channel as it echoes it.
        val datagram = ByteArray(120) { (it and 0xFF).toByte() }
        h.seam.injectFromAwgEngine(datagram)
        assertNotNull(
            "the drop must land after real traffic had flowed",
            h.seam.awaitDeliveredToAwgEngine(5_000),
        )

        val deadline = System.currentTimeMillis() + 5_000
        while (h.bridge.isRunning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }

        // The engine process still reports itself alive -- only the channel is
        // dead. That is exactly the lie this must refuse.
        assertTrue("the double's process still reports alive", h.host.lastEngine!!.isAlive())
        assertFalse(h.bridge.isRunning())
        assertFalse(h.bridge.isHealthy())
        assertNotNull(h.bridge.failure())
        assertFalse("a dead engine must never be reported healthy", h.bridge.isHealthy())
    }

    @Test
    fun anEngineThatDropsTheChannelStopsTheTunnel() {
        // closeChannelAfterFrames = 1 drops the channel right after Create is
        // answered, i.e. the first thing the pumps see is a clean EOF.
        val h = harness(WinnEngineDouble.Behaviour(closeChannelAfterFrames = 1))
        h.bridge.start()

        val deadline = System.currentTimeMillis() + 5_000
        while (h.bridge.isRunning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }
        assertFalse(h.bridge.isRunning())
        assertNotNull(h.bridge.failure())
        assertFalse(h.bridge.isHealthy())
    }

    @Test
    fun aMidSessionChannelDropRefusesTheEngineRatherThanReportingUp() {
        // Establish a genuinely healthy session with an "up" status the bridge
        // has heard, so the later refusal is a response to a dead channel and
        // not to a botched start.
        val h = harness()
        h.bridge.start()

        h.bridge.requestStatus()
        val upDeadline = System.currentTimeMillis() + 5_000
        while (!h.bridge.statusJson().contains("\"state\":\"up\"") &&
            System.currentTimeMillis() < upDeadline
        ) {
            Thread.sleep(10)
        }
        assertTrue(h.bridge.statusJson(), h.bridge.statusJson().contains("\"state\":\"up\""))
        assertTrue(h.bridge.isRunning())
        assertTrue(h.bridge.isHealthy())

        // Mid-session the engine's end of the channel goes away: the host reader
        // sees a clean EOF and must treat the engine as dead.
        h.engineDouble.close()

        val deadline = System.currentTimeMillis() + 5_000
        while (h.bridge.isRunning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }

        // The refusal is about the dead channel, not the process table: the fake
        // process would still claim isAlive()==true, and that must NOT let the
        // bridge keep reporting the tunnel as up.
        assertTrue("process table entry is still present", h.alive.get())
        assertFalse(h.bridge.isRunning())
        assertFalse("a dead engine must never read as healthy", h.bridge.isHealthy())
        val failure = h.bridge.failure()
        assertNotNull("a dead engine must be reported as a failure", failure)
        assertTrue(failure!!, failure.contains("closed the channel"))
    }

    @Test
    fun statusPublishedBeforeTheRequestWriteReturnsIsConsumed() {
        lateinit var h: Harness
        val reply = "{\"seq\":1}"
        h = harness(
            behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false),
            wrapTransport = { inner ->
                object : WinnEngineTransport by inner {
                    override fun writeFrame(opcode: Int, payload: ByteArray) {
                        inner.writeFrame(opcode, payload)
                        if (opcode == WinnFraming.OP_STATUS_REQUEST) {
                            h.engineDouble.push(WinnFraming.OP_STATUS_RESPONSE, reply.toByteArray())
                            awaitCondition { h.bridge.statusJson() == reply }
                        }
                    }
                }
            },
        )
        h.bridge.start()
        val began = System.nanoTime()
        assertEquals(reply, h.bridge.requestStatusAndAwait(1_000L))
        assertTrue((System.nanoTime() - began) / 1_000_000L < 750L)
    }

    @Test
    fun statusPublishedAfterTheWaitBeginsIsConsumed() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        val replies = CopyOnWriteArrayList<String>()
        val errors = CopyOnWriteArrayList<Throwable>()
        val waiter = statusWaiter(h.bridge, replies, errors)
        awaitCondition { waiter.state == Thread.State.TIMED_WAITING }
        h.engineDouble.push(WinnFraming.OP_STATUS_RESPONSE, "{\"seq\":2}".toByteArray())
        waiter.join(750L)
        assertFalse(waiter.isAlive)
        assertTrue(errors.isEmpty())
        assertEquals(listOf("{\"seq\":2}"), replies.toList())
    }

    @Test
    fun anEarlierOutstandingRequestMaySupplyTheNewStatus() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        h.bridge.requestStatus()
        awaitCondition { h.engineDouble.statusRequests.get() == 1 }
        val replies = CopyOnWriteArrayList<String>()
        val errors = CopyOnWriteArrayList<Throwable>()
        val waiter = statusWaiter(h.bridge, replies, errors)
        awaitCondition {
            h.engineDouble.statusRequests.get() == 2 && waiter.state == Thread.State.TIMED_WAITING
        }
        h.engineDouble.push(WinnFraming.OP_STATUS_RESPONSE, "{\"seq\":\"earlier\"}".toByteArray())
        waiter.join(750L)
        assertFalse(waiter.isAlive)
        assertTrue(errors.isEmpty())
        assertEquals(listOf("{\"seq\":\"earlier\"}"), replies.toList())
    }

    @Test
    fun statusWithoutAReplyReturnsTheCacheAtTheTimeout() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        val cached = h.bridge.statusJson()
        val began = System.nanoTime()
        assertEquals(cached, h.bridge.requestStatusAndAwait(100L))
        val elapsed = (System.nanoTime() - began) / 1_000_000L
        assertTrue("elapsed=$elapsed", elapsed >= 80L && elapsed < 750L)
    }

    @Test
    fun eofAndCloseWakeAnAlreadyWaitingStatusReader() {
        for (eof in listOf(true, false)) {
            val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
            h.bridge.start()
            val cached = h.bridge.statusJson()
            val replies = CopyOnWriteArrayList<String>()
            val errors = CopyOnWriteArrayList<Throwable>()
            val waiter = statusWaiter(h.bridge, replies, errors)
            awaitCondition { waiter.state == Thread.State.TIMED_WAITING }
            val stopped = java.util.concurrent.CountDownLatch(1)
            val terminator = Thread {
                try {
                    if (eof) h.engineDouble.close() else h.bridge.close()
                } finally {
                    stopped.countDown()
                }
            }.apply { isDaemon = true; start() }
            try {
                waiter.join(500L)
                assertFalse("terminal state did not wake the waiter", waiter.isAlive)
                assertTrue(errors.isEmpty())
                assertEquals(listOf(cached), replies.toList())
                assertFalse(h.bridge.isRunning())
            } finally {
                assertTrue(stopped.await(3L, java.util.concurrent.TimeUnit.SECONDS))
                terminator.join(1_000L)
            }
        }
    }

    @Test
    fun interruptionPropagatesFromTheStatusWait() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        val replies = CopyOnWriteArrayList<String>()
        val errors = CopyOnWriteArrayList<Throwable>()
        val waiter = statusWaiter(h.bridge, replies, errors)
        awaitCondition { waiter.state == Thread.State.TIMED_WAITING }
        waiter.interrupt()
        waiter.join(750L)
        assertFalse(waiter.isAlive)
        assertTrue(replies.isEmpty())
        assertEquals(1, errors.size)
        assertTrue(errors.single() is InterruptedException)
    }

    private fun statusWaiter(
        bridge: WinnTunnelBridge,
        replies: MutableList<String>,
        errors: MutableList<Throwable>,
    ): Thread {
        val waiter = Thread {
            try {
                replies += bridge.requestStatusAndAwait(1_000L)
            } catch (error: Throwable) {
                errors += error
            }
        }.apply { isDaemon = true; start() }
        cleanups += Closeable { waiter.interrupt(); waiter.join(1_500L) }
        return waiter
    }

    private fun awaitCondition(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 1_000_000_000L
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(1L)
        assertTrue("condition did not become true", condition())
    }

    // ---- shutdown --------------------------------------------------------

    @Test
    fun closeSendsCloseAndReleasesTheSeamAndTheSocket() {
        val h = harness()
        h.bridge.start()
        h.bridge.close()

        val deadline = System.currentTimeMillis() + 5_000
        while (!h.engineDouble.sawClose.get() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }
        assertTrue("engine never saw Close", h.engineDouble.sawClose.get())
        assertTrue("seam not released", h.seam.closeCount.get() >= 1)
        assertTrue("underlay socket not released", h.underlay.closed.get())
        assertTrue("engine process not stopped", h.host.lastEngine!!.closed.get())
        assertFalse(h.bridge.isRunning())
    }

    @Test
    fun closeIsIdempotent() {
        val h = harness()
        h.bridge.start()
        h.bridge.close()
        h.bridge.close()
        h.bridge.close()
        assertEquals(1, h.seam.closeCount.get())
    }

    @Test
    fun startingTwiceIsRefused() {
        val h = harness()
        h.bridge.start()
        try {
            h.bridge.start()
            fail("expected a second start() to be refused")
        } catch (_: IllegalStateException) {
        }
        assertEquals(1, h.host.engineStarts.get())
    }

    @Test
    fun aSpawnFailureReleasesTheAlreadyProtectedSocket() {
        val underlay = FakeUnderlaySocket(protectedBeforeHandoff = true)
        val seam = FakeAwgDatagramSeam()
        val host = FakeHost(underlay, seam, engineFactory = null)
        val bridge = WinnTunnelBridge(host = host, maxDatagram = 1500, configJson = "{}")
        cleanups += bridge
        try {
            bridge.start()
            fail("expected start() to fail")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("did not start"))
        }
        assertTrue("underlay socket leaked after a failed spawn", underlay.closed.get())
        assertTrue("seam leaked after a failed spawn", seam.closeCount.get() >= 1)
        assertFalse(bridge.isRunning())
    }
}
