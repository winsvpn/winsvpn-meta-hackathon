package org.winsvpn.app

import java.io.Closeable
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pump failures must preserve typed OS network evidence. Collapsing the
 * throwable to a class-name string and stopped-state is what previously
 * blocked generation-bound Winn v1 AWG then Xray cover.
 */
class WinnV3BridgeTest {

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

    @Test
    fun `inbound pump typed ENETUNREACH authorizes ordinary cover`() {
        val error = TypedErrnoFailure(101, "ENETUNREACH: network is unreachable")
        val h = harness(inboundError = error)
        h.bridge.start()
        val snapshot = awaitFailedSnapshot(h.bridge)
        assertEquals(WinnV3OrdinaryNetworkFailureClass.NETWORK_UNREACHABLE, snapshot.ordinaryNetworkFailure)
        assertEquals(101, snapshot.ordinaryNetworkPosixErrno)
        assertTrue(snapshot.cause === error)
        assertFalse(snapshot.running)
        assertTrue(snapshot.failure!!.contains("inbound pump stopped"))
        assertAuthorizedOrdinary(snapshot)
    }

    @Test
    fun `outbound pump typed EHOSTUNREACH authorizes ordinary cover`() {
        val error = TypedErrnoFailure(113, "EHOSTUNREACH: host is unreachable")
        val h = harness(outboundError = error)
        h.bridge.start()
        val snapshot = awaitFailedSnapshot(h.bridge)
        if (snapshot.ordinaryNetworkFailure == null) {
            System.err.println("DIAG outbound-ehost: ${debugSnapshot(snapshot)}")
            var c: Throwable? = snapshot.cause
            while (c != null) {
                System.err.println(
                    "DIAG chain: ${c.javaClass.name} errnoField=" +
                        (try { c.javaClass.getField("errno").get(c) } catch (t: Throwable) { "no:${t.javaClass.simpleName}" }),
                )
                c = c.cause
            }
            System.err.println(
                "DIAG classify=" + WinnV3OrdinaryNetworkEvidence.classifyThrowable(snapshot.cause),
            )
        }
        assertEquals("snap=" + debugSnapshot(snapshot), WinnV3OrdinaryNetworkFailureClass.HOST_UNREACHABLE, snapshot.ordinaryNetworkFailure)
        assertEquals(113, snapshot.ordinaryNetworkPosixErrno)
        assertTrue(snapshot.cause === error)
        assertFalse(snapshot.running)
        assertTrue(snapshot.failure!!.contains("outbound pump stopped"))
        assertAuthorizedOrdinary(snapshot)
    }

    @Test
    fun `all four Android Linux errnos authorize from a stopped inbound pump`() {
        for (failure in WinnV3OrdinaryNetworkFailureClass.entries) {
            val error = TypedErrnoFailure(failure.posixErrno, "ignored ENETUNREACH text")
            val h = harness(inboundError = error)
            h.bridge.start()
            val snapshot = awaitFailedSnapshot(h.bridge)
            if (snapshot.ordinaryNetworkFailure == null) {
                System.err.println("DIAG inbound-all: ${debugSnapshot(snapshot)}")
            }
            assertEquals(failure.name + " snap=" + debugSnapshot(snapshot), failure, snapshot.ordinaryNetworkFailure)
            assertEquals(failure.name, failure.posixErrno, snapshot.ordinaryNetworkPosixErrno)
            assertAuthorizedOrdinary(snapshot, failure.name)
            h.bridge.close()
        }
    }

    @Test
    fun `class-name pump collapse without typed errno remains unknown`() {
        val error = IOException("ENETUNREACH: network is unreachable")
        val h = harness(inboundError = error)
        h.bridge.start()
        val snapshot = awaitFailedSnapshot(h.bridge)
        assertNull(snapshot.ordinaryNetworkFailure)
        assertNull(snapshot.ordinaryNetworkPosixErrno)
        assertTrue(snapshot.cause === error)
        assertUnknown(snapshot)
    }

    @Test
    fun `timeout pump failure remains unknown`() {
        val error = SocketTimeoutException("timed out")
        val h = harness(outboundError = error)
        h.bridge.start()
        val snapshot = awaitFailedSnapshot(h.bridge)
        assertNull(snapshot.ordinaryNetworkFailure)
        assertUnknown(snapshot)
    }

    @Test
    fun `Darwin ENETUNREACH on a pump remains unknown`() {
        val error = TypedErrnoFailure(51, "ENETUNREACH: network is unreachable")
        val h = harness(inboundError = error)
        h.bridge.start()
        val snapshot = awaitFailedSnapshot(h.bridge)
        assertNull(snapshot.ordinaryNetworkFailure)
        assertEquals(51, error.errno)
        assertUnknown(snapshot)
    }

    @Test
    fun `engine OP_ERROR text that spells ENETUNREACH remains unknown`() {
        val h = harness()
        h.bridge.start()
        h.engineDouble.push(
            WinnFraming.OP_ERROR,
            "ENETUNREACH: network is unreachable".toByteArray(),
        )
        val snapshot = awaitFailedSnapshot(h.bridge)
        assertNull(snapshot.ordinaryNetworkFailure)
        assertNull(snapshot.ordinaryNetworkPosixErrno)
        assertTrue(snapshot.failure!!.contains("ENETUNREACH"))
        assertUnknown(snapshot)
        // The engine's text is the stored reason, never the logged line.
        assertTrue(h.host.errors.any { it.contains("Winn v3 engine reported an error") })
        assertTrue(h.host.errors.none { it.contains("ENETUNREACH") })
    }

    @Test
    fun `production capture of a typed send errno reaches the classifier`() {
        val live = mutableSetOf<Int>()
        val sent = java.util.concurrent.atomic.AtomicInteger(0)
        val h = harness(
            probe = {
                WinnV3ProtectedSocketErrno.capture(
                    open = {
                        live.add(7)
                        7
                    },
                    protect = { true },
                    send = {
                        sent.incrementAndGet()
                        throw object : IOException("sendto failed: Network is unreachable") {
                            @JvmField val errno: Int = 101
                        }
                    },
                    close = { live.remove(it) },
                )
            },
        )
        h.bridge.start()
        val snapshot = h.bridge.snapshot()
        assertTrue(snapshot.running)
        assertTrue(live.isEmpty())
        assertEquals(1, sent.get())
        assertEquals(101, snapshot.ordinaryNetworkPosixErrno)
        assertEquals(
            WinnV3OrdinaryNetworkFailureClass.NETWORK_UNREACHABLE,
            snapshot.ordinaryNetworkFailure,
        )
        assertAuthorizedOrdinary(snapshot)
    }

    @Test
    fun `protection failure refuses and still closes the descriptor`() {
        val live = mutableSetOf<Int>()
        val sent = java.util.concurrent.atomic.AtomicInteger(0)
        val h = harness(
            probe = {
                WinnV3ProtectedSocketErrno.capture(
                    open = {
                        live.add(3)
                        3
                    },
                    protect = { false },
                    send = {
                        sent.incrementAndGet()
                        throw object : IOException("ENETUNREACH") {
                            @JvmField val errno: Int = 101
                        }
                    },
                    close = { live.remove(it) },
                )
            },
        )
        h.bridge.start()
        val snapshot = h.bridge.snapshot()
        assertTrue(live.isEmpty())
        assertEquals(0, sent.get())
        assertNull(snapshot.ordinaryNetworkPosixErrno)
        assertNull(snapshot.ordinaryNetworkFailure)
        assertUnknown(snapshot)
    }

    @Test
    fun `protect exception refuses without consuming a send errno`() {
        val live = mutableSetOf<Int>()
        val h = harness(
            probe = {
                WinnV3ProtectedSocketErrno.capture(
                    open = {
                        live.add(9)
                        9
                    },
                    protect = { throw IOException("protect failed: errno 101 ENETUNREACH") },
                    send = {
                        throw object : IOException("should not send") {
                            @JvmField val errno: Int = 101
                        }
                    },
                    close = { live.remove(it) },
                )
            },
        )
        h.bridge.start()
        val snapshot = h.bridge.snapshot()
        assertTrue(live.isEmpty())
        assertNull(snapshot.ordinaryNetworkPosixErrno)
        assertUnknown(snapshot)
    }

    @Test
    fun `SocketException prose from DatagramChannel send0 never authorizes`() {
        val closed = AtomicBoolean(false)
        val h = harness(
            probe = {
                WinnV3ProtectedSocketErrno.capture(
                    open = { 1 },
                    protect = { true },
                    send = {
                        throw java.net.SocketException(
                            "sendto failed: ENETUNREACH (Network is unreachable)",
                        )
                    },
                    close = { closed.set(true) },
                )
            },
        )
        h.bridge.start()
        val snapshot = h.bridge.snapshot()
        assertTrue(closed.get())
        assertNull(snapshot.ordinaryNetworkPosixErrno)
        assertUnknown(snapshot)
    }

    @Test
    fun `synthetic ErrnoException class name and message never authorize`() {
        class ErrnoException(message: String) : IOException(message)
        val closed = AtomicBoolean(false)
        val h = harness(
            probe = {
                WinnV3ProtectedSocketErrno.capture(
                    open = { 1 },
                    protect = { true },
                    send = { throw ErrnoException("errno 101 ENETUNREACH") },
                    close = { closed.set(true) },
                )
            },
        )
        h.bridge.start()
        val snapshot = h.bridge.snapshot()
        assertTrue(closed.get())
        assertNull(snapshot.ordinaryNetworkPosixErrno)
        assertUnknown(snapshot)
    }

    @Test
    fun `Darwin and ECONNREFUSED probe errnos remain unknown`() {
        for (code in listOf(51, 111)) {
            val closed = AtomicBoolean(false)
            val h = harness(
                probe = {
                    WinnV3ProtectedSocketErrno.capture(
                        open = { 1 },
                        protect = { true },
                        send = {
                            throw object : IOException("ENETUNREACH") {
                                @JvmField val errno: Int = code
                            }
                        },
                        close = { closed.set(true) },
                    )
                },
            )
            h.bridge.start()
            val snapshot = h.bridge.snapshot()
            assertTrue("errno $code", closed.get())
            assertEquals("errno $code", code, snapshot.ordinaryNetworkPosixErrno)
            assertNull("errno $code", snapshot.ordinaryNetworkFailure)
            assertUnknown(snapshot)
            h.bridge.close()
        }
    }

    @Test
    fun `probeProtectedSocketErrno is invoked at most once and cached across status snapshots`() {
        val probeCount = java.util.concurrent.atomic.AtomicInteger(0)
        val h = harness(
            probe = {
                probeCount.incrementAndGet()
                WinnV3ProtectedSocketErrno.Result(posixErrno = null, protected = true, closed = true)
            },
        )
        h.bridge.start()
        for (i in 1..10) {
            val snapshot = h.bridge.snapshot()
            assertNull(snapshot.ordinaryNetworkPosixErrno)
            assertNull(snapshot.ordinaryNetworkFailure)
        }
        assertEquals(1, probeCount.get())
        h.bridge.close()
    }

    @Test
    fun `pump failure sites pass the throwable into fail instead of collapsing it`() {
        val source = readBridgeSource()
        assertTrue(source.contains("fail(\"Winn v3 outbound pump stopped: \${e.javaClass.simpleName}\", e)"))
        assertTrue(source.contains("fail(\"Winn v3 inbound pump stopped: \${e.javaClass.simpleName}\", e)"))
        assertTrue(source.contains("WinnV3OrdinaryNetworkEvidence.classifyThrowable(cause)"))
        assertTrue(source.contains("fun snapshot(): WinnV3BridgeSnapshot"))
        assertTrue(source.contains("probeProtectedSocketErrno"))
        assertTrue(source.contains("WinnV3ProtectedSocketErrno"))
        assertFalse(source.contains("if (running && !closed) fail(\"Winn v3 outbound pump stopped:"))
        assertFalse(source.contains("if (running && !closed) fail(\"Winn v3 inbound pump stopped:"))
        assertFalse(source.contains("DatagramChannel.open"))
        assertFalse(source.contains("import java.nio.channels"))
        assertFalse(source.contains(".message!!.contains"))
    }

    private fun assertAuthorizedOrdinary(
        snapshot: WinnV3BridgeSnapshot,
        label: String = "snapshot",
    ) {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            bridgeFailure = snapshot.failure,
            bridgeRunning = snapshot.running,
            cause = snapshot.cause,
            ordinaryNetworkPosixErrno = snapshot.ordinaryNetworkPosixErrno,
            ordinaryNetworkFailure = snapshot.ordinaryNetworkFailure,
        )
        assertEquals(label, WinnV3NativeVerdict.ORDINARY_CONNECTIVITY, got)
        assertEquals(label, 41L, got.awgXrayAuthorizationToken(41L))
        assertFalse(label, got.securityRefusal)
    }

    private fun assertUnknown(snapshot: WinnV3BridgeSnapshot) {
        val got = WinnV3NativeVerdictClassifier.fromEvidence(
            bridgeFailure = snapshot.failure,
            bridgeRunning = snapshot.running,
            error = snapshot.failure,
            cause = snapshot.cause,
            ordinaryNetworkPosixErrno = snapshot.ordinaryNetworkPosixErrno,
            ordinaryNetworkFailure = snapshot.ordinaryNetworkFailure,
        )
        assertEquals(WinnV3NativeVerdict.UNKNOWN_TERMINAL, got)
        assertEquals(-1L, got.awgXrayAuthorizationToken(41L))
    }

    private fun awaitFailedSnapshot(bridge: WinnV3Bridge): WinnV3BridgeSnapshot {
        // The failed pumps run on their own threads, so the stopped state is
        // reached asynchronously. Return only once a snapshot has SETTLED (the
        // same stopped state observed twice in a row) so a torn read -- the
        // failure text visible one poll before the typed errno it travels with
        // -- is never captured as if it were the terminal state. The final
        // assertion still requires the errno, so settling cannot turn a real
        // errno loss into a pass; it only waits out a transient.
        val deadline = System.currentTimeMillis() + 5_000
        var previous: WinnV3BridgeSnapshot? = null
        while (System.currentTimeMillis() < deadline) {
            val snapshot = bridge.snapshot()
            val stopped = !snapshot.running && !snapshot.failure.isNullOrBlank()
            if (stopped && snapshot == previous) return snapshot
            previous = if (stopped) snapshot else null
            Thread.sleep(10)
        }
        throw AssertionError("bridge never recorded a settled pump failure: ${bridge.snapshot()}")
    }

    private fun debugSnapshot(s: WinnV3BridgeSnapshot): String =
        "running=${s.running} failure=${s.failure} errno=${s.ordinaryNetworkPosixErrno} " +
            "nf=${s.ordinaryNetworkFailure} cause=${s.cause?.javaClass?.simpleName}"

    private class TypedErrnoFailure(
        @JvmField val errno: Int,
        message: String,
    ) : IOException(message)

    private class FakeUnderlaySocket : WinnUnderlaySocket {
        override val protectedBeforeHandoff: Boolean = true
        override val descriptor: FileDescriptor = FileDescriptor()
        override val localPort: Int = 40404
        override fun close() = Unit
    }

    private class FakeEngineProcess(
        override val transport: WinnEngineTransport,
        private val alive: AtomicBoolean,
    ) : WinnEngineProcess {
        override fun isAlive(): Boolean = alive.get()
        override fun describe(): String = "double"
        override fun close() {
            alive.set(false)
            transport.close()
        }
    }

    private class FakeHost(
        private val underlay: FakeUnderlaySocket,
        private val engineFactory: () -> FakeEngineProcess,
    ) : WinnEngineHost {
        val errors = CopyOnWriteArrayList<String>()
        override fun openProtectedUnderlaySocket(): WinnUnderlaySocket = underlay
        override fun startEngineProcess(): WinnEngineProcess = engineFactory()
        override fun openAwgDatagramSeam(): WinnAwgDatagramSeam? = null
        override fun onDebug(message: String) = Unit
        override fun onWarning(message: String, error: Throwable?) = Unit
        override fun onError(message: String, error: Throwable?) {
            errors += message
        }
    }

    private class BlockingSeam : WinnV3IpPacketSeam {
        private val gate = CountDownLatch(1)
        override fun readOutgoingPacket(buffer: ByteArray): Int {
            gate.await()
            return -1
        }
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() {
            gate.countDown()
        }
    }

    /** A seam whose close fails after releasing its reader (Round L). */
    private class CloseThrowingSeam : WinnV3IpPacketSeam {
        private val inner = BlockingSeam()
        override fun readOutgoingPacket(buffer: ByteArray): Int = inner.readOutgoingPacket(buffer)
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() {
            inner.close()
            throw IOException("seam close failed")
        }
    }

    // Round L (OI-L4): the bridge's own confirmation that close() finished,
    // which the release acknowledgement rests on.
    @Test
    fun `a clean close is confirmed and nothing is confirmed before close`() {
        val h = harness()
        h.bridge.start()
        assertFalse(h.bridge.closeCompleted())
        h.bridge.close()
        assertTrue(h.bridge.closeCompleted())
    }

    @Test
    fun `a close whose seam close throws is not confirmed`() {
        val h = harness(seamOverride = CloseThrowingSeam())
        h.bridge.start()
        h.bridge.close()
        assertFalse(h.bridge.closeCompleted())
    }

    /** A seam whose close is held open until [release], then fails or not. */
    private class GatedCloseSeam(private val fail: Boolean) : WinnV3IpPacketSeam {
        private val inner = BlockingSeam()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        override fun readOutgoingPacket(buffer: ByteArray): Int = inner.readOutgoingPacket(buffer)
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() {
            inner.close()
            entered.countDown()
            release.await(10, java.util.concurrent.TimeUnit.SECONDS)
            if (fail) throw IOException("seam close failed late")
        }
    }

    private fun concurrentCloses(fail: Boolean): Pair<Harness, GatedCloseSeam> {
        val seam = GatedCloseSeam(fail)
        val h = harness(seamOverride = seam)
        h.bridge.start()
        // The first close (the engine thread's, say) is held open inside it.
        Thread { h.bridge.close() }.apply { isDaemon = true; start() }
        assertTrue(seam.entered.await(10, java.util.concurrent.TimeUnit.SECONDS))
        // A concurrent close (a teardown pass's) returns at once...
        h.bridge.close()
        // ...and must not read as finished while the first is still running.
        assertFalse(h.bridge.closeCompleted())
        assertFalse(h.bridge.awaitCloseCompleted(100L))
        assertFalse(h.bridge.closeCompletion().await(100L))
        return h to seam
    }

    @Test
    fun `a concurrent close held open and then failed is never reported complete`() {
        val (h, seam) = concurrentCloses(fail = true)
        seam.release.countDown()
        assertFalse(h.bridge.awaitCloseCompleted(8_000L))
        assertFalse(h.bridge.closeCompleted())
    }

    @Test
    fun `a concurrent close held open and then finished cleanly is reported complete once it ends`() {
        val (h, seam) = concurrentCloses(fail = false)
        seam.release.countDown()
        assertTrue(h.bridge.awaitCloseCompleted(8_000L))
    }

    @Test
    fun `a holding pass and a later release pass over a concurrent close that then fails`() {
        // The real bridge's completion, through the runner the service uses,
        // across the initial (holding) pass and the subsequent release pass.
        val (h, seam) = concurrentCloses(fail = true)
        val debt = WinnV3CleanupDebt()
        val retirement = WinnV3EngineRetirement()
        fun runner(bridges: () -> List<WinnV3Completion>) = WinnV3ReleaseTeardown(
            stopFallbackTransport = { true },
            stopWinnEngines = bridges,
            stopVpnEngine = {},
            engineRetired = { retirement.awaitCompleted(200L) },
            debt = debt,
            warn = { _, _ -> },
            bridgeCloseWaitMs = 100L,
        )
        val holding = runner {
            h.bridge.close()
            listOf(h.bridge.closeCompletion())
        }
        holding.stopEngines()
        assertEquals(
            WinnV3ReleaseLedger.Disposition.WINN3_HOLD,
            holding.disposition(winn3HoldKept = true, blockKept = true, interfacesClosed = false),
        )

        // The first close fails; the engine thread records its retirement
        // from the awaited completion, as VpnTunnelService's finally does.
        seam.release.countDown()
        retirement.finish(h.bridge.awaitCloseCompleted(8_000L))

        // The release pass finds the bridge reference already cleared.
        val release = runner { emptyList() }
        release.stopEngines()
        assertEquals(
            WinnV3ReleaseLedger.Disposition.INCOMPLETE,
            release.disposition(winn3HoldKept = false, blockKept = false, interfacesClosed = true),
        )
    }

    private class ThrowingSeam(private val error: Throwable) : WinnV3IpPacketSeam {
        override fun readOutgoingPacket(buffer: ByteArray): Int = throw error
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() = Unit
    }

    private class PumpThrowTransport(
        private val inner: WinnEngineTransport,
        private val error: Throwable,
    ) : WinnEngineTransport {
        private val reads = AtomicInteger(0)
        override fun writeFrame(opcode: Int, payload: ByteArray) = inner.writeFrame(opcode, payload)
        override fun sendDescriptor(fd: FileDescriptor) = inner.sendDescriptor(fd)
        override fun readFrame(): WinnFrame? {
            val n = reads.incrementAndGet()
            if (n > 1) throw error
            return inner.readFrame()
        }
        override fun setReadTimeoutMs(timeoutMs: Int) = inner.setReadTimeoutMs(timeoutMs)
        override fun close() = inner.close()
    }

    @Test
    fun `close during spawn returns before late process cleanup finishes`() {
        val spawning = CountDownLatch(1)
        val releaseSpawn = CountDownLatch(1)
        val cleaning = CountDownLatch(1)
        val releaseCleanup = CountDownLatch(1)
        val failures = CopyOnWriteArrayList<Throwable>()
        val h = harness(
            beforeSpawn = {
                spawning.countDown()
                assertTrue(releaseSpawn.await(5, java.util.concurrent.TimeUnit.SECONDS))
            },
            wrapTransport = { inner ->
                object : WinnEngineTransport by inner {
                    override fun close() {
                        cleaning.countDown()
                        assertTrue(releaseCleanup.await(5, java.util.concurrent.TimeUnit.SECONDS))
                        inner.close()
                    }
                }
            },
        )
        val starter = Thread {
            try { h.bridge.start() } catch (error: Throwable) { failures += error }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(spawning.await(2, java.util.concurrent.TimeUnit.SECONDS))
            val began = System.nanoTime()
            h.bridge.close()
            assertTrue((System.nanoTime() - began) / 1_000_000 < 1_000L)
            assertFalse(h.bridge.closeCompleted())
            releaseSpawn.countDown()
            assertTrue(cleaning.await(2, java.util.concurrent.TimeUnit.SECONDS))
            assertFalse(h.bridge.closeCompleted())
        } finally {
            releaseSpawn.countDown()
            releaseCleanup.countDown()
            starter.join(2_000L)
        }
        assertFalse(starter.isAlive)
        assertEquals(1, failures.size)
        assertFalse(h.bridge.isRunning())
        assertTrue(h.bridge.closeCompleted())
    }

    @Test
    fun `close at CreateAck or the pump publication boundary prevents late pumps`() {
        for (atAck in listOf(true, false)) {
            val reached = CountDownLatch(1)
            val release = CountDownLatch(1)
            val failures = CopyOnWriteArrayList<Throwable>()
            val h = harness(wrapTransport = { inner ->
                object : WinnEngineTransport by inner {
                    private var firstRead = true
                    override fun readFrame(): WinnFrame? {
                        val frame = inner.readFrame()
                        if (atAck && firstRead) {
                            firstRead = false
                            reached.countDown()
                            assertTrue(release.await(5, java.util.concurrent.TimeUnit.SECONDS))
                        }
                        return frame
                    }
                    override fun setReadTimeoutMs(timeoutMs: Int) {
                        inner.setReadTimeoutMs(timeoutMs)
                        if (!atAck && timeoutMs == 0) {
                            reached.countDown()
                            assertTrue(release.await(5, java.util.concurrent.TimeUnit.SECONDS))
                        }
                    }
                }
            })
            val starter = Thread {
                try { h.bridge.start() } catch (error: Throwable) { failures += error }
            }.apply { isDaemon = true; start() }
            try {
                assertTrue(reached.await(2, java.util.concurrent.TimeUnit.SECONDS))
                val began = System.nanoTime()
                h.bridge.close()
                assertTrue((System.nanoTime() - began) / 1_000_000 < 1_000L)
                assertFalse(h.bridge.closeCompleted())
            } finally {
                release.countDown()
                starter.join(2_000L)
            }
            assertFalse(starter.isAlive)
            assertEquals(1, failures.size)
            assertFalse(h.bridge.isRunning())
            assertTrue(h.bridge.closeCompleted())
        }
    }

    @Test
    fun `status waiter observes a new response instead of the CreateAck cache`() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        val results = CopyOnWriteArrayList<String>()
        val waiter = Thread { results += h.bridge.requestStatusAndAwait(1_000L) }
            .apply { isDaemon = true; start() }
        awaitStatusRequests(h.engineDouble, 1)
        h.engineDouble.push(WinnFraming.OP_STATUS_RESPONSE, "{\"seq\":1}".toByteArray())
        waiter.join(750L)
        assertFalse(waiter.isAlive)
        assertEquals(listOf("{\"seq\":1}"), results.toList())
    }

    @Test
    fun `an earlier outstanding response can satisfy the new document wait`() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        h.bridge.requestStatus()
        awaitStatusRequests(h.engineDouble, 1)
        val results = CopyOnWriteArrayList<String>()
        val waiter = Thread { results += h.bridge.requestStatusAndAwait(1_000L) }
            .apply { isDaemon = true; start() }
        awaitStatusRequests(h.engineDouble, 2)
        h.engineDouble.push(WinnFraming.OP_STATUS_RESPONSE, "{\"seq\":\"earlier\"}".toByteArray())
        waiter.join(750L)
        assertFalse(waiter.isAlive)
        assertEquals(listOf("{\"seq\":\"earlier\"}"), results.toList())
    }

    @Test
    fun `status without a reply waits to its monotonic timeout`() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        val cached = h.bridge.statusJson()
        val began = System.nanoTime()
        assertEquals(cached, h.bridge.requestStatusAndAwait(100L))
        val elapsed = (System.nanoTime() - began) / 1_000_000L
        assertTrue("elapsed=$elapsed", elapsed >= 80L && elapsed < 750L)
    }

    @Test
    fun `EOF and close wake a waiting status reader`() {
        for (eof in listOf(true, false)) {
            val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
            h.bridge.start()
            val results = CopyOnWriteArrayList<String>()
            val waiter = Thread { results += h.bridge.requestStatusAndAwait(1_000L) }
                .apply { isDaemon = true; start() }
            awaitStatusRequests(h.engineDouble, 1)
            if (eof) h.engineDouble.close() else h.bridge.close()
            waiter.join(750L)
            assertFalse(waiter.isAlive)
            assertEquals(1, results.size)
        }
    }

    @Test
    fun `interrupted status wait propagates and restores the interrupt flag`() {
        val h = harness(behaviour = WinnEngineDouble.Behaviour(answerStatusRequests = false))
        h.bridge.start()
        val interrupted = AtomicBoolean(false)
        val waiter = Thread {
            try {
                h.bridge.requestStatusAndAwait(1_000L)
            } catch (_: InterruptedException) {
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }.apply { isDaemon = true; start() }
        awaitStatusRequests(h.engineDouble, 1)
        waiter.interrupt()
        waiter.join(750L)
        assertFalse(waiter.isAlive)
        assertTrue(interrupted.get())
    }

    /**
     * A batched seam for the pump census. Its first uplink batch is refused as
     * stale (the real seam does that after a rebind), its second is written,
     * and its device takes none of the downlink packets it is offered.
     */
    private class CensusSeam : WinnV3BatchedIpPacketSeam {
        private val gate = CountDownLatch(1)
        private val reads = AtomicInteger(0)
        val refused = AtomicInteger(0)
        val offeredDownlink = AtomicInteger(0)

        override fun readOutgoingBatch(batch: WinnV3PacketBatch): Int {
            batch.clear()
            when (reads.incrementAndGet()) {
                1 -> repeat(3) { batch.append(WinnFraming.OP_INBOUND, byteArrayOf(0x45, 1), 0, 2) }
                2 -> repeat(2) { batch.append(WinnFraming.OP_INBOUND, byteArrayOf(0x45, 2), 0, 2) }
                else -> {
                    gate.await()
                    return -1
                }
            }
            return batch.count
        }

        override fun writeOutgoingBatchIfCurrent(batch: WinnV3PacketBatch, write: () -> Unit): Boolean {
            if (reads.get() == 1) {
                refused.incrementAndGet()
                return false
            }
            write()
            return true
        }

        override fun writeIncomingBatch(batch: WinnV3PacketBatch, start: Int, end: Int): Int {
            offeredDownlink.addAndGet(end - start)
            return 0
        }

        override fun readOutgoingPacket(buffer: ByteArray): Int {
            gate.await()
            return -1
        }
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() = gate.countDown()
    }

    @Test
    fun `pump census counts written uplink batches and delivered downlink packets only`() {
        val seam = CensusSeam()
        val h = harness(seamOverride = seam, framedStream = true)
        h.bridge.start()
        val deadline = System.nanoTime() + 2_000_000_000L
        while (seam.offeredDownlink.get() < 2 && System.nanoTime() < deadline) Thread.sleep(1L)
        assertEquals("the engine echoed the written batch", 2, seam.offeredDownlink.get())
        assertEquals("the stale batch never reached the engine", 2, h.engineDouble.receivedInbound.size)
        assertEquals(1, seam.refused.get())
        val census = h.bridge.pumpCensus()
        assertEquals("a refused stale batch is not counted", 2L, census.uplinkPackets)
        assertEquals(1L, census.uplinkWrites)
        assertTrue(census.uplinkWriteMaxNanos <= census.uplinkWriteNanos)
        assertEquals("packets the device did not take are not counted", 0L, census.downlinkPackets)
        assertTrue(census.downlinkWrites >= 1L)
        assertEquals("this seam keeps no drop count", -1L, census.seamDrops)
        assertEquals(-1L, census.nativeWritePackets)
        assertTrue(h.bridge.statusAgeMs() >= 0L)
    }

    @Test
    fun `status age is unknown before any document arrives`() {
        val h = harness()
        assertEquals(-1L, h.bridge.statusAgeMs())
    }

    private fun awaitStatusRequests(engine: WinnEngineDouble, count: Int) {
        val deadline = System.nanoTime() + 1_000_000_000L
        while (engine.statusRequests.get() < count && System.nanoTime() < deadline) Thread.sleep(1L)
        assertTrue("missing status request $count", engine.statusRequests.get() >= count)
    }

    private class Harness(
        val bridge: WinnV3Bridge,
        val engineDouble: WinnEngineDouble,
        val host: FakeHost,
    )

    private fun harness(
        inboundError: Throwable? = null,
        outboundError: Throwable? = null,
        probe: (() -> WinnV3ProtectedSocketErrno.Result)? = null,
        seamOverride: WinnV3IpPacketSeam? = null,
        behaviour: WinnEngineDouble.Behaviour = WinnEngineDouble.Behaviour(),
        beforeSpawn: () -> Unit = {},
        wrapTransport: (WinnEngineTransport) -> WinnEngineTransport = { it },
        framedStream: Boolean = false,
    ): Harness {
        val (hostSide, engineSide) = WinnEngineDouble.connectedPair()
        val double = WinnEngineDouble(engineSide, behaviour)
        double.start()
        // framedStream: the production batch transport over the same socket,
        // so the batched pumps (and their census) run instead of the
        // frame-at-a-time compatibility path.
        val loopback: WinnEngineTransport = if (framedStream) {
            WinnV3FramedStreamTransport(
                input = hostSide.getInputStream(),
                output = hostSide.getOutputStream(),
                descriptorSender = {},
                timeoutSetter = { hostSide.soTimeout = it },
                socketCloser = { hostSide.close() },
            )
        } else {
            LoopbackWinnTransport(hostSide)
        }
        val transport = wrapTransport(
            if (outboundError != null) PumpThrowTransport(loopback, outboundError) else loopback
        )
        val alive = AtomicBoolean(true)
        val underlay = FakeUnderlaySocket()
        val host = FakeHost(underlay) {
            beforeSpawn()
            FakeEngineProcess(transport, alive)
        }
        val seam: WinnV3IpPacketSeam = seamOverride
            ?: if (inboundError != null) ThrowingSeam(inboundError) else BlockingSeam()
        val bridge = WinnV3Bridge(
            host = host,
            seam = seam,
            config = WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820",
                innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1",
                innerMtu = 1359,
                pathMtu = 1500,
                carrierClasses = listOf("udp", "tcp", "tls"),
                sessionId = "session-1",
            ),
            probeProtectedSocketErrno = probe ?: {
                WinnV3ProtectedSocketErrno.Result(closed = true)
            },
        )
        cleanups += bridge
        cleanups += double
        cleanups += Closeable {
            try {
                hostSide.close()
            } catch (_: Exception) {
            }
        }
        return Harness(bridge, double, host)
    }

    private fun readBridgeSource(): String {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt")
            if (candidate.isFile) return candidate.readText()
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app/WinnV3Bridge.kt")
            if (here.isFile) return here.readText()
            dir = dir.parentFile
        }
        throw AssertionError("could not locate WinnV3Bridge.kt")
    }
}
