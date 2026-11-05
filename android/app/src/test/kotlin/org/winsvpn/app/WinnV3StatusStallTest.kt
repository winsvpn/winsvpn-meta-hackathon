package org.winsvpn.app

import java.io.FileDescriptor
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round A3: the host recovery ceiling stays enforceable while status I/O is
 * wedged. The real [WinnV3Bridge] runs against the engine double with a
 * transport whose `StatusRequest` write never returns, which is what a packet
 * writer holding the transport lock behind a full socket buffer looks like.
 *
 * Deliberately written against API that both the Round A3 v1 candidate and
 * this version have, so it runs red on v1 (whose `requestStatus()` writes
 * synchronously) rather than merely failing to compile there.
 */
class WinnV3StatusStallTest {

    private val recoveringDocument =
        """{"event":"posture","posture":"hold","gate_state":"closed","rx_packets":0,"rx_offered":0,"lifecycle":"recovering"}"""

    /** A transport whose StatusRequest write parks until [wedge] opens. */
    private class WedgingTransport(private val inner: WinnEngineTransport) : WinnEngineTransport {
        val wedge = CountDownLatch(1)
        val statusWritesEntered = AtomicInteger(0)
        override fun writeFrame(opcode: Int, payload: ByteArray) {
            if (opcode == WinnFraming.OP_STATUS_REQUEST) {
                statusWritesEntered.incrementAndGet()
                wedge.await()
            }
            inner.writeFrame(opcode, payload)
        }
        override fun sendDescriptor(fd: FileDescriptor) = inner.sendDescriptor(fd)
        override fun readFrame(): WinnFrame? = inner.readFrame()
        override fun setReadTimeoutMs(timeoutMs: Int) = inner.setReadTimeoutMs(timeoutMs)
        override fun close() = inner.close()
    }

    private class ParkedSeam : WinnV3IpPacketSeam {
        private val gate = CountDownLatch(1)
        override fun readOutgoingPacket(buffer: ByteArray): Int {
            gate.await()
            return -1
        }
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() = gate.countDown()
    }

    /** Calls [block] on its own thread; true when it returned within [ms]. */
    private fun returnsWithin(ms: Long, block: () -> Unit): Boolean {
        val done = CountDownLatch(1)
        val thread = Thread {
            block()
            done.countDown()
        }.apply {
            isDaemon = true
            start()
        }
        val returned = done.await(ms, TimeUnit.MILLISECONDS)
        if (!returned) thread.interrupt()
        return returned
    }

    @Test
    fun `a wedged status write never blocks the caller, and the ceiling still fires on time`() {
        val pair = WinnEngineDouble.connectedPair()
        val engine = WinnEngineDouble(
            pair.second,
            WinnEngineDouble.Behaviour(
                createReplyPayload =
                    """{"gate_state":"carrying","rx_packets":3,"rx_offered":3,"lifecycle":"connected"}""",
                answerStatusRequests = false,
            ),
        )
        engine.start()
        val transport = WedgingTransport(LoopbackWinnTransport(pair.first))
        val alive = AtomicBoolean(true)
        val clock = AtomicLong(1_000_000L)
        val bridge = WinnV3Bridge(
            host = object : WinnEngineHost {
                override fun openProtectedUnderlaySocket(): WinnUnderlaySocket = object : WinnUnderlaySocket {
                    override val protectedBeforeHandoff = true
                    override val descriptor = FileDescriptor()
                    override val localPort = 40405
                    override fun close() = Unit
                }
                override fun startEngineProcess(): WinnEngineProcess = object : WinnEngineProcess {
                    override val transport: WinnEngineTransport = transport
                    override fun isAlive() = alive.get()
                    override fun describe() = "double"
                    override fun close() {
                        alive.set(false)
                        transport.close()
                    }
                }
                override fun openAwgDatagramSeam(): WinnAwgDatagramSeam? = null
                override fun onDebug(message: String) = Unit
                override fun onWarning(message: String, error: Throwable?) = Unit
                override fun onError(message: String, error: Throwable?) = Unit
            },
            seam = ParkedSeam(),
            config = WinnV3EngineConfig(
                gatewayEndpoint = "203.0.113.9:51820",
                innerAddress = "10.8.1.3",
                innerNextHop = "10.8.1.1",
                innerMtu = 1359,
                pathMtu = 1500,
                carrierClasses = listOf("udp", "tcp", "tls"),
                sessionId = "session-stall",
            ),
            clockMs = { clock.get() },
        )
        try {
            bridge.start()
            // The engine's last word before the transport wedges: recovering.
            engine.push(WinnFraming.OP_STATUS_RESPONSE, recoveringDocument.toByteArray())
            val deadline = System.currentTimeMillis() + 5_000
            while (!bridge.statusJson().contains("recovering") && System.currentTimeMillis() < deadline) {
                Thread.sleep(5)
            }
            assertTrue(bridge.statusJson().contains("recovering"))

            // The monitoring step of the post-promotion loop, run the way the
            // loop runs it: request, read the latest document, judge it on the
            // host's monotonic clock. Every request must return promptly even
            // though the first one is parked in the transport for good.
            val watch = WinnV3LifecycleWatch()
            var verdict = WinnV3LifecycleWatch.Verdict.UNREPORTED
            var healthyWhileWedged = true
            var seconds = 0
            while (seconds <= 200) {
                assertTrue(
                    "requestStatus() blocked on a wedged transport at t=${seconds}s",
                    returnsWithin(1_000L) { bridge.requestStatus() },
                )
                verdict = watch.observe(WinnV3EngineStatus.parse(bridge.statusJson()), clock.get())
                if (seconds > WinnV3Bridge.STATUS_STALE_MS / 1_000 + 1) healthyWhileWedged = healthyWhileWedged && bridge.isHealthy()
                clock.addAndGet(1_000L)
                seconds++
            }
            assertEquals("one write is parked; the rest were coalesced, not stacked", 1, transport.statusWritesEntered.get())
            assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, verdict)
            assertFalse("liveness must go stale while the transport is wedged", healthyWhileWedged)
        } finally {
            transport.wedge.countDown()
            try { bridge.close() } catch (_: Exception) {}
            try { engine.close() } catch (_: Exception) {}
            try { pair.first.close() } catch (_: Exception) {}
        }
    }
}
