package org.winsvpn.app

import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.abs
import kotlin.math.sqrt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round A3: the recovery probe is randomized, capped and owner-bound, never a
 * cadence (`winn3/carrier/dial.go`; `WinnV3Host` §3). See [WinnV3RecoveryProber].
 *
 * The metronome detector is `metronomeVerdict` from
 * `winn3/session/fingerprint_test.go`, ported line for line, and it is shown
 * to object to a fixed schedule, a clamped schedule and a schedule rounded
 * onto the 1 s status poll before it is trusted on the real one.
 */
class WinnV3RecoveryProberTest {

    private class FakeTimer : WinnV3RecoveryProber.Timer {
        val delays = mutableListOf<Long>()
        val tasks = mutableListOf<Runnable>()
        val cancelled = AtomicInteger(0)
        var closed = false

        override fun schedule(delayNanos: Long, task: Runnable): WinnV3RecoveryProber.Cancellable {
            delays += delayNanos
            tasks += task
            return WinnV3RecoveryProber.Cancellable { cancelled.incrementAndGet() }
        }

        fun fireLast() = tasks.last().run()

        override fun close() {
            closed = true
        }
    }

    private val recovering = WinnV3LifecycleWatch.Verdict.RECOVERING

    // ---- the detector ------------------------------------------------------

    private fun metronomeVerdict(intervals: List<Long>): String {
        if (intervals.size < 32) return "too few intervals to judge"
        val counts = HashMap<Long, Int>()
        var sum = 0.0
        for (v in intervals) {
            counts[v] = (counts[v] ?: 0) + 1
            sum += v.toDouble()
        }
        val mean = sum / intervals.size
        val distinct = counts.size.toDouble() / intervals.size
        if (distinct < 0.5) return "only ${counts.size} distinct interval values across ${intervals.size} fires"
        val worst = counts.values.maxOrNull() ?: 0
        if (worst.toDouble() / intervals.size > 0.10) return "one interval holds ${worst * 100 / intervals.size}% of the fires"
        var varsum = 0.0
        for (v in intervals) {
            val d = v - mean
            varsum += d * d
        }
        val cv = sqrt(varsum / intervals.size) / mean
        if (cv < 0.25) return "coefficient of variation is only $cv"
        var lag = 1
        while (lag <= 8 && lag < intervals.size / 4) {
            var num = 0.0
            for (i in 0 until intervals.size - lag) {
                num += (intervals[i] - mean) * (intervals[i + lag] - mean)
            }
            val r = num / varsum
            if (abs(r) > 0.25) return "autocorrelation $r at lag $lag"
            lag++
        }
        return ""
    }

    private fun realDelays(n: Int): List<Long> {
        val draw = WinnV3RecoveryProber.secureDraw()
        return List(n) {
            WinnV3RecoveryProber.nextDelayNanos(
                draw,
                WinnV3RecoveryProber.MIN_DELAY_NANOS,
                WinnV3RecoveryProber.MAX_DELAY_NANOS,
            )
        }
    }

    @Test
    fun `the detector has teeth against fixed, clamped and poll-rounded schedules`() {
        // The v1 schedule: one probe every 5.000 s.
        assertNotEquals("", metronomeVerdict(List(256) { 5_000_000_000L }))
        // A clamped exponential: most draws parked on the cap.
        val random = SecureRandom()
        val clamped = List(256) { minOf(5_000_000_000L, (random.nextDouble() * 20e9).toLong()) }
        assertNotEquals("", metronomeVerdict(clamped))
        // Tiny jitter rounded onto the 1 s poll: a handful of values.
        val rounded = realDelays(256).map { (it / 1_000_000_000L) * 1_000_000_000L }
        assertNotEquals("", metronomeVerdict(rounded))
    }

    @Test
    fun `the real delays are discrete uniform at ns resolution, bounded, and not a metronome`() {
        val delays = realDelays(4_096)
        assertEquals("", metronomeVerdict(delays))
        for (d in delays) {
            assertTrue("delay $d below the open lower bound", d > WinnV3RecoveryProber.MIN_DELAY_NANOS)
            assertTrue("delay $d above the open upper bound", d < WinnV3RecoveryProber.MAX_DELAY_NANOS)
        }
        val onWholeSeconds = delays.count { it % 1_000_000_000L == 0L }
        assertTrue("$onWholeSeconds of ${delays.size} delays sit on a whole second", onWholeSeconds <= 1)
        assertTrue("draws must span the interval", delays.maxOrNull()!! - delays.minOrNull()!! > 6_000_000_000L)
    }

    @Test
    fun `each probe is scheduled at exactly its own drawn delay, independent of the poll`() {
        val draws = ArrayDeque(listOf(1L, 1_234_567_891L, 7_999_999_997L, 42L))
        val timer = FakeTimer()
        val prober = WinnV3RecoveryProber(
            timer = timer,
            draw = { bound ->
                val next = draws.removeFirst()
                assertTrue(next < bound)
                next
            },
            isStillOwner = { true },
            send = { true },
        )
        prober.onVerdict(recovering)
        // A second RECOVERING verdict, as the 1 s poll delivers, must not
        // schedule another probe or move the pending one.
        prober.onVerdict(recovering)
        prober.onVerdict(recovering)
        assertEquals(1, timer.delays.size)
        timer.fireLast()
        timer.fireLast()
        timer.fireLast()
        val base = WinnV3RecoveryProber.MIN_DELAY_NANOS + 1
        assertEquals(
            listOf(base + 1L, base + 1_234_567_891L, base + 7_999_999_997L, base + 42L),
            timer.delays,
        )
    }

    @Test
    fun `an episode sends at most its cap, then nothing`() {
        val timer = FakeTimer()
        val sent = AtomicInteger(0)
        val prober = WinnV3RecoveryProber(
            timer = timer,
            draw = WinnV3RecoveryProber.secureDraw(),
            isStillOwner = { true },
            send = { sent.incrementAndGet(); true },
        )
        prober.onVerdict(recovering)
        repeat(WinnV3RecoveryProber.MAX_PROBES_PER_EPISODE * 3) {
            if (prober.hasPendingProbe()) timer.fireLast()
            prober.onVerdict(recovering)
        }
        assertEquals(WinnV3RecoveryProber.MAX_PROBES_PER_EPISODE, sent.get())
        assertEquals(WinnV3RecoveryProber.MAX_PROBES_PER_EPISODE, timer.delays.size)
        assertFalse(prober.hasPendingProbe())
    }

    @Test
    fun `a verdict other than recovering ends the episode and the next one starts afresh`() {
        val timer = FakeTimer()
        val sent = AtomicInteger(0)
        val prober = WinnV3RecoveryProber(
            timer = timer,
            draw = WinnV3RecoveryProber.secureDraw(),
            isStillOwner = { true },
            send = { sent.incrementAndGet(); true },
        )
        prober.onVerdict(recovering)
        timer.fireLast()
        assertEquals(1, prober.sentInEpisode())
        prober.onVerdict(WinnV3LifecycleWatch.Verdict.CONNECTED)
        assertTrue("the pending probe is cancelled", timer.cancelled.get() >= 1)
        assertFalse(prober.hasPendingProbe())
        // A late fire of the cancelled task sends nothing.
        timer.tasks.last().run()
        assertEquals(1, sent.get())
        for (verdict in listOf(
            WinnV3LifecycleWatch.Verdict.BLOCKED,
            WinnV3LifecycleWatch.Verdict.UNREPORTED,
        )) {
            prober.onVerdict(verdict)
            assertFalse("$verdict never probes", prober.hasPendingProbe())
        }
        prober.onVerdict(recovering)
        assertEquals(0, prober.sentInEpisode())
        assertTrue(prober.hasPendingProbe())
    }

    @Test
    fun `a change of owner cancels the prober before it sends`() {
        val timer = FakeTimer()
        val owner = AtomicBoolean(true)
        val sent = AtomicInteger(0)
        val prober = WinnV3RecoveryProber(
            timer = timer,
            draw = WinnV3RecoveryProber.secureDraw(),
            isStillOwner = { owner.get() },
            send = { sent.incrementAndGet(); true },
        )
        prober.onVerdict(recovering)
        owner.set(false)
        timer.fireLast()
        assertEquals("a superseded session sends nothing", 0, sent.get())
        assertTrue(timer.closed)
        prober.onVerdict(recovering)
        assertEquals("a closed prober schedules nothing", 1, timer.delays.size)
    }

    @Test
    fun `the production timer fires on its own thread at the drawn delay`() {
        val timer = WinnV3ExecutorProbeTimer("probe-test")
        try {
            val fired = CountDownLatch(1)
            val start = System.nanoTime()
            var at = 0L
            timer.schedule(30_000_000L, Runnable {
                at = System.nanoTime()
                fired.countDown()
            })
            assertTrue(fired.await(5, TimeUnit.SECONDS))
            assertTrue("fired early", at - start >= 30_000_000L)
            val never = CountDownLatch(1)
            timer.schedule(50_000_000L, Runnable { never.countDown() }).cancel()
            assertFalse("a cancelled probe must not fire", never.await(300, TimeUnit.MILLISECONDS))
        } finally {
            timer.close()
        }
    }
}
