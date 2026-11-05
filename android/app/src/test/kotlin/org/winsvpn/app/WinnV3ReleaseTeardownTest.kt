package org.winsvpn.app

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round L (OI-L4): failure injection at the boundary
 * VpnTunnelService.runTeardownPass calls. The service builds one
 * [WinnV3ReleaseTeardown] per pass with its real operations and the
 * process-wide [WinnV3CleanupDebt], routes every engine stop and every
 * interface close through it, and publishes whatever
 * [WinnV3ReleaseTeardown.disposition] returns (pinned by
 * WinnV3ReleaseLedgerTest). Here the same runner gets operations that throw,
 * report an unconfirmed stop, never finish, or finish late; and a second pass
 * over the same debt checks that the evidence survives.
 */
class WinnV3ReleaseTeardownTest {

    private val closed = WinnV3ReleaseLedger.Disposition.CLOSED
    private val incomplete = WinnV3ReleaseLedger.Disposition.INCOMPLETE
    private val hold = WinnV3ReleaseLedger.Disposition.WINN3_HOLD

    private class Recorder {
        val calls = mutableListOf<String>()
        val warnings = mutableListOf<String>()
    }

    private class Iface(private val name: String, private val calls: MutableList<String>, private val fail: Boolean = false) : Closeable {
        override fun close() {
            calls += "close $name"
            if (fail) throw IOException("$name close failed")
        }
    }

    /** A bridge close held open, then finished with [ok]. */
    private class HeldClose {
        private val finished = CountDownLatch(1)
        @Volatile private var ok = false
        fun finish(ok: Boolean) {
            this.ok = ok
            finished.countDown()
        }
        val completion = WinnV3Completion { timeout ->
            finished.await(timeout, TimeUnit.MILLISECONDS) && ok
        }
    }

    /**
     * One pass through the runner, shaped like runTeardownPass: engine stops,
     * then either the hold branch (hold cleanup of the retained interface),
     * or the releasing closes, then the finally's notification outcome (a
     * refused hold closes the capture interface and drops the field whether
     * or not that close threw).
     */
    private fun pass(
        rec: Recorder,
        debt: WinnV3CleanupDebt = WinnV3CleanupDebt(),
        fallback: () -> Boolean = { true },
        winnEngines: () -> List<WinnV3Completion> = { emptyList() },
        vpnEngine: () -> Unit = {},
        retired: () -> Boolean = { true },
        retainedFails: Boolean = false,
        captureFails: Boolean = false,
        block: Boolean = false,
        winn3Hold: Boolean = false,
        notificationRefused: Boolean = false,
    ): WinnV3ReleaseLedger.Disposition {
        val release = WinnV3ReleaseTeardown(
            stopFallbackTransport = { rec.calls += "fallback"; fallback() },
            stopWinnEngines = { rec.calls += "winn engines"; winnEngines() },
            stopVpnEngine = { rec.calls += "vpn engine"; vpnEngine() },
            engineRetired = { rec.calls += "retired?"; retired() },
            debt = debt,
            warn = { message, _ -> rec.warnings += message },
            bridgeCloseWaitMs = 100L,
        )
        release.stopFallback()
        release.stopEngines()
        var retained: Closeable? = Iface("retained", rec.calls, retainedFails)
        var capture: Closeable? = Iface("capture", rec.calls, captureFails)
        var blockEstablished = false
        if (block) {
            if (release.close("Retained interface close under a hold", retained)) retained = null
            blockEstablished = true
        } else {
            if (release.close("Retained interface close", retained)) retained = null
            if (release.close("Capture interface close", capture)) capture = null
        }
        var holding = false
        if (blockEstablished) {
            holding = true
            if (notificationRefused) {
                holding = false
                release.close("Capture interface close after a refused hold", capture)
                capture = null
            }
        }
        return release.disposition(
            winn3HoldKept = winn3Hold && blockEstablished && holding,
            blockKept = blockEstablished && holding,
            interfacesClosed = retained == null && capture == null,
        )
    }

    @Test
    fun `a pass whose every step is confirmed is a release`() {
        val rec = Recorder()
        assertEquals(closed, pass(rec))
        assertEquals(
            listOf("fallback", "winn engines", "vpn engine", "close retained", "close capture", "retired?"),
            rec.calls,
        )
        assertTrue(rec.warnings.isEmpty())
    }

    @Test
    fun `an engine stop that throws is not a release, and the pass still closes the interfaces`() {
        val rec = Recorder()
        val result = pass(rec, winnEngines = { throw IllegalStateException("bridge close threw") })
        assertEquals(incomplete, result)
        assertTrue("the rest of the pass must still run", rec.calls.containsAll(
            listOf("vpn engine", "close retained", "close capture")))
        assertEquals(listOf("Winn engine stop was incomplete"), rec.warnings)
        assertFalse("no release is claimed, so the retirement is not consulted", "retired?" in rec.calls)
    }

    @Test
    fun `the VPN engine stop throwing is not a release`() {
        val rec = Recorder()
        assertEquals(incomplete, pass(rec, vpnEngine = { throw RuntimeException("awgTurnOff threw") }))
        assertEquals(listOf("VPN engine stop was incomplete"), rec.warnings)
    }

    @Test
    fun `a bridge close that ends badly, or a fallback that outlives its stop, is not a release`() {
        assertEquals(incomplete, pass(Recorder(), winnEngines = { listOf(WinnV3Completion { false }) }))
        assertEquals(incomplete, pass(Recorder(), fallback = { false }))
    }

    @Test
    fun `an interface close that throws is not a release, and the other interface is still closed`() {
        val rec = Recorder()
        assertEquals(incomplete, pass(rec, retainedFails = true))
        assertTrue("close capture" in rec.calls)
        assertEquals(listOf("Retained interface close was incomplete"), rec.warnings)

        assertEquals(incomplete, pass(Recorder(), captureFails = true))
    }

    @Test
    fun `a refused hold notification followed by a throwing close is not a release, then or later`() {
        // The owner's release meets a configured kill-switch block, the
        // notification the block needs cannot be posted, and closing the
        // interface throws. The field is dropped anyway, as the service does.
        val debt = WinnV3CleanupDebt()
        val rec = Recorder()
        val initial = pass(rec, debt, block = true, notificationRefused = true, captureFails = true)
        assertEquals(incomplete, initial)
        assertEquals(listOf("Capture interface close after a refused hold was incomplete"), rec.warnings)

        // The subsequent release pass finds every field null and every step
        // fine. The descriptor whose close threw is still unaccounted for.
        val subsequent = pass(Recorder(), debt)
        assertEquals(incomplete, subsequent)
        assertTrue(debt.unresolved().single().startsWith("Capture interface close after a refused hold"))

        // Positive control: the same refused hold with a clean close releases.
        assertEquals(closed, pass(Recorder(), block = true, notificationRefused = true))
    }

    @Test
    fun `a hold cleanup close that throws keeps the hold, and poisons the later release`() {
        val debt = WinnV3CleanupDebt()
        assertEquals(hold, pass(Recorder(), debt, block = true, winn3Hold = true, retainedFails = true))
        assertEquals(incomplete, pass(Recorder(), debt))
    }

    @Test
    fun `a bridge close held open across the holding pass and then failed never becomes a release`() {
        val debt = WinnV3CleanupDebt()
        val held = HeldClose()
        // Initial (holding) pass: the bridge close is still running when the
        // pass's bound expires. The hold stands; the close is deferred.
        assertEquals(hold, pass(Recorder(), debt, block = true, winn3Hold = true,
            winnEngines = { listOf(held.completion) }))
        assertEquals(listOf("winn engine bridge close"), debt.unresolved())

        // The close then fails. The release pass finds no bridge left to stop.
        held.finish(ok = false)
        assertEquals(incomplete, pass(Recorder(), debt))
        assertEquals(incomplete, pass(Recorder(), debt))
    }

    @Test
    fun `a bridge close held open and then finished cleanly releases on the later pass`() {
        val debt = WinnV3CleanupDebt()
        val held = HeldClose()
        assertEquals(hold, pass(Recorder(), debt, block = true, winn3Hold = true,
            winnEngines = { listOf(held.completion) }))
        // Still running at the release pass: not a release yet.
        assertEquals(incomplete, pass(Recorder(), debt))
        held.finish(ok = true)
        assertEquals(closed, pass(Recorder(), debt))
        assertTrue(debt.unresolved().isEmpty())
    }

    @Test
    fun `an engine retirement that times out is not a release, within its bound`() {
        val retirement = WinnV3EngineRetirement()
        val started = System.nanoTime()
        val result = pass(Recorder(), retired = { retirement.awaitCompleted(150L) })
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertEquals(incomplete, result)
        assertTrue("the wait is bounded: ${elapsedMs}ms", elapsedMs in 100L..5_000L)
    }

    @Test
    fun `an engine retirement that finished badly is not a release, and a clean one is`() {
        val bad = WinnV3EngineRetirement().apply { finish(false) }
        assertEquals(incomplete, pass(Recorder(), retired = { bad.awaitCompleted(1_000L) }))
        val good = WinnV3EngineRetirement().apply { finish(true) }
        assertEquals(closed, pass(Recorder(), retired = { good.awaitCompleted(1_000L) }))
        // The first finish wins.
        good.finish(false)
        assertTrue(good.awaitCompleted(0L))
    }

    @Test
    fun `holds and blocks are reported as such and never wait on the retirement`() {
        val rec = Recorder()
        assertEquals(hold, pass(rec, block = true, winn3Hold = true, retired = { error("waited") }))
        assertEquals(WinnV3ReleaseLedger.Disposition.KILL_SWITCH_BLOCK,
            pass(Recorder(), block = true, retired = { error("waited") }))
        assertFalse("retired?" in rec.calls)
    }

    @Test
    fun `an incomplete pass keeps the ledger's hold outstanding, so Dart has nothing to accept`() {
        val ledger = WinnV3ReleaseLedger()
        val held = ledger.passCompleted(WinnV3ReleaseLedger.Disposition.WINN3_HOLD)
        val after = ledger.passCompleted(pass(Recorder(), winnEngines = { throw IllegalStateException() }))
        assertEquals(incomplete, after.lastDisposition)
        assertEquals(held.holdId, after.holdId)
        assertEquals("incomplete", after.readinessFields()[WinnV3ReleaseLedger.KEY_LAST_DISPOSITION])
    }

    /** The injected exception at the finally's stopForeground(STOP_FOREGROUND_REMOVE). */
    private class FinalizationFailure : RuntimeException("stopForeground threw")

    /**
     * A faithful extraction of VpnTunnelService.runTeardownPass's control flow
     * for the kill-switch branch, statement for statement in the service's
     * order: the runner built first; the body (fallback stop, engine stops,
     * hold cleanup, block established) under the service's two catches; then
     * the `finally`: the interface flag, the block posture, the notification
     * outcome, and for a refused notification the recorded capture close, the
     * field and flag dropped, then stopForeground and stopSelf; and only after
     * the whole finally, disposition(). The order is pinned against the
     * service source by WinnV3ReleaseLedgerTest. [stopForeground] throwing is
     * Astra's injected finalization exception: it leaves the finally, so
     * disposition() is never reached, exactly as in the service.
     */
    private fun serviceShapedPass(
        debt: WinnV3CleanupDebt,
        rec: Recorder = Recorder(),
        capture: Closeable?,
        retained: Closeable? = null,
        killSwitchBlock: Boolean,
        notificationPosted: Boolean = true,
        stopForeground: () -> Unit = {},
    ): WinnV3ReleaseLedger.Disposition {
        val release = WinnV3ReleaseTeardown(
            stopFallbackTransport = { true },
            stopWinnEngines = { emptyList() },
            stopVpnEngine = {},
            engineRetired = { true },
            debt = debt,
            warn = { message, _ -> rec.warnings += message },
            bridgeCloseWaitMs = 100L,
        )
        var vpnInterface = capture
        var retainedKillSwitchInterface = retained
        var blockPostureEstablished = false
        var holdingBlockPosture = false
        var isInterfaceOpen = vpnInterface != null
        try {
            release.stopFallback()
            release.stopEngines()
            if (killSwitchBlock && vpnInterface != null) {
                if (release.close("Retained interface close under a hold", retainedKillSwitchInterface)) {
                    retainedKillSwitchInterface = null
                }
                blockPostureEstablished = true
            } else if (!killSwitchBlock) {
                if (release.close("Retained interface close", retainedKillSwitchInterface)) {
                    retainedKillSwitchInterface = null
                }
                if (release.close("Capture interface close", vpnInterface)) {
                    vpnInterface = null
                }
            }
        } catch (e: IOException) {
            release.evidence.fail("teardown pass: IOException")
        } catch (e: Exception) {
            release.evidence.fail("teardown pass: ${e.javaClass.simpleName}")
        } finally {
            if (!blockPostureEstablished) isInterfaceOpen = false
            if (blockPostureEstablished) {
                holdingBlockPosture = true
                val keepHold = notificationPosted
                if (!keepHold) {
                    holdingBlockPosture = false
                    release.close("Capture interface close after a refused hold", vpnInterface)
                    vpnInterface = null
                    isInterfaceOpen = false
                    rec.calls += "stopForeground"
                    stopForeground()
                    rec.calls += "stopSelf"
                }
            } else {
                rec.calls += "stopForeground"
                stopForeground()
                rec.calls += "stopSelf"
            }
        }
        return release.disposition(
            winn3HoldKept = false,
            blockKept = blockPostureEstablished && holdingBlockPosture,
            interfacesClosed = vpnInterface == null && retainedKillSwitchInterface == null,
        )
    }

    private fun assertFinalizationEscapes(block: () -> Unit) {
        try {
            block()
        } catch (_: FinalizationFailure) {
            return
        }
        throw AssertionError("the injected finalization exception did not escape the pass")
    }

    @Test
    fun `a refused notification close failure then a finalization exception leaves the next pass incomplete`() {
        val debt = WinnV3CleanupDebt()
        val rec = Recorder()
        // An outstanding hold, engine retirement fine, the configured
        // kill-switch block's notification refused, the capture close throws,
        // then stopForeground throws: the pass leaves through its finally.
        assertFinalizationEscapes {
            serviceShapedPass(
                debt, rec,
                capture = Iface("capture", rec.calls, fail = true),
                killSwitchBlock = true,
                notificationPosted = false,
                stopForeground = { throw FinalizationFailure() },
            )
        }
        assertEquals(listOf("close capture", "stopForeground"), rec.calls)
        assertTrue("the close failure must already be in the debt", debt.unresolved().any {
            it.startsWith("Capture interface close after a refused hold")
        })

        // The later non-holding pass, no new session, every resource null.
        val later = serviceShapedPass(debt, capture = null, killSwitchBlock = false)
        assertEquals(incomplete, later)
        // And the ledger publishes that, not closed, for the outstanding hold.
        val ledger = WinnV3ReleaseLedger()
        val held = ledger.passCompleted(WinnV3ReleaseLedger.Disposition.WINN3_HOLD)
        val after = ledger.passCompleted(later)
        assertEquals(incomplete, after.lastDisposition)
        assertEquals(held.holdId, after.holdId)
    }

    @Test
    fun `a finalization exception alone still leaves the aborted pass unresolved`() {
        // Every close succeeds; only stopForeground throws. The pass cleared
        // its fields and never reached its acknowledgement.
        val debt = WinnV3CleanupDebt()
        assertFinalizationEscapes {
            serviceShapedPass(
                debt,
                capture = Iface("capture", mutableListOf()),
                killSwitchBlock = true,
                notificationPosted = false,
                stopForeground = { throw FinalizationFailure() },
            )
        }
        assertTrue(debt.unresolved().any { it.endsWith("did not finish") })
        assertEquals(incomplete, serviceShapedPass(debt, capture = null, killSwitchBlock = false))
    }

    @Test
    fun `without the finalization exception the same passes behave as before`() {
        // Clean close, notification refused, no exception: a release.
        assertEquals(closed, serviceShapedPass(WinnV3CleanupDebt(),
            capture = Iface("capture", mutableListOf()), killSwitchBlock = true, notificationPosted = false))
        // Throwing close, no exception: that pass and the next are incomplete.
        val debt = WinnV3CleanupDebt()
        assertEquals(incomplete, serviceShapedPass(debt,
            capture = Iface("capture", mutableListOf(), fail = true), killSwitchBlock = true, notificationPosted = false))
        assertEquals(incomplete, serviceShapedPass(debt, capture = null, killSwitchBlock = false))
        // A new session clears even an aborted pass.
        val aborted = WinnV3CleanupDebt()
        assertFinalizationEscapes {
            serviceShapedPass(aborted, capture = Iface("capture", mutableListOf()), killSwitchBlock = true,
                notificationPosted = false, stopForeground = { throw FinalizationFailure() })
        }
        aborted.clear()
        assertEquals(closed, serviceShapedPass(aborted, capture = null, killSwitchBlock = false))
    }

    @Test
    fun `a new session clears the debt`() {
        val debt = WinnV3CleanupDebt()
        pass(Recorder(), debt, captureFails = true)
        assertEquals(incomplete, pass(Recorder(), debt))
        debt.clear()
        assertEquals(closed, pass(Recorder(), debt))
    }
}
