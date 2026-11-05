package org.winsvpn.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round L (OI-L4): the generation-bound release acknowledgement a held
 * reconnect or held server switch waits on before preparing anything.
 */
class WinnV3ReleaseLedgerTest {

    private val closed = WinnV3ReleaseLedger.Disposition.CLOSED
    private val hold = WinnV3ReleaseLedger.Disposition.WINN3_HOLD

    @Test
    fun `nothing is outstanding and nothing was released before any pass`() {
        val fields = WinnV3ReleaseLedger().snapshot().readinessFields()
        assertEquals(0L, fields[WinnV3ReleaseLedger.KEY_HOLD_ID])
        assertEquals(0L, fields[WinnV3ReleaseLedger.KEY_SEQUENCE])
        assertEquals(0L, fields[WinnV3ReleaseLedger.KEY_LAST_HOLD_ID])
        assertEquals("none", fields[WinnV3ReleaseLedger.KEY_LAST_DISPOSITION])
    }

    @Test
    fun `an owner stop that closes the interface releases exactly the outstanding hold`() {
        val ledger = WinnV3ReleaseLedger()
        val held = ledger.passCompleted(hold)
        assertTrue(held.holdId > 0L)
        val mark = ledger.snapshot()

        val released = ledger.passCompleted(closed)
        assertEquals(0L, released.holdId)
        assertEquals(mark.holdId, released.lastHoldId)
        assertEquals(closed, released.lastDisposition)
        assertTrue(released.sequence > mark.sequence)
    }

    @Test
    fun `a configured kill switch keeps its block and is not reported as a release`() {
        val ledger = WinnV3ReleaseLedger()
        val held = ledger.passCompleted(hold)
        val after = ledger.passCompleted(WinnV3ReleaseLedger.Disposition.KILL_SWITCH_BLOCK)
        assertEquals(held.holdId, after.lastHoldId)
        assertEquals("kill_switch_block", after.readinessFields()[WinnV3ReleaseLedger.KEY_LAST_DISPOSITION])
        assertNotEquals(closed, after.lastDisposition)
    }

    @Test
    fun `an incomplete pass keeps the hold outstanding until a later pass closes it`() {
        val ledger = WinnV3ReleaseLedger()
        val held = ledger.passCompleted(hold)
        val incomplete = ledger.passCompleted(WinnV3ReleaseLedger.Disposition.INCOMPLETE)
        assertEquals(held.holdId, incomplete.holdId)
        val released = ledger.passCompleted(closed)
        assertEquals(held.holdId, released.lastHoldId)
        assertEquals(closed, released.lastDisposition)
    }

    @Test
    fun `a later hold has a new identity, so an old acknowledgement cannot satisfy it`() {
        val ledger = WinnV3ReleaseLedger()
        val first = ledger.passCompleted(hold)
        ledger.passCompleted(closed)
        val second = ledger.passCompleted(hold)
        assertNotEquals(first.holdId, second.holdId)
        // A second holding pass over the same interface keeps the same hold.
        assertEquals(second.holdId, ledger.passCompleted(hold).holdId)
    }

    @Test
    fun `a supersession ends the hold without releasing it`() {
        val ledger = WinnV3ReleaseLedger()
        val held = ledger.passCompleted(hold)
        val after = ledger.passCompleted(WinnV3ReleaseLedger.Disposition.SUPERSEDED)
        assertEquals(0L, after.holdId)
        assertEquals(held.holdId, after.lastHoldId)
        assertEquals("superseded", after.readinessFields()[WinnV3ReleaseLedger.KEY_LAST_DISPOSITION])
    }

    @Test
    fun `the disposition is read from what the pass left and what it confirmed`() {
        fun of(hold: Boolean, block: Boolean, closed: Boolean, confirmed: Boolean = true) =
            WinnV3ReleaseLedger.dispositionOf(hold, block, closed, confirmed)
        assertEquals(WinnV3ReleaseLedger.Disposition.WINN3_HOLD, of(hold = true, block = true, closed = false))
        assertEquals(WinnV3ReleaseLedger.Disposition.KILL_SWITCH_BLOCK, of(hold = false, block = true, closed = false))
        assertEquals(WinnV3ReleaseLedger.Disposition.CLOSED, of(hold = false, block = false, closed = true))
        assertEquals(WinnV3ReleaseLedger.Disposition.INCOMPLETE, of(hold = false, block = false, closed = false))
        // A hold the pass had to give up (no notification, no interface) is
        // not kept: what decides is whether the interfaces are closed.
        assertEquals(WinnV3ReleaseLedger.Disposition.CLOSED, of(hold = true, block = false, closed = true))
        // Null descriptor fields alone are not a release (Round L turn 2).
        assertEquals(WinnV3ReleaseLedger.Disposition.INCOMPLETE,
            of(hold = false, block = false, closed = true, confirmed = false))
    }

    @Test
    fun `the service publishes the acknowledgement only after the pass has closed its interfaces`() {
        val source = source("VpnTunnelService.kt")
        val pass = source.substring(
            source.indexOf("fun runTeardownPass(plan: WinnV3CaptureCustody.Plan): Boolean {"),
            source.indexOf("return blockPostureEstablished && holdingBlockPosture"),
        )
        val clearLifecycle = pass.indexOf("if (!plan.holdCapture) winn3HostLifecycle.clear()")
        val closeInterface = pass.indexOf("release.close(\"Capture interface close\", vpnInterface)")
        val finallyBlock = pass.indexOf("} finally {")
        val lastStop = pass.lastIndexOf("stopSelf()")
        val ack = pass.indexOf("winn3ReleaseLedger.passCompleted(")
        assertTrue("lifecycle clear not found", clearLifecycle >= 0)
        assertTrue("interface close not found", closeInterface > clearLifecycle)
        assertTrue("the pass has no finally", finallyBlock > closeInterface)
        assertTrue("the acknowledgement is missing", ack >= 0)
        assertTrue("the acknowledgement precedes the pass's finally", ack > finallyBlock)
        assertTrue("the acknowledgement precedes the pass's last stop", ack > lastStop)
        assertEquals("exactly one acknowledgement per pass", 1,
            Regex("""winn3ReleaseLedger\.passCompleted\(""").findAll(pass).count())
        val ackCall = pass.substring(ack)
        assertTrue("the acknowledgement must come from the release runner",
            ackCall.contains("release.disposition("))
        assertTrue(ackCall.contains("interfacesClosed = vpnInterface == null && retainedKillSwitchInterface == null"))
        // Every engine stop and every releasing close of the pass goes
        // through the runner, never around it.
        val runner = pass.indexOf("val release = WinnV3ReleaseTeardown(")
        assertTrue("the pass builds no release runner", runner >= 0 && runner < closeInterface)
        assertTrue(pass.contains("release.stopFallback()"))
        assertTrue(pass.contains("release.stopEngines()"))
        assertTrue(pass.contains("release.close(\"Retained interface close\", retainedKillSwitchInterface)"))
        val body = pass.substring(runner)
        for (direct in listOf("\n                stopXrayTransport()", "\n                    stopWinnBridge()",
            "\n                    stopAwgEngine()")) {
            assertEquals("a direct $direct bypasses the runner", -1, body.indexOf(direct))
        }
        assertTrue(pass.contains("release.evidence.fail(\"teardown pass: IOException\")"))
        // Every interface close in the pass, the hold cleanup and the close
        // after a refused hold notification included, is recorded evidence:
        // no raw close of either interface remains anywhere in the pass.
        for (raw in listOf("vpnInterface?.close()", "retainedKillSwitchInterface?.close()",
            "vpnInterface.close()", "retainedKillSwitchInterface.close()")) {
            assertEquals("a raw $raw in the pass bypasses the evidence", -1, pass.indexOf(raw))
        }
        assertTrue(Regex("""release\.close\(\s*"Retained interface close before blocking replacement",\s*retained,\s*\)""")
            .containsMatchIn(pass))
        assertTrue(Regex("""release\.close\(\s*"Prior capture interface close under a blocking hold",\s*prior,\s*\)""")
            .containsMatchIn(pass))
        assertTrue(pass.contains("release.close(\"Narrow interface close after a refused hold\", prior)"))
        assertTrue(pass.contains("release.close(\"Capture interface close after a refused hold\", vpnInterface)"))
        assertTrue("the pass must carry the process-wide debt", pass.contains("debt = winn3CleanupDebt,"))
        // The debt is cleared only when a new session begins.
        assertEquals(2, Regex("""winn3CleanupDebt\.clear\(\)""").findAll(source).count())
        // Round L turn 4: the runner (which opens the pass in the debt) is the
        // pass's FIRST statement, and the finally's finalization calls sit
        // between the refused-hold close and disposition(), which is the
        // order WinnV3ReleaseTeardownTest's serviceShapedPass extracts.
        val passBody = pass.substring(pass.indexOf("fun runTeardownPass(plan: WinnV3CaptureCustody.Plan): Boolean {"))
        val firstStatement = passBody.lines().drop(1).first { it.isNotBlank() && !it.trim().startsWith("//") }.trim()
        assertEquals("val release = WinnV3ReleaseTeardown(", firstStatement)
        val theFinally = passBody.indexOf("} finally {")
        val refusedClose = passBody.indexOf("release.close(\"Capture interface close after a refused hold\", vpnInterface)")
        val stopForeground = passBody.indexOf("stopForeground(STOP_FOREGROUND_REMOVE)", refusedClose)
        val stopSelf = passBody.indexOf("stopSelf()", stopForeground)
        assertTrue(theFinally in 0 until refusedClose)
        assertTrue(stopForeground > refusedClose && stopSelf > stopForeground)
        assertTrue("disposition() must come after the whole finally",
            source.indexOf("release.disposition(", source.indexOf("fun runTeardownPass")) > source.indexOf(
                "stopSelf()", source.indexOf("stopForeground(STOP_FOREGROUND_REMOVE)", source.indexOf(
                    "release.close(\"Capture interface close after a refused hold\"")) + 1))
        // The engine thread's retirement awaits its bridge close to its END.
        assertTrue(source.contains("bridge?.awaitCloseCompleted(WinnV3ReleaseTeardown.BRIDGE_CLOSE_WAIT_MS) == false"))

        // A new connect that takes the held interface over ends the hold
        // without releasing it.
        val supersede = source.indexOf("winn3HostLifecycle.supersede()")
        val superseded = source.indexOf("winn3ReleaseLedger.passCompleted(WinnV3ReleaseLedger.Disposition.SUPERSEDED)")
        assertTrue(supersede >= 0 && superseded > supersede)

        // The app reads it through getTunnelReadiness.
        assertTrue(source("MainActivity.kt").contains("+ claimFields + VpnTunnelService.currentReleaseFields()"))
    }

    private fun source(name: String): String {
        val candidates = listOf(
            File("src/main/kotlin/org/winsvpn/app/$name"),
            File("app/src/main/kotlin/org/winsvpn/app/$name"),
            File("android/app/src/main/kotlin/org/winsvpn/app/$name"),
        )
        return (candidates.firstOrNull { it.isFile }
            ?: error("$name not found from ${File(".").absolutePath}")).readText()
    }
}
