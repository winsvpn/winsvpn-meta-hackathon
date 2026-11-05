package org.winsvpn.app

import java.io.File
import java.io.FileDescriptor
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round A3: who may end a promoted Winn v3 session's capture, and in which
 * order competing requests take effect. Each scenario the Round A3 verdict
 * names is driven through [WinnV3CaptureCustody] and [WinnV3HostLifecycleBoard]
 * exactly as VpnTunnelService drives them: a request under the teardown lock
 * with the in-flight flag, one pass per plan, `afterPass` with what the pass
 * left held, and owner-checked publications from the session loop.
 */
class WinnV3CaptureCustodyTest {

    private val auto = WinnV3TeardownCause.AUTOMATIC

    // Observations published straight to a board (no watch in the test),
    // stamped with increasing revisions as a watch would stamp them.
    private var revision = 0L
    private fun obs(
        verdict: WinnV3LifecycleWatch.Verdict,
        observer: WinnV3LifecycleObserver? = null,
        cause: String? = null,
    ) = WinnV3LifecycleWatch.Observation(verdict, observer, cause, ++revision)

    /**
     * VpnTunnelService's teardown, minus Android: the REAL
     * [WinnV3TeardownWorker] and [WinnV3CaptureCustody] under one lock, with
     * the service's callbacks, and a pass that makes the same decisions
     * `runTeardownPass` makes (kill-switch policy or capture hold, the queued
     * revocation check, the notification outcome, the board updates).
     */
    private class Service(atTransition: (Service) -> Unit = {}) {
        val lock = Any()
        val custody = WinnV3CaptureCustody()
        val board = WinnV3HostLifecycleBoard()
        @Volatile var tearingDown = false
        var generation = 1
        var retirements = 0
        val passes = mutableListOf<WinnV3CaptureCustody.Plan>()
        val worker: WinnV3TeardownWorker = WinnV3TeardownWorker(
            lock = lock,
            custody = custody,
            onPlanStarted = {
                tearingDown = true
                generation += 1
            },
            onRetired = {
                tearingDown = false
                retirements += 1
            },
            atTransition = { atTransition(this) },
        )

        fun request(
            cause: WinnV3TeardownCause,
            allowBlockPosture: Boolean = cause.rank < 2,
            keepVpnLauncher: Boolean = true,
        ): WinnV3CaptureCustody.Plan? = worker.submit(cause, keepVpnLauncher, allowBlockPosture)

        /**
         * One pass. [killSwitchArmed] is the live kill-switch policy;
         * [notification] is what posting the hold's notification returned.
         * Returns whether an interface is left held.
         */
        fun pass(
            plan: WinnV3CaptureCustody.Plan,
            killSwitchArmed: Boolean = false,
            notification: WinnV3CaptureCustody.NotificationResult =
                WinnV3CaptureCustody.NotificationResult.POSTED,
            duringEngineStop: () -> Unit = {},
            afterHold: () -> Unit = {},
        ): Boolean {
            passes += plan
            custody.releaseLimitationFor(plan.cause)?.let { board.releaseHeldCapture(it) }
            if (!plan.holdCapture) board.clear()
            var hold = plan.allowBlockPosture && (plan.holdCapture || killSwitchArmed)
            duringEngineStop()
            var outrankedBy: String? = null
            if (hold && !custody.blockPostureStillAllowed(plan)) {
                hold = false
                outrankedBy = custody.outrankingLimitation() ?: WinnV3CaptureCustody.LIMITATION_SERVICE_DESTROYED
            }
            if (!hold) {
                if (plan.holdCapture) {
                    board.holdCapture(false, outrankedBy ?: WinnV3CaptureCustody.LIMITATION_NO_BLOCKING_INTERFACE)
                }
                return false
            }
            val keep = if (plan.holdCapture) {
                board.holdCapture(true, null)
                val outcome = WinnV3CaptureCustody.holdOutcome(notification)
                board.holdCapture(outcome.keepCapture, outcome.limitation)
                outcome.keepCapture
            } else {
                notification == WinnV3CaptureCustody.NotificationResult.POSTED
            }
            if (keep) afterHold()
            return keep
        }

        /** The teardown thread: the worker drains every pass, then retires. */
        fun runTeardown(
            first: WinnV3CaptureCustody.Plan,
            killSwitchArmed: Boolean = false,
            notification: WinnV3CaptureCustody.NotificationResult =
                WinnV3CaptureCustody.NotificationResult.POSTED,
            duringFirstEngineStop: () -> Unit = {},
            afterFirstHold: () -> Unit = {},
        ): Boolean {
            var held = false
            var firstPass = true
            worker.drain(first, { plan ->
                val isFirst = firstPass
                firstPass = false
                held = pass(
                    plan,
                    killSwitchArmed,
                    notification,
                    if (isFirst) duringFirstEngineStop else ({}),
                    if (isFirst) afterFirstHold else ({}),
                )
                held
            })
            return held
        }

        /** executeTunnelTeardown: submit, and run a new worker if one is needed. */
        fun teardown(
            cause: WinnV3TeardownCause,
            killSwitchArmed: Boolean = false,
            notification: WinnV3CaptureCustody.NotificationResult =
                WinnV3CaptureCustody.NotificationResult.POSTED,
        ): Boolean? = request(cause)?.let { runTeardown(it, killSwitchArmed, notification) }

        fun promote(owner: Int) {
            board.begin(owner)
            custody.markPromoted(owner)
        }
    }

    // ---- an unsolicited end holds capture however it arrives ---------------

    @Test
    fun `a terminal failure between two polls holds capture though recovery was never sampled`() {
        val service = Service()
        val session = service.generation
        service.promote(session)
        val watch = WinnV3LifecycleWatch()
        // The last poll saw connected; the round then ended terminally and the
        // process went away before the next poll.
        val connected = WinnV3EngineStatus.parse("""{"gate_state":"carrying","rx_packets":4,"lifecycle":"connected"}""")
        assertEquals(WinnV3LifecycleWatch.Verdict.CONNECTED, watch.observe(connected, 1_000L))
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.CHANGED,
            service.board.publish(session, obs(watch.lastVerdict(), watch.blockedObserver(), watch.blockedCause())),
        )

        val plan = service.request(auto)!!
        assertTrue("an automatic end of a promoted session holds capture", plan.holdCapture)
        assertTrue(service.runTeardown(plan))
        val snapshot = service.board.snapshot()
        assertEquals(WinnV3Lifecycle.BLOCKED, snapshot.state)
        assertEquals(WinnV3LifecycleObserver.SESSION_ENDED, snapshot.observer)
        assertTrue(snapshot.captureHeld)
        assertTrue(snapshot.actionRequired())
        assertFalse(snapshot.permitsConnectedClaim())
    }

    @Test
    fun `an Error frame before any status holds capture on the real bridge`() {
        val harness = BridgeHarness()
        try {
            harness.bridge.start()
            val service = Service()
            val session = service.generation
            service.promote(session)
            // The engine answers the first host packet after `blocked` with an
            // Error frame; no status reached the host first.
            harness.engine.push(WinnFraming.OP_ERROR, "winn3: session is blocked".toByteArray())
            val deadline = System.currentTimeMillis() + 5_000
            while (harness.bridge.isRunning() && System.currentTimeMillis() < deadline) Thread.sleep(10)
            assertFalse("the Error frame must stop the bridge", harness.bridge.isRunning())
            // What the engine thread's loop exit and catch do next.
            val plan = service.request(auto)!!
            assertTrue(plan.holdCapture)
            assertTrue(service.runTeardown(plan))
            assertTrue(service.board.snapshot().captureHeld)
            assertEquals(WinnV3LifecycleObserver.SESSION_ENDED, service.board.snapshot().observer)
        } finally {
            harness.close()
        }
    }

    @Test
    fun `an engine-reported blocked keeps the engine's observation through the hold`() {
        val service = Service()
        val session = service.generation
        service.promote(session)
        val watch = WinnV3LifecycleWatch()
        watch.observe(WinnV3EngineStatus.parse("""{"gate_state":"closed","rx_packets":0,"lifecycle":"blocked","lifecycle_cause":"budget_spent"}"""), 0L)
        service.board.publish(session, obs(watch.lastVerdict(), watch.blockedObserver(), watch.blockedCause()))
        service.runTeardown(service.request(auto)!!)
        val snapshot = service.board.snapshot()
        assertEquals(WinnV3LifecycleObserver.ENGINE, snapshot.observer)
        assertEquals("budget_spent", snapshot.cause)
        assertTrue(snapshot.captureHeld)
    }

    @Test
    fun `the visibility watchdog and every other automatic caller hold a promoted session`() {
        // VpnTunnelService's visibility branch calls executeTunnelTeardown with
        // no cause at all, which is AUTOMATIC; so do the engine-health branch,
        // the engine thread, the camouflage refresh and onTaskRemoved.
        val service = Service()
        service.promote(service.generation)
        val plan = service.request(auto)!!
        assertTrue(plan.holdCapture)
        assertTrue(plan.allowBlockPosture)
        assertTrue(service.runTeardown(plan, killSwitchArmed = false))

        // Before promotion nothing is held by this rule: the staged start's
        // own verdict owns that path, and the kill switch keeps its old rule.
        val fresh = Service()
        val before = fresh.request(auto)!!
        assertFalse(before.holdCapture)
        assertFalse(fresh.runTeardown(before, killSwitchArmed = false))
        assertEquals(WinnV3HostLifecycleBoard.Snapshot(), fresh.board.snapshot())
    }

    @Test
    fun `the service passes a cause only for the owner, the OS and process death`() {
        val source = serviceSource()
        val calls = Regex("""executeTunnelTeardown\(([^)]*)\)""").findAll(source)
            .map { it.groupValues[1] }
            .filter { !it.contains("keepVpnLauncher: Boolean") }
            .toList()
        assertTrue("the call sites were not found; this guard would be vacuous", calls.size >= 15)
        val withCause = calls.filter { it.contains("cause =") }
        assertEquals(withCause.toString(), 2, withCause.size)
        assertTrue(withCause.any { it.contains("WinnV3TeardownCause.OS_REVOKE") })
        assertTrue(withCause.any { it.contains("WinnV3TeardownCause.PROCESS_DESTROY") })
        assertFalse("no call site may opt out of custody", source.contains("holdCapture = "))
        // The disconnect body is multi-line, so check it separately.
        val disconnect = source.substring(source.indexOf("if (action == \"ACTION_DISCONNECT\")"))
        assertTrue(disconnect.substring(0, 700).contains("cause = WinnV3TeardownCause.OWNER_DISCONNECT"))
    }

    // ---- the foreground notification --------------------------------------

    @Test
    fun `a notification failure never silently turns a hold into a release`() {
        // The disguise refused: released, and the app is told why.
        val refused = Service()
        refused.promote(refused.generation)
        assertFalse(refused.runTeardown(
            refused.request(auto)!!,
            notification = WinnV3CaptureCustody.NotificationResult.DISGUISE_REFUSED,
        ))
        val released = refused.board.snapshot()
        assertFalse(released.captureHeld)
        assertEquals(WinnV3CaptureCustody.LIMITATION_DISGUISE_REFUSED, released.limitation)
        assertEquals(WinnV3Lifecycle.BLOCKED, released.state)
        assertEquals(false, released.readinessFields()[WinnV3HostLifecycleBoard.KEY_CAPTURE_HELD])
        assertEquals(
            WinnV3CaptureCustody.LIMITATION_DISGUISE_REFUSED,
            released.readinessFields()[WinnV3HostLifecycleBoard.KEY_LIMITATION],
        )

        // The platform threw: kept, under the notification posted at connect,
        // and the app is told the hold is not guaranteed.
        val threw = Service()
        threw.promote(threw.generation)
        assertTrue(threw.runTeardown(
            threw.request(auto)!!,
            notification = WinnV3CaptureCustody.NotificationResult.PLATFORM_FAILED,
        ))
        val kept = threw.board.snapshot()
        assertTrue(kept.captureHeld)
        assertEquals(WinnV3CaptureCustody.LIMITATION_FOREGROUND_REFRESH_FAILED, kept.limitation)
    }

    // ---- owner and OS precedence -------------------------------------------

    @Test
    fun `a disconnect that arrives during a teardown is queued and then releases the hold`() {
        val service = Service()
        service.promote(service.generation)
        val first = service.request(auto)!!
        var queuedPlan: WinnV3CaptureCustody.Plan? = first
        val held = service.runTeardown(first, duringFirstEngineStop = {
            // ACTION_DISCONNECT lands while the hold teardown is stopping engines.
            queuedPlan = service.request(WinnV3TeardownCause.OWNER_DISCONNECT)
        })
        assertNull("the disconnect was queued, not run twice at once", queuedPlan)
        assertEquals(
            listOf(WinnV3TeardownCause.AUTOMATIC, WinnV3TeardownCause.OWNER_DISCONNECT),
            service.passes.map { it.cause },
        )
        assertFalse("the follow-up owner pass holds no capture", service.passes[1].holdCapture)
        assertFalse(held)
        assertEquals(WinnV3HostLifecycleBoard.Snapshot(), service.board.snapshot())
        assertFalse(service.custody.isPromoted())
    }

    @Test
    fun `a queued disconnect after a pass that released everything is already satisfied`() {
        val service = Service()
        val first = service.request(auto)!!
        service.runTeardown(first, duringFirstEngineStop = {
            service.request(WinnV3TeardownCause.OWNER_DISCONNECT)
        })
        assertEquals(1, service.passes.size)
    }

    @Test
    fun `an armed kill switch still holds after the owner's disconnect, by the old rule`() {
        val service = Service()
        service.promote(service.generation)
        val plan = service.request(WinnV3TeardownCause.OWNER_DISCONNECT)!!
        assertFalse(plan.holdCapture)
        assertTrue(service.runTeardown(plan, killSwitchArmed = true))
        assertEquals(WinnV3HostLifecycleBoard.Snapshot(), service.board.snapshot())
    }

    @Test
    fun `a revocation during an in-flight hold wins before the hold is built`() {
        val service = Service()
        service.promote(service.generation)
        val first = service.request(auto)!!
        val held = service.runTeardown(first, killSwitchArmed = true, duringFirstEngineStop = {
            assertNull(service.request(WinnV3TeardownCause.OS_REVOKE, allowBlockPosture = false))
        })
        assertFalse("revocation outranks both the capture hold and the kill switch", held)
        assertEquals("the revocation was satisfied by the pass it outranked", 1, service.passes.size)
        val notice = service.board.snapshot()
        assertTrue("the owed hold's release is reported", notice.isReleaseNotice())
        assertEquals(WinnV3CaptureCustody.LIMITATION_VPN_PERMISSION_REVOKED, notice.limitation)
    }

    private fun lateOsReleaseIsReported(cause: WinnV3TeardownCause, limitation: String) {
        val service = Service()
        service.promote(service.generation)
        val first = service.request(auto)!!
        val held = service.runTeardown(first, killSwitchArmed = true, afterFirstHold = {
            // The hold is built; the OS request queues before the queue is inspected.
            assertNull(service.request(cause, allowBlockPosture = false))
        })
        assertEquals(listOf(WinnV3TeardownCause.AUTOMATIC, cause), service.passes.map { it.cause })
        assertFalse(service.passes[1].allowBlockPosture)
        assertFalse(service.passes[1].holdCapture)
        assertFalse("the $cause released everything", held)
        assertFalse(service.tearingDown)
        val notice = service.board.snapshot()
        assertTrue("$cause after the hold was built must leave a release notice", notice.isReleaseNotice())
        assertEquals(limitation, notice.limitation)
        val readiness = VpnTunnelService.readinessClaimFields(false, false, false, notice)
        assertEquals(false, readiness[WinnV3HostLifecycleBoard.KEY_CAPTURE_HELD])
        assertEquals(true, readiness[WinnV3HostLifecycleBoard.KEY_ACTION_REQUIRED])
        assertEquals(limitation, readiness[WinnV3HostLifecycleBoard.KEY_LIMITATION])
        assertEquals("blocked", readiness[WinnV3HostLifecycleBoard.KEY_LIFECYCLE])
        // ...and it survives the service's later cleanup.
        service.teardown(WinnV3TeardownCause.PROCESS_DESTROY)
        assertEquals(limitation, service.board.snapshot().limitation)
    }

    @Test
    fun `a revocation that lands after the hold was built runs as a follow-up and releases`() {
        lateOsReleaseIsReported(WinnV3TeardownCause.OS_REVOKE, WinnV3CaptureCustody.LIMITATION_VPN_PERMISSION_REVOKED)
    }

    @Test
    fun `a destruction that lands after the hold was built runs as a follow-up and is reported`() {
        lateOsReleaseIsReported(WinnV3TeardownCause.PROCESS_DESTROY, WinnV3CaptureCustody.LIMITATION_SERVICE_DESTROYED)
    }

    @Test
    fun `revoking or destroying a steady hold is reported, the owner's Disconnect is acknowledged`() {
        for ((cause, limitation) in listOf(
            WinnV3TeardownCause.OS_REVOKE to WinnV3CaptureCustody.LIMITATION_VPN_PERMISSION_REVOKED,
            WinnV3TeardownCause.PROCESS_DESTROY to WinnV3CaptureCustody.LIMITATION_SERVICE_DESTROYED,
        )) {
            val service = Service()
            service.promote(service.generation)
            assertTrue(service.teardown(auto)!!)
            assertEquals(false, service.teardown(cause))
            assertEquals("$cause", limitation, service.board.snapshot().limitation)
            assertTrue(service.board.snapshot().isReleaseNotice())
        }
        val owner = Service()
        owner.promote(owner.generation)
        assertTrue(owner.teardown(auto)!!)
        owner.teardown(WinnV3TeardownCause.OWNER_DISCONNECT)
        assertEquals("an owner release is acknowledged, not a notice", WinnV3HostLifecycleBoard.Snapshot(), owner.board.snapshot())
        assertNull(WinnV3CaptureCustody().releaseLimitationFor(WinnV3TeardownCause.OWNER_DISCONNECT))
        assertNull(WinnV3CaptureCustody().releaseLimitationFor(WinnV3TeardownCause.AUTOMATIC))
    }

    @Test
    fun `the service publishes the late OS release before it clears the board`() {
        val source = serviceSource()
        val pass = source.substring(source.indexOf("fun runTeardownPass(plan: WinnV3CaptureCustody.Plan): Boolean {"))
        val release = pass.indexOf("winn3HostLifecycle.releaseHeldCapture(limitation)")
        val clear = pass.indexOf("if (!plan.holdCapture) winn3HostLifecycle.clear()")
        assertTrue(release > 0)
        assertTrue("published BEFORE the clear", release < clear)
    }

    // ---- Android publication order ------------------------------------------

    @Test
    fun `a connected decided before a blocked can never be published over it`() {
        val board = WinnV3HostLifecycleBoard()
        val owner = 5
        board.begin(owner)
        val binding = WinnV3LifecycleBinding(WinnV3LifecycleWatch(), owner)
        val lock = Any()
        fun publish(o: WinnV3LifecycleWatch.Observation) =
            synchronized(lock) { WinnV3PostPromotionStep.publish(board, binding, true, o) }
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.CHANGED,
            publish(WinnV3PostPromotionStep.judge(binding, doc("connected"), 1_000L)),
        )
        val decided = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        var stale: WinnV3HostLifecycleBoard.Publication? = null
        // The engine loop: decides CONNECTED, then is paused before it takes the lock.
        val engine = Thread {
            val observation = WinnV3PostPromotionStep.judge(binding, doc("connected"), 2_000L)
            decided.countDown()
            resume.await()
            stale = publish(observation)
        }.apply { start() }
        assertTrue(decided.await(5, java.util.concurrent.TimeUnit.SECONDS))
        // The health check: observes stopped on the same watch and publishes.
        val health = Thread {
            val observation = binding.watch.observation(
                WinnV3EngineStatus.parse(doc("stopped")),
                2_500L,
            )
            publish(observation)
        }.apply { start() }
        health.join(5_000)
        assertEquals(WinnV3Lifecycle.BLOCKED, board.snapshot().state)
        assertEquals(WinnV3LifecycleObserver.SESSION_ENDED, board.snapshot().observer)
        resume.countDown()
        engine.join(5_000)
        assertEquals("the older CONNECTED was refused", WinnV3HostLifecycleBoard.Publication.OBSOLETE, stale)
        assertEquals("blocked stands", WinnV3Lifecycle.BLOCKED, board.snapshot().state)
        assertEquals(false, VpnTunnelService.readinessClaimFields(true, true, true, board.snapshot())["active"])
    }

    @Test
    fun `blocked is terminal for its session, whatever the revision`() {
        val board = WinnV3HostLifecycleBoard()
        board.begin(1)
        assertEquals(WinnV3HostLifecycleBoard.Publication.CHANGED, board.publish(1, obs(WinnV3LifecycleWatch.Verdict.BLOCKED, WinnV3LifecycleObserver.ENGINE, "terminal")))
        for (verdict in listOf(
            WinnV3LifecycleWatch.Verdict.CONNECTED,
            WinnV3LifecycleWatch.Verdict.RECOVERING,
            WinnV3LifecycleWatch.Verdict.UNREPORTED,
        )) {
            assertEquals("$verdict after blocked", WinnV3HostLifecycleBoard.Publication.OBSOLETE, board.publish(1, obs(verdict)))
        }
        assertEquals(WinnV3Lifecycle.BLOCKED, board.snapshot().state)
        assertEquals("terminal", board.snapshot().cause)
        // An equal or older revision is obsolete too.
        val stale = WinnV3LifecycleWatch.Observation(WinnV3LifecycleWatch.Verdict.BLOCKED, null, null, 1)
        assertEquals(WinnV3HostLifecycleBoard.Publication.OBSOLETE, board.publish(1, stale))
        // A new session starts clean.
        board.begin(2)
        assertEquals(WinnV3HostLifecycleBoard.Publication.CHANGED, board.publish(2, obs(WinnV3LifecycleWatch.Verdict.CONNECTED)))
    }

    @Test
    fun `a binding from a replaced session can publish nothing over its successor`() {
        val board = WinnV3HostLifecycleBoard()
        val old = WinnV3LifecycleBinding(WinnV3LifecycleWatch(), 7)
        board.begin(old.owner)
        WinnV3PostPromotionStep.publish(board, old, true, WinnV3PostPromotionStep.judge(old, doc("connected"), 1_000L))
        // A configuration replacement: the board and the binding both move on.
        board.supersede()
        val replacement = WinnV3LifecycleBinding(WinnV3LifecycleWatch(), 8)
        board.begin(replacement.owner)
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.CHANGED,
            WinnV3PostPromotionStep.publish(board, replacement, true, WinnV3PostPromotionStep.judge(replacement, doc("connected"), 1_000L)),
        )
        // The health check read the OLD pair before the replacement; its later
        // (even BLOCKED, even newer-revision) observation is refused.
        val late = old.watch.observation(WinnV3EngineStatus.parse(doc("stopped")), 2_000L)
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, late.verdict)
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.REJECTED,
            WinnV3PostPromotionStep.publish(board, old, true, late),
        )
        assertEquals(WinnV3Lifecycle.CONNECTED, board.snapshot().state)
        // And the service validates the SAME pair it captured.
        val source = serviceSource()
        val check = source.substring(source.indexOf("private fun currentEngineHandleHealthy(): Boolean")).take(4_500)
        assertTrue(check.contains("winnV3LifecycleBinding === binding"))
        assertTrue(check.contains("binding = binding,"))
        assertFalse(source.contains("winnV3LifecycleWatchOwner"))
    }

    @Test
    fun `a revocation of a steady hold releases and holds nothing`() {
        val service = Service()
        service.promote(service.generation)
        assertTrue(service.runTeardown(service.request(auto)!!))
        val revoke = service.request(WinnV3TeardownCause.OS_REVOKE, allowBlockPosture = false)!!
        assertFalse(revoke.allowBlockPosture)
        assertFalse(service.runTeardown(revoke, killSwitchArmed = true))
        // PROCESS_DESTROY is ranked with revocation.
        assertEquals(WinnV3TeardownCause.OS_REVOKE.rank, WinnV3TeardownCause.PROCESS_DESTROY.rank)
    }

    @Test
    fun `an automatic request during an in-flight teardown adds nothing`() {
        val service = Service()
        service.promote(service.generation)
        val first = service.request(auto)!!
        service.runTeardown(first, duringFirstEngineStop = { service.request(auto) })
        assertEquals(1, service.passes.size)
    }

    // ---- the worker's retirement: no request lost -----------------------------

    /**
     * Runs [block] on its own thread and returns once that thread is parked
     * waiting for a monitor, which here can only be the teardown lock.
     */
    private class Contender<T>(block: () -> T) {
        @Volatile var result: T? = null
        @Volatile private var done = false
        private val thread = Thread {
            result = block()
            done = true
        }.apply {
            isDaemon = true
            start()
        }

        init {
            val deadline = System.currentTimeMillis() + 5_000
            while (thread.state != Thread.State.BLOCKED && !done && System.currentTimeMillis() < deadline) {
                Thread.sleep(1)
            }
            check(thread.state == Thread.State.BLOCKED) {
                "the contender never parked on the teardown lock (state ${thread.state}, done=$done)"
            }
        }

        fun await(): T? {
            thread.join(5_000)
            check(!thread.isAlive) { "the contender never got the lock" }
            return result
        }
    }

    private fun lateRequestIsNotLost(cause: WinnV3TeardownCause) {
        var contender: Contender<WinnV3CaptureCustody.Plan?>? = null
        val service = Service(atTransition = { s ->
            // Inside the worker's last transition: the queue has just been
            // inspected and found empty, and the worker has not retired. This
            // is the window v2 lost the request in.
            if (contender == null) {
                contender = Contender { s.request(cause, allowBlockPosture = cause.rank < 2) }
            }
        })
        service.promote(service.generation)
        val first = service.request(auto)!!
        assertTrue("the automatic pass holds capture", service.runTeardown(first, killSwitchArmed = true))
        assertEquals("the worker retired exactly once", 1, service.retirements)
        val late = contender!!.await()
        assertNotNull("a $cause landing after the last queue inspection was lost", late)
        assertEquals(cause, late!!.cause)
        assertTrue("the late request owns a new worker", service.tearingDown)
        assertFalse("the late request releases the hold", service.runTeardown(late))
        assertFalse(service.tearingDown)
        assertEquals(listOf(WinnV3TeardownCause.AUTOMATIC, cause), service.passes.map { it.cause })
    }

    @Test
    fun `a disconnect between the last queue inspection and retirement is not lost`() {
        lateRequestIsNotLost(WinnV3TeardownCause.OWNER_DISCONNECT)
    }

    @Test
    fun `a revocation between the last queue inspection and retirement is not lost`() {
        lateRequestIsNotLost(WinnV3TeardownCause.OS_REVOKE)
    }

    @Test
    fun `a pass that throws still lets a queued request run, and the worker still retires`() {
        val service = Service()
        service.promote(service.generation)
        val first = service.request(auto)!!
        val ran = mutableListOf<WinnV3TeardownCause>()
        service.worker.drain(first, { plan ->
            ran += plan.cause
            if (plan.cause == WinnV3TeardownCause.AUTOMATIC) {
                assertNull(service.request(WinnV3TeardownCause.OWNER_DISCONNECT))
                throw IllegalStateException("a platform call threw mid-pass")
            }
            false
        })
        assertEquals(listOf(WinnV3TeardownCause.AUTOMATIC, WinnV3TeardownCause.OWNER_DISCONNECT), ran)
        assertFalse(service.tearingDown)
        assertEquals(1, service.retirements)
    }

    @Test
    fun `a same-rank request after a pass that held runs, with the owner's latest intent`() {
        val service = Service()
        val first = service.request(WinnV3TeardownCause.OWNER_DISCONNECT, keepVpnLauncher = true)!!
        service.runTeardown(first, killSwitchArmed = true, afterFirstHold = {
            assertNull(service.request(WinnV3TeardownCause.OWNER_DISCONNECT, keepVpnLauncher = false))
        })
        assertEquals(2, service.passes.size)
        assertFalse("the later keepVpnLauncher wins", service.passes[1].keepVpnLauncher)
    }

    // ---- a release notice survives the service's own end --------------------

    @Test
    fun `a disguise release is still reported after the service is destroyed`() {
        val service = Service()
        service.promote(service.generation)
        assertEquals(false, service.teardown(auto, notification = WinnV3CaptureCustody.NotificationResult.DISGUISE_REFUSED))
        // stopSelf() -> onDestroy() -> PROCESS_DESTROY, on a new worker.
        assertEquals(false, service.teardown(WinnV3TeardownCause.PROCESS_DESTROY))
        val notice = service.board.snapshot()
        assertTrue(notice.isReleaseNotice())
        assertEquals(WinnV3CaptureCustody.LIMITATION_DISGUISE_REFUSED, notice.limitation)
        val readiness = VpnTunnelService.readinessClaimFields(false, false, false, notice)
        assertEquals(false, readiness[WinnV3HostLifecycleBoard.KEY_CAPTURE_HELD])
        assertEquals(WinnV3CaptureCustody.LIMITATION_DISGUISE_REFUSED, readiness[WinnV3HostLifecycleBoard.KEY_LIMITATION])
        assertEquals(true, readiness[WinnV3HostLifecycleBoard.KEY_ACTION_REQUIRED])
        // A later automatic end of the stopped service keeps it too.
        service.teardown(auto)
        assertTrue(service.board.snapshot().isReleaseNotice())
    }

    @Test
    fun `a destruction that lands while the hold is being built is itself reported`() {
        val service = Service()
        service.promote(service.generation)
        val first = service.request(auto)!!
        val held = service.runTeardown(first, duringFirstEngineStop = {
            // onDestroy while the promoted session's teardown is in flight.
            assertNull(service.request(WinnV3TeardownCause.PROCESS_DESTROY))
        })
        assertFalse(held)
        assertEquals("nothing was held, so the queued destruction adds no pass", 1, service.passes.size)
        val notice = service.board.snapshot()
        assertTrue("the release of an owed hold is not silent", notice.isReleaseNotice())
        assertEquals(WinnV3CaptureCustody.LIMITATION_SERVICE_DESTROYED, notice.limitation)
    }

    @Test
    fun `a release notice ends only when the owner acknowledges it or a new session supersedes it`() {
        val board = WinnV3HostLifecycleBoard()
        fun released() {
            board.begin(3)
            board.holdCapture(held = false, limitation = WinnV3CaptureCustody.LIMITATION_DISGUISE_REFUSED)
        }
        released()
        board.clear()
        assertTrue("an automatic end keeps it", board.snapshot().isReleaseNotice())
        board.acknowledgeReleaseNotice()
        assertEquals("the owner's Disconnect acknowledges it", WinnV3HostLifecycleBoard.Snapshot(), board.snapshot())
        released()
        board.supersede()
        assertEquals("a new connect supersedes it", WinnV3HostLifecycleBoard.Snapshot(), board.snapshot())
        released()
        board.begin(4)
        assertEquals("a new session supersedes it", WinnV3HostLifecycleBoard.Snapshot(), board.snapshot())
        // A HELD capture is not a notice: an owner's pass clears it as before.
        board.holdCapture(held = true, limitation = null)
        board.clear()
        assertEquals(WinnV3HostLifecycleBoard.Snapshot(), board.snapshot())
    }

    @Test
    fun `the service acknowledges on Disconnect and supersedes on connect`() {
        val source = serviceSource()
        val disconnect = source.substring(source.indexOf("if (action == \"ACTION_DISCONNECT\")")).take(600)
        assertTrue(disconnect.contains("winn3HostLifecycle.acknowledgeReleaseNotice()"))
        val reset = source.substring(source.indexOf("private fun resetTunnelBeforeConnect()")).take(2_500)
        assertTrue(reset.contains("winn3HostLifecycle.supersede()"))
        assertFalse(reset.contains("winn3HostLifecycle.clear()"))
    }

    // ---- post-promotion non-live states, watch -> board -> readiness ----------

    private fun doc(lifecycle: String?) =
        if (lifecycle == null) """{"gate_state":"carrying","rx_packets":6}"""
        else """{"gate_state":"carrying","rx_packets":6,"lifecycle":"$lifecycle"}"""

    private fun nonLiveEndsTheClaim(lifecycle: String?, observer: WinnV3LifecycleObserver) {
        val service = Service()
        val owner = service.generation
        service.promote(owner)
        val binding = WinnV3LifecycleBinding(WinnV3LifecycleWatch(), owner)
        fun step(json: String, now: Long): Pair<WinnV3LifecycleWatch.Verdict, WinnV3HostLifecycleBoard.Publication> {
            val observation = WinnV3PostPromotionStep.judge(binding, json, now)
            return observation.verdict to WinnV3PostPromotionStep.publish(service.board, binding, true, observation)
        }
        val (connected, published) = step(doc("connected"), 1_000L)
        assertEquals(WinnV3LifecycleWatch.Verdict.CONNECTED, connected)
        assertEquals(WinnV3HostLifecycleBoard.Publication.CHANGED, published)
        assertEquals(true, VpnTunnelService.readinessClaimFields(true, true, true, service.board.snapshot())["active"])

        val (verdict, publication) = step(doc(lifecycle), 2_000L)
        assertEquals("post-promotion `$lifecycle` is an end", WinnV3LifecycleWatch.Verdict.BLOCKED, verdict)
        assertEquals("the connected snapshot must not survive it", WinnV3HostLifecycleBoard.Publication.CHANGED, publication)
        assertTrue("the loop ends on it", WinnV3PostPromotionStep.endsLoop(verdict, publication))
        // With service, engine and interface all still up, nothing claims connected.
        val live = VpnTunnelService.readinessClaimFields(true, true, true, service.board.snapshot())
        assertEquals(false, live["active"])
        assertEquals(false, live["tunnel_healthy"])
        assertEquals(false, live["engine_ready"])
        assertEquals(true, live[WinnV3HostLifecycleBoard.KEY_CAPTURE_HELD])
        assertEquals(true, live[WinnV3HostLifecycleBoard.KEY_ACTION_REQUIRED])
        assertEquals(observer.wire, live[WinnV3HostLifecycleBoard.KEY_OBSERVER])
        assertFalse(VpnTunnelService.tunnelHealthyFor(true, true, true, service.board.snapshot()))
        assertEquals(
            VpnTunnelService.TunnelForegroundState.BLOCKED,
            VpnTunnelService.tunnelForegroundFor(true, true, true, service.board.snapshot().state),
        )
        // The loop's end throws into the AUTOMATIC teardown, which holds.
        val plan = service.request(auto)!!
        assertTrue(plan.holdCapture)
        assertTrue(service.runTeardown(plan))
        val held = VpnTunnelService.readinessClaimFields(false, false, true, service.board.snapshot())
        assertEquals(true, held[WinnV3HostLifecycleBoard.KEY_CAPTURE_HELD])
        assertEquals(observer.wire, held[WinnV3HostLifecycleBoard.KEY_OBSERVER])
    }

    @Test
    fun `stopped after connected ends the connected claim at once as session_ended`() {
        nonLiveEndsTheClaim("stopped", WinnV3LifecycleObserver.SESSION_ENDED)
    }

    @Test
    fun `connecting after proof ends the connected claim at once as invalid_transition`() {
        nonLiveEndsTheClaim("connecting", WinnV3LifecycleObserver.INVALID_TRANSITION)
    }

    @Test
    fun `a lifecycle that disappears after connected is an invalid transition`() {
        nonLiveEndsTheClaim(null, WinnV3LifecycleObserver.INVALID_TRANSITION)
    }

    @Test
    fun `the health check publishes a post-promotion end through the same step`() {
        val source = serviceSource()
        val check = source.substring(source.indexOf("private fun currentEngineHandleHealthy(): Boolean")).take(4_000)
        assertTrue(check.contains("WinnV3PostPromotionStep.publish("))
        val thread = source.substring(source.indexOf("private fun startWinnV3EngineThread("))
        assertTrue(thread.contains("WinnV3PostPromotionStep.judge("))
        assertTrue(thread.contains("if (WinnV3PostPromotionStep.endsLoop(verdict, publication)) break"))
        assertFalse(source.contains("NOT_LIVE"))
    }

    // ---- configuration replacement racing the post-promotion loop -----------

    @Test
    fun `a replacement that lands while the loop sleeps wins every later publication`() {
        val service = Service()
        val old = service.generation
        service.promote(old)
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.CHANGED,
            service.board.publish(old, obs(WinnV3LifecycleWatch.Verdict.RECOVERING)),
        )
        // ACTION_CONNECT with a new configuration: resetTunnelBeforeConnect
        // clears custody and the board, then the new session begins.
        service.custody.clear()
        service.board.clear()
        service.generation += 1
        val replacement = service.generation
        service.board.begin(replacement)
        // The old loop wakes from Thread.sleep(1000) and tries to publish.
        for (verdict in WinnV3LifecycleWatch.Verdict.entries) {
            assertEquals(
                "the superseded session may not publish $verdict",
                WinnV3HostLifecycleBoard.Publication.REJECTED,
                service.board.publish(old, obs(verdict, WinnV3LifecycleObserver.ENGINE, "terminal")),
            )
        }
        assertEquals(WinnV3HostLifecycleBoard.Snapshot(), service.board.snapshot())
        assertFalse("the old promotion cannot make the new session hold", service.custody.isPromoted())
        // The new session publishes normally.
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.CHANGED,
            service.board.publish(replacement, obs(WinnV3LifecycleWatch.Verdict.CONNECTED)),
        )
        // And a hold ends every publication from the session it held.
        service.custody.markPromoted(replacement)
        service.runTeardown(service.request(auto)!!)
        assertEquals(
            WinnV3HostLifecycleBoard.Publication.REJECTED,
            service.board.publish(replacement, obs(WinnV3LifecycleWatch.Verdict.CONNECTED)),
        )
    }

    // ---- helpers -----------------------------------------------------------

    private fun serviceSource(): String {
        val candidates = listOf(
            File("src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt"),
            File("app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt"),
            File("android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt"),
        )
        return (candidates.firstOrNull { it.isFile }
            ?: error("VpnTunnelService.kt not found from ${File(".").absolutePath}")).readText()
    }

    /** A real WinnV3Bridge against the engine double, as WinnV3BridgeTest builds one. */
    private class BridgeHarness : AutoCloseable {
        private val pair = WinnEngineDouble.connectedPair()
        val engine = WinnEngineDouble(pair.second).also { it.start() }
        private val alive = AtomicBoolean(true)
        private val transport = LoopbackWinnTransport(pair.first)
        val bridge = WinnV3Bridge(
            host = object : WinnEngineHost {
                override fun openProtectedUnderlaySocket(): WinnUnderlaySocket = object : WinnUnderlaySocket {
                    override val protectedBeforeHandoff = true
                    override val descriptor = FileDescriptor()
                    override val localPort = 40404
                    override fun close() = Unit
                }
                override fun startEngineProcess(): WinnEngineProcess = object : WinnEngineProcess {
                    override val transport: WinnEngineTransport = this@BridgeHarness.transport
                    override fun isAlive() = alive.get()
                    override fun describe() = "double"
                    override fun close() {
                        alive.set(false)
                        this@BridgeHarness.transport.close()
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
                sessionId = "session-1",
            ),
        )

        override fun close() {
            try { bridge.close() } catch (_: Exception) {}
            try { engine.close() } catch (_: Exception) {}
            try { pair.first.close() } catch (_: Exception) {}
        }
    }

    private class ParkedSeam : WinnV3IpPacketSeam {
        private val gate = java.util.concurrent.CountDownLatch(1)
        override fun readOutgoingPacket(buffer: ByteArray): Int {
            gate.await()
            return -1
        }
        override fun writeIncomingPacket(packet: ByteArray, length: Int) = Unit
        override fun rebindDevice(device: WinnV3TunDevice) = Unit
        override fun close() = gate.countDown()
    }
}
