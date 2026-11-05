package org.winsvpn.app

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Round L (OI-L4): the release-completion acknowledgement for a held Winn v3
 * capture.
 *
 * ## Why the app needs it
 *
 * A held reconnect or a held server switch stops the held tunnel and then
 * prepares a new one, and preparation needs the control plane. While the held
 * interface is still up it is a blackhole for this app's own requests too
 * (measured on an S26, 2026-09-23), so preparation must not start before the
 * old capture is gone. None of the existing signals says that:
 *
 * - `getTunnelState` / `active` are already false while a session is held;
 * - `winn3_capture_held` and the lifecycle keys are cleared at the START of a
 *   teardown pass ([WinnV3HostLifecycleBoard.clear]), before the engines stop
 *   and before the interface is closed;
 * - a failed readiness query says nothing.
 *
 * ## What it records
 *
 * Every teardown pass of VpnTunnelService ends with exactly one
 * [passCompleted], taken after the pass's `finally` has left the interfaces in
 * their final state for that pass. A pass that keeps a Winn v3 capture hold
 * gives the hold an identity ([Snapshot.holdId], non-zero while it is
 * outstanding). A later pass that ends it records which hold it ended
 * ([Snapshot.lastHoldId]), how ([Snapshot.lastDisposition]), and advances
 * [Snapshot.sequence]. The app binds its wait to the hold id it saw before it
 * asked for the stop and to the sequence at that moment, so an acknowledgement
 * for another hold, or one that predates the request, cannot satisfy it.
 *
 * [Disposition.CLOSED] is the only release. A kill switch the owner configured
 * still turns the end of a session into a block ([Disposition.KILL_SWITCH_BLOCK]):
 * that is preserved, and it is reported as NOT released, because the
 * interface is still up and still takes the app's own traffic.
 *
 * ## Limits
 *
 * CLOSED means every required step of the pass was CONFIRMED complete
 * ([WinnV3ReleaseTeardown]): the fallback transport stopped, each engine
 * bridge close FINISHED successfully within its bound, the Winn v3 engine
 * thread finished its own retirement, every interface close the pass
 * performed returned without throwing, this service holds no interface
 * descriptor (`vpnInterface`, `retainedKillSwitchInterface`), and no earlier
 * pass left unresolved cleanup evidence ([WinnV3CleanupDebt]). Null
 * descriptor fields alone are never enough: a step that threw, timed out or
 * could not confirm itself makes the pass [Disposition.INCOMPLETE]. It is not an observation that Android has already
 * removed the VPN network. The ledger lives in the service process: a process death loses it,
 * and after a restart no hold id is published, so the app has nothing to bind
 * to and does not proceed.
 */
internal class WinnV3ReleaseLedger {

    enum class Disposition(val wire: String) {
        /** The pass left this service holding no interface: the capture is closed. */
        CLOSED("closed"),

        /** The pass kept an interface as the configured kill-switch block. Not a release. */
        KILL_SWITCH_BLOCK("kill_switch_block"),

        /** The pass built, or kept, a Winn v3 capture hold. */
        WINN3_HOLD("winn3_hold"),

        /** The pass could not leave its interfaces closed (for example, a close failed). */
        INCOMPLETE("incomplete"),

        /** A new connect took the held interface over as its own handover block. */
        SUPERSEDED("superseded"),
    }

    data class Snapshot(
        /** The outstanding Winn v3 hold, or 0 when none is outstanding. */
        val holdId: Long = 0L,
        /** Advances once per completed teardown pass (and per supersession). */
        val sequence: Long = 0L,
        /** The hold that was outstanding when the last pass completed, or 0. */
        val lastHoldId: Long = 0L,
        val lastDisposition: Disposition? = null,
    ) {
        /** The keys MainActivity adds to `getTunnelReadiness`. */
        fun readinessFields(): Map<String, Any> = linkedMapOf(
            KEY_HOLD_ID to holdId,
            KEY_SEQUENCE to sequence,
            KEY_LAST_HOLD_ID to lastHoldId,
            KEY_LAST_DISPOSITION to (lastDisposition?.wire ?: DISPOSITION_NONE),
        )
    }

    private var nextHoldId = 0L
    private var current = Snapshot()

    /** One teardown pass completed with [disposition]. */
    @Synchronized
    fun passCompleted(disposition: Disposition): Snapshot {
        val outstanding = current.holdId
        val sequence = current.sequence + 1
        current = when (disposition) {
            // A second holding pass keeps the same interface, so the same hold.
            Disposition.WINN3_HOLD -> Snapshot(
                holdId = if (outstanding != 0L) outstanding else ++nextHoldId,
                sequence = sequence,
                lastHoldId = outstanding,
                lastDisposition = disposition,
            )
            // Nothing is known to be closed: the hold stays outstanding.
            Disposition.INCOMPLETE -> Snapshot(
                holdId = outstanding,
                sequence = sequence,
                lastHoldId = outstanding,
                lastDisposition = disposition,
            )
            else -> Snapshot(
                holdId = 0L,
                sequence = sequence,
                lastHoldId = outstanding,
                lastDisposition = disposition,
            )
        }
        return current
    }

    @Synchronized
    fun snapshot(): Snapshot = current

    companion object {
        const val KEY_HOLD_ID = "winn3_hold_id"
        const val KEY_SEQUENCE = "winn3_release_sequence"
        const val KEY_LAST_HOLD_ID = "winn3_release_hold_id"
        const val KEY_LAST_DISPOSITION = "winn3_release_disposition"
        const val DISPOSITION_NONE = "none"

        /**
         * What one pass left, from the pass's own final state: whether it
         * kept a block interface, whether that block is a Winn v3 capture hold
         * (as opposed to the kill switch), whether this service still holds
         * any interface descriptor, and whether every required teardown step
         * was confirmed ([WinnV3TeardownEvidence.confirmed]).
         */
        fun dispositionOf(
            winn3HoldKept: Boolean,
            blockKept: Boolean,
            interfacesClosed: Boolean,
            teardownConfirmed: Boolean,
        ): Disposition = when {
            blockKept && winn3HoldKept -> Disposition.WINN3_HOLD
            blockKept -> Disposition.KILL_SWITCH_BLOCK
            interfacesClosed && teardownConfirmed -> Disposition.CLOSED
            else -> Disposition.INCOMPLETE
        }
    }
}

/**
 * Round L (OI-L4): a close whose completion can be awaited within a bound.
 * The bridges hand one out ([WinnV3Bridge.closeCompletion]); it answers true
 * only once that close has FINISHED and every step of it succeeded.
 */
internal fun interface WinnV3Completion {
    fun await(timeoutMs: Long): Boolean
}

/**
 * Round L (OI-L4): what one teardown pass can prove it completed.
 *
 * A step counts only when it returns true WITHOUT throwing. False is a step
 * that could not confirm its own completion; an exception is recorded and
 * handed to the step's warning. [step] never throws an [Exception], so the
 * pass carries on with the rest of its teardown exactly as before; it simply
 * can no longer claim a release. A close still running when the pass had to
 * move on is [defer]red with its [WinnV3Completion], so a later pass can
 * still see it finish (or fail).
 *
 * Every failure and every deferral is written to [debt] AT THE MOMENT it is
 * recorded, not when the pass publishes its acknowledgement: a pass that
 * throws out of its own `finally` after this point never reaches
 * [WinnV3ReleaseTeardown.disposition], and its evidence must survive it.
 */
internal class WinnV3TeardownEvidence(private val debt: WinnV3CleanupDebt? = null) {
    private val failures = mutableListOf<String>()
    private val pending = mutableListOf<Pair<String, WinnV3Completion>>()

    fun step(name: String, onFailure: (Exception) -> Unit = {}, action: () -> Boolean): Boolean {
        val done = try {
            action()
        } catch (e: Exception) {
            record("$name: ${e.javaClass.simpleName}")
            onFailure(e)
            return false
        }
        if (!done) record("$name: not confirmed")
        return done
    }

    /** A failure the pass observed outside a step (its own catch blocks). */
    fun fail(name: String) {
        record(name)
    }

    /** A close that had not finished within the pass's bound. */
    fun defer(name: String, completion: WinnV3Completion) {
        pending += name to completion
        debt?.defer(name, completion)
    }

    val confirmed: Boolean get() = failures.isEmpty() && pending.isEmpty()

    fun failures(): List<String> = failures.toList()

    private fun record(failure: String) {
        failures += failure
        debt?.fail(failure)
    }
}

/**
 * Round L (OI-L4): unresolved cleanup evidence that outlives the pass that
 * found it. A holding pass whose bridge close failed, or had not finished,
 * leaves the bridge references cleared; without this, the later release pass
 * would find nothing left to check and say CLOSED. A pass that began and
 * never reached its acknowledgement (it threw, even from its own `finally`)
 * stays open here too. Deferred closes are
 * re-checked on every later pass and drop out only once they are confirmed
 * finished and successful. A failure (an exception, an unconfirmed step, a
 * throwing close) never drops out: nothing authoritative can later prove that
 * a descriptor whose close threw is closed. The debt is cleared only when a
 * new tunnel session begins, whose own release concerns its own resources.
 */
internal class WinnV3CleanupDebt {
    private val failures = mutableListOf<String>()
    private val pending = mutableListOf<Pair<String, WinnV3Completion>>()

    // Passes that began and have not reached their acknowledgement. A pass
    // that exits exceptionally (from its body or from its own `finally`)
    // stays here, so a later pass cannot say CLOSED merely because that
    // aborted pass had already cleared the resource fields.
    private val openPasses = linkedSetOf<Long>()
    private var nextPass = 0L

    /** A teardown pass begins. Its token stays open until [endPass]. */
    @Synchronized
    fun beginPass(): Long {
        val token = ++nextPass
        openPasses += token
        return token
    }

    /** The pass holding [token] reached its acknowledgement. Idempotent. */
    @Synchronized
    fun endPass(token: Long) {
        openPasses -= token
    }

    @Synchronized
    fun fail(name: String) {
        failures += name
    }

    @Synchronized
    fun defer(name: String, completion: WinnV3Completion) {
        pending += name to completion
    }

    /** Re-checks the deferred closes without waiting; true only if nothing is unresolved. */
    @Synchronized
    fun resolve(): Boolean {
        pending.removeAll { (_, completion) ->
            try {
                completion.await(0L)
            } catch (_: Exception) {
                false
            }
        }
        return failures.isEmpty() && pending.isEmpty() && openPasses.isEmpty()
    }

    @Synchronized
    fun unresolved(): List<String> =
        failures + pending.map { it.first } + openPasses.map { "teardown pass $it did not finish" }

    @Synchronized
    fun clear() {
        failures.clear()
        pending.clear()
        openPasses.clear()
    }
}

/**
 * Round L (OI-L4): the Winn v3 engine thread's own retirement (its
 * bridge close FINISHED and succeeded, its seam closed), which that thread
 * performs in its `finally` and which a release pass must see finished before
 * it may say CLOSED. The first [finish] wins.
 */
internal class WinnV3EngineRetirement {
    private val finished = CountDownLatch(1)
    private val done = AtomicBoolean(false)
    @Volatile private var completed = false

    fun finish(completed: Boolean) {
        if (!done.compareAndSet(false, true)) return
        this.completed = completed
        finished.countDown()
    }

    /** True only if the retirement finished within [timeoutMs] and completed. */
    fun awaitCompleted(timeoutMs: Long): Boolean = try {
        finished.await(timeoutMs, TimeUnit.MILLISECONDS) && completed
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }
}

/**
 * Round L (OI-L4): the release-relevant steps of one
 * `VpnTunnelService.runTeardownPass`, run by the service itself with its real
 * operations and by the tests with injected failures. Every engine stop and
 * every interface close the pass performs (the releasing closes, the hold
 * cleanup, and the close after a refused hold notification) goes through
 * here, so its [disposition] rests on what those steps confirmed and on the
 * [debt] earlier passes left, never on descriptor fields alone.
 */
internal class WinnV3ReleaseTeardown(
    private val stopFallbackTransport: () -> Boolean,
    private val stopWinnEngines: () -> List<WinnV3Completion>,
    private val stopVpnEngine: () -> Unit,
    private val engineRetired: () -> Boolean,
    private val debt: WinnV3CleanupDebt,
    private val warn: (String, Exception) -> Unit,
    private val bridgeCloseWaitMs: Long = BRIDGE_CLOSE_WAIT_MS,
) {
    // Opened in the debt before any cleanup step can run, and closed only by
    // disposition(): any exceptional exit in between leaves it open.
    private val passToken = debt.beginPass()

    val evidence = WinnV3TeardownEvidence(debt)

    fun stopFallback() {
        evidence.step("fallback transport stop", { warn("Fallback transport stop was incomplete", it) }) {
            stopFallbackTransport()
        }
    }

    /**
     * Both engine stops, in the pass's order and with the warnings it always
     * logged. Each bridge close is awaited to its END within
     * [bridgeCloseWaitMs]; one still running is deferred, not assumed done.
     */
    fun stopEngines() {
        evidence.step("winn engine stop", { warn("Winn engine stop was incomplete", it) }) {
            for (completion in stopWinnEngines()) {
                if (!completion.await(bridgeCloseWaitMs)) evidence.defer("winn engine bridge close", completion)
            }
            true
        }
        evidence.step("vpn engine stop", { warn("VPN engine stop was incomplete", it) }) {
            stopVpnEngine()
            true
        }
    }

    /** Closes one interface. True only if [closeable] closed (or was absent) without throwing. */
    fun close(name: String, closeable: Closeable?): Boolean =
        evidence.step(name, { warn("$name was incomplete", it) }) {
            closeable?.close()
            true
        }

    /**
     * The pass's disposition. This pass's evidence is already in the [debt]
     * (it was written there as it was recorded); reaching here closes this
     * pass's own entry, and nothing else does. The engine thread's retirement
     * is awaited only when everything else already proves a release, so holds
     * and blocks never wait on it.
     */
    fun disposition(
        winn3HoldKept: Boolean,
        blockKept: Boolean,
        interfacesClosed: Boolean,
    ): WinnV3ReleaseLedger.Disposition {
        debt.endPass(passToken)
        val candidate = WinnV3ReleaseLedger.dispositionOf(
            winn3HoldKept, blockKept, interfacesClosed, debt.resolve(),
        )
        if (candidate != WinnV3ReleaseLedger.Disposition.CLOSED) return candidate
        val retired = try {
            engineRetired()
        } catch (_: Exception) {
            false
        }
        return if (retired) {
            WinnV3ReleaseLedger.Disposition.CLOSED
        } else {
            WinnV3ReleaseLedger.Disposition.INCOMPLETE
        }
    }

    companion object {
        /** How long a release pass waits for the Winn v3 engine thread's retirement. */
        const val ENGINE_RETIREMENT_WAIT_MS = 5_000L

        /**
         * How long a pass waits for one bridge close to FINISH: the close ack
         * (750 ms) plus four bounded 1 s joins, with margin.
         */
        const val BRIDGE_CLOSE_WAIT_MS = 6_000L
    }
}
