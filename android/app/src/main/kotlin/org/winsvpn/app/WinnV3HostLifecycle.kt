package org.winsvpn.app

import java.io.Closeable
import java.security.SecureRandom
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

/*
 * Round A3: what a PROMOTED Android host does with the Winn v3 engine's
 * lifecycle (Round A2), and who may end its capture.
 *
 * Everything here is free of Android imports so the decisions run under a
 * plain-JVM test. VpnTunnelService only feeds these classes and acts on what
 * they return; it holds no lifecycle rule of its own.
 *
 *  - [WinnV3RecoveryCeiling]: the host-selected ceiling on recovery.
 *  - [WinnV3LifecycleWatch]: one status document at a time, the host verdict.
 *  - [WinnV3RecoveryProber]: randomized, capped delivery-proof stimulation.
 *  - [WinnV3CaptureCustody]: which teardown may release capture, and ordering.
 *  - [WinnV3HostLifecycleBoard]: the owner-checked state the notification,
 *    `isTunnelHealthy()` and the app's readiness map are derived from.
 *
 * None of these authorises AmneziaWG, Xray or any other protocol, and none of
 * them is consulted before promotion. The pre-promotion verdict and the cover
 * authorization token are written by the staged start alone.
 */

/**
 * The host-side recovery ceiling: the longest interval this host tolerates
 * without renewed delivery proof from the engine, measured on a monotonic
 * clock from this host's first observation of `recovering` in an episode and
 * reset only by an engine-reported `connected`.
 *
 * It is a HOST-SELECTED POLICY VALUE, informed by the failed-handshake timing
 * model below. It is not a proven upper bound on a correct recovery: the
 * supervisor's round budget resets on authenticated traffic while `connected`
 * requires delivery, `Reconnect.Run` imposes no per-round deadline, and frame
 * round retirement can wait while its context lives, so a correct but slow
 * recovery CAN outlast it. When it does, this host stops claiming anything and
 * asks the user to act, while keeping capture; it never releases routes and
 * never grants fallback.
 *
 * The failed-handshake model, from `winn3/session/config.go` and
 * `winn3/carrier/dial.go`:
 *
 *  - one round that never establishes: sum over i < 5 of min(8 s, 0.5 s * 2^i)
 *    plus one cap, 0.5 + 1 + 2 + 4 + 8 + 8 = 23.5 s;
 *  - five such rounds: 117.5 s;
 *  - five inter-round waits, each conservatively bounded by the 8 s cap: 40 s
 *    (the supervisor's real windows after a proven round sum to 8 s);
 *  - [STATUS_SAMPLING_SLACK_MS] of observation allowance: 10 s;
 *  - total 167.5 s.
 */
internal object WinnV3RecoveryCeiling {
    /** `carrier.DefaultBackoffAttempts`, the supervisor's round budget. */
    const val SUPERVISOR_ROUNDS = 5
    /** `carrier.DefaultBackoffBase` and `carrier.DefaultBackoffCap`. */
    const val SUPERVISOR_BACKOFF_BASE_MS = 500L
    const val SUPERVISOR_BACKOFF_CAP_MS = 8_000L
    /** `session.DefaultRetryBase`, `DefaultRetryCap`, `DefaultRetryAttempts`. */
    const val SESSION_RETRY_BASE_MS = 500L
    const val SESSION_RETRY_CAP_MS = 8_000L
    const val SESSION_RETRY_ATTEMPTS = 5
    /** Observation allowance: one health-watchdog interval. */
    const val STATUS_SAMPLING_SLACK_MS = 10_000L

    /** The failed-handshake budget of one round, the model's first term. */
    fun handshakeBudgetMs(
        baseMs: Long = SESSION_RETRY_BASE_MS,
        capMs: Long = SESSION_RETRY_CAP_MS,
        attempts: Int = SESSION_RETRY_ATTEMPTS,
    ): Long {
        var total = 0L
        var window = baseMs
        repeat(attempts) {
            total += window
            if (window < capMs) window = minOf(window * 2, capMs)
        }
        return total + capMs
    }

    /** Five failed rounds plus five waits at the cap: 157.5 s. */
    val FAILED_HANDSHAKE_EPISODE_MS: Long =
        SUPERVISOR_ROUNDS * handshakeBudgetMs() + SUPERVISOR_ROUNDS * SUPERVISOR_BACKOFF_CAP_MS

    /** 167.5 s: the host-selected maximum interval without renewed delivery proof. */
    val CEILING_MS: Long = FAILED_HANDSHAKE_EPISODE_MS + STATUS_SAMPLING_SLACK_MS
}

/**
 * Who reported the end a host is showing. The app renders a different line for
 * each, because "the engine stopped trying" and "this host stopped waiting"
 * are different facts, and neither is a claim about why.
 */
internal enum class WinnV3LifecycleObserver(val wire: String) {
    /** The engine published `blocked`; its `lifecycle_cause` travels with it. */
    ENGINE("engine"),
    /** Recovery outlived [WinnV3RecoveryCeiling]; the engine said `recovering`. */
    RECOVERY_CEILING("recovery_ceiling"),
    /** The promoted session ended without a `blocked` reaching this host. */
    SESSION_ENDED("session_ended"),
    /** The document carried a lifecycle this host could not trust. */
    INVALID_STATUS("invalid_status"),
    /**
     * After promotion the engine published a state its own contract rules out
     * once a round has proven delivery: `connecting` (the engine never returns
     * to it after first proof), or no lifecycle at all where one was
     * published before. Not a claim about why.
     */
    INVALID_TRANSITION("invalid_transition"),
}

/**
 * What a promoted host makes of the engine's lifecycle, one status document at
 * a time.
 *
 * Stateful only in three facts: when this host first saw the current recovery
 * episode (on the caller's MONOTONIC clock; the service passes
 * `SystemClock.elapsedRealtime()`), whether a lifecycle was ever published,
 * and whether the tunnel has been judged blocked. Blocked is a latch on
 * Android: this host owns the engine process and stops it on blocked, keeping
 * capture. Apple's reversible verdict is a different, documented policy; see
 * `WinsWinn3Lifecycle`.
 *
 * The watch is fed only AFTER promotion, so every non-live state is an end of
 * a promoted session and is judged blocked at once: `stopped` by
 * [WinnV3LifecycleObserver.SESSION_ENDED], a post-proof `connecting` or a
 * lifecycle that disappears by [WinnV3LifecycleObserver.INVALID_TRANSITION].
 * Nothing post-promotion leaves an earlier `connected` standing.
 *
 * Thread-safe: the engine thread and the health watchdog both feed it.
 */
internal class WinnV3LifecycleWatch(
    private val ceilingMs: Long = WinnV3RecoveryCeiling.CEILING_MS,
) {
    enum class Verdict {
        /** The engine reports `connected`: its current round has delivery proof. */
        CONNECTED,

        /** `recovering` inside the ceiling. Keep everything, claim nothing. */
        RECOVERING,

        /**
         * Engine-reported `blocked`, a lifecycle this host does not know or
         * cannot trust, recovery past the ceiling, `stopped`, or an invalid
         * post-proof transition. [blockedObserver] says which. Capture is
         * kept, the user must act, and no other protocol is ever authorised
         * by it.
         */
        BLOCKED,

        /**
         * No lifecycle in any document so far: an engine older than the field.
         * Once a lifecycle has been seen its absence is an invalid transition.
         */
        UNREPORTED,
    }

    /**
     * One observation, stamped with this watch's own [revision] in the same
     * critical section that decided it. Both the engine loop and the health
     * check observe the same watch, so revisions are totally ordered in the
     * order the verdicts were decided, and [WinnV3HostLifecycleBoard] refuses
     * to publish an observation older than one it already published. A
     * CONNECTED decided before a BLOCKED can therefore never land after it.
     */
    data class Observation(
        val verdict: Verdict,
        val observer: WinnV3LifecycleObserver?,
        val cause: String?,
        val revision: Long,
    )

    private var revision = 0L

    /** [observe], stamped. */
    @Synchronized
    fun observation(status: WinnV3EngineStatus, nowMs: Long): Observation {
        val verdict = observe(status, nowMs)
        revision += 1
        return Observation(verdict, blockedBy, cause, revision)
    }

    /** [observeUntrusted], stamped. */
    @Synchronized
    fun untrustedObservation(): Observation {
        val verdict = observeUntrusted()
        revision += 1
        return Observation(verdict, blockedBy, cause, revision)
    }

    private var recoveringSinceMs: Long? = null
    private var everReported = false
    private var blockedBy: WinnV3LifecycleObserver? = null
    private var cause: String? = null
    private var last: Verdict = Verdict.UNREPORTED

    @Synchronized
    fun observe(status: WinnV3EngineStatus, nowMs: Long): Verdict {
        val verdict = when {
            blockedBy != null -> Verdict.BLOCKED
            !status.lifecycleRecognized -> latch(WinnV3LifecycleObserver.INVALID_STATUS, null)
            status.lifecycle == null && everReported ->
                latch(WinnV3LifecycleObserver.INVALID_TRANSITION, null)
            else -> when (status.lifecycle) {
                null -> Verdict.UNREPORTED
                WinnV3Lifecycle.CONNECTED -> {
                    recoveringSinceMs = null
                    Verdict.CONNECTED
                }
                WinnV3Lifecycle.RECOVERING -> {
                    val since = recoveringSinceMs ?: nowMs.also { recoveringSinceMs = it }
                    if (nowMs - since > ceilingMs) {
                        latch(WinnV3LifecycleObserver.RECOVERY_CEILING, null)
                    } else {
                        Verdict.RECOVERING
                    }
                }
                WinnV3Lifecycle.BLOCKED ->
                    latch(WinnV3LifecycleObserver.ENGINE, status.lifecycleCause)
                WinnV3Lifecycle.STOPPED -> latch(WinnV3LifecycleObserver.SESSION_ENDED, null)
                WinnV3Lifecycle.CONNECTING -> latch(WinnV3LifecycleObserver.INVALID_TRANSITION, null)
            }
        }
        if (status.lifecycle != null) everReported = true
        last = verdict
        return verdict
    }

    /**
     * A status document this host could not parse at all, after promotion. A
     * supervised engine that publishes something this host cannot read has
     * proven nothing and is treated as the closed vocabulary requires.
     */
    @Synchronized
    fun observeUntrusted(): Verdict {
        val verdict = if (blockedBy != null) {
            Verdict.BLOCKED
        } else {
            latch(WinnV3LifecycleObserver.INVALID_STATUS, null)
        }
        last = verdict
        return verdict
    }

    private fun latch(observer: WinnV3LifecycleObserver, observedCause: String?): Verdict {
        blockedBy = observer
        cause = observedCause
        return Verdict.BLOCKED
    }

    @Synchronized
    fun lastVerdict(): Verdict = last

    /** Who ended it, once blocked. */
    @Synchronized
    fun blockedObserver(): WinnV3LifecycleObserver? = blockedBy

    /** The engine's own `lifecycle_cause` when the engine reported blocked. */
    @Synchronized
    fun blockedCause(): String? = cause

    /** How long this host has watched the current episode, or null. */
    @Synchronized
    fun recoveringForMs(nowMs: Long): Long? = recoveringSinceMs?.let { nowMs - it }
}

/**
 * Delivery-proof stimulation while the engine recovers.
 *
 * WHY THE HOST SENDS IT. An established successor on an idle phone delivers
 * nothing, so the engine keeps saying `recovering` (a round is `connected`
 * only on its own delivery) and the host ceiling would eventually judge a
 * working tunnel. The engine has no delivery-proof stimulus of its own: its
 * randomized keepalives are session frames, not inner packets, so they never
 * advance `rx_packets`. Moving the stimulus into the engine is a change to
 * the certified Round A2 runtime and is outside this host round; it is the
 * preferred long-term home and is recorded as such.
 *
 * WHY IT IS NOT A CADENCE. `winn3/carrier/dial.go` forbids fixed retry
 * spacing, and `WinnV3Host` §3 makes the engine the tunnel's timing
 * authority. So nothing here is periodic:
 *
 *  - every delay is drawn independently from a CSPRNG ([SecureRandom]),
 *    discrete uniform at nanosecond resolution on the open interval
 *    ([MIN_DELAY_NANOS], [MAX_DELAY_NANOS]): each of its 7,999,999,999
 *    possible delays has the same small, nonzero probability, and none
 *    carries extra mass (no clamp, no rounding onto a tick);
 *  - each probe is scheduled on its own timer at exactly that delay, never on
 *    the 1 s status poll, so no draw is rounded onto a tick;
 *  - an episode sends at most [MAX_PROBES_PER_EPISODE] probes, then stops;
 *  - the episode ends on any verdict but RECOVERING, and the prober closes the
 *    moment its session stops being the owner.
 *
 * The probe itself is the staged start's inner ICMP echo to the inner next
 * hop, injected through the tunnel seam: it can only enter the tunnel.
 */
internal class WinnV3RecoveryProber(
    private val timer: Timer,
    private val draw: (Long) -> Long,
    private val isStillOwner: () -> Boolean,
    private val send: (attempt: Int) -> Boolean,
    private val minDelayNanos: Long = MIN_DELAY_NANOS,
    private val maxDelayNanos: Long = MAX_DELAY_NANOS,
    private val maxProbesPerEpisode: Int = MAX_PROBES_PER_EPISODE,
) : Closeable {

    /** Schedules one task after an exact delay. The service's is a real executor. */
    interface Timer : Closeable {
        fun schedule(delayNanos: Long, task: Runnable): Cancellable
    }

    fun interface Cancellable {
        fun cancel()
    }

    companion object {
        /** 1 s, exclusive. */
        const val MIN_DELAY_NANOS = 1_000_000_000L
        /** 9 s, exclusive. */
        const val MAX_DELAY_NANOS = 9_000_000_000L
        /** At most this many probes of 36 bytes in one recovery episode. */
        const val MAX_PROBES_PER_EPISODE = 12

        /** A draw uniform on [0, bound) from one [SecureRandom], rejection-sampled. */
        fun secureDraw(random: SecureRandom = SecureRandom()): (Long) -> Long = { bound ->
            require(bound > 0)
            var result: Long
            while (true) {
                val bits = random.nextLong() ushr 1
                result = bits % bound
                if (bits - result + (bound - 1) >= 0) break
            }
            result
        }

        /** One delay on the open interval (min, max). */
        fun nextDelayNanos(draw: (Long) -> Long, minNanos: Long, maxNanos: Long): Long {
            require(maxNanos - minNanos >= 2)
            return minNanos + 1 + draw(maxNanos - minNanos - 1)
        }
    }

    private var closed = false
    private var episode = 0L
    private var inEpisode = false
    private var sentThisEpisode = 0
    private var pending: Cancellable? = null

    /** Feed every post-promotion verdict. */
    fun onVerdict(verdict: WinnV3LifecycleWatch.Verdict) {
        synchronized(this) {
            if (closed) return
            if (verdict != WinnV3LifecycleWatch.Verdict.RECOVERING) {
                endEpisodeLocked()
                return
            }
            if (!inEpisode) {
                inEpisode = true
                sentThisEpisode = 0
                scheduleLocked()
            }
        }
        if (!isStillOwner()) close()
    }

    private fun scheduleLocked() {
        if (pending != null || sentThisEpisode >= maxProbesPerEpisode) return
        val forEpisode = episode
        val delay = nextDelayNanos(draw, minDelayNanos, maxDelayNanos)
        pending = timer.schedule(delay, Runnable { fire(forEpisode) })
    }

    private fun fire(forEpisode: Long) {
        val attempt = synchronized(this) {
            if (closed || forEpisode != episode || !inEpisode) return
            pending = null
            if (sentThisEpisode >= maxProbesPerEpisode) return
            sentThisEpisode += 1
            sentThisEpisode
        }
        if (!isStillOwner()) {
            close()
            return
        }
        send(attempt)
        synchronized(this) {
            if (!closed && forEpisode == episode && inEpisode) scheduleLocked()
        }
    }

    private fun endEpisodeLocked() {
        pending?.cancel()
        pending = null
        if (inEpisode) episode += 1
        inEpisode = false
        sentThisEpisode = 0
    }

    /** Probes sent in the current episode. */
    @Synchronized
    fun sentInEpisode(): Int = sentThisEpisode

    @Synchronized
    fun hasPendingProbe(): Boolean = pending != null

    override fun close() {
        synchronized(this) {
            if (closed) return
            closed = true
            endEpisodeLocked()
        }
        try {
            timer.close()
        } catch (_: Exception) {
        }
    }
}

/** The production [WinnV3RecoveryProber.Timer]: one daemon thread, exact delays. */
internal class WinnV3ExecutorProbeTimer(threadName: String) : WinnV3RecoveryProber.Timer {
    private val executor = ScheduledThreadPoolExecutor(
        1,
        ThreadFactory { task -> Thread(task, threadName).apply { isDaemon = true } },
    ).apply {
        removeOnCancelPolicy = true
        executeExistingDelayedTasksAfterShutdownPolicy = false
    }

    override fun schedule(delayNanos: Long, task: Runnable): WinnV3RecoveryProber.Cancellable {
        val future = executor.schedule(task, delayNanos, TimeUnit.NANOSECONDS)
        return WinnV3RecoveryProber.Cancellable { future.cancel(false) }
    }

    override fun close() {
        executor.shutdownNow()
    }
}

/** Why a tunnel is being torn down, which decides whether capture may end. */
internal enum class WinnV3TeardownCause(val rank: Int) {
    /**
     * Anything this host decided on its own: the engine ending (a terminal
     * failure between polls, an Error frame before any status), the health
     * watchdog, the VPN-visibility watchdog, a camouflage notification refusal,
     * a configuration refused at connect. Never releases a promoted v3
     * session's capture by itself.
     */
    AUTOMATIC(0),

    /** The owner pressed Disconnect. Outranks any automatic hold. */
    OWNER_DISCONNECT(1),

    /** Android withdrew VPN authorization. Outranks everything, holds nothing. */
    OS_REVOKE(2),

    /** The service is being destroyed; a tun cannot outlive its process. */
    PROCESS_DESTROY(2),
}

/**
 * Which teardown may release a promoted Winn v3 session's capture, and in what
 * order competing requests take effect.
 *
 * PROMOTION IS RECORDED ONCE, when the session is published connected, and
 * not re-derived from the latest lifecycle sample. So an unsolicited end of a
 * promoted session holds capture even when recovery was never sampled: a
 * terminal failure that completes between two polls, or an Error frame that
 * reaches the bridge before any status does.
 *
 * Owner disconnect and OS revocation are distinct and outrank a hold. A
 * request that arrives while a teardown is in flight is QUEUED: [afterPass]
 * returns it as a follow-up whenever the finished pass left anything held
 * (and says why it is dropped otherwise), and a queued revocation withdraws
 * the in-flight pass's right to hold at all ([blockPostureStillAllowed]).
 *
 * Calls are serialised by [WinnV3TeardownWorker] under the service's teardown
 * lock, which also owns the in-flight flag; this class holds no Android state.
 */
internal class WinnV3CaptureCustody {

    data class Plan(
        val cause: WinnV3TeardownCause,
        val keepVpnLauncher: Boolean,
        val allowBlockPosture: Boolean,
        /** Keep capture as a blackhole whatever the kill switch says. */
        val holdCapture: Boolean,
    )

    enum class NotificationResult {
        /** The hold's foreground notification was posted. */
        POSTED,

        /** The disguise refused a notification it could not make safe. */
        DISGUISE_REFUSED,

        /** The platform threw while re-posting the foreground notification. */
        PLATFORM_FAILED,
    }

    data class HoldOutcome(val keepCapture: Boolean, val limitation: String?)

    companion object {
        /**
         * Released, and said so: the only notification Android would accept
         * names the real app while the disguise is up. The owner's standing
         * precedence (the same one the kill-switch hold already obeys) puts the
         * disguise first. Capture retention is therefore NOT unconditional on
         * Android, and the app is told.
         */
        const val LIMITATION_DISGUISE_REFUSED = "disguise_refused_notification"

        /**
         * Kept, and said so: the service is still foreground under the
         * notification it posted at connect, but the hold's own notification
         * could not be posted, so the OS may end the process and the hold
         * with it.
         */
        const val LIMITATION_FOREGROUND_REFRESH_FAILED = "foreground_refresh_failed"

        /** No interface existed and no blocking interface could be built. */
        const val LIMITATION_NO_BLOCKING_INTERFACE = "blocking_interface_unavailable"

        /** The hold was being built when the service was destroyed. */
        const val LIMITATION_SERVICE_DESTROYED = "service_destroyed"

        /** The hold was being built when Android withdrew VPN authorization. */
        const val LIMITATION_VPN_PERMISSION_REVOKED = "vpn_permission_revoked"

        fun holdOutcome(result: NotificationResult): HoldOutcome = when (result) {
            NotificationResult.POSTED -> HoldOutcome(keepCapture = true, limitation = null)
            NotificationResult.DISGUISE_REFUSED ->
                HoldOutcome(keepCapture = false, limitation = LIMITATION_DISGUISE_REFUSED)
            NotificationResult.PLATFORM_FAILED ->
                HoldOutcome(keepCapture = true, limitation = LIMITATION_FOREGROUND_REFRESH_FAILED)
        }
    }

    private var promotedOwner: Int? = null
    private var queued: Plan? = null

    /** The v3 session owned by generation [owner] was published connected. */
    @Synchronized
    fun markPromoted(owner: Int) {
        promotedOwner = owner
    }

    @Synchronized
    fun isPromoted(): Boolean = promotedOwner != null

    /** A new connect supersedes everything queued or recorded. */
    @Synchronized
    fun clear() {
        promotedOwner = null
        queued = null
    }

    /**
     * A teardown request. Returns the plan to run now, or null when a pass is
     * already in flight; the request is then queued. An automatic request adds
     * nothing to one in flight (the pass in flight already ends the session).
     * Of two owner or OS requests the higher rank wins, and of two of the same
     * rank the LATER one wins, so the owner's latest `keepVpnLauncher` is the
     * one that runs. Callers go through [WinnV3TeardownWorker], which supplies
     * [inFlight] under the same lock as the worker's retirement.
     */
    @Synchronized
    fun request(
        cause: WinnV3TeardownCause,
        keepVpnLauncher: Boolean,
        allowBlockPosture: Boolean,
        inFlight: Boolean,
    ): Plan? {
        val plan = Plan(
            cause = cause,
            keepVpnLauncher = keepVpnLauncher,
            allowBlockPosture = allowBlockPosture && cause.rank < WinnV3TeardownCause.OS_REVOKE.rank,
            holdCapture = cause == WinnV3TeardownCause.AUTOMATIC && promotedOwner != null,
        )
        if (inFlight) {
            if (cause.rank > 0 && cause.rank >= (queued?.cause?.rank ?: 0)) queued = plan
            return null
        }
        if (cause.rank > 0) promotedOwner = null
        return plan
    }

    /**
     * Whether the pass for [plan] may still hold ANY interface (capture or
     * kill switch). False once a revocation or process destruction is queued:
     * those beat a hold that is still being built.
     */
    @Synchronized
    fun blockPostureStillAllowed(plan: Plan): Boolean =
        plan.allowBlockPosture && (queued?.cause?.rank ?: 0) < WinnV3TeardownCause.OS_REVOKE.rank

    /**
     * What a pass for [cause] releasing an ESTABLISHED hold must report, or
     * null when that release is not a notice: the owner's Disconnect is an
     * acknowledged release, and an automatic pass does not release a hold.
     */
    fun releaseLimitationFor(cause: WinnV3TeardownCause): String? = when (cause) {
        WinnV3TeardownCause.OS_REVOKE -> LIMITATION_VPN_PERMISSION_REVOKED
        WinnV3TeardownCause.PROCESS_DESTROY -> LIMITATION_SERVICE_DESTROYED
        WinnV3TeardownCause.OWNER_DISCONNECT, WinnV3TeardownCause.AUTOMATIC -> null
    }

    /**
     * The limitation to report when a queued revocation or process
     * destruction stopped a capture hold from being built, or null when
     * nothing outranks it.
     */
    @Synchronized
    fun outrankingLimitation(): String? = when (queued?.cause) {
        WinnV3TeardownCause.OS_REVOKE -> LIMITATION_VPN_PERMISSION_REVOKED
        WinnV3TeardownCause.PROCESS_DESTROY -> LIMITATION_SERVICE_DESTROYED
        else -> null
    }

    /**
     * The pass for [plan] finished. [heldAnything] is whether it left an
     * interface held. Returns the queued request to run next, or null.
     *
     * A queued request runs whenever the pass left anything held, whatever
     * its rank: a follow-up pass is idempotent (engines are already stopped,
     * a held interface is kept or released by the follow-up's own rule), so
     * running a same-rank request costs nothing and can only apply the
     * owner's latest intent.
     *
     * It is dropped in exactly one case, and deliberately: the pass held
     * NOTHING. Then the interface is closed, the service has stopped itself
     * and `isServiceActive` is false, so a follow-up pass could only repeat a
     * release that already happened: `hadActiveSession` is false, so it would
     * not even touch the launcher component. What each request does beyond
     * the pass (ACTION_DISCONNECT's grant and restart-config clearing,
     * onRevoke's restart-config clearing and `super.onRevoke()`) runs at the
     * call site before [request], so dropping the pass loses none of it. A
     * release notice the pass published is kept, not erased by a follow-up
     * ([WinnV3HostLifecycleBoard.clear]).
     */
    @Synchronized
    fun afterPass(plan: Plan, heldAnything: Boolean): Plan? {
        val next = queued
        queued = null
        if (!heldAnything) {
            promotedOwner = null
            return null
        }
        if (next == null) return null
        promotedOwner = null
        return next
    }
}

/**
 * The teardown worker's lifecycle: one worker at a time, and no request lost
 * between the worker's last look at the queue and its retirement.
 *
 * [submit] and the worker's end-of-pass transition in [drain] take the SAME
 * [lock]. At the end of every pass the worker, holding it, asks
 * [WinnV3CaptureCustody.afterPass] for the next queued plan and, when there is
 * none, declares itself idle and retires ([onRetired]) in that one critical
 * section. So a request either arrives before that section, is queued and is
 * returned by it, or arrives after it, finds no worker in flight and is
 * returned by [submit] as a plan for a new worker. There is no third place
 * for it to go.
 *
 * VpnTunnelService supplies its own `winnEngineLock`, mirrors [isInFlight]
 * into `tearingDown` through [onPlanStarted] and [onRetired], and runs each
 * pass on its teardown thread.
 */
internal class WinnV3TeardownWorker(
    private val lock: Any,
    private val custody: WinnV3CaptureCustody,
    /** Called under [lock] whenever a plan is about to run. */
    private val onPlanStarted: (WinnV3CaptureCustody.Plan) -> Unit = {},
    /** Called under [lock] when the worker goes idle. */
    private val onRetired: () -> Unit = {},
    /** Test seam only: called under [lock] after the queue was inspected. */
    private val atTransition: () -> Unit = {},
) {
    private var inFlight = false

    fun isInFlight(): Boolean = synchronized(lock) { inFlight }

    /**
     * A teardown request. Returns the plan the caller must run on a new
     * worker ([drain]), or null when a worker is in flight and has queued it.
     */
    fun submit(
        cause: WinnV3TeardownCause,
        keepVpnLauncher: Boolean,
        allowBlockPosture: Boolean,
    ): WinnV3CaptureCustody.Plan? = synchronized(lock) {
        val plan = custody.request(cause, keepVpnLauncher, allowBlockPosture, inFlight)
            ?: return@synchronized null
        inFlight = true
        onPlanStarted(plan)
        plan
    }

    /**
     * The worker body. Runs [first] and every follow-up, then retires. A pass
     * that throws is treated as having left something held, so a queued
     * owner or OS request still runs after it.
     */
    fun drain(
        first: WinnV3CaptureCustody.Plan,
        runPass: (WinnV3CaptureCustody.Plan) -> Boolean,
        onPassError: (Exception) -> Unit = {},
    ) {
        var plan: WinnV3CaptureCustody.Plan? = first
        while (plan != null) {
            val finished: WinnV3CaptureCustody.Plan = plan
            val held = try {
                runPass(finished)
            } catch (e: Exception) {
                onPassError(e)
                true
            }
            plan = synchronized(lock) {
                val next = custody.afterPass(finished, held)
                atTransition()
                if (next == null) {
                    inFlight = false
                    onRetired()
                } else {
                    onPlanStarted(next)
                }
                next
            }
        }
    }

    /**
     * A connect that resets the service while no worker should be running.
     * Mirrors the service's own reset of `tearingDown`; call under [lock].
     */
    fun forceIdleLocked() {
        inFlight = false
    }
}

/**
 * One step of the post-promotion loop (and of the health check that shares
 * its watch), from a status document to what the board publishes. Both
 * callers run exactly this, so the path watch -> board -> readiness is one
 * path and is tested as one.
 */
internal object WinnV3PostPromotionStep {
    /** The observation for one document; one this host cannot parse is untrusted. */
    fun judge(
        binding: WinnV3LifecycleBinding,
        json: String,
        nowMs: Long,
    ): WinnV3LifecycleWatch.Observation =
        try {
            binding.watch.observation(WinnV3EngineStatus.parse(json), nowMs)
        } catch (_: WinnV3StartRefusal) {
            binding.watch.untrustedObservation()
        }

    /**
     * Publishes [observation] for the session [binding] names. [stillOwner]
     * is the caller's ownership check of THAT binding (the watch and the
     * generation captured together), taken under its teardown lock.
     */
    fun publish(
        board: WinnV3HostLifecycleBoard,
        binding: WinnV3LifecycleBinding,
        stillOwner: Boolean,
        observation: WinnV3LifecycleWatch.Observation,
    ): WinnV3HostLifecycleBoard.Publication =
        if (!stillOwner) {
            WinnV3HostLifecycleBoard.Publication.REJECTED
        } else {
            board.publish(binding.owner, observation)
        }

    /** Whether the loop must end: superseded, or blocked (the teardown holds). */
    fun endsLoop(
        verdict: WinnV3LifecycleWatch.Verdict,
        publication: WinnV3HostLifecycleBoard.Publication,
    ): Boolean =
        publication == WinnV3HostLifecycleBoard.Publication.REJECTED ||
            verdict == WinnV3LifecycleWatch.Verdict.BLOCKED
}

/**
 * A promoted session's lifecycle watch together with the tunnel generation
 * that owns it. Captured and validated as ONE pair: a reader that took the
 * watch of one session can never publish under the owner of another.
 */
internal data class WinnV3LifecycleBinding(
    val watch: WinnV3LifecycleWatch,
    val owner: Int,
)

/**
 * The lifecycle state the service publishes, owner-checked.
 *
 * Every publication from a session names the tunnel generation that owns it,
 * and is refused unless that generation is still the board's owner, so a
 * post-promotion loop that wakes from its sleep after a configuration
 * replacement cannot write the old session's state over the new one. Only the
 * service's own teardown and connect paths change the owner.
 */
internal class WinnV3HostLifecycleBoard {

    data class Snapshot(
        val state: WinnV3Lifecycle? = null,
        val observer: WinnV3LifecycleObserver? = null,
        val cause: String? = null,
        val captureHeld: Boolean = false,
        val limitation: String? = null,
    ) {
        /** Connected may be claimed only for a legacy engine or engine-proven connected. */
        fun permitsConnectedClaim(): Boolean =
            state == null || state == WinnV3Lifecycle.CONNECTED

        /** The user must act: blocked, whoever observed it. */
        fun actionRequired(): Boolean = state == WinnV3Lifecycle.BLOCKED

        /** Capture was released because the platform could not keep the hold. */
        fun isReleaseNotice(): Boolean =
            state == WinnV3Lifecycle.BLOCKED && !captureHeld && limitation != null

        /** The keys MainActivity adds to `getTunnelReadiness`. */
        fun readinessFields(): Map<String, Any> {
            val fields = linkedMapOf<String, Any>(
                KEY_CAPTURE_HELD to captureHeld,
                KEY_ACTION_REQUIRED to actionRequired(),
            )
            state?.let { fields[KEY_LIFECYCLE] = it.wire }
            observer?.let { fields[KEY_OBSERVER] = it.wire }
            cause?.let { fields[KEY_CAUSE] = it }
            limitation?.let { fields[KEY_LIMITATION] = it }
            return fields
        }
    }

    /**
     * REJECTED: not the owner (superseded, the loop must end). OBSOLETE: the
     * owner, but an observation older than one already published, or a
     * non-blocked verdict after blocked; nothing changes and the next
     * observation decides.
     */
    enum class Publication { REJECTED, OBSOLETE, UNCHANGED, CHANGED }

    companion object {
        const val KEY_LIFECYCLE = "winn3_lifecycle"
        const val KEY_OBSERVER = "winn3_lifecycle_observer"
        const val KEY_CAUSE = "winn3_lifecycle_cause"
        const val KEY_CAPTURE_HELD = "winn3_capture_held"
        const val KEY_ACTION_REQUIRED = "winn3_action_required"
        const val KEY_LIMITATION = "winn3_hold_limitation"
    }

    private var owner: Int? = null
    private var current = Snapshot()
    private var lastRevision = 0L

    /** A v3 session owned by generation [owner] is starting. */
    @Synchronized
    fun begin(owner: Int) {
        this.owner = owner
        current = Snapshot()
        lastRevision = 0L
    }

    /**
     * A session ended without a hold: nothing is described any more, EXCEPT
     * a release notice. A hold the platform could not keep ([holdCapture] with
     * `held = false` and a limitation) says that capture was released and
     * why; it survives every later end of the service (its stopSelf, the
     * PROCESS_DESTROY teardown onDestroy then requests, any queued follow-up)
     * until the owner acknowledges it ([acknowledgeReleaseNotice]) or a new
     * connect supersedes it ([supersede], [begin]).
     */
    @Synchronized
    fun clear() {
        owner = null
        if (!current.isReleaseNotice()) current = Snapshot()
    }

    /** A new connect: the previous session, and any notice about it, is gone. */
    @Synchronized
    fun supersede() {
        owner = null
        current = Snapshot()
    }

    /**
     * An ESTABLISHED capture hold is being released by a revocation or by the
     * service's destruction (a pass that holds nothing, after the hold was
     * built). Turns the held snapshot into a release notice with
     * [limitation] BEFORE that pass clears anything, so [clear] keeps it.
     * No-op unless the board describes a held capture.
     */
    @Synchronized
    fun releaseHeldCapture(limitation: String) {
        if (current.state != WinnV3Lifecycle.BLOCKED || !current.captureHeld) return
        owner = null
        current = current.copy(captureHeld = false, limitation = limitation)
    }

    /** The owner acted (Disconnect): the release notice has been seen. */
    @Synchronized
    fun acknowledgeReleaseNotice() {
        if (current.isReleaseNotice()) current = Snapshot()
    }

    /**
     * One post-promotion observation from the session owned by [owner].
     *
     * Ordered: an observation whose revision is not newer than the last one
     * published is OBSOLETE. And terminal: once this session is published
     * BLOCKED, nothing but BLOCKED is accepted for it, whatever its revision.
     * Only [begin] (a new session) or the service's own teardown and connect
     * paths move the board off it.
     */
    @Synchronized
    fun publish(owner: Int, observation: WinnV3LifecycleWatch.Observation): Publication {
        if (this.owner != owner) return Publication.REJECTED
        if (observation.revision <= lastRevision) return Publication.OBSOLETE
        lastRevision = observation.revision
        val verdict = observation.verdict
        val observer = observation.observer
        val cause = observation.cause
        if (current.state == WinnV3Lifecycle.BLOCKED && verdict != WinnV3LifecycleWatch.Verdict.BLOCKED) {
            return Publication.OBSOLETE
        }
        val next = when (verdict) {
            WinnV3LifecycleWatch.Verdict.CONNECTED ->
                Snapshot(state = WinnV3Lifecycle.CONNECTED, captureHeld = false)
            WinnV3LifecycleWatch.Verdict.RECOVERING ->
                Snapshot(state = WinnV3Lifecycle.RECOVERING, captureHeld = true)
            WinnV3LifecycleWatch.Verdict.BLOCKED ->
                Snapshot(
                    state = WinnV3Lifecycle.BLOCKED,
                    observer = observer,
                    cause = if (observer == WinnV3LifecycleObserver.ENGINE) cause else null,
                    captureHeld = true,
                )
            WinnV3LifecycleWatch.Verdict.UNREPORTED -> Snapshot()
        }
        if (next == current) return Publication.UNCHANGED
        current = next
        return Publication.CHANGED
    }

    /**
     * The teardown is holding a promoted session's capture. Blocked by
     * whoever already observed it, or by the host when the session ended
     * without a `blocked` reaching it. The session publishes nothing more.
     */
    @Synchronized
    fun holdCapture(held: Boolean, limitation: String?) {
        owner = null
        val blocked = current.state == WinnV3Lifecycle.BLOCKED
        current = Snapshot(
            state = WinnV3Lifecycle.BLOCKED,
            observer = if (blocked) current.observer else WinnV3LifecycleObserver.SESSION_ENDED,
            cause = if (blocked) current.cause else null,
            captureHeld = held,
            limitation = limitation,
        )
    }

    @Synchronized
    fun snapshot(): Snapshot = current
}
