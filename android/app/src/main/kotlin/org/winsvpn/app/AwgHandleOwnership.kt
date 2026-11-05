package org.winsvpn.app

/**
 * The live AmneziaWG engine handle, paired with the tunnel generation that
 * published it.
 *
 * # Why the pairing exists
 *
 * `GoBackend.awgTurnOn` hands back a small integer handle, and AmneziaWG is
 * free to reuse that number across completely unrelated tunnels once the
 * first one is torn down. This is not a hypothetical: on real hardware
 * (motorola edge plus 2023, Android 15, 2026-08-04T10:52Z,
 * `.winn_platform_progress/evidence/devicecheck_20260804T105214Z_motorola_edge_plus_2023.log`,
 * step `9c-double-teardown-is-a-no-op`), a torn-down session's handle `0` was
 * reissued VERBATIM to the very next tunnel started afterwards.
 *
 * A teardown that identifies "the engine I started" by that raw integer
 * alone cannot tell those two sessions apart. Concretely: session A starts,
 * gets handle 0, and is torn down normally. Session B then starts and is
 * also handed handle 0. If session A's engine thread has a late or
 * duplicate path back to its own cleanup -- a second `finally` running, a
 * race with the thread that superseded it, anything -- and that path calls
 * teardown with its OWN captured `handle = 0`, a raw `handle == handle`
 * comparison matches session B's live, working engine and turns it off.
 * That is a silent, user-visible VPN drop for a tunnel that never had
 * anything wrong with it.
 *
 * [releaseIfOwned] closes that gap by additionally requiring the tunnel
 * generation that published the handle to match the generation asking to
 * release it. Tunnel generations
 * ([VpnTunnelService.nextTunnelGeneration]/`invalidateTunnelGeneration`) are
 * strictly increasing for the lifetime of the process and are never reused,
 * so two different sessions can never share one -- unlike the AmneziaWG
 * handle itself. This reuses the SAME generation counter every other
 * supersede check in `VpnTunnelService` already reads; it is not a second,
 * competing notion of session identity.
 *
 * Deliberately NOT "null the handle after teardown": that would not have
 * caught this bug at all. The failure mode is a LATE, duplicate release
 * arriving AFTER a live successor has already published a new handle into
 * the same slot -- at that point the slot is non-null (it holds the
 * successor's real handle), so a null-check finds nothing wrong. Only
 * comparing the identity of what published the slot, not merely whether the
 * slot is occupied, tells the two sessions apart.
 */
class AwgHandleOwnership {
    private val lock = Object()
    private var handle = -1
    private var generation = -1

    /** The currently published handle, or -1 if none is published. */
    fun current(): Int = synchronized(lock) { handle }

    /**
     * Publishes [handle] as owned by [generation], iff no handle is
     * currently published AND [stillWanted] returns true -- both checked
     * atomically under the same lock that guards [releaseIfOwned] and
     * [forceRelease], so a concurrent publish or release can never race this
     * one. [stillWanted] is evaluated while holding the lock; it must not
     * block or re-enter this object.
     *
     * Returns whether the publish happened. When it did not, [handle] was
     * never adopted here and the caller is responsible for turning it back
     * off.
     */
    fun publishIfFreeAnd(handle: Int, generation: Int, stillWanted: () -> Boolean): Boolean {
        return synchronized(lock) {
            if (this.handle >= 0 || !stillWanted()) {
                false
            } else {
                this.handle = handle
                this.generation = generation
                true
            }
        }
    }

    /**
     * Releases [handle] iff it is still published AND was published under
     * [generation] -- see the class doc for why both must match, not just
     * the handle. Returns whether this call actually released it; the
     * caller should only turn the underlying engine off when it did,
     * because a `false` here means either it was already released or a live
     * successor now owns that same raw handle value.
     */
    fun releaseIfOwned(handle: Int, generation: Int): Boolean {
        return synchronized(lock) {
            if (this.handle == handle && this.generation == generation) {
                this.handle = -1
                this.generation = -1
                true
            } else {
                false
            }
        }
    }

    /**
     * Unconditionally clears whatever is currently published, regardless of
     * which generation owns it, and returns it (or -1 if nothing was
     * published).
     *
     * For the "a new tunnel is starting, stop whatever is running right
     * now, no questions asked" paths ([VpnTunnelService.resetTunnelBeforeConnect]
     * / `executeTunnelTeardown`) -- NOT a substitute for [releaseIfOwned] in
     * a session's own late cleanup, which must stay ownership-scoped or this
     * class would not fix anything.
     */
    fun forceRelease(): Int {
        return synchronized(lock) {
            val active = handle
            handle = -1
            generation = -1
            active
        }
    }
}
