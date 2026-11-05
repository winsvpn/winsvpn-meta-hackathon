package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round A3: what a PROMOTED Android host makes of the Winn v3 engine's
 * lifecycle, the host-selected recovery ceiling, and what the notification may
 * claim. See [WinnV3LifecycleWatch] and [WinnV3RecoveryCeiling].
 */
class WinnV3LifecycleWatchTest {

    private fun status(lifecycle: String?, cause: String? = null): WinnV3EngineStatus {
        val parts = mutableListOf(""""gate_state":"closed"""", """"rx_packets":0""")
        if (lifecycle != null) parts += """"lifecycle":"$lifecycle""""
        if (cause != null) parts += """"lifecycle_cause":"$cause""""
        return WinnV3EngineStatus.parse(parts.joinToString(",", "{", "}"))
    }

    // ---- parse -------------------------------------------------------------

    @Test
    fun `parse reads the lifecycle and its cause`() {
        val parsed = status("blocked", "budget_spent")
        assertEquals(WinnV3Lifecycle.BLOCKED, parsed.lifecycle)
        assertEquals("budget_spent", parsed.lifecycleCause)
        assertTrue(parsed.lifecycleRecognized)
    }

    @Test
    fun `an absent lifecycle is null and an unknown or empty one is blocked and unrecognized`() {
        assertNull(status(null).lifecycle)
        assertTrue(status(null).lifecycleRecognized)
        for (unknown in listOf("a-state-nobody-defined", "", "Connected")) {
            val parsed = status(unknown)
            assertEquals("`$unknown`", WinnV3Lifecycle.BLOCKED, parsed.lifecycle)
            assertFalse("`$unknown` must not read as the engine's own blocked", parsed.lifecycleRecognized)
        }
        for (known in WinnV3Lifecycle.entries) {
            assertEquals(known, status(known.wire).lifecycle)
            assertTrue(status(known.wire).lifecycleRecognized)
        }
    }

    // ---- the ceiling -------------------------------------------------------

    @Test
    fun `the ceiling is the failed-handshake model plus an observation allowance`() {
        assertEquals(23_500L, WinnV3RecoveryCeiling.handshakeBudgetMs())
        assertEquals(157_500L, WinnV3RecoveryCeiling.FAILED_HANDSHAKE_EPISODE_MS)
        assertEquals(167_500L, WinnV3RecoveryCeiling.CEILING_MS)
        assertTrue(WinnV3RecoveryCeiling.CEILING_MS > 3 * 10_000L)
    }

    // ---- the watch ---------------------------------------------------------

    @Test
    fun `connected is connected`() {
        val watch = WinnV3LifecycleWatch()
        assertEquals(WinnV3LifecycleWatch.Verdict.CONNECTED, watch.observe(status("connected"), 0L))
        assertNull(watch.blockedObserver())
    }

    @Test
    fun `recovering inside the ceiling is recovering`() {
        val watch = WinnV3LifecycleWatch()
        // 35 s is where the old rule tore the tunnel down.
        for (t in listOf(0L, 15_000L, 25_000L, 35_000L, WinnV3RecoveryCeiling.CEILING_MS)) {
            assertEquals(
                "recovering at $t ms",
                WinnV3LifecycleWatch.Verdict.RECOVERING,
                watch.observe(status("recovering"), t),
            )
        }
        assertEquals(WinnV3RecoveryCeiling.CEILING_MS, watch.recoveringForMs(WinnV3RecoveryCeiling.CEILING_MS))
    }

    @Test
    fun `recovery past the ceiling is host-observed blocked, distinct from engine blocked`() {
        val watch = WinnV3LifecycleWatch()
        watch.observe(status("recovering"), 1_000L)
        assertEquals(
            WinnV3LifecycleWatch.Verdict.BLOCKED,
            watch.observe(status("recovering"), 1_000L + WinnV3RecoveryCeiling.CEILING_MS + 1),
        )
        assertEquals(WinnV3LifecycleObserver.RECOVERY_CEILING, watch.blockedObserver())
        assertNull("the host observed the ceiling; it has no engine cause", watch.blockedCause())
        // Latched on Android: the engine thread stops the session on it.
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, watch.observe(status("connected"), 999_999L))

        val engine = WinnV3LifecycleWatch()
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, engine.observe(status("blocked", "terminal"), 0L))
        assertEquals(WinnV3LifecycleObserver.ENGINE, engine.blockedObserver())
        assertEquals("terminal", engine.blockedCause())
    }

    @Test
    fun `a frozen recovering document still trips the ceiling on the host clock`() {
        // What a wedged status transport looks like from here: no new
        // document, the same `recovering` read again, and only time moving.
        val watch = WinnV3LifecycleWatch()
        val frozen = status("recovering")
        var verdict = WinnV3LifecycleWatch.Verdict.UNREPORTED
        var now = 5_000L
        while (now <= 5_000L + WinnV3RecoveryCeiling.CEILING_MS + 1_000L) {
            verdict = watch.observe(frozen, now)
            now += 1_000L
        }
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, verdict)
        assertEquals(WinnV3LifecycleObserver.RECOVERY_CEILING, watch.blockedObserver())
    }

    @Test
    fun `a new episode starts its own clock`() {
        val watch = WinnV3LifecycleWatch()
        watch.observe(status("recovering"), 0L)
        watch.observe(status("connected"), 100_000L)
        assertNull(watch.recoveringForMs(100_000L))
        assertEquals(WinnV3LifecycleWatch.Verdict.RECOVERING, watch.observe(status("recovering"), 110_000L))
        assertEquals(WinnV3LifecycleWatch.Verdict.RECOVERING, watch.observe(status("recovering"), 210_000L))
    }

    @Test
    fun `every engine cause is carried, and an unknown or untrusted lifecycle is invalid_status`() {
        for (cause in listOf("never_established", "budget_spent", "terminal")) {
            val fresh = WinnV3LifecycleWatch()
            assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, fresh.observe(status("blocked", cause), 0L))
            assertEquals(cause, fresh.blockedCause())
            assertEquals(WinnV3LifecycleObserver.ENGINE, fresh.blockedObserver())
        }
        val unknown = WinnV3LifecycleWatch()
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, unknown.observe(status("a-state-nobody-defined"), 0L))
        assertEquals(WinnV3LifecycleObserver.INVALID_STATUS, unknown.blockedObserver())

        val untrusted = WinnV3LifecycleWatch()
        untrusted.observe(status("connected"), 0L)
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, untrusted.observeUntrusted())
        assertEquals(WinnV3LifecycleObserver.INVALID_STATUS, untrusted.blockedObserver())
    }

    @Test
    fun `stopped and a post-proof connecting end the session, each named for what it is`() {
        for ((state, observer) in listOf(
            "stopped" to WinnV3LifecycleObserver.SESSION_ENDED,
            "connecting" to WinnV3LifecycleObserver.INVALID_TRANSITION,
        )) {
            val watch = WinnV3LifecycleWatch()
            watch.observe(status("connected"), 0L)
            assertEquals(state, WinnV3LifecycleWatch.Verdict.BLOCKED, watch.observe(status(state), 1_000L))
            assertEquals(state, observer, watch.blockedObserver())
            assertNull("$state carries no engine cause", watch.blockedCause())
            assertEquals("latched", WinnV3LifecycleWatch.Verdict.BLOCKED, watch.observe(status("connected"), 2_000L))
        }
    }

    @Test
    fun `a lifecycle that disappears after one was published is an invalid transition`() {
        val watch = WinnV3LifecycleWatch()
        watch.observe(status("recovering"), 0L)
        assertEquals(WinnV3LifecycleWatch.Verdict.BLOCKED, watch.observe(status(null), 1_000L))
        assertEquals(WinnV3LifecycleObserver.INVALID_TRANSITION, watch.blockedObserver())
        // Never published at all is a legacy engine, and stays unreported.
        val legacy = WinnV3LifecycleWatch()
        assertEquals(WinnV3LifecycleWatch.Verdict.UNREPORTED, legacy.observe(status(null), 0L))
        assertEquals(WinnV3LifecycleWatch.Verdict.UNREPORTED, legacy.observe(status(null), 1_000L))
    }

    @Test
    fun `an engine without the field is unreported`() {
        assertEquals(WinnV3LifecycleWatch.Verdict.UNREPORTED, WinnV3LifecycleWatch().observe(status(null), 0L))
    }

    // ---- what the notification may claim ------------------------------------

    @Test
    fun `the notification claims connected only when the engine says connected`() {
        val full = { lifecycle: WinnV3Lifecycle? ->
            VpnTunnelService.tunnelForegroundFor(true, true, true, lifecycle)
        }
        assertEquals(VpnTunnelService.TunnelForegroundState.CONNECTED, full(null))
        assertEquals(VpnTunnelService.TunnelForegroundState.CONNECTED, full(WinnV3Lifecycle.CONNECTED))
        assertEquals(VpnTunnelService.TunnelForegroundState.RECOVERING, full(WinnV3Lifecycle.RECOVERING))
        assertEquals(VpnTunnelService.TunnelForegroundState.BLOCKED, full(WinnV3Lifecycle.BLOCKED))
        assertEquals(VpnTunnelService.TunnelForegroundState.CONNECTING, full(WinnV3Lifecycle.STOPPED))
        assertEquals(
            VpnTunnelService.TunnelForegroundState.BLOCKED,
            VpnTunnelService.tunnelForegroundFor(false, false, true, WinnV3Lifecycle.BLOCKED),
        )
        assertEquals(
            VpnTunnelService.TunnelForegroundState.CONNECTING,
            VpnTunnelService.tunnelForegroundFor(false, true, true, WinnV3Lifecycle.RECOVERING),
        )
    }

    @Test
    fun `recovering and blocked texts never claim a running tunnel`() {
        for (state in listOf(
            VpnTunnelService.TunnelForegroundState.RECOVERING,
            VpnTunnelService.TunnelForegroundState.BLOCKED,
        )) {
            val text = VpnTunnelService.tunnelForegroundTextFor(false, state)
            assertFalse("$state text claims running: $text", text.contains("running"))
            assertFalse("$state text claims encryption: $text", text.contains("Encrypted"))
            assertTrue("$state text says traffic is held: $text", text.contains("held"))
            assertEquals(
                "the title must not flicker",
                VpnTunnelService.tunnelForegroundTitleFor(false, VpnTunnelService.TunnelForegroundState.CONNECTED),
                VpnTunnelService.tunnelForegroundTitleFor(false, state),
            )
        }
        val blocked = VpnTunnelService.tunnelForegroundTextFor(
            false, VpnTunnelService.TunnelForegroundState.BLOCKED,
        ).lowercase()
        for (claim in listOf("censor", "revoked", "banned")) {
            assertFalse("the blocked text must not claim $claim", blocked.contains(claim))
        }
    }
}
