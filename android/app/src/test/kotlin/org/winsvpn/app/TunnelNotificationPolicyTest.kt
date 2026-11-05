package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The foreground-service notification must be ACCURATE, QUIET, NON-DISMISSIBLE
 * while connected and STABLE in Doze. These tests pin the policy that makes it
 * so, as pure functions plus a few structural invariants over the service's own
 * wiring.
 *
 * Accuracy means a claim the datapath has not proven. The notification exists
 * before the tunnel is established (a service must be foreground before it can
 * dial), so it must say "Connecting..." until the carrying composite turns true
 * and only then "…tunnel is running". Non-dismissible means `.setOngoing(true)`
 * on the very notification that `startForeground` posts. Doze-correct means the
 * tunnel-status update path is silent (`.setOnlyAlertOnce`), deduplicated, and
 * uses `notify` rather than tearing the service down.
 */
class TunnelNotificationPolicyTest {

    // ---- Accuracy: the state derived from the carrying composite ----------

    @Test
    fun `CONNECTED requires the full carrying composite - every other bit is CONNECTING`() {
        assertTrue(
            VpnTunnelService.tunnelForegroundFor(
                serviceActive = true,
                engineReady = true,
                interfaceOpen = true,
            ) == VpnTunnelService.TunnelForegroundState.CONNECTED,
        )
        // The negative half: remove ANY one of the three and it must not claim
        // connected. This is what stops the notification (and the dashboard)
        // from painting a tunnel that is not carrying.
        val composites = listOf(
            Triple(false, true, true),
            Triple(true, false, true),
            Triple(true, true, false),
            Triple(true, false, false),
            Triple(false, true, false),
            Triple(false, false, true),
            Triple(false, false, false),
        )
        for ((active, ready, open) in composites) {
            assertEquals(
                "serviceActive=$active engineReady=$ready interfaceOpen=$open must be CONNECTING",
                VpnTunnelService.TunnelForegroundState.CONNECTING,
                VpnTunnelService.tunnelForegroundFor(active, ready, open),
            )
        }
    }

    @Test
    fun `CONNECTING text never claims protection`() {
        val connecting = VpnTunnelService.tunnelForegroundTextFor(
            disguised = false,
            state = VpnTunnelService.TunnelForegroundState.CONNECTING,
        )
        assertEquals("Connecting...", connecting)
        assertNotEquals(
            "a CONNECTING tunnel must not repeat the connected claim",
            "Encrypted network tunnel is running.",
            connecting,
        )
        assertTrue(
            "the connecting text must not assert the tunnel is running",
            !connecting.contains("running"),
        )
    }

    @Test
    fun `CONNECTED text is the only place the running claim appears, and only for a proven tunnel`() {
        assertEquals(
            "Encrypted network tunnel is running.",
            VpnTunnelService.tunnelForegroundTextFor(
                disguised = false,
                state = VpnTunnelService.TunnelForegroundState.CONNECTED,
            ),
        )
    }

    @Test
    fun `CONNECTING and CONNECTED titles are identical - a flappy title is a tell`() {
        val titleOf = { state: VpnTunnelService.TunnelForegroundState ->
            VpnTunnelService.tunnelForegroundTitleFor(false, state)
        }
        val connectingTitle = titleOf(VpnTunnelService.TunnelForegroundState.CONNECTING)
        assertEquals(
            "Win's VPN Active",
            connectingTitle,
        )
        assertEquals(
            "the title must not flicker across CONNECTING/CONNECTED",
            connectingTitle,
            titleOf(VpnTunnelService.TunnelForegroundState.CONNECTED),
        )
    }

    @Test
    fun `a disguised install reveals neither state nor identity`() {
        // The decoy app must not leak connection state AND must not name the
        // product, whatever the tunnel is doing.
        for (state in VpnTunnelService.TunnelForegroundState.values()) {
            assertEquals(
                VpnTunnelService.DISGUISED_DISPLAY_NAME,
                VpnTunnelService.tunnelForegroundTitleFor(true, state),
            )
            assertEquals(
                "Running in background.",
                VpnTunnelService.tunnelForegroundTextFor(true, state),
            )
        }
    }

    // ---- Importance: the channel settles at LOW, never louder -------------

    @Test
    fun `an inherited louder importance is quietened to LOW but never raised against the user`() {
        // LOW (2) is the ceiling; a DEFAULT/HIGH/MAX channel from an old build
        // is downgraded to LOW. A user who quietened further (MIN, or NONE for
        // fully hidden) is left exactly as they set it.
        assertEquals(2, VpnTunnelService.normalizedTunnelChannelImportance(3)) // DEFAULT -> LOW
        assertEquals(2, VpnTunnelService.normalizedTunnelChannelImportance(4)) // HIGH -> LOW
        assertEquals(2, VpnTunnelService.normalizedTunnelChannelImportance(5)) // MAX -> LOW
        assertEquals(2, VpnTunnelService.normalizedTunnelChannelImportance(2)) // LOW stays
        assertEquals(1, VpnTunnelService.normalizedTunnelChannelImportance(1)) // MIN preserved
        assertEquals(0, VpnTunnelService.normalizedTunnelChannelImportance(0)) // NONE preserved
    }

    // ---- Non-dismissible while connected + Doze-correct wiring ------------

    @Test
    fun `the notification posted to the shade is ongoing and never cleared`() {
        val source = mainSource()
        assertEquals(
            "the tunnel notification must be pinned with setOngoing(true); any edit " +
                "that makes it dismissible (a swipe kills a VPN's only always-on " +
                "surface) must fail here",
            true,
            source.contains(".setOngoing(true)"),
        )
    }

    @Test
    fun `state updates stay silent and deduplicated - the Doze contract`() {
        val source = mainSource()
        // A status re-paint must not re-alert / chime (bad in Doze and on a
        // watched device).
        assertTrue(
            "no setOnlyAlertOnce: a state flip would re-alert the shade",
            source.contains(".setOnlyAlertOnce(true)"),
        )
        // The dedupe latch: a busy health watchdog must not churn the row.
        assertTrue(
            "no dedupe latch: the 10s health loop would churn the shade",
            source.contains("if (lastPostedForegroundState == state) return"),
        )
        // The update path must be a silent in-place re-paint, never a teardown.
        val refresh = functionBody(source, "private fun refreshForegroundStatusNotification(")
        assertTrue(
            "the update path must notify, not stopForeground; body was:\n$refresh",
            refresh.contains("manager.notify(TUNNEL_NOTIFICATION_ID"),
        )
        assertTrue(
            "the update path must not stop the service; body was:\n$refresh",
            !refresh.contains("stopForeground"),
        )
    }

    @Test
    fun `every proven-engine site re-asserts the notification against the live composite`() {
        val source = mainSource()
        // All three engine-ready paths (AWG, Winn v3 promo gate, Winn seam
        // convergence) must flip the notification to connected on proof. If one
        // of them stops re-postining, a proven tunnel could still show
        // "Connecting..." -- a false NEGATIVE that is easy to ship.
        val reasserts = source.split(
            "refreshForegroundStatusNotification(currentTunnelForegroundState())",
        ).size - 1
        assertTrue(
            "expected the three engine-ready sites plus the health loop to " +
                "re-assert; found $reasserts",
            reasserts >= 4,
        )
    }

    @Test
    fun `the notification is re-posted on camouflage swap using the LIVE state, not a hardcoded one`() {
        val source = mainSource()
        // refreshForegroundNotificationForCamouflage -> startAsForegroundService
        // must describe the current state, so a swap while connected does not
        // flip a proven tunnel back to "Connecting...".
        val body = functionBody(source, "private fun startAsForegroundService(): Boolean")
        assertTrue(
            "startAsForegroundService must use the live state; body was:\n$body",
            body.contains("val state = currentTunnelForegroundState()"),
        )
        assertTrue(
            "startAsForegroundService must post the standard notification id",
            body.contains("startForeground(TUNNEL_NOTIFICATION_ID"),
        )
    }

    @Test
    fun `the connected claim text lives only in the policy, never inlined at a call site`() {
        val source = mainSource()
        // If the connected claim is inlined somewhere other than the policy, a
        // future edit could bypass the state gate and claim a running tunnel
        // before it is proven. It must occur exactly once: in
        // tunnelForegroundTextFor.
        val occurrences = source.split("Encrypted network tunnel is running.").size - 1
        assertEquals(1, occurrences)
    }

    // ---- A requested Double VPN running on one hop is never silent --------

    @Test
    fun `a single-hop session says so once the tunnel is proven`() {
        assertEquals(
            "Single hop: Double VPN unavailable.",
            VpnTunnelService.tunnelForegroundTextFor(
                disguised = false,
                state = VpnTunnelService.TunnelForegroundState.CONNECTED,
                doubleVpnSingleHop = true,
            ),
        )
    }

    @Test
    fun `the single-hop notice rewrites only the connected claim`() {
        // CONNECTING, RECOVERING and BLOCKED claim nothing about the route, so
        // they read exactly as they do for any other session.
        for (state in VpnTunnelService.TunnelForegroundState.values()) {
            if (state == VpnTunnelService.TunnelForegroundState.CONNECTED) continue
            for (disguised in listOf(false, true)) {
                assertEquals(
                    "state=$state disguised=$disguised",
                    VpnTunnelService.tunnelForegroundTextFor(disguised, state),
                    VpnTunnelService.tunnelForegroundTextFor(disguised, state, true),
                )
            }
        }
    }

    @Test
    fun `a session that is not single hop reads exactly as before`() {
        for (state in VpnTunnelService.TunnelForegroundState.values()) {
            for (disguised in listOf(false, true)) {
                assertEquals(
                    VpnTunnelService.tunnelForegroundTextFor(disguised, state),
                    VpnTunnelService.tunnelForegroundTextFor(disguised, state, false),
                )
            }
        }
        assertEquals(
            "Encrypted network tunnel is running.",
            VpnTunnelService.tunnelForegroundTextFor(
                disguised = false,
                state = VpnTunnelService.TunnelForegroundState.CONNECTED,
                doubleVpnSingleHop = false,
            ),
        )
    }

    @Test
    fun `a disguised notification is byte-identical for a marked and an unmarked session`() {
        // Owner ruling 2026-10-23: while the calculator disguise is on, the
        // single-hop marker changes NOTHING in the notification. The text is
        // the only thing the marker can reach (title is not even given it),
        // so identical text for every state is the whole runtime claim; the
        // structural test below pins that nothing else in the builder reads it.
        for (state in VpnTunnelService.TunnelForegroundState.values()) {
            val unmarked = VpnTunnelService.tunnelForegroundTextFor(
                disguised = true,
                state = state,
                doubleVpnSingleHop = false,
            )
            val marked = VpnTunnelService.tunnelForegroundTextFor(
                disguised = true,
                state = state,
                doubleVpnSingleHop = true,
            )
            assertEquals("state=$state", unmarked, marked)
            assertEquals("Running in background.", marked)
            assertEquals(
                VpnTunnelService.tunnelForegroundTitleFor(true, state),
                VpnTunnelService.DISGUISED_DISPLAY_NAME,
            )
        }
    }

    @Test
    fun `nothing in the notification builder other than the text can read the marker`() {
        val source = mainSource()
        val body = functionBody(
            source,
            "private fun buildForegroundNotification(state: TunnelForegroundState): Notification",
        )
        assertEquals(
            "the marker must appear exactly once in the builder: as the text argument",
            1,
            body.split("doubleVpnSingleHop").size - 1,
        )
        assertTrue(
            body.contains("val text = tunnelForegroundTextFor(disguised, state, doubleVpnSingleHop)"),
        )
        // Icon, channel, priority, actions and extras are all decided by
        // `disguised` and fixed builder calls. None may name the route.
        val withoutTextArgument = body.replace("doubleVpnSingleHop", "")
        for (forbidden in listOf("SINGLE_HOP", "SingleHop", "DOUBLE_VPN", "setSubText", "setExtras", "putExtra(\"double")) {
            assertFalse(
                "builder must not reference $forbidden",
                withoutTextArgument.contains(forbidden),
            )
        }
        // The disguised text constant of the previous candidate must be gone.
        assertFalse(source.contains("DISGUISED_SINGLE_HOP_TEXT"))
        assertFalse(source.contains("Running in background (limited)"))
    }

    @Test
    fun `the canonical saved choice is read as wanted, not wanted, or unknown`() {
        // The value of double_vpn_requested in the saved settings, as the app
        // itself reads it: only a boolean true is wanted.
        assertEquals(VpnTunnelService.DoubleVpnIntent.WANTED, VpnTunnelService.doubleVpnIntentFromChoice(true))
        assertEquals(VpnTunnelService.DoubleVpnIntent.NOT_WANTED, VpnTunnelService.doubleVpnIntentFromChoice(false))
        // An absent key and a JSON null are unknown during a native restart.
        assertEquals(VpnTunnelService.DoubleVpnIntent.UNKNOWN, VpnTunnelService.doubleVpnIntentFromChoice(null))
        val jsonNull = object : Any() {
            override fun toString() = "null"
        }
        assertEquals(VpnTunnelService.DoubleVpnIntent.UNKNOWN, VpnTunnelService.doubleVpnIntentFromChoice(jsonNull))
        assertEquals(VpnTunnelService.DoubleVpnIntent.UNKNOWN, VpnTunnelService.doubleVpnIntentFromChoice("null"))
        // Anything else is not a choice the app would have written.
        for (unknown in listOf<Any>("true", "1", 1, 0, "yes", listOf(true), emptyMap<String, Any>())) {
            assertEquals(
                "value=$unknown",
                VpnTunnelService.DoubleVpnIntent.UNKNOWN,
                VpnTunnelService.doubleVpnIntentFromChoice(unknown),
            )
        }
    }

    @Test
    fun `the marker follows route and CURRENT intent, never a stale one`() {
        val single = mapOf("doublevpnroute" to "single-hop")
        val two = mapOf("doublevpnroute" to "two-hop")
        val noRoute = mapOf("excludedpackages" to "a,b")
        val wanted = VpnTunnelService.DoubleVpnIntent.WANTED
        val notWanted = VpnTunnelService.DoubleVpnIntent.NOT_WANTED
        val unknown = VpnTunnelService.DoubleVpnIntent.UNKNOWN
        // B8: a saved single-hop config restored by the system while the user
        // now wants Double VPN comes up marked.
        assertTrue(VpnTunnelService.doubleVpnSingleHopFor(single, wanted))
        // Intent off never shows it.
        assertFalse(VpnTunnelService.doubleVpnSingleHopFor(single, notWanted))
        // A genuine Double config never shows it, whatever the intent.
        for (intent in listOf(wanted, notWanted, unknown)) {
            assertFalse("intent=$intent", VpnTunnelService.doubleVpnSingleHopFor(two, intent))
        }
        // Unknown intent is treated as wanted (fail toward telling).
        assertTrue(VpnTunnelService.doubleVpnSingleHopFor(single, unknown))
        // R2-02, owner ruling: a config saved by an older build names no route.
        // It is restarted and marked while Double VPN is wanted or the choice is
        // unknown, and not marked when Double VPN is off.
        for (legacy in listOf(noRoute, emptyMap())) {
            assertTrue(VpnTunnelService.doubleVpnSingleHopFor(legacy, wanted))
            assertTrue(VpnTunnelService.doubleVpnSingleHopFor(legacy, unknown))
            assertFalse(VpnTunnelService.doubleVpnSingleHopFor(legacy, notWanted))
        }
        // Spelling is tolerated; only the exact two-hop value clears a marker.
        assertTrue(VpnTunnelService.doubleVpnSingleHopFor(mapOf("doublevpnroute" to " Single-Hop "), wanted))
        assertFalse(VpnTunnelService.doubleVpnSingleHopFor(mapOf("doublevpnroute" to " Two-Hop "), wanted))
        assertTrue(VpnTunnelService.doubleVpnSingleHopFor(mapOf("doublevpnroute" to "single"), wanted))
        assertTrue(VpnTunnelService.doubleVpnSingleHopFor(mapOf("doublevpnroute" to "two-hop;single-hop"), wanted))
    }

    // ---- R2-01 and R2-02: the service decision on real INI text, with the
    // canonical settings and the stale copy as separate, injectable facts. ----

    private val ini = "[Interface]\nPrivateKey = k\nAddress = 10.9.1.2/32\n\n" +
        "[Peer]\nPublicKey = p\nEndpoint = 198.51.100.7:9210\n\n"

    /** A saved config written by a build that stamps the route. */
    private fun savedWithRoute(route: String) =
        ini + "[WinsApp]\nExcludedPackages = \nExcludedPathsB64 = \nDoubleVpnRoute = $route\n"

    /** A saved config written BEFORE the route existed: the actual old section shape. */
    private val legacySaved = ini + "[WinsDebug]\nClientPublicKey = k\n\n" +
        "[WinsApp]\nExcludedPackages = \nExcludedPathsB64 = \n\n"

    /**
     * What the service does on a (re)start, with the canonical value of
     * `double_vpn_requested` it read (or null when the settings could not be
     * read) and a stale `route_intent.txt` copy that the decision must not see.
     */
    private fun restartMarker(config: String, canonical: Any?, readable: Boolean, staleCopy: String?): Boolean {
        @Suppress("UNUSED_VARIABLE") val ignored = staleCopy
        val intent = if (!readable) {
            VpnTunnelService.DoubleVpnIntent.UNKNOWN
        } else {
            VpnTunnelService.doubleVpnIntentFromChoice(canonical)
        }
        return VpnTunnelService.doubleVpnSingleHopForRestart(config, intent)
    }

    @Test
    fun `R2-01 settings false with a stale copy of 1 gives no marker`() {
        for (copy in listOf("1", "0", null, "garbage")) {
            assertFalse(
                "single-hop route, copy=$copy",
                restartMarker(savedWithRoute("single-hop"), false, true, copy),
            )
            assertFalse(
                "legacy, copy=$copy",
                restartMarker(legacySaved, false, true, copy),
            )
        }
    }

    @Test
    fun `R2-01 settings true with a stale copy of 0 gives the marker`() {
        for (copy in listOf("0", "1", null, "garbage")) {
            assertTrue(
                "single-hop route, copy=$copy",
                restartMarker(savedWithRoute("single-hop"), true, true, copy),
            )
        }
    }

    @Test
    fun `R2-01 with the settings unreadable and the copy failing too a one-hop restart is marked`() {
        // Both writes failed or the store cannot be read: nothing authoritative
        // says Double VPN is off, so the restart is marked, never silent.
        for (copy in listOf("0", "1", null)) {
            assertTrue(restartMarker(savedWithRoute("single-hop"), null, false, copy))
            assertTrue(restartMarker(legacySaved, null, false, copy))
        }
        // A settings document that does not hold a boolean is unknown as well.
        assertTrue(restartMarker(savedWithRoute("single-hop"), "true", true, "0"))
    }

    @Test
    fun `R2-02 a legacy saved INI restarted with Double VPN on is marked, with it off is not`() {
        assertTrue(restartMarker(legacySaved, true, true, null))
        assertTrue("choice unknown", restartMarker(legacySaved, null, false, null))
        assertFalse(restartMarker(legacySaved, false, true, null))
        // The old file has no route key at all.
        assertEquals(
            emptyMap<String, String>(),
            VpnTunnelService.parseConfigSectionOf(legacySaved, "winsapp").filterKeys { it == "doublevpnroute" },
        )
    }

    @Test
    fun `R2-02 a config saved as two-hop is never marked`() {
        for (canonical in listOf<Any?>(true, false, null, "x")) {
            for (readable in listOf(true, false)) {
                assertFalse(
                    "canonical=$canonical readable=$readable",
                    restartMarker(savedWithRoute("two-hop"), canonical, readable, "1"),
                )
            }
        }
    }

    @Test
    fun `R2-02 the restart is never refused or cleared for an indeterminate route or choice`() {
        val source = mainSource()
        assertFalse(source.contains("Refusing tunnel start"))
        // The start path around the marker decision must not return early.
        val decided = source.indexOf(
            "doubleVpnSingleHop = doubleVpnSingleHopFor(appSection, readDoubleVpnIntent())",
        )
        val nextFifteen = source.substring(decided, decided + 700)
        assertFalse(nextFifteen.contains("return START_NOT_STICKY"))
        assertFalse(nextFifteen.contains("clearRestartConfig()"))
        assertFalse(nextFifteen.contains("executeTunnelTeardown()"))
    }

    @Test
    fun `a restart judges the saved config against the choice in force now`() {
        // The same saved single-hop config, restored three times as the user
        // changes their mind: the text follows the intent, not the config.
        val saved = mapOf("doublevpnroute" to "single-hop")
        val connected = VpnTunnelService.TunnelForegroundState.CONNECTED
        fun textFor(intent: VpnTunnelService.DoubleVpnIntent, disguised: Boolean) =
            VpnTunnelService.tunnelForegroundTextFor(
                disguised,
                connected,
                VpnTunnelService.doubleVpnSingleHopFor(saved, intent),
            )
        assertEquals(
            "Encrypted network tunnel is running.",
            textFor(VpnTunnelService.DoubleVpnIntent.NOT_WANTED, false),
        )
        assertEquals(
            "Single hop: Double VPN unavailable.",
            textFor(VpnTunnelService.DoubleVpnIntent.WANTED, false),
        )
        assertEquals(
            "Single hop: Double VPN unavailable.",
            textFor(VpnTunnelService.DoubleVpnIntent.UNKNOWN, false),
        )
        // Disguised: all three are the ordinary disguised notification.
        for (intent in VpnTunnelService.DoubleVpnIntent.values()) {
            assertEquals("Running in background.", textFor(intent, true))
        }
    }

    @Test
    fun `the service decides the marker at every start and restart from its own reads`() {
        val source = mainSource()
        // Both a Dart start and a START_STICKY or always-on restart reach the
        // same line, after the config has been resolved from the saved copy.
        val resolved = source.indexOf("val config = suppliedConfig.ifBlank {")
        val decided = source.indexOf(
            "doubleVpnSingleHop = doubleVpnSingleHopFor(appSection, readDoubleVpnIntent())",
        )
        val foreground = source.indexOf("if (!startAsForegroundService()) {")
        assertTrue(resolved in 0 until decided)
        assertTrue("the first notification must already know the route", decided < foreground)
        assertEquals(1, source.split("doubleVpnSingleHop = doubleVpnSingleHopFor(").size - 1)
        // The choice is the CANONICAL saved one (vpn_settings.txt). The legacy
        // copy is never read, and a read that throws is UNKNOWN, never a crash
        // and never "not wanted".
        val readerStart = source.indexOf("private fun readDoubleVpnIntent(): DoubleVpnIntent")
        val readerEnd = source.indexOf("private fun loadRestartConfig()", readerStart)
        assertTrue(readerStart in 0 until readerEnd)
        val reader = source.substring(readerStart, readerEnd)
        assertTrue(reader.contains("File(File(applicationInfo.dataDir, \"app_flutter\"), \"vpn_settings.txt\")"))
        assertTrue(reader.contains("secureFileStore.read(\"vpn_settings.txt\", legacy)"))
        assertTrue(reader.contains("\"double_vpn_requested\""))
        assertFalse(reader.contains("DOUBLE_VPN_INTENT_RECORD"))
        assertTrue(reader.contains("catch (e: Exception)"))
        assertTrue(reader.contains("DoubleVpnIntent.UNKNOWN"))
        assertFalse(reader.contains("NOT_WANTED"))
        // R2-05: the copy is retired with the restart state.
        val clearStart = source.indexOf("private fun clearRestartConfig()")
        val clearEnd = source.indexOf("private fun restartConfigFile()", clearStart)
        assertTrue(clearStart in 0 until clearEnd)
        assertTrue(source.substring(clearStart, clearEnd).contains("secureFileStore.delete(DOUBLE_VPN_INTENT_RECORD)"))
        // Teardown clears it; readiness reports the same field.
        assertTrue(source.contains("doubleVpnSingleHop = false"))
        assertTrue(
            source.contains("DOUBLE_VPN_READINESS_KEY to (activeInstance?.doubleVpnSingleHop == true)"),
        )
        assertEquals("double_vpn_single_hop", VpnTunnelService.DOUBLE_VPN_READINESS_KEY)
        assertEquals("route_intent.txt", VpnTunnelService.DOUBLE_VPN_INTENT_RECORD)
    }

    /** Reads the service source from the test working directory (walk-up). */
    private fun mainSource(): String {
        var dir: java.io.File? = java.io.File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            for (relative in listOf(
                "src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt",
                "android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt",
            )) {
                val candidate = java.io.File(dir, relative)
                if (candidate.isFile) return candidate.readText()
            }
            dir = dir.parentFile
        }
        throw AssertionError(
            "could not locate VpnTunnelService.kt from ${System.getProperty("user.dir")}",
        )
    }

    /** Brace-balanced body of the declaration starting with [signature]. */
    private fun functionBody(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("could not find $signature", start >= 0)
        val open = source.indexOf('{', start)
        assertTrue("no body for $signature", open >= 0)
        var depth = 0
        var i = open
        while (i < source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> depth--
            }
            if (depth == 0) return source.substring(open, i + 1)
            i++
        }
        throw AssertionError("unterminated body for $signature")
    }
}
