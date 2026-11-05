package org.winsvpn.app.wear

import androidx.compose.ui.graphics.toArgb
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneSnapshotTest {

    @Test
    fun `wire payload cannot claim a phone source node`() {
        val forged = PhoneSnapshot.parse("""{"status":"connected","sourceNodeId":"phone-a"}""")
        assertNull(forged?.sourceNodeId)
    }

    @Test
    fun `parses a full snapshot`() {
        val snapshot = PhoneSnapshot.parse(
            """
            {"v":1,"status":"connected","detail":"Tokyo","selectedSlug":"jp-1",
             "canConnect":true,"updatedAt":1234,
             "countries":[{"slug":"jp-1","name":"Japan","flag":"🇯🇵"},
                          {"slug":"de-1","name":"Germany","flag":"🇩🇪"}]}
            """.trimIndent()
        )

        assertNotNull(snapshot)
        requireNotNull(snapshot)
        assertEquals(TunnelStatus.CONNECTED, snapshot.status)
        assertEquals("Tokyo", snapshot.detail)
        assertEquals(2, snapshot.countries.size)
        assertEquals("Japan", snapshot.selectedCountry?.name)
        assertTrue(snapshot.canConnect)
        assertEquals(1234L, snapshot.updatedAt)
    }

    @Test
    fun `unknown status does not crash and is not treated as connected`() {
        val snapshot = PhoneSnapshot.parse("""{"status":"teleporting"}""")
        requireNotNull(snapshot)
        assertEquals(TunnelStatus.UNKNOWN, snapshot.status)
        assertFalse(snapshot.status.isOnOrGoingOn)
        assertFalse(snapshot.status.isBusy)
    }

    @Test
    fun `missing canConnect defaults to true for forward compatibility`() {
        val snapshot = PhoneSnapshot.parse("""{"status":"disconnected"}""")
        requireNotNull(snapshot)
        assertTrue(snapshot.canConnect)
    }

    @Test
    fun `malformed payloads degrade to null rather than throwing`() {
        assertNull(PhoneSnapshot.parse("not json"))
        assertNull(PhoneSnapshot.parse(""))
        assertNull(PhoneSnapshot.parse(null as String?))
        assertNull(PhoneSnapshot.parse(ByteArray(0)))
    }

    @Test
    fun `countries without a slug are dropped`() {
        val snapshot = PhoneSnapshot.parse(
            """{"countries":[{"name":"Nowhere"},{"slug":"us-1","name":"United States"}]}"""
        )
        requireNotNull(snapshot)
        assertEquals(1, snapshot.countries.size)
        assertEquals("us-1", snapshot.countries.single().slug)
    }

    @Test
    fun `country falls back to its slug when the phone sends no name`() {
        val snapshot = PhoneSnapshot.parse("""{"countries":[{"slug":"sg-1"}]}""")
        requireNotNull(snapshot)
        assertEquals("sg-1", snapshot.countries.single().name)
    }

    @Test
    fun `connecting and disconnecting are busy states`() {
        assertTrue(TunnelStatus.CONNECTING.isBusy)
        assertTrue(TunnelStatus.DISCONNECTING.isBusy)
        assertFalse(TunnelStatus.CONNECTED.isBusy)
        assertTrue(TunnelStatus.CONNECTING.isOnOrGoingOn)
        assertTrue(TunnelStatus.CONNECTED.isOnOrGoingOn)
        assertFalse(TunnelStatus.FAILED.isOnOrGoingOn)
    }

    @Test
    fun `encoded commands carry only an intent and never a credential`() {
        val json = JSONObject(String(WatchLink.encodeCommand(WatchLink.COMMAND_SELECT_COUNTRY, "jp-1")))
        assertEquals(WatchLink.COMMAND_SELECT_COUNTRY, json.getString(WatchLink.FIELD_COMMAND))
        assertEquals("jp-1", json.getString(WatchLink.FIELD_SLUG))
        assertEquals(setOf("v", WatchLink.FIELD_COMMAND, WatchLink.FIELD_SLUG), json.keys().asSequence().toSet())
        val encoded = json.toString().lowercase()
        assertFalse(encoded.contains("winn"))
        assertFalse(encoded.contains("xray"))
        assertFalse(encoded.contains("amnezia"))
        assertFalse(json.has("engine"))
    }

    @Test
    fun `a command without a slug omits the field entirely`() {
        val json = JSONObject(String(WatchLink.encodeCommand(WatchLink.COMMAND_DISCONNECT)))
        assertFalse(json.has(WatchLink.FIELD_SLUG))
    }

    @Test
    fun `load_pct is read when it is exactly a contract value`() {
        val snapshot = PhoneSnapshot.parse(
            """{"countries":[{"slug":"a","load_pct":0},{"slug":"b","load_pct":55},
               {"slug":"c","load_pct":60},{"slug":"d","load_pct":85},{"slug":"e","load_pct":100}]}"""
        )
        requireNotNull(snapshot)
        assertEquals(listOf(0, 55, 60, 85, 100), snapshot.countries.map { it.loadPct })
    }

    @Test
    fun `every malformed load_pct is unknown and never costs the list`() {
        val snapshot = PhoneSnapshot.parse(
            """{"countries":[
               {"slug":"missing"},
               {"slug":"null","load_pct":null},
               {"slug":"string","load_pct":"45"},
               {"slug":"float","load_pct":45.5},
               {"slug":"integral-float","load_pct":45.0},
               {"slug":"negative","load_pct":-5},
               {"slug":"over","load_pct":105},
               {"slug":"off-step","load_pct":47},
               {"slug":"bool","load_pct":true},
               {"slug":"object","load_pct":{"v":45}},
               {"slug":"array","load_pct":[45]},
               {"slug":"huge","load_pct":99999999999999999999}]}"""
        )
        requireNotNull(snapshot)
        assertEquals(12, snapshot.countries.size)
        snapshot.countries.forEach { assertNull("${it.slug} must be unknown", it.loadPct) }
    }

    @Test
    fun `load bar colour thresholds match the phone`() {
        assertNull(ServerLoadColors.fillFor(null))
        assertEquals(ServerLoadColors.low, ServerLoadColors.fillFor(0))
        assertEquals(ServerLoadColors.low, ServerLoadColors.fillFor(55))
        assertEquals(ServerLoadColors.elevated, ServerLoadColors.fillFor(60))
        assertEquals(ServerLoadColors.elevated, ServerLoadColors.fillFor(80))
        assertEquals(ServerLoadColors.high, ServerLoadColors.fillFor(85))
        assertEquals(ServerLoadColors.high, ServerLoadColors.fillFor(100))
        assertEquals(0f, ServerLoadColors.fillFraction(null))
        assertTrue(ServerLoadColors.fillFraction(0) > 0f)
        assertEquals(1f, ServerLoadColors.fillFraction(100))
    }

    @Test
    fun `the bar edge keeps 3 to 1 on every chip background it can sit on`() {
        // Wear Material defaults read from compose-material 1.6.2 bytecode.
        val surface = 0xFF303133.toInt() // secondaryChipColors background
        val primary = 0xFFAECBFA.toInt() // primaryChipColors background (selected)
        val background = 0xFF000000.toInt() // Scaffold background behind chips
        val backgrounds = mapOf(
            "unselected chip" to ServerLoadColors.chipBackgroundArgb(surface, true, background),
            "unselected chip, disabled" to ServerLoadColors.chipBackgroundArgb(surface, false, background),
            "selected chip" to ServerLoadColors.chipBackgroundArgb(primary, true, background),
            "selected chip, disabled" to ServerLoadColors.chipBackgroundArgb(primary, false, background),
            "home chip (secondary, enabled)" to ServerLoadColors.chipBackgroundArgb(surface, true, background),
        )
        // Composites are what Wear draws: 0.38 alpha over black.
        assertEquals(0xFF121313.toInt(), backgrounds.getValue("unselected chip, disabled"))
        assertEquals(0xFF424D5F.toInt(), backgrounds.getValue("selected chip, disabled"))
        for ((name, bg) in backgrounds) {
            val edge = ServerLoadColors.outlineFor(bg).toArgb()
            assertTrue("$name: edge ${Integer.toHexString(edge)} on ${Integer.toHexString(bg)} " +
                "= ${contrast(edge, bg)}", contrast(edge, bg) >= 3.0)
        }
        // The turn 2 defect, as a control: a fixed light outline on the
        // selected chip is 1.20:1.
        assertTrue(contrast(ServerLoadColors.outline.toArgb(), primary) < 3.0)
        // Fills sit on the dark track inside the edge.
        val track = ServerLoadColors.track.toArgb()
        for (fill in listOf(ServerLoadColors.low, ServerLoadColors.elevated, ServerLoadColors.high)) {
            assertTrue("fill vs track", contrast(fill.toArgb(), track) >= 3.0)
        }
        // The shipped helper agrees with this test's own formula.
        assertEquals(contrast(0xFFDADCE0.toInt(), primary), ServerLoadColors.contrast(0xFFDADCE0.toInt(), primary), 1e-9)
    }

    // ---- load_at and freshness (Round LC OI-5) ------------------------------

    private val loadAt = 1_790_480_000L // seconds
    private val publishedAt = loadAt * 1000 + 2_500 // phone published 2.5 s later

    private fun liveSnapshot(country: WatchCountry, arrivedAt: Long = 10_000L) = PhoneSnapshot(
        status = TunnelStatus.CONNECTED,
        detail = "",
        selectedSlug = country.slug,
        countries = listOf(country),
        canConnect = true,
        updatedAt = publishedAt,
        arrivedAtElapsedMs = arrivedAt,
    )

    private val jp = WatchCountry("jp-1", "Japan", "JP", loadPct = 45, loadAtSec = loadAt)

    @Test
    fun `load_at is parsed strictly and a parsed snapshot counts as restored`() {
        val snapshot = PhoneSnapshot.parse(
            """{"updatedAt":1790480002500,"countries":[
               {"slug":"a","load_pct":45,"load_at":1790480000},
               {"slug":"b","load_pct":45,"load_at":"1790480000"},
               {"slug":"c","load_pct":45,"load_at":1790480000.5},
               {"slug":"d","load_pct":45,"load_at":-1},
               {"slug":"e","load_pct":45,"load_at":null},
               {"slug":"f","load_pct":45}]}"""
        )
        requireNotNull(snapshot)
        assertEquals(6, snapshot.countries.size)
        assertEquals(listOf(1_790_480_000L, null, null, null, null, null), snapshot.countries.map { it.loadAtSec })
        assertNull("parse() never stamps an arrival", snapshot.arrivedAtElapsedMs)
    }

    @Test
    fun `a live figure shows until 60 s after the phone received it`() {
        val snap = liveSnapshot(jp)
        val wallAtArrival = publishedAt + 300 // 300 ms transit, clocks agree
        assertEquals(45, LoadFreshness.visibleLoadPct(jp, snap, 10_000L, wallAtArrival))
        // 60 s after load_at on both clocks.
        val later = 60_000L - 2_500L - 300L
        assertEquals(45, LoadFreshness.visibleLoadPct(jp, snap, 10_000L + later - 1, wallAtArrival + later - 1))
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L + later, wallAtArrival + later))
        assertEquals(1L, LoadFreshness.msUntilExpiry(jp, snap, 10_000L + later - 1, wallAtArrival + later - 1))
        assertNull(LoadFreshness.msUntilExpiry(jp, snap, 10_000L + later, wallAtArrival + later))
    }

    @Test
    fun `a snapshot restored from storage never shows load`() {
        val restored = liveSnapshot(jp).copy(arrivedAtElapsedMs = null)
        assertNull(LoadFreshness.visibleLoadPct(jp, restored, 10_000L, publishedAt))
    }

    @Test
    fun `a load_at in the watch future is unknown`() {
        val snap = liveSnapshot(jp)
        // Watch clock 5 s behind the phone: load_at is in its future.
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L, loadAt * 1000 - 5_000))
    }

    @Test
    fun `a watch clock ahead of the phone only expires early`() {
        val snap = liveSnapshot(jp)
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L, publishedAt + 120_000))
    }

    @Test
    fun `a delayed delivery is caught by the wall clock`() {
        // Published at load_at + 2.5 s, delivered 5 minutes later (watch was out
        // of range); clocks agree. Time since arrival alone would say ~2.5 s.
        val snap = liveSnapshot(jp)
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L, publishedAt + 300_000))
    }

    @Test
    fun `time since arrival is counted even if the watch clock is set back`() {
        val snap = liveSnapshot(jp)
        // 70 s pass on the monotonic clock; the wall clock was moved back 70 s.
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L + 70_000L, publishedAt))
    }

    @Test
    fun `old phone and malformed stamps render unknown, never throw`() {
        val snap = liveSnapshot(jp)
        val noLoadAt = jp.copy(loadAtSec = null) // an old phone never sends it
        val noLoad = jp.copy(loadPct = null)
        assertNull(LoadFreshness.visibleLoadPct(noLoadAt, snap, 10_000L, publishedAt))
        assertNull(LoadFreshness.visibleLoadPct(noLoad, snap, 10_000L, publishedAt))
        assertNull(LoadFreshness.visibleLoadPct(jp, snap.copy(updatedAt = 0L), 10_000L, publishedAt))
        // updatedAt earlier than load_at: inconsistent, unknown.
        assertNull(LoadFreshness.visibleLoadPct(jp, snap.copy(updatedAt = loadAt * 1000 - 1), 10_000L, publishedAt))
        // Monotonic time running backwards: unknown.
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 9_999L, publishedAt))
    }

    // ---- Round LC turn 2: overflow in load_at * 1000 ----------------------

    @Test
    fun `Sol's overflow case is unknown, not fresh`() {
        val hostile = 2_305_843_011_004_173_952L
        // Premise: the naive multiplication really does wrap to a present-day
        // value, which is how the turn 2 code rendered it fresh.
        assertEquals(1_790_480_000_000L, hostile * 1000L)
        val country = jp.copy(loadAtSec = hostile)
        val snap = liveSnapshot(country).copy(updatedAt = 1_790_480_002_500L)
        assertNull(LoadFreshness.ageMs(country, snap, 10_000L, 1_790_480_002_800L))
        assertNull(LoadFreshness.visibleLoadPct(country, snap, 10_000L, 1_790_480_002_800L))
    }

    @Test
    fun `extreme load_at values are unknown at render time`() {
        val snap = liveSnapshot(jp)
        for (bad in listOf(
            Long.MAX_VALUE,
            Long.MIN_VALUE,
            -1L,
            0L,
            MIN_LOAD_AT_SEC - 1,
            MAX_LOAD_AT_SEC + 1,
            9_007_199_254_740_993L, // 2^53 + 1
            Long.MAX_VALUE / 1000L,
            Long.MAX_VALUE / 1000L + 1,
        )) {
            val c = jp.copy(loadAtSec = bad)
            assertNull("load_at=$bad", LoadFreshness.visibleLoadPct(c, snap, 10_000L, publishedAt + 300))
        }
    }

    @Test
    fun `extreme load_at values are rejected by the parser`() {
        val snapshot = PhoneSnapshot.parse(
            """{"countries":[
               {"slug":"sol","load_pct":45,"load_at":2305843011004173952},
               {"slug":"max","load_pct":45,"load_at":9223372036854775807},
               {"slug":"min","load_pct":45,"load_at":-9223372036854775808},
               {"slug":"neg","load_pct":45,"load_at":-1},
               {"slug":"p53","load_pct":45,"load_at":9007199254740993},
               {"slug":"over64","load_pct":45,"load_at":18446744073709551616},
               {"slug":"below","load_pct":45,"load_at":1599999999},
               {"slug":"above","load_pct":45,"load_at":4102444801},
               {"slug":"lo-edge","load_pct":45,"load_at":1600000000},
               {"slug":"hi-edge","load_pct":45,"load_at":4102444800}]}"""
        )
        requireNotNull(snapshot)
        assertEquals(10, snapshot.countries.size)
        val got = snapshot.countries.associate { it.slug to it.loadAtSec }
        for (slug in listOf("sol", "max", "min", "neg", "p53", "over64", "below", "above")) {
            assertNull(slug, got[slug])
        }
        assertEquals(1_600_000_000L, got["lo-edge"])
        assertEquals(4_102_444_800L, got["hi-edge"])
    }

    @Test
    fun `a hostile updatedAt cannot overflow the age sum into freshness`() {
        // publishAge ~ Long.MAX; with a large monotonic reading the unguarded
        // sum publishAge + sinceArrival wraps negative and max() would pick
        // the small wall age.
        val snap = liveSnapshot(jp, arrivedAt = 0L).copy(updatedAt = Long.MAX_VALUE)
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, Long.MAX_VALUE / 2, publishedAt + 300))
        assertNull(LoadFreshness.msUntilExpiry(jp, snap, Long.MAX_VALUE / 2, publishedAt + 300))
    }

    @Test
    fun `an absurd watch clock is unknown, not an overflow`() {
        val snap = liveSnapshot(jp)
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L, Long.MIN_VALUE))
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L, 0L))
        // A far-future watch clock: load_at is far in the past -> expired.
        assertNull(LoadFreshness.visibleLoadPct(jp, snap, 10_000L, Long.MAX_VALUE))
    }

    // ---- published bands and Burmese strings (Round LC turn 3) ------------

    @Test
    fun `published bands 25 60 90 100 are green amber red red`() {
        // 60 (busy) sits exactly on the amber threshold; a `>` would make it green.
        assertEquals(ServerLoadColors.low, ServerLoadColors.fillFor(25))
        assertEquals(ServerLoadColors.elevated, ServerLoadColors.fillFor(60))
        assertEquals(ServerLoadColors.high, ServerLoadColors.fillFor(90))
        assertEquals(ServerLoadColors.high, ServerLoadColors.fillFor(100))
    }

    @Test
    fun `Burmese watch strings match the phone's owner-approved wording`() {
        // Owner ruling: .agent/debates/_decisions/owner_ruling_load_bar_burmese_20260927.md
        val root = listOf(java.io.File("."), java.io.File(".."), java.io.File("../.."), java.io.File("../../.."))
            .firstOrNull { java.io.File(it, "wear_os/app/src/main/res/values-my/strings.xml").isFile }
            ?: error("repo root not found from ${java.io.File(".").absolutePath}")
        fun strings(path: String): Map<String, String> =
            Regex("<string name=\"([a-z_]+)\">([^<]*)</string>")
                .findAll(java.io.File(root, path).readText(Charsets.UTF_8))
                .associate { it.groupValues[1] to it.groupValues[2] }
        val my = strings("wear_os/app/src/main/res/values-my/strings.xml")
        val en = strings("wear_os/app/src/main/res/values/strings.xml")
        val arb = JSONObject(java.io.File(root, "lib/l10n/app_my.arb").readText(Charsets.UTF_8))
        val percent = my["watch_server_load_percent"] ?: error("watch_server_load_percent missing in values-my")
        val unknown = my["watch_server_load_unknown"] ?: error("watch_server_load_unknown missing in values-my")
        // Same bytes as the Flutter ARB, with Android's placeholder and %% escape.
        assertEquals(arb.getString("serverLoadPercent").replace("{percent}%", "%1\$d%%"), percent)
        assertEquals(arb.getString("serverLoadUnknown"), unknown)
        // Placeholder shape matches English, and it formats.
        assertTrue(en.getValue("watch_server_load_percent").endsWith("%1\$d%%"))
        assertTrue(percent.endsWith("%1\$d%%"))
        val formatted = String.format(percent, 60)
        assertTrue(formatted, formatted.endsWith("60%"))
        for (s in listOf(percent, unknown, formatted)) {
            assertFalse("no U+FFFD in $s", s.contains('\uFFFD'))
            assertFalse("no Latin placeholder left in $s", s.contains("{percent}"))
        }
        // Burmese script actually present (not an English fallback copy).
        assertTrue(unknown.any { it in '\u1000'..'\u109F' })
    }

    private fun contrast(a: Int, b: Int): Double {
        fun lum(c: Int): Double {
            fun ch(v: Int): Double {
                val s = v / 255.0
                return if (s <= 0.03928) s / 12.92 else Math.pow((s + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * ch((c shr 16) and 0xFF) + 0.7152 * ch((c shr 8) and 0xFF) + 0.0722 * ch(c and 0xFF)
        }
        val la = lum(a)
        val lb = lum(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }
}
