package org.winsvpn.app.wear

import org.json.JSONObject

/**
 * The watch <-> phone wire contract.
 *
 * Deliberately tiny. The watch is a remote control: it sends an intent
 * ("connect", "disconnect", "select this country") and renders whatever state
 * the phone reports back. It never selects a tunnel engine. The paired phone
 * runs Winn v3 as the primary protocol, then the ordered Winn v1 AWG-then-Xray
 * fallback. The watch never sees an account number, a key, a tunnel config, a
 * server address or a token, and it never persists one -- the only server
 * identity that crosses the link is the opaque node slug the phone already
 * shows in its own picker, plus a display name and a flag emoji.
 *
 * The same field names and values are used by the watchOS build so there is one
 * contract to reason about, not two.
 */
object WatchLink {

    /** MessageClient path: watch -> phone commands. UTF-8 JSON body. */
    const val PATH_COMMAND = "/winsvpn/cmd"

    /** MessageClient + DataClient path: phone -> watch state. UTF-8 JSON body. */
    const val PATH_STATE = "/winsvpn/state"

    /** DataItem key holding the UTF-8 JSON snapshot on [PATH_STATE]. */
    const val KEY_SNAPSHOT = "snapshot"

    const val COMMAND_CONNECT = "connect"
    const val COMMAND_DISCONNECT = "disconnect"
    const val COMMAND_SELECT_COUNTRY = "selectCountry"
    const val COMMAND_REQUEST_STATE = "requestState"

    const val FIELD_COMMAND = "command"
    const val FIELD_SLUG = "slug"

    /** Bumped only if the field set changes incompatibly. */
    const val PROTOCOL_VERSION = 1

    fun encodeCommand(command: String, slug: String? = null): ByteArray {
        val json = JSONObject()
            .put("v", PROTOCOL_VERSION)
            .put(FIELD_COMMAND, command)
        if (!slug.isNullOrBlank()) {
            json.put(FIELD_SLUG, slug)
        }
        return json.toString().toByteArray(Charsets.UTF_8)
    }
}

/**
 * What the phone says its tunnel is doing.
 *
 * [PERMISSION_REQUIRED] is the state that most often makes a naive watch app
 * look broken: the OS VPN consent prompt (Android's VpnService dialog, Apple's
 * VPN configuration approval) has not been granted. A watch cannot grant it and
 * must never try to; the only correct behaviour is to say so and stop.
 */
enum class TunnelStatus(val wireValue: String) {
    DISCONNECTED("disconnected"),
    CONNECTING("connecting"),
    CONNECTED("connected"),
    DISCONNECTING("disconnecting"),
    FAILED("failed"),
    PERMISSION_REQUIRED("permissionRequired"),
    UNKNOWN("unknown");

    val isBusy: Boolean
        get() = this == CONNECTING || this == DISCONNECTING

    /** True when tapping the toggle should mean "stop", not "start". */
    val isOnOrGoingOn: Boolean
        get() = this == CONNECTED || this == CONNECTING

    companion object {
        fun fromWire(value: String?): TunnelStatus =
            entries.firstOrNull { it.wireValue.equals(value, ignoreCase = true) } ?: UNKNOWN
    }
}

/** One selectable exit country, exactly as the phone already labels it. */
data class WatchCountry(
    val slug: String,
    val name: String,
    val flag: String,
    /**
     * Hub-reported load, 0..100 in steps of 5, or null when unknown. Absent on
     * every snapshot from a phone build that predates the field.
     */
    val loadPct: Int? = null,
    /**
     * When the PHONE received [loadPct]: whole seconds since the Unix epoch on
     * the phone's clock, or null. A figure without it is never shown.
     */
    val loadAtSec: Long? = null,
)

/** Wire key for [WatchCountry.loadPct]; the same key the hub and phone use. */
internal const val FIELD_LOAD_PCT = "load_pct"

/** Wire key for [WatchCountry.loadAtSec] (lib/watch_bridge.dart kWatchLoadAtKey). */
internal const val FIELD_LOAD_AT = "load_at"

/**
 * The one parser for `load_pct`. Total: anything that is not an integer in
 * 0..100 on a step of 5 is unknown (null): a string, a float, a bool, JSON
 * null, a negative, over 100, off-step, or no key at all. It never throws, so
 * one bad value can never cost the watch its country list.
 */
internal fun parseLoadPct(raw: Any?): Int? {
    val value = when (raw) {
        is Int -> raw.toLong()
        is Long -> raw
        else -> return null
    }
    if (value < 0L || value > 100L || value % 5L != 0L) return null
    return value.toInt()
}

/**
 * Plausible window for `load_at`, in epoch seconds. Checked on the raw value
 * BEFORE any arithmetic (Round LC turn 2: a `load_at` of 2305843011004173952
 * wrapped to a present-day value when multiplied by 1000 and rendered fresh).
 * 1_600_000_000 is 2020-09-13, before this feature existed; 4_102_444_800 is
 * 2100-01-01. The upper bound that matters at render time is "not after this
 * watch's now" ([LoadFreshness.ageMs]); this one just keeps absurd values out.
 */
internal const val MIN_LOAD_AT_SEC = 1_600_000_000L
internal const val MAX_LOAD_AT_SEC = 4_102_444_800L

/** Total parser for `load_at`: an integer inside the window above, else null. */
internal fun parseLoadAtSec(raw: Any?): Long? {
    val value = when (raw) {
        is Int -> raw.toLong()
        is Long -> raw
        else -> return null
    }
    return if (value < MIN_LOAD_AT_SEC || value > MAX_LOAD_AT_SEC) null else value
}

/**
 * Whether a country's load figure may be shown RIGHT NOW (Round LC OI-5).
 *
 * A figure is shown for at most [MAX_AGE_MS] after the phone received it, and
 * never from a snapshot restored from storage (the Data Layer keeps the last
 * item across launches; [PhoneSnapshot.arrivedAtElapsedMs] is null for it).
 *
 * Age is the larger of two estimates, so a clock problem can only make a figure
 * look OLDER:
 *  1. skew-free: (updatedAt - load_at), both on the phone's clock, plus the time
 *     since the snapshot arrived on this watch's monotonic clock
 *     (SystemClock.elapsedRealtime, which keeps counting in deep sleep). It
 *     misses only transit time.
 *  2. wall clock: this watch's clock minus load_at. It includes transit time,
 *     but a watch clock that is BEHIND the phone understates it.
 * The max is fooled only when both fail at once, and then only by the smaller
 * of the transit delay and the clock skew. A load_at in this watch's future is
 * unknown, never "fresh". Every input that does not make sense is unknown.
 */
object LoadFreshness {
    const val MAX_AGE_MS = 60_000L

    /**
     * Age in ms, or null (unknown). Every untrusted input is range-checked by
     * COMPARISON before it takes part in any arithmetic, so no step can wrap:
     *  - load_at must lie in [MIN_LOAD_AT_SEC, MAX_LOAD_AT_SEC] and must not be
     *    after this watch's now, compared in whole SECONDS (0 s allowance for
     *    the future), so load_at * 1000 <= nowWallMs <= Long.MAX_VALUE;
     *  - the multiplication is also Math.multiplyExact, as a second guard;
     *  - after that every difference is between two non-negative values, and
     *    the one sum is only formed when both terms are below [MAX_AGE_MS]
     *    (anything larger already means "expired").
     * Callers treat any result >= [MAX_AGE_MS] as unknown.
     */
    fun ageMs(country: WatchCountry, snapshot: PhoneSnapshot, nowElapsedMs: Long, nowWallMs: Long): Long? {
        if (country.loadPct == null) return null
        val loadAtSec = country.loadAtSec ?: return null
        val arrivedAt = snapshot.arrivedAtElapsedMs ?: return null
        val updatedAt = snapshot.updatedAt
        if (loadAtSec < MIN_LOAD_AT_SEC || loadAtSec > MAX_LOAD_AT_SEC) return null
        if (nowWallMs <= 0L || updatedAt <= 0L) return null
        if (loadAtSec > nowWallMs / 1000L) return null // in the watch's future
        if (arrivedAt < 0L || arrivedAt > nowElapsedMs) return null
        val loadAtMs = try {
            Math.multiplyExact(loadAtSec, 1000L)
        } catch (_: ArithmeticException) {
            return null
        }
        if (loadAtMs > updatedAt) return null // published before it was received
        val publishAge = updatedAt - loadAtMs // both > 0: cannot wrap
        val sinceArrival = nowElapsedMs - arrivedAt // 0..nowElapsedMs
        val wallAge = nowWallMs - loadAtMs // 0..nowWallMs
        if (publishAge >= MAX_AGE_MS || sinceArrival >= MAX_AGE_MS || wallAge >= MAX_AGE_MS) {
            return MAX_AGE_MS
        }
        return maxOf(publishAge + sinceArrival, wallAge)
    }

    fun visibleLoadPct(country: WatchCountry, snapshot: PhoneSnapshot, nowElapsedMs: Long, nowWallMs: Long): Int? {
        val age = ageMs(country, snapshot, nowElapsedMs, nowWallMs) ?: return null
        return if (age < MAX_AGE_MS) country.loadPct else null
    }

    /** Ms until the shown figure expires, or null if nothing is shown. */
    fun msUntilExpiry(country: WatchCountry, snapshot: PhoneSnapshot, nowElapsedMs: Long, nowWallMs: Long): Long? {
        val age = ageMs(country, snapshot, nowElapsedMs, nowWallMs) ?: return null
        return (MAX_AGE_MS - age).takeIf { it > 0L }
    }
}

/**
 * The whole of what the watch knows. Anything not in here, the watch does not
 * get to know.
 */
data class PhoneSnapshot(
    val status: TunnelStatus,
    val detail: String,
    val selectedSlug: String,
    val countries: List<WatchCountry>,
    /**
     * Whether starting a tunnel or changing country will actually work right
     * now. On Android those two paths are owned by the phone app's Dart layer
     * (it builds the tunnel config), so they are unavailable while the phone
     * app is closed -- whereas stopping a tunnel and reading status are served
     * by the always-resident native service and stay available.
     */
    val canConnect: Boolean,
    val updatedAt: Long,
    /**
     * SystemClock.elapsedRealtime() when this snapshot arrived live from the
     * phone, or null for one restored from the Data Layer at launch. Set by
     * [PhoneLink], never parsed from the wire. See [LoadFreshness].
     */
    val arrivedAtElapsedMs: Long? = null,
    /** Data Layer source node, set locally for a live message, never read from JSON. */
    val sourceNodeId: String? = null,
) {
    val selectedCountry: WatchCountry?
        get() = countries.firstOrNull { it.slug == selectedSlug }

    companion object {
        val EMPTY = PhoneSnapshot(
            status = TunnelStatus.UNKNOWN,
            detail = "",
            selectedSlug = "",
            countries = emptyList(),
            canConnect = false,
            updatedAt = 0L,
        )

        /**
         * Tolerant by design: a snapshot from a newer phone build with extra
         * fields must still render, and a malformed one must degrade to
         * [EMPTY] rather than crash the watch face app.
         */
        fun parse(payload: ByteArray?): PhoneSnapshot? {
            if (payload == null || payload.isEmpty()) return null
            return parse(String(payload, Charsets.UTF_8))
        }

        fun parse(payload: String?): PhoneSnapshot? {
            if (payload.isNullOrBlank()) return null
            return try {
                val json = JSONObject(payload)
                val countriesJson = json.optJSONArray("countries")
                val countries = buildList {
                    for (index in 0 until (countriesJson?.length() ?: 0)) {
                        val item = countriesJson?.optJSONObject(index) ?: continue
                        val slug = item.optString("slug").trim()
                        if (slug.isEmpty()) continue
                        add(
                            WatchCountry(
                                slug = slug,
                                name = item.optString("name").trim().ifEmpty { slug },
                                flag = item.optString("flag").trim(),
                                loadPct = parseLoadPct(item.opt(FIELD_LOAD_PCT)),
                                loadAtSec = parseLoadAtSec(item.opt(FIELD_LOAD_AT)),
                            )
                        )
                    }
                }
                PhoneSnapshot(
                    status = TunnelStatus.fromWire(json.optString("status")),
                    detail = json.optString("detail").trim(),
                    selectedSlug = json.optString("selectedSlug").trim(),
                    countries = countries,
                    canConnect = json.optBoolean("canConnect", true),
                    updatedAt = json.optLong("updatedAt"),
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}

/** Whether the watch can currently reach the phone app at all. */
enum class PhoneLinkState {
    /** Looking for a paired node; nothing rendered yet. */
    CONNECTING,

    /** A snapshot has arrived. */
    LINKED,

    /** No paired node, or the phone app is not answering. */
    UNREACHABLE,
}
