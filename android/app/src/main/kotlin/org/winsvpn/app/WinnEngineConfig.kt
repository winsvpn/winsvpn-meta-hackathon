package org.winsvpn.app

/**
 * Builds the `configJson` argument of `WinnTunnelCreate(configJson, udpFd)`
 * (WINN_PROTOCOL_PLATFORM_PLAN.md section 2) from the app's existing INI-style
 * tunnel config.
 *
 * THE SCHEMA IS THE ENGINE'S, NOT THIS FILE'S. Every key below is a field of
 * `datapath.Config` in `winn_protocol_experimental/datapath/config.go`, which
 * decodes with `DisallowUnknownFields`. That makes a spelling mistake or a
 * helpfully-added extra key a hard create-time error, not a silent default --
 * so this file emits those keys and nothing else. The previous version of this
 * file emitted `winn_framing_version`, `role`, `endpoint`, `mtu`,
 * `tunnel_address`, `dns`, `udp_socket` and `params`; not one of them is a
 * field of `datapath.Config`, so the very first one would have failed the
 * decode even if the framing had been right.
 *
 * Winn Protocol is selected by an additive `[winn]` section alongside the
 * `[Interface]`/`[Peer]` sections AmneziaWG already uses:
 *
 *     [winn]
 *     enabled = true
 *     endpoint = 203.0.113.7:51820
 *     h1 = 1234567890            ; optional AmneziaWG header types
 *     h2 = ...
 *
 * THE ENDPOINT MUST BE AN IP LITERAL. The engine refuses a hostname
 * (`validateIPLiteralEndpoint`) for a reason worth restating: resolving one
 * inside the engine would leak a DNS lookup outside the tunnel before the
 * protected resolver exists. This class enforces the same rule at config time
 * so the failure names the field instead of arriving as an opaque engine error.
 *
 * KEY MATERIAL. `[winn]` values may carry secrets. Nothing in this file logs a
 * value, and callers must never log the string returned by [toConfigJson].
 * Use [describeForLog] instead, which emits key names only.
 *
 * No `org.json` here on purpose: the Android unit-test `android.jar` stubs
 * `org.json` and every call throws "not mocked", which would make this
 * untestable on the JVM.
 */
internal class WinnEngineConfig private constructor(
    val gatewayEndpoint: String,
    val maxDatagram: Int,
    val sessionId: String,
    val awgHeaderTypes: AwgHeaderTypes?,
    /**
     * The datapath carrier, and the THIRD anti-downgrade gate.
     *
     * This used to be the constant [CARRIER_DIRECT_AWG], emitted
     * unconditionally by [toConfigJson]. That is a hole, and a subtle one: both
     * existing anti-downgrade gates are in Dart -- the dispatch seam and
     * `winnSectionForTunnelConfig` -- and this line sits BELOW both of them. A
     * `winn/3` config that they correctly approved still became whatever this
     * constant said, beneath every gate that existed.
     *
     * It is not an active downgrade today, because direct-awg is genuinely the
     * only carrier `datapath.Open` can build. It is a LATENT one: the moment a
     * carrier becomes reachable, a hard-coded constant here would keep forcing
     * classical AmneziaWG while three layers above believed otherwise, and
     * nothing would report it.
     *
     * So the value is resolved rather than assumed, defaults to direct-awg
     * (today's behaviour, unchanged), and [from] refuses any value the engine
     * cannot build. When carriers land, the `[winn]` section declares one and
     * this stays honest by construction.
     */
    val carrier: String,
) {

    /**
     * Whether this session needs a carrier profile written and named on the
     * engine's argv.
     *
     * Derived from [carrier] rather than stored, so it cannot drift from the
     * value [toConfigJson] emits. The engine enforces the same equivalence from
     * the other side: `openWithProfile` refuses a profile beside a direct-awg
     * configuration, and `datapath.Open` refuses a carrier configuration with
     * no profile (`ErrCarrierNoDialer`). Neither may silently become the other.
     */
    val requiresCarrierProfile: Boolean get() = carrier != CARRIER_DIRECT_AWG

    /**
     * The AmneziaWG h1..h4 header type values, when the deployment sets them,
     * together with the s1..s4 prefix padding sizes.
     *
     * s1..s4 are not decoration. AmneziaWG PREPENDS s1 random bytes to a
     * handshake initiation, s2 to a handshake response, s3 to a cookie reply and
     * s4 to a transport datagram, so the header word the engine matches on is at
     * that offset rather than at offset 0. `datapath/classify.go` states the
     * consequence: omitting s1/s2/s3 silently kills the handshake counters, and
     * omitting a nonzero s4 silently kills the TRANSPORT counters -- which are
     * the ones `transport_observed_both_ways` is built from, and that is the
     * only field a route-promotion gate may use.
     *
     * This app emits `S1 = 16`, `S2 = 80`, `S3 = 16`, `S4 = 0` into the
     * AmneziaWG `[Interface]` section, so the AWG engine really does apply that
     * padding. Before these fields existed the `[winn]` section carried only
     * h1..h4, so the engine classified against offset 0 and the handshake
     * classes could never match on a perfectly healthy tunnel.
     *
     * They are optional and default to zero, which is the unpadded WireGuard
     * layout, so a configuration that omits them behaves exactly as before.
     */
     internal data class AwgHeaderSpec(
        val start: Long,
        val end: Long,
    ) {
        fun isRange(): Boolean = end > start
        fun spec(): String = if (isRange()) "$start-$end" else start.toString()
        fun overlaps(other: AwgHeaderSpec): Boolean =
            start <= other.end && other.start <= end
        fun contains(word: Long): Boolean = word in start..end

        companion object {
            const val MIN = 5L
            const val MAX = 0xFFFFFFFFL
            const val MAX_RANGE_WIDTH = 4294967295L
            const val SPEC_MAX_LENGTH = 21

            fun parse(raw: String?): AwgHeaderSpec? {
                if (raw == null) return null
                val text = raw.trim()
                if (text.isEmpty() ||
                    text.length > SPEC_MAX_LENGTH ||
                    text.contains('\r') ||
                    text.contains('\n') ||
                    text.contains('\u0000')
                ) return null
                if (text.any { it.isWhitespace() }) return null
                val sep = text.indexOf('-')
                if (sep < 0) {
                    if (text.length > 10 || text.any { it !in '0'..'9' }) return null
                    val v = text.toLongOrNull() ?: return null
                    if (v < MIN || v > MAX) return null
                    return AwgHeaderSpec(v, v)
                }
                val startText = text.substring(0, sep)
                val endText = text.substring(sep + 1)
                if (startText.isEmpty() || endText.isEmpty()) return null
                if (endText.contains('-')) return null
                if (startText.length > 10 || endText.length > 10) return null
                if (startText.any { it !in '0'..'9' } || endText.any { it !in '0'..'9' }) return null
                val s = startText.toLongOrNull() ?: return null
                val e = endText.toLongOrNull() ?: return null
                if (s < MIN || e > MAX || e < s) return null
                if (e - s + 1 > MAX_RANGE_WIDTH) return null
                return AwgHeaderSpec(s, e)
            }
        }
    }

    internal data class AwgHeaderTypes(
        val h1: AwgHeaderSpec,
        val h2: AwgHeaderSpec,
        val h3: AwgHeaderSpec,
        val h4: AwgHeaderSpec,
        val s1: Int = 0,
        val s2: Int = 0,
        val s3: Int = 0,
        val s4: Int = 0,
    ) {
        fun distinct(): Boolean {
            val specs = listOf(h1, h2, h3, h4)
            for (a in specs.indices) {
                for (b in a + 1 until specs.size) {
                    if (specs[a].overlaps(specs[b])) return false
                }
            }
            return true
        }
    }

    /**
     * The Create payload. Never log this -- see the class KDoc.
     *
     * `payload` is fixed at [PAYLOAD_AWG_DATAGRAM]. It is the single most
     * consequential value in this document: it declares that Inbound and
     * Outbound frames carry AmneziaWG OUTER DATAGRAMS. The host must actually
     * supply those (see [WinnAwgDatagramSeam]); declaring it while pumping raw
     * tun packets would put cleartext on the wire, which is why the engine
     * refuses the honest alternative, `payload:"ip-packet"`, outright.
     *
     * `allow_own_socket` is fixed false. On Android the engine must never open
     * a socket of its own: an unmarked socket's datagrams route back into this
     * service's tun and the tunnel dead-loops.
     */
    fun toConfigJson(): String {
        val sb = StringBuilder(256)
        sb.append('{')
        appendPair(sb, "contract", CONTRACT_VERSION)
        sb.append(',')
        appendPair(sb, "payload", PAYLOAD_AWG_DATAGRAM)
        sb.append(',')
        // THIRD ANTI-DOWNGRADE GATE. See the `carrier` KDoc: this value sits
        // BELOW both Dart gates, so a config they correctly approved as winn/3
        // still becomes whatever is written here. Emit what was resolved, and
        // let `from()` be the thing that refuses an unsupported value.
        appendPair(sb, "carrier", carrier)
        sb.append(',')
        appendPair(sb, "gateway_endpoint", gatewayEndpoint)
        sb.append(',')
        appendPair(sb, "max_datagram", maxDatagram.toString(), quoted = false)
        if (sessionId.isNotEmpty()) {
            sb.append(',')
            appendPair(sb, "session_id", sessionId)
        }
        sb.append(',')
        appendPair(sb, "allow_own_socket", "false", quoted = false)
        awgHeaderTypes?.let { types ->
            sb.append(",\"awg_header_types\":{")
            // Ranges are JSON strings, scalars are JSON numbers. Mirrors the hub
            // and the Go datapath: a scalar travels as a number, a range as a
            // quoted "start-end" string, so a legacy profile round-trips
            // byte-identically and a range survives.
            fun appendHeader(sb: StringBuilder, key: String, spec: AwgHeaderSpec) {
                if (spec.isRange()) {
                    appendPair(sb, key, spec.spec(), quoted = true)
                } else {
                    appendPair(sb, key, spec.start.toString(), quoted = false)
                }
            }
            appendHeader(sb, "h1", types.h1)
            sb.append(',')
            appendHeader(sb, "h2", types.h2)
            sb.append(',')
            appendHeader(sb, "h3", types.h3)
            sb.append(',')
            appendHeader(sb, "h4", types.h4)
            // s1..s4 are always emitted, including zeros. The engine's decoder
            // treats an absent field as 0, so emitting them costs nothing and
            // makes the offsets the engine will use explicit in the document
            // rather than implied by their absence.
            sb.append(',')
            appendPair(sb, "s1", types.s1.toString(), quoted = false)
            sb.append(',')
            appendPair(sb, "s2", types.s2.toString(), quoted = false)
            sb.append(',')
            appendPair(sb, "s3", types.s3.toString(), quoted = false)
            sb.append(',')
            appendPair(sb, "s4", types.s4.toString(), quoted = false)
            sb.append('}')
        }
        sb.append('}')
        return sb.toString()
    }

    /** Key names only. Safe to log; [toConfigJson] is not. */
    fun describeForLog(): String =
        "winn config: contract=$CONTRACT_VERSION payload=$PAYLOAD_AWG_DATAGRAM " +
            "carrier=$carrier max_datagram=$maxDatagram " +
            "awg_header_types=${awgHeaderTypes != null}"

    private fun appendPair(sb: StringBuilder, key: String, value: String, quoted: Boolean = true) {
        sb.append(jsonString(key)).append(':')
        if (quoted) sb.append(jsonString(value)) else sb.append(value)
    }

    companion object {
        const val SECTION = "winn"

        /** `datapath.ContractVersion`. */
        const val CONTRACT_VERSION = "winn-datapath/1"

        /** `datapath.PayloadAWGDatagram`. The only implemented payload mode. */
        const val PAYLOAD_AWG_DATAGRAM = "awg-datagram"

        /** `datapath.CarrierDirectAWG`. The only carrier `Open` can build. */
        const val CARRIER_DIRECT_AWG = "direct-awg"

        /**
         * `datapath.CarrierHTTP3`. Reachable through `OpenWithCarrier`, which
         * `cmd/winn-datapath` calls when it is given `-carrier-profile PATH`.
         *
         * It is buildable on Android specifically because its dialer rides a
         * caller-supplied, already-protected UNCONNECTED UDP socket -- which is
         * exactly the socket this host already opens, protects and hands over
         * by SCM_RIGHTS. No new socket work was needed to reach it.
         */
        const val CARRIER_HTTP3 = WinnCarrierProfile.CARRIER_HTTP3

        /**
         * `datapath.CarrierHTTP2`. NOT in [SUPPORTED_CARRIERS], and the reason
         * is a host capability rather than a protocol gap: its dialer takes a
         * CONNECTED, protected TCP socket (`carrier.SocketKindStream`), and
         * this host opens an unconnected UDP one. Naming it here would produce
         * a dialer `openWithCarrier` then refuses for a socket-kind mismatch,
         * so it stays refused until the host opens the socket it needs.
         */
        const val CARRIER_HTTP2 = WinnCarrierProfile.CARRIER_HTTP2

        /** `datapath.MaxDatagramCeiling` / `MinDatagram`. */
        const val MAX_DATAGRAM_CEILING = 1500
        const val MIN_DATAGRAM = 32

        /**
         * Section keys the host consumes itself and does not forward.
         *
         * [WinnCarrierProfile.CARRIER_KEYS] is folded in because those keys
         * describe the CARRIER PROFILE, a separate document that travels as a
         * file path on argv. Not one of them is a field of `datapath.Config`,
         * whose decoder rejects unknown fields, so forwarding any of them would
         * be a hard create-time error. They are read by
         * [WinnCarrierProfile.from] instead.
         */
        private val RESERVED_KEYS =
            setOf("enabled", "endpoint", "session_id", "max_datagram", "carrier") +
                WinnCarrierProfile.CARRIER_KEYS +
                // The v3 selector and its sizing keys. Folded in rather than
                // listed, so adding one to WinnV3SessionPlan cannot leave this
                // set behind. They are consumed by that class and never
                // forwarded: not one of them is a field of `datapath.Config`,
                // whose decoder rejects unknown fields.
                WinnV3SessionPlan.V3_KEYS

        /**
         * Carriers this host can actually start.
         *
         * WIDENED, and the widening is the point of this stage. `datapath.Open`
         * still builds only direct-awg, so if that were the whole story this
         * set would still be a single element. What changed is that
         * `cmd/winn-datapath` now accepts `-carrier-profile PATH`, loads a
         * `carrierhost.Profile` from it and calls `OpenWithCarrier` -- so
         * [CARRIER_HTTP3] is reachable from the process Android actually
         * spawns, and claiming it here is no longer a claim the engine cannot
         * honour.
         *
         * [CARRIER_HTTP2] is deliberately still absent. See its KDoc: the
         * engine implements it, but its dialer needs a connected TCP socket
         * this host does not open, so accepting it would move the failure from
         * a named refusal here to a socket-kind mismatch inside the engine.
         *
         * This set stays the narrow one. A carrier is added to it when the HOST
         * can supply what the carrier's dialer takes, not when the engine gains
         * the carrier.
         */
        private val SUPPORTED_CARRIERS = setOf(CARRIER_DIRECT_AWG, CARRIER_HTTP3)

        /**
         * The `[winn]` keys a non-direct-awg carrier cannot start without.
         *
         * The optional members of [WinnCarrierProfile.CARRIER_KEYS] --
         * `sequence_epoch`, `max_inner_datagram`, `privacy_profile` -- are
         * absent because `carrierhost` supplies a defined default for each.
         * Everything here has no safe default: a missing `suite` or a missing
         * `manifest_digest` cannot be guessed without weakening the session or
         * silently claiming a different deployment.
         *
         * GENERATED, not hand-typed. This was a literal list identical to
         * [WinnCarrierProfileKeys.SERVED_REQUIRED] -- one more copy of exactly
         * the thing the generation scheme exists to remove. Drift here was
         * fail-closed either way (a key dropped from this list becomes a late
         * refusal inside the engine instead of an early named one), which is
         * why it was low priority rather than a defect; it is still a copy, and
         * `RequiredServedProfileKeys` in servedkeys.go is the authority.
         *
         * The only consumer sorts before use, so [Set] versus [List] and any
         * iteration-order difference cannot reach behaviour.
         */
        private val REQUIRED_CARRIER_KEYS = WinnCarrierProfileKeys.SERVED_REQUIRED

        private val HEADER_TYPE_KEYS = listOf("h1", "h2", "h3", "h4")

        /**
         * Prefix padding sizes. Optional and independent of h1..h4: a
         * deployment may set header types without padding, and each size
         * defaults to 0 (the unpadded WireGuard layout) when absent.
         *
         * Unlike h1..h4 these are NOT all-or-none. The shipping profile sets
         * S4 = 0 deliberately while S1..S3 are nonzero, so requiring all four
         * would refuse the app's own configuration.
         */
        private val PADDING_KEYS = listOf("s1", "s2", "s3", "s4")

        fun isEnabled(section: Map<String, String>): Boolean {
            val v = section["enabled"]?.trim()?.lowercase() ?: return false
            return v == "true" || v == "1" || v == "yes" || v == "y"
        }

        /**
         * @param mtu the tunnel MTU, used only to size the datagram bound.
         * @throws IllegalArgumentException with a message that names the
         *   offending field but never its value.
         */
        fun from(
            section: Map<String, String>,
            mtu: Int,
            @Suppress("UNUSED_PARAMETER") tunnelAddress: String = "",
            @Suppress("UNUSED_PARAMETER") dnsServers: List<String> = emptyList(),
        ): WinnEngineConfig {
            require(isEnabled(section)) { "Winn section is not enabled" }
            require(mtu in 576..9000) { "Winn MTU is out of range" }

            // FOURTH ANTI-DOWNGRADE GATE, and the one that guards v3.
            //
            // This class builds the v1 create document and emits
            // PAYLOAD_AWG_DATAGRAM unconditionally. A section that asked for
            // protocol 3 reaching here means the caller took the v1 branch for a
            // v3 configuration, and the result would be a working AmneziaWG
            // session the user believes is Winn Protocol v3 — a downgrade with
            // no symptom, which is the worst kind. It is refused here as well as
            // in the caller because this is the layer that can see the
            // contradiction directly: the section says 3, this document says
            // awg-datagram, and both cannot be true.
            require(!WinnV3SessionPlan.isRequested(section)) {
                "Winn section asks for ${WinnV3SessionPlan.KEY_PROTOCOL}=" +
                    "${WinnV3SessionPlan.PROTOCOL_V3}, but this is the v1 configuration builder " +
                    "and it emits payload '$PAYLOAD_AWG_DATAGRAM'. Starting a v1 session here " +
                    "would be a silent downgrade of the user's protocol; refusing instead."
            }
            WinnV3SessionPlan.refuseUnknownProtocol(section)?.let {
                throw IllegalArgumentException(it)
            }

            val endpoint = section["endpoint"].orEmpty().trim()
            require(isIpLiteralEndpoint(endpoint)) {
                "Winn endpoint must be an IP literal with a port, not a hostname: the engine " +
                    "refuses to resolve one because that lookup would leave outside the tunnel"
            }

            // The engine bounds a single datagram; the tunnel MTU plus the
            // AmneziaWG overhead is what it has to hold. Clamped to the
            // engine's own ceiling so an out-of-range value is a named local
            // error rather than an opaque create-time refusal.
            val rawMaxDatagram = section["max_datagram"]?.trim().orEmpty()
            val requested = if (rawMaxDatagram.isEmpty()) {
                MAX_DATAGRAM_CEILING
            } else {
                rawMaxDatagram.toIntOrNull() ?: -1
            }
            require(requested in MIN_DATAGRAM..MAX_DATAGRAM_CEILING) {
                "Winn max_datagram must be within [$MIN_DATAGRAM, $MAX_DATAGRAM_CEILING]"
            }

            val sessionId = section["session_id"].orEmpty().trim()
            require(sessionId.length <= 128) { "Winn session_id exceeds 128 bytes" }

            val headerTypes = parseHeaderTypes(section)

            // Anything else in [winn] is refused rather than forwarded. The
            // engine's decoder rejects unknown fields, so quietly dropping a
            // key the operator set would be worse than saying so: they would
            // believe it took effect.
            for (rawKey in section.keys) {
                val key = rawKey.trim().lowercase()
                if (key.isEmpty() || key in RESERVED_KEYS ||
                    key in HEADER_TYPE_KEYS || key in PADDING_KEYS
                ) continue
                throw IllegalArgumentException(
                    "Winn section carries '$key', which is not a field of the engine's " +
                        "configuration; the engine rejects unknown fields"
                )
            }

            val carrier = section["carrier"]?.trim()?.lowercase()
                ?.takeIf { it.isNotEmpty() } ?: CARRIER_DIRECT_AWG
            require(carrier in SUPPORTED_CARRIERS) {
                if (carrier == CARRIER_HTTP2) {
                    "Winn carrier '$CARRIER_HTTP2' needs a connected, protected TCP socket, and " +
                        "this host opens an unconnected UDP one; refusing rather than silently " +
                        "starting a different carrier"
                } else {
                    "Winn carrier '$carrier' is not one this engine can build; " +
                        "refusing rather than silently starting a different one"
                }
            }
            // A carrier other than direct-awg requires a carrier profile, and
            // the engine refuses the pairing in BOTH directions -- a profile
            // beside a direct-awg config, and a carrier config with no profile.
            // Checking here means a section that named a carrier but carried no
            // carrier fields fails where the field can be named, rather than as
            // an engine startup error after a socket has been protected and
            // handed over.
            if (carrier != CARRIER_DIRECT_AWG) {
                val missing = REQUIRED_CARRIER_KEYS
                    .filter { section[it].isNullOrBlank() }
                    .sorted()
                require(missing.isEmpty()) {
                    "Winn carrier '$carrier' needs the carrier profile fields " +
                        "${missing.joinToString(", ")}, which this configuration does not carry; " +
                        "refusing rather than starting an unauthenticated carrier for a session " +
                        "that was configured for an authenticated one"
                }
            }

            return WinnEngineConfig(
                gatewayEndpoint = endpoint,
                maxDatagram = requested,
                sessionId = sessionId,
                awgHeaderTypes = headerTypes,
                carrier = carrier,
            )
        }

        private fun parseHeaderTypes(section: Map<String, String>): AwgHeaderTypes? {
            // 0xFFFFFFFF ceiling parity - must equal VpnConfigValidator.awgHeaderMax
            val present = HEADER_TYPE_KEYS.filter { !section[it].isNullOrBlank() }
            val padding = PADDING_KEYS.map { key ->
                val raw = section[key]?.trim()
                if (raw.isNullOrEmpty()) return@map 0
                val parsed = raw.toIntOrNull()
                require(parsed != null && parsed in 0..0xFFFF) {
                    "Winn padding size '$key' is not a 16-bit unsigned value"
                }
                parsed
            }
            if (present.isEmpty()) {
                // Padding without header types would be forwarded to an engine
                // that has no header word to find at those offsets, so refuse
                // rather than silently drop it.
                require(padding.all { it == 0 }) {
                    "Winn padding sizes s1..s4 require the header types h1..h4; " +
                        "padding shifts where the header word is read from, so it " +
                        "is meaningless without one"
                }
                return null
            }
            require(present.size == HEADER_TYPE_KEYS.size) {
                "Winn AmneziaWG header types must be given as all of h1..h4 or none"
            }
            val specs = HEADER_TYPE_KEYS.map { key ->
                // 0xFFFFFFFF ceiling parity
                val raw = section[key]!!.trim()
                val spec = AwgHeaderSpec.parse(raw)
                require(spec != null) {
                    "Winn header type '$key' is not a 32-bit unsigned value or range"
                }
                spec
            }
            val types = AwgHeaderTypes(
                specs[0], specs[1], specs[2], specs[3],
                padding[0], padding[1], padding[2], padding[3],
            )
            require(types.distinct()) {
                "Winn header types h1..h4 must be pairwise distinct; equal values make " +
                    "datagram classification ambiguous"
            }
            return types
        }

        /**
         * Mirrors `datapath.validateIPLiteralEndpoint`: an IP literal and a
         * nonzero port, never a hostname. IPv6 is bracketed, as in
         * `[2001:db8::1]:51820`.
         */
        fun isIpLiteralEndpoint(endpoint: String): Boolean {
            if (endpoint.isEmpty()) return false
            val host: String
            val portText: String
            if (endpoint.startsWith("[")) {
                val end = endpoint.indexOf(']')
                if (end < 0 || end + 1 >= endpoint.length || endpoint[end + 1] != ':') return false
                host = endpoint.substring(1, end)
                portText = endpoint.substring(end + 2)
                if (!isIpv6Literal(host)) return false
            } else {
                val colon = endpoint.lastIndexOf(':')
                if (colon <= 0) return false
                host = endpoint.substring(0, colon)
                portText = endpoint.substring(colon + 1)
                if (!isIpv4Literal(host)) return false
            }
            val port = portText.toIntOrNull() ?: return false
            return port in 1..65535
        }

        private fun isIpv4Literal(host: String): Boolean {
            val parts = host.split('.')
            if (parts.size != 4) return false
            var allZero = true
            for (part in parts) {
                if (part.isEmpty() || part.length > 3) return false
                if (!part.all { it in '0'..'9' }) return false
                val value = part.toIntOrNull() ?: return false
                if (value !in 0..255) return false
                if (value != 0) allZero = false
            }
            // Unspecified and multicast are not routable unicast literals, the
            // same rule the engine applies.
            if (allZero) return false
            val first = parts[0].toInt()
            return first !in 224..239
        }

        private fun isIpv6Literal(host: String): Boolean {
            if (host.isEmpty() || host.length > 39) return false
            if (!host.all { it in "0123456789abcdefABCDEF:" }) return false
            val compressed = host.indexOf("::")
            if (compressed >= 0 && host.indexOf("::", compressed + 1) >= 0) return false
            val groups: List<String> = if (compressed >= 0) {
                val head = host.substring(0, compressed)
                val tail = host.substring(compressed + 2)
                val parts = (if (head.isEmpty()) emptyList() else head.split(':')) +
                    (if (tail.isEmpty()) emptyList() else tail.split(':'))
                if (parts.size > 7) return false
                parts
            } else {
                val parts = host.split(':')
                if (parts.size != 8) return false
                parts
            }
            if (groups.any { it.isEmpty() || it.length > 4 }) return false
            // Unspecified (::) is not a destination; ff00::/8 is multicast.
            if (groups.all { it.toInt(16) == 0 }) return false
            val first = if (compressed == 0) 0 else groups.first().toInt(16)
            return first and 0xff00 != 0xff00
        }

        fun jsonString(value: String): String {
            val sb = StringBuilder(value.length + 2)
            sb.append('"')
            for (ch in value) {
                when (ch) {
                    '"' -> sb.append("\\\"")
                    '\\' -> sb.append("\\\\")
                    '\n' -> sb.append("\\n")
                    '\r' -> sb.append("\\r")
                    '\t' -> sb.append("\\t")
                    '\b' -> sb.append("\\b")
                    '\u000C' -> sb.append("\\f")
                    else ->
                        if (ch < ' ' || ch == '\u007F') {
                            sb.append("\\u").append("%04x".format(ch.code))
                        } else {
                            sb.append(ch)
                        }
                }
            }
            sb.append('"')
            return sb.toString()
        }
    }
}
