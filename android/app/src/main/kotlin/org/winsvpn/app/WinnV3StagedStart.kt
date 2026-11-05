package org.winsvpn.app

/**
 * The promotion gate and the staged start that drives it.
 *
 * `WINN3_TUN_LAYER_20260808.md` §4.1 defines PROVEN as a property of the tun
 * layer, and is emphatic that it must not be defined in terms of the socket:
 *
 * > 1. `Gate.State() == StateCarrying` — the session driver says DATA may flow;
 * >    and
 * > 2. `Stats().RxPackets > 0` — an inner packet **validated and reached the
 * >    host device**, which is the first moment anything has proven the whole
 * >    chain (carrier, crypto, framing, address assignment, host device).
 * >
 * > `RxPackets` is the right counter and `RxOffered` is not: the first counts
 * > deliveries, the second counts arrivals.
 *
 * That last sentence is why [WinnV3EngineStatus.parse] refuses a status
 * document that reports `rx_offered` without `rx_packets` instead of falling
 * back to it. Falling back would promote on a packet that ARRIVED — one the
 * validator may have rejected for a martian source, the wrong address family,
 * or an address this tunnel was never assigned — and the whole point of the
 * gate is that the promotion waits for a DELIVERY.
 */

/** `winn3/tun.State`, mirrored. The names are the Go `String()` values. */
internal enum class WinnV3GateState(val wire: String) {
    DOWN("down"),
    EPOCH0("epoch0"),
    HANDSHAKING("handshaking"),
    REKEYING("rekeying"),
    CARRYING("carrying"),
    CLOSED("closed"),
    ;

    /** `winn3/tun.State.MayCarry()` — exactly one state carries. */
    fun mayCarry(): Boolean = this == CARRYING

    companion object {
        /**
         * Parses a wire name, or null.
         *
         * Null rather than a default, and the caller treats null as "not
         * carrying". A defaulting parse is the shape that fails OPEN when the
         * Go side adds a state, and `TestOnlyEstablishedCarries` in
         * `winn3/driver` walks all 256 values of `session.State` precisely to
         * stop that happening on the other side of this seam.
         */
        fun fromWire(text: String?): WinnV3GateState? {
            if (text == null) return null
            // Exact match against the tun vocabulary. trim()+lowercase() used
            // to accept " CARRYING " and "carrying\n" as carrying, which the
            // engine never writes and which C++ kCarryingGate rejects. A
            // padded or cased name is not a state; the caller treats null as
            // not carrying.
            return entries.firstOrNull { it.wire == text }
        }
    }
}

/**
 * `winn3/driver.Lifecycle*`, mirrored: the supervised frame mode's recovery
 * state, published as `lifecycle` in the status document (Round A2).
 *
 * `connected` means the round the document read has its OWN delivery proof.
 * `recovering` means a round ended and no successor has proven delivery yet;
 * the engine publishes posture `hold` and this host keeps its tunnel and its
 * installed capture exactly as they are. `blocked` means the supervisor has
 * finished (its `lifecycle_cause` is an observation, never a claim of
 * censorship or revocation); it authorises no fallback to another protocol
 * and no release of capture. `stopped` means the tunnel was closed.
 */
internal enum class WinnV3Lifecycle(val wire: String) {
    CONNECTING("connecting"),
    CONNECTED("connected"),
    RECOVERING("recovering"),
    BLOCKED("blocked"),
    STOPPED("stopped"),
    ;

    companion object {
        /**
         * Parses a wire name. Null only when the key is ABSENT, which is an
         * engine that predates the field (or the desktop mode); the caller
         * then keeps the rule it had before the field existed. A value this
         * host does not know is BLOCKED, because the driver's vocabulary is
         * closed and says a host meeting an unknown value must treat it so:
         * that keeps capture and claims nothing.
         */
        fun fromWire(text: String?): WinnV3Lifecycle? {
            if (text == null) return null
            return entries.firstOrNull { it.wire == text } ?: BLOCKED
        }
    }
}

/** The refusal a staged start raises. Never a widening; see §4.3. */
internal class WinnV3StartRefusal(
    message: String,
    val verdict: WinnV3NativeVerdict = WinnV3NativeVerdict.TERMINAL_SECURITY,
) : IllegalStateException(message)

/**
 * The native v3 start verdict. These four wire names are the entire
 * vocabulary a later cover path is allowed to read.
 *
 * `connectivity_failed` is not in it. Only typed OS network unreachability
 * (Android/Linux ENETDOWN/ENETUNREACH/EHOSTDOWN/EHOSTUNREACH) may mint
 * `ordinary_connectivity`, including when the observing pump has already
 * stopped. Timeout, silence, class-name pump collapse, engine/runtime death,
 * malformed status, stale identity, and security evidence remain terminal
 * and cannot authorize AWG/Xray.
 */
internal enum class WinnV3NativeVerdict(val wire: String) {
    ORDINARY_CONNECTIVITY("ordinary_connectivity"),
    TERMINAL_SECURITY("terminal_security"),
    UNKNOWN_TERMINAL("unknown_terminal"),
    CONNECTED("connected"),
    ;

    val securityRefusal: Boolean
        get() = this == TERMINAL_SECURITY || this == UNKNOWN_TERMINAL

    fun awgXrayAuthorizationToken(generation: Long): Long =
        if (this == ORDINARY_CONNECTIVITY) generation else -1L
}

/**
 * Android/Linux POSIX classes that may prove ordinary network unreachability.
 *
 * Darwin numbers (ENETUNREACH=51 and friends) are not in this set. Raw
 * exception text is not a member either: only these four errno values, or
 * an explicit [WinnV3OrdinaryNetworkFailureClass] / authenticated flag, may
 * authorize Winn v1 AWG then Xray cover.
 */
internal enum class WinnV3OrdinaryNetworkFailureClass(val posixErrno: Int) {
    NETWORK_DOWN(100),
    NETWORK_UNREACHABLE(101),
    HOST_DOWN(112),
    HOST_UNREACHABLE(113),
    ;

    companion object {
        fun fromPosixErrno(errno: Int): WinnV3OrdinaryNetworkFailureClass? =
            entries.firstOrNull { it.posixErrno == errno }
    }
}

/**
 * Typed ordinary-network evidence. Never derived from exception message text.
 *
 * A throwable whose public `errno` / `getErrno()` is one of the four
 * Android/Linux allowlist values is accepted. Exception class and message are
 * not OS errno evidence. Timeout types and [java.net.ConnectException] are not.
 *
 * Official Android libcore `DatagramChannelImpl.send0` calls `handleSocketError`,
 * which throws [java.net.SocketException] and drops the numeric errno. That
 * shape is unknown_terminal. Production evidence is captured at a protected
 * `android.system.Os` / `ErrnoException` socket boundary.
 */
internal object WinnV3OrdinaryNetworkEvidence {
    fun classify(
        failure: WinnV3OrdinaryNetworkFailureClass? = null,
        posixErrno: Int? = null,
        cause: Throwable? = null,
    ): WinnV3OrdinaryNetworkFailureClass? {
        if (failure != null) return failure
        posixErrno?.let { errno ->
            WinnV3OrdinaryNetworkFailureClass.fromPosixErrno(errno)?.let { return it }
        }
        classifyThrowable(cause)?.let { return it }
        return null
    }

    fun classifyThrowable(error: Throwable?): WinnV3OrdinaryNetworkFailureClass? =
        typedPosixErrno(error)?.let { WinnV3OrdinaryNetworkFailureClass.fromPosixErrno(it) }

    /**
     * The numeric OS errno on [error] or its cause chain, or null.
     *
     * Reads only a public `errno` field or `getErrno()`. Never [Throwable.message],
     * [Class.getName], or [Class.getSimpleName].
     */
    fun typedPosixErrno(error: Throwable?): Int? {
        var current = error
        val seen = HashSet<Throwable>()
        while (current != null && seen.add(current)) {
            val r = posixErrnoOf(current)
            if (r != null) return r
            current = current.cause
        }
        return null
    }

    private fun posixErrnoOf(error: Throwable): Int? {
        val fromField = try {
            intErrno(error.javaClass.getField("errno").get(error))
        } catch (_: NoSuchFieldException) {
            null
        } catch (_: IllegalAccessException) {
            null
        }
        if (fromField != null) return fromField
        return try {
            intErrno(error.javaClass.getMethod("getErrno").invoke(error))
        } catch (_: NoSuchMethodException) {
            null
        } catch (_: IllegalAccessException) {
            null
        } catch (_: java.lang.reflect.InvocationTargetException) {
            null
        }
    }

    private fun intErrno(value: Any?): Int? = value as? Int
}

/**
 * Capture of a typed POSIX errno from one protected UDP route check.
 *
 * Android libcore `DatagramChannelImpl.send0` throws [java.net.SocketException]
 * and loses the number. The production boundary is therefore `Os.socket` /
 * `VpnService.protect` / `Os.connect` / `ErrnoException.errno`, injected here so
 * the close/protect/send policy runs on a plain JVM. Protection failure is not
 * ordinary unreachability: an unprotected probe would hairpin into the VPN.
 * The descriptor is closed on every path, including open and protect failure.
 * Only [send] may mint a numeric errno; open/protect throwables never authorize.
 */
internal object WinnV3ProtectedSocketErrno {
    data class Result(
        val posixErrno: Int? = null,
        val protected: Boolean = false,
        val closed: Boolean = false,
        val protectionFailed: Boolean = false,
        val cause: Throwable? = null,
    )

    fun <T> capture(
        open: () -> T,
        protect: (T) -> Boolean,
        send: (T) -> Unit,
        close: (T) -> Unit,
        typedErrno: (Throwable) -> Int? = { WinnV3OrdinaryNetworkEvidence.typedPosixErrno(it) },
    ): Result {
        var descriptor: T? = null
        var socketProtected = false
        var protectionFailed = false
        var posixErrno: Int? = null
        var cause: Throwable? = null
        var closed = false
        try {
            descriptor = try {
                open()
            } catch (_: Throwable) {
                null
            }
            val live = descriptor
            if (live != null) {
                socketProtected = try {
                    protect(live)
                } catch (_: Exception) {
                    false
                }
                if (!socketProtected) {
                    protectionFailed = true
                } else {
                    try {
                        send(live)
                    } catch (thrown: Throwable) {
                        posixErrno = typedErrno(thrown)
                        cause = thrown
                    }
                }
            }
        } finally {
            val live = descriptor
            if (live != null) {
                try {
                    close(live)
                    closed = true
                } catch (_: Exception) {
                    closed = false
                }
            } else {
                closed = true
            }
        }
        return Result(
            posixErrno = posixErrno,
            protected = socketProtected,
            closed = closed,
            protectionFailed = protectionFailed,
            cause = cause,
        )
    }
}

/** What one staged poll observes about the v3 bridge. */
internal data class WinnV3BridgeSnapshot(
    val running: Boolean,
    val failure: String?,
    val ordinaryNetworkFailure: WinnV3OrdinaryNetworkFailureClass? = null,
    val ordinaryNetworkPosixErrno: Int? = null,
    val positiveOrdinaryUnreachability: Boolean = false,
    val cause: Throwable? = null,
)

/**
 * A verdict bound to one Dart-issued start token. A stale generation cannot
 * publish an AWG/Xray authorization token for a later attempt.
 */
internal data class WinnV3PublishedNativeVerdict(
    val startToken: Long,
    val startGeneration: Long,
    val verdict: WinnV3NativeVerdict,
) {
    val state: String get() = verdict.wire
    val securityRefusal: Boolean get() = verdict.securityRefusal
    val awgXrayAuthorizationToken: Long get() = verdict.awgXrayAuthorizationToken(startToken)
}

internal object WinnV3NativeVerdictPublisher {
    fun apply(
        currentToken: Long,
        currentGeneration: Long,
        startToken: Long,
        startGeneration: Long,
        verdict: WinnV3NativeVerdict,
    ): WinnV3PublishedNativeVerdict? {
        if (startToken != currentToken || startGeneration != currentGeneration) return null
        return WinnV3PublishedNativeVerdict(startToken, startGeneration, verdict)
    }
}

/** Exact MethodChannel identity parsing. Floating-point coercion is forbidden. */
internal object WinnV3MethodIdentity {
    fun exactPositiveLong(value: Any?): Long? {
        val exact = when (value) {
            is Byte -> value.toLong()
            is Short -> value.toLong()
            is Int -> value.toLong()
            is Long -> value
            else -> return null
        }
        return exact.takeIf { it > 0L }
    }

    fun exactSelectionGeneration(value: Any?): String? {
        val text = value as? String ?: return null
        if (text.length !in 8..64) return null
        if (!text[0].isLetterOrDigit()) return null
        if (!text.all { it.isLetterOrDigit() || it == '.' || it == '_' || it == ':' || it == '-' }) {
            return null
        }
        return text
    }

    fun exactNodeSlug(value: Any?): String? {
        val text = value as? String ?: return null
        val trimmed = text.trim()
        if (trimmed.isEmpty() || trimmed.equals("auto", ignoreCase = true)) return null
        return trimmed
    }

    fun configRequestsV3(config: String): Boolean {
        var inWinnSection = false
        for (rawLine in config.lineSequence()) {
            val line = rawLine.trim()
            if (line.startsWith("[") && line.endsWith("]")) {
                inWinnSection = line.substring(1, line.length - 1)
                    .trim()
                    .equals("winn", ignoreCase = true)
                continue
            }
            if (!inWinnSection || line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue
            }
            val separator = line.indexOf('=')
            if (separator <= 0) continue
            val key = line.substring(0, separator).trim().lowercase()
            val value = line.substring(separator + 1).trim()
            if (key == "protocol" && value == "3") return true
            if (key == "carrier" && value.lowercase() == "winn3") return true
        }
        return false
    }
}

internal data class WinnV3NativeReadinessSnapshot(
    val startToken: Long,
    val startGeneration: Long,
    val state: String,
    val securityRefusal: Boolean,
    val awgXrayAuthorizationToken: Long,
    val selectionGeneration: String = "",
    val failedNode: String = "",
)

internal enum class WinnV3CoverLeg {
    AWG,
    XRAY,
    ;

    companion object {
        fun parse(value: String?): WinnV3CoverLeg? = when (value) {
            "awg" -> AWG
            "xray" -> XRAY
            else -> null
        }
    }
}

internal data class WinnV3AwgXrayGrant(
    val startToken: Long,
    val startGeneration: Long,
    val selectionGeneration: String,
    val failedV3Node: String,
    val exactV1Target: String = "",
    val issuedMonotonicMs: Long,
    val nextLeg: WinnV3CoverLeg = WinnV3CoverLeg.AWG,
    val targetBound: Boolean = false,
)

internal object WinnV3AwgXrayGrantStore {
    const val TTL_MS = 60_000L
    private val lock = Any()
    @Volatile private var grant: WinnV3AwgXrayGrant? = null

    fun clear() {
        synchronized(lock) { grant = null }
    }

    fun arm(
        startToken: Long,
        startGeneration: Long,
        selectionGeneration: String,
        failedV3Node: String,
        nowMs: Long,
    ): Boolean {
        if (startToken <= 0L || startGeneration <= 0L || nowMs <= 0L) return false
        if (selectionGeneration.length !in 8..64) return false
        if (failedV3Node.isBlank() || failedV3Node.equals("auto", ignoreCase = true)) return false
        synchronized(lock) {
            grant = WinnV3AwgXrayGrant(
                startToken = startToken,
                startGeneration = startGeneration,
                selectionGeneration = selectionGeneration,
                failedV3Node = failedV3Node,
                issuedMonotonicMs = nowMs,
            )
        }
        return true
    }

    fun consume(
        startToken: Long,
        startGeneration: Long,
        selectionGeneration: String,
        failedV3Node: String,
        exactV1Target: String,
        requestedLeg: WinnV3CoverLeg,
        nowMs: Long,
    ): Boolean {
        synchronized(lock) {
            val current = grant ?: return false
            if (current.startToken <= 0L || current.issuedMonotonicMs <= 0L ||
                nowMs < current.issuedMonotonicMs ||
                nowMs - current.issuedMonotonicMs > TTL_MS
            ) {
                grant = null
                return false
            }
            val target = exactV1Target.trim()
            if (startToken != current.startToken ||
                startGeneration != current.startGeneration ||
                selectionGeneration != current.selectionGeneration ||
                failedV3Node != current.failedV3Node ||
                target.isEmpty() ||
                target.equals("auto", ignoreCase = true)
            ) {
                grant = null
                return false
            }
            if (current.targetBound && target != current.exactV1Target) {
                grant = null
                return false
            }
            if (requestedLeg != current.nextLeg) {
                grant = null
                return false
            }
            grant = if (requestedLeg == WinnV3CoverLeg.AWG) {
                current.copy(
                    exactV1Target = target,
                    nextLeg = WinnV3CoverLeg.XRAY,
                    targetBound = true,
                )
            } else {
                null
            }
            return true
        }
    }
}

/**
 * Classifies a failed v3 start. Only positively proven ordinary network
 * unreachability may be [WinnV3NativeVerdict.ORDINARY_CONNECTIVITY]. Mixed
 * security evidence wins.
 *
 * Ordinary unreachability is a typed fact: an authenticated failure class,
 * an Android/Linux POSIX errno from the closed allowlist, typed throwable
 * evidence from [WinnV3OrdinaryNetworkEvidence], or a numeric errno captured
 * at a protected [WinnV3ProtectedSocketErrno] send. Boolean flags, timeout,
 * cancel, silence, class-name pump collapse, Darwin errno, ECONNREFUSED, and
 * raw exception text never authorize AWG/Xray cover. A handshake timeout is
 * [WinnV3NativeVerdict.UNKNOWN_TERMINAL] even when an errno is also present.
 *
 * A stopped pump is ordinary only when that pump preserved typed OS network
 * evidence. Engine/runtime death and a dead bridge without a typed errno
 * remain unknown_terminal.
 */
internal object WinnV3NativeVerdictClassifier {
    fun fromEvidence(
        statusRefusal: String? = null,
        bridgeFailure: String? = null,
        @Suppress("UNUSED_PARAMETER")
        bridgeRunning: Boolean = true,
        untrustworthyStatus: String? = null,
        timedOut: Boolean = false,
        error: String? = null,
        cause: Throwable? = null,
        @Suppress("UNUSED_PARAMETER")
        positiveOrdinaryUnreachability: Boolean = false,
        ordinaryNetworkPosixErrno: Int? = null,
        ordinaryNetworkFailure: WinnV3OrdinaryNetworkFailureClass? = null,
    ): WinnV3NativeVerdict {
        val parts = listOfNotNull(
            statusRefusal?.takeIf { it.isNotBlank() },
            bridgeFailure?.takeIf { it.isNotBlank() },
            untrustworthyStatus?.takeIf { it.isNotBlank() },
            error?.takeIf { it.isNotBlank() },
        )
        val blob = parts.joinToString("\n").lowercase()
        if (looksLikeSecurity(blob) || !statusRefusal.isNullOrBlank()) {
            return WinnV3NativeVerdict.TERMINAL_SECURITY
        }
        if (!untrustworthyStatus.isNullOrBlank()) {
            return WinnV3NativeVerdict.UNKNOWN_TERMINAL
        }
        // Timeout is silence, not proof that the physical network is
        // unreachable. It wins over a typed errno attached to the same poll.
        if (timedOut) {
            return WinnV3NativeVerdict.UNKNOWN_TERMINAL
        }
        val typedOrdinary = WinnV3OrdinaryNetworkEvidence.classify(
            failure = ordinaryNetworkFailure,
            posixErrno = ordinaryNetworkPosixErrno,
            cause = cause,
        )
        if (typedOrdinary != null) {
            return WinnV3NativeVerdict.ORDINARY_CONNECTIVITY
        }
        // A stopped pump, class-name collapse, or engine/runtime death is
        // not ordinary unreachability once typed OS evidence is absent.
        return WinnV3NativeVerdict.UNKNOWN_TERMINAL
    }

    private fun looksLikeSecurity(blob: String): Boolean {
        if (blob.isEmpty()) return false
        val sanitized = if (blob.contains("handshake attempts exhausted") ||
            blob.contains("nothing arrived at all")
        ) {
            blob.replace("check the gateway static key, the admission secret and the gateway id", "")
                .replace("check the gateway static key", "")
                .replace("gateway static key", "")
                .replace("admission secret and the gateway id", "")
        } else {
            blob
        }
        return SECURITY_NEEDLES.any { sanitized.contains(it) }
    }

    private val SECURITY_NEEDLES = listOf(
        "static key",
        "static_key",
        "wrong key",
        "admission secret",
        "admission_secret",
        "admission rejected",
        "admission refused",
        "admission refusal",
        "gateway id",
        "gateway_id",
        "replay",
        "malformed proof",
        "malformed status",
        "stale ack",
        "stale create-ack",
        "stale create ack",
        "silent downgrade",
        "unauthorized",
        "authentication failed",
    )
}

/**
 * The subset of the engine's status document the promotion gate reads.
 *
 * Only three fields, deliberately. A gate that reads more is a gate with more
 * ways to be wrong, and everything else the engine reports is diagnostics.
 * The lifecycle pair is the one addition, and it can only subtract: a gate
 * that sees `recovering`, `blocked`, `stopped` or `connecting` refuses to call
 * the tunnel proven, and nothing about it can make an unproven tunnel proven.
 */
internal data class WinnV3EngineStatus(
    val gateState: WinnV3GateState?,
    val rxPackets: Long,
    val rxOffered: Long,
    val refusal: String? = null,
    // The supervised engine's recovery state, and its blocked cause. Null when
    // the document does not carry them (an engine older than Round A2). These
    // never widen anything: the promotion gate only ever uses them to REFUSE.
    val lifecycle: WinnV3Lifecycle? = null,
    val lifecycleCause: String? = null,
    // False only when the document carried a lifecycle string outside the
    // closed vocabulary (it then parses as BLOCKED, and a host must be able to
    // say the engine did not report blocked: the value was not understood).
    val lifecycleRecognized: Boolean = true,
) {
    companion object {
        const val KEY_GATE_STATE = "gate_state"
        const val KEY_RX_PACKETS = "rx_packets"
        const val KEY_RX_OFFERED = "rx_offered"
        const val KEY_REFUSAL = "refusal"
        const val KEY_LIFECYCLE = "lifecycle"
        const val KEY_LIFECYCLE_CAUSE = "lifecycle_cause"

        /**
         * Parses the engine's `StatusResponse` payload.
         *
         * A flat-scan parser rather than `org.json`, for the same reason the
         * rest of this host avoids it: it runs unchanged on a plain JVM under
         * unit test, and the document is three scalars.
         *
         * @throws WinnV3StartRefusal when the document reports arrivals but not
         *   deliveries. See the file header: substituting one for the other is
         *   the exact error `WINN3_TUN_LAYER_20260808.md` §5 records a sibling
         *   lane catching, and it is worse here than where it was found,
         *   because here it promotes a tunnel.
         */
        @Throws(WinnV3StartRefusal::class)
        fun parse(json: String): WinnV3EngineStatus {
            if (json.length > MAX_STATUS_BYTES) {
                throw WinnV3StartRefusal(
                    "the engine status document exceeds $MAX_STATUS_BYTES bytes"
                )
            }
            // Empty is "nothing to read yet", not a hostile document: a blank
            // poll must not abort a staged start. Concatenated objects are
            // the opposite — findTopLevelColon would otherwise treat every
            // depth-1 `{...}` as the top-level object, so
            // `{"event":"x"}{"gate_state":<the carrying name>,"rx_packets":1}` parsed
            // as proven. C++ IsSingleJsonObject and Go decoder.More() already
            // refuse that shape.
            val trimmed = json.trim()
            if (trimmed.isEmpty()) {
                return WinnV3EngineStatus(null, 0L, 0L)
            }
            if (trimmed.first() != '{' || trimmed.last() != '}' ||
                !isSingleJsonObject(trimmed)
            ) {
                throw WinnV3StartRefusal(
                    "status document is not a single JSON object"
                )
            }
            for (key in listOf(
                    KEY_GATE_STATE, KEY_RX_PACKETS, KEY_RX_OFFERED,
                    KEY_REFUSAL, "event", "promotion_ready",
                    KEY_LIFECYCLE, KEY_LIFECYCLE_CAUSE,
                )) {
                if (countTopLevelKey(trimmed, key) > 1) {
                    throw WinnV3StartRefusal("duplicate JSON member $key")
                }
            }
            val rxPackets = scanLong(trimmed, KEY_RX_PACKETS)
            val rxOffered = scanLong(trimmed, KEY_RX_OFFERED)
            val gateText = scanString(trimmed, KEY_GATE_STATE)
            val refusal = scanString(trimmed, KEY_REFUSAL)
            val lifecycleText = scanString(trimmed, KEY_LIFECYCLE)
            val lifecycleCause = scanString(trimmed, KEY_LIFECYCLE_CAUSE)
            if (countTopLevelKey(trimmed, KEY_LIFECYCLE) == 1 && lifecycleText == null) {
                throw WinnV3StartRefusal("$KEY_LIFECYCLE is not a JSON string")
            }
            if (countTopLevelKey(trimmed, KEY_LIFECYCLE_CAUSE) == 1 && lifecycleCause == null) {
                throw WinnV3StartRefusal("$KEY_LIFECYCLE_CAUSE is not a JSON string")
            }
            if (countTopLevelKey(trimmed, KEY_RX_PACKETS) == 1 && rxPackets == null) {
                throw WinnV3StartRefusal("$KEY_RX_PACKETS is not an integer")
            }
            if (countTopLevelKey(trimmed, KEY_RX_OFFERED) == 1 && rxOffered == null) {
                throw WinnV3StartRefusal("$KEY_RX_OFFERED is not an integer")
            }
            if (countTopLevelKey(trimmed, KEY_GATE_STATE) == 1 && gateText == null) {
                throw WinnV3StartRefusal("$KEY_GATE_STATE is not a JSON string")
            }
            if (countTopLevelKey(trimmed, KEY_REFUSAL) == 1 && refusal == null) {
                throw WinnV3StartRefusal("$KEY_REFUSAL is not a JSON string")
            }
            if (rxPackets == null && rxOffered != null) {
                throw WinnV3StartRefusal(
                    "the engine status reports $KEY_RX_OFFERED but not $KEY_RX_PACKETS. " +
                        "RxOffered counts ARRIVALS and RxPackets counts DELIVERIES; promoting " +
                        "on an arrival would promote on a packet the inner-IP validator may " +
                        "have rejected. Refusing rather than substituting one for the other."
                )
            }
            return WinnV3EngineStatus(
                gateState = WinnV3GateState.fromWire(gateText),
                rxPackets = rxPackets ?: 0L,
                rxOffered = rxOffered ?: 0L,
                refusal = refusal?.trim()?.takeIf { it.isNotEmpty() },
                lifecycle = WinnV3Lifecycle.fromWire(lifecycleText),
                lifecycleCause = lifecycleCause?.trim()?.takeIf { it.isNotEmpty() },
                lifecycleRecognized = lifecycleText == null ||
                    WinnV3Lifecycle.entries.any { it.wire == lifecycleText },
            )
        }

        // Same 64 KiB ceiling as maxWinn3StatusBytes / kMaxStatusLineBytes.
        const val MAX_STATUS_BYTES = 64 * 1024

        // isSingleJsonObject is true when `line` (already trimmed) is exactly
        // one JSON object. findTopLevelColon keeps scanning after the first
        // `}`, so a second object at depth 1 would otherwise supply
        // gate_state / rx_packets and prove a tunnel the first object never
        // claimed. Same walk as C++ detail::IsSingleJsonObject.
        private fun isSingleJsonObject(line: String): Boolean {
            class Parser {
                var index = 0

                fun fail(): Nothing = throw IllegalArgumentException()

                fun whitespace() {
                    while (index < line.length &&
                        line[index].let { it == ' ' || it == '\t' || it == '\n' || it == '\r' }
                    ) {
                        index++
                    }
                }

                fun consume(c: Char): Boolean {
                    if (index < line.length && line[index] == c) {
                        index++
                        return true
                    }
                    return false
                }

                fun expect(c: Char) {
                    if (!consume(c)) fail()
                }

                fun string() {
                    expect('"')
                    while (index < line.length) {
                        val c = line[index++]
                        if (c == '"') return
                        if (c.code < 0x20) fail()
                        if (c == '\\') {
                            if (index >= line.length) fail()
                            when (line[index++]) {
                                '"', '\\', '/', 'b', 'f', 'n', 'r', 't' -> Unit
                                'u' -> repeat(4) {
                                    if (index >= line.length ||
                                        line[index++].let { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }
                                    ) {
                                        fail()
                                    }
                                }
                                else -> fail()
                            }
                        }
                    }
                    fail()
                }

                fun digits() {
                    val start = index
                    while (index < line.length && line[index] in '0'..'9') {
                        index++
                    }
                    if (index == start) fail()
                }

                fun number() {
                    consume('-')
                    if (!consume('0')) {
                        if (index >= line.length || line[index] !in '1'..'9') {
                            fail()
                        }
                        digits()
                    }
                    if (consume('.')) digits()
                    if (consume('e') || consume('E')) {
                        if (!consume('+')) consume('-')
                        digits()
                    }
                }

                fun literal(text: String) {
                    if (!line.startsWith(text, index)) fail()
                    index += text.length
                }

                fun value(depth: Int) {
                    if (depth > 64) fail()
                    whitespace()
                    if (index >= line.length) fail()
                    when (line[index]) {
                        '"' -> string()
                        '{' -> objectValue(depth)
                        '[' -> arrayValue(depth)
                        't' -> literal("true")
                        'f' -> literal("false")
                        'n' -> literal("null")
                        else -> number()
                    }
                }

                fun objectValue(depth: Int) {
                    expect('{')
                    whitespace()
                    if (consume('}')) return
                    while (true) {
                        string()
                        whitespace()
                        expect(':')
                        value(depth + 1)
                        whitespace()
                        if (consume('}')) return
                        expect(',')
                        whitespace()
                    }
                }

                fun arrayValue(depth: Int) {
                    expect('[')
                    whitespace()
                    if (consume(']')) return
                    while (true) {
                        value(depth + 1)
                        whitespace()
                        if (consume(']')) return
                        expect(',')
                        whitespace()
                    }
                }

                fun parse() {
                    whitespace()
                    objectValue(0)
                    whitespace()
                    if (index != line.length) fail()
                }
            }

            return try {
                Parser().parse()
                true
            } catch (_: IllegalArgumentException) {
                false
            }
        }

        // findTopLevelColon locates a key of the TOP-LEVEL object only.
        //
        // The previous scanner took the first `"<key>"` anywhere, so
        // `{"extra":{"gate_state":<the carrying name>,"rx_packets":1}}` parsed as
        // proven: nested keys are preceded by `{` the same way top-level
        // keys are. Go's decodeWinn3Status unmarshals only the top-level
        // object. This host now does the same.
        private fun decodeMemberName(
            json: String,
            at: Int,
        ): Pair<String, Int>? {
            if (at >= json.length || json[at] != '"') return null
            val name = StringBuilder()
            var index = at + 1
            while (index < json.length) {
                val character = json[index++]
                if (character == '"') return name.toString() to index
                if (character.code < 0x20) return null
                if (character != '\\') {
                    name.append(character)
                    continue
                }
                if (index >= json.length) return null
                when (val escaped = json[index++]) {
                    '"', '\\', '/' -> name.append(escaped)
                    'b' -> name.append('\b')
                    'f' -> name.append('\u000c')
                    'n' -> name.append('\n')
                    'r' -> name.append('\r')
                    't' -> name.append('\t')
                    'u' -> {
                        if (index + 4 > json.length) return null
                        var value = 0
                        repeat(4) {
                            val digit = json[index++].digitToIntOrNull(16)
                                ?: return null
                            value = value * 16 + digit
                        }
                        name.append(value.toChar())
                    }
                    else -> return null
                }
            }
            return null
        }

        private fun findTopLevelColon(json: String, key: String, start: Int = 0): Int {
            var depth = 0
            var inString = false
            var escaped = false
            var i = 0
            while (i < json.length) {
                val c = json[i]
                if (inString) {
                    if (escaped) {
                        escaped = false
                    } else if (c == '\\') {
                        escaped = true
                    } else if (c == '"') {
                        inString = false
                    }
                    i++
                    continue
                }
                when (c) {
                    '"' -> {
                        val member = if (depth == 1) decodeMemberName(json, i) else null
                        if (member != null && member.first == key) {
                            var after = member.second
                            while (after < json.length && json[after].isWhitespace()) after++
                            if (after < json.length && json[after] == ':' && after >= start) {
                                return after
                            }
                        }
                        inString = true
                    }
                    '{', '[' -> depth++
                    '}', ']' -> if (depth > 0) depth--
                }
                i++
            }
            return -1
        }

        private fun countTopLevelKey(json: String, key: String): Int {
            var n = 0
            var start = 0
            while (true) {
                val colon = findTopLevelColon(json, key, start)
                if (colon < 0) return n
                n++
                if (n > 1) return n
                start = colon + 1
            }
        }

        private fun isJsonValueEnd(json: String, at: Int): Boolean {
            if (at >= json.length) return true
            val c = json[at]
            return c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' ||
                c == '\n' || c == '\r'
        }

        // scanString unescapes JSON strings the way RFC 8259 does, not by
        // taking the character after '\\' literally. The previous reader
        // turned `"ca\rrying"` into the carrying name, which fromWire then treated
        // as proven. `\r` is a carriage return; `\c` is illegal and refused.
        private fun scanString(json: String, key: String): String? {
            val colon = findTopLevelColon(json, key)
            if (colon < 0) return null
            var i = colon + 1
            while (i < json.length && json[i].isWhitespace()) i++
            if (i >= json.length || json[i] != '"') return null
            val collected = StringBuilder()
            i++
            while (i < json.length) {
                val c = json[i]
                if (c == '\\') {
                    if (i + 1 >= json.length) return null
                    i++
                    when (val e = json[i]) {
                        '"', '\\', '/' -> collected.append(e)
                        'b' -> collected.append('\b')
                        'f' -> collected.append('\u000C')
                        'n' -> collected.append('\n')
                        'r' -> collected.append('\r')
                        't' -> collected.append('\t')
                        'u' -> {
                            if (i + 4 >= json.length) return null
                            val hex = json.substring(i + 1, i + 5)
                            val cp = hex.toIntOrNull(16) ?: return null
                            if (cp < 0x20 || cp > 0x7E) return null
                            collected.append(cp.toChar())
                            i += 4
                        }
                        else -> return null
                    }
                    i++
                    continue
                }
                if (c == '"') return collected.toString()
                if (c.code < 0x20) return null
                collected.append(c)
                i++
            }
            return null
        }

        private fun scanLong(json: String, key: String): Long? {
            val colon = findTopLevelColon(json, key)
            if (colon < 0) return null
            var i = colon + 1
            while (i < json.length && json[i].isWhitespace()) i++
            if (i >= json.length || json[i] < '0' || json[i] > '9') return null
            if (json[i] == '0' && i + 1 < json.length && json[i + 1] in '0'..'9') {
                return null
            }
            val start = i
            while (i < json.length && json[i] in '0'..'9') i++
            if (!isJsonValueEnd(json, i)) return null
            return json.substring(start, i).toLongOrNull()
        }
    }
}

/**
 * The gate itself: two conditions, both required, neither substitutable.
 *
 * Stateless on purpose. It holds no latch, so it cannot report proven for a
 * session that was proven and has since torn down — the caller asks it about
 * the status it has right now.
 */
internal object WinnV3PromotionGate {

    /**
     * §4.1's two clauses, ANDed, and never while a supervised engine says its
     * current round is anything but `connected`. An absent lifecycle is an
     * engine older than the field and keeps the two-clause rule unchanged.
     */
    fun isProven(status: WinnV3EngineStatus): Boolean =
        status.gateState?.mayCarry() == true && status.rxPackets > 0 &&
            (status.lifecycle == null || status.lifecycle == WinnV3Lifecycle.CONNECTED)

    /**
     * Why a status is not yet proven, for the log. Returns null when it is.
     *
     * Worth the few lines: the difference between "carrying but no packet has
     * been delivered" and "not carrying at all" is the difference between a
     * gateway that is not answering and a handshake that has not completed, and
     * on a censored network that is the whole diagnosis.
     */
    fun whyNotProven(status: WinnV3EngineStatus): String? {
        if (isProven(status)) return null
        val gate = status.gateState
        if (gate == null || !gate.mayCarry()) {
            return "gate is ${gate?.wire ?: "unreported"}, not carrying"
        }
        val lifecycle = status.lifecycle
        if (lifecycle != null && lifecycle != WinnV3Lifecycle.CONNECTED) {
            return "the engine's lifecycle is ${lifecycle.wire}, not connected"
        }
        return "gate is carrying but RxPackets is ${status.rxPackets}; " +
            "RxOffered is ${status.rxOffered}, which is arrivals and not deliveries"
    }
}

/**
 * The staged start: BOOTSTRAP, wait for proof, PROMOTE — or refuse.
 *
 * Free of Android imports so the whole state machine runs under unit test. The
 * two things it cannot do itself are supplied as lambdas: installing a posture
 * (which is `VpnService.Builder` + `establish()`), and reading the engine's
 * status (which is a `StatusRequest`/`StatusResponse` round trip).
 *
 * ## The three rules of §4.3, and where each one lives
 *
 * 1. *A start that would be staged but cannot build a narrow bootstrap must
 *    refuse to start, never fall back.* — [start] propagates every
 *    [WinnV3PostureRefusal] out and has no branch that installs [promote]'s
 *    posture on that path. There is no `catch` around the bootstrap install.
 * 2. *A proof that does not complete inside its deadline must fail the start
 *    with the host untouched.* — [start] returns [Outcome.RefusedNotProven]
 *    and calls [tearDown], never [promote].
 * 3. *After promotion the tunnel holds its routes fail-closed.* — not this
 *    class's: it belongs to the service's teardown path, which already holds
 *    routes on this platform.
 *
 * The optional [probe] lambda is the self-starting promotion probe (see
 * [WinnV3PromotionProbe]): the caller supplies a platform send, and this class
 * bounds it to [probeMaxAttempts] injections spaced [probeIntervalMs] apart,
 * fired only while the gate is carrying with zero delivered packets. It is
 * advisory: the gate above is still the only thing that decides promotion.
 */
internal class WinnV3StagedStart(
    private val bootstrap: WinnV3Posture,
    private val promoted: WinnV3Posture,
    private val proofDeadlineMs: Long,
    private val pollIntervalMs: Long,
    private val install: (WinnV3Posture) -> Unit,
    private val installBootstrapIfStillOwner: ((WinnV3Posture) -> Boolean)? = null,
    private val promoteIfStillOwner: ((WinnV3Posture) -> Boolean)? = null,
    private val readStatus: () -> String,
    private val inspectBridge: () -> WinnV3BridgeSnapshot = {
        WinnV3BridgeSnapshot(running = true, failure = null)
    },
    private val tearDown: () -> Unit,
    private val isStillOwner: () -> Boolean = { true },
    private val log: (String) -> Unit = {},
    private val probe: (() -> Unit)? = null,
    private val probeMaxAttempts: Int = WinnV3PromotionProbe.MAX_PROBE_ATTEMPTS,
    private val probeIntervalMs: Long = WinnV3PromotionProbe.PROBE_INTERVAL_MS,
    private val nowMs: () -> Long,
    private val sleepMs: (Long) -> Unit,
) {

    companion object {
        /**
         * The default proof deadline.
         *
         * The session's own handshake retransmission schedule is what this has
         * to outlast, and `WINN3_DRIVER_LOOP_20260808.md` §2 puts an idle
         * established session's silence draw at up to forty-five seconds. Thirty
         * seconds is comfortably longer than a handshake that is going to
         * complete and comfortably shorter than a user's patience with a
         * spinner. §4.3 rule 2 makes the cost of being wrong a retry, not a
         * leak.
         */
        const val DEFAULT_PROOF_DEADLINE_MS = 30_000L
        const val DEFAULT_POLL_INTERVAL_MS = 250L
    }

    sealed class Outcome {
        /** Bootstrap installed, proof observed, promotion installed. */
        data class Promoted(
            val rxPacketsAtPromotion: Long,
            val pollCount: Int,
            val verdict: WinnV3NativeVerdict = WinnV3NativeVerdict.CONNECTED,
        ) : Outcome()

        /**
          * Bootstrap installed, proof never observed. The host is torn down and
          * the user was promised nothing: the system still reports Connecting,
          * so a refusal costs a retry, whereas a promotion on an unproven
          * datapath costs the user their traffic.
          *
          * [verdict] is never `connectivity_failed`. A timeout without
          * positive ordinary-unreachability evidence is
          * [WinnV3NativeVerdict.UNKNOWN_TERMINAL].
          */
        data class RefusedNotProven(
            val reason: String,
            val pollCount: Int,
            val verdict: WinnV3NativeVerdict,
        ) : Outcome()
    }

    init {
        if (bootstrap.stage != WinnV3Stage.BOOTSTRAP) {
            throw WinnV3StartRefusal("the bootstrap posture is ${bootstrap.stage}, not BOOTSTRAP")
        }
        if (promoted.stage != WinnV3Stage.PROMOTED) {
            throw WinnV3StartRefusal("the promotion posture is ${promoted.stage}, not PROMOTED")
        }
        // §4.2 across BOTH postures. A promotion that changes the interface MTU
        // is a promotion that changes the number every full-size flow was sized
        // against, mid-session, with no way to tell the peer.
        if (bootstrap.mtu != promoted.mtu) {
            throw WinnV3StartRefusal(
                "the bootstrap MTU is ${bootstrap.mtu} and the promotion MTU is ${promoted.mtu}. " +
                    "§4.2 pins the interface MTU to exactly Tunnel.InnerMTU(), which does not " +
                    "change at promotion; a promotion that widens it black holes every " +
                    "full-size flow it just captured."
            )
        }
    }

    /**
     * Runs the staged start to a verdict.
     *
     * Never throws for "not proven" — that is [Outcome.RefusedNotProven], which
     * the caller reports. It DOES throw [WinnV3PostureRefusal] out of the
     * bootstrap install, because a bootstrap that could not be built narrow is
     * a configuration error and the correct response is the same refusal §4.3
     * rule 1 demands.
     */
    @Throws(WinnV3PostureRefusal::class, WinnV3StartRefusal::class)
    fun start(): Outcome {
        refuseIfSuperseded("before bootstrap")
        log("winn3: installing BOOTSTRAP posture — ${bootstrap.describe()}")
        val bootstrapInstalledForCurrentOwner =
            installBootstrapIfStillOwner?.invoke(bootstrap) ?: run {
                install(bootstrap)
                isStillOwner()
            }
        if (!bootstrapInstalledForCurrentOwner) {
            tearDown()
            throw WinnV3StartRefusal(
                "the Winn v3 start was superseded during bootstrap",
                WinnV3NativeVerdict.UNKNOWN_TERMINAL,
            )
        }

        val deadline = nowMs() + proofDeadlineMs
        var polls = 0
        var probesSent = 0
        var nextProbeAtMs = 0L
        var lastReason = "no status was read"
        while (nowMs() < deadline) {
            val pollStartedAtMs = nowMs()
            polls++
            val snapshot = inspectBridgeSafe()
            if (bridgeHasFailed(snapshot)) {
                log("winn3: bridge failed during staged poll — ${snapshot.failure ?: "not running"}")
                tearDown()
                return refuseFromBridge(snapshot, polls)
            }
            val status = try {
                WinnV3EngineStatus.parse(readStatus())
            } catch (e: WinnV3StartRefusal) {
                // A status document this host cannot trust is not a reason to
                // keep waiting and it is certainly not a reason to promote.
                // Malformed proof is unknown_terminal, never connectivity.
                tearDown()
                throw WinnV3StartRefusal(
                    e.message ?: "untrustworthy Winn v3 status document",
                    WinnV3NativeVerdict.UNKNOWN_TERMINAL,
                )
            }
            if (!status.refusal.isNullOrEmpty()) {
                tearDown()
                throw WinnV3StartRefusal(
                    "the Winn v3 engine refused the session: ${status.refusal}",
                    WinnV3NativeVerdictClassifier.fromEvidence(statusRefusal = status.refusal),
                )
            }
            if (nowMs() >= deadline) break
            if (WinnV3PromotionGate.isProven(status)) {
                refuseIfSuperseded("before promotion")
                val provenSnapshot = inspectBridgeSafe()
                if (bridgeHasFailed(provenSnapshot)) {
                    log(
                        "winn3: status looked proven but the bridge has failed — " +
                            "${provenSnapshot.failure ?: "not running"}"
                    )
                    tearDown()
                    return refuseFromBridge(provenSnapshot, polls)
                }
                refuseIfSuperseded("after final bridge inspection")
                log(
                    "winn3: datapath proven — gate=carrying rxPackets=${status.rxPackets} " +
                        "after $polls polls; installing PROMOTED posture"
                )
                val installedForCurrentOwner = promoteIfStillOwner?.invoke(promoted) ?: run {
                    refuseIfSuperseded("immediately before promotion install")
                    install(promoted)
                    isStillOwner()
                }
                if (!installedForCurrentOwner) {
                    tearDown()
                    throw WinnV3StartRefusal(
                        "the Winn v3 start was superseded during promotion",
                        WinnV3NativeVerdict.UNKNOWN_TERMINAL,
                    )
                }
                return Outcome.Promoted(
                    status.rxPackets,
                    polls,
                    WinnV3NativeVerdict.CONNECTED,
                )
            }
            lastReason = WinnV3PromotionGate.whyNotProven(status) ?: "unknown"
            val liveOrdinary = WinnV3NativeVerdictClassifier.fromEvidence(
                bridgeFailure = snapshot.failure,
                bridgeRunning = snapshot.running,
                timedOut = false,
                cause = snapshot.cause,
                ordinaryNetworkPosixErrno = snapshot.ordinaryNetworkPosixErrno,
                ordinaryNetworkFailure = snapshot.ordinaryNetworkFailure,
            )
            if (liveOrdinary == WinnV3NativeVerdict.ORDINARY_CONNECTIVITY) {
                if (!isStillOwner()) {
                    tearDown()
                    throw WinnV3StartRefusal(
                        "winn3 staged start was superseded before ordinary-network cover",
                        WinnV3NativeVerdict.UNKNOWN_TERMINAL,
                    )
                }
                log("winn3: structured OS network error during staged poll")
                tearDown()
                return Outcome.RefusedNotProven(
                    lastReason,
                    polls,
                    WinnV3NativeVerdict.ORDINARY_CONNECTIVITY,
                )
            }
            // The self-starting promotion probe, bounded: at most a handful of
            // one-packet injections spaced across the promotion window, and
            // only while the gate carries with nothing delivered. Carrying with
            // zero deliveries is the starvation shape the probe exists to
            // break; it is never fired before the gate carries and never once
            // a packet has been delivered, so a session about to be refused or
            // already proven is left alone. Advisory only: promotion still
            // decides exclusively from the engine's own proof, and the window
            // still fails closed when nothing comes back.
            if (probe != null && probesSent < probeMaxAttempts &&
                status.gateState?.mayCarry() == true && status.rxPackets == 0L
            ) {
                val now = nowMs()
                if (now >= nextProbeAtMs) {
                    probesSent++
                    nextProbeAtMs = now + probeIntervalMs
                    try {
                        log(
                            "winn3: gate is carrying with nothing delivered; " +
                                "sending the self-starting promotion probe " +
                                "$probesSent/$probeMaxAttempts"
                        )
                        probe()
                    } catch (e: Exception) {
                        log(
                            "winn3: the self-starting promotion probe failed: " +
                                e.javaClass.simpleName
                        )
                    }
                }
            }
            val remainingTickMs =
                pollIntervalMs - (nowMs() - pollStartedAtMs)
            val remainingProofMs = deadline - nowMs()
            val sleepForMs = minOf(remainingTickMs, remainingProofMs)
            if (sleepForMs > 0L) sleepMs(sleepForMs)
        }

        // §4.3 rule 2. The host is put back exactly as it was.
        log("winn3: refusing to promote after ${proofDeadlineMs}ms — $lastReason")
        val timeoutSnapshot = inspectBridgeSafe()
        tearDown()
        val timeoutVerdict = WinnV3NativeVerdictClassifier.fromEvidence(
            bridgeFailure = timeoutSnapshot.failure,
            bridgeRunning = timeoutSnapshot.running,
            timedOut = true,
            error = lastReason,
            cause = timeoutSnapshot.cause,
            ordinaryNetworkPosixErrno = timeoutSnapshot.ordinaryNetworkPosixErrno,
            ordinaryNetworkFailure = timeoutSnapshot.ordinaryNetworkFailure,
        )
        return Outcome.RefusedNotProven(
            lastReason,
            polls,
            if (timeoutVerdict == WinnV3NativeVerdict.CONNECTED) {
                WinnV3NativeVerdict.UNKNOWN_TERMINAL
            } else {
                timeoutVerdict
            },
        )
    }

    private fun inspectBridgeSafe(): WinnV3BridgeSnapshot {
        return try {
            inspectBridge()
        } catch (e: Exception) {
            WinnV3BridgeSnapshot(
                running = false,
                failure = "bridge inspection failed: ${e.javaClass.simpleName}",
            )
        }
    }

    private fun bridgeHasFailed(snapshot: WinnV3BridgeSnapshot): Boolean =
        !snapshot.running || !snapshot.failure.isNullOrBlank()

    private fun refuseFromBridge(
        snapshot: WinnV3BridgeSnapshot,
        polls: Int,
    ): Outcome.RefusedNotProven {
        val reason = snapshot.failure?.takeIf { it.isNotBlank() }
            ?: "Winn v3 bridge is not running"
        val verdict = WinnV3NativeVerdictClassifier.fromEvidence(
            bridgeFailure = snapshot.failure,
            bridgeRunning = snapshot.running,
            error = reason,
            cause = snapshot.cause,
            positiveOrdinaryUnreachability = snapshot.positiveOrdinaryUnreachability,
            ordinaryNetworkPosixErrno = snapshot.ordinaryNetworkPosixErrno,
            ordinaryNetworkFailure = snapshot.ordinaryNetworkFailure,
        )
        val cancelledOrdinary = !isStillOwner() &&
            verdict == WinnV3NativeVerdict.ORDINARY_CONNECTIVITY
        return Outcome.RefusedNotProven(
            reason = reason,
            pollCount = polls,
            verdict = when {
                cancelledOrdinary -> WinnV3NativeVerdict.UNKNOWN_TERMINAL
                verdict == WinnV3NativeVerdict.CONNECTED -> WinnV3NativeVerdict.UNKNOWN_TERMINAL
                else -> verdict
            },
        )
    }

    private fun refuseIfSuperseded(phase: String) {
        if (isStillOwner()) return
        // A stale staged-start thread must never establish a new VpnService
        // interface after disconnect or replace the interface owned by a fast
        // reconnect. Closing the resources allocated by this staged start is
        // safe before bootstrap and mandatory after bootstrap.
        tearDown()
        throw WinnV3StartRefusal(
            "winn3 staged start was superseded $phase",
            WinnV3NativeVerdict.UNKNOWN_TERMINAL,
        )
    }
}
