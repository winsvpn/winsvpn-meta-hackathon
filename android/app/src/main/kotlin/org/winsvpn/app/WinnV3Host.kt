package org.winsvpn.app

import java.io.Closeable

/**
 * What the Android host supplies to `winn3/driver`, and what it deliberately
 * does not.
 *
 * ## 1. The Go interfaces this host satisfies
 *
 * `winn3/driver.Config` needs four things, and only three of them are the
 * host's. The interfaces are declared in the tun and driver packages, not
 * imported from `session`, and this file names each one it answers:
 *
 * | Go declaration | Android |
 * |---|---|
 * | `tun.Device { ReadPacket([]byte) (int, error); WritePacket([]byte) (int, error); MTU() int }` | the `ParcelFileDescriptor` from `VpnService.Builder.establish()`, pumped as [WinnV3IpPacketSeam] |
 * | `carrier.UDPConfig.Conn` (the socket `NewUDP` wraps) | [WinnUnderlaySocket] — a `DatagramSocket`, `VpnService.protect()`ed **before** it is handed over |
 * | `tun.Clock { Now() time.Time }` / `driver.Clock { Now(); NewTimer(d) }` | **NOT the host's.** See §3 below. |
 * | `tun.FrameSink { SendData(pkt []byte) error }` | **NOT the host's.** The loop supplies it through `winn3/driver/sink.go`'s three-line name adapter. |
 *
 * ## 2. The socket, and why `protect()` before connect is the whole story
 *
 * `carrier.DialUDP` opens its own socket. Android must not use it. The path is
 * `carrier.NewUDP(UDPConfig{Conn: existing, Peer: remote, OwnsConn: false})`,
 * over a `*net.UDPConn` the engine gets from `net.FilePacketConn` on a
 * descriptor this host sent with SCM_RIGHTS — because:
 *
 *  - `VpnService.protect()` marks the kernel socket, not the descriptor number:
 *    netd sets the bypass-VPN `SO_MARK` on the `struct sock`, and route lookups
 *    for that socket then skip the VPN routing rules entirely.
 *  - `dup()` and SCM_RIGHTS both produce a new descriptor onto the *same* open
 *    file description and the same `struct sock`, so the mark travels into the
 *    subprocess.
 *  - A socket the engine opened for itself carries no mark, matches the routes
 *    this service just installed, and dead-loops.
 *
 * All of that is already implemented and already proven on a real device:
 * [WinnAndroidEngineHost.openProtectedUnderlaySocket]. **v3 changes none of
 * it.** That is the single largest reason Android was the right platform to
 * integrate first.
 *
 * ## 3. The clock the host must NOT supply
 *
 * `WINN3_DRIVER_LOOP_20260808.md` §3: *`winn3/session` and `winn3/tun` both
 * refuse to own a timer, and both are right to: a timing policy that lives in
 * two layers will disagree with itself, and the measured failure this protocol
 * replaces was a 25.000-second keepalive that was a timer in the wrong layer.*
 *
 * `driver.Config.Clock` nil means `driver.SystemClock`, and `SessionClock`
 * fills the session's and the tun's from it, so **one** clock exists per
 * tunnel and it is inside the engine. A host that shipped its own `Now()`
 * across the frame channel would be a second timing authority reachable by a
 * peer-supplied message — the exact shape §3 forbids. This host therefore
 * supplies no clock, and [WinnV3EngineConfig] carries no time field.
 *
 * ## 4. Subprocess, not in-process — and the finding that decides it
 *
 * Android keeps the subprocess. `cmd/winn-datapath` is the shape Linux and
 * Windows use and the shape this host already speaks: a Go binary named
 * `libwinnengine.so`, extracted by the package installer from a signed APK,
 * executed from `nativeLibraryDir`, reached over one abstract-namespace
 * AF_UNIX stream socket with a uid check. iOS is forced into `cdatapath`
 * because it forbids subprocesses; Android has no such rule and gains nothing
 * from the C ABI.
 *
 * There is one real argument for going in-process, and it is worth stating
 * because it is what a reader will ask. In v3 the engine needs a `tun.Device`,
 * and the obvious move is to send the tun descriptor by SCM_RIGHTS exactly as
 * the UDP socket is sent. **That does not work on Android, and the reason is
 * the staged posture itself:**
 *
 *  - Android has no API to change the routes, MTU or resolvers of a live
 *    `VpnService` interface. The only mechanism is to call
 *    `Builder.establish()` again, which yields a **new** descriptor.
 *  - So promotion — §4.1's second posture — necessarily replaces the tun
 *    descriptor mid-session.
 *  - `tun.Config.Device` is read once, in `tun.New`, and `Tunnel` exposes no
 *    way to swap it. `PumpOutbound` is already blocked in `ReadPacket` on the
 *    old one.
 *
 * A descriptor handed over at create time is therefore a descriptor that goes
 * stale at exactly the moment the tunnel starts carrying traffic. Going
 * in-process would not help: the Go side has the same fixed `Device`.
 *
 * **The resolution is that the host owns the tun device and pumps IP packets
 * across the frame channel**, so the engine's `tun.Device` is a stable,
 * channel-backed device whose identity survives a re-`establish()`. The host
 * swaps its own file streams under it and the engine never notices. That reuses
 * the `Inbound`/`Outbound` frames the AWG path already pumps — it is the
 * existing mechanism with a different payload, not a second one.
 *
 * ## 5. The payload-semantics boundary inverts, and Android's oldest blocker
 *    disappears with it
 *
 * [WinnAwgDatagramSeam] documents the v2 rule: Inbound/Outbound carry
 * **AmneziaWG outer datagrams**, never raw IP packets, and the engine refuses
 * `payload:"ip-packet"` at create time because `winn_protocol_experimental/
 * datapath` contains no WireGuard implementation and would forward tun packets
 * to the gateway in cleartext. Android has no such datagram source without
 * patching libwg-go, which is why [WinnTunnelBridge] refuses to start.
 *
 * **In v3 that inverts.** `winn3/core` is the crypto — ML-KEM-768 ratchet,
 * AEAD, framing — and `winn3/tun` is the inner-IP validator, so `ip-packet` is
 * not merely permitted, it is the only correct payload: the engine's
 * `tun.Device` is defined as *an IP packet starting at its version nibble*
 * (`winn3/tun/params.go`). The v2 refusal was about a missing implementation,
 * not about the wire.
 *
 * The consequence is the useful one: **v3 on Android needs no AmneziaWG
 * outer-datagram seam at all.** The `WinnAwgLoopbackSeam` relay exists to
 * synthesise one; v3 does not need it, does not use it, and does not need
 * libwg-go patched. Android's longest-standing v2 integration blocker is not
 * solved by this lane — it is bypassed by the protocol.
 */
internal object WinnV3Host {

    /**
     * The `payload` value a v3 create must carry.
     *
     * Held as a constant beside [WinnEngineConfig.PAYLOAD_AWG_DATAGRAM] so the
     * two can never be confused at a call site, and so a test can assert that a
     * v3 config never emits the v2 value and vice versa. Getting this wrong in
     * the v2 direction is what puts cleartext on the wire.
     */
    const val PAYLOAD_IP_PACKET = "ip-packet"

    /**
     * The flag that selects the v3 stack in the engine binary.
     *
     * **This flag now exists, and it does not travel alone.** When this comment
     * said "does not exist yet" that was true; the seam has since landed, and
     * running the real binary — cross-compiled for `android/arm64` and executed
     * on an API 34 device — shows the argv described here was incomplete:
     *
     *     winn-datapath: -winn3 needs -winn3-keys PATH
     *
     * So `-winn3` alone starts a subprocess that exits 1 before a frame
     * crosses. [FLAG_WINN3_KEYS] is the other half; see [WinnV3Keys] for the
     * document it names and for why key material travels as a path rather than
     * in the Create frame.
     *
     * [capabilityRefusal] still makes an engine that cannot speak v3 a refusal
     * rather than a silent v1 session, which is the same discipline
     * `WinnTunnelBridge.NO_DATAGRAM_SEAM` applies to the v1 gap: the gap is
     * enforced, not narrated.
     */
    const val FLAG_WINN3 = "-winn3"

    /**
     * The flag naming the `-winn3` key document.
     *
     * Mandatory whenever [FLAG_WINN3] is present — the engine refuses each
     * without the other — and it carries a PATH, never the material. See
     * [WinnV3Keys].
     */
    const val FLAG_WINN3_KEYS = "-winn3-keys"

    /**
     * The seam `cmd/winn-datapath` has to grow, stated precisely enough to
     * implement without reading this file.
     *
     * Not written by this lane: `winn_protocol_experimental/cmd/` is a sibling
     * lane's territory. Described and stopped, per the lane's brief.
     */
    const val ENGINE_SEAM =
        "cmd/winn-datapath needs one flag, -winn3, that builds driver.NewClient instead of " +
            "datapath.Open. Its dependencies all exist: driver.NewSizing(pathMTU, classes...) " +
            "for the plan floor; carrier.NewUDP(UDPConfig{Conn: <the SCM_RIGHTS socket via " +
            "net.FilePacketConn>, Peer: <gateway>, OwnsConn: false}) for the carrier, which " +
            "is why the socket must NOT be dialled by carrier.DialUDP; a tun.Device backed by " +
            "the duplex Inbound/Outbound frames rather than by a descriptor, because Android " +
            "re-establishes its tun at promotion and tun.Config.Device is fixed at tun.New; " +
            "and driver.Config.Tun with Sink and CarrierFloorMessageSize left zero, which the " +
            "loop pins. The status document must additionally publish gate_state and " +
            "rx_packets from Loop.Tunnel().Gate().State() and Loop.Tunnel().Stats(), because " +
            "those two are the whole of the promotion gate. It must publish rx_packets " +
            "whenever it publishes rx_offered: this host refuses a status that reports " +
            "arrivals without deliveries rather than substituting one for the other. " +
            "-print-contract must gain a machine-readable payload list so a host can probe " +
            "for v3 support instead of matching English prose."

    /**
     * The refusal when the packaged engine cannot speak v3.
     *
     * Deliberately shaped like `WinnTunnelBridge.NO_DATAGRAM_SEAM`: a constant,
     * so a test can assert the gap is reported rather than worked around.
     */
    const val NO_V3_ENGINE =
        "Refusing to start a Winn Protocol v3 session: the packaged engine does not advertise " +
            "the ip-packet payload. v3 carries inner IP packets, because winn3/core is the " +
            "crypto and winn3/tun is the inner-IP validator; the v2 engine refuses ip-packet " +
            "at create time because it contains no WireGuard implementation and would forward " +
            "tun packets to the gateway in cleartext. Starting a v2 session here instead would " +
            "be a silent downgrade of the user's protocol, so this refuses. " + ENGINE_SEAM

    /**
     * Probes a `-print-contract` banner for v3 support.
     *
     * Two accepted shapes, in order of preference:
     *
     *  1. a machine-readable `"payloads":[...]` list containing `ip-packet` —
     *     the shape [ENGINE_SEAM] asks the engine lane for;
     *  2. nothing else. In particular the current banner's free-text
     *     `payload_semantics` is **not** matched, even though it names both
     *     payloads in English ("carry AmneziaWG outer datagrams, not raw IP
     *     packets"). Matching prose would make the host's protocol selection
     *     depend on a sentence somebody might reword, and this sentence in
     *     particular says "not raw IP packets" — a substring search for
     *     "ip-packet" against a document that says the opposite is precisely
     *     the bug that would start a v2 session believing it was v3.
     */
    fun engineSupportsV3(contractBanner: String): Boolean {
        val at = contractBanner.indexOf("\"payloads\"")
        if (at < 0) return false
        val open = contractBanner.indexOf('[', at)
        if (open < 0) return false
        val close = contractBanner.indexOf(']', open)
        if (close < 0) return false
        val list = contractBanner.substring(open + 1, close)
        return list.split(',').any { it.trim().trim('"') == PAYLOAD_IP_PACKET }
    }

    /** The refusal text for a specific banner, with the banner quoted for the log. */
    fun capabilityRefusal(contractBanner: String): String =
        "$NO_V3_ENGINE Contract banner was: ${contractBanner.trim().take(400)}"

    /**
     * The argv for a v3 engine subprocess.
     *
     * Every flag except [FLAG_WINN3] is copied from
     * [WinnAndroidEngineHost.engineArguments], because the spawn contract is
     * read from the engine and not assumed: `-transport unix`, `-control
     * @<abstract-name>`, `-receive-fd`. The engine DIALS and this host LISTENS,
     * and `flags.NArg() != 0` makes any positional argument fatal, so nothing
     * here is positional.
     */
    fun engineArguments(
        enginePath: String,
        channelName: String,
        carrierProfilePath: String? = null,
        winn3KeysPath: String? = null,
    ): List<String> = buildList {
        addAll(WinnAndroidEngineHost.engineArguments(enginePath, channelName, carrierProfilePath))
        add(FLAG_WINN3)
        // Optional in this signature and MANDATORY on the wire. It is optional
        // here only so the flag's placement can still be asserted without a
        // path; a spawn that omits it is refused by
        // WinnAndroidEngineHost.startEngineProcess before a process exists,
        // rather than by the engine after one does.
        if (winn3KeysPath != null) {
            require(winn3KeysPath.isNotBlank()) {
                "A blank winn3 key document path would make the engine exit with " +
                    "\"$FLAG_WINN3 needs $FLAG_WINN3_KEYS PATH\"; refusing to build that argv."
            }
            add(FLAG_WINN3_KEYS); add(winn3KeysPath)
        }
    }
}

/**
 * The source and sink of the bytes that cross `Inbound` and `Outbound` in a v3
 * session: **inner IP packets**, off and onto the host's tun device.
 *
 * The v3 counterpart of [WinnAwgDatagramSeam], and the reason it is a separate
 * interface rather than a mode flag on that one: the two carry different bytes,
 * and a single interface whose meaning depends on a field elsewhere is exactly
 * how a host ends up labelling tun packets as AWG datagrams. The type system
 * should make that unrepresentable, so it does.
 *
 * What crosses here matches `winn3/tun.Device`'s own words: *an IP packet
 * starting at its version nibble.* Android's tun descriptor already delivers
 * exactly that — no Darwin 4-byte address-family prefix, no Linux
 * `PACKET_INFO` header — so this seam adds no framing and strips none.
 *
 * ## Why the host owns this and the engine does not
 *
 * See [WinnV3Host] §4. Promotion re-establishes the interface and produces a
 * new descriptor; `tun.Config.Device` is fixed at `tun.New`. The host swaps the
 * descriptor under this seam and the engine's device identity is unchanged.
 */
internal interface WinnV3IpPacketSeam : Closeable {
    /**
     * Blocks for the next inner IP packet the host stack wants sent, copies it
     * into [buffer] and returns its length. Returns -1 when the seam is
     * finished.
     */
    fun readOutgoingPacket(buffer: ByteArray): Int

    /** Delivers one validated inner IP packet to the host stack. */
    fun writeIncomingPacket(packet: ByteArray, length: Int)

    /**
     * Replaces the underlying tun descriptor after a promotion.
     *
     * The engine is not told and must not be: from `winn3/tun`'s side the
     * `Device` is unchanged, which is the property that makes a staged posture
     * possible on this platform at all.
     */
    fun rebindDevice(device: WinnV3TunDevice)
}

/**
 * One established tun interface: the descriptor plus the MTU the host set on
 * it.
 *
 * The MTU travels with the descriptor because `tun.Device.MTU()` is read by
 * `tun.New` and checked against the tunnel's inner MTU — *Attach refuses if
 * this exceeds the tunnel's inner MTU* — so a host that reports one number and
 * configures another has built the black hole §4.2 exists to prevent.
 */
internal interface WinnV3TunDevice : Closeable {
    val mtu: Int
    fun read(buffer: ByteArray): Int
    fun write(packet: ByteArray, length: Int)
}

/**
 * The v3 `Create` payload.
 *
 * The same flat-append style as [WinnEngineConfig], for the same reason: no
 * `org.json` dependency in a class that has to run under a plain-JVM unit test.
 *
 * Three fields are fixed and cannot be overridden by a caller:
 *
 *  - `payload` is [WinnV3Host.PAYLOAD_IP_PACKET]. A v3 session that announced
 *    `awg-datagram` would be asking the engine to forward AmneziaWG datagrams
 *    it has no implementation for.
 *  - `allow_own_socket` is false. Same rule as v2 and for the same reason: a
 *    socket the engine opened for itself carries no `SO_MARK` and dead-loops.
 *  - `owns_tun` is false. The host owns the device; see [WinnV3Host] §4.
 *
 * `inner_mtu` is **not** advisory. It is the number §4.2 pins the interface to,
 * and the engine cross-checks it against its own `Sizing.InnerMTU`; a
 * disagreement is a refusal on both sides rather than a silent truncation.
 */
internal class WinnV3EngineConfig(
    val gatewayEndpoint: String,
    val innerAddress: String,
    val innerNextHop: String,
    val innerMtu: Int,
    val pathMtu: Int,
    val carrierClasses: List<String>,
    val sessionId: String,
) {
    init {
        require(gatewayEndpoint.isNotBlank()) { "a v3 session needs a gateway endpoint" }
        require(innerAddress.isNotBlank()) { "a v3 session needs an assigned inner address" }
        require(carrierClasses.isNotEmpty()) {
            "a v3 session needs a migration plan: driver.NewSizing refuses an empty one, " +
                "because a floor computed over no classes is a floor that guarantees nothing " +
                "and the first migration is 84 bytes too wide"
        }
        require(innerMtu >= WinnV3Sizing.MIN_INNER_MTU_V4) {
            "inner MTU $innerMtu is below the ${WinnV3Sizing.MIN_INNER_MTU_V4}-byte IPv4 floor"
        }
        // The plan floor, and EQUALITY with it. Not "at most": the create seam
        // accepts only the floor exactly — `cmd/winn-datapath/winn3_create.go`
        // refusal 3, pinned by TestTheFloorIsTheOnlyAcceptableInnerMTU, which
        // refuses 1360 and 1358 as well as 1443 — because a narrower MTU
        // silently costs throughput the plan already paid for, and there is no
        // reading under which a host that computed a different number is right.
        //
        // A "≤ floor" check here would let a config through that the engine then
        // refuses at create time, which turns a Kotlin-side bug into a start
        // failure on a handset instead of a failed unit test.
        val floor = WinnV3Sizing.planFloorInnerMtu(pathMtu, carrierClasses)
        require(innerMtu == floor) {
            "inner MTU $innerMtu is not the plan floor $floor over " +
                "${carrierClasses.joinToString(",", "[", "]")} at a path MTU of $pathMtu " +
                "(message size ${WinnV3Sizing.planFloorMessageSize(pathMtu, carrierClasses)}). " +
                "§4.2 pins the interface to EXACTLY the floor. A wider one black-holes every " +
                "full-size flow at the first migration off the dialled carrier while the tunnel " +
                "still reads up at both ends — the hardest failure to diagnose in the field, and " +
                "indistinguishable from censorship. If $innerMtu came from the carrier that was " +
                "dialled rather than from the plan, that is the defect this refusal exists to " +
                "catch: the engine refuses the same document."
        }
    }

    fun toJson(): String = buildString {
        append('{')
        appendPair(this, "payload", WinnV3Host.PAYLOAD_IP_PACKET)
        appendPair(this, "gateway_endpoint", gatewayEndpoint)
        appendPair(this, "inner_address", innerAddress)
        appendPair(this, "inner_next_hop", innerNextHop)
        appendPair(this, "inner_mtu", innerMtu.toString(), quoted = false)
        appendPair(this, "path_mtu", pathMtu.toString(), quoted = false)
        appendPair(this, "carrier_classes", carrierClasses.joinToString(",", "[", "]") { WinnEngineConfig.jsonString(it) }, quoted = false)
        appendPair(this, "session_id", sessionId)
        appendPair(this, "allow_own_socket", "false", quoted = false)
        appendPair(this, "owns_tun", "false", quoted = false, last = true)
        append('}')
    }

    private fun appendPair(
        sb: StringBuilder,
        key: String,
        value: String,
        quoted: Boolean = true,
        last: Boolean = false,
    ) {
        sb.append(WinnEngineConfig.jsonString(key)).append(':')
        if (quoted) sb.append(WinnEngineConfig.jsonString(value)) else sb.append(value)
        if (!last) sb.append(',')
    }
}
