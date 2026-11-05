package org.winsvpn.app

/**
 * The **staged posture** `winn3/tun` requires of a host, expressed for Android.
 *
 * This is `WINN3_TUN_LAYER_20260808.md` §4 in code. Nothing here is invented:
 * every rule below is a row of §4.1's table or a clause of §4.3, and the one
 * number the whole thing turns on comes from `winn3/tun/params.go`.
 *
 * ## Why a description rather than a pile of Builder calls
 *
 * §4.3.1 is explicit about the shape, and it is the shape iOS already ships:
 *
 * > The iOS code throws rather than widening, and **verifies narrowness on the
 * > settings object it just built rather than trusting the code that built it**.
 * > That is the right shape and it should be copied verbatim.
 *
 * `VpnService.Builder` is write-only :  it has no getters :  so on Android
 * "the settings object it just built" cannot be re-read. The equivalent is to
 * record every call as it is made and verify the RECORD. That is
 * [WinnV3PostureRecord]: [applyTo] writes through it to the real builder, and
 * [WinnV3Posture.verifyNarrow] then reads back what was actually asked for. A
 * bug in [applyTo] is therefore caught by [verifyNarrow], which is the whole
 * point of not verifying the intent.
 *
 * ## Deliberately free of Android imports
 *
 * Same reason [WinnTunnelBridge] is: so the posture rules are exercised on a
 * plain JVM, and the Android-specific part is one thin adapter over
 * `VpnService.Builder` that has nothing in it to get wrong. The address family
 * constants are passed as plain ints rather than pulled from `OsConstants`.
 */
internal object WinnV3Sizing {

    /**
     * `winn3/tun.Overhead()` :  transport message overhead plus the DATA frame
     * header:
     *
     *     Overhead() = core.TransportOverhead() + FrameOverhead
     *                = (8 + 2 + 16)             + 3
     *                = 29
     *
     * Padding does not appear here on purpose: `core.Seal` writes it as zero
     * bytes INSIDE the AEAD and the inner length field recovers the payload
     * boundary, so it costs no frame header and no per-packet overhead.
     *
     * Duplicating a Go constant in Kotlin is a real cost and it is paid
     * knowingly. The alternative :  asking the engine for the number over the
     * frame channel :  would make the host's interface MTU depend on a value the
     * peer supplied, and §4.2 is a rule about what the HOST must set. What
     * guards the duplication is [assertsAgreeWithGo], which pins the three
     * worked examples `winn3/tun/params.go` states in its own doc comment.
     */
    const val OVERHEAD = 29

    /** `winn3/tun.UDPOverIPv4Overhead` :  20 bytes of IPv4 header, 8 of UDP. */
    const val UDP_OVER_IPV4_OVERHEAD = 28

    /** `winn3/tun.UDPOverIPv6Overhead` :  40 bytes of IPv6 header, 8 of UDP. */
    const val UDP_OVER_IPV6_OVERHEAD = 48

    /** `winn3/tun.IPv6MinLinkMTU` :  RFC 8200's hard floor. */
    const val IPV6_MIN_LINK_MTU = 1280

    /** `winn3/tun.MinInnerMTUv4` :  RFC 1122's minimum reassembly buffer. */
    const val MIN_INNER_MTU_V4 = 576

    /** `winn3/tun.InnerMTU(carrierMaxMessage)`. */
    fun innerMtu(carrierMaxMessage: Int): Int = carrierMaxMessage - OVERHEAD

    /** `winn3/tun.CarrierMessageFor(mtu)`. */
    fun carrierMessageFor(mtu: Int): Int = mtu + OVERHEAD

    /**
     * `winn3/tun.InnerMTUForPath(pathMTU, outerOverhead)`.
     *
     * **SINGLE CARRIER.** This is the inner MTU for ONE class over ONE address
     * family, and it is the wrong number to configure an interface with whenever
     * the session may migrate. Use [planFloorInnerMtu] for that; this stays
     * because `winn3/tun/params.go` states its three worked examples in these
     * terms and [assertsAgreeWithGo] pins them.
     */
    fun innerMtuForPath(pathMtu: Int, outerOverhead: Int): Int =
        innerMtu(pathMtu - outerOverhead)

    // --- the plan floor -------------------------------------------------------
    //
    // Everything from here to [planFloorInnerMtu] is a Kotlin mirror of
    // `winn_protocol_experimental/winn3/carrier/sizing.go`. THE TWO FILES ARE A
    // PAIR: a change to a header cost, a class, or the clamps in one of them is
    // a change that must be made in the other in the same commit, or the two
    // sides of the create seam disagree about how wide the tunnel is. The Go
    // seam refuses a disagreement (`cmd/winn-datapath/winn3_create.go` refusal
    // 3, and `winn3_frame_test.go`'s TestTheFloorIsTheOnlyAcceptableInnerMTU),
    // so a drift shows up as "Android cannot start a session" :  loud, which is
    // the point. Do not make it quiet by relaxing the equality.
    //
    // The header costs below are `carrier/sizing.go`'s own constants and its
    // reasons for them are not repeated here; read them there.

    /** `carrier.ipv4HeaderBytes` :  IPv4 with no options. */
    const val IPV4_HEADER_BYTES = 20

    /** `carrier.ipv6HeaderBytes` :  the fixed IPv6 header, no extension headers. */
    const val IPV6_HEADER_BYTES = 40

    /** `carrier.udpHeaderBytes`. */
    const val UDP_HEADER_BYTES = 8

    /**
     * `carrier.tcpHeaderBytes` :  20 fixed plus 12 for the RFC 7323 timestamps
     * option, which Android negotiates by default. The 12 is the common case,
     * not a safety margin.
     */
    const val TCP_HEADER_BYTES = 20 + 12

    /** `carrier.tlsRecordBytes` :  TLS 1.3: 5 header, 1 inner content type, 16 tag. */
    const val TLS_RECORD_BYTES = 5 + 1 + 16

    /** `carrier.LengthRecordOverhead` :  §4.2's sealed length: AEAD(k_len, n_i, uint16). */
    const val LENGTH_RECORD_OVERHEAD = 2 + 16

    /**
     * `session.MessageFloor()` :  `core.TransportOverhead() + frameHeaderSize`.
     *
     * Numerically equal to [OVERHEAD] and equal to it by construction rather
     * than by coincidence: `tun.Overhead()` is the same sum. Named separately
     * because it is the lower clamp of `session.MaxMessageSizeForPath`, which is
     * a different role from "the bytes a message costs".
     */
    const val MESSAGE_FLOOR = OVERHEAD

    /** `core.MaxTransportPayload` :  the upper clamp of `MaxMessageSizeForPath`. */
    const val MAX_TRANSPORT_PAYLOAD = 65535

    /**
     * The carrier class names that cross the create document, which are
     * `carrier.Class.String()`'s own values.
     *
     * `cmd/winn-datapath` resolves them with `winn3ClassNamed`, which refuses
     * anything else rather than charging it a default, so this host refuses the
     * same set. A silently-charged unknown class is a floor computed for a
     * carrier nobody named.
     */
    val CARRIER_CLASSES = listOf("udp", "tcp", "tls")

    /**
     * `carrier.Overhead(class, family)` :  the bytes a carrier of this class and
     * family wraps around one Winn3 message, down to the IP header.
     *
     * @param ipv4 false means IPv6, which is the more expensive header. An
     *   unknown family is not representable here: `carrier.Overhead` charges
     *   `FamilyUnknown` the IPv6 cost and [planFloorMessageSize] takes the
     *   minimum over BOTH families anyway, so the conservative case is always
     *   included.
     * @throws IllegalArgumentException for a class name this host does not know.
     */
    fun carrierOverhead(carrierClass: String, ipv4: Boolean): Int {
        val ip = if (ipv4) IPV4_HEADER_BYTES else IPV6_HEADER_BYTES
        return when (carrierClass.trim()) {
            "udp" -> ip + UDP_HEADER_BYTES
            "tcp" -> ip + TCP_HEADER_BYTES + LENGTH_RECORD_OVERHEAD
            "tls" -> ip + TCP_HEADER_BYTES + TLS_RECORD_BYTES + LENGTH_RECORD_OVERHEAD
            else -> throw IllegalArgumentException(
                "unknown carrier class \"$carrierClass\"; use ${CARRIER_CLASSES.joinToString()}. " +
                    "cmd/winn-datapath refuses the same name rather than charging it a default, " +
                    "because a floor computed over a class nobody named is a floor that " +
                    "guarantees nothing"
            )
        }
    }

    /** `session.MaxMessageSizeForPath(pathMTU, carrierOverhead)`, clamps included. */
    fun maxMessageSizeForPath(pathMtu: Int, carrierOverhead: Int): Int {
        val n = pathMtu - carrierOverhead
        if (n < MESSAGE_FLOOR) return MESSAGE_FLOOR
        if (n > MAX_TRANSPORT_PAYLOAD) return MAX_TRANSPORT_PAYLOAD
        return n
    }

    /**
     * `carrier.Floor(pathMTU, classes...)` :  the NARROWEST MaxMessageSize across
     * every class the session may migrate to, across BOTH address families.
     *
     * The minimum over the plan and not over the dialled carrier, because that
     * is the whole content of the number: size to the class in use and the first
     * failover black-holes every full-size flow while the tunnel still reads
     * "up", small packets keep working, and the report arrives from somewhere
     * nobody can attach a debugger. Since the answer to a censor who blocks UDP
     * is precisely to fail over, that is a likely failure and not an exotic one.
     *
     * Both families, because a migration can change family as easily as class :
     * a gateway reachable over both, or a handset moving from a v4-only cellular
     * network to a v6-only one. A floor computed for the family in use is the
     * same bug one layer along.
     *
     * @throws IllegalArgumentException on an empty plan or an unknown class.
     *   Empty is refused rather than charged the worst case, matching
     *   `driver.NewSizing`: a host that forgot to name its plan has a bug that a
     *   silently conservative number would hide until the first migration.
     */
    fun planFloorMessageSize(pathMtu: Int, carrierClasses: List<String>): Int {
        require(carrierClasses.isNotEmpty()) {
            "a migration plan must name the carrier classes the session may escalate to"
        }
        var best = 0
        for (carrierClass in carrierClasses) {
            for (ipv4 in listOf(true, false)) {
                val n = maxMessageSizeForPath(pathMtu, carrierOverhead(carrierClass, ipv4))
                if (best == 0 || n < best) best = n
            }
        }
        return best
    }

    /**
     * `driver.NewSizing(pathMTU, classes...).InnerMTU` :  the tun interface MTU
     * §4.2 pins the host to, and the ONLY value the create seam accepts.
     *
     * This is what [WinnV3EngineConfig] requires `inner_mtu` to equal and what
     * [WinnV3Posture.bootstrap] and [WinnV3Posture.promotion] should both be
     * given. `innerMtuForPath` is not a substitute for it and never was.
     */
    fun planFloorInnerMtu(pathMtu: Int, carrierClasses: List<String>): Int =
        innerMtu(planFloorMessageSize(pathMtu, carrierClasses))

    /**
     * `carrier.NewPlanFloor(...).InnerIPv6` :  whether the plan floor, not the
     * dialled carrier, can carry inner IPv6.
     *
     * Computed for the NARROWEST class for the same reason the message floor is:
     * a tunnel that carried inner IPv6 until it failed over and then black-holed
     * every full-size v6 packet is the original trap wearing a v6 hat.
     */
    fun planCarriesInnerIpv6(pathMtu: Int, carrierClasses: List<String>): Boolean =
        planFloorInnerMtu(pathMtu, carrierClasses) >= IPV6_MIN_LINK_MTU

    /** `winn3/tun.MinCarrierMessageForIPv6()` :  1309. */
    fun minCarrierMessageForIpv6(): Int = carrierMessageFor(IPV6_MIN_LINK_MTU)

    /**
     * Whether the plan floor can carry inner IPv6 at all.
     *
     * False is common and is not a defect: §2.3 records that at a 1280-byte
     * outer path inner IPv6 is impossible for ANY tunnel.
     */
    fun carriesInnerIpv6(carrierMaxMessage: Int): Boolean =
        innerMtu(carrierMaxMessage) >= IPV6_MIN_LINK_MTU

    /**
     * The worked examples from `winn3/tun/params.go`'s and
     * `winn3/carrier/sizing.go`'s own doc comments, asserted rather than
     * trusted. Called from a unit test and from the on-device posture harness;
     * if the Go side changes [OVERHEAD] or a header cost this fails in Kotlin
     * instead of black-holing every full-size flow on a handset in Myanmar.
     *
     * The last three are the plan floor, and they are the ones that matter: the
     * 84-byte gap between `InnerMTUForPath(1500,28)` and
     * `planFloorInnerMtu(1500, [udp,tcp,tls])` is exactly the defect the create
     * seam refuses, and it is the difference between the dialled UDP/IPv4
     * carrier's overhead (28) and the plan's worst case, TLS over IPv6 (112).
     */
    fun assertsAgreeWithGo(): List<String> = buildList {
        check(innerMtuForPath(1500, UDP_OVER_IPV4_OVERHEAD) == 1443) {
            "InnerMTUForPath(1500, 28) must be 1443"
        }
        check(innerMtuForPath(1500, UDP_OVER_IPV6_OVERHEAD) == 1423) {
            "InnerMTUForPath(1500, 48) must be 1423"
        }
        check(innerMtuForPath(1280, UDP_OVER_IPV6_OVERHEAD) == 1203) {
            "InnerMTUForPath(1280, 48) must be 1203"
        }
        check(minCarrierMessageForIpv6() == 1309) {
            "MinCarrierMessageForIPv6() must be 1309"
        }
        // driver.Sizing's own doc comment: "Floor(1280, UDP, TCP, TLS) is 1168
        // against 1252 for a dialled UDP/IPv4 carrier :  84 bytes".
        check(planFloorMessageSize(1500, CARRIER_CLASSES) == 1388) {
            "Floor(1500, udp, tcp, tls) must be 1388"
        }
        check(planFloorInnerMtu(1500, CARRIER_CLASSES) == 1359) {
            "the plan floor inner MTU at a 1500-byte path must be 1359"
        }
        check(planFloorInnerMtu(1280, CARRIER_CLASSES) == 1139) {
            "the plan floor inner MTU at a 1280-byte path must be 1139"
        }
        check(planFloorMessageSize(1280, CARRIER_CLASSES) == 1168) {
            "Floor(1280, udp, tcp, tls) must be 1168"
        }
        add("InnerMTUForPath(1500,28)=1443")
        add("InnerMTUForPath(1500,48)=1423")
        add("InnerMTUForPath(1280,48)=1203")
        add("MinCarrierMessageForIPv6()=1309")
        add("Floor(1500,udp,tcp,tls)=1388 innerMTU=1359")
        add("Floor(1280,udp,tcp,tls)=1168 innerMTU=1139")
        add("the 84-byte gap: 1443 (dialled udp/v4) - 1359 (plan floor) = 84")
    }
}

/** An address on the inner interface. Always a host address; see [WinnV3Posture]. */
internal data class WinnV3Address(val address: String, val prefixLength: Int)

/** One route, as `VpnService.Builder.addRoute` takes it. */
internal data class WinnV3Route(val address: String, val prefixLength: Int)

/** Which of the two §4.1 postures this is. */
internal enum class WinnV3Stage { BOOTSTRAP, PROMOTED }

/**
 * The reason a staged start refused.
 *
 * §4.3 rule 1: *a start that WOULD be staged but cannot build a narrow
 * bootstrap must refuse to start, never fall back to installing the full
 * tunnel immediately.* Every one of these is a refusal and none of them has a
 * widening branch.
 */
internal class WinnV3PostureRefusal(message: String) : IllegalStateException(message)

/**
 * The sink [WinnV3Posture.applyTo] writes to.
 *
 * `VpnService.Builder` is not an interface and cannot be constructed off-device,
 * so the posture writes to this instead and the service supplies a four-line
 * adapter.
 */
internal interface WinnV3PostureSink {
    fun addAddress(address: String, prefixLength: Int)
    fun addRoute(address: String, prefixLength: Int)

    /**
     * Excludes a destination from the tunnel.
     *
     * Returns false when the platform has no such API. `Builder.excludeRoute`
     * arrived in API 33 and this app's `minSdk` is 24, so on most of the fleet
     * the answer is false and the exclusion is carried entirely by
     * `VpnService.protect()` :  see [WinnV3Posture.OUTER_EXCLUSION_NOTE].
     */
    fun excludeRoute(address: String, prefixLength: Int): Boolean

    fun setMtu(mtu: Int)
    fun addDnsServer(server: String)
    fun allowFamily(family: Int)
}

/**
 * Everything [WinnV3Posture.applyTo] actually asked for, in order.
 *
 * This is the "settings object it just built" that §4.3.1 says to verify, made
 * readable on a platform whose builder has no getters.
 */
internal class WinnV3PostureRecord(private val delegate: WinnV3PostureSink?) : WinnV3PostureSink {

    val addresses = mutableListOf<WinnV3Address>()
    val routes = mutableListOf<WinnV3Route>()
    val excludedRoutes = mutableListOf<WinnV3Route>()
    val refusedExclusions = mutableListOf<WinnV3Route>()

    /**
     * Exclusions the builder ACCEPTED and then lost to a later include.
     *
     * `VpnService.Builder.excludeRoute(prefix)` is `addRoute(prefix, RTN_THROW)`
     * on Android 13 and 14: one `mRoutes` list, and a private `addRoute` that
     * calls `findRouteIndexByDestination` and does `mRoutes.set(index, ...)`
     * when the destination is already present. An include therefore OVERWRITES
     * an exclusion that named the same prefix, silently and with no return
     * value to notice it by. Recording it keeps [verifyNarrow] honest.
     */
    val shadowedExclusions = mutableListOf<WinnV3Route>()
    val dnsServers = mutableListOf<String>()
    val families = mutableListOf<Int>()
    var mtu: Int? = null
        private set

    override fun addAddress(address: String, prefixLength: Int) {
        addresses += WinnV3Address(address, prefixLength)
        delegate?.addAddress(address, prefixLength)
    }

    override fun addRoute(address: String, prefixLength: Int) {
        val route = WinnV3Route(address, prefixLength)
        // Last write wins PER DESTINATION, because that is what the platform
        // does. See [shadowedExclusions]: the record must describe the builder
        // it wrapped, not the sequence of calls it was handed, or §4.3.1
        // verifies an intent the builder never held.
        val shadowed = excludedRoutes.filter { sameDestination(it, route) }
        if (shadowed.isNotEmpty()) {
            excludedRoutes.removeAll { sameDestination(it, route) }
            shadowedExclusions += shadowed
        }
        routes.removeAll { sameDestination(it, route) }
        routes += route
        delegate?.addRoute(address, prefixLength)
    }

    override fun excludeRoute(address: String, prefixLength: Int): Boolean {
        val route = WinnV3Route(address, prefixLength)
        val applied = delegate?.excludeRoute(address, prefixLength) ?: true
        if (applied) {
            routes.removeAll { sameDestination(it, route) }
            excludedRoutes.removeAll { sameDestination(it, route) }
            excludedRoutes += route
        } else {
            refusedExclusions += route
        }
        return applied
    }

    /**
     * Destination equality the way `RouteInfo` computes it.
     *
     * `IpPrefix` masks the address to the prefix length in its constructor, so
     * `10.0.0.7/24` and `10.0.0.0/24` are ONE destination to the platform. A
     * plain string compare would miss that and report an exclusion the builder
     * has already dropped. IPv4 is normalized numerically; anything this parser
     * does not recognise as a dotted quad falls back to a trimmed text compare,
     * which is exact for the `::`/0 sink and the literals this layer installs.
     */
    private fun sameDestination(left: WinnV3Route, right: WinnV3Route): Boolean {
        if (left.prefixLength != right.prefixLength) return false
        val a = WinnV3Resolvers.ipv4Value(left.address)
        val b = WinnV3Resolvers.ipv4Value(right.address)
        if (a != null && b != null) {
            val mask =
                if (left.prefixLength <= 0) 0L
                else (0xFFFFFFFFL shl (32 - left.prefixLength)) and 0xFFFFFFFFL
            return (a and mask) == (b and mask)
        }
        return left.address.trim().equals(right.address.trim(), ignoreCase = true)
    }

    override fun setMtu(mtu: Int) {
        this.mtu = mtu
        delegate?.setMtu(mtu)
    }

    override fun addDnsServer(server: String) {
        dnsServers += server
        delegate?.addDnsServer(server)
    }

    override fun allowFamily(family: Int) {
        families += family
        delegate?.allowFamily(family)
    }

    /** True when a default route of either family was asked for. */
    fun hasDefaultRoute(): Boolean = routes.any { it.prefixLength == 0 }

    /** True when anything IPv6 was asked for :  an address, a route, or a resolver. */
    fun hasAnyIpv6(): Boolean =
        addresses.any { it.address.contains(':') } ||
            routes.any { it.address.contains(':') } ||
            dnsServers.any { it.contains(':') } ||
            families.contains(WinnV3Posture.AF_INET6)

    fun describe(): String = buildString {
        append("addresses=").append(addresses.joinToString { "${it.address}/${it.prefixLength}" })
        append(" mtu=").append(mtu)
        append(" routes=").append(routes.joinToString { "${it.address}/${it.prefixLength}" })
        append(" excluded=").append(excludedRoutes.joinToString { "${it.address}/${it.prefixLength}" })
        if (shadowedExclusions.isNotEmpty()) {
            append(" shadowed_exclusions=")
                .append(shadowedExclusions.joinToString { "${it.address}/${it.prefixLength}" })
        }
        append(" dns=").append(dnsServers.joinToString())
        append(" families=").append(families.joinToString())
    }
}

/**
 * §4.4 :  which resolvers a winn/3 STANDALONE session may install, DERIVED.
 *
 * ## The sibling defect this closes
 *
 * `VpnTunnelService` read the resolver out of the AmneziaWG document and
 * defaulted it:
 *
 *     val dnsServer = parseConfigValue(awgConfig, "DNS") ?: "10.8.1.1"
 *
 * and handed it straight to [WinnV3SessionPlan.from] as a v3 resolver.
 * `10.8.1.1` is an address in the **v1 inner space**: a standalone v3 session
 * shares no address space with the relay, and the winn/3 tun layer drops what
 * does not match its own assignment. So the promoted posture pointed every
 * name lookup at an address inside a tunnel that discards it :  and if the
 * AmneziaWG document happened to carry a public resolver instead, at an address
 * the censor can read in the clear.
 *
 * [WinnV3Posture.promotion] already refused an EMPTY resolver list. Nothing
 * asked whether a NON-empty one was inner, which is the half a served
 * configuration makes reachable.
 *
 * ## The predicate is derived, never transported
 *
 * `windows/runner/winn3_posture.h` carries `dns_servers_are_inner` as "the
 * host's own declaration". Windows can take that from a local `[winn3]` file
 * because somebody with the machine wrote it; Android has no such file, and the
 * only document that reaches this host is the unsigned `[winn]` section the hub
 * serves. `winn3/conform` pins `dns`, `dns_are_inner`, `dns_servers` and
 * `resolvers` ABSENT from that section, and states why in one line: a
 * transported boolean asserting "this resolver is inside the tunnel" is the
 * leak wearing a flag.
 *
 * So this object derives it from the two inner facts the signed descriptor
 * carries :  `inner_v4` and `inner_router_v4` :  and from nothing else. The rules
 * are the same five Apple's `WinsWinn3Resolvers` applies, in the same order,
 * because the two hosts are answering the same question about the same
 * document.
 *
 * Free of Android imports, like everything else in this file, so it runs on a
 * plain JVM.
 */
internal object WinnV3Resolvers {

    /**
     * Why this host cannot derive that [resolver] is inside THIS session's
     * tunnel, or null when it can.
     *
     * @param innerAddress `[winn] inner_v4`, the session's own assignment.
     * @param innerNextHop `[winn] inner_router_v4`, documented as the inner
     *   next hop *for PMTU signals only*.
     * @param innerResolver `[winn] inner_resolver_v4`, the gateway's inner DNS
     *   responder address off the SAME ML-DSA-65-signed descriptor. Defaults to
     *   empty, which is what every descriptor in existence carries and what
     *   every caller predating the field supplies :  so the default reproduces
     *   this function's behaviour exactly as it was.
     */
    fun notInnerReason(
        resolver: String,
        innerAddress: String,
        innerNextHop: String,
        innerResolver: String = "",
    ): String? {
        val value = resolver.trim()
        if (value.isEmpty()) return "it is empty"
        val candidate = ipv4Value(value)
            ?: return "$value is not an IPv4 literal, and a resolver that must itself be " +
                "resolved is the lookup outside the tunnel this layer exists to prevent"
        // THE ONE CLAUSE THAT NARROWED, AND EXACTLY HOW FAR.
        //
        // Was: "is the next hop" -> refuse. Is now: "is the next hop AND the
        // signed descriptor names no resolver there" -> refuse. Every other
        // clause below is untouched and still applies to the descriptor's own
        // value: a hostname, this device's own assignment, a public literal and
        // anything outside the assignment's /24 stay refused even when the
        // descriptor names them, because the descriptor is a signed FACT about
        // where the gateway listens, not permission to skip a check.
        //
        // The old ground -- "answers no queries" -- was true of every gateway
        // that has ever run and stops being true for one running
        // `cmd/winn3-gateway -resolver`. That responder answers at the gateway's
        // own `-inner-v4`, which IS this client's next hop, because winn3/tun's
        // outbound validator requires a reply's source to equal the endpoint's
        // own assignment; a resolver at a second inner address cannot answer
        // through the tunnel at all. Apple's `WinsWinn3Resolvers.notInnerReason`
        // narrows the same clause the same way, in the same position.
        //
        // Compared as PARSED VALUES, not as text: `10.64.0.1` and `10.64.000.1`
        // are one address, and a string compare would refuse the operator's own
        // signed resolver while quoting a value that looks identical to it.
        val nextHop = innerNextHop.trim()
        if (nextHop.isNotEmpty() && ipv4Value(nextHop) == candidate) {
            val advertised = innerResolver.trim()
            if (advertised.isEmpty() || ipv4Value(advertised) != candidate) {
                return "$value is the inner next hop, which is documented as carrying PMTU " +
                    "signals only and answers no queries; naming it would trade a leak for " +
                    "total name-resolution failure. The signed descriptor does not name a " +
                    "resolver there :  it carries inner_resolver_v4 = \"$advertised\" :  so this " +
                    "host has no signed fact saying anything listens on that address"
            }
        }
        val assignment = ipv4Value(innerAddress)
            ?: return "$value cannot be shown to be inner because the session's inner_v4 " +
                "assignment carries no IPv4 literal to derive an inner space from"
        if (candidate == assignment) {
            return "$value is this session's own inner_v4 assignment, which is this device; " +
                "nothing answers there"
        }
        if (isPublicIpv4Literal(value)) {
            return "$value is a PUBLIC resolver. It is reachable off-tunnel by construction, so " +
                "it resolves over the censored path the moment the tunnel drops"
        }
        if (!sameInnerBlock(candidate, assignment)) {
            return "$value is outside the /24 around this session's inner_v4 assignment " +
                "($innerAddress), so this host cannot derive that it is reachable only through " +
                "THIS tunnel :  a resolver in the v1 AmneziaWG inner space is dropped by the " +
                "winn/3 tun layer, not carried"
        }
        return null
    }

    /** The candidates that survive the derivation. */
    fun inner(
        candidates: List<String>,
        innerAddress: String,
        innerNextHop: String,
        innerResolver: String = "",
    ): List<String> = candidates
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .filter { notInnerReason(it, innerAddress, innerNextHop, innerResolver) == null }

    /**
     * Why a standalone session may not promote, or null.
     *
     * Two clauses, in `winn3_posture.h`'s order and for its stated reasons. The
     * second is a claim about the WHOLE LIST rather than about each member, and
     * that is deliberate: `dns_servers_are_inner` is ONE boolean over the whole
     * of `dns_servers`, and `VpnService.Builder.addDnsServer` hands every entry
     * to the platform resolver, which :  not this code :  picks which one answers.
     * Filtering a mixed list down and promoting on the survivors would leave a
     * public resolver installed beside an inner one and call it inner.
     */
    fun promotionRefusalReason(
        candidates: List<String>,
        innerAddress: String,
        innerNextHop: String,
        innerResolver: String = "",
    ): String? {
        val offered = candidates.map { it.trim() }.filter { it.isNotEmpty() }
        if (offered.isEmpty()) {
            return "a standalone winn/3 session has no resolver it can justify. This posture " +
                "takes the default route, and a host that widens its routes without also " +
                "moving name resolution leaves every DNS query going to the resolver it was " +
                "handed by the network it is hiding from :  in the clear, over the physical " +
                "interface, while the tunnel reports carrying. There is no v3 resolver " +
                "anywhere in the system today: the signed gateway descriptor's closed field " +
                "set carries none, and the served [winn] section deliberately has no dns key " +
                "because it is unsigned. The route set and the resolver set have to move " +
                "together or neither may move"
        }
        val rejected =
            offered.mapNotNull { notInnerReason(it, innerAddress, innerNextHop, innerResolver) }
        if (rejected.isNotEmpty()) {
            return "a standalone winn/3 session cannot install the ${offered.size} resolver(s) " +
                "this configuration offers, because this host cannot DERIVE that every one of " +
                "them is reachable only through the tunnel: ${rejected.joinToString("; ")}. " +
                "They come from the AmneziaWG [Interface] DNS line, which belongs to a session " +
                "this one shares nothing with. The declaration is derived and never " +
                "transported :  a boolean on the wire asserting a resolver is inside the tunnel " +
                "is the leak wearing a flag"
        }
        return null
    }

    /** `dns_are_inner`, derived: at least one resolver, and every one derivable. */
    fun areInner(
        candidates: List<String>,
        innerAddress: String,
        innerNextHop: String,
        innerResolver: String = "",
    ): Boolean =
        promotionRefusalReason(candidates, innerAddress, innerNextHop, innerResolver) == null

    /**
     * The same ranges `lib/main.dart:_isPublicIpv4Literal` and Apple's
     * `WinsWinn3Resolvers.isPublicIPv4Literal` exclude, so no two hosts can
     * disagree about which literals are the ones that actually ship.
     */
    fun isPublicIpv4Literal(value: String): Boolean {
        val parsed = ipv4Value(value) ?: return false
        val first = (parsed shr 24) and 0xff
        val second = (parsed shr 16) and 0xff
        if (first == 10L || first == 127L || first == 0L) return false
        if (first == 100L && second in 64..127) return false
        if (first == 169L && second == 254L) return false
        if (first == 172L && second in 16..31) return false
        if (first == 192L && second == 168L) return false
        if (first >= 224L) return false
        return true
    }

    /** Two addresses in the same /24. */
    fun sameInnerBlock(a: Long, b: Long): Boolean = (a and 0xFFFFFF00L) == (b and 0xFFFFFF00L)

    /**
     * A dotted quad as an unsigned 32-bit value in a [Long], or null.
     *
     * Hand-rolled rather than `InetAddress.getByName`, which would perform a
     * NAME LOOKUP for anything that is not a literal :  inside the one code path
     * whose whole subject is not leaking lookups.
     */
    fun ipv4Value(text: String): Long? {
        val parts = text.trim().split('.')
        if (parts.size != 4) return null
        var result = 0L
        for (part in parts) {
            if (part.isEmpty() || part.length > 3 || part.any { it !in '0'..'9' }) return null
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            result = (result shl 8) or octet.toLong()
        }
        return result
    }
}

/**
 * One of the two §4.1 postures, built and then verified.
 *
 * Construct with [bootstrap] or [promotion]; the constructor is private so
 * there is no way to assemble a posture that skipped its own checks.
 */
internal class WinnV3Posture private constructor(
    val stage: WinnV3Stage,
    val addresses: List<WinnV3Address>,
    val mtu: Int,
    val routes: List<WinnV3Route>,
    val excludedRoutes: List<WinnV3Route>,
    val dnsServers: List<String>,
    val families: List<Int>,
) {

    companion object {
        /** `OsConstants.AF_INET`, as a plain int so this file stays portable. */
        const val AF_INET = 2

        /** `OsConstants.AF_INET6`. */
        const val AF_INET6 = 10

        /**
         * §4.1's last row, on Android.
         *
         * > outer-transport exclusion route | **present from the first posture**
         *
         * On Android the exclusion is NOT primarily a route. `VpnService.protect()`
         * marks the kernel socket :  netd sets the bypass-VPN `SO_MARK` on the
         * `struct sock` :  so route lookups for that socket skip the VPN rules
         * before any route this builder installs is consulted. That is a
         * STRONGER guarantee than a route-based exclusion, which a later, more
         * specific route can shadow, and it is established BEFORE the first
         * posture exists because the socket is opened and protected before
         * `establish()` is called at all. See [WinnUnderlaySocket].
         *
         * `Builder.excludeRoute` (API 33+) is applied as well when the platform
         * has it, as defence in depth against a build that ever loses the
         * protect() ordering. It is not a substitute: a start whose socket was
         * not protected is refused by [WinnTunnelBridge] regardless of what
         * routes were installed.
         */
        const val OUTER_EXCLUSION_NOTE =
            "outer-transport exclusion on Android is VpnService.protect() on the carrier " +
                "socket (SO_MARK on the struct sock, consulted before the tunnel's routes); " +
                "Builder.excludeRoute is applied additionally on API 33+."

        /**
         * BOOTSTRAP :  §4.1's first table. Installed before any user traffic is
         * possible.
         *
         * @param innerAddress the address the gateway assigned. A HOST address:
         *   §4.1 requires prefix length /32 (or /128), because *the tun layer
         *   validates against the address, not the prefix; a wider prefix on the
         *   interface invites the host to originate from an address the tunnel
         *   will drop.*
         * @param innerMtu **exactly** `Tunnel.InnerMTU()`. Not the path MTU, not
         *   the carrier's message size, and not the MTU of the class that was
         *   dialled :  the floor over every class the session may fail over to.
         * @param innerNextHop the single included route: enough to prove the
         *   datapath, not enough to capture anything.
         * @param outerTransportExclusion the gateway endpoint the carrier dials.
         */
        @Throws(WinnV3PostureRefusal::class)
        fun bootstrap(
            innerAddress: String,
            innerMtu: Int,
            innerNextHop: String,
            outerTransportExclusion: WinnV3Route?,
        ): WinnV3Posture {
            refuseUnless(innerAddress.isNotBlank()) { "bootstrap has no assigned inner address" }
            refuseUnless(!innerAddress.contains(':')) {
                "bootstrap inner address $innerAddress is IPv6; §4.1 forbids IPv6 in the " +
                    "bootstrap posture, so an IPv6-only assignment cannot be staged"
            }
            refuseUnless(innerNextHop.isNotBlank()) { "bootstrap has no inner next hop to route to" }
            refuseUnless(!innerNextHop.contains(':')) {
                "bootstrap inner next hop $innerNextHop is IPv6; §4.1 forbids IPv6 in the " +
                    "bootstrap posture"
            }
            refuseUnless(innerMtu >= WinnV3Sizing.MIN_INNER_MTU_V4) {
                "inner MTU $innerMtu is below the ${WinnV3Sizing.MIN_INNER_MTU_V4}-byte IPv4 " +
                    "floor; winn3/tun refuses to construct this tunnel and so does this host"
            }
            refuseUnless(outerTransportExclusion == null || !outerTransportExclusion.address.contains(':')) {
                "the outer-transport exclusion is IPv6; the bootstrap posture installs no IPv6 " +
                    "and an IPv6 exclusion there would be inert"
            }

            return WinnV3Posture(
                stage = WinnV3Stage.BOOTSTRAP,
                // /32 exactly. §4.1: the tun layer validates against the address.
                addresses = listOf(WinnV3Address(innerAddress, 32)),
                mtu = innerMtu,
                // At most ONE route, and it is the inner next hop.
                routes = listOf(WinnV3Route(innerNextHop, 32)),
                excludedRoutes = listOfNotNull(outerTransportExclusion),
                // No DNS. §4.4: a resolver pointed into an unproven tunnel makes
                // EVERY name lookup on the machine fail, including the app's own
                // control-plane fetch, so a failed bootstrap becomes a machine
                // that cannot recover without manual intervention.
                dnsServers = emptyList(),
                // IPv4 only. No IPv6 anything.
                families = listOf(AF_INET),
            )
        }

        /**
         * PROMOTION :  §4.1's second posture: *default route, IPv6, DNS, and the
         * full route set, in one call.*
         *
         * Installed **only** after [WinnV3PromotionGate] says the datapath is
         * proven. This function does not check that; it cannot, because it does
         * not own the counters. [WinnV3StagedStart] is the one place the two
         * meet, and it is the only caller.
         *
         * @param innerIpv6Address the inner IPv6 address, or null. Null is the
         *   right answer whenever the plan floor cannot carry inner IPv6
         *   (`InnerMTU < 1280`), and passing one anyway is refused rather than
         *   installed: an IPv6 route on a link narrower than RFC 8200's floor is
         *   a black hole, because IPv6 routers do not fragment.
         * @param ipv6SinkAddress the fail-closed IPv6 sink this platform already
         *   requires of its other tunnel modes, used when there is no inner IPv6
         *   to offer. Together with a `::/0` route it blackholes host IPv6
         *   instead of leaking it beside a v4-only tunnel.
         */
        @Throws(WinnV3PostureRefusal::class)
        @Suppress("LongParameterList")
        fun promotion(
            innerAddress: String,
            innerMtu: Int,
            routes: List<WinnV3Route>,
            dnsServers: List<String>,
            innerNextHop: String,
            outerTransportExclusion: WinnV3Route?,
            innerIpv6Address: String? = null,
            ipv6SinkAddress: String? = null,
            innerResolver: String = "",
        ): WinnV3Posture {
            refuseUnless(innerAddress.isNotBlank()) { "promotion has no assigned inner address" }
            refuseUnless(innerMtu >= WinnV3Sizing.MIN_INNER_MTU_V4) {
                "inner MTU $innerMtu is below the ${WinnV3Sizing.MIN_INNER_MTU_V4}-byte IPv4 floor"
            }
            refuseUnless(routes.isNotEmpty()) {
                "promotion installs no routes; a promotion that captures nothing is a tunnel " +
                    "the user believes is carrying their traffic and is not"
            }
            refuseUnless(routes.any { it.address == "0.0.0.0" && it.prefixLength == 0 }) {
                "standalone winn/3 promotion does not install the IPv4 default route. " +
                    "The app is a full-tunnel VPN, and widening DNS without routing every " +
                    "IPv4 destination through the tunnel can send its inner resolver toward " +
                    "the physical network while the app reports Connected"
            }
            refuseUnless(dnsServers.isNotEmpty()) {
                "promotion installs no resolvers. §4.4 requires the resolvers to be INNER " +
                    "addresses reachable only through the tunnel, so that a subsequent tunnel " +
                    "failure produces resolution failure rather than resolution over the " +
                    "censored path; installing none leaves the host's own resolvers in place, " +
                    "which is the opposite"
            }
            // AND THAT THEY ARE INNER, WHICH IS THE HALF THAT WAS MISSING.
            //
            // The clause above has always been here and it is not enough: it
            // asks whether a resolver was named, never whether the named one is
            // reachable ONLY through this tunnel. `VpnTunnelService` handed this
            // function `parseConfigValue(awgConfig, "DNS") ?: "10.8.1.1"` :  the
            // AmneziaWG document's resolver, defaulted into the v1 inner space
            // :  so a standalone session promoted with a resolver its own tun
            // layer drops, or, when the served document carried a public one,
            // with an address the censor reads in the clear.
            //
            // DERIVED HERE, NOT DECLARED BY A CALLER. `winn3_posture.h` takes
            // `dns_servers_are_inner` as an input because a local `[winn3]` file
            // on a desktop is written by somebody with the machine. Android has
            // no such file: the only document reaching this host is the unsigned
            // `[winn]` section, and a transported boolean asserting "this
            // resolver is inside the tunnel" is the leak wearing a flag. So the
            // predicate is computed from the two inner facts the SIGNED
            // descriptor carries and from nothing else.
            // `innerResolver` is the SIGNED descriptor's `inner_resolver_v4` and
            // it is passed, never consulted here: the derivation stays in one
            // place, and this builder must not grow a second opinion about which
            // resolver is inner. Empty on every configuration served today.
            WinnV3Resolvers.promotionRefusalReason(
                dnsServers, innerAddress, innerNextHop, innerResolver,
            )
                ?.let { throw WinnV3PostureRefusal(it) }
            if (innerIpv6Address != null) {
                refuseUnless(innerMtu >= WinnV3Sizing.IPV6_MIN_LINK_MTU) {
                    "inner IPv6 was requested at an inner MTU of $innerMtu, below RFC 8200's " +
                        "${WinnV3Sizing.IPV6_MIN_LINK_MTU}-byte link floor. IPv6 routers do not " +
                        "fragment, so this is a black hole, not a narrow link. winn3/tun refuses " +
                        "the same configuration"
                }
                refuseUnless(innerIpv6Address.contains(':')) {
                    "inner IPv6 address $innerIpv6Address is not an IPv6 address"
                }
            }
            // The sink is an IPv6 ADDRESS and is subject to the SAME kernel floor the
            // inner one is, even though it carries no traffic: a Linux kernel refuses
            // to attach any IPv6 address to a device below RFC 8200's 1280-byte minimum
            // link MTU (`ipv6_add_dev()` returns -EINVAL; Android surfaces it as
            // "IllegalArgumentException: Cannot set address" out of establish()). So a
            // sink on a narrow link would fail exactly like inner IPv6 would :  a plan
            // that built, bootstrapped, handshaked, reached gate=carrying and only then
            // could not promote. Guard it the same way: impossible here, not merely
            // handled downstream. The threshold is `inner_mtu`, which IS the plan floor,
            // so this is the plan-aware form and needs no second Floor call.
            if (ipv6SinkAddress != null) {
                refuseUnless(innerMtu >= WinnV3Sizing.IPV6_MIN_LINK_MTU) {
                    "the IPv6 fail-closed sink $ipv6SinkAddress was requested at an inner MTU " +
                        "of $innerMtu, below RFC 8200's ${WinnV3Sizing.IPV6_MIN_LINK_MTU}-byte " +
                        "link floor. The sink is an IPv6 address even though it carries no " +
                        "traffic, and no Linux kernel attaches one to a device below that " +
                        "floor (\"Invalid argument\"; Android reports \"Cannot set address\" " +
                        "out of VpnService.Builder.establish()). winn3/tun refuses the same " +
                        "configuration"
                }
            }
            // Exactly one of the two IPv6 shapes, and never neither: leaving host
            // IPv6 on the physical interface beside a promoted v4 tunnel is the
            // leak ANDROID_IPV6_FAIL_CLOSED_FIX_AND_KILL_SWITCH_SCOPE_20260807.md
            // closed, and a v3 promotion must not reopen it.
            refuseUnless(innerIpv6Address != null || ipv6SinkAddress != null) {
                "promotion carries neither inner IPv6 nor an IPv6 fail-closed sink. Host IPv6 " +
                    "would keep egressing outside the tunnel while the app reports Connected, " +
                    "which on this threat model is an attributable session"
            }

            val addresses = mutableListOf(WinnV3Address(innerAddress, 32))
            val allRoutes = routes.toMutableList()
            val families = mutableListOf(AF_INET, AF_INET6)

            if (innerIpv6Address != null) {
                addresses += WinnV3Address(innerIpv6Address, 128)
                if (allRoutes.none { it.address == "::" && it.prefixLength == 0 }) {
                    allRoutes += WinnV3Route("::", 0)
                }
            } else {
                addresses += WinnV3Address(requireNotNull(ipv6SinkAddress), 128)
                if (allRoutes.none { it.address == "::" && it.prefixLength == 0 }) {
                    allRoutes += WinnV3Route("::", 0)
                }
            }

            return WinnV3Posture(
                stage = WinnV3Stage.PROMOTED,
                addresses = addresses,
                mtu = innerMtu,
                routes = allRoutes,
                excludedRoutes = listOfNotNull(outerTransportExclusion),
                dnsServers = dnsServers.toList(),
                families = families,
            )
        }

        /**
         * §4.3.1 in one function: verify the RECORD, not the intent.
         *
         * Called after [applyTo] has run against the real builder and before
         * `establish()`. A bootstrap that fails any clause here has already
         * written those calls into the builder, so the only correct response is
         * to throw the builder away and refuse :  which is exactly what the
         * caller does, because there is no widening branch anywhere below.
         */
        @Throws(WinnV3PostureRefusal::class)
        fun verifyNarrow(record: WinnV3PostureRecord, requireExclusion: Boolean) {
            refuseUnless(record.addresses.size == 1) {
                "bootstrap asked for ${record.addresses.size} addresses; §4.1 allows exactly one"
            }
            val only = record.addresses.first()
            refuseUnless(only.prefixLength == 32) {
                "bootstrap address ${only.address} was installed at /${only.prefixLength}; " +
                    "§4.1 requires /32 because a wider prefix invites the host to originate " +
                    "from an address the tunnel will drop"
            }
            refuseUnless(record.routes.size <= 1) {
                "bootstrap installed ${record.routes.size} routes; §4.1 allows at most one"
            }
            refuseUnless(!record.hasDefaultRoute()) {
                "bootstrap installed a default route. §4.1 requires the host to keep its own; " +
                    "a default route on an unproven datapath captures the user's traffic before " +
                    "anything has shown the tunnel can carry it"
            }
            refuseUnless(!record.hasAnyIpv6()) {
                "bootstrap installed IPv6 (${record.describe()}). §4.1 requires IPv6 settings " +
                    "absent so the host keeps its own IPv6"
            }
            refuseUnless(record.dnsServers.isEmpty()) {
                "bootstrap installed ${record.dnsServers.size} resolvers. §4.4: name resolution " +
                    "must never depend on an unproven tunnel, and a resolver pointed into one " +
                    "makes every lookup on the machine fail :  including the app's own " +
                    "control-plane fetch"
            }
            refuseUnless(record.mtu != null) { "bootstrap set no MTU" }
            if (requireExclusion) {
                refuseUnless(record.excludedRoutes.isNotEmpty()) {
                    "bootstrap installed no outer-transport exclusion route on a platform that " +
                        "supports one. §4.1 requires it present from the first posture so the " +
                        "carrier's own socket can never be captured by the later promotion"
                }
                refuseUnless(record.shadowedExclusions.isEmpty()) {
                    "bootstrap asked for the exclusion " +
                        record.shadowedExclusions.joinToString {
                            "${it.address}/${it.prefixLength}"
                        } +
                        " and then installed an include on the same destination, which on " +
                        "Android replaces it in the builder's one route list " +
                        "(Builder.excludeRoute is addRoute(prefix, RTN_THROW), and the private " +
                        "addRoute does mRoutes.set on a destination match). The builder holds " +
                        "no exclusion for that prefix, so the carrier's own socket would be " +
                        "captured by the promotion this posture precedes"
                }
            }
        }

        /**
         * Makes an already VERIFIED bootstrap builder fail closed: both default
         * routes into the tun plus the IPv6 sink. Only for a start that replaces
         * something that was protecting the user (a live tunnel, a handover
         * block, a capture hold, an armed kill switch). The outer-transport
         * exclusion is a different destination and survives these includes.
         */
        fun applyFailClosedBootstrapCapture(sink: WinnV3PostureSink, ipv6SinkAddress: String) {
            sink.addRoute("0.0.0.0", 0)
            sink.addAddress(ipv6SinkAddress, 128)
            sink.addRoute("::", 0)
        }

        /**
         * §4.3.1 for the fail-closed bootstrap: verify the RECORD after
         * [applyFailClosedBootstrapCapture] ran through it. [verifyNarrow] has
         * already passed on the same record, so what may differ is exactly the
         * capture: both default routes and the IPv6 sink, still no resolver,
         * and the outer-transport exclusion still in force where the platform
         * has one. Anything else refuses, as [verifyNarrow] does.
         */
        @Throws(WinnV3PostureRefusal::class)
        fun verifyFailClosedBootstrap(
            record: WinnV3PostureRecord,
            ipv6SinkAddress: String,
            requireExclusion: Boolean,
        ) {
            refuseUnless(
                record.addresses.size == 2 &&
                    record.addresses.count {
                        it.address == ipv6SinkAddress && it.prefixLength == 128
                    } == 1,
            ) {
                "fail-closed bootstrap must hold the verified address and the IPv6 sink " +
                    "only (${record.describe()})"
            }
            refuseUnless(
                record.routes.any { it.address == "0.0.0.0" && it.prefixLength == 0 } &&
                    record.routes.any { it.address == "::" && it.prefixLength == 0 },
            ) {
                "fail-closed bootstrap must capture both families (${record.describe()})"
            }
            refuseUnless(record.routes.size <= 3) {
                "fail-closed bootstrap installed ${record.routes.size} routes; the verified " +
                    "route and the two default routes are the most it may hold"
            }
            refuseUnless(record.dnsServers.isEmpty()) {
                "fail-closed bootstrap installed ${record.dnsServers.size} resolvers. §4.4 " +
                    "still applies"
            }
            if (requireExclusion) {
                refuseUnless(
                    record.excludedRoutes.isNotEmpty() && record.shadowedExclusions.isEmpty(),
                ) {
                    "fail-closed bootstrap lost its outer-transport exclusion, so the " +
                        "carrier's own socket would be captured"
                }
            }
        }

        private inline fun refuseUnless(condition: Boolean, message: () -> String) {
            if (!condition) throw WinnV3PostureRefusal(message())
        }
    }

    /**
     * Writes this posture into [sink] and returns the record of what was
     * actually asked for.
     *
     * MTU is set FIRST and unconditionally. §4.2 is the obligation the whole
     * layer turns on :  *the host must set the tun interface MTU to exactly the
     * value `Tunnel.InnerMTU()` publishes* :  and setting it first means no early
     * return can leave a posture whose MTU was never applied.
     */
    fun applyTo(sink: WinnV3PostureSink?): WinnV3PostureRecord {
        val record = WinnV3PostureRecord(sink)
        record.setMtu(mtu)
        for (a in addresses) record.addAddress(a.address, a.prefixLength)
        // THE EXCLUSION GOES IN LAST, AND THE ORDER WAS BACKWARDS UNTIL NOW.
        //
        // The previous order (exclusions first) was justified by "a platform
        // which applies them in order never has a window in which the tunnel's
        // routes exist and the exclusion does not". `VpnService.Builder` has no
        // such window to protect: it is a pure accumulator that applies NOTHING
        // until `establish()`, so no ordering here can leave a live interface
        // half-configured.
        //
        // What ordering does decide is which call survives. On Android 13 and
        // 14 `Builder.excludeRoute(prefix)` is `addRoute(prefix, RTN_THROW)`,
        // sharing one `mRoutes` list with the includes, and the private
        // `addRoute` resolves a destination collision with `mRoutes.set(index,
        // newRoute)`. First writer loses. Applying exclusions first therefore
        // let any include naming the same prefix delete the outer-transport
        // exclusion, while [WinnV3PostureRecord] still reported it applied and
        // `verifyNarrow(requireExclusion = true)` still passed: a posture that
        // verified a property the builder did not have.
        //
        // Exclusions last makes the collision resolve the safe way round (the
        // exclusion wins), and the record now models the replacement either
        // way, so §4.3.1 refuses rather than approves it.
        for (r in routes) record.addRoute(r.address, r.prefixLength)
        for (e in excludedRoutes) record.excludeRoute(e.address, e.prefixLength)
        for (d in dnsServers) record.addDnsServer(d)
        for (f in families) record.allowFamily(f)
        return record
    }

    fun describe(): String =
        "$stage addresses=${addresses.joinToString { "${it.address}/${it.prefixLength}" }} " +
            "mtu=$mtu routes=${routes.size} excluded=${excludedRoutes.size} dns=${dnsServers.size}"
}
