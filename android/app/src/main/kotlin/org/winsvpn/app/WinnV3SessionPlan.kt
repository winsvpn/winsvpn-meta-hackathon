package org.winsvpn.app

/**
 * Everything a v3 session needs, resolved from the `[winn]` section once and
 * checked before anything is allocated: the create document and BOTH postures.
 *
 * ## Why both postures are built up front
 *
 * §4.3 rule 1 :  *a start that would be staged but cannot build a narrow
 * bootstrap must refuse to start, never fall back* :  is only enforceable if the
 * refusal happens before the tunnel exists. Building the promotion posture here
 * too means a configuration that can bootstrap but could never promote (no
 * routes, no resolvers, inner IPv6 below the v6 link floor) is refused at the
 * same moment, rather than after the user has watched a spinner for thirty
 * seconds and the host has been reconfigured once.
 *
 * ## The MTU is computed, never copied
 *
 * The `MTU` in the AmneziaWG `[Interface]` section is AmneziaWG's number and is
 * the wrong one here :  it is sized for that protocol's overhead over the dialled
 * carrier. §4.2 pins a v3 interface to exactly `driver.NewSizing(...).InnerMTU`,
 * the floor across every class the session may migrate to, and
 * [WinnV3EngineConfig] requires equality with it rather than "at most". So this
 * computes [WinnV3Sizing.planFloorInnerMtu] from the PATH MTU and the migration
 * plan and ignores the AmneziaWG value entirely. At a 1500-byte path over
 * `[udp, tcp, tls]` that is 1359, and the 84-byte gap between it and the dialled
 * UDP/IPv4 carrier's 1443 is the whole point. (The DEFAULT path MTU is 1280, not
 * 1500 :  this sentence said 1500 until 2026-08-09, when every host converged on
 * 1280. At the default the floor is 1139.)
 *
 * ## One thing this class resolves and cannot install
 *
 * A plan is not the same as a posture the platform will accept. See
 * [promotionEstablishRefusal] for the kernel rule no v3 constructor can know,
 * and why it is checked at start rather than discovered at promotion.
 *
 * Free of Android imports so the resolution rules run under a plain-JVM test.
 */
internal class WinnV3SessionPlan private constructor(
    val engineConfig: WinnV3EngineConfig,
    val bootstrap: WinnV3Posture,
    val promotion: WinnV3Posture,
    val innerMtu: Int,
    val gatewayEndpoint: String,
) {

    fun describeForLog(): String =
        "winn3 plan: innerMtu=$innerMtu (plan floor) bootstrap=[${bootstrap.describe()}] " +
            "promotion=[${promotion.describe()}]"

    /**
     * Why THIS PLATFORM could not install [promotion], or null.
     *
     * ## The gap this closes
     *
     * Every other refusal in this class is a rule about the CONFIGURATION, and
     * [from] enforces those by calling the real constructors. This one is a rule
     * about the KERNEL, and no constructor in the v3 tree can know it:
     *
     *   Linux refuses to attach an IPv6 address to a device whose MTU is below
     *   RFC 8200's 1280-byte minimum link MTU. `ipv6_add_dev()` returns
     *   `-EINVAL`, `RTNETLINK answers: Invalid argument`, and Android's
     *   `VpnService.Builder.establish()` surfaces it as
     *   `IllegalArgumentException: Cannot set address`.
     *
     * MEASURED on emulator-5554 (API 34) on 2026-08-09 against the kernel
     * directly, with no app in the way: on a dummy device at MTU 1139 an IPv6
     * `/128` is refused and an IPv4 `/32` is accepted; at 1279 refused; at 1280
     * and 1359 accepted. The boundary is exactly 1280 and it is the kernel's,
     * not the framework's :  which is why it is stated here as a platform fact
     * rather than restated as a posture rule.
     *
     * [WinnV3Posture.promotion] ALWAYS installs an IPv6 address :  the inner one
     * when there is one, the fail-closed sink when there is not, and never
     * neither, because host IPv6 egressing beside a promoted v4 tunnel is an
     * attributable session. Its own `IPV6_MIN_LINK_MTU` clause guards the inner
     * address; since 2026-08-10 the fail-closed sink is guarded with the SAME
     * floor :  [WinnV3Posture.promotion] refuses to build a promotion whose sink
     * would be installed on a link narrower than RFC 8200's 1280-byte minimum :
     * so neither IPv6 shape can reach `establish()` on a narrow link. The
     * function below (which reads the RECORD) therefore now fires for a plan
     * that reaches it, and is retained as the start-time backstop and the rich
     * operator diagnostic, but the sink shape itself is refused earlier, inside
     * [WinnV3SessionPlan.from], by the posture constructor.
     *
     * ## Why it reads the RECORD rather than restating the rule
     *
     * `cmd/winn3-gateway`'s `preflightSession` :  silent-refusal instance #8's
     * fix :  runs the REAL constructors rather than a hand-written copy of their
     * rules, so "a rule added to either package is enforced here on the day it
     * is added and this file does not have to be touched". This is the same
     * shape one layer up: it asks the CONSTRUCTED posture what addresses it will
     * actually ask the platform for, through the same [WinnV3Posture.applyTo]
     * the installer uses, with a null sink so nothing is written. A third IPv6
     * shape added to [WinnV3Posture.promotion] tomorrow is covered without an
     * edit here, and a shape that stops installing IPv6 stops firing this
     * without one either.
     *
     * That second property is what makes this safe to land ahead of the owner's
     * decision on the default: it is a statement about what the platform accepts,
     * not a vote on what the posture should be. Raise the default and it stops
     * firing; drop the IPv6 requirement below a threshold and it stops firing.
     * Neither outcome needs this function changed.
     */
    fun promotionEstablishRefusal(): String? {
        // The real posture, through the real writer, into a record instead of a
        // Builder. Nothing is opened and nothing is written; see applyTo.
        val record = promotion.applyTo(null)
        val mtu = record.mtu ?: return null
        val ipv6Addresses = record.addresses.filter { it.address.contains(':') }
        if (ipv6Addresses.isEmpty()) return null
        if (mtu >= WinnV3Sizing.IPV6_MIN_LINK_MTU) return null

        val pathMtu = engineConfig.pathMtu
        val classes = engineConfig.carrierClasses
        val messageSize = WinnV3Sizing.planFloorMessageSize(pathMtu, classes)
        // DERIVED, not tabulated. The smallest path MTU whose plan floor clears
        // the v6 link floor over THIS plan's classes :  1421 over the shipping
        // [udp, tcp, tls], because the narrowest class is TLS over IPv6 and it
        // is charged 112 bytes. Searching with the real function means a change
        // to any carrier's overhead moves this number instead of stranding it.
        val minimumPathMtu = (WinnV3Sizing.IPV6_MIN_LINK_MTU..MAX_PATH_MTU)
            .firstOrNull { WinnV3Sizing.planCarriesInnerIpv6(it, classes) }

        return "Winn Protocol v3 cannot start with this configuration, and refusing now is the " +
            "whole point of saying so: the session would handshake, carry packets, reach " +
            "gate=carrying, and only then fail to promote :  which on this threat model is " +
            "indistinguishable from the network censoring the user.\n" +
            "The promotion posture must install the IPv6 address " +
            ipv6Addresses.joinToString { "${it.address}/${it.prefixLength}" } +
            " on an interface of MTU $mtu. No Linux kernel accepts an IPv6 address below RFC " +
            "8200's ${WinnV3Sizing.IPV6_MIN_LINK_MTU}-byte minimum link MTU :  Android reports " +
            "it as \"IllegalArgumentException: Cannot set address\" out of " +
            "VpnService.Builder.establish().\n" +
            "THE CHAIN, every step computed from this configuration:\n" +
            "  path_mtu $pathMtu" +
            (if (pathMtu == DEFAULT_PATH_MTU) " (the default; no [winn] $KEY_PATH_MTU was set)" else "") +
            "\n" +
            "  -> plan floor message size $messageSize across " +
            classes.joinToString(", ", "[", "]") +
            " (the NARROWEST class, not the one dialled)\n" +
            "  -> inner MTU $mtu = $messageSize - ${WinnV3Sizing.OVERHEAD} of winn3 per-packet " +
            "overhead\n" +
            "  -> $mtu is below ${WinnV3Sizing.IPV6_MIN_LINK_MTU}, so the address cannot be " +
            "attached and the promotion cannot be installed.\n" +
            "Neither end of this is wrong on its own. The carrier floor is correct, the posture's " +
            "refusal to route inner IPv6 on a narrow link is correct, and the kernel's floor is " +
            "RFC 8200. They are jointly unsatisfiable at this path MTU.\n" +
            (
                if (minimumPathMtu != null) {
                    "The smallest $KEY_PATH_MTU that clears the floor over " +
                        classes.joinToString(", ", "[", "]") + " is $minimumPathMtu."
                } else {
                    "No path MTU this host accepts clears the floor over " +
                        classes.joinToString(", ", "[", "]") + "."
                }
                )
    }

    companion object {
        /**
         * The `[winn]` key that selects v3, and the value that means it.
         *
         * A dedicated key rather than a derived signal. The `mode` string
         * `"winn-v3"` that `VpnTunnelService` already logs is a LABEL for the
         * v1-over-Winn arrangement and has never selected a protocol; reusing it
         * would have silently turned every existing deployment into a v3 attempt
         * against an engine that cannot serve one.
         */
        const val KEY_PROTOCOL = "protocol"
        const val PROTOCOL_V3 = "3"

        /**
         * The SERVED selector: `[winn] carrier = winn3`.
         *
         * `protocol = 3` above is this host's own spelling and nothing emits it.
         * `lib/winn_protocol_dispatch.dart` writes `carrier = winn3`, Apple
         * selects on it, and `WinnEngineConfig.SUPPORTED_CARRIERS` deliberately
         * does NOT contain it :  so before 2026-08-09 a served standalone config
         * reaching this host went down the v1 branch and was refused with
         * "Winn carrier 'winn3' is not one this engine can build". Loud, and
         * wrong: the config was perfectly good and named a protocol this host
         * implements.
         *
         * Both spellings select v3, and they are checked with the same exactness
         * for the same reason: this decides which protocol the user's traffic
         * crosses, and a fuzzy match here is a downgrade nobody can see.
         */
        const val KEY_CARRIER = "carrier"
        const val CARRIER_WINN3 = "winn3"

        /**
         * The signed descriptor's `node` field, copied into `[winn]` as `node`.
         *
         * Necessary but not sufficient: [from] also binds it to every present
         * selected-node identity before any credential field is read.
         */
        const val KEY_DESCRIPTOR_NODE = "node"

        /**
         * The native INI spelling of the route-selected node. One of
         * [SELECTED_NODE_IDENTITY_KEYS], not the only one: a matching decoy
         * `node_slug` must not hide a different `location_slug`.
         */
        const val KEY_SELECTED_NODE = "selected_node"

        /**
         * Served-config keys that name the route-selected node, including
         * underscored names, no-underscore twins, and the native INI spelling.
         *
         * Order is the check order, matching Dart's
         * `kWinn3SelectedNodeIdentityKeys`. A first-wins read of these keys is
         * a substitution hole.
         */
        val SELECTED_NODE_IDENTITY_KEYS = listOf(
            "node_slug",
            "nodeslug",
            "location_slug",
            "locationslug",
            KEY_SELECTED_NODE,
            "selectednode",
        )

        /**
         * The refusal when the signed descriptor node is missing, not an ASCII
         * identity, disagrees with a selected-node alias, or the aliases
         * disagree with each other.
         *
         * Named so a test can pin the gap without scraping a sentence, and so
         * [from] cannot accept a plan after this check by "handling" a
         * different exception. Values are never interpolated: a Unicode
         * selected node is not logged back out of the refusal that exists to
         * reject it.
         */
        const val DESCRIPTOR_NODE_BINDING_REFUSAL =
            "Winn signed descriptor node and selected node must both be present and match"

        /**
         * This tunnel's inner IPv4 address, from the signed gateway descriptor.
         *
         * ==================================================================
         * THIS IS NOT THE AmneziaWG ADDRESS, AND THE DIFFERENCE IS THE WHOLE
         * REASON THIS KEY EXISTS
         * ==================================================================
         *
         * Until 2026-08-09 `VpnTunnelService.startWinnV3EngineThread` passed
         * `innerAddress = clientIp` :  the address the AmneziaWG relay was
         * assigned. A standalone v3 session shares no address space with the
         * relay because it shares no session with it: the inner assignment comes
         * from the v3 gateway's own inner space and arrives on the descriptor.
         *
         * The winn/3 tun layer validates the SOURCE address of every packet the
         * host offers and drops what does not match its assignment. An interface
         * carrying the relay's address therefore hands the engine a stream of
         * packets it silently discards, the gate never carries, and the session
         * fails closed at the deadline with `winn3_rx_dropped_invalid` as the
         * only clue. Every other host in the tree reads this field; this one
         * reused a value that happened to be in scope.
         */
        const val KEY_INNER_V4 = "inner_v4"

        /**
         * The inner next hop, as the field contract and the hub spell it.
         *
         * The same value [KEY_INNER_NEXT_HOP] names, under the name every other
         * host and the control plane use. Both are read :  see [innerNextHopOf] :
         * because `inner_next_hop` is this host's own older spelling and a lab
         * configuration written against it must not silently lose its one
         * bootstrap route.
         */
        const val KEY_INNER_ROUTER_V4 = "inner_router_v4"

        /**
         * Optional: the gateway's INNER DNS RESPONDER address, off the same
         * ML-DSA-65-signed descriptor [KEY_INNER_ROUTER_V4] arrives on.
         *
         * Absent from every descriptor that exists today, and absent means
         * "this gateway advertises no inner resolver" :  which is the state
         * [WinnV3Resolvers] already handles by refusing to promote. It is read
         * here rather than in `VpnTunnelService` because this is the object that
         * already holds both inner facts the derivation needs, and a resolver
         * address that arrived through a second path would be a resolver address
         * whose trust nobody could state in one place.
         *
         * NOT a `dns` key and not a boolean. `conform`'s
         * `ServedWinnSectionCarriesNoPostureKey` pins `dns`, `dns_are_inner`,
         * `dns_servers` and `resolvers` absent from `[winn]` because a
         * transported boolean asserting "this resolver is inside the tunnel" is
         * the leak wearing a flag. A signed ADDRESS is different in kind: the
         * host runs its own unchanged derivation against it, and a value that
         * fails any clause is still refused.
         */
        const val KEY_INNER_RESOLVER_V4 = "inner_resolver_v4"

        /** Optional: the outer path MTU the migration plan is computed against. */
        const val KEY_PATH_MTU = "path_mtu"

        /** Optional: the migration plan, comma-separated. Defaults to all three. */
        const val KEY_CARRIER_CLASSES = "carrier_classes"

        /**
         * Optional: the single inner destination the BOOTSTRAP posture routes.
         *
         * Defaults to the first resolver, which in this app's configurations is
         * the gateway's own inner address (`DNS = 10.8.1.1` beside
         * `Address = 10.8.1.3/32`). That default is what makes the bootstrap
         * able to prove anything: it must route SOMEWHERE the gateway will
         * answer from, and the inner resolver is the one address every one of
         * these deployments has. It stays overridable because a deployment whose
         * resolver is not its inner next hop would otherwise have no way to say
         * so, and §4.1 allows exactly one route here :  there is no room to
         * install both and hope.
         */
        const val KEY_INNER_NEXT_HOP = "inner_next_hop"

        /**
         * The outer path MTU a section that names none resolves to.
         *
         * ==================================================================
         * 1280, NOT 1500, AND THE CHANGE IS A DEFECT FIX
         * ==================================================================
         *
         * `carrier.DefaultPathMTU` is 1280 and so is `tun.IPv6MinLinkMTU`; the
         * suite pins the two names to one number precisely so a host that
         * defaults through either agrees with a host that defaults through the
         * other. `cmd/winn3-gateway -path-mtu`, `cmd/winn-datapath`'s profile,
         * `cdatapath` and Apple's `winn3PathMTU` (zero meaning "the engine's
         * conservative default") all land on 1280. This host alone defaulted to
         * 1500, and the served `[winn]` section carries `path_mtu` only when an
         * operator set one :  so the default is the case that actually happens.
         *
         * The damage is measured, not argued: at 1280 the udp+tcp+tls floor is
         * 1168/1139 and at 1500 it is 1388/1359. That is the WIDE mismatch
         * regime `path-mtu-not-negotiated` records against a live gateway :  the
         * session never carries at all, the gateway refuses five datagrams and
         * closes, and the client's gate never leaves down. Nothing is logged to
         * the user and nothing is signalled to the client.
         *
         * A path MTU is a FLOOR, so defaulting narrow is the safe direction: a
         * client that plans smaller than the path allows wastes bytes, and one
         * that plans larger black-holes every full-size flow.
         *
         * ## RAISED 1280 -> 1450 ON 2026-08-10, WITH THE REST OF THE FLEET
         *
         * Everything above is the record of the 2026-08-09 fix, when this host
         * was the odd one out at 1500 and every other entry point resolved to
         * 1280. It is kept because the WIDE mismatch it describes is real and
         * the arithmetic still holds. What changed is that 1280 was the wrong
         * number for ALL of them.
         *
         * "Defaulting narrow is the safe direction" was true about the OUTER
         * path and false about what it costs INSIDE. 1280 outer is 1139 inner
         * over this host's plan, and an interface at 1139 cannot carry IPv6 at
         * all: RFC 8200 requires 1280 of any link that does, and the kernel
         * enforces it :  `ipv6_add_dev()` returns -EINVAL. So 1280..1420 is a
         * 141-value DEAD ZONE in which a session resolves, bootstraps, carries
         * and can NEVER promote. [promotionEstablishRefusal] is this host's own
         * guard against it, and on the old default it was the thing standing
         * between the user and a tunnel that looked up and moved nothing.
         *
         * 1421 is where the zone ends (1280 + 29 + 112 for TLS over IPv6).
         * 1450 clears it with 29 bytes of headroom and concedes 50 rather than
         * the 220 the old default gave away on every packet of a metered
         * connection.
         *
         * winn3/driver.NewSizing now REFUSES the band outright, so a served
         * `path_mtu` inside it is a loud refusal rather than a tunnel that
         * comes up and never promotes. [MIN_PATH_MTU] mirrors that refusal here.
         */
        const val DEFAULT_PATH_MTU = 1450

        /**
         * The widest path MTU this host will plan against.
         *
         * Named rather than repeated so [promotionEstablishRefusal]'s search for
         * the smallest workable path MTU and [from]'s range check cannot drift
         * apart. `winn3/conform`'s own warning applies: two names for one number
         * is how defect 3 gets a sibling.
         */
        const val MAX_PATH_MTU = 9000

        /**
         * The narrowest path MTU that can actually PROMOTE. ADDED 2026-08-10.
         *
         * It is documentation and a shared constant for the refusal messages,
         * NOT a parse-time gate :  see the note on [from]'s range check.
         *
         * 1280 + 29 bytes of v3 overhead + 112 for TLS over IPv6, the widest
         * class [WinnV3Sizing.CARRIER_CLASSES] may migrate to. Below it the plan
         * floor puts the inner interface under RFC 8200's minimum link MTU and
         * inner IPv6 becomes impossible :  see [DEFAULT_PATH_MTU].
         *
         * It mirrors winn3/driver.NewSizing's refusal, which is computed
         * per-plan rather than fixed. This host ships one plan, so one number is
         * honest here; if it ever offers the operator a narrower plan, this must
         * become a computation or it will refuse configurations that work.
         */
        const val MIN_PATH_MTU = 1421

        /**
         * The keys this plan consumes. Folded into
         * [WinnEngineConfig.RESERVED_KEYS] so the v2 builder does not mistake
         * one for a field of `datapath.Config`.
         */
        val V3_KEYS = setOf(
            KEY_PROTOCOL, KEY_PATH_MTU, KEY_CARRIER_CLASSES, KEY_INNER_NEXT_HOP,
            // The served spelling. `carrier` is already reserved by
            // WinnEngineConfig itself; the other two are this host's business.
            KEY_INNER_V4, KEY_INNER_ROUTER_V4,
            // THE SIGNED RESOLVER ADDRESS, AND IT WAS READ WITHOUT BEING LISTED.
            //
            // [innerResolverOf] has consumed `inner_resolver_v4` since the field
            // existed, and `lib/winn_protocol_dispatch.dart` emits it into the
            // served `[winn]` section the moment a descriptor carries one. It
            // was never added HERE, and this set is folded into
            // `WinnEngineConfig.RESERVED_KEYS`, whose parse loop throws
            // IllegalArgumentException on the first key it does not recognise.
            //
            // So the day the hub starts signing `inner_resolver_v4` (the nodes
            // germany-de1, canada-ca1 and spain-madrid are configured with
            // `inner_resolver_v4 = 10.10.0.1`), every configuration that reaches
            // `WinnEngineConfig.from` on this platform becomes a refusal quoting
            // a key the operator deliberately set: the exact hazard the `psk`
            // line four lines below was added to prevent, reached by the one
            // field that is also load-bearing for §4.4. Apple already reads it
            // (`WinsWinn3SessionStart.winn3InnerResolverV4`), so the divergence
            // would be Android-only and would look like a network fault.
            KEY_INNER_RESOLVER_V4,
            // Optional on the served section and consumed by neither this class
            // nor WinnV3Keys today. Named so it is a KNOWN key rather than an
            // unrecognised one: WinnEngineConfig.from refuses what it does not
            // recognise, so an unlisted `psk` would turn a perfectly good served
            // config into a refusal on this platform alone.
            "psk",
            // Descriptor-to-selected-node binding. Folded in so a hostile
            // alias cannot be forwarded as a datapath.Config field, and so a
            // key added to [SELECTED_NODE_IDENTITY_KEYS] cannot leave this
            // set behind.
            KEY_DESCRIPTOR_NODE,
        ) +
            SELECTED_NODE_IDENTITY_KEYS +
            // The key material's own keys. Folded in rather than listed, for the
            // same reason: a key added to WinnV3Keys must not need a second edit
            // here to stop the v1 builder mistaking it for an engine field.
            WinnV3Keys.SECTION_KEYS

        /**
         * Whether this section asks for v3.
         *
         * Deliberately exact. `protocol = 3` selects v3 and every other value :
         * including `3.0`, `v3` and `winn/3` :  does not, because a fuzzy match
         * here decides which protocol the user's traffic crosses. An unrecognised
         * value is refused by [refuseUnknownProtocol] rather than defaulting to
         * v1, so a typo cannot silently downgrade.
         */
        fun isRequested(section: Map<String, String>): Boolean =
            section[KEY_PROTOCOL]?.trim() == PROTOCOL_V3 ||
                section[KEY_CARRIER]?.trim()?.lowercase() == CARRIER_WINN3

        /**
         * The inner next hop this section names, under either spelling.
         *
         * `inner_router_v4` is the served name and wins when both are present,
         * because a configuration carrying both came from the control plane and
         * the control plane's spelling is the contract. Neither is defaulted
         * here; [from] falls back to the first resolver, which is what makes a
         * bootstrap posture able to prove anything.
         */
        fun innerNextHopOf(section: Map<String, String>): String =
            section[KEY_INNER_ROUTER_V4]?.trim()?.takeIf { it.isNotEmpty() }
                ?: section[KEY_INNER_NEXT_HOP]?.trim()?.takeIf { it.isNotEmpty() }
                ?: ""

        /**
         * The inner resolver this section names, or "".
         *
         * ONE spelling only, unlike [innerNextHopOf]. That function reads two
         * names because this host shipped its own older `inner_next_hop` before
         * the served contract existed and lab documents written against it must
         * not silently lose their one bootstrap route. This field has no legacy
         * spelling to be compatible with :  it has never shipped under any name :
         * so accepting a second one could only ever let a typo decide where every
         * name lookup in the session goes.
         */
        fun innerResolverOf(section: Map<String, String>): String =
            section[KEY_INNER_RESOLVER_V4]?.trim() ?: ""

        /**
         * The refusal for a `protocol` value that is neither absent nor `3`.
         *
         * Returns null when the value is acceptable. A separate function from
         * [isRequested] because the two answer different questions and a single
         * one that both selected and validated would have to return a tri-state
         * that every caller then re-interprets.
         */
        fun refuseUnknownProtocol(section: Map<String, String>): String? {
            val raw = section[KEY_PROTOCOL]?.trim() ?: return null
            if (raw.isEmpty() || raw == PROTOCOL_V3 || raw == "1") return null
            return "Winn section sets $KEY_PROTOCOL='$raw', which this host does not implement. " +
                "Refusing rather than falling back to v1: a protocol selected by a typo is a " +
                "downgrade the user cannot see."
        }

        /**
         * ASCII-only lowercase, matching native `LowerAscii` on Windows and
         * Linux.
         *
         * Kotlin's `String.lowercase()` is Unicode-aware and folds U+212A
         * KELVIN SIGN onto `k`, so a selected node of `K1` would match a
         * signed `k1`. This host must not accept that fold: Dart already
         * refuses it, and native Android is an independent gate, not a
         * second chance for a hostile INI that skipped Dart.
         */
        fun asciiLowercase(value: String): String {
            val out = StringBuilder(value.length)
            for (ch in value) {
                val code = ch.code
                if (code in 0x41..0x5A) {
                    out.append((code + 0x20).toChar())
                } else {
                    out.append(ch)
                }
            }
            return out.toString()
        }

        /**
         * Trim only ASCII SP/HT/LF/CR, matching native `Trim` on Windows and
         * Linux. Kotlin's `trim()` strips NBSP and other Unicode spaces that
         * would otherwise fold `lab-alpha\u00a0` onto `lab-alpha`.
         */
        fun asciiTrim(value: String): String {
            var start = 0
            var end = value.length
            while (start < end && isAsciiHorizontalWhitespace(value[start])) start++
            while (end > start && isAsciiHorizontalWhitespace(value[end - 1])) end--
            return if (start == 0 && end == value.length) value else value.substring(start, end)
        }

        /**
         * Trim, reject non-ASCII, ASCII-lowercase, then the slug alphabet.
         *
         * Returns null when [raw] is not a node identity. The alphabet is
         * hub/client `^[a-z0-9][a-z0-9-]{1,39}$`: 2-40 ASCII letters, digits,
         * or hyphens, starting with an alphanumeric. A Kelvin fold, a
         * homoglyph, or a compatibility form is null, never a match.
         */
        fun normalizedNodeIdentity(raw: String?): String? = readNodeIdentity(raw).value

        /**
         * Route-selected node identity from a `[winn]` section.
         *
         * Empty means missing, malformed, Unicode, or conflicting aliases.
         * [from] treats empty the same as a cross-node mismatch: refuse
         * [DESCRIPTOR_NODE_BINDING_REFUSAL] before reading `inner_v4` or any
         * other descriptor credential. All present identities must agree; a
         * matching decoy alias cannot paper over a different selected node.
         */
        fun selectedNodeIdentity(section: Map<String, String>): String {
            var bound: String? = null
            var sawPresent = false
            for (key in SELECTED_NODE_IDENTITY_KEYS) {
                if (!section.containsKey(key)) continue
                val read = readNodeIdentity(section[key])
                if (!read.present) continue
                sawPresent = true
                val value = read.value ?: return ""
                if (bound == null) {
                    bound = value
                } else if (bound != value) {
                    return ""
                }
            }
            if (!sawPresent) return ""
            return bound ?: ""
        }

        /**
         * True when the signed descriptor `node` equals every present
         * selected-node identity on [section].
         */
        fun descriptorMatchesSelectedNode(section: Map<String, String>): Boolean {
            val descriptor = normalizedNodeIdentity(section[KEY_DESCRIPTOR_NODE]) ?: return false
            val selected = selectedNodeIdentity(section)
            return selected.isNotEmpty() && selected == descriptor
        }

        /**
         * Builds the plan, or throws.
         *
         * @param section the `[winn]` section.
         * @param relayInnerAddress the AmneziaWG `Address` assignment, used ONLY
         *   when the section carries no [KEY_INNER_V4]. A served standalone
         *   config always carries it; see that constant for why reusing the
         *   relay's address is a session that reports up and carries nothing.
         * @param dnsServers the inner resolvers. The promotion posture requires
         *   at least one; the bootstrap posture installs none.
         * @param promotionRoutes the full route set promotion captures.
         * @param ipv6SinkAddress the fail-closed IPv6 sink this platform already
         *   requires of its other tunnel modes.
         *
         * @throws WinnV3PostureRefusal when a posture cannot be built narrow.
         * @throws IllegalArgumentException when the section is malformed.
         */
        @Throws(WinnV3PostureRefusal::class)
        @Suppress("LongParameterList")
        fun from(
            section: Map<String, String>,
            relayInnerAddress: String,
            dnsServers: List<String>,
            promotionRoutes: List<WinnV3Route>,
            ipv6SinkAddress: String,
        ): WinnV3SessionPlan {
            require(isRequested(section)) { "the Winn section does not ask for protocol 3" }

            // Bind the signed descriptor node to every present selected-node
            // identity BEFORE any credential field is read. Signature validity
            // (or a well-formed inner_v4) is not enough: a valid descriptor for
            // gateway A substituted into gateway B's config would seal
            // initiations only A can open. Conflicting aliases are a mismatch,
            // not a first-wins preference. Unicode case folding is a mismatch,
            // not a match. The protocol=3 spelling is not a bypass of the
            // carrier=winn3 spelling: both selectors build a credential-bearing
            // plan through this function.
            require(descriptorMatchesSelectedNode(section)) {
                DESCRIPTOR_NODE_BINDING_REFUSAL
            }

            // THE INNER ADDRESS COMES FROM THE SECTION, NOT FROM THE RELAY.
            // See KEY_INNER_V4. `relayInnerAddress` is the AmneziaWG assignment
            // and is accepted here ONLY as the fallback for a lab configuration
            // predating `inner_v4`; a served config always carries the field,
            // and the fallback is refused for anything the tun layer would then
            // drop. Silently reusing the relay's address builds a session that
            // starts, reports up at both ends and carries nothing.
            val innerAddress = section[KEY_INNER_V4]?.trim()?.takeIf { it.isNotEmpty() }
                ?: relayInnerAddress.trim()
            require(innerAddress.isNotEmpty()) {
                "Winn $KEY_INNER_V4 is absent; the inner address comes from the ML-DSA-65-signed " +
                    "gateway descriptor and nothing in this configuration carries it. A v3 " +
                    "session shares no address space with the AmneziaWG relay, and the winn/3 " +
                    "tun layer drops every packet whose source does not match its assignment"
            }

            val endpoint = section["endpoint"].orEmpty().trim()
            require(WinnEngineConfig.isIpLiteralEndpoint(endpoint)) {
                "Winn endpoint must be an IP literal with a port, not a hostname: resolving one " +
                    "inside the engine would leak a lookup outside the tunnel"
            }

            val pathMtu = section[KEY_PATH_MTU]?.trim()?.takeIf { it.isNotEmpty() }
                ?.let {
                    it.toIntOrNull()
                        ?: throw IllegalArgumentException("Winn $KEY_PATH_MTU is not a number")
                }
                ?: DEFAULT_PATH_MTU
            // 1280 and not MIN_PATH_MTU. This is a PARSE bound, not the
            // dead-zone policy: the band 1280..1420 is refused for this host by
            // winn3/driver.NewSizing inside the engine AND by
            // [promotionEstablishRefusal] before the tunnel is established, and
            // both name the number to use. Refusing a third time here would
            // only move a loud failure earlier while breaking the ability to
            // construct a dead-zone plan in order to TEST those two refusals.
            require(pathMtu in 1280..MAX_PATH_MTU) {
                "Winn $KEY_PATH_MTU is out of range; a path below 1280 cannot carry this protocol " +
                    "and one above $MAX_PATH_MTU is not a link this host will meet"
            }

            val carrierClasses = section[KEY_CARRIER_CLASSES]?.trim()?.takeIf { it.isNotEmpty() }
                ?.split(',')?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }
                ?: WinnV3Sizing.CARRIER_CLASSES
            require(carrierClasses.isNotEmpty()) {
                "Winn $KEY_CARRIER_CLASSES names no classes; driver.NewSizing refuses an empty " +
                    "plan because a floor computed over nothing guarantees nothing"
            }
            require(carrierClasses.contains("udp")) {
                "Winn $KEY_CARRIER_CLASSES must contain udp because the shipping engine dials udp"
            }
            // Resolve every class now. carrierOverhead throws on an unknown one,
            // and doing it here means the failure names the key rather than
            // arriving from inside the sizing computation.
            for (c in carrierClasses) WinnV3Sizing.carrierOverhead(c, ipv4 = true)

            // §4.2's number, computed and not copied. See the class KDoc.
            val innerMtu = WinnV3Sizing.planFloorInnerMtu(pathMtu, carrierClasses)

            val innerNextHop = innerNextHopOf(section).takeIf { it.isNotEmpty() }
                ?: dnsServers.firstOrNull()?.trim().orEmpty()

            // THE SIGNED FIELD REPLACES THE CANDIDATE LIST; IT DOES NOT JOIN IT.
            //
            // `dnsServers` is `parseConfigValue(awgConfig, "DNS")` :  the
            // AmneziaWG relay's line, belonging to a session this one shares
            // nothing with. When the descriptor names an inner resolver, that
            // is the only candidate, because `VpnService.Builder.addDnsServer`
            // hands every entry to the platform resolver and the PLATFORM, not
            // this code, picks which one answers: a relay or public entry
            // sitting second in the list answers whenever the first is slow.
            // `WinnV3Resolvers.promotionRefusalReason` would refuse that mixed
            // list anyway; replacing means the honest configuration never has to
            // be rescued by a refusal.
            //
            // Empty field -> `candidates` is `dnsServers` exactly as before, so
            // every configuration served today derives, and refuses, identically.
            val innerResolver = innerResolverOf(section)
            val candidates = if (innerResolver.isNotEmpty()) {
                listOf(innerResolver)
            } else {
                dnsServers
            }
            require(innerNextHop.isNotEmpty()) {
                "a v3 bootstrap needs one inner destination to route, and this configuration " +
                    "supplies neither $KEY_INNER_ROUTER_V4 nor $KEY_INNER_NEXT_HOP nor a " +
                    "resolver to default to"
            }

            val sessionId = section["session_id"].orEmpty().trim()
            require(sessionId.length <= 128) { "Winn session_id exceeds 128 bytes" }

            // The outer-transport exclusion: the gateway the carrier dials. On
            // Android this is defence in depth beside protect(); see
            // WinnV3Posture.OUTER_EXCLUSION_NOTE.
            val exclusion = endpoint.substringBeforeLast(':').trim()
                .takeIf { it.isNotEmpty() && !it.contains(':') }
                ?.let { WinnV3Route(it, 32) }

            val engineConfig = WinnV3EngineConfig(
                gatewayEndpoint = endpoint,
                innerAddress = innerAddress,
                innerNextHop = innerNextHop,
                innerMtu = innerMtu,
                pathMtu = pathMtu,
                carrierClasses = carrierClasses,
                sessionId = sessionId,
            )

            val bootstrap = WinnV3Posture.bootstrap(
                innerAddress = innerAddress,
                innerMtu = innerMtu,
                innerNextHop = innerNextHop,
                outerTransportExclusion = exclusion,
            )

            // No inner IPv6 is offered, and the reason is that NOTHING CARRIES
            // ONE: the ML-DSA-65-signed descriptor's closed field set has no
            // inner v6, the hub serves `winn3_inner_v4` and nothing else, and
            // the `[winn]` section has no v6 key. There is no address to assign.
            //
            // CORRECTED 2026-08-09. This comment previously justified the null
            // by arithmetic, and the arithmetic was wrong in a way worth naming
            // rather than quietly deleting: it said the plan floor "is below RFC
            // 8200's 1280-byte link floor ... :  1359 at a 1500-byte path", and
            // 1359 is ABOVE 1280. Inner IPv6 is arithmetically fine at a
            // 1500-byte path; it is impossible at 1280, where the floor is 1139.
            // The threshold is a path MTU of 1421 over [udp, tcp, tls], because
            // the narrowest class is TLS over IPv6. A wrong reason for a right
            // line is how the right line survives the day the reason stops
            // holding.
            //
            // The IPv6 sink is therefore the correct shape for the reason above
            // :  an absent address, not a narrow link :  and it is the same one
            // every other tunnel mode on this platform installs. Note that the
            // sink is still an IPv6 ADDRESS, so it is subject to the same kernel
            // floor the inner one would be. Since 2026-08-10
            // [WinnV3Posture.promotion] guards the sink with that same floor, a
            // plan whose `inner_mtu` is below 1280 is refused HERE :  by this
            // `promotion(...)` call throwing `WinnV3PostureRefusal` :  rather than
            // leaving it to [promotionEstablishRefusal] after the plan exists.
            // `innerNextHop` travels with the resolvers because the promotion
            // posture DERIVES `dns_are_inner` from the two inner facts the
            // signed descriptor carries :  the assignment and the next hop :  and
            // this is the one place that holds both. See [WinnV3Resolvers].
            //
            // Note the interaction with the fallback above, which is deliberate
            // rather than an oversight: a configuration whose only resolver IS
            // its inner next hop refuses, because that address is documented as
            // carrying PMTU signals only and answers no queries. Naming it would
            // trade a leak for total name-resolution failure. Served
            // configurations always carry `inner_router_v4`, so the fallback is
            // reached only by lab documents predating it :  and one of those with
            // a single resolver is exactly the `DNS = 10.8.1.1` beside
            // `Address = 10.8.1.3` shape that made this defect look considered.
            //
            // AMENDED 2026-08-12. That refusal is now conditional on ONE fact,
            // and only one: whether the ML-DSA-65-signed descriptor names a
            // resolver AT that same address, via [KEY_INNER_RESOLVER_V4]. It
            // does not for any descriptor that exists, so the paragraph above
            // still describes every configuration this host meets today. What
            // changed is that "the gateway behind the next hop answers no
            // queries" is a claim about a gateway, and `cmd/winn3-gateway
            // -resolver` is a gateway for which it is false :  answering at its
            // own `-inner-v4`, which is this client's next hop, because
            // winn3/tun's outbound validator will not carry a reply whose source
            // is not the endpoint's own assignment.
            val promotion = WinnV3Posture.promotion(
                innerAddress = innerAddress,
                innerMtu = innerMtu,
                routes = promotionRoutes,
                dnsServers = candidates,
                innerNextHop = innerNextHop,
                outerTransportExclusion = exclusion,
                innerIpv6Address = null,
                ipv6SinkAddress = ipv6SinkAddress,
                innerResolver = innerResolver,
            )

            return WinnV3SessionPlan(
                engineConfig = engineConfig,
                bootstrap = bootstrap,
                promotion = promotion,
                innerMtu = innerMtu,
                gatewayEndpoint = endpoint,
            )
        }

        private fun isAsciiHorizontalWhitespace(ch: Char): Boolean =
            ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'

        /**
         * Hub/client node-slug alphabet after ASCII lowercase: 2-40 letters,
         * digits, or hyphens, starting with an alphanumeric. Checked with
         * explicit code points rather than a regex so a UNICODE_CASE flag
         * cannot widen `a-z` onto Kelvin.
         */
        private fun isAsciiNodeIdentity(value: String): Boolean {
            if (value.length !in 2..40) return false
            if (value == "auto") return false
            val first = value[0].code
            if (first !in 0x30..0x39 && first !in 0x61..0x7A) return false
            for (index in 1 until value.length) {
                val code = value[index].code
                if (code != 0x2D && code !in 0x30..0x39 && code !in 0x61..0x7A) {
                    return false
                }
            }
            return true
        }

        private class NodeIdentityRead(val present: Boolean, val value: String?)

        /**
         * Scan the untrimmed value for non-ASCII first. Native ASCII Trim
         * would leave NBSP in place; those must not fold onto an ASCII slug.
         * Whitespace-only ASCII is absent (the key was present but named
         * nothing). Any other failure is present-and-invalid, so a decoy
         * empty alias cannot hide a different selected node, and a Kelvin
         * alias cannot be skipped as "not a slug".
         */
        private fun readNodeIdentity(raw: String?): NodeIdentityRead {
            if (raw == null) return NodeIdentityRead(present = false, value = null)
            if (raw.any { it.code > 0x7F }) {
                return NodeIdentityRead(present = true, value = null)
            }
            val trimmed = asciiTrim(raw)
            if (trimmed.isEmpty()) return NodeIdentityRead(present = false, value = null)
            val lowered = asciiLowercase(trimmed)
            if (!isAsciiNodeIdentity(lowered)) {
                return NodeIdentityRead(present = true, value = null)
            }
            return NodeIdentityRead(present = true, value = lowered)
        }
    }
}
