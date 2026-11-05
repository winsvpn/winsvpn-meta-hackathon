package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The adoption seam: the tun fd reaching the v3 frame device instead of
 * AmneziaWG, and the promotion that replaces the interface underneath it.
 *
 * The v3 layer's own rules are already covered by `WinnV3HostTest`,
 * `WinnV3PostureTest` and `WinnV3StagedStartTest`. This file tests only what
 * adoption ADDED: the selection gate, the plan that resolves a `[winn]` section
 * into two postures, the seam's behaviour across a rebind, and the two
 * source-level invariants that a future edit could quietly break.
 */
class WinnV3AdoptionTest {

    // ------------------------------------------------------------------
    // Selection. A protocol chosen by a fuzzy match is a protocol the user
    // cannot see.
    // ------------------------------------------------------------------

    @Test
    fun `only the exact value 3 selects v3`() {
        assertTrue(WinnV3SessionPlan.isRequested(mapOf("protocol" to "3")))
        assertTrue("surrounding whitespace is trimmed",
            WinnV3SessionPlan.isRequested(mapOf("protocol" to "  3 ")))
        for (near in listOf("3.0", "v3", "winn/3", "03", "1", "", "true", "33")) {
            assertFalse("'$near' must not select v3",
                WinnV3SessionPlan.isRequested(mapOf("protocol" to near)))
        }
        assertFalse("an absent key must not select v3",
            WinnV3SessionPlan.isRequested(emptyMap()))
    }

    @Test
    fun `an unrecognised protocol value is refused rather than defaulted`() {
        assertNull(WinnV3SessionPlan.refuseUnknownProtocol(emptyMap()))
        assertNull(WinnV3SessionPlan.refuseUnknownProtocol(mapOf("protocol" to "3")))
        assertNull(WinnV3SessionPlan.refuseUnknownProtocol(mapOf("protocol" to "1")))
        for (bad in listOf("2", "v3", "3.0", "winn/3")) {
            val refusal = WinnV3SessionPlan.refuseUnknownProtocol(mapOf("protocol" to bad))
            assertNotNull("'$bad' must be refused, not silently treated as v1", refusal)
            assertTrue(refusal!!, refusal.contains(bad))
        }
    }

    // ------------------------------------------------------------------
    // The MTU. This is the one number the whole layer turns on.
    // ------------------------------------------------------------------

    @Test
    fun `the plan pins the interface to the plan floor and not to the dialled carrier`() {
        // The path MTU is NAMED here rather than defaulted. It used to be
        // implicit, because this host's default was 1500 — and that default was
        // itself the divergence fixed on 2026-08-09 (every other host defaults
        // to 1280). A test that leans on a default is a test that changes
        // meaning when the default does, and this one has to keep measuring the
        // 84-byte gap.
        val plan = plan(baseSection() + ("path_mtu" to "1500"))
        // 1359, not 1443. The 84-byte gap between them is the defect the create
        // seam refuses: 1443 is InnerMTUForPath(1500, 28), the DIALLED UDP/IPv4
        // carrier, and it black-holes every full-size flow at the first
        // migration to TLS over IPv6.
        assertEquals(1359, plan.innerMtu)
        assertEquals(1443, WinnV3Sizing.innerMtuForPath(1500, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD))
        assertEquals(
            "both postures carry exactly the plan floor",
            plan.innerMtu, plan.bootstrap.mtu,
        )
        assertEquals(plan.innerMtu, plan.promotion.mtu)
    }

    @Test
    fun `the AmneziaWG MTU cannot reach the v3 interface`() {
        // The section carries no MTU at all and the plan produces the plan
        // floor at the DEFAULT path MTU, which is the property: v3's MTU is
        // COMPUTED from the path and the migration plan, never copied from the
        // AmneziaWG [Interface] value that sized a different protocol's
        // overhead.
        val plan = plan(section = baseSection())
        assertEquals(1309, plan.innerMtu) // 1139 until the default moved on 2026-08-10
        // And a wider path moves it, so it really is computed.
        assertEquals(1359, plan(section = baseSection() + ("path_mtu" to "1500")).innerMtu)
    }

    @Test
    fun `the create document is ip-packet and never awg-datagram`() {
        val json = plan().engineConfig.toJson()
        assertTrue(json, json.contains("\"payload\":\"${WinnV3Host.PAYLOAD_IP_PACKET}\""))
        assertFalse(
            "a v3 create carrying the v1 payload would ask the engine to forward " +
                "AmneziaWG datagrams it has no implementation for",
            json.contains(WinnEngineConfig.PAYLOAD_AWG_DATAGRAM),
        )
        assertTrue(json, json.contains("\"owns_tun\":false"))
        assertTrue(json, json.contains("\"allow_own_socket\":false"))
        assertTrue(json, json.contains("\"inner_mtu\":1309"))
    }

    // ------------------------------------------------------------------
    // The platform preflight: the kernel rule no v3 constructor can know.
    //
    // MEASURED against the emulator-5554 kernel on 2026-08-09, with no app in
    // the way: on a dummy device at MTU 1139 an IPv6 /128 is refused with
    // `RTNETLINK answers: Invalid argument` while an IPv4 /32 is accepted; at
    // 1279 refused; at 1280 and at 1359 accepted. Android surfaces that EINVAL
    // as `IllegalArgumentException: Cannot set address` out of establish().
    // ------------------------------------------------------------------

    @Test
    fun `the default path MTU can now install the promotion posture`() {
        // INVERTED ON 2026-08-10, AND THE INVERSION IS THE POINT.
        //
        // This test used to assert that a plan on the DEFAULT path MTU could
        // never install its promotion posture — the plan built, and the
        // platform would reject it. That was true and it was an outage: every
        // session that omitted path_mtu, which is the common case, carried and
        // could never promote.
        //
        // The default moved 1280 -> 1450 and the floor moved 1139 -> 1309,
        // clearing RFC 8200's 1280-byte minimum link MTU by 29 bytes. The
        // refusal below is now expected to be ABSENT.
        val plan = plan()
        assertEquals(1309, plan.innerMtu)
        assertTrue(
            "the plan floor at the fleet default must clear the kernel's IPv6 link floor",
            plan.innerMtu >= WinnV3Sizing.IPV6_MIN_LINK_MTU,
        )
        assertNull(
            "a plan on the fleet default must start; if this is non-null the default is " +
                "back inside the dead zone and every session that omits path_mtu is an " +
                "outage:\n" + plan.promotionEstablishRefusal(),
            plan.promotionEstablishRefusal(),
        )
    }

    // RE-INSTRUMENTED 2026-08-10. These tests used to build a dead-zone plan with
    // `WinnV3SessionPlan.from` and then read `promotionEstablishRefusal()`; they
    // are rewritten because the guard MOVED (see [refusalFor]). The IPv6
    // fail-closed sink is now guarded symmetrically with the inner IPv6 address
    // inside `WinnV3Posture.promotion`, and since `from()` always installs the
    // sink, a plan whose floor (`inner_mtu`) is below RFC 8200's 1280 floor is
    // refused at CONSTRUCTION — `WinnV3SessionPlan.from` throws `WinnV3PostureRefusal`
    // — rather than being built and then refused by
    // `promotionEstablishRefusal()`. The dead-zone invariant is unchanged (it
    // must refuse, and refuse before any tunnel exists); it is simply enforced
    // one layer earlier, which is the "impossible rather than handled" shape the
    // sink-floor defect asked for.

    @Test
    fun `a dead-zone path MTU still cannot install the promotion posture`() {
        // The other half, and the reason the test above is not a weakening: the
        // guard itself must still fire. 1280 is the low edge of the dead zone —
        // reachable only by an operator setting path_mtu by hand, since nothing
        // defaults there any more.
        val e = refusalFor(1280)
        assertEquals(1139, WinnV3Sizing.planFloorInnerMtu(1280, WinnV3Sizing.CARRIER_CLASSES))
        assertTrue(
            "the refusal must name RFC 8200's 1280 floor; it said:\n${e.message}",
            e.message!!.contains("1280"),
        )
    }

    @Test
    fun `the posture refusal names the sink, the floor and the symptom`() {
        // path_mtu 1280 by hand: the default no longer lands in the dead zone, so
        // the refusal has to be provoked rather than inherited.
        val refusal = refusalFor(1280).message!!
        // The posture cannot name path_mtu or the plan-floor chain (it only receives
        // inner_mtu), but it must name the address that would be rejected and the
        // floor below which no Linux kernel attaches it — which is what the operator
        // sees when a version of this guard was not in place.
        for (needle in listOf(
            "1280-byte link floor",
            "Cannot set address",           // the symptom they will have seen in logcat
            VpnTunnelService.IPV6_FAIL_CLOSED_SINK, // the address actually refused
        )) {
            assertTrue(
                "the refusal must name '$needle'; it said:\n$refusal",
                refusal.contains(needle),
            )
        }
    }

    @Test
    fun `a configuration that can promote is not refused`() {
        // THE OVER-FIRE CONTROL. `cmd/winn3-gateway`'s preflight ships with
        // TestAValidConfigurationIsNotRefused for the same reason: a preflight
        // that refuses everything passes every test that only checks it refuses,
        // and it would take the working 1500-byte configuration — the one the
        // 4.86 MB carry run used — down with the broken one.
        val wide = plan(baseSection() + ("path_mtu" to "1500"))
        assertEquals(1359, wide.innerMtu)
        assertNull(
            "a 1500-byte path clears the floor at 1359 and must start",
            wide.promotionEstablishRefusal(),
        )
        for (pathMtu in listOf(1421, 1422, 1450, 1500, 9000)) {
            assertNull(
                "path_mtu $pathMtu clears the v6 link floor and must not be refused",
                plan(baseSection() + ("path_mtu" to "$pathMtu")).promotionEstablishRefusal(),
            )
        }
    }

    @Test
    fun `the boundary is exactly the plan floor crossing 1280`() {
        // Derived on both sides rather than tabulated: the refusal must fire on
        // exactly the path MTUs whose plan floor is below the v6 link floor, and
        // on no others. 1421 is where [udp, tcp, tls] crosses, because the
        // narrowest class is TLS over IPv6 at 112 bytes of overhead.
        val classes = WinnV3Sizing.CARRIER_CLASSES
        assertEquals(1280, WinnV3Sizing.planFloorInnerMtu(1421, classes))
        assertEquals(1279, WinnV3Sizing.planFloorInnerMtu(1420, classes))
        for (pathMtu in 1280..1500) {
            val expectRefusal = !WinnV3Sizing.planCarriesInnerIpv6(pathMtu, classes)
            val refused = try {
                plan(baseSection() + ("path_mtu" to "$pathMtu"))
                false
            } catch (ref: WinnV3PostureRefusal) {
                true
            }
            assertEquals(
                "path_mtu $pathMtu: plan floor ${WinnV3Sizing.planFloorInnerMtu(pathMtu, classes)}",
                expectRefusal,
                refused,
            )
        }
    }

    @Test
    fun `the whole accepted range below the threshold is a dead zone`() {
        // The shape of the defect, stated once. `from` accepts 1280..9000; the
        // platform can install the promotion posture only from 1421 up. Every
        // value in between resolves, builds two postures, and could never
        // promote — which is why the check exists rather than a comment. Since
        // 2026-08-10 each such value is refused at CONSTRUCTION by the posture's
        // symmetric sink guard, so the dead set is those that throw.
        val dead = (1280..1420).filter {
            try {
                plan(baseSection() + ("path_mtu" to "$it"))
                false
            } catch (ref: WinnV3PostureRefusal) {
                true
            }
        }
        assertEquals("every accepted path_mtu below 1421 is unpromotable", 141, dead.size)
        assertEquals(1280, dead.first())
        assertEquals(1420, dead.last())
    }

    @Test
    fun `the posture refusal names the address the platform rejects`() {
        // The sink is an IPv6 address and the posture refuses to let a sub-1280
        // plan attempt to install it. The refusal must name that address — the
        // one `VpnService.Builder.establish()` would otherwise reject with
        // "Cannot set address".
        val e = refusalFor(1280)
        assertTrue(
            "the refusal must name the sink the platform would reject; it said:\n${e.message}",
            e.message!!.contains(VpnTunnelService.IPV6_FAIL_CLOSED_SINK),
        )
    }

    // ------------------------------------------------------------------
    // The two postures.
    // ------------------------------------------------------------------

    @Test
    fun `the bootstrap posture captures nothing`() {
        val record = plan().bootstrap.applyTo(null)
        assertEquals(1, record.addresses.size)
        assertEquals(32, record.addresses.first().prefixLength)
        assertEquals("at most one route", 1, record.routes.size)
        assertFalse("no default route on an unproven datapath", record.hasDefaultRoute())
        assertFalse("no IPv6 anything", record.hasAnyIpv6())
        assertTrue("no resolver may depend on an unproven tunnel", record.dnsServers.isEmpty())
        assertEquals(1309, record.mtu) // 1139 until the default moved on 2026-08-10
        // And the whole thing passes the narrowness check it will be given.
        WinnV3Posture.verifyNarrow(record, requireExclusion = true)
    }

    @Test
    fun `the bootstrap route is the inner next hop`() {
        val record = plan().bootstrap.applyTo(null)
        assertEquals(
            "the one route must be the inner next hop",
            WinnV3Route("10.8.1.1", 32), record.routes.single(),
        )
        val overridden = plan(section = baseSection() + ("inner_next_hop" to "10.9.9.9"))
        assertEquals(
            WinnV3Route("10.9.9.9", 32),
            overridden.bootstrap.applyTo(null).routes.single(),
        )
    }

    /**
     * The sibling of the Apple defect, on this platform, in the exact shape
     * `VpnTunnelService` produced it.
     *
     * It read the resolver out of the AmneziaWG document and defaulted it —
     * `parseConfigValue(awgConfig, "DNS") ?: "10.8.1.1"` — and handed that to a
     * standalone v3 plan. `10.8.1.1` is an address in the v1 inner space AND,
     * for a configuration that names no `inner_next_hop`, it becomes the
     * bootstrap's next hop as well, which is documented as carrying PMTU
     * signals only and answers no queries.
     *
     * So the promoted posture pointed every name lookup either at an address
     * the winn/3 tun layer drops or at one that answers nothing, while the
     * routes moved onto the tunnel and the gate reported carrying. The
     * `dnsServers.isNotEmpty()` clause that already existed cannot see it: a
     * resolver was named.
     */
    @Test
    fun `a v1 shaped resolver is refused for a standalone session`() {
        // No inner_next_hop, so it defaults to the resolver, which is exactly
        // what the old VpnTunnelService default produced.
        val e = assertThrows(WinnV3PostureRefusal::class.java) {
            WinnV3SessionPlan.from(
                section = baseSection(),
                relayInnerAddress = "10.8.1.3",
                dnsServers = listOf("10.8.1.1"),
                promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
                ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
            )
        }
        assertTrue(e.message, e.message!!.contains("PMTU"))
    }

    /** The Apple half of the same defect, measured on this host's derivation. */
    @Test
    fun `a public resolver is refused for a standalone session`() {
        val e = assertThrows(WinnV3PostureRefusal::class.java) {
            WinnV3SessionPlan.from(
                section = baseSection() + ("inner_next_hop" to "10.8.1.1"),
                relayInnerAddress = "10.8.1.3",
                // What lib/main.dart's Apple fallback writes, and what a served
                // AmneziaWG document can carry on any platform.
                dnsServers = listOf("9.9.9.9", "149.112.112.112"),
                promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
                ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
            )
        }
        assertTrue(e.message, e.message!!.contains("PUBLIC"))
    }

    /**
     * A MIXED list is refused rather than filtered, which is the same claim
     * `winn3_posture.h` makes with one boolean over the whole of `dns_servers`.
     * `Builder.addDnsServer` hands every entry to the platform resolver, and
     * the platform — not this code — picks which one answers.
     */
    @Test
    fun `one derivable resolver does not license the public one beside it`() {
        val e = assertThrows(WinnV3PostureRefusal::class.java) {
            WinnV3SessionPlan.from(
                section = baseSection() + ("inner_next_hop" to "10.8.1.1"),
                relayInnerAddress = "10.8.1.3",
                dnsServers = listOf("10.8.1.53", "9.9.9.9"),
                promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
                ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
            )
        }
        assertTrue(e.message, e.message!!.contains("PUBLIC"))
        assertEquals(
            "the derivation still identifies WHICH member is inner; it simply does not " +
                "promote on the remainder",
            listOf("10.8.1.53"),
            WinnV3Resolvers.inner(listOf("10.8.1.53", "9.9.9.9"), "10.8.1.3", "10.8.1.1"),
        )
    }

    @Test
    fun `a format v3 served config installs only its signed inner resolver`() {
        val served = parseIniSection(SERVED_WINN_SECTION, "winn")
        val plan = WinnV3SessionPlan.from(
            section = served,
            relayInnerAddress = "10.8.1.3",
            dnsServers = listOf("9.9.9.9"),
            promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
            ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
        )
        assertEquals(listOf("10.10.0.1"), plan.promotion.applyTo(null).dnsServers)
    }

    /**
     * The v1 fallback must not be reachable from the v3 path at all.
     *
     * A grep, and it is the only thing that can hold this: the defect was a
     * DEFAULT crossing a protocol boundary, and a host that reintroduced it
     * would compute every number on the way there correctly.
     */
    @Test
    fun `the v3 start is not handed the v1 resolver fallback`() {
        val service = readMainSource("VpnTunnelService.kt")
        assertTrue(
            "the v3 thread must take a candidate LIST, not the v1 dnsServer with its " +
                "10.8.1.1 default folded in",
            service.contains("resolverCandidates = winn3ResolverCandidates"),
        )
        assertTrue(
            "and startWinnV3EngineThread declares a candidate list rather than one resolver",
            service.contains("resolverCandidates: List<String>"),
        )
        assertFalse(
            "the v3 thread's body must not mention the v1 dnsServer at all — the relay's own " +
                "start still uses it, and that is correct, but it must not cross the boundary",
            Regex("\\bdnsServer\\b").containsMatchIn(
                functionBodyOf(service, "private fun startWinnV3EngineThread"),
            ),
        )
        assertTrue(
            "and the candidate list is the [Interface] DNS line with NO fallback",
            service.contains("val winn3ResolverCandidates: List<String> = parseConfigValue("),
        )
    }

    @Test
    fun `the promotion posture installs the shared IPv6 fail-closed sink`() {
        val record = plan().promotion.applyTo(null)
        assertTrue(
            "host IPv6 must not keep egressing beside a promoted v4 tunnel",
            record.addresses.any { it.address == VpnTunnelService.IPV6_FAIL_CLOSED_SINK },
        )
        assertTrue("the sink needs ::/0 to blackhole anything",
            record.routes.any { it.address == "::" && it.prefixLength == 0 })
        assertTrue("promotion installs the inner resolvers", record.dnsServers.isNotEmpty())
        assertTrue("promotion captures the route set", record.routes.size > 1)
    }

    @Test
    fun `the sink address is the one the v1 builder installs`() {
        // Two establish paths now exist. Two copies of a fail-closed address is
        // how one of them quietly stops being fail-closed, so the constant is
        // asserted to be the literal the v1 builder actually uses.
        val service = readMainSource("VpnTunnelService.kt")
        assertEquals(
            "the v1 builder must install the shared constant, not its own literal",
            1,
            Regex("addAddress\\(IPV6_FAIL_CLOSED_SINK, 128\\)").findAll(service).count(),
        )
        assertEquals("fd00:d951:0001::1", VpnTunnelService.IPV6_FAIL_CLOSED_SINK)
    }

    // ------------------------------------------------------------------
    // The anti-downgrade gate.
    // ------------------------------------------------------------------

    @Test
    fun `the v1 config builder refuses a v3 section`() {
        val thrown = runCatching {
            WinnEngineConfig.from(
                section = baseSection() + ("enabled" to "true"),
                mtu = 1280,
            )
        }.exceptionOrNull()
        assertNotNull("a v3 section reaching the v1 builder must refuse", thrown)
        val message = thrown!!.message.orEmpty()
        assertTrue(message, message.contains("silent downgrade"))
        assertTrue(message, message.contains(WinnEngineConfig.PAYLOAD_AWG_DATAGRAM))
    }

    @Test
    fun `the v1 config builder still accepts a v1 section`() {
        // The regression guard on the gate above: adding it must not have made
        // every existing deployment refuse to start.
        val config = WinnEngineConfig.from(
            section = mapOf("enabled" to "true", "endpoint" to "203.0.113.7:51820"),
            mtu = 1280,
        )
        assertTrue(config.toConfigJson().contains(WinnEngineConfig.PAYLOAD_AWG_DATAGRAM))
    }

    @Test
    fun `the v1 config builder refuses an unknown protocol value`() {
        val thrown = runCatching {
            WinnEngineConfig.from(
                section = mapOf(
                    "enabled" to "true", "endpoint" to "203.0.113.7:51820", "protocol" to "2",
                ),
                mtu = 1280,
            )
        }.exceptionOrNull()
        assertNotNull("protocol=2 is neither v1 nor v3 and must not default", thrown)
    }

    // ------------------------------------------------------------------
    // The argv.
    // ------------------------------------------------------------------

    @Test
    fun `the v3 argv is the v1 argv plus the flag and nothing else`() {
        val v1 = WinnAndroidEngineHost.engineArguments("/lib/libwinnengine.so", "chan")
        val v3 = WinnV3Host.engineArguments("/lib/libwinnengine.so", "chan")
        assertEquals(v1 + WinnV3Host.FLAG_WINN3, v3)
        assertFalse("the v1 argv must never carry the v3 flag", v1.contains(WinnV3Host.FLAG_WINN3))
        // Nothing positional: flags.NArg() != 0 is fatal to the engine.
        assertEquals("/lib/libwinnengine.so", v3.first())
        assertTrue(v3.drop(1).none { !it.startsWith("-") && !v3[v3.indexOf(it) - 1].startsWith("-") })
    }

    @Test
    fun `the v3 argv carries the key document the engine demands`() {
        val argv = WinnV3Host.engineArguments("/lib/e.so", "chan", null, "/data/winn3-keys.json")
        // The engine states its own full argv in its refusal message, and this
        // is that argv:
        //   -transport unix -control @NAME -receive-fd -winn3 -winn3-keys PATH
        assertEquals(
            listOf(
                "/lib/e.so", "-transport", "unix", "-control", "@chan", "-receive-fd",
                "-winn3", "-winn3-keys", "/data/winn3-keys.json",
            ),
            argv,
        )
        assertTrue(argv.contains(WinnV3Host.FLAG_WINN3_KEYS))
    }

    @Test
    fun `a blank key document path is refused rather than built into an argv`() {
        val thrown = runCatching {
            WinnV3Host.engineArguments("/lib/e.so", "chan", null, "   ")
        }.exceptionOrNull()
        assertNotNull("a blank path makes the engine exit before a frame crosses", thrown)
    }

    // ------------------------------------------------------------------
    // The key document. It names paths and holds no material.
    // ------------------------------------------------------------------

    @Test
    fun `a section with no v3 key material is refused by name`() {
        val thrown = runCatching { WinnV3Keys.from(baseSection()) }.exceptionOrNull()
        assertNotNull("v3 has no anonymous mode", thrown)
        val message = thrown!!.message.orEmpty()
        assertTrue(message, message.contains(WinnV3Keys.KEY_STATIC))
        assertTrue(message, message.contains(WinnV3Keys.KEY_GATEWAY_STATIC))
        assertTrue("it must not offer a v1 fallback", message.contains("silent downgrade"))
    }

    @Test
    fun `key material that is not base64 over exactly 32 bytes is refused`() {
        for (
            bad in listOf(
                "",
                "ab",
                // Valid base64, WRONG LENGTH — 48 bytes and 30. This is the case
                // a length check exists for: X25519 has exactly one length, and
                // a key of any other produces a handshake that fails for a
                // reason no log on either side names.
                "z".repeat(64),
                "Hx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8=",
                "ab".repeat(33),
                // THE STALE SPELLING. 64 lowercase hex characters is what this
                // host read until 2026-08-09 and what a lab config written
                // against it still carries. It is also valid base64 of 48 bytes,
                // so nothing about it is self-evidently wrong — which is exactly
                // why the length check has to be the thing that catches it
                // rather than the decoder.
                "1f".repeat(32),
                // URL-safe base64. The descriptor never uses it, and a lenient
                // decoder that accepted it would silently produce different key
                // bytes for two values an operator would call the same.
                "Hx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8-",
            )
        ) {
            val thrown = runCatching {
                WinnV3Keys.from(keySection() + (WinnV3Keys.KEY_STATIC to bad))
            }.exceptionOrNull()
            assertNotNull("'${bad.take(8)}...' must be refused", thrown)
        }
    }

    @Test
    fun `the gateway id is decoded exactly once and the admission secret not at all`() {
        val keys = WinnV3Keys.from(keySection())
        val dir = File(
            System.getProperty("java.io.tmpdir"),
            "winnv3-adoption-encoding-${System.nanoTime()}",
        )
        try {
            val json = keys.writeTo(dir).readText()

            // ONE decode of gateway_id: operator text in the document, and NOT
            // the six plausible bytes a second decode would produce. `gw-lab-1`
            // is not itself base64, so this fixture would fail LOUDLY on a
            // double decode — the reference operator name `winsgw01` is eight
            // characters of the base64 alphabet and would not.
            assertTrue(json, json.contains("\"gateway_id\":\"$GATEWAY_ID_TEXT\""))

            // ZERO further decodes of the admission secret. The file holds the
            // bytes the section carried under base64 and nothing else: hex-
            // decoding them keys 32 bytes against the gateway's 64, and that
            // failure BUILDS a session and then goes silent, which is worse
            // than a refusal because a host watching for "did the gateway see
            // me" sees yes.
            assertEquals(ADMISSION_SECRET, File(dir, "admission.key").readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a served standalone section selects v3 and supplies its own inner address`() {
        // THE DOCUMENT THE CONTROL PLANE ACTUALLY EMITS, byte for byte.
        //
        // Not a hand-built map: SERVED_WINN_SECTION is what
        // conform.ServedWinnSectionINI renders for the reference operator, and
        // winn3/conform's TestTheServedFixtureIsTheOneEveryHostParses greps this
        // file for every line of it. windows/runner/winn3_supervisor_test.cc and
        // linux/runner/linux_winn3_host_test.cc carry the same literal. A map
        // written by hand would agree with whatever this host happened to expect
        // and could not catch the contract moving.
        val served = parseIniSection(SERVED_WINN_SECTION, "winn")
        assertTrue(
            "a served config names carrier = winn3 and no `protocol` key at all; before " +
                "2026-08-09 this host took the v1 branch and refused it by carrier name",
            WinnV3SessionPlan.isRequested(served),
        )

        val plan = WinnV3SessionPlan.from(
            section = served,
            // The relay's address, deliberately DIFFERENT from inner_v4. If the
            // plan ever takes this one, the winn/3 tun layer drops every packet
            // the host offers and the session reports up while carrying nothing.
            relayInnerAddress = "10.8.1.3",
            // A public relay resolver is deliberately offered here. The signed
            // format-v3 inner_resolver_v4 must replace it outright.
            dnsServers = listOf("9.9.9.9"),
            promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
            ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
        )
        assertEquals("10.10.0.9", plan.engineConfig.innerAddress)
        assertEquals("10.10.0.1", plan.engineConfig.innerNextHop)
        assertEquals(listOf("10.10.0.1"), plan.promotion.applyTo(null).dnsServers)
        // The plan floor across udp+tcp+tls at a 1500-byte path, which is the
        // number winn3/conform pins for every host. 1443 here would be the
        // dialled UDP/IPv4 carrier — defect 2, 84 bytes too wide.
        assertEquals(1359, plan.innerMtu)

        // And the keys parse from the SAME section, with no v3_ prefixed field
        // anywhere in it. The gateway id reaches the key document as the
        // OPERATOR NAME, decoded exactly once here at the descriptor boundary.
        assertEquals(SERVED_GATEWAY_ID_TEXT, WinnV3Keys.from(served).let { keys ->
            val dir = File(
                System.getProperty("java.io.tmpdir"),
                "winnv3-served-${System.nanoTime()}",
            )
            try {
                val json = keys.writeTo(dir).readText()
                Regex("\"gateway_id\":\"([^\"]*)\"").find(json)?.groupValues?.get(1)
            } finally {
                dir.deleteRecursively()
            }
        })
    }

    @Test
    fun `a served standalone section binds the signed descriptor node`() {
        val served = parseIniSection(SERVED_WINN_SECTION, "winn")
        for (broken in listOf(
            served - WinnV3SessionPlan.KEY_DESCRIPTOR_NODE,
            served - WinnV3SessionPlan.KEY_SELECTED_NODE,
            served + (WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-beta"),
            served + ("location_slug" to "lab-beta"),
            served +
                (WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "k1") +
                (WinnV3SessionPlan.KEY_SELECTED_NODE to "\u212A1"),
        )) {
            val error = assertThrows(IllegalArgumentException::class.java) {
                WinnV3SessionPlan.from(
                    section = broken,
                    relayInnerAddress = "10.8.1.3",
                    dnsServers = listOf("9.9.9.9"),
                    promotionRoutes = listOf(WinnV3Route("0.0.0.0", 0)),
                    ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
                )
            }
            assertTrue(error.message.orEmpty().contains("node"))
            assertEquals(
                WinnV3SessionPlan.DESCRIPTOR_NODE_BINDING_REFUSAL,
                error.message,
            )
        }
    }

    @Test
    fun `a section naming no path mtu plans at the same default every other host uses`() {
        // The fleet default. This host defaulted to 1500 until 2026-08-09,
        // which put it in the WIDE mismatch regime against a gateway at its own
        // default: the session never carries at all and neither end says why.
        //
        // RAISED 1280 -> 1450 ON 2026-08-10, with every other entry point.
        // carrier.DefaultPathMTU and tun.IPv6MinLinkMTU used to be the same
        // number and are now deliberately not: the second is RFC 8200's floor
        // for the INNER link and is still 1280, while 1280 as an OUTER planning
        // number floors this plan at 1139 inner -- below that same floor, so no
        // kernel will put IPv6 on the interface (ipv6_add_dev returns -EINVAL)
        // and the session carries but can never promote. winn3/conform's
        // TestEveryEntryPointDefaultsThroughTheOneConstant is what now pins the
        // four hosts together.
        assertEquals(1450, WinnV3SessionPlan.DEFAULT_PATH_MTU)
        val plan = plan(keySection())
        assertEquals(
            "a 1450-byte path over [udp,tcp,tls] floors at 1309, not at 1139 or 1359",
            1309, plan.innerMtu,
        )
        assertTrue(
            "the plan floor at the fleet default must clear RFC 8200's minimum link MTU, " +
                "or every default session is back in the dead zone",
            plan.innerMtu >= WinnV3Sizing.IPV6_MIN_LINK_MTU,
        )
    }

    @Test
    fun `the key document names paths and contains no key material`() {
        val dir = File(
            System.getProperty("java.io.tmpdir"),
            "winnv3-adoption-keys-${System.nanoTime()}",
        )
        try {
            val document = WinnV3Keys.from(keySection()).writeTo(dir)
            val json = document.readText()
            assertTrue(json, json.contains("\"version\":\"${WinnV3Keys.VERSION}\""))
            assertTrue(json, json.contains("\"role\":\"${WinnV3Keys.ROLE_CLIENT}\""))
            // StrictPQ, because harvest-now-decrypt-later is a live threat here.
            assertTrue(json, json.contains("\"fast_pq\":false"))
            // Zero: the field may only make the ratchet turn MORE often, so a
            // host with no opinion must not invent a number.
            assertTrue(json, json.contains("\"rekey_after_messages\":0"))
            assertFalse(
                "the document must name paths, never the material itself",
                json.contains(STATIC_HEX) || json.contains(GATEWAY_HEX) ||
                    json.contains(ADMISSION_SECRET) || json.contains(STATIC_B64) ||
                    json.contains(GATEWAY_B64) || json.contains(ADMISSION_B64),
            )
            // The gateway id is the ONE field the document carries as a value,
            // and it carries the OPERATOR TEXT — decoded exactly once, here, at
            // the descriptor boundary. The engine computes the admission tag
            // over these bytes and never transmits them, so a second decode
            // anywhere produces a tag no gateway can verify and a silence
            // nothing distinguishes from a censored path.
            assertTrue(json, json.contains("\"gateway_id\":\"$GATEWAY_ID_TEXT\""))
            assertFalse(
                "the base64 transport encoding must not survive into the key document",
                json.contains(GATEWAY_ID_B64),
            )
            // And the material really was written, verbatim where the engine
            // reads it verbatim.
            assertEquals(STATIC_HEX, File(dir, "static.key").readText())
            assertEquals(GATEWAY_HEX, File(dir, "gateway.pub").readText())
            assertEquals(
                "the engine does not hex-decode the admission file",
                ADMISSION_SECRET, File(dir, "admission.key").readText(),
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `plaintext key material is generation scoped and destroyable after create ack`() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "winnv3-adoption-key-lifetime-${System.nanoTime()}",
        )
        val first = WinnV3Keys.keyDirectory(root, generation = 7, startToken = 101L)
        val successor = WinnV3Keys.keyDirectory(root, generation = 8, startToken = 102L)
        assertFalse(first.absolutePath == successor.absolutePath)

        val keys = WinnV3Keys.from(keySection())
        try {
            keys.writeTo(first)
            keys.writeTo(successor)
            assertTrue(File(first, "static.key").isFile)
            assertTrue(File(first, "admission.key").isFile)
            assertTrue(keys.destroy(first))
            assertTrue(first.isDirectory)
            assertEquals(0L, File(first, "static.key").length())
            assertEquals(0L, File(first, "admission.key").length())
            assertTrue(
                "a stale generation cleanup must not touch its successor",
                File(successor, "admission.key").isFile,
            )
            assertTrue(keys.destroy(successor))
            assertTrue(successor.isDirectory)
            assertEquals(0L, File(successor, "static.key").length())
            assertEquals(0L, File(successor, "admission.key").length())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `key cleanup refuses unknown children instead of deleting them`() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "winnv3-adoption-key-unknown-${System.nanoTime()}",
        )
        val directory = WinnV3Keys.keyDirectory(root, generation = 9, startToken = 103L)
        val keys = WinnV3Keys.from(keySection())
        try {
            keys.writeTo(directory)
            val unknown = File(directory, "unexpected")
            unknown.writeText("do-not-delete")
            assertTrue(keys.destroy(directory))
            assertTrue(unknown.isFile)
            assertEquals("do-not-delete", unknown.readText())
            assertEquals(0L, File(directory, "static.key").length())
            assertEquals(0L, File(directory, "admission.key").length())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `the recorded banner from the real android engine passes the probe`() {
        // Captured verbatim from `libwinnengine.so -print-contract` after a
        // GOOS=android GOARCH=arm64 cross-build, executed on an API 34
        // emulator. Pinned so that a change to either side of the probe shows
        // up here rather than as a refusal on a handset.
        assertTrue(
            "the real engine's real banner must pass the capability probe",
            WinnV3Host.engineSupportsV3(REAL_ANDROID_BANNER),
        )
        // The shipping banner that predates the payloads field must not, and
        // its prose names both payloads in English, which is the trap.
        assertFalse(
            WinnV3Host.engineSupportsV3(
                """{"contract":"winn-datapath/1","payload_semantics":"inbound and outbound """ +
                    """frames carry AmneziaWG outer datagrams, not raw IP packets"}"""
            ),
        )
    }

    // ------------------------------------------------------------------
    // The seam across a promotion. This is the behaviour that only shows up
    // on a handset, so it is the behaviour most worth pinning here.
    // ------------------------------------------------------------------

    @Test
    fun `a rebind does not strand the pump on the dead interface`() {
        // The old device models a deactivated tun descriptor whose blocked read
        // never returns -- which is the case the naive swappable-reference
        // implementation gets wrong, and which cannot be reproduced off-device.
        val stuck = BlockingDevice()
        val seam = WinnV3AndroidIpPacketSeam(stuck)
        try {
            val live = ScriptedDevice(listOf(byteArrayOf(0x45, 1, 2, 3)))
            seam.rebindDevice(live)

            val buffer = ByteArray(2048)
            val n = readWithin(seam, buffer, 3_000)
            assertEquals("the packet from the NEW device must reach the pump", 4, n)
            assertEquals(0x45.toByte(), buffer[0])
        } finally {
            seam.close()
            stuck.release()
        }
    }

    @Test
    fun `a rebind closes the device it replaced`() {
        val first = ScriptedDevice(emptyList())
        val seam = WinnV3AndroidIpPacketSeam(first)
        try {
            val second = ScriptedDevice(emptyList())
            seam.rebindDevice(second)
            assertTrue("the replaced descriptor must not be leaked", first.closed.get())
            assertFalse("the live descriptor must stay open", second.closed.get())
        } finally {
            seam.close()
        }
    }

    @Test
    fun `the outbound queue drops rather than growing without bound`() {
        val device = ScriptedDevice(List(64) { byteArrayOf(0x45, it.toByte()) }, keepOpen = true)
        val seam = WinnV3AndroidIpPacketSeam(device, queueDepth = 4)
        try {
            // Nothing drains, so everything past the depth must be dropped and
            // counted -- not buffered until the process is OOM-killed.
            val deadline = System.currentTimeMillis() + 3_000
            while (seam.droppedCount() == 0L && System.currentTimeMillis() < deadline) {
                Thread.sleep(10)
            }
            assertTrue("overflow must be dropped and counted", seam.droppedCount() > 0)
        } finally {
            seam.close()
            device.release()
        }
    }

    @Test
    fun `an inbound packet goes to the device installed at that instant`() {
        val first = ScriptedDevice(emptyList())
        val seam = WinnV3AndroidIpPacketSeam(first)
        try {
            seam.writeIncomingPacket(byteArrayOf(1, 2, 3), 3)
            assertEquals(1, first.written.size)
            val second = ScriptedDevice(emptyList())
            seam.rebindDevice(second)
            seam.writeIncomingPacket(byteArrayOf(4, 5), 2)
            assertEquals("after promotion it is the promoted interface", 1, second.written.size)
            assertEquals("and not the replaced one", 1, first.written.size)
        } finally {
            seam.close()
        }
    }

    @Test
    fun `the pump buffer is sized from the interface MTU`() {
        assertEquals(1359, WinnV3Bridge.bufferSizeFor(1359))
        assertEquals(
            "never below the IPv4 floor, whatever it is handed",
            WinnV3Sizing.MIN_INNER_MTU_V4, WinnV3Bridge.bufferSizeFor(0),
        )
        assertEquals(
            "never above what one frame can carry",
            WinnFraming.MAX_PAYLOAD_BYTES, WinnV3Bridge.bufferSizeFor(1_000_000),
        )
    }

    // ------------------------------------------------------------------
    // Source-level invariants. These are the ones a future edit breaks
    // silently, so they are asserted against the source rather than behaviour.
    // ------------------------------------------------------------------

    @Test
    fun `the v3 start never hands the tun to AmneziaWG`() {
        val body = functionBodyOf(
            readMainSource("VpnTunnelService.kt"),
            "private fun startWinnV3EngineThread(",
        )
        for (v1Call in listOf("awgTurnOn", "startAwgEngine", "WinnAwgLoopbackSeam", "detachFd")) {
            assertFalse(
                "the whole point of v3 adoption is that the tun fd goes to the frame device; " +
                    "found '$v1Call' in the v3 start",
                body.contains(v1Call),
            )
        }
        assertTrue("the tun must reach the v3 seam", body.contains("WinnV3AndroidIpPacketSeam("))
        assertTrue("promotion must rebind rather than restart", body.contains("rebindDevice("))
        assertTrue("the bootstrap posture must be verified, not trusted",
            body.contains("verifyNarrow("))
    }

    @Test
    fun `the v3 start publishes typed native verdicts and never connectivity_failed`() {
        val service = stripComments(readMainSource("VpnTunnelService.kt"))
        val body = stripComments(
            functionBodyOf(service, "private fun startWinnV3EngineThread("),
        )
        assertFalse(
            "a timeout must not authorize AWG/Xray cover",
            service.contains("connectivity_failed"),
        )
        assertFalse(service.contains("security_refused"))
        assertTrue(body.contains("inspectBridge"))
        assertTrue(body.contains("snapshot()"))
        assertTrue(body.contains("failureCause()"))
        assertTrue(body.contains("ordinaryNetworkPosixErrno()"))
        assertTrue(body.contains("ordinaryNetworkFailure()"))
        assertTrue(body.contains("isRunning()"))
        assertTrue(body.contains("failure()"))
        assertTrue(body.contains("WinnV3NativeVerdict.CONNECTED"))
        assertTrue(body.contains("WinnV3NativeVerdictClassifier"))
        assertTrue(body.contains("probeProtectedSocketErrno"))
        assertTrue(body.contains("captureWinnV3ProtectedSocketErrno"))
        assertTrue(service.contains("lastWinn3AwgXrayAuthorizationToken"))
        val probe = functionBodyOf(service, "private fun captureWinnV3ProtectedSocketErrno(")
        // A UDP connect() captures synchronous route and connect errors and
        // sends no datagram. The 1-byte datagram it replaced opened a second
        // gateway session on every connect.
        assertTrue(probe.contains("Os.connect("))
        assertFalse(probe.contains("Os.sendto"))
        assertFalse(probe.contains("ByteArray("))
        assertTrue(probe.contains("ErrnoException"))
        assertTrue(probe.contains("protect("))
        assertTrue(probe.contains("Os.close"))
        assertTrue(probe.contains("Os.socket"))
        assertTrue(probe.contains("getByAddress"))
        assertFalse(probe.contains("DatagramChannel"))
        assertFalse(probe.contains("getByName"))
        assertFalse(probe.contains(".message"))
        val activity = stripComments(readMainSource("MainActivity.kt"))
        assertTrue(activity.contains("VpnTunnelService.currentWinn3ReadinessSnapshot()"))
        assertTrue(activity.contains("\"winn3_verdict\" to winn3Readiness.state"))
        assertTrue(activity.contains("\"winn3_start_generation\" to"))
        assertTrue(activity.contains("winn3Readiness.startGeneration"))
        assertTrue(activity.contains("\"winn3_awg_xray_authorization_token\" to"))
        assertTrue(activity.contains("winn3Readiness.awgXrayAuthorizationToken"))
        assertTrue(activity.contains("putExtra(\"WINN3_START_GENERATION\""))
    }

    @Test
    fun `readiness publication is atomic with live tunnel ownership`() {
        val service = readMainSource("VpnTunnelService.kt")

        val awgStart = functionBodyOf(service, "private fun startAwgEngineThread(")
        val awgPublish = functionBodyOf(
            awgStart,
            "val readyPublished = synchronized(winnEngineLock)",
        )
        assertTrue(awgPublish.contains("tearingDown"))
        assertTrue(awgPublish.contains("generation != tunnelGeneration"))
        assertTrue(awgPublish.contains("currentAwgHandle() != handle"))
        assertTrue(awgPublish.contains("isEngineReady = true"))
        assertTrue(awgPublish.contains("engineReadyAtMs = SystemClock.elapsedRealtime()"))

        val v1Start = functionBodyOf(service, "private fun startWinnEngineThread(")
        val v1Publish = functionBodyOf(
            v1Start,
            "val readyPublished = synchronized(winnEngineLock)",
        )
        assertTrue(v1Publish.contains("tearingDown"))
        assertTrue(v1Publish.contains("generation != tunnelGeneration"))
        assertTrue(v1Publish.contains("winnBridge !== created"))
        assertTrue(v1Publish.contains("currentAwgHandle() != awgHandle"))
        assertTrue(v1Publish.contains("isEngineReady = true"))
        assertTrue(v1Publish.contains("engineReadyAtMs = SystemClock.elapsedRealtime()"))

        val v3Start = functionBodyOf(service, "private fun startWinnV3EngineThread(")
        val v3Publish = functionBodyOf(
            v3Start,
            "val connectedPublished = synchronized(winnEngineLock)",
        )
        assertTrue(v3Publish.contains("tearingDown"))
        assertTrue(v3Publish.contains("generation != tunnelGeneration"))
        assertTrue(v3Publish.contains("isEngineReady = true"))
        assertTrue(v3Publish.contains("completeWinn3Start("))
        assertTrue(v3Publish.contains("WinnV3NativeVerdict.CONNECTED"))
        assertTrue(v3Publish.contains("engineReadyAtMs = SystemClock.elapsedRealtime()"))
    }

    @Test
    fun `the service refuses v3 before publishing or starting when identities are absent`() {
        val body = stripComments(
            functionBodyOf(
                readMainSource("VpnTunnelService.kt"),
                "override fun onStartCommand(",
            ),
        )
        val identityCheck = body.indexOf(
            "winn3StartToken <= 0L || winn3StartGeneration <= 0L",
        )
        val begin = body.indexOf("beginWinn3Start(")
        val nativeStart = body.indexOf("startWinnV3EngineThread(")
        assertTrue("the service must validate exact positive v3 identities", identityCheck >= 0)
        assertTrue("the service must publish a pending verdict after validation", begin >= 0)
        assertTrue("identity validation must precede verdict publication", identityCheck < begin)
        assertTrue("identity validation must precede native allocation", identityCheck < nativeStart)
        assertTrue(body.contains("return START_NOT_STICKY"))
    }

    @Test
    fun `the v3 start gates on the packaged engine before it allocates anything`() {
        val body = functionBodyOf(
            readMainSource("VpnTunnelService.kt"),
            "private fun startWinnV3EngineThread(",
        )
        val probe = body.indexOf("probeV3Support()")
        val establish = body.indexOf("builder.establish()")
        assertTrue("the capability probe must exist", probe >= 0)
        assertTrue("and must run before any interface is established", probe < establish)
        assertTrue("its failure must be the documented refusal",
            body.contains("WinnV3Host.capabilityRefusal("))
    }

    @Test
    fun `a v3 spawn without a key document is refused before a process exists`() {
        val body = functionBodyOf(
            readMainSource("WinnAndroidEngineHost.kt"),
            "override fun startEngineProcess(): WinnEngineProcess",
        )
        assertTrue(
            "the engine refuses -winn3 without -winn3-keys, so spawning anyway produces a " +
                "subprocess that exits 1 with a message only logcat sees",
            body.contains("winn3 && winn3KeysPath.isNullOrBlank()"),
        )
        val refusal = body.indexOf("winn3KeysPath.isNullOrBlank()")
        val spawn = body.indexOf("builder.start()")
        assertTrue("the refusal must precede the spawn", refusal in 0 until spawn)
    }

    @Test
    fun `adoption added no Error-catching clause`() {
        // The two landmines this codebase has already hit were both an Error
        // walking past a catch (Exception). Adoption's API-33 call is guarded
        // by a version check instead, so none of the v3 adoption execution
        // files may catch Error. Do not assert an app-wide count here: startup
        // compatibility and private-file probes have their own reviewed Error
        // catches and are outside this adoption invariant.
        val offenders = mutableMapOf<String, Int>()
        for (file in mainKotlinSources().filter {
            it.name in setOf("WinnV3AndroidTun.kt", "WinnV3Bridge.kt", "WinnV3SessionPlan.kt")
        }) {
            val hits = Regex("catch\\s*\\([^)]*:\\s*(Throwable|Error|NoClassDefFoundError|" +
                "UnsatisfiedLinkError|NoSuchMethodError)\\s*\\)")
                .findAll(stripComments(file.readText())).count()
            if (hits > 0) offenders[file.name] = hits
        }
        for (added in listOf("WinnV3AndroidTun.kt", "WinnV3Bridge.kt", "WinnV3SessionPlan.kt")) {
            assertNull("$added must catch no Error", offenders[added])
        }
    }

    @Test
    fun `the API 33 exclusion call is guarded by a version check and not a catch`() {
        val body = functionBodyOf(
            readMainSource("WinnV3AndroidTun.kt"),
            "override fun excludeRoute(address: String, prefixLength: Int): Boolean",
        )
        assertTrue(
            "excludeRoute is API 33 and IpPrefix's constructor is API 31; both raise an " +
                "Error on an older runtime, which a catch (Exception) does not see",
            body.contains("Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU"),
        )
        val guard = body.indexOf("Build.VERSION.SDK_INT")
        val call = body.indexOf("builder.excludeRoute(")
        assertTrue("the guard must precede the call", guard in 0 until call)
    }

    @Test
    fun `System loadLibrary was not introduced by adoption`() {
        for (added in listOf("WinnV3AndroidTun.kt", "WinnV3Bridge.kt", "WinnV3SessionPlan.kt")) {
            assertFalse(
                "ApiLevelGateTest pins System.loadLibrary to ensureAwgNativeLoaded",
                readMainSource(added).contains("System.loadLibrary"),
            )
        }
    }

    // ------------------------------------------------------------------
    // Doubles and helpers. Named for this file so they cannot collide with
    // the doubles the other v3 test files use.
    // ------------------------------------------------------------------

    private class BlockingDevice : WinnV3TunDevice {
        override val mtu: Int = 1359
        private val gate = CountDownLatch(1)
        override fun read(buffer: ByteArray): Int {
            // Models the descriptor a promotion just deactivated: blocked, and
            // never waking.
            gate.await()
            return -1
        }
        override fun write(packet: ByteArray, length: Int) = Unit
        override fun close() = Unit
        fun release() = gate.countDown()
    }

    private class ScriptedDevice(
        packets: List<ByteArray>,
        private val keepOpen: Boolean = false,
    ) : WinnV3TunDevice {
        override val mtu: Int = 1359
        private val pending = ArrayDeque(packets)
        private val gate = CountDownLatch(1)
        val written = mutableListOf<ByteArray>()
        val closed = AtomicBoolean(false)

        override fun read(buffer: ByteArray): Int {
            val next = synchronized(pending) { pending.removeFirstOrNull() }
            if (next != null) {
                System.arraycopy(next, 0, buffer, 0, next.size)
                return next.size
            }
            if (keepOpen) gate.await()
            return -1
        }

        override fun write(packet: ByteArray, length: Int) {
            synchronized(written) { written += packet.copyOf(length) }
        }

        override fun close() {
            closed.set(true)
            gate.countDown()
        }

        fun release() = gate.countDown()
    }

    private fun readWithin(
        seam: WinnV3AndroidIpPacketSeam,
        buffer: ByteArray,
        timeoutMs: Long,
    ): Int {
        var result = Int.MIN_VALUE
        val done = CountDownLatch(1)
        Thread {
            result = seam.readOutgoingPacket(buffer)
            done.countDown()
        }.apply { isDaemon = true; start() }
        assertTrue(
            "readOutgoingPacket did not return within ${timeoutMs}ms, which means the pump is " +
                "stranded on the interface the promotion replaced",
            done.await(timeoutMs, TimeUnit.MILLISECONDS),
        )
        return result
    }

    private companion object {
        // The KEY FILE contents the engine reads: 64 hex characters for each
        // X25519 key, and the admission secret's own bytes.
        val STATIC_HEX = "1f".repeat(32)
        val GATEWAY_HEX = "2e".repeat(32)
        const val ADMISSION_SECRET = "lab-admission-secret-padded-to-32-bytes"

        // The `[winn]` TRANSPORT encodings, which are what a served config
        // carries and what WinnV3Keys.from now reads: base64 over the 32 raw
        // key bytes, and base64 over the admission FILE's bytes. The two pairs
        // are deliberately stated separately rather than derived from each
        // other — a fixture that computed the expected file from the input
        // would agree with the code by construction and could not catch it
        // re-encoding.
        const val STATIC_B64 = "Hx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8="
        const val GATEWAY_B64 = "Li4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4uLi4="
        const val ADMISSION_B64 = "bGFiLWFkbWlzc2lvbi1zZWNyZXQtcGFkZGVkLXRvLTMyLWJ5dGVz"

        /** `gw-lab-1`, base64 — the encoding the signed descriptor carries. */
        const val GATEWAY_ID_B64 = "Z3ctbGFiLTE="
        const val GATEWAY_ID_TEXT = "gw-lab-1"

        /**
         * The served `[winn]` section, exactly as the control plane emits it.
         *
         * GENERATED, not composed: this is `conform.ServedWinnSectionINI` over
         * the reference operator, and winn3/conform's
         * `TestTheServedFixtureIsTheOneEveryHostParses` greps this file for
         * every line. `windows/runner/winn3_supervisor_test.cc` and
         * `linux/runner/linux_winn3_host_test.cc` carry the same text, so all
         * three hosts are demonstrably parsing ONE document rather than three
         * fixtures that happen to resemble each other.
         *
         * Every value is chosen to make a silent failure loud. `gateway_id` is
         * base64 over `winsgw01`, which is eight characters of the base64
         * alphabet — a host that decodes it TWICE gets six plausible bytes and
         * a gateway that never answers. `admission_key` is base64 over the key
         * file's 64 ASCII hex characters; base64 over the 32 bytes they encode
         * is the encoding that builds a session and then goes silent.
         */
        val SERVED_WINN_SECTION =
            """
            [winn]
            enabled = true
            carrier = winn3
            endpoint = 203.0.113.7:51820
            node = lab-alpha
            selected_node = lab-alpha
            inner_v4 = 10.10.0.9
            inner_router_v4 = 10.10.0.1
            inner_resolver_v4 = 10.10.0.1
            static_private = ERERERERERERERERERERERERERERERERERERERERERE=
            gateway_static = U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=
            gateway_id = d2luc2d3MDE=
            admission_key = NmYzOWEwYzFkMjRiN2U4ZjVhM2M5MDEyYjRkNmU4ZjAxYTJiM2M0ZDVlNmY3MDgxOTJhM2I0YzVkNmU3ZjgwOQ==
            path_mtu = 1500
            carrier_classes = udp,tcp,tls
            """.trimIndent()

        /** `winsgw01`, the operator name SERVED_WINN_SECTION's gateway_id encodes. */
        const val SERVED_GATEWAY_ID_TEXT = "winsgw01"

        /**
         * The smallest INI reader that can carry the served fixture into a
         * section map, so the values this host is tested with are the ones a
         * server sends rather than ones a test author chose.
         *
         * Deliberately minimal. The real reader lives outside this module; what
         * has to be exercised here is `WinnV3SessionPlan.from` and
         * `WinnV3Keys.from` against the served NAMES and ENCODINGS, and a full
         * INI parser in a test would only add a second thing that can be wrong.
         */
        fun parseIniSection(document: String, want: String): Map<String, String> {
            val out = mutableMapOf<String, String>()
            var section = ""
            for (raw in document.lines()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.substring(1, line.length - 1).lowercase()
                    continue
                }
                if (section != want) continue
                val equals = line.indexOf('=')
                require(equals > 0) { "the [$want] line '$line' is not key = value" }
                out[line.substring(0, equals).trim().lowercase()] =
                    line.substring(equals + 1).trim()
            }
            return out
        }

        /** Verbatim `-print-contract` output of the android/arm64 engine. */
        const val REAL_ANDROID_BANNER =
            """{"contract":"winn-datapath/1","protocol_version":"winn/3","wire":""" +
                """"winn-datapath-duplex/1","frame_magic":"0x334E4E57","frame_version":1,""" +
                """"frame_header_size":16,"max_frame_payload":65535,"max_datagram":1500,""" +
                """"payloads":["awg-datagram","ip-packet"],"payload_semantics":"without """ +
                """-winn3, inbound and outbound frames carry AmneziaWG outer datagrams and """ +
                """not raw IP packets; with -winn3 they carry raw inner IP packets and no """ +
                """AmneziaWG is involved at all","carrier_profile_version":""" +
                """"winn-carrier-profile/1","carriers_buildable":["direct-awg",""" +
                """"http3-connect-udp","http2-stream"],"goos":"android","goarch":"arm64"}"""
    }

    private fun keySection(): Map<String, String> = baseSection() + mapOf(
        WinnV3Keys.KEY_GATEWAY_ID to GATEWAY_ID_B64,
        WinnV3Keys.KEY_STATIC to STATIC_B64,
        WinnV3Keys.KEY_GATEWAY_STATIC to GATEWAY_B64,
        WinnV3Keys.KEY_ADMISSION to ADMISSION_B64,
    )

    private fun baseSection(): Map<String, String> = mapOf(
        "enabled" to "true",
        "endpoint" to "203.0.113.7:51820",
        "protocol" to "3",
        WinnV3SessionPlan.KEY_DESCRIPTOR_NODE to "lab-alpha",
        WinnV3SessionPlan.KEY_SELECTED_NODE to "lab-alpha",
    )

    /**
     * A plan from [section], with an inner next hop injected when the section
     * names none.
     *
     * The injection is what stops every caller here having to carry one. It is
     * needed because `WinnV3SessionPlan.from` defaults the next hop to the FIRST
     * RESOLVER, and a session whose resolver is its own next hop is now refused:
     * that address carries PMTU signals only and answers no queries, so naming
     * it would trade a leak for total name-resolution failure. Served
     * configurations always carry `inner_router_v4`, so the defaulting path is
     * a lab-document shape rather than a served one — and
     * `a v1 shaped resolver is refused for a standalone session` pins what it
     * now does.
     */
    private fun plan(section: Map<String, String> = baseSection()): WinnV3SessionPlan =
        WinnV3SessionPlan.from(
            section = if (WinnV3SessionPlan.innerNextHopOf(section).isEmpty()) {
                section + ("inner_next_hop" to "10.8.1.1")
            } else {
                section
            },
            relayInnerAddress = "10.8.1.3",
            // 10.8.1.53, NOT 10.8.1.1. The inner next hop carries PMTU signals
            // only and answers no queries, so a session naming it as its
            // resolver is refused — `a v1 shaped resolver is refused for a
            // standalone session` below pins that, and it is the shape
            // VpnTunnelService used to produce by defaulting to 10.8.1.1.
            dnsServers = listOf("10.8.1.53"),
            promotionRoutes = listOf(
                WinnV3Route("0.0.0.0", 0),
                WinnV3Route("10.8.1.0", 24),
            ),
            ipv6SinkAddress = VpnTunnelService.IPV6_FAIL_CLOSED_SINK,
        )

    /**
     * The refusal the POSTURE now raises for a dead-zone path MTU.
     *
     * `WinnV3Posture.promotion` guards the IPv6 fail-closed sink with exactly
     * the same RFC 8200 floor it guards the inner IPv6 address with, and
     * `WinnV3SessionPlan.from` always installs the sink — so a configuration
     * whose plan floor (`inner_mtu`) is below 1280 is refused at CONSTRUCTION:
     * `from()` throws `WinnV3PostureRefusal` as soon as it calls `promotion()`.
     * This helper turns that construction-time refusal into a value to assert
     * on, and fails loudly if the configuration was (wrongly) accepted.
     */
    private fun refusalFor(pathMtu: Int): WinnV3PostureRefusal =
        try {
            plan(baseSection() + ("path_mtu" to "$pathMtu"))
            throw AssertionError(
                "expected a WinnV3PostureRefusal for dead-zone path_mtu $pathMtu " +
                    "and from() wrongly built a plan",
            )
        } catch (e: WinnV3PostureRefusal) {
            e
        }

    private fun functionBodyOf(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("could not find $signature", start >= 0)
        val open = source.indexOf('{', start + signature.length - 1)
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

    private fun stripComments(text: String): String =
        text.replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("(?m)//.*$"), "")

    private fun readMainSource(name: String): String = File(mainSourceDir(), name).readText()

    private fun mainKotlinSources(): List<File> =
        mainSourceDir().listFiles { f: File -> f.name.endsWith(".kt") }?.sortedBy { it.name }
            ?: emptyList()

    private fun mainSourceDir(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "android/app/src/main/kotlin/org/winsvpn/app")
            if (candidate.isDirectory) return candidate
            val here = File(dir, "app/src/main/kotlin/org/winsvpn/app")
            if (here.isDirectory) return here
            dir = dir.parentFile
        }
        throw AssertionError("could not locate the main Kotlin source directory")
    }
}
