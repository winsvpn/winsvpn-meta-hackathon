package org.winsvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `WINN3_TUN_LAYER_20260808.md` §4, held to the same standard as the Go side.
 *
 * Every test names the clause it pins. Where the Go lane used mutation testing,
 * these use the same idea by hand: several tests below feed [WinnV3Posture.verifyNarrow]
 * a record that a *plausible mistake* would have produced, and require it to
 * refuse :  so the guard cannot be deleted without a red test.
 */
class WinnV3PostureTest {

    private val gateway = WinnV3Route("203.0.113.9", 32)

    // --- §4.2, the arithmetic --------------------------------------------------

    @Test
    fun `the MTU arithmetic agrees with winn3 tun params byte for byte`() {
        // The three worked examples in winn3/tun/params.go's own doc comment.
        val proofs = WinnV3Sizing.assertsAgreeWithGo()
        assertEquals(7, proofs.size)
        assertEquals(29, WinnV3Sizing.OVERHEAD)
        assertEquals(1443, WinnV3Sizing.innerMtuForPath(1500, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD))
        assertEquals(1423, WinnV3Sizing.innerMtuForPath(1500, WinnV3Sizing.UDP_OVER_IPV6_OVERHEAD))
        assertEquals(1203, WinnV3Sizing.innerMtuForPath(1280, WinnV3Sizing.UDP_OVER_IPV6_OVERHEAD))
    }

    // --- the plan floor: winn3/carrier/sizing.go, mirrored --------------------

    @Test
    fun `every per-class overhead is the one carrier sizing go charges`() {
        // Each number is re-derived here from carrier/sizing.go's own components
        // rather than copied from the Kotlin constant it checks, so a typo in
        // WinnV3Sizing does not agree with itself.
        assertEquals(20 + 8, WinnV3Sizing.carrierOverhead("udp", ipv4 = true))
        assertEquals(40 + 8, WinnV3Sizing.carrierOverhead("udp", ipv4 = false))
        assertEquals(20 + (20 + 12) + (2 + 16), WinnV3Sizing.carrierOverhead("tcp", ipv4 = true))
        assertEquals(40 + (20 + 12) + (2 + 16), WinnV3Sizing.carrierOverhead("tcp", ipv4 = false))
        assertEquals(
            20 + (20 + 12) + (5 + 1 + 16) + (2 + 16),
            WinnV3Sizing.carrierOverhead("tls", ipv4 = true),
        )
        assertEquals(
            40 + (20 + 12) + (5 + 1 + 16) + (2 + 16),
            WinnV3Sizing.carrierOverhead("tls", ipv4 = false),
        )
        // The one that decides the floor of the shipping plan.
        assertEquals(112, WinnV3Sizing.carrierOverhead("tls", ipv4 = false))
        // And the one the defect used instead.
        assertEquals(28, WinnV3Sizing.carrierOverhead("udp", ipv4 = true))
    }

    @Test
    fun `the plan floor is the minimum over every class and both families`() {
        val classes = listOf("udp", "tcp", "tls")
        // Every member of the cross product, listed, so the minimum is visibly a
        // minimum over all six and not over a subset.
        val all = classes.flatMap { c ->
            listOf(true, false).map { v4 -> WinnV3Sizing.maxMessageSizeForPath(1500, WinnV3Sizing.carrierOverhead(c, v4)) }
        }
        assertEquals(listOf(1472, 1452, 1430, 1410, 1408, 1388), all)
        assertEquals(1388, WinnV3Sizing.planFloorMessageSize(1500, classes))
        assertEquals(1359, WinnV3Sizing.planFloorInnerMtu(1500, classes))
        assertEquals(all.min(), WinnV3Sizing.planFloorMessageSize(1500, classes))
    }

    @Test
    fun `the floor is narrower than the dialled carrier by exactly 84 bytes`() {
        // driver.Sizing's doc comment measures the gap at a 1280-byte path; it is
        // the same 84 at any path MTU, because it is 112 − 28.
        for (path in listOf(1280, 1400, 1500)) {
            val dialled = WinnV3Sizing.innerMtuForPath(path, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD)
            val floor = WinnV3Sizing.planFloorInnerMtu(path, listOf("udp", "tcp", "tls"))
            assertEquals("path $path", 84, dialled - floor)
        }
        // The two numbers the Go seam's refusal names.
        assertEquals(1443, WinnV3Sizing.innerMtuForPath(1500, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD))
        assertEquals(1359, WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp", "tcp", "tls")))
        // driver.Sizing's own worked example, at the RFC 8200 planning floor.
        assertEquals(1168, WinnV3Sizing.planFloorMessageSize(1280, listOf("udp", "tcp", "tls")))
        assertEquals(
            1252,
            WinnV3Sizing.maxMessageSizeForPath(1280, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD),
        )
    }

    @Test
    fun `a plan of one class is still computed over both address families`() {
        // udp-only is genuinely wider than udp+tcp+tls, but it is NOT
        // InnerMTUForPath(1500, 28): IPv6 is the narrower family and a migration
        // can change family as easily as class.
        assertEquals(1423, WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp")))
        assertEquals(1443, WinnV3Sizing.innerMtuForPath(1500, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD))
        assertEquals(1381, WinnV3Sizing.planFloorInnerMtu(1500, listOf("tcp")))
        assertEquals(1359, WinnV3Sizing.planFloorInnerMtu(1500, listOf("tls")))
        // Order is irrelevant: it is a minimum, not a fold over the first entry.
        assertEquals(
            WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp", "tcp", "tls")),
            WinnV3Sizing.planFloorInnerMtu(1500, listOf("tls", "tcp", "udp")),
        )
        // And adding a class can only narrow it.
        assertTrue(
            WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp", "tls")) <
                WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp")),
        )
    }

    @Test
    fun `the plan floor refuses an empty plan and an unknown class`() {
        // driver.NewSizing refuses both rather than charging the worst case
        // silently, because a host that forgot to name its plan has a bug a
        // conservative number would hide until the first migration.
        try {
            WinnV3Sizing.planFloorInnerMtu(1500, emptyList())
            throw AssertionError("an empty plan was accepted")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("escalate to"))
        }
        try {
            WinnV3Sizing.planFloorInnerMtu(1500, listOf("udp", "quic"))
            throw AssertionError("an unknown class was accepted")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("quic"))
        }
    }

    @Test
    fun `the plan floor clamps exactly where session MaxMessageSizeForPath does`() {
        // Below the message floor the Go side returns MessageFloor(), not a
        // negative, so InnerMTU falls to 0 rather than going negative and being
        // handed to a Builder.
        assertEquals(WinnV3Sizing.MESSAGE_FLOOR, WinnV3Sizing.maxMessageSizeForPath(100, 112))
        assertEquals(0, WinnV3Sizing.planFloorInnerMtu(100, listOf("udp", "tls")))
        assertEquals(29, WinnV3Sizing.MESSAGE_FLOOR)
        assertEquals(65535, WinnV3Sizing.maxMessageSizeForPath(1 shl 20, 28))
    }

    @Test
    fun `inner IPv6 over a plan is decided by the narrowest class in it`() {
        // At a 1400-byte path a udp-only plan carries inner IPv6 (1323 ≥ 1280)
        // and the same plan with tls in it does not (1259). Answering from the
        // dialled carrier would promise inner IPv6 and then black-hole it at the
        // first failover :  the original trap wearing a v6 hat.
        assertTrue(WinnV3Sizing.planCarriesInnerIpv6(1400, listOf("udp")))
        assertFalse(WinnV3Sizing.planCarriesInnerIpv6(1400, listOf("udp", "tcp", "tls")))
        assertEquals(1323, WinnV3Sizing.planFloorInnerMtu(1400, listOf("udp")))
        assertEquals(1259, WinnV3Sizing.planFloorInnerMtu(1400, listOf("udp", "tcp", "tls")))
        // At the RFC 8200 planning floor no plan carries inner IPv6 at all.
        assertFalse(WinnV3Sizing.planCarriesInnerIpv6(1280, listOf("udp")))
    }

    @Test
    fun `carrierMessageFor is the exact inverse of innerMtu`() {
        for (n in 600..1600) {
            assertEquals(n, WinnV3Sizing.carrierMessageFor(WinnV3Sizing.innerMtu(n)))
        }
    }

    @Test
    fun `inner IPv6 is impossible at a 1280 byte outer path`() {
        // §2.3: at a 1280-byte outer path inner IPv6 is impossible for ANY tunnel.
        val inner = WinnV3Sizing.innerMtuForPath(1280, WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD)
        assertTrue(inner < WinnV3Sizing.IPV6_MIN_LINK_MTU)
        assertFalse(WinnV3Sizing.carriesInnerIpv6(1280 - WinnV3Sizing.UDP_OVER_IPV4_OVERHEAD))
        assertEquals(1309, WinnV3Sizing.minCarrierMessageForIpv6())
    }

    // --- §4.1 BOOTSTRAP --------------------------------------------------------

    @Test
    fun `bootstrap installs the address at 32 and exactly one route`() {
        val p = WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway)
        val r = p.applyTo(null)

        assertEquals(1, r.addresses.size)
        assertEquals(WinnV3Address("10.8.1.3", 32), r.addresses.first())
        assertEquals(1, r.routes.size)
        assertEquals(WinnV3Route("10.8.1.1", 32), r.routes.first())
        assertEquals(1443, r.mtu)
        WinnV3Posture.verifyNarrow(r, requireExclusion = true)
    }

    @Test
    fun `bootstrap installs no default route, no IPv6 and no DNS`() {
        val r = WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway).applyTo(null)
        assertFalse(r.hasDefaultRoute())
        assertFalse(r.hasAnyIpv6())
        assertTrue(r.dnsServers.isEmpty())
        assertEquals(listOf(WinnV3Posture.AF_INET), r.families)
    }

    @Test
    fun `the outer transport exclusion is present in the FIRST posture`() {
        val r = WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway).applyTo(null)
        assertEquals(listOf(gateway), r.excludedRoutes)
    }

    @Test
    fun `the exclusion is applied after every route`() {
        // CORRECTED 2026-09-15, and the old assertion was the exact opposite.
        //
        // It read `exclude < route`, justified by "there must be no window in
        // which the tunnel's routes exist and the exclusion does not".
        // `VpnService.Builder` has no such window: it accumulates and applies
        // nothing until establish(), so no call order here can leave a live
        // interface half-configured.
        //
        // What the order DOES decide is which call survives a destination
        // collision. On Android 13 and 14 `Builder.excludeRoute(prefix)` is
        // `addRoute(prefix, RTN_THROW)` over the same `mRoutes` list, and the
        // private addRoute resolves a repeated destination with
        // `mRoutes.set(index, newRoute)`. Exclusions first means an include
        // silently deletes the outer-transport exclusion. Exclusions last means
        // the exclusion wins, which is the only safe direction.
        val order = mutableListOf<String>()
        val sink = object : WinnV3PostureSink {
            override fun addAddress(address: String, prefixLength: Int) { order += "addr" }
            override fun addRoute(address: String, prefixLength: Int) { order += "route" }
            override fun excludeRoute(address: String, prefixLength: Int): Boolean {
                order += "exclude"; return true
            }
            override fun setMtu(mtu: Int) { order += "mtu" }
            override fun addDnsServer(server: String) { order += "dns" }
            override fun allowFamily(family: Int) { order += "family" }
        }
        WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway).applyTo(sink)
        assertTrue(order.indexOf("exclude") > order.indexOf("route"))
        // §4.2: the MTU is set first, so no early return can leave it unapplied.
        assertEquals("mtu", order.first())
    }

    @Test
    fun `an include on the exclusion's destination is recorded as shadowed, not applied`() {
        // The record must describe the BUILDER. Feeding the calls in the order
        // the old applyTo used reproduces the platform's replacement, and the
        // record has to show the exclusion gone rather than report it applied.
        val record = WinnV3PostureRecord(null)
        record.setMtu(1443)
        record.addAddress("10.8.1.3", 32)
        record.excludeRoute("203.0.113.9", 32)
        record.addRoute("203.0.113.9", 32)

        assertTrue(record.excludedRoutes.isEmpty())
        assertEquals(listOf(WinnV3Route("203.0.113.9", 32)), record.shadowedExclusions)
        assertEquals(listOf(WinnV3Route("203.0.113.9", 32)), record.routes)
        // §4.3.1 must refuse it rather than approve a property the builder
        // does not hold. The only exclusion is gone, so the "installed no
        // outer-transport exclusion" clause is the one that fires.
        val why = refusal { WinnV3Posture.verifyNarrow(record, requireExclusion = true) }
        assertTrue(why.message!!.contains("no outer-transport exclusion"))
    }

    @Test
    fun `a shadowed exclusion is refused by name even when another survives`() {
        // Two exclusions, one of them overwritten by a later include. The
        // surviving one keeps excludedRoutes non-empty, so the first clause
        // passes and only the shadow check can catch this.
        val record = WinnV3PostureRecord(null)
        record.setMtu(1443)
        record.addAddress("10.8.1.3", 32)
        record.excludeRoute("203.0.113.9", 32)
        record.excludeRoute("198.51.100.7", 32)
        record.addRoute("203.0.113.9", 32)

        assertEquals(listOf(WinnV3Route("198.51.100.7", 32)), record.excludedRoutes)
        val why = refusal { WinnV3Posture.verifyNarrow(record, requireExclusion = true) }
        assertTrue(why.message!!.contains("203.0.113.9/32"))
        // The lost prefix is also in describe(), so a log of the record shows it.
        assertTrue(record.describe().contains("shadowed_exclusions=203.0.113.9/32"))
    }

    @Test
    fun `destination collision is compared masked, not as text`() {
        // IpPrefix masks the address to the prefix length in its constructor,
        // so 10.0.0.7slash24 and 10.0.0.0slash24 are ONE destination to the
        // platform. A string compare would miss the replacement and report an
        // exclusion the builder already dropped.
        val record = WinnV3PostureRecord(null)
        record.addRoute("10.0.0.7", 24)
        record.excludeRoute("10.0.0.0", 24)

        assertEquals(listOf(WinnV3Route("10.0.0.0", 24)), record.excludedRoutes)
        assertTrue(record.routes.isEmpty())
    }

    @Test
    fun `the real posture order leaves the exclusion installed`() {
        // The shipping bootstrap: one host route to the inner next hop, one
        // exclusion on the gateway. Different destinations, so nothing is
        // shadowed and verifyNarrow passes on a real API 33+ platform.
        val record = WinnV3Posture
            .bootstrap("10.10.0.4", 1373, "10.10.0.1", WinnV3Route("198.51.100.227", 32))
            .applyTo(null)

        assertEquals(listOf(WinnV3Route("198.51.100.227", 32)), record.excludedRoutes)
        assertEquals(listOf(WinnV3Route("10.10.0.1", 32)), record.routes)
        assertTrue(record.shadowedExclusions.isEmpty())
        WinnV3Posture.verifyNarrow(record, requireExclusion = true)
    }

    @Test
    fun `a platform without excludeRoute records the refusal rather than pretending`() {
        val sink = object : WinnV3PostureSink {
            override fun addAddress(address: String, prefixLength: Int) {}
            override fun addRoute(address: String, prefixLength: Int) {}
            override fun excludeRoute(address: String, prefixLength: Int) = false
            override fun setMtu(mtu: Int) {}
            override fun addDnsServer(server: String) {}
            override fun allowFamily(family: Int) {}
        }
        val r = WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway).applyTo(sink)
        assertTrue(r.excludedRoutes.isEmpty())
        assertEquals(listOf(gateway), r.refusedExclusions)
        // On such a platform the exclusion is carried entirely by protect(), so
        // verifyNarrow must not demand a route it could not install.
        WinnV3Posture.verifyNarrow(r, requireExclusion = false)
    }

    // --- §4.3 rule 1: refuse, never widen --------------------------------------

    @Test
    fun `bootstrap refuses an inner MTU below the IPv4 floor`() {
        val e = refusal { WinnV3Posture.bootstrap("10.8.1.3", 575, "10.8.1.1", gateway) }
        assertTrue(e.message!!.contains("576"))
    }

    @Test
    fun `bootstrap refuses an IPv6 assignment rather than staging it`() {
        val e = refusal { WinnV3Posture.bootstrap("fd00::2", 1443, "10.8.1.1", gateway) }
        assertTrue(e.message!!.contains("IPv6"))
    }

    @Test
    fun `bootstrap refuses an IPv6 next hop`() {
        refusal { WinnV3Posture.bootstrap("10.8.1.3", 1443, "fd00::1", gateway) }
    }

    @Test
    fun `bootstrap refuses an IPv6 outer exclusion, which would be inert`() {
        refusal {
            WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", WinnV3Route("2001:db8::1", 128))
        }
    }

    @Test
    fun `bootstrap refuses a blank address and a blank next hop`() {
        refusal { WinnV3Posture.bootstrap("", 1443, "10.8.1.1", gateway) }
        refusal { WinnV3Posture.bootstrap("10.8.1.3", 1443, "  ".trim(), gateway) }
    }

    // --- §4.3.1: verify the RECORD, not the intent ------------------------------
    //
    // Each of the five below is a record a plausible bug in applyTo would have
    // produced. They are the mutation guards: delete a clause of verifyNarrow and
    // one of these goes red.

    @Test
    fun `verifyNarrow refuses a widened prefix`() {
        val r = record { it.addAddress("10.8.1.3", 24); it.setMtu(1443) }
        val e = refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
        assertTrue(e.message!!.contains("/24"))
    }

    @Test
    fun `verifyNarrow refuses a default route`() {
        val r = record {
            it.addAddress("10.8.1.3", 32); it.setMtu(1443); it.addRoute("0.0.0.0", 0)
        }
        val e = refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
        assertTrue(e.message!!.contains("default route"))
    }

    @Test
    fun `verifyNarrow refuses two routes`() {
        val r = record {
            it.addAddress("10.8.1.3", 32); it.setMtu(1443)
            it.addRoute("10.8.1.1", 32); it.addRoute("10.9.0.0", 16)
        }
        refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
    }

    @Test
    fun `verifyNarrow refuses IPv6 in any of its four shapes`() {
        val address = record { it.addAddress("10.8.1.3", 32); it.setMtu(1); it.addAddress("fd00::1", 128) }
        val route = record { it.addAddress("10.8.1.3", 32); it.setMtu(1); it.addRoute("fd00::", 64) }
        val dns = record { it.addAddress("10.8.1.3", 32); it.setMtu(1); it.addDnsServer("fd00::53") }
        val family = record {
            it.addAddress("10.8.1.3", 32); it.setMtu(1); it.allowFamily(WinnV3Posture.AF_INET6)
        }
        // The address form trips the one-address clause first; the other three
        // must each be caught by the IPv6 clause specifically.
        refusal { WinnV3Posture.verifyNarrow(address, requireExclusion = false) }
        for (r in listOf(route, dns, family)) {
            val e = refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
            assertTrue(e.message, e.message!!.contains("IPv6"))
        }
    }

    @Test
    fun `an IPv6 default route is caught by the default-route clause first`() {
        // Belt and braces, and it documents the guard ORDER: `::/0` is both a
        // default route and IPv6, and the default-route clause runs first. Either
        // refusal is correct; what must never happen is neither.
        val r = record { it.addAddress("10.8.1.3", 32); it.setMtu(1443); it.addRoute("::", 0) }
        val e = refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
        assertTrue(e.message!!.contains("default route"))
    }

    @Test
    fun `verifyNarrow refuses DNS`() {
        val r = record { it.addAddress("10.8.1.3", 32); it.setMtu(1443); it.addDnsServer("10.8.1.1") }
        val e = refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
        assertTrue(e.message!!.contains("resolver"))
    }

    @Test
    fun `verifyNarrow refuses a missing MTU`() {
        val r = record { it.addAddress("10.8.1.3", 32) }
        refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
    }

    @Test
    fun `verifyNarrow refuses a missing exclusion where the platform has one`() {
        val r = record { it.addAddress("10.8.1.3", 32); it.setMtu(1443) }
        val e = refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = true) }
        assertTrue(e.message!!.contains("first posture"))
    }

    // --- §4.1 PROMOTION ---------------------------------------------------------

    @Test
    fun `promotion installs the default route, DNS and IPv6`() {
        val p = WinnV3Posture.promotion(
            innerAddress = "10.8.1.3",
            innerMtu = 1443,
            routes = listOf(WinnV3Route("0.0.0.0", 0)),
            // NOT 10.8.1.1, which is the inner next hop below. That address
            // carries PMTU signals only and answers no queries, so naming it as
            // the resolver would trade a leak for total name-resolution failure
            // :  see WinnV3Resolvers, and the test that pins the refusal.
            dnsServers = listOf("10.8.1.53"),
            innerNextHop = "10.8.1.1",
            outerTransportExclusion = gateway,
            ipv6SinkAddress = "fd00:d951:0001::1",
        )
        val r = p.applyTo(null)
        assertTrue(r.hasDefaultRoute())
        assertEquals(listOf("10.8.1.53"), r.dnsServers)
        assertTrue(r.hasAnyIpv6())
        assertEquals(listOf(gateway), r.excludedRoutes)
        // And the exclusion survives into the wide posture, which is the point
        // of §4.1's "so the carrier's own socket can never be captured by the
        // later promotion".
        assertTrue(r.routes.contains(WinnV3Route("0.0.0.0", 0)))
    }

    @Test
    fun `promotion refuses inner IPv6 below RFC 8200's link floor`() {
        val e = refusal {
            WinnV3Posture.promotion(
                innerAddress = "10.8.1.3",
                innerMtu = 1203,
                routes = listOf(WinnV3Route("0.0.0.0", 0)),
                dnsServers = listOf("10.8.1.53"),
                innerNextHop = "10.8.1.1",
                outerTransportExclusion = gateway,
                innerIpv6Address = "fd00::2",
            )
        }
        assertTrue(e.message!!.contains("1280"))
    }

    @Test
    fun `promotion accepts inner IPv6 at or above the floor`() {
        val p = WinnV3Posture.promotion(
            innerAddress = "10.8.1.3",
            innerMtu = 1443,
            routes = listOf(WinnV3Route("0.0.0.0", 0)),
            dnsServers = listOf("10.8.1.53"),
            innerNextHop = "10.8.1.1",
            outerTransportExclusion = gateway,
            innerIpv6Address = "fd00::2",
        )
        val r = p.applyTo(null)
        assertTrue(r.addresses.contains(WinnV3Address("fd00::2", 128)))
        assertTrue(r.routes.contains(WinnV3Route("::", 0)))
    }

    @Test
    fun `promotion refuses the IPv6 fail-closed sink below RFC 8200's link floor`() {
        val e = refusal {
            WinnV3Posture.promotion(
                innerAddress = "10.8.1.3",
                innerMtu = 1203,
                routes = listOf(WinnV3Route("0.0.0.0", 0)),
                dnsServers = listOf("10.8.1.53"),
                innerNextHop = "10.8.1.1",
                outerTransportExclusion = gateway,
                innerIpv6Address = null,
                ipv6SinkAddress = "fd00:d951:0001::1",
            )
        }
        assertTrue(e.message!!.contains("1280"))
    }

    @Test
    fun `promotion accepts the IPv6 fail-closed sink at or above the floor`() {
        val p = WinnV3Posture.promotion(
            innerAddress = "10.8.1.3",
            innerMtu = 1309,
            routes = listOf(WinnV3Route("0.0.0.0", 0)),
            dnsServers = listOf("10.8.1.53"),
            innerNextHop = "10.8.1.1",
            outerTransportExclusion = gateway,
            innerIpv6Address = null,
            ipv6SinkAddress = "fd00:d951:0001::1",
        )
        val r = p.applyTo(null)
        assertTrue(r.addresses.contains(WinnV3Address("fd00:d951:0001::1", 128)))
        assertTrue(r.routes.contains(WinnV3Route("::", 0)))
    }

    @Test
    fun `promotion refuses to leave host IPv6 outside the tunnel`() {
        val e = refusal {
            WinnV3Posture.promotion(
                innerAddress = "10.8.1.3",
                innerMtu = 1443,
                routes = listOf(WinnV3Route("0.0.0.0", 0)),
                dnsServers = listOf("10.8.1.53"),
                innerNextHop = "10.8.1.1",
                outerTransportExclusion = gateway,
            )
        }
        assertTrue(e.message!!.contains("IPv6"))
    }

    @Test
    fun `promotion refuses no routes and refuses no resolvers`() {
        refusal {
            WinnV3Posture.promotion(
                "10.8.1.3", 1443, emptyList(), listOf("10.8.1.53"), "10.8.1.1", gateway,
                ipv6SinkAddress = "fd00::1",
            )
        }
        val e = refusal {
            WinnV3Posture.promotion(
                "10.8.1.3", 1443, listOf(WinnV3Route("0.0.0.0", 0)), emptyList(), "10.8.1.1",
                gateway, ipv6SinkAddress = "fd00::1",
            )
        }
        assertTrue(e.message!!.contains("resolver"))
    }

    @Test
    fun `standalone promotion refuses a route set without the IPv4 default`() {
        val e = refusal {
            WinnV3Posture.promotion(
                "10.8.1.3", 1443, listOf(WinnV3Route("10.8.1.0", 24)),
                listOf("10.8.1.53"), "10.8.1.1", gateway,
                ipv6SinkAddress = "fd00::1",
            )
        }
        assertTrue(e.message!!.contains("IPv4 default route"))
    }

    @Test
    fun `a promotion posture is never mistaken for a bootstrap one`() {
        val promoted = WinnV3Posture.promotion(
            "10.8.1.3", 1443, listOf(WinnV3Route("0.0.0.0", 0)), listOf("10.8.1.53"),
            "10.8.1.1", gateway, ipv6SinkAddress = "fd00::1",
        )
        assertEquals(WinnV3Stage.PROMOTED, promoted.stage)
        val r = promoted.applyTo(null)
        // The whole safety property, restated as a test: the promotion posture
        // must FAIL the bootstrap check.
        refusal { WinnV3Posture.verifyNarrow(r, requireExclusion = false) }
    }

    @Test
    fun `describe names the stage so a log line cannot confuse the two`() {
        val b = WinnV3Posture.bootstrap("10.8.1.3", 1443, "10.8.1.1", gateway)
        assertTrue(b.describe().startsWith("BOOTSTRAP"))
        assertNotNull(b.applyTo(null).describe())
    }

    // --- helpers ----------------------------------------------------------------

    private fun record(build: (WinnV3PostureRecord) -> Unit): WinnV3PostureRecord =
        WinnV3PostureRecord(null).also(build)

    private fun refusal(block: () -> Unit): WinnV3PostureRefusal =
        try {
            block()
            throw AssertionError("expected a WinnV3PostureRefusal and none was thrown")
        } catch (e: WinnV3PostureRefusal) {
            e
        }
}
