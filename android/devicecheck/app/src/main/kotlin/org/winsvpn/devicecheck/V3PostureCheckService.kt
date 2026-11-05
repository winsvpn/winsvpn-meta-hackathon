package org.winsvpn.devicecheck

import android.content.Intent
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import org.winsvpn.app.WinnV3Posture
import org.winsvpn.app.WinnV3PostureRecord
import org.winsvpn.app.WinnV3PostureRefusal
import org.winsvpn.app.WinnV3PostureSink
import org.winsvpn.app.WinnV3Route
import org.winsvpn.app.WinnV3Sizing
import org.winsvpn.app.WinnV3Stage
import org.winsvpn.app.WinnV3StagedStart
import org.winsvpn.app.WinnV3StartRefusal
import java.io.FileInputStream
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * The on-device proof of `WINN3_TUN_LAYER_20260808.md` §4 for Android.
 *
 * It drives the SHIPPING posture code — `WinnV3Posture`, copied in
 * byte-for-byte by `build_devicecheck.sh` — against a REAL
 * `VpnService.Builder`, establishes a real interface, and then reads back what
 * the kernel actually got. That last part is the whole point: everything the
 * builder is told can be verified in a JVM unit test, and none of it proves
 * that Android installed it.
 *
 * Nothing here needs the engine binary. §4 is a contract about what the HOST
 * must configure, and that is exactly the half that can be proved without a
 * gateway, without a carrier, and without a byte on any wire — which is why
 * this runs entirely inside an emulator with no routable listener anywhere.
 */
class V3PostureCheckService : VpnService() {

    companion object {
        const val TAG = "WINN3POSTURE"

        /** Inner assignment. RFC 5737 / RFC 1918 documentation space only. */
        private const val INNER_ADDRESS = "10.8.1.3"
        private const val INNER_NEXT_HOP = "10.8.1.1"
        private const val INNER_DNS = "10.8.1.1"
        private const val IPV6_SINK = "fd00:d951:0001::1"

        /**
         * The gateway the carrier would dial. TEST-NET-3 (RFC 5737), so it is
         * unroutable by construction: this harness never opens a socket to it
         * and could not reach it if it did.
         */
        private const val GATEWAY_HOST = "203.0.113.9"

        /**
         * The plan path MTU. Matches `WinnV3SessionPlan.DEFAULT_PATH_MTU` in
         * the app module (not copied here, but matched by value).
         */
        private const val PATH_MTU = 1500

        /**
         * THE MIGRATION PLAN THIS RUN PROVES. A declaration, not a measurement:
         * [WinnV3EngineConfig] accepts whatever `carrierClasses` its caller
         * names, and a posture that does not say which plan it is honouring is
         * a posture that cannot be checked against anything.
         *
         * [WinnV3Sizing.CARRIER_CLASSES] is the shipping default -- the plan
         * `WinnV3SessionPlan.from` builds in the app module when a deployment's
         * `[winn]` section has no `carrier_classes` key, which is the common
         * case. Pointing at that constant rather than copying its contents here
         * means this harness tracks the shipping default if it is ever widened,
         * instead of silently proving a plan nobody ships any more.
         *
         * A single-carrier UDP/IPv4 number -- `InnerMTUForPath(1500, 28) =
         * 1443` -- is NOT this plan's floor and must not be used to configure
         * the interface: see [WinnV3Sizing.innerMtuForPath]'s own "SINGLE
         * CARRIER" warning. This harness used to compute exactly that number
         * and report it as PASS evidence, which made it the mirror image of the
         * bug §4.2 exists to catch: PASS evidence for an interface 84 bytes
         * wider than this plan's own floor allows -- the same gap
         * `WinnV3EngineConfig.init` now refuses on the app side.
         *
         * ONE plan is enough for what this run checks, and that is a
         * conclusion, not an oversight. Every result below comes from a single
         * `Builder.setMtu(innerMtu)` call threaded through [WinnV3Posture];
         * nothing downstream here branches on which classes make up the plan,
         * only on the resulting `innerMtu` int, and step 0 already cross-checks
         * [WinnV3Sizing.planFloorInnerMtu] against Go's worked examples for
         * both this plan and a narrower one, at two path MTUs. A second
         * on-device run of a different plan would re-prove the same
         * kernel-install fidelity with a different int; it would not exercise a
         * different code path here. What it WOULD exercise -- `carrier_classes`
         * parsing and defaulting, i.e. turning a deployment's config into a
         * plan in the first place -- is `WinnV3SessionPlan.from`'s job in the
         * app module, is not driven by this service at all, and is therefore a
         * real gap in on-device coverage that adding a second plan number here
         * would not close.
         */
        private val PLAN = WinnV3Sizing.CARRIER_CLASSES

        /** How long the bootstrap posture is held so the OS view can be snapshotted. */
        private const val HOLD_MS = 9_000L
    }

    private var current: ParcelFileDescriptor? = null
    @Volatile private var worker: Thread? = null
    private val checkDescriptors = ArrayList<ParcelFileDescriptor>()

    private fun say(line: String) = Log.i(TAG, line)
    private fun result(step: String, verdict: String, detail: String) =
        Log.i(TAG, "RESULT | $step | $verdict | $detail")

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (worker != null) return START_NOT_STICKY
        worker = Thread({
            try {
                runChecks()
            } finally {
                for (descriptor in checkDescriptors) {
                    try {
                        descriptor.close()
                    } catch (_: Exception) {
                    }
                }
                checkDescriptors.clear()
                current = null
                stopSelf()
                worker = null
            }
        }, "winn3-posture")
        worker!!.start()
        return START_NOT_STICKY
    }

    private fun runChecks() {
        val innerMtu = WinnV3Sizing.planFloorInnerMtu(PATH_MTU, PLAN)
        say("winn3 staged-posture check starting. plan=$PLAN innerMTU=$innerMtu " +
            "(plan floor, not a single-carrier number) pathMTU=$PATH_MTU")

        try {
            WinnV3Sizing.assertsAgreeWithGo().forEach { say("  arithmetic: $it") }
            result("0-arithmetic", "PASS",
                "Kotlin agrees with winn3/tun/params.go and winn3/carrier/sizing.go " +
                    "(see the arithmetic lines above); this run proves plan $PLAN at a " +
                    "$PATH_MTU-byte path MTU, whose floor is planFloorInnerMtu=$innerMtu")
        } catch (e: IllegalStateException) {
            result("0-arithmetic", "FAIL", "${e.message}")
            return
        }

        val exclusion = WinnV3Route(GATEWAY_HOST, 32)

        // --- §4.1 BOOTSTRAP -------------------------------------------------
        val bootstrap = try {
            WinnV3Posture.bootstrap(INNER_ADDRESS, innerMtu, INNER_NEXT_HOP, exclusion)
        } catch (e: WinnV3PostureRefusal) {
            result("1-bootstrap-build", "FAIL", "${e.message}")
            return
        }
        result("1-bootstrap-build", "PASS", bootstrap.describe())

        val bootstrapFd = try {
            install(bootstrap, "1-bootstrap")
        } catch (e: Exception) {
            result("2-bootstrap-establish", "FAIL", "${e.javaClass.simpleName}: ${e.message}")
            return
        }
        if (bootstrapFd == null) {
            result("2-bootstrap-establish", "FAIL", "establish() returned null")
            return
        }
        result("2-bootstrap-establish", "PASS", "tun established, fd=${bootstrapFd.fd}")

        // --- what the KERNEL actually got, not what the builder was told ----
        val observed = observeInterface()
        say("observed: $observed")
        checkKernelIsNarrow(observed, innerMtu)

        // Hold the bootstrap posture so the OS's own view can be snapshotted
        // from outside the app -- `ip route`, `ip addr` -- which is stronger
        // evidence about routes than anything this process can enumerate.
        say("HOLD-BEGIN bootstrap posture is installed; snapshot the OS view now")
        Thread.sleep(HOLD_MS)
        say("HOLD-END")

        // --- §4.3 rule 1: a bootstrap that cannot be narrow must refuse ------
        checkRefusals(innerMtu, exclusion)

        // --- §4.1 the promotion gate ----------------------------------------
        val promoted = try {
            WinnV3Posture.promotion(
                innerAddress = INNER_ADDRESS,
                innerMtu = innerMtu,
                routes = listOf(WinnV3Route("0.0.0.0", 0)),
                dnsServers = listOf(INNER_DNS),
                innerNextHop = INNER_NEXT_HOP,
                outerTransportExclusion = exclusion,
                ipv6SinkAddress = IPV6_SINK,
            )
        } catch (e: WinnV3PostureRefusal) {
            result("4-promotion-build", "FAIL", "${e.message}")
            return
        }
        result("4-promotion-build", "PASS", promoted.describe())

        // The gate refuses while nothing has been delivered, and the staged
        // start must reach RefusedNotProven WITHOUT installing the promotion.
        val installedStages = mutableListOf<WinnV3Stage>()
        var toreDown = false
        val unprovenOutcome = try {
            WinnV3StagedStart(
                bootstrap = bootstrap,
                promoted = promoted,
                proofDeadlineMs = 600L,
                pollIntervalMs = 150L,
                install = { installedStages += it.stage },
                readStatus = { """{"gate_state":"carrying","rx_packets":0,"rx_offered":9}""" },
                tearDown = { toreDown = true },
                log = { say("  staged: $it") },
                nowMs = { System.currentTimeMillis() },
                sleepMs = { Thread.sleep(it) },
            ).start()
        } catch (e: WinnV3StartRefusal) {
            result("5-gate-refuses", "FAIL", "unexpected refusal: ${e.message}")
            return
        }
        if (unprovenOutcome is WinnV3StagedStart.Outcome.RefusedNotProven &&
            !installedStages.contains(WinnV3Stage.PROMOTED) && toreDown
        ) {
            result("5-gate-refuses", "PASS",
                "9 packets ARRIVED and 0 were DELIVERED; the gate refused to promote and the " +
                    "start tore down. reason=${unprovenOutcome.reason}")
        } else {
            result("5-gate-refuses", "FAIL",
                "outcome=$unprovenOutcome installed=$installedStages toreDown=$toreDown")
        }

        // --- promotion, for real, on the same interface ----------------------
        val promotedFd = try {
            install(promoted, "6-promotion")
        } catch (e: Exception) {
            result("6-promotion-establish", "FAIL", "${e.javaClass.simpleName}: ${e.message}")
            return
        }
        if (promotedFd == null) {
            result("6-promotion-establish", "FAIL", "establish() returned null")
            return
        }
        result("6-promotion-establish", "PASS", "promoted, fd=${promotedFd.fd}")

        // THE FINDING THIS CHECK EXISTS FOR: does promotion replace the tun
        // descriptor? If it does, an engine holding the old one by SCM_RIGHTS is
        // holding a dead device, and winn3/tun cannot swap Device under a live
        // Tunnel.
        val sameFd = promotedFd.fd == bootstrapFd.fd
        val oldStillReadable = try {
            FileInputStream(bootstrapFd.fileDescriptor).available()
            true
        } catch (e: Exception) {
            false
        }
        result("7-descriptor-identity",
            if (!sameFd) "PASS" else "NOTE",
            "bootstrap fd=${bootstrapFd.fd} promoted fd=${promotedFd.fd} same=$sameFd " +
                "oldDescriptorStillOpen=$oldStillReadable. A new descriptor means an engine " +
                "that adopted the old one by SCM_RIGHTS is holding a dead device, which is why " +
                "the host owns the tun and pumps IP packets over the frame channel.")

        val promotedObserved = observeInterface()
        say("observed after promotion: $promotedObserved")
        result("8-promotion-observed", if (promotedObserved.mtu == innerMtu) "PASS" else "FAIL",
            "mtu=${promotedObserved.mtu} (must still be exactly $innerMtu; §4.2 does not change " +
                "at promotion) addresses=${promotedObserved.addresses}")

        try {
            promotedFd.close()
        } catch (_: Exception) {
        }
        try {
            bootstrapFd.close()
        } catch (_: Exception) {
        }
        current = null
        result("9-teardown", "PASS", "both descriptors closed; nothing is left established")
        say("winn3 staged-posture check complete.")
        stopSelf()
    }

    /**
     * Applies a posture to a real `VpnService.Builder`, verifies the RECORD (not
     * the intent), and only then calls `establish()`.
     */
    private fun install(posture: WinnV3Posture, step: String): ParcelFileDescriptor? {
        val builder = Builder().setSession("winn3-posture-check")
        var excludeSupported = false
        val sink = object : WinnV3PostureSink {
            override fun addAddress(address: String, prefixLength: Int) {
                builder.addAddress(address, prefixLength)
            }

            override fun addRoute(address: String, prefixLength: Int) {
                builder.addRoute(address, prefixLength)
            }

            override fun excludeRoute(address: String, prefixLength: Int): Boolean {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
                return try {
                    builder.excludeRoute(IpPrefix(InetAddress.getByName(address), prefixLength))
                    excludeSupported = true
                    true
                } catch (e: Exception) {
                    say("  excludeRoute($address/$prefixLength) rejected: ${e.message}")
                    false
                }
            }

            override fun setMtu(mtu: Int) {
                builder.setMtu(mtu)
            }

            override fun addDnsServer(server: String) {
                builder.addDnsServer(server)
            }

            override fun allowFamily(family: Int) {
                // The posture speaks plain ints; map them here, which is the one
                // place this harness touches OsConstants.
                val mapped = when (family) {
                    WinnV3Posture.AF_INET -> OsConstants.AF_INET
                    WinnV3Posture.AF_INET6 -> OsConstants.AF_INET6
                    else -> return
                }
                builder.allowFamily(mapped)
            }
        }

        val record: WinnV3PostureRecord = posture.applyTo(sink)
        say("  $step record: ${record.describe()}")

        if (posture.stage == WinnV3Stage.BOOTSTRAP) {
            // §4.3.1 verbatim: verify narrowness on what was built.
            WinnV3Posture.verifyNarrow(record, requireExclusion = excludeSupported)
            result("$step-verify-narrow", "PASS",
                "the record passed §4.3.1: one /32 address, ${record.routes.size} route, " +
                    "no default route, no IPv6, no DNS, mtu=${record.mtu}, " +
                    "excludeRoute supported=$excludeSupported " +
                    "(refused=${record.refusedExclusions.size})")
        }

        val fd = builder.establish()
        if (fd != null) checkDescriptors.add(fd)
        current = fd
        return fd
    }

    /**
     * What the kernel has, read back through the platform's own interface list.
     *
     * Scoped to the NEWEST interface carrying the assignment. During the
     * promotion window Android has both the old and the new tun up at once —
     * measured, run 1: `tun0` and `tun1` both present, both carrying
     * `10.8.1.3/32` — so an enumeration that unions every match reports a
     * posture that never existed on one interface.
     */
    private fun observeInterface(): Observed {
        var best: Observed? = null
        try {
            for (nif in NetworkInterface.getNetworkInterfaces()) {
                val addrs = nif.interfaceAddresses.map {
                    "${it.address.hostAddress}/${it.networkPrefixLength}"
                }
                if (addrs.none { it.startsWith("$INNER_ADDRESS/") }) continue
                val o = Observed(nif.name, nif.mtu, addrs)
                if (best == null || nif.name > best!!.name) best = o
            }
        } catch (e: Exception) {
            say("  interface enumeration failed: ${e.message}")
        }
        return best ?: Observed("?", -1, emptyList())
    }

    private data class Observed(val name: String, val mtu: Int, val addresses: List<String>)

    /**
     * IPv6 link-local, which the kernel generates on any IPv6-capable interface
     * whether or not the builder asked for IPv6.
     *
     * MEASURED on emulator-5554 (API 34), run 1: a bootstrap posture that
     * installed no IPv6 address, no IPv6 route, no IPv6 resolver and did not
     * call `allowFamily(AF_INET6)` still came up with
     * `fe80::7855:c466:6de1:984b%tun0/64` on the interface.
     *
     * This does **not** violate §4.1. Link-local is scoped to the link, carries
     * no traffic off it, and — with no IPv6 route on the interface — captures
     * nothing: the host keeps its own IPv6 exactly as §4.1 requires. An app
     * cannot suppress it (`net.ipv6.conf.<if>.disable_ipv6` is not reachable
     * from an unprivileged process), so a check that treated its presence as a
     * failure would be a check no Android host could ever pass.
     *
     * What must be absent is a **routable** IPv6 address and any IPv6 route,
     * and that is what is asserted below.
     */
    private fun isKernelLinkLocal(cidr: String): Boolean =
        cidr.lowercase().startsWith("fe80:")

    private fun checkKernelIsNarrow(o: Observed, innerMtu: Int) {
        if (o.mtu != innerMtu) {
            result("3-kernel-mtu", "FAIL",
                "the interface MTU the kernel reports is ${o.mtu}, not $innerMtu. §4.2: a device " +
                    "MTU larger than the tunnel can carry turns every full-size flow into a " +
                    "black hole")
        } else {
            result("3-kernel-mtu", "PASS",
                "interface ${o.name} MTU is exactly Tunnel.InnerMTU() = $innerMtu")
        }
        val v4 = o.addresses.filter { !it.contains(':') }
        val v6 = o.addresses.filter { it.contains(':') }
        val routableV6 = v6.filterNot { isKernelLinkLocal(it) }
        if (v4 == listOf("$INNER_ADDRESS/32")) {
            result("3-kernel-address", "PASS", "the kernel installed exactly $INNER_ADDRESS/32")
        } else {
            result("3-kernel-address", "FAIL", "the kernel installed $v4")
        }
        if (routableV6.isEmpty()) {
            result("3-kernel-ipv6", "PASS",
                "no ROUTABLE IPv6 on the bootstrap interface; the host keeps its own. " +
                    "Kernel-generated link-local present: $v6 — scoped to the link, carries " +
                    "nothing off it, and not suppressible from an unprivileged app")
        } else {
            result("3-kernel-ipv6", "FAIL",
                "the bootstrap interface carries routable IPv6: $routableV6")
        }
    }

    /** §4.3 rule 1, exercised against the real platform rather than a double. */
    private fun checkRefusals(innerMtu: Int, exclusion: WinnV3Route) {
        val cases = listOf(
            "ipv6-assignment" to { WinnV3Posture.bootstrap("fd00::2", innerMtu, INNER_NEXT_HOP, exclusion) },
            "mtu-below-floor" to { WinnV3Posture.bootstrap(INNER_ADDRESS, 500, INNER_NEXT_HOP, exclusion) },
            "no-assignment" to { WinnV3Posture.bootstrap("", innerMtu, INNER_NEXT_HOP, exclusion) },
        )
        var refused = 0
        for ((name, build) in cases) {
            try {
                build()
                result("3-refusal-$name", "FAIL", "a bootstrap that should be impossible was built")
            } catch (e: WinnV3PostureRefusal) {
                refused++
                say("  refusal $name: ${e.message}")
            }
        }
        result("3-refusals", if (refused == cases.size) "PASS" else "FAIL",
            "$refused of ${cases.size} impossible bootstraps refused; none widened")
    }

    override fun onDestroy() {
        try {
            current?.close()
        } catch (_: Exception) {
        }
        current = null
        super.onDestroy()
    }
}
