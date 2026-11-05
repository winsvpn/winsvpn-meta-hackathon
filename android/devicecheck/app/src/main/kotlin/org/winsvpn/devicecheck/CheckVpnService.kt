package org.winsvpn.devicecheck

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.util.Log
import org.amnezia.awg.GoBackend
import org.amnezia.awg.crypto.KeyPair
import org.winsvpn.app.WinnAndroidEngineHost
import org.winsvpn.app.WinnAwgDatagramSeam
import org.winsvpn.app.WinnAwgLoopbackSeam
import org.winsvpn.app.WinnEngineConfig
import org.winsvpn.app.WinnEngineHost
import org.winsvpn.app.WinnEngineProcess
import org.winsvpn.app.WinnTunnelBridge
import org.winsvpn.app.WinnUnderlaySocket
import java.io.File
import java.io.FileDescriptor
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Device verification harness. It drives the REAL host sources, copied in
 * unmodified from android/app/src/main/kotlin/org/winsvpn/app/, against the
 * REAL engine binary from winn_protocol_experimental/cmd/winn-datapath.
 *
 * WHY THE REAL ENGINE. The Android lane and the datapath lane were both green
 * and mutually unusable: each tested against its own double, and a double
 * speaks whatever the code under test speaks. The four incompatibilities
 * (argv, channel discovery, frame layout, payload semantics) and a fifth (the
 * config schema) all lived in the gap between the two. Nothing short of the
 * real binary talking to the real host code closes that gap, so that is what
 * this harness does.
 *
 * Everything is written to logcat under the tag [TAG]. Nothing is persisted.
 */
class CheckVpnService : VpnService() {

    companion object {
        const val TAG = "WINNCHECK"

        /**
         * How long either short-lived engine probe in step 0 may take before
         * it is killed. Was an inline `20, TimeUnit.SECONDS`; see
         * [readAndWaitAtMost] for why the unit changed to milliseconds.
         */
        private const val ENGINE_PROBE_TIMEOUT_MILLIS = 20_000L

        /** Tunnel addressing. Deliberately in a documentation range. */
        private const val TUN_ADDRESS = "10.211.0.2"
        private const val TUN_DNS = "10.211.0.1"
        private const val TUN_MTU = 1280

        /**
         * The engine's gateway endpoint for this run: a real UDP server that
         * answers. The engine forwards every Inbound datagram here over the
         * protected socket, verbatim, and delivers what comes back as Outbound.
         * A DNS resolver is the simplest real thing that does that.
         */
        private const val GATEWAY = "8.8.8.8:53"
        private const val PROBE_NAME = "dns.google"

        /**
         * The differential target. In "routed" mode this single /32 is the ONLY
         * public address pulled into the tunnel, so the rest of the device is
         * untouched while the differential runs.
         */
        private const val DIFFERENTIAL_TARGET = "9.9.9.9"

        /**
         * "scoped": only this app is in the tunnel, whole default route.
         * "routed": every uid is in the tunnel exactly as the shipping
         * VpnTunnelService leaves it for Winn, but only 9.9.9.9/32 and
         * 10.211.0.0/16 are routed into it.
         */
        const val EXTRA_MODE = "mode"

        /** The responder half of the handshake check. */
        private const val RESPONDER_LIBRARY_NAME = "libawgresponder.so"

        /**
         * The AmneziaWG obfuscation profile. These are the SHIPPING defaults,
         * copied from `lib/main.dart` (`_defaultAwgJc`/`Jmin`/`Jmax` at L113-115
         * and the `S1..S4`/`H1..H4` fallbacks in `_buildRawAmneziaConfig` at
         * L3155-3165). Using the real profile rather than plain-WireGuard
         * defaults means the handshake exercises the AmneziaWG wire format --
         * custom header types and both junk mechanisms -- rather than a
         * degenerate case of it.
         */
        private const val AWG_JC = 2
        private const val AWG_JMIN = 10
        private const val AWG_JMAX = 30
        private const val AWG_S1 = 16
        private const val AWG_S2 = 80
        private const val AWG_S3 = 16
        private const val AWG_S4 = 0
        private const val AWG_H1 = 11L
        private const val AWG_H2 = 22L
        private const val AWG_H3 = 33L
        private const val AWG_H4 = 44L

        /** The inner address of the AmneziaWG interface for the handshake check. */
        private const val AWG_INNER_ADDRESS = "10.212.0.2"

        /**
         * "shipping" uses S1/S2/S3 exactly as `lib/main.dart` defaults them.
         * "nopadding" zeroes them and changes nothing else.
         *
         * The pair is a controlled experiment, not a convenience switch.
         * AmneziaWG PREPENDS S1 random bytes to a handshake initiation and S2 to
         * a handshake response (amneziawg-go `device/send.go`,
         * `peer.device.paddings.init`), while the Winn datapath classifies a
         * datagram by reading its leading 4-byte word as the header type
         * (`datapath/classify.go`, `AWGHeaderTypes.classify`). Those two facts
         * cannot both hold: with the shipping padding the leading word is
         * random, so no handshake can ever be classified. Running the same
         * handshake both ways is what turns that from an argument into a
         * measurement.
         */
        const val EXTRA_AWG_PADDING = "awgpadding"
    }

    /** S1/S2/S3 for this run: the shipping values, or zero. */
    private fun awgPadding(): Triple<Int, Int, Int> =
        if (paddingMode == "nopadding") Triple(0, 0, 0) else Triple(AWG_S1, AWG_S2, AWG_S3)

    private fun awgUapiParams(): String {
        val (s1, s2, s3) = awgPadding()
        return "jc=$AWG_JC,jmin=$AWG_JMIN,jmax=$AWG_JMAX," +
            "s1=$s1,s2=$s2,s3=$s3,s4=$AWG_S4," +
            "h1=$AWG_H1,h2=$AWG_H2,h3=$AWG_H3,h4=$AWG_H4"
    }

    @Volatile private var worker: Thread? = null
    @Volatile private var mode: String = "scoped"
    @Volatile private var paddingMode: String = "shipping"

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (worker != null) return START_NOT_STICKY
        mode = intent?.getStringExtra(EXTRA_MODE) ?: "scoped"
        paddingMode = intent?.getStringExtra(EXTRA_AWG_PADDING) ?: "shipping"
        val thread = Thread({ runChecks() }, "winn-devicecheck")
        worker = thread
        thread.start()
        return START_NOT_STICKY
    }

    private fun say(line: String) = Log.i(TAG, line)

    private fun result(step: String, verdict: String, detail: String) =
        Log.i(TAG, "RESULT | $step | $verdict | $detail")

    private fun runChecks() {
        var tun: ParcelFileDescriptor? = null
        var bridge: WinnTunnelBridge? = null
        try {
            say("===== WINN ANDROID INTEROP VERIFICATION BEGIN =====")
            say("device=${Build.MANUFACTURER} ${Build.MODEL} sdk=${Build.VERSION.SDK_INT} " +
                "release=${Build.VERSION.RELEASE} abis=${Build.SUPPORTED_ABIS.joinToString()}")
            say("uid=${android.os.Process.myUid()} pid=${android.os.Process.myPid()} " +
                "package=$packageName")

            step0Packaging()
            step0Contract()
            step0OldSpawnContract()

            val consent = prepare(this)
            if (consent != null) {
                result("0-consent", "FAIL",
                    "VpnService.prepare() returned a consent intent; cannot establish")
                return
            }
            say("VpnService.prepare() returned null: this app already holds VPN consent.")

            // --- Step 1a: protect() before any tunnel exists ---------------
            step1Protect("1a-protect-before-establish")

            // --- establish the tunnel -------------------------------------
            tun = establishTunnel()
            if (tun == null) {
                result("2-establish", "FAIL", "VpnService.Builder.establish() returned null")
                return
            }
            result("2-establish", "PASS",
                "tun established, fd=${tun.fd}, mtu=$TUN_MTU, mode=$mode")
            reportNetworkPlacement("after establish")

            // --- Step 1b: protect() with the tunnel up, plus the
            //     differential that proves the mark actually bypasses it ----
            step1Protect("1b-protect-after-establish")
            step1Differential()

            // --- Steps 3-6: the real host code against the real engine -----
            val realHost = WinnAndroidEngineHost(
                vpnService = this,
                context = this,
                logDebug = { Log.i(TAG, "host: $it") },
                logWarn = { message, error -> Log.w(TAG, "host: $message", error) },
                logError = { message, error -> Log.e(TAG, "host: $message", error) },
            )
            val seam = HarnessDatagramSeam()
            val recorder = RecordingHost(realHost, seam)

            // The production configuration document, built by the real
            // WinnEngineConfig from a real [winn] section.
            val engineConfig = WinnEngineConfig.from(
                section = linkedMapOf("enabled" to "true", "endpoint" to GATEWAY),
                mtu = TUN_MTU,
            )
            say("config (key names only): ${engineConfig.describeForLog()}")

            val created = WinnTunnelBridge(
                host = recorder,
                maxDatagram = engineConfig.maxDatagram,
                configJson = engineConfig.toConfigJson(),
            )

            try {
                created.start()
                bridge = created
                result("3-interop-handshake", "PASS",
                    "the real host spawned the real winn-datapath binary, it dialled the " +
                        "abstract channel, the uid check passed, the protected descriptor " +
                        "crossed by SCM_RIGHTS, and the engine answered Create with CreateAck")
            } catch (e: Exception) {
                result("3-interop-handshake", "FAIL", describe(e))
                say("parent-side socket identity was: ${recorder.describeParent()}")
                return
            }

            val createAck = created.statusJson()
            say("CreateAck status JSON from the real engine: $createAck")

            step4DescriptorIdentity(recorder, createAck)
            step5DatagramRoundTrip(seam)
            step6StatusRoundTrip(created)

            // Release the wire-verification bridge before the handshake check
            // so its engine subprocess and its protected socket are gone and
            // step 8 is unambiguously about its own.
            step7Close(created)
            bridge = null

            step8AwgHandshakeThroughWinn(tun)
        } catch (e: Throwable) {
            Log.e(TAG, "harness aborted", e)
            result("harness", "FAIL", describe(e))
        } finally {
            step7Close(bridge)
            try { tun?.close() } catch (e: Exception) { Log.w(TAG, "tun close", e) }
            say("===== WINN ANDROID INTEROP VERIFICATION END =====")
            stopSelf()
        }
    }

    // ------------------------------------------------------------------
    // step 0: packaging, and what the packaged binary says it is
    // ------------------------------------------------------------------

    private fun engineFile(): File =
        File(applicationInfo.nativeLibraryDir, WinnAndroidEngineHost.ENGINE_LIBRARY_NAME)

    private fun step0Packaging() {
        val dir = File(applicationInfo.nativeLibraryDir)
        say("nativeLibraryDir=$dir")
        dir.listFiles()?.forEach {
            say("  ${it.name} size=${it.length()} canExecute=${it.canExecute()}")
        }
        val engine = engineFile()
        if (!engine.isFile) {
            result("0-packaging", "FAIL",
                "${WinnAndroidEngineHost.ENGINE_LIBRARY_NAME} is not in nativeLibraryDir")
            return
        }
        val digest = MessageDigest.getInstance("SHA-256")
        engine.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        val hex = digest.digest().joinToString("") { "%02x".format(it) }
        result("0-packaging", "PASS",
            "${engine.name} extracted to nativeLibraryDir, ${engine.length()} bytes, " +
                "canExecute=${engine.canExecute()}, sha256=$hex")
    }

    /**
     * Read [process]'s merged output to EOF and wait for it to exit, giving up
     * after [timeoutMillis] on EVERY API level this harness declares. Returns
     * the trimmed output; the process has exited by the time this returns, so
     * [Process.exitValue] is safe on it.
     *
     * WHY THIS EXISTS. Both callers used `process.waitFor(20, TimeUnit.SECONDS)`
     * -- `java.lang.Process#waitFor(long, TimeUnit)`, which is **API 26**, in a
     * module whose `minSdk` is 24. On an API 24 or 25 handset that method is
     * simply absent, so the runtime raises `NoSuchMethodError` at the call
     * site. That is an `Error`, not an `Exception`, so the `catch (e: Exception)`
     * wrapped around each caller does not see it: the step would not report
     * FAIL, it would take the whole harness down. Exactly the defect fixed in
     * `WinnCarrierProfile.posixModeOrNull` on 2026-08-08 (an API 26
     * `java.nio.file` call under the same `minSdk 24`), and fixed the same way
     * -- gate it, and put a real implementation behind the gate rather than a
     * swallow. It went unreported here only because this module sets
     * `lint { abortOnError = false }`.
     *
     * WHY THE FALLBACK NEEDS A WATCHDOG. Below API 26 the only waiter is the
     * API 1 no-arg [Process.waitFor], which blocks forever -- and a bound is
     * the entire reason the timed overload was reached for. So below 26 the
     * bound has to come from outside the call, and that is what the daemon
     * watchdog below is: at the deadline it destroys the process, which ends
     * the blocking wait. Note that [Process.destroyForcibly] is **also** API
     * 26, so it is unavailable in precisely the branch that needs it;
     * [Process.destroy] (API 1) is the only termination primitive the fallback
     * can use, and it is more than enough for this harness's own short-lived
     * engine probes.
     *
     * WHY THE READ IS INSIDE THE BOUND. `readBytes()` blocks until EOF, and
     * both callers ran it BEFORE waiting -- so an engine that hung without
     * exiting hung the harness on the read, 20-second timeout or not. The
     * timeout only ever bounded a wait that, by then, had almost nothing left
     * to wait for. Arming the watchdog first puts the read under the same
     * deadline, which is what the timeout was always meant to promise.
     *
     * One behaviour change worth naming: on timeout the old code left the
     * process ALIVE and then threw `IllegalThreadStateException` out of
     * `exitValue()` into the caller's `catch`, reporting FAIL and leaking a
     * running engine. This kills it instead, so the step reports a real exit
     * status and nothing is left behind.
     */
    private fun readAndWaitAtMost(process: Process, timeoutMillis: Long): String {
        val finished = AtomicBoolean(false)
        val watchdog = Thread {
            try {
                Thread.sleep(timeoutMillis)
                if (!finished.get()) {
                    say("engine probe exceeded ${timeoutMillis} ms; destroying it")
                    process.destroy()
                }
            } catch (_: InterruptedException) {
                // Normal: the probe finished in time and disarmed us.
            } catch (t: Throwable) {
                Log.w(TAG, "engine probe watchdog", t)
            }
        }
        watchdog.isDaemon = true
        watchdog.start()
        return try {
            val output = process.inputStream.readBytes().toString(Charsets.UTF_8).trim()
            awaitExit(process, timeoutMillis)
            output
        } finally {
            finished.set(true)
            watchdog.interrupt()
        }
    }

    /**
     * Wait for [process] to exit. The watchdog in [readAndWaitAtMost] is the
     * outer deadline covering the read as well; this is the in-thread wait.
     *
     * API 26+ gets the timed overload, so the wait carries its own bound and
     * does not lean on the watchdog. API 24 and 25 -- the two levels that used
     * to raise `NoSuchMethodError` here -- get the API 1 no-arg wait, which is
     * unbounded on its own and is bounded by the watchdog destroying the
     * process.
     */
    private fun awaitExit(process: Process, timeoutMillis: Long) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            awaitExitTimed(process, timeoutMillis)
            return
        }
        process.waitFor()
    }

    /** API 26+ only -- see [awaitExit]. */
    @androidx.annotation.RequiresApi(Build.VERSION_CODES.O)
    private fun awaitExitTimed(process: Process, timeoutMillis: Long) {
        process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
    }

    /**
     * The packaged binary self-describes ON THIS DEVICE. `-print-contract`
     * writes a JSON banner and exits, so this reads the frame magic, version,
     * header size and payload semantics straight out of the artifact that is
     * about to be spawned, rather than assuming which binary was staged.
     */
    private fun step0Contract() {
        val engine = engineFile()
        if (!engine.isFile) return
        try {
            val process = ProcessBuilder(engine.absolutePath, "-print-contract")
                .redirectErrorStream(true)
                .start()
            val banner = readAndWaitAtMost(process, ENGINE_PROBE_TIMEOUT_MILLIS)
            val magicOk = banner.contains("\"frame_magic\":\"0x334E4E57\"")
            val headerOk = banner.contains("\"frame_header_size\":16")
            val versionOk = banner.contains("\"frame_version\":1")
            val payloadOk = banner.contains("AmneziaWG outer datagrams, not raw IP packets")
            result(
                "0b-packaged-engine-contract",
                if (magicOk && headerOk && versionOk && payloadOk) "PASS" else "FAIL",
                "exit=${process.exitValue()} banner=$banner",
            )
        } catch (e: Exception) {
            result("0b-packaged-engine-contract", "FAIL", describe(e))
        }
    }

    /**
     * The regression, reproduced on the device. `<engine> tunnel` is the argv
     * the host used to spawn; the binary takes flags only and dies on any
     * positional argument, before any handshake. Recording it here means the
     * failure this whole change fixes is demonstrated rather than described.
     */
    private fun step0OldSpawnContract() {
        val engine = engineFile()
        if (!engine.isFile) return
        try {
            val builder = ProcessBuilder(engine.absolutePath, "tunnel")
            builder.environment()["WINN_ENGINE_CHANNEL"] = "winn-engine-deadbeef"
            builder.redirectErrorStream(true)
            val process = builder.start()
            val output = readAndWaitAtMost(process, ENGINE_PROBE_TIMEOUT_MILLIS)
            val died = process.exitValue() != 0
            result(
                "0c-old-spawn-contract-still-fatal",
                if (died) "PASS" else "FAIL",
                "the previous argv+env produced exit=${process.exitValue()} \"$output\"; " +
                    "the current argv is ${WinnAndroidEngineHost.engineArguments(
                        engine.absolutePath, "<channel>").joinToString(" ")}",
            )
        } catch (e: Exception) {
            result("0c-old-spawn-contract-still-fatal", "FAIL", describe(e))
        }
    }

    // ------------------------------------------------------------------
    // step 1: VpnService.protect()
    // ------------------------------------------------------------------

    private fun step1Protect(step: String) {
        val socket = DatagramSocket()
        var owner: ParcelFileDescriptor? = null
        try {
            // Read SO_MARK before and after, so the value protect() installs on
            // the struct sock is visible rather than merely asserted.
            owner = ParcelFileDescriptor.fromDatagramSocket(socket)
            val before = sockoptInt(owner.fileDescriptor, OsConstants.SOL_SOCKET, 36)
            val ok = protect(socket)
            val after = sockoptInt(owner.fileDescriptor, OsConstants.SOL_SOCKET, 36)
            val detail = "VpnService.protect(DatagramSocket) returned $ok " +
                "(local port ${socket.localPort}, SO_MARK before=$before after=$after, " +
                "inode=${inodeOf(owner.fileDescriptor)})"
            result(step, if (ok) "PASS" else "FAIL", detail)
        } catch (e: Exception) {
            result(step, "FAIL", "protect() threw: ${describe(e)}")
        } finally {
            try { owner?.close() } catch (_: Exception) {}
            if (owner == null) socket.close()
        }
    }

    /**
     * The differential. With the tunnel up and this app's traffic routed into
     * it, and with nothing yet draining the tun, an unprotected socket cannot
     * reach the internet and a protected one can. This is what turns
     * "protect() returned true" into "protect() actually bypasses the tunnel".
     */
    private fun step1Differential() {
        val protectedSocket = DatagramSocket()
        val bareSocket = DatagramSocket()
        val target = if (mode == "routed") DIFFERENTIAL_TARGET else GATEWAY.substringBefore(':')
        try {
            val protectedOk = protect(protectedSocket)
            say("differential against $target: protect() on the first socket returned " +
                "$protectedOk; the second socket is deliberately left unprotected")

            val protectedResult = dnsProbe(protectedSocket, target, 6_000)
            val bareResult = dnsProbe(bareSocket, target, 6_000)
            say("differential: protected socket -> $protectedResult")
            say("differential: unprotected socket -> $bareResult")

            val verdict = when {
                protectedResult.startsWith("ok") && !bareResult.startsWith("ok") -> "PASS"
                protectedResult.startsWith("ok") && bareResult.startsWith("ok") -> "INCONCLUSIVE"
                else -> "FAIL"
            }
            result("1c-protect-differential", verdict,
                "protected=[$protectedResult] unprotected=[$bareResult]")
        } catch (e: Exception) {
            result("1c-protect-differential", "FAIL", describe(e))
        } finally {
            protectedSocket.close()
            bareSocket.close()
        }
    }

    // ------------------------------------------------------------------
    // step 4: the engine's own view of the descriptor it was handed
    // ------------------------------------------------------------------

    /**
     * The real engine reports `local_endpoint` in its status: the address of
     * the socket it adopted. If the descriptor crossed SCM_RIGHTS intact, that
     * is the very socket this process opened and protected, so the ports match.
     *
     * This is weaker than the retained inspector's inode/SO_COOKIE comparison
     * and deliberately so: it is what the REAL engine can be asked, with no
     * bespoke instrumentation on the far side.
     */
    private fun step4DescriptorIdentity(recorder: RecordingHost, statusJson: String) {
        val localEndpoint = jsonString(statusJson, "local_endpoint")
        val enginePort = localEndpoint.substringAfterLast(':').toIntOrNull() ?: -1
        val ownedByEngine = statusJson.contains("\"socket_owned_by_engine\":true")
        val match = recorder.parentPort > 0 && recorder.parentPort == enginePort

        say("parent socket : port=${recorder.parentPort} inode=${recorder.parentInode} " +
            "mark=${recorder.parentMark}")
        say("engine socket : local_endpoint=$localEndpoint socket_owned_by_engine=$ownedByEngine")

        result(
            "4-scm-rights-descriptor-adopted",
            if (match && !ownedByEngine) "PASS" else "FAIL",
            "the engine adopted a socket bound to $localEndpoint; the host protected and " +
                "handed over one bound to port ${recorder.parentPort}; match=$match; " +
                "socket_owned_by_engine=$ownedByEngine (must be false -- an engine-opened " +
                "socket carries no protect mark and would dead-loop the tunnel)",
        )
    }

    // ------------------------------------------------------------------
    // step 5: real datagrams, both ways, through the real engine
    // ------------------------------------------------------------------

    /**
     * Pushes one datagram through the whole real path:
     *
     *   harness seam -> WinnTunnelBridge inbound pump -> WNN3 Inbound frame
     *   -> real winn-datapath -> the PROTECTED socket -> 8.8.8.8:53
     *   -> reply -> WNN3 Outbound frame -> bridge outbound pump -> harness seam
     *
     * Nothing here is simulated. If the frame layout, the opcode vocabulary,
     * the direction rules or the descriptor hand-off were wrong, no reply
     * arrives.
     */
    private fun step5DatagramRoundTrip(seam: HarnessDatagramSeam) {
        try {
            val query = dnsQuery(0x5741, PROBE_NAME)
            seam.injectOutgoing(query)
            val reply = seam.awaitIncoming(15_000)
            if (reply == null) {
                result("5-datagram-round-trip", "FAIL",
                    "no Outbound frame came back within 15s; the engine sent " +
                        "${seam.outgoingCount.get()} Inbound datagram(s)")
                return
            }
            val idMatch = reply.size >= 2 &&
                reply[0] == 0x57.toByte() && reply[1] == 0x41.toByte()
            val answers = if (reply.size >= 8) {
                ((reply[6].toInt() and 0xFF) shl 8) or (reply[7].toInt() and 0xFF)
            } else 0
            result("5-datagram-round-trip", if (idMatch) "PASS" else "FAIL",
                "sent a ${query.size} byte datagram as an Inbound frame; the engine " +
                    "forwarded it to $GATEWAY over the protected socket and returned a " +
                    "${reply.size} byte Outbound frame; transaction id matched=$idMatch, " +
                    "$answers answer record(s)")
        } catch (e: Exception) {
            result("5-datagram-round-trip", "FAIL", describe(e))
        }
    }

    // ------------------------------------------------------------------
    // step 6: status round trip, and the counters that prove the bytes moved
    // ------------------------------------------------------------------

    private fun step6StatusRoundTrip(bridge: WinnTunnelBridge) {
        try {
            bridge.requestStatus()
            val deadline = System.currentTimeMillis() + 8_000
            var status = bridge.statusJson()
            while (System.currentTimeMillis() < deadline &&
                (jsonNumber(status, "tx_datagrams").toLongOrNull() ?: 0L) == 0L
            ) {
                Thread.sleep(200)
                status = bridge.statusJson()
            }
            val tx = jsonNumber(status, "tx_datagrams").toLongOrNull() ?: -1L
            val rx = jsonNumber(status, "rx_datagrams").toLongOrNull() ?: -1L
            say("final status JSON: $status")
            say("bridge health after a status round trip: healthy=${bridge.isHealthy()} " +
                "running=${bridge.isRunning()} failure=${bridge.failure()}")
            result("6-status-round-trip", if (tx > 0 && rx > 0) "PASS" else "FAIL",
                "StatusRequest was answered with StatusResponse; the engine counted " +
                    "tx_datagrams=$tx rx_datagrams=$rx over the protected socket; " +
                    "isHealthy()=${bridge.isHealthy()} (false until a round trip lands, " +
                    "so process existence alone cannot fake it)")
        } catch (e: Exception) {
            result("6-status-round-trip", "FAIL", describe(e))
        }
    }

    private fun step7Close(bridge: WinnTunnelBridge?) {
        if (bridge == null) return
        try {
            bridge.close()
            result("7-close-handshake", if (!bridge.isRunning()) "PASS" else "FAIL",
                "Close was sent and the bridge released the engine, the seam and the " +
                    "protected socket; isRunning()=${bridge.isRunning()}")
        } catch (e: Exception) {
            result("7-close-handshake", "FAIL", describe(e))
        }
    }

    // ------------------------------------------------------------------
    // step 8: a REAL AmneziaWG handshake carried by the real Winn engine
    // ------------------------------------------------------------------

    /**
     * The bar for this lane. Steps 3-6 prove the WIRE with a queue standing in
     * for the payload source; they say nothing about AmneziaWG. This step
     * replaces the queue with the real [WinnAwgLoopbackSeam] and puts a real
     * AmneziaWG engine on each end of it:
     *
     *     [libam-go.so from android/app/libs/amneziawg.aar]   <- the SHIPPING engine
     *         Endpoint = 127.0.0.1:<seam port>
     *              |
     *         [WinnAwgLoopbackSeam]                           <- the code under test
     *              |
     *         [WinnTunnelBridge, WNN3 frames]
     *              |
     *         [cmd/winn-datapath]                             <- the REAL engine
     *              |  the one protected socket, via SCM_RIGHTS
     *         127.0.0.1:<responder port>
     *              |
     *         [libawgresponder.so]                            <- the SAME amneziawg-go
     *
     * Nothing on this path is a double. If the seam mislabelled bytes, dropped
     * the AmneziaWG junk packets, truncated a datagram, replied to the wrong
     * local port, or if the peer endpoint drifted off loopback, the Noise
     * handshake does not complete and `last_handshake_time_sec` stays 0.
     */
    private fun step8AwgHandshakeThroughWinn(tun: ParcelFileDescriptor) {
        var responder: Process? = null
        var seam: WinnAwgLoopbackSeam? = null
        var bridge: WinnTunnelBridge? = null
        var awgHandle = -1
        try {
            val responderBinary = File(applicationInfo.nativeLibraryDir, RESPONDER_LIBRARY_NAME)
            if (!responderBinary.isFile) {
                result("8-awg-handshake", "FAIL",
                    "$RESPONDER_LIBRARY_NAME is not in nativeLibraryDir; " +
                        "run android/devicecheck/build_devicecheck.sh")
                return
            }

            // Both key pairs come from the shipping AAR's own Curve25519, so
            // even the key material on this path is the product's code.
            val initiator = KeyPair()
            val responderKeys = KeyPair()

            val responderPort = reserveUdpPort()
            responder = ProcessBuilder(
                responderBinary.absolutePath,
                "-listen-port", responderPort.toString(),
                "-private-key", responderKeys.privateKey.toBase64(),
                "-peer-public-key", initiator.publicKey.toBase64(),
                "-awg-params", awgUapiParams(),
                "-run-for", "120s",
            ).redirectErrorStream(true).start()
            val responderLines = drainResponder(responder)
            if (!awaitResponderLine(responderLines, "listening on udp/", 10_000)) {
                result("8-awg-handshake", "FAIL",
                    "the AmneziaWG responder never reported that it was listening")
                return
            }
            say("responder is listening on udp/$responderPort with ${awgUapiParams()}")

            // --- the seam under test ---------------------------------------
            // Named arguments deliberately: a trailing lambda binds to the LAST
            // parameter, which is now onSessionEnd (lossy, summary) -> Unit. The
            // bare trailing form used to reach onDropped and silently stopped
            // doing so when the seam grew a session-end callback.
            seam = WinnAwgLoopbackSeam.open(
                onDropped = { reason -> say("seam dropped a datagram: $reason") },
                onSessionEnd = { lossy, summary ->
                    say("seam session ended: lossy=$lossy $summary")
                },
            )
            result("8a-seam-open", "PASS",
                "WinnAwgLoopbackSeam bound to 127.0.0.1:${seam.localPort}. It was NOT " +
                    "passed to VpnService.protect(): the claim under test is that a " +
                    "loopback-bound socket needs no mark because Android resolves " +
                    "127.0.0.0/8 from the local table before any VPN rule, so it can " +
                    "never enter this service's tun. If that claim is false, the AWG " +
                    "engine's datagrams loop and no handshake completes.")

            step8eLoopbackConfinement()

            // --- the Winn bridge, pointed at the responder ------------------
            val winnConfig = WinnEngineConfig.from(
                section = linkedMapOf(
                    "enabled" to "true",
                    "endpoint" to "127.0.0.1:$responderPort",
                    "h1" to AWG_H1.toString(),
                    "h2" to AWG_H2.toString(),
                    "h3" to AWG_H3.toString(),
                    "h4" to AWG_H4.toString(),
                ),
                mtu = TUN_MTU,
            )
            say("winn config for the handshake run: ${winnConfig.describeForLog()}")
            val realHost = WinnAndroidEngineHost(
                vpnService = this,
                context = this,
                logDebug = { Log.i(TAG, "host: $it") },
                logWarn = { message, error -> Log.w(TAG, "host: $message", error) },
                logError = { message, error -> Log.e(TAG, "host: $message", error) },
            )
            val created = WinnTunnelBridge(
                host = SeamHost(realHost, seam),
                maxDatagram = winnConfig.maxDatagram,
                configJson = winnConfig.toConfigJson(),
            )
            created.start()
            bridge = created
            result("8b-bridge-with-real-seam", "PASS",
                "WinnTunnelBridge started against the real winn-datapath binary with the " +
                    "real loopback seam as its payload source (not the queue used in " +
                    "steps 3-6)")

            // --- the shipping AmneziaWG engine, pointed at the seam ---------
            System.loadLibrary("am-go")
            val awgConfig = buildAwgConfig(
                privateKey = initiator.privateKey.toBase64(),
                peerPublicKey = responderKeys.publicKey.toBase64(),
                seamPort = seam.localPort,
            )
            val awgTunFd = ParcelFileDescriptor.dup(tun.fileDescriptor).detachFd()
            awgHandle = GoBackend.awgTurnOn("winncheck", awgTunFd, awgConfig, filesDir.absolutePath)
            if (awgHandle < 0) {
                result("8-awg-handshake", "FAIL",
                    "GoBackend.awgTurnOn returned $awgHandle; the AmneziaWG engine did not start")
                return
            }
            val v4 = GoBackend.awgGetSocketV4(awgHandle)
            val v6 = GoBackend.awgGetSocketV6(awgHandle)
            result("8c-awg-sockets-left-unprotected", if (v4 >= 0 || v6 >= 0) "PASS" else "FAIL",
                "the AmneziaWG engine opened its own sockets (v4=$v4 v6=$v6) and " +
                    "VpnService.protect() was NOT called on either of them in this run. " +
                    "SO_MARK is not directly readable here (${markOfRawFd(v4)}), so the claim " +
                    "is not made from a mark: it is made from the combination of step 1c -- an " +
                    "unprotected socket provably cannot reach the network while this tunnel is " +
                    "up -- and step 8 below. If loopback were subject to the VPN routing, these " +
                    "unmarked sockets would have had their datagrams captured by this service's " +
                    "own tun and no handshake could complete. A completed handshake is therefore " +
                    "the measurement, and the only socket carrying a protect mark anywhere on " +
                    "this path is the one the Winn engine received by SCM_RIGHTS.")

            // WireGuard only initiates when it has something to send. Real
            // traffic from an ordinary unprotected socket is the honest
            // trigger: it enters this service's tun, the AmneziaWG engine
            // reads it, finds no session and starts a handshake.
            nudgeTunnelTraffic()

            // --- the verdict -----------------------------------------------
            val deadline = System.currentTimeMillis() + 45_000
            var handshake = "0"
            var awgState = ""
            while (System.currentTimeMillis() < deadline) {
                awgState = GoBackend.awgGetConfig(awgHandle) ?: ""
                handshake = uapiValue(awgState, "last_handshake_time_sec")
                if (handshake.isNotEmpty() && handshake != "0") break
                Thread.sleep(250)
            }
            created.requestStatus()
            Thread.sleep(750)
            val winnStatus = created.statusJson()
            val tx = jsonNumber(winnStatus, "tx_datagrams").toLongOrNull() ?: -1L
            val rx = jsonNumber(winnStatus, "rx_datagrams").toLongOrNull() ?: -1L

            say("AmneziaWG engine state: rx_bytes=${uapiValue(awgState, "rx_bytes")} " +
                "tx_bytes=${uapiValue(awgState, "tx_bytes")} " +
                "last_handshake_time_sec=$handshake")
            say("winn engine status: $winnStatus")
            say(seam.describeForLog())
            say("responder said: ${responderLines.joinToString(" | ")}")

            val handshakeCompleted = handshake.isNotEmpty() && handshake != "0"
            val carriedBothWays = seam.outgoingCount > 0 && seam.incomingCount > 0
            val engineCarriedIt = tx > 0 && rx > 0
            val responderAgrees = responderLines.any { it.contains("HANDSHAKE COMPLETE") }

            result(
                "8-awg-handshake",
                if (handshakeCompleted && carriedBothWays && engineCarriedIt && responderAgrees)
                    "PASS" else "FAIL",
                "AmneziaWG handshake completed=$handshakeCompleted " +
                    "(last_handshake_time_sec=$handshake); the responder independently " +
                    "reported completion=$responderAgrees; every outer datagram crossed the " +
                    "seam (out=${seam.outgoingCount} in=${seam.incomingCount}) and the real " +
                    "winn-datapath engine (tx_datagrams=$tx rx_datagrams=$rx). " +
                    "Payload was declared \"awg-datagram\" and the bytes really were " +
                    "AmneziaWG outer datagrams, obfuscation profile ${awgUapiParams()}.",
            )

            step8dClassification(winnStatus, handshakeCompleted)
        } catch (e: Throwable) {
            result("8-awg-handshake", "FAIL", describe(e))
        } finally {
            if (awgHandle >= 0) {
                try { GoBackend.awgTurnOff(awgHandle) } catch (e: Throwable) {
                    Log.w(TAG, "awgTurnOff", e)
                }
            }
            try { bridge?.close() } catch (e: Exception) { Log.w(TAG, "bridge close", e) }
            try { seam?.close() } catch (e: Exception) { Log.w(TAG, "seam close", e) }
            try { responder?.destroy() } catch (e: Exception) { Log.w(TAG, "responder stop", e) }
        }
    }

    /**
     * The seam's containment claim, measured rather than asserted.
     *
     * [WinnAwgLoopbackSeam] argues that binding to 127.0.0.1 makes the relay
     * structurally incapable of reaching the network, so it needs no
     * `VpnService.protect()` and can never be the second unprotected socket
     * that dead-loops the tunnel. That is a claim about the kernel, so it is
     * worth one syscall: a socket bound the same way must fail to address an
     * off-device host. If it succeeds, the containment is administrative rather
     * than structural and the seam's KDoc is overstating it.
     */
    private fun step8eLoopbackConfinement() {
        val confined = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        try {
            confined.soTimeout = 2_000
            val probe = dnsQuery(0x5743, PROBE_NAME)
            val outcome = try {
                confined.send(
                    DatagramPacket(
                        probe, probe.size,
                        InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53),
                    )
                )
                // A send that is accepted is not yet a leak; a reply would be.
                val back = DatagramPacket(ByteArray(1500), 1500)
                confined.receive(back)
                "REACHED THE NETWORK: ${back.length} bytes from ${back.address?.hostAddress}"
            } catch (e: Exception) {
                "refused: ${e.javaClass.simpleName}: ${e.message}"
            }
            result(
                "8e-seam-socket-cannot-address-the-network",
                if (!outcome.startsWith("REACHED")) "PASS" else "FAIL",
                "a socket bound exactly as the seam binds (127.0.0.1:0) tried to reach " +
                    "8.8.8.8:53 and $outcome. This is why the seam needs no protect(): its " +
                    "confinement does not depend on a routing rule being right, and it cannot " +
                    "become the second unprotected network socket that WinnUnderlaySocket warns " +
                    "would dead-loop the tunnel.",
            )
        } finally {
            confined.close()
        }
    }

    /**
     * The engine's own reading of what it just carried.
     *
     * The Winn datapath classifies each outer datagram by its leading 4-byte
     * word (`datapath/classify.go`). AmneziaWG prepends S1 random bytes to a
     * handshake initiation and S2 to a handshake response
     * (amneziawg-go `device/send.go`). With the shipping profile those are 16
     * and 80, so the leading word of every handshake datagram is random and the
     * engine cannot recognise it -- `tx_handshake_initiations`,
     * `rx_handshake_responses`, `handshake_response_observed` and
     * `transport_observed_both_ways` stay at zero/false for a tunnel that is
     * demonstrably healthy.
     *
     * Run with `--es awgpadding nopadding` to see the same handshake classify
     * correctly with S1=S2=S3=0. The verdict below is deliberately about the
     * DIFFERENCE between the two runs, not about either alone.
     */
    private fun step8dClassification(winnStatus: String, handshakeCompleted: Boolean) {
        val initiations = jsonNumber(winnStatus, "tx_handshake_initiations").toLongOrNull() ?: -1L
        val responses = jsonNumber(winnStatus, "rx_handshake_responses").toLongOrNull() ?: -1L
        val observed = winnStatus.contains("\"handshake_response_observed\":true")
        val bothWays = winnStatus.contains("\"transport_observed_both_ways\":true")
        val classification = jsonString(winnStatus, "awg_classification")
        val (s1, s2, s3) = awgPadding()
        val padded = s1 > 0 || s2 > 0

        // With padding on, the engine MUST fail to classify the handshake; with
        // padding off it MUST succeed. Either outcome inverted would mean this
        // explanation of the mechanism is wrong.
        val asPredicted =
            if (padded) initiations == 0L && responses == 0L && !observed
            else initiations > 0L && responses > 0L && observed

        result(
            "8d-engine-classification-vs-shipping-padding",
            if (handshakeCompleted && asPredicted) "PASS" else "FAIL",
            "padding S1=$s1 S2=$s2 S3=$s3; awg_classification=$classification; the engine " +
                "counted tx_handshake_initiations=$initiations rx_handshake_responses=$responses " +
                "handshake_response_observed=$observed transport_observed_both_ways=$bothWays " +
                "for a handshake that DID complete. " +
                if (padded) {
                    "This is the shipping profile, and the counters are zero: AmneziaWG puts " +
                        "S1/S2 random bytes in front of the header-type word that " +
                        "datapath/classify.go reads, so no handshake datagram can ever be " +
                        "classified. Any health check or route-promotion gate keyed on these " +
                        "fields can never fire for this app. Transport datagrams still classify " +
                        "because S4=0 leaves them unpadded."
                } else {
                    "With S1/S2 zeroed the same handshake classifies correctly, which isolates " +
                        "the padding as the cause rather than the header types, the seam or the " +
                        "carrier."
                },
        )
    }

    /**
     * The AmneziaWG configuration, in the SHIPPING format: this is
     * `_buildRawAmneziaConfig` in lib/main.dart with the peer endpoint pointed
     * at the seam instead of at the gateway -- exactly the one-line change the
     * production wiring would make, and exactly the change the app already
     * makes today for the stealth-Xray transport.
     */
    private fun buildAwgConfig(privateKey: String, peerPublicKey: String, seamPort: Int): String {
        val (s1, s2, s3) = awgPadding()
        return """
        [Interface]
        PrivateKey = $privateKey
        Address = $AWG_INNER_ADDRESS/32
        MTU = $TUN_MTU
        Jc = $AWG_JC
        Jmin = $AWG_JMIN
        Jmax = $AWG_JMAX
        S1 = $s1
        S2 = $s2
        S3 = $s3
        S4 = $AWG_S4
        H1 = $AWG_H1
        H2 = $AWG_H2
        H3 = $AWG_H3
        H4 = $AWG_H4

        [Peer]
        PublicKey = $peerPublicKey
        Endpoint = ${WinnAwgLoopbackSeam.peerEndpoint(seamPort)}
        AllowedIPs = 0.0.0.0/0
        PersistentKeepalive = 5
        """.trimIndent()
    }

    /** A port nothing else holds, released immediately so the responder can bind it. */
    private fun reserveUdpPort(): Int {
        val probe = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port = probe.localPort
        probe.close()
        return port
    }

    private fun drainResponder(process: Process): MutableList<String> {
        val lines = java.util.Collections.synchronizedList(ArrayList<String>())
        Thread {
            try {
                process.inputStream.bufferedReader().useLines { stream ->
                    stream.forEach { line ->
                        lines.add(line)
                        say("awgresponder: $line")
                    }
                }
            } catch (_: Exception) {
            }
        }.apply {
            name = "winn-devicecheck-responder-log"
            isDaemon = true
            start()
        }
        return lines
    }

    private fun awaitResponderLine(lines: List<String>, needle: String, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            synchronized(lines) {
                if (lines.any { it.contains(needle) }) return true
            }
            Thread.sleep(100)
        }
        return false
    }

    /**
     * Sends one ordinary datagram into the tunnel so the AmneziaWG engine has a
     * reason to start a handshake. The socket is deliberately NOT protected: it
     * is meant to be captured by the tun, which is what produces the outbound
     * packet the engine must encapsulate.
     */
    private fun nudgeTunnelTraffic() {
        try {
            DatagramSocket().use { socket ->
                val query = dnsQuery(0x5742, PROBE_NAME)
                socket.send(
                    DatagramPacket(
                        query, query.size,
                        InetSocketAddress(InetAddress.getByName(DIFFERENTIAL_TARGET), 53),
                    )
                )
                say("nudged the tunnel with one unprotected datagram to $DIFFERENTIAL_TARGET:53 " +
                    "so the AmneziaWG engine has traffic to encapsulate")
            }
        } catch (e: Exception) {
            say("tunnel nudge failed (persistent keepalive should still trigger): ${describe(e)}")
        }
    }

    /** The host with only [openAwgDatagramSeam] replaced by the real loopback seam. */
    private inner class SeamHost(
        private val real: WinnAndroidEngineHost,
        private val seam: WinnAwgLoopbackSeam,
    ) : WinnEngineHost {
        override fun openProtectedUnderlaySocket(): WinnUnderlaySocket =
            real.openProtectedUnderlaySocket()

        override fun startEngineProcess(): WinnEngineProcess = real.startEngineProcess()

        override fun openAwgDatagramSeam(): WinnAwgDatagramSeam = seam

        override fun onDebug(message: String) = real.onDebug(message)
        override fun onWarning(message: String, error: Throwable?) = real.onWarning(message, error)
        override fun onError(message: String, error: Throwable?) = real.onError(message, error)
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private fun establishTunnel(): ParcelFileDescriptor? {
        val builder = Builder()
            .addAddress(TUN_ADDRESS, 32)
            .setMtu(TUN_MTU)
            .setSession("winn-devicecheck")
        builder.setBlocking(true)
        if (mode == "routed") {
            // Every uid is inside the tunnel, which is what the shipping
            // VpnTunnelService does for Winn. Only two prefixes are routed
            // into it, so no other app on this phone loses anything: one
            // documentation range, and the single public /32 the differential
            // needs to be decisive.
            builder.addRoute(DIFFERENTIAL_TARGET, 32)
            builder.addRoute("10.211.0.0", 16)
            say("tunnel mode=routed: all uids in the tunnel, routes limited to " +
                "$DIFFERENTIAL_TARGET/32 and 10.211.0.0/16, no DNS server announced")
        } else {
            builder.addRoute("0.0.0.0", 0)
            builder.addDnsServer(TUN_DNS)
            try {
                builder.addAllowedApplication(packageName)
            } catch (e: Exception) {
                say("addAllowedApplication failed: ${describe(e)}")
            }
            say("tunnel mode=scoped: only $packageName is inside the tunnel")
        }
        return builder.establish()
    }

    /**
     * Whether this uid's default network is actually the VPN. Without this the
     * differential cannot be interpreted: a socket that never entered the
     * tunnel proves nothing about protect().
     */
    private fun reportNetworkPlacement(label: String) {
        try {
            val manager = getSystemService(android.net.ConnectivityManager::class.java)
            val active = manager.activeNetwork
            val capabilities = active?.let { manager.getNetworkCapabilities(it) }
            val link = active?.let { manager.getLinkProperties(it) }
            val isVpn = capabilities?.hasTransport(
                android.net.NetworkCapabilities.TRANSPORT_VPN) ?: false
            say("$label: activeNetwork=$active interface=${link?.interfaceName} " +
                "TRANSPORT_VPN=$isVpn " +
                "NOT_VPN_capability=${capabilities?.hasCapability(
                    android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)}")
        } catch (e: Exception) {
            say("$label: network placement unavailable: ${describe(e)}")
        }
    }

    private fun dnsProbe(socket: DatagramSocket, server: String, timeoutMs: Int): String {
        return try {
            socket.soTimeout = timeoutMs
            val query = dnsQuery(0x5741, PROBE_NAME)
            socket.send(DatagramPacket(query, query.size,
                InetSocketAddress(InetAddress.getByName(server), 53)))
            val buffer = ByteArray(1500)
            val reply = DatagramPacket(buffer, buffer.size)
            val started = System.currentTimeMillis()
            socket.receive(reply)
            val elapsed = System.currentTimeMillis() - started
            val idMatch = reply.length >= 2 &&
                buffer[0] == 0x57.toByte() && buffer[1] == 0x41.toByte()
            val answers = if (reply.length >= 8) {
                ((buffer[6].toInt() and 0xFF) shl 8) or (buffer[7].toInt() and 0xFF)
            } else 0
            if (idMatch) {
                "ok: ${reply.length} byte reply from ${reply.address.hostAddress}:${reply.port} " +
                    "in ${elapsed}ms, $answers answer record(s)"
            } else {
                "reply of ${reply.length} bytes but the transaction id did not match"
            }
        } catch (e: Exception) {
            "no reply: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    private fun dnsQuery(id: Int, name: String): ByteArray {
        val out = ArrayList<Byte>(64)
        out.add((id ushr 8).toByte()); out.add((id and 0xFF).toByte())
        out.add(0x01); out.add(0x00) // recursion desired
        out.add(0x00); out.add(0x01) // one question
        out.add(0x00); out.add(0x00)
        out.add(0x00); out.add(0x00)
        out.add(0x00); out.add(0x00)
        for (label in name.split(".")) {
            if (label.isEmpty()) continue
            out.add(label.length.toByte())
            for (c in label.toByteArray(Charsets.US_ASCII)) out.add(c)
        }
        out.add(0x00)
        out.add(0x00); out.add(0x01) // A
        out.add(0x00); out.add(0x01) // IN
        return out.toByteArray()
    }

    /**
     * The harness's own outer-datagram seam.
     *
     * The shipping host has none -- see WinnAwgDatagramSeam for why -- and that
     * gap is real. This one exists so the WIRE can be verified end to end
     * without one: it is a queue, not an AmneziaWG engine, and the bytes it
     * carries are a DNS query rather than an AWG datagram. The engine forwards
     * whatever it is given verbatim, so this exercises exactly the same code
     * path a real seam would, and claims nothing about AmneziaWG.
     */
    private class HarnessDatagramSeam : WinnAwgDatagramSeam {
        private val outgoing = LinkedBlockingQueue<ByteArray>()
        private val incoming = LinkedBlockingQueue<ByteArray>()
        private val closed = AtomicBoolean(false)
        val outgoingCount = AtomicInteger(0)

        override fun readOutgoingDatagram(buffer: ByteArray): Int {
            while (!closed.get()) {
                val datagram = outgoing.poll(25, TimeUnit.MILLISECONDS) ?: continue
                val n = minOf(buffer.size, datagram.size)
                System.arraycopy(datagram, 0, buffer, 0, n)
                outgoingCount.incrementAndGet()
                return n
            }
            return -1
        }

        override fun writeIncomingDatagram(datagram: ByteArray, length: Int) {
            incoming.put(datagram.copyOf(length))
        }

        fun injectOutgoing(datagram: ByteArray) = outgoing.put(datagram)

        fun awaitIncoming(timeoutMs: Long): ByteArray? =
            incoming.poll(timeoutMs, TimeUnit.MILLISECONDS)

        override fun close() {
            closed.set(true)
        }
    }

    private inner class RecordingHost(
        private val real: WinnAndroidEngineHost,
        private val seam: HarnessDatagramSeam,
    ) : WinnEngineHost {
        var parentInode: String = ""
        var parentPort: Int = -1
        var parentMark: String = "unread"

        override fun openProtectedUnderlaySocket(): WinnUnderlaySocket {
            val socket = real.openProtectedUnderlaySocket()
            parentPort = socket.localPort
            parentInode = inodeOf(socket.descriptor)
            parentMark = sockoptInt(socket.descriptor, OsConstants.SOL_SOCKET, 36)
            result("1d-protect-in-real-host-code", "PASS",
                "WinnAndroidEngineHost.openProtectedUnderlaySocket() returned a socket " +
                    "with protectedBeforeHandoff=${socket.protectedBeforeHandoff}, " +
                    "port=$parentPort, inode=$parentInode, SO_MARK=$parentMark")
            return socket
        }

        override fun startEngineProcess(): WinnEngineProcess = real.startEngineProcess()

        /**
         * The one thing the harness substitutes. The real host returns null
         * here, which is the honest answer for the shipping app and would make
         * the bridge refuse to start; the harness supplies a queue so the wire
         * itself can be exercised. Everything else is the real host.
         */
        override fun openAwgDatagramSeam(): WinnAwgDatagramSeam {
            val production = real.openAwgDatagramSeam()
            result("3b-production-seam-absent", if (production == null) "PASS" else "FAIL",
                "WinnAndroidEngineHost.openAwgDatagramSeam() returned $production. Null is " +
                    "correct today: the engine carries AmneziaWG outer datagrams and this " +
                    "app's AWG engine exposes no seam that yields them, so the shipping " +
                    "bridge refuses to start rather than sending tun packets mislabelled " +
                    "as datagrams. The harness substitutes a queue to exercise the wire.")
            return seam
        }

        override fun onDebug(message: String) = real.onDebug(message)
        override fun onWarning(message: String, error: Throwable?) = real.onWarning(message, error)
        override fun onError(message: String, error: Throwable?) = real.onError(message, error)

        fun describeParent(): String = "inode=$parentInode port=$parentPort mark=$parentMark"
    }
}

// ----------------------------------------------------------------------
// free functions
// ----------------------------------------------------------------------

internal fun inodeOf(fd: FileDescriptor): String = try {
    val dup = ParcelFileDescriptor.dup(fd)
    try {
        val link = Os.readlink("/proc/self/fd/${dup.fd}")
        if (link.startsWith("socket:[") && link.endsWith("]")) {
            link.substring("socket:[".length, link.length - 1)
        } else {
            link
        }
    } finally {
        dup.close()
    }
} catch (e: Throwable) {
    "unavailable(${e.javaClass.simpleName}: ${e.message})"
}

/**
 * Reflection rather than a direct call so that an option this platform refuses
 * to expose is reported instead of failing the build.
 */
internal fun sockoptInt(fd: FileDescriptor, level: Int, option: Int): String = try {
    val method = Os::class.java.getMethod(
        "getsockoptInt",
        FileDescriptor::class.java,
        Int::class.javaPrimitiveType,
        Int::class.javaPrimitiveType,
    )
    (method.invoke(null, fd, level, option) as Int).toString()
} catch (e: Throwable) {
    val cause = e.cause ?: e
    "unavailable(${cause.javaClass.simpleName}: ${cause.message})"
}

/** One value out of an AmneziaWG uapi document (`key=value` per line). */
internal fun uapiValue(document: String, key: String): String {
    for (line in document.split('\n')) {
        val trimmed = line.trim()
        val separator = trimmed.indexOf('=')
        if (separator > 0 && trimmed.substring(0, separator) == key) {
            return trimmed.substring(separator + 1)
        }
    }
    return ""
}

/**
 * SO_MARK for a raw descriptor number, which is what `awgGetSocketV4/V6`
 * return. `Os.getsockoptInt` wants a FileDescriptor, and there is no public
 * constructor that takes an int, so the field is set reflectively. Diagnostic
 * only: a failure here is reported, never fatal.
 */
internal fun markOfRawFd(rawFd: Int): String {
    if (rawFd < 0) return "no-socket($rawFd)"
    return try {
        val fd = FileDescriptor()
        val field = FileDescriptor::class.java.getDeclaredField("descriptor")
        field.isAccessible = true
        field.setInt(fd, rawFd)
        sockoptInt(fd, OsConstants.SOL_SOCKET, 36)
    } catch (e: Throwable) {
        "unavailable(${e.javaClass.simpleName})"
    }
}

internal fun describe(error: Throwable): String {
    val parts = ArrayList<String>()
    var current: Throwable? = error
    var guard = 0
    while (current != null && guard++ < 8) {
        parts.add("${current.javaClass.name}: ${current.message}")
        current = current.cause
    }
    return parts.joinToString(" <- ")
}

internal fun jsonString(json: String, key: String): String {
    val marker = "\"$key\":\""
    val start = json.indexOf(marker)
    if (start < 0) return ""
    val from = start + marker.length
    val end = json.indexOf('"', from)
    if (end < 0) return ""
    return json.substring(from, end)
}

internal fun jsonNumber(json: String, key: String): String {
    val marker = "\"$key\":"
    val start = json.indexOf(marker)
    if (start < 0) return ""
    var from = start + marker.length
    if (from < json.length && json[from] == '"') return ""
    var end = from
    while (end < json.length && (json[end].isDigit() || json[end] == '-')) end++
    return json.substring(from, end)
}
