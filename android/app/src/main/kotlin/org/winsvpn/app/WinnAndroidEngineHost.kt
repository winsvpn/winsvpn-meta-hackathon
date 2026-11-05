package org.winsvpn.app

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.BufferedInputStream
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The Android implementation of [WinnEngineHost].
 *
 * Packaging follows the `libxray.so` precedent exactly (see
 * `tools/build_xray_engine.sh` and `tools/prepare_android_xray_assets.sh`):
 * the Go engine is cross-compiled to a plain executable, named `lib*.so` so
 * the package installer extracts it, dropped in
 * `android/app/src/main/jniLibs/<abi>/`, and executed from
 * `applicationInfo.nativeLibraryDir`. No new packaging mechanism, no new
 * Gradle configuration: `useLegacyPackaging = true` and the existing
 * `abiFilters` already cover it.
 *
 * The channel is one abstract-namespace AF_UNIX stream socket rather than the
 * subprocess's stdin/stdout, for one hard reason: SCM_RIGHTS. A pipe cannot
 * carry a file descriptor, and the protected UDP socket has to cross the
 * process boundary as a descriptor. stdout/stderr stay free for engine logs,
 * drained to logcat the same way the Xray subprocess already is.
 *
 * `LocalServerSocket(name)` binds in the Linux ABSTRACT namespace, i.e. the
 * kernel address is "\0<name>". A Go client reaches it with
 * `net.Dial("unix", "@"+name)`: Go's `SockaddrUnix` turns a leading '@' into
 * the leading NUL byte the kernel uses for the abstract namespace.
 *
 * THE SPAWN CONTRACT IS READ FROM THE ENGINE, NOT ASSUMED. Everything below
 * comes from `winn_protocol_experimental/cmd/winn-datapath/main.go`:
 *
 *  - It parses flags only. `flags.NArg() != 0` makes any positional argument a
 *    fatal error, so the `"tunnel"` subcommand this host used to pass killed
 *    the process before a single frame was exchanged:
 *    `winn-datapath: unexpected argument "tunnel"`, exit 1.
 *  - It reads NO environment variables. `WINN_ENGINE_CHANNEL` appears nowhere
 *    in the Go tree; the channel is named by `-control`.
 *  - The engine DIALS, this host LISTENS. `serveUnix` calls `net.Dial("unix",
 *    opts.control)`, so the listener must be bound before the child starts.
 *  - `-receive-fd` makes it read exactly one SCM_RIGHTS descriptor with a
 *    one-byte `recvmsg` BEFORE serving frames. See
 *    [WinnEngineTransport.sendDescriptor].
 *
 * The engine also self-describes: `winn-datapath -print-contract` prints the
 * frame magic, version, header size and payload semantics as JSON and exits.
 * That is a build-verification hook, never a runtime one -- it writes a plain
 * JSON line to stdout, not a frame.
 */
internal class WinnAndroidEngineHost(
    private val vpnService: VpnService,
    private val context: Context,
    private val logDebug: (String) -> Unit,
    private val logWarn: (String, Throwable?) -> Unit,
    private val logError: (String, Throwable?) -> Unit,
    /**
     * The already-open outer-datagram seam, or null when this host has none.
     *
     * It is INJECTED rather than opened here, and that is the whole safety
     * property: a seam is only correct if the AmneziaWG engine has actually been
     * pointed at it. Opening one here would produce a relay nothing sends to,
     * so [WinnTunnelBridge] would start happily and then carry nothing --
     * strictly worse than the refusal it does today. Only the caller that
     * rewrote the AmneziaWG peer endpoint knows the seam is wired, so only that
     * caller may supply it. See [WinnAwgLoopbackSeam].
     */
    private val awgDatagramSeam: WinnAwgDatagramSeam? = null,
    /**
     * The carrier profile file this session's engine must be pointed at, or
     * null for a direct-awg session.
     *
     * Like [awgDatagramSeam] it is INJECTED rather than built here, and for the
     * same class of reason: only the caller that resolved the carrier from the
     * `[winn]` section knows whether this session is a carrier session, and
     * writing a profile here would let this host start a carrier the
     * configuration never asked for.
     */
    private val carrierProfilePath: String? = null,
    /**
     * Whether this host spawns the engine in v3 mode.
     *
     * False keeps the argv byte-identical to what every shipping session uses
     * today; true appends [WinnV3Host.FLAG_WINN3], which builds
     * `driver.NewClient` instead of `datapath.Open` and moves the
     * Inbound/Outbound payload from AmneziaWG outer datagrams to inner IP
     * packets.
     *
     * It is a constructor flag rather than a parameter of [startEngineProcess]
     * because the choice belongs to whoever built this host :  the same caller
     * that decided which seam to open :  and a per-call parameter would let one
     * host spawn both, which is a mode-flag of exactly the kind
     * [WinnV3IpPacketSeam] exists to make unrepresentable.
     *
     * NOTHING HERE PROBES THE ENGINE. [supportsV3] is the probe, and the caller
     * must run it before constructing this with true; see the refusal in
     * [WinnV3Host.NO_V3_ENGINE].
     */
    private val winn3: Boolean = false,
    /**
     * The `-winn3-keys` document, for a v3 spawn.
     *
     * MANDATORY when [winn3] is true, and [startEngineProcess] refuses without
     * it. The engine refuses `-winn3` and `-winn3-keys` each without the other,
     * so a spawn missing this produces a subprocess that exits 1 with a message
     * only logcat sees; refusing here names the gap before a process exists.
     * Like [carrierProfilePath] it is a PATH :  see [WinnV3Keys].
     */
    private val winn3KeysPath: String? = null,
    private val winn3GatewayEndpoint: String? = null,
) : WinnEngineHost {

    companion object {

        /**
         * Accepts until a connection from [ownUid] arrives, closing every other
         * one. A foreign connection is refused, not allowed to abort the start.
         * Pure so a JVM test can drive it without LocalServerSocket.
         */
        internal fun <S> acceptFromOwnUid(
            accept: () -> S,
            uidOf: (S) -> Int,
            close: (S) -> Unit,
            ownUid: Int,
            onForeign: () -> Unit = {},
        ): S {
            while (true) {
                val candidate = accept()
                val uid = try {
                    uidOf(candidate)
                } catch (_: IOException) {
                    -1
                }
                if (uid == ownUid) return candidate
                onForeign()
                try {
                    close(candidate)
                } catch (_: IOException) {
                }
            }
        }
        /** Same naming rule as libxray.so: must be `lib*.so` to be extracted. */
        const val ENGINE_LIBRARY_NAME = "libwinnengine.so"

        private const val ACCEPT_TIMEOUT_MS = 8_000L

        /** `-print-contract` writes one line and exits; this only bounds a hang. */
        private const val CONTRACT_PROBE_TIMEOUT_MS = 4_000L

        private val RANDOM = SecureRandom()

        // The packaged engine's banner, keyed on the file the package installer
        // extracted. The file cannot change without a package update, which
        // replaces this process, so one spawn per process is enough.
        private data class ProbeKey(val path: String, val length: Long, val modified: Long)
        @Volatile
        private var cachedV3Probe: Pair<ProbeKey, Pair<Boolean, String>>? = null

        /** Connect the protected, already-bound socket without replacing it. */
        fun connectUnderlaySocket(socket: DatagramSocket, endpoint: String) {
            require(WinnEngineConfig.isIpLiteralEndpoint(endpoint)) {
                "Winn underlay endpoint must be an IP literal with a port"
            }
            val host = endpoint.substringBeforeLast(':').removeSurrounding("[", "]")
            val peer = InetSocketAddress(
                InetAddress.getByName(host),
                endpoint.substringAfterLast(':').toInt(),
            )
            val localPort = socket.localPort
            check(socket.isBound && !socket.isClosed && localPort > 0) {
                "Winn underlay socket must be open and bound before connect"
            }
            socket.connect(peer)
            check(socket.isConnected && socket.remoteSocketAddress == peer &&
                socket.localPort == localPort
            ) { "Winn underlay socket did not retain its bound port and gateway peer" }
        }

        /**
         * The argv `winn-datapath` actually parses, for the abstract socket
         * named [channelName]. Exposed so a test can assert the spawn contract
         * without spawning anything.
         *
         * [carrierProfilePath], when non-null, adds `-carrier-profile PATH`.
         * That single flag is what moves this session from `datapath.Open`
         * (direct-awg, classical AmneziaWG on the wire) to
         * `datapath.OpenWithCarrier` (AmneziaWG datagrams inside authenticated
         * Winn envelopes over HTTP/3 CONNECT-UDP, with a post-quantum TLS 1.3
         * handshake, ECH and ML-DSA signing).
         *
         * THE PATH IS PASSED, NOT THE DOCUMENT. The engine opens the file
         * itself, under this application's own uid, and makes every trust
         * decision there. Inlining the configuration into the Create frame
         * instead would make it material the child had to trust because the
         * peer said so -- which is the objection `datapath/carrier.go` raises
         * against carrying a carrier configuration across the C ABI, and it
         * applies just as much to the duplex frame channel.
         */
        fun engineArguments(
            enginePath: String,
            channelName: String,
            carrierProfilePath: String? = null,
        ): List<String> = buildList {
            add(enginePath)
            add("-transport"); add("unix")
            // Leading '@' is how Go names an abstract-namespace socket, which
            // is what LocalServerSocket binds.
            add("-control"); add("@$channelName")
            // The protected UDP descriptor arrives over the control socket's
            // ancillary data rather than being inherited by number.
            add("-receive-fd")
            if (carrierProfilePath != null) {
                require(carrierProfilePath.isNotBlank()) {
                    "A blank carrier profile path would make the engine fall back to " +
                        "datapath.Open and start direct-awg for a session configured for a " +
                        "carrier; refusing to build that argv."
                }
                add("-carrier-profile"); add(carrierProfilePath)
            }
        }
    }

    /**
     * Runs the PACKAGED engine once with `-print-contract` and asks
     * [WinnV3Host.engineSupportsV3] whether it can carry a v3 session.
     *
     * THE BINARY IN THE APK IS THE ONE THAT MATTERS, and it is not the one a
     * developer's `go build` produces. `WinnEngineInteropTest` builds the engine
     * from source on the host machine, so a source tree that has grown the
     * `payloads` field makes that test green while every handset in the field is
     * still running whatever `.so` was packaged :  which, at the time this probe
     * was written, advertised no `payloads` key at all. So this probes the file
     * under `nativeLibraryDir` and nothing else.
     *
     * A probe that cannot run is a probe that failed: the answer is false, the
     * caller refuses, and the session does not silently become v1. That is the
     * same discipline [WinnV3Host.engineSupportsV3] applies to a banner with no
     * `payloads` key.
     *
     * The banner is returned alongside the verdict so the refusal can quote what
     * the engine actually said.
     */
    fun probeV3Support(): Pair<Boolean, String> {
        val engine = try {
            resolveEngineExecutable()
        } catch (e: IOException) {
            return false to "the packaged engine could not be resolved: ${e.message}"
        }
        val key = ProbeKey(engine.absolutePath, engine.length(), engine.lastModified())
        cachedV3Probe?.let { (cachedKey, answer) ->
            if (cachedKey == key && answer.first) return answer
        }
        val answer = try {
            val process = ProcessBuilder(engine.absolutePath, "-print-contract")
                .redirectErrorStream(true)
                .start()

            // THE TIMEOUT IS A WATCHDOG, NOT `Process.waitFor(long, TimeUnit)`.
            //
            // That overload is API 26 and this app's minSdk is 24, so on an
            // API 24/25 handset it raises NoSuchMethodError -- an ERROR, which
            // the `catch (e: Exception)` below does not catch. That is exactly
            // the defect WinnCarrierProfile shipped (an API-26 call guarded by
            // catch (Exception), which crashed every API 24/25 user on first
            // connect), and Android lint caught this one before it left the
            // tree. The fix is a version-safe path rather than a wider catch:
            // the tree holds three Error-catching clauses and this adds none.
            //
            // readBytes() already blocks until the child closes stdout, which
            // for a binary whose whole job is to print one line and exit is the
            // same event as termination. The watchdog exists only so a binary
            // that is NOT that -- a wrong file packaged under the same name --
            // cannot hang the tunnel start. Destroying it closes the stream, so
            // readBytes() returns a partial banner, engineSupportsV3 says no,
            // and the caller refuses. Fail-closed on every path.
            val watchdog = Thread {
                try {
                    Thread.sleep(CONTRACT_PROBE_TIMEOUT_MS)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                try {
                    process.destroy()
                } catch (_: Exception) {
                }
            }.apply {
                name = "Calc-Winn-ContractProbe"
                isDaemon = true
                start()
            }

            val banner = try {
                process.inputStream.readBytes().toString(Charsets.UTF_8)
            } finally {
                // No-arg waitFor is API 1. It cannot outlive the watchdog.
                try {
                    process.waitFor()
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
                watchdog.interrupt()
            }
            WinnV3Host.engineSupportsV3(banner) to banner
        } catch (e: Exception) {
            false to "the packaged engine could not be probed: ${e.javaClass.simpleName}"
        }
        if (answer.first) cachedV3Probe = key to answer
        return answer
    }

    override fun openProtectedUnderlaySocket(): WinnUnderlaySocket {
        // Bind once before protection. The platform chooses the local address
        // family and source address when this socket is connected below.
        val socket = DatagramSocket()
        try {
            socket.receiveBufferSize = 16 * 1024 * 1024
            socket.sendBufferSize = 16 * 1024 * 1024
        } catch (e: Exception) {
            logWarn("Could not set 16MB socket buffer on outer datagram socket", e)
        }
        val protectedOk = try {
            vpnService.protect(socket)
        } catch (e: Exception) {
            socket.close()
            throw IOException("VpnService.protect() failed for the Winn outer UDP socket", e)
        }
        if (!protectedOk) {
            socket.close()
            throw IOException(
                "VpnService.protect() refused the Winn outer UDP socket; refusing to hand an " +
                    "unprotected socket to the engine."
            )
        }

        try {
            if (winn3) {
                val endpoint = winn3GatewayEndpoint
                    ?: throw IOException("Winn v3 underlay is missing its gateway endpoint")
                // protect must precede connect and every send. Connecting UDP
                // installs the kernel peer filter; it sends no handshake.
                connectUnderlaySocket(socket, endpoint)
            }
            // API 29+ duplicates the descriptor. Earlier releases share the
            // socket's FileDescriptor object, so retain the Java socket too.
            val owner = ParcelFileDescriptor.fromDatagramSocket(socket)
                ?: throw IOException("Winn underlay descriptor is unavailable")
            return AndroidUnderlaySocket(socket, owner)
        } catch (e: Exception) {
            socket.close()
            throw IOException("Could not prepare the protected Winn underlay socket", e)
        }
    }

    override fun openProtectedStreamSocket(): WinnUnderlaySocket? {
        if (!winn3) return null
        val fd = Os.socket(OsConstants.AF_INET, OsConstants.SOCK_STREAM, 0)
        try {
            val protectedOk = ParcelFileDescriptor.dup(fd).use { duplicate ->
                vpnService.protect(duplicate.fd)
            }
            if (!protectedOk) {
                throw IOException("VpnService.protect() refused the Winn v3 TCP socket")
            }
            return object : WinnUnderlaySocket {
                override val descriptor: FileDescriptor = fd
                override val protectedBeforeHandoff: Boolean = true
                override val localPort: Int = 0
                override fun close() { Os.close(fd) }
            }
        } catch (e: Exception) {
            try { Os.close(fd) } catch (_: Exception) { }
            throw IOException("Could not prepare the protected Winn v3 TCP socket", e)
        }
    }

    override fun openProtectedStreamChannel(): WinnProtectedStreamChannel? {
        if (!winn3) return null
        val channelName = newChannelName()
        val listener = LocalServerSocket(channelName)
        val hostSide = LocalSocket()
        val engineSide: LocalSocket
        try {
            hostSide.connect(LocalSocketAddress(channelName,
                LocalSocketAddress.Namespace.ABSTRACT))
            engineSide = listener.accept()
            if (engineSide.peerCredentials.uid != android.os.Process.myUid()) {
                engineSide.close()
                throw IOException("Winn v3 TCP request channel was claimed by a foreign uid; refusing it.")
            }
        } catch (e: Exception) {
            hostSide.close()
            listener.close()
            throw IOException("Could not open the Winn v3 TCP request channel", e)
        }
        listener.close()
        val closed = AtomicBoolean(false)
        val worker = Thread {
            try {
                val input = hostSide.inputStream
                val output = hostSide.outputStream
                while (!closed.get() && input.read() == 1) {
                    val socket = try { openProtectedStreamSocket() } catch (_: Exception) { null }
                    if (socket == null || !socket.protectedBeforeHandoff) {
                        socket?.close()
                        output.write(0)
                        output.flush()
                        continue
                    }
                    try {
                        hostSide.setFileDescriptorsForSend(arrayOf(socket.descriptor))
                        output.write(1)
                        output.flush()
                    } finally {
                        hostSide.setFileDescriptorsForSend(null)
                        socket.close()
                    }
                }
            } catch (_: Exception) {
            } finally {
                try { hostSide.close() } catch (_: Exception) { }
            }
        }.apply {
            name = "Calc-Winn-TCPDescriptor"
            isDaemon = true
            start()
        }
        return object : WinnProtectedStreamChannel {
            override val descriptor: FileDescriptor = engineSide.fileDescriptor
            override fun close() {
                if (!closed.compareAndSet(false, true)) return
                try { engineSide.shutdownOutput() } catch (_: IOException) { }
                try { hostSide.shutdownInput() } catch (_: IOException) { }
                try { hostSide.shutdownOutput() } catch (_: IOException) { }

                var closeFailure: IOException? = null
                try {
                    engineSide.close()
                } catch (e: IOException) {
                    closeFailure = e
                }
                try {
                    hostSide.close()
                } catch (e: IOException) {
                    if (closeFailure == null) closeFailure = e
                    else closeFailure?.addSuppressed(e)
                }

                if (Thread.currentThread() != worker) {
                    try {
                        worker.join(1_000L)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw IOException("Interrupted while stopping the Winn v3 TCP descriptor worker", e)
                    }
                    if (worker.isAlive) {
                        throw IOException("Winn v3 TCP descriptor worker did not stop")
                    }
                }
                closeFailure?.let { throw it }
            }
        }
    }

    private class AndroidUnderlaySocket(
        private val retained: DatagramSocket,
        private val owner: ParcelFileDescriptor,
    ) : WinnUnderlaySocket {
        override val descriptor: FileDescriptor get() = owner.fileDescriptor
        override val protectedBeforeHandoff: Boolean = true
        override val localPort: Int = retained.localPort
        override fun close() {
            try {
                owner.close()
            } finally {
                // On API 29+ the original remains open after owner.close().
                // On older releases the shared FileDescriptor is invalidated
                // by that close, so this cannot close a reused descriptor.
                retained.close()
            }
        }
    }

    override fun startEngineProcess(): WinnEngineProcess {
        val engine = resolveEngineExecutable()
        if (winn3 && winn3KeysPath.isNullOrBlank()) {
            throw IOException(
                "Refusing to spawn the Winn v3 engine without a ${WinnV3Host.FLAG_WINN3_KEYS} " +
                    "document: the engine refuses ${WinnV3Host.FLAG_WINN3} without it and would " +
                    "exit before a single frame crossed. ${WinnV3Keys.NO_KEY_MATERIAL}"
            )
        }
        val channelName = newChannelName()

        // Bind and listen before the child exists, so it cannot lose a race.
        val server = LocalServerSocket(channelName)
        var process: Process? = null
        try {
            val builder = ProcessBuilder(
                if (winn3) {
                    WinnV3Host.engineArguments(
                        engine.absolutePath, channelName, carrierProfilePath, winn3KeysPath,
                    )
                } else {
                    engineArguments(engine.absolutePath, channelName, carrierProfilePath)
                },
            )
            // Debug builds only: the uplink ring's drain low water for an
            // S26 A/B, read by the engine's newToEngineRing (the engine's one
            // application setting taken from the environment; the spawn
            // contract above is otherwise flags only). The file present means
            // 16, absent means 1, the Go default. It is read at each spawn, so
            // a reconnect switches arms. Release builds set nothing and run
            // the Go default.
            if (BuildConfig.DEBUG && winn3) {
                val lowWater = if (
                    File(context.filesDir, "winn3_drain_low_water_16").exists()
                ) "16" else "1"
                builder.environment()["WINN3_DRAIN_LOW_WATER"] = lowWater
                logDebug("winn3: drain low water $lowWater")
            }
            builder.redirectErrorStream(true)
            process = builder.start()
            drainEngineLog(process)

            val channel = acceptEngineChannel(server, process)
            return AndroidEngineProcess(process, LocalSocketWinnTransport(channel), engine.name)
        } catch (e: Exception) {
            try {
                process?.destroy()
            } catch (_: Exception) {
            }
            throw if (e is IOException) e else IOException("Winn engine subprocess failed to start", e)
        } finally {
            try {
                server.close()
            } catch (e: Exception) {
                logWarn("Winn engine channel listener close was incomplete", e)
            }
        }
    }

    private fun acceptEngineChannel(server: LocalServerSocket, process: Process): LocalSocket {
        val accepted = AtomicReference<LocalSocket?>(null)
        val failure = AtomicReference<Exception?>(null)
        val done = CountDownLatch(1)
        Thread {
            try {
                accepted.set(
                    acceptFromOwnUid(
                        accept = { server.accept() },
                        uidOf = { it.peerCredentials.uid },
                        close = { it.close() },
                        ownUid = android.os.Process.myUid(),
                        onForeign = {
                            logWarn("Winn engine channel refused a foreign-uid connection", null)
                        },
                    ),
                )
            } catch (e: Exception) {
                failure.set(e)
            } finally {
                done.countDown()
            }
        }.apply {
            name = "Calc-Winn-Accept"
            isDaemon = true
            start()
        }

        if (!done.await(ACCEPT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            // Closing the listener unblocks the accept thread.
            try {
                server.close()
            } catch (_: Exception) {
            }
            throw IOException(
                "Winn engine did not connect to its channel within ${ACCEPT_TIMEOUT_MS}ms. " +
                    "Check that $ENGINE_LIBRARY_NAME is the winn-datapath binary and that it " +
                    "accepts -transport unix -control @<name> -receive-fd; run it once with " +
                    "-print-contract to see what it really is."
            )
        }
        val socket = accepted.get()
            ?: throw IOException("Winn engine channel accept failed", failure.get())

        try {
            socket.receiveBufferSize = 16 * 1024 * 1024
            socket.sendBufferSize = 16 * 1024 * 1024
        } catch (e: Exception) {
            logWarn("Could not set 16MB buffer on engine local socket", e)
        }

        // Three things gate this channel: the abstract name is 128 random
        // bits, exactly one connection is ever accepted (the listener is
        // closed immediately after), and the peer must be our own uid.
        // A pid check is deliberately absent (java.lang.Process on Android
        // exposes no pid() at this compileSdk, and the uid check is the real
        // boundary anyway).
        val credentials = socket.peerCredentials
        if (credentials.uid != android.os.Process.myUid()) {
            socket.close()
            throw IOException("Winn engine channel was claimed by a foreign uid; refusing it.")
        }
        if (!isProcessAlive(process)) {
            socket.close()
            throw IOException("Winn engine exited during startup; refusing its channel.")
        }
        logDebug("Winn engine channel accepted from our own uid.")
        return socket
    }

    private fun isProcessAlive(process: Process): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            process.isAlive
        } else {
            try {
                process.exitValue()
                false
            } catch (_: IllegalThreadStateException) {
                true
            }
        }

    private fun drainEngineLog(process: Process) {
        Thread {
            try {
                process.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        if (BuildConfig.DEBUG) {
                            logDebug("winn-engine: ${line.take(500)}")
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }.apply {
            name = "Calc-Winn-EngineLog"
            isDaemon = true
            start()
        }
    }

    private fun newChannelName(): String {
        val bytes = ByteArray(16)
        RANDOM.nextBytes(bytes)
        val hex = StringBuilder(bytes.size * 2)
        for (b in bytes) hex.append("%02x".format(b.toInt() and 0xFF))
        return "winn-engine-$hex"
    }

    /**
     * Only the APK-packaged native library path is trusted, for the same
     * reason `resolveXrayExecutable` in VpnTunnelService gives: it is
     * extracted by the OS package installer from a signed, release-verified
     * APK. There is deliberately no app-writable fallback.
     */
    private fun resolveEngineExecutable(): File {
        val nativeLib = File(context.applicationInfo.nativeLibraryDir, ENGINE_LIBRARY_NAME)
        // ONLY WHEN IT IS NOT ALREADY EXECUTABLE, AND THAT IS NOT A
        // MICRO-OPTIMISATION.
        //
        // MEASURED, Motorola edge plus 2023 (ZY22GTV6Z3), 2026-08-22:
        //   avc: denied { setattr } for name="libwinnengine.so"
        //   scontext=u:r:untrusted_app:s0 tcontext=u:object_r:apk_data_file:s0
        //
        // Files under `nativeLibraryDir` are extracted by the package installer
        // and are ALREADY executable; they are labelled `apk_data_file`, which
        // `untrusted_app` has no `setattr` permission on. The unconditional
        // chmod therefore never changed anything and only ever produced an
        // SELinux audit record, twice per tunnel start (once here, once from
        // the capability probe). A denied setattr in the transcript of a failing
        // VPN start is a false lead that costs real triage time, and on a device
        // with auditd forwarding it is also noise in somebody's SIEM.
        if (nativeLib.isFile && !nativeLib.canExecute()) {
            nativeLib.setExecutable(true, true)
        }
        if (!nativeLib.isFile || !nativeLib.canExecute()) {
            throw IOException(
                "Missing Winn Protocol engine binary. Run " +
                    "android/tools/prepare_android_winn_assets.sh before building the APK. " +
                    "Expected $ENGINE_LIBRARY_NAME under android/app/src/main/jniLibs/<abi>/; " +
                    "device ABIs=${Build.SUPPORTED_ABIS.joinToString()}"
            )
        }
        return nativeLib
    }

    /**
     * The seam the caller supplied, or null.
     *
     * Null is still the answer for any caller that has not wired one, and
     * [WinnTunnelBridge] still refuses to start on it. What changed is that
     * Android now HAS an implementation -- [WinnAwgLoopbackSeam] -- so the
     * refusal means "this caller did not point AmneziaWG at a seam" rather than
     * "no such thing exists on this platform". Returning the tun's raw IP
     * packets here would still be the mislabelling the engine refuses at create
     * time, and nothing here does that.
     */
    override fun openAwgDatagramSeam(): WinnAwgDatagramSeam? = awgDatagramSeam

    override fun onDebug(message: String) = logDebug(message)

    override fun onWarning(message: String, error: Throwable?) = logWarn(message, error)

    override fun onError(message: String, error: Throwable?) = logError(message, error)

    private class AndroidEngineProcess(
        private val process: Process,
        override val transport: WinnEngineTransport,
        private val binaryName: String,
    ) : WinnEngineProcess {

        override fun isAlive(): Boolean =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                process.isAlive
            } else {
                try {
                    process.exitValue()
                    false
                } catch (_: IllegalThreadStateException) {
                    true
                }
            }

        override fun describe(): String = binaryName

        override fun close() {
            var failure: IOException? = null

            fun record(error: Exception) {
                val wrapped = if (error is IOException) {
                    error
                } else {
                    IOException("Winn engine resource close failed", error)
                }
                val first = failure
                if (first == null) failure = wrapped else first.addSuppressed(wrapped)
            }

            try {
                transport.close()
            } catch (error: Exception) {
                record(error)
            }

            try {
                process.destroy()
                var exited = waitForExit(1_500L)
                if (!exited && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    process.destroyForcibly()
                    exited = waitForExit(2_000L)
                }
                if (!exited) {
                    throw IOException("Winn engine subprocess did not stop")
                }
            } catch (error: Exception) {
                record(error)
            }

            failure?.let { throw it }
        }

        private fun waitForExit(timeoutMs: Long): Boolean {
            val deadline = System.nanoTime() + timeoutMs * 1_000_000L
            while (isAlive() && System.nanoTime() < deadline) {
                try {
                    Thread.sleep(50L)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return !isAlive()
                }
            }
            return !isAlive()
        }
    }

    private class LocalSocketWinnTransport(private val socket: LocalSocket) : WinnV3BatchTransport {
        init {
            try {
                // Max uplink batch is 694.5 KiB. Keeping it at or below half the send
                // buffer lets batch N+1 be staged while batch N drains, instead of
                // lockstep. net.core.wmem_max = 8 MiB on SM-S948U1 admits 2 MiB.
                socket.sendBufferSize = 2 * 1024 * 1024
                socket.receiveBufferSize = 1048576
            } catch (_: Exception) {
            }
        }
        private val out: OutputStream = socket.outputStream
        private val stream = WinnV3FramedStreamTransport(
            input = socket.inputStream,
            output = out,
            descriptorSender = { fd ->
                // Exactly one byte, and nothing else, in this sendmsg: the
                // engine's -receive-fd path reads it with a one-byte recvmsg
                // before the frame reader ever runs. Sending more here would
                // deliver into the frame reader's input stream ahead of the
                // real first frame.
                socket.setFileDescriptorsForSend(arrayOf(fd))
                try {
                    out.write(0)
                    out.flush()
                } finally {
                    socket.setFileDescriptorsForSend(null)
                }
            },
            timeoutSetter = { socket.soTimeout = it },
            socketCloser = {
                // Shutdown both directions before close to wake blocked I/O.
                // This callback runs without the stream writer's monitor.
                try {
                    socket.shutdownInput()
                } catch (_: Exception) {
                }
                try {
                    socket.shutdownOutput()
                } catch (_: Exception) {
                }
                socket.close()
            },
            descriptorGroupSender = { fds ->
                socket.setFileDescriptorsForSend(fds)
                try {
                    out.write(0)
                    out.flush()
                } finally {
                    socket.setFileDescriptorsForSend(null)
                }
            },
            descriptorChannelSender = { fds ->
                socket.setFileDescriptorsForSend(fds)
                try {
                    out.write(1)
                    out.flush()
                } finally {
                    socket.setFileDescriptorsForSend(null)
                }
            },
        )

        override fun writeFrame(opcode: Int, payload: ByteArray) = stream.writeFrame(opcode, payload)
        override fun writeBatch(batch: WinnV3PacketBatch) = stream.writeBatch(batch)
        override fun readBatch(batch: WinnV3PacketBatch): Int = stream.readBatch(batch)
        override fun sendDescriptor(fd: FileDescriptor) = stream.sendDescriptor(fd)
        override fun sendDescriptors(fds: Array<FileDescriptor>) = stream.sendDescriptors(fds)
        override fun sendDescriptorChannel(udp: FileDescriptor, channel: FileDescriptor) =
            stream.sendDescriptorChannel(udp, channel)
        override fun readFrame(): WinnFrame? = stream.readFrame()
        override fun setReadTimeoutMs(timeoutMs: Int) = stream.setReadTimeoutMs(timeoutMs)
        override fun close() = stream.close()
    }
}
