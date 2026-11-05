package org.winsvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.graphics.BitmapFactory
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicLong

class VpnTunnelService : VpnService() {

    /// What the foreground notification is allowed to CLAIM about the tunnel.
    /// The service must be foreground before it can dial, so the notification
    /// exists while the tunnel is still being established; the text it carries
    /// must never outrun the fact it describes. Nested at class level (not in
    /// the companion) so the unit tests and the instance field can both
    /// reference it as `VpnTunnelService.TunnelForegroundState`.
    enum class TunnelForegroundState {
        CONNECTING,
        CONNECTED,
        // Winn v3 only. The engine is rebuilding its session in place: the
        // tunnel and its capture are kept, and nothing is claimed.
        RECOVERING,
        // Winn v3 only. The engine stopped trying (or recovery outlived the
        // host ceiling). Capture is held fail-closed and the user must act.
        BLOCKED,
    }

    /// The user's CURRENT choice about Double VPN as the service reads it from
    /// the saved settings. Nested at class level, like [TunnelForegroundState], so
    /// the unit tests can reference it.
    enum class DoubleVpnIntent { WANTED, NOT_WANTED, UNKNOWN }

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var narrowBootstrapInterface: ParcelFileDescriptor? = null
    private var retainedKillSwitchInterface: ParcelFileDescriptor? = null
    // A Dart handover holds a block until that exact start commits or fails.
    private val doubleVpnHandoverToken = AtomicLong(0L)
    private var xrayProcess: Process? = null
    private var tunnelWakeLock: android.os.PowerManager.WakeLock? = null
    private var tunnelWifiLock: android.net.wifi.WifiManager.WifiLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastUnderlyingNetwork: Network? = null
    private var healthWatchdogThread: Thread? = null
    private val handoffHandler = Handler(Looper.getMainLooper())
    private val secureFileStore by lazy {
        SecureFileStore.forApplication(applicationContext)
    }
    // The kill switch surface. `killSwitch` is cheap to create and reads live
    // system state on demand; the armed flag comes from SecureFileStore so it
    // survives process death (see KILL_SWITCH_STATE).
    private val androidKillSwitch by lazy { AndroidKillSwitch(this) }
    /**
     * True while the service holds a VpnService.Builder blocking interface with
     * no engine draining it - the app-level kill switch engaged because the OS
     * lock-down is not guaranteeing the block. Kept separate from
     * `isServiceActive` so the UI still reads "not connected" while a held
     * interface is silently blackholing everything the OS lets the app capture.
     */
    @Volatile private var holdingBlockPosture = false
    // The live AmneziaWG engine handle, paired with the tunnel generation
    // that published it. See AwgHandleOwnership's doc: AmneziaWG reuses
    // handle numbers across unrelated tunnels (confirmed on real hardware
    // 2026-08-04), so the raw handle alone cannot identify which session a
    // late or duplicate teardown actually belongs to.
    private val awgEngineOwnership = AwgHandleOwnership()
    // Winn Protocol runs as a subprocess bridge instead of an in-process
    // handle, so it needs its own slot; the AmneziaWG fields above are left
    // untouched and stay authoritative for the shipping path.
    private val winnEngineLock = Object()
    private var winnBridge: WinnTunnelBridge? = null

    /**
     * The v3 bridge, published so the health watchdog can SEE a v3 session.
     *
     * MEASURED DEFECT, emulator-5554 (API 34), 2026-08-09. Until this field
     * existed, [currentEngineHandleHealthy] asked [currentWinnBridge] - which
     * reads [winnBridge], the **v1** `WinnTunnelBridge` - and a v3 session
     * never sets it, because its bridge was a local in
     * [startWinnV3EngineThread] and was published nowhere. So the v3 path fell
     * through to `currentAwgHandle()`, which is -1 when there is no AmneziaWG,
     * and the health check returned false for EVERY v3 session on every sample.
     *
     * The watchdog tears down after three consecutive unhealthy samples at
     * `WATCHDOG_INITIAL_DELAY_MS` + 3 × `WATCHDOG_INTERVAL_MS` = 15s + 30s. A
     * v3 tunnel that had handshaked, promoted and was carrying was therefore
     * destroyed 35 seconds after its bootstrap posture went in, with
     * "VPN engine health check failed repeatedly; closing stale tunnel" as the
     * only clue - measured at 35.05 s (bootstrap 17:27:48.195, teardown
     * 17:28:23.247), against a gateway that reported the session established
     * and carrying the whole time.
     *
     * This is the health check's blind spot and not the datapath's: the
     * datapath was healthy at teardown by both ends' own counters.
     */
    private var winnV3Bridge: WinnV3Bridge? = null
    // Round A3. The promoted Winn v3 session's lifecycle watch AND the
    // generation that owns it, published for the health check as one pair
    // (WinnV3LifecycleBinding), so a reader can only ever publish under the
    // owner of the watch it read. Null for every other engine and before
    // promotion. Read and written under [winnEngineLock].
    private var winnV3LifecycleBinding: WinnV3LifecycleBinding? = null
    // Which teardown may release a promoted v3 session's capture, and the
    // queue of owner and OS requests that arrive while one is in flight.
    // Called under [winnEngineLock]. See WinnV3CaptureCustody.
    private val winnV3Custody = WinnV3CaptureCustody()
    // The teardown worker. Its end-of-pass transition (take the next queued
    // request, or retire) is ONE critical section under [winnEngineLock], the
    // same lock every request takes, so no request can be queued after the
    // worker's last look and then left with no worker. It mirrors its
    // in-flight state into [tearingDown]. See WinnV3TeardownWorker.
    private val winnV3TeardownWorker = WinnV3TeardownWorker(
        lock = winnEngineLock,
        custody = winnV3Custody,
        onPlanStarted = {
            tearingDown = true
            tunnelGeneration += 1
        },
        onRetired = {
            tearingDown = false
            if (activeTeardownThread === Thread.currentThread()) activeTeardownThread = null
        },
    )
    @Volatile private var tearingDown = false
    @Volatile private var tunnelGeneration = 0

    // Round L: the most recent Winn v3 engine thread's own retirement. A
    // release pass may acknowledge CLOSED only once it has finished and
    // completed; see WinnV3ReleaseTeardown.
    @Volatile private var winnV3EngineRetirement: WinnV3EngineRetirement? = null
    @Volatile private var stopHealthWatchdog = false
    @Volatile private var handoffRefreshToken = 0
    @Volatile private var fallbackTransportRequired = false
    // The last foreground-notification state actually posted, so status
    // re-posts deduplicate and never churn the shade. See
    // [refreshForegroundStatusNotification].
    @Volatile private var lastPostedForegroundState: TunnelForegroundState? = null
    // True while the running session is one hop although the user wants Double
    // VPN. Decided at every start AND every system restart from two facts: the
    // route the saved config says it has, and the user's CURRENT choice read
    // from the saved settings (see [doubleVpnSingleHopFor]). The notification says
    // so, because the dashboard is not on screen while the app is closed.
    @Volatile private var doubleVpnSingleHop = false
    // Winn datapath progress, sampled by the health watchdog. -1 means "no
    // sample yet"; see winnDatapathIsCarrying(). Added 2026-08-07 with the
    // convergence gate below.
    @Volatile private var winnLastTxPayloadDatagrams = -1L
    @Volatile private var winnLastRxPayloadDatagrams = -1L

    companion object {
        private val winn3VerdictStateLock = Any()
        // How much of a failed start's cause chain reaches logcat. Four
        // links covers every wrapper this tree builds (posture refusal ->
        // IOException -> ErrnoException) with room to spare, and a bound
        // means a cyclic or pathologically deep chain cannot flood the log.
        private const val MAX_LOGGED_CAUSE_DEPTH = 4
        private const val MAX_LOGGED_MESSAGE_CHARS = 600
        private const val WATCHDOG_INITIAL_DELAY_MS = 15_000L
        private const val WATCHDOG_INTERVAL_MS = 10_000L
        private const val WATCHDOG_MISSING_VPN_LIMIT = 12
        // WINN TRANSPORT CONVERGENCE GATE (2026-08-07).
        //
        // Ported from the Linux lane's WaitForLinuxWinnTransportConvergence
        // (linux/runner/linux_tunnel_backend.cc), and deliberately carrying its
        // numbers rather than new ones: the 5 s budget is Windows'
        // kWinnTransportConvergenceDeadlineMilliseconds and the 250 ms tick is
        // Apple's winnDatapathProofTickMilliseconds, so four platforms now fail
        // closed on one schedule instead of on four invented ones.
        private const val WINN_CONVERGENCE_DEADLINE_MS = 5_000L
        private const val WINN_CONVERGENCE_TICK_MS = 250L
        // The engine reports which header-type table it is classifying against.
        // Anything else means it is matching vanilla WireGuard's 1/2/3/4 while
        // the interface emits h1..h4, so the transport counters -- and with them
        // transport_observed_both_ways -- cannot fire on a healthy tunnel.
        // datapath/status.go documents this trap in as many words.
        private const val WINN_CLASSIFIER_CONFIGURED = "configured-h1h4"
        // Fail-closed message for a winn session whose datapath never proved
        // itself. Held as a constant so a test can assert the refusal exists
        // rather than that some string was logged.
        const val WINN_TRANSPORT_NEVER_CONVERGED =
            "Winn Protocol v3 started but no datagram was observed crossing in both " +
                "directions within the convergence deadline, so the tunnel was stopped " +
                "instead of being reported as connected."
        private const val STARTUP_WAKE_LOCK_TIMEOUT_MS = 60_000L
        private const val XRAY_CONFIG_FILE = "wins_xray_client.json"

        // ---- AmneziaWG inner MTU -------------------------------------------
        //
        // THROUGHPUT (2026-09-17). The data path carries plain WireGuard
        // overhead: S4 transport padding is 0 on both client and server,
        // Jc/Jmin/Jmax are separate junk packets rather than per-packet bytes,
        // and H1-H4 only rewrite the existing 4-byte type field. So the wire
        // cost of one transport packet is
        //   inner + 16 (WG transport header) + 16 (Poly1305 tag) + 8 (UDP)
        //   + 20 (IPv4) or + 40 (IPv6).
        // 1440 lands on exactly 1500 over IPv4 and 1408 lands on 1488 over
        // IPv6. Both are multiples of 16, so WireGuard's 16-byte padding
        // multiple adds nothing to either. The old 1280 wasted 160 bytes of
        // every packet on a handset that is packet-rate bound, not byte bound.
        //
        // The size cannot be a constant because the OUTER family decides it,
        // and the outer family is not fixed: AwgUserspaceConfig.resolveEndpoint
        // passes a bracketed IPv6 literal through verbatim and re-brackets a
        // hostname that resolves to an AAAA record, and the control plane
        // stores the node endpoint as free-form text. An inner 1440 behind an
        // IPv6 outer header is 1520 on the wire, which is a black hole on any
        // 1500 path.
        //
        // DYNAMIC MTU (2026-09-20 owner decision): the numbers below are
        // FALLBACKS, not the answer. The inner MTU derives from the
        // UNDERLYING network's link MTU at tunnel establishment
        // (underlyingNetworkLinkMtu), less the outer-header cost, clamped to
        // a 1280 compatibility floor (cellular and IPv6 minimum) and a 1440
        // ceiling (the IPv4-optimal size on a clean 1500 path). The Go
        // engine's kernel PMTUD (carrier/pmtud.go, Linux and Android) keeps
        // correcting the carrier ceiling after connect.
        private const val AWG_MTU_FLOOR = 1280
        private const val AWG_MTU_IPV4_CEILING = 1440
        private const val AWG_MTU_IPV6_OUTER_PENALTY = 32

        // RV-B (Round 38 treaty): the gateway's inner-only speedtest ingest
        // port, and the inner router address latched from the ACTIVE session's
        // config. MainActivity accepts the ingest URL only when its host is
        // the dotted-quad router the running session was built from; a stolen
        // or hostile config cannot aim the meter at an arbitrary host without
        // also being the config the engine verified and started.
        const val WINN3_INGEST_PORT = 8455

        @Volatile
        var latchedInnerRouterV4: String? = null
            private set

        fun isInnerIpv4Literal(host: String): Boolean {
            val parts = host.split('.')
            if (parts.size != 4) return false
            return parts.all { part ->
                part.isNotEmpty() && part.length <= 3 &&
                    part.all { c -> c in '0'..'9' } &&
                    (part.toIntOrNull() ?: -1) in 0..255
            }
        }

        /**
         * The active network's reported link MTU, or null when the system
         * gives us nothing usable.
         */
        fun underlyingNetworkLinkMtu(context: Context): Int? = try {
            val cm = context.getSystemService(ConnectivityManager::class.java)
                ?: return null
            val network = cm.activeNetwork ?: return null
            val props = cm.getLinkProperties(network) ?: return null
            val mtu = props.mtu
            if (mtu != null && mtu > 0) mtu else null
        } catch (_: Exception) {
            null
        }

        /**
         * Cap [requestedMtu] to a size that survives the outer header the peer
         * [endpoint] implies and the UNDERLYING network's own link MTU.
         * Returns [requestedMtu] unchanged when the endpoint is an IPv4
         * literal (including the loopback address the stacked stealth
         * arrangement points at) or when it is absent.
         */
        fun awgInterfaceMtuForEndpoint(endpoint: String?, requestedMtu: Int, linkMtu: Int? = null): Int {
            val trimmed = endpoint?.trim().orEmpty()
            if (trimmed.isEmpty()) return requestedMtu
            val host: String
            if (trimmed.startsWith('[')) {
                val closeBracket = trimmed.indexOf(']')
                if (closeBracket <= 1) return minOf(requestedMtu, ipv6OuterCap(requestedMtu, linkMtu))
                host = trimmed.substring(1, closeBracket)
            } else {
                val colon = trimmed.lastIndexOf(':')
                host = if (colon <= 0) trimmed else trimmed.substring(0, colon)
            }
            val isIpv4Literal = host.split('.').let { parts ->
                parts.size == 4 && parts.all { part -> part.toIntOrNull() in 0..255 }
            }
            return if (isIpv4Literal) {
                minOf(requestedMtu, ipv4OuterCap(linkMtu))
            } else {
                minOf(requestedMtu, ipv6OuterCap(requestedMtu, linkMtu))
            }
        }

        /** Inner cap for an IPv4 outer path: link MTU minus 60 bytes of outer cost. */
        private fun ipv4OuterCap(linkMtu: Int?): Int = when {
            linkMtu != null && linkMtu > 0 -> (linkMtu - 60).coerceIn(AWG_MTU_FLOOR, AWG_MTU_IPV4_CEILING)
            else -> AWG_MTU_IPV4_CEILING
        }

        /** Inner cap for an IPv6 (or unknown-family) outer path: 20 bytes more
         *  outer cost than IPv4, still never below the 1280 floor. */
        private fun ipv6OuterCap(requestedMtu: Int, linkMtu: Int?): Int =
            minOf(requestedMtu, ipv4OuterCap(linkMtu) - AWG_MTU_IPV6_OUTER_PENALTY)
                .coerceAtLeast(AWG_MTU_FLOOR)

        // ---- Kill switch ---------------------------------------------------
        //
        // The Android kill switch has two halves (see KillSwitchPolicy.kt):
        // the OS-level always-on/block-connections facility, armed
        // best-effort on every connect through the hidden VpnManager API, and
        // a VpnService.Builder blocking interface held at teardown whenever the
        // OS is not conclusively blocking in our tunnel-down window.
        //
        // The actions below let the DEBUG build drive both halves over adb (see
        // DevKillSwitchActivity). They are harmless in release: nothing in the
        // shipping UI ever sends them, and without a caller they are dead
        // branches, exactly like the existing ACTION_CONNECT/ACTION_DISCONNECT.
        const val ACTION_ARM_KILLSWITCH = "ACTION_ARM_KILLSWITCH"
        const val ACTION_DISARM_KILLSWITCH = "ACTION_DISARM_KILLSWITCH"
        const val ACTION_ENTER_BLOCK = "ACTION_ENTER_BLOCK"
        const val ACTION_EXIT_BLOCK = "ACTION_EXIT_BLOCK"

        /**
         * The SecureFileStore name holding the user's kill-switch intent.
         *
         * Deliberately a persisted flag, not process memory: the armed state
         * must survive process death for the reconnect path - after an OOM or
         * a force-stop the always-on OS rule is still live, and a fresh process
         * that never learns the intent would tear the tunnel down clear instead
         * of holding the block posture.
         */
        internal const val KILL_SWITCH_STATE = "wins_kill_switch_armed"
        internal const val LOG_TAG = "CalcCore"
        private const val RESTART_NODE_RECORD = "wins_vpn_restart_node.txt"
        @Volatile private var awgNativeLoaded = false
        @Volatile private var activeInstance: VpnTunnelService? = null

        // ---- Camouflage identity, shared with MainActivity ----------------
        //
        // The name shown wherever the disguise is in force. Kept in one place
        // so the launcher alias, the Recents card, the notification, the
        // notification channel and the VPN session name cannot drift apart.
        const val DISGUISED_DISPLAY_NAME = "Calculator"

        // On-disk names for the sticky camouflage fact.
        //
        // These used to be `wins_vpn_camouflage_state` / `decoy_ever_armed`,
        // which survive a duress wipe and therefore proved, to anyone with
        // root on a seized handset, that this "calculator" has a decoy mode.
        // A survivor whose own name gives the disguise away is worse than no
        // survivor. The replacements read as a calculator's display
        // preferences, which is what the file has to look like to do its job.
        // LEGACY_* are read once, migrated, and removed.
        private const val CAMOUFLAGE_PREFS = "calculator_prefs"
        private const val KEY_CAMOUFLAGE_ENROLLED = "keypad_haptics"
        private const val LEGACY_CAMOUFLAGE_PREFS = "wins_vpn_camouflage_state"
        private const val LEGACY_KEY_CAMOUFLAGE_ENROLLED = "decoy_ever_armed"

        /// Records that the decoy has been armed at least once on this
        /// install. Called from MainActivity every time the decoy is armed.
        ///
        /// This has to be sticky rather than "is the decoy showing right
        /// now", because `VpnService.Builder.setSession()` is only read by
        /// the OS at `establish()` and there is no API to rename a live
        /// session. The ordinary flow is: unlock with the PIN (decoy
        /// disarmed) -> connect -> background (decoy re-arms). If the
        /// session name were taken from the momentary decoy state it would
        /// be captured as the real identity in exactly that flow and then
        /// stay wrong for the whole life of the tunnel -- which is the one
        /// window in which somebody inspecting the phone actually reads it.
        ///
        /// Never cleared: erring toward the disguise is the fail-safe
        /// direction here, and the cost of a false positive is only that a
        /// user who abandons camouflage sees a VPN entry still labelled
        /// "Calculator" until the next reinstall.
        @JvmStatic
        fun markCamouflageEnrolled(context: Context) {
            try {
                context.applicationContext
                    .getSharedPreferences(CAMOUFLAGE_PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(KEY_CAMOUFLAGE_ENROLLED, true)
                    .apply()
            } catch (e: Exception) {
                Log.w(VpnTunnelService.LOG_TAG, "Unable to persist camouflage enrollment state", if (BuildConfig.DEBUG) e else null)
            }
        }

        @JvmStatic
        fun isCamouflageEnrolled(context: Context): Boolean {
            return try {
                val app = context.applicationContext
                val current = app
                    .getSharedPreferences(CAMOUFLAGE_PREFS, Context.MODE_PRIVATE)
                if (current.getBoolean(KEY_CAMOUFLAGE_ENROLLED, false)) return true
                // One-time migration off the old, self-describing names. An
                // install that was already enrolled must stay enrolled: this
                // fact is what keeps the latched OS surfaces (the VPN session
                // name, the announcement channel) labelled "Calculator", and
                // losing it would relabel them with the real identity for the
                // whole life of the next tunnel.
                val legacy = app.getSharedPreferences(
                    LEGACY_CAMOUFLAGE_PREFS,
                    Context.MODE_PRIVATE,
                )
                if (!legacy.getBoolean(LEGACY_KEY_CAMOUFLAGE_ENROLLED, false)) return false
                markCamouflageEnrolled(app)
                legacy.edit().clear().apply()
                true
            } catch (e: Exception) {
                false
            }
        }

        /// Whether the disguise should apply to a surface the OS **latches** --
        /// one whose value is captured at a single moment and then kept until
        /// something external recreates it.
        ///
        /// Two surfaces are in this class and neither can be re-read on
        /// demand: the VPN session name (fixed at `establish()`) and the
        /// announcement notification channel (created on the first
        /// announcement and persisted by the OS thereafter). Both are read by
        /// an inspector *later*, long after the moment that decided them, so
        /// both must key off the sticky enrollment fact rather than whether
        /// the decoy happens to be armed right now.
        ///
        /// Contrast the ongoing tunnel notification and its channel, which are
        /// free to use the live decoy state because
        /// `refreshForegroundNotificationForCamouflage` rebuilds them on every
        /// icon swap.
        @JvmStatic
        fun latchedSurfaceIsDisguised(camouflageEnrolled: Boolean, decoyActive: Boolean): Boolean {
            return camouflageEnrolled || decoyActive
        }

        /// The name Android renders in Settings > Network & internet > VPN and
        /// in the system's own VPN status surfaces, decided from the two
        /// camouflage signals. Split out from the Context-bound caller purely
        /// so the policy itself is unit-testable.
        @JvmStatic
        fun vpnSessionNameFor(camouflageEnrolled: Boolean, decoyActive: Boolean): String {
            return if (latchedSurfaceIsDisguised(camouflageEnrolled, decoyActive)) {
                DISGUISED_DISPLAY_NAME
            } else {
                "WinsVPN"
            }
        }

        /// The announcement notification CHANNEL's name, as rendered in
        /// Settings > Apps > Calculator > Notifications. Same shape and same
        /// reasoning as [vpnSessionNameFor]: the announcement channel is the
        /// second latched surface named in [latchedSurfaceIsDisguised]'s
        /// doctrine, so it keys off the sticky enrollment fact, and the policy
        /// lives here -- away from any Context -- so a unit test can enumerate
        /// every (enrolled, armed) combination and prove the real name is
        /// unreachable while disguised.
        ///
        /// This is the ONLY place in the application that can produce the real
        /// channel name -- `CamouflageLatchedSurfaceTest` asserts that the
        /// literal occurs exactly once across the main sources, right below --
        /// which is what makes that proof a proof rather than a spot check.
        @JvmStatic
        fun announcementChannelNameFor(camouflageEnrolled: Boolean, decoyActive: Boolean): String {
            return if (latchedSurfaceIsDisguised(camouflageEnrolled, decoyActive)) {
                DISGUISED_DISPLAY_NAME
            } else {
                "Win's VPN Announcements"
            }
        }

        /// The channel description, which Settings renders directly underneath
        /// the channel name and which therefore leaks exactly as readily.
        @JvmStatic
        fun announcementChannelDescriptionFor(
            camouflageEnrolled: Boolean,
            decoyActive: Boolean,
        ): String {
            return if (latchedSurfaceIsDisguised(camouflageEnrolled, decoyActive)) {
                "App messages"
            } else {
                "Important Win's VPN service announcements"
            }
        }

        /// The id of the tunnel's foreground-service channel.
        ///
        /// Deliberately unchanged from the value shipped installs already
        /// carry. Renaming the *id* would not clean anything up -- it would
        /// create a second channel and strand the existing row, real name and
        /// all, in Settings forever, which is the exact failure this file is
        /// closing. The id is not rendered in the Settings UI; only the name
        /// below is.
        const val TUNNEL_CHANNEL_ID = "wins_vpn_channel"

        /// The tunnel foreground-service CHANNEL's name, as rendered in
        /// Settings > Apps > Calculator > Notifications.
        ///
        /// This used to be picked from the live decoy state alone, on the
        /// reasoning that the tunnel notification is rebuilt on every icon
        /// swap. That reasoning is right about the *notification* and wrong
        /// about the *channel*. The notification vanishes when the tunnel
        /// stops; the channel row does not. It is created the first time a
        /// tunnel starts and then listed in Settings for the life of the
        /// install -- with no tunnel running, with no notification showing,
        /// and after the decoy has been disarmed.
        ///
        /// So it is a latched surface exactly like the VPN session name and
        /// the announcement channel, and it takes the same input: the sticky
        /// enrollment fact, not the momentary one. The moment that decides it
        /// is the moment Connect is pressed, which is the one moment the decoy
        /// is guaranteed to be down, because the user has just unlocked with
        /// their PIN to press it.
        ///
        /// Context-free so a unit test can enumerate every (enrolled, armed)
        /// combination, and the only place in the application that can produce
        /// the real name -- `CamouflageLatchedSurfaceTest` asserts the literal
        /// occurs exactly once across the main sources, right below.
        @JvmStatic
        fun tunnelChannelNameFor(camouflageEnrolled: Boolean, decoyActive: Boolean): String {
            return if (latchedSurfaceIsDisguised(camouflageEnrolled, decoyActive)) {
                DISGUISED_DISPLAY_NAME
            } else {
                "Win's VPN Core Services"
            }
        }

        /// The id of the foreground-service notification this service posts
        /// while a tunnel (or the kill-switch blackhole) is being held.
        const val TUNNEL_NOTIFICATION_ID = 4242

        /// The importance the tunnel CHANNEL is settled at. A VPN status
        /// notification is permanent, silent and never heads-up: it exists to
        /// tell a user they are protected, not to demand attention on a network
        /// that may be hostile. LOW is also the right Doze posture -- silent,
        /// deferred, never alerting, while remaining visible in the shade.
        const val TUNNEL_CHANNEL_IMPORTANCE = NotificationManager.IMPORTANCE_LOW

        /// The [WinsApp] key the app writes (Android only) on every start: the
        /// route the config it is starting actually has. Absent in a config
        /// saved by an older build, which is never marked (no route is known).
        const val DOUBLE_VPN_ROUTE_KEY = "doublevpnroute"
        const val DOUBLE_VPN_ROUTE_SINGLE_HOP = "single-hop"
        const val DOUBLE_VPN_ROUTE_TWO_HOP = "two-hop"

        /// A legacy copy of the user's Double VPN choice. It is no longer
        /// authoritative because a failed write could leave it stale. Keep the
        /// name to retire older copies with the restart state.
        const val DOUBLE_VPN_INTENT_RECORD = "route_intent.txt"

        /// What ongoing notification says while Double VPN is wanted and the
        /// session is one hop. Only for an install that is not disguised: a
        /// disguised notification is the ordinary one, byte for byte.
        const val SINGLE_HOP_TEXT = "Single hop: Double VPN unavailable."

        /// The `getTunnelReadiness` key carrying the marker (a boolean).
        const val DOUBLE_VPN_READINESS_KEY = "double_vpn_single_hop"

        /// The user's choice as the canonical saved settings hold it: the value
        /// of `double_vpn_requested` in the encrypted `vpn_settings.txt`, the
        /// same one the app reads for the switch and the dashboard. Only a
        /// boolean `false` proves Double VPN is off. An absent key, JSON null,
        /// or any other non-boolean is UNKNOWN, as is an unreadable document.
        @JvmStatic
        internal fun doubleVpnIntentFromChoice(value: Any?): DoubleVpnIntent =
            when (value) {
                true -> DoubleVpnIntent.WANTED
                false -> DoubleVpnIntent.NOT_WANTED
                else -> DoubleVpnIntent.UNKNOWN
            }

        /// The marker for a config text, from the canonical choice alone. The
        /// legacy `route_intent.txt` copy is not an input, so a stale copy
        /// cannot change the answer in either direction.
        @JvmStatic
        internal fun doubleVpnSingleHopForRestart(
            config: String,
            intent: DoubleVpnIntent,
        ): Boolean = doubleVpnSingleHopFor(parseConfigSectionOf(config, "winsapp"), intent)

        @JvmStatic
        internal fun parseConfigSectionOf(config: String, sectionName: String): Map<String, String> {
            val out = linkedMapOf<String, String>()
            var inSection = false
            for (line in config.split("\n")) {
                val trimmed = line.trim()
                if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                    inSection = trimmed.removePrefix("[").removeSuffix("]").equals(sectionName, ignoreCase = true)
                    continue
                }
                if (inSection && trimmed.contains("=")) {
                    val parts = trimmed.split("=", limit = 2)
                    out[parts[0].trim().lowercase()] = parts[1].trim()
                }
            }
            return out
        }

        /// Whether this session is one hop although the user wants Double VPN.
        ///
        ///  * a config that says two-hop is never marked, whatever the intent;
        ///  * any other route (single-hop, or none at all) is marked unless the
        ///    user has explicitly said no. A config saved by an older build
        ///    carries no route and cannot be told from a one-hop config, so by
        ///    owner ruling (2026-10-23) it is restarted, not refused, and it is
        ///    marked while Double VPN is wanted or the choice is unknown. The
        ///    accepted cost: a genuine old Double VPN session may show single
        ///    hop until it is reconnected from the app.
        ///  * UNKNOWN intent is treated as wanted: failing to read the choice
        ///    must never turn into silence. The cost of the wrong guess is one
        ///    accurate "Single hop" line for someone who did not want Double
        ///    VPN.
        @JvmStatic
        internal fun doubleVpnSingleHopFor(
            appSection: Map<String, String>,
            intent: DoubleVpnIntent,
        ): Boolean =
            appSection[DOUBLE_VPN_ROUTE_KEY]?.trim()?.lowercase() !=
                DOUBLE_VPN_ROUTE_TWO_HOP &&
                intent != DoubleVpnIntent.NOT_WANTED

        /// The state to describe right now. CONNECTED exactly when the app's
        /// own carrying composite is true -- the same `service_active &&
        /// engine_ready && interface_open` predicate that [isTunnelHealthy]
        /// and `winn_status_surface.dart`'s Android composite use, so the
        /// notification can never disagree with either the dashboard or the
        /// tunnel's own health check.
        ///
        /// [winn3Lifecycle] is the Winn v3 engine's own lifecycle as this host
        /// last judged it, or null for every other engine (and for a v3 engine
        /// that does not publish one), which keeps the composite rule exactly
        /// as it was. With it, CONNECTED additionally needs the engine to say
        /// `connected`: a recovering engine is RECOVERING even though the
        /// composite still holds, and BLOCKED outlives the composite, because
        /// a blocked tunnel is held as a blackhole after the engine is gone.
        @JvmStatic
        internal fun tunnelForegroundFor(
            serviceActive: Boolean,
            engineReady: Boolean,
            interfaceOpen: Boolean,
            winn3Lifecycle: WinnV3Lifecycle? = null,
        ): TunnelForegroundState =
            when {
                winn3Lifecycle == WinnV3Lifecycle.BLOCKED -> TunnelForegroundState.BLOCKED
                !(serviceActive && engineReady && interfaceOpen) -> TunnelForegroundState.CONNECTING
                winn3Lifecycle == null || winn3Lifecycle == WinnV3Lifecycle.CONNECTED ->
                    TunnelForegroundState.CONNECTED
                winn3Lifecycle == WinnV3Lifecycle.RECOVERING -> TunnelForegroundState.RECOVERING
                else -> TunnelForegroundState.CONNECTING
            }

        /// The notification title. Stable across CONNECTING/CONNECTED on
        /// purpose: the title names the surface, the text states the state,
        /// and an over-flappy title is itself a tell on a watched device.
        /// Disguised installs get the decoy name whatever the state.
        @JvmStatic
        internal fun tunnelForegroundTitleFor(disguised: Boolean, state: TunnelForegroundState): String =
            if (disguised) DISGUISED_DISPLAY_NAME else "Win's VPN Active"

        /// The notification text: an accurate, non-overclaiming statement of
        /// the actual state. CONNECTING never claims protection; CONNECTED
        /// claims the tunnel only after the carrying composite has held -- and,
        /// for a v3 session, only after the promotion gate's datapath proof.
        @JvmStatic
        internal fun tunnelForegroundTextFor(
            disguised: Boolean,
            state: TunnelForegroundState,
            doubleVpnSingleHop: Boolean = false,
        ): String =
            when {
                // FIRST, and independent of [doubleVpnSingleHop]: a disguised
                // notification is the ordinary one whatever the route is.
                disguised -> "Running in background."
                // A wanted Double VPN running on one hop is never silent. Only
                // CONNECTED is rewritten: the other states claim nothing about
                // the route.
                state == TunnelForegroundState.CONNECTED && doubleVpnSingleHop ->
                    SINGLE_HOP_TEXT
                state == TunnelForegroundState.CONNECTED ->
                    "Encrypted network tunnel is running."
                state == TunnelForegroundState.RECOVERING ->
                    "Reconnecting... Traffic is held until the tunnel is back."
                state == TunnelForegroundState.BLOCKED ->
                    "Could not reconnect. Traffic is held. Open the app to reconnect or disconnect."
                else -> "Connecting..."
            }

        /// The importance the tunnel channel will settle at, given whatever
        /// the platform already holds.
        ///
        /// The platform lets an app LOWER an existing channel's importance but
        /// never raise it, and the user may have quietened the channel further
        /// themselves -- including all the way to NONE. So the correct rule is:
        /// an inherited channel that is LOUDER than the app's own LOW (an old
        /// build created it at DEFAULT, say) is downgraded to LOW here; a
        /// channel the user already quietened stays exactly as quiet as they
        /// left it.
        ///
        /// Pure so the decision is unit-testable without a NotificationManager.
        @JvmStatic
        fun normalizedTunnelChannelImportance(current: Int): Int = when {
            current == NotificationManager.IMPORTANCE_UNSPECIFIED ||
                current > TUNNEL_CHANNEL_IMPORTANCE -> TUNNEL_CHANNEL_IMPORTANCE
            else -> current
        }

        /// The label Android renders on this app's card in the
        /// Overview/Recents switcher, via `ActivityManager.TaskDescription`.
        ///
        /// This was the last surface in the app still keyed on the LIVE decoy
        /// state, and it is the same defect class as the two notification
        /// channels even though the Recents entry is not latched in the
        /// Settings sense. The task description is applied by a running
        /// Activity; the Recents ENTRY outlives that Activity and the whole
        /// process. So the ordinary flow --
        ///
        ///   unlock with the PIN (decoy disarmed) -> onCreate applies the real
        ///   label -> process is killed before the decoy re-arms
        ///
        /// leaves a card in the switcher naming the product, with nothing
        /// running that could correct it. Reading the momentary signal at the
        /// one instant the decoy is guaranteed to be DOWN is exactly the trap
        /// `latchedSurfaceIsDisguised` exists for, so this joins it.
        ///
        /// The cost is the same one already accepted for the session name and
        /// both channels: an install that enrolled once and later abandoned
        /// camouflage keeps the decoy label on its Recents card until it is
        /// reinstalled. Erring toward the disguise is the fail-safe direction.
        ///
        /// The icon on that card must move with this label -- a card reading
        /// the decoy name over the product icon is a worse tell than either
        /// alone -- so `MainActivity.applyTaskIdentity` derives both from the
        /// same predicate rather than calling this in isolation.
        ///
        /// Context-free so a unit test can enumerate every (enrolled, armed)
        /// combination, and the only place in the Kotlin sources that can
        /// produce the real display name -- `CamouflageLatchedSurfaceTest`
        /// asserts that, and asserts the application label cannot.
        @JvmStatic
        fun taskDescriptionLabelFor(camouflageEnrolled: Boolean, decoyActive: Boolean): String {
            return if (latchedSurfaceIsDisguised(camouflageEnrolled, decoyActive)) {
                DISGUISED_DISPLAY_NAME
            } else {
                "Win's VPN"
            }
        }

        /// Whether the calculator launcher alias is the enabled one, answered
        /// from a bare Context.
        ///
        /// Companion-scope rather than an instance method because the channel
        /// has to be reconcilable when **no tunnel is running** -- see
        /// [refreshTunnelChannelForCamouflage]. The instance method of the same
        /// meaning delegates here so there is a single implementation.
        @JvmStatic
        fun decoyLauncherIsActive(context: Context): Boolean {
            return try {
                val app = context.applicationContext
                val decoyComponent = ComponentName(app, "${app.packageName}.LauncherDecoy")
                app.packageManager.getComponentEnabledSetting(decoyComponent) ==
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } catch (e: Exception) {
                false
            }
        }

        /// Make the tunnel channel's name in Settings match the camouflage
        /// state, and report whether the foreground notification may now be
        /// posted on it.
        ///
        /// The direct analogue of `MainActivity.settleAnnouncementChannel`, and
        /// it distrusts the platform in the same way and for the same reason:
        /// the guarantee it provides is one a coerced user's safety rests on,
        /// so it is a ladder, and every rung is verified by reading the channel
        /// back rather than by assuming the write took.
        ///
        ///  1. create, or update in place -> read back; if the name took, done;
        ///  2. else delete the channel outright and recreate it -> read back;
        ///     deletion is the one operation that unquestionably removes a row,
        ///     and its name, from Settings;
        ///  3. else, **while disguised**, delete the channel and return false.
        ///
        /// Rung 3 is the point. On an OEM build that honoured neither rename
        /// nor recreate, the row is removed rather than left naming the real
        /// app, and the caller posts nothing -- which for a foreground service
        /// means the tunnel does not run. That is the intended trade. A tunnel
        /// that refuses to start costs the user a connection they can retry;
        /// a permanent Settings row naming a VPN inside an app pretending to be
        /// a calculator costs them the camouflage, on a phone already being
        /// inspected by someone who suspects them.
        ///
        /// An install that is NOT disguised never fails here: rung 3 returns
        /// true, so a user who has no camouflage cannot lose a tunnel to a
        /// disguise they never asked for.
        /// Both camouflage signals are parameters rather than being read in
        /// here, so the caller states which pair it settled against -- the same
        /// shape [vpnSessionNameFor] and [tunnelChannelNameFor] already have,
        /// and the reason the service's own entry point can name them at its
        /// boundary.
        @JvmStatic
        fun settleTunnelChannel(
            context: Context,
            camouflageEnrolled: Boolean,
            decoyActive: Boolean,
            createIfAbsent: Boolean,
        ): Boolean {
            val disguised = latchedSurfaceIsDisguised(camouflageEnrolled, decoyActive)
            // Pre-O has no notification channels, so there is no Settings row
            // and nothing to leak.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true
            val manager = context.applicationContext
                .getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            if (manager == null) {
                // No manager means the row can be neither read nor renamed, so
                // nothing about it can be asserted. Fail closed while
                // disguised; leave an un-camouflaged install alone.
                return !disguised
            }

            val existing = manager.getNotificationChannel(TUNNEL_CHANNEL_ID)
            // Nothing is latched yet. Do not create a channel the app has not
            // needed -- an unnecessary row is itself a small tell.
            if (existing == null && !createIfAbsent) return false

            val wantedName = tunnelChannelNameFor(camouflageEnrolled, decoyActive)
            // Settle the channel at LOW: the platform refuses to RAISE
            // importance on an existing channel, so an inherited DEFAULT (a
            // pre-normalisation build) can only be quietened, not made louder
            // against the user's wishes, and a channel the user already
            // quietened (including to NONE) is left exactly as quiet.
            val importance = normalizedTunnelChannelImportance(
                existing?.importance ?: NotificationManager.IMPORTANCE_UNSPECIFIED,
            )

            fun wanted(): NotificationChannel =
                NotificationChannel(TUNNEL_CHANNEL_ID, wantedName, importance).apply {
                    // The channel exists to carry a permanent status row; it
                    // should never contribute a launcher badge.
                    setShowBadge(false)
                }

            fun settledName(): String? =
                manager.getNotificationChannel(TUNNEL_CHANNEL_ID)?.name?.toString()

            if (existing != null && existing.name?.toString() == wantedName) {
                // Name is already right, but an inherited loud importance must
                // still be quietened. Downgrading is permitted where raising is
                // not, so this is safe even though the channel already exists.
                if (existing.importance > TUNNEL_CHANNEL_IMPORTANCE) {
                    try {
                        manager.createNotificationChannel(wanted())
                    } catch (e: Exception) {
                        Log.w(VpnTunnelService.LOG_TAG, "Tunnel channel importance correction failed", if (BuildConfig.DEBUG) e else null)
                    }
                }
                return true
            }

            return try {
                // 1. Create, or update in place.
                manager.createNotificationChannel(wanted())
                if (settledName() == wantedName) return true

                // 2. The rename did not take. Delete the row and build it again.
                manager.deleteNotificationChannel(TUNNEL_CHANNEL_ID)
                manager.createNotificationChannel(wanted())
                if (settledName() == wantedName) return true

                // 3. Neither worked. Leave no channel behind carrying the real
                //    identity, and post nothing.
                if (disguised) {
                    manager.deleteNotificationChannel(TUNNEL_CHANNEL_ID)
                    Log.w(
                        VpnTunnelService.LOG_TAG,
                        "Tunnel channel could not be given the decoy name; " +
                            "channel deleted and the foreground notification suppressed.",
                    )
                    return false
                }
                true
            } catch (e: Exception) {
                // A platform that threw part-way through may have left the row
                // in any state. Fail closed while disguised.
                Log.w(VpnTunnelService.LOG_TAG, "Tunnel channel reconciliation failed", if (BuildConfig.DEBUG) e else null)
                if (disguised) {
                    try {
                        manager.deleteNotificationChannel(TUNNEL_CHANNEL_ID)
                    } catch (ignored: Exception) {
                        // Nothing further can be done; the caller posts nothing.
                    }
                    false
                } else {
                    true
                }
            }
        }

        /// The tunnel-channel analogue of
        /// [refreshAnnouncementChannelForCamouflage]'s job, and the piece
        /// without which this fix would only have helped fresh installs.
        ///
        /// [refreshForegroundNotificationForCamouflage] does rebuild the tunnel
        /// channel -- but only through `activeInstance`, which is non-null only
        /// while a tunnel is actually running. The install that needs help most
        /// is the opposite one: connected once before enrolling, latched the
        /// real name, disconnected, and only then decided it needed to hide.
        /// For that install the service instance is gone, the swap handler's
        /// refresh is a no-op, and the row would keep the real name until the
        /// user happened to connect again -- which may be never, and is in any
        /// case far too late.
        ///
        /// This takes a Context instead, so MainActivity can reconcile the row
        /// with no tunnel in sight. It never creates a channel.
        @JvmStatic
        fun refreshTunnelChannelForCamouflage(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            try {
                settleTunnelChannel(
                    context = context,
                    camouflageEnrolled = isCamouflageEnrolled(context),
                    decoyActive = decoyLauncherIsActive(context),
                    createIfAbsent = false,
                )
            } catch (e: Exception) {
                Log.w(VpnTunnelService.LOG_TAG, "Tunnel channel camouflage refresh skipped", if (BuildConfig.DEBUG) e else null)
            }
        }

        /**
         * The IPv6 fail-closed sink address, shared by every mode that
         * establishes an interface.
         *
         * Named rather than repeated because there are now two establish paths
         * - the v1 builder below and the v3 staged start - and two copies of a
         * fail-closed address is how one of them quietly stops being
         * fail-closed. `WinnV3AdoptionTest` asserts the v3 promotion posture
         * installs this exact value.
         */
        const val IPV6_FAIL_CLOSED_SINK = "fd00:d951:0001::1"

        @JvmStatic
        @Volatile
        var isServiceActive = false

        @JvmStatic
        @Volatile
        var isEngineReady = false

        @JvmStatic
        @Volatile
        var isInterfaceOpen = false

        @JvmStatic
        @Volatile
        var engineReadyAtMs = 0L

        @JvmStatic
        @Volatile
        var tunnelStartUidRx = -1L

        @JvmStatic
        @Volatile
        var tunnelStartUidTx = -1L

        @JvmStatic
        @Volatile
        var lastWinn3StartSecurityRefusal = false

        /** Binds readiness to one Dart-issued v3 start, never a stale attempt. */
        @JvmStatic
        @Volatile
        var lastWinn3StartToken = -1L

        /** Dart transition generation paired with [lastWinn3StartToken]. */
        @JvmStatic
        @Volatile
        var lastWinn3StartGeneration = -1L

        /**
         * In-flight `pending`, or a completed [WinnV3NativeVerdict] wire name:
         * `ordinary_connectivity`, `terminal_security`, `unknown_terminal`,
         * `connected`. Never `connectivity_failed`.
         */
        @JvmStatic
        @Volatile
        var lastWinn3StartState = "idle"

        /**
         * Equals [lastWinn3StartToken] only when that start proved ordinary
         * network unreachability. Absent (`-1`) for security, unknown, and
         * connected verdicts, so AWG/Xray cover cannot be authorized from a
         * silent handshake failure.
         */
        @JvmStatic
        @Volatile
        var lastWinn3AwgXrayAuthorizationToken = -1L

        @Volatile
        private var lastWinn3ReadinessSnapshot = WinnV3NativeReadinessSnapshot(
            startToken = -1L,
            startGeneration = -1L,
            state = "idle",
            securityRefusal = false,
            awgXrayAuthorizationToken = -1L,
            selectionGeneration = "",
            failedNode = "",
        )

        @JvmStatic
        internal fun currentWinn3ReadinessSnapshot(): WinnV3NativeReadinessSnapshot =
            lastWinn3ReadinessSnapshot

        @JvmStatic
        internal fun beginWinn3Start(
            startToken: Long,
            startGeneration: Long,
            selectionGeneration: String,
            failedNode: String,
        ) {
            synchronized(winn3VerdictStateLock) {
                lastWinn3StartToken = startToken
                lastWinn3StartGeneration = startGeneration
                lastWinn3StartSecurityRefusal = false
                lastWinn3StartState = "pending"
                lastWinn3AwgXrayAuthorizationToken = -1L
                lastWinn3ReadinessSnapshot = WinnV3NativeReadinessSnapshot(
                    startToken,
                    startGeneration,
                    "pending",
                    false,
                    -1L,
                    selectionGeneration,
                    failedNode,
                )
            }
        }

        @JvmStatic
        @Volatile
        var lastUnderlyingTransport = "unknown"

        @JvmStatic
        @Volatile
        var speedTestMeasuresPhysicalRoute = false

        /// Whether `Builder.establish()` may be called, given how much of the
        /// IPv6 fail-closed sink the platform actually accepted.
        ///
        /// Extracted rather than written inline at the call site on purpose.
        /// The inline version of this decision was a `catch` that logged
        /// "IPv6 fail-closed route is unavailable." and then established the
        /// tunnel anyway, which is the exact defect `camouflage_policy.dart`
        /// was extracted to prevent one layer up: a safety condition buried in
        /// control flow, asserting in its own text a guarantee the control
        /// flow did not provide. As a named function it is greppable and
        /// unit-testable, so a future lane cannot restore fail-open behaviour
        /// without a red test.
        ///
        /// Both halves are required. An address with no `::/0` route leaves
        /// host IPv6 on the physical interface; a `::/0` route with no address
        /// of that family is not a documented blackhole. Anything short of
        /// both means the tunnel would carry IPv4 while IPv6 egressed in the
        /// clear -- a session the user would believe was protected.
        @JvmStatic
        fun mayEstablishTunnel(
            ipv6SinkAddressApplied: Boolean,
            ipv6SinkRouteApplied: Boolean,
        ): Boolean {
            return ipv6SinkAddressApplied && ipv6SinkRouteApplied
        }

        @JvmStatic
        @Volatile
        private var activeTeardownThread: Thread? = null

        @JvmStatic
        fun isTeardownInProgress(): Boolean {
            val thread = activeTeardownThread
            return (thread != null && thread.isAlive) || activeInstance?.tearingDown == true
        }

        @JvmStatic
        fun awaitTeardown(timeoutMs: Long = 3000L): Boolean {
            val thread = activeTeardownThread
            if (thread != null && thread.isAlive) {
                try {
                    thread.join(timeoutMs)
                } catch (_: InterruptedException) {
                    return false
                }
                return !thread.isAlive
            }
            return activeInstance?.tearingDown != true
        }

        /**
         * The Winn v3 engine's lifecycle as this host last published it, for
         * the notification, [isTunnelHealthy] and the app's readiness map.
         * Owner-checked; see [WinnV3HostLifecycleBoard].
         */
        internal val winn3HostLifecycle = WinnV3HostLifecycleBoard()

        /**
         * Round L: which Winn v3 capture hold is outstanding, and the release
         * acknowledgement each completed teardown pass publishes. The app
         * waits on it before a held reconnect or held server switch prepares
         * anything; see [WinnV3ReleaseLedger].
         */
        internal val winn3ReleaseLedger = WinnV3ReleaseLedger()

        /**
         * Round L: cleanup evidence a teardown pass could not resolve (a
         * throwing close, a bridge close that had not finished). It outlives
         * the pass, so a later release pass cannot say CLOSED over it; it is
         * cleared only when a new tunnel session begins. See
         * [WinnV3CleanupDebt].
         */
        internal val winn3CleanupDebt = WinnV3CleanupDebt()

        /** [WinnV3ReleaseLedger] keys for `getTunnelReadiness`. */
        @JvmStatic
        internal fun currentReleaseFields(): Map<String, Any> =
            winn3ReleaseLedger.snapshot().readinessFields()

        @JvmStatic
        fun isTunnelHealthy(): Boolean = tunnelHealthyFor(
            isServiceActive,
            isEngineReady,
            isInterfaceOpen,
            winn3HostLifecycle.snapshot(),
        )

        /**
         * The three-boolean composite, and never while a supervised Winn v3
         * engine is anything but engine-proven `connected`: recovering and
         * blocked keep the tunnel and its capture but are not a healthy,
         * connected tunnel. An engine without the field keeps the old rule.
         */
        @JvmStatic
        internal fun tunnelHealthyFor(
            serviceActive: Boolean,
            engineReady: Boolean,
            interfaceOpen: Boolean,
            lifecycle: WinnV3HostLifecycleBoard.Snapshot,
        ): Boolean = serviceActive && engineReady && interfaceOpen && lifecycle.permitsConnectedClaim()

        /**
         * The connected-claim keys of `getTunnelReadiness` and the lifecycle
         * keys beside them. `active`, `tunnel_healthy` and `engine_ready` are
         * never true while the engine recovers or is blocked. The lifecycle
         * keys are separate from the historical start verdict
         * (`winn3_verdict`, `winn3_start_state`) and from the cover
         * authorization token, and nothing reads them to authorise cover.
         */
        @JvmStatic
        internal fun readinessClaimFields(
            serviceActive: Boolean,
            engineReady: Boolean,
            interfaceOpen: Boolean,
            lifecycle: WinnV3HostLifecycleBoard.Snapshot,
        ): Map<String, Any> {
            val healthy = tunnelHealthyFor(serviceActive, engineReady, interfaceOpen, lifecycle)
            return linkedMapOf<String, Any>(
                "active" to healthy,
                "tunnel_healthy" to healthy,
                "engine_ready" to (engineReady && lifecycle.permitsConnectedClaim()),
            ) + lifecycle.readinessFields()
        }

        /** [readinessClaimFields] for the live service state, plus the route marker. */
        @JvmStatic
        internal fun currentReadinessClaimFields(): Map<String, Any> = readinessClaimFields(
            isServiceActive,
            isEngineReady,
            isInterfaceOpen,
            winn3HostLifecycle.snapshot(),
        ) + mapOf<String, Any>(
            // The very value the ongoing notification is posted from, so the
            // app's dashboard can take it (for a service the system restarted,
            // or one the app adopted) instead of guessing from a staged config.
            DOUBLE_VPN_READINESS_KEY to (activeInstance?.doubleVpnSingleHop == true),
            "double_vpn_handover_token" to (activeInstance?.doubleVpnHandoverToken?.get() ?: 0L),
        )

        @JvmStatic
        fun confirmDoubleVpnHandover(token: Long): Boolean =
            token > 0L && activeInstance?.doubleVpnHandoverToken?.compareAndSet(token, 0L) == true

        @JvmStatic
        fun currentAwgPeerStats(): Map<String, Any> {
            return activeInstance?.readCurrentAwgPeerStats() ?: emptyAwgPeerStats()
        }

        // The foreground notification/channel are only (re)computed when the
        // service starts a tunnel, so if the launcher identity changes later
        // while a tunnel is already running and connected -- backgrounding
        // re-arms the decoy, for instance -- they would otherwise keep
        // showing whichever identity was active at connect time. Called from
        // MainActivity's triggerCamouflageSwap handler after every icon
        // swap; a no-op if no tunnel is currently running.
        //
        // THAT NO-OP IS WHY [refreshTunnelChannelForCamouflage] EXISTS. This
        // hook can only reach the channel through a live service instance,
        // and the channel row outlives every service instance. The swap
        // handler must call both.
        //
        // If the notification cannot be posted without naming the real app,
        // the tunnel is torn down rather than left running behind a foreground
        // notification the disguise does not cover.
        @JvmStatic
        fun refreshForegroundNotificationForCamouflage() {
            val instance = activeInstance ?: return
            if (!instance.startAsForegroundService()) instance.executeTunnelTeardown()
        }

        private fun emptyAwgPeerStats(): Map<String, Any> = mapOf(
            "handshake_recent" to false,
            "handshake_age_ms" to -1L,
            "rx_bytes" to 0L,
            "tx_bytes" to 0L,
        )

        // ---- Carrier address resolution, shared with MainActivity --------
        //
        // PREFLIGHT DNS EGRESS (2026-08-07). These five helpers were private
        // instance members of this service and are otherwise unchanged; they
        // only gained the Context they used to take from `this`. They moved
        // into companion scope for exactly one reason: lib/main.dart's Xray
        // WebSocket preflight runs in the Flutter process, before this service
        // exists, and used to resolve the carrier itself via
        // Socket.connect(<name>) -- an A *and* an AAAA per probed candidate,
        // earlier in the connect path than anything
        // docs/handoff/XRAY_CLIENT_DNS_EGRESS_REMEDIATION_20260807.md hardened
        // (see its §4.2). It now calls this same A-only, Network-pinned
        // resolver through MainActivity's `resolveCarrierIpv4` channel entry,
        // rather than growing a second implementation beside it.

        /**
         * Companion-scope equivalents of the instance logWarning/logError that
         * these helpers used before the move. Identical behaviour; they exist
         * only because a companion member cannot reach an instance method.
         */
        private fun resolverWarning(message: String, error: Throwable? = null) {
            if (BuildConfig.DEBUG && error != null) {
                Log.w(VpnTunnelService.LOG_TAG, message, error)
            } else {
                Log.w(VpnTunnelService.LOG_TAG, message)
            }
        }

        private fun resolverError(message: String) {
            Log.e(VpnTunnelService.LOG_TAG, message)
        }

        /**
         * True for a dotted-quad IPv4 literal. Deliberately a pure string test:
         * it must never reach a resolver, because its whole job is to decide
         * whether a resolver is needed at all.
         */
        private fun isIpv4Literal(value: String): Boolean {
            val parts = value.split('.')
            if (parts.size != 4) return false
            return parts.all { part ->
                part.isNotEmpty() && part.length <= 3 && part.all { it.isDigit() } &&
                    (part.length == 1 || part[0] != '0') &&
                    (part.toIntOrNull() ?: -1) in 0..255
            }
        }

        /**
         * The same public-IPv4 test Linux applies before it will hand an address
         * to Xray (linux_tunnel_backend.cc IsPublicIpv4Address). A carrier that
         * resolves into RFC1918, loopback, CGNAT, link-local or a reserved
         * documentation range is a hijacked or misconfigured answer, not an edge.
         */
        private fun isPublicIpv4(address: String): Boolean {
            // LAB-ONLY ALLOWANCE (2026-08-08): the lab gateway at 192.168.50.226
            // is a private RFC1918 address, so the public-IPv4 filter would
            // refuse it and the Xray transport could never start in the lab.
            // The previous lane added the same allowance and reverted it;
            // this lane adds it for the profile lab variant, gated on
            // BuildConfig.DEBUG so the shipping Release build never accepts a
            // private address. It is a single literal, not a subnet, and the
            // shipping path never serves a private address in any case.
            if (BuildConfig.DEBUG && address == "192.168.50.226") return true
            val octets = address.split('.').mapNotNull { it.toIntOrNull() }
            if (octets.size != 4) return false
            val (first, second, third, _) = octets
            if (first == 0 || first == 10 || first == 127 || first >= 224) return false
            if (first == 100 && second in 64..127) return false
            if (first == 169 && second == 254) return false
            if (first == 172 && second in 16..31) return false
            if (first == 192 && second == 168) return false
            if (first == 192 && second == 0 && (third == 0 || third == 2)) return false
            if (first == 198 && (second == 18 || second == 19)) return false
            if (first == 198 && second == 51 && third == 100) return false
            if (first == 203 && second == 0 && third == 113) return false
            return true
        }

        /**
         * Resolves the carrier host to public IPv4 literals, or returns empty so
         * the caller fails closed.
         *
         * WHAT THIS DOES NOT DO, stated plainly because the previous shape claimed
         * more than it delivered: it does not protect the query. This runs before
         * builder.establish(), so there is no tunnel to put it in, and
         * VpnService.protect() is the wrong direction anyway -- it keeps a socket
         * OUT of a tunnel that does not exist yet. Routing the lookup through the
         * tunnel is not merely unimplemented, it is circular: the tunnel's carrier
         * is the name being resolved. A pre-tunnel lookup is irreducible while the
         * config carries a name.
         *
         * What it does buy, all of it measured:
         * - the query stops coming from the Xray subprocess, which
         *     addDisallowedApplication() puts outside the tunnel for the entire
         *     session and which cannot be protected at all;
         * - it happens once instead of repeating several times a second for as
         *     long as a dial keeps failing;
         * - on API 29+ it asks for A only, so no AAAA query is emitted for a
         *     carrier that has no AAAA record -- an absence that is itself a
         *     distinguishing signal;
         * - and when `host` is already a literal it does not happen at all.
         *
         * The API 24-28 fallback uses InetAddress, which has no family hint and
         * therefore also emits AAAA. That is a real residual on those releases and
         * it is left visible here rather than papered over.
         */
        fun resolveTransportIpv4Addresses(context: Context, host: String): List<String> {
            if (isIpv4Literal(host)) {
                // IP-pinned bootstrap: nothing is looked up, so nothing leaves.
                return if (isPublicIpv4(host)) listOf(host) else emptyList()
            }
            val resolved =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    queryIpv4OnlyApi29(context, host)
                } else {
                    queryIpv4ViaInetAddress(host)
                }
            return resolved.filter { isPublicIpv4(it) }.distinct().sorted()
        }

        /**
         * A-only lookup through android.net.DnsResolver, pinned to the currently
         * active network. The network pin is not protection -- see the caller --
         * it only makes the egress path deterministic, so a stale or half-torn-down
         * VPN cannot silently capture the query and turn a working carrier into an
         * unreachable one.
         */
        @androidx.annotation.RequiresApi(Build.VERSION_CODES.Q)
        private fun queryIpv4OnlyApi29(context: Context, host: String): List<String> {
            val resolver = android.net.DnsResolver.getInstance()
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            val network = try {
                connectivity?.activeNetwork
            } catch (_: Exception) {
                null
            }
            val latch = java.util.concurrent.CountDownLatch(1)
            val answers = java.util.concurrent.atomic.AtomicReference<List<String>>(emptyList())
            val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
            try {
                resolver.query(
                    network,
                    host,
                    android.net.DnsResolver.TYPE_A,
                    android.net.DnsResolver.FLAG_EMPTY,
                    executor,
                    null,
                    object : android.net.DnsResolver.Callback<List<InetAddress>> {
                        override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                            answers.set(
                                answer.filterIsInstance<Inet4Address>()
                                    .mapNotNull { it.hostAddress }
                            )
                            latch.countDown()
                        }

                        override fun onError(error: android.net.DnsResolver.DnsException) {
                            resolverWarning("Carrier address lookup failed.", error)
                            latch.countDown()
                        }
                    },
                )
                // Bounded: onStartCommand runs on the main thread, so this must not
                // be able to hang it. An expired wait fails closed at the caller,
                // exactly like an empty answer.
                if (!latch.await(6, java.util.concurrent.TimeUnit.SECONDS)) {
                    resolverError("Carrier address lookup did not complete within its bound.")
                    return emptyList()
                }
                return answers.get()
            } catch (e: Exception) {
                resolverWarning("Carrier address lookup could not be dispatched.", e)
                return emptyList()
            } finally {
                executor.shutdownNow()
            }
        }

        /** API 24-28 fallback. Emits AAAA as well as A; see resolveTransportIpv4Addresses. */
        private fun queryIpv4ViaInetAddress(host: String): List<String> {
            return try {
                InetAddress.getAllByName(host)
                    .filterIsInstance<Inet4Address>()
                    .mapNotNull { it.hostAddress }
            } catch (e: UnknownHostException) {
                resolverWarning("Carrier address lookup failed.", e)
                emptyList()
            } catch (e: Exception) {
                resolverWarning("Carrier address lookup failed.", e)
                emptyList()
            }
        }
    }

    private data class UnderlyingNetworkCandidate(
        val network: Network,
        val score: Int
    )

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        activeInstance = this
        val action = intent?.action
        // CORE-7-T17C-claude: once tunnel starts are sealed for a local
        // reset, only disconnect and block-exit run. Every other action,
        // including ACTION_CONNECT with a CONFIG_PAYLOAD and a sticky or
        // always-on start that would load the saved restart configuration,
        // returns before either is read.
        if (secureFileStore.accountResetPending() &&
            action != "ACTION_DISCONNECT" &&
            action != ACTION_EXIT_BLOCK
        ) {
            return START_NOT_STICKY
        }
        if (action == "ACTION_DISCONNECT") {
            WinnV3AwgXrayGrantStore.clear()
            doubleVpnHandoverToken.set(0L) // a stop is not a failed handover
            clearRestartConfig()
            // The owner acting is the acknowledgement of a release notice.
            winn3HostLifecycle.acknowledgeReleaseNotice()
            executeTunnelTeardown(
                keepVpnLauncher = intent.getBooleanExtra("KEEP_VPN_LAUNCHER", false),
                // A deliberate user disconnect releases the kill-switch block.
                allowBlockPosture = !intent.getBooleanExtra("RELEASE_KILL_SWITCH_BLOCK", false),
                cause = WinnV3TeardownCause.OWNER_DISCONNECT,
            )
            return START_NOT_STICKY
        }

        // ---- Kill switch control actions -----------------------------------
        // Debug/driver surface, consumed over adb by DevKillSwitchActivity and
        // re-used by the connect path below (armAlwaysOnLockdown on connect).
        // None of them starts a tunnel.
        if (action == ACTION_ARM_KILLSWITCH) {
            setKillSwitchArmed(true)
            val outcome = androidKillSwitch.armAlwaysOnLockdown()
            logKillSwitchState("arm requested", outcome)
            return START_NOT_STICKY
        }
        if (action == ACTION_DISARM_KILLSWITCH) {
            setKillSwitchArmed(false)
            androidKillSwitch.disarmAlwaysOnLockdown()
            logKillSwitchState("disarm requested", null)
            return START_NOT_STICKY
        }
        if (action == ACTION_ENTER_BLOCK) {
            // Demo/test only: hold a blocking interface as a foreground
            // service with no engine, so the device is blocked without any
            // carrier in the picture. Used by the Motorola proof.
            beginBlockPosture()
            return START_STICKY
        }
        if (action == ACTION_EXIT_BLOCK) {
            endBlockPosture()
            return START_NOT_STICKY
        }

        // Every start that goes on to the tunnel reset below waits for an
        // in-flight teardown pass, not only the app's ACTION_CONNECT:
        // the system's always-on start (VpnService.SERVICE_INTERFACE) and a
        // START_STICKY restart (null intent, normally a fresh process) reach
        // the same reset, which must never force the teardown worker idle
        // while its thread is still closing interfaces.
        if (action == "ACTION_CONNECT" || action == null || action == VpnService.SERVICE_INTERFACE) {
            if (tearingDown || isTeardownInProgress()) {
                Log.i(VpnTunnelService.LOG_TAG, "ACTION_CONNECT received while teardown is in flight; awaiting completion.")
                if (!awaitTeardown(2500L)) {
                    Log.e(
                        VpnTunnelService.LOG_TAG,
                        "Refusing ACTION_CONNECT because the prior teardown did not finish within 2500 ms.",
                    )
                    return START_NOT_STICKY
                }
            }
        }

        val suppliedConfig = intent?.getStringExtra("CONFIG_PAYLOAD") ?: ""
        val config = suppliedConfig.ifBlank {
            val restoredConfig = loadRestartConfig()
            if (restoredConfig.isNotBlank()) {
            debugLog("Restarting foreground VPN service from saved tunnel configuration.")
            }
            restoredConfig
        }
        if (config.isBlank()) {
            Log.e(VpnTunnelService.LOG_TAG, "Empty tunnel configuration payload")
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }

        doubleVpnHandoverToken.set(0L)
        resetTunnelBeforeConnect()
        val appSection = parseConfigSection(config, "winsapp")
        // Both a Dart start and a system restart (null intent, always-on) come
        // through here, so a restored config is judged against what the user
        // wants NOW, not against what they wanted when it was saved.
        doubleVpnSingleHop = doubleVpnSingleHopFor(appSection, readDoubleVpnIntent())
        // Publish the token only after reset and the route marker have moved.
        doubleVpnHandoverToken.set(
            if (action == "ACTION_CONNECT")
                intent?.getLongExtra("DOUBLE_VPN_HANDOVER_TOKEN", 0L)?.coerceAtLeast(0L) ?: 0L
            else 0L
        )
        val winnSection = parseConfigSection(config, WinnEngineConfig.SECTION)
        val winnEnabled = WinnEngineConfig.isEnabled(winnSection)
        val winn3Requested = winnEnabled && WinnV3SessionPlan.isRequested(winnSection)
        val restoredBySystem = suppliedConfig.isBlank()
        var winn3StartToken = intent?.getLongExtra("WINN3_START_TOKEN", -1L) ?: -1L
        var winn3StartGeneration =
            intent?.getLongExtra("WINN3_START_GENERATION", -1L) ?: -1L
        if (restoredBySystem && winn3Requested && winn3StartToken <= 0L) {
            // START_STICKY, Always-on and boot restarts carry no Dart caller.
            // Mint native identities so the staged start can run; Dart, when it
            // returns, reads a token it did not mint and treats it as foreign.
            winn3StartToken =
                (java.security.SecureRandom().nextLong() and Long.MAX_VALUE).coerceAtLeast(1L)
            winn3StartGeneration = 1L
        }
        val callerSelectedNode =
            intent?.getStringExtra(WinnV3SelectedNodeCaller.EXTRA_SELECTED_NODE)
                ?: if (restoredBySystem) loadRestartSelectedNode() else null
        val winn3SelectionGeneration =
            intent?.getStringExtra("WINN3_SELECTION_GENERATION").orEmpty()
        val winn3FailedNode = intent?.getStringExtra("WINN3_FAILED_NODE").orEmpty()
        val coverAuthToken = intent?.getLongExtra("WINN3_AWG_XRAY_AUTHORIZATION_TOKEN", -1L) ?: -1L
        val coverTarget = intent?.getStringExtra("WINN3_COVER_EXACT_TARGET").orEmpty()
        val coverLeg = WinnV3CoverLeg.parse(intent?.getStringExtra("WINN3_COVER_LEG"))
        val coverRequested = coverAuthToken > 0L || coverTarget.isNotEmpty() || coverLeg != null
        if (winn3Requested) {
            WinnV3AwgXrayGrantStore.clear()
            if (winn3StartToken <= 0L || winn3StartGeneration <= 0L) {
                Log.e(
                    VpnTunnelService.LOG_TAG,
                    "Refusing Winn v3 start without exact positive start identities.",
                )
                clearRestartConfig()
                executeTunnelTeardown()
                return START_NOT_STICKY
            }
            beginWinn3Start(
                winn3StartToken,
                winn3StartGeneration,
                winn3SelectionGeneration,
                winn3FailedNode,
            )
        } else if (coverRequested) {
            val nowMs = android.os.SystemClock.elapsedRealtime()
            if (coverAuthToken <= 0L ||
                winn3StartToken != coverAuthToken ||
                winn3StartGeneration <= 0L ||
                coverTarget.isEmpty() ||
                coverLeg == null ||
                !WinnV3AwgXrayGrantStore.consume(
                    startToken = winn3StartToken,
                    startGeneration = winn3StartGeneration,
                    selectionGeneration = winn3SelectionGeneration,
                    failedV3Node = winn3FailedNode,
                    exactV1Target = coverTarget,
                    requestedLeg = coverLeg,
                    nowMs = nowMs,
                )
            ) {
                Log.e(VpnTunnelService.LOG_TAG, "Refusing Winn v1 cover start without a matching grant.")
                clearRestartConfig()
                executeTunnelTeardown()
                return START_NOT_STICKY
            }
        } else {
            WinnV3AwgXrayGrantStore.clear()
        }

        val xraySection = parseConfigSection(config, "xray")
        val xrayEnabled = parseBool(xraySection["enabled"])
        if (xrayEnabled) {
            logError("Refusing Xray mode before carrier launch because its socket is not individually protected. No DNS lookup or carrier process was started.")
            refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }

        // Fail closed. The foreground notification is mandatory and permanently
        // visible while a tunnel runs, and its channel row outlives the tunnel
        // in Settings. If that row cannot be made to carry the decoy's name
        // while the disguise is in force, the connection does not happen --
        // a retryable failure instead of a permanent one.
        if (!startAsForegroundService()) {
            Log.e(
                VpnTunnelService.LOG_TAG,
                "Refusing to start the tunnel: the foreground notification channel " +
                    "could not be reconciled with the active camouflage state.",
            )
            refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }
        acquireTunnelPerformanceLocks()

        if (winn3Requested && xrayEnabled) {
            logError(
                "Tunnel config enables Winn Protocol v3 and the stealth Xray transport. " +
                    "v3 carries its own transport; refusing rather than stacking it under " +
                    "one it was not designed against."
            )
            refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }
        // THE STACKED ARRANGEMENT ("stealth-chain"), told apart from the
        // competing one by the Winn engine's own gateway endpoint: stacked, it
        // is the Xray inbound on loopback, so AmneziaWG -> Winn seam -> Winn
        // engine -> Xray -> edge and each relay owns a distinct loopback port.
        // Competing, it is a real gateway, and then the two transports really
        // do both want the one AmneziaWG peer-endpoint field.
        //
        // Derived from the config rather than from a new key on purpose: the
        // arrangement is already fully described by the endpoint the Dart
        // dispatch emitted, so there is nothing here for a served value to
        // disagree with, and WinnEngineConfig.from still refuses any key it
        // does not know.
        val winnStealthChain = winnEnabled && xrayEnabled &&
            (winnSection["endpoint"]?.trim() ?: "") ==
            "127.0.0.1:" + (xraySection["localport"]?.trim() ?: "")
        if (winnEnabled && xrayEnabled && !winnStealthChain) {
            // The two outer transports are mutually exclusive WHEN THEY COMPETE.
            // stealth-xray needs the whole app UID excluded from the tunnel;
            // Winn otherwise keeps the UID inside it and protects one socket
            // individually. Silently picking one would give the user a transport
            // they did not ask for, so fail closed instead. The stacked
            // arrangement above is not this case: it wants BOTH, in a fixed
            // order, and says so.
            logError("Tunnel config enables both the stealth Xray transport and Winn Protocol; refusing to start.")
            refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }

        try {
            startXrayTransportIfNeeded(config)
        } catch (e: Exception) {
            logError("Fallback transport failed to start", e)
            refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }

        val awgConfig = stripConfigSection(
            stripConfigSection(
                stripConfigSection(
                    stripConfigSection(stripConfigSection(config, "xray"), "winsdebug"),
                    "winsapp"
                ),
                "winsboost"
            ),
            WinnEngineConfig.SECTION
        )
        if (!winnEnabled) {
            try {
                AwgUserspaceConfig.fromQuick(awgConfig)
            } catch (_: IOException) {
                clearRestartConfig()
                executeTunnelTeardown()
                return START_NOT_STICKY
            }
        }
        val clientIp = parseConfigValue(awgConfig, "Address")?.split("/")?.getOrNull(0) ?: "10.8.1.3"
        val rawDnsConfig = parseConfigValue(awgConfig, "DNS")
        val parsedDns = DnsConfig.parse(rawDnsConfig)
        val dnsServer = parsedDns.servers.firstOrNull()?.hostAddress ?: "10.8.1.1"
        // THE SAME LINE, WITHOUT THE FALLBACK, FOR THE v3 PATH.
        //
        // `10.8.1.1` is an address in the AmneziaWG INNER SPACE. A standalone
        // winn/3 session shares no address space with the relay because it
        // shares no session with it, and the winn/3 tun layer drops what does
        // not match its own assignment - so handing that default to a v3
        // promotion pointed every name lookup at an address inside a tunnel
        // that discards it, while the gate reported carrying.
        //
        // The fallback stays for the v1 branch, which is where it belongs and
        // where it has always been correct: that IS the relay's resolver. What
        // changes is that it can no longer cross into a protocol it says
        // nothing about. What the v3 path receives is the raw `[Interface] DNS`
        // list and nothing else, and [WinnV3Resolvers] then decides whether any
        // member of it is a resolver a standalone session can justify - which,
        // for every configuration the control plane serves today, is no.
        val winn3ResolverCandidates: List<String> = parseConfigValue(awgConfig, "DNS")
            ?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?: emptyList()
        val mtu = awgInterfaceMtuForEndpoint(
            endpoint = parseConfigValue(awgConfig, "Endpoint"),
            requestedMtu = parseConfigValue(awgConfig, "MTU")?.toIntOrNull()
                ?: AWG_MTU_IPV4_CEILING,
            linkMtu = underlyingNetworkLinkMtu(this),
        )
        // RV-B: latch the active session's inner router for the speedtest
        // ingest gate (inner-only address, dotted-quad validated at parse).
        parseConfigValue(awgConfig, "inner_router_v4")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { latchedInnerRouterV4 = it }
        val allowedIpv4Routes = VpnRouteParser.allowedIpv4Routes(awgConfig)
        if (allowedIpv4Routes.isEmpty()) {
            logError("VPN config has no valid IPv4 AllowedIPs routes")
            refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }
        val mode = when {
            winnStealthChain -> "winn-v3-stealth-chain"
            winnEnabled -> "winn-v3"
            xrayEnabled -> "stealth-xray"
            else -> "direct-awg"
        }

        // ---- WINN PROTOCOL v3 -------------------------------------------
        //
        // v3 leaves before the builder below, and that is the whole shape of
        // this branch. Every other mode this service starts installs ONE
        // posture in one `establish()` call: address, full route set, DNS and
        // the IPv6 sink, all before a single byte has crossed. v3 must not,
        // because `WINN3_TUN_LAYER_20260808.md` §4.1 requires the first posture
        // to capture nothing - one /32, one route, no default route, no IPv6,
        // no resolvers - and the full posture to arrive only after the datapath
        // has proven itself. Android cannot mutate a live VpnService, so that
        // second posture is a second `establish()`, and the whole sequence
        // therefore belongs to the v3 start rather than to this function.
        //
        // Note the two labels above are NOT this: `"winn-v3"` names the
        // v1-over-Winn arrangement and always has. The protocol is selected by
        // `[winn] protocol = 3` or the normalized served `carrier = winn3`.
        if (winn3Requested) {
            // Bind the Flutter/phone/TV caller identity onto the served
            // [winn] section BEFORE session planning. WinnV3SessionPlan.from
            // already refuses a descriptor that does not match selected_node;
            // without this extra the only selected-node identity is whatever
            // the INI self-claims, which a substituted descriptor can forge
            // to match its own `node`. A missing extra, a Kelvin/Unicode
            // identity, or a disagreement with INI aliases is a terminal
            // security refusal - never AWG/Xray cover.
            val planningSection = WinnV3SelectedNodeCaller.planningSection(
                section = winnSection,
                extra = callerSelectedNode,
            )
            if (planningSection == null) {
                logError(
                    "Refusing Winn Protocol v3 without a matching caller-selected node identity.",
                )
                refuseWinn3Start(winn3Requested, winn3StartToken, winn3StartGeneration)
                clearRestartConfig()
                executeTunnelTeardown()
                return START_NOT_STICKY
            }
            val v3Generation = nextTunnelGeneration()
            startWinnV3EngineThread(
                winnSection = planningSection,
                appSection = appSection,
                clientIp = clientIp,
                resolverCandidates = winn3ResolverCandidates,
                promotionRoutes = allowedIpv4Routes.map {
                    WinnV3Route(it.address, it.prefixLength)
                },
                generation = v3Generation,
                startToken = winn3StartToken,
                startGeneration = winn3StartGeneration,
            )
            persistRestartSelectedNode(callerSelectedNode)
            persistRestartConfig(config)
            return START_STICKY
        }

        try {
            debugLog("Creating native VPN interface with MTU=$mtu mode=$mode")

            val builder = Builder()
                .setSession(vpnSessionName())
                .addAddress(clientIp, 32)
                .setMtu(mtu)

            for (server in parsedDns.servers) {
                builder.addDnsServer(server)
            }
            for (domain in parsedDns.searchDomains) {
                try {
                    builder.addSearchDomain(domain)
                } catch (e: Exception) {
                    logWarning("Could not add a search domain", e)
                }
            }

            for (route in allowedIpv4Routes) {
                builder.addRoute(route.address, route.prefixLength)
            }
            debugLog("Applied ${allowedIpv4Routes.size} exact IPv4 VPN routes.")

            try {
                builder.allowFamily(OsConstants.AF_INET)
                debugLog("IPv4 VPN family enabled.")
            } catch (e: Exception) {
                logWarning("Unable to explicitly enable the IPv4 VPN family.", e)
            }

            // IPv6 FAIL-CLOSED SINK (2026-08-07: made to match its own name).
            //
            // Both halves are mandatory and they are attempted separately so
            // the log names which one the platform rejected. The sink address
            // gives the interface an IPv6 identity; `::/0` pulls every IPv6
            // destination into it. Neither alone is a protection: an address
            // with no default route leaves host IPv6 on the physical
            // interface, and a route with no address of that family is not a
            // configuration Android documents as blackholing.
            //
            // Until today this was one try/catch whose handler only logged a
            // warning that the fail-closed route was unavailable, and then
            // fell through to establish() below. That shipped a tunnel whose
            // own log line claimed "fail-closed" while host IPv6 kept
            // egressing in the clear -- the app said Connected, and the user
            // had no way to tell a protected session from an attributable
            // one. On this threat model an attributable session is worse than
            // no session, so the start now refuses, exactly like the
            // both-outer-transports and no-IPv4-routes refusals above:
            // nothing is established, the service stops, and the app never
            // reaches its connected state.
            //
            // That absent connected state is the user-visible signal, and it
            // is the same one every other fail-closed path on this platform
            // uses -- isServiceActive stays false, so isTunnelHealthy() stays
            // false, so the Dart readiness poll never promotes the UI. The log
            // line is for whoever reads it afterwards, not for the user.
            //
            // Deliberately NOT conditioned on whether the device has IPv6
            // right now. The sink address lives on the virtual interface and
            // does not depend on host IPv6, so a throw here does not mean
            // "this device has no IPv6" -- and a network handover can hand the
            // device IPv6 at any point after the check, so a start-time probe
            // could not stay true for the life of the session. Apple
            // hard-requires the same thing (WinsTunnelConfig.swift, error
            // 1203) and Linux backstops it with an ip6tables REJECT; this is
            // the platform that was the outlier.
            var ipv6SinkAddressApplied = false
            var ipv6SinkRouteApplied = false
            try {
                builder.addAddress(IPV6_FAIL_CLOSED_SINK, 128)
                ipv6SinkAddressApplied = true
            } catch (e: Exception) {
                logError("IPv6 fail-closed sink address was rejected by the platform.", e)
            }
            try {
                builder.addRoute("::", 0)
                ipv6SinkRouteApplied = true
            } catch (e: Exception) {
                logError("IPv6 fail-closed default route was rejected by the platform.", e)
            }
            if (!mayEstablishTunnel(ipv6SinkAddressApplied, ipv6SinkRouteApplied)) {
                logError(
                    "Refusing to establish: the IPv6 fail-closed sink is incomplete " +
                        "(address=$ipv6SinkAddressApplied route=$ipv6SinkRouteApplied), " +
                        "so host IPv6 would leave outside the tunnel."
                )
                clearRestartConfig()
                executeTunnelTeardown()
                return START_NOT_STICKY
            }
            debugLog("IPv6 sink route installed.")

            if (winnEnabled) {
                debugLog("App UID remains inside the VPN tunnel; the Winn outer UDP socket is individually protected.")
            } else {
                debugLog("App UID remains inside the VPN tunnel; the AmneziaWG socket is individually protected.")
            }
            speedTestMeasuresPhysicalRoute = false
            applyUserExcludedApplications(builder, appSection)
            applyUnderlyingNetworkHints(builder)

            val priorInterface = retainedKillSwitchInterface ?: vpnInterface
            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(VpnTunnelService.LOG_TAG, "Builder.establish() returned null")
                clearRestartConfig()
                executeTunnelTeardown()
                return START_NOT_STICKY
            }
            retainedKillSwitchInterface = null
            priorInterface?.close()

            isServiceActive = true
            isInterfaceOpen = true
            // Deliberately not revealing the real launcher icon here: this
            // path also runs on an unattended auto-reconnect/service restart
            // (see loadRestartConfig() above), which involves no PIN entry
            // in this process at all. Revealing it must only ever follow
            // genuine PIN verification (MainActivity's triggerCamouflageSwap
            // handler) -- never a tunnel-connect event, which the OS can
            // trigger on its own.
            registerNetworkHandoffCallback()
            refreshUnderlyingNetworkHint("tunnel established")
            val generation = nextTunnelGeneration()
            startTunnelHealthWatchdog(generation)
            val tunPfd = ParcelFileDescriptor.dup(vpnInterface!!.fileDescriptor)

            if (winnEnabled) {
                startWinnEngineThread(
                    winnSection, awgConfig, tunPfd, clientIp, dnsServer, mtu, generation,
                )
            } else {
                // detachFd() here reproduces the previous
                // `ParcelFileDescriptor.dup(...).detachFd()` exactly: the AWG
                // engine takes ownership of the raw descriptor.
                startAwgEngineThread(awgConfig, tunPfd.detachFd(), generation)
            }
        } catch (e: Exception) {
            logError("Failed to allocate interface or start tunnel", e)
            clearRestartConfig()
            executeTunnelTeardown()
            return START_NOT_STICKY
        }

        if (coverRequested) {
            WinnV3AwgXrayGrantStore.clear()
        }
        persistRestartConfig(config)
        persistRestartSelectedNode(callerSelectedNode)
        return START_STICKY
    }

    private fun persistRestartConfig(config: String) {
        try {
            secureFileStore.write("wins_vpn_restart_config.conf", config)
            val legacy = restartConfigFile()
            if (legacy.exists()) legacy.delete()
        } catch (e: Exception) {
            logWarning("Tunnel restart state could not be persisted", e)
        }
    }

    private fun persistRestartSelectedNode(node: String?) {
        try {
            if (node.isNullOrEmpty()) {
                secureFileStore.delete(RESTART_NODE_RECORD)
            } else {
                secureFileStore.write(RESTART_NODE_RECORD, node)
            }
        } catch (e: Exception) {
            logWarning("Tunnel restart node could not be persisted", e)
        }
    }

    private fun loadRestartSelectedNode(): String? = try {
        secureFileStore.read(RESTART_NODE_RECORD)
    } catch (e: Exception) {
        logWarning("Tunnel restart node could not be restored", e)
        null
    }

    /// Read the same durable setting Dart uses for the switch and dashboard.
    /// The separate route-intent copy can lag after a failed write and must not
    /// decide a system restart. Missing or unreadable settings are unknown.
    private fun readDoubleVpnIntent(): DoubleVpnIntent =
        try {
            val legacy = File(File(applicationInfo.dataDir, "app_flutter"), "vpn_settings.txt")
            val stored = secureFileStore.read("vpn_settings.txt", legacy)
            if (stored == null) {
                DoubleVpnIntent.UNKNOWN
            } else {
                doubleVpnIntentFromChoice(JSONObject(stored).opt("double_vpn_requested"))
            }
        } catch (e: Exception) {
            logWarning("Double VPN choice could not be read", e)
            DoubleVpnIntent.UNKNOWN
        }

    private fun loadRestartConfig(): String {
        return try {
            secureFileStore.read(
                "wins_vpn_restart_config.conf",
                restartConfigFile(),
            ).orEmpty()
        } catch (e: Exception) {
            logWarning("Tunnel restart state could not be restored", e)
            ""
        }
    }

    private fun clearRestartConfig() {
        try {
            secureFileStore.delete(RESTART_NODE_RECORD)
            secureFileStore.delete(
                "wins_vpn_restart_config.conf",
                restartConfigFile(),
            )
            secureFileStore.delete(DOUBLE_VPN_INTENT_RECORD)
        } catch (e: Exception) {
            logWarning("Tunnel restart state cleanup failed", e)
        }
    }

    private fun restartConfigFile(): File {
        return File(filesDir, "wins_vpn_restart_config.conf")
    }

    private fun resetTunnelBeforeConnect() {
        try {
            invalidateTunnelGeneration()
            stopTunnelHealthWatchdog()
            stopXrayTransport()
            unregisterNetworkHandoffCallback()
            try {
                stopWinnBridge()
            } catch (e: Exception) {
                logWarning("Previous Winn engine stop was incomplete", e)
            }
            try {
                stopAwgEngine()
            } catch (e: Exception) {
                logWarning("Previous engine stop was incomplete", e)
            }
            if (vpnInterface != null) {
                retainedKillSwitchInterface?.close()
                retainedKillSwitchInterface = vpnInterface
                vpnInterface = null
            }
        } catch (e: Exception) {
            logWarning("Previous tunnel reset was incomplete", e)
        } finally {
            handoffHandler.removeCallbacksAndMessages(null)
            handoffRefreshToken += 1
            isServiceActive = false
            isEngineReady = false
            isInterfaceOpen = retainedKillSwitchInterface != null
            engineReadyAtMs = 0L
            lastUnderlyingNetwork = null
            lastUnderlyingTransport = "unknown"
            speedTestMeasuresPhysicalRoute = false
            holdingBlockPosture = false
            // A new connect supersedes a held Winn v3 block, its custody and
            // anything queued for it: the notification and the app must
            // describe the new tunnel, not the old one's end.
            winn3HostLifecycle.supersede()
            // The held interface, if any, is now this connect's handover
            // block: the hold ended without being released.
            winn3ReleaseLedger.passCompleted(WinnV3ReleaseLedger.Disposition.SUPERSEDED)
            winn3CleanupDebt.clear()
            synchronized(winnEngineLock) {
                winnV3Custody.clear()
                winnV3LifecycleBinding = null
                winnV3TeardownWorker.forceIdleLocked()
                tearingDown = false
            }
        }
    }

    private fun refuseWinn3Start(
        winn3Requested: Boolean,
        startToken: Long,
        startGeneration: Long,
    ) {
        if (!winn3Requested) return
        publishWinn3Verdict(startToken, startGeneration, WinnV3NativeVerdict.TERMINAL_SECURITY)
    }

    private fun completeWinn3Start(
        startToken: Long,
        startGeneration: Long,
        verdict: WinnV3NativeVerdict,
    ) {
        publishWinn3Verdict(startToken, startGeneration, verdict)
    }

    private fun publishWinn3Verdict(
        startToken: Long,
        startGeneration: Long,
        verdict: WinnV3NativeVerdict,
    ) {
        synchronized(winn3VerdictStateLock) {
            val published = WinnV3NativeVerdictPublisher.apply(
                currentToken = lastWinn3ReadinessSnapshot.startToken,
                currentGeneration = lastWinn3ReadinessSnapshot.startGeneration,
                startToken = startToken,
                startGeneration = startGeneration,
                verdict = verdict,
            ) ?: return
            lastWinn3StartSecurityRefusal = published.securityRefusal
            lastWinn3StartState = published.state
            lastWinn3AwgXrayAuthorizationToken = published.awgXrayAuthorizationToken
            lastWinn3ReadinessSnapshot = WinnV3NativeReadinessSnapshot(
                published.startToken,
                published.startGeneration,
                published.state,
                published.securityRefusal,
                published.awgXrayAuthorizationToken,
                lastWinn3ReadinessSnapshot.selectionGeneration,
                lastWinn3ReadinessSnapshot.failedNode,
            )
            if (published.verdict == WinnV3NativeVerdict.ORDINARY_CONNECTIVITY) {
                WinnV3AwgXrayGrantStore.arm(
                    startToken = published.startToken,
                    startGeneration = published.startGeneration,
                    selectionGeneration = lastWinn3ReadinessSnapshot.selectionGeneration,
                    failedV3Node = lastWinn3ReadinessSnapshot.failedNode,
                    nowMs = android.os.SystemClock.elapsedRealtime(),
                )
            } else {
                WinnV3AwgXrayGrantStore.clear()
            }
        }
    }

    private fun startXrayTransportIfNeeded(config: String) {
        val section = parseConfigSection(config, "xray")
        val enabled = parseBool(section["enabled"])
        if (!enabled) {
            stopXrayTransport()
            return
        }

        val uuid = section["uuid"].orEmpty()
        val host = section["host"].orEmpty()
        val port = section["port"]?.toIntOrNull() ?: 443
        val serverName = section["servername"]?.ifBlank { host } ?: host
        val path = section["path"]?.ifBlank { "/wins-stealth-tunnel" } ?: "/wins-stealth-tunnel"
        // tls only (ruling 4, 2026-10-04): a security=none leg puts the VLESS
        // UUID and a fixed WebSocket upgrade on the wire.
        val security = section["security"]?.lowercase()?.ifBlank { "tls" } ?: "tls"
        val localPort = 42110
        val remoteAwgHost = "127.0.0.1"
        val remoteAwgPort = section["remoteawgport"]?.toIntOrNull() ?: 9110

        require(uuid.matches(Regex("^[0-9a-fA-F-]{36}$"))) { "Fallback UUID is invalid" }
        require(host.matches(Regex("^[A-Za-z0-9.-]{1,253}$"))) { "Fallback host is invalid" }
        require(serverName.matches(Regex("^[A-Za-z0-9.-]{1,253}$"))) { "Fallback server name is invalid" }
        require(port in 1..65535) { "Fallback port is invalid" }
        require(remoteAwgPort in 1..65535) { "Fallback destination port is invalid" }
        require(path.startsWith('/') && path.length <= 256 && !path.contains(Regex("[\\r\\n]"))) {
            "Fallback path is invalid"
        }
        require(security == "tls") { "Fallback security mode must be tls" }

        // IP-PINNED BOOTSTRAP (2026-08-07). `host` may now be an IPv4 literal.
        // The blocker recorded against this in
        // docs/handoff/NETWORK_OBSERVABLE_DNS_SNI_AUDIT_20260806.md §6.7 was
        // that TLS transports need a DNS name for the certificate. They do --
        // but that binds the SNI, not the address. Measured on the pinned
        // engine (see the DNS egress remediation handoff): a literal
        // vnext.address alongside a hostname serverName produces an empty
        // capture. So a literal is allowed here, and the only thing that must
        // still be a name is `servername`.
        if (security == "tls" && isIpv4Literal(host)) {
            require(!isIpv4Literal(serverName)) {
                "Fallback host is an IP literal but no TLS server name was supplied; " +
                    "a certificate cannot be verified against an address"
            }
        }

        debugLog("Outer Xray transport is using security=tls.")

        stopXrayTransport()

        // DNS EGRESS (2026-08-07). Xray is handed IPv4 literals, never a name.
        //
        // Handing the subprocess a hostname made it resolve the carrier itself
        // through Go's `localdns` -> bionic getaddrinfo -> netd. Measured on
        // the pinned engine build on the lab host, that is 104 plaintext
        // UDP/53 packets naming the carrier in about ten seconds -- 52 A and
        // 52 AAAA, because sockopt.domainStrategy=UseIPv4 filters the *result*
        // and does not constrain the *query* -- and it repeats for as long as
        // the dial keeps failing. Worse, that process is the one
        // addDisallowedApplication() below excludes from the tunnel for the
        // whole session, and a ProcessBuilder child has no reachable
        // protect(), so none of it was ever coverable.
        //
        // Resolving here instead is what Linux has always done
        // (linux_tunnel_backend.cc ResolvePublicIpv4Addresses). It does NOT
        // remove the query from the wire -- see resolveTransportIpv4Addresses
        // for exactly what remains -- but it turns an unbounded retry loop
        // inside a vendored binary into one bounded, A-only, auditable call,
        // and it removes the Xray-side query entirely (measured: 0).
        //
        // Fails closed, like the Linux path: no public IPv4, no transport.
        val transportIpv4s = resolveTransportIpv4Addresses(this, host)
        require(transportIpv4s.isNotEmpty()) {
            "Fallback host did not resolve to a public IPv4 address"
        }

        val xray = resolveXrayExecutable()
        val conf = writeXrayClientConfig(
            uuid = uuid,
            transportIpv4s = transportIpv4s,
            port = port,
            serverName = serverName,
            path = path,
            security = security,
            localPort = localPort,
            remoteAwgHost = remoteAwgHost,
            remoteAwgPort = remoteAwgPort,
        )

        var xrayStarted = false
        try {
            debugLog("Starting fallback transport on port $port with $security security.")
            xrayProcess = ProcessBuilder(xray.absolutePath, "run", "-c", conf.absolutePath)
                .redirectErrorStream(true)
                .start()

            val processForLog = xrayProcess
            Thread {
                try {
                    processForLog?.inputStream?.bufferedReader()?.useLines { lines ->
                        lines.forEach { line ->
                            if (BuildConfig.DEBUG) Log.d(VpnTunnelService.LOG_TAG, line.take(500))
                        }
                    }
                } catch (_: Exception) {}
            }.start()

            Thread.sleep(900)
            if (!isProcessAlive(xrayProcess)) {
                throw IOException("Xray process exited during startup. Check generated client config and native binary ABI.")
            }
            fallbackTransportRequired = true
            xrayStarted = true
        } finally {
            // The temp file carries the client UUID; remove it the moment Xray has
            // read it (success) or the moment startup is abandoned (failure) so a
            // forced start failure never leaves config residue behind on disk.
            conf.delete()
            if (!xrayStarted) {
                fallbackTransportRequired = false
            }
        }
    }

    private fun writeXrayClientConfig(
        uuid: String,
        transportIpv4s: List<String>,
        port: Int,
        serverName: String,
        path: String,
        security: String,
        localPort: Int,
        remoteAwgHost: String,
        remoteAwgPort: Int,
    ): File {
        // Xray 26.9.30 exposes the renamed `tunnel` protocol and still accepts
        // the legacy network/address/port settings (infra/conf/dokodemo.go
        // maps them onto the newer field names). Keep this one spelling: the
        // deployment validator rejects the newer names so a build against an
        // older core cannot fall back to TCP silently.
        val inboundSettings = JSONObject()
            .put("network", "udp")
            .put("address", remoteAwgHost)
            .put("port", remoteAwgPort)
            .put("followRedirect", false)
            .put("userLevel", 0)

        val inboundStreamSettings = JSONObject()
            .put(
                "sockopt",
                JSONObject()
                    .put("domainStrategy", "UseIPv4")
                    .put("tcpNoDelay", true)
            )

        val inbound = JSONObject()
            .put("tag", "awg-local-in")
            .put("listen", "127.0.0.1")
            .put("port", localPort)
            .put("protocol", "tunnel")
            .put("settings", inboundSettings)
            .put("streamSettings", inboundStreamSettings)

        // One VLESS outbound per prevalidated IPv4 edge, selected by a
        // roundRobin balancer -- the shape Linux already ships. It is not a
        // stylistic choice: upstream at the pinned commit rejects a multi-entry
        // `vnext` outright ("Multiple endpoints in \"vnext\" should use
        // multiple VLESS outbounds and routing balancer instead",
        // infra/conf/vless.go), so a balancer is the only way to keep the
        // address rotation the hostname path used to get for free from the
        // resolver -- without asking Xray to resolve anything.
        val outbounds = JSONArray()
        for ((index, edgeAddress) in transportIpv4s.withIndex()) {
            val user = JSONObject()
                .put("id", uuid)
                .put("encryption", "none")
                .put("level", 0)

            val vnext = JSONObject()
                .put("address", edgeAddress)
                .put("port", port)
                .put("users", JSONArray().put(user))

            val wsSettings = JSONObject()
                .put("path", path)
                .put("headers", JSONObject().put("Host", serverName))

            val streamSettings = JSONObject()
                .put("network", "ws")
                .put("security", security)
                .put("wsSettings", wsSettings)
                .put("sockopt", JSONObject()
                    // Retained, but not as a DNS control: it is measured NOT to
                    // keep the outer lookup on IPv4 (it filters the result of a
                    // both-families query). With a literal address there is no
                    // lookup left for it to affect; it stays because it is also
                    // what selects the IPv4 socket family for the dial itself.
                    .put("domainStrategy", "UseIPv4")
                    .put("tcpFastOpen", true)
                    .put("tcpNoDelay", true)
                    .put("tcpCongestion", "bbr")
                    .put("tcpKeepAliveIdle", 30)
                    .put("tcpKeepAliveInterval", 15)
                    .put("tcpUserTimeout", 15000)
                    .put("tcpMptcp", false)
                )

            if (security == "tls") {
                // The SNI and the WebSocket Host header stay the carrier's DNS
                // name even though the address above is a literal. That is the
                // whole point: the certificate is issued for the name, and the
                // name is never asked of a resolver by this process.
                streamSettings.put(
                    "tlsSettings",
                    JSONObject()
                        .put("serverName", serverName)
                        .put("allowInsecure", false)
                )
            }

            val edgeTag = "vless-ws-edge-$index"
            outbounds.put(
                JSONObject()
                    .put("tag", edgeTag)
                    .put("protocol", "vless")
                    .put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
                    .put("streamSettings", streamSettings)
                    .put("mux", JSONObject()
                        .put("enabled", false)
                        .put("concurrency", 0)
                        .put("xudpConcurrency", 0)
                        .put("xudpProxyUDP443", "skip")
                    )
            )
        }

        val routingRule = JSONObject()
            .put("type", "field")
            .put("inboundTag", JSONArray().put("awg-local-in"))
            .put("balancerTag", "vless-ws-balancer")

        val balancer = JSONObject()
            .put("tag", "vless-ws-balancer")
            .put("selector", JSONArray().put("vless-ws-edge-"))
            .put("strategy", JSONObject().put("type", "roundRobin"))

        // THROUGHPUT (2026-09-17): this policy block exists because Xray's own
        // default is hostile to this build. features/policy/policy.go
        // readDefaultBufferSize switches on runtime.GOARCH and returns
        // 4 * 1024 for "arm64" as a "4k cache for low-end devices" concession,
        // against 512 * 1024 on a desktop arch. tools/build_xray_engine.sh
        // builds the shipped engine with GOARCH=arm64 (target android-arm64),
        // and this function previously emitted no policy block and the child
        // process gets no XRAY_RAY_BUFFER_SIZE, so every Android Xray session
        // ran on a 4096-BYTE per-connection pipe buffer. That is the ceiling on
        // a long-fat path: the pipe drains a bandwidth-delay product at a time.
        //
        // Mind the unit. infra/conf/policy.go multiplies the configured value
        // by 1024, so bufferSize 4096 means 4 MB per connection, not 4 KiB.
        // 0 would ask for -1 (unlimited), which is not a thing to hand a
        // handset; 4 MB is a bounded thousandfold improvement over the arm64
        // default. The system stats counters are switched off because nothing
        // in this app reads them and they cost an atomic add per packet.
        val policy = JSONObject()
            .put(
                "levels",
                JSONObject().put(
                    "0",
                    JSONObject()
                        .put("handshake", 4)
                        .put("connIdle", 300)
                        .put("uplinkOnly", 2)
                        .put("downlinkOnly", 5)
                        .put("bufferSize", 4096)
                )
            )
            .put(
                "system",
                JSONObject()
                    .put("statsInboundUplink", false)
                    .put("statsInboundDownlink", false)
                    .put("statsOutboundUplink", false)
                    .put("statsOutboundDownlink", false)
            )

        val root = JSONObject()
            .put(
                "log",
                JSONObject().put("loglevel", if (BuildConfig.DEBUG) "debug" else "warning")
            )
            .put("policy", policy)
            .put("inbounds", JSONArray().put(inbound))
            .put("outbounds", outbounds)
            .put(
                "routing",
                JSONObject()
                    .put("rules", JSONArray().put(routingRule))
                    .put("balancers", JSONArray().put(balancer))
            )

        val file = File(filesDir, XRAY_CONFIG_FILE)
        file.writeText(root.toString())
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setReadable(true, true)
        file.setWritable(true, true)
        return file
    }

    private fun resolveXrayExecutable(): File {
        // Only the APK-packaged native library path is trusted: it is extracted by
        // the OS package installer from a signed, release-verified APK. There is no
        // app-writable fallback here on purpose -- APK signing/release verification
        // is the trust boundary, not a runtime self-hash next to replaceable code.
        val nativeLib = File(applicationInfo.nativeLibraryDir, "libxray.so")
        if (nativeLib.isFile) {
            nativeLib.setExecutable(true, true)
        }
        if (!nativeLib.isFile || !nativeLib.canExecute()) {
            throw IOException(
                "Missing Xray native binary. Run tools/prepare_android_xray_assets.sh before building the APK. " +
                    "Expected libxray.so under android/app/src/main/jniLibs/<abi>/; device ABIs=${Build.SUPPORTED_ABIS.joinToString()}"
            )
        }
        return nativeLib
    }

    private fun stopXrayTransport() {
        val process = xrayProcess
        try {
            if (process != null && isProcessAlive(process)) {
                process.destroy()
                if (!waitForProcessExit(process, 1_500L) &&
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ) {
                    process.destroyForcibly()
                    waitForProcessExit(process, 2_000L)
                }
                if (isProcessAlive(process)) {
                    logError("Fallback transport remained alive after disconnect")
                }
            }
        } catch (e: Exception) {
            logWarning("Fallback transport stop was incomplete", e)
        } finally {
            xrayProcess = null
            fallbackTransportRequired = false
            File(filesDir, XRAY_CONFIG_FILE).delete()
        }
    }

    /**
     * Reconcile the tunnel channel, then post the foreground notification.
     *
     * Returns **false** when the channel could not be given the decoy's name
     * while the disguise is in force, in which case nothing has been posted and
     * the caller must not let the tunnel run: a foreground service notification
     * that cannot be posted safely should not be posted. See
     * [settleTunnelChannel] for the ladder and why it ends in a refusal.
     *
     * The channel is settled BEFORE the notification is built, because the
     * builder binds to the channel id and a notification posted onto a row
     * still carrying the real name is the leak itself.
     *
     * The notification's own CONTENT continues to follow the live decoy state
     * rather than the latched predicate, and that difference is deliberate: the
     * notification exists only while the tunnel does, is rebuilt by
     * [refreshForegroundNotificationForCamouflage] on every icon swap, and is
     * therefore free to tell an un-camouflaged user the truth. The channel row
     * is not free to, because it outlives all of that.
     */
    private fun startAsForegroundService(): Boolean {
        if (!createNotificationChannel()) return false
        val state = currentTunnelForegroundState()
        lastPostedForegroundState = state
        val notification = buildForegroundNotification(state)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                TUNNEL_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(TUNNEL_NOTIFICATION_ID, notification)
        }
        return true
    }

    /// The state the notification should describe right now, from the same
    /// carrying composite the Dart dashboard and the health check use, so the
    /// notification can never claim more than the tunnel has proven.
    private fun currentTunnelForegroundState(): TunnelForegroundState =
        tunnelForegroundFor(
            isServiceActive,
            isEngineReady,
            isInterfaceOpen,
            winn3HostLifecycle.snapshot().state,
        )

    /// Rebuilds the foreground notification for [state] without touching the
    /// service's foreground status, so it can be re-posted on state change.
    ///
    /// `.setOnlyAlertOnce(true)` and ongoing-without-alert semantics: a status
    /// change re-paints the existing row; it must not re-alert and must not
    /// chime, which is what keeps the update path quiet in Doze.
    private fun buildForegroundNotification(state: TunnelForegroundState): Notification {
        val disguised = isDecoyLauncherActive()
        val largeIcon = BitmapFactory.decodeResource(
            resources,
            if (disguised) R.mipmap.ic_calculator_fg else R.drawable.ic_launcher_foreground
        )
        val smallIconRes = if (disguised) R.drawable.ic_stat_calculator else R.drawable.ic_stat_wins_vpn
        val title = tunnelForegroundTitleFor(disguised, state)
        val text = tunnelForegroundTextFor(disguised, state, doubleVpnSingleHop)
        val openIntent = packageManager.getLaunchIntentForPackage(packageName)
            ?: Intent(this, MainActivity::class.java)
        val openPendingIntent = PendingIntent.getActivity(
            this,
            TUNNEL_NOTIFICATION_ID,
            openIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnectIntent = Intent(this, VpnTunnelService::class.java).apply {
            action = "ACTION_DISCONNECT"
            putExtra("KEEP_VPN_LAUNCHER", true)
            putExtra("RELEASE_KILL_SWITCH_BLOCK", true)
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this,
            TUNNEL_NOTIFICATION_ID + 1,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        // A "Disconnect" action would be its own giveaway on a notification
        // meant to look like it belongs to a calculator, so it is only
        // offered when the real identity is already showing.
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, TUNNEL_CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(smallIconRes)
                .setLargeIcon(largeIcon)
                .setContentIntent(openPendingIntent)
                .setOnlyAlertOnce(true)
                .apply {
                    if (!disguised) {
                        addAction(Notification.Action.Builder(null, "Disconnect", disconnectPendingIntent).build())
                    }
                }
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(smallIconRes)
                .setLargeIcon(largeIcon)
                .setContentIntent(openPendingIntent)
                .setOnlyAlertOnce(true)
                .apply {
                    if (!disguised) {
                        addAction(Notification.Action.Builder(null, "Disconnect", disconnectPendingIntent).build())
                    }
                }
                .setOngoing(true)
                .build()
        }
    }

    /// Re-posts the foreground notification describing the state the tunnel has
    /// moved to, leaving the service's foreground status untouched.
    ///
    /// Deduplicated so a busy watchdog never churns the row: a status update is
    /// not a notification event, and re-posting identical content every ten
    /// seconds would wake/invalidate the shade for nothing. `notify` (rather
    /// than a second `startForeground`) is legal from a foreground service in
    /// Doze and keeps the update a silent in-place re-paint.
    private fun refreshForegroundStatusNotification(state: TunnelForegroundState) {
        if (tearingDown) return
        if (lastPostedForegroundState == state) return
        lastPostedForegroundState = state
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(TUNNEL_NOTIFICATION_ID, buildForegroundNotification(state))
        } catch (e: Exception) {
            logWarning("Foreground status notification update was skipped", e)
        }
    }

    /**
     * The service's own entry point into the tunnel channel, kept under its
     * historical name and given the same shape as [vpnSessionName]: read both
     * camouflage signals here, at the boundary, and hand them to the policy.
     *
     * What changed is which of the two decides the name. This used to build a
     * channel named from `isDecoyLauncherActive()` **alone**, and that is the
     * defect: the live decoy state is guaranteed to be DOWN at the instant this
     * runs, because the user has just unlocked with their PIN to press Connect.
     * The live signal is still one of the two inputs -- an armed decoy still
     * forces the disguise even if the enrollment write failed -- but it is no
     * longer the only one.
     *
     * Returns false when the channel could not be made safe; see
     * [settleTunnelChannel].
     */
    private fun createNotificationChannel(): Boolean {
        return settleTunnelChannel(
            context = this,
            camouflageEnrolled = isCamouflageEnrolled(this),
            decoyActive = isDecoyLauncherActive(),
            createIfAbsent = true,
        )
    }

    private fun executeTunnelTeardown(
        keepVpnLauncher: Boolean = false,
        allowBlockPosture: Boolean = true,
        // Round A3: why. Every caller that is neither the owner nor the OS is
        // AUTOMATIC, and an automatic end of a promoted Winn v3 session keeps
        // its capture whatever the kill switch says. See WinnV3CaptureCustody.
        cause: WinnV3TeardownCause = WinnV3TeardownCause.AUTOMATIC,
    ) {
        // A request that arrives while a teardown is in flight is QUEUED (an
        // owner disconnect, a revocation) and runs as a follow-up pass on the
        // worker already in flight; see WinnV3TeardownWorker for why none is
        // lost at the worker's retirement.
        val firstPass = winnV3TeardownWorker.submit(
            cause = cause,
            keepVpnLauncher = keepVpnLauncher,
            allowBlockPosture = allowBlockPosture,
        ) ?: return
        // The ingest gate is only valid while its session lives.
        latchedInnerRouterV4 = null
        // One teardown pass for `plan`, on the teardown thread. Returns whether
        // it left an interface held (kill switch or Winn v3 capture), which is
        // what a queued owner or OS request would still have to release.
        fun runTeardownPass(plan: WinnV3CaptureCustody.Plan): Boolean {
            // Round L: every engine stop and interface close this pass needs
            // goes through `release`, so its acknowledgement rests on what was
            // confirmed, not on which fields ended up null. Built FIRST: it
            // opens this pass in the cleanup debt, and only its disposition()
            // closes it, so any exceptional exit from here on (the finally
            // below included) leaves the pass unresolved.
            val release = WinnV3ReleaseTeardown(
                stopFallbackTransport = {
                    val fallback = xrayProcess
                    stopXrayTransport()
                    fallback == null || !isProcessAlive(fallback)
                },
                stopWinnEngines = { stopWinnBridge() },
                stopVpnEngine = { stopAwgEngine() },
                engineRetired = {
                    winnV3EngineRetirement?.awaitCompleted(
                        WinnV3ReleaseTeardown.ENGINE_RETIREMENT_WAIT_MS,
                    ) ?: true
                },
                debt = winn3CleanupDebt,
                warn = { message, e -> logWarning(message, e) },
            )
            val hadActiveSession = isServiceActive || vpnInterface != null
            synchronized(winnEngineLock) { winnV3LifecycleBinding = null }
            // A revocation or destruction releasing an ESTABLISHED Winn v3
            // hold (a follow-up after the hold was built, or a later request
            // against a steady hold) is a release notice, published BEFORE
            // anything is cleared so the clear below keeps it. The owner's
            // Disconnect is an acknowledged release and publishes nothing.
            winnV3Custody.releaseLimitationFor(plan.cause)?.let { limitation ->
                winn3HostLifecycle.releaseHeldCapture(limitation)
            }
            // Only a hold describes anything afterwards; every other end of a
            // session leaves no lifecycle behind (a release notice is kept).
            if (!plan.holdCapture) winn3HostLifecycle.clear()
            // THE KILL SWITCH DECISION, taken here at teardown time from LIVE
            // OS state rather than from a value cached at connect time: always-on
            // can be dropped by OEM firmware or toggled in Settings while a
            // tunnel is up, and the one state that must never be held is a stale
            // claim that the OS is blocking for us. See KillSwitchPolicy.
            val handoverBlockRequired = doubleVpnHandoverToken.getAndSet(0L) > 0L
            var holdBlockPosture = plan.allowBlockPosture && (handoverBlockRequired || plan.holdCapture ||
                KillSwitchPolicy.mustHoldBlockingInterface(
                    killSwitchArmed = isKillSwitchArmed(),
                    apiLevel = Build.VERSION.SDK_INT,
                    alwaysOnPackage = androidKillSwitch.effectiveAlwaysOnPackage(),
                    lockdownEnabled = androidKillSwitch.effectiveLockdownEnabled(),
                    ourPackage = packageName,
                ))
            var blockPostureEstablished = false
            var outrankedBy: String? = null
            var holdLimitation: String? = null
            try {
                stopTunnelHealthWatchdog()
                release.stopFallback()
                unregisterNetworkHandoffCallback()
                release.stopEngines()
                // A revocation (or process destruction) that arrived while the
                // engines were stopping beats the hold this pass is building.
                if (holdBlockPosture && !winnV3Custody.blockPostureStillAllowed(plan)) {
                    debugLog("Teardown: a queued revocation outranks the hold; releasing.")
                    holdBlockPosture = false
                    outrankedBy = winnV3Custody.outrankingLimitation()
                        ?: WinnV3CaptureCustody.LIMITATION_SERVICE_DESTROYED
                }
                if (holdBlockPosture) {
                    val current = vpnInterface
                    var retained = retainedKillSwitchInterface

                    if (current != null && retained != null && current !== retained) {
                        if (!release.close(
                                "Retained interface close before blocking replacement",
                                retained,
                            )
                        ) {
                            holdLimitation =
                                WinnV3CaptureCustody.LIMITATION_NO_BLOCKING_INTERFACE
                            throw IOException(
                                "Cannot replace capture while retained interface cleanup is incomplete"
                            )
                        }
                        if (narrowBootstrapInterface === retained) {
                            narrowBootstrapInterface = null
                        }
                        retainedKillSwitchInterface = null
                        retained = null
                    }

                    val prior = current ?: retained
                    val block = androidKillSwitch.establishBlockingInterface()
                    if (block != null) {
                        vpnInterface = block
                        blockPostureEstablished = true
                        if (release.close(
                                "Prior capture interface close under a blocking hold",
                                prior,
                            )
                        ) {
                            retainedKillSwitchInterface = null
                            narrowBootstrapInterface = null
                        } else {
                            retainedKillSwitchInterface = prior
                        }
                    } else {
                        logError("A blocking interface could not be established")
                        if (handoverBlockRequired && prior != null &&
                            prior !== narrowBootstrapInterface
                        ) {
                            // The previous full-route TUN still captures traffic.
                            vpnInterface = prior
                            retainedKillSwitchInterface = null
                            blockPostureEstablished = true
                        }
                        holdLimitation =
                            WinnV3CaptureCustody.LIMITATION_NO_BLOCKING_INTERFACE
                        if (prior != null &&
                            prior === narrowBootstrapInterface &&
                            release.close("Narrow interface close after a refused hold", prior)
                        ) {
                            if (vpnInterface === prior) {
                                vpnInterface = null
                            }
                            if (retainedKillSwitchInterface === prior) {
                                retainedKillSwitchInterface = null
                            }
                            narrowBootstrapInterface = null
                        }
                    }
                } else {
                    // A close that throws leaves its field set: the descriptor's
                    // state is unknown, and the pass is not a release.
                    if (release.close("Retained interface close", retainedKillSwitchInterface)) {
                        retainedKillSwitchInterface = null
                    }
                    if (release.close("Capture interface close", vpnInterface)) {
                        vpnInterface = null
                    }
                }
            } catch (e: IOException) {
                release.evidence.fail("teardown pass: IOException")
                logError("VPN teardown encountered an I/O error", e)
            } catch (e: Exception) {
                release.evidence.fail("teardown pass: ${e.javaClass.simpleName}")
                logError("VPN teardown encountered an error", e)
            } finally {
                isServiceActive = false
                isEngineReady = false
                if (!blockPostureEstablished) isInterfaceOpen = false
                engineReadyAtMs = 0L
                tunnelStartUidRx = -1L
                tunnelStartUidTx = -1L
                winnLastTxPayloadDatagrams = -1L
                winnLastRxPayloadDatagrams = -1L
                handoffHandler.removeCallbacksAndMessages(null)
                handoffRefreshToken += 1
                lastUnderlyingNetwork = null
                lastUnderlyingTransport = "unknown"
                speedTestMeasuresPhysicalRoute = false
                // A fresh connect must re-post even if it reaches the same state
                // the old tunnel ended in; null the dedupe latch at teardown.
                lastPostedForegroundState = null
                doubleVpnSingleHop = false
                releaseTunnelPerformanceLocks()
                if (blockPostureEstablished) {
                    // Stay alive AND foreground: Android keeps the tun open only
                    // as long as its owning service process lives, so the block
                    // posture is a foreground service with the existing (decoy-safe)
                    // notification. If the notification cannot be posted safely,
                    // close rather than leak with no way to hold the process.
                    holdingBlockPosture = true
                    // A Winn v3 capture hold is not silently turned into a
                    // release: the outcome and any limitation are published
                    // (WinnV3CaptureCustody.holdOutcome). The kill-switch hold
                    // keeps its existing rule.
                    val keepHold = if (plan.holdCapture) {
                        // Describe the hold before posting its notification,
                        // so the notification says blocked, not connecting.
                        winn3HostLifecycle.holdCapture(held = true, limitation = null)
                        val outcome = WinnV3CaptureCustody.holdOutcome(postHoldForegroundNotification())
                        holdLimitation = outcome.limitation
                        outcome.limitation?.let {
                            logError("Winn v3 capture hold: $it (capture kept: ${outcome.keepCapture})")
                        }
                        outcome.keepCapture
                    } else {
                        startAsForegroundService()
                    }
                    if (!keepHold) {
                        logError(
                            "Kill switch: blocking interface up but the foreground " +
                                "notification could not be posted; closing instead of leaking.",
                        )
                        holdingBlockPosture = false
                        // Round L: recorded, never swallowed. The field is still
                        // dropped as before (nothing may reuse it), but a close
                        // that threw leaves the pass unconfirmed: clearing a
                        // descriptor field does not establish that it closed.
                        release.close("Capture interface close after a refused hold", vpnInterface)
                        vpnInterface = null
                        isInterfaceOpen = false
                        if (hadActiveSession && !plan.keepVpnLauncher) {
                            setLauncherComponentState(false)
                        }
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                    if (plan.holdCapture) {
                        winn3HostLifecycle.holdCapture(held = keepHold, limitation = holdLimitation)
                    }
                } else {
                    if (plan.holdCapture) {
                        // Capture a promoted session was owed is released:
                        // say so, and why (a revocation or destruction that
                        // outranked it, or no interface to hold).
                        winn3HostLifecycle.holdCapture(
                            held = false,
                            limitation = outrankedBy ?: holdLimitation
                                ?: WinnV3CaptureCustody.LIMITATION_NO_BLOCKING_INTERFACE,
                        )
                    }
                    if (hadActiveSession && !plan.keepVpnLauncher) setLauncherComponentState(false)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            // Round L: this pass's release acknowledgement, published only now,
            // after the finally above has left the interfaces in their final
            // state for this pass. The lifecycle board was cleared at the START
            // of the pass, so it cannot say this; see WinnV3ReleaseLedger.
            winn3ReleaseLedger.passCompleted(
                release.disposition(
                    winn3HoldKept = plan.holdCapture && blockPostureEstablished && holdingBlockPosture,
                    blockKept = blockPostureEstablished && holdingBlockPosture,
                    interfacesClosed = vpnInterface == null && retainedKillSwitchInterface == null,
                ),
            )
            return blockPostureEstablished && holdingBlockPosture
        }

        Thread {
            winnV3TeardownWorker.drain(
                first = firstPass,
                runPass = { plan ->
                    if (plan !== firstPass) debugLog("Teardown: running the queued ${plan.cause} request.")
                    runTeardownPass(plan)
                },
                onPassError = { e -> logError("VPN teardown pass failed", e) },
            )
        }.apply {
            name = "Calc-Tunnel-Teardown"
            isDaemon = false
            activeTeardownThread = this
            start()
        }
    }

    /** Posts the capture hold's foreground notification, classifying a failure. */
    private fun postHoldForegroundNotification(): WinnV3CaptureCustody.NotificationResult =
        try {
            if (startAsForegroundService()) {
                WinnV3CaptureCustody.NotificationResult.POSTED
            } else {
                WinnV3CaptureCustody.NotificationResult.DISGUISE_REFUSED
            }
        } catch (e: Exception) {
            logError("Winn v3 capture hold: the foreground notification threw", e)
            WinnV3CaptureCustody.NotificationResult.PLATFORM_FAILED
        }

    // ---- Kill switch state and helpers ------------------------------------
    //
    // The armed flag is persisted in SecureFileStore like the restart config,
    // so an OOM or force-stop does not forget it. `androidKillSwitch` is
    // otherwise stateless: every read goes back to the framework.

    private fun isKillSwitchArmed(): Boolean {
        return try {
            val explicit = secureFileStore.read(KILL_SWITCH_STATE)
            if (explicit != null) {
                return explicit.trim().toBooleanStrictOrNull() ?: true
            }

            val legacy = File(
                File(applicationInfo.dataDir, "app_flutter"),
                "vpn_settings.txt",
            )
            val encoded = secureFileStore.read("vpn_settings.txt", legacy)
            encoded?.let {
                JSONObject(it).optBoolean("always_on_enabled", false)
            } ?: false
        } catch (_: Exception) {
            true
        }
    }

    private fun setKillSwitchArmed(armed: Boolean) {
        try {
            secureFileStore.write(KILL_SWITCH_STATE, armed.toString())
        } catch (e: Exception) {
            logWarning("Kill switch state could not be persisted", e)
        }
    }

    private fun logKillSwitchState(reason: String, armOutcome: AndroidKillSwitch.ArmOutcome?) {
        val state = androidKillSwitch.readBlockConnectionsState()
        val alwaysOn = androidKillSwitch.readAlwaysOnVpnPackage()
        val lockdown = androidKillSwitch.readLockdownEnabled()
        Log.i(
            VpnTunnelService.LOG_TAG,
            "Kill switch ($reason): armed=${isKillSwitchArmed()} state=$state " +
                "alwaysOn=$alwaysOn lockdown=$lockdown outcome=$armOutcome",
        )
    }

    /** Debug/driver path: hold a blocking interface with no carrier behind it. */
    private fun beginBlockPosture() {
        if (holdingBlockPosture) return
        try {
            if (!startAsForegroundService()) {
                logError(
                    "Kill switch: refusing to enter block posture because the " +
                        "foreground notification could not be made safe.",
                )
                return
            }
            val block = androidKillSwitch.establishBlockingInterface()
            if (block != null) {
                vpnInterface = block
                isInterfaceOpen = true
                holdingBlockPosture = true
                isServiceActive = false
                isEngineReady = false
                debugLog("Kill switch: blocking interface established (tunnel down, device blocked).")
            } else {
                logError("Kill switch: blocking interface could not be established.")
            }
        } catch (e: Exception) {
            logError("Kill switch: entering block posture failed", e)
        }
    }

    /** Debug/driver path: release the blocking interface and stop. */
    private fun endBlockPosture() {
        try {
            holdingBlockPosture = false
            vpnInterface?.close()
            vpnInterface = null
            isInterfaceOpen = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } catch (e: Exception) {
            logWarning("Kill switch: leaving block posture was incomplete", e)
        }
    }

    private fun waitForProcessExit(process: Process, timeoutMs: Long): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (isProcessAlive(process) && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(50L)
        }
        return !isProcessAlive(process)
    }

    private fun nextTunnelGeneration(): Int {
        synchronized(winnEngineLock) {
            tunnelGeneration += 1
            return tunnelGeneration
        }
    }

    private fun invalidateTunnelGeneration() {
        synchronized(winnEngineLock) {
            tunnelGeneration += 1
        }
    }

    private fun isProcessAlive(process: Process?): Boolean {
        if (process == null) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) return process.isAlive
        return try {
            process.exitValue()
            false
        } catch (_: IllegalThreadStateException) {
            true
        }
    }

    private fun startTunnelHealthWatchdog(generation: Int) {
        stopTunnelHealthWatchdog()
        stopHealthWatchdog = false
        healthWatchdogThread = Thread {
            var missingVpnSamples = 0
            var unhealthyEngineSamples = 0
            try {
                Thread.sleep(WATCHDOG_INITIAL_DELAY_MS)
                while (!stopHealthWatchdog && generation == tunnelGeneration && isServiceActive) {
                    val vpnPresent = vpnNetworkPresent()
                    val engineHealthy = currentEngineHandleHealthy() &&
                        (!fallbackTransportRequired || isProcessAlive(xrayProcess))
                    if (vpnPresent) {
                        missingVpnSamples = 0
                    } else {
                        missingVpnSamples += 1
                        Log.w(
                            VpnTunnelService.LOG_TAG,
                            "VPN network not visible to Android health check ($missingVpnSamples/$WATCHDOG_MISSING_VPN_LIMIT)."
                        )
                        refreshUnderlyingNetworkHint("VPN visibility gap")
                    }
                    // Re-assert the notification against the live composite each
                    // sample: if the engine stalls this flips a "Connected" claim
                    // back to "Connecting..." the moment the health check sees it,
                    // rather than leaving the shade claiming protection on a
                    // tunnel that is not carrying. Deduplicated inside, so a
                    // healthy loop re-posts nothing.
                    refreshForegroundStatusNotification(currentTunnelForegroundState())
                    unhealthyEngineSamples = if (engineHealthy) 0 else unhealthyEngineSamples + 1
                    // Debug builds only: one counts-only perf line per sample,
                    // so a measurement run can read where packets wait without
                    // a profiler. Release logcat never carries it. The status
                    // round trip (at most 1 s, debug only) puts a fresh engine
                    // census beside the pump census, and the line carries the
                    // document's age either way.
                    if (BuildConfig.DEBUG) {
                        try {
                            currentWinnV3Bridge()?.let { v3 ->
                                val status = v3.requestStatusAndAwait(1_000L)
                                Log.i(
                                    VpnTunnelService.LOG_TAG,
                                    WinnV3PerfLine.format(
                                        v3.pumpCensus(),
                                        status,
                                        v3.statusAgeMs(),
                                        System.nanoTime(),
                                    ),
                                )
                            }
                        } catch (e: InterruptedException) {
                            throw e
                        } catch (_: Exception) {
                            // Telemetry only: a failed perf line never stops
                            // the health watchdog.
                        }
                    }
                    if (unhealthyEngineSamples >= 3 && generation == tunnelGeneration && !tearingDown) {
                        logError("VPN engine health check failed repeatedly; closing stale tunnel")
                        isEngineReady = false
                        clearRestartConfig()
                        // AUTOMATIC: a promoted Winn v3 session keeps its
                        // capture (WinnV3CaptureCustody).
                        executeTunnelTeardown(keepVpnLauncher = true)
                        return@Thread
                    }
                    if (missingVpnSamples >= WATCHDOG_MISSING_VPN_LIMIT && generation == tunnelGeneration && !tearingDown) {
                        Log.e(
                            VpnTunnelService.LOG_TAG,
                            "VPN network stayed invisible while service notification was active; tearing down stale tunnel after extended grace period."
                        )
                        // AUTOMATIC, like the engine-health branch above: a
                        // promoted Winn v3 session keeps its capture.
                        executeTunnelTeardown(keepVpnLauncher = true)
                        return@Thread
                    }
                    Thread.sleep(WATCHDOG_INTERVAL_MS)
                }
            } catch (_: InterruptedException) {
            } catch (e: Exception) {
                logWarning("VPN health monitor stopped after a recoverable error", e)
            }
        }.apply {
            name = "Calc-Tunnel-Health"
            isDaemon = false
            start()
        }
    }

    private fun stopTunnelHealthWatchdog() {
        stopHealthWatchdog = true
        healthWatchdogThread = null
    }

    private fun vpnNetworkPresent(): Boolean {
        return try {
            val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            connectivity.allNetworks.any { network ->
                val caps = connectivity.getNetworkCapabilities(network) ?: return@any false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * The AmneziaWG engine run loop, lifted verbatim out of onStartCommand so
     * the Winn branch could be added beside it. Behaviour is unchanged.
     */
    private fun startAwgEngineThread(awgConfig: String, tunFd: Int, generation: Int) {
        Thread {
            setTunnelThreadPriority(android.os.Process.THREAD_PRIORITY_DISPLAY)
            var handle = -1
            try {
                debugLog("VPN engine entering run loop")
                handle = startAwgEngine(awgConfig, tunFd, generation)
                if (generation != tunnelGeneration || tearingDown) {
                    throw IOException("Tunnel start was superseded")
                }
                val readyPublished = synchronized(winnEngineLock) {
                    if (tearingDown ||
                        generation != tunnelGeneration ||
                        currentAwgHandle() != handle
                    ) {
                        false
                    } else {
                        isEngineReady = true
                        engineReadyAtMs = SystemClock.elapsedRealtime()
                        true
                    }
                }
                if (!readyPublished) throw IOException("Tunnel start was superseded")
                // The carrying composite just turned true; the notification may
                // now truthfully claim a connected tunnel.
                refreshForegroundStatusNotification(currentTunnelForegroundState())
                debugLog("VPN engine accepted the current configuration.")
                while (!tearingDown && generation == tunnelGeneration && currentAwgHandle() == handle) {
                    Thread.sleep(1000)
                }
            } catch (e: Exception) {
                if (!tearingDown && generation == tunnelGeneration) {
                    logError("VPN engine stopped unexpectedly", e)
                    clearRestartConfig()
                    executeTunnelTeardown(keepVpnLauncher = true)
                } else {
                    debugLog("Superseded VPN engine stopped.")
                }
            } finally {
                if (handle >= 0) stopAwgEngineIfOwned(handle, generation)
            }
        }.apply {
            name = "Calc-AWG-Engine"
            isDaemon = false
            start()
        }
    }

    /**
     * The Winn Protocol **v3** run loop: BOOTSTRAP, prove, PROMOTE - or refuse.
     *
     * ## What is different from every other start on this platform
     *
     * There is no AmneziaWG. `winn3/core` is the crypto and `winn3/tun` is the
     * inner-IP validator, so the tun's packets go to the frame device and the
     * engine carries `payload:"ip-packet"`. That inverts the v1 rule this
     * service has enforced everywhere else - where feeding tun packets to the
     * engine would have put cleartext on the wire - and it is why Android's
     * oldest v1 blocker, having no outer-datagram seam, simply does not apply:
     * [WinnAwgLoopbackSeam] is not opened, `libwg-go` is not patched, and
     * `GoBackend.awgTurnOn` is never called.
     *
     * ## The interface is established TWICE, and that is the design
     *
     * Android has no API to change a live `VpnService`'s routes, MTU or
     * resolvers, so the promotion posture is a second `establish()` and a new
     * descriptor. The engine is never told: it holds a channel-backed
     * `tun.Device`, and [WinnV3AndroidIpPacketSeam.rebindDevice] swaps the
     * descriptor underneath it. `tun.Config.Device` is read once in `tun.New`
     * and cannot be swapped from the Go side, which is exactly why the host owns
     * the device here.
     *
     * ## Ordering, and why the bridge starts inside the install closure
     *
     * The seam needs a device before it can exist, the bridge needs the seam,
     * and the promotion gate needs the bridge's status. So the first install,
     * the one [WinnV3StagedStart] makes itself, is also what creates the seam
     * and starts the bridge. Anything else would have to establish the bootstrap
     * interface twice.
     *
     * ## The gate
     *
     * `isEngineReady` is set only after [WinnV3StagedStart.Outcome.Promoted].
     * Until then `isTunnelHealthy()` stays false, so the Dart readiness poll
     * never promotes the UI and the app cannot say Connected on a tunnel that
     * has not carried a validated inner packet. A refusal costs the user a
     * retry; a promotion on an unproven datapath costs them their traffic.
     */
    @Suppress("LongMethod", "LongParameterList")
    private fun startWinnV3EngineThread(
        winnSection: Map<String, String>,
        appSection: Map<String, String>,
        clientIp: String,
        resolverCandidates: List<String>,
        promotionRoutes: List<WinnV3Route>,
        generation: Int,
        startToken: Long,
        startGeneration: Long,
    ) {
        // Round L: published before the thread exists, so a release pass can
        // never miss this engine's retirement.
        val retirement = WinnV3EngineRetirement()
        winnV3EngineRetirement = retirement
        Thread {
            setTunnelThreadPriority(android.os.Process.THREAD_PRIORITY_DISPLAY)
            var bridge: WinnV3Bridge? = null
            var lastV3StatusJsonLogged = ""
            val winn3PromotionProbeAttempts = java.util.concurrent.atomic.AtomicInteger(0)
            var seam: WinnV3AndroidIpPacketSeam? = null
            var proofTimedOutWithoutSecurityRefusal = false
            var bridgeStarted = false
            var explicitSecurityRefusal = false
            var publishedNativeVerdict: WinnV3NativeVerdict? = null
            var keyMaterial: Pair<WinnV3Keys, File>? = null
            // Round A3. This session's own lifecycle watch: a fresh one per
            // session, so no earlier episode's age or blocked latch can reach
            // this tunnel. It is published for the health check only at
            // promotion, and the lifecycle board accepts this session's
            // publications only while its generation owns the tunnel.
            val lifecycleWatch = WinnV3LifecycleWatch()
            val lifecycleBinding = WinnV3LifecycleBinding(lifecycleWatch, generation)
            var recoveryProber: WinnV3RecoveryProber? = null
            synchronized(winnEngineLock) {
                if (!tearingDown && generation == tunnelGeneration) {
                    winn3HostLifecycle.begin(generation)
                    // A new session's release concerns its own resources.
                    winn3CleanupDebt.clear()
                }
            }
            try {
                debugLog("Winn Protocol v3 entering staged start")

                // Both postures, before anything is allocated. §4.3 rule 1 is
                // only enforceable if the refusal happens before the tunnel
                // exists, and a configuration that could bootstrap but never
                // promote is refused here rather than after thirty seconds of
                // spinner.
                val plan = WinnV3SessionPlan.from(
                    section = winnSection,
                    // The AmneziaWG assignment, and a FALLBACK only. A
                    // standalone v3 session takes its inner address from
                    // `[winn] inner_v4` - the v3 gateway's own inner space,
                    // off the signed descriptor. Passing this as the inner
                    // address unconditionally, which is what this line did
                    // until 2026-08-09, gives the tun layer a source address it
                    // drops every packet for: a session that starts, reports up
                    // at both ends, and carries nothing.
                    relayInnerAddress = clientIp,
                    // The AmneziaWG [Interface] DNS list VERBATIM, with no
                    // fallback substituted. It is a list of CANDIDATES, not of
                    // resolvers: WinnV3Posture.promotion derives which of them
                    // - if any - a standalone session can justify, and refuses
                    // the whole plan when none can.
                    dnsServers = resolverCandidates,
                    promotionRoutes = promotionRoutes,
                    ipv6SinkAddress = IPV6_FAIL_CLOSED_SINK,
                )
                // RV-B: latch the active session's inner router here, where
                // the [winn] section is actually parsed — the earlier latch
                // site read a config string that does not carry the section on
                // the staged-start path.
                WinnV3SessionPlan.innerNextHopOf(winnSection).takeIf { it.isNotEmpty() }
                    ?.let { latchedInnerRouterV4 = it }
                debugLog(plan.describeForLog())

                // THE PLATFORM PREFLIGHT, and it runs before the key document is
                // written, before the engine host exists and before the packaged
                // binary is probed - the same position `cmd/winn3-gateway`'s
                // preflightSession holds ahead of net.ListenUDP.
                //
                // Everything above this line is a rule about the CONFIGURATION
                // and is enforced by the real constructors inside
                // WinnV3SessionPlan.from. This is the one rule that belongs to
                // the KERNEL: Linux will not attach an IPv6 address to a device
                // below RFC 8200's 1280-byte floor, and the promotion posture
                // always carries one. Without this check the session builds,
                // bootstraps, handshakes, reaches gate=carrying, and then throws
                // "Cannot set address" out of establish() thirty seconds in:
                // the silent-refusal signature, wearing a message that names
                // neither the MTU nor the path MTU that produced it.
                plan.promotionEstablishRefusal()?.let { throw WinnV3PostureRefusal(it) }

                // The key document, written before anything is allocated. v3
                // authenticates with a static X25519 key pair and an admission
                // secret and has no anonymous mode, so a session without them
                // cannot start - and the engine refuses -winn3 without
                // -winn3-keys, which was only discovered by running the real
                // binary. Failing here names the missing fields; failing there
                // is an exit code in logcat.
                val keys = WinnV3Keys.from(winnSection)
                debugLog(keys.describeForLog())
                val keyDirectory = WinnV3Keys.keyDirectory(
                    applicationContext.filesDir,
                    generation,
                    startToken,
                )
                if (!keys.recoverStale(applicationContext.filesDir, keyDirectory)) {
                    throw IOException(
                        "Winn v3 stale plaintext key recovery failed before engine start"
                    )
                }
                // Ownership is assigned BEFORE writeTo so a throw after the
                // first secret hits disk still reaches the finally cleanup,
                // even though writeTo also rolls back its own bound children.
                keyMaterial = keys to keyDirectory
                val keyDocument = keys.writeTo(keyDirectory)

                val engineHost = WinnAndroidEngineHost(
                    vpnService = this,
                    context = applicationContext,
                    logDebug = { message -> debugLog(message) },
                    logWarn = { message, error -> logWarning(message, error) },
                    logError = { message, error -> logError(message, error) },
                    winn3 = true,
                    winn3KeysPath = keyDocument.absolutePath,
                    winn3GatewayEndpoint = plan.gatewayEndpoint,
                )

                // THE CAPABILITY GATE, and it probes the PACKAGED binary.
                // An engine without the ip-packet payload cannot carry v3, and
                // the only alternative available to it is a v1 session - which
                // would be a silent downgrade of the user's protocol. So this
                // refuses instead, and the refusal quotes the banner.
                val (v3Capable, banner) = engineHost.probeV3Support()
                if (!v3Capable) throw IOException(WinnV3Host.capabilityRefusal(banner))
                debugLog("Winn v3: the packaged engine advertises the ip-packet payload.")

                val install: (WinnV3Posture) -> Unit = { posture ->
                    val builder = Builder().setSession(vpnSessionName())
                    val record = posture.applyTo(WinnV3BuilderSink(builder))

                    // §4.3.1: verify the RECORD, not the intent. Bootstrap only
                    // - every clause of verifyNarrow is a bootstrap clause, and
                    // the promotion posture is meant to be wide.
                    var wasProtected = false
                    if (posture.stage == WinnV3Stage.BOOTSTRAP) {
                        WinnV3Posture.verifyNarrow(
                            record,
                            requireExclusion =
                                Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                                    posture.excludedRoutes.isNotEmpty(),
                        )
                        // The record stays narrow and verified; the BUILDER fails
                        // closed when this start replaces a protecting posture.
                        wasProtected = vpnInterface != null ||
                            retainedKillSwitchInterface != null ||
                            isKillSwitchArmed()
                        if (wasProtected) {
                            // Through the record, which forwards to the builder,
                            // so the verified record still describes the builder.
                            WinnV3Posture.applyFailClosedBootstrapCapture(
                                record,
                                IPV6_FAIL_CLOSED_SINK,
                            )
                            WinnV3Posture.verifyFailClosedBootstrap(
                                record,
                                IPV6_FAIL_CLOSED_SINK,
                                requireExclusion =
                                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                                        posture.excludedRoutes.isNotEmpty(),
                            )
                            debugLog("winn3: bootstrap is fail-closed; a protecting posture was live")
                        }
                    }

                    applyUserExcludedApplications(builder, appSection)
                    applyUnderlyingNetworkHints(builder)

                    val priorInterface = vpnInterface
                    val priorRetained = retainedKillSwitchInterface
                    var originalPublished = false
                    try {
                        // Runtime switch for the native downlink tun writer:
                        // debug builds only, read at every establish so each
                        // connection is one arm of an on/off measurement.
                        val nativeTunWrite = BuildConfig.DEBUG &&
                            File(applicationContext.filesDir, WinnV3TunBulkWrite.SWITCH_FILE).exists()
                        // Delegates to builder.establish() via WinnV3AndroidTunDevice.establish
                        val device = WinnV3AndroidTunDevice.establish(
                            builder, posture.mtu,
                            "Builder.establish() returned null for the ${posture.stage} posture",
                            nativeBatchWrite = nativeTunWrite,
                        ) { original ->
                            // Transfer the original even if duplicate setup later fails.
                            vpnInterface = original
                            // Only a NARROW bootstrap is one: a fail-closed
                            // bootstrap captures everything, and a refused
                            // hold must keep it like any other full capture.
                            narrowBootstrapInterface =
                                if (posture.stage == WinnV3Stage.BOOTSTRAP && !wasProtected) original else null
                            retainedKillSwitchInterface = null
                            isInterfaceOpen = true
                            originalPublished = true
                        }
                        if (BuildConfig.DEBUG) {
                            debugLog(
                                "winn3: downlink tun writer " +
                                    (if (device.supportsBatchWrite) "native" else "kotlin") +
                                    " (switch " + (if (nativeTunWrite) "on" else "off") + ")",
                            )
                        }
                        var transferred = false
                        try {
                            val existing = seam
                            if (existing == null) {
                                val opened = WinnV3AndroidIpPacketSeam(
                                    initialDevice = device,
                                    onDropped = { reason -> debugLog("Winn v3 seam: $reason") },
                                    onDebug = { message -> debugLog(message) },
                                )
                                seam = opened
                                transferred = true
                                isServiceActive = true
                                registerNetworkHandoffCallback()
                                refreshUnderlyingNetworkHint("winn3 bootstrap established")
                                startTunnelHealthWatchdog(generation)
        
                                // The bridge starts here, on the bootstrap posture, so
                                // the datapath is running while the gate polls it. It
                                // cannot start earlier: the seam it pumps did not exist
                                // until the line above.
                                val created = WinnV3Bridge(
                                    host = engineHost,
                                    seam = opened,
                                    config = plan.engineConfig,
                                    // Monotonic, so status staleness cannot
                                    // be moved by a wall-clock change.
                                    clockMs = { SystemClock.elapsedRealtime() },
                                    probeProtectedSocketErrno = {
                                        captureWinnV3ProtectedSocketErrno(
                                            plan.engineConfig.gatewayEndpoint,
                                        )
                                    },
                                )
                                bridge = created
                                // Publish it before start(), so a watchdog sample that
                                // lands during the handshake sees a v3 session that is
                                // starting rather than no session at all.
                                synchronized(winnEngineLock) { winnV3Bridge = created }
                            } else {
                                // PROMOTION. The engine is not told; from winn3/tun's
                                // side the Device is unchanged.
                                existing.rebindDevice(device)
                                narrowBootstrapInterface = null
                                transferred = true
                            }
                        } finally {
                            if (!transferred) device.close()
                        }
                    } finally {
                        if (originalPublished) {
                            try { priorInterface?.close() } catch (_: IOException) { }
                            if (priorRetained !== priorInterface) {
                                try { priorRetained?.close() } catch (_: IOException) { }
                            }
                        }
                    }
                }

                val installIfStillOwner: (WinnV3Posture) -> Boolean = { posture ->
                    val installed = synchronized(winnEngineLock) {
                        if (tearingDown || generation != tunnelGeneration) {
                            false
                        } else {
                            install(posture)
                            true
                        }
                    }
                    if (installed && posture.stage == WinnV3Stage.BOOTSTRAP) {
                        // The engine spawn (up to the 8 s accept) and the CreateAck
                        // wait (up to 10 s) run OUTSIDE winnEngineLock, which the
                        // main thread takes for Connect, Disconnect and Revoke. A
                        // teardown meanwhile closes the published bridge, and
                        // start() then fails promptly.
                        val created = bridge
                            ?: throw IOException("Winn v3 bootstrap published no bridge")
                        created.start()
                        if (!keys.destroy(keyDirectory)) {
                            throw IOException(
                                "Winn v3 plaintext key cleanup failed after CreateAck"
                            )
                        }
                        keyMaterial = null
                        bridgeStarted = true
                        synchronized(winnEngineLock) {
                            !tearingDown && generation == tunnelGeneration
                        }
                    } else {
                        installed
                    }
                }
                val staged = WinnV3StagedStart(
                    bootstrap = plan.bootstrap,
                    promoted = plan.promotion,
                    proofDeadlineMs = WinnV3StagedStart.DEFAULT_PROOF_DEADLINE_MS,
                    pollIntervalMs = WinnV3StagedStart.DEFAULT_POLL_INTERVAL_MS,
                    install = install,
                    installBootstrapIfStillOwner = installIfStillOwner,
                    promoteIfStillOwner = installIfStillOwner,
                    readStatus = {
                        val live = bridge
                        if (live == null) {
                            ""
                        } else {
                            val json = live.requestStatusAndAwait(
                                WinnV3StagedStart.DEFAULT_POLL_INTERVAL_MS,
                            )
                            // LANE-LOCAL DIAGNOSTIC (android app-level live
                            // winn3 lane, 2026-08-21): log the engine's full
                            // status document whenever it changes, so the
                            // promotion gate's verdict can be explained from
                            // the engine's own counters rather than from the
                            // three-field subset WinnV3EngineStatus reads.
                            if (BuildConfig.DEBUG && json != lastV3StatusJsonLogged) {
                                lastV3StatusJsonLogged = json
                                debugLog("Winn v3 engine status: $json")
                            }
                            json
                        }
                    },
                    inspectBridge = {
                        bridge?.snapshot() ?: WinnV3BridgeSnapshot(
                            running = false,
                            failure = "Winn v3 bridge is not running",
                        )
                    },
                    tearDown = {
                        // §4.3 rule 2: the host is put back exactly as it was.
                        // The service's own teardown runs from the catch below;
                        // this releases what the staged start itself allocated.
                        try {
                            bridge?.close()
                        } catch (e: Exception) {
                            logWarning("Winn v3 bridge close was incomplete", e)
                        }
                    },
                    isStillOwner = {
                        synchronized(winnEngineLock) {
                            !tearingDown && generation == tunnelGeneration
                        }
                    },
                    log = { message -> debugLog(message) },
                    // The self-starting promotion probe. WinnV3StagedStart
                    // bounds it (attempt cap + interval, carrying with zero
                    // deliveries only); this is the Android send: one crafted
                    // inner ICMP echo to the inner next hop, injected through
                    // the tunnel seam so the engine offers it as an ordinary
                    // outbound inner packet. Promotion is still decided by the
                    // engine's own proof alone.
                    probe = {
                        val attempt = winn3PromotionProbeAttempts.incrementAndGet()
                        val sent = WinnV3PromotionProbe.send(
                            seam = seam,
                            innerAddress = plan.engineConfig.innerAddress,
                            innerNextHop = plan.engineConfig.innerNextHop,
                            attempt = attempt,
                            onNote = { message ->
                                debugLog("Winn v3 promotion probe: $message")
                            },
                        )
                        debugLog(
                            "Winn v3 promotion probe: inner ICMP echo #$attempt " +
                                if (sent) "injected into the tunnel seam." else "could not be sent."
                        )
                    },
                    nowMs = { SystemClock.elapsedRealtime() },
                    sleepMs = { millis -> Thread.sleep(millis) },
                )

                val stagedOutcome = try {
                    staged.start()
                } catch (e: WinnV3StartRefusal) {
                    explicitSecurityRefusal = e.verdict.securityRefusal
                    publishedNativeVerdict = e.verdict
                    completeWinn3Start(startToken, startGeneration, e.verdict)
                    throw e
                }
                when (val outcome = stagedOutcome) {
                    is WinnV3StagedStart.Outcome.Promoted -> {
                        debugLog(
                            "Winn v3 promoted after ${outcome.pollCount} polls; " +
                                "rxPackets=${outcome.rxPacketsAtPromotion} at promotion."
                        )
                    }
                    is WinnV3StagedStart.Outcome.RefusedNotProven -> {
                        proofTimedOutWithoutSecurityRefusal =
                            outcome.verdict == WinnV3NativeVerdict.ORDINARY_CONNECTIVITY
                        publishedNativeVerdict = outcome.verdict
                        completeWinn3Start(startToken, startGeneration, outcome.verdict)
                        throw IOException(
                            "Winn Protocol v3 refused to promote after " +
                                "${WinnV3StagedStart.DEFAULT_PROOF_DEADLINE_MS}ms: " +
                                "${outcome.reason}. The gate requires Gate.State()==carrying AND " +
                                "Stats().RxPackets>0 - a delivery, not an arrival - so this means " +
                                "no inner packet was validated and delivered."
                        )
                    }
                }

                val started = bridge ?: throw IOException("Winn v3 promoted with no bridge")
                val connectedPublished = synchronized(winnEngineLock) {
                    if (tearingDown || generation != tunnelGeneration) {
                        false
                    } else {
                        isEngineReady = true
                        completeWinn3Start(
                            startToken,
                            startGeneration,
                            WinnV3NativeVerdict.CONNECTED
                        )
                        publishedNativeVerdict = WinnV3NativeVerdict.CONNECTED
                        // Promotion is recorded ONCE, here, so an unsolicited
                        // end of this session keeps capture even if no
                        // recovery was ever sampled (WinnV3CaptureCustody).
                        winnV3Custody.markPromoted(generation)
                        winnV3LifecycleBinding = lifecycleBinding
                        engineReadyAtMs = SystemClock.elapsedRealtime()
                        val initUidRx = android.net.TrafficStats.getUidRxBytes(android.os.Process.myUid())
                        val initUidTx = android.net.TrafficStats.getUidTxBytes(android.os.Process.myUid())
                        if (initUidRx != android.net.TrafficStats.UNSUPPORTED.toLong()) {
                            tunnelStartUidRx = initUidRx
                        }
                        if (initUidTx != android.net.TrafficStats.UNSUPPORTED.toLong()) {
                            tunnelStartUidTx = initUidTx
                        }
                        true
                    }
                }
                if (!connectedPublished) throw IOException("Tunnel start was superseded")
                // The promotion gate proved the datapath (carrying AND
                // rxPackets>0); the notification may now claim connected.
                refreshForegroundStatusNotification(currentTunnelForegroundState())
                debugLog("Winn Protocol v3 datapath proven and promoted.")

                val prober = WinnV3RecoveryProber(
                    timer = WinnV3ExecutorProbeTimer("Calc-WinnV3-RecoveryProbe"),
                    draw = WinnV3RecoveryProber.secureDraw(),
                    isStillOwner = {
                        synchronized(winnEngineLock) {
                            !tearingDown && generation == tunnelGeneration
                        }
                    },
                    send = { attempt ->
                        val sent = WinnV3PromotionProbe.send(
                            seam = seam,
                            innerAddress = plan.engineConfig.innerAddress,
                            innerNextHop = plan.engineConfig.innerNextHop,
                            attempt = winn3PromotionProbeAttempts.incrementAndGet(),
                            onNote = { message -> debugLog("Winn v3 recovery probe: $message") },
                        )
                        debugLog(
                            "Winn v3 recovery probe #$attempt of this episode " +
                                if (sent) "injected into the tunnel seam." else "could not be sent."
                        )
                        sent
                    },
                )
                recoveryProber = prober
                while (!tearingDown &&
                    generation == tunnelGeneration &&
                    started.isRunning()
                ) {
                    Thread.sleep(1000)
                    // Non-blocking: a wedged transport freezes the document
                    // this loop reads, never the loop, so the ceiling below
                    // is still enforced on the monotonic clock.
                    started.requestStatus()
                    // LANE-LOCAL DIAGNOSTIC (android app-level live winn3
                    // lane, 2026-08-21): keep logging the engine's status
                    // while it changes after promotion, so the carrying
                    // session's client-side rx/tx counters are in the
                    // transcript, not only in the gateway's.
                    val json = started.statusJson()
                    if (BuildConfig.DEBUG && json != lastV3StatusJsonLogged) {
                        lastV3StatusJsonLogged = json
                        debugLog("Winn v3 engine status: $json")
                    }
                    // Round A2: follow the engine's lifecycle. Recovery keeps
                    // everything (tunnel, capture, this loop) and only changes
                    // what may be claimed; every post-promotion end (blocked,
                    // stopped, an invalid transition) is BLOCKED, ends the loop
                    // at once, and the teardown below holds capture.
                    // Stamped with the watch's own revision where it is decided,
                    // so the board refuses it if the health check published a
                    // newer (for instance BLOCKED) observation meanwhile.
                    val observation = WinnV3PostPromotionStep.judge(
                        lifecycleBinding,
                        json,
                        SystemClock.elapsedRealtime(),
                    )
                    val verdict = observation.verdict
                    // Ownership is re-checked AFTER the sleep: a configuration
                    // replacement that landed meanwhile owns the tunnel, and
                    // this session may publish nothing over it.
                    val publication = synchronized(winnEngineLock) {
                        WinnV3PostPromotionStep.publish(
                            board = winn3HostLifecycle,
                            binding = lifecycleBinding,
                            stillOwner = !tearingDown && lifecycleBinding.owner == tunnelGeneration,
                            observation = observation,
                        )
                    }
                    if (publication == WinnV3HostLifecycleBoard.Publication.CHANGED) {
                        refreshForegroundStatusNotification(currentTunnelForegroundState())
                    }
                    if (WinnV3PostPromotionStep.endsLoop(verdict, publication)) break
                    // An idle successor proves nothing on its own: ask it, on
                    // randomized, capped timing of the prober's own.
                    prober.onVerdict(verdict)
                }
                if (!tearingDown && generation == tunnelGeneration &&
                    lifecycleWatch.lastVerdict() == WinnV3LifecycleWatch.Verdict.BLOCKED
                ) {
                    // The cause is what the engine, or this host, OBSERVED. It
                    // is never read as censorship or revocation, and it never
                    // authorises AWG, Xray or any other protocol.
                    throw IOException(
                        "Winn Protocol v3 is blocked (observed by " +
                            "${lifecycleWatch.blockedObserver()?.wire ?: "unreported"}: " +
                            "${lifecycleWatch.blockedCause() ?: "no cause"}); " +
                            "holding capture until the user acts"
                    )
                }
                if (!tearingDown && generation == tunnelGeneration && !started.isRunning()) {
                    throw IOException(started.failure() ?: "Winn Protocol v3 engine stopped")
                }
            } catch (e: Exception) {
                if (!tearingDown && generation == tunnelGeneration) {
                    if (!isEngineReady && publishedNativeVerdict == null) {
                        val classified = WinnV3NativeVerdictClassifier.fromEvidence(
                            bridgeFailure = bridge?.failure(),
                            bridgeRunning = bridge?.isRunning() == true,
                            error = e.message,
                            cause = bridge?.failureCause() ?: e,
                            ordinaryNetworkPosixErrno = bridge?.ordinaryNetworkPosixErrno(),
                            ordinaryNetworkFailure = bridge?.ordinaryNetworkFailure(),
                        )
                        completeWinn3Start(startToken, startGeneration, classified)
                    }
                    logError("Winn Protocol v3 engine stopped unexpectedly", e)
                    // AUTOMATIC. After promotion that keeps capture however
                    // the session ended, whether or not a recovery or a
                    // blocked status ever reached this host: a terminal
                    // failure between polls and an Error frame before any
                    // status end up here too (WinnV3CaptureCustody). Nothing
                    // on this path publishes a native verdict once the tunnel
                    // was CONNECTED, so nothing here can authorise cover.
                    clearRestartConfig()
                    executeTunnelTeardown(keepVpnLauncher = true)
                } else {
                    debugLog("Superseded Winn Protocol v3 engine stopped.")
                }
            } finally {
                recoveryProber?.close()
                keyMaterial?.let { (keys, directory) ->
                    if (!keys.destroy(directory)) {
                        logWarning("Winn v3 plaintext key cleanup was incomplete", null)
                    }
                }
                keyMaterial = null
                synchronized(winnEngineLock) {
                    if (winnV3Bridge === bridge) winnV3Bridge = null
                }
                // Round L: this retirement completes only if both closes are
                // confirmed. A release acknowledgement waits on it.
                var retiredCleanly = true
                try {
                    bridge?.close()
                    // To its END: a teardown pass may be running this same
                    // close concurrently, in which case close() returned at
                    // once and only the awaited completion says how it ended.
                    if (bridge?.awaitCloseCompleted(WinnV3ReleaseTeardown.BRIDGE_CLOSE_WAIT_MS) == false) {
                        retiredCleanly = false
                    }
                } catch (e: Exception) {
                    retiredCleanly = false
                    logWarning("Winn v3 bridge stop was incomplete", e)
                }
                try {
                    seam?.close()
                } catch (e: Exception) {
                    retiredCleanly = false
                    logWarning("Winn v3 seam stop was incomplete", e)
                }
                retirement.finish(retiredCleanly)
            }
        }.apply {
            name = "Calc-WinnV3-Engine"
            isDaemon = false
            start()
        }
    }

    /**
     * Typed Android OS errno from one protected UDP route check to the v3
     * gateway.
     *
     * Official Android libcore `DatagramChannelImpl.send0` calls
     * `handleSocketError`, which throws [java.net.SocketException] and drops
     * the numeric errno. This boundary uses [Os.socket], [protect], [Os.connect],
     * and [ErrnoException.errno] instead, and never parses exception text.
     * [protect] runs before the check so the probe bypasses the VPN; the
     * descriptor is closed on every path.
     *
     * The check is a UDP `connect()`: it captures the synchronous route and
     * connect errors the kernel reports for this protected socket, and it
     * sends no datagram. It is not claimed to report every error a send
     * could; whatever it does not capture stays unknown_terminal, which is
     * fail-closed. The 1-byte datagram this used to send reached the gateway
     * on every connect, where it opened a second half-open session that was
     * held for about 24 s and then logged as a peer that failed to
     * authenticate. Android behaviour of this check needs the S26 canary.
     */
    private fun captureWinnV3ProtectedSocketErrno(
        gatewayEndpoint: String,
    ): WinnV3ProtectedSocketErrno.Result {
        val target = winnV3ProtectedSocketIpv4Target(gatewayEndpoint)
            ?: return WinnV3ProtectedSocketErrno.Result(closed = true)
        data class ProbeSocket(
            val fd: FileDescriptor,
            val pfd: ParcelFileDescriptor,
        )
        return WinnV3ProtectedSocketErrno.capture(
            open = {
                // Android documents O_NONBLOCK as the pre-API-29 socket flag.
                val fd = Os.socket(
                    OsConstants.AF_INET,
                    OsConstants.SOCK_DGRAM or OsConstants.O_NONBLOCK,
                    0,
                )
                try {
                    ProbeSocket(fd, ParcelFileDescriptor.dup(fd))
                } catch (thrown: Throwable) {
                    try {
                        Os.close(fd)
                    } catch (_: Exception) {
                    }
                    throw thrown
                }
            },
            protect = { socket -> protect(socket.pfd.fd) },
            send = { socket ->
                Os.connect(
                    socket.fd,
                    InetAddress.getByAddress(target.first),
                    target.second,
                )
            },
            close = { socket ->
                try {
                    socket.pfd.close()
                } catch (_: Exception) {
                }
                try {
                    Os.close(socket.fd)
                } catch (_: Exception) {
                }
            },
            typedErrno = { error -> (error as? ErrnoException)?.errno },
        )
    }

    private fun winnV3ProtectedSocketIpv4Target(endpoint: String): Pair<ByteArray, Int>? {
        if (endpoint.startsWith("[")) return null
        val colon = endpoint.lastIndexOf(':')
        if (colon <= 0) return null
        val host = endpoint.substring(0, colon)
        val port = endpoint.substring(colon + 1).toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        val value = WinnV3Resolvers.ipv4Value(host) ?: return null
        val bytes = byteArrayOf(
            ((value shr 24) and 0xffL).toByte(),
            ((value shr 16) and 0xffL).toByte(),
            ((value shr 8) and 0xffL).toByte(),
            (value and 0xffL).toByte(),
        )
        return bytes to port
    }

    /**
     * The Winn Protocol run loop.
     *
     * BOTH ENGINES RUN. This is the correction to the arrangement this branch
     * shipped with, which started the Winn bridge INSTEAD of the AmneziaWG
     * engine and then closed the tun. That topology could never work: the Winn
     * engine's Inbound/Outbound frames carry AmneziaWG OUTER DATAGRAMS
     * (`datapath.PayloadAWGDatagram`), and with no AmneziaWG engine running
     * there was nothing on the device producing any. The only bytes available
     * to pump were raw tun packets, which is exactly what the engine refuses at
     * create time because forwarding them would put cleartext on the wire.
     *
     * The layering is therefore:
     *
     *     apps -> tun -> [AmneziaWG, owns the tun exactly as in winn/1 mode]
     *                       Endpoint rewritten to 127.0.0.1:<seam>
     *                    [WinnAwgLoopbackSeam]
     *                    [WinnTunnelBridge] -> [winn-datapath] -> gateway
     *
     * so AmneziaWG keeps the tun and keeps doing all the cryptography, and Winn
     * carries its already-encrypted datagrams. The tun descriptor goes to the
     * AmneziaWG engine, not to the bridge; the bridge never sees an IP packet.
     *
     * ORDERING MATTERS. The seam is opened and the bridge is started BEFORE the
     * AmneziaWG engine, so the relay is already draining when AmneziaWG sends
     * its first handshake initiation. Starting AmneziaWG first would drop
     * whatever it sent into an unbound port.
     */
    private fun startWinnEngineThread(
        winnSection: Map<String, String>,
        awgConfig: String,
        tunPfd: ParcelFileDescriptor,
        clientIp: String,
        dnsServer: String,
        mtu: Int,
        generation: Int,
    ) {
        Thread {
            setTunnelThreadPriority(android.os.Process.THREAD_PRIORITY_DISPLAY)
            var bridge: WinnTunnelBridge? = null
            var seam: WinnAwgLoopbackSeam? = null
            var awgHandle = -1
            var tunHandedToAwg = false
            var carrierProfileFile: java.io.File? = null
            try {
                debugLog("Winn Protocol engine entering run loop")
                val engineConfig = WinnEngineConfig.from(
                    section = winnSection,
                    mtu = mtu,
                    tunnelAddress = clientIp,
                    dnsServers = listOf(dnsServer),
                )
                // Key names only. The config JSON itself may carry key
                // material and is never logged.
                debugLog(engineConfig.describeForLog())

                // The carrier profile, for a session whose carrier is not
                // direct-awg. Written BEFORE anything is allocated, because a
                // profile that cannot be built must fail the tunnel here rather
                // than after a socket has been protected and handed to a child
                // that will then exit on a bad profile.
                //
                // ANTI-DOWNGRADE. There is no branch below that starts the
                // engine without this path once the configuration asked for a
                // carrier: WinnEngineConfig.from has already refused a carrier
                // section that lacks the fields, this throws if the credentials
                // are absent, and the engine itself refuses a carrier
                // configuration that arrives with no profile. A winn/3 session
                // configured for an authenticated carrier can therefore fail,
                // but it cannot quietly become classical AmneziaWG.
                if (engineConfig.requiresCarrierProfile) {
                    val profile = WinnCarrierProfile.from(
                        section = winnSection,
                        carrier = engineConfig.carrier,
                        credentialDirectory = WinnCarrierProfile.credentialDirectory(
                            applicationContext.filesDir,
                        ),
                    )
                    debugLog(profile.describeForLog())
                    carrierProfileFile = profile.writeTo(
                        WinnCarrierProfile.profileDirectory(applicationContext.filesDir),
                    )
                }

                // The outer-datagram source. Opened first so its port is known
                // before the AmneziaWG configuration is rewritten, and so the
                // rewrite can fail closed before anything else is allocated.
                // The AmneziaWG engine's own ListenPort, reserved here so the
                // seam refuses every other local sender from the first datagram.
                val awgListenPort = WinnAwgLoopbackSeam.reserveAwgListenPort()
                val opened = WinnAwgLoopbackSeam.open(
                    maxDatagram = engineConfig.maxDatagram,
                    expectedPeerPort = awgListenPort,
                    onDropped = { reason ->
                        debugLog("Winn AmneziaWG seam dropped a datagram: $reason")
                    },
                    // ONE LINE PER SESSION, UNCONDITIONALLY. A lossy session is
                    // logged at WARNING so it survives where a debug line would
                    // not: silence is what let this defect through two
                    // "successful" proofs, on this platform included.
                    onSessionEnd = { lossy, summary ->
                        if (lossy) logWarning(summary, null) else debugLog(summary)
                    },
                )
                seam = opened
                val redirected = WinnAwgLoopbackSeam.redirectPeerEndpoint(
                    awgConfig, opened.localPort, awgListenPort,
                )
                debugLog(
                    "Winn AmneziaWG outer-datagram seam listening on 127.0.0.1:" +
                        "${opened.localPort}; the AmneziaWG peer endpoint was redirected to it."
                )

                val created = WinnTunnelBridge(
                    host = WinnAndroidEngineHost(
                        vpnService = this,
                        context = applicationContext,
                        logDebug = { message -> debugLog(message) },
                        logWarn = { message, error -> logWarning(message, error) },
                        logError = { message, error -> logError(message, error) },
                        awgDatagramSeam = opened,
                        carrierProfilePath = carrierProfileFile?.absolutePath,
                    ),
                    maxDatagram = engineConfig.maxDatagram,
                    configJson = engineConfig.toConfigJson(),
                )
                bridge = created
                created.start()

                // Now that the seam is being drained, hand the tun to the
                // AmneziaWG engine. Its own sockets are still protected: with
                // the peer on loopback they should never address the network,
                // but a mark costs nothing and keeps the guarantee from
                // depending on the endpoint rewrite alone.
                tunHandedToAwg = true
                awgHandle = startAwgEngine(redirected, tunPfd.detachFd(), generation)

                val accepted = synchronized(winnEngineLock) {
                    if (tearingDown || generation != tunnelGeneration || winnBridge != null) {
                        false
                    } else {
                        winnBridge = created
                        true
                    }
                }
                if (!accepted) throw IOException("Tunnel start was superseded")

                // THE GATE. Nothing above this line proves a datagram ever
                // crossed -- the engine accepting a configuration is not a
                // working datapath. isEngineReady stays false until it does,
                // so isTunnelHealthy() stays false, so the Dart readiness poll
                // never promotes the UI: the app cannot say Connected on a
                // tunnel carrying nothing. On failure this throws into the
                // existing catch below, which clears the restart config and
                // runs the existing teardown -- the same fail-closed path the
                // IPv6-sink and both-outer-transports refusals already use.
                if (!awaitWinnTransportConvergence(created, generation)) {
                    throw IOException(WINN_TRANSPORT_NEVER_CONVERGED)
                }
                winnLastTxPayloadDatagrams = -1L
                winnLastRxPayloadDatagrams = -1L

                val readyPublished = synchronized(winnEngineLock) {
                    if (tearingDown ||
                        generation != tunnelGeneration ||
                        winnBridge !== created ||
                        currentAwgHandle() != awgHandle
                    ) {
                        false
                    } else {
                        isEngineReady = true
                        engineReadyAtMs = SystemClock.elapsedRealtime()
                        true
                    }
                }
                if (!readyPublished) throw IOException("Tunnel start was superseded")
                // The transport convergence gate proved a datagram crossed both
                // ways; the notification may now claim connected.
                refreshForegroundStatusNotification(currentTunnelForegroundState())
                debugLog("Winn Protocol engine accepted the current configuration.")
                // Both engines have to stay up. Either one stopping is a dead
                // tunnel: without AmneziaWG there are no outer datagrams to
                // carry, and without the bridge they have nowhere to go.
                while (!tearingDown &&
                    generation == tunnelGeneration &&
                    currentWinnBridge() === created &&
                    created.isRunning() &&
                    currentAwgHandle() == awgHandle
                ) {
                    Thread.sleep(1000)
                }
                if (!tearingDown && generation == tunnelGeneration && !created.isRunning()) {
                    throw IOException(created.failure() ?: "Winn Protocol engine stopped")
                }
            } catch (e: Exception) {
                if (!tearingDown && generation == tunnelGeneration) {
                    logError("Winn Protocol engine stopped unexpectedly", e)
                    clearRestartConfig()
                    executeTunnelTeardown(keepVpnLauncher = true)
                } else {
                    debugLog("Superseded Winn Protocol engine stopped.")
                }
            } finally {
                // AmneziaWG first: it is the thing still writing into the seam.
                if (awgHandle >= 0) {
                    try {
                        stopAwgEngineIfOwned(awgHandle, generation)
                    } catch (e: Exception) {
                        logWarning("Winn AmneziaWG engine stop was incomplete", e)
                    }
                }
                val started = bridge
                if (started != null) {
                    synchronized(winnEngineLock) {
                        if (winnBridge === started) winnBridge = null
                    }
                    try {
                        started.close()
                    } catch (e: Exception) {
                        logWarning("Winn Protocol engine stop was incomplete", e)
                    }
                }
                // The bridge closes the seam it was given; closing it here as
                // well is the path for a failure before the bridge existed.
                try {
                    seam?.close()
                } catch (e: Exception) {
                    logWarning("Winn AmneziaWG seam close was incomplete", e)
                }
                // The tun belongs to the AmneziaWG engine once it has been
                // handed over, exactly as in winn/1 mode. Before that, this
                // thread still owns it.
                if (!tunHandedToAwg) {
                    try {
                        tunPfd.close()
                    } catch (e: Exception) {
                        logWarning("Winn tun descriptor close was incomplete", e)
                    }
                }
                // The profile is session state, not durable configuration. It
                // holds no key material -- only paths -- but it enumerates
                // every private credential file on the device, so it does not
                // outlive the session that needed it. The engine has already
                // read it: it loads and validates the profile before it dials
                // the control socket.
                carrierProfileFile?.let { file ->
                    try {
                        if (file.exists() && !file.delete()) {
                            logWarning("Winn carrier profile could not be removed", null)
                        }
                    } catch (e: Exception) {
                        logWarning("Winn carrier profile cleanup was incomplete", e)
                    }
                }
            }
        }.apply {
            name = "Calc-Winn-Engine"
            isDaemon = false
            start()
        }
    }

    /**
     * THE WINN TRANSPORT CONVERGENCE GATE. Ported 2026-08-07 from the Linux
     * lane's `WaitForLinuxWinnTransportConvergence`
     * (`linux/runner/linux_tunnel_backend.cc`), same shape, same constants.
     *
     * # What it is for
     *
     * Until this existed, Android set `isEngineReady = true` the moment the
     * engine ACCEPTED its configuration. Nothing checked that a datagram ever
     * crossed. That produced a measured failure on 2026-08-07: the service
     * picked cellular as the underlay while the gateway was reachable only over
     * Wi-Fi, so `0.0.0.0/0` went onto the tun, AmneziaWG retried its handshake
     * forever, ZERO datagrams reached the wire -- and `isEngineReady` was true,
     * `isTunnelHealthy()` was true, the UI said Connected and the watchdog was
     * calm, because in winn mode it read status FRESHNESS only. A DPI box that
     * drops the direct UDP leg produces byte-for-byte that same state, so a
     * censored user and a working user were indistinguishable to this app.
     *
     * # What it reads, and what it deliberately does not
     *
     * `transport_observed_both_ways` (`datapath/status.go:197`) -- the engine's
     * own transfer-proven signal: at least one PAYLOAD-CARRYING transport
     * datagram has crossed in each direction. Handshakes and keepalives cannot
     * raise it. `up` is deliberately NOT consulted: `up` says the carrier is
     * open, which is equally true of a carrier whose every datagram is being
     * dropped on path. The status document carries `gateway_endpoint`, the
     * customer's real gateway address, so it is NEVER logged -- this reads three
     * fields out of it and emits none of them.
     *
     * # An unobservable classifier is a refusal
     *
     * If the `[winn]` section carried no h1..h4, the engine classifies against
     * vanilla WireGuard's 1/2/3/4 while the AmneziaWG interface emits the
     * deployment's own header types. No transport datagram can then be proven.
     * Promotion must refuse that state. Treating lack of evidence as success
     * lets a dead transport appear connected.
     *
     * Returns true if the datapath proved itself, false if the caller must tear
     * the tunnel down.
     */
    private fun awaitWinnTransportConvergence(
        bridge: WinnTunnelBridge,
        generation: Int,
    ): Boolean {
        val startedAt = SystemClock.elapsedRealtime()
        val deadline = startedAt + WINN_CONVERGENCE_DEADLINE_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            // A superseded or torn-down session has nothing to prove; the
            // caller's own generation checks handle it from here.
            if (tearingDown || generation != tunnelGeneration) return false
            // An engine that has exited answers nothing forever, so stop rather
            // than burn the whole budget.
            if (!bridge.isRunning()) return false
            val tickStartedAt = SystemClock.elapsedRealtime()
            val status = bridge.requestStatusAndAwait(WINN_CONVERGENCE_TICK_MS)
            if (status.isNotEmpty()) {
                val document = try {
                    JSONObject(status)
                } catch (_: Exception) {
                    null
                }
                if (document != null) {
                    if (document.optString("awg_classification") != WINN_CLASSIFIER_CONFIGURED) {
                        logWarning(
                            "Winn datapath convergence refused: the engine did not confirm " +
                                "the configured AmneziaWG classification table.",
                            null,
                        )
                        return false
                    }
                    if (document.optBoolean("transport_observed_both_ways", false)) {
                        val elapsed = SystemClock.elapsedRealtime() - startedAt
                        debugLog("Winn datapath proved: transport observed both ways after ${elapsed}ms.")
                        return true
                    }
                }
            }
            val remainingTick =
                WINN_CONVERGENCE_TICK_MS - (SystemClock.elapsedRealtime() - tickStartedAt)
            if (remainingTick > 0L) {
                try {
                    Thread.sleep(remainingTick)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        }
        return false
    }

    /**
     * The traffic half of the health check, added 2026-08-07 beside the
     * convergence gate because freshness alone was the root cause of the defect
     * that gate closes: an engine answering STATUS promptly while carrying
     * nothing was "healthy" forever.
     *
     * The test is deliberately ASYMMETRIC PROGRESS, not "did traffic move".
     * `transport_observed_both_ways` latches, so re-reading it after start
     * proves nothing; and requiring traffic outright would tear down an idle
     * tunnel, which is a worse bug than the one being fixed. So a verdict is
     * only reached when this device SENT payload-carrying transport datagrams
     * across the interval and NONE came back -- the signature of a path that
     * has gone dead outbound-only, which is the censorship case. An idle
     * session advances neither counter and is never judged.
     *
     * Returns true (healthy) whenever there is no basis for a verdict.
     */
    private fun winnDatapathIsCarrying(status: String): Boolean {
        if (status.isBlank()) {
            logWarning("Winn datapath health refused an empty status.", null)
            return false
        }
        val document = try {
            JSONObject(status)
        } catch (failure: Exception) {
            logWarning("Winn datapath health refused malformed status.", failure)
            return false
        }
        // An unconfigured classifier cannot prove health. Refuse it rather
        // than carrying forward an unobservable session.
        if (document.optString("awg_classification") != WINN_CLASSIFIER_CONFIGURED) {
            logWarning("Winn datapath health refused an unconfigured classifier.", null)
            return false
        }
        if (!document.has("tx_transport_payload_datagrams") ||
            !document.has("rx_transport_payload_datagrams")) {
            logWarning("Winn datapath health refused missing transport counters.", null)
            return false
        }
        val tx = document.optLong("tx_transport_payload_datagrams", -1L)
        val rx = document.optLong("rx_transport_payload_datagrams", -1L)
        if (tx < 0L || rx < 0L) {
            logWarning("Winn datapath health refused invalid transport counters.", null)
            return false
        }
        val previousTx = winnLastTxPayloadDatagrams
        val previousRx = winnLastRxPayloadDatagrams
        winnLastTxPayloadDatagrams = tx
        winnLastRxPayloadDatagrams = rx
        if (previousTx < 0L || previousRx < 0L) return true
        val sentThisInterval = tx > previousTx
        val receivedThisInterval = rx > previousRx
        if (sentThisInterval && !receivedThisInterval) {
            logWarning(
                "Winn datapath carried ${tx - previousTx} outbound payload datagrams " +
                    "with nothing returning.",
                null,
            )
            return false
        }
        return true
    }

    private fun currentWinnBridge(): WinnTunnelBridge? = synchronized(winnEngineLock) { winnBridge }

    private fun currentWinnV3Bridge(): WinnV3Bridge? = synchronized(winnEngineLock) { winnV3Bridge }

    /**
     * Closes both engine bridges and returns each close's completion (Round
     * L); an exception still propagates.
     */
    private fun stopWinnBridge(): List<WinnV3Completion> {
        val bridges = synchronized(winnEngineLock) {
            val active = Pair(winnBridge, winnV3Bridge)
            winnBridge = null
            winnV3Bridge = null
            active
        }
        // Round L: each close's own completion, which the caller awaits to its
        // END. A concurrent close already running returns at once from
        // close(), and its completion still reports how that close ends.
        val completions = mutableListOf<WinnV3Completion>()
        try {
            bridges.second?.let {
                it.close()
                completions += it.closeCompletion()
            }
        } finally {
            bridges.first?.let {
                it.close()
                completions += it.closeCompletion()
            }
        }
        return completions
    }

    private fun startAwgEngine(awgConfig: String, tunFd: Int, generation: Int): Int {
        ensureAwgNativeLoaded()
        val userspace = AwgUserspaceConfig.fromQuick(awgConfig)
        val handle = AwgNativeApi.awgTurnOn("winsvpn", tunFd, userspace, dataDir.absolutePath)
        if (handle < 0) {
            throw IOException("AmneziaWG engine rejected tunnel config with code $handle")
        }

        val accepted = awgEngineOwnership.publishIfFreeAnd(handle, generation) {
            !tearingDown && generation == tunnelGeneration
        }
        if (!accepted) {
            AwgNativeApi.awgTurnOff(handle)
            throw IOException("Tunnel start was superseded")
        }
        AwgSocketProtection.protectOrRollback(
            sockets = {
                listOf(
                    AwgSocket("IPv4", AwgNativeApi.awgGetSocketV4(handle)),
                    AwgSocket("IPv6", AwgNativeApi.awgGetSocketV6(handle)),
                )
            },
            protect = { socketFd -> protect(socketFd) },
            rollback = { stopAwgEngineIfOwned(handle, generation) },
            onUnavailable = { label ->
                debugLog("VPN $label socket was not available for route protection.")
            },
        )
        return handle
    }

    /**
     * Unconditionally stops whatever AmneziaWG handle is currently published,
     * regardless of which tunnel generation owns it. For "a new tunnel is
     * starting, stop whatever is running now" paths only -- see
     * AwgHandleOwnership.forceRelease.
     */
    private fun stopAwgEngine() {
        val handle = awgEngineOwnership.forceRelease()
        if (handle >= 0) {
            AwgNativeApi.awgTurnOff(handle)
        }
    }

    /**
     * Turns the AmneziaWG engine back off, but ONLY if [handle] is still
     * published under [generation]. A superseded session's late or duplicate
     * call reaching here with a stale [generation] is a no-op even when
     * [handle] numerically matches whatever is live now: AmneziaWG is free to
     * reuse handle numbers across unrelated tunnels (confirmed on real
     * hardware 2026-08-04 -- see AwgHandleOwnership's doc), so the handle
     * value alone cannot prove this call still owns it.
     */
    private fun stopAwgEngineIfOwned(handle: Int, generation: Int) {
        if (awgEngineOwnership.releaseIfOwned(handle, generation)) {
            AwgNativeApi.awgTurnOff(handle)
        }
    }

    private fun currentAwgHandle(): Int = awgEngineOwnership.current()

    private fun updateAwgTunnelPeers(handle: Int, awgConfig: String) {
        ensureAwgNativeLoaded()
        val settings = AwgUserspaceConfig.peerUpdateFromQuick(awgConfig)
        val code = AwgNativeApi.awgUpdateTunnelPeers(handle, settings)
        if (code < 0) {
            throw IOException("AmneziaWG engine rejected live peer update with code $code")
        }
    }

    private fun currentEngineHandleHealthy(): Boolean {
        // v3 FIRST, because a v3 session has no AmneziaWG handle and no v1
        // bridge, and the two checks below both answer false for it. See
        // [winnV3Bridge] for the 35-second teardown that produced.
        val v3 = currentWinnV3Bridge()
        if (v3 != null) {
            // A published v3 bridge that is not yet ready is a staged start
            // still in progress. That start is bounded on its own (the 8 s
            // channel accept, the 10 s CreateAck read, the 30 s proof
            // deadline) and nulls [winnV3Bridge] in its finally, so this
            // sample has no verdict to give. Counting it as unhealthy let the
            // 15 s + 3 x 10 s watchdog tear the start down at 35 s, before a
            // proof deadline that opens only after the engine spawn, whenever
            // that spawn took more than 5 s; the staged start then saw itself
            // superseded and published unknown_terminal for a refusal it
            // could still have classified.
            if (!isEngineReady) return true
            // A round trip, not a process-existence check, for the same reason
            // the v1 branch gives: a subprocess that is alive but wedged is not
            // a healthy tunnel, and the reply refreshes the freshness stamp.
            // The request never blocks this watchdog (Round A3): a wedged
            // transport leaves the stamp to go stale, which isHealthy() reads.
            v3.requestStatus()
            if (!v3.isHealthy()) return false
            // Freshness alone was the 2026-08-07 blackout. The v3 document
            // carries the two counters the promotion gate itself is defined on,
            // so re-read them: the gate must still be carrying, and RxPackets
            // is cumulative, so this cannot tear down an idle tunnel that has
            // ever delivered.
            val status = try {
                WinnV3EngineStatus.parse(v3.statusJson())
            } catch (_: WinnV3StartRefusal) {
                // A status document this host cannot trust is not a healthy one.
                return false
            }
            // Round A2: a supervised engine says what it is doing, and a
            // correct recovery is not a dead engine. While it recovers there is
            // no carrying gate and no published counter by design, so the two
            // counters below would call every recovery window unhealthy and
            // tear the tunnel down 35 s into it. The watch is bounded twice:
            // the engine ends its own episode in `blocked`, and the host
            // ceiling ends one the engine cannot (WinnV3RecoveryCeiling).
            // Liveness is still checked above: a missing or stale status
            // document, or an exited process, is unhealthy whatever it said.
            // The watch and its owner, captured as one pair and validated as
            // that same pair at publication.
            val binding = synchronized(winnEngineLock) {
                winnV3LifecycleBinding.takeIf { it != null && !tearingDown && it.owner == tunnelGeneration }
            }
            val observation = binding?.watch?.observation(status, SystemClock.elapsedRealtime())
            val verdict = observation?.verdict
            if (binding != null && observation != null && verdict == WinnV3LifecycleWatch.Verdict.BLOCKED) {
                // Take a post-promotion end off the connected claim NOW, not a
                // poll later: the board is what isTunnelHealthy() and the
                // readiness map read. Same step, same pair.
                synchronized(winnEngineLock) {
                    WinnV3PostPromotionStep.publish(
                        board = winn3HostLifecycle,
                        binding = binding,
                        stillOwner = !tearingDown && winnV3LifecycleBinding === binding &&
                            binding.owner == tunnelGeneration,
                        observation = observation,
                    )
                }
            }
            when (verdict) {
                WinnV3LifecycleWatch.Verdict.CONNECTED,
                WinnV3LifecycleWatch.Verdict.RECOVERING -> return true
                // Blocked is not healthy, but it is not this check's to end
                // either: the engine thread ends the session on it, and that
                // teardown holds capture (WinnV3CaptureCustody).
                WinnV3LifecycleWatch.Verdict.BLOCKED -> return true
                WinnV3LifecycleWatch.Verdict.UNREPORTED, null -> Unit
            }
            if (status.gateState == null && status.rxPackets == 0L) {
                // Nothing was reported at all yet; no basis for a verdict.
                return true
            }
            return WinnV3PromotionGate.isProven(status)
        }
        val bridge = currentWinnBridge()
        if (bridge != null) {
            if (!isEngineReady) return false
            // Deliberately a round trip, not a process-existence check: a
            // subprocess that is alive but wedged is not a healthy tunnel.
            // The reply refreshes the freshness stamp isHealthy() reads.
            bridge.requestStatus()
            if (!bridge.isHealthy()) return false
            // ...and freshness alone was the root cause of the 2026-08-07
            // silent-blackout defect: an engine answering STATUS promptly while
            // carrying nothing passed this check forever. The document the
            // round trip above just refreshed also carries what actually
            // crossed, so read that too rather than only its timestamp.
            return winnDatapathIsCarrying(bridge.statusJson())
        }
        val handle = currentAwgHandle()
        if (handle < 0 || !isEngineReady) return false
        return try {
            AwgNativeApi.awgGetConfig(handle)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun readCurrentAwgPeerStats(): Map<String, Any> {
        val v3 = currentWinnV3Bridge()
        if (v3 != null) {
            if (!isEngineReady) return emptyAwgPeerStats()
            v3.requestStatus()
            return try {
                val status = WinnV3EngineStatus.parse(v3.statusJson())
                val isCarrying = status.gateState?.mayCarry() == true
                val hasDelivered = status.rxPackets > 0L

                val currentUidRx = android.net.TrafficStats.getUidRxBytes(android.os.Process.myUid())
                val currentUidTx = android.net.TrafficStats.getUidTxBytes(android.os.Process.myUid())
                if (tunnelStartUidRx < 0L && currentUidRx != android.net.TrafficStats.UNSUPPORTED.toLong()) {
                    tunnelStartUidRx = currentUidRx
                }
                if (tunnelStartUidTx < 0L && currentUidTx != android.net.TrafficStats.UNSUPPORTED.toLong()) {
                    tunnelStartUidTx = currentUidTx
                }

                val deltaRx = if (tunnelStartUidRx >= 0L && currentUidRx != android.net.TrafficStats.UNSUPPORTED.toLong() && currentUidRx >= tunnelStartUidRx) {
                    currentUidRx - tunnelStartUidRx
                } else {
                    -1L
                }
                val deltaTx = if (tunnelStartUidTx >= 0L && currentUidTx != android.net.TrafficStats.UNSUPPORTED.toLong() && currentUidTx >= tunnelStartUidTx) {
                    currentUidTx - tunnelStartUidTx
                } else {
                    -1L
                }

                val rx = if (deltaRx >= 0L) {
                    if (hasDelivered) maxOf(1024L, deltaRx) else deltaRx
                } else {
                    maxOf(if (hasDelivered) 1024L else 0L, status.rxPackets * 128L)
                }

                val tx = if (deltaTx >= 0L) {
                    if (hasDelivered) maxOf(1024L, deltaTx) else deltaTx
                } else {
                    if (hasDelivered) 1024L else 0L
                }

                mapOf(
                    "handshake_recent" to (isCarrying && hasDelivered),
                    "handshake_age_ms" to (if (isCarrying && hasDelivered) 0L else -1L),
                    "rx_bytes" to rx,
                    "tx_bytes" to tx,
                )
            } catch (_: Exception) {
                emptyAwgPeerStats()
            }
        }
        val v1 = currentWinnBridge()
        if (v1 != null) {
            if (!isEngineReady) return emptyAwgPeerStats()
            v1.requestStatus()
            val carrying = winnDatapathIsCarrying(v1.statusJson())
            return if (carrying) {
                val currentUidRx = android.net.TrafficStats.getUidRxBytes(android.os.Process.myUid())
                val currentUidTx = android.net.TrafficStats.getUidTxBytes(android.os.Process.myUid())
                if (tunnelStartUidRx < 0L && currentUidRx != android.net.TrafficStats.UNSUPPORTED.toLong()) {
                    tunnelStartUidRx = currentUidRx
                }
                if (tunnelStartUidTx < 0L && currentUidTx != android.net.TrafficStats.UNSUPPORTED.toLong()) {
                    tunnelStartUidTx = currentUidTx
                }
                val deltaRx = if (tunnelStartUidRx >= 0L && currentUidRx != android.net.TrafficStats.UNSUPPORTED.toLong() && currentUidRx >= tunnelStartUidRx) {
                    currentUidRx - tunnelStartUidRx
                } else {
                    -1L
                }
                val deltaTx = if (tunnelStartUidTx >= 0L && currentUidTx != android.net.TrafficStats.UNSUPPORTED.toLong() && currentUidTx >= tunnelStartUidTx) {
                    currentUidTx - tunnelStartUidTx
                } else {
                    -1L
                }
                mapOf(
                    "handshake_recent" to true,
                    "handshake_age_ms" to 0L,
                    "rx_bytes" to if (deltaRx >= 0L) maxOf(1024L, deltaRx) else 1024L,
                    "tx_bytes" to if (deltaTx >= 0L) maxOf(1024L, deltaTx) else 1024L,
                )
            } else {
                emptyAwgPeerStats()
            }
        }
        val handle = currentAwgHandle()
        if (handle < 0 || !isEngineReady) return emptyAwgPeerStats()
        return try {
            val config = AwgNativeApi.awgGetConfig(handle) ?: return emptyAwgPeerStats()
            var latestHandshakeSeconds = 0L
            var receivedBytes = 0L
            var transmittedBytes = 0L
            for (line in config.lineSequence()) {
                when {
                    line.startsWith("last_handshake_time_sec=") -> {
                        val value = line.substringAfter('=').toLongOrNull() ?: 0L
                        latestHandshakeSeconds = maxOf(latestHandshakeSeconds, value)
                    }
                    line.startsWith("rx_bytes=") -> {
                        receivedBytes += line.substringAfter('=').toLongOrNull() ?: 0L
                    }
                    line.startsWith("tx_bytes=") -> {
                        transmittedBytes += line.substringAfter('=').toLongOrNull() ?: 0L
                    }
                }
            }
            val nowSeconds = System.currentTimeMillis() / 1000L
            val ageMs = if (latestHandshakeSeconds > 0L) {
                maxOf(0L, nowSeconds - latestHandshakeSeconds) * 1000L
            } else {
                -1L
            }
            mapOf(
                "handshake_recent" to (ageMs in 0L..180_000L),
                "handshake_age_ms" to ageMs,
                "rx_bytes" to receivedBytes,
                "tx_bytes" to transmittedBytes,
            )
        } catch (_: Exception) {
            emptyAwgPeerStats()
        }
    }

    /**
     * THE ONE PLACE IN THE TUNNEL PATH WHERE THE FAILURE IS AN `Error`.
     *
     * `System.loadLibrary` does not throw an `Exception` when the `.so` is
     * absent for this device's ABI -- it throws `UnsatisfiedLinkError`, which
     * is an `Error`. Both engine run loops that reach here
     * ([startAwgEngineThread] and [startWinnEngineThread]) are wrapped in
     * `catch (e: Exception)`, so before this `try` the `Error` walked straight
     * past both of them, out of a bare `Thread {}` with no uncaught handler.
     *
     * That was worse than a crash. The handler it skipped is the one that calls
     * [clearRestartConfig] -- so the service died with its restart
     * configuration intact and came back to load the same missing library
     * again, indefinitely, while [executeTunnelTeardown] never ran and the
     * VpnService stayed up around a dead engine.
     *
     * Rethrown as `IOException` rather than widening either catch to
     * `Throwable`: this is the only `Error` those loops can produce that means
     * "this tunnel cannot start", and it is a device/packaging fact, not a bug
     * in the run loop. Both loops already treat `IOException` as exactly that.
     * Widening the catches instead would have swallowed `OutOfMemoryError` and
     * `StackOverflowError` into a tunnel teardown that then tries to allocate.
     *
     * Sibling of the `WinnCarrierProfile.isOwnerOnly` API-26 defect fixed in the
     * same lane -- see `docs/handoff/ANDROID_LINT_FINDINGS_20260808.md`. Same
     * shape both times: an `Error` reaching a handler written for `Exception`.
     */
    private fun ensureAwgNativeLoaded() {
        if (awgNativeLoaded) return
        synchronized(VpnTunnelService::class.java) {
            if (!awgNativeLoaded) {
                try {
                    System.loadLibrary("am-go")
                } catch (e: UnsatisfiedLinkError) {
                    throw IOException(
                        "The AmneziaWG native library (am-go) is not present for this " +
                            "device's ABI; the tunnel engine cannot start.",
                        e,
                    )
                }
                awgNativeLoaded = true
            }
        }
    }

    private fun acquireTunnelPerformanceLocks() {
        acquireTunnelWakeLock()
        acquireTunnelWifiLock()
    }

    private fun releaseTunnelPerformanceLocks() {
        releaseTunnelWakeLock()
        releaseTunnelWifiLock()
    }

    private fun acquireTunnelWifiLock() {
        try {
            if (tunnelWifiLock?.isHeld == true) return
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager ?: return
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
            } else {
                @Suppress("DEPRECATION")
                android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF
            }
            tunnelWifiLock = wifiManager.createWifiLock(mode, "Calc:Net").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (e: Exception) {
            logWarning("VPN wifi lock is unavailable", e)
        }
    }

    private fun releaseTunnelWifiLock() {
        try {
            tunnelWifiLock?.takeIf { it.isHeld }?.release()
        } catch (e: Exception) {
            logWarning("VPN wifi lock release was incomplete", e)
        } finally {
            tunnelWifiLock = null
        }
    }

    private fun acquireTunnelWakeLock() {
        try {
            if (tunnelWakeLock?.isHeld == true) return
            val powerManager = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            tunnelWakeLock = powerManager.newWakeLock(
                android.os.PowerManager.PARTIAL_WAKE_LOCK,
                "Calc:Worker"
            ).apply {
                setReferenceCounted(false)
                // Untimed, for the life of the tunnel. A timed acquire lapses
                // 60s into every session and hands the SoC back to cpuidle,
                // which puts C-state exit latency on the uplink poll-to-notify
                // handoff for the entire rest of the transfer. The WifiLock
                // beside this one is already held untimed for the same reason.
                acquire()
            }
        } catch (e: Exception) {
            logWarning("VPN wake lock is unavailable", e)
        }
    }

    private fun releaseTunnelWakeLock() {
        try {
            tunnelWakeLock?.takeIf { it.isHeld }?.release()
        } catch (e: Exception) {
            logWarning("VPN wake lock release was incomplete", e)
        } finally {
            tunnelWakeLock = null
        }
    }

    private fun applyUnderlyingNetworkHints(builder: Builder) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return
        try {
            val underlying = currentBestUnderlyingNetwork()
            if (underlying != null) {
                builder.setUnderlyingNetworks(arrayOf(underlying))
                lastUnderlyingNetwork = underlying
                lastUnderlyingTransport = networkTransportName(underlying)
                debugLog("Underlying network hint set for $lastUnderlyingTransport transport.")
            } else {
                builder.setUnderlyingNetworks(null)
                lastUnderlyingNetwork = null
                lastUnderlyingTransport = "none"
                debugLog("No active non-VPN underlying network is available.")
            }
        } catch (e: Exception) {
            logWarning("Underlying network hint was skipped", e)
        }
    }

    private fun currentBestUnderlyingNetwork(): Network? {
        val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = connectivity.activeNetwork
        val candidates = connectivity.allNetworks
            .mapNotNull { network -> scoreUnderlyingNetwork(connectivity, network, active) }
        val validated = candidates.filter { candidate ->
            connectivity.getNetworkCapabilities(candidate.network)
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        }
        return (validated.ifEmpty { candidates })
            .maxWithOrNull(
                compareBy<UnderlyingNetworkCandidate> { it.score }
                    .thenBy { if (it.network == lastUnderlyingNetwork) 1 else 0 }
            )
            ?.network
    }

    private fun scoreUnderlyingNetwork(
        connectivity: ConnectivityManager,
        network: Network,
        active: Network?
    ): UnderlyingNetworkCandidate? {
        val caps = connectivity.getNetworkCapabilities(network) ?: return null
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        ) {
            return null
        }
        if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) {
            return null
        }

        val transportScore = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 300
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 200
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 100
            else -> return null
        }

        val score = transportScore +
            (if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 4_000 else 0) +
            (if (network == active && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) 1_000 else 0) +
            (if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)) 25 else 0) +
            (if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED)) 10 else 0)

        return UnderlyingNetworkCandidate(
            network = network,
            score = score
        )
    }

    private fun networkTransportName(network: Network): String {
        return try {
            val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val caps = connectivity.getNetworkCapabilities(network)
            transportName(caps)
        } catch (_: Exception) {
            "unknown"
        }
    }

    private fun transportName(caps: NetworkCapabilities?): String {
        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ethernet"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
            else -> "unknown"
        }
    }

    private fun refreshUnderlyingNetworkHint(reason: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1 || !isServiceActive) return
        try {
            val underlying = currentBestUnderlyingNetwork()
            if (underlying == lastUnderlyingNetwork) return
            if (underlying != null) {
                if (!setUnderlyingNetworks(arrayOf(underlying))) {
                    logWarning(
                        "Android rejected the underlying network switch after $reason."
                    )
                    return
                }
                lastUnderlyingNetwork = underlying
                lastUnderlyingTransport = networkTransportName(underlying)
                debugLog("Underlying network switched to $lastUnderlyingTransport after $reason.")
            } else {
                if (!setUnderlyingNetworks(null)) {
                    logWarning(
                        "Android rejected clearing the underlying network after $reason."
                    )
                    return
                }
                lastUnderlyingNetwork = null
                lastUnderlyingTransport = "none"
                debugLog("Underlying network cleared after $reason.")
            }
        } catch (e: Exception) {
            logWarning("Underlying network refresh was skipped", e)
        }
    }

    private fun scheduleUnderlyingNetworkRefresh(reason: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1 || !isServiceActive) return
        val generation = tunnelGeneration
        val token = synchronized(this) {
            handoffRefreshToken += 1
            handoffRefreshToken
        }
        longArrayOf(750L, 2_500L, 6_000L).forEach { delayMs ->
            handoffHandler.postDelayed({
                if (
                    isServiceActive &&
                    !tearingDown &&
                    generation == tunnelGeneration &&
                    token == handoffRefreshToken
                ) {
                    refreshUnderlyingNetworkHint("$reason delayed ${delayMs}ms")
                }
            }, delayMs)
        }
    }

    private fun registerNetworkHandoffCallback() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1 || networkCallback != null) return
        try {
            val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    refreshUnderlyingNetworkHint("network available")
                    scheduleUnderlyingNetworkRefresh("network available")
                }

                override fun onLost(network: Network) {
                    refreshUnderlyingNetworkHint("network lost")
                    scheduleUnderlyingNetworkRefresh("network lost")
                }

                override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                    refreshUnderlyingNetworkHint("network capabilities changed")
                    scheduleUnderlyingNetworkRefresh("network capabilities changed")
                }

                override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                    refreshUnderlyingNetworkHint("network link changed")
                    scheduleUnderlyingNetworkRefresh("network link changed")
                }
            }
            connectivity.registerNetworkCallback(request, callback)
            networkCallback = callback
            debugLog("Network handoff callback registered.")
        } catch (e: Exception) {
            logWarning("Network handoff callback registration was skipped", e)
        }
    }

    private fun unregisterNetworkHandoffCallback() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return
        val callback = networkCallback ?: return
        try {
            val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            connectivity.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            logWarning("Network handoff callback unregister was skipped", e)
        } finally {
            networkCallback = null
        }
    }

    private fun setTunnelThreadPriority(priority: Int) {
        try {
            android.os.Process.setThreadPriority(priority)
        } catch (e: Exception) {
            logWarning("VPN thread priority was unchanged", e)
        }
    }

    override fun onRevoke() {
        // On revoke the OS has already torn the interface and the user has
        // withdrawn VPN authorization, so no blocking interface can be (re)
        // established and holding the posture would be a lie. Tear down plainly.
        clearRestartConfig()
        // Outranks an automatic Winn v3 capture hold, including one still
        // being built by an in-flight teardown (WinnV3CaptureCustody).
        executeTunnelTeardown(allowBlockPosture = false, cause = WinnV3TeardownCause.OS_REVOKE)
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: android.content.Intent?) {
        if (isServiceActive && !tearingDown) {
            debugLog("Task removed while VPN service remains active.")
            // Swiping the task away is one of the moments the decoy re-arms, so
            // this re-post is also a camouflage reconciliation. Same refusal as
            // at connect time if the channel will not take the decoy's name.
            if (!startAsForegroundService()) executeTunnelTeardown()
            return
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        // The process itself is being destroyed; a blocking interface cannot
        // outlive its owner, so holding the posture here would accomplish
        // nothing (the tun closes with the process). Tear down plainly.
        executeTunnelTeardown(allowBlockPosture = false, cause = WinnV3TeardownCause.PROCESS_DESTROY)
        if (activeInstance === this) activeInstance = null
        super.onDestroy()
    }

    // The foreground-service notification is mandatory and always visible
    // while the tunnel runs (Android will not let a foreground service hide
    // it), so it must match whichever launcher identity is currently active
    // rather than always announcing the real name -- otherwise the disguise
    // is defeated by the one always-on system surface neither the app nor
    // the OS lets the user dismiss.
    private fun isDecoyLauncherActive(): Boolean = decoyLauncherIsActive(this)

    /// The name Android renders in Settings > Network & internet > VPN and in
    /// the system's own VPN status surfaces. Previously hardcoded to
    /// "WinsVPN", which announced the real identity on a system screen the
    /// disguise otherwise covers.
    ///
    /// Uses the sticky enrollment flag rather than the live decoy state --
    /// see `markCamouflageEnrolled` for why the momentary state is the wrong
    /// input for a value the OS latches at `establish()` and never re-reads.
    private fun vpnSessionName(): String {
        return vpnSessionNameFor(
            camouflageEnrolled = isCamouflageEnrolled(this),
            decoyActive = isDecoyLauncherActive(),
        )
    }

    // TV form-factor detection. Same pair as MainActivity.isTelevision:
    // UiModeManager TELEVISION on real TVs, FEATURE_LEANBACK for Play TV
    // devices. Either true means camouflage must never be armed - the decoy
    // calculator has no D-pad focus handling and would lock the user out.
    private fun isTelevision(): Boolean {
        try {
            val uiModeManager = getSystemService(Context.UI_MODE_SERVICE) as? android.app.UiModeManager
            if (uiModeManager?.currentModeType == android.content.res.Configuration.UI_MODE_TYPE_TELEVISION) {
                return true
            }
        } catch (_: Exception) {}
        try {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)) {
                return true
            }
        } catch (_: Exception) {}
        return false
    }

    private fun setLauncherComponentState(showRealVpn: Boolean) {
        if (isTelevision()) return
        try {
            // Teardown defaults keepVpnLauncher=false and would enable
            // LauncherDecoy after a session. On TV that is a lock-out, so
            // force the real launcher regardless of the caller.
            val showReal = showRealVpn || isTelevision()
            val pm = packageManager
            val realComponent = ComponentName(this, "$packageName.LauncherReal")
            val decoyComponent = ComponentName(this, "$packageName.LauncherDecoy")
            if (showReal) {
                pm.setComponentEnabledSetting(realComponent, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
                pm.setComponentEnabledSetting(decoyComponent, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            } else {
                pm.setComponentEnabledSetting(decoyComponent, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
                pm.setComponentEnabledSetting(realComponent, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            }
        } catch (e: Exception) {
            logError("Failed to update launcher component state", e)
        }
    }

    private fun applyUserExcludedApplications(builder: Builder, appSection: Map<String, String>) {
        val packages = appSection["excludedpackages"]
            ?.split(",")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() && it != packageName }
            ?.distinct()
            ?: emptyList()

        for (excludedPackage in packages) {
            try {
                builder.addDisallowedApplication(excludedPackage)
                debugLog("Applied a user-selected split-tunnel exclusion.")
            } catch (e: PackageManager.NameNotFoundException) {
                logWarning("Skipped a split-tunnel package that is no longer installed.")
            } catch (e: Exception) {
                logError("Failed to apply a split-tunnel exclusion.", e)
                throw IllegalStateException("Android refused a required split-tunnel package exclusion", e)
            }
        }
    }

    private fun parseConfigValue(config: String?, key: String): String? {
        if (config == null) return null
        val lines = config.split("\n")
        var currentSection = ""
        for (line in lines) {
            val trimmedLine = line.trim()
            if (trimmedLine.startsWith("[") && trimmedLine.endsWith("]")) {
                currentSection = trimmedLine.lowercase()
                continue
            }

            val isCorrectSection = when (key.lowercase()) {
                "address", "dns", "mtu", "privatekey", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4" -> currentSection == "[interface]"
                "publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive" -> currentSection == "[peer]"
                else -> true
            }

            if (isCorrectSection && trimmedLine.contains("=")) {
                val parts = trimmedLine.split("=", limit = 2)
                if (parts.size > 1 && parts[0].trim().equals(key, ignoreCase = true)) {
                    return parts[1].trim()
                }
            }
        }
        return null
    }

    private fun parseConfigSection(config: String, sectionName: String): Map<String, String> =
        parseConfigSectionOf(config, sectionName)

    private fun stripConfigSection(config: String, sectionName: String): String {
        val out = StringBuilder()
        var skip = false
        for (line in config.split("\n")) {
            val trimmed = line.trim()
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                skip = trimmed.removePrefix("[").removeSuffix("]").equals(sectionName, ignoreCase = true)
            }
            if (!skip) out.append(line).append('\n')
        }
        return out.toString().trim()
    }

    private fun parseBool(value: String?): Boolean {
        val v = value?.trim()?.lowercase() ?: return false
        return v == "true" || v == "1" || v == "yes" || v == "y"
    }

    private fun debugLog(message: String) {
        Log.i(VpnTunnelService.LOG_TAG, message)
    }

    /**
     * The throwable, rendered so a RELEASE logcat actually carries it.
     *
     * MEASURED DEFECT, Motorola edge plus 2023 (ZY22GTV6Z3), Android 14,
     * 2026-09-15. [logError] and [logWarning] gated the `Throwable` overload of
     * `Log.e`/`Log.w` on `BuildConfig.DEBUG`, so the installed release build
     * printed "Winn Protocol v3 engine stopped unexpectedly" and discarded the
     * exception type, its message and its whole cause chain.
     *
     * That is not a logging nicety on this path. [startWinnV3EngineThread] is
     * ONE `try` wrapped around session planning, the posture refusals, the key
     * document, the capability probe, the bridge and the staged start, and
     * every one of those failures lands on that single line. Without the
     * throwable they are one indistinguishable string, and the protocol then
     * falls back to AmneziaWG on a reason nobody can read: a silent downgrade
     * of the user's transport, diagnosed from an empty message.
     *
     * The chain is walked under an IDENTITY set, not a hash set. `equals` on a
     * Throwable is identity by default but is overridable, and `initCause(this)`
     * and mutually-referencing causes both occur in the wild; either would spin
     * here forever. The depth bound is the second guard.
     *
     * Every refusal string in this tree is written to be read in a log (see
     * `WinnV3Keys.describeForLog`, which names fields and never their bytes), so
     * promoting them out of the debug build leaks no key material.
     */
    private fun describeThrowable(error: Throwable): String {
        val chain = StringBuilder()
        val seen = java.util.Collections.newSetFromMap(
            java.util.IdentityHashMap<Throwable, Boolean>()
        )
        var current: Throwable? = error
        var depth = 0
        while (current != null && seen.add(current) && depth < MAX_LOGGED_CAUSE_DEPTH) {
            if (depth > 0) chain.append(" <- ")
            chain.append(current.javaClass.name)
            val text = current.message
            // Release keeps the type chain and the throw site, which is what
            // tells the failures apart. Messages carry addresses, hostnames
            // and config lines, so only a debug build prints them.
            if (BuildConfig.DEBUG && !text.isNullOrBlank()) {
                chain.append(": ").append(text.take(MAX_LOGGED_MESSAGE_CHARS))
            }
            current.stackTrace.firstOrNull()?.let { chain.append(" at ").append(it) }
            current = current.cause
            depth++
        }
        if (current != null) chain.append(" <- (cause chain truncated)")
        return chain.toString()
    }

    private fun logWarning(message: String, error: Throwable? = null) {
        if (error == null) {
            Log.w(VpnTunnelService.LOG_TAG, message)
        } else {
            Log.w(LOG_TAG, "$message: ${describeThrowable(error)}", if (BuildConfig.DEBUG) error else null)
        }
    }

    private fun logError(message: String, error: Throwable? = null) {
        if (error == null) {
            Log.e(VpnTunnelService.LOG_TAG, message)
        } else {
            Log.e(LOG_TAG, "$message: ${describeThrowable(error)}", if (BuildConfig.DEBUG) error else null)
        }
    }
}

/**
 * Phone and TV [MainActivity] callers pass the user-selected node as an Intent
 * extra so [WinnV3SessionPlan.from] does not bind a signed descriptor only to
 * identities the served INI itself claims.
 *
 * A first-wins read of method-argument aliases, a `.toString()` of a nested
 * map, or a Unicode case fold onto the descriptor `node` is a substitution
 * hole. All present identities must agree; missing or invalid is empty, and
 * empty refuses a v3 start.
 */
internal object WinnV3SelectedNodeCaller {
    const val EXTRA_SELECTED_NODE = "WINN3_SELECTED_NODE"

    val METHOD_ARGUMENT_KEYS: List<String> = (
        WinnV3SessionPlan.SELECTED_NODE_IDENTITY_KEYS +
            listOf("selectedNode", "winn3SelectedNode", "winn3_selected_node")
        ).distinct()

    private val nestedSlugKeys = listOf(
        "slug",
        "node_slug",
        "nodeslug",
        "location_slug",
        "locationslug",
    )

    private class IdentityRead(val present: Boolean, val value: String?)

    fun methodHasIdentityArgument(arguments: Any?): Boolean {
        val map = arguments as? Map<*, *> ?: return false
        for (key in METHOD_ARGUMENT_KEYS) {
            if (!map.containsKey(key)) continue
            if (readValue(map[key]).present) return true
        }
        return false
    }

    fun resolveFromStartTunnel(arguments: Any?, config: String): String {
        val caller = identityFromMap(arguments as? Map<*, *>)
        if (!caller.present || caller.value == null) return ""
        return agree(caller, identityFromWinnConfig(config))
    }

    fun planningSection(section: Map<String, String>, extra: String?): Map<String, String>? {
        val caller = readString(extra)
        // The Intent extra is the phone/TV caller identity. A served INI
        // `selected_node` that merely repeats the descriptor `node` is not
        // enough: that is the self-claim this overlay exists to bind against.
        if (!caller.present || caller.value == null) return null
        val agreed = agree(caller, identityFromSection(section))
        if (agreed.isEmpty()) return null
        val bound = bindToSection(section, agreed) ?: return null
        if (!WinnV3SessionPlan.descriptorMatchesSelectedNode(bound)) return null
        return bound
    }

    fun bindToSection(
        section: Map<String, String>,
        callerIdentity: String,
    ): Map<String, String>? {
        val normalized = WinnV3SessionPlan.normalizedNodeIdentity(callerIdentity) ?: return null
        val bound = LinkedHashMap(section)
        bound[WinnV3SessionPlan.KEY_SELECTED_NODE] = normalized
        if (WinnV3SessionPlan.selectedNodeIdentity(bound) != normalized) return null
        return bound
    }

    private fun identityFromMap(map: Map<*, *>?): IdentityRead {
        if (map == null) return IdentityRead(present = false, value = null)
        var bound: String? = null
        var sawPresent = false
        for (key in METHOD_ARGUMENT_KEYS) {
            if (!map.containsKey(key)) continue
            val read = readValue(map[key])
            if (!read.present) continue
            sawPresent = true
            val value = read.value ?: return IdentityRead(present = true, value = null)
            if (bound == null) {
                bound = value
            } else if (bound != value) {
                return IdentityRead(present = true, value = null)
            }
        }
        if (!sawPresent) return IdentityRead(present = false, value = null)
        return IdentityRead(present = true, value = bound)
    }

    private fun identityFromWinnConfig(config: String): IdentityRead {
        return identityFromSection(parseWinnSection(config))
    }

    private fun identityFromSection(section: Map<String, String>): IdentityRead {
        var bound: String? = null
        var sawPresent = false
        for (key in WinnV3SessionPlan.SELECTED_NODE_IDENTITY_KEYS) {
            if (!section.containsKey(key)) continue
            val read = readString(section[key])
            if (!read.present) continue
            sawPresent = true
            val value = read.value ?: return IdentityRead(present = true, value = null)
            if (bound == null) {
                bound = value
            } else if (bound != value) {
                return IdentityRead(present = true, value = null)
            }
        }
        if (!sawPresent) return IdentityRead(present = false, value = null)
        return IdentityRead(present = true, value = bound)
    }

    private fun agree(vararg reads: IdentityRead): String {
        var bound: String? = null
        var sawPresent = false
        for (read in reads) {
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

    private fun readValue(raw: Any?): IdentityRead {
        if (raw == null) return IdentityRead(present = false, value = null)
        if (raw is String) return readString(raw)
        if (raw is Map<*, *>) {
            var bound: String? = null
            var sawSlug = false
            for (key in nestedSlugKeys) {
                if (!raw.containsKey(key)) continue
                val nested = raw[key] ?: continue
                sawSlug = true
                if (nested !is String) {
                    return IdentityRead(present = true, value = null)
                }
                val read = readString(nested)
                if (!read.present || read.value == null) {
                    return IdentityRead(present = true, value = null)
                }
                val value = read.value
                if (bound == null) {
                    bound = value
                } else if (bound != value) {
                    return IdentityRead(present = true, value = null)
                }
            }
            if (!sawSlug || bound == null) {
                return IdentityRead(present = true, value = null)
            }
            return IdentityRead(present = true, value = bound)
        }
        return IdentityRead(present = true, value = null)
    }

    private fun readString(raw: String?): IdentityRead {
        if (raw == null) return IdentityRead(present = false, value = null)
        if (raw.any { it.code > 0x7F }) {
            return IdentityRead(present = true, value = null)
        }
        if (raw.trim().isEmpty()) {
            return IdentityRead(present = false, value = null)
        }
        val normalized = WinnV3SessionPlan.normalizedNodeIdentity(raw)
        return if (normalized == null) {
            IdentityRead(present = true, value = null)
        } else {
            IdentityRead(present = true, value = normalized)
        }
    }

    private fun parseWinnSection(config: String): Map<String, String> {
        val out = linkedMapOf<String, String>()
        var inSection = false
        for (line in config.split("\n")) {
            val trimmed = line.trim()
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                inSection = trimmed.removePrefix("[").removeSuffix("]")
                    .equals(WinnEngineConfig.SECTION, ignoreCase = true)
                continue
            }
            if (inSection && trimmed.contains("=")) {
                val parts = trimmed.split("=", limit = 2)
                out[parts[0].trim().lowercase()] = parts[1].trim()
            }
        }
        return out
    }
}
