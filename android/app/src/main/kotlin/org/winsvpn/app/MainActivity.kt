package org.winsvpn.app

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.provider.Settings
import android.app.UiModeManager
import android.content.res.Configuration
import android.telephony.SmsManager
import android.util.Log
import android.view.View
import android.view.WindowManager
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsControllerCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink

class MainActivity : FlutterActivity() {
    private val CHANNEL = "wins_vpn/tunnel"
    private val ANNOUNCEMENT_CHANNEL_ID = "wins_vpn_announcements"
    private val VPN_REQUEST_CODE = 2424
    private val DURESS_SMS_PERMISSION_REQUEST_CODE = 2727
    private var pendingConfig: String? = null
    private var pendingWinn3StartToken: Long? = null
    private var pendingWinn3StartGeneration: Long? = null
    private var pendingWinn3SelectionGeneration: String? = null
    private var pendingWinn3FailedNode: String? = null
    private var pendingWinn3CoverAuthToken: Long? = null
    private var pendingWinn3CoverTarget: String? = null
    private var pendingWinn3CoverLeg: String? = null
    private var pendingWinn3SelectedNode: String? = null
    private var pendingDoubleVpnHandoverToken: Long? = null
    private var pendingResult: MethodChannel.Result? = null
    private var vpnAuthorizationPending = false
    private var lastTunnelStartRequestAtMs = 0L
    // Held between requestDuressSmsPermission and onRequestPermissionsResult so
    // Dart learns the user's ACTUAL SEND_SMS decision (a decline is first-class).
    private var pendingSmsPermissionResult: MethodChannel.Result? = null
    private val secureFileStore by lazy {
        SecureFileStore.forApplication(applicationContext)
    }
    private val GENERIC_BROWSER_USER_AGENT = "Mozilla/5.0"
    private val speedTestUploadChunk = ByteArray(128 * 1024) { 0x5A.toByte() }
    // Unbounded on purpose: every Dart caller awaits its own reply before it
    // asks again, so the queue never holds more than one request per caller.
    private val readinessExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
    private val speedTestGeneration = AtomicLong(0L)
    private val activeSpeedTestConnections =
        ConcurrentHashMap.newKeySet<HttpURLConnection>()
    private val activeSpeedTestCalls =
        ConcurrentHashMap.newKeySet<Call>()
    private val ingestTag = VpnTunnelService.LOG_TAG

    override fun onCreate(savedInstanceState: Bundle?) {
        // Neither the real dashboard nor the decoy calculator may ever appear
        // in a Recents/Overview thumbnail or a screenshot/screen recording:
        // FLAG_SECURE makes the OS render both as blank, closing this off at
        // the platform level instead of racing an async Dart state update
        // against the OS's own snapshot timing on every background transition.
        if (!BuildConfig.DEBUG) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }
        WindowCompat.setDecorFitsSystemWindows(window, false)
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }
        super.onCreate(savedInstanceState)
        if (!BuildConfig.DEBUG) {
            window.decorView.filterTouchesWhenObscured = true
        }
        // M-13: the launcher-alias swap alone does not change what the
        // Overview/Recents card shows for this task -- that is keyed off this
        // Activity's own task description. Apply it as soon as the Activity
        // (re)starts (e.g. after process death while the decoy was armed) so
        // Recents never has a window where it reflects the real identity
        // while the calculator decoy is supposed to be in effect. An enrolled
        // install is disguised here even with the decoy momentarily down,
        // because this card can outlive the process that drew it.
        applyTaskIdentity(decoyActive = isDecoyLauncherActive())
        // The announcement channel latches its name in Settings and nothing
        // else ever revisits it, so reconcile it on every start. This is what
        // catches the install that was announced to BEFORE the user enrolled
        // in camouflage: no announcement need ever arrive again for the real
        // name to disappear from Settings > Apps > Calculator > Notifications.
        refreshAnnouncementChannelForCamouflage()
        // The tunnel's own channel row latches the same way and was left
        // behind by the same reasoning. Its in-service refresh hook only works
        // through a live service instance, so it cannot reach the install that
        // connected once before enrolling and has been disconnected ever since
        // -- which is precisely the install carrying the real name. Reconciled
        // here, with no tunnel in sight.
        VpnTunnelService.refreshTunnelChannelForCamouflage(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            window.decorView.importantForAutofill =
                View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "checkDialerLaunch" -> {
                    // The dialer shortcut may open the app, but it never bypasses the user's PIN.
                    result.success(false)
                }
                "getDeviceHardwareDetails" -> {
                    val manufacturer = Build.MANUFACTURER?.uppercase()?.ifBlank { "ANDROID" } ?: "ANDROID"
                    val model = Build.MODEL?.ifBlank { "DEVICE" } ?: "DEVICE"
                    // Deliberately no hardware identifier here. Device identity is
                    // the random per-install ID generated in Dart
                    // (_loadOrCreateInstallId); that is what every privacy
                    // disclosure describes and what the three-device limit is
                    // keyed on. Do not reintroduce Settings.Secure.ANDROID_ID or
                    // any hash of it -- doing so would re-identify every existing
                    // install and invalidate the published disclosures.
                    result.success(mapOf(
                        "device_model" to "$manufacturer $model".trim(),
                        "app_version" to BuildConfig.VERSION_NAME,
                    ))
                }
                "getAppDocumentsDirectory" -> {
                    val directory = File(applicationInfo.dataDir, "app_flutter")
                    directory.mkdirs()
                    result.success(directory.absolutePath)
                }
                "sealAccountStartsForRecovery" -> {
                    runSecureStorageOperation(result) {
                        secureFileStore.sealAccountStartsForRecovery()
                    }
                }
                "resetAllLocalAccountData" -> {
                    runSecureStorageOperation(result) {
                        secureFileStore.resetAllLocalAccountData()
                    }
                }
                "closeAfterAccountRecovery" -> {
                    result.success(true)
                    finishAndRemoveTask()
                    android.os.Process.killProcess(android.os.Process.myPid())
                }
                "readSecureText" -> {
                    val name = call.argument<String>("name").orEmpty()
                    runSecureStorageOperation(result) {
                        secureFileStore.read(name, legacyAppFile(name))
                    }
                }
                "writeSecureText" -> {
                    val name = call.argument<String>("name").orEmpty()
                    val value = call.argument<String>("value")
                    if (value == null) {
                        result.error("BAD_ARGS", "Secure value is missing", null)
                    } else {
                        runSecureStorageOperation(result) {
                            secureFileStore.write(name, value)
                            true
                        }
                    }
                }
                "deleteSecureText" -> {
                    val name = call.argument<String>("name").orEmpty()
                    runSecureStorageOperation(result) {
                        secureFileStore.delete(name, legacyAppFile(name))
                    }
                }
                "getInstalledApps" -> {
                    Thread {
                        try {
                            val apps = loadInstalledAppsForSplitTunnel()
                            runOnUiThread { result.success(apps) }
                        } catch (e: Exception) {
                            Log.w(VpnTunnelService.LOG_TAG, "Installed-app list unavailable")
                            runOnUiThread {
                                result.error("APP_LIST_FAILED", "Installed-app list unavailable", null)
                            }
                        }
                    }.apply {
                        name = "Calc-App-List"
                        isDaemon = true
                        start()
                    }
                }
                "launchExternalUrl" -> {
                    val url = call.argument<String>("url").orEmpty()
                    try {
                        val uri = Uri.parse(url)
                        if (!isAllowedExternalUri(uri)) {
                            result.success(false)
                            return@setMethodCallHandler
                        }
                        val launchIntent = Intent(Intent.ACTION_VIEW, uri).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        if (launchIntent.resolveActivity(packageManager) != null) {
                            startActivity(launchIntent)
                            result.success(true)
                        } else {
                            result.success(false)
                        }
                    } catch (_: Exception) {
                        result.success(false)
                    }
                }
                "shareText" -> {
                    val text = call.argument<String>("text").orEmpty()
                    val title = call.argument<String>("title").orEmpty().ifBlank { "Share" }
                    if (text.isBlank()) {
                        result.success(false)
                    } else {
                        try {
                            val sendIntent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, text)
                            }
                            val chooser = Intent.createChooser(sendIntent, title).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            startActivity(chooser)
                            result.success(true)
                        } catch (_: Exception) {
                            result.success(false)
                        }
                    }
                }
                "showAnnouncementNotification" -> {
                    val title = call.argument<String>("title").orEmpty()
                        .ifBlank { "Win's VPN Announcement" }
                    val body = call.argument<String>("body").orEmpty()
                    result.success(showAnnouncementNotification(title, body))
                }
                "getTunnelState" -> {
                    result.success(VpnTunnelService.isTunnelHealthy())
                }
                "monotonicMilliseconds" -> {
                    // M-15 support: the Dart PIN-lockout state machine needs a
                    // clock the user cannot rewind via device Settings, unlike
                    // DateTime.now(). elapsedRealtime() counts milliseconds
                    // since boot (including deep sleep) and is not
                    // user-adjustable.
                    result.success(android.os.SystemClock.elapsedRealtime())
                }
                "duressSmsCapability" -> {
                    // Enrollment UX only: tells Dart whether the device-native
                    // covert-SMS path can work here, so the enrollment screen can
                    // request the grant and warn honestly if SMS is impossible on
                    // this device. Never used on the arming path (that just calls
                    // sendDuressSms and treats false as "not delivered").
                    result.success(mapOf(
                        "has_telephony" to canOfferDuressSms(),
                        "can_offer_sms" to canOfferDuressSms(),
                        "has_permission" to hasSendSmsPermission(),
                    ))
                }
                "requestDuressSmsPermission" -> {
                    // Runtime request, made ONLY from duress enrollment (never at
                    // install/first launch). Resolves to the user's ACTUAL choice:
                    // the reply is held until onRequestPermissionsResult fires, so
                    // Dart can store a contact only when SMS was really granted.
                    // Declining is a first-class outcome (returns false), not an
                    // error.
                    when {
                        !canOfferDuressSms() -> result.success(false)
                        hasSendSmsPermission() -> result.success(true)
                        else -> {
                            // Resolve any stale pending request as declined before
                            // taking ownership of this one.
                            pendingSmsPermissionResult?.success(false)
                            pendingSmsPermissionResult = result
                            try {
                                requestPermissions(
                                    arrayOf(Manifest.permission.SEND_SMS),
                                    DURESS_SMS_PERMISSION_REQUEST_CODE,
                                )
                            } catch (_: Exception) {
                                pendingSmsPermissionResult = null
                                result.success(false)
                            }
                        }
                    }
                }
                "sendDuressSms" -> {
                    // DEVICE-NATIVE covert duress alert (Samsung-Emergency-SOS
                    // style). SmsManager.sendTextMessage/sendMultipartTextMessage
                    // transmits directly via the radio with NO compose UI and NO
                    // user tap. Because this app is NOT the default SMS handler,
                    // the send writes NOTHING to the system Messages/Sent store
                    // (only the default SMS app can write that store, Android
                    // 4.4+), so there is no on-device trace for an inspector to
                    // find. We deliberately do not insert the message into any
                    // system store ourselves (no ContentResolver write below).
                    val destination = call.argument<String>("destination").orEmpty()
                    val text = call.argument<String>("text").orEmpty()
                    sendDuressSms(destination, text, result)
                }
                "getPowerOptimizationStatus" -> {
                    result.success(powerOptimizationStatus())
                }
                "getTunnelReadiness" -> {
                    readinessExecutor.execute {
                        val payload = try {
                            buildTunnelReadiness()
                        } catch (e: Exception) {
                            null
                        }
                        runOnUiThread {
                            if (payload != null) {
                                result.success(payload)
                            } else {
                                result.error("READINESS_FAILED", "Tunnel readiness is unavailable", null)
                            }
                        }
                    }
                }
                "probeVpnInternet" -> {
                    probeVpnInternet(result)
                }
                "measureDownloadMbps" -> {
                    measureDownloadMbps(call.arguments, result)
                }
                "measureUploadMbps" -> {
                    measureUploadMbps(call.arguments, result)
                }
                "measureUploadViaTunnelIngest" -> {
                    measureUploadViaTunnelIngest(call.arguments, result)
                }
                "cancelSpeedTestMeasurements" -> {
                    cancelSpeedTestMeasurements()
                    result.success(true)
                }
                "startTunnel" -> {
                    if (secureFileStore.accountResetPending()) {
                        result.error(
                            "ACCOUNT_RESET_PENDING",
                            "Local account recovery requires restart",
                            null,
                        )
                        return@setMethodCallHandler
                    }
                    val configString = call.argument<String>("config")
                    if (configString.isNullOrBlank()) {
                        result.error("BAD_ARGS", "Configuration payload missing", null)
                        return@setMethodCallHandler
                    }
                    val rawHandoverToken = call.argument<Any>("doubleVpnHandoverToken")
                    val handoverToken = WinnV3MethodIdentity.exactPositiveLong(rawHandoverToken)
                    if (rawHandoverToken != null && handoverToken == null) {
                        result.error("BAD_ARGS", "Double VPN handover token must be a positive integer", null)
                        return@setMethodCallHandler
                    }
                    val rawWinn3StartToken = call.argument<Any>("winn3StartToken")
                    val rawWinn3StartGeneration = call.argument<Any>("winn3StartGeneration")
                    val winn3StartToken = WinnV3MethodIdentity.exactPositiveLong(rawWinn3StartToken)
                    val winn3StartGeneration =
                        WinnV3MethodIdentity.exactPositiveLong(rawWinn3StartGeneration)
                    val winn3SelectionGeneration = WinnV3MethodIdentity.exactSelectionGeneration(
                        call.argument<Any>("winn3SelectionGeneration"),
                    )
                    val winn3FailedNode = WinnV3MethodIdentity.exactNodeSlug(
                        call.argument<Any>("winn3FailedNode"),
                    )
                    val coverAuthToken = WinnV3MethodIdentity.exactPositiveLong(
                        call.argument<Any>("winn3AwgXrayAuthorizationToken"),
                    )
                    val coverTarget = WinnV3MethodIdentity.exactNodeSlug(
                        call.argument<Any>("winn3CoverExactTarget"),
                    )
                    val coverLeg = call.argument<Any>("winn3CoverLeg") as? String
                    val requestsWinn3 = WinnV3MethodIdentity.configRequestsV3(configString)
                    if ((requestsWinn3 || rawWinn3StartToken != null || rawWinn3StartGeneration != null) &&
                        (winn3StartToken == null || winn3StartGeneration == null)
                    ) {
                        result.error(
                            "BAD_ARGS",
                            "Winn v3 start token and transition generation must both be exact positive integers",
                            null,
                        )
                        return@setMethodCallHandler
                    }
                    val winn3SelectedNode = WinnV3SelectedNodeCaller.resolveFromStartTunnel(
                        arguments = call.arguments,
                        config = configString,
                    )
                    if ((requestsWinn3 ||
                            WinnV3SelectedNodeCaller.methodHasIdentityArgument(call.arguments)) &&
                        winn3SelectedNode.isEmpty()
                    ) {
                        result.error(
                            "BAD_ARGS",
                            "Winn v3 start requires the exact user-selected node identity",
                            null,
                        )
                        return@setMethodCallHandler
                    }
                    val now = android.os.SystemClock.elapsedRealtime()
                    if (pendingResult != null ||
                        vpnAuthorizationPending ||
                        now - lastTunnelStartRequestAtMs < 1_500L
                    ) {
                        Log.w(VpnTunnelService.LOG_TAG, "Duplicate tunnel start request ignored.")
                        result.error(
                            "CONNECT_IN_PROGRESS",
                            "A VPN connection attempt is already in progress",
                            null,
                        )
                        return@setMethodCallHandler
                    }
                    lastTunnelStartRequestAtMs = now
                    Log.i(VpnTunnelService.LOG_TAG, "Tunnel start request received.")
                    pendingConfig = configString
                    pendingWinn3StartToken = winn3StartToken
                    pendingWinn3StartGeneration = winn3StartGeneration
                    pendingWinn3SelectionGeneration = winn3SelectionGeneration
                    pendingWinn3FailedNode = winn3FailedNode
                    pendingWinn3CoverAuthToken = coverAuthToken
                    pendingWinn3CoverTarget = coverTarget
                    pendingWinn3CoverLeg = coverLeg
                    pendingWinn3SelectedNode = winn3SelectedNode.takeIf { it.isNotEmpty() }
                    pendingDoubleVpnHandoverToken = handoverToken
                    pendingResult = result
                    activateNativeVpnEngine()
                }
                "confirmDoubleVpnHandover" -> {
                    val token = WinnV3MethodIdentity.exactPositiveLong(call.argument<Any>("token"))
                    result.success(token != null && VpnTunnelService.confirmDoubleVpnHandover(token))
                }
                "stopTunnel" -> {
                    try {
                        // A disconnect can arrive while Android's VPN consent sheet is
                        // still open. Revoke ownership of that pending start before
                        // signalling the service; otherwise a later RESULT_OK would
                        // launch an obsolete tunnel after Dart already reported the
                        // connection as cancelled.
                        cancelPendingVpnAuthorization()
                        lastTunnelStartRequestAtMs = 0L
                        val keepVpnLauncher = call.argument<Boolean>("keepVpnLauncher") == true
                        val releaseBlock = call.argument<Boolean>("releaseKillSwitchBlock") == true
                        val disconnectIntent = Intent(this, VpnTunnelService::class.java).apply {
                            action = "ACTION_DISCONNECT"
                            putExtra("KEEP_VPN_LAUNCHER", keepVpnLauncher)
                            putExtra("RELEASE_KILL_SWITCH_BLOCK", releaseBlock)
                        }
                        startService(disconnectIntent)
                        val responded = java.util.concurrent.atomic.AtomicBoolean(false)
                        Thread {
                            try {
                                val startMs = android.os.SystemClock.elapsedRealtime()
                                VpnTunnelService.awaitTeardown(2500L)
                                while (android.os.SystemClock.elapsedRealtime() - startMs < 1200) {
                                    if (!VpnTunnelService.isTunnelHealthy() && !VpnTunnelService.isTeardownInProgress()) {
                                        break
                                    }
                                    try {
                                        Thread.sleep(40)
                                    } catch (_: InterruptedException) {
                                        break
                                    }
                                }
                                runOnUiThread {
                                    if (responded.compareAndSet(false, true)) {
                                        result.success("Tunnel Teardown Signal Transmitted")
                                    }
                                }
                            } catch (e: Exception) {
                                runOnUiThread {
                                    if (responded.compareAndSet(false, true)) {
                                        result.error("TEARDOWN_THREAD_ERROR", e.localizedMessage, null)
                                    }
                                }
                            }
                        }.start()
                    } catch (e: Exception) {
                        result.error("TEARDOWN_CRASH", e.localizedMessage, null)
                    }
                }
                // BUILD-SETTINGS LANE (2026-08-10). Settings toggle -> system
                // always-on VPN for this package. Arming uses the hidden
                // VpnManager.setAlwaysOnVpn just like AndroidKillSwitch; the
                // verdict is always the post-write read-back, never the write
                // itself. The returned string is surfaced verbatim by the Dart
                // toggle so the UI never claims a state the system did not
                // confirm: "armed" / "disabled" / "not_verified" /
                // "unavailable".
                "setAlwaysOnVpn" -> {
                    val enabled = call.argument<Boolean>("enabled") == true
                    result.success(setAlwaysOnVpn(enabled))
                }
                "requestBatteryExemption" -> {
                    if (!VpnTunnelService.isTunnelHealthy()) {
                        result.error(
                            "TUNNEL_INACTIVE",
                            "Battery exemption is available only after the VPN tunnel is active",
                            null,
                        )
                        return@setMethodCallHandler
                    }
                    // LINT `BatteryLife` (2 warnings, on the two
                    // ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS references
                    // below) IS DELIBERATELY LEFT UNSUPPRESSED. Lint's claim is
                    // that this intent violates Play's Content Policy; Play's
                    // own exception list names VPN as an acceptable use case,
                    // and the guard immediately above is what makes this app fit
                    // it -- the prompt is unreachable unless a tunnel is already
                    // healthy, so it is never shown at install or first launch,
                    // only to a user whose live tunnel Doze is about to cut.
                    //
                    // Not suppressed, because whether to ship this is a
                    // DISTRIBUTION decision and not a code one. An @SuppressLint
                    // here would delete the signal from
                    // the next lint run before the owner had ever seen it.
                    //
                    // THIS COMMENT MUST STAY BELOW THE isTunnelHealthy() GUARD.
                    // `android_battery_exemption_policy_test.dart` asserts that
                    // the guard appears before the FIRST occurrence of
                    // ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS in this
                    // branch, and it does not exempt comments -- naming the
                    // constant above the guard turns that test red even though
                    // the code order is unchanged. It cost one red run here.
                    val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                        !pm.isIgnoringBatteryOptimizations(packageName)
                    ) {
                        try {
                            val directRequest = Intent(
                                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                Uri.parse("package:${packageName}")
                            )
                            val requestIntent = if (directRequest.resolveActivity(packageManager) != null) {
                                directRequest
                            } else {
                                Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                            }
                            startActivity(requestIntent)
                            result.success(
                                powerOptimizationStatus() + mapOf(
                                    "prompted" to true,
                                    "direct_exemption_requested" to
                                        (requestIntent.action ==
                                            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS),
                                )
                            )
                        } catch (e: Exception) {
                            result.error("INTENT_FAILED", "Battery settings are unavailable", null)
                        }
                    } else {
                        result.success(powerOptimizationStatus() + mapOf("prompted" to false))
                    }
                }
                "isTelevision" -> {
                    result.success(isTelevision())
                }
                "triggerCamouflageSwap" -> {
                    // TV must never be disguised: D-pad remote has no focus
                    // handling on the decoy calculator, so arming would lock the
                    // user out with no way back. Fail closed to real VPN.
                    if (isTelevision()) {
                        result.success(false)
                        return@setMethodCallHandler
                    }
                    try {
                        val showRealVpn = call.argument<Boolean>("showRealVpn") == true
                        // Latch the fact that this install uses camouflage the
                        // first time the decoy is armed. Surfaces the OS only
                        // reads once -- notably the VPN session name, which is
                        // fixed at Builder.establish() -- need the enrollment
                        // fact, not the momentary armed/disarmed state, or they
                        // capture the real identity during the brief unlocked
                        // window in which the user actually presses Connect.
                        if (!showRealVpn) {
                            VpnTunnelService.markCamouflageEnrolled(this)
                        }
                        setLauncherComponentState(showRealVpn)
                        applyTaskIdentity(decoyActive = !showRealVpn)
                        // If a tunnel is already running (connected before this
                        // swap, e.g. backgrounding while connected), its
                        // foreground notification/channel would otherwise keep
                        // announcing whichever identity was active at connect
                        // time -- refresh them to match now.
                        VpnTunnelService.refreshForegroundNotificationForCamouflage()
                        // ...and the call above is a no-op when no tunnel is
                        // running, which is the common case at the moment
                        // someone arms the decoy. The channel row exists
                        // regardless, so it is reconciled through a Context
                        // rather than through the service instance.
                        VpnTunnelService.refreshTunnelChannelForCamouflage(this)
                        // Same argument, one surface over: the announcement
                        // channel's name is latched in Settings and only this
                        // call ever revisits it. Arming the decoy must rename
                        // a channel an earlier announcement already created,
                        // not wait for the next announcement to do it.
                        refreshAnnouncementChannelForCamouflage()
                        result.success(true)
                    } catch (e: Exception) {
                        result.error("CAMOUFLAGE_SWAP_FAILED", e.localizedMessage, null)
                    }
                }
                "resolveCarrierIpv4" -> {
                    val host = call.argument<String>("host").orEmpty().trim()
                    if (host.isEmpty() || host.length > 253) {
                        result.error("BAD_ARGS", "Carrier host is missing", null)
                    } else {
                        Thread {
                            val addresses = VpnTunnelService.resolveTransportIpv4Addresses(applicationContext, host)
                            runOnUiThread { result.success(addresses) }
                        }.apply {
                            name = "Calc-Carrier-Resolve"
                            isDaemon = true
                            start()
                        }
                    }
                }
                else -> result.notImplemented()
            }
        }

        // Wear OS companion, on its own channel so watch traffic can never
        // widen or perturb the tunnel channel's contract above. Registering it
        // is also what tells WatchBridge that a Dart layer exists and therefore
        // that connecting and country switching are currently possible.
        val watchChannel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            WatchBridge.DART_CHANNEL,
        )
        watchChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                WatchBridge.METHOD_PUBLISH_STATE -> {
                    val payload = call.argument<String>("payload").orEmpty()
                    result.success(WatchBridge.publishFromDart(applicationContext, payload))
                }
                else -> result.notImplemented()
            }
        }
        WatchBridge.attachDart(watchChannel)
        WatchBridge.purgeRetainedState(applicationContext) { deleted ->
            if (BuildConfig.DEBUG && !deleted) {
                Log.w("CalcCore", "Retained state cleanup was not confirmed")
            }
        }
    }

    override fun onDestroy() {
        readinessExecutor.shutdown()
        // The engine is going away, so connect/country requests from the watch
        // must start reporting as unavailable rather than dispatching into a
        // dead channel.
        WatchBridge.detachDart()
        super.onDestroy()
    }

    /**
     * Whether this device can actually put an SMS on a radio.
     *
     * This answers only the hardware half of the capability. The enrollment
     * screen uses canOfferDuressSms(), which also requires SEND_SMS to be
     * declared by the installed package. If that permission is ever restored,
     * the same change must declare android.hardware.telephony with
     * required="false" so Play does not filter wifi-only devices.
     *
     * `FEATURE_TELEPHONY` alone is not the honest answer on every one of those
     * devices. A cellular-data tablet has the radio and reports
     * `FEATURE_TELEPHONY` true while carrying no SMS stack at all, so an
     * enrollment screen keyed on it would offer a duress contact, accept a
     * number, and then deliver nothing on the day it mattered -- the silent
     * failure this must not have. Android 13 split that out into
     * `FEATURE_TELEPHONY_MESSAGING`, which is the precise question, so ask it
     * where it exists.
     *
     * THE GATE IS API 33 AND NOT API 31, AND THE DIFFERENCE IS A BUG LINT
     * CAUGHT. `FEATURE_TELEPHONY_MESSAGING` is a compile-time String constant,
     * so a wrong gate does not fail loudly -- the literal inlines and the call
     * compiles and runs anywhere. It just returns `false` on every platform
     * that does not declare that feature, and the feature is declared from 33.
     * Gating at 31 would therefore have told every Android 12 and 12L phone
     * that it could not send SMS, and silently disabled duress SMS on exactly
     * the devices this function exists to keep honest. That is why the gate is
     * `TIRAMISU` and why this paragraph is here.
     *
     * Below 33, `FEATURE_TELEPHONY` is the best answer the platform can give.
     */
    private fun hasTelephony(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_MESSAGING)
        }
        return packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
    }

    private fun hasSendSmsPermission(): Boolean {
        return checkSelfPermission(Manifest.permission.SEND_SMS) ==
            PackageManager.PERMISSION_GRANTED
    }

    @Suppress("DEPRECATION")
    private fun isSendSmsDeclared(): Boolean {
        return try {
            val info = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS,
            )
            info.requestedPermissions?.contains(Manifest.permission.SEND_SMS) == true
        } catch (_: Exception) {
            false
        }
    }

    private fun canOfferDuressSms(): Boolean =
        isSendSmsDeclared() && hasTelephony()

    @Suppress("DEPRECATION")
    private fun resolveSmsManager(): SmsManager? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                getSystemService(SmsManager::class.java)
            } else {
                SmsManager.getDefault()
            }
        } catch (_: Exception) {
            null
        }
    }

    // Sends the duress alert directly through the telephony radio. Returns true
    // to Dart only when every SMS part reported RESULT_OK within the wait
    // window; anything else (no service / radio off / no permission / timeout)
    // returns false so the Dart caller keeps the alert on its retry queue.
    // Runs off the UI thread. Nothing here writes to the Messages/Sent store.
    private fun sendDuressSms(
        destination: String,
        text: String,
        result: MethodChannel.Result,
    ) {
        val trimmed = destination.trim()
        if (trimmed.isEmpty() || text.isEmpty()) {
            result.success(false)
            return
        }
        if (!canOfferDuressSms() || !hasSendSmsPermission()) {
            // iOS-equivalent dead end on Android: no SIM stack or no grant. The
            // alert is not lost -- Dart queues it -- it just cannot go by SMS now.
            result.success(false)
            return
        }
        val sms = resolveSmsManager()
        if (sms == null) {
            result.success(false)
            return
        }
        Thread {
            var delivered = false
            var receiver: BroadcastReceiver? = null
            try {
                val parts = sms.divideMessage(text)
                val partCount = if (parts.isNullOrEmpty()) 1 else parts.size
                val latch = CountDownLatch(partCount)
                val failed = java.util.concurrent.atomic.AtomicBoolean(false)
                // Unique per-send action so overlapping sends never cross-signal.
                val action = "org.winsvpn.app.DURESS_SMS_SENT." +
                    System.nanoTime().toString()
                receiver = object : BroadcastReceiver() {
                    override fun onReceive(context: Context?, intent: Intent?) {
                        if (resultCode != Activity.RESULT_OK) failed.set(true)
                        latch.countDown()
                    }
                }
                // API 33+ requires an explicit export flag; this receiver is a
                // private, same-process signal, so mark it NOT_EXPORTED.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    registerReceiver(receiver, IntentFilter(action),
                        Context.RECEIVER_NOT_EXPORTED)
                } else {
                    @Suppress("UnspecifiedRegisterReceiverFlag")
                    registerReceiver(receiver, IntentFilter(action))
                }
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                        PendingIntent.FLAG_IMMUTABLE else 0
                val sentIntents = ArrayList<PendingIntent>(partCount)
                for (i in 0 until partCount) {
                    sentIntents.add(
                        PendingIntent.getBroadcast(
                            applicationContext,
                            i,
                            Intent(action).setPackage(packageName),
                            flags,
                        )
                    )
                }
                if (partCount == 1) {
                    sms.sendTextMessage(trimmed, null, text, sentIntents[0], null)
                } else {
                    sms.sendMultipartTextMessage(
                        trimmed, null, parts, sentIntents, null)
                }
                // Bounded wait: confirm the radio accepted the message before we
                // let the caller wipe. Offline (NO_SERVICE) resolves quickly to
                // a failure, which routes the alert to the retry queue.
                latch.await(20, TimeUnit.SECONDS)
                delivered = !failed.get()
            } catch (_: Exception) {
                delivered = false
            } finally {
                try {
                    if (receiver != null) unregisterReceiver(receiver)
                } catch (_: Exception) {}
            }
            runOnUiThread { result.success(delivered) }
        }.apply {
            name = "Calc-Duress-SMS"
            isDaemon = true
            start()
        }
    }

    private fun powerOptimizationStatus(): Map<String, Any> {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        val ignoring = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pm.isIgnoringBatteryOptimizations(packageName)
        } else {
            true
        }
        val manufacturer = Build.MANUFACTURER?.trim()?.ifBlank { "Android" } ?: "Android"
        val model = Build.MODEL?.trim()?.ifBlank { "Device" } ?: "Device"
        return mapOf(
            "ignoring_battery_optimizations" to ignoring,
            "manufacturer" to manufacturer,
            "model" to model,
            "android_sdk" to Build.VERSION.SDK_INT
        )
    }

    private fun buildTunnelReadiness(): Map<String, Any?> {
        val now = android.os.SystemClock.elapsedRealtime()
        val readyForMs = if (VpnTunnelService.engineReadyAtMs > 0L) {
            now - VpnTunnelService.engineReadyAtMs
        } else {
            0L
        }
        val vpnStatus = vpnNetworkStatus()
        val tunStats = tunTrafficStats()
        val awgStats = VpnTunnelService.currentAwgPeerStats()
        val awgRx = (awgStats["rx_bytes"] as? Number)?.toLong() ?: 0L
        val awgTx = (awgStats["tx_bytes"] as? Number)?.toLong() ?: 0L
        val tunRx = tunStats["rx"]
        val tunTx = tunStats["tx"]
        val tunAvailable = tunRx != null && tunTx != null && (tunRx > 0L || tunTx > 0L)
        val effectiveRx = if (tunAvailable) tunRx!! else awgRx
        val effectiveTx = if (tunAvailable) tunTx!! else awgTx
        val counterSource = if (tunAvailable) "tun" else if (awgRx > 0L || awgTx > 0L) "awg_peer" else "none"
        // `active`, `tunnel_healthy` and `engine_ready` never claim
        // a Winn v3 tunnel the engine has not proven connected, and
        // the current lifecycle travels beside them, separate from
        // the historical start verdict below (Round A3).
        val claimFields = VpnTunnelService.currentReadinessClaimFields()
        val winn3Readiness = VpnTunnelService.currentWinn3ReadinessSnapshot()
        return (mapOf(
            "service_active" to VpnTunnelService.isServiceActive,
            "interface_open" to VpnTunnelService.isInterfaceOpen,
            "engine_ready_ms" to readyForMs,
            "winn3_security_refusal" to winn3Readiness.securityRefusal,
            "winn3_start_token" to winn3Readiness.startToken,
            "winn3_start_generation" to
                winn3Readiness.startGeneration,
            "winn3_selection_generation" to
                winn3Readiness.selectionGeneration,
            "winn3_failed_node" to winn3Readiness.failedNode,
            "winn3_verdict" to winn3Readiness.state,
            "winn3_start_state" to winn3Readiness.state,
            "underlying_transport" to VpnTunnelService.lastUnderlyingTransport,
            "vpn_present" to vpnStatus["present"],
            "vpn_internet" to vpnStatus["internet"],
            "vpn_validated" to vpnStatus["validated"],
            "tun_rx_bytes" to tunRx,
            "tun_tx_bytes" to tunTx,
            "awg_handshake_recent" to awgStats["handshake_recent"],
            "awg_handshake_age_ms" to awgStats["handshake_age_ms"],
            "awg_rx_bytes" to awgRx,
            "awg_tx_bytes" to awgTx,
            "traffic_rx_bytes" to effectiveRx,
            "traffic_tx_bytes" to effectiveTx,
            "traffic_counter_source" to counterSource,
            "uid_rx_bytes" to uidRxBytes(),
            "uid_tx_bytes" to uidTxBytes(),
            "speed_test_physical_route_only" to VpnTunnelService.speedTestMeasuresPhysicalRoute
        ) + claimFields + VpnTunnelService.currentReleaseFields()).let { payload ->
            if (winn3Readiness.awgXrayAuthorizationToken > 0L) {
                payload + ("winn3_awg_xray_authorization_token" to
                    winn3Readiness.awgXrayAuthorizationToken)
            } else {
                payload
            }
        }
    }

    /**
     * Persists the app-level traffic-blocking preference and opens the system VPN
     * settings. Returns "saved_settings_opened", "saved_settings_unavailable" or
     * "not_verified"; the system Always-on VPN configuration is not changed or verified.
     */
    private fun setAlwaysOnVpn(enabled: Boolean): String {
        try {
            secureFileStore.write(
                VpnTunnelService.KILL_SWITCH_STATE,
                enabled.toString(),
            )
        } catch (_: Exception) {
            return "not_verified"
        }

        return try {
            startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
            "saved_settings_opened"
        } catch (_: Exception) {
            "saved_settings_unavailable"
        }
    }

    private fun legacyAppFile(name: String): File {
        require(SecureFileStore.isAllowedName(name)) { "Unsupported secure file name" }
        return File(File(applicationInfo.dataDir, "app_flutter"), name)
    }

    private fun runSecureStorageOperation(
        result: MethodChannel.Result,
        operation: () -> Any?,
    ) {
        SecureStorageOperationQueue.execute {
            try {
                val value = operation()
                runOnUiThread { result.success(value) }
            } catch (_: Exception) {
                Log.w(VpnTunnelService.LOG_TAG, "Secure local storage operation failed")
                runOnUiThread {
                    result.error(
                        "SECURE_STORAGE_FAILED",
                        "Secure local storage is unavailable",
                        null,
                    )
                }
            }
        }
    }

    private fun isAllowedExternalUri(uri: Uri): Boolean {
        return uri.scheme?.lowercase() in setOf(
            "https",
            "fb",
            "instagram",
            "linkedin",
            "twitter",
            "vnd.youtube",
        )
    }

    /**
     * Make the announcement channel's name in Settings match the camouflage
     * state, and report whether a notification may now be posted on it.
     *
     * WHY THIS EXISTS. The channel is the worst kind of camouflage surface:
     * the OS captures its name once, at creation, and then renders it in
     * Settings > Apps > Calculator > Notifications for the life of the install
     * -- listed there even when no notification is showing, and surviving the
     * decoy being disarmed. Choosing the name correctly at creation time is
     * therefore necessary but NOT sufficient. An install that received an
     * announcement before the user ever armed the decoy has already had the
     * real channel name written into that screen, and enrolling
     * afterwards did nothing to it. Closing that needs the existing channel
     * actively reconciled, which is what this does and what the missing
     * `refreshAnnouncementChannelForCamouflage` hook could not.
     *
     * The name IS mutable: `createNotificationChannel` with an id that already
     * exists updates the existing channel's name and description rather than
     * duplicating it -- the same platform property
     * `VpnTunnelService.settleTunnelChannel` relies on for the tunnel channel,
     * where it applies the identical ladder. This function does not TRUST that,
     * because the guarantee
     * it provides is one a coerced user's safety rests on. It writes, reads
     * the channel back, and if the name did not take it deletes the channel
     * outright and recreates it. Deletion is the one operation that
     * unquestionably removes the row, and its name, from Settings.
     *
     * FAIL CLOSED. If after both attempts the name still is not the decoy's
     * while we are disguised, the channel is deleted and `false` returned, so
     * nothing is posted. Losing the banner costs the user a notification; the
     * announcement itself is still delivered and is read in-app after the PIN
     * unlock, which is the only place it was ever safe to read. Leaking the
     * real identity into a permanent Settings row costs them the camouflage.
     */
    private fun settleAnnouncementChannel(
        manager: NotificationManager,
        createIfAbsent: Boolean,
    ): Boolean {
        // Pre-O has no notification channels, so there is no Settings row and
        // nothing to leak.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true

        val existing = manager.getNotificationChannel(ANNOUNCEMENT_CHANNEL_ID)
        // Nothing is latched yet. Do not create a channel the app has not
        // needed -- an unnecessary row is itself a small tell.
        if (existing == null && !createIfAbsent) return false

        val enrolled = VpnTunnelService.isCamouflageEnrolled(this)
        val armed = isDecoyLauncherActive()
        val disguised = VpnTunnelService.latchedSurfaceIsDisguised(enrolled, armed)
        val wantedName = VpnTunnelService.announcementChannelNameFor(enrolled, armed)
        val wantedDescription =
            VpnTunnelService.announcementChannelDescriptionFor(enrolled, armed)
        // Reuse whatever importance is already there. The platform refuses to
        // raise importance on an existing channel anyway, and the user may
        // have lowered it themselves.
        val importance = existing?.importance ?: NotificationManager.IMPORTANCE_DEFAULT

        fun wanted(): NotificationChannel =
            NotificationChannel(ANNOUNCEMENT_CHANNEL_ID, wantedName, importance).apply {
                description = wantedDescription
            }

        fun settledName(): String? =
            manager.getNotificationChannel(ANNOUNCEMENT_CHANNEL_ID)?.name?.toString()

        if (existing != null &&
            existing.name?.toString() == wantedName &&
            existing.description == wantedDescription
        ) {
            return true
        }

        // 1. Create, or update in place.
        manager.createNotificationChannel(wanted())
        if (settledName() == wantedName) return true

        // 2. The rename did not take. Delete the row and build it again.
        manager.deleteNotificationChannel(ANNOUNCEMENT_CHANNEL_ID)
        manager.createNotificationChannel(wanted())
        if (settledName() == wantedName) return true

        // 3. Neither worked. Leave no channel behind carrying the real
        //    identity, and post nothing.
        if (disguised) {
            manager.deleteNotificationChannel(ANNOUNCEMENT_CHANNEL_ID)
            Log.w(
                VpnTunnelService.LOG_TAG,
                "Announcement channel could not be given the decoy name; " +
                    "channel deleted and the notification suppressed.",
            )
            return false
        }
        return true
    }

    /**
     * The announcement-channel analogue of
     * `VpnTunnelService.refreshForegroundNotificationForCamouflage`, and the
     * piece whose absence made this channel a permanent leak: it renames a
     * channel that ALREADY exists, so an install that was announced to before
     * the decoy was ever armed stops advertising the real identity the moment
     * camouflage is enrolled, rather than waiting for an announcement that may
     * never come. It never creates a channel.
     */
    private fun refreshAnnouncementChannelForCamouflage() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            settleAnnouncementChannel(manager, createIfAbsent = false)
        } catch (e: Exception) {
            Log.w(VpnTunnelService.LOG_TAG, "Announcement channel camouflage refresh skipped", if (BuildConfig.DEBUG) e else null)
        }
    }

    private fun showAnnouncementNotification(title: String, body: String): Boolean {
        if (body.isBlank()) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 4243)
            return false
        }

        // Announcements are the one notification whose text this app does not
        // author -- the title comes from Dart and the body from the server --
        // so while the decoy is armed none of it can be trusted to be free of
        // the real identity. Everything user-visible here is therefore
        // replaced wholesale rather than filtered: channel name, channel
        // description, title, body and small icon. The real announcement is
        // still delivered; it is read inside the app after the PIN unlock,
        // which is the only place it was ever safe to read.
        //
        // The signal is the sticky enrollment flag, not the live decoy state,
        // for the same reason the VPN session name uses it: the notification
        // CHANNEL is a latched surface. It is created on the first
        // announcement and then persists in Settings > Apps > Calculator >
        // Notifications for the life of the install, listed there even when no
        // notification is showing. An announcement that arrives while the user
        // has the app open -- decoy momentarily down, which is the common
        // case, since that is when announcements are fetched -- would
        // otherwise carve the real channel name into a Settings screen
        // permanently.
        val disguised = VpnTunnelService.latchedSurfaceIsDisguised(
            camouflageEnrolled = VpnTunnelService.isCamouflageEnrolled(this),
            decoyActive = isDecoyLauncherActive(),
        )
        val shownTitle = if (disguised) VpnTunnelService.DISGUISED_DISPLAY_NAME else title
        val shownBody = if (disguised) "You have a new message." else body

        return try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            // Creates the channel on first use, and reconciles one an earlier,
            // un-enrolled install already latched. False means the decoy name
            // could not be guaranteed, so nothing is posted.
            if (!settleAnnouncementChannel(manager, createIfAbsent = true)) return false

            val openIntent = packageManager.getLaunchIntentForPackage(packageName)
                ?.apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                }
                ?: Intent(this, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                }
            val pendingIntent = PendingIntent.getActivity(
                this,
                4244,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
            )
            val notificationId = 5300 + kotlin.math.abs(body.hashCode() % 997)
            val notification: Notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, ANNOUNCEMENT_CHANNEL_ID)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(this)
            }
                .setContentTitle(shownTitle.take(80))
                .setContentText(shownBody.take(120))
                .setStyle(Notification.BigTextStyle().bigText(shownBody))
                .setSmallIcon(
                    if (disguised) R.drawable.ic_stat_calculator else R.drawable.ic_stat_wins_vpn
                )
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .build()
            manager.notify(notificationId, notification)
            true
        } catch (e: Exception) {
            Log.w(VpnTunnelService.LOG_TAG, "Announcement notification skipped", if (BuildConfig.DEBUG) e else null)
            false
        }
    }

    private fun vpnNetworkStatus(): Map<String, Boolean> {
        val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        var present = false
        var hasInternet = false
        var validated = false
        connectivity.allNetworks.forEach { network ->
            val caps = connectivity.getNetworkCapabilities(network) ?: return@forEach
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@forEach
            present = true
            hasInternet = hasInternet || caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            validated = validated || caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }
        return mapOf("present" to present, "internet" to hasInternet, "validated" to validated)
    }

    private fun probeVpnInternet(result: MethodChannel.Result) {
        Thread {
            val response = mutableMapOf<String, Any>(
                "ok" to false,
                "bound_to_tunnel" to false,
                "traffic_proof" to false,
                "tun_rx_delta" to 0L,
                "tun_tx_delta" to 0L,
                "awg_handshake_recent" to false,
                "awg_rx_bytes" to 0L,
                "awg_tx_bytes" to 0L,
                "status" to 0,
                "error" to ""
            )
            try {
                val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                var vpnNetwork: Network? = null
                for (searchAttempt in 0 until 12) {
                    vpnNetwork = connectivity.allNetworks.firstOrNull { network ->
                        val caps = connectivity.getNetworkCapabilities(network) ?: return@firstOrNull false
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    }
                    if (vpnNetwork != null) break
                    Thread.sleep(100)
                }
                if (vpnNetwork == null) {
                    throw IllegalStateException("No VPN network available for probe")
                }
                response["bound_to_tunnel"] = true

                // The VPN process is excluded from its own TUN so its transport cannot loop.
                // An authenticated handshake proves bidirectional encryption with the server.
                var httpOk = false
                var probeStatus = 0
                val probeUrls = listOf(
                    "https://connectivitycheck.gstatic.com/generate_204",
                    "https://cloudflare.com/cdn-cgi/trace"
                )
                for (probeUrl in probeUrls) {
                    var connection: java.net.HttpURLConnection? = null
                    try {
                        connection = vpnNetwork.openConnection(java.net.URL(probeUrl)) as java.net.HttpURLConnection
                        connection.instanceFollowRedirects = false
                        connection.useCaches = false
                        connection.connectTimeout = 5000
                        connection.readTimeout = 5000
                        connection.setRequestProperty("Connection", "close")
                        connection.connect()
                        probeStatus = connection.responseCode
                        if (probeStatus in 200..399) {
                            httpOk = true
                            break
                        }
                    } catch (e: Exception) {
                        Log.e(
                            VpnTunnelService.LOG_TAG,
                            if (BuildConfig.DEBUG) {
                                "Probe $probeUrl failed: ${e.javaClass.simpleName}: ${e.message}"
                            } else {
                                "Probe failed: ${e.javaClass.simpleName}"
                            },
                        )
                    } finally {
                        try { connection?.disconnect() } catch (_: Exception) {}
                    }
                }

                var handshakeRecent = false
                var receivedBytes = 0L
                var transmittedBytes = 0L
                if (httpOk) {
                    for (attempt in 0 until 10) {
                        val peerStats = VpnTunnelService.currentAwgPeerStats()
                        handshakeRecent = peerStats["handshake_recent"] as? Boolean ?: false
                        receivedBytes = (peerStats["rx_bytes"] as? Number)?.toLong() ?: 0L
                        transmittedBytes = (peerStats["tx_bytes"] as? Number)?.toLong() ?: 0L
                        if (handshakeRecent && receivedBytes >= 80L && transmittedBytes >= 80L) {
                            break
                        }
                        Thread.sleep(50)
                    }
                } else {
                    val peerStats = VpnTunnelService.currentAwgPeerStats()
                    handshakeRecent = peerStats["handshake_recent"] as? Boolean ?: false
                    receivedBytes = (peerStats["rx_bytes"] as? Number)?.toLong() ?: 0L
                    transmittedBytes = (peerStats["tx_bytes"] as? Number)?.toLong() ?: 0L
                }
                val trafficProof = VpnTrafficProof.isSatisfied(
                    handshakeRecent = handshakeRecent,
                    receivedBytes = receivedBytes,
                    transmittedBytes = transmittedBytes,
                )
                val ok = httpOk && (trafficProof || (handshakeRecent && receivedBytes >= 80L))
                response["awg_handshake_recent"] = handshakeRecent
                response["awg_rx_bytes"] = receivedBytes
                response["awg_tx_bytes"] = transmittedBytes
                response["traffic_proof"] = trafficProof
                response["owner_http_probe_ok"] = httpOk
                response["status"] = probeStatus
                response["ok"] = ok
                response["error"] = if (ok) {
                    ""
                } else if (!httpOk) {
                    "Waiting for VPN DNS and internet route to carry traffic (status=$probeStatus)"
                } else {
                    "VPN did not return bidirectional payload through VPN engine"
                }
            } catch (e: Exception) {
                response["error"] = e.localizedMessage ?: e.javaClass.simpleName
            }
            Log.d(
                VpnTunnelService.LOG_TAG,
                "VPN internet probe result ok=${response["ok"]} " +
                    "trafficProof=${response["traffic_proof"]} rx=${response["awg_rx_bytes"]} tx=${response["awg_tx_bytes"]} error=${response["error"]}"
            )

            runOnUiThread {
                result.success(response)
            }
        }.apply {
            name = "Calc-Network-Probe"
            isDaemon = true
            start()
        }
    }

    private fun measureDownloadMbps(arguments: Any?, result: MethodChannel.Result) {
        val args = arguments as? Map<*, *> ?: run {
            result.error("BAD_ARGS", "Speed-test arguments are missing", null)
            return
        }
        val rawUrl = args["url"] as? String ?: ""
        val streamCount = (args["streamCount"] as? Number)?.toInt()?.coerceIn(1, 32) ?: 1
        val durationMs = (args["durationMilliseconds"] as? Number)
            ?.toLong()?.coerceIn(1_000L, 10_000L) ?: 6_000L
        val url = validatedSpeedTestUrl(rawUrl) ?: run {
            // Distinct code and a named host so a refusal is diagnosable from
            // the Dart side too, instead of being indistinguishable from any
            // other native speed-test failure.
            result.error(
                "SPEED_TEST_HOST_NOT_ALLOWED",
                "Speed-test URL rejected by the host allowlist: " +
                    speedTestHostLabel(rawUrl),
                null,
            )
            return
        }
        val measurementGeneration = speedTestGeneration.get()

        Thread {
            val firstByteAt = AtomicLong(0L)
            val finishedAt = AtomicLong(0L)
            val transferred = AtomicLong(0L)
            val executor = Executors.newFixedThreadPool(streamCount)
            val ready = CountDownLatch(streamCount)
            val start = CountDownLatch(1)
            val done = CountDownLatch(streamCount)

            repeat(streamCount) { streamIndex ->
                executor.execute {
                    ready.countDown()
                    var streamBytes = 0L
                    try {
                        start.await(3, TimeUnit.SECONDS)
                        if (speedTestGeneration.get() != measurementGeneration) {
                            return@execute
                        }
                        val durationNanos = TimeUnit.MILLISECONDS.toNanos(durationMs)
                        var sequence = 0
                        val buffer = ByteArray(64 * 1024)
                        while (speedTestGeneration.get() == measurementGeneration) {
                            val now = System.nanoTime()
                            val startNanos = firstByteAt.get()
                            if (startNanos != 0L && now >= startNanos + durationNanos) {
                                break
                            }
                            var connection: HttpURLConnection? = null
                            var failed = false
                            try {
                                val streamUrl = speedTestStreamUrl(url, streamIndex, sequence++)
                                connection = streamUrl.openConnection() as HttpURLConnection
                                activeSpeedTestConnections.add(connection)
                                if (speedTestGeneration.get() != measurementGeneration) break
                                connection.instanceFollowRedirects = false
                                connection.connectTimeout = 5_000
                                connection.readTimeout = 5_000
                                connection.useCaches = false
                                connection.setRequestProperty("Accept-Encoding", "identity")
                                connection.setRequestProperty("Cache-Control", "no-store")
                                connection.setRequestProperty("Connection", "keep-alive")
                                connection.setRequestProperty("User-Agent", GENERIC_BROWSER_USER_AGENT)
                                val status = connection.responseCode
                                if (status !in 200..299) break
                                connection.inputStream.use { input ->
                                    while (speedTestGeneration.get() == measurementGeneration) {
                                        val loopNow = System.nanoTime()
                                        val loopStart = firstByteAt.get()
                                        if (loopStart != 0L && loopNow >= loopStart + durationNanos) {
                                            break
                                        }
                                        val read = input.read(buffer)
                                        if (read <= 0) break
                                        firstByteAt.compareAndSet(0L, System.nanoTime())
                                        finishedAt.set(System.nanoTime())
                                        streamBytes += read.toLong()
                                    }
                                }
                            } catch (_: Exception) {
                                failed = true
                                break
                            } finally {
                                if (connection != null) {
                                    activeSpeedTestConnections.remove(connection)
                                }
                                connection?.disconnect()
                            }
                        }
                    } finally {
                        transferred.addAndGet(streamBytes)
                        done.countDown()
                    }
                }
            }

            ready.await(3, TimeUnit.SECONDS)
            start.countDown()
            done.await(durationMs + 5_000L, TimeUnit.MILLISECONDS)
            executor.shutdownNow()
            for (conn in activeSpeedTestConnections) {
                try { conn.disconnect() } catch (_: Exception) {}
            }
            activeSpeedTestConnections.clear()
            val startNanos = firstByteAt.get()
            val endNanos = finishedAt.get()
            val activeNanos = if (startNanos > 0L && endNanos >= startNanos) {
                (endNanos - startNanos).coerceAtLeast(1L)
            } else {
                TimeUnit.MILLISECONDS.toNanos(durationMs)
            }
            val elapsedNanos = minOf(activeNanos, TimeUnit.MILLISECONDS.toNanos(durationMs))
            val mbps = transferred.get().toDouble() * 8_000.0 / elapsedNanos.toDouble()
            runOnUiThread {
                if (speedTestGeneration.get() != measurementGeneration ||
                    transferred.get() < 256 * 1024 || !mbps.isFinite() || mbps <= 0) {
                    result.success(null)
                } else {
                    result.success(mapOf(
                        "mbps" to mbps,
                        "bytes" to transferred.get(),
                        "stream_count" to streamCount,
                        "engine" to "android-native-http1",
                        // True when the app's own UID currently bypasses the VPN (stealth
                        // Xray's outer transport requires this); the measured throughput is
                        // then the physical route, not the tunneled route.
                        "physical_route_only" to VpnTunnelService.speedTestMeasuresPhysicalRoute
                    ))
                }
            }
        }.apply {
            name = "Calc-Native-Download-Test"
            isDaemon = true
            start()
        }
    }

    /**
     * RV-B (Round 38 treaty): upload measurement against the gateway's INNER
     * speedtest ingest over a RAW SOCKET.
     *
     * WHY RAW SOCKET. Android's cleartext HTTP policy (which the OkHttp
     * upload path enforces) refused http://10.x.x.x because the policy cannot
     * know this connection never leaves the encrypted tunnel. The policy's
     * purpose — keeping user data off plaintext INTERNET paths — does not
     * apply to intra-tunnel traffic, and the destination is pinned to the
     * signed descriptor's inner router, latched by the running session
     * (VpnTunnelService.latchedInnerRouterV4). A plain TCP socket sits outside
     * the HTTP stacks the policy governs.
     *
     * PROTOCOL. One POST per stream with a Content-Length sized to the
     * per-stream budget; the body is zeros streamed until the shared window
     * ends; shutdownOutput then makes the ingest answer with the
     * AUTHORITATIVE count of bytes it actually received
     * ({"received_bytes":N}), which is what the rate uses — not what the
     * client pushed into its local socket buffer.
     *
     * GATE. The router must be dotted-quad AND equal the session-latched
     * value; anything else returns null and the Dart layer falls back to the
     * third-party targets.
     */
    private fun measureUploadViaTunnelIngest(arguments: Any?, result: MethodChannel.Result) {        val args = arguments as? Map<*, *> ?: run {
            result.success(null)
            return
        }
        val router = (args["router"] as? String)?.trim().orEmpty()
        val port = (args["port"] as? Number)?.toInt() ?: 0
        val streamCount = (args["streamCount"] as? Number)?.toInt()?.coerceIn(1, 32) ?: 1
        val maximumBytes = (args["maximumBytes"] as? Number)?.toLong() ?: (4L * 1024 * 1024 * 1024)
        val durationMs = (args["durationMilliseconds"] as? Number)?.toLong()?.coerceIn(1_000L, 10_000L)
            ?: 8_000L
        val measurementGeneration = speedTestGeneration.get()

        if (port <= 0 || !VpnTunnelService.isInnerIpv4Literal(router) ||
            router != VpnTunnelService.latchedInnerRouterV4
        ) {
            Log.i(
                ingestTag,
                "tunnel ingest refused: router=$router " +
                    "latched=${VpnTunnelService.latchedInnerRouterV4 ?: "null"} port=$port",
            )
            result.success(null)
            return
        }

        Thread {
            try {
                val windowNanos = TimeUnit.MILLISECONDS.toNanos(durationMs)
                val budgetPerStream = maximumBytes / streamCount
                val statusCodes = ConcurrentLinkedQueue<Int>()
                val receivedBytes = ConcurrentLinkedQueue<Long>()
                val firstByteAt = AtomicLong(0L)
                val windowStart = AtomicLong(0L)
                val done = CountDownLatch(streamCount)

                val chunk = ByteArray(128 * 1024)
                val requestHead = buildString {
                    append("POST /speedtest/up HTTP/1.1\r\n")
                    append("Host: ").append(router).append(':').append(port).append("\r\n")
                    append("Content-Type: application/octet-stream\r\n")
                    append("Content-Length: ").append(budgetPerStream).append("\r\n")
                    append("Connection: close\r\n\r\n")
                }.toByteArray(Charsets.US_ASCII)

                val workers = (1..streamCount).map { streamIndex ->
                    Thread {
                        var socket: java.net.Socket? = null
                        try {
                            windowStart.compareAndSet(0L, System.nanoTime())
                            socket = java.net.Socket()
                            // Round 46 Treaty (OI-1): 1 Gbps at 65 ms RTT requires
                            // 8,125,000 B total in flight; 8,125,000 / 32 = 253,907 B per stream.
                            // Must be set before connect() so window scale is negotiated in the SYN.
                            socket.sendBufferSize = 1_048_576
                            socket.tcpNoDelay = true
                            if (streamIndex == 1) {
                                val eff = socket.sendBufferSize
                                android.util.Log.i(
                                    VpnTunnelService.LOG_TAG,
                                    "sndbuf_req=1048576 sndbuf_eff=$eff floor=253907"
                                )
                                if (eff < 253_907) {
                                    android.util.Log.w(VpnTunnelService.LOG_TAG, "sndbuf clamped below per-stream BDP floor")
                                }
                            }
                            // Round 39 convergence (opus): a node whose
                            // firewall DROPs (rather than rejects) the ingest
                            // port would otherwise park this connect for the
                            // platform default (tens of seconds) and stall
                            // the whole test. 1500 ms is enough for an
                            // in-tunnel round trip many times over.
                            socket.connect(java.net.InetSocketAddress(router, port), 1_500)
                            socket.soTimeout = 15_000
                            val out = socket.getOutputStream()
                            out.write(requestHead)
                            out.flush()
                            var start = firstByteAt.get()
                            while (speedTestGeneration.get() == measurementGeneration) {
                                start = firstByteAt.get()
                                val now = System.nanoTime()
                                if (start == 0L) {
                                    firstByteAt.compareAndSet(0L, now)
                                } else if (now >= start + windowNanos) {
                                    break
                                }
                                out.write(chunk)
                            }
                            out.flush()
                            socket.shutdownOutput()
                            val response = socket.getInputStream().readBytes()
                            val received = Regex("\"received_bytes\":(\\d+)")
                                .find(String(response, Charsets.US_ASCII))
                                ?.groupValues?.get(1)?.toLongOrNull() ?: 0L
                            receivedBytes.add(received)
                            statusCodes.add(200)
                        } catch (e: Exception) {
                            Log.w(
                                ingestTag,
                                if (BuildConfig.DEBUG) {
                                    "tunnel ingest stream $streamIndex error: " +
                                        "${e.javaClass.simpleName}: ${e.message}"
                                } else {
                                    "tunnel ingest stream $streamIndex error: ${e.javaClass.simpleName}"
                                },
                            )
                        } finally {
                            runCatching { socket?.close() }
                            done.countDown()
                        }
                    }.apply {
                        name = "Calc-Ingest-Upload-$streamIndex"
                        isDaemon = true
                    }
                }
                workers.forEach { it.start() }
                done.await(durationMs + 15_000, TimeUnit.MILLISECONDS)
                workers.forEach { it.join(2_000) }

                val total = receivedBytes.sum()
                val startNanos = firstByteAt.get()
                // received_bytes counts what the ingest received until each
                // stream closed, after its send buffer drained, so the window
                // runs to that point and is not capped at the write window.
                val windowUsed = if (startNanos > 0L) {
                    (System.nanoTime() - startNanos).coerceAtLeast(1L)
                } else {
                    TimeUnit.MILLISECONDS.toNanos(durationMs)
                }
                val mbps = total.toDouble() * 8_000.0 / windowUsed.toDouble()
                Log.i(
                    ingestTag,
                    "tunnel-ingest-run router=$router statuses=$statusCodes bytes=$total " +
                        "window_ms=${windowUsed / 1_000_000} streams=$streamCount " +
                        "mbps=${"%.1f".format(mbps)}",
                )
                runOnUiThread {
                    if (speedTestGeneration.get() != measurementGeneration ||
                        total < 256 * 1024 || !mbps.isFinite() || mbps <= 0
                    ) {
                        result.success(null)
                    } else {
                        result.success(
                            mapOf(
                                "mbps" to mbps,
                                "bytes" to total,
                                "stream_count" to streamCount,
                                "engine" to "tunnel-ingest-rawsocket",
                            ),
                        )
                    }
                }
            } catch (e: Exception) {
                Log.w(
                    ingestTag,
                    if (BuildConfig.DEBUG) {
                        "tunnel ingest run failed: ${e.javaClass.simpleName}: ${e.message}"
                    } else {
                        "tunnel ingest run failed: ${e.javaClass.simpleName}"
                    },
                )
                runOnUiThread { result.success(null) }
            }
        }.apply {
            name = "Calc-Ingest-Upload-Run"
            isDaemon = true
            start()
        }
    }

    private fun measureUploadMbps(arguments: Any?, result: MethodChannel.Result) {
        val args = arguments as? Map<*, *> ?: run {
            result.error("BAD_ARGS", "Speed-test arguments are missing", null)
            return
        }
        val rawUrl = args["url"] as? String ?: ""
        val streamCount = (args["streamCount"] as? Number)?.toInt()?.coerceIn(1, 32) ?: 32
        val durationMs = (args["durationMilliseconds"] as? Number)
            ?.toLong()?.coerceIn(1_000L, 10_000L) ?: 6_000L
        val maximumBytes = (args["maximumBytes"] as? Number)
            ?.toLong()?.coerceIn(8L * 1024 * 1024, 8L * 1024 * 1024 * 1024)
            ?: 4L * 1024 * 1024 * 1024
        val url = validatedSpeedTestUrl(rawUrl) ?: run {
            result.error(
                "SPEED_TEST_HOST_NOT_ALLOWED",
                "Speed-test URL rejected by the host allowlist: " +
                    speedTestHostLabel(rawUrl),
                null,
            )
            return
        }
        val measurementGeneration = speedTestGeneration.get()

        activeSpeedTestConnections.toList().forEach { connection ->
            try { connection.disconnect() } catch (_: Exception) {}
        }
        activeSpeedTestConnections.clear()

        Thread {
            val resolvedIpv4 = try {
                Dns.SYSTEM.lookup(url.host).filterIsInstance<Inet4Address>()
            } catch (e: Exception) {
                android.util.Log.w(
                    VpnTunnelService.LOG_TAG,
                    if (BuildConfig.DEBUG) {
                        "DNS lookup for ${url.host} failed: ${e.message}"
                    } else {
                        "DNS lookup failed: ${e.javaClass.simpleName}"
                    },
                )
                emptyList()
            }
            val speedTestDns = object : Dns {
                override fun lookup(hostname: String): List<InetAddress> {
                    if (resolvedIpv4.isNotEmpty() && hostname.equals(url.host, ignoreCase = true)) {
                        return resolvedIpv4.shuffled()
                    }
                    val addresses = Dns.SYSTEM.lookup(hostname)
                    val ipv4 = addresses.filterIsInstance<Inet4Address>()
                    return if (ipv4.isNotEmpty()) ipv4.shuffled() else addresses
                }
            }

            val speedTestSocketFactory = object : javax.net.SocketFactory() {
                private val delegate = javax.net.SocketFactory.getDefault()
                private fun configure(socket: java.net.Socket): java.net.Socket {
                    socket.tcpNoDelay = true
                    try {
                        // The kernel doubles an explicitly set SO_SNDBUF, so this
                        // lands at 1 MiB effective per stream, 32 MiB over 32
                        // streams. That covers the bandwidth-delay product of
                        // 1.3 Gbps at a 200 ms loaded RTT and 4 Gbps at the 65 ms
                        // Canada RTT, four times the 330 Mbps the Canada tunnel
                        // carried (gateway UdpInDatagrams, 2026-10-09). A run
                        // reports only when every stream completed within 15 s
                        // of the 8 s write window, so what the sockets hold when
                        // the window ends must drain in 15 s: 32 MiB drains at
                        // 18 Mbps and above. At 2 MiB (128 MiB in all) every
                        // link under 72 Mbps reported nothing; at 16 MiB the
                        // sockets took about 800 MB in the 8 s window.
                        socket.sendBufferSize = 512 * 1024
                    } catch (_: Exception) {}
                    return socket
                }
                override fun createSocket(): java.net.Socket = configure(delegate.createSocket())
                override fun createSocket(host: String?, port: Int): java.net.Socket =
                    configure(delegate.createSocket(host, port))
                override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): java.net.Socket =
                    configure(delegate.createSocket(host, port, localHost, localPort))
                override fun createSocket(host: InetAddress?, port: Int): java.net.Socket =
                    configure(delegate.createSocket(host, port))
                override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): java.net.Socket =
                    configure(delegate.createSocket(address, port, localAddress, localPort))
            }

            val okHttpClient = OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                .protocols(listOf(Protocol.HTTP_1_1))
                .dns(speedTestDns)
                .socketFactory(speedTestSocketFactory)
                .proxy(Proxy.NO_PROXY)
                .connectTimeout(10_000, TimeUnit.MILLISECONDS)
                .readTimeout(15_000, TimeUnit.MILLISECONDS)
                .writeTimeout(durationMs + 12_000L, TimeUnit.MILLISECONDS)
                .connectionPool(ConnectionPool(streamCount.coerceAtLeast(32), 5, TimeUnit.MINUTES))
                .retryOnConnectionFailure(true)
                .build()

            val firstByteAt = AtomicLong(0L)
            val finishedAt = AtomicLong(0L)
            val reserved = AtomicLong(0L)
            val confirmed = AtomicLong(0L)
            val failedStreams = AtomicLong(0L)
            // Round 38 instrumentation: per-worker facts for the variance
            // investigation (served host family and HTTP status).
            val statusCodes = java.util.concurrent.ConcurrentLinkedQueue<Int>()
            val servedHosts = java.util.concurrent.ConcurrentLinkedQueue<String>()
            val executor = Executors.newFixedThreadPool(streamCount)
            val ready = CountDownLatch(streamCount)
            val start = CountDownLatch(1)
            val done = CountDownLatch(streamCount)

            repeat(streamCount) { streamIndex ->
                executor.execute {
                    ready.countDown()
                    var call: Call? = null
                    var requestBytes = 0L
                    var bodyCompleted = false
                    try {
                        start.await(5, TimeUnit.SECONDS)
                        if (speedTestGeneration.get() != measurementGeneration) {
                            return@execute
                        }
                        val targetUrl = speedTestStreamUrl(url, streamIndex, 0)
                        val durationNanos = TimeUnit.MILLISECONDS.toNanos(durationMs)
                        val buffer = speedTestUploadChunk

                        val requestBody = object : RequestBody() {
                            override fun contentType(): okhttp3.MediaType? =
                                "application/octet-stream".toMediaTypeOrNull()

                            override fun contentLength(): Long = -1L

                            override fun isOneShot(): Boolean = true

                            override fun writeTo(sink: BufferedSink) {
                                while (speedTestGeneration.get() == measurementGeneration) {
                                    val now = System.nanoTime()
                                    val startNanos = firstByteAt.get()
                                    if (startNanos != 0L && now >= startNanos + durationNanos) {
                                        break
                                    }
                                    val before = reserved.getAndAdd(buffer.size.toLong())
                                    if (before >= maximumBytes) break
                                    val writable = minOf(buffer.size.toLong(), maximumBytes - before).toInt()
                                    if (writable <= 0) break
                                    firstByteAt.compareAndSet(0L, System.nanoTime())
                                    sink.write(buffer, 0, writable)
                                    requestBytes += writable.toLong()
                                }
                                sink.flush()
                                bodyCompleted = true
                            }
                        }

                        val requestBuilder = Request.Builder()
                            .url(targetUrl)
                            .post(requestBody)
                            .header("Content-Type", "application/octet-stream")
                            .header("Cache-Control", "no-store")
                            .header("Connection", "keep-alive")

                        if (targetUrl.host.lowercase() == "speed.cloudflare.com") {
                            requestBuilder
                                .header("User-Agent", GENERIC_BROWSER_USER_AGENT)
                                .header("Accept", "*/*")
                                .header("Origin", "https://speed.cloudflare.com")
                                .header("Referer", "https://speed.cloudflare.com/")
                                .header("Sec-Fetch-Site", "same-origin")
                                .header("Sec-Fetch-Mode", "cors")
                        } else {
                            requestBuilder.header("User-Agent", GENERIC_BROWSER_USER_AGENT)
                        }

                        val request = requestBuilder.build()
                        call = okHttpClient.newCall(request)
                        activeSpeedTestCalls.add(call)

                        if (speedTestGeneration.get() != measurementGeneration) {
                            return@execute
                        }

                        val response = call.execute()
                        statusCodes.add(response.code)
                        servedHosts.add(response.request.url.host)
                        val successful = response.code in 200..299 && bodyCompleted
                        response.close()
                        if (successful) {
                            confirmed.addAndGet(requestBytes)
                            val completedAt = System.nanoTime()
                            finishedAt.updateAndGet { previous -> maxOf(previous, completedAt) }
                        } else {
                            failedStreams.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        failedStreams.incrementAndGet()
                        val line = e.stackTrace.firstOrNull()?.lineNumber ?: -1
                        android.util.Log.w(
                            VpnTunnelService.LOG_TAG,
                            if (BuildConfig.DEBUG) {
                                "Upload stream $streamIndex error at line $line: ${e.javaClass.simpleName}: ${e.message}"
                            } else {
                                "Upload stream $streamIndex error at line $line: ${e.javaClass.simpleName}"
                            },
                        )
                    } finally {
                        if (call != null) {
                            activeSpeedTestCalls.remove(call)
                        }
                        done.countDown()
                    }
                }
            }

            ready.await(5, TimeUnit.SECONDS)
            // ROUND 37/38 EXPERIMENT RECORD (2026-09-20): a 1-second warm-up
            // and carrier buffers at 4 MiB (~1 BDP) were each tested and
            // REVERTED. Observed association: upload results split by the
            // speedtest target family label — "North America" runs measured
            // 681-790 Mbps up, "Global Backbone" runs 234-301 Mbps up, across
            // three build configurations (warm-up, 4 MiB buffers, reverted) —
            // with downloads 717-792 throughout and zero engine drops. The
            // CAUSE IS OPEN: the Round 38 stage-1 deep-buffer derivation and
            // the Arbiter's endpoint-selection reading were both challenged
            // (the label is chosen by the run's own download winner, and the
            // upload target mapping needs per-run instrumentation: resolved
            // host, HTTP status, server-acked bytes, stream count). This run
            // logs those values; do not reinstate either knob until the
            // instrumented data names the cause.
            start.countDown()
            val allFinished = done.await(durationMs + 15_000L, TimeUnit.MILLISECONDS)
            executor.shutdownNow()
            for (activeCall in activeSpeedTestCalls) {
                try { activeCall.cancel() } catch (_: Exception) {}
            }
            activeSpeedTestCalls.clear()

            val startNanos = firstByteAt.get()
            val endNanos = finishedAt.get()
            val activeNanos = if (startNanos > 0L && endNanos >= startNanos) {
                (endNanos - startNanos).coerceAtLeast(1L)
            } else {
                TimeUnit.MILLISECONDS.toNanos(durationMs)
            }
            val elapsedNanos = activeNanos
            val mbps = confirmed.get().toDouble() * 8_000.0 / elapsedNanos.toDouble()
            // Round 38 cross-examination instrumentation: per-run facts that
            // decide WHY the upload number varies (served host family, HTTP
            // status distribution, completed-request bytes, window), captured per worker
            // during the run.
            android.util.Log.i(
                VpnTunnelService.LOG_TAG,
                "upload-run url=${url.host} statuses=$statusCodes hosts=$servedHosts " +
                    "bytes=${confirmed.get()} window_ms=${elapsedNanos / 1_000_000} " +
                    "streams=$streamCount mbps=${"%.1f".format(mbps)}"
            )
            runOnUiThread {
                if (speedTestGeneration.get() != measurementGeneration ||
                    !allFinished || failedStreams.get() != 0L ||
                    confirmed.get() < 256 * 1024 || !mbps.isFinite() || mbps <= 0) {
                    result.success(null)
                } else {
                    result.success(mapOf(
                        "mbps" to mbps,
                        "bytes" to confirmed.get(),
                        "stream_count" to streamCount,
                        "engine" to "android-native-okhttp",
                        "physical_route_only" to VpnTunnelService.speedTestMeasuresPhysicalRoute
                    ))
                }
            }
        }.apply {
            name = "Calc-Native-Upload-Test"
            isDaemon = true
            start()
        }
    }

    private fun cancelSpeedTestMeasurements() {
        speedTestGeneration.incrementAndGet()
        activeSpeedTestConnections.toList().forEach { connection ->
            connection.disconnect()
        }
        activeSpeedTestCalls.toList().forEach { call ->
            try { call.cancel() } catch (_: Exception) {}
        }
    }

    // Every host the native speed-test downloader/uploader may reach, matched
    // EXACTLY. This is the Android half of a cross-language contract whose
    // single source of truth is _speedTestTargetsForNode in lib/main.dart;
    // test/speed_test_host_allowlist_contract_test.dart fails the moment the
    // two drift apart, so a hostname change cannot silently diverge.
    //
    // Exact hosts, deliberately not leading-dot suffix wildcards. The three
    // ISP entries were previously ".speedtest.frontier.com", ".st.charter.com"
    // and ".sonic.net", each a whole-zone wildcard serving exactly ONE
    // hardcoded hostname. ".sonic.net" was the bare corporate zone, so it
    // accepted every host under Sonic's entire DNS estate -- member portals,
    // mail, and any dangling record available for subdomain takeover -- which
    // is not a surface this product can justify carrying.
    //
    // Narrowing costs nothing. Speed-test URLs are `const` literals in
    // lib/main.dart; hub node data (slug/name) is only substring-matched to
    // pick WHICH hardcoded group runs and can never supply a URL, so this
    // allowlist is defence in depth against a future change rather than a
    // filter on live server input. If an ISP rotates a speedtest hostname the
    // compiled-in constant in lib/main.dart has to be edited regardless, so a
    // wildcard bought no resilience -- and _measureDownloadMbps falls back to
    // the pure-Dart sampler when this native call fails, so a rejection
    // degrades the measurement path rather than losing the feature.
    private val speedTestAllowedHosts = setOf(
        "speed.cloudflare.com",
        "cachefly.cachefly.net",
        "losangeles.ca.speedtest.frontier.com",
        "lsanca-speedtest-ookla-02.st.charter.com",
        "speedtest.lax2.sonic.net",
    )

    private fun validatedSpeedTestUrl(rawUrl: String): URL? {
        // Rejections are logged, never silently dropped: this gate is the only
        // thing standing between a URL handed over the MethodChannel and a real
        // outbound fetch, so a refusal is either a target that needs updating
        // or an attempt worth seeing. Only the host is ever logged -- never the
        // raw URL, which could carry credentials in its userInfo.
        val url = try {
            URL(rawUrl)
        } catch (e: Exception) {
            Log.w(
                VpnTunnelService.LOG_TAG,
                "Speed-test URL rejected: unparseable (${e.javaClass.simpleName})",
            )
            return null
        }
        // RV-B (Round 38 treaty): the gateway's inner speedtest ingest is plain
        // HTTP by design — the tunnel itself provides confidentiality, and the
        // address is reachable only through an admitted session. Accept it only
        // when it names the ACTIVE session's inner router on the ingest port,
        // which the Dart layer carries from the signed descriptor; a stolen
        // config cannot aim this at an arbitrary host without also forging the
        // descriptor that the engine already verified and latched.
        if (url.protocol == "http" &&
            url.port == VpnTunnelService.WINN3_INGEST_PORT &&
            VpnTunnelService.isInnerIpv4Literal(url.host)
        ) {
            if (url.host == VpnTunnelService.latchedInnerRouterV4) {
                return url
            }
            Log.i(
                VpnTunnelService.LOG_TAG,
                "Speed-test ingest URL host ${url.host} does not match the " +
                    "active session router (latched=${VpnTunnelService.latchedInnerRouterV4 ?: "null"})",
            )
        }
        if (url.protocol != "https") {
            Log.w(VpnTunnelService.LOG_TAG, "Speed-test URL rejected: scheme is not https")
            return null
        }
        if (url.userInfo != null) {
            Log.w(VpnTunnelService.LOG_TAG, "Speed-test URL rejected: embedded credentials")
            return null
        }
        val host = url.host.lowercase()
        if (!speedTestAllowedHosts.contains(host)) {
            Log.w(VpnTunnelService.LOG_TAG, "Speed-test URL rejected: host not allowed")
            return null
        }
        return url
    }

    // Host of [rawUrl] for diagnostics only. URL.host excludes any userInfo, so
    // this cannot echo credentials back to the Dart layer.
    private fun speedTestHostLabel(rawUrl: String): String {
        return try {
            URL(rawUrl).host.lowercase().ifEmpty { "<no-host>" }
        } catch (_: Exception) {
            "<unparseable>"
        }
    }

    private fun speedTestStreamUrl(base: URL, streamIndex: Int, sequence: Int): URL {
        val host = base.host.lowercase()
        if (host == "speed.cloudflare.com" && base.path == "/__down") {
            return URL("https://speed.cloudflare.com/__down?bytes=100000000")
        }
        if (host == "speed.cloudflare.com" && base.path == "/__up") {
            return URL("https://speed.cloudflare.com/__up")
        }
        if (host == "cachefly.cachefly.net") return base
        val separator = if (base.query.isNullOrBlank()) "?" else "&"
        return URL("${base}$separator" + "r=${System.nanoTime()}-$streamIndex-$sequence")
    }

    // Best-effort diagnostics only. Android may restrict /proc/net/dev for app
    // UIDs, so tunnel acceptance must use the native AWG counters instead.
    private fun tunTrafficStats(): Map<String, Long?> {
        // Modern Android SELinux intentionally denies untrusted applications
        // access to /proc/net/dev. Readiness already uses the protected native
        // peer counters and a VPN-bound Internet probe, so returning null
        // TUN counters avoids an audit denial every poll and enables clean fallback.
        return mapOf("rx" to null, "tx" to null)
    }

    private fun uidRxBytes(): Long {
        val value = TrafficStats.getUidRxBytes(android.os.Process.myUid())
        return if (value == TrafficStats.UNSUPPORTED.toLong()) 0L else value
    }

    private fun uidTxBytes(): Long {
        val value = TrafficStats.getUidTxBytes(android.os.Process.myUid())
        return if (value == TrafficStats.UNSUPPORTED.toLong()) 0L else value
    }

    private fun activateNativeVpnEngine() {
        val intent = VpnService.prepare(applicationContext)
        if (intent != null) {
            Log.i(VpnTunnelService.LOG_TAG, "Android VPN authorization is required.")
            vpnAuthorizationPending = true
            try {
                startActivityForResult(intent, VPN_REQUEST_CODE)
            } catch (e: Exception) {
                vpnAuthorizationPending = false
                pendingResult?.error(
                    "AUTHORIZATION_FAILED",
                    "Android VPN authorization could not be opened",
                    null,
                )
                pendingResult = null
                pendingConfig = null
                pendingWinn3StartToken = null
                pendingWinn3StartGeneration = null
                pendingWinn3SelectionGeneration = null
                pendingWinn3FailedNode = null
                pendingWinn3CoverAuthToken = null
                pendingWinn3CoverTarget = null
                pendingWinn3CoverLeg = null
                pendingWinn3SelectedNode = null
                pendingDoubleVpnHandoverToken = null
            }
        } else {
            Log.i(VpnTunnelService.LOG_TAG, "Android VPN authorization is already granted.")
            executeServiceLaunch()
        }
    }

    @Suppress("DEPRECATION")
    private fun loadInstalledAppsForSplitTunnel(): List<Map<String, Any>> {
        val pm = packageManager
        return pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .asSequence()
            .filter { it.packageName != packageName }
            .map { app ->
                val label = app.loadLabel(pm)?.toString()?.trim()
                    ?.ifBlank { app.packageName } ?: app.packageName
                val isSystem =
                    (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                        (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                mapOf(
                    "name" to label,
                    "package_name" to app.packageName,
                    "is_system" to isSystem
                )
            }
            .sortedWith(compareBy<Map<String, Any>> {
                (it["name"] as? String).orEmpty().lowercase()
            }.thenBy {
                (it["package_name"] as? String).orEmpty()
            })
            .toList()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != VPN_REQUEST_CODE) return
        if (!vpnAuthorizationPending) {
            Log.w(VpnTunnelService.LOG_TAG, "Duplicate VPN authorization result ignored.")
            return
        }
        vpnAuthorizationPending = false
        if (resultCode == Activity.RESULT_OK) {
            Log.i(VpnTunnelService.LOG_TAG, "Android VPN authorization was granted.")
            executeServiceLaunch()
        } else {
            Log.i(VpnTunnelService.LOG_TAG, "Android VPN authorization was declined.")
            pendingResult?.error("UNAUTHORIZED", "User denied VPN access", null)
            pendingResult = null
            pendingConfig = null
            pendingWinn3StartToken = null
            pendingWinn3StartGeneration = null
            pendingWinn3SelectionGeneration = null
            pendingWinn3FailedNode = null
            pendingWinn3CoverAuthToken = null
            pendingWinn3CoverTarget = null
            pendingWinn3CoverLeg = null
            pendingWinn3SelectedNode = null
            pendingDoubleVpnHandoverToken = null
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        if (requestCode == DURESS_SMS_PERMISSION_REQUEST_CODE) {
            val granted = grantResults.isNotEmpty() &&
                grantResults[0] == PackageManager.PERMISSION_GRANTED
            val pending = pendingSmsPermissionResult
            pendingSmsPermissionResult = null
            pending?.success(granted)
            return
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }

    private fun cancelPendingVpnAuthorization() {
        val pending = pendingResult
        pendingResult = null
        pendingConfig = null
        pendingWinn3StartToken = null
        pendingWinn3StartGeneration = null
        pendingWinn3SelectionGeneration = null
        pendingWinn3FailedNode = null
        pendingWinn3CoverAuthToken = null
        pendingWinn3CoverTarget = null
        pendingWinn3CoverLeg = null
        pendingWinn3SelectedNode = null
        pendingDoubleVpnHandoverToken = null
        vpnAuthorizationPending = false
        if (pending != null) {
            pending.error(
                "CONNECT_CANCELLED",
                "VPN connection request was cancelled",
                null,
            )
        }
    }

    private fun executeServiceLaunch() {
        // A VPN consent granted after the reset sealed starts must not reach
        // startForegroundService: the service gate returns before
        // startForeground, so the pending start is cancelled here instead.
        if (secureFileStore.accountResetPending()) {
            cancelPendingVpnAuthorization()
            return
        }
        val config = pendingConfig
        val winn3StartToken = pendingWinn3StartToken
        val winn3StartGeneration = pendingWinn3StartGeneration
        val winn3SelectionGeneration = pendingWinn3SelectionGeneration
        val winn3FailedNode = pendingWinn3FailedNode
        val coverAuthToken = pendingWinn3CoverAuthToken
        val coverTarget = pendingWinn3CoverTarget
        val coverLeg = pendingWinn3CoverLeg
        val winn3SelectedNode = pendingWinn3SelectedNode
        val handoverToken = pendingDoubleVpnHandoverToken
        val result = pendingResult
        pendingConfig = null
        pendingWinn3StartToken = null
        pendingWinn3StartGeneration = null
        pendingWinn3SelectionGeneration = null
        pendingWinn3FailedNode = null
        pendingWinn3CoverAuthToken = null
        pendingWinn3CoverTarget = null
        pendingWinn3CoverLeg = null
        pendingWinn3SelectedNode = null
        pendingDoubleVpnHandoverToken = null
        pendingResult = null
        if (config.isNullOrBlank() || result == null) {
            Log.w(VpnTunnelService.LOG_TAG, "Tunnel service launch had no pending request; ignoring it.")
            return
        }
        try {
            Log.i(VpnTunnelService.LOG_TAG, "Starting the foreground VPN service.")
            if (winn3StartToken != null && winn3StartGeneration != null) {
                VpnTunnelService.beginWinn3Start(
                    startToken = winn3StartToken,
                    startGeneration = winn3StartGeneration,
                    selectionGeneration = winn3SelectionGeneration.orEmpty(),
                    failedNode = winn3FailedNode.orEmpty(),
                )
            }
            val serviceIntent = Intent(this, VpnTunnelService::class.java).apply {
                action = "ACTION_CONNECT"
                putExtra("CONFIG_PAYLOAD", config)
                if (winn3StartToken != null) {
                    putExtra("WINN3_START_TOKEN", winn3StartToken)
                }
                if (winn3StartGeneration != null) {
                    putExtra("WINN3_START_GENERATION", winn3StartGeneration)
                }
                if (!winn3SelectionGeneration.isNullOrEmpty()) {
                    putExtra("WINN3_SELECTION_GENERATION", winn3SelectionGeneration)
                }
                if (!winn3FailedNode.isNullOrEmpty()) {
                    putExtra("WINN3_FAILED_NODE", winn3FailedNode)
                }
                if (coverAuthToken != null) {
                    putExtra("WINN3_AWG_XRAY_AUTHORIZATION_TOKEN", coverAuthToken)
                }
                if (!coverTarget.isNullOrEmpty()) {
                    putExtra("WINN3_COVER_EXACT_TARGET", coverTarget)
                }
                if (!coverLeg.isNullOrEmpty()) {
                    putExtra("WINN3_COVER_LEG", coverLeg)
                }
                if (!winn3SelectedNode.isNullOrEmpty()) {
                    putExtra(WinnV3SelectedNodeCaller.EXTRA_SELECTED_NODE, winn3SelectedNode)
                }
                if (handoverToken != null) {
                    putExtra("DOUBLE_VPN_HANDOVER_TOKEN", handoverToken)
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
            result.success("Tunnel Initializing")
        } catch (e: Exception) {
            result.error("ENGINE_CRASH", "VPN engine could not start", null)
        }
    }


    override fun onStop() {
        super.onStop()
    }

    // M-13: setLauncherComponentState only swaps which launcher alias is
    // enabled, i.e. which icon/label appears on the Home screen and in the
    // launcher's app list. It has no effect on the Overview/Recents card for
    // this already-running task, which Android renders from this Activity's
    // own ActivityManager.TaskDescription rather than from the launcher
    // component. Without this, a local observer who opens Recents while the
    // calculator decoy is armed still reads the product name on the task card.
    //
    // The parameter is the LIVE decoy state, and it is deliberately no longer
    // the whole answer. The Recents ENTRY outlives this Activity and the
    // process that set it, so keying the card on the momentary signal leaves
    // the product name on a card with nothing left running to correct it --
    // see VpnTunnelService.taskDescriptionLabelFor for the flow that does it.
    // Label and icon both come off the shared latched-surface predicate, and
    // they move together: a card reading the decoy name over the product icon
    // is a worse tell than either alone.
    private fun applyTaskIdentity(decoyActive: Boolean) {
        val camouflageEnrolled = VpnTunnelService.isCamouflageEnrolled(this)
        val disguised = VpnTunnelService.latchedSurfaceIsDisguised(
            camouflageEnrolled = camouflageEnrolled,
            decoyActive = decoyActive,
        )
        val label = VpnTunnelService.taskDescriptionLabelFor(
            camouflageEnrolled = camouflageEnrolled,
            decoyActive = decoyActive,
        )
        val icon = BitmapFactory.decodeResource(
            resources,
            if (disguised) R.mipmap.ic_calculator else R.mipmap.ic_launcher
        )
        @Suppress("DEPRECATION")
        setTaskDescription(
            ActivityManager.TaskDescription(
                label,
                icon,
                0xFF111827.toInt()
            )
        )
    }

    private fun isDecoyLauncherActive(): Boolean {
        return try {
            val decoyComponent = ComponentName(this, "$packageName.LauncherDecoy")
            packageManager.getComponentEnabledSetting(decoyComponent) ==
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        } catch (e: Exception) {
            false
        }
    }

    // TV form-factor detection. Must be reliable across OEMs: UiModeManager
    // reports TELEVISION on real TVs, and leanback is the Play feature that
    // marks TV devices. Either true means this is a TV and camouflage must
    // never be armed (D-pad remote cannot enter PIN, would lock user out).
    private fun isTelevision(): Boolean {
        try {
            val uiModeManager = getSystemService(Context.UI_MODE_SERVICE) as? UiModeManager
            if (uiModeManager?.currentModeType == Configuration.UI_MODE_TYPE_TELEVISION) {
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
        val pm = packageManager
        val realComponent = ComponentName(this, "$packageName.LauncherReal")
        val decoyComponent = ComponentName(this, "$packageName.LauncherDecoy")
        fun isEffectivelyEnabled(component: ComponentName, manifestDefault: Boolean): Boolean {
            return when (pm.getComponentEnabledSetting(component)) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> true
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED -> false
                else -> manifestDefault
            }
        }
        // Must mirror AndroidManifest.xml: LauncherReal enabled="false", LauncherDecoy enabled="true".
        val realWasEnabled = isEffectivelyEnabled(realComponent, manifestDefault = false)
        val decoyWasEnabled = isEffectivelyEnabled(decoyComponent, manifestDefault = true)
        if (showRealVpn) {
            if (!realWasEnabled) {
                pm.setComponentEnabledSetting(realComponent, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
            }
            if (decoyWasEnabled) {
                pm.setComponentEnabledSetting(decoyComponent, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            }
        } else {
            if (!decoyWasEnabled) {
                pm.setComponentEnabledSetting(decoyComponent, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
            }
            if (realWasEnabled) {
                pm.setComponentEnabledSetting(realComponent, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            }
        }
    }
}
