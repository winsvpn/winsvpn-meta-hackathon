package org.winsvpn.app

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.google.android.gms.wearable.Wearable
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Phone half of the Wear OS remote control.
 *
 * Design constraints this file exists to enforce:
 *
 *  - The watch is a remote control, never a second VPN client. It sends intent
 *    and renders state. No credential, key, endpoint or tunnel config crosses
 *    the link; [sanitizedCountries] whitelists three display fields out of a
 *    node cache that also holds server endpoints.
 *  - Connecting is owned by the Dart layer, because Dart is what builds the
 *    tunnel config and what drives the OS VPN consent prompt. When Dart is not
 *    attached, connecting is reported as unavailable rather than faked.
 *  - Disconnecting and reading status are owned by [VpnTunnelService], which is
 *    resident whenever a tunnel exists, so those two keep working with the
 *    phone app closed -- which is the case that matters for a wrist kill switch.
 */
object WatchBridge {

    /** Flutter MethodChannel used only for watch traffic. */
    const val DART_CHANNEL = "wins_vpn/watch"

    /** Dart -> native: hand over the current user-visible state. */
    const val METHOD_PUBLISH_STATE = "publishWatchState"

    /** Native -> Dart: the watch asked for something. */
    const val METHOD_ON_COMMAND = "onWatchCommand"

    /** Wearable Data Layer paths. Must match `wear_os` WatchLink. */
    const val PATH_COMMAND = "/winsvpn/cmd"
    const val PATH_STATE = "/winsvpn/state"
    const val KEY_SNAPSHOT = "snapshot"

    const val COMMAND_CONNECT = "connect"
    const val COMMAND_DISCONNECT = "disconnect"
    const val COMMAND_SELECT_COUNTRY = "selectCountry"
    const val COMMAND_REQUEST_STATE = "requestState"

    private const val TAG = VpnTunnelService.LOG_TAG
    private const val NODE_CACHE_FILE = "node_cache.json"
    private const val PROTOCOL_VERSION = 1

    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Live only while a FlutterEngine exists. Its nullness is the single source
     * of truth for "can the watch ask us to connect".
     */
    @Volatile
    private var dartChannel: MethodChannel? = null

    /** Last semantic payload Dart published, without the publish timestamp. */
    @Volatile
    private var lastDartPayload: String? = null

    /** Last payload actually put on the wire, timestamp included. */
    @Volatile
    private var lastPublishedSnapshot: String? = null

    fun attachDart(channel: MethodChannel) {
        dartChannel = channel
    }

    fun detachDart() {
        dartChannel = null
        lastDartPayload = null
        // Deliberately keep lastPublishedSnapshot: a watch that polls right
        // after the phone app is swiped away should still see the last known
        // country list, with canConnect recomputed as false by snapshotJson().
    }

    // ---------------------------------------------------------------- publish

    /**
     * Called from Dart whenever user-visible state changes.
     *
     * @param payload the semantic snapshot: status, detail, selectedSlug,
     *   countries, canConnect. Dart must not put anything else in it.
     * @return true when this changed something and was pushed to the watch.
     */
    fun publishFromDart(context: Context, payload: String): Boolean {
        if (payload == lastDartPayload) return false
        lastDartPayload = payload
        val stamped = try {
            JSONObject(payload)
                .put("v", PROTOCOL_VERSION)
                .put("updatedAt", System.currentTimeMillis())
                .toString()
        } catch (_: Exception) {
            Log.w(TAG, "Rejected malformed watch payload from Dart.")
            return false
        }
        // Only Dart's own snapshot is cached. A reply reconciled against native
        // health below is sent but never stored, so a later poll re-checks
        // health against what Dart said rather than against an earlier reply.
        lastPublishedSnapshot = stamped
        push(context, stamped)
        return true
    }

    fun purgeRetainedState(context: Context, onResult: (Boolean) -> Unit) {
        try {
            val uri = android.net.Uri.Builder()
                .scheme("wear")
                .authority("*")
                .path(PATH_STATE)
                .build()
            Wearable.getDataClient(context.applicationContext)
                .deleteDataItems(
                    uri,
                    com.google.android.gms.wearable.DataClient.FILTER_PREFIX,
                )
                .addOnSuccessListener { onResult(true) }
                .addOnFailureListener { onResult(false) }
        } catch (_: Exception) {
            onResult(false)
        }
    }

    private fun push(context: Context, snapshot: String) {
        val appContext = context.applicationContext
        // Messages only, and only to a connected node. Nothing is persisted in
        // Google Play services' Data Layer store, which this app cannot wipe.
        try {
            val bytes = snapshot.toByteArray(Charsets.UTF_8)
            val messageClient = Wearable.getMessageClient(appContext)
            Wearable.getNodeClient(appContext).connectedNodes
                .addOnSuccessListener { nodes ->
                    nodes.forEach { node ->
                        messageClient.sendMessage(node.id, PATH_STATE, bytes)
                    }
                }
        } catch (e: Exception) {
            Log.w(TAG, "Direct state message failed: ${e.javaClass.simpleName}")
        }
    }


    // ---------------------------------------------------------------- command

    /**
     * Handle one watch command.
     *
     * The Wearable Data Layer only delivers between nodes running the same
     * package signed with the same certificate, so the sender is already
     * authenticated by the platform; this method still refuses anything outside
     * the four known verbs.
     */
    fun handleCommand(context: Context, rawPayload: ByteArray?) {
        val json = try {
            JSONObject(String(rawPayload ?: ByteArray(0), Charsets.UTF_8))
        } catch (_: Exception) {
            Log.w(TAG, "Ignored malformed watch command.")
            return
        }
        val command = json.optString("command").trim()
        val slug = json.optString("slug").trim()

        when (command) {
            COMMAND_REQUEST_STATE -> Unit

            COMMAND_DISCONNECT -> disconnectNatively(context)

            COMMAND_CONNECT, COMMAND_SELECT_COUNTRY -> {
                val channel = dartChannel
                if (channel == null) {
                    // No Dart, no config builder, and no Activity to host the
                    // OS VPN consent dialog. Say so instead of half-trying.
                    Log.i(TAG, "Watch '$command' ignored: phone app not running.")
                } else {
                    val arguments = mapOf(
                        "command" to command,
                        "slug" to slug,
                    )
                    mainHandler.post {
                        try {
                            channel.invokeMethod(METHOD_ON_COMMAND, arguments)
                        } catch (e: Exception) {
                            Log.w(TAG, "Watch command dispatch failed: ${e.javaClass.simpleName}")
                        }
                    }
                }
            }

            else -> {
                Log.w(TAG, "Ignored unknown watch command.")
                return
            }
        }

        // Always answer, including for refused commands: an unanswered tap is
        // what makes a watch app feel broken.
        push(context, snapshotJson(context))
    }

    private fun disconnectNatively(context: Context) {
        // Mirrors MainActivity's "stopTunnel" path. Safe with the phone app
        // closed because a live tunnel means VpnTunnelService is already a
        // running foreground service.
        if (!VpnTunnelService.isServiceActive) return
        try {
            val intent = Intent(context.applicationContext, VpnTunnelService::class.java).apply {
                action = "ACTION_DISCONNECT"
                putExtra("KEEP_VPN_LAUNCHER", true)
                putExtra("RELEASE_KILL_SWITCH_BLOCK", true)
            }
            context.applicationContext.startService(intent)
        } catch (e: Exception) {
            Log.w(TAG, "Watch disconnect failed: ${e.javaClass.simpleName}")
        }
    }

    // --------------------------------------------------------------- snapshot

    /**
     * Current state as JSON.
     *
     * When Dart is attached its own snapshot wins, because only Dart knows
     * about transitional states like "connecting" and about failure text. When
     * Dart is gone this is synthesised from the native service plus the node
     * cache Dart last wrote, with `canConnect` forced false.
     */
    /**
     * True when the user has never granted the OS VPN consent. A watch cannot
     * grant it (VpnService.prepare requires a foreground Activity), so the
     * watch must surface "permissionRequired" rather than hanging or showing a
     * stale disconnected.
     */
    private fun needsVpnPermission(context: Context): Boolean = try {
        VpnService.prepare(context.applicationContext) != null
    } catch (_: Exception) {
        false
    }

    fun snapshotJson(context: Context): String {
        val channel = dartChannel
        val cached = lastPublishedSnapshot
        val isHealthy = VpnTunnelService.isTunnelHealthy()
        if (channel != null && cached != null) {
            // A backgrounded Flutter engine stays attached but stops
            // republishing, so its last "connected" can outlive the tunnel
            // (a watch disconnect, an engine failure, revoked consent). Every
            // reply re-checks that claim against native health; Dart's
            // transitional states and its redacted fields are kept as sent.
            try {
                val snapshot = JSONObject(cached)
                val cachedStatus = snapshot.optString("status")
                val liveStatus = WatchSnapshotHealth.status(cachedStatus, isHealthy) {
                    needsVpnPermission(context)
                }
                // Re-stamped at reply time: the watch ages load figures by
                // (updatedAt - load_at) plus its own time since arrival, so a
                // reply carrying the original publish time would leave out
                // every second the snapshot sat cached here.
                snapshot.put(
                    "updatedAt",
                    WatchSnapshotHealth.updatedAt(
                        snapshot.optLong("updatedAt"),
                        System.currentTimeMillis(),
                    ),
                )
                if (liveStatus != cachedStatus) {
                    snapshot.put("status", liveStatus).put("detail", "")
                }
                return snapshot.toString()
            } catch (_: Exception) {
                // A malformed cache falls through to the native snapshot.
            }
        }

        val nativeStatus = when {
            isHealthy -> "connected"
            needsVpnPermission(context) -> "permissionRequired"
            else -> "disconnected"
        }
        val cache = readNodeCache(context)
        return try {
            val fallback = JSONObject()
                .put("v", PROTOCOL_VERSION)
                .put("status", nativeStatus)
                .put("detail", "")
                .put("selectedSlug", cache?.optString("selected_slug")?.trim().orEmpty())
                .put("countries", sanitizedCountries(cache))
                .put("canConnect", false)
                .put("updatedAt", System.currentTimeMillis())
            fallback.toString()
        } catch (e: Exception) {
            Log.w(TAG, "Snapshot synthesis failed: ${e.javaClass.simpleName}")
            """{"v":$PROTOCOL_VERSION,"status":"unknown","canConnect":false}"""
        }
    }

    private fun readNodeCache(context: Context): JSONObject? = try {
        val file = File(
            File(context.applicationContext.applicationInfo.dataDir, "app_flutter"),
            NODE_CACHE_FILE,
        )
        if (file.isFile) JSONObject(file.readText()) else null
    } catch (_: Exception) {
        null
    }

    /**
     * Whitelist, not blacklist.
     *
     * `node_cache.json` also carries `endpoint` and `stealth_endpoint`. Those
     * are server addresses and must never reach the watch, so this copies the
     * three display fields out by name rather than filtering the original
     * object -- a new sensitive field added to the cache later cannot leak
     * through by default.
     */
    private fun sanitizedCountries(cache: JSONObject?): JSONArray {
        val out = JSONArray()
        val nodes = cache?.optJSONArray("nodes") ?: return out
        for (index in 0 until nodes.length()) {
            val node = nodes.optJSONObject(index) ?: continue
            val slug = node.optString("slug").trim()
            if (slug.isEmpty() || slug == "unknown") continue
            out.put(
                JSONObject()
                    .put("slug", slug)
                    .put("name", node.optString("name").trim().ifEmpty { slug })
                    .put("flag", node.optString("flag").trim())
            )
        }
        return out
    }
}
