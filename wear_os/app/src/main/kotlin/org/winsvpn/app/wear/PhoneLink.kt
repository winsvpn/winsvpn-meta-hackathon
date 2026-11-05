package org.winsvpn.app.wear

import android.content.Context
import android.net.Uri
import android.os.SystemClock
import com.google.android.gms.wearable.CapabilityClient
import com.google.android.gms.wearable.DataClient
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.Wearable
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.tasks.await

/**
 * Everything the watch knows about how to reach the phone.
 *
 * Commands go out over [MessageClient] because it fails immediately and loudly
 * when the phone is out of range -- that failure is exactly the "phone
 * unreachable" signal the UI needs. State comes back over both [MessageClient]
 * (an immediate reply, so a tap feels instant) and [DataClient] (a retained
 * item, so re-opening the app shows last-known state instead of a spinner).
 */
class PhoneLink(context: Context) {

    private val appContext = context.applicationContext
    private val messageClient: MessageClient = Wearable.getMessageClient(appContext)
    private val dataClient: DataClient = Wearable.getDataClient(appContext)
    private val capabilityClient: CapabilityClient = Wearable.getCapabilityClient(appContext)

    /**
     * Resolve the paired node that is actually running the companion phone app.
     *
     * Using the capability rather than "any connected node" matters on a watch
     * paired to more than one device, and it means a phone without the app
     * installed reports as unreachable instead of silently swallowing commands.
     *
     * The Data Layer pairs a watch node only with a phone node running the same
     * package signed with the same certificate. That match is keyed on THIS
     * app's own identity, so this watch must itself be running the release
     * package -- `org.winsvpn.app` -- or it would resolve debug/QA phone nodes
     * instead of the signed release. [PairingMatcher] states that exact-match
     * contract; a watch built with a `.debug`/`.test` application id refuses to
     * pair here rather than bind to a non-release companion.
     */
    private suspend fun phoneNodeId(): String? {
        if (!PairingMatcher.isRelease(appContext.packageName)) return null
        return runCatching {
            capabilityClient
                .getCapability(PHONE_CAPABILITY, CapabilityClient.FILTER_REACHABLE)
                .await()
                .nodes
                .sortedByDescending { it.isNearby }
                .firstOrNull()
                ?.id
        }.getOrNull()
    }

    /**
     * @return true only if the phone acknowledged receipt. A false here is a
     * genuine "could not deliver", which the UI surfaces rather than pretending
     * the tap worked.
     */
    suspend fun send(command: String, slug: String? = null, expectedNodeId: String? = null): Boolean {
        val nodeId = phoneNodeId() ?: return false
        if (command != WatchLink.COMMAND_REQUEST_STATE && !PairingMatcher.matchesSelectedNode(expectedNodeId, nodeId)) {
            return false
        }
        return runCatching {
            messageClient
                .sendMessage(nodeId, WatchLink.PATH_COMMAND, WatchLink.encodeCommand(command, slug))
                .await()
            true
        }.getOrDefault(false)
    }

    /** Last state the phone published, if the Data Layer still holds one. */
    suspend fun lastKnownSnapshot(): PhoneSnapshot? = runCatching {
        val uri = Uri.Builder()
            .scheme(WEAR_URI_SCHEME)
            .path(WatchLink.PATH_STATE)
            .build()
        val buffer = dataClient.getDataItems(uri, DataClient.FILTER_PREFIX).await()
        try {
            buffer
                .asSequence()
                .mapNotNull { item ->
                    DataMapItem.fromDataItem(item).dataMap.getString(WatchLink.KEY_SNAPSHOT)
                }
                .mapNotNull(PhoneSnapshot::parse)
                .maxByOrNull { it.updatedAt }
        } finally {
            buffer.release()
        }
    }.getOrNull()

    /**
     * Every state update the phone pushes, from either transport, stamped with
     * its arrival time on this watch's monotonic clock. Only live arrivals are
     * stamped; [lastKnownSnapshot] is not, so its load figures render unknown
     * (see [LoadFreshness]).
     */
    fun snapshots(): Flow<PhoneSnapshot> = messageSnapshots()
        .map { it.copy(arrivedAtElapsedMs = SystemClock.elapsedRealtime()) }

    private fun messageSnapshots(): Flow<PhoneSnapshot> = callbackFlow {
        val listener = MessageClient.OnMessageReceivedListener { event ->
            if (event.path == WatchLink.PATH_STATE) {
                val snapshot = PhoneSnapshot.parse(event.data)
                if (snapshot != null) {
                    trySend(snapshot.copy(sourceNodeId = event.sourceNodeId))
                }
            }
        }
        messageClient.addListener(listener)
        awaitClose { messageClient.removeListener(listener) }
    }.buffer(capacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST).filter { snapshot ->
        // One node lookup at a time, in arrival order: a lookup per message in
        // its own coroutine let a newer state finish first and be overwritten
        // by the older one. A burst while a lookup is in flight drops the
        // oldest queued state, never the newest (trySend on the default
        // suspending buffer failed, so the latest state was the one lost).
        PairingMatcher.matchesSelectedNode(snapshot.sourceNodeId, phoneNodeId())
    }

    private fun dataSnapshots(): Flow<PhoneSnapshot> = callbackFlow {
        val listener = DataClient.OnDataChangedListener { events ->
            // The buffer is owned by the caller and released once this returns,
            // so everything needed must be read out synchronously here -- and
            // it must not be released again from this side.
            events
                .filter { it.type == DataEvent.TYPE_CHANGED }
                .filter { it.dataItem.uri.path == WatchLink.PATH_STATE }
                .mapNotNull {
                    DataMapItem.fromDataItem(it.dataItem).dataMap.getString(WatchLink.KEY_SNAPSHOT)
                }
                .mapNotNull(PhoneSnapshot::parse)
                .forEach(::trySend)
        }
        dataClient.addListener(listener)
        awaitClose { dataClient.removeListener(listener) }
    }

    private companion object {
        /**
         * Declared by the phone app in `android/app/src/main/res/values/wear.xml`.
         */
        const val PHONE_CAPABILITY = "wins_vpn_phone"
        const val WEAR_URI_SCHEME = "wear"
    }
}
