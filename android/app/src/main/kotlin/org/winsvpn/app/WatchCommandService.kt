package org.winsvpn.app

import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.WearableListenerService

/**
 * Receives commands from the paired Wear OS app.
 *
 * Runs in the phone app's own process, so it can read [VpnTunnelService]'s
 * state directly and reach the live Flutter MethodChannel through
 * [WatchBridge] when the app happens to be open -- without ever starting the
 * Flutter engine itself just to answer a status poll.
 */
class WatchCommandService : WearableListenerService() {

    override fun onMessageReceived(messageEvent: MessageEvent) {
        if (messageEvent.path != WatchBridge.PATH_COMMAND) {
            super.onMessageReceived(messageEvent)
            return
        }
        WatchBridge.handleCommand(applicationContext, messageEvent.data)
    }
}
