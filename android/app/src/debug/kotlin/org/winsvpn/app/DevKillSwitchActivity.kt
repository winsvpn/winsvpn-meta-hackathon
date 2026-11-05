package org.winsvpn.app

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log

/**
 * DEBUG SOURCE SET ONLY. Driver for the Android kill switch, used by the
 * Motorola proof and by any future device lane.
 *
 * `am` launches this activity (which the Debug manifest declares exported, in
 * `src/debug/AndroidManifest.xml`), it forwards one of four verbs to the real
 * [VpnTunnelService], and finishes. It performs no VPN call itself:
 *
 *   adb shell am start -n org.winsvpn.app.debug/org.winsvpn.app.DevKillSwitchActivity \
 *       --ez arm true        # arm kill switch + best-effort always-on lock-down
 *   --ez disarm true         # disarm + lift lock-down
 *   --ez block true          # hold a VpnService.Builder blocking interface
 *   --ez exit true           # release the blocking interface
 *
 * Why it is safe: it lives in `src/debug/` (release AAB never sees it), it
 * takes a boolean over adb and nothing else, and it touches no key material,
 * no config and no PIN gate — the same boundary DevVpnPrepareActivity draws.
 * Arming is a user-decided state, not a credential: this only persists the
 * flag the shipping kill-switch feature reads.
 */
class DevKillSwitchActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val arm = intent?.getBooleanExtra("arm", false)
        val disarm = intent?.getBooleanExtra("disarm", false)
        val block = intent?.getBooleanExtra("block", false)
        val exit = intent?.getBooleanExtra("exit", false)
        val service = Intent(this, VpnTunnelService::class.java)
        when {
            arm == true -> {
                service.action = VpnTunnelService.ACTION_ARM_KILLSWITCH
                startService(service)
                Log.i(TAG, "requested arm")
            }
            disarm == true -> {
                service.action = VpnTunnelService.ACTION_DISARM_KILLSWITCH
                startService(service)
                Log.i(TAG, "requested disarm")
            }
            block == true -> {
                service.action = VpnTunnelService.ACTION_ENTER_BLOCK
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(service)
                } else {
                    startService(service)
                }
                Log.i(TAG, "requested block posture")
            }
            exit == true -> {
                service.action = VpnTunnelService.ACTION_EXIT_BLOCK
                startService(service)
                Log.i(TAG, "requested exit block posture")
            }
            else -> Log.w(TAG, "no recognised verb; nothing sent")
        }
        finish()
    }

    companion object {
        const val TAG = "WinsDevKillSwitch"
    }
}