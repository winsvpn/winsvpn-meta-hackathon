package org.winsvpn.app

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * DEBUG SOURCE SET ONLY. A minimal, real [VpnService] the instrumented
 * [AndroidKillSwitchTest] starts to prove the kill switch on a physical device.
 *
 * It exists because `VpnService.Builder.establish()` only returns a tun when the
 * calling component is a REAL VpnService that the system has bound (the
 * framework checks the service Binder callback, not a constructed instance), so
 * the test cannot hand [AndroidKillSwitch] an instance it built itself. This
 * service is started by the app (`org.winsvpn.app.debug`) under test, and inside
 * `onStartCommand` it drives the very code under test:
 *
 *     AndroidKillSwitch(this).establishBlockingInterface()
 *
 * which puts the whole route table (IPv4 default + the IPv6 fail-closed sink)
 * inside the tun with no engine draining it, so every cleartext packet is
 * dropped while it is up. The returned descriptor and any error are exposed on
 * the companion so the test (which runs in the same process) can observe the
 * establishment, measure egress against it, then tear it down.
 *
 * Why it is safe: it lives in `src/debug/`, so the release AAB and the release
 * dependency freeze never see it -- the same boundary DevVpnPrepareActivity and
 * DevKillSwitchActivity already draw. It starts no tunnel, reads no config and
 * touches no key material. It only ever arms the kill switch's blocking
 * interface, which is a best-effort drop-posture, and it closes the descriptor
 * on destroy so a test that does not clean up cannot leave the owner's phone
 * offline.
 */
class KillSwitchBlockService : VpnService() {

    /** Action that triggers a fresh blocking-interface establishment. */
    companion object {
        private const val TAG = "WinsKSBlock"
        const val ACTION_ARM_BLOCK = "org.winsvpn.app.action.ARM_KILLSWITCH_BLOCK"

        /** The descriptor returned by [AndroidKillSwitch.establishBlockingInterface]. */
        @Volatile
        var lastEstablishment: ParcelFileDescriptor? = null

        /** Non-null when the last [ACTION_ARM_BLOCK] did not cleanly establish. */
        @Volatile
        var lastError: String? = null

        val isUp: Boolean get() = lastEstablishment != null

        /** Tear down any remembered descriptor without touching the System service. */
        fun releaseMemoryPfd() {
            lastEstablishment?.let { pfd ->
                try {
                    pfd.close()
                } catch (_: Exception) {
                }
            }
            lastEstablishment = null
            lastError = null
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_ARM_BLOCK) {
            try {
                val killSwitch = AndroidKillSwitch(this)
                val pfd = killSwitch.establishBlockingInterface()
                lastError = if (pfd == null) {
                    "establishBlockingInterface returned null (is the debug package the " +
                        "prepared VPN package? seat consent via DevVpnPrepareActivity)"
                } else {
                    Log.i(TAG, "blocking interface armed, fd=${pfd.fd}")
                    null
                }
                lastEstablishment = pfd
            } catch (e: Exception) {
                lastError = e.toString()
                Log.e(TAG, "kill-switch blocking establish failed", e)
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        releaseMemoryPfd()
        super.onDestroy()
    }
}
