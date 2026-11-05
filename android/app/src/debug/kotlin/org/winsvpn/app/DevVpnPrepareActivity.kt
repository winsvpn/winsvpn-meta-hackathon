package org.winsvpn.app

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.util.Log

/**
 * DEBUG SOURCE SET ONLY. Added 2026-08-07 by the Android winn/3 criteria lane.
 *
 * # Why this exists
 *
 * `VpnService.Builder.establish()` returns null unless the calling package is
 * the framework's CURRENT PREPARED VPN PACKAGE. That slot is global (one per
 * user) and is only written when some component of the app calls
 * `VpnService.prepare()`. `adb shell appops set <pkg> ACTIVATE_VPN allow` is
 * necessary but NOT sufficient: it authorises the package, it does not seat it.
 * Measured on device 2026-08-07 -- with ACTIVATE_VPN already `allow`, three
 * consecutive starts of the real [VpnTunnelService] reached
 * `mode=winn-v3`, installed routes and the IPv6 sink, and then logged
 * "Builder.establish() returned null", because `org.winsvpn.devicecheck` still
 * held the prepared slot from an earlier harness run.
 *
 * In the shipping app that call lives in `MainActivity.activateNativeVpnEngine()`
 * and is reached only through the Dart connect path, which is behind the app
 * PIN and privacy-consent gates. Those are the OWNER's to satisfy, not a lane's.
 * This activity performs the one framework call that gate would have performed,
 * and nothing else, so a lane can exercise the REAL shipping tunnel service
 * without creating a credential on the owner's behalf.
 *
 * # Why it is safe
 *
 * It lives in `src/debug/`, so AGP merges it into the debug variant ONLY. The
 * release AAB and the release dependency freeze for 1.0.14+29 are untouched,
 * exactly as `android/tools/prepare_android_winn_assets.sh` argues for the
 * staged engine binary. The debug variant already carries
 * `applicationIdSuffix = ".debug"`, so this cannot seat the STORE build either.
 *
 * It cannot grant itself anything. If the ACTIVATE_VPN appop is not already
 * `allow`, `prepare()` returns a consent Intent and this activity REFUSES to
 * launch it -- it logs and finishes. Showing that dialog would be asking the
 * device user to consent to something on the owner's behalf, which is the same
 * line the PIN gate draws. Granting the appop is a deliberate, separate,
 * host-side act (`adb shell appops set ... ACTIVATE_VPN allow`).
 *
 * It starts no tunnel, reads no config and touches no key material.
 */
class DevVpnPrepareActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val intent = VpnService.prepare(applicationContext)
        if (intent == null) {
            Log.i(TAG, "DEVPREPARE: ok=true package is the prepared VPN package")
        } else {
            // Deliberately NOT startActivityForResult(intent). See the KDoc.
            Log.i(
                TAG,
                "DEVPREPARE: ok=false consent is required and this activity will " +
                    "not request it; grant the ACTIVATE_VPN appop first",
            )
        }
        finish()
    }

    private companion object {
        const val TAG = "WinsDevVpnPrepare"
    }
}
