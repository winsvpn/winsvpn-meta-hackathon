package org.winsvpn.app

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.util.Log

/**
 * PROFILE SOURCE SET ONLY. Added 2026-08-08 by the Android full-bar lane.
 *
 * Mirrors `src/debug/kotlin/org/winsvpn/app/DevVpnPrepareActivity.kt` for
 * the profile variant. The profile variant now carries
 * `applicationIdSuffix = ".profile"` so it installs alongside the store build
 * (`org.winsvpn.app`) and the debug build (`org.winsvpn.app.debug`) without
 * requiring an uninstall that would destroy `SecureFileStore`
 * (`client_keypair.json`, `user_pin.txt`, `install_id.txt`) and burn a
 * device slot. See `android/app/build.gradle.kts` and
 * `docs/handoff/WINN3_ANDROID_FULL_BAR_20260808.md`.
 *
 * Why this exists: identical to the debug copy — `VpnService.Builder.establish()`
 * returns null unless this package is the prepared VPN holder; `appops set
 * ACTIVATE_VPN allow` authorises but does not seat it, and in the shipping app
 * the prepare call is behind the PIN gate. This activity performs that one call
 * and nothing else, so the real `VpnTunnelService` can be exercised on a
 * release-shaped AOT artefact without creating a credential.
 *
 * Safety: refuses to raise the consent dialog itself (logs and finishes if
 * `prepare()` returns an Intent). Takes no extras, starts no tunnel.
 */
class DevVpnPrepareActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val intent = VpnService.prepare(applicationContext)
        if (intent == null) {
            Log.i(TAG, "DEVPREPARE: ok=true package is the prepared VPN package")
        } else {
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
