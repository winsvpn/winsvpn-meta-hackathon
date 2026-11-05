package org.winsvpn.devicecheck

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.widget.TextView

/**
 * Keeps the process in the foreground for the duration of the run so the
 * platform does not stop the service mid-check. It does nothing else.
 */
class CheckActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        val view = TextView(this)
        view.setBackgroundColor(Color.BLACK)
        view.setTextColor(Color.GREEN)
        view.textSize = 16f
        view.text = "Winn Android device verification running.\n" +
            "Output goes to logcat under the tag ${CheckVpnService.TAG}."
        setContentView(view)

        val consent = VpnService.prepare(this)
        if (consent != null) {
            Log.e(CheckVpnService.TAG,
                "RESULT | 0-consent | FAIL | VpnService.prepare() wants user consent; " +
                    "grant it or the run cannot establish a tunnel")
            view.text = "VPN consent missing. Nothing was established."
            return
        }
        val mode = intent?.getStringExtra(CheckVpnService.EXTRA_MODE) ?: "scoped"

        // The winn3 staged-posture check is a separate service with a separate
        // tag. It needs no engine binary and no gateway -- WINN3_TUN_LAYER §4 is
        // a contract about what the HOST configures -- so it is kept apart from
        // the AWG run rather than bolted onto it, and nothing above step 0 of
        // the AWG run changes.
        if (mode == "v3-posture") {
            view.text = "Winn Protocol v3 staged-posture check running.\n" +
                "Output goes to logcat under the tag ${V3PostureCheckService.TAG}."
            startService(Intent(this, V3PostureCheckService::class.java))
            return
        }

        val service = Intent(this, CheckVpnService::class.java)
        service.putExtra(CheckVpnService.EXTRA_MODE, mode)
        service.putExtra(CheckVpnService.EXTRA_AWG_PADDING,
            intent?.getStringExtra(CheckVpnService.EXTRA_AWG_PADDING) ?: "shipping")
        startService(service)
    }
}
