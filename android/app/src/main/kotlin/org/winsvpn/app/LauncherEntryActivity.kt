package org.winsvpn.app

import android.app.Activity
import android.content.Intent
import android.os.Bundle

abstract class LauncherEntryActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startActivity(Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        })
        finish()
        overridePendingTransition(0, 0)
    }
}

class RealLauncherActivity : LauncherEntryActivity()

class DecoyLauncherActivity : LauncherEntryActivity()
