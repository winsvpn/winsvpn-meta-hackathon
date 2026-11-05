package org.winsvpn.app.wear

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * The entire watch app: a connect/disconnect toggle and a country list.
 *
 * There is deliberately no settings screen, no account screen and no
 * diagnostics. Anything that needs a credential, a key or the tunnel config
 * belongs on the phone, which is also the only place the OS will present the
 * VPN consent prompt.
 */
class MainActivity : ComponentActivity() {

    private val viewModel: WatchViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val state by viewModel.uiState.collectAsStateWithLifecycle()
            var showCountryList by remember { mutableStateOf(false) }

            WinsWatchApp(
                state = state,
                onToggle = viewModel::toggleConnection,
                onSelectCountry = viewModel::selectCountry,
                showCountryList = showCountryList,
                onOpenCountryList = { showCountryList = true },
                onCloseCountryList = { showCountryList = false },
            )
        }
    }

    override fun onResume() {
        super.onResume()
        // startPolling() requests state on its first iteration.
        viewModel.startPolling()
    }

    override fun onPause() {
        viewModel.stopPolling()
        super.onPause()
    }
}
