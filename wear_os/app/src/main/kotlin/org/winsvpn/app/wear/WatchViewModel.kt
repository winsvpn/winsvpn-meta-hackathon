package org.winsvpn.app.wear

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Everything the two screens render. */
data class WatchUiState(
    val link: PhoneLinkState = PhoneLinkState.CONNECTING,
    val snapshot: PhoneSnapshot = PhoneSnapshot.EMPTY,
    /** A command has been handed to the Data Layer and not yet answered. */
    val sending: Boolean = false,
) {
    /**
     * The toggle spins whenever the phone is mid-transition or the watch is
     * still waiting for the phone to acknowledge a tap, so a slow link never
     * looks like a dead button.
     */
    val busy: Boolean
        get() = sending || snapshot.status.isBusy

    val canInteract: Boolean
        get() = link == PhoneLinkState.LINKED && !busy
}

class WatchViewModel(application: Application) : AndroidViewModel(application) {

    private val link = PhoneLink(application)

    private val _uiState = MutableStateFlow(WatchUiState())
    val uiState: StateFlow<WatchUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    init {
        viewModelScope.launch {
            link.snapshots().collect(::applySnapshot)
        }
    }

    /** Toggle is the phone's own single connect/disconnect entry point. */
    fun toggleConnection() {
        val status = _uiState.value.snapshot.status
        val command = if (status.isOnOrGoingOn) {
            WatchLink.COMMAND_DISCONNECT
        } else {
            WatchLink.COMMAND_CONNECT
        }
        dispatch(command)
    }

    fun selectCountry(slug: String) {
        if (slug.isBlank() || slug == _uiState.value.snapshot.selectedSlug) return
        dispatch(WatchLink.COMMAND_SELECT_COUNTRY, slug)
    }

    fun refresh() = dispatch(WatchLink.COMMAND_REQUEST_STATE, silent = true)

    private fun dispatch(command: String, slug: String? = null, silent: Boolean = false) {
        val expectedNodeId = if (silent) null else _uiState.value.snapshot.sourceNodeId
        viewModelScope.launch {
            if (!silent) {
                _uiState.update { it.copy(sending = true) }
            }
            val delivered = link.send(command, slug, expectedNodeId)
            _uiState.update { current ->
                current.copy(
                    sending = false,
                    // A delivery failure is the only reliable "phone
                    // unreachable" signal there is; a delivery success does not
                    // by itself mean the phone app is running, so LINKED is set
                    // when a snapshot actually arrives, not here.
                    link = if (delivered) current.link else PhoneLinkState.UNREACHABLE,
                )
            }
        }
    }

    private var foreground = false
    private var lastLiveSnapshotAtMs: Long? = null

    private fun invalidateLiveSnapshot(link: PhoneLinkState) {
        lastLiveSnapshotAtMs = null
        _uiState.update {
            it.copy(
                link = link,
                snapshot = PhoneSnapshot.EMPTY,
                sending = false,
            )
        }
    }

    private fun applySnapshot(snapshot: PhoneSnapshot) {
        if (!foreground) return
        lastLiveSnapshotAtMs = android.os.SystemClock.elapsedRealtime()
        _uiState.update {
            it.copy(link = PhoneLinkState.LINKED, snapshot = snapshot)
        }
    }

    /**
     * A slow heartbeat, not a busy loop: pushes cover the common case, and this
     * only exists so a missed push during a connect transition cannot leave the
     * watch showing "Connecting" forever.
     */
    fun startPolling() {
        foreground = true
        // Nothing has been asked yet: "reaching", never "unreachable".
        invalidateLiveSnapshot(PhoneLinkState.CONNECTING)
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (isActive) {
                val last = lastLiveSnapshotAtMs
                if (last != null &&
                    android.os.SystemClock.elapsedRealtime() - last >= SNAPSHOT_TTL_MS
                ) {
                    invalidateLiveSnapshot(PhoneLinkState.UNREACHABLE)
                }
                refresh()
                delay(
                    if (_uiState.value.snapshot.status.isBusy) FAST_POLL_MS
                    else IDLE_POLL_MS
                )
            }
        }
    }

    fun stopPolling() {
        foreground = false
        pollJob?.cancel()
        pollJob = null
        invalidateLiveSnapshot(PhoneLinkState.CONNECTING)
    }

    override fun onCleared() {
        pollJob?.cancel()
        super.onCleared()
    }

    private companion object {
        const val FAST_POLL_MS = 2_000L
        const val IDLE_POLL_MS = 10_000L
        const val SNAPSHOT_TTL_MS = 30_000L
    }
}
