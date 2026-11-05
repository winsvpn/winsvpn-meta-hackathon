package org.winsvpn.app.wear

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.wear.compose.foundation.lazy.ScalingLazyColumn
import androidx.wear.compose.foundation.lazy.items
import androidx.wear.compose.foundation.lazy.rememberScalingLazyListState
import androidx.wear.compose.material.Button
import androidx.wear.compose.material.ButtonDefaults
import androidx.wear.compose.material.Chip
import androidx.wear.compose.material.ChipDefaults
import androidx.wear.compose.material.CircularProgressIndicator
import androidx.wear.compose.material.ListHeader
import androidx.wear.compose.material.MaterialTheme
import androidx.wear.compose.material.PositionIndicator
import androidx.wear.compose.material.Scaffold
import androidx.wear.compose.material.Text
import androidx.wear.compose.material.TimeText
import androidx.wear.compose.material.Vignette
import androidx.wear.compose.material.VignettePosition
import kotlinx.coroutines.delay

/**
 * How the toggle should look and behave right now.
 *
 * Derived in one place so the button label, the button colour and whether the
 * button does anything can never disagree with each other -- the failure mode
 * that makes a watch remote feel broken.
 */
private data class ToggleAppearance(
    val label: String,
    val enabled: Boolean,
    val showSpinner: Boolean,
    val accent: Color,
)

/**
 * Script-neutral button labels.
 *
 * Not string resources on purpose: an ellipsis and a question mark read the
 * same in every language this app could plausibly ship in, so putting them in
 * strings.xml would only add rows to a translator's worklist that they would
 * have to copy back unchanged. Every label with a *word* in it is a resource.
 */
private const val BUSY_LABEL = "…"
private const val UNKNOWN_LABEL = "?"

@Composable
private fun toggleAppearance(state: WatchUiState): ToggleAppearance {
    val colors = MaterialTheme.colors
    return when {
        state.link == PhoneLinkState.CONNECTING && state.snapshot.updatedAt == 0L ->
            ToggleAppearance(BUSY_LABEL, enabled = false, showSpinner = true, accent = colors.primary)

        state.link == PhoneLinkState.UNREACHABLE ->
            ToggleAppearance(
                stringResource(R.string.watch_toggle_phone_unreachable),
                enabled = false,
                showSpinner = false,
                accent = colors.error,
            )

        state.sending ->
            ToggleAppearance(BUSY_LABEL, enabled = false, showSpinner = true, accent = colors.primary)

        else -> when (state.snapshot.status) {
            TunnelStatus.CONNECTING ->
                // Tapping again cancels, exactly as the phone's own power
                // button does while a connect is in flight.
                ToggleAppearance(
                    stringResource(R.string.watch_toggle_cancel),
                    enabled = true,
                    showSpinner = true,
                    accent = colors.primary,
                )

            TunnelStatus.DISCONNECTING ->
                ToggleAppearance(BUSY_LABEL, enabled = false, showSpinner = true, accent = colors.primary)

            TunnelStatus.CONNECTED ->
                ToggleAppearance(
                    stringResource(R.string.watch_toggle_on),
                    enabled = true,
                    showSpinner = false,
                    accent = colors.primary,
                )

            TunnelStatus.PERMISSION_REQUIRED ->
                // A watch cannot grant an OS VPN permission and must not try.
                ToggleAppearance(
                    stringResource(R.string.watch_toggle_off),
                    enabled = false,
                    showSpinner = false,
                    accent = colors.error,
                )

            TunnelStatus.FAILED ->
                ToggleAppearance(
                    stringResource(R.string.watch_toggle_retry),
                    enabled = state.snapshot.canConnect,
                    showSpinner = false,
                    accent = colors.error,
                )

            TunnelStatus.DISCONNECTED ->
                ToggleAppearance(
                    stringResource(R.string.watch_toggle_off),
                    enabled = state.snapshot.canConnect,
                    showSpinner = false,
                    accent = colors.onSurfaceVariant,
                )

            TunnelStatus.UNKNOWN ->
                ToggleAppearance(UNKNOWN_LABEL, enabled = false, showSpinner = false, accent = colors.onSurfaceVariant)
        }
    }
}

/**
 * The one line of prose on the screen. Every branch here is a state that would
 * otherwise render as an unexplained dead button.
 */
@Composable
private fun statusLine(state: WatchUiState): String = when {
    state.link == PhoneLinkState.CONNECTING && state.snapshot.updatedAt == 0L ->
        stringResource(R.string.watch_status_reaching_phone)
    state.link == PhoneLinkState.UNREACHABLE ->
        stringResource(R.string.watch_status_phone_unreachable)
    state.snapshot.status == TunnelStatus.PERMISSION_REQUIRED ->
        stringResource(R.string.watch_status_approve_on_phone)
    state.snapshot.status == TunnelStatus.CONNECTING ->
        stringResource(R.string.watch_status_connecting)
    state.snapshot.status == TunnelStatus.DISCONNECTING ->
        stringResource(R.string.watch_status_disconnecting)
    state.snapshot.status == TunnelStatus.FAILED ->
        // `detail` is whatever the phone sent. It is already in the phone's
        // language and is not ours to translate.
        state.snapshot.detail.ifBlank {
            stringResource(R.string.watch_status_connection_failed)
        }
    state.snapshot.status == TunnelStatus.CONNECTED ->
        stringResource(R.string.watch_status_connected)
    !state.snapshot.canConnect -> stringResource(
        R.string.watch_status_open_app_on_phone,
        stringResource(R.string.app_name),
    )
    state.snapshot.status == TunnelStatus.DISCONNECTED ->
        stringResource(R.string.watch_status_not_connected)
    else -> state.snapshot.detail.ifBlank {
        stringResource(R.string.watch_status_not_connected)
    }
}

@Composable
fun WinsWatchApp(
    state: WatchUiState,
    onToggle: () -> Unit,
    onSelectCountry: (String) -> Unit,
    showCountryList: Boolean,
    onOpenCountryList: () -> Unit,
    onCloseCountryList: () -> Unit,
) {
    MaterialTheme {
        if (showCountryList) {
            CountryListScreen(
                state = state,
                onSelect = { slug ->
                    onSelectCountry(slug)
                    onCloseCountryList()
                },
            )
        } else {
            HomeScreen(
                state = state,
                onToggle = onToggle,
                onOpenCountryList = onOpenCountryList,
            )
        }
    }
}

@Composable
private fun HomeScreen(
    state: WatchUiState,
    onToggle: () -> Unit,
    onOpenCountryList: () -> Unit,
) {
    val appearance = toggleAppearance(state)
    val selected = state.snapshot.selectedCountry

    Scaffold(
        timeText = { TimeText() },
        vignette = { Vignette(vignettePosition = VignettePosition.TopAndBottom) },
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (appearance.showSpinner) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(ButtonDefaults.LargeButtonSize + 8.dp),
                        indicatorColor = appearance.accent,
                        strokeWidth = 3.dp,
                    )
                }
                Button(
                    onClick = onToggle,
                    enabled = appearance.enabled,
                    modifier = Modifier.size(ButtonDefaults.LargeButtonSize),
                    colors = ButtonDefaults.primaryButtonColors(
                        backgroundColor = appearance.accent,
                    ),
                ) {
                    Text(
                        text = appearance.label,
                        style = MaterialTheme.typography.button,
                    )
                }
            }

            Text(
                text = statusLine(state),
                style = MaterialTheme.typography.caption2,
                textAlign = TextAlign.Center,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            )

            Chip(
                onClick = onOpenCountryList,
                enabled = state.snapshot.countries.isNotEmpty(),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                colors = ChipDefaults.secondaryChipColors(),
                label = {
                    Text(
                        text = countryLabel(selected, state.snapshot.countries.isEmpty()),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (selected != null) {
                        Spacer(Modifier.width(6.dp))
                        ServerLoadBar(
                            selected,
                            state.snapshot,
                            // secondaryChipColors, and this chip is enabled
                            // whenever it has a selected country to show.
                            chipBackgroundArgb = ServerLoadColors.chipBackgroundArgb(
                                chipArgb = MaterialTheme.colors.surface.toArgb(),
                                enabled = true,
                                behindArgb = MaterialTheme.colors.background.toArgb(),
                            ),
                            modifier = Modifier.align(Alignment.CenterVertically),
                        )
                    }
                },
            )
        }
    }
}

@Composable
private fun countryLabel(selected: WatchCountry?, listEmpty: Boolean): String = when {
    // The country name comes from the phone's server list, which is not a
    // resource on this device and must not be translated here.
    selected != null -> listOf(selected.flag, selected.name).filter { it.isNotBlank() }.joinToString(" ")
    listEmpty -> stringResource(R.string.watch_country_none_available)
    else -> stringResource(R.string.watch_country_choose)
}

@Composable
private fun CountryListScreen(
    state: WatchUiState,
    onSelect: (String) -> Unit,
) {
    val listState = rememberScalingLazyListState()

    Scaffold(
        timeText = { TimeText() },
        vignette = { Vignette(vignettePosition = VignettePosition.TopAndBottom) },
        positionIndicator = { PositionIndicator(scalingLazyListState = listState) },
    ) {
        ScalingLazyColumn(
            modifier = Modifier.fillMaxSize(),
            state = listState,
        ) {
            item {
                ListHeader { Text(stringResource(R.string.watch_country_list_title)) }
            }
            items(state.snapshot.countries, key = { it.slug }) { country ->
                val isSelected = country.slug == state.snapshot.selectedSlug
                Chip(
                    onClick = { onSelect(country.slug) },
                    // Changing country routes through the phone app's own
                    // picker logic, so it is unavailable for the same reason
                    // connecting is when the phone app is closed.
                    enabled = state.snapshot.canConnect || isSelected,
                    modifier = Modifier.fillMaxWidth(),
                    colors = if (isSelected) {
                        ChipDefaults.primaryChipColors()
                    } else {
                        ChipDefaults.secondaryChipColors()
                    },
                    label = {
                        Text(
                            text = listOf(country.flag, country.name)
                                .filter { it.isNotBlank() }
                                .joinToString(" "),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(6.dp))
                        ServerLoadBar(
                            country,
                            state.snapshot,
                            // The same colour and enabled state the Chip above
                            // is given, composited the way Wear draws it.
                            chipBackgroundArgb = ServerLoadColors.chipBackgroundArgb(
                                chipArgb = if (isSelected) {
                                    MaterialTheme.colors.primary.toArgb()
                                } else {
                                    MaterialTheme.colors.surface.toArgb()
                                },
                                enabled = state.snapshot.canConnect || isSelected,
                                behindArgb = MaterialTheme.colors.background.toArgb(),
                            ),
                            modifier = Modifier.align(Alignment.CenterVertically),
                        )
                    },
                )
            }
            if (state.snapshot.countries.isEmpty()) {
                item {
                    Text(
                        text = stringResource(
                            R.string.watch_country_list_empty,
                            stringResource(R.string.app_name),
                        ),
                        style = MaterialTheme.typography.caption2,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

/**
 * Load-bar colours. The watch theme is always dark, so the fills and track are
 * the dark set the phone app uses (lib/server_load_bar.dart
 * ServerLoadPalette.dark), value for value, so one server reads the same on
 * phone and wrist.
 *
 * THE OUTLINE IS CHOSEN PER CHIP. The bar's outer edge is its 1 dp outline
 * (the border is drawn over the fill), and no single colour reaches 3:1 on both
 * the dark unselected chip (Wear default surface 0xFF303133) and the light-blue
 * selected chip (default primary 0xFFAECBFA). So [outlineFor] picks, for the
 * chip's actual composited background, whichever of two colours contrasts more:
 * the light [outline] 0xFFDADCE0 (Wear default onSurfaceVariant) or the dark
 * [outlineOnLight], which is the track colour 0xFF1E293B. Round LC turn 2 found
 * the light outline at 1.20:1 on the selected chip; this closes that.
 * Wear defaults (surface, primary, background, ContentAlpha.disabled 0.38) were
 * read from the compose-material 1.6.2 bytecode. Every background the bar can
 * sit on is enumerated in PhoneSnapshotTest.
 */
internal object ServerLoadColors {
    val low = Color(0xFF00C853)
    val elevated = Color(0xFFFFAB40)
    val high = Color(0xFFFF334B)
    val track = Color(0xFF1E293B)
    val outline = Color(0xFFDADCE0)
    val outlineOnLight = Color(0xFF1E293B)

    /** Wear's disabled chip background alpha (ContentAlpha.disabled). */
    const val DISABLED_CHIP_ALPHA = 0.38f

    /**
     * The colour actually behind the bar: the chip colour, or for a disabled
     * chip that colour at [DISABLED_CHIP_ALPHA] over [behindArgb] (what Wear
     * draws). Opaque ARGB.
     */
    fun chipBackgroundArgb(chipArgb: Int, enabled: Boolean, behindArgb: Int): Int {
        if (enabled) return chipArgb or (0xFF shl 24)
        fun mix(shift: Int): Int {
            val f = (chipArgb shr shift) and 0xFF
            val b = (behindArgb shr shift) and 0xFF
            return Math.round(f * DISABLED_CHIP_ALPHA + b * (1f - DISABLED_CHIP_ALPHA)).coerceIn(0, 255)
        }
        return (0xFF shl 24) or (mix(16) shl 16) or (mix(8) shl 8) or mix(0)
    }

    /** Whichever outline contrasts more with [backgroundArgb]. */
    fun outlineFor(backgroundArgb: Int): Color =
        if (contrast(outline.toArgb(), backgroundArgb) >= contrast(outlineOnLight.toArgb(), backgroundArgb)) {
            outline
        } else {
            outlineOnLight
        }

    /** WCAG 2.x contrast ratio of two opaque ARGB colours. */
    fun contrast(a: Int, b: Int): Double {
        fun lum(c: Int): Double {
            fun ch(v: Int): Double {
                val x = v / 255.0
                return if (x <= 0.03928) x / 12.92 else Math.pow((x + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * ch((c shr 16) and 0xFF) + 0.7152 * ch((c shr 8) and 0xFF) + 0.0722 * ch(c and 0xFF)
        }
        val la = lum(a)
        val lb = lum(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    /** Null means no fill (unknown). Same thresholds as the phone: 60 and 85. */
    fun fillFor(loadPct: Int?): Color? = when {
        loadPct == null || loadPct < 0 || loadPct > 100 -> null
        loadPct >= 85 -> high
        loadPct >= 60 -> elevated
        else -> low
    }

    /**
     * Fraction of the bar to fill. A known value always shows a small nub so a
     * known 0% stays distinguishable from unknown, as on the phone.
     */
    fun fillFraction(loadPct: Int?): Float =
        if (loadPct == null) 0f else (loadPct / 100f).coerceIn(0.06f, 1f)
}

/**
 * A thin horizontal load bar. Unknown renders as the empty outlined track, the
 * same choice every other target makes. Wear OS has no tooltip; the value is
 * exposed to TalkBack through the content description, which is derived from
 * the FRESH figure only, so a stale value is never announced.
 *
 * Expiry: the figure is re-judged by [LoadFreshness] on every composition, and
 * a [LaunchedEffect] waits until the figure's expiry and then bumps [tick] to
 * force one recomposition that turns the bar grey. The effect is cancelled
 * when the bar leaves composition or its inputs change, so nothing outlives
 * the bar. (Its delay can run late after deep sleep; the view model's
 * 10-second state poll recomposes the screen in that case.)
 */
@Composable
private fun ServerLoadBar(
    country: WatchCountry,
    snapshot: PhoneSnapshot,
    chipBackgroundArgb: Int,
    modifier: Modifier = Modifier,
) {
    var tick by remember { mutableStateOf(0) }
    val nowElapsed = SystemClock.elapsedRealtime()
    val nowWall = System.currentTimeMillis()
    val loadPct = LoadFreshness.visibleLoadPct(country, snapshot, nowElapsed, nowWall)
    val untilExpiry = LoadFreshness.msUntilExpiry(country, snapshot, nowElapsed, nowWall)
    LaunchedEffect(country, snapshot, tick) {
        if (untilExpiry != null) {
            delay(untilExpiry)
            tick++
        }
    }
    val description = if (loadPct == null) {
        stringResource(R.string.watch_server_load_unknown)
    } else {
        stringResource(R.string.watch_server_load_percent, loadPct)
    }
    val shape = RoundedCornerShape(3.dp)
    val fill = ServerLoadColors.fillFor(loadPct)
    Box(
        modifier = modifier
            .size(width = 28.dp, height = 6.dp)
            .clip(shape)
            .background(ServerLoadColors.track)
            // Drawn over the fill, so this is always the bar's outer edge.
            .border(1.dp, ServerLoadColors.outlineFor(chipBackgroundArgb), shape)
            .semantics { contentDescription = description },
    ) {
        if (fill != null) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(ServerLoadColors.fillFraction(loadPct))
                    .background(fill),
            )
        }
    }
}
