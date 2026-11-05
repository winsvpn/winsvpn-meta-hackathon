// The one Flutter load bar, used by every Flutter surface that lists or shows
// a server (Android, iOS, macOS, Windows, Linux, Android TV).
//
// Parsing and freshness live in server_load.dart; this file only draws, and
// schedules the one rebuild that turns a bar grey when its figure expires.
//
// UNKNOWN IS AN EMPTY NEUTRAL TRACK, NOT NOTHING. Every target renders the same
// outlined grey track with no fill when the hub gave no usable value, or the
// value is older than kServerLoadMaxAge. Reasons:
//   * rows stay aligned, so a list that mixes known and unknown servers does
//     not shift names sideways;
//   * "the hub did not say" stays distinguishable from "this build has no load
//     bar", which matters while old hubs, stale values and new clients coexist;
//   * a known 0% still differs from unknown, because a known value always
//     draws at least a small nub of fill (see [_minimumFillFraction]).
// Screen readers and the tooltip say "Server load unknown" in that state, so a
// stale figure is never announced.

import 'dart:async';

import 'package:flutter/material.dart';

import 'l10n/app_localizations.dart';
import 'server_load.dart';

/// Colours for the bar, one set per brightness.
///
/// Contrast is pinned by test/server_load_bar_test.dart: every fill and the
/// outline stay at or above 3:1 (WCAG 1.4.11, non-text) against the track and
/// against the ACTUAL composite of each translucent panel the bar sits on.
@immutable
class ServerLoadPalette {
  const ServerLoadPalette({
    required this.low,
    required this.elevated,
    required this.high,
    required this.track,
    required this.outline,
  });

  /// On the app's light surfaces (the main panel and the server picker both
  /// render under `_lightSurfaceTheme`, on the translucent `_surfacePanel` and
  /// `_surfacePanelSoft` colours over the dark scaffold). Amber, red and the
  /// outline are darker than the app's usual accents because those accents
  /// fall below 3:1 on the soft panel composite (Round LC OI-7).
  static const ServerLoadPalette light = ServerLoadPalette(
    low: Color(0xFF046A38), // main.dart _emuGreen
    elevated: Color(0xFFA63A00), // dark amber, 3.39:1 on the soft panel
    high: Color(0xFFA62110), // dark red, 3.85:1 on the soft panel
    track: Color(0xFFE5E7EB), // main.dart disabled button background
    outline: Color(0xFF475569), // slate, 3.95:1 on the soft panel
  );

  /// Under a dark theme (the app's root ThemeData is dark).
  static const ServerLoadPalette dark = ServerLoadPalette(
    low: Color(0xFF00C853), // main.dart _powerConnectedColor
    elevated: Color(0xFFFFAB40), // Colors.orangeAccent
    high: Color(0xFFFF334B), // main.dart _powerDisconnectedColor
    track: Color(0xFF1E293B), // main.dart _surfaceElevated
    outline: Color(0xFF64748B), // main.dart muted input icon
  );

  final Color low;
  final Color elevated;
  final Color high;
  final Color track;
  final Color outline;

  static ServerLoadPalette of(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark ? dark : light;

  /// Fill colour for [level], or null when nothing is filled.
  Color? fillFor(ServerLoadLevel level) {
    switch (level) {
      case ServerLoadLevel.low:
        return low;
      case ServerLoadLevel.elevated:
        return elevated;
      case ServerLoadLevel.high:
        return high;
      case ServerLoadLevel.unknown:
        return null;
    }
  }
}

/// The accessibility label and tooltip text for [pct] (already parsed).
///
/// Falls back to English when no [AppLocalizations] is in scope, so the bar
/// can never throw for want of a delegate.
String serverLoadLabel(AppLocalizations? l10n, int? pct) {
  if (pct == null) return l10n?.serverLoadUnknown ?? 'Server load unknown';
  return l10n?.serverLoadPercent(pct) ?? 'Server load $pct%';
}

/// Smallest fill drawn for a KNOWN value, as a fraction of the bar, so that a
/// known 0% is visibly different from unknown.
const double _minimumFillFraction = 0.06;

/// A thin horizontal bar showing one server's load.
///
/// Takes the raw node map (anything, including a malformed one) and runs it
/// through [freshServerLoadPct], so no caller can hand it something that
/// throws, and nothing older than [kServerLoadMaxAge] is ever drawn.
///
/// Expiry: while a figure is shown, the bar holds one [Timer] for the moment
/// it expires and rebuilds itself then. The timer belongs to this State: it is
/// replaced when the node changes and cancelled in [State.dispose]. On app
/// resume the bar re-evaluates, because a timer can fire late after a suspend.
class ServerLoadBar extends StatefulWidget {
  const ServerLoadBar({
    super.key,
    required this.node,
    this.width = 36,
    this.height = 6,
  });

  /// The node map as the app holds it, carrying `load_pct` and the receipt
  /// stamps. Null or a non-map renders unknown.
  final Object? node;
  final double width;
  final double height;

  @override
  State<ServerLoadBar> createState() => _ServerLoadBarState();
}

class _ServerLoadBarState extends State<ServerLoadBar>
    with WidgetsBindingObserver {
  Timer? _expiry;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _scheduleExpiry();
  }

  @override
  void didUpdateWidget(ServerLoadBar oldWidget) {
    super.didUpdateWidget(oldWidget);
    _scheduleExpiry();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && mounted) {
      setState(_scheduleExpiry);
    }
  }

  @override
  void dispose() {
    _expiry?.cancel();
    _expiry = null;
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  void _scheduleExpiry() {
    _expiry?.cancel();
    _expiry = null;
    final remaining = serverLoadTimeToExpiry(widget.node);
    if (remaining == null) return;
    _expiry = Timer(remaining, () {
      if (!mounted) return;
      // Rebuild, and re-arm if (say) a clock correction left time on it.
      setState(_scheduleExpiry);
    });
  }

  @override
  Widget build(BuildContext context) {
    final pct = freshServerLoadPct(widget.node);
    final level = serverLoadLevel(pct);
    final palette = ServerLoadPalette.of(context);
    final fill = palette.fillFor(level);
    final label = serverLoadLabel(
      Localizations.of<AppLocalizations>(context, AppLocalizations),
      pct,
    );
    final fraction = pct == null
        ? 0.0
        : (pct / 100).clamp(_minimumFillFraction, 1.0).toDouble();
    final radius = BorderRadius.circular(widget.height / 2);

    final bar = SizedBox(
      width: widget.width,
      height: widget.height,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: palette.track,
          borderRadius: radius,
          border: Border.all(color: palette.outline, width: 1),
        ),
        child: fill == null
            ? const SizedBox.expand()
            : ClipRRect(
                borderRadius: radius,
                child: Align(
                  alignment: AlignmentDirectional.centerStart,
                  child: FractionallySizedBox(
                    key: const ValueKey<String>('server-load-fill'),
                    widthFactor: fraction,
                    heightFactor: 1,
                    child: ColoredBox(color: fill),
                  ),
                ),
              ),
      ),
    );

    return Tooltip(
      message: label,
      excludeFromSemantics: true,
      // Not a semantics container: inside a ListTile (which merges its
      // children) the load joins the row's own label, so a screen reader reads
      // "Spain (Madrid), Server load 45%" as one item.
      child: Semantics(
        label: label,
        child: ExcludeSemantics(child: bar),
      ),
    );
  }
}

/// A [ServerLoadBar] that follows the LIVE listing instead of a snapshot.
///
/// The server picker renders a copy of the list taken when it opened. This
/// wrapper re-resolves the node through [resolve] whenever [listing] notifies
/// (the app bumps it when a fetch replaces the list), so an open picker picks
/// up new figures without being reopened. Between notifications the bar's own
/// expiry timer still turns an old figure grey.
class LiveServerLoadBar extends StatelessWidget {
  const LiveServerLoadBar({
    super.key,
    required this.listing,
    required this.resolve,
  });

  final Listenable listing;
  final Object? Function() resolve;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: listing,
        builder: (context, _) => ServerLoadBar(node: resolve()),
      );
}
