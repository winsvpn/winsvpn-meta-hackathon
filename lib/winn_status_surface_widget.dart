import 'dart:async';

import 'package:flutter/material.dart';

import 'winn_status_surface.dart';

/// Reads one native readiness map, or null/throws when no platform support
/// exists or the read failed.
typedef WinnReadinessReader = Future<Object?> Function();

/// The dashboard's honest status surface: gate state, and whether traffic is
/// actually flowing, plus the byte counters that prove it.
///
/// The widget is deliberately dumb about the *meaning* of its three rows --
/// all derivation lives in lib/winn_status_surface.dart, which is pure and
/// testable without a widget. What this widget owns is only the cadence:
/// it re-reads the native readiness map on [pollInterval] and keeps the last
/// two samples so the traffic row can measure a delta rather than a moment.
///
/// Honesty rules baked into the polling:
///   * A platform with no readiness channel ([probeAvailable] false, or
///     [readinessReader] null) shows the gate as `unprobed` -- connected but
///     unverifiable -- never as `carrying`.
///   * A read that fails, or a snapshot older than [maxSampleAge], is treated
///     as NO probe, not as a stale-but-trusted one. Absence is its own row.
///   * The traffic row needs two fresh samples with counters. It degrades to
///     "Not available" rather than guessing "Flowing" from a single read.
///   * The gate surrenders to the engine's OWN transfer-proven signal: when a
///     platform reports `transport_observed_both_ways=false` the gate is never
///     `carrying` -- a false "Connected" on top of every readiness bit being
///     true is the exact defect this surface exists to surface.
class WinnStatusSurface extends StatefulWidget {
  const WinnStatusSurface({
    super.key,
    required this.connected,
    required this.connectInFlight,
    required this.probeAvailable,
    required this.readinessReader,
    required this.translate,
    this.showGate = true,
    this.pollInterval = const Duration(seconds: 3),
    this.maxSampleAge = const Duration(seconds: 12),
    this.minimumAdvanceBytes = 1,
    this.activeColor = const Color(0xFF2E7D32),
    this.warnColor = const Color(0xFFEF6C00),
    this.inactiveColor = const Color(0xFFB3261E),
    this.textColor = const Color(0xFF6B7280),
  });

  /// Whether to render the Gate: row.
  final bool showGate;

  /// The app's own belief about whether a session is live. On platforms with
  /// a readiness channel this is the composite proof the channel computed; on
  /// platforms without one it is the only signal the gate row may use.
  final bool connected;

  /// A connect request is in flight.
  final bool connectInFlight;

  /// Whether this platform exposes a native readiness read at all.
  final bool probeAvailable;

  /// Reads the native readiness map. Null/throw means "no probe this poll".
  final WinnReadinessReader? readinessReader;

  /// `main.dart`'s `_t`, so every row is localized through the app's map.
  final String Function(String english) translate;

  final Duration pollInterval;
  final Duration maxSampleAge;
  final int minimumAdvanceBytes;
  final Color activeColor;
  final Color warnColor;
  final Color inactiveColor;
  final Color textColor;

  @override
  State<WinnStatusSurface> createState() => _WinnStatusSurfaceState();
}

class _WinnStatusSurfaceState extends State<WinnStatusSurface>
    with WidgetsBindingObserver {
  Timer? _timer;
  int _readSerial = 0;
  // Set while no view is on screen (paused, hidden, detached).
  bool _offScreen = false;
  WinnReadinessSnapshot? _last;
  WinnReadinessSnapshot? _prior;
  DateTime _lastReadAt = DateTime.fromMillisecondsSinceEpoch(0);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    if (widget.probeAvailable && widget.readinessReader != null) {
      unawaited(_poll());
      _timer = Timer.periodic(widget.pollInterval, (_) => unawaited(_poll()));
    }
  }

  @override
  void didUpdateWidget(WinnStatusSurface oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.connected != widget.connected ||
        oldWidget.connectInFlight != widget.connectInFlight ||
        oldWidget.probeAvailable != widget.probeAvailable) {
      _readSerial++;
      _last = null;
      _prior = null;
      _lastReadAt = DateTime.fromMillisecondsSinceEpoch(0);
    }
    final shouldProbe = widget.probeAvailable && widget.readinessReader != null;
    if (shouldProbe && _timer == null) {
      unawaited(_poll());
      _timer = Timer.periodic(widget.pollInterval, (_) => unawaited(_poll()));
    } else if (!shouldProbe && _timer != null) {
      _timer!.cancel();
      _timer = null;
      _last = null;
      _prior = null;
    }
  }

  /// `inactive` is still on screen (an unfocused desktop window, Android split
  /// screen, a system sheet over the app): reads continue and the samples are
  /// kept. Leaving the screen (paused, hidden, detached) stops the reads and
  /// drops the samples; the first resume after that reads at once, so the
  /// row shows nothing until a new result arrives.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.inactive) return;
    final resumed = state == AppLifecycleState.resumed;
    if (resumed && !_offScreen) return;
    _offScreen = !resumed;
    _readSerial++;
    _timer?.cancel();
    _timer = null;
    if (!mounted) return;
    setState(() {
      _last = null;
      _prior = null;
      _lastReadAt = DateTime.fromMillisecondsSinceEpoch(0);
    });
    if (resumed && widget.probeAvailable && widget.readinessReader != null) {
      unawaited(_poll());
      _timer = Timer.periodic(widget.pollInterval, (_) => unawaited(_poll()));
    }
  }

  @override
  void dispose() {
    _readSerial++;
    WidgetsBinding.instance.removeObserver(this);
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _poll() async {
    final reader = widget.readinessReader;
    final now = DateTime.now();
    if (reader == null) return;
    final lifecycle = WidgetsBinding.instance.lifecycleState;
    if (lifecycle == AppLifecycleState.paused ||
        lifecycle == AppLifecycleState.hidden ||
        lifecycle == AppLifecycleState.detached) {
      return;
    }
    final serial = ++_readSerial;
    try {
      final raw = await reader();
      if (!mounted || serial != _readSerial) return;
      final map = raw is Map<Object?, Object?> ? raw : null;
      if (map == null) {
        setState(() {
          _last = null;
          _prior = null;
        });
        return;
      }
      setState(() {
        _prior = _last;
        _last = winnReadinessSnapshot(
          sampledAt: now,
          serviceActive: map['service_active'] ?? map['active'],
          engineReady: map['engine_ready'] ?? map['provider_engine_ready'],
          interfaceOpen: map['interface_open'],
          trafficRxBytes: map['traffic_rx_bytes'],
          trafficTxBytes: map['traffic_tx_bytes'],
          rxBytes: map['tun_rx_bytes'],
          txBytes: map['tun_tx_bytes'],
          awgRxBytes: map['awg_rx_bytes'],
          awgTxBytes: map['awg_tx_bytes'],
          transportProvenBothWays: map['transport_observed_both_ways'],
        );
        _lastReadAt = now;
      });
    } catch (_) {
      if (!mounted || serial != _readSerial) return;
      setState(() {
        _last = null;
        _prior = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final now = DateTime.now();
    final probeStale = now.difference(_lastReadAt) > widget.maxSampleAge;
    final snapshot = widget.probeAvailable && !probeStale ? _last : null;

    final gate = winnGateState(
      snapshot: snapshot,
      connected: widget.connected,
      connectInFlight: widget.connectInFlight,
      probeAvailable: widget.probeAvailable,
    );

    final liveSession =
        gate == WinnGateState.carrying ||
            gate == WinnGateState.establishing ||
            gate == WinnGateState.connecting ||
            gate == WinnGateState.unprobed;
    final flow = liveSession
        ? winnTrafficFlow(
            prior: _prior,
            current: snapshot ??
                WinnReadinessSnapshot(
                  serviceActive: false,
                  engineReady: false,
                  interfaceOpen: false,
                  rxBytes: null,
                  txBytes: null,
                  sampledAt: now,
                ),
            now: now,
            maxSampleAge: widget.maxSampleAge,
            minimumAdvanceBytes: widget.minimumAdvanceBytes,
          )
        : WinnTrafficFlow.unknown;

    final rate = winnTrafficRateBytesPerSecond(
      prior: _prior,
      current: snapshot ?? _last,
    );
    final counters = snapshot != null && snapshot.counterPresent
        ? snapshot
        : null;

    final gateColor = switch (gate) {
      WinnGateState.carrying => widget.activeColor,
      WinnGateState.connecting || WinnGateState.establishing => widget.warnColor,
      WinnGateState.disconnected => widget.inactiveColor,
      WinnGateState.unprobed => widget.warnColor,
    };
    final flowColor = switch (flow) {
      WinnTrafficFlow.flowing => widget.activeColor,
      WinnTrafficFlow.idle => widget.warnColor,
      WinnTrafficFlow.unknown => widget.textColor,
    };

    final hasCounters = counters != null &&
        counters.rxBytes != null &&
        counters.txBytes != null;

    return Semantics(
      container: true,
      label: 'Tunnel status',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (widget.showGate) ...[
            _StatusRow(
              label: widget.translate('Gate:'),
              value: widget.translate(winnGateStatePhrase(gate)),
              indicatorColor: gateColor,
              textColor: widget.textColor,
            ),
            const SizedBox(height: 2),
          ],
          _StatusRow(
            label: widget.translate('Traffic:'),
            value: _trafficFlowValue(
              flow: flow,
              rate: rate,
            ),
            indicatorColor: flowColor,
            textColor: widget.textColor,
          ),
          if (hasCounters) ...[
            const SizedBox(height: 2),
            Padding(
              padding: const EdgeInsets.only(left: 16),
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: Text(
                  '${widget.translate('Received (Download)')}: ${winnBytesHuman(counters.rxBytes!)}   ${widget.translate('Sent (Upload)')}: ${winnBytesHuman(counters.txBytes!)}',
                  style: TextStyle(
                    color: widget.textColor,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  String _trafficFlowValue({
    required WinnTrafficFlow flow,
    required double rate,
  }) {
    if (flow == WinnTrafficFlow.flowing) {
      final rateText = rate > 0 ? ' (${winnRateHuman(rate)})' : '';
      return '${widget.translate('Flowing')}$rateText';
    }
    return widget.translate(winnTrafficFlowPhrase(flow));
  }
}

class _StatusRow extends StatelessWidget {
  const _StatusRow({
    required this.label,
    required this.value,
    required this.indicatorColor,
    required this.textColor,
  });

  final String label;
  final String value;
  final Color indicatorColor;
  final Color textColor;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(
            color: indicatorColor,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 8),
        Text('$label ',
            style: TextStyle(color: textColor, fontSize: 11)),
        Expanded(
          child: Text(
            value,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: textColor,
              fontSize: 11,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ],
    );
  }
}