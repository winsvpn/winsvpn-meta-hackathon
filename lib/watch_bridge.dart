// Phone-side half of the companion watch apps (Wear OS and watchOS).
//
// The watch is a remote control and nothing more: it sends an intent
// ("connect", "disconnect", "use this country") and renders the state this
// file reports back. It never receives an account number, key, endpoint or
// tunnel configuration, and it never stores anything.
//
// One Dart implementation serves both platforms because the Kotlin and Swift
// sides speak the same `wins_vpn/watch` channel and the same JSON.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'server_load.dart';

/// Status vocabulary, shared verbatim with `wear_os` and the watchOS target.
enum WatchTunnelStatus {
  disconnected('disconnected'),
  connecting('connecting'),
  connected('connected'),
  disconnecting('disconnecting'),
  failed('failed'),

  /// The OS VPN consent prompt has not been granted.
  ///
  /// A watch cannot grant it and must never try to. On Apple platforms in
  /// particular, VPN approval is a user gesture Apple requires to be manual.
  permissionRequired('permissionRequired'),

  unknown('unknown');

  const WatchTunnelStatus(this.wireValue);

  final String wireValue;
}

/// What the watch asked the phone to do.
enum WatchCommand { connect, disconnect, selectCountry }

typedef WatchCommandHandler = Future<void> Function(
  WatchCommand command,
  String slug,
);

class WatchBridge {
  WatchBridge._();

  static final WatchBridge instance = WatchBridge._();

  static const MethodChannel _channel = MethodChannel('wins_vpn/watch');
  static const String _methodOnCommand = 'onWatchCommand';
  static const String _methodPublishState = 'publishWatchState';

  /// Long enough to name a failure, short enough that no status line built for
  /// the phone UI can be smuggled through wholesale.
  static const int _maxDetailLength = 60;

  static final RegExp _ipv4 = RegExp(r'\b\d{1,3}(?:\.\d{1,3}){3}\b');
  static final RegExp _ipv6 = RegExp(r'\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b');
  static final RegExp _whitespace = RegExp(r'\s+');

  /// Only the two platforms that have a companion watch. Everywhere else this
  /// class is inert rather than throwing MissingPluginException on every frame.
  static final bool _platformSupported = Platform.isAndroid || Platform.isIOS;

  @visibleForTesting
  static bool? debugSupportedOverride;

  static bool get _supported => debugSupportedOverride ?? _platformSupported;

  WatchCommandHandler? _onCommand;
  String? _lastPayload;
  String? _lastSignature;
  bool _publishInFlight = false;
  String? _pendingPayload;

  bool get isAttached => _onCommand != null;

  void attach(WatchCommandHandler onCommand) {
    if (!_supported) return;
    _onCommand = onCommand;
    _channel.setMethodCallHandler(_handleNativeCall);
  }

  void detach() {
    if (!_supported) return;
    _onCommand = null;
    _lastPayload = null;
    _lastSignature = null;
    _pendingPayload = null;
    _channel.setMethodCallHandler(null);
  }

  Future<dynamic> _handleNativeCall(MethodCall call) async {
    if (call.method != _methodOnCommand) return null;
    final handler = _onCommand;
    if (handler == null) return null;

    final arguments = call.arguments;
    if (arguments is! Map) return null;

    final command = switch ((arguments['command'] ?? '').toString()) {
      'connect' => WatchCommand.connect,
      'disconnect' => WatchCommand.disconnect,
      'selectCountry' => WatchCommand.selectCountry,
      _ => null,
    };
    if (command == null) return null;

    await handler(command, (arguments['slug'] ?? '').toString().trim());
    return null;
  }

  /// Report current user-visible state.
  ///
  /// Safe to call from `build()`: identical state is dropped before any
  /// serialisation work, so the steady-state cost is one string comparison.
  ///
  /// [locations] is the phone's own node list. Only `slug`, `name`, `flag`
  /// and, while fresh, `load_pct` with its `load_at` receipt time are
  /// forwarded (see [watchCountryEntries]). The same maps also carry
  /// `endpoint` and `stealth_endpoint`, which must never leave the phone.
  ///
  /// [canConnect] must be false whenever the phone would refuse to start a
  /// tunnel or change server -- while the local PIN gate is engaged, for
  /// instance. It is what stops the watch offering a control that would do
  /// nothing.
  void publish({
    required WatchTunnelStatus status,
    required String selectedSlug,
    required List<Map<String, dynamic>> locations,
    bool canConnect = true,
    String detail = '',
  }) {
    if (!_supported || _onCommand == null) return;

    // Cheap change detection first. `locations` is replaced wholesale whenever
    // the node list is refreshed, so identity is a sound O(1) proxy for it.
    final signature = '${status.wireValue}|$detail|$selectedSlug|$canConnect|'
        '${identityHashCode(locations)}|${locations.length}';
    if (signature == _lastSignature) return;
    _lastSignature = signature;

    final countries = watchCountryEntries(locations);

    final payload = jsonEncode(<String, dynamic>{
      'status': status.wireValue,
      'detail': _sanitizeDetail(detail),
      'selectedSlug': selectedSlug.trim(),
      'countries': countries,
      'canConnect': canConnect,
    });

    if (payload == _lastPayload) return;
    _lastPayload = payload;
    unawaited(_send(payload));
  }

  Future<void> _send(String payload) async {
    _pendingPayload = payload;
    if (_publishInFlight) return;
    _publishInFlight = true;
    try {
      while (_onCommand != null && _pendingPayload != null) {
        final next = _pendingPayload!;
        _pendingPayload = null;
        try {
          await _channel.invokeMethod<bool>(
            _methodPublishState,
            <String, dynamic>{'payload': next},
          );
        } on MissingPluginException {
          _lastSignature = null;
          _lastPayload = null;
        } catch (_) {
          _lastSignature = null;
          _lastPayload = null;
        }
      }
    } finally {
      _publishInFlight = false;
    }
  }

  /// Defence in depth.
  ///
  /// Callers are expected to pass a short failure reason, but the phone's own
  /// status strings can contain the user's public IP, so anything address-like
  /// is redacted here rather than trusted not to arrive.
  static String _sanitizeDetail(String detail) {
    var value = detail.trim().replaceAll(_whitespace, ' ');
    if (value.isEmpty) return '';
    value = value.replaceAll(_ipv4, '').replaceAll(_ipv6, '');
    value = value.replaceAll(_whitespace, ' ').trim();
    if (value.length <= _maxDetailLength) return value;
    return '${value.substring(0, _maxDetailLength - 1).trimRight()}…';
  }

  @visibleForTesting
  static String debugSanitizeDetail(String detail) => _sanitizeDetail(detail);
}

/// Watch payload key for when the phone received a country's load figure:
/// whole seconds since the Unix epoch, on the phone's wall clock.
///
/// Why epoch seconds and not a monotonic value: a monotonic reading means
/// nothing on another device, and the watch must judge age itself (it may
/// render a snapshot long after it arrived). Epoch time is the one clock both
/// devices share, and both watch platforms take their time from the paired
/// phone. It is not computed from a wall-clock reading taken at receipt: it is
/// the phone's CURRENT wall clock minus the phone's own freshness age for the
/// figure (see serverLoadAgeMs, the larger of monotonic and wall-clock age), so
/// a phone clock change after receipt cannot make a figure look younger. It is
/// floored to whole seconds, which can only make the figure look older.
/// The watches treat a `load_at` in their future as unknown.
const String kWatchLoadAtKey = 'load_at';

/// The per-country entries of the watch payload.
///
/// `load_pct` (with `load_at`) is included only when it is exactly a contract
/// value (int 0..100, step 5) AND still fresh on the phone, and is otherwise
/// omitted, which both watch apps render as unknown. Both watch parsers ignore
/// keys they do not know, so an older watch build that predates these keys
/// renders this payload unchanged.
@visibleForTesting
List<Map<String, Object>> watchCountryEntries(
    List<Map<String, dynamic>> locations) {
  final countries = <Map<String, Object>>[];
  for (final location in locations) {
    final slug = (location['slug'] ?? '').toString().trim();
    if (slug.isEmpty || slug == 'unknown') continue;
    final name = (location['name'] ?? '').toString().trim();
    final load = freshServerLoadPct(location);
    final age = load == null
        ? null
        : serverLoadAgeMs(location[kServerLoadReceivedMonoKey],
            location[kServerLoadReceivedWallKey]);
    // Emit load_at only inside the window both watches accept, so a phone
    // with an absurd clock sends no figure rather than one the watch rejects.
    final loadAtMs = age == null ? null : serverLoadClock.wallMs() - age;
    final loadAt = (loadAtMs == null ||
            loadAtMs < kServerLoadMinEpochMs ||
            loadAtMs > kServerLoadMaxEpochMs)
        ? null
        : loadAtMs ~/ 1000;
    countries.add(<String, Object>{
      'slug': slug,
      'name': name.isEmpty ? slug : name,
      'flag': (location['flag'] ?? '').toString().trim(),
      if (load != null && loadAt != null) ...<String, Object>{
        kServerLoadPctKey: load,
        kWatchLoadAtKey: loadAt,
      },
    });
  }
  return countries;
}
