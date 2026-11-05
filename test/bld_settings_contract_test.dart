import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// BUILD-SETTINGS LANE (2026-08-10).
///
/// Source-text contract tests for the four VPN settings surfaces built in this
/// lane: protocol/transport selection, always-on, and the diagnostics toggle
/// (split tunnelling already has dedicated behavioural coverage in
/// split_tunnel_routes_test.dart).
///
/// These follow the established source-text contract-test style used by the
/// stealth-transport and double-VPN preference tests in this tree, because the
/// shipping UI is a single 17k-line `main.dart` and the preferences live as
/// private members of `VpnHomeScreenState` that a widget test can only reach by
/// driving the whole network-bound shell.
///
/// The source path is injectable via `--dart-define=MAIN_DART_PATH=...` so the
/// accompanying mutation harness can point the SAME assertions at a mutant copy
/// of the file and prove each guard is actually load-bearing (mutate -> red).
const String _sourcePath = String.fromEnvironment(
  'MAIN_DART_PATH',
  defaultValue: 'lib/main.dart',
);

void main() {
  late String source;

  setUpAll(() {
    source = File(_sourcePath).readAsStringSync();
  });

  group('protocol / transport selection', () {
    test('transport-mode persistence is a dedicated mutator under its own key',
        () {
      expect(source, contains("data['transport_mode'] = mode;"));
      expect(source, contains("data.remove('transport_mode');"));
    });

    test('the selector drives the legacy stealth flag so the two never diverge',
        () {
      final setter = source.indexOf('Future<void> _setTransportMode(');
      final setterEnd = source.indexOf(
        'Future<bool> _persistAlwaysOnEnabled(',
        setter,
      );
      expect(setter, greaterThanOrEqualTo(0));
      expect(setterEnd, greaterThan(setter));
      final body = source.substring(setter, setterEnd);
      expect(
        body,
        contains('_isStealthTransportOnly = stealthFlagForTransportMode(mode);'),
        reason: 'The TCP-only choice must alias the legacy flag, so whichever '
            'control the user touched, the live connect sees the same value.',
      );
    });

    test('Direct (UDP) only suppresses the TCP fallback leg after a UDP failure',
        () {
      final gate = source.indexOf("if (_transportMode == 'udp') {");
      expect(gate, greaterThanOrEqualTo(0));
      expect(
        source.indexOf('_stopNativeTunnelForFailover()', gate),
        greaterThan(gate),
        reason:
            'The UDP-only gate must sit before the TCP fallback is attempted.',
      );
    });
  });

  group('always-on', () {
    test('always-on is persisted under its own key', () {
      expect(source, contains("data['always_on_enabled'] = true;"));
      expect(source, contains("data.remove('always_on_enabled');"));
    });

    test('the toggle talks to the platform through a setAlwaysOnVpn channel', () {
      expect(
        source,
        contains("invokeMethod<String>('setAlwaysOnVpn', {'enabled': enabled})"),
      );
    });

    test('the UI surfaces the native classified result, not a blind success', () {
      final setter = source.indexOf('Future<void> _setAlwaysOnEnabled(');
      final setterEnd = source.indexOf(
        'Future<bool> _setDiagnosticsEnabled(',
        setter,
      );
      expect(setter, greaterThanOrEqualTo(0));
      expect(setterEnd, greaterThan(setter));
      final body = source.substring(setter, setterEnd);
      expect(body, contains("'saved_settings_opened'"));
      expect(
        body,
        contains('_applyAlwaysOnToNative(enabled)'),
        reason:
            'The toggle must apply the choice to the platform and read back a '
            'classified verdict before reporting success.',
      );
    });
  });

  group('diagnostics toggle', () {
    test('diagnostics preference is persisted under its own key', () {
      expect(source, contains("data['diagnostics_enabled'] = enabled;"));
      expect(source, isNot(contains("data.remove('diagnostics_enabled');")));
    });

    test('turning diagnostics off clears any already-collected file', () {
      final setter = source.indexOf('Future<bool> _setDiagnosticsEnabled(');
      final setterEnd = source.indexOf(
        '/// Whether failure diagnostics are currently allowed',
        setter,
      );
      expect(setter, greaterThanOrEqualTo(0));
      expect(setterEnd, greaterThan(setter));
      expect(
        source.substring(setter, setterEnd),
        contains('await _clearTunnelFailureDiagnostic();'),
      );
    });

    test('the failure-write gate checks the toggle BEFORE writing anything', () {
      final persist =
          source.indexOf('Future<void> _persistTunnelFailureDiagnostic(');
      final write =
          source.indexOf('await file.writeAsString(jsonEncode({', persist);
      final gate = source.indexOf('if (!_diagnosticsEnabled) return;', persist);
      expect(persist, greaterThanOrEqualTo(0));
      expect(
        gate,
        greaterThanOrEqualTo(0),
        reason:
            'A diagnostics-off state must refuse to record a failure at all.',
      );
      expect(
        gate,
        lessThan(write),
        reason:
            'The gate must short-circuit before the diagnostic is written to '
            'disk, not after.',
      );
    });
  });
}
