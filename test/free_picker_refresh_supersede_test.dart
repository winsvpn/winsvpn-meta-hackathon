import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// A free-session server pick starts a config refresh that can take seconds.
// Before this, the refresh had no shouldCancel: tapping A and then B, with
// A's refresh finishing last, committed A's config and put the selection back
// on A, and a connect started meanwhile raced it the same way. The shipping
// _onServerRowTapped is extracted verbatim from lib/main.dart and run against
// a stand-in refresh that commits only when its shouldCancel does not say it
// was superseded, as the real _refreshFreeVpnConfig does before every write.
void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('a superseded free pick never commits over the newer choice', () async {
    final start = source.indexOf(
        '  Future<void> _onServerRowTapped(Map<String, dynamic> location,');
    final end = source.indexOf(
        '  void _showLocationPickerSheet({bool freeOnly = false}) {', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final packages = File('.dart_tool/package_config.json').absolute.path;
    final rebind = File('lib/node_selection_rebind.dart').absolute.uri;
    final display = File('lib/tunnel_display_identity.dart').absolute.uri;
    final temporary =
        await Directory.systemTemp.createTemp('wins-free-pick-supersede-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString('''
import 'dart:async';
import '$rebind';
import '$display';

class H {
  bool mounted = true;
  bool _isConnected = false;
  bool _isLoading = false;
  bool _isLoggedIn = true;
  bool _automaticNodeSelection = false;
  bool _isCensorshipModeActive = false;
  String _selected = '';
  final List<String> feedback = <String>[];
  final List<String> committed = <String>[];
  final Map<String, Completer<void>> gates = <String, Completer<void>>{};
  void setState(void Function() fn) => fn();
  String _displayNodeName(Object? value) => '\$value';
  DashboardNodeDisplay _nodeInUse() =>
      const DashboardNodeDisplay(DashboardNodeSource.picker, null);
  String _currentSelectedSlug() => _selected;
  void _rebindSelection(String slug,
          {List<Map<String, dynamic>>? knownRows}) =>
      _selected = slug;
  Future<void> _saveVpnRuntimeSettings() async {}
  Future<void> _switchServerFromUserSelection(String name,
      {String? targetSlug}) async {}
  void _showSelectionFeedback(String message) =>
      feedback.add('\$_selected:\$message');
  Future<bool> _refreshFreeVpnConfig({
    bool stealthMode = false,
    bool Function()? shouldCancel,
    String? requestedLocation,
    Object? onPrepared,
  }) async {
    final requested = requestedLocation ?? _selected;
    final gate = gates[requested] = Completer<void>();
    await gate.future;
    if (shouldCancel?.call() == true) return false;
    committed.add(requested);
    // _applySelectedNodeFromAuth binds the selection to the served node.
    _selected = requested;
    return true;
  }

${source.substring(start, end)}
}

Future<void> main() async {
  final rapid = H();
  final a = rapid._onServerRowTapped(
      <String, dynamic>{'slug': 'node-a', 'name': 'A'}, freeOnly: true);
  await Future<void>.delayed(Duration.zero);
  final b = rapid._onServerRowTapped(
      <String, dynamic>{'slug': 'node-b', 'name': 'B'}, freeOnly: true);
  await Future<void>.delayed(Duration.zero);
  rapid.gates['node-b']!.complete();
  await b;
  rapid.gates['node-a']!.complete();
  await a;
  print('rapid: committed=\${rapid.committed.join(',')} '
      'selected=\${rapid._selected} feedback=\${rapid.feedback.length}');

  final connect = H();
  final c = connect._onServerRowTapped(
      <String, dynamic>{'slug': 'node-a', 'name': 'A'}, freeOnly: true);
  await Future<void>.delayed(Duration.zero);
  connect._isLoading = true;
  connect.gates['node-a']!.complete();
  await c;
  print('connect: committed=\${connect.committed.join(',')} '
      'feedback=\${connect.feedback.length}');

  final single = H();
  final d = single._onServerRowTapped(
      <String, dynamic>{'slug': 'node-a', 'name': 'A'}, freeOnly: true);
  await Future<void>.delayed(Duration.zero);
  single.gates['node-a']!.complete();
  await d;
  print('single: committed=\${single.committed.join(',')} '
      'selected=\${single._selected} feedback=\${single.feedback.join('|')}');
}
''');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        ['--packages=$packages', program.path],
      ).timeout(const Duration(seconds: 60));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final output = '${result.stdout}';
      expect(output, contains('rapid: committed=node-b selected=node-b feedback=1'));
      expect(output, contains('connect: committed= feedback=0'));
      expect(output,
          contains('single: committed=node-a selected=node-a '
              'feedback=node-a:Free server changed.'));
    } finally {
      await temporary.delete(recursive: true);
    }
  });

  test('the Automatic row passes the same supersede check', () {
    final start = source.indexOf("title: const Text('Automatic'),");
    final end = source.indexOf(
        "'Automatic selection will sync when you connect.'", start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final tap = source.substring(start, end);
    expect(tap, contains('!_automaticNodeSelection;'));
    expect(tap, contains('shouldCancel: superseded,'));
    expect(tap, contains('if (superseded()) return;'));
  });
}
