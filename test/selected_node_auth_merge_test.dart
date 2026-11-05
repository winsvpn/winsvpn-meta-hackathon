import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Every accepted /verify, /free/verify and Double VPN reply runs
// _applySelectedNodeFromAuth. The reply's selected_node carries only slug,
// name, flag and status, and the row it built replaced this slug's /nodes
// row in _locations and node_cache.json: the endpoints (which the latency
// probe uses), transports, protocol labels, direct-AWG and reachability
// flags, regional aliases, latency and the free flag were blanked until the
// next listing. The shipping methods are extracted verbatim from
// lib/main.dart and run on a listed row.
String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

void main() {
  test('the auth reply keeps the listing fields of the selected row',
      () async {
    final source = File('lib/main.dart').readAsStringSync();
    final values = _between(
        source,
        '  String? _stringValue(Map<String, dynamic> data, List<String> keys) {',
        '  /// Verifier built from the compiled-in public key set');
    final maps = _between(
        source,
        '  Map<String, dynamic> _mapValue(Map<String, dynamic> data, List<String> keys) {',
        '  String _normalizeProtocolLabel(dynamic value) {');
    final hostname = _between(source, '  String _hostnameOnly(String value) {',
        '  ({String host, int port})? _hostPortValue(dynamic value,');
    final normalize = _between(
        source,
        "  String _displayNodeName(dynamic value, {String fallback = 'Unknown'}) {",
        '  String get _languageCode => appUiLanguageCode(');
    final latency = _between(
        source,
        '  int? _nodeLatencyMs(Map<String, dynamic>? node) {',
        '  String _nodeLatencyLabel(Map<String, dynamic>? node) {');
    final authApply = _between(
        source,
        '  void _applySelectedNodeFromAuth(Map<String, dynamic> data,',
        '  Map<String, dynamic> _normalizeVpnConfig(Map<String, dynamic> raw) {');
    final packages = File('.dart_tool/package_config.json').absolute.path;
    final load = File('lib/server_load.dart').absolute.uri;
    final temporary =
        await Directory.systemTemp.createTemp('wins-auth-node-merge-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString('''
import 'dart:async';
import 'dart:convert';
import '$load';

class H {
  List<Map<String, dynamic>> _locations = <Map<String, dynamic>>[];
  int _selectedLocationIndex = 0;
  final Set<String> _freeNodeSlugs = <String>{};
  bool _freeNodeSnapshotLive = false;
  String? _winn3CoverExactTargetSlug;
  int saves = 0;
  List<Map<String, dynamic>> _sortedNodeItems(
          Iterable<Map<String, dynamic>> nodes) =>
      nodes.map((node) => Map<String, dynamic>.from(node)).toList();
  int _indexForNodeSlug(String? slug) =>
      _locations.indexWhere((node) => node['slug'] == slug);
  Future<void> _saveCachedNodes() async => saves++;

$values
$maps
$hostname
$normalize
$latency
$authApply
}

void main() {
  final h = H();
  final listed = h._normalizeNodeItem(<String, dynamic>{
    'slug': 'de-1',
    'name': 'Germany',
    'flag': 'DE',
    'status': 'online',
    'endpoint': '203.0.113.20:9110',
    'stealth_endpoint': 'edge.example.com:443',
    'free_access_enabled': true,
    'direct_awg_enabled': false,
    'protocol_version': 'winn/1',
    'carrier': 'awg',
    'reachable': true,
    'transports': <String, dynamic>{'stealth_tcp_ws': 'ok'},
    'regional_aliases': <String>['de.example.com'],
    'latency_ms': 42,
    'load_pct': 35,
  }, loadReceipt: (mono: 1000, wall: 1700000000000));
  h._locations = <Map<String, dynamic>>[
    h._normalizeNodeItem(<String, dynamic>{'slug': 'nl-1', 'name': 'NL'}),
    listed,
  ];
  h._applySelectedNodeFromAuth(<String, dynamic>{
    'selected_node': <String, dynamic>{
      'slug': 'de-1',
      'name': 'Germany',
      'flag': 'DE',
      'status': 'online',
    },
  });
  final row = h._locations[h._selectedLocationIndex];
  print('row: ' + jsonEncode(<String, dynamic>{
    'slug': row['slug'],
    'endpoint': row['endpoint'],
    'stealth_endpoint': row['stealth_endpoint'],
    'free': row['free_access_enabled'],
    'direct': row['direct_awg_enabled'],
    'protocol': row['protocol_version'],
    'carrier': row['carrier'],
    'transports': row['transports'],
    'aliases': row['regional_aliases'],
    'latency': row['latency_ms'],
    'load': row[kServerLoadPctKey],
  }));
  print('rows=' + h._locations.length.toString() + ' saves=' + h.saves.toString());

  // A free reply still marks the node free, listed or not.
  final fresh = H();
  fresh._applySelectedNodeFromAuth(<String, dynamic>{
    'selected_node': <String, dynamic>{'slug': 'us-1', 'name': 'US'},
  }, freeAccess: true);
  final added = fresh._locations.single;
  print('unlisted: slug=' + added['slug'].toString() +
      ' free=' + added['free_access_enabled'].toString() +
      ' endpoint=[' + added['endpoint'].toString() + ']');
}
''');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        ['--packages=$packages', program.path],
      ).timeout(const Duration(seconds: 60));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final output = '${result.stdout}';
      expect(
          output,
          contains('row: {"slug":"de-1","endpoint":"203.0.113.20:9110",'
              '"stealth_endpoint":"edge.example.com:443","free":true,'
              '"direct":false,"protocol":"winn/1","carrier":"awg",'
              '"transports":{"stealth_tcp_ws":"ok"},'
              '"aliases":["de.example.com"],"latency":42,"load":35}'));
      expect(output, contains('rows=2 saves=1'));
      expect(output, contains('unlisted: slug=us-1 free=true endpoint=[]'));
    } finally {
      await temporary.delete(recursive: true);
    }
  });
}
