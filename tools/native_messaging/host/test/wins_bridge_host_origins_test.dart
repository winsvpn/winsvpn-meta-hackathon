// Run with dart run test/wins_bridge_host_origins_test.dart.
import 'dart:convert';
import 'dart:io';

import '../bin/wins_bridge_host.dart' as host;

void expect(bool condition, String message) {
  if (!condition) throw StateError(message);
}

void main() {
  final directory = Directory.systemTemp.createTempSync('wins-origin-test-');
  final companion = File('${directory.path}/allowed_origins.txt');
  const chrome = 'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/';
  const edge = 'chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/';
  const firefox = 'companion@winsvpn.org';
  final manifest = '${directory.path}/org.winsvpn.bridge.json';
  Set<String> read() => host.readAllowedOriginsFromManifestDirectory(directory: directory);
  try {
    expect(read().isEmpty, 'missing companion must deny');
    companion.writeAsStringSync(jsonEncode({
      'chrome': [chrome], 'edge': [edge], 'firefox': [firefox],
    }));
    final origins = read();
    expect(origins.length == 3, 'all three installed browsers must load');
    expect(host.resolveCallerOrigin([chrome], origins) == chrome, 'Chrome launch');
    expect(host.resolveCallerOrigin([edge, '--parent-window=0'], origins) == edge, 'Edge launch');
    expect(host.resolveCallerOrigin([manifest, firefox], origins) == firefox, 'Firefox launch');
    for (final args in <List<String>>[
      [], [firefox], [manifest, 'foreign@example.org'],
      ['relative.json', firefox], [manifest], [chrome, edge],
      [chrome, chrome], ['chrome-extension://cccccccccccccccccccccccccccccccc/'],
      ['chrome-extension://cccccccccccccccccccccccccccccccc/', chrome],
      [manifest, firefox, chrome], ['moz-extension://untrusted/', firefox],
    ]) {
      expect(host.resolveCallerOrigin(args, origins) == null, 'invalid or ambiguous launch accepted: $args');
    }
    for (final body in <String>[
      '{', '[]', '{}', '{"unknown": ["$chrome"]}',
      '{"chrome": ["$chrome", "$edge"]}', '{"chrome": [3]}',
      '{"firefox": ["foreign@example.org"]}',
      '{"edge": ["chrome-extension://cccccccccccccccccccccccccccccccc/"] , "chrome": ["bad"]}',
      ' ' * 4097,
    ]) {
      companion.writeAsStringSync(body);
      expect(read().isEmpty, 'malformed configuration must deny');
    }
    if (!Platform.isWindows) {
      companion.deleteSync();
      final target = File('${directory.path}/target');
      target.writeAsStringSync(jsonEncode({'chrome': [chrome]}));
      Link(companion.path).createSync(target.path);
      expect(read().isEmpty, 'linked companion must deny');
    }
    stdout.writeln('PASS: browser origins, Firefox argv, malformed and ambiguous denial');
  } finally {
    directory.deleteSync(recursive: true);
  }
}
