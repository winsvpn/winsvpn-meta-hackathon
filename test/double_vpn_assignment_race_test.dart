import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Runs the shipping _postDoubleVpnAssignmentRace (extracted verbatim from
// lib/main.dart) against one front that answers at once and one that stalls.
// The authenticated reply must be used without waiting for the stalled
// front's timeout, and the stalled request must be aborted.
void main() {
  test('an authenticated reply is not held behind a stalled front', () async {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf(
        '  Future<DoubleVpnAssignmentAttempt<Map<String, dynamic>?>>\n'
        '      _postDoubleVpnAssignmentRace(');
    final end = source.indexOf(
        '  Future<Map<String, dynamic>?> _postDoubleVpnAssignmentWithRetry(',
        start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final packages = File('.dart_tool/package_config.json').absolute.path;
    final temporary =
        await Directory.systemTemp.createTemp('wins-double-vpn-race-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString(
          '$_harness${source.substring(start, end)}$_end');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        ['--packages=$packages', program.path],
      ).timeout(const Duration(seconds: 60));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      final output = '${result.stdout}';
      expect(output, contains('race: status=200 value=authenticated'));
      expect(output, contains('stalled_aborted=true'));
      final elapsed = int.parse(
          RegExp(r'elapsed_ms=(\d+)').firstMatch(output)!.group(1)!);
      expect(elapsed, lessThan(1500),
          reason: 'the 3 s per-front timeout must not hold the winner');
    } finally {
      await temporary.delete(recursive: true);
    }
  });
}

const _harness = r'''
import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/double_vpn_assignment_retry.dart';
import 'package:wins_vpn/hub_request_window.dart';
import 'package:wins_vpn/verify_request_context.dart';

class StallClient extends http.BaseClient {
  bool stalledAborted = false;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (request.url.host == 'fast.example') {
      return http.StreamedResponse(
          Stream.value(utf8.encode('{"status":"authenticated"}')), 200);
    }
    final abort = request is http.Abortable ? (request as http.Abortable).abortTrigger : null;
    final gate = Completer<http.StreamedResponse>();
    abort?.whenComplete(() {
      stalledAborted = true;
      if (!gate.isCompleted) gate.completeError(http.RequestAbortedException(request.url));
    });
    return gate.future;
  }
}

class Harness {
  final StallClient _controlPlaneClient = StallClient();
  void _debugLog(String m) {}
  void _noteWinn3KeyCollision(http.Response r, String? b) {}
''';

const _end = r'''
}
Future<void> main() async {
  final h = Harness();
  final watch = Stopwatch()..start();
  final attempt = await h._postDoubleVpnAssignmentRace(
    ['https://stall.example/free/verify', 'https://fast.example/free/verify'],
    VerifyRequestContext(body: '{}', headers: {'Content-Type': 'application/json'}),
    const Duration(seconds: 3),
  );
  await Future<void>.delayed(Duration.zero);
  print('race: status=${attempt.statusCode} value=${attempt.value?['status']} '
      'elapsed_ms=${watch.elapsedMilliseconds} stalled_aborted=${h._controlPlaneClient.stalledAborted}');
}
''';
