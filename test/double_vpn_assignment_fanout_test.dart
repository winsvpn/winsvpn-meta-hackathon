import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Runs the shipping _postDoubleVpnAssignmentRace (extracted verbatim from
// lib/main.dart) against scripted fronts and reports how many fronts one
// attempt contacted. One Double VPN attempt used to post to all 29 compiled
// fronts at the same instant; every one of those requests makes the hub
// upsert the assignment and hold a worker for the Core readiness wait, so the
// burst queued behind itself past the client's seven seconds.
void main() {
  late Map<String, String> lines;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf(
        '  Future<DoubleVpnAssignmentAttempt<Map<String, dynamic>?>>\n'
        '      _postDoubleVpnAssignmentRace(');
    // The race AND the retry wrapper around it, verbatim.
    final end = source.indexOf('  String? _freeVerifyTerminalKind(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final packages = File('.dart_tool/package_config.json').absolute.path;
    final temporary =
        await Directory.systemTemp.createTemp('wins-double-vpn-fanout-');
    try {
      final program = File('${temporary.path}/probe.dart');
      await program.writeAsString(
          '$_harness${source.substring(start, end)}$_end');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        ['--packages=$packages', program.path],
      ).timeout(const Duration(seconds: 90));
      expect(result.exitCode, 0, reason: '${result.stderr}');
      lines = <String, String>{
        for (final line in '${result.stdout}'.split('\n'))
          if (line.contains(' '))
            line.substring(0, line.indexOf(' ')): line
                .substring(line.indexOf(' ') + 1),
      };
    } finally {
      await temporary.delete(recursive: true);
    }
  });

  int field(String scenario, String name) => int.parse(
      RegExp('$name=(\\d+)').firstMatch(lines[scenario]!)!.group(1)!);

  test('29 slow fronts are not contacted at once', () {
    // Every front would answer "preparing" after 1.2 s, as the hub does while
    // the Core applies the assignment.
    expect(field('preparing', 'status'), 503);
    expect(lines['preparing'], contains('preparing=true'));
    expect(field('preparing', 'started'), lessThanOrEqualTo(3),
        reason: 'one attempt may keep at most three fronts open');
  });

  test('an edge error page never outranks the hub preparing reply', () {
    expect(field('edge_then_hub', 'status'), 503);
    expect(lines['edge_then_hub'], contains('preparing=true'));
  });

  test('a hub refusal stops the walk at the first front', () {
    expect(field('refused', 'status'), 401);
    expect(field('refused', 'started'), 1);
  });

  test('a hub that needs a few seconds is polled, not stormed', () {
    // The incident: the Core needs a few seconds to apply the assignment, the
    // hub holds each request while it waits, and the client used to post every
    // attempt to all 29 fronts (58 requests for two attempts). Two attempts of
    // at most three fronts each is the bound now.
    expect(lines['poll_slow_hub'], contains('authenticated=true'));
    expect(field('poll_slow_hub', 'started'), lessThanOrEqualTo(6));
    expect(field('poll_slow_hub', 'elapsed_ms'), lessThan(12000));
  });

  test('a front that keeps answering "preparing" cannot starve the others', () {
    // Fronts 0 to 2 are a stale edge that always says "preparing"; front 3
    // is the hub with the assignment ready. The poll must reach it by moving
    // on, one attempt at a time, and not stay on the first fronts forever.
    expect(lines['censored_preparing'], contains('authenticated=true'));
    expect(field('censored_preparing', 'started'), 4);
  });

  test('a long Retry-After cannot prevent the next front being tried', () {
    expect(lines['long_retry_after'], contains('authenticated=true'));
    expect(field('long_retry_after', 'started'), 4);
    expect(field('long_retry_after', 'elapsed_ms'), lessThan(8000));
  });

  test('fronts that never answer are all reached in turn', () {
    // Three silent fronts fill the three open slots for a whole attempt; the
    // next attempt must start after them, not on them again.
    expect(lines['silent_first_batch'], contains('authenticated=true'));
    expect(field('silent_first_batch', 'started'), 4);
    expect(field('silent_first_batch', 'elapsed_ms'), lessThan(20000));
  });

  test('cancelling the poll stops the window inside it', () {
    // The outer poll stops waiting within a few hundred ms of the flip. The
    // window must stop with it: no further front may start afterwards.
    expect(field('cancelled', 'started'), 1);
    expect(field('cancelled', 'elapsed_ms'), lessThan(1500));
  });

  test('a dead first front moves on within a second', () {
    expect(field('dead_first', 'status'), 200);
    expect(field('dead_first', 'started'), 2);
    expect(field('dead_first', 'elapsed_ms'), lessThan(1000));
  });
}

const _harness = r'''
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/double_vpn_assignment_retry.dart';
import 'package:wins_vpn/hub_request_window.dart';
import 'package:wins_vpn/verify_request_context.dart';

const _preparing =
    '{"detail":"Double VPN Core assignment is still being prepared. Please try again."}';

class ScriptClient extends http.BaseClient {
  ScriptClient(this.script);
  final Future<http.StreamedResponse> Function(http.BaseRequest request) script;
  int started = 0;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    started += 1;
    return script(request);
  }
}

http.StreamedResponse reply(int status, String body,
        [Map<String, String> headers = const {}]) =>
    http.StreamedResponse(Stream.value(utf8.encode(body)), status,
        headers: headers);

// A front that never answers until the window aborts it, as a silently
// dropped connection does.
Future<http.StreamedResponse> stallUntilAbort(http.BaseRequest request) {
  final gate = Completer<http.StreamedResponse>();
  final abort =
      request is http.Abortable ? (request as http.Abortable).abortTrigger : null;
  abort?.whenComplete(() {
    if (!gate.isCompleted) {
      gate.completeError(http.RequestAbortedException(request.url));
    }
  });
  return gate.future;
}

int frontIndex(http.BaseRequest request) =>
    int.parse(request.url.host.split('.').first.substring(5));

class Harness {
  Harness(this._controlPlaneClient);
  final ScriptClient _controlPlaneClient;
  void _debugLog(String m) {}
  void _noteWinn3KeyCollision(http.Response r, String? b) {}
''';

const _end = r'''
}

Future<void> main() async {
  final urls = <String>[
    for (var i = 0; i < 29; i++) 'https://front$i.example/verify',
  ];
  Future<void> run(String name, List<String> fronts, ScriptClient client) async {
    final harness = Harness(client);
    final watch = Stopwatch()..start();
    final attempt = await harness._postDoubleVpnAssignmentRace(
      fronts,
      VerifyRequestContext(
          body: '{}', headers: {'Content-Type': 'application/json'}),
      const Duration(seconds: 7),
    );
    final preparing = isDoubleVpnAssignmentPreparing(
      statusCode: attempt.statusCode,
      body: attempt.body,
      headers: attempt.headers,
    );
    print('$name status=${attempt.statusCode} preparing=$preparing '
        'started=${client.started} elapsed_ms=${watch.elapsedMilliseconds}');
  }

  await run(
    'preparing',
    urls,
    ScriptClient((request) async {
      await Future<void>.delayed(const Duration(milliseconds: 1200));
      return reply(503, _preparing, {'retry-after': '5'});
    }),
  );
  await run(
    'edge_then_hub',
    ['https://edge.example/verify', 'https://hub.example/verify'],
    ScriptClient((request) async {
      if (request.url.host == 'edge.example') {
        return reply(503, '<!DOCTYPE html><title>edge</title>');
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
      return reply(503, _preparing, {'retry-after': '5'});
    }),
  );
  await run(
    'refused',
    urls,
    ScriptClient((request) async =>
        reply(401, '{"detail":"Invalid device credentials."}')),
  );
  final hubClock = Stopwatch();
  Future<void> runPoll(String name, List<String> fronts, ScriptClient client) async {
    final harness = Harness(client);
    final watch = Stopwatch()..start();
    final data = await harness._postDoubleVpnAssignmentWithRetry(
      fronts,
      VerifyRequestContext(
          body: '{}', headers: {'Content-Type': 'application/json'}),
      doubleVpnRequested: true,
    );
    print('$name authenticated=${data?['status'] == 'authenticated'} '
        'started=${client.started} elapsed_ms=${watch.elapsedMilliseconds}');
  }

  // The hub holds a request for 2.5 s while the Core applies the assignment,
  // answers "preparing", and is ready 3 s after the first request.
  await runPoll(
    'poll_slow_hub',
    urls,
    ScriptClient((request) async {
      if (!hubClock.isRunning) hubClock.start();
      if (hubClock.elapsed < const Duration(seconds: 3)) {
        await Future<void>.delayed(const Duration(milliseconds: 2500));
        return reply(503, _preparing, {'retry-after': '1'});
      }
      return reply(200, '{"status":"authenticated"}');
    }),
  );
  await runPoll(
    'censored_preparing',
    urls,
    ScriptClient((request) async => frontIndex(request) < 3
        ? reply(503, _preparing, {'retry-after': '0'})
        : reply(200, '{"status":"authenticated"}')),
  );
  await runPoll(
    'long_retry_after',
    urls.take(4).toList(),
    ScriptClient((request) async => frontIndex(request) < 3
        ? reply(503, _preparing, {'retry-after': '10'})
        : reply(200, '{"status":"authenticated"}')),
  );
  await runPoll(
    'silent_first_batch',
    urls,
    ScriptClient((request) => frontIndex(request) < 3
        ? stallUntilAbort(request)
        : Future<http.StreamedResponse>.value(
            reply(200, '{"status":"authenticated"}'))),
  );
  final cancelledClient = ScriptClient(stallUntilAbort);
  var shouldCancel = false;
  final cancelledWatch = Stopwatch()..start();
  final cancelledPoll = Harness(cancelledClient)._postDoubleVpnAssignmentWithRetry(
    urls,
    VerifyRequestContext(
        body: '{}', headers: {'Content-Type': 'application/json'}),
    doubleVpnRequested: true,
    shouldCancel: () => shouldCancel,
  );
  await Future<void>.delayed(const Duration(milliseconds: 50));
  shouldCancel = true;
  await cancelledPoll;
  // An outer cancellation that only stops waiting would keep starting fronts.
  await Future<void>.delayed(const Duration(milliseconds: 900));
  print('cancelled started=${cancelledClient.started} '
      'elapsed_ms=${cancelledWatch.elapsedMilliseconds}');
  await run(
    'dead_first',
    ['https://dead.example/verify', 'https://hub.example/verify'],
    ScriptClient((request) async {
      if (request.url.host == 'dead.example') {
        throw const SocketException('connection refused');
      }
      return reply(200, '{"status":"authenticated"}');
    }),
  );
}
''';
