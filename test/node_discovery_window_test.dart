import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/gateway_failover.dart';
import 'package:wins_vpn/hub_request_window.dart';

String _body(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
  final end = source.indexOf(nextSignature, start + signature.length);
  expect(end, greaterThan(start), reason: 'missing $nextSignature');
  return source.substring(start, end);
}

void main() {
  test('node discovery: one budget for resolution and the walk, abortable '
      'requests, and the beacon only after an exhaustive sweep', () {
    final source = File('lib/main.dart').readAsStringSync();
    final fetch = _body(
      source,
      'Future<bool> _fetchAvailableNodes({bool forceLive = false}) async {',
      'List<_SpeedTestTarget> _speedTestTargetsForNode(',
    );
    expect(fetch,
        contains('final discoveryBudget = HubOperationBudget(kNodeDiscoveryDeadline);'));
    expect(fetch,
        contains('await _resolveDynamicEndpointsWithin(discoveryBudget.remaining);'));
    expect(fetch, isNot(contains('await _resolveDynamicEndpoints();')));
    expect(fetch, contains('totalDeadline: discoveryBudget.remaining,'));
    expect(fetch, contains('sendHubRequest('));
    expect(fetch, isNot(contains('.timeout(')));
    expect(fetch, isNot(contains('for (final url in nodeDiscoveryUrls(')));
    // The recovery-beacon contract: every compiled gateway tried and failed.
    final gate = fetch.indexOf('if (outcome.exhaustive) {');
    final note = fetch.indexOf('_noteGatewaySweepFailure();');
    expect(gate, greaterThan(0));
    expect(note, greaterThan(gate));
    expect('_noteGatewaySweepFailure();'.allMatches(fetch).length, 1);
    // Unchanged obligations of the walk.
    expect(fetch, contains('nodeDiscoveryPayloadHasNodes(res.body)'));
    expect(fetch, contains('deferredEmptyNodesResponse ??= res.body;'));
    expect(fetch, contains('_noteGatewaySweepSuccess(liveNodesUrl);'));
    expect(fetch, contains('await _loadCachedNodesFromDisk();'));
  });

  testWidgets('a walk cut short by its deadline is not exhaustive; one where '
      'every front fails is', (tester) async {
    HubRequestWindowOutcome<String>? cut;
    runHubRequestWindow<String>(
      urls: List<String>.generate(29, (i) => 'https://f$i/nodes'),
      policy: const HubRequestWindowPolicy(
        perRequestTimeout: Duration(seconds: 5),
        totalDeadline: kNodeDiscoveryDeadline,
      ),
      attempt: (_, abort) =>
          abort.then((_) => const HubAttemptResult<String>.rejected()),
    ).then((value) => cut = value);
    await tester.pump(kNodeDiscoveryDeadline);
    expect(cut!.deadlineReached, isTrue);
    expect(cut!.exhaustive, isFalse);
    expect(cut!.started.length, lessThan(29));

    HubRequestWindowOutcome<String>? full;
    runHubRequestWindow<String>(
      urls: List<String>.generate(29, (i) => 'https://f$i/nodes'),
      attempt: (_, __) async => const HubAttemptResult<String>.rejected(),
    ).then((value) => full = value);
    for (var i = 0; i < 400 && full == null; i++) {
      await tester.pump(const Duration(milliseconds: 10));
    }
    expect(full!.exhaustive, isTrue);
    expect(full!.started.length, 29);
  });

  testWidgets('an empty listing is skipped and a later live listing wins',
      (tester) async {
    final bodies = <String, String>{
      'https://a/nodes': '{"nodes":[]}',
      'https://b/nodes': '<!DOCTYPE html>',
      'https://c/nodes': '{"nodes":[{"slug":"uk"}]}',
    };
    String? deferred;
    HubRequestWindowOutcome<String>? outcome;
    runHubRequestWindow<String>(
      urls: bodies.keys.toList(),
      attempt: (url, _) async {
        final body = bodies[url]!;
        if (body.contains('<!DOCTYPE')) {
          return const HubAttemptResult<String>.rejected();
        }
        if (!isNodeDiscoveryPayload(body) ||
            !nodeDiscoveryPayloadHasNodes(body)) {
          deferred ??= body;
          return const HubAttemptResult<String>.rejected();
        }
        return HubAttemptResult<String>.accepted(body);
      },
    ).then((value) => outcome = value);
    for (var i = 0; i < 40; i++) {
      await tester.pump(const Duration(milliseconds: 10));
    }
    expect(outcome!.acceptedUrl, 'https://c/nodes');
    expect(deferred, '{"nodes":[]}');
  });
}
