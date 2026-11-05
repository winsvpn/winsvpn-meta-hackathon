import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hub_request_window.dart';

String _body(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
  final end = source.indexOf(nextSignature, start + signature.length);
  expect(end, greaterThan(start), reason: 'missing $nextSignature');
  return source.substring(start, end);
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('the connect-path free refresh KEEPS the /free/status preflight, now '
      'cancellable', () {
    final refresh = _body(
      source,
      'Future<bool> _refreshFreeVpnConfig(',
      'Future<bool> _refreshVpnConfigForCurrentSelection(',
    );
    expect(refresh, contains('await _freeAccessPreflightTerminalKind(\n'
        '          shouldCancel: refreshCancelled,\n'
        '        ) !=\n'
        '        null'));
    final preflight = refresh.indexOf('_freeAccessPreflightTerminalKind(');
    final nodes = refresh.indexOf('await _sharedNodeDiscovery();');
    expect(preflight, greaterThan(0));
    expect(nodes, greaterThan(preflight));
  });

  test('activation keeps its early terminal message', () {
    final activation = _body(
      source,
      'Future<void> _loginWithFreeAccess() async {',
      'Future<void> _onAuthSuccess(',
    );
    expect(activation,
        contains('final preflightTerminal = await _freeAccessPreflightTerminalKind('));
  });

  test('activation cancellation during the preflight: the epoch is rechecked '
      'before any feedback, tunnel operation or account work', () {
    final activation = _body(
      source,
      'Future<void> _loginWithFreeAccess() async {',
      'Future<void> _onAuthSuccess(',
    );
    final preflight = activation.indexOf(
        'final preflightTerminal = await _freeAccessPreflightTerminalKind(');
    final check = activation.indexOf(
        'if (!_accountEpochIsCurrent(activationEpoch)) return;', preflight);
    final feedback = activation.indexOf('_showFreeVerifyTerminalFeedback(', preflight);
    final discovery = activation.indexOf('await _fetchAvailableNodes();');
    expect(preflight, greaterThan(0));
    expect(check, greaterThan(preflight));
    expect(check, lessThan(feedback));
    expect(check, lessThan(discovery));
  });

  test('activation cancellation during discovery: the epoch is rechecked '
      'before stopTunnel and before any key or account work', () {
    final activation = _body(
      source,
      'Future<void> _loginWithFreeAccess() async {',
      'Future<void> _onAuthSuccess(',
    );
    final discovery = activation.indexOf('await _fetchAvailableNodes();');
    final check = activation.indexOf(
        'if (!_accountEpochIsCurrent(activationEpoch)) return;', discovery);
    final stopTunnel = activation.indexOf("invokeMethod('stopTunnel')");
    final keys = activation.indexOf('_loadOrCreateClientKeyPair(');
    expect(check, greaterThan(discovery));
    expect(check, lessThan(stopTunnel));
    expect(check, lessThan(keys));
    // Nothing between discovery and that check.
    expect(
      activation.substring(discovery, check).trim(),
      'await _fetchAvailableNodes();',
    );
  });

  test('the preflight walk tracks, passes and releases its cancellation', () {
    final preflight = _body(
      source,
      'Future<String?> _freeAccessPreflightTerminalKind({',
      'bool _isBase64WireGuardKey(',
    );
    final track = preflight.indexOf(
        'final cancellation = _hubCancellations.track(shouldCancel ?? () => false);');
    final pass = preflight.indexOf('cancellation: cancellation,');
    final release = preflight.indexOf('_hubCancellations.release(cancellation);');
    expect(track, greaterThan(0));
    expect(pass, greaterThan(track));
    expect(release, greaterThan(pass));
  });

  test('the preflight walks the window with abortable requests under its '
      'deadline', () {
    final preflight = _body(
      source,
      'Future<String?> _freeAccessPreflightTerminalKind({',
      'bool _isBase64WireGuardKey(',
    );
    expect(preflight, contains('runHubRequestWindow<String>('));
    expect(preflight, contains('totalDeadline: kFreeStatusPreflightDeadline'));
    expect(preflight, contains('sendHubRequest('));
    expect(preflight, contains('shouldCancel: shouldCancel,'));
    expect(preflight, isNot(contains('.timeout(')));
    expect(preflight, isNot(contains('for (final url in gateways)')));
  });

  test('the preflight reads the shared origin preference, and only a 200 '
      'teaches it', () {
    final preflight = _body(
      source,
      'Future<String?> _freeAccessPreflightTerminalKind({',
      'bool _isBase64WireGuardKey(',
    );
    expect(preflight, contains('urls: _hubOriginPreference.order(gateways),'));
    expect(preflight, isNot(contains('preference: _hubOriginPreference,')));
    expect(
      preflight,
      contains('          if (response.statusCode == 200) {\n'
          '            _hubOriginPreference.recordAccepted(url);\n'
          '          }'),
    );
  });

  test('a non-HTML 500 accepted by the preflight teaches the shared '
      'preference under P1 wiring, and does not under C-2 wiring', () async {
    const fronts = <String>[
      'https://sync.winsvpn.org/free/status',
      'https://a.app-cloud-sync.net/free/status',
    ];
    // One preflight walk in which the first front is silent-rejected and the
    // second answers [status] with a non-HTML body, the case the preflight
    // closure in main.dart accepts. [c2] selects C-2's wiring (the walk reads
    // the preference, and the closure teaches it only on a 200, as the source
    // test above pins) instead of P1's (the window is given the preference).
    Future<String?> walk(HubOriginPreference preference, int status,
        {required bool c2}) async {
      final outcome = await runHubRequestWindow<String>(
        urls: c2 ? preference.order(fronts) : fronts,
        preference: c2 ? null : preference,
        permits: HubTransportPermits(3),
        policy: const HubRequestWindowPolicy(
          stagger: Duration(milliseconds: 20),
          minSpacing: Duration.zero,
        ),
        attempt: (url, abort) async {
          if (!url.contains('a.app-cloud-sync.net')) {
            return const HubAttemptResult<String>.rejected();
          }
          if (c2 && status == 200) preference.recordAccepted(url);
          return const HubAttemptResult<String>.accepted('');
        },
      );
      return outcome.acceptedUrl;
    }

    const known = 'https://sync.winsvpn.com:443';
    final p1 = HubOriginPreference()
      ..recordAccepted('https://sync.winsvpn.com/verify');
    expect(await walk(p1, 500, c2: false), fronts[1]);
    expect(p1.origin, 'https://a.app-cloud-sync.net:443',
        reason: 'P1 wiring: the accepted 500 taught the preference');

    final c2 = HubOriginPreference()
      ..recordAccepted('https://sync.winsvpn.com/verify');
    expect(await walk(c2, 500, c2: true), fronts[1]);
    expect(c2.origin, known,
        reason: 'C-2 wiring: an accepted 500 must not teach the preference');
    expect(await walk(c2, 200, c2: true), fronts[1]);
    expect(c2.origin, 'https://a.app-cloud-sync.net:443',
        reason: 'C-2 wiring: a 200 does teach it');
  });

  // ARBITER-COMPOSED (Turn 6, PERF-CHOICE): Sol's rule. The preflight
  // gives the window the preference only for forgetting it on a timeout,
  // and still learns from a 200 alone.
  test('the preflight passes the shared preference as timeoutPreference '
      'and an accepted 500 still does not teach it', () async {
    final preflight = _body(
      source,
      'Future<String?> _freeAccessPreflightTerminalKind({',
      'bool _isBase64WireGuardKey(',
    );
    expect(
      preflight,
      contains('      urls: _hubOriginPreference.order(gateways),\n'
          '      timeoutPreference: _hubOriginPreference,\n'),
    );
    expect(preflight, isNot(contains(' preference: _hubOriginPreference,')));

    const fronts = <String>[
      'https://sync.winsvpn.org/free/status',
      'https://a.app-cloud-sync.net/free/status',
    ];
    final preference = HubOriginPreference()
      ..recordAccepted('https://sync.winsvpn.com/verify');
    for (final status in <int>[500, 200]) {
      final outcome = await runHubRequestWindow<String>(
        urls: preference.order(fronts),
        timeoutPreference: preference,
        permits: HubTransportPermits(3),
        policy: const HubRequestWindowPolicy(
          stagger: Duration(milliseconds: 20),
          minSpacing: Duration.zero,
        ),
        attempt: (url, abort) async {
          if (!url.contains('a.app-cloud-sync.net')) {
            return const HubAttemptResult<String>.rejected();
          }
          if (status == 200) preference.recordAccepted(url);
          return const HubAttemptResult<String>.accepted('');
        },
      );
      expect(outcome.acceptedUrl, fronts[1]);
      expect(
          preference.origin,
          status == 200
              ? 'https://a.app-cloud-sync.net:443'
              : 'https://sync.winsvpn.com:443');
    }
  });

  testWidgets('a preflight whose fronts are all silent proceeds at its '
      '6 s deadline instead of after 29 x 3 s', (tester) async {
    HubRequestWindowOutcome<String>? outcome;
    runHubRequestWindow<String>(
      urls: List<String>.generate(29, (i) => 'https://f$i/free/status'),
      policy: const HubRequestWindowPolicy(
        perRequestTimeout: Duration(seconds: 3),
        totalDeadline: kFreeStatusPreflightDeadline,
      ),
      attempt: (_, abort) => abort.then(
          (_) => const HubAttemptResult<String>.rejected()),
    ).then((value) => outcome = value);
    await tester.pump(kFreeStatusPreflightDeadline -
        const Duration(milliseconds: 1));
    expect(outcome, isNull);
    await tester.pump(const Duration(milliseconds: 1));
    expect(outcome!.deadlineReached, isTrue);
    expect(outcome!.value, isNull);
  });
}
