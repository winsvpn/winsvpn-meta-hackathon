import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Owner transport policy: served Winn v3 is primary. A separate Winn v1
/// compatibility path defaults to direct AWG first and Xray second. A v3
/// security refusal is never permission to downgrade.
void main() {
  late String source;
  late String connect;
  late String dispatchGate;
  late String dispatchSection;

  String withoutComments(String code) => code
      .split('\n')
      .where((line) => !line.trimLeft().startsWith('//'))
      .join('\n');

  setUpAll(() {
    source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf(
      'Future<void> _connectWithSmartProtocol(',
    );
    final end = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    connect = source.substring(start, end);

    final dispatch = File('lib/winn_protocol_dispatch.dart').readAsStringSync();
    final gateStart = dispatch.indexOf('enum _Winn1FallbackDispatchLeg');
    final gateEnd = dispatch.indexOf(
      '/// True when the verified descriptor',
      gateStart,
    );
    expect(gateStart, greaterThanOrEqualTo(0));
    expect(gateEnd, greaterThan(gateStart));
    dispatchGate = withoutComments(dispatch.substring(gateStart, gateEnd));

    final sectionStart = dispatch.indexOf('String winnSectionForTunnelConfig(');
    final sectionEnd = dispatch.indexOf(
      'List<AwgHeaderSpec>? winnAwgHeaderTypes(',
      sectionStart,
    );
    expect(sectionStart, greaterThanOrEqualTo(0));
    expect(sectionEnd, greaterThan(sectionStart));
    dispatchSection =
        withoutComments(dispatch.substring(sectionStart, sectionEnd));
  });

  test('default v1 order is AWG before Xray', () {
    final awgLead = connect.indexOf(
      'final directStarted = await attemptDirectAwgCandidate();',
    );
    final xrayCandidates = connect.indexOf(
      'var candidates = await _reachableTcpFallbackOptions(',
    );
    expect(awgLead, greaterThanOrEqualTo(0));
    expect(xrayCandidates, greaterThan(awgLead));
  });

  test('the production branch attempts the served v3 lead before any fallback',
      () {
    final policy = connect.indexOf('final leadPolicy = winn3LeadPolicy(');
    final leadBranch = connect.indexOf('if (attemptLeadCandidate) {', policy);
    final attempt = connect.indexOf(
      'final directStarted = await attemptDirectAwgCandidate();',
      leadBranch,
    );
    final cover = connect.indexOf(
      'maySelectLegacyRouteAfterWinn3Lead(',
      attempt,
    );
    final xray = connect.indexOf(
      'var candidates = await _reachableTcpFallbackOptions(',
      attempt,
    );
    expect(policy, greaterThanOrEqualTo(0));
    expect(leadBranch, greaterThan(policy));
    expect(attempt, greaterThan(leadBranch));
    expect(cover, greaterThan(attempt));
    expect(xray, greaterThan(cover));
  });

  test('an AWG failure reaches Xray only after the direct success return', () {
    final awgAttempt = connect.indexOf(
      'final directStarted = await attemptDirectAwgCandidate();',
    );
    final awgSuccess = connect.indexOf('if (directStarted) {', awgAttempt);
    final awgSuccessReturn = connect.indexOf('\n        return;', awgSuccess);
    final xrayCandidates = connect.indexOf(
      'var candidates = await _reachableTcpFallbackOptions(',
      awgSuccessReturn,
    );
    final xrayLoop = connect.indexOf(
      'for (final candidate in boundedCandidates) {',
      xrayCandidates,
    );
    final xrayStart = connect.indexOf(
      'if (await _startTunnelCandidate(',
      xrayLoop,
    );

    expect(awgAttempt, greaterThanOrEqualTo(0));
    expect(awgSuccess, greaterThan(awgAttempt));
    expect(awgSuccessReturn, greaterThan(awgSuccess));
    expect(xrayCandidates, greaterThan(awgSuccessReturn));
    expect(xrayLoop, greaterThan(xrayCandidates));
    expect(xrayStart, greaterThan(xrayLoop));
  });

  test('there is no Xray production start before the AWG lead attempt', () {
    final awgAttempt = connect.indexOf(
      'final directStarted = await attemptDirectAwgCandidate();',
    );
    final xrayCandidates = connect.indexOf(
      'var candidates = await _reachableTcpFallbackOptions(',
    );
    final xrayLoop = connect.indexOf(
      'for (final candidate in boundedCandidates) {',
    );

    expect(awgAttempt, greaterThanOrEqualTo(0));
    expect(xrayCandidates, greaterThan(awgAttempt));
    expect(xrayLoop, greaterThan(xrayCandidates));
    expect(
      connect.substring(0, awgAttempt),
      isNot(contains('var candidates = await _reachableTcpFallbackOptions(')),
    );
  });

  test('v3 cover-node decision occurs before same-node Xray', () {
    final cover = connect.indexOf(
      'maySelectLegacyRouteAfterWinn3Lead(',
    );
    final xrayCandidates = connect.indexOf(
      'var candidates = await _reachableTcpFallbackOptions(',
    );
    expect(cover, greaterThanOrEqualTo(0));
    expect(xrayCandidates, greaterThan(cover));
  });

  test('security refusal terminates without v1 fallback', () {
    final awgAttempt = connect.indexOf(
      'final directStarted = await attemptDirectAwgCandidate();',
    );
    final refusal = connect.indexOf(
      'if (_lastTunnelCandidateWasSecurityRefusal) {',
      awgAttempt,
    );
    final refusalReturn = connect.indexOf('\n        return;', refusal);
    final cover = connect.indexOf(
      'maySelectLegacyRouteAfterWinn3Lead(',
      refusalReturn,
    );
    final xray = connect.indexOf(
      'var candidates = await _reachableTcpFallbackOptions(',
      cover,
    );
    expect(refusal, greaterThan(awgAttempt));
    expect(refusalReturn, greaterThan(refusal));
    expect(cover, greaterThan(refusalReturn));
    expect(xray, greaterThan(cover));
    expect(
      connect,
      contains(
        'Winn Protocol® refused an invalid or unsupported server '
        'configuration. No fallback was attempted.',
      ),
    );
    expect(
      connect,
      contains(
        'primaryVerdict: _lastWinn3NativeVerdict',
      ),
    );
  });

  test('the native start is downstream of the Dart v1 authorization gate', () {
    final candidateStart =
        source.indexOf('Future<bool> _startTunnelCandidate(');
    final candidateEnd = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      candidateStart,
    );
    final candidate = source.substring(candidateStart, candidateEnd);
    final rawConfig = candidate.indexOf('_buildRawAmneziaConfig(');
    final nativeStart =
        candidate.indexOf(".invokeMethod(\n            'startTunnel'");
    expect(rawConfig, greaterThanOrEqualTo(0));
    expect(nativeStart, greaterThan(rawConfig));

    final builderStart = source.indexOf('String _buildRawAmneziaConfig(');
    final builderEnd = source.indexOf(
      'String _currentSelectedSlug()',
      builderStart,
    );
    final builder = source.substring(builderStart, builderEnd);
    expect(builder, contains('winnSectionForTunnelConfig('));
    expect(dispatchSection,
        contains('_consumeWinn1FallbackDispatchAuthorization'));
    expect(dispatchSection, contains('throw StateError('));
  });

  test('the reviewed v1 pair is fixed in memory as AWG then Xray', () {
    expect(
      dispatchGate,
      contains('enum _Winn1FallbackDispatchLeg { awg, xray }'),
    );
    expect(
      dispatchGate,
      contains('nextLeg: _Winn1FallbackDispatchLeg.awg'),
    );
    expect(
      dispatchGate,
      contains('nextLeg: _Winn1FallbackDispatchLeg.xray'),
    );
    for (final floatingLookup in <String>[
      'HttpClient',
      'Uri.',
      'File(',
      'Directory(',
      'Process.',
      'package:http',
      'pub.dev',
      'github.com',
      'latest',
    ]) {
      expect(dispatchGate, isNot(contains(floatingLookup)));
    }
  });
}
