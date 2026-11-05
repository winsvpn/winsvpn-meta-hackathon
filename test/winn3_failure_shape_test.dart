import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';

/// The readiness document MainActivity.kt publishes for a finished v3 start:
/// `winn3_security_refusal` is `verdict.securityRefusal`, which is true for
/// BOTH terminal_security and unknown_terminal (WinnV3StagedStart.kt).
Map<String, Object?> _readiness(String verdict, {int token = 41}) =>
    <String, Object?>{
      'winn3_start_token': token,
      'winn3_start_generation': 7,
      'winn3_selection_generation': 'g',
      'winn3_failed_node': '',
      'winn3_security_refusal':
          verdict == 'terminal_security' || verdict == 'unknown_terminal',
      'winn3_verdict': verdict,
      'winn3_start_state': verdict,
    };

void main() {
  test('an unknown_terminal start is not worded as a security refusal',
      () {
    final readiness = _readiness('unknown_terminal');
    expect(nativeWinn3FailureShape(readiness, startToken: 41),
        Winn3FailureShape.unconfirmedTerminal);
    // The authority path is unchanged: still terminal, still no fallback.
    expect(nativeWinn3ReadinessVerdict(readiness, startToken: 41),
        Winn3NativeVerdict.terminalSecurity);
  });

  test('a typed security refusal keeps the refusal wording', () {
    expect(
      nativeWinn3FailureShape(_readiness('terminal_security'), startToken: 41),
      Winn3FailureShape.securityRefusal,
    );
  });

  test('another start, a missing token or an untyped verdict is unclassified',
      () {
    expect(nativeWinn3FailureShape(_readiness('unknown_terminal', token: 40),
        startToken: 41), Winn3FailureShape.unclassified);
    expect(nativeWinn3FailureShape(_readiness('unknown_terminal'),
        startToken: null), Winn3FailureShape.unclassified);
    expect(nativeWinn3FailureShape(null, startToken: 41),
        Winn3FailureShape.unclassified);
    expect(nativeWinn3FailureShape(_readiness('pending'), startToken: 41),
        Winn3FailureShape.unclassified);
    expect(
      nativeWinn3FailureShape(
        <String, Object?>{..._readiness('unknown_terminal'), 'winn3_verdict': 3},
        startToken: 41,
      ),
      Winn3FailureShape.unclassified,
    );
    expect(
      nativeWinn3FailureShape(
        <String, Object?>{
          ..._readiness('unknown_terminal'),
          'winn3_start_verdict': 'terminal_security',
        },
        startToken: 41,
      ),
      Winn3FailureShape.securityRefusal,
      reason: 'mixed aliases: security wins',
    );
  });

  test('a refusal seen once is never relabelled as silence', () {
    var shape = Winn3FailureShape.unclassified;
    shape = mergeWinn3FailureShape(shape, Winn3FailureShape.securityRefusal);
    shape = mergeWinn3FailureShape(shape, Winn3FailureShape.unconfirmedTerminal);
    expect(shape, Winn3FailureShape.securityRefusal);
    expect(
      mergeWinn3FailureShape(
        Winn3FailureShape.unconfirmedTerminal,
        Winn3FailureShape.unclassified,
      ),
      Winn3FailureShape.unconfirmedTerminal,
    );
  });

  test('the connect path words the lead failure by its shape and still '
      'returns before any fallback', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _connectWithSmartProtocol(');
    final end = source.indexOf('Future<void> _toggleVpnConnection()', start);
    final connect = source.substring(start, end);
    final awg = connect.indexOf(
        'final directStarted = await attemptDirectAwgCandidate();');
    final refusal =
        connect.indexOf('if (_lastTunnelCandidateWasSecurityRefusal) {', awg);
    final ret = connect.indexOf('\n        return;', refusal);
    final branch = connect.substring(refusal, ret);
    expect(branch, contains('Winn3FailureShape.unconfirmedTerminal'));
    expect(
      branch,
      contains("'The secure Winn Protocol® connection could not be established. '\n"
          "                'No fallback was attempted. Try again, or choose another '\n"
          "                'server.'"),
    );
    // The unconfirmed shape must not claim silence: that wording is reserved
    // for a separately typed silent-exhaustion result, which does not exist.
    expect(connect, isNot(contains('did not answer')));
    expect(branch, contains('No fallback was attempted.'));
    expect(
      connect.indexOf('maySelectLegacyRouteAfterWinn3Lead(', ret),
      greaterThan(ret),
    );
    final reader = source.substring(
      source.indexOf('Future<Winn3NativeVerdict> _nativeWinn3Verdict({'),
      source.indexOf('int _nextWinn3StartToken()'),
    );
    expect(reader, contains('nativeWinn3FailureShape(readiness'));
  });
}
