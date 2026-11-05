import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// DESKTOP-2: both desktop hosts refuse a Winn v3 `startTunnel` that lacks a
/// concrete `winn3FailedNode`. A primary (non-cover) v3 start must therefore
/// always name its own selected node. The Dart half is pinned here: the real
/// caller-identity resolver and the real argument helper are executed, and the
/// production `_startTunnelCandidate` text is checked to place the value on the
/// channel unconditionally on the v3 branch.
///
/// The source path is injectable via `--dart-define=MAIN_DART_PATH=...` so a
/// mutant copy of main.dart must turn these assertions red.
const String _sourcePath = String.fromEnvironment(
  'MAIN_DART_PATH',
  defaultValue: 'lib/main.dart',
);

bool _isConcreteNodeSlug(String value) =>
    value.isNotEmpty && value.toLowerCase() != 'auto';

void main() {
  late String candidate;

  setUpAll(() {
    final source = File(_sourcePath).readAsStringSync();
    final start = source.indexOf('Future<bool> _startTunnelCandidate(');
    final end = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    candidate = source
        .substring(start, end)
        .split('\n')
        .where((line) => !line.trimLeft().startsWith('//'))
        .join('\n');
  });

  test('every selectable node yields a concrete failed-node argument', () {
    for (final slug in <String>['sg-1', 'de-1', 'us-east-2', 'nl1']) {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: slug,
      );
      expect(caller.isPresent, isTrue, reason: slug);
      final argument = winn3StartFailedNodeArgument(
        coverFallbackInProgress: false,
        coverFailedNode: '',
        selectedSlug: caller.exactSlug,
      );
      expect(argument, slug);
      expect(_isConcreteNodeSlug(argument), isTrue, reason: slug);
    }
  });

  test('an unusable selection never reaches the channel as a v3 start', () {
    for (final slug in <String>['', '   ', 'auto', 'AUTO']) {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: slug,
      );
      expect(caller.isPresent, isFalse, reason: '"$slug"');
      expect(caller.startArguments, isEmpty, reason: '"$slug"');
    }
    final refuse = candidate.indexOf(
      'if (protocolVersion == kWinnProtocolV3 && !selectedNodeCaller.isPresent) {',
    );
    final primary = candidate.indexOf(
      "startArguments['winn3FailedNode'] = winn3FailedNodeArg;",
    );
    expect(refuse, greaterThanOrEqualTo(0));
    expect(primary, greaterThan(refuse));
    expect(
      candidate.substring(refuse, primary),
      contains('return false;'),
      reason: 'the refusal must return before a v3 start is built',
    );
  });

  test('the v3 branch always sets winn3FailedNode, on the cover path too', () {
    const header = 'if (protocolVersion == kWinnProtocolV3) {';
    final branch = candidate.indexOf(
      header,
      candidate.indexOf('final startArguments = <String, dynamic>'),
    );
    final assign = candidate.indexOf(
      "startArguments['winn3FailedNode'] = winn3FailedNodeArg;",
      branch,
    );
    expect(branch, greaterThanOrEqualTo(0));
    expect(assign, greaterThan(branch));
    expect(
      candidate.substring(branch + header.length, assign),
      isNot(contains('if (')),
      reason: 'a primary v3 start must carry the key without a cover guard',
    );
    expect(
      candidate.substring(branch, assign),
      contains('selectedSlug: selectedNodeCaller.exactSlug,'),
    );
    expect(
        candidate,
        isNot(contains(
            '_winn3CoverFallbackInProgress ? _winn3CoverFailedNode : null')));
  });

  test('a cover leg still names the failed v3 node', () {
    expect(
      winn3StartFailedNodeArgument(
        coverFallbackInProgress: true,
        coverFailedNode: 'de-1',
        selectedSlug: 'nl-1',
      ),
      'de-1',
    );
  });
}
