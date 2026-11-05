import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('connector rejects cancellation before publishing scoped proof', () {
    final source = File('lib/main.dart').readAsStringSync();
    final method = source.indexOf('Future<bool> _startTunnelCandidate(');
    expect(method, greaterThanOrEqualTo(0));

    final start = source.indexOf(
      'final proofDisplayGeneration = _tunnelDisplayLedger.generation;',
      method,
    );
    expect(start, greaterThan(method));

    final end = source.indexOf('if (!stillActive)', start);
    expect(end, greaterThan(start));
    final block = source.substring(start, end);

    final nativeRead = block.indexOf(
      "await _methodChannel.invokeMethod('getTunnelState')",
    );
    final cancellation = block.indexOf(
      'if (shouldCancel?.call() == true)',
    );
    final guard = block.indexOf('_nativeReadingIsCurrent(');
    final publication = block.indexOf(
      '_recordNativeTunnelProof(stillActive);',
    );

    expect(nativeRead, greaterThanOrEqualTo(0));
    expect(cancellation, greaterThan(nativeRead));
    expect(guard, greaterThan(cancellation));
    expect(publication, greaterThan(guard));
    expect(block, contains('proofDisplayGeneration,'));
    expect(block, contains('proofAccountEpoch,'));
    expect(block,
        contains('proofLifecycleGeneration == _resumeProofGeneration'));
    expect(block, contains('!_appInBackground'));
    expect(block, contains('!_resumeProofPending'));
  });
}
