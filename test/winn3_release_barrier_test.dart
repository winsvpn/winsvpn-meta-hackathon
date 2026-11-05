import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_release_barrier.dart';

// Round L (OI-L4): what counts as proof that a held capture was released.

Map<String, dynamic> _reading({
  int holdId = 0,
  int sequence = 8,
  int lastHoldId = 3,
  String disposition = 'closed',
  bool interfaceOpen = false,
  bool captureHeld = false,
}) =>
    <String, dynamic>{
      'active': false,
      'interface_open': interfaceOpen,
      'winn3_capture_held': captureHeld,
      'winn3_hold_id': holdId,
      'winn3_release_sequence': sequence,
      'winn3_release_hold_id': lastHoldId,
      'winn3_release_disposition': disposition,
    };

void main() {
  const mark = Winn3ReleaseMark(holdId: 3, sequence: 7);

  test('a mark is taken only for a published, held capture', () {
    expect(
        winn3ReleaseMarkFromReadiness(_reading(
            holdId: 3, sequence: 7, captureHeld: true, interfaceOpen: true)),
        mark);
    expect(winn3ReleaseMarkFromReadiness(null), isNull);
    expect(winn3ReleaseMarkFromReadiness(<String, dynamic>{'active': false}),
        isNull, reason: 'a host without the ledger has nothing to bind to');
    expect(
        winn3ReleaseMarkFromReadiness(
            _reading(holdId: 0, captureHeld: true, interfaceOpen: true)),
        isNull);
    expect(
        winn3ReleaseMarkFromReadiness(
            _reading(holdId: 3, captureHeld: false, interfaceOpen: true)),
        isNull);
  });

  test('only a later, closed acknowledgement for the marked hold releases', () {
    expect(winn3ReleaseOutcome(mark, _reading()), Winn3ReleaseOutcome.released);
    // Not yet decided: keep waiting.
    for (final reading in <Map<String, dynamic>?>[
      null,
      <String, dynamic>{'active': false, 'interface_open': false},
      _reading(sequence: 7),
      _reading(lastHoldId: 4),
      _reading(interfaceOpen: true),
      _reading(disposition: 'incomplete'),
      _reading(disposition: 'winn3_hold'),
    ]) {
      expect(winn3ReleaseOutcome(mark, reading), isNull, reason: '$reading');
    }
    expect(winn3ReleaseOutcome(mark, _reading(disposition: 'kill_switch_block')),
        Winn3ReleaseOutcome.killSwitchBlock);
    expect(winn3ReleaseOutcome(mark, _reading(disposition: 'superseded')),
        Winn3ReleaseOutcome.notReleased);
  });

  test('the keys are the ones the Android ledger publishes', () {
    final kotlin = File(
            'android/app/src/main/kotlin/org/winsvpn/app/WinnV3ReleaseLedger.kt')
        .readAsStringSync();
    for (final key in const <String>[
      'KEY_HOLD_ID = "winn3_hold_id"',
      'KEY_SEQUENCE = "winn3_release_sequence"',
      'KEY_LAST_HOLD_ID = "winn3_release_hold_id"',
      'KEY_LAST_DISPOSITION = "winn3_release_disposition"',
      'CLOSED("closed")',
      'KILL_SWITCH_BLOCK("kill_switch_block")',
      'SUPERSEDED("superseded")',
    ]) {
      expect(kotlin, contains(key));
    }
  });
}
