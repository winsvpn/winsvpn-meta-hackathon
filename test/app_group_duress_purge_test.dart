import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:wins_vpn/app_group_duress_purge.dart';

void main() {
  test('negative residual counts cannot prove a completed purge', () {
    expect(
      keychainPurgeLeftResidual(<String, dynamic>{
        'keychain_purge_complete': true,
        'keychain_purge_remaining_items': -1,
      }),
      isTrue,
    );
    expect(
      appGroupPurgeLeftResidual(<String, dynamic>{
        'app_group_purge_complete': true,
        'app_group_purge_remaining_count': -1,
      }),
      isTrue,
    );
  });
  group('keychainPurgeLeftResidual', () {
    test('a complete, observed-empty report is clean', () {
      expect(
        keychainPurgeLeftResidual(<String, dynamic>{
          'keychain_purge_complete': true,
          'keychain_purge_purged_count': 7,
          'keychain_purge_absent_count': 0,
          'keychain_purge_blocked_count': 0,
          'keychain_purge_remaining_items': 0,
        }),
        isFalse,
      );
    });

    test('an incomplete report is a residual (complete is strict)', () {
      expect(
        keychainPurgeLeftResidual(<String, dynamic>{
          'keychain_purge_complete': false,
          'keychain_purge_remaining_items': 0,
        }),
        isTrue,
      );
    });

    test('a report still holding items is a residual', () {
      expect(
        keychainPurgeLeftResidual(<String, dynamic>{
          'keychain_purge_complete': true,
          'keychain_purge_remaining_items': 1,
        }),
        isTrue,
      );
    });

    test('fails closed on a missing, malformed or absent report', () {
      expect(keychainPurgeLeftResidual(null), isTrue);
      expect(keychainPurgeLeftResidual(<String, dynamic>{}), isTrue);
      expect(
        keychainPurgeLeftResidual(<String, dynamic>{
          'keychain_purge_complete': true,
        }),
        // The remaining count is absent, so the clean state is not observed.
        isTrue,
      );
      expect(
        keychainPurgeLeftResidual(<String, dynamic>{
          'keychain_purge_complete': true,
          'keychain_purge_remaining_items': 'zero',
        }),
        isTrue,
      );
    });
  });

  group('appGroupPurgeLeftResidual', () {
    test('a complete, observed-empty container is clean', () {
      expect(
        appGroupPurgeLeftResidual(<String, dynamic>{
          'app_group_purge_complete': true,
          'app_group_purge_removed_count': 3,
          'app_group_purge_remaining_count': 0,
        }),
        isFalse,
      );
    });

    test('an incomplete container report is a residual', () {
      expect(
        appGroupPurgeLeftResidual(<String, dynamic>{
          'app_group_purge_complete': false,
          'app_group_purge_remaining_count': 0,
        }),
        isTrue,
      );
    });

    test('a container re-read with entries remaining is a residual', () {
      expect(
        appGroupPurgeLeftResidual(<String, dynamic>{
          'app_group_purge_complete': true,
          'app_group_purge_remaining_count': 2,
        }),
        isTrue,
      );
    });

    test('fails closed on a missing, malformed or absent report', () {
      expect(appGroupPurgeLeftResidual(null), isTrue);
      expect(appGroupPurgeLeftResidual(<String, dynamic>{}), isTrue);
      expect(
        appGroupPurgeLeftResidual(<String, dynamic>{
          'app_group_purge_complete': true,
        }),
        isTrue,
      );
    });
  });

  group('appleDuressPurgeLeftAnyResidual', () {
    test('invoking duress clears both roots with nothing left', () {
      expect(
        appleDuressPurgeLeftAnyResidual(
          keychain: <String, dynamic>{
            'keychain_purge_complete': true,
            'keychain_purge_remaining_items': 0,
          },
          appGroup: <String, dynamic>{
            'app_group_purge_complete': true,
            'app_group_purge_remaining_count': 0,
          },
        ),
        isFalse,
      );
    });

    test('a residual in the Keychain fails the whole wipe', () {
      expect(
        appleDuressPurgeLeftAnyResidual(
          keychain: <String, dynamic>{
            'keychain_purge_complete': true,
            'keychain_purge_remaining_items': 1,
          },
          appGroup: <String, dynamic>{
            'app_group_purge_complete': true,
            'app_group_purge_remaining_count': 0,
          },
        ),
        isTrue,
      );
    });

    test('a residual in the App Group fails the whole wipe', () {
      expect(
        appleDuressPurgeLeftAnyResidual(
          keychain: <String, dynamic>{
            'keychain_purge_complete': true,
            'keychain_purge_remaining_items': 0,
          },
          appGroup: <String, dynamic>{
            'app_group_purge_complete': true,
            'app_group_purge_remaining_count': 3,
          },
        ),
        isTrue,
      );
    });

    test('the two roots fail independently', () {
      expect(
        appleDuressPurgeLeftAnyResidual(
          keychain: null,
          appGroup: <String, dynamic>{
            'app_group_purge_complete': true,
            'app_group_purge_remaining_count': 0,
          },
        ),
        isTrue,
      );
      expect(
        appleDuressPurgeLeftAnyResidual(
          keychain: <String, dynamic>{
            'keychain_purge_complete': true,
            'keychain_purge_remaining_items': 0,
          },
          appGroup: null,
        ),
        isTrue,
      );
    });
  });

  // WIRING ONLY. This proves the extracted functions are actually used by the
  // duress sweep in main.dart -- that the residual verdict is not dead code
  // sitting beside a path that ignores it. The existing
  // `apple_private_config_persistence_test` already proves the purge method
  // channel calls live inside `_sweepAppStorageForDuress`; this closes the gap
  // that the verdict, not just the call, is on the path.
  test('the duress sweep in main.dart evaluates the residual verdict', () {
    final dart = File('lib/main.dart').readAsStringSync();
    expect(dart, contains("import 'app_group_duress_purge.dart';"));

    final sweepStart = dart.indexOf('_sweepAppStorageForDuress({');
    expect(sweepStart, greaterThanOrEqualTo(0));
    final sweepEnd = dart.indexOf(
      'THERE IS DELIBERATELY NO NATIVE APP-DATA WIPE ON THIS PATH ANY MORE',
      sweepStart,
    );
    expect(sweepEnd, greaterThan(sweepStart));
    final sweepBody = dart.substring(sweepStart, sweepEnd);
    expect(sweepBody, contains('keychainPurgeLeftResidual'));
    expect(sweepBody, contains('appGroupPurgeLeftResidual'));
  });
}
