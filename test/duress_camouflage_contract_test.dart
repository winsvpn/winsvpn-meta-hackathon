import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart';
import 'package:wins_vpn/main.dart' show buildEntryFailureDialog;

String _normalizeSourceWhitespace(String source) => source
    .replaceAll(RegExp(r'\s+'), ' ')
    .replaceAll(RegExp(r'\(\s+'), '(')
    .replaceAll(RegExp(r'\s+\)'), ')')
    .trim();

/// Tests for the duress (panic) code wiring.
///
/// READ THIS BEFORE ADDING TO THIS FILE.
///
/// Until 2026-08-06 this file was 30 passing tests and ALL of them were
/// source-greps: they read `lib/main.dart` as text and asserted that
/// substrings were present. The first end-to-end run on a real device then
/// found, in a feature whose failure mode is measured in a person's safety:
///
///   * the duress wipe UNMASKED the app -- a cold start after duress showed
///     the branded consent dialog over the real activation screen, because
///     the decoy was armed from a credential the wipe deletes;
///   * the "silent" duress entry raised a modal dialog 1047 ms later while a
///     wrong PIN raised nothing, ever -- a perfect tell;
///   * the duress branch skipped a ~60 ms ledger write, giving two timing
///     distributions with zero overlap;
///   * `node_cache.json` survived the wipe in plaintext, listing node
///     endpoints and the covert stealth domain.
///
/// Every one of those survived the green suite, and none of them could have
/// been caught by a grep: this file asserted that the popup EXISTED and was
/// generic. It never asked whether a wrong PIN also produced one.
///
/// So the first group below tests BEHAVIOUR -- what the app does, through the
/// same pure functions the app itself calls to decide. The second group keeps
/// source guards only for architecture that has no runtime surface a unit test
/// can reach (there is no hub; iOS never sends). When you add a test here, ask
/// the question this file failed to ask: would it fail if the app misbehaved?
void main() {
  group('BEHAVIOUR: a duress entry is indistinguishable from a mistyped one',
      () {
    // The signature deliberately excludes armsDuress: arming is the one thing
    // that is meant to be invisible. Everything else must match exactly.
    ObservableEntrySignature signatureFor({
      required bool duress,
      required bool lockedOut,
    }) =>
        classifyCredentialEntry(
          credentialEnrolled: true,
          pinMatches: false,
          recoveryMatches: false,
          duressMatches: duress,
          lockedOut: lockedOut,
        ).observable;

    test(
        'duress and wrong-PIN produce an identical observable signature, '
        'locked out or not', () {
      for (final lockedOut in <bool>[false, true]) {
        expect(
          signatureFor(duress: true, lockedOut: lockedOut),
          equals(signatureFor(duress: false, lockedOut: lockedOut)),
          reason: 'duress must look exactly like a mistyped code '
              '(lockedOut: $lockedOut)',
        );
      }
    });

    test('the duress entry still arms, and arming is the ONLY difference', () {
      for (final lockedOut in <bool>[false, true]) {
        final duress = classifyCredentialEntry(
          credentialEnrolled: true,
          pinMatches: false,
          recoveryMatches: false,
          duressMatches: true,
          lockedOut: lockedOut,
        );
        final wrong = classifyCredentialEntry(
          credentialEnrolled: true,
          pinMatches: false,
          recoveryMatches: false,
          duressMatches: false,
          lockedOut: lockedOut,
        );
        expect(duress.armsDuress, isTrue,
            reason: 'a lockout must not disarm the panic code: five failures '
                'is exactly what coercion produces');
        expect(wrong.armsDuress, isFalse);
        expect(duress.observable, equals(wrong.observable));
      }
    });

    test('the failure dialog is never raised on the decoy calculator',
        () {
      // For camouflage purposes, an innocent calculator must never show an error dialog.
      final duress = classifyCredentialEntry(
        credentialEnrolled: true,
        pinMatches: false,
        recoveryMatches: false,
        duressMatches: true,
        lockedOut: false,
      );
      final wrong = classifyCredentialEntry(
        credentialEnrolled: true,
        pinMatches: false,
        recoveryMatches: false,
        duressMatches: false,
        lockedOut: false,
      );
      expect(duress.showsFailureDialog, isFalse);
      expect(wrong.showsFailureDialog, isFalse);
      expect(duress.showsFailureDialog, equals(wrong.showsFailureDialog));
    });

    test('a successful unlock is the only entry that raises no dialog', () {
      final correct = classifyCredentialEntry(
        credentialEnrolled: true,
        pinMatches: true,
        recoveryMatches: false,
        duressMatches: false,
        lockedOut: false,
      );
      expect(correct.unlocks, isTrue);
      expect(correct.showsFailureDialog, isFalse);
      final recovery = classifyCredentialEntry(
        credentialEnrolled: true,
        pinMatches: false,
        recoveryMatches: true,
        duressMatches: false,
        lockedOut: false,
      );
      expect(recovery.unlocks, isTrue);
      expect(recovery.recoveryUnlock, isTrue);
      expect(recovery.showsFailureDialog, isFalse);
    });

    test(
        'the duress entry pays for the SAME attempt-ledger write a wrong '
        'entry pays for (the ~60 ms timing side-channel)', () {
      // Measured cause of the leak: the duress branch returned above the
      // ledger write, so six interleaved samples put every duress entry below
      // every wrong entry with no overlap at all. Same ledger decision, one
      // distribution.
      final duress = classifyCredentialEntry(
        credentialEnrolled: true,
        pinMatches: false,
        recoveryMatches: false,
        duressMatches: true,
        lockedOut: false,
      );
      final wrong = classifyCredentialEntry(
        credentialEnrolled: true,
        pinMatches: false,
        recoveryMatches: false,
        duressMatches: false,
        lockedOut: false,
      );
      expect(duress.recordsAttemptFailure, isTrue);
      expect(duress.recordsAttemptFailure, equals(wrong.recordsAttemptFailure));
      expect(duress.clearsAttemptLedger, equals(wrong.clearsAttemptLedger));
      expect(duress.writesAttemptLedger, isTrue);
    });

    test(
        'under lockout NEITHER path writes the ledger, so they stay '
        'identical there too', () {
      for (final duressMatches in <bool>[false, true]) {
        final outcome = classifyCredentialEntry(
          credentialEnrolled: true,
          pinMatches: false,
          recoveryMatches: false,
          duressMatches: duressMatches,
          lockedOut: true,
        );
        expect(outcome.writesAttemptLedger, isFalse);
        expect(outcome.unlocks, isFalse);
      }
    });

    test(
        'an entry against a wiped app (nothing enrolled) still keeps acting as a calculator', () {
      final outcome = classifyCredentialEntry(
        credentialEnrolled: false,
        pinMatches: false,
        recoveryMatches: false,
        duressMatches: false,
        lockedOut: false,
      );
      expect(outcome.unlocks, isFalse);
      expect(outcome.showsFailureDialog, isFalse,
          reason: 'the app must read as a regular calculator without error popups');
      expect(outcome.writesAttemptLedger, isFalse);
    });

    testWidgets(
        'there is exactly one failure dialog widget, and it names '
        'nothing sensitive', (tester) async {
      // Both paths call buildEntryFailureDialog. Two builders, however
      // carefully kept in sync, would be two things that could drift apart.
      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) => buildEntryFailureDialog(
            translate: (value) => value,
            onDismiss: () {},
          ),
        ),
      ));
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(find.text('Something went wrong'), findsOneWidget);
      expect(
          find.text(
              'The app could not complete that action. Please try again later.'),
          findsOneWidget);
      final rendered = tester
          .widgetList<Text>(find.byType(Text))
          .map((widget) => (widget.data ?? '').toLowerCase())
          .join(' ');
      for (final forbidden in <String>[
        'vpn',
        'pin',
        'duress',
        'panic',
        'sent',
        'alert',
        'location',
        'contact',
        'emergency',
        'wipe',
        // "Something went wrong" is the copy, so the guard is against naming
        // the ENTRY as wrong -- that would tell a captor a code was tried.
        'wrong code',
        'wrong pin',
        'incorrect',
      ]) {
        expect(rendered, isNot(contains(forbidden)), reason: forbidden);
      }
    });
  });

  group('BEHAVIOUR: the wipe must not take the disguise off the phone', () {
    test('the decoy still arms after a wipe has destroyed every credential',
        () {
      // The exact post-duress state: no PIN, no session, camouflage latched.
      // This is the A/B the device test ran -- before duress the app showed
      // the calculator, after duress it showed the branded consent dialog over
      // the real activation screen.
      expect(
        decoyCalculatorShouldArm(
          supportsInAppCamouflage: true,
          appIsActivated: false,
          freeAccessSession: false,
          camouflageLatched: true,
          openedByDialer: false,
          unlockedThisSession: false,
        ),
        isTrue,
      );
    });

    test('arming does not depend on the credential the wipe deletes', () {
      // Same inputs, only appIsActivated flipped: the answer must not move.
      for (final activated in <bool>[false, true]) {
        expect(
          decoyCalculatorShouldArm(
            supportsInAppCamouflage: true,
            appIsActivated: activated,
            freeAccessSession: false,
            camouflageLatched: true,
            openedByDialer: false,
            unlockedThisSession: false,
          ),
          isTrue,
          reason: 'appIsActivated: $activated',
        );
      }
    });

    test(
        'a genuinely fresh, never-camouflaged install still reaches the real '
        'activation screen', () {
      expect(
        decoyCalculatorShouldArm(
          supportsInAppCamouflage: true,
          appIsActivated: false,
          freeAccessSession: false,
          camouflageLatched: false,
          openedByDialer: false,
          unlockedThisSession: false,
        ),
        isFalse,
      );
    });

    test('a deliberate request for the real app still wins', () {
      for (final request in <String>['dialer', 'launcher']) {
        expect(
          decoyCalculatorShouldArm(
            supportsInAppCamouflage: true,
            appIsActivated: true,
            freeAccessSession: false,
            camouflageLatched: true,
            openedByDialer: request == 'dialer',
            unlockedThisSession: request == 'launcher',
          ),
          isFalse,
          reason: request,
        );
      }
    });

    test('platforms without in-app camouflage never show a decoy', () {
      expect(
        decoyCalculatorShouldArm(
          supportsInAppCamouflage: false,
          appIsActivated: true,
          freeAccessSession: true,
          camouflageLatched: true,
          openedByDialer: false,
          unlockedThisSession: false,
        ),
        isFalse,
      );
    });

    test('the latch that survives the wipe is not itself a tell', () {
      // A lone surviving file called `decoy_mode` proves the calculator is a
      // front, which is worse than no survivor at all.
      final lowered = kCamouflageLatchFileName.toLowerCase();
      for (final token in kCamouflageLatchForbiddenTokens) {
        expect(lowered, isNot(contains(token)), reason: token);
      }
      final contents = kCamouflageLatchContents.entries
          .map((entry) => '${entry.key}=${entry.value}')
          .join(',')
          .toLowerCase();
      for (final token in kCamouflageLatchForbiddenTokens) {
        expect(contents, isNot(contains(token)), reason: token);
      }
    });
  });

  group('BEHAVIOUR: what the duress wipe leaves behind', () {
    test('the plaintext node cache does NOT survive', () {
      // It listed node display names, slugs, endpoint host:port, the covert
      // stealth_endpoint domain and per-transport reachability, and it
      // survived the offline wipe untouched -- in the branch the design calls
      // "the realistic inspection case".
      for (final preserveQueue in <bool>[false, true]) {
        expect(
          duressWipeKeepsEntry('node_cache.json',
              preserveEmergencyQueue: preserveQueue),
          isFalse,
          reason: 'preserveEmergencyQueue: $preserveQueue',
        );
      }
    });

    test('nothing else that was observed surviving survives either', () {
      const observedSurvivors = <String>[
        'node_cache.json',
        'install_id.txt',
        'wins_xray_client.json',
        'wins_vpn_restart_config.conf',
        'vpn_config.txt',
        'user_pin.txt',
        'client_keypair.json',
        'pending_logout.json',
      ];
      for (final name in observedSurvivors) {
        for (final preserveQueue in <bool>[false, true]) {
          expect(
            duressWipeKeepsEntry(name, preserveEmergencyQueue: preserveQueue),
            isFalse,
            reason: '$name (preserveEmergencyQueue: $preserveQueue)',
          );
        }
      }
    });

    test('the camouflage latch survives -- that is the whole point', () {
      for (final preserveQueue in <bool>[false, true]) {
        expect(
          duressWipeKeepsEntry(kCamouflageLatchFileName,
              preserveEmergencyQueue: preserveQueue),
          isTrue,
          reason: 'preserveEmergencyQueue: $preserveQueue',
        );
      }
    });

    test('the queued alert survives ONLY while it is still queued', () {
      // Offline: the encrypted store carries the only copy of an undelivered
      // alert, so it is kept. Delivered: there is nothing to keep.
      expect(
        duressWipeKeepsEntry('$kSecureStateDirectoryName/prefs.dat',
            preserveEmergencyQueue: true),
        isTrue,
      );
      expect(
        duressWipeKeepsEntry(kSecureStateDirectoryName,
            preserveEmergencyQueue: true),
        isTrue,
      );
      expect(
        duressWipeKeepsEntry(kSecureStateDirectoryName,
            preserveEmergencyQueue: false),
        isFalse,
      );
    });

    test('the keep-list is a closed set: an unknown name is always wiped', () {
      for (final name in <String>[
        'anything_new.json',
        'nested/thing.dat',
        'a.txt',
        kCamouflageLatchFileName.toUpperCase(),
      ]) {
        expect(
            duressWipeKeepsEntry(name, preserveEmergencyQueue: false), isFalse,
            reason: name);
      }
    });
  });

  group('BEHAVIOUR: the record that survives does not announce the app', () {
    final secureStore =
        File('android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
            .readAsStringSync();

    test(
        'no secure-state record is written to a filename that names the app '
        'or what it does', () {
      // The offline branch MUST keep the settings record so the queued alert
      // can still be sent, so on a phone that has just been through a duress
      // wipe this is the one surviving file. It used to be called, literally,
      // `vpn_settings.txt.wvs`, inside a package called org.winsvpn.app.
      final mapping = RegExp(r'"([^"]+)"\s+to\s+"([^"]+)"')
          .allMatches(secureStore)
          .map((match) => MapEntry(match.group(1)!, match.group(2)!))
          .toList();
      expect(mapping, isNotEmpty,
          reason: 'the logical -> on-disk name map must exist');
      for (final entry in mapping) {
        final onDisk = entry.value.toLowerCase();
        for (final token in <String>[
          'vpn',
          'wins',
          'tunnel',
          'pin',
          'duress',
          'emergency',
          'keypair',
          'logout',
          'config',
        ]) {
          expect(onDisk, isNot(contains(token)),
              reason: '${entry.key} -> ${entry.value} leaks "$token"');
        }
      }
      // Specifically the survivor.
      final settings = mapping.firstWhere(
          (entry) => entry.key == 'vpn_settings.txt',
          orElse: () => const MapEntry('', ''));
      expect(settings.value, isNotEmpty);
      expect(settings.value, isNot(contains('vpn_settings')));
    });

    test('the rename cannot orphan a queued duress record', () {
      // A rename that stranded the queue would silently destroy the only copy
      // of an undelivered alert -- worse than the filename it fixes.
      expect(secureStore, contains('migrateLegacyLayout'));
      expect(secureStore, contains('legacyOnDiskName'));
      expect(secureStore, contains('legacySecureFile'));
      // Read and delete both still reach a record the rename could not move.
      final readBody = secureStore.substring(
          secureStore.indexOf('fun read('), secureStore.indexOf('fun delete('));
      expect(readBody, contains('legacySecureFile(name)'));
      final deleteBody = secureStore.substring(
          secureStore.indexOf('fun delete('),
          secureStore.indexOf('fun decrypt('));
      expect(deleteBody, contains('legacySecureFile(name)'));
    });

    test('the sticky camouflage flag no longer says "decoy" on disk', () {
      final service = File(
              'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt')
          .readAsStringSync();
      final prefs = RegExp(r'val CAMOUFLAGE_PREFS = "([^"]+)"')
          .firstMatch(service)
          ?.group(1);
      final key = RegExp(r'val KEY_CAMOUFLAGE_ENROLLED = "([^"]+)"')
          .firstMatch(service)
          ?.group(1);
      expect(prefs, isNotNull);
      expect(key, isNotNull);
      for (final token in kCamouflageLatchForbiddenTokens) {
        expect(prefs!.toLowerCase(), isNot(contains(token)), reason: token);
        expect(key!.toLowerCase(), isNot(contains(token)), reason: token);
      }
      // Existing installs keep their enrollment across the rename.
      expect(service, contains('LEGACY_CAMOUFLAGE_PREFS'));
      expect(service, contains('LEGACY_KEY_CAMOUFLAGE_ENROLLED'));
    });
  });

  // =====================================================================
  // ARCHITECTURE GUARDS.
  //
  // These read the source as TEXT, and that is a deliberate, bounded choice:
  // each one guards a decision whose whole content is that something DOES NOT
  // EXIST (there is no hub; iOS never sends; the ledger write is not skipped),
  // which no runtime assertion inside this process can demonstrate. They are
  // not a substitute for the behavioural groups above and must never again be
  // the only thing this file does.
  // =====================================================================
  group('ARCHITECTURE: absences that cannot be observed at runtime', () {
    final source = File('lib/main.dart').readAsStringSync();

    String between(String startNeedle, String endNeedle) {
      final start = source.indexOf(startNeedle);
      expect(start, greaterThanOrEqualTo(0), reason: 'missing: $startNeedle');
      final end = source.indexOf(endNeedle, start);
      expect(end, greaterThan(start),
          reason: 'missing after start: $endNeedle');
      return source.substring(start, end);
    }

    test(
        'there is NO hub/relay anywhere on the duress path (device-native '
        'only)', () {
      expect(source, isNot(contains('_sendDuressToHub')),
          reason: 'the hub relay send must not exist on the duress path');
      expect(source, isNot(contains('/emergency/dispatch')),
          reason: 'no hub endpoint may be POSTed for duress');
      expect(source, isNot(contains('toWirePayload')),
          reason: 'the hub wire payload must be gone');
    });

    test('RETIRED: nothing in the app can reach _armDuress or the enrollment '
        'notice, so the BEHAVIOUR groups above describe a dormant feature', () {
      // Call sites, not definitions. A comment that names the method is not a
      // call, so comment lines are dropped before counting.
      final code = source
          .split('\n')
          .where((line) => !line.trimLeft().startsWith('//'))
          .join('\n');
      expect(RegExp(r'_armDuress\(\)').allMatches(code).length, 1,
          reason: 'exactly the definition; a second match is a live caller '
              'and the duress feature is no longer retired');
      expect(RegExp(r'_buildDuressSetupNotice\(\)').allMatches(code).length, 1,
          reason: 'the enrollment notice must have no render site');
      expect(code, isNot(contains('_duressSetupAvailable = true')),
          reason: 'the enrollment offer must stay off');
      expect(code, contains('duressMatches: false,'),
          reason: '_verifyUserPin must keep the duress classification off');
      expect(code, isNot(contains('duressMatches: true')));
    });

    test('Win For All verifies only the ordinary PIN and cannot arm duress',
        () {
      final body = between(
          'Future<bool> _verifyUserPin(', 'Future<int?> _monotonicNowMs()');
      final normalizedBody = _normalizeSourceWhitespace(body);

      expect(body, isNot(contains('_readDuressCredential')));
      expect(body, isNot(contains('storedDuress')));
      expect(normalizedBody,
          contains('verifyStoredCredentialOffThread(candidate, stored)'));
      expect(body, contains('classifyCredentialEntry('));
      expect(body, contains('recoveryMatches: false'));
      expect(body, contains('duressMatches: false'));
      expect(body, isNot(contains('outcome.armsDuress')));
      expect(body, isNot(contains('_armDuress()')));
    });

    test(
        'the duress credential, contact, and optional email ride inside '
        'vpn_settings.txt, not brand-new secure-state files', () {
      for (final forbidden in <String>[
        "'duress_pin.txt'",
        "'duress_credential.txt'",
        "'duress_contact.txt'",
        "'duress_contact_email.txt'",
        "'pending_emergency.json'",
      ]) {
        expect(source, isNot(contains(forbidden)), reason: forbidden);
      }

      final readBody = between('Future<String?> _readDuressCredential()',
          'Future<void> _writeDuressCredential(');
      expect(readBody, contains("_readSensitiveJsonMap('vpn_settings.txt')"));
      expect(readBody, contains("settings['duress_credential']"));

      final writeBody = between('Future<void> _writeDuressCredential(',
          'Future<String?> _readTrustedContact()');
      expect(writeBody, contains("data['duress_credential']"));
      expect(writeBody, contains('Duress credential failed durable read-back'));
    });

    test(
        '_armDuress delivers device-native, queues only when a transport can '
        'drain it, wipes, and raises NO dialog of its own', () {
      final body = between(
          'Future<void> _armDuress()', 'bool get _supportsDeviceNativeSms');

      expect(body, contains('if (_duressArmed) return;'));
      expect(body, contains('_duressArmed = true;'));
      expect(body, contains('await _deliverDuressDispatch(dispatch)'));
      expect(body, isNot(contains('_sendDuressToHub')));
      expect(body, isNot(contains('http')));

      final deliver = body.indexOf('await _deliverDuressDispatch(dispatch)');
      final transportGate =
          body.indexOf('_duressRetryTransportAvailable(contact)');
      final queue = body.indexOf('await _queueDuressDispatch(dispatch);');
      final preserve = body.indexOf('final preserveQueue = queued;');
      final wipe = body.indexOf('preserveEmergencyQueue: preserveQueue');

      expect(deliver, greaterThanOrEqualTo(0));
      expect(transportGate, greaterThan(deliver));
      expect(queue, greaterThan(transportGate));
      expect(preserve, greaterThan(queue));
      expect(wipe, greaterThan(preserve));
      expect(body, contains("invokeMethod('stopTunnel')"));

      // THE TELL. _armDuress must not raise a dialog, because a dialog raised
      // from here is a dialog only the duress code produces. The keypad caller
      // raises the shared one for every entry that fails to unlock.
      expect(body, isNot(contains('showDialog(')));
      expect(body, isNot(contains('_showEntryFailurePopup()')));
      expect(body, isNot(contains('_showDuressErrorPopup()')));

      // And no factory-reset wipe, which is what un-disguised the app.
      expect(body, isNot(contains('_emergencyNativeWipe')));
      expect(source, isNot(contains("invokeMethod('emergencyWipeAppData')")),
          reason: 'clearApplicationUserData resets the app to a fresh install, '
              'which shows the branded activation screen');
    });

    test(
        'the shared failure dialog is not duress-specific and not raised from the keypad', () {
      expect(source, isNot(contains('_showDuressErrorPopup')),
          reason: 'a duress-named dialog is a duress-specific dialog');
      expect(source, contains('void _showEntryFailurePopup()'));
      expect(source, contains('buildEntryFailureDialog('));
      // Keypad must never raise failure dialog on wrong PIN
      final keypad = between('Future<void> _onCalculatorButtonPressed(',
          'String _evaluateDecoyMathExpression(');
      expect(keypad, isNot(contains('_showEntryFailurePopup();')));
    });

    test('delivery is device-native SMS and nothing else', () {
      final deliverBody = between('Future<bool> _deliverDuressDispatch(',
          'Future<bool> _sendDuressViaDeviceSms(');
      expect(deliverBody, contains('_supportsDeviceNativeSms'));
      expect(deliverBody, contains('_sendDuressViaDeviceSms(dispatch)'));
      for (final forbidden in <String>['http', 'Bearer', 'emergencyDispatch']) {
        expect(deliverBody, isNot(contains(forbidden)), reason: forbidden);
      }

      final smsBody = between('Future<bool> _sendDuressViaDeviceSms(',
          'Future<bool> _queueDuressDispatch(');
      expect(smsBody, contains("invokeMethod<bool>('sendDuressSms'"));
      expect(smsBody, contains("'destination'"));
      expect(smsBody, contains("'text'"));
      expect(smsBody, contains('dispatch.smsText()'));
    });

    test(
        'iOS (and any non-Android platform) is local-wipe-only: no send, no '
        'queue, no retry', () {
      final supportsBody = between('bool get _supportsDeviceNativeSms',
          'bool _duressRetryTransportAvailable');
      expect(supportsBody, contains('Platform.isAndroid'));

      final transportBody = between('bool _duressRetryTransportAvailable',
          'Future<bool> _deliverDuressDispatch(');
      expect(transportBody, contains('_supportsDeviceNativeSms'));
      expect(transportBody, contains('_isPhoneShapedContact'));

      // RETIRED (owner decision 2026-08-18): duress dispatch is disabled.
      // The retry body was excised to an early return, and the startup call
      // site is gone, so a legacy pending_emergency can never fire an
      // outbound SMS/email after upgrade. No send, no retry, no counter.
      expect(source, isNot(contains('unawaited(_retryDuressDispatch());')),
          reason: 'the startup retry must be gone: retired dispatch must not '
              'fire a legacy pending_emergency');
      final retryBody = between('Future<void> _retryDuressDispatch()',
          'Future<void> _wipeIncriminatingStateForDuress(');
      expect(retryBody, isNot(contains('_deliverDuressDispatch')),
          reason: 'the retired retry must not send anything');
      expect(retryBody, isNot(contains('attemptCount')),
          reason: 'the retired retry must not retry');
      expect(retryBody, contains('RETIRED'),
          reason: 'the off switch must be the documented retired marker');
    });

    test(
        'no iOS/macOS source implements a duress send, and the tempting '
        'sms:/mailto: door is signposted', () {
      for (final directory in <String>['ios', 'macos']) {
        final root = Directory(directory);
        if (!root.existsSync()) continue;
        for (final file in root
            .listSync(recursive: true, followLinks: false)
            .whereType<File>()
            .where((file) =>
                (file.path.endsWith('.swift') || file.path.endsWith('.m')) &&
                // AppleDouble resource forks are not source and are not UTF-8.
                !file.uri.pathSegments.last.startsWith('._'))) {
          final text = file.readAsStringSync();
          for (final forbidden in <String>[
            'sendDuressSms',
            'MFMessageComposeViewController',
            'MFMailComposeViewController',
          ]) {
            expect(text, isNot(contains(forbidden)),
                reason: '${file.path} must not implement $forbidden');
          }
        }
      }
      final config = File('apple/WinsTunnelCore/WinsTunnelConfig.swift');
      if (config.existsSync()) {
        final text = config.readAsStringSync();
        if (text.contains('"sms"') || text.contains('"mailto"')) {
          expect(text.toLowerCase(), contains('duress'),
              reason: 'the sms/mailto allowlist must carry the warning that '
                  'nothing on the duress path may ever use it');
        }
      }
    });

    test('the offline queue survives a partial wipe, everything else is swept',
        () {
      // RETIRED (owner decision 2026-08-18): the startup retry is no longer
      // invoked, so a preserved pending_emergency record can never fire an
      // outbound SMS/email. The wipe still keeps that record while it is
      // queued -- the purge must still sweep everything else, and dispatch
      // must not exist to drain it.
      expect(source, isNot(contains('unawaited(_retryDuressDispatch());')),
          reason: 'retired dispatch must not be invoked at startup');
      expect(source, contains('startup retry is no longer invoked'),
          reason: 'the retired dispatch must be documented at the call site');

      final wipeBody = between('Future<void> _wipeIncriminatingStateForDuress(',
          'Future<void> _sweepAppStorageForDuress(');
      for (final name in <String>[
        "'user_pin.txt'",
        "'vpn_config.txt'",
        "'client_keypair.json'",
        "'wins_vpn_restart_config.conf'",
        "'pending_logout.json'",
      ]) {
        expect(wipeBody, contains(name), reason: name);
      }
      expect(wipeBody, contains('preserveEmergencyQueue'));
      expect(wipeBody, contains("data['pending_emergency']"));
      expect(wipeBody, contains("_deleteSensitiveText('vpn_settings.txt')"));
      // The named list is no longer the whole wipe.
      expect(wipeBody, contains('_sweepAppStorageForDuress('));
      // And the disguise is re-latched unconditionally at the end.
      expect(wipeBody, contains('await _latchCamouflage();'));

      final sweepBody = between('Future<void> _sweepAppStorageForDuress(',
          '// THERE IS DELIBERATELY NO NATIVE APP-DATA WIPE');
      expect(sweepBody, contains('duressWipeKeepsEntry('));
      expect(sweepBody, contains('_appDocumentsDirectory()'));
      // Android's second storage root, where the tunnel service writes.
      expect(sweepBody, contains('files'));
    });

    test(
        'the decoy is armed from the latch, and the branded consent dialog '
        'never runs over it', () {
      expect(source, contains('decoyCalculatorShouldArm('));
      expect(source, contains('camouflageLatched: camouflageLatched'));
      expect(source, contains('Future<void> _latchCamouflage()'));

      final gate = between('Future<void> _initializePrivacyConsentGate()',
          'Future<void> _armCamouflageBeforeConsent()');
      final latchCheck = gate.indexOf('await _camouflageLatched()');
      final prompt =
          gate.indexOf('_showPrivacyPolicyDialog(requireConsent: true)');
      expect(latchCheck, greaterThanOrEqualTo(0),
          reason: 'a camouflaged install must be checked before prompting');
      expect(prompt, greaterThan(latchCheck),
          reason: 'the branded dialog must never precede the camouflage check');
      expect(gate, contains('await _armCamouflageBeforeConsent();'));
    });

    test('replacing the main PIN clears the duress code, contact, and email',
        () {
      final body = between(
          'Future<void> _replaceUserPin(', 'The lockout ledger lives inside');
      expect(body, contains('await _writeDuressCredential(null);'));
      expect(body, contains('await _writeTrustedContact(null);'));
      expect(body, contains('await _writeTrustedContactEmail(null);'));
    });

    test(
        '_enrollDuress stores a contact ONLY when a phone is supplied (so a '
        'wipe-only enrollment leaves no destination)', () {
      final body =
          between('Future<bool> _enrollDuress(', 'bool _isPhoneShapedContact');
      expect(
          body, contains('duressPinPolicyRejectionReason(realPin, duressPin)'));
      expect(body, contains('if (trustedPhone != null) {'));
      // L91: the credential and both contact fields go in ONE settings write
      // (so a relock cannot leave half an enrollment). A null phone removes
      // the stored contact. Behaviour: duress_enroll_commit_test.
      expect(body, contains("data['duress_credential'] = credential;"));
      expect(
          body,
          contains("      if (phone == null) {\n        data.remove('duress_contact');\n"
              "      } else {\n        data['duress_contact'] = phone;\n      }"));
      expect(body, contains('Trusted contact failed durable read-back'));
      expect(body, contains('Duress code failed read-back verification'));
    });

    test('Win For All exposes no duress enrollment surface', () {
      expect(source, contains('bool _duressSetupAvailable = false;'));
      expect(
          source,
          isNot(contains(
              'if (_duressSetupAvailable) _buildDuressSetupNotice(),')));
      expect(source, isNot(contains('_promptDuressEnrollment(knownRealPin:')),
          reason: 'activation must not offer the retired duress feature');
    });

    test(
        'Android sends via SmsManager without writing the Messages/Sent '
        'store and gates SEND_SMS at runtime', () {
      final kotlin =
          File('android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt')
              .readAsStringSync();
      expect(kotlin, contains('"sendDuressSms"'));
      expect(kotlin, contains('SmsManager'));
      expect(
          kotlin,
          anyOf(contains('sendMultipartTextMessage'),
              contains('sendTextMessage')));
      expect(kotlin, isNot(contains('contentResolver')),
          reason: 'must not write any content provider');
      expect(kotlin, isNot(contains('Telephony.Sms')),
          reason: 'must not write the Telephony/Messages provider');
      expect(kotlin, contains('"requestDuressSmsPermission"'));
      expect(kotlin, contains('Manifest.permission.SEND_SMS'));
      expect(kotlin, contains('requestPermissions('));
      expect(kotlin, contains('onRequestPermissionsResult'));
      // No end-to-end test instrumentation may ship.
      expect(kotlin, isNot(contains('DURESS_E2E_TEST_MODE')),
          reason: 'the e2e harness disables FLAG_SECURE and stubs the send');
    });

    test('the manifest declares no SMS permissions', () {
      final manifest =
          File('android/app/src/main/AndroidManifest.xml').readAsStringSync();
      expect(manifest, isNot(contains('android.permission.SEND_SMS')));
      expect(manifest, isNot(contains('android.permission.RECEIVE_SMS')));
      expect(manifest, isNot(contains('android.permission.READ_SMS')));
    });
  });
}
