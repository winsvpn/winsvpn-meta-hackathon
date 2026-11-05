// The duress COMMIT (main.dart _enrollDuress) and the settings write it goes
// through (_mutateVpnRuntimeSettings), both run verbatim, with the sensitive
// store faked at its read and write calls. Rule: a flow
// whose dialog a relock removed never commits, down to the write. The
// encoding and the settings write's own queued read are held, the app
// relocks (the dialog's stillAway turns false), the await is released, and
// nothing may be written: not the credential, not the contact, not a no-op
// rewrite. The three fields go in one settings write, so no relock can land
// between them.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

void main() {
  late Directory temporary;
  late File executable;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final enroll = _between(
        source,
        '  /// Returns true when enrolled. Returns false, having written NOTHING,',
        '  /// Mirrors the hub\'s `EMERGENCY_PHONE_RE`');
    final mutate = _between(
        source,
        '  /// [skipWriteWhen], evaluated after [mutation] ran, lets a caller whose',
        '  Future<void> _writeVpnRuntimeSetting(String key, Object? value) async {');
    final dispatch = File('lib/duress_dispatch.dart').absolute.uri;
    temporary = await Directory.systemTemp.createTemp('l91-duress-commit-');
    executable = File('${temporary.path}/commit.dart');
    await executable.writeAsString('''
import 'dart:async';
import 'dart:convert';
import '$dispatch';

// The setup policy is local_security.dart's (a Flutter import); the codes
// used here pass it, and the harness only needs it to answer "no objection".
String? duressPinPolicyRejectionReason(String realPin, String duressPin) => null;

class FakeCodec {
  Completer<void>? encodeGate;
  Future<String> encode(String pin) async {
    if (encodeGate != null) await encodeGate!.future;
    return 'enc(\$pin)';
  }
  Future<bool> verifyStoredCredential(String pin, String stored) async =>
      stored == 'enc(\$pin)';
}

class Epoch {
  int current = 0;
  bool isCurrent(int epoch) => epoch == current;
}

class H {
  // vpn_settings.txt as the sensitive store holds it.
  String? file;
  Map<String, dynamic> get storage =>
      file == null ? <String, dynamic>{} : Map<String, dynamic>.from(jsonDecode(file!) as Map);
  final _pinCredentialCodec = FakeCodec();
  bool away = true;
  // Calls of the production writer: the number the rule is about.
  int writes = 0;
  final List<Map<String, dynamic>> snapshots = <Map<String, dynamic>>[];
  // The settings write's own awaited read, held.
  Completer<void>? readGate;
  Future<void> _settingsMutationQueue = Future<void>.value();
  bool _settingsWritesSealed = false;
  final _accountSessionEpoch = Epoch();
  int reads = 0;
  Future<Map<String, dynamic>> _readSensitiveJsonMap(String name) async {
    reads++;
    if (readGate != null) await readGate!.future;
    return storage;
  }
  Future<void> _writeSensitiveText(String name, String text) async {
    writes++;
    file = text;
    snapshots.add(storage);
  }
  Future<void> _deleteSensitiveText(String name) async => file = null;
  bool _isPhoneShapedContact(String c) => c.replaceAll(RegExp(r'\\D'), '').length >= 7;
  Future<String?> _readDuressCredential() async =>
      storage['duress_credential'] as String?;
  Future<String?> _readTrustedContact() async =>
      storage['duress_contact'] as String?;

$mutate
$enroll
}

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

bool noDuressKeys(Map<String, dynamic> s) =>
    !s.keys.any((k) => k.startsWith('duress_'));

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final h = H();
  bool stillAway() => h.away;
  switch (scenario) {
    case 'control_sms':
      final ok = await h._enrollDuress(realPin: '482915', duressPin: '739264',
          trustedPhone: '+1 555 010 2030', trustedEmail: 'a@b.example',
          stillAway: stillAway);
      check(ok, 'control did not enroll');
      check(h.storage['duress_credential'] == 'enc(739264)' &&
              h.storage['duress_contact'] == '+1 555 010 2030' &&
              h.storage['duress_contact_email'] == 'a@b.example',
          'control stored \${h.storage}');
      check(h.writes == 1, 'the enrollment took \${h.writes} writes, not one');
    case 'control_wipe_clears_prior_contact':
      h.file = jsonEncode(<String, dynamic>{
        'duress_contact': '+1 555 999 0000',
        'duress_contact_email': 'old@b.example',
      });
      final ok = await h._enrollDuress(realPin: '482915', duressPin: '739264',
          stillAway: stillAway);
      check(ok && h.storage['duress_credential'] == 'enc(739264)', 'not enrolled');
      check(!h.storage.containsKey('duress_contact') &&
              !h.storage.containsKey('duress_contact_email'),
          'a wipe-only enrollment left a destination: \${h.storage}');
    case 'relock_during_encode':
      // Sol: hold the encode, relock, release it: zero writes.
      h._pinCredentialCodec.encodeGate = Completer<void>();
      final pending = h._enrollDuress(realPin: '482915', duressPin: '739264',
          trustedPhone: '+1 555 010 2030', stillAway: stillAway);
      await Future<void>.delayed(Duration.zero);
      h.away = false; // the relock
      h._pinCredentialCodec.encodeGate!.complete();
      final ok = await pending;
      check(!ok, 'reported enrolled after the relock');
      check(h.writes == 0, 'wrote \${h.writes} time(s) behind the calculator');
      check(noDuressKeys(h.storage), 'stored \${h.storage}');
      // It stops at the encode: the settings write is not even entered (no
      // settings read behind the calculator either).
      check(h.reads == 0, 'the settings write was entered after the relock');
    case 'relock_inside_write':
      // Sol, Turn 9: hold the settings read, relock, release it. The
      // mutation declines, and the production writer is never called.
      h.readGate = Completer<void>();
      final pending = h._enrollDuress(realPin: '482915', duressPin: '739264',
          trustedPhone: '+1 555 010 2030', trustedEmail: 'a@b.example',
          stillAway: stillAway);
      for (var i = 0; i < 5; i++) {
        await Future<void>.delayed(Duration.zero);
      }
      check(h.writes == 0, 'precondition: nothing written before the read');
      h.away = false; // the relock
      h.readGate!.complete();
      final ok = await pending;
      check(!ok, 'reported enrolled after the relock');
      check(h.writes == 0,
          'the writer was called \${h.writes} time(s) behind the calculator');
      check(h.file == null && noDuressKeys(h.storage), 'stored \${h.storage}');
    case 'other_callers_still_write':
      // Every other caller keeps the unconditional write, even when its
      // mutation changes nothing.
      await h._mutateVpnRuntimeSettings((data) {});
      check(h.writes == 1, 'a caller without skipWriteWhen lost its write');
    case 'one_write_no_half_enrollment':
      // Every field lands in one write: no state exists in which the
      // credential is stored without its contact, or the reverse.
      final ok = await h._enrollDuress(realPin: '482915', duressPin: '739264',
          trustedPhone: '+1 555 010 2030', trustedEmail: 'a@b.example',
          stillAway: stillAway);
      check(ok && h.snapshots.length == 1, 'not a single write: \${h.snapshots}');
      final only = h.snapshots.single;
      check(only.containsKey('duress_credential') &&
              only.containsKey('duress_contact') &&
              only.containsKey('duress_contact_email'),
          'the one write lacks a field: \$only');
    case 'relock_after_the_write':
      // The boundary: a relock after the write was made (while unlocked)
      // does not unmake it; the dialog then pops nothing.
      final ok = await h._enrollDuress(realPin: '482915', duressPin: '739264',
          stillAway: stillAway);
      h.away = false;
      check(ok && h.storage['duress_credential'] == 'enc(739264)',
          'a completed enrollment was lost');
  }
  print('PASS \$scenario');
}
''');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'control_sms',
    'control_wipe_clears_prior_contact',
    'relock_during_encode',
    'relock_inside_write',
    'one_write_no_half_enrollment',
    'other_callers_still_write',
    'relock_after_the_write',
  ]) {
    test('duress commit: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }

  test('main.dart hands the dialog\'s relock check to the commit', () {
    final dialog = File('lib/duress_enrollment_dialog.dart').readAsStringSync();
    expect(dialog, contains('          stillAway: hooks.stillAway,\n'));
    expect(dialog, contains('        if (!enrolled) return null;'));
  });
}
