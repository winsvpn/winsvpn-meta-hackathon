import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart';
import 'package:wins_vpn/local_security.dart';

/// Rebuilds a credential exactly as builds before the 6-digit change wrote
/// it: same format tag and PBKDF2 parameters, 4-digit PIN, and no `digits`
/// field. The codec can no longer produce one (it refuses to enroll at the
/// legacy length), so the migration contract has to be pinned against a
/// hand-built artifact rather than against the encoder's current output.
Future<String> _legacyCredentialAsWrittenBeforeTheLengthChange({
  required String pin,
  required List<int> salt,
  required int iterations,
}) async {
  final algorithm = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: iterations,
    bits: 256,
  );
  final key = await algorithm.deriveKey(
    secretKey: SecretKey(utf8.encode(pin)),
    nonce: salt,
  );
  return jsonEncode({
    'format': PinCredentialCodec.format,
    'iterations': iterations,
    'salt': base64Encode(salt),
    'hash': base64Encode(await key.extractBytes()),
  });
}

void main() {
  group('PIN credential codec', () {
    final codec = PinCredentialCodec(iterations: 10000);
    final salt = List<int>.generate(16, (index) => index);

    test('accepts the correct PIN and rejects an incorrect PIN', () async {
      final encoded = await codec.encode('042073', salt: salt);

      expect(await codec.verify('042073', encoded), isTrue);
      expect(await codec.verify('042074', encoded), isFalse);
    });

    test('does not store the PIN in plaintext', () async {
      final encoded = await codec.encode('730914', salt: salt);
      final decoded = jsonDecode(encoded) as Map<String, dynamic>;

      expect(encoded.contains('"730914"'), isFalse);
      expect(decoded.values.contains('730914'), isFalse);
      expect(decoded['format'], PinCredentialCodec.format);
      expect(base64Decode(decoded['hash'] as String), hasLength(32));
    });

    test('preserves and verifies a saved PIN with a leading zero', () async {
      final encoded = await codec.encode('004917', salt: salt);

      expect(await codec.verifyStoredCredential('004917', encoded), isTrue);
      expect(await codec.verifyStoredCredential('004918', encoded), isFalse);
    });

    test('accepts legacy plaintext PINs so they can be migrated', () async {
      expect(codec.isLegacyPlaintextCredential('0000\n'), isTrue);
      expect(await codec.verifyStoredCredential('0000', '0000\n'), isTrue);
      expect(await codec.verifyStoredCredential('0001', '0000\n'), isFalse);
    });

    test('rejects malformed credentials and malformed PINs', () async {
      expect(await codec.verify('730914', 'not-json'), isFalse);
      expect(await codec.verify('000', '{}'), isFalse);
      await expectLater(
        codec.encode('abcdef', salt: salt),
        throwsA(isA<FormatException>()),
      );
    });

    test('enrolls only at the current length, never the legacy length',
        () async {
      await expectLater(
        codec.encode('0420', salt: salt),
        throwsA(isA<FormatException>()),
      );
      await expectLater(
        codec.encode('04207315', salt: salt),
        throwsA(isA<FormatException>()),
      );
    });

    test('refuses to enroll a trivially guessable code', () async {
      for (final weak in <String>['000000', '123456', '111111', '121212']) {
        await expectLater(
          codec.encode(weak, salt: salt),
          throwsA(isA<FormatException>()),
          reason: '$weak must not be enrollable',
        );
      }
    });

    // The migration contract. An install that predates the 6-digit change
    // holds a credential with no recorded length; it must keep unlocking
    // with 4 digits, or the entire existing fleet is locked out.
    test('a stored credential written before the length change still verifies '
        'with its original 4 digits', () async {
      final legacyEncoded =
          await _legacyCredentialAsWrittenBeforeTheLengthChange(
        pin: '0420',
        salt: salt,
        iterations: 10000,
      );

      expect(PinCredentialCodec.storedPinLength(legacyEncoded),
          kLegacyCamouflagePinLength);
      expect(await codec.verifyStoredCredential('0420', legacyEncoded), isTrue);
      expect(await codec.verifyStoredCredential('0421', legacyEncoded), isFalse);
    });

    test('a credential enrolled now records the current length', () async {
      final encoded = await codec.encode('730914', salt: salt);
      expect(PinCredentialCodec.storedPinLength(encoded), kCamouflagePinLength);
      // A candidate of the wrong length never matches, so the keypad can
      // present exactly one candidate per attempt.
      expect(await codec.verifyStoredCredential('7309', encoded), isFalse);
    });

    test('storedPinLength reads legacy plaintext as the legacy length', () {
      expect(PinCredentialCodec.storedPinLength('0000'),
          kLegacyCamouflagePinLength);
      expect(PinCredentialCodec.storedPinLength('not-json'),
          kLegacyCamouflagePinLength);
    });
  });

  group('offline recovery code', () {
    final codec = PinCredentialCodec(iterations: 10000);
    final salt = List<int>.generate(16, (index) => index);

    test('generates the configured number of digits, from a secure source',
        () {
      final codes = <String>{};
      for (var run = 0; run < 200; run++) {
        final code = PinCredentialCodec.generateRecoveryCode();
        expect(code, matches(RegExp('^\\d{$kRecoveryCodeLength}\$')));
        codes.add(code);
      }
      // 200 draws from 10^16 colliding would mean the generator is not
      // random; this is a smoke check on the source, not a statistical test.
      expect(codes, hasLength(200));
    });

    test('verifies the issued code and rejects a near miss', () async {
      final code = PinCredentialCodec.generateRecoveryCode();
      final encoded = await codec.encodeRecoveryCode(code, salt: salt);

      expect(await codec.verifyRecoveryCode(code, encoded), isTrue);

      final lastDigit = int.parse(code[code.length - 1]);
      final nearMiss = code.substring(0, code.length - 1) +
          ((lastDigit + 1) % 10).toString();
      expect(await codec.verifyRecoveryCode(nearMiss, encoded), isFalse);
    });

    test('never stores the code in plaintext', () async {
      final code = PinCredentialCodec.generateRecoveryCode();
      final encoded = await codec.encodeRecoveryCode(code, salt: salt);

      expect(encoded.contains(code), isFalse);
      final decoded = jsonDecode(encoded) as Map<String, dynamic>;
      expect(decoded.values.contains(code), isFalse);
      expect(base64Decode(decoded['hash'] as String), hasLength(32));
    });

    test('rejects anything that is not exactly the right number of digits',
        () async {
      await expectLater(
        codec.encodeRecoveryCode('123', salt: salt),
        throwsA(isA<FormatException>()),
      );
      await expectLater(
        codec.encodeRecoveryCode('a' * kRecoveryCodeLength, salt: salt),
        throwsA(isA<FormatException>()),
      );
    });

    // The two credentials live in the same store and are fed the same
    // candidate. Neither envelope may ever be accepted by the other path.
    test('a PIN envelope and a recovery envelope are not interchangeable',
        () async {
      final pinEnvelope = await codec.encode('730914', salt: salt);
      final code = PinCredentialCodec.generateRecoveryCode();
      final recoveryEnvelope = await codec.encodeRecoveryCode(code, salt: salt);

      expect(await codec.verifyRecoveryCode(code, pinEnvelope), isFalse);
      expect(await codec.verify('730914', recoveryEnvelope), isFalse);
      expect(await codec.verifyStoredCredential('730914', recoveryEnvelope),
          isFalse);
    });

    test('the off-thread path agrees with the on-thread path', () async {
      final code = PinCredentialCodec.generateRecoveryCode();
      final encoded = await codec.encodeRecoveryCode(code, salt: salt);

      expect(await codec.verifyRecoveryCodeOffThread(code, encoded), isTrue);
      expect(
        await codec.verifyRecoveryCodeOffThread(
            PinCredentialCodec.generateRecoveryCode(), encoded),
        isFalse,
      );
    });

    test('display grouping is cosmetic and never fed back to verification',
        () async {
      final code = PinCredentialCodec.generateRecoveryCode();
      final shown = PinCredentialCodec.formatRecoveryCodeForDisplay(code);
      final encoded = await codec.encodeRecoveryCode(code, salt: salt);

      expect(shown.replaceAll(' ', ''), code);
      expect(shown, contains(' '));
      expect(await codec.verifyRecoveryCode(shown, encoded), isFalse);
      expect(await codec.verifyRecoveryCode(code, encoded), isTrue);
    });
  });

  group('trivial PIN policy', () {
    test('refuses repeats, counting sequences, and repeating patterns', () {
      const refused = <String>[
        '0000', '1111', '1234', '4321', '7890', '3210', '1212', '2468', '1357',
        '000000', '111111', '123456', '654321', '121212', '123123', '112233',
        '111222', '147258', '098765',
      ];
      for (final pin in refused) {
        expect(isTriviallyGuessablePin(pin), isTrue, reason: pin);
      }
    });

    test('allows ordinary non-patterned codes', () {
      const allowed = <String>[
        '730914', '042073', '830472', '004917', '619283', '507318',
      ];
      for (final pin in allowed) {
        expect(isTriviallyGuessablePin(pin), isFalse, reason: pin);
        expect(pinPolicyRejectionReason(pin), isNull, reason: pin);
      }
    });

    test('the rejection message never reveals what the app is', () {
      final message = pinPolicyRejectionReason('123456');
      expect(message, isNotNull);
      final lowered = message!.toLowerCase();
      for (final word in <String>[
        'vpn', 'tunnel', 'proxy', 'censor', 'server', 'wins', 'camouflage',
        'decoy', 'calculator', 'secure', 'privacy',
      ]) {
        expect(lowered, isNot(contains(word)), reason: word);
      }
    });

    test('length is reported before weakness so a half-typed code is not '
        'told it is weak', () {
      expect(pinPolicyRejectionReason('1234'), isNot(weakPinRejectionMessage));
      expect(pinPolicyRejectionReason('1234'), isNotNull);
      expect(pinPolicyRejectionReason('123456'), weakPinRejectionMessage);
    });
  });

  group('PinAttemptState', () {
    test('does not lock out below the failure threshold', () {
      var gate = const PinAttemptState();
      final now = DateTime.utc(2026, 1, 1);
      for (var i = 0; i < PinAttemptState.lockoutThreshold - 1; i++) {
        gate = gate.nextFailure(nowUtc: now);
        expect(gate.isLockedAt(now), isFalse);
      }
      expect(gate.failureCount, PinAttemptState.lockoutThreshold - 1);
      expect(gate.lockedUntilUtc, isNull);
    });

    test('locks out at the threshold with an exponentially increasing delay',
        () {
      var gate = const PinAttemptState();
      final now = DateTime.utc(2026, 1, 1);
      for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
        gate = gate.nextFailure(nowUtc: now);
      }
      expect(gate.isLockedAt(now), isTrue);
      final firstDelay = gate.lockedUntilUtc!.difference(now);
      expect(firstDelay, const Duration(seconds: PinAttemptState.baseDelaySeconds));
      expect(gate.isLockedAt(now.add(firstDelay)), isFalse);
      expect(
        gate.isLockedAt(now.add(firstDelay - const Duration(seconds: 1))),
        isTrue,
      );

      final nextGate = gate.nextFailure(nowUtc: now);
      final secondDelay = nextGate.lockedUntilUtc!.difference(now);
      expect(secondDelay, firstDelay * 2);
    });

    test('delay is capped at maxDelaySeconds', () {
      var gate = const PinAttemptState();
      final now = DateTime.utc(2026, 1, 1);
      for (var i = 0; i < PinAttemptState.lockoutThreshold + 20; i++) {
        gate = gate.nextFailure(nowUtc: now);
      }
      expect(
        gate.lockedUntilUtc!.difference(now),
        const Duration(seconds: PinAttemptState.maxDelaySeconds),
      );
    });

    test('a successful attempt clears the lockout', () {
      var gate = const PinAttemptState();
      final now = DateTime.utc(2026, 1, 1);
      for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
        gate = gate.nextFailure(nowUtc: now);
      }
      expect(gate.isLockedAt(now), isTrue);
      const cleared = PinAttemptState.clear();
      expect(cleared.failureCount, 0);
      expect(cleared.isLockedAt(now), isFalse);
    });

    test('clock rollback cannot clear an active lockout', () {
      var gate = const PinAttemptState();
      final now = DateTime.utc(2026, 1, 1, 12);
      for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
        gate = gate.nextFailure(nowUtc: now);
      }
      final rolledBack = now.subtract(const Duration(days: 1));
      expect(gate.isLockedAt(rolledBack), isTrue,
          reason: 'an absolute deadline must still be in the future relative '
              'to a rolled-back clock');
    });

    test('round-trips through JSON for secure-state persistence', () {
      final now = DateTime.utc(2026, 3, 4, 5, 6, 7);
      final gate = PinAttemptState(failureCount: 7, lockedUntilUtc: now);
      final decoded = PinAttemptState.fromJson(gate.toJson());
      expect(decoded, gate);
      expect(decoded.failureCount, 7);
      expect(decoded.lockedUntilUtc, now);
    });

    test('fromJson fails open on missing or malformed input', () {
      expect(PinAttemptState.fromJson(null), const PinAttemptState());
      expect(PinAttemptState.fromJson('garbage'), const PinAttemptState());
      expect(
        PinAttemptState.fromJson(<String, dynamic>{
          'failure_count': 'not-a-number',
          'locked_until': 'not-a-date',
        }),
        const PinAttemptState(),
      );
    });

    // M-15: a local user able to advance the device wall-clock date/time
    // must not be able to shorten a lockout once a monotonic (device
    // elapsed-time-since-boot) reading is available.
    group('monotonic-clock enforcement (M-15)', () {
      test(
          'a forward wall-clock jump alone cannot lift a lockout once a '
          'monotonic deadline is recorded', () {
        var gate = const PinAttemptState();
        final writeUtc = DateTime.utc(2026, 1, 1);
        const writeMonotonicMs = 1000000;
        for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
          gate = gate.nextFailure(
            nowUtc: writeUtc,
            nowMonotonicMs: writeMonotonicMs,
          );
        }
        expect(gate.lockedUntilMonotonicMs, isNotNull);

        // Simulate a local user advancing the wall clock by a year: the
        // wall-clock-only check would (wrongly) say unlocked.
        final jumpedUtc = writeUtc.add(const Duration(days: 365));
        expect(gate.isLockedAt(jumpedUtc), isFalse,
            reason: 'demonstrates the wall-clock-only check alone is '
                'foolable, motivating the monotonic check below');

        // Real elapsed monotonic time has barely moved (a few seconds),
        // unaffected by the wall-clock change, so the monotonic check -
        // and therefore the combined enforcement main.dart uses - must
        // still report locked.
        final barelyElapsedMonotonicMs = writeMonotonicMs + 2000;
        expect(gate.isLockedAtMonotonic(barelyElapsedMonotonicMs), isTrue);
        expect(
          gate.isLockedGivenClocks(
            nowUtc: jumpedUtc,
            nowMonotonicMs: barelyElapsedMonotonicMs,
          ),
          isTrue,
        );
      });

      test('a legacy entry with no monotonic reading falls back to the '
          'wall-clock check alone', () {
        var gate = const PinAttemptState();
        final now = DateTime.utc(2026, 1, 1);
        for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
          gate = gate.nextFailure(nowUtc: now);
        }
        expect(gate.lockedUntilMonotonicMs, isNull);
        expect(gate.isLockedGivenClocks(nowUtc: now), isTrue);
        expect(
          gate.isLockedGivenClocks(
            nowUtc: now.add(const Duration(minutes: 10)),
          ),
          isFalse,
        );
      });

      test('isMonotonicRollback only fires when an active monotonic '
          'lockout exists and the clock is behind its last reading', () {
        const belowThreshold = PinAttemptState(
          failureCount: 1,
          lastSeenMonotonicMs: 500000,
        );
        expect(belowThreshold.isMonotonicRollback(1000), isFalse,
            reason: 'no active lockout to protect, so a normal reboot must '
                'not be treated as a rollback attack');

        var locked = const PinAttemptState();
        for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
          locked = locked.nextFailure(
            nowUtc: DateTime.utc(2026, 1, 1),
            nowMonotonicMs: 500000,
          );
        }
        expect(locked.isMonotonicRollback(1000), isTrue,
            reason: 'the monotonic clock went backwards while an active '
                'lockout existed, which only happens on reboot');
        expect(locked.isMonotonicRollback(600000), isFalse,
            reason: 'forward-moving monotonic time is not a rollback');
      });

      test(
          'a reboot/monotonic rollback re-arms a fresh delay instead of '
          'clearing the penalty', () {
        var gate = const PinAttemptState();
        for (var i = 0; i < PinAttemptState.lockoutThreshold; i++) {
          gate = gate.nextFailure(
            nowUtc: DateTime.utc(2026, 1, 1),
            nowMonotonicMs: 10000000,
          );
        }
        final failureCountBeforeReboot = gate.failureCount;
        final utcDeadlineBeforeReboot = gate.lockedUntilUtc;

        // Device reboot: monotonic clock resets close to zero.
        const postRebootMonotonicMs = 500;
        expect(gate.isMonotonicRollback(postRebootMonotonicMs), isTrue);
        final rearmed = gate.rearmAfterMonotonicRollback(postRebootMonotonicMs);

        // Never auto-cleared: still locked immediately after the rearm.
        expect(rearmed.isLockedAtMonotonic(postRebootMonotonicMs), isTrue);
        // The failure count and UTC deadline (kept for display) survive
        // the rearm unchanged - only the monotonic anchor moves.
        expect(rearmed.failureCount, failureCountBeforeReboot);
        expect(rearmed.lockedUntilUtc, utcDeadlineBeforeReboot);
        // A fresh, bounded delay was imposed from the new epoch, not an
        // unbounded or zero one.
        expect(
          rearmed.lockedUntilMonotonicMs! - postRebootMonotonicMs,
          PinAttemptState.maxDelaySeconds * 1000,
        );
        // The new reading becomes the anchor for the next rollback check.
        expect(rearmed.lastSeenMonotonicMs, postRebootMonotonicMs);
        expect(rearmed.isMonotonicRollback(600), isFalse);
      });

      test('monotonic and UTC fields round-trip through JSON', () {
        final gate = PinAttemptState(
          failureCount: 6,
          lockedUntilUtc: DateTime.utc(2026, 3, 4, 5, 6, 7),
          lockedUntilMonotonicMs: 123456789,
          lastSeenMonotonicMs: 123450000,
        );
        final decoded = PinAttemptState.fromJson(gate.toJson());
        expect(decoded, gate);
        expect(decoded.lockedUntilMonotonicMs, 123456789);
        expect(decoded.lastSeenMonotonicMs, 123450000);
      });

      test('fromJson tolerates a persisted ledger with no monotonic fields '
          'at all (pre-fix installs)', () {
        final decoded = PinAttemptState.fromJson(<String, dynamic>{
          'failure_count': 5,
          'locked_until': DateTime.utc(2026, 1, 1).toIso8601String(),
        });
        expect(decoded.failureCount, 5);
        expect(decoded.lockedUntilMonotonicMs, isNull);
        expect(decoded.lastSeenMonotonicMs, isNull);
      });
    });
  });

  test('PinReenrollmentRequired carries a re-activation message', () {
    const error = PinReenrollmentRequired();
    expect(error, isA<Exception>());
    expect(error.message, contains('re-activate'));
    expect(error.toString(), contains('PinReenrollmentRequired'));
  });

  group('validatedHttpsUrl', () {
    test('accepts a plain https URL', () {
      final uri = validatedHttpsUrl('https://winsvpn.org/pay/one_month');
      expect(uri.scheme, 'https');
      expect(uri.host, 'winsvpn.org');
    });

    test('accepts an https URL with a query string', () {
      final uri =
          validatedHttpsUrl('https://sync.winsvpn.org/pay/one_month?src=app');
      expect(uri.queryParameters['src'], 'app');
    });

    test('trims surrounding whitespace before validating', () {
      final uri = validatedHttpsUrl('  https://winsvpn.org  ');
      expect(uri.host, 'winsvpn.org');
    });

    test('rejects cleartext HTTP', () {
      expect(
        () => validatedHttpsUrl('http://winsvpn.org'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects credential-bearing URLs', () {
      expect(
        () => validatedHttpsUrl('https://user:pass@winsvpn.org'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects file/data/javascript and unexpected custom schemes', () {
      for (final raw in <String>[
        'file:///etc/passwd',
        'data:text/html,<script>alert(1)</script>',
        'javascript:alert(1)',
        'ftp://winsvpn.org',
        'twitter://user?screen_name=winsvpninc',
      ]) {
        expect(
          () => validatedHttpsUrl(raw),
          throwsA(isA<FormatException>()),
          reason: raw,
        );
      }
    });

    test('rejects malformed URLs with no host', () {
      expect(
        () => validatedHttpsUrl('https:///no-host-here'),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => validatedHttpsUrl('not a url'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('validatedPaymentUrl (APP-12)', () {
    test('accepts the one reviewed release payment origin', () {
      final uri = validatedPaymentUrl(
        '$kReviewedPaymentBase/pay/one_month?src=app',
      );
      expect(uri.origin, kReviewedPaymentBase);
    });

    test('rejects gateway lookalikes, nonstandard ports, and fragments', () {
      for (final raw in <String>[
        'https://sync.winsvpn.org.evil.example/pay/one_month',
        'https://sync.winsvpn.com/pay/one_month',
        'https://sync.winsvpn.org:8443/pay/one_month',
        'https://sync.winsvpn.org/pay/one_month#checkout',
      ]) {
        expect(
          () => validatedPaymentUrl(raw),
          throwsA(isA<FormatException>()),
          reason: raw,
        );
      }
    });

    test('release ignores a payment-host build override', () {
      expect(
        compiledTrustedPaymentHosts(
          isReleaseBuild: true,
          releaseCsv: 'sync.winsvpn.org',
          overrideCsv: 'lookalike.example',
        ),
        {'sync.winsvpn.org'},
      );
    });

    test('debug/profile can explicitly bind a staging payment host', () {
      expect(
        compiledTrustedPaymentHosts(
          isReleaseBuild: false,
          releaseCsv: 'sync.winsvpn.org',
          overrideCsv: 'payments.staging.example',
        ),
        {'payments.staging.example'},
      );
    });
  });

  group('validatedAppUpdateUrl (M-9)', () {
    // These two assert the *property* -- whatever hosts this build trusts are
    // accepted, on 443, case- and whitespace-insensitively -- rather than the
    // literal `winsvpn.org`. Written against the literal they would fail the
    // moment anyone shipped a neutral-domain build, forcing the operator to
    // edit security tests to complete a security migration. That is how
    // migrations get abandoned. `WINS_TRUSTED_UPDATE_HOSTS` supplies the set.
    final trustedHosts = parseTrustedUpdateHosts(
      const String.fromEnvironment(
        'WINS_TRUSTED_UPDATE_HOSTS',
        defaultValue: 'winsvpn.org,www.winsvpn.org',
      ),
    ).toList();

    test('accepts the update hosts this build trusts, on the standard port',
        () {
      expect(trustedHosts, isNotEmpty);
      for (final host in trustedHosts) {
        expect(validatedAppUpdateUrl('https://$host/download').host, host);
      }
      // Explicit :443 and a query string are both fine.
      expect(
        validatedAppUpdateUrl('https://${trustedHosts.first}:443/download?v=2')
            .port,
        443,
      );
    });

    test('trims whitespace and is host-case-insensitive', () {
      final host = trustedHosts.first;
      expect(validatedAppUpdateUrl('  https://$host/download  ').host, host);
      expect(
        validatedAppUpdateUrl('https://${host.toUpperCase()}/download').host,
        host,
      );
    });

    test('rejects any non-allowlisted host, including look-alikes', () {
      for (final raw in <String>[
        'https://evil.com/download',
        'https://winsvpn.org.evil.com/download',
        'https://sync.winsvpn.org/download', // valid HTTPS host, not an update host
        'https://winsvpnorg/download',
      ]) {
        expect(
          () => validatedAppUpdateUrl(raw),
          throwsA(isA<FormatException>()),
          reason: raw,
        );
      }
    });

    // The three below deliberately build their URLs from a host this build
    // DOES trust, so each one fails for the reason named in its title rather
    // than incidentally failing the host check under a re-pointed build.
    test('rejects a nonstandard port', () {
      expect(
        () => validatedAppUpdateUrl('https://${trustedHosts.first}:8443/download'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a URL fragment and credential-bearing userinfo', () {
      final host = trustedHosts.first;
      expect(
        () => validatedAppUpdateUrl('https://$host/download#payload'),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => validatedAppUpdateUrl('https://user:pass@$host/download'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects cleartext HTTP even on a trusted host', () {
      expect(
        () => validatedAppUpdateUrl('http://${trustedHosts.first}/download'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  /// `WINS_TRUSTED_UPDATE_HOSTS`. This allowlist was hardcoded to the branded
  /// domain, so a neutral-domain build that re-pointed every gateway define
  /// still sent the user's browser to `winsvpn.org` through the force-update
  /// path -- the leak returning by the one route nobody re-points.
  group('trusted update host allowlist parsing', () {
    test('accepts a plain comma-separated host list, order-independent', () {
      expect(
        parseTrustedUpdateHosts('winsvpn.org,www.winsvpn.org'),
        {'winsvpn.org', 'www.winsvpn.org'},
      );
    });

    test('trims whitespace and lowercases, matching uri.host', () {
      // The comparison site lowercases uri.host, so an entry that differs only
      // in case would be an allowlist entry that silently never matches.
      expect(
        parseTrustedUpdateHosts(' WinsVPN.ORG , www.Example.NET '),
        {'winsvpn.org', 'www.example.net'},
      );
    });

    test('drops empty entries rather than admitting an empty host', () {
      expect(parseTrustedUpdateHosts('a.example.net,,,'), {'a.example.net'});
      expect(parseTrustedUpdateHosts(''), isEmpty);
      expect(parseTrustedUpdateHosts('   ,  '), isEmpty);
    });

    test('rejects anything that is not a bare host', () {
      // Each of these would parse into an entry that can never equal uri.host,
      // producing an allowlist that looks configured and is not.
      for (final bad in <String>[
        'https://winsvpn.org',
        'winsvpn.org/download',
        'winsvpn.org:8443',
        'user@winsvpn.org',
        'winsvpn.org?x=1',
        'winsvpn.org#frag',
        'wins vpn.org',
      ]) {
        expect(
          parseTrustedUpdateHosts(bad),
          isEmpty,
          reason: '$bad must not become an allowlist entry',
        );
      }
    });

    test('a wholly unusable override degrades to empty, not to the default',
        () {
      // The load-bearing property. Falling back to the compiled branded default
      // would restore the leak inside precisely the build that was removing it,
      // and would do it silently. Empty is safe in the other direction too:
      // validatedAppUpdateUrl then rejects every hub-advertised URL and the
      // force-update prompt uses its compiled website fallback.
      expect(parseTrustedUpdateHosts('https://evil.example/,,:::'), isEmpty);
    });

    test('a partially usable override keeps only the usable entries', () {
      expect(
        parseTrustedUpdateHosts('https://bad.example,good.example.net'),
        {'good.example.net'},
      );
    });

    test('the default build still trusts exactly the two first-party hosts',
        () {
      // Skips itself under a re-pointed build so that completing this migration
      // never requires editing a test -- which is how migrations get abandoned.
      if (const bool.hasEnvironment('WINS_TRUSTED_UPDATE_HOSTS')) return;
      expect(
        validatedAppUpdateUrl('https://winsvpn.org/download').host,
        'winsvpn.org',
      );
      expect(
        validatedAppUpdateUrl('https://www.winsvpn.org/download').host,
        'www.winsvpn.org',
      );
    });
  });

  /// B-APP-002: the dart-define used to override the update-host allowlist in
  /// ANY build mode, so a release build command could repoint the
  /// force-update flow at an arbitrary HTTPS host. A release build now
  /// enforces the compiled set regardless of the define, exactly as
  /// `controlPlanePinningEnforced` always enforces pinning.
  group('trusted update host allowlist release gate (B-APP-002)', () {
    test('a release build enforces the compiled hosts, define or no define',
        () {
      expect(
        compiledTrustedUpdateHosts(
          isReleaseBuild: true,
          releaseCsv: 'winsvpn.org,www.winsvpn.org',
          overrideCsv: 'evil.example,staging.example.net',
        ),
        {'winsvpn.org', 'www.winsvpn.org'},
      );
      // Even an unusable override must not degrade the release set: release
      // never reads it, so it cannot empty the allowlist either.
      expect(
        compiledTrustedUpdateHosts(
          isReleaseBuild: true,
          releaseCsv: 'winsvpn.org,www.winsvpn.org',
          overrideCsv: 'https://garbage',
        ),
        {'winsvpn.org', 'www.winsvpn.org'},
      );
    });

    test('debug/profile builds honour the define for testing', () {
      expect(
        compiledTrustedUpdateHosts(
          isReleaseBuild: false,
          releaseCsv: 'winsvpn.org,www.winsvpn.org',
          overrideCsv: 'staging.example.net',
        ),
        {'staging.example.net'},
      );
      // The debug degradation property is unchanged: unusable -> empty.
      expect(
        compiledTrustedUpdateHosts(
          isReleaseBuild: false,
          releaseCsv: 'winsvpn.org,www.winsvpn.org',
          overrideCsv: 'https://unusable.example',
        ),
        isEmpty,
      );
    });
  });
}
