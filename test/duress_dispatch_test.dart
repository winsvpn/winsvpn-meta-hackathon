import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/duress_dispatch.dart';

void main() {
  group('sanitizeTrustedContact', () {
    test('trims and keeps ordinary email/phone characters', () {
      expect(sanitizeTrustedContact('  friend@example.org  '),
          'friend@example.org');
      expect(sanitizeTrustedContact('+95 9 123-456-789'), '+95 9 123-456-789');
    });

    test('empty or whitespace-only becomes null, not an empty string', () {
      expect(sanitizeTrustedContact(null), isNull);
      expect(sanitizeTrustedContact(''), isNull);
      expect(sanitizeTrustedContact('   \t  '), isNull);
    });

    test('strips control characters so no header/line can be injected', () {
      final cleaned =
          sanitizeTrustedContact('a@b.com\r\nBcc: attacker@evil.example');
      expect(cleaned, isNotNull);
      expect(cleaned, isNot(contains('\n')));
      expect(cleaned, isNot(contains('\r')));
      // The newline is gone, which is what defeats the injection; the rest is
      // inert plain text.
      expect(cleaned, 'a@b.comBcc: attacker@evil.example');
    });

    test('caps absurdly long input', () {
      final long = 'x' * (kMaxTrustedContactLength + 50);
      expect(sanitizeTrustedContact(long)!.length, kMaxTrustedContactLength);
    });
  });

  group('DuressDispatch', () {
    final captured = DateTime.utc(2026, 8, 5, 12, 0, 0);

    DuressDispatch sample({double? lat = 16.8409, double? lng = 96.1735}) =>
        DuressDispatch(
          trustedContact: 'friend@example.org',
          latitude: lat,
          longitude: lng,
          capturedAtUtc: captured,
        );

    test('the persisted queue record carries no account/app-identifying data',
        () {
      final json = sample().toQueueString();
      final lower = json.toLowerCase();
      expect(lower, isNot(contains('vpn')));
      expect(lower, isNot(contains('account')));
      expect(lower, isNot(contains('token')));
      expect(lower, isNot(contains('device')));
      // What it MUST carry: destination, coordinates, capture time.
      final decoded = jsonDecode(json) as Map<String, dynamic>;
      expect(decoded['contact'], 'friend@example.org');
      expect(decoded['lat'], closeTo(16.8409, 1e-9));
      expect(decoded['lng'], closeTo(96.1735, 1e-9));
      expect(decoded['captured_at'], captured.toIso8601String());
    });

    test('round-trips through the queue form', () {
      final restored =
          DuressDispatch.fromQueueJson(jsonDecode(sample().toQueueString()));
      expect(restored, isNotNull);
      expect(restored!.trustedContact, 'friend@example.org');
      expect(restored.latitude, closeTo(16.8409, 1e-9));
      expect(restored.longitude, closeTo(96.1735, 1e-9));
      expect(restored.capturedAtUtc, captured);
    });

    test('fromQueueJson fails closed on malformed or contactless records', () {
      expect(DuressDispatch.fromQueueJson(null), isNull);
      expect(DuressDispatch.fromQueueJson('not a map'), isNull);
      expect(DuressDispatch.fromQueueJson(<String, dynamic>{}), isNull);
      expect(
        DuressDispatch.fromQueueJson(<String, dynamic>{'lat': 1.0, 'lng': 2.0}),
        isNull,
      );
    });

    test('a dispatch with no coordinates still has a destination and message',
        () {
      final noCoords = sample(lat: null, lng: null);
      expect(noCoords.hasCoordinates, isFalse);
      expect(noCoords.humanMessage(), contains('unavailable'));
      final decoded =
          jsonDecode(noCoords.toQueueString()) as Map<String, dynamic>;
      expect(decoded.containsKey('lat'), isFalse);
      expect(decoded.containsKey('lng'), isFalse);
      expect(decoded['contact'], 'friend@example.org');
    });

    test('smsText is a compact, neutral, no-identity safety message with a '
        'maps link when coordinates exist', () {
      final text = sample().smsText();
      final lower = text.toLowerCase();
      // Names nothing about the app, the service, or the panic feature: this
      // is the text that lands on the recipient's phone.
      for (final forbidden in <String>[
        'vpn',
        'winsvpn',
        'duress',
        'panic',
        'censor',
        'circumvent',
      ]) {
        expect(lower, isNot(contains(forbidden)), reason: forbidden);
      }
      // Still useful: it tells the recipient help may be needed, and where.
      expect(lower, contains('help'));
      expect(text, contains('https://maps.google.com/?q='));
    });

    test('smsText fits ONE SMS part, for every coordinate on the planet', () {
      // Measured on a device: at 162 characters the coordinate-bearing body
      // exceeded the 160-character GSM-7 single-part limit, so divideMessage
      // split it in two. Two parts is two chances of a partial delivery, two
      // SENT broadcasts for the native latch to wait on, twice the cost, and
      // twice the carrier trace -- each of which is a safety cost on this
      // path, not a cosmetic one.
      final extremes = <List<double>>[
        <double>[16.871311, 96.199379], // Yangon, the realistic case
        <double>[-89.999999, -179.999999], // longest possible rendering
        <double>[89.999999, 179.999999],
        <double>[0, 0],
        <double>[-0.000001, -100.000001],
      ];
      for (final pair in extremes) {
        final text =
            sample(lat: pair[0], lng: pair[1]).smsText();
        expect(text.length, lessThanOrEqualTo(kMaxSingleSmsLength),
            reason: '$pair rendered ${text.length} characters: '
                '"$text"');
        // The coordinates are the safety-relevant payload; shortening the
        // message must never have been done by dropping them.
        expect(text, contains('maps.google.com'), reason: '$pair');
      }
    });

    test('smsText without coordinates still asks for help and omits a link', () {
      final text = sample(lat: null, lng: null).smsText();
      expect(text.toLowerCase(), contains('help'));
      expect(text, isNot(contains('https://')));
      expect(text.length, lessThanOrEqualTo(kMaxSingleSmsLength));
    });

    test('redactedForLog reveals neither the contact nor the coordinates', () {
      final line = sample().redactedForLog();
      expect(line, isNot(contains('friend@example.org')));
      expect(line, isNot(contains('16.84')));
      expect(line, isNot(contains('96.17')));
      expect(line, contains('contact:set'));
      expect(line, contains('coords:set'));
    });

    test('withAnotherAttempt increments the bounded attempt counter', () {
      expect(sample().attemptCount, 0);
      expect(sample().withAnotherAttempt().attemptCount, 1);
      expect(sample().withAnotherAttempt().withAnotherAttempt().attemptCount, 2);
    });
  });

  group('duressProfileDisclosure (profile dispatch case)', () {
    const realLabel = 'Win\u2019s VPN \u2014 Primary account';
    const camouflageLabel = 'Basic calculator';

    DuressProfileDisclosure cohort({required bool duressTriggered}) =>
        duressProfileDisclosure(
          duressTriggered: duressTriggered,
          realProfileLabel: realLabel,
          camouflageProfileLabel: camouflageLabel,
        );

    test('normal operation reveals the real profile and does not seal it', () {
      final normal = cohort(duressTriggered: false);
      expect(normal.shownProfile, realLabel);
      expect(normal.shownProfile, isNotEmpty);
      expect(normal.realProfileSealed, isFalse);
      expect(normal.refuses, isFalse);
    });

    test('a duress trigger refuses to reveal a differing (camouflage) profile',
        () {
      final duress = cohort(duressTriggered: true);
      // Nothing is shown at all — the CAMOUFLAGE label is deliberately not
      // substituted in. It differs from the real profile, so showing it would
      // tell an inspector that a disguise exists.
      expect(duress.shownProfile, isEmpty);
      expect(duress.shownProfile, isNot(contains(camouflageLabel)));
      expect(duress.shownProfile, isNot(contains(realLabel)));
    });

    test('a duress trigger keeps the real profile sealed', () {
      final duress = cohort(duressTriggered: true);
      expect(duress.realProfileSealed, isTrue);
      // Sealed means not just flagged but never surfaced in any form.
      expect(duress.shownProfile, isNot(contains(realLabel)));
      expect(duress.refuses, isTrue);
    });

    test('every trigger-state/label combination is pinned', () {
      // The full matrix, asserted as truth-tables rather than one path, so a
      // regression that widens one branch cannot hide behind the others.
      final expectations = <({bool duress, String shown, bool sealed})>[
        (duress: false, shown: realLabel, sealed: false),
        (duress: true, shown: '', sealed: true),
      ];
      for (final expectation in expectations) {
        final d = cohort(duressTriggered: expectation.duress);
        expect(d.shownProfile, expectation.shown,
            reason: 'duress=${expectation.duress}');
        expect(d.realProfileSealed, expectation.sealed,
            reason: 'duress=${expectation.duress}');
        expect(d.refuses, expectation.sealed,
            reason: 'duress=${expectation.duress}');
      }
    });
  });
}
