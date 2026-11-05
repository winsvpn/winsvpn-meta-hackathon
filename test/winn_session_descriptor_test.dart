import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_session_descriptor.dart';

// TWO HALVES, on the pattern test/winn_protocol_refusal_guard_test.dart
// established: a BEHAVIOURAL half over the pure library, and a SOURCE-GUARD
// half over lib/main.dart, because the state this feature reads lives in
// private members of a State class and Dart privacy is per-library.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE PROTECTS, IN BOTH DIRECTIONS.
//
// This is a paired honesty test, on the design the browser extension's
// `extension/tools/checks.py` settled on: **no absence assertion without a
// presence assertion beside it.** The cheapest way to satisfy "must not claim
// v3" is to delete the sentence that names the protocol at all -- and that
// would damage something CORRECT.
//
//   PRESENCE half. `Winn Protocol®` is the PRODUCT'S name for its tunnel
//   stack. A product name is not a wire-format claim, and the status line is
//   the wrong place to litigate how much of the stack is first-party at a
//   given version. This file therefore FAILS if the product name is deleted
//   from the status line, or rewritten into a component list. It deliberately
//   does NOT assert that winn/1 is or is not first-party: see
//   lib/winn_session_descriptor.dart for the evidence on that question, which
//   is contested and belongs in a document, not in an assertion.
//
//   ABSENCE half. The session detail must never say "Version 3" unless
//   `winn/3` was the value the live tunnel actually negotiated, and must never
//   render an unknown or absent version as version 1.
//
// The lexicon in `extension/tools/checks.py` already draws this exact line: it
// bans an unqualified `winn protocol v3` claim while leaving the product name
// untouched. This file is the in-app counterpart of that rule.
void main() {
  // -------------------------------------------------------------------------
  // Behavioural half: the pure library.
  // -------------------------------------------------------------------------
  group('winnSessionVersion', () {
    test('a disconnected app has NO version, and it is not v1', () {
      final version = winnSessionVersion(
        isConnected: false,
        rawProtocolVersion: 'winn/1',
      );
      expect(version, WinnSessionVersion.none);
      expect(version, isNot(WinnSessionVersion.v1),
          reason: 'not connected is not a protocol version');
      expect(winnSessionVersionPhrase(version), '',
          reason: 'no session must render nothing, not a claim');
    });

    test('an absent version on a live session is none, never defaulted to v1',
        () {
      // The absent-means-v1 rule belongs to normalizedWinnProtocolVersion and
      // exists to keep OLD CONFIGS working. Applying it here would convert
      // "this process has no record of the version" into an assertion that
      // version 1 is carrying the session. That is the same defect as the
      // antivirus lane's "a source that could not be read is not an empty
      // source".
      for (final raw in <String>['', '   ']) {
        expect(
          winnSessionVersion(isConnected: true, rawProtocolVersion: raw),
          WinnSessionVersion.none,
          reason: 'raw "$raw" must not become v1',
        );
      }
    });

    test('winn/1 is reported as version 1', () {
      expect(
        winnSessionVersion(isConnected: true, rawProtocolVersion: 'winn/1'),
        WinnSessionVersion.v1,
      );
    });

    test('winn/3 is reported as version 3', () {
      expect(
        winnSessionVersion(isConnected: true, rawProtocolVersion: 'winn/3'),
        WinnSessionVersion.v3,
      );
    });

    test('an unknown version is unrecognised, not silently v1', () {
      for (final raw in <String>['winn/2', 'winn/4', 'wireguard', 'winn/3x']) {
        final version =
            winnSessionVersion(isConnected: true, rawProtocolVersion: raw);
        expect(version, WinnSessionVersion.unrecognised, reason: raw);
        expect(version, isNot(WinnSessionVersion.v1), reason: raw);
      }
    });
  });

  group('the "Version 3" claim', () {
    test('is produced for winn/3 and for NOTHING else', () {
      const candidates = <String>[
        '',
        '   ',
        'winn/1',
        'winn/2',
        'winn/4',
        'winn/30',
        'WINN/3',
        'wireguard',
        'amneziawg',
        'xray-vless-ws+amneziawg',
      ];
      for (final raw in candidates) {
        final phrase = winnSessionVersionPhrase(
          winnSessionVersion(isConnected: true, rawProtocolVersion: raw),
        );
        expect(phrase, isNot('Version 3'),
            reason: '"$raw" must not be able to claim version 3');
      }
      expect(
        winnSessionVersionPhrase(
          winnSessionVersion(isConnected: true, rawProtocolVersion: 'winn/3'),
        ),
        'Version 3',
      );
    });

    test('a winn/3 session that is not connected still cannot claim v3', () {
      expect(
        winnSessionVersionPhrase(
          winnSessionVersion(isConnected: false, rawProtocolVersion: 'winn/3'),
        ),
        '',
      );
    });
  });

  group('winnSessionTransport', () {
    test('names the transport that is actually carrying the session', () {
      expect(
        winnSessionTransport(isConnected: true, stealthActive: true),
        WinnSessionTransport.stealth,
      );
      expect(
        winnSessionTransport(isConnected: true, stealthActive: false),
        WinnSessionTransport.direct,
      );
      expect(
        winnSessionTransport(isConnected: false, stealthActive: true),
        WinnSessionTransport.none,
      );
    });
  });

  group('winnSessionDetail', () {
    String identity(String value) => value;

    test('renders nothing at all when there is no live session', () {
      expect(
        winnSessionDetail(
          version: WinnSessionVersion.none,
          transport: WinnSessionTransport.none,
          translate: identity,
        ),
        '',
      );
      // A half-known session is still not a session to describe.
      expect(
        winnSessionDetail(
          version: WinnSessionVersion.v3,
          transport: WinnSessionTransport.none,
          translate: identity,
        ),
        '',
      );
      expect(
        winnSessionDetail(
          version: WinnSessionVersion.none,
          transport: WinnSessionTransport.stealth,
          translate: identity,
        ),
        '',
      );
    });

    test('names both the version and the transport for a live session', () {
      expect(
        winnSessionDetail(
          version: WinnSessionVersion.v1,
          transport: WinnSessionTransport.stealth,
          translate: identity,
        ),
        'Version 1 · stealth transport',
      );
      expect(
        winnSessionDetail(
          version: WinnSessionVersion.v3,
          transport: WinnSessionTransport.direct,
          translate: identity,
        ),
        'Version 3 · direct transport',
      );
    });

    test('passes every part through the translator', () {
      final seen = <String>[];
      winnSessionDetail(
        version: WinnSessionVersion.v3,
        transport: WinnSessionTransport.stealth,
        translate: (value) {
          seen.add(value);
          return value;
        },
      );
      expect(seen, containsAll(<String>['Version 3', 'stealth transport']),
          reason: 'an untranslated part is unreadable to a Burmese user');
    });

    test('never emits a bare product-name claim of its own', () {
      // The session line answers "which version / which transport". It must
      // not restate the product name: two places asserting the same trademark
      // is how one of them drifts.
      for (final version in WinnSessionVersion.values) {
        for (final transport in WinnSessionTransport.values) {
          final line = winnSessionDetail(
            version: version,
            transport: transport,
            translate: identity,
          );
          expect(line.contains('Winn Protocol'), isFalse, reason: line);
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Source-guard half: lib/main.dart.
  // -------------------------------------------------------------------------
  group('lib/main.dart', () {
    late String source;

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
    });

    // ---- PRESENCE half. Protects a claim that is CORRECT. ----

    test('still names the product protocol on the status line', () {
      expect(
        source.contains("static const String _defaultProtocolLabel = "
            "'Winn Protocol®';"),
        isTrue,
        reason: 'Winn Protocol® is the product name for the tunnel stack. '
            'Deleting or renaming it is a product decision, not a copy fix, '
            'and no lane should make it as a side effect. If the name '
            'legitimately changed, update this test deliberately.',
      );
      expect(
        source.contains(
            'Text("\${_t("Selected Protocol (Automatic):")} \$_activeProtocolLabel"'),
        isTrue,
        reason: 'the product protocol must remain on screen; the session '
            'detail is additive and does not replace it',
      );
    });

    test('does not hedge or re-attribute the product protocol name', () {
      // A future lane acting on the misreading that "winn/1 means nothing of
      // ours is running" would most likely soften the label. These are the
      // shapes that softening takes.
      const forbidden = <String, String>{
        'Winn Protocol (AmneziaWG)':
            'a parenthetical component gloss turns a product name into a '
                'wire-format claim; the session line carries that instead',
        'Winn Protocol (based on':
            'the protocol is first-party; "based on" attributes it away',
        'powered by AmneziaWG':
            'attribution belongs in the licences surface, not the status line',
        'powered by Xray':
            'attribution belongs in the licences surface, not the status line',
        'AmneziaWG + Xray':
            'that is a component list, not the name of the protocol',
        'a wrapper around':
            'the product is not a wrapper around its dependencies',
      };
      forbidden.forEach((phrase, why) {
        expect(source.contains(phrase), isFalse, reason: '$phrase -- $why');
      });
    });

    // ---- ABSENCE half. Stops a claim that would be false. ----

    test('never hard-codes a version claim into the session line', () {
      // The version must come from the negotiated slot, never from a literal.
      final detailGetter = _slice(
        source,
        start: 'String get _winnSessionDetailLine',
        end: '      );',
      );
      expect(detailGetter, isNotEmpty,
          reason: 'the session detail getter is gone; this test is blind');
      for (final literal in <String>["'Version 3'", '"Version 3"', 'winn/3']) {
        expect(detailGetter.contains(literal), isFalse,
            reason: 'the session line must read the negotiated version, '
                'not assert $literal');
      }
      expect(detailGetter.contains('_activeProtocolVersion'), isTrue,
          reason: 'the version must come from the committed-session mirror');
      expect(detailGetter.contains('isConnected: _isConnected'), isTrue,
          reason: 'the detail must be gated on there being a live session');
    });

    test('the version mirror is written only from a committed connected config',
        () {
      // Same discipline the file already documents for _isCensorshipModeActive.
      final assignments = RegExp(r'_activeProtocolVersion\s*=\s*([^;]+);')
          .allMatches(source)
          .map((m) => m.group(1)!.trim())
          .toList();
      expect(assignments, isNotEmpty);
      const permitted = <String>{
        "''", // reset: no live session
        "normalizedWinnProtocolVersion(config['protocol_version'])",
        "(settingsData['active_protocol_version'] ?? '').toString().trim()",
      };
      for (final rhs in assignments) {
        final flattened = rhs.replaceAll(RegExp(r'\s+'), ' ').trim();
        expect(
          permitted.any((p) => flattened == p.replaceAll(RegExp(r'\s+'), ' ')),
          isTrue,
          reason: 'unexpected write to the version mirror: "$flattened". It '
              'may only be cleared, restored, or set from the config a tunnel '
              'actually committed -- never from a build flag, a served config '
              'that has not started, or a UI control.',
        );
      }
    });

    test('every label reset clears the version mirror beside it', () {
      // A stale version would otherwise be persisted by
      // _saveVpnRuntimeSettings and restored onto a LATER, different session.
      final lines = source.split('\n');
      final unpaired = <int>[];
      for (var i = 0; i < lines.length; i++) {
        final line = lines[i].trim();
        if (line != '_activeProtocolLabel = _defaultProtocolLabel;') continue;
        final next = i + 1 < lines.length ? lines[i + 1].trim() : '';
        if (next != "_activeProtocolVersion = '';") unpaired.add(i + 1);
      }
      expect(unpaired, isEmpty,
          reason: 'label reset without a version reset at line(s) '
              '${unpaired.join(", ")}');
    });

    // ---- Translation coverage. ----

    test('every phrase the session line can show is translated', () {
      // wins_vpn has no ARB layer: translation is the hand-rolled map in this
      // file. A missing entry falls back to English silently, which for a
      // Burmese reader means the line is unreadable and therefore unactionable.
      final my = _slice(source, start: "      'my': {", end: "\n      },");
      final de = _slice(source, start: "      'de': {", end: "\n      },");
      expect(my, isNotEmpty, reason: 'the my block is gone; test is blind');
      expect(de, isNotEmpty, reason: 'the de block is gone; test is blind');
      for (final phrase in kWinnSessionDetailPhrases) {
        expect(my.contains("'$phrase':"), isTrue,
            reason: 'Burmese translation missing for "$phrase"');
        expect(de.contains("'$phrase':"), isTrue,
            reason: 'German translation missing for "$phrase"');
      }
    });
  });
}

/// The text between the first [start] and the next [end] after it, or `''`.
String _slice(String source, {required String start, required String end}) {
  final from = source.indexOf(start);
  if (from < 0) return '';
  final to = source.indexOf(end, from + start.length);
  if (to < 0) return '';
  return source.substring(from, to + end.length);
}
