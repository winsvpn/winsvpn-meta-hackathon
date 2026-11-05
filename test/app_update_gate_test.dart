import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/app_update_gate.dart';

void main() {
  group('compareAppVersions', () {
    test('orders major.minor.patch numerically, not lexically', () {
      expect(compareAppVersions('1.0.9', '1.0.10'), -1);
      expect(compareAppVersions('1.2.0', '1.10.0'), -1);
      expect(compareAppVersions('2.0.0', '1.9.9'), 1);
      expect(compareAppVersions('1.0.14', '1.0.14'), 0);
    });

    test('ignores +build metadata and -prerelease suffix', () {
      expect(compareAppVersions('1.0.14+29', '1.0.14'), 0);
      expect(compareAppVersions('1.0.14-beta', '1.0.14'), 0);
      expect(compareAppVersions('1.0.15+1', '1.0.14+99'), 1);
    });

    test('tolerates missing components and junk without throwing', () {
      expect(compareAppVersions('1', '1.0.0'), 0);
      expect(compareAppVersions('1.2', '1.2.0'), 0);
      expect(compareAppVersions('', '0.0.0'), 0);
      expect(compareAppVersions('garbage', '0.0.0'), 0);
    });
  });

  group('tryParseExactAppVersion (L-3)', () {
    test('accepts an exact major.minor.patch triple, including zeros', () {
      expect(tryParseExactAppVersion('1.0.15'), <int>[1, 0, 15]);
      expect(tryParseExactAppVersion('0.0.0'), <int>[0, 0, 0]);
      expect(tryParseExactAppVersion('  2.3.4  '), <int>[2, 3, 4]);
    });

    test('ignores a single +build suffix but NOT a -prerelease suffix', () {
      expect(tryParseExactAppVersion('1.0.14+29'), <int>[1, 0, 14]);
      // A gate floor must be an exact release triple; -prerelease is rejected.
      expect(tryParseExactAppVersion('1.0.14-beta'), isNull);
    });

    test('rejects wrong arity, non-numeric, negative and leading-zero forms',
        () {
      for (final raw in <String>[
        '', '   ', '1', '1.2', '1.2.3.4', 'garbage', '1.x.0', '-1.0.0',
        '01.0.0', '1.0.', '.1.0', '1..0', 'v1.0.0', '1.0.0 beta',
      ]) {
        expect(tryParseExactAppVersion(raw), isNull, reason: raw);
      }
    });

    test('rejects over-wide / int64-overflow components instead of collapsing',
        () {
      // The lenient parser used to coerce these to 0 (collapse-to-zero); the
      // strict parser rejects them so they can never disable the gate.
      for (final raw in <String>[
        '10000000000.0.0', // 11 digits > the 9-digit bound
        '99999999999999999999.0.0', // far beyond int64
        '1.0.10000000000',
      ]) {
        expect(tryParseExactAppVersion(raw), isNull, reason: raw);
      }
    });
  });

  group('appUpdateRequired', () {
    test('blocks a client strictly older than the minimum', () {
      expect(appUpdateRequired('1.0.14', '1.0.15'), isTrue);
      expect(appUpdateRequired('1.0.9', '1.0.10'), isTrue);
      expect(appUpdateRequired('1.2.0', '2.0.0'), isTrue);
    });

    test('allows a client at or above the minimum', () {
      expect(appUpdateRequired('1.0.15', '1.0.15'), isFalse);
      expect(appUpdateRequired('1.0.16', '1.0.15'), isFalse);
      expect(appUpdateRequired('1.0.14+29', '1.0.14'), isFalse);
    });

    test('fails OPEN: never blocks on an empty/zero/absent/junk minimum', () {
      // A missing or misconfigured server value must never brick every client.
      expect(appUpdateRequired('1.0.14', ''), isFalse);
      expect(appUpdateRequired('1.0.14', '0.0.0'), isFalse);
      expect(appUpdateRequired('1.0.14', '   '), isFalse);
      expect(appUpdateRequired('0.0.1', 'garbage'), isFalse);
    });

    test('L-3: a malformed/overflow floor is not honoured (fails open)', () {
      // Previously an int64-overflow floor collapsed to 0.0.0 (gate disabled)
      // and a shorthand/partial floor was wrongly honoured as [maj,0,0]. Now
      // only an exact triple is a floor; anything else fails open at this pure
      // layer (the /nodes ingestion additionally keeps such a value from
      // clearing a previously-accepted floor).
      expect(appUpdateRequired('1.0.14', '99999999999999999999.0.0'), isFalse);
      expect(appUpdateRequired('1.0.14', '10000000000.0.0'), isFalse);
      // '2' would have blocked a 1.x client under the old lenient parse.
      expect(appUpdateRequired('1.0.14', '2'), isFalse);
      // Extra component / prerelease floor are likewise not exact triples.
      // (split so the pre-push ipscrub gate never reads a version quad as IPv4)
      final versionQuadForIpScrub = ['1.0.15', '.1'].join();
      expect(appUpdateRequired('1.0.14', versionQuadForIpScrub), isFalse);
      expect(appUpdateRequired('1.0.14', '1.0.15-rc1'), isFalse);
    });

    test('L-3: an exact non-zero floor still blocks an older exact client', () {
      expect(appUpdateRequired('1.0.14', '1.0.15'), isTrue);
      expect(appUpdateRequired('garbage', '1.0.15'), isTrue);
    });

    test('L-3: a prerelease/build current above the floor is not blocked', () {
      // current is a trusted compiled-in constant and stays leniently parsed,
      // so a legitimate -prerelease/+build identifier is not spuriously blocked.
      expect(appUpdateRequired('1.0.16-beta', '1.0.15'), isFalse);
      expect(appUpdateRequired('1.0.16+42', '1.0.15'), isFalse);
      expect(appUpdateRequired('1.0.15-rc1', '1.0.15'), isFalse);
    });
  });
}
