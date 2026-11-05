import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/pre_vpn_geo.dart';

/// Contract for the pre-VPN map-tile host pin.
///
/// `map_tile_url_template` is supplied by the hub in the `/api/site/geo-scene`
/// response and fetched **before any tunnel exists**, from the user's real IP.
/// Unpinned, it let a coerced, compromised or seized control plane point every
/// install's pre-tunnel fetch at an attacker-chosen host and harvest real IP
/// addresses at scale -- no exploit needed, just a value the hub already sets.
///
/// Every test below is written against the *property* (whatever hosts this
/// build trusts) rather than the literal `winsvpn.org`, so a neutral-domain
/// build does not have to edit security tests to complete a security
/// migration. `WINS_TRUSTED_MAP_TILE_HOSTS` supplies the set.
void main() {
  final trustedHosts = trustedMapTileHosts.toList();

  String templateFor(String host) =>
      'https://$host/api/site/map-tile/{z}/{x}/{y}.png';

  group('map tile host pin', () {
    test('the build ships a non-empty tile allowlist', () {
      // Guards against the pin being defeated by an empty set that makes every
      // other assertion here pass vacuously.
      expect(trustedHosts, isNotEmpty);
    });

    test('accepts the tile hosts this build trusts', () {
      for (final host in trustedHosts) {
        final template = templateFor(host);
        expect(validMapTileUrlTemplate(template), template, reason: host);
        expect(untrustedMapTileHost(template), isNull, reason: host);
      }
    });

    test('rejects any non-allowlisted host, including look-alikes', () {
      final trusted = trustedHosts.first;
      for (final host in <String>[
        'maps.winsvpn.org', // plausible, first-party-looking, not allowlisted
        'tile.attacker.example',
        '$trusted.evil.com', // suffix-of-a-trusted-name attack
        'evil.com',
        'winsvpnorg',
        '203.0.113.7', // bare IP literal
      ]) {
        final template = templateFor(host);
        expect(validMapTileUrlTemplate(template), isNull, reason: host);
        expect(untrustedMapTileHost(template), host, reason: host);
      }
    });

    test('matches by equality, so no dangling subdomain is accepted', () {
      // The reason the allowlist is exact and not a suffix wildcard: a
      // bare-zone entry would accept every one of these. See
      // docs/handoff/SPEED_TEST_ALLOWLIST_EXACT_HOSTS_20260806.md.
      for (final trusted in trustedHosts) {
        for (final host in <String>[
          'harvest.$trusted',
          'a.b.$trusted',
          '$trusted.attacker.example',
        ]) {
          expect(
            validMapTileUrlTemplate(templateFor(host)),
            isNull,
            reason: host,
          );
        }
      }
    });

    test('is host-case-insensitive and whitespace tolerant', () {
      final host = trustedHosts.first;
      final template = templateFor(host);
      expect(validMapTileUrlTemplate('  $template  '), template);
      expect(
        validMapTileUrlTemplate(templateFor(host.toUpperCase())),
        templateFor(host.toUpperCase()),
      );
    });

    // The rest deliberately build from a host this build DOES trust, so each
    // fails for the reason in its title rather than incidentally failing the
    // host check under a re-pointed build.
    test('rejects a nonstandard port on a trusted host', () {
      final host = trustedHosts.first;
      expect(
        validMapTileUrlTemplate(
          'https://$host:8443/api/site/map-tile/{z}/{x}/{y}.png',
        ),
        isNull,
      );
    });

    test('rejects cleartext HTTP on a trusted host', () {
      final host = trustedHosts.first;
      expect(
        validMapTileUrlTemplate(
          'http://$host/api/site/map-tile/{z}/{x}/{y}.png',
        ),
        isNull,
      );
    });

    test('rejects credentials, query and fragment on a trusted host', () {
      final host = trustedHosts.first;
      for (final raw in <String>[
        'https://user:pass@$host/api/site/map-tile/{z}/{x}/{y}.png',
        'https://$host/api/site/map-tile/{z}/{x}/{y}.png?key=client-secret',
        'https://$host/api/site/map-tile/{z}/{x}/{y}.png#payload',
      ]) {
        expect(validMapTileUrlTemplate(raw), isNull, reason: raw);
      }
    });

    test('rejects a malformed template regardless of host', () {
      final host = trustedHosts.first;
      for (final raw in <Object?>[
        null,
        '',
        '   ',
        42,
        'https://$host/api/site/map-tile/{z}/{x}.png', // missing {y}
        'not a url at all {z}{x}{y}',
      ]) {
        expect(validMapTileUrlTemplate(raw), isNull, reason: '$raw');
      }
    });
  });

  group('map tile rejection is diagnosable without leaking the URL', () {
    test('a shape failure is not reported as a host failure', () {
      final host = trustedHosts.first;
      // Missing {y}: rejected, but not because of its host. Reporting a host
      // here would send an operator hunting for an allowlist problem that does
      // not exist.
      expect(
        untrustedMapTileHost('https://$host/api/site/map-tile/{z}/{x}.png'),
        isNull,
      );
      expect(untrustedMapTileHost('javascript:alert(1)'), isNull);
      expect(untrustedMapTileHost(null), isNull);
    });

    test('a credential-bearing URL never surfaces its credentials', () {
      // Rejected on scheme/userinfo grounds, so nothing is reported at all --
      // the diagnosis can never become a channel for a leaked secret.
      const raw =
          'https://harvester:s3cret@tiles.attacker.example/{z}/{x}/{y}.png';
      expect(validMapTileUrlTemplate(raw), isNull);
      final reported = untrustedMapTileHost(raw);
      expect(reported, isNull);
      expect(reported ?? '', isNot(contains('s3cret')));
    });

    test('the reported value is a bare host, never the template', () {
      const host = 'tiles.attacker.example';
      final reported = untrustedMapTileHost(
        'https://$host/api/site/map-tile/{z}/{x}/{y}.png',
      );
      expect(reported, host);
      expect(reported, isNot(contains('/')));
      expect(reported, isNot(contains('{z}')));
      expect(reported, isNot(contains('https')));
    });

    test('the scene carries the rejected host through to the app', () {
      final scene = parsePreVpnGeoScene({
        'country': 'MM',
        'region': 'YA',
        'map_tile_url_template':
            'https://harvest.attacker.example/{z}/{x}/{y}.png',
      });

      expect(scene, isNotNull);
      // The hostile template is discarded...
      expect(scene!.mapTileUrlTemplate, isNull);
      // ...and the app is told why, by host alone.
      expect(scene.rejectedMapTileHost, 'harvest.attacker.example');
      // The rest of the scene still applies: rejecting a tile host must not
      // cost the user their coarse-location map.
      expect(scene.countryCode, 'MM');
      expect(scene.hasRegion, isTrue);
    });

    test('an accepted template reports no rejection', () {
      final scene = parsePreVpnGeoScene({
        'country': 'US',
        'map_tile_url_template': templateFor(trustedHosts.first),
      });
      expect(scene!.rejectedMapTileHost, isNull);
      expect(scene.mapTileUrlTemplate, isNotNull);
    });
  });

  group('the allowlist itself is screened', () {
    test('every trusted host is a bare, lowercase, port-free hostname', () {
      for (final host in trustedHosts) {
        expect(host, equals(host.toLowerCase()), reason: host);
        expect(host, isNot(contains('/')), reason: host);
        expect(host, isNot(contains(':')), reason: host);
        expect(host, isNot(contains('@')), reason: host);
        expect(host, isNot(startsWith('.')), reason: host);
        // An entry Uri disagrees with would silently never match uri.host --
        // an allowlist that looks configured and is not.
        expect(Uri.parse('https://$host').host, host, reason: host);
      }
    });

    test('no entry is a bare zone that would accept a dangling subdomain', () {
      for (final host in trustedHosts) {
        expect(host.startsWith('.'), isFalse, reason: host);
        expect(host.startsWith('*'), isFalse, reason: host);
      }
    });
  });
}
