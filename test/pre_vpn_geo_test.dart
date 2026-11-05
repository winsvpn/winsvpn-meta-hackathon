import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/pre_vpn_geo.dart';

void main() {
  // Asserts the ORDERING property rather than literal hostnames, so it still
  // holds for a build re-pointed with --dart-define=WINS_GEO_EDGE_BASES.
  test('owned geo edges precede gateways and public fallback', () {
    final sources = buildPreVpnGeoSceneSources([
      'https://sync.winsvpn.org',
      'https://sync.winsvpn.com',
    ]);

    for (var i = 0; i < preVpnGeoEdgeBases.length; i++) {
      expect(sources[i].toString(),
          '${preVpnGeoEdgeBases[i]}/api/site/geo-scene');
    }
    expect(sources.last.toString(), 'https://speed.cloudflare.com/meta');
    expect(sources.map((uri) => uri.toString()),
        contains('https://sync.winsvpn.org/api/site/geo-scene'));
  });

  test('Cloudflare coarse geo request uses its same-origin API headers', () {
    final headers = preVpnGeoRequestHeaders(
      Uri.parse('https://speed.cloudflare.com/meta'),
    );
    expect(headers['Accept'], 'application/json');
    expect(headers['Origin'], 'https://speed.cloudflare.com');
    expect(
      preVpnGeoRequestHeaders(
        Uri.parse('https://www.winsvpn.org/api/site/geo-scene'),
      ),
      isEmpty,
    );
  });

  test('geo scene accepts region and validated coordinate pairs', () {
    final scene = parsePreVpnGeoScene({
      'country': 'us',
      'region': 'US-FL',
      'latitude': '40.71',
      'longitude': -74.01,
    });

    expect(scene, isNotNull);
    expect(scene!.countryCode, 'US');
    expect(scene.regionCode, 'FL');
    expect(scene.latitude, 40.71);
    expect(scene.longitude, -74.01);
    expect(scene.hasSpecificLocation, isTrue);
  });

  test('invalid or incomplete coordinates are discarded as a pair', () {
    final scene = parsePreVpnGeoScene({
      'country': 'US',
      'region': 'FL',
      'latitude': 40.71,
      'longitude': 900,
    });

    expect(scene, isNotNull);
    expect(scene!.latitude, isNull);
    expect(scene.longitude, isNull);
    expect(scene.hasRegion, isTrue);
  });

  test('geo scene accepts a complete HTTPS map provider contract', () {
    // Built from a host this build actually trusts rather than a literal, so
    // it still holds for a build re-pointed with WINS_TRUSTED_MAP_TILE_HOSTS.
    // The tile host is pinned now; a fixture naming an arbitrary host would
    // assert the opposite of the property this suite is here to protect.
    final tileHost = trustedMapTileHosts.first;
    final template = 'https://$tileHost/api/site/map-tile/{z}/{x}/{y}.png';
    final scene = parsePreVpnGeoScene({
      'country': 'US',
      'region': 'FL',
      'map_tile_url_template': template,
      'map_attribution_text': '© Map provider • © OpenStreetMap contributors',
      'map_attribution_url': 'https://maps.winsvpn.org/attribution',
    });

    expect(scene, isNotNull);
    expect(scene!.mapTileUrlTemplate, template);
    expect(scene.rejectedMapTileHost, isNull);
    expect(scene.mapAttributionText,
        '© Map provider • © OpenStreetMap contributors');
    expect(scene.mapAttributionUrl, 'https://maps.winsvpn.org/attribution');
  });

  test('unsafe map provider values are ignored', () {
    final scene = parsePreVpnGeoScene({
      'country': 'US',
      'map_tile_url_template': 'http://user:pass@example.com/{z}/{x}/{y}.png',
      'map_attribution_text': 'bad\ncredit',
      'map_attribution_url': 'javascript:alert(1)',
    });

    expect(scene, isNotNull);
    expect(scene!.mapTileUrlTemplate, isNull);
    expect(scene.mapAttributionText, isNull);
    expect(scene.mapAttributionUrl, isNull);
    expect(
      validMapTileUrlTemplate(
        'https://maps.example.test/{z}/{x}/{y}.png?key=client-secret',
      ),
      isNull,
    );
  });

  test('Florida region resolves to Florida rather than the US center', () {
    final center = preVpnRegionCenter('US', 'FL');
    expect(center, isNotNull);
    expect(center!.latitude, closeTo(27.8, 0.01));
    expect(center.longitude, closeTo(-81.7, 0.01));
  });

  test('country-only payload is retained without claiming a region', () {
    final scene = parsePreVpnGeoScene({'country': 'US'});
    expect(scene, isNotNull);
    expect(scene!.hasSpecificLocation, isFalse);
  });

  test('malformed payloads and unsafe source URLs are rejected', () {
    expect(parsePreVpnGeoScene({'country': 'USA'}), isNull);
    expect(parsePreVpnGeoScene('<html>'), isNull);
    final sources = buildPreVpnGeoSceneSources([
      'http://example.com',
      'https://user@example.com',
      'https://example.com?next=bad',
    ]);
    expect(
      sources.length,
      preVpnGeoDirectSources.length + preVpnGeoEdgeBases.length,
    );
  });

  group('WINS_GEO_EDGE_BASES override', () {
    test('parses a neutral-domain list in order, normalised to origins', () {
      expect(
        parsePreVpnGeoEdgeBases(
          'https://a.app-cloud-sync.net, https://b.app-cloud-sync.net/ ',
        ),
        ['https://a.app-cloud-sync.net', 'https://b.app-cloud-sync.net'],
      );
    });

    test('screens out every unsafe origin shape', () {
      expect(
        parsePreVpnGeoEdgeBases(
          'http://plain.example,'
          'https://user@creds.example,'
          'https://query.example?a=b,'
          'https://frag.example#x,'
          'https://port.example:8443,'
          'https://path.example/deep/path,'
          'not a url at all,'
          ',,',
        ),
        isEmpty,
      );
    });

    test('keeps https origins with an explicit :443 and a bare slash path', () {
      expect(
        parsePreVpnGeoEdgeBases('https://ok.example:443/'),
        ['https://ok.example'],
      );
    });

    test('de-duplicates origins that differ only by trailing slash', () {
      expect(
        parsePreVpnGeoEdgeBases('https://one.example,https://one.example/'),
        ['https://one.example'],
      );
    });

    // The load-bearing property: a build that sets the override to something
    // unusable must NOT silently inherit the branded compiled default, because
    // that is precisely the build that was trying to remove it.
    test('an unusable override degrades to empty, never to a fallback', () {
      expect(parsePreVpnGeoEdgeBases('http://insecure.example'), isEmpty);
      expect(parsePreVpnGeoEdgeBases(''), isEmpty);
      expect(parsePreVpnGeoEdgeBases('   '), isEmpty);
    });

    // An empty edge list must not break the feature: the gateways and the
    // public fallback still answer.
    test('empty edge list still yields gateways and the public fallback', () {
      final sources = buildPreVpnGeoSceneSources(['https://sync.example']);
      expect(
        sources.map((uri) => uri.toString()),
        containsAll([
          'https://sync.example/api/site/geo-scene',
          'https://speed.cloudflare.com/meta',
        ]),
      );
    });

    // Guards the DEFAULT build only. A re-pointed build legitimately carries
    // different hosts, so assert the default exactly and skip when overridden
    // rather than forcing the operator to edit a test to ship a neutral build.
    test('the shipped default still resolves to the two first-party edges', () {
      expect(preVpnGeoEdgeBases, [
        'https://www.winsvpn.org',
        'https://www.winsvpn.com',
      ]);
    }, skip: const bool.hasEnvironment('WINS_GEO_EDGE_BASES')
        ? 'WINS_GEO_EDGE_BASES is overridden for this build'
        : null);
  });

  /// B-APP-006: the dart-define used to accept any HTTPS origin for the
  /// pre-tunnel geo lookup, so a build command could point a raw pre-VPN
  /// request (plaintext DNS + SNI, user's real IP) at an arbitrary host. A
  /// release build now ignores the define entirely and asks only the compiled
  /// first-party edges.
  group('WINS_TRUSTED_MAP_TILE_HOSTS release gate (F-07)', () {
    test('a release build ignores the define and trusts the compiled hosts',
        () {
      final releaseHosts = compiledTrustedMapTileHosts(
        isReleaseBuild: true,
        definePresent: true,
        defineCsv: 'evil.example,tracker.example.net',
      );
      expect(releaseHosts, contains('winsvpn.org'));
      expect(releaseHosts, isNot(contains('evil.example')));
      expect(releaseHosts, isNot(contains('tracker.example.net')));
    });

    test('an unset define keeps the compiled hosts in any mode', () {
      expect(
        compiledTrustedMapTileHosts(
          isReleaseBuild: false,
          definePresent: false,
          defineCsv: '',
        ),
        contains('winsvpn.org'),
      );
    });

    test('debug/profile builds honour the define, unusable degrades to empty',
        () {
      expect(
        compiledTrustedMapTileHosts(
          isReleaseBuild: false,
          definePresent: true,
          defineCsv: 'maps.staging.example.net',
        ),
        {'maps.staging.example.net'},
      );
      expect(
        compiledTrustedMapTileHosts(
          isReleaseBuild: false,
          definePresent: true,
          defineCsv: 'not a host',
        ),
        isEmpty,
      );
    });
  });

  group('map attribution host screen (F-12)', () {
    test('first-party and license attribution hosts are accepted', () {
      for (final host in [
        'maps.winsvpn.org',
        'www.openstreetmap.org',
        'www.naturalearthdata.com',
      ]) {
        final scene = parsePreVpnGeoScene({
          'country': 'US',
          'map_attribution_url': 'https://$host/attribution',
        });
        expect(scene!.mapAttributionUrl, 'https://$host/attribution',
            reason: '$host is a legitimate attribution origin');
      }
    });

    test('an arbitrary hub-supplied HTTPS origin is refused', () {
      final scene = parsePreVpnGeoScene({
        'country': 'US',
        'map_attribution_url': 'https://phishing.example.net/login',
      });
      expect(scene!.mapAttributionUrl, isNull,
          reason:
              'a compromised hub must not aim the user\'s browser at an '
              'arbitrary origin (F-12)');
    });

    test('a lookalike or subdomain of a trusted host is refused', () {
      for (final url in [
        'https://openstreetmap.org.evil.example/',
        'https://evil.openstreetmap.org/',
      ]) {
        final scene = parsePreVpnGeoScene({
          'country': 'US',
          'map_attribution_url': url,
        });
        expect(scene!.mapAttributionUrl, isNull, reason: '$url slipped the screen');
      }
    });
  });

  group('WINS_GEO_EDGE_BASES release gate (B-APP-006)', () {
    test('a release build ignores the define and asks the compiled edges', () {
      expect(
        compiledPreVpnGeoEdgeBases(
          isReleaseBuild: true,
          definePresent: true,
          defineCsv: 'https://evil.example,https://tracker.example.net',
        ),
        ['https://www.winsvpn.org', 'https://www.winsvpn.com'],
      );
    });

    test('an unset define keeps the compiled edges in any mode', () {
      expect(
        compiledPreVpnGeoEdgeBases(
          isReleaseBuild: false,
          definePresent: false,
          defineCsv: '',
        ),
        ['https://www.winsvpn.org', 'https://www.winsvpn.com'],
      );
    });

    test('debug/profile builds honour the define for testing', () {
      expect(
        compiledPreVpnGeoEdgeBases(
          isReleaseBuild: false,
          definePresent: true,
          defineCsv: 'https://staging.example.net',
        ),
        ['https://staging.example.net'],
      );
      // The debug degradation property is unchanged: unusable -> empty, never
      // a silent fallback to the compiled default.
      expect(
        compiledPreVpnGeoEdgeBases(
          isReleaseBuild: false,
          definePresent: true,
          defineCsv: 'http://insecure.example',
        ),
        isEmpty,
      );
    });

    test('every compiled release source host is inside the closed allowlist',
        () {
      // Assert the RELEASE resolution explicitly rather than the ambient
      // preVpnGeoEdgeBases, so this test holds even when the test run itself
      // carries a WINS_GEO_EDGE_BASES define: the release surface is a
      // property of the compiled artifact, not of this test invocation.
      final releaseEdges = compiledPreVpnGeoEdgeBases(
        isReleaseBuild: true,
        definePresent: false,
        defineCsv: '',
      );
      final releaseHosts = <String>[
        ...releaseEdges.map((base) => Uri.parse(base).host.toLowerCase()),
        ...preVpnGeoDirectSources
            .map((source) => Uri.parse(source).host.toLowerCase()),
      ];
      expect(releaseHosts, isNotEmpty);
      for (final host in releaseHosts) {
        expect(
          permittedPreVpnGeoHosts,
          contains(host),
          reason: '$host must be inside the compiled geo allowlist',
        );
      }
      expect(
        permittedPreVpnGeoHosts,
        containsAll(<String>['www.winsvpn.org', 'www.winsvpn.com']),
      );
    });
  });
}
