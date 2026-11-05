import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/gateway_failover.dart';

/// Records that must never yield a gateway. The recovery record is unsigned
/// and mutable by whoever controls its URL, so the allowlist check is the
/// entire security boundary: every one of these has to come back null.
const Map<String, String> _hostileRecords = <String, String>{
  'unrelated host': 'https://mirror.example.net',
  'unrelated host with a route suffix': 'https://mirror.example.net/nodes',
  'lookalike suffix': 'https://sync.winsvpn.org.evil.example',
  'lookalike suffix, no dot': 'https://sync.winsvpn.orgevil.example',
  'lookalike prefix': 'https://evilsync.winsvpn.org',
  'lookalike TLD': 'https://sync.winsvpn.org.co',
  'lookalike hyphenation': 'https://sync-winsvpn.org',
  'subdomain of an allowlisted host': 'https://a.sync.winsvpn.org',
  'deep subdomain': 'https://evil.attacker.hub.winsvpn.org',
  'trailing dot': 'https://sync.winsvpn.org.',
  'uppercase host': 'https://SYNC.WINSVPN.ORG',
  'mixed-case host': 'https://Sync.WinsVPN.org',
  'plaintext http': 'http://sync.winsvpn.org',
  'non-http scheme': 'ftp://sync.winsvpn.org',
  'scheme-less host': 'sync.winsvpn.org',
  'credentialed authority': 'https://user@sync.winsvpn.org',
  'credentialed authority with password': 'https://user:pass@sync.winsvpn.org',
  'host confusion via credentials': 'https://sync.winsvpn.org@evil.example',
  'IPv4 literal': 'https://203.0.113.10',
  'IPv6 literal': 'https://[2001:db8::1]',
  'off-port': 'https://sync.winsvpn.org:8443',
  'explicit default port': 'https://sync.winsvpn.org:443',
  'path-bearing': 'https://sync.winsvpn.org/evil',
  'traversal path': 'https://sync.winsvpn.org/../evil',
  'query-bearing': 'https://sync.winsvpn.org?next=evil',
  'query on a stripped suffix': 'https://sync.winsvpn.org/verify?next=evil',
  'fragment-bearing': 'https://sync.winsvpn.org#evil',
  'pipe-delimited pair': 'https://sync.winsvpn.org|203.0.113.10',
  'html error page': '<!doctype html><html></html>',
  'empty body': '',
  'whitespace only': '   \n  ',
};

void main() {
  // The positive cases below assert the *property* -- a record naming a
  // compiled gateway selects that gateway -- against whatever set this build
  // actually compiled, rather than against the literal `winsvpn.org`. Written
  // against the literals they fail the moment anyone ships a neutral-domain
  // build, which would force an operator to edit the security tests in order to
  // complete a security migration. The negative cases keep their literals: a
  // lookalike of a branded host must be rejected by every build.
  final compiled = primaryStealthGateways;
  final primaryGateway = compiled.first;
  final secondaryGateway = compiled.length > 1 ? compiled[1] : compiled.first;
  final hubGateway = compiled.last;

  test('the compiled gateway set is usable and distinct', () {
    // Guards the assumptions the tests below make about `compiled`.
    expect(compiled.length, greaterThanOrEqualTo(2));
    expect(compiled.toSet().length, compiled.length);
  });

  test('an in-allowlist record selects a compiled gateway', () {
    expect(recoveryGatewayFromRecord(primaryGateway), primaryGateway);
    expect(
      recoveryGatewayFromRecord('$primaryGateway/verify\nignored'),
      primaryGateway,
    );
    expect(
      recoveryGatewayFromRecord('  $hubGateway/nodes  '),
      hubGateway,
    );
    expect(
      recoveryGatewayFromRecord('$secondaryGateway/free/verify'),
      secondaryGateway,
    );
  });

  test('a hostile record can never introduce a host', () {
    _hostileRecords.forEach((label, body) {
      expect(recoveryGatewayFromRecord(body), isNull, reason: label);
    });
  });

  test('an in-allowlist record reorders compiled gateways without adding one',
      () {
    final gateway = recoveryGatewayFromRecord('$hubGateway/verify');
    expect(gateway, hubGateway);

    final urls = nodeDiscoveryUrls(GatewayEndpoints(gateway: gateway!));
    expect(urls.first, '$hubGateway/nodes');
    expect(
      urls.toSet(),
      compiled.map((gateway) => '$gateway/nodes').toSet(),
      reason: 'the record may re-order the compiled set and nothing else',
    );

    // A rejected record leaves every compiled gateway reachable in the
    // compiled order, so a censored record can only fail closed.
    expect(recoveryGatewayFromRecord('https://mirror.example.net'), isNull);
    expect(
      nodeDiscoveryUrls(const GatewayEndpoints(gateway: '')),
      nodeDiscoveryUrls(
        GatewayEndpoints(gateway: recoveryGatewayAllowlist.first),
      ),
    );
  });

  test('the match returns the compiled element, never record-derived text',
      () {
    // gatewayBase() builds this one with substring(), so returning the parsed
    // value instead of the allowlist entry would hand back a fresh String and
    // fail the identity checks below.
    final fromSuffixed =
        recoveryGatewayFromRecord('$secondaryGateway/free/verify\njunk');
    final fromBare = recoveryGatewayFromRecord(secondaryGateway);

    expect(fromSuffixed, secondaryGateway);
    expect(identical(fromSuffixed, fromBare), isTrue);
    expect(
      identical(
        fromSuffixed,
        recoveryGatewayAllowlist
            .firstWhere((gateway) => gateway == secondaryGateway),
      ),
      isTrue,
    );
  });

  test('every rejection happens after the record was actually fetched',
      () async {
    for (final entry in _hostileRecords.entries) {
      var fetches = 0;
      var rejections = 0;
      final gateway = await resolveRecoveryGateway(
        'https://records.invalid/gateway.txt',
        fetchRecord: (url) async {
          fetches += 1;
          expect(url.toString(), 'https://records.invalid/gateway.txt');
          return entry.value;
        },
        onRejected: () => rejections += 1,
      );

      expect(fetches, 1, reason: entry.key);
      expect(gateway, isNull, reason: entry.key);
      expect(rejections, 1, reason: entry.key);
    }
  });

  test('a fetched in-allowlist record is accepted without a rejection',
      () async {
    var fetches = 0;
    var rejections = 0;
    final gateway = await resolveRecoveryGateway(
      'https://records.invalid/gateway.txt',
      fetchRecord: (url) async {
        fetches += 1;
        return '$secondaryGateway/verify';
      },
      onRejected: () => rejections += 1,
    );

    expect(fetches, 1);
    expect(gateway, secondaryGateway);
    expect(rejections, 0);
    expect(recoveryGatewayAllowlist, contains(gateway));
  });

  test('no record text can reach a diagnostic', () async {
    const hostile =
        'https://sync.winsvpn.org.evil.example/verify?leak=account-secret';
    final diagnostics = <String>[];
    final gateway = await resolveRecoveryGateway(
      'https://records.invalid/gateway.txt',
      fetchRecord: (_) async => hostile,
      // Mirrors the production call site: onRejected takes no arguments, so
      // the message is a fixed literal that cannot embed record bytes.
      onRejected: () => diagnostics
          .add('Rejected recovery gateway outside signed allowlist'),
    );

    expect(gateway, isNull);
    expect(diagnostics, hasLength(1));
    for (final entry in diagnostics) {
      expect(entry, isNot(contains('evil.example')));
      expect(entry, isNot(contains('leak')));
      expect(entry, isNot(contains('account-secret')));
      expect(entry, isNot(contains(hostile)));
    }
  });

  test('transport failures fall back without counting as a rejection',
      () async {
    var rejections = 0;
    expect(
      await resolveRecoveryGateway(
        'https://records.invalid/gateway.txt',
        fetchRecord: (_) async => throw const SocketException('censored'),
        onRejected: () => rejections += 1,
      ),
      isNull,
    );
    expect(rejections, 0);

    // A non-200 response reaches the resolver as a null body.
    expect(
      await resolveRecoveryGateway(
        'https://records.invalid/gateway.txt',
        fetchRecord: (_) async => null,
        onRejected: () => rejections += 1,
      ),
      isNull,
    );
    expect(rejections, 0);

    // An unparseable record URL never fetches at all.
    var fetches = 0;
    expect(
      await resolveRecoveryGateway(
        '::::not a url::::',
        fetchRecord: (_) async {
          fetches += 1;
          return 'https://sync.winsvpn.org';
        },
        onRejected: () => rejections += 1,
      ),
      isNull,
    );
    expect(fetches, 0);
    expect(rejections, 0);
  });

  test('the compiled allowlist is exactly the compiled gateway set', () {
    // The invariant is the *identity* of the two lists -- the allowlist may
    // never be a superset of what the build compiled in. The literal set is
    // pinned only for the shipping default, so a neutral build does not read as
    // a test failure.
    if (!const bool.hasEnvironment('WINS_GATEWAY_BASE') &&
        !const bool.hasEnvironment('WINS_GATEWAY_BASES') &&
        !const bool.hasEnvironment('WINS_HUB_HOST')) {
      expect(recoveryGatewayAllowlist, <String>[
        'https://a.app-cloud-sync.net',
        'https://b.app-cloud-sync.net',
        'https://c.app-cloud-sync.net',
        'https://d.app-cloud-sync.net',
        'https://e.app-cloud-sync.net',
        'https://f.app-cloud-sync.net',
        'https://g.app-cloud-sync.net',
        'https://h.app-cloud-sync.net',
        'https://i.app-cloud-sync.net',
        'https://j.app-cloud-sync.net',
        'https://k.app-cloud-sync.net',
        'https://l.app-cloud-sync.net',
        'https://m.app-cloud-sync.net',
        'https://n.app-cloud-sync.net',
        'https://o.app-cloud-sync.net',
        'https://p.app-cloud-sync.net',
        'https://q.app-cloud-sync.net',
        'https://r.app-cloud-sync.net',
        'https://s.app-cloud-sync.net',
        'https://t.app-cloud-sync.net',
        'https://u.app-cloud-sync.net',
        'https://v.app-cloud-sync.net',
        'https://w.app-cloud-sync.net',
        'https://x.app-cloud-sync.net',
        'https://y.app-cloud-sync.net',
        'https://z.app-cloud-sync.net',
        'https://sync.winsvpn.org',
        'https://sync.winsvpn.com',
        'https://hub.winsvpn.org',
      ]);
    }
    expect(recoveryGatewayAllowlist, primaryStealthGateways);
    expect(
      () => recoveryGatewayAllowlist.add('https://evil.example'),
      throwsUnsupportedError,
    );
  });

  test('compiled defaults include official censorship-resistant gateways', () {
    // Pins the SHIPPING default, so it skips itself under a re-pointed build
    // rather than making a neutral-domain migration look like a test failure.
    // The negative assertion below is the one that must hold in every build.
    if (!const bool.hasEnvironment('WINS_GATEWAY_BASE') &&
        !const bool.hasEnvironment('WINS_GATEWAY_BASES') &&
        !const bool.hasEnvironment('WINS_HUB_HOST')) {
      expect(defaultGatewayBase, 'https://a.app-cloud-sync.net');
      expect(defaultHubHost, 'hub.winsvpn.org');
      // The brand-bearing fronts are the last resort, never the first SNI.
      final firstBrand = primaryStealthGateways
          .indexWhere((g) => g.contains('winsvpn.'));
      final lastNeutral = primaryStealthGateways
          .lastIndexWhere((g) => g.endsWith('.app-cloud-sync.net'));
      expect(firstBrand, greaterThan(lastNeutral));
      expect(primaryStealthGateways, contains('https://sync.winsvpn.org'));
      expect(primaryStealthGateways, contains('https://sync.winsvpn.com'));
      expect(primaryStealthGateways, contains('https://hub.winsvpn.org'));
    }
    // The data-plane zone must never become a control-plane gateway: a CNAME
    // from the app-cloud account to the Wins-account tunnel returns Cloudflare
    // 530, and reusing it would couple control-plane availability to the data
    // plane's zone. See docs/handoff/
    // CONTROL_PLANE_NEUTRAL_DOMAIN_MIGRATION_20260806.md section 2.
    expect(primaryStealthGateways,
        isNot(contains('https://sync.app-cloud-sync.net')));
  });

  test('empty dynamic gateway falls back to official HTTPS gateways only', () {
    final urls = verifyGateways(const GatewayEndpoints(gateway: ''));

    expect(urls, isNotEmpty);
    for (final gateway in compiled) {
      expect(urls, contains('$gateway/verify'));
    }
    expect(urls.every((url) => url.startsWith('https://')), isTrue);
    expect(urls.any(_containsIpLiteral), isFalse);
  });

  group('activation credential origin binding', () {
    const gateways = <String>[
      'https://primary.example/verify',
      'https://backup-a.example/verify',
      'https://backup-b.example/verify',
    ];

    test('one-time activation secret is sent to exactly one origin', () {
      expect(
        activationAttemptGateways(
          gateways,
          hasActivationSecret: true,
        ),
        <String>[gateways.first],
      );
    });

    test('existing-device authentication retains verified failover', () {
      expect(
        activationAttemptGateways(
          gateways,
          hasActivationSecret: false,
        ),
        gateways,
      );
    });

    test('empty and singleton lists are preserved', () {
      expect(
        activationAttemptGateways(
          const <String>[],
          hasActivationSecret: true,
        ),
        isEmpty,
      );
      expect(
        activationAttemptGateways(
          const <String>['https://primary.example/verify'],
          hasActivationSecret: true,
        ),
        const <String>['https://primary.example/verify'],
      );
    });
  });

  test('node discovery uses dynamic and official hostnames without IP fallback',
      () {
    final urls = nodeDiscoveryUrls(
      const GatewayEndpoints(gateway: 'https://mirror.example.app/verify'),
    );

    expect(urls.first, 'https://mirror.example.app/nodes');
    for (final gateway in compiled) {
      expect(urls, contains('$gateway/nodes'));
    }
    expect(urls.every((url) => url.startsWith('https://')), isTrue);
    expect(urls.any(_containsIpLiteral), isFalse);
    expect(urls.length, urls.toSet().length);
  });

  test('all account routes stay on HTTPS hostname gateways', () {
    const endpoints = GatewayEndpoints(
      gateway: 'https://mirror.example.app/free/verify',
    );
    final routes = <List<String>>[
      verifyGateways(endpoints),
      accountStatusGateways(endpoints),
      legalCurrentGateways(endpoints),
      freeVerifyGateways(endpoints),
      freeStatusGateways(endpoints),
      freeLogoutGateways(endpoints),
      logoutGateways(endpoints),
    ];

    expect(routes[0].first, 'https://mirror.example.app/verify');
    expect(routes[1].first, 'https://mirror.example.app/account/status');
    expect(routes[2].first, 'https://mirror.example.app/legal/current');
    expect(routes[3].first, 'https://mirror.example.app/free/verify');
    expect(routes[4].first, 'https://mirror.example.app/free/status');
    expect(routes[5].first, 'https://mirror.example.app/free/logout');
    expect(routes[6].first, 'https://mirror.example.app/logout');
    for (final urls in routes) {
      expect(urls.every((url) => url.startsWith('https://')), isTrue);
      expect(urls.any(_containsIpLiteral), isFalse);
      expect(urls.length, urls.toSet().length);
    }
  });

  test('node discovery distinguishes empty and live valid payloads', () {
    const stale = '{"maintenance":true,"nodes":[]}';
    const live =
        '{"maintenance":false,"nodes":[{"slug":"france","status":"online"}]}';

    expect(isNodeDiscoveryPayload(stale), isTrue);
    expect(nodeDiscoveryPayloadHasNodes(stale), isFalse);
    expect(isNodeDiscoveryPayload(live), isTrue);
    expect(nodeDiscoveryPayloadHasNodes(live), isTrue);
    expect(isNodeDiscoveryPayload('<!DOCTYPE html>'), isFalse);
  });

  test('free verification classifies trusted API terminal responses', () {
    expect(
      classifyFreeVerifyTerminalFailure(
        503,
        '{"detail":"Free VPN server is not online yet."}',
      ),
      'offline',
    );
    expect(
      classifyFreeVerifyTerminalFailure(
        503,
        '{"detail":"System Maintenance underway."}',
      ),
      'maintenance',
    );
    expect(
      classifyFreeVerifyTerminalFailure(
        503,
        '{"detail":"Free VPN access is not enabled."}',
      ),
      'disabled',
    );
    expect(
      classifyFreeVerifyTerminalFailure(
        409,
        '{"detail":"Free identity collision. Please reinstall."}',
      ),
      'identity_collision',
    );
    expect(
      classifyFreeVerifyTerminalFailure(429, '<html>edge limit</html>'),
      'rate_limited',
    );
  });

  test('free verification ignores transport and untrusted HTML failures', () {
    expect(
      classifyFreeVerifyTerminalFailure(522, '<html>Cloudflare</html>'),
      isNull,
    );
    expect(
      classifyFreeVerifyTerminalFailure(503, '<html>maintenance</html>'),
      isNull,
    );
    expect(
      classifyFreeVerifyTerminalFailure(200, '{"status":"authenticated"}'),
      isNull,
    );
  });

  test('free status preflight stops only on an authoritative service state',
      () {
    expect(
      classifyFreeStatusTerminalState(
        200,
        '{"status":"unavailable","free_access":true,"free_node_slugs":[]}',
      ),
      'offline',
    );
    expect(
      classifyFreeStatusTerminalState(
        200,
        '{"status":"unavailable","free_access":false}',
      ),
      'disabled',
    );
    expect(
      classifyFreeStatusTerminalState(
        200,
        '{"status":"ok","free_access":true}',
      ),
      isNull,
    );
    expect(
      classifyFreeStatusTerminalState(522, '<html>Cloudflare</html>'),
      isNull,
    );
  });

  // Regression guard for the free-access activation preflight.
  //
  // _freeAccessPreflightTerminalKind in lib/main.dart used to build its
  // /free/status URL by hand from defaultGatewayBase and query that host alone.
  // A censored sync.winsvpn.org therefore produced null -- "nothing terminal
  // established, proceed" -- while every other control-plane call in the app
  // failed over. The user was not blocked; they were denied the early accurate
  // message and failed later at node fetch with a worse one. That is the most
  // censorship-exposed path in the product, because someone stuck on it has no
  // tunnel yet and no other way in.
  //
  // The preflight now builds its list with exactly the expression asserted
  // here. If freeStatusGateways stops covering every compiled gateway, or the
  // preflight goes back to a single hand-built URL, this fails.
  test('free-access preflight reaches every compiled gateway, not just the '
      'primary', () {
    final preflight = freeStatusGateways(
      GatewayEndpoints(gateway: gatewayBase(defaultGatewayBase)),
    );

    for (final host in primaryStealthGateways) {
      expect(
        preflight,
        contains('$host/free/status'),
        reason: 'a censored gateway must not be the end of the preflight; '
            '$host is compiled in and must be tried',
      );
    }
    expect(
      preflight.length,
      greaterThan(1),
      reason: 'a single-entry preflight is the defect this test exists for',
    );
    expect(
      preflight.first,
      '${gatewayBase(defaultGatewayBase)}/free/status',
      reason: 'the primary must still be tried first so the healthy path is '
          'unchanged and costs no extra round trip',
    );
  });

  /// `WINS_RECOVERY_RECORD_URL`. The recovery record's own URL is now
  /// build-configurable, because the compiled one carries `/winsvpn/` twice in
  /// its path and it is the channel that has to survive the gateway being
  /// blocked. An override reaches an http client, so it gets a screen.
  group('recovery record URL screen', () {
    test('accepts an ordinary https file URL', () {
      expect(
        isSafeRecoveryRecordUrl(
          'https://raw.githubusercontent.com/o/r/main/active-gateway.txt',
        ),
        isTrue,
      );
      expect(
        isSafeRecoveryRecordUrl('https://cdn.example.net/a.txt'),
        isTrue,
      );
      expect(isSafeRecoveryRecordUrl('https://cdn.example.net:443/a'), isTrue);
      expect(isSafeRecoveryRecordUrl('  https://cdn.example.net/a  '), isTrue);
    });

    test('rejects a bare origin: a record is a file, not an API root', () {
      expect(isSafeRecoveryRecordUrl('https://cdn.example.net'), isFalse);
      expect(isSafeRecoveryRecordUrl('https://cdn.example.net/'), isFalse);
    });

    test('rejects everything that is not credential-free https on 443', () {
      for (final bad in <String>[
        '',
        '   ',
        'http://cdn.example.net/a.txt',
        'ftp://cdn.example.net/a.txt',
        '//cdn.example.net/a.txt',
        'https:///a.txt',
        'https://user:pass@cdn.example.net/a.txt',
        'https://cdn.example.net:8443/a.txt',
        'https://cdn.example.net/a.txt#frag',
      ]) {
        expect(
          isSafeRecoveryRecordUrl(bad),
          isFalse,
          reason: '$bad must not be fetched',
        );
      }
    });

    test('rejects IP literals, matching the gateway screen', () {
      // Same reasoning as _isSafeHttpsGateway: a hardcoded address is a
      // permanent, unrotatable IoC that pins the infrastructure.
      expect(isSafeRecoveryRecordUrl('https://93.184.216.34/a.txt'), isFalse);
      expect(isSafeRecoveryRecordUrl('https://[2606:2800::1]/a.txt'), isFalse);
    });

    test('a query string is allowed: cache-busting is legitimate here', () {
      // Unlike a gateway origin, where a query would be smuggled state, a
      // record URL may legitimately carry ?raw or a cache buster.
      expect(
        isSafeRecoveryRecordUrl('https://cdn.example.net/a.txt?raw=1'),
        isTrue,
      );
    });

    /// B-APP-005: the shape screen above still admits any HTTPS host, and the
    /// record fetch leaves the device pre-tunnel from the user's real IP. The
    /// full screen pins the host to the compiled allowlist so a
    /// WINS_RECOVERY_RECORD_URL override may rotate the record's PATH, never
    /// its host.
    test('the full screen pins the host to the compiled allowlist', () {
      expect(recoveryRecordHostAllowlist, {'raw.githubusercontent.com'});
      expect(
        isAllowedRecoveryRecordUrl(
          'https://raw.githubusercontent.com/o/r/main/active-gateway.txt',
        ),
        isTrue,
      );
      expect(
        isAllowedRecoveryRecordUrl(
          'https://raw.githubusercontent.com/o/r/main/record.txt?raw=1',
        ),
        isTrue,
      );
      for (final bad in <String>[
        // Same shape, wrong host.
        'https://cdn.example.net/a.txt',
        // Look-alikes: matching is by equality, never by suffix.
        'https://raw.githubusercontent.com.evil.example/a.txt',
        'https://evilraw.githubusercontent.com/a.txt',
        // Shape failures still fail the composed screen.
        'http://raw.githubusercontent.com/a.txt',
        'https://raw.githubusercontent.com:8443/a.txt',
        'https://user:pass@raw.githubusercontent.com/a.txt',
        'https://raw.githubusercontent.com/a.txt#frag',
      ]) {
        expect(
          isAllowedRecoveryRecordUrl(bad),
          isFalse,
          reason: '$bad must not be fetched',
        );
      }
    });
  });
}

bool _containsIpLiteral(String value) {
  final host = Uri.tryParse(value)?.host ?? '';
  return RegExp(r'^\d{1,3}(?:\.\d{1,3}){3}$').hasMatch(host) ||
      (host.startsWith('[') && host.endsWith(']'));
}
