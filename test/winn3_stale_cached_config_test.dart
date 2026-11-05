import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

// 2026-09-26 (Round CM, lane L60): an explicit-node client kept a winn/3
// config fetched while us-chicago1 planned at path MTU 1450. The operator
// moved the node to 1400, the fast path never asked the hub again, and every
// tap failed with ErrPathMTUMismatch, across restarts. These tests pin the
// three rules that end that: a fetch stamp with a bounded age, a stale mark
// on terminal failure that keeps the document for offline use, and one
// fresh-config retry only when the hub's plan actually changed.

final DateTime _now = DateTime.utc(2026, 9, 26, 14, 19, 5);

Map<String, dynamic> _cachedV3({
  String slug = 'us-chicago1',
  String pathMtu = '1450',
  Map<String, dynamic>? descriptor,
}) {
  return <String, dynamic>{
    'protocol_version': kWinnProtocolV3,
    'node_slug': slug,
    'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
    'server_endpoint': '198.51.100.7:9110',
    'winn3_path_mtu': pathMtu,
    'winn3_carrier_classes': 'udp',
    if (descriptor != null) 'winn3_descriptor': descriptor,
  };
}

Map<String, dynamic> _descriptorExpiringAt(DateTime notAfter) {
  final payload = jsonEncode(<String, dynamic>{
    'v': 1,
    'iat': notAfter.subtract(const Duration(days: 7)).millisecondsSinceEpoch ~/
        1000,
    'not_after': notAfter.millisecondsSinceEpoch ~/ 1000,
  });
  return <String, dynamic>{
    'payload': base64.encode(utf8.encode(payload)),
    'sig': 'unverified-here',
  };
}

Map<String, dynamic> _fetchedAgo(Duration age, Map<String, dynamic> config) =>
    stampVpnConfigFetchedAt(config, _now.subtract(age));

bool _skips(Map<String, dynamic>? config, {bool automatic = false}) =>
    maySkipControlPlaneRefreshWithCachedConfig(
      cachedConfig: config,
      automaticMode: automatic,
      coverExactTarget: false,
      now: _now,
    );

String _methodBody(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production method: $start');
  }
  return source.substring(first, last);
}

void main() {
  group('fast path stays fast while the cache is fresh', () {
    test('a freshly fetched explicit v3 cache still skips the hub', () {
      expect(
          _skips(_fetchedAgo(const Duration(minutes: 1), _cachedV3())), isTrue);
      expect(
          _skips(_fetchedAgo(
              kWinn3CachedConfigMaxAge - const Duration(seconds: 1),
              _cachedV3())),
          isTrue);
    });

    test('a valid descriptor far from not_after does not force a refresh', () {
      final config = _fetchedAgo(
        const Duration(minutes: 5),
        _cachedV3(
            descriptor:
                _descriptorExpiringAt(_now.add(const Duration(days: 3)))),
      );
      expect(_skips(config), isTrue);
    });

    test('an unreadable descriptor payload falls back to the stamp alone', () {
      final config = _fetchedAgo(
        const Duration(minutes: 5),
        _cachedV3(descriptor: <String, dynamic>{
          'payload': '%%% not base64 %%%',
          'sig': 'x',
        }),
      );
      expect(_skips(config), isTrue);
    });

    test('automatic and cover-exact still never skip, fresh or not', () {
      final fresh = _fetchedAgo(const Duration(minutes: 1), _cachedV3());
      expect(_skips(fresh, automatic: true), isFalse);
      expect(
        maySkipControlPlaneRefreshWithCachedConfig(
          cachedConfig: fresh,
          automaticMode: false,
          coverExactTarget: true,
          now: _now,
        ),
        isFalse,
      );
    });
  });

  group('a stale cache asks the hub first', () {
    test('a cache with no fetch stamp (every pre-fix cache) refreshes', () {
      expect(_skips(_cachedV3()), isFalse);
      expect(
        cachedConfigIsExplicitWinn3FastPathCandidate(
          cachedConfig: _cachedV3(),
          automaticMode: false,
          coverExactTarget: false,
        ),
        isTrue,
        reason: 'it is still the explicit v3 cache, only not fresh',
      );
    });

    test('a cache at or past the age bound refreshes', () {
      expect(
          _skips(_fetchedAgo(kWinn3CachedConfigMaxAge, _cachedV3())), isFalse);
      expect(
          _skips(_fetchedAgo(const Duration(hours: 18), _cachedV3())), isFalse,
          reason: 'no age is unbounded any more');
    });

    test('a stamp from the future beyond the skew allowance refreshes', () {
      final ahead = stampVpnConfigFetchedAt(_cachedV3(),
          _now.add(kVpnConfigFetchedAtFutureSkew + const Duration(seconds: 1)));
      expect(_skips(ahead), isFalse);
      final slightlyAhead = stampVpnConfigFetchedAt(
          _cachedV3(), _now.add(const Duration(minutes: 1)));
      expect(_skips(slightlyAhead), isTrue);
    });

    test('a non-integer or zero stamp is not fresh', () {
      expect(_skips(_cachedV3()..[kVpnConfigFetchedAtKey] = '1758895200000'),
          isFalse);
      expect(_skips(_cachedV3()..[kVpnConfigFetchedAtKey] = 0), isFalse);
    });

    test('a descriptor at or near not_after refreshes before verification', () {
      for (final notAfter in <DateTime>[
        _now.subtract(const Duration(minutes: 1)),
        _now.add(kWinn3CachedDescriptorExpiryMargin),
      ]) {
        final config = _fetchedAgo(
          const Duration(minutes: 5),
          _cachedV3(descriptor: _descriptorExpiringAt(notAfter)),
        );
        expect(_skips(config), isFalse, reason: 'not_after $notAfter');
      }
    });

    test('marking stale drops only the stamp and keeps the document', () {
      final fresh = _fetchedAgo(const Duration(minutes: 1), _cachedV3());
      final stale = markVpnConfigStale(fresh);
      expect(stale.containsKey(kVpnConfigFetchedAtKey), isFalse);
      expect(_skips(stale), isFalse);
      expect(Map<String, dynamic>.from(fresh)..remove(kVpnConfigFetchedAtKey),
          equals(stale));
      expect(fresh.containsKey(kVpnConfigFetchedAtKey), isTrue,
          reason: 'the input map is not mutated');
    });
  });

  group('censorship resilience: a stale cache remains usable offline', () {
    test('explicit stale v3 cache leads when the hub cannot be reached', () {
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: markVpnConfigStale(_cachedV3()),
          listingNode: null,
          automaticMode: false,
          coverExactTarget: false,
          explicitFastPathCandidate: true,
        ),
        isTrue,
      );
    });

    test('without the explicit candidate the old explicit refusal holds', () {
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: _cachedV3(),
          listingNode: null,
          automaticMode: false,
          coverExactTarget: false,
        ),
        isFalse,
      );
    });

    test('the candidate never widens cover-exact or persisted v1', () {
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: _cachedV3(),
          listingNode: null,
          automaticMode: false,
          coverExactTarget: true,
          explicitFastPathCandidate: true,
        ),
        isFalse,
      );
      expect(
        mayLeadWithCachedConfigAfterRefreshFailure(
          cachedConfig: <String, dynamic>{
            'protocol_version': kWinnProtocolV1,
            'node_slug': 'us-chicago1',
          },
          listingNode: null,
          automaticMode: false,
          coverExactTarget: false,
          explicitFastPathCandidate: true,
        ),
        isFalse,
      );
    });
  });

  group('terminal failure: one fresh refresh, retry only on a changed plan',
      () {
    test('a changed path MTU is a changed plan', () {
      expect(
        winn3ServedPlanChanged(
          previous: _cachedV3(pathMtu: '1450'),
          current: _cachedV3(pathMtu: '1400'),
        ),
        isTrue,
      );
    });

    test('a rotated descriptor or changed carrier classes is a changed plan',
        () {
      final old = _cachedV3(
          descriptor: _descriptorExpiringAt(_now.add(const Duration(days: 1))));
      final rotated = _cachedV3(
          descriptor: _descriptorExpiringAt(_now.add(const Duration(days: 9))));
      expect(winn3ServedPlanChanged(previous: old, current: rotated), isTrue);
      expect(
        winn3ServedPlanChanged(
          previous: _cachedV3(),
          current: _cachedV3()..['winn3_carrier_classes'] = 'udp,tcp',
        ),
        isTrue,
      );
    });

    test('stamp, client keys and map key order are not a plan change', () {
      final cached = _fetchedAgo(const Duration(hours: 5), _cachedV3())
        ..['client_private_key'] = 'a'
        ..['protocol_params'] = <String, dynamic>{
          'carrier': kWinnCarrierWinn3,
          'suite': 'x',
        };
      final fresh = stampVpnConfigFetchedAt(_cachedV3(), _now)
        ..['client_private_key'] = 'b'
        ..['protocol_params'] = <String, dynamic>{
          'suite': 'x',
          'carrier': kWinnCarrierWinn3,
        };
      expect(winn3ServedPlanChanged(previous: cached, current: fresh), isFalse);
    });

    test('only a fast-path config, and only once per tap, may retry', () {
      expect(
        winn3TerminalFailureMayRetryWithFreshConfig(
            configFromFastPath: true, retryAlreadyUsed: false),
        isTrue,
      );
      expect(
        winn3TerminalFailureMayRetryWithFreshConfig(
            configFromFastPath: true, retryAlreadyUsed: true),
        isFalse,
      );
      expect(
        winn3TerminalFailureMayRetryWithFreshConfig(
            configFromFastPath: false, retryAlreadyUsed: false),
        isFalse,
        reason: 'a config the hub just served is not stale',
      );
    });
  });

  group('main.dart wiring', () {
    final source = File('lib/main.dart').readAsStringSync();

    test(
        'every accepted hub config is stamped, and the stamp survives '
        'normalization', () {
      expect('stampVpnConfigFetchedAt('.allMatches(source).length, 4);
      // Activation, the free-access refresh, and both account refresh
      // branches of the per-selection refresh.
      final activation = _methodBody(
        source,
        '  Future<void> _onAuthSuccess(',
        '  Future<bool> _refreshFreeVpnConfig({',
      );
      expect('stampVpnConfigFetchedAt('.allMatches(activation).length, 1);
      final refresh = _methodBody(
        source,
        '  Future<bool> _refreshFreeVpnConfig({',
        '  Future<void> _connectWithSmartProtocol({',
      );
      expect('stampVpnConfigFetchedAt('.allMatches(refresh).length, 3);
      final normalize = _methodBody(
        source,
        '  Map<String, dynamic> _normalizeVpnConfig(',
        '  bool _hasUsableVpnConfig(',
      );
      expect(normalize, contains('raw[kVpnConfigFetchedAtKey]'));
      expect(normalize, contains('config[kVpnConfigFetchedAtKey] = fetchedAt'));
    });

    test(
        'the terminal lead branch retries once, then marks stale, before '
        'the unchanged failure message', () {
      final connect = _methodBody(
        source,
        'Future<void> _connectWithSmartProtocol(',
        'Future<void> _toggleVpnConnection()',
      );
      final refusal =
          connect.indexOf('if (_lastTunnelCandidateWasSecurityRefusal) {');
      final retry = connect.indexOf(
          'winn3TerminalFailureMayRetryWithFreshConfig(', refusal);
      final changed = connect.indexOf('winn3ServedPlanChanged(', retry);
      final latch =
          connect.indexOf('_winn3FreshConfigRetryInProgress = true;', changed);
      final stale =
          connect.indexOf('await _markCachedVpnConfigStale();', latch);
      final message = connect.indexOf(
          "'The secure Winn Protocol® connection could not be established. '",
          stale);
      expect(refusal, greaterThanOrEqualTo(0));
      expect(retry, greaterThan(refusal));
      expect(changed, greaterThan(retry));
      expect(latch, greaterThan(changed));
      expect(stale, greaterThan(latch));
      expect(message, greaterThan(stale));
      expect(
        connect,
        contains('explicitFastPathCandidate: cachedExplicitV3Candidate,'),
      );
      expect(
        connect,
        contains('directConfigFromFastPath && !directConfigFromFreshHub'),
      );
    });
  });
}
