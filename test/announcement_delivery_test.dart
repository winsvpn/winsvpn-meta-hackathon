import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Extracts the body of a method starting at the first occurrence of
/// [signature]. Same intent as the helper in
/// decoy_calculator_tunnel_independence_test.dart, but it first walks the
/// parameter list to parenthesis depth 0 before looking for the body's opening
/// brace -- a named-parameter block (`{ ... }`) otherwise balances on its own
/// and truncates the extract to the signature.
String _functionBody(String source, String signature) {
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'could not find $signature');

  var cursor = start;
  var parenDepth = 0;
  var sawParen = false;
  while (cursor < source.length) {
    final ch = source[cursor];
    if (ch == '(') {
      parenDepth++;
      sawParen = true;
    } else if (ch == ')') {
      parenDepth--;
      if (sawParen && parenDepth == 0) break;
    }
    cursor++;
  }
  expect(sawParen && parenDepth == 0, isTrue,
      reason: 'unterminated parameter list for $signature');

  final bodyOpen = source.indexOf('{', cursor);
  expect(bodyOpen, greaterThan(cursor), reason: 'no body for $signature');

  var depth = 0;
  for (var i = bodyOpen; i < source.length; i++) {
    if (source[i] == '{') depth++;
    if (source[i] == '}') {
      depth--;
      if (depth == 0) return source.substring(start, i + 1);
    }
  }
  fail('unterminated function for signature: $signature');
}

/// Drops `//` line comments so a prose warning that NAMES a forbidden API
/// ("never RichText/Linkify") does not read as a use of it.
String _stripLineComments(String code) => code
    .split('\n')
    .map((line) {
      final marker = line.indexOf('//');
      return marker < 0 ? line : line.substring(0, marker);
    })
    .join('\n');

/// Slice of the hub source running from the `@app.<method>("<path>")`
/// decorator for [path] up to the next route decorator, i.e. exactly one
/// route handler.
String _hubRouteBody(String source, String path) {
  final decorator =
      RegExp('@app\\.(?:get|post|put|delete|patch)\\(\\s*"${RegExp.escape(path)}"');
  final match = decorator.firstMatch(source);
  expect(match, isNotNull, reason: 'no hub route declared for $path');
  final start = match!.start;
  final next = source.indexOf('\n@app.', start + 1);
  return next < 0 ? source.substring(start) : source.substring(start, next);
}

void main() {
  final source = File('lib/main.dart').readAsStringSync();
  final gatewaySource = File('lib/gateway_failover.dart').readAsStringSync();
  final hub =
      File('server/wins_control_plane_setup_ONETOUCH.sh').readAsStringSync();

  group('announcements reach every platform', () {
    test(
        'the status heartbeat is no longer gated to Android and Apple, so a '
        'running Windows or Linux app still picks up a new announcement', () {
      // Critical finding: the heartbeat's own early-return used to read
      //   (!Platform.isAndroid && !_isApplePlatform)
      // which meant the 60s announcement/account sync never ran at all on
      // Windows or Linux. Those apps only ever saw the announcement that
      // happened to be current at launch, at login, or immediately after a
      // successful connect -- an announcement posted while the app sat open
      // was invisible until the user relaunched it.
      final heartbeat =
          _functionBody(source, 'Future<void> _runStatusHeartbeat()');
      final guardEnd = heartbeat.indexOf('_statusHeartbeatRunning = true;');
      expect(guardEnd, greaterThan(0));
      final guard = heartbeat.substring(0, guardEnd);
      expect(guard, isNot(contains('Platform.isAndroid')));
      expect(guard, isNot(contains('_isApplePlatform')));
      // The rest of the pre-existing guard must survive: an unauthenticated or
      // mid-operation app still does not poll.
      expect(guard, contains('_statusHeartbeatRunning'));
      expect(guard, contains('!_isLoggedIn'));
      expect(guard, contains('_isLoading'));
    });

    test(
        'native tunnel-state polling covers EVERY platform with a native '
        'backend, because a stale-green _isConnected on desktop is a false '
        'claim of protection', () {
      // Windows and Linux used to be excluded because the Dart connect/
      // disconnect flows owned _isConnected there. Their native backend can
      // die asynchronously (engine, interface, or manager), and an excluded
      // heartbeat then left a stale green "secured" UI forever -- the exact
      // false "connected" safety defect this lane closes. All platforms with
      // a native tunnel backend must now poll real state; only web is skipped.
      final heartbeat =
          _functionBody(source, 'Future<void> _runStatusHeartbeat()');
      final pollGate = heartbeat.indexOf('pollsNativeTunnelState');
      expect(pollGate, greaterThan(0),
          reason: 'native tunnel polling must remain explicitly scoped');
      expect(heartbeat, contains('_supportsNativeTunnelReadiness'));
      expect(
        heartbeat,
        isNot(contains('Platform.isAndroid || _isApplePlatform')),
        reason: 'the old Android/Apple-only crate gate must not come back',
      );
      final activeRead = heartbeat.indexOf('_readNativeTunnelActive()');
      expect(activeRead, greaterThan(pollGate),
          reason: 'the native read must sit inside the scoped branch');
    });
  });

  group('announcements reach a DISCONNECTED app', () {
    test('the announcement sync is not gated on an active tunnel', () {
      // Critical finding: announcementSyncDue used to be `active && ...`, so
      // the one announcement that matters most -- "this route is blocked,
      // switch to node X" -- was only ever fetched by users whose tunnel was
      // already working, i.e. the users who did not need it.
      final heartbeat =
          _functionBody(source, 'Future<void> _runStatusHeartbeat()');
      final start = heartbeat.indexOf('final announcementSyncDue');
      expect(start, greaterThan(0));
      final due = heartbeat.substring(start, heartbeat.indexOf(';', start));
      expect(due, isNot(contains('active')));
      expect(due, contains('_lastAnnouncementSync'));
    });

    test('a down tunnel routes to a real announcement refresh', () {
      final heartbeat =
          _functionBody(source, 'Future<void> _runStatusHeartbeat()');
      expect(heartbeat, contains('_refreshAnnouncementsWhileDisconnected('));
      expect(heartbeat, contains('expectedEpoch: heartbeatEpoch'));
    });

    test(
        'the disconnected refresh actually presents the announcement instead '
        'of only updating a background field', () {
      final disconnected = _functionBody(
          source, 'Future<void> _refreshAnnouncementsWhileDisconnected(');
      // It must ride the account/free status call (which carries the same
      // `announcement` field) rather than adding a second poll...
      expect(disconnected, contains('_refreshAccountStatus('));
      expect(disconnected, contains('force: true'));
      expect(disconnected, contains('expectedEpoch: operationEpoch'));
      expect(disconnected, isNot(contains('_fetchAvailableNodes')));
      // ...and it must reach the popup/notification presenter.
      expect(disconnected, contains('_presentAnnouncementUpdate('));
      // Only a genuine owner-posted announcement may raise a modal on this
      // path, so an ordinary offline start does not pop the seeded welcome.
      expect(disconnected, contains('requireNotifiableForPopup: true'));
    });

    test('the presenter no longer requires a connected tunnel', () {
      // _refreshAnnouncementsAfterConnect used to bail on `!_isConnected`
      // before it could show anything.
      final presenter =
          _functionBody(source, 'void _presentAnnouncementUpdate(');
      expect(presenter, isNot(contains('_isConnected')));
      expect(presenter, contains('_showAnnouncementWindow('));
      expect(presenter, contains('_maybeNotifyServerAnnouncement('));
    });
  });

  group('the announcement channel cannot be turned against the user', () {
    test('the popup is never raised over the decoy calculator', () {
      // A modal titled "Win's VPN Announcement" on top of the calculator
      // disguise would expose the user in exactly the environment the
      // disguise exists for. Same rule as _promptForMandatoryPinReset.
      final popup = _functionBody(source, 'void _showAnnouncementWindow(');
      expect(popup, contains('_showDecoyCalculator'));
      final guard = popup.indexOf('_showDecoyCalculator');
      final show = popup.indexOf('showDialog<void>(');
      expect(show, greaterThan(guard),
          reason: 'the decoy guard must precede the dialog');
    });

    test(
        'server-supplied announcement text is never rendered by a link-aware '
        'widget', () {
      // Possession of the admin token is enough to push arbitrary text to
      // every user (there is no signature on the payload), so the text must
      // never be able to become a tappable "download the update here" link.
      const forbidden = [
        'RichText',
        'Linkify',
        'SelectableText',
        'TextSpan',
        'recognizer',
        'launchUrl',
        'Uri.parse',
      ];
      final popup = _stripLineComments(
          _functionBody(source, 'void _showAnnouncementWindow('));
      for (final api in forbidden) {
        expect(popup, isNot(contains(api)),
            reason: 'announcement popup must stay plain Text');
      }
      expect(popup, contains('Text(_boundedAnnouncementText(message))'));

      // Same for the always-visible dashboard banner.
      final banner =
          source.indexOf('_boundedAnnouncementText(_serverAnnouncement)');
      expect(banner, greaterThan(0),
          reason: 'dashboard banner must render the bounded plain string');
      final bannerSlice =
          _stripLineComments(source.substring(banner - 400, banner + 200));
      for (final api in forbidden) {
        expect(bannerSlice, isNot(contains(api)));
      }
    });

    test('Linux notification bodies are markup-escaped, other platforms are not',
        () {
      // Freedesktop notification bodies are parsed as a markup subset, and
      // daemons advertising body-hyperlinks render <a href="..."> as a
      // CLICKABLE link -- the one place attacker-controlled announcement text
      // could become a tappable URL. Escaping happens once, in Dart, so it
      // covers both the native notify-send path and the Dart fallback; double
      // escaping in the native layer would show users literal "&amp;".
      final notify = _functionBody(
          source, 'Future<bool> _showSystemAnnouncementNotification(');
      expect(notify, contains('Platform.isLinux'));
      expect(notify, contains('_escapeNotificationBodyMarkup('));

      final escape =
          _functionBody(source, 'static String _escapeNotificationBodyMarkup(');
      expect(escape, contains(r"replaceAll('&', '&amp;')"));
      expect(escape, contains(r"replaceAll('<', '&lt;')"));
      expect(escape, contains(r"replaceAll('>', '&gt;')"));
      // Ampersand must be escaped first or the entities themselves get mangled.
      expect(escape.indexOf(r"replaceAll('&', '&amp;')"),
          lessThan(escape.indexOf(r"replaceAll('<', '&lt;')")));

      // The native Linux handler must NOT escape again.
      final linuxNative =
          File('linux/runner/linux_tunnel_backend.cc').readAsStringSync();
      final linuxNotify = linuxNative.substring(
          linuxNative.indexOf('bool ShowAnnouncementNotification('));
      expect(linuxNotify.substring(0, 1200), isNot(contains('&amp;')));
    });

    test('announcement text is length-bounded everywhere it is rendered', () {
      final bounded =
          _functionBody(source, 'String _boundedAnnouncementText(');
      expect(bounded, contains('_maxAnnouncementDisplayChars'));
      expect(source, contains('static const int _maxAnnouncementDisplayChars'));
      // Popup, banner and system notification all go through it.
      expect('_boundedAnnouncementText('.allMatches(source).length,
          greaterThanOrEqualTo(4));
    });
  });

  group('the hub still carries the announcement to the routes clients poll',
      () {
    test('/admin/announce exists and is admin-token gated', () {
      final route = _hubRouteBody(hub, '/admin/announce');
      expect(route, contains('x_admin_token'));
      expect(route, contains('require_admin_token'));
      // Since the 2026-09-29 key-custody ruling the hub holds no signer: the
      // route verifies an offline-signed envelope (store_verified_announcement)
      // and, only while ANNOUNCE_REQUIRE_SIGNED=0, still accepts plaintext
      // (store_unsigned_announcement). Both helpers perform the set_setting on
      // "global_announcement".
      expect(route, contains('store_verified_announcement('));
      expect(route, contains('store_unsigned_announcement(conn, msg)'));
    });

    test('nginx proxies /admin/ to the hub instead of the static site', () {
      // Another lane found nginx proxies only an explicit path list, with
      // everything else falling through to `try_files ... /index.html` -- the
      // static SITE, not FastAPI. A missing location here silently 200s an
      // HTML page at an API path.
      final start = hub.indexOf('cat > /etc/nginx/snippets/wins-hub-locations.conf');
      expect(start, greaterThan(0));
      final locations = hub.substring(start, hub.indexOf('\nEOF', start));
      // F-12 turned the single-line location into a multi-line block that
      // adds edge load shedding ahead of the same proxy_pass; the contract
      // stays: /admin/ must proxy to the hub, never fall through to the
      // static site.
      expect(
        locations,
        matches(RegExp(
            r'location /admin/ \{[^}]*proxy_pass http://127\.0\.0\.1:8000',
            dotAll: true)),
      );
      // ...and so is every route that carries the announcement back to a client.
      expect(locations, contains('location = /nodes { proxy_pass'));
      expect(locations, contains('location = /account/status { proxy_pass'));
      expect(locations, contains('location = /verify {'));
      expect(locations, contains('location /free/ { proxy_pass'));
    });

    test(
        'every hub route the client polls for account state returns the '
        'announcement field', () {
      // The overlap that makes the feature live: these are exactly the
      // suffixes gateway_failover.dart builds URLs for.
      for (final path in const [
        '/nodes',
        '/account/status',
        '/verify',
        '/free/status',
      ]) {
        expect(gatewaySource, contains("'$path'"),
            reason: '$path must still be a client-polled endpoint');
        // Since the signing lane these routes emit the announcement through
        // announcement_fields(conn), which returns the plaintext
        // "announcement" key plus the signature envelope. Accept either shape
        // so this stays a test about reach, not about the emission mechanism.
        final route = _hubRouteBody(hub, path);
        expect(
            route.contains('"announcement"') ||
                route.contains('**announcement_fields(conn)'),
            isTrue,
            reason: '$path must carry the announcement to clients');
      }
    });

    test(
        'the client default announcement matches the hub seed byte for byte, '
        'so the Burmese translation actually triggers', () {
      // _localizedAnnouncement only translates on an EXACT match against
      // _defaultAnnouncement. If the hub seed drifts by one character, every
      // Burmese-locale user silently falls back to English.
      final clientDefault = RegExp(
              r'static const String _defaultAnnouncement =\s*\n?\s*"([^"]+)"')
          .firstMatch(source);
      expect(clientDefault, isNotNull);
      final hubDefault =
          RegExp(r'WELCOME_MESSAGE_DEFAULT = "([^"]+)"').firstMatch(hub);
      expect(hubDefault, isNotNull);
      expect(clientDefault!.group(1), equals(hubDefault!.group(1)));
    });
  });
}
