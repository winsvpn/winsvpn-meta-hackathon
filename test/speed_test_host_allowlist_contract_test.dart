import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// Cross-language contract for the Android native speed-test host allowlist.
//
// validatedSpeedTestUrl() in android/app/src/main/kotlin/org/winsvpn/app/
// MainActivity.kt is the only gate between a URL handed to the native
// downloader/uploader over the measureDownloadMbps / measureUploadMbps
// MethodChannel and a real outbound HTTPS fetch. The URLs it is meant to
// admit are `const` literals in _speedTestTargetsForNode (lib/main.dart),
// which is the single source of truth -- hub node data (slug/name) is only
// substring-matched there to choose WHICH hardcoded group runs and can never
// supply a URL.
//
// On 2026-08-06 the three ISP entries were narrowed from leading-dot suffix
// wildcards (".speedtest.frontier.com", ".st.charter.com" and, worst,
// ".sonic.net" -- the bare corporate zone, which accepted any host under
// Sonic's entire DNS estate including a dangling record available for
// subdomain takeover) to the exact hostnames actually used. Nothing at
// compile time keeps a Kotlin string set and a Dart string literal in
// agreement, so -- following the same pattern as
// apple_secure_state_store_native_contract_test.dart and
// linux_secure_store_native_contract_test.dart -- these tests read both
// source files as text and pin them against each other. Editing a speed-test
// hostname in lib/main.dart without updating MainActivity.kt now fails here
// instead of silently disabling the native sampler on Android.
void main() {
  // MainActivity.kt is stored with CRLF line terminators, so normalise before
  // matching on block structure.
  String read(String path) =>
      File(path).readAsStringSync().replaceAll('\r\n', '\n');

  final dartSource = read('lib/main.dart');
  final kotlinSource =
      read('android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt');

  Set<String> dartSpeedTestHosts() {
    const marker =
        'List<_SpeedTestTarget> _speedTestTargetsForNode(Map<String, dynamic>? node) {';
    final start = dartSource.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0),
        reason: '_speedTestTargetsForNode was renamed or reshaped; this '
            'contract must be repointed at the new single source of truth.');
    final end = dartSource.indexOf('\n  }\n', start);
    expect(end, greaterThan(start));
    final body = dartSource.substring(start, end);
    final hosts = RegExp("'(https://[^']+)'")
        .allMatches(body)
        .map((match) => Uri.parse(match.group(1)!).host.toLowerCase())
        .toSet();
    expect(hosts, isNotEmpty);
    return hosts;
  }

  Set<String> kotlinAllowedHosts() {
    const marker = 'private val speedTestAllowedHosts = setOf(';
    final start = kotlinSource.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0),
        reason: 'MainActivity.kt no longer declares speedTestAllowedHosts; '
            'the native allowlist must stay a single named set.');
    final end = kotlinSource.indexOf(')', start + marker.length);
    expect(end, greaterThan(start));
    final body = kotlinSource.substring(start + marker.length, end);
    return RegExp('"([^"]+)"')
        .allMatches(body)
        .map((match) => match.group(1)!.toLowerCase())
        .toSet();
  }

  test(
      'the Android allowlist is exactly the set of hosts lib/main.dart '
      'actually speed-tests, with nothing extra', () {
    expect(kotlinAllowedHosts(), equals(dartSpeedTestHosts()));
  });

  test('the upload fallback target is covered by the same allowlist', () {
    // _runSpeedTest always adds this literal to the upload candidate set, and
    // _uploadUrlForDownloadUrl only ever returns this literal or a same-host
    // rewrite of a download URL, so the download host set must cover uploads.
    expect(dartSource, contains("'https://speed.cloudflare.com/__up'"));
    expect(kotlinAllowedHosts(), contains('speed.cloudflare.com'));
  });

  test('no allowlist entry is a wildcard suffix', () {
    for (final host in kotlinAllowedHosts()) {
      expect(host.startsWith('.'), isFalse,
          reason: '"$host" is a whole-zone wildcard. Every speed-test target '
              'is a compiled-in constant, so an exact host costs nothing and '
              'a suffix entry exposes every sibling name in that zone -- '
              'including any dangling record open to subdomain takeover.');
      expect(host.split('.').length, greaterThanOrEqualTo(2));
    }
  });

  test('validatedSpeedTestUrl matches hosts exactly, not by suffix', () {
    final start = kotlinSource.indexOf(
        'private fun validatedSpeedTestUrl(rawUrl: String): URL? {');
    expect(start, greaterThanOrEqualTo(0));
    final end = kotlinSource.indexOf('\n    }\n', start);
    expect(end, greaterThan(start));
    final body = kotlinSource.substring(start, end);
    expect(body, contains('speedTestAllowedHosts.contains(host)'));
    expect(body, isNot(contains('endsWith(')),
        reason: 'suffix matching reintroduces the whole-zone surface this '
            'allowlist was narrowed to remove.');
    // Transport guards that must survive any future edit of this function.
    expect(body, contains('url.protocol != "https"'));
    expect(body, contains('url.userInfo != null'));
  });

  test('a refused speed-test URL is loud, not silently dropped', () {
    final start = kotlinSource.indexOf(
        'private fun validatedSpeedTestUrl(rawUrl: String): URL? {');
    final end = kotlinSource.indexOf('\n    }\n', start);
    final body = kotlinSource.substring(start, end);
    // Every rejection path logs before returning null.
    expect('Log.w('.allMatches(body).length, greaterThanOrEqualTo(4));
    expect(body, contains('host not allowed'));
    // The raw URL is never logged: it can carry credentials in userInfo.
    expect(body, isNot(contains(r'$rawUrl')));
    // Dart sees a distinct, host-naming failure rather than a generic one.
    expect(kotlinSource, contains('"SPEED_TEST_HOST_NOT_ALLOWED"'));
    expect(kotlinSource,
        contains('Speed-test URL rejected by the host allowlist: '));
  });
}
