import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Android TV must never ship disguised as Calculator.
///
/// Measures three independent artifacts, not a document:
///   1. `android/app/src/tv/AndroidManifest.xml` (flavor overlay)
///   2. the AGP-merged tvRelease manifest, when the build has produced it
///   3. `aapt dump badging` of the tv release APK, when both exist
///
/// Phone `src/main` is the negative control: it MUST still say Calculator,
/// so a test that cannot see a disguise cannot pass this file.
void main() {
  final tvSource = File('android/app/src/tv/AndroidManifest.xml');
  final phoneSource = File('android/app/src/main/AndroidManifest.xml');
  final tvReleaseMerged = File(
    'build/app/intermediates/merged_manifests/tvRelease/'
    'processTvReleaseManifest/AndroidManifest.xml',
  );
  final tvReleaseApk = File(
    'build/app/outputs/apk/tv/release/app-tv-release.apk',
  );
  final vpnTunnel = File(
    'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
  );
  final mainActivity = File(
    'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
  );

  test('TV source overlay application label is the real product, never Calculator',
      () {
    expect(tvSource.existsSync(), isTrue,
        reason: 'android/app/src/tv/AndroidManifest.xml must exist');
    final xml = _stripComments(tvSource.readAsStringSync());
    expect(
      _applicationLabel(xml),
      anyOf("Win's VPN", "Win&apos;s VPN"),
      reason: 'TV overlay android:label must be the real product name',
    );
    expect(
      xml.contains('android:label="Calculator"'),
      isFalse,
      reason: 'TV overlay must never carry the disguised application label',
    );
  });

  test('phone main manifest is still disguised — negative control', () {
    expect(phoneSource.existsSync(), isTrue);
    final xml = _stripComments(phoneSource.readAsStringSync());
    expect(
      _applicationLabel(xml),
      'Calculator',
      reason: 'if this is not Calculator the TV test cannot see a disguise',
    );
  });

  test('merged tvRelease application label is the real product and decoy is off',
      () {
    if (!tvReleaseMerged.existsSync()) {
      markTestSkipped(
        'tv release artifacts not built in this checkout; run '
        'flutter build apk --flavor tv --release '
        '(or ./gradlew :app:processTvReleaseManifest from android/) '
        'and re-run to exercise the merged tvRelease manifest; '
        'a clean clone has no build/app/intermediates tree. '
        'If the artifact is absent the merged-manifest assertions cannot run, '
        'so a built tree still gets the real check.',
      );
      return;
    }
    final xml = _stripComments(tvReleaseMerged.readAsStringSync());
    expect(
      _applicationLabel(xml),
      anyOf("Win's VPN", "Win&apos;s VPN"),
      reason: 'merged tvRelease application label must survive as the real name',
    );
    final decoy = _activityAliasBlock(xml, 'LauncherDecoy');
    if (decoy != null) {
      expect(
        decoy.contains('android:enabled="true"'),
        isFalse,
        reason: 'LauncherDecoy must not be enabled in the merged TV manifest',
      );
      expect(
        decoy.contains('android:enabled="false"'),
        isTrue,
        reason: 'LauncherDecoy must be explicitly disabled on TV',
      );
    }
  });

  test('tv release APK badging application-label is Win\'s VPN, not Calculator',
      () {
    if (!tvReleaseApk.existsSync()) {
      markTestSkipped(
        'tv release artifacts not built in this checkout; run '
        'flutter build apk --flavor tv --release '
        'and re-run to exercise the APK badging assertions. '
        'The APK exists only after a tv release build, so a clean clone '
        'has nothing to badge; a built tree still gets the real check.',
      );
      return;
    }
    final aapt = _aapt();
    expect(aapt, isNotNull, reason: 'aapt not found under ANDROID_SDK_ROOT');
    final proc = Process.runSync(aapt!, ['dump', 'badging', tvReleaseApk.path]);
    expect(proc.exitCode, 0, reason: 'aapt dump badging failed: ${proc.stderr}');
    final out = proc.stdout as String;
    expect(
      out.contains("application-label:'Win's VPN'"),
      isTrue,
      reason: 'APK badging must report application-label Win\'s VPN',
    );
    expect(
      out.contains("application-label:'Calculator'"),
      isFalse,
      reason: 'APK badging must not report Calculator as the application label',
    );
    expect(
      out.contains("leanback-launchable-activity: name='org.winsvpn.app.MainActivity'"),
      isTrue,
      reason: 'leanback launchable must be MainActivity, not the decoy',
    );
  });

  test('MainActivity and VpnTunnelService both refuse to arm camouflage on TV',
      () {
    final activity = mainActivity.readAsStringSync();
    final triggerAt = activity.indexOf('"triggerCamouflageSwap"');
    expect(triggerAt, greaterThanOrEqualTo(0),
        reason: 'MainActivity must handle triggerCamouflageSwap');
    final trigger = activity.substring(
      triggerAt,
      triggerAt + 400 > activity.length ? activity.length : triggerAt + 400,
    );
    expect(trigger, contains('isTelevision()'),
        reason: 'triggerCamouflageSwap must refuse on TV');

    final service = vpnTunnel.readAsStringSync();
    final setter = _functionBody(
      service,
      'private fun setLauncherComponentState(showRealVpn: Boolean)',
      indentSpaces: 4,
    );
    expect(
      setter,
      contains('isTelevision()'),
      reason: 'VpnTunnelService.setLauncherComponentState must refuse to '
          'enable the decoy on TV; teardown defaults keepVpnLauncher=false',
    );
    expect(service, contains('UI_MODE_TYPE_TELEVISION'));
    expect(service, contains('FEATURE_LEANBACK'));
  });
}

String _stripComments(String xml) =>
    xml.replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');

String? _applicationLabel(String xml) {
  final app = RegExp(r'<application\b[^>]*>', dotAll: true).firstMatch(xml);
  if (app == null) return null;
  final label = RegExp(r'android:label="([^"]*)"').firstMatch(app.group(0)!);
  return label?.group(1);
}

String? _activityAliasBlock(String xml, String name) {
  final re = RegExp(
    r'<activity-alias\b[^>]*android:name="[^"]*' +
        RegExp.escape(name) +
        r'"[^>]*>',
    dotAll: true,
  );
  // name may appear before or after other attributes; also try name-first
  var m = re.firstMatch(xml);
  m ??= RegExp(
    r'<activity-alias\b[^>]*>',
    dotAll: true,
  ).allMatches(xml).cast<RegExpMatch?>().firstWhere(
        (block) => block!.group(0)!.contains(name),
        orElse: () => null,
      );
  if (m == null) {
    // Attribute order: enabled before name. Grab each alias and filter.
    for (final block in RegExp(r'<activity-alias\b[^>]*/?>', dotAll: true)
        .allMatches(xml)) {
      if (block.group(0)!.contains(name)) return block.group(0);
    }
    return null;
  }
  return m.group(0);
}

String? _aapt() {
  final sdk = Platform.environment['ANDROID_SDK_ROOT'] ??
      Platform.environment['ANDROID_HOME'];
  if (sdk == null || sdk.trim().isEmpty) return null;
  final candidate = File('$sdk/build-tools/36.0.0/aapt');
  if (candidate.existsSync()) return candidate.path;
  final bt = Directory('$sdk/build-tools');
  if (!bt.existsSync()) return null;
  final versions = bt
      .listSync()
      .whereType<Directory>()
      .map((d) => File('${d.path}/aapt'))
      .where((f) => f.existsSync())
      .toList();
  if (versions.isEmpty) return null;
  versions.sort((a, b) => a.path.compareTo(b.path));
  return versions.last.path;
}

String _functionBody(String source, String signature, {int indentSpaces = 8}) {
  final closer = '\n${' ' * indentSpaces}}';
  final start = source.indexOf(signature);
  expect(start, greaterThanOrEqualTo(0), reason: 'could not find $signature');
  var cursor = source.indexOf(closer, start);
  while (cursor >= 0) {
    final candidate = source.substring(start, cursor + closer.length);
    final opens = '{'.allMatches(candidate).length;
    final closes = '}'.allMatches(candidate).length;
    if (opens == closes) return candidate;
    cursor = source.indexOf(closer, cursor + closer.length);
  }
  fail('unterminated function for signature: $signature');
}
