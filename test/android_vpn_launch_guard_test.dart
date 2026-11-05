import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Xray is refused before DNS, carrier launch, and performance locks', () {
    final source = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();
    final start = source.indexOf('override fun onStartCommand(');
    expect(start, greaterThanOrEqualTo(0));
    final service = source.substring(start);
    final refusal = service.indexOf('if (xrayEnabled) {');
    final refusalEnd = service.indexOf('return START_NOT_STICKY', refusal);
    expect(refusal, greaterThanOrEqualTo(0));
    expect(refusalEnd, greaterThan(refusal));
    final block = service.substring(refusal, refusalEnd);
    expect(block, contains('refuseWinn3Start('));
    expect(block, contains('clearRestartConfig()'));
    expect(block, contains('executeTunnelTeardown()'));
    for (final operation in [
      'startXrayTransportIfNeeded(config)',
      'DnsConfig.parse(rawDnsConfig)',
      'acquireTunnelPerformanceLocks()',
    ]) {
      expect(service.indexOf(operation), greaterThan(refusalEnd));
    }
    expect(service, isNot(contains('xrayRequiresProtectedCarrier')));
  });

  test('teardown timeout refuses connect before mutable state is reset', () {
    final source = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();
    final start = source.indexOf('override fun onStartCommand(');
    expect(start, greaterThanOrEqualTo(0));
    final service = source.substring(start);
    final guard = service.indexOf('if (!awaitTeardown(2500L)) {');
    final reset = service.indexOf('resetTunnelBeforeConnect()');
    expect(guard, greaterThanOrEqualTo(0));
    expect(reset, greaterThan(guard));
    final end = service.indexOf('\n                }', guard);
    expect(end, greaterThan(guard));
    expect(end, lessThan(reset));
    expect(service.substring(guard, end), contains('return START_NOT_STICKY'));
  });

  test('Android VPN authorization and service launches are deduplicated', () {
    final activity = File(
      'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
    ).readAsStringSync();
    final service = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();
    final manifest = File(
      'android/app/src/main/AndroidManifest.xml',
    ).readAsStringSync();

    expect(activity, contains('private var vpnAuthorizationPending = false'));
    expect(activity, contains('Duplicate tunnel start request ignored.'));
    expect(activity, contains('Duplicate VPN authorization result ignored.'));
    expect(activity, contains('now - lastTunnelStartRequestAtMs < 1_500L'));
    expect(activity, contains('cancelPendingVpnAuthorization()'));
    expect(activity, contains('"CONNECT_CANCELLED"'));

    final stopHandler = activity.indexOf('"stopTunnel" -> {');
    final cancelPending = activity.indexOf(
      'cancelPendingVpnAuthorization()',
      stopHandler,
    );
    final teardownSignal = activity.indexOf(
      'startService(disconnectIntent)',
      stopHandler,
    );
    expect(stopHandler, greaterThanOrEqualTo(0));
    expect(cancelPending, greaterThan(stopHandler));
    expect(cancelPending, lessThan(teardownSignal));

    expect(activity, isNot(contains('File("/proc/net/dev")')));

    final authorizationGuard =
        activity.indexOf('if (!vpnAuthorizationPending)');
    final authorizationLaunch = activity.indexOf(
      'Log.i(VpnTunnelService.LOG_TAG, "Android VPN authorization was granted.")',
    );
    expect(authorizationGuard, greaterThanOrEqualTo(0));
    expect(authorizationGuard, lessThan(authorizationLaunch));

    expect(
      service,
      contains(
        'ACTION_CONNECT received while teardown is in flight; awaiting completion.',
      ),
    );
    final duplicateIntentGuard = service.indexOf(
      'if (action == "ACTION_CONNECT" || action == null || '
      'action == VpnService.SERVICE_INTERFACE)',
    );
    final resetBeforeConnect = service.indexOf('resetTunnelBeforeConnect()');
    expect(duplicateIntentGuard, greaterThanOrEqualTo(0));
    expect(duplicateIntentGuard, lessThan(resetBeforeConnect));

    // OI-10 (Round 36 treaty): the exported Telephony.SECRET_CODE receiver
    // was removed because the dialer code *#*#9467#*#* fingerprinted the
    // covert app in an extractable manifest. Pin its absence, not its old
    // launch path.
    expect(
      File('android/app/src/main/kotlin/org/winsvpn/app/SecretCodeReceiver.kt')
          .existsSync(),
      isFalse,
    );
    expect(manifest, isNot(contains('.SecretCodeReceiver"')));
    expect(
      manifest,
      isNot(contains(
          '<action android:name="android.provider.Telephony.SECRET_CODE"')),
    );
    expect(manifest, isNot(contains('android_secret_code')));
  });

  test('installed-app visibility is user-triggered and consent-gated', () {
    final dart = File('lib/main.dart').readAsStringSync();

    final initStart = dart.indexOf('void initState()');
    final initEnd = dart.indexOf(
      'Future<void> _loadInstalledAppsForSplitTunnel()',
      initStart,
    );
    expect(initStart, greaterThanOrEqualTo(0));
    expect(initEnd, greaterThan(initStart));
    expect(
      dart.substring(initStart, initEnd),
      isNot(contains('_loadInstalledAppsForSplitTunnel()')),
    );

    expect(
      dart,
      contains('onTap: () => unawaited(_toggleSplitTunnelPanel())'),
    );
    final toggleStart = dart.indexOf('Future<void> _toggleSplitTunnelPanel()');
    final consentCheck = dart.indexOf(
      'await _ensureAndroidPackageVisibilityConsent()',
      toggleStart,
    );
    final expandPanel = dart.indexOf(
      'setState(() => _splitTunnelExpanded = true)',
      toggleStart,
    );
    final enumerateApps = dart.indexOf(
      'unawaited(_loadInstalledAppsForSplitTunnel())',
      toggleStart,
    );
    expect(toggleStart, greaterThanOrEqualTo(0));
    expect(consentCheck, greaterThan(toggleStart));
    expect(expandPanel, greaterThan(consentCheck));
    expect(enumerateApps, greaterThan(expandPanel));

    expect(
      dart,
      contains(
          "The full list is not uploaded, shared, sold, or used for ads or analytics."),
    );
    expect(
      dart,
      contains("child: const Text('Not now')"),
    );
    expect(
      dart,
      contains("child: const Text('Continue')"),
    );
    expect(
      dart,
      contains("settingsData['android_package_visibility_consent_version']"),
    );
  });
}
