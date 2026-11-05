import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/camouflage_policy.dart';

/// Every value `Platform.operatingSystem` can take. A closed set defined by
/// Dart, deliberately NOT a list of "platforms we support" - the point is that
/// the reachable set is computed by asking the policy, so a platform added to
/// the policy is seen here on the same edit.
const List<String> _allOperatingSystems = <String>[
  'android',
  'fuchsia',
  'ios',
  'linux',
  'macos',
  'windows',
];

/// Where each platform's `stopTunnel` method-channel handler lives.
///
/// A structural fact about this repository, not a policy: these are the five
/// files that answer the channel `lib/main.dart` calls. `drop_in/` and
/// `.claude/worktrees/` hold stale copies of some of them and are deliberately
/// excluded. Each is asserted to exist, so a rename fails this test loudly
/// instead of quietly emptying the set it is derived from.
const Map<String, String> _nativeTunnelHosts = <String, String>{
  'android': 'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
  'ios': 'ios/Runner/AppDelegate.swift',
  'linux': 'linux/runner/linux_tunnel_backend.cc',
  'macos': 'macos/Runner/MainFlutterWindow.swift',
  'windows': 'windows/runner/windows_tunnel_backend.cpp',
};

/// The app removing its OWN kill switch.
///
/// This is the discriminator, and it is a real one rather than a name check.
/// Android, iOS and macOS get their kill switch from the operating system
/// (always-on VPN, `includeAllNetworks`), so no teardown appears in app
/// source - the OS owns the guarantee and `stopTunnel` cannot revoke it
/// behind the user's back. Linux installs `WINSVPN_KS` into the host packet
/// filter itself, which is state the app both creates and destroys, and which
/// outlives the app process. Only that second kind can be silently disarmed by
/// a Dart-side call.
///
/// Measured 2026-08-07: 0 matches in the Android, iOS, macOS and Windows
/// hosts; matches in the Linux host, which carries `cleanup_kill_switch`.
///
/// KNOWN BLIND SPOT, stated so nobody reads an empty set as a clean bill of
/// health. Windows is a near-miss rather than a clean negative: its stop path
/// stops the AmneziaWG tunnel service, and `windows_tunnel_backend.cpp` says
/// in its own words that WireGuard-family Windows clients "can retain their
/// WFP kill-switch while the stale service remains". That kill switch is
/// installed by the vendor service rather than by code in this repository, so
/// no teardown verb appears here to match on, and this detector does not flag
/// it. If camouflage is ever enabled on Windows, do not rely on this test -
/// verify by hand whether stopping the service drops the WFP filters.
final RegExp _appRemovesItsOwnKillSwitch = RegExp(
  r'(?:cleanup|clean_up|remove|delete|flush|teardown|tear_down|drop)'
  r'[_A-Za-z]*kill[_ ]?switch'
  r'|kill[_ ]?switch[_A-Za-z]*'
  r'(?:cleanup|clean_up|remove|delete|flush|teardown|tear_down|drop)',
  caseSensitive: false,
);

/// Anything that would make the duress teardown platform-aware.
const List<String> _platformGateTokens = <String>[
  'Platform.isAndroid',
  'Platform.isIOS',
  'Platform.isMacOS',
  'Platform.isLinux',
  'Platform.isWindows',
  'Platform.operatingSystem',
  'defaultTargetPlatform',
  '_supportsInAppCamouflage',
  'supportsInAppCalculatorCamouflage',
  '_hasNativeTunnelBridge',
  'duressMayStopTunnel',
];

/// Extracts the body of a top-level or method function starting at the
/// first occurrence of [signature], ending at the first closing brace at
/// [indentSpaces] indentation (the method's own indent level -- 2 for this
/// repo's Dart files, 4 for its Kotlin files) that balances braces.
String _functionBody(String source, String signature, {int indentSpaces = 2}) {
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

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test(
      'decoy-calculator lock state is never derived from VPN tunnel '
      'connection state', () {
    // Critical finding: activeTunnel used to be ANDed directly into the
    // decoy-calculator visibility gate, so a connected tunnel skipped the
    // PIN screen entirely -- exactly the highest-risk moment for the
    // disguise to still hold (the tunnel is a separate OS-level service
    // that keeps running across a killed-and-relaunched Flutter process,
    // so its state is never proof this fresh process was PIN-verified).
    final onboarding =
        _functionBody(source, 'Future<void> _determineSecurityOnboardingLayer()');
    final gateStart = onboarding.indexOf('_showDecoyCalculator =');
    final gateEnd = onboarding.indexOf(';', gateStart);
    expect(gateStart, greaterThanOrEqualTo(0));
    final gate = onboarding.substring(gateStart, gateEnd);
    expect(gate, isNot(contains('activeTunnel')));
    // The gate now delegates to decoyCalculatorShouldArm (duress-path-defects
    // lane, 2026-08-06): the same three inputs, passed by name, so that the
    // decision itself is unit-testable rather than only greppable. The tunnel
    // must still be nowhere near it, and the two deliberate requests for the
    // real app must still be fed in.
    expect(gate, contains('decoyCalculatorShouldArm('));
    expect(gate, contains('_supportsInAppCamouflage'));
    expect(gate, contains('openedByDialer'));
    expect(gate, contains('_launcherUnlocked'));
  });

  test(
      'tunnel-active detection never unlocks the launcher or hides the '
      'decoy calculator', () {
    // The three places that learn the tunnel just became active
    // (_runStatusHeartbeat, _reconcileNativeTunnelState, _fetchLiveNetworkIp)
    // used to treat that alone as proof of a PIN-verified session and force
    // _launcherUnlocked = true / _showDecoyCalculator = false / the native
    // real-icon swap. None of them observe any PIN entry, so none of them
    // may touch lock state -- only _onCalculatorButtonPressed's genuine PIN
    // check (via _setLauncherCamouflage(enabled: false)) may unlock, and
    // only the background/resume cycle or that same PIN check may lock.
    final heartbeat = _functionBody(source, 'Future<void> _runStatusHeartbeat()');
    expect(heartbeat, isNot(contains('_launcherUnlocked = true')));
    expect(heartbeat, isNot(contains('_showDecoyCalculator = false')));
    expect(heartbeat, isNot(contains('_setLauncherCamouflage(enabled: false)')));

    final reconcile = _functionBody(
        source, 'Future<void> _reconcileNativeTunnelState(');
    expect(reconcile, isNot(contains('_launcherUnlocked = true')));
    expect(reconcile, isNot(contains('_showDecoyCalculator = false')));
    expect(reconcile, isNot(contains('_setLauncherCamouflage(enabled: false)')));

    final fetchIp = _functionBody(source, 'Future<void> _fetchLiveNetworkIp()');
    expect(fetchIp, isNot(contains('_launcherUnlocked = true')));
    expect(fetchIp, isNot(contains('_showDecoyCalculator = false')));

    // EXACTLY TWO call sites may disable camouflage, and only these two:
    //   1. genuine PIN entry (_onCalculatorButtonPressed), which is the
    //      legitimate user path; and
    //   2. the TV never-disguised self-heal, which forcibly unlatches the
    //      decoy when the form factor turns out to be TV (a D-pad remote
    //      cannot enter the PIN, so arming the disguise would lock the user
    //      out permanently). See the TV form-factor guard in the build path.
    // No tunnel-state observer may disable it -- that is what the three
    // isNot(...) assertions above enforce.
    final pinDisable =
        '_setLauncherCamouflage(enabled: false)'.allMatches(source).length;
    expect(pinDisable, 2,
        reason: 'expected exactly two camouflage-disable call sites: genuine '
            'PIN entry and the TV self-heal. A third would be an unowned '
            'disable path; zero/one would mean the TV gate or PIN path lost '
            'its disable call.');
    final pinHandler =
        _functionBody(source, 'Future<void> _onCalculatorButtonPressed(');
    expect(pinHandler, contains('_setLauncherCamouflage(enabled: false)'));
    expect(pinHandler, contains('_verifyUserPin('));
    // The TV self-heal disable call sits behind the DeviceFormFactor.tv branch
    // in the widget build (the only other legal disable path). Grep the whole
    // build body for the pairing rather than picking one of several
    // Widget build( overloads.
    final tvHeal = source.substring(source.indexOf('DeviceFormFactor.tv'));
    expect(tvHeal, contains('_setLauncherCamouflage(enabled: false)'));
    expect(tvHeal.indexOf('DeviceFormFactor.tv'), lessThan(
        tvHeal.indexOf('_setLauncherCamouflage(enabled: false)')));
  });

  test(
      'backgrounding always re-arms the decoy regardless of tunnel state',
      () {
    // The M-1 re-lock guard used to require !_isConnected, so backgrounding
    // the app while genuinely connected -- again, the highest-value moment
    // for the disguise -- skipped re-arming the decoy entirely.
    final lifecycle =
        _functionBody(source, 'void didChangeAppLifecycleState(AppLifecycleState state)');
    final guardStart = lifecycle.indexOf('final camouflageRelevant =');
    final guardEnd = lifecycle.indexOf(';', guardStart);
    expect(guardStart, greaterThanOrEqualTo(0));
    final guard = lifecycle.substring(guardStart, guardEnd);
    expect(guard, isNot(contains('_isConnected')));
    expect(guard, contains('_supportsInAppCamouflage'));
    expect(guard, isNot(contains('_isLoading')));

    // The re-arm branch itself must be unconditional -- no early return for
    // the tunnel-active case that used to skip past setting the decoy.
    final armStart = lifecycle.indexOf('if (!camouflageRelevant) return;');
    final armBody = lifecycle.substring(armStart);
    expect(armBody, isNot(contains('if (await _readNativeTunnelActive())')));
    expect(armBody, contains('_showDecoyCalculator = true'));
    expect(armBody, contains('_setLauncherCamouflage(enabled: true)'));

    // High-severity finding: the decoy must be armed before the first
    // `await` in this handler, so it happens synchronously in the same
    // call stack as the lifecycle callback rather than racing an async
    // native round trip against the OS's own backgrounding snapshot.
    final firstAwaitIndex = armBody.indexOf('await ');
    final armIndex = armBody.indexOf('_showDecoyCalculator = true');
    expect(firstAwaitIndex, greaterThan(0));
    expect(armIndex, greaterThan(0));
    expect(armIndex, lessThan(firstAwaitIndex));
  });

  test(
      'Android: neither the real dashboard nor the decoy ever appears in a '
      'screenshot or Recents thumbnail (FLAG_SECURE)', () {
    final mainActivity =
        File('android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt')
            .readAsStringSync();
    final onCreate =
        _functionBody(mainActivity, 'override fun onCreate(savedInstanceState: Bundle?)', indentSpaces: 4);
    expect(onCreate, contains('WindowManager.LayoutParams.FLAG_SECURE'));
  });

  test(
      'Android: the foreground-service notification matches the active '
      'launcher identity instead of always announcing the real VPN', () {
    final service = File(
            'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt')
        .readAsStringSync();
    // The disguise decision lives in the notification builder: the service
    // entry point delegates to it, so whichever path re-posts the row
    // (connect, status refresh, camouflage swap) passes through here.
    final notificationFn =
        _functionBody(service, 'private fun buildForegroundNotification(', indentSpaces: 4);
    expect(notificationFn, contains('isDecoyLauncherActive()'));
    expect(notificationFn, isNot(contains('"Win\'s VPN Active"\n')));
    // The literal title must be conditional, not a bare string passed
    // straight to setContentTitle: the disguised/real split is answered by
    // the title policy, not inlined as an unconditional literal.
    expect(notificationFn, contains('val title = tunnelForegroundTitleFor(disguised, state)'));
    expect(notificationFn, contains('.setContentTitle(title)'));
    // A "Disconnect" action on a disguised notification would itself be a
    // giveaway -- it must only be offered when not disguised.
    expect(notificationFn, contains('if (!disguised) {'));

    // Tunnel-connect / auto-reconnect is not proof of PIN entry (the same
    // principle as the Dart-side fix above, at the native launcher-icon
    // layer): establishing a tunnel must never itself flip the home-screen
    // icon back to the real identity.
    final onStartCommand = _functionBody(
        service,
        'override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int',
        indentSpaces: 4);
    expect(onStartCommand, isNot(contains('setLauncherComponentState(true)')));
  });

  test(
      'iOS: the VPN profile\'s Settings-visible name matches the active '
      'alternate icon instead of always announcing the real VPN', () {
    final swift =
        File('ios/Runner/AppDelegate.swift').readAsStringSync();
    final policyBody =
        _functionBody(swift, 'private static var currentTunnelDescription: String {');
    expect(policyBody, contains('UIApplication.shared.alternateIconName != nil'));

    final saveFn = swift.substring(swift.indexOf(
        'tunnelProtocol.providerBundleIdentifier = self.providerBundleIdentifier'));
    expect(
      saveFn.substring(0, saveFn.indexOf('self.saveTunnelManager(manager)')),
      allOf(
        contains('tunnelProtocol.serverAddress = Self.currentTunnelDescription'),
        contains('manager.localizedDescription = Self.currentTunnelDescription'),
      ),
    );

    // The stale-manager cleanup heuristic must recognize a profile saved
    // under either name as belonging to this app, or a profile saved while
    // disguised would never get cleaned up/replaced correctly.
    final staleCheck =
        _functionBody(swift, 'private func shouldRemoveTunnelManager(');
    expect(staleCheck, contains('Self.tunnelDescription'));
    expect(staleCheck, contains('Self.disguisedTunnelDescription'));
  });

  test(
      'iOS: an already-saved VPN profile is re-saved with the new name when '
      'disguise state changes after connect, not left stale', () {
    final swift = File('ios/Runner/AppDelegate.swift').readAsStringSync();
    final setCamouflage =
        _functionBody(swift, 'private func setLauncherCamouflage(');
    // H-4: the resave must run from BOTH branches -- the normal icon-swap
    // path AND the early-return path where the alternate icon already matches
    // the requested state (an already-saved profile can still carry a stale
    // Settings-visible name there, so skipping the resave just because there
    // is no icon change to make is exactly the stale-name bug). Two call
    // sites, not the single one the pre-H-4 code had.
    final resaveCalls =
        'resaveExistingTunnelManagerDescriptionIfStale'
            .allMatches(setCamouflage)
            .length;
    expect(resaveCalls, greaterThanOrEqualTo(2),
        reason:
            'resave must run even when the alternate icon already matches');

    final resaveFn = _functionBody(
        swift, 'private func resaveExistingTunnelManagerDescriptionIfStale(');
    expect(resaveFn, contains('NETunnelProviderManager.loadAllFromPreferences'));
    expect(resaveFn, contains('isProviderBundleTunnelManager'));
    expect(resaveFn, contains('manager.localizedDescription != expected'));
    expect(resaveFn, contains('self.saveTunnelManager(manager)'));
    // H-4: the resave outcome is no longer fire-and-forget -- it is reported
    // through a completion and a failure is logged, not silently discarded.
    expect(resaveFn, contains('completion(.failure('));
    expect(swift, contains('func logTunnelManagerResaveFailure('));
  });

  test(
      'Android: the notification channel name (visible in system Settings '
      'independent of any single notification) also tracks disguise state, '
      'and is refreshed live when disguise state changes mid-session', () {
    final service = File(
            'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt')
        .readAsStringSync();
    final channelFn =
        _functionBody(service, 'private fun createNotificationChannel()', indentSpaces: 4);
    expect(channelFn, contains('isDecoyLauncherActive()'));
    expect(channelFn, isNot(contains('NotificationChannel(channelId, "Win\'s VPN')));

    expect(service, contains('fun refreshForegroundNotificationForCamouflage()'));

    final mainActivity =
        File('android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt')
            .readAsStringSync();
    final triggerFn = _functionBody(
        mainActivity, '"triggerCamouflageSwap" -> {', indentSpaces: 16);
    expect(triggerFn, contains('VpnTunnelService.refreshForegroundNotificationForCamouflage()'));
  });

  test(
      'no dialog from the unlocked app can be left floating over the decoy',
      () {
    // Found on-device: after a recovery-code unlock the mandatory new-PIN
    // dialog was still on screen when the app re-locked, leaving an
    // unexplained panel sitting on top of what is meant to be an ordinary
    // calculator. A dialog is a separate route, so re-arming the decoy
    // underneath it does not remove it - the routes have to be popped.
    final source = File('lib/main.dart').readAsStringSync();
    final relockStart = source.indexOf('final camouflageRelevant =');
    expect(relockStart, greaterThanOrEqualTo(0));
    final armIndex = source.indexOf('_showDecoyCalculator = true', relockStart);
    expect(armIndex, greaterThan(relockStart));
    final relockBody = source.substring(relockStart, armIndex);
    // L91: the pop lives in clearProductSurfacesForDecoy (decoy_cover.dart),
    // which also removes snack bars and banners; the relock calls it before
    // it arms the decoy. Behaviour: decoy_cover_test.
    expect(relockBody, contains('_clearProductSurfacesForDecoy();'));
    final cover = File('lib/decoy_cover.dart').readAsStringSync();
    expect(cover, contains('?.popUntil((route) => route.isFirst);'));
    expect(cover, contains('Navigator.maybeOf(context, rootNavigator: true)'));

    // And the prompt itself must refuse to open while the decoy is up,
    // rather than relying only on the pop above.
    final prompt =
        _functionBody(source, 'Future<void> _promptForMandatoryPinReset()');
    expect(prompt, contains('_showDecoyCalculator) return;'));

    // The obligation outlives a single unlock: a user who re-locks before
    // answering must be asked again, not silently let off.
    final keypad =
        _functionBody(source, 'Future<void> _onCalculatorButtonPressed(');
    expect(keypad, contains('_pinResetRequired'));
  });

  test(
      'camouflage may not be enabled on a platform whose own kill switch the '
      'duress path would tear down', () {
    // THE ONE-LINE CHANGE THIS EXISTS FOR.
    //
    // `_armDuress` calls `_methodChannel.invokeMethod('stopTunnel')` with no
    // platform gate. On Linux that lands on `stopTunnel` -> `StopTunnel()` ->
    // `RunPrivilegedTunnelCommand("stop")` -> `cleanup_kill_switch`, and the
    // mandatory `WINSVPN_KS` chain is removed from both address families. A
    // duress event would DISARM the kill switch.
    //
    // It is unreachable today for one reason only: the decoy keypad, the sole
    // route to `_armDuress` (`_onCalculatorButtonPressed` -> `_verifyUserPin`
    // -> `_armDuress`), is gated on `supportsInAppCalculatorCamouflage`, which
    // resolves to android || ios. Adding `'linux'` to that list in
    // `lib/camouflage_policy.dart` is ONE LINE and reads as a straightforward
    // feature enablement. Nothing else in this tree connects those two facts:
    // `camouflage_policy_test.dart` pins linux to false but says nothing about
    // why, and the rest of this file guards the REVERSE direction - that
    // tunnel state must not drive lock state. This is the forward direction.
    //
    // Recorded, unfixed, in
    // docs/handoff/LINUX_KILL_SWITCH_ORPHANED_CHAIN_LOCKOUT_FIX_20260807.md
    // part 4, item 1, which could not act on it: the fix needs a `main.dart`
    // edit and that lane's `main.dart` delta was zero by instruction. So is
    // this one's. The invariant is therefore asserted from OUTSIDE the file,
    // by reading it.
    //
    // TWO WAYS TO MAKE THIS GREEN, and both are real fixes:
    //   1. do not enable camouflage on a platform that installs its own
    //      host-level kill switch; or
    //   2. gate the duress teardown, so it stops the tunnel only where
    //      stopping it does not also remove a firewall the user is relying on.
    // Deleting this test is not one of them.

    // 1. WHERE CAN DURESS ACTUALLY FIRE? Computed by calling the predicates,
    //    so the answer changes on the same edit that changes the policy.
    final duressReachable = _allOperatingSystems
        .where((String os) =>
            supportsInAppCalculatorCamouflage(
                os, DeviceFormFactor.phone) ||
            supportsLauncherIconCamouflage(os, DeviceFormFactor.phone))
        .toSet();
    expect(duressReachable, isNotEmpty,
        reason: 'both camouflage predicates now refuse every platform - if '
            'that is deliberate the decoy is dead code, and if it is not, the '
            'predicates are broken');

    // 2. WHICH PLATFORMS REMOVE THEIR OWN KILL SWITCH? Read out of the native
    //    hosts rather than listed here, so a Windows or macOS host firewall
    //    added later is picked up without anyone remembering to come back.
    final removesOwnKillSwitch = <String>{};
    for (final MapEntry<String, String> host in _nativeTunnelHosts.entries) {
      final file = File(host.value);
      expect(file.existsSync(), isTrue,
          reason: 'the ${host.key} tunnel host moved: ${host.value}. Repoint '
              '_nativeTunnelHosts, or this check silently stops looking.');
      if (_appRemovesItsOwnKillSwitch.hasMatch(file.readAsStringSync())) {
        removesOwnKillSwitch.add(host.key);
      }
    }
    // A null result from a detector never seen to produce a non-null one is
    // not evidence. Linux is the known-positive; if it stops matching, the
    // detector is broken, not the tree.
    expect(removesOwnKillSwitch, contains('linux'),
        reason: 'the kill-switch teardown detector no longer matches the Linux '
            'backend, which definitely still carries cleanup_kill_switch and '
            'WINSVPN_KS. Repair the detector before believing an empty set.');

    // 3. IS THE DURESS TEARDOWN STILL UNGATED? Read from lib/main.dart's text;
    //    this test never edits that file.
    final armDuress = _functionBody(source, 'Future<void> _armDuress() async {');
    // 3a. IS THE TEARDOWN REACHABLE AT ALL? The whole coupling below only
    //     matters if something calls _armDuress. Count call sites outside
    //     comments; the definition itself is the one match that must exist.
    final liveCode = source
        .split('\n')
        .where((line) => !line.trimLeft().startsWith('//'))
        .join('\n');
    final armDuressCallers =
        RegExp(r'_armDuress\(\)').allMatches(liveCode).length - 1;
    if (armDuressCallers == 0) {
      markTestSkipped('_armDuress has no caller: the duress teardown is '
          'retired, so the kill-switch coupling below is dormant. Re-enable '
          'this test when a caller returns.');
      return;
    }
    final stopIndex = armDuress.indexOf("invokeMethod('stopTunnel')");
    expect(stopIndex, greaterThan(0),
        reason: 'PREMISE GONE: _armDuress no longer stops the tunnel at all. '
            'If that is deliberate, this whole coupling is closed and this '
            'test should be rewritten to pin the absence - do not just delete '
            'it.');
    final beforeStop = armDuress.substring(0, stopIndex);
    final gate = _platformGateTokens
        .where((String token) => beforeStop.contains(token))
        .toList();
    expect(
      gate,
      isEmpty,
      reason: 'PREMISE CHANGED, possibly for the better: the duress teardown '
          'now has something platform-shaped in front of it (${gate.join(', ')}). '
          'That is fix (2) above. Re-express the invariant below against the '
          'new gate - assert that it excludes every platform in '
          '$removesOwnKillSwitch - rather than deleting this test.',
    );

    // 3b. THE DOORS THAT DO NOT EXIST YET, read from the policy file's TEXT
    //     rather than called.
    //
    //     While this test was being written another lane added a third
    //     predicate to lib/camouflage_policy.dart - `supportsDuress`, which
    //     answers "does duress work on this platform" directly and would be
    //     the natural place for someone to type 'linux'. It is NOT at HEAD.
    //     Importing it would make this file - which IS tracked at HEAD - red
    //     in every clone, which is exactly the seventh shape
    //     tracked_reference_integrity_test.dart's header warns about: a test
    //     whose dependency is not on a file but on uncommitted CONTENT.
    //
    //     So every top-level `bool supports…(String operatingSystem)` in that
    //     file is found by name and its body is read, which covers predicates
    //     that do not exist yet as well as the two called above, and adds no
    //     compile-time dependency on any of them.
    final policySource = File('lib/camouflage_policy.dart').readAsStringSync();
    // Predicates now carry a form-factor argument (DeviceFormFactor) in
    // addition to the operating-system string, so the scan matches the
    // signature-opening line only and reads each body from there. The point
    // of this scan is unchanged: find every camouflage/duress predicate and
    // assert that none of them names a platform in removesOwnKillSwitch.
    final predicates = RegExp(
      r'^bool (supports\w+)\(',
      multiLine: true,
    ).allMatches(policySource).map((RegExpMatch m) => m.group(1)!).toList();
    expect(predicates, contains('supportsInAppCalculatorCamouflage'),
        reason: 'the platform-predicate scan found $predicates and not the one '
            'predicate that certainly exists. Repair it rather than believing '
            'the empty result it would otherwise produce.');
    final admittedInText = <String>{};
    for (final String name in predicates) {
      final body = _functionBody(
          policySource, 'bool $name(',
          indentSpaces: 0);
      for (final String os in removesOwnKillSwitch) {
        if (body.contains("'$os'")) admittedInText.add('$name -> $os');
      }
    }
    expect(
      admittedInText,
      isEmpty,
      reason: 'a platform predicate in lib/camouflage_policy.dart now names a '
          'platform that removes its own kill switch: $admittedInText. If that '
          'is an enablement, read the argument below - the duress teardown has '
          'no platform gate. If it is an EXCLUSION (`platform != ...`), this is '
          'a false positive: say so here in one line rather than deleting the '
          'check, because the next mention will not be an exclusion.',
    );

    // 4. THE INVARIANT.
    final unsafe = duressReachable.intersection(removesOwnKillSwitch);
    expect(
      unsafe,
      isEmpty,
      reason: 'Camouflage - and therefore the decoy keypad, and therefore the '
          'duress code - is now reachable on $unsafe, and on those platforms '
          "this app installs its OWN kill switch and can remove it. "
          "_armDuress's `invokeMethod('stopTunnel')` has no platform gate, so "
          'entering the duress code would tear the kill switch down: on Linux '
          'that is WINSVPN_KS, removed from both address families, leaving the '
          'device unprotected at the exact moment someone is being coerced '
          'into unlocking it. The camouflage change reads as a feature '
          'enablement and looks unrelated to the firewall. It is not.\n'
          'Fix it by gating the duress teardown, or by not enabling '
          'camouflage there. See '
          'docs/handoff/LINUX_KILL_SWITCH_ORPHANED_CHAIN_LOCKOUT_FIX_20260807'
          '.md part 4.',
    );
  });
}
