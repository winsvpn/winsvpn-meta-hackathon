import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Source-text pins: the picker is only useful if `_connectWithSmartProtocol`
/// actually calls it, and the anti-downgrade seam must still refuse same-node
/// AWG. These are claims about CODE, so comments are stripped first.
void main() {
  late String source;
  late String connect;
  late String seam;

  String withoutComments(String code) => code
      .split('\n')
      .where((line) => !line.trimLeft().startsWith('//'))
      .join('\n');

  setUpAll(() {
    source = File('lib/main.dart').readAsStringSync();
    final connectStart =
        source.indexOf('Future<void> _connectWithSmartProtocol(');
    final connectEnd = source.indexOf(
        'Future<void> _toggleVpnConnection() async', connectStart);
    expect(connectStart, greaterThanOrEqualTo(0));
    expect(connectEnd, greaterThan(connectStart));
    connect = withoutComments(source.substring(connectStart, connectEnd));

    final seamStart = source.indexOf('// --- Winn Protocol dispatch seam ---');
    final seamEnd = source.indexOf(
      "final stealthActive = _boolValue(config['stealth_active']);",
      seamStart,
    );
    expect(seamStart, greaterThanOrEqualTo(0));
    expect(seamEnd, greaterThan(seamStart));
    seam = withoutComments(source.substring(seamStart, seamEnd));
  });

  test('smart-connect asks the cover-node picker when v3 cannot use TCP', () {
    expect(connect, contains('maySelectLegacyRouteAfterWinn3Lead('));
    expect(connect, contains('_lastTunnelCandidateWasSecurityRefusal'));
    expect(connect, contains('indexOfCoverBearingWinn1Fallback('));
    expect(connect, contains('winn3CoverFallbackBudgetRemains('));
    expect(connect, contains("'winn3_connectivity_fallback_to_winn1'"));
  });

  test('ordinary v3 fallback is authorized at the hub for one generation', () {
    expect(source, contains('String _newWinn3SelectionGeneration()'));
    expect(source, contains('final random = Random.secure();'));
    expect(source, contains('..._winn3SelectionGenerationPayload'));
    expect(
      connect,
      contains('_winn3OrdinaryConnectivityAuthorized = true;'),
    );
    final authorize = connect.indexOf(
      '_winn3OrdinaryConnectivityAuthorized = true;',
    );
    final recurse =
        connect.indexOf('await _connectWithSmartProtocol()', authorize);
    expect(authorize, greaterThanOrEqualTo(0));
    expect(recurse, greaterThan(authorize));
    expect(
      connect.substring(authorize, recurse),
      isNot(contains('_lastTunnelCandidateWasSecurityRefusal = false')),
      reason: 'a security refusal must never be converted to ordinary fallback',
    );
    expect(connect, contains("_winn3SelectionGeneration = '';"));
    expect(
      connect,
      contains('_winn3OrdinaryConnectivityAuthorized = false;'),
    );
  });

  test('generation-authorized v1 fallback restores AWG then Xray order', () {
    expect(
      connect,
      contains("_boolDefaultTrue(directConfig['direct_awg_enabled']) ||\n"
          '            _winn3CoverFallbackInProgress'),
    );
    expect(
      connect,
      isNot(contains('_isStealthTransportOnly && !_winn3CoverFallbackInProgress')),
      reason: 'a TCP fallback preference cannot suppress the required AWG lead',
    );
  });

  test('v3 cover fallback does not set stealth_active on the same v3 config',
      () {
    final gate = connect.indexOf('maySelectLegacyRouteAfterWinn3Lead(');
    expect(gate, greaterThanOrEqualTo(0));
    final udpOnly = connect.indexOf("if (_transportMode == 'udp')", gate);
    expect(
      udpOnly,
      greaterThan(gate),
      reason: 'the v3 node-rotation gate must run BEFORE the udp-only finish, '
          'so a v3 node can still rotate onto another node\'s UDP',
    );
    final v3Branch = connect.substring(gate, udpOnly);
    expect(
      v3Branch,
      isNot(contains('stealthMode: true')),
      reason: 'setting stealth_active on the same v3 config is the conflict '
          'this fallback exists to stop walking into',
    );
    expect(v3Branch, contains('_winn3CoverFallbackInProgress = true'));
    expect(v3Branch, contains('await _connectWithSmartProtocol()'));
    expect(
      v3Branch,
      contains('_androidNeedsVpnPermission'),
      reason: 'missing Android VPN consent must abort rotation, not walk nodes',
    );
  });

  test('a named v3 refusal stops before cover-node selection', () {
    final refusal = connect.indexOf(
      'if (_lastTunnelCandidateWasSecurityRefusal)',
    );
    final cover = connect.indexOf('maySelectLegacyRouteAfterWinn3Lead(');
    expect(refusal, greaterThanOrEqualTo(0));
    expect(cover, greaterThan(refusal));
    expect(
      connect.substring(refusal, cover),
      contains('return;'),
      reason: 'descriptor/schema/platform refusal must terminate this connect',
    );
    expect(
      connect,
      contains('if (!_lastTunnelCandidateWasSecurityRefusal &&'),
      reason: 'a schema/signature refusal is not a failed-UDP observation',
    );
  });

  test('a generic native v3 start error is classified before fallback', () {
    final start = source.indexOf('Future<bool> _startTunnelCandidate(');
    final end = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final candidate = withoutComments(source.substring(start, end));
    expect(candidate, contains('var nativeStartAccepted = false;'));
    expect(candidate, contains('nativeStartAccepted = true;'));
    expect(
      candidate,
      contains('winn3PreAcceptanceFailureMustRefuseFallback('),
    );
    expect(candidate, contains('e is PlatformException'));
    expect(candidate, contains('final details = e.details;'));
    expect(candidate,
        contains('typedErrorVerdict = nativeWinn3ReadinessVerdict('));
    expect(
      candidate,
      contains(
          '_lastWinn3NativeVerdict != Winn3NativeVerdict.ordinaryConnectivity'),
    );
    expect(
      candidate.indexOf('nativeStartAccepted = true;'),
      greaterThan(
          candidate.indexOf(".invokeMethod(\n            'startTunnel'")),
    );
  });

  test('asynchronous native refusals are read before v3 fallback', () {
    expect(source, contains('Future<Winn3NativeVerdict> _nativeWinn3Verdict('));
    expect(source, contains('startGeneration: transitionGeneration'));
    final kotlin = File(
      'android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt',
    ).readAsStringSync();
    final service = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();
    expect(kotlin, contains('"winn3_security_refusal" to'));
    expect(kotlin, contains('"winn3_start_token" to'));
    expect(kotlin, contains('"winn3_start_generation" to'));
    expect(kotlin, contains('"winn3_awg_xray_authorization_token" to'));
    expect(kotlin, contains('"winn3_verdict" to'));
    expect(kotlin, contains('"winn3_start_state" to'));
    expect(kotlin, contains('"WINN3_START_TOKEN"'));
    expect(kotlin, contains('"WINN3_START_GENERATION"'));
    expect(service, contains('lastWinn3StartSecurityRefusal'));
    expect(service, contains('lastWinn3StartToken'));
    expect(service, contains('lastWinn3StartGeneration'));
    expect(service, contains('lastWinn3StartState'));
    expect(service, contains('proofTimedOutWithoutSecurityRefusal'));
    expect(service, contains('explicitSecurityRefusal'));
    expect(service, contains('bridgeStarted'));
  });

  test('Android v3 waits for its native verdict and refuses unreadable state',
      () {
    final start = source.indexOf('Future<bool> _startTunnelCandidate(');
    final end = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      start,
    );
    final candidate = withoutComments(source.substring(start, end));
    expect(source, contains('int _nextWinn3StartToken()'));
    expect(source, contains('mintWinn3StartToken()'));
    expect(source, contains('final random = Random.secure();'));
    expect(source, isNot(contains('int _nextAndroidWinn3StartToken()')));
    final tokenFn = source.indexOf('int _nextWinn3StartToken()');
    expect(tokenFn, greaterThanOrEqualTo(0));
    expect(
      source.substring(tokenFn, tokenFn + 280),
      isNot(contains('microsecondsSinceEpoch')),
    );
    expect(candidate, contains("startArguments['winn3StartToken']"));
    expect(candidate, contains('winn3StartToken: winn3StartToken'));
    expect(candidate, contains('_lastWinn3NativeVerdict ='));
    expect(candidate, contains('await _nativeWinn3Verdict('));
    expect(candidate, contains('mergeWinn3NativeVerdict('));
    expect(candidate, contains('on PlatformException'));
    expect(candidate, contains('on MissingPluginException'));
    expect(candidate, contains('? 128'));
    expect(
      candidate.indexOf('await _nativeWinn3Verdict('),
      greaterThan(candidate.indexOf('if (!started)')),
      reason: 'the exact native verdict decides v1 eligibility after v3 wait',
    );
  });

  test('desktop hosts publish the exact typed verdict and generation schema',
      () {
    final linux =
        File('linux/runner/linux_tunnel_backend.cc').readAsStringSync();
    final windows =
        File('windows/runner/windows_tunnel_backend.cpp').readAsStringSync();
    expect(source, contains('Platform.isWindows || Platform.isLinux'));
    for (final nativeSource in <String>[linux, windows]) {
      expect(nativeSource, contains('"winn3_verdict"'));
      expect(nativeSource, contains('"winn3_start_generation"'));
      expect(nativeSource, contains('"winn3_start_token"'));
      expect(nativeSource, contains('"winn3_selection_generation"'));
      expect(nativeSource, contains('"winn3_failed_node"'));
      expect(nativeSource, contains('"winn3_awg_xray_authorization_token"'));
      expect(nativeSource, isNot(contains('"winn3_proof_outcome"')));
    }
  });

  test(
      'ANTI-DOWNGRADE: unsupported winn/3 still returns false before any break',
      () {
    // The successful winn/3 path `break`s out of the switch into the shared
    // start logic (relay v3 still owns an AmneziaWG tun). The load-bearing
    // refusal is the unsupported branch: `return false` must appear BEFORE
    // that break, matching winn_protocol_refusal_guard_test.
    final winn3Start = seam.indexOf('case kWinnProtocolV3:');
    final defaultStart = seam.indexOf('default:', winn3Start);
    final winn3Body = seam.substring(winn3Start, defaultStart);
    final guard = winn3Body.indexOf('if (!winnDecision.supported)');
    expect(guard, greaterThanOrEqualTo(0));
    final afterGuard = winn3Body.substring(guard);
    final returnFalse = afterGuard.indexOf('return false;');
    expect(returnFalse, greaterThanOrEqualTo(0));
    expect(
      afterGuard.substring(0, returnFalse),
      isNot(contains('break;')),
      reason: 'a break on the unsupported path is a same-node AWG downgrade',
    );
  });

  test('cover uses an immutable exact target and matching start generation', () {
    expect(source, contains('_winn3CoverExactTargetSlug'));
    expect(source, contains('_winn3CoverStartGeneration'));
    expect(source, contains("startArguments['winn3CoverExactTarget']"));
    expect(
      connect,
      contains('_winn3CoverStartGeneration = transitionGeneration'),
    );
    final cover = connect.indexOf('maySelectLegacyRouteAfterWinn3Lead(');
    final udpOnly = connect.indexOf("if (_transportMode == 'udp')", cover);
    expect(cover, greaterThanOrEqualTo(0));
    expect(udpOnly, greaterThan(cover));
    final coverBody = connect.substring(cover, udpOnly);
    expect(coverBody, isNot(contains('_selectedLocationIndex =')));
    expect(coverBody, isNot(contains('_saveCachedNodes()')));
    expect(coverBody, contains('_winn3CoverExactTargetSlug = nextSlug'));
  });

  test('paid refresh applies selected_node and cover rejects a different node',
      () {
    expect(source, contains('_applySelectedNodeFromAuth(responseData);'));
    expect(source, contains('_hubResponseMatchesCoverTarget('));
    expect(source, contains('returnedNodeMatchesExactCoverTarget('));
    expect(
      source,
      contains("responseData['selected_node'] ?? responseData['selectednode']"),
    );
  });

  test('Android refuses v3+xray before Xray start', () {
    final service = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();
    final refuse = service.indexOf('if (winn3Requested && xrayEnabled)');
    final startXray = service.indexOf('startXrayTransportIfNeeded(config)');
    expect(refuse, greaterThanOrEqualTo(0));
    expect(startXray, greaterThan(refuse));
  });

  test('successful cover and direct starts clear native downgrade grants', () {
    final android = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();
    final linux =
        File('linux/runner/linux_tunnel_backend.cc').readAsStringSync();
    final windows =
        File('windows/runner/windows_tunnel_backend.cpp').readAsStringSync();

    expect(android, contains('val coverRequested ='));
    expect(
      android,
      contains('if (coverRequested) {\n            WinnV3AwgXrayGrantStore.clear()'),
    );
    expect(
      linux,
      contains('} else if (!selects_winn3) {\n'
          '      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);\n'
          '      g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();'),
    );
    expect(
      linux,
      contains('if (!selects_winn3 && cover_requested) {\n'
          '      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);\n'
          '      g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();'),
    );
    expect(windows, contains('cover_requested, async_result]() mutable'));
    expect(
      windows,
      contains('} else if (cover_requested) {\n'
          '                  std::lock_guard<std::mutex> lock(g_winn3_session_mutex);\n'
          '                  g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();'),
    );
    expect(
      android,
      contains('if (action == "ACTION_DISCONNECT") {\n'
          '            WinnV3AwgXrayGrantStore.clear()'),
    );
    expect(
      linux,
      contains('if (method == "stopTunnel") {'),
    );
    expect(
      windows,
      contains('SignalWindowsTunnelStartCancellation();'),
    );
  });

  test('Apple standalone proof uses the derived inner resolver', () {
    final ios = File('ios/PacketTunnel/PacketTunnelProvider.swift')
        .readAsStringSync();
    final macos = File('macos/PacketTunnel/PacketTunnelProvider.swift')
        .readAsStringSync();
    for (final nativeSource in <String>[ios, macos]) {
      expect(
        nativeSource,
        contains('dnsServers: WinsWinn3Resolvers.inner(config)'),
      );
    }
  });

  test('persisted v1 cannot skip refresh or authorize AWG/Xray from cache', () {
    expect(connect, contains('maySkipControlPlaneRefreshWithCachedConfig('));
    expect(connect, contains('mayLeadWithCachedConfigAfterRefreshFailure('));
    expect(connect, contains('cachedConfigMayAuthorizeAwgOrXray('));
    expect(connect, contains('_protocolListingNodeForConfig('));
    final skip = connect.indexOf('maySkipControlPlaneRefreshWithCachedConfig(');
    final refresh = connect.indexOf(
      'await _refreshVpnConfigForCurrentSelection(',
      skip,
    );
    final authorize = connect.indexOf(
      'cachedConfigMayAuthorizeAwgOrXray(',
      refresh,
    );
    expect(skip, greaterThanOrEqualTo(0));
    expect(refresh, greaterThan(skip));
    expect(authorize, greaterThan(refresh));
    expect(
      connect,
      isNot(contains('coverExact.isNotEmpty || _automaticNodeSelection')),
    );
  });
}
