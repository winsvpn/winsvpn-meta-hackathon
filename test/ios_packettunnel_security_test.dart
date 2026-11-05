import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Source-level security contracts for the iOS Packet Tunnel provider.
///
/// The Network Extension cannot be instantiated in this Dart suite. These
/// tests pin the fail-closed seams that a later edit must not delete:
/// kill-switch teardown order, persisted-secret / redirect replay refusal,
/// descriptor-node binding, and status/app-message redaction.
void main() {
  const iosDefault = 'ios/PacketTunnel/PacketTunnelProvider.swift';

  String resolve(String envKey, String fallback) {
    final value = Platform.environment[envKey];
    return (value == null || value.isEmpty) ? fallback : value;
  }

  late String iosSource;

  setUpAll(() {
    iosSource = File(resolve('WINS_IOS_PACKETTUNNEL_SWIFT', iosDefault))
        .readAsStringSync();
  });

  String stopTunnelBody() {
    const marker = 'override func stopTunnel(';
    final start = iosSource.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0), reason: 'stopTunnel is missing');
    final release = iosSource.indexOf(
      'releaseTunnelNetworkSettings(context: "stop_tunnel")',
      start,
    );
    expect(release, greaterThan(start));
    final completion = iosSource.indexOf('completionHandler()', release);
    expect(completion, greaterThan(release));
    return iosSource.substring(start, completion);
  }

  test('stopTunnel stops the datapath before releasing network settings', () {
    final body = stopTunnelBody();
    final engineStop = body.indexOf('engineAtStop?.stop()');
    final winn3Stop = body.indexOf('winn3AtStop?.stop()');
    final release = body.indexOf(
      'releaseTunnelNetworkSettings(context: "stop_tunnel")',
    );
    expect(engineStop, greaterThanOrEqualTo(0));
    expect(winn3Stop, greaterThan(engineStop));
    expect(release, greaterThan(winn3Stop));
    expect(
      body,
      contains('datapathStoppedBeforeRelease: true'),
      reason:
          'teardown status must claim datapath-before-release only when that is the actual order',
    );
  });

  test('stopTunnel awaits settings release before completing the stop', () {
    const marker = 'override func stopTunnel(';
    final start = iosSource.indexOf(marker);
    final nextOverride =
        iosSource.indexOf('\n  override func ', start + marker.length);
    final body = iosSource.substring(
      start,
      nextOverride == -1 ? iosSource.length : nextOverride,
    );
    final release = body.indexOf(
      'releaseTunnelNetworkSettings(context: "stop_tunnel")',
    );
    final completion = body.indexOf('completionHandler()', release);
    expect(release, greaterThanOrEqualTo(0));
    expect(completion, greaterThan(release));
    expect(
      body.substring(0, release),
      isNot(contains('completionHandler()')),
      reason:
          'completing stop before the release callback races teardown into cleartext',
    );
  });

  test('iOS refuses persisted winn3_ini as a start and replay source', () {
    expect(iosSource, isNot(contains('source: "injected_winn3_ini"')));
    expect(
      iosSource,
      contains('Ignoring persisted winn3_ini in providerConfiguration'),
    );
    expect(
      iosSource,
      contains('its bytes are never parsed'),
    );
  });

  test('persisted runtime configs that still carry live secrets are refused',
      () {
    expect(iosSource, contains('runtimeConfigContainsLiveSecretMaterial'));
    expect(iosSource, contains('source != "transient_start_options"'));
    expect(iosSource, contains('persisted_live_secret_material_refused'));
    expect(iosSource, contains('redactedWinnStaticPrivatePlaceholder'));
    expect(iosSource, contains('redactedWinnAdmissionKeyPlaceholder'));
  });

  String bindingFunction() {
    const marker = 'private func bindWinn3DescriptorToSelectedNode(';
    final start = iosSource.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0),
        reason: 'iOS bind function is missing');
    final next = iosSource.indexOf('\n  private ', start + marker.length);
    expect(next, greaterThan(start),
        reason: 'iOS bind function has no trailing seam');
    return iosSource.substring(start, next);
  }

  test('standalone starts bind the signed descriptor node to the selected node',
      () {
    expect(iosSource, contains('try bindWinn3DescriptorToSelectedNode('));
    expect(
        iosSource, contains('private func bindWinn3DescriptorToSelectedNode('));
    expect(iosSource, contains('winn["node"]'));
    final binding = bindingFunction();
    expect(binding, contains('winn3AsciiLowercase'));
    expect(binding, contains('unit >= 0x41 && unit <= 0x5A'));
    expect(binding, contains('unit &+ 0x20'));
    expect(binding, contains('unit > 0x7F'));
    expect(binding, contains('winn3NormalizedNodeIdentity'));
    expect(binding, contains('winn3SelectedNodeIdentity'));
    expect(binding, contains('options?[key]'));
    expect(binding, contains('winn[key]'));
    for (final key in kWinn3SelectedNodeIdentityKeys) {
      expect(binding, contains('"$key"'),
          reason: 'missing selected-node alias $key');
    }
    expect(binding, contains('"slug"'));
    expect(binding, contains('bound != value'));
    expect(binding, contains('bound != normalized'));
    expect(binding, isNot(contains('.lowercased()')));
    expect(binding, isNot(contains('trimmingCharacters')));
    expect(binding, isNot(contains('?? winn["selected_node"]')));
    expect(binding, isNot(contains('admission_key')));
    expect(binding, isNot(contains('static_private')));
    expect(binding, isNot(contains('inner_v4')));
    expect(binding, contains('guard !descriptorNode.isEmpty'));
    expect(iosSource, contains('"winn3_descriptor_node_bound": false'));
    expect(iosSource, contains('code: 1040'));
  });

  test('a failed descriptor binding cannot fall through to the AWG/Xray engine',
      () {
    final bind = iosSource.indexOf('try bindWinn3DescriptorToSelectedNode(');
    final fork = iosSource.indexOf('if parsedConfig.winn3Enabled {');
    expect(bind, greaterThanOrEqualTo(0));
    expect(fork, greaterThan(bind));
    final standalone = iosSource.indexOf(
      'try startWinn3StandaloneSession(',
      fork,
    );
    final returnAfter = iosSource.indexOf('\n        return\n', standalone);
    final engine = iosSource.indexOf(
      'WinsPacketTunnelEngineFactory.makeEngine',
      standalone,
    );
    expect(standalone, greaterThan(fork));
    expect(returnAfter, greaterThan(standalone));
    expect(engine, greaterThan(returnAfter));
  });

  test('debug self-cancel does not release a kill-switch posture while running',
      () {
    expect(
      iosSource,
      contains('dev_containment_self_cancel_release_skipped_kill_switch_held'),
    );
    expect(
      iosSource,
      contains('WinsKillSwitch.activeFor(config: config, devRunActive: false)'),
    );
    final skip = iosSource.indexOf(
      'dev_containment_self_cancel_release_skipped_kill_switch_held',
    );
    final runningRelease = iosSource.indexOf(
      'releaseTunnelNetworkSettings(context: "self_cancel_running")',
    );
    expect(skip, greaterThanOrEqualTo(0));
    expect(runningRelease, greaterThan(skip));
  });

  test('app messages and status writes keep secret payloads redacted', () {
    expect(iosSource, contains('app_message_raw_payload_redacted'));
    expect(iosSource, contains('redactedProviderErrorMessage'));
    expect(
      iosSource,
      isNot(contains('completionHandler?(messageData)')),
      reason: 'raw app-message bytes must not be echoed back',
    );
  });

  test('a stale stopped status document cannot replay over a newer generation',
      () {
    expect(iosSource, contains('shouldSkipStaleStopStatusWrite'));
    expect(
      iosSource,
      contains('fileGeneration != intendedStatusGeneration'),
    );
  });
}
