import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// The Apple providers share the security-critical tunnel core, but their
/// NetworkExtension policy adapters intentionally differ. iOS must retain its
/// phone-specific memory refusal, dev containment, and awaited settings
/// release. macOS must retain its /1 route pair, proof-hold mode, and explicit
/// allowance for an unavailable iOS-only headroom API.
void main() {
  const macosDefault = 'macos/PacketTunnel/PacketTunnelProvider.swift';
  const iosDefault = 'ios/PacketTunnel/PacketTunnelProvider.swift';

  String resolve(String envKey, String fallback) {
    final value = Platform.environment[envKey];
    return (value == null || value.isEmpty) ? fallback : value;
  }

  late String macosSource;
  late String iosSource;

  setUpAll(() {
    macosSource = File(
      resolve('WINS_MACOS_PACKETTUNNEL_SWIFT', macosDefault),
    ).readAsStringSync();
    iosSource = File(
      resolve('WINS_IOS_PACKETTUNNEL_SWIFT', iosDefault),
    ).readAsStringSync();
  });

  test('both providers retain the shared security-core seams', () {
    const required = <String>[
      'WinsTunnelConfig',
      'WinsPacketTunnelEngine',
      'WinsPacketTunnelProviderStatus',
      'WinsKillSwitch',
      'WinsWinnDatapathProofGate',
      'startWinn3StandaloneSession',
      'makeWinnStagedStartPlan',
      'verifiedStatusFields',
      'try bindWinn3DescriptorToSelectedNode(',
      'runtimeConfigContainsLiveSecretMaterial',
      'Ignoring persisted winn3_ini in providerConfiguration',
      'its bytes are never parsed',
      'persisted_live_secret_material_refused',
    ];
    for (final token in required) {
      expect(iosSource, contains(token), reason: 'iOS lost $token');
      expect(macosSource, contains(token), reason: 'macOS lost $token');
    }
    expect(iosSource, isNot(contains('source: "injected_winn3_ini"')));
    expect(macosSource, isNot(contains('source: "injected_winn3_ini"')));
  });

  test('iOS keeps phone-specific fail-closed policies', () {
    expect(iosSource, contains('return "appex_available_memory_unknown"'));
    expect(iosSource, contains('makeContainedDevNetworkSettings'));
    expect(iosSource,
        contains('releaseTunnelNetworkSettings(context: "stop_tunnel")'));
    expect(iosSource, contains('network_settings_release_outcome'));
    expect(
      iosSource,
      isNot(contains('winn_memory_gate_macos_unknown_headroom_allowed')),
    );
  });

  test('macOS keeps workstation-specific fail-closed policies', () {
    expect(macosSource, contains('winnDatapathProofPromotionHeld'));
    expect(
        macosSource, contains('Dev containment is an iOS-provider construct'));
    expect(macosSource, contains('config.appleIncludedIPv4Routes'));
    expect(
      macosSource,
      contains('winn_memory_gate_macos_unknown_headroom_allowed'),
    );
    expect(macosSource, isNot(contains('makeContainedDevNetworkSettings')));
  });

  test('platform adapters remain intentionally distinct', () {
    expect(iosSource, isNot(equals(macosSource)));
  });

  test('descriptor-to-selected-node binding is identical on iOS and macOS', () {
    String binding(String source) {
      const marker = 'private func bindWinn3DescriptorToSelectedNode(';
      final start = source.indexOf(marker);
      expect(start, greaterThanOrEqualTo(0));
      final next = source.indexOf('\n  private ', start + marker.length);
      expect(next, greaterThan(start));
      return source.substring(start, next);
    }

    expect(binding(iosSource), equals(binding(macosSource)));
  });
}
