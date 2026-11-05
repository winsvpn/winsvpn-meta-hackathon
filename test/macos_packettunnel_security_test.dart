import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Source-level security contracts for the macOS Packet Tunnel provider.
///
/// Native Network Extension objects cannot be constructed here. These tests
/// pin the fail-closed seams that must stay aligned with iOS: descriptor-node
/// binding before standalone v3, refusal of persisted `winn3_ini` replay, and
/// refusal of persisted configs that still carry live secrets. AWG then Xray
/// remain packaged v1 engines; they are never an implicit v3 downgrade.
void main() {
  const macosDefault = 'macos/PacketTunnel/PacketTunnelProvider.swift';

  String resolve(String envKey, String fallback) {
    final value = Platform.environment[envKey];
    return (value == null || value.isEmpty) ? fallback : value;
  }

  late String macosSource;

  setUpAll(() {
    macosSource = File(resolve('WINS_MACOS_PACKETTUNNEL_SWIFT', macosDefault))
        .readAsStringSync();
  });

  test('macOS refuses persisted winn3_ini as a start and replay source', () {
    expect(macosSource, isNot(contains('source: "injected_winn3_ini"')));
    expect(
      macosSource,
      contains('Ignoring persisted winn3_ini in providerConfiguration'),
    );
    expect(macosSource, contains('its bytes are never parsed'));
  });

  test('persisted runtime configs that still carry live secrets are refused', () {
    expect(macosSource, contains('runtimeConfigContainsLiveSecretMaterial'));
    expect(macosSource, contains('source != "transient_start_options"'));
    expect(macosSource, contains('persisted_live_secret_material_refused'));
    expect(macosSource, contains('redactedWinnStaticPrivatePlaceholder'));
    expect(macosSource, contains('redactedWinnAdmissionKeyPlaceholder'));
  });

  String bindingFunction() {
    const marker = 'private func bindWinn3DescriptorToSelectedNode(';
    final start = macosSource.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0), reason: 'macOS bind function is missing');
    final next = macosSource.indexOf('\n  private ', start + marker.length);
    expect(next, greaterThan(start), reason: 'macOS bind function has no trailing seam');
    return macosSource.substring(start, next);
  }

  test('standalone starts bind the signed descriptor node before the v3 fork', () {
    final bind = macosSource.indexOf('try bindWinn3DescriptorToSelectedNode(');
    final fork = macosSource.indexOf('if parsedConfig.winn3Enabled {');
    expect(bind, greaterThanOrEqualTo(0));
    expect(fork, greaterThan(bind));
    expect(macosSource, contains('private func bindWinn3DescriptorToSelectedNode('));
    expect(macosSource, contains('winn["node"]'));
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
      expect(binding, contains('"$key"'), reason: 'missing selected-node alias $key');
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
    expect(macosSource, contains('"winn3_descriptor_node_bound": false'));
    expect(macosSource, contains('code: 1040'));
  });

  test('a failed v3 check does not fall through to the AWG/Xray engine', () {
    final fork = macosSource.indexOf('if parsedConfig.winn3Enabled {');
    final standalone = macosSource.indexOf(
      'try startWinn3StandaloneSession(',
      fork,
    );
    final returnAfter = macosSource.indexOf('\n        return\n', standalone);
    final engine = macosSource.indexOf(
      'WinsPacketTunnelEngineFactory.makeEngine',
      standalone,
    );
    expect(fork, greaterThanOrEqualTo(0));
    expect(standalone, greaterThan(fork));
    expect(returnAfter, greaterThan(standalone));
    expect(engine, greaterThan(returnAfter));
  });
}
