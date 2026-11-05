import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Source-level contracts for the Apple host callers that populate Packet
/// Tunnel start options with the user-selected node slug.
///
/// Native descriptor binding already compares start-option identities against
/// the signed descriptor `node`. These tests pin that iOS AppDelegate and the
/// macOS host actually copy the Flutter caller slug into those options instead
/// of forwarding only `raw_config`.
void main() {
  late String iosSource;
  late String macosSource;
  late String iosProviderSource;
  late String macosProviderSource;

  setUpAll(() {
    iosSource = File('ios/Runner/AppDelegate.swift').readAsStringSync();
    macosSource = File('macos/Runner/MainFlutterWindow.swift').readAsStringSync();
    iosProviderSource = File('ios/PacketTunnel/PacketTunnelProvider.swift').readAsStringSync();
    macosProviderSource = File('macos/PacketTunnel/PacketTunnelProvider.swift').readAsStringSync();
  });

  String callerEnum(String source) {
    const marker = 'enum WinsWinn3SelectedNodeCaller {';
    final start = source.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0), reason: 'selected-node caller enum is missing');
    final next = source.indexOf('\n@main', start + marker.length);
    final fallback = source.indexOf('\nfinal class WinsMacOSTunnelBridge', start + marker.length);
    final end = [next, fallback].where((index) => index > start).fold<int>(source.length, (a, b) => a < b ? a : b);
    expect(end, greaterThan(start), reason: 'selected-node caller enum has no trailing seam');
    return source.substring(start, end);
  }

  String startTunnelBody(String source) {
    const marker = 'private func startTunnel(';
    final start = source.indexOf(marker);
    expect(start, greaterThanOrEqualTo(0), reason: 'startTunnel is missing');
    final stop = source.indexOf('\n  private func stopTunnel(', start);
    expect(stop, greaterThan(start), reason: 'startTunnel has no trailing seam');
    return source.substring(start, stop);
  }

  test('iOS and macOS host callers use the same selected-node start-option helper', () {
    expect(callerEnum(iosSource), equals(callerEnum(macosSource)));
  });

  test('both Apple connect paths copy caller identities into PacketTunnel start options', () {
    const helperCall = '''WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(
                  rawConfig: config,
                  clientPublicKey: clientKeyPair.publicKey,
                  accountScope: accountScope,
                  statusGeneration: statusGeneration,
                  arguments: arguments,
                  parsedConfig: parsedConfig
                )''';
    for (final entry in <String, String>{
      'ios': iosSource,
      'macos': macosSource,
    }.entries) {
      final body = startTunnelBody(entry.value);
      expect(
        body,
        contains(helperCall),
        reason: '${entry.key} startTunnel must build PacketTunnel options through the caller helper',
      );
      expect(
        body,
        isNot(contains('"raw_config": config as NSString')),
        reason: '${entry.key} must not inline a raw_config-only startVPNTunnel dictionary',
      );
    }
  });

  test('the caller helper retains every selected-node alias and the exact slug', () {
    final helper = callerEnum(iosSource);
    expect(helper, contains('static let startOptionKey = "selected_node"'));
    expect(helper, contains('copyIdentities('));
    expect(helper, contains('return exactSlug(from: dictionary(from: arguments))'));
    expect(helper, isNot(contains('parsedConfig.sections["winn"]')));
    expect(helper, contains('slug as NSString'));
    expect(helper, isNot(contains('.lowercased()')));
    expect(helper, isNot(contains('trimmingCharacters')));
    for (final key in kWinn3SelectedNodeIdentityKeys) {
      expect(helper, contains('"$key"'), reason: 'missing selected-node alias $key');
    }
    expect(helper, contains('"slug"'));
  });

  test('both Apple v3 entry points refuse an absent independent caller slug', () {
    for (final entry in <String, String>{
      'ios': iosSource,
      'macos': macosSource,
    }.entries) {
      final body = startTunnelBody(entry.value);
      expect(body, contains('if parsedConfig.winn3Enabled,'));
      expect(body, contains('code: "WINN3_SELECTED_NODE_REQUIRED"'));
    }
  });

  test('both Packet Tunnel providers require transient identity before INI corroboration', () {
    for (final entry in <String, String>{
      'ios': iosProviderSource,
      'macos': macosProviderSource,
    }.entries) {
      expect(entry.value, contains('var sawTransientIdentity = false'));
      expect(entry.value, contains('winn3ReadNodeIdentityValue(options?[key])'));
      expect(entry.value, contains('guard sawTransientIdentity, let bound else'));
      expect(entry.value, contains('winn3ReadNodeIdentityValue(winn[key])'));
      expect(
        entry.value,
        isNot(contains('let candidates: [Any?] = [options?[key], winn[key]]')),
        reason: '${entry.key} must not merge persisted and transient identities into one authority pool',
      );
      expect(entry.value, contains('lowered != "auto"'));
    }
  });

  test('both Apple host callers reject literal auto and malformed direct identities', () {
    for (final source in <String>[iosSource, macosSource]) {
      final helper = callerEnum(source);
      expect(helper, contains('isValidExactSlug'));
      expect(helper, contains('lowered != Array("auto".utf8)'));
      expect(helper, contains('(2...40).contains(bytes.count)'));
    }
  });

  test('persisted Apple providerConfiguration still does not store selected_node', () {
    for (final entry in <String, String>{
      'ios': iosSource,
      'macos': macosSource,
    }.entries) {
      var searchFrom = 0;
      var found = 0;
      while (true) {
        final start = entry.value.indexOf('providerConfiguration = [', searchFrom);
        if (start < 0) {
          break;
        }
        final end = entry.value.indexOf(']', start);
        expect(end, greaterThan(start), reason: '${entry.key} providerConfiguration is unclosed');
        expect(
          entry.value.substring(start, end),
          isNot(contains('selected_node')),
          reason: '${entry.key} must not persist selected_node in providerConfiguration',
        );
        expect(
          entry.value.substring(start, end),
          isNot(contains('node_slug')),
        );
        found += 1;
        searchFrom = end + 1;
      }
      expect(found, greaterThan(0), reason: '${entry.key} has no providerConfiguration blocks');
    }
  });
}
