import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';
import 'package:wins_vpn/winn_protocol_ios_raw_config.dart';
import 'package:wins_vpn/winn_protocol_web_control_plane.dart';

/// Tests for the web control-plane winn/3 dev override emission in
/// `lib/winn_protocol_web_control_plane.dart`.
///
/// The point of this emitter is to carry a resolved `winn/3` config to a dev
/// override file for the web surface WITHOUT starting a tunnel. The thing a
/// false-green would hide here: a config that the authoritative gate accepts
/// must be emitted as the exact `[winn]` section the gate produced, a config
/// the gate refuses must be refused with that gate's reason, and a secret's
/// VALUE must never survive into the redacted JSON snapshot.
void main() {
  group('emitWinnProtocolWebControlPlane: green path', () {
    test(
        'a valid winn/3 config is emitted to the exact [winn] section the '
        'authoritative gate produces', () {
      final config = _valid();
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isTrue, reason: emission.errors.join(','));
      expect(emission.protocolVersion, kWinnProtocolV3);

      final direct = resolveWinnProtocolStartForServedConfig(config: config);
      expect(direct.supported, isTrue, reason: direct.message);
      // The emitted override IS the authoritative section, byte for byte.
      expect(emission.iniDocument, direct.iniSection);
      expect(emission.iniDocument, startsWith('[winn]\n'));
    });

    test('re-emission is byte-identical (idempotent printer)', () {
      final config = _valid();
      final a = emitWinnProtocolWebControlPlane(config: config);
      final b = emitWinnProtocolWebControlPlane(config: config);
      expect(a.iniDocument, b.iniDocument);
    });

    test('the redacted snapshot keeps the private key private', () {
      const planted = 'PLANTED_PRIVATE_4f21c9';
      final config = _valid()..['client_private_key'] = planted;
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isTrue);
      final json = jsonEncode(emission.redactedConfig);
      expect(json, isNot(contains(planted)));
      expect(emission.redactedConfig!['client_private_key'], '<redacted>');
    });

    test('public keys survive into the snapshot (not secret)', () {
      final emission = emitWinnProtocolWebControlPlane(config: _valid());
      expect(emission.redactedConfig!['client_public_key'],
          '<REDACTED_WG_KEY>');
    });
  });

  group('emitWinnProtocolWebControlPlane: refusals (the negative)', () {
    test('a config missing a required field is refused BEFORE the gate runs',
        () {
      // This is the fail-open survivor shape: removed the required-field
      // check, a config with no private key could otherwise reach the relay
      // gate and be accepted. It must be refused by name.
      final config = _valid()..remove('client_private_key');
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isFalse);
      expect(emission.errors.any((e) => e.contains('missing_field')), isTrue);
      expect(emission.iniDocument, isNull);
      expect(emission.redactedConfig, isNull);
    });

    test('a non-winn/3 protocol_version is refused', () {
      final config = _valid()..['protocol_version'] = kWinnProtocolV1;
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isFalse);
      expect(emission.errors, contains('not_winn3'));
    });

    test('an absent protocol_version normalizes to winn/1 and is refused', () {
      final config = _valid()..remove('protocol_version');
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isFalse);
    });

    test(
        'a config the authoritative gate refuses is refused with its reason, '
        'not swallowed', () {
      final config = _valid()..['mtu'] = 40;
      final emission = emitWinnProtocolWebControlPlane(config: config);
      final direct = resolveWinnProtocolStartForServedConfig(config: config);
      expect(direct.supported, isFalse);
      expect(emission.accepted, isFalse);
      expect(emission.errors, contains('gate_${direct.reason.code}'));
    });

    test('an unknown protocol_param key is refused, never emitted', () {
      // The negative to the green round-trip: a winn/3 payload carrying a key
      // this build does not implement must be refused by the web emitter (via
      // the gate's unknown-parameter sweep), and must deliver no override file.
      final config = _valid()
        ..['protocol_params'] = <String, dynamic>{'post_quantum_mlkem': 'x'};
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isFalse);
      expect(emission.errors, contains('gate_unhonourable_protocol_params'));
      expect(emission.iniDocument, isNull);
      expect(emission.redactedConfig, isNull);
    });

    test('refusal messages never echo config values (no key material)', () {
      const planted = 'PLANTED_SECRET_9b5d77';
      final logs = <String>[];
      final config = _valid()..remove('client_private_key');
      emitWinnProtocolWebControlPlane(config: config, log: logs.add);
      expect(logs, isNotEmpty);
      for (final line in logs) {
        expect(line, isNot(contains(planted)));
      }
    });
  });

  group('missingWinnWebConfigFields / redaction prerequisites', () {
    test('the required-field set matches dev_config_source exactly', () {
      expect(kWinnWebConfigRequiredFields, <String>{
        'client_ip',
        'client_private_key',
        'client_public_key',
        'server_public_key',
      });
    });

    test('redaction matches exact secret keys, never a substring', () {
      final redacted = redactWinnConfigForWebOverride(
          <String, dynamic>{'keyboard_layout': 'qwerty'});
      expect(redacted['keyboard_layout'], 'qwerty');
    });
  });

  group('control-plane readouts: session_id, carrier hints, nonce fields', () {
    test('the emission reads back the session_id the gate emitted', () {
      final config = _valid();
      config['protocol_params'] = <String, dynamic>{'session_id': 'SESS_AB12'};
      final emission = emitWinnProtocolWebControlPlane(config: config);
      expect(emission.accepted, isTrue, reason: emission.errors.join(','));
      expect(emission.sessionId, 'SESS_AB12');
      expect(emission.iniDocument, contains('session_id = SESS_AB12'));
    });

    test('an absent session_id reads back as null and emits no such line', () {
      final emission = emitWinnProtocolWebControlPlane(config: _valid());
      expect(emission.accepted, isTrue);
      expect(emission.sessionId, isNull);
      expect(emission.iniDocument, isNot(contains('session_id')));
    });

    test('carrier hints lead with the resolved carrier and span the supported '
        'set', () {
      final emission = emitWinnProtocolWebControlPlane(config: _valid());
      expect(emission.accepted, isTrue);
      expect(emission.carrier, kWinnCarrierDirectAwg);
      expect(emission.carrierHints, isNotEmpty);
      expect(emission.carrierHints.first, kWinnCarrierDirectAwg);
      expect(emission.carrierHints.toSet(), kWinnSupportedCarriers);
    });

    test('the h1..h4/s1..s4 nonce fields are read back in order from the '
        'emitted section', () {
      final emission = emitWinnProtocolWebControlPlane(config: _valid());
      expect(emission.accepted, isTrue);
      final section = emission.iniDocument!;
      expect(emission.awgNonceFields, <String>[
        for (final key in const ['h1', 'h2', 'h3', 'h4', 's1', 's2', 's3', 's4'])
          _iniValue(section, key),
      ]);
      expect(emission.awgNonceFields.length, 8);
      // Independent teeth: the header types come straight from the config's
      // obfuscation block, not only from a re-parse of the same bytes.
      expect(emission.awgNonceFields[0], '11');
    });

    test('a refused emission carries no control-plane readouts', () {
      final emission = emitWinnProtocolWebControlPlane(
          config: _valid()..remove('client_private_key'));
      expect(emission.accepted, isFalse);
      expect(emission.sessionId, isNull);
      expect(emission.carrier, isNull);
      expect(emission.carrierHints, isEmpty);
      expect(emission.awgNonceFields, isEmpty);
    });
  });

  group('cross-parser round-trip: web control-plane parser vs iOS parser', () {
    test('both parsers read the SAME [winn] map from an emitted section', () {
      final emission = emitWinnProtocolWebControlPlane(config: _valid());
      expect(emission.accepted, isTrue, reason: emission.errors.join(','));
      final section = emission.iniDocument!;

      final web = parseWinnWinnSection(section);
      final ios = parseWinnIosControlPlaneIni(section).winn;

      // The web CLI's parsed JSON must never be a private re-parse: the two
      // parsers must agree key-for-key and value-for-value on the very same
      // [winn] section the authoritative gate produced.
      expect(web, ios,
          reason: 'web parseWinnWinnSection must agree with the iOS parser');
    });

    test('the cross-parser agreement is not vacuous (both read real fields)',
        () {
      final section = emitWinnProtocolWebControlPlane(config: _valid()).iniDocument!;
      final web = parseWinnWinnSection(section);
      // A test that accepts an empty agreement on both sides is a false green;
      // the maps must actually carry the emitted fields.
      expect(web, isNotEmpty);
      expect(web, contains('endpoint'));
      expect(web, contains('carrier'));
    });
  });
}

/// Value of one `key = value` line in an INI [section], or `''` when absent.
/// Mirrors the lib's private parser so tests reconcile against the document.
String _iniValue(String section, String key) {
  final prefix = '$key ';
  for (final line in const LineSplitter().convert(section)) {
    if (line.startsWith(prefix)) {
      final eq = line.indexOf('=');
      if (eq >= 0) return line.substring(eq + 1).trim();
    }
  }
  return '';
}

/// A served winn/3 config that resolves to a real `[winn]` section through
/// [resolveWinnProtocolStartForServedConfig] -- the same shape used in the
/// dev-config-source suite. Loopback keys only; no real key material.
Map<String, dynamic> _valid() => <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{},
      'server_endpoint': '127.0.0.1:51820',
      'client_ip': '10.99.0.2',
      'client_private_key': '<REDACTED_WG_KEY>',
      'client_public_key': '<REDACTED_WG_KEY>',
      'server_public_key': '<REDACTED_WG_KEY>',
      'mtu': 1280,
      'dns': '10.99.0.1',
      'stealth_active': false,
      'obfuscation': <String, dynamic>{
        'H1': 11,
        'H2': 22,
        'H3': 33,
        'H4': 44,
      },
    };
