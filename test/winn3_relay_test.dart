import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/double_vpn_assignment_retry.dart';
import 'package:wins_vpn/hub_verify_candidate.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Ciphertext relay Double VPN (w3r/1), client side.
///
/// The phone's session terminates at the EXIT with the exit's own signed
/// descriptor; the Core only forwards ciphertext. The client therefore changes
/// exactly one thing: the dialled address (`[winn] endpoint`). These rows pin
/// the strict `winn3_relay` parser, the binding to the rest of the config, the
/// anti-lie refusal (a Double label never rides a direct dial), the INI diff
/// against a single hop, the capability gate, the cache rule and the failure
/// action that decides when the relay is given up.
void main() {
  const relayEndpoint = '198.51.100.9:9211';
  const descriptorEndpoint = '203.0.113.7:51820';

  late SimpleKeyPair signingKey;
  late String publicKeyB64;

  setUp(() async {
    signingKey = await Ed25519().newKeyPair();
    final pub = await signingKey.extractPublicKey();
    publicKeyB64 = base64.encode(pub.bytes);
  });

  Winn3DescriptorKeyRing ring() => Winn3DescriptorKeyRing.fromEncoded(
        <String, String>{'g1': publicKeyB64},
      );

  DateTime insideLifetime() =>
      DateTime.fromMillisecondsSinceEpoch(1786000100 * 1000, isUtc: true);

  Map<String, dynamic> descriptorPayload({String node = 'lab-alpha'}) =>
      <String, dynamic>{
        'v': kWinn3DescriptorFormatVersion,
        'alg': 'ed25519',
        'kid': 'g1',
        'node': node,
        'endpoint': descriptorEndpoint,
        'inner_router_v4': '10.10.0.1',
        'inner_resolver_v4': '10.10.0.1',
        'static_pub': base64.encode(List<int>.filled(32, 0x53)),
        'gateway_id': base64.encode(utf8.encode('winsgw01')),
        'admission_secret': base64.encode(utf8.encode('ab' * 32)),
        'admission_gen': 1,
        'tag_size': 32,
        'padding': 'bucket',
        'bucket_window_s': 10,
        'max_skew_s': 60,
        'seq': 1,
        'iat': 1786000000,
        'not_after': 1786086400,
      };

  Future<Map<String, dynamic>> envelopeFor(Map<String, dynamic> payload) async {
    final raw = utf8.encode(json.encode(payload));
    final signature = await Ed25519().sign(
      <int>[...utf8.encode(kWinn3DescriptorDomain), 0x00, ...raw],
      keyPair: signingKey,
    );
    return <String, dynamic>{
      'payload': base64.encode(raw),
      'sig': base64.encode(signature.bytes),
    };
  }

  /// The single-hop standalone config the hub serves for the exit.
  Future<Map<String, dynamic>> singleHopConfig({
    Map<String, dynamic> overrides = const <String, dynamic>{},
  }) async {
    final config = <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'node_slug': 'lab-alpha',
      'server_endpoint': descriptorEndpoint,
      'client_ip': '10.8.1.3',
      'mtu': 1280,
      'double_vpn_active': false,
      'double_vpn_core_id': '',
      'double_vpn_exit_slug': '',
      'winn3_descriptor': await envelopeFor(descriptorPayload()),
      'winn3_inner_v4': '10.10.4.9',
      'winn3_static_private': base64.encode(List<int>.filled(32, 0x11)),
    };
    config.addAll(overrides);
    return config;
  }

  Map<String, dynamic> relayValue({
    Object? v = 1,
    Object? endpoint = relayEndpoint,
  }) =>
      <String, dynamic>{'v': v, 'endpoint': endpoint};

  /// The hub's relay-served response: the same single-hop config plus the
  /// Double labels and `winn3_relay`.
  Future<Map<String, dynamic>> relayConfig({
    Map<String, dynamic> overrides = const <String, dynamic>{},
  }) {
    return singleHopConfig(overrides: <String, dynamic>{
      'double_vpn_active': true,
      'double_vpn_core_id': 'north-america-core',
      'double_vpn_exit_slug': 'lab-alpha',
      kWinn3RelayKey: relayValue(),
      ...overrides,
    });
  }

  Future<WinnStartDecision> startOf(Map<String, dynamic> config) async {
    final check = await verifyWinn3Descriptor(
      config: config,
      ring: ring(),
      now: insideLifetime(),
    );
    expect(check.verified, isTrue, reason: check.reason);
    return resolveWinnProtocolStartForServedConfig(
      config: config,
      winn3Descriptor: check,
    );
  }

  List<String> iniLines(String section) =>
      section.split('\n').where((l) => l.trim().isNotEmpty).toList();

  Map<String, String> iniPairs(String section) {
    final pairs = <String, String>{};
    for (final line in section.split('\n')) {
      final idx = line.indexOf('=');
      if (idx < 0) continue;
      pairs[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
    }
    return pairs;
  }

  group('strict parser', () {
    test('the exact w3r/1 shape parses, under either spelling', () {
      final relay = parseWinn3Relay(relayValue());
      expect(relay, isNotNull);
      expect(relay!.host, '198.51.100.9');
      expect(relay.port, 9211);
      expect(relay.endpoint, relayEndpoint);

      final primary = readWinn3ServedRelay(
          <String, dynamic>{kWinn3RelayKey: relayValue()});
      expect(primary.kind, Winn3RelayReadKind.valid);
      expect(primary.relay!.endpoint, relayEndpoint);
      final compat = readWinn3ServedRelay(
          <String, dynamic>{kWinn3RelayKeyCompat: relayValue()});
      expect(compat.kind, Winn3RelayReadKind.valid);
      expect(compat.relay!.endpoint, relayEndpoint);
      final both = readWinn3ServedRelay(<String, dynamic>{
        kWinn3RelayKey: relayValue(),
        kWinn3RelayKeyCompat: relayValue(),
      });
      expect(both.kind, Winn3RelayReadKind.valid);
    });

    test('only a missing relay key is absent; null is malformed', () {
      expect(readWinn3ServedRelay(<String, dynamic>{}).kind,
          Winn3RelayReadKind.absent);
      expect(
          readWinn3ServedRelay(
              <String, dynamic>{kWinn3RelayKey: null, kWinn3RelayKeyCompat: null}).kind,
          Winn3RelayReadKind.invalid);
    });

    test('an empty map, a non-map and a wrong key set are invalid, not absent',
        () {
      final cases = <String, Object?>{
        'empty map': <String, dynamic>{},
        'string': relayEndpoint,
        'list': <Object>[1, relayEndpoint],
        'number': 1,
        'bool': true,
        'extra key': <String, dynamic>{...relayValue(), 'x': 1},
        'missing endpoint': <String, dynamic>{'v': 1},
        'missing v': <String, dynamic>{'endpoint': relayEndpoint},
        'renamed key': <String, dynamic>{'v': 1, 'addr': relayEndpoint},
        'non-string key': <Object, Object>{1: 1, 'endpoint': relayEndpoint},
      };
      for (final entry in cases.entries) {
        expect(parseWinn3Relay(entry.value), isNull, reason: entry.key);
        final read =
            readWinn3ServedRelay(<String, dynamic>{kWinn3RelayKey: entry.value});
        expect(read.kind, Winn3RelayReadKind.invalid, reason: entry.key);
        final readCompat = readWinn3ServedRelay(
            <String, dynamic>{kWinn3RelayKeyCompat: entry.value});
        expect(readCompat.kind, Winn3RelayReadKind.invalid,
            reason: '${entry.key} (compat)');
      }
    });

    test('the version must be the integer 1', () {
      for (final bad in <Object?>[2, 0, -1, '1', 1.0, 1.5, true, null, 'v1']) {
        expect(parseWinn3Relay(relayValue(v: bad)), isNull, reason: '$bad');
      }
      expect(parseWinn3Relay(relayValue(v: 1)), isNotNull);
    });

    test('hostnames, IPv6 and malformed shapes are refused', () {
      for (final bad in <Object?>[
        'core.example.com:9211',
        'localhost:9211',
        '[2001:db8::1]:9211',
        '2001:db8::1:9211',
        '::1:9211',
        '198.51.100.9',
        '198.51.100.9:',
        ':9211',
        '198.51.100:9211',
        '198.51.100.9.1:9211',
        '198.51.100.9:9211:1',
        '198.051.100.9:9211',
        '198.51.100.256:9211',
        '198.51.100.-1:9211',
        '198.51.100.+9:9211',
        '0x7f.0.0.1:9211',
        '',
        ' ',
        7,
        null,
        <String>[relayEndpoint],
      ]) {
        expect(parseWinn3Relay(relayValue(endpoint: bad)), isNull,
            reason: '$bad');
      }
    });

    test('private, loopback, link local, CGNAT, multicast, unspecified and '
        'reserved hosts are refused', () {
      for (final host in <String>[
        '0.0.0.0',
        '0.1.2.3',
        '10.0.0.5',
        '10.255.255.255',
        '100.64.0.1',
        '100.100.100.100',
        '100.127.255.255',
        '127.0.0.1',
        '127.255.255.254',
        '169.254.0.1',
        '169.254.169.254',
        '172.16.0.1',
        '172.20.1.1',
        '172.31.255.254',
        '192.168.0.1',
        '192.168.4.36',
        '224.0.0.1',
        '239.255.255.250',
        '240.0.0.1',
        '255.255.255.255',
      ]) {
        expect(parseWinn3Relay(relayValue(endpoint: '$host:9211')), isNull,
            reason: host);
      }
    });

    test('the neighbours of every refused range are accepted', () {
      // Built from octets on purpose: these are routable addresses at the
      // edges of the refused ranges, and the push gate (tools/ipscrub) refuses
      // routable literals in files it uploads.
      for (final octets in <List<int>>[
        <int>[1, 0, 0, 1],
        <int>[9, 255, 255, 255],
        <int>[11, 0, 0, 1],
        <int>[100, 63, 255, 255],
        <int>[100, 128, 0, 1],
        <int>[126, 255, 255, 255],
        <int>[128, 0, 0, 1],
        <int>[169, 253, 255, 255],
        <int>[169, 255, 0, 1],
        <int>[172, 15, 255, 255],
        <int>[172, 32, 0, 1],
        <int>[192, 167, 255, 255],
        <int>[192, 169, 0, 1],
        <int>[223, 255, 255, 255],
        <int>[198, 51, 100, 9],
        <int>[203, 0, 113, 7],
      ]) {
        final host = octets.join('.');
        expect(parseWinn3Relay(relayValue(endpoint: '$host:9211')), isNotNull,
            reason: host);
      }
    });

    test('ports below 1024, above 65535 and non canonical ports are refused',
        () {
      for (final port in <String>[
        '0',
        '1',
        '80',
        '443',
        '1023',
        '65536',
        '99999',
        '100000',
        '+9211',
        '-9211',
        '09211',
        '9211 ',
        ' 9211',
        '92 11',
        '9e3',
        '0x24fb',
        '9211.0',
        '٩٢١١',
      ]) {
        expect(
            parseWinn3Relay(relayValue(endpoint: '198.51.100.9:$port')), isNull,
            reason: port);
      }
      for (final port in <String>['1024', '9211', '9230', '65535']) {
        expect(parseWinn3Relay(relayValue(endpoint: '198.51.100.9:$port')),
            isNotNull,
            reason: port);
      }
    });

    test('padding, newline and INI injection are refused', () {
      for (final bad in <String>[
        ' 198.51.100.9:9211',
        '198.51.100.9:9211 ',
        '198.51.100.9:9211\n',
        '198.51.100.9:9211\r\n[winn]',
        '198.51.100.9\n:9211',
        '198.51.100.9:9211\nendpoint = 10.0.0.1:1',
        '198.51.100.9:9211]',
        '[198.51.100.9:9211',
        '198.51.100.9:92\u0000',
        '198.51.100.9:9211​',
        '١٩٨.51.100.9:9211',
      ]) {
        expect(parseWinn3Relay(relayValue(endpoint: bad)), isNull,
            reason: json.encode(bad));
      }
    });

    test('two spellings must agree and each must parse', () {
      final agree = readWinn3ServedRelay(<String, dynamic>{
        kWinn3RelayKey: relayValue(),
        kWinn3RelayKeyCompat: relayValue(),
      });
      expect(agree.kind, Winn3RelayReadKind.valid);
      final differentHost = readWinn3ServedRelay(<String, dynamic>{
        kWinn3RelayKey: relayValue(),
        kWinn3RelayKeyCompat: relayValue(endpoint: '198.51.100.10:9211'),
      });
      expect(differentHost.kind, Winn3RelayReadKind.invalid);
      final differentPort = readWinn3ServedRelay(<String, dynamic>{
        kWinn3RelayKey: relayValue(),
        kWinn3RelayKeyCompat: relayValue(endpoint: '198.51.100.9:9212'),
      });
      expect(differentPort.kind, Winn3RelayReadKind.invalid);
      final oneBad = readWinn3ServedRelay(<String, dynamic>{
        kWinn3RelayKey: relayValue(),
        kWinn3RelayKeyCompat: relayValue(endpoint: 'core.example.com:9211'),
      });
      expect(oneBad.kind, Winn3RelayReadKind.invalid);
      final otherBad = readWinn3ServedRelay(<String, dynamic>{
        kWinn3RelayKey: relayValue(v: 2),
        kWinn3RelayKeyCompat: relayValue(),
      });
      expect(otherBad.kind, Winn3RelayReadKind.invalid);
    });

    test('winn3ConfigCarriesRelay sees any present value, valid or not', () {
      expect(winn3ConfigCarriesRelay(<String, dynamic>{}), isFalse);
      expect(
          winn3ConfigCarriesRelay(<String, dynamic>{kWinn3RelayKey: null}),
          isTrue);
      expect(winn3ConfigCarriesRelay(<String, dynamic>{kWinn3RelayKey: 'x'}),
          isTrue);
      expect(
          winn3ConfigCarriesRelay(
              <String, dynamic>{kWinn3RelayKeyCompat: relayValue()}),
          isTrue);
      expect(winn3ConfigCarriesRelay(<String, dynamic>{kWinn3RelayKey: {}}),
          isTrue);
    });

    test('applyWinn3ServedFields copies both spellings and never invents one',
        () {
      final copied = applyWinn3ServedFields(
        dest: <String, dynamic>{},
        raw: <String, dynamic>{
          kWinn3RelayKey: relayValue(),
          kWinn3RelayKeyCompat: relayValue(),
        },
      );
      expect(copied[kWinn3RelayKey], relayValue());
      expect(copied[kWinn3RelayKeyCompat], relayValue());
      // A copy, not an alias of the served map.
      expect(identical(copied[kWinn3RelayKey], relayValue()), isFalse);
      final absent = applyWinn3ServedFields(
        dest: <String, dynamic>{},
        raw: <String, dynamic>{'node_slug': 'lab-alpha'},
      );
      expect(absent.containsKey(kWinn3RelayKey), isFalse);
      expect(absent.containsKey(kWinn3RelayKeyCompat), isFalse);
      // A malformed value survives normalization so the strict reader can
      // refuse it; it is never silently dropped into "no relay".
      final malformed = applyWinn3ServedFields(
        dest: <String, dynamic>{},
        raw: <String, dynamic>{kWinn3RelayKey: 'not-a-map'},
      );
      expect(readWinn3ServedRelay(malformed).kind, Winn3RelayReadKind.invalid);
    });

    test('null relay survives normalization and refuses a single hop', () async {
      final normalized = applyWinn3ServedFields(
        dest: <String, dynamic>{},
        raw: <String, dynamic>{kWinn3RelayKey: null},
      );
      expect(normalized.containsKey(kWinn3RelayKey), isTrue);
      final decision = await startOf(await singleHopConfig(
          overrides: <String, dynamic>{kWinn3RelayKey: null}));
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.winn3RelayMalformed);
    });

    test('normalization preserves conflicting relay route aliases', () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{'doublevpnactive': false},
        <String, dynamic>{'double_vpn': false},
        <String, dynamic>{'doublevpn': false},
        <String, dynamic>{'doublevpncoreid': 'other-core'},
        <String, dynamic>{'doublevpnexitslug': 'lab-beta'},
        <String, dynamic>{'doublevpncoreid': ''},
        <String, dynamic>{'doublevpnexitslug': ''},
        <String, dynamic>{'doublevpncoreid': 42},
      ]) {
        final raw = await relayConfig(overrides: overrides);
        final collapsed = Map<String, dynamic>.from(raw)
          ..remove(overrides.keys.single);
        final normalized = applyWinn3ServedFields(dest: collapsed, raw: raw);
        final decision = await startOf(normalized);
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3RelayMalformed,
            reason: '$overrides');
      }
    });
  });

  group('binding and start', () {
    test('a valid relay config starts and dials the relay endpoint', () async {
      final decision = await startOf(await relayConfig());
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');
      final pairs = iniPairs(decision.iniSection);
      expect(pairs['endpoint'], relayEndpoint);
      // The identity is the exit's own: node and selected_node are unchanged.
      expect(pairs['node'], 'lab-alpha');
      expect(pairs['selected_node'], 'lab-alpha');
      expect(pairs['carrier'], kWinnCarrierWinn3);
    });

    test('the compat spelling alone also dials the relay endpoint', () async {
      final config = await relayConfig(overrides: <String, dynamic>{
        kWinn3RelayKeyCompat: relayValue(),
        'doublevpnactive': true,
      })..remove(kWinn3RelayKey);
      final decision = await startOf(config);
      expect(decision.supported, isTrue, reason: decision.reason.code);
      expect(iniPairs(decision.iniSection)['endpoint'], relayEndpoint);
    });

    test('the relay INI differs from the single hop INI in the endpoint line '
        'only, and carries no new key', () async {
      final single = await startOf(await singleHopConfig());
      final relay = await startOf(await relayConfig());
      expect(single.supported, isTrue);
      expect(relay.supported, isTrue);
      expect(iniPairs(single.iniSection)['endpoint'], descriptorEndpoint);
      final singleLines = iniLines(single.iniSection);
      final relayLines = iniLines(relay.iniSection);
      expect(relayLines.length, singleLines.length);
      var differing = 0;
      for (var i = 0; i < singleLines.length; i++) {
        if (singleLines[i] == relayLines[i]) continue;
        differing++;
        expect(singleLines[i], 'endpoint = $descriptorEndpoint');
        expect(relayLines[i], 'endpoint = $relayEndpoint');
      }
      expect(differing, 1);
      expect(iniPairs(relay.iniSection).keys.toList(),
          iniPairs(single.iniSection).keys.toList());
      expect(relay.iniSection.contains('relay'), isFalse);
      expect(relay.iniSection.contains(descriptorEndpoint), isFalse,
          reason: 'the exit address is never written next to a relay dial');
    });

    test('relay absent and no Double label is an ordinary single hop',
        () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{},
        <String, dynamic>{'double_vpn_active': false},
        <String, dynamic>{'double_vpn_active': null},
        <String, dynamic>{'doublevpnactive': false},
      ]) {
        final config = await singleHopConfig(overrides: overrides);
        final decision = await startOf(config);
        expect(decision.supported, isTrue, reason: '$overrides');
        expect(iniPairs(decision.iniSection)['endpoint'], descriptorEndpoint,
            reason: '$overrides');
      }
    });

    test('a Double label without a relay is refused before any credential',
        () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{
          'double_vpn_active': true,
          'double_vpn_core_id': 'north-america-core',
          'double_vpn_exit_slug': 'lab-alpha',
        },
        <String, dynamic>{'double_vpn_active': true},
        <String, dynamic>{'doublevpnactive': true},
        <String, dynamic>{'double_vpn_active': 'true'},
        <String, dynamic>{'double_vpn_active': 1},
        // The two spellings disagree: ambiguous is not single hop.
        <String, dynamic>{'double_vpn_active': false, 'doublevpnactive': true},
        <String, dynamic>{'double_vpn_active': true, 'doublevpnactive': false},
      ]) {
        final config = await singleHopConfig(overrides: overrides);
        final decision = await startOf(config);
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3DoubleLabelWithoutRelay,
            reason: '$overrides');
        expect(decision.iniSection, isEmpty, reason: '$overrides');
        expect(decision.message.contains('\u2014'), isFalse);
      }
    });

    test('a malformed relay is refused as malformed, never as no relay',
        () async {
      for (final bad in <Object?>[
        relayValue(v: 2),
        relayValue(endpoint: 'core.example.com:9211'),
        relayValue(endpoint: '10.0.0.5:9211'),
        relayValue(endpoint: '198.51.100.9:80'),
        <String, dynamic>{...relayValue(), 'extra': 1},
        <String, dynamic>{},
        'not-a-map',
      ]) {
        final config = await relayConfig(
            overrides: <String, dynamic>{kWinn3RelayKey: bad});
        final decision = await startOf(config);
        expect(decision.supported, isFalse, reason: json.encode(bad));
        expect(decision.reason, WinnRefusalReason.winn3RelayMalformed,
            reason: json.encode(bad));
        expect(decision.iniSection, isEmpty);
        expect(decision.message.contains('\u2014'), isFalse);
      }
    });

    test('a relay on a config that is not labelled Double is refused',
        () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{'double_vpn_active': false},
        <String, dynamic>{'double_vpn_active': null},
        <String, dynamic>{'double_vpn_active': false, 'doublevpnactive': true},
      ]) {
        final decision = await startOf(await relayConfig(overrides: overrides));
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3RelayMalformed,
            reason: '$overrides');
      }
    });

    test('a relay without a Core id is refused', () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{'double_vpn_core_id': ''},
        <String, dynamic>{'double_vpn_core_id': '   '},
        <String, dynamic>{'double_vpn_core_id': null},
        <String, dynamic>{
          'double_vpn_core_id': 'north-america-core',
          'doublevpncoreid': 'another-core',
        },
      ]) {
        final decision = await startOf(await relayConfig(overrides: overrides));
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3RelayMalformed,
            reason: '$overrides');
      }
      final compatOnly = await relayConfig(overrides: <String, dynamic>{
        'double_vpn_core_id': null,
        'doublevpncoreid': 'north-america-core',
      });
      expect((await startOf(compatOnly)).supported, isTrue);
    });

    test('a relay whose exit differs from the descriptor node is refused',
        () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{'double_vpn_exit_slug': 'lab-beta'},
        <String, dynamic>{'double_vpn_exit_slug': ''},
        <String, dynamic>{'double_vpn_exit_slug': null},
        <String, dynamic>{'double_vpn_exit_slug': 'core-na'},
        <String, dynamic>{
          'double_vpn_exit_slug': 'lab-alpha',
          'doublevpnexitslug': 'lab-beta',
        },
      ]) {
        final decision = await startOf(await relayConfig(overrides: overrides));
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3RelayMalformed,
            reason: '$overrides');
      }
    });

    test('selected-node aliases that name another node still refuse as a '
        'node mismatch: the ruled rule runs first and is unchanged', () async {
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{'node_slug': 'lab-beta'},
        <String, dynamic>{'location_slug': 'lab-beta'},
        <String, dynamic>{'selected_node': 'lab-beta'},
        <String, dynamic>{'nodeslug': 'lab-beta'},
      ]) {
        final decision = await startOf(await relayConfig(overrides: overrides));
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3DescriptorNodeMismatch,
            reason: '$overrides');
      }
      // Every alias agreeing is accepted.
      final agree = await relayConfig(overrides: <String, dynamic>{
        'location_slug': 'lab-alpha',
        'selected_node': 'LAB-ALPHA',
      });
      expect((await startOf(agree)).supported, isTrue);
    });

    test('a relay that names the exit itself is refused (a Double label on a '
        'direct dial)', () async {
      final config = await relayConfig(overrides: <String, dynamic>{
        kWinn3RelayKey: relayValue(endpoint: '203.0.113.7:9211'),
      });
      final decision = await startOf(config);
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.winn3RelayMalformed);
      // The same host with the descriptor's own port is the same thing.
      final samePort = await relayConfig(overrides: <String, dynamic>{
        kWinn3RelayKey: relayValue(endpoint: descriptorEndpoint),
      });
      expect((await startOf(samePort)).supported, isFalse);
    });

    test('the ruled binding function is untouched and still pins '
        'selectedNode == descriptor.node', () async {
      final config = await relayConfig();
      final check = await verifyWinn3Descriptor(
          config: config, ring: ring(), now: insideLifetime());
      expect(check.verified, isTrue);
      expect(
          winn3DescriptorBindsSelectedNode(
              served: config, descriptor: check.descriptor!),
          isTrue);
      final other = Map<String, dynamic>.from(config)
        ..['node_slug'] = 'lab-beta';
      expect(
          winn3DescriptorBindsSelectedNode(
              served: other, descriptor: check.descriptor!),
          isFalse);
      // A valid relay never makes the binding accept another exit.
      expect(
          winn3RelayBindingForServedConfig(
                  served: config, descriptor: check.descriptor!)
              .relay!
              .endpoint,
          relayEndpoint);
      final ruling = File('tools/verify_rulings.sh');
      expect(ruling.existsSync(), isTrue);
      final dispatch = File('lib/winn_protocol_dispatch.dart').readAsStringSync();
      expect(dispatch.contains('selectedNode.isEmpty || selectedNode != descriptor.node'),
          isTrue);
    });

    test('the caller identity of a relay config is the exit, as for a single '
        'hop', () async {
      final config = await relayConfig();
      final identity = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'lab-alpha',
        servedConfig: config,
      );
      expect(identity.isPresent, isTrue);
      expect(identity.exactSlug, 'lab-alpha');
      expect(identity.startArguments[Winn3StartTunnelCallerIdentity.startArgumentKey],
          'lab-alpha');
      final wrongPick = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'lab-beta',
        servedConfig: config,
      );
      expect(wrongPick.isPresent, isFalse);
    });

    test('the Double route marker of a relay config is two-hop', () async {
      final config = await relayConfig();
      expect(
          acceptsRequestedDoubleVpnConfig(
              doubleVpnRequested: true, config: config),
          isTrue);
      expect(doubleVpnRouteOf(config), doubleVpnRouteTwoHop);
      expect(
          doubleVpnRequestedButSingleHop(
              doubleVpnRequested: true, config: config),
          isFalse);
      // The single hop fallback config (relay and labels removed) is marked.
      final single = await singleHopConfig();
      expect(doubleVpnRouteOf(single), doubleVpnRouteSingleHop);
      expect(
          doubleVpnRequestedButSingleHop(
              doubleVpnRequested: true, config: single),
          isTrue);
    });
  });

  group('route keys survive normalization (D1)', () {
    // The app's _normalizeVpnConfig (a private State method, pinned by source
    // below) collapses the Double route spellings to ONE coerced value per
    // field: the first non-null spelling wins, the others are dropped. These
    // helpers repeat exactly those three collapses, then run the REAL
    // applyWinn3ServedFields over the served document the way the app does,
    // so what the binding sees is what the app would hand it.
    String? stringValue(Map<String, dynamic> data, List<String> keys) {
      for (final key in keys) {
        final value = data[key];
        if (value != null && value.toString().trim().isNotEmpty) {
          return value.toString();
        }
      }
      return null;
    }

    bool boolValue(dynamic value) {
      if (value is bool) return value;
      return value.toString().toLowerCase() == 'true';
    }

    Map<String, dynamic> normalizeLikeTheApp(Map<String, dynamic> raw) {
      final dest = Map<String, dynamic>.from(raw)
        ..removeWhere((key, _) => kWinn3RelayRouteKeys.contains(key));
      dest['double_vpn_active'] = boolValue(raw['double_vpn_active'] ??
          raw['doublevpnactive'] ??
          raw['double_vpn'] ??
          raw['doublevpn'] ??
          false);
      dest['double_vpn_exit_slug'] =
          stringValue(raw, ['double_vpn_exit_slug', 'doublevpnexitslug']) ?? '';
      dest['double_vpn_core_id'] =
          stringValue(raw, ['double_vpn_core_id', 'doublevpncoreid']) ?? '';
      return copyWinn3SelectedNodeIdentities(
        dest: applyWinn3ServedFields(dest: dest, raw: raw),
        raw: raw,
      );
    }

    test('the helpers repeat the collapse the app source really performs', () {
      final source = File('lib/main.dart').readAsStringSync();
      final start = source.indexOf('Map<String, dynamic> _normalizeVpnConfig(');
      final end = source.indexOf('bool _hasUsableVpnConfig', start);
      final normalization = source.substring(start, end);
      final flat = normalization.replaceAll(RegExp(r'\s+'), ' ');
      expect(
          flat,
          contains("'double_vpn_active': _boolValue(raw['double_vpn_active'] "
              "?? raw['doublevpnactive'] ?? raw['double_vpn'] ?? "
              "raw['doublevpn'] ?? false),"));
      expect(
          flat,
          contains("_stringValue( raw, ['double_vpn_exit_slug', "
              "'doublevpnexitslug']) ?? '',"));
      expect(
          flat,
          contains("_stringValue(raw, ['double_vpn_core_id', "
              "'doublevpncoreid']) ?? '',"));
      // The served document, not a collapsed copy, is what reaches the field
      // copier, and the selected node aliases are copied the same way.
      expect(flat, contains('copyWinn3SelectedNodeIdentities( dest: '
          'applyWinn3ServedFields( dest: <String, dynamic>{'));
      expect(flat, contains('raw: raw,'));
    });

    test('a valid relay config is unchanged by the real normalization path',
        () async {
      final raw = await relayConfig(overrides: <String, dynamic>{
        kWinn3RelayKeyCompat: relayValue(),
        'doublevpnactive': true,
        'doublevpncoreid': 'north-america-core',
        'doublevpnexitslug': 'lab-alpha',
      });
      final normalized = normalizeLikeTheApp(raw);
      expect(normalized['doublevpnactive'], isTrue);
      expect(normalized['double_vpn_core_id'], 'north-america-core');
      final decision = await startOf(normalized);
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');
      expect(iniPairs(decision.iniSection)['endpoint'], relayEndpoint);
    });

    test('every conflicting or mistyped route spelling is refused', () async {
      final cases = <Map<String, dynamic>>[
        // A conflicting later spelling the first-wins collapse used to drop.
        <String, dynamic>{'doublevpnactive': false},
        <String, dynamic>{'double_vpn': false},
        <String, dynamic>{'doublevpn': false},
        <String, dynamic>{'doublevpncoreid': 'other-core'},
        <String, dynamic>{'doublevpnexitslug': 'lab-beta'},
        <String, dynamic>{'doublevpncoreid': ''},
        <String, dynamic>{'doublevpnexitslug': ''},
        <String, dynamic>{'doublevpncoreid': 42},
        <String, dynamic>{'doublevpnexitslug': <String>['lab-alpha']},
        <String, dynamic>{'doublevpnactive': 'true'},
        // A mistyped CANONICAL value the coercion used to launder into a
        // well-formed one (the string "true" became the bool true, 42 became
        // the string "42").
        <String, dynamic>{'double_vpn_active': 'true'},
        <String, dynamic>{'double_vpn_active': 1},
        <String, dynamic>{'double_vpn_core_id': 42},
        <String, dynamic>{'double_vpn_exit_slug': 42},
        <String, dynamic>{'double_vpn_exit_slug': 'lab-beta'},
        // A false canonical beside a true spelling (the first non-null wins).
        <String, dynamic>{'double_vpn_active': false, 'doublevpnactive': true},
      ];
      for (final overrides in cases) {
        final raw = await relayConfig(overrides: overrides);
        final normalized = normalizeLikeTheApp(raw);
        final decision = await startOf(normalized);
        expect(decision.supported, isFalse, reason: '$overrides');
        expect(decision.reason, WinnRefusalReason.winn3RelayMalformed,
            reason: '$overrides');
      }
    });

    test('the hub reply validator refuses the same conflicts', () async {
      final localPublic = base64.encode(List<int>.filled(32, 0x21));
      for (final overrides in <Map<String, dynamic>>[
        <String, dynamic>{'doublevpnactive': false},
        <String, dynamic>{'doublevpncoreid': 'other-core'},
        <String, dynamic>{'doublevpnexitslug': 'lab-beta'},
        <String, dynamic>{'double_vpn_exit_slug': 'lab-beta'},
      ]) {
        final raw = await relayConfig(overrides: overrides);
        final normalized = <String, dynamic>{
          'client_private_key': base64.encode(List<int>.filled(32, 0x11)),
          'client_public_key': localPublic,
          'server_public_key': base64.encode(List<int>.filled(32, 0x31)),
          'dns': '10.8.1.1',
          ...normalizeLikeTheApp(raw),
        };
        final rejection = await hubVerifyCandidateRejection(
          responseData: <String, dynamic>{
            'status': 'authenticated',
            'selected_node': 'lab-alpha',
          },
          servedConfig: <String, dynamic>{...normalized, 'client_public_key': ''},
          normalizedConfig: normalized,
          localClientPublicKey: localPublic,
          requirements: const HubVerifyRequirements(
            exactTarget: 'lab-alpha',
            doubleVpnRequired: true,
          ),
          descriptorRing: ring(),
          now: insideLifetime(),
        );
        expect(rejection, isNotNull, reason: '$overrides');
        expect(
            rejection == WinnRefusalReason.winn3RelayMalformed.code ||
                rejection == 'double_vpn_not_served' ||
                rejection == 'response_target_mismatch',
            isTrue,
            reason: '$overrides -> $rejection');
      }
    });

    test('without a relay no alias is added to the normalized config', () {
      final raw = <String, dynamic>{
        'node_slug': 'lab-alpha',
        'double_vpn_active': true,
        'doublevpnactive': false,
        'doublevpncoreid': 'x',
      };
      final dest = <String, dynamic>{'node_slug': 'lab-alpha'};
      final out = applyWinn3ServedFields(dest: dest, raw: raw);
      for (final key in kWinn3RelayRouteKeys) {
        expect(out.containsKey(key), isFalse, reason: key);
      }
    });

    test('a null route spelling carries no claim and never overwrites', () {
      final raw = <String, dynamic>{
        kWinn3RelayKey: <String, dynamic>{'v': 1, 'endpoint': relayEndpoint},
        'double_vpn_active': null,
        'doublevpnactive': true,
      };
      final dest = <String, dynamic>{'double_vpn_active': true};
      final out = applyWinn3ServedFields(dest: dest, raw: raw);
      expect(out['double_vpn_active'], isTrue);
      expect(out['doublevpnactive'], isTrue);
    });
  });

  group('hub reply validator', () {
    final localPublic = base64.encode(List<int>.filled(32, 0x21));

    Map<String, dynamic> usable(Map<String, dynamic> config) =>
        <String, dynamic>{
          'client_private_key': base64.encode(List<int>.filled(32, 0x11)),
          'client_public_key': localPublic,
          'server_public_key': base64.encode(List<int>.filled(32, 0x31)),
          'dns': '10.8.1.1',
          ...config,
        };

    Future<String?> reject(Map<String, dynamic> config,
        {bool doubleRequested = true}) {
      final normalized = usable(config);
      return hubVerifyCandidateRejection(
        responseData: <String, dynamic>{
          'status': 'authenticated',
          'selected_node': 'lab-alpha',
        },
        servedConfig: <String, dynamic>{...normalized, 'client_public_key': ''},
        normalizedConfig: normalized,
        localClientPublicKey: localPublic,
        requirements: HubVerifyRequirements(
          exactTarget: 'lab-alpha',
          doubleVpnRequired: doubleRequested,
        ),
        descriptorRing: ring(),
        now: insideLifetime(),
      );
    }

    test('a bound relay reply is accepted for a Double request', () async {
      expect(await reject(await relayConfig()), isNull);
    });

    test('a single hop reply to a single hop request is accepted unchanged',
        () async {
      expect(await reject(await singleHopConfig(), doubleRequested: false),
          isNull);
    });

    test('a Double label without a relay is rejected by name', () async {
      final config = await singleHopConfig(overrides: <String, dynamic>{
        'double_vpn_active': true,
        'double_vpn_core_id': 'north-america-core',
        'double_vpn_exit_slug': 'lab-alpha',
      });
      expect(await reject(config),
          WinnRefusalReason.winn3DoubleLabelWithoutRelay.code);
    });

    test('a malformed or inconsistent relay is rejected by name', () async {
      expect(
          await reject(await relayConfig(overrides: <String, dynamic>{
            kWinn3RelayKey: relayValue(v: 2),
          })),
          WinnRefusalReason.winn3RelayMalformed.code);
      expect(
          await reject(await relayConfig(overrides: <String, dynamic>{
            'double_vpn_core_id': '',
          })),
          // The empty core id also fails the existing route shape check first.
          'double_vpn_not_served');
      expect(
          await reject(await relayConfig(overrides: <String, dynamic>{
            kWinn3RelayKey: relayValue(endpoint: '203.0.113.7:9211'),
          })),
          WinnRefusalReason.winn3RelayMalformed.code);
    });
  });

  group('capability', () {
    test('absent from every build that does not name the platform', () {
      expect(kWinn3RelayEnabledPlatformsBuildValue, isEmpty);
      for (final os in <String>[
        'android',
        'ios',
        'macos',
        'windows',
        'linux',
        'fuchsia'
      ]) {
        expect(
            winnClientRelayCapabilityFlags(
              operatingSystem: os,
              supportsWinn3: true,
              supportsWinn3Descriptor: true,
            ),
            isEmpty,
            reason: 'default define is empty: $os');
        expect(
            winnClientRelayCapabilityFlags(
              operatingSystem: os,
              supportsWinn3: true,
              supportsWinn3Descriptor: true,
              buildValue: '',
            ),
            isEmpty);
      }
    });

    test('the existing capability maps never contain the relay key', () {
      for (final os in <String>['android', 'ios', 'macos', 'windows', 'linux']) {
        final flags = winnClientCapabilities(
          operatingSystem: os,
          spaKeyProvisioned: false,
          descriptorRingCarried: true,
          dualAuthHostSupported: true,
        );
        expect(flags.containsKey(kWinnClientCapabilityRelay), isFalse);
      }
      expect(
          winnClientCapabilityFlags(
            hostCanCarryWinn3: true,
            spaKeyProvisioned: true,
            descriptorRingCarried: true,
            dualAuthHostSupported: true,
          ).containsKey(kWinnClientCapabilityRelay),
          isFalse);
      expect(kWinnClientCapabilityRelay, 'supports_winn3_relay');
    });

    test('each named platform advertises true and only that platform', () {
      for (final os in kWinn3StandaloneReleasePlatforms) {
        final flags = winnClientRelayCapabilityFlags(
          operatingSystem: os,
          supportsWinn3: true,
          supportsWinn3Descriptor: true,
          buildValue: os,
        );
        expect(flags, <String, bool>{kWinnClientCapabilityRelay: true},
            reason: os);
        for (final other in kWinn3StandaloneReleasePlatforms) {
          if (other == os) continue;
          expect(
              winnClientRelayCapabilityFlags(
                operatingSystem: other,
                supportsWinn3: true,
                supportsWinn3Descriptor: true,
                buildValue: os,
              ),
              isEmpty,
              reason: '$other under a define naming only $os');
        }
      }
      expect(
          winnClientRelayCapabilityFlags(
            operatingSystem: 'ios',
            supportsWinn3: true,
            supportsWinn3Descriptor: true,
            buildValue: 'android,ios',
          ),
          <String, bool>{kWinnClientCapabilityRelay: true});
      expect(
          winnClientRelayCapabilityFlags(
            operatingSystem: ' Android ',
            supportsWinn3: true,
            supportsWinn3Descriptor: true,
            buildValue: 'android',
          ),
          <String, bool>{kWinnClientCapabilityRelay: true});
    });

    test('a malformed define empties the whole set', () {
      for (final bad in <String>[
        'Android',
        ' android',
        'android ',
        'android,android',
        'android,',
        ',android',
        'android,plan9',
        'plan9',
        ' ',
        'android, ios',
      ]) {
        expect(winn3RelayBuildEnabledPlatforms(bad), isEmpty, reason: bad);
        expect(
            winnClientRelayCapabilityFlags(
              operatingSystem: 'android',
              supportsWinn3: true,
              supportsWinn3Descriptor: true,
              buildValue: bad,
            ),
            isEmpty,
            reason: bad);
      }
      expect(winn3RelayBuildEnabledPlatforms('android,ios'),
          <String>{'android', 'ios'});
    });

    test('it needs supports_winn3 and the descriptor ring, and closes while '
        'suppressed', () {
      Map<String, bool> flags({
        bool winn3 = true,
        bool ring = true,
        bool suppressed = false,
      }) =>
          winnClientRelayCapabilityFlags(
            operatingSystem: 'android',
            supportsWinn3: winn3,
            supportsWinn3Descriptor: ring,
            suppressed: suppressed,
            buildValue: 'android',
          );
      expect(flags(), <String, bool>{kWinnClientCapabilityRelay: true});
      expect(flags(winn3: false), isEmpty);
      expect(flags(ring: false), isEmpty);
      expect(flags(suppressed: true), isEmpty);
    });

    test('the suppression window is five minutes, in memory, exclusive at '
        'the end', () {
      final now = DateTime.utc(2026, 10, 24, 12);
      expect(kWinn3RelaySuppressionWindow, const Duration(minutes: 5));
      expect(winn3RelaySuppressed(until: null, now: now), isFalse);
      final until = winn3RelaySuppressionUntil(now);
      expect(until, now.add(const Duration(minutes: 5)));
      expect(winn3RelaySuppressed(until: until, now: now), isTrue);
      expect(
          winn3RelaySuppressed(
              until: until, now: until.subtract(const Duration(seconds: 1))),
          isTrue);
      expect(winn3RelaySuppressed(until: until, now: until), isFalse);
      expect(
          winn3RelaySuppressed(
              until: until, now: until.add(const Duration(seconds: 1))),
          isFalse);
    });
  });

  group('cache rules', () {
    Future<Map<String, dynamic>> freshCached(Map<String, dynamic> config,
        {required DateTime now}) async {
      return stampVpnConfigFetchedAt(config, now);
    }

    test('a config carrying a relay never skips the hub', () async {
      // Inside the signed descriptor lifetime, so only the relay can decide.
      final now = insideLifetime();
      final plain = await freshCached(await singleHopConfig(), now: now);
      expect(
          maySkipControlPlaneRefreshWithCachedConfig(
            cachedConfig: plain,
            automaticMode: false,
            coverExactTarget: false,
            now: now,
          ),
          isTrue,
          reason: 'control: a fresh explicit single hop v3 cache still skips');
      expect(
          cachedConfigIsExplicitWinn3FastPathCandidate(
            cachedConfig: plain,
            automaticMode: false,
            coverExactTarget: false,
          ),
          isTrue);

      for (final carrier in <Map<String, dynamic>>[
        <String, dynamic>{kWinn3RelayKey: relayValue()},
        <String, dynamic>{kWinn3RelayKeyCompat: relayValue()},
        <String, dynamic>{kWinn3RelayKey: 'malformed'},
        <String, dynamic>{kWinn3RelayKey: <String, dynamic>{}},
        // D2: a PRESENT null is a malformed relay, not an absent one.
        <String, dynamic>{kWinn3RelayKey: null},
        <String, dynamic>{kWinn3RelayKeyCompat: null},
      ]) {
        final cached = await freshCached(
            await relayConfig(overrides: <String, dynamic>{
              kWinn3RelayKey: null,
              ...carrier,
            }),
            now: now);
        expect(
            maySkipControlPlaneRefreshWithCachedConfig(
              cachedConfig: cached,
              automaticMode: false,
              coverExactTarget: false,
              now: now,
            ),
            isFalse,
            reason: '$carrier');
        expect(
            cachedConfigIsExplicitWinn3FastPathCandidate(
              cachedConfig: cached,
              automaticMode: false,
              coverExactTarget: false,
            ),
            isFalse,
            reason: '$carrier');
      }
    });

    test('the served plan comparison includes the relay', () async {
      final base = await relayConfig();
      expect(kWinn3ServedPlanKeys.contains(kWinn3RelayKey), isTrue);
      expect(winn3ServedPlanChanged(previous: base, current: base), isFalse);
      final moved = await relayConfig(overrides: <String, dynamic>{
        kWinn3RelayKey: relayValue(endpoint: '198.51.100.10:9211'),
      });
      expect(winn3ServedPlanChanged(previous: base, current: moved), isTrue);
      final withdrawn = Map<String, dynamic>.from(base)
        ..remove(kWinn3RelayKey);
      expect(
          winn3ServedPlanChanged(previous: base, current: withdrawn), isTrue);
      expect(
          winn3ServedPlanChanged(previous: withdrawn, current: base), isTrue);
    });
  });

  group('failure action', () {
    Future<Map<String, dynamic>> relayLed() => relayConfig();

    test('a path failure of a relay-led fresh connect suppresses and retries',
        () async {
      final config = await relayLed();
      for (final row in <(Winn3NativeVerdict, Winn3FailureShape)>[
        (Winn3NativeVerdict.ordinaryConnectivity, Winn3FailureShape.unclassified),
        (
          Winn3NativeVerdict.ordinaryConnectivity,
          Winn3FailureShape.unconfirmedTerminal
        ),
        (
          Winn3NativeVerdict.unknownTerminal,
          Winn3FailureShape.unconfirmedTerminal
        ),
        // What Android really publishes for a silent handshake: the typed
        // unknown_terminal verdict with the security-refusal bit, which the
        // Dart verdict reader maps to terminalSecurity. Only the shape says
        // it was silence and not a refusal.
        (
          Winn3NativeVerdict.terminalSecurity,
          Winn3FailureShape.unconfirmedTerminal
        ),
      ]) {
        expect(
            winn3RelayFailureAction(
              config: config,
              isUpgradeAttempt: false,
              retryAlreadyUsed: false,
              verdict: row.$1,
              shape: row.$2,
            ),
            Winn3RelayFailureAction.suppressAndRetry,
            reason: '$row');
      }
    });

    test('the readiness an Android silent handshake publishes retries, a '
        'typed refusal does not', () async {
      final config = await relayLed();
      Map<String, Object?> readiness(String verdict) => <String, Object?>{
            'winn3_start_token': 41,
            'winn3_start_generation': 7,
            'winn3_selection_generation': 'g',
            'winn3_failed_node': '',
            'winn3_security_refusal':
                verdict == 'terminal_security' || verdict == 'unknown_terminal',
            'winn3_verdict': verdict,
            'winn3_start_state': verdict,
          };
      Winn3RelayFailureAction actionFor(String verdict) {
        final sample = readiness(verdict);
        return winn3RelayFailureAction(
          config: config,
          isUpgradeAttempt: false,
          retryAlreadyUsed: false,
          // The very readers _startTunnelCandidate uses on the real sample.
          verdict: nativeWinn3ReadinessVerdict(sample, startToken: 41),
          shape: mergeWinn3FailureShape(Winn3FailureShape.unclassified,
              nativeWinn3FailureShape(sample, startToken: 41)),
        );
      }

      // Control: the verdict reader maps the silent handshake to
      // terminalSecurity, which is why the verdict alone cannot decide.
      expect(nativeWinn3ReadinessVerdict(readiness('unknown_terminal'),
              startToken: 41),
          Winn3NativeVerdict.terminalSecurity);
      expect(actionFor('unknown_terminal'),
          Winn3RelayFailureAction.suppressAndRetry);
      expect(actionFor('terminal_security'), Winn3RelayFailureAction.none);
      expect(actionFor('pending'), Winn3RelayFailureAction.none);
    });

    test('a sample with no matching start token cannot trigger a retry', () async {
      final config = await relayLed();
      final stale = <String, Object?>{
        'winn3_start_token': 40,
        'winn3_security_refusal': true,
        'winn3_verdict': 'unknown_terminal',
      };
      expect(
          winn3RelayFailureAction(
            config: config,
            isUpgradeAttempt: false,
            retryAlreadyUsed: false,
            verdict: nativeWinn3ReadinessVerdict(stale, startToken: 41),
            shape: nativeWinn3FailureShape(stale, startToken: 41),
          ),
          Winn3RelayFailureAction.none);
    });

    test('a typed security refusal or an unknown outcome is never a relay '
        'path failure', () async {
      final config = await relayLed();
      for (final row in <(Winn3NativeVerdict, Winn3FailureShape)>[
        (Winn3NativeVerdict.terminalSecurity, Winn3FailureShape.unclassified),
        (Winn3NativeVerdict.terminalSecurity, Winn3FailureShape.securityRefusal),
        (
          Winn3NativeVerdict.ordinaryConnectivity,
          Winn3FailureShape.securityRefusal
        ),
        (
          Winn3NativeVerdict.unknownTerminal,
          Winn3FailureShape.securityRefusal
        ),
        (Winn3NativeVerdict.unknownTerminal, Winn3FailureShape.unclassified),
        (Winn3NativeVerdict.pending, Winn3FailureShape.unconfirmedTerminal),
        (Winn3NativeVerdict.pending, Winn3FailureShape.unclassified),
        (Winn3NativeVerdict.connected, Winn3FailureShape.unclassified),
      ]) {
        expect(
            winn3RelayStartFailureIsPathFailure(
                verdict: row.$1, shape: row.$2),
            isFalse,
            reason: '$row');
        expect(
            winn3RelayFailureAction(
              config: config,
              isUpgradeAttempt: false,
              retryAlreadyUsed: false,
              verdict: row.$1,
              shape: row.$2,
            ),
            Winn3RelayFailureAction.none,
            reason: '$row');
      }
    });

    test('an upgrade attempt, or a retry already used, only suppresses',
        () async {
      final config = await relayLed();
      expect(
          winn3RelayFailureAction(
            config: config,
            isUpgradeAttempt: true,
            retryAlreadyUsed: false,
            verdict: Winn3NativeVerdict.unknownTerminal,
            shape: Winn3FailureShape.unconfirmedTerminal,
          ),
          Winn3RelayFailureAction.suppressOnly);
      expect(
          winn3RelayFailureAction(
            config: config,
            isUpgradeAttempt: false,
            retryAlreadyUsed: true,
            verdict: Winn3NativeVerdict.unknownTerminal,
            shape: Winn3FailureShape.unconfirmedTerminal,
          ),
          Winn3RelayFailureAction.suppressOnly);
    });

    test('a config without a valid relay never triggers it', () async {
      for (final config in <Map<String, dynamic>>[
        await singleHopConfig(),
        await relayConfig(overrides: <String, dynamic>{
          kWinn3RelayKey: relayValue(v: 2),
        }),
        await relayConfig(overrides: <String, dynamic>{kWinn3RelayKey: null}),
      ]) {
        expect(
            winn3RelayFailureAction(
              config: config,
              isUpgradeAttempt: false,
              retryAlreadyUsed: false,
              verdict: Winn3NativeVerdict.unknownTerminal,
              shape: Winn3FailureShape.unconfirmedTerminal,
            ),
            Winn3RelayFailureAction.none);
      }
    });
  });

  group('connect wiring (source order, no device)', () {
    final main = File('lib/main.dart').readAsStringSync();

    int at(String needle, {int from = 0}) {
      final index = main.indexOf(needle, from);
      expect(index, greaterThanOrEqualTo(0), reason: needle);
      return index;
    }

    test('the relay failure branch runs before the cover node rotation, the '
        'security refusal branch and the upgrade restore', () {
      final connect = at('Future<void> _connectWithSmartProtocol({');
      final action = at('winn3RelayFailureAction(', from: connect);
      final upgradeRestore = at(
          'await _restoreSingleHopAfterDoubleVpnHandover(',
          from: connect);
      final securityRefusal =
          at('if (_lastTunnelCandidateWasSecurityRefusal) {', from: action);
      final coverRotation =
          at('final selectLegacyRouteAfterWinn3 =', from: connect);
      final indexOfCover =
          at('indexOfCoverBearingWinn1Fallback(', from: connect);
      expect(action, lessThan(upgradeRestore));
      expect(action, lessThan(securityRefusal));
      expect(action, lessThan(coverRotation));
      expect(action, lessThan(indexOfCover));
    });

    test('the retry stops the tunnel through the failover stop, is guarded and '
        'runs exactly one full connect', () {
      final connect = at('Future<void> _connectWithSmartProtocol({');
      final branch = at(
          'if (relayFailure == Winn3RelayFailureAction.suppressAndRetry) {',
          from: connect);
      final stop = at('await _stopNativeTunnelForFailover()', from: branch);
      final guardOn = at('_winn3RelayRetryInProgress = true;', from: branch);
      final retry = at('await _connectWithSmartProtocol();', from: guardOn);
      final guardOff =
          at('_winn3RelayRetryInProgress = false;', from: retry);
      expect(stop, lessThan(guardOn));
      expect(guardOn, lessThan(retry));
      expect(retry, lessThan(guardOff));
      expect(main.contains('retryAlreadyUsed: _winn3RelayRetryInProgress'),
          isTrue);
      // The window is opened for every non-none action, in memory only.
      expect(
          main.contains(
              '_winn3RelaySuppressedUntil = winn3RelaySuppressionUntil(DateTime.now());'),
          isTrue);
      final window = RegExp(r'_winn3RelaySuppressedUntil')
          .allMatches(main)
          .length;
      expect(window, greaterThanOrEqualTo(3));
      expect(main.contains("'winn3_relay_suppressed"), isFalse,
          reason: 'the window is never persisted');
    });

    test('the capability getter adds the relay flag and consults the window',
        () {
      final getter = at('Map<String, bool> get _winnCapabilityFlags {');
      final relay = at('winnClientRelayCapabilityFlags(', from: getter);
      final suppressed =
          at('winn3RelaySuppressed(', from: getter);
      expect(relay, greaterThan(getter));
      expect(suppressed, greaterThan(relay));
      expect(relay - getter, lessThan(1800));
    });

    test('the three request builders spread the dynamic capability map', () {
      expect('..._winnCapabilityFlags,'.allMatches(main).length, 3);
    });

    test('F-04: a failed relay-led attempt never strikes the direct UDP '
        'memory of the network', () {
      final attempt = at('Future<bool> attemptDirectAwgCandidate() async {');
      final guard = at('(started || !winn3ConfigCarriesRelay(directCandidateConfig))',
          from: attempt);
      final record = at('await _recordDirectUdpOutcome(', from: attempt);
      expect(guard, lessThan(record));
      // The guard sits inside the same condition as the other no-strike rules
      // (security refusal, permission), not as a separate later branch.
      final condition = main.substring(
          at('if (!_lastTunnelCandidateWasSecurityRefusal &&', from: attempt),
          record);
      expect(condition, contains('(started || !_lastAppleTunnelNeedsPermissionApproval) &&'));
      expect(condition, contains('winn3ConfigCarriesRelay(directCandidateConfig)'));
      // A success is still recorded: the only change is for started == false.
      expect(condition.contains('(started ||'), isTrue);
    });

    test('F-04: the failure shape is merged from the same readiness sample '
        'as the verdict, in both readiness loops', () {
      final start = at('Future<bool> _waitForTunnelReady(');
      final end = at('Future<bool> _stopNativeTunnel({', from: start);
      final body = main.substring(start, end);
      final verdicts = RegExp(r'mergeWinn3NativeVerdict\(').allMatches(body);
      final shapes = RegExp(
              r'_lastWinn3FailureShape = mergeWinn3FailureShape\(\s*'
              r'_lastWinn3FailureShape,\s*nativeWinn3FailureShape\(readiness, '
              r'startToken: winn3StartToken\)')
          .allMatches(body);
      expect(verdicts.length, 2);
      expect(shapes.length, 2);
      // Each shape merge sits between its verdict merge and the ready-state
      // gate that can return false.
      var from = 0;
      for (var i = 0; i < 2; i++) {
        final verdict = body.indexOf('mergeWinn3NativeVerdict(', from);
        final shape = body.indexOf('_lastWinn3FailureShape = mergeWinn3FailureShape(',
            verdict);
        final gate =
            body.indexOf('if (!nativeWinn3VerdictAllowsReadyState(verdict))', shape);
        expect(verdict, greaterThanOrEqualTo(0));
        expect(shape, greaterThan(verdict));
        expect(gate, greaterThan(shape));
        from = gate;
      }
    });

    test('the peer endpoint of the raw config follows a bound relay', () {
      final raw = at('String _buildRawAmneziaConfig(');
      final section = at('final winnSection = winnSectionForTunnelConfig(',
          from: raw);
      final relayPeer = at('readWinn3ServedRelay(config).relay?.endpoint',
          from: raw);
      // The binding is enforced (and throws) before the relay peer is read.
      expect(section, lessThan(relayPeer));
    });
  });
}
