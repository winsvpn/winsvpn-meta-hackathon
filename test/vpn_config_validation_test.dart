import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/vpn_config_validation.dart';

Map<String, dynamic> validConfig({bool stealth = false}) => {
      'client_private_key': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
      'server_public_key': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
      'preshared_key': '',
      'client_ip': '10.8.1.2',
      'dns': '10.8.1.1',
      'server_endpoint': '203.0.113.20:9110',
      'mtu': 1280,
      'obfuscation': <String, dynamic>{
        'Jc': 2,
        'Jmin': 10,
        'Jmax': 30,
        'S1': 16,
        'S2': 80,
        'S3': 16,
        'S4': 0,
        'H1': 11,
        'H2': 22,
        'H3': 33,
        'H4': 44,
      },
      'stealth_active': stealth,
      'xray': {
        'uuid': '123e4567-e89b-42d3-a456-426614174000',
        'host': 'edge.example.com',
        'server_name': 'edge.example.com',
        'path': '/wins-stealth-tunnel',
        'port': 443,
        'security': 'tls',
        'local_port': 42110,
        'remote_awg_host': '127.0.0.1',
        'remote_awg_port': 9110,
      },
    };

Map<String, dynamic> configWithRoutes(List<String> routes) {
  final config = validConfig();
  config['allowedIPv4Routes'] = routes;
  return config;
}

void main() {
  test('accepts complete direct and fallback configurations', () {
    expect(VpnConfigValidator.isUsable(validConfig()), isTrue);
    expect(VpnConfigValidator.isUsable(validConfig(stealth: true)), isTrue);

    final deployedIdentity = validConfig(stealth: true);
    (deployedIdentity['xray'] as Map<String, dynamic>)['uuid'] =
        'ffffffff-ffff-ffff-8fff-ffffffffffff';
    expect(VpnConfigValidator.isUsable(deployedIdentity), isTrue);
  });

  test('rejects native-config line injection and invalid keys', () {
    final injected = validConfig()
      ..['server_endpoint'] = '203.0.113.20:9110\nDNS = 6.6.6.6';
    final badKey = validConfig()..['server_public_key'] = 'not-a-key';

    expect(VpnConfigValidator.isUsable(injected), isFalse);
    expect(VpnConfigValidator.isUsable(badKey), isFalse);
  });

  test('rejects unsafe endpoints and inconsistent local fallback ports', () {
    final privateEndpoint = validConfig()
      ..['server_endpoint'] = '192.168.50.2:9110';
    final wrongLoopbackPort = validConfig(stealth: true);
    (wrongLoopbackPort['xray'] as Map<String, dynamic>)['local_port'] = 42111;

    expect(VpnConfigValidator.isUsable(privateEndpoint), isFalse);
    expect(VpnConfigValidator.isUsable(wrongLoopbackPort), isFalse);
  });

  test('refuses IPv4 spellings that native parsers read as another address',
      () {
    // Dart reads a leading zero as decimal; glibc getaddrinfo and iproute2
    // read it as octal (0177.0.0.1 is 127.0.0.1, 0012.0.0.1 is 10.0.0.1).
    for (final spelling in const <String>[
      '0177.0.0.1',
      '0012.0.0.1',
      '10.10.0.053',
      '010.8.1.2',
      '000.1.2.3',
    ]) {
      expect(VpnConfigValidator.isIpv4(spelling, allowPrivate: false), isFalse,
          reason: spelling);
      expect(VpnConfigValidator.isIpv4(spelling, allowPrivate: true), isFalse,
          reason: spelling);
    }
    // getaddrinfo reads these "hostnames" as 127.0.0.1 in inet_aton form
    // (measured on Darwin; glibc does the same).
    for (final host in const <String>[
      '0177.0.0.1',
      '0x7f.0.0.1',
      '0x7f000001.x.0x1',
      '127.1',
      '1.2.3.4.5',
    ]) {
      expect(VpnConfigValidator.isPublicHost(host), isFalse, reason: host);
      expect(VpnConfigValidator.isEndpoint('$host:9110'), isFalse,
          reason: host);
    }
    expect(VpnConfigValidator.isUsable(
            validConfig()..['server_endpoint'] = '0177.0.0.1:9110'),
        isFalse);
    expect(VpnConfigValidator.isUsable(
            validConfig()..['server_endpoint'] = '0x7f.0.0.1:9110'),
        isFalse);
    expect(VpnConfigValidator.isUsable(validConfig()..['client_ip'] = '10.8.1.02'),
        isFalse);
    expect(VpnConfigValidator.isUsable(validConfig()..['dns'] = '010.8.1.1'),
        isFalse);
    final numericXrayHost = validConfig(stealth: true);
    (numericXrayHost['xray'] as Map<String, dynamic>)['host'] = '127.1';
    expect(VpnConfigValidator.isUsable(numericXrayHost), isFalse);

    // Canonical spellings and ordinary names behave as before.
    expect(VpnConfigValidator.isIpv4('10.0.0.1', allowPrivate: true), isTrue);
    expect(VpnConfigValidator.isIpv4('10.0.0.1', allowPrivate: false), isFalse);
    expect(VpnConfigValidator.isIpv4('203.0.113.20', allowPrivate: false),
        isTrue);
    expect(VpnConfigValidator.isIpv4('0.0.0.0', allowPrivate: true), isFalse);
    expect(VpnConfigValidator.isEndpoint('203.0.113.20:9110'), isTrue);
    expect(VpnConfigValidator.isEndpoint('node1.example.com:9110'), isTrue);
    expect(VpnConfigValidator.isPublicHost('1e100.net'), isTrue);
    expect(VpnConfigValidator.isPublicHost('edge.example.com'), isTrue);
  });

  test('refuses non-public IPv6 literals the IPv4 rule would refuse', () {
    // dart:io keeps the spelling of an expanded unspecified address and does
    // not call a mapped loopback isLoopback, so both used to pass.
    for (final host in const <String>[
      '0:0:0:0:0:0:0:0',
      '0:0:0:0:0:0:0:1',
      '::ffff:127.0.0.1',
      '::ffff:10.0.0.1',
      '::ffff:192.168.1.1',
      '::ffff:169.254.169.254',
      '::ffff:0.0.0.0',
      '::127.0.0.1',
      'fe80::1',
      'fc00::1',
      'fd00::1',
      'ff02::1',
      '64:ff9b::a00:1',
      '2002:7f00:1::1',
      '2002:c0a8:101::1',
    ]) {
      expect(VpnConfigValidator.isPublicHost(host), isFalse, reason: host);
      expect(VpnConfigValidator.isEndpoint('[$host]:9110'), isFalse,
          reason: host);
    }
    expect(VpnConfigValidator.isUsable(
            validConfig()..['server_endpoint'] = '[fd00::1]:9110'),
        isFalse);
    expect(VpnConfigValidator.isUsable(
            validConfig()..['server_endpoint'] = '[::ffff:192.168.50.2]:9110'),
        isFalse);
    // A zone ID is refused in brackets as it is bare (isPublicHost).
    for (final host in const <String>[
      '2606:4700:4700::1111%eth0',
      '2606:4700:4700::1111%25',
      '2606:4700:4700::1111%',
    ]) {
      expect(VpnConfigValidator.isPublicHost(host), isFalse, reason: host);
      expect(VpnConfigValidator.isEndpoint('[$host]:9110'), isFalse,
          reason: host);
    }
    expect(VpnConfigValidator.isUsable(validConfig()
          ..['server_endpoint'] = '[2606:4700:4700::1111%eth0]:9110'),
        isFalse);

    // Global unicast, and mapped or 6to4 forms of a public IPv4, still pass.
    for (final host in const <String>[
      '2606:4700:4700::1111',
      '2001:db8::1',
      '::ffff:203.0.113.20',
      '2002:cb00:7114::1',
    ]) {
      expect(VpnConfigValidator.isPublicHost(host), isTrue, reason: host);
      expect(VpnConfigValidator.isEndpoint('[$host]:9110'), isTrue,
          reason: host);
    }
    expect(VpnConfigValidator.isUsable(
            validConfig()..['server_endpoint'] = '[2606:4700:4700::1111]:9110'),
        isTrue);
  });

  test('rejects malformed fallback identity, host, and path', () {
    final badUuid = validConfig(stealth: true);
    (badUuid['xray'] as Map<String, dynamic>)['uuid'] = 'not-a-uuid';
    final zeroUuid = validConfig(stealth: true);
    (zeroUuid['xray'] as Map<String, dynamic>)['uuid'] =
        '00000000-0000-0000-0000-000000000000';
    final badHost = validConfig(stealth: true);
    (badHost['xray'] as Map<String, dynamic>)['host'] = '127.0.0.1';
    final badPath = validConfig(stealth: true);
    (badPath['xray'] as Map<String, dynamic>)['path'] = '/../admin';
    final unsupportedSecurity = validConfig(stealth: true);
    (unsupportedSecurity['xray'] as Map<String, dynamic>)['security'] =
        'reality';

    expect(VpnConfigValidator.isUsable(badUuid), isFalse);
    expect(VpnConfigValidator.isUsable(zeroUuid), isFalse);
    expect(VpnConfigValidator.isUsable(badHost), isFalse);
    expect(VpnConfigValidator.isUsable(badPath), isFalse);
    expect(VpnConfigValidator.isUsable(unsupportedSecurity), isFalse);
  });

  test('rejects injected, incomplete, and inconsistent AWG obfuscation', () {
    final injected = validConfig();
    (injected['obfuscation'] as Map<String, dynamic>)['H4'] =
        '44\nTable = auto';
    final incomplete = validConfig();
    (incomplete['obfuscation'] as Map<String, dynamic>).remove('S3');
    final inconsistent = validConfig();
    (inconsistent['obfuscation'] as Map<String, dynamic>)['Jmin'] = 31;

    expect(VpnConfigValidator.isUsable(injected), isFalse);
    expect(VpnConfigValidator.isUsable(incomplete), isFalse);
    expect(VpnConfigValidator.isUsable(inconsistent), isFalse);
  });

  test('accepts a well-formed allowedIPv4Routes list and an empty one', () {
    expect(
      VpnConfigValidator.isUsable(
        configWithRoutes(['10.8.1.0/24', '192.0.2.0/26']),
      ),
      isTrue,
    );
    expect(VpnConfigValidator.isUsable(configWithRoutes([])), isTrue);
  });

  test('rejects malformed allowedIPv4Routes fixtures', () {
    final badOctet = validConfig()
      ..['allowedIPv4Routes'] = ['300.1.2.3/24'];
    final badPrefix = validConfig()
      ..['allowedIPv4Routes'] = ['10.0.0.0/33'];
    final nonNumericPrefix = validConfig()
      ..['allowedIPv4Routes'] = ['10.0.0.0/aa'];
    final missingOctet = validConfig()
      ..['allowedIPv4Routes'] = ['10.0.0/24'];
    final notAList = validConfig()
      ..['allowedIPv4Routes'] = '10.0.0.0/24';
    final mixedWithBad = validConfig()
      ..['allowedIPv4Routes'] = ['10.0.0.0/8', '999.1.2.3/16'];

    expect(VpnConfigValidator.isUsable(badOctet), isFalse);
    expect(VpnConfigValidator.isUsable(badPrefix), isFalse);
    expect(VpnConfigValidator.isUsable(nonNumericPrefix), isFalse);
    expect(VpnConfigValidator.isUsable(missingOctet), isFalse);
    expect(VpnConfigValidator.isUsable(notAList), isFalse);
    expect(VpnConfigValidator.isUsable(mixedWithBad), isFalse);
  });

  test('excludes any /0 default route from allowedIPv4Routes', () {
    final literalDefault = validConfig()
      ..['allowedIPv4Routes'] = ['0.0.0.0/0'];
    final shiftedDefault = validConfig()
      ..['allowedIPv4Routes'] = ['192.0.2.0/0'];

    expect(VpnConfigValidator.isUsable(literalDefault), isFalse);
    expect(VpnConfigValidator.isUsable(shiftedDefault), isFalse);
    expect(VpnConfigValidator.isAllowedIpv4Route('0.0.0.0/0'), isFalse);
    expect(VpnConfigValidator.isAllowedIpv4Route('10.0.0.0/8'), isTrue);
  });

  test('structural usability does not authorize persisted v1 protocol selection',
      () {
    expect(
      VpnConfigValidator.defaultPersistedProtocolVersion,
      'winn/1',
    );
    final omitted = validConfig();
    final v1 = validConfig()..['protocol_version'] = 'winn/1';
    final migrated = validConfig()
      ..['protocol_version'] = 'winn/3'
      ..['protocol_params'] = <String, dynamic>{'carrier': 'winn3'}
      ..['node_slug'] = 'spain';

    expect(VpnConfigValidator.isUsable(omitted), isTrue);
    expect(VpnConfigValidator.isUsable(v1), isTrue);
    expect(VpnConfigValidator.isUsable(migrated), isTrue);
    expect(VpnConfigValidator.persistedProtocolIsWinn1(omitted), isTrue);
    expect(VpnConfigValidator.persistedProtocolIsWinn1(v1), isTrue);
    expect(VpnConfigValidator.persistedProtocolIsWinn1(migrated), isFalse);
    expect(VpnConfigValidator.persistedProtocolVersion(migrated), 'winn/3');
    expect(VpnConfigValidator.persistedNodeSlug(migrated), 'spain');
    expect(VpnConfigValidator.persistedNodeSlug(null), isEmpty);
  });
}
