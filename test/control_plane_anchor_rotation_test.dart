import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/control_plane_pinning.dart';

/// Real-TLS tests of the anchor-set design over the PRODUCTION connect path:
/// the client's own SecureSocket.secure, its own SecurityContext, the
/// platform's chain, hostname and date checks and the default pre-send leaf
/// gate. Only the TCP connect is redirected to a loopback server, through
/// [ControlPlaneTcpConnector]; no leaf verifier or connection factory is
/// overridden.
///
/// Synthetic EC P-256 material minted 2026-10-04 with openssl for these tests
/// only (base64 DER, no key armor in the repository):
///   root A (CN=SyntheticAnchorRootA) -> intermediate A1 -> leaves A1 and A2
///     (SAN sync.winsvpn.org, hub.winsvpn.org; A2 has a NEW key: a renewal)
///     and leaf AEvil (SAN evil.example)
///   root B (CN=SyntheticAnchorRootB) -> leaf B (SAN sync.winsvpn.org)
/// Root A stands in for the CA serving today; root B stands in for another
/// CA (a Cloudflare CA switch or backup certificate), anchored or not.
const String kRootADer =
    'MIIBgjCCASigAwIBAgIUUoVDVQfUuCT2hQ8k3nk3zs4I8W4wCgYIKoZIzj0EAwIw'
    'HzEdMBsGA1UEAwwUU3ludGhldGljQW5jaG9yUm9vdEEwHhcNMjYxMDA0MTgwNTI3'
    'WhcNMzYxMDAxMTgwNTI3WjAfMR0wGwYDVQQDDBRTeW50aGV0aWNBbmNob3JSb290'
    'QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAVBq8pKTvjV05b8XLWZkeXciTuk'
    'BP+eoV2XABNYHEFq9P9IPIhrnu4HqdISkTNaCbYjpLLT5tUMDnxcGFY7uUmjQjBA'
    'MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTnx16m'
    '3lvYorrqIukP+JFGqRdIvTAKBggqhkjOPQQDAgNIADBFAiAoDbNdpuQxXLFqG2eE'
    'O3hQdabQyZA2AzKVy+zIzmq3QgIhALgnzrn3gm6i0phECwWlYWA0WusPidzkxWLN'
    'ZULfbQzp';
const String kIntADer =
    'MIIBmjCCAUGgAwIBAgIIEoUQ4umk7TMwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwU'
    'U3ludGhldGljQW5jaG9yUm9vdEEwHhcNMjYxMDA0MTgwNTI3WhcNMzYxMDAxMTgw'
    'NTI3WjAgMR4wHAYDVQQDDBVTeW50aGV0aWNJc3N1aW5nQ0EtQTEwWTATBgcqhkjO'
    'PQIBBggqhkjOPQMBBwNCAASbH4GhRt1KekoKK/AoPe8gCMhSSuvhLpzrh+EEfm20'
    'dAHT8DHoq9TjQPQaqNLm4Tg8VwEgODlV/kToJZe3KDuko2YwZDASBgNVHRMBAf8E'
    'CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUzghFvTkYdCgzu6K+'
    '32rkkCW5mUwwHwYDVR0jBBgwFoAU58dept5b2KK66iLpD/iRRqkXSL0wCgYIKoZI'
    'zj0EAwIDRwAwRAIgWqknr2OiuLn3gaFCltJv10EeOnuUJa8eqRdPwUp0mkoCIAWk'
    'lAGAUlE3JzizAJlWuMK3NWVS7wjm3h662vy8hBfs';
const String kLeafA1Der =
    'MIIB1zCCAX2gAwIBAgIJAJ9ppJcIcMk1MAoGCCqGSM49BAMCMCAxHjAcBgNVBAMM'
    'FVN5bnRoZXRpY0lzc3VpbmdDQS1BMTAeFw0yNjEwMDQxODA4MzBaFw0yODEyMTIx'
    'ODA4MzBaMBsxGTAXBgNVBAMMEHN5bmMud2luc3Zwbi5vcmcwWTATBgcqhkjOPQIB'
    'BggqhkjOPQMBBwNCAAQz4Paq6WLRVftXjdpXyJdKn0KovH4ifteJNDLhiErA354L'
    'l1WeCRtqWpmkWyVRR+oIc4FNzulYCf1TDAHdKax3o4GkMIGhMAwGA1UdEwEB/wQC'
    'MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQW'
    'BBTPCDbmrpF3qukktPKkdxWpqBrPaDAfBgNVHSMEGDAWgBTOCEW9ORh0KDO7or7f'
    'auSQJbmZTDAsBgNVHREEJTAjghBzeW5jLndpbnN2cG4ub3Jngg9odWIud2luc3Zw'
    'bi5vcmcwCgYIKoZIzj0EAwIDSAAwRQIhANL8SjY6Xzy1XC2a6R849bAWVoqWSmFp'
    'gc3dwO04tK7RAiA7tcKedc1Ba/6+lSb0o6aBQuQKAcnmrVLi1laYP3nXtQ==';
const String kLeafA1Key =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO5NRR1cDg2b8Fzqs'
    'fKZlha/FMAFWHBF3/Qzz/1eF9i2hRANCAAQz4Paq6WLRVftXjdpXyJdKn0KovH4i'
    'fteJNDLhiErA354Ll1WeCRtqWpmkWyVRR+oIc4FNzulYCf1TDAHdKax3';
const String kLeafA2Der =
    'MIIB1zCCAXygAwIBAgIIAlrGYAVd4TYwCgYIKoZIzj0EAwIwIDEeMBwGA1UEAwwV'
    'U3ludGhldGljSXNzdWluZ0NBLUExMB4XDTI2MTAwNDE4MDgzMFoXDTI4MTIxMjE4'
    'MDgzMFowGzEZMBcGA1UEAwwQc3luYy53aW5zdnBuLm9yZzBZMBMGByqGSM49AgEG'
    'CCqGSM49AwEHA0IABFFCVWhG3PHy6MOn5XeRi2E8NW48G6KEYsHvtLeE/lbpptV1'
    'nfS35saL0xQrwtd4TT5w07ikZF4g5SEdzgfcgRqjgaQwgaEwDAYDVR0TAQH/BAIw'
    'ADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYE'
    'FOhNLacje4dGax2QjD0F+kwM5qlRMB8GA1UdIwQYMBaAFM4IRb05GHQoM7uivt9q'
    '5JAluZlMMCwGA1UdEQQlMCOCEHN5bmMud2luc3Zwbi5vcmeCD2h1Yi53aW5zdnBu'
    'Lm9yZzAKBggqhkjOPQQDAgNJADBGAiEAzZ/yEPpYJWodwjKw6ocRiys/HPUMdict'
    'MrhHTblnBzsCIQDCZ2ry3qmBlCbTdZZq2JAyBsPnswmuOfUA4SAg1j4aOw==';
const String kLeafA2Key =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglKX4LSwluogcHDlu'
    'zhLvnrqfeUQRVaj0AktpecOMDi+hRANCAARRQlVoRtzx8ujDp+V3kYthPDVuPBui'
    'hGLB77S3hP5W6abVdZ30t+bGi9MUK8LXeE0+cNO4pGReIOUhHc4H3IEa';
const String kLeafAEvilDer =
    'MIIBvzCCAWSgAwIBAgIJAIb9mP4KGeWeMAoGCCqGSM49BAMCMCAxHjAcBgNVBAMM'
    'FVN5bnRoZXRpY0lzc3VpbmdDQS1BMTAeFw0yNjEwMDQxODA4MzBaFw0yODEyMTIx'
    'ODA4MzBaMBcxFTATBgNVBAMMDGV2aWwuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqG'
    'SM49AwEHA0IABKTCQsZnDSkt6xViPTwpEreNErdj5p1zTE1n3rnxrEi8Cl+FcevI'
    'F7coSzYNOVTogS+cnXFq8OVyJmTAGlSVZ3qjgY8wgYwwDAYDVR0TAQH/BAIwADAO'
    'BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFDCR'
    'Gx8qir4VPOt6Yg67M84mY1FRMB8GA1UdIwQYMBaAFM4IRb05GHQoM7uivt9q5JAl'
    'uZlMMBcGA1UdEQQQMA6CDGV2aWwuZXhhbXBsZTAKBggqhkjOPQQDAgNJADBGAiEA'
    'uJvig0H78Obi8iLHW63lZQTwKCAO3TLF+9kIMR1MJtgCIQC87/OiXLqFbd1GoZ6S'
    'bVq9lG2SAd2xf4B4ufzGayOF8Q==';
const String kLeafAEvilKey =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4lmoJHgSq76b4Gb8'
    'BP5sY5ciGhi5vgSLooGcxqXOd8yhRANCAASkwkLGZw0pLesVYj08KRK3jRK3Y+ad'
    'c0xNZ9658axIvApfhXHryBe3KEs2DTlU6IEvnJ1xavDlciZkwBpUlWd6';
const String kRootBDer =
    'MIIBgzCCASigAwIBAgIUE1y8fDy0mWW7SEYdncJaKkwc5qcwCgYIKoZIzj0EAwIw'
    'HzEdMBsGA1UEAwwUU3ludGhldGljQW5jaG9yUm9vdEIwHhcNMjYxMDA0MTgwNTI3'
    'WhcNMzYxMDAxMTgwNTI3WjAfMR0wGwYDVQQDDBRTeW50aGV0aWNBbmNob3JSb290'
    'QjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAAVvunrGijRvhWC79h9zKXX0Hp9'
    'Jd8WtSp2oX9Lm4avP82024lbdY2aw7z/x7JE0OCOfRlIyKzEl5UjPel/OzGjQjBA'
    'MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTpANMi'
    '0v6Azat5mYd3P7l4lmf/oTAKBggqhkjOPQQDAgNJADBGAiEAjF5Gt5wyMRBmvubz'
    'MAQEvWS5YIBC3Rcobqcw6CW+TfgCIQCD2E88ZWzN18wE/c8rouJTVUt7aYn70xxx'
    'asqs+f+ZiA==';
const String kLeafBDer =
    'MIIB1jCCAXygAwIBAgIJAKS2S6UjzOPcMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMM'
    'FFN5bnRoZXRpY0FuY2hvclJvb3RCMB4XDTI2MTAwNDE4MDgzMFoXDTI4MTIxMjE4'
    'MDgzMFowGzEZMBcGA1UEAwwQc3luYy53aW5zdnBuLm9yZzBZMBMGByqGSM49AgEG'
    'CCqGSM49AwEHA0IABNK+T9ge+TodJR0aBREQKmmQ32ERHrCj5gAwxOZFI962Sj9e'
    'LNa/1mAiU5JCaTn1RqxJsrUwzI07EAXFy7iaGx+jgaQwgaEwDAYDVR0TAQH/BAIw'
    'ADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYE'
    'FDnzKrNeQCCPAwYTO9l7aG5RShgtMB8GA1UdIwQYMBaAFOkA0yLS/oDNq3mZh3c/'
    'uXiWZ/+hMCwGA1UdEQQlMCOCEHN5bmMud2luc3Zwbi5vcmeCD2h1Yi53aW5zdnBu'
    'Lm9yZzAKBggqhkjOPQQDAgNIADBFAiAi2D/FqOgmRNsqkaTZ+Pf6kKunUJyEFPwt'
    'q+y/illXZgIhAKiKO18NrjjFFZbcWBRu5hdOv6qsyTFLSam7tL2gkPz1';
const String kLeafBKey =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeLZbJT/Hz1xPKdlB'
    'QwvwcNdONKw3uYEjLPSxA+Huvx+hRANCAATSvk/YHvk6HSUdGgURECppkN9hER6w'
    'o+YAMMTmRSPetko/XizWv9ZgIlOSQmk59UasSbK1MMyNOxAFxcu4mhsf';

String _pem(String label, String b64) {
  final body =
      b64.replaceAllMapped(RegExp(r'.{1,64}'), (m) => '${m.group(0)}\n');
  return '-----BEGIN $label-----\n$body-----END $label-----\n';
}

class _ChainServer {
  _ChainServer._(this._server) {
    _server.listen(_accept, onError: (Object _) {});
  }

  final SecureServerSocket _server;
  final List<String> requests = <String>[];
  int handshakesCompleted = 0;

  /// Every decrypted application byte the peer received, counted before any
  /// parsing, so a partial header counts as a leak.
  int bytesReceived = 0;

  int get port => _server.port;

  static Future<_ChainServer> start(
      List<String> chainDer, String keyDer) async {
    final SecurityContext context = SecurityContext()
      ..useCertificateChainBytes(
          utf8.encode(chainDer.map((c) => _pem('CERTIFICATE', c)).join()))
      ..usePrivateKeyBytes(utf8.encode(_pem('PRIVATE KEY', keyDer)));
    return _ChainServer._(await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4, 0, context));
  }

  Future<void> _accept(SecureSocket client) async {
    handshakesCompleted++;
    final buffer = <int>[];
    try {
      await for (final data in client.timeout(const Duration(seconds: 5))) {
        bytesReceived += data.length;
        buffer.addAll(data);
        final raw = utf8.decode(buffer, allowMalformed: true);
        final end = raw.indexOf('\r\n\r\n');
        if (end < 0) continue;
        final length = int.tryParse(
                RegExp(r'content-length:\s*(\d+)', caseSensitive: false)
                        .firstMatch(raw.substring(0, end))
                        ?.group(1) ??
                    '0') ??
            0;
        if (buffer.length < end + 4 + length) continue;
        requests.add(raw);
        client.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
            'Connection: close\r\n\r\nOK');
        await client.flush();
        break;
      }
    } catch (_) {
      // A refused or half-open client is the expected case in several tests.
    } finally {
      client.destroy();
    }
  }

  Future<void> close() => _server.close();
}

/// Maps every compiled hostname to [server] and records which hosts the
/// client opened TCP connections for.
ControlPlaneTcpConnector _loopback(_ChainServer server, List<String> opened) =>
    (String host, int port) {
      opened.add(host);
      return Socket.startConnect(InternetAddress.loopbackIPv4, server.port);
    };

void main() {
  late List<String> opened;
  setUp(() => opened = <String>[]);

  Future<int> post(_ChainServer server, List<String> anchors) async {
    final client = createPinnedControlPlaneClient(
      extraTrustAnchorsDer: anchors.map(base64Decode).toList(),
      tcpConnector: _loopback(server, opened),
    );
    try {
      final response = await client
          .post(
            Uri.parse('https://sync.winsvpn.org/verify'),
            headers: const <String, String>{
              'X-Wins-Activation': 'synthetic-test-value',
            },
            body: 'synthetic-sensitive-body',
          )
          .timeout(const Duration(seconds: 10));
      return response.statusCode;
    } finally {
      client.close();
    }
  }

  test('a renewal with a new key under an anchored CA keeps working', () async {
    final before =
        await _ChainServer.start(<String>[kLeafA1Der, kIntADer], kLeafA1Key);
    final after =
        await _ChainServer.start(<String>[kLeafA2Der, kIntADer], kLeafA2Key);
    try {
      expect(spkiSha256Base64OfCertificate(base64Decode(kLeafA1Der)),
          isNot(spkiSha256Base64OfCertificate(base64Decode(kLeafA2Der))),
          reason: 'the renewal must carry a new key');
      expect(await post(before, <String>[kRootADer]), 200);
      expect(await post(after, <String>[kRootADer]), 200);
      expect(before.requests.single, contains('synthetic-sensitive-body'));
      expect(after.requests.single, contains('synthetic-sensitive-body'));
      expect(before.bytesReceived, greaterThan(0),
          reason: 'the byte counter must see an accepted request');
    } finally {
      await before.close();
      await after.close();
    }
  });

  test(
      'a hostname-valid leaf from an unanchored chain is refused before any '
      'request byte', () async {
    final server = await _ChainServer.start(<String>[kLeafBDer], kLeafBKey);
    try {
      await expectLater(post(server, <String>[kRootADer]),
          throwsA(isA<HandshakeException>()));
      expect(opened, <String>['sync.winsvpn.org'],
          reason: 'TCP was opened, so TLS is what refused it');
      expect(server.bytesReceived, 0,
          reason: 'not even a partial header may reach the peer');
      expect(server.requests, isEmpty,
          reason: 'no header or body byte may reach the peer');
    } finally {
      await server.close();
    }
  });

  test('a CA switch to another anchored root keeps working', () async {
    final server = await _ChainServer.start(<String>[kLeafBDer], kLeafBKey);
    try {
      expect(await post(server, <String>[kRootADer, kRootBDer]), 200);
      expect(server.requests, hasLength(1));
    } finally {
      await server.close();
    }
  });

  test(
      'the compiled anchors alone refuse a chain to a non-compiled root, '
      'with no request byte sent', () async {
    final server =
        await _ChainServer.start(<String>[kLeafA1Der, kIntADer], kLeafA1Key);
    try {
      await expectLater(
          post(server, const <String>[]), throwsA(isA<HandshakeException>()));
      expect(opened, <String>['sync.winsvpn.org']);
      expect(server.bytesReceived, 0);
      expect(server.requests, isEmpty);
    } finally {
      await server.close();
    }
  });

  test('an anchored leaf for another hostname is refused', () async {
    final server = await _ChainServer.start(
        <String>[kLeafAEvilDer, kIntADer], kLeafAEvilKey);
    try {
      await expectLater(post(server, <String>[kRootADer]),
          throwsA(isA<HandshakeException>()));
      expect(server.bytesReceived, 0);
      expect(server.requests, isEmpty);
    } finally {
      await server.close();
    }
  });

  test('a host outside the compiled set never opens a TCP connection',
      () async {
    final server = await _ChainServer.start(
        <String>[kLeafAEvilDer, kIntADer], kLeafAEvilKey);
    final client = createPinnedControlPlaneClient(
      extraTrustAnchorsDer: <List<int>>[base64Decode(kRootADer)],
      tcpConnector: _loopback(server, opened),
    );
    try {
      await expectLater(
          client
              .get(Uri.parse('https://evil.example/'))
              .timeout(const Duration(seconds: 10)),
          throwsA(isA<HandshakeException>()));
      expect(opened, isEmpty);
      expect(server.handshakesCompleted, 0);
      expect(server.bytesReceived, 0);
    } finally {
      client.close();
      await server.close();
    }
  });
}
