import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:wins_vpn/control_plane_pinning.dart';
import 'package:wins_vpn/gateway_failover.dart';
import 'package:wins_vpn/hub_request_window.dart';

/// Openssl-synthesized chain fixture for the F-07 leaf-SPKI gate tests:
/// self-signed CA `CN=SyntheticPinProbeCA` -> leaf `CN=127.0.0.1`
/// (SAN IP:127.0.0.1 + DNS:127.0.0.1, serverAuth EKU). Minted 2026-08-22
/// with `openssl req -x509` / `openssl x509 -req` on an EC P-256 key, purely
/// for these tests: throwaway synthetic material, no real host, no real key,
/// no production meaning. Stored base64-of-DER (no PEM armor) so no
/// private-key armor text sits in the repository; the test reconstructs the
/// PEM blocks at runtime for the local `SecureServerSocket`.
const String kSyntheticLeafDerBase64 =
    'MIIBxzCCAW2gAwIBAgIUD/oDFZmF2HdL7CId/cYw0V+g5v8wCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTU3ludGhl'
    'dGljUGluUHJvYmVDQTAeFw0yNjA4MjIyMTUyMjVaFw0zNjA4MTkyMTUyMjVaMBQxEjAQBgNVBAMMCTEyNy4wLjAu'
    'MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKobVxHIa88Hhdphl2OqnhEK0bUBxgUvx5zV6k50Wx3FbWOUWLkG'
    'ib+u6t9C6D00NXYh2+K/fFAjYU+w553vp/ujgZIwgY8wGgYDVR0RBBMwEYcEfwAAAYIJMTI3LjAuMC4xMAwGA1Ud'
    'EwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBT4ZH5x6Pk6jfbq'
    'rsouylvHOyXAiDAfBgNVHSMEGDAWgBS5Y4XKKDqi7NajAPESaFaoyRm4QzAKBggqhkjOPQQDAgNIADBFAiBHWaUa'
    'kG98v9eS3fXwKKvJHDdtkWfislMklyUAKWgbdgIhANSnRzHb4KJqP2BH0DXU5rFyi/X1zTYT5MQRKgg9OeT0';
const String kSyntheticCaDerBase64 =
    'MIIBojCCAUegAwIBAgIUSRBrwb6A4vQk8GacMrmKYEegYTQwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTU3ludGhl'
    'dGljUGluUHJvYmVDQTAeFw0yNjA4MjIyMTUwMjdaFw0zNjA4MTkyMTUwMjdaMB4xHDAaBgNVBAMME1N5bnRoZXRp'
    'Y1BpblByb2JlQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3mXI/cDWmLhgx4v3G2csaY7wC5t7hf+qrbXql'
    'fw2Uev4D15eskmw3jvNX0i71acfhMMXvfjVHIASGWpNF3tIbo2MwYTAdBgNVHQ4EFgQUuWOFyig6ouzWowDxEmhW'
    'qMkZuEMwHwYDVR0jBBgwFoAUuWOFyig6ouzWowDxEmhWqMkZuEMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E'
    'BAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhALhVag6q8uX+qEYdNz6Repf7CwkQw2EvP6GxRPLvCX1CAiEAkiLw/11q'
    'iIev5cayLe+B9iHE8hfz4WbJ/qi7RQ8B8Cw=';
const String kSyntheticLeafKeyPkcs8DerBase64 =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7izRQTtVyQJbs7XfmbJirmA4NpcZGk8uvkA5EDKt'
    '8dGhRANCAASqG1cRyGvPB4XaYZdjqp4RCtG1AcYFL8ec1epOdFsdxW1jlFi5Bom/rurfQug9NDV2Idviv3xQI2FP'
    'sOed76f7';

/// Second synthetic chain, minted for the WVP-001 pin-probe tests: CA
/// `CN=SyntheticPinProbeCA2` -> leaf `CN=sync.winsvpn.org` (SAN
/// DNS:sync.winsvpn.org + IP:127.0.0.1, serverAuth EKU). The leaf is a
/// hostname-valid, CA-anchored certificate for a LISTED control-plane host
/// whose SPKI is deliberately NOT among the pins, recreating the exact
/// CA-valid-unpinned-leaf posture of the finding. Minted 2026-08-22 with the
/// same throwaway discipline as the F-07 fixture; base64-of-DER, no key
/// armor in the repository.
const String kProbeLeafDerBase64 =
    'MIIBwTCCAWegAwIBAgICEJIwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUU3ludGhl'
    'dGljUGluUHJvYmVDQTIwHhcNMjYwODIzMDAwNzE3WhcNMzYwODIwMDAwNzE3WjAb'
    'MRkwFwYDVQQDDBBzeW5jLndpbnN2cG4ub3JnMFkwEwYHKoZIzj0CAQYIKoZIzj0D'
    'AQcDQgAElshaR63BZ7xy2zR3wiLxSl0T236dMZVziH9mrj7EemboUEwyLCucJ0hV'
    '7tRcHDNOOKqfXy5Buo2v9z2nnd4vL6OBljCBkzAhBgNVHREEGjAYghBzeW5jLndp'
    'bnN2cG4ub3JnhwR/AAABMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQE'
    'AwIHgDAJBgNVHRMEAjAAMB0GA1UdDgQWBBQBCn9Sx4LLbVnLJMDmcURfk8Q7dTAf'
    'BgNVHSMEGDAWgBTtAJLEXQcXYiNsrrl81m6ba7iEkzAKBggqhkjOPQQDAgNIADBF'
    'AiEA1EvsA6iO4XNFLDf96s3wTBVxrbiOznAzziasAEZ6Ss8CIFDirWRSaKX4Ocpj'
    'WHnX4j+vahiJQK4d7TNuKqIpUs8K';
const String kProbeCaDerBase64 =
    'MIIBgTCCASigAwIBAgIUPZz3Nt1OIZtX9phP/dfz2yIqHtQwCgYIKoZIzj0EAwIw'
    'HzEdMBsGA1UEAwwUU3ludGhldGljUGluUHJvYmVDQTIwHhcNMjYwODIzMDAwNzE3'
    'WhcNMzYwODIwMDAwNzE3WjAfMR0wGwYDVQQDDBRTeW50aGV0aWNQaW5Qcm9iZUNB'
    'MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEbh10CiT9pvLpMqt76b2mOA4DF1'
    'aCW3wkw0O9zNVH2mnU0Gw7lPwzHgXqRAIbv6mBIWaD4Rpk2evWNCbtIQXLmjQjBA'
    'MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTtAJLE'
    'XQcXYiNsrrl81m6ba7iEkzAKBggqhkjOPQQDAgNHADBEAiADr6j5G8SVAwE6aVra'
    'KZ3LhHQLDwN7ZsOnlLtaBce5oAIgUIoOF0d0TWRW8H9E882COMxY9nO6ZsnNMKKB'
    'thviFbE=';
const String kProbeLeafKeyPkcs8DerBase64 =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNzgwWb9P32s88tC1'
    'b75hG1kHPUJJ/lIY481NN9b0aWGhRANCAASWyFpHrcFnvHLbNHfCIvFKXRPbfp0x'
    'lXOIf2auPsR6ZuhQTDIsK5wnSFXu1FwcM044qp9fLkG6ja/3Paed3i8v';

String _pemBlock(String label, List<int> der) {
  final body = base64Encode(der)
      .replaceAllMapped(RegExp(r'.{1,64}'), (m) => '${m.group(0)}\n');
  return '-----BEGIN $label-----\n$body-----END $label-----\n';
}

/// The 2026-10-04 chains (leaf, WE1, GTS Root R4 cross-signed by GlobalSign
/// Root CA) of every control-plane host, captured with
/// `openssl s_client -showcerts -servername <host> -connect <host>:443`.
/// Public certificates only.
const Map<String, String> kLiveChainFixtures20261004 = <String, String>{
  'winsvpn.org': 'test/fixtures/control_plane_chains_20261004/winsvpn.org.pem',
  'www.winsvpn.org':
      'test/fixtures/control_plane_chains_20261004/www.winsvpn.org.pem',
  'sync.winsvpn.org':
      'test/fixtures/control_plane_chains_20261004/sync.winsvpn.org.pem',
  'hub.winsvpn.org':
      'test/fixtures/control_plane_chains_20261004/hub.winsvpn.org.pem',
  'sync.winsvpn.com':
      'test/fixtures/control_plane_chains_20261004/sync.winsvpn.com.pem',
  'www.winsvpn.com':
      'test/fixtures/control_plane_chains_20261004/www.winsvpn.com.pem',
  'a.app-cloud-sync.net':
      'test/fixtures/control_plane_chains_20261004/a.app-cloud-sync.net.pem',
  'z.app-cloud-sync.net':
      'test/fixtures/control_plane_chains_20261004/z.app-cloud-sync.net.pem',
};

/// The six leaf SPKIs the 2026-08-21 build pinned. Every one was retired by
/// Cloudflare's 2026-10-02/03 renewal.
const Set<String> kRetiredLeafSpkis20260821 = <String>{
  'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=',
  'zGs7U9lcg3IogoAzwSfkDWhTbcwb0ooUYPej/E7mLgw=',
  'PMFihAZRdf6Fett/hmwNggLetHarYCq+Q467vKcU92c=',
  'mXPF7ncOVr1qyschbN29jqOw7yH9Y9SV3DxkSjfEA4g=',
  'Qz0797b14thCIeHWLMAhFYlWdAFjqhKun5QMEvnjH74=',
  'Doen/s030adq8PJQPoCv4s1SswqfZzfiU60DqXaxcJg=',
};

List<List<int>> _pemChainDer(String pem) {
  final derBlocks = <List<int>>[];
  for (final block in pem.split('-----BEGIN CERTIFICATE-----').skip(1)) {
    final b64 = block
        .split('-----END CERTIFICATE-----')
        .first
        .replaceAll(RegExp(r'\s'), '');
    derBlocks.add(base64Decode(b64));
  }
  return derBlocks;
}

List<List<int>> _anchorCertificates() =>
    _pemChainDer(kControlPlanePinnedCertificatePem);

/// DER (tag, length, content) of tbsCertificate element [index], counted after
/// the optional version: 0 serialNumber, 1 signature, 2 issuer, 3 validity,
/// 4 subject. Test-only; the library parses only the SPKI.
List<int> _tbsElement(List<int> der, int index) {
  (int, int) header(int offset) {
    final int first = der[offset + 1];
    if (first < 0x80) return (offset + 2, first);
    final int count = first & 0x7F;
    var length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | der[offset + 2 + i];
    }
    return (offset + 2 + count, length);
  }

  final (int tbsStart, _) = header(0);
  var (int cursor, _) = header(tbsStart);
  if (der[cursor] == 0xA0) {
    final (int start, int length) = header(cursor);
    cursor = start + length;
  }
  for (var i = 0;; i++) {
    final (int start, int length) = header(cursor);
    if (i == index) return der.sublist(cursor, start + length);
    cursor = start + length;
  }
}

/// openssl digest names for the certificate signature algorithms this suite
/// accepts, keyed by the DER content of the algorithm OID in hex. Anything
/// else fails the self-signature check.
const Map<String, String> _kSignatureDigests = <String, String>{
  '2a864886f70d01010b': 'sha256', // sha256WithRSAEncryption
  '2a864886f70d01010c': 'sha384', // sha384WithRSAEncryption
  '2a864886f70d01010d': 'sha512', // sha512WithRSAEncryption
  '2a8648ce3d040302': 'sha256', // ecdsa-with-SHA256
  '2a8648ce3d040303': 'sha384', // ecdsa-with-SHA384
  '2a8648ce3d040304': 'sha512', // ecdsa-with-SHA512
};

/// The signed part of a certificate: the whole tbsCertificate TLV, the
/// signatureAlgorithm OID content in hex, and the signatureValue BIT STRING
/// content without its unused-bits octet. Null when [der] is not shaped like
/// a certificate. Test-only.
({List<int> tbs, String algorithm, List<int> signature})? _signedParts(
    List<int> der) {
  (int, int) header(int offset) {
    final int first = der[offset + 1];
    if (first < 0x80) return (offset + 2, first);
    final int count = first & 0x7F;
    var length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | der[offset + 2 + i];
    }
    return (offset + 2 + count, length);
  }

  try {
    if (der[0] != 0x30) return null;
    final (int tbsAt, int certLength) = header(0);
    if (tbsAt + certLength != der.length || der[tbsAt] != 0x30) return null;
    final (int tbsBody, int tbsLength) = header(tbsAt);
    final int algorithmAt = tbsBody + tbsLength;
    if (der[algorithmAt] != 0x30) return null;
    final (int algorithmBody, int algorithmLength) = header(algorithmAt);
    if (der[algorithmBody] != 0x06) return null;
    final (int oidBody, int oidLength) = header(algorithmBody);
    final int signatureAt = algorithmBody + algorithmLength;
    if (der[signatureAt] != 0x03) return null;
    final (int signatureBody, int signatureLength) = header(signatureAt);
    if (signatureBody + signatureLength != der.length ||
        signatureLength < 2 ||
        der[signatureBody] != 0) {
      return null;
    }
    return (
      tbs: der.sublist(tbsAt, algorithmAt),
      algorithm: der
          .sublist(oidBody, oidBody + oidLength)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(),
      signature: der.sublist(signatureBody + 1, signatureBody + signatureLength),
    );
  } on RangeError {
    return null;
  }
}

class _RecordedHttpRequest {
  const _RecordedHttpRequest(this.method, this.path, this.headers, this.body);

  final String method;
  final String path;
  final Map<String, String> headers;
  final String body;
}

class _SyntheticTlsHttpServer {
  _SyntheticTlsHttpServer._(this._server, this._responseForRequest) {
    _server.listen(_accept, onError: (Object _) {});
  }

  final SecureServerSocket _server;
  final String Function(_RecordedHttpRequest request) _responseForRequest;
  final List<_RecordedHttpRequest> requests = <_RecordedHttpRequest>[];
  final Set<SecureSocket> _clients = <SecureSocket>{};
  final List<Future<void>> _handlers = <Future<void>>[];
  final List<Completer<void>> _connectionWaiters = <Completer<void>>[];
  int connectionCount = 0;
  int connectionsWithoutHttpBytes = 0;

  int get port => _server.port;

  static Future<_SyntheticTlsHttpServer> start(
    String Function(_RecordedHttpRequest request) responseForRequest,
  ) async {
    final List<int> caDer = base64Decode(kProbeCaDerBase64);
    final List<int> leafDer = base64Decode(kProbeLeafDerBase64);
    final List<int> keyDer = base64Decode(kProbeLeafKeyPkcs8DerBase64);
    final SecurityContext context = SecurityContext()
      ..useCertificateChainBytes(
        utf8.encode(
          _pemBlock('CERTIFICATE', leafDer) + _pemBlock('CERTIFICATE', caDer),
        ),
      )
      ..usePrivateKeyBytes(utf8.encode(_pemBlock('PRIVATE KEY', keyDer)));
    final SecureServerSocket server = await SecureServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      context,
    );
    return _SyntheticTlsHttpServer._(server, responseForRequest);
  }

  void _accept(SecureSocket client) {
    connectionCount++;
    for (final Completer<void> waiter in _connectionWaiters) {
      if (!waiter.isCompleted) waiter.complete();
    }
    _connectionWaiters.clear();
    _clients.add(client);
    late final Future<void> handler;
    handler = _serve(client).whenComplete(() {
      _clients.remove(client);
      _handlers.remove(handler);
    });
    _handlers.add(handler);
  }

  Future<void> _serve(SecureSocket client) async {
    final List<int> buffer = <int>[];
    try {
      int headerEndAt = -1;
      int expectedBody = -1;
      await for (final List<int> data in client.timeout(
        const Duration(seconds: 5),
        onTimeout: (_) => throw const SocketException('slow test client'),
      )) {
        buffer.addAll(data);
        final String raw = utf8.decode(buffer, allowMalformed: true);
        if (headerEndAt < 0) {
          headerEndAt = raw.indexOf('\r\n\r\n');
          if (headerEndAt >= 0) {
            final Map<String, String> headers = _parseHeaders(
              raw.substring(0, headerEndAt),
            );
            expectedBody = int.tryParse(headers['content-length'] ?? '') ?? 0;
          }
        }
        if (headerEndAt >= 0 &&
            expectedBody >= 0 &&
            buffer.length >= headerEndAt + 4 + expectedBody) {
          break;
        }
      }
      if (buffer.isEmpty) {
        connectionsWithoutHttpBytes++;
        return;
      }

      final String raw = utf8.decode(buffer, allowMalformed: true);
      if (headerEndAt < 0) return;
      final String headerBlock = raw.substring(0, headerEndAt);
      final List<String> headerLines = headerBlock.split('\r\n');
      final List<String> requestParts =
          headerLines.first.isEmpty ? <String>[] : headerLines.first.split(' ');
      final Map<String, String> headers = _parseHeaders(headerBlock);
      expectedBody = int.tryParse(headers['content-length'] ?? '') ?? 0;
      final String availableBody = raw.substring(headerEndAt + 4);
      final String body = availableBody.substring(
        0,
        expectedBody.clamp(0, availableBody.length),
      );
      final _RecordedHttpRequest request = _RecordedHttpRequest(
        requestParts.isNotEmpty ? requestParts[0] : '',
        requestParts.length > 1 ? requestParts[1] : '',
        headers,
        body,
      );
      requests.add(request);
      client.write(_responseForRequest(request));
      await client.flush();
    } catch (_) {
      if (buffer.isEmpty) connectionsWithoutHttpBytes++;
    } finally {
      client.destroy();
    }
  }

  static Map<String, String> _parseHeaders(String headerBlock) {
    final Map<String, String> headers = <String, String>{};
    for (final String line in headerBlock.split('\r\n').skip(1)) {
      final int colon = line.indexOf(':');
      if (colon > 0) {
        headers[line.substring(0, colon).trim().toLowerCase()] =
            line.substring(colon + 1).trim();
      }
    }
    return headers;
  }

  Future<void> waitForConnectionsToSettle() async {
    while (_handlers.isNotEmpty) {
      await Future.wait<void>(
        List<Future<void>>.from(_handlers),
      ).timeout(const Duration(seconds: 10));
    }
  }

  Future<void> waitForConnectionCount(int expected) async {
    while (connectionCount < expected) {
      final Completer<void> waiter = Completer<void>();
      _connectionWaiters.add(waiter);
      await waiter.future.timeout(const Duration(seconds: 10));
    }
  }

  Future<void> close() async {
    await _server.close();
    for (final SecureSocket client in _clients.toList()) {
      client.destroy();
    }
    await waitForConnectionsToSettle();
  }
}

const String _okResponse = 'HTTP/1.1 200 OK\r\n'
    'Content-Length: 2\r\n'
    'Connection: close\r\n\r\nOK';

/// Contract tests for the control-plane TLS anchor set.
///
/// The client trusts only the 12 CA roots in
/// [kControlPlanePinnedCertificatePem]; [kControlPlaneAnchorSpkiPins] records
/// their SPKI hashes, computed with
///   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER \
///     | openssl dgst -sha256 -binary | base64
/// and this suite asserts the two are identical, so neither side can drift.
void main() {
  // The 2026-08-21 *.winsvpn.org leaf (CN=winsvpn.org, notBefore 2026-08-05),
  // captured with `openssl s_client -servername sync.winsvpn.org -connect
  // sync.winsvpn.org:443 | openssl x509 -outform DER`. Its SPKI hash from the
  // openssl pipeline above is recordedLeafSpki20260821, which closes the loop
  // between the openssl ground truth and the Dart extractor offline.
  const recordedLeafSpki20260821 =
      'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=';
  const String liveSyncLeafDerBase64 =
      'MIIDezCCAyKgAwIBAgIRAJ/ZqCl1DuaiE7kcHp+izw0wCgYIKoZIzj0EAwIwOzELMAkGA1UEBhMCVVMxHjAcBgNV'
      'BAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEMMAoGA1UEAxMDV0UxMB4XDTI2MDgwNTE1MDEyMFoXDTI2MTEwMzE1'
      'NTg1M1owFjEUMBIGA1UEAxMLd2luc3Zwbi5vcmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASX2FWy9pfmErFv'
      '5JcOV//+6ZfVvwEBL6vNvKm88ZaJQ1qpQld1iB1jJIwW2f1aCHSAIzwCVReaBwPDjEtOG3ZQo4ICKjCCAiYwDgYD'
      'VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFMKLKDBKibRF'
      'ZHHBvx5QYXVHqpuYMB8GA1UdIwQYMBaAFJB3kjVnxP+ozKnme9mAeXvMk/k4MDUGCCsGAQUFBwEBBCkwJzAlBggr'
      'BgEFBQcwAoYZaHR0cDovL2kucGtpLmdvb2cvd2UxLmNydDAlBgNVHREEHjAcggt3aW5zdnBuLm9yZ4INKi53aW5z'
      'dnBuLm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vYy5wa2kuZ29vZy93'
      'ZTEvRnVjQjNfYWJZOTQuY3JsMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYA1219ENGn9XfCx+lf1wC/+YLJM1pl'
      '4dCzAXMXwMjFaXcAAAGf0qhrYQAABAMARzBFAiEA4ObcT+FUKDoK/aGUGcfMcIVSY9d/FZ0KXzo0VK3HxPUCIC8P'
      'tt2Ht1QYpptG7P3/yLGBGO1qLoD+dSsi0AvBGcjvAHYAwjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0A'
      'AAGf0qhrfgAABAMARzBFAiEAzjIp5Up07vEGXN1684PqbOFW/zglP0ZiOYcFdMkLag4CIAlrwcoLaLX2x2IfBOqM'
      '6RlObaIT/xJ+1PJr0uiHah4TMAoGCCqGSM49BAMCA0cAMEQCIH81zFKgh0Z8LMC3XIMgtBm4VZ4rHw2CGCzO2EF1'
      'tJ5uAiA1ewdcLcZaUPo7rjT3+u5Jk/rsp7nfiFrvjhY6kwMcag==';

  final List<int> certDer = base64Decode(liveSyncLeafDerBase64);

  group('the compiled control-plane host set', () {
    test('every compiled gateway host is a control-plane host', () {
      for (final gateway in primaryStealthGateways) {
        final uri = Uri.parse(gateway);
        expect(controlPlaneSpkiPinsForHost(uri.host), isNotNull,
            reason: '${uri.host} must be a control-plane host');
      }
    });

    test('the named hosts are exactly the six compiled origins', () {
      expect(kControlPlaneHosts, <String>{
        'sync.winsvpn.org',
        'hub.winsvpn.org',
        'winsvpn.org',
        'www.winsvpn.org',
        'sync.winsvpn.com',
        'www.winsvpn.com',
      });
    });

    test('every control-plane host maps to exactly the anchor SPKI pins', () {
      for (final host in <String>[
        ...kControlPlaneHosts,
        'a.app-cloud-sync.net',
        'z.app-cloud-sync.net',
        ' SYNC.WINSVPN.ORG ',
      ]) {
        expect(controlPlaneSpkiPinsForHost(host),
            same(kControlPlaneAnchorSpkiPins),
            reason: host);
      }
    });

    test('the mirror fleet is matched by zone suffix', () {
      for (final label in ['a', 'm', 'z']) {
        final host = '$label.app-cloud-sync.net';
        expect(controlPlaneSpkiPinsForHost(host), isNotNull, reason: host);
      }
      expect(controlPlaneSpkiPinsForHost('app-cloud-sync.net'), isNull,
          reason: 'bare apex is not a control-plane host');
      expect(
          controlPlaneSpkiPinsForHost('sync.app-cloud-sync.net.evil.example'),
          isNull);
    });

    test('every anchor pin is a well-formed 32-byte SPKI hash', () {
      expect(kControlPlaneAnchorSpkiPins, isNotEmpty);
      for (final pin in kControlPlaneAnchorSpkiPins) {
        expect(pin, matches(RegExp(r'^[A-Za-z0-9+/=]{44}$')), reason: pin);
        expect(base64Decode(pin), hasLength(32), reason: pin);
      }
    });

    test('unknown hosts fail closed', () {
      for (final host in <String>[
        'evil.example',
        'sync.winsvpn.org.evil.example',
        'winsvpn.org.evil.example',
        'foo.winsvpn.org',
        'foo.winsvpn.com',
        '',
      ]) {
        expect(controlPlaneSpkiPinsForHost(host), isNull, reason: host);
      }
    });
  });

  group('control-plane request targets', () {
    test('accepts pinned HTTPS hosts including explicit non-default ports', () {
      expect(
        controlPlaneRequestTargetAllowed(
          Uri.parse('https://sync.winsvpn.org/nodes'),
        ),
        isTrue,
      );
      expect(
        controlPlaneRequestTargetAllowed(
          Uri.parse('https://hub.winsvpn.org:8443/capture'),
        ),
        isTrue,
      );
      expect(
        controlPlaneRequestTargetAllowed(
          Uri.parse('HTTPS://SYNC.WINSVPN.ORG:443/'),
        ),
        isTrue,
      );
      expect(kControlPlaneMaxRedirects, 5);
    });

    test('rejects HTTP, userinfo, empty host, unpinned host, and bad ports',
        () {
      for (final uri in <Uri>[
        Uri.parse('http://sync.winsvpn.org/nodes'),
        Uri.parse('https://user:pass@sync.winsvpn.org/nodes'),
        Uri.parse('https://sync.winsvpn.org.evil.example/'),
        Uri.parse('https://example.com/'),
        Uri(scheme: 'https', host: 'sync.winsvpn.org', port: 0),
        Uri.parse('https:///nodes'),
      ]) {
        expect(
          controlPlaneRequestTargetAllowed(uri),
          isFalse,
          reason: uri.toString(),
        );
      }
    });

    test('rejects IP literals so DNS rebinding cannot skip the hostname pin',
        () {
      for (final uri in <Uri>[
        Uri.parse('https://127.0.0.1/'),
        Uri.parse('https://127.0.0.1:443/'),
        Uri.parse('https://[::1]/'),
        Uri.parse('https://[::1]:8443/nodes'),
      ]) {
        expect(
          controlPlaneRequestTargetAllowed(uri),
          isFalse,
          reason: uri.toString(),
        );
      }
    });
  });

  group('SPKI extraction from a real certificate', () {
    test('the Dart extractor reproduces the openssl ground-truth SPKI hash',
        () {
      expect(spkiSha256Base64OfCertificate(certDer),
          equals(recordedLeafSpki20260821));
    });

    test('the extracted SPKI is the full DER encoding (tag + length + key)',
        () {
      final spki = subjectPublicKeyInfoDerOfCertificate(certDer);
      expect(spki, isNotNull);
      expect(spki!.first, 0x30);
      // EC SPKI: well under 200 bytes, well over a bare key.
      expect(spki.length, lessThan(200));
      expect(spki.length, greaterThan(40));
    });

    test('a malformed DER fails closed rather than producing a pin match', () {
      expect(
          subjectPublicKeyInfoDerOfCertificate(const <int>[0x30, 0x05, 0x00]),
          isNull);
      expect(subjectPublicKeyInfoDerOfCertificate(<int>[]), isNull);
      expect(spkiSha256Base64OfCertificate(const <int>[1, 2, 3]), isNull);
    });
  });

  group('the anchored certificates carry exactly the pinned identities', () {
    test('the anchor block holds exactly the 12 compiled roots', () {
      expect(_anchorCertificates(), hasLength(12));
      expect(kControlPlaneAnchorSpkiPins, hasLength(12));
      expect(kControlPlaneAnchorSpkiPins.toSet(), hasLength(12),
          reason: 'no anchor may be listed twice');
    });

    test('the anchor SPKIs equal kControlPlaneAnchorSpkiPins, in order', () {
      expect(
        _anchorCertificates().map(spkiSha256Base64OfCertificate).toList(),
        orderedEquals(kControlPlaneAnchorSpkiPins),
      );
    });

    test('every anchor is a self-signed root, never a leaf or intermediate',
        () {
      for (final der in _anchorCertificates()) {
        expect(_tbsElement(der, 2), orderedEquals(_tbsElement(der, 4)),
            reason: 'issuer must equal subject for an anchored root');
      }
    });

    test(
        'every anchor verifies its own signature and carries CA constraints, '
        'and the check refuses a non-root', () {
      final dir = Directory.systemTemp.createTempSync('cp_anchor_');
      // The certificate's signature is checked over its own tbsCertificate
      // bytes with its own public key. No trust store takes part:
      // `openssl verify -CAfile X X` cannot be used, because OpenSSL 3.0.x
      // accepts any certificate that is in its own trust store, an
      // intermediate included, while 3.6.x refuses one.
      bool selfSigned(List<int> der, String name) {
        File('${dir.path}/$name.pem')
            .writeAsStringSync(_pemBlock('CERTIFICATE', der));
        final parts = _signedParts(der);
        final spki = subjectPublicKeyInfoDerOfCertificate(der);
        final digest = _kSignatureDigests[parts?.algorithm];
        if (parts == null || spki == null || digest == null) return false;
        final key = File('${dir.path}/$name.key.pem')
          ..writeAsStringSync(_pemBlock('PUBLIC KEY', spki));
        final tbs = File('${dir.path}/$name.tbs')..writeAsBytesSync(parts.tbs);
        final signature = File('${dir.path}/$name.sig')
          ..writeAsBytesSync(parts.signature);
        final result = Process.runSync('openssl', <String>[
          'dgst',
          '-$digest',
          '-verify',
          key.path,
          '-signature',
          signature.path,
          tbs.path,
        ]);
        return result.exitCode == 0;
      }

      try {
        final anchors = _anchorCertificates();
        for (var i = 0; i < anchors.length; i++) {
          expect(selfSigned(anchors[i], 'anchor$i'), isTrue,
              reason: 'anchor $i must verify under its own key');
          final ext = Process.runSync('openssl', <String>[
            'x509',
            '-noout',
            '-text',
            '-in',
            '${dir.path}/anchor$i.pem',
          ]);
          expect(ext.exitCode, 0, reason: 'anchor $i');
          expect(ext.stdout as String, contains('CA:TRUE'),
              reason: 'anchor $i must be a CA');
          expect(ext.stdout as String, contains('Certificate Sign'),
              reason: 'anchor $i must be allowed to sign certificates');
        }
        final chain = _pemChainDer(File(
                kLiveChainFixtures20261004['sync.winsvpn.org']!)
            .readAsStringSync());
        expect(selfSigned(chain[1], 'we1'), isFalse,
            reason: 'an intermediate must fail the self-signature check');
        expect(selfSigned(chain[2], 'r4_cross'), isFalse,
            reason: 'a cross-signed root must fail the self-signature check');
        // The two refusals above must come from the signature, not from a
        // certificate the parser or the digest table could not handle.
        for (final der in <List<int>>[chain[1], chain[2]]) {
          expect(_kSignatureDigests[_signedParts(der)?.algorithm], isNotNull);
        }
        final tampered = List<int>.from(anchors[0]);
        tampered[tampered.length - 20] ^= 0x01;
        expect(selfSigned(tampered, 'tampered'), isFalse,
            reason: 'a root whose signature was altered must fail');
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('no retired 2026-08-21 leaf is anchored or pinned', () {
      for (final spki in kRetiredLeafSpkis20260821) {
        expect(kControlPlaneAnchorSpkiPins, isNot(contains(spki)));
      }
    });

    test('a tampered SPKI is not among the anchors', () {
      final tampered = List<int>.from(certDer);
      final spki = subjectPublicKeyInfoDerOfCertificate(certDer);
      expect(spki, isNotNull);
      int? spkiOffset;
      outer:
      for (var i = 0; i <= certDer.length - spki!.length; i++) {
        for (var j = 0; j < spki.length; j++) {
          if (certDer[i + j] != spki[j]) continue outer;
        }
        spkiOffset = i;
        break;
      }
      expect(spkiOffset, isNotNull);
      tampered[spkiOffset! + spki.length - 3] ^= 0x01;
      final tamperedSpki = spkiSha256Base64OfCertificate(tampered);
      expect(tamperedSpki, isNotNull);
      expect(tamperedSpki, isNot(equals(recordedLeafSpki20260821)));
      expect(kControlPlaneAnchorSpkiPins, isNot(contains(tamperedSpki)));
    });
  });

  group('the 2026-10-04 live chains end at a compiled anchor', () {
    for (final entry in kLiveChainFixtures20261004.entries) {
      test('${entry.key}: renewed leaf -> WE1 -> anchored GTS Root R4', () {
        final chain = _pemChainDer(File(entry.value).readAsStringSync());
        expect(chain, hasLength(3));
        final List<int> leaf = chain[0];
        final List<int> we1 = chain[1];
        final List<int> r4CrossSigned = chain[2];
        expect(_tbsElement(leaf, 2), orderedEquals(_tbsElement(we1, 4)),
            reason: 'the leaf is issued by the presented intermediate');
        final anchors = _anchorCertificates()
            .where((List<int> anchor) =>
                _tbsElement(anchor, 4).join(',') ==
                _tbsElement(we1, 2).join(','))
            .toList();
        expect(anchors, hasLength(1),
            reason: 'exactly one anchor is the intermediate issuer');
        final String? anchorSpki = spkiSha256Base64OfCertificate(anchors.single);
        expect(kControlPlaneAnchorSpkiPins, contains(anchorSpki));
        expect(spkiSha256Base64OfCertificate(r4CrossSigned), anchorSpki,
            reason: 'the presented cross-signed root carries the anchored key');
        expect(kRetiredLeafSpkis20260821,
            isNot(contains(spkiSha256Base64OfCertificate(leaf))),
            reason: 'Cloudflare renewed with a new key');
        expect(
          controlPlaneValidatedLeafAcceptable(host: entry.key, leafDer: leaf),
          isTrue,
          reason: 'the renewed leaf must pass the pre-send gate',
        );
      });
    }
  });

  group('the pre-send leaf gate', () {
    final List<int> syntheticLeafDer = base64Decode(kSyntheticLeafDerBase64);

    test('accepts a parseable leaf for every control-plane host', () {
      for (final host in <String>[
        ...kControlPlaneHosts,
        'k.app-cloud-sync.net',
      ]) {
        expect(
          controlPlaneValidatedLeafAcceptable(host: host, leafDer: certDer),
          isTrue,
          reason: host,
        );
      }
    });

    test(
        'rejects every host outside the compiled set, even for a genuine '
        'control-plane leaf', () {
      for (final host in <String>[
        'localhost',
        '127.0.0.1',
        'example.com',
        'evil.example',
        'sync.winsvpn.org.evil.example',
        'foo.winsvpn.org',
        'foo.winsvpn.com',
      ]) {
        expect(
          controlPlaneValidatedLeafAcceptable(host: host, leafDer: certDer),
          isFalse,
          reason: host,
        );
        expect(
          controlPlaneValidatedLeafAcceptable(
              host: host, leafDer: syntheticLeafDer),
          isFalse,
          reason: host,
        );
      }
    });

    test('rejects DER that does not parse as a certificate', () {
      expect(
        controlPlaneValidatedLeafAcceptable(
            host: 'sync.winsvpn.org', leafDer: const <int>[1, 2, 3]),
        isFalse,
      );
      expect(
        controlPlaneValidatedLeafAcceptable(
            host: 'sync.winsvpn.org', leafDer: const <int>[]),
        isFalse,
      );
    });
  });

  group('an openssl-synthesized chain for an unlisted host is refused', () {
    late SecureServerSocket server;
    late int port;
    bool httpRequestServed = false;

    setUp(() async {
      httpRequestServed = false;
      final leafDer = base64Decode(kSyntheticLeafDerBase64);
      final caDer = base64Decode(kSyntheticCaDerBase64);
      final keyDer = base64Decode(kSyntheticLeafKeyPkcs8DerBase64);
      final context = SecurityContext()
        ..useCertificateChainBytes(utf8.encode(
            _pemBlock('CERTIFICATE', leafDer) +
                _pemBlock('CERTIFICATE', caDer)))
        ..usePrivateKeyBytes(utf8.encode(_pemBlock('PRIVATE KEY', keyDer)));
      server = await SecureServerSocket.bind(
          InternetAddress.loopbackIPv4, 0, context);
      port = server.port;
      server.listen((SecureSocket client) async {
        try {
          await client.firstWhere((data) =>
              utf8.decode(data, allowMalformed: true).contains('\r\n\r\n'));
          httpRequestServed = true;
          client.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
              'Connection: close\r\n\r\nOK');
          await client.close();
        } catch (_) {}
      }, onError: (Object _) {});
    });

    tearDown(() async {
      await server.close();
    });

    test(
        'the pinned client refuses the unlisted synthetic host with the '
        'stock anchors', () async {
      final client = createPinnedControlPlaneClient();
      try {
        await expectLater(
          client
              .get(Uri.parse('https://localhost:$port/'))
              .timeout(const Duration(seconds: 10)),
          throwsA(anything),
        );
      } finally {
        client.close();
      }
      expect(httpRequestServed, isFalse,
          reason: 'no HTTP response may ever be delivered to the client');
    });

    test(
        'the pinned client still refuses when a test injects the synthetic '
        'CA into the anchor set (the auditor\'s trick)', () async {
      // F-07: blessing the synthetic CA in the anchor set changes nothing
      // for a host outside the compiled host set.
      final client = createPinnedControlPlaneClient(
        extraTrustAnchorsDer: [base64Decode(kSyntheticCaDerBase64)],
      );
      try {
        await expectLater(
          client
              .get(Uri.parse('https://localhost:$port/'))
              .timeout(const Duration(seconds: 10)),
          throwsA(anything),
        );
      } finally {
        client.close();
      }
      expect(httpRequestServed, isFalse,
          reason: 'no HTTP response may ever be delivered to the client');
    });

    test(
        'the synthetic fixture itself is servable, so the refusals above '
        'are the client\'s doing, not a broken harness', () async {
      final raw = HttpClient()..badCertificateCallback = (c, h, p) => true;
      final client = IOClient(raw);
      try {
        final res = await client
            .get(Uri.parse('https://localhost:$port/'))
            .timeout(const Duration(seconds: 10));
        expect(res.statusCode, 200);
        expect(res.body, 'OK');
      } finally {
        client.close();
      }
      expect(httpRequestServed, isTrue);
    });
  });

  group('the exact-connection pre-send pin gate (WVP-001)', () {
    Future<ConnectionTask<Socket>> connectTo(
      _SyntheticTlsHttpServer server,
    ) async {
      final SecurityContext context = SecurityContext(withTrustedRoots: false);
      final ConnectionTask<SecureSocket> task = await SecureSocket.startConnect(
        InternetAddress.loopbackIPv4,
        server.port,
        context: context,
        onBadCertificate: (X509Certificate _) => true,
        supportedProtocols: const <String>['http/1.1'],
      );
      return ConnectionTask.fromSocket<Socket>(
        task.socket.then<Socket>((SecureSocket socket) => socket),
        task.cancel,
      );
    }

    String redirectResponse(int statusCode, _SyntheticTlsHttpServer target) =>
        'HTTP/1.1 $statusCode Redirect\r\n'
        'Location: https://hub.winsvpn.org:${target.port}/capture\r\n'
        'Content-Length: 0\r\n'
        'Connection: close\r\n\r\n';

    Future<String> bodyThroughPinnedClient(int bodyBytes) async {
      final String body = 'A' * bodyBytes;
      final _SyntheticTlsHttpServer server =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n$body',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri _, String? __, int? ___) => connectTo(server),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      try {
        final response = await client
            .get(Uri.parse('https://sync.winsvpn.org:${server.port}/nodes'))
            .timeout(const Duration(seconds: 20));
        return response.body;
      } finally {
        client.close();
        await server.close();
      }
    }

    test('a response body past the cap fails before it is buffered', () async {
      await expectLater(
        bodyThroughPinnedClient(kMaxControlPlaneResponseBytes + 1),
        throwsA(isA<ControlPlaneResponseTooLargeException>()),
      );
    });

    test('a response body at the cap is delivered whole', () async {
      final body = await bodyThroughPinnedClient(kMaxControlPlaneResponseBytes);
      expect(body.length, kMaxControlPlaneResponseBytes);
    });

    test('stalled TLS is cancelled by the exact-connection timeout', () async {
      final Completer<Socket> stalledSocket = Completer<Socket>();
      var taskCancelled = false;
      var leafVerifierCalled = false;
      final client = createPinnedControlPlaneClient(
        connectionVerificationTimeout: const Duration(milliseconds: 100),
        connectionFactory: (Uri _, String? __, int? ___) async =>
            ConnectionTask.fromSocket<Socket>(stalledSocket.future, () {
          taskCancelled = true;
        }),
        connectionLeafVerifier: (Uri _, X509Certificate __) {
          leafVerifierCalled = true;
          return true;
        },
      );
      try {
        await expectLater(
          client
              .get(Uri.parse('https://sync.winsvpn.org/stalled'))
              .timeout(const Duration(seconds: 2)),
          throwsA(isA<SocketException>()),
        );
        expect(
          taskCancelled,
          isTrue,
          reason: 'timeout must cancel the underlying connection task',
        );
        expect(
          leafVerifierCalled,
          isFalse,
          reason: 'a stalled TLS task never reaches leaf verification',
        );
      } finally {
        client.close();
      }
    });

    test(
      'a warm TTL ledger cannot authorize bytes on an unpinned connection',
      () async {
        final _SyntheticTlsHttpServer server =
            await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final Uri endpoint = Uri.parse(
          'https://sync.winsvpn.org:${server.port}/verify',
        );
        final PinnedOriginLedger ledger = PinnedOriginLedger()
          ..markVerified(endpoint);
        final client = createPinnedControlPlaneClient(
          pinProbeLedger: ledger,
          connectionFactory: (Uri _, String? __, int? ___) => connectTo(server),
          connectionLeafVerifier: (Uri _, X509Certificate __) => false,
        );
        try {
          await expectLater(
            client
                .post(
                  endpoint,
                  headers: const <String, String>{
                    'X-Wins-Activation': 'synthetic-test-value',
                  },
                  body: 'synthetic-sensitive-body',
                )
                .timeout(const Duration(seconds: 10)),
            throwsA(isA<HandshakeException>()),
          );
          await server.waitForConnectionCount(1);
          await server.waitForConnectionsToSettle();
          expect(server.connectionCount, 1);
          expect(
            server.requests,
            isEmpty,
            reason: 'the TLS peer must receive zero HTTP request bytes',
          );
          expect(server.connectionsWithoutHttpBytes, 1);
        } finally {
          client.close();
          await server.close();
        }
      },
    );

    test(
      'a verified origin still checks a new connection after a leaf swap',
      () async {
        final _SyntheticTlsHttpServer server =
            await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final Uri origin = Uri.parse('https://sync.winsvpn.org:${server.port}');
        final PinnedOriginLedger ledger = PinnedOriginLedger();
        var leafChecks = 0;
        final client = createPinnedControlPlaneClient(
          pinProbeLedger: ledger,
          connectionFactory: (Uri _, String? __, int? ___) => connectTo(server),
          // The first connection passes. The next connection models a swapped
          // leaf and must fail before HttpClient yields a writable request.
          connectionLeafVerifier: (Uri _, X509Certificate __) =>
              ++leafChecks == 1,
        );
        try {
          final response = await client
              .get(origin.resolve('/nodes'))
              .timeout(const Duration(seconds: 10));
          expect(response.statusCode, 200);
          expect(ledger.isVerified(origin), isTrue);

          await expectLater(
            client
                .post(
                  origin.resolve('/verify'),
                  headers: const <String, String>{
                    'Authorization': 'Bearer synthetic-test-value',
                  },
                  body: 'must-not-cross-swapped-connection',
                )
                .timeout(const Duration(seconds: 10)),
            throwsA(isA<HandshakeException>()),
          );
          await server.waitForConnectionCount(2);
          await server.waitForConnectionsToSettle();
          expect(server.connectionCount, 2);
          expect(server.requests, hasLength(1));
          expect(server.requests.single.method, 'GET');
          expect(
            server.requests.where(
              (request) => request.body == 'must-not-cross-swapped-connection',
            ),
            isEmpty,
          );
          expect(server.connectionsWithoutHttpBytes, 1);
        } finally {
          client.close();
          await server.close();
        }
      },
    );

    test(
      'a cross-origin redirect target is leaf-checked before any hop bytes',
      () async {
        late final _SyntheticTlsHttpServer target;
        target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final _SyntheticTlsHttpServer source =
            await _SyntheticTlsHttpServer.start(
          (_) => 'HTTP/1.1 302 Found\r\n'
              'Location: https://hub.winsvpn.org:${target.port}/capture\r\n'
              'Content-Length: 0\r\n'
              'Connection: close\r\n\r\n',
        );
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) =>
              connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
          connectionLeafVerifier: (Uri uri, X509Certificate _) =>
              uri.host == 'sync.winsvpn.org',
        );
        try {
          await expectLater(
            client.get(
              Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
              headers: const <String, String>{
                'X-Wins-Activation': 'synthetic-test-value',
              },
            ).timeout(const Duration(seconds: 10)),
            throwsA(isA<HandshakeException>()),
          );
          await source.waitForConnectionsToSettle();
          await target.waitForConnectionCount(1);
          await target.waitForConnectionsToSettle();
          expect(source.requests, hasLength(1));
          expect(target.connectionCount, 1);
          expect(
            target.requests,
            isEmpty,
            reason: 'the rejected redirect leaf must see no HTTP bytes',
          );
          expect(target.connectionsWithoutHttpBytes, 1);
        } finally {
          client.close();
          await source.close();
          await target.close();
        }
      },
    );

    test(
      'manual cross-origin redirect strips all non-public headers',
      () async {
        late final _SyntheticTlsHttpServer target;
        target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final _SyntheticTlsHttpServer source =
            await _SyntheticTlsHttpServer.start(
          (_) => 'HTTP/1.1 302 Found\r\n'
              'Location: https://hub.winsvpn.org:${target.port}/capture\r\n'
              'Content-Length: 0\r\n'
              'Connection: close\r\n\r\n',
        );
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) =>
              connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
          connectionLeafVerifier: (Uri _, X509Certificate __) => true,
        );
        try {
          final response = await client.get(
            Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
            headers: const <String, String>{
              'Accept': 'application/json',
              'Authorization': 'Bearer synthetic-test-value',
              'Cookie': 'session=synthetic-test-value',
              'X-Wins-Activation': 'synthetic-test-value',
              'X-Device-Auth-Token': 'synthetic-test-value',
              'X-Future-Credential': 'synthetic-test-value',
            },
          ).timeout(const Duration(seconds: 10));
          expect(response.statusCode, 200);
          await source.waitForConnectionsToSettle();
          await target.waitForConnectionsToSettle();
          expect(target.requests, hasLength(1));
          final Map<String, String> headers = target.requests.single.headers;
          expect(headers['accept'], 'application/json');
          for (final String name in <String>[
            'authorization',
            'cookie',
            'x-wins-activation',
            'x-device-auth-token',
            'x-future-credential',
          ]) {
            expect(headers.containsKey(name), isFalse, reason: name);
          }
        } finally {
          client.close();
          await source.close();
          await target.close();
        }
      },
    );

    test('strict policy can authorize one exact non-credential header',
        () async {
      late final _SyntheticTlsHttpServer target;
      target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
      final _SyntheticTlsHttpServer source =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 302 Found\r\n'
            'Location: https://hub.winsvpn.org:${target.port}/capture\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri uri, String? _, int? __) =>
            connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
        redirectHeaderPolicy:
            (Uri sourceOrigin, Uri targetOrigin, String name) =>
                sourceOrigin.host == 'sync.winsvpn.org' &&
                targetOrigin.host == 'hub.winsvpn.org' &&
                name == 'x-correlation-id',
      );
      try {
        final response = await client.get(
          Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
          headers: const <String, String>{
            'Authorization': 'Bearer synthetic-test-value',
            'X-Wins-Activation': 'synthetic-test-value',
            'X-Correlation-Id': 'synthetic-correlation',
          },
        ).timeout(const Duration(seconds: 10));
        expect(response.statusCode, 200);
        await target.waitForConnectionsToSettle();
        final Map<String, String> headers = target.requests.single.headers;
        expect(headers['x-correlation-id'], 'synthetic-correlation');
        expect(headers.containsKey('authorization'), isFalse);
        expect(headers.containsKey('x-wins-activation'), isFalse);
      } finally {
        client.close();
        await source.close();
        await target.close();
      }
    });

    for (final int statusCode in <int>[
      HttpStatus.movedPermanently,
      HttpStatus.found,
      HttpStatus.seeOther,
    ]) {
      test(
        'POST $statusCode normalizes to a bodyless cross-origin GET',
        () async {
          final _SyntheticTlsHttpServer target =
              await _SyntheticTlsHttpServer.start((_) => _okResponse);
          final _SyntheticTlsHttpServer source =
              await _SyntheticTlsHttpServer.start(
            (_) => redirectResponse(statusCode, target),
          );
          final client = createPinnedControlPlaneClient(
            connectionFactory: (Uri uri, String? _, int? __) =>
                connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
            connectionLeafVerifier: (Uri _, X509Certificate __) => true,
          );
          try {
            final http.Response response = await client
                .post(
                  Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
                  headers: const <String, String>{
                    'Content-Type': 'application/json',
                    'X-Wins-Activation': 'synthetic-test-value',
                  },
                  body: '{"synthetic":"body"}',
                )
                .timeout(const Duration(seconds: 10));
            expect(response.statusCode, 200);
            await source.waitForConnectionsToSettle();
            await target.waitForConnectionsToSettle();
            expect(source.requests.single.method, 'POST');
            expect(source.requests.single.body, '{"synthetic":"body"}');
            expect(target.requests, hasLength(1));
            expect(target.requests.single.method, 'GET');
            expect(target.requests.single.body, isEmpty);
            expect(
              target.requests.single.headers.containsKey('content-type'),
              isFalse,
            );
            expect(
              target.requests.single.headers.containsKey('x-wins-activation'),
              isFalse,
            );
          } finally {
            client.close();
            await source.close();
            await target.close();
          }
        },
      );
    }

    for (final int statusCode in <int>[
      HttpStatus.temporaryRedirect,
      HttpStatus.permanentRedirect,
    ]) {
      test(
        'POST $statusCode is refused instead of replayed without its body',
        () async {
          final _SyntheticTlsHttpServer target =
              await _SyntheticTlsHttpServer.start((_) => _okResponse);
          final _SyntheticTlsHttpServer source =
              await _SyntheticTlsHttpServer.start(
            (_) => redirectResponse(statusCode, target),
          );
          final client = createPinnedControlPlaneClient(
            connectionFactory: (Uri uri, String? _, int? __) =>
                connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
            connectionLeafVerifier: (Uri _, X509Certificate __) => true,
          );
          try {
            await expectLater(
              client
                  .post(
                    Uri.parse(
                      'https://sync.winsvpn.org:${source.port}/redirect',
                    ),
                    headers: const <String, String>{
                      'X-Wins-Activation': 'synthetic-test-value',
                    },
                    body: 'body-that-must-not-be-dropped',
                  )
                  .timeout(const Duration(seconds: 10)),
              throwsA(isA<http.ClientException>()),
            );
            await source.waitForConnectionsToSettle();
            expect(source.requests.single.method, 'POST');
            expect(
              source.requests.single.body,
              'body-that-must-not-be-dropped',
            );
            expect(
              target.connectionCount,
              0,
              reason: 'refusal must happen before opening the redirect target',
            );
            expect(target.requests, isEmpty);
          } finally {
            client.close();
            await source.close();
            await target.close();
          }
        },
      );
    }

    const List<int> redirectStatuses = <int>[
      HttpStatus.movedPermanently,
      HttpStatus.found,
      HttpStatus.seeOther,
      HttpStatus.temporaryRedirect,
      HttpStatus.permanentRedirect,
    ];

    const Map<String, String> credentialHeaders = <String, String>{
      'Accept': 'application/json',
      'Authorization': 'Bearer synthetic-test-value',
      'X-Wins-Activation': 'synthetic-test-value',
    };

    for (final int statusCode in redirectStatuses) {
      test(
        'GET $statusCode cross-origin strips Authorization and X-Wins-Activation',
        () async {
          final _SyntheticTlsHttpServer target =
              await _SyntheticTlsHttpServer.start((_) => _okResponse);
          final _SyntheticTlsHttpServer source =
              await _SyntheticTlsHttpServer.start(
            (_) => redirectResponse(statusCode, target),
          );
          final client = createPinnedControlPlaneClient(
            connectionFactory: (Uri uri, String? _, int? __) =>
                connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
            connectionLeafVerifier: (Uri _, X509Certificate __) => true,
          );
          try {
            final http.Response response = await client
                .get(
                  Uri.parse(
                    'https://sync.winsvpn.org:${source.port}/redirect',
                  ),
                  headers: credentialHeaders,
                )
                .timeout(const Duration(seconds: 10));
            expect(response.statusCode, 200);
            await source.waitForConnectionsToSettle();
            await target.waitForConnectionsToSettle();
            expect(source.requests.single.headers['authorization'], isNotNull);
            expect(
              source.requests.single.headers['x-wins-activation'],
              isNotNull,
            );
            expect(target.requests, hasLength(1));
            expect(target.requests.single.method, 'GET');
            expect(
                target.requests.single.headers['accept'], 'application/json');
            expect(
              target.requests.single.headers.containsKey('authorization'),
              isFalse,
            );
            expect(
              target.requests.single.headers.containsKey('x-wins-activation'),
              isFalse,
            );
          } finally {
            client.close();
            await source.close();
            await target.close();
          }
        },
      );
    }

    for (final int statusCode in redirectStatuses) {
      test(
        'GET $statusCode same-origin keeps Authorization and X-Wins-Activation',
        () async {
          late final _SyntheticTlsHttpServer server;
          server = await _SyntheticTlsHttpServer.start(
            (_RecordedHttpRequest request) {
              if (request.path == '/redirect') {
                return 'HTTP/1.1 $statusCode Redirect\r\n'
                    'Location: /capture\r\n'
                    'Content-Length: 0\r\n'
                    'Connection: close\r\n\r\n';
              }
              return _okResponse;
            },
          );
          final client = createPinnedControlPlaneClient(
            connectionFactory: (Uri _, String? __, int? ___) =>
                connectTo(server),
            connectionLeafVerifier: (Uri _, X509Certificate __) => true,
          );
          try {
            final http.Response response = await client
                .get(
                  Uri.parse(
                    'https://sync.winsvpn.org:${server.port}/redirect',
                  ),
                  headers: credentialHeaders,
                )
                .timeout(const Duration(seconds: 10));
            expect(response.statusCode, 200);
            await server.waitForConnectionsToSettle();
            expect(server.requests, hasLength(2));
            expect(server.requests.first.path, '/redirect');
            expect(server.requests.last.path, '/capture');
            expect(
              server.requests.last.headers['authorization'],
              'Bearer synthetic-test-value',
            );
            expect(
              server.requests.last.headers['x-wins-activation'],
              'synthetic-test-value',
            );
          } finally {
            client.close();
            await server.close();
          }
        },
      );
    }

    test(
      'policy cannot forward Authorization or X-Wins-Activation across origins',
      () async {
        late final _SyntheticTlsHttpServer target;
        target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final _SyntheticTlsHttpServer source =
            await _SyntheticTlsHttpServer.start(
          (_) => redirectResponse(HttpStatus.found, target),
        );
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) =>
              connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
          connectionLeafVerifier: (Uri _, X509Certificate __) => true,
          redirectHeaderPolicy: (Uri _, Uri __, String ___) => true,
        );
        try {
          final http.Response response = await client
              .get(
                Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
                headers: credentialHeaders,
              )
              .timeout(const Duration(seconds: 10));
          expect(response.statusCode, 200);
          await target.waitForConnectionsToSettle();
          final Map<String, String> headers = target.requests.single.headers;
          expect(headers.containsKey('authorization'), isFalse);
          expect(headers.containsKey('x-wins-activation'), isFalse);
        } finally {
          client.close();
          await source.close();
          await target.close();
        }
      },
    );

    test(
      'a permissive policy still cannot forward Cookie or API/token keys '
      'across origins',
      () async {
        late final _SyntheticTlsHttpServer target;
        target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final _SyntheticTlsHttpServer source =
            await _SyntheticTlsHttpServer.start(
          (_) => redirectResponse(HttpStatus.found, target),
        );
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) =>
              connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
          connectionLeafVerifier: (Uri _, X509Certificate __) => true,
          redirectHeaderPolicy: (Uri _, Uri __, String ___) => true,
        );
        try {
          final http.Response response = await client
              .get(
                Uri.parse(
                  'https://sync.winsvpn.org:${source.port}/redirect',
                ),
                headers: const <String, String>{
                  'Cookie': 'session=synthetic-test-value',
                  'X-Api-Key': 'synthetic-test-value',
                  'X-Auth-Token': 'synthetic-test-value',
                  'X-Csrf-Token': 'synthetic-test-value',
                  'X-Session-Id': 'synthetic-test-value',
                },
              )
              .timeout(const Duration(seconds: 10));
          expect(response.statusCode, 200);
          await target.waitForConnectionsToSettle();
          final Map<String, String> headers = target.requests.single.headers;
          for (final String name in <String>[
            'cookie',
            'x-api-key',
            'x-auth-token',
            'x-csrf-token',
            'x-session-id',
          ]) {
            expect(headers.containsKey(name), isFalse,
                reason: '$name must never follow an origin change');
          }
        } finally {
          client.close();
          await source.close();
          await target.close();
        }
      },
    );

    test('a different port is a new origin and drops credentials', () async {
      late final _SyntheticTlsHttpServer target;
      target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
      final _SyntheticTlsHttpServer source =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 302 Found\r\n'
            'Location: https://sync.winsvpn.org:${target.port}/capture\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri uri, String? _, int? __) =>
            connectTo(uri.port == source.port ? source : target),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      try {
        final http.Response response = await client
            .get(
              Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
              headers: credentialHeaders,
            )
            .timeout(const Duration(seconds: 10));
        expect(response.statusCode, 200);
        await target.waitForConnectionsToSettle();
        expect(
          target.requests.single.headers.containsKey('authorization'),
          isFalse,
        );
        expect(
          target.requests.single.headers.containsKey('x-wins-activation'),
          isFalse,
        );
      } finally {
        client.close();
        await source.close();
        await target.close();
      }
    });

    test('redirect loop is refused without a second hop', () async {
      final _SyntheticTlsHttpServer source =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 302 Found\r\n'
            'Location: /redirect\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri _, String? __, int? ___) => connectTo(source),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      try {
        await expectLater(
          client
              .get(
                Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
                headers: credentialHeaders,
              )
              .timeout(const Duration(seconds: 10)),
          throwsA(isA<http.ClientException>()),
        );
        await source.waitForConnectionsToSettle();
        expect(source.requests, hasLength(1));
      } finally {
        client.close();
        await source.close();
      }
    });

    test('missing Location fails closed without following', () async {
      final _SyntheticTlsHttpServer source =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 302 Found\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri _, String? __, int? ___) => connectTo(source),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      try {
        await expectLater(
          client
              .get(
                Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
                headers: credentialHeaders,
              )
              .timeout(const Duration(seconds: 10)),
          throwsA(isA<http.ClientException>()),
        );
        await source.waitForConnectionsToSettle();
        expect(source.requests, hasLength(1));
      } finally {
        client.close();
        await source.close();
      }
    });

    test('malformed Location fails closed without following', () async {
      late final _SyntheticTlsHttpServer target;
      target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
      final _SyntheticTlsHttpServer source =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 302 Found\r\n'
            'Location: https://\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri uri, String? _, int? __) =>
            connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      try {
        await expectLater(
          client
              .get(
                Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
                headers: credentialHeaders,
              )
              .timeout(const Duration(seconds: 10)),
          throwsA(isA<http.ClientException>()),
        );
        await source.waitForConnectionsToSettle();
        expect(target.connectionCount, 0);
        expect(target.requests, isEmpty);
      } finally {
        client.close();
        await source.close();
        await target.close();
      }
    });

    test('HTTP Location is refused as a downgrade before any hop bytes',
        () async {
      late final _SyntheticTlsHttpServer target;
      target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
      final _SyntheticTlsHttpServer source =
          await _SyntheticTlsHttpServer.start(
        (_) => 'HTTP/1.1 302 Found\r\n'
            'Location: http://hub.winsvpn.org:${target.port}/capture\r\n'
            'Content-Length: 0\r\n'
            'Connection: close\r\n\r\n',
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri uri, String? _, int? __) =>
            connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      try {
        await expectLater(
          client
              .get(
                Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
                headers: credentialHeaders,
              )
              .timeout(const Duration(seconds: 10)),
          throwsA(isA<HandshakeException>()),
        );
        await source.waitForConnectionsToSettle();
        expect(target.connectionCount, 0);
        expect(target.requests, isEmpty);
      } finally {
        client.close();
        await source.close();
        await target.close();
      }
    });

    test(
      'Location to an IP literal is refused even when that IP hosted the TLS',
      () async {
        late final _SyntheticTlsHttpServer target;
        target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final _SyntheticTlsHttpServer source =
            await _SyntheticTlsHttpServer.start(
          (_) => 'HTTP/1.1 302 Found\r\n'
              'Location: https://127.0.0.1:${target.port}/capture\r\n'
              'Content-Length: 0\r\n'
              'Connection: close\r\n\r\n',
        );
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) =>
              connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
          connectionLeafVerifier: (Uri _, X509Certificate __) => true,
        );
        try {
          await expectLater(
            client
                .get(
                  Uri.parse(
                    'https://sync.winsvpn.org:${source.port}/redirect',
                  ),
                  headers: credentialHeaders,
                )
                .timeout(const Duration(seconds: 10)),
            throwsA(isA<HandshakeException>()),
          );
          await source.waitForConnectionsToSettle();
          expect(target.connectionCount, 0);
          expect(target.requests, isEmpty);
        } finally {
          client.close();
          await source.close();
          await target.close();
        }
      },
    );

    test(
      'leaf verification is keyed by URI host, not the connected loopback IP',
      () async {
        final List<String> verifiedHosts = <String>[];
        final List<String> connectedHosts = <String>[];
        final _SyntheticTlsHttpServer server =
            await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) {
            connectedHosts.add(uri.host);
            return connectTo(server);
          },
          connectionLeafVerifier: (Uri uri, X509Certificate _) {
            verifiedHosts.add(uri.host);
            return true;
          },
        );
        try {
          final http.Response response = await client
              .get(
                Uri.parse('https://sync.winsvpn.org:${server.port}/nodes'),
                headers: credentialHeaders,
              )
              .timeout(const Duration(seconds: 10));
          expect(response.statusCode, 200);
          expect(connectedHosts, <String>['sync.winsvpn.org']);
          expect(verifiedHosts, <String>['sync.winsvpn.org']);
          expect(connectedHosts, isNot(contains('127.0.0.1')));
          expect(verifiedHosts, isNot(contains('127.0.0.1')));
        } finally {
          client.close();
          await server.close();
        }
      },
    );

    test('redirects are capped even when the caller asks for more hops',
        () async {
      late final _SyntheticTlsHttpServer server;
      server = await _SyntheticTlsHttpServer.start(
        (_RecordedHttpRequest request) {
          final String path = request.path;
          final int hop = path.startsWith('/r')
              ? (int.tryParse(path.substring(2)) ?? 0)
              : 0;
          return 'HTTP/1.1 302 Found\r\n'
              'Location: https://sync.winsvpn.org:${server.port}/r${hop + 1}\r\n'
              'Content-Length: 0\r\n'
              'Connection: close\r\n\r\n';
        },
      );
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri _, String? __, int? ___) => connectTo(server),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      final http.Request request = http.Request(
        'GET',
        Uri.parse('https://sync.winsvpn.org:${server.port}/r0'),
      );
      request.maxRedirects = 50;
      request.headers.addAll(credentialHeaders);
      try {
        await expectLater(
          client.send(request).timeout(const Duration(seconds: 10)),
          throwsA(isA<http.ClientException>()),
        );
        await server.waitForConnectionsToSettle();
        expect(server.requests, hasLength(kControlPlaneMaxRedirects + 1));
        expect(
          server.requests.last.path,
          '/r$kControlPlaneMaxRedirects',
        );
      } finally {
        client.close();
        await server.close();
      }
    });

    test(
      'non-credentialed GET still follows a safe same-method cross-origin 302',
      () async {
        late final _SyntheticTlsHttpServer target;
        target = await _SyntheticTlsHttpServer.start((_) => _okResponse);
        final _SyntheticTlsHttpServer source =
            await _SyntheticTlsHttpServer.start(
          (_) => redirectResponse(HttpStatus.found, target),
        );
        final client = createPinnedControlPlaneClient(
          connectionFactory: (Uri uri, String? _, int? __) =>
              connectTo(uri.host == 'sync.winsvpn.org' ? source : target),
          connectionLeafVerifier: (Uri _, X509Certificate __) => true,
        );
        try {
          final http.Response response = await client.get(
            Uri.parse('https://sync.winsvpn.org:${source.port}/redirect'),
            headers: const <String, String>{'Accept': 'application/json'},
          ).timeout(const Duration(seconds: 10));
          expect(response.statusCode, 200);
          await target.waitForConnectionsToSettle();
          expect(target.requests, hasLength(1));
          expect(target.requests.single.headers['accept'], 'application/json');
          expect(
            target.requests.single.headers.containsKey('authorization'),
            isFalse,
          );
        } finally {
          client.close();
          await source.close();
          await target.close();
        }
      },
    );
  });

  group('the verified-origin ledger', () {
    test('expires after the 10-minute TTL', () {
      var now = DateTime.utc(2026, 8, 23);
      final ledger = PinnedOriginLedger(clock: () => now);
      final uri = Uri.parse('https://sync.winsvpn.org/');
      expect(ledger.isVerified(uri), isFalse);
      ledger.markVerified(uri);
      expect(ledger.isVerified(uri), isTrue);
      now = now.add(
          kControlPlanePinVerifiedOriginTtl - const Duration(microseconds: 1));
      expect(ledger.isVerified(uri), isTrue,
          reason: 'inside the TTL the origin stays verified');
      now = now.add(const Duration(microseconds: 2));
      expect(ledger.isVerified(uri), isFalse,
          reason: 'past the TTL the origin must be re-probed');
    });

    test('invalidate drops the entry immediately', () {
      final uri = Uri.parse('https://hub.winsvpn.org/');
      final ledger = PinnedOriginLedger();
      ledger.markVerified(uri);
      expect(ledger.isVerified(uri), isTrue);
      ledger.invalidate(uri);
      expect(ledger.isVerified(uri), isFalse);
    });

    test('verification is keyed by origin: port and host both distinguish', () {
      final ledger = PinnedOriginLedger();
      final a = Uri.parse('https://sync.winsvpn.org/');
      final aPort = Uri.parse('https://sync.winsvpn.org:8443/');
      final b = Uri.parse('https://hub.winsvpn.org/');
      ledger.markVerified(a);
      expect(ledger.isVerified(a), isTrue);
      expect(ledger.isVerified(aPort), isFalse);
      expect(ledger.isVerified(b), isFalse);
    });

    test('the ledger is in-memory only: a fresh instance knows nothing', () {
      final uri = Uri.parse('https://sync.winsvpn.org/');
      PinnedOriginLedger().markVerified(uri);
      expect(PinnedOriginLedger().isVerified(uri), isFalse);
    });
  });

  group('the release gate cannot be disabled', () {
    test('release builds enforce regardless of the escape define', () {
      expect(
        controlPlanePinningEnforced(
            isReleaseBuild: true, disabledDefine: false),
        isTrue,
      );
      expect(
        controlPlanePinningEnforced(isReleaseBuild: true, disabledDefine: true),
        isTrue,
      );
    });

    test('debug/profile builds honour the escape define', () {
      expect(
        controlPlanePinningEnforced(
            isReleaseBuild: false, disabledDefine: false),
        isTrue,
      );
      expect(
        controlPlanePinningEnforced(
            isReleaseBuild: false, disabledDefine: true),
        isFalse,
      );
    });

    test('the escape define defaults to off', () {
      expect(kControlPlanePinningDisabled, isFalse);
    });

    test(
        'the client never trusts the device store, never bypasses chain '
        'validation, and never adds test anchors in a release build', () {
      final source = File('lib/control_plane_pinning.dart').readAsStringSync();
      expect(source, contains('SecurityContext(withTrustedRoots: false)'));
      expect(source, isNot(contains('withTrustedRoots: true')));
      expect(source, isNot(contains('onBadCertificate:')));
      expect(source, isNot(contains('badCertificateCallback =')));
      expect(
        source,
        contains('  if (!kReleaseMode) {\n'
            '    for (final der in extraTrustAnchorsDer) {'),
      );
      expect(
        source,
        contains('  if (kReleaseMode &&\n'
            '      (extraTrustAnchorsDer.isNotEmpty ||\n'
            '          connectionFactory != null ||\n'
            '          connectionLeafVerifier != null ||\n'
            '          tcpConnector != null)) {\n'
            "    throw StateError('control-plane test seams are forbidden in "
            "release');"),
      );
      expect(source,
          contains('  final SecurityContext context = _controlPlaneAnchorContext();'));
      // Anchors are PEM on every platform. The old iOS branch handed BoringSSL
      // a raw DER blob, which fails with BAD_PKCS12_DATA, so on iOS every hub
      // call failed TLS and Try Free Server never worked.
      expect(source, contains('    context.setTrustedCertificatesBytes(utf8.encode(pem));'));
      expect(
        source,
        contains('        context.setTrustedCertificatesBytes(\n'
            '          utf8.encode(_pemCertificateFromDer(der)),\n'
            '        );'),
      );
      expect(source, isNot(contains('Platform.isIOS')));
      expect(
        RegExp(r'setTrustedCertificatesBytes\(\s*([^)]*)\)')
            .allMatches(source)
            .map((m) => m.group(1)!.trim())
            .toList(),
        everyElement(startsWith('utf8.encode(')),
      );
    });

    test(
        'dart:io trusts a PEM anchor but refuses the same anchor as raw DER '
        '(the BoringSSL path every platform, iOS included, uses)', () {
      final anchors = _anchorCertificates();
      expect(anchors, hasLength(12));
      for (final der in anchors) {
        final pem = '-----BEGIN CERTIFICATE-----\n'
            '${base64Encode(der).replaceAllMapped(RegExp(r'.{1,64}'), (m) => '${m.group(0)}\n')}'
            '-----END CERTIFICATE-----\n';
        SecurityContext(withTrustedRoots: false)
            .setTrustedCertificatesBytes(utf8.encode(pem));
        expect(
          () => SecurityContext(withTrustedRoots: false)
              .setTrustedCertificatesBytes(der),
          throwsA(isA<TlsException>()),
        );
      }
    });

    test('the client is wired into every gateway request in main.dart', () {
      final source = File('lib/main.dart').readAsStringSync();
      expect(source, contains('createPinnedControlPlaneClient('));
      // C-core-6: the connect-and-verify ceiling is the hub window's
      // per-attempt timeout.
      expect(source, contains('HubRequestWindowPolicy().perRequestTimeout'));
      expect(source, contains('late final http.Client _controlPlaneClient'));
      // The non-control-plane fetches must keep their stock (non-pinned)
      // clients: routing them through the pinned client would fail them
      // closed. Since F-06 they ride NoRedirectClient/fetchWithoutRedirects,
      // which wraps a plain client -- still NOT the pinned one. The recovery
      // record rides the capped variant: the same stock client, with the
      // body bounded while it streams.
      final unpinnedSites = <String>[
        'await fetchWithoutRedirectsCapped(\n'
            '      url,\n'
            '      maxBytes: kMaxGatewayRecoveryRecordBytes,',
        ': fetchWithoutRedirectsCapped(\n'
            '                    source,\n'
            '                    maxBytes: kMaxPreVpnGeoSceneBytes,\n'
            '                    deadline: const Duration(seconds: 3),\n'
            '                    headers: headers,',
      ];
      for (final site in unpinnedSites) {
        expect(source, contains(site), reason: site);
      }
      expect(
        source,
        isNot(contains("Uri.parse('https://api.ipify.org')")),
        reason: 'C-core-12: no third-party public-IP lookup from the real IP',
      );
      expect(
        '_controlPlaneClient'.allMatches(source).length,
        greaterThanOrEqualTo(11),
        reason: 'every gateway request path must use the pinned client',
      );
      expect(
        source,
        contains('final pinned = controlPlaneRequestTargetAllowed(source)'),
        reason: 'first-party pre-VPN geo uses SPKI pinning while Cloudflare '
            'stays stock',
      );
      expect(
        source,
        contains('final response = await (pinned\n'
            '                ? _controlPlaneClient.get(source, headers: headers)\n'
            '                : fetchWithoutRedirectsCapped(\n'),
        reason: 'first-party pre-VPN geo uses SPKI pinning while Cloudflare '
            'stays stock, with its body capped while it streams',
      );
      expect(source, isNot(contains('fetchWithoutRedirects(source')),
          reason: 'an uncapped stock geo fetch keeps downloading after its '
              'timeout');
      expect(
        source,
        contains('permittedPreVpnGeoHosts.contains(source.host.toLowerCase())'),
        reason: 'a stock pre-VPN geo fetch is closed-allowlisted in release '
            'builds (B-APP-006)',
      );
      expect(
        source,
        contains('recoveryRecordHostAllowlist.contains(url.host.toLowerCase())'),
        reason: 'the recovery record fetch is host-allowlisted before any '
            'stock client touches it (B-APP-005)',
      );
    });
  });

  group('live handshake against the pinned hosts', () {
    // Offline-safe by default. Run once against the live control plane with
    //   WINS_CONTROL_PLANE_LIVE_TEST=1 flutter test --no-pub \
    //       test/control_plane_pinning_test.dart
    final bool live =
        Platform.environment['WINS_CONTROL_PLANE_LIVE_TEST'] == '1';

    test(
        'the pinned client completes a real handshake with the live '
        'certificate', () async {
      final client = createPinnedControlPlaneClient();
      try {
        final res = await client
            .get(Uri.parse('https://sync.winsvpn.org/nodes'))
            .timeout(const Duration(seconds: 20));
        expect(
          res.statusCode,
          isIn(<int>[200, 301, 302, 307, 308, 401, 403, 404, 429, 503]),
          reason: 'a pinned handshake must reach the real control plane',
        );
      } finally {
        client.close();
      }
    }, skip: live ? false : 'set WINS_CONTROL_PLANE_LIVE_TEST=1 to run');

    test(
        'the pinned client fail-closes against a host it carries no pins '
        'for', () async {
      final client = createPinnedControlPlaneClient();
      try {
        await client
            .get(Uri.parse('https://example.com/'))
            .timeout(const Duration(seconds: 20));
        fail('an unpinned host must never complete a handshake');
      } on HandshakeException {
        // Expected: example.com is outside the compiled host set.
      } finally {
        client.close();
      }
    }, skip: live ? false : 'set WINS_CONTROL_PLANE_LIVE_TEST=1 to run');
  });

  // ARBITER-COMPOSED (Turn 5, PERF-CHOICE). Settles whether the C-2
  // preflight rule can record a 200 that arrives after the window no longer
  // wants it. The attempt below restates the C-2 closure of
  // _freeAccessPreflightTerminalKind (sendHubRequest on the pinned client,
  // then record only on a 200); the window, sendHubRequest and the pinned
  // client's abort path are the real ones. The fronts are loopback TLS
  // servers reached through the client's connection seam.
  group('a late 200 under the C-2 preflight rule', () {
    Future<ConnectionTask<Socket>> connectTo(_LateTlsFront front) async {
      final ConnectionTask<SecureSocket> task = await SecureSocket.startConnect(
        InternetAddress.loopbackIPv4,
        front.port,
        context: SecurityContext(withTrustedRoots: false),
        onBadCertificate: (X509Certificate _) => true,
        supportedProtocols: const <String>['http/1.1'],
      );
      return ConnectionTask.fromSocket<Socket>(
        task.socket.then<Socket>((SecureSocket socket) => socket),
        task.cancel,
      );
    }

    Future<
        ({
          HubRequestWindowOutcome<String> outcome,
          List<String> recorded,
          Duration finishedAt,
          Duration lateReplyAt,
        })> walk({
      required _LateTlsFront slow,
      _LateTlsFront? fast,
      required HubRequestWindowPolicy policy,
      HubCancellation? cancellation,
    }) async {
      final fronts = <String, _LateTlsFront>{
        'sync.winsvpn.org': slow,
        if (fast != null) 'sync.winsvpn.com': fast,
      };
      final client = createPinnedControlPlaneClient(
        connectionFactory: (Uri uri, String? _, int? __) =>
            connectTo(fronts[uri.host]!),
        connectionLeafVerifier: (Uri _, X509Certificate __) => true,
      );
      final recorded = <String>[];
      var ended = 0;
      try {
        final outcome = await runHubRequestWindow<String>(
          urls: <String>[
            for (final entry in fronts.entries)
              'https://${entry.key}:${entry.value.port}/free/status',
          ],
          cancellation: cancellation,
          permits: HubTransportPermits(3),
          policy: policy,
          attempt: (url, abort) async {
            try {
              final response = await sendHubRequest(
                client,
                'GET',
                Uri.parse(url),
                abort: abort,
              );
              if (response.body.contains('<!DOCTYPE')) {
                return const HubAttemptResult<String>.rejected();
              }
              if (response.statusCode == 200) recorded.add(url);
              return const HubAttemptResult<String>.accepted('');
            } catch (_) {
              return const HubAttemptResult<String>.rejected();
            } finally {
              ended += 1;
            }
          },
        );
        final finishedAt = slow.clock.elapsed;
        await slow.replied.future.timeout(const Duration(seconds: 5));
        final deadline = DateTime.now().add(const Duration(seconds: 5));
        while (ended < outcome.started.length &&
            DateTime.now().isBefore(deadline)) {
          await Future<void>.delayed(const Duration(milliseconds: 10));
        }
        expect(ended, outcome.started.length,
            reason: 'every attempt must have ended before the check');
        return (
          outcome: outcome,
          recorded: recorded,
          finishedAt: finishedAt,
          lateReplyAt: slow.repliedAt!,
        );
      } finally {
        client.close();
      }
    }

    const lateBy = Duration(milliseconds: 600);
    const raceWindow = HubRequestWindowPolicy(
      stagger: Duration(milliseconds: 50),
      minSpacing: Duration.zero,
      perRequestTimeout: Duration(seconds: 3),
      totalDeadline: Duration(seconds: 6),
    );

    for (final headersFirst in <bool>[false, true]) {
      test(
          'a 200 from a front that lost the race is not recorded '
          '(${headersFirst ? 'headers on time, body late' : 'whole reply '
              'late'})',
          () async {
        final slow =
            await _LateTlsFront.start(lateBy, headersFirst: headersFirst);
        final fast = await _LateTlsFront.start(Duration.zero);
        try {
          final run = await walk(slow: slow, fast: fast, policy: raceWindow);
          expect(run.outcome.acceptedUrl, contains('sync.winsvpn.com'));
          expect(run.lateReplyAt, greaterThan(run.finishedAt),
              reason: 'the slow 200 was sent after the window finished');
          expect(run.recorded, hasLength(1));
          expect(run.recorded.single, contains('sync.winsvpn.com'));
        } finally {
          await slow.close();
          await fast.close();
        }
      });
    }

    test('a 200 that arrives after its own per-request timeout is not '
        'recorded', () async {
      final slow = await _LateTlsFront.start(lateBy);
      try {
        final run = await walk(
          slow: slow,
          policy: const HubRequestWindowPolicy(
            perRequestTimeout: Duration(milliseconds: 200),
            totalDeadline: Duration(seconds: 3),
          ),
        );
        expect(run.outcome.value, isNull);
        expect(run.lateReplyAt, greaterThan(const Duration(milliseconds: 200)));
        expect(run.recorded, isEmpty);
      } finally {
        await slow.close();
      }
    });

    test('a 200 that arrives after the walk was cancelled is not recorded',
        () async {
      final slow = await _LateTlsFront.start(lateBy);
      final cancellation = HubCancellation();
      final timer =
          Timer(const Duration(milliseconds: 100), cancellation.cancel);
      try {
        final run = await walk(
          slow: slow,
          policy: raceWindow,
          cancellation: cancellation,
        );
        expect(run.outcome.cancelled, isTrue);
        expect(run.lateReplyAt, greaterThan(run.finishedAt));
        expect(run.recorded, isEmpty);
      } finally {
        timer.cancel();
        await slow.close();
      }
    });

    test('control: the same slow 200 is recorded when nothing aborts it',
        () async {
      final slow = await _LateTlsFront.start(lateBy);
      try {
        final run = await walk(slow: slow, policy: raceWindow);
        expect(run.outcome.acceptedUrl, contains('sync.winsvpn.org'));
        expect(run.recorded, hasLength(1));
      } finally {
        await slow.close();
      }
    });
  });
}

/// A loopback TLS front that answers 200 with a 2-byte JSON body after
/// [delay]: the whole reply late, or with [headersFirst] the headers at once
/// and only the body late. [replied] completes once the late bytes were
/// written or the write failed; [repliedAt] is read from [clock].
class _LateTlsFront {
  _LateTlsFront._(this._server, this.delay, this.headersFirst) {
    _server.listen(_serve, onError: (Object _) {});
  }

  final SecureServerSocket _server;
  final Duration delay;
  final bool headersFirst;
  final Stopwatch clock = Stopwatch()..start();
  final Completer<void> replied = Completer<void>();
  Duration? repliedAt;

  int get port => _server.port;

  static Future<_LateTlsFront> start(Duration delay,
      {bool headersFirst = false}) async {
    final SecurityContext context = SecurityContext()
      ..useCertificateChainBytes(utf8.encode(
          _pemBlock('CERTIFICATE', base64Decode(kProbeLeafDerBase64)) +
              _pemBlock('CERTIFICATE', base64Decode(kProbeCaDerBase64))))
      ..usePrivateKeyBytes(utf8.encode(_pemBlock(
          'PRIVATE KEY', base64Decode(kProbeLeafKeyPkcs8DerBase64))));
    return _LateTlsFront._(
      await SecureServerSocket.bind(InternetAddress.loopbackIPv4, 0, context),
      delay,
      headersFirst,
    );
  }

  Future<void> _serve(SecureSocket client) async {
    const head = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
        'Content-Length: 2\r\nConnection: close\r\n\r\n';
    try {
      await client.firstWhere((data) =>
          utf8.decode(data, allowMalformed: true).contains('\r\n\r\n'));
      if (headersFirst) {
        client.write(head);
        await client.flush();
      }
      await Future<void>.delayed(delay);
      repliedAt = clock.elapsed;
      client.write(headersFirst ? '{}' : '$head{}');
      await client.flush();
      await client.close();
    } catch (_) {
      repliedAt ??= clock.elapsed;
    } finally {
      if (!replied.isCompleted) replied.complete();
      client.destroy();
    }
  }

  Future<void> close() => _server.close();
}
