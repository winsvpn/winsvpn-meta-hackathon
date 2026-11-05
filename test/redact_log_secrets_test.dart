import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/diagnostic_redaction.dart';

// Pins `redactLogSecrets` -- the anti-leak choke point for every debug log line
// in lib/main.dart -- to the exact identifier classes the product must never
// publish: server hostnames, endpoint IPs, public keys, user identifiers, and
// connection/account identifiers.
void main() {
  test('redactLogSecrets strips server hostnames and URLs', () {
    for (final input in <String>[
      'Double VPN assignment request failed through https://gw1.example.net:443/api: boom',
      'Free status preflight unavailable through wss://edge2.example.org:8443/ws: timeout',
      'Pathfinder: Gateway http://203.0.113.7:8080/v1 failed: refused',
    ]) {
      final out = redactLogSecrets(input);
      expect(out, isNot(contains('example.net')));
      expect(out, isNot(contains('example.org')));
      expect(out, isNot(contains('203.0.113.7')));
      expect(out, contains('<url>'));
    }
  });

  test('redactLogSecrets strips bare host:port and endpoint IPs', () {
    final out = redactLogSecrets(
      'gateway at gw-asia.example.net:443 peer 203.0.113.9:51820 '
      'and [2001:db8::99]:51820',
    );
    expect(out, isNot(contains('gw-asia.example.net')));
    expect(out, isNot(contains('203.0.113.9')));
    expect(out, isNot(contains('2001:db8')));
    expect(out, contains('<host>'));
    expect(out, contains('<ip>'));
  });

  test('an IPv6 address before a sentence period is still redacted', () {
    for (final input in <String>[
      'connected to 2001:db8::1.',
      'via 2a02:6b8:a::a. Retrying',
      'peer fe80::1%en0. down',
      'mapped ::ffff:203.0.113.9.',
    ]) {
      final out = redactLogSecrets(input);
      expect(out, contains('<ip>'), reason: input);
      expect(out, isNot(contains('2001:db8')), reason: input);
      expect(out, isNot(contains('2a02:6b8')), reason: input);
      expect(out, isNot(contains('fe80')), reason: input);
      expect(out, isNot(contains('203.0.113.9')), reason: input);
    }
    expect(redactLogSecrets('connected to 2001:db8::1.'),
        'connected to <ip>.');
    expect(redactTunnelFailureText('tunnel failed at 2001:db8::7.'),
        isNot(contains('2001:db8')));
    // Timestamps followed by a period stay untouched.
    expect(redactLogSecrets('done at 12:34:56.'), 'done at 12:34:56.');
  });

  test('redactLogSecrets strips public keys and tokens', () {
    const hex =
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const urlSafeKey = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMn';
    const urlToken =
        'abcdefghijklmnopqrstuvwx.yzABCDEFGHIJKLMNOPQRSTUV.0123456789abcdefghijkl';
    final out = redactLogSecrets(
      'loaded key $hex urlsafe $urlSafeKey token $urlToken',
    );
    expect(out, isNot(contains(hex)));
    expect(out, isNot(contains(urlSafeKey)));
    expect(out, isNot(contains(urlToken)));
    expect(out, contains('<key>'));
    expect(out, contains('<token>'));
  });

  test('redactLogSecrets strips user identifiers and account numbers', () {
    final out = redactLogSecrets(
      'account 1234-5678-9012 device 550e8400-e29b-41d4-a716-446655440000',
    );
    expect(out, isNot(contains('1234-5678-9012')));
    expect(out, isNot(contains('550e8400-e29b-41d4-a716-446655440000')));
    expect(out, contains('<account>'));
    expect(out, contains('<id>'));
  });

  test('redactLogSecrets redacts bare hostnames without weakening token rules', () {
    expect(
      redactLogSecrets('lookup cdn.example-edge.net failed'),
      'lookup <host> failed',
    );
    const token =
        'abcdefghijklmnopqrst.uvwxyzabcdefghijklmn.0123456789abcdefghijkl';
    final out = redactLogSecrets('token $token end');
    expect(out, 'token <token> end');
    expect(out, isNot(contains('0123456789abcdefghijkl')));
  });

  test('redactLogSecrets keeps harmless prose and non-identifiers', () {
    // The negative control: text with no identifier must pass through intact,
    // so the redactor is not a blanket that mangles every line.
    const input = 'tunnel start stage: load_manager';
    expect(redactLogSecrets(input), input);
  });
}
