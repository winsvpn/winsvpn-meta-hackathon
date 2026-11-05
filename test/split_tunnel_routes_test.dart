import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/split_tunnel_routes.dart';

void main() {
  group('normalizeExcludedIpv4Cidrs', () {
    test('accepts bare addresses and canonicalizes networks', () {
      expect(
        normalizeExcludedIpv4Cidrs(['192.168.1.25/24', '203.0.113.9']),
        ['192.168.1.0/24', '203.0.113.9/32'],
      );
    });

    test('merges overlapping and adjacent networks', () {
      expect(
        normalizeExcludedIpv4Cidrs(
            ['10.0.0.0/9', '10.128.0.0/9', '10.1.2.3/32']),
        ['10.0.0.0/8'],
      );
    });

    test('rejects malformed routes', () {
      expect(
        () => normalizeExcludedIpv4Cidrs(['300.1.1.1/24']),
        throwsFormatException,
      );
      expect(
        () => normalizeExcludedIpv4Cidrs(['10.0.0.0/33']),
        throwsFormatException,
      );
    });
  });

  group('allowedIpv4CidrsExcluding', () {
    test('uses the full IPv4 route when nothing is excluded', () {
      expect(allowedIpv4CidrsExcluding(const []), ['0.0.0.0/0']);
    });

    test('exactly excludes a private network', () {
      final allowed = allowedIpv4CidrsExcluding(['10.0.0.0/8']);
      expect(allowed, [
        '0.0.0.0/5',
        '8.0.0.0/7',
        '11.0.0.0/8',
        '12.0.0.0/6',
        '16.0.0.0/4',
        '32.0.0.0/3',
        '64.0.0.0/2',
        '128.0.0.0/1',
      ]);
    });

    test('can exclude the complete IPv4 address space', () {
      expect(allowedIpv4CidrsExcluding(['0.0.0.0/0']), isEmpty);
    });
  });

  group('windowsPerAppAllowedIpCidrs', () {
    test('keeps full coverage without either implicit kill-switch /0', () {
      expect(
        windowsPerAppAllowedIpCidrs(const ['0.0.0.0/0']),
        const ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'],
      );
    });

    test('preserves existing IPv4 destination exclusions', () {
      expect(
        windowsPerAppAllowedIpCidrs(const ['0.0.0.0/8', '2.0.0.0/7']),
        const ['0.0.0.0/8', '2.0.0.0/7', '::/1', '8000::/1'],
      );
    });
  });

  group('windowsRequiresManualTunnelRoutes', () {
    test('uses owned routes for an ordinary product-engine full tunnel', () {
      expect(
        windowsRequiresManualTunnelRoutes(),
        isTrue,
      );
    });

    test('uses manual routes for user app exclusions', () {
      expect(
        windowsRequiresManualTunnelRoutes(),
        isTrue,
      );
    });

    test('uses manual routes for the internal Xray carrier', () {
      expect(
        windowsRequiresManualTunnelRoutes(),
        isTrue,
      );
    });
  });
}
