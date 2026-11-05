import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/speed_test_policy.dart';

void main() {
  test('high-capacity public targets use parallel streams', () {
    expect(
      SpeedTestPolicy.downloadParallelism(
        Uri.parse('https://speed.cloudflare.com/__down?bytes=50000000'),
      ),
      32,
    );
    expect(
      SpeedTestPolicy.downloadParallelism(
        Uri.parse('https://regional.example/speedtest/random.jpg'),
      ),
      4,
    );
    expect(
      SpeedTestPolicy.uploadParallelism(
        Uri.parse('https://speed.cloudflare.com/__up'),
      ),
      32,
    );
    expect(
      SpeedTestPolicy.uploadParallelism(
        Uri.parse('https://regional.example/speedtest/upload.php'),
      ),
      8,
    );
  });

  test('Cloudflare stream URLs preserve the supported API query', () {
    final uri = SpeedTestPolicy.downloadUriForStream(
      'https://speed.cloudflare.com/__down?bytes=50000000',
      3,
    );

    expect(uri.queryParameters['bytes'], '50000000');
    expect(uri.queryParameters.keys, ['bytes']);
  });

  test('regional streams get unique supported cache-busters', () {
    final uri = SpeedTestPolicy.downloadUriForStream(
      'https://regional.example/speedtest/random4000x4000.jpg',
      3,
    );

    expect(uri.queryParameters['r'], endsWith('-3'));
  });

  test('parallel rates aggregate and best results do not regress', () {
    expect(
      SpeedTestPolicy.aggregateParallelMbps([120, 118.5, null, 121.5]),
      360,
    );
    expect(SpeedTestPolicy.betterResult(120, 760), 760);
    expect(SpeedTestPolicy.betterResult(760, 120), 760);
    expect(SpeedTestPolicy.isHighCapacity(850), isTrue);
    expect(SpeedTestPolicy.isHighCapacity(849.9), isFalse);
  });

  test('byte throughput is converted to megabits per second', () {
    expect(
      SpeedTestPolicy.mbpsFromBytes(
        bytes: 125000000,
        elapsed: const Duration(seconds: 1),
      ),
      1000,
    );
    expect(
      SpeedTestPolicy.mbpsFromBytes(
        bytes: 15000000,
        elapsed: const Duration(seconds: 1),
      ),
      120,
    );
    expect(
      SpeedTestPolicy.mbpsFromBytes(
        bytes: 0,
        elapsed: const Duration(seconds: 1),
      ),
      isNull,
    );
  });

  group(
      'route labels never claim VPN when only the physical route was measured',
      () {
    test('disconnected is always labeled as the device route', () {
      expect(
        SpeedTestPolicy.routeLabel(
          isConnected: false,
          physicalRouteOnly: false,
        ),
        'device',
      );
      expect(
        SpeedTestPolicy.routeLabel(
          isConnected: false,
          physicalRouteOnly: true,
        ),
        'device',
      );
      expect(
        SpeedTestPolicy.testingLabel(
          isConnected: false,
          physicalRouteOnly: true,
        ),
        'Testing device route...',
      );
    });

    test('connected with the tunnel actually carrying traffic says VPN', () {
      expect(
        SpeedTestPolicy.routeLabel(
          isConnected: true,
          physicalRouteOnly: false,
        ),
        'VPN',
      );
      expect(
        SpeedTestPolicy.testingLabel(
          isConnected: true,
          physicalRouteOnly: false,
        ),
        'Testing VPN route...',
      );
    });

    test(
        'connected but stealth-Xray excluded this app from the tunnel must '
        'not say VPN', () {
      expect(
        SpeedTestPolicy.routeLabel(
          isConnected: true,
          physicalRouteOnly: true,
        ),
        isNot('VPN'),
      );
      expect(
        SpeedTestPolicy.routeLabel(
          isConnected: true,
          physicalRouteOnly: true,
        ),
        'physical-route',
      );
      expect(
        SpeedTestPolicy.testingLabel(
          isConnected: true,
          physicalRouteOnly: true,
        ),
        isNot(contains('VPN route')),
      );
      expect(
        SpeedTestPolicy.testingLabel(
          isConnected: true,
          physicalRouteOnly: true,
        ),
        contains('physical route'),
      );
    });
  });
}
