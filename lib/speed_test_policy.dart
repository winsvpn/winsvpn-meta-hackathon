class SpeedTestPolicy {
  static const int cloudflareDownloadBytes = 50000000;
  static const double highCapacityMbps = 850;

  static int downloadParallelism(Uri uri) {
    if (uri.host == 'speed.cloudflare.com' ||
        uri.host == 'cachefly.cachefly.net') {
      return 32;
    }
    return 4;
  }

  static int uploadParallelism(Uri uri) {
    if (uri.host == 'speed.cloudflare.com') {
      return 32;
    }
    return 8;
  }

  static Uri downloadUriForStream(String rawUrl, int streamIndex) {
    final uri = Uri.parse(rawUrl);
    final query = Map<String, String>.from(uri.queryParameters);
    if (uri.host == 'speed.cloudflare.com' && uri.path == '/__down') {
      return uri.replace(
        queryParameters: {'bytes': '$cloudflareDownloadBytes'},
      );
    }
    if (uri.host == 'cachefly.cachefly.net') return uri;
    query['r'] = '${DateTime.now().microsecondsSinceEpoch}-$streamIndex';
    return uri.replace(queryParameters: query);
  }

  static double? aggregateParallelMbps(Iterable<double?> values) {
    final valid = values.whereType<double>().where((value) => value > 0);
    if (valid.isEmpty) return null;
    return valid.reduce((total, value) => total + value);
  }

  static double? mbpsFromBytes({
    required int bytes,
    required Duration elapsed,
  }) {
    if (bytes <= 0 || elapsed.inMicroseconds <= 0) return null;
    final seconds = elapsed.inMicroseconds / Duration.microsecondsPerSecond;
    return (bytes * 8) / seconds / 1000000;
  }

  static double? betterResult(double? current, double? candidate) {
    if (candidate == null || candidate <= 0) return current;
    if (current == null || candidate > current) return candidate;
    return current;
  }

  static bool isHighCapacity(double? value) =>
      value != null && value >= highCapacityMbps;

  // Word used in place of "VPN"/"device" once we know this app's own traffic
  // is currently excluded from the tunnel (stealth-Xray's outer transport
  // requires that), so the result is honestly labeled as the physical
  // connection rather than falsely implying it reflects VPN throughput.
  static String routeLabel({
    required bool isConnected,
    required bool physicalRouteOnly,
  }) {
    if (!isConnected) return 'device';
    return physicalRouteOnly ? 'physical-route' : 'VPN';
  }

  static String testingLabel({
    required bool isConnected,
    required bool physicalRouteOnly,
  }) {
    if (!isConnected) return 'Testing device route...';
    if (physicalRouteOnly) return 'Testing physical route (VPN on)...';
    return 'Testing VPN route...';
  }
}
