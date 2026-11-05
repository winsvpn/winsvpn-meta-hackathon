import 'dart:io';

import 'package:wins_vpn/throughput_speed_test.dart';

Future<void> main() async {
  const candidates = <String, String>{
    'Cloudflare': 'https://speed.cloudflare.com/__down?bytes=50000000',
    'CacheFly': 'https://cachefly.cachefly.net/100mb.test',
  };
  final tester = ThroughputSpeedTest(userAgent: 'WinsVPN-SmokeTest/1.0');

  String? selectedName;
  String? selectedUrl;
  double? bestProbe;
  for (final candidate in candidates.entries) {
    final probe = await tester.measureDownload(
      candidate.value,
      duration: const Duration(seconds: 2),
      parallelStreams: 3,
      maximumBytes: 96 * 1024 * 1024,
    );
    final mbps = probe?.mbps;
    stdout.writeln('${candidate.key} probe: ${_label(mbps)} Mbps');
    if (mbps != null && (bestProbe == null || mbps > bestProbe)) {
      bestProbe = mbps;
      selectedName = candidate.key;
      selectedUrl = candidate.value;
    }
  }

  if (selectedUrl == null) {
    throw StateError('No download endpoint was reachable.');
  }

  final download = await tester.measureDownload(
    selectedUrl,
    duration: const Duration(seconds: 8),
    parallelStreams: 6,
    maximumBytes: 512 * 1024 * 1024,
  );
  final upload = await tester.measureUpload(
    'https://speed.cloudflare.com/__up',
    duration: const Duration(seconds: 8),
    parallelStreams: 4,
    maximumBytes: 256 * 1024 * 1024,
  );

  stdout.writeln('Selected endpoint: $selectedName');
  stdout.writeln('Download: ${_label(download?.mbps)} Mbps');
  stdout.writeln('Upload: ${_label(upload?.mbps)} Mbps');
}

String _label(double? value) =>
    value == null ? 'unavailable' : value.toStringAsFixed(1);
