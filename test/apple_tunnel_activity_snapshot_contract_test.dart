import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  for (final sourcePath in <String>[
    'ios/Runner/AppDelegate.swift',
    'macos/Runner/MainFlutterWindow.swift',
  ]) {
    test('$sourcePath exposes a sanitized tunnel activity snapshot', () {
      final source = File(sourcePath).readAsStringSync();
      final snapshotStart = source.indexOf('enum WinsAppleTunnelActivitySnapshot');
      final bridgeStart = source.indexOf('TunnelBridge {', snapshotStart);
      expect(snapshotStart, greaterThanOrEqualTo(0));
      expect(bridgeStart, greaterThan(snapshotStart));
      final snapshot = source.substring(snapshotStart, bridgeStart);
      expect(source, contains('case "getTunnelActivitySnapshot"'));
      expect(source, contains('WinsAppleTunnelActivitySnapshot.value'));
      expect(snapshot, contains('["known": false, "active": false]'));
      expect(snapshot, contains('["known": true, "active": true]'));
      expect(snapshot, contains('["known": true, "active": false]'));
      expect(snapshot, isNot(contains('"status":')));
    });
  }
}
