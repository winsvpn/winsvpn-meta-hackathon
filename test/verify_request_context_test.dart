import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/verify_request_context.dart';

void main() {
  test('verify request freezes one header snapshot for all retries', () {
    final mutable = <String, String>{
      'Authorization': 'Bearer device-token',
      'Content-Type': 'application/json',
    };
    final request =
        VerifyRequestContext(body: '{"location":"auto"}', headers: mutable);

    mutable['Authorization'] = 'Bearer changed';
    expect(request.headers['Authorization'], 'Bearer device-token');
    expect(
      () => request.headers['X-Wins-Activation'] = 'unexpected',
      throwsUnsupportedError,
    );
    expect(identical(request.headers, request.headers), isTrue);
  });

  test('Apple key replacement is exposed only as an explicit commit method',
      () {
    final store =
        File('apple/WinsTunnelCore/WinsTunnelConfig.swift').readAsStringSync();
    expect(store, contains('static func replace(_ keyPair: WinsClientKeyPair'));
    expect(store, contains('readBack.privateKey == keyPair.privateKey'));
    expect(store, contains('readBack.publicKey == keyPair.publicKey'));

    for (final path in <String>[
      'ios/Runner/AppDelegate.swift',
      'macos/Runner/MainFlutterWindow.swift',
    ]) {
      final host = File(path).readAsStringSync();
      expect(host, contains('case "loadExistingClientKeyPair":'));
      expect(host, contains('case "replaceClientKeyPairForAccount":'));
      expect(host, contains('try WinsClientKeyStore.replace('));
    }
  });
}
