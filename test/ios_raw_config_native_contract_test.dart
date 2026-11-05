import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  late String source;

  setUpAll(() {
    source = File('ios/Runner/AppDelegate.swift').readAsStringSync();
  });

  test('native raw seam is DEBUG-only and Release is unimplemented', () {
    const dispatch = '''case "startIosRawConfigLabTunnel":
      #if DEBUG
        startIosRawConfigLabTunnel(call.arguments, result: result)
      #else
        result(FlutterMethodNotImplemented)
      #endif''';
    expect(source, contains(dispatch));
    expect(source.split('case "startIosRawConfigLabTunnel":').length - 1, 1);
  });

  test('raw seam loads existing identity and never calls loadOrCreate', () {
    final start = source.indexOf('private func startIosRawConfigLabTunnel(');
    final end = source.indexOf('\n  #endif', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains('WinsClientKeyStore.loadExisting('));
    expect(body, isNot(contains('WinsClientKeyStore.loadOrCreate(')));
    expect(body, contains('existingClientKeyPair: keyPair'));
    expect(
      body,
      contains('startTunnel(\n          startArguments,'),
    );
  });

  test('private key substitution happens only in native memory', () {
    final start = source.indexOf('private func startIosRawConfigLabTunnel(');
    final end = source.indexOf('\n  #endif', start);
    final body = source.substring(start, end);
    expect(
      body,
      contains('let placeholder = "__WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__"'),
    );
    expect(body, contains('with: keyPair.privateKey'));
    expect(
        body, contains('startArguments.removeValue(forKey: "configTemplate")'));
    expect(body, contains('startArguments["config"] ='));
    expect(body, isNot(contains('result(keyPair.dictionary)')));
  });

  test('lab override prevents the shipping path from creating a key', () {
    final signatureStart = source.indexOf('private func startTunnel(');
    final bodyStart = source.indexOf(') {', signatureStart);
    final bodyEnd = source.indexOf('\n  private func stopTunnel(', bodyStart);
    expect(signatureStart, greaterThanOrEqualTo(0));
    expect(bodyEnd, greaterThan(bodyStart));
    final body = source.substring(signatureStart, bodyEnd);
    expect(
      body,
      contains('existingClientKeyPair: WinsClientKeyPair? = nil'),
    );
    expect(body, contains('if let existingClientKeyPair {'));
    expect(body, contains('clientKeyPair = existingClientKeyPair'));
    expect(
      body,
      contains('clientKeyPair = try WinsClientKeyStore.loadOrCreate('),
    );
  });

  test('standalone credentials never persist to the App Group', () {
    final labStart = source.indexOf('private func startIosRawConfigLabTunnel(');
    final labEnd = source.indexOf('\n  #endif', labStart);
    final labBody = source.substring(labStart, labEnd);
    expect(labBody, contains('transientRawConfigLab: true'));

    final shippingStart = source.indexOf('private func startTunnel(');
    final shippingEnd =
        source.indexOf('\n  private func stopTunnel(', shippingStart);
    final shippingBody = source.substring(shippingStart, shippingEnd);
    expect(
      shippingBody,
      contains('transientRawConfigLab\n'
          '          ? Self.transientRawConfigLabFallbackDocument\n'
          '          : config'),
    );
    expect(
      source,
      contains('shared_config_contains_standalone_credentials": false'),
    );
  });
}
