// Watch-status surfacing contract: the phone publishes winn tunnel status
// over the `wins_vpn/watch` channel and the companion watch (watchOS
// `PhoneSnapshot`/`TunnelStatus`, Wear OS `WatchLink`) renders it.
//
// Discipline, from the FALSE_GREEN_CATALOGUE: a positive claim needs a
// negative assert too. So every "surfaces winn status" claim below is paired
// with the thing that MUST NOT cross the link -- and the source guard that the
// status is actually derived from the app's true connection state rather than
// a hardcoded constant.
//
// The Dart `WatchBridge.publish` path is platform-gated (`_supported` is only
// true on Android/iOS, so the method-channel publish is inert on the host test
// VM). That is deliberate in production and cannot be pinned from a host test.
// What CAN be pinned from the host, and what this file pins, is the wire
// contract itself (the status vocabulary the watch parses), the defence that
// keeps a public IP off the link, and the source wiring that feeds real winn
// status in -- the exact three things the phone is responsible for.

import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/watch_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  group('serial publication', () {
    const channel = MethodChannel('wins_vpn/watch');
    final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    late WatchBridge bridge;
    late Completer<bool> first;
    late List<String> states;
    late bool failFirst;

    void publish(WatchTunnelStatus status) => bridge.publish(
      status: status, selectedSlug: '', locations: const []);

    setUp(() {
      WatchBridge.debugSupportedOverride = true;
      bridge = WatchBridge.instance;
      bridge.attach((_, __) async {});
      first = Completer<bool>();
      states = [];
      failFirst = false;
      messenger.setMockMethodCallHandler(channel, (call) async {
        final payload = jsonDecode((call.arguments as Map)['payload'] as String) as Map;
        states.add(payload['status'] as String);
        if (states.length == 1) {
          await first.future;
          if (failFirst) throw PlatformException(code: 'fixture_failure');
        }
        return true;
      });
    });
    tearDown(() {
      bridge.detach();
      WatchBridge.debugSupportedOverride = null;
      messenger.setMockMethodCallHandler(channel, null);
    });

    test('a delayed publish drains the newer state and deduplicates it', () async {
      publish(WatchTunnelStatus.connecting);
      await Future<void>.delayed(Duration.zero);
      publish(WatchTunnelStatus.connected);
      expect(states, ['connecting']);
      first.complete(true);
      await Future<void>.delayed(Duration.zero);
      expect(states, ['connecting', 'connected']);
      publish(WatchTunnelStatus.connected);
      await Future<void>.delayed(Duration.zero);
      expect(states, ['connecting', 'connected']);
    });
    test('a failed publication still drains a newer payload', () async {
      failFirst = true;
      publish(WatchTunnelStatus.connecting);
      await Future<void>.delayed(Duration.zero);
      publish(WatchTunnelStatus.connected);
      first.complete(true);
      await Future<void>.delayed(Duration.zero);
      expect(states, ['connecting', 'connected']);
    });
    test('the newest pending payload replaces an intermediate state', () async {
      publish(WatchTunnelStatus.connecting);
      await Future<void>.delayed(Duration.zero);
      publish(WatchTunnelStatus.connected);
      publish(WatchTunnelStatus.disconnected);
      first.complete(true);
      await Future<void>.delayed(Duration.zero);
      expect(states, ['connecting', 'disconnected']);
    });
    test('detach clears queued publication', () async {
      publish(WatchTunnelStatus.connecting);
      await Future<void>.delayed(Duration.zero);
      publish(WatchTunnelStatus.connected);
      bridge.detach();
      first.complete(true);
      await Future<void>.delayed(Duration.zero);
      expect(states, ['connecting']);
    });
  });

  group('wire vocabulary the watch parses', () {
    test('each status emits exactly the value the companion reads', () {
      // watchOS PhoneSnapshot.TunnelStatus(rawValue:) and Wear OS
      // WatchLink read these strings; the phone staying on them is what makes
      // "winn status surfaces to the watch" true rather than decorative.
      expect(WatchTunnelStatus.disconnected.wireValue, 'disconnected');
      expect(WatchTunnelStatus.connecting.wireValue, 'connecting');
      expect(WatchTunnelStatus.connected.wireValue, 'connected');
      expect(WatchTunnelStatus.disconnecting.wireValue, 'disconnecting');
      expect(WatchTunnelStatus.failed.wireValue, 'failed');
      expect(WatchTunnelStatus.permissionRequired.wireValue,
          'permissionRequired');
      expect(WatchTunnelStatus.unknown.wireValue, 'unknown');
    });
  });

  group('detail is sanitized before it can reach the watch', () {
    test('a public IPv4 is stripped, never forwarded', () {
      final sanitized = WatchBridge.debugSanitizeDetail(
        'connected, assigned 203.0.113.7',
      );
      expect(sanitized.contains('203.0.113.7'), isFalse,
          reason: 'a public IP must not leave the phone');
      expect(sanitized.toLowerCase().contains('connected'), isTrue,
          reason: 'the human-meaningful part survives');
    });

    test('a public IPv6 is stripped, never forwarded', () {
      final sanitized = WatchBridge.debugSanitizeDetail(
        '2606:4700:4700::1111',
      );
      expect(sanitized.contains('2606:4700:4700::1111'), isFalse);
    });

    test('detail is bounded so a phone status line cannot leak wholesale', () {
      final long = WatchBridge.debugSanitizeDetail('x' * 200);
      expect(long.length, lessThanOrEqualTo(60),
          reason: 'watch detail is truncated at the contract maximum');
    });
  });

  group('lib/main.dart surfaces real winn status', () {
    late String mainSource;
    late String bridgeSource;

    setUpAll(() {
      mainSource = File('lib/main.dart').readAsStringSync();
      bridgeSource = File('lib/watch_bridge.dart').readAsStringSync();
    });

    test('the phone publishes winn status to the watch channel', () {
      expect(mainSource.contains('_publishWatchState();'), isTrue,
          reason: 'status must be announced on every build so the watch '
              'can never miss a transition');
      expect(
        mainSource.contains('WatchBridge.instance.publish('),
        isTrue,
        reason: 'the derived status must actually be published to the watch',
      );
    });

    test('the published status derives from the true connection state', () {
      expect(mainSource.contains('status = WatchTunnelStatus.connected'),
          isTrue,
          reason: 'the connected branch hoists the app\'s own state onto '
              'the link');
      // The connected verdict is gated on `_rendersConnected`, not a constant.
      // `_rendersConnected` is the app's true render state: it returns
      // `_isConnected && !_isVpnConnectInFlight && !_isTunnelTransitioning`
      // (plus, on native-tunnel platforms, a live liveness proof). Asserting on
      // it (rather than the older `else if (_isConnected) {`) pins the gate to
      // the stricter derived state that actually drives the "SECURED" paint,
      // so a stale boot boolean can never tell the watch it is connected.
      expect(mainSource.contains('else if (_rendersConnected) {'), isTrue,
          reason: 'the connected verdict must be gated on the app\'s real '
              'connected state, not a constant');
      // Strengthener: prove the render gate is itself derived from the app's
      // real `_isConnected` boolean rather than a hardcoded `true`, or the
      // previous assertion would pass against a getter that always returns
      // true. `_rendersConnected`'s body returns `_isConnected && …`.
      expect(mainSource.contains('bool get _rendersConnected {'), isTrue,
          reason: 'the render gate must exist as a derived getter');
      final gate = _slice(
        mainSource,
        start: 'bool get _rendersConnected {',
        end: '\n  }',
      );
      expect(gate.contains('return _isConnected &&'), isTrue,
          reason: 'the render gate ITSELF must be built on the app\'s real '
              'boolean, not a constant (a match elsewhere in the file does '
              'not count)');
      expect(gate.contains('return true'), isFalse);
      // Negative: the connected branch must be conditional. If a future edit
      // replaced the branch with `status = WatchTunnelStatus.connected;` as an
      // unconditional first line in _publishWatchState, the watch would be told
      // it is always connected. Assert the decision is conditional by checking
      // the disconnected default is also reachable in the same function.
      expect(
        mainSource.contains('status = WatchTunnelStatus.disconnected'),
        isTrue,
        reason: 'a disconnected default must exist so the verdict is not '
            'permanently connected',
      );
    });

    test('the watch is never sent keys, endpoints or account numbers', () {
      // The published payload carries only slug/name/flag per country; the
      // location maps that reach the phone also carry `endpoint` and
      // `stealth_endpoint`, which must be filtered before the link.
      final publishCall = _slice(
        mainSource,
        start: 'WatchBridge.instance.publish(',
        end: ');',
      );
      expect(publishCall, isNotEmpty, reason: 'the publish call is gone');
      expect(publishCall.contains('endpoint'), isFalse,
          reason: 'a node endpoint must not cross to the watch');
      expect(publishCall.contains('stealth_endpoint'), isFalse,
          reason: 'a covert endpoint must not cross to the watch');
      expect(publishCall.contains('PublicKey'), isFalse);
      expect(publishCall.contains('account'), isFalse,
          reason: 'an account identifier must not cross to the watch');
    });

    test('countries payload forwards only slug, name and flag', () {
      expect(bridgeSource.contains("'slug': slug"), isTrue);
      expect(bridgeSource.contains("'name':"), isTrue);
      expect(bridgeSource.contains("'flag':"), isTrue);
      // Negative: the exact secret-carrying keys never appear in the payload.
      for (final forbidden in <String>[
        "'endpoint'",
        "'stealth_endpoint'",
        "'public_key'",
      ]) {
        expect(bridgeSource.contains(forbidden), isFalse,
            reason: 'WatchBridge must not emit $forbidden');
      }
    });
  });
}

/// The text between the first [start] and the next [end] after it, or `''`.
String _slice(String source, {required String start, required String end}) {
  final from = source.indexOf(start);
  if (from < 0) return '';
  final to = source.indexOf(end, from + start.length);
  if (to < 0) return '';
  return source.substring(from, to + end.length);
}
