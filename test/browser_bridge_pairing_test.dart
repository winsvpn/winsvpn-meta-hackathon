// Browser pairing (R20 A1): the state machine, the IPC refusal paths, the
// pairing store, the unsigned-Windows app identity, and the in-app dialog.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/browser_bridge_app_ipc.dart';
import 'package:wins_vpn/browser_bridge_pairing_dialog.dart';
import 'package:wins_vpn/browser_bridge_protocol.dart';

const String _origin = 'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/';
const String _firefox = 'companion@winsvpn.org';
const Map<String, String> _known = <String, String>{
  _origin: 'Test Chrome',
  _firefox: 'Test Firefox',
};

class _Clock {
  DateTime now = DateTime.utc(2026, 11, 2, 12);
  DateTime call() => now;
  void advance(Duration by) => now = now.add(by);
}

class _Prompt {
  final List<BrowserBridgePairingRequest> seen =
      <BrowserBridgePairingRequest>[];
  Completer<bool> answer = Completer<bool>();

  Future<bool> call(BrowserBridgePairingRequest request) {
    seen.add(request);
    return answer.future;
  }
}

Future<void> _settle() async {
  for (var i = 0; i < 5; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Matcher _refused(BrowserBridgeAppIpcError code) => throwsA(
      isA<BrowserBridgeAppIpcException>().having((e) => e.code, 'code', code),
    );

void main() {
  group('pairing state machine', () {
    late _Clock clock;
    late _Prompt prompt;
    late List<List<BrowserBridgePairingRecord>> persisted;
    late BrowserBridgePairingRegistry registry;
    bool available = true;
    bool failPersist = false;

    setUp(() {
      clock = _Clock();
      prompt = _Prompt();
      persisted = <List<BrowserBridgePairingRecord>>[];
      available = true;
      failPersist = false;
      registry = BrowserBridgePairingRegistry(
        knownOrigins: _known,
        prompt: prompt.call,
        available: () => available,
        persist: (records) async {
          if (failPersist) throw const FileSystemException('disk full');
          persisted.add(records);
        },
        clock: clock.call,
        random: Random(7),
      );
    });

    Future<String> pairApproved([String origin = _origin]) async {
      final begun = registry.begin(origin);
      prompt.answer.complete(true);
      await _settle();
      final answer = registry.poll(origin, begun.pairingId);
      expect(answer.state, BridgePairingFlowState.approved);
      prompt.answer = Completer<bool>();
      return answer.credential;
    }

    test('begin returns a pending pairing with a six-digit code', () {
      final answer = registry.begin(_origin);
      expect(answer.state, BridgePairingFlowState.pending);
      expect(answer.pairingId, matches(kBrowserBridgePairingIdPattern));
      expect(answer.code, matches(kBridgePairingCodePattern));
      expect(answer.credential, isEmpty);
      expect(answer.expiresInSeconds, kBrowserBridgePairingTtl.inSeconds);
      expect(prompt.seen.single.code, answer.code);
      expect(prompt.seen.single.label, 'Test Chrome');
      expect(registry.pendingRequest?.code, answer.code);
      final poll = registry.poll(_origin, answer.pairingId);
      expect(poll.state, BridgePairingFlowState.pending);
      expect(poll.code, answer.code);
    });

    test('approval mints an origin-bound credential delivered exactly once',
        () async {
      final begun = registry.begin(_origin);
      prompt.answer.complete(true);
      await _settle();
      final first = registry.poll(_origin, begun.pairingId);
      expect(first.state, BridgePairingFlowState.approved);
      expect(first.credential, matches(kBridgePairingCredentialPattern));
      expect(first.code, isEmpty);
      final second = registry.poll(_origin, begun.pairingId);
      expect(second.state, BridgePairingFlowState.expired);
      expect(second.credential, isEmpty);

      expect(registry.isPaired(_origin, first.credential), isTrue);
      expect(registry.isPaired(_firefox, first.credential), isFalse);
      expect(registry.isPaired(_origin, 'd' * 64), isFalse);
      expect(registry.isPaired(_origin, null), isFalse);
      expect(registry.isPaired(null, first.credential), isFalse);
      expect(registry.isPaired(_origin, 'NOT-HEX'), isFalse);

      // The store keeps a verifier, never the credential.
      expect(persisted, hasLength(1));
      final stored = encodeBrowserBridgePairingStore(persisted.single);
      expect(stored, isNot(contains(first.credential)));
      expect(stored,
          contains(browserBridgePairingVerifier(_origin, first.credential)));
    });

    test('unknown origin, unavailable UI and missing prompt are refused', () {
      expect(
        () => registry
            .begin('chrome-extension://cccccccccccccccccccccccccccccccc/'),
        _refused(BrowserBridgeAppIpcError.identityMismatch),
      );
      available = false;
      expect(() => registry.begin(_origin),
          _refused(BrowserBridgeAppIpcError.pairingUnavailable));
      available = true;
      registry.prompt = null;
      expect(() => registry.begin(_origin),
          _refused(BrowserBridgeAppIpcError.pairingUnavailable));
      expect(prompt.seen, isEmpty);
    });

    test('a second pairing while one waits is busy, not queued', () {
      registry.begin(_origin);
      expect(() => registry.begin(_firefox),
          _refused(BrowserBridgeAppIpcError.busy));
      expect(() => registry.begin(_origin),
          _refused(BrowserBridgeAppIpcError.busy));
      expect(prompt.seen, hasLength(1));
    });

    test('deny gives no credential and starts a cooldown', () async {
      final begun = registry.begin(_origin);
      prompt.answer.complete(false);
      await _settle();
      final answer = registry.poll(_origin, begun.pairingId);
      expect(answer.state, BridgePairingFlowState.denied);
      expect(answer.credential, isEmpty);
      expect(registry.records, isEmpty);
      prompt.answer = Completer<bool>();
      expect(() => registry.begin(_origin),
          _refused(BrowserBridgeAppIpcError.rateLimited));
      clock.advance(kBrowserBridgePairingCooldown);
      expect(registry.begin(_origin).state, BridgePairingFlowState.pending);
    });

    test('no answer before the deadline expires the pairing', () async {
      final begun = registry.begin(_origin);
      clock.advance(kBrowserBridgePairingTtl);
      expect(registry.poll(_origin, begun.pairingId).state,
          BridgePairingFlowState.expired);
      // A late Allow after expiry grants nothing.
      prompt.answer.complete(true);
      await _settle();
      expect(registry.records, isEmpty);
    });

    test('an approval after the app locked is a denial', () async {
      final begun = registry.begin(_origin);
      available = false;
      prompt.answer.complete(true);
      await _settle();
      expect(registry.poll(_origin, begun.pairingId).state,
          BridgePairingFlowState.denied);
      expect(registry.records, isEmpty);
    });

    test('wrong pairing id or origin reads as expired and leaks nothing',
        () async {
      final begun = registry.begin(_origin);
      prompt.answer.complete(true);
      await _settle();
      expect(registry.poll(_firefox, begun.pairingId).state,
          BridgePairingFlowState.expired);
      expect(registry.poll(_origin, '0' * 32).credential, isEmpty);
      expect(registry.poll(_origin, 'short').state,
          BridgePairingFlowState.expired);
      // The real caller still gets its credential.
      expect(registry.poll(_origin, begun.pairingId).state,
          BridgePairingFlowState.approved);
    });

    test('an approval nobody collects takes its record back', () async {
      final begun = registry.begin(_origin);
      prompt.answer.complete(true);
      await _settle();
      expect(registry.records, hasLength(1));
      final writes = persisted.length;
      // No poll: the host died. Past the pickup grace the record is gone,
      // in memory and in the store.
      clock.advance(kBrowserBridgePairingPickupGrace + const Duration(seconds: 1));
      final late = registry.poll(_origin, begun.pairingId);
      expect(late.state, BridgePairingFlowState.expired);
      expect(late.credential, isEmpty);
      expect(registry.records, isEmpty);
      await _settle();
      expect(persisted.length, writes + 1);
      expect(persisted.last, isEmpty);
    });

    test('a re-pair nobody collects does not leave a holderless record',
        () async {
      final first = await pairApproved();
      clock.advance(kBrowserBridgePairingCooldown);
      registry.begin(_origin);
      prompt.answer.complete(true);
      await _settle();
      // The re-approval replaced (revoked) the first credential ...
      expect(registry.isPaired(_origin, first), isFalse);
      // ... and the app locks before the browser collects the new one.
      registry.cancelPending();
      await _settle();
      expect(registry.records, isEmpty);
      expect(persisted.last, isEmpty);
    });

    test('cancel during the store write leaves no record', () async {
      final gate = Completer<void>();
      final writes = <List<BrowserBridgePairingRecord>>[];
      final gated = BrowserBridgePairingRegistry(
        knownOrigins: _known,
        prompt: (_) async => true,
        persist: (records) async {
          writes.add(records);
          if (writes.length == 1) await gate.future;
        },
        clock: clock.call,
        random: Random(7),
      );
      final begun = gated.begin(_firefox);
      await _settle();
      expect(gated.records, hasLength(1)); // written, store not yet done
      gated.cancelPending(); // the app locked while the store was writing
      gate.complete();
      await _settle();
      expect(gated.records, isEmpty);
      expect(writes.last, isEmpty);
      expect(gated.poll(_firefox, begun.pairingId).credential, isEmpty);
    });

    test('a collected approval is kept when the pickup window closes',
        () async {
      final credential = await pairApproved();
      clock.advance(kBrowserBridgePairingTtl + kBrowserBridgePairingPickupGrace);
      registry.cancelPending();
      expect(registry.isPaired(_origin, credential), isTrue);
      expect(registry.records, hasLength(1));
    });

    test('local reset, duress sweep and logout revoke every pairing', () {
      final source = File('lib/main.dart').readAsStringSync();
      int at(String needle, [int from = 0]) {
        final index = source.indexOf(needle, from);
        expect(index, greaterThanOrEqualTo(0), reason: needle);
        return index;
      }

      final helper = at('Future<void> _revokeBrowserBridgePairings(String why)');
      expect(source.substring(helper, helper + 300),
          contains('await _browserBridgePairing?.revokeAll();'));
      final reset = at('      _accountResetRequiresRestart = true;\n      final erased');
      expect(source.substring(reset - 400, reset),
          contains("await _revokeBrowserBridgePairings('reset');"));
      final sweep = at('Future<void> _sweepAppStorageForDuress(');
      final sweepLoop = at('    Future<void> sweep(Directory root) async {', sweep);
      expect(source.substring(sweep, sweepLoop),
          contains("await _revokeBrowserBridgePairings('duress');"));
      for (final logout in <String>[
        '  void _resetAccountUiAfterVerifiedCleanup() {',
        '  void _forcePendingAccountCleanupUi() {',
      ]) {
        final start = at(logout);
        expect(source.substring(start, start + 200),
            contains("unawaited(_revokeBrowserBridgePairings('logout'));"),
            reason: logout);
      }
    });

    test('a failed store write fails the approval closed', () async {
      failPersist = true;
      final begun = registry.begin(_origin);
      prompt.answer.complete(true);
      await _settle();
      final answer = registry.poll(_origin, begun.pairingId);
      expect(answer.state, BridgePairingFlowState.denied);
      expect(answer.credential, isEmpty);
      expect(registry.records, isEmpty);
    });

    test('re-pairing a browser revokes its earlier credential', () async {
      final first = await pairApproved();
      clock.advance(kBrowserBridgePairingCooldown);
      final second = await pairApproved();
      expect(second, isNot(first));
      expect(registry.isPaired(_origin, first), isFalse);
      expect(registry.isPaired(_origin, second), isTrue);
      expect(registry.records, hasLength(1));
    });

    test('revoke, revokePresented and revokeAll return callers to status only',
        () async {
      final chrome = await pairApproved();
      clock.advance(kBrowserBridgePairingCooldown);
      final firefox = await pairApproved(_firefox);
      expect(await registry.revokePresented(_origin, 'e' * 64), isFalse);
      expect(registry.isPaired(_origin, chrome), isTrue);
      expect(await registry.revokePresented(_origin, chrome), isTrue);
      expect(registry.isPaired(_origin, chrome), isFalse);
      expect(registry.isPaired(_firefox, firefox), isTrue);
      expect(await registry.revoke(_firefox), isTrue);
      expect(await registry.revoke(_firefox), isFalse);
      expect(registry.records, isEmpty);
      await pairApproved();
      await registry.revokeAll();
      expect(registry.records, isEmpty);
      expect(persisted.last, isEmpty);
    });

    test('a revoke whose store write fails still stops control now', () async {
      final chrome = await pairApproved();
      failPersist = true;
      await expectLater(registry.revoke(_origin),
          _refused(BrowserBridgeAppIpcError.internal));
      expect(registry.isPaired(_origin, chrome), isFalse);
    });

    test('pairing attempts are rate limited per minute', () async {
      for (var i = 0; i < kBrowserBridgePairingMaxBeginsPerWindow; i++) {
        registry.begin(_origin);
        registry.cancelPending();
        clock.advance(kBrowserBridgePairingCooldown);
      }
      expect(() => registry.begin(_origin),
          _refused(BrowserBridgeAppIpcError.rateLimited));
      clock.advance(kBrowserBridgePairingRateWindow);
      expect(registry.begin(_origin).state, BridgePairingFlowState.pending);
    });

    test('loaded records with unknown origins or bad verifiers are dropped',
        () {
      final at = DateTime.utc(2026);
      registry.replaceRecords(<BrowserBridgePairingRecord>[
        BrowserBridgePairingRecord(
            origin: 'chrome-extension://cccccccccccccccccccccccccccccccc/',
            label: 'x',
            verifier: 'a' * 64,
            createdAt: at,
            lastUsedAt: at),
        BrowserBridgePairingRecord(
            origin: _firefox,
            label: 'x',
            verifier: 'bad',
            createdAt: at,
            lastUsedAt: at),
        BrowserBridgePairingRecord(
            origin: _origin,
            label: 'ok',
            verifier: 'a' * 64,
            createdAt: at,
            lastUsedAt: at),
      ]);
      expect(registry.records.map((r) => r.origin), <String>[_origin]);
    });

    test('production origins are exactly the recorded store and add-on ids',
        () {
      final ids = jsonDecode(
        File('tools/native_messaging/manifests/store_ids.json')
            .readAsStringSync(),
      ) as Map<String, dynamic>;
      final gecko = RegExp(r'"id":\s*"([^"]+)"')
          .firstMatch(
              File('extension/manifest/firefox.jsonc').readAsStringSync())!
          .group(1)!;
      expect(kBrowserBridgeProductionPairingOrigins, <String, String>{
        'chrome-extension://${ids['chrome']}/': 'Google Chrome',
        'chrome-extension://${ids['edge']}/': 'Microsoft Edge',
        gecko: 'Firefox',
      });
    });
  });

  group('pairing store', () {
    test('round trips and rejects anything unexpected', () {
      final at = DateTime.utc(2026, 11, 2);
      final record = BrowserBridgePairingRecord(
          origin: _origin,
          label: 'Test Chrome',
          verifier: 'a' * 64,
          createdAt: at,
          lastUsedAt: at);
      final text =
          encodeBrowserBridgePairingStore(<BrowserBridgePairingRecord>[record]);
      final decoded = decodeBrowserBridgePairingStore(text);
      expect(decoded.single.origin, _origin);
      expect(decoded.single.verifier, 'a' * 64);
      expect(decoded.single.createdAt, at);

      final root = jsonDecode(text) as Map<String, dynamic>;
      Map<String, dynamic> copy() =>
          jsonDecode(jsonEncode(root)) as Map<String, dynamic>;
      final bad = <Map<String, dynamic>>[
        copy()..['v'] = 2,
        copy()..['extra'] = true,
        copy()..['pairings'][0]['credential'] = 'a' * 64,
        copy()..['pairings'][0]['verifier'] = 'xyz',
        copy()..['pairings'][0]['origin'] = 'https://evil.example/',
        copy()
          ..['pairings'] = <Object>[root['pairings'][0], root['pairings'][0]],
      ];
      for (final value in bad) {
        expect(decodeBrowserBridgePairingStore(jsonEncode(value)), isEmpty,
            reason: jsonEncode(value));
      }
      expect(decodeBrowserBridgePairingStore('not json'), isEmpty);
    });

    test('file writes are atomic and 0600; symlinks read as empty', () async {
      final dir = Directory.systemTemp.createTempSync('wins_pairing_store_');
      addTearDown(() => dir.deleteSync(recursive: true));
      final file = File('${dir.path}/$kBrowserBridgePairingStoreFileName');
      final at = DateTime.utc(2026, 11, 2);
      await writeBrowserBridgePairingStore(file, <BrowserBridgePairingRecord>[
        BrowserBridgePairingRecord(
            origin: _origin,
            label: 'Test Chrome',
            verifier: 'a' * 64,
            createdAt: at,
            lastUsedAt: at),
      ]);
      if (!Platform.isWindows) {
        expect(file.statSync().mode & 0x1FF, 0x180);
      }
      expect(
          (await readBrowserBridgePairingStore(file)).single.origin, _origin);
      expect(dir.listSync().whereType<File>(), hasLength(1));
      final link = Link('${dir.path}/linked.json')..createSync(file.path);
      expect(await readBrowserBridgePairingStore(File(link.path)), isEmpty);
      expect(await readBrowserBridgePairingStore(File('${dir.path}/absent')),
          isEmpty);
    });
  });

  group('app IPC pairing gate over real sockets', () {
    late Directory dir;
    late File file;
    late BrowserBridgeAppIpcServer server;
    late BrowserBridgeAppIpcClient client;
    late _Prompt prompt;
    late BrowserBridgePairingRegistry registry;
    late List<String> commands;

    Future<void> start({bool withPairing = true}) async {
      dir = Directory.systemTemp.createTempSync('wins_pairing_ipc_');
      file = File('${dir.path}/ipc.json');
      prompt = _Prompt();
      commands = <String>[];
      registry = BrowserBridgePairingRegistry(
        knownOrigins: _known,
        prompt: prompt.call,
      );
      final trust = BrowserBridgeAppIpcTrust.authenticated(
        secretHex: generateBrowserBridgeAppIpcToken(),
        expectedIdentity: BrowserBridgeAppIpcProcessIdentity.currentProcess(),
      );
      server = BrowserBridgeAppIpcServer(
        discoveryFile: file,
        snapshot: () => const BridgeStatus(
          status: BridgeTunnelStatus.connected,
          detail: BridgeDetailCode.none,
          winn: BridgeWinnState.unavailableOnThisPlatform,
          selectedSlug: '',
          nodes: <BridgeNode>[],
          canRequestConnect: true,
          proxyPort: 0,
          proxyReady: true,
        ),
        onCommand: (command) async => commands.add(command.wire),
        pairing: withPairing ? registry : null,
        trust: trust,
      );
      await server.start();
      client = BrowserBridgeAppIpcClient(discoveryFile: file, trust: trust);
      addTearDown(() async {
        await server.stop();
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
    }

    Future<String> pairOverIpc() async {
      final begun = await client.pairBegin(origin: _origin);
      expect(begun.state, BridgePairingFlowState.pending);
      expect(prompt.seen.last.code, begun.code);
      prompt.answer.complete(true);
      await _settle();
      final done =
          await client.pairPoll(origin: _origin, pairingId: begun.pairingId);
      expect(done.state, BridgePairingFlowState.approved);
      return done.credential;
    }

    test('unpaired callers get status only; control never runs', () async {
      await start();
      final status = await client.getStatus(origin: _origin);
      expect(status.pairing, BridgePairingStatus.unpaired);
      expect(status.canRequestConnect, isFalse);
      await expectLater(
          client.requestDisconnect(origin: _origin, credential: 'd' * 64),
          _refused(BrowserBridgeAppIpcError.notPaired));
      await expectLater(
          client.requestConnect(origin: _origin, credential: 'd' * 64),
          _refused(BrowserBridgeAppIpcError.notPaired));
      expect(commands, isEmpty);
    });

    test('pair over IPC, control with the credential, revoke ends it',
        () async {
      await start();
      final credential = await pairOverIpc();
      final status =
          await client.getStatus(origin: _origin, credential: credential);
      expect(status.pairing, BridgePairingStatus.paired);
      expect(status.canRequestConnect, isTrue);
      await client.requestDisconnect(origin: _origin, credential: credential);
      expect(commands, <String>['request_disconnect']);

      // Same credential, other origin: refused.
      await expectLater(
          client.requestConnect(origin: _firefox, credential: credential),
          _refused(BrowserBridgeAppIpcError.notPaired));

      final revoked =
          await client.pairRevoke(origin: _origin, credential: credential);
      expect(revoked.pairing, BridgePairingStatus.unpaired);
      await expectLater(
          client.requestConnect(origin: _origin, credential: credential),
          _refused(BrowserBridgeAppIpcError.notPaired));
      await expectLater(
          client.pairRevoke(origin: _origin, credential: credential),
          _refused(BrowserBridgeAppIpcError.notPaired));
      expect(commands, <String>['request_disconnect']);
    });

    test('a revocation in the app stops a paired browser at once', () async {
      await start();
      final credential = await pairOverIpc();
      await registry.revoke(_origin);
      await expectLater(
          client.requestDisconnect(origin: _origin, credential: credential),
          _refused(BrowserBridgeAppIpcError.notPaired));
      expect(commands, isEmpty);
    });

    test('pairing refusals cross the IPC as closed codes', () async {
      await start();
      await expectLater(
          client.pairBegin(
              origin: 'chrome-extension://cccccccccccccccccccccccccccccccc/'),
          _refused(BrowserBridgeAppIpcError.identityMismatch));
      await client.pairBegin(origin: _origin);
      await expectLater(client.pairBegin(origin: _firefox),
          _refused(BrowserBridgeAppIpcError.busy));
      final unknown =
          await client.pairPoll(origin: _origin, pairingId: 'f' * 32);
      expect(unknown.state, BridgePairingFlowState.expired);
      expect(prompt.seen, hasLength(1));
    });

    test('a server without a pairing registry refuses control and pairing',
        () async {
      await start(withPairing: false);
      await expectLater(client.pairBegin(origin: _origin),
          _refused(BrowserBridgeAppIpcError.pairingUnavailable));
      await expectLater(
          client.requestDisconnect(origin: _origin, credential: 'd' * 64),
          _refused(BrowserBridgeAppIpcError.notPaired));
      final status = await client.getStatus();
      expect(status.canRequestConnect, isFalse);
      expect(commands, isEmpty);
    });

    Future<Map<String, Object?>?> raw(Map<String, Object?> body) async {
      final endpoint =
          jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      final socket = await Socket.connect(
          InternetAddress.loopbackIPv4, endpoint['port'] as int);
      final bytes = <int>[];
      final done = Completer<Map<String, Object?>?>();
      socket.listen((chunk) {
        bytes.addAll(chunk);
        if (bytes.length < 4) return;
        final n = bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24;
        if (bytes.length >= n + 4 && !done.isCompleted) {
          done.complete(
              (jsonDecode(utf8.decode(bytes.sublist(4, n + 4))) as Map)
                  .cast<String, Object?>());
        }
      }, onDone: () {
        if (!done.isCompleted) done.complete(null);
      }, onError: (_) {
        if (!done.isCompleted) done.complete(null);
      });
      socket.add(encodeBrowserBridgeAppIpcFrame(<String, Object?>{
        'v': 1,
        'id': 'r${Random().nextInt(1 << 30)}',
        'token': endpoint['token'],
        ...body,
      }));
      try {
        return await done.future.timeout(const Duration(seconds: 5));
      } finally {
        socket.destroy();
      }
    }

    test('raw same-user requests with misplaced fields are malformed',
        () async {
      await start();
      final cases = <Map<String, Object?>>[
        <String, Object?>{'type': 'request_disconnect'},
        <String, Object?>{'type': 'request_disconnect', 'origin': _origin},
        <String, Object?>{
          'type': 'request_disconnect',
          'origin': _origin,
          'credential': 'd' * 64,
          'pairing_id': 'f' * 32,
        },
        <String, Object?>{
          'type': 'pair_begin',
          'origin': _origin,
          'credential': 'd' * 64,
        },
        <String, Object?>{'type': 'pair_poll', 'origin': _origin},
        <String, Object?>{'type': 'get_status', 'credential': 'd' * 64},
        <String, Object?>{
          'type': 'request_connect',
          'origin': 'https://x/',
          'credential': 'd' * 64,
        },
        <String, Object?>{
          'type': 'request_connect',
          'origin': _origin,
          'credential': 'D' * 64,
        },
      ];
      for (final body in cases) {
        final reply = await raw(body);
        expect(reply?['ok'], isFalse, reason: jsonEncode(body));
        expect(reply?['error'], 'malformed', reason: jsonEncode(body));
      }
      // An unknown key is refused before any reply is built.
      expect(await raw(<String, Object?>{'type': 'get_status', 'grant': true}),
          isNull);
      expect(commands, isEmpty);
      expect(prompt.seen, isEmpty);
    });
  });

  group('unsigned Windows app identity', () {
    String probe({
      String exePath = r'C:\Program Files\WinsVPN\wins_vpn.exe',
      String exeOwner = 'S-1-5-32-544',
      String dirReparse = '0',
      String? exeExtraAce,
      String? dirExtraAce,
      String? volume = 'Fixed|NTFS',
      String? programFiles = r'C:\Program Files',
    }) {
      String node(String path, String owner, String kind, String reparse,
          List<String> aces) {
        return <String>[
          'NODE',
          'PATH=$path',
          'OWNER=$owner',
          'REPARSE=$reparse',
          'KIND=$kind',
          'EFFECTIVE_WRITE=0',
          ...aces,
          'ENDNODE',
        ].join('\n');
      }

      const full = 2032127;
      const readExecute = 1179817;
      final privileged = <String>[
        'ACE=S-1-5-18|A|$full|1|0',
        'ACE=S-1-5-32-544|A|$full|1|0',
        'ACE=S-1-5-32-545|A|$readExecute|1|0',
      ];
      return <String>[
        kBrowserBridgeAppIpcWindowsAclProbeVersion,
        'CURRENT_USER_SID=S-1-5-21-1-2-3-1001',
        if (volume != null) 'VOLUME=$volume',
        if (programFiles != null) 'PROGRAM_FILES=$programFiles',
        node(exePath, exeOwner, 'FILE', '0', <String>[
          ...privileged,
          if (exeExtraAce != null) 'ACE=$exeExtraAce'
        ]),
        node(r'C:\Program Files\WinsVPN', 'S-1-5-32-544', 'DIR',
            dirReparse, <String>[
          ...privileged,
          if (dirExtraAce != null) 'ACE=$dirExtraAce'
        ]),
        node(
            r'C:\Program Files',
            kBrowserBridgeAppIpcWindowsSidTrustedInstaller,
            'DIR',
            '0',
            privileged),
        node(r'C:\', kBrowserBridgeAppIpcWindowsSidTrustedInstaller, 'DIR', '0',
            <String>[...privileged, 'ACE=S-1-5-11|A|4|0|0']),
        'END',
      ].join('\n');
    }

    bool authenticates(String text,
        {String observed = r'C:\Program Files\WinsVPN\wins_vpn.exe',
        bool isLink = false}) {
      return browserBridgeAppIpcWindowsProtectedInstalledExecutableAuthenticates(
        observedPath: observed,
        acl: parseBrowserBridgeAppIpcWindowsAclProbe(text),
        isLink: isLink,
      );
    }

    test('exact protected Program Files install authenticates unsigned', () {
      expect(kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject, isNull);
      expect(authenticates(probe()), isTrue);
    });

    test('lookalike paths, links and user-writable installs do not', () {
      expect(
          authenticates(probe(),
              observed: r'C:\Users\wins\AppData\Local\WinsVPN\wins_vpn.exe'),
          isFalse);
      expect(authenticates(probe(), isLink: true), isFalse);
      expect(authenticates(probe(dirReparse: '1')), isFalse);
      expect(authenticates(probe(exeOwner: 'S-1-5-21-1-2-3-1001')), isFalse);
      expect(authenticates(probe(exeExtraAce: 'S-1-5-21-1-2-3-1001|A|2|0|0')),
          isFalse);
      expect(authenticates(probe(dirExtraAce: 'S-1-5-32-545|A|1245631|0|0')),
          isFalse);
      expect(authenticates(probe(dirExtraAce: 'S-1-1-0|A|278|0|0')), isFalse);
      // Probe output for a different file than the one observed.
      expect(
          authenticates(probe(exePath: r'C:\Program Files\WinsVPN\other.exe')),
          isFalse);
    });

    test('a network, removable or non-NTFS volume never anchors the app', () {
      expect(authenticates(probe()), isTrue);
      expect(authenticates(probe(volume: 'Network|NTFS')), isFalse);
      expect(authenticates(probe(volume: 'Removable|FAT32')), isFalse);
      expect(authenticates(probe(volume: 'Fixed|exFAT')), isFalse);
      expect(authenticates(probe(volume: 'Fixed|ReFS')), isFalse);
      // A probe that did not report its volume fails closed for the app.
      expect(authenticates(probe(volume: null)), isFalse);
    });

    test('Program Files comes from the known folder, not the host env', () {
      // A launcher sets ProgramFiles=Z:\ and mounts a share there. The probe
      // reports the OS known folder, so Z:\WinsVPN\wins_vpn.exe is not it,
      // even when that share claims a privileged owner and DACL.
      String share({String volume = 'Fixed|NTFS'}) => probe(volume: volume)
          .replaceAll(r'C:\Program Files\WinsVPN\wins_vpn.exe',
              r'Z:\WinsVPN\wins_vpn.exe')
          .replaceAll(r'PATH=C:\Program Files\WinsVPN', r'PATH=Z:\WinsVPN')
          .replaceAll(r'PATH=C:\Program Files', r'PATH=Z:\')
          .replaceAll(RegExp(r'NODE\nPATH=C:\\\nOWNER=[^\n]*\n'
              r'REPARSE=0\nKIND=DIR\nEFFECTIVE_WRITE=0\n(ACE=[^\n]*\n)*ENDNODE\n'), '');
      expect(
          authenticates(share(volume: 'Network|NTFS'),
              observed: r'Z:\WinsVPN\wins_vpn.exe'),
          isFalse);
      // The forged share's ACL chain alone would pass; only the known folder
      // and the volume refuse it.
      expect(
          browserBridgeAppIpcWindowsIntegrityFault(
            snapshot: parseBrowserBridgeAppIpcWindowsAclProbe(share()),
            expectedCanonicalPath: r'Z:\WinsVPN\wins_vpn.exe',
          ),
          isNull);
      expect(authenticates(share(), observed: r'Z:\WinsVPN\wins_vpn.exe'),
          isFalse);
      // The known folder itself moves the anchor, and a missing one refuses.
      expect(
          authenticates(probe(programFiles: r'D:\Programs'),
              observed: r'C:\Program Files\WinsVPN\wins_vpn.exe'),
          isFalse);
      expect(authenticates(probe(programFiles: null)), isFalse);
      final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
      expect(source, isNot(contains('_windowsProgramFiles(')));
      expect(source,
          contains('[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)'));
      expect(source, contains("Write-Output ('VOLUME=' + [string]\$volume.DriveType"));
    });

    test('volume and known-folder lines are closed and placed', () {
      Matcher malformed() => throwsA(isA<BrowserBridgeAppIpcException>()
          .having((e) => e.code, 'code', BrowserBridgeAppIpcError.malformed));
      final good = probe();
      // Before CURRENT_USER_SID, twice, after a NODE, or ill-formed: refused.
      expect(
          () => parseBrowserBridgeAppIpcWindowsAclProbe(good.replaceFirst(
              'CURRENT_USER_SID=S-1-5-21-1-2-3-1001\nVOLUME=Fixed|NTFS',
              'VOLUME=Fixed|NTFS\nCURRENT_USER_SID=S-1-5-21-1-2-3-1001')),
          malformed());
      expect(
          () => parseBrowserBridgeAppIpcWindowsAclProbe(good.replaceFirst(
              'VOLUME=Fixed|NTFS', 'VOLUME=Fixed|NTFS\nVOLUME=Fixed|NTFS')),
          malformed());
      expect(
          () => parseBrowserBridgeAppIpcWindowsAclProbe(
              good.replaceFirst('VOLUME=Fixed|NTFS', 'VOLUME=Fixed NTFS')),
          malformed());
      expect(
          () => parseBrowserBridgeAppIpcWindowsAclProbe(good.replaceFirst(
              r'PROGRAM_FILES=C:\Program Files', r'PROGRAM_FILES=\\srv\share')),
          malformed());
      expect(
          () => parseBrowserBridgeAppIpcWindowsAclProbe(
              good.replaceFirst('ENDNODE\n', 'ENDNODE\nVOLUME=Fixed|NTFS\n')),
          malformed());
      // The owner-receipt probe stays valid without either line.
      final receipt = parseBrowserBridgeAppIpcWindowsAclProbe(
          probe(volume: null, programFiles: null));
      expect(receipt.volume, isEmpty);
      expect(receipt.programFiles, isEmpty);
      expect(receipt.onFixedNtfs, isFalse);
    });
  });

  group('in-app pairing confirmation', () {
    BrowserBridgePairingRequest request(Duration ttl) =>
        BrowserBridgePairingRequest(
          origin: _origin,
          label: 'Google Chrome',
          code: '042917',
          expiresAt: DateTime.now().toUtc().add(ttl),
        );

    for (final action in <String>['deny', 'allow', 'timeout']) {
      testWidgets('shows the code and answers $action', (tester) async {
        bool? answer;
        await tester.pumpWidget(MaterialApp(home: Builder(builder: (context) {
          return TextButton(
            onPressed: () async {
              answer = await confirmBrowserBridgePairing(
                  context, request(const Duration(seconds: 2)));
            },
            child: const Text('Request'),
          );
        })));
        await tester.tap(find.text('Request'));
        await tester.pumpAndSettle();
        expect(answer, isNull);
        expect(find.text('042 917'), findsOneWidget);
        expect(find.textContaining('Google Chrome'), findsOneWidget);
        expect(find.textContaining('kill switch'), findsOneWidget);
        if (action == 'timeout') {
          await tester.pump(const Duration(seconds: 3));
        } else {
          await tester.tap(find.byKey(Key('browser_pairing_$action')));
        }
        await tester.pumpAndSettle();
        expect(answer, action == 'allow');
        expect(find.byKey(const Key('browser_pairing_dialog')), findsNothing);
      });
    }

    testWidgets('an already expired request never shows', (tester) async {
      bool? answer;
      await tester.pumpWidget(MaterialApp(home: Builder(builder: (context) {
        return TextButton(
          onPressed: () async {
            answer = await confirmBrowserBridgePairing(
                context, request(const Duration(seconds: -1)));
          },
          child: const Text('Request'),
        );
      })));
      await tester.tap(find.text('Request'));
      await tester.pumpAndSettle();
      expect(answer, isFalse);
      expect(find.byKey(const Key('browser_pairing_dialog')), findsNothing);
    });

    testWidgets('paired browsers list revokes one browser', (tester) async {
      final at = DateTime.utc(2026, 11, 2);
      final registry = BrowserBridgePairingRegistry(
        knownOrigins: _known,
        records: <BrowserBridgePairingRecord>[
          BrowserBridgePairingRecord(
              origin: _origin,
              label: 'Test Chrome',
              verifier: browserBridgePairingVerifier(_origin, 'c' * 64),
              createdAt: at,
              lastUsedAt: at),
        ],
      );
      await tester.pumpWidget(MaterialApp(
          home: Scaffold(
              body: Builder(
        builder: (context) => TextButton(
          onPressed: () => showBrowserBridgePairingsDialog(context, registry),
          child: const Text('Open'),
        ),
      ))));
      await tester.tap(find.text('Open'));
      await tester.pumpAndSettle();
      expect(find.text('Test Chrome'), findsOneWidget);
      await tester
          .tap(find.byKey(const Key('browser_pairing_revoke_Test Chrome')));
      await tester.pumpAndSettle();
      expect(registry.records, isEmpty);
      expect(registry.isPaired(_origin, 'c' * 64), isFalse);
      expect(find.text('No browser extension can control the VPN.'),
          findsOneWidget);
    });
  });
}
