// End-to-end proof of browser pairing through the shipping host (R20 A1).
//
// A real BrowserBridgeAppIpcServer with a pairing registry, the shipping
// AppIpcStateSource, and BridgeHost fed native messages as the extension
// sends them. The in-app confirmation is a completer the test answers.
//
// Run from this package:
//   dart run test/pairing_flow_test.dart

import 'dart:async';
import 'dart:io';

import 'package:wins_bridge_host/browser_bridge_app_ipc.dart';
import 'package:wins_bridge_host/browser_bridge_protocol.dart';

import '../bin/wins_bridge_host.dart';

const _origin = 'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/';
const _otherOrigin = 'chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/';

void _expect(bool ok, String message) {
  if (!ok) throw StateError(message);
}

void _expectEq(Object? actual, Object? expected, String message) {
  if (actual != expected) {
    throw StateError('$message: expected $expected, got $actual');
  }
}

class _App {
  BridgeTunnelStatus status = BridgeTunnelStatus.disconnected;
  final List<String> commands = <String>[];
  final List<BrowserBridgePairingRequest> prompts =
      <BrowserBridgePairingRequest>[];
  Completer<bool> answer = Completer<bool>();

  BridgeStatus snapshot() => BridgeStatus(
        status: status,
        detail: BridgeDetailCode.none,
        winn: BridgeWinnState.unavailableOnThisPlatform,
        selectedSlug: '',
        nodes: const <BridgeNode>[],
        canRequestConnect: true,
        proxyPort: 0,
        proxyReady: status.isCarryingTraffic,
      );

  Future<void> onCommand(BrowserBridgeAppIpcCommand command) async {
    commands.add(command.wire);
    if (command == BrowserBridgeAppIpcCommand.requestConnect) {
      status = BridgeTunnelStatus.connected;
    } else if (command == BrowserBridgeAppIpcCommand.requestDisconnect) {
      status = BridgeTunnelStatus.disconnected;
    }
  }

  Future<bool> prompt(BrowserBridgePairingRequest request) {
    prompts.add(request);
    return answer.future;
  }
}

BridgeHost _host(
  File file,
  BrowserBridgeAppIpcTrust owner,
  List<Map<String, Object?>> out, {
  String origin = _origin,
}) {
  final host = BridgeHost(
    stateSource: AppIpcStateSource(
      winn: BridgeWinnState.unavailableOnThisPlatform,
      discoveryFile: file,
      trust: owner,
    ),
    operatingSystem: Platform.operatingSystem,
    emitForTest: out.add,
    allowedOrigins: const <String>{_origin, _otherOrigin},
  );
  host.setCallerOrigin(origin);
  return host;
}

Map<String, Object?> _msg(String id, String type, [Map<String, Object?>? x]) =>
    <String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': id,
      'type': type,
      ...?x
    };

Future<Map<String, Object?>> _waitFor(
  List<Map<String, Object?>> out,
  bool Function(Map<String, Object?>) match, {
  Duration timeout = const Duration(seconds: 8),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    for (final message in out) {
      if (match(message)) return message;
    }
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
  throw StateError('timed out waiting for a host message; saw $out');
}

Future<void> main() async {
  final dir = Directory.systemTemp.createTempSync('wins_bridge_pairing_');
  final file = File('${dir.path}/ipc.json');
  final owner = BrowserBridgeAppIpcTrust.authenticated(
    secretHex: generateBrowserBridgeAppIpcToken(),
    expectedIdentity: BrowserBridgeAppIpcProcessIdentity.currentProcess(),
  );
  final app = _App();
  final registry = BrowserBridgePairingRegistry(
    knownOrigins: const <String, String>{
      _origin: 'Test Chrome',
      _otherOrigin: 'Test Edge',
    },
    prompt: app.prompt,
  );
  final server = BrowserBridgeAppIpcServer(
    discoveryFile: file,
    snapshot: app.snapshot,
    onCommand: app.onCommand,
    pairing: registry,
    trust: owner,
  );
  await server.start();
  try {
    final out = <Map<String, Object?>>[];
    final host = _host(file, owner, out);

    // Unpaired: status only, and control is refused as not permitted.
    await host.handleNativeMessageForTest(_msg('s1', 'get_status'));
    _expectEq(out.single['pairing'], 'unpaired', 'fresh host pairing');
    _expectEq(out.single['canRequestConnect'], false, 'unpaired control');
    out.clear();
    for (final type in <String>['request_connect', 'request_disconnect']) {
      await host.handleNativeMessageForTest(_msg('u-$type', type));
      _expectEq(out.single['error'], 'not_permitted', 'unpaired $type');
      out.clear();
    }
    _expect(app.commands.isEmpty, 'unpaired control reached the app');

    // Pairing: the reply carries the code the app shows.
    await host.handleNativeMessageForTest(_msg('p1', 'pair_begin'));
    final pending = out.single;
    _expectEq(pending['type'], 'pairing', 'pair_begin reply type');
    _expectEq(pending['state'], 'pending', 'pair_begin state');
    _expect(!pending.containsKey('credential'), 'pending carried a credential');
    _expectEq(app.prompts.length, 1, 'one in-app prompt');
    _expectEq(pending['code'], app.prompts.single.code, 'same code both sides');
    _expectEq(app.prompts.single.label, 'Test Chrome', 'prompt label');
    out.clear();

    // A second pairing while one waits is refused, not queued.
    final other = <Map<String, Object?>>[];
    final otherHost = _host(file, owner, other, origin: _otherOrigin);
    await otherHost.handleNativeMessageForTest(_msg('p2', 'pair_begin'));
    _expectEq(other.single['state'], 'busy', 'concurrent pairing');
    _expectEq(app.prompts.length, 1, 'no second prompt');

    // Approve in the app; the host's poll delivers the credential once.
    app.answer.complete(true);
    final approved = await _waitFor(
      out,
      (m) => m['type'] == 'pairing' && m['state'] == 'approved',
    );
    final credential = approved['credential'];
    _expect(
      credential is String &&
          kBridgePairingCredentialPattern.hasMatch(credential),
      'approved event lacks a credential',
    );
    // The host presents the new credential at once and pushes the change.
    await _waitFor(
      out,
      (m) => m['type'] == 'status' && m['pairing'] == 'paired',
    );
    out.clear();
    await host.handleNativeMessageForTest(_msg('s2', 'get_status'));
    _expectEq(out.single['pairing'], 'paired', 'paired after approval');
    _expectEq(out.single['canRequestConnect'], true, 'paired control offered');
    out.clear();

    await host.handleNativeMessageForTest(_msg('c1', 'request_connect'));
    _expectEq(out.single['status'], 'connected', 'paired connect');
    out.clear();
    await host.handleNativeMessageForTest(_msg('d1', 'request_disconnect'));
    _expectEq(out.single['status'], 'disconnected', 'paired disconnect');
    out.clear();
    _expectEq(app.commands.join(','), 'request_connect,request_disconnect',
        'paired controls reached the app once each');

    // A new browser session presents the stored credential.
    final next = <Map<String, Object?>>[];
    final nextHost = _host(file, owner, next);
    await nextHost.handleNativeMessageForTest(
      _msg('sp1', 'set_pairing', <String, Object?>{'credential': credential}),
    );
    _expectEq(next.single['pairing'], 'paired', 'stored credential pairs');
    next.clear();

    // The same credential under another origin is not a pairing.
    final cross = <Map<String, Object?>>[];
    final crossHost = _host(file, owner, cross, origin: _otherOrigin);
    await crossHost.handleNativeMessageForTest(
      _msg('sp2', 'set_pairing', <String, Object?>{'credential': credential}),
    );
    _expectEq(
        cross.single['pairing'], 'unpaired', 'credential is origin-bound');
    cross.clear();
    await crossHost
        .handleNativeMessageForTest(_msg('cx', 'request_disconnect'));
    _expectEq(cross.single['error'], 'not_permitted', 'cross-origin control');

    // A wrong or malformed credential is not a pairing either.
    await nextHost.handleNativeMessageForTest(_msg(
      'sp3',
      'set_pairing',
      <String, Object?>{'credential': 'd' * 64},
    ));
    _expectEq(next.single['pairing'], 'unpaired', 'wrong credential');
    next.clear();
    await nextHost.handleNativeMessageForTest(_msg(
      'sp4',
      'set_pairing',
      <String, Object?>{'credential': 'not-hex'},
    ));
    _expectEq(next.single['error'], 'malformed', 'malformed credential');
    next.clear();

    // Revoked in the app: the next request is status only.
    await nextHost.handleNativeMessageForTest(
      _msg('sp5', 'set_pairing', <String, Object?>{'credential': credential}),
    );
    _expectEq(next.single['pairing'], 'paired', 're-presented');
    next.clear();
    await registry.revoke(_origin);
    await nextHost.handleNativeMessageForTest(_msg('s3', 'get_status'));
    _expectEq(next.single['pairing'], 'unpaired', 'revoked status');
    next.clear();
    final before = app.commands.length;
    await nextHost.handleNativeMessageForTest(_msg('c2', 'request_disconnect'));
    _expectEq(next.single['error'], 'not_permitted', 'revoked disconnect');
    _expectEq(app.commands.length, before, 'revoked control reached the app');
    next.clear();

    // Pair again, then forget from the extension side.
    await Future<void>.delayed(kBrowserBridgePairingCooldown);
    app.answer = Completer<bool>()..complete(true);
    await nextHost.handleNativeMessageForTest(_msg('p3', 'pair_begin'));
    _expectEq(next.single['state'], 'pending', 're-pair pending');
    next.clear();
    await _waitFor(next, (m) => m['state'] == 'approved');
    await _waitFor(
      next,
      (m) => m['type'] == 'status' && m['pairing'] == 'paired',
    );
    next.clear();
    await nextHost.handleNativeMessageForTest(_msg('f1', 'pair_forget'));
    _expectEq(next.single['pairing'], 'unpaired', 'forgotten');
    _expect(registry.records.isEmpty, 'app still holds a forgotten pairing');
    next.clear();

    // Denied in the app: no credential, still status only.
    await Future<void>.delayed(kBrowserBridgePairingCooldown);
    app.answer = Completer<bool>()..complete(false);
    await nextHost.handleNativeMessageForTest(_msg('p4', 'pair_begin'));
    next.clear();
    final denied = await _waitFor(next, (m) => m['type'] == 'pairing');
    _expectEq(denied['state'], 'denied', 'denied state');
    _expect(!denied.containsKey('credential'), 'denied carried a credential');

    // A launch without an allowed origin cannot start a pairing.
    final stray = <Map<String, Object?>>[];
    final strayHost = BridgeHost(
      stateSource: AppIpcStateSource(
        winn: BridgeWinnState.unavailableOnThisPlatform,
        discoveryFile: file,
        trust: owner,
      ),
      operatingSystem: Platform.operatingSystem,
      emitForTest: stray.add,
      allowedOrigins: const <String>{_origin},
    );
    strayHost.setCallerOrigin(null);
    await strayHost.handleNativeMessageForTest(_msg('p5', 'pair_begin'));
    _expectEq(stray.single['error'], 'not_permitted', 'originless pair_begin');

    stdout.writeln('PASS: pairing gates control end to end; unpaired, '
        'cross-origin, wrong, revoked and denied callers get status only');
  } finally {
    await server.stop();
    await registry.dispose();
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  }
  exit(0);
}
