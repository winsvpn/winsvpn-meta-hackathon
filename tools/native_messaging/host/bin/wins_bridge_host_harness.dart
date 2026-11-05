// THE REAL HOST, WITH ONE THING REPLACED: WHERE IT LEARNS THE TUNNEL STATE.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS AND WHAT IT IS NOT
// ---------------------------------------------------------------------------
//
// `bin/wins_bridge_host.dart` talks to the desktop app over authenticated
// loopback IPC. When the app is not running that IPC is absent, the host
// reports `app_not_running`, and the proxy refuses -- fail-closed, which is
// the correct production behaviour.
//
// It also means a live browser cannot be driven past `APP_NOT_RUNNING` unless
// a real desktop app is running, so protocol-level verification of the compiled
// host still needs SOME state source that a test can write.
//
// This entry point is that state source and NOTHING ELSE. It is compiled from
// the same package, links the same `lib/` symlinks, and constructs the same
// `BridgeHost` with the same dispatch table, the same `BridgeProxyServer`,
// the same `BridgeStatus.toWire`, the same address guard and the same framing.
// The difference between this binary and the shipping one is exactly:
//
//     stateSource: AppIpcStateSource(winn: winn)     <- shipping
//     stateSource: FileStateSource(File(path))       <- here
//
// So a result measured with this binary is a result about the real host's
// protocol and proxy behaviour, and is NOT a result about the shipping
// binary's state source.
//
// THIS IS NOT A SHIPPING PATH. It is not installed, it is not referenced by
// `install_native_host.sh`, and it is not what `--selftest` builds. A file that
// lets a local writer declare "the tunnel is up" opens the proxy's gate, and
// that is precisely why it is a separate entry point rather than a flag on the
// shipping one: the shipping host has no way to be told this, by anybody.

import 'dart:convert';
import 'dart:io';

import 'package:wins_bridge_host/browser_bridge_protocol.dart';

import 'wins_bridge_host.dart';

/// Reads the tunnel state from a JSON file, in the same shape as the
/// extension harness's `dev_bridge.py` stand-in reads.
///
/// Re-read on every snapshot rather than cached, because the harness changes
/// the state under a running browser and the whole point of the run is to watch
/// the extension follow it.
///
/// Defaults are the closed ones, for the same reason the stand-in's are: a file
/// that cannot be read must produce "not connected", never "connected". A state
/// source that failed open would make every fail-closed result in this tree
/// meaningless.
class FileStateSource implements BridgeStateSource {
  FileStateSource(this.file, this.winn);

  final File file;
  final BridgeWinnState winn;

  @override
  Future<BridgeStatus> read() async {
    Map<String, Object?> raw;
    try {
      final Object? decoded = jsonDecode(await file.readAsString());
      if (decoded is! Map) return BridgeStatus.appNotRunning(winn: winn);
      raw = decoded.cast<String, Object?>();
    } catch (_) {
      return BridgeStatus.appNotRunning(winn: winn);
    }

    final String statusWire =
        raw['status'] is String ? raw['status']! as String : 'app_not_running';
    final BridgeTunnelStatus status = BridgeTunnelStatus.fromWire(statusWire);

    BridgeDetailCode detail = BridgeDetailCode.none;
    for (final BridgeDetailCode code in BridgeDetailCode.values) {
      if (code.wire == raw['detail']) detail = code;
    }

    BridgeWinnState winnState = winn;
    for (final BridgeWinnState value in BridgeWinnState.values) {
      if (value.wire == raw['winn']) winnState = value;
    }

    final List<BridgeNode> nodes = <BridgeNode>[];
    final Object? rawNodes = raw['nodes'];
    if (rawNodes is List) {
      for (final Object? node in rawNodes) {
        if (node is! Map) continue;
        try {
          nodes.add(BridgeNode(
            slug: '${node['slug']}',
            name: '${node['name']}',
            flag: '${node['flag']}',
          ));
        } catch (_) {
          // Rejected at construction, exactly as a hostile node list would be.
        }
      }
    }

    int boundedInt(Object? value) {
      if (value is! int || value < 0 || value > kMaxOutboundInteger) return 0;
      return value;
    }

    return BridgeStatus(
      status: status,
      detail: detail,
      winn: winnState,
      selectedSlug: raw['selectedSlug'] is String &&
              kSlugPattern.hasMatch(raw['selectedSlug']! as String)
          ? raw['selectedSlug']! as String
          : '',
      nodes: nodes,
      canRequestConnect: raw['canRequestConnect'] == true,
      // The proxy port is overlaid by the host from its bound socket --
      // `BridgeHost._snapshot` calls `copyWithProxy` -- so a value here for
      // `proxyPort` would be discarded. Only `proxyReady` survives, because only
      // the desktop app knows whether its gate would admit traffic.
      proxyPort: 0,
      proxyReady: raw['proxyReady'] == true,
      rxKib: boundedInt(raw['rxKib']),
      txKib: boundedInt(raw['txKib']),
    );
  }

  @override
  Future<BridgeStatus> requestConnect() => read();

  @override
  Future<BridgeStatus> requestDisconnect() => read();

  // The fixture cannot pair: it has no app to show a confirmation.
  @override
  void presentPairing({String? origin, String? credential}) {}

  @override
  Future<BridgePairingReply?> pairBegin() async => null;

  @override
  Future<BridgePairingReply?> pairPoll() async => null;

  @override
  Future<BridgeStatus> pairForget() => read();
}

String? _valueOf(List<String> args, String flag) {
  final int i = args.indexOf(flag);
  if (i < 0 || i + 1 >= args.length) return null;
  return args[i + 1];
}

Future<void> main(List<String> args) async {
  final String os = Platform.operatingSystem;
  final BridgeWinnState winn =
      resolveWinnState(operatingSystem: os, connected: false);

  final String? statePath = _valueOf(args, '--state-file');
  final BridgeStateSource source = statePath == null
      ? UnobservedStateSource(winn)
      : FileStateSource(File(statePath), winn);

  stderr.writeln('harness host: state=${statePath ?? "unobserved"}');

  // Explicit fixture identity for this nonshipping state-source harness only.
  const testCallerOrigin =
      'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/';
  final BridgeHost host = BridgeHost(
    stateSource: source,
    operatingSystem: os,
    allowedOrigins: const <String>{testCallerOrigin},
  );
  host.setCallerOrigin(testCallerOrigin);
  await host.run();
}
