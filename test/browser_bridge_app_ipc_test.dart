// Proof that the desktop-app IPC channel is loopback-only, authenticated,
// schema-bounded, and fail-closed. Every negative case below is a case the
// native host must treat as `app_not_running`.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/browser_bridge_app_ipc.dart';
import 'package:wins_vpn/browser_bridge_protocol.dart';

class _TunnelHarness {
  _TunnelHarness();

  BridgeTunnelStatus status = BridgeTunnelStatus.disconnected;
  bool canRequestConnect = true;
  final List<String> commands = <String>[];
  Duration commandDelay = Duration.zero;
  final commandStarted = Completer<void>();
  Future<void>? holdCommand;

  BridgeStatus snapshot() {
    return BridgeStatus(
      status: status,
      detail: BridgeDetailCode.none,
      winn: BridgeWinnState.unavailableOnThisPlatform,
      selectedSlug: status == BridgeTunnelStatus.appNotRunning ? '' : 'japan',
      nodes: status == BridgeTunnelStatus.appNotRunning
          ? const <BridgeNode>[]
          : <BridgeNode>[
              BridgeNode(slug: 'japan', name: 'Japan', flag: 'JP'),
            ],
      canRequestConnect:
          canRequestConnect && status == BridgeTunnelStatus.disconnected,
      proxyPort: 0,
      proxyReady: status.isCarryingTraffic,
    );
  }

  Future<void> onCommand(BrowserBridgeAppIpcCommand command) async {
    if (!commandStarted.isCompleted) commandStarted.complete();
    if (holdCommand != null) await holdCommand;
    if (commandDelay > Duration.zero) {
      await Future<void>.delayed(commandDelay);
    }
    commands.add(command.wire);
    switch (command) {
      case BrowserBridgeAppIpcCommand.requestConnect:
        if (!canRequestConnect) return;
        status = BridgeTunnelStatus.connected;
      case BrowserBridgeAppIpcCommand.requestDisconnect:
        status = BridgeTunnelStatus.disconnected;
      case BrowserBridgeAppIpcCommand.getStatus:
      case BrowserBridgeAppIpcCommand.pairBegin:
      case BrowserBridgeAppIpcCommand.pairPoll:
      case BrowserBridgeAppIpcCommand.pairRevoke:
        break;
    }
  }
}

// A browser this server already paired with. Controls in these tests present
// it; the pairing state machine itself is covered in
// browser_bridge_pairing_test.dart.
const String _kPairedOrigin =
    'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/';
final String _kPairedCredential = 'c' * 64;

BrowserBridgePairingRegistry _pairedRegistry() {
  final at = DateTime.utc(2026, 11, 1);
  return BrowserBridgePairingRegistry(
    knownOrigins: const <String, String>{_kPairedOrigin: 'Test Browser'},
    records: <BrowserBridgePairingRecord>[
      BrowserBridgePairingRecord(
        origin: _kPairedOrigin,
        label: 'Test Browser',
        verifier: browserBridgePairingVerifier(
          _kPairedOrigin,
          _kPairedCredential,
        ),
        createdAt: at,
        lastUsedAt: at,
      ),
    ],
  );
}

Directory _tempDir() {
  return Directory.systemTemp.createTempSync('wins_bridge_ipc_');
}

File _discoveryFile(Directory dir) => File('${dir.path}/ipc.json');

BrowserBridgeAppIpcTrust _ownerTrust() {
  return BrowserBridgeAppIpcTrust.authenticated(
    secretHex: generateBrowserBridgeAppIpcToken(),
    expectedIdentity: BrowserBridgeAppIpcProcessIdentity.currentProcess(),
  );
}

BrowserBridgeAppIpcClient _client(
  File file, {
  required BrowserBridgeAppIpcTrust trust,
  BrowserBridgeAppIpcClock? clock,
  BrowserBridgeAppIpcProcessLiveness? processAlive,
}) {
  return BrowserBridgeAppIpcClient(
    discoveryFile: file,
    trust: trust,
    clock: clock,
    processAlive: processAlive,
  );
}

Future<BrowserBridgeAppIpcServer> _startServer(
  File file,
  _TunnelHarness harness, {
  BrowserBridgeAppIpcClock? clock,
  BrowserBridgeAppIpcTrust? trust,
}) async {
  final server = BrowserBridgeAppIpcServer(
    discoveryFile: file,
    snapshot: harness.snapshot,
    onCommand: harness.onCommand,
    pairing: _pairedRegistry(),
    clock: clock,
    trust: trust ?? _ownerTrust(),
  );
  await server.start();
  addTearDown(() async {
    await server.stop();
    final dir = file.parent;
    if (dir.existsSync()) {
      try {
        dir.deleteSync(recursive: true);
      } catch (_) {}
    }
  });
  return server;
}

Future<void> _writeRawDiscovery(
  File file,
  Map<String, Object?> body, {
  String mode = '600',
}) async {
  await file.parent.create(recursive: true);
  await file.writeAsString(jsonEncode(body), flush: true);
  if (!Platform.isWindows) {
    final chmod = Process.runSync('chmod', <String>[mode, file.path]);
    expect(chmod.exitCode, 0);
  }
}

Map<String, Object?> _validDiscovery({
  required String token,
  required int port,
  int? pid,
  int? writtenAt,
  String host = kBrowserBridgeAppIpcLoopbackHost,
  BrowserBridgeAppIpcTrust? trust,
}) {
  final resolvedPid = pid ?? pidFromIo;
  final resolvedWritten = writtenAt ??
      (DateTime.now().toUtc().millisecondsSinceEpoch / 1000).floor();
  final mac = trust == null
      ? 'ab' * 32
      : browserBridgeAppIpcDiscoveryMac(
          trust: trust,
          host: host,
          port: port,
          token: token,
          pid: resolvedPid,
          writtenAt: resolvedWritten,
        );
  return <String, Object?>{
    'v': kBrowserBridgeAppIpcVersion,
    'host': host,
    'port': port,
    'token': token,
    'pid': resolvedPid,
    'written_at': resolvedWritten,
    'mac': mac,
  };
}

int get pidFromIo => pid;

class _FakeLoopbackApp {
  _FakeLoopbackApp({
    required this.port,
    required this.token,
    required this.close,
    this.ownerPid,
  });

  final int port;
  final String token;
  final int? ownerPid;
  final Future<void> Function() close;
}

Future<_FakeLoopbackApp> _startFakeLoopbackApp() async {
  final token = generateBrowserBridgeAppIpcToken();
  final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  listener.listen((Socket socket) async {
    try {
      socket.add(
        encodeBrowserBridgeAppIpcFrame(<String, Object?>{
          'v': kBrowserBridgeAppIpcVersion,
          'id': 'ignored',
          'ok': true,
          'type': 'get_status',
          'status': BridgeStatus(
            status: BridgeTunnelStatus.connected,
            detail: BridgeDetailCode.none,
            winn: BridgeWinnState.unavailableOnThisPlatform,
            selectedSlug: 'japan',
            nodes: <BridgeNode>[
              BridgeNode(slug: 'japan', name: 'Japan', flag: 'JP'),
            ],
            canRequestConnect: false,
            proxyPort: 1,
            proxyReady: true,
          ).toWire(),
        }),
      );
      await socket.flush();
    } catch (_) {
    } finally {
      try {
        await socket.close();
      } catch (_) {
        socket.destroy();
      }
    }
  });
  return _FakeLoopbackApp(
    port: listener.port,
    token: token,
    ownerPid: pid,
    close: listener.close,
  );
}

Future<_FakeLoopbackApp> _startForeignLoopback() async {
  final process = await Process.start(
    'python3',
    <String>[
      '-c',
      'import os,socket,sys,time\n'
          's=socket.socket(); s.bind(("127.0.0.1",0)); '
          'print(s.getsockname()[1]); print(os.getpid()); sys.stdout.flush(); '
          's.listen(1); time.sleep(30)\n',
    ],
  );
  final lines = await process.stdout
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .where((String line) => line.trim().isNotEmpty)
      .take(2)
      .toList()
      .timeout(const Duration(seconds: 8));
  final port = int.parse(lines[0].trim());
  final ownerPid = int.parse(lines[1].trim());
  return _FakeLoopbackApp(
    port: port,
    token: generateBrowserBridgeAppIpcToken(),
    ownerPid: ownerPid,
    close: () async {
      process.kill();
      await process.exitCode;
    },
  );
}

/// One loopback listener held by two processes: a parent and the child it
/// forked after `listen`. Returns the port and both pids.
Future<({int port, int parent, int child, Future<void> Function() close})>
    _startSharedLoopback() async {
  final process = await Process.start(
    'python3',
    <String>[
      '-c',
      'import os,socket,sys,time\n'
          's=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(1)\n'
          'child=os.fork()\n'
          'if child==0:\n'
          '    time.sleep(30); os._exit(0)\n'
          'print(s.getsockname()[1]); print(os.getpid()); print(child)\n'
          'sys.stdout.flush(); time.sleep(30)\n',
    ],
  );
  final lines = await process.stdout
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .where((String line) => line.trim().isNotEmpty)
      .take(3)
      .toList()
      .timeout(const Duration(seconds: 8));
  final child = int.parse(lines[2].trim());
  return (
    port: int.parse(lines[0].trim()),
    parent: int.parse(lines[1].trim()),
    child: child,
    close: () async {
      Process.killPid(child);
      process.kill();
      await process.exitCode;
    },
  );
}

void main() {
  test('desktop platforms only; Windows does not claim POSIX ownership', () {
    expect(browserBridgeAppIpcSupportedOn('macos'), isTrue);
    expect(browserBridgeAppIpcSupportedOn('linux'), isTrue);
    expect(browserBridgeAppIpcSupportedOn('windows'), isTrue);
    expect(browserBridgeAppIpcSupportedOn('android'), isFalse);
    expect(browserBridgeAppIpcSupportedOn('ios'), isFalse);
    expect(browserBridgeAppIpcUsesPosixOwnership('macos'), isTrue);
    expect(browserBridgeAppIpcUsesPosixOwnership('linux'), isTrue);
    expect(browserBridgeAppIpcUsesPosixOwnership('windows'), isFalse);
    final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
    expect(source, contains('Windows: FileStat.mode is not a POSIX'));
    expect(source, isNot(contains('Windows process liveness is kill -0')));
    expect(
      source,
      contains('Windows process liveness is not `kill -0`'),
    );
    expect(source, contains('The discovery file is not a trust root'));
    expect(source, contains('unauthenticatedIdentity'));
    expect(source, contains('5YT8H4U72M'));
    expect(source, contains('/opt/wins-vpn/wins_vpn'));
    expect(source, contains('wins_vpn.exe'));
    expect(source, contains('certificate leaf[subject.OU]'));
    expect(source, isNot(contains('--pid=')));
    final signatureStart = source.indexOf(
      'BrowserBridgeAppIpcMacosCodeSignature? _macosCodeSignatureForPid(',
    );
    expect(signatureStart, greaterThanOrEqualTo(0));
    final signatureEnd = source.indexOf('on ProcessException', signatureStart);
    expect(signatureEnd, greaterThan(signatureStart));
    final signatureBody = source.substring(signatureStart, signatureEnd);

    expect(signatureBody, contains("'--verify'"));
    expect(
      signatureBody,
      contains("'-R=anchor apple generic and identifier '"),
    );
    expect(signatureBody, contains('leaf[subject.OU] ='));
    expect(signatureBody, contains("'\$advertisedPid'"));
    expect(source, contains("<String>['-dv', '\$advertisedPid']"));
    expect(source, contains("<String>['-d', '-r-', '\$advertisedPid']"));
    expect(source, contains('WINS_IPC_WINACL_V1'));
    expect(source, contains('CURRENT_USER_SID='));
    expect(source, contains('parseBrowserBridgeAppIpcWindowsAclProbe'));
    expect(source, contains('_assertWindowsOwnerInstalledReceipt'));
    expect(source, contains('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'));
    expect(
      source,
      contains('kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject = null'),
    );
    expect(source, contains('Do not invent a thumbprint or subject.'));
    expect(source, isNot(contains('icacls')));
    expect(source, isNot(contains('_platformSecretHex')));
    expect(source, isNot(contains('return BrowserBridgeAppIpcTrust.platform')));
    expect(source, isNot(contains("startsWith(prefix)")));
    expect(source, isNot(contains("lower.contains('/program files/')")));
    expect(source, isNot(contains('0.0.0.0')));
    final host = File('tools/native_messaging/host/bin/wins_bridge_host.dart')
        .readAsStringSync();
    expect(host, contains('browserBridgeAppIpcMayIssueProxyCredential'));
    expect(host, contains('AppIpcStateSource(winn: winn)'));
    expect(host, isNot(contains('FileStateSource')));
  });

  test('tokens are 256-bit hex and compared in constant-time shape', () {
    final tokens = List<String>.generate(
      40,
      (_) => generateBrowserBridgeAppIpcToken(),
    );
    expect(tokens.toSet().length, 40);
    expect(tokens.first, hasLength(64));
    expect(isBrowserBridgeAppIpcTokenShape(tokens.first), isTrue);
    expect(
      browserBridgeAppIpcConstantTimeEquals(tokens.first, tokens.first),
      isTrue,
    );
    expect(
      browserBridgeAppIpcConstantTimeEquals(tokens.first, tokens.last),
      isFalse,
    );
    expect(
      browserBridgeAppIpcConstantTimeEquals(tokens.first, ''),
      isFalse,
    );
    expect(
      browserBridgeAppIpcConstantTimeEquals(
        tokens.first,
        tokens.first.substring(0, 63),
      ),
      isFalse,
    );
  });

  test('default discovery path stays under the user data dir', () {
    final macos = defaultBrowserBridgeAppIpcDiscoveryFile(
      operatingSystem: 'macos',
      environment: const <String, String>{'HOME': '/Users/wins'},
      macosAppGroupContainer: (String id) =>
          '/Users/wins/Library/Group Containers/$id',
    );
    expect(
      macos.path,
      '/Users/wins/Library/Group Containers/'
      '5YT8H4U72M.group.org.winsvpn.app/browser_bridge/ipc.json',
    );
    final windows = defaultBrowserBridgeAppIpcDiscoveryFile(
      operatingSystem: 'windows',
      environment: const <String, String>{
        'APPDATA': r'C:\Users\wins\AppData\Roaming'
      },
    );
    expect(
      windows.path.replaceAll('\\', '/'),
      contains('wins_vpn/browser_bridge/ipc.json'),
    );
    final linux = defaultBrowserBridgeAppIpcDiscoveryFile(
      operatingSystem: 'linux',
      environment: const <String, String>{'HOME': '/home/wins'},
    );
    expect(
      linux.path,
      '/home/wins/.local/share/wins_vpn/browser_bridge/ipc.json',
    );
  });

  test('macOS discovery comes only from the FileManager App Group path', () {
    final List<String> asked = <String>[];
    final File file = defaultBrowserBridgeAppIpcDiscoveryFile(
      operatingSystem: 'macos',
      environment: const <String, String>{
        'HOME': '/Users/wins/Library/Containers/org.winsvpn.app/Data',
      },
      macosAppGroupContainer: (String id) {
        asked.add(id);
        return '/Users/wins/Library/Group Containers/$id';
      },
    );
    expect(asked, <String>['5YT8H4U72M.group.org.winsvpn.app']);
    expect(file.path, contains('/Library/Group Containers/'));
    expect(file.path, isNot(contains('/Library/Containers/')));
    for (final String? bad in <String?>[null, '', '   ', 'relative/path']) {
      expect(
        () => defaultBrowserBridgeAppIpcDiscoveryFile(
          operatingSystem: 'macos',
          environment: const <String, String>{'HOME': '/Users/wins'},
          macosAppGroupContainer: (String _) => bad,
        ),
        throwsA(isA<BrowserBridgeAppIpcException>()),
      );
    }
  });

  group('live loopback channel', () {
    test('binds 127.0.0.1, publishes 0600 discovery, answers status', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final harness = _TunnelHarness();
      final server = await _startServer(file, harness);

      expect(server.isRunning, isTrue);
      expect(server.port, greaterThan(0));
      expect(FileSystemEntity.isLinkSync(file.path), isFalse);
      if (!Platform.isWindows) {
        expect(file.statSync().mode & 0x1FF, 0x180);
      }
      final endpoint = readBrowserBridgeAppIpcDiscovery(
        file,
        trust: server.trustForTest!,
      );
      expect(endpoint.host, kBrowserBridgeAppIpcLoopbackHost);
      expect(endpoint.port, server.port);
      expect(endpoint.token, server.tokenForTest);

      final client = _client(file, trust: server.trustForTest!);
      final status = await client.getStatus(
        origin: _kPairedOrigin,
        credential: _kPairedCredential,
      );
      expect(status.status, BridgeTunnelStatus.disconnected);
      expect(status.canRequestConnect, isTrue);
      expect(status.pairing, BridgePairingStatus.paired);
      expect(status.selectedSlug, 'japan');
      expect(status.proxyReady, isFalse);

      // The same app, asked without the pairing: status only.
      final unpaired = await client.getStatus();
      expect(unpaired.status, BridgeTunnelStatus.disconnected);
      expect(unpaired.canRequestConnect, isFalse);
      expect(unpaired.pairing, BridgePairingStatus.unpaired);
    });

    test('is not reachable on this machine\'s LAN address', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final server = await _startServer(file, _TunnelHarness());
      final interfaces = await NetworkInterface.list(
        includeLoopback: false,
        type: InternetAddressType.IPv4,
      );
      final lan = interfaces.expand((i) => i.addresses).toList();
      if (lan.isEmpty) {
        markTestSkipped('no non-loopback IPv4 interface to test against');
        return;
      }
      for (final address in lan) {
        await expectLater(
          Socket.connect(
            address,
            server.port,
            timeout: const Duration(seconds: 2),
          ),
          throwsA(isA<SocketException>()),
          reason: 'IPC answered on ${address.address}',
        );
      }
    });

    test('concurrent controls are refused instead of queued', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final release = Completer<void>();
      final harness = _TunnelHarness()..holdCommand = release.future;
      final server = await _startServer(file, harness);
      final client = _client(file, trust: server.trustForTest!);
      final first = client.requestConnect(
        requestId: 'connect-1',
        origin: _kPairedOrigin,
        credential: _kPairedCredential,
      );
      await harness.commandStarted.future;
      await expectLater(
        client.requestDisconnect(
          requestId: 'disconnect-1',
          origin: _kPairedOrigin,
          credential: _kPairedCredential,
        ),
        throwsA(isA<BrowserBridgeAppIpcException>().having(
          (error) => error.code, 'code',
          BrowserBridgeAppIpcError.busy)),
      );
      release.complete();
      final connected = await first;
      expect(connected.status, BridgeTunnelStatus.connected);
      expect(connected.proxyReady, isTrue);
      expect(harness.commands, <String>['request_connect']);
    });

    test('stop during listener bind leaves no listener or discovery', () async {
      final dir = _tempDir();
      addTearDown(() {
        if (dir.existsSync()) dir.deleteSync(recursive: true);
      });
      final file = _discoveryFile(dir);
      final harness = _TunnelHarness();
      final server = BrowserBridgeAppIpcServer(
        discoveryFile: file,
        snapshot: harness.snapshot,
        onCommand: harness.onCommand,
        trust: _ownerTrust(),
      );

      final starting = server.start();
      await server.stop();
      await starting;

      expect(server.isRunning, isFalse);
      expect(server.port, 0);
      expect(server.tokenForTest, isNull);
      expect(file.existsSync(), isFalse);
    });

    test('shutdown removes discovery and closes the listener', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final server = await _startServer(file, _TunnelHarness());
      final port = server.port;
      final trust = server.trustForTest!;
      await server.stop();
      expect(file.existsSync(), isFalse);
      await expectLater(
        Socket.connect(
          InternetAddress.loopbackIPv4,
          port,
          timeout: const Duration(seconds: 2),
        ),
        throwsA(isA<SocketException>()),
      );
      expect(
        await _client(file, trust: trust).invokeFailClosed(
          command: BrowserBridgeAppIpcCommand.getStatus,
          winn: BridgeWinnState.unavailableOnThisPlatform,
        ),
        isA<BridgeStatus>().having(
          (s) => s.status,
          'status',
          BridgeTunnelStatus.appNotRunning,
        ),
      );
    });

    test('exceptions and logs never carry the token', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final server = await _startServer(file, _TunnelHarness());
      final token = server.tokenForTest!;
      final trust = server.trustForTest!;
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: 'ab' * 32,
          port: server.port,
          trust: trust,
        ),
      );
      try {
        await _client(file, trust: trust).getStatus();
        fail('tampered token must be refused');
      } on BrowserBridgeAppIpcException catch (error) {
        expect(error.code, BrowserBridgeAppIpcError.tokenMismatch);
        expect(error.toString(), isNot(contains(token)));
        expect(error.toString(), isNot(contains('ab' * 32)));
      }
    });
  });

  group('negative cases fail closed', () {
    test('tampered token is refused', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final server = await _startServer(file, _TunnelHarness());
      final original = server.tokenForTest!;
      final trust = server.trustForTest!;
      final tampered = original.startsWith('aa') ? 'bb' * 32 : 'aa' * 32;
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: tampered,
          port: server.port,
          trust: trust,
        ),
      );
      expect(
        () => _client(file, trust: trust).getStatus(),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.tokenMismatch,
          ),
        ),
      );
      expect(
        await _client(file, trust: trust).invokeFailClosed(
          command: BrowserBridgeAppIpcCommand.getStatus,
          winn: BridgeWinnState.unavailableOnThisPlatform,
        ),
        isA<BridgeStatus>().having(
          (s) => s.status,
          'status',
          BridgeTunnelStatus.appNotRunning,
        ),
      );
    });

    test('non-loopback endpoint is refused without connecting off-loopback',
        () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final trust = _ownerTrust();
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 9,
          host: '8.8.8.8',
          trust: trust,
        ),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(file, trust: trust),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.nonLoopback,
          ),
        ),
      );
      expect(
        () => _client(file, trust: trust).getStatus(),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.nonLoopback,
          ),
        ),
      );
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 9,
          host: 'localhost',
          trust: trust,
        ),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(file, trust: trust),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.nonLoopback,
          ),
        ),
      );
    });

    test('stale discovery file is refused', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final now = DateTime.now().toUtc();
      final trust = _ownerTrust();
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 41234,
          writtenAt: (now.millisecondsSinceEpoch / 1000).floor() - 180,
          trust: trust,
        ),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: trust,
          clock: () => now,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.stale,
          ),
        ),
      );
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 41234,
          writtenAt: (now.millisecondsSinceEpoch / 1000).floor(),
          trust: trust,
        ),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: trust,
          clock: () => now,
          processAlive: (_) => false,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.stale,
          ),
        ),
      );
    });

    test('symlink discovery is refused', () async {
      if (Platform.isWindows) {
        // Creating a symlink on Windows may require a privilege this test
        // process does not have. The reader still uses isLinkSync.
        return;
      }
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final trust = _ownerTrust();
      final real = File('${dir.path}/real.json');
      await _writeRawDiscovery(
        real,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 41234,
          trust: trust,
        ),
      );
      final link = Link('${dir.path}/ipc.json');
      await link.create(real.path);
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          File(link.path),
          trust: trust,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.symlink,
          ),
        ),
      );
      final server = BrowserBridgeAppIpcServer(
        discoveryFile: File(link.path),
        snapshot: _TunnelHarness().snapshot,
        onCommand: _TunnelHarness().onCommand,
        trust: trust,
      );
      await expectLater(
        server.start(),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.symlink,
          ),
        ),
      );
    });

    test('oversized discovery and oversized IPC frame are refused', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      await file.parent.create(recursive: true);
      await file.writeAsBytes(
        List<int>.filled(kMaxBrowserBridgeAppIpcDiscoveryBytes + 8, 0x61),
        flush: true,
      );
      if (!Platform.isWindows) {
        Process.runSync('chmod', <String>['600', file.path]);
      }
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: _ownerTrust(),
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.oversized,
          ),
        ),
      );

      final harness = _TunnelHarness();
      final live =
          _discoveryFile(Directory.systemTemp.createTempSync('ipc_os_'));
      final server = await _startServer(live, harness);
      final socket = await Socket.connect(
        InternetAddress.loopbackIPv4,
        server.port,
      );
      final huge = Uint8List(8);
      ByteData.sublistView(huge)
          .setUint32(0, kMaxBrowserBridgeAppIpcFrameBytes + 1, Endian.little);
      socket.add(huge);
      await socket.flush();
      var reply = <int>[];
      try {
        reply = await socket.fold<List<int>>(
          <int>[],
          (List<int> acc, List<int> chunk) => acc..addAll(chunk),
        ).timeout(const Duration(seconds: 3), onTimeout: () => <int>[]);
      } catch (_) {
        reply = <int>[];
      }
      expect(reply, isEmpty, reason: 'oversized frame must not be answered');
      socket.destroy();
    });

    test('duplicate request id is refused as replay', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final server = await _startServer(file, _TunnelHarness());
      final client = _client(file, trust: server.trustForTest!);
      final first = await client.getStatus(requestId: 'same-id-1');
      expect(first.status, BridgeTunnelStatus.disconnected);
      expect(
        () => client.getStatus(requestId: 'same-id-1'),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.duplicateRequestId,
          ),
        ),
      );
    });

    test('app absent is fail-closed app_not_running', () async {
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final file = _discoveryFile(dir);
      final trust = _ownerTrust();
      expect(
        () => _client(file, trust: trust).getStatus(),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.missingDiscovery,
          ),
        ),
      );
      final absent = await _client(file, trust: trust).invokeFailClosed(
        command: BrowserBridgeAppIpcCommand.requestConnect,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      );
      expect(absent.status, BridgeTunnelStatus.appNotRunning);
      expect(absent.canRequestConnect, isFalse);
      expect(absent.proxyReady, isFalse);
    });

    test('group-readable discovery is unsafe permissions on POSIX', () async {
      if (Platform.isWindows) {
        return;
      }
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final file = _discoveryFile(dir);
      final trust = _ownerTrust();
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 41234,
          trust: trust,
        ),
        mode: '644',
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: trust,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unsafePermissions,
          ),
        ),
      );
    });

    test(
        'extra discovery fields and localhost aliases are malformed/non-loopback',
        () async {
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final file = _discoveryFile(dir);
      final trust = _ownerTrust();
      final extra = _validDiscovery(
        token: generateBrowserBridgeAppIpcToken(),
        port: 41234,
        trust: trust,
      )..['extra'] = 'nope';
      await _writeRawDiscovery(file, extra);
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: trust,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.malformed,
          ),
        ),
      );
    });
  });

  test(
      'connect is refused by the app still returns explicit status, not absent',
      () async {
    final dir = _tempDir();
    final file = _discoveryFile(dir);
    final harness = _TunnelHarness()..canRequestConnect = false;
    final server = await _startServer(file, harness);
    final status = await _client(file, trust: server.trustForTest!)
        .requestConnect(
      requestId: 'locked-1',
      origin: _kPairedOrigin,
      credential: _kPairedCredential,
    );
    expect(status.status, BridgeTunnelStatus.disconnected);
    expect(status.canRequestConnect, isFalse);
    expect(harness.commands, <String>['request_connect']);
  });

  group('same-UID impersonation fails closed', () {
    test('default trust path is not the discovery file', () {
      final discovery = defaultBrowserBridgeAppIpcDiscoveryFile(
        operatingSystem: 'macos',
        environment: const <String, String>{'HOME': '/Users/wins'},
        macosAppGroupContainer: (String id) =>
            '/Users/wins/Library/Group Containers/$id',
      );
      final trust = defaultBrowserBridgeAppIpcTrustFile(
        operatingSystem: 'macos',
        environment: const <String, String>{'HOME': '/Users/wins'},
      );
      expect(
        trust.path,
        '/Library/Application Support/wins_vpn/browser_bridge.identity',
      );
      expect(trust.path, isNot(discovery.path));
      expect(trust.path, isNot(contains('browser_bridge/ipc.json')));
      final linux = defaultBrowserBridgeAppIpcTrustFile(
        operatingSystem: 'linux',
        environment: const <String, String>{'HOME': '/home/wins'},
      );
      expect(linux.path, '/usr/lib/wins-vpn/browser_bridge.identity');
      final windowsTrust = defaultBrowserBridgeAppIpcTrustFile(
        operatingSystem: 'windows',
        environment: const <String, String>{
          'PROGRAMDATA': r'C:\ProgramData',
        },
      );
      expect(
        windowsTrust.path.replaceAll('\\', '/').toLowerCase(),
        'c:/programdata/wins_vpn/browser_bridge.identity',
      );
      expect(
        browserBridgeAppIpcWindowsCanonicalTrustPath(r'C:\ProgramData'),
        r'C:\ProgramData\wins_vpn\browser_bridge.identity',
      );
    });

    test('discovery cannot supply its own trust root or secret', () async {
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final file = _discoveryFile(dir);
      final owner = _ownerTrust();
      final attackerSecret = generateBrowserBridgeAppIpcToken();
      final body = _validDiscovery(
        token: generateBrowserBridgeAppIpcToken(),
        port: 41234,
        trust: BrowserBridgeAppIpcTrust.authenticated(
          secretHex: attackerSecret,
        ),
      )
        ..['secret'] = attackerSecret
        ..['identity'] = 'current_process'
        ..['trust'] = attackerSecret;
      await _writeRawDiscovery(file, body);
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: owner,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
    });

    test('same-UID chmod 0444 trust file is not owner issuance', () async {
      if (Platform.isWindows) {
        return;
      }
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final file = File('${dir.path}/browser_bridge.identity');
      await file.writeAsString(
        jsonEncode(<String, Object?>{
          'v': kBrowserBridgeAppIpcVersion,
          'secret': generateBrowserBridgeAppIpcToken(),
        }),
        flush: true,
      );
      Process.runSync('chmod', <String>['0444', file.path]);
      expect(file.statSync().mode & 0x1FF, 0x124);
      expect(
        () => readBrowserBridgeAppIpcTrustFile(file),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
    });

    test(
        'fake discovery and fake loopback cannot claim CONNECTED or proxyReady',
        () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final owner = _ownerTrust();
      final fake = await _startFakeLoopbackApp();
      addTearDown(() async {
        await fake.close();
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: fake.token,
          port: fake.port,
          trust: BrowserBridgeAppIpcTrust.authenticated(
            secretHex: generateBrowserBridgeAppIpcToken(),
          ),
        )..['secret'] = generateBrowserBridgeAppIpcToken(),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: owner,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
      final closed = await _client(file, trust: owner).invokeFailClosed(
        command: BrowserBridgeAppIpcCommand.getStatus,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      );
      expect(closed.status, BridgeTunnelStatus.appNotRunning);
      expect(closed.proxyReady, isFalse);
      expect(
        browserBridgeAppIpcMayIssueProxyCredential(closed),
        isFalse,
      );
    });

    test(
        'stolen owner secret still cannot bind a fake loopback port to the app pid',
        () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final owner = _ownerTrust();
      final fake = await _startForeignLoopback();
      addTearDown(() async {
        await fake.close();
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      expect(fake.ownerPid, isNot(pidFromIo));
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: fake.token,
          port: fake.port,
          pid: pidFromIo,
          trust: owner,
        ),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: owner,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.portOwnerMismatch,
          ),
        ),
      );
    });

    // The refusal above also passes for a lookup that never finds anyone, as
    // the Linux /proc scan did until it listed descriptors without following
    // them. These name the owner positively, on the two POSIX lookups.
    final posixLookup = Platform.isLinux || Platform.isMacOS
        ? false
        : 'the lsof and /proc lookups are macOS and Linux only';

    test('the port owner lookup names the one listening process', () async {
      final own = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final fake = await _startForeignLoopback();
      addTearDown(() async {
        await own.close();
        await fake.close();
      });
      expect(fake.ownerPid, isNot(pidFromIo));
      expect(browserBridgeAppIpcListeningPid(own.port), pidFromIo);
      expect(browserBridgeAppIpcListeningPid(fake.port), fake.ownerPid);
    }, skip: posixLookup);

    test('a listener held by two processes has no owner', () async {
      final shared = await _startSharedLoopback();
      addTearDown(shared.close);
      expect(shared.child, isNot(shared.parent));
      expect(browserBridgeAppIpcListeningPid(shared.port), isNull);
    }, skip: posixLookup);

    test('the macOS port owner lookup runs lsof by absolute path', () {
      // A PATH without /usr/sbin, or with another lsof ahead of it, must not
      // decide which process owns the bridge port.
      final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
      final start = source.indexOf(
        'int? browserBridgeAppIpcListeningPid(int port) {',
      );
      expect(start, greaterThanOrEqualTo(0));
      final end = source.indexOf('if (Platform.isLinux) {', start);
      expect(end, greaterThan(start));
      final lookup = source.substring(start, end);
      expect(lookup, contains("Process.runSync('/usr/sbin/lsof', <String>["));
      expect(lookup, isNot(contains("Process.runSync('lsof'")));
    });

    test('the POSIX owner, identity and process helpers run by absolute path', () {
      // R23 F-W1-04: a planted stat or id ahead on PATH let a user-written
      // trust file pass as owner-installed, and GNU stat (which reads -f as
      // --file-system) turned every bound-read identity into null.
      final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
      // R24 F-R24-04: the call may wrap, so the executable can sit on the
      // next line ('ps' did, and slipped past a plain substring check).
      for (final bare in <String>[
        "'stat'",
        "'id'",
        "'chmod'",
        "'kill'",
        "'lsof'",
        "'ps'",
      ]) {
        expect(
          RegExp('Process\\.runSync\\(\\s*$bare').hasMatch(source),
          isFalse,
          reason: 'bare $bare on PATH',
        );
      }
      expect(source, contains("'/bin/ps',"));
      expect("Process.runSync('/usr/bin/stat', args)".allMatches(source).length, 3);
      expect(source, contains("Process.runSync('/usr/bin/id', <String>['-u'])"));
      expect(source, contains("Process.runSync('/bin/chmod', <String>[mode, path])"));
      expect(source, contains("Process.runSync('/bin/kill', <String>['-0', '\$pid'])"));
    });

    test('a bound read refuses when a POSIX identity cannot be read', () {
      final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
      final start = source.indexOf('_BoundFileBytes _bindRegularFileBytes(');
      expect(start, greaterThanOrEqualTo(0));
      final end = source.indexOf('class _PosixFileIdentity', start);
      expect(end, greaterThan(start));
      final body = source.substring(start, end);
      final refusal = body.indexOf(
        'browserBridgeAppIpcUsesPosixOwnership(operatingSystem) &&\n'
        '      (before == null || after == null)',
      );
      expect(refusal, greaterThanOrEqualTo(0));
      expect(refusal, lessThan(body.indexOf('return _BoundFileBytes(')));
    });

    test('rename/substitution of a live discovery file is refused', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final harness = _TunnelHarness()..status = BridgeTunnelStatus.connected;
      final server = await _startServer(file, harness);
      final owner = server.trustForTest!;
      final live = await _client(file, trust: owner).getStatus();
      expect(live.status, BridgeTunnelStatus.connected);
      expect(live.proxyReady, isTrue);

      final backup = File('${file.path}.real');
      await file.rename(backup.path);
      final fake = await _startFakeLoopbackApp();
      addTearDown(fake.close);
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: fake.token,
          port: fake.port,
          trust: BrowserBridgeAppIpcTrust.authenticated(
            secretHex: generateBrowserBridgeAppIpcToken(),
          ),
        ),
      );
      expect(
        () => _client(file, trust: owner).getStatus(),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
      final closed = await _client(file, trust: owner).invokeFailClosed(
        command: BrowserBridgeAppIpcCommand.getStatus,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      );
      expect(closed.status, BridgeTunnelStatus.appNotRunning);
    });

    test('stale leftover discovery is not CONNECTED', () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final owner = _ownerTrust();
      final now = DateTime.now().toUtc();
      await _writeRawDiscovery(
        file,
        _validDiscovery(
          token: generateBrowserBridgeAppIpcToken(),
          port: 41234,
          writtenAt: (now.millisecondsSinceEpoch / 1000).floor() - 180,
          trust: owner,
        ),
      );
      expect(
        () => readBrowserBridgeAppIpcDiscovery(
          file,
          trust: owner,
          clock: () => now,
          processAlive: (_) => true,
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.stale,
          ),
        ),
      );
      final closed = await _client(file, trust: owner).invokeFailClosed(
        command: BrowserBridgeAppIpcCommand.getStatus,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      );
      expect(closed.status, BridgeTunnelStatus.appNotRunning);
      expect(browserBridgeAppIpcMayIssueProxyCredential(closed), isFalse);
    });

    test('positive current-app status requires authenticated identity',
        () async {
      final dir = _tempDir();
      final file = _discoveryFile(dir);
      final harness = _TunnelHarness()..status = BridgeTunnelStatus.connected;
      final server = await _startServer(file, harness);
      final owner = server.trustForTest!;
      final endpoint = readBrowserBridgeAppIpcDiscovery(file, trust: owner);
      expect(endpoint.pid, pidFromIo);
      expect(endpoint.port, server.port);
      final status = await _client(file, trust: owner).getStatus();
      expect(status.status, BridgeTunnelStatus.connected);
      expect(status.proxyReady, isTrue);
      expect(browserBridgeAppIpcMayIssueProxyCredential(status), isTrue);
      expect(
        browserBridgeAppIpcAdmitStatus(
          status,
          authenticatedAppIdentity: false,
          winn: BridgeWinnState.unavailableOnThisPlatform,
        ).status,
        BridgeTunnelStatus.appNotRunning,
      );
    });

    test('CONNECTED without proxyReady is not admitted as real VPN state', () {
      final connected = BridgeStatus(
        status: BridgeTunnelStatus.connected,
        detail: BridgeDetailCode.none,
        winn: BridgeWinnState.unavailableOnThisPlatform,
        selectedSlug: 'japan',
        nodes: <BridgeNode>[
          BridgeNode(slug: 'japan', name: 'Japan', flag: 'JP'),
        ],
        canRequestConnect: false,
        proxyPort: 0,
        proxyReady: false,
      );
      final admitted = browserBridgeAppIpcAdmitStatus(
        connected,
        authenticatedAppIdentity: true,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      );
      expect(admitted.status, BridgeTunnelStatus.appNotRunning);
      expect(browserBridgeAppIpcMayIssueProxyCredential(admitted), isFalse);
    });

    test('missing owner integrity root fails closed without a public MAC', () {
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final missing = File('${dir.path}/browser_bridge.identity');
      expect(
        () => loadBrowserBridgeAppIpcTrust(
          file: missing,
          operatingSystem: 'macos',
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
      expect(
        () => BrowserBridgeAppIpcTrust.platform(operatingSystem: 'macos'),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
      expect(
        () => BrowserBridgeAppIpcTrust.platform(operatingSystem: 'windows'),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
      expect(
        () => BrowserBridgeAppIpcTrust.platform(operatingSystem: 'linux'),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
    });
  });

  group('Windows ProgramData owner-receipt integrity', () {
    test('custom-group Modify cannot authenticate an owner receipt', () {
      final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(
          leafExtraAce: 'S-1-5-21-111-222-333-513|A|$_kWindowsModify|0|0',
        ),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: snapshot,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.unsafePermissions,
      );
    });

    test('source contract pins probe syntax and owner-blocked Authenticode', () {
      final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
      expect(source, isNot(contains('--pid=')));
      final signatureStart = source.indexOf(
        'BrowserBridgeAppIpcMacosCodeSignature? _macosCodeSignatureForPid(',
      );
      expect(signatureStart, greaterThanOrEqualTo(0));
      final signatureEnd = source.indexOf('on ProcessException', signatureStart);
      expect(signatureEnd, greaterThan(signatureStart));
      final signatureBody = source.substring(signatureStart, signatureEnd);

      expect(signatureBody, contains("'--verify'"));
      expect(
        signatureBody,
        contains("'-R=anchor apple generic and identifier '"),
      );
      expect(signatureBody, contains('leaf[subject.OU] ='));
      expect(signatureBody, contains("'\$advertisedPid'"));
      expect(source, contains('WINS_IPC_WINACL_V1'));
      expect(source, contains("Write-Output 'NODE'"));
      expect(source, contains('GetOwner([Security.Principal.SecurityIdentifier])'));
      expect(source, contains('GetAccessRules(\$true, \$true,'));
      expect(source, contains('WINS_IPC_TRUST_PATH'));
      expect(source, isNot(contains('icacls')));
      expect(kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject, isNull);
      expect(
        browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
          observedPath: r'C:\Program Files\WinsVPN\wins_vpn.exe',
          programFiles: r'C:\Program Files',
          authenticode: const BrowserBridgeAppIpcWindowsAuthenticode(
            status: 'Valid',
            subject: 'CN=Must-Not-Invent-A-Subject',
          ),
          reviewedSubject: kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject,
        ),
        isFalse,
      );
    });

    test('parser and evaluator: exact safe ACL is owner issuance', () {
      final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(),
      );
      expect(
        browserBridgeAppIpcWindowsOwnerReceiptSafe(
          snapshot: snapshot,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        isTrue,
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: snapshot,
          expectedCanonicalPath: r'C:\Users\wins\browser_bridge.identity',
        ),
        BrowserBridgeAppIpcError.unauthenticatedIdentity,
      );
    });

    test('parser and evaluator: writable user ACE is refused', () {
      final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(
          leafExtraAce:
              '$_kWindowsCurrentUserSid|A|$_kWindowsWrite|0|0',
        ),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: snapshot,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.unsafePermissions,
      );
    });

    test('parser and evaluator: inherited Users Modify is refused', () {
      final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(
          leafExtraAce:
              '$kBrowserBridgeAppIpcWindowsSidBuiltinUsers|A|$_kWindowsModify|1|0',
        ),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: snapshot,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.unsafePermissions,
      );
    });

    test('parser and evaluator: junction is refused', () {
      final leaf = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(leafReparse: '1'),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: leaf,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.symlink,
      );
      final parent = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(parentReparse: '1'),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: parent,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.symlink,
      );
    });

    test('parser and evaluator: wrong owner is refused', () {
      final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(leafOwner: _kWindowsCurrentUserSid),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: snapshot,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.unsafeOwnership,
      );
    });

    test('parser and evaluator: malformed and duplicate output is refused', () {
      void expectMalformed(String stdout) {
        expect(
          () => parseBrowserBridgeAppIpcWindowsAclProbe(stdout),
          throwsA(
            isA<BrowserBridgeAppIpcException>().having(
              (e) => e.code,
              'code',
              BrowserBridgeAppIpcError.malformed,
            ),
          ),
        );
      }

      final safe = _windowsAclProbe();
      expectMalformed(safe.replaceFirst('WINS_IPC_WINACL_V1', 'WINS_IPC_WINACL_V2'));
      expectMalformed(
        safe.replaceFirst(
          'CURRENT_USER_SID=$_kWindowsCurrentUserSid',
          'CURRENT_USER_SID=$_kWindowsCurrentUserSid\n'
              'CURRENT_USER_SID=$_kWindowsCurrentUserSid',
        ),
      );
      expectMalformed(
        safe.replaceFirst(
          'OWNER=$kBrowserBridgeAppIpcWindowsSidSystem',
          'OWNER=$kBrowserBridgeAppIpcWindowsSidSystem\n'
              'OWNER=$kBrowserBridgeAppIpcWindowsSidSystem',
        ),
      );
      expectMalformed(
        '$safe\nNODE\nPATH=C:\\Windows\nENDNODE\nEND',
      );
      expectMalformed(
        safe.replaceFirst('|A|', '|Allow|'),
      );
      expectMalformed(
        safe.replaceFirst(
          'OWNER=$kBrowserBridgeAppIpcWindowsSidSystem',
          r'OWNER=NT AUTHORITY\SYSTEM',
        ),
      );
      expectMalformed('$safe\nTRAILING=1');
      expectMalformed(safe.replaceFirst('ENDNODE', ''));
      expectMalformed(
        safe.replaceFirst(
          'ACE=$kBrowserBridgeAppIpcWindowsSidSystem|A|$_kWindowsFullControl|0|0',
          'ACE=$kBrowserBridgeAppIpcWindowsSidSystem|A|$_kWindowsFullControl|0|0\n'
              'ACE=$kBrowserBridgeAppIpcWindowsSidSystem|A|$_kWindowsFullControl|0|0',
        ),
      );
    });

    test('parser and evaluator: current-user effective write is refused', () {
      final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(
        _windowsAclProbe(leafEffectiveWrite: '1'),
      );
      expect(
        browserBridgeAppIpcWindowsIntegrityFault(
          snapshot: snapshot,
          expectedCanonicalPath: _kWindowsTrustPath,
        ),
        BrowserBridgeAppIpcError.unsafePermissions,
      );
    });

    test('custom injected Windows trust path cannot skip owner ACL proof', () {
      expect(kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject, isNull);
      final custom = File(
        '${Directory.systemTemp.path}/browser_bridge.identity',
      );
      expect(
        () => readBrowserBridgeAppIpcTrustFile(
          custom,
          operatingSystem: 'windows',
          environment: const <String, String>{
            'PROGRAMDATA': r'C:\ProgramData',
          },
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
      final dir = _tempDir();
      addTearDown(() {
        try {
          dir.deleteSync(recursive: true);
        } catch (_) {}
      });
      final file = File('${dir.path}/wins_vpn/browser_bridge.identity');
      file.parent.createSync(recursive: true);
      file.writeAsStringSync(
        jsonEncode(<String, Object?>{
          'v': kBrowserBridgeAppIpcVersion,
          'secret': generateBrowserBridgeAppIpcToken(),
        }),
      );
      expect(
        () => readBrowserBridgeAppIpcTrustFile(
          file,
          operatingSystem: 'windows',
          environment: <String, String>{'PROGRAMDATA': dir.path},
        ),
        throwsA(
          isA<BrowserBridgeAppIpcException>().having(
            (e) => e.code,
            'code',
            BrowserBridgeAppIpcError.unauthenticatedIdentity,
          ),
        ),
      );
    });
  });
}

const String _kWindowsTrustPath =
    r'C:\ProgramData\wins_vpn\browser_bridge.identity';

const String _kWindowsCurrentUserSid = 'S-1-5-21-111-222-333-1001';

const int _kWindowsReadExecute = 131209;

const int _kWindowsFullControl = 2032127;

const int _kWindowsWrite = 278;

const int _kWindowsModify = 197055;

String _windowsAclProbe({
  String leafOwner = kBrowserBridgeAppIpcWindowsSidSystem,
  String leafReparse = '0',
  String leafKind = 'FILE',
  String leafEffectiveWrite = '0',
  String parentReparse = '0',
  String? leafExtraAce,
}) {
  String ace(String sid, int rights, {String inherited = '0'}) {
    return 'ACE=$sid|A|$rights|$inherited|0';
  }

  String node({
    required String path,
    required String owner,
    required String kind,
    required String reparse,
    required String effectiveWrite,
    required List<String> aces,
  }) {
    return <String>[
      'NODE',
      'PATH=$path',
      'OWNER=$owner',
      'REPARSE=$reparse',
      'KIND=$kind',
      'EFFECTIVE_WRITE=$effectiveWrite',
      ...aces,
      'ENDNODE',
    ].join('\n');
  }

  final privileged = <String>[
    ace(kBrowserBridgeAppIpcWindowsSidSystem, _kWindowsFullControl),
    ace(
      kBrowserBridgeAppIpcWindowsSidBuiltinAdministrators,
      _kWindowsFullControl,
    ),
    ace(kBrowserBridgeAppIpcWindowsSidBuiltinUsers, _kWindowsReadExecute),
  ];
  final leafAces = <String>[
    ...privileged,
    if (leafExtraAce != null) 'ACE=$leafExtraAce',
  ];
  return <String>[
    kBrowserBridgeAppIpcWindowsAclProbeVersion,
    'CURRENT_USER_SID=$_kWindowsCurrentUserSid',
    node(
      path: _kWindowsTrustPath,
      owner: leafOwner,
      kind: leafKind,
      reparse: leafReparse,
      effectiveWrite: leafEffectiveWrite,
      aces: leafAces,
    ),
    node(
      path: r'C:\ProgramData\wins_vpn',
      owner: kBrowserBridgeAppIpcWindowsSidSystem,
      kind: 'DIR',
      reparse: parentReparse,
      effectiveWrite: '0',
      aces: privileged,
    ),
    node(
      path: r'C:\ProgramData',
      owner: kBrowserBridgeAppIpcWindowsSidSystem,
      kind: 'DIR',
      reparse: '0',
      effectiveWrite: '0',
      aces: <String>[
        ace(kBrowserBridgeAppIpcWindowsSidSystem, _kWindowsFullControl),
        ace(
          kBrowserBridgeAppIpcWindowsSidBuiltinAdministrators,
          _kWindowsFullControl,
        ),
        ace(kBrowserBridgeAppIpcWindowsSidBuiltinUsers, 6),
      ],
    ),
    node(
      path: r'C:\',
      owner: kBrowserBridgeAppIpcWindowsSidSystem,
      kind: 'DIR',
      reparse: '0',
      effectiveWrite: '0',
      aces: privileged,
    ),
    'END',
  ].join('\n');
}
