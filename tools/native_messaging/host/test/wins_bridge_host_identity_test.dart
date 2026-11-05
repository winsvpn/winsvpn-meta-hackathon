// Focused proof that the shipping native-messaging host will not mint
// proxy credentials for a same-UID fake discovery / fake loopback app.
//
// Run from this package:
//   dart run test/wins_bridge_host_identity_test.dart

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:wins_bridge_host/browser_bridge_app_ipc.dart';
import 'package:wins_bridge_host/browser_bridge_protocol.dart';

import '../bin/wins_bridge_host.dart';

const _allowedOrigin = 'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/';

void _expect(bool ok, String message) {
  if (!ok) {
    throw StateError(message);
  }
}

void _expectEq(Object? actual, Object? expected, String message) {
  if (actual != expected) {
    throw StateError('$message: expected $expected, got $actual');
  }
}

BridgeStatus _snapshot({
  required BridgeTunnelStatus status,
}) {
  return BridgeStatus(
    status: status,
    detail: BridgeDetailCode.none,
    winn: BridgeWinnState.unavailableOnThisPlatform,
    selectedSlug: status == BridgeTunnelStatus.connected ? 'japan' : '',
    nodes: status == BridgeTunnelStatus.connected
        ? <BridgeNode>[
            BridgeNode(slug: 'japan', name: 'Japan', flag: 'JP'),
          ]
        : const <BridgeNode>[],
    canRequestConnect: status == BridgeTunnelStatus.disconnected,
    proxyPort: 0,
    proxyReady: status.isCarryingTraffic,
  );
}

Future<void> _writeRaw(File file, Map<String, Object?> body) async {
  await file.parent.create(recursive: true);
  await file.writeAsString(jsonEncode(body), flush: true);
  if (!Platform.isWindows) {
    final chmod = Process.runSync('chmod', <String>['600', file.path]);
    _expect(chmod.exitCode == 0, 'chmod 600 failed');
  }
}

Future<void> main() async {
  final dir = Directory.systemTemp.createTempSync('wins_bridge_host_id_');
  final file = File('${dir.path}/ipc.json');
  final owner = BrowserBridgeAppIpcTrust.authenticated(
    secretHex: generateBrowserBridgeAppIpcToken(),
    expectedIdentity: BrowserBridgeAppIpcProcessIdentity.currentProcess(),
  );

  try {
    await _fakeDiscoveryDoesNotMint(file, owner);
    await _publicDerivedMacDoesNotMint(file, owner);
    await _missingOwnerIntegrityRootDoesNotMint(dir);
    _windowsOwnerReceiptStaysFailClosed(dir);
    await _positiveCurrentAppMintsOnlyWhenConnected(file, owner);
  } finally {
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  }
}

Future<void> _fakeDiscoveryDoesNotMint(
  File file,
  BrowserBridgeAppIpcTrust owner,
) async {
  final attacker = BrowserBridgeAppIpcTrust.authenticated(
    secretHex: generateBrowserBridgeAppIpcToken(),
  );
  final fakeToken = generateBrowserBridgeAppIpcToken();
  final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  try {
    final writtenAt =
        (DateTime.now().toUtc().millisecondsSinceEpoch / 1000).floor();
    await _writeRaw(file, <String, Object?>{
      'v': kBrowserBridgeAppIpcVersion,
      'host': kBrowserBridgeAppIpcLoopbackHost,
      'port': listener.port,
      'token': fakeToken,
      'pid': pid,
      'written_at': writtenAt,
      'mac': browserBridgeAppIpcDiscoveryMac(
        trust: attacker,
        host: kBrowserBridgeAppIpcLoopbackHost,
        port: listener.port,
        token: fakeToken,
        pid: pid,
        writtenAt: writtenAt,
      ),
      'secret': attacker.secretHex,
    });

    final replies = <Map<String, Object?>>[];
    final host = BridgeHost(
      stateSource: AppIpcStateSource(
        winn: BridgeWinnState.unavailableOnThisPlatform,
        discoveryFile: file,
        trust: owner,
      ),
      operatingSystem: Platform.operatingSystem,
      emitForTest: replies.add,
      allowedOrigins: const <String>{_allowedOrigin},
    );
    host.setCallerOrigin(_allowedOrigin);

    await host.handleNativeMessageForTest(<String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': 'fake-status',
      'type': 'get_status',
    });
    _expect(replies.length == 1, 'expected one status reply');
    _expectEq(replies.single['status'], 'app_not_running', 'status');
    _expectEq(replies.single['proxyReady'], false, 'proxyReady');

    replies.clear();
    await host.handleNativeMessageForTest(<String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': 'fake-cred',
      'type': 'issue_proxy_credential',
    });
    _expect(replies.length == 1, 'expected one credential refusal');
    _expectEq(replies.single['ok'], false, 'ok');
    _expectEq(replies.single['error'], 'app_not_running', 'error');
    _expect(!replies.single.containsKey('token'), 'token must not be minted');
  } finally {
    await listener.close();
  }
}

Future<void> _publicDerivedMacDoesNotMint(
  File file,
  BrowserBridgeAppIpcTrust owner,
) async {
  final identity = BrowserBridgeAppIpcProcessIdentity.productionFor('macos');
  final publicSecret = Hmac(sha256, utf8.encode(kBrowserBridgeAppIpcMacDomain))
      .convert(utf8.encode('${identity.kind}\n${identity.value}'))
      .toString();
  try {
    BrowserBridgeAppIpcTrust.platform(operatingSystem: 'macos');
    throw StateError('platform() macos must throw');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
      'platform macos',
    );
  }
  try {
    BrowserBridgeAppIpcTrust.platform(operatingSystem: 'linux');
    throw StateError('platform() linux must throw');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
      'platform linux',
    );
  }
  final fakeToken = generateBrowserBridgeAppIpcToken();
  final writtenAt =
      (DateTime.now().toUtc().millisecondsSinceEpoch / 1000).floor();
  final publicMac = Hmac(sha256, _hexBytes(publicSecret))
      .convert(
        utf8.encode(
          '$kBrowserBridgeAppIpcMacDomain\n'
          'host=$kBrowserBridgeAppIpcLoopbackHost\n'
          'port=9\n'
          'token=$fakeToken\n'
          'pid=$pid\n'
          'written_at=$writtenAt\n',
        ),
      )
      .toString();
  await _writeRaw(file, <String, Object?>{
    'v': kBrowserBridgeAppIpcVersion,
    'host': kBrowserBridgeAppIpcLoopbackHost,
    'port': 9,
    'token': fakeToken,
    'pid': pid,
    'written_at': writtenAt,
    'mac': publicMac,
  });
  try {
    readBrowserBridgeAppIpcDiscovery(
      file,
      trust: owner,
      processAlive: (_) => true,
      verifyPortOwner: false,
    );
    throw StateError('public MAC must not authenticate');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
      'public mac',
    );
  }

  final replies = <Map<String, Object?>>[];
  final host = BridgeHost(
    stateSource: AppIpcStateSource(
      winn: BridgeWinnState.unavailableOnThisPlatform,
      discoveryFile: file,
      trust: owner,
    ),
    operatingSystem: Platform.operatingSystem,
    emitForTest: replies.add,
    allowedOrigins: const <String>{_allowedOrigin},
  );
  host.setCallerOrigin(_allowedOrigin);
  await host.handleNativeMessageForTest(<String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': 'public-mac-status',
    'type': 'get_status',
  });
  _expectEq(replies.single['status'], 'app_not_running', 'public mac status');
  _expectEq(replies.single['proxyReady'], false, 'public mac proxyReady');
  replies.clear();
  await host.handleNativeMessageForTest(<String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': 'public-mac-cred',
    'type': 'issue_proxy_credential',
  });
  _expectEq(replies.single['ok'], false, 'public mac must not mint');
  _expectEq(replies.single['error'], 'app_not_running', 'public mac error');
  _expect(!replies.single.containsKey('token'), 'public mac token');
}

Future<void> _missingOwnerIntegrityRootDoesNotMint(Directory dir) async {
  final missing = File('${dir.path}/missing-owner.identity');
  try {
    loadBrowserBridgeAppIpcTrust(
      file: missing,
      operatingSystem: Platform.operatingSystem,
    );
    throw StateError('missing owner integrity root must fail closed');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
      'missing owner root',
    );
  }
  final replies = <Map<String, Object?>>[];
  final host = BridgeHost(
    stateSource: AppIpcStateSource(
      winn: BridgeWinnState.unavailableOnThisPlatform,
      discoveryFile: File('${dir.path}/absent-ipc.json'),
      trust: null,
    ),
    operatingSystem: Platform.operatingSystem,
    emitForTest: replies.add,
    allowedOrigins: const <String>{_allowedOrigin},
  );
  host.setCallerOrigin(_allowedOrigin);
  await host.handleNativeMessageForTest(<String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': 'missing-root-status',
    'type': 'get_status',
  });
  _expectEq(replies.single['status'], 'app_not_running', 'missing root status');
  replies.clear();
  await host.handleNativeMessageForTest(<String, Object?>{
    'v': kBridgeProtocolVersion,
    'id': 'missing-root-cred',
    'type': 'issue_proxy_credential',
  });
  _expectEq(replies.single['ok'], false, 'missing root must not mint');
  _expectEq(replies.single['error'], 'app_not_running', 'missing root error');
  _expect(!replies.single.containsKey('token'), 'missing root token');
}

void _windowsOwnerReceiptStaysFailClosed(Directory dir) {
  _expect(
    kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject == null,
    'windows authenticode subject must stay owner-blocked',
  );
  _expectEq(
    BrowserBridgeAppIpcProcessIdentity.productionFor('windows').value,
    kBrowserBridgeAppIpcWindowsExecutableName,
    'windows production identity',
  );
  _expect(
    !browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
      observedPath: r'C:\Program Files\WinsVPN\wins_vpn.exe',
      programFiles: r'C:\Program Files',
      authenticode: const BrowserBridgeAppIpcWindowsAuthenticode(
        status: 'Valid',
        subject: 'CN=Must-Not-Invent-A-Subject',
      ),
      reviewedSubject: kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject,
    ),
    'null reviewed subject cannot authenticate',
  );
  try {
    BrowserBridgeAppIpcTrust.platform(operatingSystem: 'windows');
    throw StateError('platform() windows must throw');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
      'platform windows',
    );
  }

  const trustPath = r'C:\ProgramData\wins_vpn\browser_bridge.identity';
  const userSid = 'S-1-5-21-111-222-333-1001';
  const readExecute = 131209;
  const fullControl = 2032127;
  const write = 278;
  const modify = 197055;
  File sourceFile = File('lib/browser_bridge_app_ipc.dart');
  if (!sourceFile.existsSync()) {
    sourceFile = File('../lib/browser_bridge_app_ipc.dart');
  }
  if (!sourceFile.existsSync()) {
    sourceFile =
        File('tools/native_messaging/host/lib/browser_bridge_app_ipc.dart');
  }
  final source = sourceFile.readAsStringSync();
  _expect(!source.contains('--pid='), 'codesign must not use --pid=');
  _expect(
    source.contains("'--verify'") &&
        source.contains("'-R=anchor apple generic and identifier '") &&
        source.contains("'\$advertisedPid'"),
    'codesign must verify an explicit requirement against the positional pid',
  );
  _expect(source.contains('WINS_IPC_WINACL_V1'), 'windows acl probe version');
  _expect(
    source.contains(
      'kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject = null',
    ),
    'windows authenticode constant stays null',
  );

  final safe = _windowsAclProbeText(
    trustPath: trustPath,
    currentUserSid: userSid,
    readExecute: readExecute,
    fullControl: fullControl,
  );
  final safeSnapshot = parseBrowserBridgeAppIpcWindowsAclProbe(safe);
  _expect(
    browserBridgeAppIpcWindowsOwnerReceiptSafe(
      snapshot: safeSnapshot,
      expectedCanonicalPath: trustPath,
    ),
    'exact safe ACL must be owner issuance',
  );

  final writable = parseBrowserBridgeAppIpcWindowsAclProbe(
    _windowsAclProbeText(
      trustPath: trustPath,
      currentUserSid: userSid,
      readExecute: readExecute,
      fullControl: fullControl,
      leafExtraAce: '$userSid|A|$write|0|0',
    ),
  );
  _expectEq(
    browserBridgeAppIpcWindowsIntegrityFault(
      snapshot: writable,
      expectedCanonicalPath: trustPath,
    ),
    BrowserBridgeAppIpcError.unsafePermissions,
    'writable user ACE',
  );

  final inheritedUsers = parseBrowserBridgeAppIpcWindowsAclProbe(
    _windowsAclProbeText(
      trustPath: trustPath,
      currentUserSid: userSid,
      readExecute: readExecute,
      fullControl: fullControl,
      leafExtraAce: '$kBrowserBridgeAppIpcWindowsSidBuiltinUsers|A|$modify|1|0',
    ),
  );
  _expectEq(
    browserBridgeAppIpcWindowsIntegrityFault(
      snapshot: inheritedUsers,
      expectedCanonicalPath: trustPath,
    ),
    BrowserBridgeAppIpcError.unsafePermissions,
    'inherited Users Modify',
  );

  final junction = parseBrowserBridgeAppIpcWindowsAclProbe(
    _windowsAclProbeText(
      trustPath: trustPath,
      currentUserSid: userSid,
      readExecute: readExecute,
      fullControl: fullControl,
      leafReparse: '1',
    ),
  );
  _expectEq(
    browserBridgeAppIpcWindowsIntegrityFault(
      snapshot: junction,
      expectedCanonicalPath: trustPath,
    ),
    BrowserBridgeAppIpcError.symlink,
    'junction',
  );

  final wrongOwner = parseBrowserBridgeAppIpcWindowsAclProbe(
    _windowsAclProbeText(
      trustPath: trustPath,
      currentUserSid: userSid,
      readExecute: readExecute,
      fullControl: fullControl,
      leafOwner: userSid,
    ),
  );
  _expectEq(
    browserBridgeAppIpcWindowsIntegrityFault(
      snapshot: wrongOwner,
      expectedCanonicalPath: trustPath,
    ),
    BrowserBridgeAppIpcError.unsafeOwnership,
    'wrong owner',
  );

  final effectiveWrite = parseBrowserBridgeAppIpcWindowsAclProbe(
    _windowsAclProbeText(
      trustPath: trustPath,
      currentUserSid: userSid,
      readExecute: readExecute,
      fullControl: fullControl,
      leafEffectiveWrite: '1',
    ),
  );
  _expectEq(
    browserBridgeAppIpcWindowsIntegrityFault(
      snapshot: effectiveWrite,
      expectedCanonicalPath: trustPath,
    ),
    BrowserBridgeAppIpcError.unsafePermissions,
    'current-user effective write',
  );

  try {
    parseBrowserBridgeAppIpcWindowsAclProbe(
      safe.replaceFirst('|A|', '|Allow|'),
    );
    throw StateError('localized ACE type must be malformed');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.malformed,
      'malformed Allow',
    );
  }
  try {
    parseBrowserBridgeAppIpcWindowsAclProbe('$safe\nTRAILING=1');
    throw StateError('duplicate trailing output must be malformed');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.malformed,
      'malformed trailing',
    );
  }

  try {
    readBrowserBridgeAppIpcTrustFile(
      File('${dir.path}/browser_bridge.identity'),
      operatingSystem: 'windows',
      environment: const <String, String>{'PROGRAMDATA': r'C:\ProgramData'},
    );
    throw StateError('custom windows path must fail closed');
  } on BrowserBridgeAppIpcException catch (error) {
    _expectEq(
      error.code,
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
      'custom windows path',
    );
  }
}

String _windowsAclProbeText({
  required String trustPath,
  required String currentUserSid,
  required int readExecute,
  required int fullControl,
  String leafOwner = kBrowserBridgeAppIpcWindowsSidSystem,
  String leafReparse = '0',
  String leafEffectiveWrite = '0',
  String? leafExtraAce,
}) {
  String ace(String sid, int rights, {String inherited = '0'}) {
    return 'ACE=$sid|A|$rights|$inherited|0';
  }

  final privileged = <String>[
    ace(kBrowserBridgeAppIpcWindowsSidSystem, fullControl),
    ace(kBrowserBridgeAppIpcWindowsSidBuiltinAdministrators, fullControl),
    ace(kBrowserBridgeAppIpcWindowsSidBuiltinUsers, readExecute),
  ];
  final leafAces = <String>[
    ...privileged,
    if (leafExtraAce != null) 'ACE=$leafExtraAce',
  ];
  String node({
    required String path,
    required String owner,
    required String reparse,
    required String kind,
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

  return <String>[
    kBrowserBridgeAppIpcWindowsAclProbeVersion,
    'CURRENT_USER_SID=$currentUserSid',
    node(
      path: trustPath,
      owner: leafOwner,
      reparse: leafReparse,
      kind: 'FILE',
      effectiveWrite: leafEffectiveWrite,
      aces: leafAces,
    ),
    node(
      path: r'C:\ProgramData\wins_vpn',
      owner: kBrowserBridgeAppIpcWindowsSidSystem,
      reparse: '0',
      kind: 'DIR',
      effectiveWrite: '0',
      aces: privileged,
    ),
    node(
      path: r'C:\ProgramData',
      owner: kBrowserBridgeAppIpcWindowsSidSystem,
      reparse: '0',
      kind: 'DIR',
      effectiveWrite: '0',
      aces: <String>[
        ace(kBrowserBridgeAppIpcWindowsSidSystem, fullControl),
        ace(kBrowserBridgeAppIpcWindowsSidBuiltinAdministrators, fullControl),
        ace(kBrowserBridgeAppIpcWindowsSidBuiltinUsers, 6),
      ],
    ),
    node(
      path: r'C:\',
      owner: kBrowserBridgeAppIpcWindowsSidSystem,
      reparse: '0',
      kind: 'DIR',
      effectiveWrite: '0',
      aces: privileged,
    ),
    'END',
  ].join('\n');
}

Uint8List _hexBytes(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Future<void> _positiveCurrentAppMintsOnlyWhenConnected(
  File file,
  BrowserBridgeAppIpcTrust owner,
) async {
  var status = BridgeTunnelStatus.disconnected;
  final server = BrowserBridgeAppIpcServer(
    discoveryFile: file,
    snapshot: () => _snapshot(status: status),
    onCommand: (BrowserBridgeAppIpcCommand command) async {
      if (command == BrowserBridgeAppIpcCommand.requestConnect) {
        status = BridgeTunnelStatus.connected;
      }
    },
    trust: owner,
  );
  await server.start();
  try {
    final replies = <Map<String, Object?>>[];
    final host = BridgeHost(
      stateSource: AppIpcStateSource(
        winn: BridgeWinnState.unavailableOnThisPlatform,
        discoveryFile: file,
        trust: owner,
      ),
      operatingSystem: Platform.operatingSystem,
      emitForTest: replies.add,
      allowedOrigins: const <String>{_allowedOrigin},
    );
    host.setCallerOrigin(_allowedOrigin);

    await host.handleNativeMessageForTest(<String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': 'disc-cred',
      'type': 'issue_proxy_credential',
    });
    _expectEq(replies.single['ok'], false, 'disconnected must not mint');
    _expectEq(replies.single['error'], 'app_not_running', 'disconnected error');

    status = BridgeTunnelStatus.connected;
    replies.clear();
    await host.handleNativeMessageForTest(<String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': 'conn-status',
      'type': 'get_status',
    });
    _expectEq(replies.single['status'], 'connected', 'connected status');
    _expectEq(replies.single['proxyReady'], true, 'connected proxyReady');

    for (final origins in <Set<String>>[
      const <String>{},
      const <String>{_allowedOrigin},
    ]) {
      for (final caller in <String?>[
        null,
        _allowedOrigin,
        'chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/',
        '${_allowedOrigin}extra',
      ]) {
        if (origins.contains(caller)) continue;
        final deniedReplies = <Map<String, Object?>>[];
        final deniedHost = BridgeHost(
          stateSource: host.stateSource,
          operatingSystem: Platform.operatingSystem,
          allowedOrigins: origins,
          emitForTest: deniedReplies.add,
        );
        deniedHost.setCallerOrigin(caller);
        try {
          await deniedHost.handleNativeMessageForTest(<String, Object?>{
            'v': kBridgeProtocolVersion,
            'id': 'origin-cred',
            'type': 'issue_proxy_credential',
          });
          _expectEq(deniedReplies.length, 1, 'one origin refusal');
          _expectEq(deniedReplies.single['ok'], false, 'origin must not mint');
          _expectEq(
            deniedReplies.single['error'],
            'app_not_running',
            'origin error',
          );
          _expect(!deniedReplies.single.containsKey('token'), 'no origin token');
          deniedReplies.clear();
          await deniedHost.handleNativeMessageForTest(<String, Object?>{
            'v': kBridgeProtocolVersion,
            'id': 'origin-status',
            'type': 'get_status',
          });
          _expectEq(deniedReplies.single['status'], 'connected', 'status works');
          _expectEq(deniedReplies.single['proxyPort'], 0, 'no proxy listener');
        } finally {
          await deniedHost.handleNativeMessageForTest(<String, Object?>{
            'v': kBridgeProtocolVersion,
            'id': 'origin-revoke',
            'type': 'revoke_proxy_credential',
          });
        }
      }
    }

    replies.clear();
    await host.handleNativeMessageForTest(<String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': 'conn-cred',
      'type': 'issue_proxy_credential',
    });
    _expectEq(replies.single['ok'], true, 'connected may mint');
    _expectEq(replies.single['type'], 'proxy_credential', 'credential type');
    _expect(replies.single['token'] is String, 'credential token');
    await host.handleNativeMessageForTest(<String, Object?>{
      'v': kBridgeProtocolVersion,
      'id': 'rev',
      'type': 'revoke_proxy_credential',
    });
  } finally {
    await server.stop();
  }
}
