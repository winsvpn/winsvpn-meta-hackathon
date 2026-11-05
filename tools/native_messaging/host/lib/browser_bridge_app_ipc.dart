// Authenticated IPv4-loopback IPC between the desktop app and the native host.
//
// No Flutter import: compiled into `bin/wins_bridge_host.dart` as well as the
// app. The native-messaging host is a separate process the browser launches;
// this is the only channel it has into a running WinsVPN desktop session.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS
// ---------------------------------------------------------------------------
//
// The extension talks to `wins_bridge_host` over native messaging. That host
// used to have no way to observe the desktop app, so it honestly reported
// `app_not_running` and refused every control. The failure direction was
// correct; the missing piece was a way to ask the app at all.
//
// This file is that piece. The desktop app binds 127.0.0.1, writes a
// current-user-only discovery file naming the port and a per-run 256-bit
// bearer token, and answers get_status / request_connect / request_disconnect.
// The native host reads that file, validates it, and only then connects.
// Every validation failure is a refusal: the host keeps reporting
// `app_not_running`. Nothing here fails open.
//
// The discovery file is not a trust root. A same-UID process can write
// `ipc.json`, bind loopback, and answer CONNECTED. Endpoint authenticity
// therefore comes from an owner-installed integrity receipt the current
// user cannot mint, plus platform signature identity of the advertised
// pid, plus a MAC and a listen-port owner check that bind that identity
// to the loopback endpoint. A public HMAC key derived from bundle id,
// executable name, or any other public identity is not an authentication
// claim. Missing or unreadable owner integrity root fails closed; it is
// not replaced by a fallback MAC. Same-UID ad-hoc signing of the shipping
// bundle id, a Program Files lookalike, or a renamed binary under a broad
// install prefix cannot authenticate. Fields inside the discovery document
// cannot supply the secret, the expected identity, or any other trust
// root. CONNECTED is admitted only after that authenticated app identity
// is proven and the app reports real VPN state.
//
// ---------------------------------------------------------------------------
// WHAT THIS IS NOT
// ---------------------------------------------------------------------------
//
// Not a proxy. Not a VPN control plane. Not reachable off this machine. The
// token never appears in a log line, an exception string, or an outbound
// native-messaging message. Windows is not treated as POSIX: mode bits and
// uid are not interpreted there.

import 'windows_system_executable.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show Hmac, sha256;

import 'browser_bridge_framing.dart';
import 'browser_bridge_protocol.dart';

/// Wire version of the app IPC envelopes and the discovery file.
const int kBrowserBridgeAppIpcVersion = 1;

/// Ceiling on one IPC frame body, in bytes. Status snapshots with a bounded
/// node list fit; a hostile peer cannot force a multi-megabyte buffer.
const int kMaxBrowserBridgeAppIpcFrameBytes = 16 * 1024;

/// Ceiling on the discovery file itself.
const int kMaxBrowserBridgeAppIpcDiscoveryBytes = 4096;

/// Discovery older than this is refused even if a pid still looks alive.
const Duration kBrowserBridgeAppIpcDiscoveryTtl = Duration(seconds: 90);

/// How often the running app rewrites `written_at` so a live session is not
/// mistaken for a crash leftover.
const Duration kBrowserBridgeAppIpcHeartbeat = Duration(seconds: 30);

const Duration kBrowserBridgeAppIpcIoTimeout = Duration(seconds: 2);

/// Connect/disconnect wait for the existing app tunnel controls to finish.
const Duration kBrowserBridgeAppIpcCommandTimeout = Duration(seconds: 60);

const int kBrowserBridgeAppIpcTokenBytes = 32;

const int kBrowserBridgeAppIpcMaxNodes = 64;

const int kBrowserBridgeAppIpcMaxSeenRequestIds = 256;

const String kBrowserBridgeAppIpcLoopbackHost = '127.0.0.1';

const String kBrowserBridgeAppIpcDiscoveryFileName = 'ipc.json';

const String kBrowserBridgeAppIpcDiscoveryDirName = 'browser_bridge';

const String kBrowserBridgeAppIpcTrustFileName = 'browser_bridge.identity';

const String kBrowserBridgeAppIpcMacDomain =
    'winsvpn-browser-bridge-app-ipc-v1';

const String kBrowserBridgeAppIpcMacosBundleId = 'org.winsvpn.app';

const String kBrowserBridgeAppIpcMacosTeamIdentifier = '5YT8H4U72M';

/// The team-prefixed App Group the sandboxed macOS app and the native host
/// share (`$(TeamIdentifierPrefix)group.org.winsvpn.app`).
const String kBrowserBridgeAppIpcMacosAppGroupIdentifier =
    '$kBrowserBridgeAppIpcMacosTeamIdentifier.group.$kBrowserBridgeAppIpcMacosBundleId';

const String kBrowserBridgeAppIpcLinuxInstalledExecutable =
    '/opt/wins-vpn/wins_vpn';

const String kBrowserBridgeAppIpcWindowsExecutableName = 'wins_vpn.exe';

const String kBrowserBridgeAppIpcWindowsInstallFolderName = 'WinsVPN';

/// Reviewed Authenticode subject for the installed Windows application.
///
/// No immutable reviewed certificate identity for `wins_vpn.exe` is
/// committed in this tree, and Windows builds ship unsigned by owner ruling.
/// Do not invent a thumbprint or subject. While this is null the app is
/// identified by its protected install location instead
/// ([browserBridgeAppIpcWindowsProtectedInstalledExecutableAuthenticates]);
/// once a subject is reviewed, both must hold.
const String? kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject = null;

/// Closed stdout contract for the Windows owner-receipt ACL probe.
const String kBrowserBridgeAppIpcWindowsAclProbeVersion = 'WINS_IPC_WINACL_V1';

const String kBrowserBridgeAppIpcWindowsSidSystem = 'S-1-5-18';

const String kBrowserBridgeAppIpcWindowsSidBuiltinAdministrators =
    'S-1-5-32-544';

const String kBrowserBridgeAppIpcWindowsSidTrustedInstaller =
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';

const String kBrowserBridgeAppIpcWindowsSidBuiltinUsers = 'S-1-5-32-545';

const String kBrowserBridgeAppIpcWindowsSidAuthenticatedUsers = 'S-1-5-11';

const String kBrowserBridgeAppIpcWindowsSidEveryone = 'S-1-1-0';

final RegExp kBrowserBridgeAppIpcWindowsSidPattern =
    RegExp(r'^S-1-[0-9]+(-[0-9]+)+$');

const int kBrowserBridgeAppIpcWindowsRightWriteData = 0x2;

const int kBrowserBridgeAppIpcWindowsRightAppendData = 0x4;

const int kBrowserBridgeAppIpcWindowsRightWriteEa = 0x10;

const int kBrowserBridgeAppIpcWindowsRightDeleteChild = 0x40;

const int kBrowserBridgeAppIpcWindowsRightWriteAttributes = 0x100;

const int kBrowserBridgeAppIpcWindowsRightDelete = 0x10000;

const int kBrowserBridgeAppIpcWindowsRightWriteDac = 0x40000;

const int kBrowserBridgeAppIpcWindowsRightWriteOwner = 0x80000;

const int kBrowserBridgeAppIpcWindowsRightGenericAll = 0x10000000;

const int kBrowserBridgeAppIpcWindowsRightGenericWrite = 0x40000000;

const int kBrowserBridgeAppIpcWindowsContentWriteRights =
    kBrowserBridgeAppIpcWindowsRightWriteData |
        kBrowserBridgeAppIpcWindowsRightAppendData |
        kBrowserBridgeAppIpcWindowsRightWriteEa |
        kBrowserBridgeAppIpcWindowsRightWriteAttributes;

const int kBrowserBridgeAppIpcWindowsReplaceRights =
    kBrowserBridgeAppIpcWindowsRightDeleteChild |
        kBrowserBridgeAppIpcWindowsRightDelete |
        kBrowserBridgeAppIpcWindowsRightWriteDac |
        kBrowserBridgeAppIpcWindowsRightWriteOwner |
        kBrowserBridgeAppIpcWindowsRightGenericAll |
        kBrowserBridgeAppIpcWindowsRightGenericWrite;

const String kBrowserBridgeAppIpcIdentityKindCurrentProcess = 'current_process';

const String kBrowserBridgeAppIpcIdentityKindBundleId = 'bundle_id';

const String kBrowserBridgeAppIpcIdentityKindInstalledExecutable =
    'installed_executable';

final RegExp kBrowserBridgeAppIpcTokenPattern = RegExp(r'^[0-9a-f]{64}$');

final RegExp kBrowserBridgeAppIpcRequestIdPattern =
    RegExp(r'^[A-Za-z0-9_-]{1,64}$');

/// Commands the native host may send. Closed. Nothing here takes an address.
enum BrowserBridgeAppIpcCommand {
  getStatus('get_status'),
  requestConnect('request_connect'),
  requestDisconnect('request_disconnect'),

  /// Start an in-app pairing confirmation for the presented `origin`.
  pairBegin('pair_begin'),

  /// Read the state of the pairing named by `pairing_id`.
  pairPoll('pair_poll'),

  /// Forget the pairing for `origin`; the caller must present it.
  pairRevoke('pair_revoke');

  const BrowserBridgeAppIpcCommand(this.wire);

  final String wire;

  static BrowserBridgeAppIpcCommand? fromWire(String value) {
    for (final command in BrowserBridgeAppIpcCommand.values) {
      if (command.wire == value) return command;
    }
    return null;
  }
}

/// Why an IPC read, write, or round-trip was refused.
///
/// Closed, and the [wire] values are the only strings that ever leave this
/// file toward a caller. The token is never one of them.
enum BrowserBridgeAppIpcError {
  missingDiscovery('missing_discovery'),
  symlink('symlink'),
  notRegularFile('not_regular_file'),
  unsafePermissions('unsafe_permissions'),
  unsafeOwnership('unsafe_ownership'),
  stale('stale'),
  nonLoopback('non_loopback'),
  malformed('malformed'),
  oversized('oversized'),
  tokenMismatch('token_mismatch'),
  duplicateRequestId('duplicate_request_id'),
  appAbsent('app_absent'),
  unsupportedVersion('unsupported_version'),
  unauthenticatedIdentity('unauthenticated_identity'),
  identityMismatch('identity_mismatch'),
  portOwnerMismatch('port_owner_mismatch'),

  /// A control request without a pairing the app recognises.
  notPaired('not_paired'),

  /// Another control or pairing is already in progress.
  busy('busy'),

  /// Pairing requests arrived faster than the app accepts them.
  rateLimited('rate_limited'),

  /// The app cannot show a pairing confirmation right now.
  pairingUnavailable('pairing_unavailable'),
  internal('internal');

  const BrowserBridgeAppIpcError(this.wire);

  final String wire;
}

class BrowserBridgeAppIpcException implements Exception {
  const BrowserBridgeAppIpcException(this.code);

  final BrowserBridgeAppIpcError code;

  @override
  String toString() => 'BrowserBridgeAppIpcException: ${code.wire}';
}

typedef BrowserBridgeAppIpcClock = DateTime Function();

typedef BrowserBridgeAppIpcProcessLiveness = bool Function(int pid);

typedef BrowserBridgeAppIpcSnapshotReader = BridgeStatus Function();

typedef BrowserBridgeAppIpcCommandHandler = Future<void> Function(
  BrowserBridgeAppIpcCommand command,
);

/// Desktop-only. Android and iOS have no native-messaging host to talk to.
bool browserBridgeAppIpcSupportedOn(String operatingSystem) {
  switch (operatingSystem.trim().toLowerCase()) {
    case 'windows':
    case 'linux':
    case 'macos':
      return true;
    default:
      return false;
  }
}

/// POSIX uid/mode checks apply on Unix. Windows ACLs are a different model;
/// this function is the one place that sentence is encoded.
bool browserBridgeAppIpcUsesPosixOwnership(String operatingSystem) {
  return operatingSystem.trim().toLowerCase() != 'windows';
}

/// Length-independent XOR comparison. Token length is public (64 hex chars);
/// the extra work is so a future format change cannot introduce a length leak.
bool browserBridgeAppIpcConstantTimeEquals(String left, String right) {
  final a = left.codeUnits;
  final b = right.codeUnits;
  var difference = a.length ^ b.length;
  final n = a.length > b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final av = i < a.length ? a[i] : 0;
    final bv = i < b.length ? b[i] : 0;
    difference |= av ^ bv;
  }
  return difference == 0;
}

/// 256-bit token, lowercase hex. Hex rather than base64 so the discovery
/// schema can be a single tight charset with no padding.
String generateBrowserBridgeAppIpcToken([Random? random]) {
  final rng = random ?? Random.secure();
  final bytes = Uint8List(kBrowserBridgeAppIpcTokenBytes);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = rng.nextInt(256);
  }
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

bool isBrowserBridgeAppIpcTokenShape(String token) {
  return kBrowserBridgeAppIpcTokenPattern.hasMatch(token);
}

/// Process identity the host compares against the advertised discovery pid.
///
/// Production values are the shipping Wins VPN platform identity, not a
/// string the discovery file is allowed to name.
class BrowserBridgeAppIpcProcessIdentity {
  const BrowserBridgeAppIpcProcessIdentity({
    required this.kind,
    required this.value,
  });

  final String kind;
  final String value;

  /// Bind to this process. Tests only: the shipping host and app use
  /// [productionFor].
  factory BrowserBridgeAppIpcProcessIdentity.currentProcess() {
    return BrowserBridgeAppIpcProcessIdentity(
      kind: kBrowserBridgeAppIpcIdentityKindCurrentProcess,
      value: '$pid',
    );
  }

  factory BrowserBridgeAppIpcProcessIdentity.productionFor(
    String operatingSystem,
  ) {
    final os = operatingSystem.trim().toLowerCase();
    if (os == 'macos') {
      return const BrowserBridgeAppIpcProcessIdentity(
        kind: kBrowserBridgeAppIpcIdentityKindBundleId,
        value: kBrowserBridgeAppIpcMacosBundleId,
      );
    }
    if (os == 'windows') {
      return const BrowserBridgeAppIpcProcessIdentity(
        kind: kBrowserBridgeAppIpcIdentityKindInstalledExecutable,
        value: kBrowserBridgeAppIpcWindowsExecutableName,
      );
    }
    return const BrowserBridgeAppIpcProcessIdentity(
      kind: kBrowserBridgeAppIpcIdentityKindInstalledExecutable,
      value: kBrowserBridgeAppIpcLinuxInstalledExecutable,
    );
  }
}

/// Observed macOS code signature of an advertised pid.
class BrowserBridgeAppIpcMacosCodeSignature {
  const BrowserBridgeAppIpcMacosCodeSignature({
    required this.identifier,
    required this.teamIdentifier,
    required this.designatedRequirement,
    required this.currentSignatureValid,
    required this.adHoc,
  });

  final String identifier;
  final String teamIdentifier;
  final String designatedRequirement;
  final bool currentSignatureValid;
  final bool adHoc;
}

/// Observed Authenticode statement of an advertised Windows executable.
class BrowserBridgeAppIpcWindowsAuthenticode {
  const BrowserBridgeAppIpcWindowsAuthenticode({
    required this.status,
    required this.subject,
  });

  final String status;
  final String subject;
}

/// One POSIX path component used by owner-receipt and Linux executable checks.
class BrowserBridgeAppIpcPosixNode {
  const BrowserBridgeAppIpcPosixNode({
    required this.path,
    required this.uid,
    required this.mode,
    required this.isLink,
    this.isRegularFile = false,
  });

  final String path;
  final int uid;
  final int mode;
  final bool isLink;
  final bool isRegularFile;
}

/// One Windows ACE from the owner-receipt probe. Rights are a 32-bit mask.
class BrowserBridgeAppIpcWindowsAce {
  const BrowserBridgeAppIpcWindowsAce({
    required this.sid,
    required this.allow,
    required this.rights,
    required this.inherited,
    required this.inheritOnly,
  });

  final String sid;
  final bool allow;
  final int rights;
  final bool inherited;
  final bool inheritOnly;
}

/// One Windows path component from the owner-receipt probe, leaf first.
class BrowserBridgeAppIpcWindowsNode {
  const BrowserBridgeAppIpcWindowsNode({
    required this.path,
    required this.ownerSid,
    required this.isReparse,
    required this.isRegularFile,
    required this.currentUserEffectiveWrite,
    required this.aces,
  });

  final String path;
  final String ownerSid;
  final bool isReparse;
  final bool isRegularFile;
  final bool currentUserEffectiveWrite;
  final List<BrowserBridgeAppIpcWindowsAce> aces;
}

/// Parsed Windows owner-receipt probe. Duplicate or malformed input is refused
/// before this object is constructed.
class BrowserBridgeAppIpcWindowsAclSnapshot {
  const BrowserBridgeAppIpcWindowsAclSnapshot({
    required this.currentUserSid,
    required this.fileThenAncestors,
    this.volume = '',
    this.programFiles = '',
  });

  final String currentUserSid;
  final List<BrowserBridgeAppIpcWindowsNode> fileThenAncestors;

  /// `<DriveType>|<DriveFormat>` of the probed path's volume as .NET reports
  /// it (for example `Fixed|NTFS`). Empty from a probe that did not say.
  final String volume;

  /// The Program Files known folder as the OS resolves it
  /// (`Environment.GetFolderPath(ProgramFiles)`, SHGetFolderPath), not the
  /// `%ProgramFiles%` the host inherited. Empty when the probe did not say.
  final String programFiles;

  /// Only a fixed local NTFS volume's DACL is evidence. A removable medium or
  /// a network share reports whatever owner and ACEs its writer chose.
  bool get onFixedNtfs => volume == 'Fixed|NTFS';
}

/// External trust root for the app IPC endpoint.
///
/// The secret never comes from the discovery file. Same-UID chmod 0444 files
/// are not owner issuance. [authenticated] is the injected owner-installed
/// secret used by tests and by a bound owner file. [platform] is not a MAC
/// key: public identity cannot authenticate, and a missing owner integrity
/// root fails closed instead of deriving HMAC material.
class BrowserBridgeAppIpcTrust {
  BrowserBridgeAppIpcTrust._({
    required this.secretHex,
    required this.expectedIdentity,
    this.sourcePath,
    this.boundDev,
    this.boundIno,
    this.boundUid,
  });

  final String secretHex;
  final BrowserBridgeAppIpcProcessIdentity expectedIdentity;
  final String? sourcePath;
  final int? boundDev;
  final int? boundIno;
  final int? boundUid;

  /// Owner-installed secret plus the process identity it authenticates.
  ///
  /// [expectedIdentity] defaults to this process so a test can bind the
  /// current app. Production loads [loadBrowserBridgeAppIpcTrust] instead.
  factory BrowserBridgeAppIpcTrust.authenticated({
    required String secretHex,
    BrowserBridgeAppIpcProcessIdentity? expectedIdentity,
  }) {
    if (!isBrowserBridgeAppIpcTokenShape(secretHex)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.unauthenticatedIdentity,
      );
    }
    return BrowserBridgeAppIpcTrust._(
      secretHex: secretHex,
      expectedIdentity:
          expectedIdentity ?? BrowserBridgeAppIpcProcessIdentity.currentProcess(),
    );
  }

  factory BrowserBridgeAppIpcTrust.platform({String? operatingSystem}) {
    // [operatingSystem] cannot mint a MAC key. Public identity is not a
    // secret, so this factory is a closed refusal on every platform.
    if (operatingSystem != null) {
      BrowserBridgeAppIpcProcessIdentity.productionFor(operatingSystem);
    }
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }

  Uint8List get secretBytes => _hexToBytes(secretHex);

  bool get isFileBound => sourcePath != null;

  @override
  String toString() =>
      'BrowserBridgeAppIpcTrust(kind: ${expectedIdentity.kind})';
}

const Set<String> _kTrustFileKeys = <String>{
  'v',
  'secret',
};

/// Default owner-installed identity path. This is not the discovery file and
/// is not under the current-user data dir the discovery file uses.
File defaultBrowserBridgeAppIpcTrustFile({
  String? operatingSystem,
  Map<String, String>? environment,
}) {
  final os = (operatingSystem ?? Platform.operatingSystem).toLowerCase();
  final env = environment ?? Platform.environment;
  if (os == 'windows') {
    final programData = _windowsEnvironmentValue(env, 'programdata');
    if (programData == null) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.unauthenticatedIdentity,
      );
    }
    return File('$programData/wins_vpn/$kBrowserBridgeAppIpcTrustFileName');
  }
  if (os == 'macos') {
    return File(
      '/Library/Application Support/wins_vpn/'
      '$kBrowserBridgeAppIpcTrustFileName',
    );
  }
  return File(
    '/usr/lib/wins-vpn/$kBrowserBridgeAppIpcTrustFileName',
  );
}

/// Load the external trust root. Missing, unreadable, or failed owner
/// issuance is unauthenticated. There is no public-identity MAC fallback.
BrowserBridgeAppIpcTrust loadBrowserBridgeAppIpcTrust({
  File? file,
  String? operatingSystem,
  Map<String, String>? environment,
}) {
  final os = operatingSystem ?? Platform.operatingSystem;
  final path = file ??
      defaultBrowserBridgeAppIpcTrustFile(
        operatingSystem: os,
        environment: environment,
      );
  if (FileSystemEntity.isLinkSync(path.path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  if (!path.existsSync()) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  return readBrowserBridgeAppIpcTrustFile(
    path,
    operatingSystem: os,
    environment: environment,
  );
}

/// Read an owner-installed secret. Same-UID ownership is refused even when
/// the mode is 0444. User-writable receipts and ancestry are refused. The
/// file may not name a process identity: identity is always the shipping
/// platform identity for [operatingSystem]. On Windows the path must be the
/// exact default ProgramData receipt; a custom injected path cannot skip
/// owner and ACL proof.
BrowserBridgeAppIpcTrust readBrowserBridgeAppIpcTrustFile(
  File file, {
  String? operatingSystem,
  Map<String, String>? environment,
}) {
  final os = operatingSystem ?? Platform.operatingSystem;
  if (browserBridgeAppIpcUsesPosixOwnership(os)) {
    _assertPosixOwnerInstalledReceipt(file.path);
  } else {
    _assertWindowsOwnerInstalledReceipt(
      file.path,
      environment: environment,
    );
  }
  final snapshot = _bindRegularFileBytes(
    file,
    maxBytes: kMaxBrowserBridgeAppIpcDiscoveryBytes,
    operatingSystem: os,
    ownerInstalledTrust: true,
  );
  if (browserBridgeAppIpcUsesPosixOwnership(os)) {
    final uid = snapshot.uid;
    final self = _posixCurrentUid();
    if (uid == null || self == null || uid == self) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.unauthenticatedIdentity,
      );
    }
    _assertPosixOwnerInstalledReceipt(file.path);
  } else {
    _assertWindowsOwnerInstalledReceipt(
      file.path,
      environment: environment,
    );
  }
  Object? decoded;
  try {
    decoded = jsonDecode(utf8.decode(snapshot.bytes));
  } catch (_) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final raw = _exactStringKeyedObject(decoded, _kTrustFileKeys);
  final version = raw['v'];
  if (version is! int || version != kBrowserBridgeAppIpcVersion) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unsupportedVersion,
    );
  }
  final secret = raw['secret'];
  if (secret is! String || !isBrowserBridgeAppIpcTokenShape(secret)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  return BrowserBridgeAppIpcTrust._(
    secretHex: secret,
    expectedIdentity: BrowserBridgeAppIpcProcessIdentity.productionFor(os),
    sourcePath: file.path,
    boundDev: snapshot.dev,
    boundIno: snapshot.ino,
    boundUid: snapshot.uid,
  );
}

void rebindBrowserBridgeAppIpcTrust(
  BrowserBridgeAppIpcTrust trust, {
  String? operatingSystem,
}) {
  final path = trust.sourcePath;
  if (path == null) return;
  final rebound = readBrowserBridgeAppIpcTrustFile(
    File(path),
    operatingSystem: operatingSystem,
  );
  if (rebound.boundDev != trust.boundDev ||
      rebound.boundIno != trust.boundIno ||
      rebound.boundUid != trust.boundUid ||
      !browserBridgeAppIpcConstantTimeEquals(
        rebound.secretHex,
        trust.secretHex,
      )) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
}

String browserBridgeAppIpcDiscoveryMac({
  required BrowserBridgeAppIpcTrust trust,
  required String host,
  required int port,
  required String token,
  required int pid,
  required int writtenAt,
}) {
  final payload = utf8.encode(
    '$kBrowserBridgeAppIpcMacDomain\n'
    'host=$host\n'
    'port=$port\n'
    'token=$token\n'
    'pid=$pid\n'
    'written_at=$writtenAt\n',
  );
  return Hmac(sha256, trust.secretBytes).convert(payload).toString();
}

bool browserBridgeAppIpcProcessMatches({
  required int pid,
  required BrowserBridgeAppIpcProcessIdentity expected,
}) {
  if (pid <= 0) return false;
  if (expected.kind == kBrowserBridgeAppIpcIdentityKindCurrentProcess) {
    return pid.toString() == expected.value;
  }
  if (expected.kind == kBrowserBridgeAppIpcIdentityKindBundleId) {
    if (expected.value != kBrowserBridgeAppIpcMacosBundleId) return false;
    final observed = _macosCodeSignatureForPid(pid);
    return observed != null &&
        browserBridgeAppIpcMacosCodeSignatureAuthenticates(observed);
  }
  if (expected.kind == kBrowserBridgeAppIpcIdentityKindInstalledExecutable) {
    return _installedExecutableMatches(pid, expected.value);
  }
  return false;
}

BridgeStatus browserBridgeAppIpcAdmitStatus(
  BridgeStatus status, {
  required bool authenticatedAppIdentity,
  required BridgeWinnState winn,
}) {
  if (!authenticatedAppIdentity) {
    return BridgeStatus.appNotRunning(winn: winn);
  }
  if (status.status == BridgeTunnelStatus.connected && !status.proxyReady) {
    return BridgeStatus.appNotRunning(winn: winn);
  }
  return status;
}

bool browserBridgeAppIpcMayIssueProxyCredential(BridgeStatus status) {
  return status.status == BridgeTunnelStatus.connected && status.proxyReady;
}

/// Default discovery path, matching the desktop app's `wins_vpn` data dir.
///
/// [environment] is injectable so tests do not have to mutate the process
/// environment. There is no production override flag: a path the user did
/// not ask for is how a state-file override would fail this open.
File defaultBrowserBridgeAppIpcDiscoveryFile({
  String? operatingSystem,
  Map<String, String>? environment,
  String? Function(String groupIdentifier)? macosAppGroupContainer,
}) {
  final os = (operatingSystem ?? Platform.operatingSystem).toLowerCase();
  final env = environment ?? Platform.environment;
  final String basePath;
  if (os == 'windows') {
    final appData = (env['APPDATA'] ?? '').trim();
    if (appData.isEmpty) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.missingDiscovery,
      );
    }
    basePath = appData;
  } else if (os == 'macos') {
    // The sandboxed app and the browser-launched host meet in the team App
    // Group container. macOS 15 grants it without a prompt only to an entitled
    // process that gets the path from FileManager, so both resolve it that
    // way; nothing is derived from HOME, and no container means no discovery.
    final String? container = (macosAppGroupContainer ??
        browserBridgeMacosAppGroupContainerPath)(
      kBrowserBridgeAppIpcMacosAppGroupIdentifier,
    );
    final String trimmed = (container ?? '').trim();
    if (trimmed.isEmpty || !trimmed.startsWith('/')) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.missingDiscovery,
      );
    }
    return File(
      '$trimmed/$kBrowserBridgeAppIpcDiscoveryDirName/'
      '$kBrowserBridgeAppIpcDiscoveryFileName',
    );
  } else {
    final home = (env['HOME'] ?? '').trim();
    if (home.isEmpty) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.missingDiscovery,
      );
    }
    basePath = '$home/.local/share';
  }
  return File(
    '$basePath/wins_vpn/$kBrowserBridgeAppIpcDiscoveryDirName/'
    '$kBrowserBridgeAppIpcDiscoveryFileName',
  );
}

// macOS App Group container lookup through FileManager, for the desktop app
// and the browser-launched native host alike (EXT-17). It lives in this file,
// not a new one, because the host package compiles this file through a fixed
// set of relative symlinks (tools/native_messaging/host/lib, pinned by
// tools/build_linux_release.sh and the release freeze tools).
//
// macOS 15 grants a team-prefixed App Group container without a prompt only to
// an entitled process that obtains the path from FileManager
// (containerURLForSecurityApplicationGroupIdentifier:). The native host is a
// Dart executable with no Flutter engine and no method channel, so the call is
// made here through the Objective-C runtime. Any failure returns null, and the
// caller then refuses (fail closed); nothing falls back to a HOME-derived path.

typedef _PtrFromCStringC = Pointer<Void> Function(Pointer<Uint8>);
typedef _MsgSend0C = Pointer<Void> Function(Pointer<Void>, Pointer<Void>);
typedef _MsgSend1C = Pointer<Void> Function(
    Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef _PoolPushC = Pointer<Void> Function();
typedef _PoolPopC = Void Function(Pointer<Void>);
typedef _PoolPopDart = void Function(Pointer<Void>);
typedef _MallocC = Pointer<Uint8> Function(IntPtr);
typedef _MallocDart = Pointer<Uint8> Function(int);
typedef _FreeC = Void Function(Pointer<Uint8>);
typedef _FreeDart = void Function(Pointer<Uint8>);

/// The App Group container path FileManager returns for [groupIdentifier], or
/// null when it is unavailable (not macOS, not entitled, or any lookup error).
String? browserBridgeMacosAppGroupContainerPath(String groupIdentifier) {
  if (!Platform.isMacOS || groupIdentifier.isEmpty) return null;
  try {
    final DynamicLibrary objc = DynamicLibrary.open('/usr/lib/libobjc.A.dylib');
    DynamicLibrary.open(
      '/System/Library/Frameworks/Foundation.framework/Foundation',
    );
    final DynamicLibrary libc = DynamicLibrary.process();
    final getClass = objc
        .lookupFunction<_PtrFromCStringC, _PtrFromCStringC>('objc_getClass');
    final selector = objc
        .lookupFunction<_PtrFromCStringC, _PtrFromCStringC>('sel_registerName');
    final Pointer<NativeFunction<Void Function()>> msgSend =
        objc.lookup<NativeFunction<Void Function()>>('objc_msgSend');
    final send0 = msgSend
        .cast<NativeFunction<_MsgSend0C>>()
        .asFunction<_MsgSend0C>();
    final send1 = msgSend
        .cast<NativeFunction<_MsgSend1C>>()
        .asFunction<_MsgSend1C>();
    final poolPush = objc
        .lookupFunction<_PoolPushC, _PoolPushC>('objc_autoreleasePoolPush');
    final poolPop =
        objc.lookupFunction<_PoolPopC, _PoolPopDart>('objc_autoreleasePoolPop');
    final malloc = libc.lookupFunction<_MallocC, _MallocDart>('malloc');
    final free = libc.lookupFunction<_FreeC, _FreeDart>('free');

    final List<Pointer<Uint8>> owned = <Pointer<Uint8>>[];
    Pointer<Uint8> cString(String value) {
      final List<int> bytes = utf8.encode(value);
      final Pointer<Uint8> out = malloc(bytes.length + 1);
      if (out == nullptr) throw StateError('malloc');
      owned.add(out);
      final view = out.asTypedList(bytes.length + 1);
      view.setAll(0, bytes);
      view[bytes.length] = 0;
      return out;
    }

    final Pointer<Void> pool = poolPush();
    try {
      final Pointer<Void> fileManager = send0(
        getClass(cString('NSFileManager')),
        selector(cString('defaultManager')),
      );
      final Pointer<Void> identifier = send1(
        getClass(cString('NSString')),
        selector(cString('stringWithUTF8String:')),
        cString(groupIdentifier).cast<Void>(),
      );
      if (fileManager == nullptr || identifier == nullptr) return null;
      final Pointer<Void> url = send1(
        fileManager,
        selector(
          cString('containerURLForSecurityApplicationGroupIdentifier:'),
        ),
        identifier,
      );
      if (url == nullptr) return null;
      final Pointer<Void> path = send0(url, selector(cString('path')));
      if (path == nullptr) return null;
      final Pointer<Uint8> utf8Path =
          send0(path, selector(cString('UTF8String'))).cast<Uint8>();
      if (utf8Path == nullptr) return null;
      var length = 0;
      while (utf8Path[length] != 0) {
        length += 1;
        if (length > 4096) return null;
      }
      final String result = utf8.decode(utf8Path.asTypedList(length));
      return result.startsWith('/') ? result : null;
    } finally {
      poolPop(pool);
      for (final Pointer<Uint8> p in owned) {
        free(p);
      }
    }
  } catch (_) {
    return null;
  }
}

/// What the discovery file is allowed to name: IPv4 loopback and a port.
/// The MAC is computed from [BrowserBridgeAppIpcTrust], never from a secret
/// carried in this document.
class BrowserBridgeAppIpcEndpoint {
  const BrowserBridgeAppIpcEndpoint({
    required this.host,
    required this.port,
    required this.token,
    required this.pid,
    required this.writtenAt,
    this.mac = '',
  });

  final String host;
  final int port;
  final String token;
  final int pid;
  final int writtenAt;
  final String mac;

  Map<String, Object?> toJson(BrowserBridgeAppIpcTrust trust) {
    final boundMac = browserBridgeAppIpcDiscoveryMac(
      trust: trust,
      host: host,
      port: port,
      token: token,
      pid: pid,
      writtenAt: writtenAt,
    );
    return <String, Object?>{
      'v': kBrowserBridgeAppIpcVersion,
      'host': host,
      'port': port,
      'token': token,
      'pid': pid,
      'written_at': writtenAt,
      'mac': boundMac,
    };
  }
}

const Set<String> _kDiscoveryKeys = <String>{
  'v',
  'host',
  'port',
  'token',
  'pid',
  'written_at',
  'mac',
};

const Set<String> _kRequestKeys = <String>{
  'v',
  'id',
  'token',
  'type',
};

/// Fields a request may add to [_kRequestKeys]. Which of them a command
/// requires or forbids is decided per command in the server dispatch.
const Set<String> _kOptionalRequestKeys = <String>{
  'origin',
  'credential',
  'pairing_id',
};

const Set<String> _kPairingReplyKeys = <String>{
  'state',
  'pairing_id',
  'code',
  'expires_in',
  'credential',
};

const Set<String> _kStatusKeys = <String>{
  'status',
  'detail',
  'winn',
  'selectedSlug',
  'nodes',
  'canRequestConnect',
  'proxyPort',
  'proxyReady',
  'proxyTls',
  'proxyTlsPort',
  'rxKib',
  'txKib',
  'pairing',
};

const Set<String> _kNodeKeys = <String>{
  'slug',
  'name',
  'flag',
};

/// Read and validate a discovery file. Never follows a symlink to success.
/// Trust is [trust] or [loadBrowserBridgeAppIpcTrust]; the document itself
/// cannot supply a secret or process identity.
BrowserBridgeAppIpcEndpoint readBrowserBridgeAppIpcDiscovery(
  File file, {
  required BrowserBridgeAppIpcTrust trust,
  BrowserBridgeAppIpcClock? clock,
  BrowserBridgeAppIpcProcessLiveness? processAlive,
  String? operatingSystem,
  bool verifyPortOwner = true,
}) {
  final os = operatingSystem ?? Platform.operatingSystem;
  rebindBrowserBridgeAppIpcTrust(trust, operatingSystem: os);
  final snapshot = _bindRegularFileBytes(
    file,
    maxBytes: kMaxBrowserBridgeAppIpcDiscoveryBytes,
    operatingSystem: os,
  );
  Object? decoded;
  try {
    decoded = jsonDecode(utf8.decode(snapshot.bytes));
  } catch (_) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (decoded is Map) {
    for (final key in decoded.keys) {
      if (key is String && _kDiscoveryTrustRootKeys.contains(key)) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.unauthenticatedIdentity,
        );
      }
    }
  }
  final raw = _exactStringKeyedObject(decoded, _kDiscoveryKeys);
  final version = raw['v'];
  if (version is! int || version != kBrowserBridgeAppIpcVersion) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unsupportedVersion,
    );
  }
  final host = raw['host'];
  if (host is! String || host != kBrowserBridgeAppIpcLoopbackHost) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.nonLoopback,
    );
  }
  final port = raw['port'];
  if (port is! int || port < 1 || port > 65535) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final token = raw['token'];
  if (token is! String || !isBrowserBridgeAppIpcTokenShape(token)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final pid = raw['pid'];
  if (pid is! int || pid <= 0) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final writtenAt = raw['written_at'];
  if (writtenAt is! int || writtenAt <= 0) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final presentedMac = raw['mac'];
  if (presentedMac is! String || !isBrowserBridgeAppIpcTokenShape(presentedMac)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final expectedMac = browserBridgeAppIpcDiscoveryMac(
    trust: trust,
    host: host,
    port: port,
    token: token,
    pid: pid,
    writtenAt: writtenAt,
  );
  if (!browserBridgeAppIpcConstantTimeEquals(expectedMac, presentedMac)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final now = (clock ?? DateTime.now)().toUtc();
  final written = DateTime.fromMillisecondsSinceEpoch(
    writtenAt * 1000,
    isUtc: true,
  );
  if (written.isAfter(now.add(const Duration(seconds: 60)))) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.stale);
  }
  if (now.difference(written) > kBrowserBridgeAppIpcDiscoveryTtl) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.stale);
  }
  final alive = processAlive ?? defaultBrowserBridgeAppIpcProcessAlive;
  if (!alive(pid)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.stale);
  }
  if (!browserBridgeAppIpcProcessMatches(
    pid: pid,
    expected: trust.expectedIdentity,
  )) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.identityMismatch,
    );
  }
  if (verifyPortOwner) {
    final owner = browserBridgeAppIpcListeningPid(port);
    if (owner == null || owner != pid) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.portOwnerMismatch,
      );
    }
  }
  return BrowserBridgeAppIpcEndpoint(
    host: host,
    port: port,
    token: token,
    pid: pid,
    writtenAt: writtenAt,
    mac: presentedMac,
  );
}

/// Atomic, current-user-only write. Refuses to publish through a symlink.
/// [trust] signs the endpoint; the written document does not carry the secret.
Future<void> writeBrowserBridgeAppIpcDiscovery(
  File file,
  BrowserBridgeAppIpcEndpoint endpoint, {
  required BrowserBridgeAppIpcTrust trust,
  String? operatingSystem,
}) async {
  if (endpoint.host != kBrowserBridgeAppIpcLoopbackHost) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.nonLoopback,
    );
  }
  if (!isBrowserBridgeAppIpcTokenShape(endpoint.token)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  rebindBrowserBridgeAppIpcTrust(trust, operatingSystem: operatingSystem);
  final os = operatingSystem ?? Platform.operatingSystem;
  final posix = browserBridgeAppIpcUsesPosixOwnership(os);
  final dir = file.parent;
  if (FileSystemEntity.isLinkSync(dir.path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  await dir.create(recursive: true);
  if (FileSystemEntity.isLinkSync(dir.path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  if (posix) {
    _posixChmod(dir.path, '700');
  }
  if (FileSystemEntity.isLinkSync(file.path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  final tmp = File(
    '${file.path}.tmp.$pid.${Random.secure().nextInt(1 << 32)}',
  );
  if (FileSystemEntity.isLinkSync(tmp.path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  final body = utf8.encode(jsonEncode(endpoint.toJson(trust)));
  if (body.length > kMaxBrowserBridgeAppIpcDiscoveryBytes) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.oversized,
    );
  }
  try {
    await tmp.writeAsBytes(body, flush: true);
    if (FileSystemEntity.isLinkSync(tmp.path)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.symlink,
      );
    }
    if (posix) {
      _posixChmod(tmp.path, '600');
      _assertPosixDiscoveryStat(tmp.statSync(), tmp.path, os);
    }
    await tmp.rename(file.path);
  } catch (error) {
    try {
      if (tmp.existsSync()) await tmp.delete();
    } catch (_) {}
    if (error is BrowserBridgeAppIpcException) rethrow;
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.internal,
    );
  }
  if (FileSystemEntity.isLinkSync(file.path)) {
    try {
      await file.delete();
    } catch (_) {}
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  if (posix) {
    _assertPosixDiscoveryStat(file.statSync(), file.path, os);
  }
}

/// Removes the discovery file. A symlink is deleted as a link, never followed.
Future<void> deleteBrowserBridgeAppIpcDiscovery(File file) async {
  try {
    if (FileSystemEntity.isLinkSync(file.path) || file.existsSync()) {
      await file.delete();
    }
  } on FileSystemException {
    // Best-effort teardown: a leftover file is stale and will be refused.
  }
}

bool defaultBrowserBridgeAppIpcProcessAlive(int pid) {
  if (pid <= 0) return false;
  if (Platform.isWindows) {
    // Windows process liveness is not `kill -0`. Do not pretend otherwise.
    try {
      final result = Process.runSync(
        windowsSystemExecutable('tasklist.exe'),
        <String>['/FI', 'PID eq $pid', '/FO', 'CSV', '/NH'],
      );
      if (result.exitCode != 0) return false;
      final out = (result.stdout as String).trim();
      if (out.isEmpty) return false;
      if (out.toLowerCase().startsWith('info:')) return false;
      return out.contains('"$pid"');
    } on ProcessException {
      // If the helper cannot run, defer to the loopback connect itself.
      return true;
    }
  }
  try {
    final result = Process.runSync('/bin/kill', <String>['-0', '$pid']);
    return result.exitCode == 0;
  } on ProcessException {
    return true;
  }
}

Uint8List encodeBrowserBridgeAppIpcFrame(Map<String, Object?> message) {
  final body = utf8.encode(jsonEncode(message));
  if (body.length > kMaxBrowserBridgeAppIpcFrameBytes) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.oversized,
    );
  }
  final frame = Uint8List(kNativeLengthPrefixBytes + body.length);
  ByteData.sublistView(frame, 0, kNativeLengthPrefixBytes)
      .setUint32(0, body.length, Endian.little);
  frame.setRange(kNativeLengthPrefixBytes, frame.length, body);
  return frame;
}

// ---------------------------------------------------------------------------
// Browser pairing (R20 A1; SF-SOL-03 / A-NEW-01)
// ---------------------------------------------------------------------------
//
// The discovery token authenticates the local account, not a browser. Any
// same-user process that can read `ipc.json` can open this server and send a
// well-formed request, with or without the shipping native host, and argv
// origins prove nothing. So the token alone grants status, never control.
//
// Control (connect, disconnect, and with disconnect the release of the kill
// switch) needs a pairing: a per-origin credential the app mints only after
// the user approves an in-app confirmation that shows a six-digit code. The
// extension popup shows the same code, so the user approves the browser they
// are looking at, not a prompt some other local program raised. The app keeps
// only a salted SHA-256 verifier per origin; the extension keeps the
// credential and presents it through the host on every request.
//
// Residual same-user risk, stated plainly: a process running as this user can
// still raise an unsolicited prompt (rate limited, one at a time), read the
// credential out of the browser profile, rewrite the app's pairing store on
// platforms without an app container, inject into the app or the browser, or
// drive the UI with synthetic input. Pairing removes silent control through
// this IPC; it does not turn a same-user process into an untrusted one.

/// How long an in-app pairing confirmation waits for the user.
const Duration kBrowserBridgePairingTtl = Duration(seconds: 120);

/// Extra time an approved pairing waits for its single credential pickup.
const Duration kBrowserBridgePairingPickupGrace = Duration(seconds: 15);

/// Quiet period after a denied or expired pairing before another may start.
const Duration kBrowserBridgePairingCooldown = Duration(seconds: 5);

/// Window and budget for pairing attempts, so a local program cannot keep
/// the confirmation on screen.
const Duration kBrowserBridgePairingRateWindow = Duration(minutes: 1);
const int kBrowserBridgePairingMaxBeginsPerWindow = 6;

/// At most one pairing per known origin; this bounds the store regardless.
const int kBrowserBridgePairingMaxRecords = 8;

const int kBrowserBridgePairingStoreVersion = 1;
const int kMaxBrowserBridgePairingStoreBytes = 8192;
const String kBrowserBridgePairingStoreFileName = 'browser_pairings.json';
const String _kBrowserBridgePairingVerifierDomain =
    'org.winsvpn.browser-bridge.pairing.v1';

/// Random 16-byte pairing handle, lowercase hex.
final RegExp kBrowserBridgePairingIdPattern = RegExp(r'^[0-9a-f]{32}$');

/// The only extensions the shipping app will pair with: the store ids in
/// `tools/native_messaging/manifests/store_ids.json`. A raw IPC caller can
/// claim any of them, which is why the user's approval, not the origin, is
/// what grants control. The origin binds a pairing to one browser so it can
/// be listed and revoked on its own.
const Map<String, String> kBrowserBridgeProductionPairingOrigins =
    <String, String>{
  'chrome-extension://lnehjdblendkagjbmdclepjalahdhbbn/': 'Google Chrome',
  'chrome-extension://glgihadopbjoandhoihghddecoibcldf/': 'Microsoft Edge',
  'companion@winsvpn.org': 'Firefox',
};

final RegExp _kBrowserBridgePairingOriginShape = RegExp(
  r'^(?:chrome-extension://[a-p]{32}/'
  r'|[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}'
  r'|\{[0-9A-Fa-f-]{36}\})$',
);

/// Syntax only. Membership in the known-origin table is checked separately.
bool isBrowserBridgePairingOriginShape(String origin) =>
    _kBrowserBridgePairingOriginShape.hasMatch(origin);

/// Salted, origin-bound verifier stored instead of the credential.
String browserBridgePairingVerifier(String origin, String credential) {
  return sha256
      .convert(utf8.encode(
        '$_kBrowserBridgePairingVerifierDomain\n$origin\n$credential\n',
      ))
      .toString();
}

/// What the app shows the user while a pairing waits.
class BrowserBridgePairingRequest {
  const BrowserBridgePairingRequest({
    required this.origin,
    required this.label,
    required this.code,
    required this.expiresAt,
  });

  final String origin;

  /// Browser name from the known-origin table. A claim, not a proof.
  final String label;

  /// Six digits, also shown in the extension popup.
  final String code;
  final DateTime expiresAt;
}

/// One remembered browser. Holds a verifier, never the credential.
class BrowserBridgePairingRecord {
  const BrowserBridgePairingRecord({
    required this.origin,
    required this.label,
    required this.verifier,
    required this.createdAt,
    required this.lastUsedAt,
  });

  final String origin;
  final String label;
  final String verifier;
  final DateTime createdAt;
  final DateTime lastUsedAt;

  BrowserBridgePairingRecord touched(DateTime at) => BrowserBridgePairingRecord(
        origin: origin,
        label: label,
        verifier: verifier,
        createdAt: createdAt,
        lastUsedAt: at,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'origin': origin,
        'label': label,
        'verifier': verifier,
        'created_at': createdAt.millisecondsSinceEpoch ~/ 1000,
        'last_used_at': lastUsedAt.millisecondsSinceEpoch ~/ 1000,
      };
}

/// A pairing answer as it crosses the app IPC. Every key is always present.
class BrowserBridgePairingAnswer {
  const BrowserBridgePairingAnswer({
    required this.state,
    this.pairingId = '',
    this.code = '',
    this.expiresInSeconds = 0,
    this.credential = '',
  });

  final BridgePairingFlowState state;
  final String pairingId;
  final String code;
  final int expiresInSeconds;
  final String credential;

  Map<String, Object?> toIpc() => <String, Object?>{
        'state': state.wire,
        'pairing_id': pairingId,
        'code': code,
        'expires_in': expiresInSeconds,
        'credential': credential,
      };
}

/// Shows the in-app confirmation. Completes true only on an explicit Allow.
typedef BrowserBridgePairingPrompt = Future<bool> Function(
  BrowserBridgePairingRequest request,
);

/// Persists the full record list. A throw makes the approval fail closed.
typedef BrowserBridgePairingPersist = Future<void> Function(
  List<BrowserBridgePairingRecord> records,
);

class _PendingBrowserPairing {
  _PendingBrowserPairing({
    required this.id,
    required this.request,
  });

  final String id;
  final BrowserBridgePairingRequest request;
  BridgePairingFlowState state = BridgePairingFlowState.pending;
  String credential = '';
  DateTime? pickupDeadline;

  /// The record this approval put into the registry, so an approval nobody
  /// collects can be taken back again.
  BrowserBridgePairingRecord? minted;
}

/// The pairing state machine. Pure Dart and clock-injected so every refusal
/// path is unit tested without a UI.
class BrowserBridgePairingRegistry {
  BrowserBridgePairingRegistry({
    Map<String, String> knownOrigins = kBrowserBridgeProductionPairingOrigins,
    this.prompt,
    this.available,
    this.persist,
    this.clock,
    Random? random,
    Iterable<BrowserBridgePairingRecord> records =
        const <BrowserBridgePairingRecord>[],
  })  : knownOrigins = Map<String, String>.unmodifiable(knownOrigins),
        _random = random ?? Random.secure() {
    replaceRecords(records);
  }

  final Map<String, String> knownOrigins;

  /// Attached by the app once it can show UI. Null means pairing unavailable.
  BrowserBridgePairingPrompt? prompt;

  /// False while the app must not ask (locked, decoy, logged out).
  bool Function()? available;

  final BrowserBridgePairingPersist? persist;
  final BrowserBridgeAppIpcClock? clock;
  final Random _random;

  final Map<String, BrowserBridgePairingRecord> _records =
      <String, BrowserBridgePairingRecord>{};
  _PendingBrowserPairing? _pending;
  DateTime? _cooldownUntil;
  final List<DateTime> _begins = <DateTime>[];
  final StreamController<void> _changes = StreamController<void>.broadcast();

  /// Fires after the remembered set or the pending request changes.
  Stream<void> get changes => _changes.stream;

  DateTime _now() => (clock ?? DateTime.now)().toUtc();

  List<BrowserBridgePairingRecord> get records {
    final list = _records.values.toList()
      ..sort((a, b) => a.origin.compareTo(b.origin));
    return List<BrowserBridgePairingRecord>.unmodifiable(list);
  }

  /// The request the app is (or should be) showing, if any.
  BrowserBridgePairingRequest? get pendingRequest {
    final pending = _pending;
    if (pending == null || pending.state != BridgePairingFlowState.pending) {
      return null;
    }
    return pending.request;
  }

  /// Load records without persisting. Unknown origins, malformed verifiers
  /// and anything past the bound are dropped: the store fails closed.
  void replaceRecords(Iterable<BrowserBridgePairingRecord> records) {
    _records.clear();
    for (final record in records) {
      if (_records.length >= kBrowserBridgePairingMaxRecords) break;
      if (!knownOrigins.containsKey(record.origin)) continue;
      if (!kBridgePairingCredentialPattern.hasMatch(record.verifier)) continue;
      _records[record.origin] = record;
    }
    _notify();
  }

  void _notify() {
    if (!_changes.isClosed) _changes.add(null);
  }

  bool isPaired(String? origin, String? credential) {
    if (origin == null || credential == null) return false;
    if (!kBridgePairingCredentialPattern.hasMatch(credential)) return false;
    final record = _records[origin];
    if (record == null) return false;
    return browserBridgeAppIpcConstantTimeEquals(
      record.verifier,
      browserBridgePairingVerifier(origin, credential),
    );
  }

  /// Record use in memory. Not persisted on its own, so status polling never
  /// writes to disk.
  void touch(String origin) {
    final record = _records[origin];
    if (record != null) _records[origin] = record.touched(_now());
  }

  void _expirePending(DateTime now) {
    final pending = _pending;
    if (pending == null) return;
    final deadline = pending.pickupDeadline ?? pending.request.expiresAt;
    if (!now.isBefore(deadline)) {
      _pending = null;
      _cooldownUntil = now.add(kBrowserBridgePairingCooldown);
      _dropUncollected(pending);
      _notify();
    }
  }

  /// An approved credential that was never collected grants nobody. The
  /// record it minted must not stay, or the app lists a browser that holds
  /// nothing (and, on a re-pair, has silently revoked the one that did).
  void _dropUncollected(_PendingBrowserPairing pending) {
    final minted = pending.minted;
    if (minted == null) return;
    pending.minted = null;
    pending.credential = '';
    final origin = pending.request.origin;
    if (!identical(_records[origin], minted)) return;
    _records.remove(origin);
    unawaited(_persistBestEffort());
  }

  Future<void> _persistBestEffort() async {
    try {
      await persist?.call(records);
    } catch (_) {
      // Memory is already correct; the next successful write catches up.
    }
  }

  String _hex(int bytes) {
    final buffer = StringBuffer();
    for (var i = 0; i < bytes; i++) {
      buffer.write(_random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  String _code() {
    final buffer = StringBuffer();
    for (var i = 0; i < 6; i++) {
      buffer.write(_random.nextInt(10));
    }
    return buffer.toString();
  }

  /// Start one in-app confirmation. Throws a closed refusal instead of
  /// queueing: unknown origin, unavailable UI, busy, or rate limited.
  BrowserBridgePairingAnswer begin(String origin) {
    final label = knownOrigins[origin];
    if (label == null) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.identityMismatch,
      );
    }
    final now = _now();
    _expirePending(now);
    final ask = prompt;
    final canAsk = available;
    if (ask == null || (canAsk != null && !canAsk())) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.pairingUnavailable,
      );
    }
    if (_pending != null) {
      throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.busy);
    }
    final cooldown = _cooldownUntil;
    if (cooldown != null && now.isBefore(cooldown)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.rateLimited,
      );
    }
    _begins.removeWhere(
      (DateTime at) => !now.isBefore(at.add(kBrowserBridgePairingRateWindow)),
    );
    if (_begins.length >= kBrowserBridgePairingMaxBeginsPerWindow) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.rateLimited,
      );
    }
    _begins.add(now);
    final pending = _PendingBrowserPairing(
      id: _hex(16),
      request: BrowserBridgePairingRequest(
        origin: origin,
        label: label,
        code: _code(),
        expiresAt: now.add(kBrowserBridgePairingTtl),
      ),
    );
    _pending = pending;
    _notify();
    unawaited(_ask(pending, ask));
    return BrowserBridgePairingAnswer(
      state: BridgePairingFlowState.pending,
      pairingId: pending.id,
      code: pending.request.code,
      expiresInSeconds: kBrowserBridgePairingTtl.inSeconds,
    );
  }

  Future<void> _ask(
    _PendingBrowserPairing pending,
    BrowserBridgePairingPrompt ask,
  ) async {
    var approved = false;
    try {
      final remaining = pending.request.expiresAt.difference(_now());
      if (remaining > Duration.zero) {
        approved = await ask(pending.request).timeout(
          remaining,
          onTimeout: () => false,
        );
      }
    } catch (_) {
      approved = false;
    }
    if (!identical(_pending, pending) ||
        pending.state != BridgePairingFlowState.pending) {
      return;
    }
    final now = _now();
    final canAsk = available;
    if (!approved ||
        !now.isBefore(pending.request.expiresAt) ||
        (canAsk != null && !canAsk())) {
      pending.state = now.isBefore(pending.request.expiresAt)
          ? BridgePairingFlowState.denied
          : BridgePairingFlowState.expired;
      pending.pickupDeadline = now.add(kBrowserBridgePairingPickupGrace);
      _cooldownUntil = now.add(kBrowserBridgePairingCooldown);
      _notify();
      return;
    }
    final origin = pending.request.origin;
    final previous = _records[origin];
    if (previous == null && _records.length >= kBrowserBridgePairingMaxRecords) {
      pending.state = BridgePairingFlowState.denied;
      pending.pickupDeadline = now.add(kBrowserBridgePairingPickupGrace);
      _notify();
      return;
    }
    final credential = _hex(32);
    final record = BrowserBridgePairingRecord(
      origin: origin,
      label: pending.request.label,
      verifier: browserBridgePairingVerifier(origin, credential),
      createdAt: now,
      lastUsedAt: now,
    );
    // One pairing per origin: approving again replaces, and so revokes, the
    // credential an earlier approval handed out for this browser.
    _records[origin] = record;
    pending.minted = record;
    try {
      await persist?.call(records);
    } catch (_) {
      pending.minted = null;
      if (identical(_records[origin], record)) {
        if (previous == null) {
          _records.remove(origin);
        } else {
          _records[origin] = previous;
        }
      }
      if (identical(_pending, pending)) {
        pending.state = BridgePairingFlowState.denied;
        pending.pickupDeadline = _now().add(kBrowserBridgePairingPickupGrace);
      }
      _notify();
      return;
    }
    if (!identical(_pending, pending)) {
      // Cancelled or expired while the store was being written. Nobody can
      // collect this credential, so the record must not outlive it.
      pending.minted = null;
      if (identical(_records[origin], record)) {
        _records.remove(origin);
        await _persistBestEffort();
      }
      _notify();
      return;
    }
    pending.state = BridgePairingFlowState.approved;
    pending.credential = credential;
    pending.pickupDeadline = _now().add(kBrowserBridgePairingPickupGrace);
    _notify();
  }

  /// State of [pairingId] for [origin]. A mismatch of either reads as
  /// expired, so a guess learns nothing. The credential leaves exactly once.
  BrowserBridgePairingAnswer poll(String origin, String pairingId) {
    final now = _now();
    _expirePending(now);
    final pending = _pending;
    if (pending == null ||
        !kBrowserBridgePairingIdPattern.hasMatch(pairingId) ||
        !browserBridgeAppIpcConstantTimeEquals(pending.id, pairingId) ||
        pending.request.origin != origin) {
      return const BrowserBridgePairingAnswer(
        state: BridgePairingFlowState.expired,
      );
    }
    if (pending.state == BridgePairingFlowState.pending) {
      final left = pending.request.expiresAt.difference(now).inSeconds;
      return BrowserBridgePairingAnswer(
        state: BridgePairingFlowState.pending,
        pairingId: pending.id,
        code: pending.request.code,
        expiresInSeconds: left < 1 ? 1 : left,
      );
    }
    _pending = null;
    _notify();
    if (pending.state == BridgePairingFlowState.approved &&
        pending.credential.isNotEmpty) {
      final credential = pending.credential;
      pending.credential = '';
      pending.minted = null;
      return BrowserBridgePairingAnswer(
        state: BridgePairingFlowState.approved,
        credential: credential,
      );
    }
    return BrowserBridgePairingAnswer(state: pending.state);
  }

  /// Drop the pending confirmation (the app is stopping or locking).
  void cancelPending() {
    final pending = _pending;
    if (pending == null) return;
    _pending = null;
    _cooldownUntil = _now().add(kBrowserBridgePairingCooldown);
    _dropUncollected(pending);
    _notify();
  }

  /// Forget one browser. The app's settings use this without a credential.
  ///
  /// The record leaves memory first, so control stops at once. If the store
  /// write then fails this throws, so the caller can tell the user that the
  /// revocation will not survive a restart.
  Future<bool> revoke(String origin) async {
    if (_records.remove(origin) == null) return false;
    _notify();
    try {
      await persist?.call(records);
    } catch (_) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.internal,
      );
    }
    return true;
  }

  /// Forget a browser on its own request; it must present its pairing.
  Future<bool> revokePresented(String origin, String credential) async {
    if (!isPaired(origin, credential)) return false;
    return revoke(origin);
  }

  /// Forget every browser (account reset or a user's "revoke all").
  Future<void> revokeAll() async {
    cancelPending();
    if (_records.isEmpty) return;
    _records.clear();
    _notify();
    try {
      await persist?.call(records);
    } catch (_) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.internal,
      );
    }
  }

  Future<void> dispose() async {
    _pending = null;
    await _changes.close();
  }
}

/// Serialise records for the app's pairing store.
String encodeBrowserBridgePairingStore(
  Iterable<BrowserBridgePairingRecord> records,
) {
  return jsonEncode(<String, Object?>{
    'v': kBrowserBridgePairingStoreVersion,
    'pairings': records
        .map((BrowserBridgePairingRecord record) => record.toJson())
        .toList(),
  });
}

/// Parse the app's pairing store strictly. Anything unexpected is an empty
/// store: losing pairings re-prompts, keeping a corrupt one could grant.
List<BrowserBridgePairingRecord> decodeBrowserBridgePairingStore(String text) {
  try {
    if (utf8.encode(text).length > kMaxBrowserBridgePairingStoreBytes) {
      return const <BrowserBridgePairingRecord>[];
    }
    final root = _exactStringKeyedObject(
      jsonDecode(text),
      const <String>{'v', 'pairings'},
    );
    if (root['v'] != kBrowserBridgePairingStoreVersion) {
      return const <BrowserBridgePairingRecord>[];
    }
    final list = root['pairings'];
    if (list is! List || list.length > kBrowserBridgePairingMaxRecords) {
      return const <BrowserBridgePairingRecord>[];
    }
    final out = <BrowserBridgePairingRecord>[];
    final seen = <String>{};
    for (final item in list) {
      final map = _exactStringKeyedObject(item, const <String>{
        'origin',
        'label',
        'verifier',
        'created_at',
        'last_used_at',
      });
      final origin = map['origin'];
      final label = map['label'];
      final verifier = map['verifier'];
      final created = map['created_at'];
      final used = map['last_used_at'];
      if (origin is! String ||
          !isBrowserBridgePairingOriginShape(origin) ||
          !seen.add(origin) ||
          label is! String ||
          label.isEmpty ||
          label.length > 64 ||
          verifier is! String ||
          !kBridgePairingCredentialPattern.hasMatch(verifier) ||
          created is! int ||
          used is! int ||
          created < 0 ||
          used < 0) {
        return const <BrowserBridgePairingRecord>[];
      }
      out.add(BrowserBridgePairingRecord(
        origin: origin,
        label: label,
        verifier: verifier,
        createdAt:
            DateTime.fromMillisecondsSinceEpoch(created * 1000, isUtc: true),
        lastUsedAt:
            DateTime.fromMillisecondsSinceEpoch(used * 1000, isUtc: true),
      ));
    }
    return out;
  } catch (_) {
    return const <BrowserBridgePairingRecord>[];
  }
}

/// Read the pairing store. A symlink, an oversized file or a non-file reads
/// as empty.
Future<List<BrowserBridgePairingRecord>> readBrowserBridgePairingStore(
  File file,
) async {
  try {
    if (FileSystemEntity.isLinkSync(file.path)) {
      return const <BrowserBridgePairingRecord>[];
    }
    if (FileSystemEntity.typeSync(file.path, followLinks: false) !=
        FileSystemEntityType.file) {
      return const <BrowserBridgePairingRecord>[];
    }
    final bytes = await file.readAsBytes();
    if (bytes.length > kMaxBrowserBridgePairingStoreBytes) {
      return const <BrowserBridgePairingRecord>[];
    }
    return decodeBrowserBridgePairingStore(utf8.decode(bytes));
  } catch (_) {
    return const <BrowserBridgePairingRecord>[];
  }
}

/// Write the pairing store atomically, current-user only on POSIX.
Future<void> writeBrowserBridgePairingStore(
  File file,
  Iterable<BrowserBridgePairingRecord> records, {
  String? operatingSystem,
}) async {
  final os = operatingSystem ?? Platform.operatingSystem;
  final posix = browserBridgeAppIpcUsesPosixOwnership(os);
  final body = utf8.encode(encodeBrowserBridgePairingStore(records));
  if (body.length > kMaxBrowserBridgePairingStoreBytes) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.oversized,
    );
  }
  final dir = file.parent;
  if (FileSystemEntity.isLinkSync(dir.path) ||
      FileSystemEntity.isLinkSync(file.path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
  await dir.create(recursive: true);
  final tmp = File(
    '${file.path}.tmp.$pid.${Random.secure().nextInt(1 << 32)}',
  );
  try {
    await tmp.writeAsBytes(body, flush: true);
    if (FileSystemEntity.isLinkSync(tmp.path)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.symlink,
      );
    }
    if (posix) {
      _posixChmod(tmp.path, '600');
    }
    await tmp.rename(file.path);
  } catch (error) {
    try {
      if (tmp.existsSync()) await tmp.delete();
    } catch (_) {}
    if (error is BrowserBridgeAppIpcException) rethrow;
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.internal,
    );
  }
}

/// Desktop-app half: loopback listener, discovery publisher, command server.
class BrowserBridgeAppIpcServer {
  BrowserBridgeAppIpcServer({
    required this.snapshot,
    required this.onCommand,
    this.pairing,
    File? discoveryFile,
    this.trust,
    this.clock,
    this.processAlive,
    String? operatingSystem,
  })  : discoveryFile = discoveryFile ??
            defaultBrowserBridgeAppIpcDiscoveryFile(
              operatingSystem: operatingSystem,
            ),
        operatingSystem = operatingSystem ?? Platform.operatingSystem;

  final BrowserBridgeAppIpcSnapshotReader snapshot;
  final BrowserBridgeAppIpcCommandHandler onCommand;

  /// Pairing state machine. Null means no caller can ever be paired, so the
  /// server answers status only and refuses every control (the 1.0.16 A2
  /// posture).
  final BrowserBridgePairingRegistry? pairing;
  bool _controlPending = false;
  final File discoveryFile;
  final BrowserBridgeAppIpcTrust? trust;
  final BrowserBridgeAppIpcClock? clock;
  final BrowserBridgeAppIpcProcessLiveness? processAlive;
  final String operatingSystem;

  ServerSocket? _listener;
  Timer? _heartbeat;
  String? _token;
  BrowserBridgeAppIpcTrust? _boundTrust;
  Future<void> _queue = Future<void>.value();
  final Set<Future<void>> _publications = <Future<void>>{};
  int _lifecycleEpoch = 0;
  final Set<String> _seenIds = <String>{};
  final List<String> _seenOrder = <String>[];
  bool _started = false;

  bool get isRunning => _started && _listener != null;

  int get port => _listener?.port ?? 0;

  /// In-memory token. Tests may compare against discovery; production never
  /// logs this. Returns null when the listener is down.
  String? get tokenForTest => _token;

  BrowserBridgeAppIpcTrust? get trustForTest => _boundTrust;

  Future<void> start() async {
    if (_started) return;
    final epoch = _lifecycleEpoch;
    final boundTrust = trust ??
        loadBrowserBridgeAppIpcTrust(operatingSystem: operatingSystem);
    rebindBrowserBridgeAppIpcTrust(
      boundTrust,
      operatingSystem: operatingSystem,
    );
    if (!browserBridgeAppIpcProcessMatches(
      pid: pid,
      expected: boundTrust.expectedIdentity,
    )) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.unauthenticatedIdentity,
      );
    }
    final listener = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      shared: false,
    );
    if (listener.address.address != kBrowserBridgeAppIpcLoopbackHost) {
      await listener.close();
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.nonLoopback,
      );
    }
    if (epoch != _lifecycleEpoch) {
      await listener.close();
      return;
    }
    final token = generateBrowserBridgeAppIpcToken();
    _listener = listener;
    _token = token;
    _boundTrust = boundTrust;
    _started = true;
    listener.listen(_onConnection, onError: (_) {}, cancelOnError: false);
    try {
      await _publishDiscoveryTracked();
    } catch (error) {
      await stop();
      if (error is BrowserBridgeAppIpcException) rethrow;
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.internal,
      );
    }
    if (epoch != _lifecycleEpoch) return;
    _heartbeat = Timer.periodic(kBrowserBridgeAppIpcHeartbeat, (_) {
      unawaited(_publishDiscoveryBestEffort());
    });
  }

  Future<void> stop() async {
    _lifecycleEpoch++;
    _started = false;
    _heartbeat?.cancel();
    _heartbeat = null;
    final listener = _listener;
    _listener = null;
    _token = null;
    _boundTrust = null;
    _seenIds.clear();
    _seenOrder.clear();
    try {
      await listener?.close();
    } catch (_) {}
    try {
      await Future.wait<void>(_publications.toList());
    } catch (_) {}
    await deleteBrowserBridgeAppIpcDiscovery(discoveryFile);
  }

  Future<void> _publishDiscoveryTracked() {
    final published = _publishDiscovery();
    _publications.add(published);
    unawaited(published.then<void>(
      (_) {
        _publications.remove(published);
      },
      onError: (Object _, StackTrace __) {
        _publications.remove(published);
      },
    ));
    return published;
  }

  Future<void> _publishDiscovery() async {
    final listener = _listener;
    final token = _token;
    final boundTrust = _boundTrust;
    if (listener == null || token == null || boundTrust == null) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.appAbsent,
      );
    }
    rebindBrowserBridgeAppIpcTrust(
      boundTrust,
      operatingSystem: operatingSystem,
    );
    final writtenAt =
        ((clock ?? DateTime.now)().toUtc().millisecondsSinceEpoch / 1000)
            .floor();
    await writeBrowserBridgeAppIpcDiscovery(
      discoveryFile,
      BrowserBridgeAppIpcEndpoint(
        host: kBrowserBridgeAppIpcLoopbackHost,
        port: listener.port,
        token: token,
        pid: pid,
        writtenAt: writtenAt,
      ),
      trust: boundTrust,
      operatingSystem: operatingSystem,
    );
  }

  Future<void> _publishDiscoveryBestEffort() async {
    try {
      await _publishDiscoveryTracked();
    } catch (_) {}
  }

  void _onConnection(Socket socket) {
    unawaited(_handleConnection(socket));
  }

  Future<void> _handleConnection(Socket socket) async {
    try {
      if (socket.remoteAddress.address != kBrowserBridgeAppIpcLoopbackHost) {
        socket.destroy();
        return;
      }
      final body = await _readFrame(
        socket,
        timeout: kBrowserBridgeAppIpcIoTimeout,
      );
      final reply = await _dispatch(body);
      socket.add(encodeBrowserBridgeAppIpcFrame(reply));
      await socket.flush().timeout(kBrowserBridgeAppIpcIoTimeout);
    } catch (_) {
      // No reply on a framing/schema failure before auth: probing the port
      // must not yield a useful envelope.
    } finally {
      try {
        await socket.close();
      } catch (_) {
        socket.destroy();
      }
    }
  }

  Future<Map<String, Object?>> _dispatch(Uint8List body) async {
    Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(body));
    } catch (_) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    final raw = _requestObject(decoded);
    final id = raw['id'];
    if (id is! String || !kBrowserBridgeAppIpcRequestIdPattern.hasMatch(id)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    final version = raw['v'];
    if (version is! int || version != kBrowserBridgeAppIpcVersion) {
      return _errorReply(id, BrowserBridgeAppIpcError.unsupportedVersion);
    }
    final presented = raw['token'];
    if (presented is! String) {
      return _errorReply(id, BrowserBridgeAppIpcError.malformed);
    }
    final expected = _token;
    if (expected == null ||
        !browserBridgeAppIpcConstantTimeEquals(expected, presented)) {
      return _errorReply(id, BrowserBridgeAppIpcError.tokenMismatch);
    }
    if (!_rememberRequestId(id)) {
      return _errorReply(id, BrowserBridgeAppIpcError.duplicateRequestId);
    }
    final type = raw['type'];
    if (type is! String) {
      return _errorReply(id, BrowserBridgeAppIpcError.malformed);
    }
    final command = BrowserBridgeAppIpcCommand.fromWire(type);
    if (command == null) {
      return _errorReply(id, BrowserBridgeAppIpcError.malformed);
    }
    final origin = raw['origin'];
    final credential = raw['credential'];
    final pairingId = raw['pairing_id'];
    if ((origin != null &&
            (origin is! String || !isBrowserBridgePairingOriginShape(origin))) ||
        (credential != null &&
            (credential is! String ||
                !kBridgePairingCredentialPattern.hasMatch(credential))) ||
        (pairingId != null &&
            (pairingId is! String ||
                !kBrowserBridgePairingIdPattern.hasMatch(pairingId)))) {
      return _errorReply(id, BrowserBridgeAppIpcError.malformed);
    }
    final presentedOrigin = origin as String?;
    final presentedCredential = credential as String?;
    final presentedPairingId = pairingId as String?;
    if (!_requestFieldsFit(
      command,
      origin: presentedOrigin != null,
      credential: presentedCredential != null,
      pairingId: presentedPairingId != null,
    )) {
      return _errorReply(id, BrowserBridgeAppIpcError.malformed);
    }
    final registry = pairing;
    bool paired() =>
        registry != null &&
        registry.isPaired(presentedOrigin, presentedCredential);

    switch (command) {
      case BrowserBridgeAppIpcCommand.getStatus:
        return _statusReply(id, command, paired: paired());
      case BrowserBridgeAppIpcCommand.pairBegin:
        if (registry == null) {
          return _errorReply(id, BrowserBridgeAppIpcError.pairingUnavailable);
        }
        try {
          return _pairingReply(id, command, registry.begin(presentedOrigin!));
        } on BrowserBridgeAppIpcException catch (error) {
          return _errorReply(id, error.code);
        } catch (_) {
          return _errorReply(id, BrowserBridgeAppIpcError.internal);
        }
      case BrowserBridgeAppIpcCommand.pairPoll:
        if (registry == null) {
          return _errorReply(id, BrowserBridgeAppIpcError.pairingUnavailable);
        }
        return _pairingReply(
          id,
          command,
          registry.poll(presentedOrigin!, presentedPairingId!),
        );
      case BrowserBridgeAppIpcCommand.pairRevoke:
        if (registry == null || !paired()) {
          return _errorReply(id, BrowserBridgeAppIpcError.notPaired);
        }
        try {
          await registry.revokePresented(
            presentedOrigin!,
            presentedCredential!,
          );
        } catch (_) {
          return _errorReply(id, BrowserBridgeAppIpcError.internal);
        }
        return _statusReply(id, command, paired: false);
      case BrowserBridgeAppIpcCommand.requestConnect:
      case BrowserBridgeAppIpcCommand.requestDisconnect:
        break;
    }

    // A discovery token authenticates the local account, not a browser.
    // Control needs the pairing the user approved in the app, presented on
    // this very request. Disconnect releases the kill switch, so it is gated
    // exactly like connect.
    if (!paired()) {
      return _errorReply(id, BrowserBridgeAppIpcError.notPaired);
    }
    // Refuse concurrent controls instead of queuing stale requests.
    if (_controlPending) {
      return _errorReply(id, BrowserBridgeAppIpcError.busy);
    }
    _controlPending = true;
    try {
      return await _serialized(() async {
        if (!isRunning || _token != expected) {
          return _errorReply(
            id,
            BrowserBridgeAppIpcError.appAbsent,
          );
        }
        // Revoked while queued behind another operation: refuse.
        if (!paired()) {
          return _errorReply(id, BrowserBridgeAppIpcError.notPaired);
        }
        try {
          registry!.touch(presentedOrigin!);
          await onCommand(command);
          if (!isRunning || _token != expected) {
            return _errorReply(id, BrowserBridgeAppIpcError.appAbsent);
          }
          return _statusReply(id, command, paired: paired());
        } on BrowserBridgeAppIpcException catch (error) {
          return _errorReply(id, error.code);
        } catch (_) {
          return _errorReply(id, BrowserBridgeAppIpcError.internal);
        }
      });
    } finally {
      _controlPending = false;
    }
  }

  Map<String, Object?> _statusReply(
    String id,
    BrowserBridgeAppIpcCommand command, {
    required bool paired,
  }) {
    try {
      final status = snapshot().copyWithPairing(
        paired ? BridgePairingStatus.paired : BridgePairingStatus.unpaired,
      );
      return <String, Object?>{
        'v': kBrowserBridgeAppIpcVersion,
        'id': id,
        'ok': true,
        'type': command.wire,
        'status': status.toWire(),
      };
    } catch (_) {
      return _errorReply(id, BrowserBridgeAppIpcError.internal);
    }
  }

  Map<String, Object?> _pairingReply(
    String id,
    BrowserBridgeAppIpcCommand command,
    BrowserBridgePairingAnswer answer,
  ) {
    return <String, Object?>{
      'v': kBrowserBridgeAppIpcVersion,
      'id': id,
      'ok': true,
      'type': command.wire,
      'pairing': answer.toIpc(),
    };
  }

  Future<T> _serialized<T>(Future<T> Function() op) {
    final done = Completer<T>();
    _queue = _queue.then((_) async {
      try {
        done.complete(await op());
      } catch (error, stack) {
        done.completeError(error, stack);
      }
    });
    return done.future;
  }

  bool _rememberRequestId(String id) {
    if (_seenIds.contains(id)) return false;
    _seenIds.add(id);
    _seenOrder.add(id);
    while (_seenOrder.length > kBrowserBridgeAppIpcMaxSeenRequestIds) {
      _seenIds.remove(_seenOrder.removeAt(0));
    }
    return true;
  }
}

/// The request envelope: every key of [_kRequestKeys], plus any of
/// [_kOptionalRequestKeys], and nothing else.
Map<String, Object?> _requestObject(Object? decoded) {
  if (decoded is! Map || decoded.keys.any((Object? key) => key is! String)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final map = Map<String, Object?>.from(decoded);
  for (final key in _kRequestKeys) {
    if (!map.containsKey(key)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
  }
  for (final key in map.keys) {
    if (!_kRequestKeys.contains(key) && !_kOptionalRequestKeys.contains(key)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
  }
  return map;
}

/// Which optional fields each command requires (true), allows (null) or
/// forbids (false). Anything else is malformed rather than ignored.
bool _requestFieldsFit(
  BrowserBridgeAppIpcCommand command, {
  required bool origin,
  required bool credential,
  required bool pairingId,
}) {
  switch (command) {
    case BrowserBridgeAppIpcCommand.getStatus:
      return !pairingId && (!credential || origin);
    case BrowserBridgeAppIpcCommand.requestConnect:
    case BrowserBridgeAppIpcCommand.requestDisconnect:
    case BrowserBridgeAppIpcCommand.pairRevoke:
      return origin && credential && !pairingId;
    case BrowserBridgeAppIpcCommand.pairBegin:
      return origin && !credential && !pairingId;
    case BrowserBridgeAppIpcCommand.pairPoll:
      return origin && pairingId && !credential;
  }
}

Map<String, Object?> _errorReply(String id, BrowserBridgeAppIpcError code) {
  return <String, Object?>{
    'v': kBrowserBridgeAppIpcVersion,
    'id': id,
    'ok': false,
    'error': code.wire,
  };
}

/// Native-host half: validate discovery, connect only to IPv4 loopback, auth.
class BrowserBridgeAppIpcClient {
  BrowserBridgeAppIpcClient({
    File? discoveryFile,
    this.trust,
    this.clock,
    this.processAlive,
    String? operatingSystem,
  })  : discoveryFile = discoveryFile ??
            defaultBrowserBridgeAppIpcDiscoveryFile(
              operatingSystem: operatingSystem,
            ),
        operatingSystem = operatingSystem ?? Platform.operatingSystem;

  final File discoveryFile;
  final BrowserBridgeAppIpcTrust? trust;
  final BrowserBridgeAppIpcClock? clock;
  final BrowserBridgeAppIpcProcessLiveness? processAlive;
  final String operatingSystem;

  Future<BridgeStatus> getStatus({
    String? requestId,
    String? origin,
    String? credential,
  }) {
    return invoke(
      BrowserBridgeAppIpcCommand.getStatus,
      requestId: requestId,
      origin: origin,
      credential: credential,
    );
  }

  Future<BridgeStatus> requestConnect({
    String? requestId,
    String? origin,
    String? credential,
  }) {
    return invoke(
      BrowserBridgeAppIpcCommand.requestConnect,
      requestId: requestId,
      origin: origin,
      credential: credential,
    );
  }

  Future<BridgeStatus> requestDisconnect({
    String? requestId,
    String? origin,
    String? credential,
  }) {
    return invoke(
      BrowserBridgeAppIpcCommand.requestDisconnect,
      requestId: requestId,
      origin: origin,
      credential: credential,
    );
  }

  Future<BridgeStatus> pairRevoke({
    required String origin,
    required String credential,
    String? requestId,
  }) {
    return invoke(
      BrowserBridgeAppIpcCommand.pairRevoke,
      requestId: requestId,
      origin: origin,
      credential: credential,
    );
  }

  /// Start or read a pairing. Returns the app's answer; refusals throw.
  Future<BrowserBridgePairingAnswer> pairBegin({
    required String origin,
    String? requestId,
  }) async {
    final payload = await _exchange(
      BrowserBridgeAppIpcCommand.pairBegin,
      requestId: requestId,
      fields: <String, Object?>{'origin': origin},
      payloadKey: 'pairing',
    );
    return parseBrowserBridgeAppIpcPairing(payload);
  }

  Future<BrowserBridgePairingAnswer> pairPoll({
    required String origin,
    required String pairingId,
    String? requestId,
  }) async {
    final payload = await _exchange(
      BrowserBridgeAppIpcCommand.pairPoll,
      requestId: requestId,
      fields: <String, Object?>{'origin': origin, 'pairing_id': pairingId},
      payloadKey: 'pairing',
    );
    return parseBrowserBridgeAppIpcPairing(payload);
  }

  /// Fail-closed wrapper used by the shipping native host: any IPC problem
  /// becomes `app_not_running`. Never throws. CONNECTED is admitted only
  /// after authenticated app identity plus real VPN state (`proxyReady`).
  Future<BridgeStatus> invokeFailClosed({
    required BrowserBridgeAppIpcCommand command,
    required BridgeWinnState winn,
    String? requestId,
    String? origin,
    String? credential,
  }) async {
    try {
      final status = await invoke(
        command,
        requestId: requestId,
        origin: origin,
        credential: credential,
      );
      return browserBridgeAppIpcAdmitStatus(
        status,
        authenticatedAppIdentity: true,
        winn: winn,
      );
    } catch (_) {
      return BridgeStatus.appNotRunning(winn: winn);
    }
  }

  Future<BridgeStatus> invoke(
    BrowserBridgeAppIpcCommand command, {
    String? requestId,
    String? origin,
    String? credential,
  }) async {
    if (command == BrowserBridgeAppIpcCommand.pairBegin ||
        command == BrowserBridgeAppIpcCommand.pairPoll) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    final payload = await _exchange(
      command,
      requestId: requestId,
      fields: <String, Object?>{
        if (origin != null) 'origin': origin,
        if (credential != null) 'credential': credential,
      },
      payloadKey: 'status',
    );
    return parseBrowserBridgeAppIpcStatus(payload);
  }

  Future<Object?> _exchange(
    BrowserBridgeAppIpcCommand command, {
    required String? requestId,
    required Map<String, Object?> fields,
    required String payloadKey,
  }) async {
    final boundTrust = trust ??
        loadBrowserBridgeAppIpcTrust(operatingSystem: operatingSystem);
    rebindBrowserBridgeAppIpcTrust(
      boundTrust,
      operatingSystem: operatingSystem,
    );
    final endpoint = readBrowserBridgeAppIpcDiscovery(
      discoveryFile,
      trust: boundTrust,
      clock: clock,
      processAlive: processAlive,
      operatingSystem: operatingSystem,
    );
    // Connect ONLY to the IPv4 loopback object, never to the string from the
    // file, so a confused parser cannot be pointed at anything else.
    if (endpoint.host != kBrowserBridgeAppIpcLoopbackHost) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.nonLoopback,
      );
    }
    Socket socket;
    try {
      socket = await Socket.connect(
        InternetAddress.loopbackIPv4,
        endpoint.port,
        timeout: kBrowserBridgeAppIpcIoTimeout,
      );
    } on SocketException {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.appAbsent,
      );
    }
    try {
      if (socket.address.address != kBrowserBridgeAppIpcLoopbackHost ||
          socket.remoteAddress.address != kBrowserBridgeAppIpcLoopbackHost) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.nonLoopback,
        );
      }
      final rebound = readBrowserBridgeAppIpcDiscovery(
        discoveryFile,
        trust: boundTrust,
        clock: clock,
        processAlive: processAlive,
        operatingSystem: operatingSystem,
      );
      if (rebound.port != endpoint.port ||
          rebound.pid != endpoint.pid ||
          !browserBridgeAppIpcConstantTimeEquals(
            rebound.token,
            endpoint.token,
          ) ||
          !browserBridgeAppIpcConstantTimeEquals(rebound.mac, endpoint.mac)) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.stale,
        );
      }
      final id = requestId ?? _newRequestId();
      if (!kBrowserBridgeAppIpcRequestIdPattern.hasMatch(id)) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      final quick = command == BrowserBridgeAppIpcCommand.getStatus ||
          command == BrowserBridgeAppIpcCommand.pairBegin ||
          command == BrowserBridgeAppIpcCommand.pairPoll;
      final replyTimeout = quick
          ? kBrowserBridgeAppIpcIoTimeout
          : kBrowserBridgeAppIpcCommandTimeout;
      socket.add(
        encodeBrowserBridgeAppIpcFrame(<String, Object?>{
          'v': kBrowserBridgeAppIpcVersion,
          'id': id,
          'token': endpoint.token,
          'type': command.wire,
          ...fields,
        }),
      );
      await socket.flush().timeout(kBrowserBridgeAppIpcIoTimeout);
      final body = await _readFrame(socket, timeout: replyTimeout);
      return _parseReply(body, id, payloadKey);
    } finally {
      try {
        await socket.close();
      } catch (_) {
        socket.destroy();
      }
    }
  }
}

Object? _parseReply(Uint8List body, String expectedId, String payloadKey) {
  Object? decoded;
  try {
    decoded = jsonDecode(utf8.decode(body));
  } catch (_) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (decoded is! Map) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (decoded.keys.any((Object? key) => key is! String)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final raw = Map<String, Object?>.from(decoded);
  final version = raw['v'];
  if (version is! int || version != kBrowserBridgeAppIpcVersion) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unsupportedVersion,
    );
  }
  final id = raw['id'];
  if (id is! String || id != expectedId) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final ok = raw['ok'];
  if (ok is! bool) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (!ok) {
    if (raw.length != 4 || !raw.containsKey('error')) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    final error = raw['error'];
    if (error is! String) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    for (final code in BrowserBridgeAppIpcError.values) {
      if (code.wire == error) {
        throw BrowserBridgeAppIpcException(code);
      }
    }
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (raw.length != 5 ||
      raw['type'] is! String ||
      !raw.containsKey(payloadKey)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  return raw[payloadKey];
}

/// Parse a pairing answer with its closed key set. A credential is accepted
/// only on an approval, a code only while pending.
BrowserBridgePairingAnswer parseBrowserBridgeAppIpcPairing(Object? raw) {
  final map = _exactStringKeyedObject(raw, _kPairingReplyKeys);
  final stateWire = map['state'];
  BridgePairingFlowState? state;
  for (final value in BridgePairingFlowState.values) {
    if (value.wire == stateWire) state = value;
  }
  final pairingId = map['pairing_id'];
  final code = map['code'];
  final expiresIn = map['expires_in'];
  final credential = map['credential'];
  if (state == null ||
      pairingId is! String ||
      code is! String ||
      expiresIn is! int ||
      credential is! String ||
      expiresIn < 0 ||
      expiresIn > kBrowserBridgePairingTtl.inSeconds) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final pending = state == BridgePairingFlowState.pending;
  final approved = state == BridgePairingFlowState.approved;
  if (pending !=
          (pairingId.isNotEmpty &&
              kBrowserBridgePairingIdPattern.hasMatch(pairingId)) ||
      (pairingId.isNotEmpty && !pending) ||
      pending != kBridgePairingCodePattern.hasMatch(code) ||
      (code.isNotEmpty && !pending) ||
      approved != kBridgePairingCredentialPattern.hasMatch(credential) ||
      (credential.isNotEmpty && !approved)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  return BrowserBridgePairingAnswer(
    state: state,
    pairingId: pairingId,
    code: code,
    expiresInSeconds: expiresIn,
    credential: credential,
  );
}

BridgeStatus parseBrowserBridgeAppIpcStatus(Object? raw) {
  final map = _exactStringKeyedObject(raw, _kStatusKeys);
  final statusWire = map['status'];
  if (statusWire is! String) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  var statusKnown = false;
  var status = BridgeTunnelStatus.unknown;
  for (final value in BridgeTunnelStatus.values) {
    if (value.wire == statusWire) {
      status = value;
      statusKnown = true;
      break;
    }
  }
  if (!statusKnown) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final detailWire = map['detail'];
  if (detailWire is! String) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  BridgeDetailCode? detail;
  for (final value in BridgeDetailCode.values) {
    if (value.wire == detailWire) {
      detail = value;
      break;
    }
  }
  if (detail == null) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final winnWire = map['winn'];
  if (winnWire is! String) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  BridgeWinnState? winn;
  for (final value in BridgeWinnState.values) {
    if (value.wire == winnWire) {
      winn = value;
      break;
    }
  }
  if (winn == null) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final selectedSlug = map['selectedSlug'];
  if (selectedSlug is! String ||
      (selectedSlug.isNotEmpty && !kSlugPattern.hasMatch(selectedSlug))) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final canRequestConnect = map['canRequestConnect'];
  final proxyReady = map['proxyReady'];
  final proxyTls = map['proxyTls'];
  if (canRequestConnect is! bool || proxyReady is! bool || proxyTls is! bool) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final proxyPort = _boundedInt(map['proxyPort'], 0, 65535);
  final proxyTlsPort = _boundedInt(map['proxyTlsPort'], 0, 65535);
  final rxKib = _boundedInt(map['rxKib'], 0, kMaxOutboundInteger);
  final txKib = _boundedInt(map['txKib'], 0, kMaxOutboundInteger);
  final pairingWire = map['pairing'];
  BridgePairingStatus? pairing;
  for (final value in BridgePairingStatus.values) {
    if (value.wire == pairingWire) pairing = value;
  }
  if (pairing == null) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final nodesRaw = map['nodes'];
  if (nodesRaw is! List) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (nodesRaw.length > kBrowserBridgeAppIpcMaxNodes) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.oversized,
    );
  }
  final nodes = <BridgeNode>[];
  for (final node in nodesRaw) {
    final nodeMap = _exactStringKeyedObject(node, _kNodeKeys);
    final slug = nodeMap['slug'];
    final name = nodeMap['name'];
    final flag = nodeMap['flag'];
    if (slug is! String || name is! String || flag is! String) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    try {
      nodes.add(BridgeNode(slug: slug, name: name, flag: flag));
    } catch (_) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
  }
  return BridgeStatus(
    status: status,
    detail: detail,
    winn: winn,
    selectedSlug: selectedSlug,
    nodes: nodes,
    canRequestConnect: canRequestConnect,
    proxyPort: proxyPort,
    proxyReady: proxyReady,
    proxyTls: proxyTls,
    proxyTlsPort: proxyTlsPort,
    rxKib: rxKib,
    txKib: txKib,
    pairing: pairing,
  );
}

int _boundedInt(Object? value, int min, int max) {
  if (value is! int || value < min || value > max) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  return value;
}

Map<String, Object?> _exactStringKeyedObject(
  Object? raw,
  Set<String> keys,
) {
  if (raw is! Map) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  if (raw.keys.any((Object? key) => key is! String)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final map = Map<String, Object?>.from(raw);
  if (map.length != keys.length) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  for (final key in keys) {
    if (!map.containsKey(key)) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
  }
  return map;
}

const Set<String> _kDiscoveryTrustRootKeys = <String>{
  'secret',
  'identity',
  'identity_kind',
  'identity_value',
  'trust',
  'key',
  'mac_key',
  'hmac',
  'root',
};

class _BoundFileBytes {
  const _BoundFileBytes({
    required this.bytes,
    this.dev,
    this.ino,
    this.uid,
  });

  final Uint8List bytes;
  final int? dev;
  final int? ino;
  final int? uid;
}

_BoundFileBytes _bindRegularFileBytes(
  File file, {
  required int maxBytes,
  required String operatingSystem,
  bool ownerInstalledTrust = false,
}) {
  _assertPathNotSymlink(file.path);
  if (!file.existsSync()) {
    throw BrowserBridgeAppIpcException(
      ownerInstalledTrust
          ? BrowserBridgeAppIpcError.unauthenticatedIdentity
          : BrowserBridgeAppIpcError.missingDiscovery,
    );
  }
  _assertPathNotSymlink(file.path);
  final type = FileSystemEntity.typeSync(file.path, followLinks: false);
  if (type != FileSystemEntityType.file) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.notRegularFile,
    );
  }
  final before = _posixFileIdentity(file.path, operatingSystem);
  final stat = file.statSync();
  if (stat.size <= 0 || stat.size > maxBytes) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.oversized,
    );
  }
  if (!ownerInstalledTrust) {
    _assertPosixDiscoveryStat(stat, file.path, operatingSystem);
  }
  final bytes = file.readAsBytesSync();
  _assertPathNotSymlink(file.path);
  if (bytes.length > maxBytes) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.oversized,
    );
  }
  final after = _posixFileIdentity(file.path, operatingSystem);
  // On macOS and Linux an identity that could not be read is a refusal, not a
  // skipped check: the bytes are bound to the inode only if both reads agree.
  if (browserBridgeAppIpcUsesPosixOwnership(operatingSystem) &&
      (before == null || after == null)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.stale);
  }
  if (before != null && after != null && before != after) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.stale);
  }
  return _BoundFileBytes(
    bytes: Uint8List.fromList(bytes),
    dev: after?.dev ?? before?.dev,
    ino: after?.ino ?? before?.ino,
    uid: after?.uid ?? before?.uid,
  );
}

class _PosixFileIdentity {
  const _PosixFileIdentity({
    required this.dev,
    required this.ino,
    required this.uid,
  });

  final int dev;
  final int ino;
  final int uid;

  @override
  bool operator ==(Object other) {
    return other is _PosixFileIdentity &&
        other.dev == dev &&
        other.ino == ino &&
        other.uid == uid;
  }

  @override
  int get hashCode => Object.hash(dev, ino, uid);
}

_PosixFileIdentity? _posixFileIdentity(String path, String os) {
  if (!browserBridgeAppIpcUsesPosixOwnership(os)) return null;
  try {
    final args = Platform.isMacOS
        ? <String>['-f', '%d %i %u', path]
        : <String>['-c', '%d %i %u', path];
    final result = Process.runSync('/usr/bin/stat', args);
    if (result.exitCode != 0) return null;
    final parts = (result.stdout as String).trim().split(RegExp(r'\s+'));
    if (parts.length != 3) return null;
    final dev = int.tryParse(parts[0]);
    final ino = int.tryParse(parts[1]);
    final uid = int.tryParse(parts[2]);
    if (dev == null || ino == null || uid == null) return null;
    return _PosixFileIdentity(dev: dev, ino: ino, uid: uid);
  } on ProcessException {
    return null;
  }
}

Uint8List _hexToBytes(String hex) {
  if (!isBrowserBridgeAppIpcTokenShape(hex)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// True only for Identifier=org.winsvpn.app, TeamIdentifier=5YT8H4U72M,
/// a designated requirement that pins that team, a current valid code
/// signature, and not ad-hoc.
bool browserBridgeAppIpcMacosCodeSignatureAuthenticates(
  BrowserBridgeAppIpcMacosCodeSignature observed,
) {
  if (!observed.currentSignatureValid) return false;
  if (observed.adHoc) return false;
  if (observed.identifier != kBrowserBridgeAppIpcMacosBundleId) return false;
  // For a Mac App Store copy this line is the team pin: the MAS branch of
  // the verified requirement carries no team clause (Apple's leaf has no
  // OU, and that branch passes for any team), while TeamIdentifier is part
  // of the signed CodeDirectory that `codesign --verify` just validated.
  if (observed.teamIdentifier != kBrowserBridgeAppIpcMacosTeamIdentifier) {
    return false;
  }
  final requirement = observed.designatedRequirement;
  if (requirement.contains('anchor adhoc')) return false;
  if (!requirement.contains(
    'identifier "$kBrowserBridgeAppIpcMacosBundleId"',
  )) {
    return false;
  }
  // csreq prints the OU quoted when it starts with a digit and bare when it
  // starts with a letter; accept exactly those two spellings of this team.
  final teamOu = RegExp(
    r'certificate leaf\[subject\.OU\] = (?:"' +
        RegExp.escape(kBrowserBridgeAppIpcMacosTeamIdentifier) +
        r'"|' +
        RegExp.escape(kBrowserBridgeAppIpcMacosTeamIdentifier) +
        r'(?![0-9A-Za-z"]))',
  );
  if (!teamOu.hasMatch(requirement)) return false;
  return true;
}

BrowserBridgeAppIpcMacosCodeSignature? parseBrowserBridgeAppIpcMacosCodeSignature({
  required String displayText,
  required String designatedRequirementText,
  required bool verifySucceeded,
}) {
  final identifier = _macosCodesignField(displayText, 'Identifier');
  final team = _macosCodesignField(displayText, 'TeamIdentifier');
  if (identifier.isEmpty) return null;
  final adHoc = _macosCodesignIsAdHoc(displayText, designatedRequirementText, team);
  return BrowserBridgeAppIpcMacosCodeSignature(
    identifier: identifier,
    teamIdentifier: team,
    designatedRequirement: designatedRequirementText,
    currentSignatureValid: verifySucceeded,
    adHoc: adHoc,
  );
}

bool _macosCodesignIsAdHoc(
  String displayText,
  String designatedRequirementText,
  String teamIdentifier,
) {
  final folded = '$displayText\n$designatedRequirementText';
  if (folded.contains('(adhoc)') ||
      folded.contains('Signature=adhoc') ||
      folded.contains('anchor adhoc')) {
    return true;
  }
  if (teamIdentifier.isEmpty || teamIdentifier == 'not set') return true;
  return false;
}

String _macosCodesignField(String text, String key) {
  final match = RegExp('^$key=(.*)\$', multiLine: true).firstMatch(text);
  return match?.group(1)?.trim() ?? '';
}

/// Exact Program Files\\WinsVPN\\wins_vpn.exe plus a Valid Authenticode
/// chain whose subject equals the reviewed identity. A missing reviewed
/// identity is owner-blocked.
bool browserBridgeAppIpcWindowsInstalledExecutableAuthenticates({
  required String observedPath,
  required String programFiles,
  required BrowserBridgeAppIpcWindowsAuthenticode authenticode,
  required String? reviewedSubject,
  bool isLink = false,
}) {
  if (isLink) return false;
  if (reviewedSubject == null || reviewedSubject.isEmpty) return false;
  final expected = browserBridgeAppIpcWindowsCanonicalInstalledPath(programFiles);
  final observed = browserBridgeAppIpcWindowsCanonicalPath(observedPath);
  if (expected == null || observed == null) return false;
  if (!_windowsPathEquals(expected, observed)) return false;
  if (authenticode.status != 'Valid') return false;
  if (authenticode.subject.isEmpty) return false;
  return authenticode.subject == reviewedSubject;
}

/// Unsigned-build identity: the advertised pid runs exactly
/// `%ProgramFiles%\\WinsVPN\\wins_vpn.exe`, not through a reparse point, and
/// the file, its folder and every ancestor pass the same ACL integrity rules
/// as the owner receipt: privileged owner, no ordinary-user write on the file
/// or its folder, no ordinary-user replace rights above. A same-user process
/// cannot place a binary there without elevation, so this does not trust an
/// arbitrary same-user process. It does not stop a same-user process from
/// injecting into the genuine app; nothing short of a privileged broker does.
///
/// The expected location comes from the probe's Program Files known folder,
/// never from the host's inherited environment: a same-user launcher can set
/// `ProgramFiles=Z:\\` for the browser it starts. And only a fixed local
/// NTFS volume counts, because a mapped SMB share or a removable medium can
/// present a privileged owner and privileged-only ACEs for a file anyone
/// wrote.
bool browserBridgeAppIpcWindowsProtectedInstalledExecutableAuthenticates({
  required String observedPath,
  required BrowserBridgeAppIpcWindowsAclSnapshot acl,
  bool isLink = false,
}) {
  if (isLink) return false;
  if (!acl.onFixedNtfs) return false;
  if (acl.programFiles.isEmpty) return false;
  final expected =
      browserBridgeAppIpcWindowsCanonicalInstalledPath(acl.programFiles);
  final observed = browserBridgeAppIpcWindowsCanonicalPath(observedPath);
  if (expected == null || observed == null) return false;
  if (!_windowsPathEquals(expected, observed)) return false;
  return browserBridgeAppIpcWindowsIntegrityFault(
        snapshot: acl,
        expectedCanonicalPath: expected,
      ) ==
      null;
}

String? browserBridgeAppIpcWindowsCanonicalInstalledPath(String programFiles) {
  final root = browserBridgeAppIpcWindowsCanonicalPath(programFiles);
  if (root == null) return null;
  return browserBridgeAppIpcWindowsCanonicalPath(
    '$root\\$kBrowserBridgeAppIpcWindowsInstallFolderName\\'
    '$kBrowserBridgeAppIpcWindowsExecutableName',
  );
}

String? browserBridgeAppIpcWindowsCanonicalPath(String path) {
  var text = path.trim();
  if (text.isEmpty) return null;
  text = text.replaceAll('/', '\\');
  if (text.startsWith('\\\\')) return null;
  final match = RegExp(r'^([A-Za-z]):\\(.*)$').firstMatch(text);
  if (match == null) return null;
  final drive = match.group(1)!.toUpperCase();
  final rest = match.group(2)!;
  final parts = <String>[];
  for (final part in rest.split('\\')) {
    if (part.isEmpty || part == '.') continue;
    if (part == '..') {
      if (parts.isEmpty) return null;
      parts.removeLast();
      continue;
    }
    parts.add(part);
  }
  if (parts.isEmpty) return '$drive:\\';
  return '$drive:\\${parts.join('\\')}';
}

bool _windowsPathEquals(String left, String right) {
  return left.toLowerCase() == right.toLowerCase();
}

String? browserBridgeAppIpcWindowsCanonicalTrustPath(String programData) {
  final root = browserBridgeAppIpcWindowsCanonicalPath(programData);
  if (root == null) return null;
  return browserBridgeAppIpcWindowsCanonicalPath(
    '$root\\wins_vpn\\$kBrowserBridgeAppIpcTrustFileName',
  );
}

String? browserBridgeAppIpcWindowsCanonicalParent(String path) {
  final canonical = browserBridgeAppIpcWindowsCanonicalPath(path);
  if (canonical == null) return null;
  if (RegExp(r'^[A-Z]:\\$').hasMatch(canonical)) return null;
  final idx = canonical.lastIndexOf('\\');
  if (idx < 2) return null;
  if (idx == 2) return '${canonical.substring(0, 2)}\\';
  return canonical.substring(0, idx);
}

/// Exact /opt/wins-vpn/wins_vpn, root-owned regular file, non-user-writable
/// file and ancestry.
bool browserBridgeAppIpcLinuxInstalledExecutableAuthenticates({
  required String observedPath,
  required int selfUid,
  required List<BrowserBridgeAppIpcPosixNode> fileThenAncestors,
}) {
  return browserBridgeAppIpcPosixIntegrityFault(
        selfUid: selfUid,
        fileThenAncestors: fileThenAncestors,
        requireRootOwnedLeaf: true,
        requiredExactPath: kBrowserBridgeAppIpcLinuxInstalledExecutable,
        observedPath: observedPath,
      ) ==
      null;
}

/// Owner-installed receipt: not same-UID, not user-writable, ancestry not
/// user-writable. Leaf must be a regular file.
bool browserBridgeAppIpcPosixOwnerReceiptSafe({
  required int selfUid,
  required List<BrowserBridgeAppIpcPosixNode> fileThenAncestors,
}) {
  return browserBridgeAppIpcPosixIntegrityFault(
        selfUid: selfUid,
        fileThenAncestors: fileThenAncestors,
        requireRootOwnedLeaf: false,
        requiredExactPath: null,
        observedPath: fileThenAncestors.isEmpty ? '' : fileThenAncestors.first.path,
      ) ==
      null;
}

BrowserBridgeAppIpcError? browserBridgeAppIpcPosixIntegrityFault({
  required int selfUid,
  required List<BrowserBridgeAppIpcPosixNode> fileThenAncestors,
  required bool requireRootOwnedLeaf,
  required String? requiredExactPath,
  required String observedPath,
}) {
  if (fileThenAncestors.isEmpty) {
    return BrowserBridgeAppIpcError.unauthenticatedIdentity;
  }
  if (requiredExactPath != null) {
    final canonical = _posixCanonicalPath(observedPath);
    if (canonical != requiredExactPath) {
      return BrowserBridgeAppIpcError.identityMismatch;
    }
    final leafCanonical = _posixCanonicalPath(fileThenAncestors.first.path);
    if (leafCanonical != requiredExactPath) {
      return BrowserBridgeAppIpcError.identityMismatch;
    }
  }
  var index = 0;
  for (final node in fileThenAncestors) {
    if (node.isLink) return BrowserBridgeAppIpcError.symlink;
    if (node.uid == selfUid) {
      return BrowserBridgeAppIpcError.unauthenticatedIdentity;
    }
    // Group-write or other-write (0022). Owner-write on a non-self uid is
    // not user-writable.
    if ((node.mode & 0x012) != 0) {
      return BrowserBridgeAppIpcError.unsafePermissions;
    }
    if (index == 0) {
      if (!node.isRegularFile) {
        return BrowserBridgeAppIpcError.notRegularFile;
      }
      if (requireRootOwnedLeaf && node.uid != 0) {
        return BrowserBridgeAppIpcError.unauthenticatedIdentity;
      }
    }
    index += 1;
  }
  return null;
}

String _posixCanonicalPath(String path) {
  final text = path.trim();
  if (!text.startsWith('/')) return '';
  final parts = <String>[];
  for (final part in text.split('/')) {
    if (part.isEmpty || part == '.') continue;
    if (part == '..') {
      if (parts.isEmpty) return '';
      parts.removeLast();
      continue;
    }
    parts.add(part);
  }
  return '/${parts.join('/')}';
}

/// Owner-installed Windows receipt: exact ProgramData path, privileged owner,
/// no reparse, and no ordinary-user write on the file or its replaceable
/// parent. Higher ancestors may allow Users create-new, but not delete-child,
/// modify, take-ownership, or change-permissions.
bool browserBridgeAppIpcWindowsOwnerReceiptSafe({
  required BrowserBridgeAppIpcWindowsAclSnapshot snapshot,
  required String expectedCanonicalPath,
}) {
  return browserBridgeAppIpcWindowsIntegrityFault(
        snapshot: snapshot,
        expectedCanonicalPath: expectedCanonicalPath,
      ) ==
      null;
}

BrowserBridgeAppIpcError? browserBridgeAppIpcWindowsIntegrityFault({
  required BrowserBridgeAppIpcWindowsAclSnapshot snapshot,
  required String expectedCanonicalPath,
}) {
  final expected = browserBridgeAppIpcWindowsCanonicalPath(expectedCanonicalPath);
  if (expected == null || snapshot.fileThenAncestors.isEmpty) {
    return BrowserBridgeAppIpcError.unauthenticatedIdentity;
  }
  if (!kBrowserBridgeAppIpcWindowsSidPattern.hasMatch(snapshot.currentUserSid)) {
    return BrowserBridgeAppIpcError.malformed;
  }
  final leaf = snapshot.fileThenAncestors.first;
  if (!_windowsPathEquals(leaf.path, expected)) {
    return BrowserBridgeAppIpcError.unauthenticatedIdentity;
  }
  var index = 0;
  String? previousPath;
  for (final node in snapshot.fileThenAncestors) {
    if (previousPath != null) {
      final parent = browserBridgeAppIpcWindowsCanonicalParent(previousPath);
      if (parent == null || !_windowsPathEquals(parent, node.path)) {
        return BrowserBridgeAppIpcError.unauthenticatedIdentity;
      }
    }
    previousPath = node.path;
    if (node.isReparse) return BrowserBridgeAppIpcError.symlink;
    if (index == 0) {
      if (!node.isRegularFile) {
        return BrowserBridgeAppIpcError.notRegularFile;
      }
    } else if (node.isRegularFile) {
      return BrowserBridgeAppIpcError.notRegularFile;
    }
    if (!_windowsOwnerAllowed(node.ownerSid)) {
      return BrowserBridgeAppIpcError.unsafeOwnership;
    }
    final includeContentWrite = index <= 1;
    if (includeContentWrite && node.currentUserEffectiveWrite) {
      return BrowserBridgeAppIpcError.unsafePermissions;
    }
    for (final ace in node.aces) {
      if (ace.inheritOnly || !ace.allow) continue;
      if (!_windowsSidRestricted(ace.sid, snapshot.currentUserSid)) {
        continue;
      }
      if (_windowsRightsUnsafe(
        ace.rights,
        includeContentWrite: includeContentWrite,
      )) {
        return BrowserBridgeAppIpcError.unsafePermissions;
      }
    }
    index += 1;
  }
  final last = snapshot.fileThenAncestors.last;
  if (browserBridgeAppIpcWindowsCanonicalParent(last.path) != null) {
    return BrowserBridgeAppIpcError.unauthenticatedIdentity;
  }
  return null;
}

/// Parse the closed Windows ACL probe contract. Duplicate keys, duplicate
/// paths, duplicate ACE rows, and any localized prose are malformed.
BrowserBridgeAppIpcWindowsAclSnapshot parseBrowserBridgeAppIpcWindowsAclProbe(
  String stdout,
) {
  final lines = stdout
      .split(RegExp(r'\r?\n'))
      .map((String line) => line.trim())
      .where((String line) => line.isNotEmpty)
      .toList();
  if (lines.isEmpty ||
      lines.first != kBrowserBridgeAppIpcWindowsAclProbeVersion) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  var index = 1;
  String? currentUserSid;
  var seenCurrentUser = false;
  var volume = '';
  var programFiles = '';
  var ended = false;
  final nodes = <BrowserBridgeAppIpcWindowsNode>[];
  final seenPaths = <String>{};
  while (index < lines.length) {
    final line = lines[index];
    index += 1;
    if (ended) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    if (line.startsWith('CURRENT_USER_SID=')) {
      if (seenCurrentUser || nodes.isNotEmpty) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      seenCurrentUser = true;
      currentUserSid = line.substring('CURRENT_USER_SID='.length);
      if (!kBrowserBridgeAppIpcWindowsSidPattern.hasMatch(currentUserSid)) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      continue;
    }
    if (line.startsWith('VOLUME=')) {
      if (!seenCurrentUser || volume.isNotEmpty || nodes.isNotEmpty) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      volume = line.substring('VOLUME='.length);
      if (!RegExp(r'^[A-Za-z]+\|[A-Za-z0-9]*$').hasMatch(volume)) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      continue;
    }
    if (line.startsWith('PROGRAM_FILES=')) {
      if (!seenCurrentUser || programFiles.isNotEmpty || nodes.isNotEmpty) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      programFiles = line.substring('PROGRAM_FILES='.length);
      if (browserBridgeAppIpcWindowsCanonicalPath(programFiles) == null) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      continue;
    }
    if (line == 'END') {
      ended = true;
      continue;
    }
    if (line != 'NODE') {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    if (!seenCurrentUser) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    String? path;
    String? owner;
    String? reparse;
    String? kind;
    String? effectiveWrite;
    final aces = <BrowserBridgeAppIpcWindowsAce>[];
    final seenAce = <String>{};
    var closed = false;
    while (index < lines.length) {
      final body = lines[index];
      index += 1;
      if (body == 'ENDNODE') {
        closed = true;
        break;
      }
      if (body == 'NODE' ||
          body == 'END' ||
          body == kBrowserBridgeAppIpcWindowsAclProbeVersion) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      final eq = body.indexOf('=');
      if (eq <= 0) {
        throw const BrowserBridgeAppIpcException(
          BrowserBridgeAppIpcError.malformed,
        );
      }
      final key = body.substring(0, eq);
      final value = body.substring(eq + 1);
      switch (key) {
        case 'PATH':
          if (path != null || value.isEmpty) {
            throw const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed,
            );
          }
          path = value;
        case 'OWNER':
          if (owner != null ||
              !kBrowserBridgeAppIpcWindowsSidPattern.hasMatch(value)) {
            throw const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed,
            );
          }
          owner = value;
        case 'REPARSE':
          if (reparse != null || (value != '0' && value != '1')) {
            throw const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed,
            );
          }
          reparse = value;
        case 'KIND':
          if (kind != null || (value != 'FILE' && value != 'DIR')) {
            throw const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed,
            );
          }
          kind = value;
        case 'EFFECTIVE_WRITE':
          if (effectiveWrite != null || (value != '0' && value != '1')) {
            throw const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed,
            );
          }
          effectiveWrite = value;
        case 'ACE':
          if (!seenAce.add(value)) {
            throw const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed,
            );
          }
          aces.add(_parseBrowserBridgeAppIpcWindowsAce(value));
        default:
          throw const BrowserBridgeAppIpcException(
            BrowserBridgeAppIpcError.malformed,
          );
      }
    }
    if (!closed ||
        path == null ||
        owner == null ||
        reparse == null ||
        kind == null ||
        effectiveWrite == null ||
        aces.isEmpty) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    final canonical = browserBridgeAppIpcWindowsCanonicalPath(path);
    if (canonical == null) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    if (!seenPaths.add(canonical.toLowerCase())) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    if (nodes.length >= 16 || aces.length > 64) {
      throw const BrowserBridgeAppIpcException(
        BrowserBridgeAppIpcError.malformed,
      );
    }
    nodes.add(
      BrowserBridgeAppIpcWindowsNode(
        path: canonical,
        ownerSid: owner,
        isReparse: reparse == '1',
        isRegularFile: kind == 'FILE',
        currentUserEffectiveWrite: effectiveWrite == '1',
        aces: List<BrowserBridgeAppIpcWindowsAce>.unmodifiable(aces),
      ),
    );
  }
  if (!ended ||
      !seenCurrentUser ||
      currentUserSid == null ||
      nodes.isEmpty) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  return BrowserBridgeAppIpcWindowsAclSnapshot(
    currentUserSid: currentUserSid,
    fileThenAncestors: List<BrowserBridgeAppIpcWindowsNode>.unmodifiable(nodes),
    volume: volume,
    programFiles: programFiles,
  );
}

BrowserBridgeAppIpcWindowsAce _parseBrowserBridgeAppIpcWindowsAce(String value) {
  final parts = value.split('|');
  if (parts.length != 5) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final sid = parts[0];
  final type = parts[1];
  final rightsRaw = parts[2];
  final inherited = parts[3];
  final inheritOnly = parts[4];
  if (!kBrowserBridgeAppIpcWindowsSidPattern.hasMatch(sid) ||
      (type != 'A' && type != 'D') ||
      (inherited != '0' && inherited != '1') ||
      (inheritOnly != '0' && inheritOnly != '1')) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  final rights = int.tryParse(rightsRaw);
  if (rights == null || rights < -2147483648 || rights > 4294967295) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.malformed,
    );
  }
  return BrowserBridgeAppIpcWindowsAce(
    sid: sid,
    allow: type == 'A',
    rights: rights & 0xFFFFFFFF,
    inherited: inherited == '1',
    inheritOnly: inheritOnly == '1',
  );
}

bool _windowsOwnerAllowed(String sid) {
  return sid == kBrowserBridgeAppIpcWindowsSidSystem ||
      sid == kBrowserBridgeAppIpcWindowsSidBuiltinAdministrators ||
      sid == kBrowserBridgeAppIpcWindowsSidTrustedInstaller;
}

bool _windowsSidRestricted(String sid, String currentUserSid) {
  return !_windowsOwnerAllowed(sid);
}

bool _windowsRightsUnsafe(int rights, {required bool includeContentWrite}) {
  final bits = rights & 0xFFFFFFFF;
  if ((bits & kBrowserBridgeAppIpcWindowsReplaceRights) != 0) {
    return true;
  }
  if (includeContentWrite &&
      (bits & kBrowserBridgeAppIpcWindowsContentWriteRights) != 0) {
    return true;
  }
  return false;
}

int? browserBridgeAppIpcListeningPid(int port) {
  if (port < 1 || port > 65535) return null;
  if (Platform.isMacOS) {
    try {
      final result = Process.runSync('/usr/sbin/lsof', <String>[
        '-nP',
        '-iTCP@$kBrowserBridgeAppIpcLoopbackHost:$port',
        '-sTCP:LISTEN',
        '-t',
      ]);
      if (result.exitCode != 0) return null;
      final lines = (result.stdout as String)
          .trim()
          .split(RegExp(r'\s+'))
          .where((String line) => line.isNotEmpty);
      final pids = <int>{};
      for (final line in lines) {
        final value = int.tryParse(line);
        if (value != null && value > 0) pids.add(value);
      }
      if (pids.length != 1) return null;
      return pids.first;
    } on ProcessException {
      return null;
    }
  }
  if (Platform.isLinux) {
    return _linuxListeningPid(port);
  }
  if (Platform.isWindows) {
    return _windowsListeningPid(port);
  }
  return null;
}

int? _linuxListeningPid(int port) {
  try {
    final table = File('/proc/net/tcp');
    if (!table.existsSync()) return null;
    final wantedPort = port.toRadixString(16).padLeft(4, '0').toUpperCase();
    const loopback = '0100007F';
    // Every listener on 127.0.0.1:port, and exactly one is accepted, as the
    // macOS lsof path accepts exactly one pid.
    final inodes = <String>{};
    for (final line in table.readAsLinesSync().skip(1)) {
      final cols = line.trim().split(RegExp(r'\s+'));
      if (cols.length < 10) continue;
      final local = cols[1].split(':');
      if (local.length != 2) continue;
      if (local[0].toUpperCase() != loopback) continue;
      if (local[1].toUpperCase() != wantedPort) continue;
      if (cols[3] != '0A') continue;
      inodes.add(cols[9]);
    }
    if (inodes.length != 1 || inodes.single == '0') return null;
    final socket = 'socket:[${inodes.single}]';
    final owners = <int>{};
    final proc = Directory('/proc');
    for (final entry in proc.listSync()) {
      if (entry is! Directory) continue;
      final advertised = int.tryParse(entry.uri.pathSegments.isEmpty
          ? entry.path.split('/').last
          : entry.path.split('/').last);
      if (advertised == null || advertised <= 0) continue;
      final fdDir = Directory('${entry.path}/fd');
      if (!fdDir.existsSync()) continue;
      final List<FileSystemEntity> fds;
      try {
        // followLinks: false. Each entry is a link such as `socket:[inode]`;
        // following it stats the socket, which dart:io then lists as a File,
        // never a Link, so no listener was ever found.
        fds = fdDir.listSync(followLinks: false);
      } on FileSystemException {
        continue;
      }
      for (final fd in fds) {
        if (fd is! Link) continue;
        try {
          if (fd.targetSync() == socket) {
            owners.add(advertised);
            break;
          }
        } on FileSystemException {
          // Closed since the listing (the listing's own descriptor among
          // them): skip this descriptor, not the rest of the process.
          continue;
        }
      }
    }
    // A listener shared with a second process is no proof of ownership.
    return owners.length == 1 ? owners.single : null;
  } catch (_) {
    return null;
  }
}

int? _windowsListeningPid(int port) {
  try {
    final result = Process.runSync(windowsSystemExecutable('NETSTAT.EXE'), <String>['-ano', '-p', 'TCP']);
    if (result.exitCode != 0) return null;
    final needle = '$kBrowserBridgeAppIpcLoopbackHost:$port';
    final pids = <int>{};
    for (final line in (result.stdout as String).split('\n')) {
      final folded = line.toUpperCase();
      if (!folded.contains('LISTEN')) continue;
      if (!line.contains(needle)) continue;
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.isEmpty) continue;
      final value = int.tryParse(parts.last);
      if (value != null && value > 0) pids.add(value);
    }
    if (pids.length != 1) return null;
    return pids.first;
  } on ProcessException {
    return null;
  }
}

BrowserBridgeAppIpcMacosCodeSignature? _macosCodeSignatureForPid(
  int advertisedPid,
) {
  try {
    // The anchor, identifier and team are proven by codesign against an
    // explicit requirement, not read back from text the process supplies.
    //
    // Mac App Store copies are re-signed by Apple ("Apple Mac OS Application
    // Signing"), whose leaf has no team OU, so a leaf[subject.OU] clause alone
    // refuses the shipping app every time. This mirrors Apple's own
    // designated requirement: either the Mac App Store leaf marker, or a
    // Developer ID chain whose leaf carries this team. The team stays pinned
    // for both through `codesign -dv` TeamIdentifier and the DR text checked
    // in browserBridgeAppIpcMacosCodeSignatureAuthenticates.
    final verify = Process.runSync(
      '/usr/bin/codesign',
      <String>[
        '--verify',
        '-R=anchor apple generic and identifier '
            '"$kBrowserBridgeAppIpcMacosBundleId" and '
            '(certificate leaf[field.1.2.840.113635.100.6.1.9] /* Mac App Store */ '
            'or certificate 1[field.1.2.840.113635.100.6.2.6] /* Developer ID CA */ '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] /* Developer ID */ '
            'and certificate leaf[subject.OU] = '
            '"$kBrowserBridgeAppIpcMacosTeamIdentifier")',
        '$advertisedPid',
      ],
    );
    final display = Process.runSync(
      '/usr/bin/codesign',
      <String>['-dv', '$advertisedPid'],
    );
    final requirement = Process.runSync(
      '/usr/bin/codesign',
      <String>['-d', '-r-', '$advertisedPid'],
    );
    return parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: '${display.stdout}\n${display.stderr}',
      designatedRequirementText:
          '${requirement.stdout}\n${requirement.stderr}',
      verifySucceeded: verify.exitCode == 0,
    );
  } on ProcessException {
    return null;
  }
}

bool _installedExecutableMatches(int advertisedPid, String expectedValue) {
  if (Platform.isLinux) {
    if (expectedValue != kBrowserBridgeAppIpcLinuxInstalledExecutable) {
      return false;
    }
    return _linuxInstalledExecutableMatches(advertisedPid);
  }
  if (Platform.isWindows) {
    if (expectedValue != kBrowserBridgeAppIpcWindowsExecutableName) {
      return false;
    }
    return _windowsInstalledExecutableMatches(advertisedPid);
  }
  return false;
}

bool _linuxInstalledExecutableMatches(int advertisedPid) {
  final path = _executablePathForPid(advertisedPid);
  if (path == null || path.isEmpty) return false;
  final self = _posixCurrentUid();
  if (self == null) return false;
  final nodes = _posixNodeChain(path, leafMustBeFile: true);
  if (nodes == null) return false;
  return browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
    observedPath: path,
    selfUid: self,
    fileThenAncestors: nodes,
  );
}

bool _windowsInstalledExecutableMatches(int advertisedPid) {
  final path = _executablePathForPid(advertisedPid);
  if (path == null || path.isEmpty) return false;
  var isLink = false;
  try {
    isLink = FileSystemEntity.isLinkSync(path);
  } catch (_) {
    return false;
  }
  final observed = browserBridgeAppIpcWindowsCanonicalPath(path);
  // Cheap shape check before spawning the probe; the probe's own Program
  // Files known folder decides the exact location.
  if (observed == null ||
      !observed.toLowerCase().endsWith(
            '\\${kBrowserBridgeAppIpcWindowsInstallFolderName.toLowerCase()}'
            '\\${kBrowserBridgeAppIpcWindowsExecutableName.toLowerCase()}',
          )) {
    return false;
  }
  final aclStdout = _windowsAclProbeStdout(observed);
  if (aclStdout == null) return false;
  final BrowserBridgeAppIpcWindowsAclSnapshot acl;
  try {
    acl = parseBrowserBridgeAppIpcWindowsAclProbe(aclStdout);
  } on BrowserBridgeAppIpcException {
    return false;
  }
  if (!browserBridgeAppIpcWindowsProtectedInstalledExecutableAuthenticates(
    observedPath: path,
    acl: acl,
    isLink: isLink,
  )) {
    return false;
  }
  const reviewedSubject = kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject;
  if (reviewedSubject == null) return true;
  final authenticode = _windowsAuthenticodeForPath(path);
  if (authenticode == null) return false;
  return browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
    observedPath: path,
    programFiles: acl.programFiles,
    authenticode: authenticode,
    reviewedSubject: reviewedSubject,
    isLink: isLink,
  );
}

BrowserBridgeAppIpcWindowsAuthenticode? _windowsAuthenticodeForPath(
  String path,
) {
  try {
    final result = Process.runSync(
      windowsSystemExecutable(r'WindowsPowerShell\v1.0\powershell.exe'),
      <String>[
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        r'$s = Get-AuthenticodeSignature -LiteralPath $env:WINS_IPC_AUTH_PATH; '
            r'Write-Output $s.Status; '
            r'if ($s.SignerCertificate -eq $null) { Write-Output "" } '
            r'else { Write-Output $s.SignerCertificate.Subject }',
      ],
      environment: windowsPowerShellProbeEnvironment(
        systemDirectory: windowsSystemDirectory(),
        values: <String, String>{'WINS_IPC_AUTH_PATH': path},
      ),
      includeParentEnvironment: false,
    );
    if (result.exitCode != 0) return null;
    final lines = (result.stdout as String)
        .split(RegExp(r'\r?\n'))
        .map((String line) => line.trim())
        .where((String line) => line.isNotEmpty)
        .toList();
    if (lines.isEmpty) return null;
    final status = lines.first;
    final subject = lines.length > 1 ? lines[1] : '';
    return BrowserBridgeAppIpcWindowsAuthenticode(
      status: status,
      subject: subject,
    );
  } on ProcessException {
    return null;
  } on StateError {
    // No trustworthy System32: refuse rather than run an unknown PowerShell.
    return null;
  }
}

void _assertPosixOwnerInstalledReceipt(String path) {
  final self = _posixCurrentUid();
  if (self == null) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final nodes = _posixNodeChain(path, leafMustBeFile: true);
  if (nodes == null) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final fault = browserBridgeAppIpcPosixIntegrityFault(
    selfUid: self,
    fileThenAncestors: nodes,
    requireRootOwnedLeaf: false,
    requiredExactPath: null,
    observedPath: path,
  );
  if (fault != null) {
    throw BrowserBridgeAppIpcException(fault);
  }
}

void _assertWindowsOwnerInstalledReceipt(
  String path, {
  Map<String, String>? environment,
}) {
  final env = environment ?? Platform.environment;
  final programData = _windowsEnvironmentValue(env, 'programdata');
  final expected = programData == null
      ? null
      : browserBridgeAppIpcWindowsCanonicalTrustPath(programData);
  final observed = browserBridgeAppIpcWindowsCanonicalPath(path);
  if (expected == null ||
      observed == null ||
      !_windowsPathEquals(expected, observed)) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  if (!Platform.isWindows) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final stdout = _windowsAclProbeStdout(observed);
  if (stdout == null) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unauthenticatedIdentity,
    );
  }
  final snapshot = parseBrowserBridgeAppIpcWindowsAclProbe(stdout);
  final fault = browserBridgeAppIpcWindowsIntegrityFault(
    snapshot: snapshot,
    expectedCanonicalPath: expected,
  );
  if (fault != null) {
    throw BrowserBridgeAppIpcException(fault);
  }
}

const String _kWindowsAclProbeCommand = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$path = [string]$env:WINS_IPC_TRUST_PATH
if ([string]::IsNullOrWhiteSpace($path)) { exit 2 }
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ([string]::IsNullOrWhiteSpace($userSid)) { exit 3 }
$dangerous = [uint32]0
$dangerous = $dangerous -bor [uint32]2
$dangerous = $dangerous -bor [uint32]4
$dangerous = $dangerous -bor [uint32]16
$dangerous = $dangerous -bor [uint32]64
$dangerous = $dangerous -bor [uint32]256
$dangerous = $dangerous -bor [uint32]65536
$dangerous = $dangerous -bor [uint32]262144
$dangerous = $dangerous -bor [uint32]524288
$dangerous = $dangerous -bor [uint32]268435456
$dangerous = $dangerous -bor [uint32]1073741824
Write-Output 'WINS_IPC_WINACL_V1'
Write-Output ('CURRENT_USER_SID=' + $userSid)
$volumeRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($path))
$volume = New-Object IO.DriveInfo($volumeRoot)
Write-Output ('VOLUME=' + [string]$volume.DriveType + '|' + [string]$volume.DriveFormat)
Write-Output ('PROGRAM_FILES=' + [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles))
$current = $path
for ($i = 0; $i -lt 16; $i++) {
  $item = Get-Item -LiteralPath $current -Force
  $full = [string]$item.FullName
  $reparse = '0'
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $reparse = '1' }
  $kind = 'FILE'
  if ($item.PSIsContainer) { $kind = 'DIR' }
  $acl = Get-Acl -LiteralPath $full
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  $aceLines = @()
  $grant = [uint32]0
  $deny = [uint32]0
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $sid = [string]$rule.IdentityReference.Value
    $type = 'D'
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) { $type = 'A' }
    $rights = [uint32]([int]$rule.FileSystemRights)
    $inherited = '0'
    if ($rule.IsInherited) { $inherited = '1' }
    $inheritOnly = '0'
    if (([int]$rule.PropagationFlags -band 2) -ne 0) { $inheritOnly = '1' }
    $aceLines += ('ACE=' + $sid + '|' + $type + '|' + $rights + '|' + $inherited + '|' + $inheritOnly)
    if ($inheritOnly -eq '0') {
      $restricted = $sid -ne 'S-1-5-18' -and $sid -ne 'S-1-5-32-544' -and $sid -ne 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
      if ($restricted) {
        if ($type -eq 'D') { $deny = $deny -bor $rights } else { $grant = $grant -bor $rights }
      }
    }
  }
  $effective = $grant -band (-bnot $deny)
  $write = '0'
  if (($effective -band $dangerous) -ne 0) { $write = '1' }
  Write-Output 'NODE'
  Write-Output ('PATH=' + $full)
  Write-Output ('OWNER=' + $ownerSid)
  Write-Output ('REPARSE=' + $reparse)
  Write-Output ('KIND=' + $kind)
  Write-Output ('EFFECTIVE_WRITE=' + $write)
  foreach ($aceLine in $aceLines) { Write-Output $aceLine }
  Write-Output 'ENDNODE'
  $parent = [System.IO.Directory]::GetParent($full)
  if ($parent -eq $null) { break }
  $next = [string]$parent.FullName
  if ($next -eq $full) { break }
  $current = $next
}
Write-Output 'END'
''';

String? _windowsAclProbeStdout(String path) {
  try {
    final result = Process.runSync(
      windowsSystemExecutable(r'WindowsPowerShell\v1.0\powershell.exe'),
      <String>[
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        _kWindowsAclProbeCommand,
      ],
      environment: windowsPowerShellProbeEnvironment(
        systemDirectory: windowsSystemDirectory(),
        values: <String, String>{'WINS_IPC_TRUST_PATH': path},
      ),
      includeParentEnvironment: false,
    );
    if (result.exitCode != 0) return null;
    return result.stdout as String;
  } on ProcessException {
    return null;
  } on StateError {
    // No trustworthy System32: refuse rather than run an unknown PowerShell.
    return null;
  }
}

String? _windowsEnvironmentValue(Map<String, String> environment, String name) {
  final wanted = name.toLowerCase();
  for (final entry in environment.entries) {
    if (entry.key.toLowerCase() == wanted) {
      final value = entry.value.trim();
      if (value.isNotEmpty) return value;
    }
  }
  return null;
}

List<BrowserBridgeAppIpcPosixNode>? _posixNodeChain(
  String path, {
  required bool leafMustBeFile,
}) {
  try {
    final paths = <String>[];
    final links = <bool>[];
    final stats = <FileStat>[];
    var current = path;
    var isLeaf = true;
    while (true) {
      final isLink = FileSystemEntity.isLinkSync(current);
      final stat = FileStat.statSync(current);
      if (stat.type == FileSystemEntityType.notFound) return null;
      if (isLeaf && leafMustBeFile && stat.type != FileSystemEntityType.file) {
        return null;
      }
      paths.add(current);
      links.add(isLink);
      stats.add(stat);
      final parent = Directory(current).parent.path;
      if (parent == current) break;
      current = parent;
      isLeaf = false;
    }
    final uids = _posixFileUids(paths);
    if (uids == null) return null;
    final nodes = <BrowserBridgeAppIpcPosixNode>[];
    for (var i = 0; i < paths.length; i++) {
      nodes.add(
        BrowserBridgeAppIpcPosixNode(
          path: paths[i],
          uid: uids[i],
          mode: stats[i].mode & 0x1FF,
          isLink: links[i],
          isRegularFile: i == 0 && stats[i].type == FileSystemEntityType.file,
        ),
      );
    }
    return nodes;
  } catch (_) {
    return null;
  }
}

String? _executablePathForPid(int advertisedPid) {
  if (Platform.isLinux) {
    try {
      return Link('/proc/$advertisedPid/exe').resolveSymbolicLinksSync();
    } catch (_) {
      return null;
    }
  }
  if (Platform.isMacOS) {
    try {
      final result = Process.runSync(
        '/bin/ps',
        <String>['-p', '$advertisedPid', '-o', 'comm='],
      );
      if (result.exitCode != 0) return null;
      return (result.stdout as String).trim();
    } on ProcessException {
      return null;
    }
  }
  if (Platform.isWindows) {
    try {
      final result = Process.runSync(
        windowsSystemExecutable(r'WindowsPowerShell\v1.0\powershell.exe'),
        <String>[
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          r'(Get-Process -Id ([int]$env:WINS_IPC_PID) -ErrorAction Stop).Path',
        ],
        environment: windowsPowerShellProbeEnvironment(
          systemDirectory: windowsSystemDirectory(),
          values: <String, String>{'WINS_IPC_PID': '$advertisedPid'},
        ),
        includeParentEnvironment: false,
      );
      if (result.exitCode != 0) return null;
      final path = (result.stdout as String).trim();
      return path.isEmpty ? null : path;
    } on ProcessException {
      return null;
    } on StateError {
      // No trustworthy System32: refuse rather than run an unknown PowerShell.
      return null;
    }
  }
  return null;
}

void _assertPathNotSymlink(String path) {
  if (FileSystemEntity.isLinkSync(path)) {
    throw const BrowserBridgeAppIpcException(BrowserBridgeAppIpcError.symlink);
  }
}

void _assertPosixDiscoveryStat(FileStat stat, String path, String os) {
  if (!browserBridgeAppIpcUsesPosixOwnership(os)) {
    // Windows: FileStat.mode is not a POSIX permission triplet, and uid is
    // not exposed. Do not interpret either as owner/group/other.
    return;
  }
  if (stat.type != FileSystemEntityType.file) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.notRegularFile,
    );
  }
  final perms = stat.mode & 0x1FF;
  if (perms != 0x180) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unsafePermissions,
    );
  }
  final self = _posixCurrentUid();
  final owner = _posixFileUid(path);
  if (self == null || owner == null || self != owner) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unsafeOwnership,
    );
  }
}

void _posixChmod(String path, String mode) {
  final result = Process.runSync('/bin/chmod', <String>[mode, path]);
  if (result.exitCode != 0) {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.unsafePermissions,
    );
  }
}

// A process's real uid does not change while it runs, so one `id -u` per
// process is enough. Every status query used to spawn it six times.
int? _cachedPosixUid;

int? _posixCurrentUid() {
  final cached = _cachedPosixUid;
  if (cached != null) return cached;
  try {
    final result = Process.runSync('/usr/bin/id', <String>['-u']);
    if (result.exitCode != 0) return null;
    final uid = int.tryParse((result.stdout as String).trim());
    _cachedPosixUid = uid;
    return uid;
  } on ProcessException {
    return null;
  }
}

/// Owner uid of every path in one `stat` process instead of one per path.
List<int>? _posixFileUids(List<String> paths) {
  if (paths.isEmpty) return const <int>[];
  try {
    final args = Platform.isMacOS
        ? <String>['-f', '%u', ...paths]
        : <String>['-c', '%u', ...paths];
    final result = Process.runSync('/usr/bin/stat', args);
    if (result.exitCode != 0) return null;
    final lines = (result.stdout as String)
        .trim()
        .split(RegExp(r'\r?\n'))
        .map((String line) => line.trim())
        .toList();
    if (lines.length != paths.length) return null;
    final uids = <int>[];
    for (final line in lines) {
      final uid = int.tryParse(line);
      if (uid == null) return null;
      uids.add(uid);
    }
    return uids;
  } on ProcessException {
    return null;
  }
}

int? _posixFileUid(String path) {
  try {
    final args = Platform.isMacOS
        ? <String>['-f', '%u', path]
        : <String>['-c', '%u', path];
    final result = Process.runSync('/usr/bin/stat', args);
    if (result.exitCode != 0) return null;
    return int.tryParse((result.stdout as String).trim());
  } on ProcessException {
    return null;
  }
}

String _newRequestId() {
  final rng = Random.secure();
  final buffer = StringBuffer();
  for (var i = 0; i < 16; i++) {
    buffer.write(rng.nextInt(16).toRadixString(16));
  }
  return buffer.toString();
}

Future<Uint8List> _readFrame(
  Socket socket, {
  Duration timeout = kBrowserBridgeAppIpcIoTimeout,
}) async {
  final buffer = <int>[];
  final completer = Completer<Uint8List>();
  final subscription = socket.listen(
    (List<int> chunk) {
      if (completer.isCompleted) return;
      buffer.addAll(chunk);
      if (buffer.length >
          kNativeLengthPrefixBytes + kMaxBrowserBridgeAppIpcFrameBytes) {
        completer.completeError(
          const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.oversized),
        );
        return;
      }
      if (buffer.length < kNativeLengthPrefixBytes) return;
      final header = Uint8List.fromList(
        buffer.sublist(0, kNativeLengthPrefixBytes),
      );
      final length = ByteData.sublistView(header).getUint32(0, Endian.little);
      if (length == 0 || length > kMaxBrowserBridgeAppIpcFrameBytes) {
        completer.completeError(
          const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.oversized),
        );
        return;
      }
      final total = kNativeLengthPrefixBytes + length;
      if (buffer.length >= total) {
        completer.complete(
          Uint8List.fromList(
            buffer.sublist(kNativeLengthPrefixBytes, total),
          ),
        );
      }
    },
    onError: (Object error, StackTrace stack) {
      if (!completer.isCompleted) {
        completer.completeError(error, stack);
      }
    },
    onDone: () {
      if (!completer.isCompleted) {
        completer.completeError(
          const BrowserBridgeAppIpcException(
              BrowserBridgeAppIpcError.malformed),
        );
      }
    },
    cancelOnError: true,
  );
  try {
    return await completer.future.timeout(timeout);
  } on TimeoutException {
    throw const BrowserBridgeAppIpcException(
      BrowserBridgeAppIpcError.appAbsent,
    );
  } finally {
    await subscription.cancel();
  }
}
