/// Winn Protocol v3 -- DEV-ONLY, NON-SHIPPING session DELIVERY path.
///
/// # What this file is, in one sentence
///
/// The missing third piece: `winn_protocol_dev_override.dart` decides whether
/// macOS may evaluate a `winn/3` config, `winn_protocol_dev_config_source.dart`
/// supplies one from disk, and this file DELIVERS the result to the real
/// Network Extension provider by calling the SAME `startTunnel` platform
/// channel method the shipping app calls -- so a proving session runs inside a
/// real appex instead of a command-line harness.
///
/// # The gap this closes, stated exactly
///
/// `macos/PacketTunnel/PacketTunnelProvider.swift:314-465`
/// (`loadRuntimeConfig`) reads its configuration from exactly two places, in
/// this order:
///
///  1. `options["raw_config"]`, the transient start options
///     (`PacketTunnelProvider.swift:321`), written by
///     `macos/Runner/MainFlutterWindow.swift:1224-1229`.
///  2. The App Group handoff file `Tunnel/latest_tunnel.conf`
///     (`PacketTunnelProvider.swift:359-452`), written by
///     `MainFlutterWindow.persistSharedTunnelConfig`
///     (`macos/Runner/MainFlutterWindow.swift:1637-1659`).
///
/// BOTH are written by one function -- `MainFlutterWindow.startTunnel`
/// (`macos/Runner/MainFlutterWindow.swift:1102`) -- which is reached by exactly
/// one Dart call: `_methodChannel.invokeMethod('startTunnel', ...)` in
/// `lib/main.dart:8690`. That call is downstream of the `winn/3` dispatch seam
/// at `lib/main.dart:8568`, which on macOS refuses with
/// `unsupported_platform` because `kWinnHostCapabilities['macos']` is
/// `.absent`. So there was no way -- none -- for a `winn/3` document to reach
/// the provider. That was missing WIRING, not a missing execution, and this
/// file is that wiring.
///
/// # What this file is NOT
///
/// It is not a second on-switch. It does not read, write, or special-case
/// [kWinnHostCapabilities]; macOS stays exactly as `.absent` as the other two
/// dev-only files leave it. The capability flip follows a proven session and is
/// the owner's decision (`WINN_PROTOCOL_PLATFORM_PLAN.md` rule 4).
///
/// It is not wired into `lib/main.dart`, and nothing in `lib/main.dart` imports
/// it. Same two reasons the sibling dev files give:
/// `test/winn_protocol_refusal_guard_test.dart` pins EXACTLY ONE
/// `case kWinnProtocolV3:` dispatch point in that file, and adding a second,
/// more permissive path there is precisely what that guard exists to catch.
/// Instead this library is reached only from
/// `lib/winn_protocol_dev_session_main.dart`, a SEPARATE Flutter entry point
/// selected with `--target`. A normal `flutter build macos` compiles
/// `lib/main.dart`, which has no import path to either file, so neither is in
/// the shipping binary at all -- not disabled in it, ABSENT from it. That is
/// mechanically checkable with `strings` (see
/// [kWinnDevSessionAbsenceProbeString]) rather than argued.
///
/// It is not a parallel config format. The `[winn]` section is produced by the
/// REAL dispatch library -- [winnSectionForTunnelConfigDevOnly], which calls the
/// real, unmodified [resolveWinnProtocolStart] -- never hand-authored here. The
/// surrounding `[Interface]`/`[Peer]`/`[WinsDebug]`/`[WinsApp]` document is the
/// same AmneziaWG INI `WinsTunnelConfig.parse` already consumes
/// (`apple/WinsTunnelCore/WinsTunnelConfig.swift`), emitted with the same keys
/// `_buildRawAmneziaConfig` emits, and it is handed to the same native
/// validator (`WinsTunnelConfig.parseAndValidate`,
/// `macos/Runner/MainFlutterWindow.swift:1125`) that every shipping start goes
/// through. See [assembleWinnDevSessionTunnelDocument] for why that writer is
/// re-implemented here rather than shared.
///
/// # The double gate
///
/// [winnDevSessionActive] is true only when BOTH hold, and there is no third
/// way to make it true and no parameter anywhere in this file that substitutes
/// a different value for either input:
///
///  1. `kDebugMode` -- a Flutter SDK compile-time constant, false BY
///     CONSTRUCTION in every `--release` and `--profile` build.
///  2. `--dart-define=WINN_DEV_SESSION=true`
///     ([kWinnDevSessionDartDefineName]), which defaults to `false`.
///
/// This is the same shape `WINS_RESET_LOCAL_STATE` uses at
/// `lib/main.dart:3849-3861`, and the same shape the two sibling dev files use.
/// In practice a THIRD gate applies too, and it is the strongest of the three:
/// this file is only reachable from a non-default `--target`.
///
/// # WHERE `WINN_DEV_CONFIG_PATH` MAY POINT (observed, not assumed)
///
/// The macOS app is sandboxed (`com.apple.security.app-sandbox` is `true` in
/// its signed entitlements), so `WINN_DEV_CONFIG_PATH` MUST name a path inside
/// the app's own container. A path under `/tmp` or `/private/tmp` fails, and it
/// fails honestly rather than mysteriously -- this exact refusal was observed on
/// 2026-08-05:
///
/// ```
/// WINN DEV SESSION: BLOCKED at config_source -- could not read
/// "/private/tmp/.../dev_winn3_macos.json": Cannot open file.
/// ```
///
/// Use `~/Library/Containers/org.winsvpn.app/Data/<name>.json`. Never commit
/// the file it points at.
///
/// # Secrets
///
/// The `[Interface] PrivateKey` this file emits is NEVER read from the dev
/// config file. It is fetched at run time from the device's own Keychain
/// through the shipping `loadOrCreateClientKeyPair` channel method
/// (`macos/Runner/MainFlutterWindow.swift:688`), because
/// `MainFlutterWindow.startTunnel` calls
/// `parsedConfig.validateInterfacePrivateKeyMatches(clientKeyPair)`
/// (`macos/Runner/MainFlutterWindow.swift:1127`) and a config whose interface
/// key is not that exact Keychain pair is refused before anything else happens.
/// That private key is placed into the document and passed to native; it is
/// never logged, never returned by any function here, and never written to any
/// file this library opens. Log lines carry the PUBLIC key only. The assembled
/// document itself is only ever logged through
/// [redactWinnDevSessionDocumentForLogging].
library;

import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/services.dart' show MethodChannel;

import 'winn_protocol_dev_config_source.dart';
import 'winn_protocol_dev_override.dart';
import 'winn_protocol_dispatch.dart';

/// The exact `--dart-define` name an operator must pass, in addition to running
/// a debug build, to let this file do anything at all.
const String kWinnDevSessionDartDefineName = 'WINN_DEV_SESSION';

/// The compiled-in value of that dart-define. `false` unless the build/run
/// command explicitly carried `--dart-define=WINN_DEV_SESSION=true`.
const bool kWinnDevSessionDartDefineValue = bool.fromEnvironment(
  kWinnDevSessionDartDefineName,
  defaultValue: false,
);

/// A literal that exists nowhere else in the tree, so
/// `strings <app binary> | grep` gives a mechanical yes/no answer to "did this
/// dev path get compiled into that binary", rather than an argument from
/// reachability. A normal `flutter build macos` (target `lib/main.dart`) must
/// not contain it.
const String kWinnDevSessionAbsenceProbeString =
    'WINN_DEV_SESSION_ABSENCE_PROBE_5f3a1c9d';

/// Pure form of the double gate. No Flutter dependency, so every combination is
/// exhaustively unit-testable without recompiling with different dart-defines.
///
/// `debugMode == false` returns `false` regardless of [dartDefineEnabled],
/// which is what makes a release build's answer always `false`.
bool computeWinnDevSessionActive({
  required bool debugMode,
  required bool dartDefineEnabled,
}) {
  return debugMode && dartDefineEnabled;
}

/// The real, wired gate -- the only place in this file that reads the actual
/// compile-time constants. Deliberately parameterless: an injectable "pretend
/// this is active" hook would itself be a second way to enable the path.
bool get winnDevSessionActive => computeWinnDevSessionActive(
      debugMode: kDebugMode,
      dartDefineEnabled: kWinnDevSessionDartDefineValue,
    );

/// Printed before this module attempts anything else, every time the gate is
/// active. There is deliberately no quiet path.
const String kWinnDevSessionBanner = '''
################################################################################
# WINN DEV SESSION ACTIVE -- DELIVERING AN UNPROVEN winn/3 CONFIG TO A REAL    #
# NETWORK EXTENSION                                                            #
#                                                                              #
# kWinnHostCapabilities['macos'] is still WinnHostCapability.absent(...), and  #
# this file does not read or change it. This process is about to hand a        #
# winn/3 tunnel document to the SAME native startTunnel entry point the        #
# shipping app uses, so that a real session can be attempted and its outcome   #
# -- success OR failure -- observed inside a real appex.                       #
#                                                                              #
# Nothing here earns the capability flip. A session that runs is EVIDENCE for  #
# the owner's decision, not the decision. A session that fails is a correct    #
# and useful result, not a reason to loosen anything.                          #
#                                                                              #
# THIS SESSION IS CONTAINED. The document carries [WinsDevContainment], so a   #
# DEBUG provider installs ONE /32 route, NO IPv6 settings and NO DNS           #
# settings. The host keeps its default route, its IPv6 and its resolvers. A    #
# contained run is therefore NOT evidence that full-tunnel routing works, and  #
# the provider status says so: dev_containment_active is true and             #
# leak_protection_config_passed is forced false.                              #
#                                                                              #
# DEVELOPMENT SIGNING ONLY. Never build a release/profile archive with this    #
# dart-define or this --target -- kDebugMode already makes the gate false if   #
# you try, but don't try.                                                      #
################################################################################''';

/// A logging sink, reusing the sibling dev files' type so a caller can pass one
/// logger to all three.
typedef WinnDevSessionLogger = WinnDevOverrideLogger;

// ignore: avoid_print
void _defaultWinnDevSessionLogger(String message) => print(message);

/// How a `session_id` must look before this file will put it in a config.
///
/// 32 lowercase hex characters = 16 bytes of entropy. This is narrower than
/// what [resolveWinnProtocolStart] accepts (it bounds LENGTH at
/// [kWinnMaxSessionIdBytes] and rejects INI-forging characters, but does not
/// prescribe a shape), and deliberately so: this file GENERATES the value
/// rather than receiving it, so it can hold itself to a fixed shape that the
/// general validator cannot demand of every server in the fleet.
final RegExp kWinnDevSessionIdPattern = RegExp(r'^[0-9a-f]{32}$');

/// Number of random bytes behind a generated session id.
const int kWinnDevSessionIdBytes = 16;

/// A fresh session identifier: 32 lowercase hex characters from
/// [Random.secure].
///
/// [random] exists for the deterministic unit test only and defaults to
/// `Random.secure()`. It is NOT a gate: substituting a weak generator cannot
/// enable a path that is otherwise closed, it can only make an id predictable,
/// and the caller that matters ([runWinnDevSession]) never passes it.
///
/// This value is generated per session and is never taken from the dev config
/// file. [winnDevSessionConfigWithFreshSessionId] OVERWRITES any `session_id`
/// found there, so an operator cannot accidentally replay one, and a served
/// value can never become a session id on this path.
String generateWinnDevSessionId([Random? random]) {
  final source = random ?? Random.secure();
  final bytes = List<int>.generate(
    kWinnDevSessionIdBytes,
    (_) => source.nextInt(256),
    growable: false,
  );
  return bytes
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// Whether [value] is the 32-lowercase-hex shape this file generates.
bool isWinnDevSessionId(String value) =>
    kWinnDevSessionIdPattern.hasMatch(value);

/// Returns a copy of [config] whose `protocol_params.session_id` is exactly
/// [sessionId], replacing whatever was there.
///
/// Throws [ArgumentError] if [sessionId] is not [isWinnDevSessionId] -- this
/// function is the only way a session id enters a config on this path, so the
/// shape check belongs here rather than at the call site where it could be
/// forgotten.
///
/// The copy is shallow except for the `protocol_params` map, which is the only
/// thing mutated. The caller's map is never modified.
Map<String, dynamic> winnDevSessionConfigWithFreshSessionId(
  Map<String, dynamic> config,
  String sessionId,
) {
  if (!isWinnDevSessionId(sessionId)) {
    throw ArgumentError.value(
      sessionId,
      'sessionId',
      'a winn dev session id must be 32 lowercase hex characters',
    );
  }
  final params = config['protocol_params'] is Map
      ? Map<String, dynamic>.from(config['protocol_params'] as Map)
      : <String, dynamic>{};
  params['session_id'] = sessionId;
  return Map<String, dynamic>.from(config)..['protocol_params'] = params;
}

/// The `[Interface] PrivateKey` value in a document is replaced by this before
/// the document is logged. Matches the placeholder
/// `WinsTunnelConfig.redactedForStorage` writes into the App Group file
/// (`apple/WinsTunnelCore/WinsTunnelConfig.swift:926-951`) so a reader of a dev
/// log and a reader of the handoff file see the same marker.
const String kWinnDevSessionRedactedPlaceholder = '<redacted>';

/// Field names, matched case-insensitively against the WHOLE key (never a
/// substring, so `PublicKey` is never caught by `Key`), whose values this file
/// replaces before logging an assembled document.
const Set<String> kWinnDevSessionRedactedIniKeys = <String>{
  'privatekey',
  'presharedkey',
  'uuid',
  'winn3_static_private',
  'winn3staticprivate',
  'winn3_psk',
  'winn3psk',
  'static_private',
  'staticprivate',
  'admission_key',
  'admissionkey',
  'psk',
  'admission_secret',
  'admissionsecret',
};

/// Returns [document] with every [kWinnDevSessionRedactedIniKeys] value
/// replaced. Structure, ordering, key names and every non-secret value are
/// preserved exactly, because the whole point of logging the document is to be
/// able to check what was handed to native.
String redactWinnDevSessionDocumentForLogging(String document) {
  return document.split('\n').map((line) {
    final separator = line.indexOf('=');
    if (separator < 0) return line;
    final key = line.substring(0, separator).trim().toLowerCase();
    if (!kWinnDevSessionRedactedIniKeys.contains(key)) return line;
    return '${line.substring(0, separator + 1)} '
        '$kWinnDevSessionRedactedPlaceholder';
  }).join('\n');
}

/// AmneziaWG obfuscation defaults, mirroring `_buildRawAmneziaConfig`'s own
/// `??` fallbacks at `lib/main.dart:3373-3383` and the Dart-side defaults in
/// [winnAwgHeaderTypes]/[winnAwgPaddingSizes]. Kept here so a dev config file
/// may omit `obfuscation` entirely and still produce a document the native
/// validator accepts (`awgObfuscation` at
/// `apple/WinsTunnelCore/WinsTunnelConfig.swift:824` requires all eleven).
const Map<String, int> kWinnDevSessionObfuscationDefaults = <String, int>{
  'Jc': 4,
  'Jmin': 40,
  'Jmax': 70,
  'S1': 16,
  'S2': 80,
  'S3': 16,
  'S4': 0,
  'H1': 11,
  'H2': 22,
  'H3': 33,
  'H4': 44,
};

/// The full-tunnel AllowedIPs this file emits.
///
/// Deliberately the DEFAULT route, not a subset: `transportIPv4ExclusionRoute`
/// (`apple/WinsTunnelCore/WinsTunnelConfig.swift:613`) returns nil unless
/// `defaultIPv4RouteEnabled`, and with no /32 exclusion the Winn engine's own
/// outer socket is matched by the tunnel's own default route and dead-loops --
/// the exact hazard `validate()` refuses at code 1504
/// (`WinsTunnelConfig.swift:1198-1203`). A proving session that did not install
/// that /32 would not be proving the thing that needs proving.
const List<String> kWinnDevSessionAllowedIPs = <String>['0.0.0.0/0', '::/0'];

/// The INI section name that asks the Packet Tunnel provider for a CONTAINED
/// start. Must equal `WinsTunnelConfig.devContainmentSection` (lowercased on
/// both sides by the INI parser) in
/// `apple/WinsTunnelCore/WinsTunnelConfig.swift`.
const String kWinnDevSessionContainmentSection = 'WinsDevContainment';

/// The narrow /32 a contained session may install, or `''` to let the provider
/// derive the tunnel's own gateway address.
///
/// Left empty on purpose. The provider derives `x.y.z.1` from the interface
/// address, which is the in-tunnel address you ping to prove the datapath
/// carries packets. It refuses anything that is not a /32, so this knob cannot
/// be used to widen a contained session back into a default route.
const String kWinnDevSessionContainmentTestRoute = '';

/// Why every document this file assembles carries the containment marker, with
/// no way to turn it off.
///
/// On 2026-08-05 a dev session on macOS took the host's IPv4 default route, its
/// IPv6 (to a sink address), and its DNS (with an empty match domain, i.e.
/// EVERY domain) — and then carried nothing, because the `winn/3` handshake
/// does not complete on macOS yet. That is a total host blackout. Killing the
/// app did not clear it: the Network Extension outlives the app and keeps the
/// settings it was given. Only a reboot cleared it.
///
/// So this is deliberately NOT a flag. There is no `containment: false`
/// parameter, no dart-define to disable it, and no config key an operator can
/// set to opt out — a knob that must be remembered is a knob that gets
/// forgotten at exactly the wrong moment. A session driven by this file is
/// contained, always.
///
/// This costs the proving session nothing that matters. The `winn/3` handshake
/// runs on the engine's OUTER socket, which is kept off the tunnel by the /32
/// exclusion either way; containment only declines to capture the host's
/// traffic while that handshake is being observed. Proving the handshake is
/// what this path is for. Proving that full-tunnel routing works is what the
/// SHIPPING path already does, on platforms that have earned it.
const String kWinnDevSessionContainmentRationale =
    'A dev session must not be able to blackhole the machine it is being '
    'developed on. Contained: one /32, no IPv6, no DNS.';

/// The platforms whose native start actually HONOURS
/// [kWinnDevSessionContainmentSection]. Membership is a statement about native
/// code that exists, not about intent:
///
///  * `macos` — `macos/PacketTunnel/PacketTunnelProvider.swift` installs one
///    /32 with no IPv6 and no DNS for a config carrying the marker.
///  * `ios` — `ios/PacketTunnel/PacketTunnelProvider.swift` does the same and,
///    additionally, THROWS rather than widening in a build that cannot contain.
///
/// `windows` is deliberately absent, and it is the reason this set exists at
/// all. See [kWinnDevSessionWindowsContainmentAbsenceRationale].
const Set<String> kWinnDevSessionContainmentCapablePlatforms = <String>{
  'macos',
  'ios',
};

/// Why Windows is not in [kWinnDevSessionContainmentCapablePlatforms], stated
/// where a reader of this file will hit it rather than in a handoff document.
///
/// Read in the Windows tree, not inferred:
///
///  1. `windows/runner/windows_tunnel_backend.cpp` →
///     `ValidateRestrictedTunnelConfig` allows exactly six INI sections:
///     `interface`, `peer`, `xray`, `winsdebug`, `winsapp`, `winn`. A document
///     carrying `[WinsDevContainment]` is refused with "Tunnel configuration
///     contains an unknown or duplicate section" — in the app process
///     (`InstallTunnel`) AND again in the privileged service
///     (`InstallPrivilegedTunnel`), neither behind a debug condition.
///  2. `InstallPrivilegedTunnel` REQUIRES `[Interface] Table = off` and then
///     `PrepareWindowsAppExclusions` requires the peer AllowedIPs to contain
///     BOTH the IPv4 and the IPv6 default; a narrow AllowedIPs is refused with
///     "The physical carrier address is not excluded from the tunnel routes."
///  3. `InstallWindowsTunnelConvergenceProbeRoute`
///     (`windows/runner/windows_split_tunnel.cpp`) installs `0.0.0.0/1`,
///     `128.0.0.0/1`, `::/1` and `8000::/1` on the tunnel BEFORE convergence is
///     proven, and `InstallWindowsTunnelRoutes` installs the /0 defaults after.
///     `ConfigureWinsAwgInterface` also sets the tunnel interface's DNS servers.
///
/// So on Windows there is no narrow mode to ask for, and asking anyway does not
/// produce a quiet full tunnel — it produces no tunnel. That is the same
/// fail-closed property the iOS lane had to engineer into its provider, arrived
/// at by a different mechanism, and it is why opening the Windows gate did not
/// have to wait for containment the way iOS did. What it DOES mean is that a
/// Windows session takes the whole machine's routing while it runs, which is
/// why [winnDevSessionUncontainedAckGiven] exists.
const String kWinnDevSessionWindowsContainmentAbsenceRationale =
    'The Windows privileged tunnel service has no containment path: it refuses '
    'the [WinsDevContainment] section outright, requires default-route '
    'AllowedIPs, and installs /1 precommit routes before convergence. A '
    'Windows dev session is therefore UNCONTAINED, and must only be run on a '
    'disposable machine.';

/// Linux reaches the same conclusion as Windows by a completely different
/// mechanism, so quoting the Windows rationale in a Linux transcript states a
/// true conclusion from another platform's evidence. Added 2026-08-06 after
/// three real Linux sessions printed exactly that.
///
/// The Linux privileged script is generated inside
/// `linux/runner/linux_tunnel_backend.cc`, and its `validate_config` step runs
/// an awk allowlist over the config's section headers that accepts only
/// `[interface]` and `[peer]`. A surviving `[WinsDevContainment]` section is
/// therefore not ignored and not honoured -- it makes the script **exit 65**,
/// and no tunnel starts at all. So, as on Windows, there is no narrow mode to
/// ask for and asking anyway produces no tunnel rather than a quiet full one;
/// unlike Windows, the refusal happens in a shell allowlist rather than in a
/// privileged service.
const String kWinnDevSessionLinuxContainmentAbsenceRationale =
    'The Linux privileged tunnel script has no containment path: its '
    'validate_config awk allowlist accepts only [interface] and [peer], so a '
    'surviving [WinsDevContainment] section makes it exit 65 and no tunnel '
    'starts at all. A Linux dev session is therefore UNCONTAINED, and must '
    'only be run on a machine whose routing you can revert.';

/// The containment-absence rationale that is actually true of
/// [operatingSystem]. Callers must use this rather than naming a platform's
/// constant directly, so a transcript never explains itself in terms of a
/// platform it did not run on.
///
/// Only ever consulted on the `!`[winnDevSessionPlatformCanContain] path, so a
/// containment-capable platform has no entry and falls through to the Windows
/// text -- which is unreachable in practice and deliberately not a silent
/// empty string.
String winnDevSessionContainmentAbsenceRationale(String operatingSystem) {
  switch (operatingSystem.trim().toLowerCase()) {
    case 'linux':
      return kWinnDevSessionLinuxContainmentAbsenceRationale;
    default:
      return kWinnDevSessionWindowsContainmentAbsenceRationale;
  }
}

/// Whether [operatingSystem]'s native start honours the containment marker.
bool winnDevSessionPlatformCanContain(String operatingSystem) =>
    kWinnDevSessionContainmentCapablePlatforms
        .contains(operatingSystem.trim().toLowerCase());

/// The dart-define an operator must ALSO pass — with this EXACT value — before
/// this file will deliver a session to a platform that cannot contain it.
///
/// Deliberately NOT a boolean. `true` is what fingers type by reflex and what a
/// copied macOS command line already contains; a sentence naming the
/// consequence is not. A wrong value, including `true`, is a refusal.
const String kWinnDevSessionUncontainedAckDartDefineName =
    'WINN_DEV_UNSAFE_UNCONTAINED_ACK';

/// The one accepted value of [kWinnDevSessionUncontainedAckDartDefineName].
const String kWinnDevSessionUncontainedAckRequiredValue =
    'UNCONTAINED_FULL_TUNNEL_ON_A_DISPOSABLE_VM';

/// The compiled-in value of that dart-define. Empty unless an operator typed it.
const String kWinnDevSessionUncontainedAckDartDefineValue =
    String.fromEnvironment(kWinnDevSessionUncontainedAckDartDefineName);

/// Pure form of the acknowledgement check, so the exact-match property is
/// testable without recompiling with a dart-define.
bool computeWinnDevSessionUncontainedAckGiven(String value) =>
    value == kWinnDevSessionUncontainedAckRequiredValue;

/// The real, wired acknowledgement. Parameterless for the same reason
/// [winnDevSessionActive] is.
bool get winnDevSessionUncontainedAckGiven =>
    computeWinnDevSessionUncontainedAckGiven(
      kWinnDevSessionUncontainedAckDartDefineValue,
    );

/// Printed before an UNCONTAINED session is delivered. There is no quiet path
/// to an uncontained tunnel through this file.
const String kWinnDevSessionUncontainedBanner = '''
################################################################################
# WINN DEV SESSION: THIS SESSION IS **NOT** CONTAINED                          #
#                                                                              #
# The platform this run targets has no containment path in its native start.   #
# The document below therefore carries NO [WinsDevContainment] section — that  #
# section would be refused outright by the native config allowlist and no      #
# tunnel would start at all.                                                   #
#                                                                              #
# What that means, concretely, for the machine this is running on: the tunnel  #
# takes the default routes. On Windows that is 0.0.0.0/1 + 128.0.0.0/1 +       #
# ::/1 + 8000::/1 before convergence and /0 after it, plus tunnel-interface    #
# DNS servers. If the responder does not carry traffic, this host's off-link   #
# networking stops until the tunnel is torn down. The service fails closed and #
# removes its owned routes on any failure, but "fails closed" is not the same  #
# as "harmless".                                                               #
#                                                                              #
# This run proceeded only because the operator typed the exact acknowledgement #
# --dart-define=WINN_DEV_UNSAFE_UNCONTAINED_ACK=                               #
#   UNCONTAINED_FULL_TUNNEL_ON_A_DISPOSABLE_VM                                 #
#                                                                              #
# An uncontained session proves MORE than a contained one about routing, and   #
# exactly the same amount about the winn/3 handshake. It still earns no        #
# capability flip: that is the owner's decision, per                           #
# WINN_PROTOCOL_PLATFORM_PLAN.md rule 4.                                       #
################################################################################''';

/// The platforms whose host app serves `loadOrCreateClientKeyPair` on the
/// shipping `wins_vpn/tunnel` channel.
///
/// Apple only, and this is a property of the native code rather than a policy:
/// `macos/Runner/MainFlutterWindow.swift` and `ios/Runner/AppDelegate.swift`
/// implement that method and then REFUSE any document whose `[Interface]
/// PrivateKey` is not the Keychain pair it returned. The Windows channel
/// handler (`windows/runner/windows_tunnel_backend.cpp`) implements no such
/// method — the shipping app generates and stores Windows key pairs in Dart —
/// so asking for it there returns `MissingPluginException` and there is nothing
/// on the native side that validates the interface key against a store.
const Set<String> kWinnDevSessionNativeKeyPairPlatforms = <String>{
  'macos',
  'ios',
};

/// Whether [operatingSystem] serves `loadOrCreateClientKeyPair`.
bool winnDevSessionPlatformHasNativeKeyPair(String operatingSystem) =>
    kWinnDevSessionNativeKeyPairPlatforms
        .contains(operatingSystem.trim().toLowerCase());

/// Platforms whose `startTunnel`/`stopTunnel` require a positive monotonic
/// transition generation argument.
///
/// Windows alone: `startTunnel` fails with `WINDOWS_TUNNEL_GENERATION_REQUIRED`
/// unless `transitionGeneration` is a positive integer, and `stopTunnel` fails
/// with `WINDOWS_TUNNEL_BAD_CANCELLATION_GENERATION` unless
/// `cancellationGeneration` is. Apple's handlers take neither.
const Set<String> kWinnDevSessionTransitionGenerationPlatforms = <String>{
  'windows',
};

/// Whether [operatingSystem]'s channel requires the generation arguments.
bool winnDevSessionPlatformNeedsTransitionGeneration(String operatingSystem) =>
    kWinnDevSessionTransitionGenerationPlatforms
        .contains(operatingSystem.trim().toLowerCase());

/// Platforms whose native start REQUIRES `[Interface] Table = off` and a
/// `[WinsApp] TunnelGatewayIPv4` literal.
///
/// Windows alone, and both are hard refusals rather than defaults:
/// `InstallPrivilegedTunnel` rejects anything but `Table = off` with "The
/// Win's VPN product engine requires owned Windows routes", and
/// `InstallWindowsTunnelRoutes` rejects a missing or non-RFC1918 gateway with
/// "The Windows per-app tunnel gateway is missing or invalid" -- after the
/// tunnel is already up, which is the worst moment to find out. The shipping
/// writer (`_buildRawAmneziaConfig`, `lib/main.dart`) emits both on Windows and
/// only on Windows; this file has to as well or every Windows session dies at
/// route promotion.
const Set<String> kWinnDevSessionManualRoutingPlatforms = <String>{'windows'};

/// Whether [operatingSystem] needs the manual-routing pair above.
bool winnDevSessionPlatformNeedsManualRouting(String operatingSystem) =>
    kWinnDevSessionManualRoutingPlatforms
        .contains(operatingSystem.trim().toLowerCase());

/// The in-tunnel gateway literal from [config], or `null` when it is absent or
/// is not something the native validator would accept.
///
/// Mirrors `_windowsTunnelGatewayIpv4` (`lib/main.dart`) and the native
/// `ParsePrivateTunnelGatewayIpv4`: RFC1918 only, and never a network or
/// broadcast last octet. Returning `null` rather than throwing lets the caller
/// name the stage it blocked at.
String? winnDevSessionManualRoutingGateway(Map<String, dynamic> config) {
  final raw = (config['tunnel_gateway_ipv4'] ?? config['tunnelgatewayipv4'] ?? '')
      .toString()
      .trim();
  final octets = raw.split('.');
  if (octets.length != 4) return null;
  final values = <int>[];
  for (final octet in octets) {
    if (octet.isEmpty || octet.length > 3) return null;
    final value = int.tryParse(octet);
    if (value == null || value < 0 || value > 255) return null;
    values.add(value);
  }
  final isRfc1918 = values[0] == 10 ||
      (values[0] == 172 && values[1] >= 16 && values[1] <= 31) ||
      (values[0] == 192 && values[1] == 168);
  if (!isRfc1918 || values[3] == 0 || values[3] == 255) return null;
  return raw;
}

/// Did the native `startTunnel` accept, given what it returned?
///
/// Deliberately per-platform, because the shipping handlers do not agree and
/// guessing costs a real session:
///
///  * Apple returns `true` on acceptance (`MainFlutterWindow.startTunnel`),
///    which is what every existing caller tests for.
///  * Windows returns the STRING `"Tunnel Initializing"`
///    (`windows_tunnel_backend.cpp`, the `startTunnel` worker's
///    `result->Success`) and signals every failure by `result->Error`, which
///    reaches Dart as a thrown `PlatformException` and never gets here. So on
///    Windows any non-null return is an acceptance, and `raw == true` -- the
///    old universal test -- would have reported a fully converged tunnel as a
///    refused start.
bool winnDevSessionStartAccepted(String operatingSystem, Object? raw) {
  if (raw == true) return true;
  return kWinnDevSessionStatusStringStartPlatforms
          .contains(operatingSystem.trim().toLowerCase()) &&
      raw is String &&
      raw.trim().isNotEmpty;
}

/// Platforms whose `startTunnel` reports acceptance with a status STRING
/// instead of `true`; see [winnDevSessionStartAccepted].
///
/// LINUX ADDED 2026-08-06 (winn/3 Linux shipping-path lane). Read in the tree,
/// not assumed: `linux/runner/linux_tunnel_backend.cc`'s `MethodCallHandler`
/// answers `startTunnel` with
/// `RespondSuccess(method_call, fl_value_new_string("Tunnel Initializing"))`
/// and reports every failure with `RespondError(..., "LINUX_TUNNEL_START_FAILED",
/// ...)`, which reaches Dart as a thrown `PlatformException` and never gets
/// here -- the identical contract Windows has, in the identical words.
///
/// ANDROID ADDED 2026-08-21 (Android app-level live winn3 lane). Same contract,
/// same words: `MainActivity.executeServiceLaunch` answers the `startTunnel`
/// channel method with `result.success("Tunnel Initializing")` after
/// `startForegroundService`, and signals a failed launch with `result.error`,
/// which reaches Dart as a thrown `PlatformException` and never gets here.
/// Leaving Android out made `runWinnDevSession` report
/// `blockedAt: 'native_start'` for a tunnel the `VpnTunnelService` had ALREADY
/// started -- so the harness skipped the traffic phase while the native winn/3
/// staged start was running, and the session's own 30 s promotion proof
/// deadline (`WinnV3StagedStart.DEFAULT_PROOF_DEADLINE_MS`) expired with zero
/// inner packets. The string here is not evidence of convergence; it is the
/// same "launch was accepted" signal the Linux contract treats it as, and the
/// harness's own verdict language below does not claim more.
///
/// Leaving a platform out is not a cosmetic mislabel. `runWinnDevSession`
/// would have taken the `!canContain` return with `blockedAt: 'native_start'`
/// for a tunnel the native side had ALREADY brought up, so the harness would
/// have reported a refusal, skipped the traffic phase, and left a live
/// full-tunnel session running on the machine with nothing arranged to stop
/// it.
const Set<String> kWinnDevSessionStatusStringStartPlatforms = <String>{
  'windows',
  'linux',
  'android',
};

/// A positive, monotonically increasing transition generation.
///
/// Wall-clock milliseconds: positive, fits int64, and increases across
/// re-runs of this harness within one process and across processes, which is
/// all the Windows backend's `IsWindowsStartGenerationAllowed` floor requires.
int winnDevSessionTransitionGeneration([DateTime? now]) =>
    (now ?? DateTime.now()).millisecondsSinceEpoch;

/// The arguments a `stopTunnel` call needs on [operatingSystem].
///
/// `null` on Apple, exactly as every existing caller passes today. On Windows
/// a `stopTunnel` without a positive `cancellationGeneration` still tears the
/// tunnel down but then reports `WINDOWS_TUNNEL_BAD_CANCELLATION_GENERATION`
/// and latches the backend fail-closed until the app restarts -- a teardown
/// that works once and then refuses to start again, which is a miserable way
/// to lose an evening.
Object? winnDevSessionStopArguments(String operatingSystem, [DateTime? now]) {
  if (!winnDevSessionPlatformNeedsTransitionGeneration(operatingSystem)) {
    return null;
  }
  return <String, dynamic>{
    'cancellationGeneration': winnDevSessionTransitionGeneration(now),
  };
}

/// Assembles the complete AmneziaWG document to hand to native.
///
/// # Why this INI writer exists here rather than being shared
///
/// The shipping writer is `_buildRawAmneziaConfig`
/// (`lib/main.dart:3272-3401`), a private method on a private `State` class.
/// Dart privacy is per-library, so it is unreachable from any other file, and
/// `lib/main.dart` is release-frozen at 1.0.14+29 and concurrently edited --
/// refactoring it to expose that writer is a change to the shipping binary in
/// service of a dev-only path, which is the wrong trade. The sibling
/// `winn_protocol_dev_config_source.dart` reached the same conclusion and
/// stopped at the `[winn]` boundary rather than duplicating this.
///
/// What keeps the duplication honest is that this document is not validated by
/// this file. It is handed to `WinsTunnelConfig.parseAndValidate`
/// (`macos/Runner/MainFlutterWindow.swift:1125`) -- the same native validator,
/// with the same 1101..1506 refusal codes, that every shipping start passes
/// through. A drift between this writer and the shipping one shows up as a
/// native validation refusal naming the field, not as a silently different
/// tunnel.
///
/// [winnSection] is passed in rather than computed here so that this function
/// cannot become a second place that decides whether Winn may start. Its only
/// legitimate sources are the real dispatch library -- and, on Windows alone,
/// [winnDevSessionWindowsWinn3NativeSection] for the local `[winn3]` spelling
/// the Windows tunnel service's [winn3] allowlist accepts; see
/// [runWinnDevSession].
///
/// [interfacePrivateKey] must be the device Keychain's own private key; see the
/// library doc.
///
/// [containmentSupportedByPlatform] defaults to `true`, which is the shape
/// every existing caller and every Apple session uses: the containment section
/// is emitted unconditionally and cannot be turned off by anything in the
/// config. Passing `false` is ONLY legitimate for a platform in neither
/// [kWinnDevSessionContainmentCapablePlatforms] nor any future one — a platform
/// whose native validator REFUSES the section, where emitting it produces no
/// tunnel rather than a contained one. [runWinnDevSession] derives this from
/// [winnDevSessionPlatformCanContain] and never from a caller's preference, and
/// it additionally requires [winnDevSessionUncontainedAckGiven] before it will
/// pass `false`. There is deliberately no config key and no dart-define that
/// turns containment off for a platform that HAS it.
String assembleWinnDevSessionTunnelDocument({
  required Map<String, dynamic> config,
  required String winnSection,
  required String interfacePrivateKey,
  required String clientPublicKey,
  bool containmentSupportedByPlatform = true,
  String manualRoutingTunnelGatewayIPv4 = '',
}) {
  if (winnSection.trim().isEmpty) {
    // '' is exactly what the native host reads as "start plain AmneziaWG", so
    // producing a document without a [winn] or [winn3] section for a winn/3
    // session would be the silent downgrade every gate in this project exists
    // to prevent.
    throw StateError(
      'Refusing to assemble a Winn dev session document with an empty [winn] '
      'or [winn3] section: an AmneziaWG document with neither starts a '
      'classical winn/1 tunnel, which would silently downgrade the session.',
    );
  }
  final obfuscation = config['obfuscation'] is Map
      ? Map<String, dynamic>.from(config['obfuscation'] as Map)
      : const <String, dynamic>{};
  Object obfs(String key) =>
      obfuscation[key] ?? kWinnDevSessionObfuscationDefaults[key]!;

  final clientIp = (config['client_ip'] ?? '').toString().trim();
  final serverPublicKey = (config['server_public_key'] ?? '').toString().trim();
  final serverEndpoint = (config['server_endpoint'] ?? '').toString().trim();
  final mtu = (config['mtu'] ?? '').toString().trim();
  final dns = (config['dns'] ?? '1.1.1.1, 1.0.0.1').toString().trim();
  final presharedKey = (config['preshared_key'] ?? '').toString().trim();
  final presharedKeyLine =
      presharedKey.isEmpty ? '' : 'PresharedKey = $presharedKey';

  final manualRouting = manualRoutingTunnelGatewayIPv4.trim();

  return <String>[
    '[Interface]',
    'PrivateKey = $interfacePrivateKey',
    'Address = $clientIp/32',
    'MTU = $mtu',
    'DNS = $dns',
    // Windows refuses any other value, and Apple's parser has no Table key at
    // all, so this is emitted exactly where the native start demands it. See
    // [kWinnDevSessionManualRoutingPlatforms].
    if (manualRouting.isNotEmpty) 'Table = off',
    'Jc = ${obfs('Jc')}',
    'Jmin = ${obfs('Jmin')}',
    'Jmax = ${obfs('Jmax')}',
    'S1 = ${obfs('S1')}',
    'S2 = ${obfs('S2')}',
    'S3 = ${obfs('S3')}',
    'S4 = ${obfs('S4')}',
    'H1 = ${obfs('H1')}',
    'H2 = ${obfs('H2')}',
    'H3 = ${obfs('H3')}',
    'H4 = ${obfs('H4')}',
    '',
    '[Peer]',
    'PublicKey = $serverPublicKey',
    presharedKeyLine,
    // The REAL AmneziaWG gateway, never a loopback address: `validate()`
    // refuses a loopback peer endpoint for a Winn config at code 1505
    // (`WinsTunnelConfig.swift:1243-1248`) because the rewrite to the seam
    // happens later, in WinsPacketTunnelEngine, and a peer that is already
    // loopback has no recoverable real gateway.
    'Endpoint = $serverEndpoint',
    'AllowedIPs = ${kWinnDevSessionAllowedIPs.join(', ')}',
    'PersistentKeepalive = 25',
    '',
    '[WinsDebug]',
    'ClientPublicKey = $clientPublicKey',
    '',
    '[WinsApp]',
    'ExcludedPackages = ',
    'ExcludedPathsB64 = ${base64Encode(const <int>[])}',
    if (manualRouting.isNotEmpty) 'TunnelGatewayIPv4 = $manualRouting',
    '',
    // CONTAINMENT, UNCONDITIONALLY on every platform that can honour it. See
    // [kWinnDevSessionContainmentRationale]. The AllowedIPs above still say
    // `0.0.0.0/0, ::/0` because the native validator requires that pairing for
    // a Winn config (code 1203) and because the /32 transport exclusion is
    // derived from it (code 1504). This section is what tells a DEBUG provider
    // to install a narrow route instead, and a Release provider ignores it
    // entirely.
    //
    // The section is omitted ONLY where emitting it would prevent any tunnel at
    // all -- a platform whose native config allowlist refuses the section
    // outright, i.e. Windows. That is not a weakening of containment: on such a
    // platform there is no contained mode to lose. See
    // [kWinnDevSessionWindowsContainmentAbsenceRationale].
    if (containmentSupportedByPlatform) '[$kWinnDevSessionContainmentSection]',
    if (containmentSupportedByPlatform) 'Enabled = true',
    if (containmentSupportedByPlatform &&
        kWinnDevSessionContainmentTestRoute.isNotEmpty)
      'TestRoute = $kWinnDevSessionContainmentTestRoute',
    '',
    winnSection.trim(),
  ]
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty)
      .join('\n');
}

/// The config keys a Windows STANDALONE winn/3 session reads for its native
/// `[winn3]` section.
///
/// These are the LOCAL spelling the Windows supervisor's `ParseWinn3Section`
/// accepts (`windows/runner/winn3_supervisor.h`), which names key FILES rather
/// than key values: the control plane cannot name a path on a device it has
/// never seen, and a hand-written dev config on the machine it runs on can.
/// Every key here maps one to one onto that parser's accepted local set, plus
/// the optional [kWinnDevSessionWindowsWinn3OptionalKeys].
///
/// A MISSING one is a refusal, never a default: `ParseWinn3Section` refuses an
/// incomplete section by name, so silently defaulting one here would only move
/// the same refusal from a named Dart error to a named native one after the
/// adapter dance has begun.
const Set<String> kWinnDevSessionWindowsWinn3NativeKeys = <String>{
  'winn3_endpoint',
  'winn3_class',
  'winn3_plan',
  'winn3_path_mtu',
  'winn3_gateway_id',
  'winn3_inner_v4',
  'winn3_router_v4',
  'winn3_static_key_path',
  'winn3_gateway_static_key_path',
  'winn3_admission_path',
};

/// Optional [kWinnDevSessionWindowsWinn3NativeKeys] companions. `winn3_routes`
/// is emitted verbatim when present; `winn3_dns` is emitted together with
/// `dns_are_inner = true`, because the native parser refuses one without the
/// other (a resolver reachable outside the tunnel is a censored-path DNS leak
/// the moment the tunnel drops).
const Set<String> kWinnDevSessionWindowsWinn3OptionalKeys = <String>{
  'winn3_routes',
  'winn3_dns',
};

/// The carrier classes [kWinnDevSessionWindowsWinn3NativeKeys] may name. Same
/// three values the native `ParseWinn3Section` accepts, kept in one place so a
/// drift shows up as one edit rather than as a mismatched string pair.
const Set<String> kWinnDevSessionWindowsWinn3CarrierClasses = <String>{
  'udp',
  'tcp',
  'tls',
};

/// True when [config] carries ANY Windows-native winn/3 field. Presence is the
/// selector: a config with none of these keys follows the unchanged
/// `[winn]`-from-the-dispatch-library path, byte for byte as before.
bool winnDevSessionConfigHasWinn3NativeFields(Map<String, dynamic> config) {
  final present = <String>{
    ...kWinnDevSessionWindowsWinn3NativeKeys,
    ...kWinnDevSessionWindowsWinn3OptionalKeys,
  }.any((key) => (config[key]?.toString().trim() ?? '').isNotEmpty);
  return present;
}

/// Whether [operatingSystem] uses the Windows native `[winn3]` spelling.
///
/// The emission is gated per-platform: `windows` AND [config] carrying at least
/// one native field. Every other platform returns false here and keeps its
/// existing `[winn]` section, so no other platform's document changes a byte.
bool winnDevSessionPlatformUsesWindowsWinn3NativeSpelling(
  String operatingSystem,
  Map<String, dynamic> config,
) {
  return operatingSystem.trim().toLowerCase() == 'windows' &&
      winnDevSessionConfigHasWinn3NativeFields(config);
}

/// Renders the Windows STANDALONE `[winn3]` section from [config].
///
/// This is a dev-config LOCAL spelling, never the served `[winn]` one: the
/// static key, gateway static key and admission secret arrive as PATHS to files
/// already on the machine, exactly as `ParseWinn3Section`'s local branch
/// requires, and `gateway_id` is the raw operator bytes (never base64, which is
/// the served spelling only).
///
/// Throws [StateError] naming the first incomplete or malformed field rather
/// than emitting something the native host would refuse after the adapter
/// dance. A control character, `[` or `]` in any value is refused here for the
/// same reason: a newline forges an extra INI key and a bracket forges a
/// section header.
String winnDevSessionWindowsWinn3NativeSection(Map<String, dynamic> config) {
  String value(String key) => (config[key] ?? '').toString().trim();
  void checkIniSafe(String key) {
    final text = value(key);
    for (final unit in text.codeUnits) {
      if (unit < 0x20 || unit == 0x7F || unit == 0x5B || unit == 0x5D) {
        throw StateError(
            'Refusing to build a Windows [winn3] section: "$key" carries a '
            'control character or bracket that could forge an INI directive.');
      }
    }
  }

  final missing = kWinnDevSessionWindowsWinn3NativeKeys
      .where((key) => value(key).isEmpty)
      .toList()
    ..sort();
  if (missing.isNotEmpty) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: the dev config file '
        'carries some Windows-native winn/3 fields but is missing '
        '(${missing.join(', ')}). A partial native section is refused rather '
        'than silently degraded to the AWG carrier.');
  }

  final endpoint = value('winn3_endpoint');
  if (!isWinnIpLiteralEndpoint(endpoint)) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_endpoint '
        '"$endpoint" is not an IP literal with a port. The staged posture of a '
        'standalone session exists so no resolver is touched until the '
        'datapath is proven, so a hostname here is exactly what it must not '
        'be.');
  }
  final carrierClass = value('winn3_class').toLowerCase();
  if (!kWinnDevSessionWindowsWinn3CarrierClasses.contains(carrierClass)) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_class '
        '"$carrierClass" must be udp, tcp or tls.');
  }
  final plan = value('winn3_plan')
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .where((token) => token.isNotEmpty)
      .toList(growable: false);
  if (plan.isEmpty ||
      plan.any((token) =>
          !kWinnDevSessionWindowsWinn3CarrierClasses.contains(token)) ||
      !plan.contains(carrierClass)) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_plan '
        '"${value('winn3_plan')}" must name only udp/tcp/tls and must contain '
        'winn3_class "$carrierClass", because the message floor (and therefore '
        'the adapter MTU) is computed over the plan.');
  }
  final pathMtuText = value('winn3_path_mtu');
  if (pathMtuText.isEmpty ||
      !pathMtuText.split('').every((c) =>
          c.codeUnitAt(0) >= 0x30 && c.codeUnitAt(0) <= 0x39) ||
      int.parse(pathMtuText) < 576 ||
      int.parse(pathMtuText) > 65535) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_path_mtu '
        '"$pathMtuText" is not a usable number.');
  }
  final innerV4 = value('winn3_inner_v4');
  if (!isWinnInnerIpv4(innerV4)) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_inner_v4 '
        '"$innerV4" is not a usable inner IPv4 assignment.');
  }
  final routerV4 = value('winn3_router_v4');
  if (!isWinnInnerIpv4(routerV4)) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_router_v4 '
        '"$routerV4" is not a usable inner IPv4 next hop.');
  }
  if (innerV4 == routerV4) {
    throw StateError(
        'Refusing to build a Windows [winn3] section: winn3_inner_v4 and '
        'winn3_router_v4 are the same address, which would make this device '
        'its own next hop.');
  }
  for (final key in <String>[
    'winn3_gateway_id',
    'winn3_static_key_path',
    'winn3_gateway_static_key_path',
    'winn3_admission_path',
    if (value('winn3_routes').isNotEmpty) 'winn3_routes',
    if (value('winn3_dns').isNotEmpty) 'winn3_dns',
  ]) {
    checkIniSafe(key);
  }

  final lines = <String>[
    '[winn3]',
    'enabled = true',
    'endpoint = $endpoint',
    'class = $carrierClass',
    'plan = ${plan.join(', ')}',
    'path_mtu = $pathMtuText',
    'gateway_id = ${value('winn3_gateway_id')}',
    'inner_v4 = $innerV4',
    'router_v4 = $routerV4',
    'static_key_path = ${value('winn3_static_key_path')}',
    'gateway_static_key_path = ${value('winn3_gateway_static_key_path')}',
    'admission_path = ${value('winn3_admission_path')}',
    if (value('winn3_routes').isNotEmpty) 'routes = ${value('winn3_routes')}',
    if (value('winn3_dns').isNotEmpty) 'dns = ${value('winn3_dns')}',
    if (value('winn3_dns').isNotEmpty) 'dns_are_inner = true',
  ];
  return lines.join('\n');
}

/// How long to wait for the Packet Tunnel extension to publish a status
/// document of its own before judging containment.
///
/// Generous on purpose: the cost of waiting is a slower dev session, the cost
/// of not waiting is tearing down a correctly contained session because the
/// extension had not started yet.
const Duration kWinnDevSessionProviderStatusTimeout = Duration(seconds: 45);

/// How often to re-read readiness while waiting for the above.
const Duration kWinnDevSessionProviderStatusPollInterval =
    Duration(milliseconds: 750);

/// How long a platform that CANNOT contain waits for the readiness snapshot
/// before the harness proceeds to the traffic phase. See the platform-aware
/// wait in [runWinnDevSession] stage 6 for why this must stay far below
/// Android's 30 s native proof deadline.
const Duration kWinnDevSessionProviderStatusSnapshotWindow =
    Duration(seconds: 6);

/// The one `stage` value the HOST APP writes into the shared status document
/// (`ios/Runner/AppDelegate.swift`, `macos/Runner/MainFlutterWindow.swift`).
/// Every other stage comes from the appex itself.
const String kWinnDevSessionAppWrittenStage = 'config_saved';

/// Whether [providerStatus] is a document the PROVIDER wrote, as opposed to the
/// placeholder the host app writes when it saves the configuration.
///
/// Deliberately keyed on the stage rather than on the containment fields: the
/// containment fields are what the verdict is computed FROM, so using their
/// presence to decide whether to keep waiting would make "the provider said
/// nothing about containment" and "the provider has not spoken yet"
/// indistinguishable — which is exactly the confusion this predicate exists to
/// remove. A provider that publishes `engine_started` with no containment
/// fields is a REAL failed-containment verdict and must not be waited out.
bool winnDevSessionProviderHasPublished(Map<String, dynamic>? providerStatus) {
  if (providerStatus == null) return false;
  final stage = (providerStatus['provider_stage'] ?? providerStatus['stage'])
      ?.toString()
      .trim();
  if (stage == null || stage.isEmpty) return false;
  return stage != kWinnDevSessionAppWrittenStage;
}

/// The provider-status field that says a session was ACTUALLY contained.
///
/// Written only by a Packet Tunnel appex that took the containment path, and
/// forwarded into the app's readiness map under the `provider_` namespace by
/// `ios/Runner/AppDelegate.swift` / `macos/Runner/MainFlutterWindow.swift`.
/// Both spellings are accepted because a caller may hand this either the raw
/// provider status document or the readiness map built from it; they carry the
/// same value and only the provider can write either.
const List<String> kWinnDevSessionContainmentActiveKeys = <String>[
  'provider_dev_containment_active',
  'dev_containment_active',
];

/// Fields that must be present AND false before a session counts as contained.
/// Each is one third of the 2026-08-05 blackout: the default IPv4 route, the
/// IPv6 sink, and the DNS capture.
///
/// A MISSING field fails the check. That is the whole point: "the provider did
/// not say" and "the provider said no" are different, and only the second is
/// evidence. The dangerous direction here is a false confirmation, so absence
/// resolves against containment, never for it.
const Map<String, List<String>> kWinnDevSessionContainmentMustBeFalseKeys =
    <String, List<String>>{
  'default_ipv4_route_installed': <String>[
    'provider_dev_containment_default_ipv4_route_installed',
    'dev_containment_default_ipv4_route_installed',
  ],
  'ipv6_settings_installed': <String>[
    'provider_dev_containment_ipv6_settings_installed',
    'dev_containment_ipv6_settings_installed',
  ],
  'dns_settings_installed': <String>[
    'provider_dev_containment_dns_settings_installed',
    'dev_containment_dns_settings_installed',
  ],
};

/// The iOS-only read-back fields. `ios/PacketTunnel/PacketTunnelProvider.swift`
/// inspects the `NEPacketTunnelNetworkSettings` object it just built and reports
/// what it FOUND there; macOS reports only what it intended. So this is checked
/// when present and not required when absent — requiring it would fail every
/// macOS session for no reason, and demanding it of macOS is that lane's call,
/// not this one's.
const List<String> kWinnDevSessionContainmentObservedKeys = <String>[
  'provider_dev_containment_observed_contained',
  'dev_containment_observed_contained',
];

/// Whether the app-side full-tunnel leak-protection verdict passed. A contained
/// session MUST fail it: `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields`
/// has a `!devContainmentActive` term precisely so a narrow session can never
/// report a validated full-tunnel posture. A `true` here alongside a claimed
/// containment means the two halves disagree, and a disagreement about leak
/// protection is resolved against the session.
const List<String> kWinnDevSessionLeakProtectionPassedKeys = <String>[
  'leak_protection_config_passed',
  'provider_leak_protection_config_passed',
];

Object? _firstPresent(Map<String, dynamic> fields, List<String> keys) {
  for (final key in keys) {
    if (fields.containsKey(key)) return fields[key];
  }
  return null;
}

bool? _firstPresentBool(Map<String, dynamic> fields, List<String> keys) {
  final value = _firstPresent(fields, keys);
  if (value is bool) return value;
  if (value is String) {
    final normalized = value.trim().toLowerCase();
    if (normalized == 'true') return true;
    if (normalized == 'false') return false;
  }
  return null;
}

/// What the provider's own status says about whether the session that just
/// started was actually contained.
class WinnDevSessionContainmentVerdict {
  const WinnDevSessionContainmentVerdict({
    required this.confirmed,
    required this.reasons,
    required this.observedFields,
  });

  /// True only when the provider status positively establishes containment.
  /// Never true by default, never true because a field was absent, and never
  /// true because the document this app SENT asked for containment.
  final bool confirmed;

  /// Machine-readable reasons this was not confirmed, sorted. Empty iff
  /// [confirmed].
  final List<String> reasons;

  /// The containment-related fields actually found, for the log and the
  /// handoff. Contains no key material: every one is a bool, an int or a short
  /// enumerated string minted by the provider.
  final Map<String, dynamic> observedFields;
}

/// Reads a provider status (or the readiness map built from it) and decides
/// whether containment is ESTABLISHED — as opposed to requested, intended, or
/// stamped.
///
/// # Why this function exists at all
///
/// Before it, `runWinnDevSession` wrote `[WinsDevContainment] Enabled = true`
/// into every document and then LOGGED that the session was contained. On macOS
/// that happened to be true, because the macOS provider honours the marker. On
/// iOS the provider contained no containment code whatsoever: the marker was
/// ignored, the session took the phone's default route, its IPv6 and all of its
/// DNS, and the app said "contained" the entire time. The document asking for
/// something is not evidence that it happened. Only the provider can say, and
/// this is the function that listens to it.
///
/// Deliberately pure and gate-independent, so every branch is unit-testable
/// without a platform, a channel, or a device.
WinnDevSessionContainmentVerdict evaluateWinnDevSessionContainment(
  Map<String, dynamic>? providerStatus,
) {
  if (providerStatus == null) {
    return const WinnDevSessionContainmentVerdict(
      confirmed: false,
      reasons: <String>['provider_status_unavailable'],
      observedFields: <String, dynamic>{},
    );
  }

  final observed = <String, dynamic>{};
  void record(List<String> keys) {
    for (final key in keys) {
      if (providerStatus.containsKey(key)) observed[key] = providerStatus[key];
    }
  }

  record(kWinnDevSessionContainmentActiveKeys);
  for (final keys in kWinnDevSessionContainmentMustBeFalseKeys.values) {
    record(keys);
  }
  record(kWinnDevSessionContainmentObservedKeys);
  record(kWinnDevSessionLeakProtectionPassedKeys);

  final reasons = <String>[];

  final active = _firstPresentBool(
    providerStatus,
    kWinnDevSessionContainmentActiveKeys,
  );
  if (active == null) {
    reasons.add('containment_active_absent');
  } else if (!active) {
    reasons.add('containment_active_false');
  }

  for (final entry in kWinnDevSessionContainmentMustBeFalseKeys.entries) {
    final value = _firstPresentBool(providerStatus, entry.value);
    if (value == null) {
      reasons.add('${entry.key}_absent');
    } else if (value) {
      reasons.add('${entry.key}_true');
    }
  }

  final observedContained = _firstPresentBool(
    providerStatus,
    kWinnDevSessionContainmentObservedKeys,
  );
  if (observedContained == false) {
    reasons.add('observed_contained_false');
  }

  final leakProtectionPassed = _firstPresentBool(
    providerStatus,
    kWinnDevSessionLeakProtectionPassedKeys,
  );
  if (leakProtectionPassed == true) {
    reasons.add('leak_protection_config_passed_true');
  }

  reasons.sort();
  return WinnDevSessionContainmentVerdict(
    confirmed: reasons.isEmpty,
    reasons: List<String>.unmodifiable(reasons),
    observedFields: Map<String, dynamic>.unmodifiable(observed),
  );
}

/// Everything one [runWinnDevSession] call found out.
class WinnDevSessionResult {
  const WinnDevSessionResult({
    required this.active,
    this.blockedAt,
    this.error,
    this.sessionId,
    this.winnSection,
    this.documentRedacted,
    this.nativeStartAccepted,
    this.providerStatus,
    this.containmentVerdict,
    this.torndownBecauseUncontained = false,
  });

  /// Whether the double gate was active. When false this is the ONLY populated
  /// field: no file was read, no channel was called, nothing was logged.
  final bool active;

  /// The named stage this session stopped at, or `null` if it reached the end
  /// of what this file drives. Deliberately a short machine-readable token
  /// (`config_source`, `client_key_pair`, `winn_section`, `native_start`,
  /// `provider_status`) so a handoff can quote it verbatim.
  ///
  /// A populated [blockedAt] is a RESULT, not a failure of this file. "BLOCKED
  /// at native_start because macOS has no VPN configuration consent yet" is a
  /// true and useful outcome; a fabricated success is not.
  final String? blockedAt;

  /// Why, in prose. Built only from stage names, exception types and messages
  /// produced by the platform -- never from key material.
  final String? error;

  /// The freshly generated 32-hex session id, once one exists.
  final String? sessionId;

  /// The `[winn]` section the REAL dispatch library produced. Contains no key
  /// material by construction (see [resolveWinnProtocolStart]'s emitted keys).
  final String? winnSection;

  /// The assembled document with secrets replaced -- safe to print, safe to
  /// paste into a handoff.
  final String? documentRedacted;

  /// What the native `startTunnel` method returned, or `null` if it was never
  /// reached or it threw.
  final bool? nativeStartAccepted;

  /// The provider status snapshot read back after the start attempt, or `null`.
  /// This is where the seam/handshake evidence appears.
  final Map<String, dynamic>? providerStatus;

  /// What the PROVIDER said about containment, or `null` if the run never got
  /// far enough to ask. This — not the document that was sent — is the only
  /// thing that makes "this session was contained" a true statement.
  final WinnDevSessionContainmentVerdict? containmentVerdict;

  /// True when this run started a tunnel, could not confirm containment, and
  /// therefore asked native to stop it again. A session that cannot prove it is
  /// contained is not allowed to keep running.
  final bool torndownBecauseUncontained;
}

/// How this file talks to native. Defaults to the SHIPPING channel -- the exact
/// `MethodChannel('wins_vpn/tunnel')` `lib/main.dart:130` declares and
/// `macos/Runner/MainFlutterWindow.swift:626` serves. A parameter rather than a
/// hard-coded call only so the driver is testable without a platform; it is not
/// a gate, and substituting it cannot open a path that [winnDevSessionActive]
/// has closed.
typedef WinnDevSessionInvoker = Future<Object?> Function(
  String method,
  Object? arguments,
);

const MethodChannel _shippingTunnelChannel = MethodChannel('wins_vpn/tunnel');

Future<Object?> _shippingInvoker(String method, Object? arguments) =>
    _shippingTunnelChannel.invokeMethod<Object?>(method, arguments);

/// Drives one dev-only `winn/3` delivery, end to end.
///
/// Stage by stage:
///
///  1. Load the operator's config through the REAL
///     [resolveWinnDevConfigSourceStart] (gated on `WINN_DEV_CONFIG_PATH`).
///  2. Generate a fresh 32-hex `session_id` and overwrite whatever the file
///     carried.
///  3. Fetch this device's Keychain key pair through the SHIPPING
///     `loadOrCreateClientKeyPair` channel method.
///  4. Ask the REAL dispatch library for the `[winn]` section
///     ([winnSectionForTunnelConfigDevOnly]).
///  5. Assemble the document and hand it to the SHIPPING `startTunnel` method,
///     which writes both the App Group file and the `raw_config` start option
///     and starts the provider.
///  6. Read the provider status back.
///
/// Every stage that cannot proceed returns a [WinnDevSessionResult] naming
/// itself in [WinnDevSessionResult.blockedAt]. Nothing here retries, degrades,
/// or falls back to a non-Winn start.
Future<WinnDevSessionResult> runWinnDevSession({
  required String operatingSystem,
  String accountScope = '',
  WinnDevSessionInvoker invoke = _shippingInvoker,
  WinnDevSessionLogger log = _defaultWinnDevSessionLogger,
}) async {
  if (!winnDevSessionActive) {
    return const WinnDevSessionResult(active: false);
  }
  log(kWinnDevSessionBanner);

  // --- 0. can this platform contain a session at all? -----------------------
  //
  // Before the config is even read, because the answer decides whether this
  // run is allowed to exist. A platform that CAN contain proceeds exactly as
  // before -- byte-identical path, containment always requested, containment
  // required from the provider before the tunnel is allowed to stay up. A
  // platform that CANNOT is refused unless the operator typed the exact
  // acknowledgement, and even then it is told, loudly, what it is getting.
  final canContain = winnDevSessionPlatformCanContain(operatingSystem);
  // LANE-ONLY CHANGE (T-M fleet speed lane, 2026-08-23, worktree /tmp/t-m-fleet,
  // NOT for merge, never committed): honour the operator's
  // WINN_DEV_UNSAFE_UNCONTAINED_ACK on a containment-capable platform too, so a
  // macOS dev session can run UNCONTAINED (full-tunnel with the default route
  // owned, kill-switch first posture, promotion-gated) when the operator
  // deliberately acknowledged it. This reuses the exact ack, banner, verdict
  // and traffic machinery the Windows/Linux path already has; macOS keeps its
  // contained default whenever the ack is absent.
  final effectiveCanContain = canContain && !winnDevSessionUncontainedAckGiven;
  if (!effectiveCanContain) {
    if (!canContain) {
      if (!winnDevSessionUncontainedAckGiven) {
        final error =
            'this platform ("$operatingSystem") has no containment path in its '
            'native start, so any session it runs takes the whole machine\'s '
            'routing. '
            '${winnDevSessionContainmentAbsenceRationale(operatingSystem)} Pass '
            '--dart-define=$kWinnDevSessionUncontainedAckDartDefineName='
            '$kWinnDevSessionUncontainedAckRequiredValue to proceed anyway, and '
            'only on a machine you can revert.';
        log('WINN DEV SESSION: BLOCKED at platform_containment -- $error');
        return WinnDevSessionResult(
          active: true,
          blockedAt: 'platform_containment',
          error: error,
        );
      }
    } else {
      log('WINN DEV SESSION: LANE-ONLY UNCONTAINED OVERRIDE -- this platform '
          '("$operatingSystem") CAN contain, and the operator\'s exact '
          'acknowledgement ($kWinnDevSessionUncontainedAckDartDefineName) '
          'forced the uncontained full-tunnel path anyway. The document below '
          'carries NO [$kWinnDevSessionContainmentSection] section.');
    }
    log(kWinnDevSessionUncontainedBanner);
  }

  // --- 1. the config, from the real dev config source -----------------------
  final source = resolveWinnDevConfigSourceStart(
    operatingSystem: operatingSystem,
    log: log,
  );
  if (!source.active) {
    const error =
        'WINN_DEV_CONFIG_PATH is not set, so there is no winn/3 config to '
        'deliver. Both dart-defines are required: WINN_DEV_SESSION=true picks '
        'this path, WINN_DEV_CONFIG_PATH=<file> supplies the config.';
    log('WINN DEV SESSION: BLOCKED at config_source -- $error');
    return const WinnDevSessionResult(
      active: true,
      blockedAt: 'config_source',
      error: error,
    );
  }
  if (source.loadError != null || source.normalizedConfig == null) {
    log('WINN DEV SESSION: BLOCKED at config_source -- ${source.loadError}');
    return WinnDevSessionResult(
      active: true,
      blockedAt: 'config_source',
      error: source.loadError,
    );
  }

  // --- 2. a fresh session id, never a served one ----------------------------
  final sessionId = generateWinnDevSessionId();
  final config = winnDevSessionConfigWithFreshSessionId(
    source.normalizedConfig!,
    sessionId,
  );
  log('WINN DEV SESSION: generated session_id=$sessionId '
      '(32 lowercase hex, Random.secure, fresh for this session; any '
      'session_id in the config file was discarded).');

  // --- 3. the device's own key pair ------------------------------------------
  //
  // On Apple this MUST come from the Keychain over the shipping channel,
  // because the native start refuses any other pair. On a platform whose
  // channel serves no such method (Windows), that requirement does not exist
  // and neither does the method, so the pair comes from the dev config file --
  // which `kWinnDevConfigRequiredFields` already forces to carry both halves.
  final String interfacePrivateKey;
  final String clientPublicKey;
  if (winnDevSessionPlatformHasNativeKeyPair(operatingSystem)) {
    try {
      final raw = await invoke(
        'loadOrCreateClientKeyPair',
        <String, dynamic>{'accountScope': accountScope},
      );
      final pair = Map<String, dynamic>.from(raw as Map);
      interfacePrivateKey = (pair['private_key'] ?? '').toString();
      clientPublicKey = (pair['public_key'] ?? '').toString();
      if (interfacePrivateKey.isEmpty || clientPublicKey.isEmpty) {
        throw StateError('the channel returned an incomplete key pair');
      }
    } catch (error) {
      final message =
          'could not load this device\'s client key pair: $error. The native '
          'start refuses any document whose [Interface] PrivateKey is not this '
          'exact Keychain pair (MainFlutterWindow.swift:1127).';
      log('WINN DEV SESSION: BLOCKED at client_key_pair -- $message');
      return WinnDevSessionResult(
        active: true,
        blockedAt: 'client_key_pair',
        error: message,
        sessionId: sessionId,
      );
    }
    // Public keys are not secret. The private key is never logged.
    log('WINN DEV SESSION: using the device Keychain key pair for '
        '[Interface] PrivateKey (accountScope="$accountScope", '
        'public_key=$clientPublicKey). The dev config file\'s '
        'client_private_key is NOT used for the interface -- the native start '
        'requires the Keychain pair. Register this public key with the gateway '
        'or the handshake cannot complete.');
  } else {
    interfacePrivateKey = (config['client_private_key'] ?? '').toString().trim();
    clientPublicKey = (config['client_public_key'] ?? '').toString().trim();
    if (interfacePrivateKey.isEmpty || clientPublicKey.isEmpty) {
      const message =
          'this platform serves no loadOrCreateClientKeyPair channel method, so '
          'the interface key pair has to come from the dev config file, and '
          'client_private_key/client_public_key are not both present in it.';
      log('WINN DEV SESSION: BLOCKED at client_key_pair -- $message');
      return WinnDevSessionResult(
        active: true,
        blockedAt: 'client_key_pair',
        error: message,
        sessionId: sessionId,
      );
    }
    log('WINN DEV SESSION: using the DEV CONFIG FILE\'s client key pair for '
        '[Interface] PrivateKey (public_key=$clientPublicKey). This platform\'s '
        'channel has no loadOrCreateClientKeyPair method and its native start '
        'validates the interface key only for self-consistency with the '
        'running AWG runtime, never against a system key store. Register this '
        'public key with the gateway or the handshake cannot complete.');
  }

  // --- 4. the winn section, from the real dispatch OR the Windows [winn3]
  //        local spelling -----------------------------------------------------
  //
  // Windows STANDALONE is the one platform that does not go through the
  // dispatch library's `[winn]` emission here. Its native tunnel service
  // (`windows/runner/windows_tunnel_backend.cpp`,
  // `ValidateRestrictedTunnelConfig`) refuses the served `[winn]` value keys
  // (`static_private`, `gateway_static` and friends are not on the `[winn]`
  // allowlist) and instead runs `InstallWinn3StandaloneTunnel` for a LOCAL
  // `[winn3]` section naming key FILES on that machine. That spelling has no
  // producer anywhere in the dispatch library -- it is what this branch
  // renders -- and it is selected only when the dev config carries at least
  // one [kWinnDevSessionWindowsWinn3NativeKeys] field and the platform is
  // Windows. Every other platform, and a Windows config with none of those
  // fields, keeps the unchanged `[winn]` path below, byte for byte.
  //
  // The descriptor gate is NOT skipped on the native spelling. For a
  // STANDALONE `winn/3` config the dispatch gate refuses without a verified
  // gateway descriptor, and the shipping seam establishes that precondition
  // with the SAME awaited [verifyWinn3Descriptor] call made here -- against
  // the same compiled verification ring. The native branch performs it for
  // real and refuses an unverified descriptor by name exactly as the `[winn]`
  // path does.
  final String winnSection;
  final bool windowsWinn3NativeSpelling =
      winnDevSessionPlatformUsesWindowsWinn3NativeSpelling(
          operatingSystem, config);
  try {
    final descriptorCheck = await verifyWinn3Descriptor(config: config);
    final verifiedDescriptor = descriptorCheck.descriptor;
    log('WINN DEV SESSION: gateway descriptor verification -- '
        'verified=${descriptorCheck.verified} reason=${descriptorCheck.reason}'
        '${verifiedDescriptor == null ? '' : ' kid=${verifiedDescriptor.kid} node=${verifiedDescriptor.node} endpoint=${verifiedDescriptor.endpoint}'}.');
    if (windowsWinn3NativeSpelling) {
      if (!descriptorCheck.verified) {
        throw StateError(
            'Refusing to build a Windows [winn3] section for a config whose '
            'gateway descriptor did not verify '
            '(${descriptorCheck.reason}). The descriptor names the static key '
            'this session authenticates against, and starting without a '
            'verified one would be a silent downgrade.');
      }
      winnSection = winnDevSessionWindowsWinn3NativeSection(config);
      log('WINN DEV SESSION: Windows-native winn/3 session selected; emitting '
          'the LOCAL [winn3] spelling (key paths, never key values).');
    } else {
      winnSection = winnSectionForTunnelConfigDevOnly(
        operatingSystem: operatingSystem,
        config: config,
        winn3Descriptor: descriptorCheck,
        log: log,
      );
    }
  } catch (error) {
    final message = '$error';
    log('WINN DEV SESSION: BLOCKED at winn_section -- $message');
    return WinnDevSessionResult(
      active: true,
      blockedAt: 'winn_section',
      error: message,
      sessionId: sessionId,
    );
  }
  final loggedWinnSection =
      redactWinnDevSessionDocumentForLogging(winnSection);
  log(windowsWinn3NativeSpelling
      ? 'WINN DEV SESSION: [winn3] section built from the Windows local '
          'spelling:\n$loggedWinnSection'
      : 'WINN DEV SESSION: [winn] section produced by the real dispatch '
          'library:\n$loggedWinnSection');

  // --- 4b. the manual-routing pair Windows refuses to start without ---------
  //
  // Checked HERE rather than left to native, because native checks the gateway
  // only in InstallWindowsTunnelRoutes -- after the adapter is up, the engine is
  // running and convergence has been proven. Failing there wastes the whole
  // session and reports it as a routing error rather than as a missing field in
  // the dev config file.
  var manualRoutingGateway = '';
  if (winnDevSessionPlatformNeedsManualRouting(operatingSystem)) {
    final gateway = winnDevSessionManualRoutingGateway(config);
    if (gateway == null) {
      final error =
          'this platform installs its own tunnel routes and refuses a document '
          'without a valid [WinsApp] TunnelGatewayIPv4. The dev config file '
          'needs a "tunnel_gateway_ipv4" field holding the in-tunnel gateway '
          'literal (RFC1918, not a .0 or .255 host) -- typically the .1 of the '
          'client_ip subnet. Found: '
          '"${config['tunnel_gateway_ipv4'] ?? ''}".';
      log('WINN DEV SESSION: BLOCKED at manual_routing_gateway -- $error');
      return WinnDevSessionResult(
        active: true,
        blockedAt: 'manual_routing_gateway',
        error: error,
        sessionId: sessionId,
        winnSection: winnSection,
      );
    }
    manualRoutingGateway = gateway;
    log('WINN DEV SESSION: this platform owns its routes; emitting '
        '[Interface] Table = off and [WinsApp] TunnelGatewayIPv4 = $gateway, '
        'exactly as the shipping writer does on it.');
  }

  // --- 5. the shipping native start -----------------------------------------
  final String document;
  try {
    document = assembleWinnDevSessionTunnelDocument(
      config: config,
      winnSection: winnSection,
      interfacePrivateKey: interfacePrivateKey,
      clientPublicKey: clientPublicKey,
      containmentSupportedByPlatform: effectiveCanContain,
      manualRoutingTunnelGatewayIPv4: manualRoutingGateway,
    );
  } catch (error) {
    final message = '$error';
    log('WINN DEV SESSION: BLOCKED at document_assembly -- $message');
    return WinnDevSessionResult(
      active: true,
      blockedAt: 'document_assembly',
      error: message,
      sessionId: sessionId,
      winnSection: winnSection,
    );
  }
  final documentRedacted = redactWinnDevSessionDocumentForLogging(document);
  log('WINN DEV SESSION: assembled tunnel document (secrets redacted):\n'
      '$documentRedacted');
  if (effectiveCanContain) {
    log('WINN DEV SESSION: this document ASKS for containment — it carries '
        '[$kWinnDevSessionContainmentSection] Enabled = true. '
        '$kWinnDevSessionContainmentRationale Asking is not the same as '
        'getting: this run will read the provider status back and REFUSE to '
        'leave a tunnel up that cannot prove it was contained. Nothing below '
        'claims containment on the strength of this section alone.');
  } else {
    log('WINN DEV SESSION: this document carries NO '
        '[$kWinnDevSessionContainmentSection] section, because this platform\'s '
        'native config allowlist refuses that section and would start no tunnel '
        'at all. Nothing below will claim this session was contained, because '
        'it will not be.');
  }

  bool? nativeStartAccepted;
  final needsGeneration =
      winnDevSessionPlatformNeedsTransitionGeneration(operatingSystem);
  final transitionGeneration = winnDevSessionTransitionGeneration();
  try {
    final raw = await invoke('startTunnel', <String, dynamic>{
      'config': document,
      'accountScope': accountScope,
      // Windows refuses a start with no positive transitionGeneration
      // (WINDOWS_TUNNEL_GENERATION_REQUIRED). Apple's handlers read neither
      // key, so this is added only where the channel actually demands it
      // rather than sent to every platform and hoped to be ignored.
      if (needsGeneration) 'transitionGeneration': transitionGeneration,
    });
    nativeStartAccepted = winnDevSessionStartAccepted(operatingSystem, raw);
    log('WINN DEV SESSION: native startTunnel returned $raw '
        '(accepted=$nativeStartAccepted).');
    if (nativeStartAccepted &&
        !effectiveCanContain &&
        winnDevSessionPlatformNeedsTransitionGeneration(operatingSystem)) {
      log('WINN DEV SESSION: on this platform a non-throwing startTunnel is a '
          'STRONGER signal than on Apple: the Windows handler runs the entire '
          'privileged start synchronously and only reports success after '
          'WaitForAwgConvergence (recent handshake + bidirectional peer '
          'transfer) AND WaitForWinnTransportConvergence '
          '(transport_observed_both_ways) have both passed. A failure at either '
          'gate arrives here as a thrown WINDOWS_TUNNEL_START_FAILED naming '
          'which one.');
    }
  } catch (error) {
    final message = '$error';
    log('WINN DEV SESSION: BLOCKED at native_start -- $message');
    return WinnDevSessionResult(
      active: true,
      blockedAt: 'native_start',
      error: message,
      sessionId: sessionId,
      winnSection: winnSection,
      documentRedacted: documentRedacted,
    );
  }

  // --- 6. read the provider's own account of what happened ------------------
  //
  // WAIT FOR THE APPEX TO PUBLISH, then judge. `startTunnel` returning true
  // means the configuration was saved and a start was requested -- NOT that
  // the Packet Tunnel extension has launched. Until it has, the newest status
  // document is still the one the HOST APP wrote at `config_saved`
  // (`ios/Runner/AppDelegate.swift:2070`), which carries no `dev_containment_*`
  // fields at all because only the appex can write them.
  //
  // Reading once, immediately, therefore judged an empty document and reported
  // `containment_active_absent` for a session whose extension had not yet had a
  // chance to say anything. Observed on a physical iPhone 16 Pro Max
  // (iOS 26.5.2): stage was still `config_saved`, observed containment fields
  // `{}`, and a session that may well have been correctly contained was torn
  // down for failing to prove something it had not yet been asked.
  //
  // This does NOT weaken the gate, and that distinction is the whole point:
  // the verdict is unchanged, only the moment it is taken. If the appex never
  // publishes, `providerStatus` stays at `config_saved`, containment stays
  // unconfirmed, and the tunnel is still stopped. Waiting can only turn a
  // false negative into a true reading; it can never turn an uncontained
  // session into a confirmed one.
  Map<String, dynamic>? providerStatus;
  // On a platform that can contain, the provider status is the only witness
  // for the containment verdict and the full timeout is the cost of listening
  // for it. On a platform that CANNOT contain, stage 7 below returns a fixed
  // `platform_cannot_contain` verdict that never reads this map -- but a
  // session on such a platform has its OWN promotion proof deadline running
  // inside the native start (Android's staged start refuses at 30 s without
  // one delivered inner packet), and the traffic phase that could satisfy it
  // cannot start until this function returns. So the wait is capped short
  // there: enough polls to capture the readiness snapshot for the transcript,
  // not enough to decide an outcome by absence.
  final providerStatusTimeout = effectiveCanContain
      ? kWinnDevSessionProviderStatusTimeout
      : kWinnDevSessionProviderStatusSnapshotWindow;
  final providerStatusDeadline = DateTime.now().add(providerStatusTimeout);
  var providerStatusPolls = 0;
  while (true) {
    providerStatusPolls++;
    try {
      final raw = await invoke('getTunnelReadiness', null);
      if (raw is Map) providerStatus = Map<String, dynamic>.from(raw);
    } catch (error) {
      log('WINN DEV SESSION: provider status unavailable: $error');
    }
    if (winnDevSessionProviderHasPublished(providerStatus)) {
      log('WINN DEV SESSION: the provider published its own status after '
          '$providerStatusPolls readiness poll(s) '
          '(stage=${providerStatus?['provider_stage'] ?? providerStatus?['stage']}).');
      break;
    }
    if (!DateTime.now().isBefore(providerStatusDeadline)) {
      log('WINN DEV SESSION: the provider did NOT publish a status of its own '
          'within ${providerStatusTimeout.inSeconds}s '
          '($providerStatusPolls polls; stage is still '
          '"${providerStatus?['provider_stage'] ?? providerStatus?['stage']}", '
          'which the HOST APP writes, not the extension).'
          '${effectiveCanContain ? ' Containment cannot be confirmed from a document the provider never wrote, so this run proceeds to the refusal below rather than assuming anything.' : ' This platform cannot contain, so no containment verdict was being waited for; the readiness snapshot above is transcript evidence only.'}');
      break;
    }
    await Future<void>.delayed(kWinnDevSessionProviderStatusPollInterval);
  }
  if (providerStatus != null) {
    log('WINN DEV SESSION: provider status: ${jsonEncode(providerStatus)}');
  }

  // --- 7. containment, ESTABLISHED or the tunnel does not stay up ------------
  //
  // The provider is the only witness. If it did not positively say the session
  // was contained — the marker honoured, no default route, no IPv6, no DNS —
  // then whatever is running is not the thing this file promised, and it is
  // running on a device someone depends on. So it gets stopped.
  //
  // This is the LAST line of defence, not the first. The first is
  // `ios/PacketTunnel/PacketTunnelProvider.swift`, which throws rather than
  // installing full-tunnel settings for a config that asked to be contained,
  // in every build shape. This exists because a defence that lives only in the
  // appex cannot be observed by the operator, and one that lives only here
  // cannot prevent the settings being installed in the first place.
  //
  // On a platform that cannot contain, there is no containment promise to
  // check and nothing the provider could say about one. Tearing the tunnel
  // down here would tear down every session that platform can ever run, on
  // the grounds that it failed to prove a property this file already told the
  // operator it does not have. So the verdict is recorded explicitly as
  // "unconfirmed because the platform cannot contain", and the run continues.
  // This branch does not run for macOS or iOS, whose path below is unchanged.
  if (!effectiveCanContain) {
    const uncontainedVerdict = WinnDevSessionContainmentVerdict(
      confirmed: false,
      reasons: <String>['platform_cannot_contain'],
      observedFields: <String, dynamic>{},
    );
    log('WINN DEV SESSION: this session is UNCONTAINED and was never claimed '
        'otherwise. '
        '${winnDevSessionContainmentAbsenceRationale(operatingSystem)} The '
        'evidence a session on this platform produces is the native start\'s '
        'own convergence gate -- a recent AmneziaWG handshake with '
        'bidirectional peer transfer, AND the Winn engine reporting '
        'transport_observed_both_ways -- both of which must pass before the '
        'service promotes any route at all.');
    return WinnDevSessionResult(
      active: true,
      sessionId: sessionId,
      winnSection: winnSection,
      documentRedacted: documentRedacted,
      nativeStartAccepted: nativeStartAccepted,
      providerStatus: providerStatus,
      containmentVerdict: uncontainedVerdict,
      blockedAt: nativeStartAccepted == true ? null : 'native_start',
      error: nativeStartAccepted == true
          ? null
          : 'native startTunnel did not report acceptance.',
    );
  }
  final containmentVerdict = evaluateWinnDevSessionContainment(providerStatus);
  if (!containmentVerdict.confirmed) {
    final message =
        'the provider did not confirm containment (${containmentVerdict.reasons.join(', ')}). '
        'Observed containment fields: ${jsonEncode(containmentVerdict.observedFields)}. '
        'A session that cannot prove it is contained is not allowed to keep '
        'running, so this run asked native to stop the tunnel.';
    log('WINN DEV SESSION: CONTAINMENT NOT ESTABLISHED -- $message');
    var torndown = false;
    if (nativeStartAccepted == true) {
      try {
        await invoke('stopTunnel', winnDevSessionStopArguments(operatingSystem));
        torndown = true;
        log('WINN DEV SESSION: tunnel stop requested. The provider also '
            'releases its network settings explicitly on stop '
            '(releaseTunnelNetworkSettings), so routing, IPv6 and DNS are '
            'handed back rather than left to the extension being reclaimed.');
      } catch (error) {
        log('WINN DEV SESSION: stopTunnel FAILED after an unconfirmed '
            'containment: $error. Stop the VPN from the system settings.');
      }
    }
    return WinnDevSessionResult(
      active: true,
      blockedAt: 'containment_unverified',
      error: message,
      sessionId: sessionId,
      winnSection: winnSection,
      documentRedacted: documentRedacted,
      nativeStartAccepted: nativeStartAccepted,
      providerStatus: providerStatus,
      containmentVerdict: containmentVerdict,
      torndownBecauseUncontained: torndown,
    );
  }
  log('WINN DEV SESSION: containment ESTABLISHED by the provider, not '
      'assumed: ${jsonEncode(containmentVerdict.observedFields)}. This session '
      'is therefore NOT evidence that full-tunnel routing works, and the '
      'leak-protection verdict is correctly failing for it.');

  return WinnDevSessionResult(
    active: true,
    sessionId: sessionId,
    winnSection: winnSection,
    documentRedacted: documentRedacted,
    nativeStartAccepted: nativeStartAccepted,
    providerStatus: providerStatus,
    containmentVerdict: containmentVerdict,
    blockedAt: nativeStartAccepted == true ? null : 'native_start',
    error: nativeStartAccepted == true
        ? null
        : 'native startTunnel did not report acceptance.',
  );
}
