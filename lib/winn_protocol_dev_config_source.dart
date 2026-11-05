/// Winn Protocol v3 -- DEV-ONLY, NON-SHIPPING config SOURCE.
///
/// # What this file is, in one sentence
///
/// A deliberately separate, deliberately loud way for a local DEBUG build to
/// load a hand-written `winn/3` tunnel config from a file on disk -- because
/// the shipping app has no other way to acquire one: every served
/// `vpn_config` comes from Win's VPN's own backend, and there is no manual /
/// custom-server entry point anywhere in `lib/` (confirmed again this session
/// by `grep -rn "addCustomServer\|manual.*entry\|CustomServer\|manualServer"
/// lib/*.dart` -> no matches; the same finding
/// `docs/handoff/WINN_PROTOCOL_MACOS_DEV_OVERRIDE_20260804.md` §1.3 records).
///
/// # What this file is NOT
///
/// It is not a second on-switch. It does not read, write, or special-case
/// [kWinnHostCapabilities] -- macOS and Windows stay exactly as `.absent` as
/// `winn_protocol_dev_override.dart` already leaves them. This file does not
/// even import that table directly; it only reaches it transitively, through
/// [resolveWinnProtocolStartDevOnly], which reads it read-only.
///
/// It is not a validator of its own. Every config this file loads is handed,
/// unmodified, to the SAME gate a server-delivered config goes through:
/// [resolveWinnProtocolStartDevOnly], which calls the real, unmodified
/// [resolveWinnProtocolStart] -- the identical function
/// `winnSectionForTunnelConfig` (called from `_buildRawAmneziaConfig` in
/// `lib/main.dart`) calls. A hand-written config that is missing a field, or
/// wrong in one, is refused exactly as a server-delivered one would be. This
/// file adds no leniency, and no second, looser parser, for anything that
/// function already validates. The one thing this file checks that the real
/// gate does not (see [kWinnDevConfigRequiredFields]) is additive-only and
/// strictly narrower: it can refuse a config the real gate would accept, by
/// naming a field the real gate is silent on but a real tunnel still needs;
/// it can never accept a config the real gate would refuse.
///
/// It is not wired into `lib/main.dart`. Same two reasons
/// `winn_protocol_dev_override.dart` gives, which apply here without change:
/// `test/winn_protocol_refusal_guard_test.dart` pins exactly one
/// `case kWinnProtocolV3:` dispatch point in that file, and the app has
/// nowhere in its UI that would ever call this file's functions even if it
/// were wired in, since there is still no manual-server screen. This module
/// is driven directly -- by a standalone dev script, by `flutter test`
/// against a throwaway file, or by a future debug-only UI trigger someone
/// adds with its own review -- the same way `tools/verify_apple_winn_seam.sh`
/// drives the native stack directly rather than through the app's UI.
///
/// It is not an assembler of a full AmneziaWG `[Interface]`/`[Peer]`
/// document. That text is built by `_buildRawAmneziaConfig` in
/// `lib/main.dart`, which is private to that library (Dart privacy is
/// per-library) and is deliberately not duplicated here -- a second copy of
/// that INI writer, quietly drifting out of sync with the real one, is a
/// worse outcome than not having a convenience function for it. This file
/// stops at the same boundary `winnSectionForTunnelConfig` does: the
/// `[winn]` section, plus the normalized config map a caller needs in order
/// to build the rest itself outside this library (see
/// [WinnDevConfigSourceResult.normalizedConfig]).
///
/// It is not a place a private key can leak through. See "Secret redaction"
/// below.
///
/// # The double gate
///
/// [winnDevConfigSourceActive] is true only when BOTH of these hold:
///
///  1. `kDebugMode` is true -- the same Flutter SDK compile-time constant
///     `winn_protocol_dev_override.dart` relies on: false by construction in
///     every release/profile build, set by the build toolchain itself, not
///     by application code.
///  2. The `WINN_DEV_CONFIG_PATH` dart-define
///     ([kWinnDevConfigPathDartDefineName]) was passed at build/run time with
///     a non-blank value -- the filesystem path to a JSON document. It
///     defaults to `''`. An operator has to type an actual path.
///
/// There is no third way to make either true, and deliberately no parameter
/// on [winnDevConfigSourceActive] or on any function in this file that lets a
/// caller substitute a different value for either input. An earlier lane
/// (`docs/handoff/WINN_PROTOCOL_MACOS_DEV_OVERRIDE_20260804.md` §1.1)
/// considered and rejected exactly this shape of test-injection hook for
/// `winn_protocol_dev_override.dart`, for a reason that applies identically
/// here: a production code path that accepts an externally supplied "pretend
/// the gate is active" value is itself a second way to activate the path,
/// true regardless of whether any caller in this codebase ever passes it.
/// The logic that needs testing without the real gate (file loading,
/// parsing, field checking, redaction) is factored into gate-independent
/// functions ([loadWinnDevConfigFromFile], [missingWinnDevConfigFields],
/// [redactWinnDevConfigForLogging]) that take their inputs as ordinary
/// parameters, and the gate itself is proven with real compiled output the
/// same way `winn_protocol_dev_override.dart`'s is: by actually running
/// `flutter test` with and without the dart-define, not by injection.
///
/// # Composability with `winn_protocol_dev_override.dart`
///
/// These two dev-only files answer two different questions and are gated
/// independently, on purpose:
///
///  - "Where does a `winn/3` config even come from, when there is no UI for
///    it?" -- this file, gated on `WINN_DEV_CONFIG_PATH`.
///  - "May macOS pretend to be a platform [kWinnHostCapabilities] already
///    trusts, for validation purposes?" -- `winn_protocol_dev_override.dart`,
///    gated on `WINN_DEV_UNSAFE_MACOS_OVERRIDE`.
///
/// Setting only `WINN_DEV_CONFIG_PATH` loads and validates a file-sourced
/// config through the REAL, unmodified [resolveWinnProtocolStart] for
/// whatever `operatingSystem` the caller passes in -- on macOS today that
/// still refuses with `unsupported_platform`, honestly, exactly as a
/// server-delivered config would. Only when BOTH dart-defines are set, AND
/// the caller passes `operatingSystem: 'macos'`, does the call additionally
/// borrow a supported donor's decision. Neither define alone, and no
/// combination of them without `kDebugMode`, ever changes what a release
/// build does.
///
/// # Secret redaction
///
/// A hand-written config file plausible enough to ever start a real tunnel
/// has to contain `client_private_key` and, optionally, `preshared_key` --
/// there is no way to negotiate an AmneziaWG session without them. This file
/// never prints either: [redactWinnDevConfigForLogging] walks the loaded
/// document (including nested maps and lists) and replaces the value of any
/// key matching [kWinnDevConfigSecretFieldNames] with `<redacted>` before
/// anything is logged. The raw, unredacted map is still returned to the
/// CALLER in [WinnDevConfigSourceResult.normalizedConfig] -- a caller needs
/// the real private key to ever start a real tunnel -- but this file itself
/// never logs it, never writes it to a second file, and never includes it in
/// any thrown exception's message (every error message this file produces is
/// built only from field NAMES, exception types, and file paths -- never
/// from a field's value). Public keys (`client_public_key`,
/// `server_public_key`) are not secret and are not redacted.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart' show kDebugMode;

import 'winn_protocol_dev_override.dart';
import 'winn_protocol_dispatch.dart';

/// The exact `--dart-define` name an operator must pass, in addition to
/// running a debug build, to activate this module.
const String kWinnDevConfigPathDartDefineName = 'WINN_DEV_CONFIG_PATH';

/// The compiled-in value of that dart-define. Empty unless the build/run
/// command explicitly carried `--dart-define=WINN_DEV_CONFIG_PATH=<path>`.
const String kWinnDevConfigPathDartDefineValue = String.fromEnvironment(
  kWinnDevConfigPathDartDefineName,
  defaultValue: '',
);

/// Pure form of the double gate -- see the library doc. No Flutter dependency,
/// so every combination is directly and exhaustively unit-testable.
bool computeWinnDevConfigSourceActive({
  required bool debugMode,
  required String configPath,
}) {
  return debugMode && configPath.trim().isNotEmpty;
}

/// The real, wired gate. As with `winnDevUnsafeMacosOverrideActive`, this is
/// the only place in this file that reads the real compile-time constants,
/// and there is no parameter here that could substitute a different value
/// for either input.
bool get winnDevConfigSourceActive => computeWinnDevConfigSourceActive(
      debugMode: kDebugMode,
      configPath: kWinnDevConfigPathDartDefineValue,
    );

/// Field names (exact match, case- and whitespace-insensitive -- never a
/// substring match, so `server_public_key` is never caught by `key`) this
/// file will never print the value of. Deliberately broader than the two
/// fields this codebase's normalized config shape actually uses
/// (`client_private_key`, `preshared_key`): a hand-authored dev file is
/// free-form JSON, not the output of `_normalizeVpnConfig`, and the
/// redaction is worthless if it only covers the one spelling the shipping
/// schema happens to use.
const Set<String> kWinnDevConfigSecretFieldNames = <String>{
  'client_private_key',
  'clientprivatekey',
  'private_key',
  'privatekey',
  'preshared_key',
  'presharedkey',
  'psk',
  'token',
  'access_token',
  'accesstoken',
  'auth_token',
  'authtoken',
  'secret',
  'winn3_static_private',
  'winn3staticprivate',
  'winn3_private_key',
  'winn3_psk',
  'winn3psk',
  'winn3_descriptor',
  'winn3descriptor',
  'static_private',
  'staticprivate',
  'admission_key',
  'admissionkey',
  'admission_secret',
  'admissionsecret',
};

/// Printed once, before this module attempts anything else, every time the
/// gate is active -- even if the file it names cannot be read at all. There
/// is deliberately no quiet path once the gate is active: an operator who set
/// `WINN_DEV_CONFIG_PATH` sees this before any outcome, success or failure.
const String kWinnDevConfigSourceBanner = '''
################################################################################
# WINN DEV CONFIG SOURCE ACTIVE -- LOADING AN UNPROVEN, DEVELOPER-SUPPLIED    #
# TUNNEL CONFIG FROM DISK                                                     #
#                                                                              #
# This is NOT a config Win's VPN's backend served. It was read from a local  #
# file because this DEBUG build was launched with                            #
# --dart-define=WINN_DEV_CONFIG_PATH=<path>. It still has to pass the same    #
# winnSectionForTunnelConfig validation and anti-downgrade gates a real       #
# server-delivered config does -- this module does not loosen or skip any    #
# of them -- but passing validation is not the same as having been vetted    #
# by Win's VPN's backend or reviewed for this device's account.              #
#                                                                              #
# Never build a release/profile archive with this dart-define set --         #
# kDebugMode already prevents it from doing anything if you try, but don't   #
# try. Never commit the file this points at.                                 #
################################################################################''';

/// The prefix that makes [kWinnDevConfigPathDartDefineName] mean "a path
/// inside this app's own container" rather than a filesystem path.
///
/// # The gap this closes
///
/// On macOS an operator can point `WINN_DEV_CONFIG_PATH` at
/// `~/Library/Containers/org.winsvpn.app/Data/<name>.json`: the sandbox
/// container is an ordinary directory on the same machine, so they can both
/// know its path and put a file in it.
///
/// On iOS neither half is true. The container is
/// `/private/var/mobile/Containers/Data/Application/<UUID>/`, the UUID is
/// minted at install time and changes on every reinstall, and the path is on
/// the phone, not on the Mac that is typing the `--dart-define`. So there was
/// no absolute path an operator could write down, and no way to place a file
/// where one would point. `WINN_DEV_CONFIG_PATH` was unusable on iOS —
/// mechanically, not by policy.
///
/// With this prefix the operator writes the part they DO know:
///
/// ```
/// --dart-define=WINN_DEV_CONFIG_PATH=container:dev_winn3_ios.json
/// ```
///
/// and the runtime resolves it against the container it is actually running
/// in. Getting the file there is the other half: see
/// `tools/push_ios_winn_dev_config.sh`, which copies a local JSON into
/// `Documents/` of the development-signed app's data container with
/// `xcrun devicectl`.
///
/// This changes nothing for a plain path. Anything not starting with this
/// prefix is used exactly as before, on every platform.
const String kWinnDevConfigContainerScheme = 'container:';

/// The container-relative directory a `container:` path resolves inside.
///
/// `Documents/` on purpose: it is the one directory that exists in a freshly
/// installed iOS data container (so a push can land before the app has ever
/// run), and it is the directory `xcrun devicectl device copy to
/// --domain-type appDataContainer` addresses most simply.
const String kWinnDevConfigContainerSubdirectory = 'Documents';

/// The outcome of resolving a possibly-`container:` config path.
class WinnDevConfigPathResolution {
  const WinnDevConfigPathResolution._({
    required this.usedContainerScheme,
    this.path,
    this.error,
    this.containerRoot,
  });

  const WinnDevConfigPathResolution.plain(String path)
      : this._(usedContainerScheme: false, path: path);

  const WinnDevConfigPathResolution.resolved({
    required String path,
    required String containerRoot,
  }) : this._(
          usedContainerScheme: true,
          path: path,
          containerRoot: containerRoot,
        );

  const WinnDevConfigPathResolution.failed(String error)
      : this._(usedContainerScheme: true, error: error);

  /// Whether the configured value carried [kWinnDevConfigContainerScheme].
  final bool usedContainerScheme;

  /// The absolute path to read, or `null` if resolution failed.
  final String? path;

  /// Why resolution failed, or `null`. Built only from the configured value and
  /// the reason -- never from file contents.
  final String? error;

  /// The container root the relative path was resolved against, when one was
  /// used. Logged so an operator can see WHERE the runtime looked.
  final String? containerRoot;

  bool get resolved => path != null;
}

/// This process's own app-container root, or `null` if it cannot be
/// determined.
///
/// On iOS the app's `HOME` environment variable IS the data container root --
/// the process is sandboxed into it -- so no plugin, no new dependency and no
/// platform channel is needed to find it, and it is available before any
/// channel is up. `Directory.systemTemp` (`<container>/tmp`) is the fallback,
/// because both point into the same container and either one is enough.
///
/// [environment] and [systemTempPath] are parameters for the unit test only.
/// They gate nothing: substituting them cannot open a path that
/// [winnDevConfigSourceActive] has closed, it can only change which directory
/// a file is looked for in.
String? winnDevConfigContainerRoot({
  Map<String, String>? environment,
  String? systemTempPath,
}) {
  final env = environment ?? Platform.environment;
  final home = (env['HOME'] ?? '').trim();
  if (home.isNotEmpty) return home;
  final temp = (systemTempPath ?? Directory.systemTemp.path).trim();
  if (temp.isEmpty) return null;
  final parent = File(temp).parent.path;
  return parent.isEmpty ? null : parent;
}

/// Turns a configured `WINN_DEV_CONFIG_PATH` value into a path to actually
/// read. Pure and gate-independent, so every branch is unit-testable.
///
/// Refuses a relative part that escapes the container (`..`, or an absolute
/// path after the prefix). Not because an operator is an attacker, but because
/// a dev knob that can be pointed at arbitrary filesystem locations by a
/// slightly wrong string is a knob that will eventually read something it
/// should not, and the refusal costs nothing.
WinnDevConfigPathResolution resolveWinnDevConfigPath(
  String configuredPath, {
  String? containerRoot,
}) {
  final trimmed = configuredPath.trim();
  if (!trimmed.startsWith(kWinnDevConfigContainerScheme)) {
    return WinnDevConfigPathResolution.plain(trimmed);
  }
  final relative =
      trimmed.substring(kWinnDevConfigContainerScheme.length).trim();
  if (relative.isEmpty) {
    return const WinnDevConfigPathResolution.failed(
      'WINN_DEV_CONFIG_PATH used the "container:" prefix but named no file '
      'after it. Expected e.g. "container:dev_winn3_ios.json".',
    );
  }
  if (relative.startsWith('/')) {
    return WinnDevConfigPathResolution.failed(
      'WINN_DEV_CONFIG_PATH "container:$relative" is absolute after the '
      '"container:" prefix. A container path is relative to the app container; '
      'drop the leading "/" or drop the prefix to use an absolute path.',
    );
  }
  final segments = relative.split('/');
  if (segments.contains('..')) {
    return WinnDevConfigPathResolution.failed(
      'WINN_DEV_CONFIG_PATH "container:$relative" contains a ".." segment. A '
      'container path may not escape the app container.',
    );
  }
  final root = containerRoot ?? winnDevConfigContainerRoot();
  if (root == null || root.trim().isEmpty) {
    return const WinnDevConfigPathResolution.failed(
      'WINN_DEV_CONFIG_PATH used the "container:" prefix, but this process\'s '
      'app-container root could not be determined (no HOME, no usable system '
      'temp directory). Use an absolute path instead.',
    );
  }
  final normalizedRoot =
      root.endsWith('/') ? root.substring(0, root.length - 1) : root;
  return WinnDevConfigPathResolution.resolved(
    path: '$normalizedRoot/$kWinnDevConfigContainerSubdirectory/$relative',
    containerRoot: normalizedRoot,
  );
}

/// Names (never contents) of the JSON files sitting next to where a
/// `container:` path pointed, so a failed load can say "the push did not land"
/// instead of only "no such file".
///
/// Filenames only, `*.json` only, sorted, capped. A dev config file's NAME is
/// not a secret; its contents are, and this never opens one.
List<String> winnDevConfigSiblingJsonFileNames(String resolvedPath) {
  try {
    final directory = File(resolvedPath).parent;
    if (!directory.existsSync()) return const <String>[];
    final names = directory
        .listSync(followLinks: false)
        .whereType<File>()
        .map((file) => file.uri.pathSegments.last)
        .where((name) => name.toLowerCase().endsWith('.json'))
        .toList()
      ..sort();
    return names.length > 20 ? names.sublist(0, 20) : names;
  } on FileSystemException {
    return const <String>[];
  }
}

/// The outcome of trying to read and JSON-decode a config file.
class WinnDevConfigFileLoad {
  const WinnDevConfigFileLoad._({this.config, this.error});

  const WinnDevConfigFileLoad.ok(Map<String, dynamic> config)
      : this._(config: config, error: null);

  const WinnDevConfigFileLoad.failed(String error)
      : this._(config: null, error: error);

  /// The decoded document, or `null` if loading failed.
  final Map<String, dynamic>? config;

  /// Why loading failed, or `null` on success. Deliberately built only from
  /// the exception's own type/message and the requested path -- never from
  /// file contents, so a JSON syntax error can never echo a fragment of a
  /// config that might contain key material back into a log.
  final String? error;

  bool get loaded => config != null;
}

/// Reads [path] and decodes it as a JSON object. The only function in this
/// file that touches `dart:io` or `dart:convert`, so every other function
/// here stays trivially unit-testable with in-memory maps.
///
/// Deliberately permissive about what counts as "a config" at this layer --
/// it only checks "is this readable JSON, and is it an object" -- because
/// refusing an individually wrong FIELD is [resolveWinnProtocolStartDevOnly]'s
/// job, not this function's. Two parsers disagreeing about what is valid
/// would be exactly the kind of second, looser gate the library doc promises
/// this file does not add.
WinnDevConfigFileLoad loadWinnDevConfigFromFile(String path) {
  final trimmedPath = path.trim();
  if (trimmedPath.isEmpty) {
    return const WinnDevConfigFileLoad.failed(
        'WINN_DEV_CONFIG_PATH was blank.');
  }
  final file = File(trimmedPath);
  final String raw;
  try {
    raw = file.readAsStringSync();
  } on FileSystemException catch (error) {
    // error.message/osError describe the FAILURE (e.g. "No such file or
    // directory"), never the file's contents.
    return WinnDevConfigFileLoad.failed(
        'could not read "$trimmedPath": ${error.message}.');
  }
  final Object? decoded;
  try {
    decoded = jsonDecode(raw);
  } on FormatException catch (error) {
    // FormatException.message from dart:convert describes the parse failure
    // (position, expected token); it does not include the source string.
    return WinnDevConfigFileLoad.failed(
        'could not parse "$trimmedPath" as JSON: ${error.message}.');
  }
  if (decoded is! Map) {
    return WinnDevConfigFileLoad.failed(
        '"$trimmedPath" must contain a JSON object at the top level, found '
        '${decoded.runtimeType}.');
  }
  return WinnDevConfigFileLoad.ok(Map<String, dynamic>.from(decoded));
}

/// Fields [resolveWinnProtocolStart] itself is silent on, but a real
/// AmneziaWG tunnel cannot start without: the client's own address and key
/// pair, and the gateway's public key. Checked here, before this file hands
/// anything to that validation, so a config missing (say) `client_private_key`
/// is refused with a message naming the field, rather than silently producing
/// a technically-valid `[winn]` section that nothing could ever actually
/// start a tunnel with.
///
/// Deliberately narrower than `_normalizeVpnConfig`'s accepted aliases in
/// `lib/main.dart` (`clientip`, `clientprivatekey`, ...): that function is
/// private to that library and is not duplicated here (see the library doc).
/// A file this loader accepts must use the same canonical, non-aliased keys
/// `_normalizeVpnConfig` itself produces as output. `server_endpoint` and
/// `mtu` are deliberately NOT in this set even though a real tunnel needs
/// them too: [resolveWinnProtocolStart] already validates both itself (the
/// former with a `gateway_endpoint` fallback this set would not know about,
/// the latter with `WinnRefusalReason.mtuOutOfRange`) and this set must never
/// be stricter than that real gate about anything the real gate already
/// covers.
const Set<String> kWinnDevConfigRequiredFields = <String>{
  'client_ip',
  'client_private_key',
  'client_public_key',
  'server_public_key',
};

/// Field-presence check independent of the winn/3-specific validation
/// [resolveWinnProtocolStart] performs -- see [kWinnDevConfigRequiredFields].
/// Returns the sorted list of missing/blank fields, empty if none are
/// missing.
List<String> missingWinnDevConfigFields(Map<String, dynamic> config) {
  final missing = kWinnDevConfigRequiredFields
      .where((key) =>
          (config[key]?.toString().trim() ?? '').isEmpty)
      .toList()
    ..sort();
  return missing;
}

/// Returns a deep copy of [config] with the value of every key in
/// [kWinnDevConfigSecretFieldNames] replaced by `<redacted>`, matched
/// case-insensitively against the exact key name (never a substring match).
/// Descends into nested maps and lists (e.g. a hand-authored
/// `protocol_params` block) because nothing stops an operator from placing a
/// secret-shaped field there too, and this function's only job is to make
/// logging safe -- not to describe or enforce the config schema.
Map<String, dynamic> redactWinnDevConfigForLogging(
    Map<String, dynamic> config) {
  return _redactMap(config);
}

Map<String, dynamic> _redactMap(Map<String, dynamic> input) {
  final out = <String, dynamic>{};
  for (final entry in input.entries) {
    final normalizedKey = entry.key.trim().toLowerCase();
    final value = entry.value;
    if (kWinnDevConfigSecretFieldNames.contains(normalizedKey) &&
        (value?.toString().isNotEmpty ?? false)) {
      out[entry.key] = '<redacted>';
    } else {
      out[entry.key] = _redactValue(value);
    }
  }
  return out;
}

Object? _redactValue(Object? value) {
  if (value is Map) {
    return _redactMap(Map<String, dynamic>.from(value));
  }
  if (value is List) {
    return value.map(_redactValue).toList();
  }
  return value;
}

/// Everything [resolveWinnDevConfigSourceStart] found out, in one place.
class WinnDevConfigSourceResult {
  const WinnDevConfigSourceResult({
    required this.active,
    this.loadError,
    this.normalizedConfig,
    this.overrideResult,
  });

  /// Whether the double gate was active for this call. False for every
  /// release build, every profile build, and every debug build launched
  /// without `WINN_DEV_CONFIG_PATH` set -- and when false, this is the ONLY
  /// populated field: no file was touched, nothing was logged.
  final bool active;

  /// Why no validation decision exists, or `null` if one does (see
  /// [overrideResult]) or if this call was inactive. Covers: the file could
  /// not be read or parsed, it was missing a required field (see
  /// [kWinnDevConfigRequiredFields]), or its `protocol_version` was not
  /// `winn/3` (this file's whole purpose). Never derived from file contents.
  final String? loadError;

  /// The loaded config, unredacted, exactly as read from disk (only the JSON
  /// object wrapper is unwrapped) -- present whenever loading and the
  /// required-field check both succeeded, regardless of what
  /// `protocol_version` turned out to be or what [overrideResult] later says.
  /// A caller that needs to build a full `[Interface]`/`[Peer]` document
  /// (this file does not) reads the tunnel keys from here, never from any
  /// logged output.
  final Map<String, dynamic>? normalizedConfig;

  /// The result of handing [normalizedConfig] to
  /// [resolveWinnProtocolStartDevOnly] -- present only when
  /// `protocol_version` normalized to `winn/3`.
  /// `overrideResult.decision.supported` is the authoritative "did this
  /// config pass" answer; `false`, for any [WinnRefusalReason], is a
  /// correct, complete result -- not a partial one, and not this file's
  /// failure.
  final WinnDevOverrideResult? overrideResult;
}

/// Business-logic evaluation of an ALREADY-LOADED config: the required-field
/// check (see [kWinnDevConfigRequiredFields]), `protocol_version` tiering,
/// and -- for a `winn/3` config -- the call into
/// [resolveWinnProtocolStartDevOnly].
///
/// Deliberately gate-independent: it does not read [winnDevConfigSourceActive]
/// and has no idea whether [config] came from a real file, so it is testable
/// in full by a normal `flutter test` run, the same way
/// `winnDevOverrideBorrowedDecision` in `winn_protocol_dev_override.dart` is.
/// [resolveWinnDevConfigSourceStart] is the only function in this file that
/// decides WHETHER to call this one -- this function itself has no gate to
/// bypass, so exposing it publicly does not create a second way to activate
/// anything: reaching it still requires a caller to have already produced a
/// config `Map`, and this file provides exactly one non-test way to do that
/// ([loadWinnDevConfigFromFile]), which the real double gate still guards.
WinnDevConfigSourceResult evaluateWinnDevConfigSourceConfig({
  required Map<String, dynamic> config,
  required String operatingSystem,
  WinnDevOverrideLogger log = _defaultWinnDevConfigSourceLogger,
}) {
  final missingFields = missingWinnDevConfigFields(config);
  if (missingFields.isNotEmpty) {
    final error =
        'config is missing required field(s): ${missingFields.join(', ')}.';
    log('WINN DEV CONFIG SOURCE: refused -- $error');
    return WinnDevConfigSourceResult(
      active: true,
      normalizedConfig: config,
      loadError: error,
    );
  }

  log('WINN DEV CONFIG SOURCE: loaded config (secrets redacted): '
      '${jsonEncode(redactWinnDevConfigForLogging(config))}');

  final protocolVersion =
      normalizedWinnProtocolVersion(config['protocol_version']);
  if (protocolVersion != kWinnProtocolV3) {
    // Mirrors the shipping dispatch seam's own tiering in
    // `_startTunnelCandidate`: only a winn/3 config is this file's business.
    // winn/1 needs no [winn] section at all -- that is not a refusal, it is
    // the shipping default -- so it is reported as out of scope rather than
    // as a failure.
    final error = protocolVersion == kWinnProtocolV1
        ? 'protocol_version is "$kWinnProtocolV1" (classical AmneziaWG); '
            'this file only has something to prove for '
            '"$kWinnProtocolV3" configs.'
        : 'unknown protocol_version "$protocolVersion".';
    log('WINN DEV CONFIG SOURCE: not evaluated -- $error');
    return WinnDevConfigSourceResult(
      active: true,
      normalizedConfig: config,
      loadError: error,
    );
  }

  final overrideResult = resolveWinnProtocolStartDevOnly(
    operatingSystem: operatingSystem,
    config: config,
    log: log,
  );
  log('WINN DEV CONFIG SOURCE: validation result -- '
      'supported=${overrideResult.decision.supported} '
      'reason=${overrideResult.decision.reason.code}.');

  return WinnDevConfigSourceResult(
    active: true,
    normalizedConfig: config,
    overrideResult: overrideResult,
  );
}

/// The single entry point this file exposes for "load a hand-written
/// `winn/3` config and see what the real gate says about it."
///
/// Does nothing -- reads no file, logs nothing -- unless
/// [winnDevConfigSourceActive] is true. When it is: logs
/// [kWinnDevConfigSourceBanner], loads [kWinnDevConfigPathDartDefineValue],
/// and hands the result to [evaluateWinnDevConfigSourceConfig].
///
/// [operatingSystem] has no default and is never read from `Platform.
/// operatingSystem` inside this library, matching [resolveWinnProtocolStart]
/// and [resolveWinnProtocolStartDevOnly]'s own shape: the real platform is a
/// property of the CALL SITE (`lib/main.dart`, or here, a standalone dev
/// script), never of the library.
WinnDevConfigSourceResult resolveWinnDevConfigSourceStart({
  required String operatingSystem,
  WinnDevOverrideLogger log = _defaultWinnDevConfigSourceLogger,
}) {
  if (!winnDevConfigSourceActive) {
    return const WinnDevConfigSourceResult(active: false);
  }

  log(kWinnDevConfigSourceBanner);
  log('WINN DEV CONFIG SOURCE: loading "$kWinnDevConfigPathDartDefineValue".');

  // Resolve a `container:` path against the app container this process is
  // actually running in -- the only way the define is usable on iOS at all.
  final resolution = resolveWinnDevConfigPath(kWinnDevConfigPathDartDefineValue);
  if (!resolution.resolved) {
    log('WINN DEV CONFIG SOURCE: refused -- ${resolution.error}');
    return WinnDevConfigSourceResult(active: true, loadError: resolution.error);
  }
  if (resolution.usedContainerScheme) {
    log('WINN DEV CONFIG SOURCE: "$kWinnDevConfigPathDartDefineValue" resolved '
        'against this app container (${resolution.containerRoot}) to '
        '"${resolution.path}".');
  }

  final loaded = loadWinnDevConfigFromFile(resolution.path!);
  if (!loaded.loaded) {
    var error = loaded.error!;
    if (resolution.usedContainerScheme) {
      final siblings = winnDevConfigSiblingJsonFileNames(resolution.path!);
      error = '$error Container root: ${resolution.containerRoot}. '
          'JSON files present in that directory: '
          '${siblings.isEmpty ? '(none)' : siblings.join(', ')}. '
          'Push one with tools/push_ios_winn_dev_config.sh.';
    }
    log('WINN DEV CONFIG SOURCE: refused -- $error');
    return WinnDevConfigSourceResult(active: true, loadError: error);
  }

  return evaluateWinnDevConfigSourceConfig(
    config: loaded.config!,
    operatingSystem: operatingSystem,
    log: log,
  );
}

/// Throwing convenience wrapper, mirroring
/// [winnSectionForTunnelConfigDevOnly]'s throw-rather-than-default contract:
/// returns the `[winn]` INI section on success, throws [StateError] for
/// every failure mode (gate inactive, file missing, malformed JSON, missing
/// field, non-winn/3 protocol version, or a real validation refusal) rather
/// than ever returning `''` to mean "something went wrong upstream" -- an
/// empty string is exactly what `VpnTunnelService` reads as "start plain
/// AmneziaWG."
String winnDevConfigSourceIniSection({
  required String operatingSystem,
  WinnDevOverrideLogger log = _defaultWinnDevConfigSourceLogger,
}) {
  final result = resolveWinnDevConfigSourceStart(
    operatingSystem: operatingSystem,
    log: log,
  );
  if (!result.active) {
    throw StateError(
        'Winn dev config source is not active (WINN_DEV_CONFIG_PATH is not '
        'set, or this is not a debug build); there is no config to load.');
  }
  if (result.loadError != null) {
    throw StateError('Winn dev config source: ${result.loadError}');
  }
  final decision = result.overrideResult!.decision;
  if (!decision.supported) {
    throw StateError(
        'Winn dev config source: config was refused '
        '(${decision.reason.code}). ${decision.message}');
  }
  return decision.iniSection;
}

// ignore: avoid_print
void _defaultWinnDevConfigSourceLogger(String message) => print(message);
