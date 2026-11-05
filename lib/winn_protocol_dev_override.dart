/// Winn Protocol v3 -- DEV-ONLY, NON-SHIPPING macOS start override.
///
/// # What this file is, in one sentence
///
/// A deliberately separate, deliberately loud escape hatch that lets a local
/// DEBUG build attempt a `winn/3` start on macOS -- so a real session can
/// actually be run and its evidence captured -- without claiming, anywhere,
/// that macOS has earned that claim for real.
///
/// # What this file is NOT
///
/// It is not, and must never become, a second way to turn macOS "on".
/// [kWinnHostCapabilities] in `winn_protocol_dispatch.dart` is untouched by
/// this file -- not read differently, not written to, not special-cased. It
/// still says `macos: WinnHostCapability.absent(...)`, and it is still
/// correct: no real `winn/3` session has been proven end-to-end on macOS
/// through this file alone. That governance decision belongs to the owner,
/// per `WINN_PROTOCOL_PLATFORM_PLAN.md` rule 4, and this file does not make
/// it, imply it has been made, or make it easier to forget it has not been.
///
/// This file is also not wired into `lib/main.dart`. Two independent reasons:
///
///  1. Rule 2 forbids flipping the `winn/3` refusal at `lib/main.dart`, and
///     `test/winn_protocol_refusal_guard_test.dart` enforces, among other
///     things, that there is EXACTLY ONE `case kWinnProtocolV3:` dispatch
///     point in the whole client -- "guards against a second, more
///     permissive switch/if-chain being added elsewhere in this file that
///     special-cases winn/3 outside this seam." Wiring this override into
///     `_startTunnelCandidate` or `_buildRawAmneziaConfig` would be exactly
///     that second path, in spirit even if not in the guard's literal text.
///  2. The shipping app has no manual/custom-server entry point -- every
///     served `vpn_config` comes from Win's VPN's own backend, which is out
///     of scope for a local dev change. Even a perfectly-wired override could
///     not be reached from the real UI without a backend-served `winn/3`
///     config, so wiring it into `lib/main.dart` would add risk to an
///     8000+ line, actively-edited, release-frozen file for no reachable
///     benefit.
///
/// Instead, this module is meant to be driven directly -- by a standalone
/// dev script/tool, or by a future debug-only trigger a lane adds with its
/// own scrutiny -- the same way `tools/verify_apple_winn_seam.sh` drives the
/// real native Swift/ObjC/Go stack directly rather than through the app's UI.
///
/// # The double gate
///
/// [winnDevUnsafeMacosOverrideActive] is true only when BOTH of these hold,
/// and there is no third way to make it true:
///
///  1. `kDebugMode` (from `package:flutter/foundation.dart`) is true. This is
///     not an app-level flag -- it is a Flutter SDK compile-time constant
///     derived from `dart.vm.product`/`dart.vm.profile`, which the build
///     toolchain itself sets. `flutter build ... --release` and
///     `--profile` always compile with one of those defined, which makes
///     `kDebugMode` false BY CONSTRUCTION. No source in this app, including
///     this file, can make `kDebugMode` true inside a release or profile
///     archive.
///  2. The `WINN_DEV_UNSAFE_MACOS_OVERRIDE` dart-define
///     ([kWinnDevUnsafeMacosOverrideDartDefineName]) was passed at build/run
///     time. It defaults to `false`. An operator has to type it.
///
/// Both are required, deliberately: a debug build alone (e.g. anyone running
/// `flutter run -d macos` for ordinary development) must NOT get this path,
/// and the dart-define alone must not either -- a release build has no way to
/// honour a dart-define into a true `kDebugMode`, but the AND is enforced in
/// code too, not left to that alone. See `test/winn_protocol_dev_override_test.dart`
/// for the exhaustive truth table and
/// `docs/handoff/WINN_PROTOCOL_MACOS_DEV_OVERRIDE_20260804.md` for a real,
/// executed demonstration that the dart-define actually flips the compiled
/// gate (run once, output quoted, not just reasoned about).
///
/// # Runtime loudness
///
/// Every time this module actually overrides a refusal, it logs
/// [kWinnDevUnsafeMacosOverrideBanner] through the supplied [WinnDevOverrideLogger]
/// (stdout by default) before returning a start decision. There is
/// deliberately no quiet path through the override -- see
/// [resolveWinnProtocolStartDevOnly].
library;

import 'package:flutter/foundation.dart' show kDebugMode;

import 'winn_protocol_dispatch.dart';

/// The exact `--dart-define` name an operator must pass, in addition to
/// running a debug build, to activate the override. Kept as a named constant
/// so a test can assert on the literal string rather than retype it.
const String kWinnDevUnsafeMacosOverrideDartDefineName =
    'WINN_DEV_UNSAFE_MACOS_OVERRIDE';

/// The compiled-in value of that dart-define. `false` unless the build/run
/// command explicitly carried
/// `--dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true`.
const bool kWinnDevUnsafeMacosOverrideDartDefineValue = bool.fromEnvironment(
  kWinnDevUnsafeMacosOverrideDartDefineName,
  defaultValue: false,
);

/// Pure form of the double gate: no Flutter dependency, no global state, so
/// every combination is directly and exhaustively unit-testable without
/// needing to fake `kDebugMode` or recompile with different dart-defines.
///
/// `debugMode == false` returns `false` regardless of [dartDefineEnabled] --
/// this is the property that makes "the dart-define alone is insufficient
/// without debug mode" true, and by the `kDebugMode` invariant documented on
/// this library, it is also what makes a release build's answer always
/// `false`: a release build can never supply `debugMode: true` here, because
/// its `kDebugMode` is `false` by construction of the Flutter SDK, not by
/// anything this function does.
bool computeWinnDevUnsafeMacosOverrideActive({
  required bool debugMode,
  required bool dartDefineEnabled,
}) {
  return debugMode && dartDefineEnabled;
}

/// The exact `--dart-define` name an operator must pass, in addition to
/// running a debug build, to activate the override FOR iOS.
///
/// Deliberately a SEPARATE define from the macOS one, not a shared
/// `WINN_DEV_UNSAFE_OVERRIDE=macos,ios`. Two reasons, both about blast radius:
///
///  1. An operator who has been running macOS dev sessions for days has that
///     dart-define in their shell history and their muscle memory. If the same
///     define also opened iOS, the first time they ran the dev target against a
///     phone they would open a path they never typed. A phone is not a laptop:
///     it is the device a user in Myanmar depends on, and it is the one the
///     owner can least afford to have wedged.
///  2. Per-platform defines make the truth table small enough to state
///     completely: macOS open and iOS shut is a state that exists, is tested,
///     and is the default for every build that only asked for macOS.
const String kWinnDevUnsafeIosOverrideDartDefineName =
    'WINN_DEV_UNSAFE_IOS_OVERRIDE';

/// The compiled-in value of that dart-define. `false` unless the build/run
/// command explicitly carried
/// `--dart-define=WINN_DEV_UNSAFE_IOS_OVERRIDE=true`.
const bool kWinnDevUnsafeIosOverrideDartDefineValue = bool.fromEnvironment(
  kWinnDevUnsafeIosOverrideDartDefineName,
  defaultValue: false,
);

/// The real, wired gate. This is the ONLY place in this file that reads the
/// actual `kDebugMode` constant and the actual compiled dart-define value,
/// and there is deliberately no parameter on this getter and no mutable
/// global anywhere in this file that could substitute a different value for
/// either input -- an injectable "pretend this is active" hook would itself
/// be a second way to enable the override, which is exactly what requirement
/// 1 (impossible in a release build) forbids. Tests that need to exercise the
/// "override is active" branch of [resolveWinnProtocolStartDevOnly] do so by
/// actually compiling and running with
/// `--dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true` (see the live
/// demonstration referenced on the library doc), not by injection.
bool get winnDevUnsafeMacosOverrideActive =>
    computeWinnDevUnsafeMacosOverrideActive(
      debugMode: kDebugMode,
      dartDefineEnabled: kWinnDevUnsafeMacosOverrideDartDefineValue,
    );

/// The iOS half of the same gate, reusing the identical pure computation so
/// there is exactly one definition of "debug AND the define" in this file.
bool get winnDevUnsafeIosOverrideActive =>
    computeWinnDevUnsafeMacosOverrideActive(
      debugMode: kDebugMode,
      dartDefineEnabled: kWinnDevUnsafeIosOverrideDartDefineValue,
    );

/// The one platform this override ever touches. Deliberately not "any absent
/// platform" -- this task is about breaking the macOS deadlock specifically,
/// and a broader "unsafe-bypass-everything" tool is a different, scarier
/// thing that nobody asked for here.
const String kWinnDevUnsafeMacosOverrideTargetPlatform = 'macos';

/// The second, separately gated platform this override can touch.
///
/// # Why iOS was added, and why only after the provider was made safe
///
/// Until 2026-08-06 this file was macOS-only, and
/// `test/winn_protocol_dev_override_test.dart` pinned iOS by name as
/// "left completely alone". That pin was correct at the time and was a
/// deliberate safety decision, not an oversight: with iOS in the list, a
/// `winn/3` document could have reached the iOS Packet Tunnel provider — and
/// that provider contained NO containment code at all. It read
/// `[WinsDevContainment]` as an unknown section and started a full tunnel:
/// default IPv4 route, IPv6 to a sink, every DNS query captured, on a phone,
/// while the app reported the session as contained. Opening this gate first
/// would have shipped that.
///
/// The order was therefore: make the provider honour containment (and FAIL
/// CLOSED when it cannot), make it release its network settings on stop, and
/// only then open the path that lets a document reach it. All three landed
/// together; this constant is the third.
///
/// What still holds, unchanged:
///
///  * `kWinnHostCapabilities['ios']` is still `WinnHostCapability.absent(...)`.
///    This file does not read it differently, write to it, or special-case it.
///    No `winn/3` session has been proven end-to-end on iOS, and this change
///    does not produce one — a contained session cannot, by construction.
///  * The double gate still applies, per platform: `kDebugMode` AND that
///    platform's own dart-define. A release or profile build cannot honour
///    either.
///  * Every other platform — android, windows, and anything unrecognised — is
///    still passed through untouched, which the same test still pins.
const String kWinnDevUnsafeIosOverrideTargetPlatform = 'ios';

/// Every platform this override can touch, each still gated on its OWN
/// dart-define. Membership here is necessary but nowhere near sufficient: see
/// [winnDevUnsafeOverrideActiveFor].
const Set<String> kWinnDevUnsafeOverrideTargetPlatforms = <String>{
  kWinnDevUnsafeMacosOverrideTargetPlatform,
  kWinnDevUnsafeIosOverrideTargetPlatform,
};

/// The dart-define name that gates each target platform, so a log line or a
/// test can name the exact define an operator has to type.
const Map<String, String> kWinnDevUnsafeOverrideDartDefineNames =
    <String, String>{
  kWinnDevUnsafeMacosOverrideTargetPlatform:
      kWinnDevUnsafeMacosOverrideDartDefineName,
  kWinnDevUnsafeIosOverrideTargetPlatform:
      kWinnDevUnsafeIosOverrideDartDefineName,
};

/// Is the override active for this exact platform?
///
/// Returns false for every platform not in
/// [kWinnDevUnsafeOverrideTargetPlatforms], and for a target platform whose own
/// dart-define was not passed. There is deliberately no parameter that can
/// substitute a value for either input, for the reason
/// [winnDevUnsafeMacosOverrideActive] documents.
bool winnDevUnsafeOverrideActiveFor(String operatingSystem) {
  switch (operatingSystem.trim().toLowerCase()) {
    case kWinnDevUnsafeMacosOverrideTargetPlatform:
      return winnDevUnsafeMacosOverrideActive;
    case kWinnDevUnsafeIosOverrideTargetPlatform:
      return winnDevUnsafeIosOverrideActive;
    default:
      return false;
  }
}

/// Printed (via the caller's [WinnDevOverrideLogger]) every single time this
/// module actually overrides a refusal. Deliberately impossible to miss:
/// wide, repeated marker characters, and it names exactly what is unproven.
const String kWinnDevUnsafeMacosOverrideBanner = '''
################################################################################
# WINN DEV OVERRIDE ACTIVE -- THIS IS AN UNPROVEN WINN PATH                   #
#                                                                              #
# kWinnHostCapabilities['macos'] is still WinnHostCapability.absent(...).     #
# No real winn/3 session has ever been carried end-to-end on macOS. This      #
# process is attempting one anyway because it is a DEBUG build AND it was     #
# launched with --dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true.            #
#                                                                              #
# This path is NOT shipping-safe, NOT reviewed, and NOT a substitute for the  #
# owner's capability decision on kWinnHostCapabilities. Its only purpose is   #
# to let that decision be backed by a real session instead of staying        #
# circular. Never build a release/profile archive with this dart-define set  #
# -- kDebugMode already prevents it from doing anything if you try, but      #
# don't try.                                                                  #
################################################################################''';

/// The iOS counterpart, printed every time this module overrides an iOS
/// refusal. Names what iOS specifically has and has not earned, and what the
/// provider will and will not do with the document that follows.
const String kWinnDevUnsafeIosOverrideBanner = '''
################################################################################
# WINN DEV OVERRIDE ACTIVE (iOS) -- THIS IS AN UNPROVEN WINN PATH ON A PHONE   #
#                                                                              #
# kWinnHostCapabilities['ios'] is still WinnHostCapability.absent(...).        #
# No real winn/3 session has ever been carried end-to-end on iOS. This        #
# process is attempting one anyway because it is a DEBUG build AND it was     #
# launched with --dart-define=WINN_DEV_UNSAFE_IOS_OVERRIDE=true.              #
#                                                                              #
# THE SESSION THIS OPENS IS CONTAINED, OR IT DOES NOT RUN. The iOS Packet     #
# Tunnel provider throws rather than installing full-tunnel settings for a    #
# config that asked to be contained -- in EVERY build shape, including a      #
# release appex that cannot contain at all. There is no build of that file    #
# in which the containment marker is silently ignored.                        #
#                                                                              #
# A contained run proves the handshake, never the routing. It is therefore    #
# not, and cannot become, the evidence for flipping the iOS capability --     #
# that stays the owner's decision, per WINN_PROTOCOL_PLATFORM_PLAN.md rule 4. #
#                                                                              #
# DEVELOPMENT SIGNING ONLY. Never build a release/profile archive with this   #
# dart-define -- kDebugMode already prevents it from doing anything, but      #
# don't try.                                                                  #
################################################################################''';

/// The banner for a given target platform, or `null` for a platform this
/// override never touches.
String? winnDevUnsafeOverrideBannerFor(String operatingSystem) {
  switch (operatingSystem.trim().toLowerCase()) {
    case kWinnDevUnsafeMacosOverrideTargetPlatform:
      return kWinnDevUnsafeMacosOverrideBanner;
    case kWinnDevUnsafeIosOverrideTargetPlatform:
      return kWinnDevUnsafeIosOverrideBanner;
    default:
      return null;
  }
}

/// A logging sink. Defaults to stdout via `print`; tests and callers that
/// want to capture or silence the banner may supply their own.
typedef WinnDevOverrideLogger = void Function(String message);

// ignore: avoid_print
void _defaultWinnDevOverrideLogger(String message) => print(message);

/// The platforms [kWinnHostCapabilities] itself calls supported right now,
/// sorted for a deterministic choice. Computed live, on every call, against
/// the real table -- never cached, never hard-coded to `'linux'` -- so that
/// if the table's supported set ever changes (in either direction) this
/// reflects it immediately, and so that if it were ever EMPTY this reports
/// that honestly (`null`) instead of silently doing nothing useful.
List<String> winnDevOverrideSupportedDonorPlatforms() {
  final names = kWinnHostCapabilities.entries
      .where((entry) => entry.value.supported)
      .map((entry) => entry.key)
      .toList()
    ..sort();
  return names;
}

/// The single donor platform [winnDevOverrideBorrowedDecision] uses, or
/// `null` if [kWinnHostCapabilities] currently has no supported entry at all.
String? winnDevOverrideDonorPlatform() {
  final supported = winnDevOverrideSupportedDonorPlatforms();
  return supported.isEmpty ? null : supported.first;
}

/// Pure, gate-independent: "what would a platform [kWinnHostCapabilities]
/// already calls supported decide for this exact [config]?"
///
/// # Why borrowing another platform's decision is honest, not a trick
///
/// [resolveWinnProtocolStart] takes `operatingSystem` for exactly one
/// purpose: the platform-support check at its very top
/// (`platformSupportsWinnProtocol`). Every line after that -- the stealth
/// conflict check, the `protocol_params` allowlist, the endpoint/mtu/datagram/
/// session-id/header-type/padding/carrier validation, and the `[winn]`
/// section it builds -- depends only on [config]. That is a property of the
/// real, unmodified, 341-plus-test-covered function today, not an assumption;
/// [`test/winn_protocol_dev_override_test.dart`] pins it with a parity
/// assertion so a future change that makes the validation genuinely
/// OS-dependent would fail loudly here rather than silently mis-borrowing.
///
/// So the honest way to ask "what would this config get on a host the table
/// already trusts" is to call the real function with a real supported
/// platform's key -- reusing the exact tested logic -- rather than
/// duplicating roughly 200 lines of validation in this file where it could
/// quietly drift from the real gate.
///
/// Returns `null` if [kWinnHostCapabilities] currently has no supported
/// platform to borrow from (see [winnDevOverrideDonorPlatform]).
WinnStartDecision? winnDevOverrideBorrowedDecision(Map<String, dynamic> config) {
  final donor = winnDevOverrideDonorPlatform();
  if (donor == null) return null;
  return resolveWinnProtocolStart(operatingSystem: donor, config: config);
}

/// The outcome of asking [resolveWinnProtocolStartDevOnly] to decide a
/// `winn/3` start, including whether it actually exercised the override.
class WinnDevOverrideResult {
  const WinnDevOverrideResult({
    required this.decision,
    required this.overrodeCapabilityGate,
    this.donorPlatform,
  });

  /// The decision to act on. Identical in shape to what
  /// [resolveWinnProtocolStart] returns -- callers that only care about the
  /// outcome, not how it was reached, can treat this exactly like that
  /// function's return value.
  final WinnStartDecision decision;

  /// True only when this result came from the override actually replacing an
  /// `unsupported_platform` refusal for macOS. False for every other
  /// platform, every other refusal reason, and every call made while
  /// [winnDevUnsafeMacosOverrideActive] is false -- which, in any build that
  /// is not both debug AND launched with the dart-define, is always.
  final bool overrodeCapabilityGate;

  /// Which [kWinnHostCapabilities] entry the decision was borrowed from, or
  /// `null` when [overrodeCapabilityGate] is false.
  final String? donorPlatform;
}

/// DEV-ONLY mirror of [resolveWinnProtocolStart].
///
/// For every platform, every config, and every build where
/// [winnDevUnsafeMacosOverrideActive] is false (which includes every release
/// build, every profile build, and every debug build that was not launched
/// with `--dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true`), this returns
/// EXACTLY what [resolveWinnProtocolStart] returns -- byte-for-byte the same
/// [WinnStartDecision] -- with [WinnDevOverrideResult.overrodeCapabilityGate]
/// false. `test/winn_protocol_dev_override_test.dart` pins this passthrough
/// property directly, which is what the default `flutter test` run (no
/// special dart-define) actually exercises.
///
/// The one case this changes: [operatingSystem] normalizes to `"macos"`, the
/// real decision is a refusal for [WinnRefusalReason.unsupportedPlatform],
/// AND [winnDevUnsafeMacosOverrideActive] is true. Then it logs
/// [kWinnDevUnsafeMacosOverrideBanner] through [log] and returns
/// [winnDevOverrideBorrowedDecision]'s result instead, with
/// `overrodeCapabilityGate: true`.
///
/// This function never reads, writes, or otherwise special-cases
/// [kWinnHostCapabilities] beyond the read [resolveWinnProtocolStart] and
/// [winnDevOverrideBorrowedDecision] already do on their own -- the table
/// itself has no idea this file exists.
WinnDevOverrideResult resolveWinnProtocolStartDevOnly({
  required String operatingSystem,
  required Map<String, dynamic> config,
  Winn3DescriptorCheck? winn3Descriptor,
  WinnDevOverrideLogger log = _defaultWinnDevOverrideLogger,
}) {
  final real = resolveWinnProtocolStart(
    operatingSystem: operatingSystem,
    config: config,
    winn3Descriptor: winn3Descriptor,
  );

  final normalizedOs = operatingSystem.trim().toLowerCase();
  final isTargetPlatform =
      kWinnDevUnsafeOverrideTargetPlatforms.contains(normalizedOs);
  final isUnsupportedPlatformRefusal = !real.supported &&
      real.reason == WinnRefusalReason.unsupportedPlatform;

  if (!isTargetPlatform || !isUnsupportedPlatformRefusal) {
    // Either this decision did not fail on the platform gate (some other
    // refusal, or an already-supported platform), or it is a platform this
    // override deliberately never touches. Either way: the real decision,
    // unmodified, and nothing logged -- there is nothing unproven happening
    // here to announce.
    return WinnDevOverrideResult(decision: real, overrodeCapabilityGate: false);
  }

  // PER-PLATFORM, not global. `winnDevUnsafeOverrideActiveFor` reads only that
  // one platform's dart-define, so a build that opened macOS has NOT opened
  // iOS, and vice versa.
  if (!winnDevUnsafeOverrideActiveFor(normalizedOs)) {
    return WinnDevOverrideResult(decision: real, overrodeCapabilityGate: false);
  }

  final donor = winnDevOverrideDonorPlatform();
  if (donor == null) {
    log('WINN DEV OVERRIDE: active, but kWinnHostCapabilities currently has '
        'no .supported platform to borrow a decision from. Refusing rather '
        'than guessing -- this is not the banner case, nothing was '
        'overridden.');
    return WinnDevOverrideResult(decision: real, overrodeCapabilityGate: false);
  }

  final borrowed = resolveWinnProtocolStart(
    operatingSystem: donor,
    config: config,
    winn3Descriptor: winn3Descriptor,
  );
  log(winnDevUnsafeOverrideBannerFor(normalizedOs)!);
  log('WINN DEV OVERRIDE: $normalizedOs start requested; kWinnHostCapabilities '
      '["$normalizedOs"] is still .absent. Borrowed the platform-independent '
      'validation result from "$donor" '
      '(kWinnHostCapabilities["$donor"].supported == true) for this exact '
      'config. Borrowed decision: supported=${borrowed.supported} '
      'reason=${borrowed.reason.code}.');
  return WinnDevOverrideResult(
    decision: borrowed,
    overrodeCapabilityGate: true,
    donorPlatform: donor,
  );
}

/// DEV-ONLY mirror of [winnSectionForTunnelConfig], routed through
/// [resolveWinnProtocolStartDevOnly] instead of [resolveWinnProtocolStart].
///
/// [winn3Descriptor] is the verified-descriptor precondition the shipping seam
/// establishes with [verifyWinn3Descriptor] before building a standalone
/// section. It is OPTIONAL with the historical default of `null`, which the
/// dispatch library reads as [WinnRefusalReason.winn3DescriptorUnverified]:
/// every caller that predates this parameter keeps its exact behaviour, and a
/// caller that WANTS a standalone `winn/3` section must have actually verified
/// the gateway descriptor first -- this dev path never invents a bypass for
/// that check, it only lets the real, awaited verification result reach the
/// same gate the shipping path threads it into.
///
/// Same throw-rather-than-default-to-empty contract as the shipping
/// function, for the same reason: an empty `[winn]` section is exactly what
/// `VpnTunnelService` reads as "start plain AmneziaWG," so silently
/// defaulting to it here would be the same silent downgrade the shipping gate
/// exists to prevent -- the override changes WHICH decision macOS can reach,
/// never what an unstartable decision means once reached.
String winnSectionForTunnelConfigDevOnly({
  required String operatingSystem,
  required Map<String, dynamic> config,
  Winn3DescriptorCheck? winn3Descriptor,
  WinnDevOverrideLogger log = _defaultWinnDevOverrideLogger,
}) {
  final protocolVersion =
      normalizedWinnProtocolVersion(config['protocol_version']);
  if (protocolVersion == kWinnProtocolV1) return '';
  if (protocolVersion != kWinnProtocolV3) {
    throw StateError(
        'Refusing to build a tunnel configuration for unknown '
        'protocol_version "$protocolVersion".');
  }
  final result = resolveWinnProtocolStartDevOnly(
    operatingSystem: operatingSystem,
    config: config,
    winn3Descriptor: winn3Descriptor,
    log: log,
  );
  if (!result.decision.supported) {
    throw StateError(
        'Refusing to build an AmneziaWG tunnel configuration for a '
        '$kWinnProtocolV3 config that cannot start the Winn path '
        '(${result.decision.reason.code}). Starting the classical AmneziaWG '
        'path here would silently downgrade a Winn Protocol v3 negotiation.');
  }
  return result.decision.iniSection;
}
