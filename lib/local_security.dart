import 'dart:convert';
import 'dart:isolate';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart' show kReleaseMode;

import 'camouflage_policy.dart';

class PinCredentialCodec {
  PinCredentialCodec({this.iterations = 120000});

  static const String format = 'pbkdf2-sha256-v1';
  final int iterations;

  /// Candidate lengths the decoy keypad may present. [kCamouflagePinLength]
  /// is what this build enrolls; [kLegacyCamouflagePinLength] is what earlier
  /// builds enrolled and must keep unlocking (refusing it would lock out
  /// every install that already has a PIN, including devices in the field).
  static final RegExp _acceptableCandidate =
      RegExp('^\\d{$kLegacyCamouflagePinLength}\$|^\\d{$kCamouflagePinLength}\$');

  Future<String> encode(String pin, {List<int>? salt}) async {
    _validatePin(pin);
    final resolvedSalt = salt ?? _secureRandomBytes(16);
    if (resolvedSalt.length < 16) {
      throw const FormatException('PIN salt must contain at least 16 bytes');
    }
    final hash = await _derive(pin, resolvedSalt, iterations);
    return jsonEncode({
      'format': format,
      // Recorded so the keypad can present exactly one candidate per attempt
      // instead of trying both lengths and spending two throttle failures on
      // one wrong entry. Absent on credentials written before the 6-digit
      // change, which is why the reader defaults to the legacy length.
      'digits': pin.length,
      'iterations': iterations,
      'salt': base64Encode(resolvedSalt),
      'hash': base64Encode(hash),
    });
  }

  Future<bool> verify(String pin, String encoded) async {
    if (!_acceptableCandidate.hasMatch(pin)) return false;
    try {
      final decoded = jsonDecode(encoded);
      if (decoded is! Map || decoded['format'] != format) return false;
      final savedIterations = int.tryParse('${decoded['iterations']}') ?? 0;
      if (savedIterations < 10000 || savedIterations > 1000000) return false;
      final savedDigits = int.tryParse('${decoded['digits']}') ??
          kLegacyCamouflagePinLength;
      if (pin.length != savedDigits) return false;
      final salt = base64Decode('${decoded['salt']}');
      final expected = base64Decode('${decoded['hash']}');
      if (salt.length < 16 || expected.length != 32) return false;
      final actual = await _derive(pin, salt, savedIterations);
      return _constantTimeEquals(actual, expected);
    } catch (_) {
      return false;
    }
  }

  Future<bool> verifyStoredCredential(String pin, String stored) async {
    final normalized = stored.trim();
    if (isLegacyPlaintextCredential(normalized)) {
      return _constantTimeEquals(utf8.encode(pin), utf8.encode(normalized));
    }
    return verify(pin, normalized);
  }

  /// Envelope tag for the offline recovery code. Deliberately distinct from
  /// [format]: [verify] rejects any envelope whose tag is not its own, so a
  /// recovery credential can never be presented to the PIN path or the other
  /// way round, whatever ends up in storage.
  static const String recoveryFormat = 'pbkdf2-sha256-recovery-v1';

  static final RegExp _recoveryCandidate =
      RegExp('^\\d{$kRecoveryCodeLength}\$');

  /// A fresh recovery code: [kRecoveryCodeLength] digits from
  /// [Random.secure]. Never `Random()` - a predictable recovery code is a
  /// backdoor, not a backup.
  static String generateRecoveryCode() {
    final random = Random.secure();
    final buffer = StringBuffer();
    for (var index = 0; index < kRecoveryCodeLength; index++) {
      buffer.write(random.nextInt(10));
    }
    return buffer.toString();
  }

  /// Groups a recovery code for transcription, e.g. 1234 5678 9012 3456.
  /// Display only - never stored, never fed back to [verifyRecoveryCode],
  /// which takes bare digits.
  static String formatRecoveryCodeForDisplay(String code) {
    final digits = code.replaceAll(RegExp(r'\D'), '');
    final groups = <String>[];
    for (var start = 0; start < digits.length; start += 4) {
      groups.add(digits.substring(start, min(start + 4, digits.length)));
    }
    return groups.join(' ');
  }

  Future<String> encodeRecoveryCode(String code, {List<int>? salt}) async {
    if (!_recoveryCandidate.hasMatch(code)) {
      throw const FormatException(
          'Recovery code must contain exactly $kRecoveryCodeLength digits');
    }
    final resolvedSalt = salt ?? _secureRandomBytes(16);
    if (resolvedSalt.length < 16) {
      throw const FormatException(
          'Recovery salt must contain at least 16 bytes');
    }
    final hash = await _derive(code, resolvedSalt, iterations);
    return jsonEncode({
      'format': recoveryFormat,
      'digits': code.length,
      'iterations': iterations,
      'salt': base64Encode(resolvedSalt),
      'hash': base64Encode(hash),
    });
  }

  Future<bool> verifyRecoveryCode(String code, String stored) async {
    if (!_recoveryCandidate.hasMatch(code)) return false;
    try {
      final decoded = jsonDecode(stored.trim());
      if (decoded is! Map || decoded['format'] != recoveryFormat) return false;
      final savedIterations = int.tryParse('${decoded['iterations']}') ?? 0;
      if (savedIterations < 10000 || savedIterations > 1000000) return false;
      final savedDigits = int.tryParse('${decoded['digits']}') ?? 0;
      if (code.length != savedDigits) return false;
      final salt = base64Decode('${decoded['salt']}');
      final expected = base64Decode('${decoded['hash']}');
      if (salt.length < 16 || expected.length != 32) return false;
      final actual = await _derive(code, salt, savedIterations);
      return _constantTimeEquals(actual, expected);
    } catch (_) {
      return false;
    }
  }

  /// [verifyRecoveryCode] on a background isolate, for the same reason as
  /// [verifyStoredCredentialOffThread], and so the PIN and recovery
  /// derivations can be run concurrently rather than back to back.
  Future<bool> verifyRecoveryCodeOffThread(String code, String stored) async {
    final configuredIterations = iterations;
    try {
      return await Isolate.run(
        () => PinCredentialCodec(iterations: configuredIterations)
            .verifyRecoveryCode(code, stored),
      );
    } catch (_) {
      return verifyRecoveryCode(code, stored);
    }
  }

  /// [verifyStoredCredential] on a background isolate.
  ///
  /// One derivation costs ~380ms at the production iteration count, measured
  /// on a development Mac. Spent on the UI isolate that is a visible freeze
  /// on the sixth keypress of what is supposed to be an ordinary
  /// calculator - the disguise leaks through the frame rate. Moving it off
  /// keeps the decoy responsive while the wall-clock cost of an attempt is
  /// unchanged, which is what the indistinguishability argument relies on.
  ///
  /// Falls back to on-thread verification if the isolate cannot be spawned.
  /// That fallback is not optional: a platform where `Isolate.run` fails
  /// would otherwise make every unlock throw, which behind the decoy is an
  /// unrecoverable lockout with no visible symptom.
  Future<bool> verifyStoredCredentialOffThread(String pin, String stored) async {
    final configuredIterations = iterations;
    try {
      return await Isolate.run(
        () => PinCredentialCodec(iterations: configuredIterations)
            .verifyStoredCredential(pin, stored),
      );
    } catch (_) {
      return verifyStoredCredential(pin, stored);
    }
  }

  Future<String> encodeOffThread(String pin, {List<int>? salt}) async {
    final configuredIterations = iterations;
    final suppliedSalt = salt == null ? null : List<int>.of(salt);
    try {
      return await Isolate.run(
        () => PinCredentialCodec(iterations: configuredIterations)
            .encode(pin, salt: suppliedSalt),
      );
    } catch (_) {
      return encode(pin, salt: suppliedSalt);
    }
  }

  Future<String> encodeRecoveryCodeOffThread(
    String code, {
    List<int>? salt,
  }) async {
    final configuredIterations = iterations;
    final suppliedSalt = salt == null ? null : List<int>.of(salt);
    try {
      return await Isolate.run(
        () => PinCredentialCodec(iterations: configuredIterations)
            .encodeRecoveryCode(code, salt: suppliedSalt),
      );
    } catch (_) {
      return encodeRecoveryCode(code, salt: suppliedSalt);
    }
  }

  bool isLegacyPlaintextCredential(String stored) {
    return RegExp('^\\d{$kLegacyCamouflagePinLength}\$').hasMatch(stored.trim());
  }

  /// How many digits the stored credential expects. Credentials written
  /// before the 6-digit change carry no `digits` field and are read as
  /// [kLegacyCamouflagePinLength], which is what keeps existing installs
  /// unlockable rather than silently bricked.
  static int storedPinLength(String stored) {
    final normalized = stored.trim();
    try {
      final decoded = jsonDecode(normalized);
      if (decoded is Map) {
        final digits = int.tryParse('${decoded['digits']}');
        if (digits == kCamouflagePinLength) return kCamouflagePinLength;
      }
    } catch (_) {
      // Legacy plaintext or unparseable: fall through to the legacy length.
    }
    return kLegacyCamouflagePinLength;
  }

  Future<List<int>> _derive(
    String pin,
    List<int> salt,
    int derivationIterations,
  ) async {
    final algorithm = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: derivationIterations,
      bits: 256,
    );
    final key = await algorithm.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );
    return key.extractBytes();
  }

  static List<int> _secureRandomBytes(int length) {
    final random = Random.secure();
    return List<int>.generate(length, (_) => random.nextInt(256));
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var difference = 0;
    for (var i = 0; i < a.length; i++) {
      difference |= a[i] ^ b[i];
    }
    return difference == 0;
  }

  static void _validatePin(String pin) {
    if (!RegExp('^\\d{$kCamouflagePinLength}\$').hasMatch(pin)) {
      throw const FormatException(
          'PIN must contain exactly $kCamouflagePinLength digits');
    }
    if (isTriviallyGuessablePin(pin)) {
      throw const FormatException(weakPinRejectionMessage);
    }
  }
}

/// Shown when a chosen code is refused at setup.
///
/// Deliberately says nothing about VPNs, tunnels, censorship, or what the
/// code protects: this string can surface on a device that is being watched,
/// and it must read as ordinary app-lock wording. It also never names the
/// stored value, only the rule that was broken.
const String weakPinRejectionMessage =
    'That code is too easy to guess. Avoid repeated digits (like 000000), '
    'counting sequences (like 123456), and repeating patterns (like 121212). '
    'Please choose a different $kCamouflagePinLength-digit code.';

/// Well-known codes that survive the structural rules below but appear at the
/// top of every published analysis of leaked PIN corpora, plus the
/// straight-line patterns people trace on a phone keypad (2-5-8-0 down the
/// middle column, 1-3-7-9 across the corners). Kept short and explicit
/// rather than sprawling: a denylist that refuses too much just pushes users
/// toward writing the code down.
const Set<String> _wellKnownWeakPins = <String>{
  // 4-digit, from published frequency analyses of breached PIN sets.
  '1004', '2000', '2001', '2580', '0852', '1379', '9731', '6969', '1990',
  // 6-digit equivalents.
  '159753', '357159', '147258', '852741', '258369', '963852', '102030',
  '696969', '123321', '654321', '112233', '121314',
};

/// True when [pin] is one of the codes an attacker with a handful of guesses
/// would try first. Applied at setup only - a code already enrolled on a
/// device keeps working, because refusing it at unlock time would lock the
/// user out with no way back in, which is the defect this lane exists to fix.
///
/// Refused:
///   * every digit identical (0000, 111111)
///   * any constant step between adjacent digits, wrapping at 9-0 - this
///     covers counting up and down (1234, 9876, 654321) and skip-counting
///     (2468, 1357, 147258, 0369)
///   * a two- or three-digit block repeated to fill the code (1212, 121212,
///     123123)
///   * equal-length runs of one digit (1122, 112233, 111222)
///   * the explicit [_wellKnownWeakPins] list
bool isTriviallyGuessablePin(String pin) {
  final normalized = pin.trim();
  if (!RegExp(r'^\d+$').hasMatch(normalized)) return false;
  final length = normalized.length;
  if (length < 2) return true;

  if (_wellKnownWeakPins.contains(normalized)) return true;

  final digits =
      normalized.split('').map((digit) => int.parse(digit)).toList(growable: false);

  // All identical, and every constant-step run (ascending, descending, and
  // skip-counting), evaluated modulo 10 so 7890 and 3210 are caught too.
  final step = (digits[1] - digits[0]) % 10;
  var constantStep = true;
  for (var index = 1; index < length; index++) {
    if ((digits[index] - digits[index - 1]) % 10 != step) {
      constantStep = false;
      break;
    }
  }
  if (constantStep) return true;

  // A short block repeated to fill the code: 1212, 121212, 123123.
  for (final blockSize in <int>[2, 3]) {
    if (length <= blockSize || length % blockSize != 0) continue;
    var repeated = true;
    for (var index = blockSize; index < length; index++) {
      if (digits[index] != digits[index - blockSize]) {
        repeated = false;
        break;
      }
    }
    if (repeated) return true;
  }

  // Equal-length runs of a single digit: 1122, 112233, 111222.
  for (final runLength in <int>[2, 3]) {
    if (length % runLength != 0) continue;
    var uniformRuns = true;
    for (var start = 0; start < length; start += runLength) {
      for (var offset = 1; offset < runLength; offset++) {
        if (digits[start + offset] != digits[start]) {
          uniformRuns = false;
          break;
        }
      }
      if (!uniformRuns) break;
    }
    if (uniformRuns) return true;
  }

  return false;
}

/// Null when [pin] may be enrolled; otherwise the message to show the user.
/// Length is checked before content so a half-typed code does not get told
/// it is weak.
String? pinPolicyRejectionReason(String pin) {
  final normalized = pin.trim();
  if (!RegExp('^\\d{$kCamouflagePinLength}\$').hasMatch(normalized)) {
    return 'Please choose a $kCamouflagePinLength-digit code.';
  }
  if (isTriviallyGuessablePin(normalized)) return weakPinRejectionMessage;
  return null;
}

/// Null when [duressPin] may be enrolled as the distinct duress code that
/// sits beside [realPin]; otherwise the message to show the user.
///
/// RETIRED (owner decision 2026-08-18): the duress unlock path is disabled
/// in main.dart. This policy function remains only so the PIN
/// validation/upgrade rules stay internally consistent; a duress code is a
/// SECOND, separately chosen PIN. Typed at the
/// decoy keypad it silently triggers the emergency response instead of
/// unlocking, so under coercion it has to be typed exactly like the real code
/// and look no different. Three rules make that safe:
///
///   * It must pass the same structural + strength policy as any PIN
///     ([pinPolicyRejectionReason]), so a weak duress code is not a soft spot.
///   * It must be enrolled at [kCamouflagePinLength]; a legacy 4-digit main
///     code has to be upgraded to six first (the codec refuses to enroll at
///     the legacy length anyway), which is what keeps the two codes the same
///     length and lets them only ever move between lengths together.
///   * It must be DIFFERENT from the real code. If the two were equal there
///     would be no code that unlocks without signalling, and the user would
///     fire the duress response every single time they opened the app.
///
/// Like [weakPinRejectionMessage], every message here is deliberately generic
/// app-lock wording: it can surface on a watched device and must never name a
/// VPN, a panic feature, or what the code protects.
String? duressPinPolicyRejectionReason(String realPin, String duressPin) {
  final normalizedReal = realPin.trim();
  final normalizedDuress = duressPin.trim();
  // Enrollment always happens at the current length. A legacy 4-digit main
  // code cannot have a duress code created beside it until it is upgraded.
  if (normalizedReal.length != kCamouflagePinLength) {
    return 'Please change your main code to a $kCamouflagePinLength-digit code '
        'before adding a second code.';
  }
  final own = pinPolicyRejectionReason(normalizedDuress);
  if (own != null) return own;
  if (_constantTimeStringEquals(normalizedDuress, normalizedReal)) {
    return 'Choose a second code that is different from your main code.';
  }
  return null;
}

/// Length-independent, content constant-time string comparison used only to
/// reject a duress code equal to the real code without leaking, through timing,
/// how many leading digits two locally-known setup values share.
bool _constantTimeStringEquals(String a, String b) => constantTimePinEquals(a, b);

/// Tracks consecutive failed camouflage-PIN attempts, an absolute UTC
/// lockout deadline (kept for display/diagnostics), and an absolute
/// monotonic-clock lockout deadline. Persisted via the app's existing
/// secure-state mechanism (never plaintext prefs).
///
/// M-15: [lockedUntilUtc] alone is not sufficient enforcement - a local user
/// who can advance the device's wall-clock date/time can make it appear
/// expired early. [lockedUntilMonotonicMs] is compared against a
/// device-local monotonic clock (e.g. Android's
/// `SystemClock.elapsedRealtime()` or Apple's `ProcessInfo.systemUptime`)
/// that counts real elapsed time since boot and cannot be advanced by
/// changing the wall-clock date/time, so callers should treat the two as
/// combined via [isLockedGivenClocks]: locked if *either* clock says so.
/// The monotonic clock can only ever move backwards on an actual device
/// reboot (see [isMonotonicRollback]/[rearmAfterMonotonicRollback]) - never
/// as a way for a local user to shorten or clear an active lockout.
class PinAttemptState {
  const PinAttemptState({
    this.failureCount = 0,
    this.lockedUntilUtc,
    this.lockedUntilMonotonicMs,
    this.lastSeenMonotonicMs,
  });

  const PinAttemptState.clear()
      : failureCount = 0,
        lockedUntilUtc = null,
        lockedUntilMonotonicMs = null,
        lastSeenMonotonicMs = null;

  final int failureCount;
  final DateTime? lockedUntilUtc;

  /// Absolute monotonic-clock lockout deadline, in the same millisecond
  /// units as the native monotonic reading. Null when no native monotonic
  /// reading was available the last time this state was written (e.g. the
  /// native handler is not yet implemented on this platform), in which case
  /// enforcement falls back to [lockedUntilUtc] alone.
  final int? lockedUntilMonotonicMs;

  /// The most recent monotonic-clock reading observed while this state was
  /// current. Used only to detect a reboot / monotonic-domain reset (the
  /// only way a monotonic clock reading can ever move backwards) so a
  /// stale pre-reboot deadline is never left in force unmodified.
  final int? lastSeenMonotonicMs;

  static const int lockoutThreshold = 5;
  static const int baseDelaySeconds = 5;
  static const int maxDelaySeconds = 300;

  bool isLockedAt(DateTime nowUtc) {
    final deadline = lockedUntilUtc;
    return deadline != null && nowUtc.isBefore(deadline);
  }

  /// Monotonic-clock lockout check: a locally-advanced wall clock cannot
  /// move [nowMonotonicMs] forward, so when a monotonic deadline was
  /// recorded this is the authoritative check.
  bool isLockedAtMonotonic(int nowMonotonicMs) {
    final deadline = lockedUntilMonotonicMs;
    return deadline != null && nowMonotonicMs < deadline;
  }

  /// Combines both clocks: locked if *either* indicates an active lockout.
  /// This is the check callers should use. It fails closed against a
  /// forward wall-clock jump (the monotonic deadline, unaffected by wall
  /// clock changes, still reports locked) while still enforcing
  /// [lockedUntilUtc] alone for states written before a monotonic reading
  /// was ever available (no [lockedUntilMonotonicMs] recorded, so only the
  /// UTC half applies).
  bool isLockedGivenClocks({required DateTime nowUtc, int? nowMonotonicMs}) {
    if (isLockedAt(nowUtc)) return true;
    return nowMonotonicMs != null && isLockedAtMonotonic(nowMonotonicMs);
  }

  /// True only when there is an active monotonic-tracked lockout
  /// ([lockedUntilMonotonicMs] set) and [nowMonotonicMs] is behind the last
  /// observed reading - the only way that can happen is the monotonic
  /// clock's own epoch resetting (a device reboot), since real elapsed time
  /// can never run backwards otherwise.
  bool isMonotonicRollback(int nowMonotonicMs) {
    final lastSeen = lastSeenMonotonicMs;
    return lockedUntilMonotonicMs != null &&
        lastSeen != null &&
        nowMonotonicMs < lastSeen;
  }

  /// Re-arms a fresh, bounded delay anchored to the new monotonic epoch
  /// after [isMonotonicRollback] detects a reboot. The pre-reboot
  /// [lockedUntilMonotonicMs] value is no longer meaningful once the
  /// monotonic clock has reset to a new epoch (comparing it to the new
  /// readings could otherwise mean anything from an accidental
  /// near-permanent lockout to an accidental early release), so this
  /// deliberately never simply clears the penalty: it imposes a fresh
  /// [maxDelaySeconds] delay from [nowMonotonicMs] instead, preserving the
  /// existing [failureCount] and [lockedUntilUtc].
  PinAttemptState rearmAfterMonotonicRollback(int nowMonotonicMs) {
    return PinAttemptState(
      failureCount: failureCount,
      lockedUntilUtc: lockedUntilUtc,
      lockedUntilMonotonicMs: nowMonotonicMs + maxDelaySeconds * 1000,
      lastSeenMonotonicMs: nowMonotonicMs,
    );
  }

  /// Records one more failed attempt. Below [lockoutThreshold] this only
  /// increments the counter; at/after it, it imposes a lockout deadline
  /// that doubles with every additional failure, capped at
  /// [maxDelaySeconds]. When [nowMonotonicMs] is supplied (a native
  /// monotonic reading was available), a matching monotonic deadline is
  /// recorded alongside the UTC one so a later wall-clock jump alone
  /// cannot lift the lockout.
  PinAttemptState nextFailure({DateTime? nowUtc, int? nowMonotonicMs}) {
    final failures = failureCount + 1;
    if (failures < lockoutThreshold) {
      return PinAttemptState(
        failureCount: failures,
        lastSeenMonotonicMs: nowMonotonicMs,
      );
    }
    final exponent = (failures - lockoutThreshold).clamp(0, 16);
    final delaySeconds =
        min(maxDelaySeconds, baseDelaySeconds * (1 << exponent));
    final now = (nowUtc ?? DateTime.now().toUtc()).toUtc();
    return PinAttemptState(
      failureCount: failures,
      lockedUntilUtc: now.add(Duration(seconds: delaySeconds)),
      lockedUntilMonotonicMs: nowMonotonicMs == null
          ? null
          : nowMonotonicMs + delaySeconds * 1000,
      lastSeenMonotonicMs: nowMonotonicMs,
    );
  }

  Map<String, dynamic> toJson() => {
        'failure_count': failureCount,
        if (lockedUntilUtc != null)
          'locked_until': lockedUntilUtc!.toIso8601String(),
        if (lockedUntilMonotonicMs != null)
          'locked_until_monotonic_ms': lockedUntilMonotonicMs,
        if (lastSeenMonotonicMs != null)
          'last_seen_monotonic_ms': lastSeenMonotonicMs,
      };

  static PinAttemptState fromJson(dynamic json) {
    if (json is! Map) return const PinAttemptState();
    final failures = int.tryParse('${json['failure_count'] ?? 0}') ?? 0;
    final rawLockedUntil = (json['locked_until'] ?? '').toString();
    final lockedUntil =
        rawLockedUntil.isEmpty ? null : DateTime.tryParse(rawLockedUntil);
    final rawLockedUntilMonotonic =
        (json['locked_until_monotonic_ms'] ?? '').toString();
    final rawLastSeenMonotonic =
        (json['last_seen_monotonic_ms'] ?? '').toString();
    return PinAttemptState(
      failureCount: failures < 0 ? 0 : failures,
      lockedUntilUtc: lockedUntil?.toUtc(),
      lockedUntilMonotonicMs: int.tryParse(rawLockedUntilMonotonic),
      lastSeenMonotonicMs: int.tryParse(rawLastSeenMonotonic),
    );
  }

  @override
  bool operator ==(Object other) =>
      other is PinAttemptState &&
      other.failureCount == failureCount &&
      other.lockedUntilUtc == lockedUntilUtc &&
      other.lockedUntilMonotonicMs == lockedUntilMonotonicMs &&
      other.lastSeenMonotonicMs == lastSeenMonotonicMs;

  @override
  int get hashCode => Object.hash(
        failureCount,
        lockedUntilUtc,
        lockedUntilMonotonicMs,
        lastSeenMonotonicMs,
      );

  @override
  String toString() => 'PinAttemptState(failureCount: $failureCount, '
      'lockedUntilUtc: $lockedUntilUtc, '
      'lockedUntilMonotonicMs: $lockedUntilMonotonicMs, '
      'lastSeenMonotonicMs: $lastSeenMonotonicMs)';
}

/// Thrown when the stored PIN credential turns out to be a legacy
/// plaintext value. The caller deletes the legacy credential before
/// throwing this - it signals that the user must re-enroll (set a new PIN
/// through re-activation) rather than that the candidate PIN was wrong.
class PinReenrollmentRequired implements Exception {
  const PinReenrollmentRequired([
    this.message =
        'The stored PIN used an unsupported legacy format and was removed '
            'for security. Please re-activate this device to set a new PIN.',
  ]);

  final String message;

  @override
  String toString() => 'PinReenrollmentRequired: $message';
}

/// Centralized guard for every external link this app launches for
/// payment/legal/referral/attribution/web-fallback purposes. Rejects
/// anything other than a credential-free https:// URL with a real host, so
/// cleartext HTTP, credential-bearing, or unexpected-scheme values can
/// never reach a URL launcher through these call sites. Callers that
/// intentionally need mailto:/tel:/sms:/app-specific schemes must not use
/// this helper; they should apply their own explicit, narrow scheme check.
Uri validatedHttpsUrl(String raw) {
  final uri = Uri.parse(raw.trim());
  if (uri.scheme != 'https' || uri.host.isEmpty || uri.userInfo.isNotEmpty) {
    throw const FormatException('Only credential-free HTTPS URLs are allowed');
  }
  return uri;
}

/// The reviewed release origin for plan and donation links.
///
/// Control-plane gateway defines must not decide where a shipped app sends a
/// user to spend money. The hub route on this origin may redirect the external
/// browser to the configured payment provider, but the app's first navigation
/// remains bound to this immutable, artifact-reviewable origin.
const String kReviewedPaymentBase = 'https://sync.winsvpn.org';
const String _releaseTrustedPaymentHostsCsv = 'sync.winsvpn.org';

/// Debug/profile-only staging override for payment-link hosts.
const bool _hasTrustedPaymentHostsDefine =
    bool.hasEnvironment('WINS_TRUSTED_PAYMENT_HOSTS');
const String _trustedPaymentHostsOverrideCsv = String.fromEnvironment(
  'WINS_TRUSTED_PAYMENT_HOSTS',
  defaultValue: _releaseTrustedPaymentHostsCsv,
);

/// Resolves the payment host allowlist without permitting a release override.
Set<String> compiledTrustedPaymentHosts({
  required bool isReleaseBuild,
  required String releaseCsv,
  required String overrideCsv,
}) {
  return parseTrustedUpdateHosts(
    isReleaseBuild ? releaseCsv : overrideCsv,
  );
}

Set<String> _resolveTrustedPaymentHosts() {
  assert(
    !(kReleaseMode && _hasTrustedPaymentHostsDefine),
    'WINS_TRUSTED_PAYMENT_HOSTS is a debug/profile-only testing override. A '
    'release build trusts exactly $_releaseTrustedPaymentHostsCsv.',
  );
  return compiledTrustedPaymentHosts(
    isReleaseBuild: kReleaseMode,
    releaseCsv: _releaseTrustedPaymentHostsCsv,
    overrideCsv: _trustedPaymentHostsOverrideCsv,
  );
}

final Set<String> _trustedPaymentHosts =
    Set<String>.unmodifiable(_resolveTrustedPaymentHosts());

/// Validates a direct payment or donation navigation against the immutable
/// release host set and the standard HTTPS origin.
Uri validatedPaymentUrl(String raw) {
  final uri = validatedHttpsUrl(raw);
  if (uri.port != 443 ||
      !_trustedPaymentHosts.contains(uri.host.toLowerCase()) ||
      uri.fragment.isNotEmpty) {
    throw const FormatException('Untrusted payment URL');
  }
  return uri;
}

/// The force-update host allowlist every release build enforces. Compiled in,
/// never overridable: the force-update flow launches the user's browser at one
/// of these hosts, so which hosts a shipped artifact trusts is a property of
/// the signed artifact, not of whoever wrote its build command (B-APP-002).
const String _releaseTrustedUpdateHostsCsv = 'winsvpn.org,www.winsvpn.org';

/// Build-time override for the force-update download host allowlist, as a
/// comma-separated list of bare hostnames. DEBUG/PROFILE ONLY.
///
/// This is a *network-observable* surface via the update path, not just an
/// authorisation one. The force-update flow launches a browser at one of these
/// hosts, so a neutral-domain build that re-points `WINS_GATEWAY_BASE` and
/// friends but leaves this list alone still sends the user's browser to the
/// branded domain the migration existed to remove. Keep it in step with
/// `WINS_PUBLIC_WEBSITE_URL`, which supplies the compiled fallback target.
/// See `docs/handoff/CONTROL_PLANE_NEUTRAL_DOMAIN_MIGRATION_20260806.md`.
///
/// A release build ignores the define entirely and enforces
/// [_releaseTrustedUpdateHostsCsv] (see [compiledTrustedUpdateHosts]); the
/// define exists so tests and local development can point the update prompt
/// at a staging host, never so a release build command could repoint a
/// shipped artifact at an arbitrary HTTPS host.
const bool _hasTrustedUpdateHostsDefine =
    bool.hasEnvironment('WINS_TRUSTED_UPDATE_HOSTS');
const String _trustedUpdateHostsOverrideCsv = String.fromEnvironment(
  'WINS_TRUSTED_UPDATE_HOSTS',
  defaultValue: _releaseTrustedUpdateHostsCsv,
);

/// Resolves the update-host allowlist a build enforces, as a pure function of
/// the build mode and the define value so the rule itself is testable.
///
/// A RELEASE build always enforces the compiled first-party set, exactly as
/// `controlPlanePinningEnforced` always enforces pinning: the override is a
/// debug/profile testing tool and cannot ride into a shipped artifact. Debug
/// and profile builds honour the define, which keeps the neutral-domain
/// migration workflow usable before a release is cut.
Set<String> compiledTrustedUpdateHosts({
  required bool isReleaseBuild,
  required String releaseCsv,
  required String overrideCsv,
}) {
  return parseTrustedUpdateHosts(
    isReleaseBuild ? releaseCsv : overrideCsv,
  );
}

Set<String> _resolveTrustedUpdateHosts() {
  assert(
    !(kReleaseMode && _hasTrustedUpdateHostsDefine),
    'WINS_TRUSTED_UPDATE_HOSTS is a debug/profile-only testing override. A '
    'release build trusts exactly the compiled hosts '
    '($_releaseTrustedUpdateHostsCsv); remove the dart-define from the '
    'release build command.',
  );
  return compiledTrustedUpdateHosts(
    isReleaseBuild: kReleaseMode,
    releaseCsv: _releaseTrustedUpdateHostsCsv,
    overrideCsv: _trustedUpdateHostsOverrideCsv,
  );
}

/// The only hosts the app trusts to serve a force-update download. Kept
/// deliberately tiny: the force-update flow can hand a user a hub-advertised
/// download URL, so an attacker who could set that value (a compromised
/// hub/admin session, or TLS interception on a device that trusts a rogue CA)
/// could otherwise pair a high minimum version with a phishing/malware page.
/// See M-9.
///
/// In a release build this is exactly the compiled first-party set and cannot
/// be widened by any dart-define (B-APP-002). In debug/profile builds a
/// set-but-unusable override degrades to **empty** rather than to the compiled
/// default. Falling back would re-introduce the branded host into precisely
/// the build that was trying to remove it. Empty is also the safe direction
/// for authorisation: [validatedAppUpdateUrl] then rejects every
/// hub-advertised URL and `_promptAppUpdateRequired` falls back to the
/// compiled website download page, so the force-update gate keeps working
/// with strictly less hub authority.
final Set<String> _trustedUpdateHosts =
    Set<String>.unmodifiable(_resolveTrustedUpdateHosts());

/// Splits and screens a `WINS_TRUSTED_UPDATE_HOSTS` value into bare, lowercase
/// hostnames. Exposed so the screen is testable and so any future caller is
/// held to the same standard rather than growing a second, weaker copy.
///
/// Rejects anything that is not a bare host: no scheme, port, path, userinfo,
/// query, fragment or whitespace. A value that carried any of those would not
/// match `uri.host` at the comparison site anyway, so accepting it would create
/// an entry that silently never matches -- an allowlist that looks configured
/// and is not.
Set<String> parseTrustedUpdateHosts(String csv) {
  final hosts = <String>{};
  for (final raw in csv.split(',')) {
    final value = raw.trim().toLowerCase();
    if (value.isEmpty) continue;
    if (value.contains('/') ||
        value.contains(':') ||
        value.contains('@') ||
        value.contains('?') ||
        value.contains('#') ||
        value.contains(RegExp(r'\s'))) {
      continue;
    }
    // Reject anything Uri does not agree is a plain registered host, so an
    // entry can never differ from what `uri.host` will produce.
    final probe = Uri.tryParse('https://$value');
    if (probe == null || probe.host != value || probe.hasPort) continue;
    hosts.add(value);
  }
  return hosts;
}

/// Stricter cousin of [validatedHttpsUrl] for the force-update download URL
/// only (M-9). On top of the credential-free-HTTPS guard it pins the host to
/// the first-party [_trustedUpdateHosts], requires the standard 443 port, and
/// rejects any URL fragment or userinfo. Throws [FormatException] on anything
/// else, so a hub-advertised `app_update_url` can never redirect the user to a
/// non-first-party host, a nonstandard port, or a fragment-smuggled target.
/// Callers that reject the value must fall back to the compiled-in first-party
/// website download page rather than launching the untrusted URL.
Uri validatedAppUpdateUrl(String raw) {
  final uri = validatedHttpsUrl(raw);
  if (uri.port != 443 ||
      !_trustedUpdateHosts.contains(uri.host.toLowerCase()) ||
      uri.fragment.isNotEmpty ||
      uri.userInfo.isNotEmpty) {
    throw const FormatException('Untrusted application update URL');
  }
  return uri;
}
