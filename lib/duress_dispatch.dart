/// Pure, side-effect-free helpers for the duress emergency dispatch.
///
/// These live outside `main.dart`'s private `State` class on purpose: Dart
/// privacy is per-library, so nothing inside that class is reachable from a
/// test file, and the shape/validation/redaction of the emergency payload is
/// exactly the part that most needs direct unit tests. Nothing in this file
/// performs I/O, touches the network, reads the clock, or logs. It only shapes,
/// validates, and redacts the record the caller sends and persists.
///
/// Threat-model rule that governs every choice here: a duress dispatch is
/// produced on a device that is being physically inspected under coercion. The
/// AT-REST record (what waits in encrypted secure storage when the device is
/// offline at the moment of entry) must not, by itself, prove the owner ran a
/// VPN or reveal anything past "a contact string and a coarse location". So the
/// persisted form carries no account number, no device id, no auth token, no
/// key material, and never the word that would name the app.
///
/// Delivery is DEVICE-NATIVE (Android SMS from the handset's own radio); there
/// is no hub and no relay, so no account/device/token identity is ever
/// composed into anything that leaves the device. The only bytes that reach the
/// trusted contact are the neutral [smsText] and the coordinates it carries.
library;

import 'dart:convert';

/// Maximum accepted length of a trusted-contact string. Long enough for an
/// email address or an international phone number; short enough that a pasted
/// blob cannot bloat the encrypted settings record.
const int kMaxTrustedContactLength = 254;

/// Normalizes a user-entered trusted contact (email or phone) for storage and
/// for use as a relay destination. Strips surrounding whitespace and removes
/// control characters and newlines, which is what stops a contact value from
/// smuggling extra headers/lines into a server-composed email or SMS. Returns
/// null when nothing usable remains, so an unconfigured contact is a clean
/// null rather than an empty-but-present value.
String? sanitizeTrustedContact(String? raw) {
  if (raw == null) return null;
  final buffer = StringBuffer();
  for (final unit in raw.codeUnits) {
    // Drop C0 control characters and DEL, which is what stops a contact
    // value from smuggling extra lines/headers into a server-composed
    // email or SMS. Everything printable (incl. spaces, +, -, @) is kept.
    if (unit >= 0x20 && unit != 0x7f) buffer.writeCharCode(unit);
  }
  final stripped = buffer.toString().trim();
  if (stripped.isEmpty) return null;
  if (stripped.length > kMaxTrustedContactLength) {
    return stripped.substring(0, kMaxTrustedContactLength);
  }
  return stripped;
}

/// The GSM-7 single-part SMS limit. A body of 161 characters is not "a
/// slightly longer message": `SmsManager.divideMessage` splits it into two
/// parts, which doubles the cost, doubles the chance of a partial delivery,
/// makes the native send wait for two SENT broadcasts instead of one, and
/// leaves twice the carrier trace. On the duress path each of those is a
/// safety cost, so [DuressDispatch.smsText] is required to stay under it.
const int kMaxSingleSmsLength = 160;

/// A neutral, clickable map link for a coordinate pair. Uses a plain HTTPS maps
/// query so the recipient can open it in any browser without the app needing to
/// be installed. Never embeds anything but the two numbers.
///
/// The short `maps.google.com/?q=` form is used rather than
/// `www.google.com/maps/search/?api=1&query=`: it resolves to the same place
/// in every browser and on both mobile platforms, and it is 21 characters
/// shorter. That is what takes the coordinate-bearing alert from 162
/// characters (two SMS parts, measured on a device) to a single part.
String mapsLinkForCoordinate(double latitude, double longitude) {
  final lat = latitude.toStringAsFixed(6);
  final lng = longitude.toStringAsFixed(6);
  return 'https://maps.google.com/?q=$lat,$lng';
}

/// The trusted-contact emergency dispatch.
///
/// One value object serves both the wait-for-connectivity queue (via
/// [toQueueJson]/[fromQueueJson]) and the recipient-facing SMS body (via
/// [smsText]). The queue form is the minimal, non-incriminating one described
/// in the library doc.
class DuressDispatch {
  const DuressDispatch({
    required this.trustedContact,
    required this.latitude,
    required this.longitude,
    required this.capturedAtUtc,
    this.attemptCount = 0,
  });

  /// Sanitized email/phone the alert should reach. Never null once a dispatch
  /// exists — a dispatch with no destination has nowhere to go.
  final String trustedContact;

  /// Last known COARSE location. Null when the app never obtained one (it holds
  /// no GPS permission; this is the IP-derived pre-VPN location), in which case
  /// the alert still goes out, just without coordinates.
  final double? latitude;
  final double? longitude;

  /// When the location/dispatch was captured, always in UTC.
  final DateTime capturedAtUtc;

  /// How many times a network send has already been attempted and failed.
  /// Lets the retry loop bound its own effort without a separate ledger.
  final int attemptCount;

  bool get hasCoordinates => latitude != null && longitude != null;

  DuressDispatch withAnotherAttempt() => DuressDispatch(
        trustedContact: trustedContact,
        latitude: latitude,
        longitude: longitude,
        capturedAtUtc: capturedAtUtc,
        attemptCount: attemptCount + 1,
      );

  /// A generic, recipient-facing message. Deliberately says nothing about a
  /// VPN, censorship, or a panic feature: if it is intercepted, or read by
  /// whoever is holding the phone, it must read as an ordinary personal safety
  /// message and expose only the coordinates it must. The hub may forward this
  /// verbatim or compose its own from the structured fields.
  String humanMessage() {
    final where = hasCoordinates
        ? 'Last known location: ${latitude!.toStringAsFixed(6)}, '
            '${longitude!.toStringAsFixed(6)} '
            '(${mapsLinkForCoordinate(latitude!, longitude!)}).'
        : 'Last known location is unavailable.';
    return 'Automated safety alert: your contact may need help and asked you '
        'to be notified. $where '
        'Sent ${capturedAtUtc.toIso8601String()}.';
  }

  /// A compact, recipient-facing SMS body for the DEVICE-NATIVE send path.
  ///
  /// Same neutrality contract as [humanMessage] — no VPN, no service name, no
  /// panic/duress wording — but short, because an SMS the user's OWN handset
  /// sends is billed and length-limited, and because the sender (the user's own
  /// number) is already known to the trusted contact. When coordinates exist it
  /// carries only a maps link; the raw numbers are implicit in that link. This
  /// is the text that shows on the recipient's phone, so it must read as an
  /// ordinary personal-safety note from a person, not a system.
  ///
  /// LENGTH IS A SAFETY PROPERTY HERE, not a nicety. The body must fit one
  /// GSM-7 part ([kMaxSingleSmsLength]); the previous wording plus the long
  /// maps URL measured 162 characters on a device and split into two parts.
  /// The coordinates are the part that must not be lost, so the wording
  /// carries the compression: the recipient already knows who the sender is
  /// (it arrives from the user's own number), so the message only has to say
  /// that help may be needed and where. If a pathological coordinate pair
  /// would still overflow, the link is dropped rather than the message split.
  ///
  /// TRANSLATION (Burmese): Burmese copy for this string and [humanMessage] now
  /// lives in `lib/l10n/app_en.arb` (template) and `lib/l10n/app_my.arb`
  /// (Burmese), generated into `AppLocalizations` as the `duress*` getters
  /// (see `lib/l10n/app_localizations_my.dart`). The Burmese was checked against
  /// the repo's syllable validator (clean) and blind cross-checked by two
  /// families (qwen, gemma) for orthography/meaning/neutrality. The RUNTIME
  /// below intentionally still uses English as the safe default: flipping the
  /// duress/SMS path to Burmese is gated on the native/Psych review the owner
  /// wants before release, and is exactly the step that must re-check length --
  /// [kMaxSingleSmsLength] for GSM-7 Latin, but non-Latin text drops the limit
  /// to 70 UCS-2 characters per SMS part. To activate: add `Locale('my')` to
  /// `kSupportedLocales` and `CFBundleLocalizations`, and select the `my`
  /// strings here.
  String smsText() {
    const withoutLocation =
        'Safety alert: someone who listed you as an emergency contact may '
        'need help. Location not available.';
    if (!hasCoordinates) return withoutLocation;
    final located =
        'Safety alert: someone who listed you as an emergency contact may '
        'need help. Approx. location: '
        '${mapsLinkForCoordinate(latitude!, longitude!)}';
    return located.length <= kMaxSingleSmsLength ? located : withoutLocation;
  }

  /// The minimal record persisted while waiting for connectivity. Carries only
  /// contact, coarse coordinates, capture time, and the attempt counter — no
  /// account number, device id, token, or app-identifying word.
  Map<String, dynamic> toQueueJson() => <String, dynamic>{
        'contact': trustedContact,
        if (latitude != null) 'lat': latitude,
        if (longitude != null) 'lng': longitude,
        'captured_at': capturedAtUtc.toIso8601String(),
        'attempts': attemptCount,
      };

  /// Rebuilds a dispatch from a persisted queue record, or null when the record
  /// is missing/malformed or carries no usable contact. Fails closed: a corrupt
  /// record is dropped rather than trusted.
  static DuressDispatch? fromQueueJson(dynamic json) {
    if (json is! Map) return null;
    final contact = sanitizeTrustedContact('${json['contact'] ?? ''}');
    if (contact == null) return null;
    final capturedRaw = '${json['captured_at'] ?? ''}';
    final captured = DateTime.tryParse(capturedRaw)?.toUtc();
    final attempts = int.tryParse('${json['attempts'] ?? 0}') ?? 0;
    return DuressDispatch(
      trustedContact: contact,
      latitude: _asDouble(json['lat']),
      longitude: _asDouble(json['lng']),
      capturedAtUtc: captured ?? DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      attemptCount: attempts < 0 ? 0 : attempts,
    );
  }

  String toQueueString() => jsonEncode(toQueueJson());

  /// A single-line, log-safe description. Contains NO contact and NO
  /// coordinates — only whether each was present and the attempt count — so a
  /// diagnostic line can record that a dispatch happened without recording who
  /// or where. This is the only representation that should ever reach a log.
  String redactedForLog() =>
      'DuressDispatch(contact:${trustedContact.isNotEmpty ? 'set' : 'unset'}, '
      'coords:${hasCoordinates ? 'set' : 'unset'}, attempts:$attemptCount)';

  static double? _asDouble(dynamic value) {
    if (value is num) return value.toDouble();
    if (value is String) return double.tryParse(value.trim());
    return null;
  }
}

// =====================================================================
// DURESS PROFILE GUARD — what a duress trigger may reveal about profiles.
//
// A profile is the named configuration record (real account profile vs the
// decoy "camouflage" profile the app can present). The dispatch-case rule
// under an armed duress trigger is that NEITHER may be revealed:
//
//   * the REAL profile must stay sealed — revealing it hands the device
//     holder the exact thing the duress path exists to protect; and
//   * the CAMOUFLAGE profile is refused too, even though it is a decoy and
//     harmless by itself, because it deliberately DIFFERS from the real one:
//     an inspector who sees a profile that is not the real one learns that a
//     disguise exists, which converts "owns a VPN" into "was operating a
//     covert tool". Revealing the decoy is therefore as much a tell as
//     revealing the real profile.
//
// The only answer the duress path may give is an explicit refusal that
// carries no label at all. This file is the pure shape/validation/redaction
// layer, so the decision lives here as a function a test can drive directly —
// exactly the part of the feature that used to be an inline branch in
// main.dart's private State class, unreachable from any test.
// =====================================================================

/// What a duress-triggered surface may present for a profile request.
///
/// [shownProfile] is empty exactly when the trigger refuses — the only legal
/// duress answer — and [realProfileSealed] reports the real profile's seal
/// state, which must be true whenever [shownProfile] is empty.
class DuressProfileDisclosure {
  const DuressProfileDisclosure({
    required this.shownProfile,
    required this.realProfileSealed,
  });

  /// The label the surface may show. Empty when a duress trigger refuses.
  final String shownProfile;

  /// Whether the REAL profile is sealed: true under a duress trigger, false
  /// during normal operation.
  final bool realProfileSealed;

  /// Whether this disclosure is a refusal: nothing may be shown AND the real
  /// profile is sealed. Both halves must hold together — a surrender that
  /// shows nothing but leaves the real profile unsealed is not a refusal, and
  /// sealing without refusing is not a duress response — which is why the
  /// suite asserts this gate and not either field alone.
  bool get refuses => shownProfile.isEmpty && realProfileSealed;
}

/// Decides, from the two profile labels the app holds, what may be revealed
/// on a surface and whether the real profile is sealed.
///
/// Normal operation (no duress trigger): the REAL label is shown and the real
/// profile is not sealed — that is the owner's own unlocked device.
///
/// Under an armed duress trigger: an explicit refusal — [shownProfile] is set
/// to the empty refusal, and the CAMOUFLAGE label is deliberately NOT
/// substituted in, because showing a profile that differs from the real one
/// proves the disguise exists. The real profile stays sealed. This is the
/// dispatch case: a duress trigger refuses to reveal a differing (camouflage)
/// profile and keeps the real one sealed.
DuressProfileDisclosure duressProfileDisclosure({
  required bool duressTriggered,
  required String realProfileLabel,
  required String camouflageProfileLabel,
}) {
  if (!duressTriggered) {
    return DuressProfileDisclosure(
      shownProfile: realProfileLabel,
      realProfileSealed: false,
    );
  }
  return DuressProfileDisclosure(
    shownProfile: '',
    realProfileSealed: true,
  );
}
