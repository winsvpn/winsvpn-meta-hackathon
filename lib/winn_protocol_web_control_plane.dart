/// Winn Protocol v3 -- WEB control-plane winn/3 config EMISSION (DEV override).
///
/// # What this file is, in one sentence
///
/// The web-surface half of the winn/3 dev-config emission: given a resolved
/// `winn/3` config (the shape `lib/winn_protocol_dev_config_source.dart`
/// loads), it renders the authoritative `[winn]` INI section through the SAME
/// served-config gate the native platforms use, and produces a DEV OVERRIDE
/// document the web surface in `web/` can serve.
///
/// # Relationship to `winn_protocol_dev_config_source.dart`
///
/// `winn_protocol_dev_config_source.dart` is the loader + required-field
/// pre-check + redaction layer; it loads a hand-written config from disk and
/// validates it. This file is the *printer* layer: it takes an already-resolved
/// `winn/3` config and asks [resolveWinnProtocolStartForServedConfig] -- the
/// exact function the shipping dispatcher uses to build a `[winn]` section from
/// a served config, and the one `winn_protocol_dev_config_source.dart` routes
/// through -- for the section it resolves to. There is no second, looser
/// parser here: a config the real gate refuses is refused here with the same
/// reason.
///
/// Notably this file does NOT re-implement the platform capability gate
/// (`resolveWinnProtocolStart`), because the web has no kernel `tun`, no
/// NetworkExtension and no VpnService: the web surface's job is to carry a
/// resolved config to a dev override file, not to start a tunnel. Emitting the
/// served-config section is the honest boundary -- it resolves WHAT the
/// negotiation produced, and ships nothing anywhere.
///
/// # Secret handling
///
/// [redactWinnConfigForWebOverride] mirrors the field-level redaction of
/// `winn_protocol_dev_config_source.dart` so that the JSON snapshot that
/// accompanies a dev override file never contains key material in the clear.
/// The `[winn]` INI section itself may legitimately carry a device private key
/// (a real AmneziaWG session cannot be described without one), so the INI
/// override file is DEV-ONLY and must never be committed or deployed -- the
/// library doc and the [kWinnWebDevOverrideBanner] both say so, and the web
/// surface's `.gitignore`/`.assetsignore` should exclude it.
///
/// # Why pure Dart
///
/// Deliberately no `package:flutter` import: the emission CLI
/// (`tool/emit_winn3_web_dev_override.dart`) runs it under a plain `dart run`
/// on the host, and the web build (`lib/winn_protocol_web_control_plane_main.dart`)
/// carries it into a Flutter web target that DOES import
/// `winn_protocol_dev_config_source.dart`. Keeping the printer Flutter-free
/// is what lets the dev emission be driven as a lightweight CLI without
/// loading the whole app.
library;

import 'dart:convert';

import 'winn_protocol_dispatch.dart';

/// The filename the web dev override INI is written under, inside `web/`.
const String kWinnWebDevOverrideFileName = 'winn3-dev-override.ini';

/// The companion JSON snapshot name (redacted) written beside the INI.
const String kWinnWebDevOverrideJsonFileName = 'winn3-dev-override.json';

/// The carrier this emission is about. Not a switch -- the emitted section is
/// whatever the authoritative gate resolves --- but kept so error strings and
/// the override metadata name the thing this file exists to carry.
const String kWinnWebControlPlaneCarrier = 'winn3';

/// Field names (exact, case- and whitespace-insensitive match -- never a
/// substring match) whose VALUE is never emitted in the redacted JSON snapshot
/// and never logged. Mirrors `kWinnDevConfigSecretFieldNames` in
/// `winn_protocol_dev_config_source.dart`; public keys are not secret.
const Set<String> kWinnWebConfigSecretFieldNames = <String>{
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

/// Fields a `winn/3` dev config must carry before this file will hand it to
/// the real gate. Deliberately identical to
/// `kWinnDevConfigRequiredFields` in `winn_protocol_dev_config_source.dart`;
/// kept as a local copy (rather than an import, which would drag in
/// `package:flutter`) with a parity note so a change to one is caught.
const Set<String> kWinnWebConfigRequiredFields = <String>{
  'client_ip',
  'client_private_key',
  'client_public_key',
  'server_public_key',
};

/// Printed (via [log]) at the start of an active emission, so whoever runs it
/// and whoever reads the override file after can never mistake it for a
/// backend-served config.
const String kWinnWebDevOverrideBanner = '''
################################################################################
# WINN/3 WEB DEV OVERRIDE EMITTED -- DEVELOPER-SUPPLIED, NON-SHIPPING          #
#                                                                              #
# This file was generated from a local dev config by the web control-plane    #
# emission. It is NOT a config Win's VPN's backend served, and it must NOT be  #
# committed or deployed. It exists so the web surface in web/ can carry a      #
# resolved winn/3 config for development/testing only. It may contain key      #
# material; treat it as secret and keep it out of any release artifact.        #
################################################################################''';

/// The outcome of trying to emit a dev override from a resolved config.
///
/// Beyond the INI section itself, a successful emission surfaces the pieces of
/// winn/3 control-plane delivery a web surface needs to describe the session it
/// is carrying -- [sessionId], [carrier] plus the [carrierHints] set, and the
/// [awgNonceFields] (`h1`..`h4` / `s1`..`s4`). Every one of these is read BACK
/// from the emitted section (the same bytes the authoritative gate produced),
/// so a reader reconciles the snapshot against the document rather than
/// trusting a second, independent derivation that could disagree with it.
class WinnWebControlPlaneEmission {
  const WinnWebControlPlaneEmission._({
    required this.accepted,
    this.errors = const <String>[],
    this.iniDocument,
    this.redactedConfig,
    this.protocolVersion,
    this.carrier,
    this.sessionId,
    this.carrierHints = const <String>[],
    this.awgNonceFields = const <String>[],
  });

  // Not `const`: the initializer wraps [carrierHints] and [awgNonceFields] in
  // `List.unmodifiable`, which is not a constant expression, so a `const`
  // constructor here could not compile. The call sites (see
  // [emitWinnProtocolWebControlPlane]) already pass non-const values.
  WinnWebControlPlaneEmission.accepted({
    required String iniDocument,
    required Map<String, dynamic> redactedConfig,
    required String protocolVersion,
    required String carrier,
    required String? sessionId,
    required List<String> carrierHints,
    required List<String> awgNonceFields,
  }) : this._(
          accepted: true,
          iniDocument: iniDocument,
          redactedConfig: redactedConfig,
          protocolVersion: protocolVersion,
          carrier: carrier,
          sessionId: sessionId,
          carrierHints: List<String>.unmodifiable(carrierHints),
          awgNonceFields: List<String>.unmodifiable(awgNonceFields),
        );

  factory WinnWebControlPlaneEmission.refused(Iterable<String> errors) =>
      WinnWebControlPlaneEmission._(
        accepted: false,
        errors: List<String>.unmodifiable(errors.toSet().toList()..sort()),
      );

  final bool accepted;

  /// Why emission was refused, or empty on success. Never derived from config
  /// values (no key material).
  final List<String> errors;

  /// The resolved `[winn]` INI section -- the document to write to
  /// [kWinnWebDevOverrideFileName]. `null` when refused.
  final String? iniDocument;

  /// The loaded config with every value of a
  /// [kWinnWebConfigSecretFieldNames] key replaced by `<redacted>` -- the
  /// JSON snapshot for [kWinnWebDevOverrideJsonFileName]. `null` when refused.
  final Map<String, dynamic>? redactedConfig;

  /// `winn/3` on success.
  final String? protocolVersion;

  /// The resolved carrier on success.
  final String? carrier;

  /// The `session_id` this resolved session carries, read back from the emitted
  /// section. Empty/`null` when the config named none (the datapath treats an
  /// absent `session_id` as valid and the gate emits nothing for it).
  final String? sessionId;

  /// The carriers this build can start, ordered with the resolved [carrier]
  /// first. A web surface reads these as the transport hints for the session:
  /// the first element is the carrier the config was committed to; the rest are
  /// the other transports this build could have started had the hub selected
  /// them. Empty when refused.
  final List<String> carrierHints;

  /// The `h1`..`h4` / `s1`..`s4` nonce-padding values this resolved session
  /// carries, read back from the emitted section in that fixed order (four
  /// AmneziaWG header types, then four prefix-padding scalars). Empty when
  /// refused.
  final List<String> awgNonceFields;
}

/// Whether [config] is missing any [kWinnWebConfigRequiredFields] field
/// (treating blank as missing). Returns the sorted missing field names.
List<String> missingWinnWebConfigFields(Map<String, dynamic> config) {
  final missing = kWinnWebConfigRequiredFields
      .where((key) => (config[key]?.toString().trim() ?? '').isEmpty)
      .toList()
    ..sort();
  return missing;
}

/// Parses the `[winn]` section out of an emitted INI document into a
/// lowercased-key map, values verbatim (trimmed). This mirrors
/// `parseWinnIosControlPlaneIni` in `winn_protocol_ios_raw_config.dart`; the
/// agreement between the two parsers is pinned by
/// `test/winn_protocol_web_control_plane_test.dart` (cross-parser round-trip)
/// so the CLI's parsed `[winn]` JSON is never a private re-parse.
Map<String, String> parseWinnWinnSection(String iniDocument) {
  final winn = <String, String>{};
  final lines = const LineSplitter().convert(iniDocument);
  var inWinn = false;
  for (final line in lines) {
    final trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      final name =
          trimmed.substring(1, trimmed.length - 1).trim().toLowerCase();
      inWinn = name == 'winn';
      continue;
    }
    if (!inWinn) continue;
    final equals = trimmed.indexOf('=');
    if (equals <= 0) continue;
    final key = trimmed.substring(0, equals).trim().toLowerCase();
    final value = trimmed.substring(equals + 1).trim();
    if (key.isEmpty) continue;
    winn[key] = value;
  }
  return winn;
}

/// A parsed `[winn]` map with every secret-field VALUE replaced by
/// `<redacted>` (exact, case-insensitive key match via
/// [kWinnWebConfigSecretFieldNames]). Never a substring match.
Map<String, String> redactWinnWinnSection(Map<String, String> winnSection) {
  return winnSection.map((key, value) {
    final normalized = key.trim().toLowerCase();
    if (kWinnWebConfigSecretFieldNames.contains(normalized) &&
        value.isNotEmpty) {
      return MapEntry(key, '<redacted>');
    }
    return MapEntry(key, value);
  });
}

/// Deep-copies [config], replacing the value of every key named by
/// [kWinnWebConfigSecretFieldNames] (exact, case-insensitive) with
/// `<redacted>`, descending into nested maps/lists.
Map<String, dynamic> redactWinnConfigForWebOverride(
    Map<String, dynamic> config) {
  return _redactMap(config);
}

Map<String, dynamic> _redactMap(Map<String, dynamic> input) {
  final out = <String, dynamic>{};
  for (final entry in input.entries) {
    final normalizedKey = entry.key.trim().toLowerCase();
    final value = entry.value;
    if (kWinnWebConfigSecretFieldNames.contains(normalizedKey) &&
        (value?.toString().isNotEmpty ?? false)) {
      out[entry.key] = '<redacted>';
    } else {
      out[entry.key] = _redactValue(value);
    }
  }
  return out;
}

Object? _redactValue(Object? value) {
  if (value is Map) return _redactMap(Map<String, dynamic>.from(value));
  if (value is List) return value.map(_redactValue).toList();
  return value;
}

/// The full text of the dev override JSON snapshot, pre-rendered.
String renderWinnWebDevOverrideJson(Map<String, dynamic> config) =>
    jsonEncode(redactWinnConfigForWebOverride(config));

/// Emits a resolved `winn/3` config as a web dev override.
///
/// Checks (a) required fields, (b) that `protocol_version` is `winn/3`, and
/// (c) that [resolveWinnProtocolStartForServedConfig] accepts the config --
/// the authoritative gate. On success returns the resolved `[winn]` INI
/// section plus a redacted JSON snapshot. A config the real gate refuses is
/// refused here with that gate's reason; [log] receives
/// [kWinnWebDevOverrideBanner] and one verdict line.
WinnWebControlPlaneEmission emitWinnProtocolWebControlPlane({
  required Map<String, dynamic> config,
  void Function(String message)? log,
}) {
  void say(String message) => log?.call(message);

  final missingFields = missingWinnWebConfigFields(config);
  if (missingFields.isNotEmpty) {
    final error =
        'winn/3 web override emission refused -- config is missing required '
        'field(s): ${missingFields.join(', ')}.';
    say(error);
    return WinnWebControlPlaneEmission.refused(<String>[
      'missing_field_${missingFields.join(',')}',
    ]);
  }

  final protocolVersion = normalizedWinnProtocolVersion(config['protocol_version']);
  if (protocolVersion != kWinnProtocolV3) {
    final error = protocolVersion == kWinnProtocolV1
        ? 'web override emission is only for protocol_version "$kWinnProtocolV3" '
            'configs, not "$kWinnProtocolV1".'
        : 'unknown protocol_version "$protocolVersion".';
    say('winn/3 web override emission: $error');
    return WinnWebControlPlaneEmission.refused(<String>['not_winn3']);
  }

  say(kWinnWebDevOverrideBanner);

  final decision =
      resolveWinnProtocolStartForServedConfig(config: config);
  if (!decision.supported) {
    final error = 'refused by the authoritative gate '
        '(${decision.reason.code}). ${decision.message}';
    say('winn/3 web override emission: $error');
    return WinnWebControlPlaneEmission.refused(<String>[
      'gate_${decision.reason.code}',
    ]);
  }

  // Report the carrier the gate ACTUALLY resolved to (read it back from the
  // emitted section rather than guessing), so metadata never disagrees with
  // the document itself.
  final carrier = _sectionValue(decision.iniSection, 'carrier');
  final sessionId = _sectionValue(decision.iniSection, 'session_id');
  if (sessionId.isEmpty) {
    say('winn/3 web override emission: accepted carrier=$carrier '
        'section_bytes=${utf8.encode(decision.iniSection).length}.');
  } else {
    say('winn/3 web override emission: accepted carrier=$carrier '
        'session_id_bytes=${utf8.encode(sessionId).length} '
        'section_bytes=${utf8.encode(decision.iniSection).length}.');
  }
  return WinnWebControlPlaneEmission.accepted(
    iniDocument: decision.iniSection,
    redactedConfig: redactWinnConfigForWebOverride(config),
    protocolVersion: kWinnProtocolV3,
    carrier: carrier,
    sessionId: sessionId.isEmpty ? null : sessionId,
    carrierHints: _carrierHintsFor(carrier),
    awgNonceFields: [
      for (final key in const ['h1', 'h2', 'h3', 'h4', 's1', 's2', 's3', 's4'])
        _sectionValue(decision.iniSection, key),
    ],
  );
}

/// The value of one `key = value` line in [section], or `''` when absent.
///
/// Parses the SAME `[winn]` document the authoritative gate produced, so the
/// readouts on [WinnWebControlPlaneEmission] can never disagree with the file
/// that is about to be written to disk.
String _sectionValue(String section, String key) {
  final prefix = '$key ';
  for (final line in const LineSplitter().convert(section)) {
    if (line.startsWith(prefix)) {
      final eq = line.indexOf('=');
      if (eq >= 0) return line.substring(eq + 1).trim();
    }
  }
  return '';
}

/// The transport hints for a session: the resolved [resolvedCarrier] first,
/// then every other carrier this build can start, in [kWinnSupportedCarriers]'
/// own order.
List<String> _carrierHintsFor(String resolvedCarrier) => <String>[
      resolvedCarrier,
      ...kWinnSupportedCarriers.where((c) => c != resolvedCarrier),
    ];
