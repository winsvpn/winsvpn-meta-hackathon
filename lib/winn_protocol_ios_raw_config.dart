/// DEV-ONLY iOS delivery of a complete `carrier = winn3` INI document through
/// the shipping `startTunnel` channel and its transient `raw_config` option.
///
/// This is deliberately separate from the served-config dispatcher. A lab
/// document is already the final native INI shape, so it does not need a
/// control-plane descriptor or a compiled descriptor-verification key. The
/// native host and provider still run their shipping validators unchanged.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/services.dart' show MethodChannel;

import 'winn_protocol_dev_config_source.dart' show resolveWinnDevConfigPath;

const String kWinnIosRawConfigLabDartDefine = 'WINN_IOS_RAW_CONFIG_LAB';
const bool kWinnIosRawConfigLabDartDefineValue = bool.fromEnvironment(
  kWinnIosRawConfigLabDartDefine,
  defaultValue: false,
);
const String kWinnIosRawConfigPathDartDefine = 'WINN_IOS_RAW_CONFIG_PATH';
const String kWinnIosRawConfigPath = String.fromEnvironment(
  kWinnIosRawConfigPathDartDefine,
  defaultValue: 'container:winn3_raw_lab.ini',
);
const String kWinnIosRawConfigAccountScopeDartDefine =
    'WINN_IOS_RAW_CONFIG_ACCOUNT_SCOPE';
const String kWinnIosRawConfigAccountScope = String.fromEnvironment(
  kWinnIosRawConfigAccountScopeDartDefine,
);

/// This literal, rather than a private key, must appear in `[Interface]`.
/// It is replaced in memory with an EXISTING Keychain identity immediately
/// before the shipping native validator receives the document.
const String kWinnIosRawConfigKeychainPlaceholder =
    '__WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__';

/// Must stay equal to `WinsTunnelConfig.maxRuntimeConfigFileBytes`.
const int kWinnIosRawConfigMaxBytes = 262144;

const MethodChannel _tunnelChannel = MethodChannel('wins_vpn/tunnel');

typedef WinnIosRawConfigInvoker = Future<Object?> Function(
  String method,
  Object? arguments,
);

Future<Object?> _shippingInvoker(String method, Object? arguments) =>
    _tunnelChannel.invokeMethod<Object?>(method, arguments);

bool computeWinnIosRawConfigLabActive({
  required bool debugMode,
  required bool dartDefineEnabled,
}) =>
    debugMode && dartDefineEnabled;

bool get winnIosRawConfigLabActive => computeWinnIosRawConfigLabActive(
      debugMode: kDebugMode,
      dartDefineEnabled: kWinnIosRawConfigLabDartDefineValue,
    );

class WinnIosRawConfigPreflight {
  const WinnIosRawConfigPreflight._({
    required this.accepted,
    required this.errors,
    this.document,
  });

  const WinnIosRawConfigPreflight.accepted(String document)
      : this._(accepted: true, errors: const <String>[], document: document);

  WinnIosRawConfigPreflight.refused(Iterable<String> errors)
      : this._(
          accepted: false,
          errors: List<String>.unmodifiable(errors.toSet().toList()..sort()),
        );

  final bool accepted;
  final List<String> errors;

  /// The original document. Never log or display this: it contains v3 key
  /// material. It is retained only so the caller can perform one substitution.
  final String? document;
}

class _IniSection {
  _IniSection(this.name);

  final String name;
  final Map<String, String> values = <String, String>{};
}

/// Structural preflight before any MethodChannel call.
///
/// This does not replace `WinsTunnelConfig.parseAndValidate`; it prevents the
/// lab seam from being accidentally used for a relay, an uncontained session,
/// a document with ambiguous duplicate keys, or a document embedding an
/// interface private key. Values are never included in an error.

bool _isValidIpv4(String value) {
  final parts = value.split('.');
  if (parts.length != 4) return false;
  for (final part in parts) {
    if (part.isEmpty) return false;
    final n = int.tryParse(part);
    if (n == null || n < 0 || n > 255) return false;
  }
  return true;
}

bool _isBase64(String value) {
  if (value.isEmpty) return false;
  try {
    base64.decode(value);
    return true;
  } on FormatException {
    return false;
  }
}

bool _isValidEndpoint(String value) {
  final colon = value.lastIndexOf(':');
  if (colon <= 0 || colon == value.length - 1) return false;
  final host = value.substring(0, colon);
  if (host.isEmpty) return false;
  final port = int.tryParse(value.substring(colon + 1));
  return port != null && port >= 1 && port <= 65535;
}

WinnIosRawConfigPreflight preflightWinnIosRawConfig(
  String document, {
  bool requireDevContainment = true,
}) {
  final errors = <String>[];
  final byteCount = utf8.encode(document).length;
  if (byteCount == 0) errors.add('config_empty');
  if (byteCount > kWinnIosRawConfigMaxBytes) errors.add('config_too_large');
  if (document.contains('\u0000')) errors.add('config_contains_nul');

  final sections = <String, _IniSection>{};
  String? activeSection;
  final placeholderCount =
      document.split(kWinnIosRawConfigKeychainPlaceholder).length - 1;
  var interfacePlaceholderCount = 0;
  final lines = const LineSplitter().convert(document);
  for (var index = 0; index < lines.length; index++) {
    final trimmed = lines[index].trim();
    if (trimmed.isEmpty || trimmed.startsWith('#') || trimmed.startsWith(';')) {
      continue;
    }
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      final name =
          trimmed.substring(1, trimmed.length - 1).trim().toLowerCase();
      if (name.isEmpty) {
        errors.add('empty_section_name');
        activeSection = null;
      } else if (sections.containsKey(name)) {
        errors.add('duplicate_section_$name');
        activeSection = name;
      } else {
        sections[name] = _IniSection(name);
        activeSection = name;
      }
      continue;
    }
    final equals = trimmed.indexOf('=');
    if (activeSection == null || equals <= 0) {
      errors.add('malformed_line_${index + 1}');
      continue;
    }
    final key = trimmed.substring(0, equals).trim().toLowerCase();
    final value = trimmed.substring(equals + 1).trim();
    if (key.isEmpty) {
      errors.add('empty_key_line_${index + 1}');
      continue;
    }
    final section = sections[activeSection]!;
    if (section.values.containsKey(key)) {
      errors.add('duplicate_key_${section.name}_$key');
      continue;
    }
    section.values[key] = value;
    if (section.name == 'interface' &&
        key == 'privatekey' &&
        value == kWinnIosRawConfigKeychainPlaceholder) {
      interfacePlaceholderCount++;
    }
  }

  for (final required in <String>[
    'interface',
    'peer',
    'winn',
    if (requireDevContainment) 'winsdevcontainment',
  ]) {
    if (!sections.containsKey(required)) {
      errors.add('missing_section_$required');
    }
  }

  final interface = sections['interface']?.values;
  if (interface != null) {
    final privateKey = interface['privatekey'];
    if (privateKey == null || privateKey.isEmpty) {
      errors.add('interface_privatekey_missing');
    } else if (privateKey != kWinnIosRawConfigKeychainPlaceholder) {
      errors.add('interface_privatekey_must_be_keychain_placeholder');
    }
  }
  if (placeholderCount != 1 || interfacePlaceholderCount != 1) {
    errors.add('keychain_placeholder_count_not_one');
  }

  final containment = sections['winsdevcontainment']?.values;
  if (requireDevContainment &&
      (containment?['enabled'] ?? '').toLowerCase() != 'true') {
    errors.add('containment_not_enabled');
  }

  final winn = sections['winn']?.values;
  if ((winn?['enabled'] ?? '').toLowerCase() != 'true') {
    errors.add('winn_not_enabled');
  }
  if ((winn?['carrier'] ?? '').toLowerCase() != 'winn3') {
    errors.add('carrier_not_winn3');
  }
  for (final required in const <String>[
    'endpoint',
    'inner_v4',
    'inner_router_v4',
    'static_private',
    'gateway_static',
    'gateway_id',
    'admission_key',
    'path_mtu',
    'carrier_classes',
  ]) {
    if ((winn?[required] ?? '').isEmpty) {
      errors.add('winn_${required}_missing');
    }
  }
  final pathMtu = int.tryParse(winn?['path_mtu'] ?? '');
  if (pathMtu == null || pathMtu <= 0) errors.add('winn_path_mtu_invalid');

  final endpoint = winn?['endpoint'] ?? '';
  if (endpoint.isNotEmpty && !_isValidEndpoint(endpoint)) {
    errors.add('winn_endpoint_malformed');
  }
  final innerV4 = winn?['inner_v4'] ?? '';
  if (innerV4.isNotEmpty && !_isValidIpv4(innerV4)) {
    errors.add('winn_inner_v4_malformed');
  }
  final innerRouterV4 = winn?['inner_router_v4'] ?? '';
  if (innerRouterV4.isNotEmpty && !_isValidIpv4(innerRouterV4)) {
    errors.add('winn_inner_router_v4_malformed');
  }
  if (innerV4.isNotEmpty &&
      innerRouterV4.isNotEmpty &&
      innerV4 == innerRouterV4) {
    // The device would be its own next hop. Nothing detects this on the wire:
    // the gateway refuses the datagram source and, on a censored network, that
    // is indistinguishable from the path being blocked.
    errors.add('winn_inner_v4_equals_router');
  }
  final carrierClasses = (winn?['carrier_classes'] ?? '').trim();
  if (carrierClasses.isNotEmpty) {
    var hasUdp = false;
    for (final token in carrierClasses.split(',')) {
      final normalized = token.trim().toLowerCase();
      if (normalized == 'udp') hasUdp = true;
      if (normalized != 'udp' && normalized != 'tcp' && normalized != 'tls') {
        errors.add('winn_carrier_classes_malformed');
        break;
      }
    }
    if (!hasUdp) errors.add('winn_carrier_classes_udp_required');
  }
  for (final field in const <String>[
    'gateway_id',
    'admission_key',
    'static_private',
    'gateway_static',
  ]) {
    final candidate = winn?[field] ?? '';
    if (candidate.isNotEmpty && !_isBase64(candidate)) {
      errors.add('winn_${field}_malformed');
    }
  }

  return errors.isEmpty
      ? WinnIosRawConfigPreflight.accepted(document)
      : WinnIosRawConfigPreflight.refused(errors);
}

class WinnIosRawConfigLabResult {
  const WinnIosRawConfigLabResult({
    required this.active,
    this.accepted = false,
    this.blockedAt,
    this.reason,
  });

  final bool active;
  final bool accepted;
  final String? blockedAt;
  final String? reason;
}

/// Read, preflight, substitute, and deliver one complete raw INI document.
///
/// No config contents, key bytes, endpoint, gateway id, or path are returned.
/// The existing Keychain read and placeholder substitution are DEBUG-only and
/// native, so the private key never crosses into Dart. That helper cannot mint
/// a credential and calls the shipping `startTunnel` implementation directly;
/// the provider still selects `options["raw_config"]` first.
Future<WinnIosRawConfigLabResult> runWinnIosRawConfigLab({
  required String operatingSystem,
  String accountScope = kWinnIosRawConfigAccountScope,
  WinnIosRawConfigInvoker invoke = _shippingInvoker,
  bool? activeOverride,
  String? configuredPathOverride,
  Future<List<int>> Function(String path)? readBytesOverride,
}) async {
  // Overrides are dependency-injection seams for tests only. Production callers
  // pass none, so the compile-time gate and configured path remain authoritative.
  final active = activeOverride ?? winnIosRawConfigLabActive;
  if (!active) {
    return const WinnIosRawConfigLabResult(active: false);
  }
  if (operatingSystem.toLowerCase() != 'ios') {
    return const WinnIosRawConfigLabResult(
      active: true,
      blockedAt: 'platform',
      reason: 'ios_only',
    );
  }

  final configuredPath = configuredPathOverride ?? kWinnIosRawConfigPath;
  final resolution = resolveWinnDevConfigPath(configuredPath);
  if (!resolution.resolved || !resolution.usedContainerScheme) {
    return const WinnIosRawConfigLabResult(
      active: true,
      blockedAt: 'config_path',
      reason: 'container_path_required',
    );
  }

  String document;
  try {
    final bytes = readBytesOverride == null
        ? await File(resolution.path!).readAsBytes()
        : await readBytesOverride(resolution.path!);
    if (bytes.isEmpty || bytes.length > kWinnIosRawConfigMaxBytes) {
      return const WinnIosRawConfigLabResult(
        active: true,
        blockedAt: 'config_read',
        reason: 'invalid_size',
      );
    }
    document = utf8.decode(bytes, allowMalformed: false);
  } catch (_) {
    return const WinnIosRawConfigLabResult(
      active: true,
      blockedAt: 'config_read',
      reason: 'unreadable_or_not_utf8',
    );
  }

  final preflight = preflightWinnIosRawConfig(document);
  if (!preflight.accepted) {
    return WinnIosRawConfigLabResult(
      active: true,
      blockedAt: 'preflight',
      reason: preflight.errors.join(','),
    );
  }

  try {
    final raw = await invoke('startIosRawConfigLabTunnel', <String, dynamic>{
      'configTemplate': document,
      'accountScope': accountScope,
    });
    return WinnIosRawConfigLabResult(
      active: true,
      accepted: raw == true,
      blockedAt: raw == true ? null : 'native_start',
      reason: raw == true ? null : 'not_accepted',
    );
  } catch (_) {
    return const WinnIosRawConfigLabResult(
      active: true,
      blockedAt: 'native_start',
      reason: 'native_refused',
    );
  }
}

/// The shipping control-plane delivery path for winn/3 config emission.
///
/// This is distinct from the DEV-only lab seam above. It is the emitter the
/// serving control plane drives: given a resolved winn/3 payload it renders the
/// full INI through the same authoritative printer/gate, and hands the native
/// host a payload to install as a `NETunnelProviderProtocol`. The native side
/// installs it (via `loadAllFromPreferences` + save) and NEVER starts the
/// tunnel, so this path can deliver a config without ever carrying traffic.
const String kWinnIosControlPlaneProtocolVersion = 'winn/3';
const String kWinnIosControlPlaneCarrier = 'winn3';
const String kWinnIosControlPlaneNativeMethod =
    'installWinn3ControlPlaneConfig';

/// The full `[winn]` INI section, rendered from a served control-plane payload.
///
/// Keys are lowercased and values preserved verbatim, so the round-trip
/// (render -> parse -> render) is byte-stable. The winn/3 carrier and enabled
/// flags are not caller-settable: the emitter forces them.
class WinnIosControlPlaneWinnFields {
  const WinnIosControlPlaneWinnFields({
    required this.endpoint,
    required this.innerV4,
    required this.innerRouterV4,
    required this.staticPrivate,
    required this.gatewayStatic,
    required this.gatewayId,
    required this.admissionKey,
    required this.pathMtu,
    required this.carrierClasses,
    this.sessionId = '',
  });

  final String endpoint;
  final String innerV4;
  final String innerRouterV4;
  final String staticPrivate;
  final String gatewayStatic;
  final String gatewayId;
  final String admissionKey;
  final String pathMtu;
  final String carrierClasses;
  final String sessionId;

  /// Snapshot as a lowercased-key map, including the forced carrier/enabled
  /// entries, so [parseWinnIosControlPlaneIni] can round-trip it exactly.
  Map<String, String> toWinnFieldMap() => <String, String>{
        'enabled': 'true',
        'carrier': kWinnIosControlPlaneCarrier,
        'endpoint': endpoint,
        'inner_v4': innerV4,
        'inner_router_v4': innerRouterV4,
        'static_private': staticPrivate,
        'gateway_static': gatewayStatic,
        'gateway_id': gatewayId,
        'admission_key': admissionKey,
        'path_mtu': pathMtu,
        'carrier_classes': carrierClasses,
        if (sessionId.isNotEmpty) 'session_id': sessionId,
      };
}

/// The delivery payload installed by the native host.
class WinnIosControlPlaneDelivery {
  const WinnIosControlPlaneDelivery({
    required this.protocolVersion,
    required this.carrier,
    required this.iniDocument,
  });

  final String protocolVersion;
  final String carrier;
  final String iniDocument;

  Map<String, Object?> toNativeArguments() => <String, Object?>{
        'config': iniDocument,
        'protocolVersion': protocolVersion,
        'carrier': carrier,
      };
}

class WinnIosControlPlaneEmission {
  const WinnIosControlPlaneEmission.accepted(
      WinnIosControlPlaneDelivery delivery)
      : this._(
          accepted: true,
          delivery: delivery,
          errors: const <String>[],
        );

  WinnIosControlPlaneEmission.refused(Iterable<String> errors)
      : this._(
          accepted: false,
          delivery: null,
          errors: List<String>.unmodifiable(errors.toSet().toList()..sort()),
        );

  const WinnIosControlPlaneEmission._({
    required this.accepted,
    required this.delivery,
    required this.errors,
  });

  final bool accepted;
  final WinnIosControlPlaneDelivery? delivery;
  final List<String> errors;
}

class WinnIosControlPlaneParsedIni {
  const WinnIosControlPlaneParsedIni(this.winn);

  /// The `[winn]` section as a lowercased-key map. Empty when absent.
  final Map<String, String> winn;
}

/// Drops any existing `[winn]` section and its body, trimming trailing blank
/// lines, so the renderer's output is canonical and idempotent.
String _stripWinnSection(String document) {
  const target = 'winn';
  final lines = const LineSplitter().convert(document);
  final out = <String>[];
  var inTarget = false;
  for (final line in lines) {
    final trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      final name =
          trimmed.substring(1, trimmed.length - 1).trim().toLowerCase();
      if (name == target) {
        inTarget = true;
        continue;
      }
      inTarget = false;
    }
    if (inTarget) continue;
    out.add(line);
  }
  while (out.isNotEmpty && out.last.trim().isEmpty) {
    out.removeLast();
  }
  return out.join('\n');
}

String _renderWinnSection(Map<String, String> winnFields) {
  final normalized = <String, String>{};
  winnFields.forEach((key, value) {
    final k = key.trim().toLowerCase();
    if (k.isEmpty) return;
    normalized[k] = value.trim();
  });
  const order = <String>[
    'enabled',
    'carrier',
    'endpoint',
    'inner_v4',
    'inner_router_v4',
    'static_private',
    'gateway_static',
    'gateway_id',
    'admission_key',
    'path_mtu',
    'carrier_classes',
    'session_id',
    'max_datagram',
    'h1',
    'h2',
    'h3',
    'h4',
    's1',
    's2',
    's3',
    's4',
  ];
  final buffer = StringBuffer('[winn]\n');
  for (final key in order) {
    final value = normalized[key];
    if (value != null && value.isNotEmpty) {
      buffer.write('$key = $value\n');
    }
  }
  final remaining = normalized.keys.where((k) => !order.contains(k)).toList()
    ..sort();
  for (final key in remaining) {
    final value = normalized[key];
    if (value != null && value.isNotEmpty) {
      buffer.write('$key = $value\n');
    }
  }
  return buffer.toString();
}

/// The authoritative INI printer for a served winn/3 control-plane payload.
///
/// Renders the `[winn]` section from [winnFields] and splices it into
/// [baseTemplate] (which carries the device-side Interface/Peer/Wins* sections).
/// Idempotent: rendering a document that already has a rendered `[winn]` section
/// produces a byte-identical document.
String renderWinnIosControlPlaneIni({
  required String baseTemplate,
  required Map<String, String> winnFields,
}) {
  final body = _stripWinnSection(baseTemplate);
  final section = _renderWinnSection(winnFields);
  return body.isEmpty ? section : '$body\n\n$section\n';
}

/// Parses the `[winn]` section back out of an emitted document, for round-trip
/// verification. Keys are lowercased; values are verbatim.
WinnIosControlPlaneParsedIni parseWinnIosControlPlaneIni(String document) {
  final winn = <String, String>{};
  final lines = const LineSplitter().convert(document);
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
  return WinnIosControlPlaneParsedIni(winn);
}

/// Emits a winn/3 control-plane config: renders the full INI through the
/// authoritative printer and gate, returning a delivery payload carrying the
/// full document plus `protocol_version`/`carrier` metadata. A non-winn3
/// carrier is refused so the delivery path can never install a relay config.
WinnIosControlPlaneEmission emitWinnIosControlPlaneConfig({
  required String baseTemplate,
  required Map<String, String> winnFields,
}) {
  final carrier = (winnFields['carrier'] ?? '').trim().toLowerCase();
  if (carrier != kWinnIosControlPlaneCarrier) {
    return WinnIosControlPlaneEmission.refused(<String>['carrier_not_winn3']);
  }
  // The winn/3 Create payload never carries a `protocol` key: protocol version
  // is conveyed out-of-band via the delivery `protocol_version` metadata, and
  // the native Apple parser must never be handed a key it does not recognise
  // (it throws on any key outside its own set). Refuse rather than silently
  // emit, so a served payload that smuggles one can never reach the device.
  for (final key in winnFields.keys) {
    if (key.trim().toLowerCase() == 'protocol') {
      return WinnIosControlPlaneEmission.refused(
        <String>['winn_protocol_key_forbidden'],
      );
    }
  }
  final rendered = renderWinnIosControlPlaneIni(
    baseTemplate: baseTemplate,
    winnFields: winnFields,
  );
  final preflight = preflightWinnIosRawConfig(
    rendered,
    requireDevContainment: false,
  );
  if (!preflight.accepted) {
    return WinnIosControlPlaneEmission.refused(preflight.errors);
  }
  return WinnIosControlPlaneEmission.accepted(WinnIosControlPlaneDelivery(
    protocolVersion: kWinnIosControlPlaneProtocolVersion,
    carrier: kWinnIosControlPlaneCarrier,
    iniDocument: rendered,
  ));
}

class WinnIosControlPlaneDeliveryResult {
  const WinnIosControlPlaneDeliveryResult({
    required this.accepted,
    this.blockedAt,
    this.reason,
  });

  final bool accepted;
  final String? blockedAt;
  final String? reason;
}

/// Delivers an emitted winn/3 config to the native host for installation as a
/// `NETunnelProviderProtocol`. The native side saves the config and never
/// starts the tunnel. No config contents cross back into Dart.
Future<WinnIosControlPlaneDeliveryResult> deliverWinnIosControlPlaneConfig({
  required String baseTemplate,
  required Map<String, String> winnFields,
  String accountScope = '',
  WinnIosRawConfigInvoker invoke = _shippingInvoker,
}) async {
  final emission = emitWinnIosControlPlaneConfig(
    baseTemplate: baseTemplate,
    winnFields: winnFields,
  );
  final delivery = emission.delivery;
  if (!emission.accepted || delivery == null) {
    return WinnIosControlPlaneDeliveryResult(
      accepted: false,
      blockedAt: 'emission',
      reason: emission.errors.join(','),
    );
  }
  try {
    final raw = await invoke(kWinnIosControlPlaneNativeMethod, <String, Object?>{
      ...delivery.toNativeArguments(),
      if (accountScope.isNotEmpty) 'accountScope': accountScope,
    });
    return WinnIosControlPlaneDeliveryResult(
      accepted: raw == true,
      blockedAt: raw == true ? null : 'native_install',
      reason: raw == true ? null : 'not_installed',
    );
  } catch (_) {
    return const WinnIosControlPlaneDeliveryResult(
      accepted: false,
      blockedAt: 'native_install',
      reason: 'native_refused',
    );
  }
}

/// Installs the exact standalone v3 document produced by the shipping Dart
/// dispatcher. The Interface private key is replaced only in its own section
/// with the native Keychain placeholder before the document crosses the
/// MethodChannel; the `[winn]` values are then re-emitted through the same
/// closed-key preflight used by the native provider.
Future<WinnIosControlPlaneDeliveryResult> deliverWinnIosServedTunnelConfig({
  required String rawTunnelConfig,
  String accountScope = '',
  WinnIosRawConfigInvoker invoke = _shippingInvoker,
}) {
  final lines = const LineSplitter().convert(rawTunnelConfig);
  final output = <String>[];
  var inInterface = false;
  var replacedPrivateKey = false;
  for (final line in lines) {
    final trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      inInterface =
          trimmed.substring(1, trimmed.length - 1).trim().toLowerCase() ==
              'interface';
    }
    final equals = trimmed.indexOf('=');
    if (inInterface && equals > 0) {
      final key = trimmed.substring(0, equals).trim().toLowerCase();
      if (key == 'privatekey') {
        if (replacedPrivateKey) {
          return Future<WinnIosControlPlaneDeliveryResult>.value(
            const WinnIosControlPlaneDeliveryResult(
              accepted: false,
              blockedAt: 'emission',
              reason: 'duplicate_interface_privatekey',
            ),
          );
        }
        output.add('PrivateKey = $kWinnIosRawConfigKeychainPlaceholder');
        replacedPrivateKey = true;
        continue;
      }
    }
    output.add(line);
  }
  if (!replacedPrivateKey) {
    return Future<WinnIosControlPlaneDeliveryResult>.value(
      const WinnIosControlPlaneDeliveryResult(
        accepted: false,
        blockedAt: 'emission',
        reason: 'interface_privatekey_missing',
      ),
    );
  }
  final document = output.join('\n');
  return deliverWinnIosControlPlaneConfig(
    baseTemplate: document,
    winnFields: parseWinnIosControlPlaneIni(document).winn,
    accountScope: accountScope,
    invoke: invoke,
  );
}
