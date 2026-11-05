/// DEV-ONLY iOS `raw_config` lab entry point.
///
/// This target is absent from normal builds. It prints stage identifiers only;
/// it never prints the config, endpoint, gateway id, or key material to
/// stdout beyond stage names, but the lab UI itself shows the emitted INI
/// and any preflight errors so an operator can verify what was delivered.
library;

import 'dart:convert';
import 'dart:io' show File, Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'winn_protocol_ios_raw_config.dart';

/// `[winn]` fields whose VALUE is key material (or admission material) and must
/// never be printed or displayed by this harness. The summary reports only
/// their PRESENCE, never their value.
const Set<String> _winnSecretKeys = <String>{
  'static_private',
  'gateway_static',
  'admission_key',
};

/// A redacted, schema-checked summary of one emitted winn/3 control-plane
/// document. Deliberately contains no key value: endpoint/inner/path/mtu are
/// routing facts, and every secret-shaped `[winn]` field is present as a NAME
/// only.
class WinnIosControlPlaneSummary {
  const WinnIosControlPlaneSummary({
    required this.schemaValid,
    this.errors = const <String>[],
    this.protocolVersion = '',
    this.carrier = '',
    this.endpoint = '',
    this.innerV4 = '',
    this.innerRouterV4 = '',
    this.pathMtu = '',
    this.carrierClasses = '',
    this.redactedSecretKeys = const <String>[],
    this.sectionNames = const <String>[],
    this.byteCount = 0,
  });

  /// True only when the authoritive control-plane emitter
  /// ([emitWinnIosControlPlaneConfig]) accepted the rendered document.
  final bool schemaValid;
  final List<String> errors;

  /// Protocol version, carrier and routing facts.
  final String protocolVersion;
  final String carrier;
  final String endpoint;
  final String innerV4;
  final String innerRouterV4;
  final String pathMtu;
  final String carrierClasses;

  /// Secret-shaped `[winn]` field names present in the emitted document, values
  /// redacted. This is the only trace the summary keeps of them.
  final List<String> redactedSecretKeys;

  /// Section names present in the emitted document (e.g. interface, peer, winn).
  final List<String> sectionNames;
  final int byteCount;

  /// JSON-safe, key-material-free snapshot for stdout. Secret fields appear as
  /// `"secret_fields":["static_private",...]`, never with a value.
  Map<String, Object?> toJsonRedacted() => <String, Object?>{
        'schema_valid': schemaValid,
        if (errors.isNotEmpty) 'errors': errors,
        'protocol_version': protocolVersion,
        'carrier': carrier,
        'endpoint': endpoint,
        'inner_v4': innerV4,
        'inner_router_v4': innerRouterV4,
        'path_mtu': pathMtu,
        'carrier_classes': carrierClasses,
        'secret_fields_redacted': redactedSecretKeys,
        'sections': sectionNames,
        'bytes': byteCount,
      };
}

List<String> _sectionNamesIn(String document) {
  final names = <String>[];
  for (final line in const LineSplitter().convert(document)) {
    final trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      final name = trimmed.substring(1, trimmed.length - 1).trim().toLowerCase();
      if (!names.contains(name)) names.add(name);
    }
  }
  return names;
}

/// Emits the winn/3 control-plane bytes for an already-read INI document and
/// answers whether that emission is schema-valid, returning only redacted,
/// key-material-free facts.
///
/// The document carries the device-side sections AND an existing `[winn]`
/// section; the authoritative emitter (`emitWinnIosControlPlaneConfig`) strips
/// and re-renders that `[winn]` from its parsed map, so a `carrier != winn3`
/// document (or one smuggling a `protocol` key) is refused exactly as it would
/// be on the wire.
WinnIosControlPlaneSummary summarizeWinnIosControlPlaneDocument(
  String document,
) {
  final winn = parseWinnIosControlPlaneIni(document).winn;
  final emission = emitWinnIosControlPlaneConfig(
    baseTemplate: document,
    winnFields: winn,
  );
  if (!emission.accepted || emission.delivery == null) {
    return WinnIosControlPlaneSummary(
      schemaValid: false,
      errors: emission.errors,
      sectionNames: _sectionNamesIn(document),
      byteCount: utf8.encode(document).length,
    );
  }
  final delivery = emission.delivery!;
  final emittedWinn = parseWinnIosControlPlaneIni(delivery.iniDocument).winn;
  final redactedKeys = _winnSecretKeys
      .where((key) =>
          emittedWinn.containsKey(key) && (emittedWinn[key] ?? '').isNotEmpty)
      .toList()
    ..sort();
  return WinnIosControlPlaneSummary(
    schemaValid: true,
    protocolVersion: delivery.protocolVersion,
    carrier: delivery.carrier,
    endpoint: emittedWinn['endpoint'] ?? '',
    innerV4: emittedWinn['inner_v4'] ?? '',
    innerRouterV4: emittedWinn['inner_router_v4'] ?? '',
    pathMtu: emittedWinn['path_mtu'] ?? '',
    carrierClasses: emittedWinn['carrier_classes'] ?? '',
    redactedSecretKeys: redactedKeys,
    sectionNames: _sectionNamesIn(delivery.iniDocument),
    byteCount: utf8.encode(delivery.iniDocument).length,
  );
}

String _renderSummary(WinnIosControlPlaneSummary summary) {
  final buffer = StringBuffer()
    ..writeln('schema valid: ${summary.schemaValid}')
    ..writeln(
        'protocol: ${summary.protocolVersion}, carrier: ${summary.carrier}');
  if (summary.errors.isNotEmpty) {
    buffer.writeln('errors: ${summary.errors.join(', ')}');
  }
  if (summary.endpoint.isNotEmpty) {
    buffer.writeln('endpoint: ${summary.endpoint}');
  }
  if (summary.innerV4.isNotEmpty || summary.innerRouterV4.isNotEmpty) {
    buffer.writeln(
        'inner: ${summary.innerV4} -> ${summary.innerRouterV4}');
  }
  if (summary.pathMtu.isNotEmpty) {
    buffer.writeln('path mtu: ${summary.pathMtu} (${summary.carrierClasses})');
  }
  if (summary.sectionNames.isNotEmpty) {
    buffer.writeln('sections: ${summary.sectionNames.join(', ')}');
  }
  if (summary.redactedSecretKeys.isNotEmpty) {
    buffer.writeln(
        'secret fields present (values redacted): '
        '${summary.redactedSecretKeys.join(', ')}');
  }
  buffer.writeln('bytes: ${summary.byteCount}');
  return buffer.toString();
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const RawConfigLabApp());
}

// Public entry for widget tests; the private alias keeps the original name
// working for any existing call sites.
class RawConfigLabApp extends StatelessWidget {
  const RawConfigLabApp({
    super.key,
    this.operatingSystemOverride,
    this.accountScopeOverride,
    this.activeOverride,
    this.configuredPathOverride,
    this.readBytesOverride,
    this.invokeOverride,
  });

  final String? operatingSystemOverride;
  final String? accountScopeOverride;
  final bool? activeOverride;
  final String? configuredPathOverride;
  final Future<List<int>> Function(String path)? readBytesOverride;
  final WinnIosRawConfigInvoker? invokeOverride;

  @override
  Widget build(BuildContext context) => MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ThemeData.dark(useMaterial3: true),
        home: RawConfigLabPage(
          operatingSystemOverride: operatingSystemOverride,
          accountScopeOverride: accountScopeOverride,
          activeOverride: activeOverride,
          configuredPathOverride: configuredPathOverride,
          readBytesOverride: readBytesOverride,
          invokeOverride: invokeOverride,
        ),
      );
}

class RawConfigLabPage extends StatefulWidget {
  const RawConfigLabPage({
    super.key,
    this.operatingSystemOverride,
    this.accountScopeOverride,
    this.activeOverride,
    this.configuredPathOverride,
    this.readBytesOverride,
    this.invokeOverride,
  });

  final String? operatingSystemOverride;
  final String? accountScopeOverride;
  final bool? activeOverride;
  final String? configuredPathOverride;
  final Future<List<int>> Function(String path)? readBytesOverride;
  final WinnIosRawConfigInvoker? invokeOverride;

  @override
  State<RawConfigLabPage> createState() => RawConfigLabPageState();
}

class RawConfigLabPageState extends State<RawConfigLabPage> {
  String _status = 'ready';
  bool _running = false;
  String? _emittedIni;
  String? _errorDetail;
  WinnIosControlPlaneSummary? _summary;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _run());
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() {
      _running = true;
      _status = 'running';
      _emittedIni = null;
      _errorDetail = null;
      _summary = null;
    });
    // Capture the document bytes for display while still delegating all
    // validation and native invoke to the shipping lab function. The wrapper
    // ensures the UI can show the emitted INI even when the test injects a
    // stub read.
    String? capturedDoc;
    Future<List<int>> captureRead(String path) async {
      final List<int> bytes;
      if (widget.readBytesOverride != null) {
        bytes = await widget.readBytesOverride!(path);
      } else {
        bytes = await File(path).readAsBytes();
      }
      try {
        capturedDoc = utf8.decode(bytes);
      } catch (_) {
        capturedDoc = null;
      }
      return bytes;
    }

    final result = await runWinnIosRawConfigLab(
      operatingSystem:
          widget.operatingSystemOverride ?? Platform.operatingSystem,
      accountScope:
          widget.accountScopeOverride ?? kWinnIosRawConfigAccountScope,
      activeOverride: widget.activeOverride,
      configuredPathOverride: widget.configuredPathOverride,
      readBytesOverride: captureRead,
      invoke: widget.invokeOverride ?? _shippingInvokeForTest,
    );
    final status = result.active
        ? (result.accepted
            ? 'native start requested; read provider status before claiming a session'
            : 'blocked at ${result.blockedAt}: ${result.reason}')
        : 'inactive: use a Debug build plus '
            '--dart-define=$kWinnIosRawConfigLabDartDefine=true';
    // Stage identifiers only. No document or key value reaches stdout.
    // ignore: avoid_print
    print('WINN IOS RAW CONFIG LAB: $status');
    if (!mounted) return;
    final captured = capturedDoc;
    setState(() {
      _running = false;
      _status = status;
      if (result.accepted && captured != null) {
        _emittedIni = captured;
        _errorDetail = null;
        // Emit the control-plane bytes and print a schema-valid, redacted
        // summary. Never the document: the summary carries no key material.
        _summary = summarizeWinnIosControlPlaneDocument(captured);
        // ignore: avoid_print
        print('WINN IOS RAW CONFIG SUMMARY: '
            '${const JsonEncoder().convert(_summary!.toJsonRedacted())}');
      } else if (!result.accepted && result.active) {
        _emittedIni = null;
        _summary = null;
        // Surface the structured refusal so widget tests and the operator can
        // see which preflight or native gate fired.
        _errorDetail = result.reason != null
            ? 'blocked at ${result.blockedAt}: ${result.reason}'
            : 'blocked at ${result.blockedAt}';
      } else if (!result.active) {
        _emittedIni = null;
        _summary = null;
        _errorDetail = null;
      } else {
        // accepted == false but no doc: keep error, no INI.
        _emittedIni = null;
        _summary = null;
        _errorDetail = result.reason != null
            ? 'blocked at ${result.blockedAt}: ${result.reason}'
            : null;
      }
    });
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('winn/3 raw config lab')),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: <Widget>[
                  Text(_status,
                      textAlign: TextAlign.center,
                      key: const Key('lab_status')),
                  if (_emittedIni != null) ...<Widget>[
                    const SizedBox(height: 16),
                    SelectableText(
                      _emittedIni!,
                      key: const Key('emitted_ini'),
                    ),
                  ],
                  if (_summary != null) ...<Widget>[
                    const SizedBox(height: 16),
                    SelectableText(
                      _renderSummary(_summary!),
                      key: const Key('schema_summary'),
                    ),
                  ],
                  if (_errorDetail != null) ...<Widget>[
                    const SizedBox(height: 12),
                    Text(
                      _errorDetail!,
                      key: const Key('error_detail'),
                      textAlign: TextAlign.center,
                    ),
                  ],
                  const SizedBox(height: 20),
                  FilledButton(
                    onPressed: _running ? null : _run,
                    child: const Text('Run once'),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
}

// Visible for testing: the default invoke just forwards to the MethodChannel
// via the library's private channel. We expose a thin wrapper so tests can
// inject a fake without needing a MethodChannel mock.
Future<Object?> _shippingInvokeForTest(String method, Object? arguments) async {
  // Defer to the real lab invoker when not overridden. We cannot import the
  // private channel directly, so we invoke through a fresh MethodChannel with
  // the same name; in tests this is intercepted by the test's invokeOverride.
  // In production this channel name matches lib/winn_protocol_ios_raw_config.dart.
  const MethodChannel channel = MethodChannel('wins_vpn/tunnel');
  return channel.invokeMethod<Object?>(method, arguments);
}
