/// Winn Protocol v3 -- WEB control-plane `[winn]` config PARSED-JSON emission
/// (pure-Dart CLI, runnable with a bare `dart run`).
///
/// Resolves a served winn/3 config through the authoritative served-config gate
/// (`lib/winn_protocol_web_control_plane.dart`), reads the emitted `[winn]`
/// section back through the shared `[winn]` parser, and prints the PARSED
/// `[winn]` config as JSON to stdout with every secret-field VALUE already
/// replaced by `<redacted>`. It starts no tunnel, opens no network socket, and
/// touches nothing beyond the input file and the lane scratch dir.
///
/// Usage (from source/wins_vpn):
///   `dart run lib/winn_protocol_web_control_plane_main.dart [configPath]`
///
/// [configPath] is an optional JSON file holding a served winn/3 config (the
/// shape `lib/winn_protocol_dev_config_source.dart` loads). When omitted, a
/// loopback-only DEV fixture is used. Refusal is reported on stdout as JSON
/// with the gate's reason codes (never config values) and exit 3.
///
/// The emitted `[winn]` document and the parsed/redacted JSON are also written
/// under `.spark_lanes/scratch/gen_ios_web_cp_main/`, and the parsed `[winn]`
/// map is validated against the raw-config parser by
/// `test/winn_protocol_web_control_plane_main_validation_test.dart`.
library;

import 'dart:convert';
import 'dart:io' show Directory, File, exit, stderr, stdout;

import 'winn_protocol_dispatch.dart';
import 'winn_protocol_web_control_plane.dart';

/// Lane scratch dir for the emitted artifacts (gitignored, never a release
/// path).
const String _scratchDir = '.spark_lanes/scratch/gen_ios_web_cp_main';

void main(List<String> args) {
  final Map<String, dynamic> config;
  if (args.isNotEmpty) {
    final inputPath = args.first;
    final input = File(inputPath);
    if (!input.existsSync()) {
      stderr.writeln('no such file: $inputPath');
      exit(2);
    }
    try {
      final decoded = jsonDecode(input.readAsStringSync());
      if (decoded is! Map) {
        stderr.writeln('$inputPath must contain a JSON object');
        exit(2);
      }
      config = Map<String, dynamic>.from(decoded);
    } catch (error) {
      stderr.writeln('could not read/parse $inputPath: $error');
      exit(2);
    }
  } else {
    config = _defaultDevConfig();
  }

  final emission = emitWinnProtocolWebControlPlane(
    config: config,
    log: stderr.writeln,
  );

  if (!emission.accepted) {
    // Refusal: reason codes only, never config values, never key material.
    stdout.writeln(jsonEncode(<String, dynamic>{
      'accepted': false,
      'errors': emission.errors,
    }));
    exit(3);
  }

  final iniDocument = emission.iniDocument!;
  final parsed = parseWinnWinnSection(iniDocument);
  final redacted = redactWinnWinnSection(parsed);

  final output = <String, dynamic>{
    'accepted': true,
    'protocol_version': emission.protocolVersion,
    'carrier': emission.carrier,
    'winn': redacted,
  };

  stdout.writeln(jsonEncode(output));

  try {
    final dir = Directory(_scratchDir);
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
    }
    File('${dir.path}/emitted_winn.ini').writeAsStringSync(iniDocument);
    File('${dir.path}/emitted_winn_parsed.json')
        .writeAsStringSync(jsonEncode(output));
    stderr
        .writeln('wrote ${dir.path}/emitted_winn.ini and '
            '${dir.path}/emitted_winn_parsed.json');
  } catch (error) {
    stderr.writeln('could not write lane deliverables: $error');
  }
}

/// Loopback-only DEV fixture in the shape the served-config gate resolves, so
/// a bare run has something honest to emit. Public keys only; no private-key
/// material in the fixture itself.
Map<String, dynamic> _defaultDevConfig() => <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{},
      'server_endpoint': '127.0.0.1:51820',
      'client_ip': '10.99.0.2',
      'client_private_key': '<REDACTED_WG_KEY>',
      'client_public_key': '<REDACTED_WG_KEY>',
      'server_public_key': '<REDACTED_WG_KEY>',
      'mtu': 1280,
      'dns': '10.99.0.1',
      'stealth_active': false,
      'obfuscation': <String, dynamic>{
        'H1': 11,
        'H2': 22,
        'H3': 33,
        'H4': 44,
      },
    };