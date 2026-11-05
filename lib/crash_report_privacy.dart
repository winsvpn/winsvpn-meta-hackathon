// Crash-report privacy subsystem.
//
// Threat model: this is a censorship-circumvention app for users in Myanmar,
// and the device may be searched. An automatic crash upload is a disclosure
// channel: a crash triggered while the tunnel is up can carry the endpoint
// address, configuration keys, an account number or the app-install identifier.
// For that reason there is deliberately NO third-party crash SDK anywhere in
// this tree, and the only crash-reporting machinery that exists is this file.
//
// Two properties are enforced structurally, not by convention:
//
//  1. Redaction happens at the capture boundary. The raw exception text and
//     stack trace are scrubbed BEFORE anything is returned, persisted or
//     handed to a transport. Nothing in this file ever retains, logs or
//     forwards the un-redacted failure text.
//
//  2. Upload requires explicit, revocable consent and FAILS CLOSED. The
//     consent record is a single marker file in app-private storage; a
//     missing, unreadable, oversized or stale-tagged file means "no". The
//     transport is only ever called by [uploadCrashReportIfConsented], which
//     refuses before calling it when consent is absent. Nothing calls that
//     function automatically today, and no adapter exists to call it with.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:ui' show PlatformDispatcher;

import 'package:flutter/foundation.dart' show FlutterError, FlutterErrorDetails;

const String kCrashReportSchemaVersion = '1';

const String kCrashReportConsentFileName = 'crash_report_consent.txt';

const int kCrashReportTextLimit = 10000;

/// A single scrubbing rule, kept in a list so a test can assert that every
/// rule exists AND fires on its own needle. A rule that is deleted, or whose
/// needle stops matching, makes that assertion fail -- this is the negative
/// control the rest of the catalogue says is usually missing.
class CrashRedactionRule {
  const CrashRedactionRule({
    required this.name,
    required this.tag,
    required this.pattern,
  });

  final String name;
  final String tag;
  final RegExp pattern;
}

/// The ordered rule set applied to a crash payload.
///
/// Order matters: the URL rule consumes `scheme://user:pass@host:port/path`
/// whole, so a credential embedded in a URI cannot survive to the later
/// standalone-credential rule; the POSIX-path rule runs before the host
/// regexes so path segments are not re-scanned; IPv6 is checked functionally
/// (see [_redactIpv6Candidate]) so timestamps are never misclassified as
/// addresses.
final List<CrashRedactionRule> kCrashRedactionRules = <CrashRedactionRule>[
  CrashRedactionRule(
    name: 'url',
    tag: '<url>',
    pattern: RegExp(
      r'\b[a-z][a-z0-9+.-]{1,31}://[^\s,;]+',
      caseSensitive: false,
    ),
  ),
  CrashRedactionRule(
    name: 'credential',
    tag: '<credential>',
    pattern: RegExp(
      r'(?<![A-Za-z0-9._-])[^\s:@/]+:[^\s@/]+@[A-Za-z0-9.-]+(?::\d{1,5})?',
      caseSensitive: false,
    ),
  ),
  CrashRedactionRule(
    name: 'winpath',
    tag: '<path>',
    pattern: RegExp(r'[A-Za-z]:\\[^\s,;]+', caseSensitive: false),
  ),
  CrashRedactionRule(
    name: 'posix_path',
    tag: '<path>',
    pattern: RegExp(r'(?<![A-Za-z0-9])/(?:[^/\s,;]+/)+[^/\s,;]+'),
  ),
  CrashRedactionRule(
    name: 'ipv6',
    tag: '<ip>',
    // Never ends in '.', or a sentence period after an address makes the
    // candidate unparseable and the address is kept (diagnostic_redaction.dart).
    pattern: RegExp(
      r'(?<![A-Za-z0-9])\[?[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*[0-9A-Fa-f:](?:%[A-Za-z0-9_.-]*[A-Za-z0-9_-])?\]?(?::\d{1,5})?(?![A-Za-z0-9])',
    ),
  ),
  CrashRedactionRule(
    name: 'ipv4',
    tag: '<ip>',
    pattern: RegExp(r'(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?'),
  ),
  CrashRedactionRule(
    name: 'host_port',
    tag: '<host>',
    pattern: RegExp(
      r'(?<![A-Za-z0-9_./-])(?:localhost|[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}):\d{1,5}(?!\d)',
      caseSensitive: false,
    ),
  ),
  CrashRedactionRule(
    name: 'email',
    tag: '<email>',
    pattern: RegExp(
      r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![A-Za-z0-9._%+-])',
    ),
  ),
  CrashRedactionRule(
    name: 'account_dashed',
    tag: '<account>',
    pattern: RegExp(r'\b\d{4}-\d{4}-\d{4}\b'),
  ),
  CrashRedactionRule(
    name: 'account_plain',
    tag: '<account>',
    pattern: RegExp(r'(?<![0-9])\d{12}(?![0-9])'),
  ),
  CrashRedactionRule(
    name: 'uuid',
    tag: '<id>',
    pattern: RegExp(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}\b'),
  ),
  CrashRedactionRule(
    name: 'mac_address',
    tag: '<id>',
    pattern:
        RegExp(r'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])'),
  ),
  CrashRedactionRule(
    name: 'hex64_key',
    tag: '<key>',
    pattern: RegExp(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])'),
  ),
  CrashRedactionRule(
    name: 'jwt',
    tag: '<token>',
    pattern: RegExp(
      r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,})?(?![A-Za-z0-9_-])',
    ),
  ),
  CrashRedactionRule(
    name: 'base64_key',
    tag: '<key>',
    pattern: RegExp(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42,44}={0,2}(?![A-Za-z0-9+/])'),
  ),
  CrashRedactionRule(
    name: 'long_token',
    tag: '<key>',
    pattern: RegExp(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43,86}(?![A-Za-z0-9_-])'),
  ),
  // The app-install identifier is base64Url (32 chars today) and nothing in the
  // old tunnel-failure rules covered a 24-42 char base64url run that has no
  // dot and no padding. Require at least one digit so long camelCase class
  // names (pure letters) survive into the triage record while identifiers do
  // not. See _loadOrCreateInstallId in main.dart.
  CrashRedactionRule(
    name: 'install_id',
    tag: '<id>',
    pattern: RegExp(
      r'(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{24,42}(?![A-Za-z0-9_-])',
    ),
  ),
  // The on-the-wire device identifier is `INSTALL-<32-char base64url>` (see
  // _loadOrCreateInstallId in main.dart). The digit requirement on install_id
  // exists so long camelCase class names survive into triage, but a base64url
  // install id can legitimately be all letters (~0.4% of draws), in which case
  // the digit-gated rule misses it. The `INSTALL-` prefix cannot appear in a
  // class name, so it is a precise anchor that closes that gap without
  // re-opening the over-redaction one. Case-sensitive: the app emits it in
  // uppercase.
  CrashRedactionRule(
    name: 'device_id_install',
    tag: '<id>',
    pattern: RegExp(
      r'(?<![A-Za-z0-9_-])INSTALL-[A-Za-z0-9_-]{24,42}(?![A-Za-z0-9_-])',
    ),
  ),
  // Last on purpose: it must run after the email, jwt and key rules, which
  // contain dots and would otherwise be partly consumed as hostnames.
  CrashRedactionRule(
    name: 'bare_hostname',
    tag: '<host>',
    pattern: RegExp(
      r"(?<![A-Za-z0-9_.@/-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])",
    ),
  ),
];

class CrashScrubResult {
  const CrashScrubResult({
    required this.redacted,
    required this.replacedByTag,
    required this.truncated,
  });

  final String redacted;
  final Map<String, int> replacedByTag;
  final bool truncated;
}

/// Scrub a raw crash payload (exception message + stack trace) before anything
/// can leave the process. This is the ONLY place raw failure text is handled.
///
/// Returns the scrubbed text and, for tests and operator triage, a map of tag
/// to replacement count. The returned text is always safe to persist or
/// transmit; callers never see the raw text.
CrashScrubResult redactCrashReport(
  String raw, {
  int maximumLength = kCrashReportTextLimit,
}) {
  final replacedByTag = <String, int>{};
  var value = raw.replaceAll('\r\n', '\n').replaceAll('\r', '\n');

  for (final rule in kCrashRedactionRules) {
    final matches = rule.pattern.allMatches(value).toList();
    if (matches.isEmpty) continue;
    final spans = <_ReplacementSpan>[];
    for (final match in matches) {
      if (rule.name == 'ipv6' && !_redactIpv6Candidate(match.group(0)!)) {
        continue;
      }
      spans.add(_ReplacementSpan(match.start, match.end, rule.tag));
    }
    if (spans.isEmpty) continue;
    replacedByTag.update(rule.tag, (count) => count + spans.length,
        ifAbsent: () => spans.length);
    value = _applyReplacements(value, spans);
  }

  var truncated = false;
  if (value.length > maximumLength) {
    value = value.substring(0, maximumLength);
    truncated = true;
  }
  if (value.trim().isEmpty) value = 'unspecified_crash';

  return CrashScrubResult(
    redacted: value,
    replacedByTag: replacedByTag,
    truncated: truncated,
  );
}

class _ReplacementSpan {
  const _ReplacementSpan(this.start, this.end, this.replacement);

  final int start;
  final int end;
  final String replacement;
}

String _applyReplacements(String value, List<_ReplacementSpan> spans) {
  if (spans.isEmpty) return value;
  // Apply from the end backwards so earlier offsets stay valid.
  spans.sort((a, b) => b.start.compareTo(a.start));
  var result = value;
  for (final span in spans) {
    result = result.substring(0, span.start) +
        span.replacement +
        result.substring(span.end);
  }
  return result;
}

bool _redactIpv6Candidate(String raw) {
  var candidate = raw;
  if (candidate.startsWith('[')) {
    final closingBracket = candidate.indexOf(']');
    if (closingBracket <= 1) return false;
    candidate = candidate.substring(1, closingBracket);
  } else {
    final lastColon = candidate.lastIndexOf(':');
    if (lastColon > 0 && candidate.indexOf(':') != lastColon) {
      final potentialPort = candidate.substring(lastColon + 1);
      if (int.tryParse(potentialPort) != null) {
        final withoutPort = candidate.substring(0, lastColon);
        if (InternetAddress.tryParse(withoutPort)?.type == InternetAddressType.IPv6) {
          return true;
        }
      }
    }
  }
  final zoneIndex = candidate.indexOf('%');
  if (zoneIndex >= 0) candidate = candidate.substring(0, zoneIndex);
  final address = InternetAddress.tryParse(candidate);
  return address?.type == InternetAddressType.IPv6;
}

/// Explicit-consent gate for crash-report UPLOAD. Fail-closed by construction:
/// the marker must exist, be small, and read exactly as the granted marker,
/// or the gate reports no consent. Revocation deletes the marker.
class CrashReportConsentGate {
  CrashReportConsentGate(this.consentFile);

  final File consentFile;

  static const String grantedMarker = 'granted';
  static const int kMaxConsentFileBytes = 128;

  Future<bool> isExplicitlyGranted() async {
    try {
      if (!await consentFile.exists()) return false;
      final length = await consentFile.length();
      if (length < 3 || length > kMaxConsentFileBytes) return false;
      final content = (await consentFile.readAsString()).trim();
      return content == grantedMarker;
    } on Object {
      return false;
    }
  }

  Future<void> grantExplicitly() async {
    await consentFile.parent.create(recursive: true);
    final random = Random.secure();
    final tmp = File(
      '${consentFile.path}.tmp.${random.nextInt(1 << 32).toRadixString(16)}',
    );
    try {
      await tmp.writeAsString('$grantedMarker\n', flush: true);
      await tmp.rename(consentFile.path);
    } on Object {
      if (await tmp.exists()) {
        try {
          await tmp.delete();
        } on Object {
          // Best effort; a stale tmp marker is inert anyway.
        }
      }
      rethrow;
    }
  }

  Future<void> revoke() async {
    if (await consentFile.exists()) {
      await consentFile.delete();
    }
  }
}

/// The error thrown when an upload is attempted without explicit consent.
/// Callers must treat this as a normal, expected outcome, not a defect.
class CrashReportUploadRefused implements Exception {
  const CrashReportUploadRefused();

  @override
  String toString() => 'crash-report upload refused: no explicit consent';
}

/// Upload a crash report through [transport], but ONLY if the consent gate
/// grants it. When consent is absent the transport is never called and
/// [CrashReportUploadRefused] is thrown. This is the single control point for
/// "no automatic upload without consent"; nothing else in the app calls a
/// transport.
Future<void> uploadCrashReportIfConsented({
  required CrashReportConsentGate consent,
  required String redactedReport,
  required Future<void> Function(String redactedReport) transport,
}) async {
  if (!await consent.isExplicitlyGranted()) {
    throw const CrashReportUploadRefused();
  }
  await transport(redactedReport);
}

/// The pipeline the app uses: [CrashReportCapture.capture] scrubs the raw
/// payload, persists ONLY the scrubbed record locally, and -- only when an
/// optional transport is supplied AND consent is granted -- forwards the
/// scrubbed record through it. The raw payload never reaches either sink.
///
/// The local record is written the same way every other piece of local state
/// is written here: app-private storage only, via the [reportDirectory] the
/// app hands in (main.dart's `_appDocumentsDirectory`). Hashing or encrypting
/// the file adds nothing: it contains no identifier, and the transport gate is
/// separate, so the file is not the disclosure channel.
class CrashReportCapture {
  CrashReportCapture({
    required this.reportDirectory,
    required this.consentGate,
    this.transport,
    this.appVersion,
    this.platformName,
  });

  final Directory reportDirectory;
  final CrashReportConsentGate consentGate;
  final Future<void> Function(String redactedRecord)? transport;
  final String? appVersion;
  final String? platformName;

  /// Capture a crash, writing a scrubbed record to app-private storage and
  /// forwarding it ONLY on explicit consent. Returns the scrubbed result.
  ///
  /// Never throws into an error handler: any persistence or transport failure
  /// is swallowed (the caller is usually inside the platform error sink, where
  /// an exception would itself crash the process). The pure scrubbing core
  /// cannot fail.
  Future<CrashScrubResult> capture(
    Object error,
    StackTrace stackTrace,
  ) async {
    final exceptionText = error.toString();
    final stackText = stackTrace.toString();
    final result = redactCrashReport('$exceptionText\n$stackText');
    try {
      final record = _buildRecord(result, exceptionText, stackTrace);
      await _writeRecord(record);
    } on Object {
      // Capture is best-effort; a disposable redacted record is not worth a
      // second crash.
    }
    final transport = this.transport;
    if (transport != null) {
      try {
        final record = _buildRecord(result, exceptionText, stackTrace);
        await uploadCrashReportIfConsented(
          consent: consentGate,
          redactedReport: record,
          transport: transport,
        );
      } on Object {
        // Consent absent or transport failed; swallowed. The local scrubbed
        // record still exists, and the caller's UI path continues.
      }
    }
    return result;
  }

  String _buildRecord(CrashScrubResult result, String exceptionText,
      StackTrace stackTrace) {
    final exceptionType =
        exceptionText.contains(':') ? exceptionText.split(':').first : exceptionText;
    final record = <String, dynamic>{
      'schema': kCrashReportSchemaVersion,
      'captured_at': DateTime.now().toUtc().toIso8601String(),
      if (platformName != null) 'platform': platformName,
      if (appVersion != null) 'app_version': appVersion,
      'exception_type': redactCrashReport(exceptionType).redacted,
      'redacted_crash_text': result.redacted,
      if (result.truncated) 'truncated': true,
    };
    return const JsonEncoder.withIndent('  ').convert(record);
  }

  Future<void> _writeRecord(String record) async {
    final directory = Directory('${reportDirectory.path}/crash_reports');
    await directory.create(recursive: true);
    final random = Random.secure();
    final nonce = random.nextInt(1 << 32).toRadixString(16).padLeft(8, '0');
    final file = File(
      '${directory.path}/crash-${DateTime.now().millisecondsSinceEpoch}-$nonce.txt',
    );
    await file.writeAsString(record, flush: true);
  }
}

/// Convenience: consent gate rooted at the app-private [reportDirectory].
CrashReportConsentGate crashReportConsentGateAt(Directory reportDirectory) {
  return CrashReportConsentGate(
    File('${reportDirectory.path}/$kCrashReportConsentFileName'),
  );
}

/// Directory provider for the global crash sink. The app sets this once it
/// knows its documents directory (main.dart `_appDocumentsDirectory`); until
/// then the sink redacts and drops, which is safe (no leak, no identity).
Directory? globalCrashReportDirectory;

void _fireAndForget(Future<void> future) {
  // Private helper named to avoid colliding with dart:async's `unawaited`,
  // which main.dart uses with a nullable-argument signature.
  // ignore: unawaited_futures
  future.then<void>((_) {}, onError: (Object _) {});
}

/// Install the platform-level error sinks so an unhandled Dart error is
/// reduced to a scrubbed, harmless record instead of raw text. The previous
/// handlers are preserved and chained; the framework's own behaviour (red
/// screen in debug, error channel in release) is unchanged.
///
/// In tests this is installed with a null [transport] so it can be exercised
/// without any network path existing.
void installPrivacySafeCrashSink({
  Future<void> Function(String redactedRecord)? transport,
  bool resetHandlers = true,
}) {
  if (!resetHandlers) return;

  final previousOnError = PlatformDispatcher.instance.onError;
  PlatformDispatcher.instance.onError = (Object error, StackTrace stack) {
    _globalCaptureDispatch(error, stack, transport);
    final safeError =
        FlutterError(redactCrashReport(error.toString()).redacted);
    final safeStack = StackTrace.fromString(
        redactCrashReport(stack.toString()).redacted);
    previousOnError?.call(safeError, safeStack);
    return true;
  };

  final previousFlutterOnError = FlutterError.onError;
  FlutterError.onError = (FlutterErrorDetails details) {
    _globalCaptureDispatch(
      details.exception,
      details.stack ?? StackTrace.empty,
      transport,
    );
    previousFlutterOnError?.call(FlutterErrorDetails(
      exception: FlutterError(
          redactCrashReport(details.exception.toString()).redacted),
      stack: StackTrace.fromString(
          redactCrashReport(
              (details.stack ?? StackTrace.empty).toString()).redacted),
      library: details.library == null
          ? null
          : redactCrashReport(details.library!).redacted,
      silent: details.silent,
    ));
  };
}

void _globalCaptureDispatch(
  Object error,
  StackTrace stackTrace,
  Future<void> Function(String redactedRecord)? transport,
) {
  final directory = globalCrashReportDirectory;
  if (directory == null) {
    // No safe directory available yet: run the pure redactor so the handler
    // still does its only mandatory job (no raw text escapes as a side
    // effect), and drop the record. Never touch disk here.
    redactCrashReport('${error.toString()}\n${stackTrace.toString()}');
    return;
  }
  _fireAndForget(
    CrashReportCapture(
      reportDirectory: directory,
      consentGate: crashReportConsentGateAt(directory),
      transport: transport,
    ).capture(error, stackTrace),
  );
}