// Hoppy corpus gate - Dart mirror of models/hoppy/agent/gate.py
// Authority: docs/design/HOPPY_AGENT_V1_20260811.md em dash rule
// This file is the importable Dart probe for the red-team harness.
// It must agree byte-for-byte with the Python gate on what counts as a violation.

/// Returns true if text contains U+2014, U+2013, or spaced double hyphen.
bool hoppyContainsViolation(String text) {
  if (text.contains('\u2014')) return true;
  if (text.contains('\u2013')) return true;
  if (text.contains(' -- ')) return true;
  // Regex: whitespace, --, then whitespace or end
  final re = RegExp(r'\s--(\s|$)');
  if (re.hasMatch(text)) return true;
  return false;
}

/// Returns a reason string or null if clean.
String? hoppyViolationReason(String text) {
  if (text.contains('\u2014')) return 'U+2014 EM DASH';
  if (text.contains('\u2013')) return 'U+2013 EN DASH';
  if (text.contains(' -- ') || RegExp(r'\s--(\s|$)').hasMatch(text)) {
    return 'spaced double hyphen';
  }
  return null;
}

/// Probe for sampled model output. Returns true if output passes (no violation).
bool hoppyProbeOutput(String text) => !hoppyContainsViolation(text);

/// Check a single row map. Returns list of violation descriptors.
List<String> hoppyCheckRow(Map<String, dynamic> row) {
  final violations = <String>[];
  final rid = (row['id'] ?? row['sample_id'] ?? row['row_id'] ?? 'unknown').toString();
  const scanKeys = ['user', 'assistant', 'system', 'content', 'text', 'output', 'completion'];
  for (final key in scanKeys) {
    final val = row[key];
    if (val is String) {
      final reason = hoppyViolationReason(val);
      if (reason != null) violations.add('$rid:$key:$reason');
    }
  }
  final messages = row['messages'];
  if (messages is List) {
    for (var i = 0; i < messages.length; i++) {
      final msg = messages[i];
      if (msg is Map) {
        final content = msg['content'];
        if (content is String) {
          final reason = hoppyViolationReason(content);
          if (reason != null) violations.add('$rid:messages[$i].content:$reason');
        }
      }
    }
  }
  for (final entry in row.entries) {
    if (scanKeys.contains(entry.key) || entry.key == 'messages' || entry.key == 'expected_action') continue;
    final v = entry.value;
    if (v is String) {
      final reason = hoppyViolationReason(v);
      if (reason != null) violations.add('$rid:${entry.key}:$reason');
    }
  }
  return violations;
}
