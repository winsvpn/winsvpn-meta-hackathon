import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Contract tests for the user-facing "Prefer TCP fallback" preference
/// (STEALTH-TRANSPORT-ONLY LANE, 2026-08-06).
///
/// Winn v3 and Winn v1 AWG are mandatory lead attempts. The preference pauses
/// optional direct-address latency probes and keeps XRay as the fallback after
/// direct failure; it must never claim or implement TCP-only behavior.
void main() {
  late String source;
  late String connectBody;

  setUpAll(() {
    source = File('lib/main.dart').readAsStringSync();
    final connectStart = source.indexOf(
      'Future<void> _connectWithSmartProtocol(',
    );
    final connectEnd = source.indexOf(
      'Future<void> _toggleVpnConnection() async',
      connectStart,
    );
    expect(connectStart, greaterThanOrEqualTo(0));
    expect(connectEnd, greaterThan(connectStart));
    connectBody = source.substring(connectStart, connectEnd);
  });

  test('the preference is persisted under its own key, not the status mirror',
      () {
    // _isCensorshipModeActive is a status mirror assigned only from a connected
    // config; repurposing it would make a connect silently rewrite the user's
    // stated preference.
    expect(source, contains("data['stealth_transport_only'] = enabled;"));
    expect(
      source,
      contains("_isStealthTransportOnly =\n"
          "            settingsData['stealth_transport_only'] == true;"),
      reason: 'An absent key must load as OFF for every existing install.',
    );
    expect(
      source,
      contains(
          "_isCensorshipModeActive = _boolValue(config['stealth_active'])"),
      reason: 'The status mirror must keep its original single writer.',
    );
    expect(
      source,
      isNot(contains("_isCensorshipModeActive = _isStealthTransportOnly")),
      reason: 'The preference must not be aliased onto the status mirror.',
    );
  });

  test('the preference is written by its own mutator, off the broad snapshot',
      () {
    // Same reasoning as Double VPN: an older queued snapshot must not be able to
    // overwrite a newer, already-durable switch selection.
    final snapshotStart = source.indexOf("data['stealth_active'] =");
    final snapshotEnd = source.indexOf("data['active_protocol_label']");
    expect(snapshotStart, greaterThanOrEqualTo(0));
    expect(snapshotEnd, greaterThan(snapshotStart));
    expect(
      source.substring(snapshotStart, snapshotEnd),
      isNot(contains('stealth_transport_only')),
    );
    expect(
        source,
        contains('_mutateVpnRuntimeSettings((data) {\n'
            "        data['stealth_transport_only'] = enabled;"));
  });

  test('the TCP preference cannot skip the served lead candidate', () {
    expect(
      connectBody,
      contains('shouldAttemptServedLeadCandidate('),
      reason: 'lead selection must use the behavior-tested protocol policy',
    );
    final leadGate = connectBody.indexOf('final attemptLeadCandidate =');
    final leadAttempt = connectBody.indexOf(
      'final directStarted = await attemptDirectAwgCandidate();',
    );
    expect(leadGate, greaterThanOrEqualTo(0));
    expect(leadAttempt, greaterThan(leadGate));
    expect(connectBody, contains('userTcpOnly: false,'));
    expect(
      connectBody,
      isNot(contains(
          'if (stealthTransportOnly && !directCandidateIsWinn3) return false;')),
    );

    expect(connectBody, isNot(contains('directUdpDemotedThisConnect')));
  });

  test('the single commit site attempts AWG before outcome bookkeeping', () {
    final closureStart = connectBody.indexOf(
      'Future<bool> attemptDirectAwgCandidate() async {',
    );
    final closureEnd = connectBody.indexOf('return started;', closureStart);
    expect(closureStart, greaterThanOrEqualTo(0));
    expect(closureEnd, greaterThan(closureStart));
    final closure = connectBody.substring(closureStart, closureEnd);

    expect(closure, isNot(contains('return false;')));
    expect(closure.indexOf('directUdpAttemptedThisConnect = true;'),
        lessThan(closure.indexOf('await _startTunnelCandidate(')));
    expect(closure.indexOf('await _startTunnelCandidate('),
        lessThan(closure.indexOf('await _recordDirectUdpOutcome(')));
  });

  test('connect failure does not claim the direct leg was withheld', () {
    expect(
      connectBody,
      isNot(contains('so the direct route was not tried')),
    );
    expect(source, contains('"Prefer TCP fallback"'));
  });

  test('the switch is retired from the UI while preserving settings contract', () {
    expect(
      source,
      isNot(contains("key: const Key('stealth_transport_only_toggle'),")),
      reason: 'The manual Prefer TCP fallback toggle was retired from UI in favor of dynamic router fallback.',
    );
  });

  test('the preference pauses both optional direct-address latency probes', () {
    final probeStart = source.indexOf(
      'Future<int?> _probeNodeLatencyMs(Map<String, dynamic> node) async',
    );
    final probeEnd = source.indexOf(
      'Future<void> _refreshNodeLatencies(',
      probeStart,
    );
    expect(probeStart, greaterThanOrEqualTo(0));
    expect(probeEnd, greaterThan(probeStart));
    final probeBody = source.substring(probeStart, probeEnd);

    final gate = probeBody.indexOf('if (_isStealthTransportOnly) return null;');
    expect(gate, greaterThanOrEqualTo(0),
        reason: 'the stealth-only early return is missing from '
            '_probeNodeLatencyMs -- the node picker would ping real addresses');

    final ping = probeBody.indexOf('_probePingLatencyMs(');
    final tcp = probeBody.indexOf('_probeTcpLatencyMs(');
    expect(ping, greaterThanOrEqualTo(0));
    expect(tcp, greaterThanOrEqualTo(0));

    expect(gate, lessThan(ping),
        reason: 'the gate must precede the ICMP probe of the direct endpoint');
    expect(gate, lessThan(tcp),
        reason:
            'the gate must ALSO precede the stealth TCP probe -- that probe '
            'is guarded on stealth.host == direct.host, so it targets the '
            "node's real address too; gating only the ping is a partial fix");
  });

  test('changing the preference under a live tunnel is refused, not silent',
      () {
    final setterStart = source.indexOf(
      'Future<void> _setStealthTransportOnly(bool enabled) async {',
    );
    expect(setterStart, greaterThanOrEqualTo(0));
    final setterEnd = source.indexOf(
      '// BUILD-SETTINGS LANE (2026-08-10). Transport-mode helpers.',
      setterStart,
    );
    expect(setterEnd, greaterThan(setterStart));
    final setter = source.substring(setterStart, setterEnd);

    expect(setter, contains('if (_isConnected) {'));
    expect(setter, contains('_showFeedback('));
    // A failed write must not leave the UI claiming a preference that is not on
    // disk -- the next connect would read the old value.
    expect(
      setter,
      contains('if (!await _persistStealthTransportOnly(enabled)) {'),
    );
    final persistCheck =
        setter.indexOf('if (!await _persistStealthTransportOnly(enabled)) {');
    expect(persistCheck, lessThan(setter.indexOf('setState(() {')));
  });
}
