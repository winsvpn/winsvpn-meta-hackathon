/// Winn Protocol v3 -- DEV-ONLY, NON-SHIPPING Flutter ENTRY POINT.
///
/// This file exists so that `lib/winn_protocol_dev_session.dart` has a caller
/// that is not `lib/main.dart`.
///
/// # Why a separate entry point, and not a debug branch in `lib/main.dart`
///
/// `test/winn_protocol_refusal_guard_test.dart` pins EXACTLY ONE
/// `case kWinnProtocolV3:` dispatch point in `lib/main.dart`, precisely so a
/// second, more permissive path cannot be added there. A debug-only branch in
/// that file would be that second path in spirit even where it passed the
/// guard's literal text, and `lib/main.dart` is release-frozen at 1.0.14+29
/// (in store review) and concurrently edited. So this path is reached the way
/// Flutter already supports reaching an alternative program in the same app:
///
/// ```
/// flutter run -d macos \
///   --target=lib/winn_protocol_dev_session_main.dart \
///   --dart-define=WINN_DEV_SESSION=true \
///   --dart-define=WINN_DEV_UNSAFE_MACOS_OVERRIDE=true \
///   --dart-define=WINN_DEV_CONFIG_PATH=/absolute/path/to/dev_winn3.json
/// ```
///
/// On iOS the same entry point is used, with the iOS-specific define and a
/// container-relative config path -- the app container's path is not knowable
/// from this Mac, so an absolute one cannot be written down (see
/// `kWinnDevConfigContainerScheme`). Push the file first:
///
/// ```
/// tools/push_ios_winn_dev_config.sh ./dev_winn3_ios.json
/// flutter run -d <device-udid> \
///   --target=lib/winn_protocol_dev_session_main.dart \
///   --dart-define=WINN_DEV_SESSION=true \
///   --dart-define=WINN_DEV_UNSAFE_IOS_OVERRIDE=true \
///   --dart-define=WINN_DEV_CONFIG_PATH=container:dev_winn3_ios.json
/// ```
///
/// On Windows the same entry point is used again, with the Windows define, an
/// absolute path (the Windows app is not sandboxed), and one EXTRA
/// acknowledgement that neither Apple platform needs:
///
/// ```
/// flutter run -d windows ^
///   --target=lib/winn_protocol_dev_session_main.dart ^
///   --dart-define=WINN_DEV_SESSION=true ^
///   --dart-define=WINN_DEV_UNSAFE_WINDOWS_OVERRIDE=true ^
///   --dart-define=WINN_DEV_UNSAFE_UNCONTAINED_ACK=UNCONTAINED_FULL_TUNNEL_ON_A_DISPOSABLE_VM ^
///   --dart-define=WINN_DEV_CONFIG_PATH=C:\q\dev_winn3_windows.json
/// ```
///
/// The acknowledgement is required because Windows CANNOT contain a session:
/// its privileged service has no narrow-route mode, refuses the
/// `[WinsDevContainment]` section outright, and installs /1 precommit routes
/// before convergence. See `kWinnDevSessionWindowsContainmentAbsenceRationale`.
/// Run it on a disposable VM only.
///
/// A Windows run also needs, beside `wins_vpn.exe` in the SAME directory:
/// `winn-datapath.exe`, `winsvpn_awg_engine.exe`, `awg.exe`, `wintun.dll`, and
/// the LocalSystem service registered from that directory
/// (`wins_vpn_tunnel_service.exe --install`, elevated). Any one missing is a
/// refusal, not a degraded start.
///
/// The macOS, iOS and Windows overrides are SEPARATE dart-defines on purpose: a
/// build that opened macOS has not opened iOS or Windows.
///
/// `--target` changes only which Dart program runs; the macOS Runner, its
/// `MainFlutterWindow`, the `wins_vpn/tunnel` channel
/// (`macos/Runner/MainFlutterWindow.swift:626`), the App Group, the Keychain
/// and the Packet Tunnel appex are all the SHIPPING ones, unchanged. That is
/// the entire point: the session runs through the real native stack, not a
/// harness.
///
/// # This is a third gate, and the strongest one
///
/// A normal `flutter build macos` compiles `lib/main.dart`. Nothing reachable
/// from `lib/main.dart` imports this file or
/// `lib/winn_protocol_dev_session.dart`, so Dart's whole-program compilation
/// leaves both entirely OUT of a shipping binary -- absent, not merely
/// disabled. `kWinnDevSessionAbsenceProbeString` makes that mechanically
/// checkable with `strings`. On top of that, `winnDevSessionActive` still
/// requires `kDebugMode` AND `--dart-define=WINN_DEV_SESSION=true`, so even a
/// release archive deliberately built against this target would refuse.
///
/// DEVELOPMENT SIGNING ONLY.
library;

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter/material.dart';

import 'winn_protocol_dev_session.dart';
import 'winn_protocol_dev_session_traffic.dart';

/// The single contained /32 to aim traffic at, e.g. `10.99.0.1`. Empty (the
/// default) runs the session exactly as before and sends nothing.
///
/// This is a dart-define rather than a derived value so that pointing the
/// harness somewhere is always a deliberate act by whoever launches it. It is
/// still not trusted: [_WinnDevSessionPageState._runTraffic] refuses to send
/// unless the PROVIDER's own readback says containment is active and is
/// exactly one route of prefix length 32.
const String kWinnDevTrafficTarget =
    String.fromEnvironment('WINN_DEV_TRAFFIC_TARGET');

/// Seconds of steady traffic. The default spans four 120 s AmneziaWG rekey
/// intervals, so rekey survival is observable rather than assumed.
const int kWinnDevTrafficSeconds =
    int.fromEnvironment('WINN_DEV_TRAFFIC_SECONDS', defaultValue: 480);

const int kWinnDevTrafficPort =
    int.fromEnvironment('WINN_DEV_TRAFFIC_PORT', defaultValue: 7777);

/// Steady-phase datagrams per second. Defaults to the historical hard-coded
/// 12/s, so a run that does not set this behaves exactly as every run before
/// this knob existed.
///
/// Raising it is an ENVIRONMENTAL accommodation, not a datapath change: an
/// 802.11 far end with `Power save: on` sleeps between beacons, so a 12/s
/// stream (83 ms gaps, against a 102.4 ms beacon interval) is delivered
/// unreliably while a faster stream keeps the peer's radio awake. Measured
/// VPN-free over the lab link: 12/s lost 0.83%, 100/s lost 0.00%.
const int kWinnDevTrafficRate =
    int.fromEnvironment('WINN_DEV_TRAFFIC_RATE', defaultValue: 12);

/// Post-rekey burst datagrams per second. `0` (the default) keeps the historical
/// unpaced burst, which fires ~3900/s and overruns the sender's own transmit
/// queue. Set it to pace the burst when the complete ordered digest matters.
const int kWinnDevTrafficBurstRate =
    int.fromEnvironment('WINN_DEV_TRAFFIC_BURST_RATE', defaultValue: 0);

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const _WinnDevSessionApp());
}

class _WinnDevSessionApp extends StatelessWidget {
  const _WinnDevSessionApp();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Winn dev session (NOT the Win\'s VPN app)',
      theme: ThemeData.dark(useMaterial3: true),
      home: const _WinnDevSessionPage(),
    );
  }
}

class _WinnDevSessionPage extends StatefulWidget {
  const _WinnDevSessionPage();

  @override
  State<_WinnDevSessionPage> createState() => _WinnDevSessionPageState();
}

class _WinnDevSessionPageState extends State<_WinnDevSessionPage> {
  final List<String> _lines = <String>[];
  bool _running = false;
  WinnDevSessionResult? _result;

  @override
  void initState() {
    super.initState();
    // Auto-run once, so a session is drivable from a script and its complete
    // transcript lands on stdout, rather than depending on someone clicking.
    // The button below re-runs it. This changes nothing about the gate: an
    // inactive build auto-runs straight into `active: false`.
    WidgetsBinding.instance.addPostFrameCallback((_) => _run());
  }

  void _log(String message) {
    // Also to stdout, so `flutter run`'s console is a complete transcript even
    // if the window is never looked at.
    // ignore: avoid_print
    print(message);
    if (!mounted) return;
    setState(() => _lines.add(message));
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() {
      _running = true;
      _lines.clear();
      _result = null;
    });
    _log('kDebugMode=$kDebugMode '
        '$kWinnDevSessionDartDefineName=$kWinnDevSessionDartDefineValue '
        'winnDevSessionActive=$winnDevSessionActive '
        'probe=$kWinnDevSessionAbsenceProbeString');
    final result = await runWinnDevSession(
      operatingSystem: Platform.operatingSystem,
      log: _log,
    );
    if (!result.active) {
      _log('WINN DEV SESSION: inactive. This build is not both a debug build '
          'AND launched with --dart-define=$kWinnDevSessionDartDefineName=true, '
          'so nothing was attempted. This is the correct outcome for every '
          'build that is not a deliberate dev session.');
    } else if (result.blockedAt != null) {
      _log('WINN DEV SESSION: RESULT = BLOCKED at ${result.blockedAt}. '
          'This is a real outcome, not a failure of the wiring.');
      if (result.blockedAt == 'containment_unverified') {
        _log('WINN DEV SESSION: the provider did not confirm containment, so '
            'this run asked native to stop the tunnel '
            '(torndown=${result.torndownBecauseUncontained}). Check the VPN is '
            'off in system settings before retrying.');
      }
    } else {
      // The success line must not claim containment on a platform that has no
      // containment path. Before 2026-08-06 it did: three real Linux sessions
      // printed "containment confirmed by the provider" four lines after the
      // harness had correctly said the session carries no [WinsDevContainment]
      // section and will not be contained. Nothing behaved wrongly -- the
      // transcript simply contradicted itself, which is worse than saying less.
      if (winnDevSessionPlatformCanContain(Platform.operatingSystem) &&
          !winnDevSessionUncontainedAckGiven) {
        _log('WINN DEV SESSION: RESULT = native start accepted AND containment '
            'confirmed by the provider. The provider status above, and the '
            'appex log, are the evidence -- an accepted start is not by itself '
            'a completed handshake, and a CONTAINED session is never evidence '
            'that full-tunnel routing works.');
      } else {
        _log('WINN DEV SESSION: RESULT = native start accepted. This platform '
            '("${Platform.operatingSystem}") has no containment path, so '
            'containment was NOT confirmed and was never claimed -- this '
            'session took the whole machine\'s routing. The evidence it '
            'produces is therefore the opposite of a contained run\'s: the '
            'native start\'s own convergence gate -- a recent AmneziaWG '
            'handshake with bidirectional peer transfer, AND the Winn engine '
            'reporting transport_observed_both_ways -- both of which must pass '
            'before any route is promoted. An accepted start is still not by '
            'itself a completed handshake.');
      }
      _logTier2ArtifactLookup(result);
      await _runTraffic(result);
    }
    if (!mounted) return;
    setState(() {
      _running = false;
      _result = result;
    });
  }

  /// Prints the tier-2 artifact-lookup diagnostics on their OWN lines.
  ///
  /// WHY THIS EXISTS RATHER THAN READING THE STATUS DUMP ABOVE. `print()` under
  /// `flutter run` truncates at 1023 characters, and the provider status map is
  /// far longer than that, so the lookup fields were being emitted, forwarded
  /// and then CUT OFF mid-document — measured, not guessed: the
  /// `provider status:` line is exactly 1023 characters long. The four fields
  /// that decide whether tier 2 resolved were on the wrong side of the cut.
  ///
  /// These are booleans and build-time names only — never a filesystem path —
  /// so they are safe to print in full.
  void _logTier2ArtifactLookup(WinnDevSessionResult result) {
    final status = result.providerStatus ?? const <String, dynamic>{};
    Object? field(String bare) => status['provider_$bare'] ?? status[bare];
    const component = 'engine_runtime_lookup_winn_packet_engine';
    const names = <String>[
      'linked_in_process',
      'fw_dir_found',
      'bin_exists',
      'bin_readable',
      'bin_exec_bit',
      'info_plist_found',
      'declared_exec_present',
      'declared_exec_matches',
      'resolved',
      'resolved_via',
      'candidate_dir_count',
    ];
    final schema = field('engine_runtime_lookup_schema_version');
    _log('WINN DEV TIER2 LOOKUP: schema_version=$schema '
        '(absent means the provider did not publish the diagnostics at all, '
        'which is a different failure from publishing false)');
    for (final name in names) {
      final value = field('${component}_$name');
      // Absence and false are DIFFERENT answers. A component resolved by tier 1
      // publishes no FrameworkProbe fields at all, so "(absent)" here means
      // "this lookup never ran", not "the probe saw false".
      _log('WINN DEV TIER2 LOOKUP: $component'
          '_$name = ${value ?? "(absent)"}');
    }
  }

  /// Drives the traffic + in-provider memory harness, but only after
  /// re-confirming from the PROVIDER's own fields that the session is
  /// contained to exactly one /32.
  ///
  /// The gate is deliberately here rather than inside the harness: refusing to
  /// generate traffic is a policy decision about this device, and it must be
  /// made against the provider's observed settings readback, never against the
  /// document that was sent or against the dart-define that named the target.
  Future<void> _runTraffic(WinnDevSessionResult result) async {
    if (kWinnDevTrafficTarget.isEmpty) {
      _log('WINN DEV TRAFFIC: no --dart-define=WINN_DEV_TRAFFIC_TARGET, so no '
          'traffic was generated. The session above stands on its own.');
      return;
    }
    // A platform that cannot contain has no /32 readback to re-confirm, and
    // demanding one would refuse traffic on every session it can ever run.
    // The gate that replaces it is stricter about the thing that actually
    // matters here: the operator had to type the exact uncontained
    // acknowledgement for the session to exist at all, and the native start
    // already refused to promote a route without a proven handshake and
    // observed bidirectional transport. Apple's path below is untouched.
    // LANE-ONLY CHANGE (T-M fleet speed lane, 2026-08-23, worktree
    // /tmp/t-m-fleet, NOT for merge, never committed): when the operator's
    // exact WINN_DEV_UNSAFE_UNCONTAINED_ACK is present, the uncontained
    // traffic path is used even on a containment-capable platform (macOS),
    // mirroring the Windows/Linux branch below. Without the ack, Apple's
    // contained readback path is byte-identical to before.
    if (!winnDevSessionPlatformCanContain(Platform.operatingSystem) ||
        winnDevSessionUncontainedAckGiven) {
      if (!winnDevSessionUncontainedAckGiven) {
        _log('WINN DEV TRAFFIC: REFUSED to send. This platform cannot contain '
            'a session and the uncontained acknowledgement was not given, so '
            'no session should exist to send over.');
        return;
      }
      _log('WINN DEV TRAFFIC: this platform is UNCONTAINED by construction, so '
          'there is no /32 readback to re-confirm. Sending to '
          '$kWinnDevTrafficTarget over a tunnel that currently holds this '
          'machine\'s default routes.');
      await runWinnDevTrafficAndMemoryProbe(
        targetIp: kWinnDevTrafficTarget,
        targetPort: kWinnDevTrafficPort,
        duration: Duration(seconds: kWinnDevTrafficSeconds),
        steadyRatePerSecond: kWinnDevTrafficRate,
        postRekeyBurstRatePerSecond: kWinnDevTrafficBurstRate,
        log: _log,
      );
      // LINUX LANE ONLY: the Linux channel publishes winn/3 pump counters
      // (tun_read_packets/bytes, inbound/outbound frames) under
      // getWinn3PumpStats, which the harness does not otherwise read. Logging
      // them here is the client-side tx/rx evidence this lane exists to
      // capture; it changes nothing about the session.
      try {
        final pump = await winnDevShippingTunnelInvoke('getWinn3PumpStats', null);
        _log('WINN DEV LINUX: getWinn3PumpStats -> $pump');
      } catch (error) {
        _log('WINN DEV LINUX: getWinn3PumpStats threw: $error');
      }
      await _stopAndReadReleaseOutcome();
      return;
    }
    final status = result.providerStatus ?? const <String, dynamic>{};
    // `providerStatus` is the readiness map, whose provider-written fields live
    // under a `provider_` namespace; the raw status document spells them bare.
    // Accept either, exactly as `kWinnDevSessionContainmentActiveKeys` does.
    Object? field(String bare) => status['provider_$bare'] ?? status[bare];
    // Whether the provider SAID ANYTHING about a key, as opposed to what it
    // said. `field()` collapses "absent" and "present but false" into the same
    // falsey answer, and those are different failures with different fixes.
    bool reported(String bare) =>
        status.containsKey('provider_$bare') || status.containsKey(bare);

    final containedActive = field('dev_containment_active') == true;
    final observedContained = field('dev_containment_observed_contained') == true;
    final routeCount = field('dev_containment_observed_included_route_count');
    final prefixLengths =
        field('dev_containment_observed_included_route_prefix_lengths');
    final oneRoute = routeCount is int && routeCount == 1;
    // The prefix lengths arrive as a LIST from the raw provider document, but
    // the host app's status sanitizer only passes scalars through, so a
    // single-route session surfaces the bare number `32` instead of `[32]`.
    // Accept either shape and require that EVERY entry is /32 -- reading only
    // `.first` would have let a second, wider route ride along unnoticed.
    final prefixValues = prefixLengths is List
        ? prefixLengths.map((v) => '$v').toList()
        : (prefixLengths == null ? const <String>[] : <String>['$prefixLengths']);
    final slashThirtyTwo =
        prefixValues.isNotEmpty && prefixValues.every((v) => v == '32');

    if (!containedActive || !observedContained || !oneRoute || !slashThirtyTwo) {
      // REFUSING IS CORRECT IN BOTH CASES BELOW and the verdict is identical.
      // What differs is where the fix lives, and reporting them identically
      // cost a macOS session on 2026-08-06: the provider was emitting no
      // `dev_containment_observed_*` fields at all, the harness printed
      // `observed_contained=false included_route_count=null`, and that reads as
      // "containment failed" when it actually meant "I could not observe it".
      // A harness that cannot say which of those it hit will either refuse
      // forever for a reason nobody diagnoses, or -- if someone later
      // "fixes" it by treating absence as acceptable -- permit a run it should
      // have refused. Naming the distinction is what keeps the second outcome
      // from looking like a reasonable change.
      final observationReported =
          reported('dev_containment_observed_contained') ||
              reported('dev_containment_observed_included_route_count') ||
              reported('dev_containment_observed_included_route_prefix_lengths');
      final diagnosis = observationReported
          ? 'The provider DID report a read-back, and it does not describe a '
              'single contained /32. Containment is genuinely not in the shape '
              'this harness requires.'
          : 'The provider reported NO dev_containment_observed_* read-back at '
              'all, so this is "I could not observe containment", NOT '
              '"containment is off". A provider that never measures the '
              'settings object it built can never satisfy this gate, and the '
              'fix belongs in that provider -- not in this check. Refusing '
              'anyway: a session nobody can observe is not a session anybody '
              'can call safe.';
      _log('WINN DEV TRAFFIC: REFUSED to send. The provider readback does not '
          'show a single contained /32 -- '
          'dev_containment_active=$containedActive '
          'dev_containment_observed_contained=$observedContained '
          'included_route_count=$routeCount '
          'prefix_lengths=$prefixLengths '
          'observation_reported=$observationReported. '
          '$diagnosis Widening containment to make traffic '
          'reach the responder is NOT this harness\'s decision to make.');
      return;
    }
    _log('WINN DEV TRAFFIC: containment re-confirmed from the provider '
        '(active, observed, 1 route, /32). Aiming at $kWinnDevTrafficTarget '
        'only.');
    await runWinnDevTrafficAndMemoryProbe(
      targetIp: kWinnDevTrafficTarget,
      targetPort: kWinnDevTrafficPort,
      duration: Duration(seconds: kWinnDevTrafficSeconds),
      steadyRatePerSecond: kWinnDevTrafficRate,
      postRekeyBurstRatePerSecond: kWinnDevTrafficBurstRate,
      log: _log,
    );
    await _stopAndReadReleaseOutcome();
  }

  /// Stops the tunnel and reports what the provider says about releasing its
  /// network settings.
  ///
  /// This is the open question `setTunnelNetworkSettings(nil)` exists to
  /// answer: on macOS the release is refused with `NEAgentErrorDomain` code 1,
  /// and nobody had checked whether iOS does the same. The provider already
  /// records the outcome; `ios/Runner/AppDelegate.swift` now forwards it, so
  /// it can be read here instead of by hand out of the appex log.
  ///
  /// A contained session is stopped at the end regardless of the answer: a dev
  /// tunnel is not left running on someone's phone.
  Future<void> _stopAndReadReleaseOutcome() async {
    try {
      _log('WINN DEV TEARDOWN: stopping the tunnel.');
      await winnDevShippingTunnelInvoke(
        'stopTunnel',
        winnDevSessionStopArguments(Platform.operatingSystem),
      );
    } catch (error) {
      _log('WINN DEV TEARDOWN: stopTunnel threw: $error');
    }
    // The release is asynchronous inside the provider; give it a moment to
    // record an outcome before reading, and say so rather than reporting an
    // absence as a verdict.
    await Future<void>.delayed(const Duration(seconds: 5));
    try {
      final raw = await winnDevShippingTunnelInvoke('getTunnelReadiness', null);
      final map = Map<String, dynamic>.from(raw as Map);
      Object? field(String bare) => map['provider_$bare'] ?? map[bare];
      final outcome = field('network_settings_release_outcome');
      if (outcome == null) {
        _log('WINN DEV TEARDOWN: the provider reported NO '
            'network_settings_release_outcome. That is an absence, not a '
            'verdict -- the appex may already have exited, taking its status '
            'with it. Read the appex log before concluding anything.');
      } else {
        _log('WINN DEV TEARDOWN: network_settings_release_outcome=$outcome '
            'requested=${field('network_settings_release_requested')} '
            'completed=${field('network_settings_release_completed')} '
            'failed=${field('network_settings_release_failed')} '
            'context=${field('network_settings_release_context')} '
            'elapsed_ms=${field('network_settings_release_elapsed_ms')} '
            'error_domain=${field('network_settings_release_error_domain')} '
            'error_code=${field('network_settings_release_error_code')}');
      }
      _log('WINN DEV TEARDOWN: tunnel status now '
          '"${map['status']}" (active=${map['active']}).');
    } catch (error) {
      _log('WINN DEV TEARDOWN: could not read the release outcome: $error');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Winn Protocol v3 -- dev session (${Platform.operatingSystem})',
        ),
        backgroundColor: Colors.deepOrange.shade900,
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          Container(
            width: double.infinity,
            color: Colors.deepOrange.shade900,
            padding: const EdgeInsets.all(12),
            child: const Text(
              'NOT the Win\'s VPN app. This is a development-only entry point '
              'that delivers an unproven winn/3 config to the real Network '
              'Extension so a session can be observed. It does not read or '
              'change kWinnHostCapabilities, and nothing it does earns the '
              'macOS capability flip.',
              style: TextStyle(fontSize: 12),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: <Widget>[
                FilledButton(
                  onPressed: _running ? null : _run,
                  child: Text(_running ? 'Running...' : 'Run winn/3 session'),
                ),
                const SizedBox(width: 16),
                if (_result != null)
                  Expanded(
                    child: Text(
                      _result!.blockedAt == null
                          ? 'native start accepted'
                          : 'BLOCKED at ${_result!.blockedAt}',
                      style: TextStyle(
                        color: _result!.blockedAt == null
                            ? Colors.greenAccent
                            : Colors.amberAccent,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(12),
              itemCount: _lines.length,
              itemBuilder: (context, index) => SelectableText(
                _lines[index],
                style: const TextStyle(
                  fontFamily: 'Menlo',
                  fontSize: 11,
                  height: 1.35,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
