// Windows start is synchronous. The service terminates itself fail-closed after
// 150s, the native response waits 160s, the manager pipe can take 5s to become
// available, and Dart retains a final 5s scheduling/channel margin.
// Keep this value numerically locked to windows_tunnel_service_protocol.h by
// tools/test_windows_start_timeout_contract.py.
const windowsTunnelNativeStartTimeout = Duration(seconds: 170);

// The native stop call can spend 5s waiting for the manager pipe and 25s on
// the bounded command. Keep a strict scheduling/channel margin above that
// complete 30s chain.
const windowsTunnelNativeStopTimeout = Duration(seconds: 35);

const windowsTunnelStopQuietWindow = Duration(seconds: 6);
// Must outlast the native tunnel-manager's worst-case recovery time: its own
// 20s stop watchdog (kStopWatchdogMilliseconds in
// windows_tunnel_service_main.cpp) plus its first SCM restart delay (5s),
// with the quiet window above still fitting afterward plus margin.
// Otherwise a slow-but-successful AWG teardown can be misread as an
// unrecoverable stop, abandoning Double VPN failover before Xray ever gets
// a chance to start.
const windowsTunnelStopSettlementTimeout = Duration(seconds: 45);
const windowsTunnelStopPollInterval = Duration(milliseconds: 500);
// Native status can spend 12s on its bounded response after a 300ms busy-pipe
// wait. Preserve margin for method-channel scheduling.
const windowsTunnelActivitySnapshotTimeout = Duration(seconds: 15);

/// Counts only time after the first observed quiet native snapshot. A slow
/// status read before that snapshot is not evidence that the tunnel was quiet.
class TunnelStopQuietWindow {
  TunnelStopQuietWindow(this.required);

  final Duration required;
  Duration? _quietSince;

  bool observe(bool? active, Duration observedAt) {
    if (active != false) {
      _quietSince = null;
      return false;
    }
    _quietSince ??= observedAt;
    return observedAt - _quietSince! >= required;
  }
}

/// One observed sample of native tunnel activity during Windows stop
/// settlement. Mirrors the tri-state returned by
/// `_nativeTunnelActivityForStopSettlement` in `lib/main.dart`:
///
/// * [active] — the manager or an Xray carrier reports in-flight traffic.
/// * [quiet] — the snapshot is known and reports no active traffic.
/// * [unknown] — the status pipe was busy/unavailable and answered nothing.
enum TunnelActivitySample { active, quiet, unknown }

/// The homogeneous, deterministic rule that decides whether a shutting-down
/// Windows tunnel has actually settled. It is the extracted, testable heart of
/// `_settleWindowsTunnelStop` in `lib/main.dart`.
///
/// A tunnel is only reported settled once a *continuous* run of [quiet]
/// samples of length [quietWindowSamples] has been observed. Any [active]
/// (in-flight) or [unknown] (busy/unavailable) sample resets that counter, so
/// the decision can never be reached while traffic is in flight — a silent
/// false "stopped" is structurally impossible. If the observed sequence ends
/// before a full quiet window (traffic still draining), the tunnel is reported
/// unsettled so the caller keeps waiting or fails closed instead of trusting a
/// premature stop.
class TunnelSettlementObservation {
  const TunnelSettlementObservation._(this.settled, this.settledAtIndex);

  /// True only if a full continuous quiet window was observed.
  final bool settled;

  /// Index into the sample list at which the decision became final, or -1 if
  /// the sequence never settled.
  final int settledAtIndex;

  static const notSettled = TunnelSettlementObservation._(false, -1);
}

TunnelSettlementObservation tunnelStopSettlement(
  List<TunnelActivitySample> samples,
  int quietWindowSamples,
) {
  var consecutiveQuiet = 0;
  for (var i = 0; i < samples.length; i++) {
    if (samples[i] == TunnelActivitySample.quiet) {
      consecutiveQuiet += 1;
      if (consecutiveQuiet >= quietWindowSamples) {
        return TunnelSettlementObservation._(true, i);
      }
    } else {
      // active (in-flight) or unknown (busy/unavailable) traffic neither
      // establishes nor continues a quiet window.
      consecutiveQuiet = 0;
    }
  }
  return TunnelSettlementObservation.notSettled;
}
