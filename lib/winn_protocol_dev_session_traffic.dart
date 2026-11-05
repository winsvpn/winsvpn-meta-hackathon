/// Winn Protocol v3 -- DEV-ONLY, NON-SHIPPING traffic + memory measurement
/// harness.
///
/// # Why this file exists in the repository rather than in a handoff table
///
/// Every previous Apple memory figure for the winn/3 datapath was published as
/// a table in a markdown handoff with the harness that produced it living only
/// in somebody's scratch directory -- the same provenance failure as the
/// unmeasured "14.0 MB" figure those tables were written to replace. A number
/// whose generator cannot be re-run is not a measurement, it is an assertion.
/// This file is the generator, and it is in-tree so the numbers can be
/// reproduced, disputed, or shown to be wrong.
///
/// # What it measures, and why BOTH numbers
///
///   * `phys_footprint` (`TASK_VM_INFO`) -- the field jetsam actually accounts
///     against the process. It says what this datapath costs.
///   * `os_proc_available_memory()` -- the bytes this process has left before
///     *its own* limit, as the OS reports it for this OS version, this device
///     and this appex's real loaded state.
///
/// Neither is sufficient alone. `phys_footprint` cannot say how close to the
/// limit it is, because the limit differs by OS version (~50 MB on iOS 15+,
/// roughly 15 MB on iOS 13/14) and by device. `os_proc_available_memory()`
/// cannot say what the datapath costs. Together they calibrate the runtime
/// memory gate against the fleet instead of against an assumption.
///
/// **Both are sampled from INSIDE the provider**, not from this process. This
/// harness only *triggers* the sample: `getTunnelReadiness` sends the
/// authenticated `health` app message, the provider handles it, samples itself,
/// writes the numbers into the shared status document, and the readiness call
/// re-reads that same-generation document before returning
/// (`ios/Runner/AppDelegate.swift:1480-1490`). The app process's own memory is
/// irrelevant and is never reported here.
///
/// # What the traffic proves, and what it does not
///
/// Payloads are deterministic in their sequence number, so the receiver can
/// rebuild the exact bytes it should have received and compare them, and an
/// ordered streaming SHA-256 over the ACTUAL returned bytes is an end-to-end
/// check that is independent of the far end's own digest. 1252-byte payloads
/// produce exactly 1280-byte inner IPv4 datagrams (20 IP + 8 UDP + 1252) =
/// the tunnel MTU, so this is MTU-sized traffic, not keepalive-sized.
///
/// It does NOT prove full-tunnel routing. Traffic is aimed at the single
/// contained /32 and nothing else, by construction. A contained session is
/// never evidence that full-tunnel routing works.
///
/// DEVELOPMENT SIGNING ONLY. Nothing reachable from `lib/main.dart` imports
/// this file, so it is absent from a shipping binary rather than merely
/// disabled -- the same third gate that
/// `lib/winn_protocol_dev_session_main.dart` documents.
library;

import 'dart:async';
import 'dart:convert' show json;
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show Digest, sha256;
import 'package:flutter/services.dart' show MethodChannel;

import 'winn_protocol_dev_session.dart'
    show WinnDevSessionInvoker, WinnDevSessionLogger;

/// A `strings`-checkable marker proving this harness is absent from a shipping
/// binary. Mirrors `kWinnDevSessionAbsenceProbeString`'s purpose.
const String kWinnDevTrafficAbsenceProbeString =
    'WINS_DEV_WINN3_TRAFFIC_HARNESS_ABSENCE_PROBE_4f9c2ad1';

/// 1252 + 8 (UDP) + 20 (IPv4) = 1280 = the winn/3 tunnel MTU. Changing this
/// without changing the MTU stops the traffic being MTU-sized, which is the
/// property criterion 4 asks for.
const int kWinnDevTrafficPayloadBytes = 1252;

/// The sequence number occupies the first 8 bytes of every payload.
const int kWinnDevTrafficSeqHeaderBytes = 8;

/// Datagrams per second during the steady phase. 12/s == 180 per 15 s bin,
/// which is the bin size the rekey-survival table is built from.
const int kWinnDevTrafficSteadyRatePerSecond = 12;

/// LINUX LAB LANE ONLY (2026-08-21): bind the traffic socket to [targetPort]
/// instead of an ephemeral port.
///
/// The lab winn3 gateway runs in REFLECT mode, whose echo swaps the inner IP
/// ADDRESSES but keeps the UDP PORTS: a datagram sent from :ephemeral to
/// :7777 comes back addressed to :7777, not to :ephemeral, so a socket bound
/// to an ephemeral port receives nothing and the kernel emits an ICMP port
/// unreachable for every echo. Binding the socket to the very port it sends
/// TO makes the reflection land back on the socket. Gated behind this
/// dart-define so the Apple/mobile paths (whose responders reply to the
/// source port) are byte-identical to before.
const bool kWinnDevTrafficBindTargetPort = bool.fromEnvironment(
  'WINN_DEV_TRAFFIC_BIND_TARGET_PORT',
  defaultValue: false,
);

/// Bin width for the rekey-survival table. AmneziaWG's `REKEY_AFTER_TIME` is
/// 120 s, so a 15 s bin localises a rekey to a single bucket.
const Duration kWinnDevTrafficBinWidth = Duration(seconds: 15);

/// How often the provider is asked to sample itself while traffic is running.
const Duration kWinnDevTrafficMemorySamplePeriod = Duration(seconds: 20);

const MethodChannel _shippingTunnelChannel = MethodChannel('wins_vpn/tunnel');

/// Calls the SHIPPING `wins_vpn/tunnel` channel — the same one `lib/main.dart`
/// declares. Public so the dev entry point can reach it for teardown without
/// declaring a second channel that could drift from this one.
Future<Object?> winnDevShippingTunnelInvoke(String method, Object? arguments) =>
    _shippingTunnelChannel.invokeMethod<Object?>(method, arguments);

Future<Object?> _shippingInvoker(String method, Object? arguments) =>
    winnDevShippingTunnelInvoke(method, arguments);

/// Builds the deterministic payload for [seq].
///
/// Deterministic in the sequence number alone, so the verifier rebuilds the
/// exact expected bytes rather than trusting a length or a checksum the sender
/// also chose.
Uint8List winnDevTrafficPayload(int seq, {int length = kWinnDevTrafficPayloadBytes}) {
  final out = Uint8List(length);
  final view = ByteData.view(out.buffer);
  view.setUint64(0, seq);
  for (var i = kWinnDevTrafficSeqHeaderBytes; i < length; i++) {
    out[i] = (seq * 31 + i * 17 + (seq >> 8)) & 0xFF;
  }
  return out;
}

/// Reads the sequence number back out of a payload, or `null` if it is too
/// short to contain one.
int? winnDevTrafficSeqOf(List<int> payload) {
  if (payload.length < kWinnDevTrafficSeqHeaderBytes) return null;
  final bytes = payload is Uint8List ? payload : Uint8List.fromList(payload);
  return ByteData.view(bytes.buffer, bytes.offsetInBytes).getUint64(0);
}

/// One provider-side memory sample, taken inside the appex.
class WinnDevMemorySample {
  const WinnDevMemorySample({
    required this.label,
    required this.elapsedSeconds,
    required this.taken,
    this.physFootprintBytes,
    this.availableBytes,
    this.availableMeasured,
    this.providerStage,
  });

  /// `idle_before_traffic`, `under_traffic`, `idle_after_traffic`.
  final String label;
  final double elapsedSeconds;

  /// Whether the provider reported having taken a sample at all. False means
  /// the provider did not run the winn-only sample path -- which is itself a
  /// finding, not a measurement.
  final bool taken;

  /// `TASK_VM_INFO.phys_footprint` inside the provider.
  final int? physFootprintBytes;

  /// `os_proc_available_memory()` inside the provider.
  final int? availableBytes;
  final bool? availableMeasured;
  final String? providerStage;

  double? get physFootprintMiB =>
      physFootprintBytes == null ? null : physFootprintBytes! / (1024 * 1024);

  double? get availableMiB =>
      availableBytes == null ? null : availableBytes! / (1024 * 1024);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'label': label,
        'elapsed_seconds': double.parse(elapsedSeconds.toStringAsFixed(1)),
        'winn_memory_sample_taken': taken,
        'phys_footprint_bytes': physFootprintBytes,
        'phys_footprint_mib': physFootprintMiB == null
            ? null
            : double.parse(physFootprintMiB!.toStringAsFixed(3)),
        'available_bytes': availableBytes,
        'available_mib': availableMiB == null
            ? null
            : double.parse(availableMiB!.toStringAsFixed(3)),
        'available_measured': availableMeasured,
        'provider_stage': providerStage,
      };

  @override
  String toString() {
    final fp = physFootprintMiB == null
        ? 'phys_footprint=UNAVAILABLE'
        : 'phys_footprint=${physFootprintMiB!.toStringAsFixed(2)} MiB';
    final av = availableMiB == null
        ? 'os_proc_available_memory=UNAVAILABLE'
        : 'os_proc_available_memory=${availableMiB!.toStringAsFixed(2)} MiB';
    return '[t+${elapsedSeconds.toStringAsFixed(1)}s $label] $fp  $av';
  }
}

/// Extracts a provider memory sample out of a `getTunnelReadiness` map.
WinnDevMemorySample winnDevMemorySampleFrom(
  Map<String, dynamic> readiness, {
  required String label,
  required double elapsedSeconds,
}) {
  int? asInt(Object? v) {
    if (v is int) return v;
    if (v is double) return v.round();
    if (v is String) return int.tryParse(v);
    return null;
  }

  // Both spellings, because a caller may hand this either the RAW provider
  // status document or the readiness map built from it. `AppDelegate` forwards
  // provider fields into a `provider_` namespace; the provider itself writes
  // them bare. They carry the same value and only the provider can write
  // either.
  Object? field(String bare) =>
      readiness['provider_$bare'] ?? readiness[bare];

  return WinnDevMemorySample(
    label: label,
    elapsedSeconds: elapsedSeconds,
    taken: field('winn_memory_sample_taken') == true,
    physFootprintBytes: asInt(field('winn_memory_sample_phys_footprint_bytes')),
    availableBytes: asInt(field('winn_memory_sample_available_bytes')),
    availableMeasured: field('winn_memory_sample_available_measured') as bool?,
    providerStage: readiness['provider_stage']?.toString(),
  );
}

/// Everything one traffic run found out.
class WinnDevTrafficResult {
  WinnDevTrafficResult({
    required this.attempted,
    this.error,
    this.durationSeconds = 0,
    this.txDatagrams = 0,
    this.txBytes = 0,
    this.rxVerified = 0,
    this.rxBytes = 0,
    this.rxCorrupt = 0,
    this.rxDuplicate = 0,
    this.rxUnknownSeq = 0,
    this.missingCount = 0,
    this.digestSentAll,
    this.digestReturned,
    this.digestOrderedComplete = false,
    this.bins = const <int, List<int>>{},
    this.memorySamples = const <WinnDevMemorySample>[],
    this.postRekeyBurstTx = 0,
    this.postRekeyBurstRx = 0,
  });

  final bool attempted;
  final String? error;
  final double durationSeconds;
  final int txDatagrams;
  final int txBytes;
  final int rxVerified;
  final int rxBytes;
  final int rxCorrupt;
  final int rxDuplicate;
  final int rxUnknownSeq;
  final int missingCount;

  /// SHA-256 over every payload this harness SENT, in send order.
  final String? digestSentAll;

  /// SHA-256 over the ACTUAL bytes that came back, in sequence order. Only
  /// meaningful when [digestOrderedComplete] is true -- a gap makes an ordered
  /// digest impossible, and saying so is better than emitting a digest over a
  /// different byte string than the one that was sent.
  final String? digestReturned;
  final bool digestOrderedComplete;

  /// `bin index -> [sent, verified]`.
  final Map<int, List<int>> bins;
  final List<WinnDevMemorySample> memorySamples;
  final int postRekeyBurstTx;
  final int postRekeyBurstRx;

  double get lossPercent =>
      txDatagrams == 0 ? 0 : (missingCount / txDatagrams) * 100;

  bool get digestMatch =>
      digestOrderedComplete &&
      digestSentAll != null &&
      digestSentAll == digestReturned;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'attempted': attempted,
        'error': error,
        'duration_seconds': double.parse(durationSeconds.toStringAsFixed(1)),
        'tx_datagrams': txDatagrams,
        'tx_bytes': txBytes,
        'rx_datagrams_verified': rxVerified,
        'rx_bytes': rxBytes,
        'rx_corrupt': rxCorrupt,
        'rx_duplicate': rxDuplicate,
        'rx_unknown_seq': rxUnknownSeq,
        'missing_count': missingCount,
        'loss_percent': double.parse(lossPercent.toStringAsFixed(4)),
        'digest_sha256_sent_all': digestSentAll,
        'digest_sha256_returned': digestReturned,
        'digest_ordered_complete': digestOrderedComplete,
        'digest_match': digestMatch,
        'post_rekey_burst_tx': postRekeyBurstTx,
        'post_rekey_burst_rx': postRekeyBurstRx,
        'bins': bins.map((k, v) => MapEntry(k.toString(), v)),
        'memory_samples':
            memorySamples.map((s) => s.toJson()).toList(growable: false),
      };
}

/// Drives MTU-sized UDP traffic at the single contained /32 and samples the
/// provider's own memory at idle and under load.
///
/// [targetIp] must be the contained /32 and nothing else. This harness never
/// widens containment and never sends anywhere else; if the contained route
/// cannot reach the responder, that is a result to report, not a knob to turn.
Future<WinnDevTrafficResult> runWinnDevTrafficAndMemoryProbe({
  required String targetIp,
  int targetPort = 7777,
  Duration duration = const Duration(seconds: 480),
  int postRekeyBurst = 1600,
  int steadyRatePerSecond = kWinnDevTrafficSteadyRatePerSecond,
  int postRekeyBurstRatePerSecond = 0,
  required WinnDevSessionLogger log,
  WinnDevSessionInvoker invoke = _shippingInvoker,
}) async {
  final samples = <WinnDevMemorySample>[];
  final started = DateTime.now();
  double elapsed() =>
      DateTime.now().difference(started).inMilliseconds / 1000.0;

  Future<void> sample(String label) async {
    try {
      final raw = await invoke('getTunnelReadiness', null);
      final map = Map<String, dynamic>.from(raw as Map);
      final s = winnDevMemorySampleFrom(
        map,
        label: label,
        elapsedSeconds: elapsed(),
      );
      samples.add(s);
      log('WINN DEV TRAFFIC: memory $s');
      if (!s.taken) {
        log('WINN DEV TRAFFIC: WARNING -- the provider did not report '
            'winn_memory_sample_taken. The winn-only sample path did not run; '
            'treat the absence as a finding, not as a zero.');
      }
    } catch (error) {
      log('WINN DEV TRAFFIC: memory sample "$label" FAILED: $error');
    }
  }

  RawDatagramSocket? socket;
  try {
    // --- 1. idle, before a single byte of traffic -------------------------
    log('WINN DEV TRAFFIC: sampling provider memory at IDLE, before traffic.');
    await sample('idle_before_traffic');

    socket = await RawDatagramSocket.bind(
      InternetAddress.anyIPv4,
      kWinnDevTrafficBindTargetPort ? targetPort : 0,
    );
    socket.readEventsEnabled = true;
    final target = InternetAddress(targetIp);
    log('WINN DEV TRAFFIC: bound udp/${socket.port}, aiming '
        '$kWinnDevTrafficPayloadBytes-byte payloads (=1280-byte inner '
        'datagrams) at $targetIp:$targetPort -- the contained /32 and nothing '
        'else.');
    if (kWinnDevTrafficBindTargetPort) {
      log('WINN DEV TRAFFIC: socket bound to the TARGET port '
          '(WINN_DEV_TRAFFIC_BIND_TARGET_PORT) because the lab gateway '
          'reflects with ports preserved; the echo returns to this port.');
    }

    var txDatagrams = 0;
    var txBytes = 0;
    var rxVerified = 0;
    var rxBytes = 0;
    var rxCorrupt = 0;
    var rxDuplicate = 0;
    var rxUnknownSeq = 0;
    final seenSeq = <int>{};
    final bins = <int, List<int>>{};
    var burstPhase = false;
    var burstTx = 0;
    var burstRx = 0;

    // Ordered streaming digest over the bytes that actually came back. A
    // bounded reorder window keeps this memory-safe on a phone: at most
    // 1024 * 1252 B ~= 1.2 MiB, in the APP process, never the appex.
    const reorderWindow = 1024;
    final pending = <int, Uint8List>{};
    var nextSeqToHash = 0;
    var orderedComplete = true;

    String? sentDigest;
    String? returnedDigest;
    final sentSinkResult = <String>[];
    final rxSinkResult = <String>[];
    final sentSink = sha256.startChunkedConversion(
      _DigestCollector(sentSinkResult),
    );
    final rxSink = sha256.startChunkedConversion(
      _DigestCollector(rxSinkResult),
    );

    void binAdd(int index, int sentDelta, int verifiedDelta) {
      final row = bins.putIfAbsent(index, () => <int>[0, 0]);
      row[0] += sentDelta;
      row[1] += verifiedDelta;
    }

    socket.listen((event) {
      if (event != RawSocketEvent.read) return;
      while (true) {
        final dg = socket!.receive();
        if (dg == null) break;
        final data = dg.data;
        final seq = winnDevTrafficSeqOf(data);
        if (seq == null) {
          rxUnknownSeq++;
          continue;
        }
        final expected = winnDevTrafficPayload(seq, length: data.length);
        var identical = data.length == kWinnDevTrafficPayloadBytes;
        if (identical) {
          for (var i = 0; i < data.length; i++) {
            if (data[i] != expected[i]) {
              identical = false;
              break;
            }
          }
        }
        if (!identical) {
          rxCorrupt++;
          continue;
        }
        if (!seenSeq.add(seq)) {
          rxDuplicate++;
          continue;
        }
        rxVerified++;
        rxBytes += data.length;
        if (burstPhase) burstRx++;
        binAdd(
          elapsed() ~/ kWinnDevTrafficBinWidth.inSeconds,
          0,
          1,
        );

        // Ordered streaming digest over the real returned bytes.
        if (orderedComplete) {
          if (seq == nextSeqToHash) {
            rxSink.add(data);
            nextSeqToHash++;
            while (pending.containsKey(nextSeqToHash)) {
              rxSink.add(pending.remove(nextSeqToHash)!);
              nextSeqToHash++;
            }
          } else if (seq > nextSeqToHash) {
            if (pending.length < reorderWindow) {
              pending[seq] = Uint8List.fromList(data);
            } else {
              orderedComplete = false;
            }
          }
        }
      }
    });

    Future<void> send(int seq) async {
      final payload = winnDevTrafficPayload(seq);
      final n = socket!.send(payload, target, targetPort);
      if (n <= 0) return;
      txDatagrams++;
      txBytes += n;
      sentSink.add(payload);
      if (burstPhase) burstTx++;
      binAdd(elapsed() ~/ kWinnDevTrafficBinWidth.inSeconds, 1, 0);
    }

    // --- 2. steady MTU-sized traffic, with periodic in-provider samples ---
    var seq = 0;
    var lastMemorySample = DateTime.now();
    final deadline = started.add(duration);
    // The datagrams-per-tick count stays at the historical 3 and the TICK
    // PERIOD is what scales with the rate, so raising the rate makes the
    // stream SMOOTHER rather than burstier. At the default 12/s this evaluates
    // to exactly the historical 3-per-250 ms and nothing changes.
    const perTick = (kWinnDevTrafficSteadyRatePerSecond * 250) ~/ 1000;
    final tickPeriod =
        Duration(microseconds: (perTick * 1000000) ~/ steadyRatePerSecond);

    log('WINN DEV TRAFFIC: steady phase begins -- '
        '$steadyRatePerSecond datagrams/s for '
        '${duration.inSeconds}s, spanning '
        '${(duration.inSeconds / 120).floor()} AmneziaWG rekey intervals.');

    while (DateTime.now().isBefore(deadline)) {
      for (var i = 0; i < perTick; i++) {
        await send(seq++);
      }
      if (DateTime.now().difference(lastMemorySample) >=
          kWinnDevTrafficMemorySamplePeriod) {
        lastMemorySample = DateTime.now();
        unawaited(sample('under_traffic'));
      }
      await Future<void>.delayed(tickPeriod);
    }

    // --- 3. the post-rekey re-verification burst --------------------------
    log('WINN DEV TRAFFIC: post-rekey burst of $postRekeyBurst datagrams at '
        't+${elapsed().toStringAsFixed(1)}s -- this is the '
        '"re-verified after >=2 rekeys" check.');
    burstPhase = true;
    final burstStarted = DateTime.now();
    for (var i = 0; i < postRekeyBurst; i++) {
      await send(seq++);
      if (postRekeyBurstRatePerSecond > 0) {
        // Absolute-schedule pacing. The unpaced default below fires ~3900/s,
        // which overruns the SENDER's own transmit queue long before anything
        // reaches the tunnel: a VPN-free UDP control over the same 802.11 link
        // loses 54.75% of an identically-paced burst. That measures the socket
        // buffer, not the datapath, so a link that cannot absorb it can never
        // produce the complete ordered digest criterion 5 asks for. Pacing the
        // burst to a rate the link demonstrably carries keeps the post-rekey
        // re-verification intact while letting the digest close.
        final due = burstStarted.add(Duration(
            microseconds:
                ((i + 1) * 1000000) ~/ postRekeyBurstRatePerSecond));
        final wait = due.difference(DateTime.now());
        if (wait > Duration.zero) await Future<void>.delayed(wait);
      } else if (i % 50 == 0) {
        await Future<void>.delayed(const Duration(milliseconds: 8));
      }
    }
    // Let the tail of the burst come back before closing the books.
    await Future<void>.delayed(const Duration(seconds: 5));
    burstPhase = false;

    final durationSeconds = elapsed();
    await sample('idle_after_traffic');

    sentSink.close();
    rxSink.close();
    sentDigest = sentSinkResult.isEmpty ? null : sentSinkResult.first;
    returnedDigest = rxSinkResult.isEmpty ? null : rxSinkResult.first;
    // The ordered digest only describes the whole stream when nothing is
    // missing from it.
    final ordered = orderedComplete && nextSeqToHash == txDatagrams;

    final missing = txDatagrams - rxVerified;
    final result = WinnDevTrafficResult(
      attempted: true,
      durationSeconds: durationSeconds,
      txDatagrams: txDatagrams,
      txBytes: txBytes,
      rxVerified: rxVerified,
      rxBytes: rxBytes,
      rxCorrupt: rxCorrupt,
      rxDuplicate: rxDuplicate,
      rxUnknownSeq: rxUnknownSeq,
      missingCount: missing < 0 ? 0 : missing,
      digestSentAll: sentDigest,
      digestReturned: ordered ? returnedDigest : null,
      digestOrderedComplete: ordered,
      bins: bins,
      memorySamples: samples,
      postRekeyBurstTx: burstTx,
      postRekeyBurstRx: burstRx,
    );
    log('WINN DEV TRAFFIC: RESULT ${json.encode(result.toJson())}');
    return result;
  } catch (error) {
    log('WINN DEV TRAFFIC: FAILED: $error');
    return WinnDevTrafficResult(
      attempted: true,
      error: '$error',
      memorySamples: samples,
    );
  } finally {
    socket?.close();
  }
}

/// Collects a `crypto` digest out of a chunked conversion into a hex string.
class _DigestCollector implements Sink<Digest> {
  _DigestCollector(this._out);
  final List<String> _out;

  @override
  void add(Digest data) => _out.add('$data');

  @override
  void close() {}
}
