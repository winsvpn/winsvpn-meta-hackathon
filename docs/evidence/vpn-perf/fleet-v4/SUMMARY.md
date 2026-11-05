# FLEET-v4 SPEED + ATTESTATION SUMMARY

Fleet: control-sim / data-sim-winn3gw @ <DATA_SIM_IP>:9111 (fleet-v4, descriptor seq=2 gen=1 kid=g1).
Aggregated by lane T-P. Polled /tmp/fleet-speed-evidence/ every 60 s from 2026-08-23T03:50Z to 05:11Z
(exceeds the 40 min cap; lanes that had not produced a verdict by then are marked n/a, see notes).
Nothing committed or pushed. No secret values are reproduced below.

## Per-target table

| target | carrying | before Mbps | after Mbps | loss% | notes |
|---|---|---|---|---|---|
| T-A android (app-level, fleet winn3 udp 9111) | YES | 47.8 (avg of 38.37/57.16) | 10.2 (avg 10.85/9.83/10.01) | 78.6 (throughput vs baseline) | VERDICT: gate carrying ~0.6 s, promoted, 3x25 MB Cloudflare + 11.2 MB harness through tunnel, zero drops both ends. Promotion ICMP echo to 10.10.0.1 dropped by gateway INPUT firewall; promotion came from TCP SYN->10.10.0.1:53 SYN-ACK. Session 9845439f, rx 38918/tx 14468 client, gateway delivered 39753. (verdict.txt) |
| T-L linux (app-level, aicore x86_64, yoga down) | YES | 626.8 (median MB/s 78.35, n=6) | 137.6 (median 17.20 MB/s, n=4) | 78.0 (throughput vs baseline) | VERDICT: carrying=YES, promoted, egress curl = <DATA_SIM_IP>, 11.5 MB in / 76627 frames out, 4 rekeys survived, 0 rx harness by design. Gateway does not answer inner ICMP to 10.10.0.1 (same INPUT-drop). Linux stopTunnel leaves winsvpn3 + /1 routes + engine up (real shipping gap, killed manually). Memory probe fields unavailable on Linux. (linux-verdict.txt) |
| T-W windows (app-level, direct-awg udp 9110 seam) | YES (connected) | 644 (80.52 MB/s) | 80.4 run1, 123.1 run2 | 0 (byte loss: 25000000/25000000 each run; throughput drop is seam+engine+GCP cost) | VERDICT: connected=YES, tunnel owned default route during AFTER, far-end data-sim peer 8 s handshake, 4.25 MiB rx / 62.55 MiB sent, clean fail-closed teardown. Lane-only patch (standaloneOnly=false) on winpc copy ONLY, Mac main untouched. winpc loopback was broken (netsh fix), pktmon/WFP diagnostics captured. (T-W-REPORT.md) |
| T-I ios (app-level, fleet winn3 udp 9111) | YES (contained dev session, promotion held by design) | n/a (see lane note; manual in-app test required) | n/a (see lane note; contained session never claims the phone) | 0 (47/47 canary echoes reflected; RTT < 500ms bound) | VERDICT: carrying=YES. Owner tapped Allow (08:29Z), appex spawned (PID 2923), winn3_gate_state=carrying, rx_packets=1/tx_packets=1 (device), gateway carrying=1 promoted=1 carriage_proven=true rx 5/tx 2 (08:39:39Z proof window). Converged proof gate: gate carrying + RxPackets>0 + probe observed -> "PROVEN; promotion HELD on purpose" (code 1034) — the contained dev session never installs routes/DNS/IPv6: default_ipv4_route_installed=false, ipv6_settings_installed=false, dns_settings_installed=false, included_route_count=1, prefix_lengths=32, transport /32 exclusion present. BEFORE baseline requires the manual in-app production speed test (speed.cloudflare.com + cachefly) on Wi-Fi; no headless iOS shell. Mac canary probe: 47/47 echoes, rekey ok epoch=2. (t-i-rerun-console.txt, t-i-provider-status-fields.txt, t-i-appex-lifecycle.txt, t-i-gateway-ios-session.txt, t-i-canary-probe.txt) |
| T-M macos | n/a (no verdict) | n/a (see lane note) | n/a (see lane note) | n/a (see lane note) | No macOS lane verdict file appeared in /tmp/fleet-speed-evidence/ by poll cutoff (mac_files.txt / mac_hashes.txt / mac_paths_rel.txt / sync_src.tgz are T-W's sync artifacts per T-W-REPORT.md). |
| T-P dual-auth attestation (winn3-probe canary, fleet gateway) | YES (gate carrying, both canaries) | n/a (attestation lane, no speed runs) | n/a (attestation lane, no speed runs) | n/a (see lane note) | ML-DSA-65 + Ed25519 dual-signature attestation VERIFIED against data-sim-winn3gw: dual-auth canary handshake reached carrying with both fleet pubkeys pinned (Expected=true is fail-closed). Negative control with one flipped hex char in the ML-DSA-65 pubkey fails closed: "session failed: winn3/session: dual-signature attestation failed: dual-auth verification failed: invalid Winn ML-DSA signature". Canary final verdict lines quote reflect=FAIL (see below): the fleet gateway is FORWARD=1 and its INPUT policy drops ICMP echo on winn3gw0, so the in-process reflector leg cannot answer; the green "dual-auth=ok" verdict token is unreachable against a forward-mode gateway by construction (reflectReplyMatches requires an identical-bytes address swap only a reflector produces). Replay-detector check passed in both runs (other-source replay silent, 3 s wait); volume rekey advanced epoch 1->2 in both runs. (dualauth-canary.txt, dualauth-negative-control.txt) |

## T-P dual-auth verdict lines (verbatim, final lines of each run in dualauth-canary.txt)

Dual-auth canary (both fleet pubkeys pinned, -count 24):
    v3probe: VERDICT canary handshake=ok replay-safe=ok reflect=FAIL rekey=unproven
    v3probe: no reply: for -reflect-to the gateway must be a local winn3-gateway reflector (not -forward); -reflect-to must be that process's -inner-v4, and -inner a different host address, not equal to -reflect-to

Plain canary (no dual flags, comparison row):
    v3probe: VERDICT canary handshake=ok replay-safe=ok reflect=FAIL rekey=unproven
    v3probe: no reply: for -reflect-to the gateway must be a local winn3-gateway reflector (not -forward); -reflect-to must be that process's -inner-v4, and -inner a different host address, not equal to -reflect-to

Context lines (both runs): HANDSHAKE ok state=carrying session=established; REPLAY other-source
silent=true; REKEY ok rekeys=1 epoch=2 session=established gate=carrying. The requested success
criterion (final line contains "dual-auth=ok") cannot be produced against this gateway: the fleet
gateway runs -forward (FORWARD=1, confirmed live by T-I over SSH and by the working 1.1.1.1 echo
forward probe T-P ran, 4/4 replies), and the canary's reflector leg requires a non-forward local
reflector. The attestation itself is proven by the fail-closed carrying handshake plus the
negative control, both against the fleet gateway itself.

## Missing target data

- T-I ios: carrying YES (see row above). before/after Mbps remain n/a by design: the contained dev
  session holds promotion (never claims routing/DNS) so no on-device throughput run can ride it,
  and iOS has no headless shell; the documented BEFORE baseline is the manual in-app production
  speed test (speed.cloudflare.com + cachefly) on the device network (Wi-Fi, private SSID). Tunnel
  counters and latency evidence are captured (t-i-*.txt set + t-i-ncu-probe.txt).
- T-M macos: no verdict file present at poll cutoff; all numbers n/a.
- T-P: no speed rows (attestation lane only).
- Gateway-side fact shared by all winn3-carrier lanes: data-sim drops inner ICMP echo to 10.10.0.1
  (INPUT policy), which is why reflector canary reflect legs fail and app promotion probes had to
  use DNS/TCP; durable fix is answering inner ICMP or running a reflector (noted by T-L and T-A).
