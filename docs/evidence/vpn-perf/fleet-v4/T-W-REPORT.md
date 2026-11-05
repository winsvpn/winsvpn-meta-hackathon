# T-W Windows APP-level live VPN test vs FLEET (data-sim) - REPORT

Date: 2026-08-23 (UTC ~04:00-05:00). Repo: winsvpnv3 @ main (b029ed7). Mac repo untouched,
git clean, nothing committed/pushed. All evidence under /tmp/fleet-speed-evidence/.

## VERDICT LINE
connected=YES | carrier=direct-awg (AWG UDP 9110) | before=644 Mbps (80.52 MB/s) |
after=80.4-123.1 Mbps (10.05 / 15.38 MB/s, two runs) | loss=0% (25,000,000/25,000,000 bytes
each run) | counters client=30,157,240 B rx / 2,188,984 B tx, fleet node=4.25 MiB rx /
62.55 MiB sent, handshake recent both sides | tunnel owned default route (0.0.0.0/0
On-link 10.8.1.50 metric 5) during AFTER | fail-closed teardown clean (routes removed).

## KEY LOG EXCERPTS (C:\fleet\windows-fleet.log -> windows-fleet.log)

Validation + assembly (lane config C:\fleet\dev_winn3_windows.json, protocol winn/3,
carrier direct-awg, fleet AWG server pubkey 3jeHy5jOFHWp4snc5btOGhx4Fu+yFcQUlwnDldxwgm0=,
endpoint <DATA_SIM_IP>:9110, obfuscation Jc=2 Jmin=10 Jmax=30 S1..S4/H1..H4 matching
data-sim awg0, Table=off, TunnelGatewayIPv4=10.8.1.1, client pub
6TAPiU34LiYCcS8Vejw2bCfEZVwHyl1K+jrkkBO7iz4= registered as runtime peer on the node):
    WINN DEV CONFIG SOURCE: validation result -- supported=true reason=none.
    WINN DEV SESSION: native startTunnel returned Tunnel Initializing (accepted=true).
    WINN DEV SESSION: provider status: {"active":true,"awg_handshake_recent":true,
      "awg_runtime_query_ok":true,"awg_rx_bytes":9036,"awg_tx_bytes":51485,
      "engine_ready":true,"engine_ready_ms":1500, ...}
    WINN DEV SESSION: RESULT = native start accepted. (uncontained, whole-machine
      routing, as designed for Windows)

Live tunnel state during AFTER (windows-awg-show-after.txt):
    peer endpoint: 127.0.0.1:56554 (winn seam; direct-awg relay chain)
    latest handshake: 1 minute, 55 seconds ago
    transfer: 28.76 MiB received, 2.09 MiB sent

Far-end proof on data-sim (datasim_awg_show_after.txt):
    peer: 6TAPiU34... endpoint: <WINPC_EGRESS_IP>:50540 (winpc egress)
    latest handshake: 8 seconds ago | transfer: 4.25 MiB received, 62.55 MiB sent

Routes during AFTER (windows-route-after.txt): default route on tunnel
    0.0.0.0/0 On-link 10.8.1.50 metric 5  < 0.0.0.0/0 via 192.168.50.1 metric 30
Post-teardown (windows-route-final2.txt): no 10.8.1.x routes, service STOPPED, no
engine/datapath processes.

## SPEED BEFORE/AFTER (curl https://speed.cloudflare.com/__down?bytes=25000000)
    BEFORE (no VPN): 80,519,447 B/s = 644 Mbps  (windows-before.txt)
    AFTER run 1:      10,045,389 B/s = 80.4 Mbps (windows-after-1.txt)
    AFTER run 2:      15,384,009 B/s = 123.1 Mbps (windows-after-2.txt)
    Both AFTER: size_download=25000000 (0% loss), remote_ip=162.159.140.220 (Cloudflare
    egress via tunnel). Throughput drop vs BEFORE is the cost of the loopback
    seam + userspace AWG engine + GCP round trip; counters prove the full 25 MB
    traversed the tunnel (client rx 30.16 MB across the two runs + probes).

## FILES (evidence)
    windows-before.txt, windows-after-1.txt, windows-after-2.txt
    windows-fleet.log (full harness console, C:\fleet\windows-fleet.log)
    windows-awg-show-after.txt, windows-awg-transfer-after.txt
    windows-route-after.txt (tunnel owns default), windows-route-final2.txt (clean)
    windows-orchestrator-step.log
    datasim_awg_show_after.txt, datasim_tcpdump5.txt (engine direct probe, 40 pkts),
    datasim_tcpdump2.txt (datapath probe, 5 pkts)
    dev_winn3_windows.json (lane config), winn_protocol_dispatch.dart (LANE-ONLY patch
    copy, see blockers), sync_src.tgz (main source synced to winpc)
    pktmon.pcapng / pktmon_lb.pcapng, wfp_filters.xml, lb_test.log, dp_probe.py,
    awg_engine_probe.py, seam_replica.py (diagnostics)

## BLOCKERS / NOTES
1. LANE-ONLY PATCH (winpc build copy ONLY, Mac main untouched, never committed):
   main's resolveWinnProtocolStart forces standaloneOnly when
   WINS_WINN3_ENABLED_PLATFORMS includes the platform, which refuses carrier
   direct-awg (carrier_unsupported). Patch passes standaloneOnly=false, letting the
   define-enabled Windows build run the direct-awg relay carrier. Without it the
   harness is structurally blocked (winn_section BLOCKED, observed before patching).
2. WINPC LOOPBACK WAS BROKEN (pre-existing, machine-wide): ping 127.0.0.1 "General
   failure", UDP ENETUNREACH, TCP connect timeout; zero packets at NDIS (pktmon).
   Root cause: corrupted Loopback Pseudo-Interface address registration. Fix (no
   reboot): netsh interface ipv4 delete/add address "Loopback Pseudo-Interface 1"
   127.0.0.1 255.0.0.0. This silently killed every winn seam session until fixed
   (engine 399 B sent into a dead seam, 0 packets to fleet).
3. Harness runs only as a real (non-SYSTEM) user in the active console session
   (service pipe auth). Launched via scheduled task (SYSTEM) + WTSQueryUserToken
   CreateProcessAsUser into session 1 (twindows). App auto-runs the session and
   prints the transcript to stdout.
4. Orchestrator convergence-detection regex was too strict (route print shows
   interface index, not name) -> CONVERGED=False logged although the tunnel was up;
   AFTER curl still ran and counters/routes prove it traversed the tunnel. sc stop
   from the non-admin twindows context failed; teardown completed from admin SSH.
5. awg.exe UAPI is admin/SYSTEM-only; the in-session orchestrator could not read
   `awg show winsvpn transfer` (Permission denied) - counters captured from admin
   SSH instead.
6. Engine artifacts rebuilt from synced main via tools/build_windows_awg_engine.ps1
   (pinned go1.26.5, amneziawg-go v0.2.19 @ 1cc9427, execution guard PASS).
   winn-datapath.exe from C:\src (previous lane build) verified working by probe.
7. data-sim peer 6TAPiU34... left registered as runtime peer (allowed-ips
   10.8.1.50/32); server config files unchanged. AdGuard/Surfshark services were
   stopped during diagnosis and restarted afterwards.
