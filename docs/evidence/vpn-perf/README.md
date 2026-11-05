# Live VPN evidence — 2026-08-21

Two real machines on the owner LAN, one tunnel, recorded live:

- Gateway: `aicore` 192.168.50.10 (Ubuntu x86_64), `winn3-gateway -mode serve`
  UDP 51833, X25519 serve keys + admission key + dual-signature attestation
  keys armed (`auth_ed25519`, `auth_mldsa65`), TLS/ECH cover supplied in lab
  mode (insecure-cover flags). See `serve_aicore.log`.
- Client: this MacBook (darwin/arm64), `winn3-probe -canary` across the LAN.

`live_run_20260821.txt`:
- pre-VPN baseline: ICMP RTT + 400MB LAN file push (no VPN) throughput.
- post-VPN: canary verdict `handshake=ok replay-safe=ok rekey=ok reflect=ok`
  (49 inner packets sent, 48 received, 0 invalid, epoch=2, rekeys=1).
- dual-auth attestation was server-armed this run; probe-side dual-auth flag
  parse blocked the pair form, so the on-wire dual-attestation verdict from the
  local runtime proof (2026-08-20, `winn_conformance_results/`) stands for that
  leg. Per-device app-level runs (Android/iOS/Windows/Linux) + tunneled bulk
  throughput remain the follow-up measurement set.
