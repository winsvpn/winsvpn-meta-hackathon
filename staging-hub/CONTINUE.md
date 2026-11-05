# CONTINUE.md - Staging Hub (Lane B) resumption notes

## Where this lane stands

- winn/3 vpn_config conversion is COMPLETE in `app.py` (protocol_version
  "winn/3", protocol_params.carrier "winn3", winn3_inner_v4 sticky per
  device+node from subnet .2 with descriptor gateway addresses reserved,
  winn3_static_private minted once per device via openssl X25519 raw-32,
  winn3_descriptor served byte-verbatim from `DESCRIPTORS_DIR/<slug>.json`
  or nodes.json placeholder, node_slug, dns, mtu). ALL AWG fields and the
  paramiko/SSH peer-push path are dropped.
- Router consult: 12s timeout default (`ROUTER_TIMEOUT_S`), fail-open
  deterministic fallback, selection enforced; live router verified
  (POST /route returns gemini decisions in ~3.0-3.5s; /health and /decisions OK).
- Tests: 20/20 pass (`python3 -m pytest -q` in .venv).
- FIELD_MAP.md: complete field table with source line citations and
  machine-checked status column.
- LIVE-OPS pass (2026-08-17): REAL TCP gateway probes on `/nodes` (at most
  every `PROBE_CACHE_S` 30s) and `/admin/probe` (3s timeout); failed probe
  marks the node unreachable + increments `recent_failures`, success recovers;
  `/admin/state` now has `uptime_s` + per-node `latency_ms`/`last_probe_ts`;
  `STATE_FILE` env honored (default `./state.json`), README deploy line
  documents `-e STATE_FILE=/srv/hub/state.json` + `/srv/wins-hub:/srv/hub`.

## Immediate next steps (in order)

1. Supervisor: run tools/winn3_sign_descriptor.py ceremony, land
   `descriptors/demo-route-a.json` + `descriptors/demo-route-b.json` in this
   directory (or DESCRIPTORS_DIR mount at deploy). Until then free-verify
   serves `winn3_descriptor: {}` + demo_provisioning reason
   "descriptor-not-landed".
2. Supervisor: build the debug APK with the SPEC v2 dart-defines
   (WINS_GATEWAY_BASE/BASES, WINS_HUB_HOST, WINS_WINN3_ENABLED_PLATFORMS,
   WINS_WINN3_DESCRIPTOR_PUBKEY_G1, WINS_WINN3_DESCRIPTOR_RING_SHA256).
3. Deploy the twin behind Caddy on the sslip.io name (Dockerfile unchanged;
   mount descriptors + writable state dir; README has the run command).
4. End-to-end carry run against demo-route-a/b once gateways are up.

## Gotchas pinned for the resumer

- The twin NEVER verifies descriptor Ed25519 signatures (no ceremony keys in
  this lane) and never re-encodes envelopes: served verbatim, shape-checked
  only (base64, 4096-byte ceiling, JSON object, v==3, node==slug, lifetime).
- A landed descriptor file that fails identity checks is served as {} with a
  loud log (fail closed), never downgraded to the nodes.json placeholder.
- winn3_static_private is per DEVICE (not per node) and sticky; never logged,
  never echoed in /admin/state (only static_public + material_source).
- mtu 1280 is inert-but-present exactly as the real hub serves it; the v3
  datapath sizes from winn3_path_mtu ("1450", classes "udp").
- dns "1.1.1.1,1.0.0.1" is the SPEC v2 pin; the twin serves it verbatim
  (the v1-era single-IP caveat no longer applies: main.dart:4811-4822 splits
  the comma list per server).
- Do NOT revert the router timeout to 2s: SUPERVISOR_NOTES.md requires 12s.
- Probes are REAL TCP connects with a 3s timeout; in tests they are always
  socket-mocked (the suite must never touch the network). Auto-probe is gated
  by `PROBE_CACHE_S` so /nodes stays fast between passes; `/admin/probe` forces
  a pass and resets the window. A successful probe RECOVERS a manually flipped
  node (probe reflects reality in addition to the manual flip).
