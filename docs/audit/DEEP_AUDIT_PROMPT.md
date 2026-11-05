# DEEP AUDIT PROMPT — Win's VPN (pre-production-deploy)

Give this entire prompt to the auditing AI. It is self-contained.

---

You are a principal security + reliability engineer performing a DEEP, ADVERSARIAL
pre-production audit of "Win's VPN", a censorship-resistant VPN operated by a US
501(c)(3). The user population is people inside Myanmar and comparable environments,
where being identified as a VPN user carries risk of detention or death. Therefore
**detectability is the primary security property; confidentiality is second.** Audit
accordingly: anything that lets a censor build a list of probable users is a P0.

Be thorough and adversarial. Do NOT modify any files. For EVERY finding report:
- Severity: P0 (ship-blocker) / P1 (high) / P2 (medium) / P3 (low)
- file:line
- The concrete failure/exploit scenario
- A minimal fix

## File map (read these first)

**Blueprints / handoff docs (the true full picture):**
- `/Users/owner/Documents/wins/source/wins_vpn/docs/blueprints/WINS_VPN_AND_WINN_PROTOCOL_BLUEPRINT.md` — product + protocol blueprint (what it is, threat model, design decisions).
- `/Users/owner/Documents/wins/source/wins_vpn/docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md` — complete handoff blueprint: architecture map, fleet inventory, secret LOCATIONS, rclone/litestream/Google-project details, deployment, current status. (Also in the `winsvpnv3` repo at `docs/blueprints/`.)
- `/Users/owner/Documents/wins/source/wins_vpn_deploy/Wins_VPN_Redeploy_Audit_Blueprint_2026-08-18.md` — pre-redeploy audit blueprint (protocol stack, fleet IPs, firewall/DNS model).

**Deployment scripts (primary audit targets):**
- Control hub: `/Users/owner/Documents/wins/source/wins_vpn/server/wins_control_plane_setup_ONETOUCH.sh`
- Data plane: `/Users/owner/Documents/wins/source/wins_vpn/server/wins_data_plane_setup_ONETOUCH.sh`
- Core double-VPN: `/Users/owner/Documents/wins/source/wins_vpn/server/wins_core_server_setup_ONETOUCH.sh`
- FDE user-data route: `deploy/make_ionos_user_data.sh` embeds `deploy/fde_boot_chain.sh`, the one supported converter. `deploy/ionos_fde_reinstall.sh` is retired and refuses to run, so it is not a conversion path to audit.
- Live-named copies: `/Users/owner/Documents/wins/source/wins_vpn/live/kansas_wins_control_plane_setup_ONETOUCH.sh`, `.../live/spain_wins_data_plane_setup_ONETOUCH.sh`

**App (Flutter):**
- Root: `/Users/owner/Documents/wins/source/wins_vpn/lib/`
- Entry: `lib/main.dart`; winn3 dispatch/verify: `lib/winn_protocol_dispatch.dart`; gateway failover: `lib/gateway_failover.dart`
- Platform shells: `android/ ios/ macos/ windows/ linux/ wear_os/` under the same root.

**Winn Protocol v3 (Go):**
- Root: `/Users/owner/Documents/wins/source/wins_vpn/winn_protocol_experimental/`
- Planes: `internal/protocol internal/pqauth internal/carrier winn3/core winn3/session`; gateways: `cmd/winn3-gateway cmd/winn3-probe cmd/winn-server`

**Ceremony / ring / secrets (locations only — never values):**
- Ring defines + manifest: `tools/winn3_descriptor_ring_defines.py`, `ceremony/ring-manifest.json` (in the app repo)
- Ceremony private keys: `~/.xprize/winn3-ceremony/{g1,g2,g3}.key` (0600)
- Hub master env: Kansas `/root/vpn_auth.env`; Mac copies `~/.xprize/redeploy/kansas_winsvpn-secrets.env`, `kansas_working.env`
- rclone/litestream: `~/.config/rclone/rclone.conf`, `~/.winsvpn/litestream-gcs.json`, `~/.winsvpn/kansas-backup-injection.env`
- Android keystore: `~/.winsvpn/android-release.keystore` + `android-release.env`

## What to audit

### A. The three deployment scripts (HIGHEST PRIORITY — command ordering matters a lot)
These are large bash scripts (~33k / ~10k / ~10k lines). Audit each for:
1. **Command ordering** — any step that runs before its prerequisite:
   - a service started before its systemd unit or config file is written
   - a firewall rule applied before the SSH-allow rule (SSH lockout risk)
   - a secret read before it is written, or a file sourced before it exists
   - a reboot gate (exit 75) whose resume path is not idempotent
2. **SSH lockout** — default-DROP firewall ordering vs the admin-SSH allow CIDRs.
3. **Secret handling** — any secret echoed to logs, written world-readable, passed in
   process args (visible in `ps`), or left in a temp file.
4. **Injection** — any unquoted variable in a shell command, SQL injection in sqlite
   writes, eval of untrusted input.
5. **Supply chain** — any curl/wget without `--proto '=https'` and a pinned SHA-256
   checksum verification of the downloaded artifact.
6. **litestream/durability** — confirm `litestream.service` carries
   `GOOGLE_APPLICATION_CREDENTIALS` and `litestream.yml` has the replica URL.

Scripts:
- Control hub:  `server/wins_control_plane_setup_ONETOUCH.sh`
- Data plane:   `server/wins_data_plane_setup_ONETOUCH.sh`
- Core (double-VPN): `server/wins_core_server_setup_ONETOUCH.sh`

### B. The Flutter app (`lib/`)
1. Any hardcoded secret/API key/token in the Dart code.
2. `lib/winn_protocol_dispatch.dart` — is the winn3 descriptor signature VERIFIED
   before connect? Any bypass? Is the ring digest attested correctly?
3. `lib/gateway_failover.dart` — can a malicious recovery file inject a gateway URL?
   Is the recovered gateway allowlist-validated?
4. Insecure storage of keys/tokens on device; any secret logged.

### C. The Winn Protocol v3 Go implementation (`winn_protocol_experimental/`)
1. winn3 handshake (winn3/core, winn3/session): replay protection, rekey correctness,
   any crypto misuse, weak/broken crypto.
2. Carrier plane (internal/carrier): injection or auth bypass.
3. Control plane (internal/protocol, internal/pqauth): signature verification, auth bypass.
4. Any secret in logs.

### D. Smart routing / failover
1. The routing cascade (Winn v3 deterministic -> Gemma -> Gemini -> deterministic
   fallback): any path where a failed route is still selected.
2. The active-gateway recovery file: can a compromised recovery file inject a gateway?
3. The edge router (if present): injection or auth bypass.

## Context (so you don't flag design decisions as bugs)
- Protocol stack: v3 primary (winn3 carrier, PQ-hybrid TLS x25519-mlkem768, 24h key
  TTL); v1 backup (Xray VLESS-WS Cloudflare-fronted -> AmneziaWG). v1 is an intentional
  fallback, not a bug.
- The app currently refuses winn/3 at runtime behind a governance on-switch; that is
  intentional until the on-switch is flipped.
- Litestream replicates the hub SQLite to GCS (not Drive — litestream can't use Drive).
- Fleet IPs are fixed provider IPs. The control-hub IP is deliberately withheld from
  public docs.
- Non-goals (do NOT report as vulnerabilities): endpoint compromise, global passive
  end-to-end correlation, DoS/availability, anonymity from the operator at the IP layer,
  the AmneziaWG crypto core itself, physical/legal coercion.

## Output format
Return:
1. A ranked list of findings, P0 first, each with severity, file:line, scenario, fix.
2. A verdict: READY-TO-DEPLOY / NOT-READY, with the exact P0/P1 list that must be
  fixed first.
3. A short "what I could not verify" list (anything you lacked access/context for).
