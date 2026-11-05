# Win's VPN + Winn Protocol — Complete Handoff Blueprint

**Written:** 2026-08-19 · **Audience:** any engineer or AI picking this up · **Classification:** private — contains secret LOCATIONS but NO secret values.

See AI_HANDOFF_20260823.md for the full 2026-08-23 state.

> Read this first. It is the single true-full-picture document: what the product is,
> the architecture, where every file and every secret lives, and how it deploys.
> It supersedes older handoff briefs where they conflict.

---

## 1. What this is

Win's VPN is a real product of a US 501(c)(3) nonprofit: a privacy / anti-censorship
VPN with calculator camouflage, priced ~$0.99/month, built for people inside Myanmar
and comparable environments. The founder's parent was assassinated by the Myanmar
junta in 2025; that fact sets the severity ordering of every design decision:

> **Detectability is the primary security property. Confidentiality is second.**
> A weakness that lets a censor build a list of probable users outranks a
> confidentiality weakness. "The fact that a user runs Winn at all" is the top asset.

Two artifacts, do not conflate them:

| Artifact | What | State |
|---|---|---|
| **Win's VPN** (the app) | Flutter client `org.winsvpn.app`, Android/iOS/macOS/Windows/Linux/Wear OS/watchOS. Shipping tunnel today = AmneziaWG + optional Xray (this is "protocol v1"). | Shipping |
| **Winn Protocol v3** | Post-quantum protocol in `winn_protocol_experimental/` (Go module `winsvpn.local/winnprotocol`): PQ-hybrid-TLS PSK-rotation control plane + a carrier plane that moves AWG datagrams across a hostile network. | Being shipped as primary; v1 stays as fallback |

**Shipping model (owner mandate):** standalone Winn Protocol **v3 is primary**. Winn Protocol **v1 is the compatibility backup** in both the apps and the servers when v3 cannot connect. The default v1 attempt order is current AmneziaWG (AWG) first, then current Xray only when AWG is unsuccessful. Previously observed network failures may demote AWG behind Xray for that network without removing either option.

**Patent-sensitive:** `winn_protocol_experimental/` must not be disclosed PUBLICLY before patent-counsel approval. All repos here are PRIVATE, so keeping it in-repo is acceptable; never paste it into a public surface.

---

## 2. Protocol stack

- **v3 (primary):** Winn Protocol v3 carrier. Suite `x25519-mlkem768`, key TTL 24h. Data-plane external firewall labels: TCP 8443 "Winn v3 carrier", UDP 9111 "Winn v3". Signed per-node descriptors + per-device inner IPv4.
- **v1 (backup):** First attempt: direct AmneziaWG over UDP 9110. If that is unsuccessful, attempt Xray VLESS-WS on the advertised TCP cover transports. Successful v1 traffic then reaches AdGuard Home DNS (127.0.0.1:53) and the internet. Labels: TCP 80 "Winn v1 decoy", UDP 9110 "Winn v1 AWG", TCP 443 "Cover TLS front".
- **Release versions:** Before each release freeze, resolve the latest stable upstream toolchain and shipped dependency versions. Exclude beta, RC, preview and nightly releases. Freeze the selected exact versions, revisions and hashes only after compatibility and security gates pass on all supported platforms.
- **Cover/stealth:** nginx cover site on 127.0.0.1:80/443; ECH cover name `<ECH_COVER_NAME>` (Spain); stealth zone `app-cloud-sync.net` on a SEPARATE Cloudflare account with 26 records `a..z.app-cloud-sync.net`.
- Two version namespaces (both correct): `protocol.Version = winn/2` (rekey control plane) vs `connectivity.Version = winn/3` (datapath).

**Routing cascade (decisions, not traffic):** (1) Winn v3 deterministic local routing when fleet healthy (zero AI cost). (2) For VPN connection initiation and distress routing, the target Smart Router consults local Gemma on the `aicore` RTX 5060 Ti and may consult the Google API, with every result constrained to an authenticated candidate set. (3) Timeout, malformed output, model outage, API outage, or an out-of-set choice falls back immediately to deterministic routing. AI never carries VPN traffic and is never the sole connectivity path.

---

## 3. Repositories (source of truth)

| Repo | Role | Visibility |
|---|---|---|
| **`winsvpn/winsvpnv3`** | **PRODUCTION source of truth** — full app codebase + protocol + deploy scripts + XPRIZE evidence. | private |
| `winsvpn/winsvpnv1` | Cleaned, history-free archive of legacy v1 (app/site/server). Deliberately stripped backup keys, live gateway notes, subscription notes, and binary artifacts. | private |
| `winsvpn/wins_vpn_private_sync` | Earlier private working copy (predates the winsvpnv3 consolidation). | private |

All three are **private** (GitHub returns 404 unauthenticated). SSH deploy key on the build Mac: `~/.ssh/winsvpn_deploy_ed25519` (reaches the fleet); GitHub push key `~/.ssh/id_ed25519_winsvpn_github`.

---

## 4. Fleet inventory (production)

| Host | IP | Provider | Role |
|---|---|---|---|
| **Kansas** | (control-hub IP withheld — see `IONOS_HUB_IP` in the hub credential file) | IONOS | **Control hub** — FastAPI/uvicorn on 127.0.0.1:8000, nginx 127.0.0.1:80/443, cloudflared control tunnel, Suricata, fail2ban, sqlite `vpn_users.db`. Ext FW: 22,80,443,2222 |
| **Spain** | `<NODE_SPAIN_IP>` | IONOS | **Data plane + Crypto Payment Gateway** (Winn v3, Xray/AWG, BTCPay Server for Bitcoin and Dash with pruned storage, Monero view-only wallet RPC). Ext FW: 22,8443,80,443; UDP 9110,9111 |
| Data planes | Germany `<NODE_GERMANY_IP>` · Netherlands `<NODE_NETHERLANDS_IP>` · France `<NODE_FRANCE_IP>` · US Chicago `<NODE_US_CHICAGO_IP>` · Canada OVH `<NODE_CANADA_IP>` · UK OVH `<NODE_UK_IP>` · Oregon `<NODE_OREGON_IP>` · Singapore `<NODE_SINGAPORE_IP>` | various | Data planes (same data-plane script) |
| **Core** | north-america-core | — | Double-VPN core, `app-cloud-sync.net` stealth zone |
| Gemini demo router | Cloud Run `winsvpn-ai-router` (us-central1) | GCP | Existing Gemini decision service with deterministic fallback; not equivalent to the target Smart Router until the initiation contract is reconciled |
| **aicore** | `192.168.50.10` (LAN) | home RTX 5060 Ti | Target local Gemma routing/support brain. Exact latest-stable model, quantization, serving runtime, API contract, and measured GPU fit must be frozen only after live validation |
| Owner admin IP | `<OWNER_ADMIN_RESIDENTIAL_IP>` | residential | The HUB_ADMIN_SSH_CIDRS allow-listed admin source. Value lives in root-only secrets on the hub, NOT in this repo |
| GCE sims | control-sim, data-sim, core-sim, xprize-hub, route-a/b | GCP | Throwaway simulation VMs |

> All fleet IPs above are FIXED provider IPs (owner confirmed they are fine to
> keep in this private repo). The matching credentials live in the files in §6.

### 4b. BUILD / TEST MACHINE ACCESS (owner-confirmed 2026-08-21)
HOW TO REACH THE LAN/RACK MACHINES THAT BUILD AND TEST THE APP ON EVERY OS.
The machines move IPs; these are the CURRENT entries, pre-wired as ssh aliases
in `~/.ssh/config` on the Mac. DO NOT re-derive these by guessing users/ports:
every alias below is tested and working.

| Alias | Host | IP | OS / arch | SSH user | Key file on the Mac |
|---|---|---|---|---|---|
| `ssh <aicore-SSH-ALIAS>` | linux-host (the 5060 Ti box) | `192.168.50.10` | Ubuntu / **x86_64**, 16 cores, has docker | `aicore` | `~/.ssh/id_ed25519_winpc` |
| `ssh <winpc-SSH-ALIAS>` | Samsung laptop (WINDOWS-HOST) | `192.168.50.19` | **Windows 11 x64** (10.0.26200) | `windows-user` | `~/.ssh/id_ed25519_winpc` + `~/.ssh/id_rsa_winpc` |
| `ssh <yoga-SSH-ALIAS>` | Lenovo Yoga (slim7x) | `192.168.50.226` | Ubuntu / **aarch64**, 12 cores | `root` | `~/.ssh/id_ed25519_yoga` |

Notes that previously cost hours (read these before touching the boxes):
- Windows (`winpc`) opens an OpenSSH server on port 22; remote commands run under
  cmd.exe, so use `&` / `&&` separators, NOT `;`. Example:
  `ssh <winpc-SSH-ALIAS> "whoami & hostname & ver"`.
- `aicore` did NOT move to a remote Hetzner IP; old ssh-config entries pointing at
  an old public Hetzner IP (see ~/.ssh/known_hosts_aitraining for the literal) are STALE. Its historical sshd port was 14636 (see
  `known_hosts_aitraining`) — ignore it; use port 22 via the alias.
- Windows-on-ARM64 VM on the Yoga (QEMU, TCG emulation, no KVM): **SSH-accessible
  through the Yoga host** — two hops, no new aliases needed:
  `ssh <yoga-SSH-ALIAS> "ssh -i /home/yoga/.ssh/winguest_ed25519 -p 12222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null winsvpn@127.0.0.1 \"...\""`.
  Port 12222 on the Yoga forwards to the guest's port 22; key
  `/home/yoga/.ssh/winguest_ed25519` lives on the Yoga (NOT on the Mac). Guest
  facts that previously cost hours:
  - VM name `win11arm64elev`; booted by `/home/yoga/winvm/boot_win11_elev.sh`
    (cortex-a76, 6 vCPU, 6 GB RAM, `-accel tcg,thread=multi`). Disk
    `/home/yoga/winvm/win11_elev.qcow2`; NVRAM `AAVMF_VARS.elev.fd`; RDP forwarded
    to the Yoga host port 13389; QEMU monitor on `mon.sock`, serial on
    `serial_elev.log`.
  - Guest OS = Windows 11 ARM64 build 10.0.26200, hostname `winsvpn-arm64`, local
    admin user `winsvpn`.
  - Flutter = `C:\Users\winsvpn\flutter\bin\flutter.bat` (NOT on `%PATH%`). Assume
    the SSH default shell is cmd.exe (`&` separators). Go/cmake not on PATH.
  - App source tree inside the VM: `C:\wv` (a file-uploaded dev snapshot, no git).
  - Arm64 build output: `C:\wv\build\windows\arm64\runner\Debug\` (`wins_vpn.exe`,
    `wins_vpn_tunnel_service.exe`, `flutter_windows.dll`).
  - Rebuilds may hit `LNK1168 ... wins_vpn_tunnel_service.exe for writing` — a
    stale link/msbuild holds the file; fix with
    `taskkill /F /IM wins_vpn.exe & taskkill /F /IM wins_vpn_tunnel_service.exe & taskkill /F /IM msbuild.exe & taskkill /F /IM link.exe`
    and rebuild. Long builds: run via `schtasks /create /tn wvarm64build /tr "cmd /c cd /d C:\wv && C:\Users\winsvpn\flutter\bin\flutter.bat build windows --debug > C:\wv\arm64build.log 2>&1" /sc once /st 23:59 /f` then `schtasks /run /tn wvarm64build` so the build survives SSH disconnect; poll `C:\wv\arm64build.log`.
  - A prior session already built this VM from
    `Win11_25H2_English_Arm64_v2.iso` (unattended install via `unattend.template.xml`);
    the ISOs stay at `/home/yoga/winvm/`.
- Apple builds (macOS/iOS/watchOS) run on this MacBook with: team `5YT8H4U72M`,
  App Store Connect key `~/.appstoreconnect/private_keys/AuthKey_REDACTEDKEY.p8`,
  Keychain identities (Apple Development: <OWNER_NAME> / Apple Distribution +
  Developer ID: Win's VPN Inc), and the real macOS signing profile
  `~/.winsvpn/apple/Signing.xcconfig.macos`. The Apple c-archives come from
  `tools/build_winn_protocol_engine.sh` targets (`datapath-ios-arm64`,
  `datapath-iossimulator-arm64`, `datapath-archive-darwin-arm64`,
  `datapath-archive-darwin-amd64`) into `tools/winn_conformance_build_out/`,
  and `apple/EngineArtifacts` must be present (copy from the dev tree if absent).

---

## 5. Directory map (where files live)

Inside the production repo (`winsvpnv3`):
- `lib/` — Flutter app (Dart). `lib/main.dart` (app entry; carries the winn/3 on-switch), `lib/winn_protocol_dispatch.dart` (v3 descriptor verify + ring attestation), `lib/gateway_failover.dart` (recovery/anti-censorship gateway selection).
- `android/ ios/ macos/ windows/ linux/ wear_os/` — platform shells + tunnel providers.
- `winn_protocol_experimental/` — Go protocol (control/carrier/data planes, `cmd/winn3-gateway`, `cmd/winn3-probe`, `cmd/winn-server`). **Patent-sensitive.**
- `server/` — deployment scripts: `wins_control_plane_setup_ONETOUCH.sh` (hub), `wins_data_plane_setup_ONETOUCH.sh` (data plane), `wins_core_server_setup_ONETOUCH.sh` (double-VPN core).
- `deploy/` + `live/` — deploy artifacts + the live-named ONETOUCH scripts (`kansas_wins_control_plane_setup_ONETOUCH.sh`, `spain_wins_data_plane_setup_ONETOUCH.sh`).
- `extension/` — Chrome/Firefox browser extension (MV3, one source tree, per-browser manifest).
- `tools/` — build/test tooling (`test_winn3_release_enablement.py`, `winn3_descriptor_ring_defines.py`, blueprint PDF generator).
- `docs/blueprints/` — blueprints including this one.
- `router/ staging-hub/ winn3-nodes/ evidence/ dashboard/ video/` — XPRIZE demo (Gemini router, staging control twin, demo gateways, evidence pack).

On the build Mac (this machine), outside the repo:
- `~/.winsvpn/` — Android release keystore + env, Apple signing export config.
- `~/.xprize/` — ceremony keys, sim-control assets, backups.
- `~/.ssh/` — fleet + GitHub keys.

---

## 6. Where secrets live (LOCATIONS ONLY — never values in this doc)

| Secret | Location | Notes |
|---|---|---|
| **Hub master env** (ADMIN_TOKEN, Cloudflare tokens+zone IDs, PayPal live, SMTP, BTCPay, Monero, double-VPN, SITE_AI) | Kansas `/root/vpn_auth.env`; latest Mac copies `~/.xprize/redeploy/kansas_winsvpn-secrets.env` and `~/.xprize/redeploy/kansas_working.env` (0600) | The production master secret file |
| Control-sim env | `~/.xprize/redeploy/controlsim-secrets.env` (0600) | GCE simulation hub |
| Hub env backup | Mac `~/.xprize/backups/kansas-backup-*.tgz` (contains `root/vpn_auth.env.bak_*`, `etc/winn/server.env`) | Full Kansas backup, 0600 |
| **Winn v3 ceremony keys** G1/G2/G3 Ed25519 private | Mac `~/.xprize/winn3-ceremony/{g1,g2,g3}.key` | 0600, NEVER in git. Pubkeys + ring manifest in-repo at `tools/winn3_descriptor_ring_defines.py` + `ceremony/ring-manifest.json` |
| Android release keystore | Mac `~/.winsvpn/android-release.keystore` + `android-release.env` (WINS_ANDROID_KEYSTORE/KEY_ALIAS/KEY_PASSWORD/STORE_PASSWORD) | Losing it = can never update the Play listing |
| Apple distribution | macOS keychain: "Apple Distribution: Win's VPN Inc (5YT8H4U72M)", "Developer ID Application: Win's VPN Inc"; provisioning profiles in `~/Library/Developer/Xcode/UserData/Provisioning Profiles` | |
| Stealth tunnel token (app-cloud-sync.net) | Build Mac, 0600 | Second Cloudflare account |
| Sim preseed | `xprize/sim-control/simassets/winsvpn-secrets.env` | SIM stubs, not production |

**Integration credential status (verified 2026-08-19):**
- Cloudflare: ✅ token ACTIVE, reads `winsvpn.org` zone.
- PayPal: ✅ live OAuth works.
- ADMIN_TOKEN: ✅ real.
- SMTP2GO: ✅ **configured + verified** (SMTP_USER=winsvpn.org, SMTP_PASS set, STARTTLS auth to mail.smtp2go.com:2525 confirmed). Security alerts go to SECURITY_ALERT_EMAIL.
- Litestream: ✅ **configured + enabled.** Replicates the hub SQLite DB to GCS (`gs://winsvpn-litestream-kansas-<GCP_PROJECT_NUMBER>/vpn_users`) for near-zero data loss (RPO-0). Litestream cannot replicate to Google Drive, so it uses a billed GCS bucket in the same Google project (`wins-vpn-rclone-backup`). `DURABILITY_BARRIER_ENABLED/REQUIRED` default to 1. Service account `litestream-replica@wins-vpn-rclone-backup.iam.gserviceaccount.com` writes the replica prefix. The installer now writes `/etc/litestream.yml` (replica URL) AND a `litestream.service` systemd unit carrying `GOOGLE_APPLICATION_CREDENTIALS` (defaults to `/root/winsvpn-secrets/litestream-gcs.json`), so replica writes authenticate automatically. Hub-only; data planes have no litestream.
- rclone: ✅ **configured.** Remotes `GoogleDrive_base:` (Drive) and `GoogleDrive_secured:` (crypt over `IONOS_Kansas_backups`). OAuth via the existing Desktop app in project `wins-vpn-rclone-backup`. Crypt passwords kept from the prior config so older Drive backups still decrypt. Config at `~/.config/rclone/rclone.conf` / `~/.winsvpn/rclone.conf` (0600). For Kansas: copy `rclone.conf` + `litestream-gcs.json` to `/root/winsvpn-secrets/` and set `RCLONE_CONFIG_SOURCE` + `LITESTREAM_REPLICA_URL` from `~/.winsvpn/kansas-backup-injection.env`.

---

## 7. Deployment

Three ONETOUCH bash scripts (order matters; they are fail-closed and reboot-aware):
1. **Control hub** `wins_control_plane_setup_ONETOUCH.sh` → Kansas. Self-contained; writes `/etc/winsvpn/role=control`; two-phase reboot gate (exit 75 → reboot → re-run).
2. **Data plane** `wins_data_plane_setup_ONETOUCH.sh` → each data-plane VPS. Stages winn3-gateway + cover/ECH creds, protocol-gated firewall, AdGuard DNS.
3. **Core** `wins_core_server_setup_ONETOUCH.sh` → double-VPN core.

Pre-requisites per host: SSH pubkey at `/root/.ssh/authorized_keys`, FDE/LUKS chosen at provider image time (scripts enforce-but-don't-retrofit root encryption), secrets preseed at `/root/winsvpn-secrets.env`.

**FDE:** the root filesystem is LUKS-encrypted while a separate `/boot` and EFI system partition remain unencrypted. No keyfile or GRUB cryptodisk path is used. Every boot requires interactive unlock through dropbear on port 2222 (`cryptroot-unlock`) or the provider VNC console. Deliver `/root/.winn-fde-pass` separately as a root-owned, single-link 0600 file containing 32 to 4096 bytes with no newline or edge whitespace. Never place it in provider user-data. `fde_boot_chain.sh` performs the supported offline pre-mount conversion and reaches an IONOS host through the user-data text that `deploy/make_ionos_user_data.sh` builds; `ionos_fde_reinstall.sh` is retired and refuses to run. Guest, credential-transition, and provider-control-plane closure are separate mandatory evidence boundaries defined in `docs/FDE_CUSTODY_CLOSURE.md`.

**Website (winsvpn.org / winsvpn.com) — Cloudflare Pages, project `winsvpn`:** Published by **direct upload, NOT git-push**: `npx wrangler pages deploy <dir> --project-name winsvpn` (account `065fa9aa4dfc90ab7c347694eccdaea3`). Pushing the repo does not publish the site. Three machine gotchas, all hit during the 2026-08-20 deploy:
1. **Node TLS is broken on this Mac** — Node's bundled CA store fails every HTTPS call with `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` (curl works, Node doesn't). Prefix wrangler with `NODE_EXTRA_CA_CERTS=/etc/ssl/cert.pem`.
2. **Non-interactive wrangler requires `CLOUDFLARE_API_TOKEN`** — it will not use the stored OAuth login in a non-TTY shell. OAuth state lives in `~/Library/Preferences/.wrangler/config/default.toml` (`oauth_token`, `expiration_time`, `refresh_token`); the access token lives ~1h.
3. **Refreshing the expired OAuth token (the non-obvious part):** the stored `refresh_token` stays valid and mints a new access token without `wrangler login` — `POST https://dash.cloudflare.com/oauth2/token` with `grant_type=refresh_token`, `refresh_token=<value from default.toml>`, `client_id=54d11594-84e4-41aa-b438-e81b8fa78ee7`. The response returns a new `access_token` (`expires_in`≈3599s) and a rotated `refresh_token`; write both back into `default.toml` (preserve `scopes`) and use the `access_token` as `CLOUDFLARE_API_TOKEN`. Never print or commit either token.

Deploy a **clean copy** of `web/` (rsync excluding `downloads/`, `*.bak*`, `._*`, `__pycache__`, `.wrangler`, `*.py`, `winn3-dev-override.*`, `wrangler.jsonc`). Downloads stay excluded until the exact signed artifacts, sidecars, and receipts pass the public download custody gates. Direct artifacts at or below Cloudflare Pages' 25 MiB per-file limit may be included only by that later publication lane; larger files require a separately reviewed same-origin delivery design. GitHub Releases remain backup storage and are not website publication authority. After deploy, verify every dedicated legal URL with a cache-buster; the homepage inline Privacy Policy and `/privacy/` must carry the same `Version <date>.vN` as `legal/MASTER_LEGAL_DOCUMENT.txt`.

---

## 8. Complete architecture map

**Google account / project (backups + durability):**
- Google account: `admin@winsvpn.org`.
- Google Cloud project: `wins-vpn-rclone-backup` (billed).
- rclone OAuth client: existing Desktop app in that project (new client secret + refresh token).
- rclone remotes: `GoogleDrive_base:` (Drive) and `GoogleDrive_secured:` (crypt over `IONOS_Kansas_backups`).
- Litestream GCS bucket: `gs://winsvpn-litestream-kansas-<GCP_PROJECT_NUMBER>/vpn_users`; service account `litestream-replica@wins-vpn-rclone-backup.iam.gserviceaccount.com`.
- Drive quota seen: 435 GiB used of 5 TiB.

**Control plane (Kansas):** FastAPI/uvicorn hub on 127.0.0.1:8000 behind nginx + cloudflared control tunnel; sqlite `vpn_users.db` replicated by litestream to GCS; Suricata IDS/IPS + fail2ban; Cloudflare tokens for `winsvpn.org`/`winsvpn.com` zones.

**Data plane (each VPS):** winn3-gateway (v3 carrier, TCP 8443 + UDP 9111) + Xray/AWG (v1 backup, UDP 9110), protocol-gated firewall, AdGuard Home DNS (127.0.0.1:53) with failover upstream chain (Quad9 → OpenDNS → DNS4EU → Cloudflare → Atom Myanmar → MPT).

**Core (double-VPN):** ingress `core0` → exit `coreexit0`, Xray stealth (WebSocket 80/443), `app-cloud-sync.net` stealth zone.

**Cryptocurrency payment processing architecture (Spain & Kansas Hub):**
- **BTCPay Server (Spain <NODE_SPAIN_IP>):** Docker Compose deployment supporting Bitcoin (BTC) and Dash (DASH) with the `opt-save-storage-s` pruned storage fragment, keeping storage well within Spain's available disk envelope. Local proxy routing via Nginx binds to 127.0.0.1:23000 and connects through Cloudflare Tunnel under `btcpay.winsvpn.org`, preserving origin hiding with zero exposed management ports.
- **Monero wallet service (Spain <NODE_SPAIN_IP>):** Dedicated unprivileged systemd daemon (`monero-wallet-rpc.service`, user `monero-wallet`) running official release v0.18.5.1 with `--restricted-rpc` and HTTP Digest Authentication bound to loopback 127.0.0.1:18083, connected to trusted remote daemons with `--untrusted-daemon`. The wallet operates view-only with zero private spend keys, guaranteeing funds cannot be swept or exfiltrated from the server under any condition.
- **Kansas Control Hub integration:** Greenfield REST client (`/pay/crypto/create-invoice`) binds order pricing and metadata to local `payment_orders` records before invoice creation. The webhook (`/webhook/btcpay`) validates HMAC-SHA256 signatures and provides idempotent account provisioning. Monero orders (`/pay/monero/create-order`) dynamically mint subaddresses under account 0, and background sweeps (`/admin/monero/poll`) verify on-chain confirmations (`MONERO_CONFIRMATIONS=10`).
- **Fail-closed pricing and delivery:** Monero prices resolve via Kraken and CoinGecko feeds with a 20% deviation ceiling against the last persisted rate. Fixed terms (30-day $0.99, 365-day $11.88, and 10-year Lifetime $99) provision automatically via email in accordance with public billing terms on `www.winsvpn.org/billing/`.


**Smart routing target:** VPN connection initiation and distress routing consult local Gemma on `aicore` first and the Google API where configured, then deterministically validate the selected route against the authenticated candidate set. Any AI or API failure falls back without blocking Winn v3 primary or Winn v1 AWG-first/Xray-second compatibility. Recovery via `active-gateway.txt` (sync.winsvpn.org + 26 stealth bases a..z.app-cloud-sync.net), allowlist-validated.

The exact client ordering, explicit TCP-only and diagnostic overrides, strict
v1 candidate classification, and terminal security-refusal rule are defined in
`docs/WINN_PROTOCOL_SELECTION_POLICY.md`.

**AI brain target (aicore, home RTX 5060 Ti):** local Gemma serving plus a narrow Smart Router interface for initiation/routing/support. The current repository contains a separate Gemini Cloud Run router but does not yet prove the local Gemma initiation path. Do not treat the earlier `Gemma 4 12B NVFP4`, port, or serving-runtime claim as release evidence until the exact latest-stable model and runtime are measured on `aicore` and the fail-safe integration tests pass.

---

## 9. Current status (2026-08-19)

- All client targets build/analyze clean: Win x64+arm64, Linux x64+arm64, macOS (Developer-ID signed), iOS (signed IPA), Android phone+tv (signed APKs), Chrome+Firefox extensions, Wear OS (signed), watchOS (Ad-Hoc signed; App Store needs the watch-extension provisioning profile).
- Real winn/3 session verified on the GCE sim (handshake=ok, replay-safe, rekey).
- Repo consolidation: merging full codebase into `winsvpnv3` as production source of truth.
- Open items: fresh fleet redeploy (owner-driven).
- watchOS App Store profile: present and readable for the modern single-target bundle `org.winsvpn.app.watchkitapp` (`iOS Team Store Provisioning Profile: org.winsvpn.app.watchkitapp`, Apple Distribution, expires 2027-08-11). The former `org.winsvpn.app.watchkitapp.extension` profile belongs to the removed legacy extension target and must not be selected for archive or export.
- 2026-08-20: Legal reconciled into a single canonical `legal/MASTER_LEGAL_DOCUMENT.txt` (Version 2026-08-20.v1) with per-surface derivations (app, server clickwrap, website, store-compliance appendix); website `/privacy/` and the homepage inline Privacy Policy both deployed at 2026-08-20.v1 via Cloudflare Pages direct upload (see §7). Follow-up: Burmese/German translations of the payment-terms paragraph in `web/index.html` still need the crypto-payment wording added by a native speaker.

### 2026-09-11: connected server-switch preparation and dispatch repair

Local source repair against `e8d3df358ec8c8f6cfc114468a9cd027724286b6` plus the
owner's existing working changes. Connected selection now enters one guarded
smart-connect invocation. Its config refresh returns a staged result without
publishing config/cache; the old tunnel stops only after replacement config,
local-key, protocol authorization, raw-config, and update checks succeed.
Preparation failure retains the native route and restores the previous selected
node with fresh native status. Removed the ignored five-second prefetch and the
25-second cache-freshness heuristic, which lost dispatch generation alignment.
Primary hub v1 authorization now survives same-generation AWG-to-Xray refresh
without rewinding either leg; fallback refresh requests the exact original node.
Cancellation fences preparation and candidate commit, including UI flag cleanup.

Validation: 327 targeted Flutter tests passed in a manifest-verified isolated
copy, including 11 extracted-production-method transaction scenarios and 11 v1
primary-grant lifecycle tests. Analyzer clean; all 53 ruled invariants and six
Apple route checks passed. Existing Android native edits were preserved.
These are local source/behavior checks, not device or deployment proof. ADB
reported no attached device. The formal Android release producer refused a build
because no `ReleaseInputIndex` was supplied; no matching index was available in
this checkout. No APK installation, live server switch, push, or deployment was
performed. Remaining: a valid frozen release input index/build, then uninstall,
install, launch and exercise Free Access France-to-Germany on an attached phone,
including unavailable-hub preparation and cancellation, with native logs and
readiness evidence. A failed native replacement after cutover remains a real
connection failure; this patch does not claim overlapping native tunnels or
guaranteed reconnection when the network cannot carry the selected transport.

### 2026-09-11: Spain cryptocurrency payment infrastructure implementation

Automated deployment of cryptocurrency payment processing on the Spain server (`<NODE_SPAIN_IP>`) and integration with Kansas Control Hub. Provisions BTCPay Server for Bitcoin (BTC) and Dash (DASH) in pruned storage mode (`opt-save-storage-s`) to preserve local NVMe capacity. Configures Monero view-only wallet RPC (`v0.18.5.1`, SHA256 verified) running under systemd with `--restricted-rpc` and HTTP digest authentication. Routes incoming traffic via local Nginx and Cloudflare Tunnel origin hiding (`btcpay.winsvpn.org`), satisfying least-privilege transport rules on Kansas Hub (`https://` standard port 443). Validated contract invariants: BTCPay Greenfield API integration, webhook HMAC-SHA256 verification, atomic piconero conversions, multi-oracle price extraction, and order ledger idempotency across `payment_orders` and `monero_orders` tables.


### 2026-09-13: requested Round 4 source remediation

Implemented the eight owner-requested repairs: single-use enrollment keys,
worker offload for six control-plane entry points, pseudonymous verify logging,
bounded Linux child-pipe writes and SIGPIPE handling, Android API 26 floor and
native API annotations, strict Dart version alias preservation, Apple proof-stage
stop ownership, and the Windows protected pipe prefix. Android lint also required
one additional key-helper annotation and an API-compatible nonblocking socket
creation in VpnTunnelService. Existing owner changes and ruled lines were preserved.

Validation: all three required commands pass; full Flutter suite 1924 passed with
2 skips; 283 focused Android JVM tests and lint pass; server replay/concurrency and
real ASGI contention probes pass; both Apple provider typechecks, four extracted
ownership scenarios, Linux hostile pipe tests, 69 Windows wire checks, and all
59 general plus 6 Apple rulings pass. Details, source hashes, and exact limits:
[Round 4 remediation](../evidence/round4_remediation.md).

Remaining: formal Android input index and release APK, then the connected-phone
uninstall/install/launch/logcat smoke test; packaged native target acceptance;
6 pre-existing broader Android artifact/identity test failures and 1 existing
Apple wiring-test failure. No signing, device installation, commit, push,
publication, deployment, or release approval occurred. Preferred Cursor lanes
failed usage limits and workspace delegation failed initialization; the lead
completed the repairs locally.

### 2026-09-13: requested Round 5 source remediation

Implemented all six requested repair groups: paid crypto checkout stays within
the automated order flow, the donation modal is isolated from its drawer,
Firefox privacy readback fails closed, Android Xray modes refuse whole-UID
bypass and no longer hold a full-session Wi-Fi lock, client QUIC receive windows
are capped, and paid activation email is queued transactionally with retryable
encrypted delivery records. PayPal network calls run in workers, reconciliation
closes SQLite before HTTP, and paid Smart Router work requires authorization.
Existing free-access offloads were verified. Descriptor fixtures reset key
consumption/expiry and use returned bearer tokens for reconnects.

Validation: all five mandatory commands pass (analyzer clean; server suites
11, 8 and 117 tests; website 56 pass, 1 explicit skip). New Round 5 server tests
16 pass; Firefox regressions 12 pass; Chromium checkout scenarios 14 pass;
QUIC carrier race suite, Kotlin compilation/lint and 283 JVM tests pass. The
pinned real ASGI probe, payment/deletion regression suites, negative controls,
and all 59 general plus 6 Apple rulings pass their expected outcomes. Details:
[Round 5 remediation](../evidence/round5_remediation.md).

Remaining: connected-phone smoke requires the reviewed release input index
and a freshly built release APK. The actual producer refused without
`ReleaseInputIndex`; the APK is absent. The owner was asked for the index path.
No uninstall, installation, deployment, push or release acceptance occurred.
QUIC window bounds do not establish an Apple process-memory ceiling. Preferred
Cursor lanes exhausted usage limits and workspace delegation failed to start;
no independent model review is claimed.


### 2026-09-13: requested Round 6 source remediation

Implemented early Android Xray refusal before DNS/carrier launch, teardown-timeout
connect refusal, Linux normal/SIGINT/SIGTERM native shutdown, worker offload for
both logout endpoints, BTCPay checkout origin binding and deterministic close for
the two security-event SQLite writers. Preserved the existing dirty worktree.
The H3 receive-window test was already staged/tracked. Rebuilt and verified the
Chrome extension ZIP from current sources.

Validation: all seven mandatory commands pass. Flutter analyzer is clean and
1,926 tests pass with 2 existing live-test skips; server suites pass 11, 8, 16 and
117 tests; website passes 56 checks with 1 explicit skip. New Round 6 server tests
7 pass and fail against the pre-fix source. Android Kotlin/lint and 283 JVM tests,
Linux arm64/x64 compilation and GLib shutdown harnesses, QUIC carrier race tests,
12 browser regressions, archive verification and all 65 rulings checks pass.
Details, hashes, command logs and limits: [Round 6 remediation](../evidence/round6_remediation.md).

Remaining: Android connected-phone smoke is blocked by the absent reviewed
RELEASE_INPUT_INDEX.json and fresh release APK. The actual producer refuses
without the index; the owner was asked for its path. No phone uninstall/install,
publication, deployment, push or release approval occurred. Native Linux resource
operations are simulated in the lifecycle harness, so actual packaged route and
firewall cleanup remains a target-device acceptance step. Cursor/Grok usage limits
and workspace-agent initialization failures prevented independent model review.


### 2026-09-13: requested Round 7 source remediation

Implemented all ten requested defect groups: independent Monero consensus,
durable stale-peer cleanup, bearer rotation on slot replacement, admission
rollback on direct/Double VPN exit sync failure, worker offload for all four
account-deletion routes, authenticated account status and Dart bearer headers,
fail-closed expiration, bounded durations, named Linux inhibitor service and
Linux/Android socket-buffer comparison units. F11 resides in the Go carrier
helper rather than the C++ runner. Free-access timestamps and one-time legacy
migration were reconciled with strict expiration validation.

Validation: all eight mandatory commands pass. Flutter analyzer clean; 1926
Flutter tests pass with 2 existing live skips; server suites pass 11, 8, 16, 7
and 117 tests; website passes 56 checks with 1 explicit skip. New Round 7 server
suite: 17 pass and saved pre-fix source fails. Existing deletion, expiry and
crypto suites pass. Go carrier race tests, Linux arm64/x64 compilation,
inhibitor command harnesses, real Linux loopback socket tests and all 65 ruled
invariants pass. Details, final hashes and logs:
[Round 7 remediation](../evidence/round7_remediation.md).

Remaining: Android phone smoke is blocked by the absent reviewed input index
and release APK. The producer explicitly refuses without ReleaseInputIndex;
the owner was asked for the path. Actual desktop systemd/logind inhibition and
deployed control-plane behavior are not certified by these local tests.
Existing working changes were preserved. No uninstall/install, deployment,
push or release approval occurred. Cursor usage limits and workspace-agent
initialization failure prevented independent model review.

### 2026-09-13: requested Round 8 source remediation

Implemented all 12 requested repair groups: expiration-safe customer exports,
durable device revocation, PayPal capture confirmation, durable v3 registry
refresh triggers and retry, 70 synchronous route conversions, resolved Linux
inhibitor executable paths, Android startup-only wake locking and split-tunnel
failure propagation, Android Xray capability suppression, release identity test
alignment, browser package rebuilds, and the requested verification/copy fixes.
Adapted the async heartbeat alias and direct route test callers. The H3 test was
already staged. Existing dirty work and ruled decisions were preserved.

All 12 mandatory commands pass: analyzer clean; Flutter 1926 pass with 2 existing
skips; required server suites 196 pass; website 56 checks with 1 existing skip;
all 65 rulings and the Apple channel contract pass. New Round 8 server tests:
13 pass, with saved pre-fix negative controls failing as expected. Real ASGI
worker dispatch, additional affected route suites, Linux arm64/x64 compilation
and inhibitor harnesses, Go carrier race tests, and both extension ZIP verifiers
pass. Changed sources/tests use LF. Details, hashes, logs, and limitations:
[Round 8 remediation](../evidence/round8_remediation.md).

Android Kotlin/lint completed with zero lint errors. The full JVM suite is
586 pass and 5 artifact failures: absent debug engines, an engine-less existing
debug APK, and the existing Windows native consumer-authority refusal. The
identity test passes. The release producer still refuses without a reviewed
ReleaseInputIndex; no index or release APK exists in the checked artifact paths.
Connected-phone uninstall/install/launch/logcat and wake-lock expiry remain
blocked pending that release artifact. No phone installation, commit, push,
publication, deployment, or release approval occurred. Cursor usage limits and
workspace-agent startup failure prevented independent model review.


### 2026-09-13: requested Round 9 source remediation

Implemented active v3 gateway authorization and return-path revalidation, parsed
expiration selection, standalone admission rollback on registry publication
failure, remaining control-plane worker offloads, bounded Linux process groups,
the iOS 15 MiB sampled watchdog, systemd custody of legacy SPA expiry, and Apple
wiring oracle alignment. Preserved the existing dirty work and ruled decisions.

All 15 required commands pass: analyzer clean, Flutter 1,926 pass with two
existing skips, required server suites 209 pass, website 56 pass with one
existing skip, rulings and Apple contracts pass, and the complete Go module
passes. Additional server, gateway race, hostile Linux process, Swift watchdog
and ownership tests pass. Six new server regressions reject the saved original
source. All 13 changed source/test files use LF. Details, exact logs, hashes,
patch and verification limits: [Round 9 remediation](../evidence/round9_remediation.md).

The watchdog checks observed memory each second; it is not an allocator limit.
Physical iOS stress and route recovery, actual SPA timer expiry on a hub, and
packaged privileged Linux lifecycle behavior remain unverified. No signing,
installation, commit, push, publication or deployment occurred. Cursor usage
limits and workspace-agent failure were bypassed through three successful
local Codex CLI lanes, with lead integration and verification.


### 2026-09-13: requested Round 11 source remediation

Implemented deferred Double VPN activation consumption and post-Core authority
revalidation, durable cleanup for uncertain direct AWG installation, direct Go
peer-key lookup, native-host origin provisioning and Firefox launch parsing,
Linux numeric-only refusal diagnostics, owned Flutter keyboard focus nodes,
removal of session-wide Linux inhibition, and resolved split-bypass sleep paths.
New Go tests and new referenced Flutter files are staged. Existing dirty work
and ruled decisions were preserved.

All 19 mandatory commands pass: analyzer clean, Flutter 1,927 pass with two
existing skips, all requested server/domain suites, website audit, rulings,
Apple contracts, Windows runtime checks, and the full Go module. New server
regressions, real ASGI authority probes, gateway race tests, compiled Linux
seams, native-host compilation, and fresh installed-origin probes pass.
The broader native registration suite retains the same eight failures found
with pre-edit native files. Details, hashes, exact results and task-only diff:
[Round 11 remediation](../evidence/round11_remediation.md).

Android phone smoke remains blocked by the missing reviewed ReleaseInputIndex
and absent release APK, despite an attached phone. The actual release producer
refused without the index. No phone uninstall/install, signing, publication,
push, deployment or release approval occurred. Cursor usage limits and the
workspace-agent initialization failure prevented independent model review.
