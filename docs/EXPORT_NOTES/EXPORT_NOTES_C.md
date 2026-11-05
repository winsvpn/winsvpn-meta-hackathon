# Lane C export notes (server, deploy, cloudflare, netlify, dashboard, evidence, progress evidence, root ops scripts)

Source: git worktree branch release-1.0.17 at commit faff0b5, tracked files only (`git ls-files`).
Output: this directory, original relative paths preserved. Nothing was pushed or published.
Policy: publish the true source except secrets; infrastructure addresses, real hostnames, SSH aliases, fleet inventories and anything usable to target the live fleet count as secrets.

## 1. Included directories and file counts

| Path | Source tracked files | Exported | Excluded |
|---|---|---|---|
| server | 233 | 229 | 4 |
| deploy | 25 | 25 | 0 |
| cloudflare | 5 | 2 | 3 |
| netlify | 2 | 2 | 0 |
| dashboard | 12 | 12 | 0 |
| evidence | 15 | 15 | 0 |
| .winn_platform_progress | 8 | 8 | 0 |
| (root) | 4 | 4 | 0 |
| total | 304 | 297 | 7 |

Root-level ops scripts exported: backup_to_gdrive.sh, capture_evidence.sh, optimize_vps.sh, weekly_maintenance.sh.
Kept binary-type files: server/vendor/cloudflare-main.gpg (OpenPGP public key, Cloudflare apt signing certificate) and cloudflare/Worker.png (screenshot showing only the public sync.winsvpn.org Worker route).

## 2. Excluded paths, grouped by rule

### Rule 1, secrets and key material (unscrubbable images)

- `cloudflare/API screen.png`: screenshot of an API token edit page showing the Cloudflare account id, a partial token id and the account email address
- `cloudflare/Cloudflare DNS.png`: screenshot of the live DNS zone, a full node inventory with six real A-record addresses plus the proxied hub origin address
- `cloudflare/Cloudflare app-cloud-sync.net.png`: screenshot of the account overview showing the Cloudflare account id and the account email address

### Rule 2, evidence and logs

No whole-file exclusions under this rule. Evidence and log files with real addresses were scrubbable (see section 3) and were kept.

### Rule 3, prebuilt binaries

- `server/awg-carry-client-linux-amd64`: prebuilt ELF binary, 10.3 MB
- `server/awg-carry-client-linux-arm64`: prebuilt ELF binary, 9.8 MB
- `server/winn3-probe-linux-amd64`: prebuilt ELF binary, 6.8 MB
- `server/winn3-probe-linux-arm64`: prebuilt ELF binary, 6.3 MB

## 3. Scrubbed files and replacement counts

Replacement is literal, in place, with no reformatting. Placeholders used:

- `NODE_IP_ES1`: Spain data-plane node public address
- `NODE_IP_DE1`: Germany data-plane node public address
- `NODE_IP_CA1`: Canada data-plane node public address
- `HUB_IP`: control hub (Kansas) public address
- `DEMO_ROUTE_B_IP`: GCP demo gateway B egress address
- `DEMO_ROUTE_A_IP`: GCP demo gateway A egress address
- `IPV6_RESOLVER_REDACTED`: a global IPv6 resolver literal captured in a macOS route dump
- `AI_ROUTER_HOST`: Cloud Run service hostname carrying the GCP project number
- `EDGE_AICORE_HOST`: cloudflared ingress hostname of the AI core edge router
- `-mgmt.example.test`: management hostnames of the form <node>-mgmt.<domain> (test fixtures)
- `.mgmt.example.test`: the management DNS zone wildcard mentioned in an installer comment
- `GCE_INSTANCE_ROUTE_A`: GCE instance name of demo gateway A
- `GCE_INSTANCE_ROUTE_B`: GCE instance name of demo gateway B
- `GCE_INSTANCE_HUB`: GCE instance name of the staging hub
- `ssh AICORE_HOST`: SSH host alias for the AI core host
- `DEPLOY_USER@`: owner login name in an ssh command
- `~/.ssh/DEPLOY_KEY`: owner deploy key filename
- `/tmp/lane-scratchpad`: owner workstation scratch path (session-specific)
- `$HOME`: owner workstation home directory path prefix
- `SHA256:REDACTED_FINGERPRINT`: deploy key public fingerprint
- `LAB_GATEWAY_PUBKEY_1`: WireGuard public key of a lab-LAN gateway (session 2026-08-06, Linux)
- `LAB_GATEWAY_PUBKEY_2`: WireGuard public key of a lab-LAN gateway (session 2026-08-06, macOS)
- `CF_ZONE_ID_ORG_REDACTED`: Cloudflare zone id for winsvpn.org pinned as an installer default
- `CF_ZONE_ID_COM_REDACTED`: Cloudflare zone id for winsvpn.com pinned as an installer default
- `LAB_SESSION_ID_1`: random per-run lab session id
- `LAB_SESSION_ID_2`: random per-run lab session id
- `LAB_SESSION_ID_3`: random per-run lab session id
- `LAB_SESSION_ID_4`: random per-run lab session id

| File | Replacements | Placeholders (count) |
|---|---|---|
| `.winn_platform_progress/evidence/winn3_linux_20260806T194436Z_two_host_lan_gateway_session.txt` | 6 | LAB_GATEWAY_PUBKEY_1 (6) |
| `.winn_platform_progress/evidence/winn3_linux_20260806T203726Z_flutter_app_shipping_path_session.txt` | 246 | LAB_GATEWAY_PUBKEY_1 (237), LAB_SESSION_ID_1 (3), LAB_SESSION_ID_2 (3), LAB_SESSION_ID_3 (3) |
| `.winn_platform_progress/evidence/winn3_macos_20260806T155246Z_contained_remote_gateway_session.txt` | 13 | IPV6_RESOLVER_REDACTED (1), /tmp/lane-scratchpad (6), $HOME (1), LAB_GATEWAY_PUBKEY_2 (2), LAB_SESSION_ID_4 (3) |
| `capture_evidence.sh` | 3 | AI_ROUTER_HOST (1), $HOME (2) |
| `deploy/edge-router-aicore/cloudflared/config.yml` | 1 | EDGE_AICORE_HOST (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-3d598a37352e1edf87627ee45e96bd743f75e8c4.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-405099967b61acaee088431da007282200dc6797.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-457e452bd821cc7e2978ea5f3b3404080e7cd2c7.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-4a4fe3e02d24860dbf12c657c2f098dcbbac93c9.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-8287dd46a32ba7bc1a83ec73d757c9c61f09d255.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-a99d3539db0befe176918c1e4ac68ad1b5a35ec3.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/FLIP-AUTHORIZATION-cde67bb221badeaf11a9f8648fb98191cab810ce.json` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/PENDING-OWNER-INPUT.json` | 113 | $HOME (113) |
| `deploy/production-input-evidence/flip-battery-3d598a3.md` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), HUB_IP (1) |
| `deploy/production-input-evidence/ssh-identity-attestation-prep.json` | 1 | SHA256:REDACTED_FINGERPRINT (1) |
| `evidence/CONTINUE.md` | 3 | DEMO_ROUTE_B_IP (1), $HOME (2) |
| `evidence/DEMO_RUNBOOK.md` | 14 | DEMO_ROUTE_B_IP (2), DEMO_ROUTE_A_IP (2), AI_ROUTER_HOST (7), $HOME (3) |
| `evidence/EVIDENCE_CHECKLIST.md` | 22 | DEMO_ROUTE_B_IP (4), DEMO_ROUTE_A_IP (2), AI_ROUTER_HOST (6), GCE_INSTANCE_ROUTE_A (1), GCE_INSTANCE_ROUTE_B (1), GCE_INSTANCE_HUB (1), ssh AICORE_HOST (2), $HOME (5) |
| `evidence/EVIDENCE_PACK.md` | 16 | DEMO_ROUTE_B_IP (5), DEMO_ROUTE_A_IP (4), GCE_INSTANCE_ROUTE_A (2), GCE_INSTANCE_ROUTE_B (2), GCE_INSTANCE_HUB (1), $HOME (2) |
| `evidence/EVIDENCE_ZIP.md` | 1 | $HOME (1) |
| `evidence/FACTS.md` | 11 | DEMO_ROUTE_B_IP (1), DEMO_ROUTE_A_IP (1), AI_ROUTER_HOST (2), GCE_INSTANCE_ROUTE_A (2), GCE_INSTANCE_ROUTE_B (2), GCE_INSTANCE_HUB (2), $HOME (1) |
| `evidence/LANE_REPORT.md` | 10 | ssh AICORE_HOST (1), DEPLOY_USER@ (1), ~/.ssh/DEPLOY_KEY (1), $HOME (7) |
| `evidence/README_INDEX.md` | 1 | AI_ROUTER_HOST (1) |
| `evidence/REPO_PLAN.md` | 3 | AI_ROUTER_HOST (3) |
| `evidence/REVENUE_TEMPLATE.md` | 1 | AI_ROUTER_HOST (1) |
| `evidence/SUBMISSION_DRAFT.md` | 5 | DEMO_ROUTE_B_IP (1), DEMO_ROUTE_A_IP (1), AI_ROUTER_HOST (2), $HOME (1) |
| `evidence/VIDEO_SCRIPT.md` | 7 | DEMO_ROUTE_B_IP (2), DEMO_ROUTE_A_IP (2), AI_ROUTER_HOST (3) |
| `server/spain_crypto_payments_setup.sh` | 2 | NODE_IP_ES1 (2) |
| `server/test_crypto_payments_spain.py` | 1 | NODE_IP_ES1 (1) |
| `server/test_fleet2_tamper_alerts.py` | 6 | -mgmt.example.test (6) |
| `server/test_fleet_reset_cp_installer.py` | 2 | CF_ZONE_ID_ORG_REDACTED (1), CF_ZONE_ID_COM_REDACTED (1) |
| `server/test_winn3_onetouch_cover.py` | 1 | $HOME (1) |
| `server/wins_control_plane_setup_ONETOUCH.sh` | 3 | .mgmt.example.test (1), CF_ZONE_ID_ORG_REDACTED (1), CF_ZONE_ID_COM_REDACTED (1) |
| `server/wins_data_plane_setup_ONETOUCH.sh` | 3 | NODE_IP_ES1 (1), NODE_IP_DE1 (1), NODE_IP_CA1 (1) |
| `server/wins_winn3_gateway_install_maintenance_test.sh` | 2 | $HOME (2) |
| total | 521 | 35 files |

## 4. Reviewed and kept on purpose

- Pinned Ed25519 verification public keys in `server/wins_control_plane_setup_ONETOUCH.sh` (announce keys A1 to A3 near line 7127, signer ticket keys g1 to g3 near line 7198), the g2 key used as a test vector in `server/test_hub_h1_descriptor_signer.py`, and the staging G1 descriptor public key quoted in `evidence/LANE_REPORT.md`. These are public verification keys served to every client by design; replacing them would break the pin logic and the signer test. One `sed` on these six base64 values reverses this decision if the owner prefers.
- `ED_PUB` in `server/test_fleet2_tamper_alerts.py`, an SSH Ed25519 public key used only as a fixture in that file (appears nowhere else in the worktree).
- Public endpoints: hub.winsvpn.org, sync.winsvpn.org, sync.winsvpn.com, btcpay.winsvpn.org, monero-rpc.winsvpn.org, www.winsvpn.org, mail.winsvpn.org, sync.app-cloud-sync.net, a.app-cloud-sync.net, winsvpn.pages.dev, plus role addresses at winsvpn.org and winsvpn.com.
- `ACTIVE_GATEWAY_GIST_ID_DEFAULT` in the control-plane installer: the public GitHub Gist that clients fetch for active-gateway discovery. Public by design; same id is in `.env.example` and `GitHub Gist.txt` (other lanes).
- The hub nickname "Kansas" and node slugs (spain-madrid, germany-de1, canada-ca1, demo-route-a, demo-route-b): labels, not addresses.
- Cloudflare published IP ranges, OpenDNS and Quad9 resolvers, RFC 1918 / RFC 5737 / 2001:db8 literals, CGNAT 100.64/10 in tests, route prefixes such as 128.0.0.0/1 and 45.0.0.0/8, and fixture addresses 1.2.3.4, 1.2.3.5, 4.5.6.7, 1.3.101.110.
- `server/runtime_captured/*`, `server/final_iptables_requested.txt`, `server/testdata/winn3_gateway_winvpn_input/*`: captured firewall state containing only RFC 1918 addresses and interface names.
- `server/hub-commerce.env.example` and `deploy/edge-router-aicore/env/cloudflared-token.env.example`: names-only templates with empty values.
- `deploy/production-input-evidence/PENDING-OWNER-INPUT.json` and the FLIP-AUTHORIZATION records: governance evidence with sha256 digests and file metadata, no secret bytes; addresses and workstation paths scrubbed.
- `winsvpn-secrets` occurrences (16 files): the name of the secrets file or directory (`/root/winsvpn-secrets.env`, `~/.winsvpn-secrets`), never a value.

## 5. Scanner output

### gitleaks

Command: `gitleaks detect --no-git --source /Volumes/WinsBuild/winsvpn/hackathon/fullsrc/laneC --redact` (gitleaks 8.30.1).

Output: `INF scanned ~15026088 bytes (15.03 MB) in 1.72s`, `WRN leaks found: 55` (generic-api-key 49, jfrog-identity-token 6).

All 55 are false positives by shape, none is a credential:

| File | Lines | Rule | Why it is not a secret |
|---|---|---|---|
| `server/test_control_data_cloudflared_deb_pin.py` | 16 | generic-api-key | expected sha256 of the pinned cloudflared .deb (public package checksum) |
| `server/test_installer_sync_hub_fx2.py` | 1922 | generic-api-key | fixture env line `WINN3_CANARY_KEY_DIR=/etc/winn/canary/none`, a directory path |
| `server/test_sync_core_fix2_hub.py` | 730 | generic-api-key | fixture token `0123456789abcdef0123456789abcdef` |
| `server/test_winn3_sign_descriptor_tool.py` | 546 | generic-api-key | a file path join `admission32.key`, not a value |
| `server/winn3-probe.build.json` | 40 lines (40 to 1256) | generic-api-key | build manifest: sha256 digests of Go source files whose names contain key/token/auth |
| `server/wins_control_plane_setup_ONETOUCH.sh` | 272, 33233, 34418 | generic-api-key | line 272 is `ADMIN_TOKEN_DEFAULT=""` (empty); lines 33233 and 34418 are Python keyword arguments `deferred_activation_secret, consumed=...` with no value |
| `server/wins_core_server_setup_ONETOUCH.sh` | 7653, 7654, 13823, 13824, 14426, 14427 | jfrog-identity-token | pinned sha256 download checksums for the Xray release tarball and binary (XRAY_LINUX_64_SHA256, XRAY_LINUX_64_BIN_SHA256) |
| `server/wins_data_plane_setup_ONETOUCH.sh` | 545, 16998 | generic-api-key | line 545 is `ADMIN_TOKEN_DEFAULT=""` (empty); line 16998 is the Sec-WebSocket-Key example value from RFC 6455 section 1.3 (base64 of the text "the sample nonce") |

### grep checks on the output tree

- IPv4 literals outside the allowed ranges (loopback, unspecified, RFC 1918, link-local, RFC 5737, CGNAT, 1.1.1.1/1.0.0.1/8.8.8.8/8.8.4.4/9.9.9.9, OpenDNS, Cloudflare published ranges): 11 unique values remain, all fixtures or route prefixes: 1.2.3.4, 1.2.3.5, 1.2.3.0, 4.5.6.7, 1.3.101.110 (test fixtures); 128.0.0.0, 45.0.0.0, 46.0.0.0, 47.0.0.0, 100.0.0.0, 172.32.0.0 (route prefixes in egress tests and the core installer). All six real addresses from the source are gone (0 hits each).
- IPv6 global literals: one hit, `2001:0db8::1` in `server/test_control_plane_round6.py` (documentation range). The one real-world literal was replaced by IPV6_RESOLVER_REDACTED.
- `BEGIN .*PRIVATE KEY`: 4 hits, all fixtures or match patterns: `server/test_hub_h0_review_fixes.py:148` (writes the literal text `fixture`), `server/wins_control_plane_setup_ONETOUCH.sh:1275` (a case pattern that refuses such input), `server/test_winn3_client_keys_hub.py:1207` (header string used as invalid input), `server/test_winn3_hub_env_write.py:45` (`FAKE_PEM` with body `not-a-real-key`).
- Owner workstation home path prefix and owner login name: 0 hits (123 occurrences across 13 files replaced; 113 of them in PENDING-OWNER-INPUT.json).
- `winsvpn-secrets`: 16 files, 58 occurrences, all file or directory names, no values. Kept.
- `ssh <alias>`: after excluding prose, the remaining hits are `ssh -p ${unlock_port} root@<server-ip>` (installer log text with a placeholder), `ssh -p 2222 with` (prose in deploy/fde_boot_chain.sh), and the scrubbed `ssh -i ~/.ssh/DEPLOY_KEY DEPLOY_USER@<STAGING_HUB_IP>` in evidence/LANE_REPORT.md. `ssh aicore` (3 occurrences) became `ssh AICORE_HOST`. `ssh release-host` in dashboard/test_dashboard.py:1905 is a fixture string in a list of rejected command shapes.
- `Host ` blocks (ssh_config style), `HostName`, `ProxyJump`, `IdentityFile`: 0 hits.
- `garble`: 4 hits, all the English word "garbled" (comment at wins_control_plane_setup_ONETOUCH.sh:7814 and a variable name in test_winn3_onetouch_s7.py:829 to 831). Not the Go obfuscator.
- Token-like strings (32 or more chars of [A-Za-z0-9_-]): 7,772 unique. 2,351 are sha1/sha256/sha512 hex digests (build manifests, pins, evidence inventories), 4,626 snake_case identifiers, 388 CONSTANT_NAMES, 207 kebab-case slugs or filenames, 116 CamelCase identifiers, 66 mixed identifiers. The 18 with no identifier shape were inspected one by one: fixture values (`0123456789abcdef...`, `abab...`, `f00dfeed...`, `fedcba...`, `L65FAKETUNNELSECRETnotarealvalue...`, the base64 alphabet constants, an `age1qyq...` dummy recipient), the PKCS#8 DER prefixes `302e020100300506032b65{6e,70}04220420`, and the NIST P-256 generator point hex in `server/test_winn3_onetouch_s4.py`. The two Cloudflare zone ids and four lab session ids found in this pass were scrubbed (section 3).
- A separate entropy pass (Shannon entropy at least 4.3 bits per char, three character classes, identifiers and digests filtered) over all kept text files outside the build manifests and run logs produced 209 candidates in 60 files: go.sum module checksums in the vendored cloudflared patches and the core installer, the pinned public keys listed in section 4, FAKE-prefixed fixture tokens, and long documentation paths. No credential-shaped value remains.
- Base64 44-char strings: go.sum `h1:` checksums, the pinned public keys (section 4), fixture keys (`"A" * 43 + "="` style), and the two lab gateway keys that were replaced.
- Email addresses: only example.test / example.com / example.org fixtures, role addresses at winsvpn.org and winsvpn.com, systemd unit names, OpenSSH key type names, and the public judging@hacker.fund / testing@devpost.com addresses. The personal account email visible in the excluded screenshots does not appear in any text file.
- Cloudflare account id (seen in the excluded screenshot URLs): 0 hits in text. Tunnel ids: all 18 UUID-shaped strings are fixtures (11111111-..., 0123abcd-..., ffffffff-..., 12345678-...).

## 6. Integrity checks

- Files exported: 297 of 304. Excluded: 7. Output size about 15 MB.
- Byte comparison against the source: exactly 35 files differ (the scrubbed set above); every other exported file is byte-identical. No extra files in the output.
- File modes preserved (executable bits copied with the content).
- Source worktree `git status --short` is empty after the export; nothing was written there.

## 7. Notes for the coordinator and other lanes

- `docs/blueprints/AI_HANDOFF_20260823.md` (not in this slice) contains the same two Cloudflare zone ids that were scrubbed here.
- `.env.example`, `GitHub Gist.txt`, `tools/test_deployment_runtime_configs.sh` and `tools/test_gateway_failover.ps1` (other lanes) carry the active-gateway Gist id that this lane kept as a public endpoint; whichever decision is taken should be applied consistently.
- The excluded `cloudflare/Cloudflare DNS.png` is the clearest fleet inventory in the whole slice (six node A records plus the hub origin). Do not let any lane re-add it.
- Installer defaults `CLOUDFLARE_WINSVPN_ORG_ZONE_ID_DEFAULT` and `CLOUDFLARE_WINSVPN_COM_ZONE_ID_DEFAULT` now hold placeholders, so a deployment from the public copy must supply the zone ids through the environment or the secrets file. Logic is unchanged.
- Placeholders inside Python and shell string literals (for example `$HOME/.homebrew/...` in `server/test_winn3_onetouch_cover.py`) are inert: the code falls back to `shutil.which` or `command -v` when the path does not exist.
