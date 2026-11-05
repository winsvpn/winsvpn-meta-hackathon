# Win's VPN Security Notes

## Secrets And Rotation

The active app no longer contains the server admin token or sends `x-admin-token` to public `/verify` requests.

Server-side one-touch scripts contain only non-secret defaults. Real credentials
must be supplied through root-owned deployment environment files with mode
`600`:

```bash
chmod 600 /root/vpn_auth.env /root/vpn_auth/.env /root/node.env 2>/dev/null || true
```

The audit found previously tracked Google/rclone credentials plus a credential
in an ignored local sync-backup directory. The current tracked backup helper is
now credential-free, but all affected OAuth client secrets, refresh/access
tokens, rclone crypt passwords, and the ignored backup credential must be
revoked and reissued. Git history must be purged separately; editing the current
tree does not remove old objects.

Rotate these before any fresh deployment:

- Admin token.
- SPA key and SPA HMAC key.
- SMTP2GO username/password.
- PayPal REST client secret and webhook ID if the installer or `/root/vpn_auth.env` is shared outside the private deployment environment.
- rclone config and Google tokens.
- Any keys in local backup/reference text files.

`.env.example` now uses placeholders.

Only `server/wins_*_setup_ONETOUCH.sh` is authoritative deployment automation.
Root firewall/performance text files and `Update/` copies are historical
references or handoff snapshots, not executable production sources.

## Firewall Safety

The active data-plane firewall uses owned chains:

- `WINVPN-INPUT`
- `WINVPN-FORWARD`
- `WINVPN-NAT-PREROUTING`
- `WINVPN-NAT-POSTROUTING`
- `WINVPN-MANGLE-FORWARD`
- `WINVPN-DOCKER`

The hub firewall uses `WINVPN-HUB-INPUT`.

The scripts refresh only owned chains and do not flush full filter/nat/mangle tables or DOCKER-USER. Docker is restarted only if `RESTART_DOCKER_AFTER_FIREWALL=1`.

## Control Hub IDS/IPS

The control-plane one-touch installer deploys Suricata and Fail2Ban by default.
Inbound hub TCP 80/443 is sent through NFQUEUE 0. High-confidence local rules
use `drop`; ET Open remains alert/evidence-oriented so noisy community
signatures do not become automatic customer-impacting blocks. Exploit probes,
scans, hostile reputation hits, traversal attempts, and credential-file
discovery are retained for evidence. No configuration can promise zero false
positives; tune only by SID after packet/log review. Fail2Ban protects real SSH
inside `WINVPN-HUB-INPUT`.
Temporary bans are not persisted into `/etc/iptables/rules.v4`; Fail2Ban
recreates the live chain at service start.

Security email alerts go to `security@winsvpn.com` through the rotated SMTP2GO credentials for P1 and P2 only. P3 events are local-DB-only. Only loopback is exempt by default; operator exemptions must be supplied dynamically through `SECURITY_ALERT_EXEMPT_IPS`. Alert emails hash account identifiers and user-agent values, render aligned labels, and show Eastern time in the body; UTC is retained only in the local database for correlation.

Known JAWS/MVPower DVR probe signatures are suppressed only at the email layer because the control hub runs Nginx and FastAPI, not the affected DVR products. These events remain available in Suricata and the security event database, and the exact unused `/shell` origin route returns `404`. Do not turn this exception into a broad command-injection suppression rule; new signatures and evidence of successful execution still require investigation.

The 2026-07-10 review confirmed that one automated `/shell` request carrying a Mozi download/execute string produced five overlapping alerts (`2009363`, `2025883`, `2029022`, `2030092`, and `2030093`). Before the exact Nginx route was added, the SPA fallback returned `index.html` with HTTP 200; the request was not proxied to FastAPI or a command interpreter. Host checks found no downloaded payload, matching execution log, failed service, or unrecognized successful login. The live monitor now suppresses email for only those five inapplicable signatures, retains the events, and normalizes accidental quotes around comma-separated signature IDs. Replay validation produced five suppressed records and zero email sends while unrelated signature IDs remained alertable.

The hub keeps a separate root-only security event database at `/var/lib/wins-security-alerts/security_events.db` with 180-day retention for drilldown. It stores control-plane intrusion/admin/auth metadata such as priority, event type, source IP, request path, email status, and JSON details. This is not VPN traffic logging; data-plane inspection is limited to public Xray TCP ingress and exit-node destination metadata is not recorded.

Control, data, and core roles enforce `MaxAuthTries 5`. The hub defaults to
key-only SSH restricted to trusted source CIDRs; global/password access requires
explicit recovery overrides. Hub bans are inserted into `WINVPN-HUB-INPUT`;
data-plane bans are inserted into `WINVPN-INPUT` before the SSH allow rule.

Data-plane Suricata is enabled by default only on the advertised public Xray TCP
ports. Raw AmneziaWG UDP 9110 and FORWARD/customer egress traffic never enter
NFQUEUE, preserving the no-log boundary while still defending the exposed
stealth listener.

Core-role Suricata follows the same boundary for the opt-in "Double VPN" relay:
NFQUEUE inspects only `WINVPN-CORE-INPUT` (the still-encrypted public ingress,
before AmneziaWG decrypts it). `WINVPN-CORE-FORWARD` never queues to Suricata,
because `core0`/`coreexit0` are themselves AmneziaWG tunnel interfaces, so
forwarded traffic there is the decrypted second-hop payload; queuing it would
let a signature match log a customer's real, decrypted destination on the
product's most privacy-oriented tier. CIDR-source restriction, the SMTP/NTP/
SSDP abuse-port blocks, and the per-source UDP rate limit are still enforced
on that chain as plain iptables rules, independent of Suricata.

## Supply Chain And Package Safety

- Production installers fail closed outside Ubuntu 24.04 unless a disposable
  compatibility-test override is explicit.
- Data/core roles fail closed outside x86_64 because the reviewed AmneziaWG
  manifest currently exposes linux/amd64.
- APT waits for cloud-init and package-manager jobs, preserves existing VPS
  configuration files noninteractively, and avoids package removals by default.
- The AmneziaWG image is pinned by immutable manifest digest. Xray, AdGuard
  Home, and optional YABS installer scripts are pinned to commits and verified
  by SHA-256 before execution.
- YABS and core local AI are disabled by default because neither is required to
  carry VPN traffic.
- Admin-token hub communication defaults to public-CA HTTPS and rejects
  plaintext HTTP unless an isolated-test override is explicit.

## Honeynet Isolation

The hidden production control hub does not run a public honeypot. Cowrie is
disabled there by default because redirecting public TCP 22 to the hub would
reveal the protected origin and mix hostile traffic with a trusted VPN role.
The retained Cowrie path is an explicit isolated-lab compatibility option only.

Deploy deception only with `server/wins_honeynet_setup_ONETOUCH.sh` on a
separate, disposable Ubuntu 24.04 decoy VPS/IP that has no VPN-role marker,
credentials, backup access, management trust, or route to the control/data/core
planes. The decoy's provider and host firewalls must restrict egress so a
compromise cannot be used to attack third parties. Honeypot telemetry and
captured payloads must remain outside the customer database and production
backups and must be treated as hostile evidence.

## PayPal

The scripts do not embed a PayPal REST secret. Production strict mode requires
the REST credentials, webhook ID, public client ID, plan IDs, and lifetime
purchase URLs during `--preflight`; absence stops before package changes.
Provisioning uses values injected through `/root/winsvpn-secrets.env` and
written mode `600` to `/root/vpn_auth.env`, including:

- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `PAYPAL_WEBHOOK_ID`

The PayPal engine verifies webhook signatures, stores processed webhook IDs in SQLite, retries transient REST failures, provisions new accounts, applies plan updates, syncs recurring billing, and revokes active devices for inactive PayPal subscriptions. The public account options are 1 month, 1 year, Lifetime Access + Tech Support, and Lifetime Access without tech support; both lifetime options create 10-year accounts. Admin repair is available through `wins-admin` options 16/17 and the authenticated `/admin/paypal/dead-letter` and `/admin/paypal/retry` endpoints; retry resyncs the subscription from PayPal rather than storing/replaying full webhook payloads.

PayPal click tracking uses hub redirect links under `/pay/{option}` instead of embedding ad SDKs in the VPN app. The `payment_clicks` table stores option/source, HMAC IP buckets, and hashed user-agent/referrer values; it does not store raw IP addresses, account numbers, emails, or device IDs. Website Meta/Google pixels should fire on the public website click event or thank-you flow, not inside the VPN tunnel client.

## No-Log Controls

- Uvicorn is started with `--no-access-log`.
- Hub and data-plane Nginx configs use `access_log off`.
- Xray access logging is disabled with `"access": "none"`.
- Application logs avoid account numbers, device hashes, email addresses, subscription IDs, SPA source IPs, and VPN traffic metadata.
- `/verify` rate limiting stores HMAC buckets for source/account pressure, not raw IP addresses or raw account numbers.
- SQLite still stores activation/payment/device state needed for device limits and automated revocation.

## Client Keys

New Android activations generate the client WireGuard/X25519 keypair on the phone. The hub receives and stores only `client_public_key`; `client_private_key` remains empty for new phone-owned devices. Legacy clients without `client_public_key` still fall back to server-side key generation so old APKs are not broken during rollout.

The extra AmneziaWG preshared-key layer is feature-flagged with `AWG_PRESHARED_KEYS_ENABLED=1`. It is disabled by default because the current bundled Android native engine rejected the server handshake response when PSK was enabled, even though hub, database, and data-plane fingerprints matched. Re-enable it only after validating a newer native backend with a canary APK.

Data planes do not need client private-key generation code. They receive public peer updates from the hub over SSH and apply them to the AmneziaWG 2 container (`amnezia-awg2`) with `awg set`; the phone-owned private key never leaves the Android app.

## Xray / Stealth

Android stealth mode uses Xray's current `tunnel` inbound on `127.0.0.1:42110`, restricted to UDP and rewriting only to the local AmneziaWG destination, then VLESS over WebSocket to the data-plane Nginx/Xray path. Server Xray forwards to `127.0.0.1:9110` for AmneziaWG. The Core bridge enables XUDP aggregation only for its AWG UDP flow; normal app clients keep their platform-specific proven mux policy.

The rendered server config passes `jq` and installed `xray -test`. Xray warns that WebSocket transport is deprecated upstream, so keep VLESS-WS for the current Cloudflare path but plan a future XHTTP review.

Reference used during audit: https://xtls.github.io/en/config/

## Android Reverse Engineering

The APK still exposes public discovery domains, payment links, and SPA public parameters. The deployed Worker URL is now supplied by Gist/Netlify discovery rather than hardcoded raw Worker fallbacks. Do not embed admin tokens or private server credentials in the app.

The current local APK can still be flagged by antivirus products because it is sideloaded, VPN-capable, obfuscated, bundles native networking binaries, and supports calculator camouflage. Do not add binary padding or other AV-evasion tricks. For public distribution, use a real Play upload key, Play App Signing, a clear privacy policy, and be prepared to ship a Play-compliant build flavor if Google/Norton object to hidden-launcher camouflage.

## Other Backend Artifacts

The obsolete `wins-backend` Lemon Squeezy webhook was removed. Production purchase and automatic account provisioning are PayPal-only, and the release audit rejects reintroduction of Lemon Squeezy runtime code.

## Remaining Live Validation

Run a full production rehearsal:

1. Deploy hub.
2. Deploy one data node.
3. Confirm node heartbeat and public key registration.
4. Activate a test account on Android.
5. Connect in direct AmneziaWG mode.
6. Connect in Xray stealth mode.
7. Logout/deactivate and confirm peer removal.
8. Reboot hub/node and confirm timers/firewall persistence.
