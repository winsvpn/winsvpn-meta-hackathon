#!/usr/bin/env python3
"""Run Independent Deep Audits via Codex CLI across Daybreak Blue, Astra, and 5.6 Sol.

Models audited:
- Daybreak Blue: gpt-daybreak-blue-latest (extra high reasoning)
- Astra: gpt-6-astra (extra high reasoning)
- 5.6 Sol: gpt-5.6-sol (extra high reasoning)

Each model runs inside its own isolated snapshot workspace under
/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes so the three
concurrent auditors cannot disturb each other or the production working tree
at /Users/owner/xprize/winsvpnv3.

Targets evaluated:
1. Windows (x86, arm64)
2. Linux (x86, arm64)
3. macOS (x86, arm64)
4. Android (x86, arm64) & AndroidTV
5. iOS & tvOS
6. Browser Extensions (Chrome, Firefox, Edge, Safari)
7. Servers (Control plane, data planes, Cloudflare worker, Cloudflare DNS)
8. 3 Protocols (Winn v3, AmneziaWG primary, XRay fallback) & Core App
9. Live Website, Cloudflare DNS, Payments (PayPal, Monero, BTCPay), and Account Provisioning
10. Performance optimizations across all platforms

Usage:
    python3 tools/run_codex_tripartite_audit.py

Environment overrides:
    CODEX_AUDIT_TIMEOUT   per-model wall clock limit in seconds (default 21600)
    CODEX_AUDIT_MODELS    comma separated subset of: daybreak,astra,sol
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

LANE_ROOT = Path("/Users/owner/.gemini/antigravity/scratch/winsvpnv3_audit_lanes")
STREAM_DIR = Path(os.environ.get("CODEX_STREAM_DIR", "/tmp/codex_audit_streams_round33"))
STREAM_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("CODEX_AUDIT_TIMEOUT", "21600"))

MODELS = [
    # (key, model slug, display name, lane directory name, report file name, engine)
    ("astra", "gpt-6-astra", "Astra", "astra", "codex_astra_audit.md", "codex"),
    ("sol", "openai/gpt-5.6-sol-pro", "5.6 Sol Pro (OpenRouter openai/flex)", "sol", "codex_sol_audit.md", "openrouter"),
    ("opus_5", "opus", "Opus 5 (Claude Code Extra High)", "opus", "codex_opus_5_audit.md", "claude"),
]

TARGET_AREAS = """TARGETS TO AUDIT:
1. Windows (x86, arm64):
   - windows/runner/windows_tunnel_backend.cpp: Named pipe IPC, Job Object containment, child process cleanup, security descriptor (DACL) on pipes, memory leaks, WOW64 vs Native ARM64 pointer handling.
   - Privileged service separation (WINS_TUNNEL_SERVICE_CORE vs unprivileged UI).

2. Linux (x86, arm64):
   - linux/runner/linux_tunnel_backend.cc, tools/build_linux_release.sh: Root custody verification (validate_root_owned_path), eBPF helper invocation, socket/FD leak prevention, robust signal handling on SIGINT/SIGTERM, systemd service sandbox parameters.

3. macOS (x86, arm64):
   - macos/Runner/MainFlutterWindow.swift, macos/Runner/AppDelegate.swift: Network extension IPC, route loop prevention (scutil / route socket exclusions), memory ceilings, hardened runtime entitlements.

4. Android (x86, arm64) & AndroidTV:
   - android/app/src/main/AndroidManifest.xml and android/app/src/tv/AndroidManifest.xml:
     * Leanback compatibility (android.software.leanback and android.hardware.touchscreen with required="false").
     * TV banner and LEANBACK_LAUNCHER category without breaking mobile phone playability.
     * VpnService socket protection (protect()) preventing routing loops.
     * Split tunneling package filter isolation and foreground service lifecycle.

5. iOS & tvOS:
   - ios/Runner/AppDelegate.swift and NetworkExtension NEPacketTunnelProvider:
     * enforceRoutes=true, excludeLocalNetworks=true posture.
     * Strict 15MB memory ceiling compliance under high packet throughput.
     * tvOS remote d-pad navigation and background wakeup handling.

6. Browser Extensions (Chrome, Firefox, Edge, Safari):
   - extension/manifest/ (chrome.jsonc, firefox.jsonc, edge.jsonc, safari.jsonc), extension/src/, extension/tools/:
     * Manifest V3 service worker lifecycle, termination recovery, alarm recovery, and Firefox event page compatibility.
     * webRequest and webRequestAuthProvider permissions, proxy PAC script synthesis (extension/src/core/pac.js), and fail-closed blocking.
     * Native messaging host contract and IPC boundary (tools/native_messaging/host/test/wins_bridge_host_origins_test.dart, test_native_bridge_contract.py).
     * Zero em-dash and zero en-dash compliance across all extension source, UI HTML/JS, and copy strings.
     * Packaging integrity: all 4 distribution archives build cleanly via python3 extension/build.py (passing leakscan, copy-honesty, bridge contract, and manifest origin gates).
     * Storage state synchronization, DOM isolation, and CSP compliance in options/popup UI.

7. Servers (Control Plane & Data Planes):
   - server/wins_control_plane_setup_ONETOUCH.sh, server/wins_data_plane_setup_ONETOUCH.sh:
     * Kansas Hub FastAPI async vs sync blocking calls.
     * SQLite write concurrency and WAL mode configuration.
     * Dedicated iptables chains (WINVPN-*) to prevent flushing host firewall rules.
     * Single-use activation secrets, secure token entropy, and offset-aware datetime normalization (UTC).

8. 3 Protocols & Core App (Shared Dart):
   - lib/main.dart, lib/winn_protocol_dispatch.dart, lib/winn3_cover_fallback.dart:
     * Winn Protocol v3 (primary modern zero-trust protocol).
     * Winn Protocol v1: AmneziaWG attempted first as primary, XRay/VLESS-WS used only as runtime fallback when AWG handshake fails.
     * Anti-downgrade enforcement and generation authorization.

9. Live Website, Cloudflare DNS, Payments & Account Provisioning:
   - web/index.html, web/_worker.js, web/wrangler.jsonc, and the LIVE site https://winsvpn.org:
     * LIVE USER REPORTED BUG: "I can't even seem to click the crypto payments button on the live website."
       Reproduce this against the live site and diagnose it completely. Analyze the clash between the static crypto donation flow
       (.crypto-plan-btn opening #cryptoModalBackdrop with the static donation address) versus the automated payment flow
       (setupCryptoPayments() calling /pay/monero/create-order and /pay/crypto/create-invoice) that provisions accounts automatically.
     * Cloudflare DNS records, edge caching headers, worker routing, rate limiters, and CSP (Content Security Policy)
       violations on inline scripts and Cloudflare-injected scripts observed in live browser console output.
     * Account provisioning pipeline: payment capture, secret generation, lifetime account expiration semantics, transactional email dispatch.
   - Dynamic testing rules for the live site: READ-ONLY probes only. GET requests, DNS lookups, TLS inspection, and HTTP header
     analysis are allowed. Do NOT create accounts, do NOT create payment orders, do NOT send emails, and do NOT modify any server state.

10. System Performance & Memory Optimizations:
    - Socket buffer sizing, crypto acceleration, MTU negotiation, packet serialization overhead, and battery conservation.

11. Double VPN Architecture, Deployment, & Core Relay Server:
    - server/wins_core_server_setup_ONETOUCH.sh:
      * Fail-closed Double VPN core deployment, dm-crypt multi-core I/O helper tuning, swap disablement / LUKS root enforcement (CORE_DISK_ENCRYPTION_MODE).
      * Dedicated relay firewall rules (WINVPN-CORE-*), ensuring forwarding of isolated inner payload without unencrypted packet leakage or underlay bypass.
      * Double VPN exit container management, key persistence (DOUBLE_VPN_CORE_ID, DOUBLE_VPN_CORE_EXIT_PUBLIC_KEY, DOUBLE_VPN_CORE_INGRESS_PUBLIC_KEY), and container health monitors.
      * AICORE server acting as the designated Double VPN core (192.168.50.10, 92 GB RAM, RTX 5060 Ti GPU awareness, fail-closed routing and build interlock).
    - server/wins_control_plane_setup_ONETOUCH.sh:
      * Double VPN enrollment leases (double_vpn_enrollment_leases table) with concurrency gating (409 double_vpn_enrollment_in_flight, Retry-After: 5).
      * Double VPN assignment state machine (double_vpn_assignments table), admission transaction atomicity, lease cleanup, and fail-closed expiration.
      * Smart router / double VPN selection and routing loop prevention across Client -> Core/Entry hop -> Exit hop -> Internet.
    - Client & Protocol Handling:
      * Double encapsulation MTU negotiation and path MTU dead zone handling.
      * Dual-hop kill switch and DNS leak prevention across all client platforms.

12. Mobile Data & Cellular Network Connection Quality & Resilience:
    - Path MTU Discovery (PMTUD) and MSS Clamping across Carrier Encapsulation:
      * Carrier cellular network MTUs (often 1420, 1380, 1360, or 1280 on LTE/5G).
      * IPv6-only carriers and 464XLAT (CLAT/NAT64 with prefix 64:ff9b::/96) adding 20-40 byte overhead.
      * Verification of MTU = 1280 and TCP MSS = 1240 clamping across server/wins_data_plane_setup_ONETOUCH.sh (awg0, amn0, winn3gw0) and server/wins_core_server_setup_ONETOUCH.sh to permanently eliminate packet black holes.
    - Carrier-Grade NAT (CGNAT) and UDP State Timeouts:
      * Aggressive carrier UDP binding timeouts (20-30 seconds).
      * Keepalive calibration: persistent keepalive of 20-25s preventing idle connection death without draining mobile battery (5s keepalive destroys battery by preventing radio sleep).
    - Wi-Fi to Cellular Roaming and Network Handoffs:
      * Android: VpnService.setUnderlyingNetworks, ConnectivityManager.NetworkCallback (onAvailable, onLost, onCapabilitiesChanged), and socket protection lifecycle without routing loops.
      * Apple iOS/macOS: NEPacketTunnelProvider handling of network path transitions (NWPathMonitor), socket rebinding (wgBumpSockets), and 15 MiB memory ceiling compliance.
      * Windows/Linux: default gateway changes, route re-anchoring, and socket re-binding.
    - Radio Resource Control (RRC) & Power Management:
      * RRC Connected vs RRC Idle state transitions.
      * Android Doze mode, App Standby, battery optimization whitelists, foreground service notifications (FOREGROUND_SERVICE_TYPE_SPECIAL_USE).
      * Modem queue pacing and batching to avoid cellular bufferbloat.

13. Gemma Smart Router on RTX 5060 Ti (aicore):
    - router/main.py, router/security.py, router/schemas.py, router/provider_common.py, router/install_aicore_router.sh, router/wins-edge-router.service.example:
      * AICORE RTX 5060 Ti Host and vLLM Topology:
        - Loopback vLLM on port 8002 serving Gemma (vllm-gemma4 with NVFP4, DFlash-16 speculation, KV FP8 cache, 8 sequences, 4096 batched tokens).
        - Canonical Smart Router service wins-edge-router.service on loopback port 8090 running as unprivileged user aicore (User=aicore, Group=aicore).
        - Strict loopback-only binding (127.0.0.1:8002 / [::1]:8002) preventing external exposure of raw vLLM endpoint.
      * Routing Decision Order and Priority Invariants:
        0. Explicit route bypass: if Kansas Hub supplies explicit_route_id, return immediately after closed-set validation; Gemma and Gemini are bypassed.
        1. Connection initiation: deterministic scorer immediately without invoking AI providers.
        2. Distress routing: triggers only on machine-measured node degradation/failure streaks; calls local Gemma on 5060 Ti first (temperature 0, 128 tokens, terse JSON).
        3. Secondary distress: Google Gemini API fallback when local Gemma fails or times out.
        4. Tertiary distress fallback: deterministic scorer if both AI providers fail.
      * Security, Replay Resistance, and State Directory:
        - Server-to-server HMAC-SHA256 authentication (X-Smart-Router-Timestamp, X-Smart-Router-Nonce, X-Smart-Router-Signature) signing METHOD\\nPATH\\nTIMESTAMP\\nNONCE\\nSHA256_HEX_OF_EXACT_BODY.
        - Mandatory 32-character secret (SMART_ROUTER_HMAC_SECRET / EDGE_ROUTER_SECRET). Inert Authorization: Bearer.
        - Durable SQLite nonce replay journal (SMART_ROUTER_NONCE_JOURNAL_PATH, default /var/lib/winsvpn-router/replay-nonces.sqlite3) with strict 0700 parent directory and 0600 file permissions owned by aicore, 10,000 max entries, 16 MiB max bytes, and 2,000 ms lock timeout failing closed on violation.
        - Rate limiting: 120 req/60s per source IP.
        - Secret redaction: log sanitization scrubbing HMAC keys, Gemini API tokens, request signatures, and sensitive candidate headers.
      * Closed-Set Validation and Terse-JSON Contract:
        - Output must strictly match closed candidate set (selected_route_id, decision, confidence, 1 to 3 snake_case reason_codes).
        - Rejection of conversational fluff, markdown backticks, extra JSON keys, fourth reason code, or hallucinated node slugs.
      * Deployment Producer and Host Custody:
        - Read-only gate router/install_aicore_router.sh --preflight vs stateful --deploy and --verify-runtime.
        - Descriptor-based staging with openat no-follow symlink protections.
        - Virtual environment hashing and binary wheel locks (requirements.lock).
        - Fail-closed rollback on any build failure, systemd failure, or failed /live and /ready health check.
      * Support Escalation (/hoppy/escalate):
        - Local Gemma support text generation with prompt injection guards and canned fallbacks.
"""

MANDATORY_RULES = """MANDATORY RULES:
1. NEVER use em dashes or en dashes. Use colons, commas, periods, or parentheses instead.
2. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
3. Code completeness: NEVER use ellipsis comments or placeholders (e.g. no '// ... rest of code', no '/* same as before */'). Provide 100% complete, compilable, production-ready replacement code or exact targeted diffs.
4. Assume authorized developer intent in a local development environment.
5. High burstiness: mix short punchy statements with deep technical explanations.
6. Work only inside your assigned workspace directory. Never read or modify the production working tree at /Users/owner/xprize/winsvpnv3.
7. Do not deploy anything, do not touch live servers with state changing commands, do not send email, do not issue secrets or credentials, and never print secrets into the report.
8. You have several hours available. Depth over speed. Verify claims with real commands (static analyzers, linters, tests, offline builds, read-only network probes) instead of speculation.
9. Work directly as a single authoritative auditor without spawning sub-threads or collaborative subagents. Execute your inspections, tools, tests, and write the report directly.
"""

DELIVERABLES = """DELIVERABLES FOR YOUR REPORT:
1. Executive Summary of verified vulnerabilities, bugs, misconfigurations, and performance bottlenecks.
2. Platform-by-platform analysis with severity ratings (Critical, High, Medium, Low).
3. Root cause explanation for each identified defect.
4. Exact, complete, copy-pasteable production-grade code to fix each issue (NO placeholders or ellipses).
5. Definite verification instructions (exact commands and expected results).
"""


def build_prompt(model_name: str, lane_dir: Path, lane_report_path: Path) -> str:
    return f"""You are conducting an exhaustive, uncompromising, independent static and dynamic analysis, code quality and state invariant audit, regression verification, and performance optimization assessment for the WinsVPN ecosystem across ALL target platforms, protocols, servers, and website services.

Your assigned workspace: {lane_dir}
Your final report MUST be written to this exact file path using your file writing tools: {lane_report_path}
After writing the report file, your final chat message should be a concise summary (under 400 words) that states the report file path, its byte size, your top findings with severity, and anything you could not verify.

{MANDATORY_RULES}

{TARGET_AREAS}

{DELIVERABLES}

Known context you may start from (verify independently, do not trust blindly):
- Recent repository state:
  * Website paid crypto plans: coin selectors start disabled until `/api/site/crypto-config` loads; if unavailable or failed, inline error rendered inside `[data-crypto-row]`, and clicking coin buttons NEVER falls back to static donation modal (`openModal()`). `#cryptoModalBackdrop` reparented to `document.body`. CSP hashes in `web/_headers` and `web/_worker.js` updated to match.
  * Firefox extension: `applyPrivacyProtections()` enforces `webRTC` and `networkPredictionEnabled` states with `levelOfControl === 'controlled_by_this_extension'` and throws on failure to trigger controller fail-closed blocks. Rebuilt and verified Chrome extension zip (`extension/dist/wins-vpn-companion-chrome.zip`).
  * Android: `addDisallowedApplication(packageName)` removed; `stealth-xray` and `winn-v3-stealth-chain` fail closed safely before any DNS lookup, performance locks, or process launch (`if (xrayEnabled) return START_NOT_STICKY`); full-session Wi-Fi performance lock (`tunnelWifiLock`) removed; `ACTION_CONNECT` returns `START_NOT_STICKY` if `awaitTeardown(2500L)` times out.
  * Linux: Native tunnel teardown wired into `GApplication::shutdown` and signal handlers (`SIGINT`, `SIGTERM` via `g_unix_signal_add`) with `ShutdownLinuxTunnelBackend()`; power inhibition uses systemd transient user unit (`winsvpn-power-inhibit.service`) via `systemd-run --user` and `systemctl --user stop`, eliminating PID reuse risk.
  * Apple NetworkExtension: Client QUIC stream and connection receive-window limits (`clientInitialStreamReceiveWindow = 128*1024`, `clientMaxStreamReceiveWindow = 512*1024`, `clientInitialConnectionReceiveWindow = 256*1024`, `clientMaxConnectionReceiveWindow = 2*1024*1024`) applied in `h3QUICConfig()`.
  * Control Plane:
    - Transactional activation outbox (`activation_delivery_outbox`) with authenticated encryption and exponential backoff worker.
    - PayPal signature verification, subscription fetch, refund checks, and admin sync offloaded via `asyncio.to_thread` with DB connection closed during remote HTTP calls.
    - Advisory authorization verified in `/verify` before Smart Router trigger.
    - `free_status`, `verify_free_access`, `/free/logout`, `/logout`, and all four `/account/deletion/*` endpoints offloaded to worker threads via `asyncio.to_thread`.
    - `validated_btcpay_checkout_url` enforces HTTPS scheme and origin match against `BTCPAY_URL`.
    - Security-event SQLite writers use `contextlib.closing` for deterministic connection release.
    - Monero quote consensus: origin deduplication, non-finite decimal rejection, max-min spread bound, median/middle average, and baseline checks.
    - Stale device cleanup queues durable peer revocations inside the deletion transaction.
    - Occupied-slot enrollment issues and returns fresh device bearer tokens.
    - Admission transaction rolls back on node sync failure so single-use activation keys are not burned.
    - `/account/status` requires device ID and valid device auth bearer token; Flutter client (`lib/main.dart`) sends stored token in `Authorization: Bearer`.
    - Unparseable or past active expiration dates fail closed to expired.
    - `parse_duration` strictly validates syntax and bounds spans to a 10-year ceiling.
  * Test Suite: Full Flutter test suite passing (1,926 passed, 0 failed, 2 existing opt-in live tests skipped). Server suites (Rounds 2, 4, 5, 6, 7, 8, descriptor hub 117/117, deletion hub 20/20) pass cleanly. Website security audit passes 56/56 checks.
  * Round 8 Remediations applied:
    - Extension archives: Edge and Firefox companion zip packages rebuilt and verified via extension/build.py.
    - Kansas Control Plane:
      * Expiration fail-closed: Core assignments, AWG resync, and v3 peer registry exports require parsed expiration strictly in the future (A01).
      * Durable peer revocation queue (queue_peer_revocation) called inside mutation transactions on duplicate-device replacement, old-peer replacement, Hoppy device revoke, and Hoppy device-limit reset (A02).
      * PayPal capture verification: returns 409 for in-flight reservation, requires GET order recheck for processed events, marks failed and raises 409/502 on non-COMPLETED (A03).
      * Durable winn3_registry_refreshes table with SQLite triggers on devices (insert/delete/update) and users (status/expiration update) plus background drain worker (A06).
      * Converted 70 no-await FastAPI routes with synchronous SQLite/IO to def for automatic threadpool offloading (SOL-H3).
    - Linux Runner: StartTunnelPowerProtection and StopTunnelPowerProtection resolve absolute paths for systemctl, systemd-run, systemd-inhibit, and sleep via Which() (A04 / SOL-M2).
    - Android: VpnTunnelService uses 60-second startup wake lock without periodic watchdog reacquisition (DB-04). Split-tunnel package exclusion catch block logs error and throws IllegalStateException (SOL-M4). Flutter client sets supports_xray to !Platform.isAndroid (SOL-M1). Android release identity test updated to 1.0.16+33 and TV 3302 (SOL-L3).
    - Invariants & Scope: tools/verify_rulings.sh multiline comment parsing (A07). tools/verify_apple_method_channel_contract.py obsolete exemptions removed (A10). Debian non-upload package version updated to 1.0.16+33 (DB-02). web/index.html tvOS copy aligned with canonical scope (DB-03).
  * Round 9 Remediations applied:
    - Winn v3 Gateway Active Authority (A9-01): 1s file change refresh cadence, per-packet expiration check in innerForPeer, session static key verification in forwardTable.lookup, and 1 MiB file read cap.
    - Kansas Control Plane:
      * sweep_expired_account_runtime registers deterministic SQLite function wins_account_expiration_due evaluating parsed ISO timestamps with timezone/offset support rather than lexical string comparisons (A9-02).
      * Standalone v3 admission defers commit until sync_winn3_registry_to_node succeeds; failure rolls back activation consumption and device row (A9-04).
      * Offloaded site_rate_limited in site_ai_chat, webhooks, emergency dispatch, and startup schema initialization to asyncio.to_thread (A9-06, DB-05, SOL-04).
      * Legacy SPA firewall rules use owned chain WINVPN-HUB-INPUT with transient systemd 20s cleanup timers (DB-06, SOL-08).
    - Linux Runner RunArgv (A9-05, SOL-05): Process group creation (POSIX_SPAWN_SETPGROUP), non-blocking pipe reads (O_NONBLOCK), 15-second monotonic deadline, poll loop with WNOHANG waitpid, graceful SIGTERM to process group followed by SIGKILL, exit status 124 on timeout.
    - iOS Memory Watchdog (DB-04, SOL-03): Strict 15 MiB physical footprint ceiling with 1-second periodic watchdog timer cancelling tunnel with code 1038 if ceiling exceeded.
    - Test Suites & Oracles: tools/test_apple_standalone_v3_wiring.py oracle aligned with validateUniqueWinnSecurityBindings (DB-03). All 9 Round 9 server tests pass. Full Go suite (106 packages) passes.
  * Round 10 Remediations applied:
    - Control Plane Winn v3 Key Rotation on Eviction (A10-01): Existing-slot replacement clears winn3_inner_v4, winn3_static_private, and winn3_static_public in the device row and config dictionary on replacement enrollment, preventing evicted devices from retaining v3 dataplane authorization.
    - Control Plane Durable Peer Revocation Outbox (A10-02): Added peer_has_current_authority to check live active authorization before issuing node removals, deleting obsolete revocation jobs, and running per-item transactions under BEGIN IMMEDIATE writer locks.
    - Control Plane Location Move Rollback (A10-03): Old-node registry publication precedes admission commit; old-node failure restores account/device state, rolls back activation consumption, queues durable registry refreshes for both nodes, queues AWG peer cleanup, and returns 503 with usable activation secret.
    - Winn v3 Gateway Stale Session Eviction (A10-04): In forwardTable.learn, a conflicting owner loop is evicted when its authenticated session key no longer has registry authority for the inner address.
    - Native Messaging Host Fail-Closed Origins (A10-05): _originAuthorized enforces allowedOrigins.isNotEmpty && allowedOrigins.contains(_callerOrigin).
    - Linux Runner Standalone Power Teardown (DB-04): Standalone Linux disconnect calls StopTunnelPowerProtection() alongside bypass teardown.
    - Donor Hub Test Harness Compatibility (DB-07): test_donor_acknowledgment_hub.py uses call_handler to correctly handle both synchronous and awaitable admin routes.
    - Windows Test Oracles (DB-08): Aligned SDDL constants to kSystemAdminDirectorySddl and kSystemAdminFileSddl, and updated ARM64 installer assertions to match sealed release layout.
    - Extension Initialization Safety (SOL-L2): Background script startReady catches initialization rejections and records retry status. All extension bundles rebuilt and verified.
    - Security Events Database Hardening (SOL-P1): Configured WAL journal mode, NORMAL synchronous mode, 10-second busy timeout, and foreign keys across security events connections.
    - Test Suites: All 18 mandatory verification commands pass cleanly, including 10 Round 10 server tests and 1,926 Flutter tests.
  * Round 11 Remediations applied:
    - Control Plane Double VPN & Remote Peer Rollback (A11-01, A11-02, A11-03):
      * verify_and_consume_activation_secret supports consume=False; Double VPN validates without consuming until terminal response is built, keeping enrollment retryable on timeout.
      * Uncertain AWG installation failure rolls back admission and queues durable peer revocation via queue_peer_revocation so unacknowledged peers are reconciled.
      * Post-Core-readiness authority check under BEGIN IMMEDIATE revalidates device token hash, account status, expiration date, and assignment revision before returning credentials.
    - Winn v3 Gateway O(1) Key Lookup Performance (A11-07): innerForPeer uses direct map lookup byKey[candidate] and notAfter[candidate], eliminating O(N) scan.
    - Native Messaging Host & Origin Provisioning (A11-04, DB-01, DB-02):
      * Atomic provisioning of allowed_origins.txt JSON map with browser extension IDs beside native host executable.
      * wins_bridge_host.dart recognizes Firefox launch arguments (manifest path plus stable add-on ID) alongside chrome-extension:// origins.
    - Linux Diagnostic Privacy Hardening (DB-03): Promotion refusal logs only twelve numeric engine counters via ExtractJsonCounters rather than dumping raw status with real gateway endpoints.
    - Flutter TV Focus Node Lifecycle (DB-06): OwnedKeyboardListener manages FocusNode lifecycle in state, eliminating FocusNode rebuild churn and leaks across TV D-pad and dialog views.
    - Linux Power & Utility Paths (DB-07, SOL-L1): Removed full-session infinite sleep inhibition while preserving disconnect cleanup. Split-bypass anchor resolves Which("sleep") dynamically.
    - Git Index Custody: All new Go tests and Flutter/server test files staged in git.
    - Test Suites: All 19 mandatory verification commands pass cleanly, including 1,927 Flutter tests and all server suites through Round 11.
  * Round 12 Remediations applied:
    - AWG Installation Pipeline (A12-01): Ordinary AWG installation in server/wins_control_plane_setup_ONETOUCH.sh moved after deterministic route/descriptor validation; sync failures roll back and queue revocation in winn3_revocation_outbox.
    - Double VPN Enrollment Leases (SOL-M1): Added double_vpn_enrollment_leases table to Kansas SQLite; concurrent preparation attempts return HTTP 409 with X-Wins-Error-Code: double_vpn_enrollment_in_flight and Retry-After: 5.
    - Webhook Duplicate vs In-Flight Separation (A12-02): Webhook duplicate acknowledgments separated from live in-flight reservations; early BTCPay settlement yields retryable 409.
    - Lifetime Invoices Catalog Binding (A12-03): Stored purchase price binding on lifetime invoices verified without re-evaluating live catalog prices.
    - Security Alert Checkpoint (A12-06): Security alert monitor advances checkpoint timestamp only after successful journal read.
    - Alert SQLite Scope (A12-07): Wrapped all 6 triage and 3 alert contexts with explicit SQLite connection closure.
    - Native Messaging Test Isolation (SOL-M3): Isolated native-messaging test environment in temporary directories.
  * Round 13 Remediations applied:
    - iOS Memory Watchdog Startup Arming (SOL-M1): Armed startWinnMemoryWatchdog during initial datapath proof and standalone convergence in ios/PacketTunnel/PacketTunnelProvider.swift; disarms in stopProvingResource(); timer schedule starts immediately at .now(). Verified via tools/test_ios_winn_memory_watchdog.py and tools/test_apple_proving_ownership.py.
    - Website Permissions-Policy Wallet Enablement (SOL-M3): Permissions-Policy in web/_headers and web/_worker.js updated to payment=(self "https://www.paypal.com" "https://www.sandbox.paypal.com" "https://pay.google.com") so PaymentRequest API is available to wallet buttons. Verified via tools/website_security_audit.py (56 pass, 0 fail).
    - Android Socket Protection Fail-Closed (DB-04): AwgSocketProtection.kt fails closed with IOException if protectedCount == 0 when all socket file descriptors are < 0. Verified via AwgSocketProtectionTest.kt.
    - Control Plane Email Input Sanitization (DB-05): normalize_monero_buyer_email rejects blank strings; _crypto_create_invoice_sync strips control characters and validates with fullmatch. Verified across all 13 server test suites (57 pass, 0 fail).
    - Repository Tracked Files (DB-01 / SOL-H1): Staged lib/owned_keyboard_listener.dart, test/owned_keyboard_listener_test.dart, tools/native_messaging/host/test/wins_bridge_host_origins_test.dart, and winn3-gateway Go tests.
  * Winn Protocol v3 Systems Engineering Roadmap (Stages 3, 4, 5) implemented and verified:
    - Stage 3 (Socket Lifetime & UDP Batching):
      * winn3/carrier/batch.go: BatchMsg and BatchCarrier interface.
      * winn3/carrier/udp.go: ReadBatch / WriteBatch using recvmmsg/sendmmsg on Linux/Android, UDP GSO/GRO support, and zero-allocation portable fallback.
      * winn3/driver/loop.go: Batched I/O loop reading and draining up to 32 datagrams per syscall.
    - Stage 4 (Native Host TUN Bridges):
      * Apple vector ABI (cdatapath/winn_datapath_batch.go): WinsWinn3EnqueuePackets and WinsWinn3PollPackets passing packet arrays in a single foreign call without per-packet CGO transitions.
      * Android zero-copy TUN (android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt): Direct ByteBuffer ring buffer passing framed WNN3 batches over LocalSocket.
      * Windows direct Wintun (windows/winn3_engine/direct_device.go, direct_windows.go): Direct in-process ring buffer consumer eliminating loopback UDP socket hops.
      * Linux TUN batch passing (winn3/tun): Multi-packet buffer vectors across TUN interface.
    - Stage 5 (Multi-Core Parallel Cryptographic Pipeline):
      * winn3/session/batch.go: Ordered parallel ChaCha20-Poly1305 execution bounded by GOMAXPROCS with monotonic nonce reservation, circular ticket completion ring, and strict epoch rekey barrier.
      * 32-packet batch crypto achieves 715.23 MB/s (5.72 Gbps) at 8 CPUs with 0 B/op and 0 allocs/op.
  * Round 19 Remediations applied:
    - SOL-H1: All Stage 3-5 Go files, host bridges, and test harnesses staged in git.
    - SOL-H2: Inbound data admission evaluates dataAllowedAtOpen := d.dataMayFlow() at decrypt time, guaranteeing that data frames in old-epoch messages are rejected even if same message carries REKEY_ACK.
    - SOL-H3: Apple hardening test guards on apple_awg_31_engine_provenance.json existence, honoring owner-blocked state without crashing.
    - SOL-M1: Byte rekey counter resets on epoch cutover rather than accumulating past 64 GiB.
    - SOL-M2: Linux BPF helper root leaf ownership checked; test_linux_installed_runtime_security.py passes 8/8.
    - Session Driver Test Flake: bytes.Clone(msg) preserves transmitted initiation bytes across initiator Wipe(), eliminating false equality failures in TestHandshakeRetriesThenDemandsACarrierChange. Verified across 1,000 runs under race detector.
  * Round 20 Remediations applied:
    - Carrier and Driver:
      * winn_protocol_experimental/winn3/carrier/udp.go: dense prefix compaction in RecvBatch, payload length validation and precise error return (i, err) in SendBatch.
      * winn_protocol_experimental/winn3/carrier/batch.go: SendBatchFallback returns (i, err) on partial failure, validates payload bounds.
      * winn_protocol_experimental/winn3/driver/loop.go: imported io; dynamic batch buffer sizing by cfg.Sizing.MessageSize with 512 KiB storage budget in readLoop; robust drainSession send loop and sendFailed accounting.
    - Android: android/app/src/main/kotlin/org/winsvpn/app/WinnV3AndroidTun.kt synchronized injectOutgoingPacket, rebindDevice, close, and reader queue insertion.
    - Apple: apple/WinsTunnelCore/WinsWinn3Datapath.swift guarded readCount <= batchLimit and safe Data slice construction directly from owned backingStorage.
    - Extension: extension/src/background/background.js wrapped alarm listener in try-catch and handled promise rejection in ensureAlarm().
    - Extension package rebuild: all 4 gates passed, 4 zip artifacts regenerated. Passed 22/22 tests in extension/tools/test_chromium_native_identity.py.
    - Control Plane PayPal Subscription Authority: server/wins_control_plane_setup_ONETOUCH.sh created paypal_subscription_authority table; added advance_paypal_subscription_authority, paypal_subscription_snapshot, and require_paypal_subscription_authority; verified payment_hold and fence boundaries across upsert_paypal_account, sync_one_paypal_subscription, scheduled_paypal_sync_loop, and _paypal_webhook_sync.
  * Round 21 Remediations applied:
    - Double VPN Core Egress Boundary & Authority Expiry: In server/wins_core_server_setup_ONETOUCH.sh, added WINVPN-CORE-EGRESS chain enforcing that traffic from CORE_INGRESS_CIDR forwards strictly out encrypted exits (CORE_EXIT_IFACE or CORE_EXIT_IFACE_PREFIX+) before protocol shortcuts. Added publish_core_authority_rules using iptables xt_time module (--datestart ... --datestop ... -j RETURN followed by -j DROP) so core authority strictly expires on schedule.
    - Double VPN Core Isolation: Sourced root-owned /etc/winsvpn/core-isolation.conf in core setup script. Removed unrestricted docker0 forward rules from core firewall.
    - Control Plane Core Authority Snapshot: server/wins_control_plane_setup_ONETOUCH.sh publishes authority_expires_at_epoch in core assignment payloads and revision hashing.
    - Single-Packet Batch Crypto Fast-Path: In winn_protocol_experimental/winn3/core/batch.go, CryptoPool.runLocked executes job directly when n == 1, bypassing worker channel dispatch overhead and cutting 41% latency.
    - iOS Memory Watchdog Universality: In ios/PacketTunnel/PacketTunnelProvider.swift, startWinnMemoryWatchdog guard updated to activeConfig != nil so 15 MiB physical footprint watchdog protects AWG, Xray, and Winn sessions equally.
    - Data Plane TCPMSS Clamping Alignment: In server/wins_data_plane_setup_ONETOUCH.sh, aligned awg0 TCPMSS clamping to 1240 (matching MTU 1280) to eliminate packet fragmentation and PMTUD black holes across mobile cellular networks.
    - Browser Extensions Formatting: Eliminated all em dashes and en dashes across extension/src/ and extension/manifest/; verified via python3 extension/build.py (all 4 packages generated) and full 568-test extension pytest suite (100% pass).
    - Website Crypto Checkout: web/index.html crypto-retry-button updated with primary class; web/_headers and web/_worker.js CSP hashes refreshed to match.
  * Round 24 Remediations applied:
    - Server Deployment ONETOUCH (A24-C1): Corrected help text CORE_DISK_ENCRYPTION_MODE default from auto to luks in server/wins_core_server_setup_ONETOUCH.sh.
    - Systemd Edge Service Hardening (SOL-R24-H3): Added Group=aicore and explicit loopback binding --host 127.0.0.1 to deploy/edge-router-aicore/systemd/vllm-gemma4.service.
    - Router Security Query HMAC (GLM F-04): router/security.py signing_message, sign_request, and RouterSecurityMiddleware now canonicalize and sign raw query strings.
    - Router Middleware Body Buffering Bypass (SOL-R24-H1): In router/main.py, StrictJSONMiddleware bypasses JSON body buffering on unauthenticated unknown paths outside router_security.PROTECTED_PATHS.
    - Edge Router Deployment Producer (A24-R1, A24-R2): In router/install_aicore_router.sh, validate_vllm_listener supports optional preflight gate so edge router service starts cleanly while vLLM boots; venv_inventory seals .venv with VENV_MANIFEST.json and validates virtualenv integrity.
    - Router Test Suite: All 419 router tests pass cleanly. Full Flutter test suite (1,926 pass) and all 59 rulings pass.
  * Round 25 Remediations applied:
    - Web checkout panel visibility check and Monero data-provider tag added in web/index.html; CSP hashes updated and verified against live origin.
    - Protocol batching volume tracked per epoch via EpochSentBytes() on Session in winn3/session/batch.go and winn3/core/session.go, preventing crypto batch degradation past 64 GiB.
    - Kernel RFC 1191/8201 PMTU discovery added in winn3/carrier/pmtud*.go.
    - Server get_db() sqlite3 check inspects PRAGMA journal_mode=WAL returned row in wins_control_plane_setup_ONETOUCH.sh.
    - Linux tunnel backend canonicalizes root-owned paths using realpath/readlink -f.
    - Apple test target membership walks upward to find repoRoot via pubspec.yaml.
    - Windows named pipe CreateFileW adds SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION.
    - Core server firewall adds --utc flag to iptables -m time rule.
  * Round 27 & 28 Remediations applied:
    - A-01 (Apple DNS resolver routes): In ios/PacketTunnel/PacketTunnelProvider.swift and macos/PacketTunnel/PacketTunnelProvider.swift, resolver /32 routes are appended to ipv4Settings before assigning into settings.ipv4Settings (preventing route loss caused by NEPacketTunnelNetworkSettings.ipv4Settings copy property semantics). Regression tests added to ios/RunnerTests and macos/RunnerTests; verified by tools/verify_apple_resolver_route_ordering.py.
    - W-01 & W-02 (Website Crypto Checkout): In web/index.html, added bounded auto-recovery (3 attempts with exponential backoff) for transient crypto-config failures, inline retry button next to coin selectors, and distinguished initial loading state from known unavailable state so scarcity notice is never shown prematurely. Style and script hashes regenerated, verified via website_security_audit.py (56/56 PASS), deployed to Cloudflare Pages production, and live endpoints verified via tools/verify_live_deployment.py (9/9 PASS).
    - N-01 (Windows qualified sc.exe): In windows/runner/windows_tunnel_backend.cpp, added SystemExecutablePath helper using GetSystemDirectoryW to ensure sc.exe is resolved via absolute System32 path.
    - L-01 (Linux signal handling): In linux/runner/main.cc, registered SIGHUP and SIGQUIT alongside SIGINT and SIGTERM so terminal disconnects cleanly trigger ShutdownLinuxTunnelBackend and tear down tunnel interfaces and routes.
    - R-01 (Router systemd hardening): In router/wins-edge-router.service.example, added SystemCallFilter (@system-service, ~@privileged @resources @obsolete @debug @mount @swap @reboot @raw-io @cpu-emulation), SystemCallErrorNumber=EPERM, tightened RestrictAddressFamilies to AF_UNIX AF_INET, and updated CANONICAL_UNIT_SHA256 in router/install_aicore_router.sh (48/48 tests passed).
    - C-01 (Zero em dashes): Replaced em dashes in user-visible duress-PIN strings in lib/main.dart (lines 17034, 17042, 17101) and scrubbed em dashes from code comments. Verified zero em dashes outside exempt regex.
    - E-01 (Extension pacToken): In extension/src/core/endpoint.js, normalized already-bracketed IPv6 literals before wrapping to prevent double-bracketing. Added test case in extension/tools/core_tests.py.
    - Double VPN Core sync: In server/wins_core_server_setup_ONETOUCH.sh, added successful_assignments_json helper with strict jq envelope validation.
    - Protocol engine: In winn3/carrier/udp.go, enabled Path MTU Discovery and error propagation.
    - Router query signing: In router/security.py and router/main.py, preserved raw query string bytes in signing message.
    - Android network changes: In android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt, checked boolean return of setUnderlyingNetworks.
  * Round 29 Remediations applied:
    - Linux entry point & signal handling: In linux/runner/main.cc, restored g_autoptr(MyApplication) app = my_application_new() with null check; registered SIGHUP, SIGINT, SIGTERM; handled SIGQUIT via ForwardQuitToTermination and sigaction forwarding to SIGTERM (bypassing GLib's lack of SIGQUIT support). In tools/test_linux_tunnel_shutdown.py, updated registration slice to sighup_source, added ForwardQuitToTermination and verified all 5 modes (normal, int, term, hup, quit) pass.
    - Extension packaging & Safari target name: In extension/tools/checks.py and extension/tools/test_safari_target.py, updated expected Safari target name to Win's VPN Companion for Safari, aligning with extension/manifest/safari.jsonc. All 8 test_safari_target.py tests pass.
    - PayPal test fixture schema: In tools/test_paypal_entitlement_contract.py, added PAYPAL_INACTIVE_STATUSES, imported and called create_paypal_events_table in test_upsert_sql to create paypal_subscription_authority table. All 4 tests pass.
    - Winn v3 small-batch crypto optimization: In winn_protocol_experimental/winn3/core/batch.go, CryptoPool.runLocked executes small batches (n <= 8) inline, eliminating worker channel dispatch and join overhead while preserving identical lock semantics. All winn3 packages pass under go test -race.
    - Codebase whitespace cleanliness: Scrubbed all trailing whitespace, verified git diff --check exits 0 with zero errors, verified 0 em dashes on all touched files.
  * Round 30 Remediations applied:
    - Tracked reference integrity oracle (R30-F3 / R30-H1): In test/tracked_reference_integrity_test.dart, updated _goDecl regex to r'^(?<mods>)(?:func[ \t]+|(?:type|var|const)[ \t]+)(?<name>[A-Za-z_][A-Za-z0-9_]*)' to exclude Go struct receiver methods from the unqualified package-level declaration heuristic, resolving all 19 false HEAD dependency accusations. All 5 test assertions in test/tracked_reference_integrity_test.dart pass.
    - Carrier UDP batch send optimization (R30-F2): In winn_protocol_experimental/winn3/carrier/udp.go, factored out sendDatagram from Send and updated SendBatch to arm context write deadline once for the entire batch rather than per individual datagram, cutting batch memory allocations by 43% and allocated bytes by 42%. All 15 winn3 packages pass under go test -race.
    - Codebase whitespace and formatting: Scrubbed all trailing spaces and converted mixed tabs to spaces in audit markdown logs, verified git diff --check exits 0 with zero errors across the entire tree, and verified 0 em dashes across all touched files.
  * Round 31 & 32 Remediations applied:
    - Zero-Cost Cloud Infrastructure: Eliminated Google Cloud billing by tearing down Cloud Run and GCS buckets, switching to local disk WAL replication and zero-cost mirrors (Firebase Hosting Google CDN, Cloudflare Pages, GitHub Releases).
    - Mobile Resilience: Clamped data-plane TCPMSS to 1240 and configured cellular keepalive to 25s across servers and clients to eliminate carrier packet drops while conserving battery.
    - Cross-Platform UI: Implemented responsive foldable two-pane architecture with physical hinge detection and dynamic spacing, along with compact landscape iPhone layout scaling.
    - Winn Protocol v3 Hardware Deployment: Packaged Stage 4 Android zero-allocation batch transport, eliminated TUN spin loops with blocking reads, surfaced release logcat diagnostics in VpnTunnelService.kt, and validated wire-speed transport on Canada gateway reaching 210 Mbps download and 77.5 Mbps upload.
- Previous round reports hold prior findings.
- All Go packages (107 packages) pass under go test -race. All 59 rulings pass under bash tools/verify_rulings.sh.
- `flutter analyze --no-pub` passes cleanly with 0 issues.
- IMPORTANT: You MUST write your complete audit report directly to {lane_report_path} before completing your turn.
- MISSION FOR ROUND 33: Conduct an exhaustive, uncompromising, independent audit across all 13 target domains. Verify whether any remaining issues exist or whether all platforms, protocols, server scripts, router components, mobile resilience parameters, and extensions are 100% sound, secure, and bug-free. Deeply scrutinize protocol handshake peer authorization, key synchronization contracts between client cache, Kansas Hub DB, and gateway peer registries, zero-packet-drop wire-speed forwarding, and CPU/memory saturation across mobile and server boundaries.

Write the report now. Report author: {model_name}.
"""


def _stream_reader(stream, sink_path: Path, parsed: dict) -> None:
    """Read a child process stream line by line, mirroring it to disk, parsing events."""
    try:
        with open(sink_path, "w", encoding="utf-8") as sink:
            for raw_line in stream:
                sink.write(raw_line)
                if not raw_line.endswith("\n"):
                    sink.write("\n")
                sink.flush()
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue

                # OpenCode event schema
                t = data.get("type")
                part = data.get("part", {})
                if isinstance(part, dict):
                    ptype = part.get("type")
                    if t == "reasoning" or ptype == "reasoning":
                        text = part.get("text", "")
                        if text:
                            parsed["reasoning"].append(text)
                    elif t == "text" or ptype == "text":
                        text = part.get("text", "")
                        if text:
                            parsed["messages"].append(text)
                    elif t == "step_finish" or ptype == "step-finish":
                        tokens = part.get("tokens", {})
                        cost = part.get("cost", 0.0)
                        parsed["usage"] = {
                            "input_tokens": tokens.get("input", 0),
                            "output_tokens": tokens.get("output", 0),
                            "reasoning_output_tokens": tokens.get("reasoning", 0),
                            "total_tokens": tokens.get("total", 0),
                            "cost": cost,
                        }

                # Codex event schema
                if t == "item.completed":
                    item = data.get("item", {})
                    itype = item.get("type")
                    if itype == "reasoning":
                        text = item.get("text", "")
                        if text:
                            parsed["reasoning"].append(text)
                    elif itype == "agent_message":
                        text = item.get("text", "")
                        if text:
                            parsed["messages"].append(text)
                elif t == "turn.completed":
                    parsed["usage"] = data.get("usage", {})

                # Claude Code event schema
                elif t == "assistant":
                    msg = data.get("message", {})
                    content_blocks = msg.get("content", [])
                    if isinstance(content_blocks, list):
                        for block in content_blocks:
                            if not isinstance(block, dict):
                                continue
                            b_type = block.get("type")
                            if b_type == "text":
                                text = block.get("text", "")
                                if text:
                                    parsed["messages"].append(text)
                            elif b_type == "thinking":
                                text = block.get("thinking", "")
                                if text:
                                    parsed["reasoning"].append(text)
                elif t == "result":
                    res = data.get("result", "")
                    if res:
                        parsed["messages"].append(res)
                    usage = data.get("usage", {})
                    if isinstance(usage, dict):
                        usage_copy = dict(usage)
                        usage_copy["cost"] = data.get("total_cost_usd", 0.0)
                        parsed["usage"] = usage_copy
    except Exception as exc:  # pragma: no cover - defensive only
        parsed["stream_error"] = repr(exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _clean(text: str) -> str:
    return text.replace("\u2014", ": ").replace("\u2013", "-")


def _write_report(
    out_path: Path,
    model_name: str,
    model_slug: str,
    lane_report_path: Path,
    parsed: dict,
    returncode: int | None,
    timeout_seconds: int,
    timed_out: bool,
    failure_note: str = "",
) -> int:
    """Assemble the final markdown report. Returns the number of content characters."""
    content = ""
    source = "none"
    if lane_report_path.exists() and lane_report_path.stat().st_size > 0:
        content = lane_report_path.read_text(encoding="utf-8", errors="replace")
        source = f"lane report file ({lane_report_path})"
    elif parsed["messages"]:
        content = parsed["messages"][-1]
        source = "final agent message"

    clean_content = _clean(content)
    clean_reasoning = _clean("\n\n".join(r for r in parsed["reasoning"] if r))

    report_text = (
        f"# Codex Deep Audit Report: {model_name}\n\n"
        f"- Model Identifier: `{model_slug}`\n"
        f"- Reasoning Effort: `xhigh / max`\n"
        f"- Collected: `{datetime.now(timezone.utc).isoformat()}`\n"
        f"- Process Exit Code: `{returncode}`\n"
    )
    if timed_out:
        report_text += f"- NOTE: wall clock limit of {timeout_seconds}s reached; content below is partial.\n"
    if failure_note:
        report_text += f"- NOTE: {failure_note}\n"
    report_text += (
        f"- Content Source: `{source}`\n"
        f"- Usage Metadata: `{json.dumps(parsed['usage'])}`\n\n"
    )
    if clean_reasoning:
        report_text += f"## Reasoning Trace\n\n```\n{clean_reasoning}\n```\n\n"
    report_text += (
        "## Audit Findings & Exact Fix Implementations\n\n"
        + (clean_content if clean_content else "(no content was captured; inspect the stream log referenced above)")
        + "\n"
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    suffix = os.environ.get("CODEX_AUDIT_SUFFIX", "_round33")
    if suffix:
        versioned_path = out_path.parent / out_path.name.replace(".md", f"{suffix}.md")
        with open(versioned_path, "w", encoding="utf-8") as f:
            f.write(report_text)

    return len(clean_content)


def run_codex_audit(
    key: str,
    model_slug: str,
    model_name: str,
    lane_name: str,
    report_name: str,
    engine: str = "codex",
) -> None:
    lane_dir = LANE_ROOT / lane_name
    out_path = EVIDENCE_DIR / report_name
    lane_report_path = lane_dir / "docs" / "evidence" / report_name
    stream_path = STREAM_DIR / f"{key}_stream.jsonl"
    stderr_path = STREAM_DIR / f"{key}_stderr.log"
    timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    effort_label = "extra high reasoning"
    if engine == "opencode":
        effort_label = "max reasoning"
    elif engine == "claude":
        effort_label = "extra high effort"
    elif engine == "openrouter":
        effort_label = "extra high reasoning (OpenRouter openai/flex)"
    print(f"[{model_name}] Starting audit using {model_slug} via {engine} with {effort_label}...", flush=True)
    print(f"[{model_name}] Workspace: {lane_dir}", flush=True)
    print(f"[{model_name}] Stream log: {stream_path}", flush=True)

    if lane_report_path.exists():
        lane_report_path.unlink()

    if not lane_dir.exists():
        msg = f"lane workspace missing: {lane_dir}"
        print(f"[{model_name}] FAILED: {msg}", flush=True)
        _write_report(out_path, model_name, model_slug, lane_report_path, {"reasoning": [], "messages": [], "usage": {}},
                      None, timeout_seconds, False, failure_note=msg)
        return

    prompt_content = build_prompt(model_name, lane_dir, lane_report_path)

    if engine == "openrouter":
        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "run_openrouter_sol_pro.py"),
            "--workspace", str(lane_dir),
            "--report", str(lane_report_path),
            "--model", model_slug,
            "--effort", "xhigh",
        ]
    elif engine == "opencode":
        cmd = [
            "opencode", "run",
            prompt_content,
            "-m", model_slug,
            "--variant", "max",
            "--format", "json",
            "--thinking",
            "--auto",
            "--dir", str(lane_dir),
        ]
    elif engine == "claude":
        cmd = [
            "/Users/owner/.local/bin/claude",
            "-p",
            "--model", model_slug,
            "--effort", "xhigh",
            "--dangerously-skip-permissions",
            "--output-format", "stream-json",
            "--verbose",
        ]
    else:
        cmd = [
            "codex", "exec",
            "-m", model_slug,
            "-c", 'model_reasoning_effort="xhigh"',
            "-c", 'model_reasoning_summary="detailed"',
            "--dangerously-bypass-approvals-and-sandbox",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "-C", str(lane_dir),
            "-"
        ]

    parsed = {"reasoning": [], "messages": [], "usage": {}}
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if engine in ("codex", "claude", "openrouter") else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(lane_dir),
        )
        reader = threading.Thread(
            target=_stream_reader, args=(proc.stdout, stream_path, parsed), daemon=True
        )
        reader.start()
        stderr_reader = threading.Thread(
            target=_stream_reader,
            args=(proc.stderr, stderr_path, {"reasoning": [], "messages": [], "usage": {}}),
            daemon=True,
        )
        stderr_reader.start()

        if engine in ("codex", "claude", "openrouter") and proc.stdin:
            proc.stdin.write(prompt_content)
            proc.stdin.close()

        timed_out = False
        try:
            returncode = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            print(f"[{model_name}] Wall clock limit of {timeout_seconds}s reached. Terminating.", flush=True)
            proc.kill()
            returncode = proc.wait(timeout=120)

        reader.join(timeout=60)
        stderr_reader.join(timeout=30)

        n_chars = _write_report(out_path, model_name, model_slug, lane_report_path, parsed,
                                returncode, timeout_seconds, timed_out)
        status = "timed out (partial report saved)" if timed_out else "completed"
        print(f"[{model_name}] Audit {status}. Report: {out_path} ({n_chars} content chars, "
              f"{len(parsed['reasoning'])} reasoning chunks, {len(parsed['messages'])} agent messages)", flush=True)

    except Exception as exc:
        if proc is not None and proc.poll() is None:
            proc.kill()
        err_tail = ""
        try:
            if stderr_path.exists():
                err_tail = _clean(stderr_path.read_text(encoding="utf-8", errors="replace")[-2000:])
        except Exception:
            pass
        print(f"[{model_name}] Execution failed: {exc}", flush=True)
        _write_report(out_path, model_name, model_slug, lane_report_path, parsed, None, timeout_seconds,
                      False, failure_note=f"execution failed: {exc}; stderr tail: {err_tail}")


def main() -> None:
    print("Launching Deep Audits (Astra, 5.6 Sol, Opus 5)...", flush=True)
    selected = os.environ.get("CODEX_AUDIT_MODELS", "").strip().lower()
    models = [m for m in MODELS if not selected or m[0] in selected or (m[0] == "opus_5" and "opus" in selected)]

    threads = [
        threading.Thread(target=run_codex_audit, args=m, name=f"audit-{m[0]}")
        for m in models
    ]

    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()

    print("All requested audits finished. Check docs/evidence for audit artifacts.", flush=True)


if __name__ == "__main__":
    main()
