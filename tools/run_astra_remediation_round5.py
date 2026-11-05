#!/usr/bin/env python3
"""Run Astra (gpt-6-astra) via Codex CLI to fix all verified Round 5 defects in /Users/owner/xprize/winsvpnv3.

Usage:
    python3 tools/run_astra_remediation_round5.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = Path("/tmp/astra_remediation_round5.log")
STREAM_PATH = Path("/tmp/astra_remediation_round5_stream.jsonl")

REMEDIATION_PROMPT = """You are Astra (gpt-6-astra), the lead security engineer and remediation architect for the WinsVPN ecosystem.

Your mission: Fix all verified defects discovered during the Round 5 Tripartite Deep Audit directly in the repository at /Users/owner/xprize/winsvpnv3.
You have full write access and execution privileges in this workspace.

MANDATORY EXECUTION RULES:
1. NEVER use em dashes (—) or en dashes (–). Use colons, commas, periods, or parentheses instead.
2. Ban AI cliches: delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary.
3. Code completeness: NEVER use ellipsis comments or placeholders (no '// ... rest of code', no '/* same as before */'). Provide 100% complete, compilable, production-ready replacement code or exact targeted diffs.
4. Surgical modifications: Modify ONLY the necessary lines and functions. Preserve existing architecture and formatting.
5. Verification: Proactively run commands to verify your changes. You must run:
   - flutter analyze --no-pub
   - python3 server/test_control_plane_deepseek_round2.py
   - python3 server/test_control_plane_round4.py
   - python3 server/test_winn3_descriptor_hub.py
   - python3 tools/website_security_audit.py

TARGET DEFECTS TO REMEDIATE:

1. Website Paid Crypto Checkout Fallback & Drawer Modal Isolation:
   - Files:
     * web/index.html
     * web/_headers
     * web/_worker.js
   - Defects:
     * When crypto modal backdrop is nested inside the donation drawer, opening it keeps it hidden while locking page scrolling.
     * When automated cryptocurrency checkout is loading, disabled, or fails, clicking a paid plan coin button (BTC, DASH, XMR) fell back to openModal(coin, planTitle) which opens the static donation wallet without order attribution or automatic account provisioning.
   - Fixes:
     * In web/index.html: ensure #cryptoModalBackdrop is attached to document.body if its parent is not document.body.
     * Implement setCryptoCoinSelectors(card, moneroEnabled, cryptoEnabled) and renderCryptoUnavailable(card, message). Initially disable all .crypto-coin-btn selectors until crypto-config is successfully fetched.
     * If crypto-config fetch fails or automated checkout is disabled, renderCryptoUnavailable on all cards and disable coin buttons.
     * In the coin button click listener (.crypto-coin-selector-grid .crypto-coin-btn): NEVER call openModal(coin, planTitle) as a fallback for paid plan cards. If not triggered, render an inline notice on the card that automated crypto checkout is unavailable.
     * Recompute the SHA-256 hash of the modified inline script and update script-src CSP hashes in web/_headers and web/_worker.js.

2. Firefox Browser Extension WebRTC & Network Prediction Fail-Closed Protection:
   - File: extension/src/adapters/firefox.js
   - Defect: applyPrivacyProtections() catches errors and returns { webrtc: 'not_applied' } instead of throwing, allowing the controller to report 'protected' while non-proxied WebRTC UDP continues leaking outside the proxy.
   - Fix:
     * In applyPrivacyProtections():
       - Await api.privacy.network.webRTCIPHandlingPolicy.set({ value: 'disable_non_proxied_udp' }).
       - Await api.privacy.network.webRTCIPHandlingPolicy.get({}).
       - Check that set succeeded and state has value === 'disable_non_proxied_udp' and levelOfControl === 'controlled_by_this_extension'. If not, throw new Error('Firefox WebRTC protection did not take effect').
       - Await api.privacy.network.networkPredictionEnabled.set({ value: false }).
       - Await api.privacy.network.networkPredictionEnabled.get({}).
       - Check that set succeeded and state has value === false and levelOfControl === 'controlled_by_this_extension'. If not, throw new Error('Firefox network prediction remained enabled').
       - Return { webrtc: 'applied', prediction: 'applied' }.

3. Android VPN Routing & Performance:
   - File: android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt
   - Defects:
     * addDisallowedApplication(packageName) in Xray modes (stealth-xray, winn-v3-stealth-chain) excludes the ENTIRE application UID from the VPN tunnel, leaking control plane, update, and API traffic.
     * acquireTunnelWifiLock() holds WIFI_MODE_FULL_LOW_LATENCY for the full duration of every tunnel session, causing excessive battery drain and impaired Wi-Fi roaming.
   - Fixes:
     * Replace the whole xrayRequiresWholeUidBypass block: fail closed for stealth-xray and winn-v3-stealth-chain until an individually protected carrier socket descriptor seam exists:
       val xrayRequiresProtectedCarrier = mode == "stealth-xray" || mode == "winn-v3-stealth-chain"
       if (xrayRequiresProtectedCarrier) {
           logError("Refusing Xray mode because its carrier socket is not individually protected; excluding the app UID would route app traffic outside the VPN.")
           clearRestartConfig()
           executeTunnelTeardown()
           return START_NOT_STICKY
       } else if (winnEnabled) {
           debugLog("App UID remains inside the VPN tunnel; the Winn outer UDP socket is individually protected.")
       } else {
           debugLog("App UID remains inside the VPN tunnel; the AmneziaWG socket is individually protected.")
       }
       Remove speedTestMeasuresPhysicalRoute = xrayRequiresWholeUidBypass (or set to false).
     * Remove tunnelWifiLock variable and acquireTunnelWifiLock() / releaseTunnelWifiLock() calls, keeping tunnelWakeLock intact.

4. Apple NetworkExtension Memory Ceiling & QUIC Receive-Window Caps:
   - File: winn_protocol_experimental/internal/carrier/h3.go
   - Defect: Uncapped QUIC receive windows (up to 15MB per connection in quic-go defaults) risk iOS NetworkExtension jetsam termination against the strict 15MB system memory ceiling.
   - Fix:
     * Define receive-window limits:
       const (
           clientInitialStreamReceiveWindow      uint64 = 128 * 1024
           clientMaxStreamReceiveWindow          uint64 = 512 * 1024
           clientInitialConnectionReceiveWindow  uint64 = 256 * 1024
           clientMaxConnectionReceiveWindow      uint64 = 2 * 1024 * 1024
       )
     * Implement applyClientReceiveWindowLimits(config *quic.Config).
     * In h3QUICConfig(), call applyClientReceiveWindowLimits(quicConfig) on every client QUIC config.

5. Control Plane Durable Activation Outbox & PayPal Async Offloading:
   - File: server/wins_control_plane_setup_ONETOUCH.sh
   - Defects:
     * Asynchronous BackgroundTasks email dispatch can silently drop paid activation keys if SMTP fails or service restarts.
     * PayPal webhook verification, subscription fetch, and sync_due_paypal_subscriptions make blocking network requests on the async event loop while holding open SQLite transactions.
     * In /verify, Smart Router is triggered before verifying advisory authorization on paid accounts.
     * free_status and verify_free_access run synchronous DB queries on the event loop.
   - Fixes:
     * Implement transactional activation outbox:
       - Table activation_delivery_outbox(delivery_id, account_number, target_email, subscriber_name, plan_type, sealed_secret, status, attempts, lease_token, lease_until, next_attempt_at, last_error, created_at, sent_at).
       - seal_activation_delivery / open_activation_delivery with authenticated encryption (HMAC-SHA256).
       - enqueue_activation_delivery called atomically within the transaction before finish_paypal_event and crypto order commits.
       - claim_activation_delivery_batch / finish_activation_delivery / drain_activation_delivery_outbox_once with exponential backoff.
       - Background worker loop started on app startup.
     * In paypal_webhook:
       - Offload verify_paypal_webhook_signature via await asyncio.to_thread(...).
       - Offload fetch_paypal_subscription via await asyncio.to_thread(...).
       - Offload paypal_refund_is_terminal via await asyncio.to_thread(...).
     * In admin_paypal_sync:
       - return await asyncio.to_thread(sync_due_paypal_subscriptions, lookahead_hours).
       - In sync_due_paypal_subscriptions: query candidate accounts, CLOSE the DB connection, make PayPal HTTP calls, then open short individual transactions to commit updates.
     * In /verify:
       - Before calling smart_router_trigger_for_existing_node, verify that the caller is authorized (verify_advisory_request_authorized) with either a valid device bearer or a valid unconsumed activation key. If not authorized, reject with HTTP 401 before making external Smart Router calls.
     * In free_status and verify_free_access:
       - Offload synchronous work via await asyncio.to_thread(_free_status_sync, platform) and await asyncio.to_thread(_prepare_free_login_sync, ...).

6. Server Test Suite Isolation:
   - File: server/test_winn3_descriptor_hub.py
   - Defect: arm_activation(mod, account) updates activation_secret_hash without resetting activation_secret_used_at or activation_secret_expires_at, causing subsequent tests using that account to fail with 401.
   - Fix:
     * In arm_activation():
       UPDATE users SET activation_secret_hash = ?, activation_secret_used_at = NULL, activation_secret_expires_at = NULL WHERE account_number = ?

Execute all repairs now, run the test suites, and report the results.
"""


def _stream_reader(stream, sink_path: Path, parsed: dict) -> None:
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
                t = data.get("type")
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
    except Exception as exc:
        parsed["error"] = repr(exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def main() -> None:
    print("================================================================", flush=True)
    print("Launching Astra (gpt-6-astra) Round 5 Remediation via Codex CLI...", flush=True)
    print("Repository Root:", REPO_ROOT, flush=True)
    print("Log Path:", LOG_PATH, flush=True)
    print("Stream Path:", STREAM_PATH, flush=True)
    print("================================================================", flush=True)

    cmd = [
        "codex", "exec",
        "-m", "gpt-6-astra",
        "-c", 'model_reasoning_effort="xhigh"',
        "-c", 'model_reasoning_summary="detailed"',
        "--dangerously-bypass-approvals-and-sandbox",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "-C", str(REPO_ROOT),
        "-"
    ]

    parsed = {"reasoning": [], "messages": [], "usage": {}}
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    t_stdout = threading.Thread(target=_stream_reader, args=(proc.stdout, STREAM_PATH, parsed), daemon=True)
    t_stdout.start()

    proc.stdin.write(REMEDIATION_PROMPT)
    proc.stdin.close()

    try:
        ret = proc.wait(timeout=10800)
    except subprocess.TimeoutExpired:
        print("[Astra] Timeout expired. Killing process.", flush=True)
        proc.kill()
        ret = proc.wait()

    t_stdout.join(timeout=30)
    print(f"[Astra] Remediation finished with exit code {ret}.", flush=True)
    if parsed["messages"]:
        print("\n--- Astra Final Output ---", flush=True)
        print(parsed["messages"][-1], flush=True)


if __name__ == "__main__":
    main()
