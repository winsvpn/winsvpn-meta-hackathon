#!/usr/bin/env python3
"""Round 37: verification debate. Dispatches the implemented-fix verification
packet to the three standing podiums and collects independent verdicts.

Usage: python3 tools/run_round37_verify.py --stage1
       python3 tools/run_round37_verify.py --stage3 --oi-file <path>
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import pathlib
import socket
import ssl
import time
import urllib.parse
import urllib.request

_spec = importlib.util.spec_from_file_location(
    "r36", "/Users/owner/xprize/winsvpnv3/tools/run_round36_surface_audit.py"
)
r36 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r36)

RECEIPTS = r36.RECEIPTS_DIR.parent / "round37"
RECEIPTS.mkdir(parents=True, exist_ok=True)

# Round 37 keeps its own cache: r36's raw file already holds stage1_* keys from
# the Round 36 audit, and reusing them would skip dispatch entirely.
RAW_OUTPUT = r36.DOCS_EVIDENCE / "debate_round37_verify_raw.json"
CACHE_LOCK = r36.CACHE_LOCK


def load_cache() -> dict:
    with CACHE_LOCK:
        if RAW_OUTPUT.exists():
            try:
                import json

                return json.loads(RAW_OUTPUT.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}


def update_cache(key: str, value: str):
    import json

    with CACHE_LOCK:
        cache = {}
        if RAW_OUTPUT.exists():
            try:
                cache = json.loads(RAW_OUTPUT.read_text(encoding="utf-8"))
            except Exception:
                cache = {}
        cache[key] = value
        RAW_OUTPUT.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def query_openrouter_model(model_name: str, prompt: str, system_role: str, max_tokens: int) -> str:
    """Backup path for the Sol Pro seat (User-provided): the :batch slug rides
    OpenAI's batch tier when the synchronous flex endpoint is rate-limited."""
    # Egress validation (SSRF gate): https only, allowlisted host, and every
    # resolved address must be public before anything is sent.
    parsed = urllib.parse.urlparse(r36.OPENROUTER_ENDPOINT)
    if parsed.scheme != "https" or parsed.hostname not in r36.EGRESS_HOST_ALLOWLIST:
        raise RuntimeError(f"egress endpoint failed allowlist: {r36.OPENROUTER_ENDPOINT}")
    for info in socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP):
        addr = ipaddress.ip_address(info[4][0])
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            raise RuntimeError(f"egress host resolves to forbidden address class: {addr}")
    key = r36.get_openrouter_key()
    tls_ctx = r36.build_verified_tls_context()
    for attempt in range(6):
        payload = {
            "model": model_name,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_role},
                {"role": "user", "content": prompt},
            ],
            "provider": {"order": ["OpenAI"], "allow_fallbacks": True},
            "reasoning": {"effort": "high"},
            "service_tier": "flex",
        }
        req = urllib.request.Request(
            r36.OPENROUTER_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://winsvpn.org",
                "X-Title": "Winthos Debate Round 37 Verification",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=600, context=tls_ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "error" in data:
                    print(f"[{model_name}] upstream error (attempt {attempt+1}): {data['error'].get('message')}", flush=True)
                    time.sleep(min(45, 10 * (attempt + 1)))
                    continue
                choice = data["choices"][0]["message"]
                content = (choice.get("content") or choice.get("reasoning") or "").strip()
                if content:
                    return r36.clean_text(content)
        except Exception as exc:
            print(f"[{model_name}] attempt {attempt+1} failed: {exc}", flush=True)
            time.sleep(min(45, 10 * (attempt + 1)))
    raise RuntimeError(f"{model_name} query failed after retries")

IMPLEMENTATION_LEDGER = """
ROUND 37 VERIFICATION PACKET: WIN'S VPN, ROUND 36 TREATY IMPLEMENTATION
(You verified Round 36's findings unanimously. This packet is the
implementation record. Verify each fix is coherent, complete, and does not
introduce a new defect. Answer from THIS PACKET ONLY: no tools, no network.)

FIX 1 (OI-1, OI-2, OI-16, OI-35, OI-43, OI-11; server/spain_crypto_payments_setup.sh):
- Dependencies: binary names checked (command -v docker) mapped only to their
  own package names (docker.io, git); nginx added.
- Monero archive: downloaded and extracted only inside mktemp -d
  /tmp/wins-monero.XXXXXXXX (mode 0700), find -xdev must return EXACTLY ONE
  monero-wallet-rpc, symlink-refused, then install 0755.
- Credential: rpc-login=user:pass written to /var/lib/monero/monero-wallet-rpc.conf
  owned monero-wallet:monero-wallet 0600, passed via --config-file; the systemd
  unit (root:root 0640) contains NO credential; the --disable-rpc-login=0 and
  --confirm-external-bind=0 flags were deleted; the stdout printf of the
  password was deleted (summary now names the credential file only).
- Log file /var/log/winsvpn/monero-wallet-rpc.log pre-created
  monero-wallet:monero-wallet 0600; runuser writability check; systemctl
  is-active gate with journal tail on failure.
- BTCPay: no git clone in the root installer. Requires BTCPAY_REVIEWED_COMMIT
  (40 hex), pre-staged checkout at .git, HEAD equality, clean worktree and
  index, then btcpay-setup.sh runs.
- Nginx: the public /monero-rpc location block was REMOVED entirely (behind
  Cloudflare Tunnel every source is loopback, so allow-listing could not
  distinguish the hub). Hub access moves to the WireGuard management path.
- bash -n clean; server/test_crypto_payments_spain.py: 7/7 pass.

FIX 2 (OI-4, OI-5, OI-18, OI-48; web/_worker.js):
- requireQuota gained bindingRequired: missing binding or binding error returns
  503 quota_unavailable for PAID routes (translate, ai-chat pass true).
- handleMapTile gates BEFORE cache lookup with RATE_LIMITER_MAP_TILE,
  bindingRequired=true, 120 req/60s.
- isolateLocalRateLimited: pruneRateBuckets now deletes only EXPIRED entries
  and returns the expired count; when the map is at RATE_BUCKET_CAP with zero
  expired entries, a NEW client is refused (429) instead of FIFO-evicting a
  fresh entry. No capacity pressure can reset an existing client's window.
- publicFallbackAnswer: the containsSecretRequest branch returns a reply that
  is BYTE-IDENTICAL to the generic miss (the trailing "For safety..." clause
  was removed from both), so the keyword list is not binary-searchable.
  Topic-specific answers above the miss are still suppressed for secret
  queries.
- Parses as an ES module (node import check).

FIX 3 (OI-7; web/_headers + web/_worker.js CONTENT_SECURITY_POLICY):
- CSP dropped googletagmanager.com, connect.facebook.net, google-analytics.com,
  doubleclick.net, googleadservices.com, the bare img-src https: wildcard, and
  the facebook/google-analytics connect origins. PayPal, Apple Pay, Google Pay
  retained. web/verify_inline_csp.py passes ("OK: 1 inline <style> and 2 inline
  <script> block(s) hash-pinned").

FIX 4 (OI-8, OI-9, OI-10; AndroidManifest.xml + tests):
- LauncherDecoy (calculator) is now enabled=true as the default launcher alias;
  LauncherReal enabled=false. TV overlay removes both aliases (unchanged).
- The exported Telephony.SECRET_CODE receiver (host 9467) was DELETED from the
  manifest, its class file deleted, its proguard keep rule deleted, and the two
  Kotlin contract tests updated (whitelist minus SecretCodeReceiver).
- QUERY_ALL_PACKAGES retained with an in-manifest requirement note (the
  split-tunnel picker uses getInstalledApplications, full inventory) plus a
  LAUNCHER intent <queries> entry; Play Permissions Declaration flagged as an
  operator requirement before next submission.
- Phone APK built successfully with these changes.

FIX 5 (OI-12, OI-37, OI-39; router/security.py + router/main.py):
- decision_log_path default moved from /tmp/router_decisions.jsonl to
  /var/lib/winsvpn-router/decisions.jsonl (the unit's StateDirectory, 0700).
- Middleware is deny-by-default: PUBLIC_PATHS = {/live, /ready, /favicon.ico}
  pass; paths in PROTECTED_PATHS get the full HMAC+nonce+window admission;
  anything else is 404 "not found" BEFORE a handler runs.
- Storage-slot acquisition: bounded blocking acquire with timeout
  min(remaining, 0.25s) before a clean TimeoutError (mapped to 503 upstream).
- New router/tests/test_route_inventory.py: every registered route must be in
  PROTECTED_PATHS or PUBLIC_PATHS; public surface must stay minimal. All four
  router suites exit 0.

FIX 6 (OI-13; android/app/build.gradle.kts + tools/test_standalone_v3_artifact.py):
- verifyAndroidReleaseEngineInputs now validates the source-set WINNER:
  src/release shadows src/main, existence resolved with
  Files.exists(..., NOFOLLOW_LINKS); an unsafe release-side file fails the
  gate even when a safe main candidate exists. The old
  candidates.none(::isSafeNonEmptyReleaseInput) is gone. Contract test asserts
  NOFOLLOW selection present and the old shape absent; 18/18 pass.

FIX 7 (OI-19, OI-26; winn3-nodes/deploy_and_verify.sh):
- net.core.default_qdisc=fq removed from the node-wide sysctl drop-in; a
  bounded waiter (120 x 1s) applies `tc qdisc replace dev winn3gw0 root fq`
  when the gateway creates the device.
- cmd_verify_node shreds staged secret material after verify passes
  (static key, admission key, cover leaf + cover keys, ech-server-keys.json)
  and PASS/FAIL-receipts each removal; redeploy then requires re-staging.
- bash -n clean.

FIX 8 (OI-42; extension/build.py + extension/tools/test_manifest_version.py):
- build_manifest() stamps m["version"] = app_version() parsed from
  pubspec.yaml ("1.0.16+33" ships as "1.0.16"); new drift test (3 cases)
  asserts every target manifest equals the pubspec version. 3/3 pass.

FIX 9 (OI-17; extension/src/core/endpoint.js):
- pacToken runs validateEndpoint and throws TypeError on invalid endpoints;
  runtime-verified: valid token built, routable host rejected, port 65536
  rejected.

FIX 10 (OI-14; both ONETOUCH installers):
- wins_require_trusted_env_file (regular file, non-symlink, root-owned, 0600
  or stricter) gates every sourced defaults file. bash -n clean.

FIX 11 (OI-3, in-repo part):
- server/wins_winn3_gateway_install_memory_unit_test.sh oracle aligned from
  14336 KiB/session to the installer's current 1536 KiB/session (64 MiB base,
  High=75% of Max, GOMEMLIMIT=80% of High, unchanged); full suite passes.

VERIFIED ALREADY CONFORMING (no change): OI-6 (swap fail-closed present),
OI-21 (sanitiseSettings normalizes every rule at load and set), OI-22
(announce_non_forwarding_gateway banner makes the mode unmistakable),
OI-31 (Vary: Origin already set), OI-40 (unit already UMask=0077 +
StateDirectoryMode=0700), OI-41 (exact-origin allowlist, no wildcard), OI-45
(watch service gates path, platform-authenticated sender, unknown verbs
refused), OI-47 (installer bash -n clean).

CONTEXT YOU SHOULD CHALLENGE:
- A speedtest pre-warm experiment (1s full-rate warm-up, uncounted) was
  implemented, measured WORSE (upload 257-301 Mbps after the burst vs 704-766
  without warm-up, downloads fine), and REVERTED. Working hypothesis: some
  carrier-path buffer drains a full-rate burst at about 300 Mbps. The finding
  is recorded in a code comment in MainActivity.kt.
- OI-3 on-host reconciliation captured canada's live installer (sha256
  8d269ff2..., 492485 bytes); the substantive deltas left for the owner are
  AWG MTU default (node 1280 vs repo 1440) and a repo-only node-map block.

MANDATE (independent verification):
1. For each FIX 1..11: VERIFIED, or DISPUTED: <specific defect in the fix as
   described>, or INCOMPLETE: <what is missing>. Attack the designs: e.g., is
   the Monero config-file placement readable by the service user while still
   excluding other users? Does the deny-by-default middleware break FastAPI
   internals (docs routes, redirects)? Does the FIFO-refusal limiter create a
   denial-of-service amplifier? Does the source-set-winner gate mishandle
   stale src/release leftovers? Is the version stamping robust to pubspec
   format changes?
2. For the pre-warm collapse finding: name the most probable mechanism in a
   UDP-carrier VPN that drains a ~90 MB burst at about one third of its
   steady-state rate for at least six seconds, given: carrier is UDP with
   in-house reliability, buffers are 128 MiB at the kernel and 32 MiB in-app,
   the drain persists after the burst stops. Rank: carrier pipe inbox depth
   backpressure, gateway per-peer queue, pacing/token bucket, Cloudflare
   endpoint throttle, client socket buffer. Say what measurement would
   discriminate.
3. Any UNVERIFIED-LIVE claim must be marked inline.
4. End with NEXT: the single most valuable check the Arbiter can run locally.
Format rules: zero em/en dashes; banned cliches; bold only list keys.
"""

SYSTEM_SEATS = r36.SYSTEM_SEATS


def stage1():
    print("=== ROUND 37 STAGE 1: INDEPENDENT VERIFICATION VERDICTS ===", flush=True)
    packet = clean_packet = r36.clean_text(IMPLEMENTATION_LEDGER)
    digest = hashlib.sha256(packet.encode()).hexdigest()
    print(f"packet bytes: {len(packet)}, sha256: {digest}", flush=True)
    (RECEIPTS / "packet_dispatched.txt").write_text(packet, encoding="utf-8")

    cache = load_cache()

    def prompts(seat, cache_):
        return packet, SYSTEM_SEATS[seat]

    import concurrent.futures

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r37_stage1_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r37stage1"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r37stage1"))
            else:
                def solpro_with_batch_fallback():
                    try:
                        return r36.query_openrouter(packet, SYSTEM_SEATS[seat], 12000)
                    except RuntimeError:
                        print("[solpro] primary rate-limited; falling back to :batch", flush=True)
                        return query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, SYSTEM_SEATS[seat], 12000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_batch_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            update_cache(key, result)
            fname = f"debate_round37_stage1_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 37 stage1: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 37 STAGE 1 COMPLETE", flush=True)


def stage3(oi_file: pathlib.Path):
    print("=== ROUND 37 STAGE 3: CONVERGENCE VOTE ===", flush=True)
    oi_text = r36.clean_text(oi_file.read_text(encoding="utf-8"))
    cache = load_cache()

    def prompts(seat, cache_):
        others = []
        for other in r36.SEAT_KEYS:
            if other == seat:
                continue
            body = cache_.get(f"r37_stage1_{other}", "(missing)")
            others.append(f"=== {other.upper()} (Turn 1, FULL TEXT) ===\n{body[:20000]}")
        own = cache_.get(f"r37_stage1_{seat}", "(missing)")
        prompt = (
            "ROUND 37 STAGE 3: CONVERGENCE VOTE. Sealed rules apply. Sources: "
            "the Turn 1 verdicts below and the Arbiter's Open Items docket, "
            "which carries the post-cross-examination code changes (all "
            "applied and tested on the working tree) plus attached evidence.\n\n"
            "OPEN ITEMS DOCKET:\n" + oi_text + "\n\n"
            "=== YOUR TURN 1 VERDICT (AS FILED) ===\n" + own[:20000]
            + "\n\n=== OTHER SEATS' TURN 1 VERDICTS ===\n" + "\n\n".join(others)
            + "\n\nVOTE MANDATE: for every item RV-1..RV-12 answer exactly one "
            "line:\nRV-<n>: AGREE\nor\nRV-<n>: DISAGREE: <one concrete "
            "falsifiable reason (arithmetic, architecture fact, or "
            "measurement). A DISAGREE without a falsifiable reason counts as "
            "AGREE.>\nThen a one-paragraph ROUND 37 RATIFICATION STATEMENT: "
            "which of the Round 36 treaty's 50 items you consider closed by "
            "the implemented fixes, and what remains open.\n"
            "Zero em dashes or en dashes; banned cliches; bold only list keys."
        )
        return r36.clean_text(prompt), SYSTEM_SEATS[seat]

    import concurrent.futures

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r37_stage3_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            prompt, system_role = prompts(seat, cache)
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, prompt, "r37stage3"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, prompt, "r37stage3"))
            else:
                tasks[key] = (seat, ex.submit(r36.query_openrouter, prompt, system_role, 12000))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            update_cache(key, result)
            fname = f"debate_round37_stage3_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 37 stage3: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 37 STAGE 3 COMPLETE", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage1", action="store_true")
    parser.add_argument("--stage3", action="store_true")
    parser.add_argument("--oi-file", type=pathlib.Path)
    args = parser.parse_args()
    if args.stage1:
        stage1()
    elif args.stage3:
        if not args.oi_file or not args.oi_file.exists():
            raise SystemExit("--stage3 requires --oi-file")
        stage3(args.oi_file)


if __name__ == "__main__":
    main()
