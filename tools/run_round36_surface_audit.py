#!/usr/bin/env python3
"""
Winthos Debate Council: Round 36 Surface-Wide Audit (Pass 1)
Docket: bugs, errors, misconfigurations, weaknesses across apps, servers,
protocols, website, payments, extension. Unanimous agreement required before
any fix is implemented (ICDP, AGENTS.md Section 13).

Podiums (three independent lineages; Arbiter is the session model, separate lineage):
  Seat 1: Antigravity (Gemini 3.8 Flash High) via `agy -p`
  Seat 2: Claude Opus 5 via `claude -p --model opus`
  Seat 3: GPT-5.6 Sol Pro via OpenRouter (reasoning effort: high)

Usage:
  python3 tools/run_round36_surface_audit.py --stage12
  python3 tools/run_round36_surface_audit.py --stage3 --oi-file <path>
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
RAW_OUTPUT = DOCS_EVIDENCE / "debate_round36_surface_raw.json"
RECEIPTS_DIR = REPO_ROOT / ".agent" / "debates" / "round36"
RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)

SEAT_AGY_CWD = pathlib.Path("/tmp/r36_seat_agy")
SEAT_CLAUDE_CWD = pathlib.Path("/tmp/r36_seat_claude")

# Fixed egress endpoints. The audit tool talks to exactly these hosts and
# nothing else; both are validated (scheme https, host allowlist, public
# resolved IP) before any request leaves the machine.
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
EGRESS_HOST_ALLOWLIST = {"openrouter.ai"}

CACHE_LOCK = threading.Lock()
RECEIPT_LOCK = threading.Lock()

# (repo-relative path, byte cap). Small files included whole; large files capped
# from the head, with the manifest telling podiums what to request for Round 37.
BUNDLE_FILES: list[tuple[str, int]] = [
    ("server/spain_crypto_payments_setup.sh", 20000),
    ("server/hub-commerce.env.example", 4000),
    ("winn3-nodes/deploy_and_verify.sh", 26000),
    ("tools/verify_live_deployment.py", 12000),
    ("web/_worker.js", 24000),
    ("web/_headers", 4000),
    ("web/manifest.json", 2000),
    ("web/wrangler.jsonc", 8000),
    ("android/app/build.gradle.kts", 28000),
    ("android/app/src/main/AndroidManifest.xml", 16000),
    ("extension/manifest/base.jsonc", 8000),
    ("extension/src/core/endpoint.js", 6000),
    ("extension/src/core/pac.js", 4000),
    ("server/wins_winn3_gateway_install.sh", 20000),
    ("server/wins_data_plane_setup_ONETOUCH.sh", 20000),
    ("server/wins_control_plane_setup_ONETOUCH.sh", 16000),
    ("server/wins_core_server_setup_ONETOUCH.sh", 16000),
    ("router/main.py", 16000),
    ("router/security.py", 16000),
]


def get_openrouter_key() -> str:
    env_key = os.environ.get("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    auth_file = pathlib.Path.home() / ".local" / "share" / "opencode" / "auth.json"
    if auth_file.exists():
        try:
            data = json.loads(auth_file.read_text(encoding="utf-8"))
            key = data.get("openrouter", {}).get("key")
            if key:
                return key.strip()
        except Exception:
            pass
    raise RuntimeError("OpenRouter API key not found")


def clean_text(text: str) -> str:
    return text.replace("\u2014", ": ").replace("\u2013", "-")


# ---------------------------------------------------------------------------
# Egress validation (defense against SSRF): scheme, allowlisted host, and a
# resolved-IP check that rejects private, loopback, link-local, and reserved
# addresses before connecting.
# ---------------------------------------------------------------------------


def validate_egress_url(endpoint: str):
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" or parsed.hostname not in EGRESS_HOST_ALLOWLIST:
        raise RuntimeError(f"egress endpoint failed allowlist: {endpoint}")
    addr_infos = socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP)
    for info in addr_infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise RuntimeError(f"egress host resolves to forbidden address class: {ip}")


def build_verified_tls_context():
    # macOS Homebrew Python does not always locate a CA bundle by default.
    # Use certifi when present, else the macOS system trust store. Certificate
    # verification stays ON either way.
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        system_bundle = pathlib.Path("/etc/ssl/cert.pem")
        if system_bundle.exists():
            return ssl.create_default_context(cafile=str(system_bundle))
        return ssl.create_default_context()


# ---------------------------------------------------------------------------
# Local Privacy Gate (ICDP 13.9.3): deterministic scanning before any dispatch.
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED-KEY-BLOCK]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED-GH-TOKEN]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED-API-KEY]"),
    (re.compile(r"xox[abp]-[A-Za-z0-9-]{10,}"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}[\"']"), r"\1: \"[REDACTED]\""),
]

IP_TOKEN_MAP: dict[str, str] = {}
IP_COUNTER = {"n": 0}
PUBLIC_IP_RE = re.compile(r"(?<!\d)(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def gate_ip_sub(match: re.Match) -> str:
    ip = match.group(0)
    if ip not in IP_TOKEN_MAP:
        IP_COUNTER["n"] += 1
        IP_TOKEN_MAP[ip] = f"[IP_{IP_COUNTER['n']}]"
    return IP_TOKEN_MAP[ip]


def apply_privacy_gate(text: str, source: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    for pattern, replacement in SECRET_PATTERNS:
        text, hits = pattern.subn(replacement, text)
        if hits:
            notes.append(f"{source}: {hits} secret-pattern hit(s) redacted by class")
    text = PUBLIC_IP_RE.sub(gate_ip_sub, text)
    text = text.replace("/Users/owner", "[HOME]")
    text = re.sub(r"/home/[A-Za-z0-9_.-]+", "[HOME]", text)
    text = text.replace("/root/", "[ROOT]/")
    if re.search(r"-----BEGIN", text):
        notes.append(f"{source}: residual BEGIN marker after gate, file content suspect")
    return text, notes


GATE_LOG: list[str] = []


def gate_log_extend(notes: list[str]):
    with CACHE_LOCK:
        GATE_LOG.extend(notes)
        (RECEIPTS_DIR / "privacy_gate.log").write_text("\n".join(GATE_LOG), encoding="utf-8")


# ---------------------------------------------------------------------------
# Packet assembly
# ---------------------------------------------------------------------------

OVERVIEW = """
PRODUCT OVERVIEW (Arbiter-provided, factual):
Win's VPN is a paid (about USD 0.99 per month) privacy and anti-censorship VPN of a
US 501(c)(3) nonprofit, built for users in Myanmar and comparable high-threat
jurisdictions. The client UI is a working calculator (camouflage). Threat priority:
detectability outranks confidentiality; user enumeration risk is the worst outcome.

Dual artifacts:
1. Win's VPN client (org.winsvpn.app): Flutter app, platforms Android, Android TV,
   iOS, macOS, Windows, Linux, Wear OS, watchOS.
2. Winn Protocol v3 engine (Go, dir winn_protocol_experimental/): post-quantum hybrid
   TLS key exchange (x25519-mlkem768, 24h key TTL), dual Ed25519 + ML-DSA-65 auth,
   ChaCha20-Poly1305 AEAD carrier. PATENT-SENSITIVE: never recommend publishing
   internals; all repos stay private.
3. Fallback tunnel: AmneziaWG over UDP 9110, then Xray VLESS-WS on TCP 80/443.

Fleet (values redacted to aliases; all nodes are Debian-family Linux, root deploy):
- <CANADA_MGMT_SSH_ALIAS>: active data plane gateway (Winn v3 UDP 9111, AWG UDP 9110, TCP 443)
- spain-mgmt: data plane + crypto payment gateway (TCP 8443, 443)
- germany-mgmt: data plane gateway (TCP 8443)
- kansas hub: production control hub (FastAPI + SQLite + Litestream, TCP 22/80/443/2222/8000)
Client ship channel: Google Play, Apple App Store, Windows installer (Inno), Linux
stores (Flathub, snap), browser extension stores (Chrome, Firefox, Safari).

CURRENT IN-FLIGHT STATE (git status, uncommitted):
"""

MANIFEST_TAIL = """
ROUND 36 MANDATE (TURN 1, INDEPENDENT VERDICT):

You are one of three independent podiums. The Arbiter is a separate model and does
not vote. Answer from THIS PACKET ONLY. Do not access any filesystem, network, or
tool. This is a sealed offline audit; external facts are unknown to you unless the
packet states them.

1. Audit every domain A through H listed below and return findings F-1..F-N sorted
   by severity:
   - P0: exploitable or user-exposing now (security, privacy, censorship-detection,
         payment loss, store rejection risk)
   - P1: broken, wrong, or misconfigured (functional bugs, footguns, race conditions)
   - P2: quality and durability (tests, hygiene, docs, ops)
2. Every finding must carry: domain letter, severity, exact repo-relative file
   (plus function or line when visible in the packet evidence), a short evidence
   quote from the packet, the EXACT proposed fix (code diff or command or config),
   and residual risk after the fix. Findings without an exact fix are invalid.
3. Domains:
   A. Android app (Flutter + Kotlin bridge, VpnTunnelService, WinnV3* classes,
      calculator camouflage, VPN permissions)
   B. Go protocol engine (Winn v3: carrier, session, driver, tun, PMTUD files new
      and unreviewed)
   C. Gateway and server fleet deployment (install and ONETOUCH scripts,
      deploy_and_verify, iptables/sysctl posture)
   D. Control hub (FastAPI + SQLite + Litestream; account, entitlement, deletion)
   E. Website (Cloudflare Worker, headers, CSP, wrangler config)
   F. Payments (Spain crypto payment gateway, hub commerce env, PayPal entitlement)
   G. Browser extension (Chrome, Firefox, Safari; PAC, endpoints, store listings)
   H. Apple platforms (iOS/macOS PacketTunnel providers; inventory only this round)
4. Any claim about the outside world (CVE numbers, library versions, store rules,
   provider terms) must be marked UNVERIFIED-LIVE inline. Do not assert unmarked
   external facts.
5. Format rules: strictly zero em dashes or en dashes (use colons, commas, periods,
   parentheses); banned vocabulary: delve, testament, tapestry, crucial, leverage,
   furthermore, moreover, in summary, seamless, robust, comprehensive, elevate,
   streamline, unlock, landscape, realm, utilize, it's worth noting, dive into,
   beacon, vital, interplay; bold styling only on top-level list keys; no rule of
   three triads.
6. End your reply with a section NEXT-DEEP-DIVE: up to 6 repo-relative files or
   directories you need in full for Round 37, each with one line of why.

Absolute constraints: the downlink datapath is frozen by user directive; findings
may READ it but fixes must not modify it. Production fleet changes are proposed
only, never assumed applied. Do not recommend publishing any internal artifact.
"""


def build_inventory() -> str:
    lines: list[str] = []
    try:
        status = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "status", "--short"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        lines.append(status[:6000])
    except Exception as e:
        lines.append(f"(git status unavailable: {e})")
    lines.append("\nTOP-LEVEL DIRECTORY MAP:")
    lines.append("android/ Flutter Android host + Kotlin engine bridge; apple/ shared Apple sources;")
    lines.append("ios/, macos/ platform runners + PacketTunnel; windows/, linux/ desktop runners;")
    lines.append("wear_os/ watch target; extension/ browser extension; web/ Cloudflare Pages site;")
    lines.append("server/ fleet install + hub tests; winn3-nodes/ gateway deploy + verify;")
    lines.append("router/ edge router service (aicore); dashboard/ ops dashboards; tools/ release +")
    lines.append("audit tooling; lib/ Flutter Dart sources; winn_protocol_experimental/ Go engine.")
    for label, path in [
        ("server/", REPO_ROOT / "server"),
        ("web/", REPO_ROOT / "web"),
        ("tools/ (audit+release subset)", REPO_ROOT / "tools"),
        ("extension/src/", REPO_ROOT / "extension" / "src"),
        ("android Kotlin app/", REPO_ROOT / "android" / "app" / "src" / "main" / "kotlin" / "org" / "winsvpn" / "app"),
        ("winn_protocol_experimental/winn3/", REPO_ROOT / "winn_protocol_experimental" / "winn3"),
    ]:
        try:
            names = sorted(p.name for p in path.iterdir())
            lines.append(f"\n{label} ({len(names)} entries): {', '.join(names[:120])}")
        except Exception as e:
            lines.append(f"\n{label}: (listing failed: {e})")
    return "\n".join(lines)


def build_packet() -> str:
    gate_log_extend([])
    inventory = apply_privacy_gate(build_inventory(), "inventory")[0]
    parts: list[str] = [OVERVIEW, inventory, "\nEVIDENCE FILES (repo-relative; capped files are head excerpts):\n"]
    for rel, cap in BUNDLE_FILES:
        path = REPO_ROOT / rel
        if not path.exists():
            parts.append(f"#### {rel} (MISSING FROM WORKING TREE)\n")
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        truncated = len(raw.encode("utf-8")) > cap
        body, notes = apply_privacy_gate(raw[:cap], rel)
        gate_log_extend(notes)
        suffix = " ... (CAPPED, request in NEXT-DEEP-DIVE for full text)" if truncated else ""
        parts.append(f"#### {rel}{suffix}\n```({rel})\n{body}\n```\n")
    mapping = ", ".join(f"{ip}->{tok}" for ip, tok in sorted(IP_TOKEN_MAP.items())) or "(none)"
    gate_log_extend([f"ip-placeholder-map (local only, never dispatched): {mapping}"])
    packet = clean_text("\n".join(parts)) + "\n" + clean_text(MANIFEST_TAIL)
    return packet


# ---------------------------------------------------------------------------
# Dispatchers. Each CLI seat is launched with a literal argument list (no shell,
# no interpolation); the only variable input is the prompt fed over stdin.
# ---------------------------------------------------------------------------


def write_receipt(seat: str, stage: str, packet: str, output: str, status: str):
    rec = {
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seat": seat,
        "stage": stage,
        "packet_sha256": hashlib.sha256(packet.encode("utf-8")).hexdigest(),
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "output_bytes": len(output.encode("utf-8")),
        "status": status,
    }
    with RECEIPT_LOCK:
        with open(RECEIPTS_DIR / "receipts.raw.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def query_openrouter(
    prompt: str,
    system_role: str,
    max_tokens: int,
    model: str = "openai/gpt-5.6-sol-pro",
    reasoning_effort: str = "high",
) -> str:
    validate_egress_url(OPENROUTER_ENDPOINT)
    key = get_openrouter_key()
    tls_ctx = build_verified_tls_context()
    for attempt in range(8):
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_role},
                {"role": "user", "content": prompt},
            ],
            "provider": {"order": ["OpenAI"], "allow_fallbacks": True},
            "reasoning": {"effort": reasoning_effort},
            # Flex tier: half price, per the standing OpenRouter configuration
            # for this seat. Lowest uptime priority is acceptable for a debate
            # dispatch; retries cover transient unavailability.
            "service_tier": "flex",
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OPENROUTER_ENDPOINT,
            data=data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://winsvpn.org",
                "X-Title": "Winthos Debate Round 36 Surface Audit",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=600, context=tls_ctx) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                if "error" in res_data:
                    print(f"[solpro] upstream error (attempt {attempt+1}): {res_data['error'].get('message')}", flush=True)
                    time.sleep(min(45, 8 * (attempt + 1)))
                    continue
                choice = res_data["choices"][0]["message"]
                content = (choice.get("content") or choice.get("reasoning") or "").strip()
                if content:
                    return clean_text(content)
        except Exception as e:
            print(f"[solpro] attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(min(45, 8 * (attempt + 1)))
    raise RuntimeError("solpro query failed after retries")


def query_agy(prompt: str, stage: str) -> str:
    SEAT_AGY_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete audit packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Reply with your verdict only.\n\n"
        + prompt
    )
    try:
        proc = subprocess.Popen(
            # agy requires the prompt attached to --print and reads the full
            # packet from stdin; --print must carry only a short instruction
            # (macOS caps a single argv string, so the packet never rides argv).
            ["agy", "--effort", "high", "--disable-slash-commands", "--output-format", "text",
             "--print", "Answer the prompt provided on standard input."],
            cwd=str(SEAT_AGY_CWD),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=1500)
    except subprocess.TimeoutExpired:
        write_receipt("agy", stage, prompt, "", "timeout")
        raise RuntimeError("agy timed out")
    out = out_bytes.decode("utf-8", errors="replace").strip()
    err = err_bytes.decode("utf-8", errors="replace")
    if proc.returncode != 0 or not out:
        write_receipt("agy", stage, prompt, err[:2000], f"fail rc={proc.returncode}")
        raise RuntimeError(f"agy failed rc={proc.returncode}: {err[:400]}")
    write_receipt("agy", stage, prompt, out, "ok")
    return clean_text(out)


def query_claude(prompt: str, stage: str) -> str:
    SEAT_CLAUDE_CWD.mkdir(parents=True, exist_ok=True)
    stdin_text = (
        "The complete audit packet follows after this line. Read all of it, then "
        "complete the mandate it contains. Do not use any tools; reply with your "
        "verdict only.\n\n" + prompt
    )
    try:
        proc = subprocess.Popen(
            ["claude", "--print", "--model", "opus", "--output-format", "text"],
            cwd=str(SEAT_CLAUDE_CWD),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out_bytes, err_bytes = proc.communicate(stdin_text.encode("utf-8"), timeout=1500)
    except subprocess.TimeoutExpired:
        write_receipt("claude-opus5", stage, prompt, "", "timeout")
        raise RuntimeError("claude timed out")
    out = out_bytes.decode("utf-8", errors="replace").strip()
    err = err_bytes.decode("utf-8", errors="replace")
    if proc.returncode != 0 or not out:
        write_receipt("claude-opus5", stage, prompt, err[:2000], f"fail rc={proc.returncode}")
        raise RuntimeError(f"claude failed rc={proc.returncode}: {err[:400]}")
    write_receipt("claude-opus5", stage, prompt, out, "ok")
    return clean_text(out)


SYSTEM_SEATS = {
    "agy": (
        "You are Seat 1 (Antigravity, Gemini 3.8 Flash High) of the Winthos Debate "
        "Council Round 36 surface audit. You are an independent auditor. Produce "
        "exhaustive, exact, evidence-quoted findings. Zero em dashes or en dashes; "
        "ban AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, "
        "moreover, in summary, seamless, robust, comprehensive, streamline, unlock)."
    ),
    "claude-opus5": (
        "You are Seat 2 (Claude Opus 5) of the Winthos Debate Council Round 36 "
        "surface audit. You are an independent auditor. Produce exact code diffs, "
        "configs, and command-level fixes. Zero em dashes or en dashes; ban AI "
        "cliches (delve, testament, tapestry, crucial, leverage, furthermore, "
        "moreover, in summary, seamless, robust, comprehensive, streamline, unlock)."
    ),
    "solpro": (
        "You are Seat 3 (GPT-5.6 Sol Pro) of the Winthos Debate Council Round 36 "
        "surface audit. You are an independent auditor. Every claim must carry "
        "empirical proof or arithmetic. Zero em dashes or en dashes; ban AI cliches "
        "(delve, testament, tapestry, crucial, leverage, furthermore, moreover, "
        "in summary, seamless, robust, comprehensive, streamline, unlock)."
    ),
}

SEAT_KEYS = ["agy", "claude-opus5", "solpro"]


def load_cache() -> dict:
    with CACHE_LOCK:
        if RAW_OUTPUT.exists():
            try:
                return json.loads(RAW_OUTPUT.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}


def update_cache(key: str, value: str):
    with CACHE_LOCK:
        cache = {}
        if RAW_OUTPUT.exists():
            try:
                cache = json.loads(RAW_OUTPUT.read_text(encoding="utf-8"))
            except Exception:
                cache = {}
        cache[key] = value
        RAW_OUTPUT.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def dispatch_stage(stage: str, per_seat_prompt_fn, max_tokens: int = 16000):
    cache = load_cache()
    tasks: dict[str, tuple[str, concurrent.futures.Future]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for seat in SEAT_KEYS:
            key = f"{stage}_{seat}"
            if cache.get(key):
                print(f"[{seat}] {stage} cached ({len(cache[key])} bytes)", flush=True)
                continue
            prompt, system_role = per_seat_prompt_fn(seat, cache)
            if seat == "agy":
                tasks[key] = (seat, executor.submit(query_agy, prompt, stage))
            elif seat == "claude-opus5":
                tasks[key] = (seat, executor.submit(query_claude, prompt, stage))
            else:
                tasks[key] = (seat, executor.submit(query_openrouter, prompt, system_role, max_tokens))
        failures: list[str] = []
        for key, (seat, future) in tasks.items():
            try:
                result = future.result()
            except Exception as e:
                failures.append(f"{key}: {e}")
                print(f"!! {key} FAILED: {e}", flush=True)
                continue
            update_cache(key, result)
            fname = f"debate_round36_{stage}_{seat.replace('claude-opus5', 'opus5')}.md"
            (DOCS_EVIDENCE / fname).write_text(f"# Round 36 {stage}: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete, {fname} ({len(result)} bytes)", flush=True)
        if failures:
            raise RuntimeError(
                f"{stage} incomplete; successful seats are cached, rerun to retry only the failures: "
                + "; ".join(failures)
            )


# ---------------------------------------------------------------------------
# Stage 1+2
# ---------------------------------------------------------------------------


def stage12():
    print("=== ROUND 36 STAGE 1: INDEPENDENT FULL-SURFACE VERDICTS ===", flush=True)
    packet = build_packet()
    print(f"packet bytes: {len(packet)}, sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    (RECEIPTS_DIR / "packet_dispatched.txt").write_text(packet, encoding="utf-8")

    def stage1_prompts(seat: str, cache: dict):
        return packet, SYSTEM_SEATS[seat]

    dispatch_stage("stage1", stage1_prompts)

    print("=== ROUND 36 STAGE 2: CROSS-EXAMINATION ===", flush=True)
    cache = load_cache()

    def stage2_prompts(seat: str, cache: dict):
        own = cache.get(f"stage1_{seat}", "(your Turn 1 verdict is not on file)")
        others = []
        for other in SEAT_KEYS:
            if other == seat:
                continue
            body = cache.get(f"stage1_{other}", "(missing)")
            others.append(f"=== {'SEAT ' + str(SEAT_KEYS.index(other)+1) + ': ' + other.upper()} (Turn 1, FULL TEXT) ===\n{body[:80000]}")
        prompt = (
            "ROUND 36 STAGE 2: ADVERSARIAL CROSS-EXAMINATION. Sealed packet rules "
            "still apply: packet evidence and the Turn 1 verdicts below are your only "
            "sources; no tools, no network.\n\n"
            "All three seats submitted independent Turn 1 verdicts. Your own Turn 1 "
            "verdict as filed is reproduced first so you can reference your own "
            "positions exactly; do not re-litigate it from memory.\n\n"
            "=== YOUR TURN 1 VERDICT (AS FILED) ===\n"
            + own[:80000]
            + "\n\nTHE OTHER SEATS' TURN 1 VERDICTS (FULL TEXT):\n\n"
            + "\n\n".join(others)
            + "\n\nYour mandate:\n"
            "1. Steelman each opposing seat: present the strongest version of why they "
            "reasoned as they did, and name the single strongest point in each "
            "opposing verdict.\n"
            "2. State whether that reasoning changes your own Turn 1 position, per "
            "finding, and why.\n"
            "3. Then output your REVISED FINAL FINDINGS list (F-1..F-N) with the same "
            "required fields (domain, severity, exact file, evidence quote, exact "
            "fix, residual risk), merging any finding you now accept and dropping "
            "any finding you now refute (state the refutation). A finding you keep "
            "unchanged stays in the list.\n"
            "4. A 'do not ship' or 'cannot be done' verdict is NOT a valid finding: "
            "for every defect you identify you must propose a constructive fix that "
            "makes the component work as intended. If a fix needs operator or User "
            "action, say exactly which command or decision is required.\n"
            "5. Zero em dashes or en dashes; banned cliches; bold only list keys."
        )
        return clean_text(prompt), SYSTEM_SEATS[seat]

    dispatch_stage("stage2", stage2_prompts)
    print("=== ROUND 36 STAGES 1+2 COMPLETE. Arbiter must now compile the OI docket, "
          "then run --stage3 --oi-file <path> ===", flush=True)


# ---------------------------------------------------------------------------
# Stage 3 (convergence vote on the Arbiter-compiled OI docket)
# ---------------------------------------------------------------------------


def stage3(oi_file: pathlib.Path):
    oi_text = clean_text(oi_file.read_text(encoding="utf-8"))
    print(f"=== ROUND 36 STAGE 3: CONVERGENCE VOTE ({len(oi_text)} bytes of OI docket) ===", flush=True)
    cache = load_cache()

    def stage3_prompts(seat: str, cache: dict):
        others = []
        for other in SEAT_KEYS:
            if other == seat:
                continue
            body = cache.get(f"stage2_{other}", "(missing)")
            others.append(f"=== {'SEAT ' + str(SEAT_KEYS.index(other)+1) + ': ' + other.upper()} (Turn 2 revised, FULL TEXT) ===\n{body[:80000]}")
        prompt = (
            "ROUND 36 STAGE 3: CONVERGENCE VOTE. Sealed packet rules apply; your "
            "sources are the Turn 2 verdicts below and the Arbiter-compiled Open "
            "Items docket.\n\n"
            "OPEN ITEMS DOCKET (Arbiter-compiled from Turn 1 and Turn 2):\n"
            + oi_text
            + "\n\nVOTE MANDATE:\n"
            "For EVERY open item OI-1..OI-N answer exactly one line:\n"
            "OI-<n>: AGREE\n"
            "or\n"
            "OI-<n>: DISAGREE: <one concrete falsifiable reason (arithmetic, license "
            "text, architecture fact, or measurement). A DISAGREE without a "
            "falsifiable reason is invalid and counts as AGREE.>\n"
            "Then append a RATIFICATION STATEMENT listing any items you believe are "
            "still unresolved and what evidence would settle them.\n"
            "Zero em dashes or en dashes; banned cliches; bold only list keys.\n\n"
            + "\n\n".join(others)
        )
        return clean_text(prompt), SYSTEM_SEATS[seat]

    dispatch_stage("stage3", stage3_prompts)
    print("=== ROUND 36 STAGE 3 COMPLETE ===", flush=True)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stage12", action="store_true")
    group.add_argument("--stage3", action="store_true")
    parser.add_argument("--oi-file", type=pathlib.Path)
    args = parser.parse_args()
    if args.stage12:
        stage12()
    else:
        if not args.oi_file or not args.oi_file.exists():
            raise SystemExit("--stage3 requires --oi-file pointing at the compiled docket")
        stage3(args.oi_file)


if __name__ == "__main__":
    main()
