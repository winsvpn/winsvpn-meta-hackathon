#!/usr/bin/env python3
"""
Winthos Permanent Three-AI Presidential Debate Protocol (Speed & Architecture)
Target: Multi-Gbps Wire-Speed Across Winn v3, AWG, and XRay
Podiums:
  Podium 1: Antigravity (Council Chair, Gemini 3.8 Flash High Thinking)
  Podium 2: GPT-5.6 Sol Pro (OpenAI, OpenRouter openai/gpt-5.6-sol-pro)
  Podium 3: Claude Opus 5 (Anthropic, Claude Code CLI --model opus --effort max)
"""

import hashlib
import json
import os
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)

PROTON_DIR = pathlib.Path(
    "/Users/owner/Library/CloudStorage/ProtonDrive-REDACTED_EMAIL/Winthos-AI-Final-Mastery-20260914/04_FRONTIER_COUNCIL_DELIBERATIONS"
)
PROTON_DIR.mkdir(parents=True, exist_ok=True)


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
    raise RuntimeError("OpenRouter API key not found in environment or ~/.local/share/opencode/auth.json")


def query_sol_pro(prompt: str, effort: str = "high") -> str:
    key = get_openrouter_key()
    ctx = ssl._create_unverified_context()
    payload = {
        "model": "openai/gpt-5.6-sol-pro",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are serving as Podium 2 (GPT-5.6 Sol Pro) under the Winthos Permanent "
                    "Presidential Debate Protocol v4.0. Adhere strictly to the cadence mandate: "
                    "high burstiness, alternating short decisive assertions with compound analytical proofs, "
                    "strictly ZERO em dashes or en dashes (use periods, commas, colons, or parentheses instead), "
                    "ban all AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
                    "Every claim must be backed by Level 1 empirical proof or Level 3 mathematical derivations. "
                    "Do not split differences or seek polite consensus."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "provider": {"order": ["OpenAI", "Azure"], "allow_fallbacks": True},
        "reasoning": {"effort": effort},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": "Winthos Presidential Debate Speed Audit",
        },
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choice = res_data["choices"][0]["message"]
                return choice.get("content", "").strip()
        except Exception as e:
            print(f"[Sol Pro] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(5 * (attempt + 1))
    raise RuntimeError("Sol Pro query failed after 5 attempts")


def query_claude_opus(prompt: str) -> str:
    cmd = [
        "/Users/owner/.local/bin/claude",
        "-p",
        prompt,
        "--model",
        "opus",
        "--effort",
        "max",
    ]
    for attempt in range(3):
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=420,
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
            print(
                f"[Claude Opus] Return code {proc.returncode}: {proc.stderr}",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(5)
        except Exception as e:
            print(f"[Claude Opus] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(5)
    raise RuntimeError("Claude Opus query failed after 3 attempts")


def compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


TOPIC_AND_TELEMETRY = """
DELIBERATION TOPIC:
Achieve Multi-Gbps Wire-Speed (>1 Gbps) across Winn v3, AWG (Amnezia WireGuard), and XRay on the Canada VPS gateway and mobile client (Samsung Galaxy S26 Ultra). Address every layer from hardware interrupts to userspace protocol loops:
1. Canada VPS CPU and Cryptography: Audit whether CPU cryptographic execution is the primary bottleneck or if the Haswell core with AES-NI, PCLMULQDQ, and AVX2 can sustain wire-speed. Determine whether cipher agility (AES-256-GCM vs ChaCha20-Poly1305) is warranted, or if the bottleneck lies in kernel-to-user syscall overhead, lock contention, and socket buffer exhaustion.
2. Single virtio NIC Queue Bottleneck: The Canada node has `ethtool -l ens3` showing `Combined: 1` (pre-set maximum n/a, non-resizable). Ingress `virtio0-input.0` interrupts (12.3M) land exclusively on CPU 4, and egress `virtio0-output.0` (15.9M) on CPU 5. Define the exact kernel packet steering configuration (RPS mask `3f`, `rps_flow_cnt`, `rps_sock_flow_entries`, XPS) and gateway socket architecture (`SO_REUSEPORT` worker pool vs single demux loop, `SO_RCVBUF`/`SO_SNDBUF` sizing to eliminate `udp_rcvbuf_errors`).
3. Uplink Session Collapse above 600-700 Mbps: Resolve the fatal session teardown where high offered load kills the session. Audit the two-stage receive pipeline, demux lock contention, liveness probe timeout under full queue, and buffer drop semantics (`winn3_frame_device.go` tail-drop vs drop-oldest).
4. Suricata Inline IPS on TCP 443: Single NFQUEUE 0 full packet copy on inbound TCP 443 has dropped 125,188 packets. Formulate the resolution: multi-queue load balancing (`--queue-balance 0:5 --queue-cpu-fanout --queue-bypass`) vs accepting port 443 prior to NFQUEUE.
5. AWG (Amnezia WireGuard) MTU and MSS: Optimize inner MTU (1440/1408) and MSS clamp (1400) to eliminate fragmentation on 1500-byte WAN path.
6. XRay Android Client Optimization: Elevate pipe buffer from 4 KiB to 4 MB, eliminate Cloudflare CDN serialization where direct IP transport is available.
7. Android TUN Pump Serialization: Audit `WinnV3AndroidTun.kt` burst drain vs single-packet wake, `Thread.MAX_PRIORITY`, and queue overflow semantics.
8. Decoy Calculator Lockout Remediation: Resolve S26 Ultra credential lockout on `user_pin.txt` and `vpn_settings.txt` (`pin_attempt_state`), enabling verification of PIN `142536=`.

EMPIRICAL TELEMETRY AND SYSTEM STATE:
1. Network Path Measurements:
- Raw WAN (S26 Ultra to Canada Gateway without VPN): 1,742.7 Mbps down / 1,652.9 Mbps up.
- Canada VPS Local Ookla (Bell Laval): 1,962 Mbps down / 1,960 Mbps up.
- Winn v3 on AMD Ryzen 7 PRO 8845HS (Zen 4, aicore): 2.33 Gbps down / 2.01 Gbps up. Shipping gateway on aicore out to Internet: 1.84 Gbps down / 1.37 Gbps up.
- Winn v3 on Canada VPS (Linux client over WAN): 852-923 Mbps down; 587 Mbps up at 600 offered; session collapses and dies above 700-900 Mbps.
- S26 Ultra Handset on Canada VPS: 600-711 Mbps down; 21.5-255 Mbps up before client burst drain.
2. Hardware and Virtualization Telemetry (Canada VPS):
- Host: OVH KVM VPS, Linux 6.8.0-139-generic x86_64.
- CPU: 6 vCPUs, Intel Core Processor (Haswell, no TSX) @ 2.0 GHz.
- CPU Flags: `aes`, `pclmulqdq`, `avx2`, `fma`, `sse4_2`.
- Direct Empirical OpenSSL EVP Benchmark on Canada VPS (1024-byte packets):
  - ChaCha20-Poly1305: 1,218,911 kB/s = 1.22 GB/s (9.75 Gbps) per core.
  - AES-256-GCM: 1,611,681 kB/s = 1.61 GB/s (12.89 Gbps) per core.
  At 1 Gbps wire speed (125 MB/s), ChaCha20-Poly1305 requires 0.102 vCPU (10.2% of a single core). AES-256-GCM requires 0.077 vCPU (7.7% of a single core).
- NIC Queues: `ens3` has `Combined: 1` queue pair (fixed virtio-net, pre-set max n/a).
- Interrupt Mapping:
  - IRQ 36 (`virtio0-input.0`, 12,340,243 interrupts): 100% on CPU 4.
  - IRQ 37 (`virtio0-output.0`, 15,916,212 interrupts): 100% on CPU 5.
- Gateway Service Status:
  - `udp_rcvbuf_errors: 96,200` dropped packets recorded in posture log.
  - Listen: UDP/TCP port 9111.
3. Firewall and IPS Telemetry:
  - Suricata: Running inline IPS on NFQUEUE 0 for TCP 443 with full packet copy.
  - Dropped packets on NFQUEUE 0: 125,188 packets.
  - Port 9111 (Winn v3) is accepted directly in `WINVPN-INPUT` without NFQUEUE.
4. Android Client Telemetry:
  - Device: Samsung Galaxy S26 Ultra (`SM-S948U1`, serial `REDACTED_SERIAL`).
  - Active UI: `org.winsvpn.app.debug/org.winsvpn.app.MainActivity`.
  - Rate limiting gate: `_readPinAttemptState()` in `vpn_settings.txt` armed lockout after repeated candidate entries and monotonic rollback re-arming.
"""


def build_stage1_prompt(podium_name: str) -> str:
    return f"""You are serving as {podium_name} under the Winthos Permanent Three-AI Presidential Debate Protocol v4.0.

{TOPIC_AND_TELEMETRY}

RULES:
1. You have zero visibility into other podium submissions.
2. Every numerical value, memory limit, and performance projection must be proven via Level 1 or Level 3 mathematics, or tagged [UNVERIFIED].
3. Prioritize verifiable technical truth over polite consensus.
4. Adhere strictly to the cadence mandate: high burstiness, alternating short decisive statements with compound analytical proofs, zero em dashes or en dashes, and zero AI cliches.
5. Address every dilemma systematically: CPU crypto capacity, virtio single-queue softirq, socket buffers, uplink collapse root cause, Suricata NFQUEUE policy, AWG MTU/MSS, XRay buffers, Android TUN pump, and S26 lockout reset. Deliver concrete code, parameters, and commands.
"""


def build_stage2_prompt(podium_name: str, peer1_name: str, peer1_text: str, peer2_name: str, peer2_text: str) -> str:
    return f"""You are serving as {podium_name} under the Winthos Permanent Three-AI Presidential Debate Protocol (Stage 2: Cross-Podium Rebuttal).

{TOPIC_AND_TELEMETRY}

PEER TRANSCRIPTS FOR CROSS-EXAMINATION:

### {peer1_name} Stage 1 Submission:
{peer1_text}

---

### {peer2_name} Stage 1 Submission:
{peer2_text}

---

STAGE 2 MANDATE:
1. Audit Peer Claims: Identify unsupported assertions, mathematical errors, or Level 4 heuristics.
2. Direct Challenges: Quote the disputed lines directly and provide Level 1 empirical proof or Level 3 mathematical derivations.
3. Concessions: Concede only if proven incorrect by superior empirical evidence. Never concede out of politeness or conversational flow.
4. Deliver updated, fortified technical position.
5. Cadence mandate: high burstiness, zero em dashes or en dashes, zero AI cliches.
"""


def build_stage3_prompt(podium_name: str, stage2_all_text: str) -> str:
    return f"""You are serving as {podium_name} under the Winthos Permanent Three-AI Presidential Debate Protocol (Stage 3: Synthesis and Position Lock).

{TOPIC_AND_TELEMETRY}

CROSS-EXAMINATION PROCEEDINGS:
{stage2_all_text}

STAGE 3 MANDATE:
Publish a strict three-part synthesis:
1. Absorbed Points: Precise technical claims accepted from peers, citing the exact empirical or mathematical evidence that prompted the shift.
2. Defended Grounds: Challenged claims maintained by this podium, accompanied by fortified proofs.
3. Irreconcilable Delta: The exact unresolved disagreement remaining between podiums, formulated in two to three concise sentences.
4. Cadence mandate: high burstiness, zero em dashes or en dashes, zero AI cliches.
"""


if __name__ == "__main__":
    print("Debate orchestrator ready.")
