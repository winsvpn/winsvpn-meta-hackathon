#!/usr/bin/env python3
"""Run Claude Opus 5 with Extra Thinking and Fable 5.1 via Claude Code CLI directly."""

import os
import pathlib
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
CLAUDE_CLI = "/Users/owner/.local/bin/claude"
LOG_DIR = REPO_ROOT / "docs" / "evidence"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "opus5_fixing_session.log"

PROMPT = """(I want you to make the VPN connection speed achieve more than Gbps for all 3 protocol we use; Winn Protocol v3, AWG, XRay in Win's VPN. Work together with Fable 5.1)

You are Claude Opus 5 with Extra Thinking running autonomously inside Claude Code CLI.
Your mission is to directly FIX the codebase to achieve >1 Gbps wire-speed across all 3 protocols used in Win's VPN:
1. Winn Protocol v3
2. AmneziaWG (AWG)
3. XRay (VLESS-WS)

You have full tool capabilities (Bash, FileRead, FileEdit, FileWrite, etc.) with permissions bypassed.
Do NOT just consult or write analysis reports: YOU MUST FIX THE ISSUES DIRECTLY IN CODE, COMPILE, AND TEST.

You have Fable 5.1 ready to collaborate with you. You can query Fable 5.1 from Bash at any point:
/Users/owner/.local/bin/claude -p --model fable "YOUR PROMPT TO FABLE 5.1"

# FULL ACCESS TO DEVICE, INFRASTRUCTURE, AND CODEBASE:

1. TARGET DEVICE:
   - Device: Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL).
   - ADB command: adb -s REDACTED_SERIAL ...
   - Strictly target ONLY this device. NEVER touch any other device (e.g. OnePlus 12).
   - Hardware: Qualcomm Snapdragon 8 Elite (SM8750-AB) with Oryon CPU cores.
   - Wi-Fi 7 with Multi-Link Operation (MLO), 5.76 Gbps PHY, 2 Gbps local ISP fiber backhaul.
   - Measured baseline: 627 Mbps download, 255 Mbps upload, 2 ms jitter on Test ID 11891346572.
   - Historical empirical proof: 600+ Mbps upload and 700+ Mbps download achieved simultaneously.

2. TARGET INFRASTRUCTURE:
   - Canada Gateway: <NODE_CANADA_IP> (OVHcloud, Beauharnois).
   - Root SSH access: ssh -o BatchMode=yes <CANADA_MGMT_SSH_ALIAS>
   - Network: 2.0 Gbps symmetric WAN link, 1.23 ms idle ping to upstream tier 1.
   - TUN: winn3gw0 with 4 queues (IFF_MULTI_QUEUE), txqueuelen 2048, tc qdisc mq with fq.
   - Sysctls: net.core.rmem_max = 134217728 (128 MB), net.core.wmem_max = 134217728, netdev_max_backlog = 250000.
   - Kansas Gateway: 104.238.135.150.

3. PROTOCOLS TO INVESTIGATE & FIX:

   A. WINN PROTOCOL V3:
      - Client: android/app/src/main/kotlin/org/winsvpn/app/WinnV3*, winn_protocol_experimental/cdatapath/ (libwinnengine.so), winn_protocol_experimental/cmd/winn-datapath/.
      - Gateway: winn_protocol_experimental/cmd/winn3-gateway/.
      - Inspect TUN packet batching, syscall rates, ring buffer depths, and pacing. Fix any remaining stalls to break 1+ Gbps download and 600+ Mbps upload.

   B. AMNEZIAWG (AWG):
      - Code: windows/awg_engine/, winn_protocol_experimental/internal/awg/, server/build_amneziawg_go_server_image.sh, android/app/libs/amneziawg.aar, android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt.
      - Eliminate single-core crypto and syscall bottlenecks, tune UDP socket buffers, ring buffers, worker goroutine fanout, and offloads to achieve >1 Gbps wire-speed on S26 Ultra and Canada Gateway.

   C. XRAY (VLESS-WS):
      - Code: tools/build_xray_engine.sh, apple/EngineWrappers/, lib/xray_transport_options.dart.
      - Optimize TCP buffer sizes, BBR/BBRv3 congestion control, WebSocket read/write buffer allocations, mux concurrency, and TLS record sizing to achieve >1 Gbps wire-speed.

# CONSTRAINTS:
- Make concrete code edits, compile native assets and Go binaries, run tests, and verify.
- Strict anti-AI style: zero em dashes, zero en dashes. Use periods, colons, commas, or parentheses.
- Ban AI cliches.
- Take direct action now.
"""

def main():
    print("Executing Claude Opus 5 with Extra Thinking directly in Claude Code CLI...", flush=True)
    env = os.environ.copy()
    env.pop("ANTHROPIC_BASE_URL", None)
    env.pop("ANTHROPIC_AUTH_TOKEN", None)
    env.pop("ANTHROPIC_MODEL", None)
    env["CLAUDE_CODE_EFFORT_LEVEL"] = "max"
    env["MAX_THINKING_TOKENS"] = "64000"

    cmd = [
        CLAUDE_CLI,
        "-p",
        "--model", "opus",
        "--effort", "max",
        "--dangerously-skip-permissions",
        PROMPT,
    ]
    
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        p = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        for line in p.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            f.write(line)
            f.flush()
        p.wait()
        print(f"\nOpus 5 session completed with exit code {p.returncode}")
        return p.returncode

if __name__ == "__main__":
    sys.exit(main())
