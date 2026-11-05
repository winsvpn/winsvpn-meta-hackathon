#!/usr/bin/env python3
"""Round 38: speedtest endpoint-selection finding + experiment verdict.

Stage 1 dispatch to the three standing podiums. Stage 3 votes after review.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import pathlib
import time

_spec = importlib.util.spec_from_file_location(
    "r37", "/Users/owner/xprize/winsvpnv3/tools/run_round37_verify.py"
)
r37 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r37)
r36 = r37.r36

PACKET = """
ROUND 38 DELIBERATION PACKET: WIN'S VPN — SPEEDTEST ENDPOINT-SELECTION FINDING
(Answer from THIS PACKET ONLY: no tools, no network. Zero em/en dashes; banned
cliches; bold only list keys.)

FINDING UNDER VERIFICATION (Arbiter, measured on the physical Samsung Galaxy
S26 Ultra over the production Canada gateway, Winn Protocol v3, 2026-09-20):
The in-app speedtest's upload number is dominated by WHICH TARGET FAMILY the
rotation picks, not by tunnel state. The app builds target families by node
label in lib/main.dart _speedTestTargetsForNode: every node gets 'Global
Backbone' (speed.cloudflare.com first, then cachefly); a node whose label
contains canada also gets 'North America Backbone' (cachefly first, then
cloudflare). Measured pairs from this session, same builds within each group:

WITH the 1-second warm-up and 8 MiB carrier buffers (earlier build):
  run labelled 'North America': 765 up. Runs labelled 'Global Backbone':
  257, then a null (under 256 KiB) result. Downloads 717-766 throughout.
WITH warm-up and 4 MiB carrier buffers (one-knob experiment, ~1 BDP):
  'North America': 775 up. 'Global Backbone': 234, then 274 (downloads
  719-758). The 4 MiB reproduction REFUTES the deep-buffer queue theory that
  Round 37's stage 1 ranked first: one bandwidth-delay product of standing
  queue cannot produce the same collapse the 8 MiB buffers produced.
WITHOUT warm-up, 8 MiB buffers, after revert:
  'North America': 762/706, then 451/681, then 792/786. 'Global Backbone'
  runs in the same window measured 234-301.

TOTAL PATTERN ACROSS EVERY RUN TODAY: 'North America' labelled runs measure
681-790 up on every build configuration; 'Global Backbone' labelled runs
measure 234-301 up on every build configuration. The label predicts the
number better than any datapath variable does.

INTERPRETATION TO CHALLENGE: speed.cloudflare.com's anycast maps the Canada
exit IP to a colo whose __up path sustains only about 230-300 Mbps per
aggregate, while the cachefly/NA path sustains 700-790. The tunnel carries
the full rate to the fast path (proven by the 32-parallel curl test and the
North America runs). Consequence: the previously reported 'post-warm-up
collapse' was an endpoint-selection artifact, and the tunnel's true upload
capacity on the fast path is 681-790 Mbps after this session's JNI bulk
read + 16 MB socket buffer work (from a 531 Mbps baseline).

PROPOSED PRODUCT FIX (vote the design):
  A. STICKY-BEST: run both families once, then pin subsequent speedtests to
     the family with the higher measured upload for that node, with a
     periodic re-probe.
  B. REPORT-BOTH: keep the rotation but display per-family results (two
     rows) so no single number swings.
  C. ORDER-SWAP: reorder the Canada target list to put the NA family first
     and only fall back to Global Backbone when NA fails.
Vote A, B, or C with reasoning, or propose D.

ALSO IN THIS PACKET FOR VERIFICATION:
1. Carrier send/recv buffers were temporarily set to 4 MiB for the experiment
   and REVERTED to the 8 MiB default after the refutation. Both client dial
   paths (DialUDP and the adopted-descriptor path) are back on the default.
   Go tests: carrier, tun, cmd/winn-datapath all pass.
2. The warm-up code was again reverted; MainActivity.kt carries the verdict
   comment with the full measured table.
3. Dynamic MTU shipped: Android derives the inner MTU from the underlying
   network's link MTU (floor 1280, ceiling 1440, IPv6 minus 32), the Go
   engine's kernel PMTUD corrects the carrier after connect, the fleet
   installer default is 1280 (owner decision: cellular compatibility), and
   the shared Dart constants are 1280. Verified at 767/767 on Wi-Fi.
4. Spain management restored after the owner unlocked the LUKS volume;
   wg-quick@wghub0 enabled at boot on both ends; spain has a new WG keypair
   and kansas's peer was swapped. The remaining blocker is the IONOS
   whitelist firewall on kansas: inbound UDP 51820 (tcpdump on both ends
   proves the handshakes never arrive; both OS firewalls accept).
5. RV-2 (the AI-chat guardrail fork) remains with the User: (b) local-only
   chat route vs (c) keep suppression, 2-to-1 from the Round 37 micro-vote.

MANDATE (independent):
1. Attack the endpoint-selection interpretation: what else could produce a
   perfect label-number correlation across 15+ runs and three build
   configurations? Name a falsifiable alternative and its discriminating
   measurement.
2. Vote the product fix: A, B, C, or D with reasoning. Consider the user
   experience of a number that swings 3x between runs, the honesty of
   reporting the slower path, and the high-threat-user context (a stable
   believable number matters; a leak-honest dual number may confuse).
3. Restate or revise your RV-2 recommendation for the User in one line.
4. Mark external claims UNVERIFIED-LIVE inline.
"""


def stage1():
    print("=== ROUND 38 STAGE 1 ===", flush=True)
    packet = r36.clean_text(PACKET)
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    (r37.RECEIPTS / "packet_dispatched.txt").write_text(packet, encoding="utf-8")
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r38_stage1_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r38stage1"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r38stage1"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 12000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 12000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round38_stage1_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 38 stage1: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 38 STAGE 1 COMPLETE", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage1", action="store_true")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
