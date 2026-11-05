#!/usr/bin/env python3
"""Round 41 Turn 2: cross-examination on the corrected counters and the
convergence vote on the root cause + the four-part fix package."""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "r37", "/Users/owner/xprize/winsvpnv3/tools/run_round37_verify.py"
)
r37 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r37)
r36 = r37.r36

PACKET = """
ROUND 41, TURN 2 (CROSS-EXAMINATION + VOTE). The Arbiter corrected one
counter-reading of its own and adds three facts. Answer from THIS PACKET
ONLY. Zero em/en dashes; banned cliches; bold only list keys.

CORRECTED COUNTER LABELS (the Arbiter misread two columns in Turn 1; these
are the phone engine's real post-burst numbers):
  phone messages_sent 40,394 (keepalive creep) vs gateway recv 40,418: THE
  UPLINK MATCHED ONE FOR ONE. NO PATH LOSS. The phone's 536 MB burst traffic
  was INBOUND (rx_packets = tun RX = download delivery = 383,255 of the
  gateway's 398k outbound; 14,548 short).
  phone messages_received 397,332 = CARRIER receives (the download arriving).
  THE DOWNLINK DELIVERED; THE TUN DELIVERY FELL 14,548 SHORT OF THE CARRIER
  RECEIVES; POST-BURST rx FROZE WHILE CARRIER RECEIVES KEPT ARRIVING.

NEW FACTS:
  N1. The canada session's source IP <OPERATOR_WAN_IP> IS the operator's own
      home address (the deploy snapshot names it operator=). The phone
      connects DIRECTLY to canada; there is NO relay chain.
  N2. The phone's RAW UDP to canada (adb push, random pool): 150 Mbps
      offered -> 107,141 of 107,141 arrived (0.00% loss); 198 Mbps -> 100%.
      The phone's path is clean at shell-capped rates.
  N3. The phone runs Wi-Fi 7 MLO (Tx link 3843 Mbps) on the same AP/LAN as
      the Arbiter's MacBook probes (600 Mbps sustained, about 5% loss).
N1 and N2 kill any path-policing theory for the uplink and any relay theory.

TURN 1 POSITIONS:
  opus (b) widened, lead: the burst drove force-advance past the gateway's
  real transmit counter and latched the phone's receive window deaf; carrier
  datagrams kept arriving and were counted (messages_received +7/s) while
  tun delivery froze (rx_packets frozen); the gateway's rekey and liveness
  probes were then dropped as replays; two independent timers (15 s rekey
  budget, 4 lost probes) expired together. Falsifiers: post-burst drop
  attribution showing a non-replay reason, or rx resuming.
  solpro (b), lead: a rekey message on the nonce stream ages out of a
  1024-token window at 44k to 60k pps (17 to 23 ms depth) and is classified
  replay; notes the 363 s timing needs delayed scheduling and asks for
  synchronized traces.
  agy (d), lead: a post-burst writeLoop stall wedged the pipeline so the
  phone could not process the rekey.

ARBITER NOTE ON agy (d): the corrected counters kill it as root. A pipeline
stall explains burst-window drops, not post-burst deafness: messages_received
ADVANCED while rx_packets froze, so the accept side (the token filter), not
the pipe, refused everything. agy's own live-check (spin counters post-burst)
would show the writeLoop healthy.

CONVERGENCE TEXT (vote on THIS):
OI-1 ROOT CAUSE: post-burst receive-window latch. During the 8 s download
burst (up to 60k carrier datagrams/s toward a 1024-token window with 511
reorder tolerance), Wi-Fi 7 MLO reordering plus the burst drove the receive
window's force-advance past the gateway's true transmit position; from
06:13:41 the window classified arriving datagrams as beyond-window/replay,
freezing tun delivery; the gateway's in-band rekey (fired at session second
348 by its jittered 5 min timer, unrelated to the burst except in time) and
the phone's liveness responses were then dropped as replays; the 15 s rekey
budget and the 4-lost-probe liveness bound expired together at 06:14:32-33.
The window defect is the root; the rekey teardown amplifies it into a
full tunnel death.
OI-2 FIX PACKAGE (four parts, all required): (1) clamp force-advance so the
window's low edge never moves past the highest counter actually
authenticated; (2) rekey timeout becomes a recoverable rollover: no
StateFailed, no CloseRekeyFailed broadcast, retry with backoff, terminal
only at the old epoch's RejectAfter bounds, which must exist and be
enforced; (3) make-before-break epoch replacement: the fresh handshake runs
while the old epoch carries, cut over on the first authenticated data of
the new epoch, same frame device and tun, so the app observes nothing;
(4) the admit path's handshake budget counts only well-formed handshake
messages (session #19 died on one stale-epoch datagram); plus a Rekeying
or Degraded gate state so carrying stops lying during a rekey.
OI-3 WINDOW SIZE: the clamp is the load-bearing fix; DefaultTokenWindow
stays 1024 pending a D23-conformant re-derivation (the Round 40 addendum
already pins that raising it requires re-deriving the inbox geometry and
memory budget). The 14,548 in-burst losses are TCP-recoverable ordinary
loss; only the LATCH was fatal.
OI-4 APP LATCH: latchedInnerRouterV4 becomes a derived property of the
active plan, computed in the one callback every start path traverses on
entering carrying, with a generation guard so a stale teardown cannot clear
a live session's latch.
OI-5 ORDER: this ships before any throughput work; the verification is
re-running the repro (two speedtests with a 60 s gap) on the fixed build
with drop-reason instrumentation on the phone's post-burst receive path.

VOTE: for each OI, AGREE or DISAGREE with ONE falsifiable reason. Steelman
the strongest opposing Turn 1 view in one sentence each. End with NEXT.
"""


def stage2() -> None:
    print("=== ROUND 41 STAGE 2 (TURN 2) ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round41"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_stage2_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r41_stage2_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r41stage2"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r41stage2"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 8000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 8000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round41_stage2_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 41 stage2 (turn 2): {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 41 STAGE 2 COMPLETE", flush=True)


def main() -> None:
    stage2()


if __name__ == "__main__":
    main()
