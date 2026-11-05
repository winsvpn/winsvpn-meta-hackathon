#!/usr/bin/env python3
"""Round 41: the tunnel-death defect. The gateway's jittered in-band rekey
fired near a heavy download burst, failed to complete inside its 15 s budget,
and tore the session down on both ends. The app's reconnect then lost the
inner-router latch (latched=null), so the speedtest primary target refused.
Seats imported from the existing runner chain."""

from __future__ import annotations

import argparse
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
ROUND 41 DELIBERATION PACKET: THE TUNNEL-DEATH DEFECT (in-band rekey fails
near a heavy burst; both ends tear down; app reconnect loses the ingest
latch). (Answer from THIS PACKET ONLY: no tools, no network. Zero em/en
dashes; banned cliches; bold only list keys; UNVERIFIED-LIVE inline.)

REPRODUCED TIMELINE (2026-09-21, physical Samsung Galaxy S26 Ultra debug
build v1.0.16, Wi-Fi 7 MLO 6 GHz, canada gateway <NODE_CANADA_IP>:9111,
gateway binary deployed 2026-09-20 22:56 UTC, linux/amd64 rv40 build with
the reverted DefaultPipeDepth 256):

GATEWAY SIDE (per-second posture counters, UTC):
  06:08:29 sessions 2, session #18 admitted (<OPERATOR_WAN_IP>:59661), carrying 1
  06:13:31 phone starts a speedtest download leg
  06:13:32-40 gateway messages_sent 572 -> 398,375 in 9 s (about 496 Mbps
    down; the ingest download plus tunnel download legs), recv 7,470
  06:13:41 sent FROZEN at 398,414 the instant the 8 s window ended; idle
    keepalives creep +10 to 20/s
  06:14:18 carrying 1 -> 0 while keepalives still arrive (recv +7/s)
  06:14:32 gateway log: winn3-debug: [driver.writeLoop] terminal state=failed
    err=winn3/session: in-band rekey did not complete; session loop.Run
    exited state=failed; Loop.Close called; new session #19 admitted
  06:14:56 session #19 dies: the handshake budget was spent on messages that
    could not be authenticated (1 datagram), sessions -> 0

PHONE SIDE (engine posture counters, local time = UTC-4):
  02:08:29 fresh session (posture bootstrap -> handshaking -> carrying)
  02:13:31 speedtest tapped; download legs run; engine rx_packets 590 ->
    383,255 (about 536 MB inner accepted from the frame channel)
  02:14:21-02:14:30 rx FROZEN at 383,255; messages_received creeping +7/s
    (carrier keepalives alive)
  02:14:33 engine: [driver.writeLoop] terminal state=failed
    err=winn3/session: peer did not answer liveness probes
  02:14:34 tunnel failed: winn3: the frame device is closed; engine stopped
    unexpectedly; tun torn down
  02:14:36 speedtest ingest upload: tunnel ingest refused: router=10.10.0.1
    latched=null port=8455 (the inner-router latch did not survive the
    reconnect chain)
  02:14:46 fallback third-party upload rides the PHYSICAL route (the app
    excludes its own UID): 2624 to 2895 Mbps to speed.cloudflare.com, 32/32
    HTTP 200, twice. The radio and the uplink are fine; the tunnel is not.

YESTERDAY'S FIRST OBSERVATION (same device, 01:10:10 local): a clean close
instead: terminal state=closed err=<nil>, frame device closed, same ~55 s
death-after-burst shape. Two signatures, one defect family.

CODE FACTS (verified in this tree):
  - winn3/session/config.go:92-104: DefaultRekeyIntervalMin 5 min, Mean 15,
    Max 45, jittered; DefaultRekeyAfterBytes 1<<32; DefaultRekeyTimeout
    15 s. The comment: on rekey expiry the session closes and "the fallback
    is a full handshake, which is also what a fresh session looks like, so
    the failure mode adds no new observable."
  - config.go:126-136: ErrPeerUnreachable ("peer did not answer liveness
    probes"), ErrRekeyFailed ("in-band rekey did not complete"),
    ErrRekeyUnconfirmed (rekey committed locally, peer never confirmed).
    DefaultMaxLostProbes 4, probes about 20 s apart: "roughly half a minute
    typical and eighty seconds worst case."
  - session/frames.go:46: CloseRekeyFailed = an in-band rekey exchange did
    not complete.
  - winn3/driver/loop.go:499-577: writeLoop drains, syncGate, terminal check
    (StateFailed returns the session error; closed returns nil); the spins
    guard needs 4096 no-progress wakes AND frozen recv, which the keepalive
    creep defeats.
  - The gateway's carrying counter = sessions whose gate is StateCarrying
    (cmd/winn3-gateway/main.go:502-511); gate latches down on terminal
    states (driver/doc.go:62).
  - Session lifetime at failure: 363 s (admitted 06:08:29, failed 06:14:32).
    The jittered interval min is 5 min. The download burst occupied
    06:13:31-40, i.e. session seconds 302-311.
  - D23 geometry: DefaultTokenWindow 1024, receive reorder tolerance 511,
    force-advance retires the low edge; beyond-window frames drop as
    replays. During the 8 s burst the gateway sent about 398k datagrams at
    up to 60k pps toward the phone's 1024-token receive window.
  - The app reconnect chain: VpnTunnelService.latchedInnerRouterV4 is set in
    the staged-start path (WinnV3SessionPlan.innerNextHopOf) and cleared at
    teardown; the reconnect after this death produced latched=null.

MANDATE (answer every item):
1. ROOT CAUSE: rank what made the rekey exchange fail inside its 15 s
   budget. Candidates: (a) simultaneous rekey collision, both ends drawing
   jittered intervals near the same moment and each acting as initiator
   without processing the peer's initiation; (b) the rekey handshake
   datagrams, sequenced on the session's own nonce stream, fell outside the
   phone's 1024-token receive window after the 60k pps burst force-advanced
   it, and were dropped as replays; (c) the rekey response was lost to
   ordinary burst loss and the 5-attempt retry ladder (0.5 to 8 s) landed
   entirely inside the burst window; (d) the phone's engine could not
   process the rekey because its frame-side pipeline was already stalled
   from the burst (state the coupling that would make that possible);
   (e) something else you name. Give the falsification for your lead.
2. THE 363 s LIFETIME: does the jittered interval (min 5 min) firing at
   session second 300 to 360 plus the 15 s budget explain the timestamp
   exactly, or must a second trigger exist? Note the burst occupied session
   seconds 302 to 311.
3. THE FALLBACK GAP: the design comment promises rekey failure falls back
   to a full handshake with no new observable. What shipped instead tears
   the session on BOTH ends (gateway StateFailed; phone ErrPeerUnreachable
   15 s later). Name the exact code path where the promised fallback is
   missing or broken, and the minimal change that delivers the promised
   behavior: rekey fails -> data path keeps carrying on the old epoch until
   RejectAfter* -> a fresh full handshake replaces the session WITHOUT
   dropping inner packets or the app latch.
4. THE APP BUG: reconnect after teardown produced latched=null, refusing
   the ingest primary target. Give the minimal fix (where the latch must be
   re-armed or why the reconnect took a non-staged path) and the test that
   pins it.
5. SEVERITY AND ORDER: this defect (tunnel dies at first rekey near load;
   no clean recovery; speedtest primary refused) vs the 1000-up throughput
   work. State which ships first and why in one paragraph.
6. NEXT: the single most valuable check on the live path to confirm your
   root cause without shipping code.

End with VERDICT: per item, AGREE or DISAGREE with one falsifiable reason.
"""


def stage1() -> None:
    print("=== ROUND 41 STAGE 1 ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round41"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r41_stage1_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r41stage1"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r41stage1"))
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
            fname = f"debate_round41_stage1_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 41 stage1: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 41 STAGE 1 COMPLETE", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage1", action="store_true")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
