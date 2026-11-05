#!/usr/bin/env python3
"""Round 40 addendum, Turn 3: convergence vote on the amended treaty text
after the three Turn-2 objections (opus OI-1/OI-3 amendments, solpro OI-1
arithmetic correction and OI-5 paired-vantage amendment)."""

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
ROUND 40 ADDENDUM, TURN 3 (CONVERGENCE VOTE ON AMENDED TEXT). Your Turn-2
objections are incorporated verbatim below. Facts A to D are unchanged from
Turn 2 (receive-only token window; paced-vs-burst loss equality; phone Wi-Fi
TX counters 1441/692/1921/9.2%; pmtud emits no probe datagrams). Answer from
THIS PACKET ONLY. Zero em/en dashes; banned cliches; bold only list keys.
Vote AGREE or DISAGREE with ONE falsifiable reason per item on the amended
text, which is the only text under vote.

AMENDED OI-1 (ingress ceiling): rank 1st the phone uplink delivery envelope:
Calculated Tx 692 Mbps (real-world 450-550), TX PHY 1441 = 75% of RX PHY
1921, cumulative TX retry rate 9.2%, the 470-carrier plateau = 68% of
Calculated Tx, and 1166 Mbps down proving only the Rx side. Rate-dependent
path policing (fact B: 5-10% loss at 400-550 Mbps offered) is recorded as an
UNRESOLVED CEILING ABOVE the plateau, not ranked inside it: inverting Mathis
at the operating point (13.7 Mbps per stream across 32 flows) bounds inner
loss near 0.1-1.0%, so the open-loop probe's loss curve cannot be attributed
to the tunnel's operating point without measurement. Discriminator (opus,
adopted): per-tunnel carrier loss counters sampled at the 437-445 plateau;
under 0.5% confirms the radio as the sole first-rank cause, over 4%
falsifies the Mathis inversion. Client send path 3rd (bounded by the
measured 644 Mbps inner offer). Token starvation and gateway-side removed
(facts A, C, D).

AMENDED OI-2 (pacing): a latency/jitter feature only, never claimed as
capacity, gated on queue-delay measurements before any ship.

AMENDED OI-3 (target): 1000 Mbps TUNNELED upload is not certifiable on this
home Wi-Fi vantage (best path delivery 560-580 UDP against about 1043-1070
Mbps carrier needed for 1000 inner at the real 4.3-7% overhead range).
Product wording: "delivers your device's full tested uplink rate" (opus
amendment; "saturates your uplink" is withdrawn). Owner-report items: ISP
plan symmetry, phone radio, vantage (cellular for headline numbers). 1166
down stands as the tunnel's demonstrated download rate.

AMENDED OI-4 (scrubber): no redesign forced (fact D). Standing rule,
AEAD-first (opus ordering): every future diagnostic, probe, or keepalive on
the wire is AEAD-sealed; CSPRNG-filled bodies are the pre-key exception only;
constant-pattern payloads are measured to die near 100% at any rate.

AMENDED OI-5 (next check): paired-vantage adb iperf3 sweep (solpro/opus):
push iperf3 (no app PIN needed) and sweep 300-700 Mbps raw UDP with random
payloads from the phone to BOTH a LAN receiver AND canada:9111 (canada side
counted), per-step TX-retry deltas (opus). Cuts: raw plateau near 470 on
BOTH vantages implicates handset/AP/radio; phone-LAN 550+ with phone-canada
plateau implicates post-LAN policing; both vantages 550+ while the tunnel
stays 470 implicates tunnel app processing. The toybox-nc attempt (~130
Mbps) carries no evidentiary weight.
"""


def stage3() -> None:
    print("=== ROUND 40 ADDENDUM STAGE 3 (TURN 3 VOTE) ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round40"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_addendum_stage3_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r40add_stage3_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r40addstage3"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r40addstage3"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 4000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 4000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round40_addendum_stage3_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 40 addendum stage3 (turn 3): {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 40 ADDENDUM STAGE 3 COMPLETE", flush=True)


if __name__ == "__main__":
    stage3()
