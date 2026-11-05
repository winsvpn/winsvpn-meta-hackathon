#!/usr/bin/env python3
"""Round 40 addendum, Turn 2: the arbiter circulates its four verified facts
(code reads + measurements) to all three seats and asks for convergence votes
on the re-derived OI-1 ranking and the OI-2/3/4/5 texts. Seats imported from
the existing runner chain."""

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
ROUND 40 ADDENDUM, TURN 2 (CROSS-EXAMINATION + VOTE). The Arbiter resolved
the evidence gaps each of you marked and verified four facts in the tree and
on the bench. Answer from THIS PACKET ONLY: no tools, no network. Zero
em/en dashes; banned cliches; bold only list keys.

ARBITER-VERIFIED FACTS:
A. CODE: DefaultTokenWindow is RECEIVE-SIDE ONLY. params.go:164-177: "how
   many future demux tokens a receiver precomputes ... the reordering
   tolerance and the exact replay filter". The sender Seal path
   (core/session.go 384-403) computes sendPRF.token(counter) with NO window
   check; carrier has no ACK, credit, or outstanding cap anywhere.
B. MEASURED: paced vs burst-32 UDP at MATCHED mean rate, same path, random
   payloads: 400 Mbps: paced 5.83%, burst 5.35/5.89% loss; 550 Mbps: paced
   8.76/9.87%, burst 8.16/8.28%. Burst shape adds no loss; the loss is
   rate-dependent policing (~0.8% at 300 offered, ~6% at 400, ~8-10% at
   550, one 32% outlier on the first paced run discarded as transient).
C. MEASURED via adb shell (no app PIN needed): the PHONE's own Wi-Fi
   counters: Tx Link speed 1441 Mbps, "Calculated Tx: 692 Mbps", Rx Link
   speed 1921, "Calculated Rx: 1845 Mbps", cumulative TX retry rate 9.2%
   (241,748 retries of 2.6M packets), RSSI -50, 6 GHz. The same radio
   carries 1166 Mbps tunnel DOWN (Rx side). The phone's ingest plateau:
   437-445 inner = about 470 carrier = 68% of Calculated Tx.
D. CODE: carrier/pmtud.go derives PMTU from kernel EMSGSIZE on oversized
   Sends; it emits NO probe datagrams. carrier/doc.go fingerprint
   discipline: carriers emit nothing unbidden; keepalives are PING frames
   inside AEAD messages; a per-connection salt rides the first Send.

DERIVED FACTS FROM A TO D:
- Opus's rank-1 kill condition is MET: with a receive-only window there is
  no send-side BDP gate, so throughput x RTT constancy would be coincidence.
- Opus's Mathis demotion of loss-limited TCP stands: at 5-8% inner loss,
  32 streams of MSS 1400 cap at 58-292 Mbps, below the observed 437; the
  inner streams therefore do NOT see the open-loop probe's loss curve.
- agy's burst-queue mechanism is dead: fact B shows pacing does not cut
  loss at matched rates.
- The phone's uplink envelope: Calculated Tx 692 (real-world 450-550), TX
  PHY 1441 vs RX PHY 1921 (the Wi-Fi TX/RX asymmetry agy named), 9.2% TX
  retries. The 470-carrier plateau sits inside it; 1166 down proves only
  the Rx side.
- The path beyond the LAN still polices by rate: 5-10% loss at 400-550
  offered (fact B), zero canada-side kernel drops at 600 (turn-1 fact).

PROPOSED CONVERGENCE TEXT (vote on THIS text):
OI-1 (ingress ceiling, re-ranked): 1st, the phone's uplink delivery
envelope (radio TX ~692 calculated with 9.2% retries, TX PHY half of RX
PHY), compounded 2nd by rate-dependent path policing (5-10% loss above 400
Mbps offered from the LAN vantage); 3rd, the client send path (bounded:
the engine demonstrably offered 644 Mbps inner, so the pipeline is not the
445 cap); token-starvation and gateway-side removed (facts A, C, D).
OI-2 (pacing): a latency/jitter feature only. NOT the 1000-up lever. May
ship later, gated on queue-delay measurements; never claimed as capacity.
OI-3 (1000/1000): unachievable as a TUNNELED upload promise on this home
Wi-Fi vantage (best path delivery 560-580 UDP vs about 1070 carrier needed
for 1000 inner). Product wording: "saturates your uplink"; owner-report
item (ISP plan symmetry, phone radio, or a cellular vantage for headline
numbers). 1166 down stands as the tunnel's demonstrated download rate.
OI-4 (scrubber): no redesign forced (fact D: no probe datagrams exist);
new standing rule: every future diagnostic, probe, or keepalive on the
wire is AEAD-sealed or CSPRNG-filled, never constant-pattern, which is
measured to die near 100% at any rate.
OI-5 (next check): iperf3 (or equivalent) pushed to the phone via adb
(no app PIN needed), raw UDP sweep 300-700 Mbps to a LAN receiver; a raw
plateau near 470 implicates the handset/AP/radio, a raw 550+ implicates
the tunnel's app processing. Toybox-nc attempt was tool-limited (~130
Mbps through its loop) and is NOT evidence.

VOTE: for each OI, exactly AGREE or DISAGREE with ONE falsifiable reason.
Steelman in one sentence the strongest opposing position from Turn 1
(opus: send-gate BDP; agy: burst-induced loss) and say whether facts A to
D change your position. End with: NEXT one-liner.
"""


def stage2() -> None:
    print("=== ROUND 40 ADDENDUM STAGE 2 (TURN 2) ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round40"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_addendum_stage2_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r40add_stage2_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r40addstage2"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r40addstage2"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 6000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 6000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round40_addendum_stage2_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 40 addendum stage2 (turn 2): {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 40 ADDENDUM STAGE 2 COMPLETE", flush=True)


if __name__ == "__main__":
    stage2()
