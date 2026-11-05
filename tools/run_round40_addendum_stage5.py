#!/usr/bin/env python3
"""Round 40 addendum, Turn 5: final two lines after adopting opus's exact
OI-3 repair (encapsulation overhead named in the claim) and a middle-band
disposition for the plateau loss discriminator (solpro's 2% gap)."""

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
ROUND 40 ADDENDUM, TURN 5 (FINAL VOTE, TWO LINES). OI-2 and OI-4 frozen
unanimous (all three seats confirmed in Turn 4). Facts A to D unchanged.
Vote AGREE or DISAGREE with ONE falsifiable reason per line. Zero em/en
dashes; banned cliches; bold only list keys.

FINAL OI-1 + OI-5 (adds the middle band, solpro 2% gap closed): per-tunnel
carrier loss counters sampled at the 437-445 plateau are the sole arbiter
once a rule fires: under 0.5% at plateau, policing does not bind there and
the phone uplink envelope is the sole first-rank cause; over 4%, the
Mathis inversion fails and policing re-enters the plateau ranking; BETWEEN
0.5% and 4% (the middle band, e.g. a 2.0% reading), NO attribution is
made, both hypotheses remain live, and measurement continues at higher
time resolution and longer windows until one rule fires. The paired-vantage
raw sweeps are interpreted JOINTLY with the counters only (raw flows do
not test whether policing discriminates tunnel-shaped traffic). Sweep and
tunnel counters run in the SAME session on the same radio; materially
different TX-retry deltas across the two runs void the pairing.

FINAL OI-3 (opus repair adopted verbatim, solpro band added): the product
claim is "delivers your device's own measured raw uplink rate LESS PROTOCOL
ENCAPSULATION OVERHEAD, within measurement noise". The acceptance band is
the tunnel-to-raw ratio 0.91-0.95 (opus arithmetic: the fixed-sign
encapsulation tax is 4-9% across inner MTU 1280-1420, predicting about
0.94-0.958; measured today 437-445 against about 470 raw = 0.93-0.947,
inside the band), so the 5.3-7.0% trail solpro measured is the named
overhead, not noise, and the claim is expected to pass. On-device raw
uplink is measured in the same session (OI-5 sweep), never quoted from a
foreign vantage. 1000 Mbps tunneled upload stays uncertifiable on this
vantage (1043-1070 carrier required against 560-580 best measured path
delivery). Owner-report items unchanged (ISP plan symmetry, phone radio,
vantage). 1166 down stands as the tunnel's demonstrated download rate.
"""


def stage5() -> None:
    print("=== ROUND 40 ADDENDUM STAGE 5 (TURN 5 FINAL) ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round40"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_addendum_stage5_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r40add_stage5_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r40addstage5"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r40addstage5"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 2500)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 2500
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round40_addendum_stage5_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 40 addendum stage5 (turn 5): {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 40 ADDENDUM STAGE 5 COMPLETE", flush=True)


if __name__ == "__main__":
    stage5()
