#!/usr/bin/env python3
"""Round 40 addendum, Turn 4: final convergence vote on the two lines Sol
Pro's Turn-3 objections amend (OI-1/OI-5 conjoint discriminators; OI-3
device-scoped wording). OI-2 and OI-4 are already unanimous and are shown
frozen."""

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
ROUND 40 ADDENDUM, TURN 4 (FINAL VOTE ON THE TWO AMENDED LINES). OI-2 and
OI-4 are UNANIMOUS as of Turn 3 and are FROZEN as ratified. Facts A to D are
unchanged (receive-only token window; paced-vs-burst loss equality; phone
Wi-Fi TX counters 1441/692/1921/9.2%; pmtud emits no probe datagrams). Vote
AGREE or DISAGREE with ONE falsifiable reason per amended line. Zero em/en
dashes; banned cliches; bold only list keys.

AMENDED OI-1 + OI-5 (CONJOINT DISCRIMINATORS, solpro amendment adopted):
no single observation attributes the ceiling alone. The per-tunnel carrier
loss counters sampled at the 437-445 plateau are the SOLE arbiter between
rate-dependent policing and the phone uplink envelope at the operating
point (under 0.5% at plateau: policing does not bind there and the radio
envelope is the sole first-rank cause; over 4%: the Mathis inversion
fails and policing re-enters the plateau ranking). The OI-5 paired-vantage
raw sweeps (phone-to-LAN and phone-to-canada, random payloads, per-step
TX-retry deltas) are interpreted JOINTLY with those counters: their cuts
separate handset/AP/radio from tunnel app processing only in combination
with the per-tunnel loss data, because raw flows do not test whether
policing discriminates tunnel-shaped traffic (long-lived, bidirectional).
The measurement plan therefore runs the sweep and the tunnel counters in
the SAME session, on the same radio, back to back.

AMENDED OI-3 (WORDING, solpro amendment adopted): the product claim is
"delivers your device's own measured raw uplink rate, within measurement
noise", where the device's raw uplink is measured on-device in the same
session (the OI-5 sweep), not quoted from a foreign vantage. On this exact
phone today that is about 470 Mbps against the tunnel's 437-445, i.e. the
claim is expected to PASS within noise once the sweep measures the device
directly. 1000 Mbps tunneled upload stays uncertifiable on this vantage
(1043-1070 carrier required against 560-580 best measured path delivery).
Owner-report items unchanged: ISP plan symmetry, phone radio, vantage.
1166 down stands as the tunnel's demonstrated download rate.

Also confirm in one line: your Turn-3 AGREE on OI-2 and OI-4 stands frozen.
"""


def stage4() -> None:
    print("=== ROUND 40 ADDENDUM STAGE 4 (TURN 4 FINAL VOTE) ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round40"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_addendum_stage4_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r40add_stage4_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r40addstage4"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r40addstage4"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 3000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 3000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round40_addendum_stage4_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 40 addendum stage4 (turn 4): {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 40 ADDENDUM STAGE 4 COMPLETE", flush=True)


if __name__ == "__main__":
    stage4()
