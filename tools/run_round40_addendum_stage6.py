#!/usr/bin/env python3
"""Round 40 addendum, Turn 6: final lines after the arbiter computed the
acceptance band from the real transport constants (26 B Winn + 28 B UDP/IP)
and replaced the pinned loss floor with a comparison-based attribution."""

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
ROUND 40 ADDENDUM, TURN 6 (FINAL VOTE, TWO LINES, ARBITER ARITHMETIC
ATTACHED). OI-2 and OI-4 frozen unanimous. Both Turn-5 objectors' arithmetic
is adopted. Answer from THIS PACKET ONLY. Zero em/en dashes; banned cliches;
bold only list keys.

ARBITER-COMPUTED CONSTANTS (code, this tree): Winn per-datagram overhead =
DemuxTokenSize 8 + transportHeaderSize 2 (inside AEAD) + AEADTagSize 16 =
26 bytes; outer UDP/IPv4 adds 28; total wire overhead 54 bytes per carrier
datagram (core/params.go:38,59; core/session.go:38,263).

FINAL OI-1 + OI-5 (comparison-based attribution; the pinned 0.5% floor is
DELETED per both objectors): low carrier loss at the tunnel's operating
point attributes NOTHING, because a binding policer or shaper at a
TCP-limited equilibrium reads near-zero loss (opus: steady-state loss
scales like (n*MSS/(R*RTT))^2, about 1e-4 to 7e-7 here; solpro: a lossless
440 cap shows 0% loss). Attribution comes ONLY from the same-session
comparison on the same radio:
  a. raw leg: adb iperf3 UDP, random payload, phone to a LAN receiver AND
     phone to canada:9111 (canada side counted), 300-700 Mbps sweep,
     per-step TX-retry deltas.
  b. tunnel leg: the live tunnel's carrier delivery during the ingest run
     (canada-side arrivals for the tunnel 5-tuple; phone-side counters when
     the PIN returns).
  cuts: tunnel-carrier near raw-carrier (within noise): shared
  infrastructure cap (radio or path). tunnel-carrier well below raw-carrier
  with clean carrier loss: tunnel-specific cause (userspace processing or
  tunnel-discriminating policing). carrier loss over 4% at the tunnel
  operating point: consistency alarm; the Mathis inversion is re-derived
  that run. No attribution from loss magnitude alone, ever.

FINAL OI-3 (band computed from real constants; both objectors' arithmetic
adopted): the product claim is "delivers your device's own measured raw
uplink rate less measured protocol encapsulation overhead, within
measurement noise". The acceptance band is COMPUTED per session:
  ratio_pred = ((M - 40) / (M + 54)) / (D_r / (D_r + 28))
where M is the session's actual inner MTU and D_r the raw leg's datagram
payload size. Examples (D_r = 1400): M 1440 gives 0.956; M 1280 gives
0.948. The acceptance band is ratio_pred plus or minus the session's
measured noise (both legs run 3 times in the same session; the band width
is twice the largest leg's spread). A residual gap below the band is an
OPEN FINDING recorded as such, never silently named overhead. The raw leg
is measured on-device (the sweep), never the radio's Calculated Tx
estimate, which is not a measurement. 1000 Mbps tunneled upload stays
uncertifiable on this vantage (1043-1070 carrier required against 560-580
best measured path delivery). Owner-report items unchanged. 1166 down
stands as the tunnel's demonstrated download rate.
"""


def stage6() -> None:
    print("=== ROUND 40 ADDENDUM STAGE 6 (TURN 6 FINAL) ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round40"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_addendum_stage6_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r40add_stage6_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r40addstage6"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r40addstage6"))
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
            fname = f"debate_round40_addendum_stage6_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 40 addendum stage6 (turn 6): {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 40 ADDENDUM STAGE 6 COMPLETE", flush=True)


if __name__ == "__main__":
    stage6()
