#!/usr/bin/env python3
"""Round 37 convergence micro-vote: amended RV-6 (fixed) and the RV-2 fork."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import pathlib

spec = importlib.util.spec_from_file_location(
    "r37", "/Users/owner/xprize/winsvpnv3/tools/run_round37_verify.py"
)
r37 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r37)

r36 = r37.r36

AMENDED = """
AMENDED ITEM RV-6 (CLOSED BY CODE, EVIDENCE ATTACHED): app_version() now
validates per component: the base must match one to four dot-separated integers
AND every component must be 0..65535, so the solpro counterexample 65536 fails
the build instead of shipping. Drift suite now 4 tests including the
component-cap case, all passing. Vote: RV-6-AMENDED: AGREE or DISAGREE: <reason>.

ITEM RV-2 (STILL OPEN: a values fork, put to the council with three options):
the guardrail suppresses the hub LLM for infrastructure-probing messages
(the hub routes to third-party AI tiers: gemini, meta). Opus holds any
suppression is a full list-enumeration oracle at one request per candidate and
offers two closures. The three options:
  (a) REMOVE-SUPPRESSION: secret-flagged queries reach the hub LLM exactly like
      clean queries; the enumeration oracle closes; the cost is that user
      probes containing wireguard/xray/port text are answered by, and their
      text visible to, third-party AI tiers.
  (b) LOCAL-ONLY-ROUTE: the /ai-chat route serves ONLY the local topic
      fallback for every query; the hub LLM is never called; the oracle closes
      completely; the cost is losing real LLM answers for every user.
  (c) KEEP-SUPPRESSION: current behavior; the guardrail holds, the keyword
      list stays enumerable at one request per candidate when the hub is up
      and stable (a public-route oracle), documented as residual.
Privacy priority of this product (detectability and third-party exposure are
the top harms for users in high-threat jurisdictions) weighs on (a); product
capability weighs on (c). Vote exactly one line: RV-2-CLOSED-BY: (a) or (b) or
(c), followed by one sentence of justification. A unanimous letter wins; a
split goes to the User as the sovereign under 13.2.5.
"""


def main():
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r37_stage4_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            prompt = r36.clean_text(
                "ROUND 37 CONVERGENCE MICRO-VOTE (TURN 4). Sealed rules apply. "
                "Sources: your Turn 1 and Turn 3 verdicts and the Arbiter's "
                "amendments below.\n\n" + AMENDED
            )
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, prompt, "r37stage4"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, prompt, "r37stage4"))
            else:
                tasks[key] = (
                    seat,
                    ex.submit(r36.query_openrouter, prompt, r36.SYSTEM_SEATS[seat], 6000),
                )
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round37_stage4_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 37 stage4: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete", flush=True)
    for seat in r36.SEAT_KEYS:
        text = cache.get(f"r37_stage4_{seat}", "")
        if not text:
            f = r36.DOCS_EVIDENCE / f"debate_round37_stage4_{seat.replace('claude-opus5', 'opus5')}.md"
            text = f.read_text(errors="replace")
        lines = [l for l in text.splitlines() if "RV-6-AMENDED" in l or "RV-2-CLOSED-BY" in l]
        print(f"--- {seat}: " + " | ".join(x.strip()[:160] for x in lines[:2]), flush=True)


if __name__ == "__main__":
    main()
