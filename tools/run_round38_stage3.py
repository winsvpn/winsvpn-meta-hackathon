#!/usr/bin/env python3
"""Round 38 stage 3: convergence vote on the resolved docket (RV-A..RV-E)."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "r37", "/Users/owner/xprize/winsvpnv3/tools/run_round37_verify.py"
)
r37 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r37)
r36 = r37.r36


def stage3(oi_file: pathlib.Path):
    print("=== ROUND 38 STAGE 3: CONVERGENCE VOTE ===", flush=True)
    oi_text = r36.clean_text(oi_file.read_text(encoding="utf-8"))
    cache = r37.load_cache()

    def prompts(seat, cache_):
        others = []
        for other in r36.SEAT_KEYS:
            if other == seat:
                continue
            body = cache_.get(f"r38_stage1_{other}", "(missing)")
            others.append(f"=== {other.upper()} (Turn 1, FULL TEXT) ===\n{body[:16000]}")
        own = cache_.get(f"r38_stage1_{seat}", "(missing)")
        prompt = (
            "ROUND 38 STAGE 3: CONVERGENCE VOTE. Sealed rules apply. Sources: "
            "your Turn 1 verdict, the other seats' Turn 1 verdicts, and the "
            "Arbiter's docket with post-Turn-1 measurements (M-1..M-3 run on "
            "the physical device and <CANADA_MGMT_SSH_ALIAS>).\n\n"
            "OPEN ITEMS DOCKET:\n" + oi_text + "\n\n"
            "=== YOUR TURN 1 VERDICT (AS FILED) ===\n" + own[:16000]
            + "\n\n=== OTHER SEATS' TURN 1 VERDICTS ===\n" + "\n\n".join(others)
            + "\n\nVOTE MANDATE: for RV-A, RV-B, RV-C, RV-D answer exactly one "
            "line each:\nRV-<x>: AGREE\nor\nRV-<x>: DISAGREE: <one concrete "
            "falsifiable reason>.\nFor RV-E answer one line: RV-E: (b) or "
            "(c) with one sentence. Then a one-paragraph ratification "
            "statement. Zero em/en dashes; banned cliches; bold only list keys."
        )
        return r36.clean_text(prompt), r36.SYSTEM_SEATS[seat]

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r38_stage3_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            prompt, system_role = prompts(seat, cache)
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, prompt, "r38stage3"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, prompt, "r38stage3"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(prompt, system_role, 12000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", prompt, system_role, 12000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round38_stage3_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 38 stage3: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 38 STAGE 3 COMPLETE", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage3", action="store_true")
    parser.add_argument("--oi-file", type=pathlib.Path)
    args = parser.parse_args()
    if args.stage3:
        if not args.oi_file or not args.oi_file.exists():
            raise SystemExit("--stage3 requires --oi-file")
        stage3(args.oi_file)


if __name__ == "__main__":
    main()
